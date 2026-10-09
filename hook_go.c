#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "ntapi.h"
#include "hooking.h"
#include "log.h"
#include "misc.h"
#include "config.h"
#include "lookup.h"
#include "CAPE\CAPE.h"
#include "CAPE\Debugger.h"

#define LOQ_string(cat, fmt, ...) \
do { \
    static volatile LONG _index; \
    LONG _id = _index; \
    if (_id == 0) { \
        LONG _new_id = InterlockedIncrement(&g_log_index); \
        LONG _prev = InterlockedCompareExchange(&_index, _new_id, 0); \
        _id = (_prev == 0) ? _new_id : _prev; \
    } \
    loq(_id, cat, "GoBreakpoint", TRUE, 0, fmt, ##__VA_ARGS__); \
} while (0)

#define GO_VER_UNKNOWN 0
#define GO_VER_12      1
#define GO_VER_116     2
#define GO_VER_118     3
#define GO_VER_120     4

// Table of hooked Go functions keyed by function entry address
static lookup_t g_go_hook_table = {0};
static lookup_t g_go_recovered_pclntab = {0};

// Per-pclntab (per Go module) state, persisted across repeated GoRecoverSymbols() calls
typedef struct _GO_MODULE_INFO {
    int GoMinor;            // minor version from buildinfo ("go1.N"), -1 if unknown
    BOOL NoRegAbiExp;       // buildinfo version carries " X:...noregabi*" (GOEXPERIMENT disabled the register ABI)
    BOOL RegAbi;            // resolved ABI for this module
    BOOL AbiResolved;
    // Function table snapshot for PC -> Go function name resolution (GoFuncNameForPC)
    BOOL FuncTabValid;
    int Version;            // GO_VER_* pclntab format
    BYTE PtrSize;
    DWORD FieldSize;        // functab field width: 4 (Go 1.18+) or ptrSize
    uint64_t NFunc;
    PBYTE Pclntab, Functab, Funcdata, Funcnametab, ImageEnd;
    ULONG_PTR ImageBase, PreferredBase, SizeOfImage, TextStart;
} GO_MODULE_INFO;

// Candidate hooks collected during the function walk; hooks are armed only after the module ABI is resolved
#define GO_MAX_HOOK_CANDIDATES 1024
typedef struct _GO_HOOK_CANDIDATE {
    PVOID Address;
    DWORD MaxSize;
    const char* Name;
} GO_HOOK_CANDIDATE;

// Per-hook metadata: ABI/version are stored per module so multiple Go modules (e.g. an unpacked or
// injected payload built with a different Go version) do not overwrite each other's ABI
typedef struct _GO_HOOK_ENTRY {
    PVOID Address;
    PBYTE HookSite;
    BOOL InlineHooked;
    BOOL RegAbi;
    int Version;
    char Name[256];
} GO_HOOK_ENTRY;

// Pending crypto/tls.(*Conn).Read calls for one return address. Goroutines on different connections
// commonly share the same Read call site (e.g. net/http persistConn.readLoop), so each pending call is
// matched on return by its entry stack pointer: SP at return == SP at entry + sizeof(ULONG_PTR).
#define GO_TLS_SLOTS 32
#define GO_TLS_SLOT_RESERVED ((ULONG_PTR)1)

typedef struct _GO_TLS_SLOT {
    volatile ULONG_PTR EntrySP;     // 0 = free, 1 = being filled
    PVOID ReadBuffer;
    PVOID BytesReadSlot;            // stack ABI: address of result n
    BOOL RegAbi;
} GO_TLS_SLOT;

typedef struct _GO_TLS_RETURN_STATE {
    GO_TLS_SLOT Slots[GO_TLS_SLOTS];
    volatile LONG NextVictim;
} GO_TLS_RETURN_STATE;

static lookup_t g_go_tls_return_table = {0};

extern lookup_t SoftBPs;
extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern BOOL IsAddressAccessible(PVOID Address);
extern BOOL IsAddressExecutable(PVOID Address);
extern BOOL addr_in_our_dll_range(PVOID Address, ULONG_PTR Addr);
extern PCHAR GetExportDirectory(PVOID Address);

BOOL GoBreakpointHandler(struct _EXCEPTION_POINTERS* ExceptionInfo);
static void GoTlsAddPending(GO_TLS_RETURN_STATE* tlsState, PVOID retAddr, ULONG_PTR entrySP, PVOID readBuffer, PVOID bytesReadSlot, BOOL regAbi);

// Sanitize strings before passing to DebugOutput (which forwards through pipe() format parsing)
static void SanitizeForDebug(char* dst, size_t dstSize, const char* src, size_t srcLen) {
    if (!dst || dstSize == 0)
        return;
    dst[0] = '\0';
    if (!src || srcLen == 0)
        return;

    size_t copyLen = (srcLen < dstSize - 1) ? srcLen : (dstSize - 1);
    for (size_t i = 0; i < copyLen; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '%' || c < 0x20 || c > 0x7E)
            dst[i] = '.';
        else
            dst[i] = (char)c;
    }
    dst[copyLen] = '\0';
}

// Retrieve the idx-th pointer-sized argument word (0-indexed) according to the active Go ABI
static ULONG_PTR GoGetArgWord(PCONTEXT Context, BOOL RegAbi, DWORD idx) {
#ifdef _WIN64
    if (RegAbi) {
        // Go x86-64 ABIInternal integer argument registers:
        // RAX, RBX, RCX, RDI, RSI, R8, R9, R10, R11
        switch (idx) {
            case 0: return Context->Rax;
            case 1: return Context->Rbx;
            case 2: return Context->Rcx;
            case 3: return Context->Rdi;
            case 4: return Context->Rsi;
            case 5: return Context->R8;
            case 6: return Context->R9;
            case 7: return Context->R10;
            case 8: return Context->R11;
            default: return 0;
        }
    } else {
        PULONG_PTR pStack = (PULONG_PTR)Context->Rsp;
        if (IsAddressAccessible(&pStack[idx + 1]))
            return pStack[idx + 1];
        return 0;
    }
#else
    PULONG_PTR pStack = (PULONG_PTR)Context->Esp;
    if (IsAddressAccessible(&pStack[idx + 1]))
        return pStack[idx + 1];
    UNREFERENCED_PARAMETER(RegAbi);
    return 0;
#endif
}

// TRUE if the allocation looks like a PE image, including images whose MZ/e_magic was wiped (IsDisguisedPEHeader
// validates e_lfanew and the NT headers, which is what DumpRegion uses)
static BOOL GoIsPEImage(PVOID pBase) {
    if (!pBase || !IsAddressAccessible(pBase))
        return FALSE;
    return IsDisguisedPEHeader(pBase) > 0;
}

// Helper to read pointer-sized integer from pclntab header offsets
static uint64_t ReadHeaderWord(PBYTE pHeader, DWORD wordIndex, BYTE ptrSize) {
    if (ptrSize == 4) {
        return *(uint32_t*)(pHeader + 8 + wordIndex * 4);
    } else {
        return *(uint64_t*)(pHeader + 8 + wordIndex * 8);
    }
}

// Validate a pclntab header located by the internal 'golang' YARA rule (runtime/symtab.go layout) and return
// its GO_VER_* format, or GO_VER_UNKNOWN. YARA does the searching; this only rejects spurious matches.
int GoPclntabVersion(PBYTE p) {
    int ver = GO_VER_UNKNOWN;
    __try {
        if (!p || ((ULONG_PTR)p & 3) || !IsAddressAccessible(p) || !IsAddressAccessible(p + 63))
            return GO_VER_UNKNOWN;
        switch (*(PDWORD)p) {
            case 0xFFFFFFF1: ver = GO_VER_120; break;
            case 0xFFFFFFF0: ver = GO_VER_118; break;
            case 0xFFFFFFFA: ver = GO_VER_116; break;
            case 0xFFFFFFFB: ver = GO_VER_12;  break;
            default: return GO_VER_UNKNOWN;
        }
        // byte 4, 5 == 0, byte 6 is minLC (1, 2 or 4), byte 7 is ptrSize (4 or 8)
        if (p[4] || p[5] || !(p[6] == 1 || p[6] == 2 || p[6] == 4) || !(p[7] == 4 || p[7] == 8))
            return GO_VER_UNKNOWN;
        uint64_t nfunc = ReadHeaderWord(p, 0, p[7]);
        if (nfunc == 0 || nfunc >= 500000)
            return GO_VER_UNKNOWN;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GO_VER_UNKNOWN;
    }
    return ver;
}

// Verify that the entire [addr, addr + len) range is readable before handing it to loq(), which holds
// g_mutex without a __finally guard while copying string/buffer arguments.
static BOOL IsBufferAccessible(PVOID addr, SIZE_T len) {
    if (!addr || len == 0)
        return FALSE;
    ULONG_PTR start = (ULONG_PTR)addr;
    ULONG_PTR end = start + len - 1;
    if (end < start)
        return FALSE;
    __try {
        for (ULONG_PTR p = start & ~(ULONG_PTR)0xFFF; p <= (end & ~(ULONG_PTR)0xFFF); p += 0x1000) {
            volatile BYTE b = *(volatile BYTE*)p;
            (void)b;
        }
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

// Go string argument validation for single-record LOQ calls: unreadable/implausible strings log as empty
static int GoStrLen(ULONG_PTR ptr, ULONG_PTR len) {
    return (ptr != 0 && len > 0 && len < 2048 && IsBufferAccessible((PVOID)ptr, (SIZE_T)len)) ? (int)len : 0;
}

static const char* GoStrPtr(ULONG_PTR ptr, int len) {
    return len ? (const char*)ptr : "";
}

// Absolute entry address of functab[i] for a recorded module (0 if it cannot be mapped into the image)
static ULONG_PTR GoFunctabEntryAddr(GO_MODULE_INFO* m, uint64_t i, ULONG_PTR* structOff) {
    ULONG_PTR off, so = 0;
    if (m->FieldSize == 4) {
        uint32_t* p = (uint32_t*)(m->Functab + 2 * i * 4);
        if (!IsAddressAccessible(p)) return 0;
        off = p[0];
        so = p[1];
    } else {
        uint64_t* p = (uint64_t*)(m->Functab + 2 * i * 8);
        if (!IsAddressAccessible(p)) return 0;
        off = (ULONG_PTR)p[0];
        so = (ULONG_PTR)p[1];
    }
    if (structOff)
        *structOff = so;
    if (m->Version >= GO_VER_118)
        return m->TextStart + off;
    if (off >= m->ImageBase && off < m->ImageBase + m->SizeOfImage)
        return off;
    if (off >= m->PreferredBase && off < m->PreferredBase + m->SizeOfImage)
        return m->ImageBase + (off - m->PreferredBase);
    return 0;
}

// Resolve a code address to the containing Go function name using the functab of any recorded Go module.
// functab is sorted by entry PC, so this is a binary search. Returns a pointer into funcnametab or NULL.
static const char* GoFuncNameForPC(ULONG_PTR pc) {
    __try {
        for (entry_t* e = (entry_t*)g_go_recovered_pclntab.root; e != NULL; e = e->next) {
            GO_MODULE_INFO* m = (GO_MODULE_INFO*)e->data;
            if (!m->FuncTabValid || pc < m->ImageBase || pc >= (ULONG_PTR)m->ImageEnd || m->NFunc == 0)
                continue;

            uint64_t lo = 0, hi = m->NFunc;     // find last i with entry(i) <= pc
            while (hi - lo > 1) {
                uint64_t mid = lo + (hi - lo) / 2;
                ULONG_PTR a = GoFunctabEntryAddr(m, mid, NULL);
                if (a && a <= pc)
                    lo = mid;
                else
                    hi = mid;
            }

            ULONG_PTR structOff = 0;
            ULONG_PTR entry = GoFunctabEntryAddr(m, lo, &structOff);
            if (!entry || entry > pc)
                continue;
            // functab[nfunc] is the end-of-text sentinel in every pclntab format, so lo + 1 is always readable
            ULONG_PTR next = GoFunctabEntryAddr(m, lo + 1, NULL);
            if (next && pc >= next)
                continue;

            PBYTE pFuncData = m->Funcdata + structOff;
            DWORD sz0 = (m->Version >= GO_VER_118) ? 4 : (DWORD)m->PtrSize;
            if (pFuncData < m->Pclntab || (pFuncData + sz0 + 4) > m->ImageEnd || !IsAddressAccessible(pFuncData + sz0))
                continue;
            PBYTE pName = m->Funcnametab + *(uint32_t*)(pFuncData + sz0);
            if (pName < m->Pclntab || pName >= m->ImageEnd || !IsAddressAccessible(pName) || *pName == '\0')
                continue;
            return (const char*)pName;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    return NULL;
}

// TRUE if capemon has an active inline hook for an API of this name (in any DLL), i.e. the call is
// already visible in the behaviour log and does not need to be reported again from the Go side
extern hook_t* hooks;
extern SIZE_T hooks_arraysize;
static BOOL GoApiIsHooked(const char* name) {
    if (!hooks || !name)
        return FALSE;
    for (SIZE_T i = 0; i < hooks_arraysize; i++)
        if (hooks[i].is_hooked && hooks[i].funcname && !strcmp(hooks[i].funcname, name))
            return TRUE;
    return FALSE;
}

// syscall.Syscall*/SyscallN 'trap' is a function pointer (LazyProc.Addr / GetProcAddress), not an SSN.
// Resolve it to dll!export once per target; report only targets that bypass capemon's API hooks.
static lookup_t g_go_syscall_targets = {0};
static void GoResolveSyscallTarget(ULONG_PTR trap, ULONG_PTR callerRet) {
    if (lookup_get(&g_go_syscall_targets, trap, NULL))
        return;
    lookup_add(&g_go_syscall_targets, trap, 0);

    unsigned int offset = 0;
    // Export directory name first: also names manually mapped DLL copies (e.g. a fresh ntdll used to
    // bypass hooks), which are absent from the PEB loader list used by convert_address_to_dll_name_and_offset
    PCHAR exportDll = GetExportDirectory((PVOID)trap);
    char* dllName = exportDll ? NULL : convert_address_to_dll_name_and_offset(trap, &offset);
    const char* dll = exportDll ? exportDll : (dllName ? dllName : "?");
    PCHAR apiName = GetExportNameByAddress((PVOID)trap);
    const char* goCaller = callerRet ? GoFuncNameForPC(callerRet - 1) : NULL;
    BOOL hooked = GoApiIsHooked(apiName);

    char target[MAX_PATH];
    if (apiName)
        _snprintf_s(target, sizeof(target), _TRUNCATE, "%s!%s", dll, apiName);
    else if (dllName)
        _snprintf_s(target, sizeof(target), _TRUNCATE, "%s+0x%x", dll, offset);
    else
        _snprintf_s(target, sizeof(target), _TRUNCATE, "%s:0x%p", dll, (PVOID)trap);

    char safeCaller[160];
    SanitizeForDebug(safeCaller, sizeof(safeCaller), goCaller ? goCaller : "?", goCaller ? strlen(goCaller) : 1);
    DebugOutput("Go Trace: syscall target 0x%p -> %s (%s), Go caller %s\n", (PVOID)trap, target, hooked ? "hooked" : "not hooked", safeCaller);

    if (!hooked)
        LOQ_string("go_trace", "s", "API", target);

    if (dllName)
        free(dllName);
}

// Global hook callback executed whenever any registered Go breakpoint is hit
static BOOL GoBreakpointCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo) {
    if (!pBreakpointInfo || !ExceptionInfo)
        return TRUE;

    // Resolve the function name associated with this breakpoint via thread-safe lookup
    GO_HOOK_ENTRY* hookEntry = (GO_HOOK_ENTRY*)lookup_get(&g_go_hook_table, (ULONG_PTR)pBreakpointInfo->Address, NULL);
    if (!hookEntry)
        return TRUE;

    const char* funcName = hookEntry->Name;
    BOOL regabi = hookEntry->RegAbi;

    // syscall.Syscall* sits under most Win32 calls made by the Go stdlib and is mostly covered by the API
    // hooks; it is instrumented to catch direct calls into private executable memory and to name image-backed
    // targets that capemon does not hook (GoResolveSyscallTarget). No go_trace "Function" record is emitted.
    BOOL isSyscall = (strncmp(funcName, "syscall.Syscall", 15) == 0);

    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    hook_info_t* hookinfo = hook_info();
    ULONG_PTR savedRetAddr = hookinfo ? hookinfo->return_address : 0;
    ULONG_PTR savedMainCaller = hookinfo ? hookinfo->main_caller_retaddr : 0;

    if (hookinfo) {
        hookinfo->return_address = (ULONG_PTR)pBreakpointInfo->Address;
#ifdef _WIN64
        PULONG_PTR pSp = (PULONG_PTR)ctx->Rsp;
#else
        PULONG_PTR pSp = (PULONG_PTR)ctx->Esp;
#endif
        if (IsAddressAccessible(pSp))
            hookinfo->main_caller_retaddr = pSp[0];
    }

    char safeFuncName[160];
    SanitizeForDebug(safeFuncName, sizeof(safeFuncName), funcName, strlen(funcName));

    if (!isSyscall)
        DebugOutput("Go Trace: Intercepted Execution of Go Function: %s at 0x%p\n", safeFuncName, pBreakpointInfo->Address);

    // Behaviour log rule: at most ONE LOQ call per breakpoint hit. Each branch gathers all of its fields and
    // emits a single record that includes the function name; the generic record below is only a fallback.
    BOOL logged = FALSE;

    // Dynamic argument tracing based on ABI (RegABI on x64 vs. Stack ABI)
    __try {
        if (isSyscall) {
            logged = TRUE;  // syscall.Syscall* never emits a generic record
            // syscall.Syscall(trap, nargs, a1, a2, a3 uintptr) / syscall.SyscallN(trap uintptr, args ...uintptr)
            ULONG_PTR trapAddress = GoGetArgWord(ctx, regabi, 0);
#ifdef _WIN64
            PULONG_PTR pCallerSp = (PULONG_PTR)ctx->Rsp;
#else
            PULONG_PTR pCallerSp = (PULONG_PTR)ctx->Esp;
#endif
            ULONG_PTR callerRet = IsAddressAccessible(pCallerSp) ? pCallerSp[0] : 0;

            // Check if this is a direct memory address jump (indicates in-memory shellcode or PE execution)
            if (trapAddress != 0 && IsAddressAccessible((PVOID)trapAddress)) {
                if (!addr_in_our_dll_range(NULL, trapAddress)) {
                    BOOL privateExec = FALSE;
                    MEMORY_BASIC_INFORMATION mbi;
                    if (VirtualQuery((PVOID)trapAddress, &mbi, sizeof(mbi)) != 0) {
                        if ((mbi.State == MEM_COMMIT) &&
                            (mbi.Type == MEM_PRIVATE) &&
                            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                            privateExec = TRUE;
                            BOOL isPE = GoIsPEImage(mbi.AllocationBase);
                            DebugOutput("Go Trace: Detected direct in-memory %s execution at 0x%p! (Size: 0x%x)\n",
                                        isPE ? "PE" : "shellcode", (PVOID)trapAddress, (unsigned int)mbi.RegionSize);
                            LOQ_string("go_trace", "ssp", "Function", funcName,
                                       "Event", isPE ? "Go Reflective PE Payload Execution Intercepted" : "Go Direct Shellcode/Payload Execution Intercepted",
                                       "Jump Address", (PVOID)trapAddress);
                            TrackExecution((PVOID)trapAddress);
                        }
                    }

                    // Image-backed target: name the Win32/NT export and the Go caller (logged once per target,
                    // and only when the export is not already covered by a capemon API hook)
                    if (!privateExec)
                        GoResolveSyscallTarget(trapAddress, callerRet);
                }
            }
        }
        else if (strstr(funcName, "time.Sleep")) {
            // time.Sleep(d Duration) where Duration is int64 nanoseconds
            uint64_t nanoseconds = 0;
#ifdef _WIN64
            nanoseconds = (uint64_t)GoGetArgWord(ctx, regabi, 0);
#else
            uint32_t low = (uint32_t)GoGetArgWord(ctx, regabi, 0);
            uint32_t high = (uint32_t)GoGetArgWord(ctx, regabi, 1);
            nanoseconds = ((uint64_t)high << 32) | low;
#endif
            uint64_t milliseconds = nanoseconds / 1000000;

            LOQ_string("go_trace", "si", "Function", funcName, "Milliseconds", (int)milliseconds);
            logged = TRUE;
        }
        else if (strstr(funcName, "crypto/tls.(*Conn).Write")) {
            // func (c *Conn) Write(b []byte) (int, error)
            // word 0: c (*Conn), word 1: b.Data, word 2: b.Len, word 3: b.Cap
            ULONG_PTR pData = GoGetArgWord(ctx, regabi, 1);
            ULONG_PTR length = GoGetArgWord(ctx, regabi, 2);

            if (pData != 0 && length > 0 && length <= 65536) {
                size_t capLen = (length < 8192) ? (size_t)length : 8192;
                if (IsBufferAccessible((PVOID)pData, capLen)) {
                    LOQ_string("go_tls", "ssb", "Function", funcName, "Direction", "Outbound", "Plaintext", capLen, (const char*)pData);
                    logged = TRUE;
                    DebugOutput("Go TLS Outbound Plaintext Payload (%u bytes) intercepted at 0x%p\n", (unsigned int)length, (PVOID)pData);
                }
            }
        }
        else if (strstr(funcName, "crypto/tls.(*Conn).Read")) {
            // func (c *Conn) Read(b []byte) (int, error)
            // word 0: c (*Conn), word 1: b.Data, word 2: b.Len, word 3: b.Cap
            // Logged once, on return (GoBreakpointHandler), when the plaintext is available: silent at entry.
            logged = TRUE;
            ULONG_PTR pData = GoGetArgWord(ctx, regabi, 1);
            ULONG_PTR length = GoGetArgWord(ctx, regabi, 2);

            if (pData != 0 && length > 0 && IsAddressAccessible((PVOID)pData)) {
#ifdef _WIN64
                PULONG_PTR pStack = (PULONG_PTR)ctx->Rsp;
#else
                PULONG_PTR pStack = (PULONG_PTR)ctx->Esp;
#endif
                if (IsAddressAccessible(pStack) && pStack[0] != 0) {
                    PVOID retAddr = (PVOID)pStack[0];
                    GO_TLS_RETURN_STATE* tlsState = (GO_TLS_RETURN_STATE*)lookup_get_or_create(
                        &g_go_tls_return_table, (ULONG_PTR)retAddr, sizeof(GO_TLS_RETURN_STATE));
                    if (tlsState)
                        GoTlsAddPending(tlsState, retAddr, (ULONG_PTR)pStack, (PVOID)pData,
                                        // Under Stack ABI, return value n (int) is at [SP_on_entry + 5*ptrSize]
                                        regabi ? NULL : (PVOID)&pStack[5], regabi);
                }
            }
        }
        else if (strstr(funcName, ".NewCipher") ||
                 strstr(funcName, "des.NewTripleDESCipher") ||
                 strstr(funcName, "chacha20poly1305.New") ||
                 strstr(funcName, "chacha20.NewUnauthenticatedCipher") ||
                 strstr(funcName, "pbkdf2.Key") ||
                 strstr(funcName, "argon2.IDKey") ||
                 strstr(funcName, "argon2.Key") ||
                 strstr(funcName, "scrypt.Key")) {
            // First parameter is key/password []byte: word 0 = ptr, word 1 = len
            ULONG_PTR keyPtr = GoGetArgWord(ctx, regabi, 0);
            ULONG_PTR keyLen = GoGetArgWord(ctx, regabi, 1);
            BOOL readable = (keyPtr != 0 && keyLen > 0 && keyLen <= 512 && IsBufferAccessible((PVOID)keyPtr, (SIZE_T)keyLen));

            LOQ_string("go_crypto", "sib", "Function", funcName, "KeyLength", (int)keyLen,
                       "Key", readable ? (size_t)keyLen : (size_t)0, readable ? (const char*)keyPtr : "");
            logged = TRUE;
        }
        else if (strstr(funcName, "crypto/cipher.NewCBC") ||
                 strstr(funcName, "crypto/cipher.NewCFB") ||
                 strstr(funcName, "crypto/cipher.NewCTR") ||
                 strstr(funcName, "crypto/cipher.NewOFB")) {
            // func NewXXX(block Block, iv []byte): word 0..1 = block (interface), word 2 = iv.ptr, word 3 = iv.len
            ULONG_PTR ivPtr = GoGetArgWord(ctx, regabi, 2);
            ULONG_PTR ivLen = GoGetArgWord(ctx, regabi, 3);
            if (ivPtr != 0 && ivLen > 0 && ivLen <= 64 && IsBufferAccessible((PVOID)ivPtr, (SIZE_T)ivLen)) {
                LOQ_string("go_crypto", "sb", "Function", funcName, "IV", (size_t)ivLen, (const char*)ivPtr);
                logged = TRUE;
            }
        }
        else if (strstr(funcName, "net.Lookup")) {
            // func LookupHost/LookupIP/LookupTXT(host string): word 0..1 = host
            ULONG_PTR hostPtr = GoGetArgWord(ctx, regabi, 0);
            int hostLen = GoStrLen(hostPtr, GoGetArgWord(ctx, regabi, 1));
            LOQ_string("go_trace", "sS", "Function", funcName, "Host", hostLen, GoStrPtr(hostPtr, hostLen));
            logged = TRUE;
        }
        else if (strstr(funcName, "net/http.NewRequest")) {
            // func NewRequestWithContext(ctx context.Context, method, url string, body io.Reader)
            //   word 0..1: ctx (interface), word 2..3: method (string), word 4..5: url (string)
            // func NewRequest(method, url string, body io.Reader)
            //   word 0..1: method (string), word 2..3: url (string)
            DWORD baseIdx = strstr(funcName, "NewRequestWithContext") ? 2 : 0;
            ULONG_PTR methodPtr = GoGetArgWord(ctx, regabi, baseIdx);
            int methodLen = GoStrLen(methodPtr, GoGetArgWord(ctx, regabi, baseIdx + 1));
            ULONG_PTR urlPtr = GoGetArgWord(ctx, regabi, baseIdx + 2);
            int urlLen = GoStrLen(urlPtr, GoGetArgWord(ctx, regabi, baseIdx + 3));
            LOQ_string("go_trace", "sSS", "Function", funcName,
                       "Method", methodLen, GoStrPtr(methodPtr, methodLen),
                       "URL", urlLen, GoStrPtr(urlPtr, urlLen));
            logged = TRUE;
        }
        else if (strstr(funcName, "net/http.(*Client).Get") ||
                 strstr(funcName, "net/http.(*Client).Post") ||
                 strstr(funcName, "net/http.(*Client).Head") ||
                 strstr(funcName, "net/http.(*Client).PostForm") ||
                 strstr(funcName, "net/http.Get") ||
                 strstr(funcName, "net/http.Post") ||
                 strstr(funcName, "net/http.Head") ||
                 strstr(funcName, "net/http.PostForm")) {
            // Method on *Client: receiver is word 0, url (string) is word 1..2; package-level helper: url is word 0..1
            DWORD baseIdx = strstr(funcName, "(*Client)") ? 1 : 0;
            ULONG_PTR urlPtr = GoGetArgWord(ctx, regabi, baseIdx);
            int urlLen = GoStrLen(urlPtr, GoGetArgWord(ctx, regabi, baseIdx + 1));
            LOQ_string("go_trace", "sS", "Function", funcName, "URL", urlLen, GoStrPtr(urlPtr, urlLen));
            logged = TRUE;
        }
        else if (strstr(funcName, "net.Dial") || strstr(funcName, "net.(*Dialer).Dial") || strstr(funcName, "net.Listen")) {
            // func Dial(network, address string) / func Listen(network, address string)
            BOOL hasReceiver = (strstr(funcName, ").") != NULL);
            DWORD baseIdx = hasReceiver ? 1 : 0;
            if (strstr(funcName, "Context")) {
                baseIdx += 2; // skip context.Context interface (2 words)
            }
            ULONG_PTR netPtr = GoGetArgWord(ctx, regabi, baseIdx);
            int netLen = GoStrLen(netPtr, GoGetArgWord(ctx, regabi, baseIdx + 1));
            ULONG_PTR addrPtr = GoGetArgWord(ctx, regabi, baseIdx + 2);
            int addrLen = GoStrLen(addrPtr, GoGetArgWord(ctx, regabi, baseIdx + 3));
            LOQ_string("go_trace", "sSS", "Function", funcName,
                       "Network", netLen, GoStrPtr(netPtr, netLen),
                       "Address", addrLen, GoStrPtr(addrPtr, addrLen));
            logged = TRUE;
        }
        else if (strstr(funcName, "os/exec.Command") ||
                 strstr(funcName, "os.OpenFile") ||
                 strstr(funcName, "os.Create") ||
                 strstr(funcName, "os.Remove") ||
                 strstr(funcName, "os.WriteFile") ||
                 strstr(funcName, "ioutil.WriteFile")) {
            DWORD baseIdx = (strstr(funcName, "CommandContext") != NULL) ? 2 : 0;
            ULONG_PTR strPtr = GoGetArgWord(ctx, regabi, baseIdx);
            int strLen = GoStrLen(strPtr, GoGetArgWord(ctx, regabi, baseIdx + 1));
            LOQ_string("go_trace", "sS", "Function", funcName, "Target", strLen, GoStrPtr(strPtr, strLen));
            logged = TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DebugOutput("Go Trace: Exception occurred resolving Go function arguments.\n");
    }

    // Fallback: hooked function with no argument-specific record (or arguments unreadable)
    if (!logged)
        LOQ_string("go_trace", "s", "Function", funcName);

    if (hookinfo) {
        hookinfo->return_address = savedRetAddr;
        hookinfo->main_caller_retaddr = savedMainCaller;
    }

    return TRUE;
}

// Register a pending crypto/tls.(*Conn).Read call and arm its (persistent) return breakpoint
static void GoTlsAddPending(GO_TLS_RETURN_STATE* tlsState, PVOID retAddr, ULONG_PTR entrySP, PVOID readBuffer, PVOID bytesReadSlot, BOOL regAbi) {
    GO_TLS_SLOT* slot = NULL;

    // Re-use a stale slot with the same entry SP (e.g. a previous call that unwound without returning)
    for (int i = 0; i < GO_TLS_SLOTS && !slot; i++) {
        if (tlsState->Slots[i].EntrySP == entrySP &&
            InterlockedCompareExchangePointer((PVOID volatile*)&tlsState->Slots[i].EntrySP, (PVOID)GO_TLS_SLOT_RESERVED, (PVOID)entrySP) == (PVOID)entrySP)
            slot = &tlsState->Slots[i];
    }
    for (int i = 0; i < GO_TLS_SLOTS && !slot; i++) {
        if (InterlockedCompareExchangePointer((PVOID volatile*)&tlsState->Slots[i].EntrySP, (PVOID)GO_TLS_SLOT_RESERVED, NULL) == NULL)
            slot = &tlsState->Slots[i];
    }
    if (!slot) {
        // All slots taken (stale entries from stack moves/panics): evict round-robin
        LONG victim = (InterlockedIncrement(&tlsState->NextVictim) & 0x7fffffff) % GO_TLS_SLOTS;
        slot = &tlsState->Slots[victim];
        InterlockedExchangePointer((PVOID volatile*)&slot->EntrySP, (PVOID)GO_TLS_SLOT_RESERVED);
    }

    slot->ReadBuffer = readBuffer;
    slot->BytesReadSlot = bytesReadSlot;
    slot->RegAbi = regAbi;
    InterlockedExchangePointer((PVOID volatile*)&slot->EntrySP, (PVOID)entrySP);

    // Persistent return breakpoint, armed once per return site (re-armed here if ClearAllBreakpoints removed it)
    if (!lookup_get(&SoftBPs, (ULONG_PTR)retAddr, NULL))
        SetSoftwareBreakpointEx(&SoftBPs, retAddr, GoBreakpointHandler, TRUE);
}

// Software breakpoint callback registered via SetSoftwareBreakpoint for Go hooks
typedef struct _GO_BP_CALL {
    struct _EXCEPTION_POINTERS* ExceptionInfo;
    BOOL Handled;
} GO_BP_CALL;

// Body of the software-breakpoint handler; runs on the capemon alternate stack (see GoBreakpointHandler).
static void __cdecl GoBreakpointHandlerOnStack(void* p) {
    GO_BP_CALL* call = (GO_BP_CALL*)p;
    struct _EXCEPTION_POINTERS* ExceptionInfo = call->ExceptionInfo;

    PVOID Address = ExceptionInfo->ExceptionRecord->ExceptionAddress;

    BOOL handled = FALSE;

    // 1. TLS Read return breakpoints: keyed by return address, matched to the pending call by stack pointer
    //    (independent of the OS thread, since goroutines migrate between threads while blocked in Read)
    GO_TLS_SLOT pending = {0};
    BOOL matched = FALSE;
    GO_TLS_RETURN_STATE* tlsState = (GO_TLS_RETURN_STATE*)lookup_get(&g_go_tls_return_table, (ULONG_PTR)Address, NULL);
    if (tlsState) {
#ifdef _WIN64
        ULONG_PTR entrySP = (ULONG_PTR)ExceptionInfo->ContextRecord->Rsp - sizeof(ULONG_PTR);
#else
        ULONG_PTR entrySP = (ULONG_PTR)ExceptionInfo->ContextRecord->Esp - sizeof(ULONG_PTR);
#endif
        for (int i = 0; i < GO_TLS_SLOTS && !matched; i++) {
            GO_TLS_SLOT* slot = &tlsState->Slots[i];
            if (slot->EntrySP == entrySP &&
                InterlockedCompareExchangePointer((PVOID volatile*)&slot->EntrySP, (PVOID)GO_TLS_SLOT_RESERVED, (PVOID)entrySP) == (PVOID)entrySP) {
                pending = *slot;
                InterlockedExchangePointer((PVOID volatile*)&slot->EntrySP, NULL);
                matched = TRUE;
            }
        }

        // The return breakpoint stays persistent for the lifetime of the g_go_tls_return_table entry: this site is
        // only reached after a Read that registered a pending slot, and toggling it one-shot would lookup_del/re-add
        // a SoftBPs record (never freed) on every read.
        handled = TRUE;
    }

    if (tlsState && matched) {
        hook_info_t* hookinfo = hook_info();
        ULONG_PTR savedRetAddr = hookinfo ? hookinfo->return_address : 0;
        ULONG_PTR savedMainCaller = hookinfo ? hookinfo->main_caller_retaddr : 0;
        if (hookinfo) {
            hookinfo->return_address = (ULONG_PTR)Address;
            hookinfo->main_caller_retaddr = (ULONG_PTR)Address;
        }

        __try {
            ULONG_PTR bytesRead = 0;
#ifdef _WIN64
            if (pending.RegAbi) {
                bytesRead = ExceptionInfo->ContextRecord->Rax;
            } else if (pending.BytesReadSlot && IsAddressAccessible(pending.BytesReadSlot)) {
                bytesRead = *(PULONG_PTR)pending.BytesReadSlot;
            }
#else
            if (pending.BytesReadSlot && IsAddressAccessible(pending.BytesReadSlot)) {
                bytesRead = *(PULONG_PTR)pending.BytesReadSlot;
            }
#endif

            if (pending.ReadBuffer != NULL && bytesRead > 0 && bytesRead <= 65536) {
                size_t capLen = (bytesRead < 8192) ? (size_t)bytesRead : 8192;
                if (IsBufferAccessible(pending.ReadBuffer, capLen)) {
                    LOQ_string("go_tls", "ssb", "Function", "crypto/tls.(*Conn).Read", "Direction", "Inbound", "Plaintext", capLen, (const char*)pending.ReadBuffer);
                    DebugOutput("Go TLS Inbound Plaintext Payload (%u bytes) intercepted on return at 0x%p\n", (unsigned int)bytesRead, pending.ReadBuffer);
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DebugOutput("Go Trace: Exception occurred resolving Go tls.Read return.\n");
        }

        if (hookinfo) {
            hookinfo->return_address = savedRetAddr;
            hookinfo->main_caller_retaddr = savedMainCaller;
        }
    }

    // 2. Persistent function entry software breakpoints
    GO_HOOK_ENTRY* hookEntry = (GO_HOOK_ENTRY*)lookup_get(&g_go_hook_table, (ULONG_PTR)Address, NULL);
    if (hookEntry) {
        BREAKPOINTINFO bpInfo;
        memset(&bpInfo, 0, sizeof(bpInfo));
        bpInfo.Address = Address;
        bpInfo.Callback = GoBreakpointCallback;

        GoBreakpointCallback(&bpInfo, ExceptionInfo);
        handled = TRUE;
    }

    call->Handled = handled;
}

// Software-breakpoint (0xCC) path. The kernel has already pushed its exception dispatch frames onto the
// goroutine stack (that is what Go's stackSystem headroom is for); everything heavier moves to the capemon
// alternate stack. If none is available the body runs in place: an unacknowledged breakpoint would be passed
// on to the Go runtime as a fatal exception, which is worse than the overflow risk.
BOOL GoBreakpointHandler(struct _EXCEPTION_POINTERS* ExceptionInfo) {
    if (!ExceptionInfo || !ExceptionInfo->ExceptionRecord)
        return FALSE;

    hook_disable();

    GO_BP_CALL call;
    call.ExceptionInfo = ExceptionInfo;
    call.Handled = FALSE;
    if (!hook_call_on_alt_stack(GoBreakpointHandlerOnStack, &call))
        GoBreakpointHandlerOnStack(&call);

    hook_enable();
    return call.Handled;
}

#ifdef _WIN64
typedef struct _GO_INLINE_REGS {
    ULONG_PTR R15;
    ULONG_PTR R14;
    ULONG_PTR R13;
    ULONG_PTR R12;
    ULONG_PTR R11;
    ULONG_PTR R10;
    ULONG_PTR R9;
    ULONG_PTR R8;
    ULONG_PTR Rbp;
    ULONG_PTR Rsi;
    ULONG_PTR Rdi;
    ULONG_PTR Rdx;
    ULONG_PTR Rcx;
    ULONG_PTR Rbx;
    ULONG_PTR Rax;
    ULONG_PTR Rflags;
} GO_INLINE_REGS;
#else
typedef struct _GO_INLINE_REGS {
    DWORD Edi;
    DWORD Esi;
    DWORD Ebp;
    DWORD EspPushad;
    DWORD Ebx;
    DWORD Edx;
    DWORD Ecx;
    DWORD Eax;
    DWORD Eflags;
} GO_INLINE_REGS;
#endif

typedef struct _GO_INLINE_CALL {
    GO_HOOK_ENTRY* HookEntry;
    GO_INLINE_REGS* Regs;
} GO_INLINE_CALL;

// Runs on the capemon alternate stack: rebuilds a CONTEXT from the registers the stub saved on the goroutine
// stack and feeds it to the common breakpoint callback.
static void __cdecl GoInlineHookDispatchOnStack(void* p) {
    GO_INLINE_CALL* call = (GO_INLINE_CALL*)p;
    GO_HOOK_ENTRY* hookEntry = call->HookEntry;
    GO_INLINE_REGS* regs = call->Regs;

    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
#ifdef _WIN64
    ctx.Rax = regs->Rax;
    ctx.Rbx = regs->Rbx;
    ctx.Rcx = regs->Rcx;
    ctx.Rdx = regs->Rdx;
    ctx.Rdi = regs->Rdi;
    ctx.Rsi = regs->Rsi;
    ctx.Rbp = regs->Rbp;
    ctx.R8  = regs->R8;
    ctx.R9  = regs->R9;
    ctx.R10 = regs->R10;
    ctx.R11 = regs->R11;
    ctx.R12 = regs->R12;
    ctx.R13 = regs->R13;
    ctx.R14 = regs->R14;
    ctx.R15 = regs->R15;
    ctx.Rsp = (ULONG_PTR)(regs + 1);
    ctx.Rip = (ULONG_PTR)hookEntry->Address;
#else
    ctx.Eax = regs->Eax;
    ctx.Ebx = regs->Ebx;
    ctx.Ecx = regs->Ecx;
    ctx.Edx = regs->Edx;
    ctx.Esi = regs->Esi;
    ctx.Edi = regs->Edi;
    ctx.Ebp = regs->Ebp;
    ctx.Esp = (DWORD)(ULONG_PTR)(regs + 1);
    ctx.Eip = (DWORD)(ULONG_PTR)hookEntry->Address;
#endif

    EXCEPTION_RECORD er;
    memset(&er, 0, sizeof(er));
    er.ExceptionAddress = hookEntry->Address;

    EXCEPTION_POINTERS ep;
    ep.ContextRecord = &ctx;
    ep.ExceptionRecord = &er;

    BREAKPOINTINFO bpInfo;
    memset(&bpInfo, 0, sizeof(bpInfo));
    bpInfo.Address = hookEntry->Address;
    bpInfo.Callback = GoBreakpointCallback;

    GoBreakpointCallback(&bpInfo, &ep);
}

// Entered from the inline stub on the goroutine stack. Only ~stackGuard bytes (928 + 4096 on Windows) are
// guaranteed below SP there and there is no guard page, so nothing larger than a few small frames may run
// before hook_call_on_alt_stack switches to the capemon-owned stack. If no alternate stack is available the
// hit is dropped rather than risk overrunning the goroutine stack into adjacent heap memory.
#ifdef _WIN64
void GoInlineHookDispatch(GO_HOOK_ENTRY* hookEntry, GO_INLINE_REGS* regs) {
#else
void __stdcall GoInlineHookDispatch(GO_HOOK_ENTRY* hookEntry, GO_INLINE_REGS* regs) {
#endif
    if (!hookEntry || !regs)
        return;

    hook_disable();

    GO_INLINE_CALL call;
    call.HookEntry = hookEntry;
    call.Regs = regs;
    if (!hook_call_on_alt_stack(GoInlineHookDispatchOnStack, &call)) {
        static LONG warned = 0;
        if (InterlockedExchange(&warned, 1) == 0)
            DebugOutput("GoInlineHookDispatch: no alternate stack available, Go function hits are dropped.\n");
    }

    hook_enable();
}

// Locate the safe inline-hook site for a Go function:
// - Standard Go functions begin with a split-stack check (`cmp rsp, [r14+0x10]; jbe morestack` on RegABI x64,
//   `mov rcx, gs:[0x28]; cmp rsp, [rcx+0x10]; jbe morestack` on StackABI x64, or `mov ecx, fs:[0x14]; cmp esp, [ecx+8]; jbe morestack` on x86).
//   `morestack` at the end of the function finishes with `jmp entry` (+0). Placing the 5-byte E9 jump immediately
//   after `jbe morestack` (right at `sub rsp, frame_size`) ensures:
//     1) `morestack` has already grown the stack before the hook runs, and its `jmp entry` does not re-trigger the hook;
//     2) RSP/ESP and all Go argument registers (RAX..R11) are still untouched at function-entry values;
//     3) the 5-byte patch never straddles the `jbe morestack` instruction.
// - For `//go:nosplit` functions without a split-stack prologue (e.g. `syscall.Syscall*`, `time.Sleep`), returns `funcAddr`.
static PBYTE GoFindHookSite(PBYTE funcAddr, DWORD maxFuncSize, PBYTE* pCodeLimit) {
    DWORD scanLen = (maxFuncSize > 0 && maxFuncSize < 32) ? maxFuncSize : 32;
    PBYTE funcEnd = funcAddr + (maxFuncSize > 0 ? maxFuncSize : 64);
    *pCodeLimit = funcEnd;

    _DInst insns[12];
    unsigned int count = 0;
    _CodeInfo codeInfo;
    codeInfo.codeOffset = (_OffsetType)(ULONG_PTR)funcAddr;
    codeInfo.code = funcAddr;
    codeInfo.codeLen = (int)scanLen;
#ifdef _WIN64
    codeInfo.dt = Decode64Bits;
#else
    codeInfo.dt = Decode32Bits;
#endif
    codeInfo.features = DF_NONE;

    if (distorm_decompose(&codeInfo, insns, 12, &count) == DECRES_INPUTERR || count < 2)
        return funcAddr;

    BOOL sawStackGuard = FALSE;
    for (unsigned int i = 0; i < count && i < 5 && (i + 1) < count; i++) {
        if (insns[i].flags == FLAG_NOT_DECODABLE || insns[i + 1].flags == FLAG_NOT_DECODABLE)
            break;

        PBYTE b = (PBYTE)(ULONG_PTR)insns[i].addr;
        BYTE sz = insns[i].size;

        // Check for CMP reg, [reg + disp8] where disp8 == 0x10 (x64 g.stackguard0) or 0x08 (x86 g.stackguard0)
        BOOL isStackGuardCmp = FALSE;
#ifdef _WIN64
        if (sz == 4 && (b[0] >= 0x48 && b[0] <= 0x4F) && b[1] == 0x3B &&
            (b[2] & 0xC0) == 0x40 && (b[2] & 0x07) != 4 && b[3] == 0x10) {
            isStackGuardCmp = TRUE;
        }
#else
        if (sz == 3 && b[0] == 0x3B && (b[1] & 0xC0) == 0x40 && (b[1] & 0x07) != 4 && b[2] == 0x08) {
            isStackGuardCmp = TRUE;
        }
#endif
        if (isStackGuardCmp) {
            sawStackGuard = TRUE;
            PBYTE jb = (PBYTE)(ULONG_PTR)insns[i + 1].addr;
            BYTE jsz = insns[i + 1].size;
            PBYTE jbeEnd = jb + jsz;
            PBYTE jbeTarget = NULL;

            if (jsz == 2 && jb[0] == 0x76) {
                jbeTarget = jbeEnd + *(int8_t*)(jb + 1);
            } else if (jsz == 6 && jb[0] == 0x0F && jb[1] == 0x86) {
                jbeTarget = jbeEnd + *(int32_t*)(jb + 2);
            }

            if (jbeTarget && jbeTarget > jbeEnd) {
                if (jbeTarget <= funcEnd)
                    *pCodeLimit = jbeTarget;
                return jbeEnd;
            }
        }

        // Only allow standard split-stack prologue instructions before the CMP:
        // - GS/FS TLS segment load (0x64 / 0x65)
        // - MOV reg, [reg + disp] or LEA reg, [rsp - disp] (0x8B / 0x8D with optional REX)
        // - huge frames: MOV r12, rsp; SUB r12, imm (0x89, 0x81 / 0x83 with REX)
        BYTE op = b[0];
#ifdef _WIN64
        if (op >= 0x40 && op <= 0x4F && sz > 1)
            op = b[1];
#endif
        if (b[0] != 0x64 && b[0] != 0x65 && op != 0x8B && op != 0x8D && op != 0x89 && op != 0x81 && op != 0x83)
            break;
    }

    // A split-stack check was seen but its `jbe morestack` could not be resolved: patching at +0 would straddle
    // the check and be re-entered by morestack's `jmp entry`. Refuse the inline hook (caller falls back to 0xCC).
    if (sawStackGuard)
        return NULL;

    return funcAddr;
}

// Inline stub fixed parts (prologue, dispatch call, epilogue); relocated instructions and the back-jump follow
#ifdef _WIN64

static const BYTE go_prologue64[] = {
    0x9C,                                           // pushfq
    0x50, 0x53, 0x51, 0x52, 0x57, 0x56, 0x55,       // push rax, rbx, rcx, rdx, rdi, rsi, rbp
    0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, // push r8, r9, r10, r11
    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, // push r12, r13, r14, r15
    0x48, 0x89, 0xE2,                               // mov rdx, rsp (arg2 = &GO_INLINE_REGS)
    0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00,       // sub rsp, 0x80
    0x0F, 0x11, 0x04, 0x24,                         // movups [rsp+0x00], xmm0
    0x0F, 0x11, 0x4C, 0x24, 0x10,                   // movups [rsp+0x10], xmm1
    0x0F, 0x11, 0x54, 0x24, 0x20,                   // movups [rsp+0x20], xmm2
    0x0F, 0x11, 0x5C, 0x24, 0x30,                   // movups [rsp+0x30], xmm3
    0x0F, 0x11, 0x64, 0x24, 0x40,                   // movups [rsp+0x40], xmm4
    0x0F, 0x11, 0x6C, 0x24, 0x50,                   // movups [rsp+0x50], xmm5
    0x44, 0x0F, 0x11, 0x74, 0x24, 0x60,             // movups [rsp+0x60], xmm14
    0x44, 0x0F, 0x11, 0x7C, 0x24, 0x70,             // movups [rsp+0x70], xmm15 (Go zero register)
    0x48, 0x89, 0xE5,                               // mov rbp, rsp
    0x48, 0x83, 0xE4, 0xF0,                         // and rsp, -16
    0x48, 0x83, 0xEC, 0x20,                         // sub rsp, 0x20 (Win64 shadow space)
    0xFC                                            // cld
};

static const BYTE go_epilogue64[] = {
    0x48, 0x89, 0xEC,                               // mov rsp, rbp
    0x0F, 0x10, 0x04, 0x24,                         // movups xmm0, [rsp+0x00]
    0x0F, 0x10, 0x4C, 0x24, 0x10,                   // movups xmm1, [rsp+0x10]
    0x0F, 0x10, 0x54, 0x24, 0x20,                   // movups xmm2, [rsp+0x20]
    0x0F, 0x10, 0x5C, 0x24, 0x30,                   // movups xmm3, [rsp+0x30]
    0x0F, 0x10, 0x64, 0x24, 0x40,                   // movups xmm4, [rsp+0x40]
    0x0F, 0x10, 0x6C, 0x24, 0x50,                   // movups xmm5, [rsp+0x50]
    0x44, 0x0F, 0x10, 0x74, 0x24, 0x60,             // movups xmm14, [rsp+0x60]
    0x44, 0x0F, 0x10, 0x7C, 0x24, 0x70,             // movups xmm15, [rsp+0x70]
    0x48, 0x81, 0xC4, 0x80, 0x00, 0x00, 0x00,       // add rsp, 0x80
    0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, // pop r15, r14, r13, r12
    0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, // pop r11, r10, r9, r8
    0x5D, 0x5E, 0x5F, 0x5A, 0x59, 0x5B, 0x58,       // pop rbp, rsi, rdi, rdx, rcx, rbx, rax
    0x9D                                            // popfq
};
// mov rcx, imm64 (10) + mov rax, imm64 (10) + call rax (2)
#define GO_INLINE_STUB_DISPATCH 22
#define GO_INLINE_STUB_FIXED (sizeof(go_prologue64) + GO_INLINE_STUB_DISPATCH + sizeof(go_epilogue64))
#else

static const BYTE go_prologue32[] = {
    0x9C,                   // pushfd
    0x60,                   // pushad
    0x89, 0xE0,             // mov eax, esp (arg2 = &GO_INLINE_REGS)
    0x89, 0xE5,             // mov ebp, esp
    0x83, 0xE4, 0xF0,       // and esp, -16
    0xFC,                   // cld
    0x50                    // push eax
};

static const BYTE go_epilogue32[] = {
    0x89, 0xEC,             // mov esp, ebp
    0x61,                   // popad
    0x9D                    // popfd
};
// push imm32 (5) + mov eax, imm32 (5) + call eax (2)
#define GO_INLINE_STUB_DISPATCH 12
#define GO_INLINE_STUB_FIXED (sizeof(go_prologue32) + GO_INLINE_STUB_DISPATCH + sizeof(go_epilogue32))
#endif

// Inline (E9) patching is only performed while the process is still single-threaded (GoProcessPending from
// CAPE_post_init, before the entry point runs). Modules instrumented later from YaraCallback (unpacked / injected
// Go payloads) have Go worker threads running; overwriting several instructions under a live thread is unsafe, so
// those use the 1-byte 0xCC software breakpoint only.
static BOOL g_go_inline_allowed = FALSE;

// Install a Go-safe 5-byte E9 inline hook at hookSite:
// - Runs a pure observer stub in hd->pre_tramp that saves all Go ABI registers (RAX..R15, XMM0..XMM5, XMM14, XMM15, RFLAGS),
//   invokes GoInlineHookDispatch (which returns before resuming the Go function so ZERO foreign return PCs remain on the
//   goroutine stack during function execution, stack growth, or GC unwinding), restores all registers, executes the
//   relocated stolen instructions, and jumps back to hookSite + stolenLen.
static BOOL GoSetInlineHook(GO_HOOK_ENTRY* hookEntry, DWORD maxFuncSize) {
    if (!hookEntry || !hookEntry->Address)
        return FALSE;

    PBYTE codeLimit = NULL;
    PBYTE hookSite = GoFindHookSite((PBYTE)hookEntry->Address, maxFuncSize, &codeLimit);
    if (!hookSite || codeLimit < hookSite + 5 || !IsBufferAccessible(hookSite, 8))
        return FALSE;

    // Refuse sites that already start with a rel32 jmp (our own earlier patch or a foreign hook):
    // GoSetFunctionHook already returned for entries we know about, so anything here is not ours to steal.
    if (*hookSite == 0xE9)
        return FALSE;

    DWORD availBytes = (DWORD)(codeLimit - hookSite);
    if (availBytes > 32)
        availBytes = 32;

    _DInst insns[16];
    unsigned int count = 0;
    _CodeInfo codeInfo;
    codeInfo.codeOffset = (_OffsetType)(ULONG_PTR)hookSite;
    codeInfo.code = hookSite;
    codeInfo.codeLen = (int)availBytes;
#ifdef _WIN64
    codeInfo.dt = Decode64Bits;
#else
    codeInfo.dt = Decode32Bits;
#endif
    codeInfo.features = DF_NONE;

    if (distorm_decompose(&codeInfo, insns, 16, &count) == DECRES_INPUTERR || count == 0)
        return FALSE;

    DWORD stolenLen = 0;
    unsigned int nStolen = 0;
    for (unsigned int i = 0; i < count && stolenLen < 5; i++) {
        _DInst* ci = &insns[i];
        if (ci->flags == FLAG_NOT_DECODABLE || ci->size == 0)
            return FALSE;

        PBYTE insnAddr = (PBYTE)(ULONG_PTR)ci->addr;
        BYTE fc = META_GET_FC(ci->meta);
        // Reject flow-control instructions (CALL, RET, SYSCALL/SYSENTER, INT/UD2, LOOP/JRCXZ, indirect or prefixed
        // branches) except the exact unprefixed near/short JMP and Jcc encodings relocated below.
        if (fc != FC_NONE && fc != FC_CMOV) {
            BOOL relocatableBranch =
                (ci->size == 5 && insnAddr[0] == 0xE9) ||
                (ci->size == 6 && insnAddr[0] == 0x0F && (insnAddr[1] & 0xF0) == 0x80) ||
                (ci->size == 2 && insnAddr[0] == 0xEB) ||
                (ci->size == 2 && (insnAddr[0] & 0xF0) == 0x70);
            if (!relocatableBranch)
                return FALSE;
        }

        stolenLen += ci->size;
        nStolen++;
    }

    if (stolenLen < 5 || hookSite + stolenLen > codeLimit)
        return FALSE;

    // Validate everything that can fail *before* taking a hook_data_t slot (arena slots are never returned):
    //  - no stolen branch may target the interior of the patched window (hookSite, hookSite + stolenLen);
    //  - every relocated branch / RIP-relative target must lie within +-1GB of hookSite, so that with the stub
    //    allocated within 1GB of hookSite (alloc_hookdata_near) no rel32 can overflow;
    //  - the finished stub must fit pre_tramp (fixed part + relocated instructions + 5-byte back-jump).
    DWORD relocatedLen = 0;
    for (unsigned int i = 0; i < nStolen; i++) {
        _DInst* ci = &insns[i];
        PBYTE insnAddr = (PBYTE)(ULONG_PTR)ci->addr;
        PBYTE target = NULL;
        DWORD outSize = ci->size;
        if (ci->size == 5 && insnAddr[0] == 0xE9) {
            target = insnAddr + 5 + *(int32_t*)(insnAddr + 1);
        } else if (ci->size == 6 && insnAddr[0] == 0x0F && (insnAddr[1] & 0xF0) == 0x80) {
            target = insnAddr + 6 + *(int32_t*)(insnAddr + 2);
        } else if (ci->size == 2 && insnAddr[0] == 0xEB) {
            target = insnAddr + 2 + *(int8_t*)(insnAddr + 1);
            outSize = 5;
        } else if (ci->size == 2 && (insnAddr[0] & 0xF0) == 0x70) {
            target = insnAddr + 2 + *(int8_t*)(insnAddr + 1);
            outSize = 6;
        }
#ifdef _WIN64
        else if (ci->flags & FLAG_RIP_RELATIVE) {
            BYTE immBytes = 0;
            for (int k = 0; k < OPERANDS_NO; k++) {
                if (ci->ops[k].type == O_IMM || ci->ops[k].type == O_IMM1 || ci->ops[k].type == O_IMM2)
                    immBytes += (BYTE)(ci->ops[k].size / 8);
            }
            if (ci->size < (BYTE)(4 + immBytes))
                return FALSE;
            target = insnAddr + ci->size + *(int32_t*)(insnAddr + ci->size - 4 - immBytes);
        }
#endif
        if (target) {
            if (target > hookSite && target < hookSite + stolenLen)
                return FALSE;
            INT64 dist = (INT64)(target - hookSite);
            if (dist < -(INT64)0x40000000 || dist > (INT64)0x40000000)
                return FALSE;
        }
        relocatedLen += outSize;
    }

    if (GO_INLINE_STUB_FIXED + relocatedLen + 5 > MAX_PRETRAMP_SIZE)
        return FALSE;

    hook_data_t* hd = alloc_hookdata_near(hookSite);
    if (!hd)
        return FALSE;

    PBYTE stub = hd->pre_tramp;
    DWORD p = 0;

#ifdef _WIN64
    // Save RFLAGS and all 15 GPRs (RAX..R15) -> forms GO_INLINE_REGS at RSP
    memcpy(stub + p, go_prologue64, sizeof(go_prologue64));
    p += sizeof(go_prologue64);

    // mov rcx, hookEntry
    stub[p++] = 0x48;
    stub[p++] = 0xB9;
    *(uint64_t*)(stub + p) = (uint64_t)(ULONG_PTR)hookEntry;
    p += 8;

    // mov rax, &GoInlineHookDispatch; call rax
    stub[p++] = 0x48;
    stub[p++] = 0xB8;
    *(uint64_t*)(stub + p) = (uint64_t)(ULONG_PTR)&GoInlineHookDispatch;
    p += 8;
    stub[p++] = 0xFF;
    stub[p++] = 0xD0;

    memcpy(stub + p, go_epilogue64, sizeof(go_epilogue64));
    p += sizeof(go_epilogue64);
#else
    memcpy(stub + p, go_prologue32, sizeof(go_prologue32));
    p += sizeof(go_prologue32);

    // push hookEntry
    stub[p++] = 0x68;
    *(uint32_t*)(stub + p) = (uint32_t)(ULONG_PTR)hookEntry;
    p += 4;

    // mov eax, &GoInlineHookDispatch; call eax
    stub[p++] = 0xB8;
    *(uint32_t*)(stub + p) = (uint32_t)(ULONG_PTR)&GoInlineHookDispatch;
    p += 4;
    stub[p++] = 0xFF;
    stub[p++] = 0xD0;

    memcpy(stub + p, go_epilogue32, sizeof(go_epilogue32));
    p += sizeof(go_epilogue32);
#endif

    // Relocate the stolen instructions into stub + p
    for (unsigned int i = 0; i < nStolen; i++) {
        _DInst* ci = &insns[i];
        PBYTE insnAddr = (PBYTE)(ULONG_PTR)ci->addr;
        PBYTE dstInsn = stub + p;

        if (ci->size == 5 && insnAddr[0] == 0xE9) {
            PBYTE target = insnAddr + 5 + *(int32_t*)(insnAddr + 1);
            INT64 rel = (INT64)(target - (dstInsn + 5));
            if (rel < INT32_MIN || rel > INT32_MAX)
                return FALSE;
            dstInsn[0] = 0xE9;
            *(int32_t*)(dstInsn + 1) = (int32_t)rel;
            p += 5;
        } else if (ci->size == 6 && insnAddr[0] == 0x0F && (insnAddr[1] & 0xF0) == 0x80) {
            PBYTE target = insnAddr + 6 + *(int32_t*)(insnAddr + 2);
            INT64 rel = (INT64)(target - (dstInsn + 6));
            if (rel < INT32_MIN || rel > INT32_MAX)
                return FALSE;
            dstInsn[0] = 0x0F;
            dstInsn[1] = insnAddr[1];
            *(int32_t*)(dstInsn + 2) = (int32_t)rel;
            p += 6;
        } else if (ci->size == 2 && insnAddr[0] == 0xEB) {
            PBYTE target = insnAddr + 2 + *(int8_t*)(insnAddr + 1);
            INT64 rel = (INT64)(target - (dstInsn + 5));
            if (rel < INT32_MIN || rel > INT32_MAX)
                return FALSE;
            dstInsn[0] = 0xE9;
            *(int32_t*)(dstInsn + 1) = (int32_t)rel;
            p += 5;
        } else if (ci->size == 2 && (insnAddr[0] & 0xF0) == 0x70) {
            PBYTE target = insnAddr + 2 + *(int8_t*)(insnAddr + 1);
            INT64 rel = (INT64)(target - (dstInsn + 6));
            if (rel < INT32_MIN || rel > INT32_MAX)
                return FALSE;
            dstInsn[0] = 0x0F;
            dstInsn[1] = 0x80 | (insnAddr[0] & 0x0F);
            *(int32_t*)(dstInsn + 2) = (int32_t)rel;
            p += 6;
        } else {
            memcpy(dstInsn, insnAddr, ci->size);
#ifdef _WIN64
            if (ci->flags & FLAG_RIP_RELATIVE) {
                BYTE immBytes = 0;
                for (int k = 0; k < OPERANDS_NO; k++) {
                    if (ci->ops[k].type == O_IMM || ci->ops[k].type == O_IMM1 || ci->ops[k].type == O_IMM2)
                        immBytes += (BYTE)(ci->ops[k].size / 8);
                }
                if (ci->size < (BYTE)(4 + immBytes))
                    return FALSE;
                BYTE dispOff = (BYTE)(ci->size - 4 - immBytes);
                int32_t origDisp = *(int32_t*)(insnAddr + dispOff);
                PBYTE target = insnAddr + ci->size + origDisp;
                INT64 newDisp = (INT64)(target - (dstInsn + ci->size));
                if (newDisp < INT32_MIN || newDisp > INT32_MAX)
                    return FALSE;
                *(int32_t*)(dstInsn + dispOff) = (int32_t)newDisp;
            }
#endif
            p += ci->size;
        }
    }

    // Final jump back to hookSite + stolenLen
    if (p + 5 > MAX_PRETRAMP_SIZE)
        return FALSE;
    PBYTE resumeAddr = hookSite + stolenLen;
    INT64 backRel = (INT64)(resumeAddr - (stub + p + 5));
    if (backRel < INT32_MIN || backRel > INT32_MAX)
        return FALSE;
    stub[p++] = 0xE9;
    *(int32_t*)(stub + p) = (int32_t)backRel;
    p += 4;

    INT64 fwdRel = (INT64)(stub - (hookSite + 5));
    if (fwdRel < INT32_MIN || fwdRel > INT32_MAX)
        return FALSE;

    FlushInstructionCache(GetCurrentProcess(), stub, p);

    DWORD oldProt = 0;
    if (!VirtualProtect(hookSite, 8, PAGE_EXECUTE_READWRITE, &oldProt))
        return FALSE;

    // Atomically patch the 5-byte E9 jump at hookSite while preserving bytes 5..7
    LONGLONG orig8 = *(volatile LONGLONG*)hookSite;
    LONGLONG patched8 = orig8;
    PBYTE patchBytes = (PBYTE)&patched8;
    patchBytes[0] = 0xE9;
    *(int32_t*)(patchBytes + 1) = (int32_t)fwdRel;
    BOOL patched = (InterlockedCompareExchange64((volatile LONGLONG*)hookSite, patched8, orig8) == orig8);

    VirtualProtect(hookSite, 8, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), hookSite, 8);

    if (!patched)
        return FALSE;   // bytes changed under us: leave the site untouched, caller falls back to 0xCC

    hookEntry->HookSite = hookSite;
    hookEntry->InlineHooked = TRUE;
    return TRUE;
}

// Sets an inline hook (5-byte E9 trampoline) on a recovered Go function address, falling back to a software breakpoint (0xCC) if needed
static void GoSetFunctionHook(PVOID funcAddress, DWORD maxFuncSize, const char* funcName, BOOL regAbi, int version) {
    if (!funcAddress || !funcName || !IsAddressAccessible(funcAddress))
        return;

    // Already hooked: nothing to do.
    // If the hook entry exists and uses SoftBPs which was cleared (ClearAllBreakpoints), re-arm it below.
    GO_HOOK_ENTRY* hookEntry = (GO_HOOK_ENTRY*)lookup_get(&g_go_hook_table, (ULONG_PTR)funcAddress, NULL);
    if (hookEntry) {
        if (hookEntry->InlineHooked && hookEntry->HookSite && IsAddressAccessible(hookEntry->HookSite) && *hookEntry->HookSite == 0xE9)
            return;
        if (lookup_get(&SoftBPs, (ULONG_PTR)funcAddress, NULL))
            return;
    }

    char safeFuncName[160];
    SanitizeForDebug(safeFuncName, sizeof(safeFuncName), funcName, strlen(funcName));

    // Register the hook entry before arming so a hit on another thread always finds its metadata
    if (!hookEntry)
        hookEntry = (GO_HOOK_ENTRY*)lookup_add(&g_go_hook_table, (ULONG_PTR)funcAddress, sizeof(GO_HOOK_ENTRY));
    if (!hookEntry)
        return;
    hookEntry->Address = funcAddress;
    hookEntry->RegAbi = regAbi;
    hookEntry->Version = version;
    strncpy_s(hookEntry->Name, sizeof(hookEntry->Name), funcName, _TRUNCATE);

    if (g_go_inline_allowed && GoSetInlineHook(hookEntry, maxFuncSize)) {
        DebugOutput("GoSetFunctionHook: Hooked '%s' at 0x%p (patch site 0x%p) via inline trampoline.\n",
                    safeFuncName, funcAddress, hookEntry->HookSite);
        return;
    }

    // Fallback to persistent software breakpoint if the function cannot be inline-patched
    if (SetSoftwareBreakpointEx(&SoftBPs, funcAddress, GoBreakpointHandler, TRUE))
        DebugOutput("GoSetFunctionHook: Hooked '%s' at 0x%p via software breakpoint (0xCC fallback).\n", safeFuncName, funcAddress);
    else
        DebugOutput("GoSetFunctionHook: Failed to set hook on '%s' at 0x%p.\n", safeFuncName, funcAddress);
}

// Extracts the compiler version from buildinfo (inspired by GoReSym).
static void GoParseBuildInfo(PBYTE pBuildinfo, DWORD Size, char* VersionOut, size_t VersionOutSize) {
    if (!pBuildinfo || Size < 32) return;

    BYTE ptrSize = pBuildinfo[14];
    BYTE flags = pBuildinfo[15];

    __try {
        if (flags & 2) {
            // Varint-prefixed strings immediately following 32-byte header (Go 1.18+)
            PBYTE pData = pBuildinfo + 32;
            PBYTE pEnd = pBuildinfo + Size;

            // Decode version string
            uint64_t verLen = 0;
            unsigned int shift = 0;
            while (pData < pEnd && shift <= 63) {
                BYTE b = *pData++;
                verLen |= ((uint64_t)(b & 0x7F)) << shift;
                if ((b & 0x80) == 0) break;
                shift += 7;
            }

            if (verLen > 0 && verLen < 128 && (pData + verLen) <= pEnd && IsAddressAccessible(pData)) {
                char versionBuf[128] = {0};
                char safeVersion[128] = {0};
                memcpy(versionBuf, pData, (size_t)verLen);
                if (VersionOut && VersionOutSize)
                    strncpy_s(VersionOut, VersionOutSize, versionBuf, _TRUNCATE);
                SanitizeForDebug(safeVersion, sizeof(safeVersion), versionBuf, (size_t)verLen);
                DebugOutput("GoParseBuildInfo: Recovered Go Compiler Version: %s\n", safeVersion);
            }
        } else if (ptrSize == sizeof(void*)) {
            // Pointer-based string headers: [dataPtr, len]
            PVOID* pVersionPtr = (PVOID*)(pBuildinfo + 16);

            if (IsAddressAccessible(pVersionPtr) && IsAddressAccessible(*pVersionPtr)) {
                PVOID pVerData = *(PVOID*)(*pVersionPtr);
                ULONG_PTR verLen = *(ULONG_PTR*)((PBYTE)(*pVersionPtr) + ptrSize);
                if (pVerData && verLen > 0 && verLen < 128 && IsAddressAccessible(pVerData)) {
                    char versionBuf[128] = {0};
                    char safeVersion[128] = {0};
                    memcpy(versionBuf, pVerData, verLen);
                    if (VersionOut && VersionOutSize)
                        strncpy_s(VersionOut, VersionOutSize, versionBuf, _TRUNCATE);
                    SanitizeForDebug(safeVersion, sizeof(safeVersion), versionBuf, (size_t)verLen);
                    DebugOutput("GoParseBuildInfo: Recovered Go Compiler Version: %s\n", safeVersion);
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DebugOutput("GoParseBuildInfo: Exception occurred parsing Go buildinfo.\n");
    }
}

// Parse the minor version from a Go version string ("go1.17.13", "devel go1.18-abc", "go1.22rc1"); -1 if not found
static int GoParseMinorVersion(const char* Version) {
    if (!Version)
        return -1;
    const char* p = strstr(Version, "go1.");
    if (!p)
        return -1;
    p += 4;
    int minor = 0, digits = 0;
    while (*p >= '0' && *p <= '9' && digits < 3) {
        minor = minor * 10 + (*p - '0');
        p++;
        digits++;
    }
    return digits ? minor : -1;
}

// True if the version string carries a GOEXPERIMENT list (" X:a,b,c") that disables any register ABI
// component. The linker appends " X:" + GOEXPERIMENT to runtime.buildVersion (Go 1.17+). In go1.17 every
// noregabi* token (noregabi, noregabiargs, noregabiwrappers, noregabig, noregabireflect, noregabidefer)
// forces regabiargs off through the buildcfg dependency check. Only meaningful for go1.17: go1.18+ forces
// the register ABI on amd64 regardless of GOEXPERIMENT.
static BOOL GoVersionHasNoRegAbi(const char* Version) {
    if (!Version)
        return FALSE;
    const char* p = strstr(Version, " X:");
    if (!p)
        return FALSE;
    p += 3;
    while (*p && *p != ' ') {
        if (strncmp(p, "noregabi", 8) == 0)
            return TRUE;
        while (*p && *p != ',' && *p != ' ')
            p++;
        if (*p == ',')
            p++;
    }
    return FALSE;
}

// Code-level ABI evidence (amd64). The register ABI pins g in R14, so the stack-split prologue of a Go
// function compiled for ABIInternal is "CMPQ SP, 16(R14)" (49 3B 66 10) or, for larger frames,
// "LEAQ -n(SP), R12; CMPQ R12, 16(R14)" (4D 3B 66 10). Stack-ABI Go on Windows loads g from TLS first:
// "MOVQ GS:[disp32], reg" (65 48|4C 8B modrm(mod=00,rm=100) SIB=25).
// ABI0 wrappers and assembly routines in register-ABI binaries also load g from TLS, so callers must vote
// over many functions instead of trusting one sample.
#ifdef _WIN64
#define GO_ABI_PROLOGUE_WINDOW 24
#define GO_ABI_MAX_SAMPLES     512
static void GoVoteAbiPrologue(PBYTE Code, DWORD* RegVotes, DWORD* StackVotes) {
    __try {
        if (!IsBufferAccessible(Code, GO_ABI_PROLOGUE_WINDOW + 5))
            return;
        for (DWORD k = 0; k <= GO_ABI_PROLOGUE_WINDOW; k++) {
            if ((Code[k] == 0x49 || Code[k] == 0x4D) && Code[k + 1] == 0x3B && Code[k + 2] == 0x66 && Code[k + 3] == 0x10) {
                (*RegVotes)++;
                return;
            }
            if ((Code[k] == 0x64 || Code[k] == 0x65) && (Code[k + 1] == 0x48 || Code[k + 1] == 0x4C) && Code[k + 2] == 0x8B &&
                (Code[k + 3] & 0xC7) == 0x04 && Code[k + 4] == 0x25) {
                (*StackVotes)++;
                return;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}
#endif

static BOOL GoNameEndsWith(const char* name, const char* suffix) {
    size_t n = strlen(name), s = strlen(suffix);
    return n >= s && strcmp(name + n - s, suffix) == 0;
}

// Third-party symbols carry the full module path (github.com/x/y/v3.(*T).M). Match on a module-path fragment
// plus the exact ".(*Type).Method" / ".Func" suffix so only the named entry point is hooked, not the whole package.
static BOOL GoPkgFunc(const char* name, const char* pkgFragment, const char* suffix) {
    return strstr(name, pkgFragment) != NULL && GoNameEndsWith(name, suffix);
}

// Compiler-generated closure (".func1", ".func2.1") or deferwrap (".deferwrap1") name component
static BOOL GoIsGeneratedName(const char* name) {
    const char* p = name;
    while ((p = strstr(p, ".func")) != NULL) {
        if (p[5] >= '0' && p[5] <= '9')
            return TRUE;
        p += 5;
    }
    p = name;
    while ((p = strstr(p, ".deferwrap")) != NULL) {
        if (p[10] >= '0' && p[10] <= '9')
            return TRUE;
        p += 10;
    }
    return FALSE;
}

// Filter for high-signal Go functions/methods, skipping ABI wrappers, package initializers, and closures
static BOOL ShouldHookGoFunction(const char* funcName) {
    if (!funcName || *funcName == '\0')
        return FALSE;

    // Skip compiler-generated ABI0/ABIInternal wrappers, defer wrappers, closures, package init routines
    // (pkg.init, pkg.init.0) and synthetic symbols. User functions such as main.initConfig or
    // main.funcDecrypt are not excluded.
    if (GoNameEndsWith(funcName, ".abi0") ||
        GoNameEndsWith(funcName, ".abiinternal") ||
        GoIsGeneratedName(funcName) ||
        GoNameEndsWith(funcName, ".init") ||
        strstr(funcName, ".init.") ||
        strstr(funcName, "..inittask") ||
        strncmp(funcName, "type:", 5) == 0 ||
        strncmp(funcName, "type..", 6) == 0 ||
        strncmp(funcName, "go:", 3) == 0 ||
        strncmp(funcName, "go..", 4) == 0) {
        return FALSE;
    }

    // Cryptography key setup
    if (strcmp(funcName, "crypto/aes.NewCipher") == 0 ||
        strcmp(funcName, "crypto/cipher.NewGCM") == 0 ||
        strcmp(funcName, "crypto/cipher.NewCBCDecrypter") == 0 ||
        strcmp(funcName, "crypto/cipher.NewCBCEncrypter") == 0 ||
        strcmp(funcName, "crypto/cipher.NewCFBDecrypter") == 0 ||
        strcmp(funcName, "crypto/cipher.NewCFBEncrypter") == 0 ||
        strcmp(funcName, "crypto/cipher.NewCTR") == 0 ||
        strcmp(funcName, "crypto/cipher.NewOFB") == 0 ||
        strcmp(funcName, "crypto/rc4.NewCipher") == 0 ||
        strcmp(funcName, "crypto/des.NewCipher") == 0 ||
        strcmp(funcName, "crypto/des.NewTripleDESCipher") == 0 ||
        strstr(funcName, "chacha20poly1305.New") != NULL ||
        strstr(funcName, "chacha20.NewUnauthenticatedCipher") != NULL ||
        strstr(funcName, "blowfish.NewCipher") != NULL ||
        strstr(funcName, "cast5.NewCipher") != NULL ||
        strstr(funcName, "pbkdf2.Key") != NULL ||
        strstr(funcName, "argon2.IDKey") != NULL ||
        strstr(funcName, "argon2.Key") != NULL ||
        strstr(funcName, "scrypt.Key") != NULL) {
        return TRUE;
    }

    // TLS plaintext read/write
    if (strcmp(funcName, "crypto/tls.(*Conn).Write") == 0 ||
        strcmp(funcName, "crypto/tls.(*Conn).Read") == 0) {
        return TRUE;
    }

    // HTTP & WebSockets
    if (strcmp(funcName, "net/http.Get") == 0 ||
        strcmp(funcName, "net/http.Post") == 0 ||
        strcmp(funcName, "net/http.Head") == 0 ||
        strcmp(funcName, "net/http.PostForm") == 0 ||
        strcmp(funcName, "net/http.NewRequest") == 0 ||
        strcmp(funcName, "net/http.NewRequestWithContext") == 0 ||
        strcmp(funcName, "net/http.(*Client).Do") == 0 ||
        strcmp(funcName, "net/http.(*Client).Get") == 0 ||
        strcmp(funcName, "net/http.(*Client).Post") == 0 ||
        strcmp(funcName, "net/http.(*Client).Head") == 0 ||
        strcmp(funcName, "net/http.(*Client).PostForm") == 0 ||
        strcmp(funcName, "net/smtp.SendMail") == 0 ||
        GoPkgFunc(funcName, "go-resty/resty", ".(*Request).Execute") ||
        GoPkgFunc(funcName, "valyala/fasthttp", "fasthttp.Do") ||
        GoPkgFunc(funcName, "valyala/fasthttp", ".(*Client).Do") ||
        GoPkgFunc(funcName, "imroc/req", ".(*Request).Send") ||
        GoPkgFunc(funcName, "imroc/req", ".(*Request).Do") ||
        GoPkgFunc(funcName, "gorilla/websocket", ".(*Dialer).Dial") ||
        GoPkgFunc(funcName, "gorilla/websocket", ".(*Dialer).DialContext") ||
        GoPkgFunc(funcName, "gorilla/websocket", ".(*Conn).WriteMessage") ||
        GoPkgFunc(funcName, "nhooyr.io/websocket", "websocket.Dial") ||
        GoPkgFunc(funcName, "coder/websocket", "websocket.Dial")) {
        return TRUE;
    }

    // Raw sockets & DNS
    if (strcmp(funcName, "net.Dial") == 0 ||
        strcmp(funcName, "net.DialTimeout") == 0 ||
        strcmp(funcName, "net.(*Dialer).Dial") == 0 ||
        strcmp(funcName, "net.(*Dialer).DialContext") == 0 ||
        strcmp(funcName, "net.Listen") == 0 ||
        strcmp(funcName, "net.LookupHost") == 0 ||
        strcmp(funcName, "net.LookupIP") == 0 ||
        strcmp(funcName, "net.LookupTXT") == 0) {
        return TRUE;
    }

    // Execution, syscalls, file system, registry, services, and sleep
    if (strcmp(funcName, "syscall.Syscall") == 0 ||
        strcmp(funcName, "syscall.Syscall6") == 0 ||
        strcmp(funcName, "syscall.Syscall9") == 0 ||
        strcmp(funcName, "syscall.Syscall12") == 0 ||
        strcmp(funcName, "syscall.Syscall15") == 0 ||
        strcmp(funcName, "syscall.SyscallN") == 0 ||
        strcmp(funcName, "os/exec.Command") == 0 ||
        strcmp(funcName, "os/exec.CommandContext") == 0 ||
        strcmp(funcName, "os/exec.(*Cmd).Start") == 0 ||
        strcmp(funcName, "os/exec.(*Cmd).Run") == 0 ||
        strcmp(funcName, "os.WriteFile") == 0 ||
        strcmp(funcName, "io/ioutil.WriteFile") == 0 ||
        strcmp(funcName, "os.OpenFile") == 0 ||
        strcmp(funcName, "os.Create") == 0 ||
        strcmp(funcName, "os.Remove") == 0 ||
        strcmp(funcName, "os.RemoveAll") == 0 ||
        strcmp(funcName, "os.UserHomeDir") == 0 ||
        strcmp(funcName, "os.UserConfigDir") == 0 ||
        strcmp(funcName, "os/user.Current") == 0 ||
        strcmp(funcName, "path/filepath.Walk") == 0 ||
        strcmp(funcName, "path/filepath.WalkDir") == 0 ||
        strcmp(funcName, "time.Sleep") == 0 ||
        // golang.org/x/sys/windows/registry
        GoPkgFunc(funcName, "windows/registry", "registry.OpenKey") ||
        GoPkgFunc(funcName, "windows/registry", "registry.CreateKey") ||
        GoPkgFunc(funcName, "windows/registry", "registry.Key.SetStringValue") ||
        GoPkgFunc(funcName, "windows/registry", "registry.Key.SetExpandStringValue") ||
        GoPkgFunc(funcName, "windows/registry", "registry.Key.SetBinaryValue") ||
        GoPkgFunc(funcName, "windows/registry", "registry.Key.SetDWordValue") ||
        // golang.org/x/sys/windows/svc/mgr
        GoPkgFunc(funcName, "windows/svc/mgr", "mgr.Connect") ||
        GoPkgFunc(funcName, "windows/svc/mgr", ".(*Mgr).CreateService") ||
        GoPkgFunc(funcName, "windows/svc/mgr", ".(*Service).Start") ||
        GoPkgFunc(funcName, "windows/svc/mgr", ".(*Service).Delete") ||
        // sample-authored loaders
        strncmp(funcName, "main.inject", 11) == 0 ||
        strncmp(funcName, "main.execute", 12) == 0 ||
        // github.com/yusufpapurcu/wmi (and StackExchange/wmi)
        GoPkgFunc(funcName, "/wmi", "wmi.Query") ||
        GoPkgFunc(funcName, "/wmi", "wmi.QueryNamespace") ||
        GoPkgFunc(funcName, "/wmi", ".(*Client).Query") ||
        // github.com/go-ldap/ldap[/v3]
        GoPkgFunc(funcName, "go-ldap/ldap", ".Dial") ||
        GoPkgFunc(funcName, "go-ldap/ldap", ".DialURL") ||
        GoPkgFunc(funcName, "go-ldap/ldap", ".(*Conn).Bind") ||
        GoPkgFunc(funcName, "go-ldap/ldap", ".(*Conn).SimpleBind") ||
        GoPkgFunc(funcName, "go-ldap/ldap", ".(*Conn).NTLMBind") ||
        GoPkgFunc(funcName, "go-ldap/ldap", ".(*Conn).Search") ||
        // github.com/jcmturner/gokrb5[/v8]/client
        GoPkgFunc(funcName, "jcmturner/gokrb5", "client.(*Client).Login") ||
        GoPkgFunc(funcName, "jcmturner/gokrb5", "client.(*Client).GetServiceTicket") ||
        GoPkgFunc(funcName, "jcmturner/gokrb5", "client.NewWithPassword") ||
        GoPkgFunc(funcName, "jcmturner/gokrb5", "client.NewWithKeytab") ||
        // github.com/masterzen/winrm
        GoPkgFunc(funcName, "masterzen/winrm", "winrm.NewClient") ||
        GoPkgFunc(funcName, "masterzen/winrm", ".(*Client).Run") ||
        GoPkgFunc(funcName, "masterzen/winrm", ".(*Client).RunWithString") ||
        GoPkgFunc(funcName, "masterzen/winrm", ".(*Client).RunWithContext") ||
        GoPkgFunc(funcName, "masterzen/winrm", ".(*Client).CreateShell") ||
        // github.com/hirochachacha/go-smb2
        GoPkgFunc(funcName, "hirochachacha/go-smb2", ".(*Dialer).Dial") ||
        GoPkgFunc(funcName, "hirochachacha/go-smb2", ".(*Dialer).DialContext") ||
        GoPkgFunc(funcName, "hirochachacha/go-smb2", ".(*Session).Mount") ||
        GoPkgFunc(funcName, "hirochachacha/go-smb2", ".(*Share).Create") ||
        GoPkgFunc(funcName, "hirochachacha/go-smb2", ".(*Share).OpenFile") ||
        GoPkgFunc(funcName, "hirochachacha/go-smb2", ".(*Share).WriteFile")) {
        return TRUE;
    }

    return FALSE;
}

// Detections from the CAPE_init YARA scan arrive before InitialiseDebugger (CAPE_post_init); they are queued
// here and instrumented by GoProcessPending() once the debugger is up. Keyed by pclntab address.
typedef struct _GO_PENDING {
    PVOID RegionBase;
    PBYTE Pclntab;
    PBYTE Buildinfo;
    volatile LONG Done;
} GO_PENDING;
static lookup_t g_go_pending = {0};

// Go symbol recovery and runtime instrumentation for one Go module located by the internal 'golang' YARA rule.
// RegionBase: base of the scanned region (YaraCallback user_data). Pclntab: $pclntab match. Buildinfo: $buildinfo
// match or NULL. No memory scanning is done here: the unpacking engine's region scans feed this via YARA.
void GoRecoverSymbols(PVOID RegionBase, PBYTE Pclntab, PBYTE Buildinfo) {
    int detectedVer = GoPclntabVersion(Pclntab);
    if (!RegionBase || detectedVer == GO_VER_UNKNOWN)
        return;

    if (!DebuggerInitialised) {
        GO_PENDING* pend = (GO_PENDING*)lookup_get(&g_go_pending, (ULONG_PTR)Pclntab, NULL);
        if (!pend)
            pend = (GO_PENDING*)lookup_add(&g_go_pending, (ULONG_PTR)Pclntab, sizeof(GO_PENDING));
        if (pend) {
            pend->RegionBase = RegionBase;
            pend->Pclntab = Pclntab;
            pend->Buildinfo = Buildinfo;
        }
        DebugOutput("GoRecoverSymbols: Go module at 0x%p queued until debugger initialisation.\n", RegionBase);
        return;
    }

    PVOID ImageBase = RegionBase;
    PBYTE pclntab = Pclntab;
    PBYTE buildinfo = Buildinfo;
    GO_HOOK_CANDIDATE* candidates = NULL;

    __try {
        // The PE header is optional: it only refines the text start and the preferred base used to relocate
        // pre-1.18 absolute function table entries. Without it the region bounds come from the allocation.
        PIMAGE_NT_HEADERS pNt = NULL;
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ImageBase;
        if (IsAddressAccessible(pDos) && pDos->e_lfanew > 0 && pDos->e_lfanew < 0x1000) {
            PIMAGE_NT_HEADERS pHdr = (PIMAGE_NT_HEADERS)((PBYTE)ImageBase + pDos->e_lfanew);
            if (IsAddressAccessible(pHdr) && pHdr->Signature == IMAGE_NT_SIGNATURE)
                pNt = pHdr;
        }
        ULONG_PTR sizeOfImage = pNt ? (ULONG_PTR)pNt->OptionalHeader.SizeOfImage : (ULONG_PTR)GetAccessibleSize(ImageBase);
        ULONG_PTR preferredBase = pNt ? (ULONG_PTR)pNt->OptionalHeader.ImageBase : (ULONG_PTR)ImageBase;
        PBYTE pImageEnd = (PBYTE)ImageBase + sizeOfImage;
        if (!sizeOfImage || pclntab < (PBYTE)ImageBase || pclntab + 64 > pImageEnd)
            return;

        ULONG_PTR textSectionVA = 0;
        if (pNt) {
            PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
            for (WORD i = 0; i < pNt->FileHeader.NumberOfSections && !textSectionVA; i++) {
                char secName[9] = {0};
                memcpy(secName, pSec[i].Name, 8);
                if (strcmp(secName, ".text") == 0 || (pSec[i].Characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)))
                    textSectionVA = (ULONG_PTR)ImageBase + pSec[i].VirtualAddress;
            }
        }

        // Metadata (buildinfo, file paths) is logged once per pclntab; the function walk always runs so
        // hooks removed by ClearAllBreakpoints are re-armed on a later YARA hit
        GO_MODULE_INFO* modInfo = (GO_MODULE_INFO*)lookup_get(&g_go_recovered_pclntab, (ULONG_PTR)pclntab, NULL);
        BOOL alreadyProcessed = (modInfo != NULL);
        if (!modInfo) {
            modInfo = (GO_MODULE_INFO*)lookup_add(&g_go_recovered_pclntab, (ULONG_PTR)pclntab, sizeof(GO_MODULE_INFO));
            if (!modInfo)
                return;
            modInfo->GoMinor = -1;
            modInfo->NoRegAbiExp = FALSE;
            modInfo->RegAbi = FALSE;
            modInfo->AbiResolved = FALSE;
        }

        BYTE ptrSize = pclntab[7];

        // Read pclntab header offsets according to Go version (per debug/gosym/pclntab.go)
        uint64_t nfunc = 0;
        PBYTE funcnametab = NULL;
        PBYTE functab = NULL;
        PBYTE funcdata = NULL;
        DWORD functabFieldSize = (detectedVer >= GO_VER_118) ? 4 : (DWORD)ptrSize;
        ULONG_PTR textStart = textSectionVA ? textSectionVA : (ULONG_PTR)ImageBase;

        if (detectedVer == GO_VER_118 || detectedVer == GO_VER_120) {
            nfunc = ReadHeaderWord(pclntab, 0, ptrSize);
            uint64_t hdrTextStart = ReadHeaderWord(pclntab, 2, ptrSize);
            if (hdrTextStart != 0) {
                if (hdrTextStart >= (ULONG_PTR)ImageBase && hdrTextStart < (ULONG_PTR)pImageEnd)
                    textStart = (ULONG_PTR)hdrTextStart;
                else if (hdrTextStart >= preferredBase && hdrTextStart < preferredBase + sizeOfImage)
                    textStart = (ULONG_PTR)ImageBase + ((ULONG_PTR)hdrTextStart - preferredBase);
            } else if (textSectionVA != 0) {
                textStart = textSectionVA;
            }
            funcnametab = pclntab + ReadHeaderWord(pclntab, 3, ptrSize);
            // header word 4: cutab, 5: filetab (not needed)
            functab     = pclntab + ReadHeaderWord(pclntab, 7, ptrSize);
            funcdata    = functab;
        } else if (detectedVer == GO_VER_116) {
            nfunc = ReadHeaderWord(pclntab, 0, ptrSize);
            funcnametab = pclntab + ReadHeaderWord(pclntab, 2, ptrSize);
            // header word 3: cutab, 4: filetab (not needed)
            functab     = pclntab + ReadHeaderWord(pclntab, 6, ptrSize);
            funcdata    = functab;
        } else if (detectedVer == GO_VER_12) {
            nfunc = ReadHeaderWord(pclntab, 0, ptrSize);
            funcnametab = pclntab;
            functab     = pclntab + 8 + ptrSize;
            funcdata    = pclntab;
        }

        if (!alreadyProcessed)
            DebugOutput("GoRecoverSymbols: Go binary detected at 0x%p, pclntab format %d, functions %llu, ptrsize %d, text start 0x%p\n",
                        ImageBase, detectedVer, (unsigned long long)nfunc, (int)ptrSize, (PVOID)textStart);
        char buildVersion[128] = {0};

        // 2. BuildInfo located by the same YARA rule ($buildinfo): no section scanning
        if (!alreadyProcessed && buildinfo && buildinfo >= (PBYTE)ImageBase && buildinfo + 32 <= pImageEnd) {
            ULONG_PTR avail = (ULONG_PTR)(pImageEnd - buildinfo);
            GoParseBuildInfo(buildinfo, (DWORD)(avail > 0x100000 ? 0x100000 : avail), buildVersion, sizeof(buildVersion));
        }

        if (!alreadyProcessed) {
            modInfo->GoMinor = GoParseMinorVersion(buildVersion);
            modInfo->NoRegAbiExp = GoVersionHasNoRegAbi(buildVersion);
        }

        // 3. Walk function table and hook high-value security/networking/crypto APIs
        if (!functab || !funcdata || !funcnametab || nfunc == 0 || nfunc > 500000) {
            return;
        }

        // Keep the functab for PC -> function name resolution (Go caller attribution for syscall targets)
        if (!modInfo->FuncTabValid) {
            modInfo->Version = detectedVer;
            modInfo->PtrSize = ptrSize;
            modInfo->FieldSize = functabFieldSize;
            modInfo->NFunc = nfunc;
            modInfo->Pclntab = pclntab;
            modInfo->Functab = functab;
            modInfo->Funcdata = funcdata;
            modInfo->Funcnametab = funcnametab;
            modInfo->ImageEnd = pImageEnd;
            modInfo->ImageBase = (ULONG_PTR)ImageBase;
            modInfo->PreferredBase = preferredBase;
            modInfo->SizeOfImage = sizeOfImage;
            modInfo->TextStart = textStart;
            MemoryBarrier();
            modInfo->FuncTabValid = TRUE;
        }

        candidates = (GO_HOOK_CANDIDATE*)calloc(GO_MAX_HOOK_CANDIDATES, sizeof(GO_HOOK_CANDIDATE));
        if (!candidates)
            return;
        DWORD nCandidates = 0;
#ifdef _WIN64
        DWORD abiRegVotes = 0, abiStackVotes = 0;
        uint64_t abiSampleStride = (nfunc > GO_ABI_MAX_SAMPLES) ? (nfunc / GO_ABI_MAX_SAMPLES) : 1;
#endif

        for (uint64_t i = 0; i < nfunc; i++) {
            ULONG_PTR funcEntryOff = 0;
            ULONG_PTR funcStructOff = 0;
            ULONG_PTR nextEntryOff = 0;

            if (functabFieldSize == 4) {
                uint32_t* pTab32 = (uint32_t*)(functab + 2 * i * 4);
                if ((PBYTE)&pTab32[2] > pImageEnd || !IsAddressAccessible(pTab32)) break;
                funcEntryOff = pTab32[0];
                funcStructOff = pTab32[1];
                if ((i + 1) < nfunc && (PBYTE)&pTab32[3] <= pImageEnd && IsAddressAccessible(&pTab32[2]))
                    nextEntryOff = pTab32[2];
            } else {
                uint64_t* pTab64 = (uint64_t*)(functab + 2 * i * 8);
                if ((PBYTE)&pTab64[2] > pImageEnd || !IsAddressAccessible(pTab64)) break;
                funcEntryOff = (ULONG_PTR)pTab64[0];
                funcStructOff = (ULONG_PTR)pTab64[1];
                if ((i + 1) < nfunc && (PBYTE)&pTab64[3] <= pImageEnd && IsAddressAccessible(&pTab64[2]))
                    nextEntryOff = (ULONG_PTR)pTab64[2];
            }

            ULONG_PTR funcAddress = 0;
            if (detectedVer >= GO_VER_118) {
                funcAddress = textStart + funcEntryOff;
            } else {
                if (funcEntryOff >= (ULONG_PTR)ImageBase && funcEntryOff < (ULONG_PTR)pImageEnd)
                    funcAddress = funcEntryOff;
                else if (funcEntryOff >= preferredBase && funcEntryOff < preferredBase + sizeOfImage)
                    funcAddress = (ULONG_PTR)ImageBase + (funcEntryOff - preferredBase);
                else
                    continue;
            }

            if (funcAddress < (ULONG_PTR)ImageBase || funcAddress >= (ULONG_PTR)pImageEnd || !IsAddressExecutable((PVOID)funcAddress)) {
                continue;
            }

            // In Go >= 1.16, funcStructOff is relative to funcdata (functab), whereas in Go 1.2 it is relative to pclntab
            PBYTE pFuncData = funcdata + funcStructOff;
            DWORD sz0 = (detectedVer >= GO_VER_118) ? 4 : (DWORD)ptrSize;
            if (pFuncData < pclntab || (pFuncData + sz0 + 4) > pImageEnd || !IsAddressAccessible(pFuncData + sz0))
                continue;

            uint32_t nameOff = *(uint32_t*)(pFuncData + sz0);
            PBYTE pName = funcnametab + nameOff;
            if (pName < pclntab || pName >= pImageEnd || !IsAddressAccessible(pName) || *pName == '\0')
                continue;

            const char* funcName = (const char*)pName;

#ifdef _WIN64
            // Sample prologues across the function table, skipping compiler-generated ABI wrappers
            if (!modInfo->AbiResolved && (i % abiSampleStride) == 0) {
                if (!GoNameEndsWith(funcName, ".abi0") && !GoNameEndsWith(funcName, ".abiinternal"))
                    GoVoteAbiPrologue((PBYTE)funcAddress, &abiRegVotes, &abiStackVotes);
            }
#endif

            if (ShouldHookGoFunction(funcName)) {
                if (nCandidates < GO_MAX_HOOK_CANDIDATES) {
                    DWORD maxSize = 64;
                    if (nextEntryOff > funcEntryOff && (nextEntryOff - funcEntryOff) <= 0x100000)
                        maxSize = (DWORD)(nextEntryOff - funcEntryOff);
                    if ((PBYTE)funcAddress + maxSize > pImageEnd)
                        maxSize = (DWORD)(pImageEnd - (PBYTE)funcAddress);
                    candidates[nCandidates].Address = (PVOID)funcAddress;
                    candidates[nCandidates].MaxSize = maxSize;
                    candidates[nCandidates].Name = funcName;
                    nCandidates++;
                }
            }
        }

        // 5. Resolve the argument ABI for this module before arming any hook.
        //    386: always stack ABI (Go never enabled the register ABI on 386).
        //    amd64: Go 1.2-1.16 stack ABI; Go 1.17 register ABI by default, disabled by GOEXPERIMENT=noregabi*;
        //    Go 1.18+ register ABI forced on (buildcfg: "regabi is always enabled on amd64").
        //    Go 1.16 and 1.17 share pclntab magic 0xFFFFFFFA. Resolve in order:
        //      a) prologue vote (code evidence, independent of buildinfo): >= 8 votes, >= 90% agreement
        //      b) pclntab format 1.18+ (0xFFFFFFF0/0xFFFFFFF1)      -> register ABI
        //      c) format 1.16/1.17, buildinfo go1.17 " X:noregabi*" -> stack ABI
        //      d) format 1.16/1.17, buildinfo go1.17+               -> register ABI
        //      e) otherwise                                         -> stack ABI
        //    runtime.spillArgs is not used: it is present in go1.17 noregabi builds too.
        if (!modInfo->AbiResolved) {
            const char* reason = "386 stack ABI";
            BOOL regabi = FALSE;
#ifdef _WIN64
            DWORD totalVotes = abiRegVotes + abiStackVotes;
            if (totalVotes >= 8 && abiRegVotes * 10 >= totalVotes * 9) {
                regabi = TRUE;
                reason = "prologue vote: CMP SP,16(R14)";
            } else if (totalVotes >= 8 && abiStackVotes * 10 >= totalVotes * 9) {
                reason = "prologue vote: g loaded from TLS";
            } else if (detectedVer >= GO_VER_118) {
                regabi = TRUE;
                reason = "pclntab format >= Go 1.18";
            } else if (modInfo->GoMinor == 17 && modInfo->NoRegAbiExp) {
                reason = "buildinfo go1.17 GOEXPERIMENT noregabi";
            } else if (modInfo->GoMinor >= 17) {
                regabi = TRUE;
                reason = "buildinfo version >= go1.17";
            } else {
                reason = (modInfo->GoMinor >= 0) ? "buildinfo version < go1.17" : "pclntab format < Go 1.18, no evidence of register ABI";
            }
            DebugOutput("GoRecoverSymbols: ABI prologue votes: register %u, stack %u.\n", abiRegVotes, abiStackVotes);
#endif
            modInfo->RegAbi = regabi;
            modInfo->AbiResolved = TRUE;
            DebugOutput("GoRecoverSymbols: Go module at 0x%p: go1.%d, ABI %s (%s), %u hook candidates.\n",
                        ImageBase, modInfo->GoMinor, regabi ? "register" : "stack", reason, nCandidates);
        }

        for (DWORD c = 0; c < nCandidates; c++)
            GoSetFunctionHook(candidates[c].Address, candidates[c].MaxSize, candidates[c].Name, modInfo->RegAbi, detectedVer);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DebugOutput("GoRecoverSymbols: Exception occurred parsing Go pclntab structures.\n");
    }

    if (candidates)
        free(candidates);
}

// Called from CAPE_post_init once the debugger is initialised: instrument Go modules detected by the
// init-time YARA scan. No scanning here; entries were produced by YaraCallback.
void GoProcessPending(void) {
    // Still single-threaded here (called from CAPE_post_init in the loader's init path, before the entry point):
    // the only window in which multi-byte inline patches can be written safely.
    g_go_inline_allowed = TRUE;
    for (entry_t* e = (entry_t*)g_go_pending.root; e != NULL; e = e->next) {
        GO_PENDING* pend = (GO_PENDING*)e->data;
        if (InterlockedExchange(&pend->Done, 1) == 0)
            GoRecoverSymbols(pend->RegionBase, pend->Pclntab, pend->Buildinfo);
    }
    g_go_inline_allowed = FALSE;
}
