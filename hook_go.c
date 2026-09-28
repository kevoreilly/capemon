#include <stdio.h>
#include <stdint.h>
#include "ntapi.h"
#include "log.h"
#include "misc.h"
#include "config.h"
#include "lookup.h"
#include "CAPE\CAPE.h"
#include "CAPE\Debugger.h"

#define LOQ_string(cat, fmt, ...) \
do { \
    static volatile LONG _index; \
    if (_index == 0) \
        InterlockedExchange(&_index, InterlockedIncrement(&g_log_index)); \
    loq(_index, cat, "GoBreakpoint", TRUE, 0, fmt, ##__VA_ARGS__); \
} while (0)

#define GO_VER_UNKNOWN 0
#define GO_VER_12      1
#define GO_VER_116     2
#define GO_VER_118     3
#define GO_VER_120     4

#define GO_BP_NOT_OURS   0
#define GO_BP_PERSISTENT 1
#define GO_BP_ONESHOT    2

// Table of hooked Go functions keyed by function entry address
static lookup_t g_go_hook_table = {0};

typedef struct _GO_HOOK_ENTRY {
    PVOID Address;
    char Name[256];
} GO_HOOK_ENTRY;

// Structure to track unencrypted TLS payload read buffer on return, keyed by returnAddress
typedef struct _GO_TLS_RETURN_STATE {
    PVOID returnAddress;
    PVOID readBuffer;
    PVOID bytesReadSlot;
} GO_TLS_RETURN_STATE;

static lookup_t g_go_tls_return_table = {0};

// Detected Go runtime metadata for this process
static int g_go_detected_version = GO_VER_UNKNOWN;
static BOOL g_go_uses_regabi = FALSE;

extern PVOID ImageBase;
extern lookup_t SoftBPs;
extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern BOOL IsAddressAccessible(PVOID Address);
extern BOOL SetSoftwareBreakpoint(lookup_t *BPs, LPVOID Address);
extern BOOL ClearSoftwareBreakpoint(lookup_t *BPs, LPVOID Address);
extern BOOL addr_in_our_dll_range(PVOID Address, ULONG_PTR Addr);

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
static ULONG_PTR GoGetArgWord(PCONTEXT Context, DWORD idx) {
#ifdef _WIN64
    if (g_go_uses_regabi) {
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
    return 0;
#endif
}

// Detects PE files reliably even if the "MZ" header magic has been wiped/zeroed out
static BOOL IsPEFile(PVOID pBase) {
    if (!pBase || !IsAddressAccessible(pBase))
        return FALSE;

    __try {
        if (*(PWORD)pBase == 0x5A4D) { // "MZ"
            return TRUE;
        }

        PDWORD pBuf = (PDWORD)pBase;
        for (DWORD i = 0; i < 256; i++) {
            if (IsAddressAccessible(&pBuf[i])) {
                if (pBuf[i] == 0x00004550) { // "PE\0\0"
                    return TRUE;
                }
            } else {
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return FALSE;
}

// Safely scan a memory section for a specific byte pattern
static PBYTE ScanSectionForBytes(PBYTE pStart, DWORD Size, PBYTE pPattern, DWORD PatternSize) {
    if (Size < PatternSize || !pStart || !pPattern) return NULL;
    __try {
        for (PBYTE p = pStart; p <= pStart + Size - PatternSize; p++) {
            if (memcmp(p, pPattern, PatternSize) == 0) {
                return p;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    return NULL;
}

// Safely scan a memory section for the Go pclntab magic header
static PBYTE ScanSectionForPclntab(PBYTE pStart, DWORD Size, int* pOutVer) {
    if (Size < 16 || !pStart) return NULL;
    __try {
        for (PBYTE p = pStart; p <= pStart + Size - 16; p++) {
            DWORD Magic = *(PDWORD)p;
            int ver = GO_VER_UNKNOWN;

            if (Magic == 0xFFFFFFF1) {
                ver = GO_VER_120;
            } else if (Magic == 0xFFFFFFF0) {
                ver = GO_VER_118;
            } else if (Magic == 0xFFFFFFFA) {
                ver = GO_VER_116;
            } else if (Magic == 0xFFFFFFFB) {
                ver = GO_VER_12;
            }

            if (ver != GO_VER_UNKNOWN) {
                // Header validation per runtime/symtab.go:
                // byte 4, 5 == 0, byte 6 is minLC (1, 2, or 4), byte 7 is ptrSize (4 or 8)
                if (p[4] == 0 && p[5] == 0 &&
                    (p[6] == 1 || p[6] == 2 || p[6] == 4) &&
                    (p[7] == 4 || p[7] == 8)) {

                    if (pOutVer) *pOutVer = ver;
                    return p;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    return NULL;
}

// Log a recovered Go string argument safely (combining pointer and explicit length)
static void LogGoString(const char* label, PVOID pStrData, ULONG_PTR length) {
    if (pStrData != NULL && length > 0 && length < 2048 && IsAddressAccessible(pStrData)) {
        char safeBuf[200];
        SanitizeForDebug(safeBuf, sizeof(safeBuf), (const char*)pStrData, (size_t)length);
        LOQ_string("go_trace", "sS", "Param", label, "Value", (int)length, (const char*)pStrData);
        DebugOutput("Go Trace: Parameter [%s] = \"%s\"\n", label, safeBuf);
    }
}

// Global hook callback executed whenever any registered Go breakpoint is hit
static BOOL GoBreakpointCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo) {
    if (!pBreakpointInfo || !ExceptionInfo)
        return TRUE;

    // Resolve the function name associated with this breakpoint via thread-safe lookup
    const char* funcName = "UnknownGoFunc";
    GO_HOOK_ENTRY* hookEntry = (GO_HOOK_ENTRY*)lookup_get(&g_go_hook_table, (ULONG_PTR)pBreakpointInfo->Address, NULL);
    if (hookEntry) {
        funcName = hookEntry->Name;
    }

    char safeFuncName[160];
    SanitizeForDebug(safeFuncName, sizeof(safeFuncName), funcName, strlen(funcName));

    LOQ_string("go_trace", "s", "Function", funcName);
    DebugOutput("Go Trace: Intercepted Execution of Go Function: %s at 0x%p\n", safeFuncName, pBreakpointInfo->Address);

    PCONTEXT ctx = ExceptionInfo->ContextRecord;

    // Dynamic argument tracing based on ABI (RegABI on x64 vs. Stack ABI)
    __try {
        if (strstr(funcName, "syscall.Syscall")) {
            // syscall.Syscall(trap, nargs, a1, a2, a3 uintptr)
            ULONG_PTR trapAddress = GoGetArgWord(ctx, 0);

            // Check if this is a direct memory address jump (indicates in-memory shellcode or PE execution)
            if (trapAddress != 0 && IsAddressAccessible((PVOID)trapAddress)) {
                if (!addr_in_our_dll_range(NULL, trapAddress)) {
                    MEMORY_BASIC_INFORMATION mbi;
                    if (VirtualQuery((PVOID)trapAddress, &mbi, sizeof(mbi)) != 0) {
                        if ((mbi.State == MEM_COMMIT) &&
                            (mbi.Type == MEM_PRIVATE) &&
                            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {

                            if (IsPEFile(mbi.AllocationBase)) {
                                DebugOutput("Go Trace: Detected direct in-memory PE execution (MZ or PE signature found) at 0x%p! (Size: 0x%x)\n", (PVOID)trapAddress, (unsigned int)mbi.RegionSize);
                                LOQ_string("go_trace", "sp", "Event", "Go Reflective PE Payload Execution Intercepted",
                                           "Jump Address", (PVOID)trapAddress);
                            } else {
                                DebugOutput("Go Trace: Detected direct in-memory shellcode execution at 0x%p! (Size: 0x%x)\n", (PVOID)trapAddress, (unsigned int)mbi.RegionSize);
                                LOQ_string("go_trace", "sp", "Event", "Go Direct Shellcode/Payload Execution Intercepted",
                                           "Jump Address", (PVOID)trapAddress);
                            }

                            TrackExecution((PVOID)trapAddress);
                        }
                    }
                }
            }
        }
        else if (strstr(funcName, "time.Sleep")) {
            // time.Sleep(d Duration) where Duration is int64 nanoseconds
            uint64_t nanoseconds = 0;
#ifdef _WIN64
            nanoseconds = (uint64_t)GoGetArgWord(ctx, 0);
#else
            uint32_t low = (uint32_t)GoGetArgWord(ctx, 0);
            uint32_t high = (uint32_t)GoGetArgWord(ctx, 1);
            nanoseconds = ((uint64_t)high << 32) | low;
#endif
            uint64_t milliseconds = nanoseconds / 1000000;

            LOQ_string("go_trace", "si", "Event", "Go Native Sleep Intercepted",
                       "Duration (ms)", (int)milliseconds);
            DebugOutput("Go Trace: Intercepted Go native sleep for %u ms.\n", (unsigned int)milliseconds);
        }
        else if (strstr(funcName, "crypto/tls.(*Conn).Write")) {
            // func (c *Conn) Write(b []byte) (int, error)
            // word 0: c (*Conn), word 1: b.Data, word 2: b.Len, word 3: b.Cap
            ULONG_PTR pData = GoGetArgWord(ctx, 1);
            ULONG_PTR length = GoGetArgWord(ctx, 2);

            if (pData != 0 && length > 0 && length <= 65536 && IsAddressAccessible((PVOID)pData)) {
                size_t capLen = (length < 8192) ? (size_t)length : 8192;
                LOQ_string("go_tls", "sb", "Direction", "Outbound", "Plaintext", capLen, (const char*)pData);
                DebugOutput("Go TLS Outbound Plaintext Payload (%u bytes) intercepted at 0x%p\n", (unsigned int)length, (PVOID)pData);
            }
        }
        else if (strstr(funcName, "crypto/tls.(*Conn).Read")) {
            // func (c *Conn) Read(b []byte) (int, error)
            // word 0: c (*Conn), word 1: b.Data, word 2: b.Len, word 3: b.Cap
            ULONG_PTR pData = GoGetArgWord(ctx, 1);
            ULONG_PTR length = GoGetArgWord(ctx, 2);

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
                    if (tlsState) {
                        tlsState->returnAddress = retAddr;
                        tlsState->readBuffer = (PVOID)pData;
                        // Under Stack ABI, return value n (int) is at [SP_on_entry + 5*ptrSize]
                        tlsState->bytesReadSlot = g_go_uses_regabi ? NULL : (PVOID)&pStack[5];

                        SetSoftwareBreakpoint(&SoftBPs, retAddr);
                    }
                }
            }
        }
        else if (strstr(funcName, ".NewCipher") ||
                 strstr(funcName, "chacha20poly1305.New") ||
                 strstr(funcName, "chacha20.NewUnauthenticatedCipher") ||
                 strstr(funcName, "pbkdf2.Key") ||
                 strstr(funcName, "argon2.IDKey") ||
                 strstr(funcName, "argon2.Key") ||
                 strstr(funcName, "scrypt.Key")) {
            // First parameter is key/password []byte: word 0 = ptr, word 1 = len
            ULONG_PTR keyPtr = GoGetArgWord(ctx, 0);
            ULONG_PTR keyLen = GoGetArgWord(ctx, 1);

            LOQ_string("go_trace", "spp", "Event", "Go Cryptographic Key Setup Intercepted",
                       "Key Pointer", (PVOID)keyPtr,
                       "Key Length", (PVOID)keyLen);

            if (keyPtr != 0 && keyLen > 0 && keyLen <= 512 && IsAddressAccessible((PVOID)keyPtr)) {
                LOQ_string("go_crypto", "sb", "Function", funcName, "Key", (size_t)keyLen, (const char*)keyPtr);
            }
        }
        else if (strstr(funcName, "net/http.NewRequestWithContext")) {
            // func NewRequestWithContext(ctx context.Context, method, url string, body io.Reader)
            // word 0..1: ctx (interface), word 2..3: method (string), word 4..5: url (string)
            ULONG_PTR methodPtr = GoGetArgWord(ctx, 2);
            ULONG_PTR methodLen = GoGetArgWord(ctx, 3);
            ULONG_PTR urlPtr    = GoGetArgWord(ctx, 4);
            ULONG_PTR urlLen    = GoGetArgWord(ctx, 5);
            LogGoString("HTTP Method", (PVOID)methodPtr, methodLen);
            LogGoString("HTTP URL", (PVOID)urlPtr, urlLen);
        }
        else if (strstr(funcName, "net/http.NewRequest")) {
            // func NewRequest(method, url string, body io.Reader)
            // word 0..1: method (string), word 2..3: url (string)
            ULONG_PTR methodPtr = GoGetArgWord(ctx, 0);
            ULONG_PTR methodLen = GoGetArgWord(ctx, 1);
            ULONG_PTR urlPtr    = GoGetArgWord(ctx, 2);
            ULONG_PTR urlLen    = GoGetArgWord(ctx, 3);
            LogGoString("HTTP Method", (PVOID)methodPtr, methodLen);
            LogGoString("HTTP URL", (PVOID)urlPtr, urlLen);
        }
        else if (strstr(funcName, "net/http.(*Client).Get") ||
                 strstr(funcName, "net/http.(*Client).Post") ||
                 strstr(funcName, "net/http.(*Client).Head") ||
                 strstr(funcName, "net/http.(*Client).PostForm")) {
            // Receiver c (*Client) is word 0; url (string) is word 1..2
            ULONG_PTR urlPtr = GoGetArgWord(ctx, 1);
            ULONG_PTR urlLen = GoGetArgWord(ctx, 2);
            LogGoString("HTTP URL", (PVOID)urlPtr, urlLen);
        }
        else if (strstr(funcName, "net/http.Get") ||
                 strstr(funcName, "net/http.Post") ||
                 strstr(funcName, "net/http.Head") ||
                 strstr(funcName, "net/http.PostForm")) {
            // Package-level helper: url (string) is word 0..1
            ULONG_PTR urlPtr = GoGetArgWord(ctx, 0);
            ULONG_PTR urlLen = GoGetArgWord(ctx, 1);
            LogGoString("HTTP URL", (PVOID)urlPtr, urlLen);
        }
        else if (strstr(funcName, "net.Dial") || strstr(funcName, "net.Listen")) {
            // func Dial(network, address string) / func Listen(network, address string)
            BOOL hasReceiver = (strstr(funcName, ").") != NULL);
            DWORD baseIdx = hasReceiver ? 1 : 0;
            if (strstr(funcName, "Context")) {
                baseIdx += 2; // skip context.Context interface (2 words)
            }
            ULONG_PTR netPtr  = GoGetArgWord(ctx, baseIdx);
            ULONG_PTR netLen  = GoGetArgWord(ctx, baseIdx + 1);
            ULONG_PTR addrPtr = GoGetArgWord(ctx, baseIdx + 2);
            ULONG_PTR addrLen = GoGetArgWord(ctx, baseIdx + 3);
            LogGoString("Network", (PVOID)netPtr, netLen);
            LogGoString("Address", (PVOID)addrPtr, addrLen);
        }
        else if (strstr(funcName, "os/exec.Command") ||
                 strstr(funcName, "os.OpenFile") ||
                 strstr(funcName, "os.Create") ||
                 strstr(funcName, "os.Remove") ||
                 strstr(funcName, "os.WriteFile") ||
                 strstr(funcName, "ioutil.WriteFile")) {
            DWORD baseIdx = (strstr(funcName, "CommandContext") != NULL) ? 2 : 0;
            ULONG_PTR strPtr = GoGetArgWord(ctx, baseIdx);
            ULONG_PTR strLen = GoGetArgWord(ctx, baseIdx + 1);
            LogGoString("Target/Path", (PVOID)strPtr, strLen);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DebugOutput("Go Trace: Exception occurred resolving Go function arguments.\n");
    }

    return TRUE;
}

// Global dispatcher to route software breakpoint exceptions securely to hook_go.c
// Returns: GO_BP_NOT_OURS (0), GO_BP_PERSISTENT (1), or GO_BP_ONESHOT (2)
int GoBreakpointHandler(PVOID Address, struct _EXCEPTION_POINTERS* ExceptionInfo) {
    // 1. Intercept temporary TLS Read return breakpoints (keyed by returnAddress across goroutine thread migrations)
    GO_TLS_RETURN_STATE* tlsState = (GO_TLS_RETURN_STATE*)lookup_get(&g_go_tls_return_table, (ULONG_PTR)Address, NULL);
    if (tlsState && tlsState->returnAddress == Address) {
        __try {
            ULONG_PTR bytesRead = 0;
#ifdef _WIN64
            if (g_go_uses_regabi) {
                bytesRead = ExceptionInfo->ContextRecord->Rax;
            } else if (tlsState->bytesReadSlot && IsAddressAccessible(tlsState->bytesReadSlot)) {
                bytesRead = *(PULONG_PTR)tlsState->bytesReadSlot;
            }
#else
            if (tlsState->bytesReadSlot && IsAddressAccessible(tlsState->bytesReadSlot)) {
                bytesRead = *(PULONG_PTR)tlsState->bytesReadSlot;
            }
#endif

            if (tlsState->readBuffer != NULL && bytesRead > 0 && bytesRead <= 65536 && IsAddressAccessible(tlsState->readBuffer)) {
                size_t capLen = (bytesRead < 8192) ? (size_t)bytesRead : 8192;
                LOQ_string("go_tls", "sb", "Direction", "Inbound", "Plaintext", capLen, (const char*)tlsState->readBuffer);
                DebugOutput("Go TLS Inbound Plaintext Payload (%u bytes) intercepted on return at 0x%p\n", (unsigned int)bytesRead, tlsState->readBuffer);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DebugOutput("Go Trace: Exception occurred resolving Go tls.Read return.\n");
        }

        // SoftwareBreakpointHandler already restored the original instruction byte at Address;
        // remove the one-shot return breakpoint from SoftBPs (unless it is also a persistent hook).
        lookup_del(&g_go_tls_return_table, (ULONG_PTR)Address);
        if (!lookup_get(&g_go_hook_table, (ULONG_PTR)Address, NULL)) {
            lookup_del(&SoftBPs, (ULONG_PTR)Address);
        }
        return GO_BP_ONESHOT;
    }

    // 2. Intercept persistent function entry software breakpoints
    GO_HOOK_ENTRY* hookEntry = (GO_HOOK_ENTRY*)lookup_get(&g_go_hook_table, (ULONG_PTR)Address, NULL);
    if (hookEntry) {
        BREAKPOINTINFO bpInfo;
        memset(&bpInfo, 0, sizeof(bpInfo));
        bpInfo.Address = Address;
        bpInfo.Callback = GoBreakpointCallback;

        GoBreakpointCallback(&bpInfo, ExceptionInfo);
        return GO_BP_PERSISTENT;
    }

    return GO_BP_NOT_OURS;
}

// Sets an active internal software breakpoint hook (0xCC) on a recovered Go function address
static void GoSetFunctionHook(PVOID funcAddress, const char* funcName) {
    if (!funcAddress || !funcName || !IsAddressAccessible(funcAddress))
        return;

    // Check if already hooked in lookup table
    if (lookup_get(&g_go_hook_table, (ULONG_PTR)funcAddress, NULL))
        return;

    char safeFuncName[160];
    SanitizeForDebug(safeFuncName, sizeof(safeFuncName), funcName, strlen(funcName));

    if (SetSoftwareBreakpoint(&SoftBPs, funcAddress)) {
        GO_HOOK_ENTRY* hookEntry = (GO_HOOK_ENTRY*)lookup_add(&g_go_hook_table, (ULONG_PTR)funcAddress, sizeof(GO_HOOK_ENTRY));
        if (hookEntry) {
            hookEntry->Address = funcAddress;
            strncpy_s(hookEntry->Name, sizeof(hookEntry->Name), funcName, _TRUNCATE);
            DebugOutput("GoSetFunctionHook: Successfully hooked '%s' at 0x%p via software breakpoint (0xCC).\n", safeFuncName, funcAddress);
        }
    } else {
        DebugOutput("GoSetFunctionHook: Failed to set software breakpoint hook on '%s' at 0x%p.\n", safeFuncName, funcAddress);
    }
}

// Safely parses and recovers embedded source file paths from the file table
static void GoRecoverFilePaths(int goVersion, PBYTE pclntab, DWORD nfiles, PBYTE pFiletab, PBYTE pCutab, PBYTE pImageEnd) {
    UNREFERENCED_PARAMETER(pCutab);
    if (!pclntab || !pFiletab || !pImageEnd || nfiles == 0 || nfiles > 50000) return;

    __try {
        if (goVersion == GO_VER_116 || goVersion == GO_VER_118 || goVersion == GO_VER_120) {
            // In Go >= 1.16, filetab contains null-terminated strings packed sequentially
            PBYTE pCur = pFiletab;
            DWORD count = 0;

            while (pCur < pImageEnd && count < nfiles && IsAddressAccessible(pCur)) {
                if (*pCur == '\0') {
                    pCur++;
                    continue;
                }
                const char* filePath = (const char*)pCur;
                size_t len = strnlen_s(filePath, 512);
                if (len > 0 && len < 512 && (pCur + len) < pImageEnd) {
                    if (strstr(filePath, ".go")) {
                        char safePath[200];
                        SanitizeForDebug(safePath, sizeof(safePath), filePath, len);
                        LOQ_string("go_filepath", "s", "Path", filePath);
                        DebugOutput("GoRecoverFilePaths: Recovered Go Source File Path: %s\n", safePath);
                    }
                    pCur += len + 1;
                    count++;
                } else {
                    break;
                }
            }
        } else if (goVersion == GO_VER_12) {
            // In Go 1.2 - 1.15, filetab starts with uint32 count followed by uint32 offsets from pclntab
            uint32_t* pOffsets = (uint32_t*)pFiletab;
            for (DWORD i = 1; i < nfiles; i++) {
                if (!IsAddressAccessible(&pOffsets[i]))
                    break;
                uint32_t off = pOffsets[i];
                PBYTE pStr = pclntab + off;
                if (pStr >= pclntab && pStr < pImageEnd && IsAddressAccessible(pStr)) {
                    const char* filePath = (const char*)pStr;
                    size_t len = strnlen_s(filePath, 512);
                    if (len > 0 && len < 512 && strstr(filePath, ".go")) {
                        char safePath[200];
                        SanitizeForDebug(safePath, sizeof(safePath), filePath, len);
                        LOQ_string("go_filepath", "s", "Path", filePath);
                        DebugOutput("GoRecoverFilePaths: Recovered Go Source File Path: %s\n", safePath);
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DebugOutput("GoRecoverFilePaths: Exception occurred recovering Go file paths.\n");
    }
}

// Dynamic parser to extract Compiler Version and Modinfo dependency logs from memory (Inspired by GoReSym)
static void GoParseBuildInfo(PBYTE pBuildinfo, DWORD Size) {
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
                SanitizeForDebug(safeVersion, sizeof(safeVersion), versionBuf, (size_t)verLen);
                LOQ_string("go_buildinfo", "s", "Version", versionBuf);
                DebugOutput("GoParseBuildInfo: Recovered Go Compiler Version: %s\n", safeVersion);
                pData += verLen;

                // Decode modinfo string
                uint64_t modLen = 0;
                shift = 0;
                while (pData < pEnd && shift <= 63) {
                    BYTE b = *pData++;
                    modLen |= ((uint64_t)(b & 0x7F)) << shift;
                    if ((b & 0x80) == 0) break;
                    shift += 7;
                }

                if (modLen > 0 && modLen < 8192 && (pData + modLen) <= pEnd && IsAddressAccessible(pData)) {
                    LOQ_string("go_buildinfo", "S", "Modinfo", (int)modLen, (const char*)pData);
                    DebugOutput("GoParseBuildInfo: Recovered Go Modinfo dependency tree (%u bytes).\n", (unsigned int)modLen);
                }
            }
        } else if (ptrSize == sizeof(void*)) {
            // Pointer-based string headers: [dataPtr, len]
            PVOID* pVersionPtr = (PVOID*)(pBuildinfo + 16);
            PVOID* pModinfoPtr = (PVOID*)(pBuildinfo + 16 + ptrSize);

            if (IsAddressAccessible(pVersionPtr) && IsAddressAccessible(*pVersionPtr)) {
                PVOID pVerData = *(PVOID*)(*pVersionPtr);
                ULONG_PTR verLen = *(ULONG_PTR*)((PBYTE)(*pVersionPtr) + ptrSize);
                if (pVerData && verLen > 0 && verLen < 128 && IsAddressAccessible(pVerData)) {
                    char versionBuf[128] = {0};
                    char safeVersion[128] = {0};
                    memcpy(versionBuf, pVerData, verLen);
                    SanitizeForDebug(safeVersion, sizeof(safeVersion), versionBuf, (size_t)verLen);
                    LOQ_string("go_buildinfo", "s", "Version", versionBuf);
                    DebugOutput("GoParseBuildInfo: Recovered Go Compiler Version: %s\n", safeVersion);
                }
            }

            if (IsAddressAccessible(pModinfoPtr) && IsAddressAccessible(*pModinfoPtr)) {
                PVOID pModData = *(PVOID*)(*pModinfoPtr);
                ULONG_PTR modLen = *(ULONG_PTR*)((PBYTE)(*pModinfoPtr) + ptrSize);
                if (pModData && modLen > 0 && modLen < 8192 && IsAddressAccessible(pModData)) {
                    LOQ_string("go_buildinfo", "S", "Modinfo", (int)modLen, (const char*)pModData);
                    DebugOutput("GoParseBuildInfo: Recovered Go Modinfo dependency tree (%u bytes).\n", (unsigned int)modLen);
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DebugOutput("GoParseBuildInfo: Exception occurred parsing Go buildinfo.\n");
    }
}

// Helper to read pointer-sized integer from pclntab header offsets
static uint64_t ReadHeaderWord(PBYTE pHeader, DWORD wordIndex, BYTE ptrSize) {
    if (ptrSize == 4) {
        return *(uint32_t*)(pHeader + 8 + wordIndex * 4);
    } else {
        return *(uint64_t*)(pHeader + 8 + wordIndex * 8);
    }
}

// Filter for high-signal Go functions/methods, skipping ABI wrappers, package initializers, and closures
static BOOL ShouldHookGoFunction(const char* funcName) {
    if (!funcName || *funcName == '\0')
        return FALSE;

    // Skip compiler-generated ABI0/ABIInternal wrappers, defer wrappers, closures, package init routines, and synthetic symbols
    if (strstr(funcName, ".abi0") ||
        strstr(funcName, ".abiinternal") ||
        strstr(funcName, ".deferwrap") ||
        strstr(funcName, ".func") ||
        strstr(funcName, ".init") ||
        strstr(funcName, "..inittask") ||
        strncmp(funcName, "type:", 5) == 0 ||
        strncmp(funcName, "go:", 3) == 0) {
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
        strstr(funcName, "go-resty/resty.(*Request).Execute") != NULL ||
        strstr(funcName, "valyala/fasthttp.Do") != NULL ||
        strstr(funcName, "valyala/fasthttp.(*Client).Do") != NULL ||
        strstr(funcName, "imroc/req") != NULL ||
        strstr(funcName, "gorilla/websocket.(*Dialer).Dial") != NULL ||
        strstr(funcName, "gorilla/websocket.(*Conn).WriteMessage") != NULL ||
        strstr(funcName, "nhooyr.io/websocket.Dial") != NULL ||
        strstr(funcName, "net/smtp.SendMail") != NULL) {
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

    // Execution, syscalls, file system, registry, and sleep
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
        strstr(funcName, "registry.OpenKey") != NULL ||
        strstr(funcName, "registry.CreateKey") != NULL ||
        strstr(funcName, "registry.Key.Set") != NULL ||
        strstr(funcName, "windows/svc/mgr") != NULL ||
        strstr(funcName, "main.inject") != NULL ||
        strstr(funcName, "main.execute") != NULL ||
        strstr(funcName, "yusufpapurcu/wmi") != NULL ||
        strstr(funcName, "go-ldap/ldap") != NULL ||
        strstr(funcName, "jcmturner/gokrb5") != NULL ||
        strstr(funcName, "masterzen/winrm") != NULL ||
        strstr(funcName, "hirochachacha/go-smb2") != NULL) {
        return TRUE;
    }

    return FALSE;
}

// Core Go symbol discovery and runtime instrumentation entry point
void GoRecoverSymbols() {
    __try {
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ImageBase;
        if (!pDos || pDos->e_magic != IMAGE_DOS_SIGNATURE)
            return;

        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)ImageBase + pDos->e_lfanew);
        if (!pNt || pNt->Signature != IMAGE_NT_SIGNATURE)
            return;

        PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
        PBYTE pclntab = NULL;
        PBYTE buildinfo = NULL;
        int detectedVer = GO_VER_UNKNOWN;
        ULONG_PTR textSectionVA = 0;
        DWORD textSectionSize = 0;
        PBYTE pImageEnd = (PBYTE)ImageBase + pNt->OptionalHeader.SizeOfImage;

        // 1. Locate .text section bounds and scan read-only/data sections for pclntab
        for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
            char secName[9] = {0};
            memcpy(secName, pSec[i].Name, 8);

            if (memcmp(secName, ".text", 5) == 0 || (textSectionVA == 0 && (pSec[i].Characteristics & IMAGE_SCN_CNT_CODE))) {
                textSectionVA = (ULONG_PTR)ImageBase + pSec[i].VirtualAddress;
                textSectionSize = pSec[i].Misc.VirtualSize ? pSec[i].Misc.VirtualSize : pSec[i].SizeOfRawData;
            }

            if (!pclntab && (strstr(secName, ".rdata") || strstr(secName, ".rodata") || strstr(secName, "pclntab") || strstr(secName, ".data"))) {
                PBYTE pStart = (PBYTE)ImageBase + pSec[i].VirtualAddress;
                DWORD size = pSec[i].Misc.VirtualSize ? pSec[i].Misc.VirtualSize : pSec[i].SizeOfRawData;

                if (IsAddressAccessible(pStart)) {
                    pclntab = ScanSectionForPclntab(pStart, size, &detectedVer);
                }
            }
        }

        // Fast Exit if this is not a Go binary
        if (!pclntab) {
            return;
        }

        g_go_detected_version = detectedVer;
        BYTE ptrSize = pclntab[7];
#ifdef _WIN64
        // In Go 1.17+, 64-bit binaries use register-based ABI (ABIInternal)
        g_go_uses_regabi = (detectedVer == GO_VER_118 || detectedVer == GO_VER_120);
#else
        g_go_uses_regabi = FALSE;
#endif

        // Read pclntab header offsets according to Go version (per debug/gosym/pclntab.go)
        uint64_t nfunc = 0;
        uint64_t nfiles = 0;
        PBYTE funcnametab = NULL;
        PBYTE cutab = NULL;
        PBYTE filetab = NULL;
        PBYTE functab = NULL;
        PBYTE funcdata = NULL;
        DWORD functabFieldSize = (detectedVer >= GO_VER_118) ? 4 : (DWORD)ptrSize;
        ULONG_PTR preferredBase = (ULONG_PTR)pNt->OptionalHeader.ImageBase;
        ULONG_PTR textStart = textSectionVA ? textSectionVA : (ULONG_PTR)ImageBase;

        if (detectedVer == GO_VER_118 || detectedVer == GO_VER_120) {
            nfunc = ReadHeaderWord(pclntab, 0, ptrSize);
            nfiles = ReadHeaderWord(pclntab, 1, ptrSize);
            uint64_t hdrTextStart = ReadHeaderWord(pclntab, 2, ptrSize);
            if (textSectionVA != 0) {
                textStart = textSectionVA;
            } else if (hdrTextStart != 0) {
                if (hdrTextStart >= (ULONG_PTR)ImageBase && hdrTextStart < (ULONG_PTR)pImageEnd)
                    textStart = (ULONG_PTR)hdrTextStart;
                else if (hdrTextStart >= preferredBase && hdrTextStart < preferredBase + pNt->OptionalHeader.SizeOfImage)
                    textStart = (ULONG_PTR)ImageBase + ((ULONG_PTR)hdrTextStart - preferredBase);
            }
            funcnametab = pclntab + ReadHeaderWord(pclntab, 3, ptrSize);
            cutab       = pclntab + ReadHeaderWord(pclntab, 4, ptrSize);
            filetab     = pclntab + ReadHeaderWord(pclntab, 5, ptrSize);
            functab     = pclntab + ReadHeaderWord(pclntab, 7, ptrSize);
            funcdata    = functab;
        } else if (detectedVer == GO_VER_116) {
            nfunc = ReadHeaderWord(pclntab, 0, ptrSize);
            nfiles = ReadHeaderWord(pclntab, 1, ptrSize);
            funcnametab = pclntab + ReadHeaderWord(pclntab, 2, ptrSize);
            cutab       = pclntab + ReadHeaderWord(pclntab, 3, ptrSize);
            filetab     = pclntab + ReadHeaderWord(pclntab, 4, ptrSize);
            functab     = pclntab + ReadHeaderWord(pclntab, 6, ptrSize);
            funcdata    = functab;
        } else if (detectedVer == GO_VER_12) {
            nfunc = ReadHeaderWord(pclntab, 0, ptrSize);
            funcnametab = pclntab;
            functab     = pclntab + 8 + ptrSize;
            funcdata    = pclntab;
            uint64_t functabSize = (nfunc * 2 + 1) * ptrSize;
            if (nfunc > 0 && nfunc < 500000 && (functab + functabSize + 4) <= pImageEnd && IsAddressAccessible(functab + functabSize)) {
                uint32_t fileoff = *(uint32_t*)(functab + functabSize);
                if ((pclntab + fileoff + 4) <= pImageEnd && IsAddressAccessible(pclntab + fileoff)) {
                    filetab = pclntab + fileoff;
                    nfiles = *(uint32_t*)filetab;
                }
            }
        }

        DebugOutput("GoRecoverSymbols: Dynamic Go binary detected! Version: %d, Functions: %llu, PtrSize: %d, RegABI: %d, TextStart: 0x%p\n",
                    detectedVer, (unsigned long long)nfunc, (int)ptrSize, (int)g_go_uses_regabi, (PVOID)textStart);

        // 2. Parsed BuildInfo scanner: Scan .data, .rdata, or .rodata sections for buildinfo magic
        const char buildinfoMagic[] = "\xff Go buildinf:";
        for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
            char secName[9] = {0};
            memcpy(secName, pSec[i].Name, 8);

            if (strstr(secName, ".data") || strstr(secName, ".rdata") || strstr(secName, ".rodata") || strstr(secName, "buildinfo")) {
                PBYTE pStart = (PBYTE)ImageBase + pSec[i].VirtualAddress;
                DWORD size = pSec[i].Misc.VirtualSize ? pSec[i].Misc.VirtualSize : pSec[i].SizeOfRawData;

                if (IsAddressAccessible(pStart)) {
                    buildinfo = ScanSectionForBytes(pStart, size, (PBYTE)buildinfoMagic, 14);
                    if (buildinfo) {
                        GoParseBuildInfo(buildinfo, size - (DWORD)(buildinfo - pStart));
                        break;
                    }
                }
            }
        }

        // 3. Recover source file paths from the Line Table
        if (filetab && nfiles > 0) {
            GoRecoverFilePaths(detectedVer, pclntab, (DWORD)nfiles, filetab, cutab, pImageEnd);
        }

        // 4. Walk function table and hook high-value security/networking/crypto APIs
        if (!functab || !funcdata || !funcnametab || nfunc == 0 || nfunc > 500000) {
            return;
        }

        for (uint64_t i = 0; i < nfunc; i++) {
            ULONG_PTR funcEntryOff = 0;
            ULONG_PTR funcStructOff = 0;

            if (functabFieldSize == 4) {
                uint32_t* pTab32 = (uint32_t*)(functab + 2 * i * 4);
                if ((PBYTE)&pTab32[2] > pImageEnd || !IsAddressAccessible(pTab32)) break;
                funcEntryOff = pTab32[0];
                funcStructOff = pTab32[1];
            } else {
                uint64_t* pTab64 = (uint64_t*)(functab + 2 * i * 8);
                if ((PBYTE)&pTab64[2] > pImageEnd || !IsAddressAccessible(pTab64)) break;
                funcEntryOff = (ULONG_PTR)pTab64[0];
                funcStructOff = (ULONG_PTR)pTab64[1];
            }

            ULONG_PTR funcAddress = 0;
            if (detectedVer >= GO_VER_118) {
                funcAddress = textStart + funcEntryOff;
            } else {
                if (funcEntryOff >= (ULONG_PTR)ImageBase && funcEntryOff < (ULONG_PTR)pImageEnd)
                    funcAddress = funcEntryOff;
                else if (funcEntryOff >= preferredBase && funcEntryOff < preferredBase + pNt->OptionalHeader.SizeOfImage)
                    funcAddress = (ULONG_PTR)ImageBase + (funcEntryOff - preferredBase);
                else
                    continue;
            }

            if (textSectionVA != 0 && (funcAddress < textSectionVA || funcAddress >= textSectionVA + textSectionSize)) {
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

            if (ShouldHookGoFunction(funcName)) {
                char safeFuncName[160];
                SanitizeForDebug(safeFuncName, sizeof(safeFuncName), funcName, strlen(funcName));
                DebugOutput("GoRecoverSymbols: Recovered critical Go symbol '%s' at 0x%p\n", safeFuncName, (PVOID)funcAddress);

                GoSetFunctionHook((PVOID)funcAddress, funcName);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DebugOutput("GoRecoverSymbols: Exception occurred parsing Go pclntab structures.\n");
    }
}
