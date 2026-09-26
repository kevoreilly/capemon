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
#define GO_VER_116     1
#define GO_VER_118     2
#define GO_VER_120     3

// Table of hooked Go functions keyed by function address
static lookup_t g_go_hook_table = {0};

typedef struct _GO_HOOK_ENTRY {
    PVOID Address;
    char Name[256];
} GO_HOOK_ENTRY;

// Structure to track unencrypted TLS payload read buffer on return
typedef struct _GO_TLS_RETURN_STATE {
    PVOID returnAddress;
    PVOID readBuffer;
} GO_TLS_RETURN_STATE;

static lookup_t g_go_tls_thread_table = {0};

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
            } else if (Magic == 0xFFFFFFFA || Magic == 0xFFFFFFFB) {
                ver = GO_VER_116;
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
    if (pStrData != NULL && length > 0 && length < 512 && IsAddressAccessible(pStrData)) {
        char buf[512] = {0};
        memcpy(buf, pStrData, length);
        LOQ_string("go_trace", "ss", "Param", label, "Value", buf);
        DebugOutput("Go Trace: Parameter [%s] = \"%s\"\n", label, buf);
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

    LOQ_string("go_trace", "s", "Function", funcName);
    DebugOutput("Go Trace: Intercepted Execution of Go Function: %s at 0x%p\n", funcName, pBreakpointInfo->Address);

    // Dynamic argument tracing based on ABI (RegABI on x64 vs. Stack ABI)
    __try {
        if (strstr(funcName, "syscall.Syscall")) {
            // syscall.Syscall(trap, nargs, a1, a2, a3)
            ULONG_PTR trapAddress = 0;
#ifdef _WIN64
            if (g_go_uses_regabi) {
                trapAddress = ExceptionInfo->ContextRecord->Rax;
            } else {
                PULONG_PTR pStack = (PULONG_PTR)ExceptionInfo->ContextRecord->Rsp;
                if (IsAddressAccessible(&pStack[1])) trapAddress = pStack[1];
            }
#else
            PULONG_PTR pStack = (PULONG_PTR)ExceptionInfo->ContextRecord->Esp;
            if (IsAddressAccessible(&pStack[1])) trapAddress = pStack[1];
#endif

            // Check if this is a direct memory address jump (indicates in-memory shellcode or PE execution)
            if (trapAddress != 0 && IsAddressAccessible((PVOID)trapAddress)) {
                if (!addr_in_our_dll_range(NULL, trapAddress)) {
                    MEMORY_BASIC_INFORMATION mbi;
                    if (VirtualQuery((PVOID)trapAddress, &mbi, sizeof(mbi)) != 0) {
                        // Check if memory is privately allocated with execute permissions (definitive in-memory payload signature)
                        if ((mbi.State == MEM_COMMIT) && 
                            (mbi.Type == MEM_PRIVATE) && 
                            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                            
                            // Check if the allocation base contains a PE file (MZ magic or PE signature)
                            if (IsPEFile(mbi.AllocationBase)) {
                                DebugOutput("Go Trace: Detected direct in-memory PE execution (MZ or PE signature found) at 0x%p! (Size: 0x%x)\n", (PVOID)trapAddress, mbi.RegionSize);
                                LOQ_string("go_trace", "sp", "Event", "Go Reflective PE Payload Execution Intercepted",
                                           "Jump Address", (PVOID)trapAddress);
                            } else {
                                DebugOutput("Go Trace: Detected direct in-memory shellcode execution at 0x%p! (Size: 0x%x)\n", (PVOID)trapAddress, mbi.RegionSize);
                                LOQ_string("go_trace", "sp", "Event", "Go Direct Shellcode/Payload Execution Intercepted",
                                           "Jump Address", (PVOID)trapAddress);
                            }

                            // Track the memory region for unpacking/dumping via CAPE's TrackExecution
                            TrackExecution((PVOID)trapAddress);
                        }
                    }
                }
            }
        }
        else if (strstr(funcName, "time.Sleep")) {
            // time.Sleep(d Duration)
            // d is int64 nanoseconds
            uint64_t nanoseconds = 0;
#ifdef _WIN64
            if (g_go_uses_regabi) {
                nanoseconds = (uint64_t)ExceptionInfo->ContextRecord->Rax;
            } else {
                uint64_t* pStack = (uint64_t*)((PBYTE)ExceptionInfo->ContextRecord->Rsp + sizeof(void*));
                if (IsAddressAccessible(pStack)) nanoseconds = *pStack;
            }
#else
            // On x86 32-bit stack ABI, [ESP] is return address, [ESP+4] is low 32 bits, [ESP+8] is high 32 bits
            uint32_t* pStack = (uint32_t*)((PBYTE)ExceptionInfo->ContextRecord->Esp + sizeof(void*));
            if (IsAddressAccessible(&pStack[0]) && IsAddressAccessible(&pStack[1])) {
                nanoseconds = ((uint64_t)pStack[1] << 32) | pStack[0];
            }
#endif
            uint64_t milliseconds = nanoseconds / 1000000;
            
            LOQ_string("go_trace", "si", "Event", "Go Native Sleep Intercepted",
                       "Duration (ms)", (int)milliseconds);
            DebugOutput("Go Trace: Intercepted Go native sleep for %u ms.\n", (unsigned int)milliseconds);
        }
        else if (strstr(funcName, "crypto/tls.(*Conn).Write")) {
            // Method on *Conn receiver: func (c *Conn) Write(b []byte) (int, error)
            // Under Go 1.17+ RegABI:
            //   RAX: c (*Conn receiver)
            //   RBX: b.Data (pointer)
            //   RCX: b.Len
            //   RDI: b.Cap
            // Under stack ABI:
            //   [SP+1*ptr]: c
            //   [SP+2*ptr]: b.Data
            //   [SP+3*ptr]: b.Len
            //   [SP+4*ptr]: b.Cap
            ULONG_PTR pData = 0;
            ULONG_PTR length = 0;

#ifdef _WIN64
            if (g_go_uses_regabi) {
                pData = ExceptionInfo->ContextRecord->Rbx;
                length = ExceptionInfo->ContextRecord->Rcx;
            } else {
                PULONG_PTR pStack = (PULONG_PTR)ExceptionInfo->ContextRecord->Rsp;
                if (IsAddressAccessible(&pStack[2]) && IsAddressAccessible(&pStack[3])) {
                    pData = pStack[2];
                    length = pStack[3];
                }
            }
#else
            PULONG_PTR pStack = (PULONG_PTR)ExceptionInfo->ContextRecord->Esp;
            if (IsAddressAccessible(&pStack[2]) && IsAddressAccessible(&pStack[3])) {
                pData = pStack[2];
                length = pStack[3];
            }
#endif

            if (pData != 0 && length > 0 && length < 8192 && IsAddressAccessible((PVOID)pData)) {
                char* pBuf = (char*)calloc(length + 1, 1);
                if (pBuf) {
                    memcpy(pBuf, (PVOID)pData, length);
                    LOQ_string("go_tls", "ss", "Direction", "Outbound", "Plaintext", pBuf);
                    DebugOutput("Go TLS Outbound Plaintext Payload (%d bytes) Intercepted:\n%s\n", (int)length, pBuf);
                    free(pBuf);
                }
            }
        }
        else if (strstr(funcName, "crypto/tls.(*Conn).Read")) {
            // Method on *Conn receiver: func (c *Conn) Read(b []byte) (int, error)
            // Under Go 1.17+ RegABI:
            //   RAX: c (*Conn)
            //   RBX: b.Data (pointer to buffer that will receive incoming data)
            //   RCX: b.Len
            // Under stack ABI:
            //   [SP+1*ptr]: c
            //   [SP+2*ptr]: b.Data
            //   [SP+3*ptr]: b.Len
            ULONG_PTR pData = 0;
            ULONG_PTR length = 0;

#ifdef _WIN64
            if (g_go_uses_regabi) {
                pData = ExceptionInfo->ContextRecord->Rbx;
                length = ExceptionInfo->ContextRecord->Rcx;
            } else {
                PULONG_PTR pStack = (PULONG_PTR)ExceptionInfo->ContextRecord->Rsp;
                if (IsAddressAccessible(&pStack[2]) && IsAddressAccessible(&pStack[3])) {
                    pData = pStack[2];
                    length = pStack[3];
                }
            }
#else
            PULONG_PTR pStack = (PULONG_PTR)ExceptionInfo->ContextRecord->Esp;
            if (IsAddressAccessible(&pStack[2]) && IsAddressAccessible(&pStack[3])) {
                pData = pStack[2];
                length = pStack[3];
            }
#endif

            if (pData != 0 && length > 0 && IsAddressAccessible((PVOID)pData)) {
#ifdef _WIN64
                PVOID* pReturnAddress = (PVOID*)ExceptionInfo->ContextRecord->Rsp;
#else
                PVOID* pReturnAddress = (PVOID*)ExceptionInfo->ContextRecord->Esp;
#endif
                if (IsAddressAccessible(pReturnAddress) && *pReturnAddress != NULL) {
                    GO_TLS_RETURN_STATE* tlsState = (GO_TLS_RETURN_STATE*)lookup_get_or_create(&g_go_tls_thread_table, (ULONG_PTR)GetCurrentThreadId(), sizeof(GO_TLS_RETURN_STATE));
                    if (tlsState) {
                        tlsState->returnAddress = *pReturnAddress;
                        tlsState->readBuffer = (PVOID)pData;

                        SetSoftwareBreakpoint(&SoftBPs, *pReturnAddress);
                    }
                }
            }
        }
        else if (strstr(funcName, "crypto") || strstr(funcName, "Encrypt") || strstr(funcName, "Decrypt")) {
            ULONG_PTR r_arg1 = 0;
            ULONG_PTR r_arg2 = 0;

#ifdef _WIN64
            if (g_go_uses_regabi) {
                r_arg1 = ExceptionInfo->ContextRecord->Rax;
                r_arg2 = ExceptionInfo->ContextRecord->Rbx;
            } else {
                PULONG_PTR pStack = (PULONG_PTR)ExceptionInfo->ContextRecord->Rsp;
                if (IsAddressAccessible(&pStack[1])) r_arg1 = pStack[1];
                if (IsAddressAccessible(&pStack[2])) r_arg2 = pStack[2];
            }
#else
            PULONG_PTR pStack = (PULONG_PTR)ExceptionInfo->ContextRecord->Esp;
            if (IsAddressAccessible(&pStack[1])) r_arg1 = pStack[1];
            if (IsAddressAccessible(&pStack[2])) r_arg2 = pStack[2];
#endif

            LOQ_string("go_trace", "spp", "Event", "Go Cryptographic Operation Intercepted",
                       "Key/Data Register 1", (PVOID)r_arg1,
                       "Length Register 2", (PVOID)r_arg2);

            if (r_arg2 > 0 && r_arg2 < 512 && IsAddressAccessible((PVOID)r_arg1)) {
                LogGoString("Crypto Payload", (PVOID)r_arg1, r_arg2);
            }
        }
        else if (strstr(funcName, "net/http") || strstr(funcName, "go-resty/resty") || strstr(funcName, "imroc/req") || strstr(funcName, "valyala/fasthttp")) {
            ULONG_PTR r_arg1 = 0;
            ULONG_PTR r_arg2 = 0;

#ifdef _WIN64
            if (g_go_uses_regabi) {
                r_arg1 = ExceptionInfo->ContextRecord->Rax;
                r_arg2 = ExceptionInfo->ContextRecord->Rbx;
            } else {
                PULONG_PTR pStack = (PULONG_PTR)ExceptionInfo->ContextRecord->Rsp;
                if (IsAddressAccessible(&pStack[1])) r_arg1 = pStack[1];
                if (IsAddressAccessible(&pStack[2])) r_arg2 = pStack[2];
            }
#else
            PULONG_PTR pStack = (PULONG_PTR)ExceptionInfo->ContextRecord->Esp;
            if (IsAddressAccessible(&pStack[1])) r_arg1 = pStack[1];
            if (IsAddressAccessible(&pStack[2])) r_arg2 = pStack[2];
#endif

            LOQ_string("go_trace", "sp", "Event", "Go HTTP Networking Intercepted",
                       "URL String Pointer", (PVOID)r_arg1);

            if (r_arg2 > 0 && r_arg2 < 512 && IsAddressAccessible((PVOID)r_arg1)) {
                LogGoString("HTTP URL", (PVOID)r_arg1, r_arg2);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DebugOutput("Go Trace: Exception occurred resolving Go function arguments.\n");
    }

    return TRUE;
}

// Global dispatcher to route software breakpoint exceptions securely to hook_go.c
BOOL GoBreakpointHandler(PVOID Address, struct _EXCEPTION_POINTERS* ExceptionInfo) {
    // 1. Intercept temporary thread-local TLS Read return breakpoints
    GO_TLS_RETURN_STATE* tlsState = (GO_TLS_RETURN_STATE*)lookup_get(&g_go_tls_thread_table, (ULONG_PTR)GetCurrentThreadId(), NULL);
    if (tlsState && tlsState->returnAddress != NULL && Address == tlsState->returnAddress) {
        __try {
            // Under Go's ABI, the first return value "n" (bytes read) is in RAX on RegABI or top return slot
#ifdef _WIN64
            ULONG_PTR bytesRead = ExceptionInfo->ContextRecord->Rax;
#else
            ULONG_PTR bytesRead = ExceptionInfo->ContextRecord->Eax;
#endif

            if (tlsState->readBuffer != NULL && bytesRead > 0 && bytesRead < 8192 && IsAddressAccessible(tlsState->readBuffer)) {
                char* pBuf = (char*)calloc(bytesRead + 1, 1);
                if (pBuf) {
                    memcpy(pBuf, tlsState->readBuffer, bytesRead);
                    LOQ_string("go_tls", "ss", "Direction", "Inbound", "Plaintext", pBuf);
                    DebugOutput("Go TLS Inbound Plaintext Payload (%d bytes) Intercepted on Return:\n%s\n", (int)bytesRead, pBuf);
                    free(pBuf);
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DebugOutput("Go Trace: Exception occurred resolving Go tls.Read return.\n");
        }

        // Disarm the temporary return breakpoint
        ClearSoftwareBreakpoint(&SoftBPs, Address);
        tlsState->returnAddress = NULL;
        tlsState->readBuffer = NULL;
        return TRUE;
    }

    // 2. Intercept persistent function entry software breakpoints
    GO_HOOK_ENTRY* hookEntry = (GO_HOOK_ENTRY*)lookup_get(&g_go_hook_table, (ULONG_PTR)Address, NULL);
    if (hookEntry) {
        BREAKPOINTINFO bpInfo;
        bpInfo.Address = Address;
        bpInfo.Callback = GoBreakpointCallback;
        
        GoBreakpointCallback(&bpInfo, ExceptionInfo);
        return TRUE;
    }

    return FALSE;
}

// Sets an active internal software breakpoint hook (0xCC) on a recovered Go function address
static void GoSetFunctionHook(PVOID funcAddress, const char* funcName) {
    if (!funcAddress || !funcName || !IsAddressAccessible(funcAddress))
        return;

    // Check if already hooked in lookup table
    if (lookup_get(&g_go_hook_table, (ULONG_PTR)funcAddress, NULL))
        return;

    if (SetSoftwareBreakpoint(&SoftBPs, funcAddress)) {
        GO_HOOK_ENTRY* hookEntry = (GO_HOOK_ENTRY*)lookup_add(&g_go_hook_table, (ULONG_PTR)funcAddress, sizeof(GO_HOOK_ENTRY));
        if (hookEntry) {
            hookEntry->Address = funcAddress;
            strncpy_s(hookEntry->Name, sizeof(hookEntry->Name), funcName, _TRUNCATE);
            DebugOutput("GoSetFunctionHook: Successfully hooked '%s' at 0x%p via software breakpoint (0xCC).\n", funcName, funcAddress);
        }
    } else {
        DebugOutput("GoSetFunctionHook: Failed to set software breakpoint hook on '%s' at 0x%p.\n", funcName, funcAddress);
    }
}

// Safely parses and recovers embedded source file paths from the file table
static void GoRecoverFilePaths(int goVersion, PBYTE pclntab, DWORD nfiles, PBYTE pFiletab, PBYTE pCutab, DWORD ImageSize) {
    if (!pclntab || !pFiletab || nfiles == 0 || nfiles > 50000) return;

    __try {
        if (goVersion == GO_VER_116 || goVersion == GO_VER_118 || goVersion == GO_VER_120) {
            // In Go >= 1.16, filetab contains null-terminated strings packed sequentially
            PBYTE pCur = pFiletab;
            PBYTE pEnd = pclntab + ImageSize;
            DWORD count = 0;

            while (pCur < pEnd && count < nfiles && IsAddressAccessible(pCur)) {
                if (*pCur == '\0') {
                    pCur++;
                    continue;
                }
                const char* filePath = (const char*)pCur;
                size_t len = strnlen_s(filePath, 512);
                if (len > 0 && len < 512) {
                    if (strstr(filePath, ".go")) {
                        LOQ_string("go_filepath", "s", "Path", filePath);
                        DebugOutput("GoRecoverFilePaths: Recovered Go Source File Path: %s\n", filePath);
                    }
                    pCur += len + 1;
                    count++;
                } else {
                    break;
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
                memcpy(versionBuf, pData, (size_t)verLen);
                LOQ_string("go_buildinfo", "s", "Version", versionBuf);
                DebugOutput("GoParseBuildInfo: Recovered Go Compiler Version: %s\n", versionBuf);
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
                    char* modBuf = (char*)calloc((size_t)modLen + 1, 1);
                    if (modBuf) {
                        memcpy(modBuf, pData, (size_t)modLen);
                        LOQ_string("go_buildinfo", "s", "Modinfo", modBuf);
                        DebugOutput("GoParseBuildInfo: Recovered Go Modinfo dependency tree successfully.\n");
                        free(modBuf);
                    }
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
                    memcpy(versionBuf, pVerData, verLen);
                    LOQ_string("go_buildinfo", "s", "Version", versionBuf);
                    DebugOutput("GoParseBuildInfo: Recovered Go Compiler Version: %s\n", versionBuf);
                }
            }

            if (IsAddressAccessible(pModinfoPtr) && IsAddressAccessible(*pModinfoPtr)) {
                PVOID pModData = *(PVOID*)(*pModinfoPtr);
                ULONG_PTR modLen = *(ULONG_PTR*)((PBYTE)(*pModinfoPtr) + ptrSize);
                if (pModData && modLen > 0 && modLen < 8192 && IsAddressAccessible(pModData)) {
                    char* modBuf = (char*)calloc(modLen + 1, 1);
                    if (modBuf) {
                        memcpy(modBuf, pModData, modLen);
                        LOQ_string("go_buildinfo", "s", "Modinfo", modBuf);
                        DebugOutput("GoParseBuildInfo: Recovered Go Modinfo dependency tree successfully.\n");
                        free(modBuf);
                    }
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

        // 1. Walk section headers and scan read-only metadata sections for pclntab
        for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
            char secName[9] = {0};
            memcpy(secName, pSec[i].Name, 8);
            
            if (strstr(secName, ".rdata") || strstr(secName, ".rodata") || strstr(secName, "pclntab") || strstr(secName, ".data")) {
                PBYTE pStart = (PBYTE)ImageBase + pSec[i].VirtualAddress;
                DWORD size = pSec[i].Misc.VirtualSize;
                
                if (IsAddressAccessible(pStart)) {
                    pclntab = ScanSectionForPclntab(pStart, size, &detectedVer);
                    if (pclntab) {
                        break;
                    }
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
        g_go_uses_regabi = (detectedVer >= GO_VER_118 || detectedVer == GO_VER_120);
#else
        g_go_uses_regabi = FALSE;
#endif

        // Read pclntab header offsets according to Go version
        uint64_t nfunc = 0;
        uint64_t nfiles = 0;
        PBYTE funcnametab = NULL;
        PBYTE cutab = NULL;
        PBYTE filetab = NULL;
        PBYTE functab = NULL;
        DWORD functabFieldSize = (detectedVer >= GO_VER_118) ? 4 : (DWORD)ptrSize;
        ULONG_PTR textStart = (ULONG_PTR)ImageBase;

        if (detectedVer == GO_VER_118 || detectedVer == GO_VER_120) {
            nfunc = ReadHeaderWord(pclntab, 0, ptrSize);
            nfiles = ReadHeaderWord(pclntab, 1, ptrSize);
            textStart = (ULONG_PTR)ImageBase;
            funcnametab = pclntab + ReadHeaderWord(pclntab, 3, ptrSize);
            cutab       = pclntab + ReadHeaderWord(pclntab, 4, ptrSize);
            filetab     = pclntab + ReadHeaderWord(pclntab, 5, ptrSize);
            functab     = pclntab + ReadHeaderWord(pclntab, 7, ptrSize);
        } else if (detectedVer == GO_VER_116) {
            nfunc = ReadHeaderWord(pclntab, 0, ptrSize);
            nfiles = ReadHeaderWord(pclntab, 1, ptrSize);
            funcnametab = pclntab + ReadHeaderWord(pclntab, 2, ptrSize);
            cutab       = pclntab + ReadHeaderWord(pclntab, 3, ptrSize);
            filetab     = pclntab + ReadHeaderWord(pclntab, 4, ptrSize);
            functab     = pclntab + ReadHeaderWord(pclntab, 6, ptrSize);
        }

        DebugOutput("GoRecoverSymbols: Dynamic Go binary detected! Version: %d, Functions: %llu, PtrSize: %d, RegABI: %d\n",
                    detectedVer, (unsigned long long)nfunc, (int)ptrSize, (int)g_go_uses_regabi);

        // 2. Parsed BuildInfo scanner: Scan .data, .rdata, or .rodata sections for buildinfo magic
        const char buildinfoMagic[] = "\xff Go buildinf:";
        for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
            char secName[9] = {0};
            memcpy(secName, pSec[i].Name, 8);
            
            if (strstr(secName, ".data") || strstr(secName, ".rdata") || strstr(secName, ".rodata") || strstr(secName, "buildinfo")) {
                PBYTE pStart = (PBYTE)ImageBase + pSec[i].VirtualAddress;
                DWORD size = pSec[i].Misc.VirtualSize;
                
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
            GoRecoverFilePaths(detectedVer, pclntab, (DWORD)nfiles, filetab, cutab, pNt->OptionalHeader.SizeOfImage);
        }

        // 4. Walk function table and hook high-value security/networking/crypto APIs
        if (!functab || !funcnametab || nfunc == 0 || nfunc > 500000) {
            return;
        }

        for (uint64_t i = 0; i < nfunc; i++) {
            ULONG_PTR funcEntryOff = 0;
            ULONG_PTR funcStructOff = 0;

            if (functabFieldSize == 4) {
                uint32_t* pTab32 = (uint32_t*)(functab + 2 * i * 4);
                if (!IsAddressAccessible(pTab32)) break;
                funcEntryOff = pTab32[0];
                funcStructOff = pTab32[1];
            } else {
                uint64_t* pTab64 = (uint64_t*)(functab + 2 * i * 8);
                if (!IsAddressAccessible(pTab64)) break;
                funcEntryOff = (ULONG_PTR)pTab64[0];
                funcStructOff = (ULONG_PTR)pTab64[1];
            }

            ULONG_PTR funcAddress = 0;
            if (detectedVer >= GO_VER_118) {
                funcAddress = textStart + funcEntryOff;
            } else {
                funcAddress = funcEntryOff;
            }

            PBYTE pFuncData = pclntab + funcStructOff;
            if (!IsAddressAccessible(pFuncData)) continue;

            // Name offset is field 1 (4 bytes following the entryPC/entryOff)
            DWORD sz0 = (detectedVer >= GO_VER_118) ? 4 : (DWORD)ptrSize;
            if (!IsAddressAccessible(pFuncData + sz0)) continue;
            uint32_t nameOff = *(uint32_t*)(pFuncData + sz0);

            const char* funcName = (const char*)(funcnametab + nameOff);
            if (!IsAddressAccessible((PVOID)funcName) || *funcName == '\0') continue;

            // Target critical functions with high malicious utility (Stealers, Droppers, Cryptography, Websockets, Direct Syscalls, and OS operations)
            if (strstr(funcName, "crypto/aes") || 
                strstr(funcName, "crypto/cipher") ||
                strstr(funcName, "crypto/rc4") ||
                strstr(funcName, "chacha20") ||
                strstr(funcName, "crypto/des") ||
                strstr(funcName, "blowfish") ||
                strstr(funcName, "cast5") ||
                strstr(funcName, "net/http") ||
                strstr(funcName, "go-resty/resty") ||
                strstr(funcName, "valyala/fasthttp") ||
                strstr(funcName, "imroc/req") ||
                strstr(funcName, "net/websocket") ||
                strstr(funcName, "gorilla/websocket") ||
                strstr(funcName, "nhooyr.io/websocket") ||
                strstr(funcName, "net/smtp") ||
                strstr(funcName, "net/mail") ||
                strstr(funcName, "net/textproto") ||
                strstr(funcName, "net.Dial") ||
                strstr(funcName, "net.Listen") ||
                strstr(funcName, "golang.org/x/net/proxy") ||
                strstr(funcName, "net/ip") ||
                strstr(funcName, "syscall.Syscall") ||
                strstr(funcName, "main.inject") ||
                strstr(funcName, "main.execute") ||
                strstr(funcName, "crypto/tls.(*Conn).Write") ||
                strstr(funcName, "crypto/tls.(*Conn).Read") ||
                strstr(funcName, "os/exec") ||
                strstr(funcName, "path/filepath.Walk") ||
                strstr(funcName, "os.WriteFile") ||
                strstr(funcName, "ioutil.WriteFile") ||
                strstr(funcName, "os.OpenFile") ||
                strstr(funcName, "os.Create") ||
                strstr(funcName, "os.Remove") ||
                strstr(funcName, "registry.Key") ||
                strstr(funcName, "windows/svc") ||
                strstr(funcName, "os/user") ||
                strstr(funcName, "os.UserHomeDir") ||
                strstr(funcName, "os.UserConfigDir") ||
                strstr(funcName, "net.Lookup") ||
                strstr(funcName, "time.Sleep") ||
                strstr(funcName, "yusufpapurcu/wmi") ||
                strstr(funcName, "go-ldap/ldap") ||
                strstr(funcName, "jcmturner/gokrb5") ||
                strstr(funcName, "masterzen/winrm") ||
                strstr(funcName, "marcsauter/single") ||
                strstr(funcName, "singleinstance") ||
                strstr(funcName, "single_instance") ||
                strstr(funcName, "hirochachacha/go-smb2")) {
                
                DebugOutput("GoRecoverSymbols: Recovered critical Go symbol '%s' at 0x%p\n", funcName, (PVOID)funcAddress);
                
                // Programmatically hook the function dynamically
                GoSetFunctionHook((PVOID)funcAddress, funcName);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DebugOutput("GoRecoverSymbols: Exception occurred parsing Go pclntab structures.\n");
    }
}
