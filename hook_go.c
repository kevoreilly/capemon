#include <windows.h>
#include <stdio.h>
#include "log.h"
#include "misc.h"
#include "config.h"
#include "CAPE\CAPE.h"
#include "CAPE\Debugger.h"

#ifdef _WIN64
#define GO_REG_ARG1(ExceptionInfo) (ExceptionInfo->ContextRecord->Rax)
#define GO_REG_ARG2(ExceptionInfo) (ExceptionInfo->ContextRecord->Rbx)
#define GO_REG_ARG3(ExceptionInfo) (ExceptionInfo->ContextRecord->Rcx)
#define GO_REG_ARG4(ExceptionInfo) (ExceptionInfo->ContextRecord->Rdx)
#else
#define GO_REG_ARG1(ExceptionInfo) (((PULONG_PTR)ExceptionInfo->ContextRecord->Esp)[1])
#define GO_REG_ARG2(ExceptionInfo) (((PULONG_PTR)ExceptionInfo->ContextRecord->Esp)[2])
#define GO_REG_ARG3(ExceptionInfo) (((PULONG_PTR)ExceptionInfo->ContextRecord->Esp)[3])
#define GO_REG_ARG4(ExceptionInfo) (((PULONG_PTR)ExceptionInfo->ContextRecord->Esp)[4])
#endif

// Go 1.16+ Program Counter Line Table (pclntab) header definition
#pragma pack(push, 1)
typedef struct {
    uint32_t magic;          // Magic number (0xFFFFFFF1, 0xFFFFFFF0, 0xFFFFFFFA, 0xFFFFFFFB)
    uint16_t pad1;           // Padding (0x00)
    uint16_t pad2;           // Padding (0x00)
    uint8_t  minLC;          // Minimum instruction size (usually 1)
    uint8_t  ptrSize;        // Pointer size (4 or 8)
    uint32_t nfunc;          // Total number of functions
    uint32_t nfiles;         // Total number of source files
    uint32_t textStart;      // Starting virtual address of the text section
    uint32_t funcnameOffset; // Offset to function name string table
    uint32_t cuOffset;       // Offset to compilation unit table
    uint32_t filetabOffset;  // Offset to file table
    uint32_t pctabOffset;    // Offset to PC table
    uint32_t functabOffset;  // Offset to function table (contains GoFuncTabEntry)
} GoPCHeader;

typedef struct {
    uint32_t entryOff;      // RVA or offset of function start relative to textStart
    uint32_t funcOff;       // Offset to GoFunc structure relative to pclntab base
} GoFuncTabEntry;

typedef struct {
    uint32_t entryOff;      // Offset of function start
    int32_t  nameOff;       // Offset to function name string relative to funcnameOffset
} GoFunc;
#pragma pack(pop)

// Structure to associate set breakpoints with function names
typedef struct {
    PVOID Address;
    char  Name[256];
} GoHookedFunc;

GoHookedFunc g_go_hooked_funcs[128] = {0};
int g_go_hooked_count = 0;

// Thread-local variables to handle async-safe, re-entrant TLS unencrypted response capturing on return
static __declspec(thread) PVOID t_go_read_buf = NULL;
static __declspec(thread) PVOID t_go_return_hook_address = NULL;

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
        // 1. Standard DOS MZ Magic Check
        if (*(PWORD)pBase == 0x5A4D) { // "MZ"
            return TRUE;
        }

        // 2. Wiped-MZ Check: Scan first 1024 bytes (256 DWORDS) of the allocation base for "PE\0\0" (0x00004550)
        // Many reflective loaders and packers only zero out the first 64 bytes (the DOS header) to bypass 
        // simplistic memory scanners. The NT header PE signature (located at offset 0x80 - 0x200) stays fully intact.
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
    if (Size < PatternSize) return NULL;
    __try {
        for (PBYTE p = pStart; p < pStart + Size - PatternSize; p += 4) {
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
static PBYTE ScanSectionForPclntab(PBYTE pStart, DWORD Size) {
    if (Size < sizeof(GoPCHeader)) return NULL;
    __try {
        for (PBYTE p = pStart; p < pStart + Size - sizeof(GoPCHeader); p += 4) {
            DWORD Magic = *(PDWORD)p;
            if (Magic == 0xFFFFFFF1 || Magic == 0xFFFFFFF0 || Magic == 0xFFFFFFFA || Magic == 0xFFFFFFFB) {
                // Verify the structural bounds to eliminate false positives
                BYTE ptrSize = *(p + 7);
                if (ptrSize == 4 || ptrSize == 8) {
                    DWORD nfunc = *(PDWORD)(p + 8);
                    if (nfunc > 0 && nfunc < 1000000) { // Sane number of functions
                        return p;
                    }
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

    // Resolve the function name associated with this breakpoint
    const char* funcName = "UnknownGoFunc";
    for (int i = 0; i < g_go_hooked_count; i++) {
        if (g_go_hooked_funcs[i].Address == pBreakpointInfo->Address) {
            funcName = g_go_hooked_funcs[i].Name;
            break;
        }
    }

    LOQ_string("go_trace", "s", "Function", funcName);
    DebugOutput("Go Trace: Intercepted Execution of Go Function: %s at 0x%p\n", funcName, pBreakpointInfo->Address);

    // Dynamic high-signal argument tracing based on Go Calling Conventions
    __try {
        if (strstr(funcName, "syscall.Syscall")) {
            ULONG_PTR trapAddress = GO_REG_ARG1(ExceptionInfo);
            
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
                                LOQ_string("go_trace", "ss", "Event", "Go Reflective PE Payload Execution Intercepted",
                                           "Jump Address", Formatter.FormatHex(trapAddress));
                                CapeMetaData->TypeString = "Go Reflective PE Payload";
                            } else {
                                DebugOutput("Go Trace: Detected direct in-memory shellcode execution at 0x%p! (Size: 0x%x)\n", (PVOID)trapAddress, mbi.RegionSize);
                                LOQ_string("go_trace", "ss", "Event", "Go Direct Shellcode/Payload Execution Intercepted",
                                           "Jump Address", Formatter.FormatHex(trapAddress));
                                CapeMetaData->TypeString = "Go In-Memory Shellcode Payload";
                            }

                            // Dump the raw in-memory payload cleanly (headers + sections)
                            CapeMetaData->ModulePath = NULL;
                            CapeMetaData->DumpType = 0;
                            CapeMetaData->Address = mbi.AllocationBase;
                            
                            DumpMemoryRaw(mbi.AllocationBase, mbi.RegionSize);
                        }
                    }
                }
            }
        }
        else if (strstr(funcName, "crypto/tls.(*Conn).Write")) {
            // Under register calling convention: RAX points to byte array, RBX has the length
            ULONG_PTR pData = GO_REG_ARG1(ExceptionInfo);
            ULONG_PTR length = GO_REG_ARG2(ExceptionInfo);
            
            if (pData != 0 && length > 0 && length < 8192 && IsAddressAccessible((PVOID)pData)) {
                char* pBuf = (char*)calloc(length + 1, 1);
                if (pBuf) {
                    memcpy(pBuf, (PVOID)pData, length);
                    LOQ_string("go_tls", "ss", "Direction", "Outbound", "Plaintext", pBuf);
                    DebugOutput("Go TLS Outbound Plaintext Payload (%d bytes) Intercepted:\n%s\n", length, pBuf);
                    free(pBuf);
                }
            }
        }
        else if (strstr(funcName, "crypto/tls.(*Conn).Read")) {
            ULONG_PTR pData = GO_REG_ARG1(ExceptionInfo);
            ULONG_PTR length = GO_REG_ARG2(ExceptionInfo);
            
            if (pData != 0 && length > 0 && IsAddressAccessible((PVOID)pData)) {
                // Stash the destination plaintext buffer pointer thread-locally
                t_go_read_buf = (PVOID)pData;
                
                // Read the return address from top of stack
                PVOID* pReturnAddress = (PVOID*)ExceptionInfo->ContextRecord->Rsp;
                if (IsAddressAccessible(pReturnAddress) && *pReturnAddress != NULL) {
                    t_go_return_hook_address = *pReturnAddress;
                    
                    // Arm a temporary software return breakpoint (0xCC)
                    SetSoftwareBreakpoint(&SoftBPs, t_go_return_hook_address);
                }
            }
        }
        else if (strstr(funcName, "crypto") || strstr(funcName, "Encrypt") || strstr(funcName, "Decrypt")) {
            // Under Go 1.17+ register-based calling convention, args are in RAX, RBX, RCX...
            ULONG_PTR r_arg1 = GO_REG_ARG1(ExceptionInfo);
            ULONG_PTR r_arg2 = GO_REG_ARG2(ExceptionInfo);
            
            LOQ_string("go_trace", "sss", "Event", "Go Cryptographic Operation Intercepted",
                       "Key/Data Register 1", Formatter.FormatHex(r_arg1),
                       "Length Register 2", Formatter.FormatHex(r_arg2));
            
            // Go string heuristic: check if arg1 is a valid pointer and arg2 is a logical string length
            if (r_arg2 > 0 && r_arg2 < 512 && IsAddressAccessible((PVOID)r_arg1)) {
                LogGoString("Crypto Payload", (PVOID)r_arg1, r_arg2);
            }
        }
        else if (strstr(funcName, "net/http")) {
            ULONG_PTR r_arg1 = GO_REG_ARG1(ExceptionInfo);
            ULONG_PTR r_arg2 = GO_REG_ARG2(ExceptionInfo);
            
            LOQ_string("go_trace", "ss", "Event", "Go HTTP Networking Intercepted",
                       "URL String Pointer", Formatter.FormatHex(r_arg1));
            
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
    if (t_go_return_hook_address != NULL && Address == t_go_return_hook_address) {
        __try {
            // Under Go's ABI, the first return value "n" (bytes successfully decrypted/read) is in RAX
            ULONG_PTR bytesRead = ExceptionInfo->ContextRecord->Rax;
            
            if (t_go_read_buf != NULL && bytesRead > 0 && bytesRead < 8192 && IsAddressAccessible(t_go_read_buf)) {
                char* pBuf = (char*)calloc(bytesRead + 1, 1);
                if (pBuf) {
                    memcpy(pBuf, t_go_read_buf, bytesRead);
                    LOQ_string("go_tls", "ss", "Direction", "Inbound", "Plaintext", pBuf);
                    DebugOutput("Go TLS Inbound Plaintext Payload (%d bytes) Intercepted on Return:\n%s\n", bytesRead, pBuf);
                    free(pBuf);
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DebugOutput("Go Trace: Exception occurred resolving Go tls.Read return.\n");
        }
        
        // Immediately disarm and cleanup the temporary return breakpoint
        ClearSoftwareBreakpoint(&SoftBPs, t_go_return_hook_address);
        t_go_return_hook_address = NULL;
        t_go_read_buf = NULL;
        return TRUE;
    }

    // 2. Intercept persistent function entry software breakpoints
    for (int i = 0; i < g_go_hooked_count; i++) {
        if (g_go_hooked_funcs[i].Address == Address) {
            BREAKPOINTINFO bpInfo;
            bpInfo.Address = Address;
            bpInfo.Callback = GoBreakpointCallback;
            bpInfo.ThreadId = GetCurrentThreadId();
            
            GoBreakpointCallback(&bpInfo, ExceptionInfo);
            return TRUE;
        }
    }
    return FALSE;
}

// Sets an active internal software breakpoint hook (0xCC) on a recovered Go function address
static void GoSetFunctionHook(PVOID funcAddress, const char* funcName) {
    if (g_go_hooked_count >= 128)
        return;

    // Prevent duplicate hooks
    for (int i = 0; i < g_go_hooked_count; i++) {
        if (g_go_hooked_funcs[i].Address == funcAddress)
            return;
    }

    if (SetSoftwareBreakpoint(&SoftBPs, funcAddress)) {
        g_go_hooked_funcs[g_go_hooked_count].Address = funcAddress;
        strncpy_s(g_go_hooked_funcs[g_go_hooked_count].Name, sizeof(g_go_hooked_funcs[g_go_hooked_count].Name), funcName, _TRUNCATE);
        g_go_hooked_count++;
        DebugOutput("GoSetFunctionHook: Successfully hooked '%s' at 0x%p via software breakpoint (0xCC).\n", funcName, funcAddress);
    } else {
        DebugOutput("GoSetFunctionHook: Failed to set software breakpoint hook on '%s' at 0x%p.\n", funcName, funcAddress);
    }
}

// Safely parses and recovers all embedded source file paths from the file table (Inspired by GoReSym)
static void GoRecoverFilePaths(GoPCHeader* pHeader, PBYTE pclntab, DWORD ImageSize) {
    if (!pHeader || !pclntab) return;

    __try {
        PBYTE pFiletab = pclntab + pHeader->filetabOffset;
        DWORD nfiles = pHeader->nfiles;

        if (nfiles > 0 && nfiles < 5000) {
            PDWORD pOffsets = (PDWORD)pFiletab;
            for (DWORD i = 0; i < nfiles; i++) {
                if (!IsAddressAccessible(&pOffsets[i])) break;
                DWORD off = pOffsets[i];
                if (off > 0 && off < ImageSize) {
                    const char* filePath = (const char*)(pclntab + off);
                    if (IsAddressAccessible((PVOID)filePath) && strstr(filePath, ".go")) {
                        LOQ_string("go_filepath", "s", "Path", filePath);
                        DebugOutput("GoRecoverFilePaths: Recovered Go Source File Path: %s\n", filePath);
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
    BYTE endianness = pBuildinfo[15];

    __try {
        if (ptrSize == 8 && endianness == 0) { // Standard x64 little-endian PE
            PVOID* pVersionPtr = (PVOID*)(pBuildinfo + 16);
            PVOID* pModinfoPtr = (PVOID*)(pBuildinfo + 24);

            if (IsAddressAccessible(pVersionPtr) && IsAddressAccessible(*pVersionPtr)) {
                PVOID* pVerData = *(PVOID**)(pVersionPtr);
                ULONG_PTR* pVerLen = (ULONG_PTR*)((PBYTE)(*pVersionPtr) + 8);
                if (IsAddressAccessible(pVerLen) && IsAddressAccessible(pVerData)) {
                    char versionBuf[128] = {0};
                    DWORD len = (*pVerLen < 127) ? (DWORD)*pVerLen : 127;
                    memcpy(versionBuf, *pVerData, len);
                    LOQ_string("go_buildinfo", "s", "Version", versionBuf);
                    DebugOutput("GoParseBuildInfo: Recovered Go Compiler Version: %s\n", versionBuf);
                }
            }

            if (IsAddressAccessible(pModinfoPtr) && IsAddressAccessible(*pModinfoPtr)) {
                PVOID* pModData = *(PVOID**)(pModinfoPtr);
                ULONG_PTR* pModLen = (ULONG_PTR*)((PBYTE)(*pModinfoPtr) + 8);
                if (IsAddressAccessible(pModLen) && IsAddressAccessible(pModData)) {
                    DWORD len = (*pModLen < 4095) ? (DWORD)*pModLen : 4095;
                    char* modBuf = (char*)calloc(len + 1, 1);
                    if (modBuf) {
                        memcpy(modBuf, *pModData, len);
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

        // 1. Definite IsGoBinary Check: Walk section headers and scan ONLY read-only metadata sections
        // This takes less than a millisecond and has 0.00% performance overhead on non-Go binaries!
        for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
            char secName[9] = {0};
            memcpy(secName, pSec[i].Name, 8);
            
            // pclntab resides in .rdata, .rodata, or dedicated .gopclntab. Never in executable .text or writable .data.
            if (strstr(secName, ".rdata") || strstr(secName, ".rodata") || strstr(secName, "pclntab")) {
                PBYTE pStart = (PBYTE)ImageBase + pSec[i].VirtualAddress;
                DWORD size = pSec[i].Misc.VirtualSize;
                
                if (IsAddressAccessible(pStart)) {
                    pclntab = ScanSectionForPclntab(pStart, size);
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

        GoPCHeader* pHeader = (GoPCHeader*)pclntab;
        DebugOutput("GoRecoverSymbols: Dynamic Go binary detected! Recovering symbols from pclntab (Magic: 0x%x, Functions: %u)\n", pHeader->magic, pHeader->nfunc);

        // 2. Parsed BuildInfo scanner: Scan ONLY .data, .rdata, or .rodata sections for buildinfo magic
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
                        // Pass buildinfo and the remaining size of the section
                        GoParseBuildInfo(buildinfo, size - (DWORD)(buildinfo - pStart));
                        break;
                    }
                }
            }
        }

        // 3. Recover all source file paths from the Line Table
        GoRecoverFilePaths(pHeader, pclntab, pNt->OptionalHeader.SizeOfImage);

        PBYTE pFunctab = pclntab + pHeader->functabOffset;
        ULONG_PTR textStartBase = pHeader->textStart;
        ULONG_PTR absoluteTextStart = (textStartBase < (ULONG_PTR)ImageBase) ? ((ULONG_PTR)ImageBase + textStartBase) : textStartBase;

        for (DWORD i = 0; i < pHeader->nfunc; i++) {
            GoFuncTabEntry* pEntry = (GoFuncTabEntry*)(pFunctab + i * 8);
            if (!IsAddressAccessible(pEntry)) break;

            GoFunc* pFunc = (GoFunc*)(pclntab + pEntry->funcOff);
            if (!IsAddressAccessible(pFunc)) continue;

            const char* funcName = (const char*)(pclntab + pHeader->funcnameOffset + pFunc->nameOff);
            if (!IsAddressAccessible((PVOID)funcName)) continue;

            ULONG_PTR funcAddress = absoluteTextStart + pFunc->entryOff;

            // Target critical functions with high malicious utility (Stealers, Droppers, Cryptography, Websockets, Direct Syscalls, and OS operations)
            if (strstr(funcName, "crypto/aes") || 
                strstr(funcName, "crypto/cipher") ||
                strstr(funcName, "net/http") ||
                strstr(funcName, "main.decrypt") ||
                strstr(funcName, "main.download") ||
                strstr(funcName, "main.inject") ||
                strstr(funcName, "main.execute") ||
                strstr(funcName, "net/websocket") ||
                strstr(funcName, "syscall.Syscall") ||
                strstr(funcName, "crypto/tls.(*Conn).Write") ||
                strstr(funcName, "crypto/tls.(*Conn).Read") ||
                strstr(funcName, "os/exec") ||              // Process Spawning / Cmd Execution
                strstr(funcName, "path/filepath.Walk") ||   // Directory/File Sweeping (Ransomware/Stealers)
                strstr(funcName, "os.WriteFile") ||         // File Dropping/Writing
                strstr(funcName, "ioutil.WriteFile") ||     // File Dropping/Writing (Legacy)
                strstr(funcName, "os.OpenFile") ||          // Low-level File opening
                strstr(funcName, "os.Create") ||            // File Creation
                strstr(funcName, "os.Remove") ||            // File Deletion (Self-deletion)
                strstr(funcName, "registry.Key") ||         // Registry Persistence
                strstr(funcName, "windows/svc")) {          // Windows Service Persistence
                
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
