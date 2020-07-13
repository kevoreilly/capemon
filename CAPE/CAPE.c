/*
CAPE - Config And Payload Extraction
Copyright(C) 2015 - 2018 Context Information Security. (kevin.oreilly@contextis.com)

This program is free software : you can redistribute it and / or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.If not, see <http://www.gnu.org/licenses/>.
*/
//#define DEBUG_COMMENTS

#define _CRT_RAND_S
#define MD5LEN              16

#define MAX_PRETRAMP_SIZE 320
#define MAX_TRAMP_SIZE 128
#define MAX_UNICODE_PATH 32768

#define BUFSIZE                 1024    // For hashing
#define DUMP_MAX                100
#define CAPE_OUTPUT_FILE "CapeOutput.bin"
#define SUSPENDED_THREAD_MAX    4096

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <tchar.h>
#include <windows.h>
#include <Wincrypt.h>
#include <WinNT.h>
#include <Shlwapi.h>
#include <stdint.h>
#include <psapi.h>
#include <string.h>
#include <strsafe.h>
#include <tlhelp32.h>

#include "CAPE.h"
#include "Debugger.h"
#include "..\alloc.h"
#include "..\pipe.h"
#include "..\config.h"
#include "..\lookup.h"

#pragma comment(lib, "Shlwapi.lib")

typedef union _UNWIND_CODE {
    struct {
        BYTE CodeOffset;
        BYTE UnwindOp : 4;
        BYTE OpInfo : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE;

typedef struct _UNWIND_INFO {
    BYTE Version : 3;
    BYTE Flags : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset : 4;
    UNWIND_CODE UnwindCode[20];
} UNWIND_INFO;

typedef struct _hook_data_t {
    unsigned char tramp[MAX_TRAMP_SIZE];
    unsigned char pre_tramp[MAX_PRETRAMP_SIZE];
    //unsigned char our_handler[128];
    unsigned char hook_data[32];

    UNWIND_INFO unwind_info;
} hook_data_t;

typedef struct _hook_t {
    const wchar_t *library;
    const char *funcname;
    void *addr;
    void *hook_addr;
    void *new_func;
    void **old_func;
    void *alt_func;
    int allow_hook_recursion;
    int fully_emulate;
    unsigned char numargs;
    int notail;
    int is_hooked;
    hook_data_t *hookdata;
} hook_t;

typedef struct _hook_info_t {
    int disable_count;
    hook_t *last_hook;
    hook_t *current_hook;
    ULONG_PTR return_address;
    ULONG_PTR stack_pointer;
    ULONG_PTR frame_pointer;
    ULONG_PTR main_caller_retaddr;
    ULONG_PTR parent_caller_retaddr;
} hook_info_t;

extern uint32_t path_from_handle(HANDLE handle, wchar_t *path, uint32_t path_buffer_len);
extern wchar_t *ensure_absolute_unicode_path(wchar_t *out, const wchar_t *in);
extern int called_by_hook(void);
extern int operate_on_backtrace(ULONG_PTR _esp, ULONG_PTR _ebp, void *extra, int(*func)(void *, ULONG_PTR));
extern unsigned int address_is_in_stack(PVOID Address);
extern hook_info_t *hook_info();
extern ULONG_PTR base_of_dll_of_interest;
extern wchar_t *our_process_path_w;
extern wchar_t *our_commandline;
extern ULONG_PTR g_our_dll_base;
extern DWORD g_our_dll_size;
extern lookup_t g_caller_regions;

#ifdef CAPE_NIRVANA
extern void NirvanaInit();
#endif
extern void DoOutputFile(_In_ LPCTSTR lpOutputFile);
extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);
extern void CapeOutputFile(LPCTSTR lpOutputFile);
extern int IsPeImageVirtual(LPVOID Buffer);
extern int ScyllaDumpCurrentProcess(DWORD_PTR NewOEP);
extern int ScyllaDumpProcess(HANDLE hProcess, DWORD_PTR modBase, DWORD_PTR NewOEP);
extern int ScyllaDumpCurrentProcessFixImports(DWORD_PTR NewOEP);
extern int ScyllaDumpProcessFixImports(HANDLE hProcess, DWORD_PTR modBase, DWORD_PTR NewOEP);
extern int ScyllaDumpImageInCurrentProcessFixImports(DWORD_PTR modBase, DWORD_PTR NewOEP);
extern int ScyllaDumpPE(DWORD_PTR Buffer);
extern int ScyllaDumpPEToFileHandle(DWORD_PTR Buffer, HANDLE FileHandle);
extern unsigned int ScyllaDumpProcessToFileHandle(HANDLE hProcess, DWORD_PTR ModuleBase, DWORD_PTR NewOEP, HANDLE FileHandle);
extern SIZE_T GetPESize(PVOID Buffer);
extern LPVOID GetReturnAddress(hook_info_t *hookinfo);
extern PVOID CallingModule;
extern void UnpackerInit();
extern BOOL SetInitialBreakpoints(PVOID ImageBase);
extern BOOL UPXInitialBreakpoints(PVOID ImageBase);
extern BOOL BreakpointsSet;

BOOL ProcessDumped, FilesDumped, ModuleDumped, PlugXConfigDumped;
PVOID ImageBase;
char *CommandLine;
static unsigned int DumpCount;

static __inline ULONG_PTR get_stack_top(void)
{
#ifndef _WIN64
    return __readfsdword(0x04);
#else
    return __readgsqword(0x08);
#endif
}

static __inline ULONG_PTR get_stack_bottom(void)
{
#ifndef _WIN64
    return __readfsdword(0x08);
#else
    return __readgsqword(0x10);
#endif
}

// We need an export for IAT patching
#ifndef _WIN64
__declspec (naked dllexport) void dummy()
#else
__declspec(dllexport) void dummy()
#endif
{
}

//**************************************************************************************
BOOL InsideHook(LPVOID* ReturnAddress, LPVOID Address)
//**************************************************************************************
{
    if ((ULONG_PTR)Address >= g_our_dll_base && (ULONG_PTR)Address < (g_our_dll_base + g_our_dll_size))
    {
        if (ReturnAddress)
            *ReturnAddress = Address;
        return TRUE;
    }

    return FALSE;
}

//**************************************************************************************
int GetCurrentFrame(LPVOID ReturnAddress, ULONG_PTR Address)
//**************************************************************************************
{
    ReturnAddress = (LPVOID)Address;
    return 1;
}

//**************************************************************************************
LPVOID GetReturnAddress(hook_info_t *hookinfo)
//**************************************************************************************
{
    LPVOID ReturnAddress = NULL;

    __try
    {
        operate_on_backtrace(hookinfo->stack_pointer, hookinfo->frame_pointer, &ReturnAddress, GetCurrentFrame);
        return ReturnAddress;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
#ifdef _WIN64
        DoOutputDebugString("GetReturnAddress: Exception trying to get return address with Rip 0x%p.\n", hookinfo->frame_pointer);
#else
        DoOutputDebugString("GetReturnAddress: Exception trying to get return address with base pointer 0x%x.\n", hookinfo->frame_pointer);
#endif
        return NULL;
    }
}

//**************************************************************************************
PVOID GetHookCallerBase()
//**************************************************************************************
{
    PVOID ReturnAddress, AllocationBase;
    hook_info_t *hookinfo = hook_info();

    if (hookinfo->main_caller_retaddr)
        ReturnAddress = (PVOID)hookinfo->main_caller_retaddr;
    else if (hookinfo->parent_caller_retaddr)
        ReturnAddress = (PVOID)hookinfo->parent_caller_retaddr;
    //else
    //    ReturnAddress = GetReturnAddress(hookinfo);

    if (ReturnAddress)
    {
        DWORD ThreadId = GetCurrentThreadId();

        AllocationBase = GetAllocationBase(ReturnAddress);

        if (AllocationBase)
        {
            DoOutputDebugString("GetHookCallerBase: thread %d (handle 0x%x), return address 0x%p, allocation base 0x%p.\n", ThreadId, GetThreadHandle(ThreadId), ReturnAddress, AllocationBase);
            CallingModule = AllocationBase;
            return CallingModule;
            // Base-dependent breakpoints can be activated now
        }
    }
    else
        DoOutputDebugString("GetHookCallerBase: failed to get return address.\n");

    return NULL;
}

//**************************************************************************************
void PrintHexBytes(__in char* TextBuffer, __in BYTE* HexBuffer, __in unsigned int Count)
//**************************************************************************************
{
    unsigned int i;

    if (HexBuffer == NULL)
        return;

    for (i=0; i<Count; i++)
    {
        sprintf_s((TextBuffer+2*i), Count, "%2.2x", (unsigned int)*(HexBuffer+i));
    }

    return;
}

//*********************************************************************************************************************************
BOOL TranslatePathFromDeviceToLetter(__in char *DeviceFilePath, __out char* DriveLetterFilePath, __inout LPDWORD lpdwBufferSize)
//*********************************************************************************************************************************
{
    char DriveStrings[BUFSIZE];
    DriveStrings[0] = '\0';

    if (DriveLetterFilePath == NULL || *lpdwBufferSize < MAX_PATH)
    {
        *lpdwBufferSize = MAX_PATH;
        return FALSE;
    }

    if (GetLogicalDriveStrings(BUFSIZE-1, DriveStrings))
    {
        char DeviceName[MAX_PATH];
        char szDrive[3] = " :";
        BOOL FoundDevice = FALSE;
        char* p = DriveStrings;

        do
        {
            *szDrive = *p;

            if (QueryDosDevice(szDrive, DeviceName, MAX_PATH))
            {
                size_t DeviceNameLength = strlen(DeviceName);

                if (DeviceNameLength < MAX_PATH)
                {
                    FoundDevice = _strnicmp(DeviceFilePath, DeviceName, DeviceNameLength) == 0;

                    if (FoundDevice && *(DeviceFilePath + DeviceNameLength) == ('\\'))
                    {
                        // Construct DriveLetterFilePath replacing device path with DOS path
                        char NewPath[MAX_PATH];
                        StringCchPrintf(NewPath, MAX_PATH, TEXT("%s%s"), szDrive, DeviceFilePath+DeviceNameLength);
                        StringCchCopyN(DriveLetterFilePath, MAX_PATH, NewPath, strlen(NewPath));
                    }
                }
            }

            // Go to the next NULL character.
            while (*p++);
        }
        while (!FoundDevice && *p); // end of string
    }
    else
    {
        DoOutputErrorString("TranslatePathFromDeviceToLetter: GetLogicalDriveStrings failed");
        return FALSE;
    }

    return TRUE;
}

//**************************************************************************************
PVOID GetAllocationBase(PVOID Address)
//**************************************************************************************
{
    MEMORY_BASIC_INFORMATION MemInfo;

    if (!Address)
        return NULL;

    if (!SystemInfo.dwPageSize)
        GetSystemInfo(&SystemInfo);

    if (!SystemInfo.dwPageSize)
    {
        DoOutputErrorString("GetAllocationBase: Failed to obtain system page size.\n");
        return 0;
    }

    if (!VirtualQuery(Address, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
    {
        //DoOutputErrorString("GetAllocationBase: unable to query memory address 0x%x", Address);
        return 0;
    }

#ifdef DEBUG_COMMENTS
//    DoOutputErrorString("GetAllocationBase: Address 0x%p allocation base: 0x%p", Address, MemInfo.AllocationBase);
#endif
    return MemInfo.AllocationBase;
}

//**************************************************************************************
SIZE_T GetAllocationSize(PVOID Address)
//**************************************************************************************
{
    MEMORY_BASIC_INFORMATION MemInfo;
    PVOID OriginalAllocationBase, AddressOfPage;

    if (!Address)
        return 0;

    if (!SystemInfo.dwPageSize)
        GetSystemInfo(&SystemInfo);

    if (!SystemInfo.dwPageSize)
    {
        DoOutputErrorString("GetAllocationSize: Failed to obtain system page size.\n");
        return 0;
    }

    if (!VirtualQuery(Address, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
    {
        DoOutputErrorString("GetAllocationSize: unable to query memory address 0x%x", Address);
        return 0;
    }

    OriginalAllocationBase = MemInfo.AllocationBase;
    AddressOfPage = OriginalAllocationBase;

    while (MemInfo.AllocationBase == OriginalAllocationBase)
    {
        (PUCHAR)AddressOfPage += SystemInfo.dwPageSize;

        if (!VirtualQuery(AddressOfPage, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
        {
            DoOutputErrorString("GetAllocationSize: unable to query memory page 0x%x", AddressOfPage);
            return 0;
        }
    }

    return (SIZE_T)((DWORD_PTR)AddressOfPage - (DWORD_PTR)OriginalAllocationBase);

}

//**************************************************************************************
BOOL SetCapeMetaData(DWORD DumpType, DWORD TargetPid, HANDLE hTargetProcess, PVOID Address)
//**************************************************************************************
{
    if (DumpType == 0)
    {
        DoOutputDebugString("SetCapeMetaData: DumpType NULL.\n");
        return FALSE;
    }

    CapeMetaData->DumpType = DumpType;

    if (DumpType == INJECTION_PE || DumpType == INJECTION_SHELLCODE)
    {
        if (!TargetPid)
        {
            DoOutputDebugString("SetCapeMetaData: Injection type with no PID - error.\n");
            return FALSE;
        }

        if (!hTargetProcess)
        {
            DoOutputDebugString("SetCapeMetaData: Injection type with no process handle - error.\n");
            return FALSE;
        }

        CapeMetaData->TargetPid = TargetPid;

        if (CapeMetaData->TargetProcess == NULL)
        {
            DoOutputDebugString("SetCapeMetaData: failed to allocate memory for target process string.\n");
            return FALSE;
        }

        if (CapeMetaData->TargetProcess == NULL && !GetModuleFileNameEx(hTargetProcess, NULL, CapeMetaData->TargetProcess, MAX_PATH))
        {
            CapeMetaData->TargetProcess = (char*)malloc(MAX_PATH);
            DoOutputErrorString("SetCapeMetaData: GetModuleFileNameEx failed on target process, handle 0x%x", hTargetProcess);
            return FALSE;
        }
    }
    else if (DumpType == UNPACKED_PE || DumpType == UNPACKED_SHELLCODE || DumpType == URSNIF_PAYLOAD)
    {
        if (!Address)
        {
            DoOutputDebugString("SetCapeMetaData: CAPE type with missing PID - error.\n");
            return FALSE;
        }

        CapeMetaData->Address = Address;
    }

    return TRUE;
}

//**************************************************************************************
BOOL MapFile(HANDLE hFile, unsigned char **Buffer, DWORD* FileSize)
//**************************************************************************************
{
    LARGE_INTEGER LargeFileSize;
    DWORD dwBytesRead;

    if (!GetFileSizeEx(hFile, &LargeFileSize))
    {
        DoOutputErrorString("MapFile: Cannot get file size");
        return FALSE;
    }

    if (LargeFileSize.HighPart || LargeFileSize.LowPart > SIZE_OF_LARGEST_IMAGE)
    {
        DoOutputDebugString("MapFile: File too big");
        return FALSE;
    }

    if (LargeFileSize.LowPart == 0)
    {
        DoOutputDebugString("MapFile: File is zero in size.");
        return FALSE;
    }

    *FileSize = LargeFileSize.LowPart;

    DoOutputDebugString("File size: 0x%x", *FileSize);

    *Buffer = malloc(*FileSize);

    if (SetFilePointer(hFile, 0, 0, FILE_BEGIN))
    {
         DoOutputErrorString("MapFile: Failed to set file pointer");
        return FALSE;
    }

    if (*Buffer == NULL)
    {
        DoOutputErrorString("MapFile: Memory allocation error in MapFile");
        return FALSE;
    }

    if (FALSE == ReadFile(hFile, (LPVOID)*Buffer, *FileSize, &dwBytesRead, NULL))
    {
        DoOutputErrorString("ReadFile error");
        free(Buffer);
        return FALSE;
    }

    if (dwBytesRead > 0 && dwBytesRead < *FileSize)
    {
        DoOutputErrorString("MapFile: Unexpected size read in");
        free(Buffer);
        return FALSE;

    }
    else if (dwBytesRead == 0)
    {
        DoOutputErrorString("MapFile: No data read from file");
        free(Buffer);
        return FALSE;
    }

    return TRUE;
}

//**************************************************************************************
char* GetResultsPath(char* FolderName)
//**************************************************************************************
{
    char *FullPath;
    DWORD RetVal;

    FullPath = (char*)malloc(MAX_PATH);

    if (FullPath == NULL)
    {
        DoOutputErrorString("GetResultsPath: Error allocating memory for full path string");
        return 0;
    }

    // We want to dump output to the 'results' directory
    memset(FullPath, 0, MAX_PATH);

    strncpy_s(FullPath, MAX_PATH, g_config.results, strlen(g_config.results)+1);

    if (strlen(FullPath) + 1 + strlen(FolderName) >= MAX_PATH)
    {
        DoOutputDebugString("GetResultsPath: Error, destination path too long.\n");
        free(FullPath);
        return 0;
    }

    PathAppend(FullPath, FolderName);

    RetVal = CreateDirectory(FullPath, NULL);

    if (RetVal == 0 && GetLastError() != ERROR_ALREADY_EXISTS)
    {
        DoOutputErrorString("GetResultsPath: Error creating output directory %s", FullPath);
        free(FullPath);
        return 0;
    }

    return FullPath;
}

//**************************************************************************************
char* GetName()
//**************************************************************************************
{
    char *FullPathName,*OutputFilename;
    SYSTEMTIME Time;
    unsigned int random;

    FullPathName = GetResultsPath("CAPE");

    OutputFilename = (char*)malloc(MAX_PATH);

    if (OutputFilename == NULL)
    {
        DoOutputErrorString("GetName: failed to allocate memory for file name string");
        return 0;
    }

    GetSystemTime(&Time);

    if (rand_s(&random))
    {
        DoOutputErrorString("GetName: failed to obtain a random number");
        return 0;
    }

    sprintf_s(OutputFilename, MAX_PATH*sizeof(char), "%d_%d%d%d%d%d%d%d%d", GetCurrentProcessId(), abs(random * Time.wMilliseconds), Time.wSecond, Time.wMinute, Time.wHour, Time.wDay, Time.wDayOfWeek, Time.wMonth, Time.wYear);

    PathAppend(FullPathName, OutputFilename);

    free(OutputFilename);

    return FullPathName;
}

//**************************************************************************************
BOOL GetHash(unsigned char* Buffer, unsigned int Size, char* OutputFilenameBuffer)
//**************************************************************************************
{
    DWORD i;
    DWORD dwStatus = 0;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    DWORD cbHash = 0;
    BYTE MD5Hash[MD5LEN];

    // Get handle to the crypto provider
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        DoOutputErrorString("CryptAcquireContext failed");
        return 0;
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    {
        DoOutputErrorString("CryptCreateHash failed");
        CryptReleaseContext(hProv, 0);
        return 0;
    }

    if (!CryptHashData(hHash, Buffer, Size, 0))
    {
        DoOutputErrorString("CryptHashData failed");
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        return 0;
    }

    cbHash = MD5LEN;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, MD5Hash, &cbHash, 0))
    {
        DoOutputErrorString("CryptGetHashParam failed");
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    for (i = 0; i < cbHash; i++)
    {
        PrintHexBytes(OutputFilenameBuffer, MD5Hash, MD5LEN);
    }

    return 1;
}

//**************************************************************************************
char* GetHashFromHandle(HANDLE hFile)
//**************************************************************************************
{
    DWORD FileSize;
    long e_lfanew;
    PIMAGE_NT_HEADERS pNtHeader;
    unsigned char* Buffer = NULL;
    char * OutputFilenameBuffer;

    if (!MapFile(hFile, &Buffer, &FileSize))
    {
        DoOutputErrorString("MapFile error - check the path is valid and the file has size.");
        return 0;
    }

    OutputFilenameBuffer = (char*) malloc(MAX_PATH);

    if (OutputFilenameBuffer == NULL)
    {
        DoOutputErrorString("Error allocating memory for hash string");
        return 0;
    }

    if (!GetHash(Buffer, FileSize, (char*)OutputFilenameBuffer))
    {
        DoOutputErrorString("GetHashFromHandle: GetHash function failed");
        return 0;
    }

    DoOutputDebugString("GetHash returned: %s", OutputFilenameBuffer);

    // Check if we have a valid DOS and PE header at the beginning of Buffer
    if (*(WORD*)Buffer == IMAGE_DOS_SIGNATURE)
    {
        e_lfanew = *(long*)(Buffer+0x3c);

        if ((unsigned int)e_lfanew > PE_HEADER_LIMIT)
        {
            // This check is possibly not appropriate here
            // As long as we've got what's been compressed
        }

        if (*(DWORD*)(Buffer+e_lfanew) == IMAGE_NT_SIGNATURE)
        {
            pNtHeader = (PIMAGE_NT_HEADERS)(Buffer+e_lfanew);

            if ((pNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
            {
                sprintf_s((OutputFilenameBuffer+2*MD5LEN), MAX_PATH*sizeof(char), ".dll");
            }
            else if ((pNtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == IMAGE_FILE_EXECUTABLE_IMAGE)
            {
                sprintf_s((OutputFilenameBuffer+2*MD5LEN), MAX_PATH*sizeof(char)-2*MD5LEN, ".exe_");
            }
        }
    }

    CloseHandle(hFile);

    // We don't need the file buffer any more
    free(Buffer);

    // We leak the OutputFilenameBuffer
    return OutputFilenameBuffer;
}

//**************************************************************************************
double GetEntropy(PUCHAR Buffer)
//**************************************************************************************
{
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader = NULL;
    unsigned long TotalCounts[256];
	double p, lp, Entropy = 0;
	double log_2 = log((double)2);
    SIZE_T Length;
    unsigned int i;

    if (!Buffer)
    {
        DoOutputDebugString("GetEntropy: Error - no address supplied.\n");
        return 0;
    }

    if (IsDisguisedPEHeader((PVOID)Buffer) <= 0)
        return 0;

    pDosHeader = (PIMAGE_DOS_HEADER)Buffer;

    __try
    {
        if (pDosHeader->e_lfanew && (ULONG)pDosHeader->e_lfanew < PE_HEADER_LIMIT && ((ULONG)pDosHeader->e_lfanew & 3) == 0)
            pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + (ULONG)pDosHeader->e_lfanew);

        if (pNtHeader && TestPERequirements(pNtHeader))
            Length = pNtHeader->OptionalHeader.SizeOfImage;

        if (!Length)
            return 0;

        memset(TotalCounts, 0, sizeof(TotalCounts));

        for (i = 0; i < Length; i++)
        {
            TotalCounts[Buffer[i]]++;
        }

        for (i = 0; i < 256; i++)
        {
            if (TotalCounts[i] == 0) continue;

            p = 1.0 * TotalCounts[i] / Length;

            lp = log(p)/log_2;

            Entropy -= p * lp;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DoOutputDebugString("GetEntropy: Exception occured attempting to get PE entropy at 0x%p\n", (PUCHAR)Buffer+i);
        return 0;
    }

    return Entropy;
}

//**************************************************************************************
int DumpXorPE(LPBYTE Buffer, unsigned int Size)
//**************************************************************************************
{
    LONG e_lfanew;
    DWORD NT_Signature;
    unsigned int i, j, k;
    BYTE* DecryptedBuffer = NULL;

    for (i=0; i<=0xFF; i++)
    {
        // check for the DOS signature a.k.a MZ header
        if ((*Buffer^(BYTE)i) == 'M' && (*(Buffer+1)^(BYTE)i) == 'Z')
        {
            DoOutputDebugString("MZ header found with bytewise XOR key 0x%.2x\n", i);

            e_lfanew = (LONG)*(DWORD*)(Buffer+0x3c);

            DoOutputDebugString("Encrypted e_lfanew: 0x%x", e_lfanew);

            for (j=0; j<sizeof(LONG); j++)
                *((BYTE*)&e_lfanew+j) = *((BYTE*)&e_lfanew+j)^i;

            DoOutputDebugString("Decrypted e_lfanew: 0x%x", e_lfanew);

            if ((unsigned int)e_lfanew > PE_HEADER_LIMIT)
            {
                DoOutputDebugString("The pointer to the PE header seems a tad large: 0x%x", e_lfanew);
                //return FALSE;
            }

            // let's get the NT signature a.k.a PE header
            memcpy(&NT_Signature, Buffer+e_lfanew, 4);

            DoOutputDebugString("Encrypted NT_Signature: 0x%x", NT_Signature);

            // let's try decrypting it with the key
            for (k=0; k<4; k++)
                *((BYTE*)&NT_Signature+k) = *((BYTE*)&NT_Signature+k)^i;

            DoOutputDebugString("Encrypted NT_Signature: 0x%x", NT_Signature);

            // does it check out?
            if (NT_Signature == IMAGE_NT_SIGNATURE)
            {
                DoOutputDebugString("Xor-encrypted PE detected, about to dump.\n");

                DecryptedBuffer = (BYTE*)malloc(Size);

                if (DecryptedBuffer == NULL)
                {
                    DoOutputErrorString("Error allocating memory for decrypted PE binary");
                    return FALSE;
                }

                memcpy(DecryptedBuffer, Buffer, Size);

                for (k=0; k<Size; k++)
                    *(DecryptedBuffer+k) = *(DecryptedBuffer+k)^i;

                CapeMetaData->Address = DecryptedBuffer;
                DumpImageInCurrentProcess(DecryptedBuffer);

                free(DecryptedBuffer);
                return i;
            }
            else
            {
                DoOutputDebugString("PE signature invalid, looks like a false positive.\n");
                return FALSE;
            }
        }
    }

    // We free can free DecryptedBuffer as it's no longer needed
    if(DecryptedBuffer)
        free(DecryptedBuffer);

    return FALSE;
}

//**************************************************************************************
int ScanPageForNonZero(LPVOID Address)
//**************************************************************************************
{
    unsigned int p;
    DWORD_PTR AddressOfPage;

    if (!Address)
    {
        DoOutputDebugString("ScanPageForNonZero: Error - Supplied address zero.\n");
        return 0;
    }

    if (!SystemInfo.dwPageSize)
        GetSystemInfo(&SystemInfo);

    if (!SystemInfo.dwPageSize)
    {
        DoOutputErrorString("ScanPageForNonZero: Failed to obtain system page size.\n");
        return 0;
    }

    AddressOfPage = ((DWORD_PTR)Address/SystemInfo.dwPageSize)*SystemInfo.dwPageSize;

    __try
    {
        for (p=0; p<SystemInfo.dwPageSize-1; p++)
            if (*((char*)AddressOfPage+p) != 0)
                return 1;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DoOutputDebugString("ScanPageForNonZero: Exception occured reading memory address 0x%x\n", (char*)AddressOfPage+p);
        return 0;
    }

    return 0;
}

//**************************************************************************************
int ScanForNonZero(LPVOID Buffer, SIZE_T Size)
//**************************************************************************************
{
    SIZE_T p;

    if (!Buffer)
    {
        DoOutputDebugString("ScanForNonZero: Error - Supplied address zero.\n");
        return 0;
    }

    __try
    {
        for (p=0; p<Size-1; p++)
            if (*((char*)Buffer+p) != 0)
                return (int)p;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DoOutputDebugString("ScanForNonZero: Exception occured reading memory address 0x%x\n", (char*)Buffer+p);
        return 0;
    }

    return 0;
}

//**************************************************************************************
int ReverseScanForNonZero(LPVOID Buffer, SIZE_T Size)
//**************************************************************************************
{
    SIZE_T p;

    if (!Buffer)
    {
        DoOutputDebugString("ScanForNonZero: Error - Supplied address zero.\n");
        return 0;
    }

    __try
    {
        for (p=Size-1; p>=0; p--)
            if (*((char*)Buffer+p) != 0)
                return (int)p;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DoOutputDebugString("ScanForNonZero: Exception occured reading memory address 0x%x\n", (char*)Buffer+p);
        return 0;
    }

    return 0;
}

//**************************************************************************************
PVOID GetPageAddress(PVOID Address)
//**************************************************************************************
{
    if (!Address)
    {
        DoOutputDebugString("GetPageAddress: Error - Supplied address zero.\n");
        return NULL;
    }

    if (!SystemInfo.dwPageSize)
        GetSystemInfo(&SystemInfo);

    if (!SystemInfo.dwPageSize)
    {
        DoOutputErrorString("GetPageAddress: Failed to obtain system page size.\n");
        return NULL;
    }

    return (PVOID)(((DWORD_PTR)Address/SystemInfo.dwPageSize)*SystemInfo.dwPageSize);

}

//**************************************************************************************
int ScanForPE(LPVOID Buffer, SIZE_T Size, LPVOID* Offset)
//**************************************************************************************
{
    SIZE_T p;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;

    if (!Buffer || !Size)
    {
        DoOutputDebugString("ScanForPE: Error, Buffer or Size zero: 0x%x, 0x%x\n", Buffer, Size);
        return 0;
    }

    for (p=0; p<Size-1; p++)
    {
        __try
        {
            if (*((char*)Buffer+p) == 'M' && *((char*)Buffer+p+1) == 'Z')
            {
                pDosHeader = (PIMAGE_DOS_HEADER)((char*)Buffer+p);

                if ((ULONG)pDosHeader->e_lfanew == 0)
                {
                    // e_lfanew is zero
                    continue;
                }

                if ((ULONG)pDosHeader->e_lfanew > Size-p)
                {
                    // e_lfanew points beyond end of region
                    continue;
                }

                pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + (ULONG)pDosHeader->e_lfanew);

                if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
                {
                    // No 'PE' header
                    continue;
                }

                if ((pNtHeader->FileHeader.Machine == 0) || (pNtHeader->FileHeader.SizeOfOptionalHeader == 0 || pNtHeader->OptionalHeader.SizeOfHeaders == 0))
                {
                    // Basic requirements
                    DoOutputDebugString("ScanForPE: Basic requirements failure.\n");
                    continue;
                }

                if (Offset)
                    *Offset = (LPVOID)((char*)Buffer+p);

                //DoOutputDebugString("ScanForPE: PE image located at: 0x%x\n", (DWORD_PTR)((char*)Buffer+p));

                return 1;
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            DoOutputDebugString("ScanForPE: Exception occured reading memory address 0x%x\n", (DWORD_PTR)((char*)Buffer+p));
            return 0;
        }
    }

    DoOutputDebugString("ScanForPE: No PE image located at 0x%x.\n", Buffer);
    return 0;
}

//**************************************************************************************
BOOL TestPERequirements(PIMAGE_NT_HEADERS pNtHeader)
//**************************************************************************************
{
    SIZE_T MinSize;

    __try
    {
        PIMAGE_SECTION_HEADER NtSection;

        if ((pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) && (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC))
            return FALSE;

        // Basic requirements
        if (!pNtHeader->FileHeader.NumberOfSections || pNtHeader->FileHeader.NumberOfSections > PE_MAX_SECTIONS)
            return FALSE;

        if (!pNtHeader->OptionalHeader.SizeOfImage || pNtHeader->OptionalHeader.SizeOfImage > PE_MAX_SIZE)
            return FALSE;

        NtSection = IMAGE_FIRST_SECTION(pNtHeader);

        for (unsigned int i=0; i<pNtHeader->FileHeader.NumberOfSections; i++)
        {
            if (!NtSection->Misc.VirtualSize && !NtSection->SizeOfRawData)
            {
                DoOutputDebugString("TestPERequirements: Possible PE image rejected due to section %d of %d, VirtualSize and SizeOfRawData are zero.\n", i+1, pNtHeader->FileHeader.NumberOfSections);
                return FALSE;
            }

            if (NtSection->Misc.VirtualSize && NtSection->SizeOfRawData && NtSection->Misc.VirtualSize > NtSection->SizeOfRawData)
                MinSize = NtSection->SizeOfRawData;
            else if (NtSection->Misc.VirtualSize && NtSection->SizeOfRawData && NtSection->Misc.VirtualSize <= NtSection->SizeOfRawData)
                MinSize = NtSection->Misc.VirtualSize;
            else if (NtSection->SizeOfRawData)
                MinSize = NtSection->SizeOfRawData;
            else if (NtSection->Misc.VirtualSize)
                MinSize = NtSection->Misc.VirtualSize;

            if (NtSection->VirtualAddress + MinSize > (ULONG)pNtHeader->OptionalHeader.SizeOfImage)
            {
                DoOutputDebugString("TestPERequirements: Possible PE image rejected due to section %d of %d, RVA 0x%x and size 0x%x.\n", i+1, pNtHeader->FileHeader.NumberOfSections, NtSection->VirtualAddress, MinSize);
                return FALSE;
            }

            ++NtSection;
        }

        // To pass the above tests it should now be safe to dump as a PE image
        return TRUE;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DoOutputDebugString("TestPERequirements: Exception occured reading region at 0x%x\n", (DWORD_PTR)(pNtHeader));
        return FALSE;
    }
}

//**************************************************************************************
SIZE_T GetMinPESize(PIMAGE_NT_HEADERS pNtHeader)
//**************************************************************************************
{
    SIZE_T MinSize;

    __try
    {
        PIMAGE_SECTION_HEADER NtSection;

        if ((pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) && (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC))
            return 0;

        // Basic requirements
        if (!pNtHeader->FileHeader.NumberOfSections || pNtHeader->FileHeader.NumberOfSections > PE_MAX_SECTIONS)
            return 0;

        if (!pNtHeader->OptionalHeader.SizeOfImage || pNtHeader->OptionalHeader.SizeOfImage > PE_MAX_SIZE)
            return 0;

        NtSection = IMAGE_FIRST_SECTION(pNtHeader);

        for (unsigned int i=1; i<pNtHeader->FileHeader.NumberOfSections; i++)
            ++NtSection;

        if (!NtSection->PointerToRawData && !NtSection->VirtualAddress)
            return 0;

        if (NtSection->PointerToRawData)
            MinSize = NtSection->PointerToRawData + NtSection->SizeOfRawData;
        else if (NtSection->VirtualAddress)
            MinSize = NtSection->VirtualAddress + NtSection->SizeOfRawData;

        if (!MinSize || MinSize > (ULONG)pNtHeader->OptionalHeader.SizeOfImage)
        {
            DoOutputDebugString("GetMinPESize: Possible PE image rejected due to min size 0x%x (SizeOfImage 0x%x).\n", MinSize, pNtHeader->OptionalHeader.SizeOfImage);
            return 0;
        }

        return MinSize;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DoOutputDebugString("GetMinPESize: Exception occured reading region at 0x%x\n", (DWORD_PTR)(pNtHeader));
        return 0;
    }
}

//**************************************************************************************
int IsDotNetImage(LPVOID Buffer)
//**************************************************************************************
{
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader = NULL;

    __try
    {
        pDosHeader = (PIMAGE_DOS_HEADER)Buffer;

        if (pDosHeader->e_lfanew && (ULONG)pDosHeader->e_lfanew < PE_HEADER_LIMIT && ((ULONG)pDosHeader->e_lfanew & 3) == 0)
            pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + (ULONG)pDosHeader->e_lfanew);

        if (!pNtHeader || !TestPERequirements(pNtHeader))
            return 0;

#ifndef _WIN64
        if (pNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            return 0;
#endif

        if (pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress || pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress)
            return 1;

    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }

    return 0;
}

//**************************************************************************************
int IsDisguisedPEHeader(LPVOID Buffer)
//**************************************************************************************
{
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader = NULL;
    //WORD* MachineProbe;

    __try
    {
        pDosHeader = (PIMAGE_DOS_HEADER)Buffer;

        if (pDosHeader->e_lfanew && (ULONG)pDosHeader->e_lfanew < PE_HEADER_LIMIT && ((ULONG)pDosHeader->e_lfanew & 3) == 0)
            pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + (ULONG)pDosHeader->e_lfanew);

        //if (!pDosHeader->e_lfanew)
        //{
        //    // In case the header until and including 'PE' has been zeroed
        //    MachineProbe = (WORD*)&pDosHeader->e_lfanew;
        //    while ((PUCHAR)MachineProbe < (PUCHAR)&pDosHeader + (PE_HEADER_LIMIT - offsetof(IMAGE_DOS_HEADER, e_lfanew)))
        //    {
        //        if (*MachineProbe == IMAGE_FILE_MACHINE_I386 || *MachineProbe == IMAGE_FILE_MACHINE_AMD64)
        //        {
        //            pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)MachineProbe - 4);
        //            break;
        //        }
        //        MachineProbe += sizeof(WORD);
        //    }
        //}

        //if (pNtHeader && TestPERequirements(pNtHeader))
        //    return 1;

        // In case the header until and including 'PE' is missing
        //MachineProbe = (WORD*)Buffer;
        //pNtHeader = NULL;
        //while ((PUCHAR)MachineProbe < PE_HEADER_LIMIT)
        //{
        //    if (*MachineProbe == IMAGE_FILE_MACHINE_I386 || *MachineProbe == IMAGE_FILE_MACHINE_AMD64)
        //    {
        //        if ((PUCHAR)MachineProbe >= (PUCHAR)pDosHeader + 4 && (PUCHAR)MachineProbe < (PUCHAR)pDosHeader + DOS_HEADER_LIMIT)
        //        {
        //            pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)MachineProbe - 4);
        //            break;
        //        }
        //    }
        //    MachineProbe += sizeof(WORD);
        //}

        if (pNtHeader && TestPERequirements(pNtHeader))
            return 1;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return -1;
    }

    return 0;
}

//**************************************************************************************
int ScanForDisguisedPE(LPVOID Buffer, SIZE_T Size, LPVOID* Offset)
//**************************************************************************************
{
    SIZE_T p;
    int RetVal;
    BOOL PEDetected;

    if (Size == 0)
    {
        DoOutputDebugString("ScanForDisguisedPE: Error, zero size given\n");
        return 0;
    }

    PEDetected = FALSE;

    // we want to stop short of the max look-ahead in IsDisguisedPEHeader
    for (p=0; p < Size - PE_HEADER_LIMIT; p += PE_HEADER_LIMIT)
    {
        RetVal = IsDisguisedPEHeader((PVOID)((BYTE*)Buffer+p));

        if (!RetVal)
            continue;
        else if (RetVal == -1)
        {
            DoOutputDebugString("ScanForDisguisedPE: Exception occured scanning buffer at 0x%x\n", (BYTE*)Buffer+p);
            return 0;
        }

        if (Offset)
            *Offset = (PVOID)((BYTE*)Buffer+p);

        DoOutputDebugString("ScanForDisguisedPE: PE image located at: 0x%x\n", (BYTE*)Buffer+p);

        return 1;
    }

    DoOutputDebugString("ScanForDisguisedPE: No PE image located in range 0x%x-0x%x.\n", Buffer, (DWORD_PTR)Buffer + Size);

    return 0;
}

//**************************************************************************************
DWORD GetEntryPoint(LPVOID Address)
//**************************************************************************************
{
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader = NULL;

    if (!Address)
    {
        DoOutputDebugString("GetEntryPoint: Error - no address supplied.\n");
        return 0;
    }

    if (IsDisguisedPEHeader(Address) <= 0)
        return 0;

    pDosHeader = (PIMAGE_DOS_HEADER)Address;

    __try
    {
        if (pDosHeader->e_lfanew && (ULONG)pDosHeader->e_lfanew < PE_HEADER_LIMIT && ((ULONG)pDosHeader->e_lfanew & 3) == 0)
            pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + (ULONG)pDosHeader->e_lfanew);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DoOutputDebugString("GetEntryPoint: Exception occured attempting to follow e_lfanew 0x%x\n", pDosHeader->e_lfanew);
        return 0;
    }

    if (pNtHeader && TestPERequirements(pNtHeader))
        return pNtHeader->OptionalHeader.AddressOfEntryPoint;

    return 0;
}

//**************************************************************************************
BOOL DumpStackRegion(void)
//**************************************************************************************
{
    SIZE_T StackSize = (SIZE_T)(get_stack_top() - get_stack_bottom());
    CapeMetaData->DumpType = STACK_REGION;
    CapeMetaData->Address = (PVOID)get_stack_bottom();
    return DumpMemory((PVOID)get_stack_bottom(), StackSize);
}

//**************************************************************************************
BOOL DumpPEsInRange(LPVOID Buffer, SIZE_T Size)
//**************************************************************************************
{
    BOOL RetVal = FALSE;
    LPVOID PEPointer = Buffer;
    SIZE_T Count = 0;

    DoOutputDebugString("DumpPEsInRange: Scanning range 0x%x - 0x%x.\n", Buffer, (BYTE*)Buffer + Size);

    while (ScanForDisguisedPE(PEPointer, Size - ((DWORD_PTR)PEPointer - (DWORD_PTR)Buffer), &PEPointer))
    {
        RetVal = DumpImageInCurrentProcess(PEPointer);
        if (!RetVal)
            break;
        Count++;
        (BYTE*)PEPointer += 0x1000;
    }

    if (Count)
        return TRUE;

    return FALSE;
}

//**************************************************************************************
int DumpMemory(LPVOID Buffer, SIZE_T Size)
//**************************************************************************************
{
    char *FullPathName;
    DWORD dwBytesWritten;
    HANDLE hOutputFile;
    LPVOID BufferCopy;

    FullPathName = GetName();

    hOutputFile = CreateFile(FullPathName, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hOutputFile == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_EXISTS)
    {
        DoOutputDebugString("DumpMemory: CAPE output filename exists already: %s", FullPathName);
        free(FullPathName);
        return 0;
    }

    if (hOutputFile == INVALID_HANDLE_VALUE)
    {
        DoOutputErrorString("DumpMemory: Could not create CAPE output file");
        free(FullPathName);
        return 0;
    }

    dwBytesWritten = 0;

    Size = (SIZE_T)ReverseScanForNonZero(Buffer, Size);

    if (!Size)
    {
        DoOutputDebugString("DumpMemory: Nothing to dump at 0x%p!\n", Buffer);
        free(FullPathName);
        return 0;
    }

    BufferCopy = (LPVOID)((BYTE*)malloc(Size));

    if (BufferCopy == NULL)
    {
        DoOutputDebugString("DumpMemory: Failed to allocate 0x%x bytes for buffer copy.\n", Size);
        return FALSE;
    }

    __try
    {
        memcpy(BufferCopy, Buffer, Size);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DoOutputDebugString("DumpMemory: Exception occured reading memory address 0x%x\n", Buffer);
        return 0;
    }

    if (FALSE == WriteFile(hOutputFile, BufferCopy, (DWORD)Size, &dwBytesWritten, NULL))
    {
        DoOutputErrorString("DumpMemory: WriteFile error on CAPE output file");
        free(FullPathName);
        free(BufferCopy);
        return 0;
    }

    CloseHandle(hOutputFile);

    CapeMetaData->Address = Buffer;
    CapeMetaData->Size = Size;

    CapeOutputFile(FullPathName);

    DoOutputDebugString("DumpMemory: CAPE output file successfully created: %s (size 0x%x)", FullPathName, Size);
    // We can free the filename buffers
    free(FullPathName);
    free(BufferCopy);

    return 1;
}

//**************************************************************************************
BOOL DumpRegion(PVOID Address)
//**************************************************************************************
{
    MEMORY_BASIC_INFORMATION MemInfo;
    PVOID OriginalAllocationBase, OriginalBaseAddress, AddressOfPage;
    SIZE_T AllocationSize, OriginalRegionSize;

    if (!SystemInfo.dwPageSize)
        GetSystemInfo(&SystemInfo);

    if (!SystemInfo.dwPageSize)
    {
        DoOutputErrorString("DumpRegion: Failed to obtain system page size.\n");
        return 0;
    }

    if (!VirtualQuery(Address, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
    {
        DoOutputErrorString("DumpRegion: unable to query memory address 0x%x", Address);
        return 0;
    }

    OriginalAllocationBase = MemInfo.AllocationBase;
    OriginalBaseAddress = MemInfo.BaseAddress;
    OriginalRegionSize = MemInfo.RegionSize;
    AddressOfPage = OriginalAllocationBase;

    while (MemInfo.AllocationBase == OriginalAllocationBase)
    {
        (PUCHAR)AddressOfPage += SystemInfo.dwPageSize;

        if (!VirtualQuery(AddressOfPage, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
        {
            DoOutputErrorString("DumpRegion: unable to query memory page 0x%x", AddressOfPage);
            return 0;
        }
    }

    AllocationSize = (SIZE_T)((DWORD_PTR)AddressOfPage - (DWORD_PTR)OriginalAllocationBase);

    SetCapeMetaData(UNPACKED_SHELLCODE, 0, NULL, (PVOID)OriginalAllocationBase);

    if (DumpMemory(OriginalAllocationBase, AllocationSize))
    {
        if (address_is_in_stack(OriginalAllocationBase))
            DoOutputDebugString("DumpRegion: Dumped stack region from 0x%p, size 0x%x.\n", OriginalAllocationBase, AllocationSize);
        else
            DoOutputDebugString("DumpRegion: Dumped entire allocation from 0x%p, size 0x%x.\n", OriginalAllocationBase, AllocationSize);
        return TRUE;
    }
    else
    {
        DoOutputDebugString("DumpRegion: Failed to dump entire allocation from 0x%p size 0x%x.\n", OriginalAllocationBase, AllocationSize);

        SetCapeMetaData(UNPACKED_PE, 0, NULL, (PVOID)OriginalBaseAddress);

        if (DumpPEsInRange(OriginalBaseAddress, OriginalRegionSize))
        {
            DoOutputDebugString("DumpRegion: Dumped PE image(s) from base address 0x%p, size 0x%x.\n", OriginalBaseAddress, OriginalRegionSize);
            return TRUE;
        }

        SetCapeMetaData(UNPACKED_SHELLCODE, 0, NULL, (PVOID)OriginalBaseAddress);

        if (DumpMemory(OriginalBaseAddress, OriginalRegionSize))
        {
            if (address_is_in_stack(OriginalBaseAddress))
                DoOutputDebugString("DumpRegion: Dumped stack region from 0x%p, size 0x%x.\n", OriginalBaseAddress, OriginalRegionSize);
            else
                DoOutputDebugString("DumpRegion: Dumped base address 0x%p, size 0x%x.\n", OriginalBaseAddress, OriginalRegionSize);
                return TRUE;
        }
        else
        {
            DoOutputDebugString("DumpRegion: Failed to dump base address 0x%p size 0x%x.\n", OriginalBaseAddress, OriginalRegionSize);
            return FALSE;
        }
    }
}

//**************************************************************************************
int DumpImageInCurrentProcessFixImports(LPVOID BaseAddress, LPVOID NewEP)
//**************************************************************************************
{
    if (DumpCount < DUMP_MAX && ScyllaDumpImageInCurrentProcessFixImports((DWORD_PTR)BaseAddress, (DWORD_PTR)NewEP))
    {
        DumpCount++;
        return 1;
    }

    return 0;
}

//**************************************************************************************
int DumpCurrentProcessFixImports(LPVOID NewEP)
//**************************************************************************************
{
    if (DumpCount < DUMP_MAX && ScyllaDumpCurrentProcessFixImports((DWORD_PTR)NewEP))
    {
        DumpCount++;
        return 1;
    }

    return 0;
}

//**************************************************************************************
int DumpCurrentProcessNewEP(LPVOID NewEP)
//**************************************************************************************
{
    if (DumpCount < DUMP_MAX && ScyllaDumpCurrentProcess((DWORD_PTR)NewEP))
    {
        DumpCount++;
        return 1;
    }

    return 0;
}

//**************************************************************************************
int DumpCurrentProcess()
//**************************************************************************************
{
    if (DumpCount < DUMP_MAX && ScyllaDumpCurrentProcess(0))
    {
        DumpCount++;
        return 1;
    }

    return 0;
}

//**************************************************************************************
int DumpImageInCurrentProcess(LPVOID BaseAddress)
//**************************************************************************************
{
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    PVOID FirstPage = NULL;
    DWORD dwProtect = 0;
    int RetVal = 0;

    pDosHeader = (PIMAGE_DOS_HEADER)BaseAddress;

    if (DumpCount >= DUMP_MAX)
    {
        DoOutputDebugString("DumpImageInCurrentProcess: CAPE dump limit reached.\n");
        return 0;
    }

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || (*(DWORD*)((BYTE*)pDosHeader + pDosHeader->e_lfanew) != IMAGE_NT_SIGNATURE))
    {
        // We want to fix the PE header in the dump (for e.g. disassembly etc)
        if (!SystemInfo.dwPageSize)
            GetSystemInfo(&SystemInfo);

        if (!SystemInfo.dwPageSize)
        {
            DoOutputErrorString("DumpImageInCurrentProcess: Failed to obtain system page size.\n");
            return 0;
        }

        FirstPage = calloc(SystemInfo.dwPageSize, sizeof(char));

        if (!FirstPage)
        {
            DoOutputErrorString("DumpImageInCurrentProcess: Failed to allocate memory page for PE header.\n");
            return 0;
        }

        __try
        {
            memcpy(FirstPage, BaseAddress, SystemInfo.dwPageSize);
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            DoOutputDebugString("DumpImageInCurrentProcess: Exception occured copying PE header at 0x%p\n", BaseAddress);
            free(FirstPage);
            return 0;
        }

        // Set target image page permissions to allow writing of new headers
        if (!VirtualProtect((BYTE*)BaseAddress, SystemInfo.dwPageSize, PAGE_EXECUTE_READWRITE, &dwProtect))
        {
            DoOutputErrorString("DumpImageInCurrentProcess: Failed to modify memory page protection of NtHeader");
            free(FirstPage);
            return 0;
        }

        pDosHeader = (PIMAGE_DOS_HEADER)(BaseAddress);

        DoOutputDebugString("DumpImageInCurrentProcess: Disguised PE image (bad MZ and/or PE headers) at 0x%p\n", BaseAddress);

        if (!pDosHeader->e_lfanew)
        {
            // In case the header until and including 'PE' has been zeroed
            WORD* MachineProbe = (WORD*)&pDosHeader->e_lfanew;
            while ((PUCHAR)MachineProbe < (PUCHAR)pDosHeader + (PE_HEADER_LIMIT - offsetof(IMAGE_DOS_HEADER, e_lfanew)))
            {
                if (*MachineProbe == IMAGE_FILE_MACHINE_I386 || *MachineProbe == IMAGE_FILE_MACHINE_AMD64)
                {
                    if ((PUCHAR)MachineProbe > (PUCHAR)pDosHeader + 3)
                        pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)MachineProbe - 4);
                }
                MachineProbe += sizeof(WORD);
            }

            if (pNtHeader)
                pDosHeader->e_lfanew = (LONG)((PUCHAR)pNtHeader - (PUCHAR)pDosHeader);
        }

        if (!pDosHeader->e_lfanew)
        {
            // In case the header until and including 'PE' is missing
            pNtHeader = NULL;
            WORD* MachineProbe = (WORD*)pDosHeader;
            while ((PUCHAR)MachineProbe < (PUCHAR)pDosHeader + (PE_HEADER_LIMIT - offsetof(IMAGE_DOS_HEADER, e_lfanew)))
            {
                if (*MachineProbe == IMAGE_FILE_MACHINE_I386 || *MachineProbe == IMAGE_FILE_MACHINE_AMD64)
                {
                    if ((PUCHAR)MachineProbe >= (PUCHAR)pDosHeader + 4)
                    {
                        pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)MachineProbe - 4);
                        //break;
                    }
                }
                MachineProbe += sizeof(WORD);

                if (pNtHeader && (PUCHAR)pNtHeader == (PUCHAR)pDosHeader && pNtHeader->OptionalHeader.SizeOfHeaders)
                {
                    __try
                    {
                        SIZE_T HeaderShift = sizeof(IMAGE_DOS_HEADER);
                        memmove((PBYTE)BaseAddress + HeaderShift, BaseAddress, pNtHeader->OptionalHeader.SizeOfHeaders - HeaderShift);
                        memset(BaseAddress, 0, HeaderShift);
                        pDosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
                        pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)BaseAddress + HeaderShift);
                        pDosHeader->e_lfanew = (LONG)((PUCHAR)pNtHeader - (PUCHAR)pDosHeader);
                        DoOutputDebugString("DumpImageInCurrentProcess: pNtHeader moved from 0x%x to 0x%x, e_lfanew 0x%x\n", pDosHeader, pNtHeader, pDosHeader->e_lfanew);
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        DoOutputDebugString("DumpImageInCurrentProcess: Exception occured moving NtHeader from 0x%x to 0x%x, e_lfanew 0x%x\n", pDosHeader, pNtHeader, pDosHeader->e_lfanew);
                        goto end;
                    }
                }
            }
        }

        if (!pDosHeader->e_lfanew || pDosHeader->e_lfanew > PE_MAX_SIZE)
        {
            DoOutputDebugString("DumpImageInCurrentProcess: Bad e_lfanew 0x%x\n", pDosHeader->e_lfanew);
            goto end;
        }

        __try
        {
            *(WORD*)pDosHeader = IMAGE_DOS_SIGNATURE;
            *(DWORD*)((PUCHAR)pDosHeader + pDosHeader->e_lfanew) = IMAGE_NT_SIGNATURE;
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            DoOutputDebugString("DumpImageInCurrentProcess: Exception occured writing PE signatures in region at 0x%p, dumping entire memory region.\n", pDosHeader);
            goto end;
        }
    }

    if (IsPeImageVirtual(BaseAddress) == FALSE)
    {
        DoOutputDebugString("DumpImageInCurrentProcess: Attempting to dump 'raw' PE image.\n");

        if (!ScyllaDumpPE((DWORD_PTR)BaseAddress))
            DoOutputDebugString("DumpImageInCurrentProcess: Failed to dump 'raw' PE image from 0x%p, dumping memory region.\n", BaseAddress);
        else
            RetVal = 1;
    }
    else
    {
        DoOutputDebugString("DumpImageInCurrentProcess: Attempting to dump virtual PE image.\n");

        if (!ScyllaDumpProcess(GetCurrentProcess(), (DWORD_PTR)BaseAddress, 0))
            DoOutputDebugString("DumpImageInCurrentProcess: Failed to dump virtual PE image from 0x%p, dumping memory region.\n", BaseAddress);
        else
            RetVal = 1;
    }

end:
    if (FirstPage)
    {
        // Copy the original headers back
        __try
        {
            memcpy(BaseAddress, FirstPage, SystemInfo.dwPageSize);
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            DoOutputDebugString("DumpImageInCurrentProcess: Exception occured restoring PE header at 0x%p\n", BaseAddress);
            return 0;
        }

        // Restore original protection
        if (!VirtualProtect((BYTE*)BaseAddress, SystemInfo.dwPageSize, dwProtect, &dwProtect))
            DoOutputErrorString("DumpImageInCurrentProcess: Failed to restore previous memory page protection");

        free(FirstPage);
    }

    if (RetVal)
        DumpCount++;

    return RetVal;
}

//**************************************************************************************
unsigned int DumpImageToFileHandle(LPVOID BaseAddress, HANDLE FileHandle)
//**************************************************************************************
{
    unsigned int BytesWritten;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;

    pDosHeader = (PIMAGE_DOS_HEADER)BaseAddress;

    if (DumpCount >= DUMP_MAX)
    {
        DoOutputDebugString("DumpImageToFileHandle: CAPE dump limit reached.\n");
        return 0;
    }

    if (*(WORD*)BaseAddress != IMAGE_DOS_SIGNATURE)
    {
        DoOutputDebugString("DumpImageToFileHandle: No DOS signature in header.\n");
        return 0;
    }

    if (!pDosHeader->e_lfanew || pDosHeader->e_lfanew > PE_HEADER_LIMIT)
    {
        DoOutputDebugString("DumpImageToFileHandle: bad e_lfanew.\n");
        return 0;
    }

    pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + (ULONG)pDosHeader->e_lfanew);

    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        // No 'PE' header
        DoOutputDebugString("DumpImageToFileHandle: Invalid PE signature in header.\n");
        return 0;
    }

    if ((pNtHeader->FileHeader.Machine == 0) || (pNtHeader->FileHeader.SizeOfOptionalHeader == 0 || pNtHeader->OptionalHeader.SizeOfHeaders == 0))
    {
        // Basic requirements
        DoOutputDebugString("DumpImageToFileHandle: PE image invalid.\n");
        return 0;
    }

    if (IsPeImageVirtual(BaseAddress) == FALSE)
    {
        DoOutputDebugString("DumpImageToFileHandle: Attempting to dump 'raw' PE image.\n");

        if (ScyllaDumpPEToFileHandle((DWORD_PTR)BaseAddress, FileHandle))
        {
            DumpCount++;
            return 1;
        }
        else
        {
            // failed to dump pe image
            DoOutputDebugString("DumpImageToFileHandle: Failed to dump 'raw' PE image.\n");
            return 0;
        }
    }

    DoOutputDebugString("DumpImageToFileHandle: Attempting to dump virtual PE image.\n");

    BytesWritten = ScyllaDumpProcessToFileHandle(GetCurrentProcess(), (DWORD_PTR)BaseAddress, 0, FileHandle);

    if (!BytesWritten)
    {
        DoOutputDebugString("DumpImageToFileHandle: Failed to dump PE as virtual image.\n");
        return 0;
    }

    DumpCount++;
    return 1;
}

//**************************************************************************************
int DumpProcess(HANDLE hProcess, LPVOID BaseAddress, LPVOID NewEP)
//**************************************************************************************
{
    if (DumpCount < DUMP_MAX && ScyllaDumpProcess(hProcess, (DWORD_PTR)BaseAddress, (DWORD_PTR)NewEP))
    {
        DumpCount++;
        return 1;
    }

    return 0;
}

//**************************************************************************************
int DumpPE(LPVOID Buffer)
//**************************************************************************************
{
    if (DumpCount < DUMP_MAX && ScyllaDumpPE((DWORD_PTR)Buffer))
    {
        DumpCount++;
        return 1;
    }

    return 0;
}

//**************************************************************************************
void DumpInterestingRegions(MEMORY_BASIC_INFORMATION MemInfo)
//**************************************************************************************
{
    if (!MemInfo.BaseAddress)
        return;

    if (MemInfo.BaseAddress == (PVOID)g_our_dll_base)
        return;

    __try
    {
        BYTE Test = *(BYTE*)MemInfo.BaseAddress;
        Test = *(BYTE*)MemInfo.BaseAddress + PE_HEADER_LIMIT;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        // No point in continuing if we can't read!
        return;
    }

    if (IsDotNetImage(MemInfo.BaseAddress))
    {
        DoOutputDebugString("DumpInterestingRegions: Dumping .NET image at 0x%p.\n", MemInfo.BaseAddress);

        CapeMetaData->ModulePath = NULL;
        CapeMetaData->DumpType = UNPACKED_PE;
        CapeMetaData->Address = MemInfo.BaseAddress;

        DumpImageInCurrentProcess(MemInfo.BaseAddress);
    }
}

//**************************************************************************************
int DoProcessDump(PVOID CallerBase)
//**************************************************************************************
{
    PUCHAR Address;
    MEMORY_BASIC_INFORMATION MemInfo;
    HANDLE FileHandle;
    char *FullDumpPath, *OutputFilename;
    PVOID NewImageBase;

    PHANDLE SuspendedThreads = (PHANDLE)malloc(SUSPENDED_THREAD_MAX*sizeof(HANDLE));
    DWORD ThreadId = GetCurrentThreadId(), SuspendedThreadCount = 0;

    if (!SystemInfo.dwPageSize)
        GetSystemInfo(&SystemInfo);

    if (!SystemInfo.dwPageSize)
    {
        DoOutputErrorString("DoProcessDump: Failed to obtain system page size.\n");
        goto out;
    }

    if (base_of_dll_of_interest)
    {
        NewImageBase = (PVOID)base_of_dll_of_interest;
        if (ImageBase && ImageBase == NewImageBase)
            NewImageBase = NULL;
    }
    else
    {
        NewImageBase = GetModuleHandle(NULL);
        if (ImageBase && ImageBase == NewImageBase)
            NewImageBase = NULL;
    }

    // First: 'main' process dumps
    if (g_config.procdump)
    {
        if (VirtualQuery(ImageBase, &MemInfo, sizeof(MemInfo)))
        {
            DoOutputDebugString("DoProcessDump: Dumping Imagebase at 0x%p.\n", MemInfo.BaseAddress);

            CapeMetaData->DumpType = PROCDUMP;
            __try
            {
                if (g_config.import_reconstruction)
                    ProcessDumped = ScyllaDumpProcessFixImports(GetCurrentProcess(), (DWORD_PTR)MemInfo.BaseAddress, 0);
                else
                    ProcessDumped = DumpImageInCurrentProcess(MemInfo.BaseAddress);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                DoOutputDebugString("DoProcessDump: Failed to dump main process image at 0x%p.\n", MemInfo.BaseAddress);
                goto out;
            }
        }

        if (NewImageBase && VirtualQuery(NewImageBase, &MemInfo, sizeof(MemInfo)))
        {
            DoOutputDebugString("DoProcessDump: Dumping 'new' Imagebase at 0x%p.\n", NewImageBase);

            CapeMetaData->DumpType = PROCDUMP;
            __try
            {
                if (g_config.import_reconstruction)
                    ProcessDumped = ScyllaDumpProcessFixImports(GetCurrentProcess(), (DWORD_PTR)NewImageBase, 0);
                else
                    ProcessDumped = DumpImageInCurrentProcess(NewImageBase);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                DoOutputDebugString("DoProcessDump: Failed to dump 'new' process image base at 0x%p.\n", NewImageBase);
                goto out;
            }
        }
    }

    // For full-memory dumps, creat the output file
    if (g_config.procmemdump)
    {
        FullDumpPath = GetResultsPath("memory");

        if (!FullDumpPath)
        {
            DoOutputDebugString("DoProcessDump: Unable to get path to dump file directory.\n");
            goto out;
        }

        OutputFilename = (char*)malloc(MAX_PATH);

        sprintf_s(OutputFilename, MAX_PATH, "%d.dmp", CapeMetaData->Pid);

        PathAppend(FullDumpPath, OutputFilename);

        FileHandle = CreateFile(FullDumpPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

        if (FileHandle == INVALID_HANDLE_VALUE)
        {
            DoOutputDebugString("DoProcessDump: Unable to create dump file for full process memory dump.\n");
            goto out;
        }

        DoOutputDebugString("DoProcessDump: Created dump file for full process memory dump: %s.\n", FullDumpPath);
    }

    if (!g_config.procdump && !g_config.procmemdump)
        return ProcessDumped;

    // Scan entire user-mode space for both full dump and 'interesting' regions
    for (Address = (PUCHAR)SystemInfo.lpMinimumApplicationAddress; Address < (PUCHAR)SystemInfo.lpMaximumApplicationAddress;)
    {
        if (!VirtualQuery(Address, &MemInfo, sizeof(MemInfo)))
        {
            Address += SystemInfo.dwPageSize;
            continue;
        }

        if (!(MemInfo.State & MEM_COMMIT) || !(MemInfo.Type & (MEM_IMAGE | MEM_MAPPED | MEM_PRIVATE)))
        {
            Address += MemInfo.RegionSize;
            continue;
        }

        //if (g_config.procdump && MemInfo.BaseAddress != ImageBase && MemInfo.BaseAddress != NewImageBase)
        //    DumpInterestingRegions(MemInfo);

        if (g_config.procmemdump)
        {
            LARGE_INTEGER BufferAddress;
            DWORD BytesWritten;
            PVOID TempBuffer;

            BufferAddress.QuadPart = (ULONGLONG)Address;
            TempBuffer = malloc(MemInfo.RegionSize);
            if (!TempBuffer)
            {
                DoOutputDebugString("DoProcessDump: Error allocating memory for copy of region at 0x%p, size 0x%x.\n", MemInfo.BaseAddress, MemInfo.RegionSize);
                goto out;
            }
            __try
            {
                memcpy(TempBuffer, MemInfo.BaseAddress, MemInfo.RegionSize);
                WriteFile(FileHandle, &BufferAddress, sizeof(BufferAddress), &BytesWritten, NULL);
                WriteFile(FileHandle, &(DWORD)MemInfo.RegionSize, sizeof(DWORD), &BytesWritten, NULL);
                WriteFile(FileHandle, &MemInfo.State, sizeof(MemInfo.State), &BytesWritten, NULL);
                WriteFile(FileHandle, &MemInfo.Type, sizeof(MemInfo.Type), &BytesWritten, NULL);
                WriteFile(FileHandle, &MemInfo.Protect, sizeof(MemInfo.Protect), &BytesWritten, NULL);
                WriteFile(FileHandle, TempBuffer, (DWORD)MemInfo.RegionSize, &BytesWritten, NULL);
                free(TempBuffer);
#ifdef DEBUG_COMMENTS
                if (BytesWritten != MemInfo.RegionSize)
                    DoOutputDebugString("DoProcessDump: Anomaly detected, wrote only 0x%x of 0x%x bytes to memory dump from region 0x%p.\n", BytesWritten, MemInfo.RegionSize, MemInfo.BaseAddress);
                else
                    DoOutputDebugString("DoProcessDump: Added 0x%x byte region at 0x%p to memory dump (protect 0x%x).\n", MemInfo.RegionSize, MemInfo.BaseAddress, MemInfo.Protect);
#endif
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                free(TempBuffer);
#ifdef DEBUG_COMMENTS
                DoOutputDebugString("DoProcessDump: Exception attempting to dump region at 0x%p, size 0x%x.\n", MemInfo.BaseAddress, MemInfo.RegionSize);
#endif
            }
        }

        Address += MemInfo.RegionSize;
    }

out:
    if (g_config.procmemdump)
    {
        if (FileHandle)
        {
            DoOutputDebugString("DoProcessDump: Full process memory dump saved to file: %s.\n", FullDumpPath);
            CloseHandle(FileHandle);
            DoOutputFile(FullDumpPath);
        }
        if (OutputFilename)
            free(OutputFilename);
        if (FullDumpPath)
            free(FullDumpPath);
    }

    return ProcessDumped;
}

void RestoreHeaders()
{
    DWORD ImportsRVA, ImportsSize, SizeOfHeaders, dwProtect;
    PVOID BaseAddress, ImportsVA;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeaders;

    BaseAddress = GetModuleHandle(NULL);
    SizeOfHeaders = sizeof(IMAGE_NT_HEADERS);
    pDosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
    pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)BaseAddress + pDosHeader->e_lfanew);
    ImportsRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    ImportsSize = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    ImportsVA = (PBYTE)BaseAddress + ImportsRVA;

    // Check if we have a PE header after import table
    if (*(DWORD*)((PBYTE)ImportsVA + ImportsSize) != IMAGE_NT_SIGNATURE)
        return;

    // Set page permissions to allow writing of original headers
    if (!VirtualProtect((PBYTE)BaseAddress, SizeOfHeaders, PAGE_EXECUTE_READWRITE, &dwProtect))
    {
        DoOutputErrorString("RestoreHeaders: Failed to modify memory page protection of NtHeaders");
        return;
    }

    memcpy((PBYTE)BaseAddress + pDosHeader->e_lfanew, (PBYTE)ImportsVA + ImportsSize, SizeOfHeaders);

    // Restore original protection
    if (!VirtualProtect((PBYTE)BaseAddress, SizeOfHeaders, dwProtect, &dwProtect))
    {
        DoOutputErrorString("RestoreHeaders: Failed to restore previous memory page protection");
        return;
    }

    // Free memory
    if (!VirtualFree(ImportsVA, 0, MEM_RELEASE))
    {
        DoOutputErrorString("RestoreHeaders: Failed to free memory for patched IAT");
        return;
    }

    DoOutputDebugString("RestoreHeaders: Restored original import table.\n");
}

void CAPE_post_init()
{
#ifdef CAPE_NIRVANA
    if (g_config.nirvana)
        NirvanaInit{);
#endif

    if (g_config.debugger && !g_config.base_on_apiname[0])
        SetInitialBreakpoints(GetModuleHandle(NULL));

    if (g_config.unpacker)
        UnpackerInit();

    if (g_config.plugx)
        PlugXConfigDumped = FALSE;

    if (g_config.upx)
    {
        CapeMetaData->DumpType = UPX;
        g_config.procdump = 0;
        if (InitialiseDebugger())
            DoOutputDebugString("UPX unpacker: Debugger initialised.\n");
        else
            DoOutputDebugString("UPX unpacker: Failed to initialise debugger.\n");
        UPXInitialBreakpoints(GetModuleHandle(NULL));
    }

    lookup_add(&g_caller_regions, (ULONG_PTR)GetModuleHandle(NULL), 0);
    lookup_add(&g_caller_regions, (ULONG_PTR)g_our_dll_base, 0);
}

void CAPE_init()
{
    char *Character;

    // Restore headers in case of IAT patching
    RestoreHeaders();

    // Initialise CAPE global variables
    //
    //if (!g_config.standalone)
    CapeMetaData = (PCAPEMETADATA)malloc(sizeof(CAPEMETADATA));
    CapeMetaData->Pid = GetCurrentProcessId();
    CapeMetaData->ProcessPath = (char*)malloc(MAX_PATH);
    WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, (LPCWSTR)our_process_path_w, (int)wcslen(our_process_path_w)+1, CapeMetaData->ProcessPath, MAX_PATH, NULL, NULL);
    Character = CapeMetaData->ProcessPath;

    // It seems with CP_ACP or CP_UTF8 & WC_NO_BEST_FIT_CHARS, WideCharToMultiByte still
    // leaves characters that encode("utf-8"... can't encode...
    while (*Character)
    {   // Restrict to ASCII range
        if (*Character < 0x0a || *Character > 0x7E)
            *Character = 0x3F;  // '?'
        Character++;
    }

    CommandLine = (char*)malloc(MAX_PATH);
    WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, (LPCWSTR)our_commandline, (int)wcslen(our_commandline)+1, CommandLine, MAX_PATH, NULL, NULL);

    // This is package (and technique) dependent:
    CapeMetaData->DumpType = PROCDUMP;
    ProcessDumped = FALSE;

    DumpCount = 0;

    // Cuckoo debug output level for development (0=none, 2=max)
    // g_config.debug = 2;

    if (base_of_dll_of_interest)
        ImageBase = (PVOID)base_of_dll_of_interest;
    else
        ImageBase = GetModuleHandle(NULL);
#ifdef _WIN64
    DoOutputDebugString("CAPE initialised: 64-bit monitor loaded in process %d at 0x%p, image base 0x%p, stack from 0x%p-0x%p\n", CapeMetaData->Pid, g_our_dll_base, ImageBase, get_stack_bottom(), get_stack_top());
#else
    DoOutputDebugString("CAPE initialised: 32-bit monitor loaded in process %d at 0x%x, image base 0x%x, stack from 0x%x-0x%x\n", CapeMetaData->Pid, g_our_dll_base, ImageBase, get_stack_bottom(), get_stack_top());
#endif

    DoOutputDebugString("Commandline: %s.\n", CommandLine);

    return;
}
