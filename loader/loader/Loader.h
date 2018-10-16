/*
CAPE - Config And Payload Extraction
Copyright(C) 2015 - 2018 Context Information Security. (kevin.oreilly@contextis.com)

This program is free software : you can redistribute it and / or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.If not, see <http://www.gnu.org/licenses/>.
*/
#define _CRT_SECURE_NO_WARNINGS 1
#include <Windows.h>
#include <stdio.h>

#define BOUND_DIRECTORY OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]
#define IAT_DIRECTORY OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT]
#define IMPORT_DIRECTORY OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

#define BUFSIZE 512
#define PIPEBUFSIZE 16384

#ifndef _WIN64
#define DWORD_XX DWORD32
#define IMAGE_ORDINAL_FLAG_XX IMAGE_ORDINAL_FLAG32
#define IMAGE_THUNK_DATAXX IMAGE_THUNK_DATA32
#define PIMAGE_THUNK_DATAXX PIMAGE_THUNK_DATA32
#else
#define DWORD_XX DWORD64
#define IMAGE_ORDINAL_FLAG_XX IMAGE_ORDINAL_FLAG64
#define IMAGE_THUNK_DATAXX IMAGE_THUNK_DATA64
#define PIMAGE_THUNK_DATAXX PIMAGE_THUNK_DATA64
#endif

typedef struct _LSA_UNICODE_STRING 
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

typedef struct _PROCESS_BASIC_INFORMATION 
{
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
	ULONG_PTR ParentProcessId;
} PROCESS_BASIC_INFORMATION;

typedef struct _PEB_LDR_DATA 
{
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS 
{
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef void (NTAPI *PPS_POST_PROCESS_INIT_ROUTINE) 
(
    void
);

typedef struct _PEB 
{
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BOOLEAN Spare;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    BYTE Reserved4[104];
    PVOID Reserved5[52];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved6[128];
    PVOID Reserved7[1];
    ULONG SessionId;
} PEB, *PPEB;

typedef struct _TEB 
{
    NT_TIB NtTib;
    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;
    ULONG LastErrorValue;
// truncated
} TEB, *PTEB;

typedef NTSTATUS(WINAPI * _NtQuerySystemInformation)
(
	_In_ ULONG SystemInformationClass,
	_Inout_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
);

typedef NTSTATUS(WINAPI * _NtContinue)
(
    void
);

typedef LONG(WINAPI *_NtQueryInformationProcess)(HANDLE ProcessHandle,
    ULONG ProcessInformationClass, PVOID ProcessInformation,
    ULONG ProcessInformationLength, PULONG ReturnLength);

typedef NTSTATUS (NTAPI *_RtlCreateUserThread)
(
    HANDLE, 
    PSECURITY_DESCRIPTOR, 
    BOOLEAN, 
    ULONG, 
    PULONG, 
    PULONG, 
    PVOID, 
    PVOID, 
    PHANDLE, 
    PVOID
);

typedef HRESULT (WINAPI *PDLLREGRSRV)(void);
typedef void (cdecl *PSHELLCODE)(void);

enum 
{
	ERROR_INVALID_PARAM = -1,
	ERROR_PROCESS_OPEN = -2,
	ERROR_THREAD_OPEN = -3,
	ERROR_ALLOCATE = -4,
	ERROR_WRITEMEMORY = -5,
	ERROR_QUEUEUSERAPC = -6,
	ERROR_CREATEREMOTETHREAD = -7,
	ERROR_RTLCREATEUSERTHREAD = -8,
	ERROR_INJECTMODE = -9,
	ERROR_MODE = -10,
	ERROR_DEBUGPRIV = -11,
	ERROR_ARGCOUNT = -12,
	ERROR_FILE_OPEN = -13,
	ERROR_DLL_PATH = -14,
	ERROR_READMEMORY = -15
};

typedef struct _LoadLibraryThread {
    FARPROC LoadLibrary;
    FARPROC GetLastError;
    PCHAR DllPath;
} LoadLibraryThread;

SYSTEM_INFO SystemInfo;
