// Copyright 2014-2015 Optiv, Inc. (brad.spengler@optiv.com)
// This file is published under the GNU GPL v3
// http://www.gnu.org/licenses/gpl.html

#define _CRT_SECURE_NO_WARNINGS 1
#include <Windows.h>
#include <stdio.h>

enum {
	INJECT_CREATEREMOTETHREAD,
	INJECT_QUEUEUSERAPC
};

#define SystemProcessInformation 5
#define Suspended 5
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

typedef struct _CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef LONG KPRIORITY;

typedef struct _SYSTEM_THREAD {
	LARGE_INTEGER           KernelTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           CreateTime;
	ULONG                   WaitTime;
	PVOID                   StartAddress;
	CLIENT_ID               ClientId;
	KPRIORITY               Priority;
	LONG                    BasePriority;
	ULONG                   ContextSwitchCount;
	ULONG                   State;
	ULONG                   WaitReason;
} SYSTEM_THREAD, *PSYSTEM_THREAD;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	KPRIORITY               BasePriority;
	HANDLE					UniqueProcessId;
	HANDLE					InheritedFromProcessId;
	ULONG					HandleCount;
	BYTE					Reserved4[4];
	PVOID					Reserved5[11];
	SIZE_T					PeakPagefileUsage;
	SIZE_T					PrivatePageCount;
	LARGE_INTEGER			Reserved6[6];
	SYSTEM_THREAD			Threads[0];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(WINAPI * _NtQuerySystemInformation)(
	_In_ ULONG SystemInformationClass,
	_Inout_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
);

enum {
	ERROR_INVALID_PARAM = -1,
	ERROR_PROCESS_OPEN = -2,
	ERROR_THREAD_OPEN = -3,
	ERROR_ALLOCATE = -4,
	ERROR_WRITEMEMORY = -5,
	ERROR_QUEUEUSERAPC = -6,
	ERROR_CREATEREMOTETHREAD = -7,
	ERROR_INJECTMODE = -8,
	ERROR_MODE = -9,
	ERROR_DEBUGPRIV = -10,
	ERROR_ARGCOUNT = -11,
	ERROR_FILE_OPEN = -12,
	ERROR_DLL_PATH = -13
};

typedef struct _INJECT_STRUCT {
	ULONG_PTR LdrLoadDllAddress;
	UNICODE_STRING DllName;
	HANDLE OutHandle;
} INJECT_STRUCT, *PINJECT_STRUCT;
