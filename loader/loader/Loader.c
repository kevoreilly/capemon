/*
CAPE - Config And Payload Extraction
Copyright(C) 2019-2020 Kevin O'Reilly (kevoreilly@gmail.com)

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
//#define DEBUG_COMMENTS
#include "Loader.h"
#include <tlhelp32.h>
#include <strsafe.h>
#include "Shlwapi.h"

#pragma comment(lib, "shlwapi.lib")
#pragma warning(push )
#pragma warning(disable : 4996)

#define MAX_ADDRESS	0x70000000
#define MAX_RANGE	0x10000000

SYSTEM_INFO SystemInfo;
char PipeOutput[MAX_PATH], LogPipe[MAX_PATH];
BOOL DisableIATPatching, FirstProcess;

void pipe(char* Buffer, SIZE_T Length);

void DebugOutput(_In_ LPCTSTR lpOutputString, ...)
{
	char DebugOutput[MAX_PATH];
	va_list args;
	va_start(args, lpOutputString);

	memset(DebugOutput, 0, MAX_PATH*sizeof(char));
	_vsnprintf_s(DebugOutput, MAX_PATH, _TRUNCATE, lpOutputString, args);
	OutputDebugString(DebugOutput);

	memset(PipeOutput, 0, MAX_PATH*sizeof(char));
	_snprintf_s(PipeOutput, MAX_PATH, _TRUNCATE, "DEBUG:%s", DebugOutput);
	pipe(PipeOutput, strlen(PipeOutput));

	va_end(args);

	return;
}

void ErrorOutput(_In_ LPCTSTR lpOutputString, ...)
{
	char DebugOutput[MAX_PATH], ErrorOutput[MAX_PATH];
	va_list args;
	LPVOID lpMsgBuf;
	DWORD ErrorCode;

	ErrorCode = GetLastError();
	va_start(args, lpOutputString);

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		ErrorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0,
		NULL);

	memset(DebugOutput, 0, MAX_PATH*sizeof(char));
	_vsnprintf_s(DebugOutput, MAX_PATH, _TRUNCATE, lpOutputString, args);
	memset(ErrorOutput, 0, MAX_PATH*sizeof(char));
	_snprintf_s(ErrorOutput, MAX_PATH, _TRUNCATE, "Error %d (0x%x) - %s: %s", ErrorCode, ErrorCode, DebugOutput, (char*)lpMsgBuf);
	OutputDebugString(ErrorOutput);

	memset(PipeOutput, 0, MAX_PATH*sizeof(char));
	_snprintf_s(PipeOutput, MAX_PATH, _TRUNCATE, "DEBUG:%s", ErrorOutput);
	pipe(PipeOutput, strlen(PipeOutput));

	va_end(args);

	return;
}

static __inline PVOID get_peb(void)
{
#ifndef _WIN64
	return (PVOID)__readfsdword(0x30);
#else
	return (PVOID)__readgsqword(0x60);
#endif
}

int ScanForNonZero(LPVOID Buffer, SIZE_T Size)
{
	SIZE_T p;

	if (!Buffer)
	{
		DebugOutput("ScanForNonZero: Error - Supplied address zero.\n");
		return 0;
	}

	__try
	{
		for (p=0; p<Size-1; p++)
			if (*((char*)Buffer+p) != 0)
				return 1;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DebugOutput("ScanForNonZero: Exception occured reading memory address 0x%x\n", (char*)Buffer+p);
		return 0;
	}

	return 0;
}

void pipe(char* Buffer, SIZE_T Length)
{
	DWORD BytesRead;

	if (strlen(LogPipe))
	{
		if (!CallNamedPipe(LogPipe, Buffer, (DWORD)Length, Buffer, (DWORD)Length, (unsigned long *)&BytesRead, NMPWAIT_WAIT_FOREVER))
#ifdef DEBUG_COMMENTS
			ErrorOutput("Loader: Failed to call named pipe %s", LogPipe);
#else
			;
#endif
	}

	return;
}

int CopyConfig(DWORD ProcessId, char *DllName)
{
	char config_fname[MAX_PATH], analyzer_path[MAX_PATH], system_fname[MAX_PATH];
	FILE *fp;

	// look for the config in monitor directory
	strncpy(analyzer_path, DllName, strlen(DllName));
	PathRemoveFileSpec(analyzer_path); // remove filename
	snprintf(config_fname, MAX_PATH, "%s\\%u.ini", analyzer_path, ProcessId);

	fp = fopen(config_fname, "r");

	// for debugging purposes
	if (fp == NULL) {
		memset(config_fname, 0, sizeof(config_fname));
		snprintf(config_fname, MAX_PATH, "%s\\config.ini", analyzer_path);
		fp = fopen(config_fname, "r");
		if (fp == NULL)
			return 0;
	}

	if (fp == NULL)
	{
		ErrorOutput("Loader: Failed to read config file %s", config_fname);
		return 0;
	}

	fclose(fp);

	memset(system_fname, 0, sizeof(system_fname));
	snprintf(system_fname, MAX_PATH, "C:\\%u.ini", ProcessId);
	if (!CopyFile(config_fname, system_fname, 0))
	{
		ErrorOutput("Loader: Failed to copy config file %s to system path %s", config_fname, system_fname);
		return 0;
	}

	DebugOutput("Loader: Copied config file %s to system path %s", config_fname, system_fname);

	return 1;
}

int ReadConfig(DWORD ProcessId, char *DllName)
{
	char Buffer[MAX_PATH], config_fname[MAX_PATH], analyzer_path[MAX_PATH];
	FILE *fp;
	unsigned int i;
	SIZE_T Length;

	// look for the config in monitor directory
	strncpy(analyzer_path, DllName, strlen(DllName));
	PathRemoveFileSpec(analyzer_path); // remove filename
	snprintf(config_fname, MAX_PATH, "%s\\%u.ini", analyzer_path, ProcessId);

	fp = fopen(config_fname, "r");

	// for debugging purposes
	if (fp == NULL) {
		memset(config_fname, 0, sizeof(config_fname));
		snprintf(config_fname, MAX_PATH, "%s\\config.ini", analyzer_path);
		fp = fopen(config_fname, "r");
		if (fp == NULL)
			return 0;
	}

	if (fp == NULL)
	{
		ErrorOutput("Loader: Failed to read config file %s", config_fname);
		return 0;
	}

	memset(Buffer, 0, sizeof(Buffer));

	while (fgets(Buffer, sizeof(Buffer), fp) != NULL)
	{
		// cut off the newline
		char *p = strchr(Buffer, '\r');
		if (p != NULL) *p = 0;
		p = strchr(Buffer, '\n');
		if (p != NULL) *p = 0;

		// split key=value
		p = strchr(Buffer, '=');
		if (p != NULL)
		{
			const char *key = Buffer;
			char *Value = p + 1;

			*p = 0;
			Length = strlen(Value);
			if (!strcmp(key, "pipe"))
			{
				for (i = 0; i < Length; i++)
					strncpy(LogPipe, Value, Length);
#ifdef DEBUG_COMMENTS
				DebugOutput("Loader: Successfully loaded pipe name %s.\n", LogPipe);
#endif
			}
			if (!strcmp(key, "no-iat"))
			{
				DisableIATPatching = Value[0] == '1';
				if (DisableIATPatching)
					DebugOutput("Loader: IAT patching disabled.\n");
				else
					DebugOutput("Loader: IAT patching enabled.\n");
			}
			else if (!strcmp(key, "first-process"))
				FirstProcess = Value[0] == '1';
		}
	}


	fclose(fp);

	return 1;
}

BOOL GetProcessPeb(HANDLE ProcessHandle, PPEB Peb)
{
	_NtQueryInformationProcess pNtQueryInformationProcess;
	PROCESS_BASIC_INFORMATION ProcessBasicInformation;
	ULONG ulSize;
	SIZE_T dwBytesRead;

	pNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationProcess");

	memset(&ProcessBasicInformation, 0, sizeof(ProcessBasicInformation));

	if (pNtQueryInformationProcess(ProcessHandle, 0, &ProcessBasicInformation, sizeof(ProcessBasicInformation), &ulSize) >= 0 && ulSize == sizeof(ProcessBasicInformation))
		if (ReadProcessMemory(ProcessHandle, ProcessBasicInformation.PebBaseAddress, Peb, sizeof(PEB), &dwBytesRead))
			return TRUE;

	return FALSE;
}

DWORD GetProcessInitialThreadId(HANDLE ProcessHandle)
{
	DWORD ThreadId;
	_NtQueryInformationProcess pNtQueryInformationProcess;
	PROCESS_BASIC_INFORMATION ProcessBasicInformation;
	ULONG ulSize;

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	if (!SystemInfo.dwPageSize)
	{
		ErrorOutput("GetProcessInitialThreadId: Failed to obtain system page size");
		return 0;
	}

	pNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationProcess");

	memset(&ProcessBasicInformation, 0, sizeof(ProcessBasicInformation));

	if (pNtQueryInformationProcess(ProcessHandle, 0, &ProcessBasicInformation, sizeof(ProcessBasicInformation), &ulSize) < 0 || ulSize != sizeof(ProcessBasicInformation))
	{
		DebugOutput("GetProcessInitialThreadId: NtQueryInformationProcess failed.\n");
		return 0;
	}

	PTEB Teb = (PTEB)((PBYTE)ProcessBasicInformation.PebBaseAddress + SystemInfo.dwPageSize);

	if (!ReadProcessMemory(ProcessHandle, &Teb->ClientId.UniqueThread, &ThreadId, sizeof(DWORD), NULL))
	{
		PTEB Teb = (PTEB)((PBYTE)ProcessBasicInformation.PebBaseAddress - SystemInfo.dwPageSize);

		if (!ReadProcessMemory(ProcessHandle, &Teb->ClientId.UniqueThread, &ThreadId, sizeof(DWORD), NULL))
		{
#ifdef DEBUG_COMMENTS
			ErrorOutput("GetProcessInitialThreadId: ReadProcessMemory failed (0x%p)", &Teb->ClientId.UniqueThread);
#else
			DebugOutput("GetProcessInitialThreadId: ReadProcessMemory failed (0x%p).\n", &Teb->ClientId.UniqueThread);
#endif
			return 0;
		}
	}

#ifdef DEBUG_COMMENTS
	if (ThreadId)
			DebugOutput("GetProcessInitialThreadId: Initial ThreadID %d.\n", ThreadId);
#endif
	if (ThreadId)
		return ThreadId;

	return 0;
}

static int GrantDebugPrivileges(void)
{
	HANDLE Token = NULL;
	TOKEN_PRIVILEGES TokenPrivileges;
	LUID PrivilegeValue;
	int RetVal;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &Token))
		return 0;

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &PrivilegeValue))
	{
		CloseHandle(Token);
		return 0;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Luid = PrivilegeValue;
	TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	RetVal = AdjustTokenPrivileges(Token, FALSE, &TokenPrivileges, sizeof(TokenPrivileges), NULL, NULL);
	CloseHandle(Token);

	return RetVal;
}

PIMAGE_NT_HEADERS GetNtHeaders(PVOID BaseAddress)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)BaseAddress;

	__try
	{
		if (!pDosHeader->e_lfanew)
		{
			DebugOutput("GetNtHeaders: pointer to PE header zero.\n");
			return NULL;
		}

		return (PIMAGE_NT_HEADERS)((PBYTE)BaseAddress + pDosHeader->e_lfanew);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DebugOutput("GetNtHeaders: Exception occurred reading around base address 0x%p\n", BaseAddress);
		return NULL;
	}
}

__declspec(noinline) DWORD WINAPI LoadLibraryThreadFunc(LoadLibraryThread *Pointers)
{
	HMODULE ModuleHandle;

	ModuleHandle = (HMODULE)Pointers->LoadLibrary(Pointers->DllPath);

	if (ModuleHandle == NULL)
		return (DWORD)Pointers->GetLastError();

	return 0;
}

static int InjectDllViaQueuedAPC(HANDLE ProcessHandle, HANDLE ThreadHandle, const char *DllPath)
{
	SIZE_T DllPathLength;
	LoadLibraryThread Pointers;
	void *PointersAddress;
	void *RemoteFuncAddress;
	SIZE_T BytesWritten;

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	if (!SystemInfo.dwPageSize)
	{
		ErrorOutput("InjectDllViaQueuedAPC: Failed to obtain system page size");
		return 0;
	}

	DllPathLength = strlen(DllPath) + 1 + sizeof(DWORD) - ((strlen(DllPath) + 1) % sizeof(DWORD));

	if (DllPathLength == 0)
	{
		DebugOutput("InjectDllViaQueuedAPC: Dll argument bad.\n");
		return 0;
	}

	memset(&Pointers, 0, sizeof(Pointers));

	Pointers.LoadLibrary = GetProcAddress(LoadLibrary("kernel32"), "LoadLibraryA");
	Pointers.GetLastError = GetProcAddress(LoadLibrary("kernel32"),  "GetLastError");

	if (!Pointers.LoadLibrary || !Pointers.GetLastError)
	{
		DebugOutput("InjectDllViaQueuedAPC: Failed to get function pointers.\n");
		return 0;
	}

	Pointers.DllPath = (PCHAR)VirtualAllocEx(ProcessHandle, NULL, SystemInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (Pointers.DllPath == NULL)
	{
		ErrorOutput("InjectDllViaQueuedAPC: Failed to allocate buffer in target");
		return 0;
	}

	if (WriteProcessMemory(ProcessHandle, Pointers.DllPath, DllPath, DllPathLength, &BytesWritten) == FALSE || BytesWritten != DllPathLength)
	{
		ErrorOutput("InjectDllViaQueuedAPC: Failed to write to DllPath in target");
		return 0;
	}

	PointersAddress = (PBYTE)Pointers.DllPath + BytesWritten;

	if (WriteProcessMemory(ProcessHandle, PointersAddress, &Pointers, sizeof(Pointers), &BytesWritten) == FALSE || BytesWritten != sizeof(Pointers))
	{
		ErrorOutput("InjectDllViaQueuedAPC: Failed to write to PointersAddress in target");
		return 0;
	}

	RemoteFuncAddress = (PBYTE)PointersAddress + BytesWritten;

	if (WriteProcessMemory(ProcessHandle, RemoteFuncAddress, (PBYTE)(&LoadLibraryThreadFunc), 0x100, &BytesWritten) == FALSE || BytesWritten != 0x100)
	{
		ErrorOutput("InjectDllViaQueuedAPC: Failed to write to RemoteFuncAddress in target");
		return 0;
	}

	if (QueueUserAPC((PAPCFUNC)RemoteFuncAddress, ThreadHandle, (ULONG_PTR)PointersAddress) == 0)
	{
		ErrorOutput("InjectDllViaQueuedAPC: QueueUserAPC failed");
		return 0;
	}

	DebugOutput("InjectDllViaQueuedAPC: APC injection queued.\n");

	return 1;
}

static int InjectDllViaThread(HANDLE ProcessHandle, const char *DllPath)
{
	SIZE_T DllPathLength;
	LoadLibraryThread Pointers;
	void *PointersAddress;
	void *RemoteFuncAddress;
	OSVERSIONINFO OSVersion;
	SIZE_T BytesWritten;
	HANDLE RemoteThreadHandle;
	DWORD ExitCode;
	_RtlCreateUserThread RtlCreateUserThread;
	_RtlNtStatusToDosError RtlNtStatusToDosError;
	int RetVal = 0;

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	if (!SystemInfo.dwPageSize)
	{
		ErrorOutput("InjectDllViaThread: Failed to obtain system page size");
		return 0;
	}

	DllPathLength = strlen(DllPath) + 1;

	if (DllPathLength == 0)
	{
		DebugOutput("InjectDllViaThread: Dll argument bad.\n");
		return 0;
	}

	memset(&Pointers, 0, sizeof(Pointers));

	Pointers.LoadLibrary = GetProcAddress(LoadLibrary("kernel32"), "LoadLibraryA");
	Pointers.GetLastError = GetProcAddress(LoadLibrary("kernel32"),  "GetLastError");

	if (!Pointers.LoadLibrary || !Pointers.GetLastError)
	{
		DebugOutput("InjectDllViaThread: Failed to get function pointers.\n");
		return 0;
	}

	Pointers.DllPath = (PCHAR)VirtualAllocEx(ProcessHandle, NULL, SystemInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (Pointers.DllPath == NULL)
	{
		ErrorOutput("InjectDllViaThread: Failed to allocate buffer in target");
		return 0;
	}

	if (WriteProcessMemory(ProcessHandle, Pointers.DllPath, DllPath, DllPathLength, &BytesWritten) == FALSE || BytesWritten != DllPathLength)
	{
		ErrorOutput("InjectDllViaThread: Failed to write to DllPath in target");
		return 0;
	}

	PointersAddress = (PBYTE)Pointers.DllPath + BytesWritten;

	if (WriteProcessMemory(ProcessHandle, PointersAddress, &Pointers, sizeof(Pointers), &BytesWritten) == FALSE || BytesWritten != sizeof(Pointers))
	{
		ErrorOutput("InjectDllViaThread: Failed to write to PointersAddress in target");
		return 0;
	}

	RemoteFuncAddress = (PBYTE)PointersAddress + BytesWritten;

	if (WriteProcessMemory(ProcessHandle, RemoteFuncAddress, (PBYTE)(&LoadLibraryThreadFunc), 0x100, &BytesWritten) == FALSE || BytesWritten != 0x100)
	{
		ErrorOutput("InjectDllViaThread: Failed to write to RemoteFuncAddress in target");
		return 0;
	}

	OSVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

	if (!GetVersionEx(&OSVersion))
	{
		ErrorOutput("InjectDllViaThread: Failed to get OS version");
		return 0;
	}

	if (OSVersion.dwMajorVersion < 6)
	{
		RemoteThreadHandle = CreateRemoteThread(ProcessHandle, NULL, 0, RemoteFuncAddress, PointersAddress, 0, NULL);

		if (!RemoteThreadHandle)
		{
			ErrorOutput("InjectDllViaThread: CreateRemoteThread failed");
			return 0;
		}
		else
		{
			WaitForSingleObject(RemoteThreadHandle, INFINITE);
			GetExitCodeThread(RemoteThreadHandle, &ExitCode);
			CloseHandle(RemoteThreadHandle);
			VirtualFreeEx(ProcessHandle, Pointers.DllPath, SystemInfo.dwPageSize, MEM_RELEASE);

			if (ExitCode)
			{
				SetLastError(ExitCode);
				ErrorOutput("InjectDllViaThread: CreateRemoteThread injection failed");
				return 0;
			}

			DebugOutput("InjectDllViaThread: Successfully injected Dll into process via CreateRemoteThread.\n");

			return 1;
		}
	}
	else
	{
		RtlCreateUserThread = (_RtlCreateUserThread)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlCreateUserThread");

		RetVal = RtlCreateUserThread(ProcessHandle, NULL, 0, 0, 0, 0, (PTHREAD_START_ROUTINE)RemoteFuncAddress, PointersAddress, &RemoteThreadHandle, NULL);

		if (!NT_SUCCESS(RetVal))
		{
			RemoteThreadHandle = NULL;
			ErrorOutput("InjectDllViaThread: RtlCreateUserThread failed");
			return 0;
		}
		else if (RemoteThreadHandle)
		{
			WaitForSingleObject(RemoteThreadHandle, INFINITE);
			GetExitCodeThread(RemoteThreadHandle, &ExitCode);
			CloseHandle(RemoteThreadHandle);
			VirtualFreeEx(ProcessHandle, Pointers.DllPath, SystemInfo.dwPageSize, MEM_RELEASE);

			if (ExitCode)
			{
				RtlNtStatusToDosError = (_RtlNtStatusToDosError)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlNtStatusToDosError");
				SetLastError(RtlNtStatusToDosError(ExitCode));
				ErrorOutput("InjectDllViaThread: RtlCreateUserThread injection failed");
				return 0;
			}
		}

		DebugOutput("InjectDllViaThread: Successfully injected Dll into process via RtlCreateUserThread.\n");

		return 1;
	}
}

static int ReflectiveInjectDllViaThread(HANDLE ProcessHandle, const char *DllPath)
{
	SIZE_T FileSize, BytesRead;
	void *Buffer, *RemoteBuffer, *RemoteEntryPoint;
	OSVERSIONINFO OSVersion;
	SIZE_T BytesWritten;
	HANDLE hFile, RemoteThreadHandle;
	DWORD ExitCode;
	_RtlCreateUserThread RtlCreateUserThread;
	_RtlNtStatusToDosError RtlNtStatusToDosError;
	int RetVal = 0;

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	if (!SystemInfo.dwPageSize)
	{
		ErrorOutput("ReflectiveInjectDllViaThread: Failed to obtain system page size");
		return 0;
	}

	hFile = CreateFile(DllPath, GENERIC_READ, 0, (LPSECURITY_ATTRIBUTES) NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, (HANDLE) NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
#ifdef DEBUG_COMMENTS
		ErrorOutput("CreateFile");
#endif
		return 0;
	}

	FileSize = GetFileSize(hFile, NULL);

	Buffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!Buffer)
	{
#ifdef DEBUG_COMMENTS
		ErrorOutput("VirtualAlloc");
#endif
		return 0;
	}

	if (!ReadFile(hFile, Buffer, (DWORD)FileSize, (LPDWORD)&BytesRead, NULL))
	{
#ifdef DEBUG_COMMENTS
		ErrorOutput("ReadFile");
#endif
		return 0;
	}

	RemoteBuffer = (PCHAR)VirtualAllocEx(ProcessHandle, NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (RemoteBuffer == NULL)
	{
		ErrorOutput("ReflectiveInjectDllViaThread: Failed to allocate buffer in target");
		return 0;
	}

	if (WriteProcessMemory(ProcessHandle, RemoteBuffer, Buffer, FileSize, &BytesWritten) == FALSE || BytesWritten != FileSize)
	{
		ErrorOutput("ReflectiveInjectDllViaThread: Failed to write image to target");
		return 0;
	}

	RemoteEntryPoint = (PBYTE)RemoteBuffer + GetNtHeaders(Buffer)->OptionalHeader.AddressOfEntryPoint;

	OSVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

	if (!GetVersionEx(&OSVersion))
	{
		ErrorOutput("ReflectiveInjectDllViaThread: Failed to get OS version");
		return 0;
	}

	if (OSVersion.dwMajorVersion < 6)
	{
		RemoteThreadHandle = CreateRemoteThread(ProcessHandle, NULL, 0, RemoteEntryPoint, NULL, 0, NULL);

		if (!RemoteThreadHandle)
		{
			ErrorOutput("ReflectiveInjectDllViaThread: CreateRemoteThread failed");
			return 0;
		}
		else
		{
			WaitForSingleObject(RemoteThreadHandle, INFINITE);
			GetExitCodeThread(RemoteThreadHandle, &ExitCode);
			CloseHandle(RemoteThreadHandle);
			VirtualFreeEx(ProcessHandle, RemoteBuffer, SystemInfo.dwPageSize, MEM_RELEASE);

			if (ExitCode)
			{
				SetLastError(ExitCode);
				ErrorOutput("ReflectiveInjectDllViaThread: CreateRemoteThread injection failed");
				return 0;
			}

			DebugOutput("ReflectiveInjectDllViaThread: Successfully injected Dll into process via CreateRemoteThread.\n");

			return 1;
		}
	}
	else
	{
		RtlCreateUserThread = (_RtlCreateUserThread)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlCreateUserThread");

		RetVal = RtlCreateUserThread(ProcessHandle, NULL, 0, 0, 0, 0, (PTHREAD_START_ROUTINE)RemoteEntryPoint, NULL, &RemoteThreadHandle, NULL);

		if (!NT_SUCCESS(RetVal))
		{
			RemoteThreadHandle = NULL;
			ErrorOutput("ReflectiveInjectDllViaThread: RtlCreateUserThread failed");
			return 0;
		}
		else if (RemoteThreadHandle)
		{
			WaitForSingleObject(RemoteThreadHandle, INFINITE);
			GetExitCodeThread(RemoteThreadHandle, &ExitCode);
			CloseHandle(RemoteThreadHandle);
			VirtualFreeEx(ProcessHandle, RemoteBuffer, SystemInfo.dwPageSize, MEM_RELEASE);

			if (!ExitCode)
			{
				RtlNtStatusToDosError = (_RtlNtStatusToDosError)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlNtStatusToDosError");
				SetLastError(RtlNtStatusToDosError(ExitCode));
				ErrorOutput("ReflectiveInjectDllViaThread: RtlCreateUserThread injection failed");
				return 0;
			}
		}

		DebugOutput("ReflectiveInjectDllViaThread: Successfully injected Dll into process via RtlCreateUserThread.\n");

		return 1;
	}

	VirtualFree(Buffer, 0, MEM_RELEASE);
	CloseHandle(hFile);
}

static int InjectDllViaIAT(HANDLE ProcessHandle, HANDLE ThreadHandle, const char *DllPath, PEB Peb)
{
	SIZE_T DllPathLength;
	IMAGE_DOS_HEADER DosHeader;
	IMAGE_NT_HEADERS NtHeader;
	CONTEXT Context;
	MEMORY_BASIC_INFORMATION MemoryInfo;
	DWORD NewImportDirectorySize, OriginalNumberOfDescriptors, NewNumberOfDescriptors, NewSizeOfImportDescriptors, SizeOfTables, NewImportsRVA, dwProtect, SizeOfHeaders, TotalSize;
	PBYTE BaseAddress, FreeAddress, EndOfImage, TargetImportTable, AllocationAddress, NewImportDirectory;
	IMAGE_SECTION_HEADER ImportsSection;
	PIMAGE_IMPORT_DESCRIPTOR pImageDescriptor;
	PIMAGE_THUNK_DATAXX pOriginalFirstThunk, pFirstThunk;
	unsigned int i, OrdinalValue;
	SIZE_T BytesRead;
	int RetVal = 0;
	BOOL ModifiedEP = FALSE;
	PVOID AddressOfEntryPoint, CIP;

	NewImportDirectorySize = 0;
	NewImportDirectory = NULL;

	memset(&DosHeader, 0, sizeof(DosHeader));
	memset(&NtHeader, 0, sizeof(NtHeader));
	memset(&MemoryInfo, 0, sizeof(MemoryInfo));

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	if (!SystemInfo.dwPageSize)
	{
		ErrorOutput("InjectDllViaIAT: Failed to obtain system page size");
		return 0;
	}

	DllPathLength = strlen(DllPath) + 1;

	if (DllPathLength == 0)
	{
		DebugOutput("InjectDllViaIAT: Dll argument bad.\n");
		return 0;
	}

	BaseAddress = Peb.ImageBaseAddress;

#ifdef DEBUG_COMMENTS
	DebugOutput("Process image base: 0x%p\n", BaseAddress);
#endif

	if (!VirtualQueryEx(ProcessHandle, (PVOID)BaseAddress, &MemoryInfo, sizeof(MemoryInfo)))
	{
		DebugOutput("InjectDllViaIAT: Failed to query target process image base.\n");
		goto out;
	}

rebase:
	// The following checks return 1 to prevent fallback to thread injection during hollowing
	if (!ReadProcessMemory(ProcessHandle, BaseAddress, &DosHeader, sizeof(DosHeader), NULL))
	{
		ErrorOutput("InjectDllViaIAT: Failed to read DOS header from 0x%p - 0x%p", BaseAddress, BaseAddress + sizeof(DosHeader));
		RetVal = 1;
		goto out;
	}

	if (!DosHeader.e_lfanew)
	{
		DebugOutput("InjectDllViaIAT: Executable DOS header zero.\n");
		RetVal = 1;
		goto out;
	}

	if (!ReadProcessMemory(ProcessHandle, BaseAddress + DosHeader.e_lfanew, &NtHeader, sizeof(NtHeader), NULL))
	{
		ErrorOutput("InjectDllViaIAT: Failed to read NT headers from 0x%p - 0x%p", BaseAddress + DosHeader.e_lfanew, BaseAddress + DosHeader.e_lfanew + sizeof(NtHeader));
		RetVal = 1;
		goto out;
	}

	if (NtHeader.Signature != IMAGE_NT_SIGNATURE || (NtHeader.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC && NtHeader.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) || NtHeader.FileHeader.Machine == 0)
	{
		DebugOutput("InjectDllViaIAT: Executable image invalid.\n");
		RetVal = 1;
		goto out;
	}

	if (NtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress && NtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress)
	{
		DebugOutput("InjectDllViaIAT: Executable is .NET, injecting via queued APC.\n");
		return InjectDllViaQueuedAPC(ProcessHandle, ThreadHandle, DllPath);
	}

	Context.ContextFlags = CONTEXT_ALL;

	if (!ModifiedEP && !GetThreadContext(ThreadHandle, &Context))
	{
		DebugOutput("InjectDllViaIAT: GetThreadContext failed");
		goto out;
	}

#ifdef _WIN64
	AddressOfEntryPoint = (PVOID)Context.Rcx;
	CIP = AddressOfEntryPoint;
#else
	AddressOfEntryPoint = (PVOID)Context.Eax;
	CIP = AddressOfEntryPoint;
#endif
	if (!ModifiedEP && AddressOfEntryPoint != (PVOID)(BaseAddress + NtHeader.OptionalHeader.AddressOfEntryPoint))
	{
		if (Peb.Ldr)
		{
			DebugOutput("InjectDllViaIAT: Not a new process, falling back to thread injection\n");
			goto out;
		}

		AddressOfEntryPoint = (PVOID)(BaseAddress + NtHeader.OptionalHeader.AddressOfEntryPoint);
		if (!VirtualQueryEx(ProcessHandle, AddressOfEntryPoint, &MemoryInfo, sizeof(MemoryInfo)))
		{
			DebugOutput("InjectDllViaIAT: Modified EP detected, failed to query target process address 0x%p.\n", AddressOfEntryPoint);
			goto out;
		}

		BaseAddress = MemoryInfo.AllocationBase;
		DebugOutput("InjectDllViaIAT: Modified EP detected, rebasing IAT patch to new image base 0x%p (context EP 0x%p)\n", BaseAddress, CIP);
		ModifiedEP = TRUE;
		goto rebase;
	}

#ifdef DEBUG_COMMENTS
	DebugOutput("InjectDllViaIAT: IAT patching with dll name %s.\n", DllPath);
#endif

	// Get the actual import directory size
	if (NtHeader.IMPORT_DIRECTORY.VirtualAddress)
	{
		NtHeader.IMPORT_DIRECTORY.Size = 0;
		IMAGE_IMPORT_DESCRIPTOR ImageImport, *pImageImport = (IMAGE_IMPORT_DESCRIPTOR*)((PBYTE)BaseAddress + NtHeader.IMPORT_DIRECTORY.VirtualAddress);
		while (ReadProcessMemory(ProcessHandle, pImageImport, &ImageImport, sizeof(ImageImport), NULL))
		{
			NtHeader.IMPORT_DIRECTORY.Size += sizeof(IMAGE_IMPORT_DESCRIPTOR);
			if (!ImageImport.Name)
				break;
			++pImageImport;
		};
	}

	OriginalNumberOfDescriptors = NtHeader.IMPORT_DIRECTORY.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	NewNumberOfDescriptors = OriginalNumberOfDescriptors + 1;
	NewSizeOfImportDescriptors = NewNumberOfDescriptors * sizeof(IMAGE_IMPORT_DESCRIPTOR);
	if (NewSizeOfImportDescriptors % sizeof(DWORD_PTR))
		NewSizeOfImportDescriptors += sizeof(DWORD_PTR);

	// Two for OriginalFirstThunk, NULL, then two for FirstThunk, NULL.
	SizeOfTables = NewSizeOfImportDescriptors + (4 * sizeof(IMAGE_THUNK_DATAXX));

	NewImportDirectorySize = (DWORD)(SizeOfTables + DllPathLength);

	// We add the size of the original NT headers which we append to the table
	TotalSize = NewImportDirectorySize + sizeof(NtHeader);

	// Allocate the memory for our new import directory
	NewImportDirectory = (PBYTE)calloc(TotalSize, 1);

	if (NewImportDirectory == NULL)
	{
		DebugOutput("InjectDllViaIAT: Failed to allocate memory for new import directory.\n");
		RetVal = 0;
		goto out;
	}

	SizeOfHeaders = DosHeader.e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + NtHeader.FileHeader.SizeOfOptionalHeader;

	memset(&ImportsSection, 0, sizeof(ImportsSection));

	// Check which section (if any) contains the import table.
	for (i = 0; i < NtHeader.FileHeader.NumberOfSections; i++)
	{
		IMAGE_SECTION_HEADER SectionHeader;
		memset(&SectionHeader, 0, sizeof(SectionHeader));

		if (!ReadProcessMemory(ProcessHandle, (PBYTE)BaseAddress + SizeOfHeaders + sizeof(SectionHeader) * i, &SectionHeader, sizeof(SectionHeader), &BytesRead) || BytesRead < sizeof(SectionHeader))
		{
			ErrorOutput("InjectDllViaIAT: Failed to read section header from 0x%p - 0x%p", (PBYTE)BaseAddress + SizeOfHeaders + sizeof(SectionHeader) * i, (PBYTE)BaseAddress + SizeOfHeaders + sizeof(SectionHeader) * (i + 1));
			RetVal = 0;
			goto out;
		}

		if (NtHeader.IMPORT_DIRECTORY.VirtualAddress >= SectionHeader.VirtualAddress &&
			NtHeader.IMPORT_DIRECTORY.VirtualAddress < SectionHeader.VirtualAddress + SectionHeader.SizeOfRawData)
			ImportsSection = SectionHeader;
	}

	// If it looks like this image has already been patched, we bail.
	if (ImportsSection.VirtualAddress == 0)
	{
		DWORD ImportsRVA, ImportsSize, NtSignature;
		ImportsRVA = NtHeader.IMPORT_DIRECTORY.VirtualAddress;
		ImportsSize = NtHeader.IMPORT_DIRECTORY.Size + (DWORD)DllPathLength + (4 * sizeof(IMAGE_THUNK_DATAXX));

		if (!ReadProcessMemory(ProcessHandle, (PBYTE)BaseAddress + ImportsRVA + ImportsSize, &NtSignature, sizeof(DWORD), &BytesRead) || BytesRead < sizeof(DWORD))
			ErrorOutput("InjectDllViaIAT: Failed to check for PE header after existing import table at 0x%p", (PBYTE)BaseAddress + ImportsRVA + ImportsSize);
		else if (NtSignature  == IMAGE_NT_SIGNATURE)
		{
			DebugOutput("InjectDllViaIAT: This image has already been patched.\n");
			RetVal = 1;
			goto out;
		}
	}

	// Append the original import descriptors (if any) after our created one
	pImageDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)NewImportDirectory;

	if (NtHeader.IMPORT_DIRECTORY.VirtualAddress != 0)
	{
		if (!ReadProcessMemory(ProcessHandle, (PBYTE)BaseAddress + NtHeader.IMPORT_DIRECTORY.VirtualAddress, pImageDescriptor+1, OriginalNumberOfDescriptors * sizeof(IMAGE_IMPORT_DESCRIPTOR), &BytesRead)
			|| BytesRead < OriginalNumberOfDescriptors * sizeof(IMAGE_IMPORT_DESCRIPTOR))
			DebugOutput("InjectDllViaIAT: Failed to read import descriptors.\n");
		else if (!ScanForNonZero(pImageDescriptor+1, OriginalNumberOfDescriptors * sizeof(IMAGE_IMPORT_DESCRIPTOR)))
		{
			DebugOutput("InjectDllViaIAT: Blank import descriptor, aborting IAT patch.\n");
			if (!FirstProcess)
				RetVal = 1; // we bail but don't fail
			goto out;
		}
	}

	// Copy the original NtHeaders after the new table
	memcpy(NewImportDirectory + NewImportDirectorySize, &NtHeader, sizeof(NtHeader));

	// Scan address space from EXE image base for a free region to contain our new import directory
	EndOfImage = BaseAddress + NtHeader.OptionalHeader.BaseOfCode + NtHeader.OptionalHeader.SizeOfCode + NtHeader.OptionalHeader.SizeOfInitializedData + NtHeader.OptionalHeader.SizeOfUninitializedData;

	TargetImportTable = NULL;

	for (FreeAddress = EndOfImage;; FreeAddress = (PBYTE)MemoryInfo.BaseAddress + MemoryInfo.RegionSize)
	{
		PBYTE StartAddress;
		memset(&MemoryInfo, 0, sizeof(MemoryInfo));

		if (VirtualQueryEx(ProcessHandle, (PVOID)FreeAddress, &MemoryInfo, sizeof(MemoryInfo)) == 0)
		{
			if (GetLastError() == ERROR_INVALID_PARAMETER)
				break;

			ErrorOutput("InjectDllViaIAT: Failed to query target process memory at address 0x%p", FreeAddress);
			break;
		}

		// This indicates the end of user-mode address space
		if ((MemoryInfo.RegionSize & 0xFFF) == 0xFFF)
			break;

		if (MemoryInfo.State != MEM_FREE)
			continue;

#ifndef _WIN64
		if ((DWORD_PTR)MemoryInfo.BaseAddress > MAX_ADDRESS)
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("InjectDllViaIAT: Skipping region at 0x%p\n", MemoryInfo.BaseAddress);
#endif
			continue;
		}
		if ((SIZE_T)((PBYTE)MemoryInfo.BaseAddress + MemoryInfo.RegionSize) > MAX_ADDRESS)
			StartAddress = (PBYTE)MAX_ADDRESS - SystemInfo.dwPageSize;
		else
#endif
			StartAddress = (PBYTE)MemoryInfo.BaseAddress + MemoryInfo.RegionSize - SystemInfo.dwPageSize;

		if (StartAddress - BaseAddress > MAX_RANGE)
			StartAddress = BaseAddress + MAX_RANGE;

#ifdef DEBUG_COMMENTS
		DebugOutput("InjectDllViaIAT: Found a free region from 0x%p - 0x%p, starting reverse scan from 0x%p\n", MemoryInfo.BaseAddress, (PBYTE)MemoryInfo.BaseAddress + MemoryInfo.RegionSize, StartAddress);
#endif

		for (AllocationAddress = StartAddress; AllocationAddress > (PBYTE)(((DWORD_PTR)MemoryInfo.BaseAddress + 0xFFFF) & ~(DWORD_PTR)0xFFFF); AllocationAddress -= SystemInfo.dwPageSize)
		{
			TargetImportTable = (PBYTE)VirtualAllocEx(ProcessHandle, AllocationAddress, TotalSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

			if (TargetImportTable == NULL)
			{
#ifdef DEBUG_COMMENTS
				ErrorOutput("InjectDllViaIAT: Failed to allocate new memory region at 0x%p", AllocationAddress);
#endif
				continue;
			}

#ifdef DEBUG_COMMENTS
			DebugOutput("InjectDllViaIAT: Allocated 0x%x bytes for new import table at 0x%p.\n", TotalSize, TargetImportTable);
#endif
			break;
		}

		if (TargetImportTable)
			break;
	}

	if (TargetImportTable == NULL)
	{
		DebugOutput("InjectDllViaIAT: Failed to allocate region in target process for new import table.\n");
		goto out;
	}

	NewImportsRVA = (DWORD)(TargetImportTable - (PBYTE)BaseAddress);

	if (StringCchCopyA((char*)NewImportDirectory + SizeOfTables, NewImportDirectorySize - SizeOfTables, DllPath))
	{
		ErrorOutput("InjectDllViaIAT: Failed to copy DLL path to new import directory");
		goto out;
	}

	// We fill our new import descriptor with required values
	pImageDescriptor->OriginalFirstThunk = NewImportsRVA + NewSizeOfImportDescriptors;
	pImageDescriptor->FirstThunk = NewImportsRVA + NewSizeOfImportDescriptors + (sizeof(IMAGE_THUNK_DATAXX) * 2);
	pImageDescriptor->Name = NewImportsRVA + SizeOfTables;

	// We will use an ordinal value of 1
	OrdinalValue = 1;

	// We write the ordinal value & flag to OriginalFirstThunk
	pOriginalFirstThunk = (PIMAGE_THUNK_DATAXX)(NewImportDirectory + NewSizeOfImportDescriptors);
	pOriginalFirstThunk->u1.Ordinal =  OrdinalValue | IMAGE_ORDINAL_FLAG_XX;

	// We write to FirstThunk in the same way
	pFirstThunk = pOriginalFirstThunk + 2;
	pFirstThunk->u1.Ordinal = OrdinalValue | IMAGE_ORDINAL_FLAG_XX;

	// Write the new table to the process
	if (!WriteProcessMemory(ProcessHandle, TargetImportTable, NewImportDirectory, TotalSize, NULL))
	{
		ErrorOutput("InjectDllViaIAT: Failed to write new import descriptor table to target process");
		RetVal = 0;
		goto out;
	}

	// If IAT zero, set it to section that contains original import table to prevent LdrpSnapIAT failure
	if (NtHeader.IAT_DIRECTORY.VirtualAddress == 0)
	{
		if (ImportsSection.VirtualAddress)
		{
			NtHeader.IAT_DIRECTORY.VirtualAddress = ImportsSection.VirtualAddress;
			if (ImportsSection.Misc.VirtualSize)
				NtHeader.IAT_DIRECTORY.Size = ImportsSection.Misc.VirtualSize;
			else
				NtHeader.IAT_DIRECTORY.Size = ImportsSection.SizeOfRawData;
		}
		// Required for Win10+ 
		else
		{
			NtHeader.IAT_DIRECTORY.VirtualAddress = pImageDescriptor->FirstThunk;
			NtHeader.IAT_DIRECTORY.Size = sizeof(IMAGE_THUNK_DATAXX);
		}
	}

	// Now set the import table directory entry to point to the new table
	NtHeader.IMPORT_DIRECTORY.VirtualAddress = NewImportsRVA;
	NtHeader.IMPORT_DIRECTORY.Size = NewImportDirectorySize;

	// Set bound imports values to zero to prevent them overriding our new import table
	NtHeader.BOUND_DIRECTORY.VirtualAddress = 0;
	NtHeader.BOUND_DIRECTORY.Size = 0;

	// Zero out any checksum
	NtHeader.OptionalHeader.CheckSum = 0;

	// Set target image page permissions to allow writing of new headers
	if (!VirtualProtectEx(ProcessHandle, (PBYTE)BaseAddress, NtHeader.OptionalHeader.SizeOfHeaders, PAGE_EXECUTE_READWRITE, &dwProtect))
	{
		ErrorOutput("InjectDllViaIAT: Failed to modify memory page protection of NtHeader");
		goto out;
	}

	// Copy the new NT headers back to the target process
	if (!WriteProcessMemory(ProcessHandle, (PBYTE)BaseAddress + DosHeader.e_lfanew, &NtHeader, sizeof(NtHeader), NULL))
	{
		ErrorOutput("InjectDllViaIAT: Failed to write new NtHeader");
		RetVal = 0;
		goto out;
	}

	// Restore original protection
	if (!VirtualProtectEx(ProcessHandle, (PBYTE)BaseAddress, NtHeader.OptionalHeader.SizeOfHeaders, dwProtect, &dwProtect))
	{
		ErrorOutput("InjectDllViaIAT: Failed to restore previous memory page protection");
		goto out;
	}

	DebugOutput("InjectDllViaIAT: Successfully patched IAT.\n");

	RetVal = 1;

out:
	return RetVal;
}

static int InjectDll(int ProcessId, int ThreadId, const char *DllPath)
{
	HANDLE ProcessHandle = NULL, ThreadHandle = NULL;
	int RetVal = 0, InitialThreadId;
	PEB Peb;

	ProcessHandle = NULL;
	ThreadHandle = NULL;
	memset(&Peb, 0, sizeof(PEB));

	if (!ProcessId)
	{
		DebugOutput("InjectDll: Error, no process identifier supplied.\n");
		goto out;
	}

	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);

	if (ProcessHandle == NULL)
	{
		RetVal = 0;
		if (GetLastError() == ERROR_ACCESS_DENIED)
		{
			// On Win10+ this could mean the target process is PPL (e.g. services.exe)
			// Try injecting with PPLinject (https://github.com/splunk/PPLinject)
#ifdef _WIN64
			char PPLinject[] = "PPLinject64.exe";
#else
			char PPLinject[] = "PPLinject.exe";
#endif
			char CommandLine[BUFSIZE];
			PROCESS_INFORMATION pi;
			STARTUPINFOEX sie = {sizeof(sie)};
#ifdef DEBUG_COMMENTS
			if (strlen(LogPipe))
				sprintf_s(CommandLine, sizeof(CommandLine)-1, "%s -d %d %s %s", PPLinject, ProcessId, DllPath, LogPipe);
			else
#endif
				sprintf_s(CommandLine, sizeof(CommandLine)-1, "%s %d %s", PPLinject, ProcessId, DllPath);
			CopyConfig(ProcessId, (PCHAR)DllPath);
			if (!CreateProcess(NULL, CommandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &sie.StartupInfo, &pi))
				DebugOutput("Loader: Failed to open process, PPLinject launch failed\n");
			else
			{
				DebugOutput("Loader: Unable to open process, launched: %s\n", CommandLine);
				RetVal = 1;
			}
		}
		else ErrorOutput("InjectDll: Failed to open process");
		goto out;
	}

	if (!GetProcessPeb(ProcessHandle, &Peb))
		DebugOutput("InjectDll: GetProcessPeb failure.\n");

	// If no thread id supplied, we fetch the initial thread id from the initial TEB
	if (!ThreadId && Peb.ImageBaseAddress && !Peb.Ldr)
	{
		InitialThreadId = GetProcessInitialThreadId(ProcessHandle);

		if (!InitialThreadId)
		{
			if (Peb.SessionId)
			{
				DebugOutput("InjectDll: No thread ID supplied, GetProcessInitialThreadId failed (SessionId=%d).\n", Peb.SessionId);
				RetVal = 0;
				goto out;
			}

			DebugOutput("InjectDll: No thread ID supplied, GetProcessInitialThreadId failed, falling back to thread injection.\n");
		}
		else
		{
			ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, InitialThreadId);
			if (ThreadHandle == NULL)
				DebugOutput("InjectDll: No thread ID supplied, OpenThread on initial thread ID %d failed", InitialThreadId);
			else
				DebugOutput("InjectDll: No thread ID supplied, initial thread ID %d, handle 0x%x\n", InitialThreadId, ThreadHandle);
		}
	}
	else if (ThreadId)
	{
		ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadId);

		if (ThreadHandle == NULL)
			DebugOutput("InjectDll: OpenThread failed");
	}

	// We try to use IAT patching in case this is a new process.
	// If it's not, this function is expected to fail.
	if (!DisableIATPatching && ThreadHandle && Peb.ImageBaseAddress)
	{
		if (InjectDllViaIAT(ProcessHandle, ThreadHandle, DllPath, Peb))
		{
			RetVal = 1;
			goto out;
		}
	}

	if (ThreadId && ThreadHandle)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("InjectDll: IAT patching failed, falling back to queued APC injection.\n");
#endif
		RetVal = InjectDllViaQueuedAPC(ProcessHandle, ThreadHandle, DllPath);
	}
	else
	{
#ifdef DEBUG_COMMENTS
		if (!DisableIATPatching)
			DebugOutput("InjectDll: IAT patching failed, falling back to thread injection.\n");
		else
			DebugOutput("InjectDll: IAT patching disabled, falling back to thread injection.\n");
#endif
		RetVal = InjectDllViaThread(ProcessHandle, DllPath);
	}

#ifdef DEBUG_COMMENTS
	if (RetVal)
		DebugOutput("InjectDll: Successfully injected DLL.\n");
	else
		DebugOutput("InjectDll: DLL injection failed.\n");
#endif

out:
	if (ProcessHandle)
		CloseHandle(ProcessHandle);
	if (ThreadHandle)
		CloseHandle(ThreadHandle);

	return RetVal;
}

int CreateMonitorPipe(char* Name, char* Dll)
{
	HANDLE PipeHandle;
	char PipeName[BUFSIZE];
	int LastPid = 0;

	if (__argc != 4)
		return 0;

	sprintf_s(PipeName, sizeof(PipeName)-1, "\\\\.\\PIPE\\%s", Name);

	DebugOutput("Loader: Starting pipe %s (DLL to inject %s).\n", PipeName, Dll);

	while (1)
	{
		PipeHandle = CreateNamedPipeA(PipeName, PIPE_ACCESS_DUPLEX,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES,
			PIPEBUFSIZE,
			PIPEBUFSIZE,
			0,
			NULL);

		if (ConnectNamedPipe(PipeHandle, NULL) || GetLastError() == ERROR_PIPE_CONNECTED)
		{
			char buf[PIPEBUFSIZE];
			char response[PIPEBUFSIZE];
			int response_len = 0;
			int bytes_read = 0;
			int BytesWritten = 0;

			memset(buf, 0, sizeof(buf));
			memset(response, 0, sizeof(response));

			ReadFile(PipeHandle, buf, sizeof(buf), &bytes_read, NULL);
			DebugOutput("%s\n", buf);
			if (!strncmp(buf, "PROCESS:", 8)) {
				int ProcessId = -1, ThreadId = -1;
				char *p;
				if ((p = strchr(buf, ','))) {
					*p = '\0';
					ProcessId = atoi(&buf[10]); // skipping the '0:' or '1:' suspended flag
					ThreadId = atoi(p + 1);	 // (soon to be deprecated)
				}
				else {
					ProcessId = atoi(&buf[10]);
				}
				if (ProcessId && ThreadId && ProcessId != LastPid)
				{
					DebugOutput("About to call InjectDll on process %d, thread 5%d.\n", ProcessId, ThreadId);
					if (InjectDll(ProcessId, ThreadId, Dll))
						LastPid = ProcessId;
				}
			}
			WriteFile(PipeHandle, response, response_len, &BytesWritten, NULL);
			CloseHandle(PipeHandle);
		}
	}

}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	DebugOutput("CAPE loader.\n");

	if (__argc < 2)
	{
		DebugOutput("Loader: Error - too few arguments!\n");
		return 0;
	}

	if (!GrantDebugPrivileges())
	{
		DebugOutput("Loader: Error - unable to obtain debug privileges.\n");
		return 0;
	}

	if (!strcmp(__argv[1], "rinject"))
	{
		// usage: loader.exe rinject <pid> <dll to load>
		int ProcessId, ret;
		HANDLE ProcessHandle;
		char *DllName;
		if (__argc < 4)
		{
			DebugOutput("Loader: Error - too few arguments for injection (%d)\n", __argc);
			return 0;
		}

		ProcessId = atoi(__argv[2]);
		DllName = __argv[3];

		if (!ReadConfig(ProcessId, DllName))
			DebugOutput("Loader: Failed to load config for process %d.\n", ProcessId);

		DebugOutput("Loader: Injecting process %d with %s.\n", ProcessId, DllName);

		ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);

		if (ProcessHandle == NULL)
		{
			ErrorOutput("Failed to open process");
			return 0;
		}

		ret = ReflectiveInjectDllViaThread(ProcessHandle, __argv[3]);

		if (ret)
			DebugOutput("Successfully injected DLL %s.\n", __argv[3]);
		else
			DebugOutput("Failed to inject DLL %s.\n", __argv[3]);

		CloseHandle(ProcessHandle);

		return ret;
	}
	else if (!strcmp(__argv[1], "inject"))
	{
		// usage: loader.exe inject <pid> <tid> <dll to load>
		int ProcessId, ThreadId, ret;
		char *DllName;
		if (__argc < 5)
		{
			DebugOutput("Loader: Error - too few arguments for injection (%d)\n", __argc);
			return 0;
		}

		ProcessId = atoi(__argv[2]);
		ThreadId = atoi(__argv[3]);
		DllName = __argv[4];

		if (!ReadConfig(ProcessId, DllName))
			DebugOutput("Loader: Failed to load config for process %d.\n", ProcessId);
#ifdef DEBUG_COMMENTS
		else
			DebugOutput("Loader: Loaded config for process %d.\n", ProcessId);
#endif

		if (ThreadId)
			DebugOutput("Loader: Injecting process %d (thread %d) with %s.\n", ProcessId, ThreadId, DllName);
		else
			DebugOutput("Loader: Injecting process %d with %s.\n", ProcessId, DllName);

		ret = InjectDll(ProcessId, ThreadId, DllName);

		if (ret >= 0)
			DebugOutput("Successfully injected DLL %s.\n", __argv[4]);
		else
			DebugOutput("Failed to inject DLL %s.\n", __argv[4]);

		return ret;
	}
	else if (!strcmp(__argv[1], "load"))
	{
		// usage: loader.exe load <monitor dll> <binary> <commandline>
		DWORD ExplorerPid = 0, ProcessId = 0;
		SIZE_T cbAttributeListSize = 0;
		PROCESS_INFORMATION pi;
		STARTUPINFOEX sie = {sizeof(sie)};
		HANDLE hParentProcess = NULL, ProcessHandle = NULL, ThreadHandle = NULL;
		PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
		char szCommand[2048];
		szCommand[0] = L'\0';
		int ret;

		if (__argv[4] && strlen(__argv[4]))
		{
			StringCchCat(szCommand, sizeof(szCommand), __argv[3]);
			StringCchCat(szCommand, sizeof(szCommand), " ");
			StringCchCat(szCommand, sizeof(szCommand), __argv[4]);
		}
		else
			strncpy(szCommand, __argv[3], strlen(__argv[3])+1);

		DebugOutput("Loader: Loading %s (%s) with DLL %s.\n", __argv[3], szCommand, __argv[2]);

		memset(&sie, 0, sizeof(sie));
		memset(&pi, 0, sizeof(pi));

		DebugOutput("Loader: Executing %s (%s).\n", __argv[3], szCommand);

		InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttributeListSize);

		pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, cbAttributeListSize);

		if (pAttributeList == NULL)
		{
			ErrorOutput("Loader: HeapAlloc error");
			return 0;
		}

		if (!InitializeProcThreadAttributeList(pAttributeList, 1, 0, &cbAttributeListSize))
		{
			ErrorOutput("Loader: InitializeProcThreadAttributeList error");
			return 0;
		}

		// Get the PID of explorer by its windows handle
		GetWindowThreadProcessId(GetShellWindow(), &ExplorerPid);

		// Credit to Didier Stevens - SelectMyParent
		hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ExplorerPid);

		if (hParentProcess == NULL)
		{
			ErrorOutput("Loader: OpenProcess error");
			return 0;
		}

		if (!UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL))
		{
			ErrorOutput("Loader: UpdateProcThreadAttribute error");
			return 0;
		}

		sie.lpAttributeList = pAttributeList;

		if (!CreateProcess(__argv[3], szCommand, NULL, NULL, FALSE, CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &sie.StartupInfo, &pi))
		{
			ErrorOutput("Loader: CreateProcess error");
			return 0;
		}

		DeleteProcThreadAttributeList(pAttributeList);

		CloseHandle(hParentProcess);

		if (!pi.dwProcessId)
		{
			DebugOutput("Loader: Failed to execute %s.\n", __argv[3]);
			return 0;
		}

		if (!ReadConfig(pi.dwProcessId, __argv[2]))
			DebugOutput("Loader: Failed to load config for process %d.\n", pi.dwProcessId);
#ifdef DEBUG_COMMENTS
		else
			DebugOutput("Loader: Loaded config for process %d.\n", pi.dwProcessId);
#endif
		ret = InjectDll(pi.dwProcessId, pi.dwThreadId, __argv[2]);

		if (ret)
			DebugOutput("Successfully injected DLL %s.\n", __argv[2]);
		else
			DebugOutput("Failed to inject DLL %s.\n", __argv[2]);

		ThreadHandle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, pi.dwThreadId);

		if (ThreadHandle)
		{
			ResumeThread(ThreadHandle);
			CloseHandle(ThreadHandle);
		}
		else
			DebugOutput("There was a problem resuming the new process %s.\n", __argv[3]);

		if (!strlen(LogPipe))
			return pi.dwProcessId;

		return CreateMonitorPipe(LogPipe, __argv[2]);
	}
	else if (!strcmp(__argv[1], "shellcode"))
	{
		// usage: loader.exe shellcode <payload file> <offset (optional)>
		HANDLE hInputFile;
		LARGE_INTEGER InputFileSize;
		BYTE *PayloadBuffer = NULL;
		DWORD dwBytesRead = 0;
		unsigned int Offset = 0;

		PSHELLCODE Payload;

		//if (!ReadConfig(GetCurrentProcessId()))
		//	DebugOutput("Loader: Failed to load config for process %d.\n", GetCurrentProcessId());

		hInputFile = CreateFile(__argv[2], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (!hInputFile || hInputFile == INVALID_HANDLE_VALUE)
		{
			ErrorOutput("Error opening input file");
			return 0;
		}

		if (!GetFileSizeEx(hInputFile, &InputFileSize))
		{
			ErrorOutput("Error getting file size");
			return 0;
		}

		if (InputFileSize.HighPart)
		{
			DebugOutput("Input file is too big!.\n");
			return 0;
		}

		PayloadBuffer = (PBYTE)VirtualAlloc(NULL, InputFileSize.LowPart, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (PayloadBuffer == NULL)
		{
			DebugOutput("Error allocating memory for file buffer.\n");
			return 0;
		}

		memset(PayloadBuffer, 0, InputFileSize.LowPart);

		if (FALSE == ReadFile(hInputFile, PayloadBuffer, InputFileSize.LowPart, &dwBytesRead, NULL))
		{
			DebugOutput("ReadFile error on input file.\n");
			return 0;
		}

		if (__argc > 3)
		{
			if (!_strnicmp(__argv[3], "ep", 2) && GetNtHeaders(PayloadBuffer))
				Offset = (unsigned int)GetNtHeaders(PayloadBuffer)->OptionalHeader.AddressOfEntryPoint;
			else
				Offset = strtoul(__argv[3], NULL, 0);
		}

		Payload = (PSHELLCODE)((PBYTE)PayloadBuffer + Offset);

		__try
		{
			Payload();
			DebugOutput("Successfully executed payload at 0x%p.\n", (PBYTE)PayloadBuffer + Offset);
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			DebugOutput("Exception executing payload at 0x%p.\n", (PBYTE)PayloadBuffer + Offset);
		}

		free(PayloadBuffer);
		CloseHandle(hInputFile);
		return 1;
	}
	else if (!strcmp(__argv[1], "pipe"))
	{
		// usage: loader.exe pipe <pipe name> <dll to load>
		return CreateMonitorPipe(__argv[2], __argv[3]);
	}
	return 0;
}
