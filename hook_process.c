/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2015 Cuckoo Sandbox Developers, Optiv, Inc. (brad.spengler@optiv.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include "ntapi.h"
#include <tlhelp32.h>
#include <psapi.h>
#include "hooking.h"
#include "log.h"
#include "pipe.h"
#include "misc.h"
#include "ignore.h"
#include "hook_sleep.h"
#include "unhook.h"
#include "config.h"
#include "CAPE\CAPE.h"
#include "CAPE\Debugger.h"
#include "CAPE\Injection.h"
#include "CAPE\Unpacker.h"

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern void ErrorOutput(_In_ LPCTSTR lpOutputString, ...);
extern struct TrackedRegion *TrackedRegionList;
extern void AllocationHandler(PVOID BaseAddress, SIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
extern void DebuggerAllocationHandler(PVOID BaseAddress, SIZE_T RegionSize, ULONG Protect);
extern void ProtectionHandler(PVOID BaseAddress, ULONG Protect, PULONG OldProtect);
extern void FreeHandler(PVOID BaseAddress), ProcessMessage(DWORD ProcessId, DWORD ThreadId);
extern void ProcessTrackedRegion(), DebuggerShutdown(), DumpStrings();

extern lookup_t g_caller_regions;
extern HANDLE g_terminate_event_handle;
extern BOOL CAPEExceptionDispatcher(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context);
extern void file_handle_terminate();
extern int DoProcessDump();
extern PVOID GetHookCallerBase();
extern BOOL ProcessDumped;

static BOOL ntdll_protect_logged;

HOOKDEF(HANDLE, WINAPI, CreateToolhelp32Snapshot,
	__in DWORD dwFlags,
	__in DWORD th32ProcessID
) {
	HANDLE ret = Old_CreateToolhelp32Snapshot(dwFlags, th32ProcessID);

	LOQ_handle("process", "hi", "Flags", dwFlags, "ProcessId", th32ProcessID);

	return ret;
}

HOOKDEF(BOOL, WINAPI, Process32NextW,
	__in HANDLE hSnapshot,
	__out LPPROCESSENTRY32W lppe
	) {
	BOOL ret = Old_Process32NextW(hSnapshot, lppe);

	/* skip returning protected processes */
	while (ret && lppe && is_protected_pid(lppe->th32ProcessID))
		ret = Old_Process32NextW(hSnapshot, lppe);

	if (ret)
		LOQ_bool("process", "ui", "ProcessName", lppe->szExeFile, "ProcessId", lppe->th32ProcessID);
	else
		LOQ_bool("process", "");

	return ret;
}

HOOKDEF(BOOL, WINAPI, Process32FirstW,
	__in HANDLE hSnapshot,
	__out LPPROCESSENTRY32W lppe
	) {
	BOOL ret = Old_Process32FirstW(hSnapshot, lppe);

	/* skip returning protected processes */
	while (ret && lppe && is_protected_pid(lppe->th32ProcessID))
		ret = Old_Process32NextW(hSnapshot, lppe);

	if (ret)
		LOQ_bool("process", "ui", "ProcessName", lppe->szExeFile, "ProcessId", lppe->th32ProcessID);
	else
		LOQ_bool("process", "");

	return ret;
}

HOOKDEF(BOOL, WINAPI, Module32NextW,
	__in HANDLE hSnapshot,
	__out LPMODULEENTRY32W lpme
	) {
	BOOL ret = Old_Module32NextW(hSnapshot, lpme);

	if (ret)
		LOQ_bool("process", "uii", "ModuleName", lpme->szModule, "ModuleID", lpme->th32ModuleID, "ProcessId", lpme->th32ProcessID);
	else
		LOQ_bool("process", "");

	return ret;
}

HOOKDEF(BOOL, WINAPI, Module32FirstW,
	__in HANDLE hSnapshot,
	__out LPMODULEENTRY32W lpme
	) {
	BOOL ret = Old_Module32FirstW(hSnapshot, lpme);

	if (ret)
		LOQ_bool("process", "uii", "ModuleName", lpme->szModule, "ModuleID", lpme->th32ModuleID, "ProcessId", lpme->th32ProcessID);
	else
		LOQ_bool("process", "");

	return ret;
}

HOOKDEF(UINT, WINAPI, WinExec,
	__in LPCSTR lpCmdLine,
	__in UINT   uCmdShow
) {
	UINT ret = Old_WinExec(lpCmdLine, uCmdShow);
	LOQ_nonzero("process", "si", "CmdLine", lpCmdLine, "CmdShow", uCmdShow);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CreateProcessA,
	__in_opt	LPCSTR lpApplicationName,
	__inout_opt LPSTR lpCommandLine,
	__in_opt	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	__in_opt	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	__in		BOOL bInheritHandles,
	__in		DWORD dwCreationFlags,
	__in_opt	LPVOID lpEnvironment,
	__in_opt	LPCSTR lpCurrentDirectory,
	__in		LPSTARTUPINFOA lpStartupInfo,
	__out	    LPPROCESS_INFORMATION lpProcessInformation
) {
	BOOL ret;
	ENSURE_STRUCT(lpProcessInformation, PROCESS_INFORMATION);

	ret = Old_CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
		bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

	if (dwCreationFlags & EXTENDED_STARTUPINFO_PRESENT && lpStartupInfo->cb == sizeof(STARTUPINFOEXA)) {
		HANDLE ParentHandle = (HANDLE)-1;
		unsigned int i;
		LPSTARTUPINFOEXA lpExtStartupInfo = (LPSTARTUPINFOEXA)lpStartupInfo;
		if (lpExtStartupInfo->lpAttributeList) {
			for (i = 0; i < lpExtStartupInfo->lpAttributeList->Count; i++)
				if (lpExtStartupInfo->lpAttributeList->Entries[i].Attribute == PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)
					ParentHandle = *(HANDLE *)lpExtStartupInfo->lpAttributeList->Entries[i].lpValue;
		}
		LOQ_bool("process", "sshiippps", "ApplicationName", lpApplicationName,
			"CommandLine", lpCommandLine, "CreationFlags", dwCreationFlags,
			"ProcessId", lpProcessInformation->dwProcessId,
			"ThreadId", lpProcessInformation->dwThreadId,
			"ParentHandle", ParentHandle,
			"ProcessHandle", lpProcessInformation->hProcess,
			"ThreadHandle", lpProcessInformation->hThread, "StackPivoted", is_stack_pivoted() ? "yes" : "no");
	}
	else {
		LOQ_bool("process", "sshiipps", "ApplicationName", lpApplicationName,
			"CommandLine", lpCommandLine, "CreationFlags", dwCreationFlags,
			"ProcessId", lpProcessInformation->dwProcessId,
			"ThreadId", lpProcessInformation->dwThreadId,
			"ProcessHandle", lpProcessInformation->hProcess,
			"ThreadHandle", lpProcessInformation->hThread, "StackPivoted", is_stack_pivoted() ? "yes" : "no");
	}

	return ret;
}

HOOKDEF(BOOL, WINAPI, CreateProcessW,
	__in_opt	LPWSTR lpApplicationName,
	__inout_opt LPWSTR lpCommandLine,
	__in_opt	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	__in_opt	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	__in		BOOL bInheritHandles,
	__in		DWORD dwCreationFlags,
	__in_opt	LPVOID lpEnvironment,
	__in_opt	LPWSTR lpCurrentDirectory,
	__in		LPSTARTUPINFOW lpStartupInfo,
	__out	    LPPROCESS_INFORMATION lpProcessInformation
) {
	BOOL ret;
	ENSURE_STRUCT(lpProcessInformation, PROCESS_INFORMATION);

	ret = Old_CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
		bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

	if (dwCreationFlags & EXTENDED_STARTUPINFO_PRESENT && lpStartupInfo->cb == sizeof(STARTUPINFOEXW)) {
		HANDLE ParentHandle = (HANDLE)-1;
		unsigned int i;
		LPSTARTUPINFOEXW lpExtStartupInfo = (LPSTARTUPINFOEXW)lpStartupInfo;
		if (lpExtStartupInfo->lpAttributeList) {
			for (i = 0; i < lpExtStartupInfo->lpAttributeList->Count; i++)
				if (lpExtStartupInfo->lpAttributeList->Entries[i].Attribute == PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)
					ParentHandle = *(HANDLE *)lpExtStartupInfo->lpAttributeList->Entries[i].lpValue;
		}
		LOQ_bool("process", "uuhiippps", "ApplicationName", lpApplicationName,
			"CommandLine", lpCommandLine, "CreationFlags", dwCreationFlags,
			"ProcessId", lpProcessInformation->dwProcessId,
			"ThreadId", lpProcessInformation->dwThreadId,
			"ParentHandle", ParentHandle,
			"ProcessHandle", lpProcessInformation->hProcess,
			"ThreadHandle", lpProcessInformation->hThread, "StackPivoted", is_stack_pivoted() ? "yes" : "no");
	}
	else {
		LOQ_bool("process", "uuhiipps", "ApplicationName", lpApplicationName,
			"CommandLine", lpCommandLine, "CreationFlags", dwCreationFlags,
			"ProcessId", lpProcessInformation->dwProcessId,
			"ThreadId", lpProcessInformation->dwThreadId,
			"ProcessHandle", lpProcessInformation->hProcess,
			"ThreadHandle", lpProcessInformation->hThread, "StackPivoted", is_stack_pivoted() ? "yes" : "no");
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateProcess,
	__out	   PHANDLE ProcessHandle,
	__in		ACCESS_MASK DesiredAccess,
	__in_opt	POBJECT_ATTRIBUTES ObjectAttributes,
	__in		HANDLE ParentProcess,
	__in		BOOLEAN InheritObjectTable,
	__in_opt	HANDLE SectionHandle,
	__in_opt	HANDLE DebugPort,
	__in_opt	HANDLE ExceptionPort
) {
	NTSTATUS ret = Old_NtCreateProcess(ProcessHandle, DesiredAccess,
		ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle,
		DebugPort, ExceptionPort);
	DWORD pid = pid_from_process_handle(*ProcessHandle);
	LOQ_ntstatus("process", "PphOl", "ProcessHandle", ProcessHandle, "ParentHandle", ParentProcess, "DesiredAccess", DesiredAccess,
		"FileName", ObjectAttributes, "ProcessId", pid);
	if (!g_config.single_process && NT_SUCCESS(ret)) {
		ProcessMessage(pid, 0);
		disable_sleep_skip();
	}
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateProcessEx,
	__out	   PHANDLE ProcessHandle,
	__in		ACCESS_MASK DesiredAccess,
	__in_opt	POBJECT_ATTRIBUTES ObjectAttributes,
	__in		HANDLE ParentProcess,
	__in		ULONG Flags,
	__in_opt	HANDLE SectionHandle,
	__in_opt	HANDLE DebugPort,
	__in_opt	HANDLE ExceptionPort,
	__in		ULONG JobMemberLevel
) {
	NTSTATUS ret = Old_NtCreateProcessEx(ProcessHandle, DesiredAccess,
		ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort,
		ExceptionPort, JobMemberLevel);
	DWORD pid = pid_from_process_handle(*ProcessHandle);
	LOQ_ntstatus("process", "PphOhhl", "ProcessHandle", ProcessHandle, "ParentHandle", ParentProcess, "DesiredAccess", DesiredAccess,
		"FileName", ObjectAttributes, "Flags", Flags, "SectionHandle", SectionHandle, "ProcessId", pid);
	if (!g_config.single_process && NT_SUCCESS(ret)) {
		ProcessMessage(pid, 0);
		disable_sleep_skip();
	}
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateUserProcess,
	__out	   PHANDLE ProcessHandle,
	__out	   PHANDLE ThreadHandle,
	__in		ACCESS_MASK ProcessDesiredAccess,
	__in		ACCESS_MASK ThreadDesiredAccess,
	__in_opt	POBJECT_ATTRIBUTES ProcessObjectAttributes,
	__in_opt	POBJECT_ATTRIBUTES ThreadObjectAttributes,
	__in		ULONG ProcessFlags,
	__in		ULONG ThreadFlags,
	__in_opt	PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	__inout	 PPS_CREATE_INFO CreateInfo,
	__in_opt	PPS_ATTRIBUTE_LIST AttributeList
) {
	RTL_USER_PROCESS_PARAMETERS _ProcessParameters;
	NTSTATUS ret;

	memset(&_ProcessParameters, 0, sizeof(_ProcessParameters));

	if (ProcessParameters == NULL)
		ProcessParameters = &_ProcessParameters;
	ret = Old_NtCreateUserProcess(ProcessHandle, ThreadHandle,
		ProcessDesiredAccess, ThreadDesiredAccess,
		ProcessObjectAttributes, ThreadObjectAttributes,
		ProcessFlags, ThreadFlags | 1, ProcessParameters,
		CreateInfo, AttributeList);
	DWORD pid = pid_from_process_handle(*ProcessHandle);
	LOQ_ntstatus("process", "PPhhOOool", "ProcessHandle", ProcessHandle,
		"ThreadHandle", ThreadHandle,
		"ProcessDesiredAccess", ProcessDesiredAccess,
		"ThreadDesiredAccess", ThreadDesiredAccess,
		"ProcessFileName", ProcessObjectAttributes,
		"ThreadName", ThreadObjectAttributes,
		"ImagePathName", &ProcessParameters->ImagePathName,
		"CommandLine", &ProcessParameters->CommandLine,
		"ProcessId", pid);
	if (NT_SUCCESS(ret)) {
		DWORD tid = tid_from_thread_handle(*ThreadHandle);
		if (!g_config.single_process) {
			PROCESS_INFORMATION ProcessInformation;
			ProcessInformation.dwProcessId = pid;
			ProcessInformation.dwThreadId = tid;
			ProcessInformation.hProcess = (*ProcessHandle);
			ProcessInformation.hThread = (*ThreadHandle);
			CreateProcessHandler(ProcessParameters->ImagePathName.Buffer, NULL, &ProcessInformation);
			ProcessMessage(pid, tid);
		}
		if (!(ThreadFlags & 1))
			ResumeThread(*ThreadHandle);
		disable_sleep_skip();
	}
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, RtlCreateUserProcess,
	IN	  PUNICODE_STRING ImagePath,
	IN	  ULONG ObjectAttributes,
	IN OUT  PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	IN	  PSECURITY_DESCRIPTOR ProcessSecurityDescriptor OPTIONAL,
	IN	  PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
	IN	  HANDLE ParentProcess,
	IN	  BOOLEAN InheritHandles,
	IN	  HANDLE DebugPort OPTIONAL,
	IN	  HANDLE ExceptionPort OPTIONAL,
	OUT	 PRTL_USER_PROCESS_INFORMATION ProcessInformation
) {
	NTSTATUS ret = Old_RtlCreateUserProcess(ImagePath, ObjectAttributes,
		ProcessParameters, ProcessSecurityDescriptor,
		ThreadSecurityDescriptor, ParentProcess, InheritHandles, DebugPort,
		ExceptionPort, ProcessInformation);
	DWORD pid = pid_from_process_handle(ProcessInformation->ProcessHandle);
	LOQ_ntstatus("process", "ohpl", "ImagePath", ImagePath, "ObjectAttributes", ObjectAttributes,
		"ParentHandle", ParentProcess, "ProcessId", pid);
	if (NT_SUCCESS(ret)) {
		DWORD tid = tid_from_thread_handle(ProcessInformation->ThreadHandle);
		if (!g_config.single_process) {
			PROCESS_INFORMATION WinProcessInformation;
			WinProcessInformation.dwProcessId = (DWORD)(DWORD_PTR)ProcessInformation->ClientId.UniqueProcess;
			WinProcessInformation.dwThreadId = (DWORD)(DWORD_PTR)ProcessInformation->ClientId.UniqueThread;
			WinProcessInformation.hProcess = ProcessInformation->ProcessHandle;
			WinProcessInformation.hThread = ProcessInformation->ThreadHandle;
			CreateProcessHandler(ProcessParameters->ImagePathName.Buffer, NULL, &WinProcessInformation);
			ProcessMessage(pid, tid);
		}
		disable_sleep_skip();
	}
	return ret;
}

HOOKDEF(BOOL, WINAPI, CreateProcessWithLogonW,
	_In_		LPCWSTR			   lpUsername,
	_In_opt_	LPCWSTR			   lpDomain,
	_In_		LPCWSTR			   lpPassword,
	_In_		DWORD				 dwLogonFlags,
	_In_opt_	LPCWSTR			   lpApplicationName,
	_Inout_opt_ LPWSTR				lpCommandLine,
	_In_		DWORD				 dwCreationFlags,
	_In_opt_	LPVOID				lpEnvironment,
	_In_opt_	LPCWSTR			   lpCurrentDirectory,
	_In_		LPSTARTUPINFOW		lpStartupInfo,
	_Out_	   LPPROCESS_INFORMATION lpProcessInfo
) {
	BOOL ret;
	LPWSTR origcommandline = NULL;
	ENSURE_STRUCT(lpProcessInfo, PROCESS_INFORMATION);

	if (lpCommandLine)
		origcommandline = wcsdup(lpCommandLine);

	ret = Old_CreateProcessWithLogonW(lpUsername, lpDomain, lpPassword, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInfo);

	LOQ_bool("process", "uuuhuuhiipp",
		"Username", lpUsername,
		"Domain", lpDomain,
		"Password", lpPassword,
		"LogonFlags", dwLogonFlags,
		"ApplicationName", lpApplicationName,
		"CommandLine", origcommandline,
		"CreationFlags", dwCreationFlags,
		"ProcessId", lpProcessInfo->dwProcessId,
		"ThreadId", lpProcessInfo->dwThreadId,
		"ProcessHandle", lpProcessInfo->hProcess,
		"ThreadHandle", lpProcessInfo->hThread
	);

	if (origcommandline)
		free(origcommandline);

	if (ret) {
		if (!g_config.single_process) {
			CreateProcessHandler((LPWSTR)lpApplicationName, lpCommandLine, lpProcessInfo);
			ProcessMessage(lpProcessInfo->dwProcessId, lpProcessInfo->dwThreadId);
		}
		if (!(dwCreationFlags & CREATE_SUSPENDED) && is_valid_address_range((ULONG_PTR)lpProcessInfo, (DWORD)sizeof(PROCESS_INFORMATION)))
			ResumeThread(lpProcessInfo->hThread);
		disable_sleep_skip();
	}
	return ret;
}

HOOKDEF(BOOL, WINAPI, CreateProcessWithTokenW,
	_In_		HANDLE				hToken,
	_In_		DWORD				 dwLogonFlags,
	_In_opt_	LPCWSTR			   lpApplicationName,
	_Inout_opt_ LPWSTR				lpCommandLine,
	_In_		DWORD				 dwCreationFlags,
	_In_opt_	LPVOID				lpEnvironment,
	_In_opt_	LPCWSTR			   lpCurrentDirectory,
	_In_		LPSTARTUPINFOW		lpStartupInfo,
	_Out_	   LPPROCESS_INFORMATION lpProcessInfo
) {
	BOOL ret;
	LPWSTR origcommandline = NULL;

	if (lpCommandLine)
		origcommandline = wcsdup(lpCommandLine);

	ret = Old_CreateProcessWithTokenW(hToken, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInfo);

	if (lpProcessInfo) {
		LOQ_bool("process", "huuhiipp",
			"LogonFlags", dwLogonFlags,
			"ApplicationName", lpApplicationName,
			"CommandLine", origcommandline,
			"CreationFlags", dwCreationFlags,
			"ProcessId", lpProcessInfo->dwProcessId,
			"ThreadId", lpProcessInfo->dwThreadId,
			"ProcessHandle", lpProcessInfo->hProcess,
			"ThreadHandle", lpProcessInfo->hThread
		);
	}
	else {
		LOQ_bool("process", "huuhiipp",
			"LogonFlags", dwLogonFlags,
			"ApplicationName", lpApplicationName,
			"CommandLine", origcommandline,
			"CreationFlags", dwCreationFlags,
			"ProcessId", NULL,
			"ThreadId", NULL,
			"ProcessHandle", NULL,
			"ThreadHandle", NULL
		);
	}

	if (origcommandline)
		free(origcommandline);

	if (ret && lpProcessInfo) {
		if (!g_config.single_process) {
			CreateProcessHandler((LPWSTR)lpApplicationName, lpCommandLine, lpProcessInfo);
			ProcessMessage(lpProcessInfo->dwProcessId, lpProcessInfo->dwThreadId);
		}
		if (!(dwCreationFlags & CREATE_SUSPENDED))
			ResumeThread(lpProcessInfo->hThread);
		disable_sleep_skip();
	}
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenProcess,
	__out	 PHANDLE ProcessHandle,
	__in	  ACCESS_MASK DesiredAccess,
	__in	  POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt  PCLIENT_ID ClientId
) {
	// although the documentation on msdn is a bit vague, this seems correct
	// for both XP and Vista (the ClientId->UniqueProcess part, that is)

	int pid = 0;
	NTSTATUS ret;

	if (ClientId != NULL) {
		__try {
			pid = (int)(ULONG_PTR)ClientId->UniqueProcess;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
	}

	if (is_protected_pid(pid)) {
		ret = STATUS_ACCESS_DENIED;
		LOQ_ntstatus("process", "ppl", "ProcessHandle", NULL, "DesiredAccess", DesiredAccess,
			"ProcessIdentifier", pid);
		return ret;
	}

	ret = Old_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

	if (NT_SUCCESS(ret) && g_config.injection)
		OpenProcessHandler(*ProcessHandle, pid);

	LOQ_ntstatus("process", "Phi", "ProcessHandle", ProcessHandle,
		"DesiredAccess", DesiredAccess,
		"ProcessIdentifier", pid);

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenProcessToken,
	__in HANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__out PHANDLE TokenHandle
) {
	NTSTATUS ret;
	ret = Old_NtOpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle);
	LOQ_ntstatus("process", "phP", "ProcessHandle", ProcessHandle, "DesiredAccess", DesiredAccess, "TokenHandle", TokenHandle);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryInformationToken,
	IN HANDLE TokenHandle,
	IN TOKEN_INFORMATION_CLASS TokenInformationClass,
	OUT PVOID TokenInformation,
	IN ULONG TokenInformationLength,
	OUT PULONG ReturnLength OPTIONAL
) {
	NTSTATUS ret = Old_NtQueryInformationToken(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength);
	LOQ_ntstatus("process", "ib", "TokenInformationClass", TokenInformationClass, "TokenInformation", TokenInformationLength, TokenInformation);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtResumeProcess,
	__in  HANDLE ProcessHandle
) {
	NTSTATUS ret;
	DWORD pid = pid_from_process_handle(ProcessHandle);
	if (g_config.injection)
		ResumeProcessHandler(ProcessHandle, pid);
	pipe("RESUME:%d", pid);
	ret = Old_NtResumeProcess(ProcessHandle);
	LOQ_ntstatus("process", "pl", "ProcessHandle", ProcessHandle, "ProcessId", pid);
	return ret;
}

int process_shutting_down;

HOOKDEF(NTSTATUS, WINAPI, NtTerminateProcess,
	__in_opt  HANDLE ProcessHandle,
	__in	  NTSTATUS ExitStatus
) {
	// Process will terminate. Default logging will not work. Be aware: return value not valid
	lasterror_t lasterror;
	get_lasterrors(&lasterror);
	NTSTATUS ret = 0;
	DWORD Pid = 0;

	if (ProcessHandle == NULL) {
		// we mark this here as this termination type will kill all threads but ours, including
		// the logging thread.  By setting this, we'll switch into a direct logging mode
		// for the subsequent call to NtTerminateProcess against our own process handle
		process_shutting_down = 1;
		LOQ_ntstatus("process", "ph", "ProcessHandle", ProcessHandle, "ExitCode", ExitStatus);
		file_handle_terminate();
	}
	else if (NtCurrentProcess() == ProcessHandle) {
		Pid = GetCurrentProcessId();
		process_shutting_down = 1;
		LOQ_ntstatus("process", "ph", "ProcessHandle", ProcessHandle, "ExitCode", ExitStatus);
		log_free();
		file_handle_terminate();
	}
	else {
		Pid = pid_from_process_handle(ProcessHandle);
		if (is_protected_pid(Pid)) {
			ret = STATUS_ACCESS_DENIED;
			LOQ_ntstatus("process", "ph", "ProcessHandle", ProcessHandle, "ExitCode", ExitStatus);
			return ret;
		}
		else {
			LOQ_ntstatus("process", "ph", "ProcessHandle", ProcessHandle, "ExitCode", ExitStatus);
		}
	}

	if (Pid)
		pipe("KILL:%d", Pid);

	DumpStrings();

	if (process_shutting_down && g_config.injection)
		TerminateHandler();

	if (process_shutting_down && g_config.debugger)
		DebuggerShutdown();

	if (process_shutting_down && g_config.procdump && !ProcessDumped) {
		DebugOutput("NtTerminateProcess hook: Attempting to dump process %d\n", GetCurrentProcessId());
		DoProcessDump();
	}

	set_lasterrors(&lasterror);
	ret = Old_NtTerminateProcess(ProcessHandle, ExitStatus);
	return ret;
}

// We typically don't want WER to spawn werfault.exe in the sandbox
#define ALLOW_WER 0

HOOKDEF(NTSTATUS, WINAPI,  RtlReportSilentProcessExit,
	__in_opt  HANDLE ProcessHandle,
	__in	  NTSTATUS ExitStatus
)
{
	NTSTATUS ret = 0;
	DWORD pid = pid_from_process_handle(ProcessHandle);
	if (ALLOW_WER)
		ret = Old_RtlReportSilentProcessExit(ProcessHandle, ExitStatus);
	return ret;
}

extern void file_write(HANDLE file_handle);

HOOKDEF(NTSTATUS, WINAPI, NtCreateSection,
	__out	 PHANDLE SectionHandle,
	__in	  ACCESS_MASK DesiredAccess,
	__in_opt  POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt  PLARGE_INTEGER MaximumSize,
	__in	  ULONG SectionPageProtection,
	__in	  ULONG AllocationAttributes,
	__in_opt  HANDLE FileHandle
) {
	NTSTATUS ret = Old_NtCreateSection(SectionHandle, DesiredAccess,
		ObjectAttributes, MaximumSize, SectionPageProtection,
		AllocationAttributes, FileHandle);
	LOQ_ntstatus("process", "Phop", "SectionHandle", SectionHandle,
		"DesiredAccess", DesiredAccess, "ObjectAttributes", ObjectAttributes ? ObjectAttributes->ObjectName : NULL,
		"FileHandle", FileHandle);

	if (NT_SUCCESS(ret) && FileHandle && (DesiredAccess & SECTION_MAP_WRITE)) {
		file_write(FileHandle);
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenSection,
	__out  PHANDLE SectionHandle,
	__in   ACCESS_MASK DesiredAccess,
	__in   POBJECT_ATTRIBUTES ObjectAttributes
) {
	NTSTATUS ret = Old_NtOpenSection(SectionHandle, DesiredAccess,
		ObjectAttributes);
	LOQ_ntstatus("process", "Ppo", "SectionHandle", SectionHandle, "DesiredAccess", DesiredAccess,
		"ObjectAttributes", ObjectAttributes ? ObjectAttributes->ObjectName : NULL);
	return ret;
}

HOOKDEF(BOOL, WINAPI, ShellExecuteExW,
	__inout  SHELLEXECUTEINFOW *pExecInfo
) {
	BOOL ret = Old_ShellExecuteExW(pExecInfo);
	if (pExecInfo->lpFile && lstrlenW(pExecInfo->lpFile) > 2 &&
		pExecInfo->lpFile[1] == L':' && pExecInfo->lpFile[2] == L'\\') {
		LOQ_bool("process", "Fui", "FilePath", pExecInfo->lpFile,
			"Parameters", pExecInfo->lpParameters, "Show", pExecInfo->nShow);
	} else {
		LOQ_bool("process", "uui", "FilePath", pExecInfo->lpFile,
			"Parameters", pExecInfo->lpParameters, "Show", pExecInfo->nShow);
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtMapViewOfSection,
	__in	 HANDLE SectionHandle,
	__in	 HANDLE ProcessHandle,
	__inout  PVOID *BaseAddress,
	__in	 ULONG_PTR ZeroBits,
	__in	 SIZE_T CommitSize,
	__inout  PLARGE_INTEGER SectionOffset,
	__inout  PSIZE_T ViewSize,
	__in	 UINT InheritDisposition,
	__in	 ULONG AllocationType,
	__in	 ULONG Win32Protect
) {
	char *ModuleName = NULL;
	unsigned int DllRVA;

	NTSTATUS ret = Old_NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits,
		CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
	DWORD pid = pid_from_process_handle(ProcessHandle);

	ModuleName = convert_address_to_dll_name_and_offset((ULONG_PTR)*BaseAddress, &DllRVA);

	if (!ModuleName)
		LOQ_ntstatus("process", "ppPpPhs", "SectionHandle", SectionHandle,"ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
			"SectionOffset", SectionOffset, "ViewSize", ViewSize, "Win32Protect", Win32Protect, "StackPivoted", is_stack_pivoted() ? "yes" : "no");
	else
		LOQ_ntstatus("process", "ppPspPhs", "SectionHandle", SectionHandle,"ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
			"ModuleName", ModuleName, "SectionOffset", SectionOffset, "ViewSize", ViewSize, "Win32Protect", Win32Protect, "StackPivoted", is_stack_pivoted() ? "yes" : "no");

	if (NT_SUCCESS(ret)) {
		if (g_config.injection)
			MapSectionViewHandler(ProcessHandle, SectionHandle, *BaseAddress, *ViewSize);
		if (!g_config.single_process && pid != GetCurrentProcessId()) {
			ProcessMessage(pid, 0);
			disable_sleep_skip();
		}
		else if (ret == STATUS_IMAGE_NOT_AT_BASE && Win32Protect == PAGE_READONLY) {
			prevent_module_reloading(BaseAddress);
		}
	}

	if (ModuleName)
		free(ModuleName);

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtMapViewOfSectionEx,
	__in	 	HANDLE SectionHandle,
	__in	 	HANDLE ProcessHandle,
	__inout  	PVOID *BaseAddress,
	__inout  	PLARGE_INTEGER SectionOffset,
	__inout  	PSIZE_T ViewSize,
	__in	 	ULONG AllocationType,
	__in	 	ULONG Win32Protect,
	__inout_opt	MEM_EXTENDED_PARAMETER *Parameters,
	__in	 	ULONG ParameterCount
) {
	NTSTATUS ret = Old_NtMapViewOfSectionEx(SectionHandle, ProcessHandle, BaseAddress, SectionOffset, ViewSize,
		AllocationType, Win32Protect, Parameters, ParameterCount);
	DWORD pid = pid_from_process_handle(ProcessHandle);

	LOQ_ntstatus("process", "ppPpPhs", "SectionHandle", SectionHandle,"ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
	"SectionOffset", SectionOffset, "ViewSize", ViewSize, "Win32Protect", Win32Protect, "StackPivoted", is_stack_pivoted() ? "yes" : "no");

	if (NT_SUCCESS(ret)) {
		if (g_config.injection)
			MapSectionViewHandler(ProcessHandle, SectionHandle, *BaseAddress, *ViewSize);
		if (!g_config.single_process && pid != GetCurrentProcessId()) {
			ProcessMessage(pid, 0);
			disable_sleep_skip();
		}
		else if (ret == STATUS_IMAGE_NOT_AT_BASE && Win32Protect == PAGE_READONLY) {
			prevent_module_reloading(BaseAddress);
		}
	}
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtUnmapViewOfSection,
	__in	  HANDLE ProcessHandle,
	__in_opt  PVOID BaseAddress
) {
	SIZE_T map_size = 0; MEMORY_BASIC_INFORMATION mbi;
	DWORD pid = pid_from_process_handle(ProcessHandle);
	NTSTATUS ret;

	if (VirtualQueryEx(ProcessHandle, BaseAddress, &mbi, sizeof(mbi)) == sizeof(mbi))
		map_size = mbi.RegionSize;

	if (g_config.injection)
		UnmapSectionViewHandler(BaseAddress);

	if (!prevent_module_unloading(BaseAddress))
		ret = STATUS_SUCCESS;
	else
		ret = Old_NtUnmapViewOfSection(ProcessHandle, BaseAddress);

	LOQ_ntstatus("process", "ppp", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress, "RegionSize", map_size);

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtUnmapViewOfSectionEx,
	__in	  HANDLE ProcessHandle,
	__in_opt  PVOID BaseAddress,
	__in	  ULONG Flags
) {
	SIZE_T map_size = 0; MEMORY_BASIC_INFORMATION mbi;
	DWORD pid = pid_from_process_handle(ProcessHandle);
	NTSTATUS ret;

	if (VirtualQueryEx(ProcessHandle, BaseAddress, &mbi, sizeof(mbi)) == sizeof(mbi))
		map_size = mbi.RegionSize;

	if (g_config.injection)
		UnmapSectionViewHandler(BaseAddress);

	if (!prevent_module_unloading(BaseAddress))
		ret = STATUS_SUCCESS;
	else
		ret = Old_NtUnmapViewOfSectionEx(ProcessHandle, BaseAddress, Flags);

	LOQ_ntstatus("process", "pppi", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress, "RegionSize", map_size, "Flags", Flags);

	return ret;
}

HOOKDEF(HMODULE, WINAPI, LoadLibraryExW,
	__in	  LPCWSTR lpLibFileName,
	__in	  HANDLE  hFile,
	__in	  DWORD   dwFlags
) {
	HMODULE ret = Old_LoadLibraryExW(lpLibFileName, hFile, dwFlags);
	LOQ_nonnull("system", "uh", "lpLibFileName", lpLibFileName, "dwFlags", dwFlags);
	return ret;
}

// it's not safe to call pipe() in this hook until we replace all uses of snprintf in pipe()
HOOKDEF(NTSTATUS, WINAPI, NtAllocateVirtualMemory,
	__in	 HANDLE ProcessHandle,
	__inout  PVOID *BaseAddress,
	__in	 ULONG_PTR ZeroBits,
	__inout  PSIZE_T RegionSize,
	__in	 ULONG AllocationType,
	__in	 ULONG Protect
) {
	NTSTATUS ret = Old_NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

	if (NT_SUCCESS(ret) && !called_by_hook() && NtCurrentProcess() == ProcessHandle) {
		if (g_config.unpacker)
			AllocationHandler(*BaseAddress, *RegionSize, AllocationType, Protect);

		if (g_config.base_on_alloc)
			DebuggerAllocationHandler(*BaseAddress, *RegionSize, Protect);
	}

	LOQ_ntstatus("process", "pPPhs", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
		"RegionSize", RegionSize, "Protection", Protect, "StackPivoted", is_stack_pivoted() ? "yes" : "no");

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtAllocateVirtualMemoryEx,
	__in	 HANDLE ProcessHandle,
	__inout  PVOID *BaseAddress,
	__inout  PSIZE_T RegionSize,
	__in	 ULONG AllocationType,
	__in	 ULONG PageProtection,
	__inout  MEM_EXTENDED_PARAMETER *Parameters,
	__in	 ULONG ParameterCount
) {
	NTSTATUS ret = Old_NtAllocateVirtualMemoryEx(ProcessHandle, BaseAddress, RegionSize, AllocationType, PageProtection, Parameters, ParameterCount);

	if (NT_SUCCESS(ret) && !called_by_hook() && NtCurrentProcess() == ProcessHandle) {
		if (g_config.unpacker)
			AllocationHandler(*BaseAddress, *RegionSize, AllocationType, PageProtection);

		if (g_config.base_on_alloc)
			DebuggerAllocationHandler(*BaseAddress, *RegionSize, PageProtection);
	}

	LOQ_ntstatus("process", "pPPhs", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
		"RegionSize", RegionSize, "Protection", PageProtection, "StackPivoted", is_stack_pivoted() ? "yes" : "no");

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtReadVirtualMemory,
	__in		HANDLE ProcessHandle,
	__in		LPCVOID BaseAddress,
	__out	   LPVOID Buffer,
	__in		SIZE_T NumberOfBytesToRead,
	__out_opt   PSIZE_T NumberOfBytesRead
) {
	NTSTATUS ret;
	ENSURE_SIZET(NumberOfBytesRead);

	ret = Old_NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);

	LOQ_ntstatus("process", "pphB", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress, "Size", NumberOfBytesToRead, "Buffer", NumberOfBytesRead, Buffer);

	return ret;
}

HOOKDEF(BOOL, WINAPI, ReadProcessMemory,
	_In_	HANDLE hProcess,
	_In_	LPCVOID lpBaseAddress,
	_Out_   LPVOID lpBuffer,
	_In_	SIZE_T nSize,
	_Out_   PSIZE_T lpNumberOfBytesRead
) {
	BOOL ret;
	ENSURE_SIZET(lpNumberOfBytesRead);

	ret = Old_ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);

	LOQ_bool("process", "pphB", "ProcessHandle", hProcess, "BaseAddress", lpBaseAddress, "Size", nSize, "Buffer", lpNumberOfBytesRead, lpBuffer);

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtWriteVirtualMemory,
	__in		HANDLE ProcessHandle,
	__in		LPVOID BaseAddress,
	__in		LPCVOID Buffer,
	__in		SIZE_T NumberOfBytesToWrite,
	__out_opt   PSIZE_T NumberOfBytesWritten
) {
	NTSTATUS ret;
	DWORD pid;
	ENSURE_SIZET(NumberOfBytesWritten);

	ret = Old_NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer,
		NumberOfBytesToWrite, NumberOfBytesWritten);

	pid = pid_from_process_handle(ProcessHandle);

	LOQ_ntstatus("process", "ppBhs",
		"ProcessHandle", ProcessHandle,
		"BaseAddress", BaseAddress,
		"Buffer", NumberOfBytesWritten, Buffer,
		"BufferLength", is_valid_address_range((ULONG_PTR)NumberOfBytesWritten, 4) ? *NumberOfBytesWritten : 0,
		"StackPivoted", is_stack_pivoted() ? "yes" : "no");

	if (pid != GetCurrentProcessId() && NT_SUCCESS(ret)) {
		if (g_config.injection)
			WriteMemoryHandler(ProcessHandle, BaseAddress, Buffer, *NumberOfBytesWritten);
		if (!g_config.single_process)
			ProcessMessage(pid, 0);
		disable_sleep_skip();
	}

	return ret;
}

HOOKDEF(BOOL, WINAPI, WriteProcessMemory,
	_In_	HANDLE hProcess,
	_In_	LPVOID lpBaseAddress,
	_In_	LPCVOID lpBuffer,
	_In_	SIZE_T nSize,
	_Out_   PSIZE_T lpNumberOfBytesWritten
) {
	BOOL ret;
	DWORD pid;
	ENSURE_SIZET(lpNumberOfBytesWritten);

	ret = Old_WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

	pid = pid_from_process_handle(hProcess);

	LOQ_bool("process", "ppBhs", "ProcessHandle", hProcess, "BaseAddress", lpBaseAddress,
		"Buffer", lpNumberOfBytesWritten, lpBuffer, "BufferLength", *lpNumberOfBytesWritten, "StackPivoted", is_stack_pivoted() ? "yes" : "no");

	if (pid != GetCurrentProcessId() && ret) {
		if (g_config.injection)
			WriteMemoryHandler(hProcess, lpBaseAddress, lpBuffer, *lpNumberOfBytesWritten);
		if (!g_config.single_process)
			ProcessMessage(pid, 0);
		disable_sleep_skip();
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtWow64ReadVirtualMemory64,
	__in HANDLE ProcessHandle,
	__in_opt PVOID64 BaseAddress,
	__out PVOID Buffer,
	__in unsigned __int64 BufferSize,
	__out_opt PLARGE_INTEGER NumberOfBytesRead
) {
	NTSTATUS ret;
	DWORD pid;
	ENSURE_LARGE_INTEGER(NumberOfBytesRead);

	ret = Old_NtWow64ReadVirtualMemory64(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);

	pid = pid_from_process_handle(ProcessHandle);

	LOQ_ntstatus("process", "pxb", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
		"Buffer", NumberOfBytesRead->LowPart, Buffer);

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtWow64WriteVirtualMemory64,
	__in HANDLE ProcessHandle,
	__in_opt PVOID64 BaseAddress,
	__in PVOID Buffer,
	__in unsigned __int64 BufferSize,
	__out_opt PLARGE_INTEGER NumberOfBytesWritten
) {
	BOOL ret;
	DWORD pid;
	ENSURE_LARGE_INTEGER(NumberOfBytesWritten);

	ret = Old_NtWow64WriteVirtualMemory64(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);

	pid = pid_from_process_handle(ProcessHandle);

	LOQ_ntstatus("process", "pxbhs", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
		"Buffer", NumberOfBytesWritten->LowPart, Buffer, "BufferLength", NumberOfBytesWritten->LowPart, "StackPivoted", is_stack_pivoted() ? "yes" : "no");

	if (pid != GetCurrentProcessId() && NT_SUCCESS(ret)) {
		if (g_config.injection)
			WriteMemoryHandler(ProcessHandle, BaseAddress, Buffer, NumberOfBytesWritten->LowPart);
		if (!g_config.single_process)
			ProcessMessage(pid, 0);
		disable_sleep_skip();
	}

	return ret;
}

/* need to keep in mind we might end up being called in either of the two below functions while some
   critical DLL code is protected RW by some poorly-written malware that doesn't care about reliability with
   concurrent thread execution
 */
HOOKDEF(NTSTATUS, WINAPI, NtProtectVirtualMemory,
	IN	  HANDLE ProcessHandle,
	IN OUT  PVOID *BaseAddress,
	IN OUT  PSIZE_T NumberOfBytesToProtect,
	IN	  ULONG NewAccessProtection,
	OUT	 PULONG OldAccessProtection
) {
	NTSTATUS ret;
	MEMORY_BASIC_INFORMATION meminfo;
	DWORD OriginalNewAccessProtection = 0;
	unsigned int DllRVA;
	char *ModuleName = NULL;
	if (BaseAddress)
		ModuleName = convert_address_to_dll_name_and_offset((ULONG_PTR)*BaseAddress, &DllRVA);

	if (g_config.ntdll_protect && NewAccessProtection == PAGE_EXECUTE_READWRITE && BaseAddress && NumberOfBytesToProtect &&
			NtCurrentProcess() == ProcessHandle && is_in_dll_range((ULONG_PTR)*BaseAddress) &&
			ModuleName && !strcmp(ModuleName, "ntdll.dll")) {
				// don't allow writes, this will cause memory access violations
				// that we are going to handle in the RtlDispatchException hook
				OriginalNewAccessProtection = NewAccessProtection;
				NewAccessProtection = PAGE_EXECUTE_READ;
	}

	memset(&meminfo, 0, sizeof(meminfo));
	if (NewAccessProtection == PAGE_EXECUTE_READ && BaseAddress && NumberOfBytesToProtect && NtCurrentProcess() == ProcessHandle && is_in_dll_range((ULONG_PTR)*BaseAddress)) {
		lasterror_t lasterrors;
		get_lasterrors(&lasterrors);
		VirtualQueryEx(ProcessHandle, *BaseAddress, &meminfo, sizeof(meminfo));
		if (meminfo.Protect == PAGE_EXECUTE_READWRITE)
			restore_hooks_on_range((ULONG_PTR)*BaseAddress, (ULONG_PTR)*BaseAddress + *NumberOfBytesToProtect);
		set_lasterrors(&lasterrors);
	}

	ret = Old_NtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);

	memset(&meminfo, 0, sizeof(meminfo));
	if (NT_SUCCESS(ret) && BaseAddress && OldAccessProtection && *OldAccessProtection == NewAccessProtection) {
		lasterror_t lasterrors;
		get_lasterrors(&lasterrors);
		VirtualQueryEx(ProcessHandle, *BaseAddress, &meminfo, sizeof(meminfo));
		set_lasterrors(&lasterrors);
	}

	if (OriginalNewAccessProtection)
	{
		if (OldAccessProtection && *OldAccessProtection == NewAccessProtection)
			*OldAccessProtection = OriginalNewAccessProtection;
		NewAccessProtection = OriginalNewAccessProtection;
	}

	if (NT_SUCCESS(ret) && BaseAddress && !called_by_hook() && NtCurrentProcess() == ProcessHandle)
	{
		PVOID AllocationBase = GetAllocationBase(*BaseAddress);
		if (g_config.unpacker)
			ProtectionHandler(*BaseAddress, NewAccessProtection, OldAccessProtection);
		if (g_config.caller_regions)
		{
			if (g_config.yarascan && lookup_get(&g_caller_regions, (ULONG_PTR)AllocationBase, 0))
			{
				DebugOutput("NtProtectVirtualMemory: Rescinding caller region at 0x%p due to protection change.\n", AllocationBase);
				lookup_del(&g_caller_regions, (ULONG_PTR)AllocationBase);
			}
		}
	}

	if (NewAccessProtection == PAGE_EXECUTE_READWRITE &&
		(ULONG_PTR)meminfo.AllocationBase >= get_stack_bottom() && (((ULONG_PTR)meminfo.AllocationBase + meminfo.RegionSize) <= get_stack_top())) {
		LOQ_ntstatus("process", "pPPhhHss", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
			"NumberOfBytesProtected", NumberOfBytesToProtect,
			"MemoryType", meminfo.Type,
			"NewAccessProtection", NewAccessProtection,
			"OldAccessProtection", OldAccessProtection, "StackPivoted", is_stack_pivoted() ? "yes" : "no", "IsStack", "yes");
	}
	else if (ModuleName)
		LOQ_ntstatus("process", "pPsPhhHs", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress, "ModuleName", ModuleName,
			"NumberOfBytesProtected", NumberOfBytesToProtect, "MemoryType", meminfo.Type, "NewAccessProtection", NewAccessProtection,
			"OldAccessProtection", OldAccessProtection, "StackPivoted", is_stack_pivoted() ? "yes" : "no");
	else
		LOQ_ntstatus("process", "pPPhhHs", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
			"NumberOfBytesProtected", NumberOfBytesToProtect, "MemoryType", meminfo.Type, "NewAccessProtection", NewAccessProtection,
			"OldAccessProtection", OldAccessProtection, "StackPivoted", is_stack_pivoted() ? "yes" : "no");

	if (ModuleName)
		free(ModuleName);

	return ret;
}

HOOKDEF(BOOL, WINAPI, VirtualProtectEx,
	__in   HANDLE hProcess,
	__in   LPVOID lpAddress,
	__in   SIZE_T dwSize,
	__in   DWORD flNewProtect,
	__out  PDWORD lpflOldProtect
) {
	BOOL ret;
	MEMORY_BASIC_INFORMATION meminfo;
	DWORD OriginalNewProtect = 0;
	unsigned int DllRVA;
	char *ModuleName = NULL;
	ModuleName = convert_address_to_dll_name_and_offset((ULONG_PTR)lpAddress, &DllRVA);

	if (g_config.ntdll_protect && flNewProtect == PAGE_EXECUTE_READWRITE && lpAddress && dwSize &&
			NtCurrentProcess() == hProcess && is_in_dll_range((ULONG_PTR)lpAddress) &&
			ModuleName && !strcmp(ModuleName, "ntdll.dll")) {
				// don't allow writes, this will cause memory access violations
				// that we are going to handle in the RtlDispatchException hook
				OriginalNewProtect = flNewProtect;
				flNewProtect = PAGE_EXECUTE_READ;
	}

	memset(&meminfo, 0, sizeof(meminfo));
	if (flNewProtect == PAGE_EXECUTE_READ && lpAddress && dwSize && NtCurrentProcess() == hProcess && is_in_dll_range((ULONG_PTR)lpAddress)) {
		lasterror_t lasterrors;
		get_lasterrors(&lasterrors);
		VirtualQueryEx(hProcess, lpAddress, &meminfo, sizeof(meminfo));
		if (meminfo.Protect == PAGE_EXECUTE_READWRITE)
			restore_hooks_on_range((ULONG_PTR)lpAddress, (ULONG_PTR)lpAddress + dwSize);
		set_lasterrors(&lasterrors);
	}

	ret = Old_VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);

	memset(&meminfo, 0, sizeof(meminfo));
	if (ret && lpflOldProtect && *lpflOldProtect == flNewProtect) {
		lasterror_t lasterrors;
		get_lasterrors(&lasterrors);
		VirtualQueryEx(hProcess, lpAddress, &meminfo, sizeof(meminfo));
		set_lasterrors(&lasterrors);
	}

	if (OriginalNewProtect)
	{
		if (lpflOldProtect && *lpflOldProtect == flNewProtect)
			*lpflOldProtect = OriginalNewProtect;
		flNewProtect = OriginalNewProtect;
	}

	if (NT_SUCCESS(ret) && !called_by_hook() && NtCurrentProcess() == hProcess)
	{
		char ModulePath[MAX_PATH];
		PVOID AllocationBase = GetAllocationBase(lpAddress);
		BOOL MappedModule = GetMappedFileName(GetCurrentProcess(), AllocationBase, ModulePath, MAX_PATH);
		if (g_config.unpacker)
			ProtectionHandler(lpAddress, flNewProtect, lpflOldProtect);
		if (g_config.caller_regions)
		{
			if (g_config.yarascan && lookup_get(&g_caller_regions, (ULONG_PTR)AllocationBase, 0))
			{
				DebugOutput("VirtualProtectEx: Rescinding caller region at 0x%p due to protection change.\n", AllocationBase);
				lookup_del(&g_caller_regions, (ULONG_PTR)AllocationBase);
			}
		}
	}

	if (flNewProtect == PAGE_EXECUTE_READWRITE && NtCurrentProcess() == hProcess &&
		(ULONG_PTR)meminfo.AllocationBase >= get_stack_bottom() && (((ULONG_PTR)meminfo.AllocationBase + meminfo.RegionSize) <= get_stack_top())) {
		LOQ_bool("process", "ppphhHss", "ProcessHandle", hProcess, "Address", lpAddress,
			"Size", dwSize, "MemType", meminfo.Type, "Protection", flNewProtect, "OldProtection", lpflOldProtect, "StackPivoted", is_stack_pivoted() ? "yes" : "no", "IsStack", "yes");
	}
	else if (ModuleName)
		LOQ_bool("process", "ppsphhHs", "ProcessHandle", hProcess, "Address", lpAddress, "ModuleName", ModuleName, 
			"Size", dwSize, "MemType", meminfo.Type, "Protection", flNewProtect, "OldProtection", lpflOldProtect,
			"StackPivoted", is_stack_pivoted() ? "yes" : "no");
	else
		LOQ_bool("process", "ppphhHs", "ProcessHandle", hProcess, "Address", lpAddress, "Size", dwSize, "MemType", meminfo.Type, 
			"Protection", flNewProtect, "OldProtection", lpflOldProtect, "StackPivoted", is_stack_pivoted() ? "yes" : "no");

	if (ModuleName)
		free(ModuleName);

	return ret;
}

// it's not safe to call pipe() in this hook until we replace all uses of snprintf in pipe()
HOOKDEF(NTSTATUS, WINAPI, NtFreeVirtualMemory,
	IN	  HANDLE ProcessHandle,
	IN	  PVOID *BaseAddress,
	IN OUT  PSIZE_T RegionSize,
	IN	  ULONG FreeType
) {
	if (g_config.unpacker && !called_by_hook() && NtCurrentProcess() == ProcessHandle && *RegionSize == 0 && (FreeType & MEM_RELEASE))
		FreeHandler(*BaseAddress);

	NTSTATUS ret = Old_NtFreeVirtualMemory(ProcessHandle, BaseAddress,
		RegionSize, FreeType);

	LOQ_ntstatus("process", "pPPh", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
		"RegionSize", RegionSize, "FreeType", FreeType);

	return ret;
}

HOOKDEF(BOOL, WINAPI, VirtualFreeEx,
	__in  HANDLE hProcess,
	__in  LPVOID lpAddress,
	__in  SIZE_T dwSize,
	__in  DWORD dwFreeType
) {
	BOOL ret = Old_VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType);
	LOQ_bool("process", "ppph", "ProcessHandle", hProcess, "Address", lpAddress,
		"Size", dwSize, "FreeType", dwFreeType);
	return ret;
}

HOOKDEF(int, CDECL, system,
	const char *command
) {
	int ret = Old_system(command);
	LOQ_nonnegone("process", "s", "Command", command);
	return ret;
}

HOOKDEF(BOOL, WINAPI, WaitForDebugEvent,
	__out LPDEBUG_EVENT lpDebugEvent,
	__in DWORD dwMilliseconds
) {
	BOOL ret = Old_WaitForDebugEvent(lpDebugEvent, dwMilliseconds);

	if (!ret)
		return ret;

	switch (lpDebugEvent->dwDebugEventCode) {
	case CREATE_THREAD_DEBUG_EVENT:
		LOQ_bool("process", "iiip", "EventCode", lpDebugEvent->dwDebugEventCode, "ProcessId", lpDebugEvent->dwProcessId, "ThreadId", lpDebugEvent->dwThreadId, "StartAddress", lpDebugEvent->u.CreateThread.lpStartAddress);
		break;
	case LOAD_DLL_DEBUG_EVENT:
		// we could continue ourselves here and skip notification to the malware of capemon loading
	default:
		LOQ_bool("process", "iii", "EventCode", lpDebugEvent->dwDebugEventCode, "ProcessId", lpDebugEvent->dwProcessId, "ThreadId", lpDebugEvent->dwThreadId);
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, DbgUiWaitStateChange,
	__out PDBGUI_WAIT_STATE_CHANGE StateChange,
	__in_opt PLARGE_INTEGER Timeout)
{
	NTSTATUS ret = Old_DbgUiWaitStateChange(StateChange, Timeout);

	if (NT_SUCCESS(ret)) {
		switch (StateChange->NewState) {
		case DbgCreateThreadStateChange:
			LOQ_ntstatus("process", "iiip", "NewState", StateChange->NewState, "ProcessId", pid_from_process_handle(StateChange->AppClientId.UniqueProcess), "ThreadId", tid_from_thread_handle(StateChange->AppClientId.UniqueThread), "StartAddress", StateChange->StateInfo.CreateThread.NewThread.StartAddress);
			break;
		case DbgLoadDllStateChange:
			{
				wchar_t *fname = calloc(32768, sizeof(wchar_t));

				path_from_handle(StateChange->StateInfo.LoadDll.FileHandle, fname, 32768);
				// we could continue ourselves here and skip notification to the malware of capemon loading
				LOQ_ntstatus("process", "iiiF", "NewState", StateChange->NewState, "ProcessId", pid_from_process_handle(StateChange->AppClientId.UniqueProcess), "ThreadId", tid_from_thread_handle(StateChange->AppClientId.UniqueThread), "DllPath", fname);
				free(fname);
			}
			break;
		default:
			LOQ_ntstatus("process", "iii", "NewState", StateChange->NewState, "ProcessId", pid_from_process_handle(StateChange->AppClientId.UniqueProcess), "ThreadId", tid_from_thread_handle(StateChange->AppClientId.UniqueThread));
		}
	}

	return ret;
}

HOOKDEF_NOTAIL(WINAPI, RtlDispatchException,
	__in PEXCEPTION_RECORD ExceptionRecord,
	__in PCONTEXT Context)
{
	if (ExceptionRecord && (ULONG_PTR)ExceptionRecord->ExceptionAddress >= g_our_dll_base && (ULONG_PTR)ExceptionRecord->ExceptionAddress < (g_our_dll_base + g_our_dll_size)) {
		if (!(g_config.debugger && ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)) {
			char buf[160];
			ULONG_PTR seh = 0;
			DWORD *tebtmp = (DWORD *)NtCurrentTeb();
			if (tebtmp[0] != 0xffffffff)
				seh = ((DWORD*)(DWORD_PTR)tebtmp[0])[1];
			if (seh < g_our_dll_base || seh >= (g_our_dll_base + g_our_dll_size)) {
				_snprintf(buf, sizeof(buf), "Exception 0x%x reported at offset 0x%x in capemon itself while accessing 0x%p from hook %s", ExceptionRecord->ExceptionCode, (DWORD)((ULONG_PTR)ExceptionRecord->ExceptionAddress - g_our_dll_base), (PVOID)ExceptionRecord->ExceptionInformation[1], hook_info()->current_hook ? hook_info()->current_hook->funcname : "unknown");
				log_anomaly("capemon crash", buf);
			}
		}
	}

	// flush logs prior to handling of an exception without having to register a vectored exception handler
	log_flush();

	return TRUE;
}

HOOKDEF_ALT(BOOL, WINAPI, RtlDispatchException,
	__in PEXCEPTION_RECORD ExceptionRecord,
	__in PCONTEXT Context)
{
	if (g_config.ntdll_protect) {
		if (ExceptionRecord && ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && ExceptionRecord->ExceptionFlags == 0 &&
			ExceptionRecord->NumberParameters == 2 && ExceptionRecord->ExceptionInformation[0] == 1) {
			unsigned int offset;
			char *dllname = convert_address_to_dll_name_and_offset(ExceptionRecord->ExceptionInformation[1], &offset);
			if (dllname && !strcmp(dllname, "ntdll.dll")) {
				// if trying to write to ntdll.dll, then just skip the instruction
				if (!ntdll_protect_logged) {
					ntdll_protect_logged = TRUE;
#ifdef _WIN64
					DebugOutput("RtlDispatchException: skipped instruction at 0x%p writing to ntdll (0x%p - 0x%p)\n", Context->Rip, ExceptionRecord->ExceptionInformation[1], offset);
				}
				Context->Rip += lde((void*)Context->Rip);
#else
					DebugOutput("RtlDispatchException: skipped instruction at 0x%x writing to ntdll (0x%x - 0x%x)\n", Context->Eip, ExceptionRecord->ExceptionInformation[1], offset);
				}
				Context->Eip += lde((void*)Context->Eip);
#endif
				int ret = 0;
				if (g_config.log_exceptions)
					LOQ_void("system", "pppp", "ExceptionCode", ExceptionRecord->ExceptionCode, "ExceptionAddress", ExceptionRecord->ExceptionAddress, "ExceptionFlags", ExceptionRecord->ExceptionFlags, "ExceptionInformation", ExceptionRecord->ExceptionInformation[0]);
				return TRUE;
			}
			if (dllname)
				free(dllname);
		}
	}

	if (g_config.log_exceptions && !((ULONG_PTR)ExceptionRecord->ExceptionAddress >= g_our_dll_base && (ULONG_PTR)ExceptionRecord->ExceptionAddress < (g_our_dll_base + g_our_dll_size)) && !(g_config.debugger && SingleStepHandler && (ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP || ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION || ExceptionRecord->ExceptionCode == STATUS_PRIVILEGED_INSTRUCTION))) {
		int ret = 0;
		if (!ExceptionRecord->NumberParameters && (ExceptionRecord->ExceptionCode >= 0x80000000 || g_config.log_exceptions > 1))
			LOQ_void("system", "ppp", "ExceptionCode", ExceptionRecord->ExceptionCode, "ExceptionAddress", ExceptionRecord->ExceptionAddress, "ExceptionFlags", ExceptionRecord->ExceptionFlags);
		else if (ExceptionRecord->NumberParameters == 1 && (ExceptionRecord->ExceptionCode >= 0x80000000 || g_config.log_exceptions > 1))
			LOQ_void("system", "pppp", "ExceptionCode", ExceptionRecord->ExceptionCode, "ExceptionAddress", ExceptionRecord->ExceptionAddress, "ExceptionFlags", ExceptionRecord->ExceptionFlags, "ExceptionInformation", ExceptionRecord->ExceptionInformation[0]);
		else if (ExceptionRecord->NumberParameters == 2 && (ExceptionRecord->ExceptionCode >= 0x80000000 || g_config.log_exceptions > 1))
			LOQ_void("system", "ppppp", "ExceptionCode", ExceptionRecord->ExceptionCode, "ExceptionAddress", ExceptionRecord->ExceptionAddress, "ExceptionFlags", ExceptionRecord->ExceptionFlags, "ExceptionInformation[0]", ExceptionRecord->ExceptionInformation[0], "ExceptionInformation[1]", ExceptionRecord->ExceptionInformation[1]);
	}

	if (CAPEExceptionDispatcher(ExceptionRecord, Context))
		return TRUE;
	else
		return Old_RtlDispatchException(ExceptionRecord, Context);
}

HOOKDEF_NOTAIL(WINAPI, NtRaiseException,
	__in PEXCEPTION_RECORD ExceptionRecord,
	__in PCONTEXT Context,
	__in BOOLEAN SearchFrames
) {
	EXCEPTION_POINTERS exc;

	exc.ContextRecord = Context;
	exc.ExceptionRecord = ExceptionRecord;

	if (g_config.debug)
		capemon_exception_handler(&exc);

	return 0;
}

BOOL EnableFakeCount;

HOOKDEF(UINT, WINAPI, GetWriteWatch,
	__in		DWORD		dwFlags,
	__in		PVOID		lpBaseAddress,
	__in		SIZE_T		dwRegionSize,
	__out		PVOID*		lpAddresses,
	__inout		ULONG_PTR*	lpdwCount,
	__out		LPDWORD		lpdwGranularity
) {
	UINT ret = Old_GetWriteWatch(dwFlags, lpBaseAddress, dwRegionSize, lpAddresses, lpdwCount, lpdwGranularity);
	LOQ_zero("process", "phiL", "BaseAddress", lpBaseAddress, "RegionSize", dwRegionSize, "Flags", dwFlags, "Count", lpdwCount);
#ifndef _WIN64
	// For Pikabot detonation, e.g. 2ebf4db49a8a7875e9c443482f82af1febd9751eee65be155355c3525331ae88
	// ref https://github.com/BaumFX/cpp-anti-debug/blob/d6e84a09b21593a65a5d7545e0d3df876cb0a29a/anti_debug.cpp#L260
	if (ret)
		EnableFakeCount = TRUE;
	else if (EnableFakeCount && lpdwCount && *lpdwCount == 1)
		*lpdwCount = 0;
#endif
	return ret;
}

HOOKDEF(BOOL, WINAPI, UpdateProcThreadAttribute,
	__inout		LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
	__in		DWORD		dwFlags,
	__in		DWORD_PTR	Attribute,
	__in		PVOID		lpValue,
	__in		SIZE_T		cbSize,
	__out_opt	PVOID		lpPreviousValue,
	__in_opt	PSIZE_T		lpReturnSize
) {
	BOOL ret = 0;
	if (!(Attribute == PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY && *(DWORD64*)lpValue == PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON))
		ret = Old_UpdateProcThreadAttribute(lpAttributeList, dwFlags, Attribute, lpValue, cbSize, lpPreviousValue, lpReturnSize);
	LOQ_zero("process", "lL", "Attribute", Attribute, "Value", lpValue);
	return ret;
}
