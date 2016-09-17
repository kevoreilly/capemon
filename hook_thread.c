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
#include "hooking.h"
#include "log.h"
#include "pipe.h"
#include "misc.h"
#include "hook_sleep.h"
#include "unhook.h"
#include "lookup.h"

static lookup_t g_ignored_threads;

void ignored_threads_init(void)
{
	lookup_init(&g_ignored_threads);
}

BOOLEAN is_ignored_thread(DWORD tid)
{
	void *ret;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);
	ret = lookup_get(&g_ignored_threads, (unsigned int)tid, NULL);
	set_lasterrors(&lasterror);

	if (ret)
		return TRUE;
	return FALSE;
}

void remove_ignored_thread(DWORD tid)
{
	lasterror_t lasterror;

	get_lasterrors(&lasterror);
	lookup_del(&g_ignored_threads, tid);
	set_lasterrors(&lasterror);
}

void add_ignored_thread(DWORD tid)
{
	lasterror_t lasterror;

	get_lasterrors(&lasterror);
	pipe("INFO:Adding ignored thread %d", tid);
	lookup_add(&g_ignored_threads, tid, 0);
	set_lasterrors(&lasterror);
}


HOOKDEF(NTSTATUS, WINAPI, NtQueueApcThread,
	__in HANDLE ThreadHandle,
	__in PIO_APC_ROUTINE ApcRoutine,
	__in_opt PVOID ApcRoutineContext,
	__in_opt PIO_STATUS_BLOCK ApcStatusBlock,
	__in_opt ULONG ApcReserved
) {
	DWORD PID = pid_from_thread_handle(ThreadHandle);
	DWORD TID = tid_from_thread_handle(ThreadHandle);
	NTSTATUS ret;

	pipe("PROCESS:%d:%d,%d", is_suspended(PID, TID), PID, TID);

	ret = Old_NtQueueApcThread(ThreadHandle, ApcRoutine,
							   ApcRoutineContext, ApcStatusBlock, ApcReserved);

	LOQ_ntstatus("threading", "iip", "ProcessId", PID, "ThreadId", TID, "ThreadHandle", ThreadHandle);

	if (NT_SUCCESS(ret))
		disable_sleep_skip();
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueueApcThreadEx,
	__in HANDLE ThreadHandle,
	__in_opt HANDLE UserApcReserveHandle,
	__in PIO_APC_ROUTINE ApcRoutine,
	__in_opt PVOID ApcRoutineContext,
	__in_opt PIO_STATUS_BLOCK ApcStatusBlock,
	__in_opt PVOID ApcReserved
) {
	DWORD PID = pid_from_thread_handle(ThreadHandle);
	DWORD TID = tid_from_thread_handle(ThreadHandle);
	NTSTATUS ret;

	pipe("PROCESS:%d:%d,%d", is_suspended(PID, TID), PID, TID);

	ret = Old_NtQueueApcThreadEx(ThreadHandle, UserApcReserveHandle, ApcRoutine,
								 ApcRoutineContext, ApcStatusBlock, ApcReserved);

	LOQ_ntstatus("threading", "iip", "ProcessId", PID, "ThreadId", TID, "ThreadHandle", ThreadHandle);

	if (NT_SUCCESS(ret))
		disable_sleep_skip();
	return ret;
}


HOOKDEF(NTSTATUS, WINAPI, NtCreateThread,
	__out     PHANDLE ThreadHandle,
	__in      ACCESS_MASK DesiredAccess,
	__in_opt  POBJECT_ATTRIBUTES ObjectAttributes,
	__in      HANDLE ProcessHandle,
	__out     PCLIENT_ID ClientId,
	__in      PCONTEXT ThreadContext,
	__in      PINITIAL_TEB InitialTeb,
	__in      BOOLEAN CreateSuspended
	) {
	DWORD pid = pid_from_process_handle(ProcessHandle);

	NTSTATUS ret = Old_NtCreateThread(ThreadHandle, DesiredAccess,
		ObjectAttributes, ProcessHandle, ClientId, ThreadContext,
		InitialTeb, TRUE);

	if (NT_SUCCESS(ret)) {
		//if (called_by_hook() && pid == GetCurrentProcessId())
		//	add_ignored_thread((DWORD)ClientId->UniqueThread);
		pipe("PROCESS:%d:%d,%d", is_suspended(pid, (DWORD)(ULONG_PTR)ClientId->UniqueThread), pid, (DWORD)(ULONG_PTR)ClientId->UniqueThread);
		if (CreateSuspended == FALSE) {
			lasterror_t lasterror;
			get_lasterrors(&lasterror);
			ResumeThread(*ThreadHandle);
			set_lasterrors(&lasterror);
		}
	}

	LOQ_ntstatus("threading", "PpOi", "ThreadHandle", ThreadHandle, "ProcessHandle", ProcessHandle,
        "ObjectAttributes", ObjectAttributes, "CreateSuspended", CreateSuspended);

	if (NT_SUCCESS(ret))
        disable_sleep_skip();
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateThreadEx,
    OUT     PHANDLE hThread,
    IN      ACCESS_MASK DesiredAccess,
    IN      PVOID ObjectAttributes,
    IN      HANDLE ProcessHandle,
    IN      LPTHREAD_START_ROUTINE lpStartAddress,
    IN      PVOID lpParameter,
    IN      DWORD CreateFlags,
    IN      LONG StackZeroBits,
    IN      LONG SizeOfStackCommit,
    IN      LONG SizeOfStackReserve,
    OUT     PVOID lpBytesBuffer
) {
	DWORD pid = pid_from_process_handle(ProcessHandle);
	
	NTSTATUS ret = Old_NtCreateThreadEx(hThread, DesiredAccess,
        ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter,
        CreateFlags | 1, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve,
        lpBytesBuffer);

	if (NT_SUCCESS(ret)) {
		DWORD tid = tid_from_thread_handle(*hThread);
		//if (called_by_hook() && pid == GetCurrentProcessId())
		//	add_ignored_thread(tid);

		pipe("PROCESS:%d:%d,%d", is_suspended(pid, tid), pid, tid);
		if (!(CreateFlags & 1)) {
			lasterror_t lasterror;
			get_lasterrors(&lasterror);
			ResumeThread(*hThread);
			set_lasterrors(&lasterror);
		}
	}
	LOQ_ntstatus("threading", "Ppph", "ThreadHandle", hThread, "ProcessHandle", ProcessHandle,
        "StartAddress", lpStartAddress, "CreateFlags", CreateFlags);

	if (NT_SUCCESS(ret))
		disable_sleep_skip();
	
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenThread,
    __out  PHANDLE ThreadHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes,
    __in   PCLIENT_ID ClientId
) {
    NTSTATUS ret = Old_NtOpenThread(ThreadHandle, DesiredAccess,
        ObjectAttributes, ClientId);
	DWORD PID = 0;
	DWORD TID = 0;

	if (NT_SUCCESS(ret) && ThreadHandle) {
		PID = pid_from_thread_handle(*ThreadHandle);
		TID = tid_from_thread_handle(*ThreadHandle);
	}

	if (ClientId) {
		LOQ_ntstatus("threading", "Phii", "ThreadHandle", ThreadHandle, "DesiredAccess", DesiredAccess,
			"ProcessId", PID, "ThreadId", TID);
	} else {
		LOQ_ntstatus("threading", "PhO", "ThreadHandle", ThreadHandle, "DesiredAccess", DesiredAccess,
			"ObjectAttributes", ObjectAttributes);
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtGetContextThread,
    __in     HANDLE ThreadHandle,
    __inout  LPCONTEXT Context
) {
    NTSTATUS ret = Old_NtGetContextThread(ThreadHandle, Context);
	if (Context->ContextFlags & CONTEXT_CONTROL)
#ifdef _WIN64
		LOQ_ntstatus("threading", "pp", "ThreadHandle", ThreadHandle, "InstructionPointer", Context->Rip);
#else
		LOQ_ntstatus("threading", "pp", "ThreadHandle", ThreadHandle, "InstructionPointer", Context->Eip);
#endif
	else
		LOQ_ntstatus("threading", "p", "ThreadHandle", ThreadHandle);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtSetContextThread,
    __in  HANDLE ThreadHandle,
    __in  const CONTEXT *Context
) {
	NTSTATUS ret;
	DWORD pid = pid_from_thread_handle(ThreadHandle);
	DWORD tid = tid_from_thread_handle(ThreadHandle);
	pipe("PROCESS:%d:%d,%d", is_suspended(pid, tid), pid, tid);

	ret = Old_NtSetContextThread(ThreadHandle, Context);
	if (Context->ContextFlags & CONTEXT_CONTROL)
#ifdef _WIN64
		LOQ_ntstatus("threading", "pp", "ThreadHandle", ThreadHandle, "InstructionPointer", Context->Rip);
#else
		LOQ_ntstatus("threading", "pp", "ThreadHandle", ThreadHandle, "InstructionPointer", Context->Eip);
#endif
	else
		LOQ_ntstatus("threading", "p", "ThreadHandle", ThreadHandle);

    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtSuspendThread,
    __in        HANDLE ThreadHandle,
    __out_opt   ULONG *PreviousSuspendCount
) {
	DWORD pid = pid_from_thread_handle(ThreadHandle);
	DWORD tid = tid_from_thread_handle(ThreadHandle);
	NTSTATUS ret;
	ENSURE_ULONG(PreviousSuspendCount);

	if (pid == GetCurrentProcessId() && tid && (tid == g_unhook_detect_thread_id || tid == g_unhook_watcher_thread_id ||
		tid == g_watchdog_thread_id || tid == g_terminate_event_thread_id || tid == g_log_thread_id ||
		tid == g_logwatcher_thread_id || tid == g_procname_watcher_thread_id)) {
		ret = 0;
		*PreviousSuspendCount = 0;
		LOQ_ntstatus("threading", "pLs", "ThreadHandle", ThreadHandle,
			"SuspendCount", PreviousSuspendCount, "Alert", "Attempted to suspend cuckoomon thread");
	}
	else {
		pipe("PROCESS:%d:%d,%d", is_suspended(pid, tid), pid, tid);

		ret = Old_NtSuspendThread(ThreadHandle, PreviousSuspendCount);
		LOQ_ntstatus("threading", "pL", "ThreadHandle", ThreadHandle,
			"SuspendCount", PreviousSuspendCount);
	}
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtResumeThread,
    __in        HANDLE ThreadHandle,
    __out_opt   ULONG *SuspendCount
) {
	DWORD pid = pid_from_thread_handle(ThreadHandle);
	DWORD tid = tid_from_thread_handle(ThreadHandle);
	NTSTATUS ret;
	ENSURE_ULONG(SuspendCount);
	pipe("RESUME:%d,%d", pid, tid);

    ret = Old_NtResumeThread(ThreadHandle, SuspendCount);
    LOQ_ntstatus("threading", "pI", "ThreadHandle", ThreadHandle, "SuspendCount", SuspendCount);
    return ret;
}

extern DWORD tmphookinfo_threadid;
extern CRITICAL_SECTION g_tmp_hookinfo_lock;

HOOKDEF(NTSTATUS, WINAPI, NtTerminateThread,
    __in  HANDLE ThreadHandle,
    __in  NTSTATUS ExitStatus
) {
    // Thread will terminate. Default logging will not work. Be aware: return value not valid
	DWORD pid = pid_from_thread_handle(ThreadHandle);
	DWORD tid = tid_from_thread_handle(ThreadHandle);
	NTSTATUS ret = 0;

	if (tmphookinfo_threadid && tid == tmphookinfo_threadid) {
		tmphookinfo_threadid = 0;
		LeaveCriticalSection(&g_tmp_hookinfo_lock);
	}

	//remove_ignored_thread(tid);

	if (pid == GetCurrentProcessId() && tid && (tid == g_unhook_detect_thread_id || tid == g_unhook_watcher_thread_id ||
		tid == g_watchdog_thread_id || tid == g_terminate_event_thread_id || tid == g_log_thread_id ||
		tid == g_logwatcher_thread_id || tid == g_procname_watcher_thread_id)) {
		ret = 0;
		LOQ_ntstatus("threading", "phs", "ThreadHandle", ThreadHandle, "ExitStatus", ExitStatus, "Alert", "Attempted to kill cuckoomon thread");
		return ret;
	}

	LOQ_ntstatus("threading", "ph", "ThreadHandle", ThreadHandle, "ExitStatus", ExitStatus);
    ret = Old_NtTerminateThread(ThreadHandle, ExitStatus);

	disable_tail_call_optimization();

	return ret;
}

HOOKDEF(HANDLE, WINAPI, CreateThread,
    __in   LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in   SIZE_T dwStackSize,
    __in   LPTHREAD_START_ROUTINE lpStartAddress,
    __in   LPVOID lpParameter,
    __in   DWORD dwCreationFlags,
    __out_opt  LPDWORD lpThreadId
) {
	HANDLE ret;
	ENSURE_DWORD(lpThreadId);

	ret = Old_CreateThread(lpThreadAttributes, dwStackSize,
        lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    LOQ_nonnull("threading", "pphI", "StartRoutine", lpStartAddress, "Parameter", lpParameter,
        "CreationFlags", dwCreationFlags, "ThreadId", lpThreadId);
    if (ret != NULL)
        disable_sleep_skip();
    return ret;
}

HOOKDEF(HANDLE, WINAPI, CreateRemoteThread,
    __in   HANDLE hProcess,
    __in   LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in   SIZE_T dwStackSize,
    __in   LPTHREAD_START_ROUTINE lpStartAddress,
    __in   LPVOID lpParameter,
    __in   DWORD dwCreationFlags,
    __out_opt  LPDWORD lpThreadId
) {
	DWORD pid;
	HANDLE ret;
	ENSURE_DWORD(lpThreadId);

	pid = pid_from_process_handle(hProcess);
	ret = Old_CreateRemoteThread(hProcess, lpThreadAttributes,
        dwStackSize, lpStartAddress, lpParameter, dwCreationFlags | CREATE_SUSPENDED,
        lpThreadId);

	if (ret != NULL) {
		pipe("PROCESS:%d:%d,%d", is_suspended(pid, *lpThreadId), pid, *lpThreadId);
		if (!(dwCreationFlags & CREATE_SUSPENDED)) {
			lasterror_t lasterror;
			get_lasterrors(&lasterror);
			ResumeThread(ret);
			set_lasterrors(&lasterror);
		}
	}

	LOQ_nonnull("threading", "ppphI", "ProcessHandle", hProcess, "StartRoutine", lpStartAddress,
        "Parameter", lpParameter, "CreationFlags", dwCreationFlags,
        "ThreadId", lpThreadId);

	if (ret != NULL)
		disable_sleep_skip();
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, RtlCreateUserThread,
    IN HANDLE ProcessHandle,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    IN BOOLEAN CreateSuspended,
    IN ULONG StackZeroBits,
    IN OUT PULONG StackReserved,
    IN OUT PULONG StackCommit,
    IN PVOID StartAddress,
    IN PVOID StartParameter OPTIONAL,
    OUT PHANDLE ThreadHandle,
    OUT PCLIENT_ID ClientId
) {
	DWORD pid;
	NTSTATUS ret;
	ENSURE_CLIENT_ID(ClientId);

	pid = pid_from_process_handle(ProcessHandle);
	
	ret = Old_RtlCreateUserThread(ProcessHandle, SecurityDescriptor,
        TRUE, StackZeroBits, StackReserved, StackCommit,
        StartAddress, StartParameter, ThreadHandle, ClientId);
    LOQ_ntstatus("threading", "pippPi", "ProcessHandle", ProcessHandle,
        "CreateSuspended", CreateSuspended, "StartAddress", StartAddress,
        "StartParameter", StartParameter, "ThreadHandle", ThreadHandle,
        "ThreadIdentifier", ClientId->UniqueThread);

	if (NT_SUCCESS(ret)) {
		pipe("PROCESS:%d:%d,%d", is_suspended(pid, (DWORD)(ULONG_PTR)ClientId->UniqueThread), pid, (DWORD)(ULONG_PTR)ClientId->UniqueThread);
		if (CreateSuspended == FALSE) {
			lasterror_t lasterror;
			get_lasterrors(&lasterror);
			ResumeThread(ThreadHandle);
			set_lasterrors(&lasterror);
		}
	}

	if (NT_SUCCESS(ret))
		disable_sleep_skip();

	return ret;
}
