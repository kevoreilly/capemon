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
#include "CAPE\CAPE.h"
#include "CAPE\Debugger.h"

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void GetThreadContextHandler(DWORD Pid, LPCONTEXT Context);
extern void SetThreadContextHandler(DWORD Pid, const CONTEXT *Context);
extern void ResumeThreadHandler(DWORD Pid);
#ifdef CAPE_TRACE
extern void NtContinueHandler(PCONTEXT ThreadContext);
unsigned int TestFlag = 0;
#endif

static lookup_t g_ignored_threads;

DWORD LastInjected;

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
	DWORD pid = pid_from_thread_handle(ThreadHandle);
	DWORD tid = tid_from_thread_handle(ThreadHandle);
	NTSTATUS ret;

    if (!g_config.single_process && pid != GetCurrentProcessId())
        pipe("PROCESS:%d:%d,%d", is_suspended(pid, tid), pid, tid);

    ret = Old_NtQueueApcThread(ThreadHandle, ApcRoutine, ApcRoutineContext, ApcStatusBlock, ApcReserved);

	LOQ_ntstatus("threading", "iip", "ProcessId", pid, "ThreadId", tid, "ThreadHandle", ThreadHandle);

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
	DWORD pid = pid_from_thread_handle(ThreadHandle);
	DWORD tid = tid_from_thread_handle(ThreadHandle);
	NTSTATUS ret;

    if (!g_config.single_process && pid != GetCurrentProcessId())
        pipe("PROCESS:%d:%d,%d", is_suspended(pid, tid), pid, tid);

    ret = Old_NtQueueApcThreadEx(ThreadHandle, UserApcReserveHandle, ApcRoutine, ApcRoutineContext, ApcStatusBlock, ApcReserved);

	LOQ_ntstatus("threading", "iip", "ProcessId", pid, "ThreadId", tid, "ThreadHandle", ThreadHandle);

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
        DWORD tid = tid_from_thread_handle(*ThreadHandle);
		//if (called_by_hook() && pid == GetCurrentProcessId())
		//	add_ignored_thread(tid);

        if (DebuggerEnabled && !called_by_hook()) {
            DoOutputDebugString("NtCreateThread: Initialising breakpoints for thread %d.\n", tid);
            InitNewThreadBreakpoints(tid);
        }

        if (!g_config.single_process && pid != GetCurrentProcessId())
            pipe("PROCESS:%d:%d,%d", is_suspended(pid, tid), pid, tid);

        if (CreateSuspended == FALSE) {
			lasterror_t lasterror;
			get_lasterrors(&lasterror);
			ResumeThread(*ThreadHandle);
			set_lasterrors(&lasterror);
		}

        LOQ_ntstatus("threading", "PpOiii", "ThreadHandle", ThreadHandle, "ProcessHandle", ProcessHandle,
            "ObjectAttributes", ObjectAttributes, "CreateSuspended", CreateSuspended, "ThreadId", tid,
			"ProcessId", pid);

        disable_sleep_skip();
	}
    else
        LOQ_ntstatus("threading", "PpOi", "ThreadHandle", ThreadHandle, "ProcessHandle", ProcessHandle,
            "ObjectAttributes", ObjectAttributes, "CreateSuspended", CreateSuspended);

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

		if (pid != GetCurrentProcessId())
            if (DebuggerEnabled && !called_by_hook()) {
                DoOutputDebugString("NtCreateThreadEx: Initialising breakpoints for thread %d.\n", tid);
                InitNewThreadBreakpoints(tid);
            }

            if (!g_config.single_process)
                pipe("PROCESS:%d:%d,%d", is_suspended(pid, tid), pid, tid);

            if (!(CreateFlags & 1)) {
			lasterror_t lasterror;
			get_lasterrors(&lasterror);
			ResumeThread(*hThread);
			set_lasterrors(&lasterror);
		}

        LOQ_ntstatus("threading", "Ppphii", "ThreadHandle", hThread, "ProcessHandle", ProcessHandle,
            "StartAddress", lpStartAddress, "CreateFlags", CreateFlags, "ThreadId", tid,
			"ProcessId", pid);

        disable_sleep_skip();
	}
    else
        LOQ_ntstatus("threading", "Ppph", "ThreadHandle", hThread, "ProcessHandle", ProcessHandle,
            "StartAddress", lpStartAddress, "CreateFlags", CreateFlags);

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
	DWORD pid = 0;
	DWORD tid = 0;

	if (NT_SUCCESS(ret) && ThreadHandle) {
		pid = pid_from_thread_handle(*ThreadHandle);
		tid = tid_from_thread_handle(*ThreadHandle);
	}

	if (ClientId) {
		LOQ_ntstatus("threading", "Phiii", "ThreadHandle", ThreadHandle, "DesiredAccess", DesiredAccess,
			"ProcessId", pid, "ThreadId", tid, "ProcessId", pid);
	} else {
		LOQ_ntstatus("threading", "PhOi", "ThreadHandle", ThreadHandle, "DesiredAccess", DesiredAccess,
			"ObjectAttributes", ObjectAttributes, "ProcessId", pid);
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtGetContextThread,
    __in     HANDLE ThreadHandle,
    __inout  LPCONTEXT Context
) {
	ENSURE_HANDLE(ThreadHandle);
	ENSURE_STRUCT(Context, CONTEXT);
	DWORD tid = tid_from_thread_handle(ThreadHandle);

    NTSTATUS ret = Old_NtGetContextThread(ThreadHandle, Context);
    DWORD pid = pid_from_thread_handle(ThreadHandle);
    if (Context && Context->ContextFlags & CONTEXT_CONTROL)
#ifdef _WIN64
		LOQ_ntstatus("threading", "ppi", "ThreadHandle", ThreadHandle, "InstructionPointer", Context->Rcx,
		"ProcessId", pid);
#else
		LOQ_ntstatus("threading", "ppi", "ThreadHandle", ThreadHandle, "InstructionPointer", Context->Eax,
		"ProcessId", pid);
#endif
	else
		LOQ_ntstatus("threading", "pi", "ThreadHandle", ThreadHandle, "ProcessId", pid);
    if (g_config.injection)
        GetThreadContextHandler(pid, Context);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtSetContextThread,
    __in  HANDLE ThreadHandle,
    __in  const CONTEXT *Context
) {
	NTSTATUS ret;
	DWORD pid = pid_from_thread_handle(ThreadHandle);
	DWORD tid = tid_from_thread_handle(ThreadHandle);

    ret = Old_NtSetContextThread(ThreadHandle, Context);

    if (Context && Context->ContextFlags & CONTEXT_CONTROL)
#ifdef _WIN64
		LOQ_ntstatus("threading", "pp", "ThreadHandle", ThreadHandle, "InstructionPointer", Context->Rcx);
#else
		LOQ_ntstatus("threading", "pp", "ThreadHandle", ThreadHandle, "InstructionPointer", Context->Eax);
#endif
	else
		LOQ_ntstatus("threading", "p", "ThreadHandle", ThreadHandle);
    if (g_config.injection)
        SetThreadContextHandler(pid, Context);
    if (!g_config.single_process && pid != GetCurrentProcessId())
        pipe("PROCESS:%d:%d,%d", is_suspended(pid, tid), pid, tid);

    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtSuspendThread,
    __in        HANDLE ThreadHandle,
    __out_opt   ULONG *PreviousSuspendCount
) {
	NTSTATUS ret;
	DWORD pid = pid_from_thread_handle(ThreadHandle);
	DWORD tid = tid_from_thread_handle(ThreadHandle);
	ENSURE_ULONG(PreviousSuspendCount);

	if (pid == GetCurrentProcessId() && tid && (tid == g_unhook_detect_thread_id || tid == g_unhook_watcher_thread_id ||
		tid == g_watchdog_thread_id || tid == g_terminate_event_thread_id || tid == g_log_thread_id ||
		tid == g_logwatcher_thread_id || tid == g_procname_watcher_thread_id)) {
		ret = 0;
		*PreviousSuspendCount = 0;
		LOQ_ntstatus("threading", "pLsi", "ThreadHandle", ThreadHandle,
			"SuspendCount", PreviousSuspendCount, "Alert", "Attempted to suspend cuckoomon thread",
			"ProcessId", pid);
	}
	else {
		if (!g_config.single_process)
            pipe("PROCESS:%d:%d,%d", is_suspended(pid, tid), pid, tid);
		ret = Old_NtSuspendThread(ThreadHandle, PreviousSuspendCount);
		LOQ_ntstatus("threading", "pLii", "ThreadHandle", ThreadHandle, "SuspendCount", PreviousSuspendCount, "ThreadId", tid,
		"ProcessId", pid);
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
    if (g_config.injection)
        ResumeThreadHandler(pid);
    if (pid != GetCurrentProcessId())
        pipe("RESUME:%d,%d", pid, tid);

    ret = Old_NtResumeThread(ThreadHandle, SuspendCount);
    LOQ_ntstatus("threading", "pIi", "ThreadHandle", ThreadHandle, "SuspendCount", SuspendCount, "ProcessId", pid);
    return ret;
}

extern DWORD tmphookinfo_threadid;

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
	}

	//remove_ignored_thread(tid);

	if (pid == GetCurrentProcessId() && tid && (tid == g_unhook_detect_thread_id || tid == g_unhook_watcher_thread_id ||
		tid == g_watchdog_thread_id || tid == g_terminate_event_thread_id || tid == g_log_thread_id ||
		tid == g_logwatcher_thread_id || tid == g_procname_watcher_thread_id)) {
		ret = 0;
		LOQ_ntstatus("threading", "phsi", "ThreadHandle", ThreadHandle, "ExitStatus", ExitStatus, "Alert", "Attempted to kill cuckoomon thread",
		"ProcessId", pid);
		return ret;
	}

	LOQ_ntstatus("threading", "phii", "ThreadHandle", ThreadHandle, "ExitStatus", ExitStatus, "ThreadId", tid, "ProcessId", pid);

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
        lpStartAddress, lpParameter, dwCreationFlags | CREATE_SUSPENDED, lpThreadId);

	if (ret != NULL) {
        if (DebuggerEnabled && !called_by_hook()) {
            DoOutputDebugString("CreateThread: Initialising breakpoints for thread %d.\n", *lpThreadId);
            InitNewThreadBreakpoints(*lpThreadId);
        }

        if (!(dwCreationFlags & CREATE_SUSPENDED)) {
            lasterror_t lasterror;
            get_lasterrors(&lasterror);
            ResumeThread(ret);
            set_lasterrors(&lasterror);
        }

        LOQ_nonnull("threading", "pphI", "StartRoutine", lpStartAddress, "Parameter", lpParameter,
            "CreationFlags", dwCreationFlags, "ThreadId", lpThreadId);

        disable_sleep_skip();
    }
    else
        LOQ_nonnull("threading", "pphI", "StartRoutine", lpStartAddress, "Parameter", lpParameter,
            "CreationFlags", dwCreationFlags);

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
        if (pid != GetCurrentProcessId())
            if (!g_config.single_process)
                pipe("PROCESS:%d:%d,%d", is_suspended(pid, *lpThreadId), pid, *lpThreadId);
        else if (DebuggerEnabled && !called_by_hook()) {
            DoOutputDebugString("CreateRemoteThread: Initialising breakpoints for (local) thread %d.\n", *lpThreadId);
            InitNewThreadBreakpoints(*lpThreadId);
        }

        if (!(dwCreationFlags & CREATE_SUSPENDED)) {
			lasterror_t lasterror;
			get_lasterrors(&lasterror);
			ResumeThread(ret);
			set_lasterrors(&lasterror);
		}

		disable_sleep_skip();
	}

	LOQ_nonnull("threading", "ppphI", "ProcessHandle", hProcess, "StartRoutine", lpStartAddress,
        "Parameter", lpParameter, "CreationFlags", dwCreationFlags,
        "ThreadId", lpThreadId, "ProcessId", pid);

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
    ENSURE_HANDLE(ThreadHandle);
	ENSURE_CLIENT_ID(ClientId);

	pid = pid_from_process_handle(ProcessHandle);

	ret = Old_RtlCreateUserThread(ProcessHandle, SecurityDescriptor,
        TRUE, StackZeroBits, StackReserved, StackCommit,
        StartAddress, StartParameter, ThreadHandle, ClientId);
    LOQ_ntstatus("threading", "pippPi", "ProcessHandle", ProcessHandle,
        "CreateSuspended", CreateSuspended, "StartAddress", StartAddress,
        "StartParameter", StartParameter, "ThreadHandle", ThreadHandle,
        "ThreadIdentifier", ClientId->UniqueThread);

	if (NT_SUCCESS(ret) && ClientId && ThreadHandle) {
        DWORD tid = tid_from_thread_handle(ThreadHandle);
        if (pid != GetCurrentProcessId())
            if (!g_config.single_process)
                pipe("PROCESS:%d:%d,%d", is_suspended(pid, tid), pid, tid);
        else if (DebuggerEnabled && !called_by_hook()) {
            DoOutputDebugString("RtlCreateUserThread: Initialising breakpoints for (local) thread %d.\n", tid);
            InitNewThreadBreakpoints(tid);
        }
		if (CreateSuspended == FALSE && is_valid_address_range((ULONG_PTR)ThreadHandle, 4)) {
			lasterror_t lasterror;
			get_lasterrors(&lasterror);
			ResumeThread(*ThreadHandle);
			set_lasterrors(&lasterror);
		}
		disable_sleep_skip();
	}

    LOQ_ntstatus("threading", "pippPi", "ProcessHandle", ProcessHandle,
        "CreateSuspended", CreateSuspended, "StartAddress", StartAddress,
        "StartParameter", StartParameter, "ThreadHandle", ThreadHandle,
        "ThreadId", ClientId->UniqueThread);

    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtSetInformationThread,
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN PVOID ThreadInformation,
    IN ULONG ThreadInformationLength
) {
	NTSTATUS ret;
    ENSURE_HANDLE(ThreadHandle);
    DWORD tid = tid_from_thread_handle(ThreadHandle);

    ret = Old_NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);

    if (ThreadInformationClass == ThreadHideFromDebugger)
        LOQ_ntstatus("threading", "pii", "ThreadHandle", ThreadHandle,
            "ThreadInformationClass", ThreadInformationClass,
            "ThreadId", tid);

    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryInformationThread,
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL
) {
	NTSTATUS ret;
    ENSURE_HANDLE(ThreadHandle);
    DWORD tid = tid_from_thread_handle(ThreadHandle);

    ret = Old_NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);

    LOQ_ntstatus("threading", "pibi", "ThreadHandle", ThreadHandle,
        "ThreadInformationClass", ThreadInformationClass,
        "ThreadInformation", ThreadInformationLength, ThreadInformation,
        "ThreadId", tid);

    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtYieldExecution,
    VOID
) {
	NTSTATUS ret = 0;
    LOQ_void("threading", "");
    ret = Old_NtYieldExecution();
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtContinue,
    IN PCONTEXT ThreadContext,
    IN BOOLEAN  RaiseAlert
)
{
	NTSTATUS ret = 0;
#ifdef CAPE_TRACE
    NtContinueHandler(ThreadContext);
#endif
    ret = Old_NtContinue(ThreadContext, RaiseAlert);
    return ret;
}