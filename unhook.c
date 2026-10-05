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
#include <stdlib.h>
#include "ntapi.h"
#include "hooking.h"
#include "pipe.h"
#include "log.h"
#include "misc.h"
#include "config.h"
#include <Sddl.h>
#include <tlhelp32.h>
#include "CAPE\CAPE.h"
#include "CAPE\Debugger.h"
#include "CAPE\YaraHarness.h"
#include "CAPE\Unpacker.h"

#define UNHOOK_MAXCOUNT 2048
#define UNHOOK_BUFSIZE 32

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern void file_handle_terminate();
extern int DoProcessDump();
extern BOOL ProcessDumped;
extern void DebuggerShutdown(), DumpStrings();
extern HANDLE DebuggerLog, TlsLog;

static HANDLE g_unhook_thread_handle, g_watcher_thread_handle;

// Index for adding new hooks and iterating all existing hooks.
static uint32_t g_index = 0;

// Length of this region.
static uint32_t g_length[UNHOOK_MAXCOUNT];

// Address of the region.
static uint8_t *g_addr[UNHOOK_MAXCOUNT];

// Function name of the region.
static const hook_t *g_unhook_hooks[UNHOOK_MAXCOUNT];

// The original contents of this region, before we modified it.
static uint8_t g_orig[UNHOOK_MAXCOUNT][UNHOOK_BUFSIZE];

// The contents of this region after we modified it.
static uint8_t g_our[UNHOOK_MAXCOUNT][UNHOOK_BUFSIZE];

// If the region has been modified, did we report this already?
static uint8_t g_hook_reported[UNHOOK_MAXCOUNT];

int address_already_hooked(uint8_t *addr)
{
	uint32_t idx;

	for (idx = 0; idx < g_index; idx++)
		/* hack to handle the safe hooktype */
		if (addr == g_addr[idx] || addr == (g_addr[idx] + 5))
			return 1;

	return 0;
}

uint32_t get_first_zero_addr_index(void)
{
	uint32_t i;
	for (i = 0; i < g_index; i++) {
		if (g_addr[i] == NULL) {
			g_addr[i] = (uint8_t *)1;
			return i;
		}
	}
	return g_index;
}

static int max_unhook_warned;

void unhook_detect_add_region(const hook_t *hook, uint8_t *addr,
	const uint8_t *orig, const uint8_t *our, uint32_t length)
{
	uint32_t index;

	if(g_index >= UNHOOK_MAXCOUNT - 1) {
		if (!max_unhook_warned)
			pipe("CRITICAL:Reached maximum number of unhook detection entries!");
		max_unhook_warned = 1;
		return;
	}

	if (address_already_hooked(addr))
		return;

	index = get_first_zero_addr_index();

	g_length[index] = MIN(length, UNHOOK_BUFSIZE);
	g_addr[index] = addr;
	g_unhook_hooks[index] = hook;

	memcpy(g_orig[index], orig, g_length[index]);
	memcpy(g_our[index], our, g_length[index]);
	g_hook_reported[index] = 0;

	if (index == g_index)
		g_index++;
}

void invalidate_regions_for_hook(const hook_t *hook)
{
	uint32_t idx;

	for (idx = 0; idx < g_index; idx++) {
		if (g_unhook_hooks[idx] == hook) {
			/* get the unhook watcher to ignore this region */
			g_hook_reported[idx] = 1;
			/* since this hook was removed, we shouldn't prevent the same address from being hooked again
			   later, see address_already_hooked() above */
			g_addr[idx] = 0;
		}
	}
}

void remove_hook(const char *funcname)
{
	for (uint32_t idx = 0; idx < g_index; idx++) {
		if (g_addr[idx] && !stricmp(g_unhook_hooks[idx]->funcname, funcname)) {
			DWORD old_protect;
			if (!VirtualProtect(g_addr[idx], g_length[idx], PAGE_EXECUTE_READWRITE, &old_protect))
				return;
			memcpy(g_addr[idx], g_orig[idx], g_length[idx]);
			VirtualProtect(g_addr[idx], g_length[idx], old_protect, &old_protect);
			/* get the unhook watcher to ignore this region */
			g_hook_reported[idx] = 1;
			g_addr[idx] = 0;
		}
	}
}

void remove_all_hooks(void)
{
	for (uint32_t idx = 0; idx < g_index; idx++) {
		DWORD old_protect;
		if (!g_addr[idx])
			continue;
		if (!VirtualProtect(g_addr[idx], g_length[idx], PAGE_EXECUTE_READWRITE, &old_protect))
			continue;				/* skip one bad region, keep restoring the rest */
		memcpy(g_addr[idx], g_orig[idx], g_length[idx]);	/* restore original (pre-hook) bytes */
		VirtualProtect(g_addr[idx], g_length[idx], old_protect, &old_protect);
		/* get the unhook watcher to ignore this region */
		g_hook_reported[idx] = 1;
		g_addr[idx] = 0;
	}
}

void restore_hooks_on_range(ULONG_PTR start, ULONG_PTR end)
{
	lasterror_t lasterror;
	uint32_t idx;

	get_lasterrors(&lasterror);

	__try {
		for (idx = 0; idx < g_index; idx++) {
			DWORD old_protect;
			if ((ULONG_PTR)g_addr[idx] < start || ((ULONG_PTR)g_addr[idx] + g_length[idx]) > end)
				continue;
			if (!memcmp(g_orig[idx], g_addr[idx], g_length[idx])) {
				if (!VirtualProtect(g_addr[idx], g_length[idx], PAGE_EXECUTE_READWRITE, &old_protect))
					return;
				memcpy(g_addr[idx], g_our[idx], g_length[idx]);
				VirtualProtect(g_addr[idx], g_length[idx], old_protect, &old_protect);
				log_hook_restoration(g_unhook_hooks[idx]);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		;
	}

	set_lasterrors(&lasterror);
}


void restore_hook(uint32_t idx)
{
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	__try {
		for (uint32_t i = 0; i < g_index; i++) {
			if (i == idx) {
				DWORD old_protect;
				if (!VirtualProtect(g_addr[idx], g_length[idx], PAGE_EXECUTE_READWRITE, &old_protect))
					return;
				memcpy(g_addr[idx], g_our[idx], g_length[idx]);
				VirtualProtect(g_addr[idx], g_length[idx], old_protect, &old_protect);
				log_hook_restoration(g_unhook_hooks[idx]);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		;
	}

	set_lasterrors(&lasterror);
}


static DWORD WINAPI _unhook_detect_thread(LPVOID param)
{
	static int watcher_first = 1;
	uint32_t idx;

	hook_disable();

	while (1) {
		if(WaitForSingleObject(g_watcher_thread_handle,
				500) != WAIT_TIMEOUT) {
			if(watcher_first != 0) {
				if(is_shutting_down() == 0) {
					log_anomaly("unhook", "Unhook watcher thread has been corrupted!");
				}
				watcher_first = 0;
			}
			raw_sleep(100);
		}

		for (idx = 0; idx < g_index; idx++) {
			if (g_unhook_hooks[idx]->is_hooked && g_hook_reported[idx] == 0) {
				char *tmpbuf = NULL;
				if (!is_valid_address_range((ULONG_PTR)g_addr[idx], g_length[idx]))
					continue;
				__try {
					int is_modification = 1;
					// Check whether this memory region still equals what we made it.
					if (!memcmp(g_addr[idx], g_our[idx], g_length[idx]))
						continue;

					// Attempt restoration
					if (g_config.hook_restore) {
						restore_hook(idx);
						if (!memcmp(g_addr[idx], g_our[idx], g_length[idx]))
							continue;
					}

					// If the memory region matches the original contents, then it
					// has been restored to its original state.
					if (!memcmp(g_orig[idx], g_addr[idx], g_length[idx]))
						is_modification = 0;

					if (is_shutting_down() == 0) {
						if (is_modification) {
							char *tmpbuf2;
							tmpbuf2 = tmpbuf = malloc(g_length[idx]);
							memcpy(tmpbuf, g_addr[idx], g_length[idx]);
							log_hook_modification(g_unhook_hooks[idx], g_our[idx], tmpbuf, g_length[idx]);
							tmpbuf = NULL;
							free(tmpbuf2);
						}
						else
							log_hook_removal(g_unhook_hooks[idx]);
					}
					g_hook_reported[idx] = 1;
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					// cuckoo currently has no handling for FreeLibrary, so if a hooked DLL ends up
					// being unloaded we would crash in the code above
					if (tmpbuf)
						free(tmpbuf);
				}
			}
		}
	}

	return 0;
}

static DWORD WINAPI _unhook_watch_thread(LPVOID param)
{
	hook_disable();

	while (WaitForSingleObject(g_unhook_thread_handle, 1000) == WAIT_TIMEOUT);

	if(is_shutting_down() == 0) {
		log_anomaly("unhook", "Unhook detection thread has been corrupted!");
	}
	return 0;
}

DWORD g_unhook_detect_thread_id;
DWORD g_unhook_watcher_thread_id;

int unhook_init_detection()
{
	g_unhook_thread_handle =
		CreateThread(NULL, 0, &_unhook_detect_thread, NULL, 0, &g_unhook_detect_thread_id);

	g_watcher_thread_handle =
		CreateThread(NULL, 0, &_unhook_watch_thread, NULL, 0, &g_unhook_watcher_thread_id);

	if(g_unhook_thread_handle != NULL && g_watcher_thread_handle != NULL) {
		return 0;
	}

	pipe("CRITICAL:Error initializing unhook detection threads!");
	return -1;
}

static HANDLE g_terminate_event_thread_handle;
HANDLE g_terminate_event_handle;

static DWORD WINAPI _terminate_event_thread(LPVOID param)
{
	hook_disable();

	DWORD ProcessId = GetCurrentProcessId();

	WaitForSingleObject(g_terminate_event_handle, INFINITE);

	CloseHandle(g_terminate_event_handle);

	if (g_config.unhook_on_terminate) {
		DebugOutput("Terminate Event: unhooking monitor from process %d\n", ProcessId);
		g_config.hook_restore = 0;	/* stop the unhook detect thread re-applying our hooks */
		remove_all_hooks();
	}

	if (g_config.debugger)
		DebuggerShutdown();

	DumpStrings();

	if (g_config.procdump || g_config.procmemdump) {
		if (!ProcessDumped) {
			DebugOutput("Terminate Event: Attempting to dump process %d\n", ProcessId);
			DoProcessDump();
		}
		else
			DebugOutput("Terminate Event: Process %d has already been dumped(!)\n", ProcessId);
	}
	else
		DebugOutput("Terminate Event: Skipping dump of process %d\n", ProcessId);

	if (CurrentRegion) {
		ProcessTrackedRegion(CurrentRegion);
		CurrentRegion = NULL;
	}

	file_handle_terminate();

	if (g_config.yarascan)
		YaraShutdown();

	if (TlsLog && TlsLog != INVALID_HANDLE_VALUE)
		CloseHandle(TlsLog);

	g_terminate_event_handle = OpenEventA(EVENT_MODIFY_STATE, FALSE, g_config.terminate_event_name);
	if (g_terminate_event_handle) {
		SetEvent(g_terminate_event_handle);
		CloseHandle(g_terminate_event_handle);
		DebugOutput("Terminate Event: monitor shutdown complete for process %d\n", ProcessId);
	}
	else
		DebugOutput("Terminate Event: Shutdown complete for process %d but failed to inform analyzer.\n", ProcessId);

	log_flush();
	if (g_config.terminate_processes)
		ExitProcess(0);
	return 0;
}

DWORD g_terminate_event_thread_id;

int terminate_event_init()
{
	SECURITY_DESCRIPTOR sd;
	SECURITY_ATTRIBUTES sa;
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = FALSE;
	sa.lpSecurityDescriptor = &sd;
	g_terminate_event_handle = CreateEventA(&sa, FALSE, FALSE, g_config.terminate_event_name);

	g_terminate_event_thread_handle =
		CreateThread(NULL, 0, &_terminate_event_thread, NULL, 0, &g_terminate_event_thread_id);

	if (g_terminate_event_handle != NULL && g_terminate_event_thread_handle != NULL)
		return 0;

	pipe("CRITICAL:Error initializing terminate event thread!");
	return -1;
}

static HANDLE g_procname_watch_thread_handle;

static UNICODE_STRING InitialProcessName;
static UNICODE_STRING InitialProcessPath;

static DWORD WINAPI _procname_watch_thread(LPVOID param)
{
	hook_disable();

	while (1) {
		PLDR_DATA_TABLE_ENTRY mod; PEB *peb = (PEB *)get_peb();
		__try {
			mod = (PLDR_DATA_TABLE_ENTRY)peb->LoaderData->InLoadOrderModuleList.Flink;
			if (InitialProcessName.Length != mod->BaseDllName.Length || InitialProcessPath.Length != mod->FullDllName.Length ||
				memcmp(InitialProcessName.Buffer, mod->BaseDllName.Buffer, InitialProcessName.Length) ||
				memcmp(InitialProcessPath.Buffer, mod->FullDllName.Buffer, InitialProcessPath.Length)) {
				// allow concurrent modifications to settle, as malware doesn't particularly care about proper locking
				Sleep(50);

				log_procname_anomaly(&InitialProcessName, &InitialProcessPath, &mod->BaseDllName, &mod->FullDllName);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}

		Sleep(1000);
	}

	return 0;
}

DWORD g_procname_watcher_thread_id;

int procname_watch_init()
{
	PLDR_DATA_TABLE_ENTRY mod; PEB *peb = (PEB *)get_peb();
	mod = (PLDR_DATA_TABLE_ENTRY)peb->LoaderData->InLoadOrderModuleList.Flink;

	InitialProcessName.MaximumLength = mod->BaseDllName.MaximumLength;
	InitialProcessName.Length = mod->BaseDllName.Length;
	InitialProcessName.Buffer = (PWSTR)calloc(mod->BaseDllName.MaximumLength, 1);
	memcpy(InitialProcessName.Buffer, mod->BaseDllName.Buffer, InitialProcessName.Length);

	InitialProcessPath.MaximumLength = mod->FullDllName.MaximumLength;
	InitialProcessPath.Length = mod->FullDllName.Length;
	InitialProcessPath.Buffer = (PWSTR)calloc(mod->FullDllName.MaximumLength, 1);
	memcpy(InitialProcessPath.Buffer, mod->FullDllName.Buffer, InitialProcessPath.Length);

	g_procname_watch_thread_handle =
		CreateThread(NULL, 0, &_procname_watch_thread, NULL, 0, &g_procname_watcher_thread_id);

	if (g_procname_watch_thread_handle != NULL)
		return 0;

	pipe("CRITICAL:Error initializing procname watch thread!");
	return -1;
}


DWORD g_watchdog_thread_id;

#define WATCHDOG_MAX_THREADS 128
#define WATCHDOG_MAX_FRAMES  32

typedef struct _WATCHDOG_REQUEST {
	DWORD tid;
	HANDLE hThread;
	ULONG generation;
	volatile LONG status; // 0 = PENDING, 1 = COMPLETED_BY_APC, 2 = FALLBACK_TAKEN
	volatile LONG apc_dispatched_count;
	volatile LONG apc_executed_count;
	BOOL sampled_via_apc;
	BOOL in_snapshot;
	CONTEXT ctx;
	ULONG_PTR backtrace[WATCHDOG_MAX_FRAMES];
	unsigned int backtrace_count;
} WATCHDOG_REQUEST;

static WATCHDOG_REQUEST g_watchdog_requests[WATCHDOG_MAX_THREADS];
static ULONG g_watchdog_generation = 0;

static WATCHDOG_REQUEST *watchdog_get_or_create_slot(DWORD tid)
{
	int i;
	int free_idx = -1;
	for (i = 0; i < WATCHDOG_MAX_THREADS; i++) {
		if (g_watchdog_requests[i].tid == tid)
			return &g_watchdog_requests[i];
		if (free_idx == -1 && g_watchdog_requests[i].tid == 0)
			free_idx = i;
	}
	if (free_idx != -1) {
		memset(&g_watchdog_requests[free_idx], 0, sizeof(WATCHDOG_REQUEST));
		g_watchdog_requests[free_idx].tid = tid;
		return &g_watchdog_requests[free_idx];
	}
	return NULL;
}

static VOID NTAPI WatchdogApcCallback(ULONG_PTR Parameter)
{
	WATCHDOG_REQUEST *req = (WATCHDOG_REQUEST *)Parameter;
	if (!req)
		return;

	InterlockedIncrement(&req->apc_executed_count);

	// Atomically try to claim the slot (transition from 0 -> 1)
	if (InterlockedCompareExchange(&req->status, 1, 0) != 0)
		return;

	memset(&req->ctx, 0, sizeof(req->ctx));
	req->ctx.ContextFlags = CONTEXT_FULL;
	RtlCaptureContext(&req->ctx);

	req->backtrace_count = 0;
#ifndef _WIN64
	{
		ULONG_PTR top = get_stack_top();
		ULONG_PTR bottom = get_stack_bottom();
		ULONG_PTR _ebp = req->ctx.Ebp;
		ULONG_PTR _esp = req->ctx.Esp;
		unsigned int count = 0;

		__try {
			if (_esp >= bottom && _esp <= (top - sizeof(ULONG_PTR))) {
				req->backtrace[count++] = *(ULONG_PTR *)_esp;
			}
			while (_ebp >= bottom && _ebp <= (top - (2 * sizeof(ULONG_PTR))) && count < WATCHDOG_MAX_FRAMES) {
				ULONG_PTR retaddr = *(ULONG_PTR *)(_ebp + sizeof(ULONG_PTR));
				ULONG_PTR next_ebp = *(ULONG_PTR *)_ebp;
				if (next_ebp <= _ebp)
					break;
				_ebp = next_ebp;
				if (retaddr)
					req->backtrace[count++] = retaddr;
				else
					break;
			}
		}
		__except(EXCEPTION_EXECUTE_HANDLER) {
		}
		req->backtrace_count = count;
	}
#else
	{
		CONTEXT local_ctx;
		memcpy(&local_ctx, &req->ctx, sizeof(CONTEXT));
		DWORD64 imgbase;
		PRUNTIME_FUNCTION runfunc;
		KNONVOLATILE_CONTEXT_POINTERS nvctx;
		PVOID handlerdata;
		ULONG_PTR establisherframe;
		unsigned int frame = 0;

		if (!srw_lock_held()) {
			__try {
				for (frame = 0; frame < WATCHDOG_MAX_FRAMES; frame++) {
					req->backtrace[frame] = (ULONG_PTR)local_ctx.Rip;
					runfunc = RtlLookupFunctionEntry(local_ctx.Rip, &imgbase, NULL);
					memset(&nvctx, 0, sizeof(nvctx));
					if (runfunc == NULL) {
						if (our_isbadreadptr((PVOID)local_ctx.Rsp, sizeof(PVOID)))
							break;
						local_ctx.Rip = (ULONG_PTR)(*(ULONG_PTR *)local_ctx.Rsp);
						local_ctx.Rsp += 8;
					}
					else {
						RtlVirtualUnwind(UNW_FLAG_NHANDLER, imgbase, local_ctx.Rip, runfunc, &local_ctx, &handlerdata, &establisherframe, &nvctx);
					}
					if (!local_ctx.Rip)
						break;
				}
			}
			__except(EXCEPTION_EXECUTE_HANDLER) {
			}
			req->backtrace_count = frame;
		}
	}
#endif

	req->sampled_via_apc = TRUE;
}

#ifndef _WIN64
static unsigned int safe_capture_suspended_backtrace_x86(HANDLE hThread, CONTEXT *ctx, ULONG_PTR *backtrace, unsigned int max_depth)
{
	unsigned int count = 0;
	THREAD_BASIC_INFORMATION tbi;
	ULONG ulSize = 0;
	ULONG_PTR top = 0, bottom = 0;
	ULONG_PTR _ebp, _esp;

	if (pNtQueryInformationThread && pNtQueryInformationThread(hThread, 0, &tbi, sizeof(tbi), &ulSize) >= 0 && tbi.TebBaseAddress) {
		PNT_TIB tib = (PNT_TIB)tbi.TebBaseAddress;
		__try {
			top = (ULONG_PTR)tib->StackBase;
			bottom = (ULONG_PTR)tib->StackLimit;
		}
		__except(EXCEPTION_EXECUTE_HANDLER) {
			top = 0;
			bottom = 0;
		}
	}

	_ebp = ctx->Ebp;
	_esp = ctx->Esp;

	__try {
		if (top && bottom) {
			if (_esp >= bottom && _esp <= (top - sizeof(ULONG_PTR))) {
				backtrace[count++] = *(ULONG_PTR *)_esp;
			}
			while (_ebp >= bottom && _ebp <= (top - (2 * sizeof(ULONG_PTR))) && count < max_depth) {
				ULONG_PTR retaddr = *(ULONG_PTR *)(_ebp + sizeof(ULONG_PTR));
				ULONG_PTR next_ebp = *(ULONG_PTR *)_ebp;
				if (next_ebp <= _ebp)
					break;
				_ebp = next_ebp;
				if (retaddr)
					backtrace[count++] = retaddr;
				else
					break;
			}
		} else {
			while (_ebp && count < max_depth) {
				ULONG_PTR retaddr = *(ULONG_PTR *)(_ebp + sizeof(ULONG_PTR));
				ULONG_PTR next_ebp = *(ULONG_PTR *)_ebp;
				if (next_ebp <= _ebp)
					break;
				_ebp = next_ebp;
				if (retaddr)
					backtrace[count++] = retaddr;
				else
					break;
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
	}
	return count;
}
#else
static unsigned int safe_unwind_backtrace_x64(CONTEXT *ctx, ULONG_PTR *backtrace, unsigned int max_depth)
{
	CONTEXT local_ctx;
	memcpy(&local_ctx, ctx, sizeof(CONTEXT));
	DWORD64 imgbase;
	PRUNTIME_FUNCTION runfunc;
	KNONVOLATILE_CONTEXT_POINTERS nvctx;
	PVOID handlerdata;
	ULONG_PTR establisherframe;
	unsigned int frame = 0;

	if (srw_lock_held())
		return 0;

	__try {
		for (frame = 0; frame < max_depth; frame++) {
			backtrace[frame] = (ULONG_PTR)local_ctx.Rip;
			runfunc = RtlLookupFunctionEntry(local_ctx.Rip, &imgbase, NULL);
			memset(&nvctx, 0, sizeof(nvctx));
			if (runfunc == NULL) {
				if (our_isbadreadptr((PVOID)local_ctx.Rsp, sizeof(PVOID)))
					break;
				local_ctx.Rip = (ULONG_PTR)(*(ULONG_PTR *)local_ctx.Rsp);
				local_ctx.Rsp += 8;
			}
			else {
				RtlVirtualUnwind(UNW_FLAG_NHANDLER, imgbase, local_ctx.Rip, runfunc, &local_ctx, &handlerdata, &establisherframe, &nvctx);
			}
			if (!local_ctx.Rip)
				break;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
	}
	return frame;
}
#endif

static void watchdog_log_sample(WATCHDOG_REQUEST *req)
{
	char msg[4096];
	char *dllname;
	unsigned int off = 0;
	unsigned int i;

#ifdef _WIN64
	dllname = convert_address_to_dll_name_and_offset((ULONG_PTR)req->ctx.Rip, &off);
	_snprintf_s(msg, sizeof(msg), _TRUNCATE,
		"INFO: PID %u thread: %u [%s] RIP: %s+%x(0x%I64x) RAX: 0x%I64x RBX: 0x%I64x RCX: 0x%I64x RDX: 0x%I64x RSI: 0x%I64x RDI: 0x%I64x RBP: 0x%I64x RSP: 0x%I64x",
		GetCurrentProcessId(), req->tid, req->sampled_via_apc ? "APC" : "BUSY",
		dllname ? dllname : "", off, (ULONG_PTR)req->ctx.Rip,
		(ULONG_PTR)req->ctx.Rax, (ULONG_PTR)req->ctx.Rbx, (ULONG_PTR)req->ctx.Rcx, (ULONG_PTR)req->ctx.Rdx,
		(ULONG_PTR)req->ctx.Rsi, (ULONG_PTR)req->ctx.Rdi, (ULONG_PTR)req->ctx.Rbp, (ULONG_PTR)req->ctx.Rsp);
#else
	dllname = convert_address_to_dll_name_and_offset((ULONG_PTR)req->ctx.Eip, &off);
	_snprintf_s(msg, sizeof(msg), _TRUNCATE,
		"INFO: PID %u thread: %u [%s] EIP: %s+%x(0x%lx) EAX: 0x%lx EBX: 0x%lx ECX: 0x%lx EDX: 0x%lx ESI: 0x%lx EDI: 0x%lx EBP: 0x%lx ESP: 0x%lx",
		GetCurrentProcessId(), req->tid, req->sampled_via_apc ? "APC" : "BUSY",
		dllname ? dllname : "", off, (ULONG_PTR)req->ctx.Eip,
		(ULONG_PTR)req->ctx.Eax, (ULONG_PTR)req->ctx.Ebx, (ULONG_PTR)req->ctx.Ecx, (ULONG_PTR)req->ctx.Edx,
		(ULONG_PTR)req->ctx.Esi, (ULONG_PTR)req->ctx.Edi, (ULONG_PTR)req->ctx.Ebp, (ULONG_PTR)req->ctx.Esp);
#endif

	if (dllname)
		free(dllname);

	for (i = 0; i < req->backtrace_count; i++) {
		char *dllname2 = convert_address_to_dll_name_and_offset(req->backtrace[i], &off);
		char frame_buf[128];
#ifdef _WIN64
		_snprintf_s(frame_buf, sizeof(frame_buf), _TRUNCATE, " %s+%x(0x%I64x)", dllname2 ? dllname2 : "", off, (ULONG_PTR)req->backtrace[i]);
#else
		_snprintf_s(frame_buf, sizeof(frame_buf), _TRUNCATE, " %s+%x(0x%lx)", dllname2 ? dllname2 : "", off, (ULONG_PTR)req->backtrace[i]);
#endif
		if (dllname2)
			free(dllname2);
		strncat_s(msg, sizeof(msg), frame_buf, _TRUNCATE);
	}
	strncat_s(msg, sizeof(msg), "\n", _TRUNCATE);
	pipe("%z", msg);
}

static DWORD WINAPI _watchdog_thread(LPVOID param)
{
	(void)param;
	hook_disable();

	while (1) {
		int interval = g_config.watchdog_interval > 0 ? g_config.watchdog_interval : 5000;
		int apc_wait = 500;
		int i;
		HANDLE hSnap;
		int remaining_sleep;

		if (interval < 600)
			apc_wait = interval / 2;

		// Mark all slots as not seen in current snapshot
		for (i = 0; i < WATCHDOG_MAX_THREADS; i++) {
			g_watchdog_requests[i].in_snapshot = FALSE;
		}

		// Enumerate active threads of current process
		hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hSnap != INVALID_HANDLE_VALUE) {
			THREADENTRY32 te;
			te.dwSize = sizeof(te);
			if (Thread32First(hSnap, &te)) {
				do {
					if (te.th32OwnerProcessID == GetCurrentProcessId() &&
						te.th32ThreadID != GetCurrentThreadId() &&
						!is_monitor_thread(te.th32ThreadID)) {

						WATCHDOG_REQUEST *req = watchdog_get_or_create_slot(te.th32ThreadID);
						if (req) {
							req->in_snapshot = TRUE;

							// If an APC is not currently in flight for this thread, queue one
							if (req->apc_dispatched_count == req->apc_executed_count) {
								HANDLE hThread;
								req->generation = ++g_watchdog_generation;
								req->status = 0; // PENDING
								req->sampled_via_apc = FALSE;
								req->backtrace_count = 0;

								hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
								if (!hThread)
									hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);

								if (hThread) {
									req->hThread = hThread;
									if (QueueUserAPC((PAPCFUNC)WatchdogApcCallback, hThread, (ULONG_PTR)req) != 0) {
										InterlockedIncrement(&req->apc_dispatched_count);
									}
									else {
										CloseHandle(hThread);
										req->hThread = NULL;
										req->status = 2; // skip to fallback later if needed
									}
								}
							}
						}
					}
				} while (Thread32Next(hSnap, &te));
			}
			CloseHandle(hSnap);
		}

		// Allow alertable threads to execute their APC
		raw_sleep(apc_wait);

		// Evaluate sampled threads and fallback to safe suspend for busy ones
		for (i = 0; i < WATCHDOG_MAX_THREADS; i++) {
			WATCHDOG_REQUEST *req = &g_watchdog_requests[i];
			LONG prev;
			if (!req->tid || !req->in_snapshot)
				continue;

			// Check if APC executed
			prev = InterlockedCompareExchange(&req->status, 2, 0);
			if (prev == 1) {
				// APC succeeded!
				if (req->hThread) {
					CloseHandle(req->hThread);
					req->hThread = NULL;
				}
				watchdog_log_sample(req);
			}
			else {
				// APC did not execute (thread is busy or in non-alertable wait).
				// Perform Safe Suspend/Resume Fallback.
				HANDLE hThread = req->hThread;
				if (!hThread) {
					hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, req->tid);
					if (!hThread)
						hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, req->tid);
				}

				if (hThread) {
					if (SuspendThread(hThread) != (DWORD)-1) {
						memset(&req->ctx, 0, sizeof(req->ctx));
						req->ctx.ContextFlags = CONTEXT_FULL;
						if (GetThreadContext(hThread, &req->ctx)) {
#ifndef _WIN64
							req->backtrace_count = safe_capture_suspended_backtrace_x86(hThread, &req->ctx, req->backtrace, WATCHDOG_MAX_FRAMES);
#endif
						}
						ResumeThread(hThread);

#ifdef _WIN64
						// On x64, unwind stack safely AFTER resuming the thread to avoid lock contention
						req->backtrace_count = safe_unwind_backtrace_x64(&req->ctx, req->backtrace, WATCHDOG_MAX_FRAMES);
#endif
						req->sampled_via_apc = FALSE;
						watchdog_log_sample(req);
					}
					CloseHandle(hThread);
					req->hThread = NULL;
				}
			}
		}

		// Cleanup terminated threads from our slots
		for (i = 0; i < WATCHDOG_MAX_THREADS; i++) {
			WATCHDOG_REQUEST *req = &g_watchdog_requests[i];
			if (req->tid && !req->in_snapshot) {
				if (req->hThread) {
					CloseHandle(req->hThread);
					req->hThread = NULL;
				}
				memset(req, 0, sizeof(WATCHDOG_REQUEST));
			}
		}

		// Sleep for the remainder of the interval
		remaining_sleep = interval - apc_wait;
		if (remaining_sleep > 0)
			raw_sleep(remaining_sleep);
	}

	return 0;
}

int init_watchdog(void)
{
	HANDLE hWatchdog = CreateThread(NULL, 0, &_watchdog_thread, NULL, 0, &g_watchdog_thread_id);
	if (hWatchdog) {
		CloseHandle(hWatchdog);
		return 0;
	}
	return -1;
}
