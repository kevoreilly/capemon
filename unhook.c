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
#include "pipe.h"
#include "log.h"
#include "misc.h"
#include "config.h"
#include <Sddl.h>
#include "CAPE\YaraHarness.h"

#define UNHOOK_MAXCOUNT 2048
#define UNHOOK_BUFSIZE 32

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern void file_handle_terminate();
extern int DoProcessDump();
extern BOOL ProcessDumped;
extern void ClearAllBreakpoints();
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

	if(g_index == UNHOOK_MAXCOUNT - 1) {
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

void restore_hooks_on_range(ULONG_PTR start, ULONG_PTR end)
{
	lasterror_t lasterror;
	uint32_t idx;

	get_lasterrors(&lasterror);

	__try {
		for (idx = 0; idx < g_index; idx++) {
			if ((ULONG_PTR)g_addr[idx] < start || ((ULONG_PTR)g_addr[idx] + g_length[idx]) > end)
				continue;
			if (!memcmp(g_orig[idx], g_addr[idx], g_length[idx])) {
				memcpy(g_addr[idx], g_our[idx], g_length[idx]);
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
				if (!is_valid_address_range((ULONG_PTR)g_addr[idx], g_length[idx])) {
					continue;
				}
				__try {
					int is_modification = 1;
					// Check whether this memory region still equals what we made it.
					if (!memcmp(g_addr[idx], g_our[idx], g_length[idx])) {
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

	if (g_config.debugger)
		DebuggerShutdown();

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

	file_handle_terminate();

	DumpStrings();

	if (g_config.yarascan)
		YaraShutdown();

	if (TlsLog && TlsLog != INVALID_HANDLE_VALUE)
		CloseHandle(TlsLog);

	g_terminate_event_handle = OpenEventA(EVENT_MODIFY_STATE, FALSE, g_config.terminate_event_name);
	if (g_terminate_event_handle) {
		SetEvent(g_terminate_event_handle);
		CloseHandle(g_terminate_event_handle);
		DebugOutput("Terminate Event: CAPE shutdown complete for process %d\n", ProcessId);
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

#ifndef _WIN64
static ULONG_PTR capemonaddrs[60];
static int capemonaddrs_num;

static int find_capemon_addrs(void *unused, ULONG_PTR addr)
{
	if (capemonaddrs_num < 60)
		capemonaddrs[capemonaddrs_num++] = addr;
	return 0;
}

static int _operate_on_backtrace(ULONG_PTR retaddr, ULONG_PTR _ebp, void *extra, int(*func)(void *, ULONG_PTR))
{
	int ret = 0;

	while (_ebp)
	{
		// obtain the return address and the next value of ebp
		ULONG_PTR addr = *(ULONG_PTR *)(_ebp + sizeof(ULONG_PTR));
		_ebp = *(ULONG_PTR *)_ebp;

		ret = func(extra, addr);
		if (ret)
			return ret;
	}

	return ret;
}

static DWORD WINAPI _watchdog_thread(LPVOID param)
{
	hook_disable();

	while (1) {
		char msg[MAX_PATH];
		char *dllname;
		unsigned int off = 0;
		int i;

		CONTEXT ctx;
		raw_sleep(5000);
		memset(&capemonaddrs, 0, sizeof(capemonaddrs));
		capemonaddrs_num = 0;
		memset(&ctx, 0, sizeof(ctx));
		SuspendThread((HANDLE)param);
		ctx.ContextFlags = CONTEXT_FULL;
		GetThreadContext((HANDLE)param, &ctx);
		dllname = convert_address_to_dll_name_and_offset(ctx.Eip, &off);
		_snprintf_s(msg, MAX_PATH, _TRUNCATE, "INFO: PID %u thread: %p EIP: %s+%x(0x%lx) EAX: 0x%lx EBX: 0x%lx ECX: 0x%lx EDX: 0x%lx ESI: 0x%lx EDI: 0x%lx EBP: 0x%lx ESP: 0x%lx\n", GetCurrentProcessId(), param, dllname ? dllname : "", off, ctx.Eip, ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx, ctx.Esi, ctx.Edi, ctx.Ebp, ctx.Esp);

		_operate_on_backtrace(ctx.Eip, ctx.Ebp, NULL, find_capemon_addrs);

		for (i = 0; i < capemonaddrs_num; i++) {
			char *dllname2 = convert_address_to_dll_name_and_offset(capemonaddrs[i], &off);
			sprintf(msg + strlen(msg), " %s+%x(0x%lx)", dllname2 ? dllname2 : "", off, capemonaddrs[i]);
			if (dllname2)
				free(dllname2);
		}

		if (dllname)
			free(dllname);
		ResumeThread((HANDLE)param);
		pipe(msg);
	}
}

int init_watchdog()
{
	HANDLE mainthreadhandle;

	DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &mainthreadhandle, THREAD_ALL_ACCESS, FALSE, 0);

	CreateThread(NULL, 0, &_watchdog_thread, mainthreadhandle, 0, &g_watchdog_thread_id);

	return 0;
}
#endif
