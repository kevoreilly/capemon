/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2014 Cuckoo Sandbox Developers

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
#include <stddef.h>
#include "ntapi.h"
#include <psapi.h>
#include "hooking.h"
#include "hooks.h"
#include "ignore.h"
#include "unhook.h"
#include "misc.h"
#include "pipe.h"
#include "CAPE\CAPE.h"
#include "CAPE\Debugger.h"
#include "CAPE\Unpacker.h"
#include "CAPE\YaraHarness.h"

#ifdef _WIN64
#define TLS_LAST_WIN32_ERROR 0x68
#define TLS_LAST_NTSTATUS_ERROR 0x1250
#else
#define TLS_LAST_WIN32_ERROR 0x34
#define TLS_LAST_NTSTATUS_ERROR 0xbf4
#endif
#define HOOK_TIME_SAMPLE 100
#define HOOK_RATE_LIMIT 0x100

static lookup_t g_hook_info;
lookup_t g_caller_regions;

extern BOOL inside_hook(LPVOID Address);
extern BOOL SetInitialBreakpoints(PVOID ImageBase);
extern BOOL BreakpointOnReturn(PVOID Address);
extern ULONG_PTR base_of_dll_of_interest;
extern BOOL BreakpointsSet;
extern PVOID ImageBase;
extern BOOLEAN g_dll_main_complete;

void emit_rel(unsigned char *buf, unsigned char *source, unsigned char *target)
{
	*(DWORD *)buf = (DWORD)(target - (source + 4));
}

// need to be very careful about what we call in here, as it can be called in the context of any hook
// including those that hold the loader lock

static int set_caller_info_fallback(void *_hook_info, ULONG_PTR addr)
{
	hook_info_t *hookinfo = _hook_info;

	if (addr && !inside_hook((PVOID)addr)) {
		if (!hookinfo->main_caller_retaddr) {
			hookinfo->main_caller_retaddr = addr;
			return 0;
		}
		else if (!hookinfo->parent_caller_retaddr) {
			hookinfo->parent_caller_retaddr = addr;
			return 1;
		}
	}

	return 0;
}

static void caller_dispatch(hook_info_t *hookinfo, ULONG_PTR addr)
{
	if (g_config.tlsdump || !stricmp(hookinfo->current_hook->funcname, "RtlDispatchException") || !stricmp(hookinfo->current_hook->funcname, "NtContinue"))
		return;
	if (!g_config.unpacker && !g_config.caller_regions)
		return;
	PVOID AllocationBase = GetAllocationBase((PVOID)addr);
	if (!AllocationBase || !g_dll_main_complete || hookinfo->main_caller_retaddr)
		return;
	PTRACKEDREGION TrackedRegion = NULL;
	if (g_config.unpacker)
	{
		TrackedRegion = GetTrackedRegion((PVOID)AllocationBase);
		if (TrackedRegion && (TrackedRegion->Address || TrackedRegion->PagesDumped))
			return;
		if (!TrackedRegion) {
			TrackedRegion = AddTrackedRegion((PVOID)AllocationBase, 0);
			if (!TrackedRegion) {
				DebugOutput("caller_dispatch: Failed to add region at 0x%p to tracked regions list (%ws::%s returns to 0x%p, thread %d).\n", AllocationBase, hookinfo->current_hook->library, hookinfo->current_hook->funcname, addr, GetCurrentThreadId());
				return;
			}
			DebugOutput("caller_dispatch: Added region at 0x%p to tracked regions list (%ws::%s returns to 0x%p, thread %d).\n", AllocationBase, hookinfo->current_hook->library, hookinfo->current_hook->funcname, addr, GetCurrentThreadId());
		}
		TrackedRegion->Address = (PVOID)addr;
	}
	if (g_config.caller_regions) {
		if (lookup_get(&g_caller_regions, (ULONG_PTR)AllocationBase, 0))
			return;
		lookup_add(&g_caller_regions, (ULONG_PTR)AllocationBase, 0);
		DebugOutput("caller_dispatch: Adding region at 0x%p to caller regions list (%ws::%s returns to 0x%p, thread %d).\n", AllocationBase, hookinfo->current_hook->library, hookinfo->current_hook->funcname, addr, GetCurrentThreadId());
	}
	if (g_config.base_on_caller)
		SetInitialBreakpoints((PVOID)AllocationBase);
	if (!g_config.loaderlock_scans && loader_lock_held()) {
		DebugOutput("caller_dispatch: Scans and dumps of calling region at 0x%p skipped as loader lock held.\n", AllocationBase);
		return;
	}
	else if (loader_lock_held())
		DebugOutput("caller_dispatch: Scanning calling region at 0x%p...\n", AllocationBase);
	char ModulePath[MAX_PATH];
	BOOL MappedModule = GetMappedFileName(GetCurrentProcess(), AllocationBase, ModulePath, MAX_PATH);
	if (g_config.unpacker)
		ProcessTrackedRegion(TrackedRegion);
	else if (g_config.caller_regions) {
		if (g_config.yarascan)
			YaraScan(AllocationBase, GetAccessibleSize(AllocationBase));
		if (!MappedModule && AllocationBase != ImageBase && AllocationBase != (PVOID)base_of_dll_of_interest)
			DumpRegion((PVOID)addr);
	}
	else if (MappedModule)
		DebugOutput("caller_dispatch: Dump of calling region at 0x%p skipped (%ws::%s returns to 0x%p mapped as %s).\n", AllocationBase, hookinfo->current_hook->library, hookinfo->current_hook->funcname, addr, ModulePath);
	else
		DebugOutput("caller_dispatch: Dump of calling region at 0x%p skipped (%ws::%s returns to 0x%p).\n", AllocationBase, hookinfo->current_hook->library, hookinfo->current_hook->funcname, addr);
}

static int set_caller_info(void *_hook_info, ULONG_PTR addr)
{
	hook_info_t *hookinfo = _hook_info;

	if (!is_in_dll_range(addr) && !inside_hook((PVOID)addr)) {
		caller_dispatch(hookinfo, addr);
		if (hookinfo->main_caller_retaddr == 0)
			hookinfo->main_caller_retaddr = addr;
		else {
			hookinfo->parent_caller_retaddr = addr;
			return 1;
		}
	}
	return 0;
}

int hook_is_excluded(hook_t *h)
{
	unsigned int i;

	for (i = 0; i < ARRAYSIZE(g_config.excluded_apinames); i++) {
		if (!g_config.excluded_apinames[i])
			break;
		if (!stricmp(h->funcname, g_config.excluded_apinames[i]))
			return 1;
	}
	for (i = 0; i < ARRAYSIZE(g_config.excluded_dllnames); i++) {
		if (!g_config.excluded_dllnames[i])
			break;
		if (!wcsicmp(h->library, g_config.excluded_dllnames[i]))
			return 1;
	}

	return 0;
}

int add_hook_exclusion(const char *apiname)
{
	for (unsigned int i = 0; i < ARRAYSIZE(g_config.excluded_apinames); i++) {
		if (!g_config.excluded_apinames[i]) {
			g_config.excluded_apinames[i] = strdup(apiname);
			return 1;
		}
	}

	return 0;
}

int addr_in_our_dll_range(void *unused, ULONG_PTR addr)
{
	if (addr >= g_our_dll_base && addr < (g_our_dll_base + g_our_dll_size))
		return 1;
	return 0;
}

static int __called_by_hook(ULONG_PTR stack_pointer, ULONG_PTR frame_pointer)
{
	int ret = operate_on_backtrace(stack_pointer, frame_pointer, NULL, addr_in_our_dll_range);

	// if exception operating on backtrace or LdrpInvertedFunctionTableSRWLock held, prevent recursion
	if (ret == -1)
		return 1;

	return ret;
}

int called_by_hook(void)
{
	hook_info_t *hookinfo = hook_info();

	return __called_by_hook(hookinfo->stack_pointer, hookinfo->frame_pointer);
}

BOOL ModuleDumped;

void api_dispatch(hook_t *h, hook_info_t *hookinfo)
{
	unsigned int i;
	ULONG_PTR main_caller_retaddr, parent_caller_retaddr;
	PVOID AllocationBase = NULL;

	main_caller_retaddr = hookinfo->main_caller_retaddr;
	parent_caller_retaddr = hookinfo->parent_caller_retaddr;

	if (g_config.debugger && DebuggerInitialised)
	{
		DWORD CurrentThreadId = GetCurrentThreadId();
		InitNewThreadBreakpoints(CurrentThreadId, NULL);
		for (i = 0; i < ARRAYSIZE(g_config.base_on_apiname); i++) {
			if (!g_config.base_on_apiname[i])
				break;
			if (!__called_by_hook(hookinfo->stack_pointer, hookinfo->frame_pointer) && !stricmp(h->funcname, g_config.base_on_apiname[i])) {
				DebugOutput("Base-on-API: %s call detected in thread %d, main_caller_retaddr 0x%p.\n", g_config.base_on_apiname[i], CurrentThreadId, main_caller_retaddr);
				AllocationBase = GetHookCallerBase();
				if (AllocationBase) {
					BreakpointsSet = SetInitialBreakpoints((PVOID)AllocationBase);
					if (BreakpointsSet)
						DebugOutput("Base-on-API: GetHookCallerBase success 0x%p - Breakpoints set.\n", AllocationBase);
					else
						DebugOutput("Base-on-API: Failed to set breakpoints on 0x%p.\n", AllocationBase);
				}
				else
					DebugOutput("Base-on-API: GetHookCallerBase fail.\n");
				break;
			}
		}
	}

	for (i = 0; i < ARRAYSIZE(g_config.dump_on_apinames); i++) {
		if (!g_config.dump_on_apinames[i])
			break;
		if (!ModuleDumped && !stricmp(h->funcname, g_config.dump_on_apinames[i])) {
			DebugOutput("Dump-on-API: %s call detected in thread %d, main_caller_retaddr 0x%p.\n", g_config.dump_on_apinames[i], GetCurrentThreadId(), main_caller_retaddr);
			if (main_caller_retaddr) {
				AllocationBase = GetHookCallerBase();
				if (AllocationBase) {
					if (g_config.dump_on_api_type)
						CapeMetaData->DumpType = g_config.dump_on_api_type;
					if (DumpRegion(AllocationBase)) {
						ModuleDumped = TRUE;
						DebugOutput("Dump-on-API: Dumped memory region at 0x%p due to %s call.\n", AllocationBase, h->funcname);
					}
					else {
						DebugOutput("Dump-on-API: Failed to dump memory region at 0x%p due to %s call.\n", AllocationBase, h->funcname);
					}
				}
				else
					DebugOutput("Dump-on-API: Failed to obtain current module base address.\n");
			}
			else
				DebugOutput("Dump-on-API: No valid return address.\n");
			break;
		}
	}


	if (g_config.debugger && !__called_by_hook(hookinfo->stack_pointer, hookinfo->frame_pointer) && !stricmp(h->funcname, g_config.break_on_return)) {
		DebugOutput("Break-on-return: %s call detected in thread %d.\n", g_config.break_on_return, GetCurrentThreadId());
		if (main_caller_retaddr)
			BreakpointOnReturn((PVOID)main_caller_retaddr);
		else if (parent_caller_retaddr)
			BreakpointOnReturn((PVOID)parent_caller_retaddr);
		else
			BreakpointOnReturn((PVOID)hookinfo->return_address);
	}
}

extern BOOLEAN is_ignored_thread(DWORD tid);
static hook_info_t tmphookinfo;
DWORD tmphookinfo_threadid;
FILETIME ft;

// returns 1 if we should call our hook, 0 if we should call the original function instead
// on x86 this is actually: hook, esp, ebp
// on x64 this is actually: hook, rsp, rip of hook (for unwind-based stack walking)
int WINAPI enter_hook(hook_t *h, ULONG_PTR sp, ULONG_PTR ebp_or_rip)
{
	hook_info_t *hookinfo;

	if (h->fully_emulate)
		return 1;

	if (h->new_func == &New_NtAllocateVirtualMemory) {
		lasterror_t lasterrors;
		get_lasterrors(&lasterrors);
		if (lookup_get(&g_hook_info, (ULONG_PTR)GetCurrentThreadId(), NULL) == NULL && (!tmphookinfo_threadid || tmphookinfo_threadid != GetCurrentThreadId())) {
			memset(&tmphookinfo, 0, sizeof(tmphookinfo));
			tmphookinfo_threadid = GetCurrentThreadId();
		}
		set_lasterrors(&lasterrors);
	}
	else if (tmphookinfo_threadid) {
		tmphookinfo_threadid = 0;
	}

	hookinfo = hook_info();

	if ((hookinfo->disable_count < 1) && (h->allow_hook_recursion || (!__called_by_hook(sp, ebp_or_rip) /*&& !is_ignored_thread(GetCurrentThreadId())*/))) {

		if (g_config.api_rate_cap && h->new_func != &New_RtlDispatchException && h->new_func != &New_NtContinue) {
			if (h->hook_disabled)
				return 0;
			h->counter++;
			if (g_config.api_cap && h->counter >= g_config.api_cap) {
				DebugOutput("api-cap: %s hook disabled due to count: %d\n", h->funcname, h->counter);
				h->hook_disabled = 1;
				return 0;
			}
			if (Old_GetSystemTimeAsFileTime)
				Old_GetSystemTimeAsFileTime(&ft);
			else
				GetSystemTimeAsFileTime(&ft);
			if (ft.dwLowDateTime - h->hook_timer < HOOK_TIME_SAMPLE) {
				h->rate_counter++;
				if (h->rate_counter > HOOK_RATE_LIMIT/g_config.api_rate_cap) {
					DebugOutput("api-rate-cap: %s hook disabled due to rate\n", h->funcname);
					h->rate_counter = 0;
					h->hook_disabled = 1;
					return 0;
				}
			}
			else {
				h->rate_counter = 0;
				h->hook_timer = ft.dwLowDateTime;
			}
		}

		hookinfo->last_hook = hookinfo->current_hook;
		hookinfo->current_hook = h;
		hookinfo->stack_pointer = sp;
		hookinfo->return_address = *(ULONG_PTR *)sp;
		hookinfo->frame_pointer = ebp_or_rip;

		/* set caller information */
		hookinfo->main_caller_retaddr = 0;
		hookinfo->parent_caller_retaddr = 0;

		operate_on_backtrace(sp, ebp_or_rip, hookinfo, set_caller_info);

		if (!hookinfo->main_caller_retaddr)
			operate_on_backtrace(sp, ebp_or_rip, hookinfo, set_caller_info_fallback);

		api_dispatch(h, hookinfo);

		return 1;
	}

	return 0;
}

hook_info_t *hook_info()
{
	hook_info_t *ptr;

	lasterror_t lasterror;

	if (tmphookinfo_threadid && tmphookinfo_threadid == GetCurrentThreadId())
		return &tmphookinfo;

	get_lasterrors(&lasterror);

	ptr = (hook_info_t *)lookup_get(&g_hook_info, (ULONG_PTR)GetCurrentThreadId(), NULL);
	if (ptr == NULL) {
		ptr = lookup_add(&g_hook_info, (ULONG_PTR)GetCurrentThreadId(), sizeof(hook_info_t));
		memset(ptr, 0, sizeof(*ptr));
	}

	set_lasterrors(&lasterror);

	return ptr;
}

void get_lasterrors(lasterror_t *errors)
{
	char *teb = NULL;

	errors->Eflags = (DWORD)__readeflags();

	teb = (char *)NtCurrentTeb();

	if (teb == NULL) {
		errors->Win32Error = -1;
		errors->NtstatusError = -1;
		return;
	}

	errors->Win32Error = *(DWORD *)(teb + TLS_LAST_WIN32_ERROR);
	errors->NtstatusError = *(DWORD *)(teb + TLS_LAST_NTSTATUS_ERROR);
}

// we do our own version of this function to avoid the potential debug triggers
void set_lasterrors(lasterror_t *errors)
{
	char *teb = (char *)NtCurrentTeb();

	if (teb == NULL)
		return;

	*(DWORD *)(teb + TLS_LAST_WIN32_ERROR) = errors->Win32Error;
	*(DWORD *)(teb + TLS_LAST_NTSTATUS_ERROR) = errors->NtstatusError;

	if ((errors->Eflags))
		__writeeflags(errors->Eflags);
}

void hook_enable()
{
	hook_info()->disable_count = 0;
}

void hook_disable()
{
	hook_info()->disable_count = 1;
}
