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
#include "hooking.h"
#include "hooks.h"
#include "ignore.h"
#include "unhook.h"
#include "misc.h"
#include "pipe.h"
#include "CAPE\CAPE.h"
#include "CAPE\Debugger.h"
#include "CAPE\Extraction.h"

#ifdef _WIN64
#define TLS_LAST_WIN32_ERROR 0x68
#define TLS_LAST_NTSTATUS_ERROR 0x1250
#else
#define TLS_LAST_WIN32_ERROR 0x34
#define TLS_LAST_NTSTATUS_ERROR 0xbf4
#endif

static lookup_t g_hook_info;
lookup_t g_caller_regions;

#ifdef CAPE_TRACE
extern BOOL SetInitialBreakpoints(PVOID ImageBase);
extern BOOL BreakpointOnReturn(PVOID Address);
extern BOOL BreakpointsSet;
extern BOOL TraceRunning;
#endif

void hook_init()
{
    lookup_init_no_cs(&g_hook_info);
    lookup_init(&g_caller_regions);
}

void emit_rel(unsigned char *buf, unsigned char *source, unsigned char *target)
{
	*(DWORD *)buf = (DWORD)(target - (source + 4));
}

// need to be very careful about what we call in here, as it can be called in the context of any hook
// including those that hold the loader lock

static int set_caller_info(void *unused, ULONG_PTR addr)
{
	hook_info_t *hookinfo = hook_info();

	if (!is_in_dll_range(addr)) {
        PVOID AllocationBase = GetAllocationBase((PVOID)addr);
        if (AllocationBase && !lookup_get(&g_caller_regions, (ULONG_PTR)AllocationBase, 0)) {
            lookup_add(&g_caller_regions, (ULONG_PTR)AllocationBase, 0);
            DoOutputDebugString("set_caller_info: Adding region at 0x%p to caller regions list (%ws::%s).\n", AllocationBase, hookinfo->current_hook->library, hookinfo->current_hook->funcname);
            if (g_config.extraction) {
                PTRACKEDREGION TrackedRegion = GetTrackedRegion((PVOID)addr);
                if (TrackedRegion) {
                    TrackedRegion->CanDump = 1;
                    ProcessTrackedRegion(TrackedRegion);
                }
                else if (g_config.verbose_dumping) {
                    TrackedRegion = AddTrackedRegion((PVOID)addr, 0,0);
                    TrackedRegion->CanDump = 1;
                    ProcessTrackedRegion(TrackedRegion);
                }
            }
            else if (g_config.verbose_dumping) {
                DoOutputDebugString("VerboseDump: Dumping calling region at 0x%p.\n", AllocationBase);

                CapeMetaData->ModulePath = NULL;
                CapeMetaData->DumpType = DATADUMP;
                CapeMetaData->Address = AllocationBase;

                if (IsDisguisedPEHeader(AllocationBase))
                    DumpImageInCurrentProcess(AllocationBase);
                else
                    DumpRegion(AllocationBase);
            }
        }
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

int addr_in_our_dll_range(void *unused, ULONG_PTR addr)
{
	if (addr >= g_our_dll_base && addr < (g_our_dll_base + g_our_dll_size))
		return 1;
	return 0;
}

static int __called_by_hook(ULONG_PTR stack_pointer, ULONG_PTR frame_pointer)
{
	return operate_on_backtrace(stack_pointer, frame_pointer, NULL, addr_in_our_dll_range);
}

int called_by_hook(void)
{
	hook_info_t *hookinfo = hook_info();

	return __called_by_hook(hookinfo->stack_pointer, hookinfo->frame_pointer);
}

void api_dispatch(hook_t *h, hook_info_t *hookinfo)
{
	unsigned int i;
	ULONG_PTR main_caller_retaddr, parent_caller_retaddr;
    PVOID AllocationBase = NULL;

	main_caller_retaddr = hookinfo->main_caller_retaddr;
	parent_caller_retaddr = hookinfo->parent_caller_retaddr;

#ifdef CAPE_TRACE
    for (i = 0; i < ARRAYSIZE(g_config.base_on_apiname); i++) {
		if (!g_config.base_on_apiname[i])
			break;
		if (!__called_by_hook(hookinfo->stack_pointer, hookinfo->frame_pointer) && !stricmp(h->funcname, g_config.base_on_apiname[i])) {
            DoOutputDebugString("Base-on-API: %s call detected in thread %d, main_caller_retaddr 0x%p.\n", g_config.base_on_apiname[i], GetCurrentThreadId(), main_caller_retaddr);
            AllocationBase = GetHookCallerBase(hookinfo);
            if (AllocationBase) {
                BreakpointsSet = SetInitialBreakpoints((PVOID)AllocationBase);
                if (BreakpointsSet)
                    DoOutputDebugString("Base-on-API: GetHookCallerBase success 0x%p - Breakpoints set.\n", AllocationBase);
                else
                    DoOutputDebugString("Base-on-API: Failed to set breakpoints on 0x%p.\n", AllocationBase);
            }
            else
                DoOutputDebugString("Base-on-API: GetHookCallerBase fail.\n");
            break;
        }
    }
#endif

	for (i = 0; i < ARRAYSIZE(g_config.dump_on_apinames); i++) {
		if (!g_config.dump_on_apinames[i])
			break;
		if (!ModuleDumped && !stricmp(h->funcname, g_config.dump_on_apinames[i])) {
            DoOutputDebugString("Dump-on-API: %s call detected in thread %d, main_caller_retaddr 0x%p.\n", g_config.base_on_apiname[i], GetCurrentThreadId(), main_caller_retaddr);
            if (main_caller_retaddr) {
                if (!AllocationBase)
                    AllocationBase = GetHookCallerBase(hookinfo);
                if (AllocationBase) {
                    if (g_config.dump_on_api_type)
                        CapeMetaData->DumpType = g_config.dump_on_api_type;
                    if (DumpImageInCurrentProcess(AllocationBase)) {
                        ModuleDumped = TRUE;
                        DoOutputDebugString("Dump-on-API: Dumped module at 0x%p due to %s call.\n", AllocationBase, h->funcname);
                    }
                    else if (DumpRegion(AllocationBase)) {
                        ModuleDumped = TRUE;
                        DoOutputDebugString("Dump-on-API: Dumped memory region at 0x%p due to %s call.\n", AllocationBase, h->funcname);
                    }
                    else {
                        DoOutputDebugString("Dump-on-API: Failed to dump memory region at 0x%p due to %s call.\n", AllocationBase, h->funcname);
                    }
                }
                else
                    DoOutputDebugString("Dump-on-API: Failed to obtain current module base address.\n");
            }
            break;
        }
    }

#ifdef CAPE_TRACE
    if (!__called_by_hook(hookinfo->stack_pointer, hookinfo->frame_pointer) && !stricmp(h->funcname, g_config.break_on_return)) {
        DoOutputDebugString("Break-on-return: %s call detected in thread %d.\n", g_config.break_on_return, GetCurrentThreadId());
        TraceRunning = TRUE;
        if (main_caller_retaddr)
            BreakpointOnReturn((PVOID)main_caller_retaddr);
        else if (parent_caller_retaddr)
            BreakpointOnReturn((PVOID)parent_caller_retaddr);
        else
            BreakpointOnReturn((PVOID)hookinfo->return_address);
    }
#endif
}

extern BOOLEAN is_ignored_thread(DWORD tid);
static hook_info_t tmphookinfo;
DWORD tmphookinfo_threadid;

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
		if (lookup_get_no_cs(&g_hook_info, (ULONG_PTR)GetCurrentThreadId(), NULL) == NULL && (!tmphookinfo_threadid || tmphookinfo_threadid != GetCurrentThreadId())) {
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
		hookinfo->last_hook = hookinfo->current_hook;
		hookinfo->current_hook = h;
		hookinfo->stack_pointer = sp;
		hookinfo->return_address = *(ULONG_PTR *)sp;
		hookinfo->frame_pointer = ebp_or_rip;

		/* set caller information */
		hookinfo->main_caller_retaddr = 0;
		hookinfo->parent_caller_retaddr = 0;

		operate_on_backtrace(sp, ebp_or_rip, NULL, set_caller_info);

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

	ptr = (hook_info_t *)lookup_get_no_cs(&g_hook_info, (ULONG_PTR)GetCurrentThreadId(), NULL);
	if (ptr == NULL) {
		ptr = lookup_add_no_cs(&g_hook_info, (ULONG_PTR)GetCurrentThreadId(), sizeof(hook_info_t));
		memset(ptr, 0, sizeof(*ptr));
	}

	set_lasterrors(&lasterror);

	return ptr;
}

void get_lasterrors(lasterror_t *errors)
{
	char *teb;

    errors->Eflags = (DWORD)__readeflags();

    teb = (char *)NtCurrentTeb();

	errors->Win32Error = *(DWORD *)(teb + TLS_LAST_WIN32_ERROR);
	errors->NtstatusError = *(DWORD *)(teb + TLS_LAST_NTSTATUS_ERROR);
}

// we do our own version of this function to avoid the potential debug triggers
void set_lasterrors(lasterror_t *errors)
{
	char *teb = (char *)NtCurrentTeb();

	*(DWORD *)(teb + TLS_LAST_WIN32_ERROR) = errors->Win32Error;
	*(DWORD *)(teb + TLS_LAST_NTSTATUS_ERROR) = errors->NtstatusError;

    if ((errors->Eflags))
        __writeeflags(errors->Eflags);
}

void hook_enable()
{
    hook_info()->disable_count--;
}

void hook_disable()
{
    hook_info()->disable_count++;
}
