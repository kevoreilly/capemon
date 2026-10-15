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
static lookup_t g_hook_thread_state;
static lookup_t g_force_hook_threads;

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

	if (addr && !inside_hook((PVOID)addr) && !InsideMonitor(NULL, (PVOID)addr)) {
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

static int filter_callers(hook_info_t *hookinfo)
{
	if (!stricmp(hookinfo->current_hook->funcname, "RtlDispatchException") && !wcsicmp(hookinfo->current_hook->library, L"ntdll"))
		return 1;
	if (!stricmp(hookinfo->current_hook->funcname, "NtContinue") && !wcsicmp(hookinfo->current_hook->library, L"ntdll"))
		return 1;
	if (!stricmp(hookinfo->current_hook->funcname, "compileMethod") && !wcsicmp(hookinfo->current_hook->library, L"clrjit"))
		return 1;
	return 0;
}

static void caller_dispatch(hook_info_t *hookinfo, ULONG_PTR addr)
{
	if (g_config.tlsdump)
		return;
	if (filter_callers(hookinfo))
		return;
	if (!g_config.unpacker)
		return;
	PVOID AllocationBase = GetAllocationBase((PVOID)addr);
	if (!AllocationBase || !g_dll_main_complete || hookinfo->main_caller_retaddr)
		return;
	PTRACKEDREGION TrackedRegion = NULL;
	if (g_config.unpacker)
	{
		TrackedRegion = GetTrackedRegion((PVOID)AllocationBase);
		if (TrackedRegion && (TrackedRegion->Caller || TrackedRegion->PagesDumped))
			return;
		if (!TrackedRegion) {
			TrackedRegion = AddTrackedRegion((PVOID)AllocationBase, 0);
			if (!TrackedRegion) {
#ifdef DEBUG_COMMENTS
				DebugOutput("caller_dispatch: Failed to add region at 0x%p to tracked regions list (%ws::%s returns to 0x%p, thread %d).\n", AllocationBase, hookinfo->current_hook->library, hookinfo->current_hook->funcname, addr, GetCurrentThreadId());
#endif
				return;
			}
			DebugOutput("caller_dispatch: Added region at 0x%p to tracked regions list (%ws::%s returns to 0x%p, thread %d).\n", AllocationBase, hookinfo->current_hook->library, hookinfo->current_hook->funcname, addr, GetCurrentThreadId());
		}
		TrackedRegion->Caller = (PVOID)addr;
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
	else if (MappedModule)
		DebugOutput("caller_dispatch: Dump of calling region at 0x%p skipped (%ws::%s returns to 0x%p mapped as %s).\n", AllocationBase, hookinfo->current_hook->library, hookinfo->current_hook->funcname, addr, ModulePath);
	else
		DebugOutput("caller_dispatch: Dump of calling region at 0x%p skipped (%ws::%s returns to 0x%p).\n", AllocationBase, hookinfo->current_hook->library, hookinfo->current_hook->funcname, addr);
}

static int set_caller_info(void *_hook_info, ULONG_PTR addr)
{
	hook_info_t *hookinfo = _hook_info;

	if (!is_in_dll_range(addr) && !inside_hook((PVOID)addr) && !InsideMonitor(NULL, (PVOID)addr)) {
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

	if (g_config.included_apinames[0] != NULL) {
		int found = 0;
		for (i = 0; i < ARRAYSIZE(g_config.included_apinames); i++) {
			if (!g_config.included_apinames[i])
				break;
			if (!stricmp(h->funcname, g_config.included_apinames[i])) {
				found = 1;
				break;
			}
		}
		if (!found)
			return 1;
	}

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

extern void start_transparent_hooks();
extern void end_transparent_hooks();

int addr_in_our_dll_range(void *unused, ULONG_PTR addr)
{
	if (addr >= g_our_dll_base && addr < (g_our_dll_base + g_our_dll_size))
		if (addr < (ULONG_PTR)&start_transparent_hooks || addr >= (ULONG_PTR)&end_transparent_hooks)
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

void api_dispatch(hook_t *h, hook_info_t *hookinfo)
{
	unsigned int i;
	ULONG_PTR main_caller_retaddr, parent_caller_retaddr;
	PVOID AllocationBase = NULL;

	main_caller_retaddr = hookinfo->main_caller_retaddr;
	parent_caller_retaddr = hookinfo->parent_caller_retaddr;

	if (g_config.debugger && DebuggerInitialised)
	{
		for (i = 0; i < ARRAYSIZE(g_config.base_on_apiname); i++) {
			if (!g_config.base_on_apiname[i])
				break;
			if (!__called_by_hook(hookinfo->stack_pointer, hookinfo->frame_pointer) && !stricmp(h->funcname, g_config.base_on_apiname[i])) {
				DebugOutput("Base-on-API: %s call detected in thread %d, main_caller_retaddr 0x%p.\n", g_config.base_on_apiname[i], GetCurrentThreadId(), main_caller_retaddr);
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
		if (!stricmp(h->funcname, g_config.dump_on_apinames[i])) {
			DebugOutput("Dump-on-API: %s call detected in thread %d, main_caller_retaddr 0x%p.\n", g_config.dump_on_apinames[i], GetCurrentThreadId(), main_caller_retaddr);
			if (main_caller_retaddr) {
				AllocationBase = GetHookCallerBase();
				if (AllocationBase) {
					if (g_config.dump_on_api_type)
						CapeMetaData->DumpType = g_config.dump_on_api_type;
					if (DumpRegion(AllocationBase))
						DebugOutput("Dump-on-API: Dumped memory region at 0x%p due to %s call.\n", AllocationBase, h->funcname);
					else
						DebugOutput("Dump-on-API: Failed to dump memory region at 0x%p due to %s call.\n", AllocationBase, h->funcname);
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
		if (main_caller_retaddr && !is_in_dll_range(main_caller_retaddr))
			BreakpointOnReturn((PVOID)main_caller_retaddr);
		else if (parent_caller_retaddr && !is_in_dll_range(parent_caller_retaddr))
			BreakpointOnReturn((PVOID)parent_caller_retaddr);
		else
			BreakpointOnReturn((PVOID)hookinfo->return_address);
	}

	if (g_config.hook_watch)
		DebugOutput("api_dispatch: %s\n", h->funcname);
}

void add_force_hook_thread_func(const char* function)
{
	DWORD tid = GetCurrentThreadId();
	const char** funcname = lookup_get(&g_force_hook_threads, (unsigned int)tid, NULL);
	if (!funcname)
		funcname = lookup_add(&g_force_hook_threads, tid, sizeof(char*));
	if (funcname)
		*funcname = function;
}

BOOLEAN force_hook_thread_func(const char* hookname)
{
	DWORD tid = GetCurrentThreadId();
	const char** funcname = lookup_get(&g_force_hook_threads, (unsigned int)tid, NULL);
	if (funcname && !stricmp(hookname, *funcname)) {
		lookup_del(&g_force_hook_threads, tid);
		return TRUE;
	}
	return FALSE;
}

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

	if (g_config.debugger && hookinfo->disable_count > 0 && h->new_func == &New_RtlDispatchException)
		return 1;

	if ((hookinfo->disable_count < 1) && (h->allow_hook_recursion || force_hook_thread_func(h->funcname) || (!__called_by_hook(sp, ebp_or_rip) /*&& !is_ignored_thread(GetCurrentThreadId())*/))) {

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
	if (hook_info()->disable_count > 0)
		hook_info()->disable_count--;
}

void hook_disable()
{
	hook_info()->disable_count++;
}

// ---------------------------------------------------------------------------
// Alternate (capemon-owned) stack
//
// Callbacks reached from code running on a stack the target controls must not consume that stack:
// goroutine stacks are heap allocations with no guard page and only ~stackGuard bytes of headroom below
// SP after a split check (928 + 4096 on Windows); pivoted/scratch stacks have no guarantee at all. A
// CONTEXT (1232 bytes on x64) plus loq's 2 KB buffer already exceed that, and the overflow is silent.
//
// The switch itself is a byte-coded thunk (MSVC x64 has no inline asm). It must not be unwound through,
// so alt_stack_entry wraps fn in __try/__except. TEB StackBase/StackLimit are redirected to the
// alternate stack while on it: x64 RtlDispatchException rejects establisher frames outside those
// bounds, which would turn any __try inside fn into an unhandled exception.
// ---------------------------------------------------------------------------

#ifdef _WIN64
typedef void (*alt_stack_thunk_t)(alt_stack_fn_t fn, void *arg, PVOID stack_top);
static const unsigned char alt_stack_thunk_code[] = {
	0x55,                   // push rbp
	0x48, 0x89, 0xE5,       // mov rbp, rsp
	0x48, 0x89, 0xC8,       // mov rax, rcx         (fn)
	0x48, 0x89, 0xD1,       // mov rcx, rdx         (arg)
	0x4C, 0x89, 0xC4,       // mov rsp, r8          (stack_top, 16-byte aligned)
	0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20        (Win64 shadow space; keeps rsp 16-aligned before the call)
	0xFF, 0xD0,             // call rax
	0x48, 0x89, 0xEC,       // mov rsp, rbp
	0x5D,                   // pop rbp
	0xC3                    // ret
};
#else
typedef void (__cdecl *alt_stack_thunk_t)(alt_stack_fn_t fn, void *arg, PVOID stack_top);
static const unsigned char alt_stack_thunk_code[] = {
	0x55,                   // push ebp
	0x89, 0xE5,             // mov ebp, esp
	0x8B, 0x45, 0x08,       // mov eax, [ebp+8]     (fn)
	0x8B, 0x4D, 0x0C,       // mov ecx, [ebp+12]    (arg)
	0x8B, 0x65, 0x10,       // mov esp, [ebp+16]    (stack_top)
	0x51,                   // push ecx
	0xFF, 0xD0,             // call eax             (cdecl; argument discarded by the mov below)
	0x89, 0xEC,             // mov esp, ebp
	0x5D,                   // pop ebp
	0xC3                    // ret
};
#endif

static alt_stack_thunk_t g_alt_stack_thunk;

typedef struct _alt_stack_call_t {
	alt_stack_fn_t fn;
	void *arg;
} alt_stack_call_t;

static void __cdecl alt_stack_entry(void *p)
{
	alt_stack_call_t *call = (alt_stack_call_t *)p;

	__try {
		call->fn(call->arg);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DebugOutput("hook_call_on_alt_stack: exception 0x%x escaped callback at 0x%p.\n", GetExceptionCode(), call->fn);
	}
}

hook_thread_state_t *hook_thread_state(void)
{
	hook_thread_state_t *ptr;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	ptr = (hook_thread_state_t *)lookup_get(&g_hook_thread_state, (ULONG_PTR)GetCurrentThreadId(), NULL);
	if (ptr == NULL) {
		ptr = (hook_thread_state_t *)lookup_add(&g_hook_thread_state, (ULONG_PTR)GetCurrentThreadId(), sizeof(hook_thread_state_t));
		if (ptr != NULL)
			memset(ptr, 0, sizeof(*ptr));
	}

	set_lasterrors(&lasterror);

	return ptr;
}

static BOOL alt_stack_init(hook_thread_state_t *state)
{
	// VirtualAlloc/VirtualProtect are hooked: keep our own allocations out of the behaviour log
	hook_disable();

	if (g_alt_stack_thunk == NULL) {
		PVOID page = VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (page != NULL) {
			DWORD old_prot;
			memcpy(page, alt_stack_thunk_code, sizeof(alt_stack_thunk_code));
			if (VirtualProtect(page, 0x1000, PAGE_EXECUTE_READ, &old_prot)) {
				FlushInstructionCache(GetCurrentProcess(), page, sizeof(alt_stack_thunk_code));
				if (InterlockedCompareExchangePointer((PVOID volatile *)&g_alt_stack_thunk, page, NULL) != NULL)
					VirtualFree(page, 0, MEM_RELEASE);   // lost the race: another thread published its copy
			}
			else
				VirtualFree(page, 0, MEM_RELEASE);
		}
	}

	if (state->alt_stack == NULL)
		state->alt_stack = VirtualAlloc(NULL, HOOK_ALT_STACK_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	hook_enable();

	return g_alt_stack_thunk != NULL && state->alt_stack != NULL;
}

BOOL hook_on_alt_stack(void)
{
	hook_thread_state_t *state = hook_thread_state();
	return state != NULL && state->alt_stack_depth > 0;
}

BOOL hook_get_orig_stack_bounds(ULONG_PTR *bottom, ULONG_PTR *top)
{
	hook_thread_state_t *state = hook_thread_state();
	if (state != NULL && state->alt_stack_depth > 0 && state->orig_stack_base != NULL && state->orig_stack_limit != NULL) {
		if (bottom != NULL)
			*bottom = (ULONG_PTR)state->orig_stack_limit;
		if (top != NULL)
			*top = (ULONG_PTR)state->orig_stack_base;
		return TRUE;
	}
	return FALSE;
}

BOOL hook_call_on_alt_stack(alt_stack_fn_t fn, void *arg)
{
	hook_thread_state_t *state = hook_thread_state();
	alt_stack_call_t call;
	PNT_TIB tib;
	PVOID saved_base, saved_limit, stack_top;
#ifndef _WIN64
	PVOID saved_exc_list;
#endif

	if (fn == NULL || state == NULL)
		return FALSE;

	// Already on our stack (nested hook or callback on the same thread)
	if (state->alt_stack_depth > 0) {
		fn(arg);
		return TRUE;
	}

	// Everything up to the switch runs on the caller's stack: keep it to a few small frames
	if (!alt_stack_init(state))
		return FALSE;

	call.fn = fn;
	call.arg = arg;
	stack_top = (PVOID)(((ULONG_PTR)state->alt_stack + HOOK_ALT_STACK_SIZE) & ~(ULONG_PTR)0xF);

	tib = (PNT_TIB)NtCurrentTeb();
	saved_base = tib->StackBase;
	saved_limit = tib->StackLimit;
#ifndef _WIN64
	// On x86 SEH registration records are chained from fs:[0] and validated against [StackLimit, StackBase].
	// Terminate the chain at EXCEPTION_CHAIN_END before switching so alt_stack_entry's __try starts a clean
	// chain entirely within the alternate stack.
	saved_exc_list = tib->ExceptionList;
#endif

	state->orig_stack_base = saved_base;
	state->orig_stack_limit = saved_limit;
	state->alt_stack_orig_sp = (ULONG_PTR)&call;
	state->alt_stack_depth = 1;
	tib->StackBase = stack_top;
	tib->StackLimit = state->alt_stack;
#ifndef _WIN64
	tib->ExceptionList = (PVOID)(ULONG_PTR)-1;
#endif

	g_alt_stack_thunk(alt_stack_entry, &call, stack_top);

#ifndef _WIN64
	tib->ExceptionList = saved_exc_list;
#endif
	tib->StackBase = saved_base;
	tib->StackLimit = saved_limit;
	state->alt_stack_depth = 0;
	state->alt_stack_orig_sp = 0;
	state->orig_stack_base = NULL;
	state->orig_stack_limit = NULL;

	return TRUE;
}
