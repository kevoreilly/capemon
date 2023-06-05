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
#include <distorm.h>
#include "ntapi.h"
#include "misc.h"
#include "hooking.h"
#include "hooks.h"
#include "log.h"
#include "pipe.h"
#include "ignore.h"
#include "hook_file.h"
#include "hook_sleep.h"
#include "config.h"
#include "unhook.h"
#include "bson.h"
#include "Shlwapi.h"

// Allow debug mode to be turned on at compilation time.
#ifdef CUCKOODBG
#undef CUCKOODBG
#define CUCKOODBG 1
#else
#define CUCKOODBG 0
#endif

#define WIDE_STRING_LIMIT 32768

char *our_process_path;
char *our_process_name;
char *our_dll_path;
wchar_t *our_process_path_w;
wchar_t *our_dll_path_w;
wchar_t *our_commandline;
BOOL is_64bit_os;

extern ULONG_PTR ntdll_base;
extern PVOID ImageBase;
extern void CAPE_init();
extern void CAPE_post_init();
extern SIZE_T GetAllocationSize(PVOID Address);
extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern LONG WINAPI CAPEExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo);
extern ULONG_PTR base_of_dll_of_interest;
extern BOOL BreakpointsHit, SetInitialBreakpoints(PVOID ImageBase);
extern PCHAR ScyllaGetExportDirectory(PVOID Address);
extern PCHAR ScyllaGetExportNameByScan(PVOID Address, PCHAR* ModuleName, SIZE_T ScanSize);
extern void YaraScan(PVOID Address, SIZE_T Size);

extern BOOL set_hooks_dll(const wchar_t *library);
extern void set_hooks_by_export_directory(const wchar_t *exportdirectory, const wchar_t *library);
extern void revalidate_all_hooks(void);
extern void set_hooks();

int path_is_system(const wchar_t *path_w)
{
	if (((!wcsnicmp(path_w, L"c:\\windows\\system32\\", 20) ||
		!wcsnicmp(path_w, L"c:\\windows\\syswow64\\", 20) ||
		!wcsnicmp(path_w, L"c:\\windows\\sysnative\\", 21))))
		return 1;
	return 0;
}

int path_is_program_files(const wchar_t *path_w)
{
	if (((!wcsnicmp(path_w, L"c:\\program files\\", 17) ||
		!wcsnicmp(path_w, L"c:\\program files (x86)\\", 23))))
		return 1;
	return 0;
}

int loader_is_allowed(const char *loader_name)
{
	if (!_stricmp(loader_name, "rundll32.exe") ||
		!_stricmp(loader_name, "regsvr32.exe"))
		return 1;
	return 0;
}

int path_is_shared(const wchar_t *path1, const wchar_t *path2)
{
	SIZE_T len1, len2, len;
	wchar_t *slash1, *slash2;
	if (!path1 || !path2)
		return 0;
	__try {
		slash1 = wcsrchr(path1, L'\\');
		slash2 = wcsrchr(path2, L'\\');
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		return 0;
	}
	if (!slash1 || !slash2)
		return 0;
	len1 = slash1 - path1;
	len2 = slash2 - path2;
	if (len1 < len2)
		len = len1;
	else
		len = len2;
	if (len && !wcsnicmp(path1, path2, len))
		return 1;
	return 0;
}

VOID CALLBACK New_DllLoadNotification(
	_In_	 ULONG					   NotificationReason,
	_In_	 const PLDR_DLL_NOTIFICATION_DATA NotificationData,
	_In_opt_ PVOID					   Context)
{
	PWCHAR dllname, dllpath;
	COPY_UNICODE_STRING(library, NotificationData->Loaded.FullDllName);
	dllname = get_dll_basename(library.Buffer);
	dllpath = wcschr(our_commandline, ' ');
	if (dllpath && wcsstr(dllpath, L"C:"))
		dllpath = wcsstr(dllpath, L"C:");
	else if (dllpath && wcsstr(dllpath, L"c:"))
		dllpath = wcsstr(dllpath, L"c:");

	int ret = 0;
	if (!g_config.tlsdump)
		LOQ_void("system", "sup", "NotificationReason", NotificationReason == 1 ? "load" : "unload", "DllName", library.Buffer, "DllBase", NotificationReason == 1 ? NotificationData->Loaded.DllBase : NotificationData->Unloaded.DllBase);

	if (NotificationReason == 1) {
		BOOL coverage_module = FALSE;
		for (unsigned int i = 0; i < ARRAYSIZE(g_config.coverage_modules); i++) {
			if (!g_config.coverage_modules[i])
				break;
			if (!wcsicmp(dllname, g_config.coverage_modules[i]))
				coverage_module = TRUE;
		}
		if (coverage_module) {
			DebugOutput("The module loaded at 0x%p has been selected for coverage: %ws (0x%x bytes).\n", NotificationData->Loaded.DllBase, library.Buffer, NotificationData->Loaded.SizeOfImage);
			if (g_config.debugger)
				SetInitialBreakpoints((PVOID)NotificationData->Loaded.DllBase);
			if (g_config.yarascan)
				YaraScan((PVOID)base_of_dll_of_interest, NotificationData->Loaded.SizeOfImage);
		}
		else if ((g_config.file_of_interest && !wcsicmp(library.Buffer, g_config.file_of_interest)) ||
			(path_is_system(our_process_path_w) && loader_is_allowed(our_process_name) && dllpath && !wcsnicmp(dllpath, library.Buffer, wcslen(library.Buffer)))) {
			if (!base_of_dll_of_interest)
				set_dll_of_interest((ULONG_PTR)NotificationData->Loaded.DllBase);
			//ImageBase = (PVOID)base_of_dll_of_interest;
			if (g_config.file_of_interest == NULL) {
				g_config.file_of_interest = calloc(1, (wcslen(library.Buffer) + 1) * sizeof(wchar_t));
				wcsncpy(g_config.file_of_interest, library.Buffer, wcslen(library.Buffer));
			}
			DebugOutput("Target DLL loaded at 0x%p: %ws (0x%x bytes).\n", NotificationData->Loaded.DllBase, library.Buffer, NotificationData->Loaded.SizeOfImage);
			if (g_config.yarascan)
				YaraScan((PVOID)base_of_dll_of_interest, NotificationData->Loaded.SizeOfImage);
			if (g_config.debugger && !g_config.base_on_apiname[0])
			{
				BreakpointsHit = FALSE;
				SetInitialBreakpoints((PVOID)base_of_dll_of_interest);
			}
		}
		//else if (path_is_shared(our_process_path_w, library.Buffer)) {
		//	DebugOutput("Local DLL loaded at 0x%p: %ws (0x%x bytes).\n", NotificationData->Loaded.DllBase, library.Buffer, NotificationData->Loaded.SizeOfImage);
		//	if (g_config.debugger)
		//		SetInitialBreakpoints((PVOID)NotificationData->Loaded.DllBase);
		//}
		else {
			SIZE_T numconverted, size;
			WCHAR exportdirectory_w[MAX_PATH];
			char* exportdirectory;

			add_dll_range((ULONG_PTR)NotificationData->Loaded.DllBase, (ULONG_PTR)NotificationData->Loaded.DllBase + GetAllocationSize(NotificationData->Loaded.DllBase));

			if (!set_hooks_dll(dllname)) {
				exportdirectory = ScyllaGetExportDirectory(NotificationData->Loaded.DllBase);
				if (exportdirectory) {
					size = strlen(exportdirectory);
					mbstowcs_s(&numconverted, exportdirectory_w, MAX_PATH, exportdirectory, size+1);
					for (unsigned int i=0; i<numconverted; i++) {
						if (!wcsnicmp(exportdirectory_w+i, L".dll", 4))
							memset(exportdirectory_w+i, 0, sizeof(WCHAR));
					}
					if (wcsicmp(dllname, exportdirectory_w))
						set_hooks_by_export_directory(exportdirectory_w, dllname);
				}
			}

			//if (g_config.debugger) {
			//	if (g_config.break_on_apiname && g_config.break_on_modname) {
			//		dllname = (char*)malloc(MAX_PATH);
			//		WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, (LPCWSTR)dllname_w, (int)wcslen(dllname_w)+1, dllname, MAX_PATH, NULL, NULL);
			//		if (!_stricmp(dllname, g_config.break_on_modname)) {
			//			BreakpointsHit = FALSE;
			//			SetInitialBreakpoints(NotificationData->Loaded.DllBase);
			//		}
			//	}
			//}
			DebugOutput("DLL loaded at 0x%p: %ws (0x%x bytes).\n", NotificationData->Loaded.DllBase, library.Buffer, NotificationData->Loaded.SizeOfImage);
		}
	}
	else {
		// unload
		if (!is_valid_address_range((ULONG_PTR)NotificationData->Unloaded.DllBase, 0x1000)) {
			// if this unload actually caused removal of the DLL instead of a reference counter decrement,
			// then we need to loop through our hooks and unmark the hooks eliminated by this removal
			revalidate_all_hooks();
		}
	}
}

static int parse_stack_trace(void *msg, ULONG_PTR addr)
{
	unsigned int offset;
	char *buf = convert_address_to_dll_name_and_offset(addr, &offset);
	if (buf) {
		PCHAR funcname;
		__try {
			funcname = ScyllaGetExportNameByScan((PVOID)addr, NULL, 0x50);
		}
		__except(EXCEPTION_EXECUTE_HANDLER) {
			;
		}
		if (funcname)
			snprintf((char *)msg + strlen(msg), sizeof(msg) - strlen(msg) - 1, "%s::%s(0x%x)\n", buf, funcname, offset);
		else
			snprintf((char *)msg + strlen(msg), sizeof(msg) - strlen(msg) - 1, "%s+0x%x\n", buf, offset);
		free(buf);
	}

	return 0;
}

LONG WINAPI capemon_exception_handler(__in struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	char *msg;
	char *dllname;
	char *sehname;
	unsigned int offset;
	ULONG_PTR eip;
	ULONG_PTR ebp_or_rip;
	ULONG_PTR seh = 0;
	PUCHAR eipptr;
	ULONG_PTR *stack;
	lasterror_t lasterror;

	if (ExceptionInfo->ExceptionRecord == NULL || ExceptionInfo->ContextRecord == NULL)
		return EXCEPTION_CONTINUE_SEARCH;

	eip = (ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress;
	eipptr = (PUCHAR)eip;

#ifdef _WIN64
	stack = (ULONG_PTR *)(ULONG_PTR)(ExceptionInfo->ContextRecord->Rsp);
	ebp_or_rip = eip;
#else
	stack = (ULONG_PTR *)(ULONG_PTR)(ExceptionInfo->ContextRecord->Esp);
	ebp_or_rip = (ULONG_PTR)(ExceptionInfo->ContextRecord->Ebp);
	{
		DWORD *tebtmp = (DWORD *)NtCurrentTeb();
		if (tebtmp[0] != 0xffffffff)
			seh = ((DWORD *)tebtmp[0])[1];
	}
#endif

	if (g_config.debug == 1 && ExceptionInfo->ExceptionRecord->ExceptionCode < 0xc0000000)
		return EXCEPTION_CONTINUE_SEARCH;

	if (ExceptionInfo->ExceptionRecord->ExceptionCode == DBG_PRINTEXCEPTION_C)
		return EXCEPTION_CONTINUE_SEARCH;

	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
		return CAPEExceptionFilter(ExceptionInfo);

	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
		return CAPEExceptionFilter(ExceptionInfo);

	hook_disable();

	get_lasterrors(&lasterror);

	log_flush();

	msg = malloc(WIDE_STRING_LIMIT);

	dllname = convert_address_to_dll_name_and_offset(eip, &offset);

	sprintf(msg, "Exception Caught! PID: %u EIP:", GetCurrentProcessId());
	if (dllname) {
		PCHAR FunctionName;
		__try {
			FunctionName = ScyllaGetExportNameByScan((PVOID)eip, NULL, 0x50);
		}
		__except(EXCEPTION_EXECUTE_HANDLER) {
			;
		}
		if (FunctionName)
			snprintf(msg + strlen(msg), sizeof(msg) - strlen(msg) - 1, " %s::%s(0x%x)", dllname, FunctionName, offset);
		else
			snprintf(msg + strlen(msg), sizeof(msg) - strlen(msg) - 1, " %s+0x%x", dllname, offset);
	}

	sehname = convert_address_to_dll_name_and_offset(seh, &offset);
	if (sehname)
		snprintf(msg + strlen(msg), sizeof(msg) - strlen(msg) - 1, " SEH: %s+0x%x", sehname, offset);

	snprintf(msg + strlen(msg), sizeof(msg) - strlen(msg), " %.08Ix, Fault Address: %.08Ix, Esp: %.08Ix, Exception Code: %08x\n",
		eip, ExceptionInfo->ExceptionRecord->ExceptionInformation[1], (ULONG_PTR)stack, ExceptionInfo->ExceptionRecord->ExceptionCode);

#ifdef _WIN64
	snprintf(msg + strlen(msg), sizeof(msg) - strlen(msg) - 1,
		"RAX 0x%I64x RBX 0x%I64x RCX 0x%I64x RDX 0x%I64x RSI 0x%I64x RDI 0x%I64x\nR8 0x%I64x R9 0x%I64x R10 0x%I64x R11 0x%I64x R12 0x%I64x R13 0x%I64x R14 0x%I64x R15 0x%I64x RSP 0x%I64x RBP 0x%I64x\n",
		ExceptionInfo->ContextRecord->Rax, ExceptionInfo->ContextRecord->Rbx, ExceptionInfo->ContextRecord->Rcx, ExceptionInfo->ContextRecord->Rdx,
		ExceptionInfo->ContextRecord->Rsi, ExceptionInfo->ContextRecord->Rdi, ExceptionInfo->ContextRecord->R8, ExceptionInfo->ContextRecord->R9,
		ExceptionInfo->ContextRecord->R10, ExceptionInfo->ContextRecord->R11, ExceptionInfo->ContextRecord->R12, ExceptionInfo->ContextRecord->R13,
		ExceptionInfo->ContextRecord->R14, ExceptionInfo->ContextRecord->R15, ExceptionInfo->ContextRecord->Rsp, ExceptionInfo->ContextRecord->Rbp
		);
#else
	snprintf(msg + strlen(msg), sizeof(msg) - strlen(msg) - 1,
		"EAX 0x%x EBX 0x%x ECX 0x%x EDX 0x%x ESI 0x%x EDI 0x%x\n ESP 0x%x EBP 0x%x\n",
		ExceptionInfo->ContextRecord->Eax, ExceptionInfo->ContextRecord->Ebx, ExceptionInfo->ContextRecord->Ecx, ExceptionInfo->ContextRecord->Edx,
		ExceptionInfo->ContextRecord->Esi, ExceptionInfo->ContextRecord->Edi, ExceptionInfo->ContextRecord->Esp, ExceptionInfo->ContextRecord->Ebp
		);
#endif

	operate_on_backtrace((ULONG_PTR)stack, ebp_or_rip, msg, &parse_stack_trace);

#ifdef _FULL_STACK_TRACE
	if (is_valid_address_range((ULONG_PTR)stack, 100 * sizeof(ULONG_PTR)))
	{
		DWORD i;
		// overflows ahoy
		for (i = 0; i < (get_stack_top() - (ULONG_PTR)stack)/sizeof(ULONG_PTR); i++) {
			char *buf = convert_address_to_dll_name_and_offset(stack[i], &offset);
			if (buf) {
				PCHAR funcname = NULL;
				__try {
					funcname = ScyllaGetExportNameByScan((PVOID)eip, NULL, 0x50);
				}
				__except(EXCEPTION_EXECUTE_HANDLER) {
					;
				}
				if (funcname)
					snprintf(msg + strlen(msg), sizeof(msg) - strlen(msg) - 1, " %s::%s(0x%x)\n", buf, funcname, offset);
				else
					snprintf(msg + strlen(msg), sizeof(msg) - strlen(msg) - 1, " %s+0x%x\n", buf, offset);
				free(buf);
			}
			if (sizeof(msg) - strlen(msg) < 0x200)
				goto next;
		}
		strcat(msg, ", ");
	}
	else {
		strcat(msg, "invalid stack, ");
	}
next:
#endif

	if (is_valid_address_range(eip, 16)) {
		PCHAR FunctionName;
		_DecodeType DecodeType;
		_DecodeResult Result;
		_OffsetType Offset = 0;
		_DecodedInst DecodedInstruction;
		unsigned int DecodedInstructionsCount = 0;
#ifdef _WIN64
		DecodeType = Decode64Bits;
#else
		DecodeType = Decode32Bits;
#endif
		Result = distorm_decode(Offset, (const unsigned char*)eip, 0x100, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount);

		if (dllname) {
			__try {
				FunctionName = ScyllaGetExportNameByScan((PVOID)eip, NULL, 0x40);
			}
			__except(EXCEPTION_EXECUTE_HANDLER) {
				;
			}
			if (FunctionName)
			{
				DebugOutput("%s::%s (`) %-20s %-6s%-4s%-30s\n", dllname, FunctionName, (DWORD_PTR)eip, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
			}

			else
			{
				DebugOutput("%s::0x%p %-20s %-6s%-4s%-30s\n", dllname, (DWORD_PTR)eip, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
			}
		}
		else
		{
			DebugOutput("0x%p %-20s %-6s%-4s%-30s\n", (DWORD_PTR)eip, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
		}
	}

	DebugOutput(msg);

	if (dllname)
		free(dllname);
	free(msg);

	set_lasterrors(&lasterror);

	hook_enable();

	return EXCEPTION_CONTINUE_SEARCH;
}

void notify_successful_load(void)
{
	// notify analyzer.py that we've loaded
	pipe("LOADED:%d", GetCurrentProcessId());
}

void get_our_process_path(void)
{
	wchar_t *tmp = calloc(1, WIDE_STRING_LIMIT * sizeof(wchar_t));
	wchar_t *tmp2 = calloc(1, WIDE_STRING_LIMIT * sizeof(wchar_t));
	our_process_path = (char*)calloc(sizeof(char), MAX_PATH);

	GetModuleFileNameW(NULL, tmp, WIDE_STRING_LIMIT);

	ensure_absolute_unicode_path(tmp2, tmp);

	our_process_path_w = tmp2;

	WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, (LPCWSTR)our_process_path_w, (int)wcslen(our_process_path_w)+1, our_process_path, MAX_PATH, NULL, NULL);

	our_process_name = get_exe_basename(our_process_path);

	free(tmp);
}

void get_our_dll_path(void)
{
	wchar_t *tmp = calloc(1, WIDE_STRING_LIMIT * sizeof(wchar_t));
	wchar_t *tmp2 = calloc(1, WIDE_STRING_LIMIT * sizeof(wchar_t));
	our_dll_path = (char*)calloc(sizeof(char), MAX_PATH);

	GetModuleFileNameW((HMODULE)g_our_dll_base, tmp, WIDE_STRING_LIMIT);

	ensure_absolute_unicode_path(tmp2, tmp);

	our_dll_path_w = tmp2;

	WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, (LPCWSTR)our_dll_path_w, (int)wcslen(our_dll_path_w)+1, our_dll_path, MAX_PATH, NULL, NULL);

	free(tmp);
}

void get_our_commandline(void)
{
	our_commandline = GetCommandLineW();
}

void set_os_bitness(void)
{
	LPFN_ISWOW64PROCESS pIsWow64Process;

	is_64bit_os = FALSE;

	pIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");

	if (pIsWow64Process)
		pIsWow64Process(GetCurrentProcess(), &is_64bit_os);
}

HANDLE g_heap;

static void *malloc_func(size_t size)
{
	return malloc(size);
}

static void *realloc_func(void *ptr, size_t size)
{
	return realloc(ptr, size);
}

static void free_func(void *ptr)
{
	free(ptr);
}

void init_private_heap(void)
{
	bson_set_malloc_func(malloc_func);
	bson_set_realloc_func(realloc_func);
	bson_set_free_func(free_func);
#ifdef USE_PRIVATE_HEAP
	g_heap = HeapCreate(0, 4 * 1024 * 1024, 0);
#endif
}

extern CRITICAL_SECTION readfile_critsec, g_mutex, g_writing_log_buffer_mutex;
BOOLEAN g_dll_main_complete;
OSVERSIONINFOA g_osverinfo;

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
{
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	if (dwReason == DLL_PROCESS_ATTACH) {
		unsigned int i;
		DWORD pids[MAX_PROTECTED_PIDS];
		unsigned int length = sizeof(pids);

		// we can sometimes be injected multiple times into a process
		if (already_hooked())
			goto abort;

		g_our_dll_base = (ULONG_PTR)hModule;
		g_our_dll_size = get_image_size(g_our_dll_base);
		ntdll_base = (ULONG_PTR)GetModuleHandle("ntdll");

		g_osverinfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
		GetVersionEx(&g_osverinfo);

		resolve_runtime_apis();

		init_private_heap();

		set_os_bitness();

		if (g_config.standalone) {
			// initialise CAPE
			CAPE_init();
			DebugOutput("Standalone mode initialised.\n");
			return TRUE;
		}

		InitializeCriticalSection(&g_mutex);
		InitializeCriticalSection(&g_writing_log_buffer_mutex);

		// initialize file stuff, needs to be performed prior to any file normalization
		file_init();

		get_our_dll_path();

		get_our_process_path();

		get_our_commandline();

		// read the config settings
		if (!read_config())
#if CUCKOODBG
			;
		else
			DebugOutput("Config loaded.\n");
#else
			// if we're not debugging, then failure to read the capemon config should be a critical error
			goto abort;
#endif

		// don't inject into our own binaries run out of the analyzer directory unless they're the first process (intended)
		if (wcslen(g_config.w_analyzer) && !wcsnicmp(our_process_path_w, g_config.w_analyzer, wcslen(g_config.w_analyzer)) && !g_config.first_process)
			goto abort;

		if (g_config.debug) {
			AddVectoredExceptionHandler(1, capemon_exception_handler);
			SetUnhandledExceptionFilter(capemon_exception_handler);
			SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOALIGNMENTFAULTEXCEPT | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
			_set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
		}

#if !CUCKOODBG
		hide_module_from_peb(hModule);
#endif

		// obtain all protected pids
		pipe2(pids, &length, "GETPIDS:");
		for (i = 0; i < length / sizeof(pids[0]); i++) {
			add_protected_pid(pids[i]);
		}

		hkcu_init();

		// initialize the log file
		if (!g_config.tlsdump)
			log_init(g_config.debug || g_config.standalone);

		// initialize the Sleep() skipping stuff
		init_sleep_skip(g_config.first_process);

		// we skip a random given amount of milliseconds each run
		init_startup_time(g_config.startup_time);

		// initialize our unhook detection
		unhook_init_detection();

		// initialize detection of process name spoofing
		procname_watch_init();

		// initialize terminate notification event
		terminate_event_init();

		// initialize misc critical sections
		InitializeCriticalSection(&readfile_critsec);

		// initialise CAPE
		CAPE_init();

		// adds our own DLL range as well, since the hiding is done later
		add_all_dlls_to_dll_ranges();

		// initialize all hooks
		set_hooks();

		CAPE_post_init();

		// initialize context watchdog
		//init_watchdog();

#ifndef _WIN64
		if (!g_config.no_stealth) {
			/* for people too lazy to setup VMs properly */
			PEB *peb = get_peb();
			if (peb->NumberOfProcessors == 1)
				peb->NumberOfProcessors = 2;
		}
#endif

		if (!g_config.tlsdump)
			notify_successful_load();
	}
	else if(dwReason == DLL_PROCESS_DETACH) {
		// in production, we shouldn't ever get called in this way since we
		// unlink ourselves from the module list in the PEB
		// so don't call log_free(), as it'll have side-effects
		// log_free();
	}

	g_dll_main_complete = TRUE;
	set_lasterrors(&lasterror);
	return TRUE;

abort:
	set_lasterrors(&lasterror);
	return FALSE;
}
