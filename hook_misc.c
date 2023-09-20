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
#include "hook_file.h"
#include "hook_sleep.h"
#include "config.h"
#include "ignore.h"
#include "CAPE\CAPE.h"
#include "CAPE\Injection.h"
#include "CAPE\Debugger.h"
#include "CAPE\YaraHarness.h"

#define STATUS_BAD_COMPRESSION_BUFFER ((NTSTATUS)0xC0000242L)

extern char *our_process_name;
extern int path_is_system(const wchar_t *path_w);
extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern void ProcessMessage(DWORD ProcessId, DWORD ThreadId);

LPTOP_LEVEL_EXCEPTION_FILTER TopLevelExceptionFilter;
BOOL PlugXConfigDumped, CompressedPE;
DWORD ExportAddress;

HOOKDEF(HHOOK, WINAPI, SetWindowsHookExA,
	__in  int idHook,
	__in  HOOKPROC lpfn,
	__in  HINSTANCE hMod,
	__in  DWORD dwThreadId
) {

	HHOOK ret;

	if (hMod && lpfn && dwThreadId) {
		DWORD pid = get_pid_by_tid(dwThreadId);
		if (pid != GetCurrentProcessId())
			ProcessMessage(pid, 0);
	}

	ret = Old_SetWindowsHookExA(idHook, lpfn, hMod, dwThreadId);
	LOQ_nonnull("system", "ippi", "HookIdentifier", idHook, "ProcedureAddress", lpfn,
		"ModuleAddress", hMod, "ThreadId", dwThreadId);
	return ret;
}

HOOKDEF(HHOOK, WINAPI, SetWindowsHookExW,
	__in  int idHook,
	__in  HOOKPROC lpfn,
	__in  HINSTANCE hMod,
	__in  DWORD dwThreadId
) {

	HHOOK ret;

	if (hMod && lpfn && dwThreadId) {
		DWORD pid = get_pid_by_tid(dwThreadId);
		if (pid != GetCurrentProcessId())
			ProcessMessage(pid, 0);
	}

	ret = Old_SetWindowsHookExW(idHook, lpfn, hMod, dwThreadId);
	LOQ_nonnull("system", "ippi", "HookIdentifier", idHook, "ProcedureAddress", lpfn,
		"ModuleAddress", hMod, "ThreadId", dwThreadId);
	return ret;
}

HOOKDEF(BOOL, WINAPI, UnhookWindowsHookEx,
	__in  HHOOK hhk
) {

	BOOL ret = Old_UnhookWindowsHookEx(hhk);
	LOQ_bool("hooking", "p", "HookHandle", hhk);
	return ret;
}

HOOKDEF(LPTOP_LEVEL_EXCEPTION_FILTER, WINAPI, SetUnhandledExceptionFilter,
	_In_  LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter
) {
	BOOL ret = 1;
	LPTOP_LEVEL_EXCEPTION_FILTER res;

	if (g_config.debug)
		res = NULL;
	else {
		res = Old_SetUnhandledExceptionFilter(lpTopLevelExceptionFilter);
		TopLevelExceptionFilter = lpTopLevelExceptionFilter;
	}

	LOQ_bool("hooking", "p", "ExceptionFilter", lpTopLevelExceptionFilter);
	return res;
}

PVECTORED_EXCEPTION_HANDLER SampleVectoredHandler;

LONG WINAPI VectoredExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	if ((ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress >= g_our_dll_base && (ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress < (g_our_dll_base + g_our_dll_size))
		return EXCEPTION_CONTINUE_SEARCH;
	else
		return SampleVectoredHandler(ExceptionInfo);
}

HOOKDEF(PVOID, WINAPI, RtlAddVectoredExceptionHandler,
	__in	ULONG First,
	__out   PVECTORED_EXCEPTION_HANDLER Handler
) {
	PVOID ret = 0;

	if (!SampleVectoredHandler) {
		SampleVectoredHandler = Handler;
		ret = Old_RtlAddVectoredExceptionHandler(First, VectoredExceptionFilter);
	}
	else
		ret = Old_RtlAddVectoredExceptionHandler(First, Handler);

	LOQ_nonnull("hooking", "ip", "First", First, "Handler", Handler);

	return ret;
}

HOOKDEF(UINT, WINAPI, SetErrorMode,
	_In_ UINT uMode
) {
	UINT ret = 0;

	if (!g_config.debug)
	ret = Old_SetErrorMode(uMode);

	//LOQ_void("system", "h", "Mode", uMode);
	disable_tail_call_optimization();
	return ret;
}

// Called with the loader lock held
HOOKDEF(NTSTATUS, WINAPI, LdrGetDllHandle,
	__in_opt	PWORD pwPath,
	__in_opt	PVOID Unused,
	__in		PUNICODE_STRING ModuleFileName,
	__out	   PHANDLE pHModule
) {
	NTSTATUS ret = Old_LdrGetDllHandle(pwPath, Unused, ModuleFileName, pHModule);
	LOQ_ntstatus("system", "oP", "FileName", ModuleFileName, "ModuleHandle", pHModule);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, LdrGetProcedureAddress,
	__in		HMODULE ModuleHandle,
	__in_opt	PANSI_STRING FunctionName,
	__in_opt	WORD Ordinal,
	__out	   PVOID *FunctionAddress
) {
	NTSTATUS ret = Old_LdrGetProcedureAddress(ModuleHandle, FunctionName, Ordinal, FunctionAddress);

	if (FunctionName != NULL && FunctionName->Length == 13 && FunctionName->Buffer != NULL &&
		(!strncmp(FunctionName->Buffer, "EncodePointer", 13) || !strncmp(FunctionName->Buffer, "DecodePointer", 13)))
		return ret;

	if (ExportAddress && Ordinal == 1 && path_is_system(our_process_path_w) && !_stricmp(our_process_name, "rundll32.exe")) {
		*FunctionAddress = (PVOID)((PBYTE)ModuleHandle + ExportAddress);
		DebugOutput("LdrGetProcedureAddress: Patched export address to 0x%p", *FunctionAddress);
	}

	LOQ_ntstatus("system", "opSiP", "ModuleName", get_basename_of_module(ModuleHandle), "ModuleHandle", ModuleHandle,
		"FunctionName", FunctionName != NULL ? FunctionName->Length : 0, FunctionName != NULL ? FunctionName->Buffer : NULL,
		"Ordinal", Ordinal, "FunctionAddress", FunctionAddress);

	if (hook_info()->main_caller_retaddr && g_config.first_process && FunctionName != NULL && (ret == 0xc000007a || ret == 0xc0000139) && FunctionName->Length == 7 &&
		!strncmp(FunctionName->Buffer, "DllMain", 7) && wcsicmp(our_process_path_w, g_config.file_of_interest)) {
		log_flush();
		ExitThread(0);
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, LdrGetProcedureAddressForCaller,
	__in		HMODULE ModuleHandle,
	__in_opt	PANSI_STRING FunctionName,
	__in_opt	WORD Ordinal,
	__out		PVOID *FunctionAddress,
	__in		BOOL bValue,
	__in		PVOID *CallbackAddress
) {
	NTSTATUS ret = Old_LdrGetProcedureAddressForCaller(ModuleHandle, FunctionName, Ordinal, FunctionAddress, bValue, CallbackAddress);

	if (FunctionName != NULL && FunctionName->Length == 13 && FunctionName->Buffer != NULL &&
		(!strncmp(FunctionName->Buffer, "EncodePointer", 13) || !strncmp(FunctionName->Buffer, "DecodePointer", 13)))
		return ret;

	if (ExportAddress && Ordinal == 1 && path_is_system(our_process_path_w) && !_stricmp(our_process_name, "rundll32.exe")) {
		*FunctionAddress = (PVOID)((PBYTE)ModuleHandle + ExportAddress);
		DebugOutput("LdrGetProcedureAddress: Patched export address to 0x%p", *FunctionAddress);
	}

	LOQ_ntstatus("system", "opSiP", "ModuleName", get_basename_of_module(ModuleHandle), "ModuleHandle", ModuleHandle,
		"FunctionName", FunctionName != NULL ? FunctionName->Length : 0, FunctionName != NULL ? FunctionName->Buffer : NULL,
		"Ordinal", Ordinal, "FunctionAddress", FunctionAddress);

	if (hook_info()->main_caller_retaddr && g_config.first_process && FunctionName != NULL && (ret == 0xc000007a || ret == 0xc0000139) && FunctionName->Length == 7 &&
		!strncmp(FunctionName->Buffer, "DllMain", 7) && wcsicmp(our_process_path_w, g_config.file_of_interest)) {
		log_flush();
		ExitThread(0);
	}

	return ret;
}

HOOKDEF(BOOL, WINAPI, DeviceIoControl,
	__in		 HANDLE hDevice,
	__in		 DWORD dwIoControlCode,
	__in_opt	 LPVOID lpInBuffer,
	__in		 DWORD nInBufferSize,
	__out_opt	LPVOID lpOutBuffer,
	__in		 DWORD nOutBufferSize,
	__out_opt	LPDWORD lpBytesReturned,
	__inout_opt  LPOVERLAPPED lpOverlapped
) {
	BOOL ret;
	ENSURE_DWORD(lpBytesReturned);

	ret = Old_DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer,
		nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned,
		lpOverlapped);
	LOQ_bool("device", "phbb", "DeviceHandle", hDevice, "IoControlCode", dwIoControlCode,
		"InBuffer", nInBufferSize, lpInBuffer,
		"OutBuffer", *lpBytesReturned, lpOutBuffer);

	if (!g_config.no_stealth && ret && lpOutBuffer)
		perform_device_fakery(lpOutBuffer, *lpBytesReturned, dwIoControlCode);

	return ret;
}

HOOKDEF_NOTAIL(WINAPI, NtShutdownSystem,
	__in  UINT Action
) {
	DWORD ret = 0;
	LOQ_zero("system", "i", "Action", Action);
	pipe("SHUTDOWN:");
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, NtSetSystemPowerState,
	__in  UINT SystemAction,
	__in  UINT MinSystemState,
	__in  UINT Flags
) {
	DWORD ret = 0;
	LOQ_zero("system", "iih", "SystemAction", SystemAction, "MinSystemState", MinSystemState, "Flags", Flags);
	pipe("SHUTDOWN:");
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, ExitWindowsEx,
	__in  UINT uFlags,
	__in  DWORD dwReason
) {
	DWORD ret = 0;
	LOQ_zero("system", "hi", "Flags", uFlags, "Reason", dwReason);
	pipe("SHUTDOWN:");
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, InitiateShutdownW,
	_In_opt_ LPWSTR lpMachineName,
	_In_opt_ LPWSTR lpMessage,
	_In_	 DWORD  dwGracePeriod,
	_In_	 DWORD  dwShutdownFlags,
	_In_	 DWORD  dwReason
) {
	DWORD ret = 0;
	LOQ_zero("system", "uuihh", "MachineName", lpMachineName, "Message", lpMessage, "GracePeriod", dwGracePeriod, "ShutdownFlags", dwShutdownFlags, "Reason", dwReason);
	pipe("SHUTDOWN:");
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, InitiateSystemShutdownW,
	_In_opt_ LPWSTR lpMachineName,
	_In_opt_ LPWSTR lpMessage,
	_In_	 DWORD  dwTimeout,
	_In_	 BOOL	bForceAppsClosed,
	_In_	 BOOL	bRebootAfterShutdown
) {
	DWORD ret = 0;
	LOQ_zero("system", "uuiii", "MachineName", lpMachineName, "Message", lpMessage, "Timeout", dwTimeout, "ForceAppsClosed", bForceAppsClosed, "RebootAfterShutdown", bRebootAfterShutdown);
	pipe("SHUTDOWN:");
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, NtRaiseHardError,
	IN NTSTATUS 	ErrorStatus,
	IN ULONG 	NumberOfParameters,
	IN ULONG 	UnicodeStringParameterMask,
	IN PULONG_PTR 	Parameters,
	IN ULONG 	ValidResponseOptions,
	OUT PULONG 	Response
) {
	DWORD ret = 0;
	LOQ_zero("system", "hi", "ErrorStatus", ErrorStatus, "ResponseOptions", ValidResponseOptions);

	if (ValidResponseOptions == OptionShutdownSystem)
		pipe("SHUTDOWN:");

	return ret;
}

HOOKDEF_NOTAIL(WINAPI, InitiateSystemShutdownExW,
	_In_opt_ LPWSTR lpMachineName,
	_In_opt_ LPWSTR lpMessage,
	_In_	 DWORD  dwTimeout,
	_In_	 BOOL	bForceAppsClosed,
	_In_	 BOOL	bRebootAfterShutdown,
	_In_	 DWORD	dwReason
) {
	DWORD ret = 0;
	LOQ_zero("system", "uuiiih", "MachineName", lpMachineName, "Message", lpMessage, "Timeout", dwTimeout, "ForceAppsClosed", bForceAppsClosed, "RebootAfterShutdown", bRebootAfterShutdown, "Reason", dwReason);
	pipe("SHUTDOWN:");
	return ret;
}

static int num_isdebuggerpresent;

HOOKDEF(BOOL, WINAPI, IsDebuggerPresent,
	void
) {

	BOOL ret = Old_IsDebuggerPresent();
	num_isdebuggerpresent++;
	if (num_isdebuggerpresent < 20)
		LOQ_bool("system", "");
	else if (num_isdebuggerpresent == 20)
		LOQ_bool("system", "s", "Status", "Log limit reached");
#ifndef _WIN64
	else if (num_isdebuggerpresent == 1000) {
		lasterror_t lasterror;

		get_lasterrors(&lasterror);
		__try {
			hook_info_t *hookinfo = hook_info();
			PUCHAR p = (PUCHAR)hookinfo->main_caller_retaddr - 6;
			if (p[0] == 0xff && p[1] == 0x15 && p[6] == 0x49) {
				DWORD oldprot;
				VirtualProtect(p, 6, PAGE_EXECUTE_READWRITE, &oldprot);
				memcpy(p, "\x31\xc0\x31\xc9\x41\x90", 6);
				VirtualProtect(p, 6, oldprot, &oldprot);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
		set_lasterrors(&lasterror);
	}
#endif

	return ret;
}

HOOKDEF(BOOL, WINAPI, LookupPrivilegeValueW,
	__in_opt  LPWSTR lpSystemName,
	__in	  LPWSTR lpName,
	__out	 PLUID lpLuid
) {

	BOOL ret = Old_LookupPrivilegeValueW(lpSystemName, lpName, lpLuid);
	LOQ_bool("system", "uu", "SystemName", lpSystemName, "PrivilegeName", lpName);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtClose,
	__in	HANDLE Handle
) {
	NTSTATUS ret;
	if (Handle == g_log_handle) {
		ret = STATUS_INVALID_HANDLE;
		LOQ_ntstatus("system", "ps", "Handle", Handle, "Alert", "Tried to close Cuckoo's log handle");
		return ret;
	}
	ret = Old_NtClose(Handle);
	LOQ_ntstatus("system", "p", "Handle", Handle);
	if(NT_SUCCESS(ret)) {
		remove_file_from_log_tracking(Handle);
		DumpSectionViewsForHandle(Handle);
		file_close(Handle);
	}
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtDuplicateObject,
	__in	   HANDLE SourceProcessHandle,
	__in	   HANDLE SourceHandle,
	__in_opt   HANDLE TargetProcessHandle,
	__out_opt  PHANDLE TargetHandle,
	__in	   ACCESS_MASK DesiredAccess,
	__in	   ULONG HandleAttributes,
	__in	   ULONG Options
	) {
	NTSTATUS ret = Old_NtDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle,
		TargetHandle, DesiredAccess, HandleAttributes, Options);
	if (TargetHandle)
		LOQ_ntstatus("system", "pppPh", "SourceProcessHandle", SourceProcessHandle, "SourceHandle", SourceHandle, "TargetProcessHandle", TargetProcessHandle, "TargetHandle", TargetHandle, "Options", Options);
	else
		LOQ_ntstatus("system", "pph", "SourceProcessHandle", SourceProcessHandle, "SourceHandle", SourceHandle, "Options", Options);

	if (NT_SUCCESS(ret)) {
		if (TargetProcessHandle == NtCurrentProcess() && TargetHandle) {
			handle_duplicate(SourceHandle, *TargetHandle);
			handle_duplicate(SourceHandle, *TargetHandle);
		}
		if (SourceProcessHandle == NtCurrentProcess() && (Options & DUPLICATE_CLOSE_SOURCE)) {
			remove_file_from_log_tracking(SourceHandle);
			file_close(SourceHandle);
		}
	}
	return ret;
}

HOOKDEF(BOOL, WINAPI, SaferIdentifyLevel,
	_In_	   DWORD				  dwNumProperties,
	_In_opt_   PVOID				  pCodeProperties,
	_Out_	  PVOID				  pLevelHandle,
	_Reserved_ LPVOID				 lpReserved
) {
	BOOL ret;
	ret = Old_SaferIdentifyLevel(dwNumProperties, pCodeProperties, pLevelHandle, lpReserved);
	LOQ_bool("misc", "");
	return ret;
}


HOOKDEF(NTSTATUS, WINAPI, NtMakeTemporaryObject,
	__in	 HANDLE ObjectHandle
	) {
	NTSTATUS ret = Old_NtMakeTemporaryObject(ObjectHandle);
	LOQ_ntstatus("system", "p", "ObjectHandle", ObjectHandle);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtMakePermanentObject,
	__in	 HANDLE ObjectHandle
	) {
	NTSTATUS ret = Old_NtMakePermanentObject(ObjectHandle);
	LOQ_ntstatus("system", "p", "ObjectHandle", ObjectHandle);
	return ret;
}

HOOKDEF(BOOL, WINAPI, WriteConsoleA,
	_In_		HANDLE hConsoleOutput,
	_In_		const VOID *lpBuffer,
	_In_		DWORD nNumberOfCharsToWrite,
	_Out_	   LPDWORD lpNumberOfCharsWritten,
	_Reserved_  LPVOID lpReseverd
) {
	BOOL ret = Old_WriteConsoleA(hConsoleOutput, lpBuffer,
		nNumberOfCharsToWrite, lpNumberOfCharsWritten, lpReseverd);
	LOQ_bool("system", "pS", "ConsoleHandle", hConsoleOutput,
		"Buffer", nNumberOfCharsToWrite, lpBuffer);
	return ret;
}

HOOKDEF(BOOL, WINAPI, WriteConsoleW,
	_In_		HANDLE hConsoleOutput,
	_In_		const VOID *lpBuffer,
	_In_		DWORD nNumberOfCharsToWrite,
	_Out_	   LPDWORD lpNumberOfCharsWritten,
	_Reserved_  LPVOID lpReseverd
) {
	BOOL ret = Old_WriteConsoleW(hConsoleOutput, lpBuffer,
		nNumberOfCharsToWrite, lpNumberOfCharsWritten, lpReseverd);
	LOQ_bool("system", "pU", "ConsoleHandle", hConsoleOutput,
		"Buffer", nNumberOfCharsToWrite, lpBuffer);
	return ret;
}

HOOKDEF(int, WINAPI, GetSystemMetrics,
	_In_  int nIndex
) {
	int ret = Old_GetSystemMetrics(nIndex);

	if (nIndex == SM_CXSCREEN || nIndex == SM_CXVIRTUALSCREEN || nIndex == SM_CYSCREEN ||
		nIndex == SM_CYVIRTUALSCREEN || nIndex == SM_REMOTECONTROL || nIndex == SM_REMOTESESSION ||
		nIndex == SM_SHUTTINGDOWN || nIndex == SM_SWAPBUTTON)
		LOQ_nonzero("misc", "i", "SystemMetricIndex", nIndex);
	return ret;
}

typedef int (WINAPI * __GetSystemMetrics)(__in int nIndex);

__GetSystemMetrics _GetSystemMetrics;

DWORD WINAPI our_GetSystemMetrics(
	__in int nIndex
) {
	if (!_GetSystemMetrics) {
		_GetSystemMetrics = (__GetSystemMetrics)GetProcAddress(LoadLibraryA("user32"), "GetSystemMetrics");
	}
	return _GetSystemMetrics(nIndex);
}

static LARGE_INTEGER last_skipped;
static int num_to_spoof;
static int num_spoofed;
static int lastx;
static int lasty;

HOOKDEF(BOOL, WINAPI, GetCursorPos,
	_Out_ LPPOINT lpPoint
) {
	ENSURE_STRUCT(lpPoint, POINT);
	BOOL ret = Old_GetCursorPos(lpPoint);

	/* work around the fact that skipping sleeps prevents the human module from making the system look active */
	if (ret && time_skipped.QuadPart != last_skipped.QuadPart) {
		int xres, yres;
		xres = our_GetSystemMetrics(0);
		yres = our_GetSystemMetrics(1);
		if (!num_to_spoof)
			num_to_spoof = (random() % 20) + 10;
		if (num_spoofed < num_to_spoof) {
			lpPoint->x = random() % xres;
			lpPoint->y = random() % yres;
			num_spoofed++;
		}
		else {
			lpPoint->x = lastx;
			lpPoint->y = lasty;
			lastx = lpPoint->x;
			lasty = lpPoint->y;
		}
		last_skipped.QuadPart = time_skipped.QuadPart;
	}
	else if (last_skipped.QuadPart == 0) {
		last_skipped.QuadPart = time_skipped.QuadPart;
	}

	if (ret){
			LOQ_bool("misc", "ii", "x", lpPoint != NULL ? lpPoint->x : 0,
				 "y", lpPoint != NULL ? lpPoint->y : 0);
	}
	else{
		LOQ_bool("misc", "ii", "x", 0, "y", 0);
	}
	return ret;
}

HOOKDEF(DWORD, WINAPI, GetLastError,
	void
)
{
	DWORD ret = Old_GetLastError();
	LOQ_void("misc", "");
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetComputerNameA,
	_Out_	LPSTR lpBuffer,
	_Inout_  LPDWORD lpnSize
) {
	BOOL ret = Old_GetComputerNameA(lpBuffer, lpnSize);
	LOQ_bool("misc", "s", "ComputerName", lpBuffer);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetComputerNameW,
	_Out_	LPWSTR lpBuffer,
	_Inout_  LPDWORD lpnSize
) {
	BOOL ret = Old_GetComputerNameW(lpBuffer, lpnSize);
	LOQ_bool("misc", "u", "ComputerName", lpBuffer);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetComputerNameExW,
	__in	int NameType,
	__out	LPWSTR lpBuffer,
	__out	LPDWORD nSize
) {
	BOOL ret = Old_GetComputerNameExW(NameType, lpBuffer, nSize);
	LOQ_bool("misc", "u", "ComputerName", lpBuffer);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetUserNameA,
	_Out_	LPSTR lpBuffer,
	_Inout_  LPDWORD lpnSize
) {
	BOOL ret = Old_GetUserNameA(lpBuffer, lpnSize);
	LOQ_bool("misc", "s", "Name", lpBuffer);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetUserNameW,
	_Out_	LPWSTR lpBuffer,
	_Inout_  LPDWORD lpnSize
) {
	BOOL ret = Old_GetUserNameW(lpBuffer, lpnSize);
	LOQ_bool("misc", "u", "Name", lpBuffer);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtLoadDriver,
	__in PUNICODE_STRING DriverServiceName
) {
	NTSTATUS ret = Old_NtLoadDriver(DriverServiceName);
	LOQ_ntstatus("misc", "o", "DriverServiceName", DriverServiceName);
	return ret;
}

static unsigned int asynckeystate_logcount;

HOOKDEF(SHORT, WINAPI, GetAsyncKeyState,
	__in int vKey
) {
	SHORT ret = Old_GetAsyncKeyState(vKey);
	if (asynckeystate_logcount < 50 && ((vKey >= 0x30 && vKey <= 0x39) || (vKey >= 0x41 && vKey <= 0x5a))) {
		asynckeystate_logcount++;
		LOQ_nonzero("windows", "i", "KeyCode", vKey);
	}
	else if (asynckeystate_logcount == 50) {
		asynckeystate_logcount++;
		LOQ_nonzero("windows", "is", "KeyCode", vKey, "Status", "Log limit reached");
	}
	return ret;
}

#define PLUGX_SIGNATURE 0x5658	// 'XV'

HOOKDEF(NTSTATUS, WINAPI, RtlDecompressBuffer,
	__in USHORT CompressionFormat,
	__out PUCHAR UncompressedBuffer,
	__in ULONG UncompressedBufferSize,
	__in PUCHAR CompressedBuffer,
	__in ULONG CompressedBufferSize,
	__out PULONG FinalUncompressedSize
) {
	NTSTATUS ret = Old_RtlDecompressBuffer(CompressionFormat, UncompressedBuffer, UncompressedBufferSize,
		CompressedBuffer, CompressedBufferSize, FinalUncompressedSize);

	LOQ_ntstatus("misc", "pch", "UncompressedBufferAddress", UncompressedBuffer, "UncompressedBuffer",
		*FinalUncompressedSize, UncompressedBuffer, "UncompressedBufferLength", *FinalUncompressedSize);

	if ((NT_SUCCESS(ret) || ret == STATUS_BAD_COMPRESSION_BUFFER) && (*FinalUncompressedSize > 0)) {
		if (g_config.unpacker || g_config.plugx) {
			DebugOutput("RtlDecompressBuffer hook: scanning region 0x%x size 0x%x.\n", UncompressedBuffer, *FinalUncompressedSize);
			if (g_config.yarascan)
				YaraScan(UncompressedBuffer, *FinalUncompressedSize);
			if (*(WORD*)UncompressedBuffer == PLUGX_SIGNATURE) {
                DebugOutput("PlugX header - correcting");
				PBYTE PEImage = (BYTE*)malloc(*FinalUncompressedSize);
				if (PEImage) {
					g_config.plugx = 1;
					memcpy(PEImage, UncompressedBuffer, *FinalUncompressedSize);
					*(WORD*)PEImage = IMAGE_DOS_SIGNATURE;
					LONG e_lfanew = *(LONG*)(PEImage + FIELD_OFFSET(IMAGE_DOS_HEADER, e_lfanew));
					if (*(DWORD*)(PEImage + e_lfanew) == PLUGX_SIGNATURE)
						*(DWORD*)(PEImage + e_lfanew) = IMAGE_NT_SIGNATURE;
					CapeMetaData->TypeString = "PlugX Payload";
					DumpPEsInRange(PEImage, *FinalUncompressedSize);
					free(PEImage);
				}
			}
			else if (g_config.plugx)
				CapeMetaData->TypeString = "PlugX Payload";
			else
				CapeMetaData->DumpType = COMPRESSION;
			CompressedPE = DumpPEsInRange(UncompressedBuffer, *FinalUncompressedSize);
		}
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, RtlCompressBuffer,
	_In_  USHORT CompressionFormatAndEngine,
	_In_  PUCHAR UncompressedBuffer,
	_In_  ULONG  UncompressedBufferSize,
	_Out_ PUCHAR CompressedBuffer,
	_In_  ULONG  CompressedBufferSize,
	_In_  ULONG  UncompressedChunkSize,
	_Out_ PULONG FinalCompressedSize,
	_In_  PVOID  WorkSpace
) {
	NTSTATUS ret = Old_RtlCompressBuffer(CompressionFormatAndEngine, UncompressedBuffer, UncompressedBufferSize,
		CompressedBuffer, CompressedBufferSize, UncompressedChunkSize, FinalCompressedSize, WorkSpace);

	LOQ_ntstatus("misc", "pbh", "UncompressedBufferAddress", UncompressedBuffer, "UncompressedBuffer",
		ret ? 0 : UncompressedBufferSize, UncompressedBuffer, "UncompressedBufferLength", ret ? 0 : UncompressedBufferSize);

	return ret;

}

HOOKDEF(void, WINAPI, GetSystemInfo,
	__out LPSYSTEM_INFO lpSystemInfo
) {
	int ret = 0;

	Old_GetSystemInfo(lpSystemInfo);

	if (!g_config.no_stealth && lpSystemInfo->dwNumberOfProcessors < 4)
		lpSystemInfo->dwNumberOfProcessors = 4;

	LOQ_void("misc", "");

	return;
}

HOOKDEF(NTSTATUS, WINAPI, NtSetInformationProcess,
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__in PVOID ProcessInformation,
	__in ULONG ProcessInformationLength
) {
	NTSTATUS ret = 0;
	if (!g_config.syscall || ProcessInformationClass != ProcessInstrumentationCallback)
		ret = Old_NtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
	if ((ProcessInformationClass == ProcessExecuteFlags || ProcessInformationClass == ProcessBreakOnTermination) && ProcessInformationLength == 4)
		LOQ_ntstatus("process", "ii", "ProcessInformationClass", ProcessInformationClass, "ProcessInformation", *(int*)ProcessInformation);
	else
		LOQ_ntstatus("process", "ib", "ProcessInformationClass", ProcessInformationClass, "ProcessInformation", ProcessInformationLength, ProcessInformation);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryInformationProcess,
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
) {
	NTSTATUS ret = Old_NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
	LOQ_ntstatus("process", "ib", "ProcessInformationClass", ProcessInformationClass, "ProcessInformation", ProcessInformationLength, ProcessInformation);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQuerySystemInformation,
	_In_ ULONG SystemInformationClass,
	_Inout_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
) {
	NTSTATUS ret;
	char *buf;
	lasterror_t lasterror;
	ENSURE_ULONG(ReturnLength);

	if (SystemInformationClass != SystemProcessInformation || SystemInformation == NULL) {
normal_call:
		ret = Old_NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
		LOQ_ntstatus("misc", "i", "SystemInformationClass", SystemInformationClass);

		if (!g_config.no_stealth && SystemInformationClass == SystemBasicInformation && SystemInformationLength >= sizeof(SYSTEM_BASIC_INFORMATION) && NT_SUCCESS(ret)) {
			PSYSTEM_BASIC_INFORMATION p = (PSYSTEM_BASIC_INFORMATION)SystemInformation;
			p->NumberOfProcessors = 2;
		}

		/* This is nearly arbitrary and simply designed to test whether the Upatre author(s) or others
		are reading this code */
		if (!g_config.no_stealth && SystemInformationClass == SystemProcessorPerformanceInformation &&
			NT_SUCCESS(ret) && SystemInformationLength >= (sizeof(LARGE_INTEGER) * 3)) {
			PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION perf_info = (PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION)SystemInformation;
			perf_info->IdleTime.HighPart |= 2;
		}
		else if (!g_config.no_stealth && SystemInformationClass == SystemPerformanceInformation &&
			NT_SUCCESS(ret) && SystemInformationLength >= sizeof(LARGE_INTEGER)) {
			PLARGE_INTEGER perf_info = (PLARGE_INTEGER)SystemInformation;
			perf_info->HighPart |= 2;
		}

		return ret;
	}

	get_lasterrors(&lasterror);
	buf = calloc(1, SystemInformationLength);
	set_lasterrors(&lasterror);
	if (buf == NULL)
		goto normal_call;

	ret = Old_NtQuerySystemInformation(SystemInformationClass, buf, SystemInformationLength, ReturnLength);
	LOQ_ntstatus("misc", "i", "SystemInformationClass", SystemInformationClass);

	if (SystemInformationLength >= sizeof(SYSTEM_PROCESS_INFORMATION) && NT_SUCCESS(ret)) {
		PSYSTEM_PROCESS_INFORMATION our_p = (PSYSTEM_PROCESS_INFORMATION)buf;
		char *their_last_p = NULL;
		char *their_p = (char *)SystemInformation;
		ULONG lastlen = 0;
		while (1) {
			if (!is_protected_pid((DWORD)(ULONG_PTR)our_p->UniqueProcessId)) {
				PSYSTEM_PROCESS_INFORMATION tmp;
				if (our_p->NextEntryOffset)
					lastlen = our_p->NextEntryOffset;
				else
					lastlen = *ReturnLength - (ULONG)((char *)our_p - buf);
				// make sure we copy all data associated with the entry
				memcpy(their_p, our_p, lastlen);
				tmp = (PSYSTEM_PROCESS_INFORMATION)their_p;
				tmp->NextEntryOffset = lastlen;
				// adjust the only pointer field in the struct so that it points into the user's buffer,
				// but only if the pointer exists, otherwise we'd rewrite a NULL pointer to something not NULL
				if (tmp->ImageName.Buffer)
					tmp->ImageName.Buffer = (PWSTR)(((ULONG_PTR)tmp->ImageName.Buffer - (ULONG_PTR)our_p) + (ULONG_PTR)their_p);
				their_last_p = their_p;
				their_p += lastlen;
			}
			if (!our_p->NextEntryOffset)
				break;
			our_p = (PSYSTEM_PROCESS_INFORMATION)((PCHAR)our_p + our_p->NextEntryOffset);
		}
		if (their_last_p) {
			PSYSTEM_PROCESS_INFORMATION tmp;
			tmp = (PSYSTEM_PROCESS_INFORMATION)their_last_p;
			*ReturnLength = (ULONG)(their_last_p + tmp->NextEntryOffset - (char *)SystemInformation);
			tmp->NextEntryOffset = 0;
		}
	}

	free(buf);

	return ret;
}

static GUID _CLSID_DiskDrive = { 0x4d36e967, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };
static GUID _CLSID_CDROM = { 0x4d36e965, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };
static GUID _CLSID_Display = { 0x4d36e968, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };
static GUID _CLSID_FDC = { 0x4d36e969, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };
static GUID _CLSID_HDC = { 0x4d36e96a, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };
static GUID _CLSID_FloppyDisk = { 0x4d36e980, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 };

static char *known_object(IID *cls)
{
	if (!memcmp(cls, &_CLSID_DiskDrive, sizeof(*cls)))
		return "DiskDrive";
	else if (!memcmp(cls, &_CLSID_CDROM, sizeof(*cls)))
		return "CDROM";
	else if (!memcmp(cls, &_CLSID_Display, sizeof(*cls)))
		return "Display";
	else if (!memcmp(cls, &_CLSID_FDC, sizeof(*cls)))
		return "FDC";
	else if (!memcmp(cls, &_CLSID_HDC, sizeof(*cls)))
		return "HDC";
	else if (!memcmp(cls, &_CLSID_FloppyDisk, sizeof(*cls)))
		return "FloppyDisk";

	return NULL;
}

HOOKDEF(HDEVINFO, WINAPI, SetupDiGetClassDevsA,
	_In_opt_ const GUID   *ClassGuid,
	_In_opt_	   PCSTR Enumerator,
	_In_opt_	   HWND   hwndParent,
	_In_		   DWORD  Flags
) {
	IID id1;
	char idbuf[40];
	char *known;
	lasterror_t lasterror;
	HDEVINFO ret = Old_SetupDiGetClassDevsA(ClassGuid, Enumerator, hwndParent, Flags);

	get_lasterrors(&lasterror);

	if (ClassGuid) {
		memcpy(&id1, ClassGuid, sizeof(id1));
		sprintf(idbuf, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", id1.Data1, id1.Data2, id1.Data3,
			id1.Data4[0], id1.Data4[1], id1.Data4[2], id1.Data4[3], id1.Data4[4], id1.Data4[5], id1.Data4[6], id1.Data4[7]);

		if ((known = known_object(&id1)))
			LOQ_handle("misc", "ss", "ClassGuid", idbuf, "Known", known);
		else
			LOQ_handle("misc", "s", "ClassGuid", idbuf);

		set_lasterrors(&lasterror);
	}
	return ret;
}

HOOKDEF(HDEVINFO, WINAPI, SetupDiGetClassDevsW,
	_In_opt_ const GUID   *ClassGuid,
	_In_opt_	   PCWSTR Enumerator,
	_In_opt_	   HWND   hwndParent,
	_In_		   DWORD  Flags
) {
	IID id1;
	char idbuf[40];
	char *known;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	HDEVINFO ret = Old_SetupDiGetClassDevsW(ClassGuid, Enumerator, hwndParent, Flags);
	if (ClassGuid) {
		memcpy(&id1, ClassGuid, sizeof(id1));
		sprintf(idbuf, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", id1.Data1, id1.Data2, id1.Data3,
			id1.Data4[0], id1.Data4[1], id1.Data4[2], id1.Data4[3], id1.Data4[4], id1.Data4[5], id1.Data4[6], id1.Data4[7]);

		if ((known = known_object(&id1)))
			LOQ_handle("misc", "ss", "ClassGuid", idbuf, "Known", known);
		else
			LOQ_handle("misc", "s", "ClassGuid", idbuf);

		set_lasterrors(&lasterror);
	}
	return ret;
}

HOOKDEF(BOOL, WINAPI, SetupDiGetDeviceRegistryPropertyA,
	_In_	  HDEVINFO		 DeviceInfoSet,
	_In_	  PSP_DEVINFO_DATA DeviceInfoData,
	_In_	  DWORD			Property,
	_Out_opt_ PDWORD		   PropertyRegDataType,
	_Out_opt_ PBYTE			PropertyBuffer,
	_In_	  DWORD			PropertyBufferSize,
	_Out_opt_ PDWORD		   RequiredSize
) {
	BOOL ret;
	ENSURE_DWORD(PropertyRegDataType);
	ENSURE_DWORD(RequiredSize);

	ret = Old_SetupDiGetDeviceRegistryPropertyA(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize);

	if (!g_config.no_stealth && ret && PropertyBuffer) {
		replace_ci_string_in_buf(PropertyBuffer, *RequiredSize, "VBOX", "DELL_");
		replace_ci_string_in_buf(PropertyBuffer, *RequiredSize, "QEMU", "DELL");
		replace_ci_string_in_buf(PropertyBuffer, *RequiredSize, "VMWARE", "DELL__");
	}

	if (PropertyBuffer)
		LOQ_bool("misc", "ir", "Property", Property, "PropertyBuffer", *PropertyRegDataType, PropertyBufferSize, PropertyBuffer);

	return ret;
}


HOOKDEF(BOOL, WINAPI, SetupDiGetDeviceRegistryPropertyW,
	_In_	  HDEVINFO		 DeviceInfoSet,
	_In_	  PSP_DEVINFO_DATA DeviceInfoData,
	_In_	  DWORD			Property,
	_Out_opt_ PDWORD		   PropertyRegDataType,
	_Out_opt_ PBYTE			PropertyBuffer,
	_In_	  DWORD			PropertyBufferSize,
	_Out_opt_ PDWORD		   RequiredSize
) {
	BOOL ret;
	ENSURE_DWORD(PropertyRegDataType);
	ENSURE_DWORD(RequiredSize);

	ret = Old_SetupDiGetDeviceRegistryPropertyW(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize);

	if (!g_config.no_stealth && ret && PropertyBuffer) {
		replace_ci_wstring_in_buf((PWCHAR)PropertyBuffer, *RequiredSize / sizeof(WCHAR), L"VBOX", L"DELL_");
		replace_ci_wstring_in_buf((PWCHAR)PropertyBuffer, *RequiredSize / sizeof(WCHAR), L"QEMU", L"DELL");
		replace_ci_wstring_in_buf((PWCHAR)PropertyBuffer, *RequiredSize / sizeof(WCHAR), L"VMWARE", L"DELL__");
	}

	if (PropertyBuffer)
		LOQ_bool("misc", "iR", "Property", Property, "PropertyBuffer", *PropertyRegDataType, PropertyBufferSize, PropertyBuffer);

	return ret;
}

HOOKDEF(BOOL, WINAPI, SetupDiBuildDriverInfoList,
	_In_	HDEVINFO		 DeviceInfoSet,
	_Inout_ PSP_DEVINFO_DATA DeviceInfoData,
	_In_	DWORD			DriverType
) {
	BOOL ret;
	ret = Old_SetupDiBuildDriverInfoList(DeviceInfoSet, DeviceInfoData, DriverType);
	LOQ_bool("misc", "");
	return ret;
}

HOOKDEF(HRESULT, WINAPI, DecodeImageEx,
	__in PVOID pStream, // IStream *
	__in PVOID pMap, // IMapMIMEToCLSID *
	__in PVOID pEventSink, // IUnknown *
	__in_opt LPCWSTR pszMIMETypeParam
) {
	HRESULT ret = Old_DecodeImageEx(pStream, pMap, pEventSink, pszMIMETypeParam);
	LOQ_hresult("misc", "");
	return ret;
}

HOOKDEF(HRESULT, WINAPI, DecodeImage,
	__in PVOID pStream, // IStream *
	__in PVOID pMap, // IMapMIMEToCLSID *
	__in PVOID pEventSink // IUnknown *
) {
	HRESULT ret = Old_DecodeImage(pStream, pMap, pEventSink);
	LOQ_hresult("misc", "");
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, LsaOpenPolicy,
	PLSA_UNICODE_STRING SystemName,
	PVOID ObjectAttributes,
	ACCESS_MASK DesiredAccess,
	PVOID PolicyHandle
) {
	NTSTATUS ret = Old_LsaOpenPolicy(SystemName, ObjectAttributes, DesiredAccess, PolicyHandle);
	LOQ_ntstatus("misc", "");
	return ret;
}

HOOKDEF(DWORD, WINAPI, WNetGetProviderNameW,
	__in DWORD dwNetType,
	__out LPWSTR lpProviderName,
	__inout LPDWORD lpBufferSize
) {
	DWORD ret;
	WCHAR *tmp = calloc(1, (*lpBufferSize + 1) * sizeof(wchar_t));

	if (tmp == NULL)
		return Old_WNetGetProviderNameW(dwNetType, lpProviderName, lpBufferSize);

	ret = Old_WNetGetProviderNameW(dwNetType, tmp, lpBufferSize);

	LOQ_zero("misc", "iu", "NetType", dwNetType, "ProviderName", ret == NO_ERROR ? tmp : L"");

	// WNNC_NET_RDR2SAMPLE, used for vbox detection
	if (!g_config.no_stealth && ret && dwNetType == 0x250000) {
		lasterror_t lasterrors;

		ret = ERROR_NO_NETWORK;
		lasterrors.Win32Error = ERROR_NO_NETWORK;
		lasterrors.NtstatusError = STATUS_ENTRYPOINT_NOT_FOUND;
		lasterrors.Eflags = 0;
	}
	else if (ret == NO_ERROR && lpProviderName) {
		wcscpy(lpProviderName, tmp);
	}

	free(tmp);

	return ret;
}

HOOKDEF(DWORD, WINAPI, RasValidateEntryNameW,
	_In_ LPCWSTR lpszPhonebook,
	_In_ LPCWSTR lpszEntry
) {
	DWORD ret = Old_RasValidateEntryNameW(lpszPhonebook, lpszEntry);
	LOQ_zero("misc", "uu", "Phonebook", lpszPhonebook, "Entry", lpszEntry);
	return ret;
}

HOOKDEF(DWORD, WINAPI, RasConnectionNotificationW,
	_In_ PVOID hrasconn,
	_In_ HANDLE   hEvent,
	_In_ DWORD	dwFlags
) {
	DWORD ret = Old_RasConnectionNotificationW(hrasconn, hEvent, dwFlags);
	LOQ_zero("misc", "");
	return ret;
}

HOOKDEF(BOOL, WINAPI, SystemTimeToTzSpecificLocalTime,
	_In_opt_ LPTIME_ZONE_INFORMATION lpTimeZone,
	_In_	 LPSYSTEMTIME			lpUniversalTime,
	_Out_	LPSYSTEMTIME			lpLocalTime
) {
	BOOL ret = SystemTimeToTzSpecificLocalTime(lpTimeZone, lpUniversalTime, lpLocalTime);
	LOQ_bool("misc", "");
	return ret;
}

HOOKDEF(HRESULT, WINAPI, CLSIDFromProgID,
	_In_ LPCOLESTR lpszProgID,
	_Out_ LPCLSID lpclsid
) {
	HRESULT ret = CLSIDFromProgID(lpszProgID, lpclsid);
	LOQ_hresult("misc", "u", "ProgID", lpszProgID);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetCurrentHwProfileW,
	_Out_ LPHW_PROFILE_INFO lpHwProfileInfo
) {
	BOOL ret = Old_GetCurrentHwProfileW(lpHwProfileInfo);
	LOQ_bool("misc", "uu", "ProfileGUID", lpHwProfileInfo->szHwProfileGuid, "ProfileName", lpHwProfileInfo->szHwProfileName);
	return ret;
}

HOOKDEF(BOOL, WINAPI, IsUserAdmin,
	void
) {
	BOOL ret = Old_IsUserAdmin();
	LOQ_bool("misc", "");
	return ret;
}

HOOKDEF(void, WINAPI, GlobalMemoryStatus,
	_Out_ LPMEMORYSTATUS lpBuffer
) {
	BOOL ret = TRUE;
	Old_GlobalMemoryStatus(lpBuffer);
	if (!g_config.no_stealth && lpBuffer->dwTotalPhys < 0x80000000)
		lpBuffer->dwTotalPhys = (SIZE_T)0x200000000;
	LOQ_void("misc", "ii", "MemoryLoad", lpBuffer->dwMemoryLoad, "TotalPhysicalMB", lpBuffer->dwTotalPhys / (1024 * 1024));
}

HOOKDEF(BOOL, WINAPI, GlobalMemoryStatusEx,
	_Out_ LPMEMORYSTATUSEX lpBuffer
) {
	BOOL ret = Old_GlobalMemoryStatusEx(lpBuffer);
	if (ret && !g_config.no_stealth && lpBuffer->ullTotalPhys < 0x80000000)
		lpBuffer->ullTotalPhys = 0x200000000;
	LOQ_void("misc", "ii", "MemoryLoad", lpBuffer->dwMemoryLoad, "TotalPhysicalMB", lpBuffer->ullTotalPhys / (1024 * 1024));
	return ret;
}

HOOKDEF(BOOL, WINAPI, SystemParametersInfoA,
	_In_	UINT  uiAction,
	_In_	UINT  uiParam,
	_Inout_ PVOID pvParam,
	_In_	UINT  fWinIni
) {
	BOOL ret = Old_SystemParametersInfoA(uiAction, uiParam, pvParam, fWinIni);
	if (ret && (uiAction == SPI_SETDESKWALLPAPER || uiAction == SPI_GETDESKWALLPAPER))
		LOQ_bool("misc", "hhs", "Action", uiAction, "uiParam", uiParam, "pvParam", pvParam);
	else
		LOQ_bool("misc", "hh", "Action", uiAction, "uiParam", uiParam);

	return ret;
}

HOOKDEF(BOOL, WINAPI, SystemParametersInfoW,
	_In_	UINT  uiAction,
	_In_	UINT  uiParam,
	_Inout_ PVOID pvParam,
	_In_	UINT  fWinIni
) {
	BOOL ret = Old_SystemParametersInfoW(uiAction, uiParam, pvParam, fWinIni);
	if (ret && (uiAction == SPI_SETDESKWALLPAPER || uiAction == SPI_GETDESKWALLPAPER))
		LOQ_bool("misc", "hhu", "Action", uiAction, "uiParam", uiParam, "pvParam", pvParam);
	else
		LOQ_bool("misc", "hh", "Action", uiAction, "uiParam", uiParam);

	return ret;
}

HOOKDEF(HRESULT, WINAPI, PStoreCreateInstance,
	_Out_ PVOID **ppProvider,
	_In_  VOID *pProviderID,
	_In_  VOID *pReserved,
	_In_  DWORD dwFlags
) {
	HRESULT ret = Old_PStoreCreateInstance(ppProvider, pProviderID, pReserved, dwFlags);
	LOQ_hresult("misc", "");
	return ret;
}

HOOKDEF(void, WINAPIV, memcpy,
   void *dest,
   const void *src,
   size_t count
)
{
	Old_memcpy(dest, src, count);

	if ((g_config.plugx || CompressedPE) && !PlugXConfigDumped &&
	(
		count == 0xae4  ||	// 2788
		count == 0xbe4  ||	// 3044
		count == 0x150c ||	// 5388
		count == 0x1510 ||	// 5392
		count == 0x1516 ||	// 5398
		count == 0x170c ||	// 5900
		count == 0x1b18 ||	// 6936
		count == 0x1d18 ||	// 7448
		count == 0x2540 ||	// 9536
		count == 0x254c ||	// 9668
		count == 0x2d58 ||	// 11608
		count == 0x36a4 ||	// 13988
		count == 0x4ea4		// 20132
		//count > 0xa00 &&	//fuzzy matching (2560)
		//count < 0x5000	//fuzzy matching (20480)
	))
	{
		DebugOutput("PlugX config detected (size 0x%d), dumping.\n", count);
		CapeMetaData->TypeString = "PlugX Config";
		DumpMemoryRaw((BYTE*)src, count);
		PlugXConfigDumped = TRUE;
	}

	return;
}

HOOKDEF(void, WINAPIV, srand,
	unsigned int seed
)
{
	int ret = 0;	// needed for LOQ_void

	Old_srand(seed);

	LOQ_void("misc", "h", "seed", seed);
}

HOOKDEF(LPSTR, WINAPI, lstrcpynA,
  _Out_ LPSTR   lpString1,
  _In_  LPSTR   lpString2,
  _In_  int	 iMaxLength
)
{
	LPSTR ret;

	ret = Old_lstrcpynA(lpString1, lpString2, iMaxLength);

	LOQ_nonzero("misc", "u", "String", lpString1);

	return ret;
}

HOOKDEF(int, WINAPI, lstrcmpiA,
  _In_  LPCSTR   lpString1,
  _In_  LPCSTR   lpString2
)
{
	int ret;

	ret = Old_lstrcmpiA(lpString1, lpString2);

	LOQ_nonzero("misc", "ss", "String1", lpString1, "String2", lpString2);

	return ret;
}

HOOKDEF(HRSRC, WINAPI, FindResourceExA,
	HMODULE hModule,
	LPCSTR lpType,
	LPCSTR lpName,
	WORD wLanguage
)
{
	HRSRC ret = Old_FindResourceExA(hModule, lpType, lpName, wLanguage);

	char type_id[8];
	if (IS_INTRESOURCE(lpType)) {
		snprintf(type_id, sizeof type_id, "#%hu", (WORD)lpType);
		lpType = type_id;
	}

	char name_id[8];
	if (IS_INTRESOURCE(lpName)) {
		snprintf(name_id, sizeof name_id, "#%hu", (WORD)lpName);
		lpName = name_id;
	}

	LOQ_handle("misc", "pssh", "Module", hModule, "Type", lpType, "Name", lpName, "Language", wLanguage);

	return ret;
}

HOOKDEF(HRSRC, WINAPI, FindResourceExW,
	HMODULE hModule,
	LPCWSTR lpType,
	LPCWSTR lpName,
	WORD wLanguage
)
{
	HRSRC ret = Old_FindResourceExW(hModule, lpType, lpName, wLanguage);

	wchar_t type_id[8];
	if (IS_INTRESOURCE(lpType)) {
		swprintf_s(type_id, sizeof(type_id), L"#%hu", (WORD)lpType);
		lpType = type_id;
	}

	wchar_t name_id[8];
	if (IS_INTRESOURCE(lpName)) {
		swprintf_s(name_id, sizeof(name_id), L"#%hu", (WORD)lpName);
		lpName = name_id;
	}

	LOQ_handle("misc", "puuh", "Module", hModule, "Type", lpType, "Name", lpName, "Language", wLanguage);

	return ret;
}

HOOKDEF(HGLOBAL, WINAPI, LoadResource,
  _In_opt_ HMODULE hModule,
  _In_	 HRSRC   hResInfo
)
{
	HGLOBAL ret = Old_LoadResource(hModule, hResInfo);

	LOQ_handle("misc", "pp", "Module", hModule, "ResourceInfo", hResInfo);

	return ret;
}

HOOKDEF(LPVOID, WINAPI, LockResource,
  _In_ HGLOBAL hResData
)
{
	LPVOID ret = Old_LockResource(hResData);

	LOQ_nonnull("misc", "p", "ResourceData", hResData);

	return ret;
}

HOOKDEF(DWORD, WINAPI, SizeofResource,
	_In_opt_ HMODULE hModule,
	_In_	 HRSRC   hResInfo
)
{
	DWORD ret = Old_SizeofResource(hModule, hResInfo);

	LOQ_nonzero("misc", "pp", "ModuleHandle", hModule, "ResourceInfo", hResInfo);

	return ret;
}

HOOKDEF(BOOL, WINAPI, EnumResourceTypesExA,
	_In_opt_ HMODULE		 hModule,
	_In_	 ENUMRESTYPEPROC lpEnumFunc,
	_In_	 LONG_PTR		lParam,
	_In_	 DWORD		   dwFlags,
	_In_	 LANGID		  LangId
) {
	BOOL ret = TRUE;
	LOQ_bool("misc", "ppphh",
		"ModuleHandle", hModule,
		"EnumFunc", lpEnumFunc,
		"Parameter", lParam,
		"Flags", dwFlags,
		"LangId", LangId
	);
	return Old_EnumResourceTypesExA(hModule, lpEnumFunc, lParam, dwFlags, LangId);;
}

HOOKDEF(BOOL, WINAPI, EnumResourceTypesExW,
	_In_opt_ HMODULE		 hModule,
	_In_	 ENUMRESTYPEPROC lpEnumFunc,
	_In_	 LONG_PTR		lParam,
	_In_	 DWORD		   dwFlags,
	_In_	 LANGID		  LangId
) {
	BOOL ret = TRUE;
	LOQ_bool("misc", "ppphh",
		"ModuleHandle", hModule,
		"EnumFunc", lpEnumFunc,
		"Parameter", lParam,
		"Flags", dwFlags,
		"LangId", LangId
	);
	return Old_EnumResourceTypesExW(hModule, lpEnumFunc, lParam, dwFlags, LangId);;
}

HOOKDEF(BOOL, WINAPI, EnumCalendarInfoA,
	CALINFO_ENUMPROCA lpCalInfoEnumProc,
	LCID			  Locale,
	CALID			 Calendar,
	CALTYPE		   CalType
) {
	BOOL ret = TRUE;
	LOQ_bool("misc", "phhh",
		"CalInfoEnumProc", lpCalInfoEnumProc,
		"Locale", Locale,
		"Calendar", Calendar,
		"CalType", CalType
	);
	return Old_EnumCalendarInfoA(lpCalInfoEnumProc, Locale, Calendar, CalType);
}

HOOKDEF(BOOL, WINAPI, EnumCalendarInfoW,
	CALINFO_ENUMPROCA lpCalInfoEnumProc,
	LCID			  Locale,
	CALID			 Calendar,
	CALTYPE		   CalType
) {
	BOOL ret = TRUE;
	LOQ_bool("misc", "phhh",
		"CalInfoEnumProc", lpCalInfoEnumProc,
		"Locale", Locale,
		"Calendar", Calendar,
		"CalType", CalType
	);
	return Old_EnumCalendarInfoW(lpCalInfoEnumProc, Locale, Calendar, CalType);
}

HOOKDEF(BOOL, WINAPI, EnumTimeFormatsA,
	TIMEFMT_ENUMPROCA lpTimeFmtEnumProc,
	LCID			  Locale,
	DWORD			 dwFlags
) {
	BOOL ret = TRUE;
	LOQ_bool("misc", "phh",
		"TimeFmtEnumProc", lpTimeFmtEnumProc,
		"Locale", Locale,
		"Flags", dwFlags
	);
	return Old_EnumTimeFormatsA(lpTimeFmtEnumProc, Locale, dwFlags);
}

HOOKDEF(BOOL, WINAPI, EnumTimeFormatsW,
	TIMEFMT_ENUMPROCA lpTimeFmtEnumProc,
	LCID			  Locale,
	DWORD			 dwFlags
) {
	BOOL ret = TRUE;
	LOQ_bool("misc", "phh",
		"TimeFmtEnumProc", lpTimeFmtEnumProc,
		"Locale", Locale,
		"Flags", dwFlags
	);
	return Old_EnumTimeFormatsW(lpTimeFmtEnumProc, Locale, dwFlags);
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateTransaction,
	PHANDLE			TransactionHandle,
	ACCESS_MASK		DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	LPGUID			 Uow,
	HANDLE			 TmHandle,
	ULONG			  CreateOptions,
	ULONG			  IsolationLevel,
	ULONG			  IsolationFlags,
	PLARGE_INTEGER	 Timeout,
	PUNICODE_STRING	Description
) {
	NTSTATUS ret = Old_NtCreateTransaction(TransactionHandle, DesiredAccess, ObjectAttributes, Uow, TmHandle, CreateOptions, IsolationLevel, IsolationFlags, Timeout, Description);
	LOQ_ntstatus("misc", "PhObphhhio",
		"TransactionHandle", TransactionHandle,
		"DesiredAccess", DesiredAccess,
		"ObjectAttributes", ObjectAttributes,
		"UnitOfWork", sizeof (GUID), Uow,
		"TmHandle", TmHandle,
		"CreateOptions", CreateOptions,
		"IsolationLevel", IsolationLevel,
		"IsolationFlags", IsolationFlags,
		"Timeout", Timeout,
		"Description", Description
	);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenTransaction,
	PHANDLE			TransactionHandle,
	ACCESS_MASK		DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	LPGUID			 Uow,
	HANDLE			 TmHandle
) {
	NTSTATUS ret = Old_NtOpenTransaction(TransactionHandle, DesiredAccess, ObjectAttributes, Uow, TmHandle);
	LOQ_ntstatus("misc", "PhObp",
		"TransactionHandle", TransactionHandle,
		"DesiredAccess", DesiredAccess,
		"ObjectAttributes", ObjectAttributes,
		"UnitOfWork", sizeof (GUID), Uow,
		"TmHandle", TmHandle
	);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtRollbackTransaction,
	HANDLE  TransactionHandle,
	BOOLEAN Wait
) {
	NTSTATUS ret = Old_NtRollbackTransaction(TransactionHandle, Wait);
	LOQ_ntstatus("misc", "pi", "TransactionHandle", TransactionHandle, "Wait", Wait);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCommitTransaction,
	HANDLE  TransactionHandle,
	BOOLEAN Wait
) {
	NTSTATUS ret = Old_NtCommitTransaction(TransactionHandle, Wait);
	LOQ_ntstatus("misc", "pi", "TransactionHandle", TransactionHandle, "Wait", Wait);
	return ret;
}

HOOKDEF(BOOL, WINAPI, RtlSetCurrentTransaction,
	_In_ HANDLE	 TransactionHandle
) {
	BOOL ret = Old_RtlSetCurrentTransaction(TransactionHandle);
	LOQ_bool("misc", "p", "TransactionHandle", TransactionHandle);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, OleConvertOLESTREAMToIStorage,
	IN LPOLESTREAM		  lpolestream,
	OUT LPSTORAGE		   pstg,
	IN const DVTARGETDEVICE *ptd
) {
	void *buf = NULL; uintptr_t len = 0;

	HRESULT ret = Old_OleConvertOLESTREAMToIStorage(lpolestream, pstg, ptd);

#ifndef _WIN64
	if (lpolestream != NULL) {
		buf = (PVOID)*((uint8_t *) lpolestream + 8);
		len = *((uint8_t *) lpolestream + 12);
	}
#endif

	LOQ_bool("misc", "b", "OLE2", len, buf);
	return ret;
}

HOOKDEF(HANDLE, WINAPI, HeapCreate,
  _In_ DWORD  flOptions,
  _In_ SIZE_T dwInitialSize,
  _In_ SIZE_T dwMaximumSize
)
{
	HANDLE ret;
	ret = Old_HeapCreate(flOptions, dwInitialSize, dwMaximumSize);
	LOQ_nonnull("misc", "ihh", "Options", flOptions, "InitialSize", dwInitialSize, "MaximumSize", dwMaximumSize);
	return ret;
}

HOOKDEF(BOOL, WINAPI, FlsAlloc,
	_In_ PFLS_CALLBACK_FUNCTION lpCallback
) {
	BOOL ret = Old_FlsAlloc(lpCallback);
	LOQ_bool("misc", "p", "Callback", lpCallback);
	return ret;
}

HOOKDEF(BOOL, WINAPI, FlsSetValue,
	_In_	 DWORD dwFlsIndex,
	_In_opt_ PVOID lpFlsData
) {
	BOOL ret = Old_FlsSetValue(dwFlsIndex, lpFlsData);
	LOQ_bool("misc", "ip", "Index", dwFlsIndex, "Data", lpFlsData);
	return ret;
}


HOOKDEF(PVOID, WINAPI, FlsGetValue,
	_In_	 DWORD dwFlsIndex
) {
	PVOID ret = Old_FlsGetValue(dwFlsIndex);
	LOQ_nonnull("misc", "ip", "Index", dwFlsIndex, "ReturnValue", ret);
	return ret;
}

HOOKDEF(BOOL, WINAPI, FlsFree,
	_In_	 DWORD dwFlsIndex
) {
	BOOL ret = Old_FlsFree(dwFlsIndex);
	LOQ_bool("misc", "ip", "Index", dwFlsIndex);
	return ret;
}


HOOKDEF(PVOID, WINAPI, LocalAlloc,
	_In_ UINT uFlags,
	_In_ SIZE_T uBytes)
{
	PVOID ret = Old_LocalAlloc(uFlags, uBytes);
	LOQ_nonnull("misc", "ii", "Flags", uFlags, "Bytes", uBytes);
	return ret;
}

HOOKDEF(VOID, WINAPI, LocalFree,
	HLOCAL hMem)
{
	int ret = 0;
	Old_LocalFree(hMem);
	LOQ_void("misc", "p", "SourceBuffer", hMem);
}

#define MSGFLT_ADD 1
#define MSGFLT_REMOVE 2
HOOKDEF(BOOL, WINAPI, ChangeWindowMessageFilter,
	UINT  message,
	DWORD dwFlag
)
{
	BOOL ret;
	if (dwFlag != MSGFLT_REMOVE && dwFlag != MSGFLT_ADD) {
		ret = FALSE;
		SetLastError(ERROR_INVALID_PARAMETER);
	}
	else
		ret = Old_ChangeWindowMessageFilter(message, dwFlag);
	LOQ_bool("misc", "ii", "message", message, "dwFlag", dwFlag);
	return ret;
}

HOOKDEF(LPWSTR, WINAPI, rtcEnvironBstr,
	struct envstruct *es
)
{
	LPWSTR ret = Old_rtcEnvironBstr(es);
	LOQ_bool("misc", "uu", "EnvVar", es->envstr, "EnvStr", ret);
	if (ret && !wcsicmp(es->envstr, L"userdomain"))
		// replace first char so it differs from computername
		*ret = '#';
	return ret;
}

HOOKDEF(HKL, WINAPI, GetKeyboardLayout,
	DWORD idThread
)
{
	HKL ret = Old_GetKeyboardLayout(idThread);
	LOQ_nonnull("misc", "p", "KeyboardLayout", (DWORD_PTR)ret & 0xFFFF);
	return ret;
}

HOOKDEF(VOID, WINAPI, RtlMoveMemory,
	_Out_	   VOID UNALIGNED *Destination,
	_In_  const VOID UNALIGNED *Source,
	_In_		SIZE_T		 Length
)
{
	int ret = 0;
	Old_RtlMoveMemory(Destination, Source, Length);
	LOQ_void("misc", "bppi", "Destination", Length, Destination, "Source", Source, "destination", Destination, "Length", Length);
	return;
}

HOOKDEF(void, WINAPI, OutputDebugStringA,
	LPCSTR lpOutputString
)
{
	int ret = 0;
	Old_OutputDebugStringA(lpOutputString);
	LOQ_void("misc", "s", "OutputString", lpOutputString);
	return;
}

HOOKDEF(void, WINAPI, OutputDebugStringW,
	LPCWSTR lpOutputString
)
{
	int ret = 0;
	Old_OutputDebugStringW(lpOutputString);
	LOQ_void("misc", "u", "OutputString", lpOutputString);
	return;
}

HOOKDEF(void, WINAPI, SysFreeString,
	BSTR bstrString
)
{
	int ret = 0;
	if (SysStringLen(bstrString) > 3)
		LOQ_void("misc", "u", "String", bstrString);
	Old_SysFreeString(bstrString);
	return;
}

HOOKDEF_NOTAIL(WINAPI, ScriptIsComplex,
	const WCHAR *pwcInChars,
	int cInChars,
	DWORD dwFlags
)
{
	DWORD ret = 0;
	if (cInChars > 1)
		LOQ_void("misc", "uii", "pwcInChars", pwcInChars, "cInChars", cInChars, "dwFlags", dwFlags);
	return ret;
}

HOOKDEF(int, WINAPI, StrCmpNICW,
	_In_ LPCWSTR pszStr1,
	_In_ LPCWSTR pszStr2,
	_In_ int nChar
)
{
	int ret;
	ret = Old_StrCmpNICW(pszStr1, pszStr2, nChar);
	LOQ_nonzero("misc", "uui", "String1", pszStr1, "String2", pszStr2, "nChar", nChar);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, VarBstrCat,
	_In_ BSTR bstrLeft,
	_In_ BSTR bstrRight,
	_In_ LPBSTR pbstrResult
)
{
	HRESULT ret = Old_VarBstrCat(bstrLeft, bstrRight, pbstrResult);
	LOQ_void("misc", "uuu", "bstrLeft", bstrLeft, "bstrRight", bstrRight, "pbstrResult", *pbstrResult);
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, rtcCreateObject2,
	WORD *arg1,
	LPCOLESTR arg2,
	wchar_t arg3
)
{
	DWORD ret = 0;
	LOQ_void("misc", "u", "ProgID", arg2);
	return ret;
}

HOOKDEF(BOOL, WINAPI, RtlDosPathNameToNtPathName_U,
	_In_	   PCWSTR DosFileName,
	_Out_	  PUNICODE_STRING NtFileName,
	_Out_opt_  PWSTR* FilePath,
	_Out_opt_  VOID* DirectoryInfo
)
{
	BOOL ret = Old_RtlDosPathNameToNtPathName_U(DosFileName, NtFileName, FilePath, DirectoryInfo);
	LOQ_bool("misc", "u", "DosFileName", DosFileName);
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, DownloadFile,
	LPCSTR url,
	LPCSTR path,
	int flag
)
{
	DWORD ret = 0;
	LOQ_void("network", "ssi", "URL", url,"Path", path, "Flag",flag);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryLicenseValue,
	__in		PUNICODE_STRING Name,
	__in_opt	ULONG* Type,
	__in_opt	PVOID Buffer,
	__in		ULONG Length,
	__in		ULONG* DataLength
) {
	WCHAR VMDetection[] = L"Kernel-VMDetection-Private";
	NTSTATUS ret = Old_NtQueryLicenseValue(Name, Type, Buffer, Length, DataLength);
	if (NT_SUCCESS(ret) && Buffer && !wcsncmp(Name->Buffer, VMDetection, Name->Length))
		*(PBOOL)Buffer = FALSE;
	LOQ_ntstatus("system", "oP", "Name", Name, "Type", Type);
	return ret;
}

HOOKDEF(int, WINAPI, MultiByteToWideChar,
	__in		UINT	CodePage,
	__in		DWORD	dwFlags,
	__in		LPCCH	lpMultiByteStr,
	__in		int		cbMultiByte,
	__out_opt	LPWSTR	lpWideCharStr,
	__in		int		cchWideChar
) {
	DWORD ret = 0;
	if (CodePage == CP_ACP || CodePage == CP_UTF8)
		LOQ_zero("misc", "s", "String", lpMultiByteStr);
	return Old_MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
}

HOOKDEF(int, WINAPI, WideCharToMultiByte,
	__in		UINT	CodePage,
	__in		DWORD	dwFlags,
	__in		LPCWCH	lpWideCharStr,
	__in		int		cchWideChar,
	__out_opt	LPSTR	lpMultiByteStr,
	__in		int		cbMultiByte,
	__in_opt	LPCCH	lpDefaultChar,
	__out_opt	LPBOOL	lpUsedDefaultChar
) {
	DWORD ret = 0;
	if (CodePage == CP_ACP || CodePage == CP_UTF8)
		LOQ_zero("misc", "u", "String", lpWideCharStr);
	return Old_WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
}

HOOKDEF(LPSTR, WINAPI, GetCommandLineA,
	void
) {
	LPSTR ret = Old_GetCommandLineA();
	LOQ_nonnull("misc", "s", "CommandLine", ret);
	return ret;
}

HOOKDEF(LPWSTR, WINAPI, GetCommandLineW,
	void
) {
	LPWSTR ret = Old_GetCommandLineW();
	LOQ_nonnull("misc", "u", "CommandLine", ret);
	return ret;
}
