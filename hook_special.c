/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2015 Cuckoo Sandbox Developers, Optiv, Inc. (brad.spengler@optiv.com

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
#include "hook_sleep.h"
#include "misc.h"
#include "config.h"
#include "CAPE\CAPE.h"

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern int DoProcessDump(PVOID CallerBase);
extern ULONG_PTR base_of_dll_of_interest;
extern void CreateProcessHandler(LPWSTR lpApplicationName, LPWSTR lpCommandLine, LPPROCESS_INFORMATION lpProcessInformation);
extern void ProcessMessage(DWORD ProcessId, DWORD ThreadId);
extern void set_hooks();
extern void notify_successful_load(void);
extern BOOL ProcessDumped;

PVOID LastDllUnload;

static int wmi_sent = 0;
static int bits_sent = 0;
static int tasksched_sent = 0;
static int interop_sent = 0;

HOOKDEF_NOTAIL(WINAPI, LdrLoadDll,
	__in_opt	PWCHAR PathToFile,
	__in_opt	PULONG Flags,
	__in		PUNICODE_STRING ModuleFileName,
	__out	   PHANDLE ModuleHandle
) {

	//
	// In the event that loading this dll results in loading another dll as
	// well, then the unicode string (which is located in the TEB) will be
	// overwritten, therefore we make a copy of it for our own use.
	//
	lasterror_t lasterror;
	NTSTATUS ret = 0;

	COPY_UNICODE_STRING(library, ModuleFileName);

	get_lasterrors(&lasterror);

	if (!g_config.tlsdump && !called_by_hook() && wcsncmp(library.Buffer, g_config.dllpath, wcslen(g_config.dllpath))) {
		if (g_config.file_of_interest && g_config.suspend_logging) {
			wchar_t *absolutename = malloc(32768 * sizeof(wchar_t));
			ensure_absolute_unicode_path(absolutename, library.Buffer);
			if (!wcsicmp(absolutename, g_config.file_of_interest))
				g_config.suspend_logging = FALSE;
			free(absolutename);
		}

		if (!wcsncmp(library.Buffer, L"\\??\\", 4) || library.Buffer[1] == L':')
			LOQ_ntstatus("system", "HFP", "Flags", Flags, "FileName", library.Buffer,
			"BaseAddress", ModuleHandle);
		else
			LOQ_ntstatus("system", "HoP", "Flags", Flags, "FileName", &library,
			"BaseAddress", ModuleHandle);

		if (library.Buffer[1] == L':' && (!wcsnicmp(library.Buffer, L"c:\\windows\\system32\\", 20) ||
										  !wcsnicmp(library.Buffer, L"c:\\windows\\syswow64\\", 20) ||
										  !wcsnicmp(library.Buffer, L"c:\\windows\\sysnative\\", 21))) {
			ret = 1;
		}
		else if (library.Buffer[1] != L':') {
			WCHAR newlib[MAX_PATH] = { 0 };
			DWORD concatlen = MIN((DWORD)wcslen(library.Buffer), MAX_PATH - 21);
			wcscpy(newlib, L"c:\\windows\\system32\\");
			wcsncat(newlib, library.Buffer, concatlen);
			if (GetFileAttributesW(newlib) != INVALID_FILE_ATTRIBUTES)
				ret = 1;
		}

	}
	else if (!wcsncmp(library.Buffer, g_config.dllpath, wcslen(g_config.dllpath))) {
		// Don't log attempts to load monitor twice
		if (g_config.tlsdump) {
			// lsass injected a second time - switch to 'normal' mode
			g_config.tlsdump = 0;
			if (read_config()) {
				log_init(g_config.debug || g_config.standalone);
				set_hooks();
				notify_successful_load();
			}
		}
		ret = 1;
	}

	set_lasterrors(&lasterror);

	return ret;
}

HOOKDEF_ALT(NTSTATUS, WINAPI, LdrLoadDll,
	__in_opt	PWCHAR PathToFile,
	__in_opt	PULONG Flags,
	__in		PUNICODE_STRING ModuleFileName,
	__out	   PHANDLE ModuleHandle
) {
	NTSTATUS ret;

	COPY_UNICODE_STRING(library, ModuleFileName);

	hook_info_t saved_hookinfo;

	memcpy(&saved_hookinfo, hook_info(), sizeof(saved_hookinfo));
	ret = Old_LdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle);
	memcpy(hook_info(), &saved_hookinfo, sizeof(saved_hookinfo));

	disable_tail_call_optimization();
	return ret;
}

extern void revalidate_all_hooks(void);

HOOKDEF_NOTAIL(WINAPI, LdrUnloadDll,
	PVOID DllImageBase
) {
	if (DllImageBase && DllImageBase == (PVOID)base_of_dll_of_interest && g_config.procdump && !ProcessDumped)
	{
		DebugOutput("Target DLL unloading from 0x%p, dumping\n", DllImageBase);
		CapeMetaData->DumpType = PROCDUMP;
		if (g_config.import_reconstruction)
			DumpImageInCurrentProcessFixImports(DllImageBase, 0);
		else
			DumpImageInCurrentProcess(DllImageBase);
	}

	if (DllImageBase && DllImageBase != LastDllUnload)
	{
		DebugOutput("DLL unloaded from 0x%p.\n", DllImageBase);
		LastDllUnload = DllImageBase;
	}

	return 0;
}

HOOKDEF(BOOL, WINAPI, CreateProcessInternalW,
	__in_opt	LPVOID lpUnknown1,
	__in_opt	LPWSTR lpApplicationName,
	__inout_opt LPWSTR lpCommandLine,
	__in_opt	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	__in_opt	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	__in		BOOL bInheritHandles,
	__in		DWORD dwCreationFlags,
	__in_opt	LPVOID lpEnvironment,
	__in_opt	LPWSTR lpCurrentDirectory,
	__in		LPSTARTUPINFOW lpStartupInfo,
	__out	   LPPROCESS_INFORMATION lpProcessInformation,
	__in_opt	LPVOID lpUnknown2
) {
	BOOL ret;
	hook_info_t saved_hookinfo;

	memcpy(&saved_hookinfo, hook_info(), sizeof(saved_hookinfo));
	ret = Old_CreateProcessInternalW(lpUnknown1, lpApplicationName,
		lpCommandLine, lpProcessAttributes, lpThreadAttributes,
		bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment,
		lpCurrentDirectory, lpStartupInfo, lpProcessInformation, lpUnknown2);
	memcpy(hook_info(), &saved_hookinfo, sizeof(saved_hookinfo));

	if (ret != FALSE) {
		CreateProcessHandler(lpApplicationName, lpCommandLine, lpProcessInformation);
		ProcessMessage(lpProcessInformation->dwProcessId, lpProcessInformation->dwThreadId);

		// if the CREATE_SUSPENDED flag was not set, then we have to resume the main thread ourself
		if ((dwCreationFlags & CREATE_SUSPENDED) == 0) {
			ResumeThread(lpProcessInformation->hThread);
		}

		disable_sleep_skip();
	}

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

static _CoTaskMemFree pCoTaskMemFree;
static _ProgIDFromCLSID pProgIDFromCLSID;

HOOKDEF(HRESULT, WINAPI, CoCreateInstance,
	__in	REFCLSID rclsid,
	__in	LPUNKNOWN pUnkOuter,
	__in	DWORD dwClsContext,
	__in	REFIID riid,
	__out	LPVOID *ppv
) {
	IID id1;
	IID id2;
	char idbuf1[40];
	char idbuf2[40];
	lasterror_t lasterror;
	HRESULT ret;
	hook_info_t saved_hookinfo;
	OLECHAR *resolv = NULL;

	get_lasterrors(&lasterror);

	if (!pCoTaskMemFree)
		pCoTaskMemFree = (_CoTaskMemFree)GetProcAddress(GetModuleHandleA("ole32"), "CoTaskMemFree");
	if (!pProgIDFromCLSID)
		pProgIDFromCLSID = (_ProgIDFromCLSID)GetProcAddress(GetModuleHandleA("ole32"), "ProgIDFromCLSID");

	if (is_valid_address_range((ULONG_PTR)rclsid, 16))
			memcpy(&id1, rclsid, sizeof(id1));
		if (is_valid_address_range((ULONG_PTR)riid, 16))
			memcpy(&id2, riid, sizeof(id2));
	sprintf(idbuf1, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", id1.Data1, id1.Data2, id1.Data3,
		id1.Data4[0], id1.Data4[1], id1.Data4[2], id1.Data4[3], id1.Data4[4], id1.Data4[5], id1.Data4[6], id1.Data4[7]);
	sprintf(idbuf2, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", id2.Data1, id2.Data2, id2.Data3,
		id2.Data4[0], id2.Data4[1], id2.Data4[2], id2.Data4[3], id2.Data4[4], id2.Data4[5], id2.Data4[6], id2.Data4[7]);

#ifndef _WIN64
	if (!called_by_hook()) {
		if (!strcmp(idbuf1, "4590F811-1D3A-11D0-891F-00AA004B2E24") || !strcmp(idbuf1, "4590F812-1D3A-11D0-891F-00AA004B2E24") ||
			!strcmp(idbuf1, "172BDDF8-CEEA-11D1-8B05-00600806D9B6") || !strcmp(idbuf1, "CF4CC405-E2C5-4DDD-B3CE-5E7582D8C9FA")) {
			if (!wmi_sent) {
				wmi_sent = 1;
				pipe("WMI:");
			}
		}
		if (!strcmp(idbuf1, "4991D34B-80A1-4291-83B6-3328366B9097") || !strcmp(idbuf1, "5CE34C0D-0DC9-4C1F-897C-100000000003"))
			if (!bits_sent) {
				bits_sent = 1;
				pipe("BITS:");
			}
		if (!strcmp(idbuf1, "0F87369F-A4E5-4CFC-BD3E-73E6154572DD") || !strcmp(idbuf1, "0F87369F-A4E5-4CFC-BD3E-5529CE8784B0"))
			if (!tasksched_sent) {
				tasksched_sent = 1;
				pipe("TASKSCHED:");
			}
		if (!strcmp(idbuf1, "000209FF-0000-0000-C000-000000000046") || !strcmp(idbuf1, "00024500-0000-0000-C000-000000000046") || !strcmp(idbuf1, "91493441-5A91-11CF-8700-00AA0060263B") ||
			!strcmp(idbuf1, "000246FF-0000-0000-C000-000000000046") || !strcmp(idbuf1, "0002CE02-0000-0000-C000-000000000046") || !strcmp(idbuf1, "75DFF2B7-6936-4C06-A8BB-676A7B00B24B") ||
			!strcmp(idbuf1, "C08AFD90-F2A1-11D1-8455-00A0C91F3880") || !strcmp(idbuf1, "0006F03A-0000-0000-C000-000000000046") || !strcmp(idbuf1, "0002DF01-0000-0000-C000-000000000046") ||
			!strcmp(idbuf1, "000C101C-0000-0000-C000-000000000046") || !strcmp(idbuf1, "00000323-0000-0000-C000-000000000046"))
			if (!interop_sent) {
				interop_sent = 1;
				pipe("INTEROP:");
			}
	}
#endif

	disable_sleep_skip();

	set_lasterrors(&lasterror);

	memcpy(&saved_hookinfo, hook_info(), sizeof(saved_hookinfo));
	ret = Old_CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);
	memcpy(hook_info(), &saved_hookinfo, sizeof(saved_hookinfo));

	get_lasterrors(&lasterror);

	pProgIDFromCLSID(&id1, &resolv);

	LOQ_hresult("com", "shsu", "rclsid", idbuf1, "ClsContext", dwClsContext, "riid", idbuf2, "ProgID", resolv);

	if (resolv)
		pCoTaskMemFree(resolv);

	set_lasterrors(&lasterror);

	return ret;
}

HOOKDEF(HRESULT, WINAPI, CoCreateInstanceEx,
	__in	REFCLSID rclsid,
	__in	LPUNKNOWN pUnkOuter,
	__in	DWORD dwClsContext,
	_In_	COSERVERINFO *pServerInfo,
	_In_	DWORD		dwCount,
	_Inout_ MULTI_QI	 *pResults
	) {
	IID id1;
	char idbuf1[40];
	lasterror_t lasterror;
	HRESULT ret;
	hook_info_t saved_hookinfo;
	OLECHAR *resolv = NULL;

	get_lasterrors(&lasterror);

	if (!pCoTaskMemFree)
		pCoTaskMemFree = (_CoTaskMemFree)GetProcAddress(GetModuleHandleA("ole32"), "CoTaskMemFree");
	if (!pProgIDFromCLSID)
		pProgIDFromCLSID = (_ProgIDFromCLSID)GetProcAddress(GetModuleHandleA("ole32"), "ProgIDFromCLSID");

	if (is_valid_address_range((ULONG_PTR)rclsid, 16))
			memcpy(&id1, rclsid, sizeof(id1));
	sprintf(idbuf1, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", id1.Data1, id1.Data2, id1.Data3,
		id1.Data4[0], id1.Data4[1], id1.Data4[2], id1.Data4[3], id1.Data4[4], id1.Data4[5], id1.Data4[6], id1.Data4[7]);

#ifndef _WIN64
	if (!called_by_hook()) {
		if (!strcmp(idbuf1, "4590F811-1D3A-11D0-891F-00AA004B2E24") || !strcmp(idbuf1, "4590F812-1D3A-11D0-891F-00AA004B2E24") ||
			!strcmp(idbuf1, "172BDDF8-CEEA-11D1-8B05-00600806D9B6") || !strcmp(idbuf1, "CF4CC405-E2C5-4DDD-B3CE-5E7582D8C9FA")) {
			if (!wmi_sent) {
				wmi_sent = 1;
				pipe("WMI:");
			}
		}
		if (!strcmp(idbuf1, "4991D34B-80A1-4291-83B6-3328366B9097") || !strcmp(idbuf1, "5CE34C0D-0DC9-4C1F-897C-100000000003"))
			if (!bits_sent) {
				bits_sent = 1;
				pipe("BITS:");
			}
		if (!strcmp(idbuf1, "0F87369F-A4E5-4CFC-BD3E-73E6154572DD") || !strcmp(idbuf1, "0F87369F-A4E5-4CFC-BD3E-5529CE8784B0"))
			if (!tasksched_sent) {
				tasksched_sent = 1;
				pipe("TASKSCHED:");
			}
		if (!strcmp(idbuf1, "000209FF-0000-0000-C000-000000000046") || !strcmp(idbuf1, "00024500-0000-0000-C000-000000000046") || !strcmp(idbuf1, "91493441-5A91-11CF-8700-00AA0060263B") ||
			!strcmp(idbuf1, "000246FF-0000-0000-C000-000000000046") || !strcmp(idbuf1, "0002CE02-0000-0000-C000-000000000046") || !strcmp(idbuf1, "75DFF2B7-6936-4C06-A8BB-676A7B00B24B") ||
			!strcmp(idbuf1, "C08AFD90-F2A1-11D1-8455-00A0C91F3880") || !strcmp(idbuf1, "0006F03A-0000-0000-C000-000000000046") || !strcmp(idbuf1, "0002DF01-0000-0000-C000-000000000046") ||
			!strcmp(idbuf1, "000C101C-0000-0000-C000-000000000046"))
			if (!interop_sent) {
				interop_sent = 1;
				pipe("INTEROP:");
			}
	}
#endif

	disable_sleep_skip();

	set_lasterrors(&lasterror);

	memcpy(&saved_hookinfo, hook_info(), sizeof(saved_hookinfo));
	ret = Old_CoCreateInstanceEx(rclsid, pUnkOuter, dwClsContext, pServerInfo, dwCount, pResults);
	memcpy(hook_info(), &saved_hookinfo, sizeof(saved_hookinfo));


	if (!called_by_hook()) {
		get_lasterrors(&lasterror);
		pProgIDFromCLSID(&id1, &resolv);

		LOQ_hresult("com", "shuu", "rclsid", idbuf1, "ClsContext", dwClsContext, "ServerName", pServerInfo ? pServerInfo->pwszName : NULL, "ProgID", resolv);

		if (resolv)
			pCoTaskMemFree(resolv);
		set_lasterrors(&lasterror);
	}

	return ret;
}

HOOKDEF(HRESULT, WINAPI, CoGetClassObject,
	_In_	 REFCLSID	 rclsid,
	_In_	 DWORD		dwClsContext,
	_In_opt_ COSERVERINFO *pServerInfo,
	_In_	 REFIID	   riid,
	_Out_	LPVOID	   *ppv
) {
	HRESULT ret;
	lasterror_t lasterror;
	IID id1;
	IID id2;
	char idbuf1[40];
	char idbuf2[40];
	hook_info_t saved_hookinfo;
	OLECHAR *resolv = NULL;

	get_lasterrors(&lasterror);

	if (!pCoTaskMemFree)
		pCoTaskMemFree = (_CoTaskMemFree)GetProcAddress(GetModuleHandleA("ole32"), "CoTaskMemFree");
	if (!pProgIDFromCLSID)
		pProgIDFromCLSID = (_ProgIDFromCLSID)GetProcAddress(GetModuleHandleA("ole32"), "ProgIDFromCLSID");

	if (is_valid_address_range((ULONG_PTR)rclsid, 16))
			memcpy(&id1, rclsid, sizeof(id1));
		if (is_valid_address_range((ULONG_PTR)riid, 16))
		memcpy(&id2, riid, sizeof(id2));
	sprintf(idbuf1, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", id1.Data1, id1.Data2, id1.Data3,
		id1.Data4[0], id1.Data4[1], id1.Data4[2], id1.Data4[3], id1.Data4[4], id1.Data4[5], id1.Data4[6], id1.Data4[7]);
	sprintf(idbuf2, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", id2.Data1, id2.Data2, id2.Data3,
		id2.Data4[0], id2.Data4[1], id2.Data4[2], id2.Data4[3], id2.Data4[4], id2.Data4[5], id2.Data4[6], id2.Data4[7]);

	set_lasterrors(&lasterror);

	memcpy(&saved_hookinfo, hook_info(), sizeof(saved_hookinfo));
	ret = Old_CoGetClassObject(rclsid, dwClsContext, pServerInfo, riid, ppv);
	memcpy(hook_info(), &saved_hookinfo, sizeof(saved_hookinfo));

	get_lasterrors(&lasterror);

	pProgIDFromCLSID(&id1, &resolv);

	LOQ_hresult("com", "shsu", "rclsid", idbuf1, "ClsContext", dwClsContext, "riid", idbuf2, "ProgID", resolv);

	if (resolv)
		pCoTaskMemFree(resolv);

	set_lasterrors(&lasterror);

	return ret;
}

HOOKDEF_NOTAIL(WINAPI, JsEval,
	PVOID Arg1,
	PVOID Arg2,
	PVOID Arg3,
	int Index,
	DWORD *scriptobj
) {
#ifndef _WIN64
	PWCHAR jsbuf;
	PUCHAR p;
#endif
	int ret = 0;

	/* TODO: 64-bit support*/
#ifdef _WIN64
	return ret;
#else

	p = (PUCHAR)scriptobj[4 * Index - 2];
	jsbuf = *(PWCHAR *)(p + 8);
	if (jsbuf)
		LOQ_ntstatus("browser", "u", "Javascript", jsbuf);

	return ret;
#endif
}

HOOKDEF(int, WINAPI, COleScript_ParseScriptText,
	PVOID Arg1,
	PWCHAR ScriptBuf,
	PVOID Arg3,
	PVOID Arg4,
	PVOID Arg5,
	PVOID Arg6,
	PVOID Arg7,
	PVOID Arg8,
	PVOID Arg9,
	PVOID Arg10
) {
	int ret = Old_COleScript_ParseScriptText(Arg1, ScriptBuf, Arg3, Arg4, Arg5, Arg6, Arg7, Arg8, Arg9, Arg10);
	LOQ_ntstatus("browser", "u", "Script", ScriptBuf);
	return ret;
}

HOOKDEF(PVOID, WINAPI, JsParseScript,
	const wchar_t *script,
	PVOID SourceContext,
	const wchar_t *sourceUrl,
	PVOID *result
) {
	PVOID ret = Old_JsParseScript(script, SourceContext, sourceUrl, result);

	LOQ_zero("browser", "uu", "Script", script, "Source", sourceUrl);

	return ret;
}

HOOKDEF_NOTAIL(WINAPI, JsRunScript,
	const wchar_t *script,
	PVOID SourceContext,
	const wchar_t *sourceUrl,
	PVOID *result
) {
	int ret = 0;

	LOQ_zero("browser", "uu", "Script", script, "Source", sourceUrl);
	return ret;
}

// based on code by Stephan Chenette and Moti Joseph of Websense, Inc. released under the GPLv3
// http://securitylabs.websense.com/content/Blogs/3198.aspx

HOOKDEF(int, WINAPI, CDocument_write,
	PVOID this,
	SAFEARRAY *psa
) {
	DWORD i;
	PWCHAR buf;
	int ret = Old_CDocument_write(this, psa);
	VARIANT *pvars = (VARIANT *)psa->pvData;
	unsigned int buflen = 0;
	unsigned int offset = 0;
	for (i = 0; i < psa->rgsabound[0].cElements; i++) {
		if (pvars[i].vt == VT_BSTR)
			buflen += (unsigned int)wcslen((const wchar_t *)pvars[i].pbstrVal) + 8;
	}
	buf = calloc(1, (buflen + 1) * sizeof(wchar_t));
	if (buf == NULL)
		return ret;

	for (i = 0; i < psa->rgsabound[0].cElements; i++) {
		if (pvars[i].vt == VT_BSTR) {
			wcscpy(buf + offset, (const wchar_t *)pvars[i].pbstrVal);
			offset += (unsigned int)wcslen((const wchar_t *)pvars[i].pbstrVal);
			wcscpy(buf + offset, L"\r\n||||\r\n");
			offset += 8;
		}
	}

	LOQ_ntstatus("browser", "u", "Buffer", buf);

	return ret;
}

HOOKDEF(HRESULT, WINAPI, IsValidURL,
	_In_       LPBC    pBC,
	_In_       LPCWSTR szURL,
	_Reserved_ DWORD   dwReserved
)
{
	HRESULT ret = Old_IsValidURL(pBC, szURL, dwReserved);
	LOQ_hresult("network", "u", "URL", szURL);
	return ret;
}