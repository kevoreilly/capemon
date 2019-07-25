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
#include "config.h"

static BOOLEAN servicename_from_handle(SC_HANDLE hService, PWCHAR servicename)
{
	lasterror_t lasterror;
	DWORD byteneeded;
	LPQUERY_SERVICE_CONFIGW servconfig = calloc(1, 0x2000);
	BOOLEAN ret = FALSE;

	if (servconfig == NULL) {
		servicename[0] = L'\0';
		return ret;
	}
	get_lasterrors(&lasterror);
	// TODO: handle localized strings for Vista+
	ret = QueryServiceConfigW(hService, servconfig, 0x2000, &byteneeded);

	if (ret) {
		SC_HANDLE scmhandle = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
		if (scmhandle != NULL) {
			// appears to work just fine using the service's handle, but let's do it according to spec
			ret = GetServiceKeyNameW(scmhandle, servconfig->lpDisplayName, servicename, &byteneeded);
			CloseServiceHandle(scmhandle);
		}
		else {
			ret = FALSE;
		}
	}
	if (!ret)
		servicename[0] = L'\0';

	set_lasterrors(&lasterror);

	return ret;
}

HOOKDEF(SC_HANDLE, WINAPI, OpenSCManagerA,
    __in_opt  LPCTSTR lpMachineName,
    __in_opt  LPCTSTR lpDatabaseName,
    __in      DWORD dwDesiredAccess
) {
    SC_HANDLE ret = Old_OpenSCManagerA(lpMachineName, lpDatabaseName,
        dwDesiredAccess);
    LOQ_nonnull("services", "ssh", "MachineName", lpMachineName, "DatabaseName", lpDatabaseName,
        "DesiredAccess", dwDesiredAccess);
    return ret;
}

HOOKDEF(SC_HANDLE, WINAPI, OpenSCManagerW,
    __in_opt  LPWSTR lpMachineName,
    __in_opt  LPWSTR lpDatabaseName,
    __in      DWORD dwDesiredAccess
) {
    SC_HANDLE ret = Old_OpenSCManagerW(lpMachineName, lpDatabaseName,
        dwDesiredAccess);
    LOQ_nonnull("services", "uuh", "MachineName", lpMachineName, "DatabaseName", lpDatabaseName,
        "DesiredAccess", dwDesiredAccess);
    return ret;
}

HOOKDEF(SC_HANDLE, WINAPI, CreateServiceA,
    __in       SC_HANDLE hSCManager,
    __in       LPCSTR lpServiceName,
    __in_opt   LPCSTR lpDisplayName,
    __in       DWORD dwDesiredAccess,
    __in       DWORD dwServiceType,
    __in       DWORD dwStartType,
    __in       DWORD dwErrorControl,
    __in_opt   LPCSTR lpBinaryPathName,
    __in_opt   LPCSTR lpLoadOrderGroup,
    __out_opt  LPDWORD lpdwTagId,
    __in_opt   LPCSTR lpDependencies,
    __in_opt   LPCSTR lpServiceStartName,
    __in_opt   LPCSTR lpPassword
) {
    SC_HANDLE ret = Old_CreateServiceA(hSCManager, lpServiceName,
		lpDisplayName, dwDesiredAccess | SERVICE_QUERY_CONFIG, dwServiceType, dwStartType,
        dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId,
        lpDependencies, lpServiceStartName, lpPassword);
	LOQ_nonnull("services", "pssh3i3s", "ServiceControlHandle", hSCManager,
        "ServiceName", lpServiceName, "DisplayName", lpDisplayName,
        "DesiredAccess", dwDesiredAccess, "ServiceType", dwServiceType,
        "StartType", dwStartType, "ErrorControl", dwErrorControl,
        "BinaryPathName", lpBinaryPathName,
        "ServiceStartName", lpServiceStartName,
        "Password", lpPassword);

	return ret;
}

HOOKDEF(SC_HANDLE, WINAPI, CreateServiceW,
    __in       SC_HANDLE hSCManager,
    __in       LPWSTR lpServiceName,
    __in_opt   LPWSTR lpDisplayName,
    __in       DWORD dwDesiredAccess,
    __in       DWORD dwServiceType,
    __in       DWORD dwStartType,
    __in       DWORD dwErrorControl,
    __in_opt   LPWSTR lpBinaryPathName,
    __in_opt   LPWSTR lpLoadOrderGroup,
    __out_opt  LPDWORD lpdwTagId,
    __in_opt   LPWSTR lpDependencies,
    __in_opt   LPWSTR lpServiceStartName,
    __in_opt   LPWSTR lpPassword
) {
    SC_HANDLE ret = Old_CreateServiceW(hSCManager, lpServiceName,
        lpDisplayName, dwDesiredAccess | SERVICE_QUERY_CONFIG, dwServiceType, dwStartType,
        dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId,
        lpDependencies, lpServiceStartName, lpPassword);
    LOQ_nonnull("services", "puuh3i3u", "ServiceControlHandle", hSCManager,
        "ServiceName", lpServiceName, "DisplayName", lpDisplayName,
        "DesiredAccess", dwDesiredAccess, "ServiceType", dwServiceType,
        "StartType", dwStartType, "ErrorControl", dwErrorControl,
        "BinaryPathName", lpBinaryPathName,
        "ServiceStartName", lpServiceStartName,
        "Password", lpPassword);
    return ret;
}

HOOKDEF(SC_HANDLE, WINAPI, OpenServiceA,
    __in  SC_HANDLE hSCManager,
    __in  LPCTSTR lpServiceName,
    __in  DWORD dwDesiredAccess
) {
	lasterror_t lasterror;
	SC_HANDLE ret;
	get_lasterrors(&lasterror);
	ret = Old_OpenServiceA(hSCManager, lpServiceName,
		dwDesiredAccess | SERVICE_QUERY_CONFIG);
	if (ret != NULL)
		set_lasterrors(&lasterror);
	else
		ret = Old_OpenServiceA(hSCManager, lpServiceName, dwDesiredAccess);
    LOQ_nonnull("services", "psh", "ServiceControlManager", hSCManager,
        "ServiceName", lpServiceName, "DesiredAccess", dwDesiredAccess);
    return ret;
}

HOOKDEF(SC_HANDLE, WINAPI, OpenServiceW,
    __in  SC_HANDLE hSCManager,
    __in  LPWSTR lpServiceName,
    __in  DWORD dwDesiredAccess
) {
	lasterror_t lasterror;
	SC_HANDLE ret;
	get_lasterrors(&lasterror);
	ret = Old_OpenServiceW(hSCManager, lpServiceName,
		dwDesiredAccess | SERVICE_QUERY_CONFIG);
	if (ret != NULL)
		set_lasterrors(&lasterror);
	else
		ret = Old_OpenServiceW(hSCManager, lpServiceName, dwDesiredAccess);

    LOQ_nonnull("services", "puh", "ServiceControlManager", hSCManager,
        "ServiceName", lpServiceName, "DesiredAccess", dwDesiredAccess);
    return ret;
}

extern wchar_t *our_process_path_w;

HOOKDEF(BOOL, WINAPI, StartServiceA,
    __in      SC_HANDLE hService,
    __in      DWORD dwNumServiceArgs,
    __in_opt  LPCTSTR *lpServiceArgVectors
) {
	PWCHAR servicename = calloc(1, 0x1000);
	BOOLEAN dispret = servicename_from_handle(hService, servicename);
	BOOL ret;

	if (dispret && !g_config.suspend_logging && (wcsicmp(servicename, L"osppsvc") || !g_config.file_of_interest || !wcsicmp(our_process_path_w, g_config.file_of_interest)))
		pipe("SERVICE:%Z", servicename);
	ret = Old_StartServiceA(hService, dwNumServiceArgs,
        lpServiceArgVectors);
    LOQ_bool("services", "pua", "ServiceHandle", hService, "ServiceName", servicename, "Arguments", dwNumServiceArgs,
        lpServiceArgVectors);
	free(servicename);
    return ret;
}

HOOKDEF(BOOL, WINAPI, StartServiceW,
    __in      SC_HANDLE hService,
    __in      DWORD dwNumServiceArgs,
    __in_opt  LPWSTR *lpServiceArgVectors
) {
	PWCHAR servicename = calloc(1, 0x1000);
	BOOLEAN dispret = servicename_from_handle(hService, servicename);
	BOOL ret;

	if (dispret && !g_config.suspend_logging && (wcsicmp(servicename, L"osppsvc") || !g_config.file_of_interest || !wcsicmp(our_process_path_w, g_config.file_of_interest)))
		pipe("SERVICE:%Z", servicename);
    ret = Old_StartServiceW(hService, dwNumServiceArgs,
        lpServiceArgVectors);
    LOQ_bool("services", "puA", "ServiceHandle", hService, "ServiceName", servicename, "Arguments", dwNumServiceArgs,
        lpServiceArgVectors);
	free(servicename);
    return ret;
}

HOOKDEF(BOOL, WINAPI, ControlService,
    __in   SC_HANDLE hService,
    __in   DWORD dwControl,
    __out  LPSERVICE_STATUS lpServiceStatus
) {
	PWCHAR servicename = calloc(1, 0x1000);
	BOOL ret;
	servicename_from_handle(hService, servicename);
	ret = Old_ControlService(hService, dwControl, lpServiceStatus);
    LOQ_bool("services", "pui", "ServiceHandle", hService, "ServiceName", servicename, "ControlCode", dwControl);
	free(servicename);
    return ret;
}

HOOKDEF(BOOL, WINAPI, DeleteService,
    __in  SC_HANDLE hService
) {
	PWCHAR servicename = calloc(1, 0x1000);
	BOOL ret;
	servicename_from_handle(hService, servicename);
	ret = Old_DeleteService(hService);
    LOQ_bool("services", "pu", "ServiceHandle", hService, "ServiceName", servicename);
	free(servicename);
    return ret;
}
