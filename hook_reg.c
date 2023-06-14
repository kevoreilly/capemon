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
#include "misc.h"
#include "log.h"
#include "config.h"
#include "CAPE\CAPE.h"

HOOKDEF(LONG, WINAPI, RegOpenKeyExA,
	__in		HKEY hKey,
	__in_opt	LPCTSTR lpSubKey,
	__reserved  DWORD ulOptions,
	__in		REGSAM samDesired,
	__out	   PHKEY phkResult
) {
	HKEY saved_hkey = phkResult ? *phkResult : INVALID_HANDLE_VALUE;
	LONG ret = Old_RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired,
		phkResult);

	// fake the absence of some keys
	if (!g_config.no_stealth && (ret == ERROR_SUCCESS || ret == ERROR_ACCESS_DENIED)) {
		unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
		PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
		wchar_t *keypath = get_full_key_pathA(hKey, lpSubKey, keybuf, allocsize);
		int i;

		wchar_t *hidden_keys[] = {
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\DSDT\\VBOX__",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\DSDT\\VBOX__\\VBOXBIOS",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\FADT\\VBOX__",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\FADT\\VBOX__\\VBOXFACP",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\RSDT\\VBOX__",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\RSDT\\VBOX__\\VBOXRSDT"
		};

		for (i = 0; i < _countof(hidden_keys); ++i) {
			if (!wcsicmp(keypath, hidden_keys[i])) {
				lasterror_t errors;
				// clean up state to avoid leaking information
				if (ret == ERROR_SUCCESS && phkResult) {
					RegCloseKey(*phkResult);
					*phkResult = saved_hkey;
				}
				ret = errors.Win32Error = ERROR_FILE_NOT_FOUND;
				errors.NtstatusError = STATUS_OBJECT_NAME_NOT_FOUND;
				errors.Eflags = 0;
				set_lasterrors(&errors);
				break;
			}
		}

		// fake some values
		if (lpSubKey && !g_config.no_stealth)
			perform_ascii_registry_fakery(keypath, (LPVOID)lpSubKey, (ULONG)strlen(lpSubKey));
		free(keybuf);
	}

	LOQ_zero("registry", "psPe", "Registry", hKey, "SubKey", lpSubKey, "Handle", phkResult,
		"FullName", hKey, lpSubKey);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegOpenKeyExW,
	__in		HKEY hKey,
	__in_opt	LPWSTR lpSubKey,
	__reserved  DWORD ulOptions,
	__in		REGSAM samDesired,
	__out	   PHKEY phkResult
) {
	HKEY saved_hkey = phkResult ? *phkResult : INVALID_HANDLE_VALUE;
	LONG ret = Old_RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired,
		phkResult);

	// fake the absence of some keys
	if (!g_config.no_stealth && (ret == ERROR_SUCCESS || ret == ERROR_ACCESS_DENIED)) {
		unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
		PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
		wchar_t *keypath = get_full_key_pathW(hKey, lpSubKey, keybuf, allocsize);
		int i;

		wchar_t *hidden_keys[] = {
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\DSDT\\VBOX__",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\DSDT\\VBOX__\\VBOXBIOS",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\FADT\\VBOX__",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\FADT\\VBOX__\\VBOXFACP",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\RSDT\\VBOX__",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\RSDT\\VBOX__\\VBOXRSDT"
		};

		for (i = 0; i < _countof(hidden_keys); ++i) {
			if (!wcsicmp(keypath, hidden_keys[i])) {
				lasterror_t errors;
				// clean up state to avoid leaking information
				if (ret == ERROR_SUCCESS && phkResult) {
					RegCloseKey(*phkResult);
					*phkResult = saved_hkey;
				}
				ret = errors.Win32Error = ERROR_FILE_NOT_FOUND;
				errors.NtstatusError = STATUS_OBJECT_NAME_NOT_FOUND;
				errors.Eflags = 0;
				set_lasterrors(&errors);
				break;
			}
		}

		// fake some values
		if (lpSubKey && !g_config.no_stealth)
			perform_unicode_registry_fakery(keypath, lpSubKey, (ULONG)wcslen(lpSubKey));
		free(keybuf);
	}

	LOQ_zero("registry", "puPE", "Registry", hKey, "SubKey", lpSubKey, "Handle", phkResult,
		"FullName", hKey, lpSubKey);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegCreateKeyExA,
	__in		HKEY hKey,
	__in		LPCTSTR lpSubKey,
	__reserved  DWORD Reserved,
	__in_opt	LPTSTR lpClass,
	__in		DWORD dwOptions,
	__in		REGSAM samDesired,
	__in_opt	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__out	   PHKEY phkResult,
	__out_opt   LPDWORD lpdwDisposition
) {
	LONG ret;
	ENSURE_DWORD(lpdwDisposition);
	ret = Old_RegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass,
		dwOptions, samDesired, lpSecurityAttributes, phkResult,
		lpdwDisposition);

	// fake the absence of some keys
	if (!g_config.no_stealth && ret == ERROR_SUCCESS && *lpdwDisposition == REG_OPENED_EXISTING_KEY) {
		unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
		PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
		wchar_t *keypath = get_full_key_pathA(hKey, lpSubKey, keybuf, allocsize);
		int i;

		wchar_t *hidden_keys[] = {
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\DSDT\\VBOX__",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\DSDT\\VBOX__\\VBOXBIOS",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\FADT\\VBOX__",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\FADT\\VBOX__\\VBOXFACP",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\RSDT\\VBOX__",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\RSDT\\VBOX__\\VBOXRSDT"
		};

		for (i = 0; i < _countof(hidden_keys); ++i) {
			if (!wcsicmp(keypath, hidden_keys[i])) {
				*lpdwDisposition = REG_CREATED_NEW_KEY;
				break;
			}
		}
		free(keybuf);
	}

	LOQ_zero("registry", "psshPeI", "Registry", hKey, "SubKey", lpSubKey, "Class", lpClass,
		"Access", samDesired, "Handle", phkResult, "FullName", hKey, lpSubKey,
		"Disposition", lpdwDisposition);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegCreateKeyExW,
	__in		HKEY hKey,
	__in		LPWSTR lpSubKey,
	__reserved  DWORD Reserved,
	__in_opt	LPWSTR lpClass,
	__in		DWORD dwOptions,
	__in		REGSAM samDesired,
	__in_opt	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__out	   PHKEY phkResult,
	__out_opt   LPDWORD lpdwDisposition
) {
	LONG ret;
	ENSURE_DWORD(lpdwDisposition);
	ret = Old_RegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass,
		dwOptions, samDesired, lpSecurityAttributes, phkResult,
		lpdwDisposition);

	// fake the absence of some keys
	if (!g_config.no_stealth && ret == ERROR_SUCCESS && *lpdwDisposition == REG_OPENED_EXISTING_KEY) {
		unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
		PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
		wchar_t *keypath = get_full_key_pathW(hKey, lpSubKey, keybuf, allocsize);
		int i;

		wchar_t *hidden_keys[] = {
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\DSDT\\VBOX__",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\DSDT\\VBOX__\\VBOXBIOS",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\FADT\\VBOX__",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\FADT\\VBOX__\\VBOXFACP",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\RSDT\\VBOX__",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\RSDT\\VBOX__\\VBOXRSDT"
		};

		for (i = 0; i < _countof(hidden_keys); ++i) {
			if (!wcsicmp(keypath, hidden_keys[i])) {
				*lpdwDisposition = REG_CREATED_NEW_KEY;
				break;
			}
		}
		free(keybuf);
	}

	LOQ_zero("registry", "puuhPEI", "Registry", hKey, "SubKey", lpSubKey, "Class", lpClass,
		"Access", samDesired, "Handle", phkResult, "FullName", hKey, lpSubKey,
		"Disposition", lpdwDisposition);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegDeleteKeyA,
	__in  HKEY hKey,
	__in  LPCTSTR lpSubKey
) {
	LONG ret = Old_RegDeleteKeyA(hKey, lpSubKey);
	LOQ_zero("registry", "pse", "Handle", hKey, "SubKey", lpSubKey,
		"FullName", hKey, lpSubKey);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegDeleteKeyW,
	__in  HKEY hKey,
	__in  LPWSTR lpSubKey
) {
	LONG ret = Old_RegDeleteKeyW(hKey, lpSubKey);
	LOQ_zero("registry", "puE", "Handle", hKey, "SubKey", lpSubKey,
		"FullName", hKey, lpSubKey);
	return ret;
}

HOOKDEF(LSTATUS, WINAPI, RegDeleteKeyExW,
	_In_ HKEY    hKey,
	_In_ LPCWSTR lpSubKey,
	_In_ REGSAM  samDesired,
	__reserved DWORD   Reserved
) {
	LSTATUS ret = Old_RegDeleteKeyExW(hKey, lpSubKey, samDesired, Reserved);
	LOQ_zero("registry", "puhE", "Handle", hKey, "SubKey", lpSubKey, "Access", samDesired, "FullName", hKey, lpSubKey);
	return ret;
}

HOOKDEF(LSTATUS, WINAPI, RegDeleteKeyExA,
	_In_ HKEY   hKey,
	_In_ LPCSTR lpSubKey,
	_In_ REGSAM samDesired,
	__reserved DWORD  Reserved
) {
	LSTATUS ret = Old_RegDeleteKeyExA(hKey, lpSubKey, samDesired, Reserved);
	LOQ_zero("registry", "puhE", "Handle", hKey, "SubKey", lpSubKey, "Access", samDesired, "FullName", hKey, lpSubKey);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegEnumKeyW,
	__in   HKEY hKey,
	__in   DWORD dwIndex,
	__out  LPWSTR lpName,
	__in   DWORD cchName
) {
	LONG ret = Old_RegEnumKeyW(hKey, dwIndex, lpName, cchName);

	// fake the absence of some keys
	if (!g_config.no_stealth && ret == ERROR_SUCCESS) {
		unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
		PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
		wchar_t *keypath = get_full_key_pathW(hKey, NULL, keybuf, allocsize);
		int i, j;

		wchar_t *parent_keys[] = {
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\DSDT",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\FADT",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\RSDT"
			L"HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Enum\\IDE"
		};

		wchar_t *replace_subkeys[] = {
			L"VBOX__", L"DELL__",
			L"VMware_", L"Dell_",
			L"VMWar_", L"Dell_",
		};

		for (i = 0, j = 0; i < _countof(parent_keys); i += 1, j += 2) {
			if (!wcsicmp(keypath, parent_keys[i]) && !wcsicmp(lpName, replace_subkeys[j])) {
				wcscpy_s(lpName, sizeof(lpName), replace_subkeys[j + 1]);
				break;
			}
		}
		free(keybuf);
	}

	LOQ_zero("registry", "piuE", "Handle", hKey, "Index", dwIndex, "Name", ret ? L"" : lpName,
		"FullName", hKey, ret ? L"" : lpName);

	return ret;
}

HOOKDEF(LONG, WINAPI, RegEnumKeyExA,
	__in		 HKEY hKey,
	__in		 DWORD dwIndex,
	__out		LPTSTR lpName,
	__inout	  LPDWORD lpcName,
	__reserved   LPDWORD lpReserved,
	__inout	  LPTSTR lpClass,
	__inout_opt  LPDWORD lpcClass,
	__out_opt	PFILETIME lpftLastWriteTime
) {
	LONG ret = Old_RegEnumKeyExA(hKey, dwIndex, lpName, lpcName, lpReserved,
		lpClass, lpcClass, lpftLastWriteTime);

	// fake the absence of some keys
	if (!g_config.no_stealth && ret == ERROR_SUCCESS) {
		unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
		PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
		wchar_t *keypath = get_full_key_pathA(hKey, NULL, keybuf, allocsize);
		int i, j;

		wchar_t *parent_keys[] = {
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\DSDT",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\FADT",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\RSDT"
			L"HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Enum\\IDE"
		};

		char *replace_subkeys[] = {
			"VBOX__", "DELL__",
			"VMware_", "Dell_",
			"VMWar_", "Dell_",
		};

		for (i = 0, j = 0; i < _countof(parent_keys); i += 1, j += 2) {
			if (!wcsicmp(keypath, parent_keys[i]) && !stricmp(lpName, replace_subkeys[j])) {
				strcpy_s(lpName, sizeof(lpName), replace_subkeys[j + 1]);
				break;
			}
		}

		// fake some values
		if (lpName && !g_config.no_stealth)
			perform_ascii_registry_fakery(keypath, lpName, (ULONG)strlen(lpName));
		free(keybuf);
	}

	LOQ_zero("registry", "pisse", "Handle", hKey, "Index", dwIndex, "Name", ret ? "" : lpName,
		"Class", ret ? "" : lpClass, "FullName", hKey, ret ? "" : lpName);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegEnumKeyExW,
	__in		 HKEY hKey,
	__in		 DWORD dwIndex,
	__out		LPWSTR lpName,
	__inout	  LPDWORD lpcName,
	__reserved   LPDWORD lpReserved,
	__inout	  LPWSTR lpClass,
	__inout_opt  LPDWORD lpcClass,
	__out_opt	PFILETIME lpftLastWriteTime
) {
	LONG ret = Old_RegEnumKeyExW(hKey, dwIndex, lpName, lpcName, lpReserved,
		lpClass, lpcClass, lpftLastWriteTime);

	// fake the absence of some keys
	if (!g_config.no_stealth && ret == ERROR_SUCCESS) {
		unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
		PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
		wchar_t *keypath = get_full_key_pathW(hKey, NULL, keybuf, allocsize);
		int i, j;

		wchar_t *parent_keys[] = {
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\DSDT",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\FADT",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\RSDT"
		};

		wchar_t *replace_subkeys[] = {
			L"VBOX__", L"DELL__",
			L"VMware_", L"Dell_",
			L"VMWar_", L"Dell_",
		};

		for (i = 0, j = 0; i < _countof(parent_keys); i += 1, j += 2) {
			if (!wcsicmp(keypath, parent_keys[i]) && !wcsicmp(lpName, replace_subkeys[j])) {
				wcscpy_s(lpName, sizeof(lpName), replace_subkeys[j + 1]);
				break;
			}
		}

		// fake some values
		if (lpName && !g_config.no_stealth)
			perform_unicode_registry_fakery(keypath, lpName, (ULONG)wcslen(lpName));
		free(keybuf);
	}

	LOQ_zero("registry", "piuuE", "Handle", hKey, "Index", dwIndex, "Name", ret ? L"" : lpName,
		"Class", ret ? L"" : lpClass, "FullName", hKey, ret ? L"" : lpName);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegEnumValueA,
	__in		 HKEY hKey,
	__in		 DWORD dwIndex,
	__out		LPTSTR lpValueName,
	__inout	  LPDWORD lpcchValueName,
	__reserved   LPDWORD lpReserved,
	__out_opt	LPDWORD lpType,
	__out_opt	LPBYTE lpData,
	__inout_opt  LPDWORD lpcbData
) {
	LONG ret;
	ENSURE_DWORD(lpType);
	ret = Old_RegEnumValueA(hKey, dwIndex, lpValueName, lpcchValueName,
		lpReserved, lpType, lpData, lpcbData);
	if (ret == ERROR_SUCCESS && lpType != NULL && lpData != NULL &&
			lpcbData != NULL) {
		LOQ_zero("registry", "pisre", "Handle", hKey, "Index", dwIndex,
			"ValueName", lpValueName, "Data", *lpType, *lpcbData, lpData,
			"FullName", hKey, lpValueName);
	}
	else {
		LOQ_zero("registry", "pisIIe", "Handle", hKey, "Index", dwIndex,
			"ValueName", ret == ERROR_SUCCESS ? lpValueName : "", "Type", lpType, "DataLength", lpcbData,
			"FullName", hKey, ret == ERROR_SUCCESS ? lpValueName : "");
	}
	return ret;
}

HOOKDEF(LONG, WINAPI, RegEnumValueW,
	__in		 HKEY hKey,
	__in		 DWORD dwIndex,
	__out		LPWSTR lpValueName,
	__inout	  LPDWORD lpcchValueName,
	__reserved   LPDWORD lpReserved,
	__out_opt	LPDWORD lpType,
	__out_opt	LPBYTE lpData,
	__inout_opt  LPDWORD lpcbData
) {
	LONG ret;
	ENSURE_DWORD(lpType);
	ret = Old_RegEnumValueW(hKey, dwIndex, lpValueName, lpcchValueName,
		lpReserved, lpType, lpData, lpcbData);
	if (ret == ERROR_SUCCESS && lpType != NULL && lpData != NULL &&
			lpcbData != NULL) {
		LOQ_zero("registry", "piuRE", "Handle", hKey, "Index", dwIndex,
			"ValueName", lpValueName, "Data", *lpType, *lpcbData, lpData,
			"FullName", hKey, lpValueName);
	}
	else {
		LOQ_zero("registry", "piuIIE", "Handle", hKey, "Index", dwIndex,
			"ValueName", ret == ERROR_SUCCESS ? lpValueName : L"", "Type", lpType, "DataLength", lpcbData,
			"FullName", hKey, ret == ERROR_SUCCESS ? lpValueName : L"");
	}
	return ret;
}

HOOKDEF(LONG, WINAPI, RegSetValueExA,
	__in		HKEY hKey,
	__in_opt	LPCTSTR lpValueName,
	__reserved  DWORD Reserved,
	__in		DWORD dwType,
	__in		const BYTE *lpData,
	__in		DWORD cbData
) {
	LONG ret = Old_RegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData,
		cbData);
	if (ret == ERROR_SUCCESS) {
		if (g_config.regdump && cbData > REGISTRY_VALUE_SIZE_MIN) {
			CapeMetaData->DumpType = REGDUMP;
			DumpMemory((PVOID)lpData, cbData);
			DebugOutput("RegSetValueExA hook: Dumped registry value %s.\n", lpValueName);
		}
		LOQ_zero("registry", "psiriv", "Handle", hKey, "ValueName", lpValueName, "Type", dwType,
			"Buffer", dwType, cbData, lpData, "BufferLength", cbData,
			"FullName", hKey, lpValueName);
	}
	else {
		LOQ_zero("registry", "psiv", "Handle", hKey, "ValueName", lpValueName, "Type", dwType,
			"FullName", hKey, lpValueName);
	}
	return ret;
}

HOOKDEF(LONG, WINAPI, RegSetValueExW,
	__in		HKEY hKey,
	__in_opt	LPWSTR lpValueName,
	__reserved  DWORD Reserved,
	__in		DWORD dwType,
	__in		const BYTE *lpData,
	__in		DWORD cbData
) {
	LONG ret = Old_RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData,
		cbData);
	if (ret == ERROR_SUCCESS) {
		if (g_config.regdump && cbData > REGISTRY_VALUE_SIZE_MIN) {
			CapeMetaData->DumpType = REGDUMP;
			DumpMemory((PVOID)lpData, cbData);
			DebugOutput("RegSetValueExW hook: Dumped registry value %s.\n", lpValueName);
		}
		LOQ_zero("registry", "puiRiV", "Handle", hKey, "ValueName", lpValueName, "Type", dwType,
			"Buffer", dwType, cbData, lpData, "BufferLength", cbData,
			"FullName", hKey, lpValueName);
	}
	else {
		LOQ_zero("registry", "puiV", "Handle", hKey, "ValueName", lpValueName, "Type", dwType,
			"FullName", hKey, lpValueName);
	}
	return ret;
}

HOOKDEF(LONG, WINAPI, RegQueryValueExA,
	__in		 HKEY hKey,
	__in_opt	 LPCTSTR lpValueName,
	__reserved   LPDWORD lpReserved,
	__out_opt	LPDWORD lpType,
	__out_opt	LPBYTE lpData,
	__inout_opt  LPDWORD lpcbData
) {
	LONG ret;
	ENSURE_DWORD(lpType);
	ret = Old_RegQueryValueExA(hKey, lpValueName, lpReserved, lpType,
		lpData, lpcbData);
	if (ret == ERROR_SUCCESS && lpType != NULL && lpData != NULL && lpcbData != NULL) {
		unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
		PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
		wchar_t *keypath = get_full_keyvalue_pathA(hKey, lpValueName, keybuf, allocsize);

		// fake some values
		if (lpData && !g_config.no_stealth)
			perform_ascii_registry_fakery(keypath, lpData, *lpcbData);

		LOQ_zero("registry", "psru", "Handle", hKey, "ValueName", lpValueName,
			"Data", *lpType, *lpcbData, lpData,
			"FullName", keypath);
		free(keybuf);
	}
	else if (ret == ERROR_MORE_DATA) {
		LOQ_zero("registry", "psPIv", "Handle", hKey, "ValueName", lpValueName,
			"Type", lpType, "DataLength", lpcbData,
			"FullName", hKey, lpValueName);
	}
	else {
		LOQ_zero("registry", "psv", "Handle", hKey, "ValueName", lpValueName,
			"FullName", hKey, lpValueName);
	}
	return ret;
}

HOOKDEF(LONG, WINAPI, RegQueryValueExW,
	__in		 HKEY hKey,
	__in_opt	 LPWSTR lpValueName,
	__reserved   LPDWORD lpReserved,
	__out_opt	LPDWORD lpType,
	__out_opt	LPBYTE lpData,
	__inout_opt  LPDWORD lpcbData
) {
	LONG ret;
	ENSURE_DWORD(lpType);
	ret = Old_RegQueryValueExW(hKey, lpValueName, lpReserved, lpType,
		lpData, lpcbData);
	if (ret == ERROR_SUCCESS && lpType != NULL && lpData != NULL &&
			lpcbData != NULL) {
		unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
		PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
		wchar_t *keypath = get_full_keyvalue_pathW(hKey, lpValueName, keybuf, allocsize);

		// fake some values
		if (lpData && !g_config.no_stealth)
			perform_unicode_registry_fakery(keypath, lpData, *lpcbData);

		LOQ_zero("registry", "puRu", "Handle", hKey, "ValueName", lpValueName,
			"Data", *lpType, *lpcbData, lpData,
			"FullName", keypath);
		free(keybuf);
	}
	else if (ret == ERROR_MORE_DATA) {
		LOQ_zero("registry", "puPIV", "Handle", hKey, "ValueName", lpValueName,
			"Type", lpType, "DataLength", lpcbData,
			"FullName", hKey, lpValueName);
	}
	else {
		LOQ_zero("registry", "puV", "Handle", hKey, "ValueName", lpValueName,
			"FullName", hKey, lpValueName);
	}
	return ret;
}

HOOKDEF(LONG, WINAPI, RegDeleteValueA,
	__in	  HKEY hKey,
	__in_opt  LPCTSTR lpValueName
) {
	LONG ret = Old_RegDeleteValueA(hKey, lpValueName);
	LOQ_zero("registry", "psv", "Handle", hKey, "ValueName", lpValueName,
		"FullName", hKey, lpValueName);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegDeleteValueW,
	__in	  HKEY hKey,
	__in_opt  LPWSTR lpValueName
) {
	LONG ret = Old_RegDeleteValueW(hKey, lpValueName);
	LOQ_zero("registry", "puV", "Handle", hKey, "ValueName", lpValueName,
		"FullName", hKey, lpValueName);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegQueryInfoKeyA,
	_In_		 HKEY hKey,
	_Out_opt_	LPTSTR lpClass,
	_Inout_opt_  LPDWORD lpcClass,
	_Reserved_   LPDWORD lpReserved,
	_Out_opt_	LPDWORD lpcSubKeys,
	_Out_opt_	LPDWORD lpcMaxSubKeyLen,
	_Out_opt_	LPDWORD lpcMaxClassLen,
	_Out_opt_	LPDWORD lpcValues,
	_Out_opt_	LPDWORD lpcMaxValueNameLen,
	_Out_opt_	LPDWORD lpcMaxValueLen,
	_Out_opt_	LPDWORD lpcbSecurityDescriptor,
	_Out_opt_	PFILETIME lpftLastWriteTime
) {
	LONG ret = Old_RegQueryInfoKeyA(hKey, lpClass, lpcClass, lpReserved,
		lpcSubKeys, lpcMaxSubKeyLen, lpcMaxClassLen, lpcValues,
		lpcMaxValueNameLen, lpcMaxValueLen, lpcbSecurityDescriptor,
		lpftLastWriteTime);
	LOQ_zero("registry", "pS6I", "KeyHandle", hKey, "Class", lpcClass ? *lpcClass : 0, lpClass,
		"SubKeyCount", lpcSubKeys, "MaxSubKeyLength", lpcMaxSubKeyLen,
		"MaxClassLength", lpcMaxClassLen, "ValueCount", lpcValues,
		"MaxValueNameLength", lpcMaxValueNameLen,
		"MaxValueLength", lpcMaxValueLen);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegQueryInfoKeyW,
	_In_		 HKEY hKey,
	_Out_opt_	LPWSTR lpClass,
	_Inout_opt_  LPDWORD lpcClass,
	_Reserved_   LPDWORD lpReserved,
	_Out_opt_	LPDWORD lpcSubKeys,
	_Out_opt_	LPDWORD lpcMaxSubKeyLen,
	_Out_opt_	LPDWORD lpcMaxClassLen,
	_Out_opt_	LPDWORD lpcValues,
	_Out_opt_	LPDWORD lpcMaxValueNameLen,
	_Out_opt_	LPDWORD lpcMaxValueLen,
	_Out_opt_	LPDWORD lpcbSecurityDescriptor,
	_Out_opt_	PFILETIME lpftLastWriteTime
) {
	LONG ret = Old_RegQueryInfoKeyW(hKey, lpClass, lpcClass, lpReserved,
		lpcSubKeys, lpcMaxSubKeyLen, lpcMaxClassLen, lpcValues,
		lpcMaxValueNameLen, lpcMaxValueLen, lpcbSecurityDescriptor,
		lpftLastWriteTime);
	LOQ_zero("registry", "pU6I", "KeyHandle", hKey, "Class", lpcClass ? *lpcClass : 0, lpClass,
		"SubKeyCount", lpcSubKeys, "MaxSubKeyLength", lpcMaxSubKeyLen,
		"MaxClassLength", lpcMaxClassLen, "ValueCount", lpcValues,
		"MaxValueNameLength", lpcMaxValueNameLen,
		"MaxValueLength", lpcMaxValueLen);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegCloseKey,
	__in	HKEY hKey
	) {
	LONG ret = Old_RegCloseKey(hKey);
	LOQ_zero("registry", "p", "Handle", hKey);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegNotifyChangeKeyValue,
	_In_	 HKEY   hKey,
	_In_	 BOOL   bWatchSubtree,
	_In_	 DWORD  dwNotifyFilter,
	_In_opt_ HANDLE hEvent,
	_In_	 BOOL   fAsynchronous
) {
	LONG ret = 0;

	if (!fAsynchronous)
		LOQ_zero("registry", "Ehii", "FullName", hKey, NULL, "NotifyFilter", dwNotifyFilter, "WatchSubtree", bWatchSubtree, "Asynchronous", fAsynchronous);

	ret = Old_RegNotifyChangeKeyValue(hKey, bWatchSubtree, dwNotifyFilter, hEvent, fAsynchronous);

	if (fAsynchronous)
		LOQ_zero("registry", "Ehii", "FullName", hKey, NULL, "NotifyFilter", dwNotifyFilter, "WatchSubtree", bWatchSubtree, "Asynchronous", fAsynchronous);

	return ret;
}
