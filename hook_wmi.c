#include <stdio.h>
#include "log.h"
#include "misc.h"
#include "config.h"

static int g_last_seen_disk_query = 0;
static int g_last_seen_physicalmemory = 0;


HOOKDEF(HRESULT, WINAPI, WMI_Get,
	PVOID		_this,
	LPCWSTR		wszName,
	LONG		lFlags,
	VARIANT*	pVal,
	LONG*		pType,
	LONG*		plFlavor
) {
	HRESULT ret;
	lasterror_t lasterror;

	ret = Old_WMI_Get(_this, wszName, lFlags, pVal, pType, plFlavor);

	get_lasterrors(&lasterror);
	__try {
		if (!ret && !g_config.no_stealth && pVal && wszName) {
			if (pVal->vt == VT_BSTR) {
				if (!wcsicmp(wszName, L"TotalPhysicalMemory")) {
					unsigned long long actualMemory = wcstoull(pVal->bstrVal, NULL, 10);
					if (actualMemory < SPOOFED_RAM) {
						wchar_t wszMemory[16];
						memset(wszMemory, 0x0, sizeof(wszMemory));
						swprintf_s(wszMemory, sizeof(wszMemory), L"%llu", SPOOFED_RAM);
						SysFreeString(pVal->bstrVal);
						pVal->bstrVal = SysAllocString(wszMemory);
					}
				}
				else if (!wcsicmp(wszName, L"TotalVisibleMemorySize")) {
					unsigned long long actualMemory = wcstoull(pVal->bstrVal, NULL, 10);
					// actualMemory is in Kilobytes, our spoofed values are in bytes
					if (actualMemory < (SPOOFED_RAM / 1024)) {
						wchar_t wszMemory[16];
						memset(wszMemory, 0x0, sizeof(wszMemory));
						swprintf_s(wszMemory, sizeof(wszMemory), L"%llu", (SPOOFED_RAM / 1024));
						SysFreeString(pVal->bstrVal);
						pVal->bstrVal = SysAllocString(wszMemory);
					}
				}
				else if (g_last_seen_disk_query && !wcsicmp(wszName, L"Size")) {
					unsigned long long lSize = wcstoull(pVal->bstrVal, NULL, 10);
					if (lSize < SPOOFED_DISK_SIZE - RECOVERY_PARTITION_SIZE) {
						wchar_t newSize[16];
						memset(newSize, 0x0, sizeof(newSize));
						swprintf_s(newSize, sizeof(newSize), L"%llu", SPOOFED_DISK_SIZE - RECOVERY_PARTITION_SIZE);
						SysFreeString(pVal->bstrVal);
						pVal->bstrVal = SysAllocString(newSize);
					}
				}
				else if (g_last_seen_physicalmemory && !wcsicmp(wszName, L"Capacity")) {
					unsigned long long actualMemory = wcstoull(pVal->bstrVal, NULL, 10);
					if (actualMemory < SPOOFED_RAM) {
						wchar_t wszMemory[16];
						memset(wszMemory, 0x0, sizeof(wszMemory));
						swprintf_s(wszMemory, sizeof(wszMemory), L"%llu", SPOOFED_RAM);
						SysFreeString(pVal->bstrVal);
						pVal->bstrVal = SysAllocString(wszMemory);
					}
				}
			}
			else if (pVal->vt == VT_I4) {
				if (!wcsicmp(wszName, L"NumberOfCores")) {
					if (pVal->lVal < SPOOFED_CPU_CORE_NUM)
						pVal->lVal = SPOOFED_CPU_CORE_NUM;
				}
				else if (!wcsicmp(wszName, L"AdapterRAM")) {
					if (pVal->lVal < SPOOFED_GPU_RAM) {
						pVal->lVal = SPOOFED_GPU_RAM_WMI;
					}
				}
				else if (!wcsicmp(wszName, L"MaxRefreshRate")) {
					if (pVal->lVal < SPOOFED_REFRESH_RATE) {
						pVal->lVal = SPOOFED_REFRESH_RATE;
					}
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		;
	}
	set_lasterrors(&lasterror);

	LOQ_hresult("system", "un", "Name", wszName, "Value", pVal);
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, WMI_ExecQuery,
	PVOID		_this,
	const BSTR	strQueryLanguage,
	const BSTR	strQuery,
	LONG		lFlags,
	PVOID		pCtx,
	PVOID*		ppEnum
) {
	HRESULT ret = 0;
	if (!ret && !g_config.no_stealth && strQuery) {
		if (!_wcsnicmp(strQuery, L"SELECT ", 7)) {
			if (wcsistr(strQuery, L" FROM Win32_LogicalDisk")) {
				g_last_seen_disk_query = 1;
				//pipe("INFO:setting g_last_seen_disk_query");
			}
			else if (wcsistr(strQuery, L" FROM Win32_PhysicalMemory")) {
				g_last_seen_physicalmemory = 1;
			}
		}
	}
	LOQ_hresult("system", "uu", "Query", strQuery, "QueryLanguage", strQueryLanguage);
	return 0;
}

HOOKDEF_NOTAIL(WINAPI, WMI_ExecQueryAsync,
	PVOID		_this,
	const BSTR	strQueryLanguage,
	const BSTR	strQuery,
	long		lFlags,
	PVOID		pCtx,
	PVOID		pResponseHandler
) {
	HRESULT ret = 0;
	LOQ_hresult("system", "u", "Query", strQuery);
	return 0;
}

HOOKDEF_NOTAIL(WINAPI, WMI_ExecMethod,
	PVOID		_this,
	const BSTR	strObjectPath,
	const BSTR	strMethodName,
	long		lFlags,
	PVOID		pCtx,
	PVOID		pInParams,
	PVOID*		ppOutParams,
	PVOID*		ppCallResult
) {
	HRESULT ret = 0;
	LOQ_hresult("system", "uu", "ObjectPath", strObjectPath, "MethodName", strMethodName);
	return 0;
}

HOOKDEF_NOTAIL(WINAPI, WMI_ExecMethodAsync,
	PVOID		_this,
	const BSTR	strObjectPath,
	const BSTR	strMethodName,
	long		lFlags,
	PVOID		pCtx,
	PVOID		pInParams,
	PVOID		pResponseHandler
) {
	HRESULT ret = 0;
	return 0;
}

HOOKDEF_NOTAIL(WINAPI, WMI_GetObject,
	PVOID           _this,
	const BSTR      strObjectPath,
	long            lFlags,
	PVOID           pCtx,
	PVOID*          ppObject,
	PVOID*          ppCallResult
) {
	HRESULT ret = 0;
	if (strObjectPath && SysStringLen(strObjectPath) > 0)
		LOQ_hresult("system", "u", "ObjectPath", strObjectPath);
	else
		LOQ_hresult("system", "u", "ObjectPath", L"");
	return 0;
}

HOOKDEF_NOTAIL(WINAPI, WMI_GetObjectAsync,
	PVOID		_this,
	const BSTR	strObjectPath,
	long		lFlags,
	PVOID		pCtx,
	PVOID		pResultHandler
) {
	HRESULT ret = 0;
	LOQ_hresult("system", "u", "ObjectPath", strObjectPath);
	return 0;
}