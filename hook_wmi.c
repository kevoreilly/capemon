#include "log.h"
#include "misc.h"
#include "config.h"
#include <Wbemidl.h>

__declspec(thread) static int g_last_seen_disk_query = 0;
__declspec(thread) static int g_last_seen_physicalmemory = 0;

void SpoofWmiData(const wchar_t* szClassName, const wchar_t* wszName, VARIANT* pVal) {
	if (g_config.bypass_antivm)
		return;

	if (!szClassName || !wszName || !pVal)
		return;

	//
	// Spoofery logic for BSTR (wchar_t *)
	//
	if (pVal->vt == VT_BSTR && pVal->bstrVal != NULL) {
		if (!_wcsicmp(pVal->bstrVal, L"Microsoft Basic Display Adapter")) {
			SysFreeString(pVal->bstrVal);
			pVal->bstrVal = SysAllocString(SPOOFED_GPU_NAME);
		}
		else if (!_wcsicmp(wszName, L"TotalPhysicalMemory")) {
			unsigned long long actualMemory = wcstoull(pVal->bstrVal, NULL, 10);
			if (actualMemory < SPOOFED_RAM) {
				SysFreeString(pVal->bstrVal);
				pVal->bstrVal = SysAllocString(WIDE_SPOOFED_RAM);
			}
		}
		else if (!_wcsicmp(wszName, L"TotalVisibleMemorySize")) {
			unsigned long long actualMemory = wcstoull(pVal->bstrVal, NULL, 10);
			// actualMemory is in Kilobytes, our spoofed values are in bytes
			if (actualMemory < (SPOOFED_RAM / 1024)) {
				SysFreeString(pVal->bstrVal);
				pVal->bstrVal = SysAllocString(WIDE_SPOOFED_RAM_IN_KB);
			}
		}
		//
		// Logic for BSTR fakery specific to an exact szClassName
		//
		else if (!_wcsicmp(szClassName, L"Win32_LogicalDisk") && !_wcsicmp(wszName, L"Size")) {
			if (g_last_seen_disk_query) {
				unsigned long long lSize = wcstoull(pVal->bstrVal, NULL, 10);
				if (lSize < SPOOFED_DISK_SIZE - RECOVERY_PARTITION_SIZE) {
					SysFreeString(pVal->bstrVal);
					pVal->bstrVal = SysAllocString(WIDE_DISK_LOGICAL_SIZE);
				}
			}
		}
		else if (!_wcsicmp(szClassName, L"Win32_PhysicalMemory") && !_wcsicmp(wszName, L"Capacity")) {
			if (g_last_seen_physicalmemory) {
				unsigned long long actualMemory = wcstoull(pVal->bstrVal, NULL, 10);
				if (actualMemory < SPOOFED_RAM) {
					SysFreeString(pVal->bstrVal);
					pVal->bstrVal = SysAllocString(WIDE_SPOOFED_RAM);
				}
			}
		}
	}
	//
	// Spoofery logic for I4 (Signed 32-bit integer)
	//
	else if (pVal->vt == VT_I4) {
		if (!_wcsicmp(szClassName, L"Win32_Processor") && !_wcsicmp(wszName, L"ThreadCount")) {
			if (pVal->lVal < (LONG)g_config.spoofed_cpu_count)
				pVal->lVal = (LONG)g_config.spoofed_cpu_count;
		}
		else if (!_wcsicmp(wszName, L"NumberOfCores")) {
			if (pVal->lVal < (LONG)g_config.spoofed_cpu_count)
				pVal->lVal = (LONG)g_config.spoofed_cpu_count;
		}
		else if (!_wcsicmp(wszName, L"NumberOfLogicalProcessors")) {
			if (pVal->lVal < (LONG)g_config.spoofed_cpu_count)
				pVal->lVal = (LONG)g_config.spoofed_cpu_count;
		}
		else if (!_wcsicmp(wszName, L"NumberOfEnabledCore")) {
			if (pVal->lVal < (LONG)g_config.spoofed_cpu_count)
				pVal->lVal = (LONG)g_config.spoofed_cpu_count;
		}
		else if (!_wcsicmp(wszName, L"AdapterRAM")) {
			if (pVal->lVal < SPOOFED_GPU_RAM) {
				pVal->lVal = SPOOFED_GPU_RAM_WMI;
			}
		}
		else if (!_wcsicmp(wszName, L"MaxRefreshRate")) {
			if (pVal->lVal < SPOOFED_REFRESH_RATE) {
				pVal->lVal = SPOOFED_REFRESH_RATE;
			}
		}
	}
	else if (pVal->vt == VT_BOOL) {
		if ((!_wcsicmp(szClassName, L"Win32_ComputerSystem") && (!_wcsicmp(wszName, L"PartOfDomain"))))
			pVal->boolVal = VARIANT_TRUE;
	}
	//
	// Spoofery logic for NULL
	//
	else if (pVal->vt == VT_NULL) {
		if (!_wcsicmp(wszName, L"SMBIOSBIOSVersion")) {
			pVal->vt = VT_BSTR;
			pVal->bstrVal = SysAllocString(L"1.23.1");
		}
	}
}

HOOKDEF(HRESULT, WINAPI, WMI_Get,
	_In_		PVOID	_this,
	_In_		LPCWSTR	wszName,
	_In_		LONG	lFlags,
	_Out_		VARIANT	*pVal,
	_Out_opt_	CIMTYPE	*pType,
	_Out_opt_	LONG	*plFlavor
) {
	HRESULT ret;
	WCHAR szClassName[256] = L"";
	if (wszName && _wcsicmp(wszName, L"__CLASS") != 0) {
		VARIANT classVariant;
		VariantInit(&classVariant);
		IWbemClassObject* pWmiObject = (IWbemClassObject*)_this;
		HRESULT hr = pWmiObject->lpVtbl->Get(pWmiObject, L"__CLASS", 0, &classVariant, NULL, NULL);
		if (SUCCEEDED(hr) && classVariant.vt == VT_BSTR) {
			wcscpy_s(szClassName, _countof(szClassName), classVariant.bstrVal);
		}
		VariantClear(&classVariant);
	}

	ret = Old_WMI_Get(_this, wszName, lFlags, pVal, pType, plFlavor);
	SpoofWmiData(szClassName, wszName, pVal);

	// Short circuit, return early for things we don't want to log
	if (!ret && !g_config.full_logs && wszName) {
		if (
			!_wcsicmp(wszName, L"__GENUS") ||
			!_wcsicmp(wszName, L"__PATH") ||
			!_wcsicmp(wszName, L"__RELPATH") ||
			!_wcsicmp(wszName, L"__SUPERCLASS") ||
			!_wcsicmp(wszName, L"SECURITY_DESCRIPTOR") ||
			!_wcsicmp(wszName, L"__NAMESPACE") ||
			!_wcsicmp(wszName, L"__CLASS") ||
			!_wcsicmp(wszName, L"__DERIVATION")
		) {
			return ret;
		}
	}

	LOQ_hresult("system", "unu", "Name", wszName, "Value", pVal, "Class", szClassName);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, WMI_Next,
	_In_		PVOID	_this,
	_In_		LONG	lFlags,
	_Out_		BSTR	*strName,
	_Out_		VARIANT	*pVal,
	_Out_opt_	CIMTYPE	*pType,
	_Out_opt_	LONG	*plFlavor
) {
	HRESULT ret = Old_WMI_Next(_this, lFlags, strName, pVal, pType, plFlavor);

	// Return early for some cases we don't want to log / spoof
	if (ret != S_OK)
		return ret;

	if (!pVal)
		return ret;

	if (pVal->vt == VT_NULL)
		return ret;

	if (!strName || !*strName)
		return ret;

	// If all is well at this point, we should do the spoofs
	lasterror_t lasterror;
	get_lasterrors(&lasterror);
	VARIANT classVariant;
	VariantInit(&classVariant);

	__try {
		IWbemClassObject* pWmiObject = (IWbemClassObject*)_this;
		HRESULT hr = pWmiObject->lpVtbl->Get(pWmiObject, L"__CLASS", 0, &classVariant, NULL, NULL);
		WCHAR szClassName[256] = L"";
		if (SUCCEEDED(hr) && classVariant.vt == VT_BSTR) {
			wcscpy_s(szClassName, _countof(szClassName), classVariant.bstrVal);
		}
		SpoofWmiData(szClassName, *strName, pVal);
		LOQ_hresult("system", "unu", "Name", *strName, "Value", pVal, "Class", szClassName);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		LOQ_hresult("system", "un", "Name", *strName, "Value", pVal);
	}

	VariantClear(&classVariant);
	set_lasterrors(&lasterror);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, WMI_ExecQuery,
	_In_	PVOID					_this,
	_In_	const BSTR				strQueryLanguage,
	_In_	const BSTR				strQuery,
	_In_	LONG					lFlags,
	_In_	IWbemContext			*pCtx,
	_Out_	IEnumWbemClassObject	**ppEnum
) {
	HRESULT ret;
	g_last_seen_disk_query = 0;
	g_last_seen_physicalmemory = 0;

	if (strQuery) {
		if (!_wcsnicmp(strQuery, L"SELECT ", 7)) {
			if (wcsistr(strQuery, L" FROM Win32_LogicalDisk")) {
				g_last_seen_disk_query = 1;
			}
			else if (wcsistr(strQuery, L" FROM Win32_PhysicalMemory")) {
				g_last_seen_physicalmemory = 1;
			}
		}
	}
	ret = Old_WMI_ExecQuery(_this, strQueryLanguage, strQuery, lFlags, pCtx, ppEnum);
	LOQ_hresult("system", "uu", "Query", strQuery, "QueryLanguage", strQueryLanguage);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, WMI_ExecQueryAsync,
	_In_	PVOID			_this,
	_In_	const BSTR		strQueryLanguage,
	_In_	const BSTR		strQuery,
	_In_	LONG			lFlags,
	_In_	IWbemContext	*pCtx,
	_In_	IWbemObjectSink	*pResponseHandler
) {
	HRESULT ret;
	g_last_seen_disk_query = 0;
	g_last_seen_physicalmemory = 0;

	if (strQuery) {
		if (!_wcsnicmp(strQuery, L"SELECT ", 7)) {
			if (wcsistr(strQuery, L" FROM Win32_LogicalDisk")) {
				g_last_seen_disk_query = 1;
			}
			else if (wcsistr(strQuery, L" FROM Win32_PhysicalMemory")) {
				g_last_seen_physicalmemory = 1;
			}
		}
	}
	ret = Old_WMI_ExecQueryAsync(_this, strQueryLanguage, strQuery, lFlags, pCtx, pResponseHandler);
	LOQ_hresult("system", "uu", "Query", strQuery, "QueryLanguage", strQueryLanguage);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, WMI_ExecMethod,
	_In_	PVOID				_this,
	_In_	const BSTR			strObjectPath,
	_In_	const BSTR			strMethodName,
	_In_	LONG				lFlags,
	_In_	IWbemContext		*pCtx,
	_In_	IWbemClassObject	*pInParams,
	_Out_	IWbemClassObject	**ppOutParams,
	_Out_	IWbemCallResult		**ppCallResult
) {
	HRESULT ret = 0;
	LOQ_hresult("system", "uu", "ObjectPath", strObjectPath, "MethodName", strMethodName);
	return Old_WMI_ExecMethod(_this, strObjectPath, strMethodName, lFlags, pCtx, pInParams, ppOutParams, ppCallResult);
}

HOOKDEF(HRESULT, WINAPI, WMI_ExecMethodAsync,
	_In_	PVOID				_this,
	_In_	const BSTR			strObjectPath,
	_In_	const BSTR			strMethodName,
	_In_	LONG				lFlags,
	_In_	IWbemContext		*pCtx,
	_In_	IWbemClassObject	*pInParams,
	_In_	IWbemObjectSink		*pResponseHandler
) {
	HRESULT ret = 0;
	LOQ_hresult("system", "uu", "ObjectPath", strObjectPath, "MethodName", strMethodName);
	return Old_WMI_ExecMethodAsync(_this, strObjectPath, strMethodName, lFlags, pCtx, pInParams, pResponseHandler);
}

HOOKDEF(HRESULT, WINAPI, WMI_GetObject,
	_In_	PVOID				_this,
	_In_	const BSTR			strObjectPath,
	_In_	LONG				lFlags,
	_In_	IWbemContext		*pCtx,
	_Out_	IWbemClassObject	**ppObject,
	_Out_	IWbemCallResult		**ppCallResult
) {
	HRESULT ret = 0;
	if (strObjectPath && SysStringLen(strObjectPath) > 0)
		LOQ_hresult("system", "u", "ObjectPath", strObjectPath);
	else
		LOQ_hresult("system", "u", "ObjectPath", L"");

	return Old_WMI_GetObject(_this, strObjectPath, lFlags, pCtx, ppObject, ppCallResult);
}

HOOKDEF(HRESULT, WINAPI, WMI_GetObjectAsync,
	_In_	PVOID			_this,
	_In_	const BSTR		strObjectPath,
	_In_	LONG			lFlags,
	_In_	IWbemContext	*pCtx,
	_In_	IWbemObjectSink	*pResultHandler
) {
	HRESULT ret = 0;
	if (strObjectPath && SysStringLen(strObjectPath) > 0)
		LOQ_hresult("system", "u", "ObjectPath", strObjectPath);
	else
		LOQ_hresult("system", "u", "ObjectPath", L"");

	return Old_WMI_GetObjectAsync(_this, strObjectPath, lFlags, pCtx, pResultHandler);
}

HOOKDEF(HRESULT, WINAPI, WMI_CreateInstanceEnum,
	_In_	PVOID					_this,
	_In_	const BSTR				strFilter,
	_In_	long					lFlags,
	_In_	IWbemContext			*pCtx,
	_Out_	IEnumWbemClassObject	**ppEnum
) {
	HRESULT ret = 0;
	LOQ_hresult("system", "u", "QueryClass", strFilter);
	return Old_WMI_CreateInstanceEnum(_this, strFilter, lFlags, pCtx, ppEnum);
}

HOOKDEF(HRESULT, WINAPI, WMI_CreateInstanceEnumAsync,
	_In_	PVOID			_this,
	_In_	const BSTR		strFilter,
	_In_	long			lFlags,
	_In_	IWbemContext	*pCtx,
	_In_	IWbemObjectSink	*pResponseHandler
) {
	HRESULT ret = 0;
	LOQ_hresult("system", "u", "QueryClass", strFilter);
	return Old_WMI_CreateInstanceEnumAsync(_this, strFilter, lFlags, pCtx, pResponseHandler);
}
