#include <stdio.h>
#include "log.h"
#include "misc.h"
#include "config.h"
#include "hooks.h"
#include <Wbemidl.h>

enum {
	WMI_FAKE_CLASS_NONE = 0,
	WMI_FAKE_CLASS_FAN,
	WMI_FAKE_CLASS_CACHEMEMORY,
	WMI_FAKE_CLASS_VOLTAGEPROBE,
	WMI_FAKE_CLASS_PORTCONNECTOR,
	WMI_FAKE_CLASS_THERMALZONEINFO,
	WMI_FAKE_CLASS_CIM_MEMORY,
	WMI_FAKE_CLASS_CIM_SENSOR,
	WMI_FAKE_CLASS_CIM_NUMERICSENSOR,
	WMI_FAKE_CLASS_CIM_TEMPERATURESENSOR,
	WMI_FAKE_CLASS_CIM_VOLTAGESENSOR,
	WMI_FAKE_CLASS_CIM_PHYSICALCONNECTOR,
	WMI_FAKE_CLASS_CIM_SLOT
};

typedef struct {
	int last_seen_disk_query;
	int last_seen_physicalmemory;
	int last_seen_fake_class;
} wmi_thread_context_t;

extern DWORD g_wmi_tracker_tls_index;

// Fallback context if TLS allocation fails (shared across threads as last resort)
static wmi_thread_context_t g_wmi_fallback_context = {0};

static wmi_thread_context_t* GetWmiThreadContext(void) {
	wmi_thread_context_t* pCtx = NULL;
	if (g_wmi_tracker_tls_index != TLS_OUT_OF_INDEXES) {
		pCtx = (wmi_thread_context_t*)TlsGetValue(g_wmi_tracker_tls_index);
		if (!pCtx) {
			pCtx = (wmi_thread_context_t*)calloc(1, sizeof(wmi_thread_context_t));
			if (pCtx) {
				TlsSetValue(g_wmi_tracker_tls_index, pCtx);
			} else {
				// calloc failed - use fallback (not thread-safe but prevents crash)
				pCtx = &g_wmi_fallback_context;
			}
		}
	} else {
		// TLS not initialized - use fallback
		pCtx = &g_wmi_fallback_context;
	}
	return pCtx;
}

// Accessor macros: GetWmiThreadContext now guaranteed to return non-NULL
#define g_last_seen_disk_query (GetWmiThreadContext()->last_seen_disk_query)
#define g_last_seen_physicalmemory (GetWmiThreadContext()->last_seen_physicalmemory)
#define g_last_seen_fake_class (GetWmiThreadContext()->last_seen_fake_class)

void TlsWmiThreadCleanup(void) {
	if (g_wmi_tracker_tls_index != TLS_OUT_OF_INDEXES) {
		wmi_thread_context_t* pCtx = (wmi_thread_context_t*)TlsGetValue(g_wmi_tracker_tls_index);
		if (pCtx) {
			free(pCtx);
			TlsSetValue(g_wmi_tracker_tls_index, NULL);
		}
	}
}

void SpoofWmiData(const void* pObject, const wchar_t* szClassName, const wchar_t* wszName, VARIANT* pVal) {
	int pointer_idx = (pObject != NULL) ? (int)(((ULONG_PTR)pObject >> 4) % 3) : 0;

	if (g_config.no_stealth)
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
		else if (!_wcsicmp(wszName, L"DeviceID") && g_last_seen_fake_class != WMI_FAKE_CLASS_NONE) {
			SysFreeString(pVal->bstrVal);
			switch (g_last_seen_fake_class) {
				case WMI_FAKE_CLASS_FAN: pVal->bstrVal = SysAllocString(L"Fan0"); break;
				case WMI_FAKE_CLASS_CACHEMEMORY: {
					wchar_t fName[32];
					swprintf_s(fName, _countof(fName), L"Cache%d", pointer_idx);
					pVal->bstrVal = SysAllocString(fName);
					break;
				}
				case WMI_FAKE_CLASS_VOLTAGEPROBE: pVal->bstrVal = SysAllocString(L"Voltage0"); break;
				case WMI_FAKE_CLASS_PORTCONNECTOR: pVal->bstrVal = SysAllocString(L"Port0"); break;
				case WMI_FAKE_CLASS_THERMALZONEINFO: pVal->bstrVal = SysAllocString(L"Thermal0"); break;
				case WMI_FAKE_CLASS_CIM_MEMORY: pVal->bstrVal = SysAllocString(L"CIMMemory0"); break;
				case WMI_FAKE_CLASS_CIM_SENSOR: pVal->bstrVal = SysAllocString(L"CIMSensor0"); break;
				case WMI_FAKE_CLASS_CIM_NUMERICSENSOR: pVal->bstrVal = SysAllocString(L"CIMNumeric0"); break;
				case WMI_FAKE_CLASS_CIM_TEMPERATURESENSOR: pVal->bstrVal = SysAllocString(L"CIMTemp0"); break;
				case WMI_FAKE_CLASS_CIM_VOLTAGESENSOR: pVal->bstrVal = SysAllocString(L"CIMVoltage0"); break;
				case WMI_FAKE_CLASS_CIM_PHYSICALCONNECTOR: pVal->bstrVal = SysAllocString(L"CIMConnector0"); break;
				case WMI_FAKE_CLASS_CIM_SLOT: pVal->bstrVal = SysAllocString(L"CIMSlot0"); break;
			}
		}
		else if (!_wcsicmp(wszName, L"Status") && g_last_seen_fake_class != WMI_FAKE_CLASS_NONE) {
			SysFreeString(pVal->bstrVal);
			pVal->bstrVal = SysAllocString(L"OK");
		}
		else if (!_wcsicmp(wszName, L"Purpose") && g_last_seen_fake_class == WMI_FAKE_CLASS_CACHEMEMORY) {
			SysFreeString(pVal->bstrVal);
			switch (pointer_idx) {
				case 0: pVal->bstrVal = SysAllocString(L"Internal L1 Cache"); break;
				case 1: pVal->bstrVal = SysAllocString(L"Internal L2 Cache"); break;
				case 2: pVal->bstrVal = SysAllocString(L"External L3 Cache"); break;
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
		else if (g_last_seen_fake_class != WMI_FAKE_CLASS_NONE) {
			if (!_wcsicmp(wszName, L"InstalledSize")) {
				switch (pointer_idx) {
					case 0: pVal->lVal = 32768; break; // L1: 32KB
					case 1: pVal->lVal = 262144; break; // L2: 256KB
					case 2: pVal->lVal = (LONG)g_config.wmi_cache_size; break; // L3: User Configurable
				}
			}
			else if (!_wcsicmp(wszName, L"Level")) {
				switch (pointer_idx) {
					case 0: pVal->lVal = 3; break; // L1 (3)
					case 1: pVal->lVal = 4; break; // L2 (4)
					case 2: pVal->lVal = 5; break; // L3 (5)
				}
			}
			else if (!_wcsicmp(wszName, L"CurrentReading")) {
				pVal->lVal = (LONG)g_config.wmi_voltage_reading;
			}
			else if (!_wcsicmp(wszName, L"ConnectorType")) {
				pVal->lVal = 3; // DB9 Male
			}
			else if (!_wcsicmp(wszName, L"PortType")) {
				pVal->lVal = 2; // Serial Port
			}
			else if (!_wcsicmp(wszName, L"CurrentTemperature")) {
				pVal->lVal = (LONG)g_config.wmi_temperature_reading;
			}
		}
	}
	else if (pVal->vt == VT_BOOL) {
		if ((!_wcsicmp(szClassName, L"Win32_ComputerSystem") && (!_wcsicmp(wszName, L"PartOfDomain"))))
			pVal->boolVal = VARIANT_TRUE;
		else if (g_last_seen_fake_class == WMI_FAKE_CLASS_FAN && !_wcsicmp(wszName, L"ActiveCooling")) {
			pVal->boolVal = VARIANT_TRUE;
		}
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

static BOOL IsPropertyValidForFakeClass(int fakeClass, const wchar_t* wszName) {
	if (!wszName)
		return FALSE;

	// Core properties common to almost all faked classes
	if (!_wcsicmp(wszName, L"DeviceID") || !_wcsicmp(wszName, L"Status") || !_wcsicmp(wszName, L"__CLASS"))
		return TRUE;

	switch (fakeClass) {
		case WMI_FAKE_CLASS_FAN:
			return !_wcsicmp(wszName, L"ActiveCooling");
		case WMI_FAKE_CLASS_CACHEMEMORY:
			return !_wcsicmp(wszName, L"InstalledSize") || !_wcsicmp(wszName, L"Level") || !_wcsicmp(wszName, L"Purpose");
		case WMI_FAKE_CLASS_VOLTAGEPROBE:
			return !_wcsicmp(wszName, L"CurrentReading");
		case WMI_FAKE_CLASS_PORTCONNECTOR:
			return !_wcsicmp(wszName, L"ConnectorType") || !_wcsicmp(wszName, L"PortType");
		case WMI_FAKE_CLASS_THERMALZONEINFO:
			return !_wcsicmp(wszName, L"CurrentTemperature");
	}

	return FALSE;
}

HOOKDEF(HRESULT, WINAPI, WMI_Get,
	_In_		PVOID	_this,
	_In_		LPCWSTR	wszName,
	_In_		LONG	lFlags,
	_Inout_		VARIANT	*pVal,
	_Out_opt_	CIMTYPE	*pType,
	_Out_opt_	LONG	*plFlavor
) {
	HRESULT ret;
	WCHAR szClassName[256] = L"";

	if (wszName && _wcsicmp(wszName, L"__CLASS") == 0 && g_last_seen_fake_class != WMI_FAKE_CLASS_NONE) {
		VariantInit(pVal);
		pVal->vt = VT_BSTR;
		switch (g_last_seen_fake_class) {
			case WMI_FAKE_CLASS_FAN: pVal->bstrVal = SysAllocString(L"Win32_Fan"); break;
			case WMI_FAKE_CLASS_CACHEMEMORY: pVal->bstrVal = SysAllocString(L"Win32_CacheMemory"); break;
			case WMI_FAKE_CLASS_VOLTAGEPROBE: pVal->bstrVal = SysAllocString(L"Win32_VoltageProbe"); break;
			case WMI_FAKE_CLASS_PORTCONNECTOR: pVal->bstrVal = SysAllocString(L"Win32_PortConnector"); break;
			case WMI_FAKE_CLASS_THERMALZONEINFO: pVal->bstrVal = SysAllocString(L"Win32_ThermalZoneInfo"); break;
			case WMI_FAKE_CLASS_CIM_MEMORY: pVal->bstrVal = SysAllocString(L"CIM_Memory"); break;
			case WMI_FAKE_CLASS_CIM_SENSOR: pVal->bstrVal = SysAllocString(L"CIM_Sensor"); break;
			case WMI_FAKE_CLASS_CIM_NUMERICSENSOR: pVal->bstrVal = SysAllocString(L"CIM_NumericSensor"); break;
			case WMI_FAKE_CLASS_CIM_TEMPERATURESENSOR: pVal->bstrVal = SysAllocString(L"CIM_TemperatureSensor"); break;
			case WMI_FAKE_CLASS_CIM_VOLTAGESENSOR: pVal->bstrVal = SysAllocString(L"CIM_VoltageSensor"); break;
			case WMI_FAKE_CLASS_CIM_PHYSICALCONNECTOR: pVal->bstrVal = SysAllocString(L"CIM_PhysicalConnector"); break;
			case WMI_FAKE_CLASS_CIM_SLOT: pVal->bstrVal = SysAllocString(L"CIM_Slot"); break;
		}
		if (pType) *pType = CIM_STRING;
		if (plFlavor) *plFlavor = 0;
		return S_OK;
	}

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

	if (ret == WBEM_E_NOT_FOUND && g_last_seen_fake_class != WMI_FAKE_CLASS_NONE && IsPropertyValidForFakeClass(g_last_seen_fake_class, wszName)) {
		VariantInit(pVal);
		ret = S_OK;
	}

	if (g_last_seen_fake_class != WMI_FAKE_CLASS_NONE) {
		switch (g_last_seen_fake_class) {
			case WMI_FAKE_CLASS_FAN: wcscpy_s(szClassName, _countof(szClassName), L"Win32_Fan"); break;
			case WMI_FAKE_CLASS_CACHEMEMORY: wcscpy_s(szClassName, _countof(szClassName), L"Win32_CacheMemory"); break;
			case WMI_FAKE_CLASS_VOLTAGEPROBE: wcscpy_s(szClassName, _countof(szClassName), L"Win32_VoltageProbe"); break;
			case WMI_FAKE_CLASS_PORTCONNECTOR: wcscpy_s(szClassName, _countof(szClassName), L"Win32_PortConnector"); break;
			case WMI_FAKE_CLASS_THERMALZONEINFO: wcscpy_s(szClassName, _countof(szClassName), L"Win32_ThermalZoneInfo"); break;
			case WMI_FAKE_CLASS_CIM_MEMORY: wcscpy_s(szClassName, _countof(szClassName), L"CIM_Memory"); break;
			case WMI_FAKE_CLASS_CIM_SENSOR: wcscpy_s(szClassName, _countof(szClassName), L"CIM_Sensor"); break;
			case WMI_FAKE_CLASS_CIM_NUMERICSENSOR: wcscpy_s(szClassName, _countof(szClassName), L"CIM_NumericSensor"); break;
			case WMI_FAKE_CLASS_CIM_TEMPERATURESENSOR: wcscpy_s(szClassName, _countof(szClassName), L"CIM_TemperatureSensor"); break;
			case WMI_FAKE_CLASS_CIM_VOLTAGESENSOR: wcscpy_s(szClassName, _countof(szClassName), L"CIM_VoltageSensor"); break;
			case WMI_FAKE_CLASS_CIM_PHYSICALCONNECTOR: wcscpy_s(szClassName, _countof(szClassName), L"CIM_PhysicalConnector"); break;
			case WMI_FAKE_CLASS_CIM_SLOT: wcscpy_s(szClassName, _countof(szClassName), L"CIM_Slot"); break;
		}
	}

	SpoofWmiData(_this, szClassName, wszName, pVal);

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
		SpoofWmiData(_this, szClassName, *strName, pVal);
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
	BSTR queryToExecute = (BSTR)strQuery;
	g_last_seen_disk_query = 0;
	g_last_seen_physicalmemory = 0;
	g_last_seen_fake_class = WMI_FAKE_CLASS_NONE;

	if (strQuery) {
		if (!_wcsnicmp(strQuery, L"SELECT ", 7)) {
			if (wcsistr(strQuery, L" FROM Win32_LogicalDisk")) {
				g_last_seen_disk_query = 1;
			}
			else if (wcsistr(strQuery, L" FROM Win32_PhysicalMemory")) {
				g_last_seen_physicalmemory = 1;
			}
			else if (wcsistr(strQuery, L" FROM Win32_Fan")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_FAN;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_ComputerSystem");
			}
			else if (wcsistr(strQuery, L" FROM Win32_CacheMemory")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_CACHEMEMORY;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_Processor");
			}
			else if (wcsistr(strQuery, L" FROM Win32_VoltageProbe")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_VOLTAGEPROBE;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_ComputerSystem");
			}
			else if (wcsistr(strQuery, L" FROM Win32_PortConnector")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_PORTCONNECTOR;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_ComputerSystem");
			}
			else if (wcsistr(strQuery, L" FROM Win32_ThermalZoneInfo")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_THERMALZONEINFO;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_ComputerSystem");
			}
			else if (wcsistr(strQuery, L" FROM CIM_Memory")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_CIM_MEMORY;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_ComputerSystem");
			}
			else if (wcsistr(strQuery, L" FROM CIM_Sensor")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_CIM_SENSOR;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_ComputerSystem");
			}
			else if (wcsistr(strQuery, L" FROM CIM_NumericSensor")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_CIM_NUMERICSENSOR;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_ComputerSystem");
			}
			else if (wcsistr(strQuery, L" FROM CIM_TemperatureSensor")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_CIM_TEMPERATURESENSOR;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_ComputerSystem");
			}
			else if (wcsistr(strQuery, L" FROM CIM_VoltageSensor")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_CIM_VOLTAGESENSOR;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_ComputerSystem");
			}
			else if (wcsistr(strQuery, L" FROM CIM_PhysicalConnector")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_CIM_PHYSICALCONNECTOR;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_ComputerSystem");
			}
			else if (wcsistr(strQuery, L" FROM CIM_Slot")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_CIM_SLOT;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_ComputerSystem");
			}
		}
	}
	ret = Old_WMI_ExecQuery(_this, strQueryLanguage, queryToExecute, lFlags, pCtx, ppEnum);
	if (queryToExecute != strQuery) {
		SysFreeString(queryToExecute);
	}
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
	BSTR queryToExecute = (BSTR)strQuery;
	g_last_seen_disk_query = 0;
	g_last_seen_physicalmemory = 0;
	g_last_seen_fake_class = WMI_FAKE_CLASS_NONE;

	if (strQuery) {
		if (!_wcsnicmp(strQuery, L"SELECT ", 7)) {
			if (wcsistr(strQuery, L" FROM Win32_LogicalDisk")) {
				g_last_seen_disk_query = 1;
			}
			else if (wcsistr(strQuery, L" FROM Win32_PhysicalMemory")) {
				g_last_seen_physicalmemory = 1;
			}
			else if (wcsistr(strQuery, L" FROM Win32_Fan")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_FAN;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_ComputerSystem");
			}
			else if (wcsistr(strQuery, L" FROM Win32_CacheMemory")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_CACHEMEMORY;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_Processor");
			}
			else if (wcsistr(strQuery, L" FROM Win32_VoltageProbe")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_VOLTAGEPROBE;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_ComputerSystem");
			}
			else if (wcsistr(strQuery, L" FROM Win32_PortConnector")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_PORTCONNECTOR;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_ComputerSystem");
			}
			else if (wcsistr(strQuery, L" FROM Win32_ThermalZoneInfo")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_THERMALZONEINFO;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_ComputerSystem");
			}
			else if (wcsistr(strQuery, L" FROM CIM_Memory")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_CIM_MEMORY;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_ComputerSystem");
			}
			else if (wcsistr(strQuery, L" FROM CIM_Sensor")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_CIM_SENSOR;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_ComputerSystem");
			}
			else if (wcsistr(strQuery, L" FROM CIM_NumericSensor")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_CIM_NUMERICSENSOR;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_ComputerSystem");
			}
			else if (wcsistr(strQuery, L" FROM CIM_TemperatureSensor")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_CIM_TEMPERATURESENSOR;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_ComputerSystem");
			}
			else if (wcsistr(strQuery, L" FROM CIM_VoltageSensor")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_CIM_VOLTAGESENSOR;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_ComputerSystem");
			}
			else if (wcsistr(strQuery, L" FROM CIM_PhysicalConnector")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_CIM_PHYSICALCONNECTOR;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_ComputerSystem");
			}
			else if (wcsistr(strQuery, L" FROM CIM_Slot")) {
				g_last_seen_fake_class = WMI_FAKE_CLASS_CIM_SLOT;
				queryToExecute = SysAllocString(L"SELECT * FROM Win32_ComputerSystem");
			}
		}
	}
	ret = Old_WMI_ExecQueryAsync(_this, strQueryLanguage, queryToExecute, lFlags, pCtx, pResponseHandler);
	if (queryToExecute != strQuery) {
		SysFreeString(queryToExecute);
	}
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
