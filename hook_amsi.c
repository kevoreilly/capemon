#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include "hooking.h"
#include "log.h"
#include "misc.h"
#include "lookup.h"
#include "CAPE\CAPE.h"

#define AMSIBUFFER 0x6a
#define AMSISTREAM 0x6b

extern CRITICAL_SECTION g_mutex;

// Per-thread "AMSI hook active" flag using lock-free lookup table (LOOKUP_THREAD)
// to avoid static TLS (__declspec(thread)) crashes in post-loaded/injected DLLs.
static lookup_t g_amsi_active_lookup;

BOOL IsAmsiActive(void) {
	BOOL *p = (BOOL *)LOOKUP_THREAD(&g_amsi_active_lookup, BOOL);
	return p ? *p : FALSE;
}

void SetAmsiActive(BOOL val) {
	BOOL *p = (BOOL *)LOOKUP_THREAD(&g_amsi_active_lookup, BOOL);
	if (p)
		*p = val;
}

HOOKDEF(HRESULT, WINAPI, AmsiScanBuffer,
	_In_     PVOID        amsiContext,
	_In_     PVOID        buffer,
	_In_     ULONG        length,
	_In_opt_ LPCWSTR      contentName,
	_In_opt_ PVOID        amsiSession,
	_Out_    PVOID        result
) {
	SetAmsiActive(TRUE);
	HRESULT ret = Old_AmsiScanBuffer(amsiContext, buffer, length, contentName, amsiSession, result);
	SetAmsiActive(FALSE);

	LOQ_hresult("amsi", "up", "ContentName", contentName, "Length", length);

	if (g_config.amsidump && buffer != NULL && length > 0 && !our_isbadreadptr(buffer, length)) {
		EnterCriticalSection(&g_mutex);
		SetCapeMetaData(AMSIBUFFER, 0, NULL, NULL);
		DumpMemoryRaw(buffer, (SIZE_T)length);
		LeaveCriticalSection(&g_mutex);
		DebugOutput("AmsiScanBuffer: Actively dumped AMSI buffer of size %u at 0x%p.\n", length, buffer);
	}

	return ret;
}

HOOKDEF(HRESULT, WINAPI, AmsiScanString,
	_In_     PVOID        amsiContext,
	_In_     LPCWSTR      string,
	_In_opt_ LPCWSTR      contentName,
	_In_opt_ PVOID        amsiSession,
	_Out_    PVOID        result
) {
	SetAmsiActive(TRUE);
	HRESULT ret = Old_AmsiScanString(amsiContext, string, contentName, amsiSession, result);
	SetAmsiActive(FALSE);

	LOQ_hresult("amsi", "uu", "ContentName", contentName, "String", string);

	if (g_config.amsidump && string != NULL && !our_isbadreadptr((PVOID)string, sizeof(wchar_t))) {
		SIZE_T len = 0;
		__try {
			len = (wcslen(string) + 1) * sizeof(wchar_t);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			len = 0;
		}

		if (len > sizeof(wchar_t) && !our_isbadreadptr((PVOID)string, len)) {
			EnterCriticalSection(&g_mutex);
			SetCapeMetaData(AMSIBUFFER, 0, NULL, NULL);
			DumpMemoryRaw((PVOID)string, len);
			LeaveCriticalSection(&g_mutex);
			DebugOutput("AmsiScanString: Actively dumped AMSI string at 0x%p.\n", string);
		}
	}

	return ret;
}
