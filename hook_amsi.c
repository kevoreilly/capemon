#include <windows.h>
#include "hooking.h"
#include "log.h"
#include "misc.h"
#include "CAPE\CAPE.h"

#define AMSIBUFFER 0x6a
#define AMSISTREAM 0x6b

HOOKDEF(HRESULT, WINAPI, AmsiScanBuffer,
	_In_     PVOID        amsiContext,
	_In_     PVOID        buffer,
	_In_     ULONG        length,
	_In_opt_ LPCWSTR      contentName,
	_In_opt_ PVOID        amsiSession,
	_Out_    PVOID        result
) {
	HRESULT ret = Old_AmsiScanBuffer(amsiContext, buffer, length, contentName, amsiSession, result);

	LOQ_hresult("amsi", "up", "ContentName", contentName, "Length", length);

	if (g_config.amsidump && buffer != NULL && length > 0) {
		SetCapeMetaData(AMSIBUFFER, NULL, NULL, NULL);
		DumpMemoryRaw(buffer, (SIZE_T)length);
		DebugOutput("AmsiScanBuffer: Actively dumped AMSI buffer of size %d at 0x%p.\n", length, buffer);
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
	HRESULT ret = Old_AmsiScanString(amsiContext, string, contentName, amsiSession, result);

	LOQ_hresult("amsi", "uu", "ContentName", contentName, "String", string);

	if (g_config.amsidump && string != NULL) {
		SIZE_T len = (wcslen(string) + 1) * sizeof(wchar_t);
		SetCapeMetaData(AMSIBUFFER, NULL, NULL, NULL);
		DumpMemoryRaw((PVOID)string, len);
		DebugOutput("AmsiScanString: Actively dumped AMSI string at 0x%p.\n", string);
	}

	return ret;
}
