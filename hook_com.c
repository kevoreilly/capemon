
#include "hooking.h"
#include "log.h"
#include "CAPE\CAPE.h"
#include <Wbemidl.h>

BOOL ContainsNamespace(const wchar_t* resource, const wchar_t* target) {
	/*
	* Basically case insensitive strstr except we don't care about forward/backward slashes.
	* Used for namespace checks in WbemLocator_ConnectServer
	*/
	if (!resource || !target) {
		return FALSE;
	}

	// Iterate through the resource string to find a starting match point
	for (; *resource; ++resource) {
		const wchar_t* h = resource; // Haystack pointer
		const wchar_t* n = target;   // Needle pointer

		// Attempt to match the target string from the current position
		while (*h && *n) {
			BOOL isSlashMatch = (*h == L'/' || *h == L'\\') && (*n == L'/' || *n == L'\\');
			if (isSlashMatch || (towlower(*h) == towlower(*n))) {
				h++;
				n++;
			}
			else {
				// Break on mismatch
				break;
			}
		}

		// If we reached the end of the target string, it's a successful match
		if (*n == L'\0') {
			return TRUE;
		}
	}

	return FALSE;
}

__declspec(thread) BOOL bHookViaWbemLocator;
HOOKDEF(HRESULT, WINAPI, WbemLocator_ConnectServer,
	_In_	PVOID			_this,
	_In_	const BSTR		strNetworkResource,
	_In_	const BSTR		strUser,
	_In_	const BSTR		strPassword,
	_In_	const BSTR		strLocale,
	_In_	long			lSecurityFlags,
	_In_	const BSTR		strAuthority,
	_In_	IWbemContext	*pCtx,
	_Out_	IWbemServices	**ppNamespace
) {
	HRESULT ret;
	ret = Old_WbemLocator_ConnectServer(_this, strNetworkResource, strUser, strPassword, strLocale, lSecurityFlags, strAuthority, pCtx, ppNamespace);

	if (ret == S_OK && (
		ContainsNamespace(strNetworkResource, L"ROOT\\CIMV2") ||
		ContainsNamespace(strNetworkResource, L"ROOT\\SecurityCenter2") ||
		ContainsNamespace(strNetworkResource, L"ROOT\\Microsoft\\Windows\\Defender") ||
		ContainsNamespace(strNetworkResource, L"ROOT\\subscription") ||
		ContainsNamespace(strNetworkResource, L"ROOT\\Microsoft\\Windows\\TaskScheduler")
	)) 
	{
		bHookViaWbemLocator = TRUE;
		set_com_hooks(NULL, NULL, *ppNamespace);
		bHookViaWbemLocator = FALSE;
	}

	LOQ_hresult("com", "uu", "NetworkResource", strNetworkResource, "User", strUser);
	return ret;
}