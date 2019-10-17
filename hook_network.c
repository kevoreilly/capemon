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
#include <windns.h>
#include <wininet.h>
#include "hooking.h"
#include "log.h"
#include "pipe.h"
#include "config.h"
#include "misc.h"

extern BOOL DumpRegion(PVOID Address);
extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);

static int did_initial_request;

HOOKDEF(DWORD, WINAPI, InternetConfirmZoneCrossingA,
	_In_ HWND hWnd,
	_In_ LPTSTR szUrlPrev,
	_In_ LPTSTR szUrlNew,
	_In_ BOOL bPost
) {
	DWORD ret = Old_InternetConfirmZoneCrossingA(hWnd, szUrlPrev, szUrlNew, bPost);
	LOQ_zero("network", "ss", "UrlPrev", szUrlPrev, "UrlNew", szUrlNew);
	return ret;
}

HOOKDEF(DWORD, WINAPI, InternetConfirmZoneCrossingW,
	_In_ HWND hWnd,
	_In_ LPTSTR szUrlPrev,
	_In_ LPTSTR szUrlNew,
	_In_ BOOL bPost
) {
	DWORD ret = Old_InternetConfirmZoneCrossingW(hWnd, szUrlPrev, szUrlNew, bPost);
	LOQ_zero("network", "uu", "UrlPrev", szUrlPrev, "UrlNew", szUrlNew);
	return ret;
}

HOOKDEF(SECURITY_STATUS, WINAPI, SslEncryptPacket,
	_In_    NCRYPT_PROV_HANDLE hSslProvider,
	_Inout_ NCRYPT_KEY_HANDLE hKey,
	_In_    PBYTE pbInput,
	_In_    DWORD cbInput,
	_Out_   PBYTE pbOutput,
	_In_    DWORD cbOutput,
	_Out_   DWORD *pcbResult,
	_In_    ULONGLONG SequenceNumber,
	_In_    DWORD dwContentType,
	_In_    DWORD dwFlags
) {
	SECURITY_STATUS ret = 0;
	if (cbInput > 0)
		LOQ_zero("network", "cli", "Buffer", cbInput, pbInput, "SequenceNumber", (long)SequenceNumber, "BufferSize", cbInput);

	ret = Old_SslEncryptPacket(hSslProvider, hKey, pbInput, cbInput, pbOutput, cbOutput, pcbResult, SequenceNumber, dwContentType, dwFlags);
	disable_tail_call_optimization();
	return ret;
}

HOOKDEF(SECURITY_STATUS, WINAPI, SslDecryptPacket,
	_In_    NCRYPT_PROV_HANDLE hSslProvider,
	_Inout_ NCRYPT_KEY_HANDLE hKey,
	_In_    PBYTE pbInput,
	_In_    DWORD cbInput,
	_Out_   PBYTE pbOutput,
	_In_    DWORD cbOutput,
	_Out_   DWORD *pcbResult,
	_In_    ULONGLONG SequenceNumber,
	_In_    DWORD dwFlags
) {
	SECURITY_STATUS ret = Old_SslDecryptPacket(hSslProvider, hKey, pbInput, cbInput, pbOutput, cbOutput, pcbResult, SequenceNumber, dwFlags);
	if (pcbResult > 0)
	{
		/* Only use the large buffer logger for the first sequence to avoid logging large amounts of data that
		   is not the initial response (for example file downloads) 
		*/
		if (SequenceNumber < 2)
		    LOQ_zero("network", "ClI", "Buffer", pcbResult, pbOutput, "SequenceNumber", (long)SequenceNumber, "BufferSize", pcbResult);
		else
			LOQ_zero("network", "BlI", "Buffer", pcbResult, pbOutput, "SequenceNumber", (long)SequenceNumber, "BufferSize", pcbResult);
	}
	return ret;
}

HOOKDEF(HINTERNET, WINAPI, WinHttpOpen,
	_In_opt_ LPCWSTR pwszUserAgent,
	_In_ DWORD dwAccessType,
	_In_ LPCWSTR pwszProxyName,
	_In_ LPCWSTR pwszProxyBypass,
	_In_ DWORD dwFlags
) {
	HINTERNET ret = Old_WinHttpOpen(pwszUserAgent, dwAccessType, pwszProxyName, pwszProxyBypass, dwFlags);
	LOQ_nonnull("network", "uuuhh", "UserAgent", pwszUserAgent, "ProxyName", pwszProxyName, "ProxyBypass", pwszProxyBypass, "AccessType", dwAccessType, "Flags", dwFlags);
	return ret;
}

HOOKDEF(BOOL, WINAPI, WinHttpGetIEProxyConfigForCurrentUser,
	_Inout_ LPVOID pProxyConfig // WINHTTP_CURRENT_USER_IE_PROXY_CONFIG *
) {
	BOOL ret = Old_WinHttpGetIEProxyConfigForCurrentUser(pProxyConfig);
	LOQ_bool("network", "");
	return ret;
}

HOOKDEF(BOOL, WINAPI, WinHttpGetProxyForUrl,
	_In_ HINTERNET hSession,
	_In_ LPCWSTR lpcwszUrl,
	_In_ LPVOID pAutoProxyOptions, // WINHTTP_AUTOPROXY_OPTIONS *
	_Out_ LPVOID pProxyInfo // WINHTTP_PROXY_INFO *
) {
    if (g_config.dump_config_region) {
        if (DumpRegion((PVOID)lpcwszUrl))
            DoOutputDebugString("WinHttpGetProxyForUrl hook: Successfully dumped region at 0x%p.\n", lpcwszUrl, lpcwszUrl);
        else
            DoOutputDebugString("WinHttpGetProxyForUrl hook: Failed to dump region at 0x%p.\n", lpcwszUrl, lpcwszUrl);
    }
	BOOL ret = Old_WinHttpGetProxyForUrl(hSession, lpcwszUrl, pAutoProxyOptions, pProxyInfo);
	LOQ_bool("network", "pu", "SessionHandle", hSession, "Url", lpcwszUrl);
	return ret;
}

HOOKDEF(BOOL, WINAPI, WinHttpSetOption,
	_In_ HINTERNET hInternet,
	_In_ DWORD dwOption,
	_In_ LPVOID lpBuffer,
	_In_ DWORD dwBufferLength
) {
	BOOL ret = Old_WinHttpSetOption(hInternet, dwOption, lpBuffer, dwBufferLength);
	LOQ_bool("network", "phb", "InternetHandle", hInternet, "Option", dwOption, "Buffer", dwBufferLength, lpBuffer);
	return ret;
}

HOOKDEF(HINTERNET, WINAPI, WinHttpConnect,
	_In_ HINTERNET hSession,
	_In_ LPCWSTR pswzServerName,
	_In_ INTERNET_PORT nServerPort,
	_Reserved_ DWORD dwReserved
) {
    if (g_config.dump_config_region) {
        if (DumpRegion((PVOID)pswzServerName))
            DoOutputDebugString("WinHttpConnect hook: Successfully dumped region at 0x%p.\n", pswzServerName, pswzServerName);
        else
            DoOutputDebugString("WinHttpConnect hook: Failed to dump region at 0x%p.\n", pswzServerName, pswzServerName);
    }
	HINTERNET ret = Old_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
	LOQ_nonnull("network", "pui", "SessionHandle", hSession, "ServerName", pswzServerName, "ServerPort", nServerPort);
	return ret;
}

HOOKDEF(HINTERNET, WINAPI, WinHttpOpenRequest,
	_In_  HINTERNET hConnect,
	_In_  LPCWSTR pwszVerb,
	_In_  LPCWSTR pwszObjectName,
	_In_  LPCWSTR pwszVersion,
	_In_  LPCWSTR pwszReferrer,
	_In_  LPCWSTR *ppwszAcceptTypes,
	_In_  DWORD dwFlags
) {
	HINTERNET ret;
	LPCWSTR referer;

	if ((pwszReferrer == NULL || !wcscmp(pwszReferrer, L"")) && g_config.url_of_interest && g_config.w_referrer && wcslen(g_config.w_referrer) && !did_initial_request)
		referer = g_config.w_referrer;
	else
		referer = pwszReferrer;

	ret = Old_WinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName, pwszVersion, referer, ppwszAcceptTypes, dwFlags);
	LOQ_nonnull("network", "puuuuh", "InternetHandle", hConnect, "Verb", pwszVerb, "ObjectName", pwszObjectName, "Version", pwszVersion, "Referrer", referer, "Flags", dwFlags);

	did_initial_request = TRUE;

	return ret;
}

HOOKDEF(BOOL, WINAPI, WinHttpSetTimeouts,
	_In_  HINTERNET hInternet,
	_In_  int dwResolveTimeout,
	_In_  int dwConnectTimeout,
	_In_  int dwSendTimeout,
	_In_  int dwReceiveTimeout
) {
	BOOL ret = Old_WinHttpSetTimeouts(hInternet, dwResolveTimeout, dwConnectTimeout, dwSendTimeout, dwReceiveTimeout);
	LOQ_bool("network", "piiii", "InternetHandle", hInternet, "ResolveTimeout", dwResolveTimeout, "ConnectTimeout", dwConnectTimeout, "SendTimeout", dwSendTimeout, "ReceiveTimeout", dwReceiveTimeout);
	return ret;
}

HOOKDEF(BOOL, WINAPI, WinHttpSendRequest,
	_In_      HINTERNET hRequest,
	_In_opt_  LPCWSTR pwszHeaders,
	_In_      DWORD dwHeadersLength,
	_In_opt_  LPVOID lpOptional,
	_In_      DWORD dwOptionalLength,
	_In_      DWORD dwTotalLength,
	_In_      DWORD_PTR dwContext
) {
	BOOL ret = Old_WinHttpSendRequest(hRequest, pwszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext);
	if (dwHeadersLength == -1)
		LOQ_bool("network", "pub", "InternetHandle", hRequest, "Headers", pwszHeaders, "Optional", dwOptionalLength, lpOptional);
	else
		LOQ_bool("network", "pbb", "InternetHandle", hRequest, "Headers", dwHeadersLength, pwszHeaders, "Optional", dwOptionalLength, lpOptional);

	return ret;
}

HOOKDEF(BOOL, WINAPI, WinHttpReceiveResponse,
	_In_        HINTERNET hRequest,
	_Reserved_  LPVOID lpReserved
) {
	BOOL ret = Old_WinHttpReceiveResponse(hRequest, lpReserved);
	LOQ_bool("network", "p", "InternetHandle", hRequest);
	return ret;
}

HOOKDEF(BOOL, WINAPI, WinHttpQueryHeaders,
	_In_      HINTERNET hRequest,
	_In_      DWORD dwInfoLevel,
	_In_opt_  LPCWSTR pwszName,
	_Out_     LPVOID lpBuffer,
	_Inout_   LPDWORD lpdwBufferLength,
	_Inout_   LPDWORD lpdwIndex
) {
	BOOL ret = Old_WinHttpQueryHeaders(hRequest, dwInfoLevel, pwszName, lpBuffer, lpdwBufferLength, lpdwIndex);
	LOQ_bool("network", "p", "InternetHandle", hRequest);
	return ret;
}

/* if servername is NULL, then this isn't network related, but for simplicity sake we'll log it as such */
HOOKDEF(DWORD, WINAPI, NetUserGetInfo,
	_In_ LPCWSTR servername,
	_In_ LPCWSTR username,
	_In_ DWORD level,
	_Out_ LPBYTE *bufptr
) {
	DWORD ret = Old_NetUserGetInfo(servername, username, level, bufptr);
	LOQ_zero("network", "uui", "ServerName", servername, "UserName", username, "Level", level);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, ObtainUserAgentString,
	_In_ DWORD dwOption,
	_Out_ LPSTR pcszUAOut,
	_Out_ DWORD *cbSize
) {
	HRESULT ret = Old_ObtainUserAgentString(dwOption, pcszUAOut, cbSize);
	LOQ_hresult("network", "s", "UserAgent", pcszUAOut);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, URLDownloadToFileW,
    LPUNKNOWN pCaller,
    LPWSTR szURL,
    LPWSTR szFileName,
    DWORD dwReserved,
    LPVOID lpfnCB
) {
    HRESULT ret = Old_URLDownloadToFileW(pCaller, szURL, szFileName, dwReserved, lpfnCB);
    LOQ_hresult("network", "uFs", "URL", szURL, "FileName", szFileName, "StackPivoted", is_stack_pivoted() ? "yes" : "no");
    if(ret == S_OK)
      pipe("FILE_NEW:%Z", szFileName);

    return ret;
}

HOOKDEF(HRESULT, WINAPI, URLDownloadToCacheFileW,
  _In_ LPUNKNOWN lpUnkcalled,
  _In_ LPCWSTR szURL,
  _Out_ LPWSTR szFilename,
  _In_ DWORD cchFilename,
  _Reserved_ DWORD dwReserved,
  _In_opt_ VOID *pBSC
) {
  HRESULT ret = Old_URLDownloadToCacheFileW(lpUnkcalled, szURL, szFilename, cchFilename, dwReserved, pBSC);
  LOQ_hresult("network", "uFs", "URL", szURL, "Filename", ret == S_OK ? szFilename : L"", "StackPivoted", is_stack_pivoted() ? "yes" : "no");
  if (ret == S_OK)
    pipe("FILE_NEW:%Z", szFilename);

  return ret;
}

HOOKDEF(BOOL, WINAPI, InternetGetConnectedState,
	_Out_ LPDWORD lpdwFlags,
	_In_ DWORD dwReserved
) {
	BOOL ret = Old_InternetGetConnectedState(lpdwFlags, dwReserved);
	LOQ_bool("network", "");
	return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetOpenA,
    _In_  LPCTSTR lpszAgent,
    _In_  DWORD dwAccessType,
    _In_  LPCTSTR lpszProxyName,
    _In_  LPCTSTR lpszProxyBypass,
    _In_  DWORD dwFlags
) {
	HINTERNET ret = Old_InternetOpenA(lpszAgent, dwAccessType, lpszProxyName,
        lpszProxyBypass, dwFlags);

	if (g_config.url_of_interest && g_config.suspend_logging)
		g_config.suspend_logging = FALSE;
	
	LOQ_nonnull("network", "shssh", "Agent", lpszAgent, "AccessType", dwAccessType,
        "ProxyName", lpszProxyName, "ProxyBypass", lpszProxyBypass,
        "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetOpenW,
    _In_  LPWSTR lpszAgent,
    _In_  DWORD dwAccessType,
    _In_  LPWSTR lpszProxyName,
    _In_  LPWSTR lpszProxyBypass,
    _In_  DWORD dwFlags
) {
    HINTERNET ret = Old_InternetOpenW(lpszAgent, dwAccessType, lpszProxyName,
        lpszProxyBypass, dwFlags);

	if (g_config.url_of_interest && g_config.suspend_logging)
		g_config.suspend_logging = FALSE;

	LOQ_nonnull("network", "uhuuh", "Agent", lpszAgent, "AccessType", dwAccessType,
        "ProxyName", lpszProxyName, "ProxyBypass", lpszProxyBypass,
        "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetConnectA,
    _In_  HINTERNET hInternet,
    _In_  LPCTSTR lpszServerName,
    _In_  INTERNET_PORT nServerPort,
    _In_  LPCTSTR lpszUsername,
    _In_  LPCTSTR lpszPassword,
    _In_  DWORD dwService,
    _In_  DWORD dwFlags,
    _In_  DWORD_PTR dwContext
) {
    if (g_config.dump_config_region) {
        if (DumpRegion((PVOID)lpszServerName))
            DoOutputDebugString("InternetConnectA hook: Successfully dumped region at 0x%p.\n", lpszServerName);
        else
            DoOutputDebugString("InternetConnectA hook: Failed to dump region at 0x%p.\n", lpszServerName);
    }
	HINTERNET ret = Old_InternetConnectA(hInternet, lpszServerName,
        nServerPort, lpszUsername, lpszPassword, dwService, dwFlags,
        dwContext);
    LOQ_nonnull("network", "psissih", "InternetHandle", hInternet, "ServerName", lpszServerName,
        "ServerPort", nServerPort, "Username", lpszUsername,
        "Password", lpszPassword, "Service", dwService, "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetConnectW,
    _In_  HINTERNET hInternet,
    _In_  LPWSTR lpszServerName,
    _In_  INTERNET_PORT nServerPort,
    _In_  LPWSTR lpszUsername,
    _In_  LPWSTR lpszPassword,
    _In_  DWORD dwService,
    _In_  DWORD dwFlags,
    _In_  DWORD_PTR dwContext
) {
    if (g_config.dump_config_region) {
        if (DumpRegion((PVOID)lpszServerName))
            DoOutputDebugString("InternetConnectW hook: Successfully dumped region at 0x%p.\n", lpszServerName);
        else
            DoOutputDebugString("InternetConnectW hook: Failed to dump region at 0x%p.\n", lpszServerName);
    }
    HINTERNET ret = Old_InternetConnectW(hInternet, lpszServerName,
        nServerPort, lpszUsername, lpszPassword, dwService, dwFlags,
        dwContext);
    LOQ_nonnull("network", "puiuuih", "InternetHandle", hInternet, "ServerName", lpszServerName,
        "ServerPort", nServerPort, "Username", lpszUsername,
        "Password", lpszPassword, "Service", dwService, "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetOpenUrlA,
    __in  HINTERNET hInternet,
    __in  LPCTSTR lpszUrl,
    __in  LPCTSTR lpszHeaders,
    __in  DWORD dwHeadersLength,
    __in  DWORD dwFlags,
    __in  DWORD_PTR dwContext
) {
    if (g_config.dump_config_region) {
        if (DumpRegion((PVOID)lpszUrl))
            DoOutputDebugString("InternetOpenUrlA hook: Successfully dumped region at 0x%p.\n", lpszUrl);
        else
            DoOutputDebugString("InternetOpenUrlA hook: Failed to dump region at 0x%p.\n", lpszUrl);
    }
    HINTERNET ret = Old_InternetOpenUrlA(hInternet, lpszUrl, lpszHeaders,
        dwHeadersLength, dwFlags, dwContext);
    LOQ_nonnull("network", "psSh", "ConnectionHandle", hInternet, "URL", lpszUrl,
        "Headers", dwHeadersLength, lpszHeaders, "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetOpenUrlW,
    __in  HINTERNET hInternet,
    __in  LPWSTR lpszUrl,
    __in  LPWSTR lpszHeaders,
    __in  DWORD dwHeadersLength,
    __in  DWORD dwFlags,
    __in  DWORD_PTR dwContext
) {
    if (g_config.dump_config_region) {
        if (DumpRegion((PVOID)lpszUrl))
            DoOutputDebugString("InternetOpenUrlW hook: Successfully dumped region at 0x%p.\n", lpszUrl);
        else
            DoOutputDebugString("InternetOpenUrlW hook: Failed to dump region at 0x%p.\n", lpszUrl);
    }
    HINTERNET ret = Old_InternetOpenUrlW(hInternet, lpszUrl, lpszHeaders,
        dwHeadersLength, dwFlags, dwContext);
    LOQ_nonnull("network", "puUh", "ConnectionHandle", hInternet, "URL", lpszUrl,
        "Headers", dwHeadersLength, lpszHeaders, "Flags", dwFlags);
    return ret;
}

typedef BOOL(WINAPI *__HttpAddRequestHeadersA)(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers);
__HttpAddRequestHeadersA _HttpAddRequestHeadersA;

void workaround_httpopenrequest_referrer_bug(HINTERNET hRequest)
{
	char *buf;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);
	buf = malloc(strlen("Referer: ") + strlen(g_config.referrer) + 3);

	if (!_HttpAddRequestHeadersA)
		_HttpAddRequestHeadersA = (__HttpAddRequestHeadersA)GetProcAddress(LoadLibraryA("wininet"), "HttpAddRequestHeadersA");
	strcpy(buf, "Referer: ");
	strcat(buf, g_config.referrer);
	strcat(buf, "\r\n");
	_HttpAddRequestHeadersA(hRequest, buf, -1, HTTP_ADDREQ_FLAG_ADD_IF_NEW);
	free(buf);
	set_lasterrors(&lasterror);
}

HOOKDEF(HINTERNET, WINAPI, HttpOpenRequestA,
    __in  HINTERNET hConnect,
    __in  LPCSTR lpszVerb,
    __in  LPCSTR lpszObjectName,
    __in  LPCSTR lpszVersion,
    __in  LPCSTR lpszReferer,
    __in  LPCSTR *lplpszAcceptTypes,
    __in  DWORD dwFlags,
    __in  DWORD_PTR dwContext
) {
	HINTERNET ret;
	LPCSTR referer;

	if ((lpszReferer == NULL || !strcmp(lpszReferer, "")) && g_config.url_of_interest && g_config.referrer && strlen(g_config.referrer) && !did_initial_request)
		referer = g_config.referrer;
	else
		referer = lpszReferer;

	ret = Old_HttpOpenRequestA(hConnect, lpszVerb, lpszObjectName,
		lpszVersion, lpszReferer, lplpszAcceptTypes, dwFlags, dwContext);
    LOQ_nonnull("network", "pshss", "InternetHandle", hConnect, "Path", lpszObjectName,
        "Flags", dwFlags, "Referrer", referer, "Verb", lpszVerb);

	if (ret && referer != lpszReferer)
		workaround_httpopenrequest_referrer_bug(ret);

	did_initial_request = TRUE;

    return ret;
}

HOOKDEF(HINTERNET, WINAPI, HttpOpenRequestW,
    __in  HINTERNET hConnect,
    __in  LPCWSTR lpszVerb,
    __in  LPCWSTR lpszObjectName,
    __in  LPCWSTR lpszVersion,
    __in  LPCWSTR lpszReferer,
    __in  LPCWSTR *lplpszAcceptTypes,
    __in  DWORD dwFlags,
    __in  DWORD_PTR dwContext
) {
	HINTERNET ret;
	LPCWSTR referer;

	if ((lpszReferer == NULL || !wcscmp(lpszReferer, L"")) && g_config.url_of_interest && g_config.w_referrer && wcslen(g_config.w_referrer) && !did_initial_request)
		referer = g_config.w_referrer;
	else
		referer = lpszReferer; 
	
	ret = Old_HttpOpenRequestW(hConnect, lpszVerb, lpszObjectName,
		lpszVersion, lpszReferer, lplpszAcceptTypes, dwFlags, dwContext);
    LOQ_nonnull("network", "puhuu", "InternetHandle", hConnect, "Path", lpszObjectName,
		"Flags", dwFlags, "Referrer", referer, "Verb", lpszVerb);

	if (ret && referer != lpszReferer)
		workaround_httpopenrequest_referrer_bug(ret);

	did_initial_request = TRUE;

	return ret;
}

HOOKDEF(BOOL, WINAPI, HttpSendRequestA,
    __in  HINTERNET hRequest,
    __in  LPCTSTR lpszHeaders,
    __in  DWORD dwHeadersLength,
    __in  LPVOID lpOptional,
    __in  DWORD dwOptionalLength
) {
    BOOL ret = Old_HttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength,
        lpOptional, dwOptionalLength);

	if (g_config.url_of_interest && g_config.suspend_logging)
		g_config.suspend_logging = FALSE;

	if(dwHeadersLength == (DWORD) -1 && lpszHeaders != NULL) dwHeadersLength = (DWORD)strlen(lpszHeaders);
    LOQ_bool("network", "pSb", "RequestHandle", hRequest,
        "Headers", dwHeadersLength, lpszHeaders,
        "PostData", dwOptionalLength, lpOptional);
    return ret;
}

HOOKDEF(BOOL, WINAPI, HttpSendRequestW,
    __in  HINTERNET hRequest,
    __in  LPWSTR lpszHeaders,
    __in  DWORD dwHeadersLength,
    __in  LPVOID lpOptional,
    __in  DWORD dwOptionalLength
) {
    BOOL ret = Old_HttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength,
        lpOptional, dwOptionalLength);

	if (g_config.url_of_interest && g_config.suspend_logging)
		g_config.suspend_logging = FALSE;
	
	LOQ_bool("network", "pUb", "RequestHandle", hRequest,
        "Headers", dwHeadersLength, lpszHeaders,
        "PostData", dwOptionalLength, lpOptional);
    return ret;
}

HOOKDEF(BOOL, WINAPI, HttpSendRequestExA,
	__in  HINTERNET hRequest,
	__in  LPINTERNET_BUFFERSA lpBuffersIn,
	__out LPINTERNET_BUFFERSA lpBuffersOut,
	__in  DWORD dwFlags,
	__in  DWORD_PTR dwContext
) {
	BOOL ret = Old_HttpSendRequestExA(hRequest, lpBuffersIn, lpBuffersOut, dwFlags, dwContext);

	if (g_config.url_of_interest && g_config.suspend_logging)
		g_config.suspend_logging = FALSE;

	/* TODO: handle entire chain of buffers */
	if (lpBuffersIn && lpBuffersIn->dwStructSize >= sizeof(INTERNET_BUFFERSA)) {
		LOQ_bool("network", "pSbh", "RequestHandle", hRequest,
			"Headers", lpBuffersIn->dwHeadersLength, lpBuffersIn->lpcszHeader,
			"PostData", lpBuffersIn->dwBufferLength, lpBuffersIn->lpvBuffer,
			"Flags", dwFlags);
	}
	else {
		LOQ_bool("network", "ph", "RequestHandle", hRequest, "Flags", dwFlags);
	}
	return ret;
}

HOOKDEF(BOOL, WINAPI, HttpSendRequestExW,
	__in  HINTERNET hRequest,
	__in  LPINTERNET_BUFFERSW lpBuffersIn,
	__out LPINTERNET_BUFFERSW lpBuffersOut,
	__in  DWORD dwFlags,
	__in  DWORD_PTR dwContext
) {
	BOOL ret = Old_HttpSendRequestExW(hRequest, lpBuffersIn, lpBuffersOut, dwFlags, dwContext);

	if (g_config.url_of_interest && g_config.suspend_logging)
		g_config.suspend_logging = FALSE;

	/* TODO: handle entire chain of buffers */
	if (lpBuffersIn && lpBuffersIn->dwStructSize >= sizeof(INTERNET_BUFFERSW)) {
		LOQ_bool("network", "pUbh", "RequestHandle", hRequest,
			"Headers", lpBuffersIn->dwHeadersLength, lpBuffersIn->lpcszHeader,
			"PostData", lpBuffersIn->dwBufferLength, lpBuffersIn->lpvBuffer,
			"Flags", dwFlags);
	}
	else {
		LOQ_bool("network", "ph", "RequestHandle", hRequest, "Flags", dwFlags);
	}
	return ret;
}

HOOKDEF(BOOL, WINAPI, HttpEndRequestA,
	__in  HINTERNET hRequest,
	__out LPINTERNET_BUFFERSA lpBuffersOut,
	__in  DWORD dwFlags,
	__in  DWORD_PTR dwContext
) {
	BOOL ret = Old_HttpEndRequestA(hRequest, lpBuffersOut, dwFlags, dwContext);
	LOQ_bool("network", "p", "RequestHandle", hRequest);
	return ret;
}

HOOKDEF(BOOL, WINAPI, HttpEndRequestW,
	__in  HINTERNET hRequest,
	__out LPINTERNET_BUFFERSW lpBuffersOut,
	__in  DWORD dwFlags,
	__in  DWORD_PTR dwContext
) {
	BOOL ret = Old_HttpEndRequestW(hRequest, lpBuffersOut, dwFlags, dwContext);
	LOQ_bool("network", "p", "RequestHandle", hRequest);
	return ret;
}


HOOKDEF(BOOL, WINAPI, HttpAddRequestHeadersA,
	__in HINTERNET hRequest,
	__in LPCSTR lpszHeaders,
	__in DWORD dwHeadersLength,
	__in DWORD dwModifiers
) {
	BOOL ret = Old_HttpAddRequestHeadersA(hRequest, lpszHeaders, dwHeadersLength, dwModifiers);
	if (dwHeadersLength == (DWORD)-1 && lpszHeaders != NULL) dwHeadersLength = (DWORD)strlen(lpszHeaders);
	LOQ_bool("network", "pSh", "RequestHandle", hRequest,
		"Headers", dwHeadersLength, lpszHeaders,
		"Modifiers", dwModifiers);
	return ret;
}

HOOKDEF(BOOL, WINAPI, HttpAddRequestHeadersW,
	__in HINTERNET hRequest,
	__in LPCWSTR lpszHeaders,
	__in DWORD dwHeadersLength,
	__in DWORD dwModifiers
) {
	BOOL ret = Old_HttpAddRequestHeadersW(hRequest, lpszHeaders, dwHeadersLength, dwModifiers);
	if (dwHeadersLength == (DWORD)-1 && lpszHeaders != NULL) dwHeadersLength = (DWORD)wcslen(lpszHeaders);
	LOQ_bool("network", "pUh", "RequestHandle", hRequest,
		"Headers", dwHeadersLength, lpszHeaders,
		"Modifiers", dwModifiers);
	return ret;
}

HOOKDEF(BOOL, WINAPI, HttpQueryInfoA,
	_In_    HINTERNET hRequest,
	_In_    DWORD     dwInfoLevel,
	_Inout_ LPVOID    lpvBuffer,
	_Inout_ LPDWORD   lpdwBufferLength,
	_Inout_ LPDWORD   lpdwIndex
) {
	BOOL ret = Old_HttpQueryInfoA(hRequest, dwInfoLevel, lpvBuffer, lpdwBufferLength, lpdwIndex);
	if (dwInfoLevel == HTTP_QUERY_DATE || dwInfoLevel == HTTP_QUERY_EXPIRES || dwInfoLevel == HTTP_QUERY_REQUEST_METHOD || dwInfoLevel == HTTP_QUERY_CONTENT_TYPE || dwInfoLevel == HTTP_QUERY_STATUS_TEXT || dwInfoLevel == HTTP_QUERY_RAW_HEADERS_CRLF)
		LOQ_bool("network", "phS", "RequestHandle", hRequest, "InfoLevel", dwInfoLevel, "Buffer", ret ? *lpdwBufferLength : 0, lpvBuffer);
	else
		LOQ_bool("network", "phB", "RequestHandle", hRequest, "InfoLevel", dwInfoLevel, "Buffer", lpdwBufferLength, lpvBuffer);
	return ret;
}

HOOKDEF(BOOL, WINAPI, HttpQueryInfoW,
	_In_    HINTERNET hRequest,
	_In_    DWORD     dwInfoLevel,
	_Inout_ LPVOID    lpvBuffer,
	_Inout_ LPDWORD   lpdwBufferLength,
	_Inout_ LPDWORD   lpdwIndex
) {
	BOOL ret = Old_HttpQueryInfoW(hRequest, dwInfoLevel, lpvBuffer, lpdwBufferLength, lpdwIndex);
	if (dwInfoLevel == HTTP_QUERY_DATE || dwInfoLevel == HTTP_QUERY_EXPIRES || dwInfoLevel == HTTP_QUERY_REQUEST_METHOD || dwInfoLevel == HTTP_QUERY_CONTENT_TYPE || dwInfoLevel == HTTP_QUERY_STATUS_TEXT || dwInfoLevel == HTTP_QUERY_RAW_HEADERS_CRLF)
		LOQ_bool("network", "phU", "RequestHandle", hRequest, "InfoLevel", dwInfoLevel, "Buffer", ret ? (*lpdwBufferLength / sizeof(WCHAR)) : 0, lpvBuffer);
	else
		LOQ_bool("network", "phB", "RequestHandle", hRequest, "InfoLevel", dwInfoLevel, "Buffer", lpdwBufferLength, lpvBuffer);
	return ret;
}


HOOKDEF(int, WINAPI, NSPStartup,
	__in LPGUID lpProviderId,
	__out PVOID lpnspRoutines
) {
	int ret = Old_NSPStartup(lpProviderId, lpnspRoutines);
	LOQ_zero("network", "");
	return ret;
}
HOOKDEF(BOOL, WINAPI, InternetReadFile,
    _In_   HINTERNET hFile,
    _Out_  LPVOID lpBuffer,
    _In_   DWORD dwNumberOfBytesToRead,
    _Out_  LPDWORD lpdwNumberOfBytesRead
) {
    BOOL ret = Old_InternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
    if (is_bytes_in_buf(lpBuffer, *lpdwNumberOfBytesRead, "\x00\x50\x4f\x4c\x49\x4d\x4f\x52\x46\x00", 10, 256))
      LOQ_bool("network", "pCI", "InternetHandle", hFile, "Buffer", lpdwNumberOfBytesRead, lpBuffer, "BytesRead", lpdwNumberOfBytesRead);
    else
      LOQ_bool("network", "pBI", "InternetHandle", hFile, "Buffer", lpdwNumberOfBytesRead, lpBuffer, "BytesRead", lpdwNumberOfBytesRead);

    return ret;
}

HOOKDEF(BOOL, WINAPI, InternetWriteFile,
    _In_   HINTERNET hFile,
    _In_   LPCVOID lpBuffer,
    _In_   DWORD dwNumberOfBytesToWrite,
    _Out_  LPDWORD lpdwNumberOfBytesWritten
) {
    BOOL ret = Old_InternetWriteFile(hFile, lpBuffer, dwNumberOfBytesToWrite,
        lpdwNumberOfBytesWritten);
    LOQ_bool("network", "pB", "InternetHandle", hFile,
        "Buffer", lpdwNumberOfBytesWritten, lpBuffer);
    return ret;
}

HOOKDEF(BOOL, WINAPI, InternetCloseHandle,
    _In_  HINTERNET hInternet
) {
    BOOL ret = Old_InternetCloseHandle(hInternet);
    LOQ_bool("network", "p", "InternetHandle", hInternet);
    return ret;
}

#ifndef CAPE_HANCITOR
HOOKDEF(BOOL, WINAPI, InternetCrackUrlA,
	_In_ LPCSTR lpszUrl,
	_In_ DWORD dwUrlLength,
	_In_ DWORD dwFlags,
	_Inout_ LPURL_COMPONENTSA lpUrlComponents
) {
    if (g_config.dump_config_region) {
        if (DumpRegion((PVOID)lpszUrl))
            DoOutputDebugString("InternetCrackUrlA hook: Successfully dumped region at 0x%p.\n", lpszUrl);
        else
            DoOutputDebugString("InternetCrackUrlA hook: Failed to dump region at 0x%p.\n", lpszUrl);
    }
	BOOL ret = Old_InternetCrackUrlA(lpszUrl, dwUrlLength, dwFlags, lpUrlComponents);
	LOQ_bool("network", "s", "Url", lpszUrl);
	return ret;
}
#endif

HOOKDEF(BOOL, WINAPI, InternetCrackUrlW,
	_In_ LPCWSTR lpszUrl,
	_In_ DWORD dwUrlLength,
	_In_ DWORD dwFlags,
	_Inout_ LPURL_COMPONENTSW lpUrlComponents
) {
    if (g_config.dump_config_region) {
        if (DumpRegion((PVOID)lpszUrl))
            DoOutputDebugString("InternetCrackUrlW hook: Successfully dumped region at 0x%p.\n", lpszUrl);
        else
            DoOutputDebugString("InternetCrackUrlW hook: Failed to dump region at 0x%p.\n", lpszUrl);
    }
	BOOL ret = Old_InternetCrackUrlW(lpszUrl, dwUrlLength, dwFlags, lpUrlComponents);
	LOQ_bool("network", "u", "Url", lpszUrl);
	return ret;
}

HOOKDEF(BOOL, WINAPI, InternetSetOptionA,
	_In_ HINTERNET hInternet,
	_In_ DWORD dwOption,
	_In_ LPVOID lpBuffer,
	_In_ DWORD dwBufferLength
) {
	BOOL ret = Old_InternetSetOptionA(hInternet, dwOption, lpBuffer, dwBufferLength);
	if (lpBuffer && dwBufferLength == 4) {
		LOQ_bool("network", "phH", "InternetHandle", hInternet, "Option", dwOption, "Buffer", lpBuffer);
	}
	else if (lpBuffer) {
		LOQ_bool("network", "phb", "InternetHandle", hInternet, "Option", dwOption, "Buffer", dwBufferLength, lpBuffer);
	}
	else {
		LOQ_bool("network", "ph", "InternetHandle", hInternet, "Option", dwOption);
	}
	return ret;
}

HOOKDEF(DNS_STATUS, WINAPI, DnsQuery_A,
    __in         PCSTR lpstrName,
    __in         WORD wType,
    __in         DWORD Options,
    __inout_opt  PVOID pExtra,
    __out_opt    PDNS_RECORD *ppQueryResultsSet,
    __out_opt    PVOID *pReserved
) {
    DNS_STATUS ret = Old_DnsQuery_A(lpstrName, wType, Options, pExtra,
        ppQueryResultsSet, pReserved);

	if (g_config.url_of_interest && g_config.suspend_logging)
		g_config.suspend_logging = FALSE;

	LOQ_zero("network", "sih", "Name", lpstrName, "Type", wType, "Options", Options);
    return ret;
}

HOOKDEF(DNS_STATUS, WINAPI, DnsQuery_UTF8,
    __in         LPBYTE lpstrName,
    __in         WORD wType,
    __in         DWORD Options,
    __inout_opt  PVOID pExtra,
    __out_opt    PDNS_RECORD *ppQueryResultsSet,
    __out_opt    PVOID *pReserved
) {
    DNS_STATUS ret = Old_DnsQuery_UTF8(lpstrName, wType, Options, pExtra,
        ppQueryResultsSet, pReserved);

	if (g_config.url_of_interest && g_config.suspend_logging)
		g_config.suspend_logging = FALSE;

	LOQ_zero("network", "sih", "Name", lpstrName, "Type", wType, "Options", Options);
    return ret;
}

HOOKDEF(DNS_STATUS, WINAPI, DnsQuery_W,
    __in         PWSTR lpstrName,
    __in         WORD wType,
    __in         DWORD Options,
    __inout_opt  PVOID pExtra,
    __out_opt    PDNS_RECORD *ppQueryResultsSet,
    __out_opt    PVOID *pReserved
) {
    DNS_STATUS ret = Old_DnsQuery_W(lpstrName, wType, Options, pExtra,
        ppQueryResultsSet, pReserved);

	if (g_config.url_of_interest && g_config.suspend_logging)
		g_config.suspend_logging = FALSE;

	LOQ_zero("network", "uih", "Name", lpstrName, "Type", wType, "Options", Options);
    return ret;
}

HOOKDEF(int, WINAPI, getaddrinfo,
    _In_opt_  PCSTR pNodeName,
    _In_opt_  PCSTR pServiceName,
    _In_opt_  const ADDRINFOA *pHints,
    _Out_     PADDRINFOA *ppResult
) {
	int ret = Old_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);

	if (g_config.url_of_interest && g_config.suspend_logging)
		g_config.suspend_logging = FALSE;

	LOQ_zero("network", "ss", "NodeName", pNodeName, "ServiceName", pServiceName);
    return ret;
}

HOOKDEF(int, WINAPI, GetAddrInfoW,
    _In_opt_  PCWSTR pNodeName,
    _In_opt_  PCWSTR pServiceName,
    _In_opt_  const ADDRINFOW *pHints,
    _Out_     PADDRINFOW *ppResult
) {
    int ret = Old_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);

	if (g_config.url_of_interest && g_config.suspend_logging)
		g_config.suspend_logging = FALSE;

	LOQ_zero("network", "uu", "NodeName", pNodeName, "ServiceName", pServiceName);
    return ret;
}

HOOKDEF(DWORD, WINAPI, WNetUseConnectionW,
	_In_     HWND hwndOwner,
	_In_     LPNETRESOURCEW lpNetResource,
	_In_     LPCWSTR lpPassword,
	_In_     LPCWSTR lpUserID,
	_In_     DWORD dwFlags,
	_Out_    LPWSTR lpAccessName,
	_Inout_  LPDWORD lpBufferSize,
	_Out_    LPDWORD lpResult
) {
	DWORD ret = Old_WNetUseConnectionW(hwndOwner, lpNetResource, lpPassword, lpUserID, dwFlags, lpAccessName, lpBufferSize, lpResult);
	LOQ_zero("network", "uuuuuh", "LocalName", lpNetResource ? lpNetResource->lpLocalName : NULL,
		     "RemoteName", lpNetResource ? lpNetResource->lpRemoteName : NULL, "Password", lpPassword, "UserID", lpUserID, "AccessName", lpAccessName, "Flags", dwFlags);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CryptRetrieveObjectByUrlW,
	_In_     LPCWSTR                  pszUrl,
	_In_     LPCSTR                   pszObjectOid,
	_In_     DWORD                    dwRetrievalFlags,
	_In_     DWORD                    dwTimeout,
	_Out_    LPVOID                   *ppvObject,
	_In_     HCRYPTASYNC              hAsyncRetrieve,
	_In_opt_ PCRYPT_CREDENTIALS       pCredentials,
	_In_opt_ LPVOID                   pvVerify,
	_In_     PCRYPT_RETRIEVE_AUX_INFO pAuxInfo
) {
	BOOL ret = Old_CryptRetrieveObjectByUrlW(pszUrl, pszObjectOid, dwRetrievalFlags, dwTimeout, ppvObject, hAsyncRetrieve, pCredentials, pvVerify, pAuxInfo);
	LOQ_bool("network", "u", "URL", pszUrl);
	return ret;
}

HOOKDEF(ULONG, WINAPI, GetAdaptersAddresses,
	_In_    ULONG                 Family,
	_In_    ULONG                 Flags,
	_In_    PVOID                 Reserved,
	_Inout_ PVOID				  AdapterAddresses, // PIP_ADAPTER_ADDRESSES
	_Inout_ PULONG                SizePointer
) {
	ULONG ret = Old_GetAdaptersAddresses(Family, Flags, Reserved, AdapterAddresses, SizePointer);
	LOQ_zero("network", "");
	return ret;
}

HOOKDEF(DWORD, WINAPI, GetAdaptersInfo,
	_Out_   PVOID pAdapterInfo, // PIP_ADAPTER_INFO
	_Inout_ PULONG           pOutBufLen
) {
	DWORD ret = Old_GetAdaptersInfo(pAdapterInfo, pOutBufLen);
	LOQ_zero("network", "");
	return ret;
}

HOOKDEF(ULONG, WINAPI, NetGetJoinInformation,
	_In_  LPCWSTR               lpServer,
	_Out_ LPWSTR                *lpNameBuffer,
	_Out_ DWORD *				BufferType
) {
	ULONG ret = Old_NetGetJoinInformation(lpServer, lpNameBuffer, BufferType);

	LOQ_zero("network", "uuI", "Server", lpServer, "NetBIOSName", *lpNameBuffer, "JoinStatus", BufferType);

	return ret;
}

HOOKDEF(ULONG, WINAPI, NetUserGetLocalGroups,
	_In_  LPCWSTR servername,
	_In_  LPCWSTR username,
	_In_  DWORD   level,
	_In_  DWORD   flags,
	_Out_ LPBYTE  *bufptr,
	_In_  DWORD   prefmaxlen,
	_Out_ LPDWORD entriesread,
	_Out_ LPDWORD totalentries
) {
	ULONG ret = Old_NetUserGetLocalGroups(servername, username, level, flags, bufptr, prefmaxlen, entriesread, totalentries);

	LOQ_zero("network", "uui", "ServerName", servername, "UserName", username, "Level", level);

	return ret;
}

HOOKDEF(HRESULT, WINAPI, CoInternetSetFeatureEnabled,
	INTERNETFEATURELIST FeatureEntry,
	_In_ DWORD			dwFlags,
	BOOL				fEnable
) {
	HRESULT ret = Old_CoInternetSetFeatureEnabled(FeatureEntry, dwFlags, fEnable);

	LOQ_hresult("network", "ihi", "FeatureEntry", FeatureEntry, "Flags", dwFlags, "Enable", fEnable);

	return ret;
}
