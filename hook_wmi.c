#include "log.h"
#include "misc.h"

HOOKDEF(HRESULT, WINAPI, WMI_Get,
	PVOID		_this,
	LPCWSTR		wszName,
	LONG		lFlags,
	VARIANT*	pVal,
	LONG*		pType,
	LONG*		plFlavor
) {
	HRESULT ret;
	ret = Old_WMI_Get(_this, wszName, lFlags, pVal, pType, plFlavor);
	LOQ_hresult("system", "u", "Name", wszName);
	//LOQ_hresult("system", "un", "Name", wszName, "Value", pVal);
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
	LOQ_hresult("system", "u", "Query", strQuery);
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
	LOQ_hresult("system", "uu", "ObjectPath", strObjectPath, "MethodName", strMethodName);
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
		LOQ_hresult("system", "u", "ObjectPath", L"[NULL or Empty]");
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