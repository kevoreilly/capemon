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
#include "pipe.h"
#include "log.h"

#define StringAtomSize 0x100

extern void ProcessMessage(DWORD ProcessId, DWORD ThreadId);
extern void DumpSectionViewsForPid(DWORD Pid);

typedef DWORD (WINAPI * __GetWindowThreadProcessId)(
	__in HWND hWnd,
	__out_opt LPDWORD lpdwProcessId
);

__GetWindowThreadProcessId _GetWindowThreadProcessId;

DWORD WINAPI our_GetWindowThreadProcessId(
	__in HWND hWnd,
	__out_opt LPDWORD lpdwProcessId
) {
	lasterror_t lasterror;
	DWORD ret;

	get_lasterrors(&lasterror);
	if (!_GetWindowThreadProcessId) {
		_GetWindowThreadProcessId = (__GetWindowThreadProcessId)GetProcAddress(LoadLibraryA("user32"), "GetWindowThreadProcessId");
	}
	ret = _GetWindowThreadProcessId(hWnd, lpdwProcessId);
	set_lasterrors(&lasterror);
	return ret;
}

typedef DWORD(WINAPI * __GetClassNameA)(
	_In_  HWND   hWnd,
	_Out_ LPTSTR lpClassName,
	_In_  int	nMaxCount
);

__GetClassNameA _GetClassNameA;

DWORD WINAPI our_GetClassNameA(
	_In_  HWND   hWnd,
	_Out_ LPSTR lpClassName,
	_In_  int	nMaxCount
) {
	lasterror_t lasterror;
	DWORD ret;

	get_lasterrors(&lasterror);
	if (!_GetClassNameA) {
		_GetClassNameA = (__GetClassNameA)GetProcAddress(LoadLibraryA("user32"), "GetClassNameA");
	}
	ret = _GetClassNameA(hWnd, lpClassName, nMaxCount);
	set_lasterrors(&lasterror);
	return ret;
}

HOOKDEF(HWND, WINAPI, FindWindowA,
	__in_opt  LPCTSTR lpClassName,
	__in_opt  LPCTSTR lpWindowName
) {
	// The atom must be in the low-order word of lpClassName;
	// the high-order word must be zero (from MSDN documentation.)
	HWND ret = Old_FindWindowA(lpClassName, lpWindowName);
	if(((DWORD_PTR) lpClassName & 0xffff) == (DWORD_PTR) lpClassName) {
		LOQ_nonnull("windows", "is", "ClassName", lpClassName, "WindowName", lpWindowName);
	}
	else {
		LOQ_nonnull("windows", "ss", "ClassName", lpClassName, "WindowName", lpWindowName);
	}
	return ret;
}

HOOKDEF(HWND, WINAPI, FindWindowW,
	__in_opt  LPWSTR lpClassName,
	__in_opt  LPWSTR lpWindowName
) {
	HWND ret = Old_FindWindowW(lpClassName, lpWindowName);
	if(((DWORD_PTR) lpClassName & 0xffff) == (DWORD_PTR) lpClassName) {
		LOQ_nonnull("windows", "iu", "ClassName", lpClassName, "WindowName", lpWindowName);
	}
	else {
		LOQ_nonnull("windows", "uu", "ClassName", lpClassName, "WindowName", lpWindowName);
	}
	return ret;
}

HOOKDEF(HWND, WINAPI, FindWindowExA,
	__in_opt  HWND hwndParent,
	__in_opt  HWND hwndChildAfter,
	__in_opt  LPCTSTR lpszClass,
	__in_opt  LPCTSTR lpszWindow
) {
	HWND ret = Old_FindWindowExA(hwndParent, hwndChildAfter, lpszClass,
		lpszWindow);

	// lpszClass can be one of the predefined window controls.. which lay in
	// the 0..ffff range
	if(((DWORD_PTR) lpszClass & 0xffff) == (DWORD_PTR) lpszClass) {
		LOQ_nonnull("windows", "is", "ClassName", lpszClass, "WindowName", lpszWindow);
	}
	else {
		LOQ_nonnull("windows", "ss", "ClassName", lpszClass, "WindowName", lpszWindow);
	}
	return ret;
}

HOOKDEF(HWND, WINAPI, FindWindowExW,
	__in_opt  HWND hwndParent,
	__in_opt  HWND hwndChildAfter,
	__in_opt  LPWSTR lpszClass,
	__in_opt  LPWSTR lpszWindow
) {
	HWND ret = Old_FindWindowExW(hwndParent, hwndChildAfter, lpszClass,
		lpszWindow);
	// lpszClass can be one of the predefined window controls.. which lay in
	// the 0..ffff range
	if(((DWORD_PTR) lpszClass & 0xffff) == (DWORD_PTR) lpszClass) {
		LOQ_nonnull("windows", "iu", "ClassName", lpszClass, "WindowName", lpszWindow);
	}
	else {
		LOQ_nonnull("windows", "uu", "ClassName", lpszClass, "WindowName", lpszWindow);
	}
	return ret;
}

HOOKDEF(BOOL, WINAPI, PostMessageA,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
) {
	BOOL ret = Old_PostMessageA(hWnd, Msg, wParam, lParam);

	LOQ_bool("windows", "ph", "WindowHandle", hWnd, "Message", Msg);

	return ret;
}

HOOKDEF(BOOL, WINAPI, PostMessageW,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
) {
	BOOL ret = Old_PostMessageW(hWnd, Msg, wParam, lParam);

	LOQ_bool("windows", "ph", "WindowHandle", hWnd, "Message", Msg);

	return ret;
}

HOOKDEF(BOOL, WINAPI, PostThreadMessageA,
	_In_  DWORD idThread,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
) {
	BOOL ret = Old_PostThreadMessageA(idThread, Msg, wParam, lParam);

	LOQ_bool("windows", "pi", "ThreadId", idThread, "Message", Msg);

	return ret;
}

HOOKDEF(BOOL, WINAPI, PostThreadMessageW,
	_In_  DWORD idThread,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
) {
	BOOL ret = Old_PostThreadMessageW(idThread, Msg, wParam, lParam);

	LOQ_bool("windows", "pi", "ThreadId", idThread, "Message", Msg);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SendMessageA,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
) {
	BOOL ret = Old_SendMessageA(hWnd, Msg, wParam, lParam);

	LOQ_bool("windows", "ph", "WindowHandle", hWnd, "Message", Msg);

	return ret;
}

HOOKDEF(BOOL, WINAPI, SendMessageW,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
	) {
	BOOL ret = Old_SendMessageW(hWnd, Msg, wParam, lParam);

	LOQ_bool("windows", "ph", "WindowHandle", hWnd, "Message", Msg);

	return ret;
}

HOOKDEF(BOOL, WINAPI, SendNotifyMessageA,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
) {
	BOOL ret;
	DWORD pid;
	lasterror_t lasterror;

	ret = Old_SendNotifyMessageA(hWnd, Msg, wParam, lParam);

	LOQ_bool("windows", "ph", "WindowHandle", hWnd, "Message", Msg);

	get_lasterrors(&lasterror);
	if (hWnd) {
		our_GetWindowThreadProcessId(hWnd, &pid);
		if (pid != GetCurrentProcessId()) {
			DumpSectionViewsForPid(pid);
			ProcessMessage(pid, 0);
		}
	}
	set_lasterrors(&lasterror);

	return ret;
}

HOOKDEF(BOOL, WINAPI, SendNotifyMessageW,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
	) {
	BOOL ret;
	DWORD pid;
	lasterror_t lasterror;

	ret = Old_SendNotifyMessageW(hWnd, Msg, wParam, lParam);

	LOQ_bool("windows", "ph", "WindowHandle", hWnd, "Message", Msg);

	get_lasterrors(&lasterror);
	if (hWnd) {
		our_GetWindowThreadProcessId(hWnd, &pid);
		if (pid != GetCurrentProcessId()) {
			DumpSectionViewsForPid(pid);
			ProcessMessage(pid, 0);
		}
	}
	set_lasterrors(&lasterror);

	return ret;
}

HOOKDEF(LONG, WINAPI, SetWindowLongA,
	_In_ HWND hWnd,
	_In_ int nIndex,
	_In_ LONG dwNewLong
	) {
	DWORD pid;
	lasterror_t lasterror;
	LONG ret;
	BOOL isbad = FALSE;

	ret = Old_SetWindowLongA(hWnd, nIndex, dwNewLong);

	get_lasterrors(&lasterror);
	if (nIndex == 0 && hWnd) {
		our_GetWindowThreadProcessId(hWnd, &pid);
		if (pid != GetCurrentProcessId()) {
			char classname[StringAtomSize];
			memset(classname, 0, StringAtomSize);
			our_GetClassNameA(hWnd, classname, StringAtomSize);
			if (!stricmp(classname, "Shell_TrayWnd")) {
				DumpSectionViewsForPid(pid);
				ProcessMessage(pid, 0);
				isbad = TRUE;
			}
		}
	}
	set_lasterrors(&lasterror);

	if (isbad)
		LOQ_nonzero("windows", "pip", "WindowHandle", hWnd, "Index", nIndex, "NewLong", dwNewLong);

	return ret;
}

HOOKDEF(LONG_PTR, WINAPI, SetWindowLongPtrA,
	_In_ HWND hWnd,
	_In_ int nIndex,
	_In_ LONG_PTR dwNewLong
	) {
	DWORD pid;
	lasterror_t lasterror;
	LONG_PTR ret;
	BOOL isbad = FALSE;

	ret = Old_SetWindowLongPtrA(hWnd, nIndex, dwNewLong);

	get_lasterrors(&lasterror);
	if (nIndex == 0 && hWnd) {
		our_GetWindowThreadProcessId(hWnd, &pid);
		if (pid != GetCurrentProcessId()) {
			char classname[StringAtomSize];
			memset(classname, 0, StringAtomSize);
			our_GetClassNameA(hWnd, classname, StringAtomSize);
			if (!stricmp(classname, "Shell_TrayWnd")) {
				DumpSectionViewsForPid(pid);
				ProcessMessage(pid, 0);
				isbad = TRUE;
			}
		}
	}
	set_lasterrors(&lasterror);

	if (isbad)
		LOQ_nonzero("windows", "pip", "WindowHandle", hWnd, "Index", nIndex, "NewLong", dwNewLong);

	return ret;
}

HOOKDEF(LONG, WINAPI, SetWindowLongW,
	_In_ HWND hWnd,
	_In_ int nIndex,
	_In_ LONG dwNewLong
	) {
	DWORD pid;
	lasterror_t lasterror;
	LONG ret;
	BOOL isbad = FALSE;

	ret = Old_SetWindowLongW(hWnd, nIndex, dwNewLong);

	get_lasterrors(&lasterror);
	if (nIndex == 0 && hWnd) {
		our_GetWindowThreadProcessId(hWnd, &pid);
		if (pid != GetCurrentProcessId()) {
			char classname[StringAtomSize];
			memset(classname, 0, StringAtomSize);
			our_GetClassNameA(hWnd, classname, StringAtomSize);
			if (!stricmp(classname, "Shell_TrayWnd")) {
				DumpSectionViewsForPid(pid);
				ProcessMessage(pid, 0);
				isbad = TRUE;
			}
		}
	}
	set_lasterrors(&lasterror);

	if (isbad)
		LOQ_nonzero("windows", "pip", "WindowHandle", hWnd, "Index", nIndex, "NewLong", dwNewLong);

	return ret;

}

HOOKDEF(LONG_PTR, WINAPI, SetWindowLongPtrW,
	_In_ HWND hWnd,
	_In_ int nIndex,
	_In_ LONG_PTR dwNewLong
	) {
	DWORD pid;
	lasterror_t lasterror;
	LONG_PTR ret;
	BOOL isbad = FALSE;

	ret = Old_SetWindowLongPtrW(hWnd, nIndex, dwNewLong);

	get_lasterrors(&lasterror);
	if (nIndex == 0 && hWnd) {
		our_GetWindowThreadProcessId(hWnd, &pid);
		if (pid != GetCurrentProcessId()) {
			char classname[StringAtomSize];
			memset(classname, 0, StringAtomSize);
			our_GetClassNameA(hWnd, classname, StringAtomSize);
			if (!stricmp(classname, "Shell_TrayWnd")) {
				DumpSectionViewsForPid(pid);
				ProcessMessage(pid, 0);
				isbad = TRUE;
			}
		}
	}
	set_lasterrors(&lasterror);

	if (isbad)
		LOQ_nonzero("windows", "pip", "WindowHandle", hWnd, "Index", nIndex, "NewLong", dwNewLong);

	return ret;

}

HOOKDEF(BOOL, WINAPI, EnumWindows,
	_In_  WNDENUMPROC lpEnumFunc,
	_In_  LPARAM lParam
) {

	BOOL ret = Old_EnumWindows(lpEnumFunc, lParam);
	LOQ_bool("windows", "");
	return ret;
}

HOOKDEF_NOTAIL(WINAPI, CreateWindowExA,
	__in DWORD dwExStyle,
	__in_opt LPCSTR lpClassName,
	__in_opt LPCSTR lpWindowName,
	__in DWORD dwStyle,
	__in int x,
	__in int y,
	__in int nWidth,
	__in int nHeight,
	__in_opt HWND hWndParent,
	__in_opt HMENU hMenu,
	__in_opt HINSTANCE hInstance,
	__in_opt LPVOID lpParam
) {
	HWND ret = (HWND)1;
	// lpClassName can be one of the predefined window controls.. which lay in
	// the 0..ffff range
	if (((DWORD_PTR)lpClassName & 0xffff) == (DWORD_PTR)lpClassName) {
		LOQ_nonnull("windows", "isiiiih", "ClassName", lpClassName, "WindowName", lpWindowName, "x", x, "y", y, "Width", nWidth, "Height", nHeight, "Style", dwStyle);
	}
	else {
		LOQ_nonnull("windows", "ssiiiih", "ClassName", lpClassName, "WindowName", lpWindowName, "x", x, "y", y, "Width", nWidth, "Height", nHeight, "Style", dwStyle);
	}

	return 0;
}

HOOKDEF_NOTAIL(WINAPI, CreateWindowExW,
	__in DWORD dwExStyle,
	__in_opt LPWSTR lpClassName,
	__in_opt LPWSTR lpWindowName,
	__in DWORD dwStyle,
	__in int x,
	__in int y,
	__in int nWidth,
	__in int nHeight,
	__in_opt HWND hWndParent,
	__in_opt HMENU hMenu,
	__in_opt HINSTANCE hInstance,
	__in_opt LPVOID lpParam
) {
	HWND ret = (HWND)1;
	// lpClassName can be one of the predefined window controls.. which lay in
	// the 0..ffff range
	if (((DWORD_PTR)lpClassName & 0xffff) == (DWORD_PTR)lpClassName) {
		LOQ_nonnull("windows", "iuiiiih", "ClassName", lpClassName, "WindowName", lpWindowName, "x", x, "y", y, "Width", nWidth, "Height", nHeight, "Style", dwStyle);
	}
	else {
		LOQ_nonnull("windows", "uuiiiih", "ClassName", lpClassName, "WindowName", lpWindowName, "x", x, "y", y, "Width", nWidth, "Height", nHeight, "Style", dwStyle);
	}
	return 0;
}
