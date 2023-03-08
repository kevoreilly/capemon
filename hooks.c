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
#include "ntapi.h"
#include "misc.h"
#include "hooking.h"
#include "hooks.h"
#include "pipe.h"

extern char *our_process_name;
extern int path_is_system(const wchar_t *path_w);
extern int path_is_program_files(const wchar_t *path_w);
extern VOID CALLBACK New_DllLoadNotification(ULONG NotificationReason, const PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context);
extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern void ErrorOutput(_In_ LPCTSTR lpOutputString, ...);
extern DWORD GetTimeStamp(LPVOID Address);

struct _g_config g_config;
volatile int dummy_val;
hook_t* hooks;
SIZE_T hooks_size, hooks_arraysize;

void disable_tail_call_optimization(void)
{
	dummy_val++;
}

#define HOOK(library, funcname) {L###library, #funcname, NULL, NULL, \
	&New_##funcname, (void **) &Old_##funcname, NULL, FALSE, FALSE, 0, FALSE}

#define HOOK_SPECIAL(library, funcname) {L###library, #funcname, NULL, NULL, \
	&New_##funcname, (void **) &Old_##funcname, NULL, TRUE, FALSE, 0, FALSE}

#define HOOK_EMULATE(library, funcname) {L###library, #funcname, NULL, NULL, \
	&New_##funcname, (void **) &Old_##funcname, NULL, TRUE, TRUE, 0, FALSE}

#define HOOK_NOTAIL_ALT(library, funcname, numargs) {L###library, #funcname, NULL, NULL, \
	&New_##funcname, (void **) &Old_##funcname, &Alt_##funcname, TRUE, FALSE, numargs, TRUE}

#define HOOK_NOTAIL(library, funcname, numargs) {L###library, #funcname, NULL, NULL, \
	&New_##funcname, NULL, NULL, TRUE, FALSE, numargs, TRUE}

#define HOOK_FUNCRVA(library, funcname, timestamp, rva) {L###library, #funcname, NULL, NULL, \
	&New_##funcname, (void **) &Old_##funcname, NULL, FALSE, FALSE, 0, FALSE, timestamp, rva}

hook_t full_hooks[] = {

	//
	// Special Hooks
	//
	// NOTE: due to the fact that the "special" hooks don't use a hook count
	// (whereas the "normal" hooks, those with allow_hook_recursion set to
	// zero, do) we have to hook the "special" hooks first. Otherwise the
	// execution flow will end up in an infinite loop, because of hook count
	// and whatnot.
	//
	// In other words, do *NOT* place "special" hooks behind "normal" hooks.
	//

	HOOK_NOTAIL_ALT(ntdll, LdrLoadDll, 4),
	HOOK_NOTAIL(ntdll, LdrUnloadDll, 1),
	HOOK_SPECIAL(ntdll, NtCreateUserProcess),
	HOOK_SPECIAL(kernel32, CreateProcessInternalW),
	HOOK_SPECIAL(urlmon, IsValidURL),
	//HOOK(kernel32, lstrcpynA),
	//HOOK(kernel32, lstrcmpiA),
	HOOK_SPECIAL(jscript, COleScript_ParseScriptText),
	HOOK_NOTAIL(jscript, JsEval, 5),
	HOOK_SPECIAL(jscript9, JsParseScript),
	HOOK_NOTAIL(jscript9, JsRunScript, 4),
	HOOK_SPECIAL(mshtml, CDocument_write),
	// COM object creation hook
	HOOK_SPECIAL(ole32, CoCreateInstance),
	HOOK_SPECIAL(ole32, CoCreateInstanceEx),
	HOOK_SPECIAL(ole32, CoGetClassObject),
	HOOK_SPECIAL(combase, CoCreateInstance),
	HOOK_SPECIAL(combase, CoCreateInstanceEx),
	HOOK_SPECIAL(combase, CoGetClassObject),
	HOOK_NOTAIL_ALT(ntdll, RtlDispatchException, 2),
	HOOK_NOTAIL(ntdll, NtRaiseException, 3),
	// lowest variant of MoveFile()
	HOOK_NOTAIL_ALT(kernel32, MoveFileWithProgressW, 5),
	HOOK_NOTAIL_ALT(kernelbase, MoveFileWithProgressTransactedW, 6),
	HOOK_NOTAIL_ALT(kernel32, MoveFileWithProgressTransactedW, 6),

	// File Hooks
	HOOK(ntdll, NtQueryAttributesFile),
	HOOK(ntdll, NtQueryFullAttributesFile),
	HOOK(ntdll, NtCreateFile),
	HOOK(ntdll, NtOpenFile),
	HOOK(ntdll, NtReadFile),
	HOOK(ntdll, NtWriteFile),
	HOOK(ntdll, NtDeleteFile),
	HOOK(ntdll, NtDeviceIoControlFile),
	HOOK(ntdll, NtQueryDirectoryFile),
	HOOK(ntdll, NtQueryInformationFile),
	HOOK(ntdll, NtSetInformationFile),
	HOOK(ntdll, NtOpenDirectoryObject),
	HOOK(ntdll, NtCreateDirectoryObject),
	HOOK(ntdll, NtQueryDirectoryObject),
	HOOK(kernel32, CreateFileTransactedA),
	HOOK(kernel32, CreateFileTransactedW),
	// CreateDirectoryExA calls CreateDirectoryExW
	// CreateDirectoryW does not call CreateDirectoryExW
	HOOK(kernel32, CreateDirectoryW),
	HOOK(kernel32, CreateDirectoryExW),
	HOOK(kernel32, RemoveDirectoryA),
	HOOK(kernel32, RemoveDirectoryW),
	HOOK(kernel32, FindFirstFileExA),
	HOOK(kernel32, FindFirstFileExW),
	HOOK(kernel32, FindNextFileW),
	// Covered by NtCreateFile() but still grab this information
	HOOK(kernel32, CopyFileA),
	HOOK(kernel32, CopyFileW),
	HOOK_NOTAIL_ALT(kernel32, CopyFileExW, 6),
	// Covered by NtSetInformationFile() but still grab this information
	HOOK(kernel32, DeleteFileA),
	HOOK(kernel32, DeleteFileW),
	HOOK(kernel32, GetDiskFreeSpaceExA),
	HOOK(kernel32, GetDiskFreeSpaceExW),
	HOOK(kernel32, GetDiskFreeSpaceA),
	HOOK(kernel32, GetDiskFreeSpaceW),
	HOOK(kernel32, GetVolumeNameForVolumeMountPointW),
	HOOK(kernel32, GetVolumeInformationByHandleW),
	HOOK(shell32, SHGetFolderPathW),
	HOOK(shell32, SHGetKnownFolderPath),
	HOOK(shell32, SHGetFileInfoW),
	HOOK(version, GetFileVersionInfoW),
	HOOK(version, GetFileVersionInfoSizeW),
	HOOK(kernel32, FindFirstChangeNotificationW),

	// Registry Hooks
	// Note: Most, if not all, of the Registry API go natively from both the
	// A as well as the W versions. In other words, we have to hook all the
	// ascii *and* unicode APIs of those functions.
	HOOK(advapi32, RegOpenKeyExA),
	HOOK(advapi32, RegOpenKeyExW),
	HOOK(advapi32, RegCreateKeyExA),
	HOOK(advapi32, RegCreateKeyExW),
	// Note that RegDeleteKeyEx() is available for 64bit XP/Vista+
	HOOK(advapi32, RegDeleteKeyA),
	HOOK(advapi32, RegDeleteKeyW),
	// RegEnumKeyA() calls RegEnumKeyExA(), but RegEnumKeyW() does *not*
	// call RegEnumKeyExW()
	HOOK(advapi32, RegEnumKeyW),
	HOOK(advapi32, RegEnumKeyExA),
	HOOK(advapi32, RegEnumKeyExW),
	HOOK(advapi32, RegEnumValueA),
	HOOK(advapi32, RegEnumValueW),
	HOOK(advapi32, RegSetValueExA),
	HOOK(advapi32, RegSetValueExW),
	HOOK(advapi32, RegQueryValueExA),
	HOOK(advapi32, RegQueryValueExW),
	HOOK(advapi32, RegDeleteValueA),
	HOOK(advapi32, RegDeleteValueW),
	HOOK(advapi32, RegQueryInfoKeyA),
	HOOK(advapi32, RegQueryInfoKeyW),
	HOOK(advapi32, RegCloseKey),
	HOOK(advapi32, RegNotifyChangeKeyValue),
	// On newer versions of Windows, the above registry APIs are also accessible via kernel32 without
	// the need for advapi32 (and advapi32 will actually simply end up pointing into the kernel32 version).
	// Add these below to make sure we still end up hooking the APIs even if advapi32 isn't loaded
	HOOK(kernel32, RegOpenKeyExA),
	HOOK(kernel32, RegOpenKeyExW),
	HOOK(kernel32, RegCreateKeyExA),
	HOOK(kernel32, RegCreateKeyExW),
	HOOK(kernel32, RegDeleteKeyA),
	HOOK(kernel32, RegDeleteKeyW),
	HOOK(kernel32, RegEnumKeyW),
	HOOK(kernel32, RegEnumKeyExA),
	HOOK(kernel32, RegEnumKeyExW),
	HOOK(kernel32, RegEnumValueA),
	HOOK(kernel32, RegEnumValueW),
	HOOK(kernel32, RegSetValueExA),
	HOOK(kernel32, RegSetValueExW),
	HOOK(kernel32, RegQueryValueExA),
	HOOK(kernel32, RegQueryValueExW),
	HOOK(kernel32, RegDeleteValueA),
	HOOK(kernel32, RegDeleteValueW),
	HOOK(kernel32, RegQueryInfoKeyA),
	HOOK(kernel32, RegQueryInfoKeyW),
	HOOK(kernel32, RegCloseKey),
	HOOK(kernel32, RegNotifyChangeKeyValue),
	// Native Registry Hooks
	HOOK(ntdll, NtCreateKey),
	HOOK(ntdll, NtOpenKey),
	HOOK(ntdll, NtOpenKeyEx),
	HOOK(ntdll, NtRenameKey),
	HOOK(ntdll, NtReplaceKey),
	HOOK(ntdll, NtEnumerateKey),
	HOOK(ntdll, NtEnumerateValueKey),
	HOOK(ntdll, NtSetValueKey),
	HOOK(ntdll, NtQueryValueKey),
	HOOK(ntdll, NtQueryMultipleValueKey),
	HOOK(ntdll, NtDeleteKey),
	HOOK(ntdll, NtDeleteValueKey),
	HOOK(ntdll, NtLoadKey),
	HOOK(ntdll, NtLoadKey2),
	HOOK(ntdll, NtLoadKeyEx),
	HOOK(ntdll, NtQueryKey),
	HOOK(ntdll, NtSaveKey),
	HOOK(ntdll, NtSaveKeyEx),

	// Window Hooks
	HOOK(user32, FindWindowA),
	HOOK(user32, FindWindowW),
	HOOK(user32, FindWindowExA),
	HOOK(user32, FindWindowExW),
	HOOK(user32, PostMessageA),
	HOOK(user32, PostMessageW),
//	HOOK(user32, SendMessageA),	// maldoc detonation issues
//	HOOK(user32, SendMessageW),	//
	HOOK(user32, SendNotifyMessageA),
	HOOK(user32, SendNotifyMessageW),
	HOOK(user32, SetWindowLongA),
	HOOK(user32, SetWindowLongW),
	HOOK(user32, SetWindowLongPtrA),
	HOOK(user32, SetWindowLongPtrW),
//	HOOK_NOTAIL(user32, CreateWindowExA, 12),	// maldoc detonation issues
//	HOOK_NOTAIL(user32, CreateWindowExW, 12),	//
//	HOOK(user32, EnumWindows),	// Disable for now, invokes a user-specified callback that can contain
	// calls to any functions that we won't end up logging. We need another hook type which
	// logs the hook and then every function called by that hook (modulo perhaps some blacklisted
	// functions for this specific hook type)

	// Sync Hooks
	HOOK(ntdll, NtCreateMutant),
	HOOK(ntdll, NtOpenMutant),
	HOOK(ntdll, NtReleaseMutant),
	HOOK(ntdll, NtCreateEvent),
	HOOK(ntdll, NtOpenEvent),
	HOOK(ntdll, NtCreateNamedPipeFile),
	HOOK(ntdll, NtAddAtom),
	HOOK(ntdll, NtAddAtomEx),
	HOOK(ntdll, NtFindAtom),
	HOOK(ntdll, NtDeleteAtom),
	HOOK(ntdll, NtQueryInformationAtom),

	// Process Hooks
	HOOK(ntdll, NtAllocateVirtualMemory),
	HOOK(ntdll, NtAllocateVirtualMemoryEx),
	HOOK(ntdll, NtReadVirtualMemory),
	HOOK(kernel32, ReadProcessMemory),
	HOOK(ntdll, NtWriteVirtualMemory),
	HOOK(kernel32, WriteProcessMemory),
	HOOK(ntdll, NtWow64WriteVirtualMemory64),
	HOOK(ntdll, NtWow64ReadVirtualMemory64),
	HOOK(ntdll, NtProtectVirtualMemory),
	HOOK(kernel32, VirtualProtectEx),
	HOOK(ntdll, NtFreeVirtualMemory),
	HOOK(ntdll, NtCreateProcess),
	HOOK(ntdll, NtCreateProcessEx),
	HOOK(ntdll, RtlCreateUserProcess),
	HOOK(ntdll, NtOpenProcess),
	HOOK(ntdll, NtTerminateProcess),
	HOOK(ntdll, RtlReportSilentProcessExit),
	HOOK(ntdll, NtResumeProcess),
	HOOK(ntdll, NtCreateSection),
	HOOK(ntdll, NtDuplicateObject),
	HOOK(ntdll, NtMakeTemporaryObject),
	HOOK(ntdll, NtMakePermanentObject),
	HOOK(ntdll, NtOpenSection),
	HOOK(ntdll, NtMapViewOfSection),
	HOOK(ntdll, NtMapViewOfSectionEx),
	HOOK(ntdll, NtUnmapViewOfSection),
	HOOK(ntdll, NtUnmapViewOfSectionEx),
	HOOK(kernel32, WaitForDebugEvent),
	HOOK(ntdll, DbgUiWaitStateChange),
	HOOK(advapi32, CreateProcessWithLogonW),
	HOOK(advapi32, CreateProcessWithTokenW),
	HOOK(kernel32, CreateToolhelp32Snapshot),
	HOOK(kernel32, Process32FirstW),
	HOOK(kernel32, Process32NextW),
	HOOK(kernel32, Module32FirstW),
	HOOK(kernel32, Module32NextW),
	//HOOK(kernel32, VirtualFreeEx),
	// all variants of ShellExecute end up in ShellExecuteExW
	HOOK(shell32, ShellExecuteExW),
	HOOK(msvcrt, system),

	// Thread Hooks
	HOOK(ntdll, NtCreateThread),
	HOOK(ntdll, NtCreateThreadEx),
	HOOK(ntdll, NtTerminateThread),
	HOOK(ntdll, NtQueueApcThread),
	HOOK(ntdll, NtQueueApcThreadEx),
	HOOK(ntdll, NtOpenThread),
	HOOK(ntdll, NtGetContextThread),
	HOOK(ntdll, NtSetContextThread),
	HOOK(ntdll, NtSuspendThread),
	HOOK(ntdll, NtResumeThread),
	HOOK(ntdll, RtlCreateUserThread),
	HOOK(ntdll, NtSetInformationThread),
	HOOK(ntdll, NtQueryInformationThread),
	HOOK(ntdll, NtYieldExecution),
	HOOK(ntdll, NtContinue),
	HOOK(kernel32, CreateThread),
	HOOK(kernel32, CreateRemoteThread),
	HOOK(kernel32, SwitchToThread),
	//HOOK(kernel32, DisableThreadLibraryCalls),

	// Misc Hooks
#ifndef _WIN64
	HOOK(ntdll, memcpy),
#endif
	HOOK(msvcrt, memcpy),
	//HOOK(ntdll, RtlMoveMemory),
	HOOK(kernel32, GetCommandLineA),
	HOOK(kernel32, GetCommandLineW),
	HOOK(kernel32, OutputDebugStringA),
	HOOK(kernel32, OutputDebugStringW),
	HOOK(kernel32, HeapCreate),
	HOOK(msvcrt, srand),
	HOOK(user32, ChangeWindowMessageFilter),
	HOOK(user32, SetWindowsHookExA),
	HOOK(user32, SetWindowsHookExW),
	HOOK(user32, UnhookWindowsHookEx),
	HOOK(kernel32, SetUnhandledExceptionFilter),
	HOOK(ntdll, RtlAddVectoredExceptionHandler),
	HOOK(kernel32, SetErrorMode),
	HOOK(ntdll, LdrGetDllHandle),
	HOOK(ntdll, LdrGetProcedureAddress),
	HOOK(ntdll, LdrGetProcedureAddressForCaller),
	HOOK(kernel32, DeviceIoControl),
	HOOK_NOTAIL(ntdll, NtShutdownSystem, 1),
	HOOK_NOTAIL(ntdll, NtSetSystemPowerState, 3),
	HOOK_NOTAIL(user32, ExitWindowsEx, 2),
	HOOK_NOTAIL(advapi32, InitiateShutdownW, 5),
	HOOK_NOTAIL(advapi32, InitiateSystemShutdownW, 5),
	HOOK_NOTAIL(advapi32, InitiateSystemShutdownExW, 6),
	HOOK_NOTAIL(ntdll, NtRaiseHardError, 6),
	HOOK(kernel32, IsDebuggerPresent),
	HOOK(advapi32, LookupPrivilegeValueW),
	HOOK(advapi32, GetCurrentHwProfileW),
	HOOK(ntdll, NtClose),
	HOOK(kernel32, WriteConsoleA),
	HOOK(kernel32, WriteConsoleW),
	HOOK(user32, GetSystemMetrics),
	HOOK(user32, GetCursorPos),
	HOOK(kernel32, GetComputerNameA),
	HOOK(kernel32, GetComputerNameW),
	HOOK(advapi32, GetUserNameA),
	HOOK(advapi32, GetUserNameW),
	HOOK(user32, GetAsyncKeyState),
	HOOK(ntdll, NtLoadDriver),
	HOOK(ntdll, NtSetInformationProcess),
	//HOOK(ntdll, NtQueryInformationProcess),
	HOOK(ntdll, RtlDecompressBuffer),
	HOOK(ntdll, RtlCompressBuffer),
	HOOK(kernel32, GetSystemInfo),
	HOOK(ntdll, NtQuerySystemInformation),
	HOOK(setupapi, SetupDiGetClassDevsA),
	HOOK(setupapi, SetupDiGetClassDevsW),
	HOOK(setupapi, SetupDiGetDeviceRegistryPropertyA),
	HOOK(setupapi, SetupDiGetDeviceRegistryPropertyW),
	HOOK(setupapi, SetupDiBuildDriverInfoList),
	HOOK(setupapi, IsUserAdmin),
	HOOK(imgutil, DecodeImageEx),
	HOOK(imgutil, DecodeImage),
	HOOK(advapi32, LsaOpenPolicy),
	HOOK(mpr, WNetGetProviderNameW),
	HOOK(rasapi32, RasValidateEntryNameW),
	HOOK(rasapi32, RasConnectionNotificationW),
	HOOK(kernel32, SystemTimeToTzSpecificLocalTime),
	HOOK(ole32, CLSIDFromProgID),
	//HOOK(ole32, OleConvertOLESTREAMToIStorage),
	HOOK(kernel32, GlobalMemoryStatus),
	HOOK(kernel32, GlobalMemoryStatusEx),
	HOOK(user32, SystemParametersInfoA),
	HOOK(user32, SystemParametersInfoW),
	HOOK(pstorec, PStoreCreateInstance),
	HOOK(advapi32, SaferIdentifyLevel),
	HOOK(user32, GetKeyboardLayout),
	//HOOK(oleaut32, SysFreeString),	// breaks Guloader e.g. 4f150ed4669f3a26cfbb6cf06c9843de3bf2a619de4807053512502ef983a3b2
	HOOK(oleaut32, VarBstrCat),
	HOOK_NOTAIL(usp10, ScriptIsComplex, 3),
	HOOK_NOTAIL(inseng,DownloadFile,3),
#ifndef _WIN64
	HOOK(ntdll, RtlDosPathNameToNtPathName_U),
	HOOK(ntdll, NtQueryLicenseValue),
	HOOK(vbe7, rtcEnvironBstr),
	HOOK(shlwapi, StrCmpNICW),
	HOOK(shlwapi, UrlCanonicalizeW),
	HOOK_NOTAIL(vbe7, rtcCreateObject2, 3),
#endif

	// PE resource related functions
	HOOK(kernel32, FindResourceExA),
	HOOK(kernel32, FindResourceExW),
	HOOK(kernel32, LoadResource),
	HOOK(kernel32, LockResource),
	HOOK(kernel32, SizeofResource),

	// functions with callbacks (abused for control-flow transfer)
	HOOK(kernel32, EnumResourceTypesExA),
	HOOK(kernel32, EnumResourceTypesExW),
	HOOK(kernel32, EnumCalendarInfoA),
	HOOK(kernel32, EnumCalendarInfoW),
	HOOK(kernel32, EnumTimeFormatsA),
	HOOK(kernel32, EnumTimeFormatsW),

	// transaction functions (for process doppelganging)
	HOOK(ntdll, NtCreateTransaction),
	HOOK(ntdll, NtOpenTransaction),
	HOOK(ntdll, NtRollbackTransaction),
	HOOK(ntdll, NtCommitTransaction),
	HOOK(ntdll, RtlSetCurrentTransaction),

	// Network Hooks
	HOOK(netapi32, NetUserGetInfo),
	HOOK(netapi32, NetGetJoinInformation),
	HOOK(netapi32, NetUserGetLocalGroups),
	HOOK(netapi32, DsEnumerateDomainTrustsW),
	HOOK(urlmon, URLDownloadToFileW),
	HOOK(urlmon, URLDownloadToCacheFileW),
	HOOK(urlmon, ObtainUserAgentString),
	HOOK(wininet, InternetGetConnectedState),
	HOOK(wininet, InternetOpenA),
	HOOK(wininet, InternetOpenW),
	HOOK(wininet, InternetConnectA),
	HOOK(wininet, InternetConnectW),
	HOOK(wininet, InternetOpenUrlA),
	HOOK(wininet, InternetOpenUrlW),
	HOOK(wininet, HttpOpenRequestA),
	HOOK(wininet, HttpOpenRequestW),
	HOOK(wininet, HttpSendRequestA),
	HOOK(wininet, HttpSendRequestW),
	HOOK(wininet, HttpSendRequestExA),
	HOOK(wininet, HttpSendRequestExW),
	HOOK(wininet, HttpAddRequestHeadersA),
	HOOK(wininet, HttpAddRequestHeadersW),
	HOOK(wininet, HttpQueryInfoA),
	HOOK(wininet, HttpQueryInfoW),
	HOOK(wininet, HttpEndRequestA),
	HOOK(wininet, HttpEndRequestW),
	HOOK(wininet, InternetReadFile),
	HOOK(wininet, InternetWriteFile),
	HOOK(wininet, InternetCloseHandle),
	HOOK(wininet, InternetCrackUrlA),
	HOOK(wininet, InternetCrackUrlW),
	HOOK(wininet, InternetSetOptionA),
	HOOK(wininet, InternetConfirmZoneCrossingA),
	HOOK(wininet, InternetConfirmZoneCrossingW),
	HOOK(winhttp, WinHttpOpen),
	HOOK(winhttp, WinHttpGetIEProxyConfigForCurrentUser),
	HOOK(winhttp, WinHttpGetProxyForUrl),
	HOOK(winhttp, WinHttpSetOption),
	HOOK(winhttp, WinHttpConnect),
	HOOK(winhttp, WinHttpOpenRequest),
	HOOK(winhttp, WinHttpSetTimeouts),
	HOOK(winhttp, WinHttpQueryHeaders),
	HOOK(winhttp, WinHttpSendRequest),
	HOOK(winhttp, WinHttpReceiveResponse),
	HOOK(dnsapi, DnsQuery_A),
	HOOK(dnsapi, DnsQuery_UTF8),
	HOOK(dnsapi, DnsQuery_W),
	HOOK(ws2_32, getaddrinfo),
	HOOK(ws2_32, GetAddrInfoW),
	HOOK(mpr, WNetUseConnectionW),
	HOOK(cryptnet, CryptRetrieveObjectByUrlW),
	HOOK(ncrypt, SslEncryptPacket),
	HOOK(ncrypt, SslDecryptPacket),
	HOOK(iphlpapi, GetAdaptersAddresses),
	HOOK(iphlpapi, GetAdaptersInfo),
	HOOK(urlmon, CoInternetSetFeatureEnabled),

	// Service Hooks
	HOOK(advapi32, OpenSCManagerA),
	HOOK(advapi32, OpenSCManagerW),
	HOOK(advapi32, CreateServiceA),
	HOOK(advapi32, CreateServiceW),
	HOOK(advapi32, OpenServiceA),
	HOOK(advapi32, OpenServiceW),
	HOOK(advapi32, StartServiceA),
	HOOK(advapi32, StartServiceW),
	HOOK(sechost, StartServiceA),
	HOOK(sechost, StartServiceW),
	HOOK(advapi32, ControlService),
	HOOK(advapi32, DeleteService),

	// Sleep Hooks
	HOOK(ntdll, NtQueryPerformanceCounter),
	HOOK(ntdll, NtDelayExecution),
	HOOK(ntdll, NtWaitForSingleObject),
	HOOK_SPECIAL(kernel32, GetLocalTime),
	HOOK_SPECIAL(kernel32, GetSystemTime),
	HOOK_SPECIAL(kernel32, GetSystemTimeAsFileTime),
	HOOK_EMULATE(kernel32, GetTickCount),
	HOOK_EMULATE(kernel32, GetTickCount64),
	HOOK_SPECIAL(ntdll, NtQuerySystemTime),
	HOOK(user32, GetLastInputInfo),
	HOOK_SPECIAL(winmm, timeGetTime),
	HOOK(ntdll, NtSetTimer),
	HOOK(ntdll, NtSetTimerEx),
	HOOK(user32, MsgWaitForMultipleObjectsEx),
	HOOK(kernel32, CreateTimerQueueTimer),

	// Socket Hooks
	HOOK(ws2_32, WSAStartup),
	HOOK(ws2_32, gethostname),
	HOOK(ws2_32, gethostbyname),
	HOOK(ws2_32, socket),
	HOOK(ws2_32, connect),
	HOOK(ws2_32, send),
	HOOK(ws2_32, sendto),
	HOOK(ws2_32, recv),
	HOOK(ws2_32, recvfrom),
	HOOK(ws2_32, accept),
	HOOK(ws2_32, bind),
	HOOK(ws2_32, listen),
	HOOK(ws2_32, select),
	HOOK(ws2_32, setsockopt),
	HOOK(ws2_32, ioctlsocket),
	HOOK(ws2_32, closesocket),
	HOOK(ws2_32, shutdown),
	HOOK(ws2_32, WSAAccept),
	HOOK(ws2_32, WSAConnect),
	HOOK(ws2_32, WSAConnectByNameW),
	HOOK(ws2_32, WSAConnectByList),
	HOOK(ws2_32, WSARecv),
	HOOK(ws2_32, WSARecvFrom),
	HOOK(ws2_32, WSASend),
	HOOK(ws2_32, WSASendTo),
	HOOK(ws2_32, WSASendMsg),
	HOOK(ws2_32, WSASocketA),
	HOOK(ws2_32, WSASocketW),
	// HOOK(wsock32, connect),
	// HOOK(wsock32, send),
	// HOOK(wsock32, recv),
	HOOK(mswsock, ConnectEx),
	HOOK(mswsock, TransmitFile),
	HOOK(mswsock, NSPStartup),

	// Crypto Functions
	HOOK(advapi32, CryptAcquireContextA),
	HOOK(advapi32, CryptAcquireContextW),
	HOOK(advapi32, CryptProtectData),
	HOOK(advapi32, CryptUnprotectData),
	HOOK(advapi32, CryptProtectMemory),
	HOOK(advapi32, CryptUnprotectMemory),
	HOOK(advapi32, CryptDecrypt),
	HOOK(advapi32, CryptEncrypt),
	HOOK(advapi32, CryptHashData),
	HOOK(advapi32, CryptDecodeMessage),
	HOOK(advapi32, CryptDecryptMessage),
	HOOK(advapi32, CryptEncryptMessage),
	HOOK(advapi32, CryptHashMessage),
	HOOK(advapi32, CryptDeriveKey),
	HOOK(advapi32, CryptExportKey),
	HOOK(advapi32, CryptDestroyKey),
	HOOK(advapi32, CryptGenKey),
	HOOK(advapi32, CryptCreateHash),
	HOOK(advapi32, CryptDestroyHash),
	HOOK(advapi32, CryptEnumProvidersA),
	HOOK(advapi32, CryptEnumProvidersW),
	HOOK(advapi32, QueryUsersOnEncryptedFile),
	HOOK(advapi32, CryptGenRandom),
	HOOK(advapi32, CryptImportKey),
	HOOK(wintrust, HTTPSCertificateTrust),
	HOOK(wintrust, HTTPSFinalProv),
	HOOK(crypt32, CryptDecodeObjectEx),
	HOOK(crypt32, CryptImportPublicKeyInfo),
	HOOK(ncrypt, NCryptImportKey),
	HOOK(ncrypt, NCryptDecrypt),
	HOOK(ncrypt, NCryptEncrypt),
	HOOK(bcrypt, BCryptImportKey),
	HOOK(bcrypt, BCryptImportKeyPair),
	HOOK(bcrypt, BCryptDecrypt),
	HOOK(bcrypt, BCryptEncrypt),
	// needed due to the DLL being delay-loaded in some cases
	HOOK(cryptsp, CryptAcquireContextA),
	HOOK(cryptsp, CryptAcquireContextW),
	HOOK(cryptsp, CryptProtectData),
	HOOK(cryptsp, CryptUnprotectData),
	HOOK(cryptsp, CryptProtectMemory),
	HOOK(cryptsp, CryptUnprotectMemory),
	HOOK(cryptsp, CryptDecrypt),
	HOOK(cryptsp, CryptEncrypt),
	HOOK(cryptsp, CryptHashData),
	HOOK(cryptsp, CryptDecodeMessage),
	HOOK(cryptsp, CryptDecryptMessage),
	HOOK(cryptsp, CryptEncryptMessage),
	HOOK(cryptsp, CryptHashMessage),
	HOOK(cryptsp, CryptExportKey),
	HOOK(cryptsp, CryptGenKey),
	HOOK(cryptsp, CryptCreateHash),
	HOOK(cryptsp, CryptEnumProvidersA),
	HOOK(cryptsp, CryptEnumProvidersW),
	HOOK(cryptsp, CryptHashSessionKey),
	HOOK(cryptsp, CryptGenRandom),
	HOOK(cryptsp, CryptImportKey),
};

// This hook set is intended to include only hooks which are necessary
// to follow the execution chain with base functionality

hook_t min_hooks[] = {
	HOOK_NOTAIL_ALT(ntdll, LdrLoadDll, 4),
	HOOK_NOTAIL(ntdll, LdrUnloadDll, 1),
	HOOK_SPECIAL(ntdll, NtCreateUserProcess),
	HOOK_SPECIAL(kernel32, CreateProcessInternalW),

	HOOK_SPECIAL(ole32, CoCreateInstance),
	HOOK_SPECIAL(ole32, CoCreateInstanceEx),
	HOOK_SPECIAL(ole32, CoGetClassObject),
	HOOK_SPECIAL(combase, CoCreateInstance),
	HOOK_SPECIAL(combase, CoCreateInstanceEx),
	HOOK_SPECIAL(combase, CoGetClassObject),

	HOOK_NOTAIL_ALT(ntdll, RtlDispatchException, 2),
	HOOK_NOTAIL(ntdll, NtRaiseException, 3),

	HOOK(ntdll, NtCreateProcess),
	HOOK(ntdll, NtCreateProcessEx),
	HOOK(ntdll, RtlCreateUserProcess),
	HOOK(advapi32, CreateProcessWithLogonW),
	HOOK(advapi32, CreateProcessWithTokenW),

	HOOK(shell32, ShellExecuteExW),

	HOOK(ntdll, NtAllocateVirtualMemory),
	HOOK(ntdll, NtWriteVirtualMemory),
	HOOK(ntdll, NtWow64WriteVirtualMemory64),
	HOOK(ntdll, NtMapViewOfSection),
	HOOK(ntdll, NtUnmapViewOfSection),
	HOOK(kernel32, WriteProcessMemory),

	HOOK(ntdll, NtContinue),
	HOOK(ntdll, NtQueueApcThread),
	HOOK(ntdll, NtQueueApcThreadEx),
	HOOK(ntdll, NtCreateThread),
	HOOK(ntdll, NtCreateThreadEx),
	HOOK(ntdll, NtSetContextThread),
	HOOK(ntdll, NtSuspendThread),
	HOOK(ntdll, RtlCreateUserThread),
	HOOK(kernel32, CreateRemoteThread),
	HOOK(user32, SendNotifyMessageA),
	HOOK(user32, SendNotifyMessageW),
	HOOK(user32, SetWindowLongA),
	HOOK(user32, SetWindowLongW),
	HOOK(user32, SetWindowLongPtrA),
	HOOK(user32, SetWindowLongPtrW),

	HOOK(user32, SetWindowsHookExA),
	HOOK(user32, SetWindowsHookExW),

	HOOK(ntdll, NtCreateFile),
	HOOK(ntdll, NtOpenFile),
	HOOK(ntdll, NtSetInformationFile),
	HOOK(kernel32, DeleteFileA),
	HOOK(kernel32, DeleteFileW),
	HOOK(ntdll, NtDeleteFile),
	HOOK(kernel32, CopyFileA),
	HOOK(kernel32, CopyFileW),
	HOOK_NOTAIL_ALT(kernel32, CopyFileExW, 6),
	HOOK_NOTAIL_ALT(kernel32, MoveFileWithProgressW, 5),
	HOOK_NOTAIL_ALT(kernelbase, MoveFileWithProgressTransactedW, 6),
	HOOK_NOTAIL_ALT(kernel32, MoveFileWithProgressTransactedW, 6),

	HOOK(ntdll, NtClose),
	HOOK(ntdll, NtResumeThread),
	HOOK(ntdll, NtResumeProcess),
	HOOK(ntdll, NtTerminateProcess),
	HOOK(ntdll, RtlReportSilentProcessExit),

	HOOK(ntdll, NtDuplicateObject),

	HOOK_SPECIAL(kernel32, GetSystemTimeAsFileTime),

	HOOK(advapi32, StartServiceA),
	HOOK(advapi32, StartServiceW),
	HOOK(sechost, StartServiceA),
	HOOK(sechost, StartServiceW),

	HOOK(urlmon, URLDownloadToFileW),
	HOOK(urlmon, URLDownloadToCacheFileW),
};

hook_t zero_hooks[] = {

	//
	// 'Zero' Hooks
	//
	// What are the abolute minimum hooks necessary to use
	// the debugger/instruction trace?
	//

	HOOK_NOTAIL_ALT(ntdll, RtlDispatchException, 2),
	HOOK(ntdll, NtContinue),
};

hook_t tls_hooks[] = {
	HOOK_NOTAIL_ALT(ntdll, LdrLoadDll, 4),	// allows monitor reload to trigger switch from tlsdump to 'normal' mode
	HOOK(ncrypt, SslGenerateMasterKey),
	HOOK(ncrypt, SslImportMasterKey),
	HOOK(ncrypt, SslGenerateSessionKeys),
	HOOK(ncrypt, SslHashHandshake),
};

hook_t office_hooks[] = {
	HOOK_NOTAIL_ALT(ntdll, LdrLoadDll, 4),
	HOOK_NOTAIL(ntdll, LdrUnloadDll, 1),
	HOOK_SPECIAL(ntdll, NtCreateUserProcess),
	HOOK_SPECIAL(kernel32, CreateProcessInternalW),
	HOOK_SPECIAL(urlmon, IsValidURL),
	//HOOK(kernel32, lstrcpynA),
	//HOOK(kernel32, lstrcmpiA),
	HOOK_SPECIAL(jscript, COleScript_ParseScriptText),
	HOOK_NOTAIL(jscript, JsEval, 5),
	HOOK_SPECIAL(jscript9, JsParseScript),
	HOOK_NOTAIL(jscript9, JsRunScript, 4),
	HOOK_SPECIAL(mshtml, CDocument_write),
	// COM object creation hook
	HOOK_SPECIAL(ole32, CoCreateInstance),
	HOOK_SPECIAL(ole32, CoCreateInstanceEx),
	HOOK_SPECIAL(ole32, CoGetClassObject),
	HOOK_SPECIAL(combase, CoCreateInstance),
	HOOK_SPECIAL(combase, CoCreateInstanceEx),
	HOOK_SPECIAL(combase, CoGetClassObject),
	HOOK_NOTAIL_ALT(ntdll, RtlDispatchException, 2),
	HOOK_NOTAIL(ntdll, NtRaiseException, 3),
	// lowest variant of MoveFile()
	HOOK_NOTAIL_ALT(kernel32, MoveFileWithProgressW, 5),
	HOOK_NOTAIL_ALT(kernelbase, MoveFileWithProgressTransactedW, 6),
	HOOK_NOTAIL_ALT(kernel32, MoveFileWithProgressTransactedW, 6),

	// File Hooks
	HOOK(ntdll, NtQueryAttributesFile),
	HOOK(ntdll, NtQueryFullAttributesFile),
	HOOK(ntdll, NtCreateFile),
	HOOK(ntdll, NtOpenFile),
	HOOK(ntdll, NtReadFile),
	HOOK(ntdll, NtWriteFile),
	HOOK(ntdll, NtDeleteFile),
	HOOK(ntdll, NtDeviceIoControlFile),
	HOOK(ntdll, NtQueryDirectoryFile),
	HOOK(ntdll, NtQueryInformationFile),
	HOOK(ntdll, NtSetInformationFile),
	HOOK(ntdll, NtOpenDirectoryObject),
	HOOK(ntdll, NtCreateDirectoryObject),
	HOOK(ntdll, NtQueryDirectoryObject),
	HOOK(kernel32, CreateFileTransactedA),
	HOOK(kernel32, CreateFileTransactedW),
	// CreateDirectoryExA calls CreateDirectoryExW
	// CreateDirectoryW does not call CreateDirectoryExW
	HOOK(kernel32, CreateDirectoryW),
	HOOK(kernel32, CreateDirectoryExW),
	HOOK(kernel32, RemoveDirectoryA),
	HOOK(kernel32, RemoveDirectoryW),
	HOOK(kernel32, FindFirstFileExA),
	HOOK(kernel32, FindFirstFileExW),
	HOOK(kernel32, FindNextFileW),
	// Covered by NtCreateFile() but still grab this information
	HOOK(kernel32, CopyFileA),
	HOOK(kernel32, CopyFileW),
	HOOK_NOTAIL_ALT(kernel32, CopyFileExW, 6),
	// Covered by NtSetInformationFile() but still grab this information
	HOOK(kernel32, DeleteFileA),
	HOOK(kernel32, DeleteFileW),
	HOOK(kernel32, GetDiskFreeSpaceExA),
	HOOK(kernel32, GetDiskFreeSpaceExW),
	HOOK(kernel32, GetDiskFreeSpaceA),
	HOOK(kernel32, GetDiskFreeSpaceW),
	HOOK(kernel32, GetVolumeNameForVolumeMountPointW),
	HOOK(kernel32, GetVolumeInformationByHandleW),
	HOOK(shell32, SHGetFolderPathW),
	HOOK(shell32, SHGetKnownFolderPath),
	HOOK(shell32, SHGetFileInfoW),
	HOOK(version, GetFileVersionInfoW),
	HOOK(version, GetFileVersionInfoSizeW),
	HOOK(kernel32, FindFirstChangeNotificationW),

	// Registry Hooks
	// Note: Most, if not all, of the Registry API go natively from both the
	// A as well as the W versions. In other words, we have to hook all the
	// ascii *and* unicode APIs of those functions.
	HOOK(advapi32, RegOpenKeyExA),
	HOOK(advapi32, RegOpenKeyExW),
	HOOK(advapi32, RegCreateKeyExA),
	HOOK(advapi32, RegCreateKeyExW),
	// Note that RegDeleteKeyEx() is available for 64bit XP/Vista+
	HOOK(advapi32, RegDeleteKeyA),
	HOOK(advapi32, RegDeleteKeyW),
	// RegEnumKeyA() calls RegEnumKeyExA(), but RegEnumKeyW() does *not*
	// call RegEnumKeyExW()
	HOOK(advapi32, RegEnumKeyW),
	HOOK(advapi32, RegEnumKeyExA),
	HOOK(advapi32, RegEnumKeyExW),
	HOOK(advapi32, RegEnumValueA),
	HOOK(advapi32, RegEnumValueW),
	HOOK(advapi32, RegSetValueExA),
	HOOK(advapi32, RegSetValueExW),
	HOOK(advapi32, RegQueryValueExA),
	HOOK(advapi32, RegQueryValueExW),
	HOOK(advapi32, RegDeleteValueA),
	HOOK(advapi32, RegDeleteValueW),
	HOOK(advapi32, RegQueryInfoKeyA),
	HOOK(advapi32, RegQueryInfoKeyW),
	HOOK(advapi32, RegCloseKey),
	HOOK(advapi32, RegNotifyChangeKeyValue),
	// On newer versions of Windows, the above registry APIs are also accessible via kernel32 without
	// the need for advapi32 (and advapi32 will actually simply end up pointing into the kernel32 version).
	// Add these below to make sure we still end up hooking the APIs even if advapi32 isn't loaded
	HOOK(kernel32, RegOpenKeyExA),
	HOOK(kernel32, RegOpenKeyExW),
	HOOK(kernel32, RegCreateKeyExA),
	HOOK(kernel32, RegCreateKeyExW),
	HOOK(kernel32, RegDeleteKeyA),
	HOOK(kernel32, RegDeleteKeyW),
	HOOK(kernel32, RegEnumKeyW),
	HOOK(kernel32, RegEnumKeyExA),
	HOOK(kernel32, RegEnumKeyExW),
	HOOK(kernel32, RegEnumValueA),
	HOOK(kernel32, RegEnumValueW),
	HOOK(kernel32, RegSetValueExA),
	HOOK(kernel32, RegSetValueExW),
	HOOK(kernel32, RegQueryValueExA),
	HOOK(kernel32, RegQueryValueExW),
	HOOK(kernel32, RegDeleteValueA),
	HOOK(kernel32, RegDeleteValueW),
	HOOK(kernel32, RegQueryInfoKeyA),
	HOOK(kernel32, RegQueryInfoKeyW),
	HOOK(kernel32, RegCloseKey),
	HOOK(kernel32, RegNotifyChangeKeyValue),
	// Native Registry Hooks
	HOOK(ntdll, NtCreateKey),
	HOOK(ntdll, NtOpenKey),
	HOOK(ntdll, NtOpenKeyEx),
	HOOK(ntdll, NtRenameKey),
	HOOK(ntdll, NtReplaceKey),
	HOOK(ntdll, NtEnumerateKey),
	HOOK(ntdll, NtEnumerateValueKey),
	HOOK(ntdll, NtSetValueKey),
	HOOK(ntdll, NtQueryValueKey),
	HOOK(ntdll, NtQueryMultipleValueKey),
	HOOK(ntdll, NtDeleteKey),
	HOOK(ntdll, NtDeleteValueKey),
	HOOK(ntdll, NtLoadKey),
	HOOK(ntdll, NtLoadKey2),
	HOOK(ntdll, NtLoadKeyEx),
	HOOK(ntdll, NtQueryKey),
	HOOK(ntdll, NtSaveKey),
	HOOK(ntdll, NtSaveKeyEx),

	// Window Hooks
	HOOK(user32, FindWindowA),
	HOOK(user32, FindWindowW),
	HOOK(user32, FindWindowExA),
	HOOK(user32, FindWindowExW),
	HOOK(user32, PostMessageA),
	HOOK(user32, PostMessageW),
//	HOOK(user32, SendMessageA),	// maldoc detonation issues
//	HOOK(user32, SendMessageW),	//
	HOOK(user32, SendNotifyMessageA),
	HOOK(user32, SendNotifyMessageW),
	HOOK(user32, SetWindowLongA),
	HOOK(user32, SetWindowLongW),
	HOOK(user32, SetWindowLongPtrA),
	HOOK(user32, SetWindowLongPtrW),
//	HOOK_NOTAIL(user32, CreateWindowExA, 12),	// maldoc detonation issues
//	HOOK_NOTAIL(user32, CreateWindowExW, 12),	//
//	HOOK(user32, EnumWindows),	// Disable for now, invokes a user-specified callback that can contain
	// calls to any functions that we won't end up logging. We need another hook type which
	// logs the hook and then every function called by that hook (modulo perhaps some blacklisted
	// functions for this specific hook type)

	// Sync Hooks
	HOOK(ntdll, NtCreateMutant),
	HOOK(ntdll, NtOpenMutant),
	HOOK(ntdll, NtReleaseMutant),
	HOOK(ntdll, NtCreateEvent),
	HOOK(ntdll, NtOpenEvent),
	HOOK(ntdll, NtCreateNamedPipeFile),
	HOOK(ntdll, NtAddAtom),
	HOOK(ntdll, NtAddAtomEx),
	HOOK(ntdll, NtFindAtom),
	HOOK(ntdll, NtDeleteAtom),
	HOOK(ntdll, NtQueryInformationAtom),

	// Process Hooks
	HOOK(ntdll, NtAllocateVirtualMemory),
	HOOK(ntdll, NtReadVirtualMemory),
	HOOK(kernel32, ReadProcessMemory),
	HOOK(ntdll, NtWriteVirtualMemory),
	HOOK(kernel32, WriteProcessMemory),
	HOOK(ntdll, NtWow64WriteVirtualMemory64),
	HOOK(ntdll, NtWow64ReadVirtualMemory64),
	HOOK(ntdll, NtProtectVirtualMemory),
	HOOK(kernel32, VirtualProtectEx),
	HOOK(ntdll, NtFreeVirtualMemory),
	HOOK(ntdll, NtCreateProcess),
	HOOK(ntdll, NtCreateProcessEx),
	HOOK(ntdll, RtlCreateUserProcess),
	HOOK(ntdll, NtOpenProcess),
	HOOK(ntdll, NtTerminateProcess),
	HOOK(ntdll, RtlReportSilentProcessExit),
	HOOK(ntdll, NtResumeProcess),
	HOOK(ntdll, NtCreateSection),
	HOOK(ntdll, NtDuplicateObject),
	HOOK(ntdll, NtMakeTemporaryObject),
	HOOK(ntdll, NtMakePermanentObject),
	HOOK(ntdll, NtOpenSection),
	HOOK(ntdll, NtMapViewOfSection),
	HOOK(ntdll, NtUnmapViewOfSection),
	HOOK(kernel32, WaitForDebugEvent),
	HOOK(ntdll, DbgUiWaitStateChange),
	HOOK(advapi32, CreateProcessWithLogonW),
	HOOK(advapi32, CreateProcessWithTokenW),
	HOOK(kernel32, CreateToolhelp32Snapshot),
	HOOK(kernel32, Process32FirstW),
	HOOK(kernel32, Process32NextW),
	HOOK(kernel32, Module32FirstW),
	HOOK(kernel32, Module32NextW),
	//HOOK(kernel32, VirtualFreeEx),
	// all variants of ShellExecute end up in ShellExecuteExW
	HOOK(shell32, ShellExecuteExW),
	HOOK(msvcrt, system),

	// Thread Hooks
	HOOK(ntdll, NtCreateThread),
	HOOK(ntdll, NtCreateThreadEx),
	HOOK(ntdll, NtTerminateThread),
	HOOK(ntdll, NtQueueApcThread),
	HOOK(ntdll, NtQueueApcThreadEx),
	HOOK(ntdll, NtOpenThread),
	HOOK(ntdll, NtGetContextThread),
	HOOK(ntdll, NtSetContextThread),
	HOOK(ntdll, NtSuspendThread),
	HOOK(ntdll, NtResumeThread),
	HOOK(ntdll, RtlCreateUserThread),
	HOOK(ntdll, NtSetInformationThread),
	HOOK(ntdll, NtQueryInformationThread),
	HOOK(ntdll, NtYieldExecution),
	HOOK(ntdll, NtContinue),
	HOOK(kernel32, CreateThread),
	HOOK(kernel32, CreateRemoteThread),
	HOOK(kernel32, SwitchToThread),

	// Misc Hooks
#ifndef _WIN64
	//HOOK(ntdll, memcpy),
#endif
	//HOOK(msvcrt, memcpy),
	//HOOK(ntdll, RtlMoveMemory),
	HOOK(kernel32, OutputDebugStringA),
	HOOK(kernel32, OutputDebugStringW),
	HOOK(kernel32, HeapCreate),
	HOOK(msvcrt, srand),
	HOOK(user32, ChangeWindowMessageFilter),
	HOOK(user32, SetWindowsHookExA),
	HOOK(user32, SetWindowsHookExW),
	HOOK(user32, UnhookWindowsHookEx),
	HOOK(kernel32, SetUnhandledExceptionFilter),
	HOOK(ntdll, RtlAddVectoredExceptionHandler),
	HOOK(kernel32, SetErrorMode),
	HOOK(ntdll, LdrGetDllHandle),
	HOOK(ntdll, LdrGetProcedureAddress),
	HOOK(ntdll, LdrGetProcedureAddressForCaller),
	HOOK(kernel32, DeviceIoControl),
	HOOK_NOTAIL(ntdll, NtShutdownSystem, 1),
	HOOK_NOTAIL(ntdll, NtSetSystemPowerState, 3),
	HOOK_NOTAIL(user32, ExitWindowsEx, 2),
	HOOK_NOTAIL(advapi32, InitiateShutdownW, 5),
	HOOK_NOTAIL(advapi32, InitiateSystemShutdownW, 5),
	HOOK_NOTAIL(advapi32, InitiateSystemShutdownExW, 6),
	HOOK_NOTAIL(ntdll, NtRaiseHardError, 6),
	HOOK(kernel32, IsDebuggerPresent),
	HOOK(advapi32, LookupPrivilegeValueW),
	HOOK(advapi32, GetCurrentHwProfileW),
	HOOK(ntdll, NtClose),
	HOOK(kernel32, WriteConsoleA),
	HOOK(kernel32, WriteConsoleW),
	HOOK(user32, GetSystemMetrics),
	HOOK(user32, GetCursorPos),
	HOOK(kernel32, GetComputerNameA),
	HOOK(kernel32, GetComputerNameW),
	HOOK(advapi32, GetUserNameA),
	HOOK(advapi32, GetUserNameW),
	HOOK(user32, GetAsyncKeyState),
	HOOK(ntdll, NtLoadDriver),
	HOOK(ntdll, NtSetInformationProcess),
	//HOOK(ntdll, NtQueryInformationProcess),
	HOOK(ntdll, RtlDecompressBuffer),
	HOOK(ntdll, RtlCompressBuffer),
	HOOK(kernel32, GetSystemInfo),
	HOOK(ntdll, NtQuerySystemInformation),
	HOOK(setupapi, SetupDiGetClassDevsA),
	HOOK(setupapi, SetupDiGetClassDevsW),
	HOOK(setupapi, SetupDiGetDeviceRegistryPropertyA),
	HOOK(setupapi, SetupDiGetDeviceRegistryPropertyW),
	HOOK(setupapi, SetupDiBuildDriverInfoList),
	HOOK(setupapi, IsUserAdmin),
	HOOK(imgutil, DecodeImageEx),
	HOOK(imgutil, DecodeImage),
	HOOK(advapi32, LsaOpenPolicy),
	HOOK(mpr, WNetGetProviderNameW),
	HOOK(rasapi32, RasValidateEntryNameW),
	HOOK(rasapi32, RasConnectionNotificationW),
	HOOK(kernel32, SystemTimeToTzSpecificLocalTime),
	HOOK(ole32, CLSIDFromProgID),
	//HOOK(ole32, OleConvertOLESTREAMToIStorage),
	HOOK(kernel32, GlobalMemoryStatus),
	HOOK(kernel32, GlobalMemoryStatusEx),
	HOOK(user32, SystemParametersInfoA),
	HOOK(user32, SystemParametersInfoW),
	HOOK(pstorec, PStoreCreateInstance),
	HOOK(advapi32, SaferIdentifyLevel),
	HOOK(user32, GetKeyboardLayout),
	//HOOK(oleaut32, SysFreeString),	// breaks Guloader e.g. 4f150ed4669f3a26cfbb6cf06c9843de3bf2a619de4807053512502ef983a3b2
	HOOK(oleaut32, VarBstrCat),
	HOOK_NOTAIL(usp10, ScriptIsComplex, 3),
	HOOK_NOTAIL(inseng,DownloadFile,3),
#ifndef _WIN64
	HOOK(ntdll, RtlDosPathNameToNtPathName_U),
	HOOK(ntdll, NtQueryLicenseValue),
	HOOK(vbe7, rtcEnvironBstr),
	HOOK(shlwapi, StrCmpNICW),
	HOOK(shlwapi, UrlCanonicalizeW),
	HOOK_NOTAIL(vbe7, rtcCreateObject2, 3),
#endif

	// PE resource related functions
	HOOK(kernel32, FindResourceExA),
	HOOK(kernel32, FindResourceExW),
	HOOK(kernel32, LoadResource),
	HOOK(kernel32, LockResource),
	HOOK(kernel32, SizeofResource),

	// functions with callbacks (abused for control-flow transfer)
	HOOK(kernel32, EnumResourceTypesExA),
	HOOK(kernel32, EnumResourceTypesExW),
	HOOK(kernel32, EnumCalendarInfoA),
	HOOK(kernel32, EnumCalendarInfoW),
	HOOK(kernel32, EnumTimeFormatsA),
	HOOK(kernel32, EnumTimeFormatsW),

	// transaction functions (for process doppelganging)
	HOOK(ntdll, NtCreateTransaction),
	HOOK(ntdll, NtOpenTransaction),
	HOOK(ntdll, NtRollbackTransaction),
	HOOK(ntdll, NtCommitTransaction),
	HOOK(ntdll, RtlSetCurrentTransaction),

	// Network Hooks
	HOOK(netapi32, NetUserGetInfo),
	HOOK(netapi32, NetGetJoinInformation),
	HOOK(netapi32, NetUserGetLocalGroups),
	HOOK(netapi32, DsEnumerateDomainTrustsW),
	HOOK(urlmon, URLDownloadToFileW),
	HOOK(urlmon, URLDownloadToCacheFileW),
	HOOK(urlmon, ObtainUserAgentString),
	HOOK(wininet, InternetGetConnectedState),
	HOOK(wininet, InternetOpenA),
	HOOK(wininet, InternetOpenW),
	HOOK(wininet, InternetConnectA),
	HOOK(wininet, InternetConnectW),
	HOOK(wininet, InternetOpenUrlA),
	HOOK(wininet, InternetOpenUrlW),
	HOOK(wininet, HttpOpenRequestA),
	HOOK(wininet, HttpOpenRequestW),
	HOOK(wininet, HttpSendRequestA),
	HOOK(wininet, HttpSendRequestW),
	HOOK(wininet, HttpSendRequestExA),
	HOOK(wininet, HttpSendRequestExW),
	HOOK(wininet, HttpAddRequestHeadersA),
	HOOK(wininet, HttpAddRequestHeadersW),
	HOOK(wininet, HttpQueryInfoA),
	HOOK(wininet, HttpQueryInfoW),
	HOOK(wininet, HttpEndRequestA),
	HOOK(wininet, HttpEndRequestW),
	HOOK(wininet, InternetReadFile),
	HOOK(wininet, InternetWriteFile),
	HOOK(wininet, InternetCloseHandle),
	HOOK(wininet, InternetCrackUrlA),
	HOOK(wininet, InternetCrackUrlW),
	HOOK(wininet, InternetSetOptionA),
	HOOK(wininet, InternetConfirmZoneCrossingA),
	HOOK(wininet, InternetConfirmZoneCrossingW),
	HOOK(winhttp, WinHttpOpen),
	HOOK(winhttp, WinHttpGetIEProxyConfigForCurrentUser),
	HOOK(winhttp, WinHttpGetProxyForUrl),
	HOOK(winhttp, WinHttpSetOption),
	HOOK(winhttp, WinHttpConnect),
	HOOK(winhttp, WinHttpOpenRequest),
	HOOK(winhttp, WinHttpSetTimeouts),
	HOOK(winhttp, WinHttpQueryHeaders),
	HOOK(winhttp, WinHttpSendRequest),
	HOOK(winhttp, WinHttpReceiveResponse),
	HOOK(dnsapi, DnsQuery_A),
	HOOK(dnsapi, DnsQuery_UTF8),
	HOOK(dnsapi, DnsQuery_W),
	HOOK(ws2_32, getaddrinfo),
	HOOK(ws2_32, GetAddrInfoW),
	HOOK(mpr, WNetUseConnectionW),
	HOOK(cryptnet, CryptRetrieveObjectByUrlW),
	HOOK(ncrypt, SslEncryptPacket),
	HOOK(ncrypt, SslDecryptPacket),
	HOOK(iphlpapi, GetAdaptersAddresses),
	HOOK(iphlpapi, GetAdaptersInfo),
	HOOK(urlmon, CoInternetSetFeatureEnabled),

	// Service Hooks
	HOOK(advapi32, OpenSCManagerA),
	HOOK(advapi32, OpenSCManagerW),
	HOOK(advapi32, CreateServiceA),
	HOOK(advapi32, CreateServiceW),
	HOOK(advapi32, OpenServiceA),
	HOOK(advapi32, OpenServiceW),
	HOOK(advapi32, StartServiceA),
	HOOK(advapi32, StartServiceW),
	HOOK(advapi32, ControlService),
	HOOK(advapi32, DeleteService),

	// Sleep Hooks
	HOOK(ntdll, NtQueryPerformanceCounter),
	HOOK(ntdll, NtDelayExecution),
	HOOK(ntdll, NtWaitForSingleObject),
	HOOK_SPECIAL(kernel32, GetLocalTime),
	HOOK_SPECIAL(kernel32, GetSystemTime),
	HOOK_SPECIAL(kernel32, GetSystemTimeAsFileTime),
	HOOK_EMULATE(kernel32, GetTickCount),
	HOOK_EMULATE(kernel32, GetTickCount64),
	HOOK_SPECIAL(ntdll, NtQuerySystemTime),
	HOOK(user32, GetLastInputInfo),
	HOOK_SPECIAL(winmm, timeGetTime),
	HOOK(ntdll, NtSetTimer),
	HOOK(ntdll, NtSetTimerEx),
	HOOK(user32, MsgWaitForMultipleObjectsEx),
	HOOK(kernel32, CreateTimerQueueTimer),

	// Socket Hooks
	HOOK(ws2_32, WSAStartup),
	HOOK(ws2_32, gethostname),
	HOOK(ws2_32, gethostbyname),
	HOOK(ws2_32, socket),
	HOOK(ws2_32, connect),
	HOOK(ws2_32, send),
	HOOK(ws2_32, sendto),
	HOOK(ws2_32, recv),
	HOOK(ws2_32, recvfrom),
	HOOK(ws2_32, accept),
	HOOK(ws2_32, bind),
	HOOK(ws2_32, listen),
	HOOK(ws2_32, select),
	HOOK(ws2_32, setsockopt),
	HOOK(ws2_32, ioctlsocket),
	HOOK(ws2_32, closesocket),
	HOOK(ws2_32, shutdown),
	HOOK(ws2_32, WSAAccept),
	HOOK(ws2_32, WSAConnect),
	HOOK(ws2_32, WSAConnectByNameW),
	HOOK(ws2_32, WSAConnectByList),
	HOOK(ws2_32, WSARecv),
	HOOK(ws2_32, WSARecvFrom),
	HOOK(ws2_32, WSASend),
	HOOK(ws2_32, WSASendTo),
	HOOK(ws2_32, WSASendMsg),
	HOOK(ws2_32, WSASocketA),
	HOOK(ws2_32, WSASocketW),
	// HOOK(wsock32, connect),
	// HOOK(wsock32, send),
	// HOOK(wsock32, recv),
	HOOK(mswsock, ConnectEx),
	HOOK(mswsock, TransmitFile),
	HOOK(mswsock, NSPStartup),

	// Crypto Functions
	HOOK(advapi32, CryptAcquireContextA),
	HOOK(advapi32, CryptAcquireContextW),
	HOOK(advapi32, CryptProtectData),
	HOOK(advapi32, CryptUnprotectData),
	HOOK(advapi32, CryptProtectMemory),
	HOOK(advapi32, CryptUnprotectMemory),
	HOOK(advapi32, CryptDecrypt),
	HOOK(advapi32, CryptEncrypt),
	HOOK(advapi32, CryptHashData),
	HOOK(advapi32, CryptDecodeMessage),
	HOOK(advapi32, CryptDecryptMessage),
	HOOK(advapi32, CryptEncryptMessage),
	HOOK(advapi32, CryptHashMessage),
	HOOK(advapi32, CryptExportKey),
	HOOK(advapi32, CryptGenKey),
	HOOK(advapi32, CryptCreateHash),
	HOOK(advapi32, CryptEnumProvidersA),
	HOOK(advapi32, CryptEnumProvidersW),
	HOOK(advapi32, QueryUsersOnEncryptedFile),
	HOOK(advapi32, CryptGenRandom),
	HOOK(advapi32, CryptImportKey),
	HOOK(wintrust, HTTPSCertificateTrust),
	HOOK(wintrust, HTTPSFinalProv),
	HOOK(crypt32, CryptDecodeObjectEx),
	HOOK(crypt32, CryptImportPublicKeyInfo),
	HOOK(ncrypt, NCryptImportKey),
	HOOK(ncrypt, NCryptDecrypt),
	HOOK(ncrypt, NCryptEncrypt),
};

hook_t ie_hooks[] = {
	HOOK_NOTAIL_ALT(ntdll, LdrLoadDll, 4),
	HOOK_NOTAIL(ntdll, LdrUnloadDll, 1),
	HOOK_SPECIAL(ntdll, NtCreateUserProcess),
	HOOK_SPECIAL(kernel32, CreateProcessInternalW),

	HOOK_SPECIAL(ole32, CoCreateInstance),
	HOOK_SPECIAL(ole32, CoCreateInstanceEx),
	HOOK_SPECIAL(ole32, CoGetClassObject),
	HOOK_SPECIAL(urlmon, IsValidURL),
	HOOK_SPECIAL(combase, CoCreateInstance),
	HOOK_SPECIAL(combase, CoCreateInstanceEx),
	HOOK_SPECIAL(combase, CoGetClassObject),

	HOOK_NOTAIL_ALT(ntdll, RtlDispatchException, 2),
	HOOK_NOTAIL(ntdll, NtRaiseException, 3),

	HOOK(ntdll, NtCreateProcess),
	HOOK(ntdll, NtCreateProcessEx),
	HOOK(ntdll, RtlCreateUserProcess),
	HOOK(advapi32, CreateProcessWithLogonW),
	HOOK(advapi32, CreateProcessWithTokenW),

	HOOK(shell32, ShellExecuteExW),

	//HOOK(ntdll, NtAllocateVirtualMemory),
	//HOOK(ntdll, NtWriteVirtualMemory),
	//HOOK(ntdll, NtWow64WriteVirtualMemory64),
	//HOOK(ntdll, NtMapViewOfSection),
	//HOOK(ntdll, NtUnmapViewOfSection),
	//HOOK(kernel32, WriteProcessMemory),

	HOOK(ntdll, NtContinue),
	HOOK(ntdll, NtQueueApcThread),
	HOOK(ntdll, NtQueueApcThreadEx),
	HOOK(ntdll, NtCreateThread),
	//HOOK(ntdll, NtCreateThreadEx),
	HOOK(ntdll, NtSetContextThread),
	HOOK(ntdll, NtSuspendThread),
	//HOOK(ntdll, RtlCreateUserThread),
	HOOK(kernel32, CreateRemoteThread),
	HOOK(user32, SendNotifyMessageA),
	HOOK(user32, SendNotifyMessageW),
	HOOK(user32, SetWindowLongA),
	HOOK(user32, SetWindowLongW),
	HOOK(user32, SetWindowLongPtrA),
	HOOK(user32, SetWindowLongPtrW),

	HOOK(user32, SetWindowsHookExA),
	HOOK(user32, SetWindowsHookExW),

	HOOK(ntdll, NtCreateFile),
	//HOOK(ntdll, NtOpenFile),
	HOOK(ntdll, NtSetInformationFile),
	HOOK(ntdll, NtQueryAttributesFile),
	HOOK(kernel32, DeleteFileA),
	HOOK(kernel32, DeleteFileW),
	HOOK(ntdll, NtDeleteFile),
	HOOK(kernel32, CopyFileA),
	HOOK(kernel32, CopyFileW),
	HOOK_NOTAIL_ALT(kernel32, CopyFileExW, 6),
	HOOK_NOTAIL_ALT(kernel32, MoveFileWithProgressW, 5),
	HOOK_NOTAIL_ALT(kernelbase, MoveFileWithProgressTransactedW, 6),
	HOOK_NOTAIL_ALT(kernel32, MoveFileWithProgressTransactedW, 6),

	HOOK(ntdll, NtClose),
	HOOK(ntdll, NtResumeThread),
	HOOK(ntdll, NtResumeProcess),
	HOOK(ntdll, NtTerminateProcess),
	HOOK(ntdll, RtlReportSilentProcessExit),

	HOOK(ntdll, NtDuplicateObject),

	HOOK_SPECIAL(kernel32, GetSystemTimeAsFileTime),

	HOOK(advapi32, StartServiceA),
	HOOK(advapi32, StartServiceW),
	HOOK(sechost, StartServiceA),
	HOOK(sechost, StartServiceW),

	HOOK(urlmon, URLDownloadToFileW),
	HOOK(urlmon, URLDownloadToCacheFileW),
	HOOK(ole32, CLSIDFromProgID),
	HOOK(advapi32, RegOpenKeyExA),
	HOOK(advapi32, RegOpenKeyExW),
	HOOK(ntdll, NtOpenKeyEx),
	HOOK(advapi32, RegEnumValueW),

#ifndef _WIN64
	HOOK(shlwapi, UrlCanonicalizeW),
#endif
};

hook_t browser_hooks[] = {
	HOOK_SPECIAL(kernel32, CreateProcessInternalW),
	HOOK_SPECIAL(ntdll, NtCreateUserProcess),
};

hook_t test_hooks[] = {
	HOOK_NOTAIL_ALT(ntdll, RtlDispatchException, 2),
	HOOK_SPECIAL(ntdll, NtContinue),
};

BOOL inside_hook(LPVOID Address)
{
	for (unsigned int i = 0; i < hooks_arraysize; i++) {
		if ((ULONG_PTR)Address >= (ULONG_PTR)(hooks+i)->hookdata && (ULONG_PTR)Address < (ULONG_PTR)((hooks+i)->hookdata + sizeof(hook_data_t)))
			return TRUE;
	}

	return FALSE;
}

BOOL set_hooks_dll(const wchar_t *library)
{
	BOOL ret = FALSE;
	for (unsigned int i = 0; i < hooks_arraysize; i++) {
		if (!wcsicmp((hooks+i)->library, library)) {
			ret = TRUE;
			if (hook_api(hooks+i, g_config.hook_type) < 0)
				pipe("WARNING:Unable to hook %z", (hooks+i)->funcname);
		}
	}
	return ret;
}

void set_hooks_by_export_directory(const wchar_t *exportdirectory, const wchar_t *library)
{
	for (unsigned int i = 0; i < hooks_arraysize; i++) {
		if (!wcsicmp((hooks+i)->library, exportdirectory)) {
			hook_t *hook = hooks+i;
			hook->library = library;
			hook->exportdirectory = exportdirectory;
			hook->addr = NULL;
			hook->is_hooked = 0;
			if (hook_api(hook, g_config.hook_type) < 0)
				pipe("WARNING:Unable to hook %z", (hooks+i)->funcname);
		}
	}
}

extern void invalidate_regions_for_hook(const hook_t *hook);

void revalidate_all_hooks(void)
{
	for (unsigned int i = 0; i < hooks_arraysize; i++) {
		if ((hooks+i)->hook_addr && !is_valid_address_range((ULONG_PTR)(hooks+i)->hook_addr, 1)) {
			(hooks+i)->is_hooked = 0;
			(hooks+i)->hook_addr = NULL;
			invalidate_regions_for_hook(hooks+i);
		}
	}
}

PVOID g_dll_notify_cookie;

extern _LdrRegisterDllNotification pLdrRegisterDllNotification;

void set_hooks()
{
	// Before modifying any DLLs, let's first freeze all other threads in our process
	// otherwise our racy modifications can cause the task to crash prematurely
	// This code itself is racy as additional threads could be created while we're
	// processing the list, but the risk is at least greatly reduced

	HANDLE hSnapShot;
	BOOL Wow64Process;
	OSVERSIONINFO OSVersion;
	THREADENTRY32 threadInfo;
	DWORD old_protect, num_suspended_threads = 0;
	PHANDLE suspended_threads = (PHANDLE)calloc(4096, sizeof(HANDLE));
	DWORD our_tid = GetCurrentThreadId();
	DWORD our_pid = GetCurrentProcessId();

	BOOL TestHooks = FALSE;

	OSVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

	if (!GetVersionEx(&OSVersion))
		ErrorOutput("set_hooks: Failed to get OS version");

	IsWow64Process(GetCurrentProcess(), &Wow64Process);

	if (path_is_program_files(our_process_path_w))
	{
#ifndef _WIN64
		if (!_stricmp(our_process_name, "firefox.exe"))
        {
            g_config.firefox = 1;
            g_config.injection = 0;
			g_config.unpacker = 0;
            g_config.caller_regions = 0;
            g_config.api_rate_cap = 0;
            g_config.yarascan = 0;
            g_config.ntdll_protect = 0;
            DebugOutput("Firefox-specific hook-set enabled.\n");
        }
		else
#endif
		if (!_stricmp(our_process_name, "iexplore.exe"))
        {
            g_config.iexplore = 1;
            g_config.injection = 0;
            g_config.api_rate_cap = 0;
            g_config.ntdll_protect = 0;
            g_config.yarascan = 0;
            DebugOutput("Internet Explorer-specific hook-set enabled.\n");
        }

		if (strstr(our_process_path, "Microsoft Office"))
        {
			g_config.office = 1;
			g_config.unpacker = 0;
			g_config.caller_regions = 0;
			g_config.injection = 0;
			g_config.yarascan = 0;
			g_config.ntdll_protect = 0;
			DebugOutput("Microsoft Office settings enabled.\n");
        }
	}
	else if (path_is_system(our_process_path_w))
	{
		if (!_stricmp(our_process_name, "msiexec.exe")) {
			const char *excluded_apis[] = {
				"NtAllocateVirtualMemory",
				"NtProtectVirtualMemory",
				"VirtualProtectEx",
				"CryptDecodeMessage",
				"CryptDecryptMessage",
				"NtCreateThreadEx",
				"SetWindowLongPtrA",
				"SetWindowLongPtrW",
				"NtWaitForSingleObject",
				"NtSetTimer",
				"NtSetTimerEx",
				"RegOpenKeyExA",
				"RegOpenKeyExW",
				"RegCreateKeyExA",
				"RegCreateKeyExW",
				"RegDeleteKeyA",
				"RegDeleteKeyW",
				"RegEnumKeyW",
				"RegEnumKeyExA",
				"RegEnumKeyExW",
				"RegEnumValueA",
				"RegEnumValueW",
				"RegSetValueExA",
				"RegSetValueExW",
				"RegQueryValueExA",
				"RegQueryValueExW",
				"RegDeleteValueA",
				"RegDeleteValueW",
				"RegQueryInfoKeyA",
				"RegQueryInfoKeyW",
				"RegCloseKey",
				"RegNotifyChangeKeyValue",
				"NtCreateKey",
				"NtOpenKey",
				"NtOpenKeyEx",
				"NtRenameKey",
				"NtReplaceKey",
				"NtEnumerateKey",
				"NtEnumerateValueKey",
				"NtSetValueKey",
				"NtQueryValueKey",
				"NtQueryMultipleValueKey",
				"NtDeleteKey",
				"NtDeleteValueKey",
				"NtLoadKey",
				"NtLoadKey2",
				"NtLoadKeyEx",
				"NtQueryKey",
				"NtSaveKey",
				"NtSaveKeyEx"
			};

			for (unsigned int i = 0; i < sizeof(excluded_apis) / sizeof(excluded_apis[0]); i++) {
				if (!add_hook_exclusion(excluded_apis[i])) {
					DebugOutput("Unable to set hook exclusion for msiexec.\n");
					break;
				}
			}
			g_config.ntdll_protect = 0;
			g_config.yarascan = 0;
			g_config.msi = 1;
			DebugOutput("MsiExec hook set enabled\n");
		}
		else if (!_stricmp(our_process_name, "services.exe")) {
			g_config.yarascan = 0;
			g_config.unpacker = 0;
			g_config.caller_regions = 0;
			g_config.injection = 0;
			g_config.minhook = 1;
			DebugOutput("services.exe hook set enabled\n");
		}
		else if (!_stricmp(our_process_name, "svchost.exe") && wcsstr(our_commandline, L"-k DcomLaunch") || wcsstr(our_commandline, L"-k netsvcs")) {
			g_config.yarascan = 0;
			g_config.unpacker = 0;
			g_config.caller_regions = 0;
			g_config.injection = 0;
			g_config.minhook = 1;
			DebugOutput("Service host hook set enabled\n");
		}
		else if (!_stricmp(our_process_name, "wscript.exe")) {
			const char *excluded_apis[] = {
				"memcpy",
				"LoadResource",
				"LockResource",
				"SizeofResource",
			};
			for (unsigned int i = 0; i < sizeof(excluded_apis) / sizeof(excluded_apis[0]); i++) {
				if (!add_hook_exclusion(excluded_apis[i])) {
					DebugOutput("Unable to set hook exclusion for wscript\n");
					break;
				}
			}
			DebugOutput("wscript hook set enabled\n");
		}
	}

	// Hook set selection
	if (TestHooks) {
		DebugOutput("Test hook set enabled");
		hooks = test_hooks;
		hooks_size = sizeof(test_hooks);
		hooks_arraysize = ARRAYSIZE(test_hooks);
	}
	else if (g_config.tlsdump) {
		hooks = tls_hooks;
		hooks_size = sizeof(tls_hooks);
		hooks_arraysize = ARRAYSIZE(tls_hooks);
	}
	else if (g_config.minhook) {
		hooks = min_hooks;
		hooks_size = sizeof(min_hooks);
		hooks_arraysize = ARRAYSIZE(min_hooks);
	}
	else if (g_config.zerohook) {
		hooks = zero_hooks;
		hooks_size = sizeof(zero_hooks);
		hooks_arraysize = ARRAYSIZE(zero_hooks);
	}
	else if (g_config.office) {
		hooks = office_hooks;
		hooks_size = sizeof(office_hooks);
		hooks_arraysize = ARRAYSIZE(office_hooks);
	}
	else if (g_config.iexplore) {
		hooks = ie_hooks;
		hooks_size = sizeof(ie_hooks);
		hooks_arraysize = ARRAYSIZE(ie_hooks);
	}
	else if (g_config.chrome || g_config.firefox || g_config.edge) {
		hooks = browser_hooks;
		hooks_size = sizeof(browser_hooks);
		hooks_arraysize = ARRAYSIZE(browser_hooks);
	}
	else {
		hooks = full_hooks;
		hooks_size = sizeof(full_hooks);
		hooks_arraysize = ARRAYSIZE(full_hooks);
	}

	// The hooks contain executable code as well, so they have to be RWX
	VirtualProtect(hooks, hooks_size, PAGE_EXECUTE_READWRITE, &old_protect);

	memset(&threadInfo, 0, sizeof(threadInfo));
	threadInfo.dwSize = sizeof(threadInfo);

	hook_init();

	hook_disable();

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	Thread32First(hSnapShot, &threadInfo);
	do {
		if (threadInfo.th32OwnerProcessID != our_pid || threadInfo.th32ThreadID == our_tid || num_suspended_threads >= 4096)
			continue;
		suspended_threads[num_suspended_threads] = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadInfo.th32ThreadID);
		if (suspended_threads[num_suspended_threads]) {
			SuspendThread(suspended_threads[num_suspended_threads]);
			num_suspended_threads++;
		}
	} while (Thread32Next(hSnapShot, &threadInfo));

	for (unsigned int i = 0; i < hooks_arraysize; i++) {
#ifndef _WIN64
		if ((OSVersion.dwMajorVersion == 6 && OSVersion.dwMinorVersion > 1) || OSVersion.dwMajorVersion > 6) {
			if (Wow64Process == FALSE) {
				if (!stricmp((hooks+i)->funcname, "NtWaitForSingleObject"))
					continue;
			}
		}
#endif
		//DebugOutput("set_hooks: Hooking %s", (hooks+i)->funcname);
		if (hook_api(hooks+i, g_config.hook_type) < 0)
			pipe("WARNING:Unable to hook %z", (hooks+i)->funcname);
	}

	for (unsigned int i = 0; i < num_suspended_threads; i++) {
		ResumeThread(suspended_threads[i]);
		CloseHandle(suspended_threads[i]);
	}

	free(suspended_threads);

	if (pLdrRegisterDllNotification)
		pLdrRegisterDllNotification(0, &New_DllLoadNotification, NULL, &g_dll_notify_cookie);
	else
		register_dll_notification_manually(&New_DllLoadNotification);

	hook_enable();
}
