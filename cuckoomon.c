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
#include "misc.h"
#include "hooking.h"
#include "hooks.h"
#include "log.h"
#include "pipe.h"
#include "ignore.h"
#include "hook_file.h"
#include "hook_sleep.h"
#include "config.h"
#include "unhook.h"
#include "bson.h"
#include "Shlwapi.h"

struct _g_config g_config;
char *our_process_path;
char *our_dll_path;
wchar_t *our_process_path_w;
wchar_t *our_dll_path_w;
wchar_t *our_commandline;
BOOL is_64bit_os;
volatile int dummy_val;

extern void init_CAPE();
extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern LONG WINAPI CAPEExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo);
extern ULONG_PTR base_of_dll_of_interest;
#ifdef CAPE_TRACE
extern BOOL SetInitialBreakpoints(PVOID ImageBase);
#endif
extern PCHAR ScyllaGetExportDirectory(PVOID Address);
extern void ExtractionDllInit(PVOID DllBase);

void disable_tail_call_optimization(void)
{
	dummy_val++;
}

// Allow debug mode to be turned on at compilation time.
#ifdef CUCKOODBG
#undef CUCKOODBG
#define CUCKOODBG 1
#else
#define CUCKOODBG 0
#endif

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

static hook_t g_hooks[] = {

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

    //HOOK(kernel32, lstrcpynA),
    //HOOK(kernel32, lstrcmpiA),

	// special handling
	HOOK_SPECIAL(jscript, COleScript_ParseScriptText),
	HOOK_NOTAIL(jscript, JsEval, 5),
	HOOK_SPECIAL(jscript9, JsParseScript),
	HOOK_NOTAIL(jscript9, JsRunScript, 4),
	HOOK_SPECIAL(mshtml, CDocument_write),

	// COM object creation hook
	HOOK_SPECIAL(ole32, CoCreateInstance),
	HOOK_SPECIAL(ole32, CoCreateInstanceEx),
	HOOK_SPECIAL(ole32, CoGetClassObject),

	HOOK_SPECIAL(ntdll, RtlDispatchException),
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

    //
    // Registry Hooks
    //
    // Note: Most, if not all, of the Registry API go natively from both the
    // A as well as the W versions. In other words, we have to hook all the
    // ascii *and* unicode APIs of those functions.
    //

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
	HOOK_NOTAIL(user32, CreateWindowExA, 12),
	HOOK_NOTAIL(user32, CreateWindowExW, 12),

	HOOK(user32, FindWindowA),
    HOOK(user32, FindWindowW),
    HOOK(user32, FindWindowExA),
    HOOK(user32, FindWindowExW),
	// Disable for now, invokes a user-specified callback that can contain calls to any functions that we
	// won't end up logging. We need another hook type which logs the hook and then every function
	// called by that hook (modulo perhaps some blacklisted functions for this specific hook type)
    //HOOK(user32, EnumWindows),
	HOOK(user32, PostMessageA),
	HOOK(user32, PostMessageW),
	HOOK(user32, SendMessageA),
	HOOK(user32, SendMessageW),
	HOOK(user32, SendNotifyMessageA),
	HOOK(user32, SendNotifyMessageW),
	HOOK(user32, SetWindowLongA),
	HOOK(user32, SetWindowLongW),
	HOOK(user32, SetWindowLongPtrA),
	HOOK(user32, SetWindowLongPtrW),

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
	HOOK(kernel32, CreateToolhelp32Snapshot),
	HOOK(kernel32, Process32FirstW),
	HOOK(kernel32, Process32NextW),
	HOOK(kernel32, Module32FirstW),
	HOOK(kernel32, Module32NextW),
	HOOK(ntdll, NtCreateProcess),
    HOOK(ntdll, NtCreateProcessEx),
    HOOK(ntdll, RtlCreateUserProcess),
    HOOK(ntdll, NtOpenProcess),
    HOOK(ntdll, NtTerminateProcess),
	HOOK(ntdll, NtResumeProcess),
	HOOK(ntdll, NtCreateSection),
	HOOK(ntdll, NtDuplicateObject),
    HOOK(ntdll, NtMakeTemporaryObject),
    HOOK(ntdll, NtMakePermanentObject),
    HOOK(ntdll, NtOpenSection),
    HOOK(ntdll, NtMapViewOfSection),
	HOOK(kernel32, WaitForDebugEvent),
	HOOK(ntdll, DbgUiWaitStateChange),
	HOOK(advapi32, CreateProcessWithLogonW),
	HOOK(advapi32, CreateProcessWithTokenW),

    // all variants of ShellExecute end up in ShellExecuteExW
    HOOK(shell32, ShellExecuteExW),
    HOOK(ntdll, NtUnmapViewOfSection),
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
    //HOOK(kernel32, VirtualFreeEx),
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
    HOOK(kernel32, CreateThread),
    HOOK(kernel32, CreateRemoteThread),
    HOOK(ntdll, RtlCreateUserThread),
    HOOK(ntdll, NtSetInformationThread),
    HOOK(ntdll, NtQueryInformationThread),
    HOOK(ntdll, NtYieldExecution),
    HOOK(ntdll, NtContinue),

    // Memory copy hooks
    //HOOK(ntdll, RtlMoveMemory),

    // Misc Hooks
#ifndef _WIN64
	HOOK(ntdll, memcpy),
#endif
	HOOK(kernel32, OutputDebugStringA),
	HOOK(kernel32, OutputDebugStringW),
	HOOK(kernel32, HeapCreate),
	HOOK(msvcrt, memcpy),
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

	// transaction functions (for process doppel-ganging)
	HOOK(ntdll, NtCreateTransaction),
	HOOK(ntdll, NtOpenTransaction),
	HOOK(ntdll, NtRollbackTransaction),
	HOOK(ntdll, NtCommitTransaction),
	HOOK(ntdll, RtlSetCurrentTransaction),

    // Network Hooks
	HOOK(netapi32, NetUserGetInfo),
	HOOK(netapi32, NetGetJoinInformation),
	HOOK(netapi32, NetUserGetLocalGroups),
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

    //
    // Crypto Functions
    //

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

	HOOK(vbe7, rtcEnvironBstr),
};

void set_hooks_dll(const wchar_t *library)
{
	for (unsigned int i = 0; i < ARRAYSIZE(g_hooks); i++) {
        if(!wcsicmp(g_hooks[i].library, library)) {
			if (hook_api(&g_hooks[i], g_config.hook_type) < 0)
				pipe("WARNING:Unable to hook %z", g_hooks[i].funcname);
        }
    }
}

void set_hooks_by_export_directory(const wchar_t *exportdirectory, const wchar_t *library)
{
	for (unsigned int i = 0; i < ARRAYSIZE(g_hooks); i++) {
        if(!wcsicmp(g_hooks[i].library, exportdirectory)) {
			hook_t hook = g_hooks[i];
            hook.library = library;
            hook.exportdirectory = exportdirectory;
            hook.addr = NULL;
            hook.is_hooked = 0;
            if (hook_api(&hook, g_config.hook_type) < 0)
				pipe("WARNING:Unable to hook %z", g_hooks[i].funcname);
        }
    }
}
extern void invalidate_regions_for_hook(const hook_t *hook);

void revalidate_all_hooks(void)
{
	int i;
	for (i = 0; i < ARRAYSIZE(g_hooks); i++) {
		if (g_hooks[i].hook_addr && !is_valid_address_range((ULONG_PTR)g_hooks[i].hook_addr, 1)) {
			g_hooks[i].is_hooked = 0;
			g_hooks[i].hook_addr = NULL;
			invalidate_regions_for_hook(&g_hooks[i]);
		}
	}
}

PVOID g_dll_notify_cookie;

VOID CALLBACK New_DllLoadNotification(
	_In_     ULONG                       NotificationReason,
	_In_     const PLDR_DLL_NOTIFICATION_DATA NotificationData,
	_In_opt_ PVOID                       Context)
{
	PWCHAR dllname, rundll_path;
	COPY_UNICODE_STRING(library, NotificationData->Loaded.FullDllName);

	if (g_config.debug) {
		int ret = 0;
		/* Just for debug purposes, gives a stripped fake function name */
		LOQ_void("system", "sup", "NotificationReason", NotificationReason == 1 ? "load" : "unload", "DllName", library.Buffer, "DllBase", NotificationReason == 1 ? NotificationData->Loaded.DllBase : NotificationData->Unloaded.DllBase);
	}

    // for rundll32 only
    rundll_path = wcschr(our_commandline, ' ');
	if (rundll_path)
        if (*rundll_path == L' ') rundll_path++;

    if (NotificationReason == 1) {
		if (g_config.file_of_interest && !wcsicmp(library.Buffer, g_config.file_of_interest)) {
            if (!base_of_dll_of_interest)
                set_dll_of_interest((ULONG_PTR)NotificationData->Loaded.DllBase);
            DoOutputDebugString("Target DLL loaded at 0x%p: %ws (0x%x bytes).\n", NotificationData->Loaded.DllBase, library.Buffer, NotificationData->Loaded.SizeOfImage);
            if (g_config.extraction)
                ExtractionDllInit((PVOID)base_of_dll_of_interest);
#ifdef CAPE_TRACE
            SetInitialBreakpoints((PVOID)base_of_dll_of_interest);
#endif
        }
        else if (((!wcsnicmp(our_commandline, L"c:\\windows\\system32\\rundll32.exe", 32) ||
                    !wcsnicmp(our_commandline, L"c:\\windows\\syswow64\\rundll32.exe", 32) ||
                    !wcsnicmp(our_commandline, L"c:\\windows\\sysnative\\rundll32.exe", 33))) &&
                    !wcsnicmp(rundll_path, library.Buffer, wcslen(library.Buffer))) {
            set_dll_of_interest((ULONG_PTR)NotificationData->Loaded.DllBase);
            if (g_config.file_of_interest == NULL) {
                g_config.file_of_interest = calloc(1, (wcslen(library.Buffer) + 1) * sizeof(wchar_t));
                wcsncpy(g_config.file_of_interest, library.Buffer, wcslen(library.Buffer));
            }
            DoOutputDebugString("rundll32 target DLL loaded at 0x%p: %ws (0x%x bytes).\n", NotificationData->Loaded.DllBase, library.Buffer, NotificationData->Loaded.SizeOfImage);
#ifdef CAPE_TRACE
            SetInitialBreakpoints((PVOID)base_of_dll_of_interest);
#endif
        }
        else {

            SIZE_T numconverted, size;
            WCHAR exportdirectory_w[MAX_PATH];
            char* exportdirectory;

            // unoptimized, but easy
            add_all_dlls_to_dll_ranges();

            dllname = get_dll_basename(&library);
            set_hooks_dll(dllname);

            exportdirectory = ScyllaGetExportDirectory(NotificationData->Loaded.DllBase);
            if (exportdirectory) {
                size = strlen(exportdirectory);
                mbstowcs_s(&numconverted, exportdirectory_w, MAX_PATH, exportdirectory, size+1);
                for (unsigned int i=0; i<numconverted; i++) {
                    if (!wcsnicmp(exportdirectory_w+i, L".dll", 4))
                        memset(exportdirectory_w+i, 0, sizeof(WCHAR));
                }
                if (wcsicmp(dllname, exportdirectory_w))
                    set_hooks_by_export_directory(exportdirectory_w, dllname);
            }

#ifdef CAPE_TRACE
            //if (g_config.break_on_apiname && g_config.break_on_modname) {
            //    dllname = (char*)malloc(MAX_PATH);
            //    WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, (LPCWSTR)dllname_w, (int)wcslen(dllname_w)+1, dllname, MAX_PATH, NULL, NULL);
            //    if (!stricmp(dllname, g_config.break_on_modname)) {
            //        SetInitialBreakpoints(NotificationData->Loaded.DllBase);
            //    }
            //}
#endif
            DoOutputDebugString("DLL loaded at 0x%p: %ws (0x%x bytes).\n", NotificationData->Loaded.DllBase, library.Buffer, NotificationData->Loaded.SizeOfImage);
        }
	}
	else {
		// unload
		if (!is_valid_address_range((ULONG_PTR)NotificationData->Unloaded.DllBase, 0x1000)) {
			// if this unload actually caused removal of the DLL instead of a reference counter decrement,
			// then we need to loop through our hooks and unmark the hooks eliminated by this removal
			revalidate_all_hooks();
		}
	}
}

extern _LdrRegisterDllNotification pLdrRegisterDllNotification;

void set_hooks()
{
	// before modifying any DLLs, let's first freeze all other threads in our process
	// otherwise our racy modifications can cause the task to crash prematurely
	// This code itself is racy as additional threads could be created while we're
	// processing the list, but the risk is at least greatly reduced
	PHANDLE suspended_threads = (PHANDLE)calloc(4096, sizeof(HANDLE));
	DWORD num_suspended_threads = 0;
	DWORD i;
	HANDLE hSnapShot;
	THREADENTRY32 threadInfo;
	DWORD our_tid = GetCurrentThreadId();
	DWORD our_pid = GetCurrentProcessId();
	// the hooks contain executable code as well, so they have to be RWX
	DWORD old_protect;

	VirtualProtect(g_hooks, sizeof(g_hooks), PAGE_EXECUTE_READWRITE, &old_protect);

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

    // now, hook each api :)
    for (i = 0; i < ARRAYSIZE(g_hooks); i++) {
		//pipe("INFO:Hooking %z", g_hooks[i].funcname);
		if (hook_api(&g_hooks[i], g_config.hook_type) < 0)
			pipe("WARNING:Unable to hook %z", g_hooks[i].funcname);
    }

	for (i = 0; i < num_suspended_threads; i++) {
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

static int parse_stack_trace(void *msg, ULONG_PTR addr)
{
	unsigned int offset;
	char *buf = convert_address_to_dll_name_and_offset(addr, &offset);
	if (buf) {
		snprintf((char *)msg + strlen(msg), sizeof(msg) - strlen(msg) - 1, " %s+%x", buf, offset);
		free(buf);
	}

	return 0;
}

LONG WINAPI cuckoomon_exception_handler(__in struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	char *msg;
	char *dllname;
	char *sehname;
	unsigned int offset;
	ULONG_PTR eip;
	ULONG_PTR ebp_or_rip;
	ULONG_PTR seh = 0;
	PUCHAR eipptr;
	ULONG_PTR *stack;
	lasterror_t lasterror;

	if (ExceptionInfo->ExceptionRecord == NULL || ExceptionInfo->ContextRecord == NULL)
		return EXCEPTION_CONTINUE_SEARCH;

	eip = (ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress;
	eipptr = (PUCHAR)eip;

#ifdef _WIN64
	stack = (ULONG_PTR *)(ULONG_PTR)(ExceptionInfo->ContextRecord->Rsp);
	ebp_or_rip = eip;
#else
	stack = (ULONG_PTR *)(ULONG_PTR)(ExceptionInfo->ContextRecord->Esp);
	ebp_or_rip = (ULONG_PTR)(ExceptionInfo->ContextRecord->Ebp);
	{
		DWORD *tebtmp = (DWORD *)NtCurrentTeb();
		if (tebtmp[0] != 0xffffffff)
			seh = ((DWORD *)tebtmp[0])[1];
	}
#endif

	if (g_config.debug == 1 && ExceptionInfo->ExceptionRecord->ExceptionCode < 0xc0000000)
		return EXCEPTION_CONTINUE_SEARCH;

    if (ExceptionInfo->ExceptionRecord->ExceptionCode == DBG_PRINTEXCEPTION_C)
		return EXCEPTION_CONTINUE_SEARCH;

    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
		return CAPEExceptionFilter(ExceptionInfo);

    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
		return CAPEExceptionFilter(ExceptionInfo);

	hook_disable();

	get_lasterrors(&lasterror);

	log_flush();

	msg = malloc(32768);

	dllname = convert_address_to_dll_name_and_offset(eip, &offset);

	sprintf(msg, "Exception Caught! PID: %u EIP:", GetCurrentProcessId());
	if (dllname)
		snprintf(msg + strlen(msg), sizeof(msg) - strlen(msg) - 1, " %s+%x", dllname, offset);

	sehname = convert_address_to_dll_name_and_offset(seh, &offset);
	if (sehname)
		snprintf(msg + strlen(msg), sizeof(msg) - strlen(msg) - 1, " SEH: %s+%x", sehname, offset);

	snprintf(msg + strlen(msg), sizeof(msg) - strlen(msg), " %.08Ix, Fault Address: %.08Ix, Esp: %.08Ix, Exception Code: %08x, ",
		eip, ExceptionInfo->ExceptionRecord->ExceptionInformation[1], (ULONG_PTR)stack, ExceptionInfo->ExceptionRecord->ExceptionCode);

	operate_on_backtrace((ULONG_PTR)stack, ebp_or_rip, msg, &parse_stack_trace);

#ifdef _FULL_STACK_TRACE
	if (is_valid_address_range((ULONG_PTR)stack, 100 * sizeof(ULONG_PTR)))
	{
		DWORD i;
		// overflows ahoy
		for (i = 0; i < (get_stack_top() - (ULONG_PTR)stack)/sizeof(ULONG_PTR); i++) {
			char *buf = convert_address_to_dll_name_and_offset(stack[i], &offset);
			if (buf) {
				snprintf(msg + strlen(msg), sizeof(msg) - strlen(msg) - 1, " %s+%x", buf, offset);
				free(buf);
			}
			if (sizeof(msg) - strlen(msg) < 100)
				goto next;
		}
		strcat(msg, ", ");
	}
	else {
		strcat(msg, "invalid stack, ");
	}
next:
#endif

	if (is_valid_address_range(eip, 16)) {
		snprintf(msg + strlen(msg), sizeof(msg) - strlen(msg) - 1, " Bytes at EIP: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			eipptr[0], eipptr[1], eipptr[2], eipptr[3], eipptr[4], eipptr[5], eipptr[6], eipptr[7], eipptr[8], eipptr[9], eipptr[10], eipptr[11], eipptr[12], eipptr[13], eipptr[14], eipptr[15]);
	}
	debug_message(msg);
    DoOutputDebugString(msg);
	if (dllname)
		free(dllname);
	free(msg);

	set_lasterrors(&lasterror);

	hook_enable();

	return EXCEPTION_CONTINUE_SEARCH;
}

static void notify_successful_load(void)
{
	// notify analyzer.py that we've loaded
	pipe("LOADED:%d", GetCurrentProcessId());
}

void get_our_process_path(void)
{
	wchar_t *tmp = calloc(1, 32768 * sizeof(wchar_t));
	wchar_t *tmp2 = calloc(1, 32768 * sizeof(wchar_t));
    our_process_path = (char*)calloc(sizeof(char), MAX_PATH);

	GetModuleFileNameW(NULL, tmp, 32768);

	ensure_absolute_unicode_path(tmp2, tmp);

	our_process_path_w = tmp2;

    WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, (LPCWSTR)our_process_path_w, (int)wcslen(our_process_path_w)+1, our_process_path, MAX_PATH, NULL, NULL);

	free(tmp);
}

void get_our_dll_path(void)
{
	wchar_t *tmp = calloc(1, 32768 * sizeof(wchar_t));
	wchar_t *tmp2 = calloc(1, 32768 * sizeof(wchar_t));
    our_dll_path = (char*)calloc(sizeof(char), MAX_PATH);

	GetModuleFileNameW((HMODULE)g_our_dll_base, tmp, 32768);

	ensure_absolute_unicode_path(tmp2, tmp);

	our_dll_path_w = tmp2;

    WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, (LPCWSTR)our_dll_path_w, (int)wcslen(our_dll_path_w)+1, our_dll_path, MAX_PATH, NULL, NULL);

	free(tmp);
}
void get_our_commandline(void)
{
	wchar_t *tmp = calloc(1, 32768 * sizeof(wchar_t));

    PEB *peb = get_peb();

    ensure_absolute_unicode_path(tmp, peb->ProcessParameters->CommandLine.Buffer);

    our_commandline = tmp;
}

void set_os_bitness(void)
{
	LPFN_ISWOW64PROCESS pIsWow64Process;

	is_64bit_os = FALSE;

	pIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");

	if (pIsWow64Process)
		pIsWow64Process(GetCurrentProcess(), &is_64bit_os);
}

HANDLE g_heap;

static void *malloc_func(size_t size)
{
	return malloc(size);
}

static void *realloc_func(void *ptr, size_t size)
{
	return realloc(ptr, size);
}

static void free_func(void *ptr)
{
	free(ptr);
}

void init_private_heap(void)
{
	bson_set_malloc_func(malloc_func);
	bson_set_realloc_func(realloc_func);
	bson_set_free_func(free_func);
#ifdef USE_PRIVATE_HEAP
	g_heap = HeapCreate(0, 4 * 1024 * 1024, 0);
#endif
}

BOOL inside_hook(LPVOID Address)
{
	for (unsigned int i = 0; i < ARRAYSIZE(g_hooks); i++) {
        if ((ULONG_PTR)Address >= (ULONG_PTR)g_hooks[i].hookdata && (ULONG_PTR)Address < (ULONG_PTR)(g_hooks[i].hookdata + sizeof(hook_data_t)))
            return TRUE;
    }

    return FALSE;
}
BOOLEAN g_dll_main_complete;

extern void ignored_threads_init(void);

extern CRITICAL_SECTION readfile_critsec;

extern CRITICAL_SECTION g_mutex;
extern CRITICAL_SECTION g_writing_log_buffer_mutex;

OSVERSIONINFOA g_osverinfo;

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
{
	char config_fname[MAX_PATH], analyzer_path[MAX_PATH];
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	if (dwReason == DLL_PROCESS_ATTACH) {
		unsigned int i;
		DWORD pids[MAX_PROTECTED_PIDS];
		unsigned int length = sizeof(pids);

#ifdef STANDALONE
        // initialise CAPE
        resolve_runtime_apis();
        init_CAPE();
        return TRUE;
#endif

		/* we can sometimes be injected twice into a process, say if we queued up an APC that we timed out waiting to
		   complete, and then did a successful createremotethread, so just do a cheap check for our hooks and fake that
		   we loaded successfully
		*/
		/* Doesn't handle all hook types, modify as necessary */
		if (!memcmp((PUCHAR)WaitForDebugEvent, "\x8b\xff\xff\x25", 4) || !memcmp((PUCHAR)WaitForDebugEvent, "\xff\x25", 2) ||
			!memcmp((PUCHAR)WaitForDebugEvent, "\x8b\xff\xe9", 3) || !memcmp((PUCHAR)WaitForDebugEvent, "\xe9", 1) ||
			!memcmp((PUCHAR)WaitForDebugEvent, "\xeb\xf9", 2))
			goto abort;

		g_our_dll_base = (ULONG_PTR)hModule;
		g_our_dll_size = get_image_size(g_our_dll_base);

		g_osverinfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
		GetVersionEx(&g_osverinfo);

		resolve_runtime_apis();

		init_private_heap();

		set_os_bitness();

		InitializeCriticalSection(&g_mutex);
		InitializeCriticalSection(&g_writing_log_buffer_mutex);

		// initialize file stuff, needs to be performed prior to any file normalization
		file_init();
		//ignored_threads_init();

		get_our_dll_path();

		get_our_process_path();

		get_our_commandline();

		// adds our own DLL range as well, since the hiding is done later
		add_all_dlls_to_dll_ranges();

        // read the config settings
		if (!read_config())
#if CUCKOODBG
			;
		else
			DoOutputDebugString("Config loaded.\n");
#else
			// if we're not debugging, then failure to read the cuckoomon config should be a critical error
			goto abort;
#endif

		// don't inject into our own binaries run out of the analyzer directory unless they're the first process (intended)
		if (wcslen(g_config.w_analyzer) && !wcsnicmp(our_process_path_w, g_config.w_analyzer, wcslen(g_config.w_analyzer)) && !g_config.first_process)
			goto abort;

		if (g_config.debug) {
			AddVectoredExceptionHandler(1, cuckoomon_exception_handler);
			SetUnhandledExceptionFilter(cuckoomon_exception_handler);
			SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOALIGNMENTFAULTEXCEPT | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
			_set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
		}

#if !CUCKOODBG
		hide_module_from_peb(hModule);
#endif

		// obtain all protected pids
        pipe2(pids, &length, "GETPIDS:");
        for (i = 0; i < length / sizeof(pids[0]); i++) {
            add_protected_pid(pids[i]);
        }

		hkcu_init();

        // initialize the log file
        log_init(CUCKOODBG);

        // initialize the Sleep() skipping stuff
        init_sleep_skip(g_config.first_process);

        // we skip a random given amount of milliseconds each run
        init_startup_time(g_config.startup_time);

        // disable the retaddr check if the user wants so
        //if(g_config.retaddr_check == 0) {
        //    hook_disable_retaddr_check();
        //}

		// initialize our unhook detection
        unhook_init_detection();

        // initialize detection of process name spoofing
		procname_watch_init();

		// initialize terminate notification event
		terminate_event_init();

		// initialize misc critical sections
		InitializeCriticalSection(&readfile_critsec);

		// initialize all hooks
        set_hooks();

		// initialize context watchdog
		//init_watchdog();

        // initialise CAPE
        init_CAPE();

#ifndef _WIN64
		if (!g_config.no_stealth) {
			/* for people too lazy to setup VMs properly */
			PEB *peb = get_peb();
			if (peb->NumberOfProcessors == 1)
				peb->NumberOfProcessors = 2;
		}
#endif

		notify_successful_load();
    }
    else if(dwReason == DLL_PROCESS_DETACH) {
		// in production, we shouldn't ever get called in this way since we
		// unlink ourselves from the module list in the PEB
		// so don't call log_free(), as it'll have side-effects
        // log_free();
    }

	g_dll_main_complete = TRUE;
	set_lasterrors(&lasterror);
	return TRUE;

abort:
    // delete config file
    strncpy(analyzer_path, our_dll_path, strlen(our_dll_path));
    PathRemoveFileSpec(analyzer_path); // remove filename
    PathRemoveFileSpec(analyzer_path); // remove dll folder
    sprintf(config_fname, "%s\\%u.ini", analyzer_path, GetCurrentProcessId());
	DeleteFileA(config_fname);

    // backward compatibility
    memset(config_fname, 0, sizeof(config_fname));
	sprintf(config_fname, "C:\\%u.ini", GetCurrentProcessId());
	DeleteFileA(config_fname);

	set_lasterrors(&lasterror);
	return FALSE;
}
