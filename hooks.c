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
#include "CAPE\CAPE.h"

typedef struct
{
	PCHAR FunctionName;
	PVOID Address;
} NameByAddress;

extern NameByAddress* GetAddressesByYara(HMODULE ModuleBase, PCHAR FunctionNames[], SIZE_T FunctionCount, SIZE_T* OutFoundCount);
extern VOID CALLBACK New_DllLoadNotification(ULONG NotificationReason, const PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context);
extern PVOID GetAddressByYara(HMODULE ModuleBase, PCHAR FunctionName);
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

#define HOOK_WITHNAME(library, funcname, mangled) {L###library, mangled, NULL, NULL, \
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

#define HOOK_EXE(funcname) {NULL, #funcname, NULL, NULL, \
	&New_##funcname, (void **) &Old_##funcname, NULL, FALSE, FALSE, 0, FALSE}

#define HOOK_EXERVA(funcname, timestamp, rva) {NULL, #funcname, NULL, NULL, \
	&New_##funcname, (void **) &Old_##funcname, NULL, FALSE, FALSE, 0, FALSE, timestamp, rva}

#define HOOK_COM(moniker) {NULL, #moniker, NULL, NULL, \
    &New_##moniker, (void **) &Old_##moniker, NULL, FALSE, FALSE, 0, FALSE, 0, FALSE}

#define HOOK_COM_WITHNAME(friendlyname, funcname) {NULL, #funcname, NULL, NULL, \
    &New_##friendlyname, (void **) &Old_##friendlyname, NULL, FALSE, FALSE, 0, FALSE, 0, FALSE}


com_hook_t g_com_hooks[] = {
	{ HOOK_COM(WbemLocator_ConnectServer), &CLSID_WbemLocator, &IID_IWbemLocator },
	{ HOOK_COM_WITHNAME(WMI_ExecQuery, IWbemServices_ExecQuery), NULL, NULL },
	{ HOOK_COM_WITHNAME(WMI_ExecQueryAsync, IWbemServices_ExecQueryAsync), NULL, NULL },
	{ HOOK_COM_WITHNAME(WMI_CreateInstanceEnum, IWbemServices_CreateInstanceEnum), NULL, NULL },
	{ HOOK_COM_WITHNAME(WMI_CreateInstanceEnumAsync, IWbemServices_CreateInstanceEnumAsync), NULL, NULL },
	{ HOOK_COM_WITHNAME(WMI_GetObject, IWbemServices_GetObjectW), NULL, NULL },
	{ HOOK_COM_WITHNAME(WMI_GetObjectAsync, IWbemServices_GetObjectAsync), NULL, NULL },
	{ HOOK_COM_WITHNAME(WMI_ExecMethod, IWbemServices_ExecMethod), NULL, NULL },
	{ HOOK_COM_WITHNAME(WMI_ExecMethodAsync, IWbemServices_ExecMethodAsync), NULL, NULL },
};

hook_t full_hooks[] = {
	// Process Hooks
	HOOK_NOTAIL_ALT(ntdll, RtlDispatchException, 2),
	HOOK_NOTAIL(ntdll, NtRaiseException, 3),

	HOOK_NOTAIL_ALT(ntdll, LdrLoadDll, 4),
	HOOK_NOTAIL(ntdll, LdrUnloadDll, 1),
	HOOK_SPECIAL(ntdll, NtCreateUserProcess),
	HOOK_SPECIAL(kernel32, CreateProcessInternalW),

	HOOK(ntdll, LdrpCallInitRoutine),
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
	HOOK(ntdll, NtOpenProcessToken),
	HOOK(ntdll, NtAdjustPrivilegesToken),
	HOOK(ntdll, NtQueryInformationToken),
	HOOK(kernel32, WaitForDebugEvent),
	HOOK(ntdll, DbgUiWaitStateChange),
	HOOK(advapi32, CreateProcessWithLogonW),
	HOOK(advapi32, CreateProcessWithTokenW),
	HOOK(kernel32, CreateToolhelp32Snapshot),
	HOOK(kernel32, Process32FirstW),
	HOOK(kernel32, Process32NextW),
	HOOK(kernel32, Module32FirstW),
	HOOK(kernel32, Module32NextW),
	HOOK(kernel32, Thread32First),
	HOOK(kernel32, Thread32Next),
	HOOK(kernelbase, K32EnumProcesses),
	HOOK(wtsapi32, WTSEnumerateProcessesW),
	HOOK(wtsapi32, WTSEnumerateProcessesExW),
	HOOK(kernel32, CreateProcessA),
	HOOK(kernel32, CreateProcessW),
	HOOK(kernel32, WinExec),
	HOOK(kernel32, LoadLibraryExW),
	//HOOK(kernel32, VirtualFreeEx),
	// all variants of ShellExecute end up in ShellExecuteExW
	HOOK(shell32, ShellExecuteExW),
	HOOK(msvcrt, system),
	HOOK(ntdll, vDbgPrintExWithPrefixInternal),

	// Thread Hooks
	HOOK_SPECIAL(ntdll, NtCreateThread),
	HOOK_SPECIAL(ntdll, NtCreateThreadEx),
	HOOK(ntdll, NtTerminateThread),
	HOOK(ntdll, NtQueueApcThread),
	HOOK(ntdll, NtQueueApcThreadEx),
	HOOK(ntdll, NtOpenThread),
	HOOK(ntdll, NtGetContextThread),
	HOOK(ntdll, NtSetContextThread),
	HOOK_NOTAIL(ntdll, RtlUserThreadStart, 2),
#ifdef _WIN64
	HOOK(ntdll, RtlWow64GetThreadContext),
	HOOK(ntdll, RtlWow64SetThreadContext),
#endif
	HOOK(ntdll, NtSuspendThread),
	HOOK(ntdll, NtResumeThread),
	HOOK(ntdll, NtAlertResumeThread),
	HOOK(ntdll, RtlCreateUserThread),
	HOOK(ntdll, NtSetInformationThread),
	HOOK(ntdll, NtQueryInformationThread),
	HOOK(ntdll, NtYieldExecution),
	HOOK(ntdll, NtContinue),
	HOOK(ntdll, NtContinueEx),
	HOOK(ntdll, NtTestAlert),
	HOOK(kernelbase, SetThreadStackGuarantee),
	HOOK(kernelbase, SetThreadDescription),
	HOOK(kernel32, CreateThread),
	HOOK(kernel32, CreateRemoteThread),
	HOOK(kernel32, CreateRemoteThreadEx),
	HOOK(kernel32, SwitchToThread),
	//HOOK(kernel32, DisableThreadLibraryCalls),

	// Script hooks
	HOOK_SPECIAL(clrjit, compileMethod),
	HOOK_SPECIAL(urlmon, IsValidURL),
	HOOK_SPECIAL(jscript, COleScript_ParseScriptText),
	HOOK_NOTAIL(jscript, JsEval, 5),
	HOOK_SPECIAL(jscript9, JsParseScript),
	HOOK_NOTAIL(jscript9, JsRunScript, 4),
	HOOK_SPECIAL(mshtml, CDocument_write),

	// COM object creation hook
	HOOK_SPECIAL(ole32, CoCreateInstance),
	HOOK_SPECIAL(ole32, CoCreateInstanceEx),
	HOOK_SPECIAL(ole32, CoGetClassObject),
	HOOK_SPECIAL(ole32, CoGetObject),
	HOOK_SPECIAL(combase, CoCreateInstance),
	HOOK_SPECIAL(combase, CoCreateInstanceEx),
	HOOK_SPECIAL(combase, CoGetClassObject),
	HOOK_SPECIAL(combase, CoGetObject),

	// WMI Hooks
#ifdef _WIN64
	HOOK_WITHNAME(fastprox, WMI_Get, "?Get@CWbemObject@@UEAAJPEBGJPEAUtagVARIANT@@PEAJ2@Z"),
	HOOK_WITHNAME(fastprox, WMI_Next, "?Next@CWbemObject@@UEAAJJPEAPEAGPEAUtagVARIANT@@PEAJ2@Z"),
#else
	HOOK_WITHNAME(fastprox, WMI_Get, "?Get@CWbemObject@@UAGJPBGJPAUtagVARIANT@@PAJ2@Z"),
	HOOK_WITHNAME(fastprox, WMI_Next, "?Next@CWbemObject@@UAGJJPAPAGPAUtagVARIANT@@PAJ2@Z"),
#endif

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
	HOOK(ntdll, NtQueryVolumeInformationFile),
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
	HOOK(kernel32, GetVolumeInformationA),
	HOOK(kernel32, GetVolumeInformationW),
	HOOK(kernel32, SetFileInformationByHandle),
	HOOK(shell32, SHGetFolderPathW),
	HOOK(shell32, SHGetKnownFolderPath),
	HOOK(shell32, SHGetFileInfoW),
	HOOK(version, GetFileVersionInfoW),
	HOOK(version, GetFileVersionInfoSizeW),
	HOOK(kernel32, FindFirstChangeNotificationW),
	// lowest variant of MoveFile()
	HOOK_NOTAIL_ALT(kernel32, MoveFileWithProgressW, 5),
	HOOK_NOTAIL_ALT(kernelbase, MoveFileWithProgressTransactedW, 6),
	HOOK_NOTAIL_ALT(kernel32, MoveFileWithProgressTransactedW, 6),
	HOOK(kernel32, UpdateProcThreadAttribute),
	HOOK(kernel32, GetWriteWatch),
	HOOK(rstrtmgr, RmStartSession),

	// Registry Hooks
	// Note: Most, if not all, of the Registry API go natively from both the 'A' as well as
	// the 'W' versions. So we have to hook all the ascii *and* unicode APIs of those functions.
	HOOK(advapi32, RegOpenKeyExA),
	HOOK(advapi32, RegOpenKeyExW),
	HOOK(advapi32, RegCreateKeyExA),
	HOOK(advapi32, RegCreateKeyExW),
	HOOK(advapi32, RegDeleteKeyA),
	HOOK(advapi32, RegDeleteKeyW),
	// RegEnumKeyA() calls RegEnumKeyExA(), but RegEnumKeyW() does *not* call RegEnumKeyExW()
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
	HOOK(advapi32, RegDeleteKeyExW),
	HOOK(advapi32, RegDeleteKeyExA),
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
	HOOK(user32, PostThreadMessageA),
	HOOK(user32, PostThreadMessageW),
//	HOOK(user32, SendMessageA),	// maldoc detonation issues
//	HOOK(user32, SendMessageW),	//
	HOOK(user32, SendNotifyMessageA),
	HOOK(user32, SendNotifyMessageW),
	HOOK(user32, SetWindowLongA),
	HOOK(user32, SetWindowLongW),
	HOOK(user32, SetWindowLongPtrA),
	HOOK(user32, SetWindowLongPtrW),
	HOOK(user32, EnumDisplayDevicesA),
	HOOK(user32, EnumDisplayDevicesW),
	HOOK(msi, MsiInstallProductA),
	HOOK(msi, MsiInstallProductW),
//	HOOK_NOTAIL(user32, CreateWindowExA, 12),	// maldoc detonation issues
//	HOOK_NOTAIL(user32, CreateWindowExW, 12),	//
//	HOOK(user32, EnumWindows),	// Disable for now, invokes a user-specified callback that can contain
	// calls to any functions that we won't end up logging. We need another hook type which
	// logs the hook and then every function called by that hook (modulo perhaps some blacklisted
	// functions for this specific hook type)
	HOOK(user32, MessageBoxTimeoutW),
	HOOK(user32, EnumDisplayDevicesW),

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

	// Misc Hooks
	//HOOK(ntdll, RtlMoveMemory),
	HOOK(kernel32, GetCommandLineA),
	HOOK(kernel32, GetCommandLineW),
	HOOK(shcore, CommandLineToArgvW),
	HOOK(kernel32, OutputDebugStringA),
	HOOK(kernel32, OutputDebugStringW),
	HOOK(kernel32, HeapCreate),
	HOOK(msvcrt, srand),
	HOOK(user32, ChangeWindowMessageFilter),
	HOOK(user32, SetWindowsHookExA),
	HOOK(user32, SetWindowsHookExW),
	HOOK(user32, UnhookWindowsHookEx),
	HOOK(kernel32, SetUnhandledExceptionFilter),
	HOOK(kernel32, UnhandledExceptionFilter),
	HOOK(ntdll, RtlAddVectoredExceptionHandler),
	HOOK(ntdll, RtlRemoveVectoredExceptionHandler),
	HOOK(kernel32, SetErrorMode),
	HOOK(ntdll, LdrGetDllHandle),
	HOOK(ntdll, LdrGetDllHandleEx),
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
	HOOK(kernel32, GetComputerNameExW),
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
	HOOK(ntdll, NtQueryInformationProcess),
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
	HOOK(ole32, CLSIDFromProgIDEx),
	//HOOK(ole32, OleConvertOLESTREAMToIStorage),
	HOOK(kernel32, GlobalMemoryStatus),
	HOOK(kernel32, GlobalMemoryStatusEx),
	HOOK(kernel32, GetPhysicallyInstalledSystemMemory),
	HOOK(user32, SystemParametersInfoA),
	HOOK(user32, SystemParametersInfoW),
	HOOK(pstorec, PStoreCreateInstance),
	HOOK(advapi32, SaferIdentifyLevel),
	HOOK(user32, GetKeyboardLayout),
	//HOOK(oleaut32, SysFreeString),	// breaks Guloader e.g. 4f150ed4669f3a26cfbb6cf06c9843de3bf2a619de4807053512502ef983a3b2
	HOOK(oleaut32, VarBstrCat),
	HOOK_NOTAIL(usp10, ScriptIsComplex, 3),
	HOOK_NOTAIL(inseng,DownloadFile,3),
	HOOK(imagehlp, MapFileAndCheckSumA),
#ifndef _WIN64
	HOOK(ntdll, RtlDosPathNameToNtPathName_U),
	HOOK(ntdll, NtQueryLicenseValue),
	HOOK(vbe7, rtcEnvironBstr),
	HOOK(shlwapi, StrCmpNICW),
	HOOK(shlwapi, UrlCanonicalizeW),
	HOOK_NOTAIL(vbe7, rtcCreateObject2, 3),
#endif
	HOOK(ntdll, NtPowerInformation),

	HOOK(cmd, FindFixAndRun),
	HOOK(User32, GetClipboardData),
	HOOK(User32, OpenClipboard),
	HOOK(User32, SetClipboardData),

	// Language related hooks
	HOOK(ntdll, NtQueryDefaultUILanguage),
	HOOK(ntdll, NtQueryInstallUILanguage),
	HOOK(kernel32, GetSystemDefaultLangID),
	HOOK(kernel32, GetUserDefaultLCID),

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
	HOOK(ws2_32, GetAddrInfoExW),
	HOOK(mpr, WNetUseConnectionW),
	HOOK(cryptnet, CryptRetrieveObjectByUrlW),
	HOOK(ncrypt, SslEncryptPacket),
	HOOK(ncrypt, SslDecryptPacket),
	HOOK(iphlpapi, GetAdaptersAddresses),
	HOOK(iphlpapi, GetAdaptersInfo),
	HOOK(urlmon, CoInternetSetFeatureEnabled),
	HOOK(ole32, MkParseDisplayName),
	HOOK(urlmon, MkParseDisplayNameEx),

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
	HOOK(sechost, OpenSCManagerA),
	HOOK(sechost, OpenSCManagerW),
	HOOK(sechost, CreateServiceA),
	HOOK(sechost, CreateServiceW),
	HOOK(sechost, OpenServiceA),
	HOOK(sechost, OpenServiceW),
	HOOK(sechost, StartServiceA),
	HOOK(sechost, StartServiceW),
	HOOK(sechost, ControlService),
	HOOK(sechost, DeleteService),

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
	HOOK(winmm, timeSetEvent),
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

	// DPAPI
	HOOK(crypt32, CryptProtectData),
	HOOK(crypt32, CryptUnprotectData),
	HOOK(crypt32, CryptProtectMemory),
	HOOK(crypt32, CryptUnprotectMemory),

	// Legacy DPAPI
	HOOK(advapi32, CryptProtectData),
	HOOK(advapi32, CryptUnprotectData),
	HOOK(advapi32, CryptProtectMemory),
	HOOK(advapi32, CryptUnprotectMemory),
	HOOK(cryptsp, CryptProtectData),
	HOOK(cryptsp, CryptUnprotectData),
	HOOK(cryptsp, CryptProtectMemory),
	HOOK(cryptsp, CryptUnprotectMemory),

	// General CryptoAPI
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
	HOOK(advapi32, CryptDuplicateKey),
	HOOK(advapi32, CryptGenKey),
	HOOK(advapi32, CryptCreateHash),
	HOOK(advapi32, CryptDestroyHash),
	HOOK(advapi32, CryptEnumProvidersA),
	HOOK(advapi32, CryptEnumProvidersW),
	HOOK(advapi32, QueryUsersOnEncryptedFile),
	HOOK(advapi32, CryptGenRandom),
	HOOK(advapi32, CryptImportKey),
	HOOK(advapi32, CryptHashSessionKey),

	// crypt32 additional
	HOOK(crypt32, CryptDecodeObjectEx),
	HOOK(crypt32, CryptImportPublicKeyInfo),
	HOOK(crypt32, CryptEncryptMessage),
	HOOK(crypt32, CryptDecryptMessage),
	HOOK(crypt32, CryptHashMessage),
	HOOK(crypt32, CryptSignMessage),
	HOOK(crypt32, CryptVerifyMessageSignature),

	// CNG
	HOOK(bcrypt, BCryptImportKey),
	HOOK(bcrypt, BCryptImportKeyPair),
	HOOK(bcrypt, BCryptDecrypt),
	HOOK(bcrypt, BCryptEncrypt),
	HOOK(bcrypt, BCryptDeriveKey),
	HOOK(bcrypt, BCryptKeyDerivation),
	HOOK(bcrypt, BCryptHashData),
	HOOK(bcrypt, BCryptCreateHash),
	HOOK(bcrypt, BCryptDestroyHash),
	HOOK(bcrypt, BCryptGenRandom),
	HOOK(bcrypt, BCryptOpenAlgorithmProvider),
	HOOK(bcrypt, BCryptCloseAlgorithmProvider),

	HOOK(ncrypt, NCryptImportKey),
	HOOK(ncrypt, NCryptDecrypt),
	HOOK(ncrypt, NCryptEncrypt),
	HOOK(ncrypt, NCryptCreatePersistedKey),
	HOOK(ncrypt, NCryptFinalizeKey),
	HOOK(ncrypt, NCryptOpenKey),
	HOOK(cryptbase, SystemFunction036),
	HOOK(cryptbase, SystemFunction040),
	HOOK(cryptbase, SystemFunction041),

	// wintrust
	HOOK(wintrust, HTTPSCertificateTrust),
	HOOK(wintrust, HTTPSFinalProv),
	HOOK(wintrust, WTGetSignatureInfo),

	// Delay-loaded
	HOOK(cryptsp, CryptAcquireContextA),
	HOOK(cryptsp, CryptAcquireContextW),
	HOOK(cryptsp, CryptDecrypt),
	HOOK(cryptsp, CryptEncrypt),
	HOOK(cryptsp, CryptHashData),
	HOOK(cryptsp, CryptDecodeMessage),
	HOOK(cryptsp, CryptDecryptMessage),
	HOOK(cryptsp, CryptEncryptMessage),
	HOOK(cryptsp, CryptHashMessage),
	HOOK(cryptsp, CryptDeriveKey),
	HOOK(cryptsp, CryptExportKey),
	HOOK(cryptsp, CryptDestroyKey),
	HOOK(cryptsp, CryptDuplicateKey),
	HOOK(cryptsp, CryptGenKey),
	HOOK(cryptsp, CryptCreateHash),
	HOOK(cryptsp, CryptDestroyHash),
	HOOK(cryptsp, CryptEnumProvidersA),
	HOOK(cryptsp, CryptEnumProvidersW),
	HOOK(cryptsp, CryptHashSessionKey),
	HOOK(cryptsp, CryptGenRandom),
	HOOK(cryptsp, CryptImportKey),

	// VBScript hooks
	HOOK_SPECIAL(vbscript, VbsCCur),
	HOOK_SPECIAL(vbscript, VbsCInt),
	HOOK_SPECIAL(vbscript, VbsCLng),
	HOOK_SPECIAL(vbscript, VbsCBool),
	HOOK_SPECIAL(vbscript, VbsCByte),
	HOOK_SPECIAL(vbscript, VbsCDate),
	HOOK_SPECIAL(vbscript, VbsCDbl),
	HOOK_SPECIAL(vbscript, VbsCSng),
	HOOK_SPECIAL(vbscript, VbsCStr),
	HOOK_SPECIAL(vbscript, VbsHex),
	HOOK_SPECIAL(vbscript, VbsOct),
	HOOK_SPECIAL(vbscript, VbsVarType),
	HOOK_SPECIAL(vbscript, VbsIsDate),
	HOOK_SPECIAL(vbscript, VbsIsEmpty),
	HOOK_SPECIAL(vbscript, VbsIsNull),
	HOOK_SPECIAL(vbscript, VbsIsNumeric),
	HOOK_SPECIAL(vbscript, VbsIsArray),
	HOOK_SPECIAL(vbscript, VbsIsObject),
	HOOK_SPECIAL(vbscript, VbsAtn),
	HOOK_SPECIAL(vbscript, VbsCos),
	HOOK_SPECIAL(vbscript, VbsSin),
	HOOK_SPECIAL(vbscript, VbsTan),
	HOOK_SPECIAL(vbscript, VbsExp),
	HOOK_SPECIAL(vbscript, VbsLog),
	HOOK_SPECIAL(vbscript, VbsSqr),
	HOOK_SPECIAL(vbscript, VbsRandomize),
	HOOK_SPECIAL(vbscript, VbsRnd),
	HOOK_SPECIAL(vbscript, VbsTimer),
	HOOK_SPECIAL(vbscript, VbsLBound),
	HOOK_SPECIAL(vbscript, VbsUBound),
	HOOK_SPECIAL(vbscript, VbsRGB),
	HOOK_SPECIAL(vbscript, VbsLen),
	HOOK_SPECIAL(vbscript, VbsLenB),
	HOOK_SPECIAL(vbscript, VbsLeft),
	HOOK_SPECIAL(vbscript, VbsLeftB),
	HOOK_SPECIAL(vbscript, VbsRight),
	HOOK_SPECIAL(vbscript, VbsRightB),
	HOOK_SPECIAL(vbscript, VbsMid),
	HOOK_SPECIAL(vbscript, VbsMidB),
	HOOK_SPECIAL(vbscript, VbsStrComp),
	HOOK_SPECIAL(vbscript, VbsLCase),
	HOOK_SPECIAL(vbscript, VbsUCase),
	HOOK_SPECIAL(vbscript, VbsLTrim),
	HOOK_SPECIAL(vbscript, VbsRTrim),
	HOOK_SPECIAL(vbscript, VbsTrim),
	HOOK_SPECIAL(vbscript, VbsSpace),
	HOOK_SPECIAL(vbscript, VbsString),
	HOOK_SPECIAL(vbscript, VbsInStr),
	HOOK_SPECIAL(vbscript, VbsInStrB),
	HOOK_SPECIAL(vbscript, VbsEscape),
	HOOK_SPECIAL(vbscript, VbsUnescape),
	HOOK_SPECIAL(vbscript, VbsAscB),
	HOOK_SPECIAL(vbscript, VbsChrB),
	HOOK_SPECIAL(vbscript, VbsAsc),
	HOOK_SPECIAL(vbscript, VbsChr),
	HOOK_SPECIAL(vbscript, VbsAscW),
	HOOK_SPECIAL(vbscript, VbsChrW),
	HOOK_SPECIAL(vbscript, VbsAbs),
	HOOK_SPECIAL(vbscript, VbsFix),
	HOOK_SPECIAL(vbscript, VbsInt),
	HOOK_SPECIAL(vbscript, VbsSgn),
	HOOK_SPECIAL(vbscript, VbsNow),
	HOOK_SPECIAL(vbscript, VbsDate),
	HOOK_SPECIAL(vbscript, VbsTime),
	HOOK_SPECIAL(vbscript, VbsDay),
	HOOK_SPECIAL(vbscript, VbsMonth),
	HOOK_SPECIAL(vbscript, VbsWeekday),
	HOOK_SPECIAL(vbscript, VbsYear),
	HOOK_SPECIAL(vbscript, VbsHour),
	HOOK_SPECIAL(vbscript, VbsMinute),
	HOOK_SPECIAL(vbscript, VbsSecond),
	HOOK_SPECIAL(vbscript, VbsDateValue),
	HOOK_SPECIAL(vbscript, VbsTimeValue),
	HOOK_SPECIAL(vbscript, VbsDateSerial),
	HOOK_SPECIAL(vbscript, VbsTimeSerial),
	HOOK_SPECIAL(vbscript, VbsInputBox),
	HOOK_SPECIAL(vbscript, VbsMsgBox),
	HOOK_SPECIAL(vbscript, VbsCreateObject),
	HOOK_SPECIAL(vbscript, VbsGetObject),
	HOOK_SPECIAL(vbscript, VbsDateAdd),
	HOOK_SPECIAL(vbscript, VbsDateDiff),
	HOOK_SPECIAL(vbscript, VbsDatePart),
	HOOK_SPECIAL(vbscript, VbsTypeName),
	HOOK_SPECIAL(vbscript, VbsArray),
	HOOK_SPECIAL(vbscript, VbsErase),
	HOOK_SPECIAL(vbscript, VbsFilter),
	HOOK_SPECIAL(vbscript, VbsJoin),
	HOOK_SPECIAL(vbscript, VbsSplit),
	HOOK_SPECIAL(vbscript, VbsReplace),
	HOOK_SPECIAL(vbscript, VbsStrReverse),
	HOOK_SPECIAL(vbscript, VbsInStrRev),
	HOOK_SPECIAL(vbscript, VbsEval),
	HOOK_SPECIAL(vbscript, VbsExecute),
	HOOK_SPECIAL(vbscript, VbsExecuteGlobal),
	HOOK_SPECIAL(vbscript, VbsGetRef),
	HOOK_SPECIAL(vbscript, VbsSetLocale),
	HOOK_SPECIAL(vbscript, VbsGetLocale),
	HOOK_SPECIAL(vbscript, VbsGetUILanguage),
	HOOK_SPECIAL(vbscript, VbsLoadPicture),
	HOOK_SPECIAL(vbscript, VbsScriptEngine),
	HOOK_SPECIAL(vbscript, VbsScriptEngineMajorVersion),
	HOOK_SPECIAL(vbscript, VbsScriptEngineMinorVersion),
	HOOK_SPECIAL(vbscript, VbsScriptEngineBuildVersion),
	HOOK_SPECIAL(vbscript, VbsFormatNumber),
	HOOK_SPECIAL(vbscript, VbsFormatCurrency),
	HOOK_SPECIAL(vbscript, VbsFormatPercent),
	HOOK_SPECIAL(vbscript, VbsFormatDateTime),
	HOOK_SPECIAL(vbscript, VbsWeekdayName),
	HOOK_SPECIAL(vbscript, VbsMonthName),
	HOOK_SPECIAL(vbscript, VbsRound),
	HOOK_SPECIAL(vbscript, VbsPrint),
};

hook_t native_hooks[] = {

	HOOK_NOTAIL_ALT(ntdll, RtlDispatchException, 2),
	HOOK_NOTAIL(ntdll, NtRaiseException, 3),
	HOOK_NOTAIL_ALT(ntdll, LdrLoadDll, 4),
	HOOK_NOTAIL(ntdll, LdrUnloadDll, 1),
	HOOK_SPECIAL(ntdll, NtCreateUserProcess),

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
	HOOK(ntdll, NtWriteVirtualMemory),
	HOOK(ntdll, NtWow64WriteVirtualMemory64),
	HOOK(ntdll, NtWow64ReadVirtualMemory64),
	HOOK(ntdll, NtProtectVirtualMemory),
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
	HOOK(ntdll, NtOpenProcessToken),
	HOOK(ntdll, NtQueryInformationToken),
	HOOK(ntdll, DbgUiWaitStateChange),

	// Thread Hooks
	HOOK(ntdll, NtCreateThread),
	HOOK(ntdll, NtCreateThreadEx),
	HOOK(ntdll, NtTerminateThread),
	HOOK(ntdll, NtQueueApcThread),
	HOOK(ntdll, NtQueueApcThreadEx),
	HOOK(ntdll, NtOpenThread),
	HOOK(ntdll, NtGetContextThread),
#ifdef _WIN64
	HOOK(ntdll, RtlWow64GetThreadContext),
	HOOK(ntdll, RtlWow64SetThreadContext),
#endif
	HOOK(ntdll, NtSetContextThread),
	HOOK(ntdll, NtSuspendThread),
	HOOK(ntdll, NtResumeThread),
	HOOK(ntdll, RtlCreateUserThread),
	HOOK(ntdll, NtSetInformationThread),
	HOOK(ntdll, NtQueryInformationThread),
	HOOK(ntdll, NtYieldExecution),
	HOOK(ntdll, NtContinue),

	// Misc Hooks
	//HOOK(ntdll, RtlMoveMemory),
	HOOK(ntdll, RtlAddVectoredExceptionHandler),
	HOOK(ntdll, LdrGetDllHandle),
	HOOK(ntdll, LdrGetProcedureAddress),
	HOOK(ntdll, LdrGetProcedureAddressForCaller),
	HOOK_NOTAIL(ntdll, NtShutdownSystem, 1),
	HOOK_NOTAIL(ntdll, NtSetSystemPowerState, 3),
	HOOK_NOTAIL(ntdll, NtRaiseHardError, 6),
	HOOK(ntdll, NtClose),
	HOOK(ntdll, NtLoadDriver),
	HOOK(ntdll, NtSetInformationProcess),
	//HOOK(ntdll, NtQueryInformationProcess),
	HOOK(ntdll, RtlDecompressBuffer),
	HOOK(ntdll, RtlCompressBuffer),
	HOOK(ntdll, NtQuerySystemInformation),
	HOOK(ntdll, NtQueryInformationProcess),
#ifndef _WIN64
	HOOK(ntdll, RtlDosPathNameToNtPathName_U),
	HOOK(ntdll, NtQueryLicenseValue),
#endif

	// transaction functions (for process doppelganging)
	HOOK(ntdll, NtCreateTransaction),
	HOOK(ntdll, NtOpenTransaction),
	HOOK(ntdll, NtRollbackTransaction),
	HOOK(ntdll, NtCommitTransaction),
	HOOK(ntdll, RtlSetCurrentTransaction),

	// Sleep Hooks
	HOOK(ntdll, NtQueryPerformanceCounter),
	HOOK(ntdll, NtDelayExecution),
	HOOK(ntdll, NtWaitForSingleObject),
	HOOK_SPECIAL(ntdll, NtQuerySystemTime),
	HOOK(ntdll, NtSetTimer),
	HOOK(ntdll, NtSetTimerEx),
};

// This hook set is intended to include only hooks which are necessary
// to follow the execution chain with base functionality

hook_t min_hooks[] = {
	HOOK_NOTAIL_ALT(ntdll, RtlDispatchException, 2),
	HOOK_NOTAIL(ntdll, NtRaiseException, 3),

	HOOK_NOTAIL_ALT(ntdll, LdrLoadDll, 4),
	HOOK_NOTAIL(ntdll, LdrUnloadDll, 1),
	HOOK_SPECIAL(ntdll, NtCreateUserProcess),
	HOOK_SPECIAL(kernel32, CreateProcessInternalW),

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
	HOOK(ntdll, NtContinueEx),
	HOOK(ntdll, NtQueueApcThread),
	HOOK(ntdll, NtQueueApcThreadEx),
	HOOK(ntdll, NtCreateThread),
	HOOK(ntdll, NtCreateThreadEx),
	HOOK(ntdll, NtSetContextThread),
	HOOK(ntdll, NtSuspendThread),
	HOOK(ntdll, RtlCreateUserThread),
	HOOK(kernel32, CreateRemoteThread),
	HOOK(kernel32, CreateRemoteThreadEx),

	HOOK_SPECIAL(clrjit, compileMethod),
	HOOK_SPECIAL(ole32, CoCreateInstance),
	HOOK_SPECIAL(ole32, CoCreateInstanceEx),
	HOOK_SPECIAL(ole32, CoGetClassObject),
	HOOK_SPECIAL(ole32, CoGetObject),
	HOOK_SPECIAL(combase, CoCreateInstance),
	HOOK_SPECIAL(combase, CoCreateInstanceEx),
	HOOK_SPECIAL(combase, CoGetClassObject),
	HOOK_SPECIAL(combase, CoGetObject),

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

	HOOK(ntdll, NtResumeThread),
	HOOK(ntdll, NtResumeProcess),
	HOOK(ntdll, NtTerminateProcess),
	HOOK(ntdll, RtlReportSilentProcessExit),

	HOOK(ntdll, NtDuplicateObject),

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
	HOOK(ncrypt, SslExpandTrafficKeys),
	HOOK(ncrypt, SslExpandExporterMasterKey),
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
	HOOK(kernel32, SetFileInformationByHandle),
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
	HOOK(user32, PostThreadMessageA),
	HOOK(user32, PostThreadMessageW),
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
	HOOK(kernel32, CreateProcessA),
	HOOK(kernel32, CreateProcessW),
	HOOK(kernel32, WinExec),
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
	HOOK(kernel32, CreateRemoteThreadEx),
	HOOK(kernel32, SwitchToThread),

	// Misc Hooks
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
	HOOK(kernel32, GetComputerNameExW),
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
	HOOK(ntdll, NtQueryInformationProcess),
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
	HOOK(ole32, CLSIDFromProgIDEx),
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
	HOOK(imagehlp, MapFileAndCheckSumA),
#ifndef _WIN64
	HOOK(ntdll, RtlDosPathNameToNtPathName_U),
	HOOK(ntdll, NtQueryLicenseValue),
	HOOK(vbe7, rtcEnvironBstr),
	HOOK(shlwapi, StrCmpNICW),
	HOOK(shlwapi, UrlCanonicalizeW),
	HOOK_NOTAIL(vbe7, rtcCreateObject2, 3),
#endif
	HOOK(User32, GetClipboardData),
	HOOK(User32, OpenClipboard),
	HOOK(User32, SetClipboardData),

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
	HOOK(ws2_32, GetAddrInfoExW),
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

hook_t exe_hooks[] = {
	HOOK_EXE(FindFixAndRun),
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
				DebugOutput("set_hooks_dll: Unable to hook %s", (hooks+i)->funcname);
			else if (g_config.hook_range)
				DebugOutput("set_hooks_dll: Hooked %s", (hooks+i)->funcname);
		}
	}
	return ret;
}

void set_hooks_exe(void)
{
    LDR_MODULE* mod;
    PEB* peb = (PEB*)get_peb();
    mod = (LDR_MODULE*)peb->LoaderData->InLoadOrderModuleList.Flink;
    HMODULE ullExeBase = (HMODULE)(mod->BaseAddress);

    int hook_count = sizeof(exe_hooks) / sizeof(exe_hooks[0]);
    char* func_names[sizeof(exe_hooks) / sizeof(exe_hooks[0])];

    for (int i = 0; i < hook_count; i++)
        func_names[i] = (char*)exe_hooks[i].funcname;

    SIZE_T found_count = 0;
    NameByAddress* results = GetAddressesByYara(ullExeBase, func_names, hook_count, &found_count);

    if (!results || found_count == 0) {
        if (results) free(results);
        return;
    }

    for (int i = 0; i < hook_count; i++) {
		if (exe_hooks[i].timestamp && exe_hooks[i].rva) {
			hook_t* hook = &exe_hooks[i];
			if (hook_api(hook, g_config.hook_type) < 0)
				DebugOutput("set_hooks_exe: Failed to hook %s at RVA 0x%x", hook->funcname, hook->rva);
			else
				DebugOutput("set_hooks_exe: Hooked %s at RVA 0x%x", hook->funcname, hook->rva);
		}
        else for (SIZE_T j = 0; j < found_count; j++) {
            if (results[j].FunctionName && results[j].Address && !strcmp(results[j].FunctionName, exe_hooks[i].funcname)) {
                hook_t* hook = &exe_hooks[i];
                hook->addr = results[j].Address;

                if (hook_api(hook, g_config.hook_type) < 0)
                    DebugOutput("set_hooks_exe: Failed to hook %s at 0x%p", hook->funcname, hook->addr);
                else
                    DebugOutput("set_hooks_exe: Hooked %s at 0x%p", hook->funcname, hook->addr);
            }
        }
    }

    free(results);

}

BOOL dll_is_hooked(const wchar_t *library)
{
	if (!library)
		return FALSE;
	BOOL ret = FALSE;
	for (unsigned int i = 0; i < hooks_arraysize; i++) {
		if (!wcsicmp((hooks+i)->library, library))
			ret = TRUE;
	}
	return ret;
}

void set_hooks_by_export_directory(const wchar_t *exportdirectory, const wchar_t *library)
{
	unsigned int Hooked = 0;
	for (unsigned int i = 0; i < hooks_arraysize; i++) {
		if (!wcsicmp((hooks+i)->library, exportdirectory)) {
			hook_t *hook = hooks+i;
			hook->library = library;
			hook->exportdirectory = exportdirectory;
			hook->addr = NULL;
			hook->is_hooked = 0;

			if (g_config.hook_range && i > g_config.hook_range)
				break;

			if (!stricmp((hooks+i)->funcname, "LdrGetDllHandle"))
				continue;

			if (hook_api(hooks+i, g_config.hook_type) < 0)
				DebugOutput("set_hooks_by_export_directory: Unable to hook %s", (hooks+i)->funcname);
			else {
				Hooked++;
				//DebugOutput("set_hooks_by_export_directory: Hooked %s", (hooks+i)->funcname);
			}
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

static com_hook_t* com_hooks = NULL;
static int num_com_hooks = 0;
static int num_com_hooks_installed = 0;
static int* com_hook_state = NULL;
int com_hooks_initialized = 0;

void init_com_hooks(void) {
	com_hooks = g_com_hooks;
	num_com_hooks = ARRAYSIZE(g_com_hooks);
	com_hook_state = calloc(sizeof(*com_hook_state), num_com_hooks);
}

int set_WbemLocator_hooks(PVOID pComObject, hook_t* hook) {
	IWbemLocator* pIWebmLocator = (IWbemLocator*)pComObject;
	DWORD old_protect;
	VirtualProtect(hook, sizeof(*hook), PAGE_EXECUTE_READWRITE, &old_protect);
	if (!strncmp(hook->funcname, "WbemLocator_ConnectServer", 25))
		hook->addr = pIWebmLocator->lpVtbl->ConnectServer;
	if (hook->addr) {
		return hook_api(hook, g_config.hook_type);
	}

	return -1;
}

int set_IWbemServices_hooks(PVOID pComObject, hook_t* hook) {
	IWbemServices* pIWbemServices = (IWbemServices*)pComObject;
	DWORD old_protect;
	VirtualProtect(hook, sizeof(*hook), PAGE_EXECUTE_READWRITE, &old_protect);
	if (!strcmp(hook->funcname, "IWbemServices_ExecQuery")) {
		hook->addr = pIWbemServices->lpVtbl->ExecQuery;
	}
	else if (!strncmp(hook->funcname, "IWbemServices_ExecQueryAsync", 28)) {
		hook->addr = pIWbemServices->lpVtbl->ExecQueryAsync;
	}
	else if (!strncmp(hook->funcname, "IWbemServices_GetObjectW", 24)) {
		hook->addr = pIWbemServices->lpVtbl->GetObject;
	}
	else if (!strncmp(hook->funcname, "IWbemServices_GetObjectAsync", 28)) {
		hook->addr = pIWbemServices->lpVtbl->GetObjectAsync;
	}
	else if (!strcmp(hook->funcname, "IWbemServices_ExecMethod")) {
		hook->addr = pIWbemServices->lpVtbl->ExecMethod;
	}
	else if (!strncmp(hook->funcname, "IWbemServices_ExecMethodAsync", 29)) {
		hook->addr = pIWbemServices->lpVtbl->ExecMethodAsync;
	}
	else if (!strcmp(hook->funcname, "IWbemServices_CreateInstanceEnum")) {
		hook->addr = pIWbemServices->lpVtbl->CreateInstanceEnum;
	}
	else if (!strncmp(hook->funcname, "IWbemServices_CreateInstanceEnumAsync", 37)) {
		hook->addr = pIWbemServices->lpVtbl->CreateInstanceEnumAsync;
	}
	if (hook->addr) {
		return hook_api(hook, g_config.hook_type);
	}
	return -1;
}

extern __declspec(thread) BOOL bHookViaWbemLocator;
void set_com_hooks(REFCLSID	rclsid, REFIID riid, PVOID pComObject) {
	if (!com_hooks_initialized) {
		init_com_hooks();
		com_hooks_initialized = 1;
	}
	if (num_com_hooks_installed < num_com_hooks) {
		lasterror_t lasterrors;
		get_lasterrors(&lasterrors);
		__try {
			for (int hook_idx = 0; hook_idx < num_com_hooks; hook_idx++) {
				if (!com_hook_state[hook_idx]) {
					int ret = 1;
					com_hook_t* com_hook = &com_hooks[hook_idx];
					hook_t* hook = &(com_hook->hook);
					if (
						(rclsid && com_hook->rclsid && IsEqualCLSID(rclsid, com_hook->rclsid)) || // Matches a CLSID we want to hook
						(com_hook->riid && riid && IsEqualIID(riid, com_hook->riid)) || // Matches an IID we want to hook
						(!rclsid && !riid) // Hook COM objects identified by funcname
					) {
						if (rclsid && riid) {
							if (IsEqualCLSID(rclsid, &CLSID_WbemLocator) && IsEqualIID(riid, &IID_IWbemLocator)) {
								ret = set_WbemLocator_hooks(pComObject, hook);
							}
						}
						else if (!rclsid && !riid && !com_hook->rclsid && !com_hook->riid) {
							if (bHookViaWbemLocator && !strncmp(hook->funcname, "IWbemServices_", 14)) {
								ret = set_IWbemServices_hooks(pComObject, hook);
							}
						}
					}
					if (ret == 0) {
						DebugOutput("Successfully installed hook on COM Object function %s", hook->funcname);
						num_com_hooks_installed++;
						com_hook_state[hook_idx] = 1;
					}
					else if (ret < 0) {
						DebugOutput("WARNING: Unable to hook COM Object function %s", hook->funcname);
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
		set_lasterrors(&lasterrors);
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
	unsigned int Hooked = 0;

	BOOL TestHooks = FALSE;

	OSVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

	if (!GetVersionEx(&OSVersion))
		ErrorOutput("set_hooks: Failed to get OS version");

	IsWow64Process(GetCurrentProcess(), &Wow64Process);

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
	else if (g_config.native) {
		hooks = native_hooks;
		hooks_size = sizeof(native_hooks);
		hooks_arraysize = ARRAYSIZE(native_hooks);
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
		if (g_config.hook_range && i >= g_config.hook_range)
			break;

		if (g_config.hook_range)
			DebugOutput("set_hooks: Hooking %ws::%s", (hooks+i)->library, (hooks+i)->funcname);
		if (hook_api(hooks+i, g_config.hook_type) < 0)
			DebugOutput("set_hooks: Unable to hook %ws::%s", (hooks+i)->library, (hooks+i)->funcname);
		else
			Hooked++;
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

	DebugOutput("Hooked %d out of %d functions\n", Hooked, hooks_arraysize);

	set_hooks_exe();

	hook_enable();
}
