/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2014 Cuckoo Sandbox Developers

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

#include <windns.h>
#include <wininet.h>
#include <mswsock.h>
#include "ntapi.h"
#include <tlhelp32.h>

//
// File Hooks
//

extern HOOKDEF(NTSTATUS, WINAPI, NtQueryAttributesFile,
	__in   POBJECT_ATTRIBUTES ObjectAttributes,
	__out  PFILE_BASIC_INFORMATION FileInformation
);

extern HOOKDEF(NTSTATUS, WINAPI, NtQueryFullAttributesFile,
	__in   POBJECT_ATTRIBUTES ObjectAttributes,
	__out  PFILE_NETWORK_OPEN_INFORMATION FileInformation
);

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateFile,
    __out     PHANDLE FileHandle,
    __in      ACCESS_MASK DesiredAccess,
    __in      POBJECT_ATTRIBUTES ObjectAttributes,
    __out     PIO_STATUS_BLOCK IoStatusBlock,
    __in_opt  PLARGE_INTEGER AllocationSize,
    __in      ULONG FileAttributes,
    __in      ULONG ShareAccess,
    __in      ULONG CreateDisposition,
    __in      ULONG CreateOptions,
    __in      PVOID EaBuffer,
    __in      ULONG EaLength
);

extern HOOKDEF(NTSTATUS, WINAPI, NtOpenFile,
    __out  PHANDLE FileHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes,
    __out  PIO_STATUS_BLOCK IoStatusBlock,
    __in   ULONG ShareAccess,
    __in   ULONG OpenOptions
);

extern HOOKDEF(NTSTATUS, WINAPI, NtReadFile,
    __in      HANDLE FileHandle,
    __in_opt  HANDLE Event,
    __in_opt  PIO_APC_ROUTINE ApcRoutine,
    __in_opt  PVOID ApcContext,
    __out     PIO_STATUS_BLOCK IoStatusBlock,
    __out     PVOID Buffer,
    __in      ULONG Length,
    __in_opt  PLARGE_INTEGER ByteOffset,
    __in_opt  PULONG Key
);

extern HOOKDEF(NTSTATUS, WINAPI, NtWriteFile,
    __in      HANDLE FileHandle,
    __in_opt  HANDLE Event,
    __in_opt  PIO_APC_ROUTINE ApcRoutine,
    __in_opt  PVOID ApcContext,
    __out     PIO_STATUS_BLOCK IoStatusBlock,
    __in      PVOID Buffer,
    __in      ULONG Length,
    __in_opt  PLARGE_INTEGER ByteOffset,
    __in_opt  PULONG Key
);

extern HOOKDEF(NTSTATUS, WINAPI, NtDeleteFile,
    __in  POBJECT_ATTRIBUTES ObjectAttributes
);

extern HOOKDEF(NTSTATUS, WINAPI, NtDeviceIoControlFile,
    __in   HANDLE FileHandle,
    __in   HANDLE Event,
    __in   PIO_APC_ROUTINE ApcRoutine,
    __in   PVOID ApcContext,
    __out  PIO_STATUS_BLOCK IoStatusBlock,
    __in   ULONG IoControlCode,
    __in   PVOID InputBuffer,
    __in   ULONG InputBufferLength,
    __out  PVOID OutputBuffer,
    __in   ULONG OutputBufferLength
);

extern HOOKDEF(NTSTATUS, WINAPI, NtQueryDirectoryFile,
    __in      HANDLE FileHandle,
    __in_opt  HANDLE Event,
    __in_opt  PIO_APC_ROUTINE ApcRoutine,
    __in_opt  PVOID ApcContext,
    __out     PIO_STATUS_BLOCK IoStatusBlock,
    __out     PVOID FileInformation,
    __in      ULONG Length,
    __in      FILE_INFORMATION_CLASS FileInformationClass,
    __in      BOOLEAN ReturnSingleEntry,
    __in_opt  PUNICODE_STRING FileName,
    __in      BOOLEAN RestartScan
);

extern HOOKDEF(NTSTATUS, WINAPI, NtQueryVolumeInformationFile,
    __in   HANDLE FileHandle,
    __out  PIO_STATUS_BLOCK IoStatusBlock,
    __out  PVOID FsInformation,
    __in   ULONG Length,
    __in   FS_INFORMATION_CLASS FsInformationClass
);

extern HOOKDEF(NTSTATUS, WINAPI, NtQueryInformationFile,
    __in   HANDLE FileHandle,
    __out  PIO_STATUS_BLOCK IoStatusBlock,
    __out  PVOID FileInformation,
    __in   ULONG Length,
    __in   FILE_INFORMATION_CLASS FileInformationClass
);

extern HOOKDEF(NTSTATUS, WINAPI, NtSetInformationFile,
    __in   HANDLE FileHandle,
    __out  PIO_STATUS_BLOCK IoStatusBlock,
    __in   PVOID FileInformation,
    __in   ULONG Length,
    __in   FILE_INFORMATION_CLASS FileInformationClass
);

extern HOOKDEF(NTSTATUS, WINAPI, NtOpenDirectoryObject,
    __out  PHANDLE DirectoryHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes
);

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateDirectoryObject,
    __out  PHANDLE DirectoryHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes
);

extern HOOKDEF(NTSTATUS, WINAPI, NtQueryDirectoryObject,
  __in       HANDLE DirectoryHandle,
  __out_opt  PVOID Buffer,
  __in       ULONG Length,
  __in       BOOLEAN ReturnSingleEntry,
  __in       BOOLEAN RestartScan,
  __inout    PULONG Context,
  __out_opt  PULONG ReturnLength
);

extern HOOKDEF_NOTAIL(WINAPI, MoveFileWithProgressW,
    __in      LPWSTR lpExistingFileName,
    __in_opt  LPWSTR lpNewFileName,
    __in_opt  LPPROGRESS_ROUTINE lpProgressRoutine,
    __in_opt  LPVOID lpData,
    __in      DWORD dwFlags
);

extern HOOKDEF_ALT(BOOL, WINAPI, MoveFileWithProgressW,
	__in      LPWSTR lpExistingFileName,
	__in_opt  LPWSTR lpNewFileName,
	__in_opt  LPPROGRESS_ROUTINE lpProgressRoutine,
	__in_opt  LPVOID lpData,
	__in      DWORD dwFlags
);

extern HOOKDEF_NOTAIL(WINAPI, MoveFileWithProgressTransactedW,
	__in      LPWSTR lpExistingFileName,
	__in_opt  LPWSTR lpNewFileName,
	__in_opt  LPPROGRESS_ROUTINE lpProgressRoutine,
	__in_opt  LPVOID lpData,
	__in      DWORD dwFlags,
	__in	  HANDLE hTransaction
);

extern HOOKDEF_ALT(BOOL, WINAPI, MoveFileWithProgressTransactedW,
	__in      LPWSTR lpExistingFileName,
	__in_opt  LPWSTR lpNewFileName,
	__in_opt  LPPROGRESS_ROUTINE lpProgressRoutine,
	__in_opt  LPVOID lpData,
	__in      DWORD dwFlags,
	__in	  HANDLE hTransaction
);

extern HOOKDEF(BOOL, WINAPI, CreateDirectoryW,
    __in      LPCTSTR lpPathName,
    __in_opt  LPSECURITY_ATTRIBUTES lpSecurityAttributes
);

extern HOOKDEF(BOOL, WINAPI, CreateDirectoryExW,
    __in      LPWSTR lpTemplateDirectory,
    __in      LPWSTR lpNewDirectory,
    __in_opt  LPSECURITY_ATTRIBUTES lpSecurityAttributes
);

extern HOOKDEF(BOOL, WINAPI, RemoveDirectoryA,
    __in  LPCTSTR  lpPathName
);

extern HOOKDEF(BOOL, WINAPI, RemoveDirectoryW,
    __in  LPWSTR lpPathName
);

extern HOOKDEF(HANDLE, WINAPI, CreateFileTransactedA,
  __in       LPCSTR                lpFileName,
  __in       DWORD                 dwDesiredAccess,
  __in       DWORD                 dwShareMode,
  __in_opt   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  __in       DWORD                 dwCreationDisposition,
  __in       DWORD                 dwFlagsAndAttributes,
  __in_opt   HANDLE                hTemplateFile,
  __in       HANDLE                hTransaction,
  __in_opt   PUSHORT               pusMiniVersion,
  __reserved PVOID                 pExtendedParameter
);

extern HOOKDEF(HANDLE, WINAPI, CreateFileTransactedW,
  __in       LPCWSTR               lpFileName,
  __in       DWORD                 dwDesiredAccess,
  __in       DWORD                 dwShareMode,
  __in_opt   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  __in       DWORD                 dwCreationDisposition,
  __in       DWORD                 dwFlagsAndAttributes,
  __in_opt   HANDLE                hTemplateFile,
  __in       HANDLE                hTransaction,
  __in_opt   PUSHORT               pusMiniVersion,
  __reserved PVOID                 pExtendedParameter
);

extern HOOKDEF(HANDLE, WINAPI, FindFirstFileExA,
    __in        LPCTSTR lpFileName,
    __in        FINDEX_INFO_LEVELS fInfoLevelId,
    __out       LPVOID lpFindFileData,
    __in        FINDEX_SEARCH_OPS fSearchOp,
    __reserved  LPVOID lpSearchFilter,
    __in        DWORD dwAdditionalFlags
);

extern HOOKDEF(HANDLE, WINAPI, FindFirstFileExW,
    __in        LPWSTR lpFileName,
    __in        FINDEX_INFO_LEVELS fInfoLevelId,
    __out       LPVOID lpFindFileData,
    __in        FINDEX_SEARCH_OPS fSearchOp,
    __reserved  LPVOID lpSearchFilter,
    __in        DWORD dwAdditionalFlags
);

extern HOOKDEF(BOOL, WINAPI, FindNextFileW,
	__in HANDLE hFindFile,
	__out LPWIN32_FIND_DATAW lpFindFileData
);

extern HOOKDEF(BOOL, WINAPI, CopyFileA,
    __in  LPCTSTR lpExistingFileName,
    __in  LPCTSTR lpNewFileName,
    __in  BOOL bFailIfExists
);

extern HOOKDEF(BOOL, WINAPI, CopyFileW,
    __in  LPWSTR lpExistingFileName,
    __in  LPWSTR lpNewFileName,
    __in  BOOL bFailIfExists
);

extern HOOKDEF_NOTAIL(WINAPI, CopyFileExW,
    _In_      LPWSTR lpExistingFileName,
    _In_      LPWSTR lpNewFileName,
    _In_opt_  LPPROGRESS_ROUTINE lpProgressRoutine,
    _In_opt_  LPVOID lpData,
    _In_opt_  LPBOOL pbCancel,
    _In_      DWORD dwCopyFlags
);

extern HOOKDEF_ALT(BOOL, WINAPI, CopyFileExW,
	_In_      LPWSTR lpExistingFileName,
	_In_      LPWSTR lpNewFileName,
	_In_opt_  LPPROGRESS_ROUTINE lpProgressRoutine,
	_In_opt_  LPVOID lpData,
	_In_opt_  LPBOOL pbCancel,
	_In_      DWORD dwCopyFlags
);

extern HOOKDEF(BOOL, WINAPI, DeleteFileA,
    __in  LPCSTR lpFileName
);

extern HOOKDEF(BOOL, WINAPI, DeleteFileW,
    __in  LPWSTR lpFileName
);

extern HOOKDEF(BOOL, WINAPI, GetDiskFreeSpaceExA,
    _In_opt_   PCTSTR lpDirectoryName,
    _Out_opt_  PULARGE_INTEGER lpFreeBytesAvailable,
    _Out_opt_  PULARGE_INTEGER lpTotalNumberOfBytes,
    _Out_opt_  PULARGE_INTEGER lpTotalNumberOfFreeBytes
);

extern HOOKDEF(BOOL, WINAPI, GetDiskFreeSpaceExW,
    _In_opt_   PCWSTR lpDirectoryName,
    _Out_opt_  PULARGE_INTEGER lpFreeBytesAvailable,
    _Out_opt_  PULARGE_INTEGER lpTotalNumberOfBytes,
    _Out_opt_  PULARGE_INTEGER lpTotalNumberOfFreeBytes
);

extern HOOKDEF(BOOL, WINAPI, GetDiskFreeSpaceA,
    _In_   PCTSTR lpRootPathName,
    _Out_  LPDWORD lpSectorsPerCluster,
    _Out_  LPDWORD lpBytesPerSector,
    _Out_  LPDWORD lpNumberOfFreeClusters,
    _Out_  LPDWORD lpTotalNumberOfClusters
);

extern HOOKDEF(BOOL, WINAPI, GetDiskFreeSpaceW,
    _In_   PCWSTR lpRootPathName,
    _Out_  LPDWORD lpSectorsPerCluster,
    _Out_  LPDWORD lpBytesPerSector,
    _Out_  LPDWORD lpNumberOfFreeClusters,
    _Out_  LPDWORD lpTotalNumberOfClusters
);

extern HOOKDEF(BOOL, WINAPI, GetVolumeInformationA,
	_In_opt_   LPCSTR lpRootPathName,
	_Out_opt_  LPSTR lpVolumeNameBuffer,
	_In_       DWORD nVolumeNameSize,
	_Out_opt_  LPDWORD lpVolumeSerialNumber,
	_Out_opt_  LPDWORD lpMaximumComponentLength,
	_Out_opt_  LPDWORD lpFileSystemFlags,
	_Out_opt_  LPSTR lpFileSystemNameBuffer,
	_In_       DWORD nFileSystemNameSize
);

extern HOOKDEF(BOOL, WINAPI, GetVolumeInformationW,
	_In_opt_   LPCWSTR lpRootPathName,
	_Out_opt_  LPWSTR lpVolumeNameBuffer,
	_In_       DWORD nVolumeNameSize,
	_Out_opt_  LPDWORD lpVolumeSerialNumber,
	_Out_opt_  LPDWORD lpMaximumComponentLength,
	_Out_opt_  LPDWORD lpFileSystemFlags,
	_Out_opt_  LPWSTR lpFileSystemNameBuffer,
	_In_       DWORD nFileSystemNameSize
);

extern HOOKDEF(BOOL, WINAPI, GetVolumeNameForVolumeMountPointW,
	_In_ LPCWSTR lpszVolumeMountPoint,
	_Out_ LPWSTR lpszVolumeName,
	_In_ DWORD cchBufferLength
);

extern HOOKDEF(HRESULT, WINAPI, SHGetFolderPathW,
	_In_ HWND hwndOwner,
	_In_ int nFolder,
	_In_ HANDLE hToken,
	_In_ DWORD dwFlags,
	_Out_ LPWSTR pszPath
);

extern HOOKDEF(HRESULT, WINAPI, SHGetKnownFolderPath,
	_In_     GUID			  *rfid,
	_In_     DWORD            dwFlags,
	_In_opt_ HANDLE           hToken,
	_Out_    PWSTR            *ppszPath
);

extern HOOKDEF(DWORD_PTR, WINAPI, SHGetFileInfoW,
	_In_    LPCWSTR    pszPath,
	DWORD      dwFileAttributes,
	_Inout_ SHFILEINFOW *psfi,
	UINT       cbFileInfo,
	UINT       uFlags
);

extern HOOKDEF(BOOL, WINAPI, GetFileVersionInfoW,
	_In_        LPCWSTR lptstrFilename,
	_Reserved_  DWORD dwHandle,
	_In_        DWORD dwLen,
	_Out_       LPVOID lpData
);

extern HOOKDEF(DWORD, WINAPI, GetFileVersionInfoSizeW,
	_In_       LPCWSTR lptstrFilename,
	_Out_opt_  LPDWORD lpdwHandle
);

extern HOOKDEF(HANDLE, WINAPI, FindFirstChangeNotificationW,
	_In_	LPCWSTR lpPathName,
	_In_	BOOL bWatchSubtree,
	_In_	DWORD dwNotifyFilter
);

extern HOOKDEF(BOOL, WINAPI, GetVolumeInformationByHandleW,
	_In_      HANDLE  hFile,
	_Out_opt_ LPWSTR  lpVolumeNameBuffer,
	_In_      DWORD   nVolumeNameSize,
	_Out_opt_ LPDWORD lpVolumeSerialNumber,
	_Out_opt_ LPDWORD
	lpMaximumComponentLength,
	_Out_opt_ LPDWORD lpFileSystemFlags,
	_Out_opt_ LPWSTR  lpFileSystemNameBuffer,
	_In_      DWORD   nFileSystemNameSize
);

//
// Registry Hooks
//

extern HOOKDEF(LONG, WINAPI, RegOpenKeyExA,
    __in        HKEY hKey,
    __in_opt    LPCTSTR lpSubKey,
    __reserved  DWORD ulOptions,
    __in        REGSAM samDesired,
    __out       PHKEY phkResult
);

extern HOOKDEF(LONG, WINAPI, RegOpenKeyExW,
    __in        HKEY hKey,
    __in_opt    LPWSTR lpSubKey,
    __reserved  DWORD ulOptions,
    __in        REGSAM samDesired,
    __out       PHKEY phkResult
);

extern HOOKDEF(LONG, WINAPI, RegCreateKeyExA,
    __in        HKEY hKey,
    __in        LPCTSTR lpSubKey,
    __reserved  DWORD Reserved,
    __in_opt    LPTSTR lpClass,
    __in        DWORD dwOptions,
    __in        REGSAM samDesired,
    __in_opt    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    __out       PHKEY phkResult,
    __out_opt   LPDWORD lpdwDisposition
);

extern HOOKDEF(LONG, WINAPI, RegCreateKeyExW,
    __in        HKEY hKey,
    __in        LPWSTR lpSubKey,
    __reserved  DWORD Reserved,
    __in_opt    LPWSTR lpClass,
    __in        DWORD dwOptions,
    __in        REGSAM samDesired,
    __in_opt    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    __out       PHKEY phkResult,
    __out_opt   LPDWORD lpdwDisposition
);

extern HOOKDEF(LONG, WINAPI, RegDeleteKeyA,
    __in  HKEY hKey,
    __in  LPCTSTR lpSubKey
);

extern HOOKDEF(LONG, WINAPI, RegDeleteKeyW,
    __in  HKEY hKey,
    __in  LPWSTR lpSubKey
);

extern HOOKDEF(LONG, WINAPI, RegEnumKeyW,
    __in   HKEY hKey,
    __in   DWORD dwIndex,
    __out  LPWSTR lpName,
    __in   DWORD cchName
);

extern HOOKDEF(LONG, WINAPI, RegEnumKeyExA,
    __in         HKEY hKey,
    __in         DWORD dwIndex,
    __out        LPTSTR lpName,
    __inout      LPDWORD lpcName,
    __reserved   LPDWORD lpReserved,
    __inout      LPTSTR lpClass,
    __inout_opt  LPDWORD lpcClass,
    __out_opt    PFILETIME lpftLastWriteTime
);

extern HOOKDEF(LONG, WINAPI, RegEnumKeyExW,
    __in         HKEY hKey,
    __in         DWORD dwIndex,
    __out        LPWSTR lpName,
    __inout      LPDWORD lpcName,
    __reserved   LPDWORD lpReserved,
    __inout      LPWSTR lpClass,
    __inout_opt  LPDWORD lpcClass,
    __out_opt    PFILETIME lpftLastWriteTime
);

extern HOOKDEF(LONG, WINAPI, RegEnumValueA,
    __in         HKEY hKey,
    __in         DWORD dwIndex,
    __out        LPTSTR lpValueName,
    __inout      LPDWORD lpcchValueName,
    __reserved   LPDWORD lpReserved,
    __out_opt    LPDWORD lpType,
    __out_opt    LPBYTE lpData,
    __inout_opt  LPDWORD lpcbData
);

extern HOOKDEF(LONG, WINAPI, RegEnumValueW,
    __in         HKEY hKey,
    __in         DWORD dwIndex,
    __out        LPWSTR lpValueName,
    __inout      LPDWORD lpcchValueName,
    __reserved   LPDWORD lpReserved,
    __out_opt    LPDWORD lpType,
    __out_opt    LPBYTE lpData,
    __inout_opt  LPDWORD lpcbData
);

extern HOOKDEF(LONG, WINAPI, RegSetValueExA,
    __in        HKEY hKey,
    __in_opt    LPCTSTR lpValueName,
    __reserved  DWORD Reserved,
    __in        DWORD dwType,
    __in        const BYTE *lpData,
    __in        DWORD cbData
);

extern HOOKDEF(LONG, WINAPI, RegSetValueExW,
    __in        HKEY hKey,
    __in_opt    LPWSTR lpValueName,
    __reserved  DWORD Reserved,
    __in        DWORD dwType,
    __in        const BYTE *lpData,
    __in        DWORD cbData
);

extern HOOKDEF(LONG, WINAPI, RegQueryValueExA,
    __in         HKEY hKey,
    __in_opt     LPCTSTR lpValueName,
    __reserved   LPDWORD lpReserved,
    __out_opt    LPDWORD lpType,
    __out_opt    LPBYTE lpData,
    __inout_opt  LPDWORD lpcbData
);

extern HOOKDEF(LONG, WINAPI, RegQueryValueExW,
    __in         HKEY hKey,
    __in_opt     LPWSTR lpValueName,
    __reserved   LPDWORD lpReserved,
    __out_opt    LPDWORD lpType,
    __out_opt    LPBYTE lpData,
    __inout_opt  LPDWORD lpcbData
);

extern HOOKDEF(LONG, WINAPI, RegDeleteValueA,
    __in      HKEY hKey,
    __in_opt  LPCTSTR lpValueName
);

extern HOOKDEF(LONG, WINAPI, RegDeleteValueW,
    __in      HKEY hKey,
    __in_opt  LPWSTR lpValueName
);

extern HOOKDEF(LONG, WINAPI, RegQueryInfoKeyA,
    _In_         HKEY hKey,
    _Out_opt_    LPTSTR lpClass,
    _Inout_opt_  LPDWORD lpcClass,
    _Reserved_   LPDWORD lpReserved,
    _Out_opt_    LPDWORD lpcSubKeys,
    _Out_opt_    LPDWORD lpcMaxSubKeyLen,
    _Out_opt_    LPDWORD lpcMaxClassLen,
    _Out_opt_    LPDWORD lpcValues,
    _Out_opt_    LPDWORD lpcMaxValueNameLen,
    _Out_opt_    LPDWORD lpcMaxValueLen,
    _Out_opt_    LPDWORD lpcbSecurityDescriptor,
    _Out_opt_    PFILETIME lpftLastWriteTime
);

extern HOOKDEF(LONG, WINAPI, RegQueryInfoKeyW,
    _In_         HKEY hKey,
    _Out_opt_    LPWSTR lpClass,
    _Inout_opt_  LPDWORD lpcClass,
    _Reserved_   LPDWORD lpReserved,
    _Out_opt_    LPDWORD lpcSubKeys,
    _Out_opt_    LPDWORD lpcMaxSubKeyLen,
    _Out_opt_    LPDWORD lpcMaxClassLen,
    _Out_opt_    LPDWORD lpcValues,
    _Out_opt_    LPDWORD lpcMaxValueNameLen,
    _Out_opt_    LPDWORD lpcMaxValueLen,
    _Out_opt_    LPDWORD lpcbSecurityDescriptor,
    _Out_opt_    PFILETIME lpftLastWriteTime
);

extern HOOKDEF(LONG, WINAPI, RegCloseKey,
    __in    HKEY hKey
);

extern HOOKDEF(LONG, WINAPI, RegNotifyChangeKeyValue,
	_In_     HKEY   hKey,
	_In_     BOOL   bWatchSubtree,
	_In_     DWORD  dwNotifyFilter,
	_In_opt_ HANDLE hEvent,
	_In_     BOOL   fAsynchronous
);

//
// Native Registry Hooks
//

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateKey,
    __out       PHANDLE KeyHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in        POBJECT_ATTRIBUTES ObjectAttributes,
    __reserved  ULONG TitleIndex,
    __in_opt    PUNICODE_STRING Class,
    __in        ULONG CreateOptions,
    __out_opt   PULONG Disposition
);

extern HOOKDEF(NTSTATUS, WINAPI, NtOpenKey,
    __out  PHANDLE KeyHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes
);

extern HOOKDEF(NTSTATUS, WINAPI, NtOpenKeyEx,
    __out  PHANDLE KeyHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes,
    __in   ULONG OpenOptions
);

extern HOOKDEF(NTSTATUS, WINAPI, NtRenameKey,
    __in  HANDLE KeyHandle,
    __in  PUNICODE_STRING NewName
);

extern HOOKDEF(NTSTATUS, WINAPI, NtReplaceKey,
    __in  POBJECT_ATTRIBUTES NewHiveFileName,
    __in  HANDLE KeyHandle,
    __in  POBJECT_ATTRIBUTES BackupHiveFileName
);

extern HOOKDEF(NTSTATUS, WINAPI, NtEnumerateKey,
    __in       HANDLE KeyHandle,
    __in       ULONG Index,
    __in       KEY_INFORMATION_CLASS KeyInformationClass,
    __out_opt  PVOID KeyInformation,
    __in       ULONG Length,
    __out      PULONG ResultLength
);

extern HOOKDEF(NTSTATUS, WINAPI, NtEnumerateValueKey,
    __in       HANDLE KeyHandle,
    __in       ULONG Index,
    __in       KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    __out_opt  PVOID KeyValueInformation,
    __in       ULONG Length,
    __out      PULONG ResultLength
);

extern HOOKDEF(NTSTATUS, WINAPI, NtSetValueKey,
    __in      HANDLE KeyHandle,
    __in      PUNICODE_STRING ValueName,
    __in_opt  ULONG TitleIndex,
    __in      ULONG Type,
    __in_opt  PVOID Data,
    __in      ULONG DataSize
);

extern HOOKDEF(NTSTATUS, WINAPI, NtQueryValueKey,
    __in       HANDLE KeyHandle,
    __in       PUNICODE_STRING ValueName,
    __in       KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    __out_opt  PVOID KeyValueInformation,
    __in       ULONG Length,
    __out      PULONG ResultLength
);

extern HOOKDEF(NTSTATUS, WINAPI, NtQueryMultipleValueKey,
    __in       HANDLE KeyHandle,
    __inout    PKEY_VALUE_ENTRY ValueEntries,
    __in       ULONG EntryCount,
    __out      PVOID ValueBuffer,
    __inout    PULONG BufferLength,
    __out_opt  PULONG RequiredBufferLength
);

extern HOOKDEF(NTSTATUS, WINAPI, NtDeleteKey,
    __in  HANDLE KeyHandle
);

extern HOOKDEF(NTSTATUS, WINAPI, NtDeleteValueKey,
    __in  HANDLE KeyHandle,
    __in  PUNICODE_STRING ValueName
);

extern HOOKDEF(NTSTATUS, WINAPI, NtLoadKey,
    __in  POBJECT_ATTRIBUTES TargetKey,
    __in  POBJECT_ATTRIBUTES SourceFile
);

extern HOOKDEF(NTSTATUS, WINAPI, NtLoadKey2,
    __in  POBJECT_ATTRIBUTES TargetKey,
    __in  POBJECT_ATTRIBUTES SourceFile,
    __in  ULONG Flags
);

extern HOOKDEF(NTSTATUS, WINAPI, NtLoadKeyEx,
    __in      POBJECT_ATTRIBUTES TargetKey,
    __in      POBJECT_ATTRIBUTES SourceFile,
    __in      ULONG Flags,
    __in_opt  HANDLE TrustClassKey
);

extern HOOKDEF(NTSTATUS, WINAPI, NtQueryKey,
    __in       HANDLE KeyHandle,
    __in       KEY_INFORMATION_CLASS KeyInformationClass,
    __out_opt  PVOID KeyInformation,
    __in       ULONG Length,
    __out      PULONG ResultLength
);

extern HOOKDEF(NTSTATUS, WINAPI, NtSaveKey,
    __in  HANDLE KeyHandle,
    __in  HANDLE FileHandle
);

extern HOOKDEF(NTSTATUS, WINAPI, NtSaveKeyEx,
    __in  HANDLE KeyHandle,
    __in  HANDLE FileHandle,
    __in  ULONG Format
);

//
// Window Hooks
//

extern HOOKDEF_NOTAIL(WINAPI, CreateWindowExA,
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
);

extern HOOKDEF_NOTAIL(WINAPI, CreateWindowExW,
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
);

extern HOOKDEF(HWND, WINAPI, FindWindowA,
    __in_opt  LPCTSTR lpClassName,
    __in_opt  LPCTSTR lpWindowName
);

extern HOOKDEF(HWND, WINAPI, FindWindowW,
    __in_opt  LPWSTR lpClassName,
    __in_opt  LPWSTR lpWindowName
);

extern HOOKDEF(HWND, WINAPI, FindWindowExA,
    __in_opt  HWND hwndParent,
    __in_opt  HWND hwndChildAfter,
    __in_opt  LPCTSTR lpszClass,
    __in_opt  LPCTSTR lpszWindow
);

extern HOOKDEF(HWND, WINAPI, FindWindowExW,
    __in_opt  HWND hwndParent,
    __in_opt  HWND hwndChildAfter,
    __in_opt  LPWSTR lpszClass,
    __in_opt  LPWSTR lpszWindow
);

extern HOOKDEF(BOOL, WINAPI, EnumWindows,
    _In_  WNDENUMPROC lpEnumFunc,
    _In_  LPARAM lParam
);

extern HOOKDEF(BOOL, WINAPI, PostMessageA,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
);

extern HOOKDEF(BOOL, WINAPI, PostMessageW,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
);

extern HOOKDEF(BOOL, WINAPI, SendMessageA,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
);

extern HOOKDEF(BOOL, WINAPI, SendMessageW,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
);

extern HOOKDEF(BOOL, WINAPI, SendNotifyMessageA,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
);

extern HOOKDEF(BOOL, WINAPI, SendNotifyMessageW,
	_In_  HWND hWnd,
	_In_  UINT Msg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
);

extern HOOKDEF(LONG, WINAPI, SetWindowLongA,
	_In_ HWND hWnd,
	_In_ int nIndex,
	_In_ LONG dwNewLong
);

extern HOOKDEF(LONG_PTR, WINAPI, SetWindowLongPtrA,
	_In_ HWND hWnd,
	_In_ int nIndex,
	_In_ LONG_PTR dwNewLong
);

extern HOOKDEF(LONG, WINAPI, SetWindowLongW,
	_In_ HWND hWnd,
	_In_ int nIndex,
	_In_ LONG dwNewLong
);

extern HOOKDEF(LONG_PTR, WINAPI, SetWindowLongPtrW,
	_In_ HWND hWnd,
	_In_ int nIndex,
	_In_ LONG_PTR dwNewLong
);


//
// Sync Hooks
//

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateMutant,
    __out       PHANDLE MutantHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ObjectAttributes,
    __in        BOOLEAN InitialOwner
);

extern HOOKDEF(NTSTATUS, WINAPI, NtOpenMutant,
    __out       PHANDLE MutantHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in        POBJECT_ATTRIBUTES ObjectAttributes
);

extern HOOKDEF(NTSTATUS, WINAPI, NtReleaseMutant,
    __in        HANDLE MutantHandle,
    __out_opt   PLONG PreviousCount
);

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateEvent,
	__out		PHANDLE EventHandle,
	__in		ACCESS_MASK DesiredAccess,
	__in_opt	POBJECT_ATTRIBUTES ObjectAttributes,
	__in		DWORD EventType,
	__in		BOOLEAN InitialState
);

extern HOOKDEF(NTSTATUS, WINAPI, NtOpenEvent,
	__out		PHANDLE EventHandle,
	__in		ACCESS_MASK DesiredAccess,
	__in		POBJECT_ATTRIBUTES ObjectAttributes
);

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateNamedPipeFile,
    OUT         PHANDLE NamedPipeFileHandle,
    IN          ACCESS_MASK DesiredAccess,
    IN          POBJECT_ATTRIBUTES ObjectAttributes,
    OUT         PIO_STATUS_BLOCK IoStatusBlock,
    IN          ULONG ShareAccess,
    IN          ULONG CreateDisposition,
    IN          ULONG CreateOptions,
    IN          BOOLEAN WriteModeMessage,
    IN          BOOLEAN ReadModeMessage,
    IN          BOOLEAN NonBlocking,
    IN          ULONG MaxInstances,
    IN          ULONG InBufferSize,
    IN          ULONG OutBufferSize,
    IN          PLARGE_INTEGER DefaultTimeOut
);

extern HOOKDEF(NTSTATUS, WINAPI, NtAddAtom,
	IN	PWCHAR AtomName,
	IN	ULONG	AtomNameLength,
	OUT PRTL_ATOM Atom
);

extern HOOKDEF(NTSTATUS, WINAPI, NtDeleteAtom,
	IN RTL_ATOM Atom
);

extern HOOKDEF(NTSTATUS, WINAPI, NtFindAtom,
	IN	PWCHAR AtomName,
	IN	ULONG AtomNameLength,
	OUT PRTL_ATOM Atom OPTIONAL
);

extern HOOKDEF(NTSTATUS, WINAPI, NtAddAtomEx,
	IN	PWCHAR AtomName,
	IN	ULONG	AtomNameLength,
	OUT PRTL_ATOM Atom,
	IN	PVOID	Unknown
);

extern HOOKDEF(NTSTATUS, WINAPI, NtQueryInformationAtom,
	IN	RTL_ATOM Atom,
	IN	ATOM_INFORMATION_CLASS AtomInformationClass,
    OUT PVOID AtomInformation,
    IN  ULONG AtomInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

//
// Process Hooks
//

extern HOOKDEF(HANDLE, WINAPI, CreateToolhelp32Snapshot,
	__in DWORD dwFlags,
	__in DWORD th32ProcessID
);

extern HOOKDEF(BOOL, WINAPI, Process32FirstW,
	__in HANDLE hSnapshot,
	__out LPPROCESSENTRY32W lppe
);

extern HOOKDEF(BOOL, WINAPI, Process32NextW,
	__in HANDLE hSnapshot,
	__out LPPROCESSENTRY32W lppe
);

extern HOOKDEF(BOOL, WINAPI, Module32FirstW,
	__in HANDLE hSnapshot,
	__out LPMODULEENTRY32W lpme
);

extern HOOKDEF(BOOL, WINAPI, Module32NextW,
	__in HANDLE hSnapshot,
	__out LPMODULEENTRY32W lpme
);

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateProcess,
    __out       PHANDLE ProcessHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ObjectAttributes,
    __in        HANDLE ParentProcess,
    __in        BOOLEAN InheritObjectTable,
    __in_opt    HANDLE SectionHandle,
    __in_opt    HANDLE DebugPort,
    __in_opt    HANDLE ExceptionPort
);

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateProcessEx,
    __out       PHANDLE ProcessHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ObjectAttributes,
    __in        HANDLE ParentProcess,
    __in        ULONG Flags,
    __in_opt    HANDLE SectionHandle,
    __in_opt    HANDLE DebugPort,
    __in_opt    HANDLE ExceptionPort,
    __in        BOOLEAN InJob
);

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateUserProcess,
    __out       PHANDLE ProcessHandle,
    __out       PHANDLE ThreadHandle,
    __in        ACCESS_MASK ProcessDesiredAccess,
    __in        ACCESS_MASK ThreadDesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    __in_opt    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    __in        ULONG ProcessFlags,
    __in        ULONG ThreadFlags,
    __in_opt    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    __inout     PPS_CREATE_INFO CreateInfo,
    __in_opt    PPS_ATTRIBUTE_LIST AttributeList
);

extern HOOKDEF(NTSTATUS, WINAPI, RtlCreateUserProcess,
    IN      PUNICODE_STRING ImagePath,
    IN      ULONG ObjectAttributes,
    IN OUT  PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    IN      PSECURITY_DESCRIPTOR ProcessSecurityDescriptor OPTIONAL,
    IN      PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
    IN      HANDLE ParentProcess,
    IN      BOOLEAN InheritHandles,
    IN      HANDLE DebugPort OPTIONAL,
    IN      HANDLE ExceptionPort OPTIONAL,
    OUT     PRTL_USER_PROCESS_INFORMATION ProcessInformation
);

extern HOOKDEF(NTSTATUS, WINAPI, NtOpenProcess,
    __out     PHANDLE ProcessHandle,
    __in      ACCESS_MASK DesiredAccess,
    __in      POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt  PCLIENT_ID ClientId
);

extern HOOKDEF(NTSTATUS, WINAPI, NtTerminateProcess,
    __in_opt  HANDLE ProcessHandle,
    __in      NTSTATUS ExitStatus
);

extern HOOKDEF(NTSTATUS, WINAPI, NtResumeProcess,
	__in  HANDLE ProcessHandle
);

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateSection,
    __out     PHANDLE SectionHandle,
    __in      ACCESS_MASK DesiredAccess,
    __in_opt  POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt  PLARGE_INTEGER MaximumSize,
    __in      ULONG SectionPageProtection,
    __in      ULONG AllocationAttributes,
    __in_opt  HANDLE FileHandle
);

extern HOOKDEF(NTSTATUS, WINAPI, NtDuplicateObject,
	__in       HANDLE SourceProcessHandle,
	__in       HANDLE SourceHandle,
	__in_opt   HANDLE TargetProcessHandle,
	__out_opt  PHANDLE TargetHandle,
	__in       ACCESS_MASK DesiredAccess,
	__in       ULONG HandleAttributes,
	__in       ULONG Options
);
	
extern HOOKDEF(NTSTATUS, WINAPI, NtMakeTemporaryObject,
    __in     HANDLE ObjectHandle
);

extern HOOKDEF(NTSTATUS, WINAPI, NtMakePermanentObject,
    __in     HANDLE ObjectHandle
);

extern HOOKDEF(NTSTATUS, WINAPI, NtOpenSection,
    __out  PHANDLE SectionHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes
);

extern HOOKDEF(BOOL, WINAPI, CreateProcessInternalW,
    __in_opt    LPVOID lpUnknown1,
    __in_opt    LPWSTR lpApplicationName,
    __inout_opt LPWSTR lpCommandLine,
    __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in        BOOL bInheritHandles,
    __in        DWORD dwCreationFlags,
    __in_opt    LPVOID lpEnvironment,
    __in_opt    LPWSTR lpCurrentDirectory,
    __in        LPSTARTUPINFO lpStartupInfo,
    __out       LPPROCESS_INFORMATION lpProcessInformation,
    __in_opt    LPVOID lpUnknown2
);

extern HOOKDEF(BOOL, WINAPI, WaitForDebugEvent,
	__out LPDEBUG_EVENT lpDebugEvent,
	__in DWORD dwMilliseconds
);

extern HOOKDEF(NTSTATUS, WINAPI, DbgUiWaitStateChange,
	__out PDBGUI_WAIT_STATE_CHANGE StateChange,
	__in_opt PLARGE_INTEGER Timeout
);

extern HOOKDEF(BOOLEAN, WINAPI, RtlDispatchException,
	__in PEXCEPTION_RECORD ExceptionRecord,
	__in PCONTEXT Context
);

extern HOOKDEF(NTSTATUS, WINAPI, NtRaiseException,
	__in PEXCEPTION_RECORD ExceptionRecord,
	__in PCONTEXT Context,
	__in BOOLEAN SearchFrames
);

extern HOOKDEF(BOOL, WINAPI, ShellExecuteExW,
    __inout  SHELLEXECUTEINFOW *pExecInfo
);

extern HOOKDEF(DWORD, WINAPI, GetLastError,
	void
);

extern HOOKDEF(HRESULT, WINAPI, CoCreateInstance,
	__in    REFCLSID rclsid,
	__in	LPUNKNOWN pUnkOuter,
	__in	DWORD dwClsContext,
	__in	REFIID riid,
	__out	LPVOID *ppv
);

extern HOOKDEF(HRESULT, WINAPI, CoCreateInstanceEx,
	__in    REFCLSID rclsid,
	__in	LPUNKNOWN pUnkOuter,
	__in	DWORD dwClsContext,
	_In_    COSERVERINFO *pServerInfo,
	_In_    DWORD        dwCount,
	_Inout_ MULTI_QI     *pResults
);

extern HOOKDEF(HRESULT, WINAPI, CoGetClassObject,
	_In_     REFCLSID     rclsid,
	_In_     DWORD        dwClsContext,
	_In_opt_ COSERVERINFO *pServerInfo,
	_In_     REFIID       riid,
	_Out_    LPVOID       *ppv
);

extern HOOKDEF(NTSTATUS, WINAPI, NtUnmapViewOfSection,
    _In_      HANDLE ProcessHandle,
    _In_opt_  PVOID BaseAddress
);

extern HOOKDEF(NTSTATUS, WINAPI, NtSetInformationProcess,
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__in PVOID ProcessInformation,
	__in ULONG ProcessInformationLength
);

extern HOOKDEF(NTSTATUS, WINAPI, NtQueryInformationProcess,
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

extern HOOKDEF(NTSTATUS, WINAPI, NtAllocateVirtualMemory,
    __in     HANDLE ProcessHandle,
    __inout  PVOID *BaseAddress,
    __in     ULONG_PTR ZeroBits,
    __inout  PSIZE_T RegionSize,
    __in     ULONG AllocationType,
    __in     ULONG Protect
);

extern HOOKDEF(NTSTATUS, WINAPI, NtReadVirtualMemory,
    __in        HANDLE ProcessHandle,
    __in        LPCVOID BaseAddress,
    __out       LPVOID Buffer,
    __in        SIZE_T NumberOfBytesToRead,
    __out_opt   PSIZE_T NumberOfBytesRead
);

extern HOOKDEF(BOOL, WINAPI, ReadProcessMemory,
    _In_    HANDLE hProcess,
    _In_    LPCVOID lpBaseAddress,
    _Out_   LPVOID lpBuffer,
    _In_    SIZE_T nSize,
    _Out_   PSIZE_T lpNumberOfBytesRead
);

extern HOOKDEF(NTSTATUS, WINAPI, NtWriteVirtualMemory,
    __in        HANDLE ProcessHandle,
    __in        LPVOID BaseAddress,
    __in        LPCVOID Buffer,
    __in        SIZE_T NumberOfBytesToWrite,
    __out_opt   PSIZE_T NumberOfBytesWritten
);

extern HOOKDEF(BOOL, WINAPI, WriteProcessMemory,
    _In_    HANDLE hProcess,
    _In_    LPVOID lpBaseAddress,
    _In_    LPCVOID lpBuffer,
    _In_    SIZE_T nSize,
    _Out_   PSIZE_T lpNumberOfBytesWritten
);


extern HOOKDEF(NTSTATUS, WINAPI, NtWow64ReadVirtualMemory64,
	__in HANDLE ProcessHandle,
	__in_opt LARGE_INTEGER BaseAddress,
	__out PVOID Buffer,
	__in LARGE_INTEGER BufferSize,
	__out_opt PLARGE_INTEGER NumberOfBytesRead
);

extern HOOKDEF(NTSTATUS, WINAPI, NtWow64WriteVirtualMemory64,
	__in HANDLE ProcessHandle,
	__in_opt LARGE_INTEGER BaseAddress,
	__in PVOID Buffer,
	__in LARGE_INTEGER BufferSize,
	__out_opt PLARGE_INTEGER NumberOfBytesWritten
);

extern HOOKDEF(NTSTATUS, WINAPI, NtProtectVirtualMemory,
    IN      HANDLE ProcessHandle,
    IN OUT  PVOID *BaseAddress,
    IN OUT  PSIZE_T NumberOfBytesToProtect,
    IN      ULONG NewAccessProtection,
    OUT     PULONG OldAccessProtection
);

extern HOOKDEF(BOOL, WINAPI, VirtualProtectEx,
    __in   HANDLE hProcess,
    __in   LPVOID lpAddress,
    __in   SIZE_T dwSize,
    __in   DWORD flNewProtect,
    __out  PDWORD lpflOldProtect
);

extern HOOKDEF(NTSTATUS, WINAPI, NtFreeVirtualMemory,
    IN      HANDLE ProcessHandle,
    IN      PVOID *BaseAddress,
    IN OUT  PSIZE_T RegionSize,
    IN      ULONG FreeType
);

extern HOOKDEF(BOOL, WINAPI, VirtualFreeEx,
    __in  HANDLE hProcess,
    __in  LPVOID lpAddress,
    __in  SIZE_T dwSize,
    __in  DWORD dwFreeType
);

extern HOOKDEF(int, CDECL, system,
    const char *command
);

extern HOOKDEF(BOOL, WINAPI, CreateProcessWithLogonW,
	_In_        LPCWSTR               lpUsername,
	_In_opt_    LPCWSTR               lpDomain,
	_In_        LPCWSTR               lpPassword,
	_In_        DWORD                 dwLogonFlags,
	_In_opt_    LPCWSTR               lpApplicationName,
	_Inout_opt_ LPWSTR                lpCommandLine,
	_In_        DWORD                 dwCreationFlags,
	_In_opt_    LPVOID                lpEnvironment,
	_In_opt_    LPCWSTR               lpCurrentDirectory,
	_In_        LPSTARTUPINFOW        lpStartupInfo,
	_Out_       LPPROCESS_INFORMATION lpProcessInfo
);

extern HOOKDEF(BOOL, WINAPI, CreateProcessWithTokenW,
	_In_        HANDLE                hToken,
	_In_        DWORD                 dwLogonFlags,
	_In_opt_    LPCWSTR               lpApplicationName,
	_Inout_opt_ LPWSTR                lpCommandLine,
	_In_        DWORD                 dwCreationFlags,
	_In_opt_    LPVOID                lpEnvironment,
	_In_opt_    LPCWSTR               lpCurrentDirectory,
	_In_        LPSTARTUPINFOW        lpStartupInfo,
	_Out_       LPPROCESS_INFORMATION lpProcessInfo
);

//
// Thread Hooks
//

extern HOOKDEF(NTSTATUS, WINAPI, NtQueueApcThread,
	__in HANDLE ThreadHandle,
	__in PIO_APC_ROUTINE ApcRoutine,
	__in_opt PVOID ApcRoutineContext,
	__in_opt PIO_STATUS_BLOCK ApcStatusBlock,
	__in_opt ULONG ApcReserved
);

extern HOOKDEF(NTSTATUS, WINAPI, NtQueueApcThreadEx,
	__in HANDLE ThreadHandle,
	__in_opt HANDLE UserApcReserveHandle,
	__in PIO_APC_ROUTINE ApcRoutine,
	__in_opt PVOID ApcRoutineContext,
	__in_opt PIO_STATUS_BLOCK ApcStatusBlock,
	__in_opt PVOID ApcReserved
);

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateThread,
    __out     PHANDLE ThreadHandle,
    __in      ACCESS_MASK DesiredAccess,
    __in_opt  POBJECT_ATTRIBUTES ObjectAttributes,
    __in       HANDLE ProcessHandle,
    __out      PCLIENT_ID ClientId,
    __in       PCONTEXT ThreadContext,
    __in        PINITIAL_TEB InitialTeb,
    __in      BOOLEAN CreateSuspended
);

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateThreadEx,
    OUT     PHANDLE hThread,
    IN      ACCESS_MASK DesiredAccess,
    IN      PVOID ObjectAttributes,
    IN      HANDLE ProcessHandle,
    IN      LPTHREAD_START_ROUTINE lpStartAddress,
    IN      PVOID lpParameter,
    IN      DWORD CreateFlags,
    IN      LONG StackZeroBits,
    IN      LONG SizeOfStackCommit,
    IN      LONG SizeOfStackReserve,
    OUT     PVOID lpBytesBuffer
);

extern HOOKDEF(NTSTATUS, WINAPI, NtOpenThread,
    __out  PHANDLE ThreadHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes,
    __in   PCLIENT_ID ClientId
);

extern HOOKDEF(NTSTATUS, WINAPI, NtGetContextThread,
    __in     HANDLE ThreadHandle,
    __inout  LPCONTEXT Context
);

extern HOOKDEF(NTSTATUS, WINAPI, NtSetContextThread,
    __in  HANDLE ThreadHandle,
    __in  const CONTEXT *Context
);

extern HOOKDEF(NTSTATUS, WINAPI, NtSuspendThread,
    __in       HANDLE ThreadHandle,
    __out_opt  ULONG *PreviousSuspendCount
);

extern HOOKDEF(NTSTATUS, WINAPI, NtResumeThread,
    __in        HANDLE ThreadHandle,
    __out_opt   ULONG *SuspendCount
);

extern HOOKDEF(NTSTATUS, WINAPI, NtTerminateThread,
    __in  HANDLE ThreadHandle,
    __in  NTSTATUS ExitStatus
);

extern HOOKDEF(HANDLE, WINAPI, CreateThread,
    __in   LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in   SIZE_T dwStackSize,
    __in   LPTHREAD_START_ROUTINE lpStartAddress,
    __in   LPVOID lpParameter,
    __in   DWORD dwCreationFlags,
    __out_opt  LPDWORD lpThreadId
);

extern HOOKDEF(HANDLE, WINAPI, CreateRemoteThread,
    __in   HANDLE hProcess,
    __in   LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in   SIZE_T dwStackSize,
    __in   LPTHREAD_START_ROUTINE lpStartAddress,
    __in   LPVOID lpParameter,
    __in   DWORD dwCreationFlags,
    __out_opt  LPDWORD lpThreadId
);

extern HOOKDEF(BOOL, WINAPI, TerminateThread,
    __inout  HANDLE hThread,
    __in     DWORD dwExitCode
);

extern HOOKDEF(NTSTATUS, WINAPI, RtlCreateUserThread,
    IN HANDLE ProcessHandle,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    IN BOOLEAN CreateSuspended,
    IN ULONG StackZeroBits,
    IN OUT PULONG StackReserved,
    IN OUT PULONG StackCommit,
    IN PVOID StartAddress,
    IN PVOID StartParameter OPTIONAL,
    OUT PHANDLE ThreadHandle,
    OUT PCLIENT_ID ClientId
);

//
// Misc Hooks
//

extern HOOKDEF(BOOL, WINAPI, SaferIdentifyLevel,
	_In_       DWORD                  dwNumProperties,
	_In_opt_   PVOID				  pCodeProperties,
	_Out_      PVOID				  pLevelHandle,
	_Reserved_ LPVOID                 lpReserved
);

extern HOOKDEF(DWORD, WINAPI, RasValidateEntryNameW,
	_In_ LPCWSTR lpszPhonebook,
	_In_ LPCWSTR lpszEntry
);

extern HOOKDEF(DWORD, WINAPI, RasConnectionNotificationW,
	_In_ PVOID hrasconn,
	_In_ HANDLE   hEvent,
	_In_ DWORD    dwFlags
);



extern HOOKDEF(void, WINAPI, GetSystemInfo,
	__out LPSYSTEM_INFO lpSystemInfo
);

extern HOOKDEF(NTSTATUS, WINAPI, RtlDecompressBuffer,
	__in USHORT CompressionFormat,
	__out PUCHAR UncompressedBuffer,
	__in ULONG UncompressedBufferSize,
	__in PUCHAR CompressedBuffer,
	__in ULONG CompressedBufferSize,
	__out PULONG FinalUncompressedSize
);

extern HOOKDEF(NTSTATUS, WINAPI, RtlCompressBuffer,
	_In_  USHORT CompressionFormatAndEngine,
	_In_  PUCHAR UncompressedBuffer,
	_In_  ULONG  UncompressedBufferSize,
	_Out_ PUCHAR CompressedBuffer,
	_In_  ULONG  CompressedBufferSize,
	_In_  ULONG  UncompressedChunkSize,
	_Out_ PULONG FinalCompressedSize,
	_In_  PVOID  WorkSpace
);

extern HOOKDEF(NTSTATUS, WINAPI, NtLoadDriver,
	PUNICODE_STRING DriverServiceNAme
);

extern HOOKDEF(SHORT, WINAPI, GetAsyncKeyState,
	__in int vKey
);

extern HOOKDEF(HHOOK, WINAPI, SetWindowsHookExA,
    __in  int idHook,
    __in  HOOKPROC lpfn,
    __in  HINSTANCE hMod,
    __in  DWORD dwThreadId
);

extern HOOKDEF(HHOOK, WINAPI, SetWindowsHookExW,
    __in  int idHook,
    __in  HOOKPROC lpfn,
    __in  HINSTANCE hMod,
    __in  DWORD dwThreadId
);

extern HOOKDEF(BOOL, WINAPI, UnhookWindowsHookEx,
    __in  HHOOK hhk
);

extern HOOKDEF(LPTOP_LEVEL_EXCEPTION_FILTER, WINAPI, SetUnhandledExceptionFilter,
    _In_  LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter
);

extern HOOKDEF(PVOID, WINAPI, RtlAddVectoredExceptionHandler,
    __in    ULONG First,
    __out   PVECTORED_EXCEPTION_HANDLER Handler
);

extern HOOKDEF(UINT, WINAPI, SetErrorMode,
	_In_ UINT uMode
);

extern HOOKDEF(NTSTATUS, WINAPI, LdrGetDllHandle,
    __in_opt    PWORD pwPath,
    __in_opt    PVOID Unused,
    __in        PUNICODE_STRING ModuleFileName,
    __out       PHANDLE pHModule
);

extern HOOKDEF(NTSTATUS, WINAPI, LdrGetProcedureAddress,
    __in        HMODULE ModuleHandle,
    __in_opt    PANSI_STRING FunctionName,
    __in_opt    WORD Ordinal,
    __out       PVOID *FunctionAddress
);

extern HOOKDEF(BOOL, WINAPI, DeviceIoControl,
    __in         HANDLE hDevice,
    __in         DWORD dwIoControlCode,
    __in_opt     LPVOID lpInBuffer,
    __in         DWORD nInBufferSize,
    __out_opt    LPVOID lpOutBuffer,
    __in         DWORD nOutBufferSize,
    __out_opt    LPDWORD lpBytesReturned,
    __inout_opt  LPOVERLAPPED lpOverlapped
);

extern HOOKDEF(NTSTATUS, WINAPI, NtSetTimer,
	IN HANDLE               TimerHandle,
	IN PLARGE_INTEGER       DueTime,
	IN PVOID				TimerApcRoutine OPTIONAL,
	IN PVOID                TimerContext OPTIONAL,
	IN BOOLEAN              ResumeTimer,
	IN LONG                 Period OPTIONAL,
	OUT PBOOLEAN            PreviousState OPTIONAL
);

extern HOOKDEF(NTSTATUS, WINAPI, NtSetTimerEx,
	IN HANDLE TimerHandle,
	IN int TimerSetInformationClass,
	__inout PVOID TimerSetInformation,
	IN ULONG TimerSetInformationLength
);

extern HOOKDEF(NTSTATUS, WINAPI, NtDelayExecution,
    __in    BOOLEAN Alertable,
    __in    PLARGE_INTEGER DelayInterval
);

extern HOOKDEF(DWORD, WINAPI, timeGetTime,
	void
);

extern HOOKDEF(DWORD, WINAPI, MsgWaitForMultipleObjectsEx,
	_In_       DWORD  nCount,
	_In_ const HANDLE *pHandles,
	_In_       DWORD  dwMilliseconds,
	_In_       DWORD  dwWakeMask,
	_In_       DWORD  dwFlags
);

extern HOOKDEF_NOTAIL(WINAPI, ExitWindowsEx,
    __in  UINT uFlags,
    __in  DWORD dwReason
);

extern HOOKDEF_NOTAIL(WINAPI, InitiateShutdownW,
	_In_opt_ LPWSTR lpMachineName,
	_In_opt_ LPWSTR lpMessage,
	_In_     DWORD  dwGracePeriod,
	_In_     DWORD  dwShutdownFlags,
	_In_     DWORD  dwReason
);

extern HOOKDEF_NOTAIL(WINAPI, InitiateSystemShutdownW,
	_In_opt_ LPWSTR lpMachineName,
	_In_opt_ LPWSTR lpMessage,
	_In_     DWORD  dwTimeout,
	_In_     BOOL	bForceAppsClosed,
	_In_     BOOL	bRebootAfterShutdown
);

extern HOOKDEF_NOTAIL(WINAPI, InitiateSystemShutdownExW,
	_In_opt_ LPWSTR lpMachineName,
	_In_opt_ LPWSTR lpMessage,
	_In_     DWORD  dwTimeout,
	_In_     BOOL	bForceAppsClosed,
	_In_     BOOL	bRebootAfterShutdown,
	_In_	 DWORD	dwReason
);

extern HOOKDEF_NOTAIL(WINAPI, NtRaiseHardError,
	IN NTSTATUS 	ErrorStatus,
	IN ULONG 	NumberOfParameters,
	IN ULONG 	UnicodeStringParameterMask,
	IN PULONG_PTR 	Parameters,
	IN ULONG 	ValidResponseOptions,
	OUT PULONG 	Response
);

extern HOOKDEF_NOTAIL(WINAPI, NtShutdownSystem,
	__in  UINT Action
);

extern HOOKDEF_NOTAIL(WINAPI, NtSetSystemPowerState,
	__in  UINT SystemAction,
	__in  UINT MinSystemState,
	__in  UINT Flags
);

extern HOOKDEF(BOOL, WINAPI, IsDebuggerPresent,
    void
);

extern HOOKDEF(BOOL, WINAPI, LookupPrivilegeValueW,
    __in_opt  LPWSTR lpSystemName,
    __in      LPWSTR lpName,
    __out     PLUID lpLuid
);

extern HOOKDEF(BOOL, WINAPI, GetCurrentHwProfileW,
	_Out_ LPHW_PROFILE_INFO lpHwProfileInfo
);

extern HOOKDEF(BOOL, WINAPI, IsUserAdmin,
	void
);

extern HOOKDEF(NTSTATUS, WINAPI, NtClose,
    __in    HANDLE Handle
);

extern HOOKDEF(BOOL, WINAPI, WriteConsoleA,
    _In_        HANDLE hConsoleOutput,
    _In_        const VOID *lpBuffer,
    _In_        DWORD nNumberOfCharsToWrite,
    _Out_       LPDWORD lpNumberOfCharsWritten,
    _Reserved_  LPVOID lpReseverd
);

extern HOOKDEF(BOOL, WINAPI, WriteConsoleW,
    _In_        HANDLE hConsoleOutput,
    _In_        const VOID *lpBuffer,
    _In_        DWORD nNumberOfCharsToWrite,
    _Out_       LPDWORD lpNumberOfCharsWritten,
    _Reserved_  LPVOID lpReseverd
);

extern HOOKDEF(int, WINAPI, GetSystemMetrics,
    _In_  int nIndex
);

extern HOOKDEF(BOOL, WINAPI, GetCursorPos,
    _Out_ LPPOINT lpPoint
);

extern HOOKDEF(BOOL, WINAPI, GetComputerNameA,
    _Out_    PCTSTR lpBuffer,
    _Inout_  LPDWORD lpnSize
);

extern HOOKDEF(BOOL, WINAPI, GetComputerNameW,
    _Out_    PCWSTR lpBuffer,
    _Inout_  LPDWORD lpnSize
);

extern HOOKDEF(BOOL, WINAPI, GetUserNameA,
    _Out_    PCTSTR lpBuffer,
    _Inout_  LPDWORD lpnSize
);

extern HOOKDEF(BOOL, WINAPI, GetUserNameW,
    _Out_    PCWSTR lpBuffer,
    _Inout_  LPDWORD lpnSize
);

extern HOOKDEF(void, WINAPIV, memcpy,
   void *dest,
   const void *src,
   size_t count
);   

extern HOOKDEF(HDEVINFO, WINAPI, SetupDiGetClassDevsA,
	_In_opt_ const GUID   *ClassGuid,
	_In_opt_       PCSTR Enumerator,
	_In_opt_       HWND   hwndParent,
	_In_           DWORD  Flags
);

extern HOOKDEF(HDEVINFO, WINAPI, SetupDiGetClassDevsW,
	_In_opt_ const GUID   *ClassGuid,
	_In_opt_       PCWSTR Enumerator,
	_In_opt_       HWND   hwndParent,
	_In_           DWORD  Flags
);

extern HOOKDEF(BOOL, WINAPI, SetupDiGetDeviceRegistryPropertyA,
	_In_      HDEVINFO         DeviceInfoSet,
	_In_      PSP_DEVINFO_DATA DeviceInfoData,
	_In_      DWORD            Property,
	_Out_opt_ PDWORD           PropertyRegDataType,
	_Out_opt_ PBYTE            PropertyBuffer,
	_In_      DWORD            PropertyBufferSize,
	_Out_opt_ PDWORD           RequiredSize
);

extern HOOKDEF(BOOL, WINAPI, SetupDiGetDeviceRegistryPropertyW,
	_In_      HDEVINFO         DeviceInfoSet,
	_In_      PSP_DEVINFO_DATA DeviceInfoData,
	_In_      DWORD            Property,
	_Out_opt_ PDWORD           PropertyRegDataType,
	_Out_opt_ PBYTE            PropertyBuffer,
	_In_      DWORD            PropertyBufferSize,
	_Out_opt_ PDWORD           RequiredSize
);

extern HOOKDEF(BOOL, WINAPI, SetupDiBuildDriverInfoList,
	_In_    HDEVINFO         DeviceInfoSet,
	_Inout_ PSP_DEVINFO_DATA DeviceInfoData,
	_In_    DWORD            DriverType
);

extern HOOKDEF(HRESULT, WINAPI, DecodeImageEx,
	__in PVOID pStream, // IStream *
	__in PVOID pMap, // IMapMIMEToCLSID *
	__in PVOID pEventSink, // IUnknown *
	__in_opt LPCWSTR pszMIMETypeParam
);

extern HOOKDEF(HRESULT, WINAPI, DecodeImage,
	__in PVOID pStream, // IStream *
	__in PVOID pMap, // IMapMIMEToCLSID *
	__in PVOID pEventSink // IUnknown *
);

extern HOOKDEF(NTSTATUS, WINAPI, LsaOpenPolicy,
	PLSA_UNICODE_STRING SystemName,
	PVOID ObjectAttributes,
	ACCESS_MASK DesiredAccess,
	PVOID PolicyHandle
);

extern HOOKDEF(DWORD, WINAPI, WNetGetProviderNameW,
	__in DWORD dwNetType,
	__out LPWSTR lpProviderName,
	__inout LPDWORD lpBufferSize
);

extern HOOKDEF(BOOL, WINAPI, SystemTimeToTzSpecificLocalTime,
	_In_opt_ LPTIME_ZONE_INFORMATION lpTimeZone,
	_In_     LPSYSTEMTIME            lpUniversalTime,
	_Out_    LPSYSTEMTIME            lpLocalTime
);

extern HOOKDEF(HRESULT, WINAPI, CLSIDFromProgID,
	_In_ LPCOLESTR lpszProgID,
	_Out_ LPCLSID lpclsid
);

extern HOOKDEF(void, WINAPI, GlobalMemoryStatus,
	_Out_ LPMEMORYSTATUS lpBuffer
);

extern HOOKDEF(BOOL, WINAPI, GlobalMemoryStatusEx,
	_Out_ LPMEMORYSTATUSEX lpBuffer
);

extern HOOKDEF(BOOL, WINAPI, SystemParametersInfoA,
	_In_    UINT  uiAction,
	_In_    UINT  uiParam,
	_Inout_ PVOID pvParam,
	_In_    UINT  fWinIni
);

extern HOOKDEF(BOOL, WINAPI, SystemParametersInfoW,
	_In_    UINT  uiAction,
	_In_    UINT  uiParam,
	_Inout_ PVOID pvParam,
	_In_    UINT  fWinIni
);

extern HOOKDEF(HRESULT, WINAPI, PStoreCreateInstance,
	_Out_ PVOID **ppProvider,
	_In_  VOID  *pProviderID,
	_In_  VOID  *pReserved,
	_In_  DWORD dwFlags
);

//
// Network Hooks
//
extern HOOKDEF(DWORD, WINAPI, InternetConfirmZoneCrossingA,
	_In_ HWND hWnd,
	_In_ LPTSTR szUrlPrev,
	_In_ LPTSTR szUrlNew,
	_In_ BOOL bPost
);

extern HOOKDEF(DWORD, WINAPI, InternetConfirmZoneCrossingW,
	_In_ HWND hWnd,
	_In_ LPTSTR szUrlPrev,
	_In_ LPTSTR szUrlNew,
	_In_ BOOL bPost
);

extern HOOKDEF(SECURITY_STATUS, WINAPI, SslEncryptPacket,
	_In_    NCRYPT_PROV_HANDLE hSslProvider,
	_Inout_ NCRYPT_KEY_HANDLE hKey,
	_In_    PBYTE pbInput,
	_In_    DWORD cbInput,
	_Out_   PBYTE pbOutput,
	_In_    DWORD cbOutput,
	_Out_   DWORD *pcbResult,
	_In_    ULONGLONG SequenceNumber,
	_In_    DWORD dcContentType,
	_In_    DWORD dwFlags
);

extern HOOKDEF(SECURITY_STATUS, WINAPI, SslDecryptPacket,
	_In_    NCRYPT_PROV_HANDLE hSslProvider,
	_Inout_ NCRYPT_KEY_HANDLE hKey,
	_In_    PBYTE pbInput,
	_In_    DWORD cbInput,
	_Out_   PBYTE pbOutput,
	_In_    DWORD cbOutput,
	_Out_   DWORD *pcbResult,
	_In_    ULONGLONG SequenceNumber,
	_In_    DWORD dwFlags
);

extern HOOKDEF(BOOL, WINAPI, WinHttpSendRequest,
	_In_      HINTERNET hRequest,
	_In_opt_  LPCWSTR pwszHeaders,
	_In_      DWORD dwHeadersLength,
	_In_opt_  LPVOID lpOptional,
	_In_      DWORD dwOptionalLength,
	_In_      DWORD dwTotalLength,
	_In_      DWORD_PTR dwContext
);

extern HOOKDEF(BOOL, WINAPI, WinHttpReceiveResponse,
	_In_        HINTERNET hRequest,
	_Reserved_  LPVOID lpReserved
);

extern HOOKDEF(BOOL, WINAPI, WinHttpQueryHeaders,
	_In_      HINTERNET hRequest,
	_In_      DWORD dwInfoLevel,
	_In_opt_  LPCWSTR pwszName,
	_Out_     LPVOID lpBuffer,
	_Inout_   LPDWORD lpdwBufferLength,
	_Inout_   LPDWORD lpdwIndex
);

extern HOOKDEF(HINTERNET, WINAPI, WinHttpOpen,
	_In_opt_ LPCWSTR pwszUserAgent,
	_In_ DWORD dwAccessType,
	_In_ LPCWSTR pwszProxyName,
	_In_ LPCWSTR pwszProxyBypass,
	_In_ DWORD dwFlags
);

extern HOOKDEF(BOOL, WINAPI, WinHttpGetIEProxyConfigForCurrentUser,
	_Inout_ LPVOID pProxyConfig // WINHTTP_CURRENT_USER_IE_PROXY_CONFIG *
);

extern HOOKDEF(BOOL, WINAPI, WinHttpGetProxyForUrl,
	_In_ HINTERNET hSession,
	_In_ LPCWSTR lpcwszUrl,
	_In_ LPVOID pAutoProxyOptions, // WINHTTP_AUTOPROXY_OPTIONS *
	_Out_ LPVOID pProxyInfo // WINHTTP_PROXY_INFO *
);

extern HOOKDEF(BOOL, WINAPI, WinHttpSetOption,
	_In_ HINTERNET hInternet,
	_In_ DWORD dwOption,
	_In_ LPVOID lpBuffer,
	_In_ DWORD dwBufferLength
);

extern HOOKDEF(HINTERNET, WINAPI, WinHttpConnect,
	_In_ HINTERNET hSession,
	_In_ LPCWSTR pswzServerName,
	_In_ INTERNET_PORT nServerPort,
	_Reserved_ DWORD dwReserved
);

extern HOOKDEF(HINTERNET, WINAPI, WinHttpOpenRequest,
	_In_  HINTERNET hConnect,
	_In_  LPCWSTR pwszVerb,
	_In_  LPCWSTR pwszObjectName,
	_In_  LPCWSTR pwszVersion,
	_In_  LPCWSTR pwszReferrer,
	_In_  LPCWSTR *ppwszAcceptTypes,
	_In_  DWORD dwFlags
);

extern HOOKDEF(BOOL, WINAPI, WinHttpSetTimeouts,
	_In_  HINTERNET hInternet,
	_In_  int dwResolveTimeout,
	_In_  int dwConnectTimeout,
	_In_  int dwSendTimeout,
	_In_  int dwReceiveTimeout
);

extern HOOKDEF(DWORD, WINAPI, NetUserGetInfo,
	_In_ LPCWSTR servername,
	_In_ LPCWSTR username,
	_In_ DWORD level,
	_Out_ LPBYTE *bufptr
);

extern HOOKDEF(HRESULT, WINAPI, ObtainUserAgentString,
	_In_ DWORD dwOption,
	_Out_ LPSTR pcszUAOut,
	_Out_ DWORD *cbSize
);

extern HOOKDEF(HRESULT, WINAPI, URLDownloadToFileW,
    LPUNKNOWN pCaller,
    LPWSTR szURL,
    LPWSTR szFileName,
    DWORD dwReserved,
    LPVOID lpfnCB
);

extern HOOKDEF(HRESULT, WINAPI, URLDownloadToCacheFileW,
  _In_ LPUNKNOWN lpUnkcalled,
  _In_ LPCWSTR szURL,
  _Out_ LPWSTR szFilename,
  _In_ DWORD cchFilename,
  _Reserved_ DWORD dwReserved,
  _In_opt_ VOID *pBSC
);

extern HOOKDEF(BOOL, WINAPI, InternetGetConnectedState,
	_Out_ LPDWORD lpdwFlags,
	_In_ DWORD dwReserved
);

extern HOOKDEF(HINTERNET, WINAPI, InternetOpenA,
    _In_  LPCTSTR lpszAgent,
    _In_  DWORD dwAccessType,
    _In_  LPCTSTR lpszProxyName,
    _In_  LPCTSTR lpszProxyBypass,
    _In_  DWORD dwFlags
);

extern HOOKDEF(HINTERNET, WINAPI, InternetOpenW,
    _In_  LPWSTR lpszAgent,
    _In_  DWORD dwAccessType,
    _In_  LPWSTR lpszProxyName,
    _In_  LPWSTR lpszProxyBypass,
    _In_  DWORD dwFlags
);

extern HOOKDEF(HINTERNET, WINAPI, InternetConnectA,
    _In_  HINTERNET hInternet,
    _In_  LPCTSTR lpszServerName,
    _In_  INTERNET_PORT nServerPort,
    _In_  LPCTSTR lpszUsername,
    _In_  LPCTSTR lpszPassword,
    _In_  DWORD dwService,
    _In_  DWORD dwFlags,
    _In_  DWORD_PTR dwContext
);

extern HOOKDEF(HINTERNET, WINAPI, InternetConnectW,
    _In_  HINTERNET hInternet,
    _In_  LPWSTR lpszServerName,
    _In_  INTERNET_PORT nServerPort,
    _In_  LPWSTR lpszUsername,
    _In_  LPWSTR lpszPassword,
    _In_  DWORD dwService,
    _In_  DWORD dwFlags,
    _In_  DWORD_PTR dwContext
);

extern HOOKDEF(HINTERNET, WINAPI, InternetOpenUrlA,
    __in  HINTERNET hInternet,
    __in  LPCTSTR lpszUrl,
    __in  LPCTSTR lpszHeaders,
    __in  DWORD dwHeadersLength,
    __in  DWORD dwFlags,
    __in  DWORD_PTR dwContext
);

extern HOOKDEF(HINTERNET, WINAPI, InternetOpenUrlW,
    __in  HINTERNET hInternet,
    __in  LPWSTR lpszUrl,
    __in  LPWSTR lpszHeaders,
    __in  DWORD dwHeadersLength,
    __in  DWORD dwFlags,
    __in  DWORD_PTR dwContext
);

extern HOOKDEF(BOOL, WINAPI, InternetCrackUrlA,
	_In_ LPCSTR lpszUrl,
	_In_ DWORD dwUrlLength,
	_In_ DWORD dwFlags,
	_Inout_ LPURL_COMPONENTSA lpUrlComponents
);

extern HOOKDEF(BOOL, WINAPI, InternetCrackUrlW,
	_In_ LPCWSTR lpszUrl,
	_In_ DWORD dwUrlLength,
	_In_ DWORD dwFlags,
	_Inout_ LPURL_COMPONENTSW lpUrlComponents
);

extern HOOKDEF(HINTERNET, WINAPI, HttpOpenRequestA,
    __in  HINTERNET hConnect,
    __in  LPCSTR lpszVerb,
    __in  LPCSTR lpszObjectName,
    __in  LPCSTR lpszVersion,
    __in  LPCSTR lpszReferer,
    __in  LPCSTR *lplpszAcceptTypes,
    __in  DWORD dwFlags,
    __in  DWORD_PTR dwContext
);

extern HOOKDEF(HINTERNET, WINAPI, HttpOpenRequestW,
    __in  HINTERNET hConnect,
    __in  LPCWSTR lpszVerb,
    __in  LPCWSTR lpszObjectName,
    __in  LPCWSTR lpszVersion,
    __in  LPCWSTR lpszReferer,
    __in  LPCWSTR *lplpszAcceptTypes,
    __in  DWORD dwFlags,
    __in  DWORD_PTR dwContext
);

extern HOOKDEF(BOOL, WINAPI, HttpSendRequestA,
    __in  HINTERNET hRequest,
    __in  LPCTSTR lpszHeaders,
    __in  DWORD dwHeadersLength,
    __in  LPVOID lpOptional,
    __in  DWORD dwOptionalLength
);

extern HOOKDEF(BOOL, WINAPI, HttpSendRequestW,
    __in  HINTERNET hRequest,
    __in  LPWSTR lpszHeaders,
    __in  DWORD dwHeadersLength,
    __in  LPVOID lpOptional,
    __in  DWORD dwOptionalLength
);

extern HOOKDEF(BOOL, WINAPI, HttpSendRequestExA,
	__in  HINTERNET hRequest,
	__in  LPINTERNET_BUFFERSA lpBuffersIn,
	__out LPINTERNET_BUFFERSA lpBuffersOut,
	__in  DWORD dwFlags,
	__in  DWORD_PTR dwContext
);

extern HOOKDEF(BOOL, WINAPI, HttpSendRequestExW,
	__in  HINTERNET hRequest,
	__in  LPINTERNET_BUFFERSW lpBuffersIn,
	__out LPINTERNET_BUFFERSW lpBuffersOut,
	__in  DWORD dwFlags,
	__in  DWORD_PTR dwContext
);

extern HOOKDEF(BOOL, WINAPI, HttpAddRequestHeadersA,
	__in HINTERNET hRequest,
	__in LPCSTR lpszHeaders,
	__in DWORD dwHeadersLength,
	__in DWORD dwModifiers
);

extern HOOKDEF(BOOL, WINAPI, HttpAddRequestHeadersW,
	__in HINTERNET hRequest,
	__in LPCWSTR lpszHeaders,
	__in DWORD dwHeadersLength,
	__in DWORD dwModifiers
);

extern HOOKDEF(BOOL, WINAPI, HttpQueryInfoA,
	_In_    HINTERNET hRequest,
	_In_    DWORD     dwInfoLevel,
	_Inout_ LPVOID    lpvBuffer,
	_Inout_ LPDWORD   lpdwBufferLength,
	_Inout_ LPDWORD   lpdwIndex
);

extern HOOKDEF(BOOL, WINAPI, HttpQueryInfoW,
	_In_    HINTERNET hRequest,
	_In_    DWORD     dwInfoLevel,
	_Inout_ LPVOID    lpvBuffer,
	_Inout_ LPDWORD   lpdwBufferLength,
	_Inout_ LPDWORD   lpdwIndex
);

extern HOOKDEF(BOOL, WINAPI, InternetReadFile,
    _In_   HINTERNET hFile,
    _Out_  LPVOID lpBuffer,
    _In_   DWORD dwNumberOfBytesToRead,
    _Out_  LPDWORD lpdwNumberOfBytesRead
);

extern HOOKDEF(BOOL, WINAPI, InternetWriteFile,
    _In_   HINTERNET hFile,
    _In_   LPCVOID lpBuffer,
    _In_   DWORD dwNumberOfBytesToWrite,
    _Out_  LPDWORD lpdwNumberOfBytesWritten
);

extern HOOKDEF(BOOL, WINAPI, InternetCloseHandle,
    _In_  HINTERNET hInternet
);

extern HOOKDEF(BOOL, WINAPI, InternetSetOptionA,
	_In_ HINTERNET hInternet,
	_In_ DWORD dwOption,
	_In_ LPVOID lpBuffer,
	_In_ DWORD dwBufferLength
);

extern HOOKDEF(DNS_STATUS, WINAPI, DnsQuery_A,
    __in         PCSTR lpstrName,
    __in         WORD wType,
    __in         DWORD Options,
    __inout_opt  PVOID pExtra,
    __out_opt    PDNS_RECORD *ppQueryResultsSet,
    __out_opt    PVOID *pReserved
);

extern HOOKDEF(DNS_STATUS, WINAPI, DnsQuery_UTF8,
    __in         LPBYTE lpstrName,
    __in         WORD wType,
    __in         DWORD Options,
    __inout_opt  PVOID pExtra,
    __out_opt    PDNS_RECORD *ppQueryResultsSet,
    __out_opt    PVOID *pReserved
);

extern HOOKDEF(DNS_STATUS, WINAPI, DnsQuery_W,
    __in         PWSTR lpstrName,
    __in         WORD wType,
    __in         DWORD Options,
    __inout_opt  PVOID pExtra,
    __out_opt    PDNS_RECORD *ppQueryResultsSet,
    __out_opt    PVOID *pReserved
);

extern HOOKDEF(int, WSAAPI, getaddrinfo,
    _In_opt_  PCSTR pNodeName,
    _In_opt_  PCSTR pServiceName,
    _In_opt_  const ADDRINFOA *pHints,
    _Out_     PADDRINFOA *ppResult
);

extern HOOKDEF(int, WSAAPI, GetAddrInfoW,
    _In_opt_  PCWSTR pNodeName,
    _In_opt_  PCWSTR pServiceName,
    _In_opt_  const ADDRINFOW *pHints,
    _Out_     PADDRINFOW *ppResult
);

extern HOOKDEF(DWORD, WINAPI, WNetUseConnectionW,
	_In_     HWND hwndOwner,
	_In_     LPNETRESOURCEW lpNetResource,
	_In_     LPCWSTR lpPassword,
	_In_     LPCWSTR lpUserID,
	_In_     DWORD dwFlags,
	_Out_    LPWSTR lpAccessName,
	_Inout_  LPDWORD lpBufferSize,
	_Out_    LPDWORD lpResult
);

extern HOOKDEF(BOOL, WINAPI, CryptRetrieveObjectByUrlW,
	_In_     LPCWSTR                  pszUrl,
	_In_     LPCSTR                   pszObjectOid,
	_In_     DWORD                    dwRetrievalFlags,
	_In_     DWORD                    dwTimeout,
	_Out_    LPVOID                   *ppvObject,
	_In_     HCRYPTASYNC              hAsyncRetrieve,
	_In_opt_ PCRYPT_CREDENTIALS       pCredentials,
	_In_opt_ LPVOID                   pvVerify,
	_In_     PCRYPT_RETRIEVE_AUX_INFO pAuxInfo
);

extern HOOKDEF(ULONG, WINAPI, GetAdaptersAddresses,
	_In_    ULONG                 Family,
	_In_    ULONG                 Flags,
	_In_    PVOID                 Reserved,
	_Inout_ PVOID				  AdapterAddresses, // PIP_ADAPTER_ADDRESSES
	_Inout_ PULONG                SizePointer
);

extern HOOKDEF(DWORD, WINAPI, GetAdaptersInfo,
	_Out_   PVOID pAdapterInfo, // PIP_ADAPTER_INFO
	_Inout_ PULONG           pOutBufLen
);

extern HOOKDEF(ULONG, WINAPI, NetGetJoinInformation,
	_In_  LPCWSTR               lpServer,
	_Out_ LPWSTR                *lpNameBuffer,
	_Out_ DWORD *				BufferType
);

extern HOOKDEF(ULONG, WINAPI, NetUserGetLocalGroups,
	_In_  LPCWSTR servername,
	_In_  LPCWSTR username,
	_In_  DWORD   level,
	_In_  DWORD   flags,
	_Out_ LPBYTE  *bufptr,
	_In_  DWORD   prefmaxlen,
	_Out_ LPDWORD entriesread,
	_Out_ LPDWORD totalentries
);

extern HOOKDEF(HRESULT, WINAPI, CoInternetSetFeatureEnabled,
	INTERNETFEATURELIST FeatureEntry,
	_In_ DWORD			dwFlags,
	BOOL				fEnable
);

extern HOOKDEF(int, WINAPI, NSPStartup,
	__in LPGUID lpProviderId,
	__out PVOID lpnspRoutines
);

extern HOOKDEF(BOOL, WINAPI, HttpEndRequestA,
	__in  HINTERNET hRequest,
	__out LPINTERNET_BUFFERSA lpBuffersOut,
	__in  DWORD dwFlags,
	__in  DWORD_PTR dwContext
);

extern HOOKDEF(BOOL, WINAPI, HttpEndRequestW,
	__in  HINTERNET hRequest,
	__out LPINTERNET_BUFFERSW lpBuffersOut,
	__in  DWORD dwFlags,
	__in  DWORD_PTR dwContext
);

//
// Service Hooks
//

extern HOOKDEF(SC_HANDLE, WINAPI, OpenSCManagerA,
    __in_opt  LPCTSTR lpMachineName,
    __in_opt  LPCTSTR lpDatabaseName,
    __in      DWORD dwDesiredAccess
);

extern HOOKDEF(SC_HANDLE, WINAPI, OpenSCManagerW,
    __in_opt  LPWSTR lpMachineName,
    __in_opt  LPWSTR lpDatabaseName,
    __in      DWORD dwDesiredAccess
);

extern HOOKDEF(SC_HANDLE, WINAPI, CreateServiceA,
    __in       SC_HANDLE hSCManager,
    __in       LPCTSTR lpServiceName,
    __in_opt   LPCTSTR lpDisplayName,
    __in       DWORD dwDesiredAccess,
    __in       DWORD dwServiceType,
    __in       DWORD dwStartType,
    __in       DWORD dwErrorControl,
    __in_opt   LPCTSTR lpBinaryPathName,
    __in_opt   LPCTSTR lpLoadOrderGroup,
    __out_opt  LPDWORD lpdwTagId,
    __in_opt   LPCTSTR lpDependencies,
    __in_opt   LPCTSTR lpServiceStartName,
    __in_opt   LPCTSTR lpPassword
);

extern HOOKDEF(SC_HANDLE, WINAPI, CreateServiceW,
    __in       SC_HANDLE hSCManager,
    __in       LPWSTR lpServiceName,
    __in_opt   LPWSTR lpDisplayName,
    __in       DWORD dwDesiredAccess,
    __in       DWORD dwServiceType,
    __in       DWORD dwStartType,
    __in       DWORD dwErrorControl,
    __in_opt   LPWSTR lpBinaryPathName,
    __in_opt   LPWSTR lpLoadOrderGroup,
    __out_opt  LPDWORD lpdwTagId,
    __in_opt   LPWSTR lpDependencies,
    __in_opt   LPWSTR lpServiceStartName,
    __in_opt   LPWSTR lpPassword
);

extern HOOKDEF(SC_HANDLE, WINAPI, OpenServiceA,
    __in  SC_HANDLE hSCManager,
    __in  LPCTSTR lpServiceName,
    __in  DWORD dwDesiredAccess
);

extern HOOKDEF(SC_HANDLE, WINAPI, OpenServiceW,
    __in  SC_HANDLE hSCManager,
    __in  LPWSTR lpServiceName,
    __in  DWORD dwDesiredAccess
);

extern HOOKDEF(BOOL, WINAPI, StartServiceA,
    __in      SC_HANDLE hService,
    __in      DWORD dwNumServiceArgs,
    __in_opt  LPCTSTR *lpServiceArgVectors
);

extern HOOKDEF(BOOL, WINAPI, StartServiceW,
    __in      SC_HANDLE hService,
    __in      DWORD dwNumServiceArgs,
    __in_opt  LPWSTR *lpServiceArgVectors
);

extern HOOKDEF(BOOL, WINAPI, ControlService,
    __in   SC_HANDLE hService,
    __in   DWORD dwControl,
    __out  LPSERVICE_STATUS lpServiceStatus
);

extern HOOKDEF(BOOL, WINAPI, DeleteService,
    __in  SC_HANDLE hService
);

//
// Sleep Hooks
//

extern HOOKDEF(BOOL, WINAPI, GetLastInputInfo,
	_Out_ PLASTINPUTINFO plii
);

extern HOOKDEF(NTSTATUS, WINAPI, NtDelayExecution,
    __in    BOOLEAN Alertable,
    __in    PLARGE_INTEGER DelayInterval
);

extern HOOKDEF(NTSTATUS, WINAPI, NtWaitForSingleObject,
	__in HANDLE Handle,
	__in    BOOLEAN Alertable,
	__in_opt    PLARGE_INTEGER Timeout
);

extern HOOKDEF(void, WINAPI, GetLocalTime,
    __out  LPSYSTEMTIME lpSystemTime
);

extern HOOKDEF(void, WINAPI, GetSystemTime,
    __out  LPSYSTEMTIME lpSystemTime
);

extern HOOKDEF(DWORD, WINAPI, GetTickCount,
    void
);

extern HOOKDEF(ULONGLONG, WINAPI, GetTickCount64,
	void
);

extern HOOKDEF(NTSTATUS, WINAPI, NtQuerySystemTime,
    _Out_  PLARGE_INTEGER SystemTime
);

extern HOOKDEF(void, WINAPI, GetSystemTimeAsFileTime,
	_Out_ LPFILETIME lpSystemTimeAsFileTime
);

extern HOOKDEF(NTSTATUS, WINAPI, NtQueryPerformanceCounter,
	_Out_     PLARGE_INTEGER PerformanceCounter,
	_Out_opt_ PLARGE_INTEGER PerformanceFrequency
);

extern HOOKDEF(BOOL, WINAPI, CreateTimerQueueTimer,
  _Out_    PHANDLE             phNewTimer,
  _In_opt_ HANDLE              TimerQueue,
  _In_     WAITORTIMERCALLBACK Callback,
  _In_opt_ PVOID               Parameter,
  _In_     DWORD               DueTime,
  _In_     DWORD               Period,
  _In_     ULONG               Flags
);

//
// Socket Hooks
//

extern HOOKDEF(int, WINAPI, WSAStartup,
    _In_   WORD wVersionRequested,
    _Out_  LPWSADATA lpWSAData
);

extern HOOKDEF(struct hostent *, WSAAPI, gethostbyname,
    __in  const char *name
);

extern HOOKDEF(int, WSAAPI, gethostname,
	_Out_ char *name,
	_In_  int  namelen
);

extern HOOKDEF(SOCKET, WSAAPI, socket,
    __in  int af,
    __in  int type,
    __in  int protocol
);

extern HOOKDEF(int, WSAAPI, connect,
    __in  SOCKET s,
    __in  const struct sockaddr *name,
    __in  int namelen
);

extern HOOKDEF(int, WSAAPI, send,
    __in  SOCKET s,
    __in  const char *buf,
    __in  int len,
    __in  int flags
);

extern HOOKDEF(int, WSAAPI, sendto,
    __in  SOCKET s,
    __in  const char *buf,
    __in  int len,
    __in  int flags,
    __in  const struct sockaddr *to,
    __in  int tolen
);

extern HOOKDEF(int, WSAAPI, recv,
    __in   SOCKET s,
    __out  char *buf,
    __in   int len,
    __in   int flags
);

extern HOOKDEF(int, WSAAPI, recvfrom,
    __in         SOCKET s,
    __out        char *buf,
    __in         int len,
    __in         int flags,
    __out        struct sockaddr *from,
    __inout_opt  int *fromlen
);

extern HOOKDEF(SOCKET, WSAAPI, accept,
    __in     SOCKET s,
    __out    struct sockaddr *addr,
    __inout  int *addrlen
);

extern HOOKDEF(int, WSAAPI, bind,
    __in  SOCKET s,
    __in  const struct sockaddr *name,
    __in  int namelen
);

extern HOOKDEF(int, WSAAPI, listen,
    __in  SOCKET s,
    __in  int backlog
);

extern HOOKDEF(int, WSAAPI, select,
    __in     SOCKET s,
    __inout  fd_set *readfds,
    __inout  fd_set *writefds,
    __inout  fd_set *exceptfds,
    __in     const struct timeval *timeout
);

extern HOOKDEF(int, WSAAPI, setsockopt,
    __in  SOCKET s,
    __in  int level,
    __in  int optname,
    __in  const char *optval,
    __in  int optlen
);

extern HOOKDEF(int, WSAAPI, ioctlsocket,
    __in     SOCKET s,
    __in     long cmd,
    __inout  u_long *argp
);

extern HOOKDEF(int, WSAAPI, closesocket,
    __in  SOCKET s
);

extern HOOKDEF(int, WSAAPI, shutdown,
    __in  SOCKET s,
    __in  int how
);

extern HOOKDEF(SOCKET, WSAAPI, WSAAccept,
    __in    SOCKET s,
    __out   struct sockaddr *addr,
    __inout LPINT addrlen,
    __in    LPCONDITIONPROC lpfnCondition,
    __in    DWORD_PTR dwCallbackData
);

extern HOOKDEF(int, WSAAPI, WSARecv,
    __in     SOCKET s,
    __inout  LPWSABUF lpBuffers,
    __in     DWORD dwBufferCount,
    __out    LPDWORD lpNumberOfBytesRecvd,
    __inout  LPDWORD lpFlags,
    __in     LPWSAOVERLAPPED lpOverlapped,
    __in     LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);

extern HOOKDEF(int, WSAAPI, WSARecvFrom,
    __in     SOCKET s,
    __inout  LPWSABUF lpBuffers,
    __in     DWORD dwBufferCount,
    __out    LPDWORD lpNumberOfBytesRecvd,
    __inout  LPDWORD lpFlags,
    __out    struct sockaddr *lpFrom,
    __inout  LPINT lpFromlen,
    __in     LPWSAOVERLAPPED lpOverlapped,
    __in     LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);

extern HOOKDEF(int, WSAAPI, WSASend,
    __in   SOCKET s,
    __in   LPWSABUF lpBuffers,
    __in   DWORD dwBufferCount,
    __out  LPDWORD lpNumberOfBytesSent,
    __in   DWORD dwFlags,
    __in   LPWSAOVERLAPPED lpOverlapped,
    __in   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);

extern HOOKDEF(int, WSAAPI, WSASendTo,
    __in   SOCKET s,
    __in   LPWSABUF lpBuffers,
    __in   DWORD dwBufferCount,
    __out  LPDWORD lpNumberOfBytesSent,
    __in   DWORD dwFlags,
    __in   const struct sockaddr *lpTo,
    __in   int iToLen,
    __in   LPWSAOVERLAPPED lpOverlapped,
    __in   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);

extern HOOKDEF(SOCKET, WSAAPI, WSASocketA,
    __in  int af,
    __in  int type,
    __in  int protocol,
    __in  LPWSAPROTOCOL_INFO lpProtocolInfo,
    __in  GROUP g,
    __in  DWORD dwFlags
);

extern HOOKDEF(SOCKET, WSAAPI, WSASocketW,
    __in  int af,
    __in  int type,
    __in  int protocol,
    __in  LPWSAPROTOCOL_INFO lpProtocolInfo,
    __in  GROUP g,
    __in  DWORD dwFlags
);

extern HOOKDEF(int, WSAAPI, WSAConnect,
	__in   SOCKET s,
	__in   const struct sockaddr *name,
	__in   int namelen,
	__in   LPWSABUF lpCallerData,
	__out  LPWSABUF lpCalleeData,
	__in   LPQOS lpSQOS,
	__in   LPQOS lpGQOS
);

extern HOOKDEF(BOOL, PASCAL, WSAConnectByList,
	_In_          SOCKET               s,
	_In_          PSOCKET_ADDRESS_LIST SocketAddressList,
	_Inout_       LPDWORD              LocalAddressLength,
	_Out_         LPSOCKADDR           LocalAddress,
	_Inout_       LPDWORD              RemoteAddressLength,
	_Out_         LPSOCKADDR           RemoteAddress,
	_In_          PVOID				   timeout,
	_In_          LPWSAOVERLAPPED      Reserved
);

extern HOOKDEF(BOOL, PASCAL, WSAConnectByNameW,
	_In_          SOCKET          s,
	_In_          LPWSTR          nodename,
	_In_          LPWSTR          servicename,
	_Inout_       LPDWORD         LocalAddressLength,
	_Out_         LPSOCKADDR      LocalAddress,
	_Inout_       LPDWORD         RemoteAddressLength,
	_Out_         LPSOCKADDR      RemoteAddress,
	_In_		  PVOID			  timeout,
	LPWSAOVERLAPPED Reserved
);

extern HOOKDEF(int, WSAAPI, WSASendMsg,
	_In_  SOCKET                             s,
	_In_  LPWSAMSG                           lpMsg,
	_In_  DWORD                              dwFlags,
	_Out_ LPDWORD                            lpNumberOfBytesSent,
	_In_  LPWSAOVERLAPPED                    lpOverlapped,
	_In_  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);

extern HOOKDEF(BOOL, PASCAL, ConnectEx,
    _In_      SOCKET s,
    _In_      const struct sockaddr *name,
    _In_      int namelen,
    _In_opt_  PVOID lpSendBuffer,
    _In_      DWORD dwSendDataLength,
    _Out_     LPDWORD lpdwBytesSent,
    _In_      LPOVERLAPPED lpOverlapped
);

extern HOOKDEF(BOOL, PASCAL, TransmitFile,
    SOCKET hSocket,
    HANDLE hFile,
    DWORD nNumberOfBytesToWrite,
    DWORD nNumberOfBytesPerSend,
    LPOVERLAPPED lpOverlapped,
    LPTRANSMIT_FILE_BUFFERS lpTransmitBuffers,
    DWORD dwFlags
);

//
// Crypto Hooks
//

extern HOOKDEF(BOOL, WINAPI, CryptAcquireContextA,
	_Out_	  HCRYPTPROV *phProv,
	_In_	  LPCSTR pszContainer,
	_In_	  LPCSTR pszProvider,
	_In_	  DWORD dwProvType,
	_In_	  DWORD dwFlags
);

extern HOOKDEF(BOOL, WINAPI, CryptAcquireContextW,
	_Out_	  HCRYPTPROV *phProv,
	_In_	  LPCWSTR pszContainer,
	_In_	  LPCWSTR pszProvider,
	_In_	  DWORD dwProvType,
	_In_	  DWORD dwFlags
);

extern HOOKDEF(BOOL, WINAPI, CryptProtectData,
    _In_      DATA_BLOB *pDataIn,
    _In_      LPCWSTR szDataDescr,
    _In_      DATA_BLOB *pOptionalEntropy,
    _In_      PVOID pvReserved,
    _In_opt_  CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,
    _In_      DWORD dwFlags,
    _Out_     DATA_BLOB *pDataOut
);

extern HOOKDEF(BOOL, WINAPI, CryptUnprotectData,
    _In_        DATA_BLOB *pDataIn,
    _Out_opt_   LPWSTR *ppszDataDescr,
    _In_opt_    DATA_BLOB *pOptionalEntropy,
    _Reserved_  PVOID pvReserved,
    _In_opt_    CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,
    _In_        DWORD dwFlags,
    _Out_       DATA_BLOB *pDataOut
);

extern HOOKDEF(BOOL, WINAPI, CryptProtectMemory,
    _Inout_  LPVOID pData,
    _In_     DWORD cbData,
    _In_     DWORD dwFlags
);

extern HOOKDEF(BOOL, WINAPI, CryptUnprotectMemory,
    _Inout_  LPVOID pData,
    _In_     DWORD cbData,
    _In_     DWORD dwFlags
);

extern HOOKDEF(BOOL, WINAPI, CryptDecrypt,
    _In_     HCRYPTKEY hKey,
    _In_     HCRYPTHASH hHash,
    _In_     BOOL Final,
    _In_     DWORD dwFlags,
    _Inout_  BYTE *pbData,
    _Inout_  DWORD *pdwDataLen
);

extern HOOKDEF(BOOL, WINAPI, CryptEncrypt,
    _In_     HCRYPTKEY hKey,
    _In_     HCRYPTHASH hHash,
    _In_     BOOL Final,
    _In_     DWORD dwFlags,
    _Inout_  BYTE *pbData,
    _Inout_  DWORD *pdwDataLen,
    _In_     DWORD dwBufLen
);

extern HOOKDEF(BOOL, WINAPI, CryptHashData,
    _In_  HCRYPTHASH hHash,
    _In_  BYTE *pbData,
    _In_  DWORD dwDataLen,
    _In_  DWORD dwFlags
);

extern HOOKDEF(BOOL, WINAPI, CryptDecodeMessage,
    _In_         DWORD dwMsgTypeFlags,
    _In_         PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara,
    _In_         PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara,
    _In_         DWORD dwSignerIndex,
    _In_         const BYTE *pbEncodedBlob,
    _In_         DWORD cbEncodedBlob,
    _In_         DWORD dwPrevInnerContentType,
    _Out_opt_    DWORD *pdwMsgType,
    _Out_opt_    DWORD *pdwInnerContentType,
    _Out_opt_    BYTE *pbDecoded,
    _Inout_opt_  DWORD *pcbDecoded,
    _Out_opt_    PCCERT_CONTEXT *ppXchgCert,
    _Out_opt_    PCCERT_CONTEXT *ppSignerCert
);

extern HOOKDEF(BOOL, WINAPI, CryptDecryptMessage,
    _In_         PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara,
    _In_         const BYTE *pbEncryptedBlob,
    _In_         DWORD cbEncryptedBlob,
    _Out_opt_    BYTE *pbDecrypted,
    _Inout_opt_  DWORD *pcbDecrypted,
    _Out_opt_    PCCERT_CONTEXT *ppXchgCert
);

extern HOOKDEF(BOOL, WINAPI, CryptEncryptMessage,
    _In_     PCRYPT_ENCRYPT_MESSAGE_PARA pEncryptPara,
    _In_     DWORD cRecipientCert,
    _In_     PCCERT_CONTEXT rgpRecipientCert[],
    _In_     const BYTE *pbToBeEncrypted,
    _In_     DWORD cbToBeEncrypted,
    _Out_    BYTE *pbEncryptedBlob,
    _Inout_  DWORD *pcbEncryptedBlob
);

extern HOOKDEF(BOOL, WINAPI, CryptHashMessage,
    _In_         PCRYPT_HASH_MESSAGE_PARA pHashPara,
    _In_         BOOL fDetachedHash,
    _In_         DWORD cToBeHashed,
    _In_         const BYTE *rgpbToBeHashed[],
    _In_         DWORD rgcbToBeHashed[],
    _Out_        BYTE *pbHashedBlob,
    _Inout_      DWORD *pcbHashedBlob,
    _Out_opt_    BYTE *pbComputedHash,
    _Inout_opt_  DWORD *pcbComputedHash
);

extern HOOKDEF(BOOL, WINAPI, CryptExportKey,
	_In_     HCRYPTKEY hKey,
	_In_     HCRYPTKEY hExpKey,
	_In_     DWORD dwBlobType,
	_In_     DWORD dwFlags,
	_Out_    BYTE *pbData,
	_Inout_  DWORD *pdwDataLen
);

extern HOOKDEF(BOOL, WINAPI, CryptGenKey,
	_In_   HCRYPTPROV hProv,
	_In_   ALG_ID Algid,
	_In_   DWORD dwFlags,
	_Out_  HCRYPTKEY *phKey
);

extern HOOKDEF(BOOL, WINAPI, CryptCreateHash,
	_In_   HCRYPTPROV hProv,
	_In_   ALG_ID Algid,
	_In_   HCRYPTKEY hKey,
	_In_   DWORD dwFlags,
	_Out_  HCRYPTHASH *phHash
);

extern HOOKDEF(BOOL, WINAPI, CryptEnumProvidersA,
	_In_    DWORD  dwIndex,
	_In_    DWORD  *pdwReserved,
	_In_    DWORD  dwFlags,
	_Out_   DWORD  *pdwProvType,
	_Out_   LPSTR pszProvName,
	_Inout_ DWORD  *pcbProvName
);

extern HOOKDEF(BOOL, WINAPI, CryptEnumProvidersW,
	_In_    DWORD  dwIndex,
	_In_    DWORD  *pdwReserved,
	_In_    DWORD  dwFlags,
	_Out_   DWORD  *pdwProvType,
	_Out_   LPWSTR pszProvName,
	_Inout_ DWORD  *pcbProvName
);


extern HOOKDEF(HRESULT, WINAPI, HTTPSCertificateTrust,
	PVOID data // PCRYPT_PROVIDER_DATA
);

extern HOOKDEF(HRESULT, WINAPI, HTTPSFinalProv,
	PVOID data // PCRYPT_PROVIDER_DATA
);

extern HOOKDEF(BOOL, WINAPI, CryptDecodeObjectEx,
	_In_          DWORD              dwCertEncodingType,
	_In_          LPCSTR             lpszStructType,
	_In_    const BYTE               *pbEncoded,
	_In_          DWORD              cbEncoded,
	_In_          DWORD              dwFlags,
	_In_          PCRYPT_DECODE_PARA pDecodePara,
	_Out_         void               *pvStructInfo,
	_Inout_       DWORD              *pcbStructInfo
);

extern HOOKDEF(BOOL, WINAPI, CryptImportPublicKeyInfo,
	_In_  HCRYPTPROV            hCryptProv,
	_In_  DWORD                 dwCertEncodingType,
	_In_  PCERT_PUBLIC_KEY_INFO pInfo,
	_Out_ HCRYPTKEY             *phKey
);

extern HOOKDEF(BOOL, WINAPI, CryptHashSessionKey,
    _In_     HCRYPTHASH hHash,
    _In_     HCRYPTKEY hKey,
    _In_     DWORD dwFlags
);

extern HOOKDEF(DWORD, WINAPI, QueryUsersOnEncryptedFile,
  LPCWSTR   lpFileName,
  PVOID     *pUsers
);

extern HOOKDEF(BOOL, WINAPI, CryptGenRandom,
    HCRYPTPROV hProv,
    DWORD      dwLen,
    BYTE       *pbBuffer
);

HOOKDEF(SECURITY_STATUS, WINAPI, NCryptImportKey,
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hImportKey,
    LPCWSTR            pszBlobType,
    NCryptBufferDesc   *pParameterList,
    NCRYPT_KEY_HANDLE  *phKey,
    PBYTE              pbData,
    DWORD              cbData,
    DWORD              dwFlags
);

HOOKDEF(SECURITY_STATUS, WINAPI, NCryptDecrypt,
    NCRYPT_KEY_HANDLE hKey,
    PBYTE             pbInput,
    DWORD             cbInput,
    VOID              *pPaddingInfo,
    PBYTE             pbOutput,
    DWORD             cbOutput,
    DWORD             *pcbResult,
    DWORD             dwFlags
);

HOOKDEF(SECURITY_STATUS, WINAPI, NCryptEncrypt,
    NCRYPT_KEY_HANDLE hKey,
    PBYTE             pbInput,
    DWORD             cbInput,
    VOID              *pPaddingInfo,
    PBYTE             pbOutput,
    DWORD             cbOutput,
    DWORD             *pcbResult,
    DWORD             dwFlags
);

//
// Special Hooks
//

extern HOOKDEF_NOTAIL(WINAPI, LdrLoadDll,
    __in_opt    PWCHAR PathToFile,
    __in_opt    PULONG Flags,
    __in        PUNICODE_STRING ModuleFileName,
    __out       PHANDLE ModuleHandle
);

extern HOOKDEF_ALT(NTSTATUS, WINAPI, LdrLoadDll,
	__in_opt    PWCHAR PathToFile,
	__in_opt    PULONG Flags,
	__in        PUNICODE_STRING ModuleFileName,
	__out       PHANDLE ModuleHandle
);

extern HOOKDEF_NOTAIL(WINAPI, LdrUnloadDll,
	PVOID DllImageBase
);

extern HOOKDEF(NTSTATUS, WINAPI, NtMapViewOfSection,
    _In_     HANDLE SectionHandle,
    _In_     HANDLE ProcessHandle,
    __inout  PVOID *BaseAddress,
    _In_     ULONG_PTR ZeroBits,
    _In_     SIZE_T CommitSize,
    __inout  PLARGE_INTEGER SectionOffset,
    __inout  PSIZE_T ViewSize,
    __in     UINT InheritDisposition,
    __in     ULONG AllocationType,
    __in     ULONG Win32Protect
);

extern HOOKDEF_NOTAIL(WINAPI, JsEval,
	PVOID Arg1,
	PVOID Arg2,
	PVOID Arg3,
	int Index,
	DWORD *scriptobj
);

extern HOOKDEF(int, WINAPI, COleScript_ParseScriptText,
	PVOID Arg1,
	PWCHAR ScriptBuf,
	PVOID Arg3,
	PVOID Arg4,
	PVOID Arg5,
	PVOID Arg6,
	PVOID Arg7,
	PVOID Arg8,
	PVOID Arg9,
	PVOID Arg10
);

extern HOOKDEF(PVOID, WINAPI, JsParseScript,
	const wchar_t *script,
	PVOID SourceContext,
	const wchar_t *sourceUrl,
	PVOID *result
);

extern HOOKDEF_NOTAIL(WINAPI, JsRunScript,
	const wchar_t *script,
	PVOID SourceContext,
	const wchar_t *sourceUrl,
	PVOID *result
);

extern HOOKDEF(int, WINAPI, CDocument_write,
	PVOID this,
	SAFEARRAY *psa
);

extern HOOKDEF(NTSTATUS, WINAPI, NtQuerySystemInformation,
	_In_ ULONG SystemInformationClass,
	_Inout_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
);

extern HOOKDEF(void, WINAPIV, srand,
   unsigned int seed
);   

extern HOOKDEF(NTSTATUS, WINAPI, NtSetInformationThread,
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN PVOID ThreadInformation,
    IN ULONG ThreadInformationLength
);

extern HOOKDEF(NTSTATUS, WINAPI, NtQueryInformationThread,
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

extern HOOKDEF(LPSTR, WINAPI, lstrcpynA,
  _Out_ LPSTR  lpString1,
  _In_  LPSTR  lpString2,
  _In_  int    iMaxLength
);

extern HOOKDEF(int, WINAPI, lstrcmpiA,
  _In_  LPCSTR   lpString1,
  _In_  LPCSTR   lpString2
);

extern HOOKDEF(HRSRC, WINAPI, FindResourceExA,
  HMODULE hModule,
  LPCSTR lpType,
  LPCSTR lpName,
  WORD wLanguage
);

extern HOOKDEF(HRSRC, WINAPI, FindResourceExW,
  HMODULE hModule,
  LPCWSTR lpType,
  LPCWSTR lpName,
  WORD wLanguage
);

extern HOOKDEF(HGLOBAL, WINAPI, LoadResource,
  _In_opt_ HMODULE hModule,
  _In_     HRSRC   hResInfo
);

extern HOOKDEF(LPVOID, WINAPI, LockResource,
  _In_ HGLOBAL hResData
);

extern HOOKDEF(DWORD, WINAPI, SizeofResource,
    _In_opt_ HMODULE hModule,
    _In_     HRSRC   hResInfo
);

extern HOOKDEF(BOOL, WINAPI, EnumResourceTypesExA,
	_In_opt_ HMODULE         hModule,
	_In_     ENUMRESTYPEPROC lpEnumFunc,
	_In_     LONG_PTR        lParam,
	_In_     DWORD           dwFlags,
	_In_     LANGID          LangId
);

extern HOOKDEF(BOOL, WINAPI, EnumResourceTypesExW,
	_In_opt_ HMODULE         hModule,
	_In_     ENUMRESTYPEPROC lpEnumFunc,
	_In_     LONG_PTR        lParam,
	_In_     DWORD           dwFlags,
	_In_     LANGID          LangId
);

extern HOOKDEF(BOOL, WINAPI, EnumCalendarInfoA,
	CALINFO_ENUMPROCA lpCalInfoEnumProc,
	LCID              Locale,
	CALID             Calendar,
	CALTYPE           CalType
);

extern HOOKDEF(BOOL, WINAPI, EnumCalendarInfoW,
	CALINFO_ENUMPROCA lpCalInfoEnumProc,
	LCID              Locale,
	CALID             Calendar,
	CALTYPE           CalType
);

extern HOOKDEF(BOOL, WINAPI, EnumTimeFormatsA,
	TIMEFMT_ENUMPROCA lpTimeFmtEnumProc,
	LCID              Locale,
	DWORD             dwFlags
);

extern HOOKDEF(BOOL, WINAPI, EnumTimeFormatsW,
	TIMEFMT_ENUMPROCA lpTimeFmtEnumProc,
	LCID              Locale,
	DWORD             dwFlags
);

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateTransaction,
  PHANDLE            TransactionHandle,
  ACCESS_MASK        DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  LPGUID             Uow,
  HANDLE             TmHandle,
  ULONG              CreateOptions,
  ULONG              IsolationLevel,
  ULONG              IsolationFlags,
  PLARGE_INTEGER     Timeout,
  PUNICODE_STRING    Description
);

extern HOOKDEF(NTSTATUS, WINAPI, NtOpenTransaction,
  PHANDLE            TransactionHandle,
  ACCESS_MASK        DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  LPGUID             Uow,
  HANDLE             TmHandle
);

extern HOOKDEF(NTSTATUS, WINAPI, NtRollbackTransaction,
  HANDLE  TransactionHandle,
  BOOLEAN Wait
);

extern HOOKDEF(NTSTATUS, WINAPI, NtCommitTransaction,
  HANDLE  TransactionHandle,
  BOOLEAN Wait
);

extern HOOKDEF(BOOL, WINAPI, RtlSetCurrentTransaction,
    _In_ HANDLE     TransactionHandle
);

extern HOOKDEF(NTSTATUS, WINAPI, NtYieldExecution,
    VOID
);

extern HOOKDEF(VOID, WINAPI, RtlMoveMemory,
    _Out_       VOID UNALIGNED *Destination,
    _In_  const VOID UNALIGNED *Source,
    _In_        SIZE_T         Length
);

extern HOOKDEF(HRESULT, WINAPI, OleConvertOLESTREAMToIStorage,
    IN LPOLESTREAM          lpolestream,
    OUT LPSTORAGE           pstg,
    IN const DVTARGETDEVICE *ptd
);

extern HOOKDEF(BOOL, WINAPI, ChangeWindowMessageFilter,
	UINT  message,
	DWORD dwFlag
);

extern HOOKDEF(LPWSTR, WINAPI, rtcEnvironBstr,
	struct envstruct *es
);

extern HOOKDEF(BOOL, WINAPI, CryptImportKey,
    HCRYPTPROV hProv,
    const BYTE *pbData,
    DWORD      dwDataLen,
    HCRYPTKEY  hPubKey,
    DWORD      dwFlags,
    HCRYPTKEY  *phKey
);

extern HOOKDEF(HANDLE, WINAPI, HeapCreate,
  _In_ DWORD  flOptions,
  _In_ SIZE_T dwInitialSize,
  _In_ SIZE_T dwMaximumSize
);

extern HOOKDEF(HKL, WINAPI, GetKeyboardLayout,
  _In_ DWORD idThread
);

extern HOOKDEF (void, WINAPI, OutputDebugStringA,
  LPCSTR lpOutputString
);

extern HOOKDEF (void, WINAPI, OutputDebugStringW,
  LPCWSTR lpOutputString
);

extern HOOKDEF(NTSTATUS, WINAPI, NtContinue,
  IN PCONTEXT ThreadContext,
  IN BOOLEAN  RaiseAlert
);
