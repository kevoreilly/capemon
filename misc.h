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

typedef NTSTATUS(WINAPI *_NtQuerySystemInformation)(
	_In_ ULONG SystemInformationClass,
	_Inout_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength);
typedef LONG(WINAPI *_NtQueryInformationProcess)(HANDLE ProcessHandle,
	ULONG ProcessInformationClass, PVOID ProcessInformation,
	ULONG ProcessInformationLength, PULONG ReturnLength);
typedef LONG(WINAPI *_NtSetInformationProcess)(HANDLE ProcessHandle,
	ULONG ProcessInformationClass, PVOID ProcessInformation,
	ULONG ProcessInformationLength);
typedef LONG(WINAPI *_NtQueryInformationThread)(HANDLE ThreadHandle,
	ULONG ThreadInformationClass, PVOID ThreadInformation,
	ULONG ThreadInformationLength, PULONG ReturnLength);
typedef BOOLEAN(WINAPI *_RtlGenRandom)(PVOID RandomBuffer,
	ULONG RandomBufferLength);
typedef NTSTATUS(WINAPI *_NtQueryAttributesFile)(
	_In_   const OBJECT_ATTRIBUTES *ObjectAttributes,
	_Out_  PFILE_BASIC_INFORMATION FileInformation);
typedef NTSTATUS(WINAPI *_NtQueryObject)(
	_In_opt_   HANDLE Handle,
	_In_  OBJECT_INFORMATION_CLASS ObjectInformationClass,
	_Out_opt_  PVOID ObjectInformation,
	_In_   ULONG ObjectInformationLength,
	_Out_opt_   PULONG ReturnLength);
typedef NTSTATUS(WINAPI *_NtQueryKey)(
	HANDLE  KeyHandle,
	int KeyInformationClass,
	PVOID  KeyInformation,
	ULONG  Length,
	PULONG  ResultLength);
typedef NTSTATUS(WINAPI *_NtDelayExecution)(
	BOOLEAN Alertable,
	PLARGE_INTEGER Interval);
typedef NTSTATUS(WINAPI *_NtUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID BaseAddress);
typedef NTSTATUS(WINAPI *_NtMapViewOfSection)(
	_In_	 HANDLE SectionHandle,
	_In_	 HANDLE ProcessHandle,
	__inout  PVOID *BaseAddress,
	_In_	 ULONG_PTR ZeroBits,
	_In_	 SIZE_T CommitSize,
	__inout  PLARGE_INTEGER SectionOffset,
	__inout  PSIZE_T ViewSize,
	__in	 UINT InheritDisposition,
	__in	 ULONG AllocationType,
	__in	 ULONG Win32Protect);
typedef NTSTATUS(WINAPI *_RtlAdjustPrivilege)(
	ULONG Privilege,
	BOOLEAN Enable,
	BOOLEAN CurrentThread,
	PBOOLEAN Enabled);
typedef NTSTATUS(WINAPI *_RtlEqualUnicodeString)(
	const PUNICODE_STRING String1,
	const PUNICODE_STRING String2,
	BOOLEAN CaseInSensitive);
typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
	ULONG Flags;
	const PUNICODE_STRING FullDllName;
	const PUNICODE_STRING BaseDllName;
	PVOID DllBase;
	ULONG SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
	ULONG Flags;
	const PUNICODE_STRING FullDllName;
	const PUNICODE_STRING BaseDllName;
	PVOID DllBase;
	ULONG SizeOfImage;
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
	LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
	LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

typedef VOID (CALLBACK *PLDR_DLL_NOTIFICATION_FUNCTION)(
	_In_	 ULONG					   NotificationReason,
	_In_	 const PLDR_DLL_NOTIFICATION_DATA NotificationData,
	_In_opt_ PVOID					   Context
);

typedef NTSTATUS(WINAPI *_LdrRegisterDllNotification)(
	_In_	 ULONG						  Flags,
	_In_	 PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
	_In_opt_ PVOID						  Context,
	_Out_	PVOID						  *Cookie
);

typedef ULONG(WINAPI *_RtlNtStatusToDosError)(
	NTSTATUS Status
);

typedef void (WINAPI *_CoTaskMemFree)(LPVOID pv);
typedef HRESULT (WINAPI *_ProgIDFromCLSID)(
	_In_  REFCLSID clsid,
	_Out_ LPOLESTR *lplpszProgID
);

_NtSetInformationProcess pNtSetInformationProcess;
_NtMapViewOfSection pNtMapViewOfSection;
_NtUnmapViewOfSection pNtUnmapViewOfSection;
_NtAllocateVirtualMemory pNtAllocateVirtualMemory;
_NtProtectVirtualMemory pNtProtectVirtualMemory;
_NtFreeVirtualMemory pNtFreeVirtualMemory;
_LdrRegisterDllNotification pLdrRegisterDllNotification;
_RtlNtStatusToDosError pRtlNtStatusToDosError;
_RtlAdjustPrivilege pRtlAdjustPrivilege;
void resolve_runtime_apis(void);

DWORD parent_process_id(); // By Napalm @ NetCore2K (rohitab.com)
DWORD pid_from_process_handle(HANDLE process_handle);
DWORD pid_from_thread_handle(HANDLE thread_handle);
DWORD tid_from_thread_handle(HANDLE thread_handle);
DWORD random();
void raw_sleep(int msecs);
DWORD randint(DWORD min, DWORD max);
BOOL is_directory_objattr(const OBJECT_ATTRIBUTES *obj);
BOOL file_exists(const OBJECT_ATTRIBUTES *obj);
void hide_module_from_peb(HMODULE module_handle);
BOOLEAN is_suspended(DWORD pid, DWORD tid);

uint32_t path_from_handle(HANDLE handle,
	wchar_t *path, uint32_t path_buffer_len);

uint32_t path_from_object_attributes(const OBJECT_ATTRIBUTES *obj,
	wchar_t *path, uint32_t buffer_length);

struct {
	wchar_t *hkcu_string;
	unsigned int len;
} g_hkcu;

void hkcu_init(void);

char *ensure_absolute_ascii_path(char *out, const char *in);
wchar_t *ensure_absolute_unicode_path(wchar_t *out, const wchar_t *in);

wchar_t *get_key_path(POBJECT_ATTRIBUTES ObjectAttributes, PKEY_NAME_INFORMATION keybuf, unsigned int len);
wchar_t *get_full_key_pathA(HKEY registry, const char *in, PKEY_NAME_INFORMATION keybuf, unsigned int len);
wchar_t *get_full_key_pathW(HKEY registry, const wchar_t *in, PKEY_NAME_INFORMATION keybuf, unsigned int len);
wchar_t *get_full_keyvalue_pathA(HKEY registry, const char *in, PKEY_NAME_INFORMATION keybuf, unsigned int len);
wchar_t *get_full_keyvalue_pathW(HKEY registry, const wchar_t *in, PKEY_NAME_INFORMATION keybuf, unsigned int len);
wchar_t *get_full_keyvalue_pathUS(HKEY registry, const PUNICODE_STRING in, PKEY_NAME_INFORMATION keybuf, unsigned int len);

int is_shutting_down();

// Define MAX_PATH plus tolerance for windows "tolerance"
#define MAX_PATH_PLUS_TOLERANCE MAX_PATH + 64

#define MAX_KEY_BUFLEN ((16384 + 256) * sizeof(WCHAR))

struct dll_range {
	ULONG_PTR start;
	ULONG_PTR end;
};
#define MAX_DLLS 100

DWORD get_pid_by_tid(DWORD tid);

DWORD our_getprocessid(HANDLE Process);
BOOL is_in_dll_range(ULONG_PTR addr);
void add_all_dlls_to_dll_ranges(void);
void add_dll_range(ULONG_PTR start, ULONG_PTR end);

wchar_t *get_matching_unicode_specialname(const wchar_t *path, unsigned int *matchlen);
void specialname_map_init(void);

char *convert_address_to_dll_name_and_offset(ULONG_PTR addr, unsigned int *offset);
int is_wow64_fs_redirection_disabled(void);

void set_dll_of_interest(ULONG_PTR BaseAddress);

PCHAR get_exe_basename(PCHAR ModulePath);
PWCHAR get_dll_basename(PWCHAR ModulePath);
void register_dll_notification_manually(PLDR_DLL_NOTIFICATION_FUNCTION notify);

extern char *our_process_path;
extern wchar_t *our_process_path_w;
extern wchar_t *our_commandline;

BOOLEAN is_valid_address_range(ULONG_PTR start, DWORD len);

extern ULONG_PTR g_our_dll_base;
extern DWORD g_our_dll_size;

BOOLEAN is_address_in_monitor(ULONG_PTR address);
BOOLEAN is_address_in_ntdll(ULONG_PTR address);
BOOLEAN is_address_in_win32u(ULONG_PTR address);
void num_to_string(char *buf, unsigned int buflen, unsigned int num);

DWORD get_image_size(ULONG_PTR base);

ULONG_PTR get_connectex_addr(HMODULE mod);
ULONG_PTR get_jseval_addr(HMODULE mod);
ULONG_PTR get_cdocument_write_addr(HMODULE mod);
ULONG_PTR get_olescript_compile_addr(HMODULE mod);
ULONG_PTR get_olescript_parsescripttext_addr(HMODULE mod);

BOOL is_bytes_in_buf(PCHAR buf, ULONG len, PCHAR memstr, ULONG memlen, ULONG maxsearchbytes);
void replace_string_in_buf(PCHAR buf, ULONG len, PCHAR findstr, PCHAR repstr);
void replace_wstring_in_buf(PWCHAR buf, ULONG len, PWCHAR findstr, PWCHAR repstr);
void replace_ci_string_in_buf(PCHAR buf, ULONG len, PCHAR findstr, PCHAR repstr);
void replace_ci_wstring_in_buf(PWCHAR buf, ULONG len, PWCHAR findstr, PWCHAR repstr);
void perform_ascii_registry_fakery(PWCHAR keypath, LPVOID Data, ULONG DataLength);
void perform_unicode_registry_fakery(PWCHAR keypath, LPVOID Data, ULONG DataLength);
void perform_device_fakery(PVOID OutputBuffer, ULONG OutputBufferLength, ULONG IoControlCode);
char* stristr(char* haystack, char* needle);
unsigned short our_htons(unsigned short num);
unsigned int our_htonl(unsigned int num);
void addr_to_string(const IN_ADDR addr, char *string);
PUNICODE_STRING get_basename_of_module(HMODULE module_handle);
BOOL loader_lock_held();
void perform_create_time_fakery(FILETIME *createtime);
wchar_t *ascii_to_unicode_dup(char *str);
int is_stack_pivoted(void);

LONG WINAPI capemon_exception_handler(__in struct _EXCEPTION_POINTERS *ExceptionInfo);

BOOLEAN prevent_module_unloading(PVOID BaseAddress);
void prevent_module_reloading(PVOID *BaseAddress);

struct envstruct {
	ULONG k;
	ULONG nullval;
	LPWSTR envstr;
};