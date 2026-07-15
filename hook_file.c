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
//#define DEBUG_COMMENTS
#include <stdio.h>
#include <ctype.h>
#include "ntapi.h"
#include <shlwapi.h>
#include "hooking.h"
#include "log.h"
#include "pipe.h"
#include "misc.h"
#include "ignore.h"
#include "lookup.h"
#include "hook_file.h"
#include "config.h"

#define DUMP_FILE_MASK ((GENERIC_ALL | GENERIC_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | MAXIMUM_ALLOWED) & ~SYNCHRONIZE)

// length of a hardcoded unicode string
#define UNILEN(x) (sizeof(x) / sizeof(wchar_t) - 1)

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);

BOOL files_dumped, dropped_limit_reached;
unsigned int dropped_count;

typedef struct _file_record_t {
	unsigned int attributes;
	size_t length;
	wchar_t filename[0];
} file_record_t;

typedef struct _file_log_t {
	unsigned int read_count;
	unsigned int write_count;
} file_log_t;

static lookup_t g_files;
static lookup_t g_file_logs;

static void new_file(const UNICODE_STRING *obj);

void file_init()
{
	specialname_map_init();

	dropped_count = 0;
	dropped_limit_reached = FALSE;
}

static void add_file_to_log_tracking(HANDLE file_handle)
{
	file_log_t *r = lookup_get(&g_file_logs, (ULONG_PTR)file_handle, NULL);
	if (r == NULL) {
		r = lookup_add(&g_file_logs, (ULONG_PTR)file_handle, sizeof(file_log_t));
#ifdef DEBUG_COMMENTS
		DebugOutput("add_file_to_log_tracking: Adding file handle to tracking: 0x%x", file_handle);
#endif
	}
}

static unsigned int increment_file_log_read_count(HANDLE file_handle)
{
	file_log_t *r = lookup_get(&g_file_logs, (ULONG_PTR)file_handle, NULL);
	if (r != NULL)
		return ++r->read_count;
	return 0;
}

static unsigned int increment_file_log_write_count(HANDLE file_handle)
{
	file_log_t *r = lookup_get(&g_file_logs, (ULONG_PTR)file_handle, NULL);
	if (r != NULL)
		return ++r->write_count;
	return 0;
}

void remove_file_from_log_tracking(HANDLE file_handle)
{
	lookup_del(&g_file_logs, (ULONG_PTR)file_handle);
}

static void new_file_path_ascii(const char *fname)
{
	if (dropped_count >= g_config.dropped_limit) {
		if (!dropped_limit_reached) {
			dropped_limit_reached = TRUE;
			DebugOutput("Dropped file limit reached.");
		}
		return;
	}

	char *absolutename = malloc(32768);
	if (absolutename != NULL) {
		unsigned int len;
		ensure_absolute_ascii_path(absolutename, fname);
		len = (unsigned int)strlen(absolutename);
#ifdef DEBUG_COMMENTS
		DebugOutput("new_file_path_ascii: FILE_NEW %s\n", fname);
#endif
		pipe("FILE_NEW:%d,%s", GetCurrentProcessId(), len, absolutename);
		dropped_count++;
	}
}

static void new_file_path_unicode(const wchar_t *fname)
{
	if (dropped_count >= g_config.dropped_limit) {
		if (!dropped_limit_reached) {
			dropped_limit_reached = TRUE;
			DebugOutput("Dropped file limit reached.");
		}
		return;
	}

	wchar_t *absolutename = malloc(32768 * sizeof(wchar_t));
	if (absolutename != NULL) {
		unsigned int len;
		ensure_absolute_unicode_path(absolutename, fname);
		len = lstrlenW(absolutename);
#ifdef DEBUG_COMMENTS
		DebugOutput("new_file_path_unicode: FILE_NEW %s\n", fname);
#endif
		pipe("FILE_NEW:%d,%S", GetCurrentProcessId(), len, absolutename);
		dropped_count++;
	}
}

static void new_file(const UNICODE_STRING *obj)
{
	if (dropped_count >= g_config.dropped_limit) {
		if (!dropped_limit_reached) {
			dropped_limit_reached = TRUE;
			DebugOutput("Dropped file limit reached.");
		}
		return;
	}

	const wchar_t *str = obj->Buffer;
	unsigned int len = obj->Length / sizeof(wchar_t);

	// maybe it's an absolute path (or a relative path with a harddisk,
	// such as C:abc.txt)
	if (isalpha(str[0]) != 0 && str[1] == ':') {
#ifdef DEBUG_COMMENTS
		//DebugOutput("new_file: FILE_NEW %ws\n", str);
#endif
		pipe("FILE_NEW:%d,%S", GetCurrentProcessId(), len, str);
		dropped_count++;
	}
}

static void cache_file(HANDLE file_handle, const wchar_t *path, unsigned int length_in_chars, unsigned int attributes)
{
	file_record_t *r;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	r = lookup_get(&g_files, (ULONG_PTR)file_handle, NULL);
	if (r == NULL) {
		r = lookup_add(&g_files, (ULONG_PTR)file_handle, sizeof(file_record_t) + length_in_chars * sizeof(wchar_t) + sizeof(wchar_t));

		memset(r, 0, sizeof(*r));
		r->attributes = attributes;
		r->length = length_in_chars;

		wcsncpy(r->filename, path, r->length + 1);
#ifdef DEBUG_COMMENTS
		DebugOutput("cache_file: Adding file handle to tracking: 0x%x, %ws", file_handle, path);
#endif
	}

	set_lasterrors(&lasterror);
}

void file_write(HANDLE file_handle)
{
	file_record_t *r;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	r = lookup_get(&g_files, (ULONG_PTR)file_handle, NULL);
	if (r == NULL) {
		r = lookup_add(&g_files, (ULONG_PTR)file_handle, sizeof(file_record_t));
#ifdef DEBUG_COMMENTS
		DebugOutput("file_write: Adding file handle to tracking: 0x%x", file_handle);
#endif
	}
#ifdef DEBUG_COMMENTS
	else
		DebugOutput("file_write: File handle already tracked: 0x%x", file_handle);
#endif

	set_lasterrors(&lasterror);
}

static void check_for_logging_resumption(const OBJECT_ATTRIBUTES *obj)
{
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	if (g_config.file_of_interest && g_config.suspend_logging) {
		wchar_t *fname = calloc(1, 32768 * sizeof(wchar_t));
		wchar_t *absolutename = malloc(32768 * sizeof(wchar_t));
		BOOLEAN ret = FALSE;

		path_from_object_attributes(obj, fname, 32768);

		ensure_absolute_unicode_path(absolutename, fname);

		if (!wcsicmp(absolutename, g_config.file_of_interest))
			g_config.suspend_logging = FALSE;

		free(absolutename);
		free(fname);
	}

	set_lasterrors(&lasterror);
}

static void handle_new_file(HANDLE file_handle, const OBJECT_ATTRIBUTES *obj)
{
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	if (is_directory_objattr(obj) == 0) {

		wchar_t *fname = calloc(32768, sizeof(wchar_t));
		wchar_t *absolutename = calloc(32768, sizeof(wchar_t));

		path_from_object_attributes(obj, fname, 32768);

		if (absolutename != NULL) {
			unsigned int len;
			ensure_absolute_unicode_path(absolutename, fname);
			len = lstrlenW(absolutename);
			// cache this file
			if (is_ignored_file_unicode(absolutename, len) == 0)
				cache_file(file_handle, absolutename, len, obj->Attributes);
			free(absolutename);
		}
		else {
			if (is_ignored_file_objattr(obj) == 0)
				cache_file(file_handle, fname, lstrlenW(fname), obj->Attributes);
		}
		free(fname);
	}

	set_lasterrors(&lasterror);
}

// XXX: if we ever track entries which contain pointers themselves that use runtime allocation
// this needs to be rewritten, sufficient for now for file_log_t and file_record_t
static void __handle_duplicate(lookup_t *d, HANDLE old_handle, HANDLE new_handle)
{
	unsigned int size;
	void *rdata;

	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	rdata = lookup_get(d, (ULONG_PTR)old_handle, &size);
	if (rdata) {
		void *data = lookup_add(d, (ULONG_PTR)new_handle, size);
		if (data)
			memcpy(data, rdata, size);
	}

	set_lasterrors(&lasterror);
}

void handle_duplicate(HANDLE old_handle, HANDLE new_handle)
{
	__handle_duplicate(&g_file_logs, old_handle, new_handle);
	__handle_duplicate(&g_files, old_handle, new_handle);
}

void file_close(HANDLE file_handle)
{
	lasterror_t lasterror;
	file_record_t *r;

	get_lasterrors(&lasterror);

	r = lookup_get(&g_files, (ULONG_PTR)file_handle, NULL);
	if (r != NULL) {
		UNICODE_STRING str;
		str.Length = (USHORT)r->length * sizeof(wchar_t);
		str.MaximumLength = ((USHORT)r->length + 1) * sizeof(wchar_t);
		str.Buffer = r->filename;
		new_file(&str);
		lookup_del(&g_files, (ULONG_PTR) file_handle);
#ifdef DEBUG_COMMENTS
		DebugOutput("file_close: Closing tracked file handle: 0x%x", file_handle);
#endif
	}

	set_lasterrors(&lasterror);
}

void file_handle_terminate()
{
	entry_t *p;
	file_record_t *r;
	lasterror_t lasterror;

	// ensure this only happens once as we can't lookup_del in the loop
	if (files_dumped)
		return;

	get_lasterrors(&lasterror);

	for (p = (entry_t*)&(g_files.root); p != NULL; p = p->next) {
		if (p->id) {
			r = lookup_get(&g_files, (ULONG_PTR)p->id, NULL);
			if (r != NULL) {
				UNICODE_STRING str;
				str.Length = (USHORT)r->length * sizeof(wchar_t);
				str.MaximumLength = ((USHORT)r->length + 1) * sizeof(wchar_t);
				str.Buffer = r->filename;
#ifdef DEBUG_COMMENTS
				//DebugOutput("file_handle_terminate: new_file %ws", r->filename);
#endif
				new_file(&str);
			}
		}
	}

	files_dumped = TRUE;

#ifdef DEBUG_COMMENTS
	DebugOutput("file_handle_terminate complete");
#endif
	set_lasterrors(&lasterror);
}

static BOOLEAN is_protected_objattr(POBJECT_ATTRIBUTES obj)
{
	if (!wcslen(g_config.w_analyzer))
		return FALSE;
	wchar_t path[MAX_PATH_PLUS_TOLERANCE];
	wchar_t *absolutepath = malloc(32768 * sizeof(wchar_t));
	if (absolutepath) {
		path_from_object_attributes(obj, path, MAX_PATH_PLUS_TOLERANCE);
		ensure_absolute_unicode_path(absolutepath, path);
		if (!wcsnicmp(g_config.w_analyzer, absolutepath, wcslen(g_config.w_analyzer))) {
			lasterror_t lasterror;
			lasterror.NtstatusError = STATUS_ACCESS_DENIED;
			lasterror.Win32Error = ERROR_ACCESS_DENIED;
			lasterror.Eflags = 0;
			free(absolutepath);
			set_lasterrors(&lasterror);
			return TRUE;
		}
		free(absolutepath);
	}
	return FALSE;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateFile,
	__out		PHANDLE FileHandle,
	__in		ACCESS_MASK DesiredAccess,
	__in		POBJECT_ATTRIBUTES ObjectAttributes,
	__out		PIO_STATUS_BLOCK IoStatusBlock,
	__in_opt	PLARGE_INTEGER AllocationSize,
	__in		ULONG FileAttributes,
	__in		ULONG ShareAccess,
	__in		ULONG CreateDisposition,
	__in		ULONG CreateOptions,
	__in		PVOID EaBuffer,
	__in		ULONG EaLength
) {
	NTSTATUS ret;
	BOOL file_existed;
	check_for_logging_resumption(ObjectAttributes);

	if (is_protected_objattr(ObjectAttributes))
		return STATUS_ACCESS_DENIED;

	file_existed = file_exists(ObjectAttributes);

	ret = Old_NtCreateFile(FileHandle, DesiredAccess,
		ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
		ShareAccess | FILE_SHARE_READ, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	LOQ_ntstatus("filesystem", "PhOiihss", "FileHandle", FileHandle, "DesiredAccess", DesiredAccess,
		"FileName", ObjectAttributes, "CreateDisposition", CreateDisposition,
		"ShareAccess", ShareAccess, "FileAttributes", FileAttributes, "ExistedBefore", file_existed ? "yes" : "no", "StackPivoted", is_stack_pivoted() ? "yes" : "no");
	if (NT_SUCCESS(ret)) {
		if ((DesiredAccess & DUMP_FILE_MASK) && !(FileAttributes & FILE_ATTRIBUTE_TEMPORARY))
			handle_new_file(*FileHandle, ObjectAttributes);
		add_file_to_log_tracking(*FileHandle);
	}
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenFile,
	__out  PHANDLE FileHandle,
	__in   ACCESS_MASK DesiredAccess,
	__in   POBJECT_ATTRIBUTES ObjectAttributes,
	__out  PIO_STATUS_BLOCK IoStatusBlock,
	__in   ULONG ShareAccess,
	__in   ULONG OpenOptions
) {
	NTSTATUS ret;

	check_for_logging_resumption(ObjectAttributes);

	if (is_protected_objattr(ObjectAttributes))
		return STATUS_ACCESS_DENIED;

	ret = Old_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
						IoStatusBlock, ShareAccess | FILE_SHARE_READ, OpenOptions);

	LOQ_ntstatus("filesystem", "PhOi", "FileHandle", FileHandle, "DesiredAccess", DesiredAccess,
				"FileName", ObjectAttributes, "ShareAccess", ShareAccess);

	if (NT_SUCCESS(ret)) {
		add_file_to_log_tracking(*FileHandle);
		if (DesiredAccess & DUMP_FILE_MASK)
			handle_new_file(*FileHandle, ObjectAttributes);
	}

	return ret;
}

static HANDLE LastFileHandle;
static ULONG AccumulatedLength;
CRITICAL_SECTION readfile_critsec;
static PVOID InitialBuffer;
static SIZE_T InitialBufferLength;

HOOKDEF(NTSTATUS, WINAPI, NtReadFile,
	__in	  HANDLE FileHandle,
	__in_opt  HANDLE Event,
	__in_opt  PIO_APC_ROUTINE ApcRoutine,
	__in_opt  PVOID ApcContext,
	__out	 PIO_STATUS_BLOCK IoStatusBlock,
	__out	 PVOID Buffer,
	__in	  ULONG Length,
	__in_opt  PLARGE_INTEGER ByteOffset,
	__in_opt  PULONG Key
	) {
	NTSTATUS ret = Old_NtReadFile(FileHandle, Event, ApcRoutine, ApcContext,
		IoStatusBlock, Buffer, Length, ByteOffset, Key);
	wchar_t *fname;
	BOOLEAN deletelast;
	unsigned int read_count = 0;
	ULONG_PTR length;
	lasterror_t lasterrors;

	get_lasterrors(&lasterrors);

	if (NT_SUCCESS(ret))
		length = IoStatusBlock->Information;
	else
		length = 0;

	if (get_last_api() == API_NTREADFILE && FileHandle == LastFileHandle) {
		// can overflow, but we don't care much
		AccumulatedLength += (ULONG)length;
		deletelast = TRUE;
	}
	else {
		PVOID prev;
		SIZE_T len = min(length, (unsigned int)buffer_log_max);
		PVOID newbuf;

		EnterCriticalSection(&readfile_critsec);
		newbuf = malloc(len);
		memcpy(newbuf, Buffer, len);
		prev = InitialBuffer;
		InitialBuffer = newbuf;
		if (prev)
			free(prev);
		LastFileHandle = FileHandle;
		AccumulatedLength = (ULONG)length;
		InitialBufferLength = len;
		LeaveCriticalSection(&readfile_critsec);

		deletelast = FALSE;

		read_count = increment_file_log_read_count(FileHandle);
	}

	set_special_api(API_NTREADFILE, deletelast);

	if (read_count <= 50) {
		fname = calloc(32768, sizeof(wchar_t));
		path_from_handle(FileHandle, fname, 32768);

		if (!g_config.no_stealth && g_config.ntdll_unhook && InitialBufferLength)
			prevent_module_unhooking(Buffer, fname);

		if (read_count < 50)
			LOQ_ntstatus("filesystem", "pFbl", "FileHandle", FileHandle,
				"HandleName", fname, "Buffer", InitialBufferLength, InitialBuffer, "Length", AccumulatedLength);
		else
			LOQ_ntstatus("filesystem", "pFbls", "FileHandle", FileHandle,
				"HandleName", fname, "Buffer", InitialBufferLength, InitialBuffer, "Length", AccumulatedLength, "Status", "Maximum logged reads reached for this file");

		free(fname);
	}

	set_lasterrors(&lasterrors);

	return ret;
}

// copied from misc.c to avoid clash with libyara\include\yara\strutils.h
static PCHAR memmem(PCHAR haystack, ULONG hlen, PCHAR needle, ULONG nlen)
{
	if (nlen > hlen)
		return NULL;

	ULONG i;
	for (i = 0; i < hlen - nlen + 1; i++) {
		if (!memcmp(haystack + i, needle, nlen))
			return haystack + i;
	}

	return NULL;
}

HOOKDEF(NTSTATUS, WINAPI, NtWriteFile,
	__in	  HANDLE FileHandle,
	__in_opt  HANDLE Event,
	__in_opt  PIO_APC_ROUTINE ApcRoutine,
	__in_opt  PVOID ApcContext,
	__out	 PIO_STATUS_BLOCK IoStatusBlock,
	__in	  PVOID Buffer,
	__in	  ULONG Length,
	__in_opt  PLARGE_INTEGER ByteOffset,
	__in_opt  PULONG Key
) {
	NTSTATUS ret = Old_NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);

	ULONG_PTR length = 0;

	if (NT_SUCCESS(ret))
		length = IoStatusBlock->Information;

	unsigned int write_count = increment_file_log_write_count(FileHandle);

	if (write_count <= 50) {
		if (FileHandle && FileHandle != INVALID_HANDLE_VALUE) {
			wchar_t *fname = calloc(32768, sizeof(wchar_t));
			path_from_handle(FileHandle, fname, 32768);

			// Inject into services.exe if we detect a raw RPC request to ntsvcs (e.g. CreateSvcRpc)
			if (length >= 32 && fname && !wcsicmp(fname, L"\\Device\\NamedPipe\\ntsvcs")) {
				// SCM UUID: 367abb81-9844-35f1-ad32-98f038001003
				unsigned char scm_uuid[] = {0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35, 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03};
				// NDR UUID: 8a885d04-1ceb-11c9-9fe8-08002b104860
				unsigned char ndr_uuid[] = {0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60};

				if (memmem((PCHAR)Buffer, (ULONG)length, (PCHAR)scm_uuid, sizeof(scm_uuid)) && memmem((PCHAR)Buffer, (ULONG)length, (PCHAR)ndr_uuid, sizeof(ndr_uuid))) {
					pipe("SERVICE:");
					raw_sleep(1000);
				}
			}

			if (write_count < 50) {
				LOQ_ntstatus("filesystem", "pFbl", "FileHandle", FileHandle,
					"HandleName", fname, "Buffer", length, Buffer, "Length", length);
			}
			else if (write_count == 50) {
				LOQ_ntstatus("filesystem", "pFbls", "FileHandle", FileHandle,
					"HandleName", fname, "Buffer", length, Buffer, "Length", length, "Status", "Maximum logged writes reached for this file");
			}

			free(fname);
		}
		else {
			LOQ_ntstatus("filesystem", "pl", "FileHandle", FileHandle, "Length", length);
		}
	}

	if (NT_SUCCESS(ret))
		file_write(FileHandle);

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtDeleteFile,
	__in  POBJECT_ATTRIBUTES ObjectAttributes
) {
	wchar_t path[MAX_PATH_PLUS_TOLERANCE];
	wchar_t *absolutepath = malloc(32768 * sizeof(wchar_t));
	NTSTATUS ret;

	path_from_object_attributes(ObjectAttributes, path, MAX_PATH_PLUS_TOLERANCE);
	ensure_absolute_unicode_path(absolutepath, path);

	if (dropped_count < g_config.dropped_limit) {
#ifdef DEBUG_COMMENTS
		DebugOutput("NtDeleteFile: FILE_DEL %ws\n", absolutepath);
#endif
		pipe("FILE_DEL:%d,%Z", GetCurrentProcessId(), absolutepath);
		dropped_count++;
	}

	ret = Old_NtDeleteFile(ObjectAttributes);
	LOQ_ntstatus("filesystem", "u", "FileName", absolutepath);

	free(absolutepath);

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtDeviceIoControlFile,
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
) {
	lasterror_t lasterrors;
	get_lasterrors(&lasterrors);
	ULONG_PTR length;
	ULONG origbufferloglen = min((ULONG)buffer_log_max, InputBufferLength);
	PCHAR origbuffer = malloc(origbufferloglen);
	BOOLEAN hasorigbuffer = FALSE;
	NTSTATUS ret;

	// Save off a copy of the buffer before calling the hook, as it may not be the same after the call
	if (origbuffer) {
		__try {
			memcpy(origbuffer, InputBuffer, origbufferloglen);
			hasorigbuffer = TRUE;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			hasorigbuffer = FALSE;
		}
	}


	/*
	* Check for AFD_SEND, we need to aggregate the buffer before calling the hook as calling the hook will clobber InputBuffer
	* Simply do the logic to generate the buffer we want to log here, we'll log it later with other IOCTL logging.
	*/
	PCHAR aggregated_send_payload = NULL;
	ULONG send_payload_size_to_log = 0;
	if (IoControlCode == IOCTL_AFD_SEND) {
		__try {
			if (InputBuffer && InputBufferLength >= sizeof(AFD_SEND_INFO)) {
				PAFD_SEND_INFO sendInfo = (PAFD_SEND_INFO)InputBuffer;
				if (sendInfo->AfdBufferArray && sendInfo->AfdBufferCount > 0) {
					ULONG total_send_size = 0;
					for (ULONG i = 0; i < sendInfo->AfdBufferCount; i++) {
						total_send_size += sendInfo->AfdBufferArray[i].len;
					}

					if (total_send_size > 0) {
						send_payload_size_to_log = min((ULONG)buffer_log_max, total_send_size);
						aggregated_send_payload = (PCHAR)malloc(send_payload_size_to_log);
						if (aggregated_send_payload) {
							PCHAR current_pos = aggregated_send_payload;
							ULONG bytes_copied = 0;
							for (ULONG i = 0; i < sendInfo->AfdBufferCount && bytes_copied < send_payload_size_to_log; i++) {
								PAFD_WSABUF current_source_buf = &sendInfo->AfdBufferArray[i];
								ULONG bytes_to_copy = min(current_source_buf->len, send_payload_size_to_log - bytes_copied);
								if (bytes_to_copy > 0) {
									memcpy(current_pos, current_source_buf->buf, bytes_to_copy);
									current_pos += bytes_to_copy;
									bytes_copied += bytes_to_copy;
								}
							}
						}
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			// On exception, null out the buffer (if needed) so we can log generically later
			if (aggregated_send_payload) {
				free(aggregated_send_payload);
				aggregated_send_payload = NULL;
			}
		}
	}
	set_lasterrors(&lasterrors);

	ret = Old_NtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength,
		OutputBuffer, OutputBufferLength);

	if (NT_SUCCESS(ret))
		length = IoStatusBlock->Information;
	else
		length = 0;


	get_lasterrors(&lasterrors);

	wchar_t* fname = NULL;
	fname = calloc(32768, sizeof(wchar_t));
	if (fname) {
		path_from_handle(FileHandle, fname, 32768);
	}

	switch (IoControlCode) {
	case IOCTL_AFD_BIND:
		if (InputBufferLength >= sizeof(AFD_BindDataStruct) && hasorigbuffer) {
			PAFD_BindDataStruct buf = (PAFD_BindDataStruct)origbuffer;
			__try {
				in_sockaddr* sockAddr = &buf->SockAddr;
				char ipString[16];
				our_inet_ntop(AF_INET, &sockAddr->sin_addr, ipString, sizeof(ipString));
				unsigned short port = our_ntohs(sockAddr->sin_port);
				LOQ_ntstatus(
					"network", "pFhsi",
					"FileHandle", FileHandle,
					"HandleName", fname,
					"IoControlCode", IoControlCode,
					"ip", ipString,
					"port", port
				);
				break;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				// If we're here, just use generic logging for NtDeviceIoControlFile
				goto generic_log;
			}
		}
		else {
			goto generic_log;
		}

	case IOCTL_AFD_CONNECT:
		if (InputBufferLength >= sizeof(AFD_ConnectDataStruct) && hasorigbuffer) {
			AFD_ConnectDataStruct* buf = (AFD_ConnectDataStruct*)origbuffer;
			__try {
				in_sockaddr* sockAddr = &buf->SockAddr;
				char ipString[16];
				our_inet_ntop(AF_INET, &sockAddr->sin_addr, ipString, sizeof(ipString));
				unsigned short port = our_ntohs(sockAddr->sin_port);
				LOQ_ntstatus(
					"network", "pFhsi",
					"FileHandle", FileHandle,
					"HandleName", fname,
					"IoControlCode", IoControlCode,
					"ip", ipString,
					"port", port
				);
				break;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				// If we're here, just use generic logging for NtDeviceIoControlFile
				goto generic_log;
			}
		}
		else {
			// Unexpected InputBufferLength for this IOCTL, goto generic log
			goto generic_log;
		}

	case IOCTL_AFD_RECV:
		__try {
			DWORD wait_status = -1;  // Init to -1 as WAIT_OBJECT_0 is 0
			if (InputBuffer && InputBufferLength >= sizeof(AFD_RECV_INFO)) {
				if (ret == STATUS_PENDING && Event) {
					/*
					 * We make some assumptions here; If we have an event it is an async call so we also assume:
					 *  1) The callee reset the event prior to calling this NtDeviceIoControlFile API
					 *  2) The callee will use NtWaitForSingleObject or similar, after calling NtDeviceIoControlFile
					 *
					 * NtWaitForSingleObject will wait on a handle, and if the callee is expecting to use NtWaitForSingleObject
					 * (as done in NTSockets) we'll end up deadlocking unless we also use SetEvent. This is why we use our own
					 * function to check for the event being signaled as it we do not call any APIs which interfere with the
					 * status of the event itself, so it is safe for the above assumptions as well as cases where the assumption
					 * may be wrong.
					*/
					wait_status = wait_for_event_to_be_signaled(Event, 5000);  // Allow 5 seconds of time for the event to trigger
					if (wait_status == WAIT_OBJECT_0) {
						ret = IoStatusBlock->Status;
						if (NT_SUCCESS(ret))
							length = IoStatusBlock->Information;
						else
							length = 0;
					}
				}
				if (length == 0) {
					/*
					* This can happen if we have a NTSTATUS of 0x00000103 (STATUS_PENDING)
					* Unideal, likely in the background kernel has provided the recv buffer to the API
					*/
					if (wait_status == WAIT_TIMEOUT) {
						LOQ_ntstatus(
							"network", "pFhs",
							"FileHandle", FileHandle,
							"HandleName", fname,
							"IoControlCode", IoControlCode,
							"Event", "Timeout waiting for recv, buffer will likely missing from API logs"
						);
					}
					else {
						LOQ_ntstatus(
							"network", "pFhs",
							"FileHandle", FileHandle,
							"HandleName", fname,
							"IoControlCode", IoControlCode,
							"Event", "Zero-byte receive"
						);
					}
					break;
				}

				PAFD_RECV_INFO recvInfo = (PAFD_RECV_INFO)InputBuffer;
				if (recvInfo->AfdBufferArray && recvInfo->AfdBufferCount > 0) {
					ULONG total_payload_to_log = min((ULONG)buffer_log_max, (ULONG)length);
					PCHAR aggregated_payload = (PCHAR)malloc(total_payload_to_log);
					if (!aggregated_payload) {
						// Sanity check
						goto generic_log;
					}

					PCHAR current_pos = aggregated_payload;
					ULONG bytes_copied = 0;
					ULONG bytes_remaining_from_total = (ULONG)length;
					for (ULONG i = 0; i < recvInfo->AfdBufferCount && bytes_copied < total_payload_to_log; i++) {
						PAFD_WSABUF current_source_buf = &recvInfo->AfdBufferArray[i];
						ULONG bytes_in_source = min(bytes_remaining_from_total, current_source_buf->len);
						ULONG bytes_to_copy = min(bytes_in_source, total_payload_to_log - bytes_copied);
						if (bytes_to_copy > 0) {
							memcpy(current_pos, current_source_buf->buf, bytes_to_copy);
							current_pos += bytes_to_copy;
							bytes_copied += bytes_to_copy;
						}
						bytes_remaining_from_total -= bytes_in_source;
					}

					LOQ_ntstatus(
						"network", "pFhbi",
						"FileHandle", FileHandle,
						"HandleName", fname,
						"IoControlCode", IoControlCode,
						"buffer", (size_t)bytes_copied, aggregated_payload,
						"length", length
					);
					free(aggregated_payload);
					break;
				}
			}
			else {
				// If the initial InputBuffer validation fails, go to the generic logger.
				goto generic_log;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			// On exception, log generically
			goto generic_log;
		}

	case IOCTL_AFD_SEND:
		// We parsed the send buffer prior to calling the hook, if the buffer is non-null, log it, otherwise log generically
		if (aggregated_send_payload) {
			LOQ_ntstatus(
				"network", "pFhbi",
				"FileHandle", FileHandle,
				"HandleName", fname,
				"IoControlCode", IoControlCode,
				"buffer", (size_t)send_payload_size_to_log, aggregated_send_payload,
				"length", (ULONG)length // Log the actual bytes sent from the result
			);
			free(aggregated_send_payload);
			break;
		}
		else {
			goto generic_log;
		}
	default:
	generic_log:
		if (fname) {
			LOQ_ntstatus(
				"device", "pFhbb",
				"FileHandle", FileHandle,
				"HandleName", fname,
				"IoControlCode", IoControlCode,
				"InputBuffer", InputBufferLength, InputBuffer,
				"OutputBuffer", length, OutputBuffer
			);
		}
		else {
			LOQ_ntstatus(
				"device", "phbb",
				"FileHandle", FileHandle,
				"IoControlCode", IoControlCode,
				"InputBuffer", InputBufferLength, InputBuffer,
				"OutputBuffer", length, OutputBuffer
			);
		}
	}

	if (!g_config.no_stealth && NT_SUCCESS(ret) && OutputBuffer)
		perform_device_fakery(OutputBuffer, (ULONG)length, IoControlCode);

	if (origbuffer)
		free(origbuffer);

	if (fname)
		free(fname);

	set_lasterrors(&lasterrors);

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryDirectoryFile,
	__in	  HANDLE FileHandle,
	__in_opt  HANDLE Event,
	__in_opt  PIO_APC_ROUTINE ApcRoutine,
	__in_opt  PVOID ApcContext,
	__out	 PIO_STATUS_BLOCK IoStatusBlock,
	__out	 PVOID FileInformation,
	__in	  ULONG Length,
	__in	  FILE_INFORMATION_CLASS FileInformationClass,
	__in	  BOOLEAN ReturnSingleEntry,
	__in_opt  PUNICODE_STRING FileName,
	__in	  BOOLEAN RestartScan
) {
	OBJECT_ATTRIBUTES objattr;
	NTSTATUS ret;
	ULONG_PTR length;

	memset(&objattr, 0, sizeof(objattr));
	objattr.ObjectName = FileName;
	objattr.RootDirectory = FileHandle;

	ret = Old_NtQueryDirectoryFile(FileHandle, Event,
		ApcRoutine, ApcContext, IoStatusBlock, FileInformation,
		Length, FileInformationClass, ReturnSingleEntry,
		FileName, RestartScan);

	if (NT_SUCCESS(ret))
		length = IoStatusBlock->Information;
	else
		length = 0;

	/* don't log the resulting buffer, otherwise we can't turn these calls into simple duplicates */
	if (FileInformationClass == FileNamesInformation) {
		LOQ_ntstatus("filesystem", "pOi", "FileHandle", FileHandle,
			"FileName", &objattr, "FileInformationClass", FileInformationClass);
	}
	else {
		LOQ_ntstatus("filesystem", "pbOi", "FileHandle", FileHandle,
			"FileInformation", length, FileInformation,
			"FileName", &objattr, "FileInformationClass", FileInformationClass);
	}
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryInformationFile,
	__in   HANDLE FileHandle,
	__out  PIO_STATUS_BLOCK IoStatusBlock,
	__out  PVOID FileInformation,
	__in   ULONG Length,
	__in   FILE_INFORMATION_CLASS FileInformationClass
) {
	wchar_t *fname = calloc(32768, sizeof(wchar_t));
	wchar_t *absolutepath = calloc(32768, sizeof(wchar_t));
	NTSTATUS ret;
	ULONG_PTR length;

	path_from_handle(FileHandle, fname, 32768);
	ensure_absolute_unicode_path(absolutepath, fname);

	ret = Old_NtQueryInformationFile(FileHandle, IoStatusBlock,
		FileInformation, Length, FileInformationClass);

	if (NT_SUCCESS(ret))
		length = IoStatusBlock->Information;
	else
		length = 0;

	LOQ_ntstatus("filesystem", "puib", "FileHandle", FileHandle, "HandleName", absolutepath, "FileInformationClass", FileInformationClass,
		"FileInformation", length, FileInformation);

	free(fname);
	free(absolutepath);

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryVolumeInformationFile,
	__in   HANDLE FileHandle,
	__out  PIO_STATUS_BLOCK IoStatusBlock,
	__out  PVOID FsInformation,
	__in   ULONG Length,
	__in   FS_INFORMATION_CLASS FsInformationClass
) {
	NTSTATUS ret = Old_NtQueryVolumeInformationFile
	(
		FileHandle,
		IoStatusBlock,
		FsInformation,
		Length,
		FsInformationClass
	);
	LOQ_ntstatus("filesystem", "pib", "FileHandle", FileHandle, "FsInformationClass", FsInformationClass,
		"FsInformation", IoStatusBlock->Information, FsInformation);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryAttributesFile,
	__in   POBJECT_ATTRIBUTES ObjectAttributes,
	__out  PFILE_BASIC_INFORMATION FileInformation
) {
	NTSTATUS ret = Old_NtQueryAttributesFile(ObjectAttributes, FileInformation);
	if (ObjectAttributes)
		LOQ_ntstatus("filesystem", "O", "FileName", ObjectAttributes);
	else
		LOQ_ntstatus("filesystem", "");
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryFullAttributesFile,
	__in   POBJECT_ATTRIBUTES ObjectAttributes,
	__out  PFILE_NETWORK_OPEN_INFORMATION FileInformation
) {
	NTSTATUS ret = Old_NtQueryFullAttributesFile(ObjectAttributes, FileInformation);
	LOQ_ntstatus("filesystem", "O", "FileName", ObjectAttributes);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtSetInformationFile,
	__in   HANDLE FileHandle,
	__out  PIO_STATUS_BLOCK IoStatusBlock,
	__in   PVOID FileInformation,
	__in   ULONG Length,
	__in   FILE_INFORMATION_CLASS FileInformationClass
) {
	wchar_t *fname = calloc(32768, sizeof(wchar_t));
	wchar_t *absolutepath = calloc(32768, sizeof(wchar_t));
	wchar_t *renamepath = calloc(32768, sizeof(wchar_t));
	NTSTATUS ret;

	path_from_handle(FileHandle, fname, 32768);
	ensure_absolute_unicode_path(absolutepath, fname);

	if (FileInformation != NULL && Length == sizeof(BOOLEAN) &&
			FileInformationClass == FileDispositionInformation &&
			dropped_count < g_config.dropped_limit &&
			*(BOOLEAN *) FileInformation != FALSE) {
#ifdef DEBUG_COMMENTS
		DebugOutput("NtSetInformationFile: FILE_DEL %ws\n", absolutepath);
#endif
		pipe("FILE_DEL:%d,%Z", GetCurrentProcessId(), absolutepath);
		dropped_count++;
	}

	if (FileInformation != NULL && FileInformationClass == FileRenameInformation) {
		wcsncpy(fname, ((FILE_RENAME_INFORMATION*)FileInformation)->FileName, ((FILE_RENAME_INFORMATION*)FileInformation)->FileNameLength/sizeof(WCHAR));
		wcsncpy(fname + ((FILE_RENAME_INFORMATION*)FileInformation)->FileNameLength/sizeof(WCHAR), L"\0", 1);
		ensure_absolute_unicode_path(renamepath, fname);
	}

	ret = Old_NtSetInformationFile(FileHandle, IoStatusBlock,
		FileInformation, Length, FileInformationClass);

	if (FileInformation != NULL && FileInformationClass == FileRenameInformation) {
		if (NT_SUCCESS(ret) && dropped_count < g_config.dropped_limit) {
#ifdef DEBUG_COMMENTS
			DebugOutput("NtSetInformationFile: FILE_MOVE %ws::%ws\n", absolutepath, renamepath);
#endif
			pipe("FILE_MOVE:%d,%Z::%Z", GetCurrentProcessId(), absolutepath, renamepath);
			dropped_count++;
		}
		LOQ_ntstatus("filesystem", "puiu", "FileHandle", FileHandle, "HandleName", absolutepath, "FileInformationClass", FileInformationClass,
		"FileName", renamepath);
	}
	else
		LOQ_ntstatus("filesystem", "puib", "FileHandle", FileHandle, "HandleName", absolutepath, "FileInformationClass", FileInformationClass,
		"FileInformation", Length, FileInformation);

	free(fname);
	free(absolutepath);
	free(renamepath);

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenDirectoryObject,
	__out  PHANDLE DirectoryHandle,
	__in   ACCESS_MASK DesiredAccess,
	__in   POBJECT_ATTRIBUTES ObjectAttributes
) {
	NTSTATUS ret = Old_NtOpenDirectoryObject(DirectoryHandle, DesiredAccess,
		ObjectAttributes);
	LOQ_ntstatus("filesystem", "PhO", "DirectoryHandle", DirectoryHandle,
		"DesiredAccess", DesiredAccess, "ObjectAttributes", ObjectAttributes);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateDirectoryObject,
	__out  PHANDLE DirectoryHandle,
	__in   ACCESS_MASK DesiredAccess,
	__in   POBJECT_ATTRIBUTES ObjectAttributes
) {
	NTSTATUS ret = Old_NtCreateDirectoryObject(DirectoryHandle, DesiredAccess,
		ObjectAttributes);
	LOQ_ntstatus("filesystem", "PhO", "DirectoryHandle", DirectoryHandle,
		"DesiredAccess", DesiredAccess, "ObjectAttributes", ObjectAttributes);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryDirectoryObject,
  __in	   HANDLE DirectoryHandle,
  __out_opt  PVOID Buffer,
  __in	   ULONG Length,
  __in	   BOOLEAN ReturnSingleEntry,
  __in	   BOOLEAN RestartScan,
  __inout	PULONG Context,
  __out_opt  PULONG ReturnLength
) {
	NTSTATUS ret = Old_NtQueryDirectoryObject(DirectoryHandle, Buffer, Length,
		ReturnSingleEntry, RestartScan, Context, ReturnLength);
	// Don't log STATUS_BUFFER_TOO_SMALL
	if (ret != 0xC0000023)
		LOQ_ntstatus("filesystem", "p", "DirectoryHandle", DirectoryHandle);

	return ret;
}

HOOKDEF(BOOL, WINAPI, CreateDirectoryW,
	__in	  LPWSTR lpPathName,
	__in_opt  LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
	BOOL ret = Old_CreateDirectoryW(lpPathName, lpSecurityAttributes);
	LOQ_bool("filesystem", "F", "DirectoryName", lpPathName);
	return ret;
}

HOOKDEF(BOOL, WINAPI, CreateDirectoryExW,
	__in	  LPWSTR lpTemplateDirectory,
	__in	  LPWSTR lpNewDirectory,
	__in_opt  LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
	BOOL ret = Old_CreateDirectoryExW(lpTemplateDirectory, lpNewDirectory,
		lpSecurityAttributes);
	LOQ_bool("filesystem", "F", "DirectoryName", lpNewDirectory);
	return ret;
}

HOOKDEF(BOOL, WINAPI, RemoveDirectoryA,
	__in  LPCSTR lpPathName
) {
	char path[MAX_PATH];
	BOOL ret;

	ensure_absolute_ascii_path(path, lpPathName);

	ret = Old_RemoveDirectoryA(lpPathName);
	LOQ_bool("filesystem", "s", "DirectoryName", path);

	return ret;
}

HOOKDEF(BOOL, WINAPI, RemoveDirectoryW,
	__in  LPWSTR lpPathName
) {
	wchar_t *path = malloc(32768 * sizeof(wchar_t));
	BOOL ret;

	ensure_absolute_unicode_path(path, lpPathName);

	ret = Old_RemoveDirectoryW(lpPathName);
	LOQ_bool("filesystem", "u", "DirectoryName", path);

	free(path);

	return ret;
}

HOOKDEF_NOTAIL(WINAPI, MoveFileWithProgressW,
	__in	  LPWSTR lpExistingFileName,
	__in_opt  LPWSTR lpNewFileName,
	__in_opt  LPPROGRESS_ROUTINE lpProgressRoutine,
	__in_opt  LPVOID lpData,
	__in	  DWORD dwFlags
) {
	BOOL ret = TRUE;

	if (lpProgressRoutine) {
		wchar_t *path = malloc(32768 * sizeof(wchar_t));
		ensure_absolute_unicode_path(path, lpExistingFileName);
		LOQ_bool("filesystem", "uFh", "ExistingFileName", path,
			"NewFileName", lpNewFileName, "Flags", dwFlags);
		free(path);
		return 0;
	}
	return 1;
}

HOOKDEF_ALT(BOOL, WINAPI, MoveFileWithProgressW,
	__in	  LPWSTR lpExistingFileName,
	__in_opt  LPWSTR lpNewFileName,
	__in_opt  LPPROGRESS_ROUTINE lpProgressRoutine,
	__in_opt  LPVOID lpData,
	__in	  DWORD dwFlags
) {
	wchar_t *path = malloc(32768 * sizeof(wchar_t));
	BOOL ret;

	ensure_absolute_unicode_path(path, lpExistingFileName);

	ret = Old_MoveFileWithProgressW(lpExistingFileName, lpNewFileName,
		lpProgressRoutine, lpData, dwFlags);
	LOQ_bool("filesystem", "uFh", "ExistingFileName", path,
		"NewFileName", lpNewFileName, "Flags", dwFlags);
	if (ret != FALSE) {
		if (lpNewFileName && dropped_count < g_config.dropped_limit) {
#ifdef DEBUG_COMMENTS
			DebugOutput("MoveFileWithProgressW: FILE_MOVE %ws::%ws\n", path, lpNewFileName);
#endif
			pipe("FILE_MOVE:%d,%Z::%F", GetCurrentProcessId(), path, lpNewFileName);
			dropped_count++;
		}
		else if (dropped_count < g_config.dropped_limit) {
			// we can do this here because it's not scheduled for deletion until reboot
#ifdef DEBUG_COMMENTS
			DebugOutput("MoveFileWithProgressW: FILE_DEL %ws\n", path);
#endif
			pipe("FILE_DEL:%d,%Z", GetCurrentProcessId(), path);
			dropped_count++;
		}
	}

	free(path);

	return ret;
}

HOOKDEF_NOTAIL(WINAPI, MoveFileWithProgressTransactedW,
	__in	  LPWSTR lpExistingFileName,
	__in_opt  LPWSTR lpNewFileName,
	__in_opt  LPPROGRESS_ROUTINE lpProgressRoutine,
	__in_opt  LPVOID lpData,
	__in	  DWORD dwFlags,
	__in	  HANDLE hTransaction
) {
	BOOL ret = TRUE;

	if (lpProgressRoutine) {
		wchar_t *path = malloc(32768 * sizeof(wchar_t));
		ensure_absolute_unicode_path(path, lpExistingFileName);
		LOQ_bool("filesystem", "uFh", "ExistingFileName", path,
			"NewFileName", lpNewFileName, "Flags", dwFlags);
		free(path);
		return 0;
	}
	return 1;
}

HOOKDEF_ALT(BOOL, WINAPI, MoveFileWithProgressTransactedW,
	__in	  LPWSTR lpExistingFileName,
	__in_opt  LPWSTR lpNewFileName,
	__in_opt  LPPROGRESS_ROUTINE lpProgressRoutine,
	__in_opt  LPVOID lpData,
	__in	  DWORD dwFlags,
	__in	  HANDLE hTransaction
) {
	BOOL ret;
	hook_info_t saved_hookinfo;

	memcpy(&saved_hookinfo, hook_info(), sizeof(saved_hookinfo));
	ret = Old_MoveFileWithProgressTransactedW(lpExistingFileName, lpNewFileName,
		lpProgressRoutine, lpData, dwFlags, hTransaction);
	memcpy(hook_info(), &saved_hookinfo, sizeof(saved_hookinfo));

	if (!called_by_hook()) {
		wchar_t *path = malloc(32768 * sizeof(wchar_t));

		ensure_absolute_unicode_path(path, lpExistingFileName);

		LOQ_bool("filesystem", "uFh", "ExistingFileName", path,
			"NewFileName", lpNewFileName, "Flags", dwFlags);
		if (ret != FALSE) {
			if (lpNewFileName)
				if (dropped_count < g_config.dropped_limit) {
#ifdef DEBUG_COMMENTS
					DebugOutput("MoveFileWithProgressTransactedW: FILE_MOVE %ws::%ws\n", path, lpNewFileName);
#endif
					pipe("FILE_MOVE:%d,%Z::%F", GetCurrentProcessId(), path, lpNewFileName);
					dropped_count++;
				}
			else {
				// we can do this here because it's not scheduled for deletion until reboot
				if (dropped_count < g_config.dropped_limit) {
#ifdef DEBUG_COMMENTS
					DebugOutput("MoveFileWithProgressTransactedW: FILE_DEL %ws\n", path);
#endif
					pipe("FILE_DEL:%d,%Z", GetCurrentProcessId(), path);
					dropped_count++;
				}
			}
		}

		free(path);
	}

	return ret;
}

HOOKDEF (HANDLE, WINAPI, CreateFileTransactedA,
  __in	   LPCSTR				lpFileName,
  __in	   DWORD				 dwDesiredAccess,
  __in	   DWORD				 dwShareMode,
  __in_opt   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  __in	   DWORD				 dwCreationDisposition,
  __in	   DWORD				 dwFlagsAndAttributes,
  __in_opt   HANDLE				hTemplateFile,
  __in	   HANDLE				hTransaction,
  __in_opt   PUSHORT			   pusMiniVersion,
  __reserved PVOID				 pExtendedParameter
) {
	HANDLE ret = Old_CreateFileTransactedA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
		dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, hTransaction, pusMiniVersion, pExtendedParameter);

	LOQ_handle("filesystem", "hfhh", "FileHandle", ret, "FileName", lpFileName, "TransactionHandle", hTransaction, "FlagsAndAttributes", dwFlagsAndAttributes);

	return ret;
}

HOOKDEF (HANDLE, WINAPI, CreateFileTransactedW,
  __in	   LPCWSTR			   lpFileName,
  __in	   DWORD				 dwDesiredAccess,
  __in	   DWORD				 dwShareMode,
  __in_opt   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  __in	   DWORD				 dwCreationDisposition,
  __in	   DWORD				 dwFlagsAndAttributes,
  __in_opt   HANDLE				hTemplateFile,
  __in	   HANDLE				hTransaction,
  __in_opt   PUSHORT			   pusMiniVersion,
  __reserved PVOID				 pExtendedParameter
) {
	HANDLE ret = Old_CreateFileTransactedW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
		dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, hTransaction, pusMiniVersion, pExtendedParameter);

	LOQ_handle("filesystem", "hFhh", "FileHandle", ret, "FileName", lpFileName, "TransactionHandle", hTransaction, "FlagsAndAttributes", dwFlagsAndAttributes);

	return ret;
}

HOOKDEF(HANDLE, WINAPI, FindFirstFileExA,
	__in		LPCSTR lpFileName,
	__in		FINDEX_INFO_LEVELS fInfoLevelId,
	__out	   LPVOID lpFindFileData,
	__in		FINDEX_SEARCH_OPS fSearchOp,
	__reserved  LPVOID lpSearchFilter,
	__in		DWORD dwAdditionalFlags
) {
	HANDLE ret = Old_FindFirstFileExA(lpFileName, fInfoLevelId,
		lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);

	if (!g_config.no_stealth && ret != INVALID_HANDLE_VALUE && lpFileName &&
		(!_strnicmp(lpFileName, g_config.analyzer, strlen(g_config.analyzer))
			|| !_strnicmp(lpFileName, g_config.results, strlen(g_config.results))
			|| !_strnicmp(lpFileName, g_config.pythonpath, strlen(g_config.pythonpath)))
		) {
		lasterror_t lasterror;

		lasterror.Win32Error = 0x00000002;
		lasterror.NtstatusError = 0xc000000f;
		lasterror.Eflags = 0;
		FindClose(ret);
		set_lasterrors(&lasterror);
		ret = INVALID_HANDLE_VALUE;
	}
	else if (!g_config.no_stealth && ret != INVALID_HANDLE_VALUE &&
		(!stricmp(((PWIN32_FIND_DATAA)lpFindFileData)->cFileName, g_config.analyzer + 3) ||
			!stricmp(((PWIN32_FIND_DATAA)lpFindFileData)->cFileName, g_config.results + 3) ||
			!stricmp(((PWIN32_FIND_DATAA)lpFindFileData)->cFileName, g_config.pythonpath + 3)))
	{
		BOOL result = FindNextFileA(ret, lpFindFileData);
		if (result == FALSE) {
			lasterror_t lasterror;

			lasterror.Win32Error = 0x00000002;
			lasterror.NtstatusError = 0xc000000f;
			lasterror.Eflags = 0;
			FindClose(ret);
			set_lasterrors(&lasterror);
			ret = INVALID_HANDLE_VALUE;
		}
	}


	if (!g_config.no_stealth && ret != INVALID_HANDLE_VALUE && (!stricmp(lpFileName, "c:\\windows") || !stricmp(lpFileName, "c:\\pagefile.sys")))
		perform_create_time_fakery(&((PWIN32_FIND_DATAA)lpFindFileData)->ftCreationTime);

	if (g_config.sysvol_ctime.dwLowDateTime && ret != INVALID_HANDLE_VALUE && !stricmp(lpFileName, "c:\\System Volume Information"))
		((PWIN32_FIND_DATAA)lpFindFileData)->ftCreationTime = g_config.sysvol_ctime;
	if (g_config.sys32_ctime.dwLowDateTime && ret != INVALID_HANDLE_VALUE && !stricmp(lpFileName, "c:\\windows\\system32"))
		((PWIN32_FIND_DATAA)lpFindFileData)->ftCreationTime = g_config.sys32_ctime;

	if (ret != INVALID_HANDLE_VALUE)
		LOQ_handle("filesystem", "fhh", "FileName", lpFileName,
			"FirstCreateTimeLow", ((PWIN32_FIND_DATAA)lpFindFileData)->ftCreationTime.dwLowDateTime,
			"FirstCreateTimeHigh", ((PWIN32_FIND_DATAA)lpFindFileData)->ftCreationTime.dwHighDateTime);
	else
		LOQ_handle("filesystem", "f", "FileName", lpFileName);

	return ret;
}

HOOKDEF(HANDLE, WINAPI, FindFirstFileExW,
	__in		LPWSTR lpFileName,
	__in		FINDEX_INFO_LEVELS fInfoLevelId,
	__out	   LPVOID lpFindFileData,
	__in		FINDEX_SEARCH_OPS fSearchOp,
	__reserved  LPVOID lpSearchFilter,
	__in		DWORD dwAdditionalFlags
) {
	HANDLE ret = Old_FindFirstFileExW(lpFileName, fInfoLevelId,
		lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);

	if (!g_config.no_stealth && ret != INVALID_HANDLE_VALUE && lpFileName &&
		(!wcsnicmp(lpFileName, g_config.w_analyzer, wcslen(g_config.w_analyzer))
			|| !wcsnicmp(lpFileName, g_config.w_results, wcslen(g_config.w_results))
			|| !wcsnicmp(lpFileName, g_config.w_pythonpath, wcslen(g_config.w_pythonpath)))
	) {
		lasterror_t lasterror;

		lasterror.Win32Error = 0x00000002;
		lasterror.NtstatusError = 0xc000000f;
		lasterror.Eflags = 0;
		FindClose(ret);
		set_lasterrors(&lasterror);
		ret = INVALID_HANDLE_VALUE;
	}
	else if (!g_config.no_stealth && ret != INVALID_HANDLE_VALUE &&
		(!wcsicmp(((PWIN32_FIND_DATAW)lpFindFileData)->cFileName, g_config.w_analyzer + 3) ||
		 !wcsicmp(((PWIN32_FIND_DATAW)lpFindFileData)->cFileName, g_config.w_results + 3) ||
		 !wcsicmp(((PWIN32_FIND_DATAW)lpFindFileData)->cFileName, g_config.w_pythonpath + 3)))
	{
		BOOL result = FindNextFileW(ret, lpFindFileData);
		if (result == FALSE) {
			lasterror_t lasterror;

			lasterror.Win32Error = 0x00000002;
			lasterror.NtstatusError = 0xc000000f;
			lasterror.Eflags = 0;
			FindClose(ret);
			set_lasterrors(&lasterror);
			ret = INVALID_HANDLE_VALUE;
		}
	}

	if (!g_config.no_stealth && ret != INVALID_HANDLE_VALUE && (!wcsicmp(lpFileName, L"c:\\windows") || !wcsicmp(lpFileName, L"c:\\pagefile.sys")))
		perform_create_time_fakery(&((PWIN32_FIND_DATAW)lpFindFileData)->ftCreationTime);

	if (g_config.sysvol_ctime.dwLowDateTime && ret != INVALID_HANDLE_VALUE && !wcsicmp(lpFileName, L"c:\\System Volume Information"))
		((PWIN32_FIND_DATAW)lpFindFileData)->ftCreationTime = g_config.sysvol_ctime;
	if (g_config.sys32_ctime.dwLowDateTime && ret != INVALID_HANDLE_VALUE && !wcsicmp(lpFileName, L"c:\\windows\\system32"))
		((PWIN32_FIND_DATAW)lpFindFileData)->ftCreationTime = g_config.sys32_ctime;

	if (ret != INVALID_HANDLE_VALUE)
		LOQ_handle("filesystem", "Fhh", "FileName", lpFileName,
			"FirstCreateTimeLow", ((PWIN32_FIND_DATAW)lpFindFileData)->ftCreationTime.dwLowDateTime,
			"FirstCreateTimeHigh", ((PWIN32_FIND_DATAW)lpFindFileData)->ftCreationTime.dwHighDateTime);
	else
		LOQ_handle("filesystem", "F", "FileName", lpFileName);
	return ret;
}

HOOKDEF(BOOL, WINAPI, FindNextFileW,
	__in HANDLE hFindFile,
	__out LPWIN32_FIND_DATAW lpFindFileData
) {
	BOOL ret = Old_FindNextFileW(hFindFile, lpFindFileData);

	while (!g_config.no_stealth && ret && (
		!wcsicmp(lpFindFileData->cFileName, g_config.w_analyzer + 3) ||
		!wcsicmp(lpFindFileData->cFileName, g_config.w_results + 3) ||
		!wcsicmp(lpFindFileData->cFileName, g_config.w_pythonpath + 3))) {
		ret = Old_FindNextFileW(hFindFile, lpFindFileData);
	}

	// not logging this due to the flood of logs it would cause

	return ret;
}

HOOKDEF(BOOL, WINAPI, CopyFileA,
	__in  LPCSTR lpExistingFileName,
	__in  LPCSTR lpNewFileName,
	__in  BOOL bFailIfExists
) {
	BOOL ret;
	BOOL file_existed = FALSE;
	if (GetFileAttributesA(lpNewFileName) != INVALID_FILE_ATTRIBUTES)
		file_existed = TRUE;

	ret = Old_CopyFileA(lpExistingFileName, lpNewFileName,
		bFailIfExists);
	LOQ_bool("filesystem", "ffs", "ExistingFileName", lpExistingFileName,
		"NewFileName", lpNewFileName, "ExistedBefore", file_existed ? "yes" : "no");

	if (ret)
		new_file_path_ascii(lpNewFileName);

	return ret;
}

HOOKDEF(BOOL, WINAPI, CopyFileW,
	__in  LPWSTR lpExistingFileName,
	__in  LPWSTR lpNewFileName,
	__in  BOOL bFailIfExists
) {
	BOOL ret;
	BOOL file_existed = FALSE;
	if (GetFileAttributesW(lpNewFileName) != INVALID_FILE_ATTRIBUTES)
		file_existed = TRUE;

	ret = Old_CopyFileW(lpExistingFileName, lpNewFileName,
		bFailIfExists);
	LOQ_bool("filesystem", "FFs", "ExistingFileName", lpExistingFileName,
		"NewFileName", lpNewFileName, "ExistedBefore", file_existed ? "yes" : "no");

	if (ret)
		new_file_path_unicode(lpNewFileName);

	return ret;
}

HOOKDEF_NOTAIL(WINAPI, CopyFileExW,
	_In_	  LPWSTR lpExistingFileName,
	_In_	  LPWSTR lpNewFileName,
	_In_opt_  LPPROGRESS_ROUTINE lpProgressRoutine,
	_In_opt_  LPVOID lpData,
	_In_opt_  LPBOOL pbCancel,
	_In_	  DWORD dwCopyFlags
) {
	BOOL ret = TRUE;
	BOOL file_existed = FALSE;

	if (GetFileAttributesW(lpNewFileName) != INVALID_FILE_ATTRIBUTES)
		file_existed = TRUE;

	if (lpProgressRoutine) {
		LOQ_bool("filesystem", "FFis", "ExistingFileName", lpExistingFileName,
			"NewFileName", lpNewFileName, "CopyFlags", dwCopyFlags, "ExistedBefore", file_existed ? "yes" : "no");
		return 0;
	}

	return 1;
}


HOOKDEF_ALT(BOOL, WINAPI, CopyFileExW,
	_In_	  LPWSTR lpExistingFileName,
	_In_	  LPWSTR lpNewFileName,
	_In_opt_  LPPROGRESS_ROUTINE lpProgressRoutine,
	_In_opt_  LPVOID lpData,
	_In_opt_  LPBOOL pbCancel,
	_In_	  DWORD dwCopyFlags
) {
	BOOL ret;
	BOOL file_existed = FALSE;
	if (GetFileAttributesW(lpNewFileName) != INVALID_FILE_ATTRIBUTES)
		file_existed = TRUE;

	ret = Old_CopyFileExW(lpExistingFileName, lpNewFileName,
		lpProgressRoutine, lpData, pbCancel, dwCopyFlags);
	LOQ_bool("filesystem", "FFis", "ExistingFileName", lpExistingFileName,
		"NewFileName", lpNewFileName, "CopyFlags", dwCopyFlags, "ExistedBefore", file_existed ? "yes" : "no");

	if (ret)
		new_file_path_unicode(lpNewFileName);

	return ret;
}
HOOKDEF(BOOL, WINAPI, DeleteFileA,
	__in  LPCSTR lpFileName
) {
	char path[MAX_PATH];
	BOOL ret;

	ensure_absolute_ascii_path(path, lpFileName);

	if (dropped_count < g_config.dropped_limit) {
#ifdef DEBUG_COMMENTS
		DebugOutput("DeleteFileA: FILE_DEL %ws\n", path);
#endif
		pipe("FILE_DEL:%d,%z", GetCurrentProcessId(), path);
		dropped_count++;
	}

	ret = Old_DeleteFileA(lpFileName);
	LOQ_bool("filesystem", "s", "FileName", path);

	return ret;
}

HOOKDEF(BOOL, WINAPI, DeleteFileW,
	__in  LPWSTR lpFileName
) {
	wchar_t *path = malloc(32768 * sizeof(wchar_t));
	BOOL ret;

	if (path) {
		ensure_absolute_unicode_path(path, lpFileName);

		if (dropped_count < g_config.dropped_limit) {
#ifdef DEBUG_COMMENTS
			DebugOutput("DeleteFileW: FILE_DEL %ws\n", path);
#endif
			pipe("FILE_DEL:%d,%Z", GetCurrentProcessId(), path);
			dropped_count++;
		}
	}

	ret = Old_DeleteFileW(lpFileName);
	if (path) {
		LOQ_bool("filesystem", "u", "FileName", path);
		free(path);
	}
	else {
		LOQ_bool("filesystem", "u", "FileName", lpFileName);
	}
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetDiskFreeSpaceExA,
	_In_opt_   PCSTR lpDirectoryName,
	_Out_opt_  PULARGE_INTEGER lpFreeBytesAvailable,
	_Out_opt_  PULARGE_INTEGER lpTotalNumberOfBytes,
	_Out_opt_  PULARGE_INTEGER lpTotalNumberOfFreeBytes
) {
	BOOL ret = Old_GetDiskFreeSpaceExA(lpDirectoryName, lpFreeBytesAvailable, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes);
	LOQ_bool("filesystem", "s", "DirectoryName", lpDirectoryName);
	if (!g_config.no_stealth && ret && lpTotalNumberOfBytes) {
		lpTotalNumberOfBytes->QuadPart = SPOOFED_DISK_SIZE - RECOVERY_PARTITION_SIZE;
	}

	return ret;
}

HOOKDEF(BOOL, WINAPI, GetDiskFreeSpaceExW,
	_In_opt_   PCWSTR lpDirectoryName,
	_Out_opt_  PULARGE_INTEGER lpFreeBytesAvailable,
	_Out_opt_  PULARGE_INTEGER lpTotalNumberOfBytes,
	_Out_opt_  PULARGE_INTEGER lpTotalNumberOfFreeBytes
) {
	BOOL ret = Old_GetDiskFreeSpaceExW(lpDirectoryName, lpFreeBytesAvailable, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes);
	LOQ_bool("filesystem", "u", "DirectoryName", lpDirectoryName);
	if (!g_config.no_stealth && ret && lpTotalNumberOfBytes) {
		lpTotalNumberOfBytes->QuadPart = SPOOFED_DISK_SIZE - RECOVERY_PARTITION_SIZE;
	}

	return ret;
}

HOOKDEF(BOOL, WINAPI, GetDiskFreeSpaceA,
	_In_   PCSTR lpRootPathName,
	_Out_  LPDWORD lpSectorsPerCluster,
	_Out_  LPDWORD lpBytesPerSector,
	_Out_  LPDWORD lpNumberOfFreeClusters,
	_Out_  LPDWORD lpTotalNumberOfClusters
) {
	BOOL ret = Old_GetDiskFreeSpaceA(lpRootPathName, lpSectorsPerCluster, lpBytesPerSector, lpNumberOfFreeClusters, lpTotalNumberOfClusters);
	LOQ_bool("filesystem", "s", "RootPathName", lpRootPathName);
	if (!g_config.no_stealth) {
		__try {
			if (lpTotalNumberOfClusters && lpSectorsPerCluster && lpBytesPerSector && *lpSectorsPerCluster && *lpBytesPerSector) {
				*lpTotalNumberOfClusters = (DWORD)((SPOOFED_DISK_SIZE - RECOVERY_PARTITION_SIZE) / (*lpSectorsPerCluster * *lpBytesPerSector));
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
	}

	return ret;
}

HOOKDEF(BOOL, WINAPI, GetDiskFreeSpaceW,
	_In_   PCWSTR lpRootPathName,
	_Out_  LPDWORD lpSectorsPerCluster,
	_Out_  LPDWORD lpBytesPerSector,
	_Out_  LPDWORD lpNumberOfFreeClusters,
	_Out_  LPDWORD lpTotalNumberOfClusters
) {
	BOOL ret = Old_GetDiskFreeSpaceW(lpRootPathName, lpSectorsPerCluster, lpBytesPerSector, lpNumberOfFreeClusters, lpTotalNumberOfClusters);
	LOQ_bool("filesystem", "u", "RootPathName", lpRootPathName);
	if (!g_config.no_stealth) {
		__try {
			if (lpTotalNumberOfClusters && lpSectorsPerCluster && lpBytesPerSector && *lpSectorsPerCluster && *lpBytesPerSector) {
				*lpTotalNumberOfClusters = (DWORD)((SPOOFED_DISK_SIZE - RECOVERY_PARTITION_SIZE) / (*lpSectorsPerCluster * *lpBytesPerSector));
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
	}
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetVolumeInformationA,
	_In_opt_   LPCSTR lpRootPathName,
	_Out_opt_  LPSTR lpVolumeNameBuffer,
	_In_	   DWORD nVolumeNameSize,
	_Out_opt_  LPDWORD lpVolumeSerialNumber,
	_Out_opt_  LPDWORD lpMaximumComponentLength,
	_Out_opt_  LPDWORD lpFileSystemFlags,
	_Out_opt_  LPSTR lpFileSystemNameBuffer,
	_In_	   DWORD nFileSystemNameSize
)
{
	BOOL ret = Old_GetVolumeInformationA(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize);
	LOQ_bool("filesystem", "s", "RootPathName", lpRootPathName);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetVolumeInformationW,
	_In_opt_   LPCWSTR lpRootPathName,
	_Out_opt_  LPWSTR lpVolumeNameBuffer,
	_In_	   DWORD nVolumeNameSize,
	_Out_opt_  LPDWORD lpVolumeSerialNumber,
	_Out_opt_  LPDWORD lpMaximumComponentLength,
	_Out_opt_  LPDWORD lpFileSystemFlags,
	_Out_opt_  LPWSTR lpFileSystemNameBuffer,
	_In_	   DWORD nFileSystemNameSize
)
{
	BOOL ret = Old_GetVolumeInformationW(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize);
	LOQ_bool("filesystem", "u", "RootPathName", lpRootPathName);
	return ret;
}

HOOKDEF(BOOL, WINAPI, GetVolumeNameForVolumeMountPointW,
	_In_ LPCWSTR lpszVolumeMountPoint,
	_Out_ LPWSTR lpszVolumeName,
	_In_ DWORD cchBufferLength
) {
	BOOL ret = Old_GetVolumeNameForVolumeMountPointW(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength);
	if (!g_config.no_stealth && ret) {
		replace_wstring_in_buf(lpszVolumeName, cchBufferLength, L"QEMU", L"DELL");
		replace_wstring_in_buf(lpszVolumeName, cchBufferLength, L"VMware", L"DELL__");
		replace_wstring_in_buf(lpszVolumeName, cchBufferLength, L"VMWar", L"WDRed");
	}
	LOQ_bool("filesystem", "uu", "VolumeMountPoint", lpszVolumeMountPoint, "VolumeName", lpszVolumeName);

	return ret;
}

HOOKDEF(BOOL, WINAPI, GetVolumeInformationByHandleW,
	_In_	  HANDLE  hFile,
	_Out_opt_ LPWSTR  lpVolumeNameBuffer,
	_In_	  DWORD   nVolumeNameSize,
	_Out_opt_ LPDWORD lpVolumeSerialNumber,
	_Out_opt_ LPDWORD
	lpMaximumComponentLength,
	_Out_opt_ LPDWORD lpFileSystemFlags,
	_Out_opt_ LPWSTR  lpFileSystemNameBuffer,
	_In_	  DWORD   nFileSystemNameSize
) {
	BOOL ret = Old_GetVolumeInformationByHandleW(hFile, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber,
		lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize);

	if (ret && lpVolumeSerialNumber && g_config.serial_number)
		*lpVolumeSerialNumber = g_config.serial_number;

	LOQ_bool("filesystem", "puH", "Handle", hFile, "VolumeName", lpVolumeNameBuffer, "VolumeSerial", lpVolumeSerialNumber);

	return ret;
}

HOOKDEF(BOOL, WINAPI, SetFileInformationByHandle,
	_In_		HANDLE                    hFile,
	_In_		FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
	_In_		LPVOID                    lpFileInformation,
	_In_		DWORD                     dwBufferSize
) {
	if (FileInformationClass == FileDispositionInfo && dropped_count < g_config.dropped_limit) {
		wchar_t *fname = calloc(32768, sizeof(wchar_t));
		wchar_t *path = calloc(32768, sizeof(wchar_t));

		path_from_handle(hFile, fname, 32768);
		ensure_absolute_unicode_path(path, fname);
#ifdef DEBUG_COMMENTS
		DebugOutput("SetFileInformationByHandle: FILE_DEL %ws\n", path);
#endif
		pipe("FILE_DEL:%d,%Z", GetCurrentProcessId(), path);
		dropped_count++;

		free(fname);
		free(path);
	}

	BOOL ret = Old_SetFileInformationByHandle(hFile, FileInformationClass, lpFileInformation, dwBufferSize);

	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHGetFolderPathW,
	_In_ HWND hwndOwner,
	_In_ int nFolder,
	_In_ HANDLE hToken,
	_In_ DWORD dwFlags,
	_Out_ LPWSTR pszPath
) {
	HRESULT ret = Old_SHGetFolderPathW(hwndOwner, nFolder, hToken, dwFlags, pszPath);
	LOQ_hresult("filesystem", "hu", "Folder", nFolder, "Path", pszPath);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHGetKnownFolderPath,
	_In_	 GUID			  *rfid,
	_In_	 DWORD			dwFlags,
	_In_opt_ HANDLE		   hToken,
	_Out_	PWSTR			*ppszPath
) {
	lasterror_t lasterrors;
	IID id1;
	char idbuf[40];
	HRESULT ret = Old_SHGetKnownFolderPath(rfid, dwFlags, hToken, ppszPath);

	get_lasterrors(&lasterrors);
	memcpy(&id1, rfid, sizeof(id1));
	uuid_to_string(id1, idbuf);
	LOQ_hresult("filesystem", "shu", "FolderID", idbuf, "Flags", dwFlags, "Path", ppszPath ? *ppszPath : NULL);
	set_lasterrors(&lasterrors);
	return ret;
}

HOOKDEF(DWORD_PTR, WINAPI, SHGetFileInfoW,
	_In_	LPCWSTR	pszPath,
	DWORD	  dwFileAttributes,
	_Inout_ SHFILEINFOW *psfi,
	UINT	   cbFileInfo,
	UINT	   uFlags
) {
	DWORD_PTR ret = Old_SHGetFileInfoW(pszPath, dwFileAttributes, psfi, cbFileInfo, uFlags);
	if (uFlags & SHGFI_PIDL) {
		// TODO: something useful with this
		LOQ_nonzero("filesystem", "h", "Flags", uFlags);
	}
	else if (uFlags & SHGFI_USEFILEATTRIBUTES) {
		if (cbFileInfo >= sizeof(SHFILEINFOW))
			LOQ_nonzero("filesystem", "uhuu", "Path", pszPath, "Flags", uFlags, "DisplayName", psfi->szDisplayName, "TypeName", psfi->szTypeName);
		else
			LOQ_nonzero("filesystem", "uh", "Path", pszPath, "Flags", uFlags);
	}
	else if (cbFileInfo >= sizeof(SHFILEINFOW)) {
		LOQ_nonzero("filesystem", "Fhuu", "Path", pszPath, "Flags", uFlags, "DisplayName", psfi->szDisplayName, "TypeName", psfi->szTypeName);
	}
	else {
		LOQ_nonzero("filesystem", "Fh", "Path", pszPath, "Flags", uFlags);
	}

	return ret;
}


HOOKDEF(BOOL, WINAPI, GetFileVersionInfoW,
	_In_		LPCWSTR lptstrFilename,
	_Reserved_  DWORD dwHandle,
	_In_		DWORD dwLen,
	_Out_	   LPVOID lpData
) {
	BOOL ret = Old_GetFileVersionInfoW(lptstrFilename, dwHandle, dwLen, lpData);

	if (lptstrFilename && lstrlenW(lptstrFilename) > 3 && lptstrFilename[1] == L':' && (lptstrFilename[2] == L'\\' || lptstrFilename[2] == L'/'))
		LOQ_bool("filesystem", "F", "PathName", lptstrFilename);
	else
		LOQ_bool("filesystem", "u", "PathName", lptstrFilename);
	return ret;
}

HOOKDEF(DWORD, WINAPI, GetFileVersionInfoSizeW,
	_In_	   LPCWSTR lptstrFilename,
	_Out_opt_  LPDWORD lpdwHandle
) {
	DWORD ret = Old_GetFileVersionInfoSizeW(lptstrFilename, lpdwHandle);

	if (lptstrFilename && lstrlenW(lptstrFilename) > 3 && lptstrFilename[1] == L':' && (lptstrFilename[2] == L'\\' || lptstrFilename[2] == L'/'))
		LOQ_nonzero("filesystem", "F", "PathName", lptstrFilename);
	else
		LOQ_nonzero("filesystem", "u", "PathName", lptstrFilename);

	return ret;
}

HOOKDEF(HANDLE, WINAPI, FindFirstChangeNotificationW,
	_In_	LPCWSTR lpPathName,
	_In_	BOOL bWatchSubtree,
	_In_	DWORD dwNotifyFilter
) {
	HANDLE ret = Old_FindFirstChangeNotificationW(lpPathName, bWatchSubtree, dwNotifyFilter);

	LOQ_handle("filesystem", "Fhi", "PathName", lpPathName, "NotifyFilter", dwNotifyFilter, "WatchSubtree", bWatchSubtree);

	return ret;
}

HOOKDEF(DWORD, WINAPI, RmStartSession,
	__out DWORD *pSessionHandle,
	_Reserved_ DWORD dwSessionFlags,
	__out WCHAR strSessionKey[]
) {
	DWORD ret = Old_RmStartSession(pSessionHandle, dwSessionFlags, strSessionKey);

	if (NT_SUCCESS(ret))
		LOQ_ntstatus("filesystem", "u", "SessionKey", strSessionKey);
	else
		LOQ_ntstatus("filesystem", "");

	return ret;
}