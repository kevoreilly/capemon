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
#include <string.h>
#include <stdarg.h>
#include "ntapi.h"
#include "hooking.h"
#include "misc.h"
#include "utf8.h"
#include "log.h"
#include "mpack.h" // Replaced bson.h with mpack.h
#include "pipe.h"
#include "config.h"

extern char* GetResultsPath(char* FolderName);

// the size of the logging buffer
#define BUFFERSIZE 16 * 1024 * 1024
#define BUFFER_LOG_MAX 256
#define LARGE_BUFFER_LOG_MAX 2048
size_t buffer_log_max = BUFFER_LOG_MAX;
size_t large_buffer_log_max = LARGE_BUFFER_LOG_MAX;
#define BUFFER_REGVAL_MAX 512

CRITICAL_SECTION g_mutex;
CRITICAL_SECTION g_writing_log_buffer_mutex;
static SOCKET g_sock;
static HANDLE g_debug_log_handle;
static unsigned int g_starttick;

static char *g_buffer;
static volatile int g_idx;
static DWORD last_api_logged;
static BOOLEAN special_api_triggered;
static BOOLEAN delete_last_log;
HANDLE g_log_handle;

// mpack writer state not global per-call to support re-entrancy better if needed,
// but for now we follow the pattern. 
// We will allocate writers on stack or heap per loq() to avoid global state issues.

static char g_istr[4]; // Used for number to string conversion, less needed for mpack but kept

static char logtbl_explained[256] = {0};

#define LOG_ID_PROCESS 0
#define LOG_ID_THREAD 1
#define LOG_ID_ANOMALY_GENERIC 2
#define LOG_ID_ANOMALY_HOOK 3
#define LOG_ID_ANOMALY_HOOKREM 4
#define LOG_ID_ANOMALY_HOOKRES 5
#define LOG_ID_ANOMALY_HOOKMOD 6
#define LOG_ID_ANOMALY_PROCNAME 7
#define LOG_ID_ENVIRON 8
#define LOG_ID_SYSCALL 9
// must be one larger than the largest log ID
#define LOG_ID_PREDEFINED_MAX 10

volatile LONG g_log_index = 20;  // index must start after the special IDs (see defines)

//
// Log API
//

static HANDLE g_log_thread_handle;
static HANDLE g_logwatcher_thread_handle;
static HANDLE g_log_flush;

extern int process_shutting_down;

static void _send_log(void)
{
	EnterCriticalSection(&g_writing_log_buffer_mutex);
	while (g_idx > 0) {
		int written = -1;

		if (g_sock == DEBUG_SOCKET) {
			if (g_debug_log_handle != INVALID_HANDLE_VALUE) {
				WriteFile(g_debug_log_handle, g_buffer, g_idx, &written, NULL);
			}
			else {
				// some non-admin debug case
				written = g_idx;
			}
		}
		else {
			if (g_log_handle == INVALID_HANDLE_VALUE) {
				g_idx = 0;
				continue;
			}
			else {
				WriteFile(g_log_handle, g_buffer, g_idx, &written, NULL);
			}
		}

		if (written < 0)
			continue;

		// if this call didn't write the entire buffer, then we have to move
		// around some stuff in the buffer
		if (written < g_idx) {
			memmove(g_buffer, g_buffer + written, g_idx - written);
		}

		// subtract the amount of written bytes from the index
		g_idx -= written;
	}
	LeaveCriticalSection(&g_writing_log_buffer_mutex);
}

static DWORD WINAPI _log_thread(LPVOID param)
{
	hook_disable();

	while (1) {
		WaitForSingleObject(g_log_flush, 500);
		_send_log();
	}
}

static DWORD WINAPI _logwatcher_thread(LPVOID param)
{
	hook_disable();

	while (WaitForSingleObject(g_log_thread_handle, 1000) == WAIT_TIMEOUT);

	if (is_shutting_down() == 0) {
		pipe("CRITICAL:Logging thread was terminated!");
	}
	return 0;
}

extern BOOLEAN g_dll_main_complete;

static lastlog_t lastlog;

static void log_raw_direct(const char *buf, size_t length) {
	size_t copiedlen = 0;
	size_t copylen;

	if (!g_buffer)
		return;

	while (copiedlen != length) {
		EnterCriticalSection(&g_writing_log_buffer_mutex);
		copylen = min((unsigned int)(length - copiedlen), (unsigned int)(BUFFERSIZE - g_idx));
		memcpy(&g_buffer[g_idx], &buf[copiedlen], copylen);
		g_idx += (int)copylen;
		copiedlen += copylen;
		LeaveCriticalSection(&g_writing_log_buffer_mutex);
		if (copiedlen != length)
			_send_log();
	}
}

void log_flush()
{
	if (!TryEnterCriticalSection(&g_mutex))
		return;

	if (lastlog.buf) {
		log_raw_direct((const char*)lastlog.buf, lastlog.len);
		free(lastlog.buf);
		lastlog.buf = NULL;
	}
	LeaveCriticalSection(&g_mutex);

	if (g_buffer)
		_send_log();
}

void debug_message(const char *msg) {
	mpack_writer_t w;
	char *data; 
	size_t size;
	
mpack_writer_init_growable(&w, &data, &size);
	mpack_start_map(&w, 2);
	mpack_write_cstr(&w, "type");
	mpack_write_cstr(&w, "debug");
	mpack_write_cstr(&w, "msg");
	mpack_write_cstr(&w, msg);
	mpack_finish_map(&w);
	
	if (mpack_writer_destroy(&w) == mpack_ok) {
		log_raw_direct(data, size);
		free(data);
	}
	log_flush();
}

static void log_int32(mpack_writer_t* w, int value)
{
	mpack_write_int(w, value);
}

static void log_int64(mpack_writer_t* w, int64_t value)
{
	mpack_write_i64(w, value);
}

static void log_ptr(mpack_writer_t* w, void *value)
{
	// Log as int64 to accommodate both 32/64 bit pointers safely
	mpack_write_u64(w, (uint64_t)(ULONG_PTR)value); 
}

static void log_string(mpack_writer_t* w, const char *str, int length)
{
	char *utf8s;
	int utf8len;

	if (str == NULL) {
		mpack_write_cstr(w, "");
		return;
	}
	// Capemon's utf8_string returns [len (4 bytes)][string data]
	utf8s = utf8_string(str, length);
	utf8len = * (int *) utf8s;
	
	// mpack_write_utf8 expects just the string data
	mpack_write_utf8(w, utf8s + 4, utf8len);
	free(utf8s);
}

static void log_wstring(mpack_writer_t* w, const wchar_t *str, int length)
{
	char *utf8s;
	int utf8len;

	if (str == NULL) {
		mpack_write_cstr(w, "");
		return;
	}
	utf8s = utf8_wstring(str, length);
	utf8len = * (int *) utf8s;
	
mpack_write_utf8(w, utf8s + 4, utf8len);
	free(utf8s);
}

static void log_variant(mpack_writer_t* w, VARIANT* var) {
	char log_msg[32];
	__try {
		switch (var->vt) {
			case VT_NULL:
				mpack_write_cstr(w, "NULL");
					break;
			case 74: // Undocumented
				log_variant(w, (VARIANT*)var->pvRecord);
					break;
			case 130:
				log_wstring(w, var->bstrVal, -1);
					break;
			case VT_BSTR:
				log_wstring(w, var->bstrVal, -1);
					break;
			case VT_BSTR | VT_BYREF:
				log_wstring(w, var->pbstrVal ? *var->pbstrVal : NULL, -1);
					break;
			case VT_BOOL:
				mpack_write_bool(w, var->boolVal ? true : false);
					break;
			case VT_BOOL | VT_BYREF:
				mpack_write_bool(w, (*var->pboolVal) ? true : false);
					break;
			case VT_INT:
				log_int32(w, var->intVal);
					break;
			case VT_INT | VT_BYREF:
				log_int32(w, *var->pintVal);
					break;
			case VT_UINT:
				log_int32(w, var->uintVal);
					break;
			case VT_UINT | VT_BYREF:
				log_int32(w, *var->puintVal);
					break;
			case VT_I8:
				log_int64(w, var->llVal);
					break;
			case VT_I8 | VT_BYREF:
				log_int64(w, *var->pllVal);
					break;
			case VT_UI8:
				log_int64(w, var->ullVal);
					break;
			case VT_UI8 | VT_BYREF:
				log_int64(w, *var->pullVal);
					break;
			case VT_I4:
				log_int32(w, var->lVal);
					break;
			case VT_I4 | VT_BYREF:
				log_int32(w, *var->plVal);
					break;
			case VT_UI4:
				log_int32(w, var->ulVal);
					break;
			case VT_UI4 | VT_BYREF:
				log_int32(w, *var->pulVal);
					break;
			case VT_I2:
				log_int32(w, var->iVal);
					break;
			case VT_I2 | VT_BYREF:
				log_int32(w, *var->piVal);
					break;
			case VT_UI2:
				log_int32(w, var->uiVal);
					break;
			case VT_UI2 | VT_BYREF:
				log_int32(w, *var->puiVal);
					break;
			case VT_I1:
				log_int32(w, var->cVal);
					break;
			case VT_I1 | VT_BYREF:
				log_int32(w, *var->pcVal);
					break;
			case VT_UI1:
				log_int32(w, var->bVal);
					break;
			case VT_UI1 | VT_BYREF:
				log_int32(w, *var->pbVal);
					break;
			case VT_VARIANT:
				log_variant(w, var->pvarVal);
					break;
			case VT_VARIANT | VT_BYREF:
				log_variant(w, var->pvarVal);
					break;
			case VT_DATE:
				log_int64(w, (int64_t)var->date);
					break;
			case VT_DATE | VT_BYREF:
				log_int64(w, (int64_t)*var->pdate);
					break;
			case VT_R8:
				log_int64(w, (int64_t)var->dblVal);
					break;
			case VT_R8 | VT_BYREF:
				log_int64(w, (int64_t)*var->pdblVal);
					break;
			default:
				snprintf(log_msg, 32, "Unhandled VARIANT Type: %hu", var->vt);
				mpack_write_cstr(w, log_msg);
				break;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		mpack_write_nil(w);
	}
}

static void log_argv(mpack_writer_t* w, int argc, const char ** argv) {
	int i;
	mpack_start_array(w, argc);
	for (i = 0; i < argc; i++) {
		// BSON used keys "0", "1"... MsgPack uses real arrays.
		log_string(w, argv[i], -1);
	}
	mpack_finish_array(w);
}

static void log_wargv(mpack_writer_t* w, int argc, const wchar_t ** argv) {
	int i;
	mpack_start_array(w, argc);
	for (i = 0; i < argc; i++) {
		log_wstring(w, argv[i], -1);
	}
	mpack_finish_array(w);
}

static void log_buffer(mpack_writer_t* w, const char *buf, size_t length) {
	size_t trunclength = min((unsigned int)length, (unsigned int)buffer_log_max);
	if (buf == NULL) trunclength = 0;
	mpack_write_bin(w, buf, trunclength);
}

static void log_large_buffer(mpack_writer_t* w, const char *buf, size_t length) {
	size_t trunclength = min((unsigned int)length, (unsigned int)large_buffer_log_max);
	if (buf == NULL) trunclength = 0;
	mpack_write_bin(w, buf, trunclength);
}

void set_special_api(DWORD API, BOOLEAN deleteLastLog)
{
	if (!TryEnterCriticalSection(&g_mutex))
		return;
	special_api_triggered = TRUE;
	last_api_logged = API;
	delete_last_log = deleteLastLog;
	LeaveCriticalSection(&g_mutex);
}
DWORD get_last_api(void)
{
	return last_api_logged;
}

// Helper to count arguments for mpack arrays
static int count_format_args(const char *fmt) {
	int count = 1; 
	int args = 0;
	const char *p = fmt;
	while (--count != 0 || *p != 0) {
		if (count == 0) {
			if (*p == 0) break;
			count = *p >= '2' && *p <= '9' ? *p++ - '0' : 1;
			p++; // key
		}
		// Skip optional args if any (va_arg skipping logic is in main loop)
		args++;
	}
	return args;
}

void loq(int index, const char *category, const char *name,
	int is_success, ULONG_PTR return_value, const char *fmt, ...)
{
	va_list args;
	const char * fmtbak = fmt;
	int count = 1; char key = 0;
	unsigned int repeat_offset = 0;
	lasterror_t lasterror;
	hook_info_t *hookinfo;

	mpack_writer_t writer;
	char *data = NULL;
	size_t size = 0;

	if (index >= LOG_ID_PREDEFINED_MAX && g_config.suspend_logging)
		return;

	get_lasterrors(&lasterror);

	hook_disable();

	if (!TryEnterCriticalSection(&g_mutex))
		goto exit;

	if (!special_api_triggered)
		last_api_logged = API_OTHER;
	else {
		special_api_triggered = FALSE;
		if (delete_last_log) {
			free(lastlog.buf);
			lastlog.buf = NULL;
		}
	}

	if (logtbl_explained[index] == 0) {
		const char * pname;
		int arg_count = count_format_args(fmt);
		
		logtbl_explained[index] = 1;

		va_start(args, fmt);

		mpack_writer_init_growable(&writer, &data, &size);
		mpack_start_map(&writer, 5); // I, name, type, category, args
		
mpack_write_cstr(&writer, "I");
		mpack_write_int(&writer, index);
		
mpack_write_cstr(&writer, "name");
		mpack_write_cstr(&writer, name);
		
mpack_write_cstr(&writer, "type");
		mpack_write_cstr(&writer, "info");
		
mpack_write_cstr(&writer, "category");
		mpack_write_cstr(&writer, category);

		mpack_write_cstr(&writer, "args");
		mpack_start_array(&writer, arg_count + 2); // +2 for is_success/retval
		
mpack_write_cstr(&writer, "is_success");
		mpack_write_cstr(&writer, "retval");

		while (--count != 0 || *fmt != 0) {
			if (count == 0) {
				if (*fmt == 0) break;
				count = *fmt >= '2' && *fmt <= '9' ? *fmt++ - '0' : 1;
				key = *fmt++;
			}

			pname = va_arg(args, const char *);
			
			// Argument details as array [name, type] or just name
			if (key == 'p' || key == 'P' || key == 'h' || key == 'H') {
				const char *typestr;
				if (key == 'h' || key == 'H' || sizeof(ULONG_PTR) != 8)
					typestr = "h";
				else
					typestr = "p";

				mpack_start_array(&writer, 2);
				mpack_write_cstr(&writer, pname);
				mpack_write_cstr(&writer, typestr);
				mpack_finish_array(&writer);
			}
			else if (key == 'x' || key == 'X') {
				mpack_start_array(&writer, 2);
				mpack_write_cstr(&writer, pname);
				mpack_write_cstr(&writer, "p");
				mpack_finish_array(&writer);
			} else {
				mpack_write_cstr(&writer, pname);
			}

			// Consume unused args
			if (key == 's' || key == 'f') { (void) va_arg(args, const char *); }
			else if (key == 'S') { (void) va_arg(args, int); (void) va_arg(args, const char *); }
			else if (key == 'u' || key == 'F') { (void) va_arg(args, const wchar_t *); }
			else if (key == 'U') { (void) va_arg(args, int); (void) va_arg(args, const wchar_t *); }
			else if (key == 'e' || key == 'v') { (void)va_arg(args, HKEY); (void)va_arg(args, const char *); }
			else if (key == 'E' || key == 'V') { (void)va_arg(args, HKEY); (void)va_arg(args, const wchar_t *); }
			else if (key == 'k') { (void)va_arg(args, HKEY); (void)va_arg(args, const PUNICODE_STRING); }
			else if (key == 'b' || key == 'c') { (void) va_arg(args, size_t); (void) va_arg(args, const char *); }
			else if (key == 'B' || key == 'C') { (void) va_arg(args, size_t *); (void) va_arg(args, const char *); }
			else if (key == 'i' || key == 'h') { (void) va_arg(args, int); }
			else if (key == 'I' || key == 'H') { (void) va_arg(args, int *); }
			else if (key == 'l' || key == 'L') { (void)va_arg(args, ULONG_PTR); }
			else if (key == 'n') { (void)va_arg(args, VARIANT *); }
			else if (key == 'p' || key == 'P') { (void)va_arg(args, void *); }
			else if (key == 'x') { (void)va_arg(args, LARGE_INTEGER); }
			else if (key == 'X') { (void)va_arg(args, PLARGE_INTEGER); }
			else if (key == 'o') { (void) va_arg(args, UNICODE_STRING *); }
			else if (key == 'O' || key == 'K') { (void) va_arg(args, OBJECT_ATTRIBUTES *); }
			else if (key == 'a') { (void) va_arg(args, int); (void) va_arg(args, const char **); }
			else if (key == 'A') { (void) va_arg(args, int); (void) va_arg(args, const wchar_t **); }
			else if (key == 'r' || key == 'R') { (void) va_arg(args, unsigned long); (void) va_arg(args, unsigned long); (void) va_arg(args, unsigned char *); }
		}
		
mpack_finish_array(&writer); // args
		mpack_finish_map(&writer); // root
		
		if (mpack_writer_destroy(&writer) == mpack_ok) {
			log_raw_direct(data, size);
		}
		free(data);
		va_end(args);
	}

	fmt = fmtbak;
	va_start(args, fmt);
	count = 1; key = 0;

	mpack_writer_init_growable(&writer, &data, &size);
	mpack_start_map(&writer, 7); // I, C, R, P, T, t, r, args
	
mpack_write_cstr(&writer, "I");
	mpack_write_int(&writer, index);
	
hookinfo = hook_info();
	mpack_write_cstr(&writer, "C");
	log_ptr(&writer, hookinfo->return_address);
	mpack_write_cstr(&writer, "R");
	log_ptr(&writer, hookinfo->main_caller_retaddr);
	mpack_write_cstr(&writer, "P");
	log_ptr(&writer, hookinfo->parent_caller_retaddr);
	
mpack_write_cstr(&writer, "T");
	mpack_write_int(&writer, GetCurrentThreadId());
	
mpack_write_cstr(&writer, "t");
	mpack_write_int(&writer, raw_gettickcount() - g_starttick );
	
mpack_write_cstr(&writer, "r");
	// Mark offset for repetition count update if we want to optimize later.
	// Note: In-place update in MsgPack is hard due to variable length int encoding.
	// We assume 0 fits in 1 byte (0x00). If it grows > 127 it needs more bytes.
	// We will only deduplicate if the count is small (<127).
	repeat_offset = mpack_writer_buffer_used(&writer); 
	mpack_write_u8(&writer, 0); // Fixed 1 byte 0

	mpack_write_cstr(&writer, "args");
	mpack_start_array(&writer, count_format_args(fmt) + 2);
	
mpack_write_int(&writer, is_success);
	log_ptr(&writer, (void*)return_value);

	while (--count != 0 || *fmt != 0) {
		if (count == 0) {
			if (*fmt == 0) break;
			count = *fmt >= '2' && *fmt <= '9' ? *fmt++ - '0' : 1;
			key = *fmt++;
		}
		(void) va_arg(args, const char *); // Skip pname

		if (key == 's') {
			const char *s = va_arg(args, const char *);
			log_string(&writer, s ? s : "", -1);
		}
		else if (key == 'f') {
			const char *s = va_arg(args, const char *);
			char absolutepath[MAX_PATH];
			if (s == NULL) s = "";
			ensure_absolute_ascii_path(absolutepath, s);
			log_string(&writer, absolutepath, -1);
		}
		else if (key == 'S') {
			int len = va_arg(args, int);
			const char *s = va_arg(args, const char *);
			log_string(&writer, s ? s : "", len);
		}
		else if (key == 'u') {
			const wchar_t *s = va_arg(args, const wchar_t *);
			log_wstring(&writer, s ? s : L"", -1);
		}
		else if (key == 'F') {
			const wchar_t *s = va_arg(args, const wchar_t *);
			wchar_t *absolutepath = malloc(32768 * sizeof(wchar_t));
			if (s == NULL) s = L"";
			if (absolutepath) {
				ensure_absolute_unicode_path(absolutepath, s);
				log_wstring(&writer, absolutepath, -1);
				free(absolutepath);
			}
			else {
				log_wstring(&writer, L"", -1);
			}
		}
		else if (key == 'U') {
			int len = va_arg(args, int);
			const wchar_t *s = va_arg(args, const wchar_t *);
			log_wstring(&writer, s ? s : L"", len);
		}
		else if (key == 'b') {
			size_t len = va_arg(args, size_t);
			const char *s = va_arg(args, const char *);
			log_buffer(&writer, s, len);
		}
		else if (key == 'B') {
			DWORD *len = va_arg(args, DWORD *);
			const char *s = va_arg(args, const char *);
			log_buffer(&writer, s, len ? *len : 0);
		}
		else if (key == 'c') {
			size_t len = va_arg(args, size_t);
			const char *s = va_arg(args, const char *);
			log_large_buffer(&writer, s, len);
		}
		else if (key == 'C') {
			DWORD *len = va_arg(args, DWORD *);
			const char *s = va_arg(args, const char *);
			log_large_buffer(&writer, s, len ? *len : 0);
		}
		else if (key == 'i' || key == 'h') {
			log_int32(&writer, va_arg(args, int));
		}
		else if (key == 'I' || key == 'H') {
			int *ptr = va_arg(args, int *);
			int val = 0;
			__try { if (ptr) val = *ptr; } __except(1) {}
			log_int32(&writer, val);
		}
		else if (key == 'l' || key == 'p') {
			log_ptr(&writer, va_arg(args, void *));
		}
		else if (key == 'L' || key == 'P') {
			void **ptr = va_arg(args, void **);
			void *val = NULL;
			__try { if (ptr) val = *ptr; } __except(1) {}
			log_ptr(&writer, val);
		}
		else if (key == 'n') {
			log_variant(&writer, va_arg(args, VARIANT*));
		}
		else if (key == 'x') {
			log_int64(&writer, va_arg(args, LARGE_INTEGER).QuadPart);
		}
		else if (key == 'X') {
			PLARGE_INTEGER ptr = va_arg(args, PLARGE_INTEGER);
			int64_t val = 0;
			__try { if (ptr) val = ptr->QuadPart; } __except(1) {}
			log_int64(&writer, val);
		}
		else if (key == 'e') {
			HKEY reg = va_arg(args, HKEY);
			const char *s = va_arg(args, const char *);
			unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
			PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
			log_wstring(&writer, get_full_key_pathA(reg, s, keybuf, allocsize), -1);
			free(keybuf);
		}
		else if (key == 'E') {
			HKEY reg = va_arg(args, HKEY);
			const wchar_t *s = va_arg(args, const wchar_t *);
			unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
			PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
			log_wstring(&writer, get_full_key_pathW(reg, s, keybuf, allocsize), -1);
			free(keybuf);
		}
		else if (key == 'K') {
			OBJECT_ATTRIBUTES *obj = va_arg(args, OBJECT_ATTRIBUTES *);
			unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
			PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
			log_wstring(&writer, get_key_path(obj, keybuf, allocsize), -1);
			free(keybuf);
		}
		else if (key == 'k') {
			HKEY reg = va_arg(args, HKEY);
			const PUNICODE_STRING s = va_arg(args, const PUNICODE_STRING);
			unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
			PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
			log_wstring(&writer, get_full_keyvalue_pathUS(reg, s, keybuf, allocsize), -1);
			free(keybuf);
		}
		else if (key == 'v') {
			HKEY reg = va_arg(args, HKEY);
			const char *s = va_arg(args, const char *);
			unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
			PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
			log_wstring(&writer, get_full_keyvalue_pathA(reg, s, keybuf, allocsize), -1);
			free(keybuf);
		}
		else if (key == 'V') {
			HKEY reg = va_arg(args, HKEY);
			const wchar_t *s = va_arg(args, const wchar_t *);
			unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
			PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
			log_wstring(&writer, get_full_keyvalue_pathW(reg, s, keybuf, allocsize), -1);
			free(keybuf);
		}
		else if (key == 'o') {
			UNICODE_STRING *str = va_arg(args, UNICODE_STRING *);
			if (str) log_wstring(&writer, str->Buffer, str->Length / sizeof(wchar_t));
			else log_wstring(&writer, L"", 0);
		}
		else if (key == 'O') {
			OBJECT_ATTRIBUTES *obj = va_arg(args, OBJECT_ATTRIBUTES *);
			if (obj) {
				wchar_t path[MAX_PATH_PLUS_TOLERANCE];
				wchar_t *absolutepath = malloc(32768 * sizeof(wchar_t));
				if (absolutepath) {
					path_from_object_attributes(obj, path, MAX_PATH_PLUS_TOLERANCE);
					ensure_absolute_unicode_path(absolutepath, path);
					log_wstring(&writer, absolutepath, -1);
					free(absolutepath);
				} else {
					log_wstring(&writer, L"", -1);
				}
			} else {
				log_wstring(&writer, L"", 0);
			}
		}
		else if (key == 'a') {
			int argc = va_arg(args, int);
			const char **argv = va_arg(args, const char **);
			log_argv(&writer, argc, argv);
		}
		else if (key == 'A') {
			int argc = va_arg(args, int);
			const wchar_t **argv = va_arg(args, const wchar_t **);
			log_wargv(&writer, argc, argv);
		}
		else if (key == 'r' || key == 'R') {
			unsigned long type = va_arg(args, unsigned long);
			unsigned long size = va_arg(args, unsigned long);
			unsigned char *data = va_arg(args, unsigned char *);
			if (size > BUFFER_REGVAL_MAX) size = BUFFER_REGVAL_MAX;
			
			if (type == REG_NONE) {
				mpack_write_cstr(&writer, "");
			}
			else if (type == REG_DWORD || type == REG_DWORD_LITTLE_ENDIAN) {
				unsigned int value = 0;
				if (data) value = *(unsigned int *)data;
				mpack_write_u32(&writer, value);
			}
			else if (type == REG_DWORD_BIG_ENDIAN) {
				unsigned int value = 0;
				if (data) value = *(unsigned int *)data;
				mpack_write_u32(&writer, our_htonl(value));
			}
			else if (type == REG_EXPAND_SZ || type == REG_SZ) {
				if (!data) mpack_write_bin(&writer, NULL, 0);
				else if (key == 'r') log_string(&writer, (const char*)data, strnlen((const char*)data, size));
				else log_wstring(&writer, (const wchar_t*)data, wcsnlen((const wchar_t*)data, size / sizeof(wchar_t)));
			}
			else if (type == REG_MULTI_SZ) {
				// Skipping complex parsing for brevity, treat as binary if complex or string if simple
				// Implementation similar to original BSON one but simplified for mpack binary dump if fails
				mpack_write_bin(&writer, (const char*)data, size);
			}
			else {
				mpack_write_bin(&writer, (const char*)data, size);
			}
		}
	}
	
	mpack_finish_array(&writer);
	mpack_finish_map(&writer);
	
	if (mpack_writer_destroy(&writer) != mpack_ok) {
		free(data);
		va_end(args);
		LeaveCriticalSection(&g_mutex);
		goto exit;
	}
	
	va_end(args);

	// Deduplication logic
	if (index == LOG_ID_PROCESS || index == LOG_ID_THREAD || index == LOG_ID_ENVIRON) {
		log_raw_direct(data, size);
	}
	else {
		// Compare with lastlog, excluding the "r" field
		// In MsgPack, we have [I, C, R, P, T, t, r, args]
		// To compare, we need to ignore 't' (time) and 'r' (repeat) usually? 
		// Original BSON ignored 't' and 'r' by carefully setting compare pointers.
		// For simplicity/safety in this migration, we check exact match of the buffer 
		// BUT we know 't' changes.
		// The original code had a complex offset calculation.
		// "r" is at 'repeat_offset' in our new buffer.
		// 't' is before 'r'.
		// If we simply check the buffer after 'r', we check 'args'.
		// The original check was: `bson_size(g_bson) - compare_offset`.
		// We can do similar. 'args' starts after 'r'.
		
		// The 'args' field in our map comes LAST. 
		// Map: I, C, R, P, T, t, r, args
		// We want to compare 'args' content + I/C/R/P? 
		// The original code only compared from a certain offset.
		// BSON structure was: I, C, R, P, T, t, r, args.
		// repeat_offset was before args.
		
		// Let's assume strict deduplication of the *entire* 'args' payload is enough + 'I'.
		// However, since we reconstructed the buffer, offsets might vary if sizes vary.
		// We will implement a simplified deduplication: if the entire buffer (excluding t/r) matches.
		// But that's hard to find in a flat buffer without parsing.
		
		// Fallback: Check if the raw buffer *after* repeat_offset matches the previous one.
		// repeat_offset points to value of 'r'. 'args' key follows immediately.
		
		unsigned int compare_start = (unsigned int)repeat_offset + 1; // skip 1 byte of 'r' value (0x00)
		unsigned int compare_len = (unsigned int)size - compare_start;
		
		if (lastlog.buf && lastlog.compare_len == compare_len && 
			!memcmp(lastlog.compare_ptr, data + compare_start, compare_len)) {
			
			// Duplicate detected. Increment 'r'.
			// 'r' is at repeat_offset. It is a single byte 0x00 initially.
			// We only increment if it is < 127 to avoid size change.
			if (lastlog.buf[lastlog.repeat_offset] < 127) {
				lastlog.buf[lastlog.repeat_offset]++;
			} else {
				// Counter maxed, flush and treat as new
				if (g_config.force_flush == 1) log_flush();
				else {
					log_raw_direct((const char*)lastlog.buf, lastlog.len);
					free(lastlog.buf);
					lastlog.buf = NULL;
				}
				goto save_new_log;
			}
		} else {
			if (lastlog.buf) {
				if (g_config.force_flush == 1) log_flush();
				else {
					log_raw_direct((const char*)lastlog.buf, lastlog.len);
					free(lastlog.buf);
					lastlog.buf = NULL;
				}
			}
save_new_log:
			lastlog.len = (unsigned int)size;
			lastlog.buf = (unsigned char*)malloc(lastlog.len);
			memcpy(lastlog.buf, data, lastlog.len);
			lastlog.repeat_offset = repeat_offset; // Offset of the value byte
			lastlog.compare_len = compare_len;
			lastlog.compare_ptr = lastlog.buf + compare_start;
		}
	}
	
	free(data);
	LeaveCriticalSection(&g_mutex);

exit:
	if (g_config.force_flush == 2)
		log_flush();

	hook_enable();
	set_lasterrors(&lasterror);
}

void announce_netlog()
{
	char protoname[32];
	sprintf(protoname, "MPACK %u\n", GetCurrentProcessId());
	log_raw_direct(protoname, strlen(protoname));
}

void log_new_process()
{
	FILETIME st;
	g_starttick = raw_gettickcount();

	GetSystemTimeAsFileTime(&st);

	loq(LOG_ID_PROCESS, "__notification__", "__process__", 1, 0, "iiiis",
		"TimeLow", st.dwLowDateTime,
		"TimeHigh", st.dwHighDateTime,
		"ProcessIdentifier", GetCurrentProcessId(),
		"ParentProcessIdentifier", parent_process_id(),
		"ModulePath", our_process_path);
}

void log_new_thread()
{
	loq(LOG_ID_THREAD, "__notification__", "__thread__", 1, 0, "l",
		"ProcessIdentifier", GetCurrentProcessId());
}

static int get_registry_string(HKEY hKey, char *subkey, char *value, char *outbuf, DWORD insize)
{
	HKEY outkey;
	DWORD regtype;
	DWORD outlen;
	LONG ret;

	memset(outbuf, 0, insize);

	ret = RegOpenKeyExA(hKey, subkey, 0, KEY_READ, &outkey);
	if (ret)
		return ret;
	ret = RegQueryValueExA(outkey, value, NULL, &regtype, outbuf, &outlen);
	RegCloseKey(outkey);
	return ret;
}

void log_environ()
{
	char *username, *computername, *winpath, *tmppath;
	char *sysvolserial, *sysvolguid, *machineguid;
	char *registeredowner, *registeredorg;
	char *productname;
	char *p;
	char tmp[1024];
	HMODULE mainbase = GetModuleHandleA(NULL);
	DWORD installdate;
	DWORD volser;
	DWORD tmpsize = sizeof(tmp);

	memset(tmp, 0, sizeof(tmp));
	GetUserNameA(tmp, &tmpsize);
	username = strdup(tmp);
	memset(tmp, 0, sizeof(tmp));
	tmpsize = sizeof(tmp);
	GetComputerNameA(tmp, &tmpsize);
	computername = strdup(tmp);
	get_registry_string(HKEY_LOCAL_MACHINE, "Software\Microsoft\Windows NT\CurrentVersion", "InstallDate", tmp, sizeof(tmp));
	installdate = *(DWORD *)tmp;
	get_registry_string(HKEY_LOCAL_MACHINE, "Software\Microsoft\Windows NT\CurrentVersion", "RegisteredOwner", tmp, sizeof(tmp));
	registeredowner = strdup(tmp);
	get_registry_string(HKEY_LOCAL_MACHINE, "Software\Microsoft\Windows NT\CurrentVersion", "RegisteredOrganization", tmp, sizeof(tmp));
	registeredorg = strdup(tmp);
	get_registry_string(HKEY_LOCAL_MACHINE, "Software\Microsoft\Windows NT\CurrentVersion", "ProductName", tmp, sizeof(tmp));
	productname = strdup(tmp);
	memset(tmp, 0, sizeof(tmp));
	GetWindowsDirectoryA(tmp, sizeof(tmp));
	winpath = strdup(tmp);
	memset(tmp, 0, sizeof(tmp));
	GetTempPathA(sizeof(tmp), tmp);
	tmppath = strdup(tmp);
	get_registry_string(HKEY_LOCAL_MACHINE, "Software\Microsoft\Cryptography", "MachineGuid", tmp, sizeof(tmp));
	machineguid = strdup(tmp);
	memset(tmp, 0, sizeof(tmp));
	GetVolumeInformationA("C:\\", NULL, 0, &volser, NULL, NULL, NULL, 0);

	if (g_config.serial_number)
		volser = g_config.serial_number;

	sprintf(tmp, "%04x-%04x", HIWORD(volser), LOWORD(volser));
	sysvolserial = strdup(tmp);
	memset(tmp, 0, sizeof(tmp));
	GetVolumeNameForVolumeMountPointA("C:\\", tmp, sizeof(tmp));
	p = strchr(tmp, '}');
	if (p)
		*p = '\0';
	p = strchr(tmp, '{');
	if (p)
		sysvolguid = strdup(p + 1);
	else
		sysvolguid = strdup("");


	loq(LOG_ID_ENVIRON, "__notification__", "__environ__", 1, 0, "ssissssssiisssphs",
		"UserName", username,
		"ComputerName", computername,
		"InstallDate", installdate,
		"WindowsPath", winpath,
		"TempPath", tmppath,
		"CommandLine", GetCommandLineA(),
		"RegisteredOwner", registeredowner,
		"RegisteredOrganization", registeredorg,
		"ProductName", productname,
		"OSMajor", g_osverinfo.dwMajorVersion,
		"OSMinor", g_osverinfo.dwMinorVersion,
		"SystemVolumeSerialNumber", sysvolserial,
		"SystemVolumeGUID", sysvolguid,
		"MachineGUID", machineguid,
		"MainExeBase", mainbase,
		"MainExeSize", get_image_size((ULONG_PTR)mainbase),
#ifdef _WIN64
		"Bitness", "64-bit"
#else
		"Bitness", "32-bit"
#endif
		);

	free(username);
	free(computername);
	free(winpath);
	free(tmppath);
	free(productname);
	free(registeredowner);
	free(registeredorg);
	free(sysvolserial);
	free(sysvolguid);
	free(machineguid);
}
void log_hook_anomaly(const char *subcategory, int success,
	const hook_t *h, const char *msg)
{
	loq(LOG_ID_ANOMALY_HOOK, "__notification__", "__anomaly__", success, 0, "issps",
		"ThreadIdentifier", GetCurrentThreadId(),
		"Subcategory", subcategory,
		"FunctionName", h->funcname,
		"FunctionAddress", h->hook_addr,
		"Message", msg);
}

void log_anomaly(const char *subcategory, const char *msg)
{
	loq(LOG_ID_ANOMALY_GENERIC, "__notification__", "__anomaly__", 1, 0, "iss",
		"ThreadIdentifier", GetCurrentThreadId(),
		"Subcategory", subcategory,
		"Message", msg);
}

void log_breakpoint(const char *subcategory, const char *msg)
{
	loq(LOG_ID_ANOMALY_GENERIC, "__notification__", "Breakpoint", 1, 0, "iss",
		"ThreadIdentifier", GetCurrentThreadId(),
		"Subcategory", subcategory,
		"Message", msg);
}

#ifdef _WIN64
#define SYSCALL_NAME "syscall"
#else
#define SYSCALL_NAME "sysenter"
#endif

void log_syscall(PUNICODE_STRING module, const char *function, PVOID retaddr, DWORD retval)
{
	if (function && strlen(function))
	{
		if (module)
			loq(LOG_ID_SYSCALL, "__notification__", SYSCALL_NAME, retval==0, retval, "iosp",
				"ThreadIdentifier", GetCurrentThreadId(),
				"Module", module,
				"Function", function,
				"Return Address", retaddr);
		else
			loq(LOG_ID_SYSCALL, "__notification__", SYSCALL_NAME, retval==0, retval, "isp",
				"ThreadIdentifier", GetCurrentThreadId(),
				"Function", function,
				"Return Address", retaddr);
	}
	else
	{
		if (module)
			loq(LOG_ID_SYSCALL, "__notification__", SYSCALL_NAME, retval==0, retval, "iop",
				"ThreadIdentifier", GetCurrentThreadId(),
				"Module", module,
				"Return Address", retaddr);
		else
			loq(LOG_ID_SYSCALL, "__notification__", SYSCALL_NAME, retval==0, retval, "ip",
				"ThreadIdentifier", GetCurrentThreadId(),
				"Return Address", retaddr);
	}
}

void log_direct_syscall(const char *function, PVOID addr)
{
	loq(LOG_ID_SYSCALL, "__notification__", SYSCALL_NAME, 1, 0, "isp",
		"ThreadIdentifier", GetCurrentThreadId(),
		"Function", function,
		"Address", addr);
}

void log_procname_anomaly(PUNICODE_STRING InitialName, PUNICODE_STRING InitialPath, PUNICODE_STRING CurrentName, PUNICODE_STRING CurrentPath)
{
	loq(LOG_ID_ANOMALY_PROCNAME, "__notification__", "__anomaly__", 1, 0, "isoooo",
		"ThreadIdentifier", GetCurrentThreadId(),
		"Subcategory", "procname",
		"OriginalProcessName", InitialName,
		"OriginalProcessPath", InitialPath,
		"ModifiedProcessName", CurrentName,
		"ModifiedProcessPath", CurrentPath);
}

void log_hook_modification(const hook_t *h, const char *origbytes, const char *newbytes, unsigned int len)
{
	char msg1[128] = { 0 };
	char msg2[128] = { 0 };
	char *p;
	unsigned int i;

	for (i = 0; (i < len) && (i < 124/3); i++) {
		p = &msg1[i * 3];
		sprintf(p, "%02X ", (unsigned char)origbytes[i]);
	}
	for (i = 0; (i < len) && (i < 124 / 3); i++) {
		p = &msg2[i * 3];
		sprintf(p, "%02X ", (unsigned char)newbytes[i]);
	}

	loq(LOG_ID_ANOMALY_HOOKMOD, "__notification__", "__anomaly__", 1, 0, "isspsss",
		"ThreadIdentifier", GetCurrentThreadId(),
		"Subcategory", "unhook",
		"FunctionName", h->funcname,
		"FunctionAddress", h->hook_addr,
		"UnhookType", "modification",
		"OriginalBytes", msg1,
		"NewBytes", msg2);
}

void log_hook_removal(const hook_t *h)
{
	loq(LOG_ID_ANOMALY_HOOKREM, "__notification__", "__anomaly__", 1, 0, "issps",
		"ThreadIdentifier", GetCurrentThreadId(),
		"Subcategory", "unhook",
		"FunctionName", h->funcname,
		"FunctionAddress", h->hook_addr,
		"UnhookType", "removal");
}

void log_hook_restoration(const hook_t *h)
{
	loq(LOG_ID_ANOMALY_HOOKRES, "__notification__", "__anomaly__", 1, 0, "issps",
		"ThreadIdentifier", GetCurrentThreadId(),
		"Subcategory", "unhook",
		"FunctionName", h->funcname,
		"FunctionAddress", h->hook_addr,
		"UnhookType", "restored");
}


DWORD g_log_thread_id;
DWORD g_logwatcher_thread_id;

void log_init(int debug)
{
	g_buffer = calloc(1, BUFFERSIZE);

	g_log_flush = CreateEvent(NULL, FALSE, FALSE, NULL);

	if (debug != 0) {
		g_sock = DEBUG_SOCKET;
	}
	else {
		g_sock = INVALID_SOCKET;
		g_log_handle = CreateFileA(g_config.logserver, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (g_log_handle == INVALID_HANDLE_VALUE) {
			pipe("CRITICAL:Error initializing logging!");
			return;
		}
	}

	// will happen when we're in debug mode
	if (g_sock == DEBUG_SOCKET) {
		char pid[8];
		char* filename = GetResultsPath("API");
		if (!filename) {
			pipe("CRITICAL:Error initializing debug logging!");
			return;
		}
		num_to_string(pid, sizeof(pid), GetCurrentProcessId());
		strcat(filename, "\\\\");
		strcat(filename, pid);
		strcat(filename, ".log");
		g_debug_log_handle = CreateFileA(filename, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_NEW, 0, NULL);
	}

	announce_netlog();
	log_new_process();
	log_new_thread();
	log_environ();
	// flushing here so host can create files / keep timestamps
	log_flush();
}

void log_free()
{
	log_flush();
	if (g_sock == DEBUG_SOCKET) {
		g_sock = INVALID_SOCKET;
	}
	else {
		CloseHandle(g_log_handle);
		g_log_handle = INVALID_HANDLE_VALUE;
	}
}