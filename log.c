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
#include "bson.h"
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

// current to-be-logged API call
static bson g_bson[1];
static char g_istr[4];

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

	while (copiedlen != length) {
		EnterCriticalSection(&g_writing_log_buffer_mutex);
		copylen = min(length - copiedlen, (size_t)(BUFFERSIZE - g_idx));
		memcpy(&g_buffer[g_idx], &buf[copiedlen], copylen);
		g_idx += (int)copylen;
		copiedlen += copylen;
		LeaveCriticalSection(&g_writing_log_buffer_mutex);
		if (copiedlen != length && g_buffer)
			_send_log();
	}
}

void log_flush()
{
	/* The logging thread we create in DllMain won't actually start until after DllMain
	completes, so we need to ensure we don't wait here on the logging thread as it will
	result in a deadlock.
	There's thus an implicit assumption here that we won't log more than BUFFERSIZE before
	DllMain completes, otherwise we'll lose logs.
	*/
	//if (g_dll_main_complete && !process_shutting_down) {
	//	SetEvent(g_log_flush);
	//	while (g_idx && (g_sock != INVALID_SOCKET)) raw_sleep(50);
	//}
	//else {
	/* if we're in main() still, then send the logs immediately just in case something bad
	happens early in execution of the malware's code
	*/

	//}
	// we might get called by the pipe() code trying to flush logs before logging is
	// actually initialized, so avoid any nastiness on trying to use unitialized
	// critical sections

	if (!TryEnterCriticalSection(&g_mutex))
		return;

	if (lastlog.buf) {
		log_raw_direct(lastlog.buf, lastlog.len);
		free(lastlog.buf);
		lastlog.buf = NULL;
	}
	LeaveCriticalSection(&g_mutex);

	if (g_buffer)
		_send_log();
}

void debug_message(const char *msg) {
	bson b[1];
	bson_init( b );
	bson_append_string( b, "type", "debug" );
	bson_append_string( b, "msg", msg );
	bson_finish( b );
	log_raw_direct(bson_data( b ), bson_size( b ));
	bson_destroy( b );
	log_flush();
}

/*
static void log_int8(char value)
{
	bson_append_int( g_bson, g_istr, value );
}

static void log_int16(short value)
{
	bson_append_int( g_bson, g_istr, value );
}
*/

static int bson_append_ptr(bson *b, const char *name, ULONG_PTR ptr)
{
	if (sizeof(ULONG_PTR) == 8)
		return bson_append_long(b, name, ptr);
	else
		return bson_append_int(b, name, (int)ptr);
}

static void log_int32(int value)
{
	bson_append_int( g_bson, g_istr, value );
}

static void log_int64(int64_t value)
{
	bson_append_long(g_bson, g_istr, value);
}

static void log_ptr(void *value)
{
	if (sizeof(ULONG_PTR) == 8)
		log_int64((int64_t)value);
	else
		log_int32((int)(ULONG_PTR)value);
}

static void log_string(const char *str, int length)
{
	int ret;
	char *utf8s;
	int utf8len;

	if (str == NULL) {
		bson_append_string_n( g_bson, g_istr, "", 0 );
		return;
	}
	utf8s = utf8_string(str, length);
	utf8len = * (int *) utf8s;
	ret = bson_append_binary( g_bson, g_istr, BSON_BIN_BINARY, utf8s+4, utf8len );
	if (ret == BSON_ERROR) {
		bson_append_string_n(g_bson, g_istr, "", 0);
	}
	free(utf8s);
}

static void log_wstring(const wchar_t *str, int length)
{
	int ret;
	char *utf8s;
	int utf8len;

	if (str == NULL) {
		bson_append_string_n( g_bson, g_istr, "", 0 );
		return;
	}
	utf8s = utf8_wstring(str, length);
	utf8len = * (int *) utf8s;
	ret = bson_append_binary( g_bson, g_istr, BSON_BIN_BINARY, utf8s+4, utf8len );
	if (ret == BSON_ERROR) {
		bson_append_string_n(g_bson, g_istr, "", 0);
	}
	free(utf8s);
}

static void log_argv(int argc, const char ** argv) {
	int i;

	bson_append_start_array( g_bson, g_istr );

	for (i = 0; i < argc; i++) {
		num_to_string(g_istr, 4, i);
		log_string(argv[i], -1);
	}
	bson_append_finish_array( g_bson );
}

static void log_wargv(int argc, const wchar_t ** argv) {
	int i;

	bson_append_start_array( g_bson, g_istr );

	for (i = 0; i < argc; i++) {
		num_to_string(g_istr, 4, i);
		log_wstring(argv[i], -1);
	}

	bson_append_finish_array( g_bson );
}

static void log_buffer(const char *buf, size_t length) {
	size_t trunclength = min(length, buffer_log_max);

	if (buf == NULL) {
		trunclength = 0;
	}

	bson_append_binary( g_bson, g_istr, BSON_BIN_BINARY, buf, trunclength );
}

static void log_large_buffer(const char *buf, size_t length) {
	size_t trunclength = min(length, large_buffer_log_max);

	if (buf == NULL) {
		trunclength = 0;
	}

	bson_append_binary(g_bson, g_istr, BSON_BIN_BINARY, buf, trunclength);
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

void loq(int index, const char *category, const char *name,
	int is_success, ULONG_PTR return_value, const char *fmt, ...)
{
	va_list args;
	const char * fmtbak = fmt;
	int argnum = 2;
	int count = 1; char key = 0;
	unsigned int repeat_offset = 0;
	unsigned int compare_offset = 0;
	lasterror_t lasterror;
	hook_info_t *hookinfo;

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
		bson b[1];

		logtbl_explained[index] = 1;

		va_start(args, fmt);

		bson_init( b );
		bson_append_int( b, "I", index );
		bson_append_string( b, "name", name );
		bson_append_string( b, "type", "info" );
		bson_append_string( b, "category", category );

		bson_append_start_array( b, "args" );
		bson_append_string( b, "0", "is_success" );
		bson_append_string( b, "1", "retval" );

		while (--count != 0 || *fmt != 0) {
			// we have to find the next format specifier
			if (count == 0) {
				// end of format
				if (*fmt == 0) break;

				// set the count, possibly with a repeated format specifier
				count = *fmt >= '2' && *fmt <= '9' ? *fmt++ - '0' : 1;

				// the next format specifier
				key = *fmt++;
			}

			pname = va_arg(args, const char *);
			num_to_string(g_istr, 4, argnum);
			argnum++;

			//on certain formats, we need to tell cuckoo about them for nicer display / matching
			if (key == 'p' || key == 'P' || key == 'h' || key == 'H') {
				const char *typestr;
				if (key == 'h' || key == 'H' || sizeof(ULONG_PTR) != 8)
					typestr = "h";
				else
					typestr = "p";

				bson_append_start_array( b, g_istr );
				bson_append_string( b, "0", pname );
				bson_append_string( b, "1", typestr );
				bson_append_finish_array( b );
			}
			else if (key == 'x' || key == 'X') {
				bson_append_start_array(b, g_istr);
				bson_append_string(b, "0", pname);
				bson_append_string(b, "1", "p");
				bson_append_finish_array(b);
			} else {
				bson_append_string( b, g_istr, pname );
			}

			//now ignore the values
			if (key == 's' || key == 'f') {
				(void) va_arg(args, const char *);
			}
			else if (key == 'S') {
				(void) va_arg(args, int);
				(void) va_arg(args, const char *);
			}
			else if (key == 'u' || key == 'F') {
				(void) va_arg(args, const wchar_t *);
			}
			else if (key == 'U') {
				(void) va_arg(args, int);
				(void) va_arg(args, const wchar_t *);
			}
			else if (key == 'e' || key == 'v') {
				(void)va_arg(args, HKEY);
				(void)va_arg(args, const char *);
			}
			else if (key == 'E' || key == 'V') {
				(void)va_arg(args, HKEY);
				(void)va_arg(args, const wchar_t *);
			}
			else if (key == 'k') {
				(void)va_arg(args, HKEY);
				(void)va_arg(args, const PUNICODE_STRING);
			}
			else if (key == 'b' || key == 'c') {
				(void) va_arg(args, size_t);
				(void) va_arg(args, const char *);
			}
			else if (key == 'B' || key == 'C') {
				(void) va_arg(args, size_t *);
				(void) va_arg(args, const char *);
			}
			else if (key == 'i' || key == 'h') {
				(void) va_arg(args, int);
			}
			else if (key == 'I' || key == 'H') {
				(void) va_arg(args, int *);
			}
			else if (key == 'l' || key == 'L') {
				(void)va_arg(args, ULONG_PTR);
			}
			else if (key == 'p' || key == 'P') {
				(void)va_arg(args, void *);
			}
			else if (key == 'x') {
				(void)va_arg(args, LARGE_INTEGER);
			}
			else if (key == 'X') {
				(void)va_arg(args, PLARGE_INTEGER);
			}
			else if (key == 'o') {
				(void) va_arg(args, UNICODE_STRING *);
			}
			else if (key == 'O' || key == 'K') {
				(void) va_arg(args, OBJECT_ATTRIBUTES *);
			}
			else if (key == 'a') {
				(void) va_arg(args, int);
				(void) va_arg(args, const char **);
			}
			else if (key == 'A') {
				(void) va_arg(args, int);
				(void) va_arg(args, const wchar_t **);
			}
			else if (key == 'r' || key == 'R') {
				(void) va_arg(args, unsigned long);
				(void) va_arg(args, unsigned long);
				(void) va_arg(args, unsigned char *);
			}
			else {
				pipe("CRITICAL:Unknown format string character %c", key);
			}

		}
		bson_append_finish_array( b );
		bson_finish( b );
		log_raw_direct(bson_data( b ), bson_size( b ));
		bson_destroy( b );
		// log_flush();
		va_end(args);
	}

	fmt = fmtbak;
	va_start(args, fmt);
	count = 1; key = 0; argnum = 2;

	bson_init( g_bson );
	bson_append_int( g_bson, "I", index );
	hookinfo = hook_info();
	bson_append_ptr(g_bson, "C", hookinfo->return_address);
	// return location of malware callsite
	bson_append_ptr(g_bson, "R", hookinfo->main_caller_retaddr);
	// return parent location of malware callsite
	bson_append_ptr(g_bson, "P", hookinfo->parent_caller_retaddr);
	bson_append_int(g_bson, "T", GetCurrentThreadId());
	bson_append_int(g_bson, "t", raw_gettickcount() - g_starttick );
	// number of times this log was repeated -- we'll modify this
	bson_append_int(g_bson, "r", 0);

	compare_offset = (unsigned int)(g_bson->cur - bson_data(g_bson));
	// the repeated value is encoded immediately before the stream we want to compare
	repeat_offset = compare_offset - 4;

	bson_append_start_array(g_bson, "args");
	bson_append_int( g_bson, "0", is_success );
	bson_append_ptr( g_bson, "1", return_value );


	while (--count != 0 || *fmt != 0) {

		// we have to find the next format specifier
		if (count == 0) {
			// end of format
			if (*fmt == 0) break;

			// set the count, possibly with a repeated format specifier
			count = *fmt >= '2' && *fmt <= '9' ? *fmt++ - '0' : 1;

			// the next format specifier
			key = *fmt++;
		}
		// pop the key and omit it
		(void) va_arg(args, const char *);
		num_to_string(g_istr, 4, argnum);
		argnum++;

		// log the value
		if (key == 's') {
			const char *s = va_arg(args, const char *);
			if (s == NULL) s = "";
			log_string(s, -1);
		}
		else if (key == 'f') {
			const char *s = va_arg(args, const char *);
			char absolutepath[MAX_PATH];
			if (s == NULL) s = "";
			ensure_absolute_ascii_path(absolutepath, s);

			log_string(absolutepath, -1);
		}
		else if (key == 'S') {
			int len = va_arg(args, int);
			const char *s = va_arg(args, const char *);
			if (s == NULL) { s = ""; len = 0; }
			log_string(s, len);
		}
		else if (key == 'u') {
			const wchar_t *s = va_arg(args, const wchar_t *);
			if (s == NULL) s = L"";
			log_wstring(s, -1);
		}
		else if (key == 'F') {
			const wchar_t *s = va_arg(args, const wchar_t *);
			wchar_t *absolutepath = malloc(32768 * sizeof(wchar_t));
			if (s == NULL) s = L"";
			if (absolutepath) {
				ensure_absolute_unicode_path(absolutepath, s);
				log_wstring(absolutepath, -1);
				free(absolutepath);
			}
			else {
				log_wstring(L"", -1);
			}
		}
		else if (key == 'U') {
			int len = va_arg(args, int);
			const wchar_t *s = va_arg(args, const wchar_t *);
			if (s == NULL) { s = L""; len = 0; }
			log_wstring(s, len);
		}
		else if (key == 'b') {
			size_t len = va_arg(args, size_t);
			const char *s = va_arg(args, const char *);
			log_buffer(s, len);
		}
		else if (key == 'B') {
			DWORD *len = va_arg(args, DWORD *);
			const char *s = va_arg(args, const char *);
			log_buffer(s, len == NULL ? 0 : *len);
		}
		else if (key == 'c') {
			size_t len = va_arg(args, size_t);
			const char *s = va_arg(args, const char *);
			log_large_buffer(s, len);
		}
		else if (key == 'C') {
			DWORD *len = va_arg(args, DWORD *);
			const char *s = va_arg(args, const char *);
			log_large_buffer(s, len == NULL ? 0 : *len);
		}
		else if (key == 'i' || key == 'h') {
			int value = va_arg(args, int);
			log_int32(value);
		}
		else if (key == 'I' || key == 'H') {
			int *ptr = va_arg(args, int *);
			int theval = 0;
			__try {
				if (ptr != NULL)
					theval = *ptr;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				;
			}
			log_int32(theval);
		}
		else if (key == 'l' || key == 'p') {
			void *value = va_arg(args, void *);
			log_ptr(value);
		}
		else if (key == 'L' || key == 'P') {
			void **ptr = va_arg(args, void **);
			void *theptr = NULL;

			__try {
				if (ptr != NULL)
					theptr = *ptr;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				;
			}
			log_ptr(theptr);
		}
		else if (key == 'x') {
			LARGE_INTEGER value = va_arg(args, LARGE_INTEGER);
			log_int64(value.QuadPart);
		}
		else if (key == 'X') {
			PLARGE_INTEGER ptr = va_arg(args, PLARGE_INTEGER);
			LARGE_INTEGER theval;

			theval.QuadPart = 0;

			__try {
				if (ptr != NULL)
					theval = *ptr;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				;
			}
			log_int64(theval.QuadPart);
		}
		else if (key == 'e') {
			HKEY reg = va_arg(args, HKEY);
			const char *s = va_arg(args, const char *);
			unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
			PKEY_NAME_INFORMATION keybuf = malloc(allocsize);

			log_wstring(get_full_key_pathA(reg, s, keybuf, allocsize), -1);
			free(keybuf);
		}
		else if (key == 'E') {
			HKEY reg = va_arg(args, HKEY);
			const wchar_t *s = va_arg(args, const wchar_t *);
			unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
			PKEY_NAME_INFORMATION keybuf = malloc(allocsize);

			log_wstring(get_full_key_pathW(reg, s, keybuf, allocsize), -1);
			free(keybuf);
		}
		else if (key == 'K') {
			OBJECT_ATTRIBUTES *obj = va_arg(args, OBJECT_ATTRIBUTES *);
			unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
			PKEY_NAME_INFORMATION keybuf = malloc(allocsize);

			log_wstring(get_key_path(obj, keybuf, allocsize), -1);
			free(keybuf);
		}
		else if (key == 'k') {
			HKEY reg = va_arg(args, HKEY);
			const PUNICODE_STRING s = va_arg(args, const PUNICODE_STRING);
			unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
			PKEY_NAME_INFORMATION keybuf = malloc(allocsize);

			log_wstring(get_full_keyvalue_pathUS(reg, s, keybuf, allocsize), -1);
			free(keybuf);
		}
		else if (key == 'v') {
			HKEY reg = va_arg(args, HKEY);
			const char *s = va_arg(args, const char *);
			unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
			PKEY_NAME_INFORMATION keybuf = malloc(allocsize);

			log_wstring(get_full_keyvalue_pathA(reg, s, keybuf, allocsize), -1);
			free(keybuf);
		}
		else if (key == 'V') {
			HKEY reg = va_arg(args, HKEY);
			const wchar_t *s = va_arg(args, const wchar_t *);
			unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
			PKEY_NAME_INFORMATION keybuf = malloc(allocsize);

			log_wstring(get_full_keyvalue_pathW(reg, s, keybuf, allocsize), -1);
			free(keybuf);
		}
		else if (key == 'o') {
			UNICODE_STRING *str = va_arg(args, UNICODE_STRING *);
			if (str == NULL) {
				log_string("", 0);
			}
			else {
				log_wstring(str->Buffer, str->Length / sizeof(wchar_t));
			}
		}
		else if (key == 'O') {
			OBJECT_ATTRIBUTES *obj = va_arg(args, OBJECT_ATTRIBUTES *);
			if (obj == NULL) {
				log_string("", 0);
			}
			else {
				wchar_t path[MAX_PATH_PLUS_TOLERANCE];
				wchar_t *absolutepath = malloc(32768 * sizeof(wchar_t));
				if (absolutepath) {
					path_from_object_attributes(obj, path, MAX_PATH_PLUS_TOLERANCE);

					ensure_absolute_unicode_path(absolutepath, path);
					log_wstring(absolutepath, -1);
					free(absolutepath);
				}
				else {
					log_wstring(L"", -1);
				}
			}
		}
		else if (key == 'a') {
			int argc = va_arg(args, int);
			const char **argv = va_arg(args, const char **);
			log_argv(argc, argv);
		}
		else if (key == 'A') {
			int argc = va_arg(args, int);
			const wchar_t **argv = va_arg(args, const wchar_t **);
			log_wargv(argc, argv);
		}
		else if (key == 'r' || key == 'R') {
			unsigned long type = va_arg(args, unsigned long);
			unsigned long size = va_arg(args, unsigned long);
			unsigned char *data = va_arg(args, unsigned char *);

			if (size > BUFFER_REGVAL_MAX)
				size = BUFFER_REGVAL_MAX;

			// bson_append_start_object( g_bson, g_istr );
			// bson_append_int( g_bson, "type", type );

			// strncpy(g_istr, "val", 4);
			if (type == REG_NONE) {
				log_string("", 0);
			}
			else if (type == REG_DWORD || type == REG_DWORD_LITTLE_ENDIAN) {
				unsigned int value = 0;
				if (data)
					value = *(unsigned int *)data;
				log_int32(value);
			}
			else if (type == REG_DWORD_BIG_ENDIAN) {
				unsigned int value = 0;
				if (data)
					value = *(unsigned int *)data;
				log_int32(our_htonl(value));
			}
			else if (type == REG_EXPAND_SZ || type == REG_SZ) {

				if (data == NULL) {
					bson_append_binary(g_bson, g_istr, BSON_BIN_BINARY,
						(const char *)data, 0);
				}
				// ascii strings
				else if (key == 'r') {
					int len = (int)strnlen(data, size);
					log_string(data, len);
				}
				// unicode strings
				else {
					const wchar_t *wdata = (const wchar_t *)data;
					int len = (int)wcsnlen(wdata, size / sizeof(wchar_t));
					log_wstring(wdata, len);
				}
			} else if (type == REG_MULTI_SZ) {
				if (data == NULL) {
					bson_append_binary(g_bson, g_istr, BSON_BIN_BINARY,
						(const char *)data, 0);
				}
				else if ((type == 'r' && size < 2) || (type == 'R' && size < 4))
					goto buffer_log;
				// ascii strings
				else if (key == 'r') {
					unsigned long i, x;
					unsigned int strcnt = 0;
					int found_doublenull = 0;
					char *p;
					int len;
					for (i = 0; i < size - 1; i++) {
						if (data[i] == '\0')
							strcnt++;
						if (data[i + 1] == '\0') {
							found_doublenull = 1;
							break;
						}
					}
					if (!found_doublenull)
						goto buffer_log;
					p = (char *)malloc(size + (strcnt * 4));
					if (p == NULL)
						goto buffer_log;
					for (i = 0, x = 0; i < size - 1; i++) {
						if (data[i] == '\0') {
							p[x++] = '\\';
							p[x++] = 'x';
							p[x++] = '0';
							p[x++] = '0';
							if (data[i + 1] == '\0') {
								p[x++] = '\0';
								break;
							}
						}
						else {
							p[x] = data[i];
						}
					}
					len = (int)strnlen(p, size + (strcnt * 4));
					log_string(p, len);
					free(p);
				}
				// unicode strings
				else {
					unsigned long i, x;
					unsigned int strcnt = 0;
					int found_doublenull = 0;
					const wchar_t *wdata = (const wchar_t *)data;
					wchar_t *p;
					int len;
					for (i = 0; i < (size/sizeof(wchar_t)) - 1; i++) {
						if (wdata[i] == L'\0')
							strcnt++;
						if (wdata[i + 1] == L'\0') {
							found_doublenull = 1;
							break;
						}
					}
					if (!found_doublenull)
						goto buffer_log;
					p = (wchar_t *)malloc(size + (strcnt * 4 * sizeof(wchar_t)));
					if (p == NULL)
						goto buffer_log;
					for (i = 0, x = 0; i < (size/sizeof(wchar_t)) - 1; i++) {
						if (wdata[i] == '\0') {
							p[x++] = L'\\';
							p[x++] = L'x';
							p[x++] = L'0';
							p[x++] = L'0';
							if (wdata[i + 1] == L'\0') {
								p[x++] = L'\0';
								break;
							}
						}
						else {
							p[x] = data[i];
						}
					}
					len = (int)wcsnlen(p, (size/sizeof(wchar_t)) + (strcnt * 4));
					log_wstring(p, len);
					free(p);
				}
			}
			else {
buffer_log:
				bson_append_binary(g_bson, g_istr, BSON_BIN_BINARY,
					(const char *) data, size);
			}

			// bson_append_finish_object( g_bson );
		}
	}

	va_end(args);

	bson_append_finish_array( g_bson );
	bson_finish( g_bson );

	if (index == LOG_ID_PROCESS || index == LOG_ID_THREAD || index == LOG_ID_ENVIRON) {
		// don't hold back any of our critical notifications -- these *must* be flushed in log_init()
		log_raw_direct(bson_data(g_bson), bson_size(g_bson));
	}
	else {
		if (lastlog.buf) {
			unsigned int our_len = bson_size(g_bson) - compare_offset;
			if (lastlog.compare_len == our_len && !memcmp(lastlog.compare_ptr, bson_data(g_bson) + compare_offset, our_len)) {
				// we're about to log a duplicate of the last log message, just increment the previous log's repeated count
				(*lastlog.repeated_ptr)++;
			}
			else {
				// flush logs once we're done seeing duplicates of a particular API
				if (g_config.force_flush == 1)
					log_flush();
				else {
					log_raw_direct(lastlog.buf, lastlog.len);
					free(lastlog.buf);
					lastlog.buf = NULL;
				}
			}
		}
		if (lastlog.buf == NULL) {
			lastlog.len = bson_size(g_bson);
			lastlog.buf = malloc(lastlog.len);
			memcpy(lastlog.buf, bson_data(g_bson), lastlog.len);
			lastlog.compare_len = lastlog.len - compare_offset;
			lastlog.compare_ptr = lastlog.buf + compare_offset;
			lastlog.repeated_ptr = (int *)(lastlog.buf + repeat_offset);
		}
	}

	bson_destroy( g_bson );
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
	sprintf(protoname, "BSON %u\n", GetCurrentProcessId());
	//sprintf(protoname+5, "logs/%lu.bson\n", GetCurrentProcessId());
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
	get_registry_string(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion", "InstallDate", tmp, sizeof(tmp));
	installdate = *(DWORD *)tmp;
	get_registry_string(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion", "RegisteredOwner", tmp, sizeof(tmp));
	registeredowner = strdup(tmp);
	get_registry_string(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion", "RegisteredOrganization", tmp, sizeof(tmp));
	registeredorg = strdup(tmp);
	get_registry_string(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion", "ProductName", tmp, sizeof(tmp));
	productname = strdup(tmp);
	memset(tmp, 0, sizeof(tmp));
	GetWindowsDirectoryA(tmp, sizeof(tmp));
	winpath = strdup(tmp);
	memset(tmp, 0, sizeof(tmp));
	GetTempPathA(sizeof(tmp), tmp);
	tmppath = strdup(tmp);
	get_registry_string(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Cryptography", "MachineGuid", tmp, sizeof(tmp));
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


	loq(LOG_ID_ENVIRON, "__notification__", "__environ__", 1, 0, "ssissssssiisssph",
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
		"MainExeSize", get_image_size((ULONG_PTR)mainbase)
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

void log_syscall(PUNICODE_STRING module, const char *function, PVOID retaddr, DWORD retval)
{
#ifdef _WIN64
	loq(LOG_ID_SYSCALL, "__notification__", "syscall", 1, 0, "iospp",
#else
	loq(LOG_ID_SYSCALL, "__notification__", "sysenter", 1, 0, "iospp",
#endif
		"ThreadIdentifier", GetCurrentThreadId(),
		"Module", module,
		"Function", function,
		"Return Address", retaddr,
		"Return Value", retval);
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
		strcat(filename, "\\");
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
