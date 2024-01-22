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

//
// Log API
//
// The Log takes a format string and parses the extra arguments accordingly
//
// The following Format Specifiers are available:
// s  -> (char *) -> zero-terminated string
// S  -> (int, char *) -> string with length
// f  -> (char *) -> zero-terminated ascii filename string (to be normalized)
// F  -> (wchar_t *) zero-terminated unicode filename string (to be normalized)
// u  -> (wchar_t *) -> zero-terminated unicode string
// U  -> (int, wchar_t *) -> unicode string with length
// b  -> (int, void *) -> memory with a given size (alias for S)
// B  -> (int *, void *) -> memory with a given size (value at integer)
// i  -> (int) -> integer
// l  -> (long) -> long integer
// L  -> (long *) -> pointer to a long integer
// p  -> (void *) -> pointer (alias for l)
// P  -> (void **) -> pointer to a handle (alias for L)
// o  -> (UNICODE_STRING *) -> unicode string
// O  -> (OBJECT_ATTRIBUTES *) -> wrapper around a unicode string for filenames
// K  -> (OBJECT_ATTRIBUTES *) -> wrapper around a unicode string for registry keys
// a  -> (int, char **) -> array of string
// A  -> (int, wchar_t **) -> array of unicode strings
// r  -> (Type, int, char *) type as defined for Registry operations
// R  -> (Type, int, wchar_t *) type as defined for Registry operations
//	   type r is for ascii functions, R for unicode (Nt* are unicode)
// e  -> (HKEY, char *) -> key/ascii key/value pair (to be normalized)
// E  -> (HKEY, wchar_t *) -> key/unicode key/value pair (to be normalized)
// k  -> (HKEY, UNICODE_STRING *) -> unicode string for registry values (to be normalized)
// v  -> (HKEY, char *) -> key/ascii value pair for registry values (to be normalized)
// V  -> (HKEY, wchar_t *) -> key/ascii value pair for registry values (to be normalized)

//
// Each of these format specifiers are prefixed with a zero-terminated key
// value, e.g.
//
// log("s", "key", "value");
//
// A format specifier can also be repeated for n times (with n in the range
// 2..9), e.g.
//
// loq("sss", "key1", "value", "key2", "value2", "key3", "value3");
// loq("3s", "key1", "value", "key2", "value2", "key3", "value3");
//

#include "hooking.h"

void loq(int index, const char *category, const char *name,
	int is_success, ULONG_PTR return_value, const char *fmt, ...);
void log_new_process();
void log_new_thread();
void log_anomaly(const char *subcategory, const char *msg);
void log_breakpoint(const char *subcategory, const char *msg);
void log_hook_anomaly(const char *subcategory, int success,
	const hook_t *h, const char *msg);
void log_hook_modification(const hook_t *h, const char *origbytes, const char *newbytes, unsigned int len);
void log_hook_removal(const hook_t *h);
void log_hook_restoration(const hook_t *h);
void log_procname_anomaly(PUNICODE_STRING InitialName, PUNICODE_STRING InitialPath, PUNICODE_STRING CurrentName, PUNICODE_STRING CurrentPath);

void log_init(int debug);
void log_flush();
void log_free();

void debug_message(const char *msg);

#define DEBUG_SOCKET 0xfffffffe

int log_resolve_index(const char *funcname, int index);
extern const char *logtbl[][2];
extern volatile LONG g_log_index;

extern DWORD g_log_thread_id;
extern DWORD g_logwatcher_thread_id;
extern HANDLE g_log_handle;

enum {
	API_OTHER = 0,
	API_NTREADFILE = 1,
};
void set_special_api(DWORD API, BOOLEAN deletelast);
DWORD get_last_api(void);

extern size_t buffer_log_max;
extern size_t large_buffer_log_max;

#ifdef _WIN64
#define _LOQ(eval, cat, fmt, ...) \
do { \
	static volatile LONG _index; \
	if (_index == 0) \
		InterlockedExchange(&_index, InterlockedIncrement(&g_log_index)); \
	loq(_index, cat, &__FUNCTION__[4], eval, (ULONG_PTR)ret, fmt, ##__VA_ARGS__); \
} while (0)
#else
#define _LOQ(eval, cat, fmt, ...) \
do { \
	static volatile LONG _index; \
	__asm { \
		__asm pusha \
	} \
	if (_index == 0) \
		InterlockedExchange(&_index, InterlockedIncrement(&g_log_index)); \
	loq(_index, cat, &__FUNCTION__[4], eval, (ULONG_PTR)ret, fmt, ##__VA_ARGS__); \
	__asm { \
		__asm popa \
	} \
} while (0)
#endif

#define LOQ_ntstatus(cat, fmt, ...) _LOQ(NT_SUCCESS(ret), cat, fmt, ##__VA_ARGS__)
#define LOQ_nonnull(cat, fmt, ...) _LOQ(ret != NULL, cat, fmt, ##__VA_ARGS__)
#define LOQ_handle(cat, fmt, ...) _LOQ(ret != NULL && ret != INVALID_HANDLE_VALUE, cat, fmt, ##__VA_ARGS__)
#define LOQ_void(cat, fmt, ...) _LOQ(TRUE, cat, fmt, ##__VA_ARGS__)
#define LOQ_bool(cat, fmt, ...) _LOQ(ret != FALSE, cat, fmt, ##__VA_ARGS__)
#define LOQ_hresult(cat, fmt, ...) _LOQ(ret == S_OK, cat, fmt, ##__VA_ARGS__)
#define LOQ_zero(cat, fmt, ...) _LOQ(ret == 0, cat, fmt, ##__VA_ARGS__)
#define LOQ_nonzero(cat, fmt, ...) _LOQ(ret != 0, cat, fmt, ##__VA_ARGS__)
#define LOQ_nonnegone(cat, fmt, ...) _LOQ(ret != -1, cat, fmt, ##__VA_ARGS__)
#define LOQ_sockerr(cat, fmt, ...) _LOQ(ret != SOCKET_ERROR, cat, fmt, ##__VA_ARGS__)
#define LOQ_sock(cat, fmt, ...) _LOQ(ret != INVALID_SOCKET, cat, fmt, ##__VA_ARGS__)
#define LOQ_msgwait(cat, fmt, ...) _LOQ(ret != WAIT_FAILED, cat, fmt, ##__VA_ARGS__)

#define ENSURE_LARGE_INTEGER(param) \
	LARGE_INTEGER _##param; _##param.QuadPart = 0; if(param == NULL) param = &_##param

#define ENSURE_RTL_ATOM(param) \
	RTL_ATOM _##param = 0; if(param == NULL) param = &_##param

#define ENSURE_DWORD(param) \
	DWORD _##param = 0; if(param == NULL) param = &_##param

#define ENSURE_ULONG(param) \
	ULONG _##param = 0; if(param == NULL) param = &_##param
#define ENSURE_ULONG_ZERO(param) \
	ENSURE_ULONG(param); else *param = 0

#define ENSURE_SIZET(param) \
	ULONG_PTR _##param = 0; if(param == NULL) param = &_##param
#define ENSURE_SIZET_ZERO(param) \
	ENSURE_SIZET(param); else *param = 0

#define ENSURE_CLIENT_ID(param) \
	CLIENT_ID _##param; memset(&_##param, 0, sizeof(_##param)); if (param == NULL) param = &_##param

#define ENSURE_HANDLE(param) \
	HANDLE _##param; memset(&_##param, 0, sizeof(_##param)); if (param == NULL) param = &_##param

#define ENSURE_STRUCT(param, type) \
	type _##param; memset(&_##param, 0, sizeof(_##param)); if(param == NULL) param = &_##param

#define is_aligned(POINTER, BYTE_COUNT) \
    (((uintptr_t)(const void *)(POINTER)) % (BYTE_COUNT) == 0)

typedef struct _lastlog_t {
	unsigned char *buf;
	unsigned int len;
	unsigned int compare_len;
	int *repeated_ptr;
	unsigned char *compare_ptr;
} lastlog_t;