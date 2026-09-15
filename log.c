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
#include "log_serializer.h"
#include "protobuf_wrapper.h"
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


CRITICAL_SECTION g_writing_log_buffer_mutex;
static SOCKET g_sock;
static HANDLE g_debug_log_handle;
static unsigned int g_starttick;

HANDLE g_log_handle;

// current to-be-logged API call
// Thread-local context structure - includes BSON state + active serializer pointer

// Per-thread record ring. Every record is stored as a 4-byte little-endian
// length header followed by the payload, padded up to a 4-byte boundary. A
// length header of 0 is reserved as the "wrap to offset 0" marker, which is
// why zero-length records are rejected by log_raw_direct().
//
// Both the size and every advance are multiples of 4, so write_idx and
// read_idx are always 4-byte aligned. That invariant is what guarantees a
// full 4-byte wrap marker always fits at write_idx without running off the
// end of the buffer.
#define THREAD_LOG_RING_SIZE (256 * 1024)
#define RING_ALIGN(x) (((x) + 3u) & ~3u)

#define LOGTBL_EXPLAINED_MAX 256

typedef struct {
	ULONG_PTR thread_id;
	bson g_bson[1];
	char g_istr[4];
	log_serializer_t *active_serializer;  // Strategy pattern: BSON or Protobuf
	protobuf_context_t *g_pb_ctx;

	// SPSC offsets for the finished wire bytes. write_idx is owned by the
	// logging thread, read_idx by whoever is draining.
	volatile ULONG write_idx;
	volatile ULONG read_idx;

	// Lock-free deduplication state (replaces global lastlog_t)
	unsigned char *last_buf;
	unsigned int last_len;
	unsigned int last_compare_len;
	int *last_repeated_ptr;
	unsigned char *last_compare_ptr;

	// Thread-local API triggers (fixes cross-thread race condition globals)
	DWORD last_api_logged;
	BOOLEAN special_api_triggered;
	BOOLEAN delete_last_log;

	// Which log IDs this thread has already emitted an "explain" frame for.
	// Deliberately per-thread rather than global: the result server requires
	// explain(id) to reach the wire before the first record carrying that id,
	// and the only ordering we can cheaply guarantee is FIFO within a single
	// ring. A global flag would let thread A win the race, park explain(id)
	// in its own ring, and leave thread B emitting record(id) into a ring
	// that may drain first. The cost is a duplicate explain frame per thread
	// per id, which the parser treats as an idempotent map update.
	char explained[LOGTBL_EXPLAINED_MAX];

	ULONG dropped_records;
	ULONG dropped_reported;

	// The encoded byte stream for the drain loop
	unsigned char buffer[THREAD_LOG_RING_SIZE];
} thread_log_context_t;

#include <intrin.h>

lookup_t g_log_contexts;

extern log_serializer_t g_bson_serializer;
extern log_serializer_t g_protobuf_serializer;
log_serializer_t *g_default_serializer = &g_bson_serializer;

// O(1) TEB Accessor macro for ArbitraryUserPointer (Offset 0x14 on x86, 0x28 on x64)
static __forceinline thread_log_context_t* get_teb_context() {
#ifdef _WIN64
	return (thread_log_context_t*)__readgsqword(0x28);
#else
	return (thread_log_context_t*)__readfsdword(0x14);
#endif
}

static __forceinline void set_teb_context(thread_log_context_t* ctx) {
#ifdef _WIN64
	__writegsqword(0x28, (ULONG64)ctx);
#else
	__writefsdword(0x14, (ULONG)ctx);
#endif
}

static thread_log_context_t* GetThreadLogContext(void) {
	thread_log_context_t* pCtx = get_teb_context();
	if (pCtx) {
		return pCtx;
	}

	ULONG_PTR tid = GetCurrentThreadId();
	unsigned int size;
	pCtx = (thread_log_context_t*)lookup_get(&g_log_contexts, tid, &size);
	if (!pCtx) {
		pCtx = (thread_log_context_t*)lookup_add(&g_log_contexts, tid, sizeof(thread_log_context_t));
		if (!pCtx)
			return NULL;
		memset(pCtx, 0, sizeof(thread_log_context_t));
		pCtx->thread_id = tid;
		pCtx->active_serializer = g_default_serializer;
	}

	if (get_teb_context() == NULL) {
		set_teb_context(pCtx);
	}

	return pCtx;
}

protobuf_context_t* get_thread_pb_ctx(void) {
	thread_log_context_t* pCtx = GetThreadLogContext();
	if (!pCtx)
		return NULL;
	if (!pCtx->g_pb_ctx)
		pCtx->g_pb_ctx = (protobuf_context_t*)calloc(1, sizeof(protobuf_context_t));
	return pCtx->g_pb_ctx;
}

// Single-lookup accessors
static __inline bson *log_ctx_bson(void) {
	thread_log_context_t *c = GetThreadLogContext();
	return c ? c->g_bson : NULL;
}
static __inline char *log_ctx_istr(void) {
	thread_log_context_t *c = GetThreadLogContext();
	return c ? c->g_istr : NULL;
}
static __inline log_serializer_t *log_ctx_serializer(void) {
	thread_log_context_t *c = GetThreadLogContext();
	return c ? c->active_serializer : g_default_serializer;
}
#define g_bson (log_ctx_bson())
#define g_istr (log_ctx_istr())
#define g_active_serializer (log_ctx_serializer())

static void drain_ring(thread_log_context_t *ring);
static void log_raw_direct(const char *buf, size_t length);

void TlsThreadCleanup(void) {
	thread_log_context_t* pCtx = get_teb_context();
	if (pCtx) {
		// lookup_del() only unlinks the entry, so once it is off the list the
		// drain walk can never reach this ring again. Anything still queued
		// has to go out now or it is lost for the rest of the process.
		if (pCtx->last_buf) {
			log_raw_direct((const char *)pCtx->last_buf, pCtx->last_len);
			free(pCtx->last_buf);
			pCtx->last_buf = NULL;
		}

		EnterCriticalSection(&g_writing_log_buffer_mutex);
		drain_ring(pCtx);
		LeaveCriticalSection(&g_writing_log_buffer_mutex);

		free(pCtx->g_pb_ctx);
		pCtx->g_pb_ctx = NULL;
		set_teb_context(NULL);
	}
	lookup_del(&g_log_contexts, GetCurrentThreadId());
}

// BSON Serializer Implementation (wraps existing BSON functions)
static void bson_serializer_init(void) {
	bson_init(g_bson);
}
static void bson_serializer_append_int(const char *name, int32_t val) {
	bson_append_int(g_bson, name, val);
}
static void bson_serializer_append_long(const char *name, int64_t val) {
	bson_append_long(g_bson, name, val);
}
// Strings are stored exactly as the historical log_string()/log_wstring() did:
// every source unit is run through utf8_do_encode() and the result is written
// as a BSON binary blob. This keeps the on-the-wire bytes byte-for-byte
// compatible with the result-server parser (which expects sanitised UTF-8
// binary, tolerates embedded NULs, and would reject a raw BSON string that is
// not valid UTF-8). `length` is honoured so counted, non-NUL-terminated inputs
// are never over-read.
static void bson_serializer_append_string(const char *name, const char *val, int length) {
	char stack_buf[2048];
	char *utf8s = stack_buf;
	int utf8len, pos, temp_len;
	const char *p;
	BOOL allocated = FALSE;

	if (val == NULL) {
		bson_append_string_n(g_bson, name, "", 0);
		return;
	}
	if (length == -1)
		length = (int)strlen(val);

	utf8len = utf8_strlen_ascii(val, length);
	if ((size_t)utf8len + 4 > sizeof(stack_buf)) {
		utf8s = malloc(utf8len + 4);
		allocated = TRUE;
	}
	if (utf8s == NULL) {
		bson_append_string_n(g_bson, name, "", 0);
		return;
	}

	pos = 4;
	p = val;
	temp_len = length;
	while (temp_len-- != 0)
		pos += utf8_do_encode(*p++, (unsigned char *)&utf8s[pos]);

	if (bson_append_binary(g_bson, name, BSON_BIN_BINARY, utf8s + 4, utf8len) == BSON_ERROR)
		bson_append_string_n(g_bson, name, "", 0);

	if (allocated)
		free(utf8s);
}
static void bson_serializer_append_wstring(const char *name, const wchar_t *val, int length) {
	char stack_buf[2048];
	char *utf8s = stack_buf;
	int utf8len, pos, temp_len;
	const wchar_t *p;
	BOOL allocated = FALSE;

	if (val == NULL) {
		bson_append_string_n(g_bson, name, "", 0);
		return;
	}
	if (length == -1)
		length = lstrlenW(val);

	utf8len = utf8_strlen_unicode(val, length);
	if ((size_t)utf8len + 4 > sizeof(stack_buf)) {
		utf8s = malloc(utf8len + 4);
		allocated = TRUE;
	}
	if (utf8s == NULL) {
		bson_append_string_n(g_bson, name, "", 0);
		return;
	}

	pos = 4;
	p = val;
	temp_len = length;
	while (temp_len-- != 0)
		pos += utf8_do_encode(*p++, (unsigned char *)&utf8s[pos]);

	if (bson_append_binary(g_bson, name, BSON_BIN_BINARY, utf8s + 4, utf8len) == BSON_ERROR)
		bson_append_string_n(g_bson, name, "", 0);

	if (allocated)
		free(utf8s);
}
static void bson_serializer_append_binary(const char *name, const void *buf, size_t len) {
	bson_append_binary(g_bson, name, BSON_BIN_BINARY, (const char *)buf, (int)len);
}
static void bson_serializer_finish(void) {
	bson_finish(g_bson);
}
static void bson_serializer_append_start_array(const char *name) {
	bson_append_start_array(g_bson, name);
}
static void bson_serializer_append_finish_array(void) {
	bson_append_finish_array(g_bson);
}
static const uint8_t* bson_serializer_get_data(void) {
	return (const uint8_t*)bson_data(g_bson);
}
static size_t bson_serializer_get_size(void) {
	return (size_t)bson_size(g_bson);
}
static void bson_serializer_destroy(void) {
	bson_destroy(g_bson);
}

log_serializer_t g_bson_serializer = {
	.init = bson_serializer_init,
	.append_int = bson_serializer_append_int,
	.append_long = bson_serializer_append_long,
	.append_string = bson_serializer_append_string,
	.append_wstring = bson_serializer_append_wstring,
	.append_binary = bson_serializer_append_binary,
	.append_finish = bson_serializer_finish,
	.append_start_array = bson_serializer_append_start_array,
	.append_finish_array = bson_serializer_append_finish_array,
	.get_data = bson_serializer_get_data,
	.get_size = bson_serializer_get_size,
	.destroy = bson_serializer_destroy
};

// Explain-frame tracking now lives per-thread in thread_log_context_t::explained.

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

static void _send_log(BOOL blocking);

// Writes the whole span or reports failure. WriteFile on a byte-mode pipe is
// allowed to accept less than requested; the previous global-buffer code
// handled that with a memmove, and the ring has to handle it too or a short
// write silently truncates a BSON document and desynchronises the stream.
static BOOL write_all(const unsigned char *buf, ULONG length)
{
	HANDLE h;
	ULONG off = 0;

	if (g_sock == DEBUG_SOCKET) {
		h = g_debug_log_handle;
		if (h == INVALID_HANDLE_VALUE)
			return TRUE;   // non-admin debug case, discard
	}
	else {
		h = g_log_handle;
		if (h == INVALID_HANDLE_VALUE)
			return FALSE;  // not connected yet, keep the record queued
	}

	while (off < length) {
		DWORD written = 0;
		if (!WriteFile(h, buf + off, length - off, &written, NULL))
			return FALSE;
		if (written == 0)
			return FALSE;
		off += written;
	}
	return TRUE;
}

// Drains one thread's ring. Only ever touches read_idx, so it stays SPSC-safe
// against the owning thread's concurrent log_raw_direct().
static void drain_ring(thread_log_context_t *ring)
{
	ULONG read = ring->read_idx;
	ULONG write = *(volatile ULONG *)&ring->write_idx;

	while (read != write) {
		ULONG length = *(ULONG *)&ring->buffer[read];

		if (length == 0) {
			// Wrap marker: the tail of the buffer was too short for the next
			// record. Commit the wrap before writing anything so a failed
			// write below cannot leave read_idx parked on the marker.
			read = 0;
			ring->read_idx = read;
			if (read == write)
				break;
			length = *(ULONG *)&ring->buffer[read];
			if (length == 0)
				break;  // defensive: two markers in a row is not reachable
		}

		if (!write_all(&ring->buffer[read + sizeof(ULONG)], length))
			break;  // pipe stalled or not connected, retry on the next drain

		read += (ULONG)sizeof(ULONG) + RING_ALIGN(length);
		if (read >= THREAD_LOG_RING_SIZE)
			read = 0;
		ring->read_idx = read;
	}
}

// blocking=FALSE is the periodic best-effort drain from the logging thread.
// blocking=TRUE is used by log_flush() and thread teardown, where skipping the
// drain means losing records outright.
static void _send_log(BOOL blocking)
{
	entry_t *pItem;

	if (blocking)
		EnterCriticalSection(&g_writing_log_buffer_mutex);
	else if (!TryEnterCriticalSection(&g_writing_log_buffer_mutex))
		return;

	for (pItem = (entry_t *)g_log_contexts.root; pItem != NULL; pItem = pItem->next) {
		thread_log_context_t *ring = (thread_log_context_t *)pItem->data;

		drain_ring(ring);

		// Surface backpressure losses rather than dropping them silently.
		// Reported on the command pipe, not the log pipe, so this cannot
		// recurse back into the ring being drained.
		if (ring->dropped_records != ring->dropped_reported) {
			ring->dropped_reported = ring->dropped_records;
			pipe("CRITICAL:Log ring overflow, thread %d dropped %d records",
				(int)ring->thread_id, (int)ring->dropped_records);
		}
	}

	LeaveCriticalSection(&g_writing_log_buffer_mutex);
}

static DWORD WINAPI _log_thread(LPVOID param)
{
	hook_disable();

	while (1) {
		WaitForSingleObject(g_log_flush, 500);
		_send_log(FALSE);
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


static void log_raw_direct(const char *buf, size_t length) {
	thread_log_context_t *ring = GetThreadLogContext();
	ULONG write, read, used, freeb, need, pad;

	if (!ring)
		return;

	// A zero length header is the wrap marker, so it cannot also be a record.
	if (length == 0)
		return;

	write = ring->write_idx;
	read = *(volatile ULONG *)&ring->read_idx;

	// Record stride: 4-byte header + payload padded to the next 4-byte
	// boundary. Keeping every stride aligned is what keeps write_idx aligned,
	// which in turn guarantees a full 4-byte wrap marker always fits.
	need = (ULONG)sizeof(ULONG) + RING_ALIGN((ULONG)length);

	// If the record cannot fit in the tail, the tail is burned by a wrap
	// marker. Those bytes are part of the cost of this record and have to be
	// charged against free space, otherwise the write can overrun read_idx
	// and corrupt records the drainer has not consumed yet.
	pad = (THREAD_LOG_RING_SIZE - write < need) ? (THREAD_LOG_RING_SIZE - write) : 0;

	used = (write >= read) ? (write - read) : (THREAD_LOG_RING_SIZE - read + write);
	// One stride is held back so write_idx == read_idx always means empty.
	freeb = THREAD_LOG_RING_SIZE - used - (ULONG)sizeof(ULONG);

	if (pad + need > freeb) {
		// Records larger than the ring itself can never be queued. Rather
		// than drop them, drain what this thread has already queued and then
		// write the record straight out, which preserves this thread's
		// ordering. Anything else is transient backpressure, so drop and
		// account for it.
		if (need + (ULONG)sizeof(ULONG) > THREAD_LOG_RING_SIZE) {
			EnterCriticalSection(&g_writing_log_buffer_mutex);
			drain_ring(ring);
			if (!write_all((const unsigned char *)buf, (ULONG)length))
				ring->dropped_records++;
			LeaveCriticalSection(&g_writing_log_buffer_mutex);
			return;
		}
		ring->dropped_records++;
		return;
	}

	if (pad) {
		*(ULONG *)&ring->buffer[write] = 0;
		write = 0;
	}

	*(ULONG *)&ring->buffer[write] = (ULONG)length;
	memcpy(&ring->buffer[write + sizeof(ULONG)], buf, length);

	write += need;
	if (write >= THREAD_LOG_RING_SIZE)
		write = 0;

	// Publish the payload before the index that makes it visible to the drainer.
	MemoryBarrier();
	ring->write_idx = write;
}

void log_flush()
{
	thread_log_context_t *ctx = GetThreadLogContext();
	if (ctx && ctx->last_buf) {
		log_raw_direct(ctx->last_buf, ctx->last_len);
		free(ctx->last_buf);
		ctx->last_buf = NULL;
	}

	_send_log(TRUE);
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

static void log_int32(int value)
{
	g_active_serializer->append_int( g_istr, value );
}

static void log_int64(int64_t value)
{
	g_active_serializer->append_long(g_istr, value);
}

static void log_ptr(void *value)
{
	if (sizeof(ULONG_PTR) == 8)
		log_int64((int64_t)value);
	else
		log_int32((int)(ULONG_PTR)value);
}

// Emit a pointer-sized value under an explicit key. Matches the historical
// bson_append_ptr(): int32 on 32-bit builds, int64 on 64-bit builds - the same
// width for every pointer field so the parser never has to guess.
static void serializer_append_ptr(log_serializer_t *s, const char *name, ULONG_PTR ptr)
{
	if (sizeof(ULONG_PTR) == 8)
		s->append_long(name, (int64_t)ptr);
	else
		s->append_int(name, (int32_t)ptr);
}

static void log_string(const char *str, int length)
{
	g_active_serializer->append_string(g_istr, str, length);
}

static void log_wstring(const wchar_t *str, int length)
{
	g_active_serializer->append_wstring(g_istr, str, length);
}

static void log_variant(VARIANT* var) {
	char log_msg[32];
	if (!var) {
		// Log an empty string instead of bailing to avoid gaps in the BSON array
		log_string("", 0);
		return;
	}

	__try {
		switch (var->vt) {
			case VT_EMPTY:
				log_string("", 0);
				break;
			case VT_NULL:
				log_string("NULL", -1);
				break;
			case 74:
				// Undocumented, likely internal Variant Type in vbscript engine
				// Observed with:
				// Return value (arg1) with VbsStrReverse
				// Function argument (arg3) with VbsExecute
				log_variant((VARIANT*)var->pvRecord);
				break;
			case 130:
				log_wstring(var->bstrVal, -1);
				break;
			case VT_BSTR:
				log_wstring(var->bstrVal, -1);
				break;
			case VT_BSTR | VT_BYREF:
				log_wstring(var->pbstrVal ? *var->pbstrVal : NULL, -1);
				break;
			case VT_BOOL:
				if (var->boolVal)
					log_string("TRUE", 4);
				else
					log_string("FALSE", 5);
				break;
			case VT_BOOL | VT_BYREF:
				if (*var->pboolVal)
					log_string("TRUE", 4);
				else
					log_string("FALSE", 5);
				break;
			case VT_INT:
				log_int32(var->intVal);
				break;
			case VT_INT | VT_BYREF:
				log_int32(*var->pintVal);
				break;
			case VT_UINT:
				log_int32(var->uintVal);
				break;
			case VT_UINT | VT_BYREF:
				log_int32(*var->puintVal);
				break;
			case VT_I8:
				log_int64(var->llVal);
				break;
			case VT_I8 | VT_BYREF:
				log_int64(*var->pllVal);
				break;
			case VT_UI8:
				log_int64(var->ullVal);
				break;
			case VT_UI8 | VT_BYREF:
				log_int64(*var->pullVal);
				break;
			case VT_I4:
				log_int32(var->lVal);
				break;
			case VT_I4 | VT_BYREF:
				log_int32(*var->plVal);
				break;
			case VT_UI4:
				log_int32(var->ulVal);
				break;
			case VT_UI4 | VT_BYREF:
				log_int32(*var->pulVal);
				break;
			case VT_I2:
				log_int32(var->iVal);
				break;
			case VT_I2 | VT_BYREF:
				log_int32(*var->piVal);
				break;
			case VT_UI2:
				log_int32(var->uiVal);
				break;
			case VT_UI2 | VT_BYREF:
				log_int32(*var->puiVal);
				break;
			case VT_I1:
				log_int32(var->cVal);
				break;
			case VT_I1 | VT_BYREF:
				log_int32(*var->pcVal);
				break;
			case VT_UI1:
				log_int32(var->bVal);
				break;
			case VT_UI1 | VT_BYREF:
				log_int32(*var->pbVal);
				break;
			case VT_VARIANT:
				log_variant(var->pvarVal);
				break;
			case VT_VARIANT | VT_BYREF:
				log_variant(var->pvarVal);
				break;
			case VT_DATE:
				// Note: Maybe convert to a datestamp?
				log_int64((int64_t)var->date);
				break;
			case VT_DATE | VT_BYREF:
				// Note: Maybe convert to a datestamp string?
				log_int64((int64_t)*var->pdate);
				break;
			case VT_R8:
				log_int64((int64_t)var->dblVal);
				break;
			case VT_R8 | VT_BYREF:
				log_int64((int64_t)*var->pdblVal);
				break;
			default:
				if (var->vt & VT_ARRAY)
					log_string("Array", 5);
				else {
					snprintf(log_msg, 32, "Unhandled VARIANT Type: %hu", var->vt);
					log_string(log_msg, -1);
				}
				break;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		log_string("", 0);
	}
}

static void log_argv(int argc, const char ** argv) {
	int i;

	g_active_serializer->append_start_array( g_istr );

	for (i = 0; i < argc; i++) {
		num_to_string(g_istr, 4, i);
		log_string(argv[i], -1);
	}
	g_active_serializer->append_finish_array();
}

static void log_wargv(int argc, const wchar_t ** argv) {
	int i;

	g_active_serializer->append_start_array( g_istr );

	for (i = 0; i < argc; i++) {
		num_to_string(g_istr, 4, i);
		log_wstring(argv[i], -1);
	}

	g_active_serializer->append_finish_array();
}

static void log_buffer(const char *buf, size_t length) {
	size_t trunclength = min((unsigned int)length, (unsigned int)buffer_log_max);

	if (buf == NULL) {
		trunclength = 0;
	}

	g_active_serializer->append_binary(g_istr, buf, trunclength);
}

static void log_large_buffer(const char *buf, size_t length) {
	size_t trunclength = min((unsigned int)length, (unsigned int)large_buffer_log_max);

	if (buf == NULL) {
		trunclength = 0;
	}

	g_active_serializer->append_binary(g_istr, buf, trunclength);
}

void set_special_api(DWORD API, BOOLEAN deleteLastLog)
{
	thread_log_context_t *ctx = GetThreadLogContext();
	if (!ctx) return;

	ctx->special_api_triggered = TRUE;
	ctx->last_api_logged = API;
	ctx->delete_last_log = deleteLastLog;
}
DWORD get_last_api(void)
{
	thread_log_context_t *ctx = GetThreadLogContext();
	if (!ctx) return 0;
	return ctx->last_api_logged;
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
	log_serializer_t *s = NULL;
	thread_log_context_t *ctx;

	if (index >= LOG_ID_PREDEFINED_MAX && g_config.suspend_logging)
		return;

	get_lasterrors(&lasterror);

	hook_disable();

	ctx = GetThreadLogContext();

	// The per-index "explain" frame is raw BSON metadata the result server uses
	// to name argument positions. It has no protobuf equivalent, so in protobuf
	// mode it must not be emitted - otherwise the stream is BSON frames
	// interleaved with protobuf frames.
	if (g_active_serializer == &g_bson_serializer && ctx &&
		index >= 0 && index < LOGTBL_EXPLAINED_MAX &&
		ctx->explained[index] == 0) {
		const char * pname;
		bson b[1];

		{
			ctx->explained[index] = 1;

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
			else if (key == 'n') {
				(void)va_arg(args, VARIANT *);
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
	}

	// Consume the special-API state. This used to be global state guarded by
	// g_mutex and was racy across threads; it now lives in the thread context
	// alongside the dedup cache it controls, so set_special_api() and the
	// loq() that consumes it are always the same thread.
	if (ctx) {
		if (!ctx->special_api_triggered)
			ctx->last_api_logged = API_OTHER;
		else {
			ctx->special_api_triggered = FALSE;
			if (ctx->delete_last_log) {
				free(ctx->last_buf);
				ctx->last_buf = NULL;
			}
		}
	}

	fmt = fmtbak;
	va_start(args, fmt);
	count = 1; key = 0; argnum = 2;

	// Cache the serializer for the rest of the call - it cannot change mid-loq,
	// and this avoids a TLS lookup on every field append.
	s = g_active_serializer;

	s->init();
	s->append_int( "I", index );
	hookinfo = hook_info();
	// return location of malware callsite / its parent - same width as "C".
	serializer_append_ptr(s, "C", (ULONG_PTR)hookinfo->return_address);
	serializer_append_ptr(s, "R", (ULONG_PTR)hookinfo->main_caller_retaddr);
	serializer_append_ptr(s, "P", (ULONG_PTR)hookinfo->parent_caller_retaddr);
	s->append_int("T", GetCurrentThreadId());
	s->append_int("t", raw_gettickcount() - g_starttick );
	// number of times this log was repeated -- we'll modify this
	s->append_int("r", 0);

	if (s == &g_bson_serializer) {
		compare_offset = (unsigned int)(g_bson->cur - bson_data(g_bson));
		// the repeated value is encoded immediately before the stream we compare
		repeat_offset = compare_offset - 4;
	} else {
		compare_offset = 0;
		repeat_offset = 0;
	}

	s->append_start_array("args");
	s->append_int( "0", is_success );
	serializer_append_ptr(s, "1", (ULONG_PTR)return_value);


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
		else if (key == 'n') {
			VARIANT* s = va_arg(args, VARIANT*);
			log_variant(s);
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
					s->append_binary(g_istr, NULL, 0);
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
					s->append_binary(g_istr, NULL, 0);
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
				s->append_binary(g_istr, (const char *) data, size);
			}

			// bson_append_finish_object( g_bson );
		}
	}

	va_end(args);

	s->append_finish_array();
	s->append_finish();

	{

	}

	// special-API state was already consumed above, before serialization.

	if (index == LOG_ID_PROCESS || index == LOG_ID_THREAD || index == LOG_ID_ENVIRON) {
		// don't hold back any of our critical notifications -- these *must* be flushed in log_init()
		log_raw_direct(s->get_data(), s->get_size());
	}
	else {
		// Caching and duplicate-checking are exclusive to BSON formatting (due to Protobuf's frame encapsulation)
		if (s == &g_bson_serializer && ctx) {
			if (ctx->last_buf) {
				// BSON documents are bounded by BUFFERSIZE (16 MB); the
				// size_t -> unsigned int narrowing here is safe.
				unsigned int our_len = (unsigned int)s->get_size() - compare_offset;
				if (ctx->last_compare_len == our_len && !memcmp(ctx->last_compare_ptr, s->get_data() + compare_offset, our_len)) {
					(*ctx->last_repeated_ptr)++;
				}
				else {
					if (g_config.force_flush == 1)
						log_flush();
					else {
						log_raw_direct(ctx->last_buf, ctx->last_len);
						free(ctx->last_buf);
						ctx->last_buf = NULL;
					}
				}
			}
			if (ctx->last_buf == NULL) {
				ctx->last_len = (unsigned int)s->get_size();
				ctx->last_buf = malloc(ctx->last_len);
				memcpy(ctx->last_buf, s->get_data(), ctx->last_len);
				ctx->last_compare_len = ctx->last_len - compare_offset;
				ctx->last_compare_ptr = ctx->last_buf + compare_offset;
				ctx->last_repeated_ptr = (int *)(ctx->last_buf + repeat_offset);
			}
		} else {
			// For Protobuf, write directly to result server
			log_raw_direct(s->get_data(), s->get_size());
		}
	}

	s->destroy();
	if (g_config.force_flush == 2)
		log_flush();

	hook_enable();

	set_lasterrors(&lasterror);
}

void announce_netlog()
{
	char protoname[32];
	int len = sprintf(protoname, "BSON %u\n", GetCurrentProcessId());
	//sprintf(protoname+5, "logs/%lu.bson\n", GetCurrentProcessId());

	// This header has to be the very first thing the result server reads.
	// It deliberately bypasses the per-thread rings: queued as a record it
	// would just be one entry among many, and the drain walks threads in
	// lookup order, so another thread's ring could reach the pipe first and
	// the server would reject the stream from byte zero.
	EnterCriticalSection(&g_writing_log_buffer_mutex);
	write_all((const unsigned char *)protoname, (ULONG)len);
	LeaveCriticalSection(&g_writing_log_buffer_mutex);
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
	g_log_flush = CreateEvent(NULL, FALSE, FALSE, NULL);

	if (g_config.log_format == LOG_FORMAT_PROTOBUF) {
		g_default_serializer = &g_protobuf_serializer;
		// The protobuf backend is EXPERIMENTAL. The current schema cannot
		// represent capemon's full call model (heterogeneous indexed
		// arguments, nested %a arrays, the caller "C" address, the thread id),
		// and no result-server parser consumes it yet. It is safe to enable
		// (the output stream stays self-consistent), but it is lossy - do not
		// use it for analysis until schema.proto is finalised and a parser
		// exists on the host side.
		pipe("CRITICAL:log-format=1 (protobuf) is experimental and lossy; "
			"only I/t/R/P are emitted and there is no host-side parser.");
	} else {
		g_default_serializer = &g_bson_serializer;
	}

	// The netlog protocol header announced by announce_netlog() is still "BSON";
	// a real protobuf transport would need its own header and a matching host
	// reader. Left as-is deliberately while protobuf is experimental.

	// Update active serializer for the main thread context too
	thread_log_context_t *pCtx = GetThreadLogContext();
	if (pCtx) {
		pCtx->active_serializer = g_default_serializer;
	}

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
	TlsThreadCleanup();
	if (g_sock == DEBUG_SOCKET) {
		g_sock = INVALID_SOCKET;
	}
	else {
		CloseHandle(g_log_handle);
		g_log_handle = INVALID_HANDLE_VALUE;
	}
}
