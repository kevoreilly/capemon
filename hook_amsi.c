#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <stdint.h>
#include <wchar.h>
#include "hooking.h"
#include "log.h"
#include "misc.h"
#include "lookup.h"
#include "CAPE\CAPE.h"

// Minimum AMSI buffer size (in bytes) to dump; skips empty or 1-char probes.
#define AMSI_MIN_DUMP_SIZE 4

// Maximum AMSI buffer size (in bytes) to dump (64 MB); fits in ULONG for our_isbadreadptr.
#define AMSI_MAX_DUMP_SIZE 0x4000000

// Maximum wide-character count scanned by wcsnlen in AmsiScanString (32M WCHARs = 64 MB).
#define AMSI_MAX_STRING_CHARS (AMSI_MAX_DUMP_SIZE / sizeof(wchar_t))

// Default maximum number of distinct AMSI buffers dumped per process.
// If g_config.dump_limit is configured higher, that higher limit is honoured.
#define AMSI_DUMP_LIMIT 64

// FNV-1a parameters used to deduplicate identical AMSI buffers across calls.
#define FNV1A_32_OFFSET 0x811c9dc5u
#define FNV1A_32_PRIME  0x01000193u
#define FNV1A_64_OFFSET 0xcbf29ce484222325ULL
#define FNV1A_64_PRIME  0x100000001b3ULL

// Per-thread AMSI hook recursion depth using lock-free lookup table (LOOKUP_THREAD)
// to avoid static TLS (__declspec(thread)) crashes in post-loaded/injected DLLs.
static lookup_t g_amsi_active_lookup;

// Content hashes of already-dumped AMSI buffers/streams and per-process dump counter.
static lookup_t g_amsi_dumped_hashes;
static volatile LONG g_amsi_dump_count = 0;

BOOL IsAmsiActive(void)
{
	LONG *depth = (LONG *)lookup_get(&g_amsi_active_lookup, (ULONG_PTR)GetCurrentThreadId(), NULL);
	return (depth && *depth > 0) ? TRUE : FALSE;
}

static BOOL EnterAmsiHook(void)
{
	lasterror_t lasterrors;
	LONG *depth;
	BOOL was_active = FALSE;

	get_lasterrors(&lasterrors);
	depth = (LONG *)LOOKUP_THREAD(&g_amsi_active_lookup, LONG);
	if (depth) {
		was_active = (*depth > 0);
		(*depth)++;
	}
	set_lasterrors(&lasterrors);
	return was_active;
}

static void LeaveAmsiHook(void)
{
	lasterror_t lasterrors;
	LONG *depth;

	get_lasterrors(&lasterrors);
	depth = (LONG *)lookup_get(&g_amsi_active_lookup, (ULONG_PTR)GetCurrentThreadId(), NULL);
	if (depth && *depth > 0)
		(*depth)--;
	set_lasterrors(&lasterrors);
}

static ULONG_PTR HashAmsiBuffer(const BYTE *buf, SIZE_T len, BOOL *has_content)
{
	ULONG_PTR hash = 0;
	BOOL non_trivial = FALSE;

	__try {
#ifdef _WIN64
		uint64_t h = FNV1A_64_OFFSET;
		for (SIZE_T i = 0; i < len; i++) {
			BYTE b = buf[i];
			if (b > 0x20 && b != 0x7f)
				non_trivial = TRUE;
			h ^= (uint64_t)b;
			h *= FNV1A_64_PRIME;
		}
		h ^= (uint64_t)len;
		h *= FNV1A_64_PRIME;
		hash = (ULONG_PTR)(h ? h : 1);
#else
		uint32_t h = FNV1A_32_OFFSET;
		for (SIZE_T i = 0; i < len; i++) {
			BYTE b = buf[i];
			if (b > 0x20 && b != 0x7f)
				non_trivial = TRUE;
			h ^= (uint32_t)b;
			h *= FNV1A_32_PRIME;
		}
		h ^= (uint32_t)len;
		h *= FNV1A_32_PRIME;
		hash = (ULONG_PTR)(h ? h : 1);
#endif
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		hash = 0;
		non_trivial = FALSE;
	}

	if (has_content)
		*has_content = non_trivial;
	return hash;
}

BOOL DumpAmsiBuffer(DWORD DumpType, PVOID buffer, SIZE_T length, const char *caller)
{
	lasterror_t lasterrors;
	ULONG_PTR hash;
	BOOL has_content = FALSE;
	unsigned int limit;
	BOOL dumped = FALSE;

	if (!g_config.amsidump || !CapeMetaData || !buffer)
		return FALSE;

	if (length < AMSI_MIN_DUMP_SIZE || length > AMSI_MAX_DUMP_SIZE)
		return FALSE;

	get_lasterrors(&lasterrors);
	hook_disable();

	if (our_isbadreadptr(buffer, (ULONG)length))
		goto out;

	hash = HashAmsiBuffer((const BYTE *)buffer, length, &has_content);
	if (!hash || !has_content)
		goto out;

	if (lookup_get(&g_amsi_dumped_hashes, hash, NULL))
		goto out;

	limit = ((unsigned int)g_config.dump_limit > AMSI_DUMP_LIMIT)
		? (unsigned int)g_config.dump_limit : AMSI_DUMP_LIMIT;

	if ((unsigned int)InterlockedIncrement(&g_amsi_dump_count) > limit) {
		InterlockedDecrement(&g_amsi_dump_count);
		DebugOutput("%s: AMSI dump limit (%u) reached, skipping buffer at 0x%p.\n",
			caller ? caller : "AMSI", limit, buffer);
		goto out;
	}

	LOOKUP_MARK_SEEN(&g_amsi_dumped_hashes, hash);
	SetCapeMetaData(DumpType, 0, NULL, NULL);
	if (DumpMemoryRaw(buffer, length)) {
		DebugOutput("%s: Dumped AMSI buffer at 0x%p, size 0x%Ix.\n",
			caller ? caller : "AMSI", buffer, length);
		dumped = TRUE;
	}
	else {
		InterlockedDecrement(&g_amsi_dump_count);
	}

out:
	hook_enable();
	set_lasterrors(&lasterrors);
	return dumped;
}

HOOKDEF(HRESULT, WINAPI, AmsiScanBuffer,
	_In_     PVOID        amsiContext,
	_In_     PVOID        buffer,
	_In_     ULONG        length,
	_In_opt_ LPCWSTR      contentName,
	_In_opt_ PVOID        amsiSession,
	_Out_    PVOID        result
) {
	BOOL was_active = EnterAmsiHook();
	HRESULT ret = Old_AmsiScanBuffer(amsiContext, buffer, length, contentName, amsiSession, result);
	LeaveAmsiHook();

	if (!was_active) {
		LOQ_hresult("amsi", "ui", "ContentName", contentName, "Length", length);

		if (g_config.amsidump && buffer != NULL && length >= AMSI_MIN_DUMP_SIZE)
			DumpAmsiBuffer(AMSIBUFFER, buffer, (SIZE_T)length, "AmsiScanBuffer");
	}

	return ret;
}

HOOKDEF(HRESULT, WINAPI, AmsiScanString,
	_In_     PVOID        amsiContext,
	_In_     LPCWSTR      string,
	_In_opt_ LPCWSTR      contentName,
	_In_opt_ PVOID        amsiSession,
	_Out_    PVOID        result
) {
	BOOL was_active = EnterAmsiHook();
	HRESULT ret = Old_AmsiScanString(amsiContext, string, contentName, amsiSession, result);
	LeaveAmsiHook();

	if (!was_active) {
		LOQ_hresult("amsi", "uu", "ContentName", contentName, "String", string);

		if (g_config.amsidump && string != NULL) {
			lasterror_t lasterrors;
			SIZE_T len = 0;

			get_lasterrors(&lasterrors);
			if (!our_isbadreadptr((PVOID)string, sizeof(wchar_t))) {
				__try {
					len = wcsnlen(string, AMSI_MAX_STRING_CHARS) * sizeof(wchar_t);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					len = 0;
				}
			}
			set_lasterrors(&lasterrors);

			if (len >= AMSI_MIN_DUMP_SIZE)
				DumpAmsiBuffer(AMSIBUFFER, (PVOID)string, len, "AmsiScanString");
		}
	}

	return ret;
}
