/*
CAPE - Config And Payload Extraction
Copyright(C) 2026 CAPE Sandbox developers

This program is free software : you can redistribute it and / or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

// Static crypto / TLS primitive instrumentation for statically linked BoringSSL,
// Rust `ring` / `aws-lc-rs` (`rustls`), and OpenSSL 1.1/3.x Windows assembly routines.
//
// Primitive entry points are located exclusively by the internal `static_crypto` YARA
// rule in CAPE/YaraHarness.c (PE-independent so packed/unpacked and reflective payloads
// are covered automatically) and armed via persistent software breakpoints when
// `crypto-hooks=1` is configured.
//
// Design constraints:
//  - Zero CRITICAL_SECTIONs in breakpoint callbacks (lock-free lookup_t + Interlocked* only)
//    so callbacks cannot deadlock against suspended or loader-locked threads inside VEH.
//  - Per-site hit budgets disarm breakpoints via lookup_del(&SoftBPs, ...) once exhausted,
//    preventing exception storms on bulk file encryption (e.g. ransomware).
//  - Key schedules are deduplicated via 64-bit FNV-1a hashes so repeated TLS records or
//    re-keyed blocks do not flood the behaviour log.

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "hooking.h"
#include "log.h"
#include "misc.h"
#include "lookup.h"
#include "config.h"
#include "CAPE\CAPE.h"
#include "CAPE\Debugger.h"
#include "hook_static_crypto.h"

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern lookup_t SoftBPs;

#define STATIC_CRYPTO_MAX_SITES				128
#define STATIC_CRYPTO_MAX_RET_SITES			64
#define STATIC_CRYPTO_MAX_KEYS				512
#define STATIC_CRYPTO_RET_SLOTS				32
#define STATIC_CRYPTO_SLOT_RESERVED			((ULONG_PTR)1)
#define STATIC_CRYPTO_KEY_HIT_LIMIT			512
#define STATIC_CRYPTO_DATA_HIT_LIMIT		256
#define STATIC_CRYPTO_RET_UNMATCHED_LIMIT	64
#define STATIC_CRYPTO_LOG_MAX				8192
#define STATIC_CRYPTO_DUMP_MAX				0x1000000	// 16 MB
#define STATIC_CRYPTO_MAX_LEN				0x10000000	// 256 MB sanity bound
#define STATIC_CRYPTO_GCM_DEC_MIN_LEN		96			// aesni_gcm_decrypt bails below 0x60

#define LOQ_static_crypto(apiname, fmt, ...) \
do { \
	static volatile LONG _index; \
	LONG _id = _index; \
	if (_id == 0) { \
		LONG _new_id = InterlockedIncrement(&g_log_index); \
		LONG _prev = InterlockedCompareExchange(&_index, _new_id, 0); \
		_id = (_prev == 0) ? _new_id : _prev; \
	} \
	loq(_id, "crypto", apiname, TRUE, 0, fmt, ##__VA_ARGS__); \
} while (0)

typedef enum _STATIC_CRYPTO_KIND {
	SC_NONE = 0,
	SC_AES_SET_KEY_WIN64,		// (const uint8_t *user_key, int bits, AES_KEY *key) in RCX, EDX, R8
	SC_AES_SET_KEY_CDECL32,		// cdecl (user_key, bits, key) at [ESP+4..+12]
	SC_AES_SET_KEY_OSSL32_REG,	// OpenSSL __aesni_set_encrypt_key internal reg ABI: EAX=user_key, ECX=bits, EDX=key
	SC_AES_CBC,					// (in, out, len, key, ivec[16], enc)
	SC_AES_GCM_ENC,				// (in, out, len, key, ivec[16], ...)
	SC_AES_GCM_DEC,				// (in, out, len, key, ivec[16], ...), returns bytes processed in RAX
	SC_AES_VAES_GCM_ENC,		// (in, out, len, key, ivec[16], ...), processes all len bytes
	SC_AES_VAES_GCM_DEC,		// (in, out, len, key, ivec[16], ...), void, processes all len bytes
	SC_CHACHA20_CTR32,			// (out, in, len, key[32], counter[16])
	SC_CHACHA20_POLY1305_SEAL,	// (out, pt, pt_len, ad, ad_len, seal_data*)
	SC_CHACHA20_POLY1305_OPEN,	// (out_pt, ct, pt_len, ad, ad_len, open_data*)
} STATIC_CRYPTO_KIND;

typedef struct _STATIC_CRYPTO_SPEC {
	const char *Identifier;
	STATIC_CRYPTO_KIND Kind;
	const char *Name;
	const char *Algorithm;
	LONG MaxHits;
} STATIC_CRYPTO_SPEC;

typedef struct _STATIC_CRYPTO_SITE {
	STATIC_CRYPTO_KIND Kind;
	const char *Name;
	const char *Algorithm;
	volatile LONG HitCount;
	LONG MaxHits;
	volatile LONG Disarmed;
} STATIC_CRYPTO_SITE;

typedef struct _STATIC_CRYPTO_RET_SLOT {
	volatile ULONG_PTR EntrySP;	// RSP/ESP at function entry (points to saved return address)
	STATIC_CRYPTO_KIND Kind;
	const char *Name;
	const char *Algorithm;
	PBYTE OutBuffer;
	SIZE_T Len;
	BYTE Key[32];
	BYTE Iv[16];
	DWORD IvLen;
	BOOL HasKey;
} STATIC_CRYPTO_RET_SLOT;

typedef struct _STATIC_CRYPTO_RET_STATE {
	STATIC_CRYPTO_RET_SLOT Slots[STATIC_CRYPTO_RET_SLOTS];
	volatile LONG NextVictim;
	volatile LONG TotalHits;
	volatile LONG UnmatchedHits;
	volatile LONG Disarmed;
} STATIC_CRYPTO_RET_STATE;

typedef struct _STATIC_CRYPTO_PENDING {
	PBYTE Address;
	const STATIC_CRYPTO_SPEC *Spec;
} STATIC_CRYPTO_PENDING;

static const STATIC_CRYPTO_SPEC g_crypto_specs[] = {
#ifdef _WIN64
	{ "$bssl_aes_set_enc",		SC_AES_SET_KEY_WIN64,		"aes_hw_set_encrypt_key",			"AES",				STATIC_CRYPTO_KEY_HIT_LIMIT },
	{ "$ossl_aes_set_enc",		SC_AES_SET_KEY_WIN64,		"aesni_set_encrypt_key",			"AES",				STATIC_CRYPTO_KEY_HIT_LIMIT },
	{ "$vpaes_set_enc",			SC_AES_SET_KEY_WIN64,		"vpaes_set_encrypt_key",			"AES",				STATIC_CRYPTO_KEY_HIT_LIMIT },
	{ "$vpaes_set_dec",			SC_AES_SET_KEY_WIN64,		"vpaes_set_decrypt_key",			"AES",				STATIC_CRYPTO_KEY_HIT_LIMIT },
	{ "$aesni_cbc",				SC_AES_CBC,					"aes_hw_cbc_encrypt",				"AES-CBC",			STATIC_CRYPTO_DATA_HIT_LIMIT },
	{ "$bssl_gcm_enc",			SC_AES_GCM_ENC,				"aesni_gcm_encrypt",				"AES-GCM",			STATIC_CRYPTO_DATA_HIT_LIMIT },
	{ "$bssl_gcm_dec",			SC_AES_GCM_DEC,				"aesni_gcm_decrypt",				"AES-GCM",			STATIC_CRYPTO_DATA_HIT_LIMIT },
	{ "$ossl_gcm_enc",			SC_AES_GCM_ENC,				"aesni_gcm_encrypt",				"AES-GCM",			STATIC_CRYPTO_DATA_HIT_LIMIT },
	{ "$ossl_gcm_dec",			SC_AES_GCM_DEC,				"aesni_gcm_decrypt",				"AES-GCM",			STATIC_CRYPTO_DATA_HIT_LIMIT },
	{ "$vaes_gcm_enc",			SC_AES_VAES_GCM_ENC,		"aes_gcm_enc_update_vaes_avx2",		"AES-GCM",			STATIC_CRYPTO_DATA_HIT_LIMIT },
	{ "$vaes_gcm_dec",			SC_AES_VAES_GCM_DEC,		"aes_gcm_dec_update_vaes_avx2",		"AES-GCM",			STATIC_CRYPTO_DATA_HIT_LIMIT },
	{ "$bssl_chacha_nohw",		SC_CHACHA20_CTR32,			"ChaCha20_ctr32_nohw",				"ChaCha20",			STATIC_CRYPTO_KEY_HIT_LIMIT },
	{ "$bssl_chacha_ssse3",		SC_CHACHA20_CTR32,			"ChaCha20_ctr32_ssse3",				"ChaCha20",			STATIC_CRYPTO_KEY_HIT_LIMIT },
	{ "$bssl_chacha_ssse3_4x",	SC_CHACHA20_CTR32,			"ChaCha20_ctr32_ssse3_4x",			"ChaCha20",			STATIC_CRYPTO_KEY_HIT_LIMIT },
	{ "$bssl_chacha_avx2",		SC_CHACHA20_CTR32,			"ChaCha20_ctr32_avx2",				"ChaCha20",			STATIC_CRYPTO_KEY_HIT_LIMIT },
	{ "$ossl_chacha",			SC_CHACHA20_CTR32,			"ChaCha20_ctr32",					"ChaCha20",			STATIC_CRYPTO_KEY_HIT_LIMIT },
	{ "$cc20p1305_seal_sse41",	SC_CHACHA20_POLY1305_SEAL,	"chacha20_poly1305_seal_sse41",		"ChaCha20-Poly1305",STATIC_CRYPTO_DATA_HIT_LIMIT },
	{ "$cc20p1305_seal_avx2",	SC_CHACHA20_POLY1305_SEAL,	"chacha20_poly1305_seal_avx2",		"ChaCha20-Poly1305",STATIC_CRYPTO_DATA_HIT_LIMIT },
	{ "$cc20p1305_open_sse41",	SC_CHACHA20_POLY1305_OPEN,	"chacha20_poly1305_open_sse41",		"ChaCha20-Poly1305",STATIC_CRYPTO_DATA_HIT_LIMIT },
	{ "$cc20p1305_open_avx2",	SC_CHACHA20_POLY1305_OPEN,	"chacha20_poly1305_open_avx2",		"ChaCha20-Poly1305",STATIC_CRYPTO_DATA_HIT_LIMIT },
#else
	{ "$bssl_aes_set_enc_32",	SC_AES_SET_KEY_CDECL32,		"aes_hw_set_encrypt_key",			"AES",				STATIC_CRYPTO_KEY_HIT_LIMIT },
	{ "$ossl_aes_set_enc_32",	SC_AES_SET_KEY_OSSL32_REG,	"aesni_set_encrypt_key",			"AES",				STATIC_CRYPTO_KEY_HIT_LIMIT },
	{ "$vpaes_set_enc_32",		SC_AES_SET_KEY_CDECL32,		"vpaes_set_encrypt_key",			"AES",				STATIC_CRYPTO_KEY_HIT_LIMIT },
	{ "$vpaes_set_dec_32",		SC_AES_SET_KEY_CDECL32,		"vpaes_set_decrypt_key",			"AES",				STATIC_CRYPTO_KEY_HIT_LIMIT },
	{ "$aesni_cbc_32",			SC_AES_CBC,					"aes_hw_cbc_encrypt",				"AES-CBC",			STATIC_CRYPTO_DATA_HIT_LIMIT },
	{ "$bssl_chacha_nohw_32",	SC_CHACHA20_CTR32,			"ChaCha20_ctr32_nohw",				"ChaCha20",			STATIC_CRYPTO_KEY_HIT_LIMIT },
	{ "$bssl_chacha_ssse3_32",	SC_CHACHA20_CTR32,			"ChaCha20_ctr32_ssse3",				"ChaCha20",			STATIC_CRYPTO_KEY_HIT_LIMIT },
	{ "$ossl_chacha_32",		SC_CHACHA20_CTR32,			"ChaCha20_ctr32",					"ChaCha20",			STATIC_CRYPTO_KEY_HIT_LIMIT },
#endif
};

static lookup_t g_crypto_sites = {0};
static lookup_t g_crypto_return_table = {0};
static lookup_t g_logged_keys = {0};

static volatile LONG g_armed_site_count = 0;
static volatile LONG g_ret_site_count = 0;
static volatile LONG g_logged_key_count = 0;

static volatile LONG g_reg_lock = 0;
static volatile LONG g_ret_init_lock = 0;
static STATIC_CRYPTO_PENDING g_pending[STATIC_CRYPTO_MAX_SITES];
static LONG g_pending_count = 0;

static BOOL StaticCryptoBreakpointHandler(struct _EXCEPTION_POINTERS *ExceptionInfo);

static const STATIC_CRYPTO_SPEC *StaticCryptoFindSpec(const char *Identifier)
{
	SIZE_T i;

	if (!Identifier)
		return NULL;

	for (i = 0; i < sizeof(g_crypto_specs) / sizeof(g_crypto_specs[0]); i++) {
		if (!strcmp(g_crypto_specs[i].Identifier, Identifier))
			return &g_crypto_specs[i];
	}
	return NULL;
}

static BOOL StaticCryptoIsExecutableAddress(PVOID Address)
{
	MEMORY_BASIC_INFORMATION mbi;

	if (!Address || is_address_in_monitor((ULONG_PTR)Address))
		return FALSE;

	memset(&mbi, 0, sizeof(mbi));
	if (!VirtualQuery(Address, &mbi, sizeof(mbi)))
		return FALSE;

	if (mbi.State != MEM_COMMIT)
		return FALSE;

	return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

static BOOL StaticCryptoBufferReadable(LPCVOID Ptr, SIZE_T Len)
{
	if (!Ptr || Len == 0 || Len > STATIC_CRYPTO_MAX_LEN)
		return FALSE;
	return !our_isbadreadptr(Ptr, (ULONG)Len);
}

static BOOL StaticCryptoReadWord(ULONG_PTR Addr, ULONG_PTR *OutVal)
{
	if (!Addr || our_isbadreadptr((LPCVOID)Addr, (ULONG)sizeof(ULONG_PTR)))
		return FALSE;
	*OutVal = *(const ULONG_PTR *)Addr;
	return TRUE;
}

static BOOL StaticCryptoGetArg(PCONTEXT Context, DWORD Index, ULONG_PTR *OutVal)
{
#ifdef _WIN64
	switch (Index) {
	case 0: *OutVal = (ULONG_PTR)Context->Rcx; return TRUE;
	case 1: *OutVal = (ULONG_PTR)Context->Rdx; return TRUE;
	case 2: *OutVal = (ULONG_PTR)Context->R8;  return TRUE;
	case 3: *OutVal = (ULONG_PTR)Context->R9;  return TRUE;
	default:
		// Win64 stack layout at entry: [RSP]=retaddr, [RSP+0x08..0x20]=shadow space, [RSP+0x28]=arg4
		return StaticCryptoReadWord((ULONG_PTR)Context->Rsp + (ULONG_PTR)(Index + 1) * sizeof(ULONG_PTR), OutVal);
	}
#else
	// Win32 cdecl stack layout at entry: [ESP]=retaddr, [ESP+4]=arg0, [ESP+8]=arg1, ...
	return StaticCryptoReadWord((ULONG_PTR)Context->Esp + (ULONG_PTR)(Index + 1) * sizeof(ULONG_PTR), OutVal);
#endif
}

static ULONG_PTR StaticCryptoHashKey(BYTE Tag, const BYTE *Data, SIZE_T Len)
{
	uint64_t h = 14695981039346656037ULL;
	SIZE_T i;

	h ^= (uint64_t)Tag;
	h *= 1099511628211ULL;
	h ^= (uint64_t)Len;
	h *= 1099511628211ULL;
	for (i = 0; i < Len; i++) {
		h ^= (uint64_t)Data[i];
		h *= 1099511628211ULL;
	}
#ifdef _WIN64
	return (ULONG_PTR)(h ? h : 1);
#else
	{
		ULONG_PTR folded = (ULONG_PTR)(h ^ (h >> 32));
		return folded ? folded : 1;
	}
#endif
}

// Returns TRUE if this (Tag, Key) pair has not been seen yet and records it.
static BOOL StaticCryptoMarkKeySeen(BYTE Tag, const BYTE *Key, SIZE_T KeyLen)
{
	ULONG_PTR KeyHash = StaticCryptoHashKey(Tag, Key, KeyLen);

	if (lookup_get(&g_logged_keys, KeyHash, NULL))
		return FALSE;

	if (InterlockedIncrement(&g_logged_key_count) > STATIC_CRYPTO_MAX_KEYS)
		return FALSE;

	if (!lookup_add(&g_logged_keys, KeyHash, 0))
		return FALSE;

	return TRUE;
}

static void StaticCryptoMaybeDumpKey(const BYTE *KeyBuf, SIZE_T KeyLen)
{
	if (!g_config.dump_keys || !KeyBuf || KeyLen == 0)
		return;

	if (CapeMetaData && !CapeMetaData->DumpType)
		CapeMetaData->DumpType = DATADUMP;
	DumpMemoryRaw((PVOID)KeyBuf, KeyLen);
}

static void StaticCryptoMaybeDumpPlaintext(LPCVOID Buf, SIZE_T Len, BOOL IsDecrypt)
{
	if (!Buf || Len == 0)
		return;

	if (g_config.dump_crypto) {
		SIZE_T DumpLen = (Len < STATIC_CRYPTO_DUMP_MAX) ? Len : STATIC_CRYPTO_DUMP_MAX;
		if (StaticCryptoBufferReadable(Buf, DumpLen)) {
			if (CapeMetaData && !CapeMetaData->DumpType)
				CapeMetaData->DumpType = DATADUMP;
			DumpMemoryRaw((PVOID)Buf, DumpLen);
		}
	}

	if (IsDecrypt && g_config.unpacker && Len >= sizeof(IMAGE_DOS_HEADER) &&
		StaticCryptoBufferReadable(Buf, sizeof(IMAGE_DOS_HEADER)) &&
		IsDisguisedPEHeader((PVOID)Buf)) {
		if (CapeMetaData) {
			if (!CapeMetaData->DumpType)
				CapeMetaData->DumpType = UNPACKED_PE;
			CapeMetaData->Address = (PVOID)Buf;
		}
		if (DumpImageInCurrentProcess((PVOID)Buf))
			DebugOutput("StaticCrypto: dumped decrypted PE image at 0x%p.\n", Buf);
	}
}

static void StaticCryptoQueueReturn(
	PVOID RetAddr,
	ULONG_PTR EntrySP,
	STATIC_CRYPTO_KIND Kind,
	const char *Name,
	const char *Algorithm,
	PBYTE OutBuffer,
	SIZE_T Len,
	const BYTE *Key,
	BOOL HasKey,
	const BYTE *Iv,
	DWORD IvLen)
{
	STATIC_CRYPTO_RET_STATE *State;
	STATIC_CRYPTO_RET_SLOT *Slot = NULL;
	int i;

	if (!RetAddr || !OutBuffer || Len == 0 || !StaticCryptoIsExecutableAddress(RetAddr))
		return;

	// Never overlay a return breakpoint onto an entry site breakpoint.
	if (lookup_get(&g_crypto_sites, (ULONG_PTR)RetAddr, NULL))
		return;

	State = (STATIC_CRYPTO_RET_STATE *)lookup_get(&g_crypto_return_table, (ULONG_PTR)RetAddr, NULL);
	if (!State) {
		if (InterlockedCompareExchange(&g_ret_site_count, 0, 0) >= STATIC_CRYPTO_MAX_RET_SITES)
			return;

		while (InterlockedCompareExchange(&g_ret_init_lock, 1, 0) != 0)
			YieldProcessor();

		State = (STATIC_CRYPTO_RET_STATE *)lookup_get(&g_crypto_return_table, (ULONG_PTR)RetAddr, NULL);
		if (!State) {
			if (g_ret_site_count < STATIC_CRYPTO_MAX_RET_SITES && !lookup_get(&SoftBPs, (ULONG_PTR)RetAddr, NULL)) {
				State = (STATIC_CRYPTO_RET_STATE *)lookup_add(&g_crypto_return_table, (ULONG_PTR)RetAddr, sizeof(STATIC_CRYPTO_RET_STATE));
				if (State) {
					memset(State, 0, sizeof(*State));
					if (SetSoftwareBreakpointEx(&SoftBPs, RetAddr, StaticCryptoBreakpointHandler, TRUE)) {
						InterlockedIncrement(&g_ret_site_count);
					} else {
						lookup_del(&g_crypto_return_table, (ULONG_PTR)RetAddr);
						State = NULL;
					}
				}
			}
		}
		InterlockedExchange(&g_ret_init_lock, 0);
	}

	if (!State || InterlockedCompareExchange(&State->Disarmed, 0, 0) != 0)
		return;

	// Reuse a stale slot with the same EntrySP (e.g. an earlier call that unwound without returning).
	for (i = 0; i < STATIC_CRYPTO_RET_SLOTS && !Slot; i++) {
		if (State->Slots[i].EntrySP == EntrySP &&
			InterlockedCompareExchangePointer((PVOID volatile *)&State->Slots[i].EntrySP, (PVOID)STATIC_CRYPTO_SLOT_RESERVED, (PVOID)EntrySP) == (PVOID)EntrySP)
			Slot = &State->Slots[i];
	}
	for (i = 0; i < STATIC_CRYPTO_RET_SLOTS && !Slot; i++) {
		if (InterlockedCompareExchangePointer((PVOID volatile *)&State->Slots[i].EntrySP, (PVOID)STATIC_CRYPTO_SLOT_RESERVED, NULL) == NULL)
			Slot = &State->Slots[i];
	}
	if (!Slot) {
		LONG victim = (InterlockedIncrement(&State->NextVictim) & 0x7fffffff) % STATIC_CRYPTO_RET_SLOTS;
		Slot = &State->Slots[victim];
		InterlockedExchangePointer((PVOID volatile *)&Slot->EntrySP, (PVOID)STATIC_CRYPTO_SLOT_RESERVED);
	}

	Slot->Kind = Kind;
	Slot->Name = Name;
	Slot->Algorithm = Algorithm;
	Slot->OutBuffer = OutBuffer;
	Slot->Len = Len;
	Slot->HasKey = HasKey;
	if (HasKey && Key)
		memcpy(Slot->Key, Key, sizeof(Slot->Key));
	else
		memset(Slot->Key, 0, sizeof(Slot->Key));

	Slot->IvLen = (IvLen <= sizeof(Slot->Iv)) ? IvLen : (DWORD)sizeof(Slot->Iv);
	memset(Slot->Iv, 0, sizeof(Slot->Iv));
	if (Iv && Slot->IvLen > 0)
		memcpy(Slot->Iv, Iv, Slot->IvLen);

	InterlockedExchangePointer((PVOID volatile *)&Slot->EntrySP, (PVOID)EntrySP);
}

static void StaticCryptoHandleEntry(STATIC_CRYPTO_SITE *Site, PVOID Address, PCONTEXT Context)
{
	LONG Hits = InterlockedIncrement(&Site->HitCount);
	if (Hits > Site->MaxHits) {
		if (InterlockedCompareExchange(&Site->Disarmed, 1, 0) == 0) {
			lookup_del(&SoftBPs, (ULONG_PTR)Address);
			DebugOutput("StaticCrypto: disarming %s at 0x%p after %ld hits.\n", Site->Name, Address, Site->MaxHits);
		}
		return;
	}

	switch (Site->Kind) {
	case SC_AES_SET_KEY_WIN64:
	case SC_AES_SET_KEY_CDECL32:
	case SC_AES_SET_KEY_OSSL32_REG: {
		ULONG_PTR KeyPtrVal = 0, BitsVal = 0;
		DWORD Bits;
		SIZE_T KeyBytes;
		BYTE KeyBuf[32];
		const char *AlgoStr;

#ifndef _WIN64
		if (Site->Kind == SC_AES_SET_KEY_OSSL32_REG) {
			KeyPtrVal = (ULONG_PTR)Context->Eax;
			BitsVal = (ULONG_PTR)Context->Ecx;
		} else
#endif
		{
			if (!StaticCryptoGetArg(Context, 0, &KeyPtrVal) || !StaticCryptoGetArg(Context, 1, &BitsVal))
				return;
		}

		Bits = (DWORD)BitsVal;
		if (Bits == 128) {
			KeyBytes = 16;
			AlgoStr = "AES-128";
		} else if (Bits == 192) {
			KeyBytes = 24;
			AlgoStr = "AES-192";
		} else if (Bits == 256) {
			KeyBytes = 32;
			AlgoStr = "AES-256";
		} else {
			return;
		}

		if (!StaticCryptoBufferReadable((LPCVOID)KeyPtrVal, KeyBytes))
			return;
		memcpy(KeyBuf, (LPCVOID)KeyPtrVal, KeyBytes);

		if (!StaticCryptoMarkKeySeen('A', KeyBuf, KeyBytes))
			return;

		LOQ_static_crypto("StaticCryptoKey", "ssib",
			"Function", Site->Name,
			"Algorithm", AlgoStr,
			"KeyBits", (int)Bits,
			"Key", (int)KeyBytes, KeyBuf);
		StaticCryptoMaybeDumpKey(KeyBuf, KeyBytes);
		break;
	}

	case SC_CHACHA20_CTR32: {
		ULONG_PTR LenVal = 0, KeyPtrVal = 0, CtrPtrVal = 0;
		BYTE KeyBuf[32];
		BYTE CtrBuf[16];

		if (!StaticCryptoGetArg(Context, 2, &LenVal) ||
			!StaticCryptoGetArg(Context, 3, &KeyPtrVal) ||
			!StaticCryptoGetArg(Context, 4, &CtrPtrVal))
			return;

		if (LenVal == 0 || !StaticCryptoBufferReadable((LPCVOID)KeyPtrVal, sizeof(KeyBuf)))
			return;

		memcpy(KeyBuf, (LPCVOID)KeyPtrVal, sizeof(KeyBuf));
		memset(CtrBuf, 0, sizeof(CtrBuf));
		if (StaticCryptoBufferReadable((LPCVOID)CtrPtrVal, sizeof(CtrBuf)))
			memcpy(CtrBuf, (LPCVOID)CtrPtrVal, sizeof(CtrBuf));

		if (!StaticCryptoMarkKeySeen('C', KeyBuf, sizeof(KeyBuf)))
			return;

		LOQ_static_crypto("StaticCryptoStreamKey", "ssibb",
			"Function", Site->Name,
			"Algorithm", Site->Algorithm,
			"KeyBits", 256,
			"Key", (int)sizeof(KeyBuf), KeyBuf,
			"IV", (int)sizeof(CtrBuf), CtrBuf);
		StaticCryptoMaybeDumpKey(KeyBuf, sizeof(KeyBuf));
		break;
	}

	case SC_AES_CBC: {
		ULONG_PTR InVal = 0, OutVal = 0, LenVal = 0, IvVal = 0, EncVal = 0, RetVal = 0;
		SIZE_T Len;
		BYTE IvBuf[16];
		DWORD Enc;

		if (!StaticCryptoGetArg(Context, 0, &InVal) ||
			!StaticCryptoGetArg(Context, 1, &OutVal) ||
			!StaticCryptoGetArg(Context, 2, &LenVal) ||
			!StaticCryptoGetArg(Context, 4, &IvVal) ||
			!StaticCryptoGetArg(Context, 5, &EncVal))
			return;

		Len = (SIZE_T)LenVal;
		if (Len == 0 || Len > STATIC_CRYPTO_MAX_LEN)
			return;

		memset(IvBuf, 0, sizeof(IvBuf));
		if (StaticCryptoBufferReadable((LPCVOID)IvVal, sizeof(IvBuf)))
			memcpy(IvBuf, (LPCVOID)IvVal, sizeof(IvBuf));

		Enc = (DWORD)EncVal;
		if (Enc != 0) {
			SIZE_T LogLen = (Len < STATIC_CRYPTO_LOG_MAX) ? Len : STATIC_CRYPTO_LOG_MAX;
			if (!StaticCryptoBufferReadable((LPCVOID)InVal, LogLen))
				return;
			LOQ_static_crypto("StaticCryptoEncrypt", "ssbib",
				"Function", Site->Name,
				"Algorithm", Site->Algorithm,
				"IV", (int)sizeof(IvBuf), IvBuf,
				"Length", (int)Len,
				"Buffer", (int)LogLen, (LPCVOID)InVal);
			StaticCryptoMaybeDumpPlaintext((LPCVOID)InVal, Len, FALSE);
		} else {
#ifdef _WIN64
			ULONG_PTR EntrySP = (ULONG_PTR)Context->Rsp;
#else
			ULONG_PTR EntrySP = (ULONG_PTR)Context->Esp;
#endif
			if (!OutVal || !StaticCryptoReadWord(EntrySP, &RetVal))
				return;
			StaticCryptoQueueReturn((PVOID)RetVal, EntrySP, SC_AES_CBC, Site->Name, Site->Algorithm,
				(PBYTE)OutVal, Len, NULL, FALSE, IvBuf, sizeof(IvBuf));
		}
		break;
	}

#ifdef _WIN64
	case SC_AES_GCM_ENC:
	case SC_AES_VAES_GCM_ENC: {
		ULONG_PTR InVal = 0, LenVal = 0, IvVal = 0;
		SIZE_T Len, LogLen;
		BYTE IvBuf[16];

		if (!StaticCryptoGetArg(Context, 0, &InVal) ||
			!StaticCryptoGetArg(Context, 2, &LenVal) ||
			!StaticCryptoGetArg(Context, 4, &IvVal))
			return;

		Len = (SIZE_T)LenVal;
		if (Len == 0 || Len > STATIC_CRYPTO_MAX_LEN)
			return;

		memset(IvBuf, 0, sizeof(IvBuf));
		if (StaticCryptoBufferReadable((LPCVOID)IvVal, sizeof(IvBuf)))
			memcpy(IvBuf, (LPCVOID)IvVal, sizeof(IvBuf));

		LogLen = (Len < STATIC_CRYPTO_LOG_MAX) ? Len : STATIC_CRYPTO_LOG_MAX;
		if (!StaticCryptoBufferReadable((LPCVOID)InVal, LogLen))
			return;

		LOQ_static_crypto("StaticCryptoEncrypt", "ssbib",
			"Function", Site->Name,
			"Algorithm", Site->Algorithm,
			"IV", (int)sizeof(IvBuf), IvBuf,
			"Length", (int)Len,
			"Buffer", (int)LogLen, (LPCVOID)InVal);
		StaticCryptoMaybeDumpPlaintext((LPCVOID)InVal, Len, FALSE);
		break;
	}

	case SC_AES_GCM_DEC:
	case SC_AES_VAES_GCM_DEC: {
		ULONG_PTR OutVal = 0, LenVal = 0, IvVal = 0, RetVal = 0;
		ULONG_PTR EntrySP = (ULONG_PTR)Context->Rsp;
		SIZE_T Len;
		BYTE IvBuf[16];

		if (!StaticCryptoGetArg(Context, 1, &OutVal) ||
			!StaticCryptoGetArg(Context, 2, &LenVal) ||
			!StaticCryptoGetArg(Context, 4, &IvVal))
			return;

		Len = (SIZE_T)LenVal;
		if (Len == 0 || Len > STATIC_CRYPTO_MAX_LEN || !OutVal)
			return;

		// aesni_gcm_decrypt immediately returns 0 when len < 96; avoid a useless return trap.
		if (Site->Kind == SC_AES_GCM_DEC && Len < STATIC_CRYPTO_GCM_DEC_MIN_LEN)
			return;

		memset(IvBuf, 0, sizeof(IvBuf));
		if (StaticCryptoBufferReadable((LPCVOID)IvVal, sizeof(IvBuf)))
			memcpy(IvBuf, (LPCVOID)IvVal, sizeof(IvBuf));

		if (!StaticCryptoReadWord(EntrySP, &RetVal))
			return;

		StaticCryptoQueueReturn((PVOID)RetVal, EntrySP, Site->Kind, Site->Name, Site->Algorithm,
			(PBYTE)OutVal, Len, NULL, FALSE, IvBuf, sizeof(IvBuf));
		break;
	}

	case SC_CHACHA20_POLY1305_SEAL: {
		ULONG_PTR PtVal = 0, LenVal = 0, DataVal = 0;
		SIZE_T Len, LogLen;
		BYTE KeyBuf[32];
		BYTE NonceBuf[12];

		if (!StaticCryptoGetArg(Context, 1, &PtVal) ||
			!StaticCryptoGetArg(Context, 2, &LenVal) ||
			!StaticCryptoGetArg(Context, 5, &DataVal))
			return;

		Len = (SIZE_T)LenVal;
		if (Len == 0 || Len > STATIC_CRYPTO_MAX_LEN || !StaticCryptoBufferReadable((LPCVOID)DataVal, 48))
			return;

		memcpy(KeyBuf, (const BYTE *)DataVal, sizeof(KeyBuf));
		memcpy(NonceBuf, (const BYTE *)DataVal + 36, sizeof(NonceBuf));

		if (StaticCryptoMarkKeySeen('P', KeyBuf, sizeof(KeyBuf)))
			StaticCryptoMaybeDumpKey(KeyBuf, sizeof(KeyBuf));

		LogLen = (Len < STATIC_CRYPTO_LOG_MAX) ? Len : STATIC_CRYPTO_LOG_MAX;
		if (!StaticCryptoBufferReadable((LPCVOID)PtVal, LogLen))
			return;

		LOQ_static_crypto("StaticCryptoAeadEncrypt", "ssbbib",
			"Function", Site->Name,
			"Algorithm", Site->Algorithm,
			"Key", (int)sizeof(KeyBuf), KeyBuf,
			"IV", (int)sizeof(NonceBuf), NonceBuf,
			"Length", (int)Len,
			"Buffer", (int)LogLen, (LPCVOID)PtVal);
		StaticCryptoMaybeDumpPlaintext((LPCVOID)PtVal, Len, FALSE);
		break;
	}

	case SC_CHACHA20_POLY1305_OPEN: {
		ULONG_PTR OutPtVal = 0, LenVal = 0, DataVal = 0, RetVal = 0;
		ULONG_PTR EntrySP = (ULONG_PTR)Context->Rsp;
		SIZE_T Len;
		BYTE KeyBuf[32];
		BYTE NonceBuf[12];

		if (!StaticCryptoGetArg(Context, 0, &OutPtVal) ||
			!StaticCryptoGetArg(Context, 2, &LenVal) ||
			!StaticCryptoGetArg(Context, 5, &DataVal))
			return;

		Len = (SIZE_T)LenVal;
		if (Len == 0 || Len > STATIC_CRYPTO_MAX_LEN || !OutPtVal || !StaticCryptoBufferReadable((LPCVOID)DataVal, 48))
			return;

		// union chacha20_poly1305_open_data overwrites in.{key,counter,nonce} with out.tag on return,
		// so snapshot key and nonce on entry before arming the return breakpoint.
		memcpy(KeyBuf, (const BYTE *)DataVal, sizeof(KeyBuf));
		memcpy(NonceBuf, (const BYTE *)DataVal + 36, sizeof(NonceBuf));

		if (StaticCryptoMarkKeySeen('P', KeyBuf, sizeof(KeyBuf)))
			StaticCryptoMaybeDumpKey(KeyBuf, sizeof(KeyBuf));

		if (!StaticCryptoReadWord(EntrySP, &RetVal))
			return;

		StaticCryptoQueueReturn((PVOID)RetVal, EntrySP, SC_CHACHA20_POLY1305_OPEN, Site->Name, Site->Algorithm,
			(PBYTE)OutPtVal, Len, KeyBuf, TRUE, NonceBuf, sizeof(NonceBuf));
		break;
	}
#endif

	default:
		break;
	}
}

static void StaticCryptoHandleReturn(STATIC_CRYPTO_RET_STATE *State, PVOID Address, PCONTEXT Context)
{
	STATIC_CRYPTO_RET_SLOT Pending;
	BOOL Matched = FALSE;
	ULONG_PTR ExpectedEntrySP;
	SIZE_T ActualLen, LogLen;
	int i;

	memset(&Pending, 0, sizeof(Pending));
#ifdef _WIN64
	ExpectedEntrySP = (ULONG_PTR)Context->Rsp - sizeof(ULONG_PTR);
#else
	ExpectedEntrySP = (ULONG_PTR)Context->Esp - sizeof(ULONG_PTR);
#endif

	for (i = 0; i < STATIC_CRYPTO_RET_SLOTS && !Matched; i++) {
		STATIC_CRYPTO_RET_SLOT *Slot = &State->Slots[i];
		if (Slot->EntrySP == ExpectedEntrySP &&
			InterlockedCompareExchangePointer((PVOID volatile *)&Slot->EntrySP, (PVOID)STATIC_CRYPTO_SLOT_RESERVED, (PVOID)ExpectedEntrySP) == (PVOID)ExpectedEntrySP) {
			Pending = *Slot;
			InterlockedExchangePointer((PVOID volatile *)&Slot->EntrySP, NULL);
			Matched = TRUE;
		}
	}

	if (!Matched) {
		if (InterlockedIncrement(&State->UnmatchedHits) > STATIC_CRYPTO_RET_UNMATCHED_LIMIT) {
			if (InterlockedCompareExchange(&State->Disarmed, 1, 0) == 0)
				lookup_del(&SoftBPs, (ULONG_PTR)Address);
		}
		return;
	}

	if (InterlockedIncrement(&State->TotalHits) > STATIC_CRYPTO_DATA_HIT_LIMIT * 2) {
		if (InterlockedCompareExchange(&State->Disarmed, 1, 0) == 0)
			lookup_del(&SoftBPs, (ULONG_PTR)Address);
	}

	ActualLen = Pending.Len;
#ifdef _WIN64
	if (Pending.Kind == SC_AES_GCM_DEC) {
		SIZE_T Done = (SIZE_T)Context->Rax;
		if (Done == 0)
			return;
		if (Done < ActualLen)
			ActualLen = Done;
	}
#endif

	if (!Pending.OutBuffer || ActualLen == 0 || ActualLen > STATIC_CRYPTO_MAX_LEN)
		return;

	LogLen = (ActualLen < STATIC_CRYPTO_LOG_MAX) ? ActualLen : STATIC_CRYPTO_LOG_MAX;
	if (!StaticCryptoBufferReadable(Pending.OutBuffer, LogLen))
		return;

	if (Pending.Kind == SC_CHACHA20_POLY1305_OPEN) {
		LOQ_static_crypto("StaticCryptoAeadDecrypt", "ssbbib",
			"Function", Pending.Name,
			"Algorithm", Pending.Algorithm,
			"Key", (int)sizeof(Pending.Key), Pending.Key,
			"IV", (int)Pending.IvLen, Pending.Iv,
			"Length", (int)ActualLen,
			"Buffer", (int)LogLen, Pending.OutBuffer);
	} else {
		LOQ_static_crypto("StaticCryptoDecrypt", "ssbib",
			"Function", Pending.Name,
			"Algorithm", Pending.Algorithm,
			"IV", (int)Pending.IvLen, Pending.Iv,
			"Length", (int)ActualLen,
			"Buffer", (int)LogLen, Pending.OutBuffer);
	}

	StaticCryptoMaybeDumpPlaintext(Pending.OutBuffer, ActualLen, TRUE);
}

static BOOL StaticCryptoBreakpointHandler(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	PVOID Address;
	STATIC_CRYPTO_SITE *Site = NULL;
	STATIC_CRYPTO_RET_STATE *RetState = NULL;
	PCONTEXT Context;
	hook_info_t *hookinfo;
	lasterror_t lasterror;
	unsigned int saved_disable_count = 0;
	ULONG_PTR saved_retaddr = 0, saved_main_caller = 0, saved_parent_caller = 0;

	if (!ExceptionInfo || !ExceptionInfo->ExceptionRecord || !ExceptionInfo->ContextRecord)
		return FALSE;

	Address = ExceptionInfo->ExceptionRecord->ExceptionAddress;
	Site = (STATIC_CRYPTO_SITE *)lookup_get(&g_crypto_sites, (ULONG_PTR)Address, NULL);
	if (!Site)
		RetState = (STATIC_CRYPTO_RET_STATE *)lookup_get(&g_crypto_return_table, (ULONG_PTR)Address, NULL);
	if (!Site && !RetState)
		return FALSE;

	get_lasterrors(&lasterror);
	lasterror.Eflags = 0;
	Context = ExceptionInfo->ContextRecord;
	hookinfo = hook_info();
	if (hookinfo) {
		saved_disable_count = hookinfo->disable_count;
		saved_retaddr = hookinfo->return_address;
		saved_main_caller = hookinfo->main_caller_retaddr;
		saved_parent_caller = hookinfo->parent_caller_retaddr;
		hookinfo->return_address = (ULONG_PTR)Address;
		hookinfo->main_caller_retaddr = RetState ? (ULONG_PTR)Address : 0;
		hookinfo->parent_caller_retaddr = 0;
		if (Site) {
#ifdef _WIN64
			PULONG_PTR Sp = (PULONG_PTR)Context->Rsp;
#else
			PULONG_PTR Sp = (PULONG_PTR)Context->Esp;
#endif
			if (!our_isbadreadptr(Sp, sizeof(ULONG_PTR)))
				hookinfo->main_caller_retaddr = Sp[0];
		}
	}

	hook_disable();
	__try {
		if (Site)
			StaticCryptoHandleEntry(Site, Address, Context);
		else
			StaticCryptoHandleReturn(RetState, Address, Context);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DebugOutput("StaticCrypto: exception handling breakpoint at 0x%p.\n", Address);
	}

	if (hookinfo) {
		hookinfo->disable_count = saved_disable_count;
		hookinfo->return_address = saved_retaddr;
		hookinfo->main_caller_retaddr = saved_main_caller;
		hookinfo->parent_caller_retaddr = saved_parent_caller;
	}
	set_lasterrors(&lasterror);

	return TRUE;
}

static void StaticCryptoArmSite(PBYTE MatchAddress, const STATIC_CRYPTO_SPEC *Spec)
{
	STATIC_CRYPTO_SITE *Site;

	if (!MatchAddress || !Spec || !StaticCryptoIsExecutableAddress(MatchAddress))
		return;

	if (lookup_get(&g_crypto_sites, (ULONG_PTR)MatchAddress, NULL))
		return;

	if (lookup_get(&SoftBPs, (ULONG_PTR)MatchAddress, NULL))
		return;

	if (InterlockedCompareExchange(&g_armed_site_count, 0, 0) >= STATIC_CRYPTO_MAX_SITES)
		return;

	Site = (STATIC_CRYPTO_SITE *)lookup_add(&g_crypto_sites, (ULONG_PTR)MatchAddress, sizeof(STATIC_CRYPTO_SITE));
	if (!Site)
		return;

	Site->Kind = Spec->Kind;
	Site->Name = Spec->Name;
	Site->Algorithm = Spec->Algorithm;
	Site->HitCount = 0;
	Site->MaxHits = Spec->MaxHits;
	Site->Disarmed = 0;

	if (SetSoftwareBreakpointEx(&SoftBPs, MatchAddress, StaticCryptoBreakpointHandler, TRUE)) {
		InterlockedIncrement(&g_armed_site_count);
		DebugOutput("StaticCrypto: armed %s (%s) at 0x%p.\n", Spec->Name, Spec->Algorithm, MatchAddress);
	} else {
		lookup_del(&g_crypto_sites, (ULONG_PTR)MatchAddress);
		DebugOutput("StaticCrypto: failed to arm %s at 0x%p.\n", Spec->Name, MatchAddress);
	}
}

void StaticCryptoRegisterMatch(PVOID RegionBase, PBYTE MatchAddress, const char *Identifier)
{
	const STATIC_CRYPTO_SPEC *Spec;
	LONG i;

	UNREFERENCED_PARAMETER(RegionBase);

	if (!g_config.crypto_hooks || !MatchAddress || !Identifier)
		return;

	Spec = StaticCryptoFindSpec(Identifier);
	if (!Spec)
		return;

	if (!StaticCryptoIsExecutableAddress(MatchAddress))
		return;

	if (!DebuggerInitialised) {
		while (InterlockedCompareExchange(&g_reg_lock, 1, 0) != 0)
			YieldProcessor();
		for (i = 0; i < g_pending_count; i++) {
			if (g_pending[i].Address == MatchAddress) {
				InterlockedExchange(&g_reg_lock, 0);
				return;
			}
		}
		if (g_pending_count < STATIC_CRYPTO_MAX_SITES) {
			g_pending[g_pending_count].Address = MatchAddress;
			g_pending[g_pending_count].Spec = Spec;
			g_pending_count++;
		}
		InterlockedExchange(&g_reg_lock, 0);
		return;
	}

	StaticCryptoArmSite(MatchAddress, Spec);
}

void StaticCryptoProcessPending(void)
{
	STATIC_CRYPTO_PENDING Local[STATIC_CRYPTO_MAX_SITES];
	LONG Count = 0, i;

	if (!g_config.crypto_hooks || !DebuggerInitialised)
		return;

	while (InterlockedCompareExchange(&g_reg_lock, 1, 0) != 0)
		YieldProcessor();
	Count = g_pending_count;
	if (Count > 0) {
		memcpy(Local, g_pending, (SIZE_T)Count * sizeof(STATIC_CRYPTO_PENDING));
		g_pending_count = 0;
	}
	InterlockedExchange(&g_reg_lock, 0);

	for (i = 0; i < Count; i++)
		StaticCryptoArmSite(Local[i].Address, Local[i].Spec);
}
