/*
Copyright(C) 2022 TwinWave Security (kevin@twinwave.io)
CAPE - Config And Payload Extraction

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
// Inspired by https://b.poc.fun/decrypting-schannel-tls-part-1 - thanks to Webpentest & SolidLab
// TLS 1.3 support based on https://github.com/ngo/win-frida-scripts/blob/master/lsasslkeylog-easy/keylog.js

#include <stdio.h>
#include "hooking.h"
#include "lookup.h"
#include <ncrypt.h>
#include <Shlwapi.h>

//#define DEBUG_COMMENTS
#define BUFFER_SIZE 0x1000

typedef struct _ThreadRandom {
	char ClientRandomRepr[32*2+1];
	char ServerRandomRepr[32*2+1];
} ThreadRandom;

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern char* GetResultsPath(char* FolderName);
static lookup_t ThreadClientRandom;
static lookup_t ThreadTLS13Stage;
static BOOL Logged;
static BOOL LoggedTLS13;
CHAR SecretsLine[BUFFER_SIZE];
HANDLE TlsLog;

void HexEncode(char *Dest, const uint8_t *Source, uint32_t Length)
{
	static const char charset[] = "0123456789abcdef";
	for (; Length != 0; Source++, Length--) {
		*Dest++ = charset[*Source >> 4];
		*Dest++ = charset[*Source & 15];
	}
	*Dest = 0;
}

void LogTls(char* ClientRandomRepr, char* ServerRandomRepr, char* MasterSecretRepr)
{
	SIZE_T LastWriteLength = 0;
	char *FullPathName = GetResultsPath("tlsdump");
	PathAppend(FullPathName, "tlsdump.log");
	if (!Logged) {
		Logged = TRUE;
		DebugOutput("TLS 1.2 secrets logged to: %s", FullPathName);
	}
	if (!TlsLog)
		TlsLog = CreateFile(FullPathName, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (TlsLog != INVALID_HANDLE_VALUE) {
		memset(SecretsLine, 0, BUFFER_SIZE);
		_snprintf_s(SecretsLine, BUFFER_SIZE, _TRUNCATE, "client_random: %s, server_random: %s, master_secret: %s\n", ClientRandomRepr, ServerRandomRepr, MasterSecretRepr);
		WriteFile(TlsLog, SecretsLine, (DWORD)strlen(SecretsLine), (LPDWORD)&LastWriteLength, NULL);
	}
}

// Log TLS 1.3 traffic secrets in NSS SSLKEYLOGFILE format
void LogTls13(const char* Label, const char* ClientRandomRepr, const char* SecretRepr)
{
	SIZE_T LastWriteLength = 0;
	char *FullPathName = GetResultsPath("tlsdump");
	PathAppend(FullPathName, "tlsdump.log");
	if (!LoggedTLS13) {
		LoggedTLS13 = TRUE;
		DebugOutput("TLS 1.3 secrets logged to: %s", FullPathName);
	}
	if (!TlsLog)
		TlsLog = CreateFile(FullPathName, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (TlsLog != INVALID_HANDLE_VALUE) {
		memset(SecretsLine, 0, BUFFER_SIZE);
		_snprintf_s(SecretsLine, BUFFER_SIZE, _TRUNCATE, "%s %s %s\n", Label, ClientRandomRepr, SecretRepr);
		WriteFile(TlsLog, SecretsLine, (DWORD)strlen(SecretsLine), (LPDWORD)&LastWriteLength, NULL);
	}
}

BOOL GetRandoms(PNCryptBufferDesc pParameterList, char* ClientRandomRepr, char* ServerRandomRepr)
{
	BOOL ret = FALSE;
	if (pParameterList) {
		for (unsigned int i = 0; i < pParameterList->cBuffers; i++) {
			if (pParameterList->pBuffers[i].BufferType == NCRYPTBUFFER_SSL_CLIENT_RANDOM) {
				HexEncode(ClientRandomRepr, pParameterList->pBuffers[i].pvBuffer, pParameterList->pBuffers[i].cbBuffer);
#ifdef DEBUG_COMMENTS
				DebugOutput("GetRandoms: ClientRandom %s", ClientRandomRepr);
#endif
				ret = TRUE;

			}
			else if (pParameterList->pBuffers[i].BufferType == NCRYPTBUFFER_SSL_SERVER_RANDOM) {
				HexEncode(ServerRandomRepr, pParameterList->pBuffers[i].pvBuffer, pParameterList->pBuffers[i].cbBuffer);
#ifdef DEBUG_COMMENTS
				DebugOutput("GetRandoms: ServerRandom %s", ServerRandomRepr);
#endif
			}
		}
	}
	if (ret == FALSE) {
		ThreadRandom *R = lookup_get(&ThreadClientRandom, (ULONG_PTR)GetCurrentThreadId(), NULL);
		if (R) {
			memcpy(ClientRandomRepr, R->ClientRandomRepr, 32*2+1);
#ifdef DEBUG_COMMENTS
			DebugOutput("GetRandoms: Stashed ClientRandom %s", R->ClientRandomRepr);
#endif
			if (strcmp("", ServerRandomRepr)) {
				memcpy(ServerRandomRepr, R->ServerRandomRepr, 32*2+1);
#ifdef DEBUG_COMMENTS
				DebugOutput("GetRandoms: Stashed ServerRandomRepr %s", R->ServerRandomRepr);
#endif
			}
			ret = TRUE;
		}
	}
	return ret;
}

void ExtractMasterKey(NCRYPT_KEY_HANDLE	hMasterKey, char* ClientRandomRepr, char* ServerRandomRepr)
{
	if (!hMasterKey || !ClientRandomRepr || !ServerRandomRepr)
		return;
	PBYTE p5lss = *(PBYTE*)(hMasterKey+0x10);
	if (p5lss && *(PDWORD)(p5lss+4) == 0x73736c35) {
		char MasterSecretRepr[48*2+1] = "";
		HexEncode(MasterSecretRepr, p5lss+0x1c, 48);
		if (strcmp("", MasterSecretRepr) && strcmp("", ClientRandomRepr) && strcmp("", ServerRandomRepr)) {
#ifdef DEBUG_COMMENTS
			DebugOutput("client_random: %s, server_random: %s, master_secret: %s", ClientRandomRepr, ServerRandomRepr, MasterSecretRepr);
#endif
			LogTls(ClientRandomRepr, ServerRandomRepr, MasterSecretRepr);
		}
	}
}

// Extract TLS 1.3 traffic secret from an NCRYPT_KEY_HANDLE
// NCrypt internal structures use native pointer sizes, so offsets differ
// between x64 and x86 (WoW64 32-bit processes on 64-bit OS).
// Structure chain: BDDD -> 3lss -> RUUU -> YKSM (size + secret ptr)
#ifdef _WIN64
	#define OFF_BDDD_3LSS   0x10
	#define OFF_3LSS_RUUU   0x20
	#define OFF_RUUU_YKSM   0x10
	#define OFF_YKSM_SIZE   0x10
	#define OFF_YKSM_SECRET 0x18
#else
	#define OFF_BDDD_3LSS   0x0C
	#define OFF_3LSS_RUUU   0x14
	#define OFF_RUUU_YKSM   0x0C
	#define OFF_YKSM_SIZE   0x0C
	#define OFF_YKSM_SECRET 0x10
#endif

BOOL ExtractTLS13TrafficSecret(NCRYPT_KEY_HANDLE hTrafficKey, PBYTE *pSecret, DWORD *pSecretSize)
{
	if (!hTrafficKey)
		return FALSE;

	__try {
		// BDDD structure ΓÇö outermost NCrypt key wrapper
		PBYTE pBDDD = (PBYTE)hTrafficKey;
		if (*(PDWORD)(pBDDD + 4) != 0x44444442)  // "BDDD"
			return FALSE;

		// 3lss structure ΓÇö TLS 1.3 variant (TLS 1.2 uses "5ssl"/0x73736c35)
		PBYTE p3lss = *(PBYTE*)(pBDDD + OFF_BDDD_3LSS);
		if (!p3lss || *(PDWORD)(p3lss + 4) != 0x73736c33)  // "3lss"
			return FALSE;

		// RUUU structure
		PBYTE pRUUU = *(PBYTE*)(p3lss + OFF_3LSS_RUUU);
		if (!pRUUU || *(PDWORD)(pRUUU + 4) != 0x55555552)  // "RUUU"
			return FALSE;

		// YKSM structure (MSKY) ΓÇö contains the actual secret
		PBYTE pYKSM = *(PBYTE*)(pRUUU + OFF_RUUU_YKSM);
		if (!pYKSM || *(PDWORD)(pYKSM + 4) != 0x4d534b59)  // "YKSM"
			return FALSE;

		*pSecretSize = *(DWORD*)(pYKSM + OFF_YKSM_SIZE);
		*pSecret = *(PBYTE*)(pYKSM + OFF_YKSM_SECRET);

		// Sanity check: TLS 1.3 secrets are 32 bytes (SHA-256) or 48 bytes (SHA-384)
		if (*pSecretSize != 32 && *pSecretSize != 48)
			return FALSE;
		if (!*pSecret)
			return FALSE;

		return TRUE;
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		DebugOutput("ExtractTLS13TrafficSecret: exception reading key structure");
		return FALSE;
	}
}

HOOKDEF(NTSTATUS, WINAPI, SslGenerateMasterKey,
	_In_	NCRYPT_PROV_HANDLE	hSslProvider,
	_In_	NCRYPT_KEY_HANDLE	hPrivateKey,
	_In_	NCRYPT_KEY_HANDLE	hPublicKey,
	_Out_	NCRYPT_KEY_HANDLE	*phMasterKey,
	_In_	DWORD				dwProtocol,
	_In_	DWORD				dwCipherSuite,
	_In_	PNCryptBufferDesc	pParameterList,
	_Out_	PBYTE				pbOutput,
	_In_	DWORD				cbOutput,
	_Out_	DWORD				*pcbResult,
	_In_	DWORD				dwFlags
) {
	char ClientRandomRepr[32*2+1] = "";
	char ServerRandomRepr[32*2+1] = "";
	BOOL GotClientRandom = GetRandoms(pParameterList, ClientRandomRepr, ServerRandomRepr);
	NTSTATUS ret = Old_SslGenerateMasterKey(hSslProvider, hPrivateKey, hPublicKey, phMasterKey, dwProtocol, dwCipherSuite, pParameterList, pbOutput, cbOutput, pcbResult, dwFlags);
	if (!ret && GotClientRandom)
		ExtractMasterKey(*phMasterKey, ClientRandomRepr, ServerRandomRepr);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, SslImportMasterKey,
	_In_	NCRYPT_PROV_HANDLE	hSslProvider,
	_In_	NCRYPT_KEY_HANDLE	hPrivateKey,
	_Out_	NCRYPT_KEY_HANDLE	*phMasterKey,
	_In_	DWORD				dwProtocol,
	_In_	DWORD				dwCipherSuite,
	_In_	PNCryptBufferDesc	pParameterList,
	_In_	PBYTE				pbEncryptedKey,
	_In_	DWORD				cbEncryptedKey,
	_In_	DWORD				dwFlags
) {
	char ClientRandomRepr[32*2+1] = "";
	char ServerRandomRepr[32*2+1] = "";
	BOOL GotClientRandom = GetRandoms(pParameterList, ClientRandomRepr, ServerRandomRepr);
	NTSTATUS ret = Old_SslImportMasterKey(hSslProvider, hPrivateKey, phMasterKey, dwProtocol, dwCipherSuite, pParameterList, pbEncryptedKey, cbEncryptedKey, dwFlags);
	if (!ret && GotClientRandom)
		ExtractMasterKey(*phMasterKey, ClientRandomRepr, ServerRandomRepr);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, SslGenerateSessionKeys,
	_In_	NCRYPT_PROV_HANDLE	hSslProvider,
	_In_	NCRYPT_KEY_HANDLE	hMasterKey,
	_Out_	NCRYPT_KEY_HANDLE	*phReadKey,
	_Out_	NCRYPT_KEY_HANDLE	*phWriteKey,
	_In_	PNCryptBufferDesc	pParameterList,
	_In_	DWORD				dwFlags
) {
	char ClientRandomRepr[32*2+1] = "";
	char ServerRandomRepr[32*2+1] = "";
	BOOL GotClientRandom = GetRandoms(pParameterList, ClientRandomRepr, ServerRandomRepr);
	if (GotClientRandom)
		ExtractMasterKey(hMasterKey, ClientRandomRepr, ServerRandomRepr);
	NTSTATUS ret = Old_SslGenerateSessionKeys(hSslProvider, hMasterKey, phReadKey, phWriteKey, pParameterList, dwFlags);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, SslHashHandshake,
	_In_	NCRYPT_PROV_HANDLE	hSslProvider,
	_Inout_	NCRYPT_HASH_HANDLE	hHandshakeHash,
	_Out_	PBYTE				pbInput,
	_In_	DWORD				cbInput,
	_In_	DWORD				dwFlags
) {
	unsigned int ClientRandomLength = 0;
	NTSTATUS ret = Old_SslHashHandshake(hSslProvider, hHandshakeHash, pbInput, cbInput, dwFlags);
	PWORD pwVersion = (PWORD)(pbInput+4);
	if (pbInput && *pbInput == 1 && *pwVersion == 0x0303) {
		int *pStage = (int*)lookup_get(&ThreadTLS13Stage, (ULONG_PTR)GetCurrentThreadId(), NULL);
		if (pStage) *pStage = 0;
		ThreadRandom *R = lookup_get(&ThreadClientRandom, (ULONG_PTR)GetCurrentThreadId(), NULL);
		if (R == NULL) {
			R = lookup_add(&ThreadClientRandom, (ULONG_PTR)GetCurrentThreadId(), sizeof(ThreadRandom));
			memset(R, 0, sizeof(*R));
			HexEncode(R->ClientRandomRepr, (uint8_t*)(pbInput+6), 32);
#ifdef DEBUG_COMMENTS
			DebugOutput("SslHashHandshake: ClientRandom %s", R->ClientRandomRepr);
#endif
		}
	}
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, SslExpandTrafficKeys,
	_In_		NCRYPT_PROV_HANDLE	hSslProvider,
	_In_		NCRYPT_KEY_HANDLE	hBaseKey,
	_In_		NCRYPT_HASH_HANDLE	hHashValue,
	_Out_opt_	NCRYPT_KEY_HANDLE	*phClientTrafficKey,
	_Out_opt_	NCRYPT_KEY_HANDLE	*phServerTrafficKey,
	_In_opt_	PNCryptBufferDesc	pParameterList,
	_In_		DWORD				dwFlags
) {
	NTSTATUS ret = Old_SslExpandTrafficKeys(hSslProvider, hBaseKey, hHashValue, phClientTrafficKey, phServerTrafficKey, pParameterList, dwFlags);

	if (ret != 0)
		return ret;

	// Get client_random ΓÇö try pParameterList first, fall back to stashed value
	char ClientRandomRepr[32*2+1] = "";
	char ServerRandomRepr[32*2+1] = "";
	BOOL GotClientRandom = GetRandoms(pParameterList, ClientRandomRepr, ServerRandomRepr);
	if (!GotClientRandom || !strcmp("", ClientRandomRepr))
		return ret;

	// Determine stage: first call = handshake secrets, second call = application secrets
	// Track per-thread using the lookup table
	ULONG_PTR tid = (ULONG_PTR)GetCurrentThreadId();
	int *pStage = (int*)lookup_get(&ThreadTLS13Stage, tid, NULL);
	int stage = 0;
	if (pStage) {
		stage = *pStage;
		*pStage = stage + 1;
	} else {
		pStage = (int*)lookup_add(&ThreadTLS13Stage, tid, sizeof(int));
		*pStage = 1;  // Next call will be stage 1
		stage = 0;     // This call is stage 0
	}

	const char *ClientLabel = (stage == 0) ? "CLIENT_HANDSHAKE_TRAFFIC_SECRET" : "CLIENT_TRAFFIC_SECRET_0";
	const char *ServerLabel = (stage == 0) ? "SERVER_HANDSHAKE_TRAFFIC_SECRET" : "SERVER_TRAFFIC_SECRET_0";

	// Extract client traffic secret
	if (phClientTrafficKey && *phClientTrafficKey) {
		PBYTE Secret = NULL;
		DWORD SecretSize = 0;
		if (ExtractTLS13TrafficSecret(*phClientTrafficKey, &Secret, &SecretSize)) {
			char SecretRepr[48*2+1] = "";
			HexEncode(SecretRepr, Secret, SecretSize);
			if (strcmp("", SecretRepr)) {
				DebugOutput("%s %s %s", ClientLabel, ClientRandomRepr, SecretRepr);
				LogTls13(ClientLabel, ClientRandomRepr, SecretRepr);
			}
		}
	}

	// Extract server traffic secret
	if (phServerTrafficKey && *phServerTrafficKey) {
		PBYTE Secret = NULL;
		DWORD SecretSize = 0;
		if (ExtractTLS13TrafficSecret(*phServerTrafficKey, &Secret, &SecretSize)) {
			char SecretRepr[48*2+1] = "";
			HexEncode(SecretRepr, Secret, SecretSize);
			if (strcmp("", SecretRepr)) {
				DebugOutput("%s %s %s", ServerLabel, ClientRandomRepr, SecretRepr);
				LogTls13(ServerLabel, ClientRandomRepr, SecretRepr);
			}
		}
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, SslExpandExporterMasterKey,
	_In_		NCRYPT_PROV_HANDLE	hSslProvider,
	_In_		NCRYPT_KEY_HANDLE	hBaseKey,
	_In_		NCRYPT_HASH_HANDLE	hHashValue,
	_Out_		NCRYPT_KEY_HANDLE	*phExporterMasterKey,
	_In_opt_	PNCryptBufferDesc	pParameterList,
	_In_		DWORD				dwFlags
) {
	NTSTATUS ret = Old_SslExpandExporterMasterKey(hSslProvider, hBaseKey, hHashValue, phExporterMasterKey, pParameterList, dwFlags);

	if (ret != 0)
		return ret;

	// Extract exporter master secret
	char ClientRandomRepr[32*2+1] = "";
	char ServerRandomRepr[32*2+1] = "";
	BOOL GotClientRandom = GetRandoms(pParameterList, ClientRandomRepr, ServerRandomRepr);
	if (!GotClientRandom || !strcmp("", ClientRandomRepr))
		return ret;

	if (phExporterMasterKey && *phExporterMasterKey) {
		PBYTE Secret = NULL;
		DWORD SecretSize = 0;
		if (ExtractTLS13TrafficSecret(*phExporterMasterKey, &Secret, &SecretSize)) {
			char SecretRepr[48*2+1] = "";
			HexEncode(SecretRepr, Secret, SecretSize);
			if (strcmp("", SecretRepr)) {
				DebugOutput("EXPORTER_SECRET %s %s", ClientRandomRepr, SecretRepr);
				LogTls13("EXPORTER_SECRET", ClientRandomRepr, SecretRepr);
			}
		}
	}

	return ret;
}

// ============================================================================
// BCryptHashData hook ΓÇö sniffs the TLS 1.3 transcript hash for ClientHello.
//
// Modern in-process TLS 1.3 (WinHTTP/.NET on Win10+) does *not* go through
// ncryptsslp.dll, so SslExpandTrafficKeys never fires and we have no way to
// learn client_random for the NSS keylog format. However, during the handshake
// Schannel hashes each Handshake message into a running transcript hash via
// BCryptHashData. The very first call on a fresh hash handle is the
// ClientHello, whose wire layout is:
//
//   [0]     msg_type  = 0x01 (client_hello)
//   [1..3]  length    (3 bytes, big-endian, of body)
//   [4..5]  legacy_version = 0x03 0x03
//   [6..37] random    <-- 32-byte client_random
//   [38]    legacy_session_id_len (1)
//   ...
//
// We detect this shape heuristically and stash client_random in a thread-local
// lookup so the subsequent BCryptKeyDerivation hook can recover it.
// ============================================================================

typedef PVOID BCRYPT_HASH_HANDLE;

static lookup_t ThreadTLS13ClientRandom;  // per-thread client_random for TLS 1.3 in-process

typedef struct _TLS13ClientRandom {
	char ClientRandomRepr[32*2+1];
} TLS13ClientRandom;

static BOOL LooksLikeClientHello(const UCHAR *p, ULONG cb)
{
	if (!p || cb < 40)
		return FALSE;
	if (p[0] != 0x01)                        // handshake type = client_hello
		return FALSE;
	ULONG body_len = ((ULONG)p[1] << 16) | ((ULONG)p[2] << 8) | (ULONG)p[3];
	// body_len excludes the 4-byte header. Reasonable ClientHello: 34..16384.
	if (body_len < 34 || body_len > 0x4000)
		return FALSE;
	// Body starts with legacy_version = 0x0303 (TLS 1.2 per RFC 8446 ┬º4.1.2).
	if (p[4] != 0x03 || p[5] != 0x03)
		return FALSE;
	return TRUE;
}

HOOKDEF(NTSTATUS, WINAPI, BCryptHashData,
	_Inout_	BCRYPT_HASH_HANDLE	hHash,
	_In_	PUCHAR				pbInput,
	_In_	ULONG				cbInput,
	_In_	ULONG				dwFlags
) {
	// Heuristic read-only inspection. We don't modify the buffer.
	__try {
		if (LooksLikeClientHello(pbInput, cbInput)) {
			ULONG_PTR tid = (ULONG_PTR)GetCurrentThreadId();
			int *pStage = (int*)lookup_get(&ThreadTLS13Stage, tid, NULL);
			if (pStage) *pStage = 0;
			TLS13ClientRandom *R = lookup_get(&ThreadTLS13ClientRandom, tid, NULL);
			if (!R)
				R = lookup_add(&ThreadTLS13ClientRandom, tid, sizeof(TLS13ClientRandom));
			if (R) {
				HexEncode(R->ClientRandomRepr, pbInput + 6, 32);
#ifdef DEBUG_COMMENTS
				DebugOutput("BCryptHashData: stashed TLS 1.3 client_random for thread %d: %s", (int)tid, R->ClientRandomRepr);
#endif
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		// Ignore ΓÇö just a heuristic sniff.
	}

	return Old_BCryptHashData(hHash, pbInput, cbInput, dwFlags);
}

// ============================================================================
// BCryptKeyDerivation hook ΓÇö catches TLS 1.3 HKDF-Expand-Label in-process.
//
// Windows in-process Schannel TLS 1.3 derives traffic secrets via
// BCryptKeyDerivation with a KDF_HKDF_INFO buffer containing a serialized
// HkdfLabel struct per RFC 8446 ┬º7.1:
//
//   uint16 length
//   uint8  label_len
//   uint8  label[label_len]     <- "tls13 " + logical_label
//   uint8  context_len
//   uint8  context[context_len]
//
// The logical labels we care about:
//   "c hs traffic" -> CLIENT_HANDSHAKE_TRAFFIC_SECRET
//   "s hs traffic" -> SERVER_HANDSHAKE_TRAFFIC_SECRET
//   "c ap traffic" -> CLIENT_TRAFFIC_SECRET_0
//   "s ap traffic" -> SERVER_TRAFFIC_SECRET_0
//   "exp master"   -> EXPORTER_SECRET
//
// client_random comes from the BCryptHashData ClientHello stash above.
// ============================================================================

#ifndef KDF_HKDF_INFO
#define KDF_HKDF_INFO       0x14
#endif

typedef PVOID BCRYPT_KEY_HANDLE_T;  // local alias to avoid bcrypt.h dependency

HOOKDEF(NTSTATUS, WINAPI, BCryptKeyDerivation,
	_In_		BCRYPT_KEY_HANDLE_T		hKey,
	_In_opt_	PNCryptBufferDesc		pParameterList,
	_Out_		PUCHAR					pbDerivedKey,
	_In_		ULONG					cbDerivedKey,
	_Out_		ULONG					*pcbResult,
	_In_		ULONG					dwFlags
) {
	NTSTATUS ret = Old_BCryptKeyDerivation(hKey, pParameterList, pbDerivedKey, cbDerivedKey, pcbResult, dwFlags);

	if (ret != 0 || !pParameterList || !pbDerivedKey)
		return ret;
	// TLS 1.3 traffic secrets are SHA-256 (32 bytes) or SHA-384 (48 bytes).
	if (cbDerivedKey != 32 && cbDerivedKey != 48)
		return ret;

	__try {
		PBYTE hkdfInfo = NULL;
		DWORD hkdfInfoLen = 0;
		for (unsigned int i = 0; i < pParameterList->cBuffers; i++) {
			NCryptBuffer *b = &pParameterList->pBuffers[i];
			if (b->BufferType == KDF_HKDF_INFO && b->pvBuffer && b->cbBuffer >= 4) {
				hkdfInfo = (PBYTE)b->pvBuffer;
				hkdfInfoLen = b->cbBuffer;
				break;
			}
		}
		if (!hkdfInfo)
			return ret;

		// Parse HkdfLabel: [u16 length][u8 label_len][label][u8 ctx_len][ctx]
		if (hkdfInfoLen < 3)
			return ret;
		DWORD labelLen = hkdfInfo[2];
		if (labelLen < 7 /* "tls13 " + at least 1 */ || 3 + labelLen > hkdfInfoLen)
			return ret;
		const char *label = (const char *)(hkdfInfo + 3);
		if (memcmp(label, "tls13 ", 6) != 0)
			return ret;
		const char *logical = label + 6;
		DWORD logicalLen = labelLen - 6;

		const char *nssLabel = NULL;
		if (logicalLen == 12 && !memcmp(logical, "c hs traffic", 12))
			nssLabel = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
		else if (logicalLen == 12 && !memcmp(logical, "s hs traffic", 12))
			nssLabel = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
		else if (logicalLen == 12 && !memcmp(logical, "c ap traffic", 12))
			nssLabel = "CLIENT_TRAFFIC_SECRET_0";
		else if (logicalLen == 12 && !memcmp(logical, "s ap traffic", 12))
			nssLabel = "SERVER_TRAFFIC_SECRET_0";
		else if (logicalLen == 10 && !memcmp(logical, "exp master", 10))
			nssLabel = "EXPORTER_SECRET";
		if (!nssLabel)
			return ret;

		TLS13ClientRandom *R = lookup_get(&ThreadTLS13ClientRandom, (ULONG_PTR)GetCurrentThreadId(), NULL);
		if (!R || !R->ClientRandomRepr[0]) {
#ifdef DEBUG_COMMENTS
			DebugOutput("BCryptKeyDerivation: TLS 1.3 %s derived but client_random not stashed", nssLabel);
#endif
			return ret;
		}

		char SecretRepr[48*2+1] = "";
		HexEncode(SecretRepr, pbDerivedKey, cbDerivedKey);
#ifdef DEBUG_COMMENTS
		DebugOutput("BCryptKeyDerivation: %s %s %s", nssLabel, R->ClientRandomRepr, SecretRepr);
#endif
		LogTls13(nssLabel, R->ClientRandomRepr, SecretRepr);
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		DebugOutput("BCryptKeyDerivation: exception parsing HKDF info");
	}

	return ret;
}

// ============================================================================
// BCryptDeriveKey hook ΓÇö catches TLS 1.2 master-secret derivation in modern
// WinHTTP / .NET in-process Schannel paths that bypass ncryptsslp.dll.
//
// Modern Win10/11 WinHTTP (and some .NET HttpClient paths) do not delegate
// TLS to lsass.exe via NCrypt ΓÇö they derive the master secret in-process by
// calling BCryptDeriveKey(hSecret, "TLS_PRF", ...) with a parameter list
// containing:
//   KDF_TLS_PRF_LABEL = "master secret" (13 bytes, no NUL)
//   KDF_TLS_PRF_SEED  = ClientHello.random || ServerHello.random (64 bytes)
// and output buffer sized 48 bytes = the TLS 1.2 master secret.
//
// We extract CR/SR from the seed and the master secret from the output buffer,
// then write an NSS-style line via LogTls() so wireshark/editcap can decrypt.
// ============================================================================

// Minimal local defs (bcrypt.h may not be included; BCryptBuffer/Desc share
// layout with NCryptBuffer/Desc ΓÇö same typedef root in the Windows SDK).
#ifndef KDF_TLS_PRF_LABEL
#define KDF_HASH_ALGORITHM  0x0
#define KDF_TLS_PRF_LABEL   0xC
#define KDF_TLS_PRF_SEED    0xD
#endif

typedef PVOID BCRYPT_SECRET_HANDLE;

HOOKDEF(NTSTATUS, WINAPI, BCryptDeriveKey,
	_In_		BCRYPT_SECRET_HANDLE	hSharedSecret,
	_In_		LPCWSTR					pwszKDF,
	_In_opt_	PNCryptBufferDesc		pParameterList,
	_Out_opt_	PUCHAR					pbDerivedKey,
	_In_		ULONG					cbDerivedKey,
	_Out_		ULONG					*pcbResult,
	_In_		ULONG					dwFlags
) {
	NTSTATUS ret = Old_BCryptDeriveKey(hSharedSecret, pwszKDF, pParameterList, pbDerivedKey, cbDerivedKey, pcbResult, dwFlags);

	// Only interested in successful TLS PRF derivations that produce a 48-byte
	// master secret. Other uses (key expansion, IV derivation, arbitrary KDF
	// consumers) we ignore ΓÇö wireshark derives the key block from master+randoms.
	if (ret != 0 || !pwszKDF || !pParameterList || !pbDerivedKey || cbDerivedKey != 48)
		return ret;

	__try {
		if (wcscmp(pwszKDF, L"TLS_PRF") != 0)
			return ret;

		BOOL isMasterSecret = FALSE;
		PBYTE seed = NULL;
		DWORD seedLen = 0;

		for (unsigned int i = 0; i < pParameterList->cBuffers; i++) {
			NCryptBuffer *b = &pParameterList->pBuffers[i];
			if (!b->pvBuffer || !b->cbBuffer)
				continue;
			if (b->BufferType == KDF_TLS_PRF_LABEL) {
				// Label is ASCII, no NUL. TLS 1.2 master secret derivation
				// uses the literal "master secret" (13 bytes, RFC 5246 ┬º8.1).
				if (b->cbBuffer == 13 && !memcmp(b->pvBuffer, "master secret", 13))
					isMasterSecret = TRUE;
			}
			else if (b->BufferType == KDF_TLS_PRF_SEED) {
				seed = (PBYTE)b->pvBuffer;
				seedLen = b->cbBuffer;
			}
		}

		// Key expansion derivations (seed = server_random||client_random,
		// label = "key expansion") are skipped by the isMasterSecret check.
		if (!isMasterSecret || !seed || seedLen != 64)
			return ret;

		char ClientRandomRepr[32*2+1] = "";
		char ServerRandomRepr[32*2+1] = "";
		char MasterSecretRepr[48*2+1] = "";
		HexEncode(ClientRandomRepr, seed, 32);
		HexEncode(ServerRandomRepr, seed + 32, 32);
		HexEncode(MasterSecretRepr, pbDerivedKey, 48);

#ifdef DEBUG_COMMENTS
		DebugOutput("BCryptDeriveKey: TLS 1.2 master secret captured CR=%s", ClientRandomRepr);
#endif
		LogTls(ClientRandomRepr, ServerRandomRepr, MasterSecretRepr);
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		DebugOutput("BCryptDeriveKey: exception inspecting parameter list");
	}

	return ret;
}
