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
static BOOL Logged;
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
		TlsLog = CreateFile(FullPathName, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (TlsLog != INVALID_HANDLE_VALUE) {
		memset(SecretsLine, 0, BUFFER_SIZE);
		_snprintf_s(SecretsLine, BUFFER_SIZE, _TRUNCATE, "client_random: %s, server_random: %s, master_secret: %s\n", ClientRandomRepr, ServerRandomRepr, MasterSecretRepr);
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
	if (*pbInput == 1 && *pwVersion == 0x0303) {
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
	DebugOutput("SslExpandTrafficKeys: hHashValue 0x%x", hHashValue);
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
	DebugOutput("SslExpandExporterMasterKey: hHashValue 0x%x", hHashValue);
	return ret;
}
