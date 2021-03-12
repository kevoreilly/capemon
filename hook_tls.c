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
#include "hooking.h"
#include "log.h"
#include "pipe.h"
#include "misc.h"
#include <Shlwapi.h>

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern char* GetResultsPath(char* FolderName);
#define BUFFER_SIZE 0x1000
CHAR SecretsLine[BUFFER_SIZE];
HANDLE TlsLog;

void hexencode(char *dst, const uint8_t *src, uint32_t length)
{
	static const char charset[] = "0123456789abcdef";
	for (; length != 0; src++, length--) {
		*dst++ = charset[*src >> 4];
		*dst++ = charset[*src & 15];
	}
	*dst = 0;
}

HOOKDEF(NTSTATUS, WINAPI, PRF,
	void *unk1,
	uintptr_t unk2,
	uint8_t *buf1,
	uintptr_t buf1_length,
	const char *type,
	uint32_t type_length,
	uint8_t *buf2,
	uint32_t buf2_length,
	uint8_t *buf3,
	uint32_t buf3_length
) {
	NTSTATUS ret;
	char *FullPathName;
	uintptr_t master_secret_length = 0, random_length = 0;
	uint8_t *master_secret = NULL, *client_random = NULL;
	uint8_t *server_random = NULL;

	char client_random_repr[32*2+1] = "";
	char server_random_repr[32*2+1] = "";
	char master_secret_repr[48*2+1] = "";

	if (type_length == 13 && strcmp(type, "key expansion") == 0 && buf2_length == 64) {
		SIZE_T LastWriteLength;
		master_secret_length = buf1_length;
		master_secret = buf1;

		random_length = 32;
		server_random = buf2;
		client_random = buf2 + random_length;

		hexencode(client_random_repr, client_random, random_length);
		hexencode(server_random_repr, server_random, random_length);
		hexencode(master_secret_repr, master_secret, master_secret_length);

		FullPathName = GetResultsPath("tlsdump");
		PathAppend(FullPathName, "tlsdump.log");
		DebugOutput("PRF: Path %s", FullPathName);
		if (!TlsLog)
			TlsLog = CreateFile(FullPathName, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (TlsLog != INVALID_HANDLE_VALUE) {
			memset(SecretsLine, 0, BUFFER_SIZE);
			_snprintf_s(SecretsLine, BUFFER_SIZE, _TRUNCATE, "client_random: %s, server_random: %s, master_secret: %s\n", client_random_repr, server_random_repr, master_secret_repr);
			WriteFile(TlsLog, SecretsLine, (DWORD)strlen(SecretsLine), (LPDWORD)&LastWriteLength, NULL);
		}
	}

	ret = Old_PRF(unk1, unk2, buf1, buf1_length, type, type_length, buf2, buf2_length, buf3, buf3_length);

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, Ssl3GenerateKeyMaterial,
	uintptr_t unk1,
	uint8_t *secret,
	uintptr_t secret_length,
	uint8_t *seed,
	uintptr_t seed_length,
	void *unk2,
	uintptr_t unk3
) {
	NTSTATUS ret;
	char *FullPathName;
	int random_length = 32;
	uint8_t *client_random = seed;
	uint8_t *server_random = seed + random_length;

	char client_random_repr[32*2+1] = "";
	char server_random_repr[32*2+1] = "";
	char master_secret_repr[48*2+1] = "";

	if (seed_length == 64 && secret_length == 48) {
		SIZE_T LastWriteLength;
		hexencode(client_random_repr, client_random, random_length);
		hexencode(server_random_repr, server_random, random_length);
		hexencode(master_secret_repr, secret, secret_length);

		FullPathName = GetResultsPath("tlsdump");
		PathAppend(FullPathName, "tlsdump.log");
		DebugOutput("Ssl3GenerateKeyMaterial: Path %s", FullPathName);
		if (!TlsLog)
			TlsLog = CreateFile(FullPathName, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (TlsLog != INVALID_HANDLE_VALUE) {
			memset(SecretsLine, 0, BUFFER_SIZE);
			_snprintf_s(SecretsLine, BUFFER_SIZE, _TRUNCATE, "client_random: %s, server_random: %s, master_secret: %s\n", client_random_repr, server_random_repr, master_secret_repr);
			WriteFile(TlsLog, SecretsLine, (DWORD)strlen(SecretsLine), (LPDWORD)&LastWriteLength, NULL);
		}
	}

	ret = Old_Ssl3GenerateKeyMaterial(unk1, secret, secret_length, seed, seed_length, unk2, unk3);

	return ret;
}
