/*
CAPE - Config And Payload Extraction
Copyright(C) 2020-2021 Kevin O'Reilly (kevoreilly@gmail.com)

This program is free software : you can redistribute it and / or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.If not, see <http://www.gnu.org/licenses/>.
*/
//#define DEBUG_COMMENTS
#include <stdio.h>
#include <windows.h>
#include "Shlwapi.h"
#include "CAPE.h"
#include "Debugger.h"
#include "YaraHarness.h"
#include "..\config.h"
#include "..\alloc.h"
#include "..\hook_static_crypto.h"

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern void ErrorOutput(_In_ LPCTSTR lpOutputString, ...);
extern BOOL SetInitialBreakpoints(PVOID ImageBase), DumpRegion(PVOID Address);
extern void GoRecoverSymbols(PVOID RegionBase, PBYTE Pclntab, PBYTE Buildinfo);
extern int GoPclntabVersion(PBYTE Pclntab);
extern BOOL remove_dll_range(ULONG_PTR addr);
extern char Action0[MAX_PATH], Action1[MAX_PATH], Action2[MAX_PATH], Action3[MAX_PATH];
extern void parse_config_line(char* line);
extern int ReverseScanForNonZero(PVOID Buffer, SIZE_T Size);
extern SIZE_T GetAccessibleSize(PVOID Buffer);
extern char *our_dll_path;
extern BOOL BreakpointsHit, TraceRunning;

YR_RULES* Rules = NULL;
BOOL YaraActivated, YaraLogging;
#ifdef _WIN64
extern PVOID LdrpInvertedFunctionTableSRWLock, LdrpMrdataLock;
#endif

char InternalYara[] =
	"rule capemon"
	"{strings:$hash = {d3 b9 46 1d 9a 14 bc 44 a1 61 c3 47 6a 0e 35 90 00 2c 28 81 dc a0 36 dc 2c 92 0c 7c b6 84 39 59}"
	"condition:all of them}"
#ifdef _WIN64
	"rule vDbgPrintExWithPrefixInternal"
	"{strings:$10_0_26100_3476 = {48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 54 41 56 41 57 48 83 EC 40 44 8A BC 24}"
	"$function = {40 55 53 56 41 54 41 55 41 56 41 57 48 81 EC 20 01 00 00 48 8D 6C 24 20 48 8B 05 [4] 48 33 C5 48 89 85 ?? 00 00 00 4C 89 4D ?? 44 89 45 ?? 44 8B E2 89 55 ?? 48 8B D1 48 89 4D ?? 48 8B 85}"
	"condition:uint16(0) == 0x5a4d and any of them}"
	"rule FindFixAndRun"
	"{strings:$function = {48 89 5C 24 10 48 89 74 24 18 57 41 54 41 55 41 56 41 57 48 81 EC [80-110] 85 C0 0F 88 [2] 00 00 49 8B 4? 70 66 83 (78|79) 02 3A 0F 84 [2] 00 00 48 8D 54 24 20 49 8B CE E8}"
	"condition:uint16(0) == 0x5a4d and any of them}"
#else
	"rule vDbgPrintExWithPrefixInternal"
	"{strings:$function = {68 90 00 00 00 68 [4] E8 [4] 89 95 [4] 89 8D [4] 8B 45 ?? 89 85 [4] 8B 45 ?? 89 85 [4] 64 A1 18 00 00 00 89 45 ?? 83 FA FF 0F 84}"
	"condition:uint16(0) == 0x5a4d and any of them}"
	"rule FindFixAndRun"
	"{strings:$function = {8B FF 55 8B EC 6A FE 68 [4] 68 [4] 64 A1 00 00 00 00 50 81 EC [90-96] 00 0F 84 [4] B8 E7 7F 00 00 50 8D 8D [4] E8 [4] 85 C0 0F 88 [4] 8B 4? 38 66 83 7? 02 3A 0F 84}"
	"condition:uint16(0) == 0x5a4d and any of them}"
#endif
	"rule RtlInsertInvertedFunctionTable"
	"{strings:$10_0_26100_3476 = {48 8D 0D [4] 49 F7 D8 48 8B F8 1B DB 23 5C 24 ?? E8 [4] 33 C9 E8}"
	"$10_0_19041_662 = {48 8D 0D [4] E8 [4] [7] 8B 44 24 ?? 44 8B CB 4C 8B 44 24 ?? 48 8B D7 89 44 24 ?? E8}"
	"$10_0_18362_1350 = {48 8D 0D [4] 33 D2 85 C0 48 0F 48 DA E8 [4] 33 C9 E8 [4] 8B 44 24 ?? 44 8B CF 4C 8B C3 89 44 24 ?? 48 8B D6 E8}"
	"$10_0_10240_16384 = {48 8D 0D [4] 48 8B E8 E8 [4] 33 C9 E8 [4] 8B 15 [4] 3B 15 [4] 0F 84}"
	"condition:uint16(0) == 0x5a4d and any of them}"
	"rule LdrProtectMrdata"
	"{strings:$10_0_19041_2788 = {48 8D 0D [4] E8 [4] 8B 3D [4] 85 DB 75 ?? 85 FF 75 ?? 8D 4B 04 E8}"
	"condition:uint16(0) == 0x5a4d and any of them}"
	"rule LdrpCallInitRoutine"
	"{strings:$10_0_26100_3476 = {40 53 56 57 41 54 41 55 [65-85] 84 03 FE 7F}"
	"$function = {55 8B EC 56 57 53 8B F4 [0-2] FF 75 14 FF 75 10 FF 75 0C FF 55 08 8B E6 5B 5F 5E 5D C2 10 00}"
	"condition:uint16(0) == 0x5a4d and any of them}"
	"rule WMI_ExecQuery"
	"{strings:$function = {4C 8B DC 56 57 41 54 41 56 41 57 48 83 EC 60 49 C7 43 B8 FE FF FF FF 49 89 5B 10 49 89 6B 18 45 8B E1 4D 8B F0 4C 8B F9 48 8B 41 08 48 83 78 20 00 0F 84}"
	"condition:uint16(0) == 0x5a4d and any of them}"
	"rule WMI_ExecMethod"
	"{strings:$function = {48 8B C4 56 57 41 54 41 56 41 57 48 83 EC 70 48 C7 40 B8 FE FF FF FF 48 89 58 10 48 89 68 18 45 8B E1 4D 8B F0 48 8B EA 4C 8B F9 48 8B 41 08 48 83 78 20 00 75 0A B8 08 01 01 80 E9}"
	"condition:uint16(0) == 0x5a4d and any of them}"
	"rule WMI_ExecQueryAsync"
	"{strings:$function = {4C 8B DC 56 57 41 54 41 56 41 57 48 83 EC 60 49 C7 43 B8 FE FF FF FF 49 89 5B 10 49 89 6B 18 45 8B E1 4D 8B F0 48 8B E9 48 8B 41 08 48 83 78 20 00 0F 84 [4] 49 83 63 08 00 4D 8D 43 08 E8}"
	"condition:uint16(0) == 0x5a4d and any of them}"
	"rule WMI_ExecMethodAsync"
	"{strings:$function = {48 8B C4 57 41 54 41 55 41 56 41 57 48 83 EC 60 48 C7 40 B8 FE FF FF FF 48 89 58 10 48 89 68 18 48 89 70 20 45 8B E9 4D 8B F8 4C 8B F2 48 8B E9 48 8B 41 08 48 83 78 20 00 75 0A B8 08 01 01 80 E9}"
	"condition:uint16(0) == 0x5a4d and any of them}"
	"rule WMI_GetObject"
	"{strings:$function = {4C 8B DC 56 57 41 54 41 56 41 57 48 83 EC 50 49 C7 43 ?? FE FF FF FF 49 89 5B 10 49 89 6B 18 4D 8B F9 45 8B E0 48 8B EA 4C 8B F1 48 8B 41 08 48 83 78 20 00 0F 84 12 AB 02 00 49 83 63 08 00 4D 8D 43 08 E8}"
	"condition:uint16(0) == 0x5a4d and any of them}"
	"rule WMI_GetObjectAsync"
	"{strings:$function = {48 8B C4 56 57 41 54 41 56 41 57 48 83 EC 40 48 C7 40 C8 FE FF FF FF 48 89 58 10 48 89 68 18 4D 8B F9 45 8B E0 48 8B EA 48 8B F1 48 8B 41 08 48 83 78 20 00 75 0A B8 08 01 01 80 E9}"
	"condition:uint16(0) == 0x5a4d and any of them}"
	// Go pclntab header (Go 1.2-1.15: FB, 1.16-1.17: FA, 1.18-1.19: F0, 1.20+: F1). 'golang' is a marker option,
	// not a config key: Go hooking is only performed when the user enabled go-hooks=1. The $pclntab and
	// $buildinfo ("\xff Go buildinf:") match addresses are passed to GoRecoverSymbols; $buildinfo is optional
	// (referenced via #buildinfo >= 0 so it is not rejected as an unreferenced string).
	// Condition is PE-independent: covers Go payloads in shellcode, private regions, and images with wiped PE headers.
	"rule golang"
	"{meta:cape_options = \"golang\""
	"strings:$pclntab = {(F0|F1|FA|FB) FF FF FF 00 00 (01|02|04) (04|08) [3] 00}"
	"$buildinfo = {FF 20 47 6F 20 62 75 69 6C 64 69 6E 66 3A}"
	"condition:#buildinfo >= 0 and "
	"for any i in (1..#pclntab) : (uint32(@pclntab[i] + 8) > 0 and uint32(@pclntab[i] + 8) < 500000)}"
	// Detect direct-syscall assembly stubs in 64-bit Go modules (e.g. BananaPhone, Hell's Gate).
	// $stub matches MOVQ CX, R10 (49 89 CA or 4C 8B D1) followed by SYSCALL (0F 05) within 24 bytes.
	// Sets sysbpmode=1 so the ntdll export returns cleanly to the instruction following SYSCALL in the stub.
	"rule golang_direct_syscall"
	"{meta:cape_options = \"sysbpmode=1,sysbp=$stub*-1\""
	"strings:$pclntab = {(F0|F1|FA|FB) FF FF FF 00 00 (01|02|04) 08 [3] 00}"
	"$stub = {(49 89 CA|4C 8B D1) [0-24] 0F 05}"
	"condition:$pclntab and $stub}";

// Hand-written Windows assembly primitives from BoringSSL, Rust ring / aws-lc-rs (rustls), and OpenSSL 1.1/3.x.
// Compiled in a separate string literal to stay well below MSVC's 16 KB C2026 string literal limit.
// Condition is PE-independent so unpacked/reflective images and wiped-header regions are matched automatically;
// hooks are only armed when the user opted in via crypto-hooks=1.
static const char StaticCryptoYara[] =
	"rule static_crypto"
	"{meta:cape_options = \"static_crypto\""
	"strings:"
#ifdef _WIN64
	"$bssl_aes_set_enc = {48 83 EC 08 0F 10 01 0F 57 E4 49 8D 40 10 81 FA 00 01 00 00 0F 84 [4] 81 FA C0 00 00 00 0F 84 [4] 81 FA 80 00 00 00 0F 85}"
	"$ossl_aes_set_enc = {48 83 EC 08 48 C7 C0 FF FF FF FF 48 85 C9 0F 84 [4] 4D 85 C0 0F 84 [4] 41 BA 00 08 00 10 0F 10 01 0F 57 E4 44 23 15 [4] 49 8D 40 10 81 FA 00 01 00 00 0F 84}"
	"$vpaes_set_enc = {48 89 7C 24 08 48 89 74 24 10 (48 89 E0|48 8B C4) (48 89 CF|48 8B F9) (48 89 D6|48 8B F2) (4C 89 C2|49 8B D0) [0-4] 48 8D A4 24 48 FF FF FF 0F 29 74 24 10 0F 29 7C 24 20 [55-68] (89 F0|8B C6) C1 E8 05 83 C0 05 89 82 F0 00 00 00 B9 00 00 00 00 41 B8 30 00 00 00 E8}"
	"$vpaes_set_dec = {48 89 7C 24 08 48 89 74 24 10 (48 89 E0|48 8B C4) (48 89 CF|48 8B F9) (48 89 D6|48 8B F2) (4C 89 C2|49 8B D0) [0-4] 48 8D A4 24 48 FF FF FF 0F 29 74 24 10 0F 29 7C 24 20 [55-68] (89 F0|8B C6) C1 E8 05 83 C0 05 89 82 F0 00 00 00 C1 E0 04 48 8D 54 02 10 B9 01 00 00 00}"
	"$aesni_cbc = {48 89 7C 24 08 48 89 74 24 10 (48 89 E0|48 8B C4) (48 89 CF|48 8B F9) (48 89 D6|48 8B F2) (4C 89 C2|49 8B D0) (4C 89 C9|49 8B C9) 4C 8B 44 24 28 4C 8B 4C 24 30 [0-4] 48 85 D2 0F 84 [4] 44 8B 91 F0 00 00 00 (49 89 CB|4C 8B D9) 45 85 C9 0F 84 [4] 41 0F 10 10}"
	"$bssl_gcm_enc = {48 (31|33) C0 49 81 F8 20 01 00 00 0F 82 [4] 55 48 (89 E5|8B EC) 53 41 54 41 55 41 56 41 57 48 8D A4 24 58 FF FF FF 48 89 7D 10 48 89 75 18 48 8B 7D 30}"
	"$bssl_gcm_dec = {48 (31|33) C0 49 83 F8 60 0F 82 [4] 55 48 (89 E5|8B EC) 53 41 54 41 55 41 56 41 57 48 8D A4 24 58 FF FF FF 48 89 7D 10 48 89 75 18 48 8B 7D 30}"
	"$ossl_gcm_enc = {48 89 7C 24 08 48 89 74 24 10 (48 89 E0|48 8B C4) (48 89 CF|48 8B F9) (48 89 D6|48 8B F2) (4C 89 C2|49 8B D0) (4C 89 C9|49 8B C9) 4C 8B 44 24 28 4C 8B 4C 24 30 [0-4] 4D (31|33) D2 48 81 FA 20 01 00 00 0F 82 [4] 48 8D 04 24 53 55 41 54 41 55 41 56 41 57 48 8D A4 24 58 FF FF FF}"
	"$ossl_gcm_dec = {48 89 7C 24 08 48 89 74 24 10 (48 89 E0|48 8B C4) (48 89 CF|48 8B F9) (48 89 D6|48 8B F2) (4C 89 C2|49 8B D0) (4C 89 C9|49 8B C9) 4C 8B 44 24 28 4C 8B 4C 24 30 [0-4] 4D (31|33) D2 48 83 FA 60 0F 82 [4] 48 8D 04 24 53 55 41 54 41 55 41 56 41 57 48 8D A4 24 58 FF FF FF}"
	"$vaes_gcm_enc = {56 57 41 54 48 8B 74 24 40 48 8B 7C 24 48 4C 8B 64 24 50 48 81 EC A0 00 00 00 C5 F9 7F 34 24 C5 F9 7F 7C 24 10 [185-235] 49 8D 41 10 C4 E2 7D 5A 10 C4 62 1D DC E2}"
	"$vaes_gcm_dec = {56 57 41 54 48 8B 74 24 40 48 8B 7C 24 48 4C 8B 64 24 50 48 81 EC A0 00 00 00 C5 F9 7F 34 24 C5 F9 7F 7C 24 10 [185-245] 41 83 FA 18 0F 8C [4] 0F 84 [4] C4 C2 7D 5A 93 30 FF FF FF C4 62 1D DC E2}"
	"$bssl_chacha_nohw = {48 89 7C 24 08 48 89 74 24 10 (48 89 E0|48 8B C4) (48 89 CF|48 8B F9) (48 89 D6|48 8B F2) (4C 89 C2|49 8B D0) (4C 89 C9|49 8B C9) 4C 8B 44 24 28 [0-4] 53 55 41 54 41 55 41 56 41 57 48 83 EC 58 F3 0F 6F 09 F3 0F 6F 51 10 F3 41 0F 6F 18}"
	"$bssl_chacha_ssse3 = {48 89 7C 24 08 48 89 74 24 10 (48 89 E0|48 8B C4) (48 89 CF|48 8B F9) (48 89 D6|48 8B F2) (4C 89 C2|49 8B D0) (4C 89 C9|49 8B C9) 4C 8B 44 24 28 [0-4] (49 89 E1|4C 8B CC) 48 83 EC 68 41 0F 29 71 D8 41 0F 29 79 E8 66 0F 6F 05 [4] F3 0F 6F 09 F3 0F 6F 51 10}"
	"$bssl_chacha_ssse3_4x = {48 89 7C 24 08 48 89 74 24 10 (48 89 E0|48 8B C4) (48 89 CF|48 8B F9) (48 89 D6|48 8B F2) (4C 89 C2|49 8B D0) (4C 89 C9|49 8B C9) 4C 8B 44 24 28 [0-4] (49 89 E1|4C 8B CC) 48 81 EC E8 01 00 00 41 0F 29 B1 58 FF FF FF 41 0F 29 B9 68 FF FF FF}"
	"$bssl_chacha_avx2 = {48 89 7C 24 08 48 89 74 24 10 (48 89 E0|48 8B C4) (48 89 CF|48 8B F9) (48 89 D6|48 8B F2) (4C 89 C2|49 8B D0) (4C 89 C9|49 8B C9) 4C 8B 44 24 28 [0-4] (49 89 E1|4C 8B CC) 48 81 EC 28 03 00 00 48 83 E4 E0 41 0F 29 B1 58 FF FF FF 41 0F 29 B9 68 FF FF FF}"
	"$ossl_chacha = {48 89 7C 24 08 48 89 74 24 10 (48 89 E0|48 8B C4) (48 89 CF|48 8B F9) (48 89 D6|48 8B F2) (4C 89 C2|49 8B D0) (4C 89 C9|49 8B C9) 4C 8B 44 24 28 [0-4] 48 83 FA 00 0F 84 [4] 4C 8B 15 [4] 41 F7 C2 00 02 00 00 0F 85 [4] 53 55 41 54 41 55 41 56 41 57 48 83 EC 58}"
	"$cc20p1305_open_sse41 = {48 89 7C 24 08 48 89 74 24 10 (48 89 E0|48 8B C4) (48 89 CF|48 8B F9) (48 89 D6|48 8B F2) (4C 89 C2|49 8B D0) (4C 89 C9|49 8B C9) 4C 8B 44 24 28 4C 8B 4C 24 30 [0-4] 55 53 41 54 41 55 41 56 41 57 41 51 48 81 EC E0 01 00 00 48 8D 6C 24 20 48 83 E5 E0 [50-58] (48 89 D3|48 8B DA) 4C 89 85 C0 00 00 00 48 89 9D C8 00 00 00 48 81 FB 80 00 00 00}"
	"$cc20p1305_seal_sse41 = {48 89 7C 24 08 48 89 74 24 10 (48 89 E0|48 8B C4) (48 89 CF|48 8B F9) (48 89 D6|48 8B F2) (4C 89 C2|49 8B D0) (4C 89 C9|49 8B C9) 4C 8B 44 24 28 4C 8B 4C 24 30 [0-4] 55 53 41 54 41 55 41 56 41 57 41 51 48 81 EC E0 01 00 00 48 8D 6C 24 20 48 83 E5 E0 [50-58] 49 8B 59 38 (48 01 D3|48 03 DA) 4C 89 85 C0 00 00 00 48 89 9D C8 00 00 00 (48 89 D3|48 8B DA) 48 81 FB 80 00 00 00}"
	"$cc20p1305_open_avx2 = {48 89 7C 24 08 48 89 74 24 10 (48 89 E0|48 8B C4) (48 89 CF|48 8B F9) (48 89 D6|48 8B F2) (4C 89 C2|49 8B D0) (4C 89 C9|49 8B C9) 4C 8B 44 24 28 4C 8B 4C 24 30 [0-4] 55 53 41 54 41 55 41 56 41 57 41 51 48 81 EC E0 01 00 00 48 8D 6C 24 20 48 83 E5 E0 [50-58] (48 89 D3|48 8B DA) 4C 89 85 C0 00 00 00 48 89 9D C8 00 00 00 C5 F8 77}"
	"$cc20p1305_seal_avx2 = {48 89 7C 24 08 48 89 74 24 10 (48 89 E0|48 8B C4) (48 89 CF|48 8B F9) (48 89 D6|48 8B F2) (4C 89 C2|49 8B D0) (4C 89 C9|49 8B C9) 4C 8B 44 24 28 4C 8B 4C 24 30 [0-4] 55 53 41 54 41 55 41 56 41 57 41 51 48 81 EC E0 01 00 00 48 8D 6C 24 20 48 83 E5 E0 [50-58] 49 8B 59 38 (48 01 D3|48 03 DA) 4C 89 85 C0 00 00 00 48 89 9D C8 00 00 00 (48 89 D3|48 8B DA) C5 F8 77}"
#else
	"$bssl_aes_set_enc_32 = {8B 44 24 04 8B 4C 24 08 8B 54 24 0C 53 E8 00 00 00 00 5B 8D 9B [4] 0F 10 00 0F 57 E4 8D 52 10 81 F9 00 01 00 00 0F 84 [4] 81 F9 C0 00 00 00 0F 84 [4] 81 F9 80 00 00 00 0F 85}"
	"$ossl_aes_set_enc_32 = {55 53 85 C0 0F 84 [4] 85 D2 0F 84 [4] E8 00 00 00 00 5B 8D 9B [4] 8D 2D [4] 0F 10 00 0F 57 E4 8B 6D 04 8D 52 10 81 E5 00 08 00 10 81 F9 00 01 00 00 0F 84}"
	"$vpaes_set_enc_32 = {55 53 56 57 8B 74 24 14 8D 5C 24 C8 8B 44 24 18 83 E3 F0 8B 54 24 1C 87 (E3|DC) 89 5C 24 30 (89 C3|8B D8) C1 EB 05 83 C3 05 89 9A F0 00 00 00 B9 30 00 00 00 BF 00 00 00 00}"
	"$vpaes_set_dec_32 = {55 53 56 57 8B 74 24 14 8D 5C 24 C8 8B 44 24 18 83 E3 F0 8B 54 24 1C 87 (E3|DC) 89 5C 24 30 (89 C3|8B D8) C1 EB 05 83 C3 05 89 9A F0 00 00 00 C1 E3 04 8D 54 1A 10 BF 01 00 00 00}"
	"$aesni_cbc_32 = {55 53 56 57 8B 74 24 14 (89 E3|8B DC) 8B 7C 24 18 83 EB 18 8B 44 24 1C 83 E3 F0 8B 54 24 20 8B 6C 24 24 85 C0 0F 84 [4] 83 7C 24 28 00 87 (E3|DC) 0F 10 7D 00 8B 8A F0 00 00 00}"
	"$bssl_chacha_nohw_32 = {55 53 56 57 8B 74 24 20 8B 7C 24 24 81 EC 84 00 00 00 8B 06 8B 5E 04 8B 4E 08 8B 56 0C 89 44 24 50 89 5C 24 54 89 4C 24 58 89 54 24 5C}"
	"$bssl_chacha_ssse3_32 = {55 53 56 57 E8 00 00 00 00 58 8B 7C 24 14 8B 74 24 18 8B 4C 24 1C 8B 54 24 20 8B 5C 24 24 (89 E5|8B EC) 81 EC 0C 02 00 00 83 E4 C0 89 AC 24 00 02 00 00}"
	"$ossl_chacha_32 = {55 53 56 57 (31|33) C0 3B 44 24 1C 0F 84 [4] 8B 74 24 20 8B 7C 24 24 81 EC 84 00 00 00 8B 06 8B 5E 04 8B 4E 08 8B 56 0C 89 44 24 50}"
#endif
	"condition:any of them}";

void ScannerError(int Error)
{
	switch (Error)
	{
		case ERROR_SUCCESS:
			break;
		case ERROR_COULD_NOT_MAP_FILE:  // exception scanning region
#ifdef DEBUG_COMMENTS
			DebugOutput("Yara error: exception scanning region.\n");
#endif
			break;
		case ERROR_COULD_NOT_ATTACH_TO_PROCESS:
			DebugOutput("Yara error: 'Cannot attach to process'\n");
			break;
		case ERROR_INSUFICIENT_MEMORY:
			DebugOutput("Yara error: Not enough memory\n");
			break;
		case ERROR_SCAN_TIMEOUT:
			DebugOutput("Yara error: Scanning timed out\n");
			break;
		case ERROR_COULD_NOT_OPEN_FILE:
			DebugOutput("Yara error: Could not open file\n");
			break;
		case ERROR_UNSUPPORTED_FILE_VERSION:
			DebugOutput("Yara error: Rules were compiled with a newer version of YARA.\n");
			break;
		case ERROR_CORRUPT_FILE:
			DebugOutput("Yara error: Corrupt compiled rules file.\n");
			break;
		default:
			DebugOutput("Yara error: Internal error: %d\n", Error);
			break;
	}
}

void ParseOptionLine(char* Line, char* Identifier, YR_MATCH* Match, void* user_data)
{
	char *Value, *Key, *p, *q, *r, c = 0;
	ULONG_PTR delta=0;
	SIZE_T ValueLength = 0;

	if (!Line || !Identifier)
		return;

	p = strchr(Line, '$');
	if (!p)
		return;

	p = strchr(Line, '=');
	if (!p)
		return;

	r = strchr(p, ':');
	if (r && *(r + 1) == '$')
		Value = r + 1;
	else
		Value = p + 1;
	q = strchr(Value, '+');
	if (q)
	{
		delta = strtoul(q+1, NULL, 0);
		if (*(q-1) == '*')
			delta += Match->match_length - 1;
	}
	else
	{
		q = strchr(Value, '-');
		if (q)
		{
			delta = - (int)strtoul(q+1, NULL, 0);
			if (*(q-1) == '*')
				delta += Match->match_length - 1;
		}
	}
	if (q)
	{
		ValueLength = (SIZE_T)(DWORD_PTR)(q-(DWORD_PTR)Value);
		if (*(q-1) == '*')
			ValueLength--;
	}
	else
		ValueLength = (SIZE_T)strlen(Value);

	if (*(Value+ValueLength-1) == '*')
	{
		ValueLength--;
		delta += Match->match_length - 1;
	}

	SIZE_T IdentifierLength = strlen(Identifier);
	if (strncmp(Value, Identifier, IdentifierLength < ValueLength ? IdentifierLength : ValueLength))
		return;

	Key = Line;
	if (r && *(r + 1) == '$')
	{
		c = *r;
		*r = 0;
	}
	else
	{
		c = *p;
		*p = 0;
	}

	if (_strnicmp(Line, "bp", 2) && strncmp(Line, "br", 2) && strncmp(Line, "sysbp", 5))
		delta += (ULONG_PTR)user_data;

	// was a file-static buffer written by every thread, with an unbounded
	// sprintf from rule metadata
	char NewLine[MAX_PATH];
	memset(NewLine, 0, sizeof(NewLine));
	if (r)
		_snprintf(NewLine, sizeof(NewLine) - 1, "%s%c0x%p%s", Key, c, (PUCHAR)Match->offset+delta, r);
	else
		_snprintf(NewLine, sizeof(NewLine) - 1, "%s%c0x%p", Key, c, (PUCHAR)Match->offset+delta);

	if (r && *(r + 1) == '$')
		*r = c;
	else
		*p = c;

#ifdef DEBUG_COMMENTS
	DebugOutput("ParseOptionLine: %s", NewLine);
#endif

	if (!strchr(NewLine, '$'))
		parse_config_line(NewLine);

	return;
}

int YaraCallback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
{
	switch(message)
	{
		case CALLBACK_MSG_RULE_NOT_MATCHING:
#ifdef DEBUG_COMMENTS
			DebugOutput("YaraScan rule did not match.");
#endif
		case CALLBACK_MSG_IMPORT_MODULE:
			return CALLBACK_CONTINUE;
		case CALLBACK_MSG_RULE_MATCHING:
			BOOL SetBreakpoints = FALSE, SetGoHooks = FALSE, SetStaticCryptoHooks = FALSE, DoDumpRegion = FALSE;
			YR_MATCH* Match;
			YR_STRING* String;
			YR_META* Meta;
			YR_RULE* Rule = (YR_RULE*)message_data;

			if (!strcmp(Rule->identifier, "capemon"))
				return CALLBACK_CONTINUE;

			if (!strcmp(Rule->identifier, "static_crypto") && !g_config.crypto_hooks)
				return CALLBACK_CONTINUE;

			DebugOutput("YaraScan hit: %s\n", Rule->identifier);
			if (TraceRunning)
				DebuggerOutput("YaraScan hit: %s ", Rule->identifier);

			// Process cape_options metadata
			yr_rule_metas_foreach(Rule, Meta)
			{
				if (Meta->type == META_TYPE_STRING && !strcmp(Meta->identifier, "cape_options"))
				{
					if (!strncmp(Rule->identifier, "golang", 6) && !g_config.go_hooks)
						return CALLBACK_CONTINUE;

					yr_rule_strings_foreach(Rule, String)
						yr_string_matches_foreach(context, String, Match)
						{
							DebugOutput("YaraScan match: %s (0x%x)", String->identifier, Match->offset);
							if (TraceRunning)
								DebuggerOutput("YaraScan match: %s (0x%x) ", String->identifier, Match->offset);
						}

					SIZE_T length = strlen(Meta->string);
					char* OptionLine = (char*)Meta->string;
					while (OptionLine && OptionLine < Meta->string + length)
					{
						char *p = strchr(OptionLine, ',');
						if (p)
							*p = 0;
						if (!strchr(OptionLine, '$'))
							parse_config_line(OptionLine);
						else
						{
							yr_rule_strings_foreach(Rule, String)
							{
								yr_string_matches_foreach(context, String, Match)
									ParseOptionLine(OptionLine, (char*)String->identifier, Match, user_data);
							}
						}
						if (!_strnicmp(OptionLine, "bp", 2) || !strncmp(OptionLine, "br", 2) || !strncmp(OptionLine, "sysbp", 5))
							SetBreakpoints = TRUE;
						if (!_stricmp(OptionLine, "golang"))
							SetGoHooks = TRUE;
						if (!_stricmp(OptionLine, "static_crypto"))
							SetStaticCryptoHooks = TRUE;
						if (!_stricmp("dump", OptionLine))
						{
							DebugOutput("YaraScan: Dump of region at 0x%p triggered by Yara.", user_data);
							if (TraceRunning)
								DebuggerOutput("YaraScan: Dump of region at 0x%p triggered by Yara ", user_data);
							DumpRegion(user_data);
						}
						if (!_stricmp("coverage", OptionLine))
						{
							if (remove_dll_range((ULONG_PTR)user_data))
								DebugOutput("YaraScan: Region at 0x%p removed from dll range for coverage.", user_data);
							else
								DebugOutput("YaraScan: Failed to remove region at 0x%p from dll range for coverage.", user_data);
						}
						if (!_stricmp("clear", OptionLine))
						{
							BreakpointsHit = FALSE;
							g_config.bp0 = NULL;
							g_config.bp1 = NULL;
							g_config.bp2 = NULL;
							g_config.bp3 = NULL;
							g_config.br0 = NULL;
							g_config.br1 = NULL;
							g_config.br2 = NULL;
							g_config.br3 = NULL;
							g_config.hc0 = 0;
							g_config.hc1 = 0;
							g_config.hc2 = 0;
							g_config.hc3 = 0;
							memset(Action0, 0, MAX_PATH);
							memset(Action1, 0, MAX_PATH);
							memset(Action2, 0, MAX_PATH);
							memset(Action3, 0, MAX_PATH);
						}
						if (p)
						{
							*p = ',';
							OptionLine = p+1;
						}
						else
							OptionLine = NULL;
					}
				}
			}

			if (DebuggerInitialised && SetBreakpoints)
				SetInitialBreakpoints(user_data);

			// Go runtime detected in this region: instrument it if the user opted in (go-hooks=1). The match addresses
			// are handed over so hook_go does no scanning; hits before debugger initialisation are queued there.
			if (SetGoHooks && g_config.go_hooks)
			{
				PBYTE Pclntab = NULL, Buildinfo = NULL;
				yr_rule_strings_foreach(Rule, String)
				{
					yr_string_matches_foreach(context, String, Match)
					{
						PBYTE Address = (PBYTE)user_data + Match->offset;
						if (!Pclntab && !strcmp(String->identifier, "$pclntab") && GoPclntabVersion(Address))
							Pclntab = Address;
						else if (!Buildinfo && !strcmp(String->identifier, "$buildinfo"))
							Buildinfo = Address;
					}
				}
				if (Pclntab)
					GoRecoverSymbols(user_data, Pclntab, Buildinfo);
			}

			// Statically linked BoringSSL / Rust ring / aws-lc-rs / OpenSSL assembly crypto primitives detected:
			// hand match addresses to hook_static_crypto when the user opted in (crypto-hooks=1).
			if (SetStaticCryptoHooks && g_config.crypto_hooks)
			{
				yr_rule_strings_foreach(Rule, String)
				{
					yr_string_matches_foreach(context, String, Match)
					{
						StaticCryptoRegisterMatch(user_data, (PBYTE)user_data + Match->offset, String->identifier);
					}
				}
			}

			return CALLBACK_CONTINUE;
	}

	return CALLBACK_ERROR;
}

int GetAddressesByYaraCallback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
{
    switch(message)
    {
        case CALLBACK_MSG_RULE_NOT_MATCHING:
#ifdef DEBUG_COMMENTS
            DebugOutput("YaraScan rule did not match.");
#endif
        case CALLBACK_MSG_IMPORT_MODULE:
            return CALLBACK_CONTINUE;

        case CALLBACK_MSG_RULE_MATCHING:
            YR_MATCH* Match;
            YR_STRING* String;
            YR_RULE* Rule = (YR_RULE*)message_data;
            NameByAddress* AddressInfos = (NameByAddress*)user_data;

#ifdef DEBUG_COMMENTS
            DebugOutput("GetAddressesByYaraCallback hit: %s\n", Rule->identifier);
#endif

            yr_rule_strings_foreach(Rule, String)
            {
                yr_string_matches_foreach(context, String, Match)
                {
                    for (SIZE_T i = 0; AddressInfos[i].FunctionName != NULL; i++)
                    {
                        if (!strcmp(Rule->identifier, AddressInfos[i].FunctionName))
                        {
#ifdef DEBUG_COMMENTS
                            DebugOutput("GetAddressesByYaraCallback: Found %s at RVA 0x%x", AddressInfos[i].FunctionName, Match->offset);
#endif
							AddressInfos[i].Address = (PVOID)Match->offset;
                            break;
                        }
                    }
                }
            }
            return CALLBACK_CONTINUE;
    }

    return CALLBACK_ERROR;
}

NameByAddress* GetAddressesByYara(HMODULE ModuleBase, PCHAR FunctionNames[], SIZE_T FunctionCount, SIZE_T* OutFoundCount)
{
    if (!YaraActivated || !FunctionNames || FunctionCount == 0)
        return NULL;

    SIZE_T Size = GetAccessibleSize(ModuleBase);
    if (!Size)
        return NULL;

    Size = (SIZE_T)ReverseScanForNonZero(ModuleBase, Size);
    if (!Size)
    {
        if (YaraLogging)
            DebugOutput("GetAddressesByYara: Nothing to scan at 0x%p!\n", ModuleBase);
        return NULL;
    }

    NameByAddress* AddressInfos = (NameByAddress*)calloc(FunctionCount + 1, sizeof(NameByAddress));
    if (!AddressInfos)
        return NULL;

    for (SIZE_T i = 0; i < FunctionCount; i++)
    {
        AddressInfos[i].FunctionName = FunctionNames[i];
        AddressInfos[i].Address = NULL;
    }

    int Flags = 0, Result = ERROR_SUCCESS;
    __try
    {
        Result = yr_rules_scan_mem(Rules, (PVOID)ModuleBase, Size, Flags, GetAddressesByYaraCallback, AddressInfos, g_config.yara_timeout);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        if (YaraLogging)
            DebugOutput("GetAddressesByYara: Unable to scan 0x%p\n", ModuleBase);
        free(AddressInfos);
        return NULL;
    }

    if (Result != ERROR_SUCCESS)
    {
        if (YaraLogging)
            ScannerError(Result);
        free(AddressInfos);
        return NULL;
    }

    SIZE_T FoundCount = 0;
    for (SIZE_T i = 0; i < FunctionCount; i++)
    {
        if (AddressInfos[i].Address)
        {
            AddressInfos[i].Address = (PVOID)((ULONG_PTR)ModuleBase + (ULONG_PTR)AddressInfos[i].Address);
            FoundCount++;
        }
    }

    if (OutFoundCount)
        *OutFoundCount = FoundCount;

    return AddressInfos;
}

PVOID GetAddressByYara(HMODULE ModuleBase, PCHAR FunctionName)
{
    if (!YaraActivated)
        return NULL;

    PCHAR FunctionNames[] = {FunctionName, NULL};
    SIZE_T FunctionCount = 1;
    SIZE_T FoundCount = 0;

    NameByAddress* Results = GetAddressesByYara(ModuleBase, FunctionNames, FunctionCount, &FoundCount);

    PVOID FoundAddress = NULL;
    if (Results && FoundCount > 0)
    {
        FoundAddress = Results[0].Address;
        free(Results);
    }

    return FoundAddress;
}

void YaraShutdown()
{
	YaraActivated = FALSE;

	if (Rules != NULL)
		yr_rules_destroy(Rules);

	yr_finalize();

	return;
}

void YaraScan(PVOID Address, SIZE_T Size)
{
	if (!YaraActivated)
		return;

	int Flags = 0, Result = ERROR_SUCCESS;

	if (!Size)
		return;

	SIZE_T AccessibleSize = GetAccessibleSize(Address);

	if (!AccessibleSize)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("YaraScan: Memory at 0x%p is inaccessible.\n", Address);
#endif
		return;
	}

	if (AccessibleSize < Size)
		Size = AccessibleSize;

	Size = (SIZE_T)ReverseScanForNonZero(Address, Size);

	if (!Size)
	{
		if (YaraLogging)
			DebugOutput("YaraScan: Nothing to scan at 0x%p!\n", Address);
		return;
	}

#ifndef DEBUG_COMMENTS
	if (YaraLogging)
#endif
		DebugOutput("YaraScan: Scanning 0x%p, size 0x%x\n", Address, Size);

	__try
	{
		Result = yr_rules_scan_mem(Rules, Address, Size, Flags, YaraCallback, Address, g_config.yara_timeout);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DebugOutput("YaraScan: Unable to scan 0x%p\n", Address);
		return;
	}
	if (Result != ERROR_SUCCESS)
		ScannerError(Result);
#ifdef DEBUG_COMMENTS
	else
		DebugOutput("YaraScan: successfully scanned 0x%p\n", Address);
#endif
}

void SilentYaraScan(PVOID Address, SIZE_T Size)
{
#ifndef DEBUG_COMMENTS
	BOOL PreviousYaraLogging = YaraLogging;
	YaraLogging = FALSE;
#endif
	YaraScan(Address, Size);
#ifndef DEBUG_COMMENTS
	YaraLogging = PreviousYaraLogging;
#endif
}

BOOL ScanForRulesCanary(PVOID Address, SIZE_T Size)
{
	BOOL PreviousYaraLogging = YaraLogging;
	YaraLogging = FALSE;
	BOOL CapemonRulesDetected = FALSE;
	if (GetAddressByYara(Address, "capemon"))
	{
		CapemonRulesDetected = TRUE;
		DebugOutput("ScanForRulesCanary: capemon rules detected");
	}
	YaraLogging = PreviousYaraLogging;
	return CapemonRulesDetected;
}

static unsigned int YaraAddRuleFiles(YR_COMPILER* Compiler, const char* dir)
{
	char FindString[MAX_PATH], file_name[MAX_PATH];
	WIN32_FIND_DATA FindFileData;
	unsigned int count = 0;

	snprintf(FindString, sizeof(FindString), "%s\\*.yar", dir);
#ifdef DEBUG_COMMENTS
	DebugOutput("YaraAddRuleFiles: Yara search string: %s", FindString);
#endif
	HANDLE hFind = FindFirstFile(FindString, &FindFileData);
	if (hFind == INVALID_HANDLE_VALUE)
		return 0;

	do
	{
		if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			continue;

		snprintf(file_name, sizeof(file_name), "%s\\%s", dir, FindFileData.cFileName);

		FILE* rule_file = fopen(file_name, "r");
		if (!rule_file)
			continue;

		char check_buf[4096];
		size_t bytes_read = fread(check_buf, 1, sizeof(check_buf) - 1, rule_file);
		check_buf[bytes_read] = '\0';

		if (strstr(check_buf, "cape_options") == NULL)
		{
			DebugOutput("YaraAddRuleFiles: File %s lacks cape_options metadata - skipping \n", file_name);
			fclose(rule_file);
			continue;
		}

		fseek(rule_file, 0, SEEK_SET);

		int errors = yr_compiler_add_file(Compiler, rule_file, NULL, file_name);

		if (errors == ERROR_COULD_NOT_OPEN_FILE)
			DebugOutput("YaraAddRuleFiles: Unable to open file %s\n", file_name);
		else if (errors)
		{
			DebugOutput("YaraAddRuleFiles: Unable to compile rule file %s\n", file_name);
			ScannerError(errors);
		}
		else
		{
			count++;
#ifdef DEBUG_COMMENTS
			DebugOutput("YaraAddRuleFiles: Compiled rule file %s\n", file_name);
#endif
		}

		fclose(rule_file);
	}
	while (FindNextFile(hFind, &FindFileData));

	FindClose(hFind);

	return count;
}

BOOL YaraInit()
{
	YR_COMPILER* Compiler = NULL;
	char analyzer_path[MAX_PATH], yara_dir[MAX_PATH], compiled_rules[MAX_PATH];
	BOOL Result = FALSE, RulesCompiled = FALSE;
	int flags = 0;

	// bound taken from the source: our_dll_path can exceed MAX_PATH
	strncpy(analyzer_path, our_dll_path, sizeof(analyzer_path) - 1);
	analyzer_path[sizeof(analyzer_path) - 1] = '\0';
	if (!g_config.standalone)
		PathRemoveFileSpec(analyzer_path);
	PathRemoveFileSpec(analyzer_path);
	sprintf(yara_dir, "%s\\data\\yara", analyzer_path);
	sprintf(compiled_rules, "%s\\capemon.yac", yara_dir);

	yr_initialize();

	FILE* rule_file = fopen(compiled_rules, "r");

	if (rule_file)
	{
		Result = yr_rules_load(compiled_rules, &Rules);

		fclose(rule_file);

		if (Result == ERROR_SUCCESS)
			DebugOutput("YaraInit: Compiled rules loaded from existing file %s\n", compiled_rules);
		else if (Result == ERROR_COULD_NOT_OPEN_FILE)
			DebugOutput("YaraInit: Unable to load existing compiled rules file %s\n", compiled_rules);
		else
		{
			DebugOutput("YaraInit: Error loading existing compiled rules file %s\n", compiled_rules);
			ScannerError(Result);
		}
	}
	else
	{
		if (yr_compiler_create(&Compiler) != ERROR_SUCCESS)
		{
			DebugOutput("YaraInit: yr_compiler_create failure\n");
			goto exit;
		}

		// Add 'internal' yara first
		if (yr_compiler_add_string(Compiler, InternalYara, NULL) != 0)
			DebugOutput("YaraInit: Failed to add internal yara rules.\n", compiled_rules);

		if (yr_compiler_add_string(Compiler, StaticCryptoYara, NULL) != 0)
			DebugOutput("YaraInit: Failed to add static_crypto yara rules.\n");

		unsigned int count = 0;

		if (g_config.yarascan)
		{
			count = YaraAddRuleFiles(Compiler, yara_dir);

			if (count)
				DebugOutput("YaraInit: Compiled %d rule files\n", count);
			else
			{
				DebugOutput("YaraInit: No usable rules in %s, trying %s\n", yara_dir, analyzer_path);
				count = YaraAddRuleFiles(Compiler, analyzer_path);
				if (count)
					DebugOutput("YaraInit: Compiled %d rule files\n", count);
				else
					DebugOutput("YaraInit: Found no Yara rules in %s or %s\n", yara_dir, analyzer_path);
			}
		}

		Result = yr_compiler_get_rules(Compiler, &Rules);

		if (Result != ERROR_SUCCESS)
		{
			ScannerError(Result);
			goto exit;
		}

		if (g_config.yarascan && count)
		{
			Result = yr_rules_save(Rules, compiled_rules);

			if (Result != ERROR_SUCCESS)
				ScannerError(Result);
			else
				DebugOutput("YaraInit: Compiled rules saved to file %s\n", compiled_rules);
		}

		yr_compiler_destroy(Compiler);
	}

	Compiler = NULL;

	YaraActivated = TRUE;
	YaraLogging = TRUE;

	OSVERSIONINFO OSVersion;
	OSVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

#pragma warning(suppress : 4996)
	if (!GetVersionEx(&OSVersion))
	{
		ErrorOutput("YaraInit: Failed to get OS version");
		return TRUE;
	}

#ifdef _WIN64
	if ((OSVersion.dwMajorVersion == 6 && OSVersion.dwMinorVersion > 1) || OSVersion.dwMajorVersion > 6)
	{
		HMODULE hNtdll = GetModuleHandleA("ntdll");
		if (hNtdll)
		{
			PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
			PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)hNtdll + dos->e_lfanew);
			PBYTE ntdll_base = (PBYTE)hNtdll;
			PBYTE ntdll_end = ntdll_base + nt->OptionalHeader.SizeOfImage;
			PVOID RtlInsertInvertedFunctionTable = GetAddressByYara(hNtdll, "RtlInsertInvertedFunctionTable");
			PVOID LdrProtectMrdata;

			if (RtlInsertInvertedFunctionTable)
			{
				PVOID resolved = (PVOID)((PBYTE)RtlInsertInvertedFunctionTable + *(LONG*)((PBYTE)RtlInsertInvertedFunctionTable + 3) + 7);
				if ((PBYTE)resolved >= ntdll_base && (PBYTE)resolved <= ntdll_end - sizeof(PVOID))
				{
					LdrpInvertedFunctionTableSRWLock = resolved;
					DebugOutput("RtlInsertInvertedFunctionTable 0x%p, LdrpInvertedFunctionTableSRWLock 0x%p", RtlInsertInvertedFunctionTable, LdrpInvertedFunctionTableSRWLock);
				}
			}
			LdrProtectMrdata = GetAddressByYara(hNtdll, "LdrProtectMrdata");
			if (LdrProtectMrdata)
			{
				PVOID resolved = (PVOID)((PBYTE)LdrProtectMrdata + *(LONG*)((PBYTE)LdrProtectMrdata + 3) + 7);
				if ((PBYTE)resolved >= ntdll_base && (PBYTE)resolved <= ntdll_end - sizeof(PVOID))
				{
					LdrpMrdataLock = resolved;
					DebugOutput("LdrProtectMrdata 0x%p, LdrpMrdataLock 0x%p", LdrProtectMrdata, LdrpMrdataLock);
				}
			}
		}
	}
#endif

	return TRUE;
exit:
	if (Compiler != NULL)
		yr_compiler_destroy(Compiler);

	if (Rules != NULL)
		yr_rules_destroy(Rules);

	yr_finalize();

	return FALSE;
}
