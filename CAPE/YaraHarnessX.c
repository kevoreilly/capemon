/*
CAPE - Config And Payload Extraction

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

//
// YARA-X backend for the CAPE in-monitor scanner.
//
// Drop-in replacement for YaraHarness.c: exposes the identical public API
// (YaraHarness.h) but is implemented against the YARA-X C API (yara_x.h).
// Exactly ONE of YaraHarness.c / YaraHarnessX.c is compiled into capemon -
// selected in the project file. This file is built when the project defines
// CAPE_USE_YARA_X.
//
// Behavioural parity notes vs the libyara backend:
//   * "cape_options" string metadata drives dynamic config exactly as before;
//     $pattern references in option lines are resolved to matched offsets.
//   * Compiled-rule cache uses a distinct filename (capemon.yrx) because the
//     serialised blob format differs and is locked to the YARA-X version.
//   * YARA-X scanners are single-threaded objects, so this backend keeps one
//     scanner per thread (YARA-X explicitly supports sharing the YRX_RULES
//     across threads) plus a re-entrancy guard.
//

//#define DEBUG_COMMENTS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "Shlwapi.h"
#include "CAPE.h"
#include "Debugger.h"
#include "YaraHarness.h"
#include "..\config.h"
#include "..\alloc.h"

#include "yara_x.h"

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern void ErrorOutput(_In_ LPCTSTR lpOutputString, ...);
extern BOOL SetInitialBreakpoints(PVOID ImageBase), DumpRegion(PVOID Address);
extern BOOL remove_dll_range(ULONG_PTR addr);
extern char Action0[MAX_PATH], Action1[MAX_PATH], Action2[MAX_PATH], Action3[MAX_PATH];
extern void parse_config_line(char* line);
extern int ReverseScanForNonZero(PVOID Buffer, SIZE_T Size);
extern SIZE_T GetAccessibleSize(PVOID Buffer);
extern char *our_dll_path;
extern BOOL BreakpointsHit, TraceRunning;

static YRX_RULES* Rules = NULL;
BOOL YaraActivated, YaraLogging;
#ifdef _WIN64
extern PVOID LdrpInvertedFunctionTableSRWLock;
#endif

static char NewLine[MAX_PATH];

// --- per-thread scanner state ------------------------------------------------
// YRX_SCANNER is not thread-safe and is stateful across a scan, so each thread
// gets its own, lazily created from the shared YRX_RULES. A registry lets
// YaraShutdown() destroy them before the rules (required ordering).
typedef struct _ScannerNode {
	YRX_SCANNER* Scanner;
	struct _ScannerNode* Next;
} ScannerNode;

static ScannerNode* ScannerList = NULL;
static CRITICAL_SECTION ScannerLock;
static BOOL ScannerLockInit = FALSE;

static __declspec(thread) YRX_SCANNER* t_Scanner = NULL;
static __declspec(thread) int t_Scanning = 0;

// t_Scanner is thread-local, so YaraShutdown() (running on one thread) cannot
// clear other threads' cached pointers before it destroys the YRX_SCANNER /
// YRX_RULES they point at. Every scan takes this lock shared for its duration;
// YaraShutdown() takes it exclusive before destroying anything, which blocks
// until all in-flight scans on every thread have returned.
static SRWLOCK ScanShutdownLock = SRWLOCK_INIT;

// Upper bound on the pattern matches materialised per rule hit. Config rules
// carry only a handful; this just caps a pathological rule.
#define MAX_RULE_MATCHES 512
#define MATCH_IDENT_MAX  96

typedef struct {
	char   Identifier[MATCH_IDENT_MAX];
	size_t Offset;
	size_t Length;
} MatchInfo;

typedef struct {
	MatchInfo Items[MAX_RULE_MATCHES];
	int       Count;
	char      CurIdentifier[MATCH_IDENT_MAX];
} MatchCollector;

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
	"condition:uint16(0) == 0x5a4d and any of them}";

static void ScannerError(enum YRX_RESULT Result, const char* Where)
{
	const char* detail;

	switch (Result)
	{
		case YRX_SUCCESS:
			return;
		case YRX_SCAN_TIMEOUT:
			DebugOutput("YaraScan (%s): scan timed out\n", Where);
			return;
		case YRX_SCAN_ERROR:
			detail = yrx_last_error();
			DebugOutput("YaraScan (%s): scan error%s%s\n", Where, detail ? ": " : "", detail ? detail : "");
			return;
		case YRX_SERIALIZATION_ERROR:
			DebugOutput("YaraScan (%s): compiled-rule (de)serialisation failed - rules will be recompiled\n", Where);
			return;
		case YRX_SYNTAX_ERROR:
			detail = yrx_last_error();
			DebugOutput("YaraScan (%s): rule syntax error%s%s\n", Where, detail ? ": " : "", detail ? detail : "");
			return;
		default:
			detail = yrx_last_error();
			DebugOutput("YaraScan (%s): error %d%s%s\n", Where, (int)Result, detail ? ": " : "", detail ? detail : "");
			return;
	}
}

// Copies a possibly non-NUL-terminated (ptr,len) identifier into Dst, ensuring
// a leading '$' so it compares the same way libyara's identifiers did.
// (YARA-X already returns "$name", so the prefix is normally a no-op.)
static void CopyPatternIdentifier(char* Dst, size_t DstSize, const uint8_t* Src, size_t SrcLen)
{
	size_t di = 0, si = 0;

	if (DstSize == 0)
		return;

	if (!Src || SrcLen == 0)
	{
		Dst[0] = 0;
		return;
	}

	if (Src[0] != '$' && di < DstSize - 1)
		Dst[di++] = '$';

	while (si < SrcLen && di < DstSize - 1)
		Dst[di++] = (char)Src[si++];

	Dst[di] = 0;
}

void ParseOptionLine(char* Line, char* Identifier, size_t MatchOffset, size_t MatchLength, void* user_data)
{
	char *Value, *Key, *p, *q, *r, c = 0;
	ULONG_PTR delta = 0;
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
		delta = strtoul(q + 1, NULL, 0);
		if (*(q - 1) == '*')
			delta += MatchLength - 1;
	}
	else
	{
		q = strchr(Value, '-');
		if (q)
		{
			delta = -(int)strtoul(q + 1, NULL, 0);
			if (*(q - 1) == '*')
				delta += MatchLength - 1;
		}
	}
	if (q)
	{
		ValueLength = (SIZE_T)(DWORD_PTR)(q - (DWORD_PTR)Value);
		if (*(q - 1) == '*')
			ValueLength--;
	}
	else
		ValueLength = (SIZE_T)strlen(Value);

	if (*(Value + ValueLength - 1) == '*')
	{
		ValueLength--;
		delta += MatchLength - 1;
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

	memset(NewLine, 0, sizeof(NewLine));
	if (r)
		sprintf(NewLine, "%s%c0x%p%s", Key, c, (PUCHAR)MatchOffset + delta, r);
	else
		sprintf(NewLine, "%s%c0x%p", Key, c, (PUCHAR)MatchOffset + delta);

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

// --- YARA-X iteration callbacks --------------------------------------------

static void MatchCollectCallback(const struct YRX_MATCH* Match, void* user_data)
{
	MatchCollector* mc = (MatchCollector*)user_data;

	if (!Match || mc->Count >= MAX_RULE_MATCHES)
		return;

	strncpy(mc->Items[mc->Count].Identifier, mc->CurIdentifier, MATCH_IDENT_MAX - 1);
	mc->Items[mc->Count].Identifier[MATCH_IDENT_MAX - 1] = 0;
	mc->Items[mc->Count].Offset = Match->offset;
	mc->Items[mc->Count].Length = Match->length;
	mc->Count++;
}

static void PatternCollectCallback(const struct YRX_PATTERN* Pattern, void* user_data)
{
	MatchCollector* mc = (MatchCollector*)user_data;
	const uint8_t* id = NULL;
	size_t idlen = 0;

	if (yrx_pattern_identifier(Pattern, &id, &idlen) == YRX_SUCCESS)
		CopyPatternIdentifier(mc->CurIdentifier, MATCH_IDENT_MAX, id, idlen);
	else
		mc->CurIdentifier[0] = 0;

	yrx_pattern_iter_matches(Pattern, MatchCollectCallback, mc);
}

typedef struct {
	char* CapeOptions;   // heap copy owned by ConfigRuleCallback (see below)
} MetaScan;

static void MetaScanCallback(const struct YRX_METADATA* Meta, void* user_data)
{
	MetaScan* ms = (MetaScan*)user_data;

	// The YRX_METADATA (and every pointer inside it) is freed as soon as this
	// callback returns, so the value must be copied out here, not aliased.
	if (ms->CapeOptions)
		return;
	if (Meta && Meta->value_type == YRX_STRING && Meta->identifier &&
		!strcmp(Meta->identifier, "cape_options") && Meta->value.string)
		ms->CapeOptions = _strdup(Meta->value.string);
}

// --- matching-rule callbacks ---------------------------------------------------

static void ConfigRuleCallback(const struct YRX_RULE* Rule, void* user_data)
{
	char RuleId[256];
	const uint8_t* rid = NULL;
	size_t ridlen = 0;
	BOOL SetBreakpoints = FALSE;
	MetaScan ms = { NULL };
	MatchCollector* mc;
	SIZE_T length;
	char* OptionLine;
	int i;

	if (yrx_rule_identifier(Rule, &rid, &ridlen) != YRX_SUCCESS || !rid)
		return;
	if (ridlen >= sizeof(RuleId))
		ridlen = sizeof(RuleId) - 1;
	memcpy(RuleId, rid, ridlen);
	RuleId[ridlen] = 0;

	if (!strcmp(RuleId, "capemon"))
		return;

	DebugOutput("YaraScan hit: %s\n", RuleId);
	if (TraceRunning)
		DebuggerOutput("YaraScan hit: %s ", RuleId);

	yrx_rule_iter_metadata(Rule, MetaScanCallback, &ms);
	if (!ms.CapeOptions)
		return;

	mc = (MatchCollector*)calloc(1, sizeof(MatchCollector));
	if (!mc)
	{
		free(ms.CapeOptions);
		return;
	}

	yrx_rule_iter_patterns(Rule, PatternCollectCallback, mc);

	for (i = 0; i < mc->Count; i++)
	{
		DebugOutput("YaraScan match: %s (0x%x)", mc->Items[i].Identifier, (unsigned)mc->Items[i].Offset);
		if (TraceRunning)
			DebuggerOutput("YaraScan match: %s (0x%x) ", mc->Items[i].Identifier, (unsigned)mc->Items[i].Offset);
	}

	length = (SIZE_T)strlen(ms.CapeOptions);
	OptionLine = ms.CapeOptions;
	while (OptionLine && OptionLine < ms.CapeOptions + length)
	{
		char* p = strchr(OptionLine, ',');
		if (p)
			*p = 0;

		if (!strchr(OptionLine, '$'))
			parse_config_line(OptionLine);
		else
		{
			for (i = 0; i < mc->Count; i++)
				ParseOptionLine(OptionLine, mc->Items[i].Identifier, mc->Items[i].Offset, mc->Items[i].Length, user_data);
		}

		if (!_strnicmp(OptionLine, "bp", 2) || !strncmp(OptionLine, "br", 2) || !strncmp(OptionLine, "sysbp", 5))
			SetBreakpoints = TRUE;

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
			OptionLine = p + 1;
		}
		else
			OptionLine = NULL;
	}

	if (DebuggerInitialised && SetBreakpoints)
		SetInitialBreakpoints(user_data);

	free(mc);
	free(ms.CapeOptions);
}

static void AddressRuleCallback(const struct YRX_RULE* Rule, void* user_data)
{
	NameByAddress* AddressInfos = (NameByAddress*)user_data;
	char RuleId[256];
	const uint8_t* rid = NULL;
	size_t ridlen = 0;
	MatchCollector* mc;
	int i;
	SIZE_T j;

	if (yrx_rule_identifier(Rule, &rid, &ridlen) != YRX_SUCCESS || !rid)
		return;
	if (ridlen >= sizeof(RuleId))
		ridlen = sizeof(RuleId) - 1;
	memcpy(RuleId, rid, ridlen);
	RuleId[ridlen] = 0;

	mc = (MatchCollector*)calloc(1, sizeof(MatchCollector));
	if (!mc)
		return;

	yrx_rule_iter_patterns(Rule, PatternCollectCallback, mc);

	// Match libyara backend: for the AddressInfos entry whose name equals the
	// rule identifier, record the offset of the last match seen for the rule.
	for (j = 0; AddressInfos[j].FunctionName != NULL; j++)
	{
		if (strcmp(RuleId, AddressInfos[j].FunctionName))
			continue;
		for (i = 0; i < mc->Count; i++)
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("AddressRuleCallback: %s at RVA 0x%x", AddressInfos[j].FunctionName, (unsigned)mc->Items[i].Offset);
#endif
			AddressInfos[j].Address = (PVOID)mc->Items[i].Offset;
		}
	}

	free(mc);
}

// --- scanner lifecycle -------------------------------------------------------

static YRX_SCANNER* GetThreadScanner(void)
{
	YRX_SCANNER* s;
	ScannerNode* node;

	if (t_Scanner)
		return t_Scanner;
	if (!Rules)
		return NULL;

	s = NULL;
	if (yrx_scanner_create(Rules, &s) != YRX_SUCCESS || !s)
	{
		if (YaraLogging)
			DebugOutput("YaraScan: yrx_scanner_create failed\n");
		return NULL;
	}

	if (g_config.yara_timeout > 0)
		yrx_scanner_set_timeout(s, (uint64_t)g_config.yara_timeout);

	node = (ScannerNode*)calloc(1, sizeof(ScannerNode));
	if (node && ScannerLockInit)
	{
		node->Scanner = s;
		EnterCriticalSection(&ScannerLock);
		node->Next = ScannerList;
		ScannerList = node;
		LeaveCriticalSection(&ScannerLock);
	}
	else if (node)
	{
		free(node);
	}

	t_Scanner = s;
	return s;
}

// --- public API ------------------------------------------------------------

static void YaraScanInternal(PVOID Address, SIZE_T Size, YRX_RULE_CALLBACK Callback, void* CallbackData, const char* Where)
{
	YRX_SCANNER* Scanner;
	enum YRX_RESULT Result = YRX_SUCCESS;

	if (!YaraActivated || !Size)
		return;

	if (t_Scanning)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("YaraScan (%s): re-entrant scan on same thread skipped\n", Where);
#endif
		return;
	}

	// Shared for the whole scan: blocks YaraShutdown() from destroying this
	// thread's scanner (or the shared Rules) out from under yrx_scanner_scan().
	AcquireSRWLockShared(&ScanShutdownLock);

	if (!YaraActivated)
	{
		ReleaseSRWLockShared(&ScanShutdownLock);
		return;
	}

	Scanner = GetThreadScanner();
	if (!Scanner)
	{
		ReleaseSRWLockShared(&ScanShutdownLock);
		return;
	}

	if (yrx_scanner_on_matching_rule(Scanner, Callback, CallbackData) != YRX_SUCCESS)
	{
		ReleaseSRWLockShared(&ScanShutdownLock);
		return;
	}

	t_Scanning = 1;
	__try
	{
		Result = yrx_scanner_scan(Scanner, (const uint8_t*)Address, (size_t)Size);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		t_Scanning = 0;
		ReleaseSRWLockShared(&ScanShutdownLock);
		if (YaraLogging)
			DebugOutput("YaraScan (%s): exception scanning 0x%p\n", Where, Address);
		return;
	}
	t_Scanning = 0;
	ReleaseSRWLockShared(&ScanShutdownLock);

	if (Result != YRX_SUCCESS)
		ScannerError(Result, Where);
}

void YaraScan(PVOID Address, SIZE_T Size)
{
	SIZE_T AccessibleSize;

	if (!YaraActivated || !Size)
		return;

	AccessibleSize = GetAccessibleSize(Address);
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

	YaraScanInternal(Address, Size, ConfigRuleCallback, Address, "YaraScan");
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

NameByAddress* GetAddressesByYara(HMODULE ModuleBase, PCHAR FunctionNames[], SIZE_T FunctionCount, SIZE_T* OutFoundCount)
{
	NameByAddress* AddressInfos;
	SIZE_T Size, FoundCount, i;

	if (!YaraActivated || !FunctionNames || FunctionCount == 0)
		return NULL;

	Size = GetAccessibleSize(ModuleBase);
	if (!Size)
		return NULL;

	Size = (SIZE_T)ReverseScanForNonZero(ModuleBase, Size);
	if (!Size)
	{
		if (YaraLogging)
			DebugOutput("GetAddressesByYara: Nothing to scan at 0x%p!\n", ModuleBase);
		return NULL;
	}

	AddressInfos = (NameByAddress*)calloc(FunctionCount + 1, sizeof(NameByAddress));
	if (!AddressInfos)
		return NULL;

	for (i = 0; i < FunctionCount; i++)
	{
		AddressInfos[i].FunctionName = FunctionNames[i];
		AddressInfos[i].Address = NULL;
	}

	YaraScanInternal((PVOID)ModuleBase, Size, AddressRuleCallback, AddressInfos, "GetAddressesByYara");

	FoundCount = 0;
	for (i = 0; i < FunctionCount; i++)
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
	PCHAR FunctionNames[] = { FunctionName, NULL };
	SIZE_T FoundCount = 0;
	NameByAddress* Results;
	PVOID FoundAddress = NULL;

	if (!YaraActivated)
		return NULL;

	Results = GetAddressesByYara(ModuleBase, FunctionNames, 1, &FoundCount);
	if (Results && FoundCount > 0)
	{
		FoundAddress = Results[0].Address;
		free(Results);
	}
	else if (Results)
	{
		free(Results);
	}

	return FoundAddress;
}

BOOL ScanForRulesCanary(PVOID Address, SIZE_T Size)
{
	BOOL PreviousYaraLogging = YaraLogging;
	BOOL CapemonRulesDetected = FALSE;

	YaraLogging = FALSE;
	if (GetAddressByYara(Address, "capemon"))
	{
		CapemonRulesDetected = TRUE;
		DebugOutput("ScanForRulesCanary: capemon rules detected");
	}
	YaraLogging = PreviousYaraLogging;
	return CapemonRulesDetected;
}

void YaraShutdown()
{
	ScannerNode* node;

	YaraActivated = FALSE;

	// Wait for every in-flight YaraScanInternal() (on any thread) to finish
	// and release its shared hold before destroying the scanners/Rules those
	// calls (or a not-yet-started one whose thread already cached t_Scanner)
	// may still be using. See the comment on ScanShutdownLock's declaration.
	AcquireSRWLockExclusive(&ScanShutdownLock);

	if (ScannerLockInit)
	{
		EnterCriticalSection(&ScannerLock);
		node = ScannerList;
		ScannerList = NULL;
		LeaveCriticalSection(&ScannerLock);

		while (node)
		{
			ScannerNode* next = node->Next;
			if (node->Scanner)
				yrx_scanner_destroy(node->Scanner);
			free(node);
			node = next;
		}
	}

	t_Scanner = NULL;

	if (Rules)
	{
		yrx_rules_destroy(Rules);
		Rules = NULL;
	}

	ReleaseSRWLockExclusive(&ScanShutdownLock);

	// Deliberately NOT calling yrx_finalize(): it tears down process-wide
	// wasmtime exception-handler state and is unsafe while capemon's own VEH
	// and debugger are active. capemon lives for the process lifetime anyway.
}

// Reads an entire file into a NUL-terminated heap buffer (caller frees).
static char* ReadWholeFile(const char* Path, size_t* OutLen)
{
	FILE* f = fopen(Path, "rb");
	long len;
	char* buf;
	size_t got;

	if (!f)
		return NULL;

	fseek(f, 0, SEEK_END);
	len = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (len < 0)
	{
		fclose(f);
		return NULL;
	}

	buf = (char*)malloc((size_t)len + 1);
	if (!buf)
	{
		fclose(f);
		return NULL;
	}

	got = fread(buf, 1, (size_t)len, f);
	fclose(f);
	buf[got] = 0;
	if (OutLen)
		*OutLen = got;
	return buf;
}

BOOL YaraInit()
{
	YRX_COMPILER* Compiler = NULL;
	char analyzer_path[MAX_PATH], yara_dir[MAX_PATH], file_name[MAX_PATH], compiled_rules[MAX_PATH];
	uint32_t compiler_flags = YRX_RELAXED_RE_SYNTAX | YRX_ENABLE_CONDITION_OPTIMIZATION;
	enum YRX_RESULT rc;

	if (!ScannerLockInit)
	{
		InitializeCriticalSection(&ScannerLock);
		ScannerLockInit = TRUE;
	}

	strncpy(analyzer_path, our_dll_path, strlen(our_dll_path) + 1);
	if (!g_config.standalone)
		PathRemoveFileSpec(analyzer_path);
	PathRemoveFileSpec(analyzer_path);
	sprintf(yara_dir, "%s\\data\\yara", analyzer_path);
	sprintf(compiled_rules, "%s\\capemon.yrx", yara_dir);

	// 1) Try the compiled-rule cache.
	{
		size_t blob_len = 0;
		char* blob = ReadWholeFile(compiled_rules, &blob_len);
		if (blob)
		{
			rc = yrx_rules_deserialize((const uint8_t*)blob, blob_len, &Rules);
			free(blob);
			if (rc == YRX_SUCCESS && Rules)
				DebugOutput("YaraInit: Compiled rules loaded from %s\n", compiled_rules);
			else
			{
				DebugOutput("YaraInit: Ignoring stale/incompatible %s\n", compiled_rules);
				ScannerError(rc, "deserialize");
				Rules = NULL;
			}
		}
	}

	// 2) Otherwise compile from source.
	if (!Rules)
	{
		if (yrx_compiler_create(compiler_flags, &Compiler) != YRX_SUCCESS || !Compiler)
		{
			DebugOutput("YaraInit: yrx_compiler_create failure\n");
			goto fail;
		}

		if (yrx_compiler_add_source(Compiler, InternalYara) != YRX_SUCCESS)
		{
			const char* detail = yrx_last_error();
			DebugOutput("YaraInit: failed to add internal rules%s%s\n", detail ? ": " : "", detail ? detail : "");
		}

		if (g_config.yarascan)
		{
			char FindString[MAX_PATH];
			WIN32_FIND_DATA FindFileData;
			HANDLE hFind;
			unsigned int count = 0;

			sprintf(FindString, "%s\\*.yar", yara_dir);
#ifdef DEBUG_COMMENTS
			DebugOutput("YaraInit: Yara search string: %s", FindString);
#endif
			hFind = FindFirstFile(FindString, &FindFileData);
			if (hFind != INVALID_HANDLE_VALUE)
			{
				do
				{
					size_t src_len = 0;
					char* src;

					if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
						continue;

					snprintf(file_name, sizeof(file_name), "%s\\%s", yara_dir, FindFileData.cFileName);

					src = ReadWholeFile(file_name, &src_len);
					if (!src)
					{
						DebugOutput("YaraInit: Unable to open file %s\n", file_name);
						continue;
					}

					if (!strstr(src, "cape_options"))
					{
						DebugOutput("YaraInit: File %s lacks cape_options metadata - skipping\n", file_name);
						free(src);
						continue;
					}

					rc = yrx_compiler_add_source_with_origin(Compiler, src, file_name);
					free(src);

					if (rc != YRX_SUCCESS)
					{
						const char* detail = yrx_last_error();
						DebugOutput("YaraInit: Unable to compile rule file %s%s%s\n",
							file_name, detail ? ": " : "", detail ? detail : "");
					}
					else
					{
						count++;
#ifdef DEBUG_COMMENTS
						DebugOutput("YaraInit: Compiled rule file %s\n", file_name);
#endif
					}
				}
				while (FindNextFile(hFind, &FindFileData));

				FindClose(hFind);
				DebugOutput("YaraInit: Compiled %d rule files\n", count);
			}
			else
				DebugOutput("YaraInit: Found no Yara rules in %s\n", yara_dir);
		}

		Rules = yrx_compiler_build(Compiler);
		yrx_compiler_destroy(Compiler);
		Compiler = NULL;

		if (!Rules)
		{
			const char* detail = yrx_last_error();
			DebugOutput("YaraInit: yrx_compiler_build failed%s%s\n", detail ? ": " : "", detail ? detail : "");
			goto fail;
		}

		if (g_config.yarascan)
		{
			struct YRX_BUFFER* blob = NULL;
			if (yrx_rules_serialize(Rules, &blob) == YRX_SUCCESS && blob)
			{
				FILE* f = fopen(compiled_rules, "wb");
				if (f)
				{
					fwrite(blob->data, 1, blob->length, f);
					fclose(f);
					DebugOutput("YaraInit: Compiled rules saved to %s\n", compiled_rules);
				}
				yrx_buffer_destroy(blob);
			}
			else
				DebugOutput("YaraInit: yrx_rules_serialize failed - cache not written\n");
		}
	}

	YaraActivated = TRUE;
	YaraLogging = TRUE;

	{
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
			PVOID RtlInsertInvertedFunctionTable = GetAddressByYara(GetModuleHandleA("ntdll"), "RtlInsertInvertedFunctionTable");
			if (RtlInsertInvertedFunctionTable)
			{
				LdrpInvertedFunctionTableSRWLock = (PVOID)((PBYTE)RtlInsertInvertedFunctionTable + *(DWORD*)((PBYTE)RtlInsertInvertedFunctionTable + 3) + 7);
				DebugOutput("RtlInsertInvertedFunctionTable 0x%p, LdrpInvertedFunctionTableSRWLock 0x%p", RtlInsertInvertedFunctionTable, LdrpInvertedFunctionTableSRWLock);
			}
		}
#endif
	}

	return TRUE;

fail:
	if (Compiler)
		yrx_compiler_destroy(Compiler);
	if (Rules)
	{
		yrx_rules_destroy(Rules);
		Rules = NULL;
	}
	return FALSE;
}
