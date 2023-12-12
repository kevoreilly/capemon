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

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern void ErrorOutput(_In_ LPCTSTR lpOutputString, ...);
extern BOOL SetInitialBreakpoints(PVOID ImageBase), DumpRegion(PVOID Address);
extern void parse_config_line(char* line);
extern int ReverseScanForNonZero(PVOID Buffer, SIZE_T Size);
extern SIZE_T GetAccessibleSize(PVOID Buffer);
extern char *our_dll_path;
extern BOOL BreakpointsHit;

YR_RULES* Rules = NULL;
BOOL YaraActivated, YaraLogging, CapemonRulesDetected;
#ifdef _WIN64
extern PVOID LdrpInvertedFunctionTableSRWLock;
#endif

static char NewLine[MAX_PATH];

char InternalYara[] =
	"rule RtlInsertInvertedFunctionTable"
	"{strings:$10_0_19041_662 = {48 8D 0D [4] E8 [4] [7] 8B 44 24 ?? 44 8B CB 4C 8B 44 24 ?? 48 8B D7 89 44 24 ?? E8}"
	"$10_0_18362_1350 = {48 8D 0D [4] 33 D2 85 C0 48 0F 48 DA E8 [4] 33 C9 E8 [4] 8B 44 24 ?? 44 8B CF 4C 8B C3 89 44 24 ?? 48 8B D6 E8}"
	"$10_0_10240_16384 = {48 8D 0D [4] 48 8B E8 E8 [4] 33 C9 E8 [4] 8B 15 [4] 3B 15 [4] 0F 84}"
	"condition:uint16(0) == 0x5a4d and any of them}"
	"rule capemon"
	"{strings:$hash = {d3 b9 46 1d 9a 14 bc 44 a1 61 c3 47 6a 0e 35 90 00 2c 28 81 dc a0 36 dc 2c 92 0c 7c b6 84 39 59}"
	"condition:all of them}";

BOOL ParseOptionLine(char* Line, char* Identifier, PVOID Target)
{
	char *Value, *Key, *p, *q, *r, c = 0;
	unsigned int ValueLength;
	int delta=0;
	if (!Line || !Identifier)
		return FALSE;
	p = strchr(Line, '$');
	if (!p)
		return FALSE;
	p = strchr(Line, '=');
	if (!p)
		return FALSE;
	r = strchr(p, ':');
	if (r)
		Value = r + 1;
	else
		Value = p + 1;
	q = strchr(Value, '+');
	if (q)
		delta = strtoul(q+1, NULL, 0);
	else
	{
		q = strchr(Value, '-');
		if (q)
			delta = - (int)strtoul(q+1, NULL, 0);
	}
	if (q)
		ValueLength = (unsigned int)(DWORD_PTR)(q-(DWORD_PTR)Value);
	else
		ValueLength = (unsigned int)strlen(Value);

	if (strncmp(Value, Identifier, ValueLength))
		return FALSE;

	Key = Line;
	if (r) {
		c = *r;
		*r = 0;
	}
	else {
		c = *p;
		*p = 0;
	}
	memset(NewLine, 0, sizeof(NewLine));
	sprintf(NewLine, "%s%c0x%p\0", Key, c, (PUCHAR)Target+delta);
	if (r)
		*r = c;
	else
		*p = c;
	p = strchr(NewLine, '$');
	if (p)
		return FALSE;
	return TRUE;
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
			BOOL SetBreakpoints = FALSE, DoDumpRegion = FALSE;
			YR_MATCH* Match;
			YR_STRING* String;
			YR_META* Meta;
			YR_RULE* Rule = (YR_RULE*)message_data;

			DebugOutput("YaraScan hit: %s\n", Rule->identifier);

			// Process cape_options metadata
			yr_rule_metas_foreach(Rule, Meta)
			{
				if (Meta->type == META_TYPE_STRING && !strcmp(Meta->identifier, "cape_options"))
				{
					SIZE_T length = strlen(Meta->string);
					char* OptionLine = (char*)Meta->string;
					while (OptionLine && OptionLine < Meta->string + length)
					{
						char *p = strchr(OptionLine, ',');
						if (p)
							*p = 0;
						yr_rule_strings_foreach(Rule, String)
						{
							yr_string_matches_foreach(context, String, Match)
							{
#ifdef DEBUG_COMMENTS
								DebugOutput("YaraScan match: %s, %s (0x%x)", OptionLine, String->identifier, Match->offset);
#endif
								if (ParseOptionLine(OptionLine, (char*)String->identifier, (PVOID)Match->offset))
								{
#ifdef DEBUG_COMMENTS
									DebugOutput("YaraScan: NewLine %s", NewLine);
#endif
									parse_config_line(NewLine);
									SetBreakpoints = TRUE;
								}
							}
						}

						if (!_stricmp("dump", OptionLine))
							DoDumpRegion = TRUE;
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
						}
						if (!strchr(OptionLine, '$'))
							parse_config_line(OptionLine);
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

			if (DoDumpRegion)
			{
				DebugOutput("YaraScan: Dump of region at 0x%p triggered by Yara.", user_data);
				DumpRegion(user_data);
			}

			return CALLBACK_CONTINUE;
	}

	return CALLBACK_ERROR;
}

int InternalYaraCallback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
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

			if (YaraLogging)
				DebugOutput("InternalYaraScan hit: %s\n", Rule->identifier);

			yr_rule_strings_foreach(Rule, String)
			{
				yr_string_matches_foreach(context, String, Match)
				{
#ifdef _WIN64
					if (!strcmp(Rule->identifier, "RtlInsertInvertedFunctionTable"))
					{
						if (!strcmp(String->identifier, "$10_0_19041_662") || !strcmp(String->identifier, "$10_0_18362_1350") || !strcmp(String->identifier, "$10_0_10240_16384"))
						{
							PVOID RtlInsertInvertedFunctionTable = (PVOID)((PBYTE)user_data + Match->offset);
							LdrpInvertedFunctionTableSRWLock = (PVOID)((PBYTE)RtlInsertInvertedFunctionTable + *(DWORD*)((PBYTE)RtlInsertInvertedFunctionTable + 3) + 7);
							DebugOutput("RtlInsertInvertedFunctionTable 0x%p, LdrpInvertedFunctionTableSRWLock 0x%p", RtlInsertInvertedFunctionTable, LdrpInvertedFunctionTableSRWLock);
						}
					}
#endif
					if (!strcmp(Rule->identifier, "capemon"))
						if (!strcmp(String->identifier, "$hash"))
							CapemonRulesDetected = TRUE;
				}
			}
			return CALLBACK_CONTINUE;
	}

	return CALLBACK_ERROR;
}

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

void YaraScan(PVOID Address, SIZE_T Size)
{
	if (!YaraActivated)
		return;

	int Flags = 0, Timeout = 1, Result = ERROR_SUCCESS;

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
		Result = yr_rules_scan_mem(Rules, Address, Size, Flags, YaraCallback, Address, Timeout);
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

void InternalYaraScan(PVOID Address, SIZE_T Size)
{
	if (!YaraActivated)
		return;

	int Flags = 0, Timeout = 1, Result = ERROR_SUCCESS;

	if (!Size)
		return;

	SIZE_T AccessibleSize = GetAccessibleSize(Address);

	if (!AccessibleSize)
		return;

	if (AccessibleSize < Size)
		Size = AccessibleSize;

	Size = (SIZE_T)ReverseScanForNonZero(Address, Size);

	if (!Size)
	{
		if (YaraLogging)
			DebugOutput("InternalYaraScan: Nothing to scan at 0x%p!\n", Address);
		return;
	}

	if (YaraLogging)
		DebugOutput("InternalYaraScan: Scanning 0x%p, size 0x%x\n", Address, Size);

	__try
	{
		Result = yr_rules_scan_mem(Rules, Address, Size, Flags, InternalYaraCallback, Address, Timeout);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		if (YaraLogging)
			DebugOutput("InternalYaraScan: Unable to scan 0x%p\n", Address);
		return;
	}
	if (Result != ERROR_SUCCESS && YaraLogging)
		ScannerError(Result);
#ifdef DEBUG_COMMENTS
	else
		DebugOutput("InternalYaraScan: successfully scanned 0x%p\n", Address);
#endif
}

BOOL ScanForRulesCanary(PVOID Address, SIZE_T Size)
{
	BOOL PreviousYaraLogging = YaraLogging;
	YaraLogging = FALSE;
	CapemonRulesDetected = FALSE;
	InternalYaraScan(Address, Size);
	YaraLogging = PreviousYaraLogging;
	return CapemonRulesDetected;
}

BOOL YaraInit()
{
	YR_COMPILER* Compiler = NULL;
	char analyzer_path[MAX_PATH], yara_dir[MAX_PATH], file_name[MAX_PATH], compiled_rules[MAX_PATH];
	BOOL Result = FALSE, RulesCompiled = FALSE;
	int flags = 0;

	strncpy(analyzer_path, our_dll_path, strlen(our_dll_path)+1);
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

		if (g_config.yarascan)
		{
			char FindString[MAX_PATH];
			WIN32_FIND_DATA FindFileData;
			sprintf(FindString, "%s\\*.yar", yara_dir);
#ifdef DEBUG_COMMENTS
			DebugOutput("YaraInit: Yara search string: %s", FindString);
#endif
			HANDLE hFind = FindFirstFile(FindString, &FindFileData);
			if (hFind != INVALID_HANDLE_VALUE)
			{
				unsigned int count = 0;
				do
				{
					snprintf(file_name, sizeof(file_name), "%s\\%s", yara_dir, FindFileData.cFileName);

					if (!(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
					{
						rule_file = fopen(file_name, "r");

						if (rule_file)
						{
							int errors = yr_compiler_add_file(Compiler, rule_file, NULL, file_name);

							if (errors == ERROR_COULD_NOT_OPEN_FILE)
								DebugOutput("YaraInit: Unable to open file %s\n", file_name);
							else if (errors)
							{
								DebugOutput("YaraInit: Unable to compile rule file %s\n", file_name);
								ScannerError(errors);
							}
							else
							{
								count++;
#ifdef DEBUG_COMMENTS
								DebugOutput("YaraInit: Compiled rule file %s\n", file_name);
#endif
							}

							fclose(rule_file);
						}
					}
				}
				while (FindNextFile(hFind, &FindFileData));

				FindClose(hFind);

				DebugOutput("YaraInit: Compiled %d rule files\n", count);
			}
			else
				DebugOutput("YaraInit: Found no Yara rules in %s\n", yara_dir);
		}

		// Add 'internal' yara
		if (yr_compiler_add_string(Compiler, InternalYara, NULL) != 0)
			DebugOutput("YaraInit: Failed to add internal yara rules.\n", compiled_rules);

		Result = yr_compiler_get_rules(Compiler, &Rules);

		if (Result != ERROR_SUCCESS)
		{
			ScannerError(Result);
			goto exit;
		}

		if (g_config.yarascan)
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

	if ((OSVersion.dwMajorVersion == 6 && OSVersion.dwMinorVersion > 1) || OSVersion.dwMajorVersion > 6)
	{
		PVOID Ntdll = GetModuleHandleA("ntdll");
		InternalYaraScan(Ntdll, GetAllocationSize(Ntdll));
	}

	return TRUE;
exit:
	if (Compiler != NULL)
		yr_compiler_destroy(Compiler);

	if (Rules != NULL)
		yr_rules_destroy(Rules);

	yr_finalize();

	return FALSE;
}

void YaraShutdown()
{
	YaraActivated = FALSE;

	if (Rules != NULL)
		yr_rules_destroy(Rules);

	yr_finalize();

	return;
}