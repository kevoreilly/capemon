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

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern void ErrorOutput(_In_ LPCTSTR lpOutputString, ...);
extern BOOL SetInitialBreakpoints(PVOID ImageBase), DumpRegion(PVOID Address);
extern char Action0[MAX_PATH], Action1[MAX_PATH], Action2[MAX_PATH], Action3[MAX_PATH];
extern void parse_config_line(char* line);
extern int ReverseScanForNonZero(PVOID Buffer, SIZE_T Size);
extern SIZE_T GetAccessibleSize(PVOID Buffer);
extern char *our_dll_path;
extern BOOL BreakpointsHit;

YR_RULES* Rules = NULL;
BOOL YaraActivated, YaraLogging;
#ifdef _WIN64
extern PVOID LdrpInvertedFunctionTableSRWLock;
#endif

static char NewLine[MAX_PATH];

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

	memset(NewLine, 0, sizeof(NewLine));
	if (r)
		sprintf(NewLine, "%s%c0x%p%s\0", Key, c, (PUCHAR)Match->offset+delta, r);
	else
		sprintf(NewLine, "%s%c0x%p\0", Key, c, (PUCHAR)Match->offset+delta);

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
			BOOL SetBreakpoints = FALSE, DoDumpRegion = FALSE;
			YR_MATCH* Match;
			YR_STRING* String;
			YR_META* Meta;
			YR_RULE* Rule = (YR_RULE*)message_data;

			if (!strcmp(Rule->identifier, "capemon"))
				return CALLBACK_CONTINUE;

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
						if (!strchr(OptionLine, '$'))
							parse_config_line(OptionLine);
						else
						{
							yr_rule_strings_foreach(Rule, String)
							{
								yr_string_matches_foreach(context, String, Match)
								{
#ifdef DEBUG_COMMENTS
									DebugOutput("YaraScan match: %s, %s (0x%x)", OptionLine, String->identifier, Match->offset);
#endif
									ParseOptionLine(OptionLine, (char*)String->identifier, Match, user_data);
								}
							}
						}
						if (!_strnicmp(OptionLine, "bp", 2) || !strncmp(OptionLine, "br", 2) || !strncmp(OptionLine, "sysbp", 5))
							SetBreakpoints = TRUE;
						if (!_stricmp("dump", OptionLine))
						{
							DebugOutput("YaraScan: Dump of region at 0x%p triggered by Yara.", user_data);
							DumpRegion(user_data);
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

    int Flags = 0, Timeout = 1, Result = ERROR_SUCCESS;
    __try
    {
        Result = yr_rules_scan_mem(Rules, (PVOID)ModuleBase, Size, Flags, GetAddressesByYaraCallback, AddressInfos, Timeout);
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

		// Add 'internal' yara first
		if (yr_compiler_add_string(Compiler, InternalYara, NULL) != 0)
			DebugOutput("YaraInit: Failed to add internal yara rules.\n", compiled_rules);

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

	return TRUE;
exit:
	if (Compiler != NULL)
		yr_compiler_destroy(Compiler);

	if (Rules != NULL)
		yr_rules_destroy(Rules);

	yr_finalize();

	return FALSE;
}
