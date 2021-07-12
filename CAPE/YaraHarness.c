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
#include "YaraHarness.h"
#include "..\config.h"

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern BOOL SetInitialBreakpoints(PVOID ImageBase);
extern void parse_config_line(char* line);
extern SIZE_T ScanForAccess(LPVOID Buffer, SIZE_T Size);
extern char *our_dll_path;
YR_RULES* Rules = NULL;
BOOL YaraActivated;

static char NewLine[MAX_PATH];

BOOL ParseOptionLine(char* Line, char* Identifier, PVOID Target)
{
	char *Value, *Key, *p, *q;
	unsigned int delta=0, ValueLength;
	if (!Line || !Identifier)
		return FALSE;
	p = strchr(Line, '$');
	if (!p)
		return FALSE;
	p = strchr(Line, '=');
	if (!p)
		return FALSE;
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
	*p = 0;
	memset(NewLine, 0, sizeof(NewLine));
	sprintf(NewLine, "%s=0x%p\0", Key, (PUCHAR)Target+delta);
	*p = '=';
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
			BOOL SetBreakpoints;
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
#ifdef DEBUG_COMMENTS
						DebugOutput("YaraScan hit: parse_config_line %s", OptionLine);
#endif
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

			if (SetBreakpoints)
				SetInitialBreakpoints(user_data);

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

	DebugOutput("YaraScan: Scanning 0x%p, size 0x%x\n", Address, Size);
	__try
	{
		SIZE_T AccessibleSize = ScanForAccess(Address, Size);
		if (!AccessibleSize)
			return;
#ifdef DEBUG_COMMENTS
		DebugOutput("YaraScan: AccessibleSize 0x%x\n", AccessibleSize);
#endif
		Result = yr_rules_scan_mem(Rules, Address, AccessibleSize, Flags, YaraCallback, Address, Timeout);
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

BOOL YaraInit()
{
	YR_COMPILER* Compiler = NULL;
	char analyzer_path[MAX_PATH], yara_dir[MAX_PATH], file_name[MAX_PATH], compiled_rules[MAX_PATH];
	BOOL Result = FALSE, RulesCompiled = FALSE;
	int flags = 0;

	strncpy(analyzer_path, our_dll_path, strlen(our_dll_path));
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
			ScannerError(Result);
	}
	else
	{
		if (yr_compiler_create(&Compiler) != ERROR_SUCCESS)
		{
			DebugOutput("YaraInit: yr_compiler_create failure\n");
			goto exit;
		}

		char FindString[MAX_PATH];
		WIN32_FIND_DATA FindFileData;
		sprintf(FindString, "%s\\*.yar*", yara_dir);
#ifdef DEBUG_COMMENTS
		DebugOutput("YaraInit: Yara search string: %s", FindString);
#endif
		HANDLE hFind = FindFirstFile(FindString, &FindFileData);
		if (hFind != INVALID_HANDLE_VALUE)
		{
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
							ScannerError(errors);
						else
							DebugOutput("YaraInit: Compiled rule file %s\n", file_name);

						fclose(rule_file);
					}
				}
			}
			while (FindNextFile(hFind, &FindFileData));

			FindClose(hFind);
		}

		Result = yr_compiler_get_rules(Compiler, &Rules);

		if (Result != ERROR_SUCCESS)
		{
			ScannerError(Result);
			goto exit;
		}

		Result = yr_rules_save(Rules, compiled_rules);

		if (Result != ERROR_SUCCESS)
			ScannerError(Result);
		else
			DebugOutput("YaraInit: Compiled rules saved to file %s\n", compiled_rules);

		yr_compiler_destroy(Compiler);
	}

	Compiler = NULL;

	YaraActivated = TRUE;

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