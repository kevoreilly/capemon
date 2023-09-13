/*
CAPE - Config And Payload Extraction
Copyright(C) 2015, 2016 Context Information Security. (kevin.oreilly@contextis.com)

This program is free software : you can redistribute it and / or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.If not, see <http://www.gnu.org/licenses/>.
*/
#include <time.h>
#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <Shlwapi.h>
#include "cape.h"
#include "..\pipe.h"
#include "..\config.h"

//#define DEBUG_COMMENTS
#define MAX_INT_STRING_LEN	10 // 4294967294
#define BUFFER_SIZE			0x200

TCHAR DebugBuffer[MAX_PATH];
TCHAR PipeBuffer[MAX_PATH];
TCHAR ErrorBuffer[MAX_PATH];
CHAR DebuggerLine[MAX_PATH];
CHAR StringsLine[MAX_PATH], *StringsFile;

extern char* GetResultsPath(char* FolderName);
extern struct CapeMetadata *CapeMetaData;
extern ULONG_PTR base_of_dll_of_interest;
HANDLE DebuggerLog, Strings;
extern SIZE_T LastWriteLength;
extern BOOL StopTrace;

//**************************************************************************************
void OutputString(_In_ LPCTSTR lpOutputString, va_list args)
//**************************************************************************************
{
	if (g_config.disable_logging)
		return;

	TCHAR *Character = DebugBuffer;
	memset(DebugBuffer, 0, MAX_PATH*sizeof(CHAR));
	_vsntprintf_s(DebugBuffer, MAX_PATH, _TRUNCATE, lpOutputString, args);
	while (*Character)
	{   // Restrict to ASCII range
		if (*Character < 0x0a || *Character > 0x7E)
			*Character = 0x3F;  // '?'
		Character++;
	}
	if (g_config.standalone)
		OutputDebugString(DebugBuffer);
	else
	{
		memset(PipeBuffer, 0, MAX_PATH*sizeof(CHAR));
		_sntprintf_s(PipeBuffer, MAX_PATH, _TRUNCATE, "DEBUG:%u: %s", GetCurrentProcessId(), DebugBuffer);
		pipe(PipeBuffer, strlen(PipeBuffer));
	}
	return;
}

//**************************************************************************************
void DebugOutput(_In_ LPCTSTR lpOutputString, ...)
//**************************************************************************************
{
	va_list args;
	va_start(args, lpOutputString);
	OutputString(lpOutputString, args);
	va_end(args);
	return;
}

//**************************************************************************************
void ErrorOutput(_In_ LPCTSTR lpOutputString, ...)
//**************************************************************************************
{
	va_list args;
	LPVOID lpMsgBuf;
	DWORD ErrorCode;

	ErrorCode = GetLastError();
	va_start(args, lpOutputString);

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		ErrorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0,
		NULL);

	memset(DebugBuffer, 0, MAX_PATH*sizeof(CHAR));
	_vsntprintf_s(DebugBuffer, MAX_PATH, _TRUNCATE, lpOutputString, args);

	memset(ErrorBuffer, 0, MAX_PATH*sizeof(CHAR));
	_sntprintf_s(ErrorBuffer, MAX_PATH, _TRUNCATE, "Error %u (0x%x) - %s: %s", ErrorCode, ErrorCode, DebugBuffer, (char*)lpMsgBuf);
	if (g_config.standalone)
		OutputDebugString(ErrorBuffer);
	else
	{
		memset(PipeBuffer, 0, MAX_PATH*sizeof(CHAR));
		_sntprintf_s(PipeBuffer, MAX_PATH, _TRUNCATE, "DEBUG:%s", ErrorBuffer);
		pipe(PipeBuffer, strlen(PipeBuffer));
	}

	va_end(args);

	return;
}

//**************************************************************************************
void DoOutputFile(_In_ LPCTSTR lpOutputFile)
//**************************************************************************************
{
	TCHAR OutputBuffer[MAX_PATH];
	memset(OutputBuffer, 0, MAX_PATH*sizeof(TCHAR));
	_sntprintf_s(OutputBuffer, MAX_PATH, _TRUNCATE, "FILE_DUMP:%s", lpOutputFile);
	pipe(OutputBuffer, strlen(OutputBuffer));
	return;
}

//**************************************************************************************
void CapeOutputFile(_In_ LPCTSTR lpOutputFile)
//**************************************************************************************
{
	SIZE_T BufferSize;
	char *MetadataString;

	if (CapeMetaData && CapeMetaData->DumpType == PROCDUMP)
	{
		BufferSize = 4 * (MAX_PATH + MAX_INT_STRING_LEN + 2) + 2; //// max size string can be

		MetadataString = malloc(BufferSize);

		// if our file of interest is a dll, we need to update cape module path now
		if (base_of_dll_of_interest)
		{
			if (g_config.file_of_interest == NULL)
			{
				DebugOutput("CAPE Error: g_config.file_of_interest is NULL.\n", g_config.file_of_interest);
				return;
			}

			CapeMetaData->ModulePath = (char*)malloc(MAX_PATH);
			WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, (LPCWSTR)g_config.file_of_interest, (int)wcslen(g_config.file_of_interest)+1, CapeMetaData->ModulePath, MAX_PATH, NULL, NULL);
		}
		else
			CapeMetaData->ModulePath = CapeMetaData->ProcessPath;

		// This metadata format is specific to process dumps
		_snprintf_s(MetadataString, BufferSize, BufferSize, "%u;?%s;?%s;?", CapeMetaData->DumpType, CapeMetaData->ProcessPath, CapeMetaData->ModulePath);

		memset(DebugBuffer, 0, MAX_PATH*sizeof(TCHAR));
		_sntprintf_s(DebugBuffer, MAX_PATH, _TRUNCATE, "Process dump output file: %s", lpOutputFile);
		if (g_config.standalone)
			OutputDebugString(DebugBuffer);
		else
		{
			char OutputBuffer[BUFFER_SIZE];
			memset(OutputBuffer, 0, BUFFER_SIZE*sizeof(char));
			_snprintf_s(OutputBuffer, BUFFER_SIZE, _TRUNCATE, "FILE_DUMP:%s|%u|%u|%s", lpOutputFile, CapeMetaData->Pid, CapeMetaData->PPid, MetadataString);
			pipe(OutputBuffer, strlen(OutputBuffer));
		}
	}
	else if (CapeMetaData && CapeMetaData->DumpType != PROCDUMP)
	{
		BufferSize = 4 * (MAX_PATH + MAX_INT_STRING_LEN + 2) + 2; //// max size string can be

		MetadataString = malloc(BufferSize);

		if (!CapeMetaData->ProcessPath)
			CapeMetaData->ProcessPath = "Unknown path";
		CapeMetaData->ModulePath = CapeMetaData->ProcessPath;

		if (!CapeMetaData->DumpType && CapeMetaData->TypeString && strlen(CapeMetaData->TypeString))
		{
			CapeMetaData->DumpType = TYPE_STRING;
			_snprintf_s(MetadataString, BufferSize, BufferSize, "%u;?%s;?%s;?%s;?", CapeMetaData->DumpType, CapeMetaData->ProcessPath, CapeMetaData->ModulePath, CapeMetaData->TypeString);
		}
		else if (CapeMetaData->DumpType == UNPACKED_PE || CapeMetaData->DumpType == UNPACKED_SHELLCODE)
		{
			// Unpacker-specific format
			_snprintf_s(MetadataString, BufferSize, BufferSize, "%u;?%s;?%s;?0x%p;?", CapeMetaData->DumpType, CapeMetaData->ProcessPath, CapeMetaData->ModulePath, CapeMetaData->Address);
		}
		else if (CapeMetaData->DumpType == INJECTION_PE || CapeMetaData->DumpType == INJECTION_SHELLCODE)
		{
			if (CapeMetaData->TargetProcess)
			// Injection-specific format
				_snprintf_s(MetadataString, BufferSize, BufferSize, "%u;?%s;?%s;?%s;?%u;?", CapeMetaData->DumpType, CapeMetaData->ProcessPath, CapeMetaData->ModulePath, CapeMetaData->TargetProcess, CapeMetaData->TargetPid);
			else
			{
				DebugOutput("Output: TargetProcess missing for dump from process %d", CapeMetaData->Pid);
				_snprintf_s(MetadataString, BufferSize, BufferSize, "%u;?%s;?%s;?", CapeMetaData->DumpType, CapeMetaData->ProcessPath, CapeMetaData->ModulePath);
			}
		}
		else
			_snprintf_s(MetadataString, BufferSize, BufferSize, "%u;?%s;?%s;?", CapeMetaData->DumpType, CapeMetaData->ProcessPath, CapeMetaData->ModulePath);

		if (g_config.standalone)
		{
			memset(DebugBuffer, 0, MAX_PATH*sizeof(TCHAR));
			_sntprintf_s(DebugBuffer, MAX_PATH, _TRUNCATE, "CAPE Output file: %s", lpOutputFile);
			OutputDebugString(DebugBuffer);
		}
		else
		{
			char OutputBuffer[BUFFER_SIZE];
			memset(OutputBuffer, 0, BUFFER_SIZE*sizeof(char));
			_sntprintf_s(OutputBuffer, BUFFER_SIZE, _TRUNCATE, "FILE_CAPE:%s|%u|%u|%s", lpOutputFile, CapeMetaData->Pid, CapeMetaData->PPid, MetadataString);
			pipe(OutputBuffer, strlen(OutputBuffer));
		}
	}
	else
		DebugOutput("No CAPE metadata (or wrong type) for file: %s\n", lpOutputFile);

	CapeMetaData->DumpType = 0;

	return;
}

//**************************************************************************************
void DebuggerOutput(_In_ LPCTSTR lpOutputString, ...)
//**************************************************************************************
{
	va_list args;
	char *FullPathName, *OutputFilename, *Character;

	if (g_config.no_logs > 1 || StopTrace)
		return;

	va_start(args, lpOutputString);

	if (g_config.no_logs)
	{
		OutputString(lpOutputString, args);
		va_end(args);
		return;
	}

	FullPathName = GetResultsPath("debugger");

	OutputFilename = (char*)malloc(MAX_PATH);

	if (OutputFilename == NULL)
	{
		ErrorOutput("DebuggerOutput: failed to allocate memory for file name string");
		return;
	}

	sprintf_s(OutputFilename, MAX_PATH, "%u.log", GetCurrentProcessId());

	PathAppend(FullPathName, OutputFilename);

	free(OutputFilename);

	if (!DebuggerLog)
	{
		time_t Time;
		CHAR TimeBuffer[64];

		DebuggerLog = CreateFile(FullPathName, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		if (DebuggerLog == INVALID_HANDLE_VALUE)
		{
			ErrorOutput("DebuggerOutput: Unable to open debugger logfile %s", FullPathName);
			return;
		}
		DebugOutput("DebuggerOutput: Debugger logfile %s.\n", FullPathName);

		time(&Time);
		memset(DebuggerLine, 0, MAX_PATH*sizeof(CHAR));
		ctime_s(TimeBuffer, 64, (const time_t *)&Time);
		_snprintf_s(DebuggerLine, MAX_PATH, _TRUNCATE, "CAPE Sandbox - Debugger log: %s" , TimeBuffer);
		WriteFile(DebuggerLog, DebuggerLine, (DWORD)strlen(DebuggerLine), (LPDWORD)&LastWriteLength, NULL);
		while (*lpOutputString == 0x0a)
			lpOutputString++;
	}

	memset(DebuggerLine, 0, MAX_PATH*sizeof(CHAR));
	_vsnprintf_s(DebuggerLine, MAX_PATH, _TRUNCATE, lpOutputString, args);
	Character = DebuggerLine;
	while (*Character)
	{   // Restrict to ASCII range
		if (*Character < 0x0a || *Character > 0x7E)
			*Character = 0x3F;  // '?'
		Character++;
	}
	WriteFile(DebuggerLog, DebuggerLine, (DWORD)strlen(DebuggerLine), (LPDWORD)&LastWriteLength, NULL);

	va_end(args);

	return;
}

//**************************************************************************************
void StringsOutput(_In_ LPCTSTR lpOutputString, ...)
//**************************************************************************************
{
	va_list args;
	char *OutputFilename, *Character;

	va_start(args, lpOutputString);

	StringsFile = GetResultsPath("CAPE");

	OutputFilename = (char*)malloc(MAX_PATH);

	if (OutputFilename == NULL)
	{
		ErrorOutput("StringsOutput: failed to allocate memory for file name string");
		return;
	}

	sprintf_s(OutputFilename, MAX_PATH, "%u.txt", GetCurrentProcessId());

	PathAppend(StringsFile, OutputFilename);

	free(OutputFilename);

	if (!Strings)
	{
		Strings = CreateFile(StringsFile, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		if (Strings == INVALID_HANDLE_VALUE)
		{
			ErrorOutput("StringsOutput: Unable to open strings output file %s", StringsFile);
			return;
		}

		DebugOutput("StringsOutput: Output file %s.\n", StringsFile);
	}

	memset(StringsLine, 0, MAX_PATH*sizeof(CHAR));
	_vsnprintf_s(StringsLine, MAX_PATH, _TRUNCATE, lpOutputString, args);
	Character = StringsLine;
	while (*Character)
	{   // Restrict to ASCII range
		if (*Character < 0x0a || *Character > 0x7E)
			*Character = 0x3F;  // '?'
		Character++;
	}
	WriteFile(Strings, StringsLine, (DWORD)strlen(StringsLine), (LPDWORD)&LastWriteLength, NULL);

	va_end(args);

	return;
}
