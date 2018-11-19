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
#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include "cape.h"
#include "..\pipe.h"
#include "..\config.h"

#define MAX_INT_STRING_LEN 10 // 4294967294

TCHAR DebugOutput[MAX_PATH];
TCHAR PipeOutput[MAX_PATH];
TCHAR ErrorOutput[MAX_PATH];

extern struct CapeMetadata *CapeMetaData;
extern ULONG_PTR base_of_dll_of_interest;

//**************************************************************************************
void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...)
//**************************************************************************************
{
    va_list args;

    va_start(args, lpOutputString);

    memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
    _vsntprintf_s(DebugOutput, MAX_PATH, _TRUNCATE, lpOutputString, args);
#ifdef STANDALONE
    OutputDebugString(DebugOutput);
#else
    memset(PipeOutput, 0, MAX_PATH*sizeof(TCHAR));
    _sntprintf_s(PipeOutput, MAX_PATH, _TRUNCATE, "DEBUG:%s", DebugOutput);
    pipe(PipeOutput, strlen(PipeOutput));
#endif
    va_end(args);

	return;
}

//**************************************************************************************
void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...)
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

    memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
    _vsntprintf_s(DebugOutput, MAX_PATH, _TRUNCATE, lpOutputString, args);

    memset(ErrorOutput, 0, MAX_PATH*sizeof(TCHAR));
    _sntprintf_s(ErrorOutput, MAX_PATH, _TRUNCATE, "Error %d (0x%x) - %s: %s", ErrorCode, ErrorCode, DebugOutput, (char*)lpMsgBuf);
#ifdef STANDALONE
    OutputDebugString(ErrorOutput);
#else
    memset(PipeOutput, 0, MAX_PATH*sizeof(TCHAR));
    _sntprintf_s(PipeOutput, MAX_PATH, _TRUNCATE, "DEBUG:%s", ErrorOutput);
    pipe(PipeOutput, strlen(PipeOutput));
#endif

    va_end(args);

	return;
}

//**************************************************************************************
void CapeOutputFile(_In_ LPCTSTR lpOutputFile)
//**************************************************************************************
{
    char MetadataPath[MAX_PATH];
    HANDLE hMetadata;
    SIZE_T BufferSize;
	char *Buffer;
	DWORD dwBytesWritten;

    if (CapeMetaData && CapeMetaData->DumpType == PROCDUMP)
	{
		memset(MetadataPath, 0, MAX_PATH * sizeof(TCHAR));
		_sntprintf_s(MetadataPath, MAX_PATH, MAX_PATH, "%s_info.txt", lpOutputFile);
		hMetadata = CreateFile(MetadataPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

        if (hMetadata == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_EXISTS)
        {
            DoOutputDebugString("CAPE metadata filename exists already: %s", MetadataPath);
            return;
        }

        if (hMetadata == INVALID_HANDLE_VALUE)
        {
            DoOutputErrorString("Could not create CAPE metadata file");
            return;
        }

		BufferSize = 3 * (MAX_PATH + MAX_INT_STRING_LEN + 2) + 2; //// max size string can be

		Buffer = malloc(BufferSize);

        // if our file of interest is a dll, we need to update cape module path now
        if (base_of_dll_of_interest)
        {
            if (g_config.file_of_interest == NULL)
            {
                DoOutputDebugString("CAPE Error: g_config.file_of_interest is NULL.\n", g_config.file_of_interest);
                return;
            }

            CapeMetaData->ModulePath = (char*)malloc(MAX_PATH);
            WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, (LPCWSTR)g_config.file_of_interest, (int)wcslen(g_config.file_of_interest)+1, CapeMetaData->ModulePath, MAX_PATH, NULL, NULL);
        }
        else
            CapeMetaData->ModulePath = CapeMetaData->ProcessPath;

		// This metadata format is specific to process dumps
		_snprintf_s(Buffer, BufferSize, BufferSize, "%d\n%d\n%s\n%s\n", CapeMetaData->DumpType, CapeMetaData->Pid, CapeMetaData->ProcessPath, CapeMetaData->ModulePath);

		if (FALSE == WriteFile(hMetadata, Buffer, (DWORD)strlen(Buffer), &dwBytesWritten, NULL))
		{
			DoOutputDebugString("WriteFile error on CAPE metadata file %s\n");
			CloseHandle(hMetadata);
			free(Buffer);
			return;
		}

		CloseHandle(hMetadata);

        memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
        _sntprintf_s(DebugOutput, MAX_PATH, MAX_PATH, "Process dump output file: %s", lpOutputFile);
#ifdef STANDALONE
        OutputDebugString(DebugOutput);
#else
        memset(PipeOutput, 0, MAX_PATH*sizeof(TCHAR));
        _sntprintf_s(PipeOutput, MAX_PATH, MAX_PATH, "FILE_DUMP:%s", lpOutputFile);
        pipe(PipeOutput, strlen(PipeOutput));
#endif

	}
	else if (CapeMetaData && CapeMetaData->DumpType != PROCDUMP)
	{
		memset(MetadataPath, 0, MAX_PATH * sizeof(TCHAR));
		_sntprintf_s(MetadataPath, MAX_PATH, MAX_PATH, "%s_info.txt", lpOutputFile);
		hMetadata = CreateFile(MetadataPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

        if (hMetadata == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_EXISTS)
        {
            DoOutputDebugString("CAPE metadata filename exists already: %s", MetadataPath);
            return;
        }

        if (hMetadata == INVALID_HANDLE_VALUE)
        {
            DoOutputErrorString("Could not create CAPE metadata file");
            return;
        }

		BufferSize = 3 * (MAX_PATH + MAX_INT_STRING_LEN + 2) + 2; //// max size string can be

		Buffer = malloc(BufferSize);

        if (!CapeMetaData->ProcessPath)
            CapeMetaData->ProcessPath = "Unknown path";
        CapeMetaData->ModulePath = CapeMetaData->ProcessPath;

		if (CapeMetaData->DumpType == EXTRACTION_PE || CapeMetaData->DumpType == EXTRACTION_SHELLCODE)
        {
            // Extraction-specific format
            _snprintf_s(Buffer, BufferSize, BufferSize, "%d\n%d\n%s\n%s\n0x%p\n", CapeMetaData->DumpType, CapeMetaData->Pid, CapeMetaData->ProcessPath, CapeMetaData->ModulePath, CapeMetaData->Address);
        }
		else if (CapeMetaData->DumpType == INJECTION_PE || CapeMetaData->DumpType == INJECTION_SHELLCODE || CapeMetaData->DumpType == EVILGRAB_PAYLOAD || CapeMetaData->DumpType == EVILGRAB_DATA)
        {
            if (CapeMetaData->TargetProcess && CapeMetaData->ProcessPath)
            // Injection-specific format
                _snprintf_s(Buffer, BufferSize, BufferSize, "%d\n%d\n%s\n%s\n%s\n%d\n", CapeMetaData->DumpType, CapeMetaData->Pid, CapeMetaData->ProcessPath, CapeMetaData->ModulePath, CapeMetaData->TargetProcess, CapeMetaData->TargetPid);
        }
		else if (CapeMetaData->DumpType == SEDRECO_DATA)
        {
            // Sedreco-specific format where TargetPid is used for config item index #
            _snprintf_s(Buffer, BufferSize, BufferSize, "%d\n%d\n%s\n%s\n0x%x\n", CapeMetaData->DumpType, CapeMetaData->Pid, CapeMetaData->ProcessPath, CapeMetaData->ModulePath, (DWORD)CapeMetaData->TargetPid);
        }
		else
            if (CapeMetaData->ProcessPath)
				_snprintf_s(Buffer, BufferSize, BufferSize, "%d\n%d\n%s\n%s\n", CapeMetaData->DumpType, CapeMetaData->Pid, CapeMetaData->ProcessPath, CapeMetaData->ModulePath);

        if (FALSE == WriteFile(hMetadata, Buffer, (DWORD)strlen(Buffer), &dwBytesWritten, NULL))
		{
			DoOutputDebugString("WriteFile error on CAPE metadata file %s\n");
			CloseHandle(hMetadata);
			free(Buffer);
			return;
		}

		CloseHandle(hMetadata);

        memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
        _sntprintf_s(DebugOutput, MAX_PATH, MAX_PATH, "CAPE Output file: %s", lpOutputFile);
#ifdef STANDALONE
        OutputDebugString(DebugOutput);
#else
        memset(PipeOutput, 0, MAX_PATH*sizeof(TCHAR));
        _sntprintf_s(PipeOutput, MAX_PATH, MAX_PATH, "FILE_CAPE:%s", lpOutputFile);
        pipe(PipeOutput, strlen(PipeOutput));
#endif
	}
	else
		DoOutputDebugString("No CAPE metadata (or wrong type) for file: %s\n", lpOutputFile);

	return;
}
