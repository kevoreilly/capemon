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

#include "..\pipe.h"

TCHAR DebugOutput[MAX_PATH];
TCHAR PipeOutput[MAX_PATH];
TCHAR ErrorOutput[MAX_PATH];

//**************************************************************************************
void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...)
//**************************************************************************************
{
    va_list args;

    va_start(args, lpOutputString);

    memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
    _vsntprintf_s(DebugOutput, MAX_PATH, MAX_PATH, lpOutputString, args);
    OutputDebugString(DebugOutput);

    memset(PipeOutput, 0, MAX_PATH*sizeof(TCHAR));
    _sntprintf_s(PipeOutput, MAX_PATH, MAX_PATH, "DEBUG:%s", DebugOutput);
#ifndef STANDALONE
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
    _vsntprintf_s(DebugOutput, MAX_PATH, MAX_PATH, lpOutputString, args);
    
    memset(ErrorOutput, 0, MAX_PATH*sizeof(TCHAR));
    _sntprintf_s(ErrorOutput, MAX_PATH, MAX_PATH, "Error %d (0x%x) - %s: %s", ErrorCode, ErrorCode, DebugOutput, (char*)lpMsgBuf);
    OutputDebugString(ErrorOutput);

    memset(PipeOutput, 0, MAX_PATH*sizeof(TCHAR));
    _sntprintf_s(PipeOutput, MAX_PATH, MAX_PATH, "DEBUG:%s", ErrorOutput);
#ifndef STANDALONE
    pipe(PipeOutput, strlen(PipeOutput));
#endif
    
    va_end(args);

	return;
}

//**************************************************************************************
void CapeOutputFile(_In_ LPCTSTR lpOutputFile)
//**************************************************************************************
{
    memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
    _sntprintf_s(DebugOutput, MAX_PATH, MAX_PATH, "CAPE Output file: %s", lpOutputFile);
    OutputDebugString(DebugOutput);

    memset(PipeOutput, 0, MAX_PATH*sizeof(TCHAR));
    _sntprintf_s(PipeOutput, MAX_PATH, MAX_PATH, "FILE_CAPE:%s", lpOutputFile);
#ifndef STANDALONE
    pipe(PipeOutput, strlen(PipeOutput));
#endif
	return;
}