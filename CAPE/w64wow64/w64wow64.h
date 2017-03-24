/*
W64oWoW64
Copyright (C) 2012  George Nicolaou <nicolaou.george[at]gmail.[dot]com>

This file is part of W64oWoW64.

W64oWoW64 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

W64oWoW64 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with W64oWoW64.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include <windows.h>

#ifndef STATUS_SUCCESS
#	define STATUS_SUCCESS 0
#endif

#ifndef __W64WOW64_H_
#define __W64WOW64_H_

unsigned __int64 X64Call( DWORD64 lvpFunctionPtr, int nArgc, ... );
void __cdecl SetLastErrorFromX64Call(DWORD64 status);
DWORD64 GetProcAddress64( DWORD64 lvpBaseAddress, char * lpszProcName );
DWORD64 LoadLibrary64A( char * lpcLibraryName );
DWORD64 GetModuleBase64( wchar_t * lwcModuleName );

DWORD64 VirtualAllocEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL VirtualFreeEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect);
BOOL VirtualProtectEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect);	
BOOL ReadProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
BOOL WriteProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);

extern BOOL InitializeW64oWoW64(void);
#endif