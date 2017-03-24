#ifndef _WIN64
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
#include <Windows.h>
#include "internal.h"
#include "w64wow64.h"
#include "w64wow64defs.h"
#include "windef.h"

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);

FUNCTIONPTRS sFunctions = { 0 };

/**
*
* X64Call Part of WOW64Ext Library
* See internals.h
*/
extern unsigned __int64 X64Call(DWORD64 func, int argC, ...)
{
    va_list args;
    va_start(args, argC);
    union reg64 _rcx = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
    union reg64 _rdx = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
    union reg64 _r8 = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
    union reg64 _r9 = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
    union reg64 _rax = { 0 };

    union reg64 restArgs = { (DWORD64)&va_arg(args, DWORD64) };
    
    // conversion to QWORD for easier use in inline assembly
    union reg64 _argC = { (DWORD64)argC };
    DWORD back_esp = 0;
	WORD back_fs = 0;

    __asm
    {
        ;// reset FS segment, to properly handle RFG
        mov    back_fs, fs
        mov    eax, 0x2B
        mov    fs, ax

        ;// keep original esp in back_esp variable
        mov    back_esp, esp
        
        ;// align esp to 0x10, without aligned stack some syscalls may return errors !
        ;// (actually, for syscalls it is sufficient to align to 8, but SSE opcodes 
        ;// requires 0x10 alignment), it will be further adjusted according to the
        ;// number of arguments above 4
        and    esp, 0xFFFFFFF0

        X64_Start();

        ;// below code is compiled as x86 inline asm, but it is executed as x64 code
        ;// that's why it need sometimes REX_W() macro, right column contains detailed
        ;// transcription how it will be interpreted by CPU

        ;// fill first four arguments
  REX_W mov    ecx, _rcx.dw[0]                          ;// mov     rcx, qword ptr [_rcx]
  REX_W mov    edx, _rdx.dw[0]                          ;// mov     rdx, qword ptr [_rdx]
        push   _r8.v                                    ;// push    qword ptr [_r8]
        X64_Pop(_R8);                                   ;// pop     r8
        push   _r9.v                                    ;// push    qword ptr [_r9]
        X64_Pop(_R9);                                   ;// pop     r9
                                                        ;//
  REX_W mov    eax, _argC.dw[0]                         ;// mov     rax, qword ptr [_argC]
                                                        ;// 
        ;// final stack adjustment, according to the    ;//
        ;// number of arguments above 4                 ;// 
        test   al, 1                                    ;// test    al, 1
        jnz    _no_adjust                               ;// jnz     _no_adjust
        sub    esp, 8                                   ;// sub     rsp, 8
_no_adjust:                                             ;//
                                                        ;// 
        push   edi                                      ;// push    rdi
  REX_W mov    edi, restArgs.dw[0]                      ;// mov     rdi, qword ptr [restArgs]
                                                        ;// 
        ;// put rest of arguments on the stack          ;// 
  REX_W test   eax, eax                                 ;// test    rax, rax
        jz     _ls_e                                    ;// je      _ls_e
  REX_W lea    edi, dword ptr [edi + 8*eax - 8]         ;// lea     rdi, [rdi + rax*8 - 8]
                                                        ;// 
_ls:                                                    ;// 
  REX_W test   eax, eax                                 ;// test    rax, rax
        jz     _ls_e                                    ;// je      _ls_e
        push   dword ptr [edi]                          ;// push    qword ptr [rdi]
  REX_W sub    edi, 8                                   ;// sub     rdi, 8
  REX_W sub    eax, 1                                   ;// sub     rax, 1
        jmp    _ls                                      ;// jmp     _ls
_ls_e:                                                  ;// 
                                                        ;// 
        ;// create stack space for spilling registers   ;// 
  REX_W sub    esp, 0x20                                ;// sub     rsp, 20h
                                                        ;// 
        call   func                                     ;// call    qword ptr [func]
                                                        ;// 
        ;// cleanup stack                               ;// 
  REX_W mov    ecx, _argC.dw[0]                         ;// mov     rcx, qword ptr [_argC]
  REX_W lea    esp, dword ptr [esp + 8*ecx + 0x20]      ;// lea     rsp, [rsp + rcx*8 + 20h]
                                                        ;// 
        pop    edi                                      ;// pop     rdi
                                                        ;// 
        // set return value                             ;// 
  REX_W mov    _rax.dw[0], eax                          ;// mov     qword ptr [_rax], rax

        X64_End();

        mov    ax, ds
        mov    ss, ax
        mov    esp, back_esp

        ;// restore FS segment
        mov    ax, back_fs
        mov    fs, ax
    }
    return _rax.v;
}
#pragma warning(pop)

PTEB64 NtTeb64( void )
{
	X64_Start();
	GETTEB();
	X64_End();
}

PLDR_DATA_TABLE_ENTRY64 GetModule64LdrTable( wchar_t * lwcModuleName )
{
	PTEB64 psTeb = NtTeb64();
	//PPEB64 psPeb = 
	PPEB_LDR_DATA Ldr = psTeb->ProcessEnvironmentBlock->Ldr;
	PLDR_DATA_TABLE_ENTRY64 psDataEntryStart = 
		(PLDR_DATA_TABLE_ENTRY64)Ldr->InLoadOrderModuleList.Flink;
	PLDR_DATA_TABLE_ENTRY64 psDataEntryCurrent = psDataEntryStart;

	do {
		if( memcmp( (DWORD64)psDataEntryCurrent->BaseDllName.Buffer, lwcModuleName, 
			psDataEntryCurrent->BaseDllName.Length ) == 0 ) {
				return psDataEntryCurrent;
		}
		psDataEntryCurrent = 
			(PLDR_DATA_TABLE_ENTRY64)psDataEntryCurrent->InLoadOrderLinks.Flink;
	} while( psDataEntryStart != psDataEntryCurrent && psDataEntryCurrent );
	return NULL;
}

extern void __cdecl SetLastErrorFromX64Call(DWORD64 status)
{
	typedef ULONG (WINAPI *RtlNtStatusToDosError_t)(NTSTATUS Status);
	typedef ULONG (WINAPI *RtlSetLastWin32Error_t)(NTSTATUS Status);

	static RtlNtStatusToDosError_t RtlNtStatusToDosError = NULL;
	static RtlSetLastWin32Error_t RtlSetLastWin32Error = NULL;

	if ((NULL == RtlNtStatusToDosError) || (NULL == RtlSetLastWin32Error))
	{
		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
		RtlNtStatusToDosError = (RtlNtStatusToDosError_t)GetProcAddress(ntdll, "RtlNtStatusToDosError");
		RtlSetLastWin32Error = (RtlSetLastWin32Error_t)GetProcAddress(ntdll, "RtlSetLastWin32Error");
	}
	
	if ((NULL != RtlNtStatusToDosError) && (NULL != RtlSetLastWin32Error))
	{
		RtlSetLastWin32Error(RtlNtStatusToDosError((DWORD)status));
	}
}

extern SIZE_T VirtualQueryEx64(HANDLE hProcess, DWORD64 lpAddress, MEMORY_BASIC_INFORMATION64* lpBuffer, SIZE_T dwLength)
{
	DWORD64 lvpNtdll = GetModuleBase64( L"ntdll.dll" );
	static DWORD ntqvm = 0;
	if (0 == ntqvm)
	{
		ntqvm = (DWORD)GetProcAddress64(lvpNtdll, "NtQueryVirtualMemory");
		if (0 == ntqvm)
			return 0;
	}
	DWORD64 ret = 0;
	X64Call(ntqvm, 6, (DWORD64)hProcess, lpAddress, (DWORD64)0, (DWORD64)lpBuffer, (DWORD64)dwLength, (DWORD64)&ret);
	return (SIZE_T)ret;
}

#pragma warning(push)
#pragma warning(disable : 4244)
extern DWORD64 VirtualAllocEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
	DWORD64 lvpNtdll = GetModuleBase64( L"ntdll.dll" );
    static DWORD64 ntavm = 0;
    if (0 == ntavm)
    {
        ntavm = GetProcAddress64(lvpNtdll, "NtAllocateVirtualMemory");
        if (0 == ntavm)
            return 0;
    }

    DWORD64 tmpAddr = lpAddress;
    DWORD64 tmpSize = dwSize;
    DWORD64 ret = X64Call(ntavm, 6, (DWORD64)hProcess, (DWORD64)&tmpAddr, (DWORD64)0, (DWORD64)&tmpSize, (DWORD64)flAllocationType, (DWORD64)flProtect);
	if (STATUS_SUCCESS != ret)
	{
		SetLastErrorFromX64Call(ret);
		return FALSE;
	}
    else
        return tmpAddr;
}

extern BOOL VirtualFreeEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
	DWORD64 lvpNtdll = GetModuleBase64( L"ntdll.dll" );
    static DWORD64 ntfvm = 0;
    if (0 == ntfvm)
    {
        ntfvm = GetProcAddress64(lvpNtdll, "NtFreeVirtualMemory");
        if (0 == ntfvm)
            return 0;
    }

    DWORD64 tmpAddr = lpAddress;
    DWORD64 tmpSize = dwSize;
    DWORD64 ret = X64Call(ntfvm, 4, (DWORD64)hProcess, (DWORD64)&tmpAddr, (DWORD64)&tmpSize, (DWORD64)dwFreeType);
	if (STATUS_SUCCESS != ret)
	{
		SetLastErrorFromX64Call(ret);
		return FALSE;
	}
    else
        return TRUE;
}

extern BOOL VirtualProtectEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect)
{
	DWORD64 lvpNtdll = GetModuleBase64( L"ntdll.dll" );
    static DWORD64 ntpvm = 0;
    if (0 == ntpvm)
    {
        ntpvm = GetProcAddress64(lvpNtdll, "NtProtectVirtualMemory");
        if (0 == ntpvm)
            return 0;
    }

    DWORD64 tmpAddr = lpAddress;
    DWORD64 tmpSize = dwSize;
    DWORD64 ret = X64Call(ntpvm, 5, (DWORD64)hProcess, (DWORD64)&tmpAddr, (DWORD64)&tmpSize, (DWORD64)flNewProtect, (DWORD64)lpflOldProtect);
	if (STATUS_SUCCESS != ret)
	{
		SetLastErrorFromX64Call(ret);
		return FALSE;
	}
    else
        return TRUE;
}
#pragma warning(pop)

extern BOOL ReadProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead)
{
	DWORD64 lvpNtdll = GetModuleBase64( L"ntdll.dll" );
	static DWORD nrvm = 0;
	if (0 == nrvm)
	{
		nrvm = (DWORD)GetProcAddress64(lvpNtdll, "NtReadVirtualMemory");
		if (0 == nrvm)
			return 0;
	}
	DWORD64 ret = X64Call(nrvm, 5, (DWORD64)hProcess, lpBaseAddress, (DWORD64)lpBuffer, (DWORD64)nSize, (DWORD64)lpNumberOfBytesRead);
	if (STATUS_SUCCESS != ret)
		return FALSE;
	else
		return TRUE;
}

extern BOOL WriteProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
{
	DWORD64 lvpNtdll = GetModuleBase64( L"ntdll.dll" );
	static DWORD nrvm = 0;
	if (0 == nrvm)
	{
		nrvm = (DWORD)GetProcAddress64(lvpNtdll, "NtWriteVirtualMemory");
		if (0 == nrvm)
			return 0;
	}
	DWORD64 ret = X64Call(nrvm, 5, (DWORD64)hProcess, lpBaseAddress, (DWORD64)lpBuffer, (DWORD64)nSize, (DWORD64)lpNumberOfBytesWritten);
	if (STATUS_SUCCESS != ret)
		return FALSE;
	else
		return TRUE;
}

DWORD64 GetModuleBase64( wchar_t * lwcModuleName )
{
	PLDR_DATA_TABLE_ENTRY64 LdrEntry = GetModule64LdrTable( lwcModuleName );
	return (DWORD64)LdrEntry->DllBase;
}

PIMAGE_NT_HEADERS64 GetModule64NtHeader( DWORD64 lvpBaseAddress )
{
	PIMAGE_DOS_HEADER psDosHeader = (PIMAGE_DOS_HEADER)lvpBaseAddress;
	return (PIMAGE_NT_HEADERS64)( ((__int8 *)lvpBaseAddress) + 
		psDosHeader->e_lfanew );
}

DWORD64 GetModule64PEBaseAddress( DWORD64 lvpBaseAddress )
{
	PIMAGE_NT_HEADERS64 psNtHeader = GetModule64NtHeader( lvpBaseAddress );
	return (DWORD64)psNtHeader->OptionalHeader.ImageBase;
}

DWORD64 GetModule64EntryRVA( DWORD64 lvpBaseAddress )
{
	PIMAGE_NT_HEADERS64 psNtHeader = GetModule64NtHeader( lvpBaseAddress );
	return (DWORD64)psNtHeader->OptionalHeader.AddressOfEntryPoint;
}

extern DWORD64 GetProcAddress64( DWORD64 lvpBaseAddress, char * lpszProcName )
{
	PIMAGE_NT_HEADERS64 psNtHeader = GetModule64NtHeader( lvpBaseAddress );
	char * lpcModBase = (char *)lvpBaseAddress;
	PIMAGE_EXPORT_DIRECTORY psExportDir = (PIMAGE_EXPORT_DIRECTORY)( lpcModBase + 
		psNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );

	int nNumberOfNames = psExportDir->NumberOfNames;
	unsigned long * lpulFunctions = 
		(unsigned long *)( lpcModBase + psExportDir->AddressOfFunctions );

	unsigned long * lpulNames = 
		(unsigned long *)( lpcModBase + psExportDir->AddressOfNames );

	unsigned short * lpusOrdinals = 
		(unsigned short *) ( lpcModBase + psExportDir->AddressOfNameOrdinals );

	int i;
	char * lpszFunctionName;
	for( i = 0; i < nNumberOfNames; i++ ) {
		lpszFunctionName = ((__int8 *)lpulNames[i]) + (int)lvpBaseAddress;
		if( strcmp( lpszFunctionName, lpszProcName ) == 0 ) {
			return  ( (__int8 *)lvpBaseAddress ) + 
				lpulFunctions[ lpusOrdinals[i] ];
		}
	}
	return NULL;
}

BOOL FreeKnownDllPage( wchar_t * lpwzKnownDllName )
{
	DWORD64 hSection = 0;
	DWORD64 lvpBaseAddress = 0;
	DWORD64 lvpRealBaseAddress = 0;
	DWORD64 stViewSize = 0;
	DWORD64 stRegionSize = 0;
	PTEB64 psTeb;
	X64Call( sFunctions.LdrGetKnownDllSectionHandle, 3, 
		(DWORD64)lpwzKnownDllName, 
		(DWORD64)0, 
		(DWORD64)&hSection );

	psTeb = NtTeb64();
	psTeb->NtTib.ArbitraryUserPointer = (DWORD64)lpwzKnownDllName;

	X64Call( sFunctions.NtMapViewOfSection, 10, 
		(DWORD64)hSection, 
		(DWORD64)-1, 
		(DWORD64)&lvpBaseAddress, 
		(DWORD64)0, 
		(DWORD64)0, 
		(DWORD64)0, 
		(DWORD64)&stViewSize, 
		(DWORD64)ViewUnmap, 
		(DWORD64)0, 
		(DWORD64)PAGE_READONLY );

	lvpRealBaseAddress = 
		(DWORD64)GetModule64PEBaseAddress( (DWORD64)lvpBaseAddress );

	X64Call( sFunctions.NtFreeVirtualMemory, 4, 
		(DWORD64)-1, 
		(DWORD64)&lvpRealBaseAddress, 
		(DWORD64)&stRegionSize, 
		(DWORD64)MEM_RELEASE );

	X64Call( sFunctions.NtUnmapViewOfSection, 2, (DWORD64)-1, 
		(DWORD64)lvpBaseAddress );
	return TRUE;
}

extern DWORD64 LoadLibrary64A( char * lpcLibraryName )
{
	if( sFunctions.LoadLibraryA == NULL ) {
		sFunctions.LoadLibraryA = 
			GetProcAddress64( GetModuleBase64( L"kernel32.dll" ), "LoadLibraryA" );
	}
	return (DWORD64)X64Call( sFunctions.LoadLibraryA, 1, (DWORD64)lpcLibraryName );
}

extern BOOL InitializeW64oWoW64()
{
	DWORD64 lvpNtdll = GetModuleBase64( L"ntdll.dll" );
	UNICODE_STRING64 sUnicodeString;
	__int8 * lvpKernelBaseBase;
	__int8 * lvpKernel32Base;
	PLDR_DATA_TABLE_ENTRY64 lpsKernel32Ldr;
	PLDR_DATA_TABLE_ENTRY64 lpsKernelBaseLdr;

	sFunctions.LdrGetKnownDllSectionHandle = GetProcAddress64( lvpNtdll, 
		"LdrGetKnownDllSectionHandle" );
	sFunctions.NtFreeVirtualMemory = GetProcAddress64( lvpNtdll, 
		"NtFreeVirtualMemory" );
	sFunctions.NtMapViewOfSection = GetProcAddress64( lvpNtdll, 
		"NtMapViewOfSection" );
	sFunctions.NtUnmapViewOfSection = GetProcAddress64( lvpNtdll, 
		"NtUnmapViewOfSection" );

	if( FreeKnownDllPage( L"kernel32.dll" ) == FALSE) return FALSE;
	if( FreeKnownDllPage( L"user32.dll" ) == FALSE ) return FALSE;

	sUnicodeString.Length = 0x18;
	sUnicodeString.MaximumLength = 0x1a;
	sUnicodeString.Buffer = (DWORD64)L"kernel32.dll";
	if( X64Call( GetProcAddress64( lvpNtdll, "LdrLoadDll" ), 4, 
		(DWORD64)0, 
		(DWORD64)0, 
		(DWORD64)&sUnicodeString, 
		(DWORD64)&lvpKernel32Base ) != NULL ) {
			DoOutputErrorString("Failed to load 64-bit kernel32.dll");
			return FALSE;
	}

	lvpKernelBaseBase = (__int8 *)GetModuleBase64( L"KERNELBASE.dll");
	X64Call( ( lvpKernelBaseBase + (int)GetModule64EntryRVA( lvpKernelBaseBase ) ), 
		3, 
		(DWORD64)lvpKernelBaseBase, 
		(DWORD64)DLL_PROCESS_ATTACH, 
		(DWORD64)0 );

	X64Call( ( lvpKernel32Base + (int)GetModule64EntryRVA( lvpKernel32Base ) ), 
		3, 
		(DWORD64)lvpKernel32Base, 
		(DWORD64)DLL_PROCESS_ATTACH, 
		(DWORD64)0 );

	lpsKernel32Ldr = GetModule64LdrTable( L"kernel32.dll" );
	lpsKernel32Ldr->LoadCount = 0xffff;
	lpsKernel32Ldr->Flags += LDRP_ENTRY_PROCESSED | LDRP_PROCESS_ATTACH_CALLED;

	lpsKernelBaseLdr = GetModule64LdrTable( L"KERNELBASE.dll" );
	lpsKernelBaseLdr->LoadCount = 0xffff;
	lpsKernelBaseLdr->Flags += LDRP_ENTRY_PROCESSED | LDRP_PROCESS_ATTACH_CALLED;

	return TRUE;
}

#endif