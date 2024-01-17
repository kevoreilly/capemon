/*
CAPE - Config And Payload Extraction
Copyright(C) 2015 - 2018 Context Information Security. (kevin.oreilly@contextis.com)

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
//#define DEBUG_COMMENTS

#define _CRT_RAND_S
#define MD5LEN			  16

#define MAX_PRETRAMP_SIZE 320
#define MAX_TRAMP_SIZE 128
#define MAX_UNICODE_PATH 32768

#define BUFSIZE				 1024	// For hashing
#define DUMP_MAX				10
#define CAPE_OUTPUT_FILE "CapeOutput.bin"
//#define SUSPENDED_THREAD_MAX	4096

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <tchar.h>
#include <windows.h>
#include <Wincrypt.h>
#include <WinNT.h>
#include <Shlwapi.h>
#include <stdint.h>
#include <psapi.h>
#include <string.h>
#include <strsafe.h>
#include <tlhelp32.h>

#include "CAPE.h"
#include "Debugger.h"
#include "Unpacker.h"
#include "YaraHarness.h"
#include "..\alloc.h"
#include "..\pipe.h"
#include "..\config.h"
#include "..\lookup.h"

#pragma comment(lib, "Shlwapi.lib")

typedef union _UNWIND_CODE {
	struct {
		BYTE CodeOffset;
		BYTE UnwindOp : 4;
		BYTE OpInfo : 4;
	};
	USHORT FrameOffset;
} UNWIND_CODE;

typedef struct _UNWIND_INFO {
	BYTE Version : 3;
	BYTE Flags : 5;
	BYTE SizeOfProlog;
	BYTE CountOfCodes;
	BYTE FrameRegister : 4;
	BYTE FrameOffset : 4;
	UNWIND_CODE UnwindCode[20];
} UNWIND_INFO;

typedef struct _hook_data_t {
	unsigned char tramp[MAX_TRAMP_SIZE];
	unsigned char pre_tramp[MAX_PRETRAMP_SIZE];
	//unsigned char our_handler[128];
	unsigned char hook_data[32];

	UNWIND_INFO unwind_info;
} hook_data_t;

typedef struct _hook_t {
	const wchar_t *library;
	const char *funcname;
	void *addr;
	void *hook_addr;
	void *new_func;
	void **old_func;
	void *alt_func;
	int allow_hook_recursion;
	int fully_emulate;
	unsigned char numargs;
	int notail;
	int is_hooked;
	hook_data_t *hookdata;
} hook_t;

typedef struct _hook_info_t {
	int disable_count;
	hook_t *last_hook;
	hook_t *current_hook;
	ULONG_PTR return_address;
	ULONG_PTR stack_pointer;
	ULONG_PTR frame_pointer;
	ULONG_PTR main_caller_retaddr;
	ULONG_PTR parent_caller_retaddr;
} hook_info_t;

typedef SIZE_T (WINAPI *_RtlCompareMemory)(
    _In_ const VOID* Source1,
    _In_ const VOID* Source2,
    _In_ SIZE_T Length
);

extern _RtlCompareMemory pRtlCompareMemory;
extern BOOLEAN is_image_base_remapped(HMODULE BaseAddress);
extern uint32_t path_from_handle(HANDLE handle, wchar_t *path, uint32_t path_buffer_len);
extern wchar_t *ensure_absolute_unicode_path(wchar_t *out, const wchar_t *in);
extern int called_by_hook(void);
extern DWORD parent_process_id();
extern int operate_on_backtrace(ULONG_PTR _esp, ULONG_PTR _ebp, void *extra, int(*func)(void *, ULONG_PTR));
extern unsigned int address_is_in_stack(PVOID Address);
extern BOOL is_in_dll_range(ULONG_PTR addr);
extern BOOL inside_hook(LPVOID Address);
extern hook_info_t *hook_info();
extern ULONG_PTR base_of_dll_of_interest;
extern wchar_t *our_process_path_w;
extern wchar_t *our_commandline;
extern HANDLE g_terminate_event_handle;
extern ULONG_PTR g_our_dll_base;
extern DWORD g_our_dll_size;
extern lookup_t g_caller_regions;

extern void NirvanaInit();
extern void AmsiDumperInit(HMODULE module);
extern void DoOutputFile(_In_ LPCTSTR lpOutputFile);
extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern void ErrorOutput(_In_ LPCTSTR lpOutputString, ...);
extern void CapeOutputFile(LPCTSTR lpOutputFile);
extern int IsPeImageRaw(PVOID Buffer);
extern int ScyllaDumpProcess(HANDLE hProcess, DWORD_PTR ModuleBase, DWORD_PTR NewOEP, BOOL FixImports);
extern int ScyllaDumpPE(DWORD_PTR Buffer);
extern SIZE_T GetPESize(PVOID Buffer);
extern PVOID GetReturnAddress(hook_info_t *hookinfo);
extern PVOID CallingModule;
extern void UnpackerInit();
extern BOOL SetInitialBreakpoints(PVOID ImageBase);
extern BOOL BreakpointsSet, TraceRunning;
extern lookup_t g_dotnet_jit;
extern char* StringsFile;
extern HANDLE Strings;

OSVERSIONINFO OSVersion;
BOOL ProcessDumped, ImageBaseRemapped;
PVOID ImageBase;

static __inline ULONG_PTR get_stack_top(void)
{
#ifndef _WIN64
	return __readfsdword(0x04);
#else
	return __readgsqword(0x08);
#endif
}

static __inline ULONG_PTR get_stack_bottom(void)
{
#ifndef _WIN64
	return __readfsdword(0x08);
#else
	return __readgsqword(0x10);
#endif
}

//**************************************************************************************
BOOL InsideMonitor(PVOID* ReturnAddress, PVOID Address)
//**************************************************************************************
{
	if ((ULONG_PTR)Address >= g_our_dll_base && (ULONG_PTR)Address < (g_our_dll_base + g_our_dll_size))
	{
		if (ReturnAddress)
			*ReturnAddress = Address;
		return TRUE;
	}

	return FALSE;
}

//**************************************************************************************
int GetCurrentFrame(PVOID ReturnAddress, ULONG_PTR Address)
//**************************************************************************************
{
	ReturnAddress = (PVOID)Address;
	return 1;
}

//**************************************************************************************
PVOID GetReturnAddress(hook_info_t *hookinfo)
//**************************************************************************************
{
	PVOID ReturnAddress = NULL;

	__try
	{
		operate_on_backtrace(hookinfo->stack_pointer, hookinfo->frame_pointer, &ReturnAddress, GetCurrentFrame);
		return ReturnAddress;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
#ifdef _WIN64
		DebugOutput("GetReturnAddress: Exception trying to get return address with Rip 0x%p.\n", hookinfo->frame_pointer);
#else
		DebugOutput("GetReturnAddress: Exception trying to get return address with base pointer 0x%x.\n", hookinfo->frame_pointer);
#endif
		return NULL;
	}
}

//**************************************************************************************
PVOID GetHookCallerBase()
//**************************************************************************************
{
	PVOID ReturnAddress = NULL, AllocationBase;
	hook_info_t *hookinfo = hook_info();

	if (hookinfo->main_caller_retaddr)
		ReturnAddress = (PVOID)hookinfo->main_caller_retaddr;
	else if (hookinfo->parent_caller_retaddr)
		ReturnAddress = (PVOID)hookinfo->parent_caller_retaddr;
	//else
	//	ReturnAddress = GetReturnAddress(hookinfo);

	if (ReturnAddress)
	{
		DWORD ThreadId = GetCurrentThreadId();

		AllocationBase = GetAllocationBase(ReturnAddress);

		if (AllocationBase)
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("GetHookCallerBase: thread %d, return address 0x%p, allocation base 0x%p.\n", ThreadId, ReturnAddress, AllocationBase);
#endif
			return AllocationBase;
			// Base-dependent breakpoints can be activated now
		}
	}
	else
		DebugOutput("GetHookCallerBase: failed to get return address.\n");

	return NULL;
}

//**************************************************************************************
void PrintHexBytes(__in char* TextBuffer, __in BYTE* HexBuffer, __in unsigned int Count)
//**************************************************************************************
{
	unsigned int i;

	if (HexBuffer == NULL)
		return;

	for (i=0; i<Count; i++)
	{
		sprintf_s((TextBuffer+2*i), Count, "%2.2x", (unsigned int)*(HexBuffer+i));
	}

	return;
}

//*********************************************************************************************************************************
PCHAR TranslatePathFromDeviceToLetter(PCHAR DeviceFilePath)
//*********************************************************************************************************************************
{
	char DriveStrings[BUFSIZE];
	DriveStrings[0] = '\0';

	PCHAR DriveLetterFilePath = (PCHAR)calloc(MAX_PATH, sizeof(BYTE));

	if (!DriveLetterFilePath)
	{
		DebugOutput("TranslatePathFromDeviceToLetter: Unable to allocate buffer for DriveLetterFilePath");
		return NULL;
	}

	if (GetLogicalDriveStrings(BUFSIZE-1, DriveStrings))
	{
		char DeviceName[MAX_PATH];
		char szDrive[3] = " :";
		BOOL FoundDevice = FALSE;
		PCHAR p = DriveStrings;

		do
		{
			*szDrive = *p;

			if (QueryDosDevice(szDrive, DeviceName, MAX_PATH))
			{
				size_t DeviceNameLength = strlen(DeviceName);

				if (DeviceNameLength < MAX_PATH)
				{
					FoundDevice = _strnicmp(DeviceFilePath, DeviceName, DeviceNameLength) == 0;

					if (FoundDevice && *(DeviceFilePath + DeviceNameLength) == ('\\'))
					{
						// Construct DriveLetterFilePath replacing device path with DOS path
						char NewPath[MAX_PATH];
						StringCchPrintf(NewPath, MAX_PATH, TEXT("%s%s"), szDrive, DeviceFilePath+DeviceNameLength);
						StringCchCopyN(DriveLetterFilePath, MAX_PATH, NewPath, strlen(NewPath));
					}
				}
			}

			// Go to the next NULL character.
			while (*p++);
		}
		while (!FoundDevice && *p); // end of string
	}
	else
	{
		ErrorOutput("TranslatePathFromDeviceToLetter: GetLogicalDriveStrings failed");
		return NULL;
	}

	return DriveLetterFilePath;
}

//**************************************************************************************
PVOID GetAllocationBase(PVOID Address)
//**************************************************************************************
{
	MEMORY_BASIC_INFORMATION MemInfo;

	if (!Address)
		return NULL;

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	if (!SystemInfo.dwPageSize)
	{
		ErrorOutput("GetAllocationBase: Failed to obtain system page size.\n");
		return 0;
	}

	if (!VirtualQuery(Address, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		//ErrorOutput("GetAllocationBase: unable to query memory address 0x%p", Address);
		return 0;
	}

#ifdef DEBUG_COMMENTS
//	ErrorOutput("GetAllocationBase: Address 0x%p allocation base: 0x%p", Address, MemInfo.AllocationBase);
#endif
	return MemInfo.AllocationBase;
}

//**************************************************************************************
PVOID GetBaseAddress(PVOID Address)
//**************************************************************************************
{
	MEMORY_BASIC_INFORMATION MemInfo;

	if (!Address)
		return NULL;

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	if (!SystemInfo.dwPageSize)
	{
		ErrorOutput("GetBaseAddress: Failed to obtain system page size.\n");
		return 0;
	}

	if (!VirtualQuery(Address, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		//ErrorOutput("GetBaseAddress: unable to query memory address 0x%p", Address);
		return 0;
	}

#ifdef DEBUG_COMMENTS
//	ErrorOutput("GetBaseAddress: Address 0x%p base address: 0x%p", Address, MemInfo.BaseAddress);
#endif
	return MemInfo.BaseAddress;
}

//**************************************************************************************
SIZE_T GetRegionSize(PVOID Address)
//**************************************************************************************
{
	MEMORY_BASIC_INFORMATION MemInfo;

	if (!Address)
		return 0;

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	if (!SystemInfo.dwPageSize)
	{
		ErrorOutput("GetRegionSize: Failed to obtain system page size.\n");
		return 0;
	}

	if (!VirtualQuery(Address, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		ErrorOutput("GetRegionSize: unable to query memory address 0x%p", Address);
		return 0;
	}

	return MemInfo.RegionSize;

}

//**************************************************************************************
SIZE_T GetAllocationSize(PVOID Address)
//**************************************************************************************
{
	MEMORY_BASIC_INFORMATION MemInfo;
	PVOID OriginalAllocationBase, AddressOfPage;

	if (!Address)
		return 0;

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	if (!SystemInfo.dwPageSize)
	{
		ErrorOutput("GetAllocationSize: Failed to obtain system page size.\n");
		return 0;
	}

	if (!VirtualQuery(Address, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		ErrorOutput("GetAllocationSize: unable to query memory address 0x%p", Address);
		return 0;
	}

	OriginalAllocationBase = MemInfo.AllocationBase;
	AddressOfPage = OriginalAllocationBase;

	while (MemInfo.AllocationBase == OriginalAllocationBase)
	{
		(PUCHAR)AddressOfPage += MemInfo.RegionSize;

		if (!VirtualQuery(AddressOfPage, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
		{
			ErrorOutput("GetAllocationSize: unable to query memory page 0x%p", AddressOfPage);
			return 0;
		}
	}

	return (SIZE_T)((DWORD_PTR)AddressOfPage - (DWORD_PTR)OriginalAllocationBase);
}

//**************************************************************************************
void GetMemoryInfo(PVOID Address)
//**************************************************************************************
{
	MEMORY_BASIC_INFORMATION MemInfo;

	if (!Address)
		return;

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	if (!SystemInfo.dwPageSize)
	{
		ErrorOutput("GetMemoryInfo: Failed to obtain system page size.\n");
		return;
	}

	if (!VirtualQuery(Address, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		ErrorOutput("GetMemoryInfo: unable to query memory address 0x%p", Address);
		return;
	}

#ifdef DEBUG_COMMENTS
	DebugOutput("GetMemoryInfo: Address 0x%p BaseAddress 0x%p AllocationBase 0x%p AllocationProtect 0x%x RegionSize 0x%x State 0x%x Protect 0x%x Type 0x%x", Address, MemInfo.BaseAddress, MemInfo.AllocationBase, MemInfo.AllocationProtect, MemInfo.RegionSize, MemInfo.State, MemInfo.Protect, MemInfo.Type);
#endif

	return;
}

//**************************************************************************************
SIZE_T GetAccessibleSize(PVOID Address)
//**************************************************************************************
{
	MEMORY_BASIC_INFORMATION MemInfo;
	PVOID OriginalAllocationBase, AddressOfPage;

	if (!Address)
		return 0;

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	if (!SystemInfo.dwPageSize)
	{
		ErrorOutput("GetAccessibleSize: Failed to obtain system page size.\n");
		return 0;
	}

	if (!VirtualQuery(Address, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		ErrorOutput("GetAccessibleSize: unable to query memory address 0x%p", Address);
		return 0;
	}

	if (!(MemInfo.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
		return 0;

	if (MemInfo.Protect & (PAGE_GUARD | PAGE_NOACCESS))
		return 0;

	if (!MemInfo.Protect)
		return 0;

	OriginalAllocationBase = MemInfo.AllocationBase;
	AddressOfPage = OriginalAllocationBase;

	while (MemInfo.AllocationBase == OriginalAllocationBase)
	{
		(PUCHAR)AddressOfPage += MemInfo.RegionSize;

		if (!VirtualQuery((PUCHAR)AddressOfPage, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
		{
			ErrorOutput("GetAccessibleSize: unable to query memory page 0x%p", (PUCHAR)AddressOfPage + SystemInfo.dwPageSize);
			return 0;
		}

		if (!(MemInfo.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
			break;

		if (MemInfo.Protect & (PAGE_GUARD | PAGE_NOACCESS))
			break;

		if (!MemInfo.Protect)
			break;
	}

	return (SIZE_T)((DWORD_PTR)AddressOfPage - (DWORD_PTR)OriginalAllocationBase);
}

//**************************************************************************************
PVOID GetCLRAddress(HMODULE ModuleBase, PCHAR FunctionName)
//**************************************************************************************
{
	PIMAGE_DOS_HEADER DosHeader;
	PIMAGE_NT_HEADERS NtHeader;

	if (!ModuleBase || !FunctionName)
		return NULL;

	if (!IsAddressAccessible(ModuleBase))
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("GetCLRAddress: 0x%p inaccessible\n", ModuleBase);
#endif
		return NULL;
	}

	if (*(WORD*)ModuleBase != IMAGE_DOS_SIGNATURE)
		return NULL;

	DosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
	NtHeader = (PIMAGE_NT_HEADERS)((PBYTE)DosHeader + DosHeader->e_lfanew);

	if (!IsAddressAccessible(NtHeader))
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("GetCLRAddress: NT headers at 0x%p inaccessible\n", NtHeader);
#endif
		return NULL;
	}

	if (*(DWORD*)NtHeader != IMAGE_NT_SIGNATURE)
		return NULL;

	PIMAGE_SECTION_HEADER CodeSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)ModuleBase + DosHeader->e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + NtHeader->FileHeader.SizeOfOptionalHeader);
	PVOID CodeSection = (PBYTE)ModuleBase + CodeSectionHeader->VirtualAddress;
	PDWORD Pointer = (PDWORD)CodeSection;

	while ((PBYTE)Pointer < (PBYTE)CodeSection + CodeSectionHeader->Misc.VirtualSize)
	{
		DWORD Marker = *Pointer;
		if ((Marker & 0xFFFFFFFF) == 0xFFFF0000 || (Marker & 0xFFFFFFFF) == 0xFFFF0008)
		{
			PCHAR Name = (PCHAR)(DWORD_PTR)*(Pointer + 2);
			if (Name && !strcmp(FunctionName, Name))
			{
#ifdef DEBUG_COMMENTS
				DebugOutput("GetCLRAddress: Matched %s: 0x%p", FunctionName, *(Pointer + 1));
#endif
				return (PVOID)(DWORD_PTR)*(Pointer + 1);
			}
		}
		Pointer++;
	}

	return NULL;
}

//**************************************************************************************
PVOID GetExportAddress(HMODULE ModuleBase, PCHAR FunctionName)
//**************************************************************************************
{
	PIMAGE_DOS_HEADER DosHeader;
	PIMAGE_NT_HEADERS NtHeader;
	PIMAGE_EXPORT_DIRECTORY ImageExportDirectory;
	PVOID ExportAddress = NULL;

	if (!ModuleBase || !FunctionName)
		return NULL;

	if (!IsAddressAccessible(ModuleBase))
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("GetExportAddress: 0x%p inaccessible\n", ModuleBase);
#endif
		return NULL;
	}

	if (*(WORD*)ModuleBase != IMAGE_DOS_SIGNATURE)
		return NULL;

	DosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
	NtHeader = (PIMAGE_NT_HEADERS)((PBYTE)DosHeader + DosHeader->e_lfanew);

	if (!IsAddressAccessible(NtHeader))
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("GetExportAddress: NT headers at 0x%p inaccessible\n", NtHeader);
#endif
		return NULL;
	}

	if (*(DWORD*)NtHeader != IMAGE_NT_SIGNATURE)
		return NULL;

	if (!NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
		return NULL;

	ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)ModuleBase + (DWORD_PTR)NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	if (!ImageExportDirectory->AddressOfNames)
		return NULL;

	if (ImageExportDirectory->AddressOfNames > NtHeader->OptionalHeader.SizeOfImage)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("GetExportAddress: AddressOfNames 0x%x SizeOfImage 0x%x", ImageExportDirectory->AddressOfNames, NtHeader->OptionalHeader.SizeOfImage);
#endif
		return NULL;
	}

	unsigned int *NameRVA = (unsigned int*)((PBYTE)ModuleBase + ImageExportDirectory->AddressOfNames);

	__try
	{
		for (unsigned int i = 0; i < ImageExportDirectory->NumberOfNames; i++)
		{
			if (NameRVA[i])
			{
				if (!strcmp((PCHAR)((PBYTE)ModuleBase + NameRVA[i]), FunctionName))
					ExportAddress = (PVOID)((PBYTE)ModuleBase + ((DWORD*)((PBYTE)ModuleBase + ImageExportDirectory->AddressOfFunctions))[((unsigned short*)((PBYTE)ModuleBase + ImageExportDirectory->AddressOfNameOrdinals))[i]]);
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DebugOutput("GetExportAddress: Exception occurred around 0x%p\n", NameRVA);
		return NULL;
	}


	if (!ExportAddress && ModuleBase == GetModuleHandle("clr"))
		return GetCLRAddress(ModuleBase, FunctionName);

	if (!ExportAddress && ModuleBase == GetModuleHandle("clrjit"))
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("GetExportAddress: Looking up %s\n", FunctionName);
#endif
		_getJit pgetJit;
		*(FARPROC *)&pgetJit = GetExportAddress(ModuleBase, "getJit");
		if (!pgetJit) {
			DebugOutput("GetExportAddress: failed to resolve getJit\n");
			return NULL;
		}
		PVOID** CILJitBuff = (PVOID**)pgetJit();
		if (CILJitBuff)
			ExportAddress = (unsigned char *)**CILJitBuff;
	}

	return ExportAddress;
}

//**************************************************************************************
BOOL IsAddressAccessible(PVOID Address)
//**************************************************************************************
{
	MEMORY_BASIC_INFORMATION MemInfo;

	if (!Address || Address > (PVOID)0x7fffffffffff)
		return FALSE;

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	if (!SystemInfo.dwPageSize)
	{
		ErrorOutput("IsAddressAccessible: Failed to obtain system page size.\n");
		return FALSE;
	}

	if (!VirtualQuery(Address, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{
#ifdef DEBUG_COMMENTS
		ErrorOutput("IsAddressAccessible: unable to query memory address 0x%p", Address);
#endif
		return FALSE;
	}

	if (!(MemInfo.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
		return FALSE;

	if (MemInfo.Protect & (PAGE_GUARD | PAGE_NOACCESS))
		return FALSE;

	if (!MemInfo.Protect)
		return FALSE;

	return TRUE;
}

//**************************************************************************************
BOOL IsInTrackedRegion(PTRACKEDREGION TrackedRegion, PVOID Address)
//**************************************************************************************
{
	if (Address == NULL)
	{
		DebugOutput("IsInTrackedRegion: NULL passed as address argument - error.\n");
		return FALSE;
	}

	if (TrackedRegion == NULL)
	{
		DebugOutput("IsInTrackedRegion: NULL passed as tracked region argument - error.\n");
		return FALSE;
	}

	if ((DWORD_PTR)Address >= (DWORD_PTR)TrackedRegion->AllocationBase && (DWORD_PTR)Address < ((DWORD_PTR)TrackedRegion->AllocationBase + (DWORD_PTR)GetAccessibleSize(TrackedRegion->AllocationBase)))
		return TRUE;

	return FALSE;
}

//**************************************************************************************
BOOL IsInTrackedRegions(PVOID Address)
//**************************************************************************************
{
	PTRACKEDREGION CurrentTrackedRegion = TrackedRegionList;

	if (Address == NULL)
	{
		DebugOutput("IsInTrackedRegions: NULL passed as argument - error.\n");
		return FALSE;
	}

	if (TrackedRegionList == NULL)
		return FALSE;

	while (CurrentTrackedRegion)
	{
		if ((DWORD_PTR)Address >= (DWORD_PTR)CurrentTrackedRegion->AllocationBase && (DWORD_PTR)Address < ((DWORD_PTR)CurrentTrackedRegion->AllocationBase + (DWORD_PTR)GetAccessibleSize(CurrentTrackedRegion->AllocationBase)))
			return TRUE;

		CurrentTrackedRegion = CurrentTrackedRegion->NextTrackedRegion;
	}

	return FALSE;
}

//**************************************************************************************
PTRACKEDREGION GetTrackedRegion(PVOID Address)
//**************************************************************************************
{
	PTRACKEDREGION CurrentTrackedRegion;

	if (Address == NULL)
		return NULL;

	if (TrackedRegionList == NULL)
		return NULL;

	CurrentTrackedRegion = TrackedRegionList;

	while (CurrentTrackedRegion)
	{
		if (GetAllocationBase(Address) == CurrentTrackedRegion->AllocationBase)
			return CurrentTrackedRegion;

		CurrentTrackedRegion = CurrentTrackedRegion->NextTrackedRegion;
	}

	return NULL;
}

//**************************************************************************************
PTRACKEDREGION CreateTrackedRegion()
//**************************************************************************************
{
	if (TrackedRegionList)
		return TrackedRegionList;

	PTRACKEDREGION FirstTrackedRegion = ((struct TrackedRegion*)calloc(sizeof(struct TrackedRegion), sizeof(BYTE)));

	if (FirstTrackedRegion == NULL)
	{
		DebugOutput("CreateTrackedRegion: failed to allocate memory for initial tracked region list.\n");
		return NULL;
	}

	TrackedRegionList = FirstTrackedRegion;

	//DebugOutput("CreateTrackedRegion: Tracked region list created at 0x%p.\n", TrackedRegionList);

	return TrackedRegionList;
}

//**************************************************************************************
PTRACKEDREGION AddTrackedRegion(PVOID Address, ULONG Protect)
//**************************************************************************************
{
	BOOL PageAlreadyTracked = FALSE;
	unsigned int NumberOfTrackedRegions = 0;
	PTRACKEDREGION TrackedRegion, PreviousTrackedRegion = NULL;

	if (!Address)
		return NULL;

	if (TrackedRegionList == NULL)
		CreateTrackedRegion();

	TrackedRegion = TrackedRegionList;

	while (TrackedRegion)
	{
		NumberOfTrackedRegions++;
		PreviousTrackedRegion = TrackedRegion;
		TrackedRegion = TrackedRegion->NextTrackedRegion;
	}

	if (NumberOfTrackedRegions > 100)
		DebugOutput("AddTrackedRegion: DEBUG Warning - number of tracked regions %d.\n", NumberOfTrackedRegions);

	if (GetPageAddress(Address) == GetPageAddress(TrackedRegionList))
	{
		DebugOutput("AddTrackedRegion: Warning - attempting to track the page (0x%p) containing the tracked region list at 0x%p.\n", Address, TrackedRegionList);
		return NULL;
	}

	TrackedRegion = GetTrackedRegion(Address);

	if (!TrackedRegion && PreviousTrackedRegion)
	{
		// We haven't found it in the linked list, so create a new one
		TrackedRegion = PreviousTrackedRegion;

		TrackedRegion->NextTrackedRegion = ((struct TrackedRegion*)calloc(sizeof(struct TrackedRegion), sizeof(BYTE)));

		if (TrackedRegion->NextTrackedRegion == NULL)
		{
			DebugOutput("AddTrackedRegion: Failed to allocate new tracked region struct.\n");
			return NULL;
		}

		TrackedRegion = TrackedRegion->NextTrackedRegion;
#ifdef DEBUG_COMMENTS
		DebugOutput("AddTrackedRegion: Created new tracked region for address 0x%p.\n", Address);
#endif
	}
	else
	{
		PageAlreadyTracked = TRUE;
#ifdef DEBUG_COMMENTS
		DebugOutput("AddTrackedRegion: Region at 0x%p already in tracked region 0x%p - updating.\n", Address, TrackedRegion->AllocationBase);
#endif
	}

	if (!VirtualQuery(Address, &TrackedRegion->MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		ErrorOutput("AddTrackedRegion: unable to query memory region 0x%p", Address);
		return NULL;
	}

	TrackedRegion->AllocationBase = TrackedRegion->MemInfo.AllocationBase;

	if (Address != TrackedRegion->AllocationBase)
		TrackedRegion->Address = Address;

	if (Protect)
		TrackedRegion->MemInfo.Protect = Protect;

	// If the region is a PE image
	TrackedRegion->EntryPoint = GetEntryPoint(TrackedRegion->AllocationBase);
	if (TrackedRegion->EntryPoint)
	{
		TrackedRegion->Entropy = GetPEEntropy((PUCHAR)TrackedRegion->AllocationBase);
#ifdef DEBUG_COMMENTS
		if (!TrackedRegion->Entropy)
			DebugOutput("AddTrackedRegion: GetPEEntropy failed.");
#endif

		TrackedRegion->MinPESize = GetMinPESize(TrackedRegion->AllocationBase);
		if (TrackedRegion->MinPESize)
			DebugOutput("AddTrackedRegion: Min PE size 0x%x", TrackedRegion->MinPESize);
		//else
		//	DebugOutput("AddTrackedRegion: GetMinPESize failed");
#ifdef DEBUG_COMMENTS
		if (!PageAlreadyTracked)
			DebugOutput("AddTrackedRegion: New region at 0x%p added to tracked regions: EntryPoint 0x%x, Entropy %e\n", TrackedRegion->AllocationBase, TrackedRegion->EntryPoint, TrackedRegion->Entropy);
#endif

	}
#ifdef DEBUG_COMMENTS
	else if (!PageAlreadyTracked)
		DebugOutput("AddTrackedRegion: New region at 0x%p added to tracked regions.\n", TrackedRegion->AllocationBase);
#endif

	if (lookup_get(&g_dotnet_jit, (ULONG_PTR)GetAllocationBase(Address), 0))
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("AddTrackedRegion: Ignoring the region containing 0x%p as it is the .NET JIT cache.\n", Address);
#endif
		TrackedRegion->PagesDumped = TRUE;
	}

	return TrackedRegion;
}

//**************************************************************************************
BOOL DropTrackedRegion(PTRACKEDREGION TrackedRegion)
//**************************************************************************************
{
	PTRACKEDREGION CurrentTrackedRegion, PreviousTrackedRegion;

	if (TrackedRegion == NULL)
	{
		DebugOutput("DropTrackedRegion: NULL passed as argument - error.\n");
		return FALSE;
	}

	PreviousTrackedRegion = NULL;

	if (TrackedRegionList == NULL)
	{
		DebugOutput("DropTrackedRegion: failed to obtain initial tracked region list.\n");
		return FALSE;
	}

	CurrentTrackedRegion = TrackedRegionList;

	while (CurrentTrackedRegion)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("DropTrackedRegion: CurrentTrackedRegion 0x%x, AllocationBase 0x%x.\n", CurrentTrackedRegion, CurrentTrackedRegion->AllocationBase);
#endif

		if (CurrentTrackedRegion == TrackedRegion)
		{
			// Clear any breakpoints in this region
			//if (g_config.unpacker > 1)
			//	ClearBreakpointsInRegion(TrackedRegion->AllocationBase);

			// Unlink this from the list and free the memory
			if (PreviousTrackedRegion && CurrentTrackedRegion->NextTrackedRegion)
			{
				DebugOutput("DropTrackedRegion: removed region at 0x%p from tracked region list.\n", TrackedRegion->AllocationBase);
				PreviousTrackedRegion->NextTrackedRegion = CurrentTrackedRegion->NextTrackedRegion;
			}
			else if (PreviousTrackedRegion && CurrentTrackedRegion->NextTrackedRegion == NULL)
			{
				DebugOutput("DropTrackedRegion: removed region at 0x%p from the end of the tracked region list.\n", TrackedRegion->AllocationBase);
				PreviousTrackedRegion->NextTrackedRegion = NULL;
			}
			else if (!PreviousTrackedRegion)
			{
				DebugOutput("DropTrackedRegion: removed region at 0x%p from the head of the tracked region list.\n", TrackedRegion->AllocationBase);
				TrackedRegionList = NULL;
			}

			free(CurrentTrackedRegion);

			return TRUE;
		}

		PreviousTrackedRegion = CurrentTrackedRegion;
		CurrentTrackedRegion = CurrentTrackedRegion->NextTrackedRegion;
	}

	DebugOutput("DropTrackedRegion: failed to find tracked region in list.\n");

	return FALSE;
}

//**************************************************************************************
void ClearTrackedRegion(PTRACKEDREGION TrackedRegion)
//**************************************************************************************
{
	if (!TrackedRegion->AllocationBase)
		DebugOutput("ClearTrackedRegion: Error, AllocationBase zero.\n");

	if (g_config.unpacker > 1 && TrackedRegion->BreakpointsSet && ClearBreakpointsInRegion(TrackedRegion->AllocationBase))
		TrackedRegion->BreakpointsSet = FALSE;

	CapeMetaData->Address = NULL;

	return;
}

//**************************************************************************************
BOOL ContextClearTrackedRegion(PCONTEXT Context, PTRACKEDREGION TrackedRegion)
//**************************************************************************************
{
	ClearTrackedRegion(TrackedRegion);

	if (!ContextClearAllBreakpoints(Context))
	{
		DebugOutput("ContextClearTrackedRegion: Failed to clear breakpoints.\n");
		return FALSE;
	}

	if (g_config.unpacker > 1)
		ClearAllBreakpoints();

	return TRUE;
}

//**************************************************************************************
void ProcessImageBase(PTRACKEDREGION TrackedRegion)
//**************************************************************************************
{
	DWORD EntryPoint;
	SIZE_T MinPESize;
	double Entropy;

	if (!TrackedRegion)
		return;

	if (TrackedRegion->AllocationBase != GetModuleHandle(NULL) && TrackedRegion->AllocationBase != ImageBase)
		return;

	if (g_config.yarascan)
		YaraScan(TrackedRegion->AllocationBase, GetAccessibleSize(TrackedRegion->AllocationBase));

	EntryPoint = GetEntryPoint(TrackedRegion->AllocationBase);
	MinPESize = GetMinPESize(TrackedRegion->AllocationBase);
	Entropy = GetPEEntropy(TrackedRegion->AllocationBase);

#ifdef DEBUG_COMMENTS
	DebugOutput("ProcessImageBase: EP 0x%p image base 0x%p size 0x%x entropy %e.\n", EntryPoint, TrackedRegion->AllocationBase, MinPESize, Entropy);
#endif
	if (TrackedRegion->EntryPoint && (TrackedRegion->EntryPoint != EntryPoint))
		DebugOutput("ProcessImageBase: Modified entry point (0x%p) detected at image base 0x%p - dumping.\n", EntryPoint, TrackedRegion->AllocationBase);
	else if (TrackedRegion->MinPESize && TrackedRegion->MinPESize != MinPESize)
		DebugOutput("ProcessImageBase: Modified PE size detected at image base 0x%p - new size 0x%x.\n", TrackedRegion->AllocationBase, MinPESize);
	else if (TrackedRegion->Entropy && fabs(TrackedRegion->Entropy - Entropy) > (double)ENTROPY_DELTA)
		DebugOutput("ProcessImageBase: Modified image detected at image base 0x%p - new entropy %e.\n", TrackedRegion->AllocationBase, Entropy);
	else
	{
		DebugOutput("ProcessImageBase: Main module image at 0x%p unmodified.\n", TrackedRegion->AllocationBase);
		return;
	}

	TrackedRegion->EntryPoint = EntryPoint;
	TrackedRegion->MinPESize = MinPESize;
	TrackedRegion->Entropy = Entropy;

	SetCapeMetaData(UNPACKED_PE, 0, NULL, TrackedRegion->AllocationBase);

	DumpImageInCurrentProcess(TrackedRegion->AllocationBase);
}

//**************************************************************************************
void ProcessTrackedRegion(PTRACKEDREGION TrackedRegion)
//**************************************************************************************
{
	if (!TrackedRegion || !TrackedRegion->AllocationBase)
		return;

	if (TrackedRegion->AllocationBase == ImageBase || TrackedRegion->AllocationBase == (PVOID)base_of_dll_of_interest)
	{
		ProcessImageBase(TrackedRegion);
		return;
	}

	if (!TrackedRegion->CanDump && !TrackedRegion->Address && g_terminate_event_handle)
		return;

	PVOID Address = TrackedRegion->AllocationBase;
	SIZE_T Size = (SIZE_T)ReverseScanForNonZero(Address, GetAccessibleSize(Address));

	if (!Size)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("ProcessTrackedRegion: Region at 0x%p is empty\n", Address);
#endif
		return;
	}

	if (TrackedRegion->Address)
	{
		PVOID BaseAddress = GetBaseAddress(TrackedRegion->Address);
		SIZE_T Offset = (SIZE_T)((PUCHAR)BaseAddress - (DWORD_PTR)Address);

		if (Size < Offset)
		{
			DebugOutput("ProcessTrackedRegion: Region at 0x%p skipped due to size 0x%x and offset 0x%x", BaseAddress, Size, Offset);
			return;
		}
	}

	if (TrackedRegion->SubAllocation && Size < SystemInfo.dwPageSize)
	{
		DebugOutput("ProcessTrackedRegion: Sub-allocation at 0x%p skipped due to size 0x%x", Address, Size);
		TrackedRegion->PagesDumped = TRUE;
		return;
	}

#ifdef DEBUG_COMMENTS
	DebugOutput("ProcessTrackedRegion: Address 0x%p Base 0x%p Size %d sub-allocation %d dump count %d\n", TrackedRegion->Address, Address, Size, TrackedRegion->SubAllocation, DumpCount);
#endif

	if (TrackedRegion->PagesDumped)
	{
		// Allow a big enough change in entropy to trigger another dump
		if (TrackedRegion->EntryPoint && TrackedRegion->Entropy)
		{
			double Entropy = GetPEEntropy(Address);
			if (Entropy && (fabs(TrackedRegion->Entropy - Entropy) < (double)ENTROPY_DELTA))
				return;
		}
		else
			return;
	}

	// Suppress exceptions from scans/dumps in debugger log
	BOOL TraceIsRunning = TraceRunning;
	TraceRunning = FALSE;

	if (g_config.yarascan)
		YaraScan(Address, Size);

	char ModulePath[MAX_PATH];
	BOOL MappedModule = GetMappedFileName(GetCurrentProcess(), Address, ModulePath, MAX_PATH);
	if (MappedModule)
	{
		DebugOutput("ProcessTrackedRegion: Region at 0x%p mapped as %s, skipping", Address, ModulePath);
		return;
	}

	if (!CapeMetaData->DumpType)
		CapeMetaData->DumpType = UNPACKED_SHELLCODE;

	if (!CapeMetaData->Address)
		CapeMetaData->Address = Address;

	TrackedRegion->PagesDumped = DumpRegion(Address);

	if (TrackedRegion->PagesDumped)
	{
		if (TraceIsRunning)
			DebuggerOutput("ProcessTrackedRegion: Dumped region at 0x%p.\n", Address);
		else
			DebugOutput("ProcessTrackedRegion: Dumped region at 0x%p.\n", Address);
		ClearTrackedRegion(TrackedRegion);
	}
	else
	{
		if (TraceIsRunning)
			DebuggerOutput("ProcessTrackedRegion: Failed to dump region at 0x%p.\n", Address);
		else
			DebugOutput("ProcessTrackedRegion: Failed to dump region at 0x%p.\n", Address);
	}
}

//**************************************************************************************
BOOL TrackExecution(PVOID CIP)
//**************************************************************************************
{
	PVOID AllocationBase = NULL;
	if (is_in_dll_range((ULONG_PTR)CIP) || inside_hook(CIP))
		return FALSE;

	AllocationBase = GetAllocationBase(CIP);
	if (!AllocationBase)
	{
		DebugOutput("TrackExecution: Failed to add address region for 0x%p to tracked regions list (thread %d).\n", CIP, GetCurrentThreadId());
		return FALSE;
	}

	PTRACKEDREGION TrackedRegion = GetTrackedRegion((PVOID)AllocationBase);
	if (!TrackedRegion || (TrackedRegion && !TrackedRegion->Address && !TrackedRegion->PagesDumped))
	{
		TrackedRegion = AddTrackedRegion((PVOID)AllocationBase, 0);
		if (!TrackedRegion)
		{
			DebugOutput("TrackExecution: Failed to add region at 0x%p to tracked regions list (address 0x%p, thread %d).\n", AllocationBase, CIP, GetCurrentThreadId());
			return FALSE;
		}
		DebugOutput("TrackExecution: Added region at 0x%p to tracked regions list (address 0x%p, thread %d).\n", AllocationBase, CIP, GetCurrentThreadId());
		TrackedRegion->Address = CIP;
		ProcessTrackedRegion(TrackedRegion);
	}
	return TRUE;
}

//**************************************************************************************
BOOL SetCapeMetaData(DWORD DumpType, DWORD TargetPid, HANDLE hTargetProcess, PVOID Address)
//**************************************************************************************
{
	if (DumpType == 0)
	{
		DebugOutput("SetCapeMetaData: DumpType NULL.\n");
		return FALSE;
	}

	CapeMetaData->DumpType = DumpType;

	if (DumpType == INJECTION_PE || DumpType == INJECTION_SHELLCODE)
	{
		if (!TargetPid)
		{
			DebugOutput("SetCapeMetaData: Injection type with no PID - error.\n");
			return FALSE;
		}

		if (!hTargetProcess)
		{
			DebugOutput("SetCapeMetaData: Injection type with no process handle - error.\n");
			return FALSE;
		}

		CapeMetaData->TargetPid = TargetPid;

		if (CapeMetaData->TargetProcess == NULL)
		{
			DebugOutput("SetCapeMetaData: failed to allocate memory for target process string.\n");
			return FALSE;
		}

		if (CapeMetaData->TargetProcess == NULL && !GetModuleFileNameEx(hTargetProcess, NULL, CapeMetaData->TargetProcess, MAX_PATH))
		{
			CapeMetaData->TargetProcess = (char*)calloc(MAX_PATH, sizeof(BYTE));
			ErrorOutput("SetCapeMetaData: GetModuleFileNameEx failed on target process, handle 0x%x", hTargetProcess);
			return FALSE;
		}
	}
	else if (DumpType == UNPACKED_PE || DumpType == UNPACKED_SHELLCODE)
	{
		if (!Address)
		{
			DebugOutput("SetCapeMetaData: CAPE type with missing PID - error.\n");
			return FALSE;
		}

		CapeMetaData->Address = Address;
	}

	return TRUE;
}

//**************************************************************************************
BOOL MapFile(HANDLE hFile, unsigned char **Buffer, DWORD* FileSize)
//**************************************************************************************
{
	LARGE_INTEGER LargeFileSize;
	DWORD dwBytesRead;

	if (!GetFileSizeEx(hFile, &LargeFileSize))
	{
		ErrorOutput("MapFile: Cannot get file size");
		return FALSE;
	}

	if (LargeFileSize.HighPart || LargeFileSize.LowPart > SIZE_OF_LARGEST_IMAGE)
	{
		DebugOutput("MapFile: File too big");
		return FALSE;
	}

	if (LargeFileSize.LowPart == 0)
	{
		DebugOutput("MapFile: File is zero in size.");
		return FALSE;
	}

	*FileSize = LargeFileSize.LowPart;

	DebugOutput("File size: 0x%x", *FileSize);

	*Buffer = calloc(*FileSize, sizeof(BYTE));

	if (SetFilePointer(hFile, 0, 0, FILE_BEGIN))
	{
		ErrorOutput("MapFile: Failed to set file pointer");
		return FALSE;
	}

	if (*Buffer == NULL)
	{
		ErrorOutput("MapFile: Memory allocation error in MapFile");
		return FALSE;
	}

	if (FALSE == ReadFile(hFile, (PVOID)*Buffer, *FileSize, &dwBytesRead, NULL))
	{
		ErrorOutput("ReadFile error");
		free(Buffer);
		return FALSE;
	}

	if (dwBytesRead > 0 && dwBytesRead < *FileSize)
	{
		ErrorOutput("MapFile: Unexpected size read in");
		free(Buffer);
		return FALSE;
	}

	else if (dwBytesRead == 0)
	{
		ErrorOutput("MapFile: No data read from file");
		free(Buffer);
		return FALSE;
	}

	return TRUE;
}

//**************************************************************************************
char* GetResultsPath(char* FolderName)
//**************************************************************************************
{
	char *FullPath;
	DWORD RetVal;

	FullPath = (char*)calloc(MAX_PATH, sizeof(BYTE));

	if (FullPath == NULL)
	{
		ErrorOutput("GetResultsPath: Error allocating memory for full path string");
		return 0;
	}

	strncpy_s(FullPath, MAX_PATH, g_config.results, strlen(g_config.results)+1);

	if (FolderName)
	{
		if (strlen(FullPath) + 1 + strlen(FolderName) >= MAX_PATH)
		{
			DebugOutput("GetResultsPath: Error, destination path too long.\n");
			free(FullPath);
			return 0;
		}

		PathAppend(FullPath, FolderName);

		RetVal = CreateDirectory(FullPath, NULL);

		if (RetVal == 0 && GetLastError() != ERROR_ALREADY_EXISTS)
		{
			ErrorOutput("GetResultsPath: Error creating output directory %s", FullPath);
			free(FullPath);
			return 0;
		}
	}

	return FullPath;
}

//**************************************************************************************
char* GetName()
//**************************************************************************************
{
	char *FullPathName,*OutputFilename;
	SYSTEMTIME Time;
	unsigned int random;

	FullPathName = GetResultsPath("CAPE");

	OutputFilename = (char*)calloc(MAX_PATH, sizeof(char));

	if (OutputFilename == NULL)
	{
		ErrorOutput("GetName: failed to allocate memory for file name string");
		return 0;
	}

	GetSystemTime(&Time);

	random = rand();
	if (!random)
	{
		ErrorOutput("GetName: failed to obtain a random number");
		return 0;
	}

	sprintf_s(OutputFilename, MAX_PATH*sizeof(char), "%u_%d%u%u%u%u%u%u%u", GetCurrentProcessId(), abs(random * Time.wMilliseconds), Time.wSecond, Time.wMinute, Time.wHour, Time.wDay, Time.wDayOfWeek, Time.wMonth, Time.wYear);

	PathAppend(FullPathName, OutputFilename);

	free(OutputFilename);

	return FullPathName;
}

//**************************************************************************************
char* GetTempName()
//**************************************************************************************
{
	char *FullPathName = GetResultsPath("CAPE");
	PathAppend(FullPathName, "CapeOutput.bin");
	return FullPathName;
}

//**************************************************************************************
BOOL GetHash(unsigned char* Buffer, unsigned int Size, char* OutputFilenameBuffer)
//**************************************************************************************
{
	DWORD i;
	DWORD dwStatus = 0;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	DWORD cbHash = 0;
	BYTE MD5Hash[MD5LEN];

	// Get handle to the crypto provider
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		ErrorOutput("CryptAcquireContext failed");
		return 0;
	}

	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		ErrorOutput("CryptCreateHash failed");
		CryptReleaseContext(hProv, 0);
		return 0;
	}

	if (!CryptHashData(hHash, Buffer, Size, 0))
	{
		ErrorOutput("CryptHashData failed");
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		return 0;
	}

	cbHash = MD5LEN;
	if (!CryptGetHashParam(hHash, HP_HASHVAL, MD5Hash, &cbHash, 0))
	{
		ErrorOutput("CryptGetHashParam failed");
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);

	for (i = 0; i < cbHash; i++)
	{
		PrintHexBytes(OutputFilenameBuffer, MD5Hash, MD5LEN);
	}

	return 1;
}

//**************************************************************************************
double GetPEEntropy(PUCHAR Buffer)
//**************************************************************************************
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	unsigned long TotalCounts[256];
	double p, lp, Entropy = 0;
	double log_2 = log((double)2);
	SIZE_T Length = 0;
	unsigned int i;

	if (!Buffer)
	{
		DebugOutput("GetPEEntropy: Error - no address supplied.\n");
		return 0;
	}

	if (!IsAddressAccessible(Buffer))
	{
		DebugOutput("GetPEEntropy: Error - Supplied address inaccessible: 0x%p\n", Buffer);
		return 0;
	}

	if (IsDisguisedPEHeader((PVOID)Buffer) <= 0)
		return 0;

	pDosHeader = (PIMAGE_DOS_HEADER)Buffer;

	__try
	{
		if (pDosHeader->e_lfanew && (ULONG)pDosHeader->e_lfanew < PE_HEADER_LIMIT && ((ULONG)pDosHeader->e_lfanew & 3) == 0)
			pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + (ULONG)pDosHeader->e_lfanew);

		if (pNtHeader && TestPERequirements(pNtHeader))
			Length = pNtHeader->OptionalHeader.SizeOfImage;

		if (!Length)
			return 0;

		SIZE_T AccessibleSize = GetAccessibleSize(Buffer);
		if (AccessibleSize < Length)
			Length = AccessibleSize;

		memset(TotalCounts, 0, sizeof(TotalCounts));

		for (i = 0; i < Length; i++)
		{
			TotalCounts[Buffer[i]]++;
		}

		for (i = 0; i < 256; i++)
		{
			if (TotalCounts[i] == 0) continue;

			p = 1.0 * TotalCounts[i] / Length;

			lp = log(p)/log_2;

			Entropy -= p * lp;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DebugOutput("GetPEEntropy: Exception occurred attempting to get PE entropy at 0x%p\n", (PUCHAR)Buffer+i);
		return 0;
	}

	return Entropy;
}

//**************************************************************************************
int DumpXorPE(LPBYTE Buffer, unsigned int Size)
//**************************************************************************************
{
	LONG e_lfanew;
	DWORD NT_Signature;
	unsigned int i, j, k;
	BYTE* DecryptedBuffer = NULL;

	for (i=0; i<=0xFF; i++)
	{
		// check for the DOS signature a.k.a MZ header
		if ((*Buffer^(BYTE)i) == 'M' && (*(Buffer+1)^(BYTE)i) == 'Z')
		{
			DebugOutput("MZ header found with bytewise XOR key 0x%.2x\n", i);

			e_lfanew = (LONG)*(DWORD*)(Buffer+0x3c);

			DebugOutput("Encrypted e_lfanew: 0x%x", e_lfanew);

			for (j=0; j<sizeof(LONG); j++)
				*((BYTE*)&e_lfanew+j) = *((BYTE*)&e_lfanew+j)^i;

			DebugOutput("Decrypted e_lfanew: 0x%x", e_lfanew);

			if ((unsigned int)e_lfanew > PE_HEADER_LIMIT)
			{
				DebugOutput("The pointer to the PE header seems a tad large: 0x%x", e_lfanew);
				//return FALSE;
			}

			// let's get the NT signature a.k.a PE header
			memcpy(&NT_Signature, Buffer+e_lfanew, 4);

			DebugOutput("Encrypted NT_Signature: 0x%x", NT_Signature);

			// let's try decrypting it with the key
			for (k=0; k<4; k++)
				*((BYTE*)&NT_Signature+k) = *((BYTE*)&NT_Signature+k)^i;

			DebugOutput("Encrypted NT_Signature: 0x%x", NT_Signature);

			// does it check out?
			if (NT_Signature == IMAGE_NT_SIGNATURE)
			{
				DebugOutput("Xor-encrypted PE detected, about to dump.\n");

				DecryptedBuffer = (BYTE*)calloc(Size, sizeof(BYTE));

				if (DecryptedBuffer == NULL)
				{
					ErrorOutput("Error allocating memory for decrypted PE binary");
					return FALSE;
				}

				memcpy(DecryptedBuffer, Buffer, Size);

				for (k=0; k<Size; k++)
					*(DecryptedBuffer+k) = *(DecryptedBuffer+k)^i;

				CapeMetaData->Address = DecryptedBuffer;
				DumpImageInCurrentProcess(DecryptedBuffer);

				free(DecryptedBuffer);
				return i;
			}
			else
			{
				DebugOutput("PE signature invalid, looks like a false positive.\n");
				return FALSE;
			}
		}
	}

	// We free can free DecryptedBuffer as it's no longer needed
	if(DecryptedBuffer)
		free(DecryptedBuffer);

	return FALSE;
}

void DumpStrings()
{
	if (Strings && StringsFile) {
		CloseHandle(Strings);
		Strings = NULL;
		CapeMetaData->DumpType = 0;
		if (g_config.typestring)
			CapeMetaData->TypeString = g_config.typestring;
		DebugOutput("DumpStrings: Uploading captured strings at %s\n", StringsFile);
		CapeOutputFile(StringsFile);
	}
}

//**************************************************************************************
int ScanPageForNonZero(PVOID Address)
//**************************************************************************************
{
	unsigned int p;
	DWORD_PTR AddressOfPage;

	if (!Address)
	{
		DebugOutput("ScanPageForNonZero: Error - Supplied address zero.\n");
		return 0;
	}

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	if (!SystemInfo.dwPageSize)
	{
		ErrorOutput("ScanPageForNonZero: Failed to obtain system page size.\n");
		return 0;
	}

	AddressOfPage = ((DWORD_PTR)Address/SystemInfo.dwPageSize)*SystemInfo.dwPageSize;

	__try
	{
		for (p=0; p<SystemInfo.dwPageSize-1; p++)
			if (*((char*)AddressOfPage+p) != 0)
				return 1;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DebugOutput("ScanPageForNonZero: Exception occurred reading memory address 0x%p\n", (char*)AddressOfPage+p);
		return 0;
	}

	return 0;
}

//**************************************************************************************
SIZE_T ScanForAccess(PVOID Buffer, SIZE_T Size)
//**************************************************************************************
{
	SIZE_T p, AllocationSize;
	char c = 0;

	if (!Buffer)
	{
		DebugOutput("ScanForAccess: Error - Supplied address zero.\n");
		return 0;
	}

	AllocationSize = GetAllocationSize(Buffer);
	if (AllocationSize < Size)
		Size = AllocationSize;

	__try
	{
		for (p=0; p<Size; p++)
			c = *((char*)Buffer+p);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		if (p)
		{
			DebugOutput("ScanForAccess: Exception occurred reading memory address 0x%p, accessible size 0x%x\n", (char*)Buffer+p, p);
			return p;
		}
		else
		{
			DebugOutput("ScanForAccess: Exception occurred reading memory address 0x%p, memory inaccessible\n", (char*)Buffer+p);
			return 0;
		}
	}

#ifdef DEBUG_COMMENTS
	DebugOutput("ScanForAccess: Read memory address 0x%p, byte 0x%x\n", (char*)Buffer+p, c);
#endif

	return p;
}

//**************************************************************************************
int ScanForNonZero(PVOID Buffer, SIZE_T Size)
//**************************************************************************************
{
	SIZE_T p;

	if (!Buffer)
	{
		DebugOutput("ScanForNonZero: Error - Supplied address zero.\n");
		return 0;
	}

	if (!IsAddressAccessible(Buffer))
		return 0;

	__try
	{
		for (p=0; p <= Size-1; p++)
			if (*((char*)Buffer+p) != 0)
			{
#ifdef DEBUG_COMMENTS
				DebugOutput("ScanForNonZero: Non-zero found at 0x%p (0x%x)\n", (char*)Buffer+p, *((char*)Buffer+p));
#endif
				if (p)
					return (int)p;
				else
					return 1;
			}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DebugOutput("ScanForNonZero: Exception occurred reading memory address 0x%p (buffer at 0x%p, size 0x%x)\n", (char*)Buffer+p, Buffer, Size);
		return 0;
	}

#ifdef DEBUG_COMMENTS
	DebugOutput("ScanForNonZero: No data found at 0x%p (size %d bytes)\n", Buffer, Size);
#endif
	return 0;
}

//**************************************************************************************
int ReverseScanForNonZero(PVOID Buffer, SIZE_T Size)
//**************************************************************************************
{
	SIZE_T p;

	if (!Buffer)
	{
		DebugOutput("ReverseScanForNonZero: Error - Supplied address zero.\n");
		return 0;
	}

	if (!IsAddressAccessible((PUCHAR)Buffer+Size-1))
	{
		DebugOutput("ReverseScanForNonZero: Error - Supplied address inaccessible: 0x%p\n", (PUCHAR)Buffer+Size-1);
		return 0;
	}

	__try
	{
		for (p = Size - 1; p > 0; p--)
			if (*((char*)Buffer+p) != 0)
				return (int)p + 1;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DebugOutput("ReverseScanForNonZero: Exception occurred reading memory address 0x%p (buffer at 0x%p, size 0x%x)\n", (char*)Buffer+p, Buffer, Size);
		GetMemoryInfo((char*)Buffer+p);
		return 0;
	}

	return 0;
}

//**************************************************************************************
PVOID GetPageAddress(PVOID Address)
//**************************************************************************************
{
	if (!Address)
	{
		DebugOutput("GetPageAddress: Error - Supplied address zero.\n");
		return NULL;
	}

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	if (!SystemInfo.dwPageSize)
	{
		ErrorOutput("GetPageAddress: Failed to obtain system page size.\n");
		return NULL;
	}

	return (PVOID)(((DWORD_PTR)Address/SystemInfo.dwPageSize)*SystemInfo.dwPageSize);

}

//**************************************************************************************
int ScanForPE(PVOID Buffer, SIZE_T Size, PVOID* Offset)
//**************************************************************************************
{
	SIZE_T p;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;

	if (!Buffer || !Size)
	{
		DebugOutput("ScanForPE: Error, Buffer or Size zero: 0x%x, 0x%x\n", Buffer, Size);
		return 0;
	}

	for (p=0; p<Size-1; p++)
	{
		__try
		{
			if (*((char*)Buffer+p) == 'M' && *((char*)Buffer+p+1) == 'Z')
			{
				pDosHeader = (PIMAGE_DOS_HEADER)((char*)Buffer+p);

				if ((ULONG)pDosHeader->e_lfanew == 0)
					// e_lfanew is zero
					continue;

				if ((ULONG)pDosHeader->e_lfanew > Size-p)
					// e_lfanew points beyond end of region
					continue;

				pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + (ULONG)pDosHeader->e_lfanew);

				if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
					// No 'PE' header
					continue;

				if ((pNtHeader->FileHeader.Machine == 0) || (pNtHeader->FileHeader.SizeOfOptionalHeader == 0 || pNtHeader->OptionalHeader.SizeOfHeaders == 0))
				{
					// Basic requirements
					DebugOutput("ScanForPE: Basic requirements failure.\n");
					continue;
				}

				if (Offset)
					*Offset = (PVOID)((char*)Buffer+p);

				//DebugOutput("ScanForPE: PE image located at: 0x%x\n", (DWORD_PTR)((char*)Buffer+p));

				return 1;
			}
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			DebugOutput("ScanForPE: Exception occurred reading memory address 0x%p\n", (DWORD_PTR)((char*)Buffer+p));
			return 0;
		}
	}

	DebugOutput("ScanForPE: No PE image located at 0x%x.\n", Buffer);
	return 0;
}

//**************************************************************************************
PCHAR ScanForExport(PVOID Address, SIZE_T ScanMax)
//**************************************************************************************
{
	if (!Address)
		return NULL;

	PVOID Base = GetAllocationBase(Address);
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)Base + (ULONG)((PIMAGE_DOS_HEADER)Base)->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)Base + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD AddressOfNames = (PDWORD)((PUCHAR)Base + ExportDirectory->AddressOfNames);
	PDWORD AddressOfFunctions = (PDWORD)((PUCHAR)Base + ExportDirectory->AddressOfFunctions);
	PWORD AddressOfNameOrdinals = (PWORD)((PUCHAR)Base + ExportDirectory->AddressOfNameOrdinals);

	for (unsigned int j = 0; j < ExportDirectory->NumberOfFunctions; j++)
	{
		if ((PUCHAR)Address - (PUCHAR)Base > (int)AddressOfFunctions[AddressOfNameOrdinals[j]]
		&& (PUCHAR)Address - (PUCHAR)Base - AddressOfFunctions[AddressOfNameOrdinals[j]] <= (int)ScanMax)
			return (PCHAR)Base + AddressOfNames[j];
	}

    return NULL;
}

//**************************************************************************************
PCHAR GetExportNameByAddress(PVOID Address)
//**************************************************************************************
{
	return ScanForExport(Address, 0);
}

//**************************************************************************************
BOOL TestPERequirements(PIMAGE_NT_HEADERS pNtHeader)
//**************************************************************************************
{
	__try
	{
		PIMAGE_SECTION_HEADER NtSection;

		if ((pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) && (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC))
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("TestPERequirements: Bad magic 0x%x", pNtHeader->OptionalHeader.Magic);
#endif
			return FALSE;
		}

		// Basic requirements
		if (!pNtHeader->FileHeader.NumberOfSections || pNtHeader->FileHeader.NumberOfSections > PE_MAX_SECTIONS)
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("TestPERequirements: Bad number of sections %d", pNtHeader->FileHeader.NumberOfSections);
#endif
			return FALSE;
		}

		if (!pNtHeader->OptionalHeader.SizeOfImage || pNtHeader->OptionalHeader.SizeOfImage > PE_MAX_SIZE)
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("TestPERequirements: Bad SizeOfImage 0x%x", pNtHeader->OptionalHeader.SizeOfImage);
#endif
			return FALSE;
		}

		NtSection = IMAGE_FIRST_SECTION(pNtHeader);

		if (!NtSection)
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("TestPERequirements: Bad first section entry");
#endif
			return FALSE;
		}

		for (unsigned int i=0; i<pNtHeader->FileHeader.NumberOfSections; i++)
		{
			if ((NtSection->PointerToRawData > PE_MAX_SIZE) || (NtSection->SizeOfRawData) > PE_MAX_SIZE)
				return FALSE;

			if ((NtSection->VirtualAddress > PE_MAX_SIZE) || (NtSection->Misc.VirtualSize) > PE_MAX_SIZE)
				return FALSE;

			++NtSection;
		}

		// To pass the above tests it should now be safe to dump as a PE image
		return TRUE;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DebugOutput("TestPERequirements: Exception occurred reading region at 0x%x\n", (DWORD_PTR)(pNtHeader));
		return FALSE;
	}
}

//**************************************************************************************
SIZE_T GetMinPESize(PIMAGE_NT_HEADERS pNtHeader)
//**************************************************************************************
{
	SIZE_T MinSize;

	__try
	{
		PIMAGE_SECTION_HEADER NtSection;

		if ((pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) && (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC))
			return 0;

		// Basic requirements
		if (!pNtHeader->FileHeader.NumberOfSections || pNtHeader->FileHeader.NumberOfSections > PE_MAX_SECTIONS)
			return 0;

		if (!pNtHeader->OptionalHeader.SizeOfImage || pNtHeader->OptionalHeader.SizeOfImage > PE_MAX_SIZE)
			return 0;

		NtSection = IMAGE_FIRST_SECTION(pNtHeader);

		for (unsigned int i=1; i<pNtHeader->FileHeader.NumberOfSections; i++)
			++NtSection;

		if (!NtSection->PointerToRawData && !NtSection->VirtualAddress)
			return 0;

		if (NtSection->PointerToRawData)
			MinSize = NtSection->PointerToRawData + NtSection->SizeOfRawData;
		else if (NtSection->VirtualAddress)
			MinSize = NtSection->VirtualAddress + NtSection->SizeOfRawData;

		if (!MinSize || MinSize > (ULONG)pNtHeader->OptionalHeader.SizeOfImage)
		{
			DebugOutput("GetMinPESize: Possible PE image rejected due to min size %d bytes (SizeOfImage 0x%x).\n", MinSize, pNtHeader->OptionalHeader.SizeOfImage);
			return 0;
		}

		return MinSize;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DebugOutput("GetMinPESize: Exception occurred reading region at 0x%x\n", (DWORD_PTR)(pNtHeader));
		return 0;
	}
}

//**************************************************************************************
int IsDotNetImage(PVOID Buffer)
//**************************************************************************************
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader = NULL;

	if (!IsAddressAccessible(Buffer) || IsDisguisedPEHeader(Buffer) <= 0)
		return 0;

	pDosHeader = (PIMAGE_DOS_HEADER)Buffer;

	__try
	{
		if (pDosHeader->e_lfanew && (ULONG)pDosHeader->e_lfanew < PE_HEADER_LIMIT && ((ULONG)pDosHeader->e_lfanew & 3) == 0)
			pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + (ULONG)pDosHeader->e_lfanew);

		if (!pNtHeader || !TestPERequirements(pNtHeader))
			return 0;

#ifndef _WIN64
		if (pNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			return 0;
#endif

		if (pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress || pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size)
			return 1;

	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return 0;
	}

	return 0;
}

//**************************************************************************************
int IsDisguisedPEHeader(PVOID Buffer)
//**************************************************************************************
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader = NULL;

	pDosHeader = (PIMAGE_DOS_HEADER)Buffer;

	__try
	{
		if (!pDosHeader->e_lfanew || (ULONG)pDosHeader->e_lfanew > PE_HEADER_LIMIT)
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("IsDisguisedPEHeader: Bad e_lfanew value 0x%x", pDosHeader->e_lfanew);
#endif
			return 0;
		}

		if (((ULONG)pDosHeader->e_lfanew & 3) != 0)
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("IsDisguisedPEHeader: Bad e_lfanew alignment 0x%x", pDosHeader->e_lfanew);
#endif
			return 0;
		}

		pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + (ULONG)pDosHeader->e_lfanew);

		if (pNtHeader && TestPERequirements(pNtHeader))
			return 1;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("IsDisguisedPEHeader: Exception checking PE header!");
#endif
		return -1;
	}

	return 0;
}

//**************************************************************************************
int ScanForDisguisedPE(PVOID Buffer, SIZE_T Size, PVOID* Offset)
//**************************************************************************************
{
	SIZE_T p, AccessibleSize;
	BOOL PEDetected;
	int RetVal;

	if (Size == 0)
	{
		DebugOutput("ScanForDisguisedPE: Error, zero size given\n");
		return 0;
	}

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	if (!SystemInfo.dwPageSize)
	{
		ErrorOutput("ScanForDisguisedPE: Failed to obtain system page size.\n");
		return 0;
	}

	if (Size <= SystemInfo.dwPageSize)
	{
		DebugOutput("ScanForDisguisedPE: Size too small.\n");
		return 0;
	}

	PEDetected = FALSE;

	AccessibleSize = ScanForAccess(Buffer, Size);
	if (Size > AccessibleSize)
		Size = AccessibleSize;

	// we want to stop short of the max look-ahead in IsDisguisedPEHeader
	for (p=0; p <= Size - SystemInfo.dwPageSize ; p++)
	{
		RetVal = IsDisguisedPEHeader((PVOID)((BYTE*)Buffer+p));

		if (!RetVal)
			continue;
		else if (RetVal == -1)
		{
			DebugOutput("ScanForDisguisedPE: Exception occurred scanning buffer at 0x%x\n", (BYTE*)Buffer+p);
			GetMemoryInfo((BYTE*)Buffer+p);
			return 0;
		}

		if (Offset)
			*Offset = (PVOID)((BYTE*)Buffer+p);

		DebugOutput("ScanForDisguisedPE: PE image located at: 0x%p\n", (BYTE*)Buffer+p);

		return 1;
	}

	DebugOutput("ScanForDisguisedPE: No PE image located in range 0x%p-0x%p.\n", Buffer, (DWORD_PTR)Buffer + Size);

	return 0;
}

//**************************************************************************************
DWORD GetEntryPoint(PVOID Address)
//**************************************************************************************
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader = NULL;

	if (!Address)
	{
		DebugOutput("GetEntryPoint: Error - no address supplied.\n");
		return 0;
	}

	if (!IsAddressAccessible(Address) || IsDisguisedPEHeader(Address) <= 0)
		return 0;

	pDosHeader = (PIMAGE_DOS_HEADER)Address;

	__try
	{
		if (pDosHeader->e_lfanew && (ULONG)pDosHeader->e_lfanew < PE_HEADER_LIMIT && ((ULONG)pDosHeader->e_lfanew & 3) == 0)
			pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + (ULONG)pDosHeader->e_lfanew);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DebugOutput("GetEntryPoint: Exception occurred attempting to follow e_lfanew 0x%x\n", pDosHeader->e_lfanew);
		return 0;
	}

	if (pNtHeader && TestPERequirements(pNtHeader))
		return pNtHeader->OptionalHeader.AddressOfEntryPoint;

	return 0;
}

//**************************************************************************************
DWORD GetTimeStamp(PVOID Address)
//**************************************************************************************
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader = NULL;

	if (!Address)
	{
		DebugOutput("GetTimeStamp: Error - no address supplied.\n");
		return 0;
	}

	if (IsDisguisedPEHeader(Address) <= 0)
		return 0;

	pDosHeader = (PIMAGE_DOS_HEADER)Address;

	__try
	{
		if (pDosHeader->e_lfanew && (ULONG)pDosHeader->e_lfanew < PE_HEADER_LIMIT && ((ULONG)pDosHeader->e_lfanew & 3) == 0)
			pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + (ULONG)pDosHeader->e_lfanew);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DebugOutput("GetTimeStamp: Exception occurred attempting to follow e_lfanew 0x%x\n", pDosHeader->e_lfanew);
		return 0;
	}

	if (pNtHeader && TestPERequirements(pNtHeader))
		return pNtHeader->FileHeader.TimeDateStamp;

	return 0;
}

//**************************************************************************************
int VerifyCodeSection(PVOID ImageBase, LPCWSTR Path)
//**************************************************************************************
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PBYTE CodeSectionBuffer = NULL;
	PIMAGE_BASE_RELOCATION Relocations;
	ULONG RelocationSize = 0, Size = 0;
	DWORD_PTR Delta;

	int RetVal = -1;

	if (!ImageBase)
	{
		DebugOutput("VerifyCodeSection: Error - no address supplied.\n");
		return RetVal;
	}

	if (IsDisguisedPEHeader(ImageBase) <= 0)
		return RetVal;

	pDosHeader = (PIMAGE_DOS_HEADER)ImageBase;

	if (!IsAddressAccessible(ImageBase))
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("VerifyCodeSection: 0x%p inaccessible\n", ImageBase);
#endif
		return RetVal;
	}

	if (*(WORD*)ImageBase != IMAGE_DOS_SIGNATURE)
		return RetVal;

	pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + pDosHeader->e_lfanew);

	if (!IsAddressAccessible(pNtHeader))
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("VerifyCodeSection: NT headers at 0x%p inaccessible\n", pNtHeader);
#endif
		return RetVal;
	}

	if (*(DWORD*)pNtHeader != IMAGE_NT_SIGNATURE)
		return RetVal;

	DWORD SizeOfHeaders = pDosHeader->e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + pNtHeader->FileHeader.SizeOfOptionalHeader;
	PIMAGE_SECTION_HEADER pFirstSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)ImageBase + SizeOfHeaders);

    HANDLE hFile = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
	{
#ifdef DEBUG_COMMENTS
		ErrorOutput("VerifyCodeSection: Error opening file %ws", Path);
#endif
		return RetVal;
    }

    IMAGE_DOS_HEADER DosHeader;
    DWORD bytesRead;
    if (!ReadFile(hFile, &DosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead, NULL))
	{
#ifdef DEBUG_COMMENTS
		ErrorOutput("VerifyCodeSection: Error reading file %ws", Path);
#endif
		goto end;
	}

    if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("VerifyCodeSection: IMAGE_DOS_SIGNATURE");
#endif
		goto end;
	}

	SetFilePointer(hFile, DosHeader.e_lfanew, 0, FILE_BEGIN);

    IMAGE_NT_HEADERS NtHeaders;
    if (!ReadFile(hFile, &NtHeaders, sizeof(IMAGE_NT_HEADERS), &bytesRead, NULL))
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("VerifyCodeSection: Error reading header of %ws", Path);
#endif
		goto end;
	}

	SetFilePointer(hFile, SizeOfHeaders, 0, FILE_BEGIN);

    IMAGE_SECTION_HEADER FirstSectionHeader;
    if (!ReadFile(hFile, &FirstSectionHeader, sizeof(IMAGE_SECTION_HEADER), &bytesRead, NULL))
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("VerifyCodeSection: Error reading first section of %ws", Path);
#endif
		goto end;
	}

    if (!FirstSectionHeader.SizeOfRawData)
	{
		DebugOutput("VerifyCodeSection: SizeOfRawData zero.\n");
		goto end;
	}

    CodeSectionBuffer = (PBYTE)calloc(NtHeaders.OptionalHeader.SizeOfCode, sizeof(BYTE));
    if (CodeSectionBuffer == NULL)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("VerifyCodeSection: Error allocating memory");
#endif
		return RetVal;
    }

	SetFilePointer(hFile, FirstSectionHeader.PointerToRawData, 0, FILE_BEGIN);

    DWORD BytesReadInSection;
    if (!ReadFile(hFile, CodeSectionBuffer, NtHeaders.OptionalHeader.SizeOfCode, &BytesReadInSection, NULL))
	{
#ifdef DEBUG_COMMENTS
		ErrorOutput("VerifyCodeSection: Error reading code section of %ws", Path);
#endif
		return RetVal;
    }

	Relocations = (PIMAGE_BASE_RELOCATION)((PBYTE)ImageBase + NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	RelocationSize = NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	Delta = (DWORD_PTR)((PBYTE)ImageBase - NtHeaders.OptionalHeader.ImageBase);
#ifdef DEBUG_COMMENTS
	DebugOutput("VerifyCodeSection: Relocations set to 0x%p, size 0x%x, Delta 0x%p, ImageBase 0x%p\n", Relocations, RelocationSize, Delta, NtHeaders.OptionalHeader.ImageBase);
#endif

	__try
	{
		while (RelocationSize > Size && Relocations->SizeOfBlock)
		{
			ULONG NumOfRelocs = (Relocations->SizeOfBlock - 8) / 2;
			PUSHORT Reloc = (PUSHORT)((PUCHAR)Relocations + 8);

#ifdef DEBUG_COMMENTS
			DebugOutput("VerifyCodeSection: VirtualAddress: 0x%.8x; Number of Relocs: %d; Size: %d\n", Relocations->VirtualAddress, NumOfRelocs, Relocations->SizeOfBlock);
#endif
			for (ULONG i = 0; i < NumOfRelocs; i++)
			{
				if (Reloc[i] > 0)
				{
					PUCHAR *RVA = (PUCHAR*)((PBYTE)(DWORD_PTR)Relocations->VirtualAddress + (Reloc[i] & 0x0FFF));
					DWORD_PTR Offset = (DWORD_PTR)((PBYTE)RVA - pFirstSectionHeader->VirtualAddress);
					if (Offset < FirstSectionHeader.SizeOfRawData)
#ifndef _WIN64
						(PUCHAR)*((PULONG)((PBYTE)CodeSectionBuffer + Offset)) += (ULONG)((ULONGLONG)Delta);
#else
						(PULONGLONG)*((PULONGLONG)(CodeSectionBuffer + Offset)) += (ULONGLONG)Delta;
#endif
				}
			}

			Relocations = (PIMAGE_BASE_RELOCATION)((PUCHAR)Relocations + Relocations->SizeOfBlock);
			Size += Relocations->SizeOfBlock;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DebugOutput("VerifyCodeSection: Exception rebasing image from 0x%p to 0x%p.\n", ImageBase, NtHeaders.OptionalHeader.ImageBase);
	}

	PVOID pFirstSection = (PVOID)((PBYTE)ImageBase + pFirstSectionHeader->VirtualAddress);

	SIZE_T SizeOfCode = (SIZE_T)ReverseScanForNonZero((PVOID)((PBYTE)ImageBase + pFirstSectionHeader->VirtualAddress), NtHeaders.OptionalHeader.SizeOfCode);

	SIZE_T ThunksSize = 0;
	DWORD pFirstThunk = 0;
	if (NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
	{
		__try
		{
			PIMAGE_IMPORT_DESCRIPTOR pImageImport = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)ImageBase + NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
			pFirstThunk = pImageImport->FirstThunk;
			while (pImageImport && pImageImport->FirstThunk)
			{
				PDWORD Thunks = (PDWORD)((PBYTE)ImageBase + pImageImport->FirstThunk);
				while (Thunks && *Thunks)
				{
					ThunksSize += sizeof(DWORD);
					++Thunks;
				};
				ThunksSize += sizeof(DWORD);
				++pImageImport;
			};
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			DebugOutput("VerifyCodeSection: Exception counting import thunks");
			pFirstThunk = 0;
		}
	}

	if (pFirstThunk && pFirstThunk >= pFirstSectionHeader->VirtualAddress && pFirstThunk < (pFirstSectionHeader->VirtualAddress + SizeOfCode))
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("VerifyCodeSection: Restoring original thunks - size 0x%x", ThunksSize);
#endif
		memcpy(CodeSectionBuffer + pFirstThunk - pFirstSectionHeader->VirtualAddress, (PVOID)((PBYTE)ImageBase + pFirstThunk), ThunksSize);
	}

	SIZE_T Matching = pRtlCompareMemory((PVOID)CodeSectionBuffer, pFirstSection, SizeOfCode);

    if (Matching == SizeOfCode)
	{
#ifdef DEBUG_COMMENTS
        DebugOutput("VerifyCodeSection: Executable code matches.\n");
#endif
		RetVal = 1;
    }
	else
	{
        DebugOutput("VerifyCodeSection: Executable code does not match, 0x%x of 0x%x matching\n", Matching, SizeOfCode);
		RetVal = 0;
    }

end:
	if (CodeSectionBuffer)
		free(CodeSectionBuffer);
    CloseHandle(hFile);

    return RetVal;
}

//**************************************************************************************
BOOL DumpStackRegion(void)
//**************************************************************************************
{
	SIZE_T StackSize = (SIZE_T)(get_stack_top() - get_stack_bottom());
	CapeMetaData->DumpType = STACK_REGION;
	CapeMetaData->Address = (PVOID)get_stack_bottom();
	return DumpMemory((PVOID)get_stack_bottom(), StackSize);
}

//**************************************************************************************
BOOL DumpPEsInRange(PVOID Buffer, SIZE_T Size)
//**************************************************************************************
{
	if (DumpCount >= DUMP_MAX)
	{
		DebugOutput("DumpPEsInRange: Dump at 0x%p skipped due to dump limit %d", Buffer, DUMP_MAX);
		return FALSE;
	}

	BOOL RetVal = FALSE;
	PVOID PEPointer = Buffer;
	SIZE_T Count = 0;

	if (!Size)
		return 0;

	SIZE_T AccessibleSize = GetAccessibleSize(Buffer);

	if (!AccessibleSize)
		return 0;

	if (AccessibleSize < Size)
		Size = AccessibleSize;

	Size = (SIZE_T)ReverseScanForNonZero(Buffer, Size);

	if (!Size)
	{
		DebugOutput("DumpPEsInRange: Nothing to dump at 0x%p!\n", Buffer);
		return 0;
	}

	DebugOutput("DumpPEsInRange: Scanning range 0x%p - 0x%p.\n", Buffer, (BYTE*)Buffer + Size);

	__try
	{
		while (ScanForDisguisedPE(PEPointer, Size - ((DWORD_PTR)PEPointer - (DWORD_PTR)Buffer), &PEPointer))
		{
			RetVal = DumpImageInCurrentProcess(PEPointer);
			if (!RetVal)
				break;
			Count++;
			(BYTE*)PEPointer += 0x1000;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE;
	}

	if (Count)
		return TRUE;

	return FALSE;
}

//**************************************************************************************
int DumpMemoryRaw(PVOID Buffer, SIZE_T Size)
//**************************************************************************************
{
	DWORD dwBytesWritten;
	HANDLE hOutputFile = NULL;
	PVOID BufferCopy = NULL;
	char *FullPathName = NULL;
	int ret = 0;

	BufferCopy = (PVOID)((BYTE*)calloc(Size, sizeof(BYTE)));

	if (BufferCopy == NULL)
	{
		DebugOutput("DumpMemory: Failed to allocate 0x%x bytes for buffer copy.\n", Size);
		goto end;
	}

	__try
	{
		memcpy(BufferCopy, Buffer, Size);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DebugOutput("DumpMemory: Exception occurred reading memory address 0x%p\n", Buffer);
		goto end;
	}

	FullPathName = GetName();

	hOutputFile = CreateFile(FullPathName, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hOutputFile == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_FILE_EXISTS)
			DebugOutput("DumpMemory: Payload name exists already: %s", FullPathName);
		else
			ErrorOutput("DumpMemory: Could not create Payload");
		goto end;
	}

	dwBytesWritten = 0;

	if (FALSE == WriteFile(hOutputFile, BufferCopy, (DWORD)Size, &dwBytesWritten, NULL))
	{
		ErrorOutput("DumpMemory: WriteFile error on Payload");
		goto end;
	}

	ret = 1;

end:
	if (BufferCopy)
		free(BufferCopy);
	if (hOutputFile && hOutputFile != INVALID_HANDLE_VALUE)
		CloseHandle(hOutputFile);

	if (ret)
	{
		DumpCount++;
		CapeMetaData->Address = Buffer;
		CapeMetaData->Size = Size;
		CapeOutputFile(FullPathName);
		DebugOutput("DumpMemory: Payload successfully created: %s (size %d bytes)", FullPathName, Size);
	}

	if (FullPathName)
		free(FullPathName);

	return ret;
}

//**************************************************************************************
int DumpMemory(PVOID Buffer, SIZE_T Size)
//**************************************************************************************
{
	if (DumpCount >= DUMP_MAX)
	{
		DebugOutput("DumpMemory: Dump at 0x%p skipped due to dump limit %d", Buffer, DUMP_MAX);
		return 0;
	}

	if (!Size)
		return 0;

	SIZE_T AccessibleSize = GetAccessibleSize(Buffer);

	if (!AccessibleSize)
		return 0;

	if (AccessibleSize < Size)
		Size = AccessibleSize;

	Size = (SIZE_T)ReverseScanForNonZero(Buffer, Size);

	if (!Size)
	{
		DebugOutput("DumpMemory: Nothing to dump at 0x%p!\n", Buffer);
		return 0;
	}

	return DumpMemoryRaw(Buffer, Size);
}

//**************************************************************************************
BOOL DumpRegion(PVOID Address)
//**************************************************************************************
{
	if (DumpCount >= DUMP_MAX)
	{
		DebugOutput("DumpRegion: Dump at 0x%p skipped due to dump limit %d", Address, DUMP_MAX);
		return FALSE;
	}

	PVOID AllocationBase = GetAllocationBase(Address);
	SIZE_T AccessibleSize = GetAccessibleSize(Address);

	PVOID BaseAddress = GetBaseAddress(Address);
	SIZE_T RegionSize = GetRegionSize(Address);

	SIZE_T Offset = (SIZE_T)((PUCHAR)BaseAddress - (DWORD_PTR)AllocationBase);

#ifdef DEBUG_COMMENTS
	DebugOutput("DumpRegion: Address 0x%p AllocationBase 0x%p AccessibleSize %d, BaseAddress 0x%p, RegionSize %d\n", Address, AllocationBase, AccessibleSize, BaseAddress, RegionSize);
#endif

	CapeMetaData->Address = AllocationBase;

	if (!(CapeMetaData->TypeString && strlen(CapeMetaData->TypeString)) && (!CapeMetaData->DumpType || CapeMetaData->DumpType == UNPACKED_SHELLCODE))
		CapeMetaData->DumpType = UNPACKED_PE;

	// If PEs in range but not at AllocationBase dump as shellcode
	if (DumpPEsInRange(AllocationBase, AccessibleSize) && (IsDisguisedPEHeader(AllocationBase)) > 0)
	{
		DebugOutput("DumpRegion: Dumped PE image(s) from base address 0x%p, size %d bytes.\n", AllocationBase, AccessibleSize);
		return TRUE;
	}

	if (CapeMetaData->DumpType == UNPACKED_PE)
		CapeMetaData->DumpType = UNPACKED_SHELLCODE;

	if (DumpMemory(AllocationBase, AccessibleSize))
	{
		if (address_is_in_stack(AllocationBase))
			DebugOutput("DumpRegion: Dumped stack region from 0x%p, size %d bytes.\n", AllocationBase, AccessibleSize);
		else
			DebugOutput("DumpRegion: Dumped entire allocation from 0x%p, size %d bytes.\n", AllocationBase, AccessibleSize);
		return TRUE;
	}
	else
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("DumpRegion: Failed to dump entire allocation from 0x%p size %d bytes.\n", AllocationBase, AccessibleSize);
#endif

		CapeMetaData->Address = BaseAddress;

		if (DumpMemory(BaseAddress, RegionSize))
		{
			if (address_is_in_stack(BaseAddress))
				DebugOutput("DumpRegion: Dumped stack region from 0x%p, size %d bytes.\n", BaseAddress, RegionSize);
			else
				DebugOutput("DumpRegion: Dumped region at 0x%p, size %d bytes.\n", BaseAddress, RegionSize);
			DumpCount++;
			return TRUE;
		}
		else
		{
			DebugOutput("DumpRegion: Failed to dump region at 0x%p size %d bytes.\n", BaseAddress, RegionSize);
			return FALSE;
		}
	}
}

//**************************************************************************************
int DumpProcess(HANDLE hProcess, PVOID BaseAddress, PVOID NewEP, BOOL FixImports)
//**************************************************************************************
{
	if (DumpCount >= DUMP_MAX)
	{
		DebugOutput("DumpProcess: Dump at 0x%p skipped due to dump limit %d", BaseAddress, DUMP_MAX);
		return 0;
	}

	__try
	{
		if (!ScyllaDumpProcess(hProcess, (DWORD_PTR)BaseAddress, (DWORD_PTR)NewEP, FixImports))
			return 0;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return 0;
	}

	DumpCount++;
	return 1;
}

//**************************************************************************************
int DumpPE(PVOID Buffer)
//**************************************************************************************
{
	if (DumpCount >= DUMP_MAX)
	{
		DebugOutput("DumpPE: Dump at 0x%p skipped due to dump limit %d", Buffer, DUMP_MAX);
		return 0;
	}

	__try
	{
		if (!ScyllaDumpPE((DWORD_PTR)Buffer))
			return 0;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return 0;
	}

	DumpCount++;
	return 1;
}

//**************************************************************************************
int DumpImageInCurrentProcess(PVOID BaseAddress)
//**************************************************************************************
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	PVOID RegionCopy = NULL;
	DWORD dwProtect = 0;
	int RetVal = 0;

	pDosHeader = (PIMAGE_DOS_HEADER)BaseAddress;

	if (DumpCount >= DUMP_MAX)
	{
		DebugOutput("DumpPE: Dump at 0x%p skipped due to dump limit %d", BaseAddress, DUMP_MAX);
		return 0;
	}

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || (*(DWORD*)((BYTE*)pDosHeader + pDosHeader->e_lfanew) != IMAGE_NT_SIGNATURE))
    {
        // We want to fix the PE header in the dump (for e.g. disassembly etc)
		SIZE_T RegionSize = GetAccessibleSize(BaseAddress);

        RegionCopy = calloc(RegionSize, sizeof(BYTE));

        if (!RegionCopy)
        {
            ErrorOutput("DumpImageInCurrentProcess: Failed to allocate memory page for PE header.\n");
            return 0;
        }

        __try
        {
            memcpy(RegionCopy, BaseAddress, RegionSize);
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            DebugOutput("DumpImageInCurrentProcess: Exception occured copying PE header at 0x%p\n", BaseAddress);
            free(RegionCopy);
            return 0;
        }

        pDosHeader = (PIMAGE_DOS_HEADER)RegionCopy;

        DebugOutput("DumpImageInCurrentProcess: Disguised PE image (bad MZ and/or PE headers) at 0x%p\n", BaseAddress);

        if (!pDosHeader->e_lfanew)
        {
            // In case the header until and including 'PE' has been zeroed
            WORD* MachineProbe = (WORD*)&pDosHeader->e_lfanew;
            while ((PUCHAR)MachineProbe < (PUCHAR)pDosHeader + (PE_HEADER_LIMIT - offsetof(IMAGE_DOS_HEADER, e_lfanew)))
            {
                if (*MachineProbe == IMAGE_FILE_MACHINE_I386 || *MachineProbe == IMAGE_FILE_MACHINE_AMD64)
                {
                    if ((PUCHAR)MachineProbe > (PUCHAR)pDosHeader + 3)
                        pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)MachineProbe - 4);
                }
                MachineProbe += sizeof(WORD);
            }

            if (pNtHeader)
                pDosHeader->e_lfanew = (LONG)((PUCHAR)pNtHeader - (PUCHAR)pDosHeader);
        }

        if (!pDosHeader->e_lfanew || pDosHeader->e_lfanew > PE_MAX_SIZE)
        {
            DebugOutput("DumpImageInCurrentProcess: Bad e_lfanew 0x%x\n", pDosHeader->e_lfanew);
            goto end;
        }

		*(WORD*)pDosHeader = IMAGE_DOS_SIGNATURE;
		*(DWORD*)((PUCHAR)pDosHeader + pDosHeader->e_lfanew) = IMAGE_NT_SIGNATURE;
	}


	if (IsPeImageRaw(BaseAddress))
	{
		DebugOutput("DumpImageInCurrentProcess: Attempting to dump 'raw' PE image (process %d)\n", GetCurrentProcessId());

		if (!DumpPE(BaseAddress))
			DebugOutput("DumpImageInCurrentProcess: Failed to dump 'raw' PE image from 0x%p, dumping memory region.\n", BaseAddress);
		else
			RetVal = 1;
	}
	else
	{
		DebugOutput("DumpImageInCurrentProcess: Attempting to dump virtual PE image.\n");

		if (!DumpProcess(GetCurrentProcess(), BaseAddress, 0, FALSE))
			DebugOutput("DumpImageInCurrentProcess: Failed to dump virtual PE image from 0x%p, dumping memory region.\n", BaseAddress);
		else
			RetVal = 1;
	}

end:
	if (RegionCopy)
		free(RegionCopy);

	if (RetVal)
		DumpCount++;

	return RetVal;
}

//**************************************************************************************
int DumpImageInCurrentProcessFixImports(PVOID BaseAddress, PVOID NewEP)
//**************************************************************************************
{
	return DumpProcess(NULL, BaseAddress, NewEP, TRUE);
}

//**************************************************************************************
int DumpCurrentProcessFixImports(PVOID NewEP)
//**************************************************************************************
{
	return DumpProcess(NULL, GetModuleHandle(NULL), NewEP, TRUE);
}

//**************************************************************************************
int DumpCurrentProcessNewEP(PVOID NewEP)
//**************************************************************************************
{
	return DumpProcess(NULL, GetModuleHandle(NULL), NewEP, FALSE);
}

//**************************************************************************************
int DumpCurrentProcess()
//**************************************************************************************
{
	return DumpProcess(NULL, GetModuleHandle(NULL), NULL, FALSE);
}

//**************************************************************************************
void DumpInterestingRegions(MEMORY_BASIC_INFORMATION MemInfo)
//**************************************************************************************
{
	if (!MemInfo.BaseAddress)
		return;

	if (MemInfo.BaseAddress == (PVOID)g_our_dll_base)
		return;

	if (!IsAddressAccessible(MemInfo.BaseAddress))
		return;

	char ModulePath[MAX_PATH];
	BOOL MappedModule = GetMappedFileName(GetCurrentProcess(), MemInfo.AllocationBase, ModulePath, MAX_PATH);

	if (IsDotNetImage(MemInfo.BaseAddress) && !MappedModule && MemInfo.Protect == PAGE_READWRITE && MemInfo.Type == MEM_MAPPED && MemInfo.State == MEM_COMMIT)
	{
		DebugOutput("DumpInterestingRegions: Dumping .NET image at 0x%p.\n", MemInfo.BaseAddress);

		CapeMetaData->ModulePath = NULL;
		CapeMetaData->DumpType = UNPACKED_PE;
		CapeMetaData->Address = MemInfo.BaseAddress;

		DumpImageInCurrentProcess(MemInfo.BaseAddress);
	}

	if (lookup_get(&g_dotnet_jit, (ULONG_PTR)MemInfo.BaseAddress, 0))
	{
		DebugOutput("DumpInterestingRegions: Dumping .NET JIT native cache at 0x%p.\n", MemInfo.BaseAddress);

		CapeMetaData->ModulePath = NULL;
		CapeMetaData->DumpType = 0;
#ifdef _WIN64
		CapeMetaData->TypeString = ".NET JIT native cache (64-bit)";
#else
		CapeMetaData->TypeString = ".NET JIT native cache (32-bit)";
#endif
		CapeMetaData->Address = MemInfo.BaseAddress;

		DumpMemory(MemInfo.BaseAddress, GetAccessibleSize(MemInfo.BaseAddress));
	}
}

//**************************************************************************************
int DoProcessDump()
//**************************************************************************************
{
	PUCHAR Address;
	MEMORY_BASIC_INFORMATION MemInfo;
	HANDLE FileHandle = NULL;
	char *FullDumpPath = NULL, *OutputFilename = NULL;
	wchar_t *ImagePath = NULL;
	PVOID NewImageBase = NULL;

	DWORD ThreadId = GetCurrentThreadId();

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	if (!SystemInfo.dwPageSize)
	{
		ErrorOutput("DoProcessDump: Failed to obtain system page size.\n");
		return 0;
	}

	if (ProcessDumped)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("DoProcessDump: This process has already been dumped.\n");
#endif
		return 0;
	}

	if (g_config.procdump)
	{
		if (base_of_dll_of_interest)
		{
			ImageBase = (PVOID)base_of_dll_of_interest;
			ImagePath = g_config.file_of_interest;
		}
		else
		{
			NewImageBase = GetModuleHandle(NULL);
			if (ImageBase && ImageBase == NewImageBase)
				NewImageBase = NULL;
			ImagePath = our_process_path_w;
		}

		if (IsAddressAccessible(ImageBase))
		{
			if (g_config.procdump > 1 || VerifyCodeSection(ImageBase, ImagePath) < 1)
			{
				if (g_config.procdump < 2)
					DebugOutput("DoProcessDump: Code modification detected, dumping Imagebase at 0x%p.\n", ImageBase);
				else
					DebugOutput("DoProcessDump: Dumping Imagebase at 0x%p.\n", ImageBase);
				CapeMetaData->DumpType = PROCDUMP;
				if (DumpCount > 0)
					DumpCount--;
				__try
				{
					if (g_config.import_reconstruction)
						ProcessDumped = DumpImageInCurrentProcessFixImports(ImageBase, 0);
					else
						ProcessDumped = DumpImageInCurrentProcess(ImageBase);
				}
				__except(EXCEPTION_EXECUTE_HANDLER)
				{
					DebugOutput("DoProcessDump: Failed to dump main process image at 0x%p.\n", ImageBase);
					goto out;
				}
			}
			else
			{
				DebugOutput("DoProcessDump: Skipping process dump as code is identical on disk.\n");
				ProcessDumped = TRUE;
			}
		}
#ifdef DEBUG_COMMENTS
		else
			DebugOutput("DoProcessDump: Imagebase at 0x%p inaccessible.\n", ImageBase);
#endif
		if (NewImageBase && IsAddressAccessible(NewImageBase))
		{
			DebugOutput("DoProcessDump: Dumping 'new' Imagebase at 0x%p.\n", NewImageBase);
			CapeMetaData->DumpType = PROCDUMP;
			if (DumpCount > 0)
				DumpCount--;
			__try
			{
				if (g_config.import_reconstruction)
					ProcessDumped = DumpImageInCurrentProcessFixImports(NewImageBase, 0);
				else
					ProcessDumped = DumpImageInCurrentProcess(NewImageBase);
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				DebugOutput("DoProcessDump: Failed to dump 'new' process image base at 0x%p.\n", NewImageBase);
				goto out;
			}
		}
#ifdef DEBUG_COMMENTS
		else if (NewImageBase)
			DebugOutput("DoProcessDump: Imagebase at 0x%p inaccessible.\n", NewImageBase);
#endif

		if (!ProcessDumped)
		{
			DebugOutput("DoProcessDump: Attempting raw dump of Imagebase at 0x%p.\n", ImageBase);
			ProcessDumped = DumpMemory(ImageBase, GetAccessibleSize(ImageBase));
		}
	}

	// For full-memory dumps, create the output file
	if (g_config.procmemdump)
	{
		FullDumpPath = GetResultsPath("memory");

		if (!FullDumpPath)
		{
			DebugOutput("DoProcessDump: Unable to get path to dump file directory.\n");
			goto out;
		}

		OutputFilename = (char*)calloc(MAX_PATH, sizeof(BYTE));

		sprintf_s(OutputFilename, MAX_PATH, "%u.dmp", CapeMetaData->Pid);

		PathAppend(FullDumpPath, OutputFilename);

		FileHandle = CreateFile(FullDumpPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

		if (FileHandle == INVALID_HANDLE_VALUE)
		{
			DebugOutput("DoProcessDump: Unable to create dump file for full process memory dump.\n");
			goto out;
		}
#ifdef DEBUG_COMMENTS
		else
			DebugOutput("DoProcessDump: Saving full process memory dump to %s.\n", FullDumpPath);
#endif
	}

	if (!g_config.procdump && !g_config.procmemdump)
		return ProcessDumped;

	// Scan entire user-mode space for both full dump and 'interesting' regions
	for (Address = (PUCHAR)SystemInfo.lpMinimumApplicationAddress; Address < (PUCHAR)SystemInfo.lpMaximumApplicationAddress;)
	{
		if (!VirtualQuery(Address, &MemInfo, sizeof(MemInfo)))
		{
			Address += SystemInfo.dwPageSize;
			continue;
		}

		if (!(MemInfo.State & MEM_COMMIT) || !(MemInfo.Type & (MEM_IMAGE | MEM_MAPPED | MEM_PRIVATE)))
		{
			Address += MemInfo.RegionSize;
			continue;
		}

		if (g_config.procdump && MemInfo.BaseAddress != ImageBase && MemInfo.BaseAddress != NewImageBase && !is_in_dll_range((ULONG_PTR)Address))
			DumpInterestingRegions(MemInfo);

		if (g_config.procmemdump && !is_in_dll_range((ULONG_PTR)Address) && IsAddressAccessible((PVOID)Address) && !ScanForRulesCanary(MemInfo.BaseAddress, MemInfo.RegionSize))
		{
			LARGE_INTEGER BufferAddress;
			DWORD BytesWritten;
			PVOID TempBuffer;

			BufferAddress.QuadPart = (ULONGLONG)Address;
			TempBuffer = calloc(MemInfo.RegionSize, sizeof(BYTE));
			if (!TempBuffer)
			{
				DebugOutput("DoProcessDump: Error allocating memory for copy of region at 0x%p, size 0x%x.\n", MemInfo.BaseAddress, MemInfo.RegionSize);
				goto out;
			}

			__try
			{
				if (MemInfo.BaseAddress)
					memcpy(TempBuffer, MemInfo.BaseAddress, MemInfo.RegionSize);
				WriteFile(FileHandle, &BufferAddress, sizeof(BufferAddress), &BytesWritten, NULL);
				WriteFile(FileHandle, &(DWORD)MemInfo.RegionSize, sizeof(DWORD), &BytesWritten, NULL);
				WriteFile(FileHandle, &MemInfo.State, sizeof(MemInfo.State), &BytesWritten, NULL);
				WriteFile(FileHandle, &MemInfo.Type, sizeof(MemInfo.Type), &BytesWritten, NULL);
				WriteFile(FileHandle, &MemInfo.Protect, sizeof(MemInfo.Protect), &BytesWritten, NULL);
				WriteFile(FileHandle, TempBuffer, (DWORD)MemInfo.RegionSize, &BytesWritten, NULL);
				free(TempBuffer);
#ifdef DEBUG_COMMENTS
				if (BytesWritten != MemInfo.RegionSize)
					DebugOutput("DoProcessDump: Anomaly detected, wrote only 0x%x of 0x%x bytes to memory dump from region 0x%p.\n", BytesWritten, MemInfo.RegionSize, MemInfo.BaseAddress);
				//else
				//	DebugOutput("DoProcessDump: Added 0x%x byte region at 0x%p to memory dump (protect 0x%x).\n", MemInfo.RegionSize, MemInfo.BaseAddress, MemInfo.Protect);
#endif
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				free(TempBuffer);
#ifdef DEBUG_COMMENTS
				DebugOutput("DoProcessDump: Exception attempting to dump region at 0x%p, size 0x%x.\n", MemInfo.BaseAddress, MemInfo.RegionSize);
#endif
			}
		}

		Address += MemInfo.RegionSize;
	}

out:
	if (g_config.procmemdump)
	{
		if (FileHandle)
		{
			CloseHandle(FileHandle);
			if (FullDumpPath)
				DoOutputFile(FullDumpPath);
			DebugOutput("DoProcessDump: Full process memory dump saved to file: %s.\n", FullDumpPath);
		}
		else
			DebugOutput("DoProcessDump: There was a problem saving full process memory dump to: %s.\n", FullDumpPath);
		if (OutputFilename)
			free(OutputFilename);
		if (FullDumpPath)
			free(FullDumpPath);
	}

	return ProcessDumped;
}

void RestoreHeaders()
{
	DWORD ImportsRVA, ImportsSize, SizeOfHeaders, dwProtect;
	PVOID BaseAddress, ImportsVA;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;

	BaseAddress = GetModuleHandle(NULL);
	SizeOfHeaders = sizeof(IMAGE_NT_HEADERS);
	pDosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
	pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)BaseAddress + pDosHeader->e_lfanew);
	ImportsRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	ImportsSize = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	ImportsVA = (PBYTE)BaseAddress + ImportsRVA;

	// Check if we have a PE header after import table
	if (*(DWORD*)((PBYTE)ImportsVA + ImportsSize) != IMAGE_NT_SIGNATURE)
		return;

	// Set page permissions to allow writing of original headers
	if (!VirtualProtect((PBYTE)BaseAddress, SizeOfHeaders, PAGE_EXECUTE_READWRITE, &dwProtect))
	{
		ErrorOutput("RestoreHeaders: Failed to modify memory page protection of NtHeaders");
		return;
	}

	memcpy((PBYTE)BaseAddress + pDosHeader->e_lfanew, (PBYTE)ImportsVA + ImportsSize, SizeOfHeaders);

	// Restore original protection
	if (!VirtualProtect((PBYTE)BaseAddress, SizeOfHeaders, dwProtect, &dwProtect))
	{
		ErrorOutput("RestoreHeaders: Failed to restore previous memory page protection");
		return;
	}

	// Free memory
	if (!VirtualFree(ImportsVA, 0, MEM_RELEASE))
	{
		ErrorOutput("RestoreHeaders: Failed to free memory for patched IAT");
		return;
	}

	DebugOutput("RestoreHeaders: Restored original import table.\n");
}

void CAPE_post_init()
{
	if (g_config.syscall && ((OSVersion.dwMajorVersion == 6 && OSVersion.dwMinorVersion > 1) || OSVersion.dwMajorVersion > 6))
		NirvanaInit();

	if (g_config.debugger && InitialiseDebugger())
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("Post-init: Debugger initialised.\n");
#endif
		if (!g_config.base_on_apiname[0])
			SetInitialBreakpoints(GetModuleHandle(NULL));
	}
#ifdef DEBUG_COMMENTS
	else if (g_config.debugger)
		DebugOutput("Post-init: Failed to initialise debugger.\n");
#endif

	if (g_config.unpacker)
		UnpackerInit();

	if (g_config.caller_regions)
		lookup_add(&g_caller_regions, (ULONG_PTR)g_our_dll_base, 0);

	// Restore headers in case of IAT patching
	RestoreHeaders();
}

void CAPE_init()
{
	char *Character;

	// Initialise CAPE global variables
	//
	//if (!g_config.standalone)
	CapeMetaData = (PCAPEMETADATA)calloc(sizeof(CAPEMETADATA), sizeof(BYTE));
	CapeMetaData->Pid = GetCurrentProcessId();
	CapeMetaData->PPid = parent_process_id();
	CapeMetaData->ProcessPath = (char*)calloc(MAX_PATH, sizeof(BYTE));
	WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, (LPCWSTR)our_process_path_w, (int)wcslen(our_process_path_w)+1, CapeMetaData->ProcessPath, MAX_PATH, NULL, NULL);
	Character = CapeMetaData->ProcessPath;
	if (g_config.typestring)
		CapeMetaData->TypeString = g_config.typestring;

	// It seems with CP_ACP or CP_UTF8 & WC_NO_BEST_FIT_CHARS, WideCharToMultiByte still
	// leaves characters that encode("utf-8"... can't encode...
	while (*Character)
	{   // Restrict to ASCII range
		if (*Character < 0x0a || *Character > 0x7E)
			*Character = 0x3F;  // '?'
		Character++;
	}

	ProcessDumped = FALSE;
	DumpCount = 0;

	// Cuckoo debug output level for development (0=none, 2=max)
	// g_config.debug = 2;

	YaraInit();

	ImageBase = GetModuleHandle(NULL);

	if (g_config.yarascan)
		YaraScan(ImageBase, GetAccessibleSize(ImageBase));

	if (g_config.yarascan && is_image_base_remapped(ImageBase))
	{
		ImageBaseRemapped = TRUE;

		HANDLE FileHandle = CreateFileW(our_process_path_w, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (FileHandle == INVALID_HANDLE_VALUE)
		{
			ErrorOutput("CAPE_init: Unable to open main executable image");
			goto Finish;
		}

		DWORD FileSize = GetFileSize(FileHandle, NULL);
		if (FileSize == INVALID_FILE_SIZE)
		{
			ErrorOutput("CAPE_init: Unable to get size of main executable image");
			goto Finish;
		}

		HANDLE MappingHandle = CreateFileMapping(FileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
		if (MappingHandle == NULL)
		{
			ErrorOutput("CAPE_init: Unable to create file mapping of main executable image");
			goto Finish;
		}

		LPVOID Mapped = MapViewOfFile(MappingHandle, FILE_MAP_READ, 0, 0, FileSize);
		if (Mapped == NULL)
		{
			ErrorOutput("CAPE_init: Unable to map main executable image");
			goto Finish;
		}

		DebugOutput("CAPE_init: Main executable image temporarily remapped for scanning at 0x%p", Mapped);

		YaraScan(Mapped, GetAccessibleSize(ImageBase));

Finish:
		if (Mapped) UnmapViewOfFile(Mapped);
		if (MappingHandle) CloseHandle(MappingHandle);
		if (FileHandle && FileHandle != INVALID_HANDLE_VALUE) CloseHandle(FileHandle);
	}

	OSVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

#pragma warning(suppress : 4996)
	if (!GetVersionEx(&OSVersion))
	{
		ErrorOutput("CAPE_init: Failed to get OS version");
		return;
	}

	if (g_config.amsidump && ((OSVersion.dwMajorVersion == 6 && OSVersion.dwMinorVersion > 1) || OSVersion.dwMajorVersion > 6))
		AmsiDumperInit((HMODULE)g_our_dll_base);

#ifdef _WIN64
	DebugOutput("Monitor initialised: 64-bit capemon loaded in process %d at 0x%p, thread %d, image base 0x%p, stack from 0x%p-0x%p\n", CapeMetaData->Pid, g_our_dll_base, GetCurrentThreadId(), ImageBase, get_stack_bottom(), get_stack_top());
#else
	DebugOutput("Monitor initialised: 32-bit capemon loaded in process %d at 0x%x, thread %d, image base 0x%x, stack from 0x%x-0x%x\n", CapeMetaData->Pid, g_our_dll_base, GetCurrentThreadId(), ImageBase, get_stack_bottom(), get_stack_top());
#endif

	DebugOutput("Commandline: %s\n", GetCommandLineA());

	return;
}
