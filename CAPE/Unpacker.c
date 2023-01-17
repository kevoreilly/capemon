/*
CAPE - Config And Payload Extraction
Copyright(C) 2019 Kevin O'Reilly (kevoreilly@gmail.com)

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

#include <windows.h>
#include <distorm.h>
#include "Debugger.h"
#include "CAPE.h"
#include "Unpacker.h"
#include "..\alloc.h"
#include "..\config.h"

#define PE_HEADER_LIMIT 0x200

#define MAX_PRETRAMP_SIZE 320
#define MAX_TRAMP_SIZE 128

#define ENTROPY_DELTA   1

BOOL GuardPagesDisabled = TRUE;

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

	// instead of a library/funcname combination, an address can be given
	// as well (this address has more priority than library/funcname)
	void *addr;

	// where we made our modifications
	void *hook_addr;

	// pointer to the new function
	void *new_func;

	// "function" which jumps over the trampoline and executes the original
	// function call
	void **old_func;

	// pointer to alternate new function used in notail hooks
	void *alt_func;

	// allow hook recursion on this hook?
	// (see comments @ hook_create_pre_trampoline)
	int allow_hook_recursion;

	int fully_emulate;

	unsigned char numargs;

	int notail;

	// this hook has been performed
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

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern void ErrorOutput(_In_ LPCTSTR lpOutputString, ...);

extern unsigned int address_is_in_stack(PVOID Address);
extern ULONG_PTR g_our_dll_base;
extern DWORD g_our_dll_size;
extern HANDLE g_terminate_event_handle;
extern PVOID ImageBase;
extern char *our_process_name;
extern char *our_process_path;

extern int operate_on_backtrace(ULONG_PTR _esp, ULONG_PTR _ebp, void *extra, int(*func)(void *, ULONG_PTR));
extern int WINAPI enter_hook(ULONG_PTR *h, ULONG_PTR sp, ULONG_PTR ebp_or_rip);
extern void hook_disable();
extern void hook_enable();
extern hook_info_t *hook_info();
extern int is_stack_pivoted(void);
extern BOOL is_in_dll_range(ULONG_PTR addr);

extern PVOID GetReturnAddress(hook_info_t *hookinfo);
extern BOOL DumpPEsInRange(PVOID Buffer, SIZE_T Size);
extern int DumpMemory(PVOID Buffer, SIZE_T Size);
extern int ScanForPE(PVOID Buffer, SIZE_T Size, PVOID* Offset);
extern int ScanPageForNonZero(PVOID Address);

BOOL ActivateBreakpoints(PTRACKEDREGION TrackedRegion, struct _EXCEPTION_POINTERS* ExceptionInfo);
BOOL ShellcodeExecCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo);

PTRACKEDREGION GuardedPagesToStep, TrackedRegionFromHook, CurrentBreakpointRegion;
static DWORD_PTR LastEIP, CurrentEIP;

//**************************************************************************************
PIMAGE_NT_HEADERS GetNtHeaders(PVOID BaseAddress)
//**************************************************************************************
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)BaseAddress;

	__try
	{
		if (!pDosHeader->e_lfanew)
		{
			DebugOutput("GetNtHeaders: pointer to PE header zero.\n");
			return NULL;
		}

		if ((ULONG)pDosHeader->e_lfanew > PE_HEADER_LIMIT)
		{
			DebugOutput("GetNtHeaders: pointer to PE header too big: 0x%x (at 0x%p).\n", pDosHeader->e_lfanew, &pDosHeader->e_lfanew);
			return NULL;
		}

		return (PIMAGE_NT_HEADERS)((BYTE*)BaseAddress + pDosHeader->e_lfanew);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DebugOutput("GetNtHeaders: Exception occurred reading around base address 0x%p\n", BaseAddress);
		return NULL;
	}
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

	if ((DWORD_PTR)Address >= (DWORD_PTR)TrackedRegion->AllocationBase && (DWORD_PTR)Address < ((DWORD_PTR)TrackedRegion->AllocationBase + (DWORD_PTR)TrackedRegion->RegionSize))
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
		if ((DWORD_PTR)Address >= (DWORD_PTR)CurrentTrackedRegion->AllocationBase && (DWORD_PTR)Address < ((DWORD_PTR)CurrentTrackedRegion->AllocationBase + (DWORD_PTR)CurrentTrackedRegion->RegionSize))
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
		//DebugOutput("GetTrackedRegion: AllocationBase 0x%p RegionSize 0x%d.\n", CurrentTrackedRegion->AllocationBase, CurrentTrackedRegion->RegionSize);
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

	PTRACKEDREGION FirstTrackedRegion = ((struct TrackedRegion*)malloc(sizeof(struct TrackedRegion)));

	if (FirstTrackedRegion == NULL)
	{
		DebugOutput("CreateTrackedRegion: failed to allocate memory for initial tracked region list.\n");
		return NULL;
	}

	memset(FirstTrackedRegion, 0, sizeof(struct TrackedRegion));

	TrackedRegionList = FirstTrackedRegion;

	//DebugOutput("CreateTrackedRegion: Tracked region list created at 0x%p.\n", TrackedRegionList);

	return TrackedRegionList;
}

//**************************************************************************************
PTRACKEDREGION AddTrackedRegion(PVOID Address, SIZE_T RegionSize, ULONG Protect)
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

	if (NumberOfTrackedRegions > 10)
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

		TrackedRegion->NextTrackedRegion = ((struct TrackedRegion*)malloc(sizeof(struct TrackedRegion)));

		if (TrackedRegion->NextTrackedRegion == NULL)
		{
			DebugOutput("AddTrackedRegion: Failed to allocate new tracked region struct.\n");
			return NULL;
		}

		TrackedRegion = TrackedRegion->NextTrackedRegion;

		memset(TrackedRegion, 0, sizeof(struct TrackedRegion));
		DebugOutput("AddTrackedRegion: Created new tracked region for address 0x%p.\n", Address);
	}
	else
	{
		PageAlreadyTracked = TRUE;
		DebugOutput("AddTrackedRegion: Region at 0x%p already in tracked region 0x%p - updating.\n", Address, TrackedRegion->AllocationBase);
	}

	if (!VirtualQuery(Address, &TrackedRegion->MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		ErrorOutput("AddTrackedRegion: unable to query memory region 0x%p", Address);
		return NULL;
	}

	TrackedRegion->AllocationBase = TrackedRegion->MemInfo.AllocationBase;

	if (Address != TrackedRegion->AllocationBase)
		TrackedRegion->ProtectAddress = Address;

	if (RegionSize && RegionSize > TrackedRegion->MemInfo.RegionSize)
		TrackedRegion->RegionSize = RegionSize;
	else
		TrackedRegion->RegionSize = TrackedRegion->MemInfo.RegionSize;

	if (Protect)
		TrackedRegion->Protect = Protect;
	else
		TrackedRegion->Protect = TrackedRegion->MemInfo.Protect;

	// If the region is a PE image
	TrackedRegion->EntryPoint = GetEntryPoint(TrackedRegion->AllocationBase);
	if (TrackedRegion->EntryPoint)
	{
		TrackedRegion->Entropy = GetEntropy((PUCHAR)TrackedRegion->AllocationBase);
		if (!TrackedRegion->Entropy)
			DebugOutput("AddTrackedRegion: GetEntropy failed.");

		TrackedRegion->MinPESize = GetMinPESize(TrackedRegion->AllocationBase);
		if (TrackedRegion->MinPESize)
			DebugOutput("AddTrackedRegion: Min PE size 0x%x", TrackedRegion->MinPESize);
		//else
		//	DebugOutput("AddTrackedRegion: GetMinPESize failed");
		if (!PageAlreadyTracked)
			DebugOutput("AddTrackedRegion: New region at 0x%p size 0x%x added to tracked regions: EntryPoint 0x%x, Entropy %e\n", TrackedRegion->AllocationBase, TrackedRegion->RegionSize, TrackedRegion->EntryPoint, TrackedRegion->Entropy);

	}
	else if (!PageAlreadyTracked)
		DebugOutput("AddTrackedRegion: New region at 0x%p size 0x%x added to tracked regions.\n", TrackedRegion->AllocationBase, TrackedRegion->RegionSize);

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
		DebugOutput("DropTrackedRegion: CurrentTrackedRegion 0x%x, AllocationBase 0x%x.\n", CurrentTrackedRegion, CurrentTrackedRegion->AllocationBase);

		if (CurrentTrackedRegion == TrackedRegion)
		{
			// Clear any breakpoints in this region
			//ClearBreakpointsInRange(TrackedRegion->AllocationBase, TrackedRegion->RegionSize);

			// Unlink this from the list and free the memory
			if (PreviousTrackedRegion && CurrentTrackedRegion->NextTrackedRegion)
			{
				DebugOutput("DropTrackedRegion: removed pages 0x%x-0x%x from tracked region list.\n", TrackedRegion->AllocationBase, (DWORD_PTR)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
				PreviousTrackedRegion->NextTrackedRegion = CurrentTrackedRegion->NextTrackedRegion;
			}
			else if (PreviousTrackedRegion && CurrentTrackedRegion->NextTrackedRegion == NULL)
			{
				DebugOutput("DropTrackedRegion: removed pages 0x%x-0x%x from the end of the tracked region list.\n", TrackedRegion->AllocationBase, (DWORD_PTR)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
				PreviousTrackedRegion->NextTrackedRegion = NULL;
			}
			else if (!PreviousTrackedRegion)
			{
				DebugOutput("DropTrackedRegion: removed pages 0x%x-0x%x from the head of the tracked region list.\n", TrackedRegion->AllocationBase, (DWORD_PTR)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
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
	if (!TrackedRegion->AllocationBase || !TrackedRegion->RegionSize)
	{
		DebugOutput("ClearTrackedRegion: Error, AllocationBase or RegionSize zero: 0x%p, 0x%p.\n", TrackedRegion->AllocationBase, TrackedRegion->RegionSize);
	}

	if (ClearBreakpointsInRange(TrackedRegion->AllocationBase, TrackedRegion->RegionSize))
		TrackedRegion->BreakpointsSet = FALSE;

	TrackedRegion->CanDump = FALSE;

	CapeMetaData->Address = NULL;

	if (TrackedRegion == TrackedRegionFromHook)
		TrackedRegionFromHook = NULL;

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

	ClearAllBreakpoints();

	return TRUE;
}

//**************************************************************************************
BOOL ActivateGuardPages(PTRACKEDREGION TrackedRegion)
//**************************************************************************************
{
	DWORD OldProtect;
	BOOL TrackedRegionFound = FALSE;
	PTRACKEDREGION CurrentTrackedRegion;
	PVOID TestAddress;

	SIZE_T MatchingRegionSize;

	if (TrackedRegion == NULL)
	{
		DebugOutput("ActivateGuardPages: NULL passed as argument - error.\n");
		return FALSE;
	}

	if (TrackedRegionList == NULL)
	{
		DebugOutput("ActivateGuardPages: Error - no tracked region list.\n");
		return FALSE;
	}

	CurrentTrackedRegion = TrackedRegionList;

	while (CurrentTrackedRegion)
	{
		//DebugOutput("TrackedRegion->AllocationBase 0x%x, CurrentTrackedRegion->AllocationBase 0x%x.\n", TrackedRegion->AllocationBase, CurrentTrackedRegion->AllocationBase);

		 __try
		{
			TestAddress = CurrentTrackedRegion->AllocationBase;
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			ErrorOutput("ActivateGuardPages: Exception trying to access BaseAddres from tracked region at 0x%x", CurrentTrackedRegion);
			return FALSE;
		}

		if (TrackedRegion->AllocationBase == CurrentTrackedRegion->AllocationBase)
			TrackedRegionFound = TRUE;

		CurrentTrackedRegion = CurrentTrackedRegion->NextTrackedRegion;
	}

	if (!TrackedRegionFound)
	{
		DebugOutput("ActivateGuardPages: failed to locate tracked region(s) in tracked region list.\n");
		return FALSE;
	}

	MatchingRegionSize = VirtualQuery(TrackedRegion->AllocationBase, &TrackedRegion->MemInfo, sizeof(MEMORY_BASIC_INFORMATION));

	if (!MatchingRegionSize)
	{
		ErrorOutput("ActivateGuardPages: failed to query tracked region(s) status in region 0x%x-0x%x", TrackedRegion->AllocationBase, (DWORD_PTR)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
		return FALSE;
	}

	//DebugOutput("ActivateGuardPages: BaseAddress 0x%x, AllocationBase 0x%x, AllocationProtect 0x%x, RegionSize 0x%x, State 0x%x, Protect 0x%x, Type 0x%x\n", TrackedRegion->MemInfo.BaseAddress, TrackedRegion->MemInfo.AllocationBase, TrackedRegion->MemInfo.AllocationProtect, TrackedRegion->MemInfo.RegionSize, TrackedRegion->MemInfo.State, TrackedRegion->MemInfo.Protect, TrackedRegion->MemInfo.Type);

	if (MatchingRegionSize == TrackedRegion->RegionSize && TrackedRegion->MemInfo.Protect & PAGE_GUARD)
	{
		DebugOutput("ActivateGuardPages: guard page(s) already set in region 0x%x-0x%x", TrackedRegion->AllocationBase, (DWORD_PTR)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
		return FALSE;
	}

	if (!VirtualProtect(TrackedRegion->AllocationBase, TrackedRegion->RegionSize, TrackedRegion->Protect | PAGE_GUARD, &OldProtect))
	{
		ErrorOutput("ActivateGuardPages: failed to activate guard page(s) on region 0x%x size 0x%x", TrackedRegion->AllocationBase, TrackedRegion->RegionSize);
		return FALSE;
	}

	//DebugOutput("ActivateGuardPages: Activated guard page(s) on region 0x%x size 0x%x", TrackedRegion->AllocationBase, TrackedRegion->RegionSize);

	return TRUE;
}

//**************************************************************************************
BOOL ActivateGuardPagesOnProtectedRange(PTRACKEDREGION TrackedRegion)
//**************************************************************************************
{
	DWORD OldProtect;
	BOOL TrackedRegionFound = FALSE;
	PTRACKEDREGION CurrentTrackedRegion;
	DWORD_PTR AddressOfPage;
	SIZE_T Size;
	PVOID TestAddress;

	if (TrackedRegion == NULL)
	{
		DebugOutput("ActivateGuardPagesOnProtectedRange: NULL passed as argument - error.\n");
		return FALSE;
	}

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	if (!SystemInfo.dwPageSize)
	{
		ErrorOutput("ActivateGuardPagesOnProtectedRange: Failed to obtain system page size.\n");
		return 0;
	}

	if (TrackedRegionList == NULL)
	{
		DebugOutput("ActivateGuardPagesOnProtectedRange: Error - no tracked region list.\n");
		return FALSE;
	}

	CurrentTrackedRegion = TrackedRegionList;

	while (CurrentTrackedRegion)
	{
		//DebugOutput("TrackedRegion->AllocationBase 0x%x, CurrentTrackedRegion->AllocationBase 0x%x.\n", TrackedRegion->AllocationBase, CurrentTrackedRegion->AllocationBase);

		__try
		{
			TestAddress = CurrentTrackedRegion->AllocationBase;
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			ErrorOutput("ActivateGuardPagesOnProtectedRange: Exception trying to access AllocationBase from tracked region at 0x%x", CurrentTrackedRegion);
			return FALSE;
		}

		if (TrackedRegion->AllocationBase == CurrentTrackedRegion->AllocationBase)
			TrackedRegionFound = TRUE;

		CurrentTrackedRegion = CurrentTrackedRegion->NextTrackedRegion;
	}

	if (!TrackedRegionFound)
	{
		DebugOutput("ActivateGuardPagesOnProtectedRange: failed to locate tracked region(s) in tracked region list.\n");
		return FALSE;
	}

	if (!TrackedRegion->ProtectAddress || !TrackedRegion->RegionSize)
	{
		DebugOutput("ActivateGuardPagesOnProtectedRange: Protect address or size zero: 0x%x, 0x%x.\n", TrackedRegion->ProtectAddress, TrackedRegion->RegionSize);
		return FALSE;
	}

	if (!VirtualQuery(TrackedRegion->AllocationBase, &TrackedRegion->MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		ErrorOutput("ActivateGuardPagesOnProtectedRange: unable to query memory region 0x%x", TrackedRegion->AllocationBase);
		return FALSE;
	}

	AddressOfPage = ((DWORD_PTR)TrackedRegion->ProtectAddress/SystemInfo.dwPageSize)*SystemInfo.dwPageSize;

	Size = (BYTE*)TrackedRegion->ProtectAddress + TrackedRegion->RegionSize - (BYTE*)AddressOfPage;

	if (!VirtualProtect((PVOID)AddressOfPage, Size, TrackedRegion->Protect | PAGE_GUARD, &OldProtect))
	{
		ErrorOutput("ActivateGuardPagesOnProtectedRange: failed to activate guard page(s) on region 0x%x size 0x%x", AddressOfPage, Size);
		return FALSE;
	}

	return TRUE;
}

//**************************************************************************************
BOOL DeactivateGuardPages(PTRACKEDREGION TrackedRegion)
//**************************************************************************************
{
	DWORD OldProtect;
	SIZE_T MatchingRegionSize;
	BOOL TrackedRegionFound = FALSE;
	PTRACKEDREGION CurrentTrackedRegion = TrackedRegionList;
	PVOID TestAddress;

	if (TrackedRegion == NULL)
	{
		DebugOutput("DeactivateGuardPages: NULL passed as argument - error.\n");
		return FALSE;
	}

	if (TrackedRegionList == NULL)
	{
		DebugOutput("DeactivateGuardPages: Error - no tracked region list.\n");
		return FALSE;
	}

	//DebugOutput("DeactivateGuardPages: DEBUG - tracked region list 0x%x, BaseAddress 0x%x.\n", CurrentTrackedRegion, CurrentTrackedRegion->AllocationBase);

	while (CurrentTrackedRegion)
	{
		__try
		{
			TestAddress = CurrentTrackedRegion->AllocationBase;
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			ErrorOutput("DeactivateGuardPages: Exception trying to access BaseAddres from tracked region at 0x%x", CurrentTrackedRegion);
			return FALSE;
		}

		if (TrackedRegion->AllocationBase == CurrentTrackedRegion->AllocationBase)
			TrackedRegionFound = TRUE;

		CurrentTrackedRegion = CurrentTrackedRegion->NextTrackedRegion;
	}

	if (!TrackedRegionFound)
	{
		DebugOutput("DeactivateGuardPages: failed to locate tracked region(s) in tracked region list.\n");
		return FALSE;
	}

	MatchingRegionSize = VirtualQuery(TrackedRegion->AllocationBase, &TrackedRegion->MemInfo, sizeof(MEMORY_BASIC_INFORMATION));

	if (!MatchingRegionSize)
	{
		ErrorOutput("DeactivateGuardPages: failed to query tracked region(s) status in region 0x%x-0x%x", TrackedRegion->AllocationBase, (DWORD_PTR)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
		return FALSE;
	}

	if (MatchingRegionSize == TrackedRegion->RegionSize && !(TrackedRegion->MemInfo.Protect & PAGE_GUARD))
	{
		DebugOutput("DeactivateGuardPages: guard page(s) not set in region 0x%x-0x%x", TrackedRegion->AllocationBase, (DWORD_PTR)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
		return FALSE;
	}

	if (!VirtualProtect(TrackedRegion->AllocationBase, TrackedRegion->RegionSize, TrackedRegion->Protect, &OldProtect))
	{
		ErrorOutput("DeactivateGuardPages: failed to deactivate guard page(s) on region 0x%x-0x%x", TrackedRegion->AllocationBase, (DWORD_PTR)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
		return FALSE;
	}

	DebugOutput("DeactivateGuardPages: DEBUG: Deactivated guard page(s) on region 0x%x-0x%x", TrackedRegion->AllocationBase, (DWORD_PTR)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);

	return TRUE;
}

//**************************************************************************************
BOOL ActivateSurroundingGuardPages(PTRACKEDREGION TrackedRegion)
//**************************************************************************************
{
	DWORD OldProtect, RetVal;
	DWORD_PTR AddressOfPage, PagePointer;
	BOOL TrackedRegionFound = FALSE;
	PTRACKEDREGION CurrentTrackedRegion = TrackedRegionList;
	PVOID TestAddress;

	if (TrackedRegionList == NULL)
	{
		DebugOutput("ActivateSurroundingGuardPages: Error - TrackedRegionList NULL.\n");
		return 0;
	}

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	if (!SystemInfo.dwPageSize)
	{
		ErrorOutput("ActivateSurroundingGuardPages: Failed to obtain system page size.\n");
		return 0;
	}

	while (CurrentTrackedRegion)
	{
		__try
		{
			TestAddress = CurrentTrackedRegion->AllocationBase;
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			ErrorOutput("ActivateSurroundingGuardPages: Exception trying to access BaseAddres from tracked region at 0x%x", CurrentTrackedRegion);
			return FALSE;
		}

		if (TrackedRegion->AllocationBase == CurrentTrackedRegion->AllocationBase)
			TrackedRegionFound = TRUE;

		CurrentTrackedRegion = CurrentTrackedRegion->NextTrackedRegion;
	}

	if (!TrackedRegionFound)
	{
		DebugOutput("ActivateSurroundingGuardPages: Failed to locate tracked region(s) in tracked region list.\n");
		return FALSE;
	}

	if (!TrackedRegion->LastAccessAddress)
	{
		DebugOutput("ActivateSurroundingGuardPages: Error - Last access address not set.\n");
		return 0;
	}

	if ((DWORD_PTR)TrackedRegion->LastAccessAddress < (DWORD_PTR)TrackedRegion->AllocationBase || (DWORD_PTR)TrackedRegion->LastAccessAddress >= ((DWORD_PTR)TrackedRegion->AllocationBase + (DWORD_PTR)TrackedRegion->RegionSize))
	{
		DebugOutput("ActivateSurroundingGuardPages: Last access address 0x%x not within tracked region at 0x%x.\n", TrackedRegion->LastAccessAddress, TrackedRegion->AllocationBase);
		return FALSE;
	}

	AddressOfPage = ((DWORD_PTR)TrackedRegion->LastAccessAddress/SystemInfo.dwPageSize)*SystemInfo.dwPageSize;

	if (!VirtualQuery(TrackedRegion->AllocationBase, &TrackedRegion->MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		ErrorOutput("ActivateSurroundingGuardPages: unable to query memory region 0x%x", TrackedRegion->AllocationBase);
		return FALSE;
	}

	for
	(
		PagePointer = ((DWORD_PTR)TrackedRegion->AllocationBase/SystemInfo.dwPageSize)*SystemInfo.dwPageSize;
		(BYTE*)PagePointer + SystemInfo.dwPageSize < (BYTE*)TrackedRegion->AllocationBase + TrackedRegion->RegionSize;
		PagePointer += SystemInfo.dwPageSize
	)
	{
		// We skip the initial page if a switch to breakpoints has occurred
		if (PagePointer == (DWORD_PTR)TrackedRegion->AllocationBase && TrackedRegion->BreakpointsSet)
			PagePointer += SystemInfo.dwPageSize;

		if (PagePointer != AddressOfPage)
		{
			RetVal = VirtualProtect((PVOID)PagePointer, SystemInfo.dwPageSize, TrackedRegion->Protect | PAGE_GUARD, &OldProtect);

			if (!RetVal)
			{
				DebugOutput("ActivateSurroundingGuardPages: Failed to activate page guard on tracked region at 0x%x.\n", PagePointer);
				return FALSE;
			}
		}
	}

	return TRUE;
}

//**************************************************************************************
unsigned int DumpPEsInTrackedRegion(PTRACKEDREGION TrackedRegion)
//**************************************************************************************
{
	PTRACKEDREGION CurrentTrackedRegion;
	unsigned int PEsDumped;
	BOOL TrackedRegionFound = FALSE;
	PVOID BaseAddress;
	SIZE_T Size;

	if (TrackedRegion == NULL)
	{
		DebugOutput("DumpPEsInTrackedRegion: NULL passed as argument - error.\n");
		return FALSE;
	}

	if (TrackedRegionList == NULL)
	{
		DebugOutput("DumpPEsInTrackedRegion: Error - no tracked region list.\n");
		return FALSE;
	}

	CurrentTrackedRegion = TrackedRegionList;

	__try
	{
		while (CurrentTrackedRegion)
		{
			//DEBUG
			//DebugOutput("DumpPEsInTrackedRegion: Debug: CurrentTrackedRegion 0x%p.\n", CurrentTrackedRegion);
			if (CurrentTrackedRegion->AllocationBase == TrackedRegion->AllocationBase)
				TrackedRegionFound = TRUE;

			CurrentTrackedRegion = CurrentTrackedRegion->NextTrackedRegion;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		ErrorOutput("DumpPEsInTrackedRegion: Exception trying to access BaseAddress from tracked region at 0x%p", TrackedRegion);
		return FALSE;
	}

	if (TrackedRegionFound == FALSE)
	{
		DebugOutput("DumpPEsInTrackedRegion: failed to locate tracked region(s) in tracked region list.\n");
		return FALSE;
	}

	//DEBUG
	//DebugOutput("DumpPEsInTrackedRegion: Found tracked region at 0x%p.\n", CurrentTrackedRegion);

	__try
	{
		BaseAddress = TrackedRegion->AllocationBase;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		ErrorOutput("DumpPEsInTrackedRegion: Exception trying to access BaseAddress from tracked region at 0x%p", TrackedRegion);
		return FALSE;
	}

	//DEBUG
	//DebugOutput("DumpPEsInTrackedRegion: Debug: about to scan for PE image(s).\n");

	if (!VirtualQuery(TrackedRegion->AllocationBase, &TrackedRegion->MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		ErrorOutput("DumpPEsInTrackedRegion: unable to query memory region 0x%p", TrackedRegion->AllocationBase);
		return FALSE;
	}

	if ((DWORD_PTR)TrackedRegion->AllocationBase < (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase)
	{
		DebugOutput("DumpPEsInTrackedRegion: Anomaly detected - AllocationBase 0x%p below MemInfo.AllocationBase 0x%p.\n", TrackedRegion->AllocationBase, TrackedRegion->MemInfo.AllocationBase);
		return FALSE;
	}

	if ((BYTE*)TrackedRegion->AllocationBase + TrackedRegion->RegionSize > (BYTE*)TrackedRegion->MemInfo.AllocationBase && TrackedRegion->MemInfo.RegionSize)
	{
		Size = (BYTE*)TrackedRegion->AllocationBase + TrackedRegion->RegionSize - (BYTE*)TrackedRegion->MemInfo.AllocationBase;
	}
	else
	{
		Size = TrackedRegion->RegionSize;
	}

	if ((DWORD_PTR)TrackedRegion->MemInfo.AllocationBase < (DWORD_PTR)TrackedRegion->AllocationBase)
		BaseAddress = TrackedRegion->MemInfo.AllocationBase;
	else
		BaseAddress = TrackedRegion->AllocationBase;

	TrackedRegion->Entropy = GetEntropy(TrackedRegion->AllocationBase);
	CapeMetaData->Size = Size;
	SetCapeMetaData(UNPACKED_PE, 0, NULL, BaseAddress);
	PEsDumped = DumpPEsInRange(BaseAddress, Size);

	if (PEsDumped)
	{
		DebugOutput("DumpPEsInTrackedRegion: Dumped %d PE image(s) from range 0x%p - 0x%p.\n", PEsDumped, BaseAddress, (BYTE*)BaseAddress + Size);
		TrackedRegion->PagesDumped = TRUE;
	}
	else
		DebugOutput("DumpPEsInTrackedRegion: No PE images found in range range 0x%p - 0x%p.\n", BaseAddress, (BYTE*)BaseAddress + Size);

	return PEsDumped;
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

	EntryPoint = GetEntryPoint(TrackedRegion->AllocationBase);
	MinPESize = GetMinPESize(TrackedRegion->AllocationBase);
	Entropy = GetEntropy(TrackedRegion->AllocationBase);

	DebugOutput("ProcessImageBase: EP 0x%p image base 0x%p size 0x%x entropy %e.\n", EntryPoint, TrackedRegion->AllocationBase, MinPESize, Entropy);
	if (TrackedRegion->EntryPoint && (TrackedRegion->EntryPoint != EntryPoint))
		DebugOutput("ProcessImageBase: Modified entry point (0x%p) detected at image base 0x%p - dumping.\n", EntryPoint, TrackedRegion->AllocationBase);
	else if (TrackedRegion->MinPESize && TrackedRegion->MinPESize != MinPESize)
		DebugOutput("ProcessImageBase: Modified PE size detected at image base 0x%p - new size 0x%x.\n", TrackedRegion->AllocationBase, MinPESize);
	else if (TrackedRegion->Entropy && fabs(TrackedRegion->Entropy - Entropy) > (double)ENTROPY_DELTA)
		DebugOutput("ProcessImageBase: Modified image detected at image base 0x%p - new entropy %e.\n", TrackedRegion->AllocationBase, Entropy);
	else
		return;

	TrackedRegion->EntryPoint = EntryPoint;
	TrackedRegion->MinPESize = MinPESize;
	TrackedRegion->Entropy = Entropy;

	SetCapeMetaData(UNPACKED_PE, 0, NULL, TrackedRegion->AllocationBase);

	//DumpCurrentProcessFixImports((PVOID)TrackedRegion->EntryPoint);
	DumpImageInCurrentProcess(TrackedRegion->AllocationBase);
}

//**************************************************************************************
void ProcessTrackedRegion(PTRACKEDREGION TrackedRegion)
//**************************************************************************************
{
	if (!TrackedRegion)
		return;

	if (!TrackedRegion->CanDump && g_terminate_event_handle)
		return;

	if (!TrackedRegion->AllocationBase || !TrackedRegion->RegionSize)
		return;

	if (!ScanForNonZero(TrackedRegion->AllocationBase, TrackedRegion->RegionSize))
		return;

	if (TrackedRegion->PagesDumped && TrackedRegion->Entropy && (fabs(TrackedRegion->Entropy - GetEntropy(TrackedRegion->AllocationBase)) < (double)ENTROPY_DELTA))
		return;

	TrackedRegion->PagesDumped = DumpPEsInTrackedRegion(TrackedRegion);

	if (TrackedRegion->PagesDumped)
	{
		DebugOutput("ProcessTrackedRegion: Found and dumped PE image(s) in range 0x%p - 0x%p.\n", TrackedRegion->AllocationBase, (BYTE*)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
		ClearTrackedRegion(TrackedRegion);
	}
	else
	{
		SetCapeMetaData(UNPACKED_SHELLCODE, 0, NULL, TrackedRegion->AllocationBase);

		TrackedRegion->PagesDumped = DumpMemory(TrackedRegion->AllocationBase, TrackedRegion->RegionSize);

		if (TrackedRegion->PagesDumped)
		{
			DebugOutput("ProcessTrackedRegion: dumped executable memory range at 0x%p.\n", TrackedRegion->AllocationBase);
			ClearTrackedRegion(TrackedRegion);
		}
		else
			DebugOutput("ProcessTrackedRegion: failed to dump executable memory range at 0x%p.\n", TrackedRegion->AllocationBase);
	}
}

//**************************************************************************************
void ProcessTrackedRegions()
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion = TrackedRegionList;

	while (TrackedRegion)
	{
		DebugOutput("ProcessTrackedRegions: Processing region at 0x%p.\n", TrackedRegion->AllocationBase);
		if (TrackedRegion->AllocationBase == ImageBase)
			ProcessImageBase(TrackedRegion);
		else
			ProcessTrackedRegion(TrackedRegion);

		TrackedRegion = TrackedRegion->NextTrackedRegion;
	}
}

//**************************************************************************************
void AllocationHandler(PVOID BaseAddress, SIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;

	if (!DebuggerInitialised)
		return;

	if (!BaseAddress || !RegionSize)
	{
		DebugOutput("AllocationHandler: Error, BaseAddress or RegionSize zero: 0x%p, 0x%p.\n", BaseAddress, RegionSize);
		return;
	}

	// We limit tracking to executable regions
	if (!(Protect & EXECUTABLE_FLAGS))
		return;

	DebugOutput("Allocation: 0x%p - 0x%p, size: 0x%x, protection: 0x%x.\n", BaseAddress, (PUCHAR)BaseAddress + RegionSize, RegionSize, Protect);

	hook_disable();
	ProcessTrackedRegions();

	if (TrackedRegionList)
		TrackedRegion = GetTrackedRegion(BaseAddress);
	else
		TrackedRegion = NULL;

	// if memory was previously reserved but not committed
	if (TrackedRegion && !TrackedRegion->Committed && (AllocationType & MEM_COMMIT))
	{
		DebugOutput("AllocationHandler: Previously reserved region 0x%p - 0x%p, committing at: 0x%p.\n", TrackedRegion->AllocationBase, (PUCHAR)TrackedRegion->AllocationBase + TrackedRegion->RegionSize, BaseAddress);

		if (TrackedRegion->AllocationBase != BaseAddress)
			TrackedRegion->ProtectAddress = BaseAddress;
	}
	else if (TrackedRegion && (AllocationType & MEM_RESERVE))
	{
		DebugOutput("AllocationHandler: Re-reserving region at: 0x%p.\n", BaseAddress);
		hook_enable();
		return;
	}
	else if (TrackedRegion)
	{
		// The region allocated is with a region already tracked
		DebugOutput("AllocationHandler: New allocation already in tracked region list: 0x%p, size: 0x%x.\n", TrackedRegion->AllocationBase, TrackedRegion->RegionSize);
		hook_enable();
		return;
	}
	else
	{
		DebugOutput("AllocationHandler: Adding allocation to tracked region list: 0x%p, size: 0x%x.\n", BaseAddress, RegionSize);
		TrackedRegion = AddTrackedRegion(BaseAddress, RegionSize, Protect);
	}

	if (!TrackedRegion)
	{
		DebugOutput("AllocationHandler: Error, unable to locate or add allocation in tracked region list: 0x%p.\n", BaseAddress);
		hook_enable();
		return;
	}

	if (AllocationType & MEM_COMMIT)
	{
		// Allocation committed, we determine whether to guard pages
		TrackedRegion->Committed = TRUE;

		if (Protect & EXECUTABLE_FLAGS)
		{
			if (GuardPagesDisabled)
			{
				TrackedRegion->BreakpointsSet = ActivateBreakpoints(TrackedRegion, NULL);

				if (TrackedRegion->BreakpointsSet)
					DebugOutput("AllocationHandler: Breakpoints set on newly-allocated executable region at: 0x%p (size 0x%x).\n", BaseAddress, RegionSize);
				else
					DebugOutput("AllocationHandler: Error - unable to activate breakpoints around address 0x%p.\n", BaseAddress);
			}
			else
			{
				TrackedRegion->Guarded = ActivateGuardPages(TrackedRegion);
				//TrackedRegion->Guarded = ActivateGuardPagesOnProtectedRange(TrackedRegion);

				if (TrackedRegion->Guarded)
					DebugOutput("AllocationHandler: Guarded newly-allocated executable region at 0x%p, size 0x%x.\n", BaseAddress, RegionSize);
				else
					DebugOutput("AllocationHandler: Error - failed to guard newly allocated executable region at: 0x%p.\n", BaseAddress);

			}
		}
		else
			DebugOutput("AllocationHandler: Non-executable region at 0x%p tracked but not guarded.\n", BaseAddress);
	}
	else
	{   // Allocation not committed, so we can't set guard pages or breakpoints yet
		TrackedRegion->Committed = FALSE;
		TrackedRegion->Guarded = FALSE;
		DebugOutput("AllocationHandler: Memory reserved but not committed at 0x%p.\n", BaseAddress);
	}

	hook_enable();

	return;
}

//**************************************************************************************
void ProtectionHandler(PVOID Address, SIZE_T RegionSize, ULONG Protect, PULONG OldProtect)
//**************************************************************************************
{
	//DWORD EntryPoint;
	BOOL NewRegion = FALSE;
	SIZE_T TrackedRegionSize;
	PTRACKEDREGION TrackedRegion = NULL;

	if (!DebuggerInitialised)
		return;

	if (!Address || !RegionSize)
	{
		DebugOutput("ProtectionHandler: Error, Address or RegionSize zero: 0x%p, 0x%x.\n", Address, RegionSize);
		return;
	}

	if (!(Protect & EXECUTABLE_FLAGS))
		return;

	if (is_in_dll_range((ULONG_PTR)Address))
		return;

	hook_disable();

	if (TrackedRegionList)
		TrackedRegion = GetTrackedRegion(Address);

	//if (TrackedRegion && TrackedRegion->PagesDumped)
	//{
	//	DebugOutput("ProtectionHandler: Current tracked region has already been dumped.\n");
	//	hook_enable();
	//	return;
	//}

	// If a previously-untracked region already has code, we may want to dump
	if (!TrackedRegion)
	{
		ProcessTrackedRegions();
		DebugOutput("ProtectionHandler: Adding region at 0x%p to tracked regions.\n", Address);
		TrackedRegion = AddTrackedRegion(Address, RegionSize, Protect);
		NewRegion = TRUE;
	}
	else
	{
		DebugOutput("ProtectionHandler: Address 0x%p already in tracked region at 0x%p, size 0x%x\n", Address, TrackedRegion->AllocationBase, TrackedRegion->RegionSize);
		if (TrackedRegion->Guarded)
			*OldProtect &= (~PAGE_GUARD);
	}

	if (!TrackedRegion)
	{
		DebugOutput("ProtectionHandler: Error, unable to add new region at 0x%p to tracked region list.\n", Address);
		hook_enable();
		return;
	}

	if (!VirtualQuery(Address, &TrackedRegion->MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		ErrorOutput("ProtectionHandler: unable to query memory region 0x%p", Address);
		hook_enable();
		return;
	}

	TrackedRegion->AllocationBase = TrackedRegion->MemInfo.AllocationBase;
	DebugOutput("ProtectionHandler: Address: 0x%p (alloc base 0x%p), NumberOfBytesToProtect: 0x%x, NewAccessProtection: 0x%x\n", Address, TrackedRegion->AllocationBase, RegionSize, Protect);

	TrackedRegionSize = (SIZE_T)((PBYTE)Address + RegionSize - (PBYTE)TrackedRegion->AllocationBase);

	if (TrackedRegion->RegionSize < TrackedRegionSize)
	{
		TrackedRegion->RegionSize = TrackedRegionSize;
		DebugOutput("ProtectionHandler: Increased region size at 0x%p to 0x%x.\n", TrackedRegion->AllocationBase, TrackedRegionSize);
	}

	if (TrackedRegion->Protect != Protect)
	{
		TrackedRegion->Protect = Protect;
		DebugOutput("ProtectionHandler: Updated region protection at 0x%p to 0x%x.\n", TrackedRegion->AllocationBase, Protect);
	}

	if (TrackedRegion->AllocationBase == ImageBase || TrackedRegion->AllocationBase == GetModuleHandle(NULL))
	{
		ProcessImageBase(TrackedRegion);
		hook_enable();
		return;
	}

	//if (ScanForNonZero(Address, RegionSize))
	if (!TrackedRegion->PagesDumped && (NewRegion || *OldProtect & WRITABLE_FLAGS) && ScanForNonZero(Address, RegionSize))
	{
		DebugOutput("ProtectionHandler: New code detected at (0x%p), scanning for PE images.\n", TrackedRegion->AllocationBase);

		SetCapeMetaData(UNPACKED_PE, 0, NULL, TrackedRegion->AllocationBase);
		TrackedRegion->PagesDumped = DumpPEsInTrackedRegion(TrackedRegion);

		if (TrackedRegion->PagesDumped)
		{
			DebugOutput("ProtectionHandler: PE image(s) dumped from 0x%p.\n", TrackedRegion->AllocationBase);
			ClearTrackedRegion(TrackedRegion);
			hook_enable();
			return;
		}
#ifdef DEBUG_COMMENTS
		else
			DebugOutput("ProtectionHandler: No PE images found in region at 0x%p, size 0x%x\n", TrackedRegion->AllocationBase, TrackedRegion->RegionSize);
#endif
		if (!(Protect & WRITABLE_FLAGS))
		{
			SetCapeMetaData(UNPACKED_SHELLCODE, 0, NULL, Address);
			if (DumpMemory(TrackedRegion->AllocationBase, TrackedRegion->RegionSize))
			{
				DebugOutput("ProtectionHandler: dumped memory (sub)region at 0x%p, size 0x%x\n", TrackedRegion->AllocationBase, TrackedRegion->RegionSize);
				hook_enable();
				return;
			}
			else
				DebugOutput("ProtectionHandler: Failed to dump range at 0x%p, size 0x%x\n", TrackedRegion->AllocationBase, TrackedRegion->RegionSize);
		}
		else
			DebugOutput("ProtectionHandler: Skipped range at 0x%p (size 0x%x) due to protection-write-enabled.\n", TrackedRegion->AllocationBase, TrackedRegion->RegionSize);
	}
#ifdef DEBUG_COMMENTS
	else
		DebugOutput("ProtectionHandler: No action taken on empty protected region at 0x%p.\n", Address);
#endif

	TrackedRegion->ProtectAddress = Address;

	if (GuardPagesDisabled)
	{
		TrackedRegion->BreakpointsSet = ActivateBreakpoints(TrackedRegion, NULL);

		if (TrackedRegion->BreakpointsSet)
			DebugOutput("ProtectionHandler: Breakpoints set on executable region at: 0x%p.\n", Address);
		else
			DebugOutput("ProtectionHandler: Error - unable to activate breakpoints around address 0x%p.\n", Address);
	}
	else
	{
		TrackedRegion->Guarded = ActivateGuardPages(TrackedRegion);
		//TrackedRegion->Guarded = ActivateGuardPagesOnProtectedRange(TrackedRegion);

		if (TrackedRegion->Guarded)
			DebugOutput("ProtectionHandler: Guarded executable region at: 0x%p.\n", Address);
		else
			DebugOutput("ProtectionHandler: Error - unable to activate guard pages around address 0x%p.\n", Address);
	}

	hook_enable();

	return;
}

//**************************************************************************************
void FreeHandler(PVOID BaseAddress)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;

	if (!BaseAddress)
	{
		DebugOutput("FreeHandler: Error, BaseAddress zero.\n");
		return;
	}

	TrackedRegion = GetTrackedRegion(BaseAddress);

	if (TrackedRegion == NULL)
		return;

	DebugOutput("FreeHandler: Address: 0x%p.\n", BaseAddress);

	hook_disable();

	if (TrackedRegion->Committed == TRUE && ScanForNonZero(TrackedRegion->AllocationBase, TrackedRegion->RegionSize) && !TrackedRegion->PagesDumped)
	{
		TrackedRegion->PagesDumped = DumpPEsInTrackedRegion(TrackedRegion);

		if (TrackedRegion->PagesDumped)
			DebugOutput("FreeHandler: Found and dumped PE image(s) in range 0x%p - 0x%p.\n", TrackedRegion->AllocationBase, (BYTE*)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
		else if (TrackedRegion->Protect & EXECUTABLE_FLAGS)
		{
			SetCapeMetaData(UNPACKED_SHELLCODE, 0, NULL, TrackedRegion->AllocationBase);

			TrackedRegion->Entropy = GetEntropy(TrackedRegion->AllocationBase);

			TrackedRegion->PagesDumped = DumpMemory(TrackedRegion->AllocationBase, TrackedRegion->RegionSize);

			if (TrackedRegion->PagesDumped)
				DebugOutput("FreeHandler: dumped executable memory range at 0x%p prior to its freeing.\n", TrackedRegion->AllocationBase);
			else
				DebugOutput("FreeHandler: failed to dump executable memory range at 0x%p prior to its freeing.\n", TrackedRegion->AllocationBase);
		}
	}

	ClearTrackedRegion(TrackedRegion);

	DropTrackedRegion(TrackedRegion);

	hook_enable();

	return;
}

//**************************************************************************************
void ModloadHandler(HMODULE BaseAddress)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;

	if (!BaseAddress)
	{
		DebugOutput("ModloadHandler: Error, BaseAddress zero.\n");
		return;
	}

	TrackedRegion = GetTrackedRegion((PVOID)BaseAddress);

	if (TrackedRegion == NULL)
		return;

	DebugOutput("ModloadHandler: Address: 0x%p.\n", BaseAddress);

	hook_disable();

	if (ScanForNonZero(TrackedRegion->AllocationBase, TrackedRegion->RegionSize) && !TrackedRegion->PagesDumped)
	{
		TrackedRegion->PagesDumped = DumpPEsInTrackedRegion(TrackedRegion);

		if (TrackedRegion->PagesDumped)
			DebugOutput("ModloadHandler: Dumped module at 0x%p.\n", TrackedRegion->AllocationBase);
		else
			DebugOutput("ModloadHandler: failed to dump executable memory range at 0x%p prior to its freeing.\n", TrackedRegion->AllocationBase);
	}

	ClearTrackedRegion(TrackedRegion);

	hook_enable();

	return;
}

//**************************************************************************************
void NewThreadHandler(PVOID StartAddress)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;

	if (!StartAddress)
	{
		DebugOutput("NewThreadHandler: Error, StartAddress zero.\n");
		return;
	}

	TrackedRegion = GetTrackedRegion((PVOID)StartAddress);

	if (TrackedRegion == NULL)
		return;

	DebugOutput("NewThreadHandler: Address: 0x%p.\n", StartAddress);

	hook_disable();

	if (ScanForNonZero(TrackedRegion->AllocationBase, TrackedRegion->RegionSize) && !TrackedRegion->PagesDumped)
	{
		TrackedRegion->PagesDumped = DumpPEsInTrackedRegion(TrackedRegion);

		if (TrackedRegion->PagesDumped)
			DebugOutput("NewThreadHandler: Dumped module at 0x%p.\n", TrackedRegion->AllocationBase);
		else
			DebugOutput("NewThreadHandler: Failed to dump new thread's executable memory range at 0x%p .\n", TrackedRegion->AllocationBase);
	}

	ClearTrackedRegion(TrackedRegion);

	hook_enable();

	return;
}

//**************************************************************************************
BOOL StepOverGuardPageFault(struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion = GuardedPagesToStep;
	DWORD_PTR LastAccessPage, ProtectAddressPage;

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	if (!SystemInfo.dwPageSize)
	{
		ErrorOutput("StepOverGuardPageFault: Failed to obtain system page size.\n");
		return FALSE;
	}

	if (LastEIP)
	{
#ifdef _WIN64
		CurrentEIP = ExceptionInfo->ContextRecord->Rip;
#else
		CurrentEIP = ExceptionInfo->ContextRecord->Eip;
#endif

		if (CurrentEIP == LastEIP)
		{
			// We want to keep stepping until we're past the instruction
			SetSingleStepMode(ExceptionInfo->ContextRecord, StepOverGuardPageFault);
			return TRUE;
		}
		else
		{
			if (TrackedRegion == NULL)
			{
				DebugOutput("StepOverGuardPageFault error: GuardedPagesToStep not set.\n");
				return FALSE;
			}

			LastAccessPage = ((DWORD_PTR)TrackedRegion->LastAccessAddress/SystemInfo.dwPageSize)*SystemInfo.dwPageSize;
			ProtectAddressPage = ((DWORD_PTR)TrackedRegion->ProtectAddress/SystemInfo.dwPageSize)*SystemInfo.dwPageSize;

			//DebugOutput("StepOverGuardPageFault: DEBUG Base 0x%p LastAccess 0x%p by 0x%p (LW 0x%p LR 0x%p).\n", TrackedRegion->AllocationBase, TrackedRegion->LastAccessAddress, TrackedRegion->LastAccessBy, TrackedRegion->LastWriteAddress, TrackedRegion->LastReadAddress);

			if ((DWORD_PTR)TrackedRegion->LastAccessAddress >= (DWORD_PTR)TrackedRegion->AllocationBase
				&& ((DWORD_PTR)TrackedRegion->LastAccessAddress < ((DWORD_PTR)TrackedRegion->AllocationBase + SystemInfo.dwPageSize)))
			//  - this page is the first & contains any possible pe header
			{

				if (TrackedRegion->ProtectAddress && TrackedRegion->ProtectAddress > TrackedRegion->AllocationBase)
				{
					if (TrackedRegion->LastAccessAddress == TrackedRegion->LastWriteAddress && TrackedRegion->LastAccessAddress > TrackedRegion->ProtectAddress)
						TrackedRegion->WriteCounter++;
				}
				else if (TrackedRegion->LastAccessAddress == TrackedRegion->LastWriteAddress && TrackedRegion->LastAccessAddress > TrackedRegion->AllocationBase)
					TrackedRegion->WriteCounter++;

				if (TrackedRegion->WriteCounter > SystemInfo.dwPageSize)
				{
					if (TrackedRegion->BreakpointsSet)
					{
						DebugOutput("StepOverGuardPageFault: Anomaly detected - switched to breakpoints for initial page, but guard pages still being hit.\n");

						//DebugOutput("StepOverGuardPageFault: Debug: Last write at 0x%p by 0x%p, last read at 0x%p by 0x%p.\n", TrackedRegion->LastWriteAddress, TrackedRegion->LastWrittenBy, TrackedRegion->LastReadAddress, TrackedRegion->LastReadBy);

						return FALSE;
					}

					DebugOutput("StepOverGuardPageFault: Write counter hit limit, switching to breakpoints.\n");

					if (ActivateBreakpoints(TrackedRegion, ExceptionInfo))
					{
						//DebugOutput("StepOverGuardPageFault: Switched to breakpoints on first tracked region.\n");

						//DebugOutput("StepOverGuardPageFault: Debug: Last write at 0x%p by 0x%p, last read at 0x%p by 0x%p.\n", TrackedRegion->LastWriteAddress, TrackedRegion->LastWrittenBy, TrackedRegion->LastReadAddress, TrackedRegion->LastReadBy);

						TrackedRegion->BreakpointsSet = TRUE;
						GuardedPagesToStep = NULL;
						LastEIP = (DWORD_PTR)NULL;
						CurrentEIP = (DWORD_PTR)NULL;
						return TRUE;
					}
					else
					{
						DebugOutput("StepOverGuardPageFault: Failed to set breakpoints on first tracked region.\n");
						return FALSE;
					}
				}
				else if (ActivateGuardPages(TrackedRegion))
				{
					//DebugOutput("StepOverGuardPageFault: 0x%p - Reactivated page guard on first tracked region.\n", TrackedRegion->LastAccessAddress);

					GuardedPagesToStep = NULL;
					LastEIP = (DWORD_PTR)NULL;
					CurrentEIP = (DWORD_PTR)NULL;
					return TRUE;
				}
				else
				{
					DebugOutput("StepOverGuardPageFault: Failed to activate page guard on first tracked region.\n");
					return FALSE;
				}
			}
			else if (LastAccessPage == ProtectAddressPage)
			{
				if (ActivateGuardPages(TrackedRegion))
				{
					//DebugOutput("StepOverGuardPageFault: 0x%p - Reactivated page guard on page containing protect address.\n", TrackedRegion->LastAccessAddress);
					GuardedPagesToStep = NULL;
					LastEIP = (DWORD_PTR)NULL;
					CurrentEIP = (DWORD_PTR)NULL;
					return TRUE;
				}
				else
				{
					DebugOutput("StepOverGuardPageFault: Failed to activate page guard on page containing protect address.\n");
					return FALSE;
				}
			}
			else
			{
				if (ActivateSurroundingGuardPages(TrackedRegion))
				{
					//DebugOutput("StepOverGuardPageFault: 0x%p - Reactivated page guard on surrounding pages.\n", TrackedRegion->LastAccessAddress);
					GuardedPagesToStep = NULL;
					LastEIP = (DWORD_PTR)NULL;
					CurrentEIP = (DWORD_PTR)NULL;
					return TRUE;
				}
				else
				{
					DebugOutput("StepOverGuardPageFault: Failed to activate page guard on surrounding pages.\n");
					return FALSE;
				}
			}

			DebugOutput("StepOverGuardPageFault: Failed to activate page guards.\n");
			return FALSE;
		}
	}
	else
	{
#ifdef _WIN64
		LastEIP = ExceptionInfo->ContextRecord->Rip;
#else
		LastEIP = ExceptionInfo->ContextRecord->Eip;
#endif

		if (TrackedRegion == NULL)
		{
			DebugOutput("StepOverGuardPageFault error: GuardedPagesToStep not set.\n");
			return FALSE;
		}


		SetSingleStepMode(ExceptionInfo->ContextRecord, StepOverGuardPageFault);
		return TRUE;
	}
}

//**************************************************************************************
BOOL UnpackerGuardPageHandler(struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	DWORD AccessType		= (DWORD)ExceptionInfo->ExceptionRecord->ExceptionInformation[0];
	PVOID AccessAddress	 = (PVOID)ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
	PVOID FaultingAddress   = (PVOID)ExceptionInfo->ExceptionRecord->ExceptionAddress;

	PTRACKEDREGION TrackedRegion = GetTrackedRegion(AccessAddress);

	if (TrackedRegion == NULL)
	{
		DebugOutput("UnpackerGuardPageHandler error: address 0x%p not in tracked regions.\n", AccessAddress);
		return FALSE;
	}

	// add check of whether pages *should* be guarded
	// i.e. internal consistency

	switch (AccessType)
	{
		case EXCEPTION_WRITE_FAULT:

			//DebugOutput("UnpackerGuardPageHandler: Write detected at 0x%p by 0x%p\n", AccessAddress, FaultingAddress);

			TrackedRegion->LastAccessAddress = AccessAddress;

			TrackedRegion->LastAccessBy = FaultingAddress;

			TrackedRegion->WriteDetected = TRUE;

			TrackedRegion->LastWriteAddress = AccessAddress;

			TrackedRegion->LastWrittenBy = FaultingAddress;

			GuardedPagesToStep = TrackedRegion;

			SetSingleStepMode(ExceptionInfo->ContextRecord, StepOverGuardPageFault);

			break;

		case EXCEPTION_READ_FAULT:

			TrackedRegion->LastAccessAddress = AccessAddress;

			TrackedRegion->LastAccessBy = FaultingAddress;

			TrackedRegion->ReadDetected = TRUE;

			TrackedRegion->LastReadAddress = AccessAddress;

			TrackedRegion->LastReadBy = FaultingAddress;

			GuardedPagesToStep = TrackedRegion;

			SetSingleStepMode(ExceptionInfo->ContextRecord, StepOverGuardPageFault);

			break;

		case EXCEPTION_EXECUTE_FAULT:

			DebugOutput("UnpackerGuardPageHandler: Execution detected at 0x%p\n", AccessAddress);

			if (AccessAddress != FaultingAddress)
			{
				DebugOutput("UnpackerGuardPageHandler: Anomaly detected - AccessAddress != FaultingAddress (0x%p, 0x%p).\n", AccessAddress, FaultingAddress);
			}

			TrackedRegion->LastAccessAddress = AccessAddress;

			if (!(TrackedRegion->Protect & EXECUTABLE_FLAGS))
			{
				DebugOutput("UnpackerGuardPageHandler: Anomaly detected - pages not marked with execute flag in tracked region list.\n");
			}

			if (!TrackedRegion->PagesDumped)
			{
				DebugOutput("UnpackerGuardPageHandler: Execution within guarded page detected, dumping.\n");

				if (!GuardPagesDisabled && DeactivateGuardPages(TrackedRegion))
				{
					if (DumpPEsInTrackedRegion(TrackedRegion))
						TrackedRegion->PagesDumped = TRUE;

					if (TrackedRegion->PagesDumped)
						DebugOutput("UnpackerGuardPageHandler: PE image(s) detected and dumped.\n");
					else
					{
						SetCapeMetaData(UNPACKED_SHELLCODE, 0, NULL, TrackedRegion->AllocationBase);

						TrackedRegion->Entropy = GetEntropy(TrackedRegion->AllocationBase);

						TrackedRegion->PagesDumped = DumpMemory(TrackedRegion->AllocationBase, TrackedRegion->RegionSize);

						if (TrackedRegion->PagesDumped)
							DebugOutput("UnpackerGuardPageHandler: shellcode detected and dumped from range 0x%p - 0x%p.\n", TrackedRegion->AllocationBase, (BYTE*)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
						else
							DebugOutput("UnpackerGuardPageHandler: failed to dump detected shellcode from range 0x%p - 0x%p.\n", TrackedRegion->AllocationBase, (BYTE*)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
					}

					ClearTrackedRegion(TrackedRegion);
				}
				else
					DebugOutput("UnpackerGuardPageHandler: Failed to disable guard pages for dump.\n");
			}

			break;

		default:
			DebugOutput("UnpackerGuardPageHandler: Unknown access type: 0x%x - error.\n", AccessType);
			return FALSE;
	}

	return TRUE;
}

//**************************************************************************************
void UnpackerCallback(hook_info_t *hookinfo)
//**************************************************************************************
{
	if (hookinfo == NULL)
	{
		DebugOutput("UnpackerCallback: Error, no hook info supplied.\n");
		return;
	}

	if (TrackedRegionList == NULL)
		return;

	if (!hookinfo->main_caller_retaddr && !hookinfo->parent_caller_retaddr)
		return;

	if (TrackedRegionFromHook && TrackedRegionFromHook->PagesDumped)
		TrackedRegionFromHook = NULL;

	if (TrackedRegionFromHook && ((hookinfo->main_caller_retaddr && IsInTrackedRegion(TrackedRegionFromHook, (PVOID)hookinfo->main_caller_retaddr)) ||
		(hookinfo->parent_caller_retaddr && IsInTrackedRegion(TrackedRegionFromHook, (PVOID)hookinfo->parent_caller_retaddr))))
	{
		DebugOutput("UnpackerCallback: hooked call to %ws::%s from within tracked region (from hook) at 0x%p.\n", hookinfo->current_hook->library, hookinfo->current_hook->funcname, hookinfo->main_caller_retaddr);
		TrackedRegionFromHook->CanDump = TRUE;
		ProcessTrackedRegion(TrackedRegionFromHook);
	}
	else if (hookinfo->main_caller_retaddr && IsInTrackedRegions((PVOID)hookinfo->main_caller_retaddr))
		ProcessTrackedRegion(GetTrackedRegion((PVOID)hookinfo->main_caller_retaddr));
	else if (hookinfo->parent_caller_retaddr && IsInTrackedRegions((PVOID)hookinfo->parent_caller_retaddr))
		ProcessTrackedRegion(GetTrackedRegion((PVOID)hookinfo->parent_caller_retaddr));

	return;
}

//**************************************************************************************
BOOL HookReturnCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;

	if (pBreakpointInfo == NULL)
	{
		DebugOutput("HookReturnCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DebugOutput("HookReturnCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	TrackedRegion = TrackedRegionFromHook;
	TrackedRegionFromHook = NULL;

	if (TrackedRegion == NULL)
	{
		DebugOutput("HookReturnCallback: no TrackedRegionFromHook (breakpoint %i at Address 0x%p).\n", pBreakpointInfo->Register, pBreakpointInfo->Address);
		return FALSE;
	}

	DebugOutput("HookReturnCallback: Breakpoint %i at Address 0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

	SetCapeMetaData(UNPACKED_PE, 0, NULL, TrackedRegion->AllocationBase);

	if (DumpPEsInTrackedRegion(TrackedRegion))
	{
		TrackedRegion->PagesDumped = TRUE;
		DebugOutput("HookReturnCallback: successfully dumped module.\n");
		ContextClearTrackedRegion(ExceptionInfo->ContextRecord, TrackedRegion);
		return TRUE;
	}
	else
	{
		DebugOutput("HookReturnCallback: failed to dump PE module.\n");
		return FALSE;
	}
}

//**************************************************************************************
BOOL OverlayWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;
	PVOID ReturnAddress;

	if (pBreakpointInfo == NULL)
	{
		DebugOutput("OverlayWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DebugOutput("OverlayWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);

	if (TrackedRegion == NULL)
	{
		DebugOutput("OverlayWriteCallback: unable to locate entry point address 0x%p in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	}

	TrackedRegion->EntryPoint = 0;

	DebugOutput("OverlayWriteCallback: Breakpoint %i at Address 0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

	if (!(DWORD*)pBreakpointInfo->Address)
	{
		DebugOutput("OverlayWriteCallback: Zero written, ignoring, leaving breakpoint in place.\n", pBreakpointInfo->Address);
		return TRUE;
	}

	ReturnAddress = GetReturnAddress(hook_info());

	if (ReturnAddress && !TrackedRegionFromHook)
	{
		if (InsideMonitor(NULL, ReturnAddress))
		{
			DebugOutput("OverlayWriteCallback: We are in a hooked function with return address 0x%p.\n", ReturnAddress);
			if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, 0, ReturnAddress, BP_EXEC, 0, HookReturnCallback))
			{
				DebugOutput("OverlayWriteCallback: set exec bp on return address 0x%p.\n", ReturnAddress);
				TrackedRegionFromHook = TrackedRegion;
			}
			else
			{
				DebugOutput("OverlayWriteCallback: Failed to set bp on return address 0x%p.\n", ReturnAddress);
			}
		}
		else
		{
			DebugOutput("OverlayWriteCallback: Not in a hooked function, setting callback in enter_hook() to catch next hook (return address 0x%p).\n", ReturnAddress);
			TrackedRegionFromHook = TrackedRegion;
		}
	}

	return TRUE;
}

//**************************************************************************************
BOOL FinalByteWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;
	PVOID ReturnAddress;

	if (pBreakpointInfo == NULL)
	{
		DebugOutput("FinalByteWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DebugOutput("FinalByteWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);

	if (TrackedRegion == NULL)
	{
		DebugOutput("FinalByteWriteCallback: unable to locate entry point address 0x%p in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	}

	TrackedRegion->EntryPoint = 0;

	DebugOutput("FinalByteWriteCallback: Breakpoint %i at Address 0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

	SetCapeMetaData(UNPACKED_PE, 0, NULL, TrackedRegion->AllocationBase);

	if (DumpPEsInTrackedRegion(TrackedRegion))
	{
		TrackedRegion->PagesDumped = TRUE;
		DebugOutput("FinalByteWriteCallback: successfully dumped module.\n");
		ContextClearTrackedRegion(ExceptionInfo->ContextRecord, TrackedRegion);
		return TRUE;
	}
	else
		DebugOutput("FinalByteWriteCallback: failed to dump PE module.\n");

	ReturnAddress = GetReturnAddress(hook_info());

	if (ReturnAddress && !TrackedRegionFromHook)
	{
		if (InsideMonitor(NULL, ReturnAddress))
		{
			DebugOutput("FinalByteWriteCallback: We are in a hooked function with return address 0x%p.\n", ReturnAddress);
			if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, 0, ReturnAddress, BP_EXEC, 0, HookReturnCallback))
			{
				DebugOutput("FinalByteWriteCallback: set exec bp on return address 0x%p.\n", ReturnAddress);
				TrackedRegionFromHook = TrackedRegion;
			}
			else
			{
				DebugOutput("FinalByteWriteCallback: Failed to set bp on return address 0x%p.\n", ReturnAddress);
			}
		}
		else
		{
			DebugOutput("FinalByteWriteCallback: Not in a hooked function, setting callback in enter_hook() to catch next hook (return address 0x%p).\n", ReturnAddress);
			TrackedRegionFromHook = TrackedRegion;
		}
	}

	return TRUE;
}

//**************************************************************************************
BOOL FinalSectionHeaderWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;
	DWORD VirtualSize;
	PIMAGE_SECTION_HEADER FinalSectionHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	PVOID FinalByteAddress;

	if (pBreakpointInfo == NULL)
	{
		DebugOutput("FinalSectionHeaderWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DebugOutput("FinalSectionHeaderWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);

	if (TrackedRegion == NULL)
	{
		DebugOutput("FinalSectionHeaderWriteCallback: unable to locate entry point address 0x%p in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	}

	TrackedRegion->EntryPoint = 0;

	DebugOutput("FinalSectionHeaderWriteCallback: Breakpoint %i at Address 0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

	TrackedRegion->CanDump = TRUE;

	FinalSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD*)pBreakpointInfo->Address - 4);

	if (!FinalSectionHeader->VirtualAddress || !FinalSectionHeader->SizeOfRawData)
	{
		DebugOutput("FinalSectionHeaderWriteCallback: current VirtualAddress and FinalSectionHeader->SizeOfRawData not valid: 0x%x, 0x%x (at 0x%p, 0x%p).\n", FinalSectionHeader->VirtualAddress, FinalSectionHeader->SizeOfRawData, (DWORD*)pBreakpointInfo->Address - 1, pBreakpointInfo->Address);
		return TRUE;
	}
	else
		DebugOutput("FinalSectionHeaderWriteCallback: Section %s VirtualAddress: 0x%x, FinalSectionHeader->Misc.VirtualSize: 0x%x, FinalSectionHeader->SizeOfRawData: 0x%x.\n", FinalSectionHeader->Name, FinalSectionHeader->VirtualAddress, FinalSectionHeader->Misc.VirtualSize, FinalSectionHeader->SizeOfRawData);

	FinalByteAddress = (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData - 1;

	if (!ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(BYTE), FinalByteAddress, BP_WRITE, 0, FinalByteWriteCallback))
	{
		DebugOutput("FinalSectionHeaderWriteCallback: write bp set on final byte at 0x%p.\n", FinalByteAddress);
	}

	pNtHeader = GetNtHeaders(TrackedRegion->AllocationBase);

	if (FinalSectionHeader->Misc.VirtualSize && FinalSectionHeader->Misc.VirtualSize > FinalSectionHeader->SizeOfRawData)
		VirtualSize = FinalSectionHeader->SizeOfRawData;
	else
		VirtualSize = ((FinalSectionHeader->SizeOfRawData / pNtHeader->OptionalHeader.SectionAlignment) + 1) * pNtHeader->OptionalHeader.SectionAlignment;

	if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, NULL, sizeof(DWORD), (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + VirtualSize, BP_WRITE, 0, OverlayWriteCallback))
		DebugOutput("FinalSectionHeaderWriteCallback: Set write breakpoint on first byte of overlay at: 0x%p\n", (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + VirtualSize);
	else
		DebugOutput("FinalSectionHeaderWriteCallback: Unable to set overlay breakpoint.\n");

	return TRUE;
}

//**************************************************************************************
BOOL EntryPointExecCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;

	if (pBreakpointInfo == NULL)
	{
		DebugOutput("EntryPointExecCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DebugOutput("EntryPointExecCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);

	if (TrackedRegion == NULL)
	{
		DebugOutput("EntryPointExecCallback: unable to locate entry point address 0x%p in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	}

	DebugOutput("EntryPointExecCallback: Breakpoint %i at Address 0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

	ContextClearTrackedRegion(ExceptionInfo->ContextRecord, TrackedRegion);

	SetCapeMetaData(UNPACKED_PE, 0, NULL, TrackedRegion->AllocationBase);

	if (DumpPEsInTrackedRegion(TrackedRegion))
	{
		TrackedRegion->PagesDumped = TRUE;
		DebugOutput("EntryPointExecCallback: successfully dumped module.\n");
		return TRUE;
	}
	else
	{
		DebugOutput("EntryPointExecCallback: failed to dump PE module.\n");
		return FALSE;
	}
}

//**************************************************************************************
BOOL EntryPointWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;
	DWORD SizeOfHeaders;
	PIMAGE_DOS_HEADER pDosHeader;
#ifdef _WIN64
	PIMAGE_NT_HEADERS64 pNtHeader;
#else
	PIMAGE_NT_HEADERS32 pNtHeader;
#endif

	if (pBreakpointInfo == NULL)
	{
		DebugOutput("EntryPointWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DebugOutput("EntryPointWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);

	if (TrackedRegion == NULL)
	{
		DebugOutput("EntryPointWriteCallback: unable to locate entry point address 0x%p in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	}

	TrackedRegion->EntryPoint = 0;

	DebugOutput("EntryPointWriteCallback: Breakpoint %i at Address 0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

	if ((DWORD_PTR)pBreakpointInfo->Address < (DWORD_PTR)TrackedRegion->AllocationBase || (DWORD_PTR)pBreakpointInfo->Address > (DWORD_PTR)TrackedRegion->AllocationBase + TrackedRegion->RegionSize)
	{
		DebugOutput("EntryPointWriteCallback: current AddressOfEntryPoint is not within allocated region. We assume it's only partially written and await further writes.\n");
		return TRUE;
	}

	if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, TrackedRegion->ExecBpRegister, 0, pBreakpointInfo->Address, BP_EXEC, 0, EntryPointExecCallback))
	{
		DebugOutput("EntryPointWriteCallback: ContextSetNextAvailableBreakpoint on EntryPoint 0x%p failed\n", (BYTE*)TrackedRegion->AllocationBase+*(DWORD*)(pBreakpointInfo->Address));
		return FALSE;
	}

	DebugOutput("EntryPointWriteCallback: Execution bp %d set on EntryPoint address 0x%p.\n", TrackedRegion->ExecBpRegister, pBreakpointInfo->Address);

	pDosHeader = (PIMAGE_DOS_HEADER)TrackedRegion->AllocationBase;

	if (!pDosHeader->e_lfanew)
	{
		DebugOutput("EntryPointWriteCallback: pointer to PE header zero.\n");
		return FALSE;
	}

	if ((ULONG)pDosHeader->e_lfanew > PE_HEADER_LIMIT)
	{
		DebugOutput("EntryPointWriteCallback: pointer to PE header too big: 0x%p.\n", pDosHeader->e_lfanew);
		return FALSE;
	}

	pNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)TrackedRegion->AllocationBase + pDosHeader->e_lfanew);

	SizeOfHeaders = pDosHeader->e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + pNtHeader->FileHeader.SizeOfOptionalHeader;

	if (pNtHeader->FileHeader.NumberOfSections && pNtHeader->FileHeader.SizeOfOptionalHeader && pNtHeader->OptionalHeader.SizeOfImage)
	{
		PIMAGE_SECTION_HEADER FinalSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)TrackedRegion->AllocationBase + SizeOfHeaders + (sizeof(IMAGE_SECTION_HEADER) * (pNtHeader->FileHeader.NumberOfSections - 1)));

		DebugOutput("EntryPointWriteCallback: DEBUG: NumberOfSections %d, SizeOfHeaders 0x%x.\n", pNtHeader->FileHeader.NumberOfSections, SizeOfHeaders);

		if (FinalSectionHeader->VirtualAddress && FinalSectionHeader->SizeOfRawData && (FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData <= pNtHeader->OptionalHeader.SizeOfImage))
		{
			PVOID FinalByteAddress = (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData - 1;

			if (!ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(BYTE), FinalByteAddress, BP_WRITE, 0, FinalByteWriteCallback))
			{
				DebugOutput("EntryPointWriteCallback: ContextUpdateCurrentBreakpoint failed to set write bp on final section, (address: 0x%p).\n", FinalByteAddress);
				return FALSE;
			}

			DebugOutput("EntryPointWriteCallback: Set write breakpoint on final section, last byte at 0x%p\n", FinalByteAddress);
		}
	}

	return TRUE;
}

//**************************************************************************************
BOOL AddressOfEPWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;
	PIMAGE_DOS_HEADER pDosHeader;
#ifdef _WIN64
	PIMAGE_NT_HEADERS64 pNtHeader;
#else
	PIMAGE_NT_HEADERS32 pNtHeader;
#endif
	PVOID ReturnAddress;
	DWORD SizeOfHeaders, VirtualSize;
	unsigned int Register;

	if (pBreakpointInfo == NULL)
	{
		DebugOutput("AddressOfEPWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DebugOutput("AddressOfEPWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);

	if (TrackedRegion == NULL)
	{
		DebugOutput("AddressOfEPWriteCallback: unable to locate entry point address 0x%p in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	}

	TrackedRegion->EntryPoint = 0;

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	pDosHeader = (PIMAGE_DOS_HEADER)TrackedRegion->AllocationBase;

	if (!pDosHeader->e_lfanew)
	{
		DebugOutput("AddressOfEPWriteCallback: pointer to PE header zero.\n");
		return FALSE;
	}

	if ((ULONG)pDosHeader->e_lfanew > PE_HEADER_LIMIT)
	{
		DebugOutput("AddressOfEPWriteCallback: pointer to PE header too big: 0x%p.\n", pDosHeader->e_lfanew);
		return FALSE;
	}

	DebugOutput("AddressOfEPWriteCallback: Breakpoint %i at Address 0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

	ReturnAddress = GetHookCallerBase();

	if (ReturnAddress && !TrackedRegionFromHook)
	{
		if (InsideMonitor(NULL, ReturnAddress))
		{
			DebugOutput("AddressOfEPWriteCallback: We are in a hooked function with return address 0x%p.\n", ReturnAddress);
			if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, 0, ReturnAddress, BP_EXEC, 0, HookReturnCallback))
			{
				DebugOutput("AddressOfEPWriteCallback: set exec bp on return address 0x%p.\n", ReturnAddress);
				TrackedRegionFromHook = TrackedRegion;
			}
			else
			{
				DebugOutput("AddressOfEPWriteCallback: Failed to set bp on return address 0x%p.\n", ReturnAddress);
			}
		}
		else
		{
			DebugOutput("AddressOfEPWriteCallback: Not in a hooked function, setting callback in enter_hook() to catch next hook (return address 0x%p).\n", ReturnAddress);
			TrackedRegionFromHook = TrackedRegion;
		}
	}

	pNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)TrackedRegion->AllocationBase + pDosHeader->e_lfanew);

	if ((pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) && (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC))
	{
		DebugOutput("AddressOfEPWriteCallback: Magic value not valid NT: 0x%x (at 0x%p).\n", pNtHeader->OptionalHeader.Magic, &pNtHeader->OptionalHeader.Magic);
		return TRUE;
	}

	TrackedRegion->CanDump = TRUE;

	if (pNtHeader->OptionalHeader.AddressOfEntryPoint > TrackedRegion->RegionSize)
	{
		DebugOutput("AddressOfEPWriteCallback: Valid magic value but AddressOfEntryPoint invalid: 0x%p.\n", pNtHeader->OptionalHeader.AddressOfEntryPoint);
		return TRUE;
	}

	if (!pNtHeader->OptionalHeader.AddressOfEntryPoint)
	{
		DebugOutput("AddressOfEPWriteCallback: Valid magic value but entry point still empty, leaving breakpoint intact.\n");
		return TRUE;
	}

	if (pNtHeader->OptionalHeader.AddressOfEntryPoint > TrackedRegion->RegionSize)
	{
		DebugOutput("AddressOfEPWriteCallback: Valid magic value but AddressOfEntryPoint 0x%x greater than region size 0x%x.\n", pNtHeader->OptionalHeader.AddressOfEntryPoint, TrackedRegion->RegionSize);
		return TRUE;
	}

	if ((DWORD_PTR)pNtHeader->OptionalHeader.AddressOfEntryPoint < ((DWORD_PTR)&pNtHeader->OptionalHeader.DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] - (DWORD_PTR)TrackedRegion->AllocationBase))
	{
		DebugOutput("AddressOfEPWriteCallback: Valid magic value but AddressOfEntryPoint 0x%x too small, possibly only partially written (<0x%x).\n", pNtHeader->OptionalHeader.AddressOfEntryPoint, (DWORD_PTR)&pNtHeader->OptionalHeader.DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] - (DWORD_PTR)TrackedRegion->AllocationBase);
		return TRUE;
	}

	if (*((BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint))
	{
		//ContextClearCurrentBreakpoint(ExceptionInfo->ContextRecord);

		if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, TrackedRegion->ExecBpRegister, 0, (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint, BP_EXEC, 0, EntryPointExecCallback))
		{
			DebugOutput("AddressOfEPWriteCallback: ContextSetNextAvailableBreakpoint on EntryPoint 0x%p failed\n", (BYTE*)TrackedRegion->AllocationBase+*(DWORD*)(pBreakpointInfo->Address));
			TrackedRegion->ExecBp = NULL;
			return FALSE;
		}

		TrackedRegion->ExecBp = (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint;

		DebugOutput("AddressOfEPWriteCallback: Execution bp %d set on EntryPoint 0x%p.\n", TrackedRegion->ExecBpRegister, TrackedRegion->ExecBp);
	}
	else
	{
		if (!ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(BYTE), (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint, BP_WRITE, 0, EntryPointWriteCallback))
		{
			DebugOutput("AddressOfEPWriteCallback: ContextUpdateCurrentBreakpoint failed\n");
			ContextClearBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);
			return FALSE;
		}

		DebugOutput("AddressOfEPWriteCallback: set write bp on AddressOfEntryPoint location 0x%p.\n", (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint);
	}

	SizeOfHeaders = pDosHeader->e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + pNtHeader->FileHeader.SizeOfOptionalHeader;

	if (pNtHeader->FileHeader.NumberOfSections && pNtHeader->FileHeader.SizeOfOptionalHeader && pNtHeader->OptionalHeader.SizeOfImage)
	{
		PIMAGE_SECTION_HEADER FinalSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)TrackedRegion->AllocationBase + SizeOfHeaders + (sizeof(IMAGE_SECTION_HEADER) * (pNtHeader->FileHeader.NumberOfSections - 1)));

		DebugOutput("AddressOfEPWriteCallback: DEBUG: NumberOfSections %d, SizeOfHeaders 0x%x.\n", pNtHeader->FileHeader.NumberOfSections, SizeOfHeaders);

		if (FinalSectionHeader->VirtualAddress && FinalSectionHeader->SizeOfRawData && (FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData <= pNtHeader->OptionalHeader.SizeOfImage))
		{
			PVOID FinalByteAddress = (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData - 1;

			if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(BYTE), FinalByteAddress, BP_WRITE, 0, FinalByteWriteCallback))
			{
				DebugOutput("AddressOfEPWriteCallback: SetNextAvailableBreakpoint failed to set write bp on final section, (address: 0x%p).\n", FinalByteAddress);
				return FALSE;
			}

			DebugOutput("AddressOfEPWriteCallback: Set write breakpoint on final section, last byte: 0x%p\n", *((BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData));

			if (FinalSectionHeader->Misc.VirtualSize && FinalSectionHeader->Misc.VirtualSize > FinalSectionHeader->SizeOfRawData)
				VirtualSize = FinalSectionHeader->Misc.VirtualSize;
			else if (pNtHeader->OptionalHeader.SectionAlignment)
				VirtualSize = ((FinalSectionHeader->SizeOfRawData / pNtHeader->OptionalHeader.SectionAlignment) + 1) * pNtHeader->OptionalHeader.SectionAlignment;
			else
				VirtualSize = ((FinalSectionHeader->SizeOfRawData / SystemInfo.dwPageSize) + 1) * SystemInfo.dwPageSize;

			if (FinalSectionHeader->VirtualAddress)
			{
				if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, NULL, sizeof(DWORD), (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + VirtualSize, BP_WRITE, 0, OverlayWriteCallback))
				{
					DebugOutput("AddressOfEPWriteCallback: SetNextAvailableBreakpoint failed to set write bp on final section, last byte: 0x%p.\n", (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->Misc.VirtualSize);
					return FALSE;
				}

				DebugOutput("AddressOfEPWriteCallback: Set write breakpoint on final section, last byte: 0x%p\n", (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->Misc.VirtualSize);
			}
		}
		else
		{
			if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(DWORD), &FinalSectionHeader->SizeOfRawData, BP_WRITE, 0, FinalSectionHeaderWriteCallback))
			{
				DebugOutput("AddressOfEPWriteCallback: SetNextAvailableBreakpoint failed to set write bp on final section, last byte: 0x%p.\n", &FinalSectionHeader->SizeOfRawData);
				return FALSE;
			}

			DebugOutput("AddressOfEPWriteCallback: Set write breakpoint on final section header (SizeOfRawData: 0x%x)\n", &FinalSectionHeader->SizeOfRawData);
		}
	}

	DebugOutput("AddressOfEPWriteCallback executed successfully.\n");

	return TRUE;
}

//**************************************************************************************
BOOL MagicWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;
	PIMAGE_DOS_HEADER pDosHeader;
#ifdef _WIN64
	PIMAGE_NT_HEADERS64 pNtHeader;
#else
	PIMAGE_NT_HEADERS32 pNtHeader;
#endif
	PVOID ReturnAddress, FinalByteAddress;
	DWORD SizeOfHeaders, VirtualSize;
	unsigned int Register;

	if (pBreakpointInfo == NULL)
	{
		DebugOutput("MagicWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DebugOutput("MagicWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);

	if (TrackedRegion == NULL)
	{
		DebugOutput("MagicWriteCallback: unable to locate entry point address 0x%p in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	}

	TrackedRegion->EntryPoint = 0;

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	pDosHeader = (PIMAGE_DOS_HEADER)TrackedRegion->AllocationBase;

	if (!pDosHeader->e_lfanew)
	{
		DebugOutput("MagicWriteCallback: pointer to PE header zero.\n");
		return FALSE;
	}

	if ((ULONG)pDosHeader->e_lfanew > PE_HEADER_LIMIT)
	{
		DebugOutput("MagicWriteCallback: pointer to PE header too big: 0x%p.\n", pDosHeader->e_lfanew);
		return FALSE;
	}

	DebugOutput("MagicWriteCallback: Breakpoint %i at Address 0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

	ReturnAddress = GetHookCallerBase();

	if (ReturnAddress && !TrackedRegionFromHook)
	{
		if (InsideMonitor(NULL, ReturnAddress))
		{
			DebugOutput("MagicWriteCallback: We are in a hooked function with return address 0x%p.\n", ReturnAddress);
			if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, 0, ReturnAddress, BP_EXEC, 0, HookReturnCallback))
			{
				DebugOutput("MagicWriteCallback: set exec bp on return address 0x%p.\n", ReturnAddress);
				TrackedRegionFromHook = TrackedRegion;
			}
			else
			{
				DebugOutput("MagicWriteCallback: Failed to set bp on return address 0x%p.\n", ReturnAddress);
			}
		}
		else
		{
			DebugOutput("MagicWriteCallback: Not in a hooked function, setting callback in enter_hook() to catch next hook (return address 0x%p).\n", ReturnAddress);
			TrackedRegionFromHook = TrackedRegion;
		}
	}

	pNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)TrackedRegion->AllocationBase + pDosHeader->e_lfanew);

	if ((pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) && (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC))
	{
		DebugOutput("MagicWriteCallback: Magic value not valid NT: 0x%x (at 0x%p).\n", pNtHeader->OptionalHeader.Magic, &pNtHeader->OptionalHeader.Magic);
		return TRUE;
	}

	TrackedRegion->CanDump = TRUE;

	if (!pNtHeader->OptionalHeader.AddressOfEntryPoint)
	{
		DebugOutput("MagicWriteCallback: Valid magic value but entry point still empty, leaving breakpoint intact.\n");
		return TRUE;
	}

	if (pNtHeader->OptionalHeader.AddressOfEntryPoint > TrackedRegion->RegionSize)
	{
		DebugOutput("MagicWriteCallback: Valid magic value but AddressOfEntryPoint 0x%x greater than region size 0x%x.\n", pNtHeader->OptionalHeader.AddressOfEntryPoint, TrackedRegion->RegionSize);
		return TRUE;
	}

	if ((DWORD_PTR)pNtHeader->OptionalHeader.AddressOfEntryPoint < ((DWORD_PTR)&pNtHeader->OptionalHeader.DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] - (DWORD_PTR)TrackedRegion->AllocationBase))
	{
		DebugOutput("MagicWriteCallback: Valid magic value but AddressOfEntryPoint 0x%x too small, possibly only partially written (<0x%x).\n", pNtHeader->OptionalHeader.AddressOfEntryPoint, (DWORD_PTR)&pNtHeader->OptionalHeader.DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] - (DWORD_PTR)TrackedRegion->AllocationBase);
		return TRUE;
	}

	if (*((BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint))
	{
		if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, TrackedRegion->ExecBpRegister, 0, (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint, BP_EXEC, 0, EntryPointExecCallback))
		{
			DebugOutput("MagicWriteCallback: ContextSetNextAvailableBreakpoint on EntryPoint 0x%p failed\n", (BYTE*)TrackedRegion->AllocationBase+*(DWORD*)(pBreakpointInfo->Address));
			TrackedRegion->ExecBp = NULL;
			return FALSE;
		}

		TrackedRegion->ExecBp = (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint;

		DebugOutput("MagicWriteCallback: Execution bp %d set on EntryPoint 0x%p.\n", TrackedRegion->ExecBpRegister, TrackedRegion->ExecBp);
	}
	else
	{
		if (!ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(BYTE), (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint, BP_WRITE, 0, EntryPointWriteCallback))
		{
			DebugOutput("MagicWriteCallback: ContextUpdateCurrentBreakpoint failed\n");
			ContextClearBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);
			return FALSE;
		}

		DebugOutput("MagicWriteCallback: set write bp on AddressOfEntryPoint location 0x%p.\n", (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint);
	}

	SizeOfHeaders = pDosHeader->e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + pNtHeader->FileHeader.SizeOfOptionalHeader;

	if (pNtHeader->FileHeader.NumberOfSections && pNtHeader->FileHeader.SizeOfOptionalHeader)
	{
		PIMAGE_SECTION_HEADER FinalSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)TrackedRegion->AllocationBase + SizeOfHeaders + (sizeof(IMAGE_SECTION_HEADER) * (pNtHeader->FileHeader.NumberOfSections - 1)));

		DebugOutput("MagicWriteCallback: DEBUG: NumberOfSections %d, SizeOfHeaders 0x%x.\n", pNtHeader->FileHeader.NumberOfSections, SizeOfHeaders);

		if (FinalSectionHeader->VirtualAddress && FinalSectionHeader->SizeOfRawData)
		{
			FinalByteAddress = (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData - 1;

			if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(BYTE), FinalByteAddress, BP_WRITE, 0, FinalByteWriteCallback))
			{
				DebugOutput("MagicWriteCallback: SetNextAvailableBreakpoint failed to set write bp on final section, last byte: 0x%p.\n", FinalByteAddress);
				return FALSE;
			}

			DebugOutput("MagicWriteCallback: Set write breakpoint on final section, last byte: 0x%p\n", (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData);

			if (FinalSectionHeader->Misc.VirtualSize && FinalSectionHeader->Misc.VirtualSize > FinalSectionHeader->SizeOfRawData)
				VirtualSize = FinalSectionHeader->Misc.VirtualSize;
			else if (pNtHeader->OptionalHeader.SectionAlignment)
				VirtualSize = ((FinalSectionHeader->SizeOfRawData / pNtHeader->OptionalHeader.SectionAlignment) + 1) * pNtHeader->OptionalHeader.SectionAlignment;
			else
				VirtualSize = ((FinalSectionHeader->SizeOfRawData / SystemInfo.dwPageSize) + 1) * SystemInfo.dwPageSize;

			if (FinalSectionHeader->VirtualAddress)
			{
				if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, NULL, sizeof(DWORD), (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + VirtualSize, BP_WRITE, 0, OverlayWriteCallback))
				{
					DebugOutput("MagicWriteCallback: SetNextAvailableBreakpoint failed to set write bp on final section, last byte: 0x%p.\n", (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->Misc.VirtualSize);
					return FALSE;
				}

				DebugOutput("MagicWriteCallback: Set write breakpoint on final section, last byte: 0x%p\n", (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->Misc.VirtualSize);
			}
		}
		else
		{
			if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(DWORD), &FinalSectionHeader->SizeOfRawData, BP_WRITE, 0, FinalSectionHeaderWriteCallback))
			{
				DebugOutput("MagicWriteCallback: SetNextAvailableBreakpoint failed to set write bp on final section, last byte: 0x%p.\n", &FinalSectionHeader->SizeOfRawData);
				return FALSE;
			}

			DebugOutput("MagicWriteCallback: Set write breakpoint on final section header (SizeOfRawData: 0x%x)\n", &FinalSectionHeader->SizeOfRawData);
		}
	}

	DebugOutput("MagicWriteCallback executed successfully.\n");

	return TRUE;
}

//**************************************************************************************
BOOL PEPointerWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;
	PIMAGE_DOS_HEADER pDosHeader;
#ifdef _WIN64
	PIMAGE_NT_HEADERS64 pNtHeader;
#else
	PIMAGE_NT_HEADERS32 pNtHeader;
#endif

	if (pBreakpointInfo == NULL)
	{
		DebugOutput("PEPointerWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DebugOutput("PEPointerWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	DebugOutput("PEPointerWriteCallback: Breakpoint %i at Address 0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

	TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);

	if (TrackedRegion == NULL)
	{
		DebugOutput("PEPointerWriteCallback: unable to locate address 0x%p in tracked regions.\n", pBreakpointInfo->Address);
		return FALSE;
	}

	TrackedRegion->EntryPoint = 0;

	if (TrackedRegion->ProtectAddress)
		pDosHeader = (PIMAGE_DOS_HEADER)TrackedRegion->ProtectAddress;
	else
		pDosHeader = (PIMAGE_DOS_HEADER)TrackedRegion->AllocationBase;

	if (!pDosHeader->e_lfanew)
	{
		DebugOutput("PEPointerWriteCallback: candidate pointer to PE header zero.\n");
		return TRUE;
	}

	if ((ULONG)pDosHeader->e_lfanew > PE_HEADER_LIMIT)
	{
		// This is to be expected a lot when it's not a PE.
		DebugOutput("PEPointerWriteCallback: candidate pointer to PE header too big: 0x%x (at 0x%p).\n", pDosHeader->e_lfanew, &pDosHeader->e_lfanew);

		if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &TrackedRegion->ExecBpRegister, 0, (BYTE*)TrackedRegion->AllocationBase, BP_EXEC, 0, ShellcodeExecCallback))
		{
			DebugOutput("PEPointerWriteCallback: set write bp on AddressOfEntryPoint at 0x%p.\n", TrackedRegion->AllocationBase);
			return TRUE;
		}
		else
		{
			DebugOutput("PEPointerWriteCallback: Failed to set exec bp on AllocationBase at 0x%p.\n", TrackedRegion->AllocationBase);
			TrackedRegion->ExecBp = NULL;
			return FALSE;
		}
	}

	if (*(WORD*)TrackedRegion->AllocationBase == IMAGE_DOS_SIGNATURE)
		TrackedRegion->CanDump = TRUE;

#ifdef _WIN64
	pNtHeader = (PIMAGE_NT_HEADERS64)((BYTE*)TrackedRegion->AllocationBase + pDosHeader->e_lfanew);
#else
	pNtHeader = (PIMAGE_NT_HEADERS32)((BYTE*)TrackedRegion->AllocationBase + pDosHeader->e_lfanew);
#endif

	if (TrackedRegion->MagicBp)
	{
		if (TrackedRegion->MagicBp == &pNtHeader->OptionalHeader.Magic)
		{
			DebugOutput("PEPointerWriteCallback: Leaving 'magic' breakpoint unchanged.\n");
			return TRUE;
		}

		if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, TrackedRegion->MagicBpRegister, sizeof(WORD), &pNtHeader->OptionalHeader.Magic, BP_WRITE, 0, MagicWriteCallback))
		{
			DebugOutput("PEPointerWriteCallback: Failed to set breakpoint on magic address.\n");
			return FALSE;
		}
	}
	else if (!ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(WORD), &pNtHeader->OptionalHeader.Magic, BP_WRITE, 0, MagicWriteCallback))
	{
		DebugOutput("PEPointerWriteCallback: Failed to set breakpoint on magic address.\n");
		return FALSE;
	}

	TrackedRegion->MagicBp = &pNtHeader->OptionalHeader.Magic;

	if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, 0, 4, &pNtHeader->OptionalHeader.AddressOfEntryPoint, BP_WRITE, 0, AddressOfEPWriteCallback))
	{
		DebugOutput("PEPointerWriteCallback: set write bp on AddressOfEntryPoint at 0x%p.\n", &pNtHeader->OptionalHeader.AddressOfEntryPoint);
		return TRUE;
	}
	else
	{
		DebugOutput("PEPointerWriteCallback: Failed to set bp on AddressOfEntryPoint at 0x%p.\n", &pNtHeader->OptionalHeader.AddressOfEntryPoint);
		return FALSE;
	}

	DebugOutput("PEPointerWriteCallback executed successfully with a breakpoints set on addresses of Magic (0x%p) and AddressOfEntryPoint (0x%p).\n", TrackedRegion->MagicBp, &pNtHeader->OptionalHeader.AddressOfEntryPoint);

	return TRUE;
}

//**************************************************************************************
BOOL ShellcodeExecCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;

	if (pBreakpointInfo == NULL)
	{
		DebugOutput("ShellcodeExecCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DebugOutput("ShellcodeExecCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);

	if (TrackedRegion == NULL)
	{
		DebugOutput("ShellcodeExecCallback: unable to locate address 0x%p in tracked regions.\n", pBreakpointInfo->Address);
		return FALSE;
	}

	if (!VirtualQuery(pBreakpointInfo->Address, &TrackedRegion->MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		ErrorOutput("ShellcodeExecCallback: unable to query memory region 0x%p", pBreakpointInfo->Address);
		return FALSE;
	}

	DebugOutput("ShellcodeExecCallback: Breakpoint %i at Address 0x%p (allocation base 0x%p).\n", pBreakpointInfo->Register, pBreakpointInfo->Address, TrackedRegion->MemInfo.AllocationBase);

	if (GuardPagesDisabled)
	{
		ContextClearTrackedRegion(ExceptionInfo->ContextRecord, TrackedRegion);

		DebugOutput("ShellcodeExecCallback: About to scan region for a PE image (base 0x%p, size 0x%x).\n", TrackedRegion->MemInfo.AllocationBase, (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress + TrackedRegion->MemInfo.RegionSize - (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase);

		SetCapeMetaData(UNPACKED_PE, 0, NULL, TrackedRegion->MemInfo.AllocationBase);
		TrackedRegion->PagesDumped = DumpPEsInRange(TrackedRegion->MemInfo.AllocationBase, (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress + TrackedRegion->MemInfo.RegionSize - (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase);

		if (TrackedRegion->PagesDumped)
			DebugOutput("ShellcodeExecCallback: PE image(s) detected and dumped.\n");

		// In the case where dumped PE file(s) come from inside shellcode, still dump the shellcode
		if (!TrackedRegion->PagesDumped || (TrackedRegion->PagesDumped && !IsDisguisedPEHeader(TrackedRegion->MemInfo.AllocationBase)))
		{
			SIZE_T ShellcodeSize = (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress + TrackedRegion->MemInfo.RegionSize - (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase;

			SetCapeMetaData(UNPACKED_SHELLCODE, 0, NULL, TrackedRegion->MemInfo.AllocationBase);

			TrackedRegion->Entropy = GetEntropy(TrackedRegion->AllocationBase);

			TrackedRegion->PagesDumped = DumpMemory(TrackedRegion->MemInfo.AllocationBase, ShellcodeSize);

			if (TrackedRegion->PagesDumped)
				DebugOutput("ShellcodeExecCallback: successfully dumped memory range at 0x%p (size 0x%x).\n", TrackedRegion->MemInfo.AllocationBase, ShellcodeSize);
			else
				DebugOutput("ShellcodeExecCallback: failed to dump memory range at 0x%p (size 0x%x).\n", TrackedRegion->MemInfo.AllocationBase, ShellcodeSize);
		}

		return TRUE;
	}

	if (!GuardPagesDisabled && DeactivateGuardPages(TrackedRegion))
	{
		SetCapeMetaData(UNPACKED_PE, 0, NULL, TrackedRegion->MemInfo.AllocationBase);

		if (!address_is_in_stack((PVOID)pBreakpointInfo->Address) && (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress > (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase)
		{
			DebugOutput("ShellcodeExecCallback: About to scan region for a PE image (base 0x%p, size 0x%x).\n", TrackedRegion->MemInfo.AllocationBase, (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress + TrackedRegion->MemInfo.RegionSize - (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase);
			TrackedRegion->PagesDumped = DumpPEsInRange(TrackedRegion->MemInfo.AllocationBase, (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress + TrackedRegion->MemInfo.RegionSize - (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase);
		}
		else if (address_is_in_stack((PVOID)pBreakpointInfo->Address) || (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress == (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase)
		{
			DebugOutput("ShellcodeExecCallback: About to scan region for a PE image (base 0x%p, size 0x%x).\n", TrackedRegion->MemInfo.BaseAddress, TrackedRegion->MemInfo.RegionSize);
			TrackedRegion->PagesDumped = DumpPEsInRange(TrackedRegion->MemInfo.BaseAddress, TrackedRegion->MemInfo.RegionSize);
		}

		if (TrackedRegion->PagesDumped)
		{
			DebugOutput("ShellcodeExecCallback: PE image(s) detected and dumped.\n");
			ContextClearTrackedRegion(ExceptionInfo->ContextRecord, TrackedRegion);
		}
		else
		{
			if (!address_is_in_stack((PVOID)pBreakpointInfo->Address) && (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress > (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase)
			{
				SetCapeMetaData(UNPACKED_SHELLCODE, 0, NULL, TrackedRegion->MemInfo.AllocationBase);

				TrackedRegion->Entropy = GetEntropy(TrackedRegion->AllocationBase);
				TrackedRegion->PagesDumped = DumpMemory(TrackedRegion->MemInfo.AllocationBase, (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress + TrackedRegion->MemInfo.RegionSize - (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase);

				if (TrackedRegion->PagesDumped)
				{
					DebugOutput("ShellcodeExecCallback: successfully dumped memory range at 0x%p.\n", TrackedRegion->MemInfo.AllocationBase);
					ContextClearTrackedRegion(ExceptionInfo->ContextRecord, TrackedRegion);
				}
			}
			else if (address_is_in_stack((PVOID)pBreakpointInfo->Address) || (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress == (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase)
			{
				SetCapeMetaData(UNPACKED_SHELLCODE, 0, NULL, TrackedRegion->MemInfo.BaseAddress);

				if (ScanForNonZero(TrackedRegion->MemInfo.BaseAddress, TrackedRegion->MemInfo.RegionSize))
				{
					TrackedRegion->Entropy = GetEntropy(TrackedRegion->AllocationBase);
					TrackedRegion->PagesDumped = DumpMemory(TrackedRegion->MemInfo.BaseAddress, TrackedRegion->MemInfo.RegionSize);
				}
				else
					DebugOutput("ShellcodeExecCallback: memory range at 0x%p is empty.\n", TrackedRegion->MemInfo.BaseAddress);

				if (TrackedRegion->PagesDumped)
				{
					DebugOutput("ShellcodeExecCallback: successfully dumped memory range at 0x%p.\n", TrackedRegion->MemInfo.BaseAddress);
					ContextClearTrackedRegion(ExceptionInfo->ContextRecord, TrackedRegion);
				}
			}
		}

		if (!TrackedRegion->PagesDumped)
		{
			DebugOutput("ShellcodeExecCallback: Failed to dump memory range at 0x%p.\n", TrackedRegion->MemInfo.BaseAddress);

			return FALSE;
		}
		else
			DebugOutput("ShellcodeExecCallback executed successfully.\n");

		ContextClearTrackedRegion(ExceptionInfo->ContextRecord, TrackedRegion);

		return TRUE;
	}
	else
	{
		DebugOutput("ShellcodeExecCallback: Failed to disable guard pages for dump.\n");

		return FALSE;
	}
}

//**************************************************************************************
BOOL BaseAddressWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;
	PIMAGE_DOS_HEADER pDosHeader;

	if (pBreakpointInfo == NULL)
	{
		DebugOutput("BaseAddressWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DebugOutput("BaseAddressWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	DebugOutput("BaseAddressWriteCallback: Breakpoint %i at Address 0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

	TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);

	if (TrackedRegion == NULL)
	{
		DebugOutput("BaseAddressWriteCallback: unable to locate address 0x%p in tracked regions.\n", pBreakpointInfo->Address);
		return FALSE;
	}

	TrackedRegion->EntryPoint = 0;

	if (*(WORD*)pBreakpointInfo->Address == IMAGE_DOS_SIGNATURE)
	{
		DebugOutput("BaseAddressWriteCallback: MZ header found.\n");

		TrackedRegion->CanDump = TRUE;

		pDosHeader = (PIMAGE_DOS_HEADER)pBreakpointInfo->Address;

		if (pDosHeader->e_lfanew && (unsigned int)pDosHeader->e_lfanew < PE_HEADER_LIMIT)
		{
			if (*(DWORD*)((unsigned char*)pDosHeader + pDosHeader->e_lfanew) == IMAGE_NT_SIGNATURE)
			{
				SetCapeMetaData(UNPACKED_PE, 0, NULL, TrackedRegion->AllocationBase);
				TrackedRegion->PagesDumped = DumpPEsInRange(TrackedRegion->AllocationBase, TrackedRegion->RegionSize);

				if (TrackedRegion->PagesDumped)
				{
					DebugOutput("BaseAddressWriteCallback: PE image(s) dumped from 0x%p.\n", TrackedRegion->MemInfo.AllocationBase);
					ClearTrackedRegion(TrackedRegion);
					return TRUE;
				}
				else
					DebugOutput("BaseAddressWriteCallback: failed to dump PE module from 0x%p.\n", TrackedRegion->MemInfo.AllocationBase);
			}
			else
			{
				// Deal with the situation where the breakpoint triggers after e_lfanew has already been written
				PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)TrackedRegion->AllocationBase + pDosHeader->e_lfanew);
				if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(WORD), &pNtHeader->OptionalHeader.Magic, BP_WRITE, 0, MagicWriteCallback))
				{
#ifdef _WIN64
					DebugOutput("BaseAddressWriteCallback: set write bp on magic address 0x%p (RIP = 0x%p)\n", (BYTE*)pDosHeader + pDosHeader->e_lfanew, ExceptionInfo->ContextRecord->Rip);
#else
					DebugOutput("BaseAddressWriteCallback: set write bp on magic address 0x%x (EIP = 0x%x)\n", (BYTE*)pDosHeader + pDosHeader->e_lfanew, ExceptionInfo->ContextRecord->Eip);
#endif
				}
				else
				{
					DebugOutput("BaseAddressWriteCallback: Failed to set breakpoint on magic address.\n");
					return FALSE;
				}
			}
		}
		else if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(DWORD), (BYTE*)&pDosHeader->e_lfanew, BP_WRITE, 0, PEPointerWriteCallback))
		{
			TrackedRegion->CanDump = TRUE;
#ifdef _WIN64
			DebugOutput("BaseAddressWriteCallback: set write bp on e_lfanew write location: 0x%x (RIP = 0x%x)\n", (BYTE*)&pDosHeader->e_lfanew, ExceptionInfo->ContextRecord->Rip);
#else
			DebugOutput("BaseAddressWriteCallback: set write bp on e_lfanew write location: 0x%x (EIP = 0x%x)\n", (BYTE*)&pDosHeader->e_lfanew, ExceptionInfo->ContextRecord->Eip);
#endif
		}
		else
		{
			DebugOutput("BaseAddressWriteCallback: ContextUpdateCurrentBreakpoint failed\n");
			return FALSE;
		}
	}
	else if (*(BYTE*)pBreakpointInfo->Address == 'M')
	{
		// If a PE file is being written a byte at a time we do nothing and hope that the 4D byte isn't code!
		DebugOutput("BaseAddressWriteCallback: M written to first byte, awaiting next byte.\n");
		return TRUE;
	}
	else if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &TrackedRegion->ExecBpRegister, 0, pBreakpointInfo->Address, BP_EXEC, 0, ShellcodeExecCallback))
	{
		DebugOutput("BaseAddressWriteCallback: Failed to set exec bp on tracked region protect address.\n");
		return FALSE;
	}

	DebugOutput("BaseAddressWriteCallback: byte written to 0x%x: 0x%x.\n", pBreakpointInfo->Address, *(BYTE*)pBreakpointInfo->Address);

	TrackedRegion->ExecBp = pBreakpointInfo->Address;

	DebugOutput("BaseAddressWriteCallback: Exec bp set on tracked region protect address.\n");

	return TRUE;
}

//**************************************************************************************
BOOL ActivateBreakpoints(PTRACKEDREGION TrackedRegion, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	DWORD ThreadId;
	unsigned int Register;
	PIMAGE_DOS_HEADER pDosHeader;
	//DWORD_PTR LastAccessPage, AddressOfPage;

	if (!TrackedRegion)
	{
		DebugOutput("ActivateBreakpoints: Error, tracked region argument NULL.\n");
		return FALSE;
	}

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	if (!SystemInfo.dwPageSize)
	{
		ErrorOutput("ActivateBreakpoints: Failed to obtain system page size.\n");
		return FALSE;
	}

	ThreadId = GetCurrentThreadId();

	DebugOutput("ActivateBreakpoints: TrackedRegion->AllocationBase: 0x%p, TrackedRegion->RegionSize: 0x%x, thread %d\n", TrackedRegion->AllocationBase, TrackedRegion->RegionSize, ThreadId);

	if (TrackedRegion->RegionSize == 0 || TrackedRegion->AllocationBase == NULL || ThreadId == 0)
	{
		DebugOutput("ActivateBreakpoints: Error, one of the following is NULL - TrackedRegion->AllocationBase: 0x%p, TrackedRegion->RegionSize: 0x%x, thread %d\n", TrackedRegion->AllocationBase, TrackedRegion->RegionSize, ThreadId);
		return FALSE;
	}

	//AddressOfBasePage = ((DWORD_PTR)TrackedRegion->AllocationBase/SystemInfo.dwPageSize)*SystemInfo.dwPageSize;
	//ProtectAddressPage = ((DWORD_PTR)TrackedRegion->ProtectAddress/SystemInfo.dwPageSize)*SystemInfo.dwPageSize;

	// If we are activating breakpoints on a new region we 'save' the current region's breakpoints
	if (CurrentBreakpointRegion && TrackedRegion != CurrentBreakpointRegion)
	{
		DebugOutput("ActivateBreakpoints: Switching breakpoints from region 0x%p to 0x%p.\n", CurrentBreakpointRegion->AllocationBase, TrackedRegion->AllocationBase);

		// Save them
		CurrentBreakpointRegion->TrackedRegionBreakpoints = GetThreadBreakpoints(GetCurrentThreadId());

		// Then clear them
		ClearAllBreakpoints();

		// We process the previous region if it contains code/data
		if (!CurrentBreakpointRegion->PagesDumped && CurrentBreakpointRegion->AllocationBase != ImageBase && ScanForNonZero(CurrentBreakpointRegion->AllocationBase, CurrentBreakpointRegion->RegionSize))
		{
			CurrentBreakpointRegion->CanDump = 1;
			ProcessTrackedRegion(CurrentBreakpointRegion);
		}

		// We switch regions
		CurrentBreakpointRegion = TrackedRegion;

		// We restore the breakpoints for the new region if it's already been seen
		if (CurrentBreakpointRegion->BreakpointsSet && CurrentBreakpointRegion->TrackedRegionBreakpoints)
		{
			if (!SetThreadBreakpoints(CurrentBreakpointRegion->TrackedRegionBreakpoints))
			{
				DebugOutput("ActivateBreakpoints: Failed to restore region breakpoints for region at 0x%p.\n", CurrentBreakpointRegion->AllocationBase);
				CurrentBreakpointRegion->BreakpointsSet = FALSE;
				return FALSE;
			}

			DebugOutput("ActivateBreakpoints: Restored region breakpoints for region at 0x%p.\n", CurrentBreakpointRegion->AllocationBase);

			CurrentBreakpointRegion->BreakpointsSet = TRUE;

			return TRUE;
		}
	}

	if (TrackedRegion->PagesDumped)
	{
		DebugOutput("ActivateBreakpoints: Current tracked region has already been dumped.\n");
		return TRUE;
	}

	//if (TrackedRegion->BreakpointsSet)
	//{
	//	DebugOutput("ActivateBreakpoints: Current tracked region already has breakpoints set.\n");
	//	return TRUE;
	//}

	if (TrackedRegion->ProtectAddress && TrackedRegion->ProtectAddress != TrackedRegion->AllocationBase)
		// we want to put a breakpoint on the protected address
		TrackedRegion->ExecBp = TrackedRegion->ProtectAddress;
	else
		TrackedRegion->ExecBp = TrackedRegion->AllocationBase;

	CapeMetaData->Address = TrackedRegion->ExecBp;

	ClearAllBreakpoints();

	// If ExecBp points to non-zero we assume code
	if (*(BYTE*)TrackedRegion->ExecBp)
	{
		// We set the initial 'execute' breakpoint
		if (ExceptionInfo == NULL)
		{
			if (!SetNextAvailableBreakpoint(GetCurrentThreadId(), &TrackedRegion->ExecBpRegister, 0, (BYTE*)TrackedRegion->ExecBp, BP_EXEC, 0, ShellcodeExecCallback))
			{
				DebugOutput("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set exec bp on tracked region protect address 0x%p.\n", TrackedRegion->ExecBp);
				TrackedRegion->ExecBp = NULL;
				return FALSE;
			}

			DebugOutput("ActivateBreakpoints: Set execution breakpoint on non-zero byte 0x%x at protected address: 0x%p\n", *(PUCHAR)TrackedRegion->ExecBp, TrackedRegion->ExecBp);
		}
		else
		{
			if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &TrackedRegion->ExecBpRegister, 0, (BYTE*)TrackedRegion->ExecBp, BP_EXEC, 0, ShellcodeExecCallback))
			{
				DebugOutput("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set exec bp on tracked region protect address 0x%p.\n", TrackedRegion->ExecBp);
				TrackedRegion->ExecBp = NULL;
				return FALSE;
			}

			DebugOutput("ActivateBreakpoints: Set execution breakpoint on non-zero byte 0x%x at protected address: 0x%p\n", *(PUCHAR)TrackedRegion->ExecBp, TrackedRegion->ExecBp);
		}
	}
	else
	{
		// We set a write breakpoint instead
		if (ExceptionInfo == NULL)
		{
			if (!SetNextAvailableBreakpoint(GetCurrentThreadId(), &TrackedRegion->ExecBpRegister, sizeof(WORD), (BYTE*)TrackedRegion->ExecBp, BP_WRITE, 0, BaseAddressWriteCallback))
			{
				DebugOutput("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set write bp on tracked region protect address 0x%p.\n", TrackedRegion->ExecBp);
				TrackedRegion->ExecBp = NULL;
				return FALSE;
			}

			DebugOutput("ActivateBreakpoints: Set write breakpoint on empty protect address: 0x%p\n", TrackedRegion->ExecBp);
		}
		else
		{
			if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &TrackedRegion->ExecBpRegister, sizeof(WORD), (BYTE*)TrackedRegion->ExecBp, BP_WRITE, 0, BaseAddressWriteCallback))
			{
				DebugOutput("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set write bp on tracked region protect address 0x%p.\n", TrackedRegion->ExecBp);
				TrackedRegion->ExecBp = NULL;
				return FALSE;
			}

			DebugOutput("ActivateBreakpoints: Set write breakpoint on empty protect address: 0x%p\n", TrackedRegion->ExecBp);
		}
	}

	// We also set a write bp on 'e_lfanew' address to begin our PE-write detection chain
	pDosHeader = (PIMAGE_DOS_HEADER)TrackedRegion->AllocationBase;

	if (ExceptionInfo == NULL)
	{
		if (!SetNextAvailableBreakpoint(GetCurrentThreadId(), &Register, sizeof(LONG), (BYTE*)&pDosHeader->e_lfanew, BP_WRITE, 0, PEPointerWriteCallback))
		{
			DebugOutput("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set write bp on e_lfanew address 0x%p.\n", TrackedRegion->ExecBp);
			return FALSE;
		}

		DebugOutput("ActivateBreakpoints: Set write breakpoint on e_lfanew address: 0x%p\n", &pDosHeader->e_lfanew);
	}
	else
	{
		if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(LONG), (BYTE*)&pDosHeader->e_lfanew, BP_WRITE, 0, PEPointerWriteCallback))
		{
			DebugOutput("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set write bp on e_lfanew address 0x%p.\n", TrackedRegion->ExecBp);
			return FALSE;
		}

		DebugOutput("ActivateBreakpoints: Set write breakpoint on e_lfanew address: 0x%p\n", &pDosHeader->e_lfanew);
	}

	CurrentBreakpointRegion = TrackedRegion;

	return TRUE;	// this should set TrackedRegion->BreakpointsSet in calling function
}

void UnpackerDllInit(PVOID DllBase)
{
	// We remove exe (rundll32) image from tracked regions
	if (!DropTrackedRegion(GetTrackedRegion(GetModuleHandle(NULL))))
		DebugOutput("UnpackerDllInit: Error removing exe image base from tracked regions.\n");

	ImageBase = DllBase;

	// We add the dll image to tracked regions
	PTRACKEDREGION TrackedRegion = GetTrackedRegion(DllBase);
	if (!TrackedRegion)
	{
		DebugOutput("UnpackerDllInit: Adding target dll image base to tracked regions.\n");
		TrackedRegion = AddTrackedRegion(DllBase, 0, 0);
	}
	else
	{
		TrackedRegion->PagesDumped = FALSE;
	}
}

void UnpackerInit()
{
	// Start the debugger
	if (InitialiseDebugger())
		DebugOutput("UnpackerInit: Debugger initialised.\n");
	else
		DebugOutput("UnpackerInit: Failed to initialise debugger.\n");

	if (!_strnicmp(our_process_path, "c:\\windows\\sys", 14) && !_strnicmp(our_process_name, "rundll32", 8))
	{
		DebugOutput("UnpackerInit: Skipping rundll32 module.\n");
		return;
	}

	// We add the main image to tracked regions
	CapeMetaData->DumpType = UNPACKED_PE;
	PTRACKEDREGION TrackedRegion = AddTrackedRegion(GetModuleHandle(NULL), 0, 0);
	if (TrackedRegion)
	{
		DebugOutput("UnpackerInit: Adding main image base to tracked regions.\n");
		TrackedRegion->PagesDumped = TRUE;
	}
	else
		DebugOutput("UnpackerInit: Error adding image base to tracked regions.\n");
}