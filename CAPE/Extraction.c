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
#include "Extraction.h"
#include "..\alloc.h"

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

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);

extern unsigned int address_is_in_stack(PVOID Address);
extern ULONG_PTR g_our_dll_base;
extern DWORD g_our_dll_size;
extern HANDLE g_terminate_event_handle;
extern PVOID ImageBase;

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
            DoOutputDebugString("GetNtHeaders: pointer to PE header zero.\n");
            return NULL;
        }

        if ((ULONG)pDosHeader->e_lfanew > PE_HEADER_LIMIT)
        {
            DoOutputDebugString("GetNtHeaders: pointer to PE header too big: 0x%x (at 0x%p).\n", pDosHeader->e_lfanew, &pDosHeader->e_lfanew);
            return NULL;
        }

        return (PIMAGE_NT_HEADERS)((BYTE*)BaseAddress + pDosHeader->e_lfanew);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DoOutputDebugString("GetNtHeaders: Exception occured reading around base address 0x%p\n", BaseAddress);
        return NULL;
    }
}

//**************************************************************************************
BOOL IsInTrackedRegion(PTRACKEDREGION TrackedRegion, PVOID Address)
//**************************************************************************************
{
    if (Address == NULL)
	{
        DoOutputDebugString("IsInTrackedRegion: NULL passed as address argument - error.\n");
        return FALSE;
	}

    if (TrackedRegion == NULL)
    {
        DoOutputDebugString("IsInTrackedRegion: NULL passed as tracked region argument - error.\n");
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
        DoOutputDebugString("IsInTrackedRegions: NULL passed as argument - error.\n");
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
        //DoOutputDebugString("GetTrackedRegion: AllocationBase 0x%p RegionSize 0x%d.\n", CurrentTrackedRegion->AllocationBase, CurrentTrackedRegion->RegionSize);
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
        DoOutputDebugString("CreateTrackedRegion: failed to allocate memory for initial tracked region list.\n");
        return NULL;
    }

    memset(FirstTrackedRegion, 0, sizeof(struct TrackedRegion));

    TrackedRegionList = FirstTrackedRegion;

    //DoOutputDebugString("CreateTrackedRegion: Tracked region list created at 0x%p.\n", TrackedRegionList);

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
        DoOutputDebugString("AddTrackedRegion: DEBUG Warning - number of tracked regions %d.\n", NumberOfTrackedRegions);

	if (GetPageAddress(Address) == GetPageAddress(TrackedRegionList))
	{
        DoOutputDebugString("AddTrackedRegion: Warning - attempting to track the page (0x%p) containing the tracked region list at 0x%p.\n", Address, TrackedRegionList);
		return NULL;
	}

    TrackedRegion = GetTrackedRegion(Address);

    if (!TrackedRegion)
    {
        // We haven't found it in the linked list, so create a new one
        TrackedRegion = PreviousTrackedRegion;

        TrackedRegion->NextTrackedRegion = ((struct TrackedRegion*)malloc(sizeof(struct TrackedRegion)));

        if (TrackedRegion->NextTrackedRegion == NULL)
        {
            DoOutputDebugString("AddTrackedRegion: Failed to allocate new tracked region struct.\n");
            return NULL;
        }

        TrackedRegion = TrackedRegion->NextTrackedRegion;

        memset(TrackedRegion, 0, sizeof(struct TrackedRegion));
        DoOutputDebugString("AddTrackedRegion: Created new tracked region for address 0x%p.\n", Address);
    }
    else
    {
        PageAlreadyTracked = TRUE;
        DoOutputDebugString("AddTrackedRegion: Region at 0x%p already in tracked region 0x%p - updating.\n", Address, TrackedRegion->AllocationBase);
    }

    if (!VirtualQuery(Address, &TrackedRegion->MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
    {
        DoOutputErrorString("AddTrackedRegion: unable to query memory region 0x%p", Address);
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
            DoOutputDebugString("AddTrackedRegion: GetEntropy failed.");

        TrackedRegion->MinPESize = GetMinPESize(TrackedRegion->AllocationBase);
        if (TrackedRegion->MinPESize)
            DoOutputDebugString("AddTrackedRegion: Min PE size 0x%x", TrackedRegion->MinPESize);
        //else
        //    DoOutputDebugString("AddTrackedRegion: GetMinPESize failed");
        if (!PageAlreadyTracked)
            DoOutputDebugString("AddTrackedRegion: New region at 0x%p size 0x%x added to tracked regions: EntryPoint 0x%x, Entropy %e\n", TrackedRegion->AllocationBase, TrackedRegion->RegionSize, TrackedRegion->EntryPoint, TrackedRegion->Entropy);

    }
	else if (!PageAlreadyTracked)
        DoOutputDebugString("AddTrackedRegion: New region at 0x%p size 0x%x added to tracked regions.\n", TrackedRegion->AllocationBase, TrackedRegion->RegionSize);

    return TrackedRegion;
}

//**************************************************************************************
BOOL DropTrackedRegion(PTRACKEDREGION TrackedRegion)
//**************************************************************************************
{
    PTRACKEDREGION CurrentTrackedRegion, PreviousTrackedRegion;

    if (TrackedRegion == NULL)
	{
        DoOutputDebugString("DropTrackedRegion: NULL passed as argument - error.\n");
        return FALSE;
	}

    PreviousTrackedRegion = NULL;

    if (TrackedRegionList == NULL)
	{
        DoOutputDebugString("DropTrackedRegion: failed to obtain initial tracked region list.\n");
        return FALSE;
	}

    CurrentTrackedRegion = TrackedRegionList;

	while (CurrentTrackedRegion)
	{
        DoOutputDebugString("DropTrackedRegion: CurrentTrackedRegion 0x%x, AllocationBase 0x%x.\n", CurrentTrackedRegion, CurrentTrackedRegion->AllocationBase);

        if (CurrentTrackedRegion == TrackedRegion)
        {
            // Clear any breakpoints in this region
            //ClearBreakpointsInRange(TrackedRegion->AllocationBase, TrackedRegion->RegionSize);

            // Unlink this from the list and free the memory
            if (PreviousTrackedRegion && CurrentTrackedRegion->NextTrackedRegion)
            {
                DoOutputDebugString("DropTrackedRegion: removed pages 0x%x-0x%x from tracked region list.\n", TrackedRegion->AllocationBase, (DWORD_PTR)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
                PreviousTrackedRegion->NextTrackedRegion = CurrentTrackedRegion->NextTrackedRegion;
            }
            else if (PreviousTrackedRegion && CurrentTrackedRegion->NextTrackedRegion == NULL)
            {
                DoOutputDebugString("DropTrackedRegion: removed pages 0x%x-0x%x from the end of the tracked region list.\n", TrackedRegion->AllocationBase, (DWORD_PTR)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
                PreviousTrackedRegion->NextTrackedRegion = NULL;
            }
            else if (!PreviousTrackedRegion)
            {
                DoOutputDebugString("DropTrackedRegion: removed pages 0x%x-0x%x from the head of the tracked region list.\n", TrackedRegion->AllocationBase, (DWORD_PTR)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
                TrackedRegionList = NULL;
            }

            free(CurrentTrackedRegion);

            return TRUE;
        }

		PreviousTrackedRegion = CurrentTrackedRegion;
        CurrentTrackedRegion = CurrentTrackedRegion->NextTrackedRegion;
	}

    DoOutputDebugString("DropTrackedRegion: failed to find tracked region in list.\n");

    return FALSE;
}

//**************************************************************************************
void ClearTrackedRegion(PTRACKEDREGION TrackedRegion)
//**************************************************************************************
{
    if (!TrackedRegion->AllocationBase || !TrackedRegion->RegionSize)
    {
        DoOutputDebugString("ClearTrackedRegion: Error, AllocationBase or RegionSize zero: 0x%p, 0x%p.\n", TrackedRegion->AllocationBase, TrackedRegion->RegionSize);
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
        DoOutputDebugString("ContextClearTrackedRegion: Failed to clear breakpoints.\n");
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
        DoOutputDebugString("ActivateGuardPages: NULL passed as argument - error.\n");
        return FALSE;
	}

    if (TrackedRegionList == NULL)
    {
        DoOutputDebugString("ActivateGuardPages: Error - no tracked region list.\n");
        return FALSE;
    }

    CurrentTrackedRegion = TrackedRegionList;

	while (CurrentTrackedRegion)
	{
        //DoOutputDebugString("TrackedRegion->AllocationBase 0x%x, CurrentTrackedRegion->AllocationBase 0x%x.\n", TrackedRegion->AllocationBase, CurrentTrackedRegion->AllocationBase);

         __try
        {
            TestAddress = CurrentTrackedRegion->AllocationBase;
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            DoOutputErrorString("ActivateGuardPages: Exception trying to access BaseAddres from tracked region at 0x%x", CurrentTrackedRegion);
            return FALSE;
        }

        if (TrackedRegion->AllocationBase == CurrentTrackedRegion->AllocationBase)
            TrackedRegionFound = TRUE;

        CurrentTrackedRegion = CurrentTrackedRegion->NextTrackedRegion;
	}

    if (!TrackedRegionFound)
    {
        DoOutputDebugString("ActivateGuardPages: failed to locate tracked region(s) in tracked region list.\n");
        return FALSE;
    }

    MatchingRegionSize = VirtualQuery(TrackedRegion->AllocationBase, &TrackedRegion->MemInfo, sizeof(MEMORY_BASIC_INFORMATION));

    if (!MatchingRegionSize)
    {
        DoOutputErrorString("ActivateGuardPages: failed to query tracked region(s) status in region 0x%x-0x%x", TrackedRegion->AllocationBase, (DWORD_PTR)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
        return FALSE;
    }

    //DoOutputDebugString("ActivateGuardPages: BaseAddress 0x%x, AllocationBase 0x%x, AllocationProtect 0x%x, RegionSize 0x%x, State 0x%x, Protect 0x%x, Type 0x%x\n", TrackedRegion->MemInfo.BaseAddress, TrackedRegion->MemInfo.AllocationBase, TrackedRegion->MemInfo.AllocationProtect, TrackedRegion->MemInfo.RegionSize, TrackedRegion->MemInfo.State, TrackedRegion->MemInfo.Protect, TrackedRegion->MemInfo.Type);

    if (MatchingRegionSize == TrackedRegion->RegionSize && TrackedRegion->MemInfo.Protect & PAGE_GUARD)
    {
        DoOutputDebugString("ActivateGuardPages: guard page(s) already set in region 0x%x-0x%x", TrackedRegion->AllocationBase, (DWORD_PTR)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
        return FALSE;
    }

    if (!VirtualProtect(TrackedRegion->AllocationBase, TrackedRegion->RegionSize, TrackedRegion->Protect | PAGE_GUARD, &OldProtect))
    {
        DoOutputErrorString("ActivateGuardPages: failed to activate guard page(s) on region 0x%x size 0x%x", TrackedRegion->AllocationBase, TrackedRegion->RegionSize);
        return FALSE;
    }

    //DoOutputDebugString("ActivateGuardPages: Activated guard page(s) on region 0x%x size 0x%x", TrackedRegion->AllocationBase, TrackedRegion->RegionSize);

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
        DoOutputDebugString("ActivateGuardPagesOnProtectedRange: NULL passed as argument - error.\n");
        return FALSE;
	}

    if (!SystemInfo.dwPageSize)
        GetSystemInfo(&SystemInfo);

    if (!SystemInfo.dwPageSize)
    {
        DoOutputErrorString("ActivateGuardPagesOnProtectedRange: Failed to obtain system page size.\n");
        return 0;
    }

    if (TrackedRegionList == NULL)
    {
        DoOutputDebugString("ActivateGuardPagesOnProtectedRange: Error - no tracked region list.\n");
        return FALSE;
    }

    CurrentTrackedRegion = TrackedRegionList;

	while (CurrentTrackedRegion)
	{
        //DoOutputDebugString("TrackedRegion->AllocationBase 0x%x, CurrentTrackedRegion->AllocationBase 0x%x.\n", TrackedRegion->AllocationBase, CurrentTrackedRegion->AllocationBase);

        __try
        {
            TestAddress = CurrentTrackedRegion->AllocationBase;
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            DoOutputErrorString("ActivateGuardPagesOnProtectedRange: Exception trying to access AllocationBase from tracked region at 0x%x", CurrentTrackedRegion);
            return FALSE;
        }

        if (TrackedRegion->AllocationBase == CurrentTrackedRegion->AllocationBase)
            TrackedRegionFound = TRUE;

        CurrentTrackedRegion = CurrentTrackedRegion->NextTrackedRegion;
	}

    if (!TrackedRegionFound)
    {
        DoOutputDebugString("ActivateGuardPagesOnProtectedRange: failed to locate tracked region(s) in tracked region list.\n");
        return FALSE;
    }

    if (!TrackedRegion->ProtectAddress || !TrackedRegion->RegionSize)
    {
        DoOutputDebugString("ActivateGuardPagesOnProtectedRange: Protect address or size zero: 0x%x, 0x%x.\n", TrackedRegion->ProtectAddress, TrackedRegion->RegionSize);
        return FALSE;
    }

    if (!VirtualQuery(TrackedRegion->AllocationBase, &TrackedRegion->MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
    {
        DoOutputErrorString("ActivateGuardPagesOnProtectedRange: unable to query memory region 0x%x", TrackedRegion->AllocationBase);
        return FALSE;
    }

    AddressOfPage = ((DWORD_PTR)TrackedRegion->ProtectAddress/SystemInfo.dwPageSize)*SystemInfo.dwPageSize;

    Size = (BYTE*)TrackedRegion->ProtectAddress + TrackedRegion->RegionSize - (BYTE*)AddressOfPage;

    if (!VirtualProtect((PVOID)AddressOfPage, Size, TrackedRegion->Protect | PAGE_GUARD, &OldProtect))
    {
        DoOutputErrorString("ActivateGuardPagesOnProtectedRange: failed to activate guard page(s) on region 0x%x size 0x%x", AddressOfPage, Size);
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
        DoOutputDebugString("DeactivateGuardPages: NULL passed as argument - error.\n");
        return FALSE;
	}

    if (TrackedRegionList == NULL)
    {
        DoOutputDebugString("DeactivateGuardPages: Error - no tracked region list.\n");
        return FALSE;
    }

    //DoOutputDebugString("DeactivateGuardPages: DEBUG - tracked region list 0x%x, BaseAddress 0x%x.\n", CurrentTrackedRegion, CurrentTrackedRegion->AllocationBase);

	while (CurrentTrackedRegion)
	{
        __try
        {
            TestAddress = CurrentTrackedRegion->AllocationBase;
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            DoOutputErrorString("DeactivateGuardPages: Exception trying to access BaseAddres from tracked region at 0x%x", CurrentTrackedRegion);
            return FALSE;
        }

        if (TrackedRegion->AllocationBase == CurrentTrackedRegion->AllocationBase)
            TrackedRegionFound = TRUE;

        CurrentTrackedRegion = CurrentTrackedRegion->NextTrackedRegion;
	}

    if (!TrackedRegionFound)
    {
        DoOutputDebugString("DeactivateGuardPages: failed to locate tracked region(s) in tracked region list.\n");
        return FALSE;
    }

    MatchingRegionSize = VirtualQuery(TrackedRegion->AllocationBase, &TrackedRegion->MemInfo, sizeof(MEMORY_BASIC_INFORMATION));

    if (!MatchingRegionSize)
    {
        DoOutputErrorString("DeactivateGuardPages: failed to query tracked region(s) status in region 0x%x-0x%x", TrackedRegion->AllocationBase, (DWORD_PTR)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
        return FALSE;
    }

    if (MatchingRegionSize == TrackedRegion->RegionSize && !(TrackedRegion->MemInfo.Protect & PAGE_GUARD))
    {
        DoOutputDebugString("DeactivateGuardPages: guard page(s) not set in region 0x%x-0x%x", TrackedRegion->AllocationBase, (DWORD_PTR)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
        return FALSE;
    }

    if (!VirtualProtect(TrackedRegion->AllocationBase, TrackedRegion->RegionSize, TrackedRegion->Protect, &OldProtect))
    {
        DoOutputErrorString("DeactivateGuardPages: failed to deactivate guard page(s) on region 0x%x-0x%x", TrackedRegion->AllocationBase, (DWORD_PTR)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
        return FALSE;
    }

    DoOutputDebugString("DeactivateGuardPages: DEBUG: Deactivated guard page(s) on region 0x%x-0x%x", TrackedRegion->AllocationBase, (DWORD_PTR)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);

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
        DoOutputDebugString("ActivateSurroundingGuardPages: Error - TrackedRegionList NULL.\n");
        return 0;
    }

    if (!SystemInfo.dwPageSize)
        GetSystemInfo(&SystemInfo);

    if (!SystemInfo.dwPageSize)
    {
        DoOutputErrorString("ActivateSurroundingGuardPages: Failed to obtain system page size.\n");
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
            DoOutputErrorString("ActivateSurroundingGuardPages: Exception trying to access BaseAddres from tracked region at 0x%x", CurrentTrackedRegion);
            return FALSE;
        }

        if (TrackedRegion->AllocationBase == CurrentTrackedRegion->AllocationBase)
            TrackedRegionFound = TRUE;

        CurrentTrackedRegion = CurrentTrackedRegion->NextTrackedRegion;
	}

    if (!TrackedRegionFound)
    {
        DoOutputDebugString("ActivateSurroundingGuardPages: Failed to locate tracked region(s) in tracked region list.\n");
        return FALSE;
    }

    if (!TrackedRegion->LastAccessAddress)
    {
        DoOutputDebugString("ActivateSurroundingGuardPages: Error - Last access address not set.\n");
        return 0;
    }

    if ((DWORD_PTR)TrackedRegion->LastAccessAddress < (DWORD_PTR)TrackedRegion->AllocationBase || (DWORD_PTR)TrackedRegion->LastAccessAddress >= ((DWORD_PTR)TrackedRegion->AllocationBase + (DWORD_PTR)TrackedRegion->RegionSize))
    {
        DoOutputDebugString("ActivateSurroundingGuardPages: Last access address 0x%x not within tracked region at 0x%x.\n", TrackedRegion->LastAccessAddress, TrackedRegion->AllocationBase);
        return FALSE;
    }

    AddressOfPage = ((DWORD_PTR)TrackedRegion->LastAccessAddress/SystemInfo.dwPageSize)*SystemInfo.dwPageSize;

    if (!VirtualQuery(TrackedRegion->AllocationBase, &TrackedRegion->MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
    {
        DoOutputErrorString("ActivateSurroundingGuardPages: unable to query memory region 0x%x", TrackedRegion->AllocationBase);
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
                DoOutputDebugString("ActivateSurroundingGuardPages: Failed to activate page guard on tracked region at 0x%x.\n", PagePointer);
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
    BOOL TrackedRegionFound;
    PVOID BaseAddress;
    SIZE_T Size;

    if (TrackedRegion == NULL)
	{
        DoOutputDebugString("DumpPEsInTrackedRegion: NULL passed as argument - error.\n");
        return FALSE;
	}

    if (TrackedRegionList == NULL)
    {
        DoOutputDebugString("DumpPEsInTrackedRegion: Error - no tracked region list.\n");
        return FALSE;
    }

    CurrentTrackedRegion = TrackedRegionList;

    __try
    {
        while (CurrentTrackedRegion)
        {
            //DEBUG
            //DoOutputDebugString("DumpPEsInTrackedRegion: Debug: CurrentTrackedRegion 0x%p.\n", CurrentTrackedRegion);
            if (CurrentTrackedRegion->AllocationBase == TrackedRegion->AllocationBase)
                TrackedRegionFound = TRUE;

            CurrentTrackedRegion = CurrentTrackedRegion->NextTrackedRegion;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DoOutputErrorString("DumpPEsInTrackedRegion: Exception trying to access BaseAddress from tracked region at 0x%p", TrackedRegion);
        return FALSE;
    }

    if (TrackedRegionFound == FALSE)
    {
        DoOutputDebugString("DumpPEsInTrackedRegion: failed to locate tracked region(s) in tracked region list.\n");
        return FALSE;
    }

    //DEBUG
    //DoOutputDebugString("DumpPEsInTrackedRegion: Found tracked region at 0x%p.\n", CurrentTrackedRegion);

    __try
    {
        BaseAddress = TrackedRegion->AllocationBase;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DoOutputErrorString("DumpPEsInTrackedRegion: Exception trying to access BaseAddress from tracked region at 0x%p", TrackedRegion);
        return FALSE;
    }

    //DEBUG
    //DoOutputDebugString("DumpPEsInTrackedRegion: Debug: about to scan for PE image(s).\n");

    if (!VirtualQuery(TrackedRegion->AllocationBase, &TrackedRegion->MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
    {
        DoOutputErrorString("DumpPEsInTrackedRegion: unable to query memory region 0x%p", TrackedRegion->AllocationBase);
        return FALSE;
    }

    if ((DWORD_PTR)TrackedRegion->AllocationBase < (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase)
    {
        DoOutputDebugString("DumpPEsInTrackedRegion: Anomaly detected - AllocationBase 0x%p below MemInfo.AllocationBase 0x%p.\n", TrackedRegion->AllocationBase, TrackedRegion->MemInfo.AllocationBase);
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
    SetCapeMetaData(EXTRACTION_PE, 0, NULL, BaseAddress);
    PEsDumped = DumpPEsInRange(BaseAddress, Size);

    if (PEsDumped)
    {
        DoOutputDebugString("DumpPEsInTrackedRegion: Dumped %d PE image(s) from range 0x%p - 0x%p.\n", PEsDumped, BaseAddress, (BYTE*)BaseAddress + Size);
        TrackedRegion->PagesDumped = TRUE;
    }
    else
        DoOutputDebugString("DumpPEsInTrackedRegion: No PE images found in range range 0x%p - 0x%p.\n", BaseAddress, (BYTE*)BaseAddress + Size);

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

    DoOutputDebugString("ProcessImageBase: EP 0x%p image base 0x%p size 0x%x entropy %e.\n", EntryPoint, TrackedRegion->AllocationBase, MinPESize, Entropy);
    if (TrackedRegion->EntryPoint && (TrackedRegion->EntryPoint != EntryPoint))
        DoOutputDebugString("ProcessImageBase: Modified entry point (0x%p) detected at image base 0x%p - dumping.\n", EntryPoint, TrackedRegion->AllocationBase);
    else if (TrackedRegion->MinPESize && TrackedRegion->MinPESize != MinPESize)
        DoOutputDebugString("ProcessImageBase: Modified PE size detected at image base 0x%p - new size 0x%x.\n", TrackedRegion->AllocationBase, MinPESize);
    else if (TrackedRegion->Entropy && fabs(TrackedRegion->Entropy - Entropy) > (double)ENTROPY_DELTA)
        DoOutputDebugString("ProcessImageBase: Modified image detected at image base 0x%p - new entropy %e.\n", TrackedRegion->AllocationBase, Entropy);
    else
        return;

    TrackedRegion->EntryPoint = EntryPoint;
    TrackedRegion->MinPESize = MinPESize;
    TrackedRegion->Entropy = Entropy;

    SetCapeMetaData(EXTRACTION_PE, 0, NULL, TrackedRegion->AllocationBase);

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
        DoOutputDebugString("ProcessTrackedRegion: Found and dumped PE image(s) in range 0x%p - 0x%p.\n", TrackedRegion->AllocationBase, (BYTE*)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
        ClearTrackedRegion(TrackedRegion);
    }
    else
    {
        SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, TrackedRegion->AllocationBase);

        TrackedRegion->PagesDumped = DumpMemory(TrackedRegion->AllocationBase, TrackedRegion->RegionSize);

        if (TrackedRegion->PagesDumped)
        {
            DoOutputDebugString("ProcessTrackedRegion: dumped executable memory range at 0x%p.\n", TrackedRegion->AllocationBase);
            ClearTrackedRegion(TrackedRegion);
        }
        else
            DoOutputDebugString("ProcessTrackedRegion: failed to dump executable memory range at 0x%p.\n", TrackedRegion->AllocationBase);
    }
}

//**************************************************************************************
void ProcessTrackedRegions()
//**************************************************************************************
{
    PTRACKEDREGION TrackedRegion = TrackedRegionList;

    while (TrackedRegion)
    {
        DoOutputDebugString("ProcessTrackedRegions: Processing region at 0x%p.\n", TrackedRegion->AllocationBase);
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
        DoOutputDebugString("AllocationHandler: Error, BaseAddress or RegionSize zero: 0x%p, 0x%p.\n", BaseAddress, RegionSize);
        return;
    }

    // We limit tracking to executable regions
    if (!(Protect & EXECUTABLE_FLAGS))
        return;

    DoOutputDebugString("Allocation: 0x%p - 0x%p, size: 0x%x, protection: 0x%x.\n", BaseAddress, (PUCHAR)BaseAddress + RegionSize, RegionSize, Protect);

    hook_disable();
    ProcessTrackedRegions();

    if (TrackedRegionList)
        TrackedRegion = GetTrackedRegion(BaseAddress);
    else
        TrackedRegion = NULL;

    // if memory was previously reserved but not committed
    if (TrackedRegion && !TrackedRegion->Committed && (AllocationType & MEM_COMMIT))
    {
        DoOutputDebugString("AllocationHandler: Previously reserved region 0x%p - 0x%p, committing at: 0x%p.\n", TrackedRegion->AllocationBase, (PUCHAR)TrackedRegion->AllocationBase + TrackedRegion->RegionSize, BaseAddress);

        if (TrackedRegion->AllocationBase != BaseAddress)
            TrackedRegion->ProtectAddress = BaseAddress;
    }
    else if (TrackedRegion && (AllocationType & MEM_RESERVE))
    {
        DoOutputDebugString("AllocationHandler: Re-reserving region at: 0x%p.\n", BaseAddress);
        hook_enable();
        return;
    }
    else if (TrackedRegion)
    {
        // The region allocated is with a region already tracked
        DoOutputDebugString("AllocationHandler: New allocation already in tracked region list: 0x%p, size: 0x%x.\n", TrackedRegion->AllocationBase, TrackedRegion->RegionSize);
        hook_enable();
        return;
    }
    else
    {
        DoOutputDebugString("AllocationHandler: Adding allocation to tracked region list: 0x%p, size: 0x%x.\n", BaseAddress, RegionSize);
        TrackedRegion = AddTrackedRegion(BaseAddress, RegionSize, Protect);
    }

    if (!TrackedRegion)
    {
        DoOutputDebugString("AllocationHandler: Error, unable to locate or add allocation in tracked region list: 0x%p.\n", BaseAddress);
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
                    DoOutputDebugString("AllocationHandler: Breakpoints set on newly-allocated executable region at: 0x%p (size 0x%x).\n", BaseAddress, RegionSize);
                else
                    DoOutputDebugString("AllocationHandler: Error - unable to activate breakpoints around address 0x%p.\n", BaseAddress);
            }
            else
            {
                TrackedRegion->Guarded = ActivateGuardPages(TrackedRegion);
                //TrackedRegion->Guarded = ActivateGuardPagesOnProtectedRange(TrackedRegion);

                if (TrackedRegion->Guarded)
                    DoOutputDebugString("AllocationHandler: Guarded newly-allocated executable region at 0x%p, size 0x%x.\n", BaseAddress, RegionSize);
                else
                    DoOutputDebugString("AllocationHandler: Error - failed to guard newly allocated executable region at: 0x%p.\n", BaseAddress);

            }
        }
        else
            DoOutputDebugString("AllocationHandler: Non-executable region at 0x%p tracked but not guarded.\n", BaseAddress);
    }
    else
    {   // Allocation not committed, so we can't set guard pages or breakpoints yet
        TrackedRegion->Committed = FALSE;
        TrackedRegion->Guarded = FALSE;
        DoOutputDebugString("AllocationHandler: Memory reserved but not committed at 0x%p.\n", BaseAddress);
    }

    hook_enable();

    return;
}

//**************************************************************************************
void ProtectionHandler(PVOID Address, SIZE_T RegionSize, ULONG Protect, ULONG OldProtect)
//**************************************************************************************
{
    //DWORD EntryPoint;
    BOOL NewRegion;
    SIZE_T TrackedRegionSize;
    PTRACKEDREGION TrackedRegion = NULL;

    if (!DebuggerInitialised)
        return;

    if (!Address || !RegionSize)
    {
        DoOutputDebugString("ProtectionHandler: Error, Address or RegionSize zero: 0x%p, 0x%x.\n", Address, RegionSize);
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
    //    DoOutputDebugString("ProtectionHandler: Current tracked region has already been dumped.\n");
    //    hook_enable();
    //    return;
    //}

    // If a previously-untracked region already has code, we may want to dump
    if (!TrackedRegion)
    {
        ProcessTrackedRegions();
        DoOutputDebugString("ProtectionHandler: Adding region at 0x%p to tracked regions.\n", Address);
        TrackedRegion = AddTrackedRegion(Address, RegionSize, Protect);
        NewRegion = TRUE;
    }
    else
    {
        DoOutputDebugString("ProtectionHandler: Address 0x%p already in tracked region at 0x%p, size 0x%x\n", Address, TrackedRegion->AllocationBase, TrackedRegion->RegionSize);
    }

    if (!TrackedRegion)
    {
        DoOutputDebugString("ProtectionHandler: Error, unable to add new region at 0x%p to tracked region list.\n", Address);
        hook_enable();
        return;
    }

    if (!VirtualQuery(Address, &TrackedRegion->MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
    {
        DoOutputErrorString("ProtectionHandler: unable to query memory region 0x%p", Address);
        hook_enable();
        return;
    }

    TrackedRegion->AllocationBase = TrackedRegion->MemInfo.AllocationBase;
    DoOutputDebugString("ProtectionHandler: Address: 0x%p (alloc base 0x%p), NumberOfBytesToProtect: 0x%x, NewAccessProtection: 0x%x\n", Address, TrackedRegion->AllocationBase, RegionSize, Protect);

    TrackedRegionSize = (SIZE_T)((PBYTE)Address + RegionSize - (PBYTE)TrackedRegion->AllocationBase);

    if (TrackedRegion->RegionSize < TrackedRegionSize)
    {
        TrackedRegion->RegionSize = TrackedRegionSize;
        DoOutputDebugString("ProtectionHandler: Increased region size at 0x%p to 0x%x.\n", Address, TrackedRegionSize);
    }

    if (TrackedRegion->Protect != Protect)
    {
        TrackedRegion->Protect = Protect;
        DoOutputDebugString("ProtectionHandler: Updated region protection at 0x%p to 0x%x.\n", Address, Protect);
    }

    if (TrackedRegion->AllocationBase == ImageBase || TrackedRegion->AllocationBase == GetModuleHandle(NULL))
    {
        ProcessImageBase(TrackedRegion);
        hook_enable();
        return;
    }

    //if (ScanForNonZero(Address, RegionSize))
    if ((NewRegion || OldProtect & WRITABLE_FLAGS) && ScanForNonZero(TrackedRegion->AllocationBase, TrackedRegion->RegionSize))
    {
        DoOutputDebugString("ProtectionHandler: New code detected at (0x%p), scanning for PE images.\n", TrackedRegion->AllocationBase);

        SetCapeMetaData(EXTRACTION_PE, 0, NULL, TrackedRegion->AllocationBase);
        TrackedRegion->PagesDumped = DumpPEsInTrackedRegion(TrackedRegion);

        if (TrackedRegion->PagesDumped)
        {
            DoOutputDebugString("ProtectionHandler: PE image(s) dumped from 0x%p.\n", TrackedRegion->AllocationBase);
            ClearTrackedRegion(TrackedRegion);
            hook_enable();
            return;
        }
#ifdef DEBUG_COMMENTS
        else
            DoOutputDebugString("ProtectionHandler: No PE images found in region at 0x%p, size 0x%x\n", TrackedRegion->AllocationBase, TrackedRegion->RegionSize);
#endif
        if (!(Protect & WRITABLE_FLAGS))
        {
            SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, Address);
            if (DumpMemory(TrackedRegion->AllocationBase, TrackedRegion->RegionSize))
            {
                DoOutputDebugString("ProtectionHandler: dumped memory (sub)region at 0x%p, size 0x%x\n", TrackedRegion->AllocationBase, TrackedRegion->RegionSize);
                hook_enable();
                return;
            }
            else
                DoOutputDebugString("ProtectionHandler: Failed to dump range at 0x%p, size 0x%x\n", TrackedRegion->AllocationBase, TrackedRegion->RegionSize);
        }
    }
#ifdef DEBUG_COMMENTS
    else
        DoOutputDebugString("ProtectionHandler: No action taken on empty protected region at 0x%p.\n", TrackedRegion->AllocationBase);
#endif

    TrackedRegion->ProtectAddress = Address;

    if (Protect != TrackedRegion->Protect)
    {
        DoOutputDebugString("ProtectionHandler: updating protection of tracked region around 0x%p.\n", Address);
        TrackedRegion->Protect = Protect;
    }

    if (GuardPagesDisabled)
    {
        TrackedRegion->BreakpointsSet = ActivateBreakpoints(TrackedRegion, NULL);

        if (TrackedRegion->BreakpointsSet)
            DoOutputDebugString("ProtectionHandler: Breakpoints set on executable region at: 0x%p.\n", Address);
        else
            DoOutputDebugString("ProtectionHandler: Error - unable to activate breakpoints around address 0x%p.\n", Address);
    }
    else
    {
        TrackedRegion->Guarded = ActivateGuardPages(TrackedRegion);
        //TrackedRegion->Guarded = ActivateGuardPagesOnProtectedRange(TrackedRegion);

        if (TrackedRegion->Guarded)
            DoOutputDebugString("ProtectionHandler: Guarded executable region at: 0x%p.\n", Address);
        else
            DoOutputDebugString("ProtectionHandler: Error - unable to activate guard pages around address 0x%p.\n", Address);
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
        DoOutputDebugString("FreeHandler: Error, BaseAddress zero.\n");
        return;
    }

    TrackedRegion = GetTrackedRegion(BaseAddress);

    if (TrackedRegion == NULL)
        return;

    DoOutputDebugString("FreeHandler: Address: 0x%p.\n", BaseAddress);

    hook_disable();

    if (TrackedRegion->Committed == TRUE && ScanForNonZero(TrackedRegion->AllocationBase, TrackedRegion->RegionSize) && !TrackedRegion->PagesDumped)
    {
        TrackedRegion->PagesDumped = DumpPEsInTrackedRegion(TrackedRegion);

        if (TrackedRegion->PagesDumped)
            DoOutputDebugString("FreeHandler: Found and dumped PE image(s) in range 0x%p - 0x%p.\n", TrackedRegion->AllocationBase, (BYTE*)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
        else if (TrackedRegion->Protect & EXECUTABLE_FLAGS)
        {
            SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, TrackedRegion->AllocationBase);

            TrackedRegion->Entropy = GetEntropy(TrackedRegion->AllocationBase);

            TrackedRegion->PagesDumped = DumpMemory(TrackedRegion->AllocationBase, TrackedRegion->RegionSize);

            if (TrackedRegion->PagesDumped)
                DoOutputDebugString("FreeHandler: dumped executable memory range at 0x%p prior to its freeing.\n", TrackedRegion->AllocationBase);
            else
                DoOutputDebugString("FreeHandler: failed to dump executable memory range at 0x%p prior to its freeing.\n", TrackedRegion->AllocationBase);
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
        DoOutputDebugString("ModloadHandler: Error, BaseAddress zero.\n");
        return;
    }

    TrackedRegion = GetTrackedRegion((PVOID)BaseAddress);

    if (TrackedRegion == NULL)
        return;

    DoOutputDebugString("ModloadHandler: Address: 0x%p.\n", BaseAddress);

    hook_disable();

    if (ScanForNonZero(TrackedRegion->AllocationBase, TrackedRegion->RegionSize) && !TrackedRegion->PagesDumped)
    {
        TrackedRegion->PagesDumped = DumpPEsInTrackedRegion(TrackedRegion);

        if (TrackedRegion->PagesDumped)
            DoOutputDebugString("ModloadHandler: Dumped module at 0x%p.\n", TrackedRegion->AllocationBase);
        else
            DoOutputDebugString("ModloadHandler: failed to dump executable memory range at 0x%p prior to its freeing.\n", TrackedRegion->AllocationBase);
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
        DoOutputDebugString("NewThreadHandler: Error, StartAddress zero.\n");
        return;
    }

    TrackedRegion = GetTrackedRegion((PVOID)StartAddress);

    if (TrackedRegion == NULL)
        return;

    DoOutputDebugString("NewThreadHandler: Address: 0x%p.\n", StartAddress);

    hook_disable();

    if (ScanForNonZero(TrackedRegion->AllocationBase, TrackedRegion->RegionSize) && !TrackedRegion->PagesDumped)
    {
        TrackedRegion->PagesDumped = DumpPEsInTrackedRegion(TrackedRegion);

        if (TrackedRegion->PagesDumped)
            DoOutputDebugString("NewThreadHandler: Dumped module at 0x%p.\n", TrackedRegion->AllocationBase);
        else
            DoOutputDebugString("NewThreadHandler: Failed to dump new thread's executable memory range at 0x%p .\n", TrackedRegion->AllocationBase);
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
        DoOutputErrorString("StepOverGuardPageFault: Failed to obtain system page size.\n");
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
                DoOutputDebugString("StepOverGuardPageFault error: GuardedPagesToStep not set.\n");
                return FALSE;
            }

            LastAccessPage = ((DWORD_PTR)TrackedRegion->LastAccessAddress/SystemInfo.dwPageSize)*SystemInfo.dwPageSize;
            ProtectAddressPage = ((DWORD_PTR)TrackedRegion->ProtectAddress/SystemInfo.dwPageSize)*SystemInfo.dwPageSize;

            //DoOutputDebugString("StepOverGuardPageFault: DEBUG Base 0x%p LastAccess 0x%p by 0x%p (LW 0x%p LR 0x%p).\n", TrackedRegion->AllocationBase, TrackedRegion->LastAccessAddress, TrackedRegion->LastAccessBy, TrackedRegion->LastWriteAddress, TrackedRegion->LastReadAddress);

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
                        DoOutputDebugString("StepOverGuardPageFault: Anomaly detected - switched to breakpoints for initial page, but guard pages still being hit.\n");

                        //DoOutputDebugString("StepOverGuardPageFault: Debug: Last write at 0x%p by 0x%p, last read at 0x%p by 0x%p.\n", TrackedRegion->LastWriteAddress, TrackedRegion->LastWrittenBy, TrackedRegion->LastReadAddress, TrackedRegion->LastReadBy);

                        return FALSE;
                    }

                    DoOutputDebugString("StepOverGuardPageFault: Write counter hit limit, switching to breakpoints.\n");

                    if (ActivateBreakpoints(TrackedRegion, ExceptionInfo))
                    {
                        //DoOutputDebugString("StepOverGuardPageFault: Switched to breakpoints on first tracked region.\n");

                        //DoOutputDebugString("StepOverGuardPageFault: Debug: Last write at 0x%p by 0x%p, last read at 0x%p by 0x%p.\n", TrackedRegion->LastWriteAddress, TrackedRegion->LastWrittenBy, TrackedRegion->LastReadAddress, TrackedRegion->LastReadBy);

                        TrackedRegion->BreakpointsSet = TRUE;
                        GuardedPagesToStep = NULL;
                        LastEIP = (DWORD_PTR)NULL;
                        CurrentEIP = (DWORD_PTR)NULL;
                        return TRUE;
                    }
                    else
                    {
                        DoOutputDebugString("StepOverGuardPageFault: Failed to set breakpoints on first tracked region.\n");
                        return FALSE;
                    }
                }
                else if (ActivateGuardPages(TrackedRegion))
                {
                    //DoOutputDebugString("StepOverGuardPageFault: 0x%p - Reactivated page guard on first tracked region.\n", TrackedRegion->LastAccessAddress);

                    GuardedPagesToStep = NULL;
                    LastEIP = (DWORD_PTR)NULL;
                    CurrentEIP = (DWORD_PTR)NULL;
                    return TRUE;
                }
                else
                {
                    DoOutputDebugString("StepOverGuardPageFault: Failed to activate page guard on first tracked region.\n");
                    return FALSE;
                }
            }
            else if (LastAccessPage == ProtectAddressPage)
            {
                if (ActivateGuardPages(TrackedRegion))
                {
                    //DoOutputDebugString("StepOverGuardPageFault: 0x%p - Reactivated page guard on page containing protect address.\n", TrackedRegion->LastAccessAddress);
                    GuardedPagesToStep = NULL;
                    LastEIP = (DWORD_PTR)NULL;
                    CurrentEIP = (DWORD_PTR)NULL;
                    return TRUE;
                }
                else
                {
                    DoOutputDebugString("StepOverGuardPageFault: Failed to activate page guard on page containing protect address.\n");
                    return FALSE;
                }
            }
            else
            {
                if (ActivateSurroundingGuardPages(TrackedRegion))
                {
                    //DoOutputDebugString("StepOverGuardPageFault: 0x%p - Reactivated page guard on surrounding pages.\n", TrackedRegion->LastAccessAddress);
                    GuardedPagesToStep = NULL;
                    LastEIP = (DWORD_PTR)NULL;
                    CurrentEIP = (DWORD_PTR)NULL;
                    return TRUE;
                }
                else
                {
                    DoOutputDebugString("StepOverGuardPageFault: Failed to activate page guard on surrounding pages.\n");
                    return FALSE;
                }
            }

            DoOutputDebugString("StepOverGuardPageFault: Failed to activate page guards.\n");
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
            DoOutputDebugString("StepOverGuardPageFault error: GuardedPagesToStep not set.\n");
            return FALSE;
        }


        SetSingleStepMode(ExceptionInfo->ContextRecord, StepOverGuardPageFault);
        return TRUE;
    }
}

//**************************************************************************************
BOOL ExtractionGuardPageHandler(struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
    DWORD AccessType        = (DWORD)ExceptionInfo->ExceptionRecord->ExceptionInformation[0];
    PVOID AccessAddress     = (PVOID)ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
    PVOID FaultingAddress   = (PVOID)ExceptionInfo->ExceptionRecord->ExceptionAddress;

    PTRACKEDREGION TrackedRegion = GetTrackedRegion(AccessAddress);

    if (TrackedRegion == NULL)
    {
        DoOutputDebugString("ExtractionGuardPageHandler error: address 0x%p not in tracked regions.\n", AccessAddress);
        return FALSE;
    }

    // add check of whether pages *should* be guarded
    // i.e. internal consistency

    switch (AccessType)
    {
        case EXCEPTION_WRITE_FAULT:

            //DoOutputDebugString("ExtractionGuardPageHandler: Write detected at 0x%p by 0x%p\n", AccessAddress, FaultingAddress);

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

            DoOutputDebugString("ExtractionGuardPageHandler: Execution detected at 0x%p\n", AccessAddress);

            if (AccessAddress != FaultingAddress)
            {
                DoOutputDebugString("ExtractionGuardPageHandler: Anomaly detected - AccessAddress != FaultingAddress (0x%p, 0x%p).\n", AccessAddress, FaultingAddress);
            }

            TrackedRegion->LastAccessAddress = AccessAddress;

            if (!(TrackedRegion->Protect & EXECUTABLE_FLAGS))
            {
                DoOutputDebugString("ExtractionGuardPageHandler: Anomaly detected - pages not marked with execute flag in tracked region list.\n");
            }

            if (!TrackedRegion->PagesDumped)
            {
                DoOutputDebugString("ExtractionGuardPageHandler: Execution within guarded page detected, dumping.\n");

                if (!GuardPagesDisabled && DeactivateGuardPages(TrackedRegion))
                {
                    if (DumpPEsInTrackedRegion(TrackedRegion))
                        TrackedRegion->PagesDumped = TRUE;

                    if (TrackedRegion->PagesDumped)
                        DoOutputDebugString("ExtractionGuardPageHandler: PE image(s) detected and dumped.\n");
                    else
                    {
                        SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, TrackedRegion->AllocationBase);

                        TrackedRegion->Entropy = GetEntropy(TrackedRegion->AllocationBase);

                        TrackedRegion->PagesDumped = DumpMemory(TrackedRegion->AllocationBase, TrackedRegion->RegionSize);

                        if (TrackedRegion->PagesDumped)
                            DoOutputDebugString("ExtractionGuardPageHandler: shellcode detected and dumped from range 0x%p - 0x%p.\n", TrackedRegion->AllocationBase, (BYTE*)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
                        else
                            DoOutputDebugString("ExtractionGuardPageHandler: failed to dump detected shellcode from range 0x%p - 0x%p.\n", TrackedRegion->AllocationBase, (BYTE*)TrackedRegion->AllocationBase + TrackedRegion->RegionSize);
                    }

                    ClearTrackedRegion(TrackedRegion);
                }
                else
                    DoOutputDebugString("ExtractionGuardPageHandler: Failed to disable guard pages for dump.\n");
            }

            break;

        default:
            DoOutputDebugString("ExtractionGuardPageHandler: Unknown access type: 0x%x - error.\n", AccessType);
            return FALSE;
    }

    return TRUE;
}

//**************************************************************************************
void ExtractionCallback(hook_info_t *hookinfo)
//**************************************************************************************
{
    if (hookinfo == NULL)
    {
        DoOutputDebugString("ExtractionCallback: Error, no hook info supplied.\n");
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
        DoOutputDebugString("ExtractionCallback: hooked call to %ws::%s from within tracked region (from hook) at 0x%p.\n", hookinfo->current_hook->library, hookinfo->current_hook->funcname, hookinfo->main_caller_retaddr);
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
		DoOutputDebugString("HookReturnCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("HookReturnCallback executed with NULL thread handle.\n");
		return FALSE;
	}

    TrackedRegion = TrackedRegionFromHook;
    TrackedRegionFromHook = NULL;

	if (TrackedRegion == NULL)
	{
		DoOutputDebugString("HookReturnCallback: no TrackedRegionFromHook (breakpoint %i at Address 0x%p).\n", pBreakpointInfo->Register, pBreakpointInfo->Address);
		return FALSE;
	}

	DoOutputDebugString("HookReturnCallback: Breakpoint %i at Address 0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

    SetCapeMetaData(EXTRACTION_PE, 0, NULL, TrackedRegion->AllocationBase);

    if (DumpPEsInTrackedRegion(TrackedRegion))
    {
        TrackedRegion->PagesDumped = TRUE;
        DoOutputDebugString("HookReturnCallback: successfully dumped module.\n");
        ContextClearTrackedRegion(ExceptionInfo->ContextRecord, TrackedRegion);
        return TRUE;
    }
    else
    {
        DoOutputDebugString("HookReturnCallback: failed to dump PE module.\n");
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
		DoOutputDebugString("OverlayWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("OverlayWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

    TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);

	if (TrackedRegion == NULL)
	{
		DoOutputDebugString("OverlayWriteCallback: unable to locate entry point address 0x%p in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	}

    TrackedRegion->EntryPoint = 0;

	DoOutputDebugString("OverlayWriteCallback: Breakpoint %i at Address 0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

    if (!(DWORD*)pBreakpointInfo->Address)
	{
		DoOutputDebugString("OverlayWriteCallback: Zero written, ignoring, leaving breakpoint in place.\n", pBreakpointInfo->Address);
		return TRUE;
	}

    ReturnAddress = GetReturnAddress(hook_info());

    if (ReturnAddress && !TrackedRegionFromHook)
    {
		if (InsideHook(NULL, ReturnAddress))
        {
            DoOutputDebugString("OverlayWriteCallback: We are in a hooked function with return address 0x%p.\n", ReturnAddress);
            if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, 0, ReturnAddress, BP_EXEC, HookReturnCallback))
            {
                DoOutputDebugString("OverlayWriteCallback: set exec bp on return address 0x%p.\n", ReturnAddress);
                TrackedRegionFromHook = TrackedRegion;
            }
            else
            {
                DoOutputDebugString("OverlayWriteCallback: Failed to set bp on return address 0x%p.\n", ReturnAddress);
            }
        }
        else
        {
            DoOutputDebugString("OverlayWriteCallback: Not in a hooked function, setting callback in enter_hook() to catch next hook (return address 0x%p).\n", ReturnAddress);
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
		DoOutputDebugString("FinalByteWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("FinalByteWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

    TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);

	if (TrackedRegion == NULL)
	{
		DoOutputDebugString("FinalByteWriteCallback: unable to locate entry point address 0x%p in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	}

    TrackedRegion->EntryPoint = 0;

	DoOutputDebugString("FinalByteWriteCallback: Breakpoint %i at Address 0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

    SetCapeMetaData(EXTRACTION_PE, 0, NULL, TrackedRegion->AllocationBase);

    if (DumpPEsInTrackedRegion(TrackedRegion))
    {
        TrackedRegion->PagesDumped = TRUE;
        DoOutputDebugString("FinalByteWriteCallback: successfully dumped module.\n");
        ContextClearTrackedRegion(ExceptionInfo->ContextRecord, TrackedRegion);
        return TRUE;
    }
    else
        DoOutputDebugString("FinalByteWriteCallback: failed to dump PE module.\n");

    ReturnAddress = GetReturnAddress(hook_info());

    if (ReturnAddress && !TrackedRegionFromHook)
    {
		if (InsideHook(NULL, ReturnAddress))
        {
            DoOutputDebugString("FinalByteWriteCallback: We are in a hooked function with return address 0x%p.\n", ReturnAddress);
            if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, 0, ReturnAddress, BP_EXEC, HookReturnCallback))
            {
                DoOutputDebugString("FinalByteWriteCallback: set exec bp on return address 0x%p.\n", ReturnAddress);
                TrackedRegionFromHook = TrackedRegion;
            }
            else
            {
                DoOutputDebugString("FinalByteWriteCallback: Failed to set bp on return address 0x%p.\n", ReturnAddress);
            }
        }
        else
        {
            DoOutputDebugString("FinalByteWriteCallback: Not in a hooked function, setting callback in enter_hook() to catch next hook (return address 0x%p).\n", ReturnAddress);
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
		DoOutputDebugString("FinalSectionHeaderWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("FinalSectionHeaderWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

    TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);

	if (TrackedRegion == NULL)
	{
		DoOutputDebugString("FinalSectionHeaderWriteCallback: unable to locate entry point address 0x%p in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	}

    TrackedRegion->EntryPoint = 0;

	DoOutputDebugString("FinalSectionHeaderWriteCallback: Breakpoint %i at Address 0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

    TrackedRegion->CanDump = TRUE;

    FinalSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD*)pBreakpointInfo->Address - 4);

    if (!FinalSectionHeader->VirtualAddress || !FinalSectionHeader->SizeOfRawData)
    {
        DoOutputDebugString("FinalSectionHeaderWriteCallback: current VirtualAddress and FinalSectionHeader->SizeOfRawData not valid: 0x%x, 0x%x (at 0x%p, 0x%p).\n", FinalSectionHeader->VirtualAddress, FinalSectionHeader->SizeOfRawData, (DWORD*)pBreakpointInfo->Address - 1, pBreakpointInfo->Address);
        return TRUE;
    }
    else
        DoOutputDebugString("FinalSectionHeaderWriteCallback: Section %s VirtualAddress: 0x%x, FinalSectionHeader->Misc.VirtualSize: 0x%x, FinalSectionHeader->SizeOfRawData: 0x%x.\n", FinalSectionHeader->Name, FinalSectionHeader->VirtualAddress, FinalSectionHeader->Misc.VirtualSize, FinalSectionHeader->SizeOfRawData);

    FinalByteAddress = (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData - 1;

    if (!ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(BYTE), FinalByteAddress, BP_WRITE, FinalByteWriteCallback))
    {
		DoOutputDebugString("FinalSectionHeaderWriteCallback: write bp set on final byte at 0x%p.\n", FinalByteAddress);
    }

    pNtHeader = GetNtHeaders(TrackedRegion->AllocationBase);

    if (FinalSectionHeader->Misc.VirtualSize && FinalSectionHeader->Misc.VirtualSize > FinalSectionHeader->SizeOfRawData)
        VirtualSize = FinalSectionHeader->SizeOfRawData;
    else
        VirtualSize = ((FinalSectionHeader->SizeOfRawData / pNtHeader->OptionalHeader.SectionAlignment) + 1) * pNtHeader->OptionalHeader.SectionAlignment;

    if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, NULL, sizeof(DWORD), (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + VirtualSize, BP_WRITE, OverlayWriteCallback))
        DoOutputDebugString("FinalSectionHeaderWriteCallback: Set write breakpoint on first byte of overlay at: 0x%p\n", (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + VirtualSize);
    else
        DoOutputDebugString("FinalSectionHeaderWriteCallback: Unable to set overlay breakpoint.\n");

	return TRUE;
}

//**************************************************************************************
BOOL EntryPointExecCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;

	if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("EntryPointExecCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("EntryPointExecCallback executed with NULL thread handle.\n");
		return FALSE;
	}

    TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);

	if (TrackedRegion == NULL)
	{
		DoOutputDebugString("EntryPointExecCallback: unable to locate entry point address 0x%p in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	}

	DoOutputDebugString("EntryPointExecCallback: Breakpoint %i at Address 0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

    ContextClearTrackedRegion(ExceptionInfo->ContextRecord, TrackedRegion);

    SetCapeMetaData(EXTRACTION_PE, 0, NULL, TrackedRegion->AllocationBase);

    if (DumpPEsInTrackedRegion(TrackedRegion))
    {
        TrackedRegion->PagesDumped = TRUE;
        DoOutputDebugString("EntryPointExecCallback: successfully dumped module.\n");
        return TRUE;
    }
    else
    {
        DoOutputDebugString("EntryPointExecCallback: failed to dump PE module.\n");
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
		DoOutputDebugString("EntryPointWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("EntryPointWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

    TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);

	if (TrackedRegion == NULL)
	{
		DoOutputDebugString("EntryPointWriteCallback: unable to locate entry point address 0x%p in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	}

    TrackedRegion->EntryPoint = 0;

	DoOutputDebugString("EntryPointWriteCallback: Breakpoint %i at Address 0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

    if ((DWORD_PTR)pBreakpointInfo->Address < (DWORD_PTR)TrackedRegion->AllocationBase || (DWORD_PTR)pBreakpointInfo->Address > (DWORD_PTR)TrackedRegion->AllocationBase + TrackedRegion->RegionSize)
    {
        DoOutputDebugString("EntryPointWriteCallback: current AddressOfEntryPoint is not within allocated region. We assume it's only partially written and await further writes.\n");
        return TRUE;
    }

    if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, TrackedRegion->ExecBpRegister, 0, pBreakpointInfo->Address, BP_EXEC, EntryPointExecCallback))
    {
        DoOutputDebugString("EntryPointWriteCallback: ContextSetNextAvailableBreakpoint on EntryPoint 0x%p failed\n", (BYTE*)TrackedRegion->AllocationBase+*(DWORD*)(pBreakpointInfo->Address));
        return FALSE;
    }

    TrackedRegion->EntryPoint = (DWORD)pBreakpointInfo->Address;

    DoOutputDebugString("EntryPointWriteCallback: Execution bp %d set on EntryPoint address 0x%p.\n", TrackedRegion->ExecBpRegister, pBreakpointInfo->Address);

    pDosHeader = (PIMAGE_DOS_HEADER)TrackedRegion->AllocationBase;

    if (!pDosHeader->e_lfanew)
    {
        DoOutputDebugString("EntryPointWriteCallback: pointer to PE header zero.\n");
        return FALSE;
    }

    if ((ULONG)pDosHeader->e_lfanew > PE_HEADER_LIMIT)
    {
        DoOutputDebugString("EntryPointWriteCallback: pointer to PE header too big: 0x%p.\n", pDosHeader->e_lfanew);
        return FALSE;
    }

    pNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)TrackedRegion->AllocationBase + pDosHeader->e_lfanew);

    SizeOfHeaders = pDosHeader->e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + pNtHeader->FileHeader.SizeOfOptionalHeader;

    if (pNtHeader->FileHeader.NumberOfSections && pNtHeader->FileHeader.SizeOfOptionalHeader && pNtHeader->OptionalHeader.SizeOfImage)
    {
        PIMAGE_SECTION_HEADER FinalSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)TrackedRegion->AllocationBase + SizeOfHeaders + (sizeof(IMAGE_SECTION_HEADER) * (pNtHeader->FileHeader.NumberOfSections - 1)));

        DoOutputDebugString("EntryPointWriteCallback: DEBUG: NumberOfSections %d, SizeOfHeaders 0x%x.\n", pNtHeader->FileHeader.NumberOfSections, SizeOfHeaders);

        if (FinalSectionHeader->VirtualAddress && FinalSectionHeader->SizeOfRawData && (FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData <= pNtHeader->OptionalHeader.SizeOfImage))
        {
            PVOID FinalByteAddress = (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData - 1;

            if (!ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(BYTE), FinalByteAddress, BP_WRITE, FinalByteWriteCallback))
            {
                DoOutputDebugString("EntryPointWriteCallback: ContextUpdateCurrentBreakpoint failed to set write bp on final section, (address: 0x%p).\n", FinalByteAddress);
                return FALSE;
            }

            DoOutputDebugString("EntryPointWriteCallback: Set write breakpoint on final section, last byte at 0x%p\n", FinalByteAddress);
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
		DoOutputDebugString("AddressOfEPWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("AddressOfEPWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

    TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);

	if (TrackedRegion == NULL)
	{
		DoOutputDebugString("AddressOfEPWriteCallback: unable to locate entry point address 0x%p in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	}

    TrackedRegion->EntryPoint = 0;

    if (!SystemInfo.dwPageSize)
        GetSystemInfo(&SystemInfo);

    pDosHeader = (PIMAGE_DOS_HEADER)TrackedRegion->AllocationBase;

    if (!pDosHeader->e_lfanew)
    {
        DoOutputDebugString("AddressOfEPWriteCallback: pointer to PE header zero.\n");
        return FALSE;
    }

    if ((ULONG)pDosHeader->e_lfanew > PE_HEADER_LIMIT)
    {
        DoOutputDebugString("AddressOfEPWriteCallback: pointer to PE header too big: 0x%p.\n", pDosHeader->e_lfanew);
        return FALSE;
    }

	DoOutputDebugString("AddressOfEPWriteCallback: Breakpoint %i at Address 0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

    ReturnAddress = GetHookCallerBase();

    if (ReturnAddress && !TrackedRegionFromHook)
    {
		if (InsideHook(NULL, ReturnAddress))
        {
            DoOutputDebugString("AddressOfEPWriteCallback: We are in a hooked function with return address 0x%p.\n", ReturnAddress);
            if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, 0, ReturnAddress, BP_EXEC, HookReturnCallback))
            {
                DoOutputDebugString("AddressOfEPWriteCallback: set exec bp on return address 0x%p.\n", ReturnAddress);
                TrackedRegionFromHook = TrackedRegion;
            }
            else
            {
                DoOutputDebugString("AddressOfEPWriteCallback: Failed to set bp on return address 0x%p.\n", ReturnAddress);
            }
        }
        else
        {
            DoOutputDebugString("AddressOfEPWriteCallback: Not in a hooked function, setting callback in enter_hook() to catch next hook (return address 0x%p).\n", ReturnAddress);
            TrackedRegionFromHook = TrackedRegion;
        }
	}

    pNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)TrackedRegion->AllocationBase + pDosHeader->e_lfanew);

    if ((pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) && (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC))
    {
        DoOutputDebugString("AddressOfEPWriteCallback: Magic value not valid NT: 0x%x (at 0x%p).\n", pNtHeader->OptionalHeader.Magic, &pNtHeader->OptionalHeader.Magic);
        return TRUE;
    }

    TrackedRegion->CanDump = TRUE;

    if (pNtHeader->OptionalHeader.AddressOfEntryPoint > TrackedRegion->RegionSize)
    {
        DoOutputDebugString("AddressOfEPWriteCallback: Valid magic value but AddressOfEntryPoint invalid: 0x%p.\n", pNtHeader->OptionalHeader.AddressOfEntryPoint);
        return TRUE;
    }

    if (!pNtHeader->OptionalHeader.AddressOfEntryPoint)
    {
        DoOutputDebugString("AddressOfEPWriteCallback: Valid magic value but entry point still empty, leaving breakpoint intact.\n");
        return TRUE;
    }

    if (pNtHeader->OptionalHeader.AddressOfEntryPoint > TrackedRegion->RegionSize)
    {
        DoOutputDebugString("AddressOfEPWriteCallback: Valid magic value but AddressOfEntryPoint 0x%x greater than region size 0x%x.\n", pNtHeader->OptionalHeader.AddressOfEntryPoint, TrackedRegion->RegionSize);
        return TRUE;
    }

    if ((unsigned int)pNtHeader->OptionalHeader.AddressOfEntryPoint < ((unsigned int)&pNtHeader->OptionalHeader.DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] - (DWORD_PTR)TrackedRegion->AllocationBase))
    {
        DoOutputDebugString("AddressOfEPWriteCallback: Valid magic value but AddressOfEntryPoint 0x%x too small, possibly only partially written (<0x%x).\n", pNtHeader->OptionalHeader.AddressOfEntryPoint, (unsigned int)&pNtHeader->OptionalHeader.DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] - (unsigned int)TrackedRegion->AllocationBase);
        return TRUE;
    }

    if (*((BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint))
    {
        //ContextClearCurrentBreakpoint(ExceptionInfo->ContextRecord);

        if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, TrackedRegion->ExecBpRegister, 0, (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint, BP_EXEC, EntryPointExecCallback))
        {
            DoOutputDebugString("AddressOfEPWriteCallback: ContextSetNextAvailableBreakpoint on EntryPoint 0x%p failed\n", (BYTE*)TrackedRegion->AllocationBase+*(DWORD*)(pBreakpointInfo->Address));
            TrackedRegion->ExecBp = NULL;
            return FALSE;
        }

        TrackedRegion->ExecBp = (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint;

        DoOutputDebugString("AddressOfEPWriteCallback: Execution bp %d set on EntryPoint 0x%p.\n", TrackedRegion->ExecBpRegister, TrackedRegion->ExecBp);
    }
    else
    {
        if (!ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(BYTE), (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint, BP_WRITE, EntryPointWriteCallback))
        {
            DoOutputDebugString("AddressOfEPWriteCallback: ContextUpdateCurrentBreakpoint failed\n");
            ContextClearBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);
            return FALSE;
        }

        DoOutputDebugString("AddressOfEPWriteCallback: set write bp on AddressOfEntryPoint location 0x%p.\n", (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint);
    }

    SizeOfHeaders = pDosHeader->e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + pNtHeader->FileHeader.SizeOfOptionalHeader;

    if (pNtHeader->FileHeader.NumberOfSections && pNtHeader->FileHeader.SizeOfOptionalHeader && pNtHeader->OptionalHeader.SizeOfImage)
    {
        PIMAGE_SECTION_HEADER FinalSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)TrackedRegion->AllocationBase + SizeOfHeaders + (sizeof(IMAGE_SECTION_HEADER) * (pNtHeader->FileHeader.NumberOfSections - 1)));

        DoOutputDebugString("AddressOfEPWriteCallback: DEBUG: NumberOfSections %d, SizeOfHeaders 0x%x.\n", pNtHeader->FileHeader.NumberOfSections, SizeOfHeaders);

        if (FinalSectionHeader->VirtualAddress && FinalSectionHeader->SizeOfRawData && (FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData <= pNtHeader->OptionalHeader.SizeOfImage))
        {
            PVOID FinalByteAddress = (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData - 1;

            if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(BYTE), FinalByteAddress, BP_WRITE, FinalByteWriteCallback))
            {
                DoOutputDebugString("AddressOfEPWriteCallback: SetNextAvailableBreakpoint failed to set write bp on final section, (address: 0x%p).\n", FinalByteAddress);
                return FALSE;
            }

            DoOutputDebugString("AddressOfEPWriteCallback: Set write breakpoint on final section, last byte: 0x%p\n", *((BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData));

            if (FinalSectionHeader->Misc.VirtualSize && FinalSectionHeader->Misc.VirtualSize > FinalSectionHeader->SizeOfRawData)
                VirtualSize = FinalSectionHeader->Misc.VirtualSize;
            else if (pNtHeader->OptionalHeader.SectionAlignment)
                VirtualSize = ((FinalSectionHeader->SizeOfRawData / pNtHeader->OptionalHeader.SectionAlignment) + 1) * pNtHeader->OptionalHeader.SectionAlignment;
            else
                VirtualSize = ((FinalSectionHeader->SizeOfRawData / SystemInfo.dwPageSize) + 1) * SystemInfo.dwPageSize;

            if (FinalSectionHeader->VirtualAddress)
            {
                if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, NULL, sizeof(DWORD), (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + VirtualSize, BP_WRITE, OverlayWriteCallback))
                {
                    DoOutputDebugString("AddressOfEPWriteCallback: SetNextAvailableBreakpoint failed to set write bp on final section, last byte: 0x%p.\n", (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->Misc.VirtualSize);
                    return FALSE;
                }

                DoOutputDebugString("AddressOfEPWriteCallback: Set write breakpoint on final section, last byte: 0x%p\n", (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->Misc.VirtualSize);
            }
        }
        else
        {
            if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(DWORD), &FinalSectionHeader->SizeOfRawData, BP_WRITE, FinalSectionHeaderWriteCallback))
            {
                DoOutputDebugString("AddressOfEPWriteCallback: SetNextAvailableBreakpoint failed to set write bp on final section, last byte: 0x%p.\n", &FinalSectionHeader->SizeOfRawData);
                return FALSE;
            }

            DoOutputDebugString("AddressOfEPWriteCallback: Set write breakpoint on final section header (SizeOfRawData: 0x%x)\n", &FinalSectionHeader->SizeOfRawData);
        }
    }

    DoOutputDebugString("AddressOfEPWriteCallback executed successfully.\n");

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
		DoOutputDebugString("MagicWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("MagicWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

    TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);

	if (TrackedRegion == NULL)
	{
		DoOutputDebugString("MagicWriteCallback: unable to locate entry point address 0x%p in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	}

    TrackedRegion->EntryPoint = 0;

    if (!SystemInfo.dwPageSize)
        GetSystemInfo(&SystemInfo);

    pDosHeader = (PIMAGE_DOS_HEADER)TrackedRegion->AllocationBase;

    if (!pDosHeader->e_lfanew)
    {
        DoOutputDebugString("MagicWriteCallback: pointer to PE header zero.\n");
        return FALSE;
    }

    if ((ULONG)pDosHeader->e_lfanew > PE_HEADER_LIMIT)
    {
        DoOutputDebugString("MagicWriteCallback: pointer to PE header too big: 0x%p.\n", pDosHeader->e_lfanew);
        return FALSE;
    }

	DoOutputDebugString("MagicWriteCallback: Breakpoint %i at Address 0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

    ReturnAddress = GetHookCallerBase();

    if (ReturnAddress && !TrackedRegionFromHook)
    {
		if (InsideHook(NULL, ReturnAddress))
        {
            DoOutputDebugString("MagicWriteCallback: We are in a hooked function with return address 0x%p.\n", ReturnAddress);
            if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, 0, ReturnAddress, BP_EXEC, HookReturnCallback))
            {
                DoOutputDebugString("MagicWriteCallback: set exec bp on return address 0x%p.\n", ReturnAddress);
                TrackedRegionFromHook = TrackedRegion;
            }
            else
            {
                DoOutputDebugString("MagicWriteCallback: Failed to set bp on return address 0x%p.\n", ReturnAddress);
            }
        }
        else
        {
            DoOutputDebugString("MagicWriteCallback: Not in a hooked function, setting callback in enter_hook() to catch next hook (return address 0x%p).\n", ReturnAddress);
            TrackedRegionFromHook = TrackedRegion;
        }
	}

    pNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)TrackedRegion->AllocationBase + pDosHeader->e_lfanew);

    if ((pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) && (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC))
    {
        DoOutputDebugString("MagicWriteCallback: Magic value not valid NT: 0x%x (at 0x%p).\n", pNtHeader->OptionalHeader.Magic, &pNtHeader->OptionalHeader.Magic);
        return TRUE;
    }

    TrackedRegion->CanDump = TRUE;

    if (!pNtHeader->OptionalHeader.AddressOfEntryPoint)
    {
        DoOutputDebugString("MagicWriteCallback: Valid magic value but entry point still empty, leaving breakpoint intact.\n");
        return TRUE;
    }

    if (pNtHeader->OptionalHeader.AddressOfEntryPoint > TrackedRegion->RegionSize)
    {
        DoOutputDebugString("MagicWriteCallback: Valid magic value but AddressOfEntryPoint 0x%x greater than region size 0x%x.\n", pNtHeader->OptionalHeader.AddressOfEntryPoint, TrackedRegion->RegionSize);
        return TRUE;
    }

    if ((unsigned int)pNtHeader->OptionalHeader.AddressOfEntryPoint < ((unsigned int)&pNtHeader->OptionalHeader.DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] - (DWORD_PTR)TrackedRegion->AllocationBase))
    {
        DoOutputDebugString("MagicWriteCallback: Valid magic value but AddressOfEntryPoint 0x%x too small, possibly only partially written (<0x%x).\n", pNtHeader->OptionalHeader.AddressOfEntryPoint, (unsigned int)&pNtHeader->OptionalHeader.DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] - (unsigned int)TrackedRegion->AllocationBase);
        return TRUE;
    }

    if (*((BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint))
    {
        if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, TrackedRegion->ExecBpRegister, 0, (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint, BP_EXEC, EntryPointExecCallback))
        {
            DoOutputDebugString("MagicWriteCallback: ContextSetNextAvailableBreakpoint on EntryPoint 0x%p failed\n", (BYTE*)TrackedRegion->AllocationBase+*(DWORD*)(pBreakpointInfo->Address));
            TrackedRegion->ExecBp = NULL;
            return FALSE;
        }

        TrackedRegion->ExecBp = (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint;

        DoOutputDebugString("MagicWriteCallback: Execution bp %d set on EntryPoint 0x%p.\n", TrackedRegion->ExecBpRegister, TrackedRegion->ExecBp);
    }
    else
    {
        if (!ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(BYTE), (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint, BP_WRITE, EntryPointWriteCallback))
        {
            DoOutputDebugString("MagicWriteCallback: ContextUpdateCurrentBreakpoint failed\n");
            ContextClearBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);
            return FALSE;
        }

        DoOutputDebugString("MagicWriteCallback: set write bp on AddressOfEntryPoint location 0x%p.\n", (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint);
    }

    SizeOfHeaders = pDosHeader->e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + pNtHeader->FileHeader.SizeOfOptionalHeader;

    if (pNtHeader->FileHeader.NumberOfSections && pNtHeader->FileHeader.SizeOfOptionalHeader)
    {
        PIMAGE_SECTION_HEADER FinalSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)TrackedRegion->AllocationBase + SizeOfHeaders + (sizeof(IMAGE_SECTION_HEADER) * (pNtHeader->FileHeader.NumberOfSections - 1)));

        DoOutputDebugString("MagicWriteCallback: DEBUG: NumberOfSections %d, SizeOfHeaders 0x%x.\n", pNtHeader->FileHeader.NumberOfSections, SizeOfHeaders);

        if (FinalSectionHeader->VirtualAddress && FinalSectionHeader->SizeOfRawData)
        {
            FinalByteAddress = (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData - 1;

            if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(BYTE), FinalByteAddress, BP_WRITE, FinalByteWriteCallback))
            {
                DoOutputDebugString("MagicWriteCallback: SetNextAvailableBreakpoint failed to set write bp on final section, last byte: 0x%p.\n", FinalByteAddress);
                return FALSE;
            }

            DoOutputDebugString("MagicWriteCallback: Set write breakpoint on final section, last byte: 0x%p\n", (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData);

            if (FinalSectionHeader->Misc.VirtualSize && FinalSectionHeader->Misc.VirtualSize > FinalSectionHeader->SizeOfRawData)
                VirtualSize = FinalSectionHeader->Misc.VirtualSize;
            else if (pNtHeader->OptionalHeader.SectionAlignment)
                VirtualSize = ((FinalSectionHeader->SizeOfRawData / pNtHeader->OptionalHeader.SectionAlignment) + 1) * pNtHeader->OptionalHeader.SectionAlignment;
            else
                VirtualSize = ((FinalSectionHeader->SizeOfRawData / SystemInfo.dwPageSize) + 1) * SystemInfo.dwPageSize;

            if (FinalSectionHeader->VirtualAddress)
            {
                if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, NULL, sizeof(DWORD), (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + VirtualSize, BP_WRITE, OverlayWriteCallback))
                {
                    DoOutputDebugString("MagicWriteCallback: SetNextAvailableBreakpoint failed to set write bp on final section, last byte: 0x%p.\n", (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->Misc.VirtualSize);
                    return FALSE;
                }

                DoOutputDebugString("MagicWriteCallback: Set write breakpoint on final section, last byte: 0x%p\n", (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->Misc.VirtualSize);
            }
        }
        else
        {
            if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(DWORD), &FinalSectionHeader->SizeOfRawData, BP_WRITE, FinalSectionHeaderWriteCallback))
            {
                DoOutputDebugString("MagicWriteCallback: SetNextAvailableBreakpoint failed to set write bp on final section, last byte: 0x%p.\n", &FinalSectionHeader->SizeOfRawData);
                return FALSE;
            }

            DoOutputDebugString("MagicWriteCallback: Set write breakpoint on final section header (SizeOfRawData: 0x%x)\n", &FinalSectionHeader->SizeOfRawData);
        }
    }

    DoOutputDebugString("MagicWriteCallback executed successfully.\n");

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
		DoOutputDebugString("PEPointerWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("PEPointerWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	DoOutputDebugString("PEPointerWriteCallback: Breakpoint %i at Address 0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

    TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);

	if (TrackedRegion == NULL)
	{
		DoOutputDebugString("PEPointerWriteCallback: unable to locate address 0x%p in tracked region at 0x%p.\n", pBreakpointInfo->Address, TrackedRegion->AllocationBase);
		return FALSE;
	}

    TrackedRegion->EntryPoint = 0;

    if (TrackedRegion->ProtectAddress)
        pDosHeader = (PIMAGE_DOS_HEADER)TrackedRegion->ProtectAddress;
    else
        pDosHeader = (PIMAGE_DOS_HEADER)TrackedRegion->AllocationBase;

    if (!pDosHeader->e_lfanew)
    {
        DoOutputDebugString("PEPointerWriteCallback: candidate pointer to PE header zero.\n");
        return TRUE;
    }

    if ((ULONG)pDosHeader->e_lfanew > PE_HEADER_LIMIT)
    {
        // This is to be expected a lot when it's not a PE.
        DoOutputDebugString("PEPointerWriteCallback: candidate pointer to PE header too big: 0x%x (at 0x%p).\n", pDosHeader->e_lfanew, &pDosHeader->e_lfanew);

        if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &TrackedRegion->ExecBpRegister, 0, (BYTE*)TrackedRegion->AllocationBase, BP_EXEC, ShellcodeExecCallback))
        {
            DoOutputDebugString("PEPointerWriteCallback: set write bp on AddressOfEntryPoint at 0x%p.\n", TrackedRegion->AllocationBase);
            return TRUE;
        }
        else
        {
            DoOutputDebugString("PEPointerWriteCallback: Failed to set exec bp on AllocationBase at 0x%p.\n", TrackedRegion->AllocationBase);
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
            DoOutputDebugString("PEPointerWriteCallback: Leaving 'magic' breakpoint unchanged.\n");
            return TRUE;
        }

        if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, TrackedRegion->MagicBpRegister, sizeof(WORD), &pNtHeader->OptionalHeader.Magic, BP_WRITE, MagicWriteCallback))
        {
            DoOutputDebugString("PEPointerWriteCallback: Failed to set breakpoint on magic address.\n");
            return FALSE;
        }
    }
    else if (!ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(WORD), &pNtHeader->OptionalHeader.Magic, BP_WRITE, MagicWriteCallback))
    {
        DoOutputDebugString("PEPointerWriteCallback: Failed to set breakpoint on magic address.\n");
        return FALSE;
    }

    TrackedRegion->MagicBp = &pNtHeader->OptionalHeader.Magic;

    if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, 0, 4, &pNtHeader->OptionalHeader.AddressOfEntryPoint, BP_WRITE, AddressOfEPWriteCallback))
    {
        DoOutputDebugString("PEPointerWriteCallback: set write bp on AddressOfEntryPoint at 0x%p.\n", &pNtHeader->OptionalHeader.AddressOfEntryPoint);
        return TRUE;
    }
    else
    {
        DoOutputDebugString("PEPointerWriteCallback: Failed to set bp on AddressOfEntryPoint at 0x%p.\n", &pNtHeader->OptionalHeader.AddressOfEntryPoint);
        return FALSE;
    }

    DoOutputDebugString("PEPointerWriteCallback executed successfully with a breakpoints set on addresses of Magic (0x%p) and AddressOfEntryPoint (0x%p).\n", TrackedRegion->MagicBp, &pNtHeader->OptionalHeader.AddressOfEntryPoint);

	return TRUE;
}

//**************************************************************************************
BOOL ShellcodeExecCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
    PTRACKEDREGION TrackedRegion;

    if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("ShellcodeExecCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("ShellcodeExecCallback executed with NULL thread handle.\n");
		return FALSE;
	}

    TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);

	if (TrackedRegion == NULL)
	{
		DoOutputDebugString("ShellcodeExecCallback: unable to locate address 0x%p in tracked regions.\n", pBreakpointInfo->Address);
		return FALSE;
	}

    if (!VirtualQuery(pBreakpointInfo->Address, &TrackedRegion->MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
    {
        DoOutputErrorString("ShellcodeExecCallback: unable to query memory region 0x%p", pBreakpointInfo->Address);
        return FALSE;
    }

	DoOutputDebugString("ShellcodeExecCallback: Breakpoint %i at Address 0x%p (allocation base 0x%p).\n", pBreakpointInfo->Register, pBreakpointInfo->Address, TrackedRegion->MemInfo.AllocationBase);

    if (GuardPagesDisabled)
    {
        ContextClearTrackedRegion(ExceptionInfo->ContextRecord, TrackedRegion);

        DoOutputDebugString("ShellcodeExecCallback: About to scan region for a PE image (base 0x%p, size 0x%x).\n", TrackedRegion->MemInfo.AllocationBase, (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress + TrackedRegion->MemInfo.RegionSize - (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase);


        SetCapeMetaData(EXTRACTION_PE, 0, NULL, TrackedRegion->MemInfo.AllocationBase);
        TrackedRegion->PagesDumped = DumpPEsInRange(TrackedRegion->MemInfo.AllocationBase, (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress + TrackedRegion->MemInfo.RegionSize - (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase);

        if (TrackedRegion->PagesDumped)
            DoOutputDebugString("ShellcodeExecCallback: PE image(s) detected and dumped.\n");
        else
        {
            SIZE_T DumpSize = (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress + TrackedRegion->MemInfo.RegionSize - (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase;

            SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, TrackedRegion->MemInfo.AllocationBase);

            TrackedRegion->Entropy = GetEntropy(TrackedRegion->AllocationBase);

            TrackedRegion->PagesDumped = DumpMemory(TrackedRegion->MemInfo.AllocationBase, DumpSize);

            if (TrackedRegion->PagesDumped)
                DoOutputDebugString("ShellcodeExecCallback: successfully dumped memory range at 0x%p (size 0x%x).\n", TrackedRegion->MemInfo.AllocationBase, DumpSize);
            else
                DoOutputDebugString("ShellcodeExecCallback: failed to dump memory range at 0x%p (size 0x%x).\n", TrackedRegion->MemInfo.AllocationBase, DumpSize);
        }

        return TRUE;
    }

    if (!GuardPagesDisabled && DeactivateGuardPages(TrackedRegion))
    {
        SetCapeMetaData(EXTRACTION_PE, 0, NULL, TrackedRegion->MemInfo.AllocationBase);

        if (!address_is_in_stack((PVOID)pBreakpointInfo->Address) && (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress > (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase)
        {
            DoOutputDebugString("ShellcodeExecCallback: About to scan region for a PE image (base 0x%p, size 0x%x).\n", TrackedRegion->MemInfo.AllocationBase, (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress + TrackedRegion->MemInfo.RegionSize - (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase);
            TrackedRegion->PagesDumped = DumpPEsInRange(TrackedRegion->MemInfo.AllocationBase, (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress + TrackedRegion->MemInfo.RegionSize - (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase);
        }
        else if (address_is_in_stack((PVOID)pBreakpointInfo->Address) || (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress == (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase)
        {
            DoOutputDebugString("ShellcodeExecCallback: About to scan region for a PE image (base 0x%p, size 0x%x).\n", TrackedRegion->MemInfo.BaseAddress, TrackedRegion->MemInfo.RegionSize);
            TrackedRegion->PagesDumped = DumpPEsInRange(TrackedRegion->MemInfo.BaseAddress, TrackedRegion->MemInfo.RegionSize);
        }

        if (TrackedRegion->PagesDumped)
        {
            DoOutputDebugString("ShellcodeExecCallback: PE image(s) detected and dumped.\n");
            ContextClearTrackedRegion(ExceptionInfo->ContextRecord, TrackedRegion);
        }
        else
        {
            if (!address_is_in_stack((PVOID)pBreakpointInfo->Address) && (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress > (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase)
            {
                SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, TrackedRegion->MemInfo.AllocationBase);

                TrackedRegion->Entropy = GetEntropy(TrackedRegion->AllocationBase);
                TrackedRegion->PagesDumped = DumpMemory(TrackedRegion->MemInfo.AllocationBase, (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress + TrackedRegion->MemInfo.RegionSize - (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase);

                if (TrackedRegion->PagesDumped)
                {
                    DoOutputDebugString("ShellcodeExecCallback: successfully dumped memory range at 0x%p.\n", TrackedRegion->MemInfo.AllocationBase);
                    ContextClearTrackedRegion(ExceptionInfo->ContextRecord, TrackedRegion);
                }
            }
            else if (address_is_in_stack((PVOID)pBreakpointInfo->Address) || (DWORD_PTR)TrackedRegion->MemInfo.BaseAddress == (DWORD_PTR)TrackedRegion->MemInfo.AllocationBase)
            {
                SetCapeMetaData(EXTRACTION_SHELLCODE, 0, NULL, TrackedRegion->MemInfo.BaseAddress);

                if (ScanForNonZero(TrackedRegion->MemInfo.BaseAddress, TrackedRegion->MemInfo.RegionSize))
                {
                    TrackedRegion->Entropy = GetEntropy(TrackedRegion->AllocationBase);
                    TrackedRegion->PagesDumped = DumpMemory(TrackedRegion->MemInfo.BaseAddress, TrackedRegion->MemInfo.RegionSize);
                }
                else
                    DoOutputDebugString("ShellcodeExecCallback: memory range at 0x%p is empty.\n", TrackedRegion->MemInfo.BaseAddress);

                if (TrackedRegion->PagesDumped)
                {
                    DoOutputDebugString("ShellcodeExecCallback: successfully dumped memory range at 0x%p.\n", TrackedRegion->MemInfo.BaseAddress);
                    ContextClearTrackedRegion(ExceptionInfo->ContextRecord, TrackedRegion);
                }
            }
        }

        if (!TrackedRegion->PagesDumped)
        {
            DoOutputDebugString("ShellcodeExecCallback: Failed to dump memory range at 0x%p.\n", TrackedRegion->MemInfo.BaseAddress);

            return FALSE;
        }
        else
            DoOutputDebugString("ShellcodeExecCallback executed successfully.\n");

        ContextClearTrackedRegion(ExceptionInfo->ContextRecord, TrackedRegion);

        return TRUE;
    }
    else
    {
        DoOutputDebugString("ShellcodeExecCallback: Failed to disable guard pages for dump.\n");

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
		DoOutputDebugString("BaseAddressWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("BaseAddressWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	DoOutputDebugString("BaseAddressWriteCallback: Breakpoint %i at Address 0x%p.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);

    TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);

	if (TrackedRegion == NULL)
	{
		DoOutputDebugString("BaseAddressWriteCallback: unable to locate address 0x%p in tracked region at 0x%p.\n", pBreakpointInfo->Address, TrackedRegion->AllocationBase);
		return FALSE;
	}

    TrackedRegion->EntryPoint = 0;

    if (*(WORD*)pBreakpointInfo->Address == IMAGE_DOS_SIGNATURE)
    {
        DoOutputDebugString("BaseAddressWriteCallback: MZ header found.\n");

        TrackedRegion->CanDump = TRUE;

        pDosHeader = (PIMAGE_DOS_HEADER)pBreakpointInfo->Address;

        if (pDosHeader->e_lfanew && (unsigned int)pDosHeader->e_lfanew < PE_HEADER_LIMIT)
        {
            if (*(DWORD*)((unsigned char*)pDosHeader + pDosHeader->e_lfanew) == IMAGE_NT_SIGNATURE)
            {
                SetCapeMetaData(EXTRACTION_PE, 0, NULL, TrackedRegion->AllocationBase);
                TrackedRegion->PagesDumped = DumpPEsInRange(TrackedRegion->AllocationBase, TrackedRegion->RegionSize);

                if (TrackedRegion->PagesDumped)
                {
                    DoOutputDebugString("BaseAddressWriteCallback: PE image(s) dumped from 0x%p.\n", TrackedRegion->MemInfo.AllocationBase);
                    ClearTrackedRegion(TrackedRegion);
                    return TRUE;
                }
                else
                    DoOutputDebugString("BaseAddressWriteCallback: failed to dump PE module from 0x%p.\n", TrackedRegion->MemInfo.AllocationBase);
            }
            else
            {
                // Deal with the situation where the breakpoint triggers after e_lfanew has already been written
                PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)TrackedRegion->AllocationBase + pDosHeader->e_lfanew);
                if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(WORD), &pNtHeader->OptionalHeader.Magic, BP_WRITE, MagicWriteCallback))
                {
#ifdef _WIN64
                    DoOutputDebugString("BaseAddressWriteCallback: set write bp on magic address 0x%p (RIP = 0x%p)\n", (BYTE*)pDosHeader + pDosHeader->e_lfanew, ExceptionInfo->ContextRecord->Rip);
#else
                    DoOutputDebugString("BaseAddressWriteCallback: set write bp on magic address 0x%x (EIP = 0x%x)\n", (BYTE*)pDosHeader + pDosHeader->e_lfanew, ExceptionInfo->ContextRecord->Eip);
#endif
                }
                else
                {
                    DoOutputDebugString("BaseAddressWriteCallback: Failed to set breakpoint on magic address.\n");
                    return FALSE;
                }
            }
        }
        else if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(DWORD), (BYTE*)&pDosHeader->e_lfanew, BP_WRITE, PEPointerWriteCallback))
        {
            TrackedRegion->CanDump = TRUE;
#ifdef _WIN64
            DoOutputDebugString("BaseAddressWriteCallback: set write bp on e_lfanew write location: 0x%x (RIP = 0x%x)\n", (BYTE*)&pDosHeader->e_lfanew, ExceptionInfo->ContextRecord->Rip);
#else
            DoOutputDebugString("BaseAddressWriteCallback: set write bp on e_lfanew write location: 0x%x (EIP = 0x%x)\n", (BYTE*)&pDosHeader->e_lfanew, ExceptionInfo->ContextRecord->Eip);
#endif
        }
        else
        {
            DoOutputDebugString("BaseAddressWriteCallback: ContextUpdateCurrentBreakpoint failed\n");
            return FALSE;
        }
    }
    else if (*(BYTE*)pBreakpointInfo->Address == 'M')
    {
        // If a PE file is being written a byte at a time we do nothing and hope that the 4D byte isn't code!
        DoOutputDebugString("BaseAddressWriteCallback: M written to first byte, awaiting next byte.\n");
        return TRUE;
    }
    else if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &TrackedRegion->ExecBpRegister, 0, pBreakpointInfo->Address, BP_EXEC, ShellcodeExecCallback))
    {
        DoOutputDebugString("BaseAddressWriteCallback: Failed to set exec bp on tracked region protect address.\n");
        return FALSE;
    }

    DoOutputDebugString("BaseAddressWriteCallback: byte written to 0x%x: 0x%x.\n", pBreakpointInfo->Address, *(BYTE*)pBreakpointInfo->Address);

    TrackedRegion->ExecBp = pBreakpointInfo->Address;

	DoOutputDebugString("BaseAddressWriteCallback: Exec bp set on tracked region protect address.\n");

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
        DoOutputDebugString("ActivateBreakpoints: Error, tracked region argument NULL.\n");
        return FALSE;
    }

    if (!SystemInfo.dwPageSize)
        GetSystemInfo(&SystemInfo);

    if (!SystemInfo.dwPageSize)
    {
        DoOutputErrorString("ActivateBreakpoints: Failed to obtain system page size.\n");
        return FALSE;
    }

    ThreadId = GetCurrentThreadId();

    DoOutputDebugString("ActivateBreakpoints: TrackedRegion->AllocationBase: 0x%p, TrackedRegion->RegionSize: 0x%x, thread %d\n", TrackedRegion->AllocationBase, TrackedRegion->RegionSize, ThreadId);

    if (TrackedRegion->RegionSize == 0 || TrackedRegion->AllocationBase == NULL || ThreadId == 0)
    {
        DoOutputDebugString("ActivateBreakpoints: Error, one of the following is NULL - TrackedRegion->AllocationBase: 0x%p, TrackedRegion->RegionSize: 0x%x, thread %d\n", TrackedRegion->AllocationBase, TrackedRegion->RegionSize, ThreadId);
        return FALSE;
    }

    //AddressOfBasePage = ((DWORD_PTR)TrackedRegion->AllocationBase/SystemInfo.dwPageSize)*SystemInfo.dwPageSize;
    //ProtectAddressPage = ((DWORD_PTR)TrackedRegion->ProtectAddress/SystemInfo.dwPageSize)*SystemInfo.dwPageSize;

    // If we are activating breakpoints on a new region we 'save' the current region's breakpoints
    if (CurrentBreakpointRegion && TrackedRegion != CurrentBreakpointRegion)
    {
        DoOutputDebugString("ActivateBreakpoints: Switching breakpoints from region 0x%p to 0x%p.\n", CurrentBreakpointRegion->AllocationBase, TrackedRegion->AllocationBase);

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
                DoOutputDebugString("ActivateBreakpoints: Failed to restore region breakpoints for region at 0x%p.\n", CurrentBreakpointRegion->AllocationBase);
                CurrentBreakpointRegion->BreakpointsSet = FALSE;
                return FALSE;
            }

            DoOutputDebugString("ActivateBreakpoints: Restored region breakpoints for region at 0x%p.\n", CurrentBreakpointRegion->AllocationBase);

            CurrentBreakpointRegion->BreakpointsSet = TRUE;

            return TRUE;
        }
    }

    if (TrackedRegion->PagesDumped)
    {
        DoOutputDebugString("ActivateBreakpoints: Current tracked region has already been dumped.\n");
        return TRUE;
    }

    //if (TrackedRegion->BreakpointsSet)
    //{
    //    DoOutputDebugString("ActivateBreakpoints: Current tracked region already has breakpoints set.\n");
    //    return TRUE;
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
            if (!SetNextAvailableBreakpoint(GetCurrentThreadId(), &TrackedRegion->ExecBpRegister, 0, (BYTE*)TrackedRegion->ExecBp, BP_EXEC, ShellcodeExecCallback))
            {
                DoOutputDebugString("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set exec bp on tracked region protect address 0x%p.\n", TrackedRegion->ExecBp);
                TrackedRegion->ExecBp = NULL;
                return FALSE;
            }

            DoOutputDebugString("ActivateBreakpoints: Set execution breakpoint on non-zero byte 0x%x at protected address: 0x%p\n", *(PUCHAR)TrackedRegion->ExecBp, TrackedRegion->ExecBp);
        }
        else
        {
            if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &TrackedRegion->ExecBpRegister, 0, (BYTE*)TrackedRegion->ExecBp, BP_EXEC, ShellcodeExecCallback))
            {
                DoOutputDebugString("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set exec bp on tracked region protect address 0x%p.\n", TrackedRegion->ExecBp);
                TrackedRegion->ExecBp = NULL;
                return FALSE;
            }

            DoOutputDebugString("ActivateBreakpoints: Set execution breakpoint on non-zero byte 0x%x at protected address: 0x%p\n", *(PUCHAR)TrackedRegion->ExecBp, TrackedRegion->ExecBp);
        }
    }
    else
    {
        // We set a write breakpoint instead
        if (ExceptionInfo == NULL)
        {
            if (!SetNextAvailableBreakpoint(GetCurrentThreadId(), &TrackedRegion->ExecBpRegister, sizeof(WORD), (BYTE*)TrackedRegion->ExecBp, BP_WRITE, BaseAddressWriteCallback))
            {
                DoOutputDebugString("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set write bp on tracked region protect address 0x%p.\n", TrackedRegion->ExecBp);
                TrackedRegion->ExecBp = NULL;
                return FALSE;
            }

            DoOutputDebugString("ActivateBreakpoints: Set write breakpoint on empty protect address: 0x%p\n", TrackedRegion->ExecBp);
        }
        else
        {
            if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &TrackedRegion->ExecBpRegister, sizeof(WORD), (BYTE*)TrackedRegion->ExecBp, BP_WRITE, BaseAddressWriteCallback))
            {
                DoOutputDebugString("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set write bp on tracked region protect address 0x%p.\n", TrackedRegion->ExecBp);
                TrackedRegion->ExecBp = NULL;
                return FALSE;
            }

            DoOutputDebugString("ActivateBreakpoints: Set write breakpoint on empty protect address: 0x%p\n", TrackedRegion->ExecBp);
        }
    }

    // We also set a write bp on 'e_lfanew' address to begin our PE-write detection chain
    pDosHeader = (PIMAGE_DOS_HEADER)TrackedRegion->AllocationBase;

    if (ExceptionInfo == NULL)
    {
        if (!SetNextAvailableBreakpoint(GetCurrentThreadId(), &Register, sizeof(LONG), (BYTE*)&pDosHeader->e_lfanew, BP_WRITE, PEPointerWriteCallback))
        {
            DoOutputDebugString("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set write bp on e_lfanew address 0x%p.\n", TrackedRegion->ExecBp);
            return FALSE;
        }

        DoOutputDebugString("ActivateBreakpoints: Set write breakpoint on e_lfanew address: 0x%p\n", &pDosHeader->e_lfanew);
    }
    else
    {
        if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(LONG), (BYTE*)&pDosHeader->e_lfanew, BP_WRITE, PEPointerWriteCallback))
        {
            DoOutputDebugString("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set write bp on e_lfanew address 0x%p.\n", TrackedRegion->ExecBp);
            return FALSE;
        }

        DoOutputDebugString("ActivateBreakpoints: Set write breakpoint on e_lfanew address: 0x%p\n", &pDosHeader->e_lfanew);
    }

    CurrentBreakpointRegion = TrackedRegion;

    return TRUE;    // this should set TrackedRegion->BreakpointsSet in calling function
}

void ExtractionDllInit(PVOID DllBase)
{
    // We remove exe (rundll32) image from tracked regions
    if (!DropTrackedRegion(GetTrackedRegion(GetModuleHandle(NULL))))
        DoOutputDebugString("ExtractionDllInit: Error removing exe image base from tracked regions.\n");

    ImageBase = DllBase;

    // We add the dll image to tracked regions
    PTRACKEDREGION TrackedRegion = GetTrackedRegion(DllBase);
    if (!TrackedRegion)
    {
        DoOutputDebugString("ExtractionDllInit: Adding target dll image base to tracked regions.\n");
        TrackedRegion = AddTrackedRegion(DllBase, 0, 0);
    }
    else
    {
        TrackedRegion->PagesDumped = FALSE;
    }
}

void ExtractionInit()
{
//    if (!wcsnicmp(our_commandline, L"c:\\windows\\system32\\rundll32.exe", 32) ||
//        !wcsnicmp(our_commandline, L"c:\\windows\\syswow64\\rundll32.exe", 32) ||
//        !wcsnicmp(our_commandline, L"c:\\windows\\sysnative\\rundll32.exe", 33))
//            return

    // Start the debugger
    if (launch_debugger())
    {
        DebuggerEnabled = TRUE;
        DoOutputDebugString("ExtractionInit: Debugger initialised.\n");
    }
    else
        DoOutputDebugString("ExtractionInit: Failed to initialise debugger.\n");

    CapeMetaData->DumpType = EXTRACTION_PE;

    // We add the main image to tracked regions
    PTRACKEDREGION TrackedRegion = AddTrackedRegion(GetModuleHandle(NULL), 0, 0);
    if (TrackedRegion)
        DoOutputDebugString("ExtractionInit: Adding main image base to tracked regions.\n");
    else
        DoOutputDebugString("ExtractionInit: Error adding image base to tracked regions.\n");
}