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
#include "CAPE.h"
#include "Debugger.h"
#include "Unpacker.h"
#include "..\alloc.h"
#include "..\config.h"

#define PE_HEADER_LIMIT 0x200

#define MAX_PRETRAMP_SIZE 320
#define MAX_TRAMP_SIZE 128

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern void DebuggerOutput(_In_ LPCTSTR lpOutputString, ...);
extern void ErrorOutput(_In_ LPCTSTR lpOutputString, ...);
extern void DoTraceOutput(PVOID Address);

extern int path_is_system(const wchar_t *path_w);
extern unsigned int address_is_in_stack(PVOID Address);
extern ULONG_PTR g_our_dll_base;
extern DWORD g_our_dll_size;
extern PVOID ImageBase;
extern wchar_t *our_process_path_w;
extern char *our_process_name;
extern BOOL TraceRunning;
extern int operate_on_backtrace(ULONG_PTR _esp, ULONG_PTR _ebp, void *extra, int(*func)(void *, ULONG_PTR));
extern int WINAPI enter_hook(ULONG_PTR *h, ULONG_PTR sp, ULONG_PTR ebp_or_rip);
extern void hook_disable();
extern void hook_enable();
extern int is_stack_pivoted(void);
extern BOOL is_in_dll_range(ULONG_PTR addr);

extern BOOL DumpPEsInRange(PVOID Buffer, SIZE_T Size);
extern int DumpMemory(PVOID Buffer, SIZE_T Size);
extern int ScanForPE(PVOID Buffer, SIZE_T Size, PVOID* Offset);
extern int ScanPageForNonZero(PVOID Address);

PTRACKEDREGION CurrentRegion;
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
			DebugOutput("GetNtHeaders: Pointer to PE header zero.\n");
			return NULL;
		}

		if ((ULONG)pDosHeader->e_lfanew > PE_HEADER_LIMIT)
		{
			DebugOutput("GetNtHeaders: Pointer to PE header too big: 0x%x (at 0x%p).\n", pDosHeader->e_lfanew, &pDosHeader->e_lfanew);
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
void AllocationHandler(PVOID BaseAddress, SIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion = NULL;

	if (!BaseAddress || !RegionSize)
	{
		DebugOutput("AllocationHandler: Error, BaseAddress or RegionSize zero: 0x%p, 0x%p.\n", BaseAddress, RegionSize);
		return;
	}

	// We limit tracking to executable regions
	if (!(Protect & EXECUTABLE_FLAGS))
		return;

#ifdef DEBUG_COMMENTS
	DebugOutput("Allocation: 0x%p - 0x%p, size: 0x%x, protection: 0x%x.\n", BaseAddress, (PUCHAR)BaseAddress + RegionSize, RegionSize, Protect);
#endif
	hook_disable();

	if (TrackedRegionList)
		TrackedRegion = GetTrackedRegion(BaseAddress);

	// if memory was previously reserved but not committed
	if (TrackedRegion && !TrackedRegion->Committed && (AllocationType & MEM_COMMIT))
	{
		DebugOutput("AllocationHandler: Previously reserved region at 0x%p, committing at: 0x%p.\n", TrackedRegion->AllocationBase, BaseAddress);

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
		DebugOutput("AllocationHandler: Allocation already in tracked region list: 0x%p.\n", TrackedRegion->AllocationBase);
		hook_enable();
		return;
	}
	else
	{
		if (TraceRunning)
			DebuggerOutput("AllocationHandler: Adding allocation to tracked region list: 0x%p, size: 0x%x.\n", BaseAddress, RegionSize);
		else
			DebugOutput("AllocationHandler: Adding allocation to tracked region list: 0x%p, size: 0x%x.\n", BaseAddress, RegionSize);
		TrackedRegion = AddTrackedRegion(BaseAddress, Protect);
	}

	if (!TrackedRegion)
	{
		DebugOutput("AllocationHandler: Error, unable to locate or add allocation in tracked region list: 0x%p.\n", BaseAddress);
		hook_enable();
		return;
	}

	if (CurrentRegion && CurrentRegion != TrackedRegion)
	{
		if (TraceRunning)
			DebuggerOutput("AllocationHandler: Processing previous tracked region at: 0x%p.\n", CurrentRegion->AllocationBase);
		else
			DebugOutput("AllocationHandler: Processing previous tracked region at: 0x%p.\n", CurrentRegion->AllocationBase);
		ProcessTrackedRegion(CurrentRegion);
	}

	CurrentRegion = TrackedRegion;

	if (AllocationType & MEM_COMMIT)
	{
		TrackedRegion->Committed = TRUE;

		if (Protect & EXECUTABLE_FLAGS && g_config.unpacker > 1)
		{
			TrackedRegion->BreakpointsSet = ActivateBreakpoints(TrackedRegion, NULL);

			if (TrackedRegion->BreakpointsSet)
				DebuggerOutput("AllocationHandler: Breakpoints set on newly-allocated executable region at: 0x%p (size 0x%x).\n", BaseAddress, RegionSize);
			else
				DebuggerOutput("AllocationHandler: Error - unable to activate breakpoints around address 0x%p.\n", BaseAddress);
		}
		else if (Protect & EXECUTABLE_FLAGS)
			TrackedRegion->CanDump = TRUE;
	}
	else
	{   // Allocation not committed, so we can't set breakpoints yet
		TrackedRegion->Committed = FALSE;
		DebugOutput("AllocationHandler: Memory reserved but not committed at 0x%p.\n", BaseAddress);
	}

	hook_enable();

	return;
}

//**************************************************************************************
void ProtectionHandler(PVOID Address, ULONG Protect, PULONG OldProtect)
//**************************************************************************************
{
	BOOL NewRegion = FALSE;
	PTRACKEDREGION TrackedRegion = NULL;

	if (!Address)
	{
		DebugOutput("ProtectionHandler: Error, Address zero");
		return;
	}

	if (!(Protect & EXECUTABLE_FLAGS))
		return;

	if (is_in_dll_range((ULONG_PTR)Address))
		return;

	hook_disable();

	if (TrackedRegionList)
		TrackedRegion = GetTrackedRegion(Address);

	if (!TrackedRegion)
	{
		if (TraceRunning)
			DebuggerOutput("ProtectionHandler: Adding region at 0x%p to tracked regions.\n", Address);
		else
			DebugOutput("ProtectionHandler: Adding region at 0x%p to tracked regions.\n", Address);
		TrackedRegion = AddTrackedRegion(Address, Protect);
		NewRegion = TRUE;
	}
#ifdef DEBUG_COMMENTS
	else
		DebugOutput("ProtectionHandler: Address 0x%p already in tracked region at 0x%p.\n", Address, TrackedRegion->AllocationBase);
#endif

	if (!TrackedRegion)
	{
		DebugOutput("ProtectionHandler: Error, unable to add new region at 0x%p to tracked region list.\n", Address);
		hook_enable();
		return;
	}

	if (CurrentRegion && CurrentRegion != TrackedRegion)
	{
		if (TraceRunning)
			DebuggerOutput("ProtectionHandler: Processing previous tracked region at: 0x%p.\n", CurrentRegion->AllocationBase);
		else
			DebugOutput("ProtectionHandler: Processing previous tracked region at: 0x%p.\n", CurrentRegion->AllocationBase);
		ProcessTrackedRegion(CurrentRegion);
	}

	CurrentRegion = TrackedRegion;

	if (!VirtualQuery(Address, &TrackedRegion->MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		ErrorOutput("ProtectionHandler: unable to query memory region 0x%p", Address);
		hook_enable();
		return;
	}

#ifdef DEBUG_COMMENTS
	DebugOutput("ProtectionHandler: Address: 0x%p (allocation base 0x%p), NewAccessProtection: 0x%x\n", Address, TrackedRegion->AllocationBase, Protect);
#endif

	TrackedRegion->AllocationBase = TrackedRegion->MemInfo.AllocationBase;

	if (TrackedRegion->MemInfo.Protect != Protect)
	{
		TrackedRegion->MemInfo.Protect = Protect;
#ifdef DEBUG_COMMENTS
		DebugOutput("ProtectionHandler: Updated region protection at 0x%p to 0x%x.\n", TrackedRegion->AllocationBase, Protect);
#endif
	}

	if (TrackedRegion->AllocationBase == ImageBase || TrackedRegion->AllocationBase == GetModuleHandle(NULL))
	{
		ProcessImageBase(TrackedRegion);
		hook_enable();
		return;
	}

	if (!TrackedRegion->PagesDumped && (NewRegion || *OldProtect & WRITABLE_FLAGS) && ScanForNonZero(Address, GetAccessibleSize(Address)))
	{
		DebugOutput("ProtectionHandler: New code detected at 0x%p, dumping.\n", TrackedRegion->AllocationBase);

		ProcessTrackedRegion(TrackedRegion);

		if (TrackedRegion->PagesDumped)
		{
			DebugOutput("ProtectionHandler: Dumped region at 0x%p.\n", TrackedRegion->AllocationBase);
			ClearTrackedRegion(TrackedRegion);
			hook_enable();
			return;
		}
#ifdef DEBUG_COMMENTS
		else
			DebugOutput("ProtectionHandler: No PE images found in region at 0x%p.\n", TrackedRegion->AllocationBase);
#endif
	}
#ifdef DEBUG_COMMENTS
	else
		DebugOutput("ProtectionHandler: No action taken on empty protected region at 0x%p.\n", Address);
#endif

	TrackedRegion->ProtectAddress = Address;

	if (g_config.unpacker > 1 && !TrackedRegion->PagesDumped)
	{
		TrackedRegion->BreakpointsSet = ActivateBreakpoints(TrackedRegion, NULL);

		if (TrackedRegion->BreakpointsSet)
			DebuggerOutput("ProtectionHandler: Breakpoints set on executable region at: 0x%p.\n", Address);
		else
			DebuggerOutput("ProtectionHandler: Error - unable to activate breakpoints around address 0x%p.\n", Address);
	}
	else if (!TrackedRegion->PagesDumped)
		TrackedRegion->CanDump = TRUE;

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

	if (TrackedRegion->Committed == TRUE && TrackedRegion->MemInfo.Protect & EXECUTABLE_FLAGS && ScanForNonZero(TrackedRegion->AllocationBase, GetAccessibleSize(TrackedRegion->AllocationBase)) && !TrackedRegion->PagesDumped)
	{
		ProcessTrackedRegion(TrackedRegion);

		if (TrackedRegion->PagesDumped)
			DebugOutput("FreeHandler: Dumped executable range containing 0x%p.\n", BaseAddress);
		else
			DebugOutput("FreeHandler: failed to dump executable memory range at 0x%p prior to its freeing.\n");
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

	if (ScanForNonZero(TrackedRegion->AllocationBase, GetAccessibleSize(TrackedRegion->AllocationBase)) && !TrackedRegion->PagesDumped)
	{
		ProcessTrackedRegion(TrackedRegion);

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

	if (ScanForNonZero(TrackedRegion->AllocationBase, GetAccessibleSize(TrackedRegion->AllocationBase)) && !TrackedRegion->PagesDumped)
	{
		ProcessTrackedRegion(TrackedRegion);

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
BOOL OverlayWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;

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
		DebuggerOutput("OverlayWriteCallback: Unable to locate entry point address 0x%p in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	}

#ifdef _WIN64
	DWORD64 CIP = ExceptionInfo->ContextRecord->Rip;
#else
	DWORD CIP = ExceptionInfo->ContextRecord->Eip;
#endif

	DebuggerOutput("OverlayWriteCallback: Breakpoint %i at address 0x%p (instruction at 0x%p)\n", pBreakpointInfo->Register, pBreakpointInfo->Address, CIP);
	DoTraceOutput((PVOID)CIP);

	TrackedRegion->EntryPoint = 0;

	if (!(DWORD*)pBreakpointInfo->Address)
	{
		DebuggerOutput("OverlayWriteCallback: Zero written, ignoring, leaving breakpoint in place\n", pBreakpointInfo->Address);
		return TRUE;
	}

	return TRUE;
}

//**************************************************************************************
BOOL FinalByteWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	PTRACKEDREGION TrackedRegion;

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
		DebuggerOutput("FinalByteWriteCallback: Unable to locate entry point address 0x%p in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	}

#ifdef _WIN64
	DWORD64 CIP = ExceptionInfo->ContextRecord->Rip;
#else
	DWORD CIP = ExceptionInfo->ContextRecord->Eip;
#endif

	DebuggerOutput("FinalByteWriteCallback: Breakpoint %i at address 0x%p (instruction at 0x%p)\n", pBreakpointInfo->Register, pBreakpointInfo->Address, CIP);
	DoTraceOutput((PVOID)CIP);

	TrackedRegion->EntryPoint = 0;

	SetCapeMetaData(UNPACKED_PE, 0, NULL, TrackedRegion->AllocationBase);

	ProcessTrackedRegion(TrackedRegion);

	if (TrackedRegion->PagesDumped)
	{
		DebuggerOutput("FinalByteWriteCallback: Successfully dumped module\n");
		ContextClearTrackedRegion(ExceptionInfo->ContextRecord, TrackedRegion);
	}
	else
		DebuggerOutput("FinalByteWriteCallback: Failed to dump PE module\n");

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
	unsigned int Register;

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
		DebuggerOutput("FinalSectionHeaderWriteCallback: Unable to locate entry point address 0x%p in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	}

#ifdef _WIN64
	DWORD64 CIP = ExceptionInfo->ContextRecord->Rip;
#else
	DWORD CIP = ExceptionInfo->ContextRecord->Eip;
#endif

	DebuggerOutput("FinalSectionHeaderWriteCallback: Breakpoint %i at address 0x%p (instruction at 0x%p)\n", pBreakpointInfo->Register, pBreakpointInfo->Address, CIP);
	DoTraceOutput((PVOID)CIP);

	TrackedRegion->EntryPoint = 0;

	TrackedRegion->CanDump = TRUE;

	FinalSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD*)pBreakpointInfo->Address - 4);

	if (!FinalSectionHeader->VirtualAddress || !FinalSectionHeader->SizeOfRawData)
	{
		DebuggerOutput("FinalSectionHeaderWriteCallback: current VirtualAddress and FinalSectionHeader->SizeOfRawData not valid: 0x%x, 0x%x (at 0x%p, 0x%p)\n", FinalSectionHeader->VirtualAddress, FinalSectionHeader->SizeOfRawData, (DWORD*)pBreakpointInfo->Address - 1, pBreakpointInfo->Address);
		return TRUE;
	}
#ifdef DEBUG_COMMENTS
	else
		DebuggerOutput("FinalSectionHeaderWriteCallback: Section %s VirtualAddress: 0x%x, FinalSectionHeader->Misc.VirtualSize: 0x%x, FinalSectionHeader->SizeOfRawData: 0x%x\n", FinalSectionHeader->Name, FinalSectionHeader->VirtualAddress, FinalSectionHeader->Misc.VirtualSize, FinalSectionHeader->SizeOfRawData);
#endif

	FinalByteAddress = (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData - 1;

	if (!ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(BYTE), FinalByteAddress, BP_WRITE, 0, FinalByteWriteCallback))
	{
		DebuggerOutput("FinalSectionHeaderWriteCallback: write bp set on final byte at 0x%p\n", FinalByteAddress);
	}

	pNtHeader = GetNtHeaders(TrackedRegion->AllocationBase);

	if (FinalSectionHeader->Misc.VirtualSize && FinalSectionHeader->Misc.VirtualSize > FinalSectionHeader->SizeOfRawData)
		VirtualSize = FinalSectionHeader->SizeOfRawData;
	else
		VirtualSize = ((FinalSectionHeader->SizeOfRawData / pNtHeader->OptionalHeader.SectionAlignment) + 1) * pNtHeader->OptionalHeader.SectionAlignment;

	if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(DWORD), (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + VirtualSize, BP_WRITE, 0, OverlayWriteCallback))
		DebuggerOutput("FinalSectionHeaderWriteCallback: Set breakpoint %d to write on first byte of overlay at: 0x%p\n", Register, (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + VirtualSize);
	else
		DebuggerOutput("FinalSectionHeaderWriteCallback: Unable to set overlay breakpoint\n");

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
		DebuggerOutput("EntryPointExecCallback: Unable to locate entry point address 0x%p in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	}

	DebuggerOutput("EntryPointExecCallback: Breakpoint %i at address 0x%p\n", pBreakpointInfo->Register, pBreakpointInfo->Address);
	DoTraceOutput(pBreakpointInfo->Address);

	TrackedRegion->CanDump = TRUE;

	SetCapeMetaData(UNPACKED_PE, 0, NULL, TrackedRegion->AllocationBase);

	ProcessTrackedRegion(TrackedRegion);

	if (TrackedRegion->PagesDumped)
	{
		DebuggerOutput("EntryPointExecCallback: Successfully dumped module\n");
		ContextClearTrackedRegion(ExceptionInfo->ContextRecord, TrackedRegion);
	}
	else
		DebuggerOutput("EntryPointExecCallback: Failed to dump PE module\n");

	return TRUE;
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
		DebuggerOutput("EntryPointWriteCallback: Unable to locate entry point address 0x%p in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	}

#ifdef _WIN64
	DWORD64 CIP = ExceptionInfo->ContextRecord->Rip;
#else
	DWORD CIP = ExceptionInfo->ContextRecord->Eip;
#endif

	DebuggerOutput("EntryPointWriteCallback: Breakpoint %i at address 0x%p (instruction at 0x%p)\n", pBreakpointInfo->Register, pBreakpointInfo->Address, CIP);
	DoTraceOutput((PVOID)CIP);

	TrackedRegion->EntryPoint = 0;

	if ((DWORD_PTR)pBreakpointInfo->Address < (DWORD_PTR)TrackedRegion->AllocationBase || (DWORD_PTR)pBreakpointInfo->Address > (DWORD_PTR)TrackedRegion->AllocationBase + TrackedRegion->MemInfo.RegionSize)
	{
		DebuggerOutput("EntryPointWriteCallback: current AddressOfEntryPoint is not within allocated region. We assume it's only partially written and await further writes\n");
		return TRUE;
	}

	if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, TrackedRegion->ExecBpRegister, 0, pBreakpointInfo->Address, BP_EXEC, 0, EntryPointExecCallback))
	{
		DebuggerOutput("EntryPointWriteCallback: ContextSetThreadBreakpoint on EntryPoint 0x%p failed\n", (BYTE*)TrackedRegion->AllocationBase+*(DWORD*)(pBreakpointInfo->Address));
		return FALSE;
	}

	DebuggerOutput("EntryPointWriteCallback: Execution bp %d set on EntryPoint address 0x%p\n", TrackedRegion->ExecBpRegister, pBreakpointInfo->Address);

	pDosHeader = (PIMAGE_DOS_HEADER)TrackedRegion->AllocationBase;

	if (!pDosHeader->e_lfanew)
	{
		DebuggerOutput("EntryPointWriteCallback: Pointer to PE header zero\n");
		return FALSE;
	}

	if ((ULONG)pDosHeader->e_lfanew > PE_HEADER_LIMIT)
	{
		DebuggerOutput("EntryPointWriteCallback: Pointer to PE header too big: 0x%p\n", pDosHeader->e_lfanew);
		return FALSE;
	}

	pNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)TrackedRegion->AllocationBase + pDosHeader->e_lfanew);

	SizeOfHeaders = pDosHeader->e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + pNtHeader->FileHeader.SizeOfOptionalHeader;

	if (pNtHeader->FileHeader.NumberOfSections && pNtHeader->FileHeader.SizeOfOptionalHeader && pNtHeader->OptionalHeader.SizeOfImage)
	{
		PIMAGE_SECTION_HEADER FinalSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)TrackedRegion->AllocationBase + SizeOfHeaders + (sizeof(IMAGE_SECTION_HEADER) * (pNtHeader->FileHeader.NumberOfSections - 1)));

#ifdef DEBUG_COMMENTS
		DebuggerOutput("EntryPointWriteCallback: DEBUG: NumberOfSections %d, SizeOfHeaders 0x%x\n", pNtHeader->FileHeader.NumberOfSections, SizeOfHeaders);
#endif

		if (FinalSectionHeader->VirtualAddress && FinalSectionHeader->SizeOfRawData && (FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData <= pNtHeader->OptionalHeader.SizeOfImage))
		{
			PVOID FinalByteAddress = (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData - 1;

			if (!ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(BYTE), FinalByteAddress, BP_WRITE, 0, FinalByteWriteCallback))
			{
				DebuggerOutput("EntryPointWriteCallback: ContextUpdateCurrentBreakpoint failed to set write bp on final section, (address: 0x%p)\n", FinalByteAddress);
				return FALSE;
			}

			DebuggerOutput("EntryPointWriteCallback: Set write breakpoint on final section, last byte at 0x%p\n", FinalByteAddress);
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
		DebuggerOutput("AddressOfEPWriteCallback: Unable to locate entry point address 0x%p in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	}

#ifdef _WIN64
	DWORD64 CIP = ExceptionInfo->ContextRecord->Rip;
#else
	DWORD CIP = ExceptionInfo->ContextRecord->Eip;
#endif

	DebuggerOutput("AddressOfEPWriteCallback: Breakpoint %i at address 0x%p (instruction at 0x%p)\n", pBreakpointInfo->Register, pBreakpointInfo->Address, CIP);
	DoTraceOutput((PVOID)CIP);

	TrackedRegion->EntryPoint = 0;

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	pDosHeader = (PIMAGE_DOS_HEADER)TrackedRegion->AllocationBase;

	if (!pDosHeader->e_lfanew)
	{
		DebuggerOutput("AddressOfEPWriteCallback: Pointer to PE header zero.\n");
		return FALSE;
	}

	if ((ULONG)pDosHeader->e_lfanew > PE_HEADER_LIMIT)
	{
		DebuggerOutput("AddressOfEPWriteCallback: Pointer to PE header too big: 0x%p.\n", pDosHeader->e_lfanew);
		return FALSE;
	}

	pNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)TrackedRegion->AllocationBase + pDosHeader->e_lfanew);

	if ((pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) && (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC))
	{
		DebuggerOutput("AddressOfEPWriteCallback: Magic value not valid NT: 0x%x (at 0x%p)\n", pNtHeader->OptionalHeader.Magic, &pNtHeader->OptionalHeader.Magic);
		return TRUE;
	}

	TrackedRegion->CanDump = TRUE;

	if (pNtHeader->OptionalHeader.AddressOfEntryPoint > TrackedRegion->MemInfo.RegionSize)
	{
		DebuggerOutput("AddressOfEPWriteCallback: Valid magic value but AddressOfEntryPoint invalid: 0x%p\n", pNtHeader->OptionalHeader.AddressOfEntryPoint);
		return TRUE;
	}

	if (!pNtHeader->OptionalHeader.AddressOfEntryPoint)
	{
		DebuggerOutput("AddressOfEPWriteCallback: Valid magic value but entry point still empty, leaving breakpoint intact\n");
		return TRUE;
	}

	if (pNtHeader->OptionalHeader.AddressOfEntryPoint > TrackedRegion->MemInfo.RegionSize)
	{
		DebuggerOutput("AddressOfEPWriteCallback: Valid magic value but AddressOfEntryPoint 0x%x greater than region size 0x%x\n", pNtHeader->OptionalHeader.AddressOfEntryPoint, TrackedRegion->MemInfo.RegionSize);
		return TRUE;
	}

	if ((DWORD_PTR)pNtHeader->OptionalHeader.AddressOfEntryPoint < ((DWORD_PTR)&pNtHeader->OptionalHeader.DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] - (DWORD_PTR)TrackedRegion->AllocationBase))
	{
		DebuggerOutput("AddressOfEPWriteCallback: Valid magic value but AddressOfEntryPoint 0x%x too small, possibly only partially written (<0x%x)\n", pNtHeader->OptionalHeader.AddressOfEntryPoint, (DWORD_PTR)&pNtHeader->OptionalHeader.DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] - (DWORD_PTR)TrackedRegion->AllocationBase);
		return TRUE;
	}

	if (*((BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint))
	{
		//ContextClearCurrentBreakpoint(ExceptionInfo->ContextRecord);

		if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, TrackedRegion->ExecBpRegister, 0, (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint, BP_EXEC, 0, EntryPointExecCallback))
		{
			DebuggerOutput("AddressOfEPWriteCallback: ContextSetThreadBreakpoint on EntryPoint 0x%p failed\n", (BYTE*)TrackedRegion->AllocationBase+*(DWORD*)(pBreakpointInfo->Address));
			TrackedRegion->ExecBp = NULL;
			return FALSE;
		}

		TrackedRegion->ExecBp = (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint;

		DebuggerOutput("AddressOfEPWriteCallback: Execution bp %d set on EntryPoint 0x%p\n", TrackedRegion->ExecBpRegister, TrackedRegion->ExecBp);
	}
	else
	{
		if (!ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(BYTE), (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint, BP_WRITE, 0, EntryPointWriteCallback))
		{
			DebuggerOutput("AddressOfEPWriteCallback: ContextUpdateCurrentBreakpoint failed\n");
			ContextClearBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo->Register);
			return FALSE;
		}

		DebuggerOutput("AddressOfEPWriteCallback: Updated current bp to write on AddressOfEntryPoint location 0x%p\n", (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint);
	}

	SizeOfHeaders = pDosHeader->e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + pNtHeader->FileHeader.SizeOfOptionalHeader;

	if (pNtHeader->FileHeader.NumberOfSections && pNtHeader->FileHeader.SizeOfOptionalHeader && pNtHeader->OptionalHeader.SizeOfImage)
	{
		PIMAGE_SECTION_HEADER FinalSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)TrackedRegion->AllocationBase + SizeOfHeaders + (sizeof(IMAGE_SECTION_HEADER) * (pNtHeader->FileHeader.NumberOfSections - 1)));

#ifdef DEBUG_COMMENTS
		DebuggerOutput("AddressOfEPWriteCallback: DEBUG: NumberOfSections %d, SizeOfHeaders 0x%x\n", pNtHeader->FileHeader.NumberOfSections, SizeOfHeaders);
#endif

		if (FinalSectionHeader->VirtualAddress && FinalSectionHeader->SizeOfRawData && (FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData <= pNtHeader->OptionalHeader.SizeOfImage))
		{
			if (FinalSectionHeader->Misc.VirtualSize && FinalSectionHeader->Misc.VirtualSize > FinalSectionHeader->SizeOfRawData)
				VirtualSize = FinalSectionHeader->Misc.VirtualSize;
			else if (pNtHeader->OptionalHeader.SectionAlignment)
				VirtualSize = ((FinalSectionHeader->SizeOfRawData / pNtHeader->OptionalHeader.SectionAlignment) + 1) * pNtHeader->OptionalHeader.SectionAlignment;
			else
				VirtualSize = ((FinalSectionHeader->SizeOfRawData / SystemInfo.dwPageSize) + 1) * SystemInfo.dwPageSize;

			PVOID FinalByteAddress = (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData - 1;

			if (IsAddressAccessible(FinalByteAddress))
			{
				if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(BYTE), FinalByteAddress, BP_WRITE, 0, FinalByteWriteCallback))
				{
					DebuggerOutput("AddressOfEPWriteCallback: SetNextAvailableBreakpoint failed to set write bp on final section, last byte: 0x%p\n", FinalByteAddress);
					return FALSE;
				}

				DebuggerOutput("AddressOfEPWriteCallback: Set breakpoint %d to write on final section, last byte: 0x%p\n", Register, (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData);
			}
			else if (FinalSectionHeader->PointerToRawData)
			{
				FinalByteAddress = (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->PointerToRawData + FinalSectionHeader->SizeOfRawData - 1;

				if (IsAddressAccessible(FinalByteAddress))
				{
					if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(BYTE), FinalByteAddress, BP_WRITE, 0, FinalByteWriteCallback))
					{
						DebuggerOutput("AddressOfEPWriteCallback: SetNextAvailableBreakpoint failed to set write bp on final raw section, last byte: 0x%p\n", FinalByteAddress);
						return FALSE;
					}

					DebuggerOutput("AddressOfEPWriteCallback: Set breakpoint %d to write on final raw section, last byte: 0x%p\n", Register, (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData);
				}
				else
				{
					DebuggerOutput("AddressOfEPWriteCallback: SetNextAvailableBreakpoint Final raw section address 0x%p inaccessible, PointerToRawData 0x%x, SizeOfRawData 0x%x", FinalByteAddress, FinalSectionHeader->PointerToRawData, FinalSectionHeader->SizeOfRawData);
					return FALSE;
				}
			}

			if (FinalSectionHeader->VirtualAddress)
			{
				if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(DWORD), (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + VirtualSize, BP_WRITE, 0, OverlayWriteCallback))
				{
					DebuggerOutput("AddressOfEPWriteCallback: SetNextAvailableBreakpoint failed to set write bp on final section, last byte: 0x%p\n", (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->Misc.VirtualSize);
					return FALSE;
				}

				DebuggerOutput("AddressOfEPWriteCallback: Set breakpoint %d to write on final section, last byte: 0x%p\n", Register, (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->Misc.VirtualSize);
			}
		}
		else
		{
			DebuggerOutput("AddressOfEPWriteCallback: Setting bp on section table");

			if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(DWORD), &FinalSectionHeader->SizeOfRawData, BP_WRITE, 0, FinalSectionHeaderWriteCallback))
			{
				DebuggerOutput("AddressOfEPWriteCallback: SetNextAvailableBreakpoint failed to set write bp on final section, last byte: 0x%p\n", &FinalSectionHeader->SizeOfRawData);
				return FALSE;
			}

			DebuggerOutput("AddressOfEPWriteCallback: Set breakpoint %d to write on final section header (SizeOfRawData: 0x%x)\n", Register, &FinalSectionHeader->SizeOfRawData);
		}
	}

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
	PVOID FinalByteAddress;
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
		DebuggerOutput("MagicWriteCallback: Unable to locate entry point address 0x%p in tracked region.\n", pBreakpointInfo->Address);
		return FALSE;
	}

#ifdef _WIN64
	DWORD64 CIP = ExceptionInfo->ContextRecord->Rip;
#else
	DWORD CIP = ExceptionInfo->ContextRecord->Eip;
#endif

	DebuggerOutput("MagicWriteCallback: Breakpoint %i at address 0x%p (instruction at 0x%p)\n", pBreakpointInfo->Register, pBreakpointInfo->Address, CIP);
	DoTraceOutput((PVOID)CIP);

	TrackedRegion->EntryPoint = 0;

	if (!SystemInfo.dwPageSize)
		GetSystemInfo(&SystemInfo);

	pDosHeader = (PIMAGE_DOS_HEADER)TrackedRegion->AllocationBase;

	if (!pDosHeader->e_lfanew)
	{
		DebuggerOutput("MagicWriteCallback: Pointer to PE header zero.\n");
		return FALSE;
	}

	if ((ULONG)pDosHeader->e_lfanew > PE_HEADER_LIMIT)
	{
		DebuggerOutput("MagicWriteCallback: Pointer to PE header too big: 0x%p.\n", pDosHeader->e_lfanew);
		return FALSE;
	}

	pNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)TrackedRegion->AllocationBase + pDosHeader->e_lfanew);

	if ((pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) && (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC))
	{
		DebuggerOutput("MagicWriteCallback: Magic value not valid NT: 0x%x (at 0x%p)\n", pNtHeader->OptionalHeader.Magic, &pNtHeader->OptionalHeader.Magic);
		return TRUE;
	}

	TrackedRegion->CanDump = TRUE;

	if (!pNtHeader->OptionalHeader.AddressOfEntryPoint)
	{
		DebuggerOutput("MagicWriteCallback: Valid magic value but entry point still empty, leaving breakpoint intact\n");
		return TRUE;
	}

	if (pNtHeader->OptionalHeader.AddressOfEntryPoint > TrackedRegion->MemInfo.RegionSize)
	{
		DebuggerOutput("MagicWriteCallback: Valid magic value but AddressOfEntryPoint 0x%x greater than region size 0x%x\n", pNtHeader->OptionalHeader.AddressOfEntryPoint, TrackedRegion->MemInfo.RegionSize);
		return TRUE;
	}

	if ((DWORD_PTR)pNtHeader->OptionalHeader.AddressOfEntryPoint < ((DWORD_PTR)&pNtHeader->OptionalHeader.DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] - (DWORD_PTR)TrackedRegion->AllocationBase))
	{
		DebuggerOutput("MagicWriteCallback: Valid magic value but AddressOfEntryPoint 0x%x too small, possibly only partially written (<0x%x)\n", pNtHeader->OptionalHeader.AddressOfEntryPoint, (DWORD_PTR)&pNtHeader->OptionalHeader.DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] - (DWORD_PTR)TrackedRegion->AllocationBase);
		return TRUE;
	}

	if (*((BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint))
	{
		if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, TrackedRegion->ExecBpRegister, 0, (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint, BP_EXEC, 0, EntryPointExecCallback))
		{
			DebuggerOutput("MagicWriteCallback: ContextSetThreadBreakpoint on EntryPoint 0x%p failed\n", (BYTE*)TrackedRegion->AllocationBase+*(DWORD*)(pBreakpointInfo->Address));
			TrackedRegion->ExecBp = NULL;
			return FALSE;
		}

		TrackedRegion->ExecBp = (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint;

		DebuggerOutput("MagicWriteCallback: Breakpoint %d set to execute on EntryPoint 0x%p\n", TrackedRegion->ExecBpRegister, TrackedRegion->ExecBp);
	}
	else
	{
		if (!ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(BYTE), (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint, BP_WRITE, 0, EntryPointWriteCallback))
		{
			DebuggerOutput("MagicWriteCallback: ContextUpdateCurrentBreakpoint failed\n");
			ContextClearBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo->Register);
			return FALSE;
		}

		DebuggerOutput("MagicWriteCallback: Updated current bp to write on AddressOfEntryPoint location 0x%p\n", (BYTE*)TrackedRegion->AllocationBase + pNtHeader->OptionalHeader.AddressOfEntryPoint);
	}

	SizeOfHeaders = pDosHeader->e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + pNtHeader->FileHeader.SizeOfOptionalHeader;

	if (pNtHeader->FileHeader.NumberOfSections && pNtHeader->FileHeader.SizeOfOptionalHeader)
	{
		PIMAGE_SECTION_HEADER FinalSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)TrackedRegion->AllocationBase + SizeOfHeaders + (sizeof(IMAGE_SECTION_HEADER) * (pNtHeader->FileHeader.NumberOfSections - 1)));

#ifdef DEBUG_COMMENTS
		DebuggerOutput("MagicWriteCallback: DEBUG: NumberOfSections %d, SizeOfHeaders 0x%x\n", pNtHeader->FileHeader.NumberOfSections, SizeOfHeaders);
#endif

		if (FinalSectionHeader->VirtualAddress && FinalSectionHeader->SizeOfRawData)
		{
			if (FinalSectionHeader->Misc.VirtualSize && FinalSectionHeader->Misc.VirtualSize > FinalSectionHeader->SizeOfRawData)
				VirtualSize = FinalSectionHeader->Misc.VirtualSize;
			else if (pNtHeader->OptionalHeader.SectionAlignment)
				VirtualSize = ((FinalSectionHeader->SizeOfRawData / pNtHeader->OptionalHeader.SectionAlignment) + 1) * pNtHeader->OptionalHeader.SectionAlignment;
			else
				VirtualSize = ((FinalSectionHeader->SizeOfRawData / SystemInfo.dwPageSize) + 1) * SystemInfo.dwPageSize;

			FinalByteAddress = (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData - 1;

			if (IsAddressAccessible(FinalByteAddress))
			{
				if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(BYTE), FinalByteAddress, BP_WRITE, 0, FinalByteWriteCallback))
				{
					DebuggerOutput("MagicWriteCallback: SetNextAvailableBreakpoint failed to set write bp on final section, last byte: 0x%p\n", FinalByteAddress);
					return FALSE;
				}

				DebuggerOutput("MagicWriteCallback: Set breakpoint %d to write on final section, last byte: 0x%p\n", Register, (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData);
			}
			else if (FinalSectionHeader->PointerToRawData)
			{
				FinalByteAddress = (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->PointerToRawData + FinalSectionHeader->SizeOfRawData - 1;

				if (IsAddressAccessible(FinalByteAddress))
				{
					if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(BYTE), FinalByteAddress, BP_WRITE, 0, FinalByteWriteCallback))
					{
						DebuggerOutput("MagicWriteCallback: SetNextAvailableBreakpoint failed to set write bp on final raw section, last byte: 0x%p\n", FinalByteAddress);
						return FALSE;
					}

					DebuggerOutput("MagicWriteCallback: Set breakpoint %d to write on final raw section, last byte: 0x%p\n", Register, (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->SizeOfRawData);
				}
				else
				{
					DebuggerOutput("MagicWriteCallback: SetNextAvailableBreakpoint Final raw section address 0x%p inaccessible", FinalByteAddress);
					return FALSE;
				}
			}

			if (FinalSectionHeader->VirtualAddress)
			{
				if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(DWORD), (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + VirtualSize, BP_WRITE, 0, OverlayWriteCallback))
				{
					DebuggerOutput("MagicWriteCallback: SetNextAvailableBreakpoint failed to set write bp on final section, last byte: 0x%p\n", (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->Misc.VirtualSize);
					return FALSE;
				}

				DebuggerOutput("MagicWriteCallback: Set breakpoint %d to write on final section, last byte: 0x%p\n", Register, (BYTE*)TrackedRegion->AllocationBase + FinalSectionHeader->VirtualAddress + FinalSectionHeader->Misc.VirtualSize);
			}
		}
		else
		{
			if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(DWORD), &FinalSectionHeader->SizeOfRawData, BP_WRITE, 0, FinalSectionHeaderWriteCallback))
			{
				DebuggerOutput("MagicWriteCallback: SetNextAvailableBreakpoint failed to set write bp on final section, last byte: 0x%p\n", &FinalSectionHeader->SizeOfRawData);
				return FALSE;
			}

			DebuggerOutput("MagicWriteCallback: Set breakpoint %d to write on final section header (SizeOfRawData: 0x%x)\n", Register, &FinalSectionHeader->SizeOfRawData);
		}
	}

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
	unsigned int Register;

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

	TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);

	if (TrackedRegion == NULL)
	{
		DebugOutput("PEPointerWriteCallback: unable to locate address 0x%p in tracked regions.\n", pBreakpointInfo->Address);
		return FALSE;
	}

#ifdef _WIN64
	DWORD64 CIP = ExceptionInfo->ContextRecord->Rip;
#else
	DWORD CIP = ExceptionInfo->ContextRecord->Eip;
#endif

	DebuggerOutput("PEPointerWriteCallback: Breakpoint %i at address 0x%p (instruction at 0x%p)\n", pBreakpointInfo->Register, pBreakpointInfo->Address, CIP);
	DoTraceOutput((PVOID)CIP);

	TrackedRegion->EntryPoint = 0;

	if (TrackedRegion->ProtectAddress)
		pDosHeader = (PIMAGE_DOS_HEADER)TrackedRegion->ProtectAddress;
	else
		pDosHeader = (PIMAGE_DOS_HEADER)TrackedRegion->AllocationBase;

	if (!pDosHeader->e_lfanew)
	{
		DebuggerOutput("PEPointerWriteCallback: candidate pointer to PE header zero\n");
		return TRUE;
	}

	if ((ULONG)pDosHeader->e_lfanew > PE_HEADER_LIMIT)
	{
		// This is to be expected a lot when it's not a PE.
		DebuggerOutput("PEPointerWriteCallback: candidate pointer to PE header too big: 0x%x (at 0x%p)\n", pDosHeader->e_lfanew, &pDosHeader->e_lfanew);
		return TRUE;
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
			DebuggerOutput("PEPointerWriteCallback: Leaving 'magic' breakpoint unchanged\n");
			return TRUE;
		}

		if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, TrackedRegion->MagicBpRegister, sizeof(WORD), &pNtHeader->OptionalHeader.Magic, BP_WRITE, 0, MagicWriteCallback))
		{
			DebuggerOutput("PEPointerWriteCallback: Failed to set breakpoint on magic address\n");
			return FALSE;
		}
	}
	else if (!ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(WORD), &pNtHeader->OptionalHeader.Magic, BP_WRITE, 0, MagicWriteCallback))
	{
		DebuggerOutput("PEPointerWriteCallback: Failed to set breakpoint on magic address\n");
		return FALSE;
	}

	TrackedRegion->MagicBp = &pNtHeader->OptionalHeader.Magic;

	if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, 4, &pNtHeader->OptionalHeader.AddressOfEntryPoint, BP_WRITE, 0, AddressOfEPWriteCallback))
	{
		DebuggerOutput("PEPointerWriteCallback: Set breakpoint %d to write on AddressOfEntryPoint at 0x%p\n", Register, &pNtHeader->OptionalHeader.AddressOfEntryPoint);
		return TRUE;
	}
	else
	{
		DebuggerOutput("PEPointerWriteCallback: Failed to set bp on AddressOfEntryPoint at 0x%p\n", &pNtHeader->OptionalHeader.AddressOfEntryPoint);
		return FALSE;
	}

#ifdef DEBUG_COMMENTS
	DebuggerOutput("PEPointerWriteCallback executed successfully with a breakpoints set on addresses of Magic (0x%p) and AddressOfEntryPoint (0x%p)\n", TrackedRegion->MagicBp, &pNtHeader->OptionalHeader.AddressOfEntryPoint);
#endif

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
		DebuggerOutput("ShellcodeExecCallback: Breakpoint %i at address 0x%p - unable to locate in tracked regions.\n", pBreakpointInfo->Register, pBreakpointInfo->Address);
		return FALSE;
	}

	if (!VirtualQuery(pBreakpointInfo->Address, &TrackedRegion->MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		ErrorOutput("ShellcodeExecCallback: Unable to query memory region 0x%p", pBreakpointInfo->Address);
		return FALSE;
	}

	DebuggerOutput("ShellcodeExecCallback: Breakpoint %i at address 0x%p (allocation base 0x%p)\n", pBreakpointInfo->Register, pBreakpointInfo->Address, TrackedRegion->MemInfo.AllocationBase);
	DoTraceOutput(pBreakpointInfo->Address);

	ContextClearTrackedRegion(ExceptionInfo->ContextRecord, TrackedRegion);

	TrackedRegion->CanDump = TRUE;

	SetCapeMetaData(UNPACKED_PE, 0, NULL, TrackedRegion->MemInfo.AllocationBase);
	
	ProcessTrackedRegion(TrackedRegion);

	if (TrackedRegion->PagesDumped)
	{
		DebuggerOutput("ShellcodeExecCallback: Successfully dumped memory range at 0x%p\n", TrackedRegion->MemInfo.AllocationBase);
		ContextClearTrackedRegion(ExceptionInfo->ContextRecord, TrackedRegion);
	}
	else
		DebuggerOutput("ShellcodeExecCallback: Failed to dump memory range at 0x%p\n", TrackedRegion->MemInfo.AllocationBase);

	return TRUE;
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

	TrackedRegion = GetTrackedRegion(pBreakpointInfo->Address);

	if (TrackedRegion == NULL)
	{
		DebugOutput("BaseAddressWriteCallback: unable to locate address 0x%p in tracked regions.\n", pBreakpointInfo->Address);
		return FALSE;
	}

#ifdef _WIN64
	DWORD64 CIP = ExceptionInfo->ContextRecord->Rip;
#else
	DWORD CIP = ExceptionInfo->ContextRecord->Eip;
#endif

	DebuggerOutput("BaseAddressWriteCallback: Breakpoint %i at address 0x%p writing %x (instruction at 0x%p)\n", pBreakpointInfo->Register, pBreakpointInfo->Address, *(BYTE*)pBreakpointInfo->Address, CIP);
	DoTraceOutput((PVOID)CIP);

	TrackedRegion->EntryPoint = 0;

	if (*(WORD*)pBreakpointInfo->Address == IMAGE_DOS_SIGNATURE)
	{
		DebuggerOutput("BaseAddressWriteCallback: MZ header found\n");

		TrackedRegion->CanDump = TRUE;

		if (TrackedRegion->ExecBpRegister)
			ContextClearBreakpoint(ExceptionInfo->ContextRecord, TrackedRegion->ExecBpRegister);

		pDosHeader = (PIMAGE_DOS_HEADER)pBreakpointInfo->Address;

		if (pDosHeader->e_lfanew && (unsigned int)pDosHeader->e_lfanew < PE_HEADER_LIMIT)
		{
			if (*(DWORD*)((unsigned char*)pDosHeader + pDosHeader->e_lfanew) == IMAGE_NT_SIGNATURE)
			{
				SetCapeMetaData(UNPACKED_PE, 0, NULL, TrackedRegion->AllocationBase);

				ProcessTrackedRegion(TrackedRegion);

				if (TrackedRegion->PagesDumped)
				{
					DebuggerOutput("BaseAddressWriteCallback: PE image dumped from 0x%p\n", TrackedRegion->MemInfo.AllocationBase);
					ContextClearTrackedRegion(ExceptionInfo->ContextRecord, TrackedRegion);
					return TRUE;
				}
				else
					DebuggerOutput("BaseAddressWriteCallback: Failed to dump PE module from 0x%p\n", TrackedRegion->MemInfo.AllocationBase);
			}
			else
			{
				// Deal with the situation where the breakpoint triggers after e_lfanew has already been written
				PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)TrackedRegion->AllocationBase + pDosHeader->e_lfanew);
				if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(WORD), &pNtHeader->OptionalHeader.Magic, BP_WRITE, 0, MagicWriteCallback))
				{
					DebuggerOutput("BaseAddressWriteCallback: Updated current bp to write on magic address 0x%x (EIP = 0x%p)\n", (BYTE*)pDosHeader + pDosHeader->e_lfanew, CIP);
				}
				else
				{
					DebuggerOutput("BaseAddressWriteCallback: Failed to set breakpoint on magic address\n");
					return FALSE;
				}
			}
		}
		//else if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, sizeof(DWORD), (BYTE*)&pDosHeader->e_lfanew, BP_WRITE, 0, PEPointerWriteCallback))
		//{
		//	TrackedRegion->CanDump = TRUE;
		//	DebuggerOutput("BaseAddressWriteCallback: Updated current bp to write on DOS 'e_lfanew' location: 0x%x (EIP = 0x%p)\n", (BYTE*)&pDosHeader->e_lfanew, CIP);
		//}
		//else
		//{
		//	DebuggerOutput("BaseAddressWriteCallback: ContextUpdateCurrentBreakpoint failed\n");
		//	return FALSE;
		//}
	}
	else if (*(BYTE*)pBreakpointInfo->Address == 'M')
	{
		// If a PE file is being written a byte at a time we do nothing and hope that the 4D byte isn't code!
		DebuggerOutput("BaseAddressWriteCallback: M written to first byte, awaiting next byte\n");
		return TRUE;
	}
	else if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &TrackedRegion->ExecBpRegister, 0, pBreakpointInfo->Address, BP_EXEC, 0, ShellcodeExecCallback))
	{
		DebuggerOutput("BaseAddressWriteCallback: Failed to set exec bp on tracked region protect address\n");
		return FALSE;
	}
	else
	{
		DebuggerOutput("BaseAddressWriteCallback: Breakpoint %d set to execute on tracked region base address 0x%p\n", TrackedRegion->ExecBpRegister, pBreakpointInfo->Address);
		TrackedRegion->ExecBp = pBreakpointInfo->Address;
	}

	return TRUE;
}

//**************************************************************************************
BOOL ActivateBreakpoints(PTRACKEDREGION TrackedRegion, struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	DWORD ThreadId;
	unsigned int Register;
	PIMAGE_DOS_HEADER pDosHeader;

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

	if (TrackedRegion->PagesDumped)
	{
#ifdef DEBUG_COMMENTS
		DebuggerOutput("ActivateBreakpoints: Current tracked region has already been dumped\n");
#endif
		return TRUE;
	}

	ThreadId = GetCurrentThreadId();

	DebuggerOutput("ActivateBreakpoints: AllocationBase: 0x%p, thread %d\n", TrackedRegion->AllocationBase, ThreadId);

	if (TrackedRegion->AllocationBase == NULL || ThreadId == 0)
	{
		DebuggerOutput("ActivateBreakpoints: Error, one of the following is NULL - TrackedRegion->AllocationBase: 0x%p, thread %d\n", TrackedRegion->AllocationBase, ThreadId);
		return FALSE;
	}

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
				DebuggerOutput("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set exec bp on tracked region protect address 0x%p\n", TrackedRegion->ExecBp);
				TrackedRegion->ExecBp = NULL;
				return FALSE;
			}

			DebuggerOutput("ActivateBreakpoints: Set breakpoint %d to execute on non-zero byte 0x%x at protected address: 0x%p\n", TrackedRegion->ExecBpRegister, *(PUCHAR)TrackedRegion->ExecBp, TrackedRegion->ExecBp);
		}
		else
		{
			if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &TrackedRegion->ExecBpRegister, 0, (BYTE*)TrackedRegion->ExecBp, BP_EXEC, 0, ShellcodeExecCallback))
			{
				DebuggerOutput("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set exec bp on tracked region protect address 0x%p\n", TrackedRegion->ExecBp);
				TrackedRegion->ExecBp = NULL;
				return FALSE;
			}

			DebuggerOutput("ActivateBreakpoints: Set breakpoint %d to execute on non-zero byte 0x%x at protected address: 0x%p\n", TrackedRegion->ExecBpRegister, *(PUCHAR)TrackedRegion->ExecBp, TrackedRegion->ExecBp);
		}
	}
	else
	{
		// We set a write breakpoint instead
		if (ExceptionInfo == NULL)
		{
			if (!SetNextAvailableBreakpoint(GetCurrentThreadId(), &TrackedRegion->ExecBpRegister, sizeof(WORD), (BYTE*)TrackedRegion->ExecBp, BP_WRITE, 0, BaseAddressWriteCallback))
			{
				DebuggerOutput("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set write bp on tracked region protect address 0x%p\n", TrackedRegion->ExecBp);
				TrackedRegion->ExecBp = NULL;
				return FALSE;
			}

			DebuggerOutput("ActivateBreakpoints: Set breakpoint %d to write on empty address: 0x%p\n", TrackedRegion->ExecBpRegister, TrackedRegion->ExecBp);
		}
		else
		{
			if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &TrackedRegion->ExecBpRegister, sizeof(WORD), (BYTE*)TrackedRegion->ExecBp, BP_WRITE, 0, BaseAddressWriteCallback))
			{
				DebuggerOutput("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set write bp on tracked region protect address 0x%p\n", TrackedRegion->ExecBp);
				TrackedRegion->ExecBp = NULL;
				return FALSE;
			}

			DebuggerOutput("ActivateBreakpoints: Set breakpoint %d to write on empty address: 0x%p\n", &TrackedRegion->ExecBpRegister, TrackedRegion->ExecBp);
		}
	}

	// We also set a write bp on 'e_lfanew' address to begin our PE-write detection chain
	pDosHeader = (PIMAGE_DOS_HEADER)TrackedRegion->AllocationBase;

	if (ExceptionInfo == NULL)
	{
		if (!SetNextAvailableBreakpoint(GetCurrentThreadId(), &Register, sizeof(LONG), (BYTE*)&pDosHeader->e_lfanew, BP_WRITE, 0, PEPointerWriteCallback))
		{
			DebuggerOutput("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set write bp on DOS 'e_lfanew' address 0x%p\n", TrackedRegion->ExecBp);
			return FALSE;
		}

		DebuggerOutput("ActivateBreakpoints: Set breakpoint %d to write on DOS 'e_lfanew' address: 0x%p\n", Register, &pDosHeader->e_lfanew);
	}
	else
	{
		if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &Register, sizeof(LONG), (BYTE*)&pDosHeader->e_lfanew, BP_WRITE, 0, PEPointerWriteCallback))
		{
			DebuggerOutput("ActivateBreakpoints: SetNextAvailableBreakpoint failed to set write bp on DOS 'e_lfanew' address 0x%p\n", TrackedRegion->ExecBp);
			return FALSE;
		}

		DebuggerOutput("ActivateBreakpoints: Set breakpoint %d to write on DOS 'e_lfanew' address: 0x%p\n", Register, &pDosHeader->e_lfanew);
	}

	TraceRunning = TRUE;

	return TRUE;	// this should set TrackedRegion->BreakpointsSet in calling function
}

void UnpackerInit()
{
	if (!InitialiseDebugger())
		DebugOutput("UnpackerInit: Failed to initialise debugger.\n");

	// Add the monitor to tracked regions
	PTRACKEDREGION TrackedRegion = AddTrackedRegion((PVOID)g_our_dll_base, 0);
	if (TrackedRegion)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("UnpackerInit: Adding monitor image base to tracked regions.\n");
#endif
		TrackedRegion->PagesDumped = TRUE;
		TrackedRegion->CallerDetected = TRUE;
	}
	else
		DebugOutput("UnpackerInit: Error adding monitor image base to tracked regions.\n");
}