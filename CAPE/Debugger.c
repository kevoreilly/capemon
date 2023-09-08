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
#include <stdio.h>
#include <tchar.h>
#include <assert.h>
#include "..\hooking.h"
#include "..\alloc.h"
#include "..\config.h"
#include "..\pipe.h"
#include "CAPE.h"
#include "Debugger.h"
#include "Unpacker.h"

#define PIPEBUFSIZE 512

typedef struct _INJECT_STRUCT {
	ULONG_PTR LdrLoadDllAddress;
	UNICODE_STRING DllName;
	HANDLE OutHandle;
} INJECT_STRUCT, *PINJECT_STRUCT;

DWORD LengthMask[MAX_DEBUG_REGISTER_DATA_SIZE + 1] = DEBUG_REGISTER_LENGTH_MASKS;

extern OSVERSIONINFO OSVersion;
extern SYSTEM_INFO SystemInfo;
extern ULONG_PTR g_our_dll_base;
extern DWORD g_our_dll_size;
extern BOOLEAN is_address_in_ntdll(ULONG_PTR address);
extern char *convert_address_to_dll_name_and_offset(ULONG_PTR addr, unsigned int *offset);
extern LONG WINAPI capemon_exception_handler(__in struct _EXCEPTION_POINTERS *ExceptionInfo);
extern BOOL UnpackerGuardPageHandler(struct _EXCEPTION_POINTERS* ExceptionInfo);
extern PTRACKEDREGION GetTrackedRegion(PVOID Address);
extern PVOID GetPageAddress(PVOID Address);
extern PCHAR GetNameBySsn(unsigned int Number);
extern unsigned int address_is_in_stack(DWORD Address);
extern BOOL WoW64fix(void);
extern BOOL WoW64PatchBreakpoint(unsigned int Register);
extern BOOL WoW64UnpatchBreakpoint(unsigned int Register);
extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern void ErrorOutput(_In_ LPCTSTR lpOutputString, ...);
extern BOOL SetInitialBreakpoints(PVOID ImageBase), Trace(struct _EXCEPTION_POINTERS* ExceptionInfo), SoftwareBreakpointCallback(struct _EXCEPTION_POINTERS* ExceptionInfo);
extern int operate_on_backtrace(ULONG_PTR _esp, ULONG_PTR _ebp, void *extra, int(*func)(void *, ULONG_PTR));
extern void DebuggerOutput(_In_ LPCTSTR lpOutputString, ...), DoTraceOutput(PVOID Address);
extern BOOL TraceRunning, BreakpointsSet, BreakpointsHit, StopTrace, BreakOnNtContinue;
extern PVOID BreakOnNtContinueCallback;
extern int StepOverRegister;
extern int process_shutting_down;
extern HANDLE DebuggerLog;

struct ThreadBreakpoints *MainThreadBreakpointList;
GUARD_PAGE_HANDLER GuardPageHandler;
unsigned int TrapIndex, DepthCount;
PVOID _KiUserExceptionDispatcher;
HANDLE hCapePipe;
BOOL SetSingleStepMode(PCONTEXT Context, PVOID Handler), ClearSingleStepMode(PCONTEXT Context);
static lookup_t SoftBPs, SyscallBPs;

void ApplyQueuedBreakpoints();

//**************************************************************************************
PTHREADBREAKPOINTS GetThreadBreakpoints(DWORD ThreadId)
//**************************************************************************************
{
	PTHREADBREAKPOINTS CurrentThreadBreakpoints = MainThreadBreakpointList;

	while (CurrentThreadBreakpoints)
	{
		if (CurrentThreadBreakpoints->ThreadId == ThreadId)
			return CurrentThreadBreakpoints;
		else
			CurrentThreadBreakpoints = CurrentThreadBreakpoints->NextThreadBreakpoints;
	}

	return NULL;
}

//**************************************************************************************
HANDLE GetThreadHandle(DWORD ThreadId)
//**************************************************************************************
{
	DWORD CurrentThreadId;

	PTHREADBREAKPOINTS CurrentThreadBreakpoints = MainThreadBreakpointList;

	while (CurrentThreadBreakpoints)
	{
		CurrentThreadId = GetThreadId(CurrentThreadBreakpoints->ThreadHandle);

		if (CurrentThreadId == ThreadId)
			return CurrentThreadBreakpoints->ThreadHandle;
		else
			CurrentThreadBreakpoints = CurrentThreadBreakpoints->NextThreadBreakpoints;
	}

	return NULL;
}

//**************************************************************************************
PTHREADBREAKPOINTS CreateThreadBreakpoints(DWORD ThreadId, HANDLE Handle)
//**************************************************************************************
{
	unsigned int Register;
	PTHREADBREAKPOINTS CurrentThreadBreakpoints, PreviousThreadBreakpoint;

	PreviousThreadBreakpoint = NULL;

	if (MainThreadBreakpointList == NULL)
	{
		MainThreadBreakpointList = ((struct ThreadBreakpoints*)malloc(sizeof(struct ThreadBreakpoints)));

		if (MainThreadBreakpointList == NULL)
		{
			DebugOutput("CreateThreadBreakpoints: failed to allocate memory for initial thread breakpoint list.\n");
			return NULL;
		}

		CurrentThreadBreakpoints = MainThreadBreakpointList;

		memset(CurrentThreadBreakpoints, 0, sizeof(struct ThreadBreakpoints));
	}
	else
	{
		CurrentThreadBreakpoints = MainThreadBreakpointList;

		while (CurrentThreadBreakpoints)
		{
			if (CurrentThreadBreakpoints->ThreadId && CurrentThreadBreakpoints->ThreadId == ThreadId)
			{
#ifdef DEBUG_COMMENTS
				DebugOutput("CreateThreadBreakpoints error: found an existing thread breakpoint list for ThreadId %d\n", ThreadId);
#endif
				return NULL;
			}

			PreviousThreadBreakpoint = CurrentThreadBreakpoints;
			CurrentThreadBreakpoints = CurrentThreadBreakpoints->NextThreadBreakpoints;
		}

		if (!CurrentThreadBreakpoints && PreviousThreadBreakpoint)
		{
			// We haven't found it in the linked list, so create a new one
			CurrentThreadBreakpoints = PreviousThreadBreakpoint;

			CurrentThreadBreakpoints->NextThreadBreakpoints = ((struct ThreadBreakpoints*)malloc(sizeof(struct ThreadBreakpoints)));

			if (CurrentThreadBreakpoints->NextThreadBreakpoints == NULL)
			{
				DebugOutput("CreateThreadBreakpoints: Failed to allocate new thread breakpoints.\n");
				return NULL;
			}

			memset(CurrentThreadBreakpoints->NextThreadBreakpoints, 0, sizeof(struct ThreadBreakpoints));

			CurrentThreadBreakpoints = CurrentThreadBreakpoints->NextThreadBreakpoints;
		}
	}

	if (!CurrentThreadBreakpoints)
		return NULL;

	if (Handle)
		CurrentThreadBreakpoints->ThreadHandle = Handle;
	else if (ThreadId == GetCurrentThreadId())
	{
		if (DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &CurrentThreadBreakpoints->ThreadHandle, 0, FALSE, DUPLICATE_SAME_ACCESS) == 0)
		{
			DebugOutput("CreateThreadBreakpoints: Failed to duplicate thread handle.\n");
			return NULL;
		}
	}
	else
	{
		CurrentThreadBreakpoints->ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadId);

		if (CurrentThreadBreakpoints->ThreadHandle == NULL)
		{
			DebugOutput("CreateThreadBreakpoints: Failed to open thread and get a handle.\n");
			return NULL;
		}
	}

	CurrentThreadBreakpoints->ThreadId = ThreadId;

	for (Register = 0; Register < NUMBER_OF_DEBUG_REGISTERS; Register++)
	{
		CurrentThreadBreakpoints->BreakpointInfo[Register].Register = Register;
		CurrentThreadBreakpoints->BreakpointInfo[Register].ThreadHandle = CurrentThreadBreakpoints->ThreadHandle;
	}

	g_config.debugger = 1;

	return CurrentThreadBreakpoints;
}

//**************************************************************************************
BOOL InitNewThreadBreakpoints(DWORD ThreadId, HANDLE Handle)
//**************************************************************************************
{
	PTHREADBREAKPOINTS NewThreadBreakpoints = NULL;
	BOOL ThreadBreakpointsSet = FALSE;

	if (!DebuggerInitialised)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("InitNewThreadBreakpoints: Debugger not initialised - ignoring thread %d.\n", ThreadId);
#endif
		return FALSE;
	}

	if (MainThreadBreakpointList == NULL)
	{
		DebugOutput("InitNewThreadBreakpoints: Failed to create thread breakpoints struct.\n");
		return FALSE;
	}

	if (GetThreadBreakpoints(ThreadId))
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("InitNewThreadBreakpoints: Thread breakpoints already exists for thread %d.\n", ThreadId);
#endif
		return FALSE;
	}

	NewThreadBreakpoints = CreateThreadBreakpoints(ThreadId, Handle);

	if (NewThreadBreakpoints == NULL)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("InitNewThreadBreakpoints: Cannot create new thread breakpoints.\n");
#endif
		return FALSE;
	}

	if (NewThreadBreakpoints->ThreadHandle == NULL)
	{
		DebugOutput("InitNewThreadBreakpoints error: main thread handle not set.\n");
		return FALSE;
	}

	for (unsigned int Register = 0; Register < NUMBER_OF_DEBUG_REGISTERS; Register++)
	{
		if (!MainThreadBreakpointList->BreakpointInfo[Register].Address)
			continue;

		if (!SetThreadBreakpoint(ThreadId, Register, MainThreadBreakpointList->BreakpointInfo[Register].Size, MainThreadBreakpointList->BreakpointInfo[Register].Address, MainThreadBreakpointList->BreakpointInfo[Register].Type, MainThreadBreakpointList->BreakpointInfo[Register].HitCount, MainThreadBreakpointList->BreakpointInfo[Register].Callback))
		{
			DebugOutput("InitNewThreadBreakpoints error: failed to set breakpoint %d for new thread %d.\n", Register, ThreadId);
			return FALSE;
		}

		if (!NewThreadBreakpoints->BreakpointInfo[Register].Address)
			DebugOutput("InitNewThreadBreakpoints error: problem detected setting breakpoint %d for new thread %d.\n", Register, ThreadId);
		else
			ThreadBreakpointsSet = TRUE;

	}

	if (ThreadBreakpointsSet)
		DebugOutput("InitNewThreadBreakpoints: Breakpoints set for thread %d.\n", ThreadId);
#ifdef DEBUG_COMMENTS
	else
		DebugOutput("InitNewThreadBreakpoints: No breakpoints set for thread %d.\n", ThreadId);
#endif

	return TRUE;
}

//**************************************************************************************
void OutputThreadBreakpoints(DWORD ThreadId)
//**************************************************************************************
{
	PTHREADBREAKPOINTS ThreadBreakpoints = GetThreadBreakpoints(ThreadId);

	if (!ThreadBreakpoints)
	{
		DebugOutput("OutputThreadBreakpoints: No breakpoints for thread %d.\n", ThreadId);
		return;
	}

	DebugOutput("Breakpoints for thread %d: 0x%p, 0x%p, 0x%p, 0x%p.\n", ThreadId, ThreadBreakpoints->BreakpointInfo[0].Address, ThreadBreakpoints->BreakpointInfo[1].Address, ThreadBreakpoints->BreakpointInfo[2].Address, ThreadBreakpoints->BreakpointInfo[3].Address);

	return;
}

//**************************************************************************************
BOOL GetNextAvailableBreakpoint(DWORD ThreadId, int* Register)
//**************************************************************************************
{
	DWORD CurrentThreadId;

	PTHREADBREAKPOINTS CurrentThreadBreakpoints = MainThreadBreakpointList;

	if (CurrentThreadBreakpoints == NULL)
	{
		DebugOutput("GetNextAvailableBreakpoint: MainThreadBreakpointList NULL.\n");
		return FALSE;
	}

	while (CurrentThreadBreakpoints)
	{
		CurrentThreadId = GetThreadId(CurrentThreadBreakpoints->ThreadHandle);

		if (CurrentThreadId == ThreadId)
		{
			for (unsigned int i=0; i < NUMBER_OF_DEBUG_REGISTERS; i++)
			{
				if (CurrentThreadBreakpoints->BreakpointInfo[i].Address == NULL)
				{
					*Register = i;
					return TRUE;
				}
			}
		}

		CurrentThreadBreakpoints = CurrentThreadBreakpoints->NextThreadBreakpoints;
	}

	return FALSE;
}

//**************************************************************************************
BOOL ContextGetNextAvailableBreakpoint(PCONTEXT Context, int* Register)
//**************************************************************************************
{
	unsigned int i;
	PTHREADBREAKPOINTS CurrentThreadBreakpoints;

	CurrentThreadBreakpoints = GetThreadBreakpoints(GetCurrentThreadId());

	if (CurrentThreadBreakpoints == NULL)
	{
		DebugOutput("ContextGetNextAvailableBreakpoint: Creating new thread breakpoints for thread %d.\n", GetCurrentThreadId());
		CurrentThreadBreakpoints = CreateThreadBreakpoints(GetCurrentThreadId(), NULL);
	}

	if (CurrentThreadBreakpoints == NULL)
	{
		DebugOutput("ContextGetNextAvailableBreakpoint: Cannot create new thread breakpoints.\n");
		return FALSE;
	}

	for (i=0; i < NUMBER_OF_DEBUG_REGISTERS; i++)
	{
		if (CurrentThreadBreakpoints->BreakpointInfo[i].Address == NULL)
		{
			*Register = i;
			return TRUE;
		}
	}

	return FALSE;
}

//**************************************************************************************
void DebugOutputThreadBreakpoints()
//**************************************************************************************
{
	unsigned int Register;
	PTHREADBREAKPOINTS CurrentThreadBreakpoints;
	PBREAKPOINTINFO pBreakpointInfo;

	CurrentThreadBreakpoints = GetThreadBreakpoints(GetCurrentThreadId());

	for (Register = 0; Register < NUMBER_OF_DEBUG_REGISTERS; Register++)
	{
		pBreakpointInfo = &(CurrentThreadBreakpoints->BreakpointInfo[Register]);

		if (pBreakpointInfo == NULL)
		{
			DebugOutput("DebugOutputThreadBreakpoints: Can't get BreakpointInfo.\n");
		}

		DebugOutput("Callback = 0x%x, Address = 0x%x, Size = 0x%x, Register = %i, ThreadHandle = 0x%x, Type = 0x%x\n",
			pBreakpointInfo->Callback,
			pBreakpointInfo->Address,
			pBreakpointInfo->Size,
			pBreakpointInfo->Register,
			pBreakpointInfo->ThreadHandle,
			pBreakpointInfo->Type);
	}
}

//**************************************************************************************
void ShowStack(DWORD_PTR StackPointer, unsigned int NumberOfRecords)
//**************************************************************************************
{
	unsigned int i;

	for (i=0; i<NumberOfRecords; i++)
		DebuggerOutput("0x%x ([esp+0x%x]): 0x%x\n", StackPointer+4*i, (4*i), *(DWORD*)((BYTE*)StackPointer+4*i));
}

//**************************************************************************************
BOOL RestoreSoftwareBreakpoint(struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
#ifdef DEBUG_COMMENTS
	DebugOutput("RestoreSoftwareBreakpoint: Restoring software breakpoint at 0x%p", ExceptionInfo->ExceptionRecord->ExceptionAddress);
#endif
	return SetSoftwareBreakpoint(ExceptionInfo->ExceptionRecord->ExceptionAddress);
}

//**************************************************************************************
BOOL SoftwareBreakpointHandler(struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	DWORD OldProtect;
	PVOID Address = ExceptionInfo->ExceptionRecord->ExceptionAddress;

	if (!Address)
		return FALSE;

	BYTE InsByte = *(PBYTE)Address;
	if (InsByte != 0xCC)
		return FALSE;

	PBYTE pInsByte = lookup_get(&SoftBPs, (ULONG_PTR)Address, 0);

	if (!pInsByte)
	{
		DebugOutput("SoftwareBreakpointHandler: Unable to retrieve instruction byte for 0x%p", Address);
		return FALSE;
	}

#ifdef DEBUG_COMMENTS
	DebugOutput("SoftwareBreakpointHandler: Instruction byte at 0x%p: 0x%x", Address, *pInsByte);
#endif
	if (!VirtualProtect(Address, 1, PAGE_EXECUTE_READWRITE, &OldProtect))
	{
		DebugOutput("SoftwareBreakpointHandler: Unable to change memory protection at 0x%p", Address);
		return FALSE;
	}

	*(PBYTE)Address = *pInsByte;

	VirtualProtect(Address, 1, OldProtect, &OldProtect);

	SoftwareBreakpointCallback(ExceptionInfo);

	return TRUE;
}

//**************************************************************************************
BOOL SyscallBreakpointHandler(struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
#ifdef _WIN64
	unsigned int SSN = (unsigned int)(DWORD_PTR)ExceptionInfo->ContextRecord->Rax;
#else
	unsigned int SSN = (unsigned int)(DWORD_PTR)ExceptionInfo->ContextRecord->Eax;
#endif

	PVOID Function = GetProcAddress(GetModuleHandle("ntdll"), GetNameBySsn(SSN));

	if (!Function)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("SyscallBreakpointHandler: Unable to find function for SSN 0x%x\n", SSN);
#endif
		return FALSE;
	}
#ifdef DEBUG_COMMENTS
	else
		DebugOutput("SyscallBreakpointHandler: Calling %s at 0x%p\n", GetNameBySsn(SSN), Function);
#endif

#ifdef _WIN64
	ExceptionInfo->ContextRecord->Rip = (DWORD_PTR)Function;
#else
	ExceptionInfo->ContextRecord->Eip = (DWORD_PTR)Function;
#endif

	return TRUE;
}

//**************************************************************************************
BOOL CAPEExceptionDispatcher(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context)
//**************************************************************************************
{
	EXCEPTION_POINTERS ExceptionInfo;
	ExceptionInfo.ExceptionRecord = ExceptionRecord;
	ExceptionInfo.ContextRecord = Context;
	return (CAPEExceptionFilter(&ExceptionInfo) == EXCEPTION_CONTINUE_EXECUTION);
}

//**************************************************************************************
LONG WINAPI CAPEExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	unsigned int bp;
	DWORD CurrentThreadId = GetCurrentThreadId();

	// Hardware breakpoints generate EXCEPTION_SINGLE_STEP rather than EXCEPTION_BREAKPOINT
	if (g_config.debugger && ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		PBREAKPOINTINFO pBreakpointInfo;
		PTHREADBREAKPOINTS CurrentThreadBreakpoints;

		CurrentThreadBreakpoints = GetThreadBreakpoints(CurrentThreadId);

		if (CurrentThreadBreakpoints == NULL)
		{
			DebugOutput("CAPEExceptionFilter: Can't find breakpoints for thread %d\n", CurrentThreadId);
			return EXCEPTION_CONTINUE_SEARCH;
		}

		// Test Dr6 to see if this is a breakpoint
		for (bp = 0; bp < NUMBER_OF_DEBUG_REGISTERS; bp++)
			if (ExceptionInfo->ContextRecord->Dr6 & (DWORD_PTR)(1 << bp))
				break;

		// If not it's a single-step
		if (bp == NUMBER_OF_DEBUG_REGISTERS)
		{
			if (SingleStepHandler)
				SingleStepHandler(ExceptionInfo);
			else
			{
				// Unhandled single-step exception, pass it on
				if (BreakpointsSet)
					ContextClearDebugRegisters(ExceptionInfo->ContextRecord);
				return EXCEPTION_CONTINUE_SEARCH;
			}

			return EXCEPTION_CONTINUE_EXECUTION;
		}

		if (TrapIndex)
			DebugOutput("CAPEExceptionFilter: Anomaly detected: Trap index set on non-single-step: %d\n", TrapIndex);

#ifndef DEBUG_COMMENTS
		if (!TraceRunning && !g_config.no_logs)
#endif
			DebugOutput("CAPEExceptionFilter: breakpoint %d hit by instruction at 0x%p (thread %d)\n", bp, ExceptionInfo->ExceptionRecord->ExceptionAddress, CurrentThreadId);

		pBreakpointInfo = &(CurrentThreadBreakpoints->BreakpointInfo[bp]);

		if (pBreakpointInfo == NULL)
		{
			DebugOutput("CAPEExceptionFilter: Can't get BreakpointInfo for thread %d\n", CurrentThreadId);
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		if (bp == 0 && ((DWORD_PTR)pBreakpointInfo->Address != ExceptionInfo->ContextRecord->Dr0))
			DebugOutput("CAPEExceptionFilter: Anomaly detected! bp0 address (0x%x) different to BreakpointInfo (0x%x)!\n", ExceptionInfo->ContextRecord->Dr0, pBreakpointInfo->Address);

		if (bp == 1 && ((DWORD_PTR)pBreakpointInfo->Address != ExceptionInfo->ContextRecord->Dr1))
			DebugOutput("CAPEExceptionFilter: Anomaly detected! bp1 address (0x%x) different to BreakpointInfo (0x%x)!\n", ExceptionInfo->ContextRecord->Dr1, pBreakpointInfo->Address);

		if (bp == 2 && ((DWORD_PTR)pBreakpointInfo->Address != ExceptionInfo->ContextRecord->Dr2))
			DebugOutput("CAPEExceptionFilter: Anomaly detected! bp2 address (0x%x) different to BreakpointInfo (0x%x)!\n", ExceptionInfo->ContextRecord->Dr2, pBreakpointInfo->Address);

		if (bp == 3 && ((DWORD_PTR)pBreakpointInfo->Address != ExceptionInfo->ContextRecord->Dr3))
			DebugOutput("CAPEExceptionFilter: Anomaly detected! bp3 address (0x%x) different to BreakpointInfo (0x%x)!\n", ExceptionInfo->ContextRecord->Dr3, pBreakpointInfo->Address);
#ifndef _WIN64
		if (bp == 0 && ((DWORD_PTR)pBreakpointInfo->Type != ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE0))
		{
			if (pBreakpointInfo->Type == BP_READWRITE && ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE0 == BP_WRITE && address_is_in_stack((DWORD_PTR)pBreakpointInfo->Address))
			{
				DebugOutput("CAPEExceptionFilter: Reinstated BP_READWRITE on breakpoint %d (WoW64 workaround)\n", pBreakpointInfo->Register);

				ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo->Register, pBreakpointInfo->Size, (BYTE*)pBreakpointInfo->Address, pBreakpointInfo->Type, pBreakpointInfo->HitCount, pBreakpointInfo->Callback);
			}
			else
			{
				DebugOutput("CAPEExceptionFilter: Anomaly detected! bp0 type (0x%x) different to BreakpointInfo (0x%x)!\n", ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE0, pBreakpointInfo->Type);
				CheckDebugRegisters(0, ExceptionInfo->ContextRecord);
			}
		}
		if (bp == 1 && ((DWORD)pBreakpointInfo->Type != ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE1))
		{
			if (pBreakpointInfo->Type == BP_READWRITE && ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE1 == BP_WRITE && address_is_in_stack((DWORD_PTR)pBreakpointInfo->Address))
			{
				DebugOutput("CAPEExceptionFilter: Reinstated BP_READWRITE on breakpoint %d (WoW64 workaround)\n", pBreakpointInfo->Register);

				ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo->Register, pBreakpointInfo->Size, (BYTE*)pBreakpointInfo->Address, pBreakpointInfo->Type, pBreakpointInfo->HitCount, pBreakpointInfo->Callback);
			}
			else
			{
				DebugOutput("CAPEExceptionFilter: Anomaly detected! bp1 type (0x%x) different to BreakpointInfo (0x%x)!\n", ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE1, pBreakpointInfo->Type);
				CheckDebugRegisters(0, ExceptionInfo->ContextRecord);
			}
		}
		if (bp == 2 && ((DWORD)pBreakpointInfo->Type != ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE2))
		{
			if (pBreakpointInfo->Type == BP_READWRITE && ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE2 == BP_WRITE && address_is_in_stack((DWORD_PTR)pBreakpointInfo->Address))
			{
				DebugOutput("CAPEExceptionFilter: Reinstated BP_READWRITE on stack breakpoint %d (WoW64 workaround)\n", pBreakpointInfo->Register);

				ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo->Register, pBreakpointInfo->Size, (BYTE*)pBreakpointInfo->Address, pBreakpointInfo->Type, pBreakpointInfo->HitCount, pBreakpointInfo->Callback);
			}
			else
			{
				DebugOutput("CAPEExceptionFilter: Anomaly detected! bp2 type (0x%x) different to BreakpointInfo (0x%x)!\n", ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE2, pBreakpointInfo->Type);
				CheckDebugRegisters(0, ExceptionInfo->ContextRecord);
			}
		}
		if (bp == 3 && ((DWORD)pBreakpointInfo->Type != ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE3))
		{
			if (pBreakpointInfo->Type == BP_READWRITE && ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE3 == BP_WRITE && address_is_in_stack((DWORD_PTR)pBreakpointInfo->Address))
			{
				DebugOutput("CAPEExceptionFilter: Reinstated BP_READWRITE on breakpoint %d (WoW64 workaround)\n", pBreakpointInfo->Register);

				ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo->Register, pBreakpointInfo->Size, (BYTE*)pBreakpointInfo->Address, pBreakpointInfo->Type, pBreakpointInfo->HitCount, pBreakpointInfo->Callback);
			}
			else
			{
				DebugOutput("CAPEExceptionFilter: Anomaly detected! bp3 type (0x%x) different to BreakpointInfo (0x%x)!\n", ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE3, pBreakpointInfo->Type);
				CheckDebugRegisters(0, ExceptionInfo->ContextRecord);
			}
		}
#endif // !_WIN64

		if (pBreakpointInfo->HitCount)
		{
			pBreakpointInfo->HitCount--;
			if (!pBreakpointInfo->HitCount)
			{
#ifdef DEBUG_COMMENTS
				DebugOutput("CAPEExceptionFilter: Clearing breakpoint %d due to hit count.\n", pBreakpointInfo->Register);
#endif
				ContextClearBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo->Register);
				//ApplyQueuedBreakpoints(ExceptionInfo->ContextRecord, pBreakpointInfo);
			}
		}

		if (pBreakpointInfo->Callback == NULL)
		{
			DebugOutput("CAPEExceptionFilter: Can't find callback, passing exception (thread %d)\n", CurrentThreadId);
			return EXCEPTION_CONTINUE_SEARCH;
		}
		else
		{
			// Invoke the handler
			if (pBreakpointInfo->Callback && !pBreakpointInfo->HandlerActive)
			{
				pBreakpointInfo->HandlerActive = TRUE;
#ifdef DEBUG_COMMENTS
				DebugOutput("CAPEExceptionFilter: About to call breakpoint handler at: 0x%p\n", pBreakpointInfo->Callback);
#endif
				((BREAKPOINT_HANDLER)pBreakpointInfo->Callback)(pBreakpointInfo, ExceptionInfo);
				pBreakpointInfo->HandlerActive = FALSE;
				ResumeFromBreakpoint(ExceptionInfo->ContextRecord);
			}
		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (g_config.debugger && ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT && *(PBYTE)ExceptionInfo->ExceptionRecord->ExceptionAddress == 0xCC)
	{
		// Check to see if it's a software breakpoint and it's ours
		if (lookup_get(&SoftBPs, (ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress, 0))
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("CAPEExceptionFilter: Software breakpoint at 0x%p\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);
#endif
			if (SoftwareBreakpointHandler(ExceptionInfo))
				return EXCEPTION_CONTINUE_EXECUTION;
		}

		// Is it a 'syscall' breakpoint
		if (lookup_get(&SyscallBPs, (ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress, 0))
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("CAPEExceptionFilter: 'syscall' breakpoint at 0x%p\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);
#endif
			if (SyscallBreakpointHandler(ExceptionInfo))
				return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	else if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_PRIVILEGED_INSTRUCTION || ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ILLEGAL_INSTRUCTION)
	{
#ifdef _WIN64
		_DecodedInst instruction;
		if (ide(&instruction, (void*)ExceptionInfo->ContextRecord->Rip) && !stricmp("rdtscp", instruction.mnemonic.p)) {
			if (g_config.nop_rdtscp)
			{
				DWORD OldProtect;
				VirtualProtect((PVOID)ExceptionInfo->ContextRecord->Rip, 3, PAGE_EXECUTE_READWRITE, &OldProtect);
				memcpy((PVOID)ExceptionInfo->ContextRecord->Rip, "\x90\x90\x90", 3);
				VirtualProtect((PVOID)ExceptionInfo->ContextRecord->Rip, 3, OldProtect, &OldProtect);
			}
			else
			{
				DWORD64 Timestamp = __rdtsc();
				ExceptionInfo->ContextRecord->Rax = (DWORD)Timestamp;
				ExceptionInfo->ContextRecord->Rdx = Timestamp >> 32;
				ExceptionInfo->ContextRecord->Rip += lde((void*)ExceptionInfo->ContextRecord->Rip);
			}
#else
		// Bug: our distorm fails to dissassemble rdtscp on x86
		//if (ide(&instruction, (void*)ExceptionInfo->ContextRecord->Eip) && !stricmp("rdtscp", instruction.mnemonic.p)) {
		if (!memcmp((PUCHAR)ExceptionInfo->ContextRecord->Eip, "\x0f\x01\xf9", 3)) {
			if (g_config.nop_rdtscp)
			{
				DWORD OldProtect;
				VirtualProtect((PVOID)ExceptionInfo->ContextRecord->Eip, 3, PAGE_EXECUTE_READWRITE, &OldProtect);
				memcpy((PVOID)ExceptionInfo->ContextRecord->Eip, "\x90\x90\x90", 3);
				VirtualProtect((PVOID)ExceptionInfo->ContextRecord->Eip, 3, OldProtect, &OldProtect);
			}
			else
			{
				DWORD64 Timestamp = __rdtsc();
				ExceptionInfo->ContextRecord->Eax = (DWORD)Timestamp;
				ExceptionInfo->ContextRecord->Edx = Timestamp >> 32;
				ExceptionInfo->ContextRecord->Eip += lde((void*)ExceptionInfo->ContextRecord->Eip);
			}
#endif
			return EXCEPTION_CONTINUE_EXECUTION;
		}
#ifdef DEBUG_COMMENTS
#ifdef _WIN64
		else if (ide(&instruction, (void*)ExceptionInfo->ContextRecord->Rip))
			DebugOutput("RtlDispatchException: Unhandled privileged %s instruction at 0x%p\n", instruction.mnemonic.p, ExceptionInfo->ContextRecord->Rip);
		else
			DebugOutput("RtlDispatchException: Unhandled privileged instruction at 0x%p\n", ExceptionInfo->ContextRecord->Rip);
#else
		else if (ide(&instruction, (void*)ExceptionInfo->ContextRecord->Eip))
			DebugOutput("RtlDispatchException: Unhandled privileged %s instruction at 0x%p\n", instruction.mnemonic.p, ExceptionInfo->ContextRecord->Eip);
		else
			DebugOutput("RtlDispatchException: Unhandled privileged instruction at 0x%p\n", ExceptionInfo->ContextRecord->Eip);
#endif
#endif
	}

	// Exceptions in capemon
	if ((ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress >= g_our_dll_base && (ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress < (g_our_dll_base + g_our_dll_size))
		// Filter STATUS_GUARD_PAGE_VIOLATION upon process termination as it occurs routinely in process dump full memory scan
		if (!(process_shutting_down && ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION))
			DebugOutput("CAPEExceptionFilter: Exception 0x%x accessing 0x%x caught at RVA 0x%x in capemon (expected in memory scans), passing to next handler.\n", ExceptionInfo->ExceptionRecord->ExceptionCode, ExceptionInfo->ExceptionRecord->ExceptionInformation[1], (BYTE*)ExceptionInfo->ExceptionRecord->ExceptionAddress - g_our_dll_base);

	if (TraceRunning)
	{
		unsigned int RVA;
		char *ModuleName = convert_address_to_dll_name_and_offset((ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress, &RVA);
		if (ModuleName)
		{
			if (!ExceptionInfo->ExceptionRecord->NumberParameters)
				DebuggerOutput("\nException 0x%x at 0x%p in %s (RVA 0x%x, thread %d), flags 0x%x\n", ExceptionInfo->ExceptionRecord->ExceptionCode, ExceptionInfo->ExceptionRecord->ExceptionAddress, ModuleName, RVA, CurrentThreadId, ExceptionInfo->ExceptionRecord->ExceptionFlags);
			else if (ExceptionInfo->ExceptionRecord->NumberParameters == 1)
				DebuggerOutput("\nException 0x%x at 0x%p in %s (RVA 0x%x, thread %d), flags 0x%x, exception information 0x%p\n", ExceptionInfo->ExceptionRecord->ExceptionCode, ExceptionInfo->ExceptionRecord->ExceptionAddress, ModuleName, RVA, CurrentThreadId, ExceptionInfo->ExceptionRecord->ExceptionFlags, ExceptionInfo->ExceptionRecord->ExceptionInformation[0]);
			else if (ExceptionInfo->ExceptionRecord->NumberParameters == 2)
				DebuggerOutput("\nException 0x%x at 0x%p in %s (RVA 0x%x, thread %d), flags 0x%x, exception information[0] 0x%p, exception information[1] 0x%p\n", ExceptionInfo->ExceptionRecord->ExceptionCode, ExceptionInfo->ExceptionRecord->ExceptionAddress, ModuleName, RVA, CurrentThreadId, ExceptionInfo->ExceptionRecord->ExceptionFlags, ExceptionInfo->ExceptionRecord->ExceptionInformation[0], ExceptionInfo->ExceptionRecord->ExceptionInformation[1]);
		}
		else
		{
			if (!ExceptionInfo->ExceptionRecord->NumberParameters)
				DebuggerOutput("\nException 0x%x at 0x%p, thread %d, flags 0x%x\n", ExceptionInfo->ExceptionRecord->ExceptionCode, ExceptionInfo->ExceptionRecord->ExceptionAddress, CurrentThreadId, ExceptionInfo->ExceptionRecord->ExceptionFlags);
			else if (ExceptionInfo->ExceptionRecord->NumberParameters == 1)
				DebuggerOutput("\nException 0x%x at 0x%p, thread %d, flags 0x%x, exception information 0x%p\n", ExceptionInfo->ExceptionRecord->ExceptionCode, ExceptionInfo->ExceptionRecord->ExceptionAddress, CurrentThreadId, ExceptionInfo->ExceptionRecord->ExceptionFlags, ExceptionInfo->ExceptionRecord->ExceptionInformation[0]);
			else if (ExceptionInfo->ExceptionRecord->NumberParameters == 2)
				DebuggerOutput("\nException 0x%x at 0x%p, thread %d, flags 0x%x, exception information[0] 0x%p, exception information[1] 0x%p\n", ExceptionInfo->ExceptionRecord->ExceptionCode, ExceptionInfo->ExceptionRecord->ExceptionAddress, CurrentThreadId, ExceptionInfo->ExceptionRecord->ExceptionFlags, ExceptionInfo->ExceptionRecord->ExceptionInformation[0], ExceptionInfo->ExceptionRecord->ExceptionInformation[1]);
		}
#ifdef _WIN64
		DebuggerOutput(
			"RAX 0x%I64x RBX 0x%I64x RCX 0x%I64x RDX 0x%I64x RSI 0x%I64x RDI 0x%I64x\nR8 0x%I64x R9 0x%I64x R10 0x%I64x R11 0x%I64x R12 0x%I64x R13 0x%I64x R14 0x%I64x R15 0x%I64x RSP 0x%I64x RBP 0x%I64x\n",
			ExceptionInfo->ContextRecord->Rax, ExceptionInfo->ContextRecord->Rbx, ExceptionInfo->ContextRecord->Rcx, ExceptionInfo->ContextRecord->Rdx,
			ExceptionInfo->ContextRecord->Rsi, ExceptionInfo->ContextRecord->Rdi, ExceptionInfo->ContextRecord->R8, ExceptionInfo->ContextRecord->R9,
			ExceptionInfo->ContextRecord->R10, ExceptionInfo->ContextRecord->R11, ExceptionInfo->ContextRecord->R12, ExceptionInfo->ContextRecord->R13,
			ExceptionInfo->ContextRecord->R14, ExceptionInfo->ContextRecord->R15, ExceptionInfo->ContextRecord->Rsp, ExceptionInfo->ContextRecord->Rbp
			);
#else
		DebuggerOutput(
			"EAX 0x%x EBX 0x%x ECX 0x%x EDX 0x%x ESI 0x%x EDI 0x%x ESP 0x%x EBP 0x%x\n",
			ExceptionInfo->ContextRecord->Eax, ExceptionInfo->ContextRecord->Ebx, ExceptionInfo->ContextRecord->Ecx, ExceptionInfo->ContextRecord->Edx,
			ExceptionInfo->ContextRecord->Esi, ExceptionInfo->ContextRecord->Edi, ExceptionInfo->ContextRecord->Esp, ExceptionInfo->ContextRecord->Ebp
			);
#endif
		DoTraceOutput((PVOID)ExceptionInfo->ExceptionRecord->ExceptionAddress);
	}

	if (BreakpointsSet)
		ContextClearDebugRegisters(ExceptionInfo->ContextRecord);

	// Some other exception occurred. Pass it to next handler.
	return EXCEPTION_CONTINUE_SEARCH;
}

//**************************************************************************************
BOOL ContextSetDebugRegisterEx
//**************************************************************************************
(
	PCONTEXT	Context,
	int			Register,
	int			Size,
	LPVOID		Address,
	DWORD		Type,
	BOOL		NoSetThreadContext
)
{
	DWORD Length;
#ifdef _WIN64
	PTHREADBREAKPOINTS CurrentThreadBreakpoints;
#endif

	PDWORD_PTR Dr0 = &(Context->Dr0);
	PDWORD_PTR Dr1 = &(Context->Dr1);
	PDWORD_PTR Dr2 = &(Context->Dr2);
	PDWORD_PTR Dr3 = &(Context->Dr3);
	PDR7 Dr7 = (PDR7)&(Context->Dr7);

	if ((unsigned int)Type > 3)
	{
		DebugOutput("ContextSetDebugRegister: %d is an invalid breakpoint type, must be 0-3.\n", Type);
		return FALSE;
	}

	if (Type == 2)
	{
		DebugOutput("ContextSetDebugRegister: The value 2 is a 'reserved' breakpoint type, ultimately invalid.\n");
		return FALSE;
	}

	if (Register < 0 || Register > 3)
	{
		DebugOutput("ContextSetDebugRegister: %d is an invalid register, must be 0-3.\n", Register);
		return FALSE;
	}

	if (Size < 0 || Size > 8)
	{
		DebugOutput("ContextSetDebugRegister: %d is an invalid Size, must be 1, 2, 4 or 8.\n", Size);
		return FALSE;
	}

	Length	= LengthMask[Size];

	// intel spec requires 0 for bp on execution
	if (Type == BP_EXEC)
		Length = 0;

#ifndef _WIN64
	if (Type == BP_READWRITE && address_is_in_stack((DWORD_PTR)Address))
		WoW64PatchBreakpoint(Register);
#endif

	if (Register == 0)
	{
		*Dr0 = (DWORD_PTR)Address;
		Dr7->LEN0 = Length;
		Dr7->RWE0 = Type;
		Dr7->L0 = 1;
	}
	else if (Register == 1)
	{
		*Dr1 = (DWORD_PTR)Address;
		Dr7->LEN1 = Length;
		Dr7->RWE1 = Type;
		Dr7->L1 = 1;
	}
	else if (Register == 2)
	{
		*Dr2 = (DWORD_PTR)Address;
		Dr7->LEN2 = Length;
		Dr7->RWE2 = Type;
		Dr7->L2 = 1;
	}
	else if (Register == 3)
	{
		*Dr3 = (DWORD_PTR)Address;
		Dr7->LEN3 = Length;
		Dr7->RWE3 = Type;
		Dr7->L3 = 1;
	}

#ifdef _WIN64
	if (NoSetThreadContext)
		return TRUE;

	CurrentThreadBreakpoints = GetThreadBreakpoints(GetCurrentThreadId());

	if (CurrentThreadBreakpoints == NULL)
	{
		DebugOutput("ContextSetDebugRegister: No breakpoints found for current thread %d.\n", GetCurrentThreadId());
		return FALSE;
	}

	if (CurrentThreadBreakpoints->ThreadHandle == NULL)
	{
		DebugOutput("ContextSetDebugRegister: No thread handle found in breakpoints found for current thread %d.\n", GetCurrentThreadId());
		return FALSE;
	}

	Context->ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!SetThreadContext(CurrentThreadBreakpoints->ThreadHandle, Context))
	{
		ErrorOutput("ContextSetDebugRegister: SetThreadContext failed");
		return FALSE;
	}
#endif

#ifdef DEBUG_COMMENTS
	DebugOutput("ContextSetDebugRegisterEx completed successfully: Register %d size %d Address 0x%p Type %d", Register, Size, Address, Type);
#endif

	return TRUE;
}

//**************************************************************************************
BOOL ContextSetDebugRegister
//**************************************************************************************
(
	PCONTEXT	Context,
	int			Register,
	int			Size,
	LPVOID		Address,
	DWORD		Type
)
{
	return ContextSetDebugRegisterEx(Context, Register, Size, Address, Type, FALSE);
}

//**************************************************************************************
BOOL SetDebugRegister
//**************************************************************************************
(
	HANDLE	hThread,
	int		Register,
	int		Size,
	LPVOID	Address,
	DWORD	Type
)
{
	DWORD Length;
	CONTEXT Context;

	PDWORD_PTR Dr0 = &Context.Dr0;
	PDWORD_PTR Dr1 = &Context.Dr1;
	PDWORD_PTR Dr2 = &Context.Dr2;
	PDWORD_PTR Dr3 = &Context.Dr3;
	PDR7 Dr7 = (PDR7)&(Context.Dr7);

	if ((unsigned int)Type > 3)
	{
		DebugOutput("SetDebugRegister: %d is an invalid breakpoint type, must be 0-3.\n", Type);
		return FALSE;
	}

	if (Type == 2)
	{
		DebugOutput("SetDebugRegister: The value 2 is a 'reserved' breakpoint type, ultimately invalid.\n");
		return FALSE;
	}

	if (Register < 0 || Register > 3)
	{
		DebugOutput("SetDebugRegister: %d is an invalid register, must be 0-3.\n", Register);
		return FALSE;
	}

	if (Size < 0 || Size > 8)
	{
		DebugOutput("SetDebugRegister: %d is an invalid Size, must be 1, 2, 4 or 8.\n", Size);
		return FALSE;
	}

#ifdef DEBUG_COMMENTS
	DebugOutput("SetDebugRegister: Setting breakpoint %i hThread=0x%x, Size=0x%x, Address=0x%p and Type=0x%x.\n", Register, hThread, Size, Address, Type);
#endif

	Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(hThread, &Context))
	{
#ifdef DEBUG_COMMENTS
		ErrorOutput("SetDebugRegister: GetThreadContext failed (thread handle 0x%x)", hThread);
#endif
		return FALSE;
	}

	Length	= LengthMask[Size];

	// intel spec requires 0 for bp on execution
	if (Type == BP_EXEC)
		Length = 0;

#ifndef _WIN64
	if (Type == BP_READWRITE && address_is_in_stack((DWORD_PTR)Address))
		WoW64PatchBreakpoint(Register);
#endif

	if (Register == 0)
	{
		*Dr0 = (DWORD_PTR)Address;
		Dr7->LEN0 = Length;
		Dr7->RWE0 = Type;
		Dr7->L0 = 1;
	}
	else if (Register == 1)
	{
		*Dr1 = (DWORD_PTR)Address;
		Dr7->LEN1 = Length;
		Dr7->RWE1 = Type;
		Dr7->L1 = 1;
	}
	else if (Register == 2)
	{
		*Dr2 = (DWORD_PTR)Address;
		Dr7->LEN2 = Length;
		Dr7->RWE2 = Type;
		Dr7->L2 = 1;
	}
	else if (Register == 3)
	{
		*Dr3 = (DWORD_PTR)Address;
		Dr7->LEN3 = Length;
		Dr7->RWE3 = Type;
		Dr7->L3 = 1;
	}

	Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!SetThreadContext(hThread, &Context))
	{
		ErrorOutput("SetDebugRegister: SetThreadContext failed");
		return FALSE;
	}

	return TRUE;
}

//**************************************************************************************
BOOL ContextClearDebugRegisters(PCONTEXT Context)
//**************************************************************************************
{
	if (!Context)
	{
		DebugOutput("ContextClearDebugRegisters - no context supplied.\n");
		return FALSE;
	}

	Context->Dr0 = 0;
	Context->Dr1 = 0;
	Context->Dr2 = 0;
	Context->Dr3 = 0;
	Context->Dr6 = 0;
	Context->Dr7 = 0;

	return TRUE;
}

//**************************************************************************************
BOOL ContextCheckDebugRegisters(PCONTEXT Context)
//**************************************************************************************
{
	PDR7 Dr7;

	if (!Context)
	{
		DebugOutput("CheckDebugRegisters - no context supplied.\n");
		return FALSE;
	}

	Dr7 = (PDR7)&(Context->Dr7);

	DebugOutput("Checking breakpoints\n");
	DebugOutput("Dr0 0x%p, Dr7->LEN0 %i, Dr7->RWE0 %i, Dr7->L0 %i\n", Context->Dr0, Dr7->LEN0, Dr7->RWE0, Dr7->L0);
	DebugOutput("Dr1 0x%p, Dr7->LEN1 %i, Dr7->RWE1 %i, Dr7->L1 %i\n", Context->Dr1, Dr7->LEN1, Dr7->RWE1, Dr7->L1);
	DebugOutput("Dr2 0x%p, Dr7->LEN2 %i, Dr7->RWE2 %i, Dr7->L2 %i\n", Context->Dr2, Dr7->LEN2, Dr7->RWE2, Dr7->L2);
	DebugOutput("Dr3 0x%p, Dr7->LEN3 %i, Dr7->RWE3 %i, Dr7->L3 %i\n", Context->Dr3, Dr7->LEN3, Dr7->RWE3, Dr7->L3);
	DebugOutput("Dr6 0x%p\n", Context->Dr6);

	return TRUE;
}

//**************************************************************************************
BOOL CheckDebugRegisters(HANDLE hThread, PCONTEXT pContext)
//**************************************************************************************
{
	CONTEXT	Context;
	PDWORD_PTR Dr0 = &Context.Dr0;
	PDWORD_PTR Dr1 = &Context.Dr1;
	PDWORD_PTR Dr2 = &Context.Dr2;
	PDWORD_PTR Dr3 = &Context.Dr3;
	PDR7 Dr7 = (PDR7)&(Context.Dr7);

	if (!hThread && !pContext)
	{
		DebugOutput("CheckDebugRegisters - required arguments missing.\n");
		return FALSE;
	}

	if (!hThread)
	{
		Context = *pContext;
	}
	else if (!pContext)
	{
		Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		if (!GetThreadContext(hThread, &Context))
		{
			DebugOutput("CheckDebugRegisters - failed to get thread context.\n");
			return FALSE;
		}
	}

	DebugOutput("Checking breakpoints\n");
	DebugOutput("*Dr0 0x%x, Dr7->LEN0 %i, Dr7->RWE0 %i, Dr7->L0 %i\n", *Dr0, Dr7->LEN0, Dr7->RWE0, Dr7->L0);
	DebugOutput("*Dr1 0x%x, Dr7->LEN1 %i, Dr7->RWE1 %i, Dr7->L1 %i\n", *Dr1, Dr7->LEN1, Dr7->RWE1, Dr7->L1);
	DebugOutput("*Dr2 0x%x, Dr7->LEN2 %i, Dr7->RWE2 %i, Dr7->L2 %i\n", *Dr2, Dr7->LEN2, Dr7->RWE2, Dr7->L2);
	DebugOutput("*Dr3 0x%x, Dr7->LEN3 %i, Dr7->RWE3 %i, Dr7->L3 %i\n", *Dr3, Dr7->LEN3, Dr7->RWE3, Dr7->L3);
	DebugOutput("Dr6 0x%x, thread handle 0x%x\n", Context.Dr6, hThread);

	return TRUE;
}

//**************************************************************************************
BOOL ContextClearAllBreakpointsEx(PCONTEXT Context, BOOL NoSetThreadContext)
//**************************************************************************************
{
	unsigned int i;
	PTHREADBREAKPOINTS CurrentThreadBreakpoints;

	CurrentThreadBreakpoints = GetThreadBreakpoints(GetCurrentThreadId());

	if (CurrentThreadBreakpoints == NULL)
	{
		DebugOutput("ContextClearAllBreakpoints: No breakpoints found for current thread %d.\n", GetCurrentThreadId());
		return FALSE;
	}

	for (i=0; i < NUMBER_OF_DEBUG_REGISTERS; i++)
	{
		CurrentThreadBreakpoints->BreakpointInfo[i].Register = 0;
		CurrentThreadBreakpoints->BreakpointInfo[i].Size = 0;
		CurrentThreadBreakpoints->BreakpointInfo[i].Address = NULL;
		CurrentThreadBreakpoints->BreakpointInfo[i].Type = 0;
		CurrentThreadBreakpoints->BreakpointInfo[i].HitCount = 0;
		CurrentThreadBreakpoints->BreakpointInfo[i].Callback = NULL;
	}

	Context->Dr0 = 0;
	Context->Dr1 = 0;
	Context->Dr2 = 0;
	Context->Dr3 = 0;
	Context->Dr6 = 0;
	Context->Dr7 = 0;

#ifdef _WIN64
	if (NoSetThreadContext)
		return TRUE;

	if (CurrentThreadBreakpoints->ThreadHandle == NULL)
	{
		DebugOutput("ContextClearAllBreakpoints: No thread handle found in breakpoints found for current thread %d.\n", GetCurrentThreadId());
		return FALSE;
	}

	Context->ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!SetThreadContext(CurrentThreadBreakpoints->ThreadHandle, Context))
	{
		ErrorOutput("ContextClearAllBreakpoints: SetThreadContext failed");
		return FALSE;
	}
#ifdef DEBUG_COMMENTS
	else
		DebugOutput("ContextClearAllBreakpoints: SetThreadContext success.\n");
#endif
#endif

	return TRUE;
}

BOOL ContextClearAllBreakpoints(PCONTEXT Context)
{
	BOOL NoSetThreadContext = FALSE;

	if ((OSVersion.dwMajorVersion == 6 && OSVersion.dwMinorVersion > 1) || OSVersion.dwMajorVersion > 6)
		NoSetThreadContext = TRUE;

	return ContextClearAllBreakpointsEx(Context, NoSetThreadContext);
}

//**************************************************************************************
BOOL ClearAllBreakpoints()
//**************************************************************************************
{
	CONTEXT	Context;
	PTHREADBREAKPOINTS CurrentThreadBreakpoints;
	unsigned int Register;

	CurrentThreadBreakpoints = MainThreadBreakpointList;

	while (CurrentThreadBreakpoints)
	{
		if (!CurrentThreadBreakpoints->ThreadId)
		{
			DebugOutput("ClearAllBreakpoints: Error: no thread id for thread breakpoints 0x%x.\n", CurrentThreadBreakpoints);
			return FALSE;
		}

		if (!CurrentThreadBreakpoints->ThreadHandle)
		{
			DebugOutput("ClearAllBreakpoints: Error no thread handle for thread %d.\n", CurrentThreadBreakpoints->ThreadId);
			return FALSE;
		}

		for (Register = 0; Register < NUMBER_OF_DEBUG_REGISTERS; Register++)
		{
			CurrentThreadBreakpoints->BreakpointInfo[Register].Register = 0;
			CurrentThreadBreakpoints->BreakpointInfo[Register].Size = 0;
			CurrentThreadBreakpoints->BreakpointInfo[Register].Address = NULL;
			CurrentThreadBreakpoints->BreakpointInfo[Register].Type = 0;
			CurrentThreadBreakpoints->BreakpointInfo[Register].HitCount = 0;
			CurrentThreadBreakpoints->BreakpointInfo[Register].Callback = NULL;
		}

		Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

		if (!GetThreadContext(CurrentThreadBreakpoints->ThreadHandle, &Context))
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("ClearAllBreakpoints: Error getting thread context (thread %d, handle 0x%x).\n", CurrentThreadBreakpoints->ThreadId, CurrentThreadBreakpoints->ThreadHandle);
#endif
			return FALSE;
		}

		Context.Dr0 = 0;
		Context.Dr1 = 0;
		Context.Dr2 = 0;
		Context.Dr3 = 0;
		Context.Dr6 = 0;
		Context.Dr7 = 0;

		if (!SetThreadContext(CurrentThreadBreakpoints->ThreadHandle, &Context))
		{
			DebugOutput("ClearAllBreakpoints: Error setting thread context (thread %d).\n", CurrentThreadBreakpoints->ThreadId);
			return FALSE;
		}

		CurrentThreadBreakpoints = CurrentThreadBreakpoints->NextThreadBreakpoints;
	}

	return TRUE;
}

//**************************************************************************************
BOOL ContextClearBreakpointEx(PCONTEXT Context, PBREAKPOINTINFO pBreakpointInfo, BOOL NoSetThreadContext)
//**************************************************************************************
{
	PDWORD_PTR Dr0, Dr1, Dr2, Dr3;
	PDR7 Dr7;

	if (Context == NULL)
		return FALSE;

	Dr0 = &(Context->Dr0);
	Dr1 = &(Context->Dr1);
	Dr2 = &(Context->Dr2);
	Dr3 = &(Context->Dr3);
	Dr7 = (PDR7)&(Context->Dr7);

#ifdef DEBUG_COMMENTS
	DebugOutput("ContextClearBreakpointEx: Clearing breakpoint %i\n", pBreakpointInfo->Register);
#endif

	if (pBreakpointInfo->Register == 0)
	{
		*Dr0 = 0;
		Dr7->LEN0 = 0;
		Dr7->RWE0 = 0;
		Dr7->L0 = 0;
	}
	else if (pBreakpointInfo->Register == 1)
	{
		*Dr1 = 0;
		Dr7->LEN1 = 0;
		Dr7->RWE1 = 0;
		Dr7->L1 = 0;
	}
	else if (pBreakpointInfo->Register == 2)
	{
		*Dr2 = 0;
		Dr7->LEN2 = 0;
		Dr7->RWE2 = 0;
		Dr7->L2 = 0;
	}
	else if (pBreakpointInfo->Register == 3)
	{
		*Dr3 = 0;
		Dr7->LEN3 = 0;
		Dr7->RWE3 = 0;
		Dr7->L3 = 0;
	}

#ifndef _WIN64
	if (pBreakpointInfo->Type == BP_READWRITE && address_is_in_stack((DWORD_PTR)pBreakpointInfo->Address))
		WoW64UnpatchBreakpoint(pBreakpointInfo->Register);
#endif

	pBreakpointInfo->Address = 0;
	pBreakpointInfo->Size = 0;
	pBreakpointInfo->Type = 0;
	pBreakpointInfo->HitCount = 0;
	//pBreakpointInfo->Callback = 0;

#ifdef _WIN64
	if (NoSetThreadContext)
		return TRUE;

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DebugOutput("ContextClearBreakpointEx: No thread handle found in breakpoints found for current thread %d.\n", GetCurrentThreadId());
		return FALSE;
	}

	Context->ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!SetThreadContext(pBreakpointInfo->ThreadHandle, Context))
	{
		ErrorOutput("ContextClearBreakpointEx: SetThreadContext failed");
		return FALSE;
	}
#ifdef DEBUG_COMMENTS
	else
		DebugOutput("ContextClearBreakpointEx: SetThreadContext success.\n");
#endif
#endif

	return TRUE;
}

BOOL ContextClearBreakpoint(PCONTEXT Context, int Register)
{
	BOOL NoSetThreadContext = FALSE;

	if ((OSVersion.dwMajorVersion == 6 && OSVersion.dwMinorVersion > 1) || OSVersion.dwMajorVersion > 6)
		NoSetThreadContext = TRUE;

	PTHREADBREAKPOINTS CurrentThreadBreakpoints = GetThreadBreakpoints(GetCurrentThreadId());

	if (CurrentThreadBreakpoints == NULL)
	{
		DebugOutput("ContextClearBreakpoint: Error - Failed to acquire thread breakpoints.\n");
		return FALSE;
	}

	for (unsigned int i = 0; i < NUMBER_OF_DEBUG_REGISTERS; i++)
	{
		if (CurrentThreadBreakpoints->BreakpointInfo[i].Register == Register)
			return ContextClearBreakpointEx(Context, &CurrentThreadBreakpoints->BreakpointInfo[i], NoSetThreadContext);
	}

	return FALSE;
}

//**************************************************************************************
BOOL ContextClearBreakpointsInRangeEx(PCONTEXT Context, PVOID BaseAddress, SIZE_T Size, BOOL NoSetThreadContext)
//**************************************************************************************
{
	unsigned int Register;

	PTHREADBREAKPOINTS CurrentThreadBreakpoints = MainThreadBreakpointList;

	if (BaseAddress == NULL)
	{
		DebugOutput("ContextClearBreakpointsInRange: No address supplied (may have already been cleared).\n");
		return FALSE;
	}

	if (Size == 0)
	{
		DebugOutput("ContextClearBreakpointsInRange: Size supplied is zero.\n");
		return FALSE;
	}

	DebugOutput("ContextClearBreakpointsInRange: Clearing breakpoints in range 0x%x - 0x%x.\n", BaseAddress, (BYTE*)BaseAddress + Size);

	while (CurrentThreadBreakpoints)
	{
		for (Register = 0; Register < NUMBER_OF_DEBUG_REGISTERS; Register++)
		{
			if ((DWORD_PTR)CurrentThreadBreakpoints->BreakpointInfo[Register].Address >= (DWORD_PTR)BaseAddress
				&& (DWORD_PTR)CurrentThreadBreakpoints->BreakpointInfo[Register].Address < (DWORD_PTR)((BYTE*)BaseAddress + Size))
			{
				PDR7 Dr7 = (PDR7)&(Context->Dr7);

				DebugOutput("ContextClearBreakpointsInRange: Clearing breakpoint %d address 0x%p.\n", Register, CurrentThreadBreakpoints->BreakpointInfo[Register].Address);

				if (Register == 0)
				{
					Context->Dr0 = 0;
					Dr7->LEN0 = 0;
					Dr7->RWE0 = 0;
					Dr7->L0 = 0;
				}
				else if (Register == 1)
				{
					Context->Dr1 = 0;
					Dr7->LEN1 = 0;
					Dr7->RWE1 = 0;
					Dr7->L1 = 0;
				}
				else if (Register == 2)
				{
					Context->Dr2 = 0;
					Dr7->LEN2 = 0;
					Dr7->RWE2 = 0;
					Dr7->L2 = 0;
				}
				else if (Register == 3)
				{
					Context->Dr3 = 0;
					Dr7->LEN3 = 0;
					Dr7->RWE3 = 0;
					Dr7->L3 = 0;
				}

				CurrentThreadBreakpoints->BreakpointInfo[Register].Register = 0;
				CurrentThreadBreakpoints->BreakpointInfo[Register].Size = 0;
				CurrentThreadBreakpoints->BreakpointInfo[Register].Address = NULL;
				CurrentThreadBreakpoints->BreakpointInfo[Register].Type = 0;
				CurrentThreadBreakpoints->BreakpointInfo[Register].HitCount = 0;
				CurrentThreadBreakpoints->BreakpointInfo[Register].Callback = NULL;
			}
		}

		CurrentThreadBreakpoints = CurrentThreadBreakpoints->NextThreadBreakpoints;
	}

#ifdef _WIN64
	if (NoSetThreadContext)
		return TRUE;

	if (CurrentThreadBreakpoints->ThreadHandle == NULL)
	{
		DebugOutput("ContextClearBreakpointsInRange: No thread handle found in breakpoints found for current thread %d.\n", GetCurrentThreadId());
		return FALSE;
	}

	Context->ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!SetThreadContext(CurrentThreadBreakpoints->ThreadHandle, Context))
	{
		ErrorOutput("ContextClearBreakpointsInRange: SetThreadContext failed");
		return FALSE;
	}
#ifdef DEBUG_COMMENTS
	else
		DebugOutput("ContextClearBreakpointsInRange: SetThreadContext success.\n");
#endif
#endif

	return TRUE;
}

BOOL ContextClearBreakpointsInRange(PCONTEXT Context, PVOID BaseAddress, SIZE_T Size)
{
	BOOL NoSetThreadContext = FALSE;

	if ((OSVersion.dwMajorVersion == 6 && OSVersion.dwMinorVersion > 1) || OSVersion.dwMajorVersion > 6)
		NoSetThreadContext = TRUE;

	return ContextClearBreakpointsInRangeEx(Context, BaseAddress, Size, NoSetThreadContext);
}

//**************************************************************************************
BOOL ClearBreakpointsInRange(PVOID BaseAddress, SIZE_T Size)
//**************************************************************************************
{
	unsigned int Register;

	if (BaseAddress == NULL)
	{
		DebugOutput("ClearBreakpointsInRange: No address supplied (may have already been cleared).\n");
		return FALSE;
	}

	if (Size == 0)
	{
		DebugOutput("ClearBreakpointsInRange: Size supplied is zero.\n");
		return FALSE;
	}

	DebugOutput("ClearBreakpointsInRange: Clearing breakpoints in range 0x%x - 0x%x.\n", BaseAddress, (BYTE*)BaseAddress + Size);

	PTHREADBREAKPOINTS CurrentThreadBreakpoints = MainThreadBreakpointList;

	while (CurrentThreadBreakpoints)
	{
		for (Register = 0; Register < NUMBER_OF_DEBUG_REGISTERS; Register++)
		{
			if ((DWORD_PTR)CurrentThreadBreakpoints->BreakpointInfo[Register].Address >= (DWORD_PTR)BaseAddress
				&& (DWORD_PTR)CurrentThreadBreakpoints->BreakpointInfo[Register].Address < (DWORD_PTR)((BYTE*)BaseAddress + Size))
			{
				DebugOutput("ClearBreakpointsInRange: Clearing breakpoint %d address 0x%p.\n", Register, CurrentThreadBreakpoints->BreakpointInfo[Register].Address);
				ClearBreakpoint(Register);
			}
		}

		CurrentThreadBreakpoints = CurrentThreadBreakpoints->NextThreadBreakpoints;
	}

	return TRUE;
}

//**************************************************************************************
BOOL ClearBreakpointsInRegion(PVOID BaseAddress)
//**************************************************************************************
{
	unsigned int Register;

	PTHREADBREAKPOINTS CurrentThreadBreakpoints = MainThreadBreakpointList;

	if (BaseAddress == NULL)
	{
		DebugOutput("ClearBreakpointsInRegion: No address supplied (may have already been cleared).\n");
		return FALSE;
	}

	SIZE_T Size = GetAllocationSize(BaseAddress);

	DebugOutput("ClearBreakpointsInRegion: Clearing breakpoints in range 0x%x - 0x%x.\n", BaseAddress, (BYTE*)BaseAddress + Size);

	while (CurrentThreadBreakpoints)
	{
		for (Register = 0; Register < NUMBER_OF_DEBUG_REGISTERS; Register++)
		{
			if ((DWORD_PTR)CurrentThreadBreakpoints->BreakpointInfo[Register].Address >= (DWORD_PTR)BaseAddress
				&& (DWORD_PTR)CurrentThreadBreakpoints->BreakpointInfo[Register].Address < (DWORD_PTR)((BYTE*)BaseAddress + Size))
			{
				DebugOutput("ClearBreakpointsInRegion: Clearing breakpoint %d address 0x%p (thread %d).\n", Register, CurrentThreadBreakpoints->BreakpointInfo[Register].Address, CurrentThreadBreakpoints->ThreadId);
				ClearThreadBreakpoint(CurrentThreadBreakpoints->ThreadId, Register);
			}
		}

		CurrentThreadBreakpoints = CurrentThreadBreakpoints->NextThreadBreakpoints;
	}

	return TRUE;
}

//**************************************************************************************
BOOL SetResumeFlag(PCONTEXT Context)
//**************************************************************************************
{
	if (Context == NULL)
		return FALSE;

	Context->EFlags |= FL_RF;

	return TRUE;
}

//**************************************************************************************
BOOL SetZeroFlag(PCONTEXT Context)
//**************************************************************************************
{
	if (Context == NULL)
		return FALSE;

	Context->EFlags |= FL_ZF;

	return TRUE;
}

//**************************************************************************************
BOOL ClearZeroFlag(PCONTEXT Context)
//**************************************************************************************
{
	if (Context == NULL)
		return FALSE;

	Context->EFlags &= ~FL_ZF;

	return TRUE;
}

//**************************************************************************************
BOOL FlipZeroFlag(PCONTEXT Context)
//**************************************************************************************
{
	if (Context == NULL)
		return FALSE;

	Context->EFlags ^= FL_ZF;

	return TRUE;
}

//**************************************************************************************
BOOL SetSignFlag(PCONTEXT Context)
//**************************************************************************************
{
	if (Context == NULL)
		return FALSE;

	Context->EFlags |= FL_SF;

	return TRUE;
}

//**************************************************************************************
BOOL ClearSignFlag(PCONTEXT Context)
//**************************************************************************************
{
	if (Context == NULL)
		return FALSE;

	Context->EFlags &= ~FL_SF;

	return TRUE;
}

//**************************************************************************************
BOOL FlipSignFlag(PCONTEXT Context)
//**************************************************************************************
{
	if (Context == NULL)
		return FALSE;

	Context->EFlags ^= FL_SF;

	return TRUE;
}

//**************************************************************************************
BOOL SetCarryFlag(PCONTEXT Context)
//**************************************************************************************
{
	if (Context == NULL)
		return FALSE;

	Context->EFlags |= FL_CF;

	return TRUE;
}

//**************************************************************************************
BOOL ClearCarryFlag(PCONTEXT Context)
//**************************************************************************************
{
	if (Context == NULL)
		return FALSE;

	Context->EFlags &= ~FL_CF;

	return TRUE;
}

//**************************************************************************************
BOOL FlipCarryFlag(PCONTEXT Context)
//**************************************************************************************
{
	if (Context == NULL)
		return FALSE;

	Context->EFlags ^= FL_CF;

	return TRUE;
}

//**************************************************************************************
BOOL SetSingleStepMode(PCONTEXT Context, PVOID Handler)
//**************************************************************************************
{
	if (Context == NULL)
		return FALSE;

	// set the trap flag
	Context->EFlags |= FL_TF;

	if (g_config.branch_trace)
	{
		PDR7 Dr7 = (PDR7)&(Context->Dr7);
		Dr7->LE = 1;	// LBR
		Dr7->GE = 1;	// BTF
	}

#ifdef DEBUG_COMMENTS
	//DebugOutput("SetSingleStepMode: Setting single-step mode with handler at 0x%p\n", Handler);
#endif
	SingleStepHandler = (SINGLE_STEP_HANDLER)Handler;

	return TRUE;
}

//**************************************************************************************
BOOL ClearSingleStepMode(PCONTEXT Context)
//**************************************************************************************
{
	if (Context == NULL)
		return FALSE;

	// Clear the trap flag & index
	Context->EFlags &= ~FL_TF;

	//SingleStepHandler = NULL;

	return TRUE;
}

//**************************************************************************************
BOOL ResumeFromBreakpoint(PCONTEXT Context)
//**************************************************************************************
{
	if (Context == NULL)
		return FALSE;

	// set the resume flag
	Context->EFlags |= FL_RF;

	return TRUE;
}

//**************************************************************************************
BOOL ClearDebugRegister
//**************************************************************************************
(
	HANDLE	hThread,
	int		Register,
	int		Size,
	LPVOID	Address,
	DWORD	Type
){
	CONTEXT	Context;
	BOOL DoCloseHandle = FALSE;
	PDWORD_PTR Dr0 = &Context.Dr0;
	PDWORD_PTR Dr1 = &Context.Dr1;
	PDWORD_PTR Dr2 = &Context.Dr2;
	PDWORD_PTR Dr3 = &Context.Dr3;
	PDR7 Dr7 = (PDR7)&(Context.Dr7);

	if ((unsigned int)Type > 3)
	{
		DebugOutput("ClearDebugRegister: %d is an invalid breakpoint type, must be 0-3.\n", Type);
		return FALSE;
	}

	if (Register < 0 || Register > 3)
	{
		DebugOutput("ClearDebugRegister: %d is an invalid register, must be 0-3.\n", Register);
		return FALSE;
	}

	if (Size < 0 || Size > 8)
	{
		DebugOutput("ClearDebugRegister: %d is an invalid Size, must be 1, 2, 4 or 8.\n", Size);
		return FALSE;
	}

	Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(hThread, &Context))
	{
		ErrorOutput("ClearDebugRegister: Initial GetThreadContext failed");
		return FALSE;
	}

	if (Register == 0)
	{
		*Dr0 = 0;
		Dr7->LEN0 = 0;
		Dr7->RWE0 = 0;
		Dr7->L0 = 0;
	}
	else if (Register == 1)
	{
		*Dr1 = 0;
		Dr7->LEN1 = 0;
		Dr7->RWE1 = 0;
		Dr7->L1 = 0;
	}
	else if (Register == 2)
	{
		*Dr2 = 0;
		Dr7->LEN2 = 0;
		Dr7->RWE2 = 0;
		Dr7->L2 = 0;
	}
	else if (Register == 3)
	{
		*Dr3 = 0;
		Dr7->LEN3 = 0;
		Dr7->RWE3 = 0;
		Dr7->L3 = 0;
	}

#ifndef _WIN64
	if (Type == BP_READWRITE && address_is_in_stack((DWORD_PTR)Address))
		WoW64UnpatchBreakpoint(Register);
#endif

	Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!SetThreadContext(hThread, &Context))
	{
		ErrorOutput("ClearDebugRegister: SetThreadContext failed");
		return FALSE;
	}

	if (DoCloseHandle == TRUE)
		CloseHandle(hThread);

	return TRUE;
}

//**************************************************************************************
int ContextCheckDebugRegister(CONTEXT Context, int Register)
//**************************************************************************************
{
	PDR7 Dr7;

	if (Register < 0 || Register > 3)
	{
		DebugOutput("ContextCheckDebugRegister: %d is an invalid register, must be 0-3.\n", Register);
		return FALSE;
	}

	Dr7 = (PDR7)&(Context.Dr7);

	if (Register == 0)
		return Dr7->L0;
	else if (Register == 1)
		return Dr7->L1;
	else if (Register == 2)
		return Dr7->L2;
	else if (Register == 3)
		return Dr7->L3;

	return -1;
}

//**************************************************************************************
int CheckDebugRegister(HANDLE hThread, int Register)
//**************************************************************************************
{
	CONTEXT	Context;
	PDR7 Dr7;

	if (Register < 0 || Register > 3)
	{
		DebugOutput("CheckDebugRegister: %d is an invalid register, must be 0-3.\n", Register);
		return FALSE;
	}

	Dr7 = (PDR7)&(Context.Dr7);

	Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(hThread, &Context))
	{
		ErrorOutput("CheckDebugRegister: GetThreadContext failed.\n");
		return FALSE;
	}

	if (Register == 0)
		return Dr7->L0;
	else if (Register == 1)
		return Dr7->L1;
	else if (Register == 2)
		return Dr7->L2;
	else if (Register == 3)
		return Dr7->L3;

	return -1;
}

//**************************************************************************************
BOOL ContextSetThreadBreakpointEx
//**************************************************************************************
(
	PCONTEXT		Context,
	int				Register,
	int				Size,
	LPVOID			Address,
	DWORD			Type,
	unsigned int	HitCount,
	PVOID			Callback,
	BOOL			NoSetThreadContext
)
{
	PTHREADBREAKPOINTS CurrentThreadBreakpoints;

	if (Register > 3 || Register < 0)
	{
		DebugOutput("ContextSetThreadBreakpointEx: Error - register value %d, can only have value 0-3.\n", Register);
		return FALSE;
	}

	if (!ContextSetDebugRegisterEx(Context, Register, Size, Address, Type, NoSetThreadContext))
	{
		DebugOutput("ContextSetThreadBreakpointEx: Call to ContextSetDebugRegister failed.\n");
	}
	else
	{
		CurrentThreadBreakpoints = GetThreadBreakpoints(GetCurrentThreadId());

		if (CurrentThreadBreakpoints == NULL)
		{
			DebugOutput("ContextSetThreadBreakpointEx: Error - Failed to acquire thread breakpoints.\n");
			return FALSE;
		}

		CurrentThreadBreakpoints->BreakpointInfo[Register].ThreadHandle	= CurrentThreadBreakpoints->ThreadHandle;
		CurrentThreadBreakpoints->BreakpointInfo[Register].Register		= Register;
		CurrentThreadBreakpoints->BreakpointInfo[Register].Size			= Size;
		CurrentThreadBreakpoints->BreakpointInfo[Register].Address		= Address;
		CurrentThreadBreakpoints->BreakpointInfo[Register].HitCount		= HitCount;
		CurrentThreadBreakpoints->BreakpointInfo[Register].Type			= Type;
		CurrentThreadBreakpoints->BreakpointInfo[Register].Callback		= Callback;
	}

	return TRUE;
}

//**************************************************************************************
BOOL ContextSetThreadBreakpoint
//**************************************************************************************
(
	PCONTEXT		Context,
	int				Register,
	int				Size,
	LPVOID			Address,
	DWORD			Type,
	unsigned int	HitCount,
	PVOID			Callback
)
{
	BOOL NoSetThreadContext = FALSE;

	if ((OSVersion.dwMajorVersion == 6 && OSVersion.dwMinorVersion > 1) || OSVersion.dwMajorVersion > 6)
		NoSetThreadContext = TRUE;

	return ContextSetThreadBreakpointEx(Context, Register, Size, Address, Type, HitCount, Callback, NoSetThreadContext);
}

//**************************************************************************************
BOOL ContextSetNextAvailableBreakpoint
//**************************************************************************************
(
	PCONTEXT		Context,
	int*			Register,
	int				Size,
	LPVOID			Address,
	DWORD			Type,
	unsigned int	HitCount,
	PVOID			Callback
)
{
	PTHREADBREAKPOINTS CurrentThreadBreakpoints;

	if (!Address)
	{
		DebugOutput("ContextSetNextAvailableBreakpoint: Error - breakpoint address is zero!\n");
		return FALSE;
	}

	CurrentThreadBreakpoints = GetThreadBreakpoints(GetCurrentThreadId());

	if (CurrentThreadBreakpoints == NULL)
	{
		DebugOutput("ContextSetNextAvailableBreakpoint: Error - Failed to acquire thread breakpoints.\n");
		return FALSE;
	}

	// Check whether an identical breakpoint already exists
	for (unsigned int i = 0; i < NUMBER_OF_DEBUG_REGISTERS; i++)
	{
		if
		(
			CurrentThreadBreakpoints->BreakpointInfo[i].Size == Size &&
			CurrentThreadBreakpoints->BreakpointInfo[i].Address == Address &&
			CurrentThreadBreakpoints->BreakpointInfo[i].Type == Type &&
			CurrentThreadBreakpoints->BreakpointInfo[i].HitCount == HitCount
		)
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("ContextSetNextAvailableBreakpoint: An identical breakpoint (%d) at 0x%p already exists for thread %d (process %d), skipping.\n", i, Address, CurrentThreadBreakpoints->ThreadId, GetCurrentProcessId());
#endif
			return TRUE;
		}
	}

	if (Register)
	{
		if (!ContextGetNextAvailableBreakpoint(Context, Register))
		{
			DebugOutput("ContextSetNextAvailableBreakpoint: No available breakpoints!\n");
			OutputThreadBreakpoints(GetCurrentThreadId());
			return FALSE;
		}
#ifdef DEBUG_COMMENTS
		DebugOutput("ContextSetNextAvailableBreakpoint: Calling ContextSetThreadBreakpoint with register %d", *Register);
#endif
		return ContextSetThreadBreakpoint(Context, *Register, Size, Address, Type, HitCount, Callback);
	}
	else
	{
		unsigned int TempRegister;

		if (!ContextGetNextAvailableBreakpoint(Context, &TempRegister))
		{
			DebugOutput("ContextSetNextAvailableBreakpoint: No available breakpoints!\n");
			OutputThreadBreakpoints(GetCurrentThreadId());
			return FALSE;
		}

		return ContextSetThreadBreakpoint(Context, TempRegister, Size, Address, Type, HitCount, Callback);
	}
}

//**************************************************************************************
BOOL ContextUpdateCurrentBreakpoint
//**************************************************************************************
(
	PCONTEXT		Context,
	int				Size,
	LPVOID			Address,
	DWORD			Type,
	unsigned int	HitCount,
	PVOID			Callback
)
{
	PTHREADBREAKPOINTS CurrentThreadBreakpoints;
	PBREAKPOINTINFO pBreakpointInfo;
	unsigned int bp;

	CurrentThreadBreakpoints = GetThreadBreakpoints(GetCurrentThreadId());

	if (CurrentThreadBreakpoints == NULL)
	{
		DebugOutput("ContextUpdateCurrentBreakpoint: Error - Failed to acquire thread breakpoints.\n");
		return FALSE;
	}

	for (bp = 0; bp < NUMBER_OF_DEBUG_REGISTERS; bp++)
	{
		pBreakpointInfo = &(CurrentThreadBreakpoints->BreakpointInfo[bp]);

		if (pBreakpointInfo == NULL)
		{
			DebugOutput("ContextUpdateCurrentBreakpoint: Can't get BreakpointInfo.\n");
			return FALSE;
		}

		if (pBreakpointInfo->Register == bp)
		{
			if (bp == 0 && ((DWORD_PTR)pBreakpointInfo->Address == Context->Dr0) && ((DWORD)pBreakpointInfo->Type == ((PDR7)&(Context->Dr7))->RWE0))
			{
				return ContextSetThreadBreakpoint(Context, 0, Size, Address, Type, HitCount, Callback);
			}

			if (bp == 1 && ((DWORD_PTR)pBreakpointInfo->Address == Context->Dr1) && ((DWORD)pBreakpointInfo->Type == ((PDR7)&(Context->Dr7))->RWE1))
			{
				return ContextSetThreadBreakpoint(Context, 1, Size, Address, Type, HitCount, Callback);
			}

			if (bp == 2 && ((DWORD_PTR)pBreakpointInfo->Address == Context->Dr2) && ((DWORD)pBreakpointInfo->Type == ((PDR7)&(Context->Dr7))->RWE2))
			{
				return ContextSetThreadBreakpoint(Context, 2, Size, Address, Type, HitCount, Callback);
			}

			if (bp == 3 && ((DWORD_PTR)pBreakpointInfo->Address == Context->Dr3) && ((DWORD)pBreakpointInfo->Type == ((PDR7)&(Context->Dr7))->RWE3))
			{
				return ContextSetThreadBreakpoint(Context, 3, Size, Address, Type, HitCount, Callback);
			}
		}
	}

	return FALSE;
}

//**************************************************************************************
BOOL ContextClearCurrentBreakpoint
//**************************************************************************************
(
	PCONTEXT		Context
)
{
	PTHREADBREAKPOINTS CurrentThreadBreakpoints;
	PBREAKPOINTINFO pBreakpointInfo;
	unsigned int bp;

	CurrentThreadBreakpoints = GetThreadBreakpoints(GetCurrentThreadId());

	if (CurrentThreadBreakpoints == NULL)
	{
		DebugOutput("ContextClearCurrentBreakpoint: Error - Failed to acquire thread breakpoints.\n");
		return FALSE;
	}

	for (bp = 0; bp < NUMBER_OF_DEBUG_REGISTERS; bp++)
	{
		if (Context->Dr6 & (DWORD_PTR)(1 << bp))
		{
			pBreakpointInfo = &(CurrentThreadBreakpoints->BreakpointInfo[bp]);

			if (pBreakpointInfo == NULL)
			{
				DebugOutput("ContextClearCurrentBreakpoint: Can't get BreakpointInfo.\n");
				return FALSE;
			}

			if (pBreakpointInfo->Register == bp)
				return ContextClearBreakpoint(Context, bp);
		}
	}

	return FALSE;
}

//**************************************************************************************
BOOL ContextSetThreadBreakpointsEx(PCONTEXT ThreadContext, PTHREADBREAKPOINTS ThreadBreakpoints, BOOL NoSetThreadContext)
//**************************************************************************************
{
	BOOL RetVal;
	if (!ThreadContext)
	{
		DebugOutput("ContextSetThreadBreakpointsEx: Error - no thread context.\n");
		return FALSE;
	}

	for (unsigned int Register = 0; Register < NUMBER_OF_DEBUG_REGISTERS; Register++)
	{
		RetVal = ContextSetThreadBreakpointEx
		(
			ThreadContext,
			ThreadBreakpoints->BreakpointInfo[Register].Register,
			ThreadBreakpoints->BreakpointInfo[Register].Size,
			ThreadBreakpoints->BreakpointInfo[Register].Address,
			ThreadBreakpoints->BreakpointInfo[Register].Type,
			ThreadBreakpoints->BreakpointInfo[Register].HitCount,
			ThreadBreakpoints->BreakpointInfo[Register].Callback,
			NoSetThreadContext
		);
	}

	return RetVal;
}

//**************************************************************************************
BOOL ContextSetThreadBreakpoints(PCONTEXT ThreadContext, PTHREADBREAKPOINTS ThreadBreakpoints)
//**************************************************************************************
{
	return ContextSetThreadBreakpointsEx(ThreadContext, ThreadBreakpoints, FALSE);
}

//**************************************************************************************
BOOL SetSoftwareBreakpoint(LPVOID Address)
//**************************************************************************************
{
	DWORD OldProtect;

	if (!Address || !IsAddressAccessible(Address))
		return FALSE;

	if (lookup_get(&SoftBPs, (ULONG_PTR)Address, 0))
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("SetSoftwareBreakpoint: Address 0x%p already in software breakpoint list", Address);
#endif
		return FALSE;
	}

	BYTE InsByte = *(PBYTE)Address;
	if (InsByte == 0xCC)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("SetSoftwareBreakpoint: Address 0x%p already contains 0xCC byte", Address);
#endif
		return FALSE;
	}

	PBYTE pInsByte = lookup_add(&SoftBPs, (ULONG_PTR)Address, 0);
	if (!pInsByte)
	{
		DebugOutput("SetSoftwareBreakpoint: Unable to store instruction byte at 0x%p", Address);
		return FALSE;
	}

	*pInsByte = InsByte;
#ifdef DEBUG_COMMENTS
	DebugOutput("SetSoftwareBreakpoint: Instruction byte at 0x%p: 0x%x", Address, *pInsByte);
#endif

	if (!VirtualProtect(Address, 1, PAGE_EXECUTE_READWRITE, &OldProtect))
	{
		DebugOutput("SetSoftwareBreakpoint: Unable to change memory protection at 0x%p", Address);
		return FALSE;
	}

#ifdef DEBUG_COMMENTS
	DebugOutput("SetSoftwareBreakpoint: Changed memory protection at 0x%p", Address);
#endif

	*(PBYTE)Address = 0xCC;

#ifdef DEBUG_COMMENTS
	DebugOutput("SetSoftwareBreakpoint: New instruction byte at 0x%p: 0x%x", Address, *(PBYTE)Address);
#endif
	VirtualProtect(Address, 1, OldProtect, &OldProtect);

	return TRUE;
}

//**************************************************************************************
BOOL SetSyscallBreakpoint(LPVOID Address)
//**************************************************************************************
{
	DWORD OldProtect;

	if (!Address || !IsAddressAccessible(Address))
		return FALSE;

	if (GetAllocationBase(Address) == GetModuleHandle("ntdll"))
		return FALSE;

	if (lookup_get(&SyscallBPs, (ULONG_PTR)Address, 0))
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("SetSoftwareBreakpoint: Address 0x%p already in software breakpoint list", Address);
#endif
		return FALSE;
	}

	lookup_add(&SyscallBPs, (ULONG_PTR)Address, 0);

	if (!VirtualProtect(Address, 1, PAGE_EXECUTE_READWRITE, &OldProtect))
	{
		DebugOutput("SetSoftwareBreakpoint: Unable to change memory protection at 0x%p", Address);
		return FALSE;
	}

#ifdef DEBUG_COMMENTS
	DebugOutput("SetSoftwareBreakpoint: Changed memory protection at 0x%p", Address);
#endif

	*(PBYTE)Address = 0xCC;

#ifdef DEBUG_COMMENTS
	DebugOutput("SetSoftwareBreakpoint: New instruction byte at 0x%p: 0x%x", Address, *(PBYTE)Address);
#endif
	VirtualProtect(Address, 1, OldProtect, &OldProtect);

	return TRUE;
}

//**************************************************************************************
BOOL SetThreadBreakpoint
//**************************************************************************************
(
	DWORD			ThreadId,
	int				Register,
	int				Size,
	LPVOID			Address,
	DWORD			Type,
	unsigned int	HitCount,
	PVOID			Callback
)
{
	BOOL RetVal;
	PTHREADBREAKPOINTS CurrentThreadBreakpoints;
	PBREAKPOINTINFO pBreakpointInfo = NULL;

	if (Register > 3 || Register < 0)
	{
		DebugOutput("SetThreadBreakpoint: Error - register value %d, can only have value 0-3.\n", Register);
		return FALSE;
	}

	CurrentThreadBreakpoints = GetThreadBreakpoints(ThreadId);

	if (CurrentThreadBreakpoints == NULL)
	{
		DebugOutput("SetThreadBreakpoint: Creating new thread breakpoints for thread %d.\n", ThreadId);
		CurrentThreadBreakpoints = CreateThreadBreakpoints(ThreadId, NULL);
	}

	if (CurrentThreadBreakpoints == NULL)
	{
		DebugOutput("SetThreadBreakpoint: Cannot create new thread breakpoints.\n");
		return FALSE;
	}

	__try
	{
		pBreakpointInfo = &CurrentThreadBreakpoints->BreakpointInfo[Register];
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		ErrorOutput("SetThreadBreakpoint: Exception getting pBreakpointInfo");
		return FALSE;
	}

	if (CurrentThreadBreakpoints->ThreadHandle == NULL)
	{
		DebugOutput("SetThreadBreakpoint: There is no thread handle in the thread breakpoint - Error.\n");
		return FALSE;
	}
#ifdef DEBUG_COMMENTS
	else
		DebugOutput("SetThreadBreakpoint: About to call SetDebugRegister with thread handle 0x%x, register %d, size 0x%x, address 0x%p type %d.\n", CurrentThreadBreakpoints->ThreadHandle, Register, Size, Address, Type);
#endif

	pBreakpointInfo->ThreadHandle	= CurrentThreadBreakpoints->ThreadHandle;
	pBreakpointInfo->Register		= Register;
	pBreakpointInfo->Size			= Size;
	pBreakpointInfo->Address		= Address;
	pBreakpointInfo->Type			= Type;
	pBreakpointInfo->HitCount		= HitCount;
	pBreakpointInfo->Callback		= Callback;

	__try
	{
		RetVal = SetDebugRegister(pBreakpointInfo->ThreadHandle, Register, Size, Address, Type);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		ErrorOutput("SetThreadBreakpoint: Exception calling SetDebugRegister");
		return FALSE;
	}

#ifdef DEBUG_COMMENTS
	if (RetVal)
		DebugOutput("SetThreadBreakpoint: bp set at 0x%p with register %d, hit count %d, thread %d\n", Address, Register, HitCount, ThreadId);
	else
		DebugOutput("SetThreadBreakpoint: Failed to set bp at 0x%p with register %d, hit count %d, thread %d\n", Address, Register, HitCount, ThreadId);
#endif

	return RetVal;
}

//**************************************************************************************
BOOL SetBreakpoint
//**************************************************************************************
(
	int				Register,
	int				Size,
	LPVOID			Address,
	DWORD			Type,
	unsigned int	HitCount,
	PVOID			Callback
)
{
	PTHREADBREAKPOINTS CurrentThreadBreakpoints, ThreadBreakpoints;

	if (MainThreadBreakpointList == NULL)
	{
		DebugOutput("SetBreakpoint: MainThreadBreakpointList NULL.\n");
		return FALSE;
	}

	DWORD CurrentThreadId = GetCurrentThreadId();
	CurrentThreadBreakpoints = GetThreadBreakpoints(CurrentThreadId);

	if (CurrentThreadBreakpoints == NULL)
	{
		DebugOutput("SetBreakpoint: Creating new thread breakpoints for thread %d.\n", CurrentThreadId);
		CurrentThreadBreakpoints = CreateThreadBreakpoints(CurrentThreadId, NULL);
	}

	if (CurrentThreadBreakpoints == NULL)
	{
		DebugOutput("SetBreakpoint: Cannot create new thread breakpoints.\n");
		return FALSE;
	}

	ThreadBreakpoints = MainThreadBreakpointList;

	while (ThreadBreakpoints)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("SetBreakpoint: About to call SetThreadBreakpoint for thread %d.\n", ThreadBreakpoints->ThreadId);
#endif

		SetThreadBreakpoint(ThreadBreakpoints->ThreadId, Register, Size, Address, Type, HitCount, Callback);

		ThreadBreakpoints = ThreadBreakpoints->NextThreadBreakpoints;
	}

	return TRUE;
}

//**************************************************************************************
BOOL ContextSetBreakpoint
//**************************************************************************************
(
	PCONTEXT		Context,
	int				Register,
	int				Size,
	LPVOID			Address,
	DWORD			Type,
	unsigned int	HitCount,
	PVOID			Callback
)
{
	PTHREADBREAKPOINTS CurrentThreadBreakpoints;
	PBREAKPOINTINFO pBreakpointInfo;

	DWORD CurrentThreadId = GetCurrentThreadId();
	CurrentThreadBreakpoints = GetThreadBreakpoints(CurrentThreadId);

	if (CurrentThreadBreakpoints == NULL)
	{
		DebugOutput("ContextSetBreakpoint: Error - Failed to acquire current thread breakpoints.\n");
		return FALSE;
	}

	pBreakpointInfo = &(CurrentThreadBreakpoints->BreakpointInfo[Register]);

	if (pBreakpointInfo == NULL)
	{
		DebugOutput("ContextSetBreakpoint: Can't get BreakpointInfo.\n");
		return FALSE;
	}

	ContextSetThreadBreakpoint(Context, Register, Size, Address, Type, HitCount, Callback);

	PTHREADBREAKPOINTS ThreadBreakpoints = MainThreadBreakpointList;

	if (ThreadBreakpoints == NULL)
	{
		DebugOutput("ContextSetBreakpoint: MainThreadBreakpointList NULL.\n");
		return FALSE;
	}

	while (ThreadBreakpoints)
	{
		if (ThreadBreakpoints->ThreadId && ThreadBreakpoints->ThreadId != CurrentThreadId)
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("ContextSetBreakpoint: About to call SetThreadBreakpoint for thread %d.\n", ThreadBreakpoints->ThreadId);
#endif
			SetThreadBreakpoint(ThreadBreakpoints->ThreadId, Register, Size, Address, Type, HitCount, Callback);
			ThreadBreakpoints = ThreadBreakpoints->NextThreadBreakpoints;
		}
	}

	return TRUE;
}

//**************************************************************************************
BOOL SetThreadBreakpoints(PTHREADBREAKPOINTS ThreadBreakpoints)
//**************************************************************************************
{
	if (!ThreadBreakpoints->ThreadId)
	{
		ErrorOutput("SetThreadBreakpoints: Error - Thread ID missing from ThreadBreakpoints.\n");
		return FALSE;
	}

	for (unsigned int Register = 0; Register < NUMBER_OF_DEBUG_REGISTERS; Register++)
	{
		if (!SetThreadBreakpoint
		(
			ThreadBreakpoints->ThreadId,
			ThreadBreakpoints->BreakpointInfo[Register].Register,
			ThreadBreakpoints->BreakpointInfo[Register].Size,
			ThreadBreakpoints->BreakpointInfo[Register].Address,
			ThreadBreakpoints->BreakpointInfo[Register].Type,
			ThreadBreakpoints->BreakpointInfo[Register].HitCount,
			ThreadBreakpoints->BreakpointInfo[Register].Callback
		))
			return FALSE;
	}

	return TRUE;
}

//**************************************************************************************
BOOL ClearThreadBreakpoint(DWORD ThreadId, int Register)
//**************************************************************************************
{
	PBREAKPOINTINFO pBreakpointInfo;
	PTHREADBREAKPOINTS CurrentThreadBreakpoints;

	if (Register > 3 || Register < 0)
	{
		DebugOutput("ClearThreadBreakpoint: Error - register value %d, can only have value 0-3.\n", Register);
		return FALSE;
	}

	CurrentThreadBreakpoints = GetThreadBreakpoints(ThreadId);

	if (CurrentThreadBreakpoints == NULL)
	{
		DebugOutput("ClearThreadBreakpoint: No thread breakpoints for thread %d\n", ThreadId);
		return FALSE;
	}

	pBreakpointInfo = &CurrentThreadBreakpoints->BreakpointInfo[Register];

	if (CurrentThreadBreakpoints->ThreadHandle == NULL)
	{
		DebugOutput("ClearThreadBreakpoint: There is no thread handle in the thread breakpoint - Error.\n");
		return FALSE;
	}

	if (!ClearDebugRegister(pBreakpointInfo->ThreadHandle, pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address, pBreakpointInfo->Type))
	{
		DebugOutput("ClearThreadBreakpoint: Call to ClearDebugRegister failed.\n");
		return FALSE;
	}

	pBreakpointInfo->Size		= 0;
	pBreakpointInfo->Address	= 0;
	pBreakpointInfo->Type		= 0;
	pBreakpointInfo->HitCount	= 0;
	pBreakpointInfo->Callback	= NULL;

	return TRUE;
}

//**************************************************************************************
BOOL ClearBreakpoint(int Register)
//**************************************************************************************
{
	if (MainThreadBreakpointList == NULL)
	{
		DebugOutput("ClearBreakpoint: MainThreadBreakpointList NULL.\n");
		return FALSE;
	}

	PTHREADBREAKPOINTS ThreadBreakpoints = MainThreadBreakpointList;

	while (ThreadBreakpoints)
	{
		if (ThreadBreakpoints->ThreadHandle)
			ThreadBreakpoints->BreakpointInfo[Register].ThreadHandle = ThreadBreakpoints->ThreadHandle;
		ThreadBreakpoints->BreakpointInfo[Register].Size		= 0;
		ThreadBreakpoints->BreakpointInfo[Register].Address		= NULL;
		ThreadBreakpoints->BreakpointInfo[Register].Type		= 0;
		ThreadBreakpoints->BreakpointInfo[Register].HitCount	= 0;
		ThreadBreakpoints->BreakpointInfo[Register].Callback	= NULL;

#ifdef DEBUG_COMMENTS
		DebugOutput("ClearBreakpoint: About to call ClearThreadBreakpoint for thread %d.\n", ThreadBreakpoints->ThreadId);
#endif

		ClearThreadBreakpoint(ThreadBreakpoints->ThreadId, Register);

		ThreadBreakpoints = ThreadBreakpoints->NextThreadBreakpoints;
	}

	return TRUE;
}

//**************************************************************************************
BOOL SetNextAvailableBreakpoint
//**************************************************************************************
(
	DWORD			ThreadId,
	int*			Register,
	int				Size,
	LPVOID			Address,
	DWORD			Type,
	unsigned int	HitCount,
	PVOID			Callback
)
{
	PTHREADBREAKPOINTS CurrentThreadBreakpoints = GetThreadBreakpoints(ThreadId);

	if (CurrentThreadBreakpoints == NULL)
	{
		DebugOutput("SetNextAvailableBreakpoint: Creating new thread breakpoints for thread %d.\n", ThreadId);
		CurrentThreadBreakpoints = CreateThreadBreakpoints(ThreadId, NULL);
	}

	if (CurrentThreadBreakpoints == NULL)
	{
		DebugOutput("SetNextAvailableBreakpoint: Cannot create new thread breakpoints.\n");
		return FALSE;
	}

	if (!GetNextAvailableBreakpoint(ThreadId, Register))
	{
		DebugOutput("SetNextAvailableBreakpoint: GetNextAvailableBreakpoint failed for thread %d (breakpoints possibly full).\n", ThreadId);
		return FALSE;
	}

	return SetThreadBreakpoint(ThreadId, *Register, Size, Address, Type, HitCount, Callback);
}

//**************************************************************************************
BOOL InitialiseDebugger(void)
//**************************************************************************************
{
	HANDLE MainThreadHandle;

	if (DebuggerInitialised)
		return TRUE;

	if (DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &MainThreadHandle, 0, FALSE, DUPLICATE_SAME_ACCESS) == 0)
	{
		DebugOutput("InitialiseDebugger: Failed to duplicate thread handle.\n");
		return FALSE;
	}

	MainThreadBreakpointList = CreateThreadBreakpoints(GetCurrentThreadId(), NULL);

	if (MainThreadBreakpointList == NULL)
	{
		DebugOutput("InitialiseDebugger: Failed to create thread breakpoints struct.\n");
		return FALSE;
	}

	if (MainThreadBreakpointList->ThreadHandle == NULL)
	{
		DebugOutput("InitialiseDebugger error: main thread handle not set.\n");
		return FALSE;
	}

	// Store address of KiUserExceptionDispatcher
	_KiUserExceptionDispatcher = GetProcAddress(GetModuleHandle("ntdll"), "KiUserExceptionDispatcher");

	if (_KiUserExceptionDispatcher == NULL)
	{
		DebugOutput("InitialiseDebugger error: could not resolve ntdll::KiUserExceptionDispatcher.\n");
		return FALSE;
	}
#ifdef DEBUG_COMMENTS
	else DebugOutput("InitialiseDebugger: ntdll::KiUserExceptionDispatcher = 0x%p\n", _KiUserExceptionDispatcher);
#endif

	// Initialise global variables
	ChildProcessId = 0;
	SingleStepHandler = NULL;

#ifndef _WIN64
	// Ensure wow64 patch is installed if needed
	if (!g_config.msi)
		WoW64fix();
#endif

	g_config.debugger = 1;
	DebuggerInitialised = TRUE;

	return DebuggerInitialised;
}

//**************************************************************************************
DWORD_PTR GetNestedStackPointer(void)
//**************************************************************************************
{
	CONTEXT context;

	RtlCaptureContext(&context);

#ifdef _WIN64
	return (DWORD_PTR)context.Rsp;
#else
	return (DWORD_PTR)context.Esp;
#endif
}

void DebuggerShutdown()
{
	StopTrace = TRUE;
	if (DebuggerLog) {
		if (TraceRunning)
			DebuggerOutput("\nDebuggerShutdown for process %d", GetCurrentProcessId());
		CloseHandle(DebuggerLog);
		DebuggerLog = NULL;
	}
	ClearAllBreakpoints();
	g_config.debugger = 0;
}

void NtContinueHandler(PCONTEXT ThreadContext)
{
	if (BreakpointsSet && !ThreadContext->Dr0 && !ThreadContext->Dr1 && !ThreadContext->Dr2 && !ThreadContext->Dr3)
	{
		DWORD ThreadId = GetCurrentThreadId();
		PTHREADBREAKPOINTS ThreadBreakpoints = GetThreadBreakpoints(ThreadId);
		if (ThreadBreakpoints)
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("NtContinue hook: restoring breakpoints for thread %d.\n", ThreadId);
#endif
			ContextSetThreadBreakpointsEx(ThreadContext, ThreadBreakpoints, TRUE);
#ifndef _WIN64
			if (BreakOnNtContinue) {
				BreakOnNtContinue = FALSE;
				for (unsigned int Register = 0; Register < NUMBER_OF_DEBUG_REGISTERS; Register++) {
					if (!ThreadBreakpoints->BreakpointInfo[Register].Address) {
						ContextSetThreadBreakpointEx(ThreadContext, Register, 0, (PBYTE)ThreadContext->Eip, BP_EXEC, 0, BreakOnNtContinueCallback, TRUE);
						break;
					}
				}
				BreakOnNtContinueCallback = NULL;
			}
			else if (BreakOnNtContinueCallback) {
				//BreakOnNtContinue = TRUE;
				PEXCEPTION_REGISTRATION_RECORD SEH = (PEXCEPTION_REGISTRATION_RECORD)__readfsdword(0);
				for (unsigned int Register = 0; Register < NUMBER_OF_DEBUG_REGISTERS; Register++) {
					if (!ThreadBreakpoints->BreakpointInfo[Register].Address) {
						ContextSetThreadBreakpointEx(ThreadContext, Register, 0, (PBYTE)SEH->Handler, BP_EXEC, 0, BreakOnNtContinueCallback, TRUE);
						StepOverRegister = Register;
						break;
					}
				}
				BreakOnNtContinueCallback = NULL;
			}
#endif
		}
	}
}

void DebuggerAllocationHandler(PVOID BaseAddress, SIZE_T RegionSize, ULONG Protect)
{
	if (!BaseAddress || !RegionSize)
	{
		DebugOutput("DebuggerAllocationHandler: Error, BaseAddress or RegionSize zero: 0x%p, 0x%p.\n", BaseAddress, RegionSize);
		return;
	}
#ifdef DEBUG_COMMENTS
	else
		DebugOutput("DebuggerAllocationHandler: BaseAddress 0x%p, RegionSize 0x%p.\n", BaseAddress, RegionSize);
#endif

	if (!(Protect & EXECUTABLE_FLAGS))
		return;

	if (BreakpointsHit)
		return;

	if (SetInitialBreakpoints(BaseAddress))
		DebugOutput("DebuggerAllocationHandler: Breakpoints set on new executable region at: 0x%p size 0x%p.\n", BaseAddress, RegionSize);
	else
		DebugOutput("DebuggerAllocationHandler: Error, failed to set breakpoints on new executable region at: 0x%p size 0x%p.\n", BaseAddress, RegionSize);
}

void ApplyQueuedBreakpoints()
{
	// To be implemented
}