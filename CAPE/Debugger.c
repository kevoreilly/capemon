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
#include <windows.h>
#include <assert.h>
#include <Aclapi.h>
#include "Debugger.h"
#include "..\alloc.h"
#include "..\config.h"
#include "..\pipe.h"
#include "Extraction.h"

#define PIPEBUFSIZE 512

// eflags register
#define FL_CF           0x00000001      // Carry Flag
#define FL_PF           0x00000004      // Parity Flag
#define FL_AF           0x00000010      // Auxiliary carry Flag
#define FL_ZF           0x00000040      // Zero Flag
#define FL_SF           0x00000080      // Sign Flag
#define FL_TF           0x00000100      // Trap Flag
#define FL_IF           0x00000200      // Interrupt Enable
#define FL_DF           0x00000400      // Direction Flag
#define FL_OF           0x00000800      // Overflow Flag
#define FL_IOPL_MASK    0x00003000      // I/O Privilege Level bitmask
#define FL_IOPL_0       0x00000000      //   IOPL == 0
#define FL_IOPL_1       0x00001000      //   IOPL == 1
#define FL_IOPL_2       0x00002000      //   IOPL == 2
#define FL_IOPL_3       0x00003000      //   IOPL == 3
#define FL_NT           0x00004000      // Nested Task
#define FL_RF           0x00010000      // Resume Flag
#define FL_VM           0x00020000      // Virtual 8086 mode
#define FL_AC           0x00040000      // Alignment Check
#define FL_VIF          0x00080000      // Virtual Interrupt Flag
#define FL_VIP          0x00100000      // Virtual Interrupt Pending
#define FL_ID           0x00200000      // ID flag

//
// debug register DR7 bit fields
//
typedef struct _DR7
{
    DWORD L0   : 1;    //Local enable bp0
    DWORD G0   : 1;    //Global enable bp0
    DWORD L1   : 1;    //Local enable bp1
    DWORD G1   : 1;    //Global enable bp1
    DWORD L2   : 1;    //Local enable bp2
    DWORD G2   : 1;    //Global enable bp2
    DWORD L3   : 1;    //Local enable bp3
    DWORD G3   : 1;    //Global enable bp3
    DWORD LE   : 1;    //Local Enable
    DWORD GE   : 1;    //Global Enable
    DWORD PAD1 : 3;
    DWORD GD   : 1;    //General Detect Enable
    DWORD PAD2 : 1;
    DWORD PAD3 : 1;
    DWORD RWE0 : 2;    //Read/Write/Execute bp0
    DWORD LEN0 : 2;    //Length bp0
    DWORD RWE1 : 2;    //Read/Write/Execute bp1
    DWORD LEN1 : 2;    //Length bp1
    DWORD RWE2 : 2;    //Read/Write/Execute bp2
    DWORD LEN2 : 2;    //Length bp2
    DWORD RWE3 : 2;    //Read/Write/Execute bp3
    DWORD LEN3 : 2;    //Length bp3
} DR7, *PDR7;

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _INJECT_STRUCT {
	ULONG_PTR LdrLoadDllAddress;
	UNICODE_STRING DllName;
	HANDLE OutHandle;
} INJECT_STRUCT, *PINJECT_STRUCT;

DWORD LengthMask[MAX_DEBUG_REGISTER_DATA_SIZE + 1] = DEBUG_REGISTER_LENGTH_MASKS;

DWORD MainThreadId;
struct ThreadBreakpoints *MainThreadBreakpointList;
SINGLE_STEP_HANDLER SingleStepHandler;
GUARD_PAGE_HANDLER GuardPageHandler;
HANDLE hCapePipe;

extern SYSTEM_INFO SystemInfo;

extern ULONG_PTR g_our_dll_base;
extern DWORD g_our_dll_size;
extern BOOLEAN is_address_in_ntdll(ULONG_PTR address);
extern char *convert_address_to_dll_name_and_offset(ULONG_PTR addr, unsigned int *offset);
extern LONG WINAPI cuckoomon_exception_handler(__in struct _EXCEPTION_POINTERS *ExceptionInfo);

extern BOOL ExtractionGuardPageHandler(struct _EXCEPTION_POINTERS* ExceptionInfo);
extern PTRACKEDREGION GetTrackedRegion(PVOID Address);
extern PVOID GetPageAddress(PVOID Address);
extern unsigned int address_is_in_stack(DWORD Address);
extern BOOL WoW64fix(void);
extern BOOL WoW64PatchBreakpoint(unsigned int Register);
extern BOOL WoW64UnpatchBreakpoint(unsigned int Register);
extern DWORD MyGetThreadId(HANDLE hThread);

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);

void DebugOutputThreadBreakpoints();
BOOL SetSingleStepMode(PCONTEXT Context, PVOID Handler);
BOOL ClearSingleStepMode(PCONTEXT Context);
unsigned int TrapIndex;

unsigned int DepthCount;
extern int operate_on_backtrace(ULONG_PTR _esp, ULONG_PTR _ebp, void *extra, int(*func)(void *, ULONG_PTR));
#ifdef CAPE_TRACE
extern void DebuggerOutput(_In_ LPCTSTR lpOutputString, ...);
extern BOOL TraceRunning, BreakpointsSet;
#endif

//**************************************************************************************
BOOL CountDepth(LPVOID* ReturnAddress, LPVOID Address)
//**************************************************************************************
{
#ifdef _WIN64
    if (DepthCount == 0 && ReturnAddress && Address)
#else
    if (DepthCount == 2 && ReturnAddress && Address)
#endif
    {
        DepthCount = 0;
        *ReturnAddress = Address;
        return TRUE;
    }

    DepthCount++;

    DoOutputDebugString("CountDepth: Address 0x%p, depthcount = %i.\n", Address, DepthCount);

    return FALSE;
}

//**************************************************************************************
PTHREADBREAKPOINTS GetThreadBreakpoints(DWORD ThreadId)
//**************************************************************************************
{
    DWORD CurrentThreadId;

    PTHREADBREAKPOINTS CurrentThreadBreakpoint = MainThreadBreakpointList;

	while (CurrentThreadBreakpoint)
	{
		CurrentThreadId = MyGetThreadId(CurrentThreadBreakpoint->ThreadHandle);

        if (CurrentThreadId == ThreadId)
            return CurrentThreadBreakpoint;
		else
            CurrentThreadBreakpoint = CurrentThreadBreakpoint->NextThreadBreakpoints;
	}

	return NULL;
}

//**************************************************************************************
HANDLE GetThreadHandle(DWORD ThreadId)
//**************************************************************************************
{
    DWORD CurrentThreadId;

    PTHREADBREAKPOINTS CurrentThreadBreakpoint = MainThreadBreakpointList;

	while (CurrentThreadBreakpoint)
	{
		CurrentThreadId = MyGetThreadId(CurrentThreadBreakpoint->ThreadHandle);

        if (CurrentThreadId == ThreadId)
            return CurrentThreadBreakpoint->ThreadHandle;
		else
            CurrentThreadBreakpoint = CurrentThreadBreakpoint->NextThreadBreakpoints;
	}

	return NULL;
}

//**************************************************************************************
PTHREADBREAKPOINTS CreateThreadBreakpoints(DWORD ThreadId)
//**************************************************************************************
{
	unsigned int Register;
	PTHREADBREAKPOINTS CurrentThreadBreakpoint, PreviousThreadBreakpoint;

    PreviousThreadBreakpoint = NULL;

	if (MainThreadBreakpointList == NULL)
	{
		MainThreadBreakpointList = ((struct ThreadBreakpoints*)malloc(sizeof(struct ThreadBreakpoints)));

        if (MainThreadBreakpointList == NULL)
        {
            DoOutputDebugString("CreateThreadBreakpoints: failed to allocate memory for initial thread breakpoint list.\n");
            return NULL;
        }

        memset(MainThreadBreakpointList, 0, sizeof(struct ThreadBreakpoints));

        MainThreadBreakpointList->ThreadId = MainThreadId;
	}

	CurrentThreadBreakpoint = MainThreadBreakpointList;

    while (CurrentThreadBreakpoint)
	{
        if (CurrentThreadBreakpoint->ThreadHandle && MyGetThreadId(CurrentThreadBreakpoint->ThreadHandle) == ThreadId)
        {
            //It already exists - shouldn't happen
            DoOutputDebugString("CreateThreadBreakpoints error: found an existing thread breakpoint list for ThreadId 0x%x\n", ThreadId);
            return NULL;
        }

        if ((CurrentThreadBreakpoint->ThreadId) == ThreadId)
        {
            // We have our thread breakpoint list
            break;
        }

		PreviousThreadBreakpoint = CurrentThreadBreakpoint;
        CurrentThreadBreakpoint = CurrentThreadBreakpoint->NextThreadBreakpoints;
	}

    if (!CurrentThreadBreakpoint)
    {
        // We haven't found it in the linked list, so create a new one
        CurrentThreadBreakpoint = PreviousThreadBreakpoint;

        CurrentThreadBreakpoint->NextThreadBreakpoints = ((struct ThreadBreakpoints*)malloc(sizeof(struct ThreadBreakpoints)));

        if (CurrentThreadBreakpoint->NextThreadBreakpoints == NULL)
		{
			DoOutputDebugString("CreateThreadBreakpoints: Failed to allocate new thread breakpoints.\n");
			return NULL;
		}

        memset(CurrentThreadBreakpoint->NextThreadBreakpoints, 0, sizeof(struct ThreadBreakpoints));

        CurrentThreadBreakpoint = CurrentThreadBreakpoint->NextThreadBreakpoints;
	}

	if (ThreadId == GetCurrentThreadId())
	{
		if (DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &CurrentThreadBreakpoint->ThreadHandle, 0, FALSE, DUPLICATE_SAME_ACCESS) == 0)
		{
			DoOutputDebugString("CreateThreadBreakpoints: Failed to duplicate thread handle.\n");
			free(CurrentThreadBreakpoint);
			return NULL;
		}
	}
	else
	{
		CurrentThreadBreakpoint->ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadId);

		if (CurrentThreadBreakpoint->ThreadHandle == NULL)
		{
			DoOutputDebugString("CreateThreadBreakpoints: Failed to open thread and get a handle.\n");
			free(CurrentThreadBreakpoint);
			return NULL;
		}
	}

    CurrentThreadBreakpoint->ThreadId = ThreadId;

    for (Register = 0; Register < NUMBER_OF_DEBUG_REGISTERS; Register++)
    {
        CurrentThreadBreakpoint->BreakpointInfo[Register].Register = Register;
        CurrentThreadBreakpoint->BreakpointInfo[Register].ThreadHandle = CurrentThreadBreakpoint->ThreadHandle;
    }

    return CurrentThreadBreakpoint;
}

//**************************************************************************************
BOOL InitNewThreadBreakpoints(DWORD ThreadId)
//**************************************************************************************
{
    PTHREADBREAKPOINTS NewThreadBreakpoints;

    if (MainThreadBreakpointList == NULL)
    {
		DoOutputDebugString("InitNewThreadBreakpoints: Failed to create thread breakpoints struct.\n");
		return FALSE;
    }

    NewThreadBreakpoints = CreateThreadBreakpoints(ThreadId);

	if (NewThreadBreakpoints == NULL)
	{
		DoOutputDebugString("InitNewThreadBreakpoints: Cannot create new thread breakpoints.\n");
		return FALSE;
	}

    if (NewThreadBreakpoints->ThreadHandle == NULL)
    {
		DoOutputDebugString("InitNewThreadBreakpoints error: main thread handle not set.\n");
		return FALSE;
    }

    for (unsigned int Register = 0; Register < NUMBER_OF_DEBUG_REGISTERS; Register++)
    {
        if (!MainThreadBreakpointList->BreakpointInfo[Register].Address)
            continue;

        NewThreadBreakpoints->BreakpointInfo[Register] = MainThreadBreakpointList->BreakpointInfo[Register];

        if (!NewThreadBreakpoints->BreakpointInfo[Register].Address)
            DoOutputDebugString("InitNewThreadBreakpoints error: failed to copy the breakpoint struct!\n");

        if (NewThreadBreakpoints->BreakpointInfo[Register].Address && !SetThreadBreakpoint(ThreadId, Register, NewThreadBreakpoints->BreakpointInfo[Register].Size, NewThreadBreakpoints->BreakpointInfo[Register].Address, NewThreadBreakpoints->BreakpointInfo[Register].Type, NewThreadBreakpoints->BreakpointInfo[Register].Callback))
        {
            DoOutputDebugString("InitNewThreadBreakpoints error: failed to set breakpoint %d for new thread %d.\n", Register, ThreadId);
            return FALSE;
        }
    }

    return TRUE;
}

//**************************************************************************************
void OutputThreadBreakpoints(DWORD ThreadId)
//**************************************************************************************
{
    PTHREADBREAKPOINTS ThreadBreakpoints = GetThreadBreakpoints(ThreadId);

	if (!ThreadBreakpoints)
        ThreadBreakpoints = CreateThreadBreakpoints(ThreadId);

	if (!ThreadBreakpoints)
    {
        DoOutputDebugString("OutputThreadBreakpoints: Unable to create breakpoints for thread %d.\n", ThreadId);
        return;
    }

    DoOutputDebugString("Breakpoints for thread %d: 0x%p, 0x%p, 0x%p, 0x%p.\n", ThreadId, ThreadBreakpoints->BreakpointInfo[0].Address, ThreadBreakpoints->BreakpointInfo[1].Address, ThreadBreakpoints->BreakpointInfo[2].Address, ThreadBreakpoints->BreakpointInfo[3].Address);

	return;
}

//**************************************************************************************
BOOL GetNextAvailableBreakpoint(DWORD ThreadId, unsigned int* Register)
//**************************************************************************************
{
    DWORD CurrentThreadId;
	unsigned int i;

    PTHREADBREAKPOINTS CurrentThreadBreakpoint = MainThreadBreakpointList;

	if (CurrentThreadBreakpoint == NULL)
    {
        DoOutputDebugString("GetNextAvailableBreakpoint: MainThreadBreakpointList NULL.\n");
        return FALSE;
    }

    while (CurrentThreadBreakpoint)
	{
		CurrentThreadId = MyGetThreadId(CurrentThreadBreakpoint->ThreadHandle);

        if (CurrentThreadId == ThreadId)
		{
            for (i=0; i < NUMBER_OF_DEBUG_REGISTERS; i++)
            {
                if (CurrentThreadBreakpoint->BreakpointInfo[i].Address == NULL)
                {
                    *Register = i;
                    return TRUE;
                }
            }
        }

        CurrentThreadBreakpoint = CurrentThreadBreakpoint->NextThreadBreakpoints;
	}

	return FALSE;
}

//**************************************************************************************
BOOL ContextGetNextAvailableBreakpoint(PCONTEXT Context, unsigned int* Register)
//**************************************************************************************
{
	unsigned int i;
	PTHREADBREAKPOINTS CurrentThreadBreakpoint;

    CurrentThreadBreakpoint = GetThreadBreakpoints(GetCurrentThreadId());

	if (CurrentThreadBreakpoint == NULL)
	{
		DoOutputDebugString("ContextGetNextAvailableBreakpoint: Creating new thread breakpoints for thread %d.\n", GetCurrentThreadId());
		CurrentThreadBreakpoint = CreateThreadBreakpoints(GetCurrentThreadId());
	}

	if (CurrentThreadBreakpoint == NULL)
	{
		DoOutputDebugString("ContextGetNextAvailableBreakpoint: Cannot create new thread breakpoints - FATAL.\n");
		return FALSE;
	}

    for (i=0; i < NUMBER_OF_DEBUG_REGISTERS; i++)
    {
        if (CurrentThreadBreakpoint->BreakpointInfo[i].Address == NULL)
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
    PTHREADBREAKPOINTS CurrentThreadBreakpoint;
	PBREAKPOINTINFO pBreakpointInfo;

    CurrentThreadBreakpoint = GetThreadBreakpoints(GetCurrentThreadId());

    for (Register = 0; Register < NUMBER_OF_DEBUG_REGISTERS; Register++)
    {
        pBreakpointInfo = &(CurrentThreadBreakpoint->BreakpointInfo[Register]);

        if (pBreakpointInfo == NULL)
        {
            DoOutputDebugString("DebugOutputThreadBreakpoints: Can't get BreakpointInfo - FATAL.\n");
        }

		DoOutputDebugString("Callback = 0x%x, Address = 0x%x, Size = 0x%x, Register = %i, ThreadHandle = 0x%x, Type = 0x%x\n",
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
        DoOutputDebugString("0x%x ([esp+0x%x]): 0x%x\n", StackPointer+4*i, (4*i), *(DWORD*)((BYTE*)StackPointer+4*i));
}

//**************************************************************************************
BOOL CAPEExceptionDispatcher(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context)
//**************************************************************************************
{
    struct _EXCEPTION_POINTERS ExceptionInfo;
    ExceptionInfo.ExceptionRecord = ExceptionRecord;
    ExceptionInfo.ContextRecord = Context;
    if (CAPEExceptionFilter(&ExceptionInfo) == EXCEPTION_CONTINUE_EXECUTION)
        return TRUE;
    else
        return FALSE;
}

//**************************************************************************************
LONG WINAPI CAPEExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	BREAKPOINT_HANDLER Handler;
	unsigned int bp;
	PTRACKEDREGION TrackedRegion;
    DWORD OldProtect;
    //char* DllName;
    //unsigned int DllRVA;

    // Hardware breakpoints generate EXCEPTION_SINGLE_STEP rather than EXCEPTION_BREAKPOINT
    if (ExceptionInfo->ExceptionRecord->ExceptionCode==EXCEPTION_SINGLE_STEP)
    {
		BOOL BreakpointFlag;
        PBREAKPOINTINFO pBreakpointInfo;
		PTHREADBREAKPOINTS CurrentThreadBreakpoint;

		CurrentThreadBreakpoint = GetThreadBreakpoints(GetCurrentThreadId());

		if (CurrentThreadBreakpoint == NULL)
		{
			DoOutputDebugString("CAPEExceptionFilter: Can't get thread breakpoints - FATAL.\n");
			return EXCEPTION_CONTINUE_SEARCH;
		}

        // Test Dr6 to see if this is a breakpoint
        BreakpointFlag = FALSE;
        for (bp = 0; bp < NUMBER_OF_DEBUG_REGISTERS; bp++)
		{
			if (ExceptionInfo->ContextRecord->Dr6 & (DWORD_PTR)(1 << bp))
			{
                BreakpointFlag = TRUE;
            }
        }

        // If not it's a single-step
        if (!BreakpointFlag)
        {
            if (SingleStepHandler)
                SingleStepHandler(ExceptionInfo);
            else if (TrapIndex)
            // this is from a 'StepOver' function
            {
                DoOutputDebugString("CAPEExceptionFilter: Stepping over execution breakpoint to: 0x%x\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);

                pBreakpointInfo = &(CurrentThreadBreakpoint->BreakpointInfo[TrapIndex-1]);

                ResumeAfterExecutionBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);
            }
            else
                // Unhandled single-step exception, pass it on
                return EXCEPTION_CONTINUE_SEARCH;

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        if (TrapIndex)
        {
            DoOutputDebugString("CAPEExceptionFilter: Anomaly detected: Trap index set on non-single-step: %d\n", TrapIndex);
        }

#ifdef CAPE_TRACE
        if (!TraceRunning)
#endif
        DoOutputDebugString("CAPEExceptionFilter: breakpoint hit by instruction at 0x%p (thread %d)\n", ExceptionInfo->ExceptionRecord->ExceptionAddress, GetCurrentThreadId());
#ifdef CAPE_TRACE
        DebuggerOutput("Breakpoint hit by instruction at 0x%p (thread %d)\n", ExceptionInfo->ExceptionRecord->ExceptionAddress, GetCurrentThreadId());
#endif

        for (bp = 0; bp < NUMBER_OF_DEBUG_REGISTERS; bp++)
		{
			if (ExceptionInfo->ContextRecord->Dr6 & (DWORD_PTR)(1 << bp))
			{
				pBreakpointInfo = &(CurrentThreadBreakpoint->BreakpointInfo[bp]);

                if (pBreakpointInfo == NULL)
                {
                    DoOutputDebugString("CAPEExceptionFilter: Can't get BreakpointInfo - FATAL.\n");
                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                if (pBreakpointInfo->Register == bp)
                {
                    if (bp == 0 && ((DWORD_PTR)pBreakpointInfo->Address != ExceptionInfo->ContextRecord->Dr0))
                        DoOutputDebugString("CAPEExceptionFilter: Anomaly detected! bp0 address (0x%x) different to BreakpointInfo (0x%x)!\n", ExceptionInfo->ContextRecord->Dr0, pBreakpointInfo->Address);

                    if (bp == 1 && ((DWORD_PTR)pBreakpointInfo->Address != ExceptionInfo->ContextRecord->Dr1))
                        DoOutputDebugString("CAPEExceptionFilter: Anomaly detected! bp1 address (0x%x) different to BreakpointInfo (0x%x)!\n", ExceptionInfo->ContextRecord->Dr1, pBreakpointInfo->Address);

                    if (bp == 2 && ((DWORD_PTR)pBreakpointInfo->Address != ExceptionInfo->ContextRecord->Dr2))
                        DoOutputDebugString("CAPEExceptionFilter: Anomaly detected! bp2 address (0x%x) different to BreakpointInfo (0x%x)!\n", ExceptionInfo->ContextRecord->Dr2, pBreakpointInfo->Address);

                    if (bp == 3 && ((DWORD_PTR)pBreakpointInfo->Address != ExceptionInfo->ContextRecord->Dr3))
                        DoOutputDebugString("CAPEExceptionFilter: Anomaly detected! bp3 address (0x%x) different to BreakpointInfo (0x%x)!\n", ExceptionInfo->ContextRecord->Dr3, pBreakpointInfo->Address);
#ifndef _WIN64
                    if (bp == 0 && ((DWORD_PTR)pBreakpointInfo->Type != ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE0))
                    {
                        if (pBreakpointInfo->Type == BP_READWRITE && ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE0 == BP_WRITE && address_is_in_stack((DWORD_PTR)pBreakpointInfo->Address))
                        {
                            DoOutputDebugString("CAPEExceptionFilter: Reinstated BP_READWRITE on breakpoint %d (WoW64 workaround)\n", pBreakpointInfo->Register);

                            ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo->Register, pBreakpointInfo->Size, (BYTE*)pBreakpointInfo->Address, pBreakpointInfo->Type, pBreakpointInfo->Callback);
                        }
                        else
                        {
                            DoOutputDebugString("CAPEExceptionFilter: Anomaly detected! bp0 type (0x%x) different to BreakpointInfo (0x%x)!\n", ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE0, pBreakpointInfo->Type);
                            CheckDebugRegisters(0, ExceptionInfo->ContextRecord);
                        }
                    }
                    if (bp == 1 && ((DWORD)pBreakpointInfo->Type != ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE1))
                    {
                        if (pBreakpointInfo->Type == BP_READWRITE && ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE1 == BP_WRITE && address_is_in_stack((DWORD_PTR)pBreakpointInfo->Address))
                        {
                            DoOutputDebugString("CAPEExceptionFilter: Reinstated BP_READWRITE on breakpoint %d (WoW64 workaround)\n", pBreakpointInfo->Register);

                            ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo->Register, pBreakpointInfo->Size, (BYTE*)pBreakpointInfo->Address, pBreakpointInfo->Type, pBreakpointInfo->Callback);
                        }
                        else
                        {
                            DoOutputDebugString("CAPEExceptionFilter: Anomaly detected! bp1 type (0x%x) different to BreakpointInfo (0x%x)!\n", ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE1, pBreakpointInfo->Type);
                            CheckDebugRegisters(0, ExceptionInfo->ContextRecord);
                        }
                    }
                    if (bp == 2 && ((DWORD)pBreakpointInfo->Type != ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE2))
                    {
                        if (pBreakpointInfo->Type == BP_READWRITE && ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE2 == BP_WRITE && address_is_in_stack((DWORD_PTR)pBreakpointInfo->Address))
                        {
                            DoOutputDebugString("CAPEExceptionFilter: Reinstated BP_READWRITE on stack breakpoint %d (WoW64 workaround)\n", pBreakpointInfo->Register);

                            ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo->Register, pBreakpointInfo->Size, (BYTE*)pBreakpointInfo->Address, pBreakpointInfo->Type, pBreakpointInfo->Callback);
                        }
                        else
                        {
                            DoOutputDebugString("CAPEExceptionFilter: Anomaly detected! bp2 type (0x%x) different to BreakpointInfo (0x%x)!\n", ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE2, pBreakpointInfo->Type);
                            CheckDebugRegisters(0, ExceptionInfo->ContextRecord);
                        }
                    }
                    if (bp == 3 && ((DWORD)pBreakpointInfo->Type != ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE3))
                    {
                        if (pBreakpointInfo->Type == BP_READWRITE && ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE3 == BP_WRITE && address_is_in_stack((DWORD_PTR)pBreakpointInfo->Address))
                        {
                            DoOutputDebugString("CAPEExceptionFilter: Reinstated BP_READWRITE on breakpoint %d (WoW64 workaround)\n", pBreakpointInfo->Register);

                            ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo->Register, pBreakpointInfo->Size, (BYTE*)pBreakpointInfo->Address, pBreakpointInfo->Type, pBreakpointInfo->Callback);
                        }
                        else
                        {
                            DoOutputDebugString("CAPEExceptionFilter: Anomaly detected! bp3 type (0x%x) different to BreakpointInfo (0x%x)!\n", ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE3, pBreakpointInfo->Type);
                            CheckDebugRegisters(0, ExceptionInfo->ContextRecord);
                        }
                    }
#endif // !_WIN64
                }
			}
		}

		if (pBreakpointInfo->Callback == NULL)
		{
			DoOutputDebugString("CAPEExceptionFilter: Can't get callback - FATAL.\n");
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		Handler = (BREAKPOINT_HANDLER)pBreakpointInfo->Callback;

		// Invoke the handler
        Handler(pBreakpointInfo, ExceptionInfo);

		return EXCEPTION_CONTINUE_EXECUTION;
    }
    // Page guard violations generate STATUS_GUARD_PAGE_VIOLATION
    else if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
    {
        if (g_config.extraction)
        {
            if (ExceptionInfo->ExceptionRecord->NumberParameters < 2)
            {
                DoOutputDebugString("CAPEExceptionFilter: Guard page exception with missing parameters, passing.\n");
                return EXCEPTION_CONTINUE_SEARCH;
            }

            //DoOutputDebugString("Entering CAPEExceptionFilter: guarded page access at 0x%x by 0x%x\n", ExceptionInfo->ExceptionRecord->ExceptionInformation[1], ExceptionInfo->ExceptionRecord->ExceptionAddress);

            if (TrackedRegion = GetTrackedRegion((PVOID)ExceptionInfo->ExceptionRecord->ExceptionInformation[1]))
            {
                if (is_address_in_ntdll((ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress))
                {
                    if (!VirtualProtect((PVOID)ExceptionInfo->ExceptionRecord->ExceptionInformation[1], 1, TrackedRegion->Protect | PAGE_GUARD, &OldProtect))
                    {
                        DoOutputDebugString("CAPEExceptionFilter: Failed to re-activate page guard on tracked region around 0x%x touched by ntdll.\n", ExceptionInfo->ExceptionRecord->ExceptionInformation[1]);
                    }

                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                if (GuardPageHandler)
                {
                    if (GuardPageHandler(ExceptionInfo))
                        return EXCEPTION_CONTINUE_EXECUTION;
                    else
                        return EXCEPTION_CONTINUE_SEARCH;
                }
                else
                {
                    DoOutputDebugString("CAPEExceptionFilter: Error, no page guard handler for CAPE guard page exception.\n");
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
            else
            {
                DoOutputDebugString("CAPEExceptionFilter: exception at 0x%x not within CAPE guarded page.\n", ExceptionInfo->ExceptionRecord->ExceptionInformation[1]);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
        else
        {
            DoOutputDebugString("CAPEExceptionFilter: Guard page exception, passing.\n");
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }
    //else if (ExceptionInfo->ExceptionRecord->ExceptionCode == DBG_PRINTEXCEPTION_C)
    //{
    //    // This could be useful output
    //    // TODO: find string buffer(s)        //DoOutputDebugString("CAPEExceptionFilter: DBG_PRINTEXCEPTION_C at 0x%x (0x%x).\n", ExceptionInfo->ExceptionRecord->ExceptionInformation[1], ExceptionInfo->ExceptionRecord->ExceptionInformation[0]);
    //    return EXCEPTION_CONTINUE_SEARCH;
    //}
    if ((ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress >= g_our_dll_base && (ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress < (g_our_dll_base + g_our_dll_size))
    {
        // This is a CAPE (or Cuckoo) exception
        DoOutputDebugString("CAPEExceptionFilter: Exception 0x%x caught at RVA 0x%x in capemon caught accessing 0x%x (expected in memory scans), passing to next handler.\n", ExceptionInfo->ExceptionRecord->ExceptionCode, (BYTE*)ExceptionInfo->ExceptionRecord->ExceptionAddress - g_our_dll_base, ExceptionInfo->ExceptionRecord->ExceptionInformation[1]);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Some other exception occurred. Pass it to next handler.
    //DllRVA = 0;
    //if (ExceptionInfo->ExceptionRecord->ExceptionAddress)
    //    DllName = convert_address_to_dll_name_and_offset((ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress, &DllRVA);
    //else
    //    DllName = "unknown";
    //
    //DoOutputDebugString("CAPEExceptionFilter: Exception 0x%x caught at 0x%x accessing 0x%x (RVA 0x%x in %s) passing.\n", ExceptionInfo->ExceptionRecord->ExceptionCode, ExceptionInfo->ExceptionRecord->ExceptionAddress, ExceptionInfo->ExceptionRecord->ExceptionInformation[1], DllRVA, DllName);
    return EXCEPTION_CONTINUE_SEARCH;
}

//**************************************************************************************
BOOL ContextSetDebugRegisterEx
//**************************************************************************************
(
    PCONTEXT	Context,
    int		    Register,
    int		    Size,
    LPVOID	    Address,
    DWORD	    Type,
    BOOL        NoSetThreadContext
)
{
	DWORD	Length;
#ifdef _WIN64
    PTHREADBREAKPOINTS CurrentThreadBreakpoint;
#endif

    PDWORD_PTR  Dr0 = &(Context->Dr0);
    PDWORD_PTR  Dr1 = &(Context->Dr1);
    PDWORD_PTR  Dr2 = &(Context->Dr2);
    PDWORD_PTR  Dr3 = &(Context->Dr3);
    PDR7 Dr7 = (PDR7)&(Context->Dr7);

    if ((unsigned int)Type > 3)
    {
        DoOutputDebugString("ContextSetDebugRegister: %d is an invalid breakpoint type, must be 0-3.\n", Type);
        return FALSE;
    }

    if (Type == 2)
    {
        DoOutputDebugString("ContextSetDebugRegister: The value 2 is a 'reserved' breakpoint type, ultimately invalid.\n");
        return FALSE;
    }

    if (Register < 0 || Register > 3)
    {
        DoOutputDebugString("ContextSetDebugRegister: %d is an invalid register, must be 0-3.\n", Register);
        return FALSE;
    }

    if (Size < 0 || Size > 8)
    {
        DoOutputDebugString("ContextSetDebugRegister: %d is an invalid Size, must be 1, 2, 4 or 8.\n", Size);
        return FALSE;
    }

    Length  = LengthMask[Size];

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

    Dr7->LE = 1;
    Context->Dr6 = 0;

#ifdef _WIN64
    if (NoSetThreadContext)
        return TRUE;

    CurrentThreadBreakpoint = GetThreadBreakpoints(GetCurrentThreadId());

	if (CurrentThreadBreakpoint == NULL)
	{
		DoOutputDebugString("ContextSetDebugRegister: No breakpoints found for current thread %d.\n", GetCurrentThreadId());
		return FALSE;
	}

	if (CurrentThreadBreakpoint->ThreadHandle == NULL)
	{
		DoOutputDebugString("ContextSetDebugRegister: No thread handle found in breakpoints found for current thread %d.\n", GetCurrentThreadId());
		return FALSE;
	}

    Context->ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!SetThreadContext(CurrentThreadBreakpoint->ThreadHandle, Context))
    {
        DoOutputErrorString("ContextSetDebugRegister: SetThreadContext failed");
        return FALSE;
    }
#endif

	return TRUE;
}

//**************************************************************************************
BOOL ContextSetDebugRegister
//**************************************************************************************
(
    PCONTEXT	Context,
    int		    Register,
    int		    Size,
    LPVOID	    Address,
    DWORD	    Type
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
	DWORD	Length;
    CONTEXT	Context;

    PDWORD_PTR Dr0 = &Context.Dr0;
    PDWORD_PTR Dr1 = &Context.Dr1;
    PDWORD_PTR Dr2 = &Context.Dr2;
    PDWORD_PTR Dr3 = &Context.Dr3;
    PDR7 Dr7 = (PDR7)&(Context.Dr7);

    if ((unsigned int)Type > 3)
    {
        DoOutputDebugString("SetDebugRegister: %d is an invalid breakpoint type, must be 0-3.\n", Type);
        return FALSE;
    }

    if (Type == 2)
    {
        DoOutputDebugString("SetDebugRegister: The value 2 is a 'reserved' breakpoint type, ultimately invalid.\n");
        return FALSE;
    }

    if (Register < 0 || Register > 3)
    {
        DoOutputDebugString("SetDebugRegister: %d is an invalid register, must be 0-3.\n", Register);
        return FALSE;
    }

    if (Size < 0 || Size > 8)
    {
        DoOutputDebugString("SetDebugRegister: %d is an invalid Size, must be 1, 2, 4 or 8.\n", Size);
        return FALSE;
    }

	DoOutputDebugString("SetDebugRegister: Setting breakpoint %i hThread=0x%x, Size=0x%x, Address=0x%p and Type=0x%x.\n", Register, hThread, Size, Address, Type);

    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(hThread, &Context))
    {
        DoOutputErrorString("SetDebugRegister: GetThreadContext failed (thread handle 0x%x)", hThread);
        return FALSE;
    }

    Length  = LengthMask[Size];

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

    Dr7->LE = 1;
    Context.Dr6 = 0;

    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!SetThreadContext(hThread, &Context))
    {
        DoOutputErrorString("SetDebugRegister: SetThreadContext failed");
        return FALSE;
    }

	return TRUE;
}

//**************************************************************************************
BOOL ContextCheckDebugRegisters(PCONTEXT Context)
//**************************************************************************************
{
    PDR7 Dr7;

    if (!Context)
    {
        DoOutputDebugString("CheckDebugRegisters - no context supplied.\n");
        return FALSE;
    }

    Dr7 = (PDR7)&(Context->Dr7);

	DoOutputDebugString("Checking breakpoints\n");
	DoOutputDebugString("Dr0 0x%x, Dr7->LEN0 %i, Dr7->RWE0 %i, Dr7->L0 %i\n", Context->Dr0, Dr7->LEN0, Dr7->RWE0, Dr7->L0);
	DoOutputDebugString("Dr1 0x%x, Dr7->LEN1 %i, Dr7->RWE1 %i, Dr7->L1 %i\n", Context->Dr1, Dr7->LEN1, Dr7->RWE1, Dr7->L1);
	DoOutputDebugString("Dr2 0x%x, Dr7->LEN2 %i, Dr7->RWE2 %i, Dr7->L2 %i\n", Context->Dr2, Dr7->LEN2, Dr7->RWE2, Dr7->L2);
	DoOutputDebugString("Dr3 0x%x, Dr7->LEN3 %i, Dr7->RWE3 %i, Dr7->L3 %i\n", Context->Dr3, Dr7->LEN3, Dr7->RWE3, Dr7->L3);
	DoOutputDebugString("Dr6 0x%x\n", Context->Dr6);

	return TRUE;
}

//**************************************************************************************
BOOL CheckDebugRegisters(HANDLE hThread, PCONTEXT pContext)
//**************************************************************************************
{
    CONTEXT	Context;
    PDWORD_PTR  Dr0 = &Context.Dr0;
    PDWORD_PTR  Dr1 = &Context.Dr1;
    PDWORD_PTR  Dr2 = &Context.Dr2;
    PDWORD_PTR  Dr3 = &Context.Dr3;
    PDR7 Dr7 = (PDR7)&(Context.Dr7);

    if (!hThread && !pContext)
    {
        DoOutputDebugString("CheckDebugRegisters - required arguments missing.\n");
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
            DoOutputDebugString("CheckDebugRegisters - failed to get thread context.\n");
            return FALSE;
        }
    }

	DoOutputDebugString("Checking breakpoints\n");
	DoOutputDebugString("*Dr0 0x%x, Dr7->LEN0 %i, Dr7->RWE0 %i, Dr7->L0 %i\n", *Dr0, Dr7->LEN0, Dr7->RWE0, Dr7->L0);
	DoOutputDebugString("*Dr1 0x%x, Dr7->LEN1 %i, Dr7->RWE1 %i, Dr7->L1 %i\n", *Dr1, Dr7->LEN1, Dr7->RWE1, Dr7->L1);
	DoOutputDebugString("*Dr2 0x%x, Dr7->LEN2 %i, Dr7->RWE2 %i, Dr7->L2 %i\n", *Dr2, Dr7->LEN2, Dr7->RWE2, Dr7->L2);
	DoOutputDebugString("*Dr3 0x%x, Dr7->LEN3 %i, Dr7->RWE3 %i, Dr7->L3 %i\n", *Dr3, Dr7->LEN3, Dr7->RWE3, Dr7->L3);
	DoOutputDebugString("Dr6 0x%x, thread handle 0x%x\n", Context.Dr6, hThread);

	return TRUE;
}

//**************************************************************************************
BOOL ContextClearAllBreakpoints(PCONTEXT Context)
//**************************************************************************************
{
	unsigned int i;
	PTHREADBREAKPOINTS CurrentThreadBreakpoint;

    CurrentThreadBreakpoint = GetThreadBreakpoints(GetCurrentThreadId());

	if (CurrentThreadBreakpoint == NULL)
	{
		DoOutputDebugString("ContextClearAllBreakpoints: No breakpoints found for current thread %d.\n", GetCurrentThreadId());
		return FALSE;
	}

    for (i=0; i < NUMBER_OF_DEBUG_REGISTERS; i++)
    {
        CurrentThreadBreakpoint->BreakpointInfo[i].Register = 0;
        CurrentThreadBreakpoint->BreakpointInfo[i].Size = 0;
        CurrentThreadBreakpoint->BreakpointInfo[i].Address = NULL;
        CurrentThreadBreakpoint->BreakpointInfo[i].Type = 0;
        CurrentThreadBreakpoint->BreakpointInfo[i].Callback = NULL;
    }

    Context->Dr0 = 0;
    Context->Dr1 = 0;
	Context->Dr2 = 0;
    Context->Dr3 = 0;
	Context->Dr6 = 0;
	Context->Dr7 = 0;

#ifdef _WIN64
	if (CurrentThreadBreakpoint->ThreadHandle == NULL)
	{
		DoOutputDebugString("ContextClearAllBreakpoints: No thread handle found in breakpoints found for current thread %d.\n", GetCurrentThreadId());
		return FALSE;
	}

    Context->ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!SetThreadContext(CurrentThreadBreakpoint->ThreadHandle, Context))
    {
        DoOutputErrorString("ContextClearAllBreakpoints: SetThreadContext failed");
        return FALSE;
    }
    else
        DoOutputDebugString("ContextClearAllBreakpoints: SetThreadContext success.\n");
#endif

    return TRUE;
}

//**************************************************************************************
BOOL ClearAllBreakpoints()
//**************************************************************************************
{
    CONTEXT	Context;
	PTHREADBREAKPOINTS CurrentThreadBreakpoint;
    unsigned int Register;

    CurrentThreadBreakpoint = MainThreadBreakpointList;

	while (CurrentThreadBreakpoint)
	{
        if (!CurrentThreadBreakpoint->ThreadId)
        {
            DoOutputDebugString("ClearAllBreakpoints: Error: no thread id for thread breakpoints 0x%x.\n", CurrentThreadBreakpoint);
            return FALSE;
        }

        if (!CurrentThreadBreakpoint->ThreadHandle)
        {
            DoOutputDebugString("ClearAllBreakpoints: Error no thread handle for thread %d.\n", CurrentThreadBreakpoint->ThreadId);
            return FALSE;
        }

        for (Register = 0; Register < NUMBER_OF_DEBUG_REGISTERS; Register++)
        {
            CurrentThreadBreakpoint->BreakpointInfo[Register].Register = 0;
            CurrentThreadBreakpoint->BreakpointInfo[Register].Size = 0;
            CurrentThreadBreakpoint->BreakpointInfo[Register].Address = NULL;
            CurrentThreadBreakpoint->BreakpointInfo[Register].Type = 0;
            CurrentThreadBreakpoint->BreakpointInfo[Register].Callback = NULL;
        }

        Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if (!GetThreadContext(CurrentThreadBreakpoint->ThreadHandle, &Context))
        {
            DoOutputDebugString("ClearAllBreakpoints: Error getting thread context (thread %d, handle 0x%x).\n", CurrentThreadBreakpoint->ThreadId, CurrentThreadBreakpoint->ThreadHandle);
            return FALSE;
        }

        Context.Dr0 = 0;
        Context.Dr1 = 0;
        Context.Dr2 = 0;
        Context.Dr3 = 0;
        Context.Dr6 = 0;
        Context.Dr7 = 0;

        if (!SetThreadContext(CurrentThreadBreakpoint->ThreadHandle, &Context))
        {
            DoOutputDebugString("ClearAllBreakpoints: Error setting thread context (thread %d).\n", CurrentThreadBreakpoint->ThreadId);
            return FALSE;
        }

        CurrentThreadBreakpoint = CurrentThreadBreakpoint->NextThreadBreakpoints;
	}

	return TRUE;
}

//**************************************************************************************
BOOL ContextClearBreakpoint(PCONTEXT Context, PBREAKPOINTINFO pBreakpointInfo)
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

	DoOutputDebugString("ContextClearBreakpoint: Clearing breakpoint %i\n", pBreakpointInfo->Register);

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

    Context->Dr6 = 0;

#ifdef _WIN64
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("ContextClearBreakpoint: No thread handle found in breakpoints found for current thread %d.\n", GetCurrentThreadId());
		return FALSE;
	}

    Context->ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!SetThreadContext(pBreakpointInfo->ThreadHandle, Context))
    {
        DoOutputErrorString("ContextClearBreakpoint: SetThreadContext failed");
        return FALSE;
    }
    else
        DoOutputDebugString("ContextClearBreakpoint: SetThreadContext success.\n");
#endif

	pBreakpointInfo->Address = 0;
	pBreakpointInfo->Size = 0;
	pBreakpointInfo->Callback = 0;
	pBreakpointInfo->Type = 0;

	return TRUE;
}

//**************************************************************************************
BOOL ContextClearBreakpointsInRange(PCONTEXT Context, PVOID BaseAddress, SIZE_T Size)
//**************************************************************************************
{
    unsigned int Register;

    PTHREADBREAKPOINTS CurrentThreadBreakpoint = MainThreadBreakpointList;

    if (BaseAddress == NULL)
    {
        DoOutputDebugString("ContextClearBreakpointsInRange: No address supplied (may have already been cleared).\n");
        return FALSE;
    }

    if (Size == 0)
    {
        DoOutputDebugString("ContextClearBreakpointsInRange: Size supplied is zero.\n");
        return FALSE;
    }

    DoOutputDebugString("ContextClearBreakpointsInRange: Clearing breakpoints in range 0x%x - 0x%x.\n", BaseAddress, (BYTE*)BaseAddress + Size);

    while (CurrentThreadBreakpoint)
	{
        for (Register = 0; Register < NUMBER_OF_DEBUG_REGISTERS; Register++)
        {
            if ((DWORD_PTR)CurrentThreadBreakpoint->BreakpointInfo[Register].Address >= (DWORD_PTR)BaseAddress
                && (DWORD_PTR)CurrentThreadBreakpoint->BreakpointInfo[Register].Address < (DWORD_PTR)((BYTE*)BaseAddress + Size))
            {
                PDR7 Dr7 = (PDR7)&(Context->Dr7);

                DoOutputDebugString("ContextClearBreakpointsInRange: Clearing breakpoint %d address 0x%p.\n", Register, CurrentThreadBreakpoint->BreakpointInfo[Register].Address);

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

                Context->Dr6 = 0;

                CurrentThreadBreakpoint->BreakpointInfo[Register].Register = 0;
                CurrentThreadBreakpoint->BreakpointInfo[Register].Size = 0;
                CurrentThreadBreakpoint->BreakpointInfo[Register].Address = NULL;
                CurrentThreadBreakpoint->BreakpointInfo[Register].Type = 0;
                CurrentThreadBreakpoint->BreakpointInfo[Register].Callback = NULL;
            }
        }

        CurrentThreadBreakpoint = CurrentThreadBreakpoint->NextThreadBreakpoints;
    }

#ifdef _WIN64
	if (CurrentThreadBreakpoint->ThreadHandle == NULL)
	{
		DoOutputDebugString("ContextClearBreakpointsInRange: No thread handle found in breakpoints found for current thread %d.\n", GetCurrentThreadId());
		return FALSE;
	}

    Context->ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!SetThreadContext(CurrentThreadBreakpoint->ThreadHandle, Context))
    {
        DoOutputErrorString("ContextClearBreakpointsInRange: SetThreadContext failed");
        return FALSE;
    }
    else
        DoOutputDebugString("ContextClearBreakpointsInRange: SetThreadContext success.\n");
#endif

    return TRUE;
}

//**************************************************************************************
BOOL ClearBreakpointsInRange(PVOID BaseAddress, SIZE_T Size)
//**************************************************************************************
{
    unsigned int Register;

    PTHREADBREAKPOINTS CurrentThreadBreakpoint = MainThreadBreakpointList;

    if (BaseAddress == NULL)
    {
        DoOutputDebugString("ClearBreakpointsInRange: No address supplied (may have already been cleared).\n");
        return FALSE;
    }

    if (Size == 0)
    {
        DoOutputDebugString("ClearBreakpointsInRange: Size supplied is zero.\n");
        return FALSE;
    }

    DoOutputDebugString("ClearBreakpointsInRange: Clearing breakpoints in range 0x%x - 0x%x.\n", BaseAddress, (BYTE*)BaseAddress + Size);

    while (CurrentThreadBreakpoint)
	{
        for (Register = 0; Register < NUMBER_OF_DEBUG_REGISTERS; Register++)
        {
            if ((DWORD_PTR)CurrentThreadBreakpoint->BreakpointInfo[Register].Address >= (DWORD_PTR)BaseAddress
                && (DWORD_PTR)CurrentThreadBreakpoint->BreakpointInfo[Register].Address < (DWORD_PTR)((BYTE*)BaseAddress + Size))
            {
                DoOutputDebugString("ClearBreakpointsInRange: Clearing breakpoint %d address 0x%p.\n", Register, CurrentThreadBreakpoint->BreakpointInfo[Register].Address);
                ClearBreakpoint(Register);
            }
        }

        CurrentThreadBreakpoint = CurrentThreadBreakpoint->NextThreadBreakpoints;
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
BOOL SetSingleStepMode(PCONTEXT Context, PVOID Handler)
//**************************************************************************************
{
	if (Context == NULL)
        return FALSE;

    // set the trap flag
    Context->EFlags |= FL_TF;

#ifdef BRANCH_TRACE
    // set bits 8 & 9, LBR & BTF bits for branch trace
	PDR7 Dr7 = (PDR7)&(Context->Dr7);
    //Dr7->LE = 1;
    Dr7->GE = 1;
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

    TrapIndex = 0;

    SingleStepHandler = NULL;

    return TRUE;
}

//**************************************************************************************
BOOL StepOverExecutionBreakpoint(PCONTEXT Context, PBREAKPOINTINFO pBreakpointInfo)
//**************************************************************************************
// This function allows us to get past an execution breakpoint while leaving it set. It
// diaables the breakpoint, sets single-step mode to step over the instruction, whereupon
// the breakpoint is restored in ResumeAfterExecutionBreakpoint and execution resumed.
{
	PDR7 Dr7;

	if (Context == NULL)
        return FALSE;

    Dr7 = (PDR7)&(Context->Dr7);

	switch(pBreakpointInfo->Register)
	{
        case 0:
            Dr7->L0 = 0;
            break;
        case 1:
            Dr7->L1 = 0;
            break;
        case 2:
            Dr7->L2 = 0;
            break;
        case 3:
            Dr7->L3 = 0;
            break;
	}

    // set the trap flag
    Context->EFlags |= FL_TF;

    // set the 'trap index' so we know which 'register' we're skipping
    // (off by one to allow 'set'/'unset' to be signified by !0/0)
    TrapIndex = pBreakpointInfo->Register + 1;

#ifdef _WIN64
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("StepOverExecutionBreakpoint: No thread handle found in breakpoints found for current thread %d.\n", GetCurrentThreadId());
		return FALSE;
	}

    Context->ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!SetThreadContext(pBreakpointInfo->ThreadHandle, Context))
    {
        DoOutputErrorString("StepOverExecutionBreakpoint: SetThreadContext failed");
        return FALSE;
    }
#endif

    return TRUE;
}

//**************************************************************************************
BOOL ResumeAfterExecutionBreakpoint(PCONTEXT Context, PBREAKPOINTINFO pBreakpointInfo)
//**************************************************************************************
{
	PDR7 Dr7;

	if (Context == NULL)
        return FALSE;

    Dr7 = (PDR7)&(Context->Dr7);

#ifdef _WIN64
    if (!pBreakpointInfo)
    {
        DoOutputDebugString("ResumeAfterExecutionBreakpoint: pBreakpointInfo NULL.\n");
        return FALSE;
    }
#endif

    switch(TrapIndex-1)
	{
        case 0:
            Dr7->L0 = 1;
            break;
        case 1:
            Dr7->L1 = 1;
            break;
        case 2:
            Dr7->L2 = 1;
            break;
        case 3:
            Dr7->L3 = 1;
            break;
	}

    // Clear the trap flag
    Context->EFlags &= ~FL_TF;

#ifdef _WIN64
	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("ResumeAfterExecutionBreakpoint: No thread handle found in breakpoints found for current thread %d.\n", GetCurrentThreadId());
		return FALSE;
	}

    Context->ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!SetThreadContext(pBreakpointInfo->ThreadHandle, Context))
    {
        DoOutputErrorString("ResumeAfterExecutionBreakpoint: SetThreadContext failed");
        return FALSE;
    }
#endif

    // clear the 'trap index'
    TrapIndex = 0;

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
    PDWORD_PTR  Dr0 = &Context.Dr0;
    PDWORD_PTR  Dr1 = &Context.Dr1;
    PDWORD_PTR  Dr2 = &Context.Dr2;
    PDWORD_PTR  Dr3 = &Context.Dr3;
    PDR7 Dr7 = (PDR7)&(Context.Dr7);

    if ((unsigned int)Type > 3)
    {
        DoOutputDebugString("ClearDebugRegister: %d is an invalid breakpoint type, must be 0-3.\n", Type);
        return FALSE;
    }

    if (Register < 0 || Register > 3)
    {
        DoOutputDebugString("ClearDebugRegister: %d is an invalid register, must be 0-3.\n", Register);
        return FALSE;
    }

    if (Size < 0 || Size > 8)
    {
        DoOutputDebugString("ClearDebugRegister: %d is an invalid Size, must be 1, 2, 4 or 8.\n", Size);
        return FALSE;
    }

    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(hThread, &Context))
    {
        DoOutputErrorString("ClearDebugRegister: Initial GetThreadContext failed");
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

    Context.Dr6 = 0;

    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!SetThreadContext(hThread, &Context))
    {
        DoOutputErrorString("ClearDebugRegister: SetThreadContext failed");
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
        DoOutputDebugString("ContextCheckDebugRegister: %d is an invalid register, must be 0-3.\n", Register);
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

	// should not happen
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
        DoOutputDebugString("CheckDebugRegister: %d is an invalid register, must be 0-3.\n", Register);
        return FALSE;
    }

    Dr7 = (PDR7)&(Context.Dr7);

    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(hThread, &Context))
    {
        DoOutputErrorString("CheckDebugRegister: GetThreadContext failed.\n");
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

	// should not happen
	return -1;
}

//**************************************************************************************
BOOL ContextSetBreakpoint(PTHREADBREAKPOINTS ReferenceThreadBreakpoint)
//**************************************************************************************
{
    PTHREADBREAKPOINTS CurrentThreadBreakpoint;

    if (ReferenceThreadBreakpoint == NULL)
    {
		DoOutputDebugString("ContextSetBreakpoint: ReferenceThreadBreakpoint NULL.\n");
		return FALSE;
    }

    if (MainThreadBreakpointList == NULL)
    {
		DoOutputDebugString("ContextSetBreakpoint: MainThreadBreakpointList NULL.\n");
		return FALSE;
    }

    CurrentThreadBreakpoint = MainThreadBreakpointList;

	while (CurrentThreadBreakpoint)
	{
        if (CurrentThreadBreakpoint != ReferenceThreadBreakpoint)
        {
            for (unsigned int i = 0; i < NUMBER_OF_DEBUG_REGISTERS; i++)
            {
                if (CurrentThreadBreakpoint->ThreadHandle)
                    CurrentThreadBreakpoint->BreakpointInfo[i].ThreadHandle  = CurrentThreadBreakpoint->ThreadHandle;
                CurrentThreadBreakpoint->BreakpointInfo[i].Register      = ReferenceThreadBreakpoint->BreakpointInfo[i].Register;
                CurrentThreadBreakpoint->BreakpointInfo[i].Size          = ReferenceThreadBreakpoint->BreakpointInfo[i].Size;
                CurrentThreadBreakpoint->BreakpointInfo[i].Address       = ReferenceThreadBreakpoint->BreakpointInfo[i].Address;
                CurrentThreadBreakpoint->BreakpointInfo[i].Type          = ReferenceThreadBreakpoint->BreakpointInfo[i].Type;
                CurrentThreadBreakpoint->BreakpointInfo[i].Callback      = ReferenceThreadBreakpoint->BreakpointInfo[i].Callback;

                if (CurrentThreadBreakpoint->BreakpointInfo[i].Address)
                    SetThreadBreakpoint(CurrentThreadBreakpoint->ThreadId, CurrentThreadBreakpoint->BreakpointInfo[i].Register, CurrentThreadBreakpoint->BreakpointInfo[i].Size, CurrentThreadBreakpoint->BreakpointInfo[i].Address, CurrentThreadBreakpoint->BreakpointInfo[i].Type, CurrentThreadBreakpoint->BreakpointInfo[i].Callback);
            }
        }

        CurrentThreadBreakpoint = CurrentThreadBreakpoint->NextThreadBreakpoints;
	}

	return TRUE;
}


//**************************************************************************************
BOOL ContextSetThreadBreakpointEx
//**************************************************************************************
(
    PCONTEXT	Context,
    int			Register,
    int			Size,
    LPVOID		Address,
    DWORD		Type,
	PVOID		Callback,
    BOOL        NoSetThreadContext
)
{
	PTHREADBREAKPOINTS CurrentThreadBreakpoint;

    if (Register > 3 || Register < 0)
    {
        DoOutputDebugString("ContextSetThreadBreakpoint: Error - register value %d, can only have value 0-3.\n", Register);
        return FALSE;
    }

    if (!ContextSetDebugRegisterEx(Context, Register, Size, Address, Type, NoSetThreadContext))
	{
		DoOutputDebugString("ContextSetThreadBreakpoint: Call to ContextSetDebugRegister failed.\n");
	}
	else
	{
        CurrentThreadBreakpoint = GetThreadBreakpoints(GetCurrentThreadId());

        if (CurrentThreadBreakpoint == NULL)
        {
            DoOutputDebugString("ContextSetThreadBreakpoint: Error - Failed to acquire thread breakpoints.\n");
            return FALSE;
        }

		CurrentThreadBreakpoint->BreakpointInfo[Register].ThreadHandle  = CurrentThreadBreakpoint->ThreadHandle;
		CurrentThreadBreakpoint->BreakpointInfo[Register].Register      = Register;
		CurrentThreadBreakpoint->BreakpointInfo[Register].Size          = Size;
		CurrentThreadBreakpoint->BreakpointInfo[Register].Address       = Address;
		CurrentThreadBreakpoint->BreakpointInfo[Register].Type          = Type;
		CurrentThreadBreakpoint->BreakpointInfo[Register].Callback      = Callback;
	}


    return TRUE;
}

//**************************************************************************************
BOOL ContextSetThreadBreakpoint
//**************************************************************************************
(
    PCONTEXT	Context,
    int			Register,
    int			Size,
    LPVOID		Address,
    DWORD		Type,
	PVOID		Callback
)
{
    return ContextSetThreadBreakpointEx(Context, Register, Size, Address, Type,  Callback, FALSE);
}

//**************************************************************************************
BOOL ContextSetNextAvailableBreakpoint
//**************************************************************************************
(
    PCONTEXT	    Context,
    unsigned int*	Register,
    int		        Size,
    LPVOID	        Address,
    DWORD	        Type,
	PVOID	        Callback
)
{
	PTHREADBREAKPOINTS CurrentThreadBreakpoint;

    if (!Address)
    {
        DoOutputDebugString("ContextSetNextAvailableBreakpoint: Error - breakpoint address is zero!\n");
        return FALSE;
    }

    CurrentThreadBreakpoint = GetThreadBreakpoints(GetCurrentThreadId());

    if (CurrentThreadBreakpoint == NULL)
    {
        DoOutputDebugString("ContextSetNextAvailableBreakpoint: Error - Failed to acquire thread breakpoints.\n");
        return FALSE;
    }

    // Check whether an identical breakpoint already exists
    for (unsigned int i = 0; i < NUMBER_OF_DEBUG_REGISTERS; i++)
    {
        if
        (
            CurrentThreadBreakpoint->BreakpointInfo[i].Size == Size &&
            CurrentThreadBreakpoint->BreakpointInfo[i].Address == Address &&
            CurrentThreadBreakpoint->BreakpointInfo[i].Type == Type
        )
        {
            DoOutputDebugString("ContextSetNextAvailableBreakpoint: An identical breakpoint (%d) at 0x%p already exists for thread %d (process %d), skipping.\n", i, Address, CurrentThreadBreakpoint->ThreadId, GetCurrentProcessId());
            return TRUE;
        }
    }

    if (Register)
    {
        if (!ContextGetNextAvailableBreakpoint(Context, Register))
        {
            DoOutputDebugString("ContextSetNextAvailableBreakpoint: No available breakpoints!\n");
            OutputThreadBreakpoints(GetCurrentThreadId());
            return FALSE;
        }

        return ContextSetThreadBreakpoint(Context, *Register, Size, Address, Type, Callback);
    }
    else
    {
        unsigned int TempRegister;

        if (!ContextGetNextAvailableBreakpoint(Context, &TempRegister))
        {
            DoOutputDebugString("ContextSetNextAvailableBreakpoint: No available breakpoints!\n");
            OutputThreadBreakpoints(GetCurrentThreadId());
            return FALSE;
        }

        return ContextSetThreadBreakpoint(Context, TempRegister, Size, Address, Type, Callback);
    }
}

//**************************************************************************************
BOOL ContextUpdateCurrentBreakpoint
//**************************************************************************************
(
    PCONTEXT	    Context,
    int		        Size,
    LPVOID	        Address,
    DWORD	        Type,
	PVOID	        Callback
)
{
	PTHREADBREAKPOINTS CurrentThreadBreakpoint;
    PBREAKPOINTINFO pBreakpointInfo;
    unsigned int bp;

    CurrentThreadBreakpoint = GetThreadBreakpoints(GetCurrentThreadId());

    if (CurrentThreadBreakpoint == NULL)
    {
        DoOutputDebugString("ContextUpdateCurrentBreakpoint: Error - Failed to acquire thread breakpoints.\n");
        return FALSE;
    }

    for (bp = 0; bp < NUMBER_OF_DEBUG_REGISTERS; bp++)
    {
        pBreakpointInfo = &(CurrentThreadBreakpoint->BreakpointInfo[bp]);

        if (pBreakpointInfo == NULL)
        {
            DoOutputDebugString("ContextUpdateCurrentBreakpoint: Can't get BreakpointInfo.\n");
            return FALSE;
        }

        if (pBreakpointInfo->Register == bp)
        {
            if (bp == 0 && ((DWORD_PTR)pBreakpointInfo->Address == Context->Dr0) && ((DWORD)pBreakpointInfo->Type == ((PDR7)&(Context->Dr7))->RWE0))
            {
                return ContextSetThreadBreakpoint(Context, 0, Size, Address, Type, Callback);
            }

            if (bp == 1 && ((DWORD_PTR)pBreakpointInfo->Address == Context->Dr1) && ((DWORD)pBreakpointInfo->Type == ((PDR7)&(Context->Dr7))->RWE1))
            {
                return ContextSetThreadBreakpoint(Context, 1, Size, Address, Type, Callback);
            }

            if (bp == 2 && ((DWORD_PTR)pBreakpointInfo->Address == Context->Dr2) && ((DWORD)pBreakpointInfo->Type == ((PDR7)&(Context->Dr7))->RWE2))
            {
                return ContextSetThreadBreakpoint(Context, 2, Size, Address, Type, Callback);
            }

            if (bp == 3 && ((DWORD_PTR)pBreakpointInfo->Address == Context->Dr3) && ((DWORD)pBreakpointInfo->Type == ((PDR7)&(Context->Dr7))->RWE3))
            {
                return ContextSetThreadBreakpoint(Context, 3, Size, Address, Type, Callback);
            }
        }
    }

    DoOutputDebugString("ContextUpdateCurrentBreakpoint: Exit function.\n");
    return FALSE;
}

//**************************************************************************************
BOOL ContextClearCurrentBreakpoint
//**************************************************************************************
(
    PCONTEXT	    Context
)
{
	PTHREADBREAKPOINTS CurrentThreadBreakpoint;
    PBREAKPOINTINFO pBreakpointInfo;
    unsigned int bp;

    CurrentThreadBreakpoint = GetThreadBreakpoints(GetCurrentThreadId());

    if (CurrentThreadBreakpoint == NULL)
    {
        DoOutputDebugString("ContextClearCurrentBreakpoint: Error - Failed to acquire thread breakpoints.\n");
        return FALSE;
    }

    for (bp = 0; bp < NUMBER_OF_DEBUG_REGISTERS; bp++)
    {
        if (Context->Dr6 & (DWORD_PTR)(1 << bp))
        {
            pBreakpointInfo = &(CurrentThreadBreakpoint->BreakpointInfo[bp]);

            if (pBreakpointInfo == NULL)
            {
                DoOutputDebugString("ContextClearCurrentBreakpoint: Can't get BreakpointInfo.\n");
                return FALSE;
            }

            if (pBreakpointInfo->Register == bp)
                return ContextClearBreakpoint(Context, pBreakpointInfo);
        }
    }

    return FALSE;
}

//**************************************************************************************
BOOL ContextSetThreadBreakpointsEx(PCONTEXT ThreadContext, PTHREADBREAKPOINTS ThreadBreakpoints, BOOL NoSetThreadContext)
//**************************************************************************************
{
    if (!ThreadContext)
        return FALSE;

    for (unsigned int Register = 0; Register < NUMBER_OF_DEBUG_REGISTERS; Register++)
    {
        if (!ContextSetThreadBreakpointEx
        (
            ThreadContext,
            ThreadBreakpoints->BreakpointInfo[Register].Register,
            ThreadBreakpoints->BreakpointInfo[Register].Size,
            ThreadBreakpoints->BreakpointInfo[Register].Address,
            ThreadBreakpoints->BreakpointInfo[Register].Type,
            ThreadBreakpoints->BreakpointInfo[Register].Callback,
            NoSetThreadContext
        ))
            return FALSE;
    }

    return TRUE;
}

//**************************************************************************************
BOOL ContextSetThreadBreakpoints(PCONTEXT ThreadContext, PTHREADBREAKPOINTS ThreadBreakpoints)
//**************************************************************************************
{
    return ContextSetThreadBreakpointsEx(ThreadContext, ThreadBreakpoints, FALSE);
}

//**************************************************************************************
DWORD WINAPI SetBreakpointThread(LPVOID lpParam)
//**************************************************************************************
{
    DWORD RetVal;

    PBREAKPOINTINFO pBreakpointInfo = (PBREAKPOINTINFO)lpParam;

	if (SuspendThread(pBreakpointInfo->ThreadHandle) == 0xFFFFFFFF)
		DoOutputErrorString("SetBreakpointThread: Call to SuspendThread failed for thread handle 0x%x", pBreakpointInfo->ThreadHandle);

	if (!SetDebugRegister(pBreakpointInfo->ThreadHandle, pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address, pBreakpointInfo->Type))
		DoOutputErrorString("SetBreakpointThread: Call to SetDebugRegister failed for thread handle 0x%x", pBreakpointInfo->ThreadHandle);

    RetVal = ResumeThread(pBreakpointInfo->ThreadHandle);

    if (RetVal == -1)
        DoOutputErrorString("SetBreakpointThread: ResumeThread failed for thread handle 0x%x", pBreakpointInfo->ThreadHandle);
    else if (RetVal == 0)
        DoOutputDebugString("SetBreakpointThread: Error - thread with handle 0x%x was not suspended.\n", pBreakpointInfo->ThreadHandle);
    else if (g_config.debug)
        DoOutputDebugString("SetBreakpointThread: Sample thread with handle 0x%x was suspended, now resumed.\n", pBreakpointInfo->ThreadHandle);

    return 1;
}

//**************************************************************************************
DWORD WINAPI ClearBreakpointThread(LPVOID lpParam)
//**************************************************************************************
{
    DWORD RetVal;
    PBREAKPOINTINFO pBreakpointInfo = (PBREAKPOINTINFO)lpParam;

	if (SuspendThread(pBreakpointInfo->ThreadHandle) == 0xFFFFFFFF)
		DoOutputErrorString("ClearBreakpointThread: Call to SuspendThread failed");

	if (!ClearDebugRegister(pBreakpointInfo->ThreadHandle, pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address, pBreakpointInfo->Type))
	{
		DoOutputDebugString("ClearBreakpointThread: Call to ClearDebugRegister failed.\n");
	}

    RetVal = ResumeThread(pBreakpointInfo->ThreadHandle);
    if (RetVal == -1)
    {
        DoOutputErrorString("ClearBreakpointThread: ResumeThread failed.\n");
    }
    else if (RetVal == 0)
    {
        DoOutputDebugString("ClearBreakpointThread: Error - Sample thread was not suspended.\n");
    }
    else if (g_config.debug)
    {
        DoOutputDebugString("ClearBreakpointThread: Sample thread was suspended, now resumed.\n");
    }

#ifdef DEBUG_COMMENTS
    DebugOutputThreadBreakpoints();
#endif

    return TRUE;
}

//**************************************************************************************
BOOL SetBreakpointWithoutThread
//**************************************************************************************
(
    DWORD	ThreadId,
    int		Register,
    int		Size,
    LPVOID	Address,
    DWORD	Type,
	PVOID	Callback
)
{
	PTHREADBREAKPOINTS CurrentThreadBreakpoint;
	BOOL RetVal;
    PBREAKPOINTINFO pBreakpointInfo = NULL;

    if (Register > 3 || Register < 0)
    {
        DoOutputDebugString("SetBreakpointWithoutThread: Error - register value %d, can only have value 0-3.\n", Register);
        return FALSE;
    }

    CurrentThreadBreakpoint = GetThreadBreakpoints(ThreadId);

	if (CurrentThreadBreakpoint == NULL)
	{
		DoOutputDebugString("SetBreakpointWithoutThread: Creating new thread breakpoints for thread %d.\n", ThreadId);
		CurrentThreadBreakpoint = CreateThreadBreakpoints(ThreadId);
	}

	if (CurrentThreadBreakpoint == NULL)
	{
		DoOutputDebugString("SetBreakpointWithoutThread: Cannot create new thread breakpoints - FATAL.\n");
		return FALSE;
	}

    __try
    {
        pBreakpointInfo = &CurrentThreadBreakpoint->BreakpointInfo[Register];
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DoOutputErrorString("SetBreakpointWithoutThread: Exception getting pBreakpointInfo");
        return FALSE;
    }
    DoOutputErrorString("SetBreakpointWithoutThread: pBreakpointInfo 0x%p", pBreakpointInfo);

	if (CurrentThreadBreakpoint->ThreadHandle == NULL)
	{
		DoOutputDebugString("SetBreakpointWithoutThread: There is no thread handle in the thread breakpoint - Error.\n");
		return FALSE;
	}
#ifdef DEBUG_COMMENTS
    else
		DoOutputDebugString("ClearBreakpoint: About to call SetDebugRegister with thread handle 0x%x, register %d, size 0x%x, address 0x%p type %d.\n", CurrentThreadBreakpoint->ThreadHandle, Register, Size, Address, Type);
#endif


	pBreakpointInfo->ThreadHandle   = CurrentThreadBreakpoint->ThreadHandle;
	pBreakpointInfo->Register       = Register;
	pBreakpointInfo->Size           = Size;
	pBreakpointInfo->Address        = Address;
	pBreakpointInfo->Type	        = Type;
	pBreakpointInfo->Callback       = Callback;

    __try
    {
        RetVal = SetDebugRegister(pBreakpointInfo->ThreadHandle, Register, Size, Address, Type);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DoOutputErrorString("SetBreakpointWithoutThread: Exception calling SetDebugRegister");
        return FALSE;
    }

    // Debug
    DoOutputDebugString("SetBreakpointWithoutThread: bp set with register %d\n", Register);

    return TRUE;
}

//**************************************************************************************
BOOL SetThreadBreakpoint
//**************************************************************************************
(
    DWORD	ThreadId,
    int		Register,
    int		Size,
    LPVOID	Address,
    DWORD	Type,
	PVOID	Callback
)
{
    //if (DisableThreadSuspend)
    //    return SetBreakpointWithoutThread(ThreadId, Register, Size, Address, Type, Callback);

    PBREAKPOINTINFO pBreakpointInfo;
	PTHREADBREAKPOINTS CurrentThreadBreakpoint;
	HANDLE hSetBreakpointThread;
    DWORD SetBreakpointThreadId;
    BOOL RetVal;

    if (!Address)
    {
        DoOutputDebugString("SetThreadBreakpoint: Error - breakpoint address is zero!\n");
        return FALSE;
    }

    if (Register > 3 || Register < 0)
    {
        DoOutputDebugString("SetThreadBreakpoint: Error - register value %d, can only have value 0-3.\n", Register);
        return FALSE;
    }

    CurrentThreadBreakpoint = GetThreadBreakpoints(ThreadId);

	if (CurrentThreadBreakpoint == NULL)
	{
		DoOutputDebugString("SetThreadBreakpoint: Creating new thread breakpoints for thread %d.\n", ThreadId);
		CurrentThreadBreakpoint = CreateThreadBreakpoints(ThreadId);
	}

	if (CurrentThreadBreakpoint == NULL)
	{
		DoOutputDebugString("SetThreadBreakpoint: Cannot create new thread breakpoints - error.\n");
		return FALSE;
	}

	pBreakpointInfo = &CurrentThreadBreakpoint->BreakpointInfo[Register];

	if (CurrentThreadBreakpoint->ThreadHandle == NULL)
	{
		DoOutputDebugString("SetThreadBreakpoint: There is no thread handle in the thread breakpoint - Error.\n");
		return FALSE;
	}

    // Check whether an identical breakpoint already exists
    for (unsigned int i = 0; i < NUMBER_OF_DEBUG_REGISTERS; i++)
    {
        if
        (
            CurrentThreadBreakpoint->ThreadId == ThreadId &&
            CurrentThreadBreakpoint->BreakpointInfo[i].Size == Size &&
            CurrentThreadBreakpoint->BreakpointInfo[i].Address == Address &&
            CurrentThreadBreakpoint->BreakpointInfo[i].Type == Type
        )
        {
            DoOutputDebugString("SetThreadBreakpoint: An identical breakpoint (%d) at 0x%p already exists for thread %d (process %d), skipping.\n", i, Address, ThreadId, GetCurrentProcessId());
            return TRUE;
        }
    }

	pBreakpointInfo->ThreadHandle   = CurrentThreadBreakpoint->ThreadHandle;
	pBreakpointInfo->Register       = Register;
	pBreakpointInfo->Size           = Size;
	pBreakpointInfo->Address        = Address;
	pBreakpointInfo->Type	        = Type;
	pBreakpointInfo->Callback       = Callback;

    __try
    {
        hSetBreakpointThread = CreateThread(NULL, 0, SetBreakpointThread, pBreakpointInfo, 0, &SetBreakpointThreadId);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DoOutputErrorString("SetThreadBreakpoint: An exception was raised creating SetBreakpointThread thread");
    }

	if (!hSetBreakpointThread)
    {
        DoOutputDebugString("SetThreadBreakpoint: Failed to create SetBreakpointThread thread, falling back to SetBreakpointWithoutThread.\n");

        __try
        {
            RetVal = SetBreakpointWithoutThread(ThreadId, Register, Size, Address, Type, Callback);
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            DoOutputErrorString("SetThreadBreakpoint: Error calling SetBreakpointWithoutThread");
            return FALSE;
        }

        return RetVal;
    }

    // We wait for the thread to complete - if this hasn't happened
    // in under a second, we bail and set without creating a thread
    RetVal = WaitForSingleObject(hSetBreakpointThread, 1000);

    if (RetVal != WAIT_OBJECT_0)
    {
        TerminateThread(hSetBreakpointThread, 0);
        DoOutputDebugString("SetThreadBreakpoint: SetBreakpointThread timeout, thread killed.\n");

        RetVal = ResumeThread(CurrentThreadBreakpoint->ThreadHandle);
        if (RetVal == -1)
        {
            DoOutputErrorString("SetThreadBreakpoint: ResumeThread failed. About to set breakpoint without thread.\n");
        }
        else if (RetVal == 0)
        {
            DoOutputDebugString("SetThreadBreakpoint: Sample thread was not suspended. About to set breakpoint without thread.\n");
        }
        else
        {
            DoOutputDebugString("SetThreadBreakpoint: Sample thread was suspended, now resumed. About to set breakpoint without thread.\n");
        }

        return SetBreakpointWithoutThread(ThreadId, Register, Size, Address, Type, Callback);
    }

    DoOutputDebugString("SetThreadBreakpoint: Set bp %d thread id %d type %d at address 0x%p, size %d with Callback 0x%x.\n",
        Register,
        ThreadId,
        Type,
        Address,
        Size,
        Callback
        );

    CloseHandle(hSetBreakpointThread);

    return TRUE;
}

//**************************************************************************************
BOOL SetBreakpoint
//**************************************************************************************
(
    int		Register,
    int		Size,
    LPVOID	Address,
    DWORD	Type,
	PVOID	Callback
)
{
    if (MainThreadBreakpointList == NULL)
    {
		DoOutputDebugString("SetBreakpoint: MainThreadBreakpointList NULL.\n");
		return FALSE;
    }

    PTHREADBREAKPOINTS ThreadBreakpoints = MainThreadBreakpointList;

	while (ThreadBreakpoints)
	{
		DoOutputDebugString("SetBreakpoint: About to call SetThreadBreakpoint for thread %d.\n", ThreadBreakpoints->ThreadId);

        SetThreadBreakpoint(ThreadBreakpoints->ThreadId, Register, Size, Address, Type, Callback);

        ThreadBreakpoints = ThreadBreakpoints->NextThreadBreakpoints;
	}

	return TRUE;
}

//**************************************************************************************
BOOL SetThreadBreakpoints(PTHREADBREAKPOINTS ThreadBreakpoints)
//**************************************************************************************
{
    if (!ThreadBreakpoints->ThreadId)
    {
        DoOutputErrorString("SetThreadBreakpoints: Error - Thread ID missing from ThreadBreakpoints.\n");
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
	PTHREADBREAKPOINTS CurrentThreadBreakpoint;

    if (Register > 3 || Register < 0)
    {
        DoOutputDebugString("ClearThreadBreakpoint: Error - register value %d, can only have value 0-3.\n", Register);
        return FALSE;
    }

    CurrentThreadBreakpoint = GetThreadBreakpoints(ThreadId);

	if (CurrentThreadBreakpoint == NULL)
	{
		DoOutputDebugString("ClearThreadBreakpoint: Creating new thread breakpoints for thread %d.\n", ThreadId);
		CurrentThreadBreakpoint = CreateThreadBreakpoints(ThreadId);
	}

	if (CurrentThreadBreakpoint == NULL)
	{
		DoOutputDebugString("ClearThreadBreakpoint: Cannot create new thread breakpoints - FATAL.\n");
		return FALSE;
	}

	pBreakpointInfo = &CurrentThreadBreakpoint->BreakpointInfo[Register];

	if (CurrentThreadBreakpoint->ThreadHandle == NULL)
	{
		DoOutputDebugString("ClearThreadBreakpoint: There is no thread handle in the thread breakpoint - Error.\n");
		return FALSE;
	}

    if (!ClearDebugRegister(pBreakpointInfo->ThreadHandle, pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address, pBreakpointInfo->Type))
	{
		DoOutputDebugString("ClearThreadBreakpoint: Call to ClearDebugRegister failed.\n");
        return FALSE;
	}

	//pBreakpointInfo->Register = 0;
	pBreakpointInfo->Size = 0;
	pBreakpointInfo->Address = 0;
	pBreakpointInfo->Type	  = 0;
	pBreakpointInfo->Callback = NULL;

    return TRUE;
}

//**************************************************************************************
BOOL ClearBreakpoint(int Register)
//**************************************************************************************
{
    if (MainThreadBreakpointList == NULL)
    {
		DoOutputDebugString("ClearBreakpoint: MainThreadBreakpointList NULL.\n");
		return FALSE;
    }

    PTHREADBREAKPOINTS ThreadBreakpoints = MainThreadBreakpointList;

	while (ThreadBreakpoints)
	{
        if (ThreadBreakpoints->ThreadHandle)
            ThreadBreakpoints->BreakpointInfo[Register].ThreadHandle  = ThreadBreakpoints->ThreadHandle;
        //ThreadBreakpoints->BreakpointInfo[Register].Register      = Register;
        ThreadBreakpoints->BreakpointInfo[Register].Size          = 0;
        ThreadBreakpoints->BreakpointInfo[Register].Address       = NULL;
        ThreadBreakpoints->BreakpointInfo[Register].Type          = 0;
        ThreadBreakpoints->BreakpointInfo[Register].Callback      = NULL;

#ifdef DEBUG_COMMENTS
		DoOutputDebugString("ClearBreakpoint: About to call ClearThreadBreakpoint for thread %d.\n", ThreadBreakpoints->ThreadId);
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
    DWORD	        ThreadId,
    unsigned int*	Register,
    int		        Size,
    LPVOID	        Address,
    DWORD	        Type,
	PVOID	        Callback
)
{
	PTHREADBREAKPOINTS CurrentThreadBreakpoint = GetThreadBreakpoints(ThreadId);

	if (CurrentThreadBreakpoint == NULL)
	{
		DoOutputDebugString("SetNextAvailableBreakpoint: Creating new thread breakpoints for thread %d.\n", ThreadId);
		CurrentThreadBreakpoint = CreateThreadBreakpoints(ThreadId);
	}

	if (CurrentThreadBreakpoint == NULL)
	{
		DoOutputDebugString("SetNextAvailableBreakpoint: Cannot create new thread breakpoints - FATAL.\n");
		return FALSE;
	}

    if (!GetNextAvailableBreakpoint(ThreadId, Register))
    {
        DoOutputDebugString("SetNextAvailableBreakpoint: GetNextAvailableBreakpoint failed (breakpoints possibly full).\n");
        return FALSE;
    }

    return SetThreadBreakpoint(ThreadId, *Register, Size, Address, Type, Callback);
}

//**************************************************************************************
BOOL InitialiseDebugger(void)
//**************************************************************************************
{
    HANDLE MainThreadHandle;

	MainThreadId = GetCurrentThreadId();

	if (DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &MainThreadHandle, 0, FALSE, DUPLICATE_SAME_ACCESS) == 0)
	{
		DoOutputDebugString("InitialiseDebugger: Failed to duplicate thread handle.\n");
		return FALSE;
	}

	MainThreadBreakpointList = CreateThreadBreakpoints(MainThreadId);

    if (MainThreadBreakpointList == NULL)
    {
		DoOutputDebugString("InitialiseDebugger: Failed to create thread breakpoints struct.\n");
		return FALSE;
    }

    if (MainThreadBreakpointList->ThreadHandle == NULL)
    {
		DoOutputDebugString("InitialiseDebugger error: main thread handle not set.\n");
		return FALSE;
    }

    // Initialise global variables
    ChildProcessId = 0;
    SingleStepHandler = NULL;

#ifndef _WIN64
    // Ensure wow64 patch is installed if needed
    WoW64fix();
#endif

    return TRUE;
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

#ifndef _WIN64
//**************************************************************************************
__declspec (naked dllexport) void DebuggerInit(void)
//**************************************************************************************
{
    DWORD StackPointer;

    _asm
        {
        push	ebp
        mov		ebp, esp
        // we need the stack pointer
        mov		StackPointer, esp
        sub		esp, __LOCAL_SIZE
		pushad
        }

	if (!InitialiseDebugger())
        DoOutputDebugString("Debugger initialisation failure!\n");

// Package specific code
// End of package specific code
	DoOutputDebugString("Debugger initialisation complete, about to execute OEP at 0x%p\n", OEP);

    _asm
    {
        popad
		mov     esp, ebp
        pop     ebp
        jmp		OEP
    }
}
#else
#pragma optimize("", off)
//**************************************************************************************
__declspec(dllexport) void DebuggerInit(void)
//**************************************************************************************
{
    DWORD_PTR StackPointer;

    StackPointer = GetNestedStackPointer() - 8; // this offset has been determined experimentally - TODO: tidy

	if (!InitialiseDebugger())
        DoOutputDebugString("Debugger initialisation failure!\n");
	else
        DoOutputDebugString("Debugger initialised, ESP = 0x%x\n", StackPointer);

// Package specific code
// End of package specific code

	DoOutputDebugString("Debugger initialisation complete, about to execute OEP.\n");

    OEP();
}
#pragma optimize("", on)
#endif

BOOL SendDebuggerMessage(PVOID Input)
{
    BOOL fSuccess;
	DWORD cbReplyBytes, cbWritten;

    cbReplyBytes = sizeof(PVOID);

    if (hCapePipe == NULL)
    {
        DoOutputErrorString("SendDebuggerMessage: hCapePipe NULL.");
        return FALSE;
    }

    // Write the reply to the pipe.
    fSuccess = WriteFile
    (
        hCapePipe,        // handle to pipe
        &Input,     		// buffer to write from
        cbReplyBytes, 		// number of bytes to write
        &cbWritten,   		// number of bytes written
        NULL          		// not overlapped I/O
    );

    if (!fSuccess || cbReplyBytes != cbWritten)
    {
        DoOutputErrorString("SendDebuggerMessage: Failed to send message via pipe");
        return FALSE;
    }

    DoOutputDebugString("SendDebuggerMessage: Sent message via pipe: 0x%x\n", Input);

    return TRUE;
}

//**************************************************************************************
BOOL DebugNewProcess(unsigned int ProcessId, unsigned int ThreadId, DWORD CreationFlags)
//**************************************************************************************
{
    HANDLE hProcess, hThread;
	char lpszPipename[MAX_PATH];
    BOOL fSuccess, fConnected;
    CONTEXT Context;
    DWORD cbBytesRead, cbWritten, cbReplyBytes;

    memset(lpszPipename, 0, MAX_PATH*sizeof(CHAR));

    sprintf_s(lpszPipename, MAX_PATH, "\\\\.\\pipe\\CAPEpipe_%x", ProcessId);

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, ProcessId);
    if (hProcess == NULL)
    {
        DoOutputErrorString("DebugNewProcess: OpenProcess failed");
        return FALSE;
    }

    hThread = OpenThread(THREAD_ALL_ACCESS, TRUE, ThreadId);
    if (hThread == NULL)
    {
        DoOutputErrorString("DebugNewProcess: OpenThread failed");
        return FALSE;
    }

    hCapePipe = CreateNamedPipe
    (
        lpszPipename,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE |
        PIPE_READMODE_MESSAGE |
        PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        PIPEBUFSIZE,
        PIPEBUFSIZE,
        0,
        NULL
    );

    if (hCapePipe == INVALID_HANDLE_VALUE)
    {
        DoOutputErrorString("DebugNewProcess: CreateNamedPipe failed");
        return FALSE;
    }

    DoOutputDebugString("DebugNewProcess: Announcing new process to Cuckoo, pid: %d\n", ProcessId);
    pipe("DEBUGGER:%d,%d", ProcessId, ThreadId);

    fConnected = ConnectNamedPipe(hCapePipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
    fSuccess = FALSE;
    cbBytesRead = 0;

    if (!fConnected)
    {
        DoOutputDebugString("DebugNewProcess: The client could not connect, closing pipe.\n");
        CloseHandle(hCapePipe);
        return FALSE;
    }

    DoOutputDebugString("DebugNewProcess: Client connected.\n");

    fSuccess = ReadFile
    (
        hCapePipe,
        &DebuggerEP,
        sizeof(DWORD_PTR),
        &cbBytesRead,
        NULL
    );

    if (!fSuccess || cbBytesRead == 0)
    {
        if (GetLastError() == ERROR_BROKEN_PIPE)
        {
            DoOutputErrorString("DebugNewProcess: Client disconnected.");
        }
        else
        {
            DoOutputErrorString("DebugNewProcess: ReadFile failed.");
        }
    }

    if (!DebuggerEP)
    {
        DoOutputErrorString("DebugNewProcess: Successfully read from pipe, however DebuggerEP = 0.");
        return FALSE;
    }

    Context.ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(hThread, &Context))
    {
        DoOutputDebugString("DebugNewProcess: GetThreadContext failed - FATAL\n");
        return FALSE;
    }

#ifdef _WIN64
    OEP = (PVOID)Context.Rcx;
#else
    OEP = (PVOID)Context.Eax;
#endif

    cbWritten = 0;
    cbReplyBytes = sizeof(DWORD_PTR);

    // Send the OEP to the new process
    fSuccess = WriteFile
    (
        hCapePipe,
        &OEP,
        cbReplyBytes,
        &cbWritten,
        NULL
    );
    if (!fSuccess || cbReplyBytes != cbWritten)
    {
        DoOutputErrorString("DebugNewProcess: Failed to send OEP via pipe.");
        return FALSE;
    }

    DoOutputDebugString("DebugNewProcess: Sent OEP 0x%p via pipe\n", OEP);

    Context.ContextFlags = CONTEXT_ALL;

#ifdef _WIN64
    Context.Rcx = DebuggerEP;		// set the new EP to debugger_init
#else
    Context.Eax = DebuggerEP;
#endif

    if (!SetThreadContext(hThread, &Context))
    {
        DoOutputDebugString("DebugNewProcess: Failed to set new EP\n");
        return FALSE;
    }

#ifdef _WIN64
    DoOutputDebugString("DebugNewProcess: Set new EP to DebuggerInit: 0x%x\n", Context.Rcx);
#else
    DoOutputDebugString("DebugNewProcess: Set new EP to DebuggerInit: 0x%x\n", Context.Eax);
#endif

    CloseHandle(hProcess);
    CloseHandle(hThread);

	return TRUE;
}

//**************************************************************************************
DWORD WINAPI DebuggerLaunch(LPVOID lpParam)
//**************************************************************************************
{
	HANDLE hPipe;
	BOOL   fSuccess = FALSE, NT5;
	DWORD  cbRead, cbToWrite, cbWritten, dwMode;
	PVOID  FuncAddress;

	char lpszPipename[MAX_PATH];
    OSVERSIONINFO VersionInfo;

	DoOutputDebugString("DebuggerLaunch: About to connect to CAPEpipe.\n");

    memset(lpszPipename, 0, MAX_PATH*sizeof(CHAR));

    sprintf_s(lpszPipename, MAX_PATH, "\\\\.\\pipe\\CAPEpipe_%x", GetCurrentProcessId());

    while (1)
	{
		hPipe = CreateFile(
		lpszPipename,
		GENERIC_READ |
		GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

		if (hPipe != INVALID_HANDLE_VALUE)
			break;

		if (GetLastError() != ERROR_PIPE_BUSY)
		{
			DoOutputErrorString("DebuggerLaunch: Could not open pipe");
			return -1;
		}

		if (!WaitNamedPipe(lpszPipename, 20))
		{
			DoOutputDebugString("DebuggerLaunch: Could not open pipe: 20 ms wait timed out.\n");
			return -1;
		}
	}

	// The pipe connected; change to message-read mode.
	dwMode = PIPE_READMODE_MESSAGE;
	fSuccess = SetNamedPipeHandleState
    (
		hPipe,
		&dwMode,
		NULL,
		NULL
	);
	if (!fSuccess)
	{
		DoOutputDebugString("DebuggerLaunch: SetNamedPipeHandleState failed.\n");
		return -1;
	}

	// Send VA of DebuggerInit to loader
	FuncAddress = &DebuggerInit;

	cbToWrite = sizeof(PVOID);

	fSuccess = WriteFile
    (
		hPipe,
		&FuncAddress,
		cbToWrite,
		&cbWritten,
		NULL
    );
	if (!fSuccess)
	{
		DoOutputErrorString("DebuggerLaunch: WriteFile to pipe failed");
		return -1;
	}

	DoOutputDebugString("DebuggerLaunch: DebuggerInit VA sent to loader: 0x%x\n", FuncAddress);

	fSuccess = ReadFile(
		hPipe,
		&OEP,
		sizeof(DWORD_PTR),
		&cbRead,
		NULL);

	if (!fSuccess && GetLastError() == ERROR_MORE_DATA)
	{
		DoOutputDebugString("DebuggerLaunch: ReadFile on Pipe: ERROR_MORE_DATA\n");
		CloseHandle(hPipe);
		return -1;
	}

	if (!fSuccess)
	{
		DoOutputErrorString("DebuggerLaunch: ReadFile (OEP) from pipe failed");
		CloseHandle(hPipe);
		return -1;
	}

	DoOutputDebugString("DebuggerLaunch: Read OEP from pipe: 0x%p\n", OEP);

    while (1)
    {
        fSuccess = ReadFile(
            hPipe,
            &OEP,
            sizeof(DWORD_PTR),
            &cbRead,
            NULL);

        if (!fSuccess && GetLastError() == ERROR_BROKEN_PIPE)
        {
            DoOutputDebugString("DebuggerLaunch: Pipe closed, no further updates to OEP\n");
            CloseHandle(hPipe);
            break;
        }

        if (!fSuccess && GetLastError() == ERROR_MORE_DATA)
        {
            DoOutputDebugString("DebuggerLaunch: ReadFile on Pipe: ERROR_MORE_DATA\n");
            CloseHandle(hPipe);
            return -1;
        }

        if (!fSuccess)
        {
            DoOutputErrorString("DebuggerLaunch: ReadFile from pipe failed");
            CloseHandle(hPipe);
            return -1;
        }
        else
            DoOutputDebugString("DebuggerLaunch: Read updated EP from pipe: 0x%p\n", OEP);
    }

    ZeroMemory(&VersionInfo, sizeof(OSVERSIONINFO));
    VersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&VersionInfo);

    NT5 = (VersionInfo.dwMajorVersion == 5);

    if (NT5)
    {
       	DoOutputDebugString("NT5: Leaving debugger thread alive.\n");
        while (1)
        {
            Sleep(500000);
        }
    }

    DoOutputDebugString("NT6+: Terminating debugger thread.\n");

	return 0;
}

//**************************************************************************************
int launch_debugger()
//**************************************************************************************
{
    if (DEBUGGER_LAUNCHER)
    {
        DWORD NewThreadId;
        HANDLE hDebuggerLaunch;

        hDebuggerLaunch = CreateThread(
            NULL,
            0,
            DebuggerLaunch,
            NULL,
            0,
            &NewThreadId);

        if (hDebuggerLaunch == NULL)
        {
           DoOutputDebugString("CAPE: Failed to create debugger launch thread.\n");
           return 0;
        }

        DoOutputDebugString("CAPE: Launching debugger.\n");

        CloseHandle(hDebuggerLaunch);

        return 1;
    }
    else
    {
        DebuggerInitialised = InitialiseDebugger();

        return DebuggerInitialised;
    }
}

void NtContinueHandler(PCONTEXT ThreadContext)
{
    if (BreakpointsSet && !ThreadContext->Dr0 && !ThreadContext->Dr1 && !ThreadContext->Dr2 && !ThreadContext->Dr3)
    {
        DWORD ThreadId = GetCurrentThreadId();
        if (ThreadId == MainThreadId)
        {
            PTHREADBREAKPOINTS ThreadBreakpoints = GetThreadBreakpoints(ThreadId);
            if (ThreadBreakpoints) {
                DoOutputDebugString("NtContinue hook: restoring breakpoints for thread %d.\n", ThreadId);
                ContextSetThreadBreakpointsEx(ThreadContext, ThreadBreakpoints, TRUE);
            }
        }
    }
}