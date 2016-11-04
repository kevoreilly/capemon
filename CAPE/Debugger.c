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
#ifndef _WIN64
#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <assert.h>
#include <Aclapi.h>
#include "Debugger.h"
#include "..\config.h"
#include "..\pipe.h"

#define PIPEBUFSIZE 512

// eflags register
#define FL_TF           0x00000100      // Trap flag
#define FL_RF           0x00010000      // Resume flag

#ifdef STANDALONE
extern BOOL SetNtAllocateVirtualMemoryBP(void);
#endif
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
    DWORD Pad3 : 1;
    DWORD RWE0 : 2;    //Read/Write/Execute bp0
    DWORD LEN0 : 2;    //Length bp0
    DWORD RWE1 : 2;    //Read/Write/Execute bp1
    DWORD LEN1 : 2;    //Length bp1
    DWORD RWE2 : 2;    //Read/Write/Execute bp2
    DWORD LEN2 : 2;    //Length bp2
    DWORD RWE3 : 2;    //Read/Write/Execute bp3
    DWORD LEN3 : 2;    //Length bp3
} DR7, *PDR7;

#define NUMBER_OF_DEBUG_REGISTERS       4
#define MAX_DEBUG_REGISTER_DATA_SIZE    4
#define DEBUG_REGISTER_DATA_SIZES       {1, 2, 4}
#define DEBUG_REGISTER_LENGTH_MASKS     {0xFFFFFFFF, 0, 1, 0xFFFFFFFF, 3}

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
LPTOP_LEVEL_EXCEPTION_FILTER OriginalExceptionHandler;
LONG WINAPI CAPEExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo);
SINGLE_STEP_HANDLER SingleStepHandler;
DWORD WINAPI PipeThread(LPVOID lpParam);
DWORD RemoteFuncAddress;
HANDLE hParentPipe;

extern BOOL StackWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo);
extern unsigned int address_is_in_stack(DWORD Address);
extern BOOL WoW64fix(void);
extern BOOL WoW64PatchBreakpoint(unsigned int Register);
extern BOOL WoW64UnpatchBreakpoint(unsigned int Register);
extern DWORD MyGetThreadId(HANDLE hThread);

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);

LPTOP_LEVEL_EXCEPTION_FILTER OriginalExceptionHandler;

PVOID OEP;

void DebugOutputThreadBreakpoints();
BOOL RestoreExecutionBreakpoint(PCONTEXT Context);
BOOL SetSingleStepMode(PCONTEXT Context, PVOID Handler);
BOOL ClearSingleStepMode(PCONTEXT Context);

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
            for (i=0; i<4; i++)
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
		DoOutputDebugString("ContextGetNextAvailableBreakpoint: Creating new thread breakpoints for thread 0x%x.\n", GetCurrentThreadId());
		CurrentThreadBreakpoint = CreateThreadBreakpoints(GetCurrentThreadId());
	}
	
	if (CurrentThreadBreakpoint == NULL)
	{
		DoOutputDebugString("ContextGetNextAvailableBreakpoint: Cannot create new thread breakpoints - FATAL.\n");
		return FALSE;
	}
    
    for (i=0; i<4; i++)
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
            DoOutputDebugString("CAPEExceptionFilter: Can't get BreakpointInfo - FATAL.\n");
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
void ShowStack(DWORD StackPointer, unsigned int NumberOfRecords)
//**************************************************************************************
{
    unsigned int i;
    
    for (i=0; i<NumberOfRecords; i++)
        DoOutputDebugString("0x%x ([esp+0x%x]): 0x%x\n", StackPointer+4*i, (4*i), *(DWORD*)((BYTE*)StackPointer+4*i));
}

//**************************************************************************************
LONG WINAPI CAPEExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	BREAKPOINT_HANDLER Handler;
	unsigned int bp;
	
    // Hardware breakpoints generate EXCEPTION_SINGLE_STEP rather than EXCEPTION_BREAKPOINT
    if (ExceptionInfo->ExceptionRecord->ExceptionCode==EXCEPTION_SINGLE_STEP)
    {    
		BOOL BreakpointFlag;
        PBREAKPOINTINFO pBreakpointInfo;
		PTHREADBREAKPOINTS CurrentThreadBreakpoint;
		
        // Test Dr6 to see if this is a breakpoint
        BreakpointFlag = FALSE;
        for (bp = 0; bp < NUMBER_OF_DEBUG_REGISTERS; bp++)
		{
			if (ExceptionInfo->ContextRecord->Dr6 & (1 << bp))
			{
                BreakpointFlag = TRUE;
            }
        }
        
        // If not it's a single-step
        if (BreakpointFlag == FALSE)
        {            
            SingleStepHandler(ExceptionInfo);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        
        DoOutputDebugString("Entering CAPEExceptionFilter: breakpoint hit: 0x%x\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);
		
		CurrentThreadBreakpoint = GetThreadBreakpoints(GetCurrentThreadId());

		if (CurrentThreadBreakpoint == NULL)
		{
			DoOutputDebugString("CAPEExceptionFilter: Can't get thread breakpoints - FATAL.\n");
			return EXCEPTION_CONTINUE_SEARCH;
		}
        
        for (bp = 0; bp < NUMBER_OF_DEBUG_REGISTERS; bp++)
		{
			if (ExceptionInfo->ContextRecord->Dr6 & (1 << bp))
			{
				pBreakpointInfo = &(CurrentThreadBreakpoint->BreakpointInfo[bp]);
                
                if (pBreakpointInfo == NULL)
                {
                    DoOutputDebugString("CAPEExceptionFilter: Can't get BreakpointInfo - FATAL.\n");
                    return EXCEPTION_CONTINUE_EXECUTION;
                }                
                
                if (pBreakpointInfo->Register == bp) 
                {
                    if (bp == 0 && ((DWORD)pBreakpointInfo->Address != ExceptionInfo->ContextRecord->Dr0))
                        DoOutputDebugString("CAPEExceptionFilter: Anomaly detected! bp0 address (0x%x) different to BreakpointInfo (0x%x)!\n", ExceptionInfo->ContextRecord->Dr0, pBreakpointInfo->Address);
                        
                    if (bp == 1 && ((DWORD)pBreakpointInfo->Address != ExceptionInfo->ContextRecord->Dr1))
                        DoOutputDebugString("CAPEExceptionFilter: Anomaly detected! bp1 address (0x%x) different to BreakpointInfo (0x%x)!\n", ExceptionInfo->ContextRecord->Dr1, pBreakpointInfo->Address);

                    if (bp == 2 && ((DWORD)pBreakpointInfo->Address != ExceptionInfo->ContextRecord->Dr2))
                        DoOutputDebugString("CAPEExceptionFilter: Anomaly detected! bp2 address (0x%x) different to BreakpointInfo (0x%x)!\n", ExceptionInfo->ContextRecord->Dr2, pBreakpointInfo->Address);
                    
                    if (bp == 3 && ((DWORD)pBreakpointInfo->Address != ExceptionInfo->ContextRecord->Dr3))
                        DoOutputDebugString("CAPEExceptionFilter: Anomaly detected! bp3 address (0x%x) different to BreakpointInfo (0x%x)!\n", ExceptionInfo->ContextRecord->Dr3, pBreakpointInfo->Address);

                    if (bp == 0 && ((DWORD)pBreakpointInfo->Type != ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE0))
                    {
                        if (pBreakpointInfo->Type == BP_READWRITE && ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE0 == BP_WRITE && address_is_in_stack((DWORD)pBreakpointInfo->Address))
                        {
                            DoOutputDebugString("CAPEExceptionFilter: Reinstated BP_READWRITE on breakpoint %d (WoW64 workaround)\n", pBreakpointInfo->Register);
                            
                            ContextSetHardwareBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo->Register, pBreakpointInfo->Size, (BYTE*)pBreakpointInfo->Address, pBreakpointInfo->Type, pBreakpointInfo->Callback);
                        }
                        else
                        {
                            DoOutputDebugString("CAPEExceptionFilter: Anomaly detected! bp0 type (0x%x) different to BreakpointInfo (0x%x)!\n", ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE0, pBreakpointInfo->Type);
                            CheckDebugRegisters(0, ExceptionInfo->ContextRecord);
                        }
                    }
                    if (bp == 1 && ((DWORD)pBreakpointInfo->Type != ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE1))
                    {
                        if (pBreakpointInfo->Type == BP_READWRITE && ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE1 == BP_WRITE && address_is_in_stack((DWORD)pBreakpointInfo->Address))
                        {
                            DoOutputDebugString("CAPEExceptionFilter: Reinstated BP_READWRITE on breakpoint %d (WoW64 workaround)\n", pBreakpointInfo->Register);
                            
                            ContextSetHardwareBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo->Register, pBreakpointInfo->Size, (BYTE*)pBreakpointInfo->Address, pBreakpointInfo->Type, pBreakpointInfo->Callback);
                        }
                        else
                        {
                            DoOutputDebugString("CAPEExceptionFilter: Anomaly detected! bp1 type (0x%x) different to BreakpointInfo (0x%x)!\n", ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE1, pBreakpointInfo->Type);
                            CheckDebugRegisters(0, ExceptionInfo->ContextRecord);
                        }
                    }
                    if (bp == 2 && ((DWORD)pBreakpointInfo->Type != ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE2))
                    {
                        if (pBreakpointInfo->Type == BP_READWRITE && ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE2 == BP_WRITE && address_is_in_stack((DWORD)pBreakpointInfo->Address))
                        {
                            DoOutputDebugString("CAPEExceptionFilter: Reinstated BP_READWRITE on stack breakpoint %d (WoW64 workaround)\n", pBreakpointInfo->Register);
                            
                            ContextSetHardwareBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo->Register, pBreakpointInfo->Size, (BYTE*)pBreakpointInfo->Address, pBreakpointInfo->Type, pBreakpointInfo->Callback);
                        }
                        else
                        {
                            DoOutputDebugString("CAPEExceptionFilter: Anomaly detected! bp2 type (0x%x) different to BreakpointInfo (0x%x)!\n", ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE2, pBreakpointInfo->Type);
                            CheckDebugRegisters(0, ExceptionInfo->ContextRecord);
                        }
                    }
                    if (bp == 3 && ((DWORD)pBreakpointInfo->Type != ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE3))
                    {
                        if (pBreakpointInfo->Type == BP_READWRITE && ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE3 == BP_WRITE && address_is_in_stack((DWORD)pBreakpointInfo->Address))
                        {
                            DoOutputDebugString("CAPEExceptionFilter: Reinstated BP_READWRITE on breakpoint %d (WoW64 workaround)\n", pBreakpointInfo->Register);
                            
                            ContextSetHardwareBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo->Register, pBreakpointInfo->Size, (BYTE*)pBreakpointInfo->Address, pBreakpointInfo->Type, pBreakpointInfo->Callback);
                        }
                        else
                        {
                            DoOutputDebugString("CAPEExceptionFilter: Anomaly detected! bp3 type (0x%x) different to BreakpointInfo (0x%x)!\n", ((PDR7)&(ExceptionInfo->ContextRecord->Dr7))->RWE3, pBreakpointInfo->Type);
                            CheckDebugRegisters(0, ExceptionInfo->ContextRecord);
                        }
                    }
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

    // Some other exception occurred. Pass it to next handler
    return EXCEPTION_CONTINUE_SEARCH;
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
	DWORD	Length;

    PDWORD  Dr0 = &(Context->Dr0);
    PDWORD  Dr1 = &(Context->Dr1);
    PDWORD  Dr2 = &(Context->Dr2);
    PDWORD  Dr3 = &(Context->Dr3);
    PDR7    Dr7 = (PDR7)&(Context->Dr7);

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

	DoOutputDebugString("Setting breakpoint %i within Context, Size=0x%x, Address=0x%x and Type=0x%x.\n", Register, Size, Address, Type);
	
    Length  = LengthMask[Size];

    // intel spec requires 0 for bp on execution
    if (Type == BP_EXEC)
        Length = 0;

    if (Type == BP_READWRITE && address_is_in_stack((DWORD)Address))
        WoW64PatchBreakpoint(Register);
    
    if (Register == 0)
    {
        *Dr0 = (DWORD)Address;
        Dr7->LEN0 = Length;
        Dr7->RWE0 = Type;
        Dr7->L0 = 1;    
    }
    else if (Register == 1)
    {
        *Dr1 = (DWORD)Address;
        Dr7->LEN1 = Length;
        Dr7->RWE1 = Type;
        Dr7->L1 = 1;    
    }
    else if (Register == 2)
    {
        *Dr2 = (DWORD)Address;
        Dr7->LEN2 = Length;
        Dr7->RWE2 = Type;
        Dr7->L2 = 1;    
    }
    else if (Register == 3)
    {
        *Dr3 = (DWORD)Address;
        Dr7->LEN3 = Length;
        Dr7->RWE3 = Type;
        Dr7->L3 = 1;    
    }
    
    Dr7->LE = 1;
    Context->Dr6 = 0;

	return TRUE;
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

    PDWORD  Dr0 = &Context.Dr0;
    PDWORD  Dr1 = &Context.Dr1;
    PDWORD  Dr2 = &Context.Dr2;
    PDWORD  Dr3 = &Context.Dr3;
    PDR7    Dr7 = (PDR7)&(Context.Dr7);

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

	DoOutputDebugString("Setting breakpoint %i hThread=0x%x, Size=0x%x, Address=0x%x and Type=0x%x.\n", Register, hThread, Size, Address, Type);
	
    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (!GetThreadContext(hThread, &Context))
    {
        return FALSE;
    }

    Length  = LengthMask[Size];

    // intel spec requires 0 for bp on execution
    if (Type == BP_EXEC)
        Length = 0;

    if (Type == BP_READWRITE && address_is_in_stack((DWORD)Address))
        WoW64PatchBreakpoint(Register);
    
    if (Register == 0)
    {
        *Dr0 = (DWORD)Address;
        Dr7->LEN0 = Length;
        Dr7->RWE0 = Type;
        Dr7->L0 = 1;    
    }
    else if (Register == 1)
    {
        *Dr1 = (DWORD)Address;
        Dr7->LEN1 = Length;
        Dr7->RWE1 = Type;
        Dr7->L1 = 1;    
    }
    else if (Register == 2)
    {
        *Dr2 = (DWORD)Address;
        Dr7->LEN2 = Length;
        Dr7->RWE2 = Type;
        Dr7->L2 = 1;    
    }
    else if (Register == 3)
    {
        *Dr3 = (DWORD)Address;
        Dr7->LEN3 = Length;
        Dr7->RWE3 = Type;
        Dr7->L3 = 1;    
    }
    
    Dr7->LE = 1;
    Context.Dr6 = 0;

    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!SetThreadContext(hThread, &Context))
		return FALSE;

	return TRUE;
}

//**************************************************************************************
BOOL ContextCheckDebugRegisters(PCONTEXT Context)
//**************************************************************************************
{   
    PDR7 Dr7;
    
    if (!Context)
    {
        DoOutputDebugString("CheckDebugRegisters - no arguments supplied.\n");
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
    PDWORD  Dr0 = &Context.Dr0;
    PDWORD  Dr1 = &Context.Dr1;
    PDWORD  Dr2 = &Context.Dr2;
    PDWORD  Dr3 = &Context.Dr3;
    PDR7    Dr7 = (PDR7)&(Context.Dr7);
    
    if (!hThread && !pContext)
    {
        DoOutputDebugString("CheckDebugRegisters - no arguments supplied.\n");
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
		DoOutputDebugString("ContextClearAllBreakpoints: No breakpoints found for current thread 0x%x.\n", GetCurrentThreadId());
		return FALSE;
	}
    
    for (i=0; i<4; i++)
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
	    
    return TRUE;
}

//**************************************************************************************
BOOL ClearAllBreakpoints(HANDLE hThread)
//**************************************************************************************
{
    CONTEXT	Context;
	unsigned int i; 
	PTHREADBREAKPOINTS CurrentThreadBreakpoint;    
    
    CurrentThreadBreakpoint = GetThreadBreakpoints(GetCurrentThreadId());
 
	if (CurrentThreadBreakpoint == NULL)
	{
		DoOutputDebugString("ContextClearAllBreakpoints: No breakpoints found for current thread %d.\n", GetCurrentThreadId());
		return FALSE;
	}
    
    if (hThread == NULL)
    {
        for (i=0; i<4; i++)
        {
            if (CurrentThreadBreakpoint->BreakpointInfo[i].ThreadHandle)
                hThread = CurrentThreadBreakpoint->BreakpointInfo[i].ThreadHandle;
        }
    }
    
    if (hThread == NULL)
    {
		DoOutputDebugString("ContextClearAllBreakpoints: No thread handle supplied, and none found in thread breakpoints (thread 0x%x).\n", GetCurrentThreadId());
		return FALSE;
    }
    
    for (i=0; i<4; i++)
    {
        CurrentThreadBreakpoint->BreakpointInfo[i].Register = 0;
        CurrentThreadBreakpoint->BreakpointInfo[i].Size = 0;
        CurrentThreadBreakpoint->BreakpointInfo[i].Address = NULL;
        CurrentThreadBreakpoint->BreakpointInfo[i].Type = 0;
        CurrentThreadBreakpoint->BreakpointInfo[i].Callback = NULL;
    }
    
    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(hThread, &Context))
		return FALSE;

    Context.Dr0 = 0;
    Context.Dr1 = 0;
	Context.Dr2 = 0;
    Context.Dr3 = 0;
	Context.Dr6 = 0;
	Context.Dr7 = 0;
	
	if (!SetThreadContext(hThread, &Context))
		return FALSE;
 
	return TRUE;
}

//**************************************************************************************
BOOL ContextClearHardwareBreakpoint(PCONTEXT Context, PBREAKPOINTINFO pBreakpointInfo)
//**************************************************************************************
{
    PDWORD Dr0, Dr1, Dr2, Dr3;
	PDR7 Dr7;

	if (Context == NULL)
        return FALSE;
        
    Dr0 = &(Context->Dr0);
    Dr1 = &(Context->Dr1);
    Dr2 = &(Context->Dr2);
    Dr3 = &(Context->Dr3);
    Dr7 = (PDR7)&(Context->Dr7);
    
	DoOutputDebugString("Clearing Context breakpoint %i\n", pBreakpointInfo->Register);
	
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

    if (pBreakpointInfo->Type == BP_READWRITE && address_is_in_stack((DWORD)pBreakpointInfo->Address))
        WoW64UnpatchBreakpoint(pBreakpointInfo->Register);
    
    Context->Dr6 = 0;
	
	pBreakpointInfo->Address = 0;
	pBreakpointInfo->Size = 0;
	pBreakpointInfo->Callback = 0;
	pBreakpointInfo->Type = 0;

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
BOOL SetSingleStepMode(PCONTEXT Context, PVOID Handler)
//**************************************************************************************
{
	if (Context == NULL)
        return FALSE;
    
    // set the trap flag
    Context->EFlags |= FL_TF;
    
    SingleStepHandler = (SINGLE_STEP_HANDLER)Handler;

    return TRUE;
}

//**************************************************************************************
BOOL ClearSingleStepMode(PCONTEXT Context)
//**************************************************************************************
{
	if (Context == NULL)
        return FALSE;

    // Clear the trap flag
    Context->EFlags &= ~FL_TF;

    SingleStepHandler = NULL;
    
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
)
{
    CONTEXT	Context;
    BOOL DoCloseHandle = FALSE;
    PDWORD  Dr0 = &Context.Dr0;
    PDWORD  Dr1 = &Context.Dr1;
    PDWORD  Dr2 = &Context.Dr2;
    PDWORD  Dr3 = &Context.Dr3;
    PDR7    Dr7 = (PDR7)&(Context.Dr7);
    
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

	DoOutputDebugString("Clearing breakpoint %i\n", Register);
	
    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
	if (!GetThreadContext(hThread, &Context))
    {
        DoOutputDebugString("ClearDebugRegister: Initial GetThreadContext failed");
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

    if (Type == BP_READWRITE && address_is_in_stack((DWORD)Address))
        WoW64UnpatchBreakpoint(Register);
    
    Context.Dr6 = 0;

    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	
    if (!SetThreadContext(hThread, &Context))
    {
        DoOutputDebugString("ClearDebugRegister: SetThreadContext failed");
        return FALSE;
    }	
        
    if (DoCloseHandle == TRUE)
        CloseHandle(hThread);    
    
    return TRUE;
}

//**************************************************************************************
int ContextCheckDebugRegister(CONTEXT	Context, int Register)
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
        DoOutputDebugString("CheckDebugRegister: GetThreadContext failed - FATAL\n");
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
BOOL ContextSetHardwareBreakpoint
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
	PTHREADBREAKPOINTS CurrentThreadBreakpoint;
    
    if (Register > 3 || Register < 0)
    {
        DoOutputDebugString("ContextSetHardwareBreakpoint: Error - register value %d, can only have value 0-3.\n", Register);
        return FALSE;
    }
    
    if (ContextSetDebugRegister(Context, Register, Size, Address, Type) == FALSE)
	{
		DoOutputDebugString("Call to ContextSetDebugRegister failed.\n");
	}
	else
	{
		DoOutputDebugString("Call to ContextSetDebugRegister succeeded.\n");
          
        CurrentThreadBreakpoint = GetThreadBreakpoints(GetCurrentThreadId());
        
        if (CurrentThreadBreakpoint == NULL)
        {
            DoOutputDebugString("Error: Failed to acquire thread breakpoints.\n");
            return FALSE;
        }
        
		CurrentThreadBreakpoint->BreakpointInfo[Register].Callback = Callback;
		CurrentThreadBreakpoint->BreakpointInfo[Register].Address = Address;
		CurrentThreadBreakpoint->BreakpointInfo[Register].Size = Size;
		CurrentThreadBreakpoint->BreakpointInfo[Register].Type = Type;
	}

    return TRUE;
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
    if (ContextGetNextAvailableBreakpoint(Context, Register) == FALSE)
    {
        DoOutputDebugString("ContextSetNextAvailableBreakpoint: ContextGetNextAvailableBreakpoint failed\n");
        return FALSE;
    }

    return ContextSetHardwareBreakpoint(Context, *Register, Size, Address, Type, Callback);
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
        if (Context->Dr6 & (1 << bp))
        {
            pBreakpointInfo = &(CurrentThreadBreakpoint->BreakpointInfo[bp]);
            
            if (pBreakpointInfo == NULL)
            {
                DoOutputDebugString("ContextUpdateCurrentBreakpoint: Can't get BreakpointInfo.\n");
                return FALSE;
            }                
            
            if (pBreakpointInfo->Register == bp) 
            {
                if (bp == 0 && ((DWORD)pBreakpointInfo->Address == Context->Dr0) && ((DWORD)pBreakpointInfo->Type == ((PDR7)&(Context->Dr7))->RWE0))
                {
                    return ContextSetHardwareBreakpoint(Context, 0, Size, Address, Type, Callback); 
                }                    

                if (bp == 1 && ((DWORD)pBreakpointInfo->Address == Context->Dr1) && ((DWORD)pBreakpointInfo->Type == ((PDR7)&(Context->Dr7))->RWE1))
                {
                    return ContextSetHardwareBreakpoint(Context, 1, Size, Address, Type, Callback); 
                }                    

                if (bp == 2 && ((DWORD)pBreakpointInfo->Address == Context->Dr2) && ((DWORD)pBreakpointInfo->Type == ((PDR7)&(Context->Dr7))->RWE2))
                {
                    return ContextSetHardwareBreakpoint(Context, 2, Size, Address, Type, Callback); 
                }                    

                if (bp == 3 && ((DWORD)pBreakpointInfo->Address == Context->Dr3) && ((DWORD)pBreakpointInfo->Type == ((PDR7)&(Context->Dr7))->RWE3))
                {
                    return ContextSetHardwareBreakpoint(Context, 3, Size, Address, Type, Callback); 
                }                    
            }
        }
    }
    
    return FALSE;
}

//**************************************************************************************
DWORD WINAPI SetBreakpointThread(LPVOID lpParam) 
//**************************************************************************************
{ 
    PBREAKPOINTINFO pBreakpointInfo = (PBREAKPOINTINFO)lpParam;
	 
	if (SuspendThread(pBreakpointInfo->ThreadHandle) == 0xFFFFFFFF)
		DoOutputErrorString("SetBreakpointThread: Call to SuspendThread failed");
    
	if (SetDebugRegister(pBreakpointInfo->ThreadHandle, pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address, pBreakpointInfo->Type) == FALSE)
	{
		DoOutputErrorString("Call to SetDebugRegister failed");
	}

	ResumeThread(pBreakpointInfo->ThreadHandle);

    return 1; 
} 

//**************************************************************************************
DWORD WINAPI ClearBreakpointThread(LPVOID lpParam) 
//**************************************************************************************
{ 
    PBREAKPOINTINFO pBreakpointInfo = (PBREAKPOINTINFO)lpParam;
	
	DoOutputDebugString("Inside ClearBreakpointThread.\n");

	if (SuspendThread(pBreakpointInfo->ThreadHandle) == 0xFFFFFFFF)
		DoOutputErrorString("ClearBreakpointThread: Call to SuspendThread failed");
	else
       DoOutputDebugString("ClearBreakpointThread: Current thread suspended.\n");
	
	if (ClearDebugRegister(pBreakpointInfo->ThreadHandle, pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address, pBreakpointInfo->Type) == FALSE)
	{
		DoOutputDebugString("ClearBreakpointThread: Call to ClearDebugRegister failed.\n");
	}

    DoOutputDebugString("ClearBreakpointThread: Breakpoint cleared, about to resume thread.\n");
	
	ResumeThread(pBreakpointInfo->ThreadHandle);

    return TRUE; 
}

//**************************************************************************************
BOOL SetHardwareBreakpointWithoutThread
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
    PBREAKPOINTINFO pBreakpointInfo;
	PTHREADBREAKPOINTS CurrentThreadBreakpoint;
    
    if (Register > 3 || Register < 0)
    {
        DoOutputDebugString("SetHardwareBreakpointWithoutThread: Error - register value %d, can only have value 0-3.\n", Register);
        return FALSE;
    }  
	
    CurrentThreadBreakpoint = GetThreadBreakpoints(ThreadId);

	if (CurrentThreadBreakpoint == NULL)
	{
		DoOutputDebugString("Creating new thread breakpoints for thread 0x%x.\n", ThreadId);
		CurrentThreadBreakpoint = CreateThreadBreakpoints(ThreadId);
	}
	
	if (CurrentThreadBreakpoint == NULL)
	{
		DoOutputDebugString("Cannot create new thread breakpoints - FATAL.\n");
		return FALSE;
	}

	pBreakpointInfo = &CurrentThreadBreakpoint->BreakpointInfo[Register];
	
	if (CurrentThreadBreakpoint->ThreadHandle == NULL)
	{
		DoOutputDebugString("SetHardwareBreakpointWithoutThread: There is no thread handle in the threadbreakpoint!! FATAL ERROR.\n");
		return FALSE;
	}
    	
	pBreakpointInfo->ThreadHandle = CurrentThreadBreakpoint->ThreadHandle;
	pBreakpointInfo->Register = Register;
	pBreakpointInfo->Size = Size;
	pBreakpointInfo->Address = Address;
	pBreakpointInfo->Type	  = Type;
	pBreakpointInfo->Callback = Callback;
	
	if (SetDebugRegister
	(
		pBreakpointInfo->ThreadHandle,
		pBreakpointInfo->Register,
		pBreakpointInfo->Size,
		pBreakpointInfo->Address,
		pBreakpointInfo->Type
	) == FALSE)
	{
		DoOutputDebugString("SetHardwareBreakpointWithoutThread: Call to SetDebugRegister failed.\n");
	}
	else
	{
		DoOutputDebugString("SetHardwareBreakpointWithoutThread: Call to SetDebugRegister succeeded.\n");
	}
	
    return 1; 
}

//**************************************************************************************
BOOL SetHardwareBreakpoint
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
    PBREAKPOINTINFO pBreakpointInfo;
	PTHREADBREAKPOINTS CurrentThreadBreakpoint;
	HANDLE hSetBreakpointThread;
    
    if (Register > 3 || Register < 0)
    {
        DoOutputDebugString("SetHardwareBreakpoint: Error - register value %d, can only have value 0-3.\n", Register);
        return FALSE;
    }  
	
    CurrentThreadBreakpoint = GetThreadBreakpoints(ThreadId);

	if (CurrentThreadBreakpoint == NULL)
	{
		DoOutputDebugString("Creating new thread breakpoints for thread 0x%x.\n", ThreadId);
		CurrentThreadBreakpoint = CreateThreadBreakpoints(ThreadId);
	}
	
	if (CurrentThreadBreakpoint == NULL)
	{
		DoOutputDebugString("Cannot create new thread breakpoints - FATAL.\n");
		return FALSE;
	}

	pBreakpointInfo = &CurrentThreadBreakpoint->BreakpointInfo[Register];
	
	if (CurrentThreadBreakpoint->ThreadHandle == NULL)
	{
		DoOutputDebugString("SetHardwareBreakpoint: There is no thread handle in the threadbreakpoint!! FATAL ERROR.\n");
		return FALSE;
	}
    	
	pBreakpointInfo->ThreadHandle = CurrentThreadBreakpoint->ThreadHandle;
	pBreakpointInfo->Register = Register;
	pBreakpointInfo->Size = Size;
	pBreakpointInfo->Address = Address;
	pBreakpointInfo->Type	  = Type;
	pBreakpointInfo->Callback = Callback;
    	
    OriginalExceptionHandler = SetUnhandledExceptionFilter(CAPEExceptionFilter);
    //AddVectoredContinueHandler(1, CAPEExceptionFilter);
	
    hSetBreakpointThread = CreateThread( 
		NULL,               
		0,                  
		SetBreakpointThread,
		pBreakpointInfo,    
		0,                  
		&ThreadId);          

	if (hSetBreakpointThread == NULL) 
	{
        if (GetLastError() == ERROR_BAD_EXE_FORMAT)
        {
            // There is a chance the sample has zeroed the PE header
            // of the main process, causing CreateThread to fail.
            // We thus try setting the breakpoint without suspending
            // the target thread as a last resort.
            DoOutputDebugString("SetHardwareBreakpoint: Error creating SetBreakpointThread, attempting to set breakpoint without thread.\n");
            return SetHardwareBreakpointWithoutThread(ThreadId, Register, Size, Address, Type, Callback);
        }
        
        DoOutputErrorString("Failed to create SetBreakpointThread thread");
        return 0;
	}
    
    // Wait until thread has terminated
    WaitForSingleObject(hSetBreakpointThread, INFINITE);

	CloseHandle(hSetBreakpointThread);
	
    DoOutputDebugString("SetHardwareBreakpoint: Callback = 0x%x, Address = 0x%x, Size = 0x%x, Register = %i, ThreadHandle = 0x%x, Type = 0x%x\n", 
        pBreakpointInfo->Callback, 
        pBreakpointInfo->Address, 
        pBreakpointInfo->Size, 
        pBreakpointInfo->Register, 
        pBreakpointInfo->ThreadHandle, 
        pBreakpointInfo->Type);

    return TRUE;
}

//**************************************************************************************
BOOL ClearHardwareBreakpoint(DWORD ThreadId, int Register)
//**************************************************************************************
{
    PBREAKPOINTINFO pBreakpointInfo;
	PTHREADBREAKPOINTS CurrentThreadBreakpoint;
	HANDLE hClearBreakpointThread;

    if (Register > 3 || Register < 0)
    {
        DoOutputDebugString("ClearHardwareBreakpoint: Error - register value %d, can only have value 0-3.\n", Register);
        return FALSE;
    }  
		
	CurrentThreadBreakpoint = GetThreadBreakpoints(ThreadId);
	
	if (CurrentThreadBreakpoint == NULL)
	{
		DoOutputDebugString("Cannot find thread breakpoints - failed to clear.\n");
		return FALSE;
	}

	pBreakpointInfo = &CurrentThreadBreakpoint->BreakpointInfo[Register];
	
	if (CurrentThreadBreakpoint->ThreadHandle == NULL)
	{
		DoOutputDebugString("ClearHardwareBreakpoint: There is no thread handle in the threadbreakpoint!! FATAL ERROR.\n");
		return FALSE;
	}
	else DoOutputDebugString("ClearHardwareBreakpoint: Thread handle 0x%x found in BreakpointInfo struct.\n", CurrentThreadBreakpoint->ThreadHandle);
	
	DoOutputDebugString("About to create ClearBreakpointThread thread\n");
	
	pBreakpointInfo->ThreadHandle = CurrentThreadBreakpoint->ThreadHandle;
	
	hClearBreakpointThread = CreateThread(NULL, 0,  ClearBreakpointThread, pBreakpointInfo,	0, &ThreadId);
    
	if (hClearBreakpointThread == NULL) 
	{
	   DoOutputDebugString("Failed to create ClearBreakpointThread thread\n");
	   return 0;
	}

	DoOutputDebugString("Successfully created ClearBreakpointThread thread\n");

    // Wait until thread has terminated.
    WaitForSingleObject(hClearBreakpointThread, INFINITE);

    // Close thread handle and free memory allocations.
	pBreakpointInfo->Register = 0;
	pBreakpointInfo->Size = 0;
	pBreakpointInfo->Address = 0;
	pBreakpointInfo->Type	  = 0;
	pBreakpointInfo->Callback = NULL;
	
	CheckDebugRegisters(pBreakpointInfo->ThreadHandle, 0);	
	
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
		DoOutputDebugString("SetNextAvailableBreakpoint: Creating new thread breakpoints for thread 0x%x.\n", ThreadId);
		CurrentThreadBreakpoint = CreateThreadBreakpoints(ThreadId);
	}
	
	if (CurrentThreadBreakpoint == NULL)
	{
		DoOutputDebugString("SetNextAvailableBreakpoint: Cannot create new thread breakpoints - FATAL.\n");
		return FALSE;
	}

    if (GetNextAvailableBreakpoint(ThreadId, Register) == FALSE)
    {
        DoOutputDebugString("SetNextAvailableBreakpoint: GetNextAvailableBreakpoint failed\n");
        return FALSE;
    }

    return SetHardwareBreakpoint(ThreadId, *Register, Size, Address, Type, Callback);
}

//**************************************************************************************
BOOL InitialiseDebugger(void)
//**************************************************************************************
{
    HANDLE MainThreadHandle;

	MainThreadId = GetCurrentThreadId();

	if (DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &MainThreadHandle, 0, FALSE, DUPLICATE_SAME_ACCESS) == 0)
	{
		DoOutputDebugString("Failed to duplicate thread handle.\n");
		return FALSE;
	}

	MainThreadBreakpointList = CreateThreadBreakpoints(MainThreadId);

    if (MainThreadBreakpointList == NULL)
    {
		DoOutputDebugString("Failed to create thread breakpoints struct.\n");
		return FALSE;        
    }
    
    if (MainThreadBreakpointList->ThreadHandle == NULL)
    {
		DoOutputDebugString("InitialiseDebugger error: main thread handle not set.\n");
		return FALSE;        
    }
    
    // Initialise any global variables
    ChildProcessId = 0;
    
    // Ensure wow64 patch is installed if needed
    WoW64fix();
    
    return TRUE;
}

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
	
	if (InitialiseDebugger() == FALSE)
        DoOutputDebugString("Debugger initialisation failure!\n");
	
// Target specific code

// No need for anything here,  
// as we are setting initial bp in 
// NtAllocateVirtualMemory hook
#ifdef STANDALONE
    SetNtAllocateVirtualMemoryBP();
#endif
// End of target specific code

	DoOutputDebugString("Debugger initialisation complete, about to execute OEP.\n");

    _asm
    {
        popad
		mov     esp, ebp
        pop     ebp
        jmp		OEP
    }
}

BOOL SendDebuggerMessage(DWORD Input)
{ 
    BOOL fSuccess;
	DWORD cbReplyBytes, cbWritten; 
    //struct DEBUGGER_DATA DebuggerData;
   
    //memset(&DebuggerData, 0, sizeof(struct DEBUGGER_DATA));

    cbReplyBytes = sizeof(DWORD);
    
    if (hParentPipe == NULL)
    {   
        DoOutputErrorString("SendDebuggerMessage: hParentPipe NULL.");
        return FALSE;
    }

    // Write the reply to the pipe. 
    fSuccess = WriteFile
    ( 
        hParentPipe,        // handle to pipe 
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

    DoOutputDebugString("SendDebuggerMessage: Sent message via pipe.\n");
    
    return TRUE;
}

//**************************************************************************************
DWORD WINAPI DebuggerThread(LPVOID lpParam)
//**************************************************************************************
{ 
	HANDLE hPipe; 
	BOOL   fSuccess = FALSE, NT5; 
	DWORD  cbRead, cbToWrite, cbWritten, dwMode;
	PVOID  FuncAddress;

	char lpszPipename[MAX_PATH]; 
    OSVERSIONINFO VersionInfo;
    
	DoOutputDebugString("DebuggerThread: About to connect to CAPEpipe.\n");

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
			DoOutputErrorString("DebuggerThread: Could not open pipe"); 
			return -1;
		}

		if (!WaitNamedPipe(lpszPipename, 20)) 
		{ 
			DoOutputDebugString("DebuggerThread: Could not open pipe: 20 ms wait timed out.\n"); 
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
		DoOutputDebugString("DebuggerThread: SetNamedPipeHandleState failed.\n"); 
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
		DoOutputErrorString("DebuggerThread: WriteFile to pipe failed"); 
		return -1;
	}

	DoOutputDebugString("DebuggerThread: DebuggerInit VA sent to loader: 0x%x\n", FuncAddress);

	fSuccess = ReadFile(
		hPipe,    				
		&OEP, 
		sizeof(DWORD),  		 
		&cbRead,
		NULL);  
        
	if (!fSuccess && GetLastError() == ERROR_MORE_DATA)
	{
		DoOutputDebugString("DebuggerThread: ReadFile on Pipe: ERROR_MORE_DATA\n");
		CloseHandle(hPipe);
		return -1;
	}
	
	if (!fSuccess)
	{
		DoOutputErrorString("DebuggerThread: ReadFile (OEP) from pipe failed");
		CloseHandle(hPipe);
		return -1;
	}

	DoOutputDebugString("Read OEP from pipe: 0x%x\n", OEP);
    
    fSuccess = ReadFile(
        hPipe,    				
        &OEP, 
        sizeof(DWORD),  		 
        &cbRead,
        NULL);  
        
    if (!fSuccess && GetLastError() == ERROR_MORE_DATA)
    {
        DoOutputDebugString("DebuggerThread: ReadFile on Pipe: ERROR_MORE_DATA\n");
        CloseHandle(hPipe);
        return -1;
    }
    
    if (!fSuccess && GetLastError() == ERROR_BROKEN_PIPE)
    {
        DoOutputDebugString("DebuggerThread: Pipe closed, no further updates to OEP\n");
        CloseHandle(hPipe);
    }
    else if (!fSuccess)
    {
        DoOutputErrorString("ReadFile from pipe failed");
        CloseHandle(hPipe);
        return -1;
    }
    else
        DoOutputDebugString("Read thread EP from pipe: 0x%x\n", OEP);
  
    ZeroMemory(&VersionInfo, sizeof(OSVERSIONINFO));
    VersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&VersionInfo);

    NT5 = (VersionInfo.dwMajorVersion == 5);
    
    if (NT5)
    {
       	DoOutputDebugString("NT5: Leaving debugger thread alive.\n");
        while(1)
        {
            Sleep(500000);
        }
    }

    DoOutputDebugString("NT6+: Terminating debugger thread.\n");
    
	return 0; 
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
        DoOutputErrorString("CAPE debug pipe: OpenProcess failed");
        return FALSE;
    }

    hThread = OpenThread(THREAD_ALL_ACCESS, TRUE, ThreadId);
    if (hThread == NULL) 
    {
        DoOutputErrorString("CAPE debug pipe: OpenThread failed");
        return FALSE;
    }

    hParentPipe = CreateNamedPipe
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

    if (hParentPipe == INVALID_HANDLE_VALUE) 
    {
        DoOutputErrorString("DebugNewProcess: CreateNamedPipe failed");
        return FALSE;
    }

    DoOutputDebugString("DebugNewProcess: Announcing new process to Cuckoo, pid: %d\n", ProcessId);
    pipe("DEBUGGER:%d,%d", ProcessId, ThreadId);

    fConnected = ConnectNamedPipe(hParentPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); 
    fSuccess = FALSE;
    cbBytesRead = 0;
    
    if (!fConnected) 
    {
        DoOutputDebugString("DebugNewProcess: The client could not connect, closing pipe.\n");
        CloseHandle(hParentPipe);
        return FALSE;
    }

    DoOutputDebugString("DebugNewProcess: Client connected\n");
    
    fSuccess = ReadFile
    ( 
        hParentPipe,        
        &RemoteFuncAddress, 
        sizeof(DWORD),		
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

    if (!RemoteFuncAddress)
    {
        DoOutputErrorString("DebugNewProcess: Successfully read from pipe, however RemoteFuncAddress = 0.");
        return FALSE;
    }
    
    Context.ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(hThread, &Context))
    {
        DoOutputDebugString("DebugNewProcess: GetThreadContext failed - FATAL\n");
        return FALSE;
    }

    OEP = (PVOID)Context.Eax;
    
    cbWritten = 0;
    cbReplyBytes = sizeof(DWORD);

    // Write the reply to the pipe. 
    fSuccess = WriteFile
    ( 
        hParentPipe,     
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

    DoOutputDebugString("DebugNewProcess: Sent OEP 0x%x via pipe\n", OEP);

    Context.ContextFlags = CONTEXT_ALL;
    
    Context.Eax = RemoteFuncAddress;		// eax holds new entry point
    
    if (!SetThreadContext(hThread, &Context))
    {
        DoOutputDebugString("DebugNewProcess: Failed to set new EP\n");
        return FALSE;
    }

    DoOutputDebugString("DebugNewProcess: Set new EP to DebuggerInit: 0x%x\n", Context.Eax);
    
    CloseHandle(hProcess);
    CloseHandle(hThread);

	return TRUE;
}

//**************************************************************************************
int launch_debugger()
//**************************************************************************************
{
	DWORD NewThreadId;
	HANDLE hDebuggerThread;

	DoOutputDebugString("CAPE: Launching debugger.\n");

    hDebuggerThread = CreateThread(
        NULL,		
        0,             
        DebuggerThread,
        NULL,		
        0,             
        &NewThreadId); 

    if (hDebuggerThread == NULL) 
    {
       DoOutputDebugString("CAPE: Failed to create debug pipe thread.\n");
       return 0;
    }
    else
    {
        DoOutputDebugString("CAPE: Successfully created debug pipe thread.\n");
    }

	CloseHandle(hDebuggerThread);
    
    return 1;
}
#endif