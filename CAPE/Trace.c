/*
CAPE - Config And Payload Extraction
Copyright(C) 2019 kevoreilly@gmail.com

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
#include <distorm.h>
#include "..\hooking.h"
#include "..\hooks.h"
#include "..\misc.h"
#include "Debugger.h"
#include "CAPE.h"
#include <psapi.h>
#include <intrin.h>

#define MAX_INSTRUCTIONS 0x10
#define MAX_DUMP_SIZE 0x1000000
#define SINGLE_STEP_LIMIT 0x4000  // default unless specified in web ui
#define CHUNKSIZE 0x10 * MAX_INSTRUCTIONS
#define RVA_LIMIT 0x200000
#define DoClearZeroFlag 1
#define DoSetZeroFlag   2
#define PrintEAX        3

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern void ErrorOutput(_In_ LPCTSTR lpOutputString, ...);
extern void DebuggerOutput(_In_ LPCTSTR lpOutputString, ...);
extern int DumpImageInCurrentProcess(LPVOID ImageBase);
extern int DumpMemory(LPVOID Buffer, SIZE_T Size);
extern char *CommandLine, *convert_address_to_dll_name_and_offset(ULONG_PTR addr, unsigned int *offset);
extern BOOL is_in_dll_range(ULONG_PTR addr);
extern DWORD_PTR FileOffsetToVA(DWORD_PTR modBase, DWORD_PTR dwOffset);
extern DWORD_PTR GetEntryPointVA(DWORD_PTR modBase);
extern BOOL ScyllaGetSectionByName(PVOID ImageBase, char* Name, PVOID* SectionData, SIZE_T* SectionSize);
extern PCHAR ScyllaGetExportNameByAddress(PVOID Address, PCHAR* ModuleName);
extern ULONG_PTR g_our_dll_base;
extern BOOL inside_hook(LPVOID Address);
extern void loq(int index, const char *category, const char *name,
    int is_success, ULONG_PTR return_value, const char *fmt, ...);

char *ModuleName, *PreviousModuleName;
BOOL BreakpointsSet, BreakpointsHit, FilterTrace, StopTrace, ModTimestamp, ReDisassemble;
PVOID ModuleBase, DumpAddress, ReturnAddress;
BOOL GetSystemTimeAsFileTimeImported, PayloadMarker, PayloadDumped, TraceRunning;
unsigned int DumpCount, Correction, StepCount, StepLimit, TraceDepthLimit;
char Action0[MAX_PATH], Action1[MAX_PATH], Action2[MAX_PATH], Action3[MAX_PATH], *Instruction0, *Instruction1, *Instruction2, *Instruction3;
char *procname0;
unsigned int Type0, Type1, Type2, Type3;
int cpuInfo[4], function_id, subfunction_id, StepOverRegister, TraceDepthCount, EntryPointRegister, InstructionCount;
static CONTEXT LastContext;
SIZE_T DumpSize, LastWriteLength;
char DumpSizeString[MAX_PATH], DebuggerBuffer[MAX_PATH];
LARGE_INTEGER LastTimestamp;

BOOL Trace(struct _EXCEPTION_POINTERS* ExceptionInfo);
BOOL BreakpointCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo);

BOOL DoSetSingleStepMode(int Register, PCONTEXT Context, PVOID Handler)
{
    if (!GetNextAvailableBreakpoint(GetCurrentThreadId(), &StepOverRegister))
        StepOverRegister = Register;
    return SetSingleStepMode(Context, Handler);
}

void SkipInstruction(PCONTEXT Context)
{
	PVOID CIP;
    _DecodeType DecodeType;
    _DecodeResult Result;
    _OffsetType Offset = 0;
    _DecodedInst DecodedInstruction;
    unsigned int DecodedInstructionsCount = 0;

#ifdef _WIN64
    CIP = (PVOID)Context->Rip;
    DecodeType = Decode64Bits;
#else
    CIP = (PVOID)Context->Eip;
    DecodeType = Decode32Bits;
#endif
    if (CIP)
        Result = distorm_decode(Offset, (const unsigned char*)CIP, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount);

    if (!DecodedInstruction.size)
        return;

#ifdef _WIN64
    Context->Rip += DecodedInstruction.size;
#else
    Context->Eip += DecodedInstruction.size;
#endif

    return;
}

void ActionDispatcher(struct _EXCEPTION_POINTERS* ExceptionInfo, _DecodedInst DecodedInstruction, PCHAR Action)
{
	// This could be further optimised per action but this is safe at least
	ReDisassemble = TRUE;

    if (!stricmp(Action, "ClearZeroFlag"))
    {
        ClearZeroFlag(ExceptionInfo->ContextRecord);
        DebuggerOutput("ActionDispatcher: %s detected, clearing zero flag.\n", DecodedInstruction.mnemonic.p);
    }
    else if (!stricmp(Action, "SetZeroFlag"))
    {
        SetZeroFlag(ExceptionInfo->ContextRecord);
        DebuggerOutput("ActionDispatcher: %s detected, setting zero flag.\n", DecodedInstruction.mnemonic.p);
    }
    else if (!stricmp(Action, "FlipZeroFlag"))
    {
        FlipZeroFlag(ExceptionInfo->ContextRecord);
        DebuggerOutput("ActionDispatcher: %s detected, flipping zero flag.\n", DecodedInstruction.mnemonic.p);
    }
    else if (!stricmp(Action, "ClearSignFlag"))
    {
        ClearSignFlag(ExceptionInfo->ContextRecord);
        DebuggerOutput("ActionDispatcher: %s detected, clearing Sign flag.\n", DecodedInstruction.mnemonic.p);
    }
    else if (!stricmp(Action, "SetSignFlag"))
    {
        SetSignFlag(ExceptionInfo->ContextRecord);
        DebuggerOutput("ActionDispatcher: %s detected, setting Sign flag.\n", DecodedInstruction.mnemonic.p);
    }
    else if (!stricmp(Action, "FlipSignFlag"))
    {
        FlipSignFlag(ExceptionInfo->ContextRecord);
        DebuggerOutput("ActionDispatcher: %s detected, flipping Sign flag.\n", DecodedInstruction.mnemonic.p);
    }
    else if (!stricmp(Action, "Skip"))
    {
        SkipInstruction(ExceptionInfo->ContextRecord);
        DebuggerOutput("ActionDispatcher: %s detected, skipping instruction.\n", DecodedInstruction.mnemonic.p);
    }
    else if (!stricmp(Action, "Stop"))
    {
		StopTrace = TRUE;
        DebuggerOutput("ActionDispatcher: %s detected, stopping trace.\n", DecodedInstruction.mnemonic.p);
    }
#ifndef _WIN64
    else if (!stricmp(Action, "PrintEAX"))
    {
        if (ExceptionInfo->ContextRecord->Eax)
            DebuggerOutput("ActionDispatcher: Print EAX -> 0x%x.", ExceptionInfo->ContextRecord->Eax);
    }
#endif
    else if (!stricmp(Action, "Dump"))
    {
#ifdef _WIN64
		PVOID CallingModule = GetAllocationBase((PVOID)ExceptionInfo->ContextRecord->Rip);
#else
		PVOID CallingModule = GetAllocationBase((PVOID)ExceptionInfo->ContextRecord->Eip);
#endif
        if (g_config.dumptype0)
            CapeMetaData->DumpType = g_config.dumptype0;
        else
            CapeMetaData->DumpType = UNPACKED_PE;

        if (DumpImageInCurrentProcess(CallingModule))
            DebuggerOutput("ActionDispatcher: Dumped breaking module at 0x%p.\n", CallingModule);
        else
            DebuggerOutput("ActionDispatcher: Failed to dump breaking module at 0x%p.\n", CallingModule);
    }
    else if (!stricmp(Action, "dumpebx"))
    {
        if (!stricmp(DumpSizeString, "eax"))
        {
#ifdef _WIN64
            DumpSize = ExceptionInfo->ContextRecord->Rax;
            DumpAddress = (PVOID)ExceptionInfo->ContextRecord->Rbx;
#else
            DumpSize = ExceptionInfo->ContextRecord->Eax;
            DumpAddress = (PVOID)ExceptionInfo->ContextRecord->Ebx;
#endif
            if (g_config.dumptype0)
                CapeMetaData->DumpType = g_config.dumptype0;
            else
                CapeMetaData->DumpType = UNPACKED_PE;

            if (DumpAddress && DumpSize && DumpSize < MAX_DUMP_SIZE && DumpMemory(DumpAddress, DumpSize))
            {
                DebuggerOutput("ActionDispatcher: Dumped region at 0x%p size 0x%x.\n", DumpAddress, DumpSize);
                return;
            }
            else
                DebuggerOutput("ActionDispatcher: Failed to dump region at 0x%p.\n", DumpAddress);
        }
    }
    else if (!stricmp(Action, "dumpecx"))
    {
        if (!stricmp(DumpSizeString, "eax"))
        {
#ifdef _WIN64
            PVOID CallingModule = GetAllocationBase((PVOID)ExceptionInfo->ContextRecord->Rip);
            DumpSize = ExceptionInfo->ContextRecord->Rax;
            DumpAddress = (PVOID)ExceptionInfo->ContextRecord->Rcx;
#else
            PVOID CallingModule = GetAllocationBase((PVOID)ExceptionInfo->ContextRecord->Eip);
			DumpSize = ExceptionInfo->ContextRecord->Eax;
            DumpAddress = (PVOID)ExceptionInfo->ContextRecord->Ecx;
#endif
            if (g_config.dumptype0)
                CapeMetaData->DumpType = g_config.dumptype0;
            else
                CapeMetaData->DumpType = UNPACKED_PE;

            if (DumpAddress && DumpSize && DumpSize < MAX_DUMP_SIZE && DumpMemory(DumpAddress, DumpSize))
                DebuggerOutput("ActionDispatcher: Dumped region at 0x%p size 0x%x.\n", DumpAddress, DumpSize);
            else
                DebuggerOutput("ActionDispatcher: Failed to dump region at 0x%p.\n", DumpAddress);
        }
    }
    else if (!stricmp(Action, "dumpedx"))
    {
        if (!stricmp(DumpSizeString, "ecx"))
        {
#ifdef _WIN64
            PVOID CallingModule = GetAllocationBase((PVOID)ExceptionInfo->ContextRecord->Rip);
            DumpSize = ExceptionInfo->ContextRecord->Rcx;
            DumpAddress = (PVOID)ExceptionInfo->ContextRecord->Rdx;
#else
            PVOID CallingModule = GetAllocationBase((PVOID)ExceptionInfo->ContextRecord->Eip);
            DumpSize = ExceptionInfo->ContextRecord->Ecx;
            DumpAddress = (PVOID)ExceptionInfo->ContextRecord->Edx;
#endif
            if (g_config.dumptype0)
                CapeMetaData->DumpType = g_config.dumptype0;
            else
                CapeMetaData->DumpType = UNPACKED_PE;

            if (DumpAddress && DumpSize && DumpSize < MAX_DUMP_SIZE && DumpMemory(DumpAddress, DumpSize))
                DebuggerOutput("ActionDispatcher: Dumped region at 0x%p size 0x%x.\n", DumpAddress, DumpSize);
            else
                DebuggerOutput("ActionDispatcher: Failed to dump region at 0x%p.\n", DumpAddress);
        }
    }
    else if (!stricmp(Action, "dumpesi"))
    {
#ifdef _WIN64
        DumpAddress = (PVOID)ExceptionInfo->ContextRecord->Rsi;
#else
        DumpAddress = (PVOID)ExceptionInfo->ContextRecord->Esi;
#endif
        if (!stricmp(DumpSizeString, "eax"))
        {
#ifdef _WIN64
            DumpSize = ExceptionInfo->ContextRecord->Rax;
#else
            DumpSize = ExceptionInfo->ContextRecord->Eax;
#endif
        }
        else if (!stricmp(DumpSizeString, "eax"))
        {
#ifdef _WIN64
            DumpSize = ExceptionInfo->ContextRecord->Rax;
#else
            DumpSize = ExceptionInfo->ContextRecord->Eax;
#endif
        }
        if (g_config.dumptype0)
            CapeMetaData->DumpType = g_config.dumptype0;
        else
            CapeMetaData->DumpType = UNPACKED_PE;

        if (DumpAddress && DumpSize && DumpSize < MAX_DUMP_SIZE && DumpMemory(DumpAddress, DumpSize))
            DebuggerOutput("ActionDispatcher: Dumped region at 0x%p size 0x%x.\n", DumpAddress, DumpSize);
        else
            DebuggerOutput("ActionDispatcher: Failed to dump region at 0x%p size 0x%x.\n", DumpAddress, DumpSize);
    }
    else if (stricmp(Action, "custom"))
        DebuggerOutput("ActionDispatcher: Unrecognised action: (%s)\n", Action);

    InstructionCount++;

	return;
}

BOOL Trace(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID CIP;
    unsigned int DllRVA;
    PVOID BranchTarget;

    TraceRunning = TRUE;
    BOOL StepOver = FALSE, ForceStepOver = FALSE, StopTrace = FALSE;

    _DecodeType DecodeType;
    _DecodeResult Result;
    _OffsetType Offset = 0;
    _DecodedInst DecodedInstruction;
    unsigned int DecodedInstructionsCount = 0;

#ifdef _WIN64
    CIP = (PVOID)ExceptionInfo->ContextRecord->Rip;
    DecodeType = Decode64Bits;
#else
    CIP = (PVOID)ExceptionInfo->ContextRecord->Eip;
    DecodeType = Decode32Bits;
#endif

    FilterTrace = FALSE;

    if (InsideMonitor(NULL, CIP) && g_config.trace_all == 1)
        FilterTrace = TRUE;

    if (inside_hook(CIP) && !g_config.trace_all)
        FilterTrace = TRUE;

    if (is_in_dll_range((ULONG_PTR)CIP) && !g_config.trace_all)
        FilterTrace = TRUE;

    if (!FilterTrace)
        StepCount++;
    else
    {
        StepOver = TRUE;
        if (ReturnAddress)
        {
            if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &StepOverRegister, 0, (BYTE*)ReturnAddress, BP_EXEC, BreakpointCallback))
            {
                ClearSingleStepMode(ExceptionInfo->ContextRecord);
#ifdef DEBUG_COMMENTS
                DebugOutput("Trace: Set breakpoint on return address 0x%p\n", ReturnAddress);
#endif
                LastContext = *ExceptionInfo->ContextRecord;
                ReturnAddress = NULL;
                return TRUE;
            }
            else
                DebugOutput("Trace: Failed to set breakpoint on return address 0x%p\n", ReturnAddress);
        }
    }

    if (ModTimestamp)
    {
        ModTimestamp = FALSE;
        if (!LastTimestamp.QuadPart)
        {
#ifdef _WIN64
            LastTimestamp.LowPart = (DWORD)ExceptionInfo->ContextRecord->Rax;
            LastTimestamp.HighPart = (DWORD)ExceptionInfo->ContextRecord->Rdx;
#else
            LastTimestamp.LowPart = ExceptionInfo->ContextRecord->Eax;
            LastTimestamp.HighPart = ExceptionInfo->ContextRecord->Edx;
#endif
        }
        else
        {
            LastTimestamp.QuadPart = LastTimestamp.QuadPart + g_config.fake_rdtsc;
#ifdef _WIN64
            ExceptionInfo->ContextRecord->Rax = LastTimestamp.LowPart;
            ExceptionInfo->ContextRecord->Rdx = LastTimestamp.HighPart;
#else
            ExceptionInfo->ContextRecord->Eax = LastTimestamp.LowPart;
            ExceptionInfo->ContextRecord->Edx = LastTimestamp.HighPart;
#endif
        }
    }

#ifdef _WIN64
    if (!g_config.branch_trace && !FilterTrace && LastContext.Rip)
    {
        memset(DebuggerBuffer, 0, MAX_PATH*sizeof(CHAR));

        if (LastContext.Rax != ExceptionInfo->ContextRecord->Rax)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RAX=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rax);

        if (LastContext.Rbx != ExceptionInfo->ContextRecord->Rbx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RBX=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rbx);

        if (LastContext.Rcx != ExceptionInfo->ContextRecord->Rcx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RCX=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rcx);

        if (LastContext.Rdx != ExceptionInfo->ContextRecord->Rdx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RDX=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rdx);

        if (LastContext.Rsi != ExceptionInfo->ContextRecord->Rsi)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RSI=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rsi);

        if (LastContext.Rdi != ExceptionInfo->ContextRecord->Rdi)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RDI=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rdi);

        if (LastContext.Rsp != ExceptionInfo->ContextRecord->Rsp)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RSP=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rsp);

        if (LastContext.Rbp != ExceptionInfo->ContextRecord->Rbp)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RBP=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rbp);

        if (LastContext.R8 != ExceptionInfo->ContextRecord->R8)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s R8=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->R8);

        if (LastContext.R9 != ExceptionInfo->ContextRecord->R9)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s R9=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->R9);

        if (LastContext.R10 != ExceptionInfo->ContextRecord->R10)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s R10=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->R10);

        if (LastContext.R11 != ExceptionInfo->ContextRecord->R11)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s R11=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->R11);

        if (LastContext.R12 != ExceptionInfo->ContextRecord->R12)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s R12=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->R12);

        if (LastContext.R13 != ExceptionInfo->ContextRecord->R13)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s R13=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->R13);

        if (LastContext.R14 != ExceptionInfo->ContextRecord->R14)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s R14=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->R14);

        if (LastContext.R15 != ExceptionInfo->ContextRecord->R15)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s R15=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->R15);

        if (LastContext.Xmm0.Low != ExceptionInfo->ContextRecord->Xmm0.Low)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s Xmm0.Low=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Xmm0.Low);

        if (LastContext.Xmm0.High != ExceptionInfo->ContextRecord->Xmm0.High)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s Xmm0.High=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Xmm0.High);

        if (LastContext.Xmm1.Low != ExceptionInfo->ContextRecord->Xmm1.Low)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s Xmm1.Low=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Xmm1.Low);

        if (LastContext.Xmm1.High != ExceptionInfo->ContextRecord->Xmm1.High)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s Xmm1.High=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Xmm1.High);
#else
    if (!g_config.branch_trace && !FilterTrace && LastContext.Eip)
    {
        memset(DebuggerBuffer, 0, MAX_PATH*sizeof(CHAR));

        if (LastContext.Eax != ExceptionInfo->ContextRecord->Eax)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s EAX=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Eax);

        if (LastContext.Ebx != ExceptionInfo->ContextRecord->Ebx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s EBX=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Ebx);

        if (LastContext.Ecx != ExceptionInfo->ContextRecord->Ecx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s ECX=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Ecx);

        if (LastContext.Edx != ExceptionInfo->ContextRecord->Edx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s EDX=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Edx);

        if (LastContext.Esi != ExceptionInfo->ContextRecord->Esi)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s ESI=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Esi);

        if (LastContext.Edi != ExceptionInfo->ContextRecord->Edi)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s EDI=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Edi);

        if (LastContext.Esp != ExceptionInfo->ContextRecord->Esp)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s ESP=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Esp);

        if (LastContext.Ebp != ExceptionInfo->ContextRecord->Ebp)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s EBP=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Ebp);
#endif

        DebuggerOutput(DebuggerBuffer);
    }

    if (!g_config.branch_trace && !FilterTrace)
        DebuggerOutput("\n");

    if (StepCount > StepLimit)
    {
        DebuggerOutput("Single-step limit reached (%d), releasing.\n", StepLimit);
        ClearSingleStepMode(ExceptionInfo->ContextRecord);
        memset(&LastContext, 0, sizeof(CONTEXT));
        TraceRunning = FALSE;
        StopTrace = TRUE;
        StepCount = 0;
        return TRUE;
    }

    ModuleName = convert_address_to_dll_name_and_offset((ULONG_PTR)CIP, &DllRVA);
    PCHAR FunctionName;

    if (ModuleName)
    {
        if (!PreviousModuleName || strncmp(ModuleName, PreviousModuleName, strlen(ModuleName)))
        {
            __try
            {
                FunctionName = ScyllaGetExportNameByAddress(CIP, NULL);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                DebugOutput("Trace: Error dereferencing instruction pointer 0x%p.\n", CIP);
            }
            if (FilterTrace && !g_config.branch_trace)
                DebuggerOutput("\n");
            if (FunctionName && !g_config.branch_trace)
            {
                DebuggerOutput("Break in %s::%s (RVA 0x%x, thread %d)\n", ModuleName, FunctionName, DllRVA, GetCurrentThreadId());
                for (unsigned int i = 0; i < ARRAYSIZE(g_config.trace_into_api); i++)
                {
                    if (!g_config.trace_into_api[i])
                        break;
                    if (!stricmp(FunctionName, g_config.trace_into_api[i]))
                        StepOver = FALSE;
                }
            }
            else if (!g_config.branch_trace)
            {
                DebuggerOutput("Break in %s (RVA 0x%x, thread %d)\n", ModuleName, DllRVA, GetCurrentThreadId());
                PreviousModuleName = ModuleName;
                FunctionName = NULL;
                ModuleName = NULL;
            }

        }
    }

    if (g_config.branch_trace && ExceptionInfo->ExceptionRecord->ExceptionInformation[0] > 0x20000)
    {
        BranchTarget = CIP;
        CIP = (PVOID)ExceptionInfo->ExceptionRecord->ExceptionInformation[0];

        Result = distorm_decode(Offset, (const unsigned char*)CIP, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount);

#ifdef _WIN64
        DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#else
        DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%s", (unsigned int)CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#endif
        if (ModuleName)
        {
            if (!PreviousModuleName || strncmp(ModuleName, PreviousModuleName, strlen(ModuleName)))
            {
                if (FunctionName)
                    DebuggerOutput(" -> %s::%s (RVA 0x%x, thread %d)\n", ModuleName, FunctionName, DllRVA, GetCurrentThreadId());
                else
                    DebuggerOutput(" -> %s (RVA 0x%x, thread %d)\n", ModuleName, DllRVA, GetCurrentThreadId());
                PreviousModuleName = ModuleName;
                FunctionName = NULL;
                ModuleName = NULL;
            }
            else
                DebuggerOutput("\n");
        }
        else
            DebuggerOutput("\n");

        Result = distorm_decode(Offset, (const unsigned char*)BranchTarget, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount);

#ifdef _WIN64
        DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s\n", BranchTarget, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#else
        DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s\n", (unsigned int)BranchTarget, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#endif
        if (!StopTrace)
        {
            SetSingleStepMode(ExceptionInfo->ContextRecord, Trace);
#ifdef DEBUG_COMMENTS
        }
        else
            DebugOutput("Trace: Stopping trace!\n");
#else
        }
#endif
        TraceRunning = FALSE;

        return TRUE;
    }

    // We disassemble once for the action dispatcher
    if (CIP)
        Result = distorm_decode(Offset, (const unsigned char*)CIP, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount);

    ReDisassemble = FALSE;

	// Dispatch any actions
    if (Instruction0 && !stricmp(DecodedInstruction.mnemonic.p, Instruction0))
        ActionDispatcher(ExceptionInfo, DecodedInstruction, Action0);

    if (Instruction1 && !stricmp(DecodedInstruction.mnemonic.p, Instruction1))
        ActionDispatcher(ExceptionInfo, DecodedInstruction, Action1);

    if (Instruction2 && !stricmp(DecodedInstruction.mnemonic.p, Instruction2))
        ActionDispatcher(ExceptionInfo, DecodedInstruction, Action2);

    if (Instruction3 && !stricmp(DecodedInstruction.mnemonic.p, Instruction3))
        ActionDispatcher(ExceptionInfo, DecodedInstruction, Action3);

    // We disassemble a second time in case of any changes/patches
	if (ReDisassemble)
	{
#ifdef _WIN64
		CIP = (PVOID)ExceptionInfo->ContextRecord->Rip;
#else
		CIP = (PVOID)ExceptionInfo->ContextRecord->Eip;
#endif
		if (CIP)
			Result = distorm_decode(Offset, (const unsigned char*)CIP, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount);
	}

    // Instruction handling
    if (!strcmp(DecodedInstruction.mnemonic.p, "CALL"))
    {
        PCHAR ExportName;
        // We set this as a matter of course for calls in case we might
        // want to step over this as a result of the call target
        ReturnAddress = (PVOID)((PUCHAR)CIP + DecodedInstruction.size);

        if (DecodedInstruction.size > 4 && DecodedInstruction.operands.length && !strncmp(DecodedInstruction.operands.p, "DWORD", 5) && strncmp(DecodedInstruction.operands.p, "DWORD [E", 8))
        {
            // begins with DWORD except "DWORD [E"
            PVOID CallTarget = *(PVOID*)((PUCHAR)CIP + DecodedInstruction.size - 4);
            __try
            {
                ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                DebugOutput("Trace: Error dereferencing CallTarget 0x%x.\n", CallTarget);
                ExportName = NULL;
            }

            if (ExportName)
            {
                if (!FilterTrace || g_config.trace_all)
                    DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else if (!strncmp(DecodedInstruction.operands.p, "DWORD [0x", 9))
            {
                if (!FilterTrace || g_config.trace_all)
                    DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
            }
            else if (!strncmp(DecodedInstruction.operands.p, "DWORD [FS:0xc0]", 15))
            {
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
                ForceStepOver = TRUE;
                DebuggerOutput("\nFORCE STEP OVER = %d\n", ForceStepOver);
            }
            else if (!FilterTrace || g_config.trace_all)
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-28x", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
        }
        else if (DecodedInstruction.size > 4)
        {
            PVOID CallTarget = (PVOID)((PUCHAR)CIP + (int)*(DWORD*)((PUCHAR)CIP + DecodedInstruction.size - 4) + DecodedInstruction.size);
            __try
            {
                ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                DebugOutput("Trace: Error dereferencing CallTarget 0x%x.", CallTarget);
                ExportName = NULL;
            }

            if (ExportName)
            {
                if (!FilterTrace || g_config.trace_all)
                    DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                if (!FilterTrace || g_config.trace_all)
                    DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-28x", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);

            if (CallTarget == &loq)
                StepOver = TRUE;
        }
        else if (!strncmp(DecodedInstruction.operands.p, "EAX", 3))
        {
#ifdef _WIN64
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rax;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                if (!FilterTrace || g_config.trace_all)
                    DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else if (!FilterTrace || g_config.trace_all)
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#else
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Eax;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                if (!FilterTrace || g_config.trace_all)
                    DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else if (!FilterTrace || g_config.trace_all)
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-28x", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#endif
        }
        else if (!strncmp(DecodedInstruction.operands.p, "EBX", 3))
        {
#ifdef _WIN64
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rbx;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                if (!FilterTrace || g_config.trace_all)
                    DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else if (!FilterTrace || g_config.trace_all)
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#else
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Ebx;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                if (!FilterTrace || g_config.trace_all)
                    DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else if (!FilterTrace || g_config.trace_all)
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-28x", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#endif
        }
        else if (!strncmp(DecodedInstruction.operands.p, "ECX", 3))
        {
#ifdef _WIN64
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rcx;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                if (!FilterTrace || g_config.trace_all)
                    DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else if (!FilterTrace || g_config.trace_all)
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#else
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Ecx;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                if (!FilterTrace || g_config.trace_all)
                    DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else if (!FilterTrace || g_config.trace_all)
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-28x", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#endif
        }
        else if (!strncmp(DecodedInstruction.operands.p, "EDX", 3))
        {
#ifdef _WIN64
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rdx;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                if (!FilterTrace || g_config.trace_all)
                    DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else if (!FilterTrace || g_config.trace_all)
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#else
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Edx;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                if (!FilterTrace || g_config.trace_all)
                    DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else if (!FilterTrace || g_config.trace_all)
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-28x", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#endif
        }
        else if (!strncmp(DecodedInstruction.operands.p, "EBP", 3))
        {
#ifdef _WIN64
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rbp;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                if (!FilterTrace || g_config.trace_all)
                    DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else if (!FilterTrace || g_config.trace_all)
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#else
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Ebp;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                if (!FilterTrace || g_config.trace_all)
                    DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else if (!FilterTrace || g_config.trace_all)
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-28x", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#endif
        }
        else if (!FilterTrace || g_config.trace_all)
            DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);

        if (g_config.branch_trace)
            TraceDepthCount++;
        else
        {
            if (ExportName)
            {
                for (unsigned int i = 0; i < ARRAYSIZE(g_config.trace_into_api); i++)
                {
                    if (!g_config.trace_into_api[i])
                        break;
                    if (!stricmp(ExportName, g_config.trace_into_api[i]))
                    {
                        StepOver = FALSE;
                        TraceDepthCount--;
                        DebuggerOutput("\nTrace: Stepping into %s\n", ExportName);
                    }
                }
            }

            if (((unsigned int)abs(TraceDepthCount) >= TraceDepthLimit && !g_config.trace_all) || (StepOver == TRUE && !g_config.trace_all) || ForceStepOver)
            {
                if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &StepOverRegister, 0, (BYTE*)ReturnAddress, BP_EXEC, BreakpointCallback))
                {
                    ClearSingleStepMode(ExceptionInfo->ContextRecord);
#ifndef DEBUG_COMMENTS
                    if (ForceStepOver)
#endif
                        DebugOutput("Trace: Set breakpoint on return address 0x%p (register %d)\n", ReturnAddress, StepOverRegister);
                    ReturnAddress = NULL;
                    LastContext = *ExceptionInfo->ContextRecord;
                    return TRUE;
                }
                else
                    DebugOutput("Trace: Failed to set breakpoint on return address 0x%p\n", ReturnAddress);
            }
            else
                TraceDepthCount++;
        }
    }
    else if (!strcmp(DecodedInstruction.mnemonic.p, "JMP"))
    {
        PCHAR ExportName;
#ifdef _WIN64
        ReturnAddress = *(PVOID*)(ExceptionInfo->ContextRecord->Rsp);
#else
        ReturnAddress = *(PVOID*)(ExceptionInfo->ContextRecord->Esp);
#endif

        if (DecodedInstruction.size > 4 && DecodedInstruction.operands.length && !strncmp(DecodedInstruction.operands.p, "DWORD", 5) && strncmp(DecodedInstruction.operands.p, "DWORD [E", 8))
        {
            PVOID JumpTarget;
            if (!strncmp(DecodedInstruction.operands.p, "DWORD [0x", 9))
                JumpTarget = *(PVOID*)(*(PVOID*)((PUCHAR)CIP + DecodedInstruction.size - 4));
            else
                // begins with DWORD except "DWORD [E"
                JumpTarget = *(PVOID*)((PUCHAR)CIP + DecodedInstruction.size - 4);

            __try
            {
                ExportName = ScyllaGetExportNameByAddress(JumpTarget, NULL);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                DebugOutput("Trace: Error dereferencing JumpTarget 0x%x.\n", JumpTarget);
                ExportName = NULL;
            }

            if (ExportName)
            {
                if (!FilterTrace || g_config.trace_all)
                    DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                if (!g_config.trace_all)
					ForceStepOver = TRUE;
            }
            else if (!FilterTrace || g_config.trace_all)
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-28x", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", JumpTarget);

            //if (is_in_dll_range((ULONG_PTR)JumpTarget))
            //    ForceStepOver = TRUE;
        }
        else if (DecodedInstruction.size > 4)
        {
            PVOID JumpTarget = (PVOID)((PUCHAR)CIP + (int)*(DWORD*)((PUCHAR)CIP + DecodedInstruction.size - 4) + DecodedInstruction.size);
            __try
            {
                ExportName = ScyllaGetExportNameByAddress(JumpTarget, NULL);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                DebugOutput("Trace: Error dereferencing JumpTarget 0x%x.", JumpTarget);
                ExportName = NULL;
            }

            if (ExportName)
            {
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
            }
            else
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-28x", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", JumpTarget);
        }
        else if (!FilterTrace || g_config.trace_all)
            DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
    }
#ifndef _WIN64
    else if (!strcmp(DecodedInstruction.mnemonic.p, "CALL FAR") && !strncmp(DecodedInstruction.operands.p, "0x33", 4))
    {
        ReturnAddress = (PVOID)((PUCHAR)CIP + DecodedInstruction.size);
        ForceStepOver = TRUE;
    }
    else if (!strcmp(DecodedInstruction.mnemonic.p, "JMP FAR") && !strncmp(DecodedInstruction.operands.p, "0x33", 4))
    {
		if (!FilterTrace || g_config.trace_all)
			DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", (unsigned int)CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
        ReturnAddress = *(PVOID*)(ExceptionInfo->ContextRecord->Esp);
        ForceStepOver = TRUE;
    }
#endif
    else if (!strcmp(DecodedInstruction.mnemonic.p, "CPUID"))
    {
#ifdef _WIN64
        DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#else
        DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", (unsigned int)CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#endif
		SkipInstruction(ExceptionInfo->ContextRecord);
        // Emulate
#ifdef _WIN64
		if (ExceptionInfo->ContextRecord->Rax != function_id)// || ExceptionInfo->ContextRecord->Ecx != subfunction_id)
		{
			function_id = (DWORD64)ExceptionInfo->ContextRecord->Rax;
			subfunction_id = (DWORD64)ExceptionInfo->ContextRecord->Rcx;
			__cpuidex(cpuInfo, function_id, subfunction_id);
		}
		ExceptionInfo->ContextRecord->Rax = cpuInfo[0];
		ExceptionInfo->ContextRecord->Rbx = cpuInfo[1];
		ExceptionInfo->ContextRecord->Rcx = cpuInfo[2];
		ExceptionInfo->ContextRecord->Rdx = cpuInfo[3];
#else
		if (ExceptionInfo->ContextRecord->Eax != function_id)// || ExceptionInfo->ContextRecord->Ecx != subfunction_id)
		{
			function_id = ExceptionInfo->ContextRecord->Eax;
			subfunction_id = ExceptionInfo->ContextRecord->Ecx;
			__cpuidex(cpuInfo, function_id, subfunction_id);
		}
		ExceptionInfo->ContextRecord->Eax = cpuInfo[0];
		ExceptionInfo->ContextRecord->Ebx = cpuInfo[1];
		ExceptionInfo->ContextRecord->Ecx = cpuInfo[2];
		ExceptionInfo->ContextRecord->Edx = cpuInfo[3];
#endif
	}
    else if (!strcmp(DecodedInstruction.mnemonic.p, "RET"))
    {
        if (g_config.branch_trace)
            TraceDepthCount--;
        else
        {
            if (!FilterTrace || g_config.trace_all)
#ifdef _WIN64
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#else
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", (unsigned int)CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#endif
            if (!g_config.trace_all)
				TraceDepthCount--;
        }
    }
	else if (!FilterTrace)
#ifdef _WIN64
        DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#else
        DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", (unsigned int)CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#endif

    if (!strcmp(DecodedInstruction.mnemonic.p, "RDTSC") && g_config.fake_rdtsc)
        ModTimestamp = TRUE;

    LastContext = *ExceptionInfo->ContextRecord;

    if (ForceStepOver)
    {
        if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &StepOverRegister, 0, (BYTE*)ReturnAddress, BP_EXEC, BreakpointCallback))
        {
#ifdef DEBUG_COMMENTS
            DebugOutput("Trace: Set breakpoint on return address 0x%p\n", ReturnAddress);
#endif
            LastContext = *ExceptionInfo->ContextRecord;
            ClearSingleStepMode(ExceptionInfo->ContextRecord);
            ReturnAddress = NULL;
			return TRUE;
        }
        else
            DebugOutput("Trace: Failed to set breakpoint on return address 0x%p\n", ReturnAddress);
    }
    else if (!StopTrace)
    {
        SetSingleStepMode(ExceptionInfo->ContextRecord, Trace);
#ifdef DEBUG_COMMENTS
        //DebugOutput("Trace: Restoring single-step mode!\n");
    }
    else
        DebugOutput("Trace: Stopping trace!n");
#else
    }
#endif
    TraceRunning = FALSE;

    return TRUE;
}

BOOL StepOutCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID DumpAddress, CIP;
    _DecodeType DecodeType;
    _DecodeResult Result;
    _OffsetType Offset = 0;
    _DecodedInst DecodedInstruction;
    unsigned DecodedInstructionsCount = 0;

	if (pBreakpointInfo == NULL)
	{
		DebugOutput("StepOutCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DebugOutput("StepOutCallback executed with NULL thread handle.\n");
		return FALSE;
	}

#ifdef _WIN64
    CIP = (PVOID)ExceptionInfo->ContextRecord->Rip;
    DecodeType = Decode64Bits;
#else
    CIP = (PVOID)ExceptionInfo->ContextRecord->Eip;
    DecodeType = Decode32Bits;
#endif

    if (!is_in_dll_range((ULONG_PTR)CIP) || g_config.trace_all || g_config.break_on_apiname)
        FilterTrace = FALSE;
    else if (InsideMonitor(NULL, CIP) || is_in_dll_range((ULONG_PTR)CIP))
        FilterTrace = TRUE;

    DebuggerOutput("StepOutCallback: Breakpoint hit by instruction at 0x%p\n", CIP);

    Result = distorm_decode(Offset, (const unsigned char*)CIP, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount);
    DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);

    if (!stricmp(Action0, "dumpebx"))
    {
        if (!stricmp(DumpSizeString, "eax"))
        {
#ifdef _WIN64
            DumpSize = ExceptionInfo->ContextRecord->Rax;
            DumpAddress = (PVOID)ExceptionInfo->ContextRecord->Rbx;
#else
            DumpSize = ExceptionInfo->ContextRecord->Eax;
            DumpAddress = (PVOID)ExceptionInfo->ContextRecord->Ebx;
#endif
            if (g_config.dumptype0)
                CapeMetaData->DumpType = g_config.dumptype0;
            else
                CapeMetaData->DumpType = UNPACKED_PE;

            if (DumpAddress && DumpSize && DumpSize < MAX_DUMP_SIZE && DumpMemory(DumpAddress, DumpSize))
                DebugOutput("StepOutCallback: Dumped region at 0x%p size 0x%x.\n", DumpAddress, DumpSize);
            else
                DebugOutput("StepOutCallback: Failed to dump region at 0x%p.\n", DumpAddress);
        }
    }

    ResumeFromBreakpoint(ExceptionInfo->ContextRecord);

    return TRUE;
}

BOOL BreakpointCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID CIP;
    _DecodeType DecodeType;
    _DecodeResult Result;
    _OffsetType Offset = 0;
    _DecodedInst DecodedInstruction;
    unsigned int DllRVA, bp, DecodedInstructionsCount = 0;
    BOOL StepOver = FALSE, ForceStepOver = FALSE;

	StopTrace = FALSE;

    if (pBreakpointInfo == NULL)
	{
		DebugOutput("BreakpointCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DebugOutput("BreakpointCallback executed with NULL thread handle.\n");
		return FALSE;
	}

    BreakpointsHit = TRUE;

    if (StepOverRegister && pBreakpointInfo->Register == StepOverRegister)
    {
#ifdef DEBUG_COMMENTS
        DebugOutput("BreakpointCallback: Clearing step-over register %d\n", StepOverRegister);
#endif
        ContextClearBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);
        StepOverRegister = 0;
    }
    else for (bp = 0; bp < NUMBER_OF_DEBUG_REGISTERS; bp++)
    {
        if (pBreakpointInfo->Register == bp)
        {
            TraceDepthCount = 0;
            if (bp == 0 && ((DWORD_PTR)pBreakpointInfo->Address != ExceptionInfo->ContextRecord->Dr0))
			{
                DebugOutput("BreakpointCallback: Breakpoint 0 hit at 0x%p\n", pBreakpointInfo->Address);
				break;
			}

            if (bp == 1 && ((DWORD_PTR)pBreakpointInfo->Address != ExceptionInfo->ContextRecord->Dr1))
			{
                DebugOutput("BreakpointCallback: Breakpoint 1 hit at 0x%p\n", pBreakpointInfo->Address);
				break;
			}

            if (bp == 2 && ((DWORD_PTR)pBreakpointInfo->Address != ExceptionInfo->ContextRecord->Dr2))
			{
                DebugOutput("BreakpointCallback: Breakpoint 2 hit at 0x%p\n", pBreakpointInfo->Address);
				break;
			}

            if (bp == 3 && ((DWORD_PTR)pBreakpointInfo->Address != ExceptionInfo->ContextRecord->Dr3))
			{
                DebugOutput("BreakpointCallback: Breakpoint 3 hit at 0x%p\n", pBreakpointInfo->Address);
				break;
			}
        }
    }

    // We can use this to put a marker in behavior log
    // extern void log_anomaly(const char *subcategory, const char *msg);
    // log_anomaly("Breakpoint hit", NULL);

#ifdef _WIN64
    CIP = (PVOID)ExceptionInfo->ContextRecord->Rip;
    DecodeType = Decode64Bits;
#else
    CIP = (PVOID)ExceptionInfo->ContextRecord->Eip;
    DecodeType = Decode32Bits;
#endif

    FilterTrace = FALSE;

    if (InsideMonitor(NULL, CIP) && g_config.trace_all == 1)
        FilterTrace = TRUE;

    if (inside_hook(CIP) && !g_config.trace_all)
        FilterTrace = TRUE;

    if (is_in_dll_range((ULONG_PTR)CIP) && !g_config.trace_all)
        FilterTrace = TRUE;

    if (g_config.trace_all)
        FilterTrace = FALSE;

#ifdef _WIN64
    if (!FilterTrace && LastContext.Rip)
    {
        memset(DebuggerBuffer, 0, MAX_PATH*sizeof(CHAR));

        if (LastContext.Rax != ExceptionInfo->ContextRecord->Rax)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RAX=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rax);

        if (LastContext.Rbx != ExceptionInfo->ContextRecord->Rbx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RBX=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rbx);

        if (LastContext.Rcx != ExceptionInfo->ContextRecord->Rcx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RCX=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rcx);

        if (LastContext.Rdx != ExceptionInfo->ContextRecord->Rdx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RDX=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rdx);

        if (LastContext.Rsi != ExceptionInfo->ContextRecord->Rsi)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RSI=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rsi);

        if (LastContext.Rdi != ExceptionInfo->ContextRecord->Rdi)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RDI=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rdi);

        if (LastContext.Rsp != ExceptionInfo->ContextRecord->Rsp)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RSP=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rsp);

        if (LastContext.Rbp != ExceptionInfo->ContextRecord->Rbp)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RBP=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rbp);

        if (LastContext.R8 != ExceptionInfo->ContextRecord->R8)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s R8=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->R8);

        if (LastContext.R9 != ExceptionInfo->ContextRecord->R9)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s R9=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->R9);

        if (LastContext.R10 != ExceptionInfo->ContextRecord->R10)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s R10=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->R10);

        if (LastContext.R11 != ExceptionInfo->ContextRecord->R11)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s R11=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->R11);

        if (LastContext.R12 != ExceptionInfo->ContextRecord->R12)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s R12=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->R12);

        if (LastContext.R13 != ExceptionInfo->ContextRecord->R13)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s R13=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->R13);

        if (LastContext.R14 != ExceptionInfo->ContextRecord->R14)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s R14=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->R14);

        if (LastContext.R15 != ExceptionInfo->ContextRecord->R15)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s R15=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->R15);

        if (LastContext.Xmm0.Low != ExceptionInfo->ContextRecord->Xmm0.Low)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s Xmm0.Low=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Xmm0.Low);

        if (LastContext.Xmm0.High != ExceptionInfo->ContextRecord->Xmm0.High)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s Xmm0.High=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Xmm0.High);

        if (LastContext.Xmm1.Low != ExceptionInfo->ContextRecord->Xmm1.Low)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s Xmm1.Low=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Xmm1.Low);

        if (LastContext.Xmm1.High != ExceptionInfo->ContextRecord->Xmm1.High)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s Xmm1.High=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Xmm1.High);
#else
    if (!FilterTrace && LastContext.Eip)
    {
        memset(DebuggerBuffer, 0, MAX_PATH*sizeof(CHAR));

        if (LastContext.Eax != ExceptionInfo->ContextRecord->Eax)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s EAX=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Eax);

        if (LastContext.Ebx != ExceptionInfo->ContextRecord->Ebx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s EBX=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Ebx);

        if (LastContext.Ecx != ExceptionInfo->ContextRecord->Ecx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s ECX=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Ecx);

        if (LastContext.Edx != ExceptionInfo->ContextRecord->Edx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s EDX=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Edx);

        if (LastContext.Esi != ExceptionInfo->ContextRecord->Esi)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s ESI=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Esi);

        if (LastContext.Edi != ExceptionInfo->ContextRecord->Edi)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s EDI=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Edi);

        if (LastContext.Esp != ExceptionInfo->ContextRecord->Esp)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s ESP=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Esp);

        if (LastContext.Ebp != ExceptionInfo->ContextRecord->Ebp)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s EBP=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Ebp);
#endif

        DebuggerOutput(DebuggerBuffer);
    }

    if (!FilterTrace)
        DebuggerOutput("\n");

    ModuleName = convert_address_to_dll_name_and_offset((ULONG_PTR)CIP, &DllRVA);

    if (ModuleName)
    {
        if (!PreviousModuleName || strncmp(ModuleName, PreviousModuleName, strlen(ModuleName)))
        {
            PCHAR FunctionName;

            __try
            {
                FunctionName = ScyllaGetExportNameByAddress(CIP, NULL);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                DebugOutput("BreakpointCallback: Error dereferencing instruction pointer 0x%p.\n", CIP);
            }
            if (FilterTrace)
                DebuggerOutput("\n");
            if (FunctionName)
                DebuggerOutput("Break at 0x%p in %s::%s (RVA 0x%x, thread %d)\n", CIP, ModuleName, FunctionName, DllRVA, GetCurrentThreadId());
            else
                DebuggerOutput("Break at 0x%p in %s (RVA 0x%x, thread %d)\n", CIP, ModuleName, DllRVA, GetCurrentThreadId());
            if (PreviousModuleName)
                free (PreviousModuleName);
            PreviousModuleName = ModuleName;
        }
    }

    if (g_config.step_out)
    {
        unsigned int Register = 1, Delta = 0, ChunkSize = 0x300, MaxInstructions = 0x100;    // Size of code to disassemble to search for ret
        _DecodedInst DecodedInstructions[0x100];

        memset(&DecodedInstructions, 0, sizeof(DecodedInstructions));
        Result = distorm_decode(Offset, (const unsigned char*)CIP, ChunkSize, DecodeType, DecodedInstructions, MaxInstructions, &DecodedInstructionsCount);

#ifdef _WIN64
        DebugOutput("BreakpointCallback: Searching for ret instruction to step-out from 0x%p (0x%x instructions) (0x%p).\n", CIP, DecodedInstructionsCount, *(DWORD_PTR*)((BYTE*) ExceptionInfo->ContextRecord->Rbp+8));
#else
        DebugOutput("BreakpointCallback: Searching for ret instruction to step-out from 0x%p (0x%x instructions) (0x%x).\n", CIP, DecodedInstructionsCount, *(DWORD*)((BYTE*) ExceptionInfo->ContextRecord->Ebp+4));
#endif
        g_config.step_out = 0;

        for (unsigned int i = 0; i < DecodedInstructionsCount; i++)
        {
            if (!strcmp(DecodedInstructions[i].mnemonic.p, "RET"))
            {
                if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &StepOverRegister, 0, (BYTE*)CIP + Delta, BP_EXEC, StepOutCallback))
                    DebugOutput("BreakpointCallback: Breakpoint %d set on ret instruction at 0x%p.\n", Register, (BYTE*)CIP + Delta);
                else
                    DebugOutput("BreakpointCallback: Failed to set breakpoint %d on ret instruction at 0x%p.\n", Register, (BYTE*)CIP + Delta);
                break;
            }

            Delta += DecodedInstructions[i].size;
        }

        return TRUE;
    }

    // We disassemble once for the action dispatcher
    if (CIP)
        Result = distorm_decode(Offset, (const unsigned char*)CIP, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount);

    ReDisassemble = FALSE;

	// Dispatch any actions
    if ((Instruction0 && !stricmp(DecodedInstruction.mnemonic.p, Instruction0)) || (!Instruction0 && bp == 0 && strlen(Action0)))
        ActionDispatcher(ExceptionInfo, DecodedInstruction, Action0);

    if ((Instruction1 && !stricmp(DecodedInstruction.mnemonic.p, Instruction1)) || (!Instruction1 && bp == 1 && strlen(Action1)))
        ActionDispatcher(ExceptionInfo, DecodedInstruction, Action1);

    if ((Instruction2 && !stricmp(DecodedInstruction.mnemonic.p, Instruction2)) || (!Instruction2 && bp == 2 && strlen(Action2)))
        ActionDispatcher(ExceptionInfo, DecodedInstruction, Action2);

    if ((Instruction3 && !stricmp(DecodedInstruction.mnemonic.p, Instruction3)) || (!Instruction3 && bp == 3 && strlen(Action3)))
        ActionDispatcher(ExceptionInfo, DecodedInstruction, Action3);

    // We disassemble a second time in case of any changes/patches
	if (ReDisassemble)
	{
#ifdef _WIN64
		CIP = (PVOID)ExceptionInfo->ContextRecord->Rip;
#else
		CIP = (PVOID)ExceptionInfo->ContextRecord->Eip;
#endif
		if (CIP)
			Result = distorm_decode(Offset, (const unsigned char*)CIP, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount);
	}

    // Instruction handling
    if (!strcmp(DecodedInstruction.mnemonic.p, "CALL"))
    {
        PCHAR ExportName;
        ReturnAddress = (PVOID)((PUCHAR)CIP + DecodedInstruction.size);

        if (DecodedInstruction.size > 4 && DecodedInstruction.operands.length && !strncmp(DecodedInstruction.operands.p, "DWORD", 5) && strncmp(DecodedInstruction.operands.p, "DWORD [E", 8))
        {
            PVOID CallTarget = *(PVOID*)((PUCHAR)CIP + DecodedInstruction.size - 4);
            __try
            {
                ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                DebugOutput("BreakpointCallback: Error dereferencing CallTarget 0x%x.\n", CallTarget);
                ExportName = NULL;
            }

            if (ExportName)
            {
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else if (!strncmp(DecodedInstruction.operands.p, "DWORD [0x", 9))
            {
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
            }
            else if (!strncmp(DecodedInstruction.operands.p, "DWORD [FS:0xc0]", 15))
            {
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
                ForceStepOver = TRUE;
            }
            else
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-28x", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
        }
        else if (DecodedInstruction.size > 4)
        {
            PVOID CallTarget = (PVOID)((PUCHAR)CIP + (int)*(DWORD*)((PUCHAR)CIP + DecodedInstruction.size - 4) + DecodedInstruction.size);
            __try
            {
                ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                DebugOutput("BreakpointCallback: Error dereferencing CallTarget 0x%x.", CallTarget);
                ExportName = NULL;
            }

            if (ExportName)
            {
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-28x", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
        }
        else if (!strncmp(DecodedInstruction.operands.p, "EAX", 3))
        {
#ifdef _WIN64
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rax;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#else
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Eax;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-28x", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#endif
        }
        else if (!strncmp(DecodedInstruction.operands.p, "EBX", 3))
        {
#ifdef _WIN64
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rbx;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#else
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Ebx;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-28x", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#endif
        }
        else if (!strncmp(DecodedInstruction.operands.p, "ECX", 3))
        {
#ifdef _WIN64
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rcx;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#else
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Ecx;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-28x", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#endif
        }
        else if (!strncmp(DecodedInstruction.operands.p, "EDX", 3))
        {
#ifdef _WIN64
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rdx;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#else
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Edx;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-28x", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#endif
        }
        else if (!strncmp(DecodedInstruction.operands.p, "EBP", 3))
        {
#ifdef _WIN64
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rbp;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#else
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Ebp;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-28x", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#endif
        }
        else
            DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);

        if (g_config.branch_trace)
        {
            //if (!FilterTrace)
                TraceDepthCount++;
        }

        if (ExportName)
        {
            for (unsigned int i = 0; i < ARRAYSIZE(g_config.trace_into_api); i++)
            {
                if (!g_config.trace_into_api[i])
                    break;
                if (!stricmp(ExportName, g_config.trace_into_api[i]))
                {
                    StepOver = FALSE;
                    TraceDepthCount--;
                    DebuggerOutput("\nBreakpointCallback: Stepping into %s\n", ExportName);
                }
            }
        }

        if (ReturnAddress && ((unsigned int)abs(TraceDepthCount) >= TraceDepthLimit && !g_config.trace_all) || (StepOver == TRUE && !g_config.trace_all) || ForceStepOver)
        {
            if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &StepOverRegister, 0, (BYTE*)ReturnAddress, BP_EXEC, BreakpointCallback))
                DebugOutput("BreakpointCallback: Failed to set breakpoint on return address 0x%p\n", ReturnAddress);
#ifdef DEBUG_COMMENTS
            else
                DebugOutput("BreakpointCallback: Breakpoint set on return address 0x%p\n", ReturnAddress);
#endif
#ifndef DEBUG_COMMENTS
            if (ForceStepOver)
#endif
                DebugOutput("BreakpointCallback: Set breakpoint on return address 0x%p\n", ReturnAddress);

            ReturnAddress = NULL;

            LastContext = *ExceptionInfo->ContextRecord;

            ResumeFromBreakpoint(ExceptionInfo->ContextRecord);

            return TRUE;
        }
        else
            TraceDepthCount++;
    }
//    else if (!strcmp(DecodedInstruction.mnemonic.p, "RET"))
//	{
//		if (!FilterTrace || g_config.trace_all)
//#ifdef _WIN64
//			DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
//#else
//			DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", (unsigned int)CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
//#endif
//		if (!g_config.trace_all)
//			TraceDepthCount--;
//	}
	else if (!FilterTrace)
#ifdef _WIN64
        DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#else
        DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", (unsigned int)CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#endif

    if (g_config.branch_trace)
        DebuggerOutput("\n");

    LastContext = *ExceptionInfo->ContextRecord;

    ResumeFromBreakpoint(ExceptionInfo->ContextRecord);

    if (ForceStepOver && ReturnAddress)
    {
        if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &StepOverRegister, 0, (BYTE*)ReturnAddress, BP_EXEC, BreakpointCallback))
        {
            DebugOutput("BreakpointCallback: Set breakpoint on return address 0x%p\n", ReturnAddress);
            LastContext = *ExceptionInfo->ContextRecord;
            ReturnAddress = NULL;
        }
        else
            DebugOutput("BreakpointCallback: Failed to set breakpoint on return address 0x%p\n", ReturnAddress);
    }
    else if (!StopTrace)
		DoSetSingleStepMode(pBreakpointInfo->Register, ExceptionInfo->ContextRecord, Trace);

    return TRUE;
}

BOOL BreakOnReturnCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID CIP;

	if (pBreakpointInfo == NULL)
	{
		DebugOutput("BreakOnReturnCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DebugOutput("BreakOnReturnCallback executed with NULL thread handle.\n");
		return FALSE;
	}

    BreakpointsHit = TRUE;

#ifdef _WIN64
    CIP = (PVOID)ExceptionInfo->ContextRecord->Rip;
    ReturnAddress = *(PVOID*)(ExceptionInfo->ContextRecord->Rsp);
#else
    CIP = (PVOID)ExceptionInfo->ContextRecord->Eip;
    ReturnAddress = *(PVOID*)(ExceptionInfo->ContextRecord->Esp);
#endif

    if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &StepOverRegister, 0, (BYTE*)ReturnAddress, BP_EXEC, BreakpointCallback))
        DebugOutput("BreakOnReturnCallback: Breakpoint set on return address at 0x%p.\n", ReturnAddress);
    else
        DebugOutput("BreakOnReturnCallback: Failed to set breakpoint on return address at 0x%p.\n", ReturnAddress);

    ReturnAddress = NULL;

    ResumeFromBreakpoint(ExceptionInfo->ContextRecord);

    return TRUE;
}

BOOL WriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID CIP;
    _DecodeType DecodeType;
    _DecodeResult Result;
    _OffsetType Offset = 0;
    _DecodedInst DecodedInstruction;
    unsigned int DecodedInstructionsCount = 0;
    char OutputBuffer[MAX_PATH] = "";

	if (pBreakpointInfo == NULL)
	{
		DebugOutput("WriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DebugOutput("WriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

    BreakpointsHit = TRUE;

#ifdef _WIN64
    CIP = (PVOID)ExceptionInfo->ContextRecord->Rip;
    DecodeType = Decode64Bits;
#else
    CIP = (PVOID)ExceptionInfo->ContextRecord->Eip;
    DecodeType = Decode32Bits;
#endif

    Result = distorm_decode(Offset, (const unsigned char*)CIP, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount);

    DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);

    return TRUE;
}

BOOL BreakpointOnReturn(PVOID Address)
{
    unsigned int Register;

    // We reset the trace depth count
    TraceDepthCount = 0;

    if (!SetNextAvailableBreakpoint(GetCurrentThreadId(), &Register, 0, Address, BP_EXEC, BreakpointCallback))
    {
        DebugOutput("BreakpointOnReturn: failed to set breakpoint.\n");
        return FALSE;
    }

    // TODO: add option to break once only, clearing bp
    DebugOutput("BreakpointOnReturn: execution breakpoint set at 0x%p with register %d.", Address, Register);
    return TRUE;
}

BOOL SetInitialBreakpoints(PVOID ImageBase)
{
    DWORD_PTR BreakpointVA;
    DWORD Register;

    if (BreakpointsHit)
        return TRUE;

    if (procname0 && !stristr(CommandLine, procname0))
        return TRUE;

    if (!DebuggerInitialised)
    {
        if (!InitialiseDebugger())
        {
            DebugOutput("SetInitialBreakpoints: Failed to initialise debugger.\n");
            return FALSE;
        }
    }

    StepCount = 0;
    TraceDepthCount = 0;
    InstructionCount = 0;
    StopTrace = FALSE;
    ModTimestamp = FALSE;
	function_id = -1;
	subfunction_id = -1;

    if (!StepLimit)
        StepLimit = SINGLE_STEP_LIMIT;

    if (TraceDepthLimit == 0xFFFFFFFF)
        TraceDepthLimit = 1;

    if (!ImageBase)
        ImageBase = GetModuleHandle(NULL);

#ifdef STANDALONE
    TraceDepthLimit = 5;
#endif

    if (g_config.break_on_apiname_set)
    {
        HANDLE Module = GetModuleHandle(g_config.break_on_modname);
        if (Module)
            bp0 = GetProcAddress(Module, g_config.break_on_apiname);
        else
            DebuggerOutput("Failed to get base for module (%s).", g_config.break_on_modname);
        if (bp0)
            DebuggerOutput("bp0 set to 0x%p (%s::%s).", bp0, g_config.break_on_modname, g_config.break_on_apiname);
        else
            DebuggerOutput("Failed to get address for function %s::%s.", g_config.break_on_modname, g_config.break_on_apiname);
    }

    if (EntryPointRegister)
    {
        PVOID EntryPoint = (PVOID)GetEntryPointVA((DWORD_PTR)ImageBase);

        if (EntryPoint)
        {
            // break-on-entrypoint uses bp0
            Register = EntryPointRegister - 1;

            if (SetBreakpoint(Register, 0, (BYTE*)EntryPoint, BP_EXEC, BreakpointCallback))
            {
                DebuggerOutput("Breakpoint %d set on entry point at 0x%p.", Register, EntryPoint);
                BreakpointsSet = TRUE;
                bp0 = EntryPoint;
            }
            else
            {
                DebuggerOutput("SetBreakpoint on entry point failed.\n");
                BreakpointsSet = FALSE;
                return FALSE;
            }
        }
    }
    else if (bp0)
    {
        Register = 0;
        PVOID Callback;

        if (g_config.file_offsets)
        {
            if (!IsDisguisedPEHeader(ImageBase))
            {
                DebugOutput("SetInitialBreakpoints: File offsets cannot be applied to non-PE image at 0x%p.\n", ImageBase);
                BreakpointsSet = FALSE;
                return FALSE;
            }
            BreakpointVA = FileOffsetToVA((DWORD_PTR)ImageBase, (DWORD_PTR)bp0);
        }
        else
        {
            if ((SIZE_T)bp0 > RVA_LIMIT)
                BreakpointVA = (DWORD_PTR)bp0;
            else
                BreakpointVA = (DWORD_PTR)ImageBase + (DWORD_PTR)bp0;
        }

        if (!Type0)
        {
            Type0 = BP_EXEC;
            Callback = BreakpointCallback;
        }
        else if (Type0 == BP_WRITE)
            Callback = BreakpointCallback;
            //Callback = WriteCallback;

        if (SetBreakpoint(Register, 0, (BYTE*)BreakpointVA, Type0, Callback))
        {
            DebugOutput("SetInitialBreakpoints: Breakpoint %d set on address 0x%p (RVA 0x%x, type %d)\n", Register, BreakpointVA, bp0, Type0);
            BreakpointsSet = TRUE;
        }
        else
        {
            DebugOutput("SetInitialBreakpoints: SetBreakpoint failed for breakpoint %d.\n", Register);
            BreakpointsSet = FALSE;
            return FALSE;
        }
    }

    if (bp1)
    {
        Register = 1;
        PVOID Callback;

        if (g_config.file_offsets)
            BreakpointVA = FileOffsetToVA((DWORD_PTR)ImageBase, (DWORD_PTR)bp1);
        else
        {
            if ((SIZE_T)bp1 > RVA_LIMIT)
                BreakpointVA = (DWORD_PTR)bp1;
            else
                BreakpointVA = (DWORD_PTR)ImageBase + (DWORD_PTR)bp1;
        }

        if (!Type1)
        {
            Type1 = BP_EXEC;
            Callback = BreakpointCallback;
        }
        else if (Type1 == BP_WRITE)
            Callback = WriteCallback;
        else if (Type1 == BP_READWRITE)
            Callback = WriteCallback;

        if (SetBreakpoint(Register, 0, (BYTE*)BreakpointVA, Type1, Callback))
        {
            DebugOutput("SetInitialBreakpoints: Breakpoint %d set on address 0x%p (RVA 0x%x, type %d)\n", Register, BreakpointVA, bp1, Type1);
            BreakpointsSet = TRUE;
        }
        else
        {
            DebugOutput("SetInitialBreakpoints: SetBreakpoint failed for breakpoint %d.\n", Register);
            BreakpointsSet = FALSE;
            return FALSE;
        }
    }

    if (bp2)
    {
        Register = 2;
        PVOID Callback;

        if (g_config.file_offsets)
            BreakpointVA = FileOffsetToVA((DWORD_PTR)ImageBase, (DWORD_PTR)bp2);
        else
        {
            if ((SIZE_T)bp2 > RVA_LIMIT)
                BreakpointVA = (DWORD_PTR)bp2;
            else
                BreakpointVA = (DWORD_PTR)ImageBase + (DWORD_PTR)bp2;
        }

        if (!Type2)
        {
            Type1 = BP_EXEC;
            Callback = BreakpointCallback;
        }
        else if (Type2 == BP_WRITE)
            Callback = WriteCallback;
        else if (Type2 == BP_READWRITE)
            Callback = WriteCallback;

        if (SetBreakpoint(Register, 0, (BYTE*)BreakpointVA, Type2, Callback))
        {
            DebugOutput("SetInitialBreakpoints: Breakpoint %d set on address 0x%p (RVA 0x%x, type %d)\n", Register, BreakpointVA, bp2, Type2);
            BreakpointsSet = TRUE;
        }
        else
        {
            DebugOutput("SetInitialBreakpoints: SetBreakpoint failed for breakpoint %d.\n", Register);
            BreakpointsSet = FALSE;
            return FALSE;
        }
    }

    if (bp3)
    {
        Register = 3;
        PVOID Callback;

        if (g_config.file_offsets)
            BreakpointVA = FileOffsetToVA((DWORD_PTR)ImageBase, (DWORD_PTR)bp3);
        else
        {
            if ((SIZE_T)bp3 > RVA_LIMIT)
                BreakpointVA = (DWORD_PTR)bp3;
            else
                BreakpointVA = (DWORD_PTR)ImageBase + (DWORD_PTR)bp3;
        }

        if (!Type3)
        {
            Type1 = BP_EXEC;
            Callback = BreakpointCallback;
        }
        else if (Type3 == BP_WRITE)
            Callback = WriteCallback;

        if (SetBreakpoint(Register, 0, (BYTE*)BreakpointVA, Type3, Callback))
        {
            DebugOutput("SetInitialBreakpoints: Breakpoint %d set on address 0x%p (RVA 0x%x, type %d)\n", Register, BreakpointVA, bp3, Type3);
            BreakpointsSet = TRUE;
        }
        else
        {
            DebugOutput("SetInitialBreakpoints: SetBreakpoint failed for breakpoint %d.\n", Register);
            BreakpointsSet = FALSE;
            return FALSE;
        }
    }

    if (!bp0 && g_config.br0)
    {
        Register = 0;

        if (g_config.file_offsets)
        {
            if (!IsDisguisedPEHeader(ImageBase))
            {
                DebugOutput("SetInitialBreakpoints: File offsets cannot be applied to non-PE image at 0x%p.\n", ImageBase);
                BreakpointsSet = FALSE;
                return FALSE;
            }
            BreakpointVA = FileOffsetToVA((DWORD_PTR)ImageBase, (DWORD_PTR)g_config.br0);
        }
        else
        {
            if ((SIZE_T)g_config.br0 > RVA_LIMIT)
                BreakpointVA = (DWORD_PTR)g_config.br0;
            else
                BreakpointVA = (DWORD_PTR)ImageBase + (DWORD_PTR)g_config.br0;
        }

        if (SetBreakpoint(Register, 0, (BYTE*)BreakpointVA, BP_EXEC, BreakOnReturnCallback))
        {
            DebugOutput("SetInitialBreakpoints: Breakpoint-on-return %d set on address 0x%p (RVA 0x%x, type %d)\n", Register, BreakpointVA, g_config.br0, BP_EXEC);
            BreakpointsSet = TRUE;
        }
        else
        {
            DebugOutput("SetInitialBreakpoints: SetBreakpoint failed for breakpoint %d.\n", Register);
            BreakpointsSet = FALSE;
            return FALSE;
        }
    }

    if (!bp1 && g_config.br1)
    {
        Register = 1;

        if (g_config.file_offsets)
        {
            if (!IsDisguisedPEHeader(ImageBase))
            {
                DebugOutput("SetInitialBreakpoints: File offsets cannot be applied to non-PE image at 0x%p.\n", ImageBase);
                BreakpointsSet = FALSE;
                return FALSE;
            }
            BreakpointVA = FileOffsetToVA((DWORD_PTR)ImageBase, (DWORD_PTR)g_config.br1);
        }
        else
        {
            if ((SIZE_T)g_config.br1 > RVA_LIMIT)
                BreakpointVA = (DWORD_PTR)g_config.br1;
            else
                BreakpointVA = (DWORD_PTR)ImageBase + (DWORD_PTR)g_config.br1;
        }

        if (SetBreakpoint(Register, 0, (BYTE*)BreakpointVA, BP_EXEC, BreakOnReturnCallback))
        {
            DebugOutput("SetInitialBreakpoints: Breakpoint-on-return %d set on address 0x%p (RVA 0x%x, type %d)\n", Register, BreakpointVA, g_config.br1, BP_EXEC);
            BreakpointsSet = TRUE;
        }
        else
        {
            DebugOutput("SetInitialBreakpoints: SetBreakpoint failed for breakpoint %d.\n", Register);
            BreakpointsSet = FALSE;
            return FALSE;
        }
    }

    return BreakpointsSet;
}
