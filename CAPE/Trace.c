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
#define CHUNKSIZE 0x10
#define RVA_LIMIT 0x200000
#define DoClearZeroFlag 1
#define DoSetZeroFlag   2
#define PrintEAX		3

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern void ErrorOutput(_In_ LPCTSTR lpOutputString, ...);
extern void DebuggerOutput(_In_ LPCTSTR lpOutputString, ...);
extern int DumpImageInCurrentProcess(LPVOID ImageBase);
extern int DumpMemory(LPVOID Buffer, SIZE_T Size);
extern PCHAR GetNameBySsn(unsigned int Number);
extern void log_anomaly(const char *subcategory, const char *msg);
extern char *convert_address_to_dll_name_and_offset(ULONG_PTR addr, unsigned int *offset);
extern BOOL is_in_dll_range(ULONG_PTR addr);
extern DWORD_PTR FileOffsetToVA(DWORD_PTR ModuleBase, DWORD_PTR dwOffset);
extern DWORD_PTR GetEntryPointVA(DWORD_PTR ModuleBase);
extern BOOL ScyllaGetSectionByName(PVOID ImageBase, char* Name, PVOID* SectionData, SIZE_T* SectionSize);
extern PCHAR ScyllaGetExportNameByAddress(PVOID Address, PCHAR* ModuleName);
extern ULONG_PTR g_our_dll_base;
extern BOOL inside_hook(LPVOID Address);
extern void loq(int index, const char *category, const char *name,
	int is_success, ULONG_PTR return_value, const char *fmt, ...);
extern void log_flush();
extern PVOID _KiUserExceptionDispatcher;

char *ModuleName, *PreviousModuleName;
PVOID ModuleBase, DumpAddress, ReturnAddress, BreakOnReturnAddress, BreakOnNtContinueCallback;
BOOL BreakpointsSet, BreakpointsHit, FilterTrace, StopTrace, ModTimestamp, ReDisassemble;
BOOL GetSystemTimeAsFileTimeImported, PayloadMarker, PayloadDumped, TraceRunning, BreakOnNtContinue;
unsigned int DumpCount, Correction, StepCount, StepLimit, TraceDepthLimit, BreakOnReturnRegister;
char Action0[MAX_PATH], Action1[MAX_PATH], Action2[MAX_PATH], Action3[MAX_PATH];
char *Instruction0, *Instruction1, *Instruction2, *Instruction3, *procname0;
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

VOID TraceOutput(PVOID Address, _DecodedInst DecodedInstruction)
{
#ifdef _WIN64
	DebuggerOutput("0x%p  %-24s %-6s%-4s%-30s", Address, (char*)_strupr(DecodedInstruction.instructionHex.p), (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#else
	DebuggerOutput("0x%p  %-24s %-6s%-4s%-30s", (unsigned int)Address, (char*)_strupr(DecodedInstruction.instructionHex.p), (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#endif
}

VOID TraceOutputFuncName(PVOID Address, _DecodedInst DecodedInstruction, char* FuncName)
{
	DebuggerOutput("0x%p  %-24s %-6s%-4s%-30s", Address, (char*)_strupr(DecodedInstruction.instructionHex.p), (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", FuncName);
}

VOID TraceOutputFuncAddress(PVOID Address, _DecodedInst DecodedInstruction, PVOID FuncAddress)
{
	DebuggerOutput("0x%p  %-24s %-6s%-4s0x%-28p", Address, (char*)_strupr(DecodedInstruction.instructionHex.p), (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", FuncAddress);
}

void DoTraceOutput(PVOID Address)
{
	_DecodeType DecodeType;
	_DecodeResult Result;
	_OffsetType Offset = 0;
	_DecodedInst DecodedInstruction;
	unsigned int DecodedInstructionsCount = 0;

#ifdef _WIN64
	DecodeType = Decode64Bits;
#else
	DecodeType = Decode32Bits;
#endif

	if (!Address)
		return;

	Result = distorm_decode(Offset, (const unsigned char*)Address, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount);

	if (!DecodedInstruction.size)
		return;

	TraceOutput(Address, DecodedInstruction);
	DebuggerOutput("\n");
}

SIZE_T StrTest(PCHAR StrCandidate, PCHAR OutputBuffer, SIZE_T BufferSize)
{
	if (!IsAddressAccessible((PVOID)StrCandidate))
        return 0;

	SIZE_T Count;
	if (!ReadProcessMemory(GetCurrentProcess(), StrCandidate, OutputBuffer, BufferSize, &Count))
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("StrTest: ReadProcessMemory failed on string candidate at 0x%p", StrCandidate);
#endif
		return 0;
	}
	PCHAR Character = (PCHAR)OutputBuffer;
	Count = 0;
	while (*Character)
	{
		if (Count == BufferSize)
			break;
		// Restrict to ASCII range
		if ((unsigned int)*Character < 0x0a || (unsigned int)*Character > 0x7E)
		{
			*Character = 0;
			break;
		}
		if (*Character == 0x0d)
			*Character = 0x20;
		Character++;
		Count++;
	}
    return Count;
}

SIZE_T StrTestW(PWCHAR StrCandidate, PWCHAR OutputBuffer, SIZE_T BufferSize)
{
	if (!IsAddressAccessible((PVOID)StrCandidate))
        return 0;

	SIZE_T Count;
	if (!ReadProcessMemory(GetCurrentProcess(), StrCandidate, OutputBuffer, BufferSize, &Count))
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("StrTestW: ReadProcessMemory failed on string candidate at 0x%p", StrCandidate);
#endif
		return 0;
	}
	PWCHAR Character = (PWCHAR)OutputBuffer;
	Count = 0;
	while (*Character)
	{
		if (Count == BufferSize)
			break;
		// Restrict to ASCII range
		if ((unsigned int)*Character < 0x0a || (unsigned int)*Character > 0x7E)
		{
			*Character = 0;
			break;
		}
		if (*Character == 0x0d)
			*Character = 0x20;
		Character++;
		Count++;
	}
    return Count;
}

void StringCheck(PVOID PossibleString)
{
	char OutputBuffer[MAX_PATH] = "";
	WCHAR OutputBufferW[MAX_PATH] = L"";

	SIZE_T Size = StrTest(PossibleString, OutputBuffer, MAX_PATH);
	if (Size > 64)
		DebuggerOutput(" \"%.64s...\"", (PCHAR)OutputBuffer);
	else if (Size > 3)
		DebuggerOutput(" \"%.64s\"", (PCHAR)OutputBuffer);
	else
	{
		Size = StrTestW(PossibleString, OutputBufferW, MAX_PATH*sizeof(WCHAR));
		if (Size > 64)
			DebuggerOutput(" L\"%.64ws...\"", (PWCHAR)OutputBufferW);
		else if (Size > 3)
			DebuggerOutput(" L\"%.64ws\"", (PWCHAR)OutputBufferW);
	}
}

PVOID GetRegister(PCONTEXT Context, char* RegString)
{
	PVOID Register = NULL;
	if (!Context || !RegString)
        return NULL;
    __try
    {
#ifdef _WIN64
        if (!stricmp(RegString, "eax"))
			Register = (PVOID)Context->Rax;
        else if (!stricmp(RegString, "ebx"))
			Register = (PVOID)Context->Rbx;
        else if (!stricmp(RegString, "ecx"))
			Register = (PVOID)Context->Rcx;
        else if (!stricmp(RegString, "edx"))
			Register = (PVOID)Context->Rdx;
        else if (!stricmp(RegString, "esi"))
			Register = (PVOID)Context->Rsi;
        else if (!stricmp(RegString, "edi"))
			Register = (PVOID)Context->Rdi;
        else if (!stricmp(RegString, "esp"))
			Register = (PVOID)Context->Rsp;
        else if (!stricmp(RegString, "ebp"))
			Register = (PVOID)Context->Rbp;
        else if (!stricmp(RegString, "eip"))
			Register = (PVOID)Context->Rip;
        else if (!stricmp(RegString, "rax"))
			Register = (PVOID)Context->Rax;
        else if (!stricmp(RegString, "rbx"))
			Register = (PVOID)Context->Rbx;
        else if (!stricmp(RegString, "rcx"))
			Register = (PVOID)Context->Rcx;
        else if (!stricmp(RegString, "rdx"))
			Register = (PVOID)Context->Rdx;
        else if (!stricmp(RegString, "rsi"))
			Register = (PVOID)Context->Rsi;
        else if (!stricmp(RegString, "rdi"))
			Register = (PVOID)Context->Rdi;
        else if (!stricmp(RegString, "rsp"))
			Register = (PVOID)Context->Rsp;
        else if (!stricmp(RegString, "rbp"))
			Register = (PVOID)Context->Rbp;
        else if (!stricmp(RegString, "rip"))
			Register = (PVOID)Context->Rip;
#else
        if (!stricmp(RegString, "eax"))
			Register = (PVOID)Context->Eax;
        else if (!stricmp(RegString, "ebx"))
			Register = (PVOID)Context->Ebx;
        else if (!stricmp(RegString, "ecx"))
			Register = (PVOID)Context->Ecx;
        else if (!stricmp(RegString, "edx"))
			Register = (PVOID)Context->Edx;
        else if (!stricmp(RegString, "esi"))
			Register = (PVOID)Context->Esi;
        else if (!stricmp(RegString, "edi"))
			Register = (PVOID)Context->Edi;
        else if (!stricmp(RegString, "esp"))
			Register = (PVOID)Context->Esp;
        else if (!stricmp(RegString, "ebp"))
			Register = (PVOID)Context->Ebp;
        else if (!stricmp(RegString, "eip"))
			Register = (PVOID)Context->Eip;
#endif
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        ;
    }
    return Register;
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

void NopInstruction(PCONTEXT Context)
{
	PVOID CIP;
	_DecodeType DecodeType;
	_DecodeResult Result;
	_OffsetType Offset = 0;
	_DecodedInst DecodedInstruction;
	unsigned int DecodedInstructionsCount = 0;
	DWORD OldProtect;

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

	VirtualProtect(CIP, DecodedInstruction.size, PAGE_EXECUTE_READWRITE, &OldProtect);
	for (unsigned int i=0; i<DecodedInstruction.size; i++)
		memcpy((PVOID)((PUCHAR)CIP + i), "\x90", 1);
	VirtualProtect(CIP, DecodedInstruction.size, OldProtect, &OldProtect);

	return;
}

void WriteRet(PCONTEXT Context)
{
	PVOID CIP;
	_DecodeType DecodeType;
	_DecodeResult Result;
	_OffsetType Offset = 0;
	_DecodedInst DecodedInstruction;
	unsigned int DecodedInstructionsCount = 0;
	DWORD OldProtect;

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

	VirtualProtect(CIP, DecodedInstruction.size, PAGE_EXECUTE_READWRITE, &OldProtect);
	memcpy(CIP, "\xc3", 1);
	VirtualProtect(CIP, DecodedInstruction.size, OldProtect, &OldProtect);

	return;
}

void ActionDispatcher(struct _EXCEPTION_POINTERS* ExceptionInfo, _DecodedInst DecodedInstruction, PCHAR Action)
{
	// This could be further optimised per action but this is safe at least
	ReDisassemble = TRUE;

	PVOID Target = NULL, TargetArg = NULL;
	BOOL TargetSet = FALSE;
#ifdef _WIN64
	PVOID CIP = (PVOID)ExceptionInfo->ContextRecord->Rip;
#else
	PVOID CIP = (PVOID)ExceptionInfo->ContextRecord->Eip;
#endif

	char *p = strchr(Action, ':');
	if (p) {
		char *q = strchr(p+1, ':');
		if (q && *(q+1) == ':')
		{
			*q = '\0';
			HANDLE Module = GetModuleHandle(p+1);
			*q = ':';
			if (Module)
			{
				Target = GetProcAddress(Module, q+2);
				CloseHandle(Module);
				if (!Target)
				{
					char *endptr;
					errno = 0;
					Target = (PVOID)(DWORD_PTR)strtoul(q+2, &endptr, 0);
					if (errno || endptr == q+2)
						DebuggerOutput("ActionDispatcher: Failed to get target: %s.\n", p+1);
					else
					{
						TargetSet = TRUE;
#ifdef DEBUG_COMMENTS
						DebuggerOutput("ActionDispatcher: Target 0x%p (%s).\n", Target, p+1);
#endif
					}
				}
#ifdef DEBUG_COMMENTS
				else
					DebuggerOutput("ActionDispatcher: Target 0x%p (%s).\n", Target, p+1);
#endif
			}
			*q = '\0';
			Target = GetRegister(ExceptionInfo->ContextRecord, p+1);
			*q = ':';
			if (Target)
			{
				TargetSet = TRUE;
				TargetArg = GetRegister(ExceptionInfo->ContextRecord, q+2);
			}
			//else
			//	DebuggerOutput("ActionDispatcher: Failed to get base for target module (%s).\n", p+1);
		}
		else {
			HANDLE Module = GetModuleHandle(p+1);
			if (Module)
				Target = (PVOID)(DWORD_PTR)Module;
			else
				Target = (GetRegister(ExceptionInfo->ContextRecord, p+1));
			if (!Target)
			{
				char *endptr;
				errno = 0;
				Target = (PVOID)(DWORD_PTR)strtoul(p+1, &endptr, 0);
				if (errno || endptr == p+1)
				{
					errno = 0;
					Target = (PVOID)_strtoui64(p+1, &endptr, 0);
					if (errno || endptr == p+1)
						DebuggerOutput("ActionDispatcher: Failed to get target: %s.\n", p+1);
					else
					{
						TargetSet = TRUE;
#ifdef DEBUG_COMMENTS
						DebuggerOutput("ActionDispatcher: Target 0x%p (%s).\n", Target, p+1);
#endif
					}
				}
				else
				{
					TargetSet = TRUE;
#ifdef DEBUG_COMMENTS
					DebuggerOutput("ActionDispatcher: Target 0x%p (%s).\n", Target, p+1);
#endif
				}
			}
			else
			{
				TargetSet = TRUE;
#ifdef DEBUG_COMMENTS
				DebuggerOutput("ActionDispatcher: Target 0x%p.\n", Target);
#endif
			}
		}
	}

	if (!strnicmp(Action, "SetEax", 6))
	{
		if (Target || TargetSet)
		{
#ifdef _WIN64
			ExceptionInfo->ContextRecord->Rax = (DWORD64)Target;
			DebuggerOutput("ActionDispatcher: %s detected, setting RAX to 0x%x.\n", DecodedInstruction.mnemonic.p, ExceptionInfo->ContextRecord->Rax);
#else
			ExceptionInfo->ContextRecord->Eax = (DWORD)Target;
			DebuggerOutput("ActionDispatcher: %s detected, setting EAX to 0x%x.\n", DecodedInstruction.mnemonic.p, ExceptionInfo->ContextRecord->Eax);
#endif
		}
		else
			DebuggerOutput("ActionDispatcher: Cannot set EAX - target value missing.\n");
	}
	else if (!strnicmp(Action, "SetEbx", 6))
	{
		if (Target || TargetSet)
		{
#ifdef _WIN64
			ExceptionInfo->ContextRecord->Rbx = (DWORD64)Target;
			DebuggerOutput("ActionDispatcher: %s detected, setting RBX to 0x%x.\n", DecodedInstruction.mnemonic.p, ExceptionInfo->ContextRecord->Rbx);
#else
			ExceptionInfo->ContextRecord->Ebx = (DWORD)Target;
			DebuggerOutput("ActionDispatcher: %s detected, setting EBX to 0x%x.\n", DecodedInstruction.mnemonic.p, ExceptionInfo->ContextRecord->Ebx);
#endif
		}
		else
			DebuggerOutput("ActionDispatcher: Cannot set EBX - target value missing.\n");
	}
	else if (!strnicmp(Action, "SetEcx", 6))
	{
		if (Target || TargetSet)
		{
#ifdef _WIN64
			ExceptionInfo->ContextRecord->Rcx = (DWORD64)Target;
			DebuggerOutput("ActionDispatcher: %s detected, setting RCX to 0x%x.\n", DecodedInstruction.mnemonic.p, ExceptionInfo->ContextRecord->Rcx);
#else
			ExceptionInfo->ContextRecord->Ecx = (DWORD)Target;
			DebuggerOutput("ActionDispatcher: %s detected, setting ECX to 0x%x.\n", DecodedInstruction.mnemonic.p, ExceptionInfo->ContextRecord->Ecx);
#endif
		}
		else
			DebuggerOutput("ActionDispatcher: Cannot set ECX - target value missing.\n");
	}
	else if (!strnicmp(Action, "SetEdx", 6))
	{
		if (Target || TargetSet)
		{
#ifdef _WIN64
			ExceptionInfo->ContextRecord->Rdx = (DWORD64)Target;
			DebuggerOutput("ActionDispatcher: %s detected, setting RDX to 0x%x.\n", DecodedInstruction.mnemonic.p, ExceptionInfo->ContextRecord->Rdx);
#else
			ExceptionInfo->ContextRecord->Edx = (DWORD)Target;
			DebuggerOutput("ActionDispatcher: %s detected, setting EDX to 0x%x.\n", DecodedInstruction.mnemonic.p, ExceptionInfo->ContextRecord->Edx);
#endif
		}
		else
			DebuggerOutput("ActionDispatcher: Cannot set EDX - target value missing.\n");
	}
	else if (!strnicmp(Action, "SetEsi", 6))
	{
		if (Target || TargetSet)
		{
#ifdef _WIN64
			ExceptionInfo->ContextRecord->Rsi = (DWORD64)Target;
			DebuggerOutput("ActionDispatcher: %s detected, setting RSI to 0x%x.\n", DecodedInstruction.mnemonic.p, ExceptionInfo->ContextRecord->Rsi);
#else
			ExceptionInfo->ContextRecord->Esi = (DWORD)Target;
			DebuggerOutput("ActionDispatcher: %s detected, setting ESI to 0x%x.\n", DecodedInstruction.mnemonic.p, ExceptionInfo->ContextRecord->Esi);
#endif
		}
		else
			DebuggerOutput("ActionDispatcher: Cannot set ESI - target value missing.\n");
	}
	else if (!strnicmp(Action, "SetEdi", 6))
	{
		if (Target || TargetSet)
		{
#ifdef _WIN64
			ExceptionInfo->ContextRecord->Rdi = (DWORD64)Target;
			DebuggerOutput("ActionDispatcher: %s detected, setting RDI to 0x%x.\n", DecodedInstruction.mnemonic.p, ExceptionInfo->ContextRecord->Rdi);
#else
			ExceptionInfo->ContextRecord->Edi = (DWORD)Target;
			DebuggerOutput("ActionDispatcher: %s detected, setting EDI to 0x%x.\n", DecodedInstruction.mnemonic.p, ExceptionInfo->ContextRecord->Edi);
#endif
		}
		else
			DebuggerOutput("ActionDispatcher: Cannot set EDI - target value missing.\n");
	}
	else if (!stricmp(Action, "ClearZeroFlag"))
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
	else if (!stricmp(Action, "ClearCarryFlag"))
	{
		ClearCarryFlag(ExceptionInfo->ContextRecord);
		DebuggerOutput("ActionDispatcher: %s detected, clearing Carry flag.\n", DecodedInstruction.mnemonic.p);
	}
	else if (!stricmp(Action, "SetCarryFlag"))
	{
		SetCarryFlag(ExceptionInfo->ContextRecord);
		DebuggerOutput("ActionDispatcher: %s detected, setting Carry flag.\n", DecodedInstruction.mnemonic.p);
	}
	else if (!stricmp(Action, "FlipCarryFlag"))
	{
		FlipCarryFlag(ExceptionInfo->ContextRecord);
		DebuggerOutput("ActionDispatcher: %s detected, flipping Carry flag.\n", DecodedInstruction.mnemonic.p);
	}
	else if (!strnicmp(Action, "Jmp", 3))
	{
		if (!Target && !strnicmp(DecodedInstruction.mnemonic.p, "j", 1))	// force an existing (conditional) jump
		{
			if (DecodedInstruction.size > 4 && DecodedInstruction.operands.length && !strncmp(DecodedInstruction.operands.p, "DWORD", 5) && strncmp(DecodedInstruction.operands.p, "DWORD [E", 8))
			{
				if (!strncmp(DecodedInstruction.operands.p, "DWORD [0x", 9))
					Target = *(PVOID*)(*(PVOID*)((PUCHAR)CIP + DecodedInstruction.size - 4));
				else
					Target = *(PVOID*)((PUCHAR)CIP + DecodedInstruction.size - 4);
			}
			else if (DecodedInstruction.size > 4)
				Target = (PVOID)((PUCHAR)CIP + (int)*(DWORD*)((PUCHAR)CIP + DecodedInstruction.size - 4) + DecodedInstruction.size);
			else if (DecodedInstruction.size == 2)
				Target = (PVOID)((PUCHAR)CIP + (signed char)*((PUCHAR)CIP + 1) + DecodedInstruction.size);
		}
		else if (Target)
		{
			if ((unsigned int)(DWORD_PTR)Target < 0x10000)
			{
#ifdef _WIN64
				Target = (PUCHAR)Target + ExceptionInfo->ContextRecord->Rip;
#else
				Target = (PUCHAR)Target + ExceptionInfo->ContextRecord->Eip;
#endif
			}
		}
		else
			DebuggerOutput("ActionDispatcher: No target specified for jmp action.\n");

		if (Target)
		{
			TraceOutput(CIP, DecodedInstruction);
#ifdef _WIN64
			ExceptionInfo->ContextRecord->Rip = (QWORD)Target;
#else
			ExceptionInfo->ContextRecord->Eip = (DWORD)Target;
#endif
			DebuggerOutput("\nActionDispatcher: %s detected, forcing jmp to 0x%p.\n", DecodedInstruction.mnemonic.p, Target);
		}
	}
	else if (!strnicmp(Action, "Count", 5))
	{
		if (Target)
		{
            TraceDepthCount = 0;
			StepLimit = (unsigned int)(DWORD_PTR)Target;
			DebuggerOutput("ActionDispatcher: %s detected, setting count to 0x%x.\n", DecodedInstruction.mnemonic.p, StepLimit);
		}
		else
			DebuggerOutput("ActionDispatcher: Cannot set count - target value missing.\n");
    }
	else if (!strnicmp(Action, "Skip", 4))
	{
		// We want the skipped instruction to appear in the trace
		TraceOutput(CIP, DecodedInstruction);
		SkipInstruction(ExceptionInfo->ContextRecord);
		DebuggerOutput("\nActionDispatcher: %s detected, skipping instruction.\n", DecodedInstruction.mnemonic.p);
	}
	else if (!strnicmp(Action, "Nop", 3))
	{
		// We want the nopped instruction to appear in the trace
		TraceOutput(CIP, DecodedInstruction);
		NopInstruction(ExceptionInfo->ContextRecord);
		DebuggerOutput("\nActionDispatcher: %s detected, nopping instruction.\n", DecodedInstruction.mnemonic.p);
	}
	else if (!strnicmp(Action, "Wret", 4))
	{
		WriteRet(ExceptionInfo->ContextRecord);
		DebuggerOutput("\nActionDispatcher: %s detected, ret written.\n", DecodedInstruction.mnemonic.p);
	}
	else if (!strnicmp(Action, "GoTo", 4))
	{
		if (Target)
		{
			TraceOutput(CIP, DecodedInstruction);
			if (p)
				DebuggerOutput("\nActionDispatcher: GoTo target 0x%p (%s).\n", Target, p+1);
			else
				DebuggerOutput("\nActionDispatcher: GoTo target 0x%p.\n", Target);
#ifdef _WIN64
			ExceptionInfo->ContextRecord->Rip = (QWORD)Target;
#else
			ExceptionInfo->ContextRecord->Eip = (DWORD)Target;
#endif
		}
		else
			DebuggerOutput("ActionDispatcher: Cannot GoTo - target value missing.\n");
	}
	else if (!strnicmp(Action, "Push", 4))
	{
		if (Target || TargetSet)
		{
#ifdef _WIN64
			ExceptionInfo->ContextRecord->Rsp -= sizeof(QWORD);
			*(PVOID*)(ExceptionInfo->ContextRecord->Rsp) = Target;
#else
			ExceptionInfo->ContextRecord->Esp -= sizeof(DWORD);
			*(PVOID*)(ExceptionInfo->ContextRecord->Esp) = Target;
#endif
			SkipInstruction(ExceptionInfo->ContextRecord);
			DebuggerOutput("ActionDispatcher: Pushed 0x%x\n", Target);
		}
		else
			DebuggerOutput("ActionDispatcher: Cannot push - target value missing.\n");
	}
	else if (!strnicmp(Action, "Pop", 3))
	{
#ifdef _WIN64
		ExceptionInfo->ContextRecord->Rsp += sizeof(QWORD);
#else
		ExceptionInfo->ContextRecord->Esp += sizeof(DWORD);
#endif
		DebuggerOutput("ActionDispatcher: Popped the stack");
	}
	else if (!strnicmp(Action, "Ret", 3))
	{
		if ((unsigned int)(DWORD_PTR)Target < 10)
		{
			if (!Target)
				((unsigned int)(DWORD_PTR)Target)++;
#ifdef _WIN64
			PVOID RetAddress = *(PVOID*)(ExceptionInfo->ContextRecord->Rsp+(((unsigned int)(DWORD_PTR)Target)-1)*sizeof(QWORD));
#else
			PVOID RetAddress = *(PVOID*)(ExceptionInfo->ContextRecord->Esp+(((unsigned int)Target)-1)*sizeof(DWORD));
#endif
			if (RetAddress)
			{
				TraceOutput(CIP, DecodedInstruction);
				if ((DWORD_PTR)Target > 1)
					DebuggerOutput("\nActionDispatcher: Return (%d) to 0x%p.\n", Target, RetAddress);
				else
					DebuggerOutput("\nActionDispatcher: Return to 0x%p.\n", RetAddress);
#ifdef _WIN64
				ExceptionInfo->ContextRecord->Rip = (QWORD)RetAddress;
				for (unsigned int i=0; i<(unsigned int)(DWORD_PTR)Target; i++)
					ExceptionInfo->ContextRecord->Rsp += sizeof(QWORD);
#else
				ExceptionInfo->ContextRecord->Eip = (DWORD)RetAddress;
				for (unsigned int i=0; i<(unsigned int)Target; i++)
					ExceptionInfo->ContextRecord->Esp += sizeof(DWORD);
#endif
			}
		}
	}
	else if (!strnicmp(Action, "Unwind", 6))
	{
		if ((unsigned int)(DWORD_PTR)Target < 10)
		{
			TraceOutput(CIP, DecodedInstruction);
			if (!Target)
				((unsigned int)(DWORD_PTR)Target)++;

#ifdef _WIN64
			DebuggerOutput("\nActionDispatcher: Unwind not yet implemented on x64\n");
#else
			for (unsigned int i=0; i<(unsigned int)Target; i++)
			{
				ExceptionInfo->ContextRecord->Eip = *(DWORD_PTR*)(ExceptionInfo->ContextRecord->Ebp + sizeof(DWORD_PTR));
				ExceptionInfo->ContextRecord->Esp = ExceptionInfo->ContextRecord->Ebp + 2*sizeof(DWORD_PTR);
				ExceptionInfo->ContextRecord->Ebp = *(DWORD_PTR*)ExceptionInfo->ContextRecord->Ebp;
#ifdef DEBUG_COMMENTS
				DebuggerOutput("\nActionDispatcher: Unwind %d: EIP -> 0x%x, ESP -> 0x%x, EBP -> 0x%x\n", i+1, ExceptionInfo->ContextRecord->Eip, ExceptionInfo->ContextRecord->Esp, ExceptionInfo->ContextRecord->Ebp);
#endif
			}
			if ((DWORD_PTR)Target > 1)
				DebuggerOutput("\nActionDispatcher: Unwind %d frames to 0x%p.\n", Target, ExceptionInfo->ContextRecord->Eip);
			else
				DebuggerOutput("\nActionDispatcher: Unwind to previous frame at 0x%p.\n", ExceptionInfo->ContextRecord->Eip);
#endif
		}
	}
	else if (!strnicmp(Action, "hooks:", 6))
	{
		if (*(Action + 6) == '1')
		{
			DebuggerOutput("ActionDispatcher: Enabling hooks.\n");
			hook_enable();
		}
		else if (*(Action + 6) == '0')
		{
			DebuggerOutput("ActionDispatcher: Disabling hooks.\n");
			hook_disable();
		}
	}
	else if (!stricmp(Action, "Stop"))
	{
		TraceOutput(CIP, DecodedInstruction);
		DebuggerOutput("\nActionDispatcher: %s detected, stopping trace.\n", DecodedInstruction.mnemonic.p);
		ResumeFromBreakpoint(ExceptionInfo->ContextRecord);
		ClearSingleStepMode(ExceptionInfo->ContextRecord);
		memset(&LastContext, 0, sizeof(CONTEXT));
		TraceRunning = FALSE;
		StopTrace = TRUE;
		StepCount = 0;
	}
#ifndef _WIN64
	else if (!strnicmp(Action, "Print:", 6))
	{
		char OutputBuffer[MAX_PATH] = "";
		if (Target && StrTest((char*)Target, OutputBuffer, MAX_PATH))
			DebuggerOutput("ActionDispatcher: Print 0x%p -> %s\n", Target, Target);
		else
			DebuggerOutput("ActionDispatcher: Nothing to print at 0x%p\n", Target);
	}
#endif
	else if (!stricmp(Action, "DumpImage"))
	{
#ifdef _WIN64
		PVOID CallingModule = GetAllocationBase((PVOID)ExceptionInfo->ContextRecord->Rip);
#else
		PVOID CallingModule = GetAllocationBase((PVOID)ExceptionInfo->ContextRecord->Eip);
#endif
		if (g_config.dumptype0)
			CapeMetaData->DumpType = g_config.dumptype0;
		else if (g_config.dumptype1)
			CapeMetaData->DumpType = g_config.dumptype1;
		else if (g_config.dumptype2)
			CapeMetaData->DumpType = g_config.dumptype2;
		else if (g_config.dumptype3)
			CapeMetaData->DumpType = g_config.dumptype3;
		else
			CapeMetaData->DumpType = UNPACKED_PE;

		if (strlen(g_config.typestring0))
			CapeMetaData->TypeString = g_config.typestring0;
		else if (strlen(g_config.typestring1))
			CapeMetaData->TypeString = g_config.typestring1;
		else if (strlen(g_config.typestring2))
			CapeMetaData->TypeString = g_config.typestring2;
		else if (strlen(g_config.typestring3))
			CapeMetaData->TypeString = g_config.typestring3;

		if (DumpImageInCurrentProcess(CallingModule))
			DebuggerOutput("ActionDispatcher: Dumped breaking module at 0x%p.\n", CallingModule);
		else
			DebuggerOutput("ActionDispatcher: Failed to dump breaking module at 0x%p.\n", CallingModule);
	}
	else if (!strnicmp(Action, "DumpSize:", 9))
	{
		if (Target)
		{
			DumpSize = (SIZE_T)Target;
			DebuggerOutput("ActionDispatcher: Dump size set to 0x%x.\n", Target);
		}
		else
			DebuggerOutput("ActionDispatcher: Failed to set dump size.\n");
	}
	else if (!strnicmp(Action, "SetDump:", 8))
	{
		if (Target && !TargetArg)
		{
			DumpAddress = Target;
			DebuggerOutput("SetDump: Dump address set to 0x%p.\n", Target);
		}
		else if (Target && TargetArg)
		{
			DumpAddress = Target;
			DumpSize = (SIZE_T)TargetArg;
			DebuggerOutput("SetDump: Dump address set to 0x%p, size 0x%x\n", DumpAddress, DumpSize);
		}
		else
			DebuggerOutput("SetDump: Failed to set dump address.\n");
	}
	else if (!stricmp(Action, "Dump") || !strnicmp(Action, "Dump:", 5))
	{
		if (g_config.dumptype0)
			CapeMetaData->DumpType = g_config.dumptype0;
		else if (g_config.dumptype1)
			CapeMetaData->DumpType = g_config.dumptype1;
		else if (g_config.dumptype2)
			CapeMetaData->DumpType = g_config.dumptype2;
		else if (g_config.dumptype3)
			CapeMetaData->DumpType = g_config.dumptype3;

		if (strlen(g_config.typestring0))
		{
			CapeMetaData->TypeString = g_config.typestring0;
			CapeMetaData->DumpType = TYPE_STRING;
		}
		else if (strlen(g_config.typestring1))
		{
			CapeMetaData->TypeString = g_config.typestring1;
			CapeMetaData->DumpType = TYPE_STRING;
		}
		else if (strlen(g_config.typestring2))
		{
			CapeMetaData->TypeString = g_config.typestring2;
			CapeMetaData->DumpType = TYPE_STRING;
		}
		else if (strlen(g_config.typestring3))
		{
			CapeMetaData->TypeString = g_config.typestring3;
			CapeMetaData->DumpType = TYPE_STRING;
		}

		if (strlen(DumpSizeString))
		{
			DumpSize = (SIZE_T)GetRegister(ExceptionInfo->ContextRecord, DumpSizeString);
			if (!DumpSize && p)
				DumpSize = (SIZE_T)(DWORD_PTR)strtoul(p+1, NULL, 0);
		}

		if (!Target && DumpAddress)
			Target = DumpAddress;

		if (TargetArg)
		{
			DumpSize = (SIZE_T)TargetArg;
			DebuggerOutput("ActionDispatcher: Dump size set to 0x%x\n", DumpSize);
		}

		if (Target && DumpSize && DumpSize < MAX_DUMP_SIZE && DumpMemory(Target, DumpSize))
		{
			DebuggerOutput("ActionDispatcher: Dumped region at 0x%p size 0x%x.\n", Target, DumpSize);
			return;
		}
		else if (Target && DumpRegion(Target))
		{
			DebuggerOutput("ActionDispatcher: Dumped region at 0x%p.\n", Target);
			return;
		}
		else
			DebuggerOutput("ActionDispatcher: Failed to dump region at 0x%p, size 0x%d.\n", Target, DumpSize);
		DumpAddress = 0;
		DumpSize = 0;
	}
	else if (stricmp(Action, "custom"))
		DebuggerOutput("ActionDispatcher: Unrecognised action: (%s)\n", Action);

	InstructionCount++;

	return;
}

BOOL DoStepOver(PCHAR FunctionName)
{
	char *StepOverList[] =
	{
		"RtlAllocateHeap",
		"RtlFreeHeap",
		"LdrLockLoaderLock",
		"LdrUnlockLoaderLock",
		"RtlAcquirePebLock",
		"RtlReleasePebLock",
		NULL
	};

	for (unsigned int i = 0; StepOverList[i]; i++)
	{
		if (!stricmp(StepOverList[i], FunctionName))
			return TRUE;
	}

	return FALSE;
}

BOOL Trace(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID CIP;
	unsigned int DllRVA;
	PVOID BranchTarget;

	StopTrace = FALSE;
	TraceRunning = TRUE;
	BOOL StepOver = FALSE, ForceStepOver = FALSE;

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

	if (g_config.branch_trace)
		FilterTrace = FALSE;

	// We need to increase StepCount even if FilterTrace == TRUE
	StepCount++;

	if (FilterTrace)
	{
		StepOver = TRUE;
		if (ReturnAddress)
		{
			if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &StepOverRegister, 0, (BYTE*)ReturnAddress, BP_EXEC, 1, BreakpointCallback))
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
	if (!FilterTrace)
	{
		memset(DebuggerBuffer, 0, MAX_PATH*sizeof(CHAR));

		if (LastContext.Rax != ExceptionInfo->ContextRecord->Rax)
		{
			DebuggerOutput(" RAX=%#I64x", ExceptionInfo->ContextRecord->Rax);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Rax);
		}

		if (LastContext.Rbx != ExceptionInfo->ContextRecord->Rbx)
		{
			DebuggerOutput(" RBX=%#I64x", ExceptionInfo->ContextRecord->Rbx);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Rbx);
		}

		if (LastContext.Rcx != ExceptionInfo->ContextRecord->Rcx)
		{
			DebuggerOutput(" RCX=%#I64x", ExceptionInfo->ContextRecord->Rcx);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Rcx);
		}

		if (LastContext.Rdx != ExceptionInfo->ContextRecord->Rdx)
		{
			DebuggerOutput(" RDX=%#I64x", ExceptionInfo->ContextRecord->Rdx);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Rdx);
		}

		if (LastContext.Rsi != ExceptionInfo->ContextRecord->Rsi)
		{
			DebuggerOutput(" RSI=%#I64x", ExceptionInfo->ContextRecord->Rsi);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Rsi);
		}

		if (LastContext.Rdi != ExceptionInfo->ContextRecord->Rdi)
		{
			DebuggerOutput(" RDI=%#I64x", ExceptionInfo->ContextRecord->Rdi);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Rdi);
		}

		if (LastContext.Rsp != ExceptionInfo->ContextRecord->Rsp)
		{
			DebuggerOutput(" RSP=%#I64x", ExceptionInfo->ContextRecord->Rsp);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Rsp);
			DebuggerOutput(" *RSP=%#I64x", *(QWORD*)ExceptionInfo->ContextRecord->Rsp);
			StringCheck((PVOID)*(QWORD*)ExceptionInfo->ContextRecord->Rsp);
		}

		if (LastContext.Rbp != ExceptionInfo->ContextRecord->Rbp)
		{
			DebuggerOutput(" RBP=%#I64x", ExceptionInfo->ContextRecord->Rbp);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Rbp);
		}

		if (LastContext.R8 != ExceptionInfo->ContextRecord->R8)
		{
			DebuggerOutput(" R8=%#I64x", ExceptionInfo->ContextRecord->R8);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->R8);
		}

		if (LastContext.R9 != ExceptionInfo->ContextRecord->R9)
		{
			DebuggerOutput(" R9=%#I64x", ExceptionInfo->ContextRecord->R9);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->R9);
		}

		if (LastContext.R10 != ExceptionInfo->ContextRecord->R10)
		{
			DebuggerOutput(" R10=%#I64x", ExceptionInfo->ContextRecord->R10);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->R10);
		}

		if (LastContext.R11 != ExceptionInfo->ContextRecord->R11)
		{
			DebuggerOutput(" R11=%#I64x", ExceptionInfo->ContextRecord->R11);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->R11);
		}

		if (LastContext.R12 != ExceptionInfo->ContextRecord->R12)
		{
			DebuggerOutput(" R12=%#I64x", ExceptionInfo->ContextRecord->R12);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->R12);
		}

		if (LastContext.R13 != ExceptionInfo->ContextRecord->R13)
		{
			DebuggerOutput(" R13=%#I64x", ExceptionInfo->ContextRecord->R13);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->R13);
		}

		if (LastContext.R14 != ExceptionInfo->ContextRecord->R14)
		{
			DebuggerOutput(" R14=%#I64x", ExceptionInfo->ContextRecord->R14);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->R14);
		}

		if (LastContext.R15 != ExceptionInfo->ContextRecord->R15)
		{
			DebuggerOutput(" R15=%#I64x", ExceptionInfo->ContextRecord->R15);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->R15);
		}

		if (LastContext.Xmm0.Low != ExceptionInfo->ContextRecord->Xmm0.Low)
		{
			DebuggerOutput(" Xmm0.Low=%#I64x", ExceptionInfo->ContextRecord->Xmm0.Low);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Xmm0.Low);
		}

		if (LastContext.Xmm0.High != ExceptionInfo->ContextRecord->Xmm0.High)
		{
			DebuggerOutput(" Xmm0.High=%#I64x", ExceptionInfo->ContextRecord->Xmm0.High);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Xmm0.High);
		}

		if (LastContext.Xmm1.Low != ExceptionInfo->ContextRecord->Xmm1.Low)
		{
			DebuggerOutput(" Xmm1.Low=%#I64x", ExceptionInfo->ContextRecord->Xmm1.Low);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Xmm1.Low);
		}

		if (LastContext.Xmm1.High != ExceptionInfo->ContextRecord->Xmm1.High)
		{
			DebuggerOutput(" Xmm1.High=%#I64x", ExceptionInfo->ContextRecord->Xmm1.High);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Xmm1.High);
		}
#else
	if (!FilterTrace)
	{
		if (LastContext.Eax != ExceptionInfo->ContextRecord->Eax)
		{
			DebuggerOutput(" EAX=0x%x", ExceptionInfo->ContextRecord->Eax);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Eax);
		}

		if (LastContext.Ebx != ExceptionInfo->ContextRecord->Ebx)
		{
			DebuggerOutput(" EBX=0x%x", ExceptionInfo->ContextRecord->Ebx);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Ebx);
		}

		if (LastContext.Ecx != ExceptionInfo->ContextRecord->Ecx)
		{
			DebuggerOutput(" ECX=0x%x", ExceptionInfo->ContextRecord->Ecx);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Ecx);
		}

		if (LastContext.Edx != ExceptionInfo->ContextRecord->Edx)
		{
			DebuggerOutput(" EDX=0x%x", ExceptionInfo->ContextRecord->Edx);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Edx);
		}

		if (LastContext.Esi != ExceptionInfo->ContextRecord->Esi)
		{
			DebuggerOutput(" ESI=0x%x", ExceptionInfo->ContextRecord->Esi);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Esi);
		}

		if (LastContext.Edi != ExceptionInfo->ContextRecord->Edi)
		{
			DebuggerOutput(" EDI=0x%x", ExceptionInfo->ContextRecord->Edi);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Edi);
		}

		if (LastContext.Esp != ExceptionInfo->ContextRecord->Esp)
		{
			DebuggerOutput(" ESP=0x%x", ExceptionInfo->ContextRecord->Esp);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Esp);
			DebuggerOutput(" *ESP=0x%x", *(DWORD*)ExceptionInfo->ContextRecord->Esp);
			StringCheck((PVOID)*(DWORD*)ExceptionInfo->ContextRecord->Esp);
		}

		if (LastContext.Ebp != ExceptionInfo->ContextRecord->Ebp)
		{
			DebuggerOutput(" EBP=0x%x", ExceptionInfo->ContextRecord->Ebp);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Ebp);
		}
#endif
	}

	if (!FilterTrace)
		DebuggerOutput("\n");

	if (!StepLimit || StepCount > StepLimit)
	{
		DebuggerOutput("Trace: Single-step limit reached (%d), releasing.\n", StepLimit);
		ClearSingleStepMode(ExceptionInfo->ContextRecord);
		memset(&LastContext, 0, sizeof(CONTEXT));
		TraceRunning = FALSE;
		StopTrace = TRUE;
		StepCount = 0;
		ReturnAddress = NULL;
		return TRUE;
	}

	//if (g_config.branch_trace && ExceptionInfo->ExceptionRecord->ExceptionInformation[0] > 0x20000)
	if (g_config.branch_trace && ExceptionInfo->ExceptionRecord->ExceptionInformation[0])
	{
		BranchTarget = CIP;
		CIP = (PVOID)ExceptionInfo->ExceptionRecord->ExceptionInformation[0];
	}

	PCHAR FunctionName = NULL;
	__try
	{
		FunctionName = ScyllaGetExportNameByAddress(CIP, NULL);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DebugOutput("Trace: Error dereferencing instruction pointer 0x%p.\n", CIP);
		FunctionName = NULL;
	}
	ModuleName = convert_address_to_dll_name_and_offset((ULONG_PTR)CIP, &DllRVA);

	if (ModuleName)
	{
		if (CIP == (PVOID)((PCHAR)_KiUserExceptionDispatcher+1))
		{
			DebugOutput("Trace: Stepping out of KiUserExceptionDispatcher\n");
			ForceStepOver = TRUE;
			FilterTrace = TRUE;
		}
		else if (!PreviousModuleName || strncmp(ModuleName, PreviousModuleName, strlen(ModuleName)))
		{
			PVOID ImageBase = (PVOID)((PUCHAR)CIP - DllRVA);
			if (FilterTrace)
				DebuggerOutput("\n");
			if (FunctionName)
			{
				DebuggerOutput("Break at 0x%p in %s::%s (RVA 0x%x, thread %d, ImageBase 0x%p)\n", CIP, ModuleName, FunctionName, DllRVA, GetCurrentThreadId(), ImageBase);

				ForceStepOver = DoStepOver(FunctionName);

				for (unsigned int i = 0; i < ARRAYSIZE(g_config.trace_into_api); i++)
				{
					if (!g_config.trace_into_api[i])
						break;
					if (!stricmp(FunctionName, g_config.trace_into_api[i]))
						StepOver = FALSE;
				}
				PreviousModuleName = ModuleName;
			}
			else if (!g_config.branch_trace)
			{
				DebuggerOutput("Break at 0x%p in %s (RVA 0x%x, thread %d, ImageBase 0x%p)\n", CIP, ModuleName, DllRVA, GetCurrentThreadId(), ImageBase);
				PreviousModuleName = ModuleName;
				FunctionName = NULL;
				ModuleName = NULL;
			}
		}
	}

	// We disassemble once for the action dispatcher
	if (CIP)
		Result = distorm_decode(Offset, (const unsigned char*)CIP, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount);

	ReDisassemble = FALSE;

	// Dispatch any actions
	if (Instruction0 && !strnicmp(DecodedInstruction.mnemonic.p, Instruction0, strlen(Instruction0)))
		ActionDispatcher(ExceptionInfo, DecodedInstruction, Action0);

	if (Instruction1 && !strnicmp(DecodedInstruction.mnemonic.p, Instruction1, strlen(Instruction1)))
		ActionDispatcher(ExceptionInfo, DecodedInstruction, Action1);

	if (Instruction2 && !strnicmp(DecodedInstruction.mnemonic.p, Instruction2, strlen(Instruction2)))
		ActionDispatcher(ExceptionInfo, DecodedInstruction, Action2);

	if (Instruction3 && !strnicmp(DecodedInstruction.mnemonic.p, Instruction3, strlen(Instruction3)))
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
		PCHAR ExportName = NULL;
		PVOID CallTarget = NULL;
		// We set this as a matter of course for calls in case we might
		// want to step over this as a result of the call target
		ReturnAddress = (PVOID)((PUCHAR)CIP + DecodedInstruction.size);

#ifdef _WIN64
		if (DecodedInstruction.size > 4 && DecodedInstruction.operands.length && !strncmp(DecodedInstruction.operands.p, "QWORD", 5) && strncmp(DecodedInstruction.operands.p, "QWORD [R", 8))
#else
		if (DecodedInstruction.size > 4 && DecodedInstruction.operands.length && !strncmp(DecodedInstruction.operands.p, "DWORD", 5) && strncmp(DecodedInstruction.operands.p, "DWORD [E", 8))
#endif
		// begins with DWORD except "DWORD [E" (or "QWORD [R")
		{
			CallTarget = *(PVOID*)((PUCHAR)CIP + DecodedInstruction.size - 4);

			if (!strncmp(DecodedInstruction.operands.p, "DWORD [FS:0xc0]", 15))
			{
				ExportName = DecodedInstruction.operands.p;
				ForceStepOver = TRUE;
			}
			else
			{
				__try
				{
					ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
					if (!ExportName)
						ExportName = ScyllaGetExportNameByAddress(*(PVOID*)CallTarget, NULL);
				}
				__except(EXCEPTION_EXECUTE_HANDLER)
				{
					DebugOutput("Trace: Error dereferencing CallTarget 0x%p.\n", CallTarget);
					ExportName = NULL;
				}
			}

			if (ExportName)
			{
				ModuleName = convert_address_to_dll_name_and_offset((ULONG_PTR)CallTarget, &DllRVA);
				if (!FilterTrace || g_config.trace_all)
					TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else if (!strncmp(DecodedInstruction.operands.p, "DWORD [0x", 9))
			{
				if (!FilterTrace || g_config.trace_all)
					TraceOutput(CIP, DecodedInstruction);
			}
			else if (!FilterTrace || g_config.trace_all)
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
		}
		else if (DecodedInstruction.size > 4)
		{
			CallTarget = (PVOID)((PUCHAR)CIP + (int)*(DWORD*)((PUCHAR)CIP + DecodedInstruction.size - 4) + DecodedInstruction.size);
			__try
			{
				ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
				if (!ExportName)
					ExportName = ScyllaGetExportNameByAddress(*(PVOID*)CallTarget, NULL);
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				DebugOutput("Trace: Error dereferencing CallTarget 0x%x.", CallTarget);
				ExportName = NULL;
			}

			if (!FilterTrace && ExportName)
			{
				TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else if (!FilterTrace)
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
		}
#ifdef _WIN64
		else if (!strncmp(DecodedInstruction.operands.p, "RAX", 3))
		{
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rax;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				if (!FilterTrace || g_config.trace_all)
					TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else if (!FilterTrace || g_config.trace_all)
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#else
		else if (!strncmp(DecodedInstruction.operands.p, "EAX", 3))
		{
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Eax;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				if (!FilterTrace || g_config.trace_all)
					TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else if (!FilterTrace || g_config.trace_all)
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#endif
		}
#ifdef _WIN64
		else if (!strncmp(DecodedInstruction.operands.p, "RBX", 3))
		{
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rbx;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				if (!FilterTrace || g_config.trace_all)
					TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else if (!FilterTrace || g_config.trace_all)
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#else
		else if (!strncmp(DecodedInstruction.operands.p, "EBX", 3))
		{
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Ebx;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				if (!FilterTrace || g_config.trace_all)
					TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else if (!FilterTrace || g_config.trace_all)
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#endif
		}
#ifdef _WIN64
		else if (!strncmp(DecodedInstruction.operands.p, "RCX", 3))
		{
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rcx;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				if (!FilterTrace || g_config.trace_all)
					TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else if (!FilterTrace || g_config.trace_all)
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#else
		else if (!strncmp(DecodedInstruction.operands.p, "ECX", 3))
		{
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Ecx;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				if (!FilterTrace || g_config.trace_all)
					TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else if (!FilterTrace || g_config.trace_all)
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#endif
		}
#ifdef _WIN64
		else if (!strncmp(DecodedInstruction.operands.p, "RDX", 3))
		{
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rdx;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				if (!FilterTrace || g_config.trace_all)
					TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else if (!FilterTrace || g_config.trace_all)
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#else
		else if (!strncmp(DecodedInstruction.operands.p, "EDX", 3))
		{
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Edx;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				if (!FilterTrace || g_config.trace_all)
					TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else if (!FilterTrace || g_config.trace_all)
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#endif
		}
#ifdef _WIN64
		else if (!strncmp(DecodedInstruction.operands.p, "RBP", 3))
		{
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rbp;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				if (!FilterTrace || g_config.trace_all)
					TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else if (!FilterTrace || g_config.trace_all)
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#else
		else if (!strncmp(DecodedInstruction.operands.p, "EBP", 3))
		{
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Ebp;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				if (!FilterTrace || g_config.trace_all)
					TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else if (!FilterTrace || g_config.trace_all)
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#endif
		}
#ifdef _WIN64
		else if (!strncmp(DecodedInstruction.operands.p, "RSI", 3))
		{
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rsi;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				if (!FilterTrace || g_config.trace_all)
					TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else if (!FilterTrace || g_config.trace_all)
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#else
		else if (!strncmp(DecodedInstruction.operands.p, "ESI", 3))
		{
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Esi;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				if (!FilterTrace || g_config.trace_all)
					TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else if (!FilterTrace || g_config.trace_all)
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#endif
		}
#ifdef _WIN64
		else if (!strncmp(DecodedInstruction.operands.p, "RDI", 3))
		{
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rdi;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				if (!FilterTrace || g_config.trace_all)
					TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else if (!FilterTrace || g_config.trace_all)
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#else
		else if (!strncmp(DecodedInstruction.operands.p, "EDI", 3))
		{
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Edi;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				if (!FilterTrace || g_config.trace_all)
					TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else if (!FilterTrace || g_config.trace_all)
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);;
#endif
		}
		else if (!FilterTrace || g_config.trace_all)
			TraceOutput(CIP, DecodedInstruction);

		if (ExportName)
		{
			ForceStepOver = DoStepOver(ExportName);

			for (unsigned int i = 0; i < ARRAYSIZE(g_config.trace_into_api); i++)
			{
				if (!g_config.trace_into_api[i])
					break;
				if (!stricmp(ExportName, g_config.trace_into_api[i]))
				{
					StepOver = FALSE;
					if (TraceDepthCount > 0)
						TraceDepthCount--;
					DebuggerOutput("\nTrace: Stepping into %s\n", ExportName);
				}
			}
		}

		if (CallTarget == &loq)
		{
			ExportName = "loq";
			ForceStepOver = TRUE;
		}

		if (CallTarget == &log_flush)
		{
			ExportName = "log_flush";
			ForceStepOver = TRUE;
		}

		if (!StepLimit || StepCount > StepLimit || StopTrace)
		{
			ForceStepOver = FALSE;
			StepOver = FALSE;
		}
		else if (((unsigned int)abs(TraceDepthCount) >= TraceDepthLimit && !g_config.trace_all) || (StepOver == TRUE && !g_config.trace_all) || ForceStepOver)
		{
			if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &StepOverRegister, 0, (BYTE*)ReturnAddress, BP_EXEC, 1, BreakpointCallback))
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
	else if (!strcmp(DecodedInstruction.mnemonic.p, "JMP"))
	{
		PCHAR ExportName = NULL;
		PVOID JumpTarget = NULL;
#ifdef _WIN64
		ReturnAddress = *(PVOID*)(ExceptionInfo->ContextRecord->Rsp);

		if (DecodedInstruction.size > 4 && DecodedInstruction.operands.length && !strncmp(DecodedInstruction.operands.p, "QWORD", 5) && strncmp(DecodedInstruction.operands.p, "QWORD [R", 8))
		{
			if (!strncmp(DecodedInstruction.operands.p, "QWORD [0x", 9))
				JumpTarget = *(PVOID*)(*(PVOID*)((PUCHAR)CIP + DecodedInstruction.size - 4));
			else
				// begins with QWORD except "QWORD [R"
#else
		ReturnAddress = *(PVOID*)(ExceptionInfo->ContextRecord->Esp);

		if (DecodedInstruction.size > 4 && DecodedInstruction.operands.length && !strncmp(DecodedInstruction.operands.p, "DWORD", 5) && strncmp(DecodedInstruction.operands.p, "DWORD [E", 8))
		{
			if (!strncmp(DecodedInstruction.operands.p, "DWORD [0x", 9))
				JumpTarget = *(PVOID*)(*(PVOID*)((PUCHAR)CIP + DecodedInstruction.size - 4));
			else
				// begins with DWORD except "DWORD [E"
#endif
				JumpTarget = *(PVOID*)((PUCHAR)CIP + DecodedInstruction.size - 4);

			__try
			{
				ExportName = ScyllaGetExportNameByAddress(JumpTarget, NULL);
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				DebugOutput("Trace: Error dereferencing JumpTarget 0x%p.\n", JumpTarget);
				ExportName = NULL;
			}

			if (ExportName)
			{
				ModuleName = convert_address_to_dll_name_and_offset((ULONG_PTR)JumpTarget, &DllRVA);
				if (!FilterTrace || g_config.trace_all)
					TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				if (!g_config.trace_all)
					ForceStepOver = TRUE;
			}
			else if (!FilterTrace || g_config.trace_all)
				TraceOutputFuncAddress(CIP, DecodedInstruction, JumpTarget);

			//if (is_in_dll_range((ULONG_PTR)JumpTarget))
			//	ForceStepOver = TRUE;
			if (inside_hook(JumpTarget) && g_config.trace_all < 2)
				ForceStepOver = TRUE;

			if (g_config.branch_trace)
				ForceStepOver = TRUE;
		}
		else if (DecodedInstruction.size > 4)
		{
			JumpTarget = (PVOID)((PUCHAR)CIP + (int)*(DWORD*)((PUCHAR)CIP + DecodedInstruction.size - 4) + DecodedInstruction.size);
			__try
			{
				ExportName = ScyllaGetExportNameByAddress(JumpTarget, NULL);
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				DebugOutput("Trace: Error dereferencing JumpTarget 0x%p.", JumpTarget);
				ExportName = NULL;
			}

			if (ExportName)
			{
				if (!FilterTrace || g_config.trace_all)
					TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
			}
			else
				if (!FilterTrace || g_config.trace_all)
					TraceOutputFuncAddress(CIP, DecodedInstruction, JumpTarget);
		}
		else if (!FilterTrace || g_config.trace_all)
			TraceOutput(CIP, DecodedInstruction);
	}
	//else if (!strncmp(DecodedInstruction.mnemonic.p, "REP ", 4) || !strncmp(DecodedInstruction.mnemonic.p, "LOOP", 4))
	else if (!strncmp(DecodedInstruction.mnemonic.p, "LOOP", 4))
	{
		if (!FilterTrace || g_config.trace_all)
			TraceOutput(CIP, DecodedInstruction);
		ReturnAddress = (PVOID)((PUCHAR)CIP + DecodedInstruction.size);
		ForceStepOver = TRUE;
	}
#ifndef _WIN64
	else if (!strcmp(DecodedInstruction.mnemonic.p, "CALL FAR") && !strncmp(DecodedInstruction.operands.p, "0x33", 4))
	{
		if (!FilterTrace || g_config.trace_all)
			TraceOutput(CIP, DecodedInstruction);
		ReturnAddress = (PVOID)((PUCHAR)CIP + DecodedInstruction.size);
		ForceStepOver = TRUE;
	}
	else if (!strcmp(DecodedInstruction.mnemonic.p, "JMP FAR"))
	{
		if (!FilterTrace || g_config.trace_all)
			TraceOutput(CIP, DecodedInstruction);
		ReturnAddress = *(PVOID*)(ExceptionInfo->ContextRecord->Esp);
		ForceStepOver = TRUE;
	}
	else if (!strcmp(DecodedInstruction.mnemonic.p, "INT 3"))
	{
		if (!FilterTrace || g_config.trace_all)
			TraceOutput(CIP, DecodedInstruction);
		BreakOnNtContinueCallback = BreakpointCallback;
		//LastContext = *ExceptionInfo->ContextRecord;
		//ClearSingleStepMode(ExceptionInfo->ContextRecord);
		//ReturnAddress = NULL;
		//return TRUE;
	}

#endif
#ifndef _WIN64
	else if (!strcmp(DecodedInstruction.mnemonic.p, "POP") && !strncmp(DecodedInstruction.operands.p, "SS", 2))
	{
		if (!FilterTrace)
			TraceOutput(CIP, DecodedInstruction);

		if (InsideMonitor(NULL, CIP))
		{
			DebuggerOutput("\nInternal POP SS detected.\n");
		}
		//else
		//{
			if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &StepOverRegister, 0, (PVOID)ExceptionInfo->ContextRecord->Esp, BP_READWRITE, 0, BreakpointCallback))
			{
				DebugOutput("Trace: Set stack breakpoint before POP SS at 0x%p\n", CIP);
				LastContext = *ExceptionInfo->ContextRecord;
				ClearSingleStepMode(ExceptionInfo->ContextRecord);
				ReturnAddress = NULL;
				return TRUE;
			}
			else
				DebugOutput("Trace: Failed to set stack breakpoint on 0x%p\n", ExceptionInfo->ContextRecord->Esp);
		//}
	}
//#else
//	else if (!strcmp(DecodedInstruction.mnemonic.p, "MOV") && !strncmp(DecodedInstruction.operands.p, "SS", 2))
//	{
//		TraceOutput(CIP, DecodedInstruction);
//
//		if (InsideMonitor(NULL, CIP))
//		{
//			DebuggerOutput("\nInternal MOV SS detected.\n");
//
//			if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &StepOverRegister, 0, &StackSelector, BP_READWRITE, 0, BreakpointCallback))
//			{
//				DebugOutput("DoSyscall: Set breakpoint before MOV SS at 0x%p\n", ExceptionInfo->ContextRecord->Rip);
//				//TraceRunning = FALSE;
//				//LastContext = *ExceptionInfo->ContextRecord;
//				//ClearSingleStepMode(ExceptionInfo->ContextRecord);
//				//ReturnAddress = NULL;
//				//return TRUE;
//				ReturnAddress = *(PVOID*)(ExceptionInfo->ContextRecord->Rsp);
//				ForceStepOver = TRUE;
//			}
//			else
//				DebugOutput("DoSyscall: Failed to set stack breakpoint on 0x%p\n", (PBYTE)ExceptionInfo->ContextRecord->Rsp-8);
//		}
//	}
#endif
#ifdef _WIN64
	else if (!strcmp(DecodedInstruction.mnemonic.p, "SYSCALL"))
	{
        if (!FilterTrace)
		{
			PCHAR FunctionName = GetNameBySsn((unsigned int)ExceptionInfo->ContextRecord->Rax);
#else
	else if (!strcmp(DecodedInstruction.mnemonic.p, "SYSENTER"))
	{
        if (!FilterTrace)
		{
			PCHAR FunctionName = GetNameBySsn((unsigned int)ExceptionInfo->ContextRecord->Eax);
#endif
			if (FunctionName)
				DebuggerOutput("0x%p  %-24s %-6s%-3s%-30s", CIP, (char*)_strupr(DecodedInstruction.instructionHex.p), (char*)DecodedInstruction.mnemonic.p, "", FunctionName);
			else
				TraceOutput(CIP, DecodedInstruction);
		}
		ReturnAddress = (PVOID)((PUCHAR)CIP + DecodedInstruction.size);
		ForceStepOver = TRUE;
	}
    else if (!strcmp(DecodedInstruction.mnemonic.p, "PUSHF") || !strcmp(DecodedInstruction.mnemonic.p, "POPF"))
    {
        if (!FilterTrace)
			TraceOutput(CIP, DecodedInstruction);

		if (!inside_hook(CIP) && !InsideMonitor(NULL, CIP))
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("Trace: Stepping over %s at 0x%p\n", DecodedInstruction.mnemonic.p, CIP);
#endif
			ReturnAddress = (PVOID)((PUCHAR)CIP + DecodedInstruction.size);
			ForceStepOver = TRUE;
		}
    }
	else if (!strcmp(DecodedInstruction.mnemonic.p, "RET"))
	{
		if (!FilterTrace || g_config.trace_all)
			TraceOutput(CIP, DecodedInstruction);

		if (!g_config.trace_all && TraceDepthCount > 0)
			TraceDepthCount--;
	}
	else if (!FilterTrace)
		TraceOutput(CIP, DecodedInstruction);

	if (g_config.branch_trace && BranchTarget)
	{
		Result = distorm_decode(Offset, (const unsigned char*)BranchTarget, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount);

		if (strcmp(DecodedInstruction.mnemonic.p, "CALL") && !strnicmp(DecodedInstruction.mnemonic.p, "j", 1))
			TraceOutput(CIP, DecodedInstruction);
	}

	if (!strcmp(DecodedInstruction.mnemonic.p, "RDTSC") && g_config.fake_rdtsc)
		ModTimestamp = TRUE;

	LastContext = *ExceptionInfo->ContextRecord;

	if (ForceStepOver && !StopTrace)
	{
		if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &StepOverRegister, 0, (BYTE*)ReturnAddress, BP_EXEC, 1, BreakpointCallback))
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
	{
		DebugOutput("Trace: Stopping trace!\n");
		TraceRunning = FALSE;
	}
#else
	}
	else
		TraceRunning = FALSE;
#endif
	ReturnAddress = NULL;
	return TRUE;
}

BOOL StepOutCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID CIP;
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
	TraceOutput(CIP, DecodedInstruction);

	if (!stricmp(Action0, "dumpebx"))
	{
		if (!stricmp(DumpSizeString, "eax"))
		{
#ifdef _WIN64
			DumpSize = ExceptionInfo->ContextRecord->Rax;
			PVOID Address = (PVOID)ExceptionInfo->ContextRecord->Rbx;
#else
			DumpSize = ExceptionInfo->ContextRecord->Eax;
			PVOID Address = (PVOID)ExceptionInfo->ContextRecord->Ebx;
#endif
			if (g_config.dumptype0)
				CapeMetaData->DumpType = g_config.dumptype0;
			else if (g_config.dumptype1)
				CapeMetaData->DumpType = g_config.dumptype1;
			else if (g_config.dumptype2)
				CapeMetaData->DumpType = g_config.dumptype2;
			else
				CapeMetaData->DumpType = UNPACKED_PE;

			if (Address && DumpSize && DumpSize < MAX_DUMP_SIZE && DumpMemory(Address, DumpSize))
				DebugOutput("StepOutCallback: Dumped region at 0x%p size 0x%x.\n", Address, DumpSize);
			else
				DebugOutput("StepOutCallback: Failed to dump region at 0x%p.\n", Address);
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
		ContextClearBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo->Register);
		StepOverRegister = 0;
	}
	else for (bp = 0; bp < NUMBER_OF_DEBUG_REGISTERS; bp++)
	{
		if (pBreakpointInfo->Register == bp)
		{
			if (bp == 0 && ((DWORD_PTR)pBreakpointInfo->Address == ExceptionInfo->ContextRecord->Dr0))
			{
				DebuggerOutput("Breakpoint 0 hit by instruction at 0x%p (thread %d)", ExceptionInfo->ExceptionRecord->ExceptionAddress, GetCurrentThreadId());
                TraceDepthCount = 0;
                StepCount = 0;
				if (g_config.count0)
					StepLimit = g_config.count0;
				break;
			}

			if (bp == 1 && ((DWORD_PTR)pBreakpointInfo->Address == ExceptionInfo->ContextRecord->Dr1))
			{
				DebuggerOutput("Breakpoint 1 hit by instruction at 0x%p (thread %d)", ExceptionInfo->ExceptionRecord->ExceptionAddress, GetCurrentThreadId());
                TraceDepthCount = 0;
                StepCount = 0;
				if (g_config.count1)
					StepLimit = g_config.count1;
				break;
			}

			if (bp == 2 && ((DWORD_PTR)pBreakpointInfo->Address == ExceptionInfo->ContextRecord->Dr2))
			{
				DebuggerOutput("Breakpoint 2 hit by instruction at 0x%p (thread %d)", ExceptionInfo->ExceptionRecord->ExceptionAddress, GetCurrentThreadId());
                TraceDepthCount = 0;
                StepCount = 0;
				if (g_config.count2)
					StepLimit = g_config.count2;
				break;
			}

			if (bp == 3 && ((DWORD_PTR)pBreakpointInfo->Address == ExceptionInfo->ContextRecord->Dr3))
			{
				DebuggerOutput("Breakpoint 3 hit by instruction at 0x%p (thread %d)", ExceptionInfo->ExceptionRecord->ExceptionAddress, GetCurrentThreadId());
                TraceDepthCount = 0;
                StepCount = 0;
				if (g_config.count3)
					StepLimit = g_config.count3;
				break;
			}
		}
	}

#ifdef _WIN64
	CIP = (PVOID)ExceptionInfo->ContextRecord->Rip;
	DecodeType = Decode64Bits;
#else
	CIP = (PVOID)ExceptionInfo->ContextRecord->Eip;
	DecodeType = Decode32Bits;
#endif

	if (g_config.log_breakpoints)
	{
		// Log breakpoint to behavior log
		extern void log_breakpoint(const char *subcategory, const char *msg);
		memset(DebuggerBuffer, 0, MAX_PATH*sizeof(CHAR));
		_snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "Breakpoint hit at 0x%p", CIP);
		log_breakpoint("Debugger", DebuggerBuffer);
	}

	FilterTrace = FALSE;

	if (InsideMonitor(NULL, CIP) && g_config.trace_all == 1)
		FilterTrace = TRUE;

	if (inside_hook(CIP) && !g_config.trace_all)
		FilterTrace = TRUE;

	if (is_in_dll_range((ULONG_PTR)CIP) && !g_config.trace_all)
		FilterTrace = TRUE;

	StepCount++;

#ifdef _WIN64
	if (!FilterTrace)
	{
		memset(DebuggerBuffer, 0, MAX_PATH*sizeof(CHAR));

		if (LastContext.Rax != ExceptionInfo->ContextRecord->Rax)
		{
			DebuggerOutput(" RAX=%#I64x", ExceptionInfo->ContextRecord->Rax);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Rax);
		}

		if (LastContext.Rbx != ExceptionInfo->ContextRecord->Rbx)
		{
			DebuggerOutput(" RBX=%#I64x", ExceptionInfo->ContextRecord->Rbx);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Rbx);
		}

		if (LastContext.Rcx != ExceptionInfo->ContextRecord->Rcx)
		{
			DebuggerOutput(" RCX=%#I64x", ExceptionInfo->ContextRecord->Rcx);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Rcx);
		}

		if (LastContext.Rdx != ExceptionInfo->ContextRecord->Rdx)
		{
			DebuggerOutput(" RDX=%#I64x", ExceptionInfo->ContextRecord->Rdx);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Rdx);
		}

		if (LastContext.Rsi != ExceptionInfo->ContextRecord->Rsi)
		{
			DebuggerOutput(" RSI=%#I64x", ExceptionInfo->ContextRecord->Rsi);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Rsi);
		}

		if (LastContext.Rdi != ExceptionInfo->ContextRecord->Rdi)
		{
			DebuggerOutput(" RDI=%#I64x", ExceptionInfo->ContextRecord->Rdi);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Rdi);
		}

		if (LastContext.Rsp != ExceptionInfo->ContextRecord->Rsp)
		{
			DebuggerOutput(" RSP=%#I64x", ExceptionInfo->ContextRecord->Rsp);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Rsp);
			DebuggerOutput(" *RSP=%#I64x", *(QWORD*)ExceptionInfo->ContextRecord->Rsp);
			StringCheck((PVOID)*(QWORD*)ExceptionInfo->ContextRecord->Rsp);
		}

		if (LastContext.Rbp != ExceptionInfo->ContextRecord->Rbp)
		{
			DebuggerOutput(" RBP=%#I64x", ExceptionInfo->ContextRecord->Rbp);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Rbp);
		}

		if (LastContext.R8 != ExceptionInfo->ContextRecord->R8)
		{
			DebuggerOutput(" R8=%#I64x", ExceptionInfo->ContextRecord->R8);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->R8);
		}

		if (LastContext.R9 != ExceptionInfo->ContextRecord->R9)
		{
			DebuggerOutput(" R9=%#I64x", ExceptionInfo->ContextRecord->R9);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->R9);
		}

		if (LastContext.R10 != ExceptionInfo->ContextRecord->R10)
		{
			DebuggerOutput(" R10=%#I64x", ExceptionInfo->ContextRecord->R10);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->R10);
		}

		if (LastContext.R11 != ExceptionInfo->ContextRecord->R11)
		{
			DebuggerOutput(" R11=%#I64x", ExceptionInfo->ContextRecord->R11);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->R11);
		}

		if (LastContext.R12 != ExceptionInfo->ContextRecord->R12)
		{
			DebuggerOutput(" R12=%#I64x", ExceptionInfo->ContextRecord->R12);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->R12);
		}

		if (LastContext.R13 != ExceptionInfo->ContextRecord->R13)
		{
			DebuggerOutput(" R13=%#I64x", ExceptionInfo->ContextRecord->R13);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->R13);
		}

		if (LastContext.R14 != ExceptionInfo->ContextRecord->R14)
		{
			DebuggerOutput(" R14=%#I64x", ExceptionInfo->ContextRecord->R14);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->R14);
		}

		if (LastContext.R15 != ExceptionInfo->ContextRecord->R15)
		{
			DebuggerOutput(" R15=%#I64x", ExceptionInfo->ContextRecord->R15);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->R15);
		}

		if (LastContext.Xmm0.Low != ExceptionInfo->ContextRecord->Xmm0.Low)
		{
			DebuggerOutput(" Xmm0.Low=%#I64x", ExceptionInfo->ContextRecord->Xmm0.Low);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Xmm0.Low);
		}

		if (LastContext.Xmm0.High != ExceptionInfo->ContextRecord->Xmm0.High)
		{
			DebuggerOutput(" Xmm0.High=%#I64x", ExceptionInfo->ContextRecord->Xmm0.High);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Xmm0.High);
		}

		if (LastContext.Xmm1.Low != ExceptionInfo->ContextRecord->Xmm1.Low)
		{
			DebuggerOutput(" Xmm1.Low=%#I64x", ExceptionInfo->ContextRecord->Xmm1.Low);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Xmm1.Low);
		}

		if (LastContext.Xmm1.High != ExceptionInfo->ContextRecord->Xmm1.High)
		{
			DebuggerOutput(" Xmm1.High=%#I64x", ExceptionInfo->ContextRecord->Xmm1.High);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Xmm1.High);
		}
#else
	if (!FilterTrace)
	{
		if (LastContext.Eax != ExceptionInfo->ContextRecord->Eax)
		{
			DebuggerOutput(" EAX=0x%x", ExceptionInfo->ContextRecord->Eax);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Eax);
		}

		if (LastContext.Ebx != ExceptionInfo->ContextRecord->Ebx)
		{
			DebuggerOutput(" EBX=0x%x", ExceptionInfo->ContextRecord->Ebx);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Ebx);
		}

		if (LastContext.Ecx != ExceptionInfo->ContextRecord->Ecx)
		{
			DebuggerOutput(" ECX=0x%x", ExceptionInfo->ContextRecord->Ecx);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Ecx);
		}

		if (LastContext.Edx != ExceptionInfo->ContextRecord->Edx)
		{
			DebuggerOutput(" EDX=0x%x", ExceptionInfo->ContextRecord->Edx);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Edx);
		}

		if (LastContext.Esi != ExceptionInfo->ContextRecord->Esi)
		{
			DebuggerOutput(" ESI=0x%x", ExceptionInfo->ContextRecord->Esi);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Esi);
		}

		if (LastContext.Edi != ExceptionInfo->ContextRecord->Edi)
		{
			DebuggerOutput(" EDI=0x%x", ExceptionInfo->ContextRecord->Edi);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Edi);
		}

		if (LastContext.Esp != ExceptionInfo->ContextRecord->Esp)
		{
			DebuggerOutput(" ESP=0x%x", ExceptionInfo->ContextRecord->Esp);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Esp);
			DebuggerOutput(" *ESP=0x%x", *(DWORD*)ExceptionInfo->ContextRecord->Esp);
			StringCheck((PVOID)*(DWORD*)ExceptionInfo->ContextRecord->Esp);
		}

		if (LastContext.Ebp != ExceptionInfo->ContextRecord->Ebp)
		{
			DebuggerOutput(" EBP=0x%x", ExceptionInfo->ContextRecord->Ebp);
			StringCheck((PVOID)ExceptionInfo->ContextRecord->Ebp);
		}
#endif
	}

	if (!FilterTrace)
		DebuggerOutput("\n");

	ModuleName = convert_address_to_dll_name_and_offset((ULONG_PTR)CIP, &DllRVA);

	if (ModuleName)
	{
		if (!PreviousModuleName || strncmp(ModuleName, PreviousModuleName, strlen(ModuleName)))
		{
			PCHAR FunctionName;
			PVOID ImageBase = (PVOID)((PUCHAR)CIP - DllRVA);

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
			{
				DebuggerOutput("Break at 0x%p in %s::%s (RVA 0x%x, thread %d, ImageBase 0x%p)\n", CIP, ModuleName, FunctionName, DllRVA, GetCurrentThreadId(), ImageBase);

				ForceStepOver = DoStepOver(FunctionName);

				for (unsigned int i = 0; i < ARRAYSIZE(g_config.trace_into_api); i++)
				{
					if (!g_config.trace_into_api[i])
						break;
					if (!stricmp(FunctionName, g_config.trace_into_api[i]))
						StepOver = FALSE;
				}
			}
			else
				DebuggerOutput("Break at 0x%p in %s (RVA 0x%x, thread %d, ImageBase 0x%p)\n", CIP, ModuleName, DllRVA, GetCurrentThreadId(), ImageBase);
			if (PreviousModuleName)
				free (PreviousModuleName);
			PreviousModuleName = ModuleName;
		}
	}

	if (g_config.step_out)
	{
		unsigned int Register = 1, Delta = 0, ChunkSize = 0x300, MaxInstructions = 0x100;	// Size of code to disassemble to search for ret
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
				if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &StepOverRegister, 0, (BYTE*)CIP + Delta, BP_EXEC, 0, StepOutCallback))
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
	if ((Instruction0 && !strnicmp(DecodedInstruction.mnemonic.p, Instruction0, strlen(Instruction0))) || (!Instruction0 && pBreakpointInfo->Register == 0 && strlen(Action0)))
		ActionDispatcher(ExceptionInfo, DecodedInstruction, Action0);

	if ((Instruction1 && !strnicmp(DecodedInstruction.mnemonic.p, Instruction1, strlen(Instruction1))) || (!Instruction1 && pBreakpointInfo->Register == 1 && strlen(Action1)))
		ActionDispatcher(ExceptionInfo, DecodedInstruction, Action1);

	if ((Instruction2 && !strnicmp(DecodedInstruction.mnemonic.p, Instruction2, strlen(Instruction2))) || (!Instruction2 && pBreakpointInfo->Register == 2 && strlen(Action2)))
		ActionDispatcher(ExceptionInfo, DecodedInstruction, Action2);

	if ((Instruction3 && !strnicmp(DecodedInstruction.mnemonic.p, Instruction3, strlen(Instruction3))) || (!Instruction3 && pBreakpointInfo->Register == 3 && strlen(Action3)))
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
		PCHAR ExportName = NULL;
		PVOID CallTarget = NULL;

		ReturnAddress = (PVOID)((PUCHAR)CIP + DecodedInstruction.size);

		if (DecodedInstruction.size > 4 && DecodedInstruction.operands.length && !strncmp(DecodedInstruction.operands.p, "DWORD", 5) && strncmp(DecodedInstruction.operands.p, "DWORD [E", 8))
		{
			CallTarget = *(PVOID*)((PUCHAR)CIP + DecodedInstruction.size - 4);

			if (!strncmp(DecodedInstruction.operands.p, "DWORD [FS:0xc0]", 15))
			{
				TraceOutput(CIP, DecodedInstruction);
				ForceStepOver = TRUE;
			}
			else
			{
				__try
				{
					ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
					if (!ExportName)
						ExportName = ScyllaGetExportNameByAddress(*(PVOID*)CallTarget, NULL);
				}
				__except(EXCEPTION_EXECUTE_HANDLER)
				{
					DebugOutput("BreakpointCallback: Error dereferencing CallTarget 0x%x.\n", CallTarget);
					ExportName = NULL;
				}
			}

			if (ExportName)
			{
				TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else if (!strncmp(DecodedInstruction.operands.p, "DWORD [0x", 9))
			{
				TraceOutput(CIP, DecodedInstruction);
			}
			else
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
		}
		else if (DecodedInstruction.size > 4)
		{
			CallTarget = (PVOID)((PUCHAR)CIP + (int)*(DWORD*)((PUCHAR)CIP + DecodedInstruction.size - 4) + DecodedInstruction.size);
			__try
			{
				ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
				if (!ExportName)
					ExportName = ScyllaGetExportNameByAddress(*(PVOID*)CallTarget, NULL);
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				DebugOutput("BreakpointCallback: Error dereferencing CallTarget 0x%x.", CallTarget);
				ExportName = NULL;
			}

			if (ExportName)
			{
				TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
		}
		else if (!strncmp(DecodedInstruction.operands.p, "EAX", 3))
		{
#ifdef _WIN64
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rax;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#else
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Eax;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#endif
		}
		else if (!strncmp(DecodedInstruction.operands.p, "EBX", 3))
		{
#ifdef _WIN64
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rbx;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#else
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Ebx;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#endif
		}
		else if (!strncmp(DecodedInstruction.operands.p, "ECX", 3))
		{
#ifdef _WIN64
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rcx;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#else
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Ecx;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#endif
		}
		else if (!strncmp(DecodedInstruction.operands.p, "EDX", 3))
		{
#ifdef _WIN64
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rdx;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#else
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Edx;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#endif
		}
		else if (!strncmp(DecodedInstruction.operands.p, "EBP", 3))
		{
#ifdef _WIN64
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rbp;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#else
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Ebp;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#endif
		}
		else if (!strncmp(DecodedInstruction.operands.p, "ESI", 3))
		{
#ifdef _WIN64
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rsi;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#else
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Esi;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#endif
		}
		else if (!strncmp(DecodedInstruction.operands.p, "EDI", 3))
		{
#ifdef _WIN64
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rdi;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#else
			CallTarget = (PVOID)ExceptionInfo->ContextRecord->Edi;
			ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
			if (ExportName)
			{
				TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				StepOver = TRUE;
			}
			else
				TraceOutputFuncAddress(CIP, DecodedInstruction, CallTarget);
#endif
		}
		else
			TraceOutput(CIP, DecodedInstruction);

		if (ExportName)
		{
			ForceStepOver = DoStepOver(ExportName);

			for (unsigned int i = 0; i < ARRAYSIZE(g_config.trace_into_api); i++)
			{
				if (!g_config.trace_into_api[i])
					break;
				if (!stricmp(ExportName, g_config.trace_into_api[i]))
				{
					StepOver = FALSE;
					if (TraceDepthCount > 0)
						TraceDepthCount--;
					DebuggerOutput("\nBreakpointCallback: Stepping into %s\n", ExportName);
				}
			}
		}

		if (CallTarget == &loq)
		{
			ExportName = "loq";
			ForceStepOver = TRUE;
		}

		if (CallTarget == &log_flush)
		{
			ExportName = "log_flush";
			ForceStepOver = TRUE;
		}

		if (!StepLimit || StepCount >= StepLimit || StopTrace)
		{
			ReturnAddress = NULL;
			ForceStepOver = FALSE;
			StepOver = FALSE;
		}
		else if (ReturnAddress && ((unsigned int)abs(TraceDepthCount) >= TraceDepthLimit && !g_config.trace_all) || (StepOver == TRUE && !g_config.trace_all) || ForceStepOver)
		{
			if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &StepOverRegister, 0, (BYTE*)ReturnAddress, BP_EXEC, 1, BreakpointCallback))
				DebugOutput("BreakpointCallback: Failed to set breakpoint on return address 0x%p\n", ReturnAddress);
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
//	else if (!strcmp(DecodedInstruction.mnemonic.p, "RET"))
//	{
//		if (!FilterTrace || g_config.trace_all)
//			TraceOutput(CIP, DecodedInstruction);
//		if (!g_config.trace_all && TraceDepthCount > 0)
//			TraceDepthCount--;
//	}
	else if (!strcmp(DecodedInstruction.mnemonic.p, "JMP"))
	{
		PCHAR ExportName = NULL;
		PVOID JumpTarget = NULL;
#ifdef _WIN64
		ReturnAddress = *(PVOID*)(ExceptionInfo->ContextRecord->Rsp);

		if (DecodedInstruction.size > 4 && DecodedInstruction.operands.length && !strncmp(DecodedInstruction.operands.p, "QWORD", 5) && strncmp(DecodedInstruction.operands.p, "QWORD [E", 8))
		{
			if (!strncmp(DecodedInstruction.operands.p, "QWORD [0x", 9))
				JumpTarget = *(PVOID*)(*(PVOID*)((PUCHAR)CIP + DecodedInstruction.size - 4));
			else
				// begins with QWORD except "QWORD [E"
#else
		ReturnAddress = *(PVOID*)(ExceptionInfo->ContextRecord->Esp);

		if (DecodedInstruction.size > 4 && DecodedInstruction.operands.length && !strncmp(DecodedInstruction.operands.p, "DWORD", 5) && strncmp(DecodedInstruction.operands.p, "DWORD [E", 8))
		{
			if (!strncmp(DecodedInstruction.operands.p, "DWORD [0x", 9))
				JumpTarget = *(PVOID*)(*(PVOID*)((PUCHAR)CIP + DecodedInstruction.size - 4));
			else
				// begins with DWORD except "DWORD [E"
#endif
				JumpTarget = *(PVOID*)((PUCHAR)CIP + DecodedInstruction.size - 4);

			__try
			{
				ExportName = ScyllaGetExportNameByAddress(JumpTarget, NULL);
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				DebugOutput("BreakpointCallback: Error dereferencing JumpTarget 0x%p.\n", JumpTarget);
				ExportName = NULL;
			}

			if (ExportName)
			{
				if (!FilterTrace || g_config.trace_all)
					TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
				if (!g_config.trace_all)
					ForceStepOver = TRUE;
			}
			else if (!FilterTrace || g_config.trace_all)
				TraceOutputFuncAddress(CIP, DecodedInstruction, JumpTarget);

			//if (is_in_dll_range((ULONG_PTR)JumpTarget))
			//	ForceStepOver = TRUE;
			if (inside_hook(JumpTarget) && g_config.trace_all < 2)
				ForceStepOver = TRUE;
		}
		else if (DecodedInstruction.size > 4)
		{
			JumpTarget = (PVOID)((PUCHAR)CIP + (int)*(DWORD*)((PUCHAR)CIP + DecodedInstruction.size - 4) + DecodedInstruction.size);
			__try
			{
				ExportName = ScyllaGetExportNameByAddress(JumpTarget, NULL);
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				DebugOutput("BreakpointCallback: Error dereferencing JumpTarget 0x%p.", JumpTarget);
				ExportName = NULL;
			}

			if (ExportName)
			{
				if (!FilterTrace || g_config.trace_all)
					TraceOutputFuncName(CIP, DecodedInstruction, ExportName);
			}
			else
				if (!FilterTrace || g_config.trace_all)
					TraceOutputFuncAddress(CIP, DecodedInstruction, JumpTarget);
		}
		else if (!FilterTrace || g_config.trace_all)
			TraceOutput(CIP, DecodedInstruction);

		if (is_in_dll_range((ULONG_PTR)JumpTarget))
			ForceStepOver = TRUE;
	}
	else if (!FilterTrace)
		TraceOutput(CIP, DecodedInstruction);

	LastContext = *ExceptionInfo->ContextRecord;

	ResumeFromBreakpoint(ExceptionInfo->ContextRecord);

	if (!StepLimit || StepCount > StepLimit || StopTrace)
	{
		DebuggerOutput("\nBreakpointCallback: Single-step limit reached (%d), releasing.\n", StepLimit);
		memset(&LastContext, 0, sizeof(CONTEXT));
		StopTrace = TRUE;
		StepCount = 0;
		TraceRunning = FALSE;
		ReturnAddress = NULL;
	}

	if (!StopTrace)
	{
		if (ForceStepOver && ReturnAddress)
		{
			if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &StepOverRegister, 0, (BYTE*)ReturnAddress, BP_EXEC, 1, BreakpointCallback))
			{
				DebugOutput("BreakpointCallback: Set breakpoint on return address 0x%p\n", ReturnAddress);
				ReturnAddress = NULL;
			}
			else
				DebugOutput("BreakpointCallback: Failed to set breakpoint on return address 0x%p\n", ReturnAddress);
		}
		else
			DoSetSingleStepMode(pBreakpointInfo->Register, ExceptionInfo->ContextRecord, Trace);
	}

	return TRUE;
}

BOOL BreakOnReturnCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID CIP;
	unsigned int DllRVA;

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

	ModuleName = convert_address_to_dll_name_and_offset((ULONG_PTR)CIP, &DllRVA);

	if (ModuleName)
	{
		PCHAR FunctionName;
		__try
		{
			FunctionName = ScyllaGetExportNameByAddress(CIP, NULL);
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			DebugOutput("BreakOnReturnCallback: Error dereferencing instruction pointer 0x%p.\n", CIP);
		}
		if (FunctionName)
			DebuggerOutput("\nBreak at 0x%p in %s::%s (RVA 0x%x, thread %d), releasing until return address 0x%p\n", CIP, ModuleName, FunctionName, DllRVA, GetCurrentThreadId(), ReturnAddress);
		else
			DebuggerOutput("\nBreak at 0x%p in %s (RVA 0x%x, thread %d), releasing until return address 0x%p\n", CIP, ModuleName, DllRVA, GetCurrentThreadId(), ReturnAddress);
	}

	if (!ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &StepOverRegister, 0, (BYTE*)ReturnAddress, BP_EXEC, 1, BreakpointCallback))
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

	TraceOutput(CIP, DecodedInstruction);

	return TRUE;
}

BOOL BreakpointOnReturn(PVOID Address)
{
	// Reset trace depth count
	TraceDepthCount = 0;

	if (!BreakOnReturnAddress)
	{
		if (!SetNextAvailableBreakpoint(GetCurrentThreadId(), &BreakOnReturnRegister, 0, Address, BP_EXEC, 0, BreakpointCallback))
		{
			DebugOutput("BreakpointOnReturn: failed to set breakpoint.\n");
			return FALSE;
		}
		BreakOnReturnAddress = Address;
	}
	else
	{
		if (!SetThreadBreakpoint(GetCurrentThreadId(), BreakOnReturnRegister, 0, Address, BP_EXEC, 0, BreakpointCallback))
		{
			DebugOutput("BreakpointOnReturn: failed to set breakpoint.\n");
			return FALSE;
		}
		BreakOnReturnAddress = Address;
	}

	DebugOutput("BreakpointOnReturn: execution breakpoint set at 0x%p with register %d.", Address, BreakOnReturnRegister);
	return TRUE;
}

BOOL SetConfigBP(PVOID ImageBase, DWORD Register, PVOID Address)
{
	PVOID Callback = NULL;
	DWORD_PTR BreakpointVA = 0;
	unsigned int Type = 0, HitCount = 0;

	if (g_config.file_offsets)
	{
		if (!IsDisguisedPEHeader(ImageBase))
		{
			DebugOutput("SetInitialBreakpoints: File offsets cannot be applied to non-PE image at 0x%p.\n", ImageBase);
			BreakpointsSet = FALSE;
			return FALSE;
		}
		BreakpointVA = FileOffsetToVA((DWORD_PTR)ImageBase, (DWORD_PTR)Address);
	}
	else
	{
		if ((SIZE_T)Address > RVA_LIMIT)
			BreakpointVA = (DWORD_PTR)Address;
		else
			BreakpointVA = (DWORD_PTR)ImageBase + (DWORD_PTR)Address;
	}

	if (Register == 0)
	{
		if (!Type0)
		{
			Type = BP_EXEC;
			Callback = BreakpointCallback;
		}
		else if (Type0 == BP_WRITE)
		{
			Type = BP_WRITE;
			Callback = WriteCallback;
		}
		HitCount = g_config.hc0;
	}
	else if (Register == 1)
	{
		if (!Type1)
		{
			Type = BP_EXEC;
			Callback = BreakpointCallback;
		}
		else if (Type1 == BP_WRITE)
		{
			Type = BP_WRITE;
			Callback = WriteCallback;
		}
		HitCount = g_config.hc1;
	}
	else if (Register == 2)
	{
		if (!Type2)
		{
			Type = BP_EXEC;
			Callback = BreakpointCallback;
		}
		else if (Type2 == BP_WRITE)
		{
			Type = BP_WRITE;
			Callback = WriteCallback;
		}
		HitCount = g_config.hc2;
	}
	else if (Register == 3)
	{
		if (!Type3)
		{
			Type = BP_EXEC;
			Callback = BreakpointCallback;
		}
		else if (Type3 == BP_WRITE)
		{
			Type = BP_WRITE;
			Callback = WriteCallback;
		}
		HitCount = g_config.hc3;
	}

	if (SetBreakpoint(Register, 0, (BYTE*)BreakpointVA, Type, HitCount, Callback))
	{
		DebugOutput("SetInitialBreakpoints: Breakpoint %d set on address 0x%p (RVA 0x%x, type %d, hit count %d, thread %d)\n", Register, BreakpointVA, Address, Type, HitCount, GetCurrentThreadId());
		BreakpointsSet = TRUE;
		return TRUE;
	}

	DebugOutput("SetInitialBreakpoints: SetBreakpoint failed for breakpoint %d.\n", Register);
	BreakpointsSet = FALSE;
	return FALSE;
}

BOOL SetInitialBreakpoints(PVOID ImageBase)
{
	DWORD_PTR BreakpointVA = 0;
	DWORD Register = 0;

	if (BreakpointsHit)
		return TRUE;

	if (procname0 && !stristr(GetCommandLineA(), procname0))
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

	if (!ImageBase)
		ImageBase = GetModuleHandle(NULL);

#ifdef STANDALONE
	TraceDepthLimit = 5;
#endif

	if (g_config.break_on_apiname_set)
	{
		HANDLE Module = GetModuleHandle(g_config.break_on_modname);
		if (Module)
			g_config.bp0 = GetProcAddress(Module, g_config.break_on_apiname);
		else
			DebuggerOutput("Failed to get base for module (%s).", g_config.break_on_modname);
		if (g_config.bp0)
			DebuggerOutput("bp0 set to 0x%p (%s::%s).", g_config.bp0, g_config.break_on_modname, g_config.break_on_apiname);
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

			if (SetBreakpoint(Register, 0, (BYTE*)EntryPoint, BP_EXEC, 0, BreakpointCallback))
			{
				DebuggerOutput("Breakpoint %d set on entry point at 0x%p\n", Register, EntryPoint);
				BreakpointsSet = TRUE;
				g_config.bp0 = EntryPoint;
			}
			else
			{
				DebuggerOutput("SetBreakpoint on entry point failed.\n");
				BreakpointsSet = FALSE;
				return FALSE;
			}
		}
	}
	else if (g_config.bp0)
		SetConfigBP(ImageBase, 0, g_config.bp0);

	if (g_config.bp1)
		SetConfigBP(ImageBase, 1, g_config.bp1);

	if (g_config.bp2)
		SetConfigBP(ImageBase, 2, g_config.bp2);

	if (g_config.bp3)
		SetConfigBP(ImageBase, 3, g_config.bp3);

	if (g_config.zerobp0)
		SetConfigBP(ImageBase, 0, 0);

	if (g_config.zerobp1)
		SetConfigBP(ImageBase, 1, 0);

	if (g_config.zerobp2)
		SetConfigBP(ImageBase, 2, 0);

	if (g_config.zerobp3)
		SetConfigBP(ImageBase, 3, 0);

	if (!g_config.bp0 && g_config.br0)
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

		if (SetBreakpoint(Register, 0, (BYTE*)BreakpointVA, BP_EXEC, 0, BreakOnReturnCallback))
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

	if (!g_config.bp1 && g_config.br1)
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

		if (SetBreakpoint(Register, 0, (BYTE*)BreakpointVA, BP_EXEC, 0, BreakOnReturnCallback))
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
