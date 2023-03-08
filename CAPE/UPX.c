/*
CAPE - Config And Payload Extraction
Copyright(C) 2020 Kevin O'Reilly (kevoreilly@gmail.com)

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
#include <stdio.h>
#include <windows.h>
#include <distorm.h>
#include <psapi.h>
#include "Debugger.h"

#define MAX_INSTRUCTIONS 0x10
#define SINGLE_STEP_LIMIT 0x100
#define CHUNKSIZE 0x10 * MAX_INSTRUCTIONS
#define MINIMUM_EIP_DELTA 0x2000

extern ULONG_PTR base_of_dll_of_interest;

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern void ErrorOutput(_In_ LPCTSTR lpOutputString, ...);
extern void DebuggerOutput(_In_ LPCTSTR lpOutputString, ...);

extern int DumpCurrentProcessFixImports(LPVOID NewEP);
extern DWORD_PTR GetEntryPointVA(DWORD_PTR modBase);
extern BOOL BreakpointsSet;

unsigned int StepCount, StepLimit;
DWORD_PTR LastEIP, CurrentEIP, EIPDelta, UPX_OEP;
SIZE_T LastWriteLength;
MODULEINFO modinfo;
static CONTEXT LastContext;
SIZE_T LastWriteLength;
CHAR DebuggerBuffer[MAX_PATH];
BOOL TraceRunning;

void DisassembleCIP(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID CIP;
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

	Result = distorm_decode(Offset, (const unsigned char*)CIP, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount);

	DebuggerOutput("0x%x (%02d) %-20s %-6s%-4s%-30s\n", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
}

BOOL SingleStepToOEP(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID CIP;
	_DecodeType DecodeType;
	_DecodeResult Result;
	_OffsetType Offset = 0;
	_DecodedInst DecodedInstruction;
	unsigned int DecodedInstructionsCount = 0;

	TraceRunning = TRUE;
#ifdef _WIN64
	CIP = (PVOID)(DWORD_PTR)ExceptionInfo->ContextRecord->Rip;
	DecodeType = Decode64Bits;
#else
	CIP = (PVOID)ExceptionInfo->ContextRecord->Eip;
	DecodeType = Decode32Bits;
#endif

	if (!modinfo.lpBaseOfDll)
	{
		DebuggerOutput("SingleStepToOEP: Module information not present for the target module.\n");
		return FALSE;
	}

	if ((DWORD_PTR)CIP < (DWORD_PTR)modinfo.lpBaseOfDll || (DWORD_PTR)CIP > (DWORD_PTR)modinfo.lpBaseOfDll + modinfo.SizeOfImage)
	{
		DebuggerOutput("SingleStepToOEP: EIP 0x%x is not within the target module (0x%x-0x%x).\n", CIP, modinfo.lpBaseOfDll, (PBYTE)modinfo.lpBaseOfDll + modinfo.SizeOfImage);
		return FALSE;
	}

	if (!LastEIP)
	{
		LastEIP = (DWORD_PTR)CIP;
		StepCount = 0;
		DebuggerOutput("Entering single-step mode until OEP\n");
		SetSingleStepMode(ExceptionInfo->ContextRecord, SingleStepToOEP);
		return TRUE;
	}

#ifdef _WIN64
	if (LastContext.Rip)
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
#else
	if (LastContext.Eip)
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

	DebuggerOutput("\n");

	StepCount++;

	if (StepCount > StepLimit)
	{
		DebuggerOutput("Single-step limit reached (%d), releasing.\n", StepLimit);
		StepCount = 0;
		return TRUE;
	}

	Result = distorm_decode(Offset, (const unsigned char*)CIP, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount);

#ifdef _WIN64
	DebuggerOutput("0x%x (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#else
	DebuggerOutput("0x%x (%02d) %-20s %-6s%-4s%-30s", (unsigned int)CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#endif
	CurrentEIP = (DWORD_PTR)CIP;

	if (CurrentEIP > LastEIP)
		EIPDelta = (unsigned int)(CurrentEIP - LastEIP);
	else
		EIPDelta = (unsigned int)(LastEIP - CurrentEIP);

	if (EIPDelta > MINIMUM_EIP_DELTA && EIPDelta < modinfo.SizeOfImage)
	{
		UPX_OEP = CurrentEIP;
		DebuggerOutput("\nSingleStepToOEP: Found OEP = 0x%p, dumping unpacked payload.", UPX_OEP);
		DumpCurrentProcessFixImports((PVOID)UPX_OEP);
	}
	else
	{
		LastEIP = CurrentEIP;
#ifdef _DEBUG
		DebuggerOutput("\nSingleStepToOEP: EIPDelta = 0x%x", EIPDelta);
#endif
		LastContext = *ExceptionInfo->ContextRecord;
		SetSingleStepMode(ExceptionInfo->ContextRecord, SingleStepToOEP);
	}

	return TRUE;
}

BOOL StackReadCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID CIP;
#ifdef _WIN64
	CIP = (PVOID)ExceptionInfo->ContextRecord->Rip;
#else
	CIP = (PVOID)ExceptionInfo->ContextRecord->Eip;
#endif

	if (pBreakpointInfo == NULL)
	{
		DebuggerOutput("StackReadCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DebuggerOutput("StackReadCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	DebuggerOutput("StackReadCallback: Breakpoint %i Size=0x%x, Address=0x%x, EIP=0x%x\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address, CIP);

	if (!modinfo.lpBaseOfDll)
	{
		DebuggerOutput("StackReadCallback: module information not present for the target module.\n");
		return FALSE;
	}

	if ((DWORD_PTR)CIP < (DWORD_PTR)modinfo.lpBaseOfDll || (DWORD_PTR)CIP > (DWORD_PTR)modinfo.lpBaseOfDll + modinfo.SizeOfImage)
	{
		DebuggerOutput("StackReadCallback: Breakpoint EIP 0x%x is not within the target module (0x%x-0x%x).\n", CIP, modinfo.lpBaseOfDll, (PBYTE)modinfo.lpBaseOfDll + modinfo.SizeOfImage);
		return FALSE;
	}

	ContextClearBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo->Register);

	LastContext = *ExceptionInfo->ContextRecord;

	// Turn on single-step mode which will dump on OEP
	SetSingleStepMode(ExceptionInfo->ContextRecord, SingleStepToOEP);

	DisassembleCIP(ExceptionInfo);

	return TRUE;
}

BOOL StackWriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID CIP;
#ifdef _WIN64
	CIP = (PVOID)ExceptionInfo->ContextRecord->Rip;
#else
	CIP = (PVOID)ExceptionInfo->ContextRecord->Eip;
#endif

	if (pBreakpointInfo == NULL)
	{
		DebuggerOutput("StackWriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DebuggerOutput("StackWriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	DebuggerOutput("StackWriteCallback: Breakpoint %i Size=0x%x, Address=0x%x, EIP=0x%x\n", pBreakpointInfo->Register, pBreakpointInfo->Size, pBreakpointInfo->Address, CIP);

	// Let's find out the size of the module in memory, to enable a sanity check for the eip values
	if (base_of_dll_of_interest == 0)
		GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &modinfo, sizeof(MODULEINFO));
	else
		GetModuleInformation(GetCurrentProcess(), (HMODULE)base_of_dll_of_interest, &modinfo, sizeof(MODULEINFO));

	if (!modinfo.lpBaseOfDll)
	{
		DebuggerOutput("StackWriteCallback: failed to get module information for the target module.\n");
		return FALSE;
	}

	if ((DWORD_PTR)CIP < (DWORD_PTR)modinfo.lpBaseOfDll || (DWORD_PTR)CIP > (DWORD_PTR)modinfo.lpBaseOfDll + modinfo.SizeOfImage)
	{
		DebuggerOutput("StackWriteCallback: Breakpoint EIP 0x%x is not within the target module (0x%x-0x%x).\n", CIP, modinfo.lpBaseOfDll, (PBYTE)modinfo.lpBaseOfDll + modinfo.SizeOfImage);
		return FALSE;
	}

	if (ContextUpdateCurrentBreakpoint(ExceptionInfo->ContextRecord, 1, (BYTE*)pBreakpointInfo->Address, BP_READWRITE, 0, StackReadCallback))
	{
		DebuggerOutput("StackWriteCallback: Updated breakpoint to break on read (& write).\n");
	}
	else
	{
		DebuggerOutput("StackWriteCallback: ContextUpdateCurrentBreakpoint failed.\n");
		return FALSE;
	}

	DisassembleCIP(ExceptionInfo);

	DebuggerOutput("StackWriteCallback executed successfully.\n");

	return TRUE;
}

BOOL EntryPointCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID StackPointer;

	if (pBreakpointInfo == NULL)
	{
		DebuggerOutput("EntryPointCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DebuggerOutput("EntryPointCallback executed with NULL thread handle.\n");
		return FALSE;
	}

	StepCount = 0;
#ifdef _WIN64
	StackPointer = (PVOID)(ExceptionInfo->ContextRecord->Rsp - 1);
#else
	StackPointer = (PVOID)(ExceptionInfo->ContextRecord->Esp - 1);
#endif

	if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo->Register, 1, (BYTE*)StackPointer, BP_WRITE, 0, StackWriteCallback))
	{
		DebuggerOutput("EntryPointCallback: Failed to set write breakpoint on stack.\n");
		return FALSE;
	}

	DisassembleCIP(ExceptionInfo);

	DebuggerOutput("EntryPointCallback: Write breakpoint set on stack at 0x%p\n", StackPointer);

	return TRUE;
}

BOOL UPXInitialBreakpoints(PVOID ImageBase)
{
	DWORD Register;

	if (!ImageBase)
	{
		ImageBase = GetModuleHandle(NULL);
		DebuggerOutput("ImageBase not set by base-on-api parameter, defaulting to process image base 0x%p.\n", ImageBase);
		return FALSE;
	}
	else
		DebuggerOutput("ImageBase set to 0x%p.\n", ImageBase);

	PVOID EntryPoint = (PVOID)GetEntryPointVA((DWORD_PTR)ImageBase);

	if (!StepLimit)
		StepLimit = SINGLE_STEP_LIMIT;

	if (EntryPoint)
	{
		if (SetNextAvailableBreakpoint(GetCurrentThreadId(), &Register, 0, (BYTE*)EntryPoint, BP_EXEC, 0, EntryPointCallback))
			DebuggerOutput("Breakpoint %d set on entry point at 0x%p.\n", Register, EntryPoint);
		else
		{
			DebuggerOutput("SetBreakpoint on entry point failed.\n");
			return FALSE;
		}
	}

	BreakpointsSet = TRUE;

	return TRUE;
}
