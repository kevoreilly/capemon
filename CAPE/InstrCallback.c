//#define DEBUG_COMMENTS

#include <stdio.h>
#include "..\ntapi.h"
#include <psapi.h>
#include "..\misc.h"
#include "..\lookup.h"
#include "..\config.h"
#include "CAPE.h"
#include "Debugger.h"
#include "Unpacker.h"
#include "YaraHarness.h"

#define SE_DEBUG_PRIVILEGE 0x14

#pragma pack(1)
typedef struct _IMAGE_CFG_ENTRY {
	DWORD Rva;
    struct {
        BOOLEAN SuppressedCall : 1;
        BOOLEAN ExportSuppressed : 1;
        BOOLEAN LangExcptHandler : 1;
        BOOLEAN Xfg : 1;
        BOOLEAN Reserved : 4;
    } Flags;
} IMAGE_CFG_ENTRY, *PIMAGE_CFG_ENTRY;

extern void InstrHook(void);
extern BOOL inside_hook(LPVOID Address);
extern BOOL BreakpointOnReturn(PVOID Address);
extern void DebuggerOutput(_In_ LPCTSTR lpOutputString, ...);
extern void log_syscall(PUNICODE_STRING module, const char *function, PVOID retaddr, DWORD retval);
extern int __called_by_hook(ULONG_PTR stack_pointer, ULONG_PTR frame_pointer);
extern _NtSetInformationProcess pNtSetInformationProcess;
extern ULONG_PTR ntdll_base, win32u_base;
extern lookup_t g_caller_regions;
extern ULONG_PTR base_of_dll_of_interest;
extern PVOID ImageBase;

#define SCANMIN 7
#define SCANMAX 24

unsigned int ScanForSsn(PVOID Address)
{
	if (!Address)
		return 0;

	__try
	{
		for (unsigned int i = SCANMIN; i < SCANMAX; i++)
		{
			if (*((PBYTE)Address-i) == 0xb8 && !*(PWORD)((PBYTE)Address+3-i))
				return (unsigned int)*(PWORD)((PBYTE)Address+1-i);
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return 0;
	}

	return 0;
}

PCHAR GetNameBySsn(unsigned int Number)
{
	if (!Number || Number >= 0x1000)	// we ignore SSN 0
		return NULL;

	if (!ntdll_base)
		return NULL;

	// based on https://www.mdsec.co.uk/2022/04/resolving-system-service-numbers-using-the-exception-directory
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)ntdll_base + (ULONG)((PIMAGE_DOS_HEADER)ntdll_base)->e_lfanew);
#ifdef _WIN64
	// using runtime function table on x64 just for fun
	PIMAGE_RUNTIME_FUNCTION_ENTRY RuntimeFunctionTable = (PIMAGE_RUNTIME_FUNCTION_ENTRY)((PUCHAR)ntdll_base + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
#else
	PIMAGE_LOAD_CONFIG_DIRECTORY LoadConfigDirectory = (PIMAGE_LOAD_CONFIG_DIRECTORY)((PUCHAR)ntdll_base + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
	PIMAGE_CFG_ENTRY CfgEntry = (PIMAGE_CFG_ENTRY)LoadConfigDirectory->GuardCFFunctionTable;
#endif
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ntdll_base + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD AddressOfNames = (PDWORD)((PUCHAR)ntdll_base + ExportDirectory->AddressOfNames);
	PDWORD AddressOfFunctions = (PDWORD)((PUCHAR)ntdll_base + ExportDirectory->AddressOfFunctions);
	PWORD AddressOfNameOrdinals = (PWORD)((PUCHAR)ntdll_base + ExportDirectory->AddressOfNameOrdinals);

#ifdef _WIN64
	for (unsigned int i = 0, SystemServiceNumber = 0; RuntimeFunctionTable[i].BeginAddress; i++)
#else
	for (unsigned int i = 0, SystemServiceNumber = 0; CfgEntry[i].Rva; i++)
#endif
	{
		for (unsigned int j = 0; j < ExportDirectory->NumberOfFunctions; j++)
		{
#ifdef _WIN64
			if (AddressOfFunctions[AddressOfNameOrdinals[j]] == RuntimeFunctionTable[i].BeginAddress)
#else
			if (AddressOfFunctions[AddressOfNameOrdinals[j]] == CfgEntry[i].Rva)
#endif
			{
				PCHAR Name = (PCHAR)ntdll_base + AddressOfNames[j];
				if (Number == SystemServiceNumber)
				{
#ifdef DEBUG_COMMENTS
					DebugOutput("GetNameBySsn: %s", Name);
#endif
					return Name;
				}
				if (!strncmp(Name, "Zw", 2))
					SystemServiceNumber++;
			}
		}
	}

    return NULL;
}

// https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/teb/index.htm
#ifdef _WIN64
#define InstrumentationCallbackPreviousPc	0x2d8
#define InstrumentationCallbackPreviousSp	0x2e0
#else
#define InstrumentationCallbackPreviousPc	0x1b0
#define InstrumentationCallbackPreviousSp	0x1b4
#endif
#define InstrumentationCallbackDisabled		0x1b8

#ifdef _WIN64
VOID InstrumentationCallback(PCONTEXT Context)
{
	// based on https://gist.github.com/esoterix/df38008568c50d4f83123e3a90b62ebb
	ULONG_PTR pTEB = (ULONG_PTR)NtCurrentTeb();
	Context->Rcx = Context->R10;
	Context->Rsp = *((ULONG_PTR*)(pTEB + InstrumentationCallbackPreviousSp));
	Context->Rip = *((ULONG_PTR*)(pTEB + InstrumentationCallbackPreviousPc));
	unsigned int ReturnValue = (unsigned int)Context->Rax & 0xFFFFFFFF;
	PVOID ReturnAddress = *(PVOID*)Context->Rsp;
	PVOID CIP = (PVOID)Context->Rip;
#else
VOID InstrumentationCallback(PVOID CIP, unsigned int ReturnValue)
{
	ULONG_PTR pTEB = (ULONG_PTR)NtCurrentTeb();
	PVOID ReturnAddress = *(PVOID*)*((ULONG_PTR*)(pTEB + InstrumentationCallbackPreviousSp));
#endif
	*((ULONG_PTR*)(pTEB + InstrumentationCallbackPreviousPc)) = 0;
	*((ULONG_PTR*)(pTEB + InstrumentationCallbackPreviousSp)) = 0;

	if (InterlockedOr(((LONG*)pTEB + InstrumentationCallbackDisabled), 1) == 1)
	{
		*((BOOLEAN*)pTEB + InstrumentationCallbackDisabled) = TRUE;

		if (g_config.syscall > 1 && is_address_in_win32u((ULONG_PTR)CIP))
		{
			PUNICODE_STRING ModuleName = get_basename_of_module((HMODULE)win32u_base);
			log_syscall(ModuleName, ScanForExport((PVOID)CIP, SCANMAX), (PVOID)CIP, (DWORD)(DWORD_PTR)ReturnValue);
		}
		else if (g_config.syscall && !inside_hook(CIP) && !is_address_in_ntdll((ULONG_PTR)CIP) && !is_address_in_win32u((ULONG_PTR)CIP))
		{
			PVOID AllocationBase = GetAllocationBase((PVOID)CIP);
			PUNICODE_STRING ModuleName = get_basename_of_module((HMODULE)AllocationBase);
			PCHAR FunctionName = GetNameBySsn(ScanForSsn((PVOID)CIP));
#ifdef DEBUG_COMMENTS
			DebugOutput("InstrumentationCallback: Returns to 0x%p, return value %d, ssn %d -> %s)\n", CIP, ReturnValue, ScanForSsn((PVOID)CIP), FunctionName);
#endif
			log_syscall(ModuleName, FunctionName, (PVOID)CIP, (DWORD)(DWORD_PTR)ReturnValue);
			if (g_config.caller_regions && AllocationBase && !lookup_get(&g_caller_regions, (ULONG_PTR)AllocationBase, 0))
			{
				lookup_add(&g_caller_regions, (ULONG_PTR)AllocationBase, 0);
				DebugOutput("InstrumentationCallback: Adding region at 0x%p to caller regions list (returns to 0x%p, thread %d).\n", AllocationBase, CIP, GetCurrentThreadId());
				char ModulePath[MAX_PATH];
				BOOL MappedModule = GetMappedFileName(GetCurrentProcess(), AllocationBase, ModulePath, MAX_PATH);
				if (g_config.yarascan && (!MappedModule || AllocationBase == ImageBase || AllocationBase == (PVOID)base_of_dll_of_interest))
					YaraScan(AllocationBase, GetAccessibleSize(AllocationBase));
				if (g_config.unpacker)
				{
					PTRACKEDREGION TrackedRegion = GetTrackedRegion((PVOID)CIP);
					if (TrackedRegion)
					{
						TrackedRegion->CanDump = 1;
						ProcessTrackedRegion(TrackedRegion);
					}
				}
				else if (g_config.caller_regions && !MappedModule && AllocationBase != ImageBase && AllocationBase != (PVOID)base_of_dll_of_interest)
					DumpRegion((PVOID)CIP);
				else if (MappedModule)
					DebugOutput("InstrumentationCallback: Dump of calling region at 0x%p skipped (returns to 0x%p mapped as %s).\n", AllocationBase, CIP, ModulePath);
				else
					DebugOutput("InstrumentationCallback: Dump of calling region at 0x%p skipped (returns to 0x%p).\n", AllocationBase, CIP);
			}
			else if (g_config.unpacker)
			{
				PTRACKEDREGION TrackedRegion = NULL;
				TrackedRegion = GetTrackedRegion((PVOID)AllocationBase);
				if (!TrackedRegion) {
					TrackedRegion = AddTrackedRegion((PVOID)AllocationBase, 0);
					if (!TrackedRegion)
						DebugOutput("InstrumentationCallback: Failed to add region at 0x%p to tracked regions list (thread %d).\n", AllocationBase, GetCurrentThreadId());
					else {
						DebugOutput("InstrumentationCallback: Added region at 0x%p to tracked regions list (thread %d).\n", AllocationBase, GetCurrentThreadId());
						TrackedRegion->Address = (PVOID)CIP;
					}
				}
				if (TrackedRegion)
					ProcessTrackedRegion(TrackedRegion);
			}

			//if (g_config.debugger && !__called_by_hook(Context->Rsp, CIP) && g_config.break_on_return && FunctionName && !stricmp(FunctionName, g_config.break_on_return))
			if (g_config.debugger && g_config.break_on_return && FunctionName && !stricmp(FunctionName, g_config.break_on_return))
			{
				DebugOutput("Break-on-return: %s syscall detected in thread %d.\n", g_config.break_on_return, GetCurrentThreadId());
				BreakpointOnReturn(CIP);
			}

		}
//		else
//		{
//			if (g_config.syscall > 2 && !is_in_dll_range((ULONG_PTR)ReturnAddress) && !inside_hook(ReturnAddress))
//				log_syscall(get_basename_of_module((HMODULE)ntdll_base), ScanForExport((PVOID)CIP, SCANMAX), (PVOID)CIP, (DWORD)(DWORD_PTR)ReturnValue);
//		}

		InterlockedAnd(((LONG*)pTEB + InstrumentationCallbackDisabled), 0);
	}

#ifdef _WIN64
	RtlRestoreContext(Context, NULL);
#endif
}

void NirvanaInit()
{
	NTSTATUS ret = 0;
	win32u_base = (ULONG_PTR)GetModuleHandle("win32u");
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION Nirvana;
	Nirvana.Callback = (PVOID)InstrHook;
	Nirvana.Reserved = 0;
#ifdef _WIN64
	Nirvana.Version = 0;
#else
	BOOL Wow64Process = FALSE;
	if (!IsWow64Process(GetCurrentProcess(), &Wow64Process))
	{
		DebugOutput("Syscall hooks cannot be used on 32-bit OS\n");
		return;
	}
	Nirvana.Version = (ULONG)InstrHook;
#endif
	ret = pNtSetInformationProcess(GetCurrentProcess(), (ULONG)ProcessInstrumentationCallback, &Nirvana, sizeof(Nirvana));

    if (NT_SUCCESS(ret))
        DebugOutput("Syscall hook installed, syscall logging level %d", g_config.syscall);
    else
        DebugOutput("Failed to install syscall hook, NtSetInformationProcess returned 0x%x", ret);
}
