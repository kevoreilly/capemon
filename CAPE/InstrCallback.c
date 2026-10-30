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
typedef struct _IMAGE_CFG_ENTRY
{
	DWORD Rva;
    struct
	{
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
extern ULONG_PTR ntdll_base;
extern ULONG_PTR base_of_dll_of_interest;
extern PVOID ImageBase;

#define SCANMIN 7
#define SCANMAX 24
#define SSN_SCANMAX 64

unsigned int ScanForSsn(PVOID Address)
{
	unsigned int i;
	if (!Address)
		return 0;

	__try
	{
		for (i = SCANMIN; i <= SSN_SCANMAX; i++)
		{
			PBYTE p = (PBYTE)Address - i;

			// 1. Immediate load: mov eax, imm32 (B8 <ssn_lo> <ssn_hi> 00 00)
			if (p[0] == 0xb8 && *(PWORD)(p + 3) == 0)
			{
				DWORD imm = (DWORD)*(PWORD)(p + 1);
				if (imm > 0 && imm < 0x2000)
					return (unsigned int)imm;
			}

#ifdef _WIN64
			// 2. SysWhispers4 MSVC/NASM: RIP-relative table load: mov eax, dword ptr [rip + disp32] (8B 05 <disp32>)
			if (p[0] == 0x8b && p[1] == 0x05)
			{
				INT32 disp = *(INT32 *)(p + 2);
				PDWORD pSsn = (PDWORD)(p + 6 + disp);
				DWORD ssn = *pSsn;
				unsigned int f;

				// Scan forward up to 24 bytes for optional SysWhispers4 --encrypt-ssn key XOR logic
				for (f = 6; f < 30; f++)
				{
					PBYTE q = p + f;
					// Matches: mov r11d, [rip + disp_kp0] (44 8B 1D <disp32>) followed by xor r11d, [rip + disp_kp1] (44 33 1D <disp32>)
					if (q[0] == 0x44 && q[1] == 0x8b && q[2] == 0x1d &&
					    q[7] == 0x44 && q[8] == 0x33 && q[9] == 0x1d)
					{
						DWORD kp0 = *(PDWORD)(q + 7 + *(INT32 *)(q + 3));
						DWORD kp1 = *(PDWORD)(q + 14 + *(INT32 *)(q + 10));
						ssn ^= (kp0 ^ kp1);
						break;
					}
				}

				if (ssn > 0 && ssn < 0x2000)
					return (unsigned int)ssn;
			}

			// 3. SysWhispers4 GAS/MinGW: lea rcx/r11, [rip + Table] followed by mov eax, [reg + disp]
			if ((p[0] == 0x48 || p[0] == 0x4c) && p[1] == 0x8d && (p[2] == 0x0d || p[2] == 0x1d))
			{
				INT32 disp_tbl = *(INT32 *)(p + 3);
				PBYTE pTable = p + 7 + disp_tbl;
				unsigned int f;

				for (f = 7; f < 24; f++)
				{
					PBYTE q = p + f;
					DWORD offset = 0;
					BOOL match = FALSE;

					if (q[0] == 0x8b && q[1] == 0x01) { match = TRUE; offset = 0; }
					else if (q[0] == 0x8b && q[1] == 0x41) { match = TRUE; offset = (DWORD)q[2]; }
					else if (q[0] == 0x8b && q[1] == 0x81) { match = TRUE; offset = *(DWORD *)(q + 2); }
					else if (q[0] == 0x41 && q[1] == 0x8b && q[2] == 0x03) { match = TRUE; offset = 0; }
					else if (q[0] == 0x41 && q[1] == 0x8b && q[2] == 0x43) { match = TRUE; offset = (DWORD)q[3]; }
					else if (q[0] == 0x41 && q[1] == 0x8b && q[2] == 0x83) { match = TRUE; offset = *(DWORD *)(q + 3); }

					if (match)
					{
						DWORD ssn = *(PDWORD)(pTable + offset);
						// Optional GAS KP0 ^ KP1 decrypt
						unsigned int g;
						for (g = 2; g < 32; g++)
						{
							PBYTE k = q + g;
							if (k[0] == 0x4c && k[1] == 0x8d && k[2] == 0x1d &&
							    k[7] == 0x45 && k[8] == 0x8b && k[9] == 0x1b &&
							    k[10] == 0x48 && k[11] == 0x8d && k[12] == 0x0d)
							{
								DWORD kp0 = *(PDWORD)(*(PBYTE *)(k + 7 + *(INT32 *)(k + 3)));
								DWORD kp1 = *(PDWORD)(*(PBYTE *)(k + 17 + *(INT32 *)(k + 13)));
								ssn ^= (kp0 ^ kp1);
								break;
							}
						}
						if (ssn > 0 && ssn < 0x2000)
							return (unsigned int)ssn;
					}
				}
			}
#else
			// 4. x86 table load: mov eax, [addr32] (A1 <addr32> or 8B 05 <addr32>)
			if (p[0] == 0xa1 || (p[0] == 0x8b && p[1] == 0x05))
			{
				PBYTE addr = (p[0] == 0xa1) ? *(PBYTE *)(p + 1) : *(PBYTE *)(p + 2);
				if (addr)
				{
					DWORD ssn = *(PDWORD)addr;
					unsigned int f;
					for (f = 5; f < 25; f++)
					{
						PBYTE q = p + f;
						if (q[0] == 0x8b && q[1] == 0x0d && q[6] == 0x33 && q[7] == 0x0d)
						{
							DWORD kp0 = *(DWORD *)(*(DWORD **)(q + 2));
							DWORD kp1 = *(DWORD *)(*(DWORD **)(q + 8));
							ssn ^= (kp0 ^ kp1);
							break;
						}
					}
					if (ssn > 0 && ssn < 0x2000)
						return (unsigned int)ssn;
				}
			}
#endif
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
	if (!Number)	// ignore SSN 0
		return NULL;

	Number &= 0xffff;

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

typedef struct _DLL_MAPPING
{
    LPCSTR Name;
    ULONG_PTR Base;
    DWORD Size;
} DLL_MAPPING;

static DLL_MAPPING g_DllsToFilter[] =
{
	{"ntdll",      0, 0},
	{"win32u",      0, 0},
	{"user32",      0, 0},
	{"kernelbase",  0, 0},
};


static const DWORD g_DllCount = sizeof(g_DllsToFilter) / sizeof(g_DllsToFilter[0]);
static BOOLEAN g_Initialized;

VOID InitializeFilteredDlls(VOID)
{
	if (!g_Initialized)
	{
		for (DWORD i = 0; i < g_DllCount; i++)
		{
			g_DllsToFilter[i].Base = (ULONG_PTR)GetModuleHandle(g_DllsToFilter[i].Name);
			if (g_DllsToFilter[i].Base)
				g_DllsToFilter[i].Size = get_image_size(g_DllsToFilter[i].Base);
		}
		g_Initialized = TRUE;
	}
}

BOOLEAN IsAddressInFilteredDlls(ULONG_PTR Address)
{
	if (!g_Initialized)
		return FALSE;

	for (DWORD i = 0; i < g_DllCount; i++)
	{
		if (g_DllsToFilter[i].Base && g_DllsToFilter[i].Size)
		{
			ULONG_PTR End = g_DllsToFilter[i].Base + g_DllsToFilter[i].Size;
			if (Address >= g_DllsToFilter[i].Base && Address < End)
				return TRUE;
		}
	}

	return FALSE;
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

	if (g_config.syscall && !*((BOOLEAN*)pTEB + InstrumentationCallbackDisabled))
	{
		*((BOOLEAN*)pTEB + InstrumentationCallbackDisabled) = TRUE;

		if (g_config.syscall > 1 && IsAddressInFilteredDlls((ULONG_PTR)CIP))
		{
			PUNICODE_STRING ModuleName = get_basename_of_module(GetAllocationBase(CIP));
			log_syscall(ModuleName, ScanForExport((PVOID)CIP, SCANMAX), (PVOID)CIP, (DWORD)(DWORD_PTR)ReturnValue);
		}
		else if (!inside_hook(CIP) && !IsAddressInFilteredDlls((ULONG_PTR)CIP))
		{
			PVOID AllocationBase = GetAllocationBase((PVOID)CIP);
			PUNICODE_STRING ModuleName = get_basename_of_module((HMODULE)AllocationBase);
			PCHAR FunctionName = GetNameBySsn(ScanForSsn((PVOID)CIP));
#ifdef DEBUG_COMMENTS
			DebugOutput("InstrumentationCallback: Returns to 0x%p, return value %d, ssn %d -> %s)\n", CIP, ReturnValue, ScanForSsn((PVOID)CIP), FunctionName);
#endif
			log_syscall(ModuleName, FunctionName, (PVOID)CIP, (DWORD)(DWORD_PTR)ReturnValue);
			if (g_config.unpacker)
			{
				PTRACKEDREGION TrackedRegion = NULL;
				TrackedRegion = GetTrackedRegion((PVOID)AllocationBase);
				if (!TrackedRegion)
				{
					TrackedRegion = AddTrackedRegion((PVOID)AllocationBase, 0);
					if (!TrackedRegion)
						DebugOutput("InstrumentationCallback: Failed to add region at 0x%p to tracked regions list (thread %d).\n", AllocationBase, GetCurrentThreadId());
					else
					{
						DebugOutput("InstrumentationCallback: Added region at 0x%p (base 0x%p) to tracked regions list (thread %d).\n", CIP, AllocationBase, GetCurrentThreadId());
						TrackedRegion->Caller = (PVOID)CIP;
						TrackedRegion->Address = AllocationBase;
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
	}

	*((BOOLEAN*)pTEB + InstrumentationCallbackDisabled) = FALSE;

#ifdef _WIN64
	RtlRestoreContext(Context, NULL);
#endif
}

void NirvanaInit()
{
	NTSTATUS ret = 0;
	InitializeFilteredDlls();
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
