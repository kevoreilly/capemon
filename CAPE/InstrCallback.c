//#define DEBUG_COMMENTS

#include <stdio.h>
#include "..\ntapi.h"
#include <psapi.h>
#include "..\hooking.h"
#include "..\misc.h"
#include "..\lookup.h"
#include "..\config.h"
#include "CAPE.h"
#include "Debugger.h"
#include "Unpacker.h"
#include "YaraHarness.h"

#define SE_DEBUG_PRIVILEGE 0x14

#pragma pack(push, 1)
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
#pragma pack(pop)

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
extern BOOLEAN g_dll_main_complete;

#define SCANMIN 7
#define SCANMAX 24
#define SSN_SCANMAX 64
#define STUB_SCANMAX 96
#define MAX_SSN_ENTRIES 0x2000
#define MAX_SYSCALL_EXPORTS 2048

#define INSTR_READABLE_FLAGS (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
#define INSTR_EXEC_READABLE_FLAGS (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

static BOOL QueryMemoryRange(
	PVOID Address,
	ULONG_PTR *OutStart,
	ULONG_PTR *OutEnd,
	PVOID *OutAllocBase,
	DWORD *OutType,
	BOOL RequireExecutable)
{
	MEMORY_BASIC_INFORMATION mbi;
	lasterror_t lasterror;
	SIZE_T res;
	DWORD required_flags;

	if (!Address || (ULONG_PTR)Address < 0x10000)
		return FALSE;

	get_lasterrors(&lasterror);
	lasterror.Eflags = 0;
	res = VirtualQuery(Address, &mbi, sizeof(mbi));
	set_lasterrors(&lasterror);

	if (res != sizeof(mbi))
		return FALSE;
	if (mbi.State != MEM_COMMIT)
		return FALSE;
	if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))
		return FALSE;

	required_flags = RequireExecutable ? INSTR_EXEC_READABLE_FLAGS : INSTR_READABLE_FLAGS;
	if (!(mbi.Protect & required_flags))
		return FALSE;

	if (OutStart)
		*OutStart = (ULONG_PTR)mbi.BaseAddress;
	if (OutEnd)
		*OutEnd = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
	if (OutAllocBase)
		*OutAllocBase = mbi.AllocationBase;
	if (OutType)
		*OutType = mbi.Type;
	return TRUE;
}

static BOOL IsReadableDwordInImage(
	PVOID Ptr,
	PVOID ExpectedAllocBase,
	ULONG_PTR *CachedStart,
	ULONG_PTR *CachedEnd)
{
	ULONG_PTR addr = (ULONG_PTR)Ptr;
	ULONG_PTR range_start = 0, range_end = 0;
	PVOID alloc_base = NULL;

	if (!Ptr || addr < 0x10000 || addr > (((ULONG_PTR)-1) - sizeof(DWORD)))
		return FALSE;

	if (*CachedEnd > *CachedStart && addr >= *CachedStart && (addr + sizeof(DWORD)) <= *CachedEnd)
		return TRUE;

	if (!QueryMemoryRange(Ptr, &range_start, &range_end, &alloc_base, NULL, FALSE))
		return FALSE;

	if (ExpectedAllocBase && alloc_base != ExpectedAllocBase)
		return FALSE;

	if ((addr + sizeof(DWORD)) > range_end)
		return FALSE;

	*CachedStart = range_start;
	*CachedEnd = range_end;
	return TRUE;
}

static unsigned int DecodeSsnAtInstruction(
	PBYTE p,
	ULONG_PTR CodeEnd,
	PVOID AllocBase,
	ULONG_PTR *DataStart,
	ULONG_PTR *DataEnd)
{
	SIZE_T avail;

	if ((ULONG_PTR)p >= CodeEnd)
		return 0;

	avail = (SIZE_T)(CodeEnd - (ULONG_PTR)p);

	// 1. Immediate load: mov eax, imm32 (B8 <ssn_lo> <ssn_hi> 00 00)
	if (avail >= 5 && p[0] == 0xb8 && *(PWORD)(p + 3) == 0)
	{
		DWORD imm = (DWORD)*(PWORD)(p + 1);
		if (imm > 0 && imm < MAX_SSN_ENTRIES)
			return (unsigned int)imm;
	}

#ifdef _WIN64
	// 2. SysWhispers4 MSVC/NASM: RIP-relative table load: mov eax, dword ptr [rip + disp32] (8B 05 <disp32>)
	if (avail >= 6 && p[0] == 0x8b && p[1] == 0x05)
	{
		INT32 disp = *(INT32 *)(p + 2);
		PBYTE pSsn = p + 6 + (INT_PTR)disp;
		if (IsReadableDwordInImage(pSsn, AllocBase, DataStart, DataEnd))
		{
			DWORD ssn = *(PDWORD)pSsn;
			unsigned int f;

			// Scan forward up to 34 bytes for optional SysWhispers4 --encrypt-ssn key XOR logic
			for (f = 6; f < 40; f++)
			{
				PBYTE q = p + f;
				if ((ULONG_PTR)q + 14 > CodeEnd)
					break;
				// Matches: mov r11d, [rip + disp_kp0] (44 8B 1D <disp32>) followed by xor r11d, [rip + disp_kp1] (44 33 1D <disp32>)
				if (q[0] == 0x44 && q[1] == 0x8b && q[2] == 0x1d &&
				    q[7] == 0x44 && q[8] == 0x33 && q[9] == 0x1d)
				{
					PBYTE pKp0 = q + 7 + (INT_PTR)*(INT32 *)(q + 3);
					PBYTE pKp1 = q + 14 + (INT_PTR)*(INT32 *)(q + 10);
					if (IsReadableDwordInImage(pKp0, AllocBase, DataStart, DataEnd) &&
					    IsReadableDwordInImage(pKp1, AllocBase, DataStart, DataEnd))
					{
						ssn ^= (*(PDWORD)pKp0 ^ *(PDWORD)pKp1);
					}
					break;
				}
			}

			if (ssn > 0 && ssn < MAX_SSN_ENTRIES)
				return (unsigned int)ssn;
		}
	}

	// 3. SysWhispers4 GAS/MinGW: lea rcx/r11, [rip + Table] followed by mov eax, [reg + disp]
	if (avail >= 7 &&
	    ((p[0] == 0x48 && p[1] == 0x8d && p[2] == 0x0d) ||
	     (p[0] == 0x4c && p[1] == 0x8d && p[2] == 0x1d)))
	{
		BOOL is_rcx = (p[0] == 0x48);
		INT32 disp_tbl = *(INT32 *)(p + 3);
		PBYTE pTable = p + 7 + (INT_PTR)disp_tbl;
		unsigned int f;

		for (f = 7; f < 32; f++)
		{
			PBYTE q = p + f;
			SIZE_T q_avail;
			DWORD offset = 0;
			BOOL match = FALSE;

			if ((ULONG_PTR)q >= CodeEnd)
				break;
			q_avail = (SIZE_T)(CodeEnd - (ULONG_PTR)q);

			if (is_rcx)
			{
				if (q_avail >= 2 && q[0] == 0x8b && q[1] == 0x01) { match = TRUE; offset = 0; }
				else if (q_avail >= 3 && q[0] == 0x8b && q[1] == 0x41 && (INT8)q[2] >= 0) { match = TRUE; offset = (DWORD)q[2]; }
				else if (q_avail >= 6 && q[0] == 0x8b && q[1] == 0x81) { offset = *(DWORD *)(q + 2); if (offset <= 0x10000) match = TRUE; }
			}
			else
			{
				if (q_avail >= 3 && q[0] == 0x41 && q[1] == 0x8b && q[2] == 0x03) { match = TRUE; offset = 0; }
				else if (q_avail >= 4 && q[0] == 0x41 && q[1] == 0x8b && q[2] == 0x43 && (INT8)q[3] >= 0) { match = TRUE; offset = (DWORD)q[3]; }
				else if (q_avail >= 7 && q[0] == 0x41 && q[1] == 0x8b && q[2] == 0x83) { offset = *(DWORD *)(q + 3); if (offset <= 0x10000) match = TRUE; }
			}

			if (match)
			{
				if (IsReadableDwordInImage(pTable + offset, AllocBase, DataStart, DataEnd))
				{
					DWORD ssn = *(PDWORD)(pTable + offset);
					unsigned int g;

					// Optional GAS KP0 ^ KP1 decrypt:
					// lea r11, [rip + KP0] (4C 8D 1D <disp32>); mov r11d, [r11] (45 8B 1B); lea rcx, [rip + KP1] (48 8D 0D <disp32>)
					for (g = 2; g < 36; g++)
					{
						PBYTE k = q + g;
						if ((ULONG_PTR)k + 17 > CodeEnd)
							break;
						if (k[0] == 0x4c && k[1] == 0x8d && k[2] == 0x1d &&
						    k[7] == 0x45 && k[8] == 0x8b && k[9] == 0x1b &&
						    k[10] == 0x48 && k[11] == 0x8d && k[12] == 0x0d)
						{
							PBYTE pKp0 = k + 7 + (INT_PTR)*(INT32 *)(k + 3);
							PBYTE pKp1 = k + 17 + (INT_PTR)*(INT32 *)(k + 13);
							if (IsReadableDwordInImage(pKp0, AllocBase, DataStart, DataEnd) &&
							    IsReadableDwordInImage(pKp1, AllocBase, DataStart, DataEnd))
							{
								ssn ^= (*(PDWORD)pKp0 ^ *(PDWORD)pKp1);
							}
							break;
						}
					}

					if (ssn > 0 && ssn < MAX_SSN_ENTRIES)
						return (unsigned int)ssn;
				}
				break;
			}
		}
	}
#else
	// 4. x86 table load: mov eax, [addr32] (A1 <addr32> or 8B 05 <addr32>)
	if ((avail >= 5 && p[0] == 0xa1) || (avail >= 6 && p[0] == 0x8b && p[1] == 0x05))
	{
		PBYTE addr = (p[0] == 0xa1) ? *(PBYTE *)(p + 1) : *(PBYTE *)(p + 2);
		if (IsReadableDwordInImage(addr, AllocBase, DataStart, DataEnd))
		{
			DWORD ssn = *(PDWORD)addr;
			unsigned int f;
			for (f = 5; f < 30; f++)
			{
				PBYTE q = p + f;
				if ((ULONG_PTR)q + 12 > CodeEnd)
					break;
				if (q[0] == 0x8b && q[1] == 0x0d && q[6] == 0x33 && q[7] == 0x0d)
				{
					PBYTE pKp0 = *(PBYTE *)(q + 2);
					PBYTE pKp1 = *(PBYTE *)(q + 8);
					if (IsReadableDwordInImage(pKp0, AllocBase, DataStart, DataEnd) &&
					    IsReadableDwordInImage(pKp1, AllocBase, DataStart, DataEnd))
					{
						ssn ^= (*(PDWORD)pKp0 ^ *(PDWORD)pKp1);
					}
					break;
				}
			}
			if (ssn > 0 && ssn < MAX_SSN_ENTRIES)
				return (unsigned int)ssn;
		}
	}
#endif

	return 0;
}

static unsigned int ScanForSsnInRegion(PVOID Address, ULONG_PTR CodeStart, ULONG_PTR CodeEnd, PVOID AllocBase)
{
	ULONG_PTR DataStart = CodeStart, DataEnd = CodeEnd;
	unsigned int i;

	if (!Address || CodeEnd <= CodeStart || (ULONG_PTR)Address <= CodeStart)
		return 0;

	__try
	{
		for (i = SCANMIN; i <= SSN_SCANMAX; i++)
		{
			ULONG_PTR candidate;
			unsigned int ssn;

			if (((ULONG_PTR)Address - CodeStart) < i)
				break;

			candidate = (ULONG_PTR)Address - i;
			if (candidate >= CodeEnd)
				continue;

			ssn = DecodeSsnAtInstruction((PBYTE)candidate, CodeEnd, AllocBase, &DataStart, &DataEnd);
			if (ssn)
				return ssn;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return 0;
	}

	return 0;
}

#ifdef _WIN64
static unsigned int ScanStubForSsn(PVOID StubAddress)
{
	ULONG_PTR CodeStart = 0, CodeEnd = 0;
	ULONG_PTR DataStart = 0, DataEnd = 0;
	PVOID AllocBase = NULL;
	unsigned int off;

	if (!StubAddress)
		return 0;

	if (!QueryMemoryRange(StubAddress, &CodeStart, &CodeEnd, &AllocBase, NULL, TRUE))
		return 0;

	DataStart = CodeStart;
	DataEnd = CodeEnd;

	__try
	{
		for (off = 0; off <= STUB_SCANMAX; off++)
		{
			ULONG_PTR candidate = (ULONG_PTR)StubAddress + off;
			unsigned int ssn;

			if (candidate >= CodeEnd)
				break;

			ssn = DecodeSsnAtInstruction((PBYTE)candidate, CodeEnd, AllocBase, &DataStart, &DataEnd);
			if (ssn)
				return ssn;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return 0;
	}

	return 0;
}
#endif

unsigned int ScanForSsn(PVOID Address)
{
	ULONG_PTR CodeStart = 0, CodeEnd = 0;
	PVOID AllocBase = NULL;
	PVOID QueryAddr;

	if (!Address || (ULONG_PTR)Address <= SCANMIN)
		return 0;

	QueryAddr = (PVOID)((ULONG_PTR)Address - 1);
	if (!QueryMemoryRange(QueryAddr, &CodeStart, &CodeEnd, &AllocBase, NULL, TRUE))
		return 0;

	return ScanForSsnInRegion(Address, CodeStart, CodeEnd, AllocBase);
}

typedef struct _SYSCALL_EXPORT_ITEM
{
	DWORD Rva;
	PCHAR Name;
	BOOLEAN IsZw;
} SYSCALL_EXPORT_ITEM;

static PCHAR g_SsnNameTable[MAX_SSN_ENTRIES];
static SYSCALL_EXPORT_ITEM g_SyscallExports[MAX_SYSCALL_EXPORTS];
static volatile LONG g_SsnTableState; // 0 = uninitialized, 1 = building, 2 = ready

static VOID PopulateSsnNameTable(VOID)
{
	DWORD ntdll_img_size;

	if (!ntdll_base)
		return;

	if (InterlockedCompareExchange(&g_SsnTableState, 1, 0) != 0)
		return;

	__try
	{
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll_base;
		PIMAGE_NT_HEADERS pNtHeader;
		IMAGE_DATA_DIRECTORY exp_entry;
		PIMAGE_EXPORT_DIRECTORY ExportDirectory;
		PDWORD AddressOfNames;
		PDWORD AddressOfFunctions;
		PWORD AddressOfNameOrdinals;
		DWORD exp_count = 0;
		DWORD i, gap;
		unsigned int SystemServiceNumber = 0;
		DWORD cursor = 0;

		ntdll_img_size = get_image_size(ntdll_base);
		if (ntdll_img_size <= sizeof(IMAGE_NT_HEADERS))
			goto done;

		if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
		    (DWORD)dos->e_lfanew > (ntdll_img_size - sizeof(IMAGE_NT_HEADERS)))
			goto done;

		pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)ntdll_base + (ULONG)dos->e_lfanew);
		if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
			goto done;

		exp_entry = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (!exp_entry.VirtualAddress || !exp_entry.Size ||
		    exp_entry.VirtualAddress > (ntdll_img_size - sizeof(IMAGE_EXPORT_DIRECTORY)))
			goto done;

		ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ntdll_base + exp_entry.VirtualAddress);
		if (!ExportDirectory->AddressOfFunctions || !ExportDirectory->AddressOfNames || !ExportDirectory->AddressOfNameOrdinals)
			goto done;
		if (ExportDirectory->NumberOfFunctions > 0x20000 || ExportDirectory->NumberOfNames > 0x20000)
			goto done;
		if (ExportDirectory->AddressOfFunctions > ntdll_img_size ||
		    ExportDirectory->NumberOfFunctions > (ntdll_img_size - ExportDirectory->AddressOfFunctions) / sizeof(DWORD) ||
		    ExportDirectory->AddressOfNames > ntdll_img_size ||
		    ExportDirectory->NumberOfNames > (ntdll_img_size - ExportDirectory->AddressOfNames) / sizeof(DWORD) ||
		    ExportDirectory->AddressOfNameOrdinals > ntdll_img_size ||
		    ExportDirectory->NumberOfNames > (ntdll_img_size - ExportDirectory->AddressOfNameOrdinals) / sizeof(WORD))
			goto done;

		AddressOfNames = (PDWORD)((PUCHAR)ntdll_base + ExportDirectory->AddressOfNames);
		AddressOfFunctions = (PDWORD)((PUCHAR)ntdll_base + ExportDirectory->AddressOfFunctions);
		AddressOfNameOrdinals = (PWORD)((PUCHAR)ntdll_base + ExportDirectory->AddressOfNameOrdinals);

		for (i = 0; i < ExportDirectory->NumberOfNames; i++)
		{
			WORD ord = AddressOfNameOrdinals[i];
			DWORD func_rva;
			DWORD name_rva = AddressOfNames[i];
			PCHAR Name;
			BOOLEAN is_zw;

			if (ord >= ExportDirectory->NumberOfFunctions || !name_rva || name_rva >= ntdll_img_size)
				continue;

			func_rva = AddressOfFunctions[ord];
			if (!func_rva || func_rva >= ntdll_img_size)
				continue;
			if (func_rva >= exp_entry.VirtualAddress && func_rva < (exp_entry.VirtualAddress + exp_entry.Size))
				continue;

			Name = (PCHAR)ntdll_base + name_rva;
			if (Name[0] == 'N' && Name[1] == 't')
				is_zw = FALSE;
			else if (Name[0] == 'Z' && Name[1] == 'w')
				is_zw = TRUE;
			else
				continue;

			if (exp_count < MAX_SYSCALL_EXPORTS)
			{
				g_SyscallExports[exp_count].Rva = func_rva;
				g_SyscallExports[exp_count].Name = Name;
				g_SyscallExports[exp_count].IsZw = is_zw;
				exp_count++;
			}
		}

		// Shellsort by (Rva, IsZw) so Nt* precedes Zw* at identical RVAs
		for (gap = exp_count / 2; gap > 0; gap /= 2)
		{
			for (i = gap; i < exp_count; i++)
			{
				SYSCALL_EXPORT_ITEM temp = g_SyscallExports[i];
				DWORD j = i;
				while (j >= gap &&
				       (g_SyscallExports[j - gap].Rva > temp.Rva ||
				        (g_SyscallExports[j - gap].Rva == temp.Rva && g_SyscallExports[j - gap].IsZw > temp.IsZw)))
				{
					g_SyscallExports[j] = g_SyscallExports[j - gap];
					j -= gap;
				}
				g_SyscallExports[j] = temp;
			}
		}

		// based on https://www.mdsec.co.uk/2022/04/resolving-system-service-numbers-using-the-exception-directory
#ifdef _WIN64
		{
			IMAGE_DATA_DIRECTORY exc_entry = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
			PIMAGE_RUNTIME_FUNCTION_ENTRY RuntimeFunctionTable;
			DWORD max_rtf;

			if (!exc_entry.VirtualAddress || !exc_entry.Size ||
			    exc_entry.VirtualAddress > ntdll_img_size ||
			    exc_entry.Size > (ntdll_img_size - exc_entry.VirtualAddress))
				goto done;

			RuntimeFunctionTable = (PIMAGE_RUNTIME_FUNCTION_ENTRY)((PUCHAR)ntdll_base + exc_entry.VirtualAddress);
			max_rtf = exc_entry.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

			for (i = 0; i < max_rtf && RuntimeFunctionTable[i].BeginAddress; i++)
			{
				DWORD rva = RuntimeFunctionTable[i].BeginAddress;
				PCHAR nt_name = NULL, zw_name = NULL;

				while (cursor < exp_count && g_SyscallExports[cursor].Rva < rva)
					cursor++;

				while (cursor < exp_count && g_SyscallExports[cursor].Rva == rva)
				{
					if (g_SyscallExports[cursor].IsZw)
						zw_name = g_SyscallExports[cursor].Name;
					else if (!nt_name)
						nt_name = g_SyscallExports[cursor].Name;
					cursor++;
				}

				if (zw_name)
				{
					if (SystemServiceNumber < MAX_SSN_ENTRIES)
						g_SsnNameTable[SystemServiceNumber] = nt_name ? nt_name : zw_name;
					SystemServiceNumber++;
				}
			}
		}
#else
		{
			IMAGE_DATA_DIRECTORY cfg_dir = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
			PIMAGE_LOAD_CONFIG_DIRECTORY LoadConfigDirectory;
			PBYTE CfgBase;
			DWORD CfgCount, CfgStride;

			if (!cfg_dir.VirtualAddress || cfg_dir.VirtualAddress > (ntdll_img_size - sizeof(IMAGE_LOAD_CONFIG_DIRECTORY)))
				goto done;

			LoadConfigDirectory = (PIMAGE_LOAD_CONFIG_DIRECTORY)((PUCHAR)ntdll_base + cfg_dir.VirtualAddress);
			CfgBase = (PBYTE)LoadConfigDirectory->GuardCFFunctionTable;
			CfgCount = (DWORD)LoadConfigDirectory->GuardCFFunctionCount;
			CfgStride = sizeof(DWORD) + ((LoadConfigDirectory->GuardFlags >> 28) & 0xF);

			if (!CfgBase || !CfgCount || CfgCount > 0x40000)
				goto done;
			if ((ULONG_PTR)CfgBase < ntdll_base ||
			    (ULONG_PTR)CfgBase > (ntdll_base + ntdll_img_size) ||
			    CfgCount > ((ntdll_base + ntdll_img_size) - (ULONG_PTR)CfgBase) / CfgStride)
				goto done;

			for (i = 0; i < CfgCount; i++)
			{
				DWORD rva = *(PDWORD)(CfgBase + (i * CfgStride));
				PCHAR nt_name = NULL, zw_name = NULL;

				if (!rva)
					break;

				while (cursor < exp_count && g_SyscallExports[cursor].Rva < rva)
					cursor++;

				while (cursor < exp_count && g_SyscallExports[cursor].Rva == rva)
				{
					if (g_SyscallExports[cursor].IsZw)
						zw_name = g_SyscallExports[cursor].Name;
					else if (!nt_name)
						nt_name = g_SyscallExports[cursor].Name;
					cursor++;
				}

				if (zw_name)
				{
					if (SystemServiceNumber < MAX_SSN_ENTRIES)
						g_SsnNameTable[SystemServiceNumber] = nt_name ? nt_name : zw_name;
					SystemServiceNumber++;
				}
			}
		}
#endif
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

done:
	InterlockedExchange(&g_SsnTableState, 2);
}

PCHAR GetNameBySsn(unsigned int Number)
{
	PCHAR Name;

	if (!Number)	// ignore SSN 0
		return NULL;

	Number &= 0xffff;
	if (Number >= MAX_SSN_ENTRIES || !ntdll_base)
		return NULL;

	if (g_SsnTableState == 0)
		PopulateSsnNameTable();

	if (g_SsnTableState != 2)
		return NULL;

	Name = g_SsnNameTable[Number];
#ifdef DEBUG_COMMENTS
	if (Name)
		DebugOutput("GetNameBySsn: %s", Name);
#endif
	return Name;
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
	{"win32u",     0, 0},
	{"user32",     0, 0},
	{"kernelbase", 0, 0},
};

static const DWORD g_DllCount = sizeof(g_DllsToFilter) / sizeof(g_DllsToFilter[0]);
static BOOLEAN g_Initialized;

VOID InitializeFilteredDlls(VOID)
{
	DWORD i;
	if (!g_Initialized)
	{
		for (i = 0; i < g_DllCount; i++)
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
	DWORD i;
	if (!g_Initialized)
		return FALSE;

	for (i = 0; i < g_DllCount; i++)
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

static PCHAR LookupExportInFilteredDll(PVOID Address, SIZE_T ScanMax)
{
	ULONG_PTR addr = (ULONG_PTR)Address;
	DWORD idx;

	if (!g_Initialized || !Address)
		return NULL;

	for (idx = 0; idx < g_DllCount; idx++)
	{
		ULONG_PTR base = g_DllsToFilter[idx].Base;
		DWORD size = g_DllsToFilter[idx].Size;

		if (!base || size <= sizeof(IMAGE_DOS_HEADER))
			continue;
		if (addr < base || addr >= (base + size))
			continue;

		__try
		{
			PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
			PIMAGE_NT_HEADERS nt;
			IMAGE_DATA_DIRECTORY exp_entry;
			PIMAGE_EXPORT_DIRECTORY exp_dir;
			PDWORD funcs, names;
			PWORD ordinals;
			DWORD target_rva = (DWORD)(addr - base);
			SIZE_T best_dist = ScanMax + 1;
			PCHAR best_name = NULL;
			DWORD i;

			if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
			    (DWORD)dos->e_lfanew > (size - sizeof(IMAGE_NT_HEADERS)))
				return NULL;

			nt = (PIMAGE_NT_HEADERS)(base + (DWORD)dos->e_lfanew);
			if (nt->Signature != IMAGE_NT_SIGNATURE)
				return NULL;

			exp_entry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			if (!exp_entry.VirtualAddress || !exp_entry.Size ||
			    exp_entry.VirtualAddress > (size - sizeof(IMAGE_EXPORT_DIRECTORY)))
				return NULL;

			exp_dir = (PIMAGE_EXPORT_DIRECTORY)(base + exp_entry.VirtualAddress);
			if (exp_dir->NumberOfNames > 0x20000 || exp_dir->NumberOfFunctions > 0x20000)
				return NULL;
			if (!exp_dir->AddressOfFunctions || !exp_dir->AddressOfNames || !exp_dir->AddressOfNameOrdinals)
				return NULL;
			if (exp_dir->AddressOfFunctions > size ||
			    exp_dir->NumberOfFunctions > (size - exp_dir->AddressOfFunctions) / sizeof(DWORD) ||
			    exp_dir->AddressOfNames > size ||
			    exp_dir->NumberOfNames > (size - exp_dir->AddressOfNames) / sizeof(DWORD) ||
			    exp_dir->AddressOfNameOrdinals > size ||
			    exp_dir->NumberOfNames > (size - exp_dir->AddressOfNameOrdinals) / sizeof(WORD))
				return NULL;

			funcs = (PDWORD)(base + exp_dir->AddressOfFunctions);
			names = (PDWORD)(base + exp_dir->AddressOfNames);
			ordinals = (PWORD)(base + exp_dir->AddressOfNameOrdinals);

			for (i = 0; i < exp_dir->NumberOfNames; i++)
			{
				WORD ord = ordinals[i];
				DWORD func_rva;
				DWORD name_rva;
				SIZE_T dist;
				PCHAR candidate;

				if (ord >= exp_dir->NumberOfFunctions)
					continue;
				func_rva = funcs[ord];
				if (!func_rva || func_rva >= size)
					continue;
				if (func_rva >= exp_entry.VirtualAddress && func_rva < (exp_entry.VirtualAddress + exp_entry.Size))
					continue;
				if (target_rva < func_rva)
					continue;

				dist = (SIZE_T)(target_rva - func_rva);
				if (dist > ScanMax)
					continue;

				name_rva = names[i];
				if (!name_rva || name_rva >= size)
					continue;

				candidate = (PCHAR)(base + name_rva);
				if (dist < best_dist ||
				    (dist == best_dist && best_name && best_name[0] == 'Z' && best_name[1] == 'w' &&
				     candidate[0] == 'N' && candidate[1] == 't'))
				{
					best_dist = dist;
					best_name = candidate;
					if (best_dist == 0 && best_name[0] == 'N' && best_name[1] == 't')
						break;
				}
			}

			return best_name;
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			return NULL;
		}
	}

	return NULL;
}

static PUNICODE_STRING SafeGetModuleBaseName(HMODULE ModuleBase)
{
	if (!ModuleBase)
		return NULL;

	__try
	{
		return get_basename_of_module(ModuleBase);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return NULL;
	}
}

// https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/teb/index.htm
#ifdef _WIN64
#define InstrumentationCallbackPreviousPc	0x2d8
#define InstrumentationCallbackPreviousSp	0x2e0
#define InstrumentationCallbackDisabled		0x2ec
#else
#define InstrumentationCallbackPreviousPc	0x1b0
#define InstrumentationCallbackPreviousSp	0x1b4
#define InstrumentationCallbackDisabled		0x1b8
#endif

#ifdef _WIN64
static BOOL HasSyscallR10Setup(PBYTE Buf, SIZE_T Len)
{
	SIZE_T i, k;

	for (i = 0; i < Len; i++)
	{
		// mov r10, rcx (4C 8B D1 or 49 89 CA), lea r10, [rcx] (4C 8D 11),
		// xchg r10, rcx (49 87 CA / 4C 87 D1), or/add r10, rcx (4C 0B D1 / 4C 03 D1)
		if ((i + 3) <= Len)
		{
			if ((Buf[i] == 0x4c && Buf[i + 1] == 0x8b && Buf[i + 2] == 0xd1) ||
			    (Buf[i] == 0x49 && Buf[i + 1] == 0x89 && Buf[i + 2] == 0xca) ||
			    (Buf[i] == 0x4c && Buf[i + 1] == 0x8d && Buf[i + 2] == 0x11) ||
			    (Buf[i] == 0x49 && Buf[i + 1] == 0x87 && Buf[i + 2] == 0xca) ||
			    (Buf[i] == 0x4c && Buf[i + 1] == 0x87 && Buf[i + 2] == 0xd1) ||
			    (Buf[i] == 0x4c && Buf[i + 1] == 0x0b && Buf[i + 2] == 0xd1) ||
			    (Buf[i] == 0x4c && Buf[i + 1] == 0x03 && Buf[i + 2] == 0xd1))
				return TRUE;
		}
		// push rcx (51) ... pop r10 (41 5A)
		if (Buf[i] == 0x51)
		{
			for (k = i + 1; (k + 2) <= Len && k <= (i + 16); k++)
			{
				if (Buf[k] == 0x41 && Buf[k + 1] == 0x5a)
					return TRUE;
			}
		}
	}

	return FALSE;
}

static BOOL IsFilteredDllImportThunk(PBYTE Thunk, PBYTE SyscallInsnAddr)
{
	ULONG_PTR thunk_start = 0, thunk_end = 0;

	if (!QueryMemoryRange(Thunk, &thunk_start, &thunk_end, NULL, NULL, TRUE))
		return FALSE;

	if (((ULONG_PTR)Thunk + 6) > thunk_end)
		return FALSE;

	if (Thunk[0] == 0xff && Thunk[1] == 0x25)
	{
		PBYTE slot = Thunk + 6 + (INT_PTR)*(INT32 *)(Thunk + 2);
		ULONG_PTR slot_start = 0, slot_end = 0;
		if (QueryMemoryRange(slot, &slot_start, &slot_end, NULL, NULL, FALSE) &&
		    ((ULONG_PTR)slot + sizeof(PVOID)) <= slot_end)
		{
			PVOID target_fn = *(PVOID *)slot;
			if (target_fn != (PVOID)SyscallInsnAddr && IsAddressInFilteredDlls((ULONG_PTR)target_fn))
				return TRUE;
		}
	}

	return FALSE;
}

static BOOL IsIndirectSyscallStub(PBYTE Stub, ULONG_PTR StubEnd, PBYTE SyscallInsnAddr)
{
	SIZE_T scan_len;
	SIZE_T i;

	if ((ULONG_PTR)Stub >= StubEnd)
		return FALSE;

	scan_len = (SIZE_T)(StubEnd - (ULONG_PTR)Stub);
	if (scan_len > STUB_SCANMAX)
		scan_len = STUB_SCANMAX;
	if (scan_len < 3)
		return FALSE;

	// Standard linker import thunk: jmp qword ptr [rip + disp32] (FF 25 <disp32>)
	// Reject unless the pointer slot explicitly targets the '0F 05' / 'CD 2E' gadget itself.
	if (scan_len >= 6 && Stub[0] == 0xff && Stub[1] == 0x25)
	{
		PBYTE slot = Stub + 6 + (INT_PTR)*(INT32 *)(Stub + 2);
		ULONG_PTR slot_start = 0, slot_end = 0;
		if (QueryMemoryRange(slot, &slot_start, &slot_end, NULL, NULL, FALSE) &&
		    ((ULONG_PTR)slot + sizeof(PVOID)) <= slot_end)
		{
			return (*(PVOID *)slot == (PVOID)SyscallInsnAddr) ? TRUE : FALSE;
		}
		return FALSE;
	}

	if (!HasSyscallR10Setup(Stub, scan_len))
		return FALSE;

	// Guard against normal C wrappers that happen to touch r10 and tail-jump via IAT (FF 25 or E9 -> FF 25)
	for (i = 0; (i + 5) <= scan_len; i++)
	{
		if ((i + 6) <= scan_len && Stub[i] == 0xff && Stub[i + 1] == 0x25)
		{
			PBYTE slot = Stub + i + 6 + (INT_PTR)*(INT32 *)(Stub + i + 2);
			ULONG_PTR slot_start = 0, slot_end = 0;
			if (QueryMemoryRange(slot, &slot_start, &slot_end, NULL, NULL, FALSE) &&
			    ((ULONG_PTR)slot + sizeof(PVOID)) <= slot_end)
			{
				PVOID target_fn = *(PVOID *)slot;
				if (target_fn != (PVOID)SyscallInsnAddr && IsAddressInFilteredDlls((ULONG_PTR)target_fn))
					return FALSE;
			}
		}
		else if (Stub[i] == 0xe9)
		{
			PBYTE hop = Stub + i + 5 + (INT_PTR)*(INT32 *)(Stub + i + 1);
			if (hop != SyscallInsnAddr &&
			    (IsAddressInFilteredDlls((ULONG_PTR)hop) || IsFilteredDllImportThunk(hop, SyscallInsnAddr)))
				return FALSE;
		}
	}

	return TRUE;
}

static BOOL IsIndirectCallPreceding(PBYTE pRet, ULONG_PTR RetStart)
{
	SIZE_T back = (SIZE_T)((ULONG_PTR)pRet - RetStart);

	// call reg: FF D0..D7
	if (back >= 2 && pRet[-2] == 0xff && (pRet[-1] >= 0xd0 && pRet[-1] <= 0xd7))
		return TRUE;
	// call r8..r15: 41 FF D0..D7
	if (back >= 3 && (pRet[-3] == 0x41 || pRet[-3] == 0x49) && pRet[-2] == 0xff && (pRet[-1] >= 0xd0 && pRet[-1] <= 0xd7))
		return TRUE;
	// call [reg + disp8]: FF 50..57 <disp8> (excluding SIB [rsp+disp8] which is 4 bytes)
	if (back >= 3 && pRet[-3] == 0xff && (pRet[-2] >= 0x50 && pRet[-2] <= 0x57) && pRet[-2] != 0x54)
		return TRUE;
	if (back >= 4 && pRet[-4] == 0xff && pRet[-3] == 0x54)
		return TRUE;
	if (back >= 4 && (pRet[-4] == 0x41 || pRet[-4] == 0x49) && pRet[-3] == 0xff && (pRet[-2] >= 0x50 && pRet[-2] <= 0x57) && pRet[-2] != 0x54)
		return TRUE;
	// call [reg]: FF 10..17 (excluding FF 14 SIB and FF 15 RIP-relative handled separately)
	if (back >= 2 && pRet[-2] == 0xff && (pRet[-1] >= 0x10 && pRet[-1] <= 0x17) && pRet[-1] != 0x14 && pRet[-1] != 0x15)
		return TRUE;
	if (back >= 3 && (pRet[-3] == 0x41 || pRet[-3] == 0x49) && pRet[-2] == 0xff && (pRet[-1] >= 0x10 && pRet[-1] <= 0x17) && pRet[-1] != 0x14 && pRet[-1] != 0x15)
		return TRUE;
	// call [reg + disp32]: FF 90..97 <disp32>
	if (back >= 6 && pRet[-6] == 0xff && (pRet[-5] >= 0x90 && pRet[-5] <= 0x97) && pRet[-5] != 0x94)
		return TRUE;
	if (back >= 7 && (pRet[-7] == 0x41 || pRet[-7] == 0x49) && pRet[-6] == 0xff && (pRet[-5] >= 0x90 && pRet[-5] <= 0x97) && pRet[-5] != 0x94)
		return TRUE;

	return FALSE;
}

static BOOL IsIndirectSyscall(
	PVOID CIP,
	ULONG_PTR Rsp,
	ULONG_PTR pTEB,
	PVOID *OutReturnAddress,
	PVOID *OutStubAddress,
	PVOID *OutAllocBase)
{
	ULONG_PTR cip_addr = (ULONG_PTR)CIP;
	ULONG_PTR stack_base, stack_limit;
	PVOID ReturnAddress = NULL;
	PBYTE pCip, pRet;
	ULONG_PTR ret_start = 0, ret_end = 0;
	PVOID ret_alloc_base = NULL;
	DWORD idx;
	BOOL in_filtered_stub = FALSE;

	if (OutReturnAddress)
		*OutReturnAddress = NULL;
	if (OutStubAddress)
		*OutStubAddress = NULL;
	if (OutAllocBase)
		*OutAllocBase = NULL;

	if (!g_Initialized || !CIP || !pTEB || Rsp < 0x10000)
		return FALSE;

	// 1. CIP must be inside a filtered system DLL at a 'syscall; ret' (0F 05 C3) or 'int 2Eh; ret' (CD 2E C3) gadget.
	//    This rejects non-leaf syscalls, NtContinue, and NtCallbackReturn in 3 byte reads without VirtualQuery.
	for (idx = 0; idx < g_DllCount; idx++)
	{
		ULONG_PTR base = g_DllsToFilter[idx].Base;
		DWORD size = g_DllsToFilter[idx].Size;
		if (base && size > 3 && cip_addr >= (base + 2) && cip_addr < (base + size))
		{
			in_filtered_stub = TRUE;
			break;
		}
	}
	if (!in_filtered_stub)
		return FALSE;

	pCip = (PBYTE)CIP;

	__try
	{
		BOOL is_syscall_ret = (pCip[-2] == 0x0f && pCip[-1] == 0x05 && pCip[0] == 0xc3);
		BOOL is_int2e_ret = (pCip[-2] == 0xcd && pCip[-1] == 0x2e && pCip[0] == 0xc3);
		if (!is_syscall_ret && !is_int2e_ret)
			return FALSE;

		// 2. Validate RSP against NT_TIB stack bounds in 0 syscalls; fall back to VirtualQuery if stack is pivoted.
		stack_base = *(ULONG_PTR *)(pTEB + 0x08);
		stack_limit = *(ULONG_PTR *)(pTEB + 0x10);
		if (stack_limit >= 0x10000 && stack_base > stack_limit &&
		    (stack_base - stack_limit) >= sizeof(PVOID) &&
		    Rsp >= stack_limit && Rsp <= (stack_base - sizeof(PVOID)))
		{
			ReturnAddress = *(PVOID *)Rsp;
		}
		else
		{
			ULONG_PTR sp_start = 0, sp_end = 0;
			if (!QueryMemoryRange((PVOID)Rsp, &sp_start, &sp_end, NULL, NULL, FALSE) ||
			    (Rsp + sizeof(PVOID)) > sp_end)
				return FALSE;
			ReturnAddress = *(PVOID *)Rsp;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE;
	}

	if (!ReturnAddress || (ULONG_PTR)ReturnAddress < 0x10000)
		return FALSE;

	// 3. Fast lock-free, zero-syscall rejection for system DLLs, monitor code, and hook trampolines.
	if (IsAddressInFilteredDlls((ULONG_PTR)ReturnAddress) ||
	    inside_hook(ReturnAddress) ||
	    InsideMonitor(NULL, ReturnAddress) ||
	    is_in_dll_range((ULONG_PTR)ReturnAddress))
		return FALSE;

	// 4. Verify ReturnAddress lies in committed, readable, executable memory (preserves LastError, zero loader locks).
	if (!QueryMemoryRange(ReturnAddress, &ret_start, &ret_end, &ret_alloc_base, NULL, TRUE))
		return FALSE;

	pRet = (PBYTE)ReturnAddress;

	__try
	{
		// 5A. Caller executed 'call rel32' (E8) to a local syscall stub (SysWhispers2/3/4 indirect & randomized, HellsHall, etc.)
		if (((ULONG_PTR)pRet - ret_start) >= 5 && pRet[-5] == 0xe8)
		{
			INT32 rel = *(INT32 *)(pRet - 4);
			PBYTE target = pRet + (INT_PTR)rel;

			if (!IsAddressInFilteredDlls((ULONG_PTR)target) &&
			    !inside_hook(target) &&
			    !InsideMonitor(NULL, target) &&
			    !is_in_dll_range((ULONG_PTR)target))
			{
				ULONG_PTR stub_start = ret_start, stub_end = ret_end;
				PVOID stub_alloc = ret_alloc_base;
				BOOL stub_ok = TRUE;

				if ((ULONG_PTR)target < ret_start || (ULONG_PTR)target >= ret_end)
				{
					stub_ok = QueryMemoryRange(target, &stub_start, &stub_end, &stub_alloc, NULL, TRUE) &&
					          (stub_alloc == ret_alloc_base);
				}

				// Follow at most one local E9 jump thunk (e.g. MSVC /INCREMENTAL ILT)
				if (stub_ok && (stub_end - (ULONG_PTR)target) >= 5 && target[0] == 0xe9)
				{
					PBYTE hop = target + 5 + (INT_PTR)*(INT32 *)(target + 1);
					if ((ULONG_PTR)hop >= stub_start && (ULONG_PTR)hop < stub_end)
					{
						target = hop;
					}
					else
					{
						ULONG_PTR hop_start = 0, hop_end = 0;
						PVOID hop_alloc = NULL;
						if (QueryMemoryRange(hop, &hop_start, &hop_end, &hop_alloc, NULL, TRUE) &&
						    hop_alloc == ret_alloc_base)
						{
							target = hop;
							stub_start = hop_start;
							stub_end = hop_end;
						}
						else
						{
							stub_ok = FALSE;
						}
					}
				}

				if (stub_ok && IsIndirectSyscallStub(target, stub_end, pCip - 2))
				{
					if (OutReturnAddress)
						*OutReturnAddress = ReturnAddress;
					if (OutStubAddress)
						*OutStubAddress = (PVOID)target;
					if (OutAllocBase)
						*OutAllocBase = ret_alloc_base;
					return TRUE;
				}
			}
		}

		// 5B. Inline indirect call via RIP-relative pointer (FF 15 <disp32>) pointing directly at '0F 05' / 'CD 2E'
		if (((ULONG_PTR)pRet - ret_start) >= 6 && pRet[-6] == 0xff && pRet[-5] == 0x15)
		{
			PBYTE slot = pRet + (INT_PTR)*(INT32 *)(pRet - 4);
			ULONG_PTR slot_start = 0, slot_end = 0;
			if (QueryMemoryRange(slot, &slot_start, &slot_end, NULL, NULL, FALSE) &&
			    ((ULONG_PTR)slot + sizeof(PVOID)) <= slot_end &&
			    *(PVOID *)slot == (PVOID)(pCip - 2))
			{
				if (OutReturnAddress)
					*OutReturnAddress = ReturnAddress;
				if (OutAllocBase)
					*OutAllocBase = ret_alloc_base;
				return TRUE;
			}
		}

		// 5C. Inline indirect register/memory call (e.g. shellcode 'mov r10, rcx; mov eax, ssn; call r11')
		if (IsIndirectCallPreceding(pRet, ret_start))
		{
			SIZE_T win = (SIZE_T)((ULONG_PTR)pRet - ret_start);
			if (win > SSN_SCANMAX)
				win = SSN_SCANMAX;

			if (HasSyscallR10Setup(pRet - win, win))
			{
				if (OutReturnAddress)
					*OutReturnAddress = ReturnAddress;
				if (OutAllocBase)
					*OutAllocBase = ret_alloc_base;
				return TRUE;
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE;
	}

	return FALSE;
}
#endif

static BOOL IsSafeSyscallCallbackContext(VOID)
{
#ifdef _WIN64
	if (srw_lock_held())
		return FALSE;
#endif
	return TRUE;
}

static VOID TrackSyscallCallerRegion(PVOID AllocationBase, PVOID CallerAddress, BOOL IsIndirect)
{
	PTRACKEDREGION TrackedRegion;

	if (!g_config.unpacker || !AllocationBase || !IsSafeSyscallCallbackContext())
		return;

	TrackedRegion = GetTrackedRegion(AllocationBase);
	if (TrackedRegion && (TrackedRegion->Caller || TrackedRegion->PagesDumped))
		return;

	if (!TrackedRegion)
	{
		TrackedRegion = AddTrackedRegion(AllocationBase, 0);
		if (!TrackedRegion)
		{
			DebugOutput("InstrumentationCallback: Failed to add %sregion at 0x%p to tracked regions list (thread %d).\n",
				IsIndirect ? "indirect " : "", AllocationBase, GetCurrentThreadId());
			return;
		}
		DebugOutput("InstrumentationCallback: Added %sregion at 0x%p (base 0x%p) to tracked regions list (thread %d).\n",
			IsIndirect ? "indirect " : "", CallerAddress, AllocationBase, GetCurrentThreadId());
	}

	TrackedRegion->Caller = CallerAddress;
	TrackedRegion->Address = AllocationBase;

	if (!g_config.loaderlock_scans && loader_lock_held())
		return;

	ProcessTrackedRegion(TrackedRegion);
}

#ifdef _WIN64
VOID InstrumentationCallback(PCONTEXT Context)
{
	// based on https://gist.github.com/esoterix/df38008568c50d4f83123e3a90b62ebb
	ULONG_PTR pTEB = (ULONG_PTR)NtCurrentTeb();
	unsigned int ReturnValue;
	PVOID ReturnAddress = NULL;
	PVOID IndirectStub = NULL;
	PVOID IndirectAllocBase = NULL;
	PVOID CIP;

	Context->Rcx = Context->R10;
	Context->Rsp = *((ULONG_PTR *)(pTEB + InstrumentationCallbackPreviousSp));
	Context->Rip = *((ULONG_PTR *)(pTEB + InstrumentationCallbackPreviousPc));

	if (!g_config.syscall || !g_dll_main_complete || *((BOOLEAN *)pTEB + InstrumentationCallbackDisabled))
	{
		RtlRestoreContext(Context, NULL);
		return;
	}

	*((BOOLEAN *)pTEB + InstrumentationCallbackDisabled) = TRUE;
	ReturnValue = (unsigned int)Context->Rax & 0xFFFFFFFF;
	CIP = (PVOID)Context->Rip;
#else
VOID InstrumentationCallback(PVOID CIP, unsigned int ReturnValue)
{
	ULONG_PTR pTEB = (ULONG_PTR)NtCurrentTeb();

	if (!g_config.syscall || !g_dll_main_complete || *((BOOLEAN *)pTEB + InstrumentationCallbackDisabled))
		return;

	*((BOOLEAN *)pTEB + InstrumentationCallbackDisabled) = TRUE;
#endif

	if (g_config.syscall > 1 && IsAddressInFilteredDlls((ULONG_PTR)CIP))
	{
		if (IsSafeSyscallCallbackContext())
		{
			lasterror_t lasterror;
			int saved_disable_count;
			PVOID AllocationBase;
			PUNICODE_STRING ModuleName;
			PCHAR FunctionName;

			get_lasterrors(&lasterror);
			lasterror.Eflags = 0;
			saved_disable_count = hook_info()->disable_count;
			hook_disable();

			AllocationBase = GetAllocationBase(CIP);
			ModuleName = SafeGetModuleBaseName((HMODULE)AllocationBase);
			FunctionName = LookupExportInFilteredDll((PVOID)CIP, SCANMAX);
			if (!FunctionName)
				FunctionName = ScanForExport((PVOID)CIP, SCANMAX);
			log_syscall(ModuleName, FunctionName, (PVOID)CIP, (DWORD)(DWORD_PTR)ReturnValue);

			hook_info()->disable_count = saved_disable_count;
			set_lasterrors(&lasterror);
		}
	}
#ifdef _WIN64
	else if (IsIndirectSyscall(CIP, Context->Rsp, pTEB, &ReturnAddress, &IndirectStub, &IndirectAllocBase))
	{
		if (IsSafeSyscallCallbackContext())
		{
			lasterror_t lasterror;
			int saved_disable_count;
			PVOID AllocationBase;
			PUNICODE_STRING ModuleName;
			PCHAR FunctionName = NULL;
			DWORD Ssn = 0;

			get_lasterrors(&lasterror);
			lasterror.Eflags = 0;
			saved_disable_count = hook_info()->disable_count;
			hook_disable();

			AllocationBase = IndirectAllocBase ? IndirectAllocBase : GetAllocationBase(ReturnAddress);
			ModuleName = SafeGetModuleBaseName((HMODULE)AllocationBase);

			if (IndirectStub != NULL)
				Ssn = ScanStubForSsn(IndirectStub);
			else
				Ssn = ScanForSsn(ReturnAddress);

			if (Ssn)
				FunctionName = GetNameBySsn(Ssn);
			if (!FunctionName)
				FunctionName = LookupExportInFilteredDll((PVOID)CIP, SCANMAX);
			if (!FunctionName)
				FunctionName = ScanForExport((PVOID)CIP, SCANMAX);

			log_syscall(ModuleName, FunctionName, ReturnAddress, (DWORD)(DWORD_PTR)ReturnValue);

			TrackSyscallCallerRegion(AllocationBase, ReturnAddress, TRUE);

			if (g_config.debugger && g_config.break_on_return && FunctionName && !stricmp(FunctionName, g_config.break_on_return))
			{
				DebugOutput("Break-on-return: %s indirect syscall detected in thread %d.\n", g_config.break_on_return, GetCurrentThreadId());
				BreakpointOnReturn(ReturnAddress);
			}

			hook_info()->disable_count = saved_disable_count;
			set_lasterrors(&lasterror);
		}
	}
#endif
	else if (!inside_hook(CIP) && !InsideMonitor(NULL, CIP) && !IsAddressInFilteredDlls((ULONG_PTR)CIP))
	{
		if (IsSafeSyscallCallbackContext())
		{
			lasterror_t lasterror;
			int saved_disable_count;
			PVOID AllocationBase;
			PUNICODE_STRING ModuleName;
			DWORD Ssn;
			PCHAR FunctionName;

			get_lasterrors(&lasterror);
			lasterror.Eflags = 0;
			saved_disable_count = hook_info()->disable_count;
			hook_disable();

			AllocationBase = GetAllocationBase((PVOID)CIP);
			ModuleName = SafeGetModuleBaseName((HMODULE)AllocationBase);
			Ssn = ScanForSsn((PVOID)CIP);
			FunctionName = GetNameBySsn(Ssn);
#ifdef DEBUG_COMMENTS
			DebugOutput("InstrumentationCallback: Returns to 0x%p, return value %d, ssn %d -> %s)\n", CIP, ReturnValue, Ssn, FunctionName);
#endif
			log_syscall(ModuleName, FunctionName, (PVOID)CIP, (DWORD)(DWORD_PTR)ReturnValue);

			TrackSyscallCallerRegion(AllocationBase, (PVOID)CIP, FALSE);

			if (g_config.debugger && g_config.break_on_return && FunctionName && !stricmp(FunctionName, g_config.break_on_return))
			{
				DebugOutput("Break-on-return: %s syscall detected in thread %d.\n", g_config.break_on_return, GetCurrentThreadId());
				BreakpointOnReturn(CIP);
			}

			hook_info()->disable_count = saved_disable_count;
			set_lasterrors(&lasterror);
		}
	}

	*((BOOLEAN *)pTEB + InstrumentationCallbackDisabled) = FALSE;

#ifdef _WIN64
	RtlRestoreContext(Context, NULL);
#endif
}

void NirvanaInit()
{
	NTSTATUS ret = 0;
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION Nirvana;
#ifndef _WIN64
	BOOL Wow64Process = FALSE;
#endif

	InitializeFilteredDlls();
	Nirvana.Callback = (PVOID)InstrHook;
	Nirvana.Reserved = 0;
#ifdef _WIN64
	Nirvana.Version = 0;
#else
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
