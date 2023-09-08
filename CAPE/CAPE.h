/*
CAPE - Config And Payload Extraction
Copyright(C) 2015-2017 Context Information Security. (kevin.oreilly@contextis.com)

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
extern HMODULE s_hInst;
extern WCHAR s_wzDllPath[MAX_PATH];
extern CHAR s_szDllPath[MAX_PATH];

#define PE_MAX_SIZE	 ((ULONG)0x20000000)
#define PE_MIN_SIZE	 ((ULONG)0x1000)
#define PE_MAX_SECTIONS 0xFFFF
#define REGISTRY_VALUE_SIZE_MIN 1024

typedef PVOID(WINAPI *_getJit)(void);

void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
void DebuggerOutput(_In_ LPCTSTR lpOutputString, ...);
void ErrorOutput(_In_ LPCTSTR lpOutputString, ...);

PVOID GetHookCallerBase();
BOOL InsideMonitor(PVOID* ReturnAddress, PVOID Address);
PVOID GetPageAddress(PVOID Address);
PVOID GetAllocationBase(PVOID Address);
SIZE_T GetRegionSize(PVOID Address);
SIZE_T GetAllocationSize(PVOID Address);
SIZE_T GetAccessibleSize(PVOID Address);
PVOID GetExportAddress(HMODULE ModuleBase, PCHAR FunctionName);
BOOL IsAddressAccessible(PVOID Address);
BOOL TestPERequirements(PIMAGE_NT_HEADERS pNtHeader);
SIZE_T GetMinPESize(PIMAGE_NT_HEADERS pNtHeader);
double GetPEEntropy(PUCHAR Buffer);
PCHAR TranslatePathFromDeviceToLetter(PCHAR DeviceFilePath);
DWORD GetEntryPoint(PVOID Address);
BOOL DumpPEsInRange(PVOID Buffer, SIZE_T Size);
BOOL DumpRegion(PVOID Address);
int DumpMemoryRaw(PVOID Buffer, SIZE_T Size);
int DumpMemory(PVOID Buffer, SIZE_T Size);
int DumpCurrentProcessNewEP(PVOID NewEP);
int DumpImageInCurrentProcessFixImports(PVOID BaseAddress, PVOID NewEP);
int DumpCurrentProcessFixImports(PVOID NewEP);
int DumpCurrentProcess();
int DumpProcess(HANDLE hProcess, PVOID ImageBase, PVOID NewEP, BOOL FixImports);
int DumpPE(PVOID Buffer);
int ScanForNonZero(PVOID Buffer, SIZE_T Size);
int ScanPageForNonZero(PVOID Address);
int ScanForPE(PVOID Buffer, SIZE_T Size, PVOID* Offset);
int ScanForDisguisedPE(PVOID Buffer, SIZE_T Size, PVOID* Offset);
PCHAR ScanForExport(PVOID Address, SIZE_T ScanMax);
PCHAR GetExportNameByAddress(PVOID Address);
int IsDisguisedPEHeader(PVOID Buffer);
int DumpImageInCurrentProcess(PVOID ImageBase);
void DumpSectionViewsForPid(DWORD Pid);
BOOL DumpStackRegion(void);

BOOL ProcessDumped;

SYSTEM_INFO SystemInfo;
PVOID CallingModule;

//
// MessageId: STATUS_SUCCESS
//
// MessageText:
//
//  STATUS_SUCCESS
//
#define STATUS_SUCCESS				   ((NTSTATUS)0x00000000L)

//
// MessageId: STATUS_BAD_COMPRESSION_BUFFER
//
// MessageText:
//
// The specified buffer contains ill-formed data.
//
#define STATUS_BAD_COMPRESSION_BUFFER	((NTSTATUS)0xC0000242L)

#define	PE_HEADER_LIMIT		0x200	// Range to look for PE header within candidate buffer

#define SIZE_OF_LARGEST_IMAGE ((ULONG)0x77000000)

#pragma comment(lib, "Wininet.lib")

#define	DATA				0
#define	EXECUTABLE			1
#define	DLL					2

typedef struct CapeMetadata
{
	char*	ProcessPath;
	char*	ModulePath;
	DWORD   Pid;
	DWORD   PPid;
	DWORD   DumpType;
	char*	TargetProcess;  // For injection
	DWORD	TargetPid;	  // "
	PVOID   Address;		// For shellcode/modules
	SIZE_T  Size;		   // "
	char*	TypeString;
} CAPEMETADATA, *PCAPEMETADATA;

struct CapeMetadata *CapeMetaData;

BOOL SetCapeMetaData(DWORD DumpType, DWORD TargetPid, HANDLE hTargetProcess, PVOID Address);

enum {
	PROCDUMP = 1,

	COMPRESSION = 2,

	INJECTION_PE = 3,
	INJECTION_SHELLCODE	= 4,

	UNPACKED_PE = 8,
	UNPACKED_SHELLCODE = 9,

	DATADUMP = 0x66,
	REGDUMP = 0x67,
	AMSIBUFFER = 0x6a,
	AMSISTREAM = 0x6b,

	STACK_REGION = 0x6c,

	TYPE_STRING = 0x100,
};

typedef struct TrackedRegion
{
	PVOID						AllocationBase;
	PVOID						Address;
	MEMORY_BASIC_INFORMATION	MemInfo;
	BOOL						Committed;
	BOOL						PagesDumped;
	BOOL						CanDump;
	DWORD						EntryPoint;
	double						Entropy;
	SIZE_T						MinPESize;
	PVOID						ExecBp;
	unsigned int				ExecBpRegister;
	PVOID						MagicBp;
	unsigned int				MagicBpRegister;
	BOOL						BreakpointsSet;
	BOOL						BreakpointsSaved;
	struct ThreadBreakpoints	*TrackedRegionBreakpoints;
	struct TrackedRegion		*NextTrackedRegion;
} TRACKEDREGION, *PTRACKEDREGION;

struct TrackedRegion *TrackedRegionList;

PTRACKEDREGION AddTrackedRegion(PVOID Address, ULONG Protect);
PTRACKEDREGION GetTrackedRegion(PVOID Address);
BOOL DropTrackedRegion(PTRACKEDREGION TrackedRegion);
BOOL IsInTrackedRegion(PTRACKEDREGION TrackedRegion, PVOID Address);
BOOL IsInTrackedRegions(PVOID Address);
BOOL ContextClearTrackedRegion(PCONTEXT Context, PTRACKEDREGION TrackedRegion);
void ClearTrackedRegion(PTRACKEDREGION TrackedRegion);
void ProcessImageBase(PTRACKEDREGION TrackedRegion);
void ProcessTrackedRegion(PTRACKEDREGION TrackedRegion);
