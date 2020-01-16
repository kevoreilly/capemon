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

#define PE_MAX_SIZE     ((ULONG)0x77000000)
#define PE_MIN_SIZE     ((ULONG)0x1000)
#define PE_MAX_SECTIONS 0xFFFF

void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);

PVOID GetHookCallerBase();
BOOL InsideHook(LPVOID* ReturnAddress, LPVOID Address);
PVOID GetPageAddress(PVOID Address);
PVOID GetAllocationBase(PVOID Address);
SIZE_T GetAllocationSize(PVOID Address);
BOOL TestPERequirements(PIMAGE_NT_HEADERS pNtHeader);
SIZE_T GetMinPESize(PIMAGE_NT_HEADERS pNtHeader);
double GetEntropy(PUCHAR Buffer);
BOOL TranslatePathFromDeviceToLetter(__in TCHAR *DeviceFilePath, __out TCHAR* DriveLetterFilePath, __inout LPDWORD lpdwBufferSize);
DWORD GetEntryPoint(LPVOID Address);
BOOL DumpPEsInRange(LPVOID Buffer, SIZE_T Size);
BOOL DumpRegion(PVOID Address);
int DumpMemory(LPVOID Buffer, SIZE_T Size);
int DumpCurrentProcessNewEP(LPVOID NewEP);
int DumpImageInCurrentProcessFixImports(LPVOID BaseAddress, LPVOID NewEP);
int DumpCurrentProcessFixImports(LPVOID NewEP);
int DumpCurrentProcess();
int DumpProcess(HANDLE hProcess, LPVOID ImageBase, LPVOID NewEP);
int DumpPE(LPVOID Buffer);
int ScanForNonZero(LPVOID Buffer, SIZE_T Size);
int ScanPageForNonZero(LPVOID Address);
int ScanForPE(LPVOID Buffer, SIZE_T Size, LPVOID* Offset);
int ScanForDisguisedPE(LPVOID Buffer, SIZE_T Size, LPVOID* Offset);
int IsDisguisedPEHeader(LPVOID Buffer);
int DumpImageInCurrentProcess(LPVOID ImageBase);
void DumpSectionViewsForPid(DWORD Pid);
BOOL DumpStackRegion(void);

BOOL ProcessDumped, FilesDumped, ModuleDumped;

SYSTEM_INFO SystemInfo;
PVOID CallingModule;

//
// MessageId: STATUS_SUCCESS
//
// MessageText:
//
//  STATUS_SUCCESS
//
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)

//
// MessageId: STATUS_BAD_COMPRESSION_BUFFER
//
// MessageText:
//
// The specified buffer contains ill-formed data.
//
#define STATUS_BAD_COMPRESSION_BUFFER    ((NTSTATUS)0xC0000242L)

#define	PE_HEADER_LIMIT		0x200	// Range to look for PE header within candidate buffer

#define SIZE_OF_LARGEST_IMAGE ((ULONG)0x77000000)

#pragma comment(lib, "Wininet.lib")

#define	DATA				0
#define	EXECUTABLE			1
#define	DLL			        2

#define PLUGX_SIGNATURE		0x5658	// 'XV'

typedef struct CapeMetadata
{
	char*	ProcessPath;
	char*	ModulePath;
    DWORD   Pid;
    DWORD   DumpType;
    char*	TargetProcess;  // For injection
    DWORD	TargetPid;      // "
    PVOID   Address;        // For shellcode/modules
	SIZE_T  Size;           // "
} CAPEMETADATA, *PCAPEMETADATA;

struct CapeMetadata *CapeMetaData;

BOOL SetCapeMetaData(DWORD DumpType, DWORD TargetPid, HANDLE hTargetProcess, PVOID Address);

enum {
    PROCDUMP                = 0,

    COMPRESSION             = 1,

    INJECTION_PE            = 3,
    INJECTION_SHELLCODE     = 4,
    //INJECTION_RUNPE         = 5,

    EXTRACTION_PE           = 8,
    EXTRACTION_SHELLCODE    = 9,

    PLUGX_PAYLOAD           = 0x10,
    PLUGX_CONFIG            = 0x11,

    EVILGRAB_PAYLOAD        = 0x14,
    EVILGRAB_DATA           = 0x15,

    SEDRECO_DATA            = 0x20,

    URSNIF_CONFIG           = 0x24,
    URSNIF_PAYLOAD          = 0x25,

    CERBER_CONFIG           = 0x30,
    CERBER_PAYLOAD          = 0x31,

    HANCITOR_CONFIG         = 0x34,
    HANCITOR_PAYLOAD        = 0x35,

    QAKBOT_CONFIG           = 0x38,
    QAKBOT_PAYLOAD          = 0x39,

    DATADUMP                = 0x66,

    STACK_REGION            = 0x6c
};

HANDLE EvilGrabRegHandle;
