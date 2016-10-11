extern HMODULE s_hInst;
extern WCHAR s_wzDllPath[MAX_PATH];
extern CHAR s_szDllPath[MAX_PATH];
extern int DumpCurrentProcessNewEP(DWORD NewEP);
extern int DumpCurrentProcess();
extern int DumpProcess(HANDLE hProcess, DWORD_PTR ImageBase);
extern int DumpPE(LPCVOID Buffer);
extern int ScyllaDumpPE(DWORD_PTR Buffer);
unsigned int DumpSize;

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

enum {
    PROCDUMP = 0,
    INJECTION_DLL = 1,
    INJECTION_SHELLCODE = 2,
    INJECTION_RUNPE = 3,
    COMPRESSION = 4,
    EXTRACTION = 5
};

typedef struct CapeMetadata 
{
	char*	ProcessPath;
	char*	ModulePath;
    DWORD   Pid;
    DWORD   DumpType;
    char*	ParentProcess;  // For injection
    DWORD	ParentPid;      
    PVOID   Address;        // For shellcode
	SIZE_T  Size;
} CAPEMETADATA, *PCAPEMETADATA;
