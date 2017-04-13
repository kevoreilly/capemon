#pragma once

void* CAPE_var;

#define BP_EXEC        0x00
#define BP_WRITE       0x01
#define BP_RESERVED    0x02
#define BP_READWRITE   0x03

#define EXTRACTION_MIN_SIZE 0x1001

typedef struct _EXCEPTION_REGISTRATION_RECORD {
    struct _EXCEPTION_REGISTRATION_RECORD *Next;
    PEXCEPTION_ROUTINE Handler;
} EXCEPTION_REGISTRATION_RECORD;

typedef EXCEPTION_REGISTRATION_RECORD *PEXCEPTION_REGISTRATION_RECORD;

PEXCEPTION_ROUTINE SEH_TopLevelHandler;
LPTOP_LEVEL_EXCEPTION_FILTER OriginalExceptionHandler;
LONG WINAPI CAPEExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo);
BOOL VECTORED_HANDLER;

DWORD ChildProcessId;
DWORD_PTR RemoteFuncAddress;

typedef struct BreakpointInfo 
{
	HANDLE	ThreadHandle;
    int		Register;
    int		Size;
    LPVOID	Address;
    DWORD	Type;
	LPVOID	Callback;
} BREAKPOINTINFO, *PBREAKPOINTINFO;

typedef BOOL (cdecl *BREAKPOINT_HANDLER)(PBREAKPOINTINFO, struct _EXCEPTION_POINTERS*);

typedef struct ThreadBreakpoints	
{
    DWORD						ThreadId;
	HANDLE						ThreadHandle;
	BREAKPOINTINFO 				BreakpointInfo[4];
	struct ThreadBreakpoints	*NextThreadBreakpoints;
} THREADBREAKPOINTS, *PTHREADBREAKPOINTS;	

typedef struct GuardPages	
{
    PVOID						BaseAddress;
	SIZE_T						RegionSize;
	ULONG 						Protect;
    BOOL                        WriteDetected;
    PVOID                       LastWriteAddress;
    BOOL                        ReadDetected;
    PVOID                       LastReadBy;
    BOOL                        PagesDumped;
	struct GuardPages	        *NextGuardPages;
} GUARDPAGES, *PGUARDPAGES;	

struct GuardPages *GuardPageList;

typedef BOOL (cdecl *SINGLE_STEP_HANDLER)(struct _EXCEPTION_POINTERS*);
typedef BOOL (cdecl *GUARD_PAGE_HANDLER)(struct _EXCEPTION_POINTERS*);

#ifdef __cplusplus
extern "C" {
#endif


BOOL SetBreakpoint
(
    DWORD	ThreadId,
    int		Register,
    int		Size,
    LPVOID	Address,
    DWORD	Type,
	PVOID	Callback
);

BOOL ClearBreakpoint(DWORD ThreadId, int Register);

BOOL ContextSetBreakpoint
(
    PCONTEXT	Context,
    int			Register,
    int			Size,
    LPVOID		Address,
    DWORD		Type,
	PVOID		Callback
);

BOOL GetNextAvailableBreakpoint(DWORD ThreadId, unsigned int* Register);
BOOL ContextGetNextAvailableBreakpoint(PCONTEXT Context, unsigned int* Register);
BOOL ContextUpdateCurrentBreakpoint(PCONTEXT Context, int Size, LPVOID Address, DWORD Type, PVOID Callback);
BOOL SetNextAvailableBreakpoint(DWORD ThreadId, unsigned int* Register, int Size, LPVOID Address, DWORD Type, PVOID Callback);
BOOL ContextSetNextAvailableBreakpoint(PCONTEXT Context, unsigned int* Register, int Size, LPVOID Address, DWORD Type, PVOID Callback);
BOOL ContextClearBreakpoint(PCONTEXT Context, PBREAKPOINTINFO pBreakpointInfo);
BOOL ClearBreakpointsInRange(DWORD ThreadId, PVOID BaseAddress, SIZE_T Size);
BOOL SetSingleStepMode(PCONTEXT Context, PVOID Handler);
BOOL ClearSingleStepMode(PCONTEXT Context);
BOOL ContextClearAllBreakpoints(PCONTEXT Context);
BOOL ClearAllBreakpoints(DWORD ThreadId);
BOOL CheckDebugRegisters(HANDLE hThread, PCONTEXT pContext);
int CheckDebugRegister(HANDLE hThread, int Register);
int ContextCheckDebugRegister(CONTEXT Context, int Register);
BOOL InitialiseDebugger(void);
BOOL DebugNewProcess(unsigned int ProcessId, unsigned int ThreadId, DWORD CreationFlags);
BOOL SendDebuggerMessage(DWORD Input);
int launch_debugger(void);
BOOL IsInGuardPages(PVOID Address);
PGUARDPAGES GetGuardPages(PVOID Address);
BOOL DropGuardPages(PGUARDPAGES GuardPages);
PGUARDPAGES CreateGuardPagess();
BOOL AddGuardPages(PVOID Address, SIZE_T RegionSize, ULONG Protect);
BOOL ReinstateGuardPages(PGUARDPAGES GuardPages);
BOOL DisableGuardPages(PGUARDPAGES GuardPages);

#ifdef __cplusplus
}
#endif