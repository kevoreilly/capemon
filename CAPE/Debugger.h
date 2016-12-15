#pragma once

void* CAPE_var;

#define BP_EXEC        0x00
#define BP_WRITE       0x01
#define BP_RESERVED    0x02
#define BP_READWRITE   0x03

DWORD ChildProcessId;
DWORD RemoteFuncAddress;

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

typedef BOOL (cdecl *SINGLE_STEP_HANDLER)(struct _EXCEPTION_POINTERS*);

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
BOOL InitialiseDebugger(void);
BOOL DebugNewProcess(unsigned int ProcessId, unsigned int ThreadId, DWORD CreationFlags);
BOOL SendDebuggerMessage(DWORD Input);
int launch_debugger(void);

#ifdef __cplusplus
}
#endif