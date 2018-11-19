#pragma once
#pragma once

#define DEBUGGER_LAUNCHER 0
#define DisableThreadSuspend 0

#define BP_EXEC        0x00
#define BP_WRITE       0x01
#define BP_RESERVED    0x02
#define BP_READWRITE   0x03

#define NUMBER_OF_DEBUG_REGISTERS       4
#define MAX_DEBUG_REGISTER_DATA_SIZE    4
#define DEBUG_REGISTER_DATA_SIZES       {1, 2, 4}
#define DEBUG_REGISTER_LENGTH_MASKS     {0xFFFFFFFF, 0, 1, 0xFFFFFFFF, 3}

#define EXECUTABLE_FLAGS (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
#define WRITABLE_FLAGS (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOMBINE)

#define EXTRACTION_MIN_SIZE 0x1001

#if (NTDDI_VERSION <= NTDDI_WINBLUE)
typedef struct _EXCEPTION_REGISTRATION_RECORD {
    struct _EXCEPTION_REGISTRATION_RECORD *Next;
    PEXCEPTION_ROUTINE Handler;
} EXCEPTION_REGISTRATION_RECORD;

typedef EXCEPTION_REGISTRATION_RECORD *PEXCEPTION_REGISTRATION_RECORD;
#endif

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

typedef struct TrackedRegion
{
    PVOID						BaseAddress;
    PVOID                       ProtectAddress;
	SIZE_T						RegionSize;
	ULONG 						Protect;
    MEMORY_BASIC_INFORMATION    MemInfo;
	BOOL 						Committed;
    PVOID                       LastAccessAddress;
    PVOID                       LastWriteAddress;
    PVOID                       LastReadAddress;
    BOOL                        WriteDetected;
    BOOL                        ReadDetected;
    PVOID                       LastAccessBy;
    PVOID                       LastWrittenBy;
    PVOID                       LastReadBy;
    BOOL                        PagesDumped;
    BOOL                        CanDump;
    BOOL                        Guarded;
    unsigned int                WriteCounter;
    // under review
    BOOL                        WriteBreakpointSet;
    BOOL                        PeImageDetected;
    BOOL                        AllocationBaseExecBpSet;
    BOOL                        AllocationWriteDetected;
    //
    PVOID                       ExecBp;
    unsigned int                ExecBpRegister;
    PVOID                       MagicBp;
    unsigned int                MagicBpRegister;
    BOOL                        BreakpointsSet;
    BOOL                        BreakpointsSaved;
    struct ThreadBreakpoints    *TrackedRegionBreakpoints;
	struct TrackedRegion	    *NextTrackedRegion;
} TRACKEDREGION, *PTRACKEDREGION;

struct TrackedRegion *TrackedRegionList;

typedef BOOL (cdecl *SINGLE_STEP_HANDLER)(struct _EXCEPTION_POINTERS*);
typedef BOOL (cdecl *GUARD_PAGE_HANDLER)(struct _EXCEPTION_POINTERS*);
typedef BOOL (cdecl *SAMPLE_HANDLER)(struct _EXCEPTION_POINTERS*);

typedef void (WINAPI *PWIN32ENTRY)();

#ifdef __cplusplus
extern "C" {
#endif

BOOL DebuggerInitialised;

// Global variables for submission options
void *CAPE_var1, *CAPE_var2, *CAPE_var3, *CAPE_var4;
PVOID bp0, bp1, bp2, bp3;

LONG WINAPI CAPEExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo);
PVOID CAPEExceptionFilterHandle;
SAMPLE_HANDLER SampleVectoredHandler;
PEXCEPTION_ROUTINE SEH_TopLevelHandler;
LPTOP_LEVEL_EXCEPTION_FILTER OriginalExceptionHandler;
BOOL VECTORED_HANDLER;
BOOL GuardPagesDisabled;

DWORD ChildProcessId;
DWORD ChildThreadId;
DWORD_PTR DebuggerEP;
PWIN32ENTRY OEP;

int launch_debugger(void);

// Set
BOOL SetBreakpoint(int Register, int Size, LPVOID Address, DWORD Type, PVOID Callback);
BOOL SetThreadBreakpoint(DWORD ThreadId, int Register, int Size, LPVOID Address, DWORD Type, PVOID Callback);
BOOL ContextSetThreadBreakpoint(PCONTEXT Context, int Register, int Size, LPVOID Address, DWORD Type, PVOID Callback);
BOOL ContextSetDebugRegister(PCONTEXT Context, int Register, int Size, LPVOID Address, DWORD Type);
BOOL SetThreadBreakpoints(PTHREADBREAKPOINTS ThreadBreakpoints);
BOOL ContextSetBreakpoint(PTHREADBREAKPOINTS ThreadBreakpoints);
BOOL ContextUpdateCurrentBreakpoint(PCONTEXT Context, int Size, LPVOID Address, DWORD Type, PVOID Callback);
BOOL SetNextAvailableBreakpoint(DWORD ThreadId, unsigned int* Register, int Size, LPVOID Address, DWORD Type, PVOID Callback);
BOOL SetSingleStepMode(PCONTEXT Context, PVOID Handler);
BOOL SetResumeFlag(PCONTEXT Context);
BOOL SetZeroFlag(PCONTEXT Context);
BOOL ClearZeroFlag(PCONTEXT Context);
PTHREADBREAKPOINTS CreateThreadBreakpoints(DWORD ThreadId);

// Get
BOOL GetNextAvailableBreakpoint(DWORD ThreadId, unsigned int* Register);
PTHREADBREAKPOINTS GetThreadBreakpoints(DWORD ThreadId);
BOOL ContextGetNextAvailableBreakpoint(PCONTEXT Context, unsigned int* Register);
BOOL ContextSetNextAvailableBreakpoint(PCONTEXT Context, unsigned int* Register, int Size, LPVOID Address, DWORD Type, PVOID Callback);
int CheckDebugRegister(HANDLE hThread, int Register);
BOOL CheckDebugRegisters(HANDLE hThread, PCONTEXT pContext);
int ContextCheckDebugRegister(CONTEXT Context, int Register);
BOOL ContextCheckDebugRegisters(PCONTEXT pContext);
HANDLE GetThreadHandle(DWORD ThreadId);

// Clear
BOOL ClearBreakpoint(DWORD ThreadId, int Register);
BOOL ClearBreakpointsInRange(DWORD ThreadId, PVOID BaseAddress, SIZE_T Size);
BOOL ContextClearBreakpoint(PCONTEXT Context, PBREAKPOINTINFO pBreakpointInfo);
BOOL ContextClearCurrentBreakpoint(PCONTEXT Context);
BOOL ContextClearAllBreakpoints(PCONTEXT Context);
BOOL ClearAllBreakpoints();
BOOL ClearSingleStepMode(PCONTEXT Context);

// Misc
BOOL InitNewThreadBreakpoints(DWORD ThreadId);
BOOL InitialiseDebugger(void);
BOOL DebugNewProcess(unsigned int ProcessId, unsigned int ThreadId, DWORD CreationFlags);
BOOL SendDebuggerMessage(PVOID Input);
BOOL StepOverExecutionBreakpoint(PCONTEXT Context, PBREAKPOINTINFO pBreakpointInfo);
BOOL ResumeAfterExecutionBreakpoint(PCONTEXT Context, PBREAKPOINTINFO pBreakpointInfo);

void ShowStack(DWORD_PTR StackPointer, unsigned int NumberOfRecords);

BOOL IsInTrackedRegions(PVOID Address);
PTRACKEDREGION CreateTrackedRegions();
PTRACKEDREGION GetTrackedRegion(PVOID Address);
PTRACKEDREGION AddTrackedRegion(PVOID Address, SIZE_T RegionSize, ULONG Protect);
BOOL DropTrackedRegion(PTRACKEDREGION TrackedRegion);
BOOL ActivateGuardPages(PTRACKEDREGION TrackedRegion);
BOOL ActivateGuardPagesOnProtectedRange(PTRACKEDREGION TrackedRegion);
BOOL DeactivateGuardPages(PTRACKEDREGION TrackedRegion);
BOOL ActivateSurroundingGuardPages(PTRACKEDREGION TrackedRegion);

#ifdef __cplusplus
}
#endif