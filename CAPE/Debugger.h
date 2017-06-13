#pragma once

void *CAPE_var1, *CAPE_var2, *CAPE_var3, *CAPE_var4;

#define BP_EXEC        0x00
#define BP_WRITE       0x01
#define BP_RESERVED    0x02
#define BP_READWRITE   0x03

#define EXECUTABLE_FLAGS (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

#define EXTRACTION_MIN_SIZE 0x1001

typedef struct _EXCEPTION_REGISTRATION_RECORD {
    struct _EXCEPTION_REGISTRATION_RECORD *Next;
    PEXCEPTION_ROUTINE Handler;
} EXCEPTION_REGISTRATION_RECORD;

typedef EXCEPTION_REGISTRATION_RECORD *PEXCEPTION_REGISTRATION_RECORD;

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

typedef struct TrackedPages	
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
    BOOL                        BreakpointsSet;
    unsigned int                WriteCounter;
    // under review
    BOOL                        WriteBreakpointSet;
    BOOL                        PeImageDetected;
    BOOL                        AllocationBaseExecBpSet;
    BOOL                        EntryPointExecBpSet;
    BOOL                        AllocationWriteDetected;
    BOOL                        BaseAddressExecBpSet;
    //
	struct TrackedPages	        *NextTrackedPages;
} TRACKEDPAGES, *PTRACKEDPAGES;	

struct TrackedPages *TrackedPageList;

typedef BOOL (cdecl *SINGLE_STEP_HANDLER)(struct _EXCEPTION_POINTERS*);
typedef BOOL (cdecl *GUARD_PAGE_HANDLER)(struct _EXCEPTION_POINTERS*);
typedef BOOL (cdecl *SAMPLE_HANDLER)(struct _EXCEPTION_POINTERS*);

typedef void (WINAPI *PWIN32ENTRY)();

#ifdef __cplusplus
extern "C" {
#endif

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

BOOL SetBreakpoint(DWORD ThreadId, int Register, int Size, LPVOID Address, DWORD Type, PVOID Callback);
BOOL ClearBreakpoint(DWORD ThreadId, int Register);
BOOL ContextSetBreakpoint(PCONTEXT Context, int Register, int Size, LPVOID Address, DWORD Type, PVOID Callback);
BOOL GetNextAvailableBreakpoint(DWORD ThreadId, unsigned int* Register);
BOOL ContextGetNextAvailableBreakpoint(PCONTEXT Context, unsigned int* Register);
BOOL ContextUpdateCurrentBreakpoint(PCONTEXT Context, int Size, LPVOID Address, DWORD Type, PVOID Callback);
BOOL SetNextAvailableBreakpoint(DWORD ThreadId, unsigned int* Register, int Size, LPVOID Address, DWORD Type, PVOID Callback);
BOOL ContextSetNextAvailableBreakpoint(PCONTEXT Context, unsigned int* Register, int Size, LPVOID Address, DWORD Type, PVOID Callback);
BOOL ContextClearBreakpoint(PCONTEXT Context, PBREAKPOINTINFO pBreakpointInfo);
BOOL ClearBreakpointsInRange(DWORD ThreadId, PVOID BaseAddress, SIZE_T Size);
BOOL SetResumeFlag(PCONTEXT Context);
BOOL SetSingleStepMode(PCONTEXT Context, PVOID Handler);
BOOL ClearSingleStepMode(PCONTEXT Context);
BOOL StepOverExecutionBreakpoint(PCONTEXT Context, PBREAKPOINTINFO pBreakpointInfo);
BOOL ResumeAfterExecutionBreakpoint(PCONTEXT Context, PBREAKPOINTINFO pBreakpointInfo);
BOOL ContextClearAllBreakpoints(PCONTEXT Context);
BOOL ClearAllBreakpoints(DWORD ThreadId);
BOOL CheckDebugRegisters(HANDLE hThread, PCONTEXT pContext);
int CheckDebugRegister(HANDLE hThread, int Register);
int ContextCheckDebugRegister(CONTEXT Context, int Register);
BOOL InitialiseDebugger(void);
BOOL DebugNewProcess(unsigned int ProcessId, unsigned int ThreadId, DWORD CreationFlags);
BOOL SendDebuggerMessage(DWORD Input);
int launch_debugger(void);

void ShowStack(DWORD_PTR StackPointer, unsigned int NumberOfRecords);

BOOL IsInTrackedPages(PVOID Address);
PTRACKEDPAGES CreateTrackedPagess();
PTRACKEDPAGES GetTrackedPages(PVOID Address);
PTRACKEDPAGES AddTrackedPages(PVOID Address, SIZE_T RegionSize, ULONG Protect);
BOOL DropTrackedPages(PTRACKEDPAGES TrackedPages);
BOOL ActivateGuardPages(PTRACKEDPAGES TrackedPages);
BOOL ActivateGuardPagesOnProtectedRange(PTRACKEDPAGES TrackedPages);
BOOL DeactivateGuardPages(PTRACKEDPAGES TrackedPages);
BOOL ActivateSurroundingGuardPages(PTRACKEDPAGES TrackedPages);

#ifdef __cplusplus
}
#endif