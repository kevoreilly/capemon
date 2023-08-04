#pragma once

#define BP_EXEC			0x00
#define BP_WRITE		0x01
#define BP_RESERVED		0x02
#define BP_READWRITE	0x03

#define NUMBER_OF_DEBUG_REGISTERS		4
#define MAX_DEBUG_REGISTER_DATA_SIZE	4
#define DEBUG_REGISTER_DATA_SIZES		{1, 2, 4}
#define DEBUG_REGISTER_LENGTH_MASKS		{0xFFFFFFFF, 0, 1, 0xFFFFFFFF, 3}

// eflags register
#define FL_CF			0x00000001	// Carry Flag
#define FL_PF			0x00000004	// Parity Flag
#define FL_AF			0x00000010	// Auxiliary carry Flag
#define FL_ZF			0x00000040	// Zero Flag
#define FL_SF			0x00000080	// Sign Flag
#define FL_TF			0x00000100	// Trap Flag
#define FL_IF			0x00000200	// Interrupt Enable
#define FL_DF			0x00000400	// Direction Flag
#define FL_OF			0x00000800	// Overflow Flag
#define FL_IOPL_MASK	0x00003000	// I/O Privilege Level bitmask
#define FL_IOPL_0		0x00000000	//   IOPL == 0
#define FL_IOPL_1		0x00001000	//   IOPL == 1
#define FL_IOPL_2		0x00002000	//   IOPL == 2
#define FL_IOPL_3		0x00003000	//   IOPL == 3
#define FL_NT			0x00004000	// Nested Task
#define FL_RF			0x00010000	// Resume Flag
#define FL_VM			0x00020000	// Virtual 8086 mode
#define FL_AC			0x00040000	// Alignment Check
#define FL_VIF			0x00080000	// Virtual Interrupt Flag
#define FL_VIP			0x00100000	// Virtual Interrupt Pending
#define FL_ID			0x00200000	// ID flag

//
// debug register DR7 bit fields
//
typedef struct _DR7
{
	DWORD L0   : 1;	//Local enable bp0
	DWORD G0   : 1;	//Global enable bp0
	DWORD L1   : 1;	//Local enable bp1
	DWORD G1   : 1;	//Global enable bp1
	DWORD L2   : 1;	//Local enable bp2
	DWORD G2   : 1;	//Global enable bp2
	DWORD L3   : 1;	//Local enable bp3
	DWORD G3   : 1;	//Global enable bp3
	DWORD LE   : 1;	//Local Enable/LBR
	DWORD GE   : 1;	//Global Enable/BTF
	DWORD PAD1 : 3;
	DWORD GD   : 1;	//General Detect Enable
	DWORD PAD2 : 1;
	DWORD PAD3 : 1;
	DWORD RWE0 : 2;	//Read/Write/Execute bp0
	DWORD LEN0 : 2;	//Length bp0
	DWORD RWE1 : 2;	//Read/Write/Execute bp1
	DWORD LEN1 : 2;	//Length bp1
	DWORD RWE2 : 2;	//Read/Write/Execute bp2
	DWORD LEN2 : 2;	//Length bp2
	DWORD RWE3 : 2;	//Read/Write/Execute bp3
	DWORD LEN3 : 2;	//Length bp3
} DR7, *PDR7;

#define EXECUTABLE_FLAGS (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
#define WRITABLE_FLAGS (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOMBINE)

typedef struct BreakpointInfo
{
	HANDLE			ThreadHandle;
	int				Register;
	int				Size;
	LPVOID			Address;
	DWORD			Type;
	unsigned int	HitCount;
	LPVOID			Callback;
	BOOL			HandlerActive;
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
typedef BOOL (cdecl *GUARD_PAGE_HANDLER)(struct _EXCEPTION_POINTERS*);
typedef BOOL (cdecl *SAMPLE_HANDLER)(struct _EXCEPTION_POINTERS*);

typedef void (WINAPI *PWIN32ENTRY)();

#ifdef __cplusplus
extern "C" {
#endif

BOOL DebuggerInitialised;

LONG WINAPI CAPEExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo);
SINGLE_STEP_HANDLER SingleStepHandler;
PVOID CAPEExceptionFilterHandle;
PEXCEPTION_ROUTINE SEH_TopLevelHandler;
LPTOP_LEVEL_EXCEPTION_FILTER OriginalExceptionHandler;
DWORD ChildProcessId;
DWORD ChildThreadId;
DWORD_PTR DebuggerEP;
PWIN32ENTRY OEP;

int launch_debugger(void);

// Set
BOOL ContextSetDebugRegister(PCONTEXT Context, int Register, int Size, LPVOID Address, DWORD Type);
BOOL ContextSetDebugRegisterEx(PCONTEXT Context, int Register, int Size, LPVOID Address, DWORD Type, BOOL NoSetThreadContext);
BOOL SetBreakpoint(int Register, int Size, LPVOID Address, DWORD Type, unsigned int HitCount, PVOID Callback);
BOOL SetThreadBreakpoint(DWORD ThreadId, int Register, int Size, LPVOID Address, DWORD Type, unsigned int HitCount, PVOID Callback);
BOOL ContextSetThreadBreakpoint(PCONTEXT Context, int Register, int Size, LPVOID Address, DWORD Type, unsigned int HitCount, PVOID Callback);
BOOL ContextSetThreadBreakpointEx(PCONTEXT Context, int Register, int Size, LPVOID Address, DWORD Type, unsigned int HitCount, PVOID Callback, BOOL NoSetThreadContext);
BOOL ContextSetThreadBreakpoints(PCONTEXT ThreadContext, PTHREADBREAKPOINTS ThreadBreakpoints);
BOOL ContextSetThreadBreakpointsEx(PCONTEXT ThreadContext, PTHREADBREAKPOINTS ThreadBreakpoints, BOOL NoSetThreadContext);
BOOL ContextSetBreakpoint(PCONTEXT Context, int Register, int Size, LPVOID ddress, DWORD Type, unsigned int HitCount, PVOID Callback);
BOOL ContextSetNextAvailableBreakpoint(PCONTEXT Context, int* Register, int Size, LPVOID Address, DWORD Type, unsigned int HitCount, PVOID Callback);
BOOL SetNextAvailableBreakpoint(DWORD ThreadId, int* Register, int Size, LPVOID Address, DWORD Type, unsigned int HitCount, PVOID Callback);
BOOL ContextUpdateCurrentBreakpoint(PCONTEXT Context, int Size, LPVOID Address, DWORD Type, unsigned int HitCount, PVOID Callback);
BOOL SetThreadBreakpoints(PTHREADBREAKPOINTS ThreadBreakpoints);
BOOL SetSoftwareBreakpoint(LPVOID Address);
BOOL SetSyscallBreakpoint(LPVOID Address);

BOOL SetSingleStepMode(PCONTEXT Context, PVOID Handler);
BOOL SetResumeFlag(PCONTEXT Context);
BOOL SetZeroFlag(PCONTEXT Context);
BOOL ClearZeroFlag(PCONTEXT Context);
BOOL FlipZeroFlag(PCONTEXT Context);
BOOL SetSignFlag(PCONTEXT Context);
BOOL ClearSignFlag(PCONTEXT Context);
BOOL FlipSignFlag(PCONTEXT Context);
BOOL SetCarryFlag(PCONTEXT Context);
BOOL ClearCarryFlag(PCONTEXT Context);
BOOL FlipCarryFlag(PCONTEXT Context);
PTHREADBREAKPOINTS CreateThreadBreakpoints(DWORD ThreadId, HANDLE Handle);

// Get
BOOL GetNextAvailableBreakpoint(DWORD ThreadId, int* Register);
PTHREADBREAKPOINTS GetThreadBreakpoints(DWORD ThreadId);
BOOL ContextGetNextAvailableBreakpoint(PCONTEXT Context, int* Register);
int CheckDebugRegister(HANDLE hThread, int Register);
BOOL CheckDebugRegisters(HANDLE hThread, PCONTEXT pContext);
int ContextCheckDebugRegister(CONTEXT Context, int Register);
BOOL ContextCheckDebugRegisters(PCONTEXT pContext);
HANDLE GetThreadHandle(DWORD ThreadId);

// Clear
BOOL ClearBreakpoint(int Register);
BOOL ClearThreadBreakpoint(DWORD ThreadId, int Register);
BOOL ClearBreakpointsInRange(PVOID BaseAddress, SIZE_T Size);
BOOL ClearBreakpointsInRegion(PVOID BaseAddress);
BOOL ClearAllBreakpoints();
BOOL ContextClearBreakpoint(PCONTEXT Context, int Register);
BOOL ContextClearCurrentBreakpoint(PCONTEXT Context);
BOOL ContextClearAllBreakpoints(PCONTEXT Context);
BOOL ContextClearDebugRegisters(PCONTEXT Context);
BOOL ClearSingleStepMode(PCONTEXT Context);

// Misc
BOOL InitNewThreadBreakpoints(DWORD ThreadId, HANDLE Handle);
BOOL InitialiseDebugger(void);
BOOL ResumeFromBreakpoint(PCONTEXT Context);
void OutputThreadBreakpoints(DWORD ThreadId);
void DebugOutputThreadBreakpoints();

void ShowStack(DWORD_PTR StackPointer, unsigned int NumberOfRecords);

#ifdef __cplusplus
}
#endif