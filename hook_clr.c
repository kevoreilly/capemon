#include <stdio.h>
#include "hooking.h"
#include "log.h"
#include "pipe.h"
#include "misc.h"
#include "CAPE\CAPE.h"
#include "CAPE\Debugger.h"
#include "CAPE\YaraHarness.h"

//#define DEBUG_COMMENTS

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern BOOL BreakpointCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo);
extern BOOL SetInitialBreakpoints(PVOID ImageBase);

lookup_t g_dotnet_jit;

HOOKDEF(int, WINAPI, compileMethod,
	PVOID			this,
	PVOID			compHnd,
	PVOID			methodInfo,
	unsigned int	flags,
	uint8_t**		entryAddress,
	uint32_t*		nativeSizeOfCode
)
{
    int ret = Old_compileMethod(this, compHnd, methodInfo, flags, entryAddress, nativeSizeOfCode);
	if (ret == 0) {
		PVOID AllocationBase = GetAllocationBase(*entryAddress);
		if (AllocationBase && !lookup_get(&g_dotnet_jit, (ULONG_PTR)AllocationBase, 0)) {
			if (g_config.procdump && g_config.yarascan)
				DebugOutput(".NET JIT native cache at 0x%p: scans and dumps active.\n", AllocationBase);
			else if (g_config.procdump)
				DebugOutput(".NET JIT native cache at 0x%p: dumps active.\n", AllocationBase);
			else if (g_config.yarascan)
				DebugOutput(".NET JIT native cache at 0x%p: scans active.\n", AllocationBase);
			lookup_add(&g_dotnet_jit, (ULONG_PTR)AllocationBase, 0);
		}
		if (g_config.yarascan)
		{
#ifdef DEBUG_COMMENTS
			YaraScan(*entryAddress, *nativeSizeOfCode);
#else
			SilentYaraScan(*entryAddress, *nativeSizeOfCode);
#endif
		}
		if (g_config.break_on_jit) {
			unsigned int Register;
			if (SetNextAvailableBreakpoint(GetCurrentThreadId(), &Register, 0, *entryAddress, BP_EXEC, 1, BreakpointCallback))
				DebugOutput("compileMethod: set JIT native breakpoint.\n");
			else
				DebugOutput("compileMethod: failed to set JIT native breakpoint.\n");
		}
	}
	return ret;
}
