#include <stdio.h>
#include "hooking.h"
#include "log.h"
#include "pipe.h"
#include "misc.h"
#include "CAPE\CAPE.h"
#include "CAPE\Debugger.h"
#include "CAPE\YaraHarness.h"

//#define DEBUG_COMMENTS

// Minimum MSIL bytecode size threshold to scan/dump.
// This filters out trivial methods (such as simple getters, setters, constructors, 
// and boilerplate framework methods) to prevent output spam and improve performance.
#define MIN_MSIL_SIZE_THRESHOLD 32

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern BOOL BreakpointCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo);
extern BOOL SetInitialBreakpoints(PVOID ImageBase);

lookup_t g_dotnet_jit;

// The CORINFO_METHOD_INFO structure is passed to compileMethod by the CLR JIT engine.
// The first four fields are extremely stable and consistent across all .NET versions.
typedef struct {
    PVOID                 ftn;         // opaque method handle
    PVOID                 scope;       // opaque module handle
    uint8_t *             ILCode;      // pointer to the decrypted MSIL bytecode
    unsigned int          ILCodeSize;  // size of the decrypted MSIL bytecode in bytes
} CORINFO_METHOD_INFO_REDUCED;

typedef const char* (__stdcall *fnGetMethodName)(PVOID _this, PVOID ftn, const char** moduleName);

static const char* SafeGetMethodName(PVOID compHnd, PVOID ftn, const char** moduleName) {
	const char* name = NULL;
	if (!compHnd || !ftn)
		return NULL;

	__try {
		PVOID* vtable = *(PVOID**)compHnd;
		if (vtable && vtable[0]) {
			fnGetMethodName getMethodName = (fnGetMethodName)vtable[0];
			name = getMethodName(compHnd, ftn, moduleName);

			// Probe-verify the returned name pointer for absolute crash-protection
			if (name != NULL) {
				char c = name[0];
				if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '.' || c == '<' || c == '?')) {
					name = NULL;
				}
			}

			// Probe-verify the returned class/module name pointer
			if (name != NULL && moduleName && *moduleName) {
				char c = (*moduleName)[0];
				if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '.' || c == '<' || c == '?')) {
					*moduleName = NULL;
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		name = NULL;
	}
	return name;
}

HOOKDEF(int, WINAPI, compileMethod,
	PVOID			this,
	PVOID			compHnd,
	PVOID			methodInfo,
	unsigned int	flags,
	uint8_t**		entryAddress,
	uint32_t*		nativeSizeOfCode
)
{
	CORINFO_METHOD_INFO_REDUCED *info = (CORINFO_METHOD_INFO_REDUCED *)methodInfo;
    int ret = Old_compileMethod(this, compHnd, methodInfo, flags, entryAddress, nativeSizeOfCode);
	if (ret == 0) {
		const char* className = NULL;
		const char* methodName = SafeGetMethodName(compHnd, info ? info->ftn : NULL, &className);

		if (methodName != NULL) {
			LOQ_void("dotnet", "ss", "Class", className ? className : "UnknownClass", "Method", methodName);
			DebugOutput("compileMethod: Translated .NET JIT API: %s.%s\n", className ? className : "UnknownClass", methodName);
		}

		PVOID AllocationBase = GetAllocationBase(*entryAddress);
		if (AllocationBase && !lookup_get(&g_dotnet_jit, (ULONG_PTR)AllocationBase, 0))
			lookup_add(&g_dotnet_jit, (ULONG_PTR)AllocationBase, 0);
		if (g_config.yarascan)
		{
			// Scan JIT compiled native assembly code
#ifdef DEBUG_COMMENTS
			YaraScan(*entryAddress, *nativeSizeOfCode);
#else
			SilentYaraScan(*entryAddress, *nativeSizeOfCode);
#endif

			// Scan original, decrypted intermediate MSIL bytecode (only if above size threshold)
			if (info && info->ILCode && info->ILCodeSize >= MIN_MSIL_SIZE_THRESHOLD) {
#ifdef DEBUG_COMMENTS
				YaraScan(info->ILCode, info->ILCodeSize);
#else
				SilentYaraScan(info->ILCode, info->ILCodeSize);
#endif
			}
		}
		if (g_config.procdump && info && info->ILCode && info->ILCodeSize >= MIN_MSIL_SIZE_THRESHOLD) {
			if (DotNetCacheDumpCount < g_config.jit_dumps) {
				CapeMetaData->ModulePath = NULL;
				CapeMetaData->DumpType = 0;
				CapeMetaData->TypeString = ".NET JIT MSIL bytecode";
				CapeMetaData->Address = info->ILCode;
				DumpMemoryRaw(info->ILCode, info->ILCodeSize);
				DotNetCacheDumpCount++;
				DebugOutput("compileMethod: Dumped decrypted .NET JIT MSIL bytecode at 0x%p (size 0x%x).\n", info->ILCode, info->ILCodeSize);
			}
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
