#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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

// Serialises access to g_dotnet_jit (a lock-free linked list in lookup.c) and to
// DotNetCacheDumpCount, both of which are touched concurrently by the CLR's JIT
// worker threads from inside the compileMethod hook. Initialised in DllMain.
CRITICAL_SECTION g_dotnet_jit_lock;

// The CORINFO_METHOD_INFO structure is passed to compileMethod by the CLR JIT engine.
// The first four fields are extremely stable and consistent across all .NET versions.
typedef struct {
    PVOID                 ftn;         // opaque method handle
    PVOID                 scope;       // opaque module handle
    uint8_t *             ILCode;      // pointer to the decrypted MSIL bytecode
    unsigned int          ILCodeSize;  // size of the decrypted MSIL bytecode in bytes
} CORINFO_METHOD_INFO_REDUCED;

// These ICorJitInfo methods are plain virtuals (no __stdcall qualifier), so on
// x86 they are __thiscall (this in ECX); on x64 there is a single convention.
//
// .NET Framework (clr.dll) exposes the classic 2-arg accessor:
//     const char* getMethodName(CORINFO_METHOD_HANDLE ftn, const char** moduleName)
// .NET Core / 5+ removed it; the metadata name accessor there is:
//     const char* getMethodNameFromMetadata(CORINFO_METHOD_HANDLE ftn,
//         const char** className, const char** namespaceName,
//         const char** enclosingClassNames, size_t maxEnclosingClassNames)
#if defined(_M_IX86)
typedef const char* (__thiscall *fnGetMethodName)(PVOID _this, PVOID ftn, const char** moduleName);
typedef const char* (__thiscall *fnGetMethodNameFromMetadata)(PVOID _this, PVOID ftn, const char** className, const char** namespaceName, const char** enclosingClassNames, size_t maxEnclosingClassNames);
#else
typedef const char* (*fnGetMethodName)(PVOID _this, PVOID ftn, const char** moduleName);
typedef const char* (*fnGetMethodNameFromMetadata)(PVOID _this, PVOID ftn, const char** className, const char** namespaceName, const char** enclosingClassNames, size_t maxEnclosingClassNames);
#endif

// --- .NET runtime identification ----------------------------------------------
// getMethodName() sits at a version-dependent offset in the ICorJitInfo vtable
// that the runtime deliberately reorders on every JIT-EE interface revision
// (.NET Framework 2.0/4.x, .NET Core, .NET 5-9...). There is no offset that is
// correct across runtimes, so we never call a hard-coded slot blindly: we
// identify the running CLR once and look the slot up in GetMethodNameSlot()
// below. Unknown layout => name resolution is skipped and nothing else changes.
typedef enum {
	DOTNET_RT_UNKNOWN = 0,
	DOTNET_RT_FRAMEWORK,   // clr.dll (4.x) / mscorwks.dll (2.0-3.5)
	DOTNET_RT_CORE         // coreclr.dll (.NET Core / 5+)
} dotnet_runtime_t;

static dotnet_runtime_t g_dotnet_runtime = DOTNET_RT_UNKNOWN;
static char g_dotnet_version[64] = {0};   // best-effort, taken from the module directory
static int  g_dotnet_major = 0;           // major version parsed from the above (Core only)
static int  g_getmethodname_slot = -1;    // -1 => unknown layout, name resolution disabled
static BOOL g_dotnet_runtime_resolved = FALSE;

// Returns the ICorJitInfo vtable index of the metadata name accessor for the
// detected runtime, or -1 when the layout is not known. The JIT-EE interface is
// reordered on every major .NET release (and, rarely, in servicing), so each
// entry is version-gated; a wrong index is still rejected by the output
// validation in SafeGetMethodName(), and -1 avoids the call entirely.
static int GetMethodNameSlot(dotnet_runtime_t rt, int major)
{
	switch (rt) {
	case DOTNET_RT_CORE:
		// getMethodNameFromMetadata. Index cross-checked against dotnet/runtime
		// release/9.0: ThunkInput.txt position 121 (1-based) and the flat vtable
		// order in icorjitinfoimpl_generated.h agree on 0-based slot 120.
		// .NET 8 and 10 place it elsewhere, hence the exact-major gate.
		if (major == 9)
			return 120;
		return -1;
	case DOTNET_RT_FRAMEWORK:
		// Classic getMethodName (different, older API - see fnGetMethodName).
		return -1; // TODO: verified slot for clr.dll (v4.0.30319)
	default:
		return -1;
	}
}

static void ResolveDotNetRuntime(void)
{
	HMODULE hMod = NULL;

	if (g_dotnet_runtime_resolved)
		return;

	EnterCriticalSection(&g_dotnet_jit_lock);
	if (g_dotnet_runtime_resolved) {
		LeaveCriticalSection(&g_dotnet_jit_lock);
		return;
	}

	if ((hMod = GetModuleHandleA("coreclr.dll")) != NULL)
		g_dotnet_runtime = DOTNET_RT_CORE;
	else if ((hMod = GetModuleHandleA("clr.dll")) != NULL || (hMod = GetModuleHandleA("mscorwks.dll")) != NULL)
		g_dotnet_runtime = DOTNET_RT_FRAMEWORK;

	// Both runtimes ship inside a version-named directory
	// (...\Framework64\v4.0.30319\clr.dll, ...\Microsoft.NETCore.App\8.0.11\coreclr.dll),
	// which is a hooked-API-free way to get a usable version token.
	if (hMod) {
		char path[MAX_PATH];
		DWORD len = GetModuleFileNameA(hMod, path, MAX_PATH);
		if (len > 0 && len < MAX_PATH) {
			char *end = strrchr(path, '\\');
			if (end) {
				*end = '\0';
				char *dir = strrchr(path, '\\');
				if (dir) {
					strncpy(g_dotnet_version, dir + 1, sizeof(g_dotnet_version) - 1);
					g_dotnet_version[sizeof(g_dotnet_version) - 1] = '\0';
				}
			}
		}
	}

	// Directory token is "9.0.11" for CoreCLR, "v4.0.30319" for Framework;
	// atoi() yields the CoreCLR major and 0 for the (unused-here) Framework case.
	if (g_dotnet_runtime == DOTNET_RT_CORE && g_dotnet_version[0])
		g_dotnet_major = atoi(g_dotnet_version);

	g_getmethodname_slot = GetMethodNameSlot(g_dotnet_runtime, g_dotnet_major);
	g_dotnet_runtime_resolved = TRUE;
	LeaveCriticalSection(&g_dotnet_jit_lock);

	DebugOutput("compileMethod: .NET runtime = %s %s (name accessor vtable slot %d)\n",
		g_dotnet_runtime == DOTNET_RT_CORE ? "CoreCLR" :
		g_dotnet_runtime == DOTNET_RT_FRAMEWORK ? "Framework" : "unknown",
		g_dotnet_version[0] ? g_dotnet_version : "?", g_getmethodname_slot);
}

static BOOLEAN IsSafeStringA(const char* str, size_t max_len) {
	if (!str || our_isbadreadptr(str, 1))
		return FALSE;

	__try {
		for (size_t i = 0; i < max_len; i++) {
			char c = str[i];
			if (c == '\0')
				return TRUE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
	return FALSE; // Exceeded max_len without null-termination
}

static const char* SafeGetMethodName(PVOID compHnd, PVOID ftn, const char** moduleName) {
	const char* name = NULL;
	if (moduleName)
		*moduleName = NULL;

	if (!compHnd || !ftn)
		return NULL;

	// Only proceed when the name-accessor vtable slot is known for this runtime.
	if (g_getmethodname_slot < 0)
		return NULL;

	// Verify compHnd and ftn pointers are readable before dereferencing or invoking
	if (our_isbadreadptr(compHnd, sizeof(PVOID)) || our_isbadreadptr(ftn, sizeof(PVOID)))
		return NULL;

	__try {
		PVOID* vtable = *(PVOID**)compHnd;
		PVOID slotfn = (vtable && !our_isbadreadptr(vtable, (ULONG)((g_getmethodname_slot + 1) * sizeof(PVOID))))
			? vtable[g_getmethodname_slot] : NULL;
		if (slotfn && !our_isbadreadptr(slotfn, 1)) {
			if (g_dotnet_runtime == DOTNET_RT_CORE) {
				// getMethodNameFromMetadata: moduleName receives the class name,
				// namespace is returned separately (captured but not used here -
				// the caller logs Class + Method only).
				const char* namespaceName = NULL;
				fnGetMethodNameFromMetadata getMethodNameFromMetadata = (fnGetMethodNameFromMetadata)slotfn;
				name = getMethodNameFromMetadata(compHnd, ftn, moduleName, &namespaceName, NULL, 0);
			} else {
				fnGetMethodName getMethodName = (fnGetMethodName)slotfn;
				name = getMethodName(compHnd, ftn, moduleName);
			}

			// Probe-verify the returned name pointer for absolute crash-protection
			if (name != NULL) {
				if (!IsSafeStringA(name, 256)) {
					name = NULL;
				} else {
					char c = name[0];
					if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '.' || c == '<' || c == '?')) {
						name = NULL;
					}
				}
			}

			// Probe-verify the returned class/module name pointer
			if (name != NULL && moduleName && *moduleName) {
				if (!IsSafeStringA(*moduleName, 256)) {
					*moduleName = NULL;
				} else {
					char c = (*moduleName)[0];
					if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '.' || c == '<' || c == '?')) {
						*moduleName = NULL;
					}
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		name = NULL;
		if (moduleName)
			*moduleName = NULL;
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
	CORINFO_METHOD_INFO_REDUCED *info = NULL;
	if (methodInfo && !our_isbadreadptr(methodInfo, sizeof(CORINFO_METHOD_INFO_REDUCED))) {
		info = (CORINFO_METHOD_INFO_REDUCED *)methodInfo;
	}

	int ret = Old_compileMethod(this, compHnd, methodInfo, flags, entryAddress, nativeSizeOfCode);
	if (ret == 0) {
		ResolveDotNetRuntime();

		const char* className = NULL;
		const char* methodName = SafeGetMethodName(compHnd, info ? info->ftn : NULL, &className);

		if (methodName != NULL) {
			LOQ_void("dotnet", "ss", "Class", className ? className : "UnknownClass", "Method", methodName);
			DebugOutput("compileMethod: Translated .NET JIT API: %s.%s\n", className ? className : "UnknownClass", methodName);
		}

		PVOID nativeCode = NULL;
		uint32_t nativeCodeSize = 0;

		if (entryAddress && !our_isbadreadptr(entryAddress, sizeof(PVOID))) {
			nativeCode = *entryAddress;
		}
		if (nativeSizeOfCode && !our_isbadreadptr(nativeSizeOfCode, sizeof(uint32_t))) {
			nativeCodeSize = *nativeSizeOfCode;
		}

		if (nativeCode && nativeCodeSize > 0 && !our_isbadreadptr(nativeCode, nativeCodeSize)) {
			PVOID AllocationBase = GetAllocationBase(nativeCode);
			if (AllocationBase) {
				EnterCriticalSection(&g_dotnet_jit_lock);
				if (!lookup_get(&g_dotnet_jit, (ULONG_PTR)AllocationBase, 0))
					lookup_add(&g_dotnet_jit, (ULONG_PTR)AllocationBase, 0);
				LeaveCriticalSection(&g_dotnet_jit_lock);
			}

			if (g_config.yarascan)
			{
				// Scan JIT compiled native assembly code
#ifdef DEBUG_COMMENTS
				YaraScan(nativeCode, nativeCodeSize);
#else
				SilentYaraScan(nativeCode, nativeCodeSize);
#endif
			}
		}

		if (g_config.yarascan && info && info->ILCode && info->ILCodeSize >= MIN_MSIL_SIZE_THRESHOLD && !our_isbadreadptr(info->ILCode, info->ILCodeSize))
		{
			// Scan original, decrypted intermediate MSIL bytecode (only if above size threshold)
#ifdef DEBUG_COMMENTS
			YaraScan(info->ILCode, info->ILCodeSize);
#else
			SilentYaraScan(info->ILCode, info->ILCodeSize);
#endif
		}

		if (g_config.procdump && info && info->ILCode && info->ILCodeSize >= MIN_MSIL_SIZE_THRESHOLD && !our_isbadreadptr(info->ILCode, info->ILCodeSize)) {
			// Hold the lock across the whole dump: it serialises both the shared
			// counter and the shared CapeMetaData scratch fields against other
			// JIT threads, and only runs at most g_config.jit_dumps times.
			EnterCriticalSection(&g_dotnet_jit_lock);
			if (DotNetCacheDumpCount < g_config.jit_dumps) {
				CapeMetaData->ModulePath = NULL;
				CapeMetaData->DumpType = 0;
				CapeMetaData->TypeString = ".NET JIT MSIL bytecode";
				CapeMetaData->Address = info->ILCode;
				DumpMemoryRaw(info->ILCode, info->ILCodeSize);
				DotNetCacheDumpCount++;
				DebugOutput("compileMethod: Dumped decrypted .NET JIT MSIL bytecode at 0x%p (size 0x%x).\n", info->ILCode, info->ILCodeSize);
			}
			LeaveCriticalSection(&g_dotnet_jit_lock);
		}

		if (g_config.break_on_jit && nativeCode) {
			unsigned int Register;
			if (SetNextAvailableBreakpoint(GetCurrentThreadId(), &Register, 0, nativeCode, BP_EXEC, 1, BreakpointCallback))
				DebugOutput("compileMethod: set JIT native breakpoint.\n");
			else
				DebugOutput("compileMethod: failed to set JIT native breakpoint.\n");
		}
	}
	return ret;
}
