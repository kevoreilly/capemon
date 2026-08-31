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
// The name accessor differs by runtime, hence four shapes:
//
//   Framework (clr.dll), METHOD_NAME_ABI_FRAMEWORK_V2:
//     const char* getMethodName(CORINFO_METHOD_HANDLE ftn, const char** moduleName)
//   .NET Core 2.1 ... .NET 2.2, METHOD_NAME_ABI_CORE_V3:
//     const char* getMethodNameFromMetadata(CORINFO_METHOD_HANDLE ftn,
//         const char** className, const char** namespaceName)
//   .NET Core 3.1 ... .NET 8, METHOD_NAME_ABI_CORE_V4:
//     const char* getMethodNameFromMetadata(CORINFO_METHOD_HANDLE ftn,
//         const char** className, const char** namespaceName,
//         const char** enclosingClassName)
//   .NET 9+, METHOD_NAME_ABI_CORE_V5 (adds maxEnclosingClassNames):
//     ...same, plus  size_t maxEnclosingClassNames
typedef enum {
	METHOD_NAME_ABI_NONE = 0,
	METHOD_NAME_ABI_FRAMEWORK_V2,
	METHOD_NAME_ABI_CORE_V3,
	METHOD_NAME_ABI_CORE_V4,
	METHOD_NAME_ABI_CORE_V5
} method_name_abi_t;

#if defined(_M_IX86)
typedef const char* (__fastcall *fnGetMethodName_v2)(PVOID _this, PVOID dummy, PVOID ftn, const char** moduleName);
typedef const char* (__fastcall *fnGetMethodNameFromMetadata_v3)(PVOID _this, PVOID dummy, PVOID ftn, const char** className, const char** namespaceName);
typedef const char* (__fastcall *fnGetMethodNameFromMetadata_v4)(PVOID _this, PVOID dummy, PVOID ftn, const char** className, const char** namespaceName, const char** enclosingClassName);
typedef const char* (__fastcall *fnGetMethodNameFromMetadata_v5)(PVOID _this, PVOID dummy, PVOID ftn, const char** className, const char** namespaceName, const char** enclosingClassName, size_t maxEnclosingClassNames);
#else
typedef const char* (*fnGetMethodName_v2)(PVOID _this, PVOID ftn, const char** moduleName);
typedef const char* (*fnGetMethodNameFromMetadata_v3)(PVOID _this, PVOID ftn, const char** className, const char** namespaceName);
typedef const char* (*fnGetMethodNameFromMetadata_v4)(PVOID _this, PVOID ftn, const char** className, const char** namespaceName, const char** enclosingClassName);
typedef const char* (*fnGetMethodNameFromMetadata_v5)(PVOID _this, PVOID ftn, const char** className, const char** namespaceName, const char** enclosingClassName, size_t maxEnclosingClassNames);
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
static int  g_dotnet_minor = 0;           // minor version parsed from the above (Core only)
static int  g_getmethodname_slot = -1;    // -1 => unknown layout, name resolution disabled
static method_name_abi_t g_method_name_abi = METHOD_NAME_ABI_NONE;
static BOOL g_dotnet_runtime_resolved = FALSE;

// Resolves the ICorJitInfo vtable index of the name accessor for the detected
// runtime and the ABI to call it with. Returns -1 (and *abi = NONE) when the
// layout is not known for certain: the JIT-EE interface is reordered on every
// major .NET release, so an index MUST be verified for that exact release
// before being enabled here - either by counting the "...override;" method
// declarations in that branch's src/coreclr/inc/icorjitinfoimpl_generated.h,
// or with `dps poi(@comp)` in a debugger against the real binary. A wrong index
// is still rejected by the output validation in SafeGetMethodName(), but -1
// avoids the call (and its cost) entirely.
static int GetMethodNameSlot(dotnet_runtime_t rt, int major, int minor, method_name_abi_t *abi)
{
	*abi = METHOD_NAME_ABI_NONE;

	// getMethodName / getMethodNameFromMetadata ICorJitInfo vtable slot.
	// Indices are based on real shipping binary verification.
	switch (rt) {
	case DOTNET_RT_CORE:
		switch (major) {
		case 1:
			*abi = METHOD_NAME_ABI_FRAMEWORK_V2;
			return 105; // CoreCLR 1.1.x
		case 2:
			if (minor == 0) {
				*abi = METHOD_NAME_ABI_FRAMEWORK_V2;
				return 106; // CoreCLR 2.0.x
			} else {
				*abi = METHOD_NAME_ABI_CORE_V3;
				return 114; // CoreCLR 2.1.x, 2.2.x
			}
		case 3:
			*abi = METHOD_NAME_ABI_CORE_V4;
			return 118; // CoreCLR 3.0.x / 3.1.x
		case 5:
			*abi = METHOD_NAME_ABI_CORE_V4;
			return 113; // .NET 5.0
		case 6:
			*abi = METHOD_NAME_ABI_CORE_V4;
			return 115; // .NET 6.0
		case 7:
			*abi = METHOD_NAME_ABI_CORE_V4;
			return 117; // .NET 7.0
		case 8:
			*abi = METHOD_NAME_ABI_CORE_V4;
			return 115; // .NET 8.0
		case 9:
			*abi = METHOD_NAME_ABI_CORE_V5;
			return 120; // .NET 9.0
		case 10:
			*abi = METHOD_NAME_ABI_CORE_V5;
			return 122; // .NET 10.0
		default:
			return -1;
		}
	case DOTNET_RT_FRAMEWORK:
		// getMethodName on .NET Framework clr.dll (4.8)
		*abi = METHOD_NAME_ABI_FRAMEWORK_V2;
		return 113;
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
	if (g_dotnet_runtime == DOTNET_RT_CORE && g_dotnet_version[0]) {
		int major = 0, minor = 0;
		if (sscanf(g_dotnet_version, "%d.%d", &major, &minor) >= 1) {
			g_dotnet_major = major;
			g_dotnet_minor = minor;
		}
	}

	g_getmethodname_slot = GetMethodNameSlot(g_dotnet_runtime, g_dotnet_major, g_dotnet_minor, &g_method_name_abi);
	g_dotnet_runtime_resolved = TRUE;
	LeaveCriticalSection(&g_dotnet_jit_lock);

	DebugOutput("compileMethod: .NET runtime = %s %s (name accessor vtable slot %d)\n",
		g_dotnet_runtime == DOTNET_RT_CORE ? "CoreCLR" :
		g_dotnet_runtime == DOTNET_RT_FRAMEWORK ? "Framework" : "unknown",
		g_dotnet_version[0] ? g_dotnet_version : "?", g_getmethodname_slot);
}

// Bounded, fault-tolerant check that s is a readable, NUL-terminated string
// (within 256 bytes) that plausibly looks like a managed type/method identifier.
// Rejects anything a stray/mis-typed vtable call is likely to hand back.
static BOOLEAN IsPlausibleName(const char* s)
{
	if (!s || our_isbadreadptr(s, 1))
		return FALSE;

	__try {
		char c0 = s[0];
		if (!((c0 >= 'a' && c0 <= 'z') || (c0 >= 'A' && c0 <= 'Z') ||
		      c0 == '_' || c0 == '.' || c0 == '<' || c0 == '?'))
			return FALSE;

		for (size_t i = 0; i < 256; i++) {
			if (s[i] == '\0')
				return i > 0;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
	return FALSE; // not NUL-terminated within 256 bytes
}

// Resolves the managed method name (return value) and, for the CoreCLR ABIs, the
// class and namespace via out-params. Every path is guarded: unknown slot/ABI,
// unreadable pointers and a faulting call all yield NULL with the out-params
// cleared. Never invokes a hard-coded slot without a verified GetMethodNameSlot()
// entry for the running runtime.
static const char* SafeGetMethodName(PVOID compHnd, PVOID ftn, const char** className, const char** namespaceName)
{
	const char* name = NULL;

	if (className)
		*className = NULL;
	if (namespaceName)
		*namespaceName = NULL;

	if (!compHnd || !ftn || g_getmethodname_slot < 0 || g_method_name_abi == METHOD_NAME_ABI_NONE)
		return NULL;

	if (our_isbadreadptr(compHnd, sizeof(PVOID)) || our_isbadreadptr(ftn, sizeof(PVOID)))
		return NULL;

	__try {
		PVOID* vtable = *(PVOID**)compHnd;
		PVOID slotfn = (vtable && !our_isbadreadptr(vtable, (ULONG)((g_getmethodname_slot + 1) * sizeof(PVOID))))
			? vtable[g_getmethodname_slot] : NULL;

		if (slotfn && !our_isbadreadptr(slotfn, 1)) {
			const char* enclosing = NULL;

#if defined(_M_IX86)
			switch (g_method_name_abi) {
			case METHOD_NAME_ABI_FRAMEWORK_V2:
				// className receives the combined "Namespace.Class" string.
				name = ((fnGetMethodName_v2)slotfn)(compHnd, NULL, ftn, className);
				break;
			case METHOD_NAME_ABI_CORE_V3:
				name = ((fnGetMethodNameFromMetadata_v3)slotfn)(compHnd, NULL, ftn, className, namespaceName);
				break;
			case METHOD_NAME_ABI_CORE_V4:
				name = ((fnGetMethodNameFromMetadata_v4)slotfn)(compHnd, NULL, ftn, className, namespaceName, &enclosing);
				break;
			case METHOD_NAME_ABI_CORE_V5:
				name = ((fnGetMethodNameFromMetadata_v5)slotfn)(compHnd, NULL, ftn, className, namespaceName, &enclosing, 0);
				break;
			default:
				name = NULL;
				break;
			}
#else
			switch (g_method_name_abi) {
			case METHOD_NAME_ABI_FRAMEWORK_V2:
				// className receives the combined "Namespace.Class" string.
				name = ((fnGetMethodName_v2)slotfn)(compHnd, ftn, className);
				break;
			case METHOD_NAME_ABI_CORE_V3:
				name = ((fnGetMethodNameFromMetadata_v3)slotfn)(compHnd, ftn, className, namespaceName);
				break;
			case METHOD_NAME_ABI_CORE_V4:
				name = ((fnGetMethodNameFromMetadata_v4)slotfn)(compHnd, ftn, className, namespaceName, &enclosing);
				break;
			case METHOD_NAME_ABI_CORE_V5:
				name = ((fnGetMethodNameFromMetadata_v5)slotfn)(compHnd, ftn, className, namespaceName, &enclosing, 0);
				break;
			default:
				name = NULL;
				break;
			}
#endif

			if (name && !IsPlausibleName(name))
				name = NULL;
			if (name && className && *className && !IsPlausibleName(*className))
				*className = NULL;
			if (name && namespaceName && *namespaceName && !IsPlausibleName(*namespaceName))
				*namespaceName = NULL;
			if (!name) {
				if (className)
					*className = NULL;
				if (namespaceName)
					*namespaceName = NULL;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		name = NULL;
		if (className)
			*className = NULL;
		if (namespaceName)
			*namespaceName = NULL;
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
		const char* namespaceName = NULL;
		const char* methodName = SafeGetMethodName(compHnd, info ? info->ftn : NULL, &className, &namespaceName);

		if (methodName != NULL) {
			LOQ_void("dotnet", "sss", "Namespace", namespaceName ? namespaceName : "",
				"Class", className ? className : "UnknownClass", "Method", methodName);
			DebugOutput("compileMethod: Translated .NET JIT API: %s%s%s.%s\n",
				namespaceName ? namespaceName : "", namespaceName ? "." : "",
				className ? className : "UnknownClass", methodName);
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
