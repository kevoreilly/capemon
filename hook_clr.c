#include <stdio.h>
#include "hooking.h"
#include <psapi.h>
#pragma comment(lib, "version.lib")
#include "log.h"
#include "pipe.h"
#include "misc.h"
#include "config.h"
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

// Standard CLR metadata types from corhdr.h
typedef ULONG mdToken;
typedef mdToken mdTypeDef;
typedef mdToken mdMethodDef;
typedef mdToken mdTypeRef;
typedef const unsigned char* PCCOR_SIGNATURE;

// Opaque COM interface definition for IMetaDataImport (read-only metadata queries)
// We define a compact, opaque vtable structure to preserve offsets cleanly
typedef struct IMetaDataImportVtbl IMetaDataImportVtbl;

typedef struct IMetaDataImport {
    IMetaDataImportVtbl* lpVtbl;
} IMetaDataImport;

struct IMetaDataImportVtbl {
    // IUnknown methods (0-2)
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IMetaDataImport* This, REFIID riid, void** ppvObject);
    ULONG (STDMETHODCALLTYPE *AddRef)(IMetaDataImport* This);
    ULONG (STDMETHODCALLTYPE *Release)(IMetaDataImport* This);

    // Preceding IMetaDataImport methods (3-27) declared as opaque pointers to preserve vtable layout offsets cleanly
    PVOID CloseEnum;             // void CloseEnum(HCORENUM hEnum)
    PVOID CountEnum;             // HRESULT CountEnum(HCORENUM hEnum, ULONG* pulCount)
    PVOID ResetEnum;             // HRESULT ResetEnum(HCORENUM hEnum, ULONG ulPos)
    PVOID EnumTypeDefs;          // HRESULT EnumTypeDefs(HCORENUM* phEnum, mdTypeDef rTypeDefs[], ULONG cMax, ULONG* pcTypeDefs)
    PVOID EnumInterfaceImpls;    // HRESULT EnumInterfaceImpls(HCORENUM* phEnum, mdTypeDef td, mdInterfaceImpl rImpls[], ULONG cMax, ULONG* pcImpls)
    PVOID EnumTypeRefs;          // HRESULT EnumTypeRefs(HCORENUM* phEnum, mdTypeRef rTypeRefs[], ULONG cMax, ULONG* pcTypeRefs)
    PVOID FindTypeDefByName;     // HRESULT FindTypeDefByName(LPCWSTR szTypeDef, mdToken tkEnclosingClass, mdTypeDef* ptd)
    PVOID GetScopeProps;         // HRESULT GetScopeProps(LPWSTR szName, ULONG cchName, ULONG* pchName, GUID* pmvid)
    PVOID GetModuleFromScope;    // HRESULT GetModuleFromScope(mdModule* pmd)
    PVOID GetTypeDefProps;       // HRESULT GetTypeDefProps(mdTypeDef td, LPWSTR szTypeDef, ULONG cchTypeDef, ULONG* pchTypeDef, DWORD* pdwTypeDefFlags, mdToken* ptkExtends)
    PVOID GetInterfaceImplProps; // HRESULT GetInterfaceImplProps(mdInterfaceImpl ii, mdTypeDef* pclass, mdToken* ptkIface)
    PVOID GetTypeRefProps;       // HRESULT GetTypeRefProps(mdTypeRef tr, mdToken* ptkResolutionScope, LPWSTR szName, ULONG cchName, ULONG* pchName)
    PVOID ResolveTypeRef;        // HRESULT ResolveTypeRef(mdTypeRef tr, REFIID riid, IUnknown** ppIScope, mdTypeDef* ptd)
    PVOID EnumMembers;           // HRESULT EnumMembers(HCORENUM* phEnum, mdTypeDef cl, mdToken rMembers[], ULONG cMax, ULONG* pcTokens)
    PVOID EnumMembersWithName;   // HRESULT EnumMembersWithName(HCORENUM* phEnum, mdTypeDef cl, LPCWSTR szName, mdToken rMembers[], ULONG cMax, ULONG* pcTokens)
    PVOID EnumMethods;           // HRESULT EnumMethods(HCORENUM* phEnum, mdTypeDef cl, mdMethodDef rMethods[], ULONG cMax, ULONG* pcTokens)
    PVOID EnumMethodsWithName;   // HRESULT EnumMethodsWithName(HCORENUM* phEnum, mdTypeDef cl, LPCWSTR szName, mdMethodDef rMethods[], ULONG cMax, ULONG* pcTokens)
    PVOID EnumFields;            // HRESULT EnumFields(HCORENUM* phEnum, mdTypeDef cl, mdFieldDef rFields[], ULONG cMax, ULONG* pcTokens)
    PVOID EnumFieldsWithName;    // HRESULT EnumFieldsWithName(HCORENUM* phEnum, mdTypeDef cl, LPCWSTR szName, mdFieldDef rFields[], ULONG cMax, ULONG* pcTokens)
    PVOID EnumParams;            // HRESULT EnumParams(HCORENUM* phEnum, mdMethodDef mb, mdParamDef rParams[], ULONG cMax, ULONG* pcTokens)
    PVOID EnumMemberRefs;        // HRESULT EnumMemberRefs(HCORENUM* phEnum, mdToken tkParent, mdMemberRef rMemberRefs[], ULONG cMax, ULONG* pcTokens)
    PVOID EnumMethodImpls;       // HRESULT EnumMethodImpls(HCORENUM* phEnum, mdTypeDef td, mdMethodDef rMethodBody[], mdMethodDef rMethodDecl[], ULONG cMax, ULONG* pcTokens)
    PVOID EnumPermissionSets;    // HRESULT EnumPermissionSets(HCORENUM* phEnum, mdToken tk, DWORD dwActions, mdPermission rPermission[], ULONG cMax, ULONG* pcTokens)
    PVOID FindMember;            // HRESULT FindMember(mdTypeDef cl, LPCWSTR szName, PCCOR_SIGNATURE pvSigBlob, ULONG cbSigBlob, mdToken* pmember)
    PVOID FindMethod;            // HRESULT FindMethod(mdTypeDef cl, LPCWSTR szName, PCCOR_SIGNATURE pvSigBlob, ULONG cbSigBlob, mdMethodDef* pmb)
    PVOID FindField;             // HRESULT FindField(mdTypeDef cl, LPCWSTR szName, PCCOR_SIGNATURE pvSigBlob, ULONG cbSigBlob, mdFieldDef* pfd)
    PVOID FindMemberRef;         // HRESULT FindMemberRef(mdToken tkParent, LPCWSTR szName, PCCOR_SIGNATURE pvSigBlob, ULONG cbSigBlob, mdMemberRef* pmr)

    // The specific method we actually call (28)
    HRESULT (STDMETHODCALLTYPE *GetMethodProps)(IMetaDataImport* This, mdMethodDef mb, mdTypeDef* pClass, LPWSTR szMethod, ULONG cchMethod, ULONG* pchMethod, DWORD* pdwAttr, PCCOR_SIGNATURE* ppvSigBlob, ULONG* pcbSigBlob, ULONG* pulCodeRVA, DWORD* pdwImplFlags);
};

lookup_t g_dotnet_jit;

// The CORINFO_METHOD_INFO structure is passed to compileMethod by the CLR JIT engine.
// The first four fields are extremely stable and consistent across all .NET versions.
typedef struct {
    PVOID                 ftn;         // opaque method handle
    PVOID                 scope;       // opaque module handle
    uint8_t *             ILCode;      // pointer to the decrypted MSIL bytecode
    unsigned int          ILCodeSize;  // size of the decrypted MSIL bytecode in bytes
} CORINFO_METHOD_INFO_REDUCED;

#ifdef _WIN64
typedef const char* (__stdcall *fnGetMethodName)(PVOID _this, PVOID ftn, const char** moduleName);
typedef HRESULT (__stdcall *fnGetModuleMetadata)(PVOID _this, PVOID scope, DWORD dwOpenFlags, REFIID riid, IUnknown** ppOut);
#else
typedef const char* (__fastcall *fnGetMethodName)(PVOID _ecx, PVOID _edx, PVOID ftn, const char** moduleName);
typedef HRESULT (__fastcall *fnGetModuleMetadata)(PVOID _ecx, PVOID _edx, PVOID scope, DWORD dwOpenFlags, REFIID riid, IUnknown** ppOut);
#endif

// Safe helper to resolve Class and Method metadata names dynamically
static const char* SafeGetMethodName(PVOID compHnd, PVOID ftn, const char** moduleName) {
    const char* name = NULL;
    if (!compHnd || !ftn)
        return NULL;

    __try {
        PVOID* vtable = *(PVOID**)compHnd;
        if (vtable && vtable[0]) {
            fnGetMethodName getMethodName = (fnGetMethodName)vtable[0];
#ifdef _WIN64
            name = getMethodName(compHnd, ftn, moduleName);
#else
            name = getMethodName(compHnd, NULL, ftn, moduleName);
#endif

            if (name != NULL) {
                char c = name[0];
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '.' || c == '<' || c == '?')) {
                    name = NULL;
                }
            }

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

// In-Memory Version Fingerprinting for JIT offsets
static void GetDotNetVTableOffsets(HMODULE hClrModule, int* out_getModuleMetadata_idx, int* out_getMethodDefFromMethod_idx) {
    // Structural Defaults
    *out_getModuleMetadata_idx = 40;     
    *out_getMethodDefFromMethod_idx = 113;
    
    if (!hClrModule) return;
    
    HRSRC hResInfo = FindResourceW(hClrModule, MAKEINTRESOURCEW(1), (LPCWSTR)16); // 16 == RT_VERSION
    if (!hResInfo) return;
    
    HGLOBAL hResData = LoadResource(hClrModule, hResInfo);
    if (!hResData) return;
    
    PVOID pData = LockResource(hResData);
    if (!pData) return;
    
    DWORD dwResSize = SizeofResource(hClrModule, hResInfo);
    if (dwResSize == 0) return;
    
    PVOID pAlloc = malloc(dwResSize);
    if (!pAlloc) return;
    
    memcpy(pAlloc, pData, dwResSize);
    
    VS_FIXEDFILEINFO* pFixedInfo = NULL;
    UINT puLen = 0;
    
    // Natively query from RAM mapped array. Zero disk I/O.
    if (VerQueryValueW(pAlloc, L"\\", (LPVOID*)&pFixedInfo, &puLen) && pFixedInfo != NULL) {
        DWORD major = HIWORD(pFixedInfo->dwFileVersionMS);
        DWORD minor = LOWORD(pFixedInfo->dwFileVersionMS);
        DWORD build = HIWORD(pFixedInfo->dwFileVersionLS);
        
        if (major == 2) {
            *out_getMethodDefFromMethod_idx = 86;
        } else if (major == 4 && build < 30319) {
            *out_getMethodDefFromMethod_idx = 86;
        } else if (major == 4 && build >= 30319) {
            *out_getModuleMetadata_idx = 42; 
            *out_getMethodDefFromMethod_idx = 113;
        } else if (major >= 5) {
            *out_getModuleMetadata_idx = 40;
            *out_getMethodDefFromMethod_idx = 115;
        }
    }
    
    free(pAlloc);
}

// Queries IMetaDataImport directly from the CLR compileMethod context
static IMetaDataImport* GetIMetaDataImport(PVOID compHnd, PVOID scope, int getModuleMetadata_idx) {
    IMetaDataImport* pImport = NULL;
    if (!compHnd || !scope)
        return NULL;

    __try {
        PVOID* vtable = *(PVOID**)compHnd;
        if (vtable && vtable[getModuleMetadata_idx]) {
            fnGetModuleMetadata getModuleMetadata = (fnGetModuleMetadata)vtable[getModuleMetadata_idx];
            // IID_IMetaDataImport GUID = { 0x7dac2ecc, 0xd030, 0x11d2, { 0x85, 0x9d, 0x00, 0xc0, 0x4f, 0x68, 0x32, 0x8b } }
            GUID iid_import = { 0x7dac2ecc, 0xd030, 0x11d2, { 0x85, 0x9d, 0x00, 0xc0, 0x4f, 0x68, 0x32, 0x8b } };
#ifdef _WIN64
            HRESULT hr = getModuleMetadata(compHnd, scope, 0, &iid_import, (IUnknown**)&pImport);
#else
            HRESULT hr = getModuleMetadata(compHnd, NULL, scope, 0, &iid_import, (IUnknown**)&pImport);
#endif
            if (FAILED(hr)) {
                pImport = NULL;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        pImport = NULL;
    }
    return pImport;
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
		PVOID AllocationBase = GetAllocationBase(*entryAddress);
		if (AllocationBase && !lookup_get(&g_dotnet_jit, (ULONG_PTR)AllocationBase, 0))
			lookup_add(&g_dotnet_jit, (ULONG_PTR)AllocationBase, 0);

		const char* className = NULL;
		const char* methodName = SafeGetMethodName(compHnd, info ? info->ftn : NULL, &className);

		if (methodName != NULL) {
			if (g_config.jit_trace_all) {
				LOQ_void("dotnet", "ss", "Class", className ? className : "UnknownClass", "Method", methodName);
				DebugOutput("compileMethod: Translated .NET JIT API: %s.%s\n", className ? className : "UnknownClass", methodName);
			}

			// High-Signal Callstack Correlation Alerts
			// We check the resolved class and method names for critical capability triggers (Network, Cryptography, Assembly Loading)
			if (className != NULL) {
				if (strstr(className, "System.Net.WebClient") || 
					strstr(className, "System.Net.Http.HttpClient") ||
					strstr(className, "System.Net.Sockets.Socket")) {
					LOQ_void("behavior", "ss", "Event", "Initiating .NET Network Capability", "Details", className);
					DebugOutput("compileMethod: Behavioral Event - Initiating .NET Network Capability inside %s.%s\n", className, methodName);
				}
				else if (strstr(className, "System.Security.Cryptography") || 
						 strstr(className, "Rijndael") ||
						 strstr(className, "AesManaged")) {
					LOQ_void("behavior", "ss", "Event", "Initiating .NET Cryptographic Operation", "Details", className);
					DebugOutput("compileMethod: Behavioral Event - Initiating .NET Cryptographic Operation inside %s.%s\n", className, methodName);
				}
				else if (strstr(className, "System.Reflection.Assembly") || 
						 strstr(className, "System.Reflection.Emit") ||
						 strstr(className, "System.Diagnostics.Process")) {
					LOQ_void("behavior", "ss", "Event", "Initiating .NET Process/Payload Injection", "Details", className);
					DebugOutput("compileMethod: Behavioral Event - Initiating .NET Process/Payload Injection inside %s.%s\n", className, methodName);
				}
			}
		}

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

		// Unified Metadata & Decrypted MSIL JIT Assembly Rebuilder Dumper
		if (g_config.procdump && info && info->ILCode && info->ILCodeSize >= MIN_MSIL_SIZE_THRESHOLD) {
			if (DotNetCacheDumpCount < g_config.jit_dumps) {
				int getModuleMetadata_idx = 40;
				int getMethodDefFromMethod_idx = 113;

				// Dynamically extract the CLR module version footprint in-memory using .rsrc block
				PVOID AllocationBase = GetAllocationBase(*entryAddress);
				if (AllocationBase != NULL) {
					char moduleNamePath[MAX_PATH] = {0};
					if (GetMappedFileNameA(GetCurrentProcess(), AllocationBase, moduleNamePath, MAX_PATH)) {
						// Translate device path or simply resolve handle via name isolate
						HMODULE hClrModule = GetModuleHandleA("clr.dll");
						if (!hClrModule) hClrModule = GetModuleHandleA("coreclr.dll");
						if (!hClrModule) hClrModule = GetModuleHandleA("mscorwks.dll");
						
						if (hClrModule) {
							GetDotNetVTableOffsets(hClrModule, &getModuleMetadata_idx, &getMethodDefFromMethod_idx);
						}
					}
				}

				IMetaDataImport* pImport = GetIMetaDataImport(compHnd, info->scope, getModuleMetadata_idx);
				if (pImport && pImport->lpVtbl && pImport->lpVtbl->GetMethodProps) {
					// Retrieve the clean metadata properties for this method directly from the CLR
					mdTypeDef classToken = 0;
					wchar_t wszMethodName[256] = {0};
					ULONG methodLen = 0;
					DWORD dwAttr = 0;
					PCCOR_SIGNATURE pvSig = NULL;
					ULONG cbSig = 0;
					ULONG rva = 0;
					DWORD dwImplFlags = 0;

					mdMethodDef mbToken = 0;
					
					// Resolve the method token safely using dynamically mapped ICorJitInfo::getMethodDefFromMethod
					PVOID* jitVtable = *(PVOID**)compHnd;
					if (jitVtable && jitVtable[getMethodDefFromMethod_idx]) {
#ifdef _WIN64
						typedef mdMethodDef (__stdcall *fnGetMethodDefFromMethod)(PVOID _this, PVOID ftn);
						fnGetMethodDefFromMethod getMethodDef = (fnGetMethodDefFromMethod)jitVtable[getMethodDefFromMethod_idx];
						
						__try {
							mbToken = getMethodDef(compHnd, info->ftn);
#else
						// x86 fastcall resolution
						typedef mdMethodDef (__fastcall *fnGetMethodDefFromMethod)(PVOID _ecx, PVOID _edx, PVOID ftn);
						fnGetMethodDefFromMethod getMethodDef = (fnGetMethodDefFromMethod)jitVtable[getMethodDefFromMethod_idx];
						
						__try {
							mbToken = getMethodDef(compHnd, NULL, info->ftn);
#endif
							
							// A safely evaluated .NET Method token MUST possess the 0x06 Method identifier in its MSB
							if ((mbToken & 0xFF000000) != 0x06000000) {
								mbToken = 0; // Abort: The VTable index mapped an unrelated API
							}
						} __except (EXCEPTION_EXECUTE_HANDLER) {
							mbToken = 0; // Abort
						}
					}
					
					if (mbToken != 0) {

					__try {
						HRESULT hr = pImport->lpVtbl->GetMethodProps(pImport, mbToken, &classToken, wszMethodName, 256, &methodLen, &dwAttr, &pvSig, &cbSig, &rva, &dwImplFlags);
						if (SUCCEEDED(hr)) {
							// Log resolved metadata properties cleanly into CAPE database
							DebugOutput("compileMethod: CLR COM Metadata resolved method '%ws' (Token 0x%x, RVA 0x%x).\n", wszMethodName, mbToken, rva);

							// We do not cache Method RVA as Metadata RVA here anymore.
							// ScyllaHarness will robustly locate the IMAGE_COR20_HEADER natively.
						}
					}
					__except (EXCEPTION_EXECUTE_HANDLER) {
						DebugOutput("compileMethod: Exception occurred querying CLR COM metadata properties.\n");
					}
					}
				}

				// Dump the pristine, fully decrypted MSIL bytecode payload
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

#ifdef _WIN64
#define ARRAY_LENGTH_OFFSET 8
#define ARRAY_DATA_OFFSET 16
#else
#define ARRAY_LENGTH_OFFSET 4
#define ARRAY_DATA_OFFSET 8
#endif

HOOKDEF(PVOID, WINAPI, nLoadImage,
	_In_     PVOID        pArrayObject,
	_In_opt_ PVOID        pAppDomain,
	_Inout_  PVOID*       pAssembly
) {
	if (pArrayObject != NULL && g_config.procdump) {
		__try {
			PDWORD pLength = (PDWORD)((PBYTE)pArrayObject + ARRAY_LENGTH_OFFSET);
			PBYTE pRawData = (PBYTE)pArrayObject + ARRAY_DATA_OFFSET;

			if (pLength && *pLength > 0 && IsAddressAccessible(pRawData)) {
				DebugOutput("nLoadImage: Intercepted in-memory assembly byte array loading of size %u at 0x%p (Inspired by ExtremeDumper)\n", *pLength, pRawData);
				
				// Set metadata for reflective assembly load
				CapeMetaData->ModulePath = NULL;
				CapeMetaData->DumpType = 0;
				CapeMetaData->TypeString = ".NET Reflective Load PE";
				CapeMetaData->Address = pRawData;
				
				DumpMemoryRaw(pRawData, (SIZE_T)*pLength);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DebugOutput("nLoadImage: Exception occurred parsing managed U1Array.\n");
		}
	}

	return Old_nLoadImage(pArrayObject, pAppDomain, pAssembly);
}
