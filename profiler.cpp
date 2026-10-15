#include "profiler.h"

#pragma comment(lib, "corguids.lib")

extern "C" int DumpMemoryRaw(PVOID Buffer, SIZE_T Size);
extern "C" BOOL SetCapeMetaData(DWORD DumpType, DWORD TargetPid, HANDLE hTargetProcess, PVOID Address);

#define MIN_MSIL_SIZE_THRESHOLD 32

// Defined in hook_clr.c / capemon.c / misc.c
extern "C" {
    #include "hooking.h"
    #include "misc.h"
    #include "config.h"
    extern unsigned int DotNetCacheDumpCount;
    extern lookup_t g_dotnet_jit;
}

static BOOL ReserveProfilerJitDump()
{
    for (;;) {
        LONG cur = *(volatile LONG *)&DotNetCacheDumpCount;
        if ((unsigned int)cur >= g_config.jit_dumps)
            return FALSE;
        if (InterlockedCompareExchange((volatile LONG *)&DotNetCacheDumpCount, cur + 1, cur) == cur)
            return TRUE;
    }
}

static void ReleaseProfilerJitDump()
{
    for (;;) {
        LONG cur = *(volatile LONG *)&DotNetCacheDumpCount;
        if (cur <= 0)
            return;
        if (InterlockedCompareExchange((volatile LONG *)&DotNetCacheDumpCount, cur - 1, cur) == cur)
            return;
    }
}

static BOOL HasSystemDotNetPrefixW(const WCHAR *Name)
{
    static const WCHAR *Prefixes[] = {
        L"System",
        L"Microsoft",
        L"Internal",
        L"Interop",
        L"MS",
        L"Windows",
    };
    if (!Name || !*Name)
        return FALSE;
    for (size_t i = 0; i < ARRAYSIZE(Prefixes); i++) {
        size_t len = wcslen(Prefixes[i]);
        if (!_wcsnicmp(Name, Prefixes[i], len) && (Name[len] == L'\0' || Name[len] == L'.'))
            return TRUE;
    }
    return FALSE;
}

static BOOL IsSystemDotNetModule(ICorProfilerInfo *pInfo, ModuleID moduleId)
{
    LPCBYTE pBaseLoadAddress = nullptr;
    WCHAR modulePath[MAX_PATH] = {0};
    ULONG cchModulePath = 0;

    if (!pInfo || FAILED(pInfo->GetModuleInfo(moduleId, &pBaseLoadAddress, ARRAYSIZE(modulePath), &cchModulePath, modulePath, nullptr)))
        return FALSE;

    if (pBaseLoadAddress && is_in_dll_range((ULONG_PTR)pBaseLoadAddress))
        return TRUE;

    modulePath[MAX_PATH - 1] = L'\0';
    if (modulePath[0] && (
        path_is_system(modulePath) ||
        wcsistr(modulePath, L"\\windows\\microsoft.net\\") ||
        wcsistr(modulePath, L"\\windows\\assembly\\") ||
        wcsistr(modulePath, L"\\program files\\dotnet\\") ||
        wcsistr(modulePath, L"\\program files (x86)\\dotnet\\") ||
        wcsistr(modulePath, L"\\dotnet\\shared\\")))
        return TRUE;

    return FALSE;
}

// Global profiler CLSID: {F39DABDF-BA6B-41E8-AB2A-16BE2E111005}
const CLSID CLSID_CapemonProfiler = { 0xf39dabdf, 0xba6b, 0x41e8, { 0xab, 0x2a, 0x16, 0xbe, 0x2e, 0x11, 0x10, 0x05 } };

CorProfiler::CorProfiler() : refCount(1), pCorProfilerInfo(nullptr)
{
}

CorProfiler::~CorProfiler()
{
    if (pCorProfilerInfo)
    {
        pCorProfilerInfo->Release();
        pCorProfilerInfo = nullptr;
    }
}

HRESULT STDMETHODCALLTYPE CorProfiler::QueryInterface(REFIID riid, void** ppvObject)
{
    if (!ppvObject)
        return E_POINTER;

    if (riid == IID_IUnknown || riid == IID_ICorProfilerCallback || riid == IID_ICorProfilerCallback2)
    {
        *ppvObject = this;
        AddRef();
        return S_OK;
    }

    *ppvObject = nullptr;
    return E_NOINTERFACE;
}

ULONG STDMETHODCALLTYPE CorProfiler::AddRef()
{
    return InterlockedIncrement(&refCount);
}

ULONG STDMETHODCALLTYPE CorProfiler::Release()
{
    LONG count = InterlockedDecrement(&refCount);
    if (count == 0)
        delete this;
    return count;
}

HRESULT STDMETHODCALLTYPE CorProfiler::Initialize(IUnknown *pICorProfilerInfoUnk)
{
    lasterror_t lasterror;
    hook_info_t *hookinfo = hook_info();
    unsigned int saved_disable_count = hookinfo ? hookinfo->disable_count : 0;

    get_lasterrors(&lasterror);
    hook_disable();

    // Now that the CLR has loaded our profiler, scrub the profiler environment
    // variables from the PEB and hide them from subsequent GetEnvironmentVariable calls.
    scrub_profiler_env_vars();

    DebugOutput("CorProfiler: Initialize called\n");

    HRESULT hr = pICorProfilerInfoUnk->QueryInterface(IID_ICorProfilerInfo, (void**)&pCorProfilerInfo);
    if (FAILED(hr))
    {
        ErrorOutput("CorProfiler: Failed to query ICorProfilerInfo\n");
        if (hookinfo)
            hookinfo->disable_count = saved_disable_count;
        set_lasterrors(&lasterror);
        return hr;
    }

    // Monitor JIT compilation
    DWORD eventMask = COR_PRF_MONITOR_JIT_COMPILATION;
    hr = pCorProfilerInfo->SetEventMask(eventMask);
    if (FAILED(hr))
    {
        ErrorOutput("CorProfiler: Failed to set event mask\n");
        if (hookinfo)
            hookinfo->disable_count = saved_disable_count;
        set_lasterrors(&lasterror);
        return hr;
    }

    DebugOutput("CorProfiler: Initialization successful\n");
    if (hookinfo)
        hookinfo->disable_count = saved_disable_count;
    set_lasterrors(&lasterror);
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::Shutdown()
{
    if (pCorProfilerInfo)
    {
        pCorProfilerInfo->Release();
        pCorProfilerInfo = nullptr;
    }
    return S_OK;
}

HRESULT STDMETHODCALLTYPE CorProfiler::JITCompilationStarted(FunctionID functionId, BOOL fIsSafeToBlock)
{
    if (!pCorProfilerInfo) return S_OK;

    lasterror_t lasterror;
    hook_info_t *hookinfo = hook_info();
    unsigned int saved_disable_count = hookinfo ? hookinfo->disable_count : 0;

    get_lasterrors(&lasterror);
    hook_disable();

    ModuleID moduleId = 0;
    mdToken methodToken = 0;
    HRESULT hr = pCorProfilerInfo->GetFunctionInfo(functionId, nullptr, &moduleId, &methodToken);
    if (FAILED(hr) || IsSystemDotNetModule(pCorProfilerInfo, moduleId)) {
        if (hookinfo)
            hookinfo->disable_count = saved_disable_count;
        set_lasterrors(&lasterror);
        return S_OK;
    }

    // Get metadata import interface
    IMetaDataImport* pMetaDataImport = nullptr;
    hr = pCorProfilerInfo->GetModuleMetaData(moduleId, ofRead, IID_IMetaDataImport, (IUnknown**)&pMetaDataImport);
    if (FAILED(hr) || !pMetaDataImport) {
        if (hookinfo)
            hookinfo->disable_count = saved_disable_count;
        set_lasterrors(&lasterror);
        return S_OK;
    }

    WCHAR methodName[256] = {0};
    ULONG nameLength = 0;
    mdTypeDef classToken = mdTypeDefNil;
    hr = pMetaDataImport->GetMethodProps(methodToken, &classToken, methodName, ARRAYSIZE(methodName), &nameLength, nullptr, nullptr, nullptr, nullptr, nullptr);

    WCHAR className[256] = {0};
    if (SUCCEEDED(hr) && classToken != mdTypeDefNil)
    {
        pMetaDataImport->GetTypeDefProps(classToken, className, ARRAYSIZE(className), &nameLength, nullptr, nullptr);
    }
    pMetaDataImport->Release();

    if (HasSystemDotNetPrefixW(className)) {
        if (hookinfo)
            hookinfo->disable_count = saved_disable_count;
        set_lasterrors(&lasterror);
        return S_OK;
    }

    // Now get the IL code
    LPCBYTE pMethodHeader = nullptr;
    ULONG cbMethodSize = 0;
    hr = pCorProfilerInfo->GetILFunctionBody(moduleId, methodToken, &pMethodHeader, &cbMethodSize);

    if (SUCCEEDED(hr) && pMethodHeader && cbMethodSize >= MIN_MSIL_SIZE_THRESHOLD && !our_isbadreadptr(pMethodHeader, cbMethodSize))
    {
        DebugOutput("CorProfiler JIT: %S.%S (Size: 0x%x)\n", className, methodName, cbMethodSize);
        if (g_config.procdump && ReserveProfilerJitDump()) {
            CapeMetaData->ModulePath = NULL;
            CapeMetaData->DumpType = 0;
            CapeMetaData->TypeString = ".NET Profiler MSIL bytecode";
            CapeMetaData->Address = (PVOID)pMethodHeader;
            if (!DumpMemoryRaw((PVOID)pMethodHeader, (SIZE_T)cbMethodSize))
                ReleaseProfilerJitDump();
        }
    }

    if (hookinfo)
        hookinfo->disable_count = saved_disable_count;
    set_lasterrors(&lasterror);
    return S_OK;
}

// --- All other ICorProfilerCallback methods (no-ops) ---
HRESULT STDMETHODCALLTYPE CorProfiler::AppDomainCreationStarted(AppDomainID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::AppDomainCreationFinished(AppDomainID, HRESULT) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::AppDomainShutdownStarted(AppDomainID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::AppDomainShutdownFinished(AppDomainID, HRESULT) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::AssemblyLoadStarted(AssemblyID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::AssemblyLoadFinished(AssemblyID, HRESULT) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::AssemblyUnloadStarted(AssemblyID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::AssemblyUnloadFinished(AssemblyID, HRESULT) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ModuleLoadStarted(ModuleID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ModuleLoadFinished(ModuleID, HRESULT) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ModuleUnloadStarted(ModuleID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ModuleUnloadFinished(ModuleID, HRESULT) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ModuleAttachedToAssembly(ModuleID, AssemblyID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ClassLoadStarted(ClassID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ClassLoadFinished(ClassID, HRESULT) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ClassUnloadStarted(ClassID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ClassUnloadFinished(ClassID, HRESULT) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::FunctionUnloadStarted(FunctionID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::JITCompilationFinished(FunctionID, HRESULT, BOOL) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::JITCachedFunctionSearchStarted(FunctionID, BOOL*) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::JITCachedFunctionSearchFinished(FunctionID, COR_PRF_JIT_CACHE) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::JITFunctionPitched(FunctionID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::JITInlining(FunctionID, FunctionID, BOOL*) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ThreadCreated(ThreadID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ThreadDestroyed(ThreadID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ThreadAssignedToOSThread(ThreadID, DWORD) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::RemotingClientInvocationStarted() { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::RemotingClientSendingMessage(GUID*, BOOL) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::RemotingClientReceivingReply(GUID*, BOOL) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::RemotingClientInvocationFinished() { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::RemotingServerReceivingMessage(GUID*, BOOL) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::RemotingServerInvocationStarted() { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::RemotingServerInvocationReturned() { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::RemotingServerSendingReply(GUID*, BOOL) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::UnmanagedToManagedTransition(FunctionID, COR_PRF_TRANSITION_REASON) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ManagedToUnmanagedTransition(FunctionID, COR_PRF_TRANSITION_REASON) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::RuntimeSuspendStarted(COR_PRF_SUSPEND_REASON) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::RuntimeSuspendFinished() { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::RuntimeSuspendAborted() { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::RuntimeResumeStarted() { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::RuntimeResumeFinished() { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::RuntimeThreadSuspended(ThreadID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::RuntimeThreadResumed(ThreadID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::MovedReferences(ULONG, ObjectID[], ObjectID[], ULONG[]) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ObjectAllocated(ObjectID, ClassID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ObjectsAllocatedByClass(ULONG, ClassID[], ULONG[]) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ObjectReferences(ObjectID, ClassID, ULONG, ObjectID[]) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::RootReferences(ULONG, ObjectID[]) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionThrown(ObjectID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionSearchFunctionEnter(FunctionID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionSearchFunctionLeave() { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionSearchFilterEnter(FunctionID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionSearchFilterLeave() { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionSearchCatcherFound(FunctionID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionOSHandlerEnter(UINT_PTR) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionOSHandlerLeave(UINT_PTR) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionUnwindFunctionEnter(FunctionID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionUnwindFunctionLeave() { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionUnwindFinallyEnter(FunctionID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionUnwindFinallyLeave() { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionCatcherEnter(FunctionID, ObjectID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionCatcherLeave() { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionCLRCatcherFound() { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionCLRCatcherExecute() { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::COMClassicVTableCreated(ClassID, REFGUID, void*, ULONG) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::COMClassicVTableDestroyed(ClassID, REFGUID, void*) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionCatchFunctionEnter(FunctionID, ObjectID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ExceptionCatchFunctionLeave() { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::ThreadNameChanged(ThreadID, ULONG, WCHAR[]) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::GarbageCollectionStarted(int, BOOL[], COR_PRF_GC_REASON) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::SurvivingReferences(ULONG, ObjectID[], ULONG[]) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::GarbageCollectionFinished() { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::FinalizeableObjectQueued(DWORD, ObjectID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::RootReferences2(ULONG, ObjectID[], COR_PRF_GC_ROOT_KIND[], COR_PRF_GC_ROOT_FLAGS[], UINT_PTR[]) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::HandleCreated(GCHandleID, ObjectID) { return S_OK; }
HRESULT STDMETHODCALLTYPE CorProfiler::HandleDestroyed(GCHandleID) { return S_OK; }

class CorProfilerClassFactory : public IClassFactory
{
private:
    LONG refCount;
public:
    CorProfilerClassFactory() : refCount(1) {}

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) {
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *ppvObject = this;
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() {
        return InterlockedIncrement(&refCount);
    }

    ULONG STDMETHODCALLTYPE Release() {
        LONG count = InterlockedDecrement(&refCount);
        if (count == 0) delete this;
        return count;
    }

    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject) {
        if (pUnkOuter != nullptr) return CLASS_E_NOAGGREGATION;

        CorProfiler* profiler = new CorProfiler();
        if (!profiler) return E_OUTOFMEMORY;

        HRESULT hr = profiler->QueryInterface(riid, ppvObject);
        profiler->Release();
        return hr;
    }

    HRESULT STDMETHODCALLTYPE LockServer(BOOL fLock) {
        return S_OK;
    }
};

extern "C" HRESULT STDMETHODCALLTYPE ProfilerDllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv)
{
    // AmsiDumper.cpp defines its own DllGetClassObject. We must either merge them or ensure only one exists.
    // However, for the profiler we only care about CLSID_CapemonProfiler.
    if (IsEqualCLSID(rclsid, CLSID_CapemonProfiler))
    {
        CorProfilerClassFactory* factory = new CorProfilerClassFactory();
        if (!factory) return E_OUTOFMEMORY;
        HRESULT hr = factory->QueryInterface(riid, ppv);
        factory->Release();
        return hr;
    }

    // Attempt to fallback to AmsiDumper if we merged them (not done here for brevity).
    return CLASS_E_CLASSNOTAVAILABLE;
}
