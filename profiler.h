#include <windows.h>
#include <corprof.h>
#include <corhdr.h>

extern "C" void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern "C" void ErrorOutput(_In_ LPCTSTR lpOutputString, ...);

class CorProfiler : public ICorProfilerCallback2
{
private:
    LONG refCount;
    ICorProfilerInfo* pCorProfilerInfo;

public:
    CorProfiler();
    virtual ~CorProfiler();

    // IUnknown methods
    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject);
    virtual ULONG STDMETHODCALLTYPE AddRef();
    virtual ULONG STDMETHODCALLTYPE Release();

    // ICorProfilerCallback methods (Partial implementation - only what we need)
    virtual HRESULT STDMETHODCALLTYPE Initialize(IUnknown *pICorProfilerInfoUnk);
    virtual HRESULT STDMETHODCALLTYPE Shutdown();
    virtual HRESULT STDMETHODCALLTYPE AppDomainCreationStarted(AppDomainID appDomainId);
    virtual HRESULT STDMETHODCALLTYPE AppDomainCreationFinished(AppDomainID appDomainId, HRESULT hrStatus);
    virtual HRESULT STDMETHODCALLTYPE AppDomainShutdownStarted(AppDomainID appDomainId);
    virtual HRESULT STDMETHODCALLTYPE AppDomainShutdownFinished(AppDomainID appDomainId, HRESULT hrStatus);
    virtual HRESULT STDMETHODCALLTYPE AssemblyLoadStarted(AssemblyID assemblyId);
    virtual HRESULT STDMETHODCALLTYPE AssemblyLoadFinished(AssemblyID assemblyId, HRESULT hrStatus);
    virtual HRESULT STDMETHODCALLTYPE AssemblyUnloadStarted(AssemblyID assemblyId);
    virtual HRESULT STDMETHODCALLTYPE AssemblyUnloadFinished(AssemblyID assemblyId, HRESULT hrStatus);
    virtual HRESULT STDMETHODCALLTYPE ModuleLoadStarted(ModuleID moduleId);
    virtual HRESULT STDMETHODCALLTYPE ModuleLoadFinished(ModuleID moduleId, HRESULT hrStatus);
    virtual HRESULT STDMETHODCALLTYPE ModuleUnloadStarted(ModuleID moduleId);
    virtual HRESULT STDMETHODCALLTYPE ModuleUnloadFinished(ModuleID moduleId, HRESULT hrStatus);
    virtual HRESULT STDMETHODCALLTYPE ModuleAttachedToAssembly(ModuleID moduleId, AssemblyID AssemblyId);
    virtual HRESULT STDMETHODCALLTYPE ClassLoadStarted(ClassID classId);
    virtual HRESULT STDMETHODCALLTYPE ClassLoadFinished(ClassID classId, HRESULT hrStatus);
    virtual HRESULT STDMETHODCALLTYPE ClassUnloadStarted(ClassID classId);
    virtual HRESULT STDMETHODCALLTYPE ClassUnloadFinished(ClassID classId, HRESULT hrStatus);
    virtual HRESULT STDMETHODCALLTYPE FunctionUnloadStarted(FunctionID functionId);
    virtual HRESULT STDMETHODCALLTYPE JITCompilationStarted(FunctionID functionId, BOOL fIsSafeToBlock);
    virtual HRESULT STDMETHODCALLTYPE JITCompilationFinished(FunctionID functionId, HRESULT hrStatus, BOOL fIsSafeToBlock);
    virtual HRESULT STDMETHODCALLTYPE JITCachedFunctionSearchStarted(FunctionID functionId, BOOL *pbUseCachedFunction);
    virtual HRESULT STDMETHODCALLTYPE JITCachedFunctionSearchFinished(FunctionID functionId, COR_PRF_JIT_CACHE result);
    virtual HRESULT STDMETHODCALLTYPE JITFunctionPitched(FunctionID functionId);
    virtual HRESULT STDMETHODCALLTYPE JITInlining(FunctionID callerId, FunctionID calleeId, BOOL *pfShouldInline);
    virtual HRESULT STDMETHODCALLTYPE ThreadCreated(ThreadID threadId);
    virtual HRESULT STDMETHODCALLTYPE ThreadDestroyed(ThreadID threadId);
    virtual HRESULT STDMETHODCALLTYPE ThreadAssignedToOSThread(ThreadID managedThreadId, DWORD osThreadId);
    virtual HRESULT STDMETHODCALLTYPE RemotingClientInvocationStarted();
    virtual HRESULT STDMETHODCALLTYPE RemotingClientSendingMessage(GUID *pCookie, BOOL fIsAsync);
    virtual HRESULT STDMETHODCALLTYPE RemotingClientReceivingReply(GUID *pCookie, BOOL fIsAsync);
    virtual HRESULT STDMETHODCALLTYPE RemotingClientInvocationFinished();
    virtual HRESULT STDMETHODCALLTYPE RemotingServerReceivingMessage(GUID *pCookie, BOOL fIsAsync);
    virtual HRESULT STDMETHODCALLTYPE RemotingServerInvocationStarted();
    virtual HRESULT STDMETHODCALLTYPE RemotingServerInvocationReturned();
    virtual HRESULT STDMETHODCALLTYPE RemotingServerSendingReply(GUID *pCookie, BOOL fIsAsync);
    virtual HRESULT STDMETHODCALLTYPE UnmanagedToManagedTransition(FunctionID functionId, COR_PRF_TRANSITION_REASON reason);
    virtual HRESULT STDMETHODCALLTYPE ManagedToUnmanagedTransition(FunctionID functionId, COR_PRF_TRANSITION_REASON reason);
    virtual HRESULT STDMETHODCALLTYPE RuntimeSuspendStarted(COR_PRF_SUSPEND_REASON suspendReason);
    virtual HRESULT STDMETHODCALLTYPE RuntimeSuspendFinished();
    virtual HRESULT STDMETHODCALLTYPE RuntimeSuspendAborted();
    virtual HRESULT STDMETHODCALLTYPE RuntimeResumeStarted();
    virtual HRESULT STDMETHODCALLTYPE RuntimeResumeFinished();
    virtual HRESULT STDMETHODCALLTYPE RuntimeThreadSuspended(ThreadID threadId);
    virtual HRESULT STDMETHODCALLTYPE RuntimeThreadResumed(ThreadID threadId);
    virtual HRESULT STDMETHODCALLTYPE MovedReferences(ULONG cMovedObjectIDRanges, ObjectID oldObjectIDRangeStart[], ObjectID newObjectIDRangeStart[], ULONG cObjectIDRangeLength[]);
    virtual HRESULT STDMETHODCALLTYPE ObjectAllocated(ObjectID objectId, ClassID classId);
    virtual HRESULT STDMETHODCALLTYPE ObjectsAllocatedByClass(ULONG cClassCount, ClassID classIds[], ULONG cObjects[]);
    virtual HRESULT STDMETHODCALLTYPE ObjectReferences(ObjectID objectId, ClassID classId, ULONG cObjectRefs, ObjectID objectRefIds[]);
    virtual HRESULT STDMETHODCALLTYPE RootReferences(ULONG cRootRefs, ObjectID rootRefIds[]);
    virtual HRESULT STDMETHODCALLTYPE ExceptionThrown(ObjectID thrownObjectId);
    virtual HRESULT STDMETHODCALLTYPE ExceptionSearchFunctionEnter(FunctionID functionId);
    virtual HRESULT STDMETHODCALLTYPE ExceptionSearchFunctionLeave();
    virtual HRESULT STDMETHODCALLTYPE ExceptionSearchFilterEnter(FunctionID functionId);
    virtual HRESULT STDMETHODCALLTYPE ExceptionSearchFilterLeave();
    virtual HRESULT STDMETHODCALLTYPE ExceptionSearchCatcherFound(FunctionID functionId);
    virtual HRESULT STDMETHODCALLTYPE ExceptionOSHandlerEnter(UINT_PTR __unused);
    virtual HRESULT STDMETHODCALLTYPE ExceptionOSHandlerLeave(UINT_PTR __unused);
    virtual HRESULT STDMETHODCALLTYPE ExceptionUnwindFunctionEnter(FunctionID functionId);
    virtual HRESULT STDMETHODCALLTYPE ExceptionUnwindFunctionLeave();
    virtual HRESULT STDMETHODCALLTYPE ExceptionUnwindFinallyEnter(FunctionID functionId);
    virtual HRESULT STDMETHODCALLTYPE ExceptionUnwindFinallyLeave();
    virtual HRESULT STDMETHODCALLTYPE ExceptionCatcherEnter(FunctionID functionId, ObjectID objectId);
    virtual HRESULT STDMETHODCALLTYPE ExceptionCatcherLeave();
    virtual HRESULT STDMETHODCALLTYPE COMClassicVTableCreated(ClassID wrappedClassId, REFGUID implementedIID, void *pVTable, ULONG cSlots);
    virtual HRESULT STDMETHODCALLTYPE COMClassicVTableDestroyed(ClassID wrappedClassId, REFGUID implementedIID, void *pVTable);
    virtual HRESULT STDMETHODCALLTYPE ExceptionCatchFunctionEnter(FunctionID functionId, ObjectID objectId);
    virtual HRESULT STDMETHODCALLTYPE ExceptionCatchFunctionLeave();

    // ICorProfilerCallback2 methods
    virtual HRESULT STDMETHODCALLTYPE ThreadNameChanged(ThreadID threadId, ULONG cchName, WCHAR name[]);
    virtual HRESULT STDMETHODCALLTYPE GarbageCollectionStarted(int cGenerations, BOOL generationCollected[], COR_PRF_GC_REASON reason);
    virtual HRESULT STDMETHODCALLTYPE SurvivingReferences(ULONG cSurvivingObjectIDRanges, ObjectID objectIDRangeStart[], ULONG cObjectIDRangeLength[]);
    virtual HRESULT STDMETHODCALLTYPE GarbageCollectionFinished();
    virtual HRESULT STDMETHODCALLTYPE FinalizeableObjectQueued(DWORD finalizerFlags, ObjectID objectID);
    virtual HRESULT STDMETHODCALLTYPE RootReferences2(ULONG cRootRefs, ObjectID rootRefIds[], COR_PRF_GC_ROOT_KIND rootKinds[], COR_PRF_GC_ROOT_FLAGS rootFlags[], UINT_PTR rootIds[]);
    virtual HRESULT STDMETHODCALLTYPE HandleCreated(GCHandleID handleId, ObjectID initialObjectId);
    virtual HRESULT STDMETHODCALLTYPE HandleDestroyed(GCHandleID handleId);
};
