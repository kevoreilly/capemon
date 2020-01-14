#define EXTRACTION_MIN_SIZE 0x1001

typedef struct TrackedRegion
{
    PVOID						AllocationBase;
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
    DWORD                       EntryPoint;
    double                      Entropy;
    // under review
    SIZE_T                      MinPESize;
    BOOL                        WriteBreakpointSet;
    //BOOL                        PeImageDetected;
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

PTRACKEDREGION AddTrackedRegion(PVOID Address, SIZE_T RegionSize, ULONG Protect);
PTRACKEDREGION GetTrackedRegion(PVOID Address);
void ExtractionCallback();
void ProcessImageBase(PTRACKEDREGION TrackedRegion);
void ProcessTrackedRegion(PTRACKEDREGION TrackedRegion);
//void MapSectionViewHandler(PVOID Address, SIZE_T RegionSize, ULONG Protect);
void AllocationHandler(PVOID BaseAddress, SIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
void ProtectionHandler(PVOID BaseAddress, SIZE_T RegionSize, ULONG Protect, ULONG OldProtect);
void FreeHandler(PVOID BaseAddress);
void ProcessTrackedRegions();
