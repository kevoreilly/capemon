PTRACKEDREGION CurrentRegion;

void UnpackerCallback();
//void MapSectionViewHandler(PVOID Address, SIZE_T RegionSize, ULONG Protect);
void AllocationHandler(PVOID BaseAddress, SIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
void ProtectionHandler(PVOID BaseAddress, ULONG Protect, PULONG OldProtect);
void FreeHandler(PVOID BaseAddress);
BOOL ActivateBreakpoints(PTRACKEDREGION TrackedRegion, struct _EXCEPTION_POINTERS* ExceptionInfo);
BOOL ShellcodeExecCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo);
