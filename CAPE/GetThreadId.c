/*
CAPE - Config And Payload Extraction
Copyright(C) 2015, 2016 Context Information Security. (kevin.oreilly@contextis.com)

This program is free software : you can redistribute it and / or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.If not, see <http://www.gnu.org/licenses/>.
*/
#include <Windows.h>

#define STATUS_SUCCESS ((NTSTATUS) 0x00000000)
typedef LONG NTSTATUS;
typedef LONG KPRIORITY;
typedef PVOID PTEB;

//
// Thread Information Classes
//

typedef enum _THREADINFOCLASS
{
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair_Reusable,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger,
    ThreadBreakOnTermination,
    ThreadSwitchLegacyState,
    ThreadIsTerminated,
    MaxThreadInfoClass
} THREADINFOCLASS;

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

//
// Thread Information Structures
//

//
// Basic Thread Information
//  NtQueryInformationThread using ThreadBasicInfo
//

typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PTEB TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    KPRIORITY Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION;
typedef THREAD_BASIC_INFORMATION *PTHREAD_BASIC_INFORMATION;

typedef NTSTATUS (__stdcall *pfnNtQueryInformationThread)
(
    __in HANDLE ThreadHandle,
    __in THREADINFOCLASS ThreadInformationClass,
    __out_bcount(ThreadInformationLength) PVOID ThreadInformation,
    __in ULONG ThreadInformationLength,
    __out_opt PULONG ReturnLength
);

pfnNtQueryInformationThread NtQueryInformationThread;

//**************************************************************************************
DWORD MyGetThreadId
//**************************************************************************************
(
  _In_ HANDLE Thread
)
{
    THREAD_BASIC_INFORMATION ThreadBasicInfo;
    THREADINFOCLASS ThreadInfoClass;
	HMODULE hModule;

	if (Thread == NULL)
		return 0;

	hModule = LoadLibrary("ntdll.dll");
    NtQueryInformationThread = (pfnNtQueryInformationThread) GetProcAddress(hModule, "NtQueryInformationThread");
    if (NtQueryInformationThread == NULL)
        return 0;

    ThreadInfoClass = ThreadBasicInformation;
    if (NtQueryInformationThread(Thread, ThreadInfoClass, &ThreadBasicInfo, sizeof(ThreadBasicInfo), NULL) != STATUS_SUCCESS)
    {
        FreeLibrary(hModule);
        return 0;
    }

    FreeLibrary(hModule);

	return (DWORD)(UINT_PTR)ThreadBasicInfo.ClientId.UniqueThread;
}
