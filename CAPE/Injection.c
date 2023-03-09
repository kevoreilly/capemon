/*
CAPE - Config And Payload Extraction
Copyright(C) 2019 Kevin O'Reilly (kevoreilly@gmail.com)

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
//#define DEBUG_COMMENTS
#include <stdio.h>
#include "..\ntapi.h"
#include <psapi.h>
#include <distorm.h>
#include "..\misc.h"
#include "..\hooking.h"
#include "..\log.h"
#include "..\pipe.h"
#include "..\config.h"
#include "Debugger.h"
#include "CAPE.h"
#include "Injection.h"
#include "Shlwapi.h"

#pragma comment(lib, "shlwapi.lib")
#pragma warning(push )
#pragma warning(disable : 4996)

extern _NtMapViewOfSection pNtMapViewOfSection;
extern _NtUnmapViewOfSection pNtUnmapViewOfSection;

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern void TestDebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern void ErrorOutput(_In_ LPCTSTR lpOutputString, ...);
extern PVOID get_process_image_base(HANDLE process_handle);
extern wchar_t *our_dll_path_w;
extern char *our_process_name;
extern void hook_disable();
extern void hook_enable();

//**************************************************************************************
PINJECTIONINFO GetInjectionInfo(DWORD ProcessId)
//**************************************************************************************
{
	DWORD CurrentProcessId;

	PINJECTIONINFO CurrentInjectionInfo = InjectionInfoList;
	while (CurrentInjectionInfo)
	{
		CurrentProcessId = CurrentInjectionInfo->ProcessId;

		if (CurrentProcessId == ProcessId)
			return CurrentInjectionInfo;
		else
			CurrentInjectionInfo = CurrentInjectionInfo->NextInjectionInfo;
	}

	return NULL;
}

//**************************************************************************************
PINJECTIONINFO GetInjectionInfoFromHandle(HANDLE ProcessHandle)
//**************************************************************************************
{
	HANDLE CurrentProcessHandle;

	PINJECTIONINFO CurrentInjectionInfo = InjectionInfoList;
	while (CurrentInjectionInfo)
	{
		CurrentProcessHandle = CurrentInjectionInfo->ProcessHandle;

		if (CurrentProcessHandle == ProcessHandle)
			return CurrentInjectionInfo;
		else
			CurrentInjectionInfo = CurrentInjectionInfo->NextInjectionInfo;
	}

	return NULL;
}

//**************************************************************************************
PINJECTIONINFO CreateInjectionInfo(DWORD ProcessId)
//**************************************************************************************
{
	PINJECTIONINFO CurrentInjectionInfo, PreviousInjectionInfo;

	PreviousInjectionInfo = NULL;

	if (InjectionInfoList == NULL)
	{
		InjectionInfoList = ((struct InjectionInfo*)malloc(sizeof(struct InjectionInfo)));

		if (InjectionInfoList == NULL)
		{
			DebugOutput("CreateInjectionInfo: failed to allocate memory for initial injection info list.\n");
			return NULL;
		}

		memset(InjectionInfoList, 0, sizeof(struct InjectionInfo));

		InjectionInfoList->ProcessId = ProcessId;
	}

	CurrentInjectionInfo = InjectionInfoList;

	while (CurrentInjectionInfo)
	{
		if ((CurrentInjectionInfo->ProcessId) == ProcessId)
			break;

		PreviousInjectionInfo = CurrentInjectionInfo;
		CurrentInjectionInfo = CurrentInjectionInfo->NextInjectionInfo;
	}

	if (!CurrentInjectionInfo && PreviousInjectionInfo)
	{
		// We haven't found it in the linked list, so create a new one
		CurrentInjectionInfo = PreviousInjectionInfo;

		CurrentInjectionInfo->NextInjectionInfo = ((struct InjectionInfo*)malloc(sizeof(struct InjectionInfo)));

		if (CurrentInjectionInfo->NextInjectionInfo == NULL)
		{
			DebugOutput("CreateInjectionInfo: Failed to allocate new thread breakpoints.\n");
			return NULL;
		}

		memset(CurrentInjectionInfo->NextInjectionInfo, 0, sizeof(struct InjectionInfo));

		CurrentInjectionInfo = CurrentInjectionInfo->NextInjectionInfo;

		CurrentInjectionInfo->ProcessId = ProcessId;
	}

	return CurrentInjectionInfo;
}

//**************************************************************************************
BOOL DropInjectionInfo(HANDLE ProcessHandle)
//**************************************************************************************
{
	HANDLE CurrentProcessHandle;
	PINJECTIONINFO PreviousInjectionInfo, CurrentInjectionInfo = InjectionInfoList;

	PreviousInjectionInfo = NULL;

	while (CurrentInjectionInfo)
	{
		CurrentProcessHandle = CurrentInjectionInfo->ProcessHandle;

		if (CurrentProcessHandle == ProcessHandle)
		{
			// Unlink this from the list and free the memory
			if (PreviousInjectionInfo && CurrentInjectionInfo->NextInjectionInfo)
			{
				PreviousInjectionInfo->NextInjectionInfo = CurrentInjectionInfo->NextInjectionInfo;
				DebugOutput("DropInjectionInfo: removed injection info for pid %d.\n", CurrentInjectionInfo->ProcessId);
			}
			else if (PreviousInjectionInfo && CurrentInjectionInfo->NextInjectionInfo == NULL)
			{
				PreviousInjectionInfo->NextInjectionInfo = NULL;
				DebugOutput("DropInjectionInfo: removed injection info for pid %d from the end of the section view list.\n", CurrentInjectionInfo->ProcessId);
			}
			else if (!PreviousInjectionInfo)
			{
				InjectionInfoList = NULL;
				DebugOutput("DropInjectionInfo: removed the head of the injection info list for pid %d.\n", CurrentInjectionInfo->ProcessId);
			}

			free(CurrentInjectionInfo);

			return TRUE;
		}

		PreviousInjectionInfo = CurrentInjectionInfo;
		CurrentInjectionInfo = CurrentInjectionInfo->NextInjectionInfo;
	}

	return FALSE;
}

//**************************************************************************************
PINJECTIONSECTIONVIEW GetSectionView(HANDLE SectionHandle)
//**************************************************************************************
{
	PINJECTIONSECTIONVIEW CurrentSectionView = SectionViewList;

	while (CurrentSectionView)
	{
		if (CurrentSectionView->SectionHandle == SectionHandle)
			return CurrentSectionView;

		CurrentSectionView = CurrentSectionView->NextSectionView;
	}

	return NULL;
}

//**************************************************************************************
PINJECTIONSECTIONVIEW AddSectionView(HANDLE SectionHandle, PVOID LocalView, SIZE_T ViewSize)
//**************************************************************************************
{
	PINJECTIONSECTIONVIEW CurrentSectionView, PreviousSectionView;

	PreviousSectionView = NULL;

	if (SectionViewList == NULL)
	{
		SectionViewList = ((struct InjectionSectionView*)malloc(sizeof(struct InjectionSectionView)));

		if (SectionViewList == NULL)
		{
			DebugOutput("AddSectionView: failed to allocate memory for initial section view list.\n");
			return NULL;
		}

		memset(SectionViewList, 0, sizeof(struct InjectionSectionView));

		SectionViewList->SectionHandle = SectionHandle;
		if (LocalView)
		{
			SectionViewList->LocalView = LocalView;
			SectionViewList->ViewSize = ViewSize;
		}
	}

	CurrentSectionView = SectionViewList;

	while (CurrentSectionView)
	{
		if ((CurrentSectionView->SectionHandle) == SectionHandle)
			break;

		PreviousSectionView = CurrentSectionView;
		CurrentSectionView = CurrentSectionView->NextSectionView;
	}

	if (!CurrentSectionView && PreviousSectionView)
	{
		// We haven't found it in the linked list, so create a new one
		CurrentSectionView = PreviousSectionView;

		CurrentSectionView->NextSectionView = ((struct InjectionSectionView*)malloc(sizeof(struct InjectionSectionView)));

		if (CurrentSectionView->NextSectionView == NULL)
		{
			DebugOutput("CreateSectionView: Failed to allocate new injection sectionview structure.\n");
			return NULL;
		}

		memset(CurrentSectionView->NextSectionView, 0, sizeof(struct InjectionSectionView));

		CurrentSectionView = CurrentSectionView->NextSectionView;
		CurrentSectionView->SectionHandle = SectionHandle;

		if (LocalView)
		{
			CurrentSectionView->LocalView = LocalView;
			CurrentSectionView->ViewSize = ViewSize;
		}
	}

	return CurrentSectionView;
}

//**************************************************************************************
BOOL DropSectionView(PINJECTIONSECTIONVIEW SectionView)
//**************************************************************************************
{
	PINJECTIONSECTIONVIEW CurrentSectionView, PreviousSectionView;

	PreviousSectionView = NULL;

	if (SectionViewList == NULL)
	{
		DebugOutput("DropSectionView: failed to obtain initial section view list.\n");
		return FALSE;
	}

	CurrentSectionView = SectionViewList;

	while (CurrentSectionView)
	{
		if (CurrentSectionView == SectionView)
		{
			// Unlink this from the list and free the memory
			if (PreviousSectionView && CurrentSectionView->NextSectionView)
			{
				PreviousSectionView->NextSectionView = CurrentSectionView->NextSectionView;
				DebugOutput("DropSectionView: removed a view from section view list.\n");
			}
			else if (PreviousSectionView && CurrentSectionView->NextSectionView == NULL)
			{
				PreviousSectionView->NextSectionView = NULL;
				DebugOutput("DropSectionView: removed the view from the end of the section view list.\n");
			}
			else if (!PreviousSectionView)
			{
				SectionViewList = NULL;
				DebugOutput("DropSectionView: removed the head of the section view list.\n");
			}

			free(CurrentSectionView);

			return TRUE;
		}

		PreviousSectionView = CurrentSectionView;
		CurrentSectionView = CurrentSectionView->NextSectionView;
	}

	return FALSE;
}

//**************************************************************************************
void DumpSectionViewsForPid(DWORD Pid)
//**************************************************************************************
{
	struct InjectionInfo *InjectionInfo;
	PINJECTIONSECTIONVIEW CurrentSectionView;
	LPVOID PEPointer = NULL;
	BOOL Dumped;

	if (Pid == GetCurrentProcessId())
		return;

	InjectionInfo = GetInjectionInfo(Pid);

	if (InjectionInfo == NULL)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("DumpSectionViewsForPid: No injection info for pid %d.\n", Pid);
#endif
		return;
	}

	CurrentSectionView = SectionViewList;

	while (CurrentSectionView)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("DumpSectionViewsForPid: MapDetected %d pid %d LocalView 0x%x.\n", CurrentSectionView->MapDetected, CurrentSectionView->TargetProcessId, CurrentSectionView->LocalView);
#endif

		if (CurrentSectionView->MapDetected && CurrentSectionView->TargetProcessId == Pid && CurrentSectionView->LocalView)
		{
			SIZE_T AccessibleSize = GetAccessibleSize(CurrentSectionView->LocalView);

			DebugOutput("DumpSectionViewsForPid: Shared section view found with pid %d, size %d (accessible %d), local address 0x%p.\n", Pid, CurrentSectionView->ViewSize, AccessibleSize, CurrentSectionView->LocalView);

			PEPointer = CurrentSectionView->LocalView;
			Dumped = FALSE;

			while (AccessibleSize && ScanForDisguisedPE(PEPointer, AccessibleSize - ((DWORD_PTR)PEPointer - (DWORD_PTR)CurrentSectionView->LocalView), &PEPointer))
			{
				DebugOutput("DumpSectionViewsForPid: Dumping PE image from shared section view, local address 0x%p.\n", PEPointer);

				CapeMetaData->DumpType = INJECTION_PE;
				CapeMetaData->TargetPid = Pid;
				CapeMetaData->Address = PEPointer;

				Dumped = DumpImageInCurrentProcess(PEPointer);

				if (Dumped)
					DebugOutput("DumpSectionViewsForPid: Dumped PE image from shared section view.\n");
				else
					DebugOutput("DumpSectionViewsForPid: Failed to dump PE image from shared section view.\n");

				((BYTE*)PEPointer)++;
			}

			if (AccessibleSize && Dumped == FALSE)
			{
				DebugOutput("DumpSectionViewsForPid: no PE file found in shared section view, attempting raw dump.\n");

				CapeMetaData->DumpType = INJECTION_SHELLCODE;

				CapeMetaData->TargetPid = Pid;

				Dumped = DumpMemory(CurrentSectionView->LocalView, AccessibleSize);

				if (Dumped)
					DebugOutput("DumpSectionViewsForPid: Dumped shared section view.");
				else
					DebugOutput("DumpSectionViewsForPid: Failed to dump shared section view.");
			}
		}

		//DropSectionView(CurrentSectionView);
		CurrentSectionView->MapDetected = FALSE;

		CurrentSectionView = CurrentSectionView->NextSectionView;
	}

	return;
}

//**************************************************************************************
void DumpSectionView(PINJECTIONSECTIONVIEW SectionView)
//**************************************************************************************
{
	LPVOID PEPointer = NULL;
	BOOL Dumped = FALSE;

	if (!SectionView->LocalView)
	{
		DebugOutput("DumpSectionView: Section view local view address not set.\n");
		return;
	}

	if (!SectionView->TargetProcessId)
	{
		DebugOutput("DumpSectionView: Section with local view 0x%p has no target process - error.\n", SectionView->LocalView);
		return;
	}

	if (!SectionView->ViewSize)
	{
		DebugOutput("DumpSectionView: Section with local view 0x%p has zero commit size - error.\n", SectionView->LocalView);
		return;
	}

	CapeMetaData->DumpType = INJECTION_PE;

	CapeMetaData->TargetPid = SectionView->TargetProcessId;

	CapeMetaData->Address = SectionView->LocalView;

	Dumped = DumpPEsInRange(SectionView->LocalView, SectionView->ViewSize);

	if (Dumped)
		DebugOutput("DumpSectionView: Dumped PE image from shared section view with local address 0x%p.\n", SectionView->LocalView);
	else
	{
		DebugOutput("DumpSectionView: no PE file found in shared section view with local address 0x%p, attempting raw dump.\n", SectionView->LocalView);

		CapeMetaData->DumpType = INJECTION_SHELLCODE;

		Dumped = DumpMemory(SectionView->LocalView, SectionView->ViewSize);

		if (Dumped)
		{
			DebugOutput("DumpSectionView: Dumped shared section view with local address at 0x%p", SectionView->LocalView);
		}
		else
			DebugOutput("DumpSectionView: Failed to dump shared section view with address view at 0x%p", SectionView->LocalView);
	}

	if (Dumped == TRUE)
		DropSectionView(SectionView);
	else
	{   // This may indicate the view has been unmapped already
		// Let's try and remap it.
		SIZE_T ViewSize = 0;
		PVOID BaseAddress = NULL;

		DebugOutput("DumpSectionView: About to remap section with handle 0x%x, size 0x%x.\n", SectionView->SectionHandle, SectionView->ViewSize);

		NTSTATUS ret = pNtMapViewOfSection(SectionView->SectionHandle, NtCurrentProcess(), &BaseAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READWRITE);

		if (NT_SUCCESS(ret))
		{
			CapeMetaData->DumpType = INJECTION_PE;

			Dumped = DumpPEsInRange(BaseAddress, ViewSize);

			if (Dumped)
				DebugOutput("DumpSectionView: Remapped and dumped section view with handle 0x%x.\n", SectionView->SectionHandle);
			else
			{
				DebugOutput("DumpSectionView: no PE file found in remapped section view with handle 0x%x, attempting raw dump.\n", SectionView->SectionHandle);

				CapeMetaData->DumpType = INJECTION_SHELLCODE;

				CapeMetaData->TargetPid = SectionView->TargetProcessId;

				Dumped = DumpMemory(BaseAddress, ViewSize);

				if (Dumped)
					DebugOutput("DumpSectionView: Dumped remapped section view with handle 0x%x.\n", SectionView->SectionHandle);
				else
					DebugOutput("DumpSectionView: Failed to dump remapped section view with handle 0x%x.\n", SectionView->SectionHandle);
			}

			pNtUnmapViewOfSection(SectionView->SectionHandle, BaseAddress);
		}
		else
			DebugOutput("DumpSectionView: Failed to remap section with handle 0x%x - error code 0x%x\n", SectionView->SectionHandle, ret);
	}

	return;
}

//**************************************************************************************
void DumpSectionViewsForHandle(HANDLE SectionHandle)
//**************************************************************************************
{
	PINJECTIONSECTIONVIEW CurrentSectionView = SectionViewList;

	while (CurrentSectionView)
	{
		if (CurrentSectionView->SectionHandle == SectionHandle)
			break;

		CurrentSectionView = CurrentSectionView->NextSectionView;
	}

	if (CurrentSectionView && CurrentSectionView->TargetProcessId)
	{
		DebugOutput("DumpSectionViewsForHandle: Dumping section view at 0x%p for handle 0x%x (target process %d).\n", CurrentSectionView->LocalView, SectionHandle, CurrentSectionView->TargetProcessId);
		DumpSectionView(CurrentSectionView);
	}

	return;
}

void GetThreadContextHandler(DWORD Pid, LPCONTEXT Context)
{
	if (Context && Context->ContextFlags & CONTEXT_CONTROL)
	{
		struct InjectionInfo *CurrentInjectionInfo = GetInjectionInfo(Pid);
#ifdef _WIN64
		if (CurrentInjectionInfo && CurrentInjectionInfo->ProcessId == Pid)
			CurrentInjectionInfo->StackPointer = (LPVOID)Context->Rsp;
#else
		if (CurrentInjectionInfo && CurrentInjectionInfo->ProcessId == Pid)
			CurrentInjectionInfo->StackPointer = (LPVOID)Context->Esp;
#endif
	}
}

void SetThreadContextHandler(DWORD Pid, const CONTEXT *Context)
{
	if (!Context || !(Context->ContextFlags & CONTEXT_CONTROL))
		return;

	MEMORY_BASIC_INFORMATION MemoryInfo;
	struct InjectionInfo *CurrentInjectionInfo = GetInjectionInfo(Pid);

	if (!CurrentInjectionInfo)
		return;

#ifdef _WIN64
	if (VirtualQueryEx(CurrentInjectionInfo->ProcessHandle, (PVOID)Context->Rcx, &MemoryInfo, sizeof(MemoryInfo)))
		CurrentInjectionInfo->ImageBase = (DWORD_PTR)MemoryInfo.AllocationBase;
	else
	{
		ErrorOutput("SetThreadContextHandler: Failed to query target process memory at address 0x%p", Context->Rcx);
		return;
	}

	if (!CurrentInjectionInfo || CurrentInjectionInfo->ProcessId != Pid)
		return;

	CurrentInjectionInfo->EntryPoint = Context->Rcx - CurrentInjectionInfo->ImageBase;  // rcx holds ep on 64-bit

	if (Context->Rip == (DWORD_PTR)GetProcAddress(GetModuleHandle("ntdll"), "NtMapViewOfSection"))
		DebugOutput("SetThreadContextHandler: Hollow process entry point set to NtMapViewOfSection (process %d).\n", Pid);
	else
		DebugOutput("SetThreadContextHandler: Hollow process entry point reset via NtSetContextThread to 0x%p (process %d).\n", CurrentInjectionInfo->EntryPoint, Pid);
#else
	if (VirtualQueryEx(CurrentInjectionInfo->ProcessHandle, (PVOID)Context->Eax, &MemoryInfo, sizeof(MemoryInfo)))
		CurrentInjectionInfo->ImageBase = (DWORD_PTR)MemoryInfo.AllocationBase;
	else
	{
		ErrorOutput("SetThreadContextHandler: Failed to query target process memory at address 0x%x", Context->Eax);
		return;
	}

	if (!CurrentInjectionInfo || CurrentInjectionInfo->ProcessId != Pid)
		return;

	CurrentInjectionInfo->EntryPoint = Context->Eax - CurrentInjectionInfo->ImageBase;  // eax holds ep on 32-bit

	if (Context->Eip == (DWORD)GetProcAddress(GetModuleHandle("ntdll"), "NtMapViewOfSection"))
		DebugOutput("SetThreadContextHandler: Hollow process entry point set to NtMapViewOfSection (process %d).\n", Pid);
	else
		DebugOutput("SetThreadContextHandler: Hollow process entry point reset via NtSetContextThread to 0x%p (process %d).\n", CurrentInjectionInfo->EntryPoint, Pid);
#endif
}

BOOL CheckDontMonitorList(WCHAR* TargetProcess)
{
	const wchar_t *DontMonitorList[] =
	{
		L"c:\\windows\\splwow64.exe",
	};

	if (g_config.firefox && !wcsicmp(TargetProcess, L"C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe"))
		return TRUE;

	if (g_config.chrome && !wcsicmp(TargetProcess, L"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"))
		return TRUE;

	if (g_config.edge && !wcsicmp(TargetProcess, L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"))
		return TRUE;

	if (g_config.iexplore && !wcsicmp(TargetProcess, L"C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe"))
		return TRUE;

	if (!_stricmp(our_process_name, "svchost.exe") && wcsstr(our_commandline, L"-k WerSvcGroup"))
		return TRUE;

	if (!g_config.file_of_interest || !g_config.suspend_logging)
		return FALSE;

	for (unsigned int i=0; i<ARRAYSIZE(DontMonitorList); i++)
	{
		if (!wcsicmp(TargetProcess, DontMonitorList[i]))
			return TRUE;
	}

	return FALSE;
}

void CreateProcessHandler(LPWSTR lpApplicationName, LPWSTR lpCommandLine, LPPROCESS_INFORMATION lpProcessInformation)
{
	WCHAR TargetProcess[MAX_PATH];
	struct InjectionInfo *CurrentInjectionInfo;

	if (GetInjectionInfo(lpProcessInformation->dwProcessId))
		return;

	CurrentInjectionInfo = CreateInjectionInfo(lpProcessInformation->dwProcessId);

	if (CurrentInjectionInfo == NULL)
	{
		DebugOutput("CreateProcessHandler: Failed to create injection info for new process %d", lpProcessInformation->dwProcessId);
		return;
	}

	CurrentInjectionInfo->ProcessHandle = lpProcessInformation->hProcess;
	CurrentInjectionInfo->InitialThreadId = lpProcessInformation->dwThreadId;
	CurrentInjectionInfo->ImageBase = (DWORD_PTR)get_process_image_base(lpProcessInformation->hProcess);
	CurrentInjectionInfo->EntryPoint = (DWORD_PTR)NULL;
	CurrentInjectionInfo->ImageDumped = FALSE;

	memset(TargetProcess, 0, MAX_PATH*sizeof(WCHAR));

	if (lpApplicationName)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("CreateProcessHandler: using lpApplicationName: %ws.\n", lpApplicationName);
#endif
		_snwprintf(TargetProcess, MAX_PATH, L"%ws", lpApplicationName);
	}
	else if (lpCommandLine)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("CreateProcessHandler: using lpCommandLine: %ws.\n", lpCommandLine);
#endif
		if (*lpCommandLine == L'\"')
			wcsncpy_s(TargetProcess, MAX_PATH, lpCommandLine+1, (rsize_t)((wcschr(lpCommandLine+1, '\"') - lpCommandLine)-1));
		else
		{
			if (wcschr(lpCommandLine, ' '))
				wcsncpy_s(TargetProcess, MAX_PATH, lpCommandLine, (rsize_t)((wcschr(lpCommandLine, ' ') - lpCommandLine)+1));
			else
				wcsncpy_s(TargetProcess, MAX_PATH, lpCommandLine, wcslen(lpCommandLine)+1);
		}
	}

	CurrentInjectionInfo->DontMonitor = CheckDontMonitorList(TargetProcess);

	if (lpApplicationName || lpCommandLine)
	{
		CapeMetaData->TargetProcess = (char*)malloc(MAX_PATH);
		if (CapeMetaData->TargetProcess)
		{
			WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, (LPCWSTR)TargetProcess, (int)wcslen(TargetProcess)+1, CapeMetaData->TargetProcess, MAX_PATH, NULL, NULL);
			DebugOutput("CreateProcessHandler: Injection info set for new process %d: %s, ImageBase: 0x%p", CurrentInjectionInfo->ProcessId, CapeMetaData->TargetProcess, CurrentInjectionInfo->ImageBase);
		}
		else
			DebugOutput("CreateProcessHandler: Failed to allocate memory for target process name.\n");
	}
	else
		DebugOutput("CreateProcessHandler: Injection info set for new process %d, ImageBase: 0x%p", CurrentInjectionInfo->ProcessId, CurrentInjectionInfo->ImageBase);
}

void OpenProcessHandler(HANDLE ProcessHandle, DWORD Pid)
{
	struct InjectionInfo *CurrentInjectionInfo;
	char DevicePath[MAX_PATH];
	unsigned int PathLength;

	if (Pid == GetCurrentProcessId())
		return;

	CurrentInjectionInfo = GetInjectionInfo(Pid);

	if (CurrentInjectionInfo == NULL)
	{   // First call for this process, create new info
		CurrentInjectionInfo = CreateInjectionInfo(Pid);
		if (CurrentInjectionInfo)
		{
			DebugOutput("OpenProcessHandler: Injection info created for Pid %d, handle 0x%x.\n", Pid, ProcessHandle);

			CurrentInjectionInfo->ProcessHandle = ProcessHandle;
			CurrentInjectionInfo->EntryPoint = (DWORD_PTR)NULL;
			CurrentInjectionInfo->ImageDumped = FALSE;

			CurrentInjectionInfo->ImageBase = (DWORD_PTR)get_process_image_base(ProcessHandle);

			if (CurrentInjectionInfo->ImageBase)
				DebugOutput("OpenProcessHandler: Image base for process %d (handle 0x%x): 0x%p.\n", Pid, ProcessHandle, CurrentInjectionInfo->ImageBase);

			PathLength = GetProcessImageFileName(ProcessHandle, DevicePath, MAX_PATH);

			if (PathLength)
			{
				CapeMetaData->TargetProcess = TranslatePathFromDeviceToLetter(DevicePath);
				if (!CapeMetaData->TargetProcess)
					ErrorOutput("OpenProcessHandler: Error translating target process path");
			}
			else
			{
				CapeMetaData->TargetProcess = (char*)malloc(MAX_PATH);
				if (CapeMetaData->TargetProcess)
					_snprintf(CapeMetaData->TargetProcess, MAX_PATH, "Error obtaining target process name");
				ErrorOutput("OpenProcessHandler: Error obtaining target process name");
			}
		}
		else
			DebugOutput("OpenProcessHandler: Error - cannot create new injection info.\n");
	}
	else if (CurrentInjectionInfo->ImageBase == (DWORD_PTR)NULL)
	{
		CurrentInjectionInfo->ImageBase = (DWORD_PTR)get_process_image_base(ProcessHandle);

		if (CurrentInjectionInfo->ImageBase)
			DebugOutput("OpenProcessHandler: Image base for process %d (handle 0x%x): 0x%p.\n", Pid, ProcessHandle, CurrentInjectionInfo->ImageBase);
	}
}

void MapSectionViewHandler(HANDLE ProcessHandle, HANDLE SectionHandle, PVOID BaseAddress, SIZE_T ViewSize)
{
	struct InjectionInfo *CurrentInjectionInfo;
	PINJECTIONSECTIONVIEW CurrentSectionView;
	char DevicePath[MAX_PATH];
	unsigned int PathLength;

	DWORD Pid = pid_from_process_handle(ProcessHandle);

	if (!Pid)
	{
		ErrorOutput("MapSectionViewHandler: Failed to obtain pid from process handle 0x%x", ProcessHandle);
		CurrentInjectionInfo = GetInjectionInfoFromHandle(ProcessHandle);
		Pid = CurrentInjectionInfo->ProcessId;
	}
	else
		CurrentInjectionInfo = GetInjectionInfo(Pid);

	if (!Pid)
		DebugOutput("MapSectionViewHandler: Failed to find injection info pid from process handle 0x%x.\n", ProcessHandle);

	if (Pid == GetCurrentProcessId())
	{
		CurrentSectionView = GetSectionView(SectionHandle);

		if (!CurrentSectionView)
		{
			CurrentSectionView = AddSectionView(SectionHandle, BaseAddress, ViewSize);
			DebugOutput("MapSectionViewHandler: Added section view with handle 0x%x and local view 0x%p to global list.\n", SectionHandle, BaseAddress);
		}
		else
		{
			if (CurrentSectionView->LocalView != BaseAddress)
			{
				CurrentSectionView->LocalView = BaseAddress;
				CurrentSectionView->ViewSize = ViewSize;
				DebugOutput("MapSectionViewHandler: Updated local view to 0x%p for section view with handle 0x%x.\n", BaseAddress, SectionHandle);
			}
		}
	}
	else if (CurrentInjectionInfo && CurrentInjectionInfo->ProcessId == Pid)
	{
		CurrentInjectionInfo->ProcessHandle = ProcessHandle;
		CurrentSectionView = GetSectionView(SectionHandle);

		if (!CurrentSectionView)
			CurrentSectionView = AddSectionView(SectionHandle, NULL, 0);

		if (CurrentSectionView)
		{
			CurrentSectionView->MapDetected = TRUE;
			CurrentSectionView->TargetProcessId = Pid;
			DebugOutput("MapSectionViewHandler: Added section view with handle 0x%x to existing target process %d.\n", SectionHandle, Pid);
		}
		else
			DebugOutput("MapSectionViewHandler: Error, failed to add section view with handle 0x%x and target process %d.\n", SectionHandle, Pid);
	}
	else if (!CurrentInjectionInfo && Pid != GetCurrentProcessId())
	{
		CurrentInjectionInfo = CreateInjectionInfo(Pid);

		if (CurrentInjectionInfo)
		{
			CurrentInjectionInfo->ProcessHandle = ProcessHandle;
			CurrentInjectionInfo->ProcessId = Pid;
			CurrentInjectionInfo->EntryPoint = (DWORD_PTR)NULL;
			CurrentInjectionInfo->ImageDumped = FALSE;
			CurrentInjectionInfo->ImageBase = (DWORD_PTR)get_process_image_base(ProcessHandle);

			if (CurrentInjectionInfo->ImageBase)
				DebugOutput("MapSectionViewHandler: Image base for process %d (handle 0x%x): 0x%p.\n", Pid, ProcessHandle, CurrentInjectionInfo->ImageBase);

			PathLength = GetProcessImageFileName(ProcessHandle, DevicePath, MAX_PATH);

			if (PathLength)
			{
				CapeMetaData->TargetProcess = TranslatePathFromDeviceToLetter(DevicePath);
				if (!CapeMetaData->TargetProcess)
					ErrorOutput("MapSectionViewHandler: Error translating target process path");
			}
			else
			{
				CapeMetaData->TargetProcess = (char*)malloc(MAX_PATH);
				if (CapeMetaData->TargetProcess)
					_snprintf(CapeMetaData->TargetProcess, MAX_PATH, "Error obtaining target process name");
				ErrorOutput("MapSectionViewHandler: Error obtaining target process name");
			}

			CurrentSectionView = GetSectionView(SectionHandle);

			if (CurrentSectionView)
			{
				CurrentSectionView->MapDetected = TRUE;
				CurrentSectionView->TargetProcessId = Pid;
				DebugOutput("MapSectionViewHandler: Added section view with handle 0x%x to new target process %d.\n", SectionHandle, Pid);
			}
			else
			{
				CurrentSectionView = AddSectionView(SectionHandle, NULL, 0);

				if (CurrentSectionView)
				{
					CurrentSectionView->TargetProcessId = Pid;
					DebugOutput("MapSectionViewHandler: Added section view with handle 0x%x to target process %d.\n", SectionHandle, Pid);
				}
				else
					DebugOutput("MapSectionViewHandler: Error, failed to add section view with handle 0x%x and target process %d.\n", SectionHandle, Pid);
			}
		}
	}
}

void UnmapSectionViewHandler(PVOID BaseAddress)
{
	PINJECTIONSECTIONVIEW CurrentSectionView;

	CurrentSectionView = SectionViewList;

	while (CurrentSectionView)
	{
		if (CurrentSectionView->TargetProcessId && CurrentSectionView->LocalView == BaseAddress)
		{
			DebugOutput("UnmapSectionViewHandler: Attempt to unmap view at 0x%p, dumping.\n", BaseAddress);
			CapeMetaData->TargetPid = CurrentSectionView->TargetProcessId;
			DumpSectionView(CurrentSectionView);
		}

		CurrentSectionView = CurrentSectionView->NextSectionView;
	}
}

void WriteMemoryHandler(HANDLE ProcessHandle, LPVOID BaseAddress, LPCVOID Buffer, SIZE_T NumberOfBytesWritten)
{
	DWORD Pid;
	struct InjectionInfo *CurrentInjectionInfo;
	char DevicePath[MAX_PATH];
	unsigned int PathLength;

	Pid = pid_from_process_handle(ProcessHandle);

	CurrentInjectionInfo = GetInjectionInfo(Pid);

	if (NumberOfBytesWritten == 0)
		return;

	if (!CurrentInjectionInfo && Pid != GetCurrentProcessId())
	{
		CurrentInjectionInfo = CreateInjectionInfo(Pid);

		if (CurrentInjectionInfo == NULL)
		{
			DebugOutput("WriteMemoryHandler: Cannot create new injection info - error.\n");
		}
		else
		{
			CurrentInjectionInfo->ProcessHandle = ProcessHandle;
			CurrentInjectionInfo->ProcessId = Pid;
			CurrentInjectionInfo->EntryPoint = (DWORD_PTR)NULL;
			CurrentInjectionInfo->ImageDumped = FALSE;

			CurrentInjectionInfo->ImageBase = (DWORD_PTR)get_process_image_base(ProcessHandle);

			if (CurrentInjectionInfo->ImageBase)
				DebugOutput("WriteMemoryHandler: Image base for process %d (handle 0x%x): 0x%p.\n", Pid, ProcessHandle, CurrentInjectionInfo->ImageBase);

			PathLength = GetProcessImageFileName(ProcessHandle, DevicePath, MAX_PATH);

			if (PathLength)
			{
				CapeMetaData->TargetProcess = TranslatePathFromDeviceToLetter(DevicePath);
				if (!CapeMetaData->TargetProcess)
					ErrorOutput("WriteMemoryHandler: Error translating target process path");
			}
			else
			{
				CapeMetaData->TargetProcess = (char*)malloc(MAX_PATH);
				if (CapeMetaData->TargetProcess)
					_snprintf(CapeMetaData->TargetProcess, MAX_PATH, "Error obtaining target process name");
				ErrorOutput("WriteMemoryHandler: Error obtaining target process name");
			}
		}
	}

	if (!CurrentInjectionInfo || CurrentInjectionInfo->ProcessId != Pid)
		return;

	// Check if we have a valid DOS and PE header at the beginning of Buffer
	if (IsDisguisedPEHeader((PVOID)Buffer))
	{
		CurrentInjectionInfo->ImageBase = (DWORD_PTR)BaseAddress;
		DebugOutput("WriteMemoryHandler: Executable binary injected into process %d (ImageBase 0x%x)\n", Pid, CurrentInjectionInfo->ImageBase);

		if (CurrentInjectionInfo->ImageDumped == FALSE)
		{
			SetCapeMetaData(INJECTION_PE, Pid, ProcessHandle, NULL);

			CurrentInjectionInfo->ImageDumped = DumpImageInCurrentProcess((PVOID)Buffer);

			if (CurrentInjectionInfo->ImageDumped)
			{
				PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)((char*)Buffer);
				PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((char*)Buffer + pDosHeader->e_lfanew);
				CurrentInjectionInfo->BufferBase = (LPVOID)Buffer;
				CurrentInjectionInfo->BufferSizeOfImage = pNtHeader->OptionalHeader.SizeOfImage;
				DebugOutput("WriteMemoryHandler: Dumped PE image from buffer at 0x%x, SizeOfImage 0x%x.\n", Buffer, CurrentInjectionInfo->BufferSizeOfImage);
			}
			else
			{
				DebugOutput("WriteMemoryHandler: Failed to dump PE image from buffer, attempting raw dump.\n");
				CapeMetaData->DumpType = INJECTION_SHELLCODE;
				CapeMetaData->TargetPid = Pid;
				if (DumpMemory((LPVOID)Buffer, NumberOfBytesWritten))
					DebugOutput("WriteMemoryHandler: Dumped malformed PE image from buffer.");
				else
					DebugOutput("WriteMemoryHandler: Failed to dump malformed PE image from buffer.");
			}
		}
	}
	else
	{
		if (NumberOfBytesWritten <= 0x10)	// We assign some lower limit
			return;

		if (CurrentInjectionInfo->BufferBase && Buffer > CurrentInjectionInfo->BufferBase &&
			Buffer < (LPVOID)((UINT_PTR)CurrentInjectionInfo->BufferBase + CurrentInjectionInfo->BufferSizeOfImage) && CurrentInjectionInfo->ImageDumped == TRUE)
		{
			// Looks like a previously dumped PE image is being written a section at a time to the target process.
			// We don't want to dump these writes.
			DebugOutput("WriteMemoryHandler: injection of section of PE image which has already been dumped.\n");
		}
		else
		{
			DebugOutput("WriteMemoryHandler: shellcode at 0x%p (size 0x%x) injected into process %d.\n", Buffer, NumberOfBytesWritten, Pid);

			// dump injected code/data
			CapeMetaData->DumpType = INJECTION_SHELLCODE;
			CapeMetaData->TargetPid = Pid;
			if (DumpMemory((LPVOID)Buffer, NumberOfBytesWritten))
			{

				DebugOutput("WriteMemoryHandler: Dumped injected code/data from buffer.");
			}
			else
				DebugOutput("WriteMemoryHandler: Failed to dump injected code/data from buffer.");
		}
	}
}

void DuplicationHandler(HANDLE SourceHandle, HANDLE TargetHandle)
{
	struct InjectionInfo *CurrentInjectionInfo;
	PINJECTIONSECTIONVIEW CurrentSectionView;
	char DevicePath[MAX_PATH];
	unsigned int PathLength;

	DWORD Pid = pid_from_process_handle(TargetHandle);

	if (Pid == GetCurrentProcessId())
		return;

	if (!Pid)
	{
		ErrorOutput("DuplicationHandler: Failed to obtain pid from target process handle 0x%x", TargetHandle);
		CurrentInjectionInfo = GetInjectionInfoFromHandle(TargetHandle);
		Pid = CurrentInjectionInfo->ProcessId;
	}
	else
		CurrentInjectionInfo = GetInjectionInfo(Pid);

	if (!Pid)
	{
		DebugOutput("DuplicationHandler: Failed to find pid for target process handle 0x%x in injection info list 0x%x.\n", TargetHandle);
		return;
	}

	CurrentSectionView = GetSectionView(SourceHandle);

	if (!CurrentSectionView)
	{
		DebugOutput("DuplicationHandler: Failed to find section view with source handle 0x%x.\n", SourceHandle);
		return;
	}

	if (CurrentInjectionInfo && CurrentInjectionInfo->ProcessId == Pid)
	{
		CurrentSectionView->TargetProcessId = Pid;
		DebugOutput("DuplicationHandler: Added section view with source handle 0x%x to target process %d.\n", SourceHandle, Pid);
	}
	else if (!CurrentInjectionInfo && Pid != GetCurrentProcessId())
	{
		CurrentInjectionInfo = CreateInjectionInfo(Pid);

		if (CurrentInjectionInfo == NULL)
		{
			DebugOutput("DuplicationHandler: Cannot create new injection info - error.\n");
		}
		else
		{
			CurrentInjectionInfo->ProcessHandle = SourceHandle;
			CurrentInjectionInfo->ProcessId = Pid;
			CurrentInjectionInfo->EntryPoint = (DWORD_PTR)NULL;
			CurrentInjectionInfo->ImageDumped = FALSE;

			CurrentInjectionInfo->ImageBase = (DWORD_PTR)get_process_image_base(SourceHandle);

			if (CurrentInjectionInfo->ImageBase)
				DebugOutput("DuplicationHandler: Image base for process %d (handle 0x%x): 0x%p.\n", Pid, SourceHandle, CurrentInjectionInfo->ImageBase);

			PathLength = GetProcessImageFileName(SourceHandle, DevicePath, MAX_PATH);

			if (PathLength)
			{
				CapeMetaData->TargetProcess = TranslatePathFromDeviceToLetter(DevicePath);
				if (!CapeMetaData->TargetProcess)
					ErrorOutput("DuplicationHandler: Error translating target process path");
			}
			else
			{
				CapeMetaData->TargetProcess = (char*)malloc(MAX_PATH);
				if (CapeMetaData->TargetProcess)
					_snprintf(CapeMetaData->TargetProcess, MAX_PATH, "Error obtaining target process name");
				ErrorOutput("DuplicationHandler: Error obtaining target process name");
			}

			CurrentSectionView = AddSectionView(SourceHandle, NULL, 0);

			if (CurrentSectionView)
			{
				CurrentSectionView->TargetProcessId = Pid;
				DebugOutput("DuplicationHandler: Added section view with handle 0x%x to target process %d.\n", SourceHandle, Pid);
			}
			else
				DebugOutput("DuplicationHandler: Error, failed to add section view with handle 0x%x and target process %d.\n", SourceHandle, Pid);
		}
	}
}

void CreateRemoteThreadHandler(DWORD Pid)
{
	DumpSectionViewsForPid(Pid);
}

void ResumeThreadHandler(DWORD Pid)
{
	DumpSectionViewsForPid(Pid);
}

void ResumeProcessHandler(HANDLE ProcessHandle, DWORD Pid)
{
	DumpSectionViewsForPid(Pid);
}

void TerminateHandler()
{
	PINJECTIONINFO CurrentInjectionInfo = InjectionInfoList;

	while (CurrentInjectionInfo && CurrentInjectionInfo->ProcessHandle && CurrentInjectionInfo->ProcessId)
	{
		DumpSectionViewsForPid(CurrentInjectionInfo->ProcessId);

		CurrentInjectionInfo = CurrentInjectionInfo->NextInjectionInfo;
	}
}

void ProcessMessage(DWORD ProcessId, DWORD ThreadId)
{
	if (ProcessId == GetCurrentProcessId())
		return;

	PINJECTIONINFO CurrentInjectionInfo = GetInjectionInfo(ProcessId);

	if (CurrentInjectionInfo && !ThreadId)
		ThreadId = CurrentInjectionInfo->InitialThreadId;

	if (CurrentInjectionInfo && CurrentInjectionInfo->DontMonitor)
	{
		DebugOutput("ProcessMessage: Skipping monitoring process %d", ProcessId);
		return;
	}

	if (g_config.single_process)
	{
		DebugOutput("ProcessMessage: Skipping monitoring process %d as single-process mode set.", ProcessId);
		return;
	}

	if (g_config.standalone)
	{
		BOOL Wow64Process;
		HANDLE ProcessHandle;
		PROCESS_INFORMATION ProcInfo;
		WCHAR CommandLine[MAX_PATH], LoaderPath[MAX_PATH], Loader[MAX_PATH], MonitorPath[MAX_PATH];
		WCHAR Loader64[] = L"loader_x64.exe";
		WCHAR Loader32[] = L"loader.exe";

		STARTUPINFOEXW StartupInfoEx = {sizeof(StartupInfoEx)};
		wcsncpy(LoaderPath, our_dll_path_w, wcslen(our_dll_path_w)+1);
		PathRemoveFileSpecW(LoaderPath); // remove dll name

		if (!CurrentInjectionInfo || !CurrentInjectionInfo->ProcessHandle)
		{
			ProcessHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
			if (!ProcessHandle)
			{
				DebugOutput("ProcessMessage: Unable to open handle to process %d (standalone mode)", ProcessId);
				return;
			}
		}
		else
			ProcessHandle = CurrentInjectionInfo->ProcessHandle;

		if (!IsWow64Process(ProcessHandle, &Wow64Process))
		{
			ErrorOutput("ProcessMessage: IsWow64Process failed for process %d (standalone mode)", ProcessId);
			return;
		}

		if (Wow64Process)
		{
#ifdef _WIN64
			swprintf(Loader, MAX_PATH, L"%ws\\%ws", LoaderPath, Loader32);
			swprintf(MonitorPath, MAX_PATH, L"%ws\\%ws", LoaderPath, L"capemon.dll");
			swprintf_s(CommandLine, MAX_PATH, L"%s inject %u %u %s", Loader, ProcessId, ThreadId, MonitorPath);
#else
			swprintf(Loader, MAX_PATH, L"%ws\\%ws", LoaderPath, Loader64);
			swprintf_s(CommandLine, MAX_PATH, L"%s inject %u %u %s", Loader, ProcessId, ThreadId, our_dll_path_w);
#endif
		}
		else
		{
#ifdef _WIN64
			swprintf(Loader, MAX_PATH, L"%ws\\%ws", LoaderPath, Loader64);
			swprintf_s(CommandLine, MAX_PATH, L"%s inject %u %u %s", Loader, ProcessId, ThreadId, our_dll_path_w);
#else
			GetSystemInfo(&SystemInfo);
			if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
			{
				swprintf(Loader, MAX_PATH, L"%ws\\%ws", LoaderPath, Loader64);
				swprintf(MonitorPath, MAX_PATH, L"%ws\\%ws", LoaderPath, L"capemon_x64.dll");
				swprintf_s(CommandLine, MAX_PATH, L"%s inject %u %u %s", Loader, ProcessId, ThreadId, MonitorPath);
			}
			else
			{
				swprintf(Loader, MAX_PATH, L"%ws\\%ws", LoaderPath, Loader32);
				swprintf_s(CommandLine, MAX_PATH, L"%s inject %u %u %s", Loader, ProcessId, ThreadId, our_dll_path_w);
			}
#endif
	}
		hook_disable();
		if (CreateProcessW(NULL, CommandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &StartupInfoEx.StartupInfo, &ProcInfo))
		{
			DebugOutput("ProcessMessage: Injected monitor into process %u (standalone mode)", ProcessId);
			CloseHandle(ProcInfo.hProcess);
			CloseHandle(ProcInfo.hThread);
		}
		else
			DebugOutput("ProcessMessage: Failed to inject monitor into process %d (standalone mode)", ProcessId);
		hook_enable();
	}
	else
		pipe("PROCESS:0:%d,%d", ProcessId, ThreadId);
}