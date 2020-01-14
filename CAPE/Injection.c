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
#include <stdio.h>
#include "..\ntapi.h"
#include <psapi.h>
#include <distorm.h>
#include "..\misc.h"
#include "..\hooking.h"
#include "..\log.h"
#include "Debugger.h"
#include "CAPE.h"
#include "Injection.h"

extern _NtMapViewOfSection pNtMapViewOfSection;
extern _NtUnmapViewOfSection pNtUnmapViewOfSection;

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void TestDoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);
extern PVOID get_process_image_base(HANDLE process_handle);

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
            DoOutputDebugString("CreateInjectionInfo: failed to allocate memory for initial injection info list.\n");
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

    if (!CurrentInjectionInfo)
    {
        // We haven't found it in the linked list, so create a new one
        CurrentInjectionInfo = PreviousInjectionInfo;

        CurrentInjectionInfo->NextInjectionInfo = ((struct InjectionInfo*)malloc(sizeof(struct InjectionInfo)));

        if (CurrentInjectionInfo->NextInjectionInfo == NULL)
		{
			DoOutputDebugString("CreateInjectionInfo: Failed to allocate new thread breakpoints.\n");
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
                DoOutputDebugString("DropInjectionInfo: removed injection info for pid %d.\n", CurrentInjectionInfo->ProcessId);
            }
            else if (PreviousInjectionInfo && CurrentInjectionInfo->NextInjectionInfo == NULL)
            {
                PreviousInjectionInfo->NextInjectionInfo = NULL;
                DoOutputDebugString("DropInjectionInfo: removed injection info for pid %d from the end of the section view list.\n", CurrentInjectionInfo->ProcessId);
            }
            else if (!PreviousInjectionInfo)
            {
                InjectionInfoList = NULL;
                DoOutputDebugString("DropInjectionInfo: removed the head of the injection info list for pid %d.\n", CurrentInjectionInfo->ProcessId);
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
        wchar_t *SectionName;

        if (CurrentSectionView->SectionHandle == SectionHandle)
            return CurrentSectionView;

        SectionName = malloc(MAX_UNICODE_PATH * sizeof(wchar_t));

        if (SectionName)
        {
            path_from_handle(SectionHandle, SectionViewList->SectionName, MAX_UNICODE_PATH);
            if ((!wcscmp(CurrentSectionView->SectionName, SectionName)))
            {
                DoOutputDebugString("AddSectionView: New section handle for existing named section %ws.\n", SectionHandle, SectionName);
                free(SectionName);
                return CurrentSectionView;
            }
        free(SectionName);
        }

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
            DoOutputDebugString("AddSectionView: failed to allocate memory for initial section view list.\n");
            return NULL;
        }

        memset(SectionViewList, 0, sizeof(struct InjectionSectionView));

        SectionViewList->SectionHandle = SectionHandle;
        SectionViewList->LocalView = LocalView;
        SectionViewList->ViewSize = ViewSize;
        SectionViewList->SectionName = malloc(MAX_UNICODE_PATH * sizeof(wchar_t));
        if (SectionViewList->SectionName)
            path_from_handle(SectionHandle, SectionViewList->SectionName, MAX_UNICODE_PATH);
	}

	CurrentSectionView = SectionViewList;

    while (CurrentSectionView)
	{
        wchar_t *SectionName;

        if ((CurrentSectionView->SectionHandle) == SectionHandle)
            break;

        SectionName = malloc(MAX_UNICODE_PATH * sizeof(wchar_t));
        if (SectionName)
        {
            path_from_handle(SectionHandle, SectionViewList->SectionName, MAX_UNICODE_PATH);
            if ((!wcscmp(CurrentSectionView->SectionName, SectionName)))
            {
                DoOutputDebugString("AddSectionView: New section handle for existing named section %ws.\n", SectionHandle, SectionName);
                free(SectionName);
                break;
            }
        free(SectionName);
        }

        PreviousSectionView = CurrentSectionView;
        CurrentSectionView = CurrentSectionView->NextSectionView;
	}

    if (!CurrentSectionView)
    {
        // We haven't found it in the linked list, so create a new one
        CurrentSectionView = PreviousSectionView;

        CurrentSectionView->NextSectionView = ((struct InjectionSectionView*)malloc(sizeof(struct InjectionSectionView)));

        if (CurrentSectionView->NextSectionView == NULL)
		{
			DoOutputDebugString("CreateSectionView: Failed to allocate new injection sectionview structure.\n");
			return NULL;
		}

        memset(CurrentSectionView->NextSectionView, 0, sizeof(struct InjectionSectionView));

        CurrentSectionView = CurrentSectionView->NextSectionView;
        CurrentSectionView->SectionHandle = SectionHandle;
        CurrentSectionView->LocalView = LocalView;
        CurrentSectionView->ViewSize = ViewSize;
        CurrentSectionView->SectionName = malloc(MAX_UNICODE_PATH * sizeof(wchar_t));
        path_from_handle(SectionHandle, CurrentSectionView->SectionName, MAX_UNICODE_PATH);
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
        DoOutputDebugString("DropSectionView: failed to obtain initial section view list.\n");
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
                DoOutputDebugString("DropSectionView: removed a view from section view list.\n");
            }
            else if (PreviousSectionView && CurrentSectionView->NextSectionView == NULL)
            {
                PreviousSectionView->NextSectionView = NULL;
                DoOutputDebugString("DropSectionView: removed the view from the end of the section view list.\n");
            }
            else if (!PreviousSectionView)
            {
                SectionViewList = NULL;
                DoOutputDebugString("DropSectionView: removed the head of the section view list.\n");
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
	struct InjectionInfo *CurrentInjectionInfo;
    PINJECTIONSECTIONVIEW CurrentSectionView;
    DWORD BufferSize = MAX_PATH;
    LPVOID PEPointer = NULL;
    BOOL Dumped = FALSE;

    CurrentInjectionInfo = GetInjectionInfo(Pid);

    if (CurrentInjectionInfo == NULL)
    {
        DoOutputDebugString("DumpSectionViewsForPid: No injection info for pid %d.\n", Pid);
        return;
    }

    CurrentSectionView = SectionViewList;

    while (CurrentSectionView)
    {
        if (CurrentSectionView->TargetProcessId == Pid && CurrentSectionView->LocalView)
        {
            DoOutputDebugString("DumpSectionViewsForPid: Shared section view found with pid %d, local address 0x%p.\n", Pid);

            PEPointer = CurrentSectionView->LocalView;

            while (ScanForDisguisedPE(PEPointer, CurrentSectionView->ViewSize - ((DWORD_PTR)PEPointer - (DWORD_PTR)CurrentSectionView->LocalView), &PEPointer))
            {
                DoOutputDebugString("DumpSectionViewsForPid: Dumping PE image from shared section view, local address 0x%p.\n", PEPointer);

                CapeMetaData->DumpType = INJECTION_PE;
                CapeMetaData->TargetPid = Pid;
                CapeMetaData->Address = PEPointer;

                if (DumpImageInCurrentProcess(PEPointer))
                {
                    DoOutputDebugString("DumpSectionViewsForPid: Dumped PE image from shared section view.\n");
                    Dumped = TRUE;
                }
                else
                    DoOutputDebugString("DumpSectionViewsForPid: Failed to dump PE image from shared section view.\n");

                ((BYTE*)PEPointer)++;
            }

            if (Dumped == FALSE)
            {
                DoOutputDebugString("DumpSectionViewsForPid: no PE file found in shared section view, attempting raw dump.\n");

                CapeMetaData->DumpType = INJECTION_SHELLCODE;

                CapeMetaData->TargetPid = Pid;

                if (DumpMemory(CurrentSectionView->LocalView, CurrentSectionView->ViewSize))
                {
                    DoOutputDebugString("DumpSectionViewsForPid: Dumped shared section view.");
                    Dumped = TRUE;
                }
                else
                    DoOutputDebugString("DumpSectionViewsForPid: Failed to dump shared section view.");
            }
        }

        //DropSectionView(CurrentSectionView);

        CurrentSectionView = CurrentSectionView->NextSectionView;
    }

    if (Dumped == FALSE)
        DoOutputDebugString("DumpSectionViewsForPid: no shared section views found for pid %d.\n", Pid);

    return;
}

//**************************************************************************************
void DumpSectionView(PINJECTIONSECTIONVIEW SectionView)
//**************************************************************************************
{
    DWORD BufferSize = MAX_PATH;
    LPVOID PEPointer = NULL;
    BOOL Dumped = FALSE;

    if (!SectionView->LocalView)
    {
        DoOutputDebugString("DumpSectionView: Section view local view address not set.\n");
        return;
    }

    if (!SectionView->TargetProcessId)
    {
        DoOutputDebugString("DumpSectionView: Section with local view 0x%p has no target process - error.\n", SectionView->LocalView);
        return;
    }

    if (!SectionView->ViewSize)
    {
        DoOutputDebugString("DumpSectionView: Section with local view 0x%p has zero commit size - error.\n", SectionView->LocalView);
        return;
    }

    CapeMetaData->DumpType = INJECTION_PE;

    CapeMetaData->TargetPid = SectionView->TargetProcessId;

    CapeMetaData->Address = SectionView->LocalView;

    Dumped = DumpPEsInRange(SectionView->LocalView, SectionView->ViewSize);

    if (Dumped)
        DoOutputDebugString("DumpSectionView: Dumped PE image from shared section view with local address 0x%p.\n", SectionView->LocalView);
    else
    {
        DoOutputDebugString("DumpSectionView: no PE file found in shared section view with local address 0x%p, attempting raw dump.\n", SectionView->LocalView);

        CapeMetaData->DumpType = INJECTION_SHELLCODE;

        if (DumpMemory(SectionView->LocalView, SectionView->ViewSize))
        {
            DoOutputDebugString("DumpSectionView: Dumped shared section view with local address at 0x%p", SectionView->LocalView);
            Dumped = TRUE;
        }
        else
            DoOutputDebugString("DumpSectionView: Failed to dump shared section view with address view at 0x%p", SectionView->LocalView);
    }

    if (Dumped == TRUE)
        DropSectionView(SectionView);
    else
    {   // This may indicate the view has been unmapped already
        // Let's try and remap it.
        SIZE_T ViewSize = 0;
        PVOID BaseAddress = NULL;

        DoOutputDebugString("DumpSectionView: About to remap section with handle 0x%x, size 0x%x.\n", SectionView->SectionHandle, SectionView->ViewSize);

        NTSTATUS ret = pNtMapViewOfSection(SectionView->SectionHandle, NtCurrentProcess(), &BaseAddress, 0, 0, 0, &ViewSize, ViewUnmap, 0, PAGE_READWRITE);

        if (NT_SUCCESS(ret))
        {
            CapeMetaData->DumpType = INJECTION_PE;

            Dumped = DumpPEsInRange(BaseAddress, ViewSize);

            if (Dumped)
                DoOutputDebugString("DumpSectionView: Remapped and dumped section view with handle 0x%x.\n", SectionView->SectionHandle);
            else
            {
                DoOutputDebugString("DumpSectionView: no PE file found in remapped section view with handle 0x%x, attempting raw dump.\n", SectionView->SectionHandle);

                CapeMetaData->DumpType = INJECTION_SHELLCODE;

                CapeMetaData->TargetPid = SectionView->TargetProcessId;

                if (DumpMemory(BaseAddress, ViewSize))
                {
                    DoOutputDebugString("DumpSectionView: Dumped remapped section view with handle 0x%x.\n", SectionView->SectionHandle);
                    Dumped = TRUE;
                }
                else
                    DoOutputDebugString("DumpSectionView: Failed to dump remapped section view with handle 0x%x.\n", SectionView->SectionHandle);
            }

            pNtUnmapViewOfSection(SectionView->SectionHandle, BaseAddress);
        }
        else
            DoOutputDebugString("DumpSectionView: Failed to remap section with handle 0x%x - error code 0x%x\n", SectionView->SectionHandle, ret);
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
        wchar_t *SectionName;

        if (CurrentSectionView->SectionHandle == SectionHandle)
            break;

        SectionName = malloc(MAX_UNICODE_PATH * sizeof(wchar_t));

        if (SectionName)
        {
            path_from_handle(SectionHandle, SectionViewList->SectionName, MAX_UNICODE_PATH);
            if ((!wcscmp(CurrentSectionView->SectionName, SectionName)))
            {
                DoOutputDebugString("DumpSectionViewsForHandle: New section handle for existing named section %ws.\n", SectionHandle, SectionName);
                free(SectionName);
                break;
            }
            free(SectionName);
        }

        CurrentSectionView = CurrentSectionView->NextSectionView;
	}

	if (CurrentSectionView && CurrentSectionView->TargetProcessId)
    {
        DoOutputDebugString("DumpSectionViewsForHandle: Dumping section view at 0x%p for handle 0x%x (target process %d).\n", CurrentSectionView->LocalView, SectionHandle, CurrentSectionView->TargetProcessId);
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
	MEMORY_BASIC_INFORMATION MemoryInfo;
    if (Context && Context->ContextFlags & CONTEXT_CONTROL)
    {
        struct InjectionInfo *CurrentInjectionInfo = GetInjectionInfo(Pid);
#ifdef _WIN64
        if (VirtualQueryEx(CurrentInjectionInfo->ProcessHandle, (PVOID)Context->Rcx, &MemoryInfo, sizeof(MemoryInfo)))
            CurrentInjectionInfo->ImageBase = (DWORD_PTR)MemoryInfo.AllocationBase;
        else
            DoOutputErrorString("SetThreadContextHandler: Failed to query target process memory at address 0x%p", Context->Rcx);

        if (CurrentInjectionInfo && CurrentInjectionInfo->ProcessId == Pid)
            CurrentInjectionInfo->EntryPoint = Context->Rcx - CurrentInjectionInfo->ImageBase;  // rcx holds ep on 64-bit

        if (Context->Rip == (DWORD_PTR)GetProcAddress(GetModuleHandle("ntdll"), "NtMapViewOfSection"))
            DoOutputDebugString("SetThreadContextHandler: Hollow process entry point set to NtMapViewOfSection (process %d).\n", Pid);
        else
            DoOutputDebugString("SetThreadContextHandler: Hollow process entry point reset via NtSetContextThread to 0x%p (process %d).\n", CurrentInjectionInfo->EntryPoint, Pid);
#else
        if (VirtualQueryEx(CurrentInjectionInfo->ProcessHandle, (PVOID)Context->Eax, &MemoryInfo, sizeof(MemoryInfo)))
            CurrentInjectionInfo->ImageBase = (DWORD_PTR)MemoryInfo.AllocationBase;
        else
            DoOutputErrorString("SetThreadContextHandler: Failed to query target process memory at address 0x%x", Context->Eax);

        if (CurrentInjectionInfo && CurrentInjectionInfo->ProcessId == Pid)
            CurrentInjectionInfo->EntryPoint = Context->Eax - CurrentInjectionInfo->ImageBase;  // eax holds ep on 32-bit

        if (Context->Eip == (DWORD)GetProcAddress(GetModuleHandle("ntdll"), "NtMapViewOfSection"))
            DoOutputDebugString("SetThreadContextHandler: Hollow process entry point set to NtMapViewOfSection (process %d).\n", Pid);
        else
            DoOutputDebugString("SetThreadContextHandler: Hollow process entry point reset via NtSetContextThread to 0x%p (process %d).\n", CurrentInjectionInfo->EntryPoint, Pid);
#endif
    }
}

void ResumeThreadHandler(DWORD Pid)
{
    struct InjectionInfo *CurrentInjectionInfo = GetInjectionInfo(Pid);

    if (!CurrentInjectionInfo)
    {
        DoOutputDebugString("ResumeThreadHandler: CurrentInjectionInfo 0x%x (Pid %d).\n", CurrentInjectionInfo, Pid);
        return;
    }

    if (CurrentInjectionInfo->ImageBase && !CurrentInjectionInfo->ImageDumped)
    {
        CapeMetaData->DumpType = INJECTION_PE;
        CapeMetaData->TargetPid = Pid;

        DoOutputDebugString("ResumeThreadHandler: Dumping hollowed process %d, image base 0x%p.\n", Pid, CurrentInjectionInfo->ImageBase);

        CurrentInjectionInfo->ImageDumped = DumpProcess(CurrentInjectionInfo->ProcessHandle, (PVOID)CurrentInjectionInfo->ImageBase, (PVOID)CurrentInjectionInfo->EntryPoint);

        if (CurrentInjectionInfo->ImageDumped)
            DoOutputDebugString("ResumeThreadHandler: Dumped PE image from buffer.\n");
        else
            DoOutputDebugString("ResumeThreadHandler: Failed to dump PE image from buffer.\n");
    }

    DoOutputDebugString("ResumeThreadHandler: Dumping section view for process %d.\n", Pid);

    DumpSectionViewsForPid(Pid);
}

void CreateProcessHandler(LPWSTR lpApplicationName, LPWSTR lpCommandLine, LPPROCESS_INFORMATION lpProcessInformation)
{
    WCHAR TargetProcess[MAX_PATH];
    struct InjectionInfo *CurrentInjectionInfo;

    // Create 'injection info' struct for the newly created process
    CurrentInjectionInfo = CreateInjectionInfo(lpProcessInformation->dwProcessId);

    if (CurrentInjectionInfo == NULL)
    {
        DoOutputDebugString("CreateProcessHandler: Failed to create injection info for new process %d, ImageBase: 0x%p", lpProcessInformation->dwProcessId, CurrentInjectionInfo->ImageBase);
        return;
    }

    CurrentInjectionInfo->ProcessHandle = lpProcessInformation->hProcess;
    CurrentInjectionInfo->ImageBase = (DWORD_PTR)get_process_image_base(lpProcessInformation->hProcess);
    CurrentInjectionInfo->EntryPoint = (DWORD_PTR)NULL;
    CurrentInjectionInfo->ImageDumped = FALSE;

    CapeMetaData->TargetProcess = (char*)malloc(MAX_PATH);
    memset(TargetProcess, 0, MAX_PATH*sizeof(WCHAR));

    if (lpApplicationName)
        _snwprintf(TargetProcess, MAX_PATH, L"%s", lpApplicationName);
    else if (lpCommandLine)
    {
        DoOutputDebugString("CreateProcessHandler: using lpCommandLine: %ws.\n", lpCommandLine);
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

    WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, (LPCWSTR)TargetProcess, (int)wcslen(TargetProcess)+1, CapeMetaData->TargetProcess, MAX_PATH, NULL, NULL);

    DoOutputDebugString("CreateProcessHandler: Injection info set for new process %d, ImageBase: 0x%p", CurrentInjectionInfo->ProcessId, CurrentInjectionInfo->ImageBase);
}

void CreateRemoteThreadHandler(DWORD Pid)
{
    struct InjectionInfo *CurrentInjectionInfo = GetInjectionInfo(Pid);

    if (!CurrentInjectionInfo)
    {
        DoOutputDebugString("CreateRemoteThreadHandler: CurrentInjectionInfo 0x%x (Pid %d).\n", CurrentInjectionInfo, Pid);
        return;
    }

    if (!CurrentInjectionInfo->ImageDumped)
    {
        CapeMetaData->DumpType = INJECTION_PE;
        CapeMetaData->TargetPid = Pid;

        DoOutputDebugString("CreateRemoteThreadHandler: Dumping hollowed process %d, image base 0x%p.\n", Pid, CurrentInjectionInfo->ImageBase);

        CurrentInjectionInfo->ImageDumped = DumpProcess(CurrentInjectionInfo->ProcessHandle, (PVOID)CurrentInjectionInfo->ImageBase, (PVOID)CurrentInjectionInfo->EntryPoint);

        if (CurrentInjectionInfo->ImageDumped)
        {
            DoOutputDebugString("CreateRemoteThreadHandler: Dumped PE image from buffer.\n");
        }
        else
            DoOutputDebugString("CreateRemoteThreadHandler: Failed to dump PE image from buffer.\n");
    }

    DumpSectionViewsForPid(Pid);
}

void OpenProcessHandler(HANDLE ProcessHandle, DWORD Pid)
{
	struct InjectionInfo *CurrentInjectionInfo;
    DWORD BufferSize = MAX_PATH;
    char DevicePath[MAX_PATH];
    unsigned int PathLength;

    CurrentInjectionInfo = GetInjectionInfo(Pid);

    if (CurrentInjectionInfo == NULL)
    {   // First call for this process, create new info
        CurrentInjectionInfo = CreateInjectionInfo(Pid);

        DoOutputDebugString("OpenProcessHandler: Injection info created for Pid %d, handle 0x%x.\n", Pid, ProcessHandle);

        if (CurrentInjectionInfo == NULL)
        {
            DoOutputDebugString("OpenProcessHandler: Error - cannot create new injection info.\n");
        }
        else
        {
            CurrentInjectionInfo->ProcessHandle = ProcessHandle;
            CurrentInjectionInfo->EntryPoint = (DWORD_PTR)NULL;
            CurrentInjectionInfo->ImageDumped = FALSE;
            CapeMetaData->TargetProcess = (char*)malloc(BufferSize);

            CurrentInjectionInfo->ImageBase = (DWORD_PTR)get_process_image_base(ProcessHandle);

            if (CurrentInjectionInfo->ImageBase)
                DoOutputDebugString("OpenProcessHandler: Image base for process %d (handle 0x%x): 0x%p.\n", Pid, ProcessHandle, CurrentInjectionInfo->ImageBase);

            PathLength = GetProcessImageFileName(ProcessHandle, DevicePath, BufferSize);

            if (!PathLength)
            {
                DoOutputErrorString("OpenProcessHandler: Error obtaining target process name");
                _snprintf(CapeMetaData->TargetProcess, BufferSize, "Error obtaining target process name");
            }
            else if (!TranslatePathFromDeviceToLetter(DevicePath, CapeMetaData->TargetProcess, &BufferSize))
                DoOutputErrorString("OpenProcessHandler: Error translating target process path");
        }
    }
    else if (CurrentInjectionInfo->ImageBase == (DWORD_PTR)NULL)
    {
        CurrentInjectionInfo->ImageBase = (DWORD_PTR)get_process_image_base(ProcessHandle);

        if (CurrentInjectionInfo->ImageBase)
            DoOutputDebugString("OpenProcessHandler: Image base for process %d (handle 0x%x): 0x%p.\n", Pid, ProcessHandle, CurrentInjectionInfo->ImageBase);
    }
}

void ResumeProcessHandler(HANDLE ProcessHandle, DWORD Pid)
{
	struct InjectionInfo *CurrentInjectionInfo;

    CurrentInjectionInfo = GetInjectionInfo(Pid);

    if (CurrentInjectionInfo)
    {
        if (CurrentInjectionInfo->ImageBase && CurrentInjectionInfo->ImageDumped == FALSE)
        {
            SetCapeMetaData(INJECTION_PE, Pid, ProcessHandle, NULL);

            DoOutputDebugString("ResumeProcessHandler: Dumping hollowed process %d, image base 0x%p.\n", Pid, CurrentInjectionInfo->ImageBase);

            CurrentInjectionInfo->ImageDumped = DumpProcess(ProcessHandle, (PVOID)CurrentInjectionInfo->ImageBase, (PVOID)CurrentInjectionInfo->EntryPoint);

            if (CurrentInjectionInfo->ImageDumped)
                DoOutputDebugString("ResumeProcessHandler: Dumped PE image from buffer.\n");
            else
                DoOutputDebugString("ResumeProcessHandler: Failed to dump PE image from buffer.\n");
        }

        DumpSectionViewsForPid(Pid);
    }
}

void MapSectionViewHandler(HANDLE ProcessHandle, HANDLE SectionHandle, PVOID BaseAddress, SIZE_T ViewSize)
{
	struct InjectionInfo *CurrentInjectionInfo;
    PINJECTIONSECTIONVIEW CurrentSectionView;
    char DevicePath[MAX_PATH];
    unsigned int PathLength;
    DWORD BufferSize = MAX_PATH;

    DWORD Pid = pid_from_process_handle(ProcessHandle);

    if (!Pid)
    {
        DoOutputErrorString("MapSectionViewHandler: Failed to obtain pid from process handle 0x%x", ProcessHandle);
        CurrentInjectionInfo = GetInjectionInfoFromHandle(ProcessHandle);
        Pid = CurrentInjectionInfo->ProcessId;
    }
    else
        CurrentInjectionInfo = GetInjectionInfo(Pid);

    if (!Pid)
        DoOutputDebugString("MapSectionViewHandler: Failed to find injection info pid from process handle 0x%x.\n", ProcessHandle);

    if (Pid == GetCurrentProcessId())
    {
        CurrentSectionView = GetSectionView(SectionHandle);

        if (!CurrentSectionView)
        {
            CurrentSectionView = AddSectionView(SectionHandle, BaseAddress, ViewSize);
            DoOutputDebugString("MapSectionViewHandler: Added section view with handle 0x%x amd local view 0x%p to global list (%ws).\n", SectionHandle, BaseAddress, CurrentSectionView->SectionName);
        }
        else
        {
            if (CurrentSectionView->LocalView != BaseAddress)
            {
                CurrentSectionView->LocalView = BaseAddress;
                CurrentSectionView->ViewSize = ViewSize;
                DoOutputDebugString("MapSectionViewHandler: Updated local view to 0x%p for section view with handle 0x%x (%ws).\n", BaseAddress, SectionHandle, CurrentSectionView->SectionName);
            }
        }
    }
    else if (CurrentInjectionInfo && CurrentInjectionInfo->ProcessId == Pid)
    {
        CurrentSectionView = AddSectionView(SectionHandle, BaseAddress, ViewSize);

        if (CurrentSectionView)
        {
	        CurrentSectionView->TargetProcessId = Pid;
            DoOutputDebugString("MapSectionViewHandler: Added section view with handle 0x%x to target process %d (%ws).\n", SectionHandle, Pid, CurrentSectionView->SectionName);
        }
        else
        {
            DoOutputDebugString("MapSectionViewHandler: Error, failed to add section view with handle 0x%x and target process %d (%ws).\n", SectionHandle, Pid, CurrentSectionView->SectionName);
        }
    }
    else if (!CurrentInjectionInfo && Pid != GetCurrentProcessId())
    {
        CurrentInjectionInfo = CreateInjectionInfo(Pid);

        if (CurrentInjectionInfo == NULL)
        {
            DoOutputDebugString("MapSectionViewHandler: Cannot create new injection info - error.\n");
        }
        else
        {
            CurrentInjectionInfo->ProcessHandle = ProcessHandle;
            CurrentInjectionInfo->ProcessId = Pid;
            CurrentInjectionInfo->EntryPoint = (DWORD_PTR)NULL;
            CurrentInjectionInfo->ImageDumped = FALSE;
            CapeMetaData->TargetProcess = (char*)malloc(BufferSize);

            CurrentInjectionInfo->ImageBase = (DWORD_PTR)get_process_image_base(ProcessHandle);

            if (CurrentInjectionInfo->ImageBase)
                DoOutputDebugString("MapSectionViewHandler: Image base for process %d (handle 0x%x): 0x%p.\n", Pid, ProcessHandle, CurrentInjectionInfo->ImageBase);

            PathLength = GetProcessImageFileName(ProcessHandle, DevicePath, BufferSize);

            if (!PathLength)
            {
                DoOutputErrorString("MapSectionViewHandler: Error obtaining target process name");
                _snprintf(CapeMetaData->TargetProcess, BufferSize, "Error obtaining target process name");
            }
            else if (!TranslatePathFromDeviceToLetter(DevicePath, CapeMetaData->TargetProcess, &BufferSize))
                DoOutputErrorString("MapSectionViewHandler: Error translating target process path");

            CurrentSectionView = AddSectionView(SectionHandle, BaseAddress, ViewSize);

            if (CurrentSectionView)
            {
                CurrentSectionView->TargetProcessId = Pid;
                DoOutputDebugString("MapSectionViewHandler: Added section view with handle 0x%x to target process %d (%ws).\n", SectionHandle, Pid, CurrentSectionView->SectionName);
            }
            else
                DoOutputDebugString("MapSectionViewHandler: Error, failed to add section view with handle 0x%x and target process %d (%ws).\n", SectionHandle, Pid, CurrentSectionView->SectionName);
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
            DoOutputDebugString("UnmapSectionViewHandler: Attempt to unmap view at 0x%p, dumping.\n", BaseAddress);
            CapeMetaData->DumpType = INJECTION_PE;
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
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    char DevicePath[MAX_PATH];
    unsigned int PathLength;
    DWORD BufferSize = MAX_PATH;

	Pid = pid_from_process_handle(ProcessHandle);

    CurrentInjectionInfo = GetInjectionInfo(Pid);

    if (NumberOfBytesWritten == 0)
        return;

    if (!CurrentInjectionInfo && Pid != GetCurrentProcessId())
    {
        CurrentInjectionInfo = CreateInjectionInfo(Pid);

        if (CurrentInjectionInfo == NULL)
        {
            DoOutputDebugString("WriteMemoryHandler: Cannot create new injection info - error.\n");
        }
        else
        {
            CurrentInjectionInfo->ProcessHandle = ProcessHandle;
            CurrentInjectionInfo->ProcessId = Pid;
            CurrentInjectionInfo->EntryPoint = (DWORD_PTR)NULL;
            CurrentInjectionInfo->ImageDumped = FALSE;
            CapeMetaData->TargetProcess = (char*)malloc(BufferSize);

            CurrentInjectionInfo->ImageBase = (DWORD_PTR)get_process_image_base(ProcessHandle);

            if (CurrentInjectionInfo->ImageBase)
                DoOutputDebugString("WriteMemoryHandler: Image base for process %d (handle 0x%x): 0x%p.\n", Pid, ProcessHandle, CurrentInjectionInfo->ImageBase);

            PathLength = GetProcessImageFileName(ProcessHandle, DevicePath, BufferSize);

            if (!PathLength)
            {
                DoOutputErrorString("WriteMemoryHandler: Error obtaining target process name");
                _snprintf(CapeMetaData->TargetProcess, BufferSize, "Error obtaining target process name");
            }
            else if (!TranslatePathFromDeviceToLetter(DevicePath, CapeMetaData->TargetProcess, &BufferSize))
                DoOutputErrorString("WriteMemoryHandler: Error translating target process path");
        }
    }

    if (CurrentInjectionInfo->ProcessId != Pid)
        return;

    CurrentInjectionInfo->WriteDetected = TRUE;

    // Check if we have a valid DOS and PE header at the beginning of Buffer
    if (IsDisguisedPEHeader((PVOID)Buffer))
    {
        pDosHeader = (PIMAGE_DOS_HEADER)((char*)Buffer);

        pNtHeader = (PIMAGE_NT_HEADERS)((char*)Buffer + pDosHeader->e_lfanew);

        CurrentInjectionInfo->ImageBase = (DWORD_PTR)BaseAddress;

        DoOutputDebugString("WriteMemoryHandler: Executable binary injected into process %d (ImageBase 0x%x)\n", Pid, CurrentInjectionInfo->ImageBase);

        if (CurrentInjectionInfo->ImageDumped == FALSE)
        {
            SetCapeMetaData(INJECTION_PE, Pid, ProcessHandle, NULL);

            CurrentInjectionInfo->ImageDumped = DumpImageInCurrentProcess((PVOID)Buffer);

            if (CurrentInjectionInfo->ImageDumped)
            {
                CurrentInjectionInfo->BufferBase = (LPVOID)Buffer;
                CurrentInjectionInfo->BufferSizeOfImage = pNtHeader->OptionalHeader.SizeOfImage;
                DoOutputDebugString("WriteMemoryHandler: Dumped PE image from buffer at 0x%x, SizeOfImage 0x%x.\n", Buffer, CurrentInjectionInfo->BufferSizeOfImage);
            }
            else
            {
                DoOutputDebugString("WriteMemoryHandler: Failed to dump PE image from buffer, attempting raw dump.\n");

                CapeMetaData->DumpType = INJECTION_SHELLCODE;
                CapeMetaData->TargetPid = Pid;
                if (DumpMemory((LPVOID)Buffer, NumberOfBytesWritten))
                    DoOutputDebugString("WriteMemoryHandler: Dumped malformed PE image from buffer.");
                else
                    DoOutputDebugString("WriteMemoryHandler: Failed to dump malformed PE image from buffer.");
            }
        }
    }
    else
    {
        if (NumberOfBytesWritten > 0x10)    // We assign some lower limit
        {
            if (CurrentInjectionInfo->BufferBase && Buffer > CurrentInjectionInfo->BufferBase &&
                Buffer < (LPVOID)((UINT_PTR)CurrentInjectionInfo->BufferBase + CurrentInjectionInfo->BufferSizeOfImage) && CurrentInjectionInfo->ImageDumped == TRUE)
            {
                // Looks like a previously dumped PE image is being written a section at a time to the target process.
                // We don't want to dump these writes.
                DoOutputDebugString("WriteMemoryHandler: injection of section of PE image which has already been dumped.\n");
            }
            else
            {
                DoOutputDebugString("WriteMemoryHandler: shellcode at 0x%p (size 0x%x) injected into process %d.\n", Buffer, NumberOfBytesWritten, Pid);

                // dump injected code/data
                CapeMetaData->DumpType = INJECTION_SHELLCODE;
                CapeMetaData->TargetPid = Pid;
                if (DumpMemory((LPVOID)Buffer, NumberOfBytesWritten))
                    DoOutputDebugString("WriteMemoryHandler: Dumped injected code/data from buffer.");
                else
                    DoOutputDebugString("WriteMemoryHandler: Failed to dump injected code/data from buffer.");
            }
        }
    }
}

void DuplicationHandler(HANDLE SourceHandle, HANDLE TargetHandle)
{
	struct InjectionInfo *CurrentInjectionInfo;
    PINJECTIONSECTIONVIEW CurrentSectionView;
    char DevicePath[MAX_PATH];
    unsigned int PathLength;
    DWORD BufferSize = MAX_PATH;

    DWORD Pid = pid_from_process_handle(TargetHandle);

    if (Pid == GetCurrentProcessId())
        return;

    if (!Pid)
    {
        DoOutputErrorString("DuplicationHandler: Failed to obtain pid from target process handle 0x%x", TargetHandle);
        CurrentInjectionInfo = GetInjectionInfoFromHandle(TargetHandle);
        Pid = CurrentInjectionInfo->ProcessId;
    }
    else
        CurrentInjectionInfo = GetInjectionInfo(Pid);

    if (!Pid)
    {
        DoOutputDebugString("DuplicationHandler: Failed to find pid for target process handle 0x%x in injection info list 0x%x.\n", TargetHandle);
        return;
    }

    CurrentSectionView = GetSectionView(SourceHandle);

    if (!CurrentSectionView)
    {
        DoOutputDebugString("DuplicationHandler: Failed to find section view with source handle 0x%x.\n", SourceHandle);
        return;
    }

    if (CurrentInjectionInfo && CurrentInjectionInfo->ProcessId == Pid)
    {
        CurrentSectionView->TargetProcessId = Pid;
        DoOutputDebugString("DuplicationHandler: Added section view with source handle 0x%x to target process %d (%ws).\n", SourceHandle, Pid, CurrentSectionView->SectionName);
    }
    else if (!CurrentInjectionInfo && Pid != GetCurrentProcessId())
    {
        CurrentInjectionInfo = CreateInjectionInfo(Pid);

        if (CurrentInjectionInfo == NULL)
        {
            DoOutputDebugString("DuplicationHandler: Cannot create new injection info - error.\n");
        }
        else
        {
            CurrentInjectionInfo->ProcessHandle = SourceHandle;
            CurrentInjectionInfo->ProcessId = Pid;
            CurrentInjectionInfo->EntryPoint = (DWORD_PTR)NULL;
            CurrentInjectionInfo->ImageDumped = FALSE;
            CapeMetaData->TargetProcess = (char*)malloc(BufferSize);

            CurrentInjectionInfo->ImageBase = (DWORD_PTR)get_process_image_base(SourceHandle);

            if (CurrentInjectionInfo->ImageBase)
                DoOutputDebugString("DuplicationHandler: Image base for process %d (handle 0x%x): 0x%p.\n", Pid, SourceHandle, CurrentInjectionInfo->ImageBase);

            PathLength = GetProcessImageFileName(SourceHandle, DevicePath, BufferSize);

            if (!PathLength)
            {
                DoOutputErrorString("DuplicationHandler: Error obtaining target process name");
                _snprintf(CapeMetaData->TargetProcess, BufferSize, "Error obtaining target process name");
            }
            else if (!TranslatePathFromDeviceToLetter(DevicePath, CapeMetaData->TargetProcess, &BufferSize))
                DoOutputErrorString("DuplicationHandler: Error translating target process path");

            CurrentSectionView = AddSectionView(SourceHandle, NULL, 0);

            if (CurrentSectionView)
            {
                CurrentSectionView->TargetProcessId = Pid;
                DoOutputDebugString("DuplicationHandler: Added section view with handle 0x%x to target process %d (%ws).\n", SourceHandle, Pid, CurrentSectionView->SectionName);
            }
            else
                DoOutputDebugString("DuplicationHandler: Error, failed to add section view with handle 0x%x and target process %d (%ws).\n", SourceHandle, Pid, CurrentSectionView->SectionName);
        }
    }
}

void TerminateHandler()
{
    PINJECTIONINFO CurrentInjectionInfo = InjectionInfoList;

	while (CurrentInjectionInfo && CurrentInjectionInfo->ProcessHandle && CurrentInjectionInfo->ImageBase && CurrentInjectionInfo->ProcessId)
	{
        if (!CurrentInjectionInfo->ImageDumped)
        {
            CapeMetaData->DumpType = INJECTION_PE;
            CapeMetaData->TargetPid = CurrentInjectionInfo->ProcessId;

            DoOutputDebugString("TerminateHandler: Dumping hollowed process %d, image base 0x%p.\n", CurrentInjectionInfo->ProcessId, CurrentInjectionInfo->ImageBase);

            CurrentInjectionInfo->ImageDumped = DumpProcess(CurrentInjectionInfo->ProcessHandle, (PVOID)CurrentInjectionInfo->ImageBase, (PVOID)CurrentInjectionInfo->EntryPoint);

            if (CurrentInjectionInfo->ImageDumped)
                DoOutputDebugString("TerminateHandler: Dumped PE image from buffer.\n");
            else
                DoOutputDebugString("TerminateHandler: Failed to dump PE image from buffer.\n");
        }

        CurrentInjectionInfo = CurrentInjectionInfo->NextInjectionInfo;
	}
}
