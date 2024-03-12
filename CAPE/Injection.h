/*
CAPE - Config And Payload Extraction
Copyright(C) 2015-2018 Context Information Security. (kevin.oreilly@contextis.com)

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
#define MAX_UNICODE_PATH 32768

void DumpSectionViewsForPid(DWORD Pid);
void DumpSectionViewsForHandle(HANDLE SectionHandle);

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;

typedef struct InjectionSectionView
{
	HANDLE	SectionHandle;
	PVOID	LocalView;
	SIZE_T	ViewSize;
	int		TargetProcessId;
	BOOL	MapDetected;
	struct InjectionSectionView *NextSectionView;
} INJECTIONSECTIONVIEW, *PINJECTIONSECTIONVIEW;

PINJECTIONSECTIONVIEW AddSectionView(HANDLE SectionHandle, PVOID LocalView, SIZE_T ViewSize);
PINJECTIONSECTIONVIEW GetSectionView(HANDLE SectionHandle);
BOOL DropSectionView(PINJECTIONSECTIONVIEW SectionView);
void DumpSectionViewsForPid(DWORD Pid);
void DumpSectionView(PINJECTIONSECTIONVIEW SectionView);

typedef struct InjectionInfo
{
	DWORD			ProcessId;
	HANDLE			ProcessHandle;
	DWORD			InitialThreadId;
	DWORD_PTR		ImageBase;
	DWORD_PTR		EntryPoint;
	BOOL			ImageDumped;
	LPVOID			BufferBase;
	LPVOID			StackPointer;
	unsigned int	BufferSizeOfImage;
	HANDLE			SectionHandle;
	BOOL			DontMonitor;
//	struct InjectionSectionView *SectionViewList;
	struct InjectionInfo *NextInjectionInfo;
} INJECTIONINFO, *PINJECTIONINFO;

struct InjectionInfo *InjectionInfoList;
struct InjectionSectionView *SectionViewList;

PINJECTIONINFO GetInjectionInfo(DWORD ProcessId);
PINJECTIONINFO GetInjectionInfoFromHandle(HANDLE ProcessHandle);
PINJECTIONINFO CreateInjectionInfo(DWORD ProcessId);
BOOL DropInjectionInfo(HANDLE ProcessHandle);
void CreateProcessHandler(LPWSTR lpApplicationName, LPWSTR lpCommandLine, LPPROCESS_INFORMATION lpProcessInformation);
PCHAR OpenProcessHandler(HANDLE ProcessHandle, DWORD Pid);
void ResumeProcessHandler(HANDLE ProcessHandle, DWORD Pid);
void MapSectionViewHandler(HANDLE ProcessHandle, HANDLE SectionHandle, PVOID BaseAddress, SIZE_T ViewSize);
void UnmapSectionViewHandler(PVOID BaseAddress);
void WriteMemoryHandler(HANDLE ProcessHandle, LPVOID BaseAddress, LPCVOID Buffer, SIZE_T NumberOfBytesWritten);
void TerminateHandler();
