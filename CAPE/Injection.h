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
    HANDLE                          SectionHandle;
    PVOID                           LocalView;
    SIZE_T                          ViewSize;
    int                             TargetProcessId;
    wchar_t                         *SectionName;
    struct InjectionSectionView     *NextSectionView;
} INJECTIONSECTIONVIEW, *PINJECTIONSECTIONVIEW;

PINJECTIONSECTIONVIEW AddSectionView(HANDLE SectionHandle, PVOID LocalView, SIZE_T ViewSize);
PINJECTIONSECTIONVIEW GetSectionView(HANDLE SectionHandle);
BOOL DropSectionView(PINJECTIONSECTIONVIEW SectionView);
void DumpSectionViewsForPid(DWORD Pid);
void DumpSectionView(PINJECTIONSECTIONVIEW SectionView);

typedef struct InjectionInfo
{
    int                         ProcessId;
	HANDLE	                    ProcessHandle;
    DWORD_PTR                   ImageBase;
    DWORD_PTR                   EntryPoint;
    BOOL                        WriteDetected;
    BOOL                        ImageDumped;
    LPVOID                      BufferBase;
    LPVOID                      StackPointer;
    unsigned int                BufferSizeOfImage;
    HANDLE                      SectionHandle;
//    struct InjectionSectionView *SectionViewList;
    struct InjectionInfo        *NextInjectionInfo;
} INJECTIONINFO, *PINJECTIONINFO;

struct InjectionInfo *InjectionInfoList;

PINJECTIONINFO GetInjectionInfo(DWORD ProcessId);
PINJECTIONINFO GetInjectionInfoFromHandle(HANDLE ProcessHandle);
PINJECTIONINFO CreateInjectionInfo(DWORD ProcessId);
BOOL DropInjectionInfo(HANDLE ProcessHandle);

struct InjectionSectionView *SectionViewList;
