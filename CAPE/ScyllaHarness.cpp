/*
CAPE - Config And Payload Extraction
Copyright(C) 2015 - 2018 Context Information Security. (kevin.oreilly@contextis.com)

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
#include "Scylla\PeParser.h"
#include "Scylla\ProcessAccessHelp.h"
#include "Scylla\NativeWinApi.h"
#include "Scylla\IATSearch.h"
#include "Scylla\ImportRebuilder.h"
#include "Scylla\ImportsHandling.h"

typedef unsigned __int64 QWORD;

#define USE_PE_HEADER_FROM_DISK FALSE
#define SCAN_DIRECT_IMPORTS FALSE
#define FIX_DIRECT_IMPORTS_NORMAL FALSE
#define FIX_DIRECT_IMPORTS_UNIVERSAL FALSE
#define CREATE_NEW_IAT_IN_SECTION FALSE
#define OFT_SUPPORT FALSE

#define	PE_HEADER_LIMIT 0x200
#define CAPE_OUTPUT_FILE "CapeOutput.bin"
//#define DEBUG_COMMENTS

extern "C" void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern "C" void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);
extern "C" int ScanForNonZero(LPVOID Buffer, unsigned int Size);
extern "C" PVOID GetAllocationBase(PVOID Address);
extern "C" int IsDisguisedPEHeader(LPVOID Buffer);

extern char CapeOutputPath[MAX_PATH];

//**************************************************************************************
void ScyllaInitCurrentProcess()
//**************************************************************************************
{
	ProcessAccessHelp::ownModuleList.clear();

	NativeWinApi::initialize();

	ProcessAccessHelp::setCurrentProcessAsTarget();

	ProcessAccessHelp::getProcessModules(GetCurrentProcess(), ProcessAccessHelp::ownModuleList);
}

//**************************************************************************************
extern "C" DWORD_PTR GetEntryPointVA(DWORD_PTR modBase)
//**************************************************************************************
{
    DWORD_PTR EntryPointVA;

    PeParser * peFile = 0;

	ScyllaInitCurrentProcess();

    peFile = new PeParser((DWORD_PTR)modBase, true);

    EntryPointVA = peFile->getEntryPoint() + (DWORD_PTR)modBase;

    delete peFile;

	return EntryPointVA;
}

//**************************************************************************************
extern "C" DWORD_PTR FileOffsetToVA(DWORD_PTR modBase, DWORD_PTR dwOffset)
//**************************************************************************************
{
    DWORD_PTR Test;
    PeParser * peFile = 0;

	ScyllaInitCurrentProcess();

    peFile = new PeParser(modBase, true);

    if (peFile->isValidPeFile())
    {
        //return peFile->convertOffsetToRVAVector(dwOffset) + modBase;
        Test = peFile->convertOffsetToRVAVector(dwOffset) + modBase;

        DoOutputDebugString("FileOffsetToVA: Debug - VA = 0x%p.\n", Test);

        return Test;
    }
    else return NULL;
}

//**************************************************************************************
extern "C" int ScyllaDumpCurrentProcess(DWORD_PTR NewOEP)
//**************************************************************************************
{
	DWORD_PTR entrypoint = 0;
	PeParser * peFile = 0;
    DWORD_PTR ModuleBase;

    ModuleBase = (DWORD)(ULONG_PTR)GetModuleHandle(NULL);
	ScyllaInitCurrentProcess();

    DoOutputDebugString("DumpCurrentProcess: Instantiating PeParser with address: 0x%p.\n", ModuleBase);

    peFile = new PeParser(ModuleBase, TRUE);

    if (peFile->isValidPeFile())
    {
        if (NewOEP)
            entrypoint = NewOEP;
        else
            entrypoint = peFile->getEntryPoint() + ModuleBase;

        DoOutputDebugString("DumpCurrentProcess: Module entry point VA is 0x%p.\n", entrypoint);

        if (peFile->dumpProcess(ModuleBase, entrypoint, NULL))
        {
            DoOutputDebugString("DumpCurrentProcess: Module image dump success.\n");
        }
        else
        {
            DoOutputDebugString("DumpCurrentProcess: Error - Cannot dump image.\n");
            delete peFile;
            return 0;
        }
    }
    else
    {
        DoOutputDebugString("DumpCurrentProcess: Invalid PE file or invalid PE header.\n");
        delete peFile;
        return 0;
    }

    delete peFile;

    return 1;
}

//**************************************************************************************
void ScyllaInit(HANDLE hProcess)
//**************************************************************************************
{
	ProcessAccessHelp::ownModuleList.clear();

	NativeWinApi::initialize();

	ProcessAccessHelp::hProcess = hProcess;

    ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);
}

//**************************************************************************************
extern "C" int ScyllaDumpProcess(HANDLE hProcess, DWORD_PTR ModuleBase, DWORD_PTR NewOEP)
//**************************************************************************************
{
	SIZE_T SectionBasedSizeOfImage;
	PeParser *peFile = 0;
	DWORD_PTR entrypoint = NULL;

	ScyllaInit(hProcess);

    DoOutputDebugString("DumpProcess: Instantiating PeParser with address: 0x%p.\n", ModuleBase);

    peFile = new PeParser(ModuleBase, TRUE);

    if (peFile->isValidPeFile())
    {
        if (NewOEP)
            entrypoint = NewOEP;
        else
            entrypoint = peFile->getEntryPoint();

        SectionBasedSizeOfImage = (SIZE_T)peFile->getSectionHeaderBasedSizeOfImage();

        if ((SIZE_T)entrypoint >= SectionBasedSizeOfImage)
        {
            DoOutputDebugString("DumpProcess: Error - entry point too big: 0x%x, ignoring.\n", entrypoint);
            entrypoint = NULL;
        }
        else
        {
            DoOutputDebugString("DumpProcess: Module entry point VA is 0x%p.\n", entrypoint);
            entrypoint = entrypoint + (DWORD_PTR)ModuleBase;
        }

        if (peFile->dumpProcess(ModuleBase, entrypoint, NULL))
            DoOutputDebugString("DumpProcess: Module image dump success - dump size 0x%x.\n", peFile->dumpSize);
        else
            DoOutputDebugString("DumpProcess: Failed to dump image at 0x%p.\n", ModuleBase);
    }
    else
    {
        PBYTE PEImage;
        PIMAGE_NT_HEADERS pNtHeader;
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ModuleBase;

        if (IsDisguisedPEHeader((LPVOID)ModuleBase) && *(WORD*)pDosHeader != IMAGE_DOS_SIGNATURE || (*(DWORD*)((BYTE*)pDosHeader + pDosHeader->e_lfanew) != IMAGE_NT_SIGNATURE))
        {
            MEMORY_BASIC_INFORMATION MemInfo;

            DoOutputDebugString("DumpProcess: Disguised PE image (bad MZ and/or PE headers) at 0x%p.\n", ModuleBase);

            if (!VirtualQuery((LPVOID)ModuleBase, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
            {
                DoOutputErrorString("DumpProcess: unable to query memory address 0x%p", ModuleBase);
                goto fail;
            }

            PEImage = (BYTE*)calloc(MemInfo.RegionSize, sizeof(BYTE));
            memcpy(PEImage, MemInfo.BaseAddress, MemInfo.RegionSize);

            if (!pDosHeader->e_lfanew)
            {
                // In case the header until and including 'PE' has been zeroed
                WORD* MachineProbe = (WORD*)&pDosHeader->e_lfanew;
                while ((PUCHAR)MachineProbe < (PUCHAR)pDosHeader + (PE_HEADER_LIMIT - offsetof(IMAGE_DOS_HEADER, e_lfanew)))
                {
                    if (*MachineProbe == IMAGE_FILE_MACHINE_I386 || *MachineProbe == IMAGE_FILE_MACHINE_AMD64)
                    {
                        if ((PUCHAR)MachineProbe > (PUCHAR)pDosHeader + 3)
                            pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)MachineProbe - 4);
                    }
                    MachineProbe += sizeof(WORD);
                }

                if (pNtHeader)
                    pDosHeader->e_lfanew = (LONG)((PUCHAR)pNtHeader - (PUCHAR)pDosHeader);
            }

            if (!pDosHeader->e_lfanew)
            {
                // In case the header until and including 'PE' is missing
                pNtHeader = NULL;
                WORD* MachineProbe = (WORD*)pDosHeader;
                while ((PUCHAR)MachineProbe < (PUCHAR)pDosHeader + (PE_HEADER_LIMIT - offsetof(IMAGE_DOS_HEADER, e_lfanew)))
                {
                    if (*MachineProbe == IMAGE_FILE_MACHINE_I386 || *MachineProbe == IMAGE_FILE_MACHINE_AMD64)
                    {
                        if ((PUCHAR)MachineProbe >= (PUCHAR)pDosHeader + 4)
                        {
                            pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)MachineProbe - 4);
                            //break;
                        }
                    }
                    MachineProbe += sizeof(WORD);

                    if (pNtHeader && (PUCHAR)pNtHeader == (PUCHAR)pDosHeader && pNtHeader->OptionalHeader.SizeOfHeaders)
                    {
                        SIZE_T HeaderShift = sizeof(IMAGE_DOS_HEADER);
                        memmove(PEImage + HeaderShift, PEImage, pNtHeader->OptionalHeader.SizeOfHeaders - HeaderShift);
                        memset(PEImage, 0, HeaderShift);
                        pDosHeader = (PIMAGE_DOS_HEADER)PEImage;
                        pNtHeader = (PIMAGE_NT_HEADERS)(PEImage + HeaderShift);
                        pDosHeader->e_lfanew = (LONG)((PUCHAR)pNtHeader - (PUCHAR)pDosHeader);
                        DoOutputDebugString("DumpProcess: pNtHeader moved from 0x%x to 0x%x, e_lfanew 0x%x\n", pDosHeader, pNtHeader, pDosHeader->e_lfanew);
                    }
                }
            }

            peFile = new PeParser((char*)PEImage, TRUE);

            if (peFile->isValidPeFile())
            {
                if (NewOEP)
                    entrypoint = NewOEP;
                else
                    entrypoint = peFile->getEntryPoint();

                SectionBasedSizeOfImage = (SIZE_T)peFile->getSectionHeaderBasedSizeOfImage();

                if ((SIZE_T)entrypoint >= SectionBasedSizeOfImage)
                {
                    DoOutputDebugString("DumpProcess: Error - entry point too big: 0x%x, ignoring.\n", entrypoint);
                    entrypoint = NULL;
                }
                else
                {
                    DoOutputDebugString("DumpProcess: Module entry point VA is 0x%p.\n", entrypoint);
                    entrypoint = entrypoint + (DWORD_PTR)ModuleBase;
                }

                if (peFile->dumpProcess(ModuleBase, entrypoint, NULL))
                    DoOutputDebugString("DumpProcess: Module image dump success - dump size 0x%x.\n", peFile->dumpSize);
            }

        }
        else
        {
            DoOutputDebugString("DumpProcess: Invalid PE file or invalid PE header.\n");
            goto fail;
        }
    }

    delete peFile;

    return 1;
fail:
    delete peFile;

    return 0;
}

//**************************************************************************************
extern "C" unsigned int ScyllaDumpProcessToFileHandle(HANDLE hProcess, DWORD_PTR ModuleBase, DWORD_PTR NewOEP, HANDLE FileHandle)
//**************************************************************************************
{
	unsigned int BytesWritten = 0;
    SIZE_T SectionBasedSizeOfImage;
	PeParser * peFile = 0;
	DWORD_PTR entrypoint = NULL;

	ScyllaInit(hProcess);

    DoOutputDebugString("DumpProcess: Instantiating PeParser with address: 0x%p.\n", ModuleBase);

    peFile = new PeParser(ModuleBase, TRUE);

    if (peFile->isValidPeFile())
    {
        if (NewOEP)
            entrypoint = NewOEP;
        else
            entrypoint = peFile->getEntryPoint();

        SectionBasedSizeOfImage = (SIZE_T)peFile->getSectionHeaderBasedSizeOfImage();

        if ((SIZE_T)entrypoint >= SectionBasedSizeOfImage)
        {
            DoOutputDebugString("DumpProcess: Error - entry point too big: 0x%x, ignoring.\n", entrypoint);
            entrypoint = NULL;
        }
        else
        {
            DoOutputDebugString("DumpProcess: Module entry point VA is 0x%p.\n", entrypoint);
            entrypoint = entrypoint + (DWORD_PTR)ModuleBase;
        }

        if (peFile->dumpProcess(ModuleBase, entrypoint, NULL))
        {
            BytesWritten = peFile->dumpSize;
            DoOutputDebugString("DumpProcess: Module image dump success - dump size 0x%x.\n", BytesWritten);
        }
        else
        {
            DoOutputDebugString("DumpProcess: Error - Cannot dump image.\n");
            delete peFile;
            return 0;
        }
    }
    else
    {
        DoOutputDebugString("DumpProcess: Invalid PE file or invalid PE header.\n");
        delete peFile;
        return 0;
    }

    delete peFile;

    return BytesWritten;
}

//**************************************************************************************
DWORD SafeGetDword(PVOID Address)
//**************************************************************************************
{
    DWORD RetVal = NULL;

    __try
    {
        RetVal = *(DWORD*)Address;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DoOutputDebugString("SafeGetDword: Exception occured reading memory address 0x%p\n", Address);
        return NULL;
    }

    return RetVal;
}

//**************************************************************************************
extern "C" int ScyllaDumpPE(DWORD_PTR Buffer)
//**************************************************************************************
{
	DWORD_PTR PointerToLastSection, entrypoint = 0;
	PeParser * peFile = 0;
    unsigned int SizeOfLastSection, NumberOfSections = 0;

	NativeWinApi::initialize();

	ProcessAccessHelp::setCurrentProcessAsTarget();

    DoOutputDebugString("DumpPE: Instantiating PeParser with address: 0x%p.\n", Buffer);

    peFile = new PeParser((DWORD_PTR)Buffer, TRUE);

    if (peFile->isValidPeFile())
    {
        NumberOfSections = peFile->getNumberOfSections();

        if (NumberOfSections == 0)
        {
            DoOutputDebugString("DumpPE: no sections in PE image, ignoring.\n");
            return 0;
        }

        PointerToLastSection = SafeGetDword(&(peFile->listPeSection[NumberOfSections - 1].sectionHeader.PointerToRawData));

        if (!PointerToLastSection)
        {
            DoOutputDebugString("DumpPE: failed to obtain pointer to last section.\n");
            return 0;
        }

        PointerToLastSection += (DWORD_PTR)Buffer;

        SizeOfLastSection = SafeGetDword(&(peFile->listPeSection[NumberOfSections - 1].sectionHeader.SizeOfRawData));

        if (!SizeOfLastSection)
        {
            DoOutputDebugString("DumpPE: failed to obtain size of last section.\n");
            return 0;
        }

        if (!ScanForNonZero((LPVOID)PointerToLastSection, SizeOfLastSection))
        {
            DoOutputDebugString("DumpPE: Empty or inaccessible last section, file image seems incomplete (from 0x%p to 0x%p).\n", PointerToLastSection, (DWORD_PTR)PointerToLastSection + SizeOfLastSection);
            return 0;
        }

        entrypoint = peFile->getEntryPoint();

        if (peFile->saveCompletePeToDisk(NULL))
        {
            DoOutputDebugString("DumpPE: PE file in memory dumped successfully - dump size 0x%x.\n", peFile->dumpSize);
        }
        else
        {
            DoOutputDebugString("DumpPE: Error: Cannot dump PE file from memory.\n");
            delete peFile;
            return 0;
        }
    }
    else
    {
        DoOutputDebugString("DumpPE: Error: Invalid PE file or invalid PE header.\n");
        delete peFile;
        return 0;
    }

    delete peFile;

    return 1;
}

//**************************************************************************************
extern "C" int ScyllaDumpPEToFileHandle(DWORD_PTR Buffer, HANDLE FileHandle)
//**************************************************************************************
{
	DWORD_PTR PointerToLastSection, entrypoint = 0;
	PeParser * peFile = 0;
    unsigned int SizeOfLastSection, NumberOfSections = 0;

	NativeWinApi::initialize();

	ProcessAccessHelp::setCurrentProcessAsTarget();

    DoOutputDebugString("DumpPEToFileHandle: Instantiating PeParser with address: 0x%p.\n", Buffer);

    peFile = new PeParser((DWORD_PTR)Buffer, TRUE);

    if (peFile->isValidPeFile())
    {
        NumberOfSections = peFile->getNumberOfSections();

        if (NumberOfSections == 0)
        {
            DoOutputDebugString("DumpPEToFileHandle: no sections in PE image, ignoring.\n");
            return 0;
        }

        PointerToLastSection = SafeGetDword(&(peFile->listPeSection[NumberOfSections - 1].sectionHeader.PointerToRawData));

        if (!PointerToLastSection)
        {
            DoOutputDebugString("DumpPEToFileHandle: failed to obtain pointer to last section.\n");
            return 0;
        }

        PointerToLastSection += (DWORD_PTR)Buffer;

        SizeOfLastSection = SafeGetDword(&(peFile->listPeSection[NumberOfSections - 1].sectionHeader.SizeOfRawData));

        if (!SizeOfLastSection)
        {
            DoOutputDebugString("DumpPEToFileHandle: failed to obtain size of last section.\n");
            return 0;
        }

        if (!ScanForNonZero((LPVOID)PointerToLastSection, SizeOfLastSection))
        {
            DoOutputDebugString("DumpPEToFileHandle: Empty or inaccessible last section, file image seems incomplete (from 0x%p to 0x%p).\n", PointerToLastSection, (DWORD_PTR)PointerToLastSection + SizeOfLastSection);
            return 0;
        }

        entrypoint = peFile->getEntryPoint();

        if (peFile->saveCompletePeToHandle(FileHandle))
        {
            DoOutputDebugString("DumpPEToFileHandle: PE file in memory dumped successfully - dump size 0x%x.\n", peFile->dumpSize);
        }
        else
        {
            DoOutputDebugString("DumpPEToFileHandle: Error: Cannot dump PE file from memory.\n");
            delete peFile;
            return 0;
        }
    }
    else
    {
        DoOutputDebugString("DumpPEToFileHandle: Error: Invalid PE file or invalid PE header.\n");
        delete peFile;
        return 0;
    }

    delete peFile;

    return 1;
}

//**************************************************************************************
extern "C" int LooksLikeSectionBoundary(DWORD_PTR Buffer)
//**************************************************************************************
{
    __try
    {
        if
        (
            (*(DWORD*)((BYTE*)Buffer - 4) == 0) &&          // end of previous section has zeros
            (*(DWORD*)((BYTE*)Buffer) != 0)                 // beginning of section is non-zero
        )
        {
#ifdef DEBUG_COMMENTS
            DoOutputDebugString("LooksLikeSectionBoundary: Yes - end of previous candidate section zero, beginning of candidate section at 0x%p non-zero.\n", Buffer);
#endif
            return 1;
        }
        else
        {
#ifdef DEBUG_COMMENTS
            if (*(DWORD*)((BYTE*)Buffer - 4) != 0)
                DoOutputDebugString("LooksLikeSectionBoundary: No - end of previous candidate section 0x%p not zero.\n", Buffer);

            if (*(DWORD*)((BYTE*)Buffer) == 0)
                DoOutputDebugString("LooksLikeSectionBoundary: No - beginning of candidate section 0x%p zero.\n", Buffer);
#endif
            return 0;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DoOutputDebugString("LooksLikeSectionBoundary: Exception occured reading around suspected boundary at 0x%p\n", Buffer);
        return -1;
    }
}

//**************************************************************************************
extern "C" SIZE_T GetPESize(PVOID Buffer)
//**************************************************************************************
{
	PeParser * peFile = 0;
    unsigned int NumberOfSections = 0;
    SIZE_T SectionBasedFileSize, SectionBasedImageSize;

	NativeWinApi::initialize();

	ProcessAccessHelp::setCurrentProcessAsTarget();

    peFile = new PeParser((DWORD_PTR)Buffer, TRUE);

    NumberOfSections = peFile->getNumberOfSections();
    SectionBasedFileSize = (SIZE_T)peFile->getSectionHeaderBasedFileSize();
    SectionBasedImageSize = (SIZE_T)peFile->getSectionHeaderBasedSizeOfImage();

#ifdef DEBUG_COMMENTS
    DoOutputDebugString("GetPESize: NumberOfSections %d, SectionBasedFileSize 0x%x.\n", NumberOfSections, SectionBasedFileSize);
#endif
    if (NumberOfSections == 0)
    // makes no difference in this case
    {
#ifdef DEBUG_COMMENTS
        DoOutputDebugString("GetPESize: zero sections, therefore meaningless.\n");
#endif
        delete peFile;
        return SectionBasedFileSize;
    }

    for (unsigned int SectionIndex = 0; SectionIndex < NumberOfSections; SectionIndex++)
    {
#ifdef DEBUG_COMMENTS
        DoOutputDebugString
        (
            "GetPESize: Section %d, PointerToRawData 0x%x, VirtualAddress 0x%x, SizeOfRawData 0x%x, VirtualSize 0x%x.\n",
            SectionIndex+1,
            peFile->listPeSection[SectionIndex].sectionHeader.PointerToRawData,
            peFile->listPeSection[SectionIndex].sectionHeader.VirtualAddress,
            peFile->listPeSection[SectionIndex].sectionHeader.SizeOfRawData,
            peFile->listPeSection[SectionIndex].sectionHeader.Misc.VirtualSize
        );
#endif
        if (peFile->listPeSection[SectionIndex].sectionHeader.PointerToRawData != peFile->listPeSection[SectionIndex].sectionHeader.VirtualAddress)
        {
            if (LooksLikeSectionBoundary((DWORD_PTR)Buffer + peFile->listPeSection[SectionIndex].sectionHeader.PointerToRawData))
            {
#ifdef DEBUG_COMMENTS
                DoOutputDebugString("GetPESize: Found what looks like a 'raw' section boundary - image looks raw.\n");
#endif
                delete peFile;
                return SectionBasedFileSize;
            }
            else if (LooksLikeSectionBoundary((DWORD_PTR)Buffer + peFile->listPeSection[SectionIndex].sectionHeader.VirtualAddress))
            {
#ifdef DEBUG_COMMENTS
                DoOutputDebugString("GetPESize: Found what looks like a virtual section boundary - image looks virtual.\n");
#endif
                delete peFile;
                return SectionBasedImageSize;
            }
        }
    }

    delete peFile;
    return SectionBasedImageSize;
}

//**************************************************************************************
extern "C" int IsPeImageVirtual(DWORD_PTR Buffer)
//**************************************************************************************
{
	PeParser * peFile = 0;
    unsigned int NumberOfSections = 0;
    DWORD SectionBasedFileSize;

	NativeWinApi::initialize();

	ProcessAccessHelp::setCurrentProcessAsTarget();

    peFile = new PeParser((DWORD_PTR)Buffer, TRUE);

    if (peFile->isValidPeFile())
    {
        NumberOfSections = peFile->getNumberOfSections();
        SectionBasedFileSize = peFile->getSectionHeaderBasedFileSize();
#ifdef DEBUG_COMMENTS
        DoOutputDebugString("IsPeImageVirtual: NumberOfSections %d, SectionBasedFileSize 0x%x.\n", NumberOfSections, SectionBasedFileSize);
#endif
        if (NumberOfSections == 0)
        // makes no difference in this case
        {
#ifdef DEBUG_COMMENTS
            DoOutputDebugString("IsPeImageVirtual: zero sections, therefore meaningless.\n");
#endif
            delete peFile;
            return 1;
        }

        for (unsigned int SectionIndex = 0; SectionIndex < NumberOfSections; SectionIndex++)
        {
#ifdef DEBUG_COMMENTS
            DoOutputDebugString
            (
                "IsPeImageVirtual: Section %d, PointerToRawData 0x%x, VirtualAddress 0x%x, SizeOfRawData 0x%x, VirtualSize 0x%x.\n",
                SectionIndex+1,
                peFile->listPeSection[SectionIndex].sectionHeader.PointerToRawData,
                peFile->listPeSection[SectionIndex].sectionHeader.VirtualAddress,
                peFile->listPeSection[SectionIndex].sectionHeader.SizeOfRawData,
                peFile->listPeSection[SectionIndex].sectionHeader.Misc.VirtualSize
            );
#endif
            if (peFile->listPeSection[SectionIndex].sectionHeader.PointerToRawData != peFile->listPeSection[SectionIndex].sectionHeader.VirtualAddress)
            {
                int SectionBoundary = LooksLikeSectionBoundary((DWORD_PTR)Buffer + peFile->listPeSection[SectionIndex].sectionHeader.PointerToRawData);
                if (SectionBoundary == -1)
                {
#ifdef DEBUG_COMMENTS
                    DoOutputDebugString("IsPeImageVirtual: Error reading section boundary.\n");
#endif
                    delete peFile;
                    return 0;
                }
                else if (SectionBoundary == 1)
                {
#ifdef DEBUG_COMMENTS
                    DoOutputDebugString("IsPeImageVirtual: Found what looks like a 'raw' section boundary - image looks raw.\n");
#endif
                    delete peFile;
                    return 0;
                }
                SectionBoundary = LooksLikeSectionBoundary((DWORD_PTR)Buffer + peFile->listPeSection[SectionIndex].sectionHeader.VirtualAddress);
                if (SectionBoundary == -1)
                {
#ifdef DEBUG_COMMENTS
                    DoOutputDebugString("IsPeImageVirtual: Error reading section boundary.\n");
#endif
                    delete peFile;
                    return 0;
                }
                else if (SectionBoundary == 1)
                {
#ifdef DEBUG_COMMENTS
                    DoOutputDebugString("IsPeImageVirtual: Found what looks like a virtual section boundary - image looks virtual.\n");
#endif
                    delete peFile;
                    return 1;
                }
            }
        }
    }

    delete peFile;
    return 0;
}

//**************************************************************************************
bool isIATOutsidePeImage (DWORD_PTR addressIAT)
//**************************************************************************************
{
	DWORD_PTR minAdd = 0, maxAdd = 0;

	if(ProcessAccessHelp::selectedModule)
	{
		minAdd = ProcessAccessHelp::selectedModule->modBaseAddr;
		maxAdd = minAdd + ProcessAccessHelp::selectedModule->modBaseSize;
	}
	else
	{
		minAdd = ProcessAccessHelp::targetImageBase;
		maxAdd = minAdd + ProcessAccessHelp::targetSizeOfImage;
	}

    if (addressIAT > minAdd && addressIAT < maxAdd)
	{
		return FALSE; //inside pe image
	}
	else
	{
		return TRUE; //outside pe image, requires rebasing iat
	}
}

//**************************************************************************************
extern "C" int ScyllaDumpImageInCurrentProcessFixImports(DWORD_PTR modBase, DWORD_PTR NewOEP)
//**************************************************************************************
{
    DWORD addressIAT, sizeIAT;
    BOOL IAT_Found, AdvancedIATSearch = FALSE;
    bool isAfter;

    IATSearch iatSearch;
	ApiReader apiReader;
	IATReferenceScan iatReferenceScan;
	ImportsHandling importsHandling;

	DWORD_PTR entrypointRVA = 0;
	PeParser * peFile = 0;

    //Clear stuff first
    ProcessAccessHelp::ownModuleList.clear();
    apiReader.clearAll();
    importsHandling.clearAllImports();

	NativeWinApi::initialize();

    // Instantiate required objects
    ProcessAccessHelp::setCurrentProcessAsTarget();

    ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::ownModuleList);
    ProcessAccessHelp::moduleList = ProcessAccessHelp::ownModuleList;
    ProcessAccessHelp::targetImageBase = modBase;
    ProcessAccessHelp::getSizeOfImageCurrentProcess();

    // Enumerate DLLs and imported functions
    apiReader.readApisFromModuleList();

    DoOutputDebugString("ScyllaDumpImageInCurrentProcessFixImports: Instantiating PeParser with address: 0x%p.\n", modBase);

    peFile = new PeParser(modBase, TRUE);

    if (peFile->isValidPeFile())
    {
        if (NewOEP)
            entrypointRVA = NewOEP - modBase;
        else
            entrypointRVA = peFile->getEntryPoint();

        DoOutputDebugString(TEXT("ScyllaDumpImageInCurrentProcessFixImports: Module entry point VA is 0x%p"), modBase + entrypointRVA);

        //  Let's dump then fix the dump on disk
        if (peFile->dumpProcess(modBase, modBase + entrypointRVA, CAPE_OUTPUT_FILE))
        {
            DoOutputDebugString("ScyllaDumpImageInCurrentProcessFixImports: Module image dump success %s", CapeOutputPath);
        }

        //  IAT search - we'll try the simple search first
        IAT_Found = iatSearch.searchImportAddressTableInProcess(modBase + entrypointRVA, (DWORD_PTR*)&addressIAT, &sizeIAT, FALSE);

        //  Let's try the advanced search now
        if (IAT_Found == FALSE)
            IAT_Found = iatSearch.searchImportAddressTableInProcess(modBase + entrypointRVA, (DWORD_PTR*)&addressIAT, &sizeIAT, TRUE);

        if (addressIAT && sizeIAT)
        {
            DoOutputDebugString("ScyllaDumpImageInCurrentProcessFixImports: Found IAT: 0x%x, size: 0x%x", addressIAT, sizeIAT);

            apiReader.readAndParseIAT(addressIAT, sizeIAT, importsHandling.moduleList);
            importsHandling.scanAndFixModuleList();

    		if (SCAN_DIRECT_IMPORTS)
    		{
                iatReferenceScan.ScanForDirectImports = true;
                iatReferenceScan.ScanForNormalImports = false;

                iatReferenceScan.apiReader = &apiReader;
                iatReferenceScan.startScan(ProcessAccessHelp::targetImageBase, (DWORD)ProcessAccessHelp::targetSizeOfImage, addressIAT, sizeIAT);

                DoOutputDebugString("ScyllaDumpImageInCurrentProcessFixImports: Direct imports - Found %d possible direct imports with %d unique APIs", iatReferenceScan.numberOfFoundDirectImports(), iatReferenceScan.numberOfFoundUniqueDirectImports());

                if (iatReferenceScan.numberOfFoundDirectImports() > 0)
                {
                    if (iatReferenceScan.numberOfDirectImportApisNotInIat() > 0)
                    {
                        DoOutputDebugString("ScyllaDumpImageInCurrentProcessFixImports: Direct imports - Found %d additional api addresses", iatReferenceScan.numberOfDirectImportApisNotInIat());
                        DWORD sizeIatNew = iatReferenceScan.addAdditionalApisToList();
                        DoOutputDebugString("ScyllaDumpImageInCurrentProcessFixImports: Direct imports - Old IAT size 0x%08x new IAT size 0x%08x.\n", sizeIAT, sizeIatNew);
                        importsHandling.scanAndFixModuleList();
                    }

                    iatReferenceScan.printDirectImportLog();

                    if (FIX_DIRECT_IMPORTS_NORMAL)
                    {
                        // From the Scylla source:
                        // "Direct Imports found. I can patch only direct imports by JMP/CALL
                        // (use universal method if you don't like this)
                        // but where is the junk byte?\r\n\r\nYES = After Instruction\r\nNO =
                        // Before the Instruction\r\nCancel = Do nothing", L"Information", MB_YESNOCANCEL|MB_ICONINFORMATION);

                        // This hasn't yet been tested!
                        isAfter = 1;

                        iatReferenceScan.patchDirectImportsMemory(isAfter);
                        DoOutputDebugString("ScyllaDumpImageInCurrentProcessFixImports: Direct imports patched.\n");
                    }
                }
    		}

            if (isIATOutsidePeImage(addressIAT))
            {
                DoOutputDebugString("ScyllaDumpImageInCurrentProcessFixImports: Warning - IAT is not inside the PE image, requires rebasing.\n");
            }

            ImportRebuilder importRebuild(CAPE_OUTPUT_FILE);

            if (OFT_SUPPORT)
            {
                // Untested
                importRebuild.enableOFTSupport();
                DoOutputDebugString("ScyllaDumpImageInCurrentProcessFixImports: OFT support enabled.\n");
            }

            if (SCAN_DIRECT_IMPORTS && FIX_DIRECT_IMPORTS_UNIVERSAL)
            {
                if (iatReferenceScan.numberOfFoundDirectImports() > 0)
                {
                    // Untested
                    importRebuild.iatReferenceScan = &iatReferenceScan;
                    importRebuild.BuildDirectImportsJumpTable = TRUE;
                }
            }

            if (CREATE_NEW_IAT_IN_SECTION)
            {
                importRebuild.iatReferenceScan = &iatReferenceScan;
                importRebuild.enableNewIatInSection(addressIAT, sizeIAT);
            }

            if (importRebuild.rebuildImportTable(NULL, importsHandling.moduleList))
            {
                DoOutputDebugString("ScyllaDumpImageInCurrentProcessFixImports: Import table rebuild success.\n");
                delete peFile;
                return 1;
            }
            else
            {
                DoOutputDebugString("ScyllaDumpImageInCurrentProcessFixImports: Import table rebuild failed, falling back to unfixed dump.\n");
                peFile->savePeFileToDisk(NULL);
            }
        }
        else
        {
            DoOutputDebugString("ScyllaDumpImageInCurrentProcessFixImports: Warning - Unable to find IAT in scan.\n");
        }

    }
    else
    {
        DoOutputDebugString("ScyllaDumpImageInCurrentProcessFixImports: Error - Invalid PE file or invalid PE header. Try reading PE header from disk/process.\n");
        delete peFile;
        return 0;
    }

    delete peFile;

	return 1;
}

//**************************************************************************************
extern "C" int ScyllaDumpCurrentProcessFixImports(DWORD_PTR NewOEP)
//**************************************************************************************
{
    return ScyllaDumpImageInCurrentProcessFixImports((DWORD_PTR)GetModuleHandle(NULL), NewOEP);
}

//**************************************************************************************
extern "C" int ScyllaDumpProcessFixImports(HANDLE hProcess, DWORD_PTR ModuleBase, DWORD_PTR NewOEP)
//**************************************************************************************
{
    bool isAfter;
    DWORD sizeIAT;
    DWORD_PTR addressIAT;
    BOOL IAT_Found, AdvancedIATSearch = FALSE;

    IATSearch iatSearch;
	ApiReader apiReader;
	IATReferenceScan iatReferenceScan;
	ImportsHandling importsHandling;

	DWORD_PTR entrypointRVA = 0;
	PeParser * peFile = 0;

    //Clear stuff first
    apiReader.clearAll();
    importsHandling.clearAllImports();

	NativeWinApi::initialize();

	ProcessAccessHelp::ownModuleList.clear();
	ProcessAccessHelp::hProcess = hProcess;
    ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);
    ProcessAccessHelp::targetImageBase = ModuleBase;

    apiReader.readApisFromModuleList();

    DoOutputDebugString(TEXT("DumpProcessFixImports: Instantiating PeParser with address: 0x%p"), ModuleBase);

    peFile = new PeParser(ModuleBase, true);

    if (peFile->isValidPeFile())
    {
        if (NewOEP)
            entrypointRVA = NewOEP - ModuleBase;
        else
            entrypointRVA = peFile->getEntryPoint();

        DoOutputDebugString(TEXT("DumpProcessFixImports: Module entry point VA is 0x%p"), ModuleBase + entrypointRVA);

        //  Let's dump then fix the dump on disk
        if (peFile->dumpProcess(ModuleBase, ModuleBase + entrypointRVA, CAPE_OUTPUT_FILE))
        {
            DoOutputDebugString("Module image dump success %s", CapeOutputPath);
        }

        //  We'll try the simple search first
        IAT_Found = iatSearch.searchImportAddressTableInProcess(ModuleBase + entrypointRVA, &addressIAT, &sizeIAT, FALSE);

        //  Let's try the advanced search now
        if (IAT_Found == FALSE)
            IAT_Found = iatSearch.searchImportAddressTableInProcess(ModuleBase + entrypointRVA, &addressIAT, &sizeIAT, TRUE);

        if (addressIAT && sizeIAT)
        {
            DoOutputDebugString("DumpProcessFixImports: Found IAT - 0x%x, size: 0x%x", addressIAT, sizeIAT);

            apiReader.readAndParseIAT(addressIAT, sizeIAT, importsHandling.moduleList);
            importsHandling.scanAndFixModuleList();

    		if (SCAN_DIRECT_IMPORTS)
    		{
                iatReferenceScan.ScanForDirectImports = true;
                iatReferenceScan.ScanForNormalImports = false;

                iatReferenceScan.apiReader = &apiReader;
                iatReferenceScan.startScan(ProcessAccessHelp::targetImageBase, (DWORD)ProcessAccessHelp::targetSizeOfImage, addressIAT, sizeIAT);

                DoOutputDebugString("Direct imports - Found %d possible direct imports with %d unique APIs", iatReferenceScan.numberOfFoundDirectImports(), iatReferenceScan.numberOfFoundUniqueDirectImports());

                if (iatReferenceScan.numberOfFoundDirectImports() > 0)
                {
                    if (iatReferenceScan.numberOfDirectImportApisNotInIat() > 0)
                    {
                        DoOutputDebugString("Direct imports - Found %d additional api addresses", iatReferenceScan.numberOfDirectImportApisNotInIat());
                        DWORD sizeIatNew = iatReferenceScan.addAdditionalApisToList();
                        DoOutputDebugString("Direct imports - Old IAT size 0x%08x new IAT size 0x%08x.\n", sizeIAT, sizeIatNew);
                        importsHandling.scanAndFixModuleList();
                    }

                    iatReferenceScan.printDirectImportLog();

                    if (FIX_DIRECT_IMPORTS_NORMAL)
                    {
                        // From the Scylla source:
                        // "Direct Imports found. I can patch only direct imports by JMP/CALL
                        // (use universal method if you don't like this)
                        // but where is the junk byte?\r\n\r\nYES = After Instruction\r\nNO =
                        // Before the Instruction\r\nCancel = Do nothing", L"Information", MB_YESNOCANCEL|MB_ICONINFORMATION);

                        // This hasn't yet been tested!
                        isAfter = 1;

                        iatReferenceScan.patchDirectImportsMemory(isAfter);
                        DoOutputDebugString("Direct imports patched.\n");
                    }
                }
    		}

            if (isIATOutsidePeImage(addressIAT))
            {
                DoOutputDebugString("Warning - IAT is not inside the PE image, requires rebasing.\n");
            }

            ImportRebuilder importRebuild(CapeOutputPath);

            if (OFT_SUPPORT)
            {
                // Untested
                importRebuild.enableOFTSupport();
                DoOutputDebugString("importRebuild: OFT support enabled.\n");
            }

            if (SCAN_DIRECT_IMPORTS && FIX_DIRECT_IMPORTS_UNIVERSAL)
            {
                if (iatReferenceScan.numberOfFoundDirectImports() > 0)
                {
                    // Untested
                    importRebuild.iatReferenceScan = &iatReferenceScan;
                    importRebuild.BuildDirectImportsJumpTable = TRUE;
                }
            }

            if (CREATE_NEW_IAT_IN_SECTION)
            {
                importRebuild.iatReferenceScan = &iatReferenceScan;
                importRebuild.enableNewIatInSection(addressIAT, sizeIAT);
            }

            if (importRebuild.rebuildImportTable(NULL, importsHandling.moduleList))
            {
                DoOutputDebugString("Import table rebuild success.\n");
                delete peFile;
                return 1;
            }
            else
            {
                DoOutputDebugString("Import table rebuild failed, falling back to unfixed dump.\n");
                peFile->savePeFileToDisk(NULL);
            }
        }
        else
        {
            DoOutputDebugString("Warning: Unable to find IAT in scan.\n");
        }
    }
    else
    {
        DoOutputDebugString("Error: Invalid PE file or invalid PE header. Try reading PE header from disk/process.\n");
        delete peFile;
        return 0;
    }

    delete peFile;

	return 1;
}

//**************************************************************************************
extern "C" BOOL ScyllaGetSectionByName(PVOID ImageBase, char* Name, PVOID* SectionData, SIZE_T* SectionSize)
//**************************************************************************************
{
	ScyllaInitCurrentProcess();

    PeParser *peFile = new PeParser((DWORD_PTR)ImageBase, true);

    if (!peFile->isValidPeFile())
    {
        DoOutputDebugString("ScyllaGetSectionByName: Invalid PE image.\n");
        return 0;
    }

    if (!peFile->readPeSectionsFromProcess())
    {
        DoOutputDebugString("ScyllaGetSectionByName: Failed to read PE sections from image.\n");
        return 0;
    }

    unsigned int NumberOfSections = peFile->getNumberOfSections();

    for (unsigned int i = 0; i < NumberOfSections; i++)
    {
        if (!strcmp((char*)peFile->listPeSection[i].sectionHeader.Name, Name))
        {
            *SectionData = peFile->listPeSection[i].sectionHeader.VirtualAddress + (PUCHAR)ImageBase;
            *SectionSize = peFile->listPeSection[i].sectionHeader.Misc.VirtualSize;
            DoOutputDebugString("ScyllaGetSectionByName: %s section at 0x%p size 0x%x.\n", Name, *SectionData, *SectionSize);
            return TRUE;
        }
    }

    return FALSE;
}

//**************************************************************************************
extern "C" PCHAR ScyllaGetExportNameByAddress(PVOID Address, PCHAR* ModuleName)
//**************************************************************************************
{
    ApiReader apiReader;
    ApiInfo* apiInfo;
    unsigned int ModuleIndex = 0;
    bool dummy;

	ScyllaInitCurrentProcess();

 	for (unsigned int i = 0; i < ProcessAccessHelp::ownModuleList.size(); i++) {
		if ((DWORD_PTR)Address >= ProcessAccessHelp::ownModuleList[i].modBaseAddr && (DWORD_PTR)Address < (ProcessAccessHelp::ownModuleList[i].modBaseAddr + ProcessAccessHelp::ownModuleList[i].modBaseSize))
			ModuleIndex = i+1;
	}

    if (!ModuleIndex)
    {
#ifdef DEBUG_COMMENTS
        DoOutputDebugString("ScyllaGetExportNameByAddress: Address 0x%p not within loaded modules.\n", Address);
#endif
        return NULL;
    }

    PVOID ModuleBase = GetAllocationBase(Address);

    if (!ModuleBase)
    {
#ifdef DEBUG_COMMENTS
        DoOutputDebugString("ScyllaGetExportNameByAddress: GetAllocationBase failed for 0x%p.\n", Address);
#endif
        return NULL;
    }

    PeParser *peFile = new PeParser((DWORD_PTR)ModuleBase, true);

    if (!peFile->isValidPeFile())
    {
#ifdef DEBUG_COMMENTS
        DoOutputDebugString("ScyllaGetExportNameByAddress: Invalid PE image at 0x%p.\n", Address);
#endif
        delete peFile;
        return NULL;
    }

    if (!peFile->hasExportDirectory())
    {
#ifdef DEBUG_COMMENTS
        DoOutputDebugString("ScyllaGetExportNameByAddress: Module has no exports.\n");
#endif
        delete peFile;
        return NULL;
    }

    apiReader.clearAll();

    // This creates moduleInfo->apiList
    apiReader.parseModuleWithOwnProcess(&ProcessAccessHelp::ownModuleList[ModuleIndex-1]);
    apiInfo = apiReader.getApiByVirtualAddress((DWORD_PTR)Address, &dummy);

    if (apiInfo)
    {
        if (ModuleName)
            *ModuleName = apiInfo->module->fullPath;
#ifdef DEBUG_COMMENTS
        DoOutputDebugString("ScyllaGetExportNameByAddress: Located function %s within module %s.\n", apiInfo->name, apiInfo->module->fullPath);
#endif
        delete peFile;
        return (PCHAR)apiInfo->name;
    }
#ifdef DEBUG_COMMENTS
    else
        DoOutputDebugString("ScyllaGetExportNameByAddress: Failed to locate function among module exports.\n");
#endif

    delete peFile;
    return NULL;
}

//**************************************************************************************
extern "C" PCHAR ScyllaGetExportDirectory(PVOID Address)
//**************************************************************************************
{
    ApiReader apiReader;
    unsigned int ModuleIndex = 0;

	ScyllaInitCurrentProcess();

    for (unsigned int i = 0; i < ProcessAccessHelp::ownModuleList.size(); i++) {
		if ((DWORD_PTR)Address >= ProcessAccessHelp::ownModuleList[i].modBaseAddr && (DWORD_PTR)Address < (ProcessAccessHelp::ownModuleList[i].modBaseAddr + ProcessAccessHelp::ownModuleList[i].modBaseSize))
			ModuleIndex = i+1;
	}

    if (!ModuleIndex)
    {
#ifdef DEBUG_COMMENTS
        DoOutputDebugString("ScyllaGetExportDirectory: Address 0x%p not within loaded modules.\n", Address);
#endif
        return NULL;
    }

    PVOID ModuleBase = GetAllocationBase(Address);

    if (!ModuleBase)
    {
#ifdef DEBUG_COMMENTS
        DoOutputDebugString("ScyllaGetExportDirectory: GetAllocationBase failed for 0x%p.\n", Address);
#endif
        return NULL;
    }

    PeParser *peFile = new PeParser((DWORD_PTR)ModuleBase, true);

    if (!peFile->isValidPeFile())
    {
#ifdef DEBUG_COMMENTS
        DoOutputDebugString("ScyllaGetExportDirectory: Invalid PE image at 0x%p.\n", Address);
#endif
        delete peFile;
        return NULL;
    }

    if (!peFile->hasExportDirectory())
    {
#ifdef DEBUG_COMMENTS
        DoOutputDebugString("ScyllaGetExportDirectory: Module has no exports.\n");
#endif
        delete peFile;
        return NULL;
    }

    apiReader.clearAll();

    // This creates moduleInfo->apiList
    apiReader.parseModuleWithOwnProcess(&ProcessAccessHelp::ownModuleList[ModuleIndex-1]);
    char *DirectoryName = (&ProcessAccessHelp::ownModuleList[ModuleIndex-1])->DirectoryName;

    if (DirectoryName)
    {
#ifdef DEBUG_COMMENTS
        DoOutputDebugString("ScyllaGetExportDirectory: Export directory name %s.\n", DirectoryName);
#endif
        delete peFile;
        return (PCHAR)DirectoryName;
    }
#ifdef DEBUG_COMMENTS
    else
        DoOutputDebugString("ScyllaGetExportDirectory: Failed to locate export directory name.\n");
#endif

    delete peFile;
    return NULL;
}