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
//#define DEBUG_COMMENTS

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

#define PE_HEADER_LIMIT 0x200
#define CAPE_OUTPUT_FILE "CapeOutput.bin"

extern "C" void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern "C" void ErrorOutput(_In_ LPCTSTR lpOutputString, ...);
extern "C" int ScanForNonZero(LPVOID Buffer, unsigned int Size);
extern "C" PVOID GetAllocationBase(PVOID Address);
extern "C" int IsDisguisedPEHeader(LPVOID Buffer);
extern "C" BOOL IsAddressAccessible(PVOID Address);

extern char CapeOutputPath[MAX_PATH];

//**************************************************************************************
void ScyllaInit(HANDLE hProcess)
//**************************************************************************************
{
	ProcessAccessHelp::ownModuleList.clear();

	NativeWinApi::initialize();

	if (hProcess)
	{
		ProcessAccessHelp::hProcess = hProcess;
		ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);
	}
	else
	{
		ProcessAccessHelp::setCurrentProcessAsTarget();
		ProcessAccessHelp::getProcessModules(GetCurrentProcess(), ProcessAccessHelp::ownModuleList);
	}
}

//**************************************************************************************
extern "C" DWORD_PTR GetEntryPointVA(DWORD_PTR ModuleBase)
//**************************************************************************************
{
	DWORD_PTR EntryPointVA = 0;

	PeParser * peFile = 0;

	ScyllaInit(NULL);

	peFile = new PeParser((DWORD_PTR)ModuleBase, true);

	EntryPointVA = peFile->getEntryPoint() + (DWORD_PTR)ModuleBase;

	delete peFile;

	return EntryPointVA;
}

//**************************************************************************************
extern "C" DWORD_PTR FileOffsetToVA(DWORD_PTR ModuleBase, DWORD_PTR dwOffset)
//**************************************************************************************
{
	PeParser * peFile = 0;

	ScyllaInit(NULL);

	peFile = new PeParser(ModuleBase, true);

	if (!peFile->isValidPeFile())
		return NULL;

	return peFile->convertOffsetToRVAVector(dwOffset) + ModuleBase;
}

//**************************************************************************************
DWORD SafeGetDword(PVOID Address)
//**************************************************************************************
{
	DWORD RetVal = NULL;

	if (!Address)
		return NULL;

	__try
	{
		RetVal = *(DWORD*)Address;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DebugOutput("SafeGetDword: Exception occured reading memory address 0x%p\n", Address);
		return NULL;
	}

	return RetVal;
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
extern "C" int ScyllaDumpProcess(HANDLE hProcess, DWORD_PTR ModuleBase, DWORD_PTR NewEP, BOOL FixImports)
//**************************************************************************************
{
	SIZE_T SectionBasedSizeOfImage = 0;
	PeParser *peFile = 0;
	DWORD_PTR entrypoint = NULL;

	bool isAfter = 0;
	DWORD sizeIAT = 0;
	DWORD_PTR addressIAT = 0;
	BOOL IAT_Found = FALSE;

	IATSearch iatSearch;
	ApiReader apiReader;
	IATReferenceScan iatReferenceScan;
	ImportsHandling importsHandling;

	ScyllaInit(hProcess);

	DebugOutput("DumpProcess: Instantiating PeParser with address: 0x%p.\n", ModuleBase);

	peFile = new PeParser(ModuleBase, TRUE);

	if (peFile->isValidPeFile())
	{
		if (NewEP)
		{
			if (ModuleBase && NewEP > ModuleBase)
				entrypoint = NewEP - ModuleBase;
			else
				entrypoint = NewEP;
		}
		else
			entrypoint = peFile->getEntryPoint();

		SectionBasedSizeOfImage = (SIZE_T)peFile->getSectionHeaderBasedSizeOfImage();

		if ((SIZE_T)entrypoint >= SectionBasedSizeOfImage)
		{
			DebugOutput("DumpProcess: Error - entry point too big: 0x%x, ignoring.\n", entrypoint);
			entrypoint = NULL;
		}
		else
		{
			DebugOutput("DumpProcess: Module entry point VA is 0x%p.\n", entrypoint);
			entrypoint = entrypoint + (DWORD_PTR)ModuleBase;
		}

		if (FixImports)
			if (peFile->dumpProcess(ModuleBase, entrypoint, CAPE_OUTPUT_FILE))
				DebugOutput("DumpProcess: Module image dump success %s - dump size 0x%x.\n", CapeOutputPath, peFile->dumpSize);
			else
			{
				DebugOutput("DumpProcess: Failed to dump image at 0x%p.\n", ModuleBase);
				goto fail;
			}
		else
			if (peFile->dumpProcess(ModuleBase, entrypoint, NULL))
				DebugOutput("DumpProcess: Module image dump success - dump size 0x%x.\n", peFile->dumpSize);
			else
			{
				DebugOutput("DumpProcess: Failed to dump image at 0x%p.\n", ModuleBase);
				goto fail;
			}
	}
	else
	{
		PBYTE PEImage = NULL;
		PIMAGE_NT_HEADERS pNtHeader = NULL;
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ModuleBase;

		if (IsDisguisedPEHeader((LPVOID)ModuleBase) && *(WORD*)pDosHeader != IMAGE_DOS_SIGNATURE || (*(DWORD*)((BYTE*)pDosHeader + pDosHeader->e_lfanew) != IMAGE_NT_SIGNATURE))
		{
			MEMORY_BASIC_INFORMATION MemInfo;

			DebugOutput("DumpProcess: Disguised PE image (bad MZ and/or PE headers) at 0x%p.\n", ModuleBase);

			if (!VirtualQuery((LPVOID)ModuleBase, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
			{
				ErrorOutput("DumpProcess: unable to query memory address 0x%p", ModuleBase);
				goto fail;
			}

			PEImage = (BYTE*)calloc(MemInfo.RegionSize, sizeof(BYTE));
			if (!PEImage)
				goto fail;

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
						DebugOutput("DumpProcess: pNtHeader moved from 0x%x to 0x%x, e_lfanew 0x%x\n", pDosHeader, pNtHeader, pDosHeader->e_lfanew);
					}
				}
			}

			delete peFile;
			peFile = new PeParser((char*)PEImage, TRUE);

			if (peFile->isValidPeFile())
			{
				if (NewEP)
					entrypoint = NewEP;
				else
					entrypoint = peFile->getEntryPoint();

				SectionBasedSizeOfImage = (SIZE_T)peFile->getSectionHeaderBasedSizeOfImage();

				if ((SIZE_T)entrypoint >= SectionBasedSizeOfImage)
				{
					DebugOutput("DumpProcess: Error - entry point too big: 0x%x, ignoring.\n", entrypoint);
					entrypoint = NULL;
				}
				else
				{
					DebugOutput("DumpProcess: Module entry point VA is 0x%p.\n", entrypoint);
					entrypoint = entrypoint + (DWORD_PTR)ModuleBase;
				}

				if (FixImports)
					if (peFile->dumpProcess(ModuleBase, entrypoint, CAPE_OUTPUT_FILE))
						DebugOutput("DumpProcess: Module image dump success %s - dump size 0x%x.\n", CapeOutputPath, peFile->dumpSize);
					else
						DebugOutput("DumpProcess: Failed to dump image at 0x%p.\n", ModuleBase);
				else
					if (peFile->dumpProcess(ModuleBase, entrypoint, NULL))
						DebugOutput("DumpProcess: Module image dump success - dump size 0x%x.\n", peFile->dumpSize);
					else
						DebugOutput("DumpProcess: Failed to dump image at 0x%p.\n", ModuleBase);
			}
		}
		else
		{
			DebugOutput("DumpProcess: Invalid PE file or invalid PE header.\n");
			goto fail;
		}
	}

	if (FixImports)
	{
		//  We'll try the simple search first
		IAT_Found = iatSearch.searchImportAddressTableInProcess(entrypoint, &addressIAT, &sizeIAT, FALSE);

		//  Let's try the advanced search now
		if (IAT_Found == FALSE)
			IAT_Found = iatSearch.searchImportAddressTableInProcess(entrypoint, &addressIAT, &sizeIAT, TRUE);

		if (addressIAT && sizeIAT)
		{
			DebugOutput("DumpProcess: Found IAT - 0x%x, size: 0x%x", addressIAT, sizeIAT);

			apiReader.readAndParseIAT(addressIAT, sizeIAT, importsHandling.moduleList);
			importsHandling.scanAndFixModuleList();

			if (SCAN_DIRECT_IMPORTS)
			{
				iatReferenceScan.ScanForDirectImports = true;
				iatReferenceScan.ScanForNormalImports = false;
				iatReferenceScan.apiReader = &apiReader;
				iatReferenceScan.startScan(ProcessAccessHelp::targetImageBase, (DWORD)ProcessAccessHelp::targetSizeOfImage, addressIAT, sizeIAT);

				DebugOutput("DumpProcess: Direct imports - Found %d possible direct imports with %d unique APIs", iatReferenceScan.numberOfFoundDirectImports(), iatReferenceScan.numberOfFoundUniqueDirectImports());

				if (iatReferenceScan.numberOfFoundDirectImports() > 0)
				{
					if (iatReferenceScan.numberOfDirectImportApisNotInIat() > 0)
					{
						DebugOutput("DumpProcess: Direct imports - Found %d additional api addresses", iatReferenceScan.numberOfDirectImportApisNotInIat());
						DWORD sizeIatNew = iatReferenceScan.addAdditionalApisToList();
						DebugOutput("DumpProcess: Direct imports - Old IAT size 0x%08x new IAT size 0x%08x.\n", sizeIAT, sizeIatNew);
						importsHandling.scanAndFixModuleList();
					}

					iatReferenceScan.printDirectImportLog();

					// This hasn't yet been tested!
					if (FIX_DIRECT_IMPORTS_NORMAL)
					{
						// From the Scylla source: "Direct Imports found. I can patch only direct imports by JMP/CALL
						// (use universal method if you don't like this) but where is the junk byte?\r\n\r\nYES = After Instruction\r\nNO =
						// Before the Instruction\r\nCancel = Do nothing", L"Information", MB_YESNOCANCEL|MB_ICONINFORMATION);
						isAfter = 1;
						iatReferenceScan.patchDirectImportsMemory(isAfter);
						DebugOutput("DumpProcess: Direct imports patched.\n");
					}
				}
			}

			if (isIATOutsidePeImage(addressIAT))
				DebugOutput("DumpProcess: Warning - IAT is not inside the PE image, requires rebasing.\n");

			ImportRebuilder importRebuild(CapeOutputPath);

			if (OFT_SUPPORT)
			{
				// Untested
				importRebuild.enableOFTSupport();
				DebugOutput("DumpProcess: importRebuild: OFT support enabled.\n");
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
				DebugOutput("DumpProcess: Import table rebuild success.\n");
				delete peFile;
				return 1;
			}
			else
			{
				DebugOutput("DumpProcess: Import table rebuild failed, falling back to unfixed dump.\n");
				peFile->savePeFileToDisk(NULL);
			}
		}
		else
		{
			DebugOutput("DumpProcess: Warning: Unable to find IAT in scan.\n");
		}
	}

	delete peFile;

	return 1;
fail:
	delete peFile;

	return 0;
}

//**************************************************************************************
extern "C" int ScyllaDumpPE(DWORD_PTR Buffer)
//**************************************************************************************
{
	DWORD_PTR PointerToLastSection = 0, entrypoint = 0;
	PeParser * peFile = 0;
	unsigned int SizeOfLastSection = 0, NumberOfSections = 0;

	NativeWinApi::initialize();

	ProcessAccessHelp::setCurrentProcessAsTarget();

	DebugOutput("DumpPE: Instantiating PeParser with address: 0x%p.\n", Buffer);

	peFile = new PeParser((DWORD_PTR)Buffer, TRUE);

	if (peFile->isValidPeFile())
	{
		NumberOfSections = peFile->getNumberOfSections();

		if (NumberOfSections == 0)
		{
			DebugOutput("DumpPE: no sections in PE image, ignoring.\n");
			return 0;
		}

		PointerToLastSection = SafeGetDword(&(peFile->listPeSection[NumberOfSections - 1].sectionHeader.PointerToRawData));

		if (!PointerToLastSection)
		{
			DebugOutput("DumpPE: failed to obtain pointer to last section.\n");
			return 0;
		}

		PointerToLastSection += (DWORD_PTR)Buffer;

		SizeOfLastSection = SafeGetDword(&(peFile->listPeSection[NumberOfSections - 1].sectionHeader.SizeOfRawData));

		if (!SizeOfLastSection)
		{
			DebugOutput("DumpPE: failed to obtain size of last section.\n");
			return 0;
		}

		if (!ScanForNonZero((LPVOID)PointerToLastSection, SizeOfLastSection))
			DebugOutput("DumpPE: Empty or inaccessible last section, file image seems incomplete (from 0x%p to 0x%p).\n", PointerToLastSection, (DWORD_PTR)PointerToLastSection + SizeOfLastSection);

		entrypoint = peFile->getEntryPoint();

		if (peFile->saveCompletePeToDisk(NULL))
		{
			DebugOutput("DumpPE: PE file in memory dumped successfully - dump size 0x%x.\n", peFile->dumpSize);
		}
		else
		{
			DebugOutput("DumpPE: Error: Cannot dump PE file from memory.\n");
			delete peFile;
			return 0;
		}
	}
	else
	{
		DebugOutput("DumpPE: Error: Invalid PE file or invalid PE header.\n");
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
	if (!IsAddressAccessible((PVOID)Buffer))
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("LooksLikeSectionBoundary: Address 0x%p inaccessible.\n", Buffer);
#endif
		return -1;
	}

	if (!IsAddressAccessible((PVOID)((BYTE*)Buffer - 4)))
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("LooksLikeSectionBoundary: Yes - end of previous region before candidate section at 0x%p inaccessible.\n", Buffer);
#endif
		return 1;
	}

	__try
	{
		if
		(
			(*(DWORD*)((BYTE*)Buffer - 4) == 0) &&		  // end of previous section has zeros
			(*(DWORD*)((BYTE*)Buffer) != 0)				 // beginning of section is non-zero
		)
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("LooksLikeSectionBoundary: Yes - end of previous candidate section zero, beginning of candidate section at 0x%p non-zero.\n", Buffer);
#endif
			return 1;
		}
		else
		{
#ifdef DEBUG_COMMENTS
			if (*(DWORD*)((BYTE*)Buffer - 4) != 0)
				DebugOutput("LooksLikeSectionBoundary: No - end of previous candidate section 0x%p not zero.\n", Buffer);

			if (*(DWORD*)((BYTE*)Buffer) == 0)
				DebugOutput("LooksLikeSectionBoundary: No - beginning of candidate section 0x%p zero.\n", Buffer);
#endif
			return 0;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DebugOutput("LooksLikeSectionBoundary: Exception occured reading around suspected boundary at 0x%p\n", Buffer);
		return -1;
	}
}

//**************************************************************************************
extern "C" SIZE_T GetPESize(PVOID Buffer)
//**************************************************************************************
{
	PeParser * peFile = 0;
	unsigned int NumberOfSections = 0;
	SIZE_T SectionBasedFileSize = 0, SectionBasedImageSize = 0;

	NativeWinApi::initialize();

	ProcessAccessHelp::setCurrentProcessAsTarget();

	peFile = new PeParser((DWORD_PTR)Buffer, TRUE);

	NumberOfSections = peFile->getNumberOfSections();
	SectionBasedFileSize = (SIZE_T)peFile->getSectionHeaderBasedFileSize();
	SectionBasedImageSize = (SIZE_T)peFile->getSectionHeaderBasedSizeOfImage();

#ifdef DEBUG_COMMENTS
	DebugOutput("GetPESize: NumberOfSections %d, SectionBasedFileSize 0x%x.\n", NumberOfSections, SectionBasedFileSize);
#endif
	if (NumberOfSections == 0)
	// makes no difference in this case
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("GetPESize: zero sections, therefore meaningless.\n");
#endif
		delete peFile;
		return SectionBasedFileSize;
	}

	for (unsigned int SectionIndex = NumberOfSections-1; SectionIndex >= 0; SectionIndex--)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput
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
			if (LooksLikeSectionBoundary((DWORD_PTR)Buffer + peFile->listPeSection[SectionIndex].sectionHeader.VirtualAddress))
			{
#ifdef DEBUG_COMMENTS
				DebugOutput("GetPESize: Found what looks like a virtual section boundary - image looks virtual.\n");
#endif
				delete peFile;
				return SectionBasedImageSize;
			}
			else if (LooksLikeSectionBoundary((DWORD_PTR)Buffer + peFile->listPeSection[SectionIndex].sectionHeader.PointerToRawData))
			{
#ifdef DEBUG_COMMENTS
				DebugOutput("GetPESize: Found what looks like a 'raw' section boundary - image looks raw.\n");
#endif
				delete peFile;
				return SectionBasedFileSize;
			}
		}
	}

	delete peFile;
	return SectionBasedImageSize;
}

//**************************************************************************************
extern "C" int IsPeImageRaw(DWORD_PTR Buffer)
//**************************************************************************************
{
	PeParser * peFile = 0;
	unsigned int NumberOfSections = 0;
	DWORD SectionBasedFileSize = 0;

	NativeWinApi::initialize();

	ProcessAccessHelp::setCurrentProcessAsTarget();

	peFile = new PeParser((DWORD_PTR)Buffer, TRUE);

	if (peFile->isValidPeFile())
	{
		NumberOfSections = peFile->getNumberOfSections();
		SectionBasedFileSize = peFile->getSectionHeaderBasedFileSize();
#ifdef DEBUG_COMMENTS
		DebugOutput("IsPeImageRaw: NumberOfSections %d, SectionBasedFileSize 0x%x.\n", NumberOfSections, SectionBasedFileSize);
#endif
		if (NumberOfSections == 0)
		// makes no difference in this case
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("IsPeImageRaw: zero sections, therefore meaningless.\n");
#endif
			delete peFile;
			return 0;
		}

		for (unsigned int SectionIndex = 0; SectionIndex < NumberOfSections; SectionIndex++)
		{
#ifdef DEBUG_COMMENTS
			DebugOutput
			(
				"IsPeImageRaw: Section %d, PointerToRawData 0x%x, VirtualAddress 0x%x, SizeOfRawData 0x%x, VirtualSize 0x%x.\n",
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
					DebugOutput("IsPeImageRaw: Error reading section boundary.\n");
#endif
					delete peFile;
					return 0;
				}
				else if (SectionBoundary == 1)
				{
#ifdef DEBUG_COMMENTS
					DebugOutput("IsPeImageRaw: Found what looks like a 'raw' section boundary - image looks raw.\n");
#endif
					delete peFile;
					return 1;
				}

				SectionBoundary = LooksLikeSectionBoundary((DWORD_PTR)Buffer + peFile->listPeSection[SectionIndex].sectionHeader.VirtualAddress);
				if (SectionBoundary == -1)
				{
#ifdef DEBUG_COMMENTS
					DebugOutput("IsPeImageRaw: Error reading section boundary.\n");
#endif
					delete peFile;
					return 0;
				}
				else if (SectionBoundary == 1)
				{
#ifdef DEBUG_COMMENTS
					DebugOutput("IsPeImageRaw: Found what looks like a virtual section boundary - image looks virtual.\n");
#endif
					delete peFile;
					return 0;
				}
			}
		}
	}

#ifdef DEBUG_COMMENTS
	DebugOutput("IsPeImageRaw: Unable to find any section boundaries.\n");
#endif
	delete peFile;
	return 0;
}

//**************************************************************************************
extern "C" BOOL ScyllaGetSectionByName(PVOID ImageBase, char* Name, PVOID* SectionData, SIZE_T* SectionSize)
//**************************************************************************************
{
	ScyllaInit(NULL);

	PeParser *peFile = new PeParser((DWORD_PTR)ImageBase, true);

	if (!peFile->isValidPeFile())
	{
		DebugOutput("ScyllaGetSectionByName: Invalid PE image.\n");
		return 0;
	}

	if (!peFile->readPeSectionsFromProcess())
	{
		DebugOutput("ScyllaGetSectionByName: Failed to read PE sections from image.\n");
		return 0;
	}

	unsigned int NumberOfSections = peFile->getNumberOfSections();

	for (unsigned int i = 0; i < NumberOfSections; i++)
	{
		if (!strcmp((char*)peFile->listPeSection[i].sectionHeader.Name, Name))
		{
			*SectionData = peFile->listPeSection[i].sectionHeader.VirtualAddress + (PUCHAR)ImageBase;
			*SectionSize = peFile->listPeSection[i].sectionHeader.Misc.VirtualSize;
			DebugOutput("ScyllaGetSectionByName: %s section at 0x%p size 0x%x.\n", Name, *SectionData, *SectionSize);
			return TRUE;
		}
	}

	return FALSE;
}

//**************************************************************************************
extern "C" PCHAR ScyllaGetExportNameByScan(PVOID Address, PCHAR* ModuleName, SIZE_T ScanSize)
//**************************************************************************************
{
	ApiReader apiReader;
	ApiInfo* apiInfo = NULL;
	unsigned int ModuleIndex = 0;
	bool dummy = 0;

	ScyllaInit(NULL);

	for (unsigned int i = 0; i < ProcessAccessHelp::ownModuleList.size(); i++) {
		if ((DWORD_PTR)Address >= ProcessAccessHelp::ownModuleList[i].modBaseAddr && (DWORD_PTR)Address < (ProcessAccessHelp::ownModuleList[i].modBaseAddr + ProcessAccessHelp::ownModuleList[i].modBaseSize))
			ModuleIndex = i+1;
	}

	if (!ModuleIndex)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("ScyllaGetExportNameByScan: Address 0x%p not within loaded modules.\n", Address);
#endif
		return NULL;
	}

	PVOID ModuleBase = GetAllocationBase(Address);

	if (!ModuleBase)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("ScyllaGetExportNameByScan: GetAllocationBase failed for 0x%p.\n", Address);
#endif
		return NULL;
	}
#ifdef DEBUG_COMMENTS
	else
		DebugOutput("ScyllaGetExportNameByScan: AllocationBase 0x%p for 0x%p.\n", ModuleBase, Address);
#endif

	PeParser *peFile = new PeParser((DWORD_PTR)ModuleBase, true);

	if (!peFile->isValidPeFile())
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("ScyllaGetExportNameByScan: Invalid PE image at 0x%p.\n", Address);
#endif
		delete peFile;
		return NULL;
	}

	if (!peFile->hasExportDirectory())
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("ScyllaGetExportNameByScan: Module has no exports.\n");
#endif
		delete peFile;
		return NULL;
	}

	apiReader.clearAll();

	// This creates moduleInfo->apiList
	apiReader.parseModuleWithOwnProcess(&ProcessAccessHelp::ownModuleList[ModuleIndex-1]);

	for (unsigned int i=0; i < ScanSize; i++)
	{
		apiInfo = apiReader.getApiByVirtualAddress((DWORD_PTR)Address-i, &dummy);
		if (apiInfo)
			break;
	}

	if (apiInfo)
	{
		if (ModuleName)
			*ModuleName = apiInfo->module->fullPath;
#ifdef DEBUG_COMMENTS
		DebugOutput("ScyllaGetExportNameByScan: Located function %s within module %s.\n", apiInfo->name, apiInfo->module->fullPath);
#endif
		delete peFile;
		return (PCHAR)apiInfo->name;
	}
#ifdef DEBUG_COMMENTS
	else
		DebugOutput("ScyllaGetExportNameByScan: Failed to locate function among module exports.\n");
#endif

	delete peFile;
	return NULL;
}

//**************************************************************************************
extern "C" PCHAR ScyllaGetExportNameByAddress(PVOID Address, PCHAR* ModuleName)
//**************************************************************************************
{
	return ScyllaGetExportNameByScan(Address, ModuleName, 1);
}

//**************************************************************************************
extern "C" PCHAR ScyllaGetExportDirectory(PVOID Address)
//**************************************************************************************
{
	unsigned int ModuleIndex = 0;

	ScyllaInit(NULL);

	for (unsigned int i = 0; i < ProcessAccessHelp::ownModuleList.size(); i++) {
		if ((DWORD_PTR)Address >= ProcessAccessHelp::ownModuleList[i].modBaseAddr && (DWORD_PTR)Address < (ProcessAccessHelp::ownModuleList[i].modBaseAddr + ProcessAccessHelp::ownModuleList[i].modBaseSize))
			ModuleIndex = i+1;
	}

	if (!ModuleIndex)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("ScyllaGetExportDirectory: Address 0x%p not within loaded modules.\n", Address);
#endif
		return NULL;
	}

	PVOID ModuleBase = GetAllocationBase(Address);

	if (!ModuleBase)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("ScyllaGetExportDirectory: GetAllocationBase failed for 0x%p.\n", Address);
#endif
		return NULL;
	}

	PeParser *peFile = new PeParser((DWORD_PTR)ModuleBase, true);

	if (!peFile->isValidPeFile())
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("ScyllaGetExportDirectory: Invalid PE image at 0x%p.\n", Address);
#endif
		delete peFile;
		return NULL;
	}

	char* DirectoryName = peFile->getExportDirectory();

	if (DirectoryName)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("ScyllaGetExportDirectory: Export directory name %s.\n", DirectoryName);
#endif
		delete peFile;
		return (PCHAR)DirectoryName;
	}
#ifdef DEBUG_COMMENTS
	else
		DebugOutput("ScyllaGetExportDirectory: Failed to locate export directory name.\n");
#endif

	delete peFile;
	return NULL;
}
