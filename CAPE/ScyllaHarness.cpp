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
#include "CAPE.h"

typedef unsigned __int64 QWORD;

#define USE_PE_HEADER_FROM_DISK FALSE
#define SCAN_DIRECT_IMPORTS FALSE
#define FIX_DIRECT_IMPORTS_NORMAL FALSE
#define FIX_DIRECT_IMPORTS_UNIVERSAL FALSE
#define CREATE_NEW_IAT_IN_SECTION FALSE
#define OFT_SUPPORT FALSE

#define PE_HEADER_LIMIT 0x200

//**************************************************************************************
void ScyllaInit(HANDLE hProcess)
//**************************************************************************************
{
	ProcessAccessHelp::ownModuleList.clear();

	NativeWinApi::initialize();

	if (hProcess)
		ProcessAccessHelp::hProcess = hProcess;
	else
		ProcessAccessHelp::setCurrentProcessAsTarget();
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
			entrypoint = entrypoint + (DWORD_PTR)ModuleBase;
			DebugOutput("DumpProcess: Module entry point VA is 0x%p.\n", entrypoint);
		}

		if (!FixImports)
			if (peFile->dumpProcess(ModuleBase, entrypoint, NULL))
				DebugOutput("DumpProcess: Module image dump success - dump size 0x%x.\n", peFile->dumpSize);
			else
			{
				DebugOutput("DumpProcess: Failed to dump image at 0x%p.\n", ModuleBase);
				goto fail;
			}
	}
	else if (IsDisguisedPEHeader((LPVOID)ModuleBase))
	{
		PBYTE PEImage = NULL;
		PIMAGE_NT_HEADERS pNtHeader = NULL;

		DebugOutput("DumpProcess: Disguised PE image (bad MZ and/or PE headers) at 0x%p.\n", ModuleBase);

		SIZE_T ImageSize = GetAccessibleSize((PVOID)ModuleBase);

		PEImage = (BYTE*)calloc(ImageSize, sizeof(BYTE));
		if (!PEImage)
		{
			DebugOutput("DumpProcess: unable to allocate memory region of size 0x%x\n", ImageSize);
			goto fail;
		}

		memcpy(PEImage, (PVOID)ModuleBase, ImageSize);

		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)PEImage;

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
		peFile = new PeParser((DWORD_PTR)PEImage, TRUE);

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

			if (!FixImports)
				if (peFile->dumpProcess(ModuleBase, entrypoint, NULL))
					DebugOutput("DumpProcess: Module image dump success - dump size 0x%x.\n", peFile->dumpSize);
				else
					DebugOutput("DumpProcess: Failed to dump image at 0x%p.\n", ModuleBase);
		}
		else
			DebugOutput("DumpProcess: Unable to fix PE image for dumping.\n");
	}
	else
	{
		DebugOutput("DumpProcess: Invalid PE file or invalid PE header.\n");
		goto fail;
	}

	if (FixImports)
	{
		ProcessAccessHelp::targetImageBase = ModuleBase;
		ProcessAccessHelp::getSizeOfImageCurrentProcess();
		ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);

		// Enumerate DLLs and imported functions
		apiReader.readApisFromModuleList();
		IAT_Found = iatSearch.searchImportAddressTableInProcess(ModuleBase, &addressIAT, &sizeIAT, FALSE);

		// Try advanced search
		if (!IAT_Found)
			IAT_Found = iatSearch.searchImportAddressTableInProcess(ModuleBase, &addressIAT, &sizeIAT, TRUE);

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
						DWORD sizeIatNew = iatReferenceScan.addAdditionalApisToList();
						DebugOutput("DumpProcess: Direct imports - Found %d additional api addresses, old IAT size 0x%08x new IAT size 0x%08x\n", iatReferenceScan.numberOfDirectImportApisNotInIat(), sizeIAT, sizeIatNew);
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

			ImportRebuilder importRebuild((DWORD_PTR)ModuleBase);

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

			if (importRebuild.rebuildImportTable(NULL, importsHandling.moduleList, entrypoint))
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
			DebugOutput("DumpProcess: Unable to find IAT in scan.\n");
	}

	delete peFile;

	return 1;
fail:
	delete peFile;

	return 0;
}

static void HealDotNetPEHeaders(DWORD_PTR Buffer) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)Buffer;
	
	// 1. Heal DOS Signature ("MZ" = 0x5A4D)
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
		pDos->e_magic = IMAGE_DOS_SIGNATURE;
		pDos->e_lfanew = 0x80; // Standard NT header offset
	}

	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)Buffer + pDos->e_lfanew);
	
	// 2. Heal NT Signature ("PE\0\0" = 0x00004550)
	if (pNt->Signature != IMAGE_NT_SIGNATURE) {
		pNt->Signature = IMAGE_NT_SIGNATURE;
#ifdef _WIN64
		pNt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64; // Set to standard 64-bit AMD64 machine target
		pNt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
#else
		pNt->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;  // Set to standard 32-bit x86 machine target
		pNt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
#endif
		pNt->FileHeader.NumberOfSections = 3; // Standard fallback section count
	}

	// 3. Heal CLR COM Descriptor Directory (index 14)
	PIMAGE_DATA_DIRECTORY pClrDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
	if (pClrDir->VirtualAddress == 0 || pClrDir->Size == 0) {
		dotnet_module_cache_t* pCache = FindCachedDotNetModule((ULONG_PTR)Buffer);
		DWORD metadataRVA = pCache ? pCache->MetadataRVA : 0;
		DWORD metadataSize = pCache ? pCache->MetadataSize : 0;

		// Fallback: If no cached metadata RVA exists, dynamically scan the buffer for the "BSJB" magic (0x424A5342)
		if (metadataRVA == 0) {
			__try {
				PBYTE pStart = (PBYTE)Buffer;
				// Limit scan to 2MB to keep it safe and fast
				PBYTE pEnd = pStart + 0x200000;
				for (PBYTE p = pStart + 0x200; p < pEnd - 4; p++) {
					if (*(DWORD*)p == 0x424A5342) { // "BSJB"
						metadataRVA = (DWORD)(p - pStart);
						metadataSize = 0x10000; // Safe default fallback size (64KB)
						DebugOutput("HealDotNetPEHeaders: Successfully found BSJB metadata magic in memory at offset 0x%x without cache.\n", metadataRVA);
						break;
					}
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DebugOutput("HealDotNetPEHeaders: Exception occurred scanning for BSJB magic.\n");
			}
		}

		if (metadataRVA != 0) {
			pClrDir->VirtualAddress = metadataRVA;
			pClrDir->Size = metadataSize;
			DebugOutput("HealDotNetPEHeaders: Successfully healed zeroed CLR Data Directory to RVA 0x%x (Size 0x%x).\n", metadataRVA, metadataSize);
		}
	}
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

	// Surgically heal zeroed/mangled PE headers and CLR directories in-memory right before Scylla is called
	HealDotNetPEHeaders(Buffer);

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
			DebugOutput("DumpPE: PE file at 0x%p dumped successfully - dump size 0x%x.\n", Buffer, peFile->dumpSize);
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
			if (!peFile->listPeSection[SectionIndex].sectionHeader.PointerToRawData && peFile->listPeSection[SectionIndex].sectionHeader.VirtualAddress)
			{
#ifdef DEBUG_COMMENTS
					DebugOutput("IsPeImageRaw: Missing PointerToRawData for section %d.\n", SectionIndex+1);
#endif
					delete peFile;
					return 0;
			}
			else if (peFile->listPeSection[SectionIndex].sectionHeader.PointerToRawData && !peFile->listPeSection[SectionIndex].sectionHeader.VirtualAddress)
			{
#ifdef DEBUG_COMMENTS
					DebugOutput("IsPeImageRaw: Missing VirtualAddress for section %d.\n", SectionIndex+1);
#endif
					delete peFile;
					return 1;
			}

			if (peFile->listPeSection[SectionIndex].sectionHeader.PointerToRawData != peFile->listPeSection[SectionIndex].sectionHeader.VirtualAddress)
			{
				int SectionBoundary = LooksLikeSectionBoundary((DWORD_PTR)Buffer + peFile->listPeSection[SectionIndex].sectionHeader.VirtualAddress);
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

				SectionBoundary = LooksLikeSectionBoundary((DWORD_PTR)Buffer + peFile->listPeSection[SectionIndex].sectionHeader.PointerToRawData);
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
			}
		}
	}

#ifdef DEBUG_COMMENTS
	DebugOutput("IsPeImageRaw: Unable to find any section boundaries.\n");
#endif
	delete peFile;
	return 0;
}
