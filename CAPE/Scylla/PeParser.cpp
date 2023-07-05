#include "PeParser.h"
#include "ProcessAccessHelp.h"
#include <algorithm>
#include <imagehlp.h>

#pragma comment(lib, "Imagehlp.lib")

//#define DEBUG_COMMENTS
#define SIZE_LIMIT  0x1000000

extern "C" void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern "C" void ErrorOutput(_In_ LPCTSTR lpOutputString, ...);
extern "C" void CapeOutputFile(LPCTSTR lpOutputFile);
extern "C" void ProcessDumpOutputFile(LPCTSTR lpOutputFile);
extern "C" int ReverseScanForNonZero(LPVOID Buffer, SIZE_T Size);
extern "C" int IsDisguisedPEHeader(LPVOID Buffer);
extern "C" BOOL IsAddressAccessible(PVOID Address);
extern "C" SIZE_T GetAllocationSize(PVOID Buffer);

char CapeOutputPath[MAX_PATH];

PeParser::PeParser()
{
	initClass();
}

PeParser::PeParser(const CHAR * file, bool readSectionHeaders)
{
	initClass();

	filename = file;

	if (filename)
	{
		readPeHeaderFromFile(readSectionHeaders);

		if (readSectionHeaders)
		{
			if (isValidPeFile())
			{
				getSectionHeaders();
			}
		}
	}
}

PeParser::PeParser(const DWORD_PTR moduleBase, bool readSectionHeaders)
{
	initClass();

	moduleBaseAddress = moduleBase;

	if (moduleBaseAddress)
	{
		readPeHeaderFromProcess(readSectionHeaders);

		if (readSectionHeaders)
		{
			if (isValidPeFile())
			{
				getSectionHeaders();
			}
		}
	}

}

PeParser::~PeParser()
{
	if (headerMemory)
	{
		delete [] headerMemory;
	}
	if (fileMemory)
	{
		delete [] fileMemory;
	}

	for (size_t i = 0; i < listPeSection.size(); i++)
	{
		if (listPeSection[i].data)
		{
			delete [] listPeSection[i].data;
		}
	}

	listPeSection.clear();
}

void PeParser::initClass()
{
	fileMemory = 0;
	headerMemory = 0;

	pDosHeader = 0;
	pDosStub = 0;
	dosStubSize = 0;
	pNTHeader32 = 0;
	pNTHeader64 = 0;
	overlayData = 0;
	overlaySize = 0;

	filename = 0;
	fileSize = 0;
	dumpSize = 0;
	moduleBaseAddress = 0;
	hFile = INVALID_HANDLE_VALUE;
}

bool PeParser::isPE64()
{
	if (isValidPeFile())
	{
		return (pNTHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
	}
	else
	{
		return false;
	}
}

bool PeParser::isPE32()
{
	if (isValidPeFile())
	{
		return (pNTHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
	}
	else
	{
		return false;
	}
}

bool PeParser::isTargetFileSamePeFormat()
{
#ifdef _WIN64
	return isPE64();
#else
	return isPE32();
#endif
}

bool PeParser::isValidPeFile()
{
	bool retValue = false;

	if (pDosHeader)
	{
		if (IsDisguisedPEHeader((PVOID)pDosHeader) == 1)
			retValue = true;
	}

	return retValue;
}

bool PeParser::hasDirectory(const int directoryIndex)
{
	if (isPE32())
	{
		return (pNTHeader32->OptionalHeader.DataDirectory[directoryIndex].VirtualAddress != 0);
	}
	else if (isPE64())
	{
		return (pNTHeader64->OptionalHeader.DataDirectory[directoryIndex].VirtualAddress != 0);
	}
	else
	{
		return false;
	}
}

bool PeParser::hasExportDirectory()
{
	return hasDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT);
}

bool PeParser::hasTLSDirectory()
{
	return hasDirectory(IMAGE_DIRECTORY_ENTRY_TLS);
}

bool PeParser::hasRelocationDirectory()
{
	return hasDirectory(IMAGE_DIRECTORY_ENTRY_BASERELOC);
}

char* PeParser::getExportDirectory()
{
	PIMAGE_EXPORT_DIRECTORY pExportDir;

	if (!hasExportDirectory())
		return NULL;

	if (isPE32())
	{
		pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)moduleBaseAddress + pNTHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	}
	else if (isPE64())
	{
		pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)moduleBaseAddress + pNTHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	}

	if (pExportDir && pExportDir->Name)
		return (char*)((DWORD_PTR)pExportDir->Name + (DWORD_PTR)moduleBaseAddress);

	return NULL;
}

DWORD PeParser::getEntryPoint()
{
	if (isPE32())
	{
		return pNTHeader32->OptionalHeader.AddressOfEntryPoint;
	}
	else if (isPE64())
	{
		return pNTHeader64->OptionalHeader.AddressOfEntryPoint;
	}
	else
	{
		return 0;
	}
}

bool PeParser::readPeHeaderFromProcess(bool readSectionHeaders)
{
	bool retValue = false;
	DWORD correctSize = 0;

	DWORD readSize = getInitialHeaderReadSize(readSectionHeaders);

	headerMemory = new BYTE[readSize];

	if (ProcessAccessHelp::readMemoryPartlyFromProcess(moduleBaseAddress, readSize, headerMemory))
	{
		retValue = true;

		getDosAndNtHeader(headerMemory, (LONG)readSize);

		if (isValidPeFile())
		{
			correctSize = calcCorrectPeHeaderSize(readSectionHeaders);

			if (readSize < correctSize)
			{
#ifdef DEBUG_COMMENTS
				DebugOutput("PeParser: readPeHeaderFromProcess: Correcting header size to 0x%x.\n", correctSize);
#endif
				readSize = correctSize;
				delete [] headerMemory;
				headerMemory = new BYTE[readSize];

				if (ProcessAccessHelp::readMemoryPartlyFromProcess(moduleBaseAddress, readSize, headerMemory))
				{
					getDosAndNtHeader(headerMemory, (LONG)readSize);
				}
			}
		}
	}

	return retValue;
}

bool PeParser::readPeHeaderFromFile(bool readSectionHeaders)
{
	bool retValue = false;
	DWORD correctSize = 0;
	DWORD numberOfBytesRead = 0;

	DWORD readSize = getInitialHeaderReadSize(readSectionHeaders);

	headerMemory = new BYTE[readSize];

	if (openFileHandle())
	{
		fileSize = (DWORD)ProcessAccessHelp::getFileSize(hFile);

		if (ReadFile(hFile, headerMemory, readSize, &numberOfBytesRead, 0))
		{
			retValue = true;

			getDosAndNtHeader(headerMemory, (LONG)readSize);

			if (isValidPeFile())
			{
				correctSize = calcCorrectPeHeaderSize(readSectionHeaders);

				if (readSize < correctSize)
				{
					readSize = correctSize;

					if (fileSize > 0)
					{
						if (fileSize < correctSize)
						{
							readSize = fileSize;
						}
					}

					delete [] headerMemory;
					headerMemory = new BYTE[readSize];

					SetFilePointer(hFile, 0, 0, FILE_BEGIN);

					if (ReadFile(hFile, headerMemory, readSize, &numberOfBytesRead, 0))
					{
						getDosAndNtHeader(headerMemory, (LONG)readSize);
					}
				}
			}
		}

		closeFileHandle();
	}

	return retValue;
}

bool PeParser::readPeSectionsFromProcess()
{
	SIZE_T AllocationLimit;
	DWORD_PTR ImageBase, readOffset = 0;
 	DWORD fileAlignment = 0, sectionAlignment = 0;
	unsigned int NumberOfSections = getNumberOfSections();
	if (!NumberOfSections)
		return false;

	if (isPE32())
	{
		fileAlignment = pNTHeader32->OptionalHeader.FileAlignment;
		sectionAlignment = pNTHeader32->OptionalHeader.SectionAlignment;
	}
	else
	{
		fileAlignment = pNTHeader64->OptionalHeader.FileAlignment;
		sectionAlignment = pNTHeader64->OptionalHeader.SectionAlignment;
	}

	listPeSection.reserve(NumberOfSections);

	ImageBase = getStandardImagebase();
	AllocationLimit = ImageBase + GetAllocationSize((PVOID)moduleBaseAddress);

	for (WORD i = 0; i < NumberOfSections; i++)
	{
		DWORD EndOfSection, EndOfPreviousSection = 0;

		if (i < NumberOfSections - 1)
		{
			if (listPeSection[i].sectionHeader.Misc.VirtualSize > (listPeSection[i+1].sectionHeader.VirtualAddress - listPeSection[i].sectionHeader.VirtualAddress))
			{
				listPeSection[i].normalSize = alignValue(listPeSection[i+1].sectionHeader.VirtualAddress - listPeSection[i].sectionHeader.VirtualAddress, sectionAlignment);
#ifdef DEBUG_COMMENTS
				DebugOutput("PeParser: readPeSectionsFromProcess: Correcting VirtualSize for section %d from 0x%x to 0x%x.\n", i+1, listPeSection[i].sectionHeader.Misc.VirtualSize, listPeSection[i].normalSize);
#endif
				listPeSection[i].sectionHeader.Misc.VirtualSize = listPeSection[i].normalSize;
			}
			else
			{
				listPeSection[i].normalSize = alignValue(listPeSection[i].sectionHeader.Misc.VirtualSize, sectionAlignment);
				listPeSection[i].sectionHeader.Misc.VirtualSize = listPeSection[i].normalSize;
#ifdef DEBUG_COMMENTS
				DebugOutput("PeParser: readPeSectionsFromProcess: VirtualSize for section %d ok: 0x%x.\n", i+1, listPeSection[i].sectionHeader.Misc.VirtualSize);
#endif
			}

			if (i)
			{
				EndOfPreviousSection = alignValue(listPeSection[i-1].sectionHeader.VirtualAddress + listPeSection[i-1].sectionHeader.Misc.VirtualSize, sectionAlignment);

				if (listPeSection[i].sectionHeader.VirtualAddress && (listPeSection[i].sectionHeader.VirtualAddress != EndOfPreviousSection))
				{
#ifdef DEBUG_COMMENTS
					DebugOutput("PeParser: readPeSectionsFromProcess: Correcting VirtualAddress for section %d from: 0x%x to 0x%x.\n", i+1, listPeSection[i].sectionHeader.VirtualAddress, EndOfPreviousSection);
#endif
					listPeSection[i].sectionHeader.VirtualAddress = EndOfPreviousSection;
				}
			}
			EndOfSection = EndOfPreviousSection + listPeSection[i].sectionHeader.Misc.VirtualSize;
		}
		else // last section
		{
			DWORD NewVirtualSize = alignValue(listPeSection[i].sectionHeader.SizeOfRawData, sectionAlignment);

			if (NewVirtualSize && listPeSection[i].sectionHeader.Misc.VirtualSize > NewVirtualSize)
			{
				listPeSection[i].normalSize = NewVirtualSize;
#ifdef DEBUG_COMMENTS
				DebugOutput("PeParser: readPeSectionsFromProcess: Correcting VirtualSize for last section (%d) from 0x%x to 0x%x.\n", i+1, listPeSection[i].sectionHeader.Misc.VirtualSize, NewVirtualSize);
#endif
				listPeSection[i].sectionHeader.Misc.VirtualSize = NewVirtualSize;
			}
			else
			{
				NewVirtualSize = alignValue(listPeSection[i].sectionHeader.Misc.VirtualSize, sectionAlignment);
				if (NewVirtualSize && listPeSection[i].sectionHeader.Misc.VirtualSize > NewVirtualSize)
				{
					listPeSection[i].sectionHeader.Misc.VirtualSize = NewVirtualSize;
					listPeSection[i].normalSize = NewVirtualSize;
				}
				else
					listPeSection[i].normalSize = listPeSection[i].sectionHeader.Misc.VirtualSize;
#ifdef DEBUG_COMMENTS
				DebugOutput("PeParser: readPeSectionsFromProcess: VirtualSize for last section (%d) ok: 0x%x.\n", i+1, listPeSection[i].sectionHeader.Misc.VirtualSize);
#endif
			}

			if (i)
			{
				EndOfPreviousSection = alignValue(listPeSection[i-1].sectionHeader.VirtualAddress + listPeSection[i-1].sectionHeader.Misc.VirtualSize, sectionAlignment);

				if (listPeSection[i].sectionHeader.VirtualAddress && (listPeSection[i].sectionHeader.VirtualAddress != EndOfPreviousSection))
				{
#ifdef DEBUG_COMMENTS
					DebugOutput("PeParser: readPeSectionsFromProcess: Correcting VirtualAddress for last section (%d) from: 0x%x to 0x%x.\n", i+1, listPeSection[i].sectionHeader.VirtualAddress, EndOfPreviousSection);
#endif
					listPeSection[i].sectionHeader.VirtualAddress = EndOfPreviousSection;
				}
			}
			EndOfSection = (DWORD)ImageBase + EndOfPreviousSection + listPeSection[i].sectionHeader.Misc.VirtualSize;
		}

		if (EndOfSection > AllocationLimit)
		{
			DebugOutput("PeParser: End of section %d RVA 0x%x is beyond allocated limit 0x%x\n", i+1, EndOfSection, AllocationLimit);
			break;
		}
#ifdef DEBUG_COMMENTS
		DebugOutput("PeParser: End of section %d RVA 0x%x within allocated limit 0x%x\n", i+1, EndOfSection, AllocationLimit);
#endif

		readOffset = listPeSection[i].sectionHeader.VirtualAddress + moduleBaseAddress;

		if (!readSectionFromProcess(readOffset, listPeSection[i]))
			DebugOutput("PeParser: readPeSectionsFromProcess: readSectionFromProcess failed offset 0x%x, section %d\n", readOffset, i+1);
#ifdef DEBUG_COMMENTS
		else
			DebugOutput("PeParser: readPeSectionsFromProcess: readSectionFromProcess success, section %d\n", i+1);
#endif
	}

	if (moduleBaseAddress && moduleBaseAddress != ImageBase)
	{
		if (reBasePEImage(moduleBaseAddress))
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("readPeSectionsFromProcess: Image relocated back to header image base 0x%p.\n", ImageBase);
#endif
		}
		else
			DebugOutput("readPeSectionsFromProcess: Failed to relocate image back to header image base 0x%p.\n", ImageBase);
	}
#ifdef DEBUG_COMMENTS
	else
		DebugOutput("readPeSectionsFromProcess: No relocation needed (image base 0x%p, header 0x%p.)\n", ImageBase, moduleBaseAddress);
#endif

	return true;
}

bool PeParser::readPeSectionsFromFile()
{
	bool retValue = true;
	DWORD readOffset = 0;

	listPeSection.reserve(getNumberOfSections());

	if (openFileHandle())
	{
		for (WORD i = 0; i < getNumberOfSections(); i++)
		{
			readOffset = listPeSection[i].sectionHeader.PointerToRawData;

			listPeSection[i].normalSize = listPeSection[i].sectionHeader.SizeOfRawData;

			if (!readSectionFromFile(readOffset, listPeSection[i]))
			{
				retValue = false;
			}

		}

		closeFileHandle();
	}
	else
	{
		retValue = false;
	}

	return retValue;
}

bool PeParser::getSectionHeaders()
{
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNTHeader32);

	PeFileSection peFileSection;

	listPeSection.clear();
	listPeSection.reserve(getNumberOfSections());

	for (WORD i = 0; i < getNumberOfSections(); i++)
	{
		__try
		{
			memcpy_s(&peFileSection.sectionHeader, sizeof(IMAGE_SECTION_HEADER), pSection, sizeof(IMAGE_SECTION_HEADER));
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			DebugOutput("getSectionHeaders: Exception copying section header at 0x%p.\n", pSection);
			return FALSE;
		}

		listPeSection.push_back(peFileSection);
		pSection++;
	}

	return true;
}

bool PeParser::getSectionNameUnicode(const int sectionIndex, CHAR * output, const int outputLen)
{
	CHAR sectionNameA[IMAGE_SIZEOF_SHORT_NAME + 1] = {0};

	output[0] = 0;

	memcpy(sectionNameA, listPeSection[sectionIndex].sectionHeader.Name, IMAGE_SIZEOF_SHORT_NAME); //not null terminated

	return (sprintf_s(output, outputLen, "%s", sectionNameA) != -1);
}

WORD PeParser::getNumberOfSections()
{
	return pNTHeader32->FileHeader.NumberOfSections;
}

void PeParser::setNumberOfSections(WORD numberOfSections)
{
	pNTHeader32->FileHeader.NumberOfSections = numberOfSections;
}

std::vector<PeFileSection> & PeParser::getSectionHeaderList()
{
	return listPeSection;
}

void PeParser::getDosAndNtHeader(BYTE* memory, LONG size)
{
	pDosHeader = (PIMAGE_DOS_HEADER)memory;
	DWORD readSize = getInitialHeaderReadSize(true);

	pNTHeader32 = 0;
	pNTHeader64 = 0;
	dosStubSize = 0;
	pDosStub = 0;

	if (pDosHeader->e_lfanew > 0 && pDosHeader->e_lfanew < size) //malformed PE
	{
		pNTHeader32 = (PIMAGE_NT_HEADERS32)((DWORD_PTR)pDosHeader + pDosHeader->e_lfanew);
		pNTHeader64 = (PIMAGE_NT_HEADERS64)((DWORD_PTR)pDosHeader + pDosHeader->e_lfanew);

		if (pDosHeader->e_lfanew >= sizeof(IMAGE_DOS_HEADER))
		{
			dosStubSize = pDosHeader->e_lfanew - sizeof(IMAGE_DOS_HEADER);
			pDosStub = (BYTE *)((DWORD_PTR)pDosHeader + sizeof(IMAGE_DOS_HEADER));
#ifdef DEBUG_COMMENTS
			//DebugOutput("PeParser: getDosAndNtHeader: dosStubSize size 0x%x.\n", dosStubSize);
#endif
		}
		else if (pDosHeader->e_lfanew < sizeof(IMAGE_DOS_HEADER))
		{
			//Overlapped Headers, e.g. Spack (by Bagie)
			pDosHeader->e_lfanew = sizeof(IMAGE_DOS_HEADER);
		}
	}

	if (!pDosHeader->e_lfanew)
	{
		// In case the header until and including 'PE' has been zeroed (e.g. Ursnif)
		PIMAGE_NT_HEADERS pNtHeader = NULL;
		WORD* MachineProbe = (WORD*)&pDosHeader->e_lfanew;
		while ((PUCHAR)MachineProbe < (PUCHAR)&pDosHeader + (readSize - offsetof(IMAGE_DOS_HEADER, e_lfanew)))
		{
			if (*MachineProbe == IMAGE_FILE_MACHINE_I386 || *MachineProbe == IMAGE_FILE_MACHINE_AMD64)
				pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)MachineProbe - 4);
			MachineProbe += sizeof(WORD);
		}

		if (pNtHeader)
			pDosHeader->e_lfanew = (LONG)((PUCHAR)pNtHeader - (PUCHAR)pDosHeader);
	}

	if (!pDosHeader->e_lfanew)
	{
		// In case the header until and including 'PE' is missing
		PIMAGE_NT_HEADERS pNtHeader = NULL;
		WORD* MachineProbe = (WORD*)pDosHeader;
		while ((PUCHAR)MachineProbe < (PUCHAR)pDosHeader + (readSize - offsetof(IMAGE_DOS_HEADER, e_lfanew)))
		{
			if (*MachineProbe == IMAGE_FILE_MACHINE_I386 || *MachineProbe == IMAGE_FILE_MACHINE_AMD64)
			{
				if ((PUCHAR)MachineProbe >= (PUCHAR)pDosHeader + 4 && !pNtHeader)
				{
					pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)MachineProbe - 4);
				}
			}
			MachineProbe += sizeof(WORD);

			if (pNtHeader && (PUCHAR)pNtHeader == (PUCHAR)pDosHeader)
			{
				SIZE_T HeaderShift = sizeof(IMAGE_DOS_HEADER);
				delete [] headerMemory;
				headerMemory = new BYTE[readSize];
				memset(headerMemory, 0, readSize);
				if (ProcessAccessHelp::readMemoryPartlyFromProcess(moduleBaseAddress, readSize - HeaderShift, headerMemory + HeaderShift))
				{
					pDosHeader = (PIMAGE_DOS_HEADER)headerMemory;
					pNtHeader = (PIMAGE_NT_HEADERS)(headerMemory + HeaderShift);
					pDosHeader->e_lfanew = (LONG)((PUCHAR)pNtHeader - (PUCHAR)pDosHeader);
				}
#ifdef DEBUG_COMMENTS
				DebugOutput("PeParser: getDosAndNtHeader: Corrected: DOS header 0x%x, lfanew 0x%x, NT header 0x%x.\n", pDosHeader, pDosHeader->e_lfanew, pNtHeader);
#endif
			}
		}
	}

	if (pDosHeader->e_lfanew && pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + (ULONG)pDosHeader->e_lfanew);

		if ((pNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) || (pNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC))
		{
			pDosHeader->e_magic = IMAGE_DOS_SIGNATURE;
			pNtHeader->Signature = IMAGE_NT_SIGNATURE;
		}
	}

	if (pDosHeader->e_lfanew)
	{
		pNTHeader32 = (PIMAGE_NT_HEADERS32)((DWORD_PTR)pDosHeader + pDosHeader->e_lfanew);
		pNTHeader64 = (PIMAGE_NT_HEADERS64)((DWORD_PTR)pDosHeader + pDosHeader->e_lfanew);

		// data in slack
		DWORD SlackOffset = pDosHeader->e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + pNTHeader32->FileHeader.SizeOfOptionalHeader + (sizeof(IMAGE_SECTION_HEADER) * (pNTHeader32->FileHeader.NumberOfSections)); 
		if (readSize > SlackOffset)
		{
			SlackData = (BYTE*)pDosHeader + SlackOffset;
			SizeOfSlackData = readSize - SlackOffset;
			SizeOfSlackData = ReverseScanForNonZero(SlackData, SizeOfSlackData);
		}
	}
}

DWORD PeParser::calcCorrectPeHeaderSize(bool readSectionHeaders)
{
	DWORD correctSize = pDosHeader->e_lfanew + 0x80; //extra buffer

	if (readSectionHeaders)
	{
		correctSize += getNumberOfSections() * sizeof(IMAGE_SECTION_HEADER);
	}

	if (isPE32())
	{
		correctSize += sizeof(IMAGE_NT_HEADERS32);
	}
	else if(isPE64())
	{
		correctSize += sizeof(IMAGE_NT_HEADERS64);
	}
	else
	{
		correctSize = 0; //not a valid PE
	}

	return correctSize;
}

DWORD PeParser::getInitialHeaderReadSize(bool readSectionHeaders)
{
	return 0x400;
}

DWORD PeParser::getSectionHeaderBasedFileSize()
{
	DWORD lastRawOffset = 0, lastRawSize = 0;

	//this is needed if the sections aren't sorted by their RawOffset (e.g. Petite)
	for (WORD i = 0; i < getNumberOfSections(); i++)
	{
		if ((listPeSection[i].sectionHeader.PointerToRawData + listPeSection[i].sectionHeader.SizeOfRawData) > (lastRawOffset + lastRawSize))
		{
			lastRawOffset = listPeSection[i].sectionHeader.PointerToRawData;
			lastRawSize = listPeSection[i].sectionHeader.SizeOfRawData;
		}
	}

	return (lastRawSize + lastRawOffset);
}

DWORD PeParser::getSectionHeaderBasedSizeOfImage()
{
	DWORD lastVirtualOffset = 0, lastVirtualSize = 0;

	//this is needed if the sections aren't sorted by their RawOffset (e.g. Petite)
	for (WORD i = 0; i < getNumberOfSections(); i++)
	{
		if ((listPeSection[i].sectionHeader.VirtualAddress + listPeSection[i].sectionHeader.Misc.VirtualSize) > (lastVirtualOffset + lastVirtualSize))
		{
			lastVirtualOffset = listPeSection[i].sectionHeader.VirtualAddress;
			lastVirtualSize = listPeSection[i].sectionHeader.Misc.VirtualSize;
		}
	}

	return (lastVirtualSize + lastVirtualOffset);
}

bool PeParser::openFileHandle()
{
	if (hFile == INVALID_HANDLE_VALUE)
	{
		if (filename)
		{
			hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
		}
		else
		{
			hFile = INVALID_HANDLE_VALUE;
		}
	}

	return (hFile != INVALID_HANDLE_VALUE);
}

bool PeParser::openWriteFileHandle(const CHAR *newFile)
{
	const char *filePath;
	if (newFile)
		filePath = newFile;
		// If no name was specified, assign a temporary name
	else
		filePath = GetTempName();

	hFile = CreateFile(filePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

#ifdef DEBUG_COMMENTS
	if (hFile == INVALID_HANDLE_VALUE)
		ErrorOutput("openWriteFileHandle: Cannot create %s", filePath);
#endif

	return (hFile != INVALID_HANDLE_VALUE);
}

void PeParser::closeFileHandle()
{
	if (hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}
}

bool PeParser::readSectionFromProcess(const DWORD_PTR readOffset, PeFileSection & peFileSection)
{
	return readSectionFrom(readOffset, peFileSection, true); //process
}

bool PeParser::readSectionFromFile(const DWORD readOffset, PeFileSection & peFileSection)
{
	return readSectionFrom(readOffset, peFileSection, false); //file
}

bool PeParser::readSectionFrom(const DWORD_PTR readOffset, PeFileSection & peFileSection, const bool isProcess)
{
	const DWORD maxReadSize = 100;
	DWORD currentReadSize;
	BYTE data[maxReadSize];
	bool retValue = true;
	DWORD valuesFound = 0;
	DWORD_PTR currentOffset = 0;
	DWORD readSize;

	peFileSection.data = 0;
	if (peFileSection.dataSize)
		readSize = peFileSection.dataSize;
	else
		readSize = peFileSection.normalSize;

	if (!readOffset || !readSize)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("PeParser: readSectionFrom: readOffset or readSize zero: 0x%x, 0x%x\n", readOffset, readSize);
#endif
		return true; //section without data is valid
	}

	if (readSize <= maxReadSize)
	{
		peFileSection.dataSize = readSize;
		peFileSection.normalSize = readSize;

#ifdef DEBUG_COMMENTS
		DebugOutput("PeParser: readSectionFrom: readSize <= maxReadSize: 0x%x.\n", readSize);
#endif

		if (isProcess)
		{
			return readPeSectionFromProcess(readOffset, peFileSection);
		}
		else
		{
			return readPeSectionFromFile((DWORD)readOffset, peFileSection);
		}
	}

	currentReadSize = readSize % maxReadSize; //alignment %

	if (!currentReadSize)
	{
		currentReadSize = maxReadSize;
	}
	currentOffset = readOffset + readSize - currentReadSize;

	if (!IsAddressAccessible((PVOID)currentOffset))
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("PeParser: readSectionFrom: address 0x%p inaccessible (base 0x%p, corrected size 0x%x).\n", currentOffset, readOffset, readSize);
#endif
		return false;
	}

#ifdef DEBUG_COMMENTS
	DebugOutput("PeParser: About to reverse-scan section from 0x%p (base 0x%p size 0x%x).\n", currentOffset, readOffset, readSize);
#endif

	while(currentOffset >= readOffset) //start from the end
	{
		ZeroMemory(data, currentReadSize);

		if (isProcess)
		{
			retValue = ProcessAccessHelp::readMemoryPartlyFromProcess(currentOffset, currentReadSize, data);
		}
		else
		{
			retValue = ProcessAccessHelp::readMemoryFromFile(hFile, (LONG)currentOffset, currentReadSize, data);
		}

		if (!retValue)
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("PeParser: readMemory failure reading from 0x%p (currentReadSize 0x%x).\n", currentOffset, currentReadSize);
#endif
			break;
		}
#ifdef DEBUG_COMMENTS
		//else
		//	DebugOutput("PeParser: Read memory chunk from 0x%p size 0x%x.\n", currentOffset, currentReadSize);
#endif

		valuesFound = isMemoryNotNull(data, currentReadSize);
		if (valuesFound)
		{
			//found some real code

#ifdef DEBUG_COMMENTS
			DebugOutput("PeParser: readMemory found data at 0x%p (currentReadSize 0x%x).\n", currentOffset, currentReadSize);
#endif
			currentOffset += valuesFound;

			if (readOffset < currentOffset)
			{
				//real size
				peFileSection.dataSize = (DWORD)(currentOffset - readOffset);

				//some safety space because of something like this at the end of a section:
				//FF25 C0604000 JMP DWORD PTR DS:[<&KERNEL32.RtlUnwind>]
				peFileSection.dataSize += sizeof(DWORD);

				if (peFileSection.normalSize < peFileSection.dataSize)
				{
					peFileSection.dataSize = peFileSection.normalSize;
				}
			}

			break;
		}

		currentReadSize = maxReadSize;
		currentOffset -= currentReadSize;
	}

	if (peFileSection.dataSize)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("PeParser: readSectionFrom: About to read full PE section from 0x%p size 0x%x.\n", readOffset, peFileSection.dataSize);
#endif
		if (isProcess)
		{
			retValue = readPeSectionFromProcess(readOffset, peFileSection);
		}
		else
		{
			retValue = readPeSectionFromFile((DWORD)readOffset, peFileSection);
		}
	}
#ifdef DEBUG_COMMENTS
	else
		DebugOutput("PeParser: No data read from section at 0x%p.\n", readOffset);
#endif

	return retValue;
}

DWORD PeParser::isMemoryNotNull( BYTE * data, int dataSize )
{
	for (int i = (dataSize - 1); i >= 0; i--)
	{
		if (data[i] != 0)
		{
			return i + 1;
		}
	}

	return 0;
}

bool PeParser::savePeFileToDisk(const CHAR *newFile)
{
	bool retValue = true, SectionDataWritten = false;
	char *CapeName;

#ifdef DEBUG_COMMENTS
	//DebugOutput("PeParser: savePeFileToDisk: Function entry.\n");
#endif

	DWORD dwFileOffset = 0, dwWriteSize = 0;

	if (getNumberOfSections() != listPeSection.size())
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("PeParser: savePeFileToDisk: Number of sections mismatch error.\n");
#endif
		return false;
	}

	if (!openWriteFileHandle(newFile))
	{
#ifdef DEBUG_COMMENTS
		if (newFile)
			DebugOutput("PeParser: savePeFileToDisk: Unable to create output file: %s.\n", newFile);
		else
			DebugOutput("PeParser: savePeFileToDisk: Unable to create output file.\n");
#endif
		return false;
	}

	//Dos header
	dwWriteSize = sizeof(IMAGE_DOS_HEADER);
	if (!ProcessAccessHelp::writeMemoryToFile(hFile, dwFileOffset, dwWriteSize, pDosHeader))
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("PeParser: savePeFileToDisk: Failure to write DOS header.\n");
#endif
		retValue = false;
	}
	dwFileOffset += dwWriteSize;


	if (dosStubSize && pDosStub)
	{
		//Dos Stub
		dwWriteSize = dosStubSize;
		if (!ProcessAccessHelp::writeMemoryToFile(hFile, dwFileOffset, dwWriteSize, pDosStub))
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("PeParser: savePeFileToDisk: Failure to write DOS stub.\n");
#endif
			retValue = false;
		}
		dwFileOffset += dwWriteSize;
	}

	//PE header
	if (isPE32())
		dwWriteSize = sizeof(IMAGE_NT_HEADERS32);
	else
		dwWriteSize = sizeof(IMAGE_NT_HEADERS64);

	if (!ProcessAccessHelp::writeMemoryToFile(hFile, dwFileOffset, dwWriteSize, pNTHeader32))
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("PeParser: savePeFileToDisk: Failure to write PE header.\n");
#endif
		retValue = false;
	}
	dwFileOffset += dwWriteSize;

	//section headers
	dwWriteSize = sizeof(IMAGE_SECTION_HEADER);

	for (WORD i = 0; i < getNumberOfSections(); i++)
	{
		if (!ProcessAccessHelp::writeMemoryToFile(hFile, dwFileOffset, dwWriteSize, &listPeSection[i].sectionHeader))
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("PeParser: savePeFileToDisk: Failure to write section headers (size 0x%x bytes).\n", dwWriteSize);
#endif
			retValue = false;
			break;
		}
		dwFileOffset += dwWriteSize;
	}

	//PE slack
	if (SizeOfSlackData)
	{
		dwWriteSize = (DWORD)SizeOfSlackData;
		if (!ProcessAccessHelp::writeMemoryToFile(hFile, dwFileOffset, dwWriteSize, SlackData))
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("PeParser: savePeFileToDisk: Failure to write header slack (size 0x%x bytes).\n", dwWriteSize);
#endif
			retValue = false;
		}
		dwFileOffset += dwWriteSize;
	}

	//sections
	for (WORD i = 0; i < getNumberOfSections(); i++)
	{
		if (!listPeSection[i].sectionHeader.PointerToRawData)
			continue;

		if (listPeSection[i].sectionHeader.PointerToRawData > dwFileOffset)
		{
			dwWriteSize = listPeSection[i].sectionHeader.PointerToRawData - dwFileOffset; //padding

			if (!writeZeroMemoryToFile(hFile, dwFileOffset, dwWriteSize))
			{
#ifdef DEBUG_COMMENTS
				DebugOutput("PeParser: savePeFileToDisk: Failure to write padding prior to section %d.\n", i+1);
#endif
				retValue = false;
				break;
			}
			dwFileOffset += dwWriteSize;
		}

		dwWriteSize = listPeSection[i].dataSize;

		if (dwWriteSize)
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("PeParser: savePeFileToDisk: Writing section %d of size 0x%x bytes.\n", i+1, dwWriteSize);
#endif
			if (!ProcessAccessHelp::writeMemoryToFile(hFile, listPeSection[i].sectionHeader.PointerToRawData, dwWriteSize, listPeSection[i].data))
			{
				DebugOutput("PeParser: savePeFileToDisk: Failure to write section %d of size 0x%x bytes.\n", i+1, dwWriteSize);
				retValue = false;
				break;
			}
			dwFileOffset += dwWriteSize;

			SectionDataWritten = true;

			if (listPeSection[i].dataSize < listPeSection[i].sectionHeader.SizeOfRawData) //padding
			{
				dwWriteSize = listPeSection[i].sectionHeader.SizeOfRawData - listPeSection[i].dataSize;

				if (!writeZeroMemoryToFile(hFile, dwFileOffset, dwWriteSize))
				{
					DebugOutput("PeParser: savePeFileToDisk: Failure to write padding to section %d.\n", i+1);
					retValue = false;
					break;
				}
				dwFileOffset += dwWriteSize;
			}
		}
#ifdef DEBUG_COMMENTS
		else
			DebugOutput("PeParser: savePeFileToDisk: Nothing to write for section %d.\n", i+1);
#endif
	}

	//add overlay?
	if (overlaySize && overlayData)
	{
		dwWriteSize = overlaySize;
		if (!ProcessAccessHelp::writeMemoryToFile(hFile, dwFileOffset, dwWriteSize, overlayData))
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("PeParser: savePeFileToDisk: Failure to write ovrelay data.\n");
#endif
			retValue = false;
		}
		dwFileOffset += dwWriteSize;
	}

	SetEndOfFile(hFile);
	dumpSize = dwFileOffset;

	closeFileHandle();

	// If only headers are written, fail
	// (this will allow a subsequent 'raw' memory dump)
	if (!SectionDataWritten)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("PeParser: savePeFileToDisk: No section data written!\n");
#endif
		return false;
	}

	if (!newFile)
	{
		if (!GetFullPathName(GetTempName(), MAX_PATH, CapeOutputPath, NULL))
		{
			ErrorOutput("savePeFileToDisk: There was a problem obtaining the full file path");
			return false;
		}

		CapeName = GetName();

#ifdef DEBUG_COMMENTS
		DebugOutput("PeParser: savePeFileToDisk: Full file path %s, CapeName %s.\n", CapeOutputPath, CapeName);
#endif
		if (MoveFile(CapeOutputPath, CapeName))
		{
			memset(CapeOutputPath, 0, MAX_PATH);

			if (!GetFullPathName(CapeName, MAX_PATH, CapeOutputPath, NULL))
			{
				ErrorOutput("savePeFileToDisk: There was a problem obtaining the full file path");
				return false;
			}

			CapeOutputFile(CapeOutputPath);
		}
		else if (GetLastError() == ERROR_ALREADY_EXISTS)	// have seen this occasionally
		{
			DebugOutput("savePeFileToDisk: Name clash, trying to obtain new name...");

			CapeName = GetName();

			if (MoveFile(CapeOutputPath, CapeName))
			{
				memset(CapeOutputPath, 0, MAX_PATH);

				if (!GetFullPathName(CapeName, MAX_PATH, CapeOutputPath, NULL))
				{
					ErrorOutput("savePeFileToDisk: There was a problem obtaining the full file path");
					return false;
				}

				CapeOutputFile(CapeOutputPath);
			}
			else
			{
				ErrorOutput("savePeFileToDisk: Failed twice to rename file");

				if (!DeleteFile(CapeOutputPath))
				{
					ErrorOutput("savePeFileToDisk: There was a problem deleting the file: %s", CapeOutputPath);
				}

				return false;
			}
		}
		else
		{
			ErrorOutput("savePeFileToDisk: There was a problem renaming the file");

			if (!DeleteFile(CapeOutputPath))
			{
				ErrorOutput("savePeFileToDisk: There was a problem deleting the file: %s", CapeOutputPath);
			}

			return false;
		}
	}

	return retValue;
}

bool PeParser::savePeFileToHandle(HANDLE FileHandle)
{
	bool retValue = true, SectionDataWritten = false;

#ifdef DEBUG_COMMENTS
	//DebugOutput("PeParser: savePeFileToHandle: Function entry.\n");
#endif

	DWORD dwFileOffset = 0, dwWriteSize = 0;

	if (getNumberOfSections() != listPeSection.size())
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("PeParser: savePeFileToHandle: Number of sections mismatch error.\n");
#endif
		return false;
	}

	//Dos header
	dwWriteSize = sizeof(IMAGE_DOS_HEADER);
	if (!ProcessAccessHelp::writeMemoryToFile(FileHandle, dwFileOffset, dwWriteSize, pDosHeader))
	{
		retValue = false;
	}
	dwFileOffset += dwWriteSize;


	if (dosStubSize && pDosStub)
	{
		//Dos Stub
		dwWriteSize = dosStubSize;
		if (!ProcessAccessHelp::writeMemoryToFile(FileHandle, dwFileOffset, dwWriteSize, pDosStub))
		{
			retValue = false;
		}
		dwFileOffset += dwWriteSize;
	}

	//Pe Header
	if (isPE32())
	{
		dwWriteSize = sizeof(IMAGE_NT_HEADERS32);
	}
	else
	{
		dwWriteSize = sizeof(IMAGE_NT_HEADERS64);
	}

	if (!ProcessAccessHelp::writeMemoryToFile(FileHandle, dwFileOffset, dwWriteSize, pNTHeader32))
	{
		retValue = false;
	}
	dwFileOffset += dwWriteSize;

	//section headers
	dwWriteSize = sizeof(IMAGE_SECTION_HEADER);

	for (WORD i = 0; i < getNumberOfSections(); i++)
	{
		if (!ProcessAccessHelp::writeMemoryToFile(FileHandle, dwFileOffset, dwWriteSize, &listPeSection[i].sectionHeader))
		{
			retValue = false;
			break;
		}
		dwFileOffset += dwWriteSize;
	}

	for (WORD i = 0; i < getNumberOfSections(); i++)
	{
		if (!listPeSection[i].sectionHeader.PointerToRawData)
			continue;

		if (listPeSection[i].sectionHeader.PointerToRawData > dwFileOffset)
		{
			dwWriteSize = listPeSection[i].sectionHeader.PointerToRawData - dwFileOffset; //padding

			if (!writeZeroMemoryToFile(FileHandle, dwFileOffset, dwWriteSize))
			{
				retValue = false;
				break;
			}
			dwFileOffset += dwWriteSize;
		}

		dwWriteSize = listPeSection[i].dataSize;

		if (dwWriteSize)
		{
#ifdef DEBUG_COMMENTS
			DebugOutput("PeParser: savePeFileToHandle: Writing section %d of size 0x%x bytes.\n", i+1, dwWriteSize);
#endif
			if (!ProcessAccessHelp::writeMemoryToFile(FileHandle, listPeSection[i].sectionHeader.PointerToRawData, dwWriteSize, listPeSection[i].data))
			{
				retValue = false;
				break;
			}
			dwFileOffset += dwWriteSize;

			SectionDataWritten = true;

			if (listPeSection[i].dataSize < listPeSection[i].sectionHeader.SizeOfRawData) //padding
			{
				dwWriteSize = listPeSection[i].sectionHeader.SizeOfRawData - listPeSection[i].dataSize;

				if (!writeZeroMemoryToFile(FileHandle, dwFileOffset, dwWriteSize))
				{
					retValue = false;
					break;
				}
				dwFileOffset += dwWriteSize;
			}
		}
#ifdef DEBUG_COMMENTS
		else
			DebugOutput("PeParser: savePeFileToHandle: Nothing to write for section %d.\n", i+1);
#endif
	}

	//add overlay?
	if (overlaySize && overlayData)
	{
		dwWriteSize = overlaySize;
		if (!ProcessAccessHelp::writeMemoryToFile(FileHandle, dwFileOffset, dwWriteSize, overlayData))
		{
			retValue = false;
		}
		dwFileOffset += dwWriteSize;
	}

	//SetEndOfFile(FileHandle);
	dumpSize = dwFileOffset;

	// If only headers are written, fail
	// (this will allow a subsequent 'raw' memory dump)
	if (!SectionDataWritten)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("PeParser: savePeFileToHandle: No section data written!\n");
#endif
		return false;
	}

	return retValue;
}

bool PeParser::saveCompletePeToDisk(const CHAR *newFile)
{
	bool retValue = true;
	DWORD dwWriteSize = 0;
	char *CapeName;

	if (getNumberOfSections() != listPeSection.size())
	{
		return false;
	}

	if (listPeSection[getNumberOfSections()-1].sectionHeader.PointerToRawData < pNTHeader32->OptionalHeader.FileAlignment)
	{
		DebugOutput("PE Parser: Error - image seems incomplete: (%d sections, PointerToRawData: 0x%x) - dump failed.\n", getNumberOfSections(), listPeSection[getNumberOfSections()-1].sectionHeader.PointerToRawData);
		return false;
	}

	if (!openWriteFileHandle(newFile))
	{
#ifdef DEBUG_COMMENTS
		if (newFile)
			DebugOutput("saveCompletePeToDisk: savePeFileToDisk: Unable to create output file: %s.\n", newFile);
		else
			DebugOutput("saveCompletePeToDisk: savePeFileToDisk: Unable to create output file.\n");
#endif
		return false;
	}

#ifdef DEBUG_COMMENTS
	DebugOutput("Number of sections: %d, PointerToRawData: 0x%x, SizeOfRawData: 0x%x\n", getNumberOfSections(), listPeSection[getNumberOfSections() - 1].sectionHeader.PointerToRawData, listPeSection[getNumberOfSections() - 1].sectionHeader.SizeOfRawData);
#endif

	dwWriteSize = listPeSection[getNumberOfSections()-1].sectionHeader.PointerToRawData
		+ listPeSection[getNumberOfSections()-1].sectionHeader.SizeOfRawData;

	if (!ProcessAccessHelp::writeMemoryToFile(hFile, 0, dwWriteSize, (LPCVOID)moduleBaseAddress))
	{
		retValue = false;
	}

	SetEndOfFile(hFile);
	dumpSize = dwWriteSize;

	closeFileHandle();

	if (!newFile)
	{
		if (!GetFullPathName(GetTempName(), MAX_PATH, CapeOutputPath, NULL))
		{
			ErrorOutput("saveCompletePeToDisk: There was a problem obtaining the full file path");
			return false;
		}

		CapeName = GetName();

		if (MoveFile(CapeOutputPath, CapeName))
		{
			memset(CapeOutputPath, 0, MAX_PATH);

			if (!GetFullPathName(CapeName, MAX_PATH, CapeOutputPath, NULL))
			{
				ErrorOutput("saveCompletePeToDisk: There was a problem obtaining the full file path");
				return false;
			}

			CapeOutputFile(CapeOutputPath);
		}
		else
		{
			ErrorOutput("saveCompletePeToDisk: There was a problem renaming the file");

			if (!DeleteFile(CapeOutputPath))
			{
				ErrorOutput("saveCompletePeToDisk: There was a problem deleting the file: %s", CapeOutputPath);
			}

			return false;
		}
	}

	return retValue;
}

bool PeParser::saveCompletePeToHandle(HANDLE FileHandle)
{
	DWORD dwWriteSize = 0;

	if (getNumberOfSections() != listPeSection.size())
	{
		return false;
	}

	if (listPeSection[getNumberOfSections()-1].sectionHeader.PointerToRawData < pNTHeader32->OptionalHeader.FileAlignment
		|| listPeSection[getNumberOfSections()-1].sectionHeader.SizeOfRawData < pNTHeader32->OptionalHeader.FileAlignment)
	{
		DebugOutput("PE Parser: Error - image seems incomplete: (%d sections, PointerToRawData: 0x%x, SizeOfRawData: 0x%x) - dump failed.\n", getNumberOfSections(), listPeSection[getNumberOfSections()-1].sectionHeader.PointerToRawData, listPeSection[getNumberOfSections()-1].sectionHeader.SizeOfRawData);
		return false;
	}

#ifdef DEBUG_COMMENTS
	DebugOutput("Number of sections: %d, PointerToRawData: 0x%x, SizeOfRawData: 0x%x\n", getNumberOfSections(), listPeSection[getNumberOfSections() - 1].sectionHeader.PointerToRawData, listPeSection[getNumberOfSections() - 1].sectionHeader.SizeOfRawData);
#endif

	dwWriteSize = listPeSection[getNumberOfSections()-1].sectionHeader.PointerToRawData
		+ listPeSection[getNumberOfSections()-1].sectionHeader.SizeOfRawData;

	if (!ProcessAccessHelp::writeMemoryToFile(FileHandle, 0, dwWriteSize, (LPCVOID)moduleBaseAddress))
	{
		DebugOutput("saveCompletePeToHandle: writeMemoryToFile failed.\n");
		return false;
	}

	//SetEndOfFile(FileHandle);
	dumpSize = dwWriteSize;

	return true;
}

bool PeParser::writeZeroMemoryToFile(HANDLE hFile, DWORD fileOffset, DWORD size)
{
	bool retValue = false;
	PVOID zeromemory = calloc(size, 1);

	if (zeromemory)
	{
		retValue = ProcessAccessHelp::writeMemoryToFile(hFile, fileOffset, size, zeromemory);
		free(zeromemory);
	}

	return retValue;
}

void PeParser::removeDosStub()
{
	if (pDosHeader)
	{
		dosStubSize = 0;
		pDosStub = 0; //must not delete []
		pDosHeader->e_lfanew = sizeof(IMAGE_DOS_HEADER);
	}
}

bool PeParser::readPeSectionFromFile(DWORD readOffset, PeFileSection & peFileSection)
{
	DWORD bytesRead = 0;

	peFileSection.data = new BYTE[peFileSection.dataSize];

	SetFilePointer(hFile, readOffset, 0, FILE_BEGIN);

	return (ReadFile(hFile, peFileSection.data, peFileSection.dataSize, &bytesRead, 0) != FALSE);
}

bool PeParser::readPeSectionFromProcess(DWORD_PTR readOffset, PeFileSection & peFileSection)
{
	peFileSection.data = new BYTE[peFileSection.dataSize];

	return ProcessAccessHelp::readMemoryPartlyFromProcess(readOffset, peFileSection.dataSize, peFileSection.data);
}

DWORD PeParser::alignValue(DWORD badValue, DWORD alignTo)
{
	return (((badValue + alignTo - 1) / alignTo) * alignTo);
}

bool PeParser::addNewLastSection(const CHAR * sectionName, DWORD sectionSize, BYTE * sectionData)
{
	size_t nameLength = strlen(sectionName);
	DWORD fileAlignment = 0, sectionAlignment = 0;
	PeFileSection peFileSection;

	if (nameLength > IMAGE_SIZEOF_SHORT_NAME)
	{
		return false;
	}

	if (isPE32())
	{
		fileAlignment = pNTHeader32->OptionalHeader.FileAlignment;
		sectionAlignment = pNTHeader32->OptionalHeader.SectionAlignment;
	}
	else
	{
		fileAlignment = pNTHeader64->OptionalHeader.FileAlignment;
		sectionAlignment = pNTHeader64->OptionalHeader.SectionAlignment;
	}

	memcpy_s(peFileSection.sectionHeader.Name, IMAGE_SIZEOF_SHORT_NAME, sectionName, nameLength);

	//last section doesn't need SizeOfRawData alignment
	peFileSection.sectionHeader.SizeOfRawData = sectionSize; //alignValue(sectionSize, fileAlignment);
	peFileSection.sectionHeader.Misc.VirtualSize = alignValue(sectionSize, sectionAlignment);

	peFileSection.sectionHeader.PointerToRawData = alignValue(getSectionHeaderBasedFileSize(), fileAlignment);
	peFileSection.sectionHeader.VirtualAddress = alignValue(getSectionHeaderBasedSizeOfImage(), sectionAlignment);

	peFileSection.sectionHeader.Characteristics = IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE|IMAGE_SCN_CNT_CODE|IMAGE_SCN_CNT_INITIALIZED_DATA;

	peFileSection.normalSize = peFileSection.sectionHeader.SizeOfRawData;
	peFileSection.dataSize = peFileSection.sectionHeader.SizeOfRawData;

	if (sectionData == 0)
	{
		peFileSection.data = new BYTE[peFileSection.sectionHeader.SizeOfRawData];
		ZeroMemory(peFileSection.data , peFileSection.sectionHeader.SizeOfRawData);
	}
	else
	{
		peFileSection.data = sectionData;
	}

	listPeSection.push_back(peFileSection);

	setNumberOfSections(getNumberOfSections() + 1);

	return true;
}

DWORD_PTR PeParser::getStandardImagebase()
{
	if (isPE32())
	{
		return pNTHeader32->OptionalHeader.ImageBase;
	}
	else
	{
		return (DWORD_PTR)pNTHeader64->OptionalHeader.ImageBase;
	}
}

int PeParser::convertRVAToOffsetVectorIndex(DWORD_PTR dwRVA)
{
	for (WORD i = 0; i < getNumberOfSections(); i++)
	{
		if ((listPeSection[i].sectionHeader.VirtualAddress <= dwRVA) && ((listPeSection[i].sectionHeader.VirtualAddress + listPeSection[i].sectionHeader.Misc.VirtualSize) > dwRVA))
		{
			return i;
		}
	}

	return -1;
}

DWORD_PTR PeParser::convertRVAToOffsetVector(DWORD_PTR dwRVA)
{
	for (WORD i = 0; i < getNumberOfSections(); i++)
	{
		if ((listPeSection[i].sectionHeader.VirtualAddress <= dwRVA) && ((listPeSection[i].sectionHeader.VirtualAddress + listPeSection[i].sectionHeader.Misc.VirtualSize) > dwRVA))
		{
			return ((dwRVA - listPeSection[i].sectionHeader.VirtualAddress) + listPeSection[i].sectionHeader.PointerToRawData);
		}
	}

	return 0;
}

DWORD_PTR PeParser::convertRVAToOffsetRelative(DWORD_PTR dwRVA)
{
	for (WORD i = 0; i < getNumberOfSections(); i++)
	{
		if ((listPeSection[i].sectionHeader.VirtualAddress <= dwRVA) && ((listPeSection[i].sectionHeader.VirtualAddress + listPeSection[i].sectionHeader.Misc.VirtualSize) > dwRVA))
		{
			return (dwRVA - listPeSection[i].sectionHeader.VirtualAddress);
		}
	}

	return 0;
}

DWORD_PTR PeParser::convertOffsetToRVAVector(DWORD_PTR dwOffset)
{
	for (WORD i = 0; i < getNumberOfSections(); i++)
	{
		if ((listPeSection[i].sectionHeader.PointerToRawData <= dwOffset) && ((listPeSection[i].sectionHeader.PointerToRawData + listPeSection[i].sectionHeader.SizeOfRawData) > dwOffset))
		{
			return ((dwOffset - listPeSection[i].sectionHeader.PointerToRawData) + listPeSection[i].sectionHeader.VirtualAddress);
		}
	}

	return 0;
}

BOOL PeParser::reBasePEImage(DWORD_PTR NewBase)
{
	PIMAGE_BASE_RELOCATION Relocations;
	PIMAGE_NT_HEADERS NtHeaders;
	DWORD_PTR Delta;
	ULONG RelocationSize = 0, Size = 0;

	if (isPE32())
		NtHeaders = (PIMAGE_NT_HEADERS)pNTHeader32;
	else
		NtHeaders = (PIMAGE_NT_HEADERS)pNTHeader64;

	if (NewBase & 0xFFFF)
	{
		DebugOutput("reBasePEImage: Error, invalid image base 0x%p.\n", NewBase);
		return FALSE;
	}

	if (NtHeaders->OptionalHeader.ImageBase == NewBase)
	{
		DebugOutput("reBasePEImage: Error, image base already 0x%p.\n", NewBase);
		return FALSE;
	}

	if (!NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
	{
#ifdef DEBUG_COMMENTS
		DebugOutput("reBasePEImage: Image has no relocation section.\n");
#endif
		return FALSE;
	}

	Relocations = (PIMAGE_BASE_RELOCATION)((PBYTE)NewBase + NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	RelocationSize = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	Delta = NewBase - NtHeaders->OptionalHeader.ImageBase;
#ifdef DEBUG_COMMENTS
	DebugOutput("reBasePEImage: Relocations set to 0x%p, size 0x%x, Delta 0x%p, ImageBase 0x%p\n", Relocations, RelocationSize, Delta, NtHeaders->OptionalHeader.ImageBase);
#endif

	__try
	{
		while (RelocationSize > Size && Relocations->SizeOfBlock)
		{
			ULONG NumOfRelocs = (Relocations->SizeOfBlock - 8) / 2;
			PUSHORT Reloc = (PUSHORT)((PUCHAR)Relocations + 8);

#ifdef DEBUG_COMMENTS
			DebugOutput("reBasePEImage: VirtualAddress: 0x%.8x; Number of Relocs: %d; Size: %d\n", Relocations->VirtualAddress, NumOfRelocs, Relocations->SizeOfBlock);
#endif
			for (ULONG i = 0; i < NumOfRelocs; i++)
			{
				if (Reloc[i] > 0)
				{
					PUCHAR *RVA = (PUCHAR*)((PBYTE)(DWORD_PTR)Relocations->VirtualAddress + (Reloc[i] & 0x0FFF));
#ifndef _WIN64
					PUCHAR VA = (PUCHAR)*((PULONG)(listPeSection[convertRVAToOffsetVectorIndex((DWORD_PTR)RVA)].data + convertRVAToOffsetRelative((DWORD_PTR)RVA)));
					if ((unsigned int)VA - NewBase < (unsigned int)NtHeaders->OptionalHeader.SizeOfImage)
						*((PULONG)(listPeSection[convertRVAToOffsetVectorIndex((DWORD_PTR)RVA)].data + convertRVAToOffsetRelative((DWORD_PTR)RVA))) -= (ULONG)((ULONGLONG)Delta);
#else
					PULONGLONG VA = (PULONGLONG)*((PULONGLONG)(listPeSection[convertRVAToOffsetVectorIndex((DWORD_PTR)RVA)].data + convertRVAToOffsetRelative((DWORD_PTR)RVA)));
					if ((ULONGLONG)VA - NewBase < (ULONGLONG)NtHeaders->OptionalHeader.SizeOfImage)
						*((PULONGLONG)(listPeSection[convertRVAToOffsetVectorIndex((DWORD_PTR)RVA)].data + convertRVAToOffsetRelative((DWORD_PTR)RVA))) -= (ULONGLONG)Delta;
#endif
				}
			}

			Relocations = (PIMAGE_BASE_RELOCATION)((PUCHAR)Relocations + Relocations->SizeOfBlock);
			Size += Relocations->SizeOfBlock;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DebugOutput("reBasePEImage: Exception rebasing image from 0x%p to 0x%p.\n", NewBase, NtHeaders->OptionalHeader.ImageBase);
		return FALSE;
	}

	return TRUE;
}

void PeParser::fixPeHeader()
{
	DWORD dwSize = pDosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);

	if (isPE32())
	{
		//delete bound import directories
		pNTHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
		pNTHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;

		//max 16, zeroing possible garbage values
		for (DWORD i = pNTHeader32->OptionalHeader.NumberOfRvaAndSizes; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
		{
			pNTHeader32->OptionalHeader.DataDirectory[i].Size = 0;
			pNTHeader32->OptionalHeader.DataDirectory[i].VirtualAddress = 0;
		}

		pNTHeader32->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
		pNTHeader32->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);

		pNTHeader32->OptionalHeader.SizeOfImage = getSectionHeaderBasedSizeOfImage();

		pNTHeader32->OptionalHeader.SizeOfHeaders = alignValue(dwSize + pNTHeader32->FileHeader.SizeOfOptionalHeader + (getNumberOfSections() * sizeof(IMAGE_SECTION_HEADER)), pNTHeader32->OptionalHeader.FileAlignment);

//		if (moduleBaseAddress && moduleBaseAddress != pNTHeader32->OptionalHeader.ImageBase)
//		{
//			pNTHeader32->OptionalHeader.ImageBase = (DWORD)moduleBaseAddress;
//#ifdef DEBUG_COMMENTS
//			DebugOutput("fixPeHeader: ImageBase set to 0x%x.\n", pNTHeader32->OptionalHeader.ImageBase);
//#endif
//		}
	}
	else
	{
		//delete bound import directories
		pNTHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
		pNTHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;

		//max 16, zeroing possible garbage values
		for (DWORD i = pNTHeader64->OptionalHeader.NumberOfRvaAndSizes; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
		{
			pNTHeader64->OptionalHeader.DataDirectory[i].Size = 0;
			pNTHeader64->OptionalHeader.DataDirectory[i].VirtualAddress = 0;
		}

		pNTHeader64->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
		pNTHeader64->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);

		pNTHeader64->OptionalHeader.SizeOfImage = getSectionHeaderBasedSizeOfImage();

		pNTHeader64->OptionalHeader.SizeOfHeaders = alignValue(dwSize + pNTHeader64->FileHeader.SizeOfOptionalHeader + (getNumberOfSections() * sizeof(IMAGE_SECTION_HEADER)), pNTHeader64->OptionalHeader.FileAlignment);

//		if (moduleBaseAddress && moduleBaseAddress != pNTHeader64->OptionalHeader.ImageBase)
//		{
//				pNTHeader64->OptionalHeader.ImageBase = (DWORD)moduleBaseAddress;
//#ifdef DEBUG_COMMENTS
//			DebugOutput("fixPeHeader: ImageBase set to 0x%x.\n", pNTHeader64->OptionalHeader.ImageBase);
//#endif
//		}
	}

	removeIatDirectory();
}

void PeParser::removeIatDirectory()
{
	DWORD searchAddress = 0;

	if (isPE32())
	{
		searchAddress = pNTHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;

		pNTHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
		pNTHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
	}
	else
	{
		searchAddress = pNTHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;

		pNTHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
		pNTHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
	}

	if (searchAddress)
	{
		for (WORD i = 0; i < getNumberOfSections(); i++)
		{
			if ((listPeSection[i].sectionHeader.VirtualAddress <= searchAddress) && ((listPeSection[i].sectionHeader.VirtualAddress + listPeSection[i].sectionHeader.Misc.VirtualSize) > searchAddress))
			{
				//section must be read and writable
				listPeSection[i].sectionHeader.Characteristics |= IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE;
			}
		}
	}
}

void PeParser::setDefaultFileAlignment()
{
	if (isPE32())
	{
		pNTHeader32->OptionalHeader.FileAlignment = FileAlignmentConstant;
	}
	else
	{
		pNTHeader64->OptionalHeader.FileAlignment = FileAlignmentConstant;
	}
}

bool PeFileSectionSortByPointerToRawData(const PeFileSection& d1, const PeFileSection& d2)
{
	return d1.sectionHeader.PointerToRawData < d2.sectionHeader.PointerToRawData;
}

bool PeFileSectionSortByVirtualAddress(const PeFileSection& d1, const PeFileSection& d2)
{
	return d1.sectionHeader.VirtualAddress < d2.sectionHeader.VirtualAddress;
}

void PeParser::alignAllSectionHeaders()
{
	unsigned int NumberOfSections;
	DWORD sectionAlignment = 0;
	DWORD fileAlignment = 0;
	DWORD newFileSize = 0;

	if (isPE32())
	{
		sectionAlignment = pNTHeader32->OptionalHeader.SectionAlignment;
		fileAlignment = pNTHeader32->OptionalHeader.FileAlignment;
	}
	else
	{
		sectionAlignment = pNTHeader64->OptionalHeader.SectionAlignment;
		fileAlignment = pNTHeader64->OptionalHeader.FileAlignment;
	}

	NumberOfSections = getNumberOfSections();

	std::sort(listPeSection.begin(), listPeSection.end(), PeFileSectionSortByVirtualAddress); //sort by VirtualAddress ascending

	newFileSize = pDosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + pNTHeader32->FileHeader.SizeOfOptionalHeader + (NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

	newFileSize += 0x80; // to more closely resemble typical PE files with dos stub

	for (WORD i = 0; i < NumberOfSections; i++)
	{
		listPeSection[i].sectionHeader.VirtualAddress = alignValue(listPeSection[i].sectionHeader.VirtualAddress, sectionAlignment);

		listPeSection[i].sectionHeader.PointerToRawData = alignValue(newFileSize, fileAlignment);
		listPeSection[i].sectionHeader.SizeOfRawData = alignValue(listPeSection[i].dataSize, fileAlignment);

		newFileSize = listPeSection[i].sectionHeader.PointerToRawData + listPeSection[i].sectionHeader.SizeOfRawData;
	}
}

bool PeParser::dumpProcess(DWORD_PTR modBase, DWORD_PTR entryPoint, const CHAR * dumpFilePath)
{
	moduleBaseAddress = modBase;

#ifdef DEBUG_COMMENTS
	DebugOutput("DumpProcess: called with modBase = 0x%x.\n", modBase);
#endif

	if (!readPeSectionsFromProcess())
	{
		DebugOutput("DumpProcess: There was a problem reading one or more sections, dump failed.\n");
		return false;
	}
#ifdef DEBUG_COMMENTS
	else
		DebugOutput("DumpProcess: Successfully read all sections.\n");
#endif
	setDefaultFileAlignment();

	if (entryPoint)
		setEntryPointVa(entryPoint);

	alignAllSectionHeaders();

	fixPeHeader();

	getFileOverlay();

#ifdef DEBUG_COMMENTS
	DebugOutput("DumpProcess: Fixups complete, about to save to disk.\n");
#endif
	return savePeFileToDisk(dumpFilePath);
}

bool PeParser::dumpProcess(DWORD_PTR modBase, DWORD_PTR entryPoint, const CHAR * dumpFilePath, std::vector<PeSection> & sectionList)
{
	if (listPeSection.size() == sectionList.size())
	{
		for (int i = (getNumberOfSections() - 1); i >= 0; i--)
		{
			if (!sectionList[i].isDumped)
			{
				listPeSection.erase(listPeSection.begin() + i);
				setNumberOfSections(getNumberOfSections() - 1);
			}
			else
			{
				listPeSection[i].sectionHeader.Misc.VirtualSize = sectionList[i].virtualSize;
				listPeSection[i].sectionHeader.SizeOfRawData = sectionList[i].rawSize;
				listPeSection[i].sectionHeader.Characteristics = sectionList[i].characteristics;
			}
		}
	}

	return dumpProcess(modBase, entryPoint, dumpFilePath);
}

bool PeParser::dumpProcessToHandle(DWORD_PTR modBase, DWORD_PTR entryPoint, HANDLE FileHandle)
{
	moduleBaseAddress = modBase;

#ifdef DEBUG_COMMENTS
	DebugOutput("DumpProcess: called with modBase = 0x%x.\n", modBase);
#endif

	if (!readPeSectionsFromProcess())
		DebugOutput("DumpProcess: There was a problem reading one or more sections, the dump may be incomplete.\n");
#ifdef DEBUG_COMMENTS
	else
		DebugOutput("DumpProcess: Successfully read all sections.\n");
#endif
	setDefaultFileAlignment();

	if (entryPoint)
		setEntryPointVa(entryPoint);

	alignAllSectionHeaders();

	fixPeHeader();

	getFileOverlay();

#ifdef DEBUG_COMMENTS
	DebugOutput("DumpProcess: Fixups complete, about to save to disk.\n");
#endif
	return savePeFileToHandle(FileHandle);
}

void PeParser::setEntryPointVa(DWORD_PTR entryPoint)
{
	DWORD entryPointRva = (DWORD)(entryPoint - moduleBaseAddress);

	setEntryPointRva(entryPointRva);
}

void PeParser::setEntryPointRva(DWORD entryPoint)
{
	if (isPE32())
	{
		pNTHeader32->OptionalHeader.AddressOfEntryPoint = entryPoint;
	}
	else if (isPE64())
	{
		pNTHeader64->OptionalHeader.AddressOfEntryPoint = entryPoint;
	}
}

bool PeParser::getFileOverlay()
{
	DWORD numberOfBytesRead;
	bool retValue = false;

	if (!hasOverlayData())
	{
		return false;
	}

	if (openFileHandle())
	{
		DWORD overlayOffset = getSectionHeaderBasedFileSize();
		DWORD fileSize = (DWORD)ProcessAccessHelp::getFileSize(hFile);
		overlaySize = fileSize - overlayOffset;

		overlayData = new BYTE[overlaySize];

		SetFilePointer(hFile, overlayOffset, 0, FILE_BEGIN);

		if (ReadFile(hFile, overlayData, overlaySize, &numberOfBytesRead, 0))
		{
			retValue = true;
		}

		closeFileHandle();
	}

	return retValue;
}

bool PeParser::hasOverlayData()
{
	if (!filename)
		return false;

	if (isValidPeFile())
	{
		DWORD fileSize = (DWORD)ProcessAccessHelp::getFileSize(filename);

		return (fileSize > getSectionHeaderBasedFileSize());
	}
	else
	{
		return false;
	}
}

bool PeParser::updatePeHeaderChecksum(const CHAR * targetFile, DWORD fileSize)
{
	PIMAGE_NT_HEADERS32 pNTHeader32 = 0;
	PIMAGE_NT_HEADERS64 pNTHeader64 = 0;
	DWORD headerSum = 0;
	DWORD checkSum = 0;
	bool retValue = false;

	if (!fileSize)
		return retValue;

	HANDLE hFileToMap = CreateFile(targetFile, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	if(hFileToMap != INVALID_HANDLE_VALUE)
	{
		HANDLE hMappedFile = CreateFileMapping(hFileToMap, 0, PAGE_READWRITE, 0, 0, 0);
		if(hMappedFile)
		{
			if (GetLastError() != ERROR_ALREADY_EXISTS)
			{
				LPVOID addrMappedDll = MapViewOfFile(hMappedFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);

				if (addrMappedDll)
				{
					pNTHeader32 = (PIMAGE_NT_HEADERS32)CheckSumMappedFile(addrMappedDll, fileSize, &headerSum, &checkSum);

					if (pNTHeader32)
					{
						if (pNTHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
						{
							pNTHeader64 = (PIMAGE_NT_HEADERS64)pNTHeader32;
							pNTHeader64->OptionalHeader.CheckSum = checkSum;
						}
						else
						{
							pNTHeader32->OptionalHeader.CheckSum = checkSum;
						}

						retValue = true;
					}

					UnmapViewOfFile(addrMappedDll);
				}
			}
			CloseHandle(hMappedFile);
		}
		CloseHandle(hFileToMap);
	}

	return retValue;
}

BYTE * PeParser::getSectionMemoryByIndex(int index)
{
	return listPeSection[index].data;
}

DWORD PeParser::getSectionMemorySizeByIndex(int index)
{
	return listPeSection[index].dataSize;
}

DWORD PeParser::getSectionAddressRVAByIndex( int index )
{
	return listPeSection[index].sectionHeader.VirtualAddress;
}

PIMAGE_NT_HEADERS PeParser::getCurrentNtHeader()
{
#ifdef _WIN64
	return pNTHeader64;
#else
	return pNTHeader32;
#endif
}