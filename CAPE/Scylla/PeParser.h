#pragma once

#include <windows.h>
#include <vector>
//#include "DumpSectionGui.h"

extern "C" char* GetName();
extern "C" char* GetTempName();

class PeFileSection {
public:
	IMAGE_SECTION_HEADER sectionHeader;
	BYTE * data;
	DWORD dataSize;
	DWORD normalSize;

	PeFileSection()
	{
		ZeroMemory(&sectionHeader, sizeof(IMAGE_SECTION_HEADER));
		data = 0;
		dataSize = 0;
		normalSize = 0;
	}
};

class PeSection
{
public:
	CHAR name[IMAGE_SIZEOF_SHORT_NAME + 1];
	DWORD_PTR virtualAddress;
	DWORD  virtualSize;
	DWORD  rawAddress;
	DWORD  rawSize;
	DWORD characteristics;

	bool isDumped;

	bool highlightVirtualSize();
};

class PeParser
{
public:
	PeParser(const CHAR * file, bool readSectionHeaders = true);
	PeParser(const DWORD_PTR moduleBase, bool readSectionHeaders = true);

	~PeParser();

	bool isValidPeFile();
	bool isPE64();
	bool isPE32();

	bool isTargetFileSamePeFormat();

	WORD getNumberOfSections();
	std::vector<PeFileSection> & getSectionHeaderList();

	bool hasExportDirectory();
	bool hasTLSDirectory();
	bool hasRelocationDirectory();
	bool hasOverlayData();

	DWORD getEntryPoint();
	char* getExportDirectory();

	bool getSectionNameUnicode(const int sectionIndex, CHAR * output, const int outputLen);

	DWORD getSectionHeaderBasedFileSize();
	DWORD getSectionHeaderBasedSizeOfImage();

	bool readPeSectionsFromProcess();
	bool readPeSectionsFromFile();
	bool savePeFileToDisk(const CHAR * newFile);
	bool savePeFileToHandle(HANDLE FileHandle);
	bool saveCompletePeToDisk(const CHAR * newFile);
	bool saveCompletePeToHandle(HANDLE FileHandle);
	void removeDosStub();
	void alignAllSectionHeaders();
	void fixPeHeader();
	void setDefaultFileAlignment();
	bool dumpProcess(DWORD_PTR modBase, DWORD_PTR entryPoint, const CHAR * dumpFilePath);
	bool dumpProcess(DWORD_PTR modBase, DWORD_PTR entryPoint, const CHAR * dumpFilePath, std::vector<PeSection> & sectionList);
	bool dumpProcessToHandle(DWORD_PTR modBase, DWORD_PTR entryPoint, HANDLE FileHandle);

	void setEntryPointVa(DWORD_PTR entryPoint);
	void setEntryPointRva(DWORD entryPoint);

	static bool updatePeHeaderChecksum(const CHAR * targetFile, DWORD fileSize);
	BYTE * getSectionMemoryByIndex(int index);
	DWORD getSectionMemorySizeByIndex(int index);
	int convertRVAToOffsetVectorIndex(DWORD_PTR dwRVA);
	DWORD_PTR convertOffsetToRVAVector(DWORD_PTR dwOffset);
	DWORD_PTR convertRVAToOffsetVector(DWORD_PTR dwRVA);
	DWORD_PTR convertRVAToOffsetRelative(DWORD_PTR dwRVA);
	DWORD getSectionAddressRVAByIndex( int index );
	BOOL reBasePEImage(DWORD_PTR NewBase);

	PIMAGE_NT_HEADERS getCurrentNtHeader();
	std::vector<PeFileSection> listPeSection;

	DWORD dumpSize;

protected:
	PeParser();


	static const DWORD FileAlignmentConstant = 0x200;

	const CHAR * filename;
	DWORD_PTR moduleBaseAddress;

	/************************************************************************/
	/* PE FILE															  */
	/*																	  */
	/*  IMAGE_DOS_HEADER	  64   0x40									 */
	/*	IMAGE_NT_HEADERS32   248   0xF8									 */
	/*	IMAGE_NT_HEADERS64   264  0x108									 */
	/*	IMAGE_SECTION_HEADER  40   0x28									 */
	/************************************************************************/

	PIMAGE_DOS_HEADER pDosHeader;
	BYTE * pDosStub; //between dos header and section header
	DWORD dosStubSize;
	PIMAGE_NT_HEADERS32 pNTHeader32;
	PIMAGE_NT_HEADERS64 pNTHeader64;
	BYTE * overlayData;
	DWORD overlaySize;
	/************************************************************************/

	BYTE *fileMemory, *headerMemory;

	HANDLE hFile;
	HANDLE hInfoFile;
	DWORD fileSize;

	SIZE_T SizeOfSlackData;
	BYTE* SlackData;

	bool readPeHeaderFromFile(bool readSectionHeaders);
	bool readPeHeaderFromProcess(bool readSectionHeaders);

	bool hasDirectory(const int directoryIndex);
	bool getSectionHeaders();
	void getDosAndNtHeader(BYTE * memory, LONG size);
	DWORD calcCorrectPeHeaderSize( bool readSectionHeaders );
	DWORD getInitialHeaderReadSize( bool readSectionHeaders );
	bool openFileHandle();
	void closeFileHandle();
	void initClass();
	
	DWORD isMemoryNotNull( BYTE * data, int dataSize );
	bool openWriteFileHandle( const CHAR * newFile );
	bool writeZeroMemoryToFile(HANDLE hFile, DWORD fileOffset, DWORD size);

	bool readPeSectionFromFile( DWORD readOffset, PeFileSection & peFileSection );
	bool readPeSectionFromProcess( DWORD_PTR readOffset, PeFileSection & peFileSection );

	bool readSectionFromProcess(const DWORD_PTR readOffset, PeFileSection & peFileSection );
	bool readSectionFromFile(const DWORD readOffset, PeFileSection & peFileSection );
	bool readSectionFrom(const DWORD_PTR readOffset, PeFileSection & peFileSection, const bool isProcess);

	
	DWORD_PTR getStandardImagebase();

	bool addNewLastSection(const CHAR * sectionName, DWORD sectionSize, BYTE * sectionData);
	DWORD alignValue(DWORD badValue, DWORD alignTo);

	void setNumberOfSections(WORD numberOfSections);
	
	void removeIatDirectory();
	bool getFileOverlay();
};
