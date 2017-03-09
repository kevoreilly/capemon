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

extern "C" void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern "C" void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);

char *CapeOutputPath;

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
extern "C" int ScyllaDumpCurrentProcess(DWORD NewOEP, BOOL CapeFile)
//**************************************************************************************
{
	DWORD_PTR entrypoint = 0;
	PeParser * peFile = 0;
    DWORD ModuleBase;
    
    ModuleBase = (DWORD)(ULONG_PTR)GetModuleHandle(NULL);
	ScyllaInitCurrentProcess();
    
    DoOutputDebugString("DumpCurrentProcess: Instantiating PeParser with address: 0x%x", ModuleBase);

    peFile = new PeParser(ModuleBase, TRUE);

    if (peFile->isValidPeFile())
    {
        if (NewOEP)
            entrypoint = NewOEP;
        else
            entrypoint = peFile->getEntryPoint() + ModuleBase;
            
        DoOutputDebugString("DumpCurrentProcess: Module entry point VA is 0x%x", entrypoint);
    
        if (peFile->dumpProcess(ModuleBase, entrypoint, NULL))
        {
            DoOutputDebugString("DumpCurrentProcess: Module image dump success.\n");
        }
        else
        {
            DoOutputErrorString("DumpCurrentProcess: Error - Cannot dump image");
            delete peFile;
            return 0;
        }
    }
    else
    {
        DoOutputDebugString("DumpCurrentProcess: Invalid PE file or invalid PE header.");
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
extern "C" int ScyllaDumpProcess(HANDLE hProcess, DWORD_PTR ModuleBase, DWORD NewOEP, BOOL CapeFile)
//**************************************************************************************
{
	DWORD_PTR entrypoint = 0;
	PeParser * peFile = 0;

	ScyllaInit(hProcess);
    
    DoOutputDebugString("DumpProcess: Instantiating PeParser with address: 0x%x", ModuleBase);

    peFile = new PeParser(ModuleBase, TRUE);

    if (peFile->isValidPeFile())
    {
        if (NewOEP)
            entrypoint = NewOEP;
        else
            entrypoint = peFile->getEntryPoint();

        entrypoint = entrypoint + ModuleBase;
        
        DoOutputDebugString("DumpProcess: Module entry point VA is 0x%x", entrypoint);
        
        if (peFile->dumpProcess(ModuleBase, entrypoint, NULL))
        {
            DoOutputDebugString("DumpProcess: Module image dump success");
        }
        else
        {
            DoOutputErrorString("DumpProcess: Error - Cannot dump image");
            delete peFile;
            return 0;
        }
    }
    else
    {
        DoOutputDebugString("DumpProcess: Invalid PE file or invalid PE header.");
        delete peFile;
        return 0;
    }

    delete peFile;

    return 1;
}

//**************************************************************************************
extern "C" int ScyllaDumpPE(DWORD_PTR Buffer)
//**************************************************************************************
{
	DWORD_PTR entrypoint = 0;
	PeParser * peFile = 0;

	NativeWinApi::initialize();

	ProcessAccessHelp::setCurrentProcessAsTarget();
   
    DoOutputDebugString("DumpPE: Instantiating PeParser with address: 0x%x", Buffer);

    peFile = new PeParser((DWORD_PTR)Buffer, TRUE);
    
    if (peFile->isValidPeFile())
    {        
        if (peFile->saveCompletePeToDisk(NULL))
        {
            DoOutputDebugString("DumpPE: PE file in memory dumped successfully.");
        }
        else
        {
            DoOutputDebugString("DumpPE: Error: Cannot dump PE file from memory.");
            delete peFile;
            return 0;
        }
    }
    else
    {
        DoOutputDebugString("DumpPE: Error: Invalid PE file or invalid PE header.");
        delete peFile;
        return 0;
    }

    delete peFile;

    return 1;
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
extern "C" int ScyllaDumpCurrentProcessFixImports(DWORD NewOEP, BOOL CapeFile)
//**************************************************************************************
{
    DWORD addressIAT, sizeIAT;
    BOOL IAT_Found, AdvancedIATSearch = FALSE;
    bool isAfter;
    DWORD ModuleBase;
    
    IATSearch iatSearch;
	ApiReader apiReader;
	IATReferenceScan iatReferenceScan;
	ImportsHandling importsHandling;

	DWORD_PTR entrypointRVA = 0;
	PeParser * peFile = 0;

    ModuleBase = (DWORD)(ULONG_PTR)GetModuleHandle(NULL);
    
    //Clear stuff first
    ProcessAccessHelp::ownModuleList.clear();
    apiReader.clearAll();
    importsHandling.clearAllImports();

	NativeWinApi::initialize();

    // Instantiate required objects
    ProcessAccessHelp::setCurrentProcessAsTarget();

    ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::ownModuleList);
    ProcessAccessHelp::moduleList = ProcessAccessHelp::ownModuleList;
    ProcessAccessHelp::targetImageBase = ModuleBase;
    ProcessAccessHelp::getSizeOfImageCurrentProcess();
    
    // Enumerate DLLs and imported functions
    apiReader.readApisFromModuleList();

    DoOutputDebugString("DumpCurrentProcessFixImports: Instantiating PeParser with address: 0x%x", ModuleBase);

    peFile = new PeParser(ModuleBase, TRUE);

    if (peFile->isValidPeFile())
    {
        if (NewOEP)
            entrypointRVA = NewOEP - ModuleBase;
        else
            entrypointRVA = peFile->getEntryPoint();

        DoOutputDebugString("DumpCurrentProcessFixImports: Module entry point VA is 0x%x", ModuleBase + entrypointRVA);
        
        CapeOutputPath = GetName();
        
        //  Let's dump then fix the dump on disk
        if (peFile->dumpProcess((DWORD_PTR)ModuleBase, (DWORD)ModuleBase + entrypointRVA, CapeOutputPath))
        {
            DoOutputDebugString("DumpCurrentProcessFixImports: Module image dump success %s", CapeOutputPath);
        }
        
        //  IAT search - we'll try the simple search first
        IAT_Found = iatSearch.searchImportAddressTableInProcess((DWORD_PTR)ModuleBase + entrypointRVA, (DWORD_PTR*)&addressIAT, &sizeIAT, FALSE);
        
        //  Let's try the advanced search now
        if (IAT_Found == FALSE)
            IAT_Found = iatSearch.searchImportAddressTableInProcess((DWORD_PTR)ModuleBase + entrypointRVA, (DWORD_PTR*)&addressIAT, &sizeIAT, TRUE);
        
        if (addressIAT && sizeIAT)
        {
            DoOutputDebugString("Found IAT: 0x%x, size: 0x%x", addressIAT, sizeIAT);
            
            apiReader.readAndParseIAT(addressIAT, sizeIAT, importsHandling.moduleList);
            importsHandling.scanAndFixModuleList();
            
    		if (SCAN_DIRECT_IMPORTS)
    		{
                iatReferenceScan.ScanForDirectImports = TRUE;
                iatReferenceScan.ScanForNormalImports = FALSE;
                
                iatReferenceScan.apiReader = &apiReader;
                iatReferenceScan.startScan(ProcessAccessHelp::targetImageBase, (DWORD)ProcessAccessHelp::targetSizeOfImage, addressIAT, sizeIAT);

                DoOutputDebugString("Direct imports - Found %d possible direct imports with %d unique APIs", iatReferenceScan.numberOfFoundDirectImports(), iatReferenceScan.numberOfFoundUniqueDirectImports());

                if (iatReferenceScan.numberOfFoundDirectImports() > 0)
                {
                    if (iatReferenceScan.numberOfDirectImportApisNotInIat() > 0)
                    {
                        DoOutputDebugString("Direct imports - Found %d additional api addresses", iatReferenceScan.numberOfDirectImportApisNotInIat());
                        DWORD sizeIatNew = iatReferenceScan.addAdditionalApisToList();
                        DoOutputDebugString("Direct imports - Old IAT size 0x%08x new IAT size 0x%08x", sizeIAT, sizeIatNew);
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
                        DoOutputDebugString("Direct imports patched.");
                    }
                }
    		}

            if (isIATOutsidePeImage(addressIAT))
            {
                DoOutputDebugString("Warning - IAT is not inside the PE image, requires rebasing.");
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
                DoOutputDebugString("Import table rebuild failed.\n");
            }           
        }
        else
        {
            DoOutputDebugString("Warning: Unable to find IAT in scan.\n");
        }
    
    }
    else
    {
        DoOutputDebugString("Error: Invalid PE file or invalid PE header. Try reading PE header from disk/process.");
        delete peFile;
        return 0;
    }

    delete peFile;
    
	return 1;
}

//**************************************************************************************
extern "C" int ScyllaDumpProcessFixImports(HANDLE hProcess, DWORD_PTR ModuleBase, DWORD NewOEP, BOOL CapeFile)
//**************************************************************************************
{
    BOOL isAfter;
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

    DoOutputDebugString(TEXT("DumpProcessFixImports: Instantiating PeParser with address: 0x%x"), ModuleBase);

    peFile = new PeParser(ModuleBase, true);

    if (peFile->isValidPeFile())
    {
        if (NewOEP)
            entrypointRVA = NewOEP - ModuleBase;
        else
            entrypointRVA = peFile->getEntryPoint();

        DoOutputDebugString(TEXT("DumpProcessFixImports: Module entry point VA is 0x%x"), ModuleBase + entrypointRVA);
        
        CapeOutputPath = GetName();
        
        //  Let's dump then fix the dump on disk
        if (peFile->dumpProcess(ModuleBase, ModuleBase + entrypointRVA, CapeOutputPath, CapeFile))
        {
            DoOutputDebugString("DumpProcessFixImports: Module image dump success %s", CapeOutputPath);
        }
        
        //  We'll try the simple search first
        IAT_Found = iatSearch.searchImportAddressTableInProcess(ModuleBase + entrypointRVA, &addressIAT, &sizeIAT, FALSE);
        
        //  Let's try the advanced search now
        if (IAT_Found == FALSE)
            IAT_Found = iatSearch.searchImportAddressTableInProcess(ModuleBase + entrypointRVA, &addressIAT, &sizeIAT, TRUE);
        
        if (addressIAT && sizeIAT)
        {
            DoOutputDebugString(TEXT("DumpProcessFixImports: Found IAT - 0x%x, size: 0x%x"), addressIAT, sizeIAT);
            
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
                        DoOutputDebugString("Direct imports - Old IAT size 0x%08x new IAT size 0x%08x", sizeIAT, sizeIatNew);
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
                        DoOutputDebugString("Direct imports patched.");
                    }
                }
    		}

            if (isIATOutsidePeImage(addressIAT))
            {
                DoOutputDebugString("Warning - IAT is not inside the PE image, requires rebasing.");
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
            
            if (importRebuild.rebuildImportTable(NULL, importsHandling.moduleList, CapeFile))
            {
                DoOutputDebugString("Import table rebuild success.\n");
                delete peFile;
                return 1;
            }
            else
            {
                DoOutputDebugString("Import table rebuild failed, falling back to unfixed dump.\n");
                peFile->savePeFileToDisk(NULL, CapeFile);
            }         
        }
        else
        {
            DoOutputDebugString("Warning: Unable to find IAT in scan.\n");
        }
    }
    else
    {
        DoOutputDebugString("Error: Invalid PE file or invalid PE header. Try reading PE header from disk/process.");
        delete peFile;
        return 0;
    }

    delete peFile;
    
	return 1;
}
