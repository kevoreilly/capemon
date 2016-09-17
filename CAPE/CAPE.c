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
#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <Wincrypt.h>
#include <WinNT.h>
#include <Shlwapi.h>

#include "CAPE.h"
#include "Debugger.h"
#include "..\pipe.h"
#include "..\config.h"

#pragma comment(lib, "Shlwapi.lib")

#define BUFSIZE 			1024	// For hashing
#define MD5LEN  			16

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);
extern void CapeOutputFile(LPCTSTR lpOutputFile);
extern int ScyllaDumpCurrentProcess(DWORD NewOEP);
extern int ScyllaDumpProcess(HANDLE hProcess, DWORD_PTR modBase, DWORD NewOEP);
extern int ScyllaDumpCurrentProcessFixImports(DWORD NewOEP);

static HMODULE s_hInst = NULL;
static WCHAR s_wzDllPath[MAX_PATH];
CHAR s_szDllPath[MAX_PATH];

//**************************************************************************************
void PrintHexBytes(__in char* TextBuffer, __in BYTE* HexBuffer, __in unsigned int Count)
//**************************************************************************************
{
	unsigned int i;
	
	if (HexBuffer == NULL)
		return;
	
	for (i=0; i<Count; i++)
	{
		sprintf_s((TextBuffer+2*i), Count, "%2.2x", (unsigned int)*(HexBuffer+i));	
	}
	
	return;
}

//**************************************************************************************
BOOL MapFile(HANDLE hFile, unsigned char **Buffer, DWORD* FileSize)
//**************************************************************************************
{
	LARGE_INTEGER LargeFileSize;
	DWORD dwBytesRead;
	
	if (!GetFileSizeEx(hFile, &LargeFileSize))
	{
		DoOutputErrorString("Cannot get file size");
		return FALSE;
	}

    if (LargeFileSize.HighPart || LargeFileSize.LowPart > SIZE_OF_LARGEST_IMAGE)
	{
		DoOutputDebugString("MapFile: File too big");
		return FALSE;
	}

	*FileSize = LargeFileSize.LowPart;
	
    DoOutputDebugString("File size: 0x%x", *FileSize);
	
	*Buffer = malloc(*FileSize);
	
    if (SetFilePointer(hFile, 0, 0, FILE_BEGIN))
    {
 		DoOutputErrorString("MapFile: Failed to set file pointer");
		return FALSE;   
    }
    
	if (*Buffer == NULL)
	{
		DoOutputErrorString("MapFile: Memory allocation error in MapFile");
		return FALSE;
	}
	
	if (FALSE == ReadFile(hFile, (LPVOID)*Buffer, *FileSize, &dwBytesRead, NULL))
	{
		DoOutputErrorString("ReadFile error");
        free(Buffer);
		return FALSE;
	}

    if (dwBytesRead > 0 && dwBytesRead < *FileSize)
    {
        DoOutputErrorString("MapFile: Unexpected size read in.");
        free(Buffer);
		return FALSE;

    }
    else if (dwBytesRead == 0)
    {
        DoOutputErrorString("MapFile: No data read from file");
        free(Buffer);
		return FALSE;
    }
	
	return TRUE;
}

//**************************************************************************************
BOOL GetHash(unsigned char* Buffer, unsigned int Size, char* OutputFilenameBuffer)
//**************************************************************************************
{
	DWORD i;
	DWORD dwStatus = 0;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    DWORD cbHash = 0;
    BYTE MD5Hash[MD5LEN];

    // Get handle to the crypto provider
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        DoOutputErrorString("CryptAcquireContext failed");
        return 0;
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    {
        DoOutputErrorString("CryptCreateHash failed"); 
        CryptReleaseContext(hProv, 0);
        return 0;
    }

	if (!CryptHashData(hHash, Buffer, Size, 0))
	{
		DoOutputErrorString("CryptHashData failed"); 
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		return 0;
	}

    cbHash = MD5LEN;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, MD5Hash, &cbHash, 0))
    {
        DoOutputErrorString("CryptGetHashParam failed"); 
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
	
	for (i = 0; i < cbHash; i++)
	{
		PrintHexBytes(OutputFilenameBuffer, MD5Hash, MD5LEN);
	}
	
	return 1;
}

//**************************************************************************************
char* GetHashFromHandle(HANDLE hFile)
//**************************************************************************************
{
    DWORD FileSize;
	long e_lfanew;
	PIMAGE_NT_HEADERS pNtHeader;
	unsigned char* Buffer = NULL;
	char * OutputFilenameBuffer;

	if (!MapFile(hFile, &Buffer, &FileSize))
	{	
		DoOutputErrorString("MapFile error - check path!");
		return 0;
	}
    
	OutputFilenameBuffer = (char*) malloc(MAX_PATH);

    if (OutputFilenameBuffer == NULL)
    {
		DoOutputErrorString("Error allocating memory for hash string.");
		return 0;    
    }
    
	GetHash(Buffer, FileSize, (char*)OutputFilenameBuffer);
    
    DoOutputDebugString("GetHash returned: %s", OutputFilenameBuffer);

    // Check if we have a valid DOS and PE header at the beginning of Buffer
    if (*(WORD*)Buffer == IMAGE_DOS_SIGNATURE)
    {
        e_lfanew = *(long*)(Buffer+0x3c);

        if ((unsigned int)e_lfanew>PE_HEADER_LIMIT)
        {
            // This check is possibly not appropriate here
            // As long as we've got what's been compressed
        }

        if (*(DWORD*)(Buffer+e_lfanew) == IMAGE_NT_SIGNATURE)
        {
            pNtHeader = (PIMAGE_NT_HEADERS)(Buffer+e_lfanew);

            if ((pNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
            {
                sprintf_s((OutputFilenameBuffer+2*MD5LEN), MAX_PATH*sizeof(char), ".dll");
            }
            else if ((pNtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == IMAGE_FILE_EXECUTABLE_IMAGE)
            {
                sprintf_s((OutputFilenameBuffer+2*MD5LEN), MAX_PATH*sizeof(char)-2*MD5LEN, ".exe_");
            }
        }
    }
    
    CloseHandle(hFile);
    
	// We don't need the file buffer any more
    free(Buffer);
    
    // We leak the OutputFilenameBuffer
    return OutputFilenameBuffer;
}

//**************************************************************************************
int DumpXorPE(LPBYTE Buffer, unsigned int Size)
//**************************************************************************************
{
	LONG e_lfanew;
    DWORD NT_Signature, FullKey;
	WORD TestKey;
    unsigned int i, j, k, rotation;
	BYTE* DecryptedBuffer;

    for (i=0; i<=0xFF; i++)
	{
		// check for the DOS signature a.k.a MZ header
		if ((*Buffer^(BYTE)i) == 'M' && (*(Buffer+1)^(BYTE)i) == 'Z')
		{
			DoOutputDebugString("MZ header found with bytewise XOR key 0x%.2x\n", i);

			e_lfanew = (LONG)*(DWORD*)(Buffer+0x3c);

            DoOutputDebugString("Encrypted e_lfanew: 0x%x", e_lfanew);
            
			for (j=0; j<sizeof(LONG); j++)
				*((BYTE*)&e_lfanew+j) = *((BYTE*)&e_lfanew+j)^i;

            DoOutputDebugString("Decrypted e_lfanew: 0x%x", e_lfanew);
            
			if ((unsigned int)e_lfanew > PE_HEADER_LIMIT)
			{	
				DoOutputDebugString("The pointer to the PE header seems a tad large: 0x%x", e_lfanew);
				//return FALSE;
			}

			// let's get the NT signature a.k.a PE header
			memcpy(&NT_Signature, Buffer+e_lfanew, 4);
            
            DoOutputDebugString("Encrypted NT_Signature: 0x%x", NT_Signature);
			
			// let's try decrypting it with the key
			for (k=0; k<4; k++)
				*((BYTE*)&NT_Signature+k) = *((BYTE*)&NT_Signature+k)^i;

            DoOutputDebugString("Encrypted NT_Signature: 0x%x", NT_Signature);

			// does it check out?
			if (NT_Signature == IMAGE_NT_SIGNATURE)
			{
				DoOutputDebugString("Xor-encrypted PE detected, about to dump.\n");
                
                DecryptedBuffer = (BYTE*)malloc(Size);
                
                if (DecryptedBuffer == NULL)
                {
                    DoOutputErrorString(TEXT("Error allocating memory for decrypted PE binary."));
                    return FALSE;
                }
                
                memcpy(DecryptedBuffer, Buffer, Size);
                
                for (k=0; k<Size; k++)
                    *(DecryptedBuffer+k) = *(DecryptedBuffer+k)^i;
                
                DumpPE(DecryptedBuffer);
                
                free(DecryptedBuffer);
				return TRUE;
			}
			else
			{
				DoOutputDebugString("PE signature invalid, looks like a false positive! 1 in 0x10000!!\n");
				return FALSE;
			}
		}
	}
#ifndef _WIN64
	for (i=0; i<=0xffff; i++)
	{
		// check for the DOS signature a.k.a MZ header
		if ((*(WORD*)Buffer^(WORD)i) == IMAGE_DOS_SIGNATURE)
		{
			DoOutputDebugString("MZ header found with wordwise XOR key 0x%.2x%.2x\n", *(BYTE*)&i, *((BYTE*)&i+1));
			
			// let's try just the little end of the full lfanew which is almost always the whole value anyway
			e_lfanew = *(WORD*)(Buffer+0x3c);

			// try and decrypt
			e_lfanew = e_lfanew^(WORD)i;

			if ((unsigned int)e_lfanew > PE_HEADER_LIMIT)
			{	
				// even if dword-encrypted, 
				// if the little endian word of the dword takes it too far it's over
				DoOutputDebugString("Sadly the pointer to the PE header seems a tad too large: 0x%x", e_lfanew);
				//return FALSE;
			}

			// get PE header
			memcpy(&NT_Signature, Buffer+e_lfanew, 4);
			
			// We need to rotate our key for a non-dword aligned offset
			TestKey = i;
			if (e_lfanew % 2)
			{
				__asm 
				{	
					mov ax, TestKey
					ror ax, 8
					mov TestKey, ax
				}
			}				

			// let's try decrypting it with the word key
			for (k=0; k<2; k++)
				*((WORD*)&NT_Signature+k) = *((WORD*)&NT_Signature+k)^TestKey;
				
			// does it check out?
			if (NT_Signature == IMAGE_NT_SIGNATURE)
			{
				DoOutputDebugString("Xor-encrypted PE detected, about to dump.\n");
                
                DecryptedBuffer = (BYTE*)malloc(Size);
                
                if (DecryptedBuffer == NULL)
                {
                    DoOutputErrorString(TEXT("Error allocating memory for decrypted PE binary."));
                    return FALSE;
                }
                
                memcpy(DecryptedBuffer, Buffer, Size);
                
                for (k=0; k<Size; k=k+2)
                    *(WORD*)(DecryptedBuffer+k) = *(WORD*)(DecryptedBuffer+k)^TestKey;
                
                DumpPE(DecryptedBuffer);
                
                free(DecryptedBuffer);
				return TRUE;
			}
			else if ((WORD)NT_Signature == (WORD)IMAGE_NT_SIGNATURE)
			{
				// looks like DWORD encrypted with zero most significant word of lfanew
				// let's confirm
				DWORD FullKey = TestKey + ((*(WORD*)(Buffer+0x3e))<<16);

				// let's recopy our candidate PE header
				memcpy(&NT_Signature, Buffer+e_lfanew, 4);

				// We need to rotate our key for a non-dword aligned offset
				for (rotation = 0; rotation<(unsigned int)(e_lfanew % 4); rotation++)
				{
					__asm 
					{	
						mov eax, FullKey
						ror eax, 8
						mov FullKey, eax
					}
				}	
			
				// final test of the latter two bytes of PE header
				// (might as well test the whole thing)
				if ((NT_Signature ^ FullKey) == IMAGE_NT_SIGNATURE)
                {
                    DoOutputDebugString("Xor-encrypted PE detected, about to dump.\n");
                    
                    DecryptedBuffer = (BYTE*)malloc(Size);
                    
                    if (DecryptedBuffer == NULL)
                    {
                        DoOutputErrorString(TEXT("Error allocating memory for decrypted PE binary."));
                        return FALSE;
                    }
                    
                    memcpy(DecryptedBuffer, Buffer, Size);
                    
                    for (k=0; k<Size; k=k+4)
                        *(DWORD*)(DecryptedBuffer+k) = *(DWORD*)(DecryptedBuffer+k)^FullKey;
                    
                    DumpPE(DecryptedBuffer);
                    
                    free(DecryptedBuffer);
                    return TRUE;
                }
                else
				{
					// There's *very* remote this was a false positive, we should continue
					continue;
				}
			}

			// could be dword with non-zero most signicant bytes of lfanew
			// brute force the 0xffff possibilities here
			
			for (TestKey=0; TestKey<0xffff; TestKey++)
			{
				long full_lfanew = e_lfanew + (0x10000*((*(WORD*)(Buffer+0x3e))^TestKey));						
				
				if ((unsigned int)full_lfanew > PE_HEADER_LIMIT)
				{	
					continue;			
				}

				memcpy(&NT_Signature, Buffer+full_lfanew, 4);

				// We need to rotate our key for a non-dword aligned offset
				FullKey = i + (TestKey<<16);
				for (rotation = 0; rotation<(unsigned int)(full_lfanew % 4); rotation++)
				{
					__asm 
					{	
						mov eax, FullKey
						ror eax, 8
						mov FullKey, eax
					}
				}

				// let's try decrypting it with the key
				if ((NT_Signature ^ FullKey) == IMAGE_NT_SIGNATURE)
                {
                    DoOutputDebugString("Xor-encrypted PE detected, about to dump.\n");
                    
                    DecryptedBuffer = (BYTE*)malloc(Size);
                    
                    if (DecryptedBuffer == NULL)
                    {
                        DoOutputErrorString(TEXT("Error allocating memory for decrypted PE binary."));
                        return FALSE;
                    }
                    
                    memcpy(DecryptedBuffer, Buffer, Size);
                    
                    for (k=0; k<Size; k=k+4)
                        *(DWORD*)(DecryptedBuffer+k) = *(DWORD*)(DecryptedBuffer+k)^FullKey;
                    
                    DumpPE(DecryptedBuffer);
                    
                    free(DecryptedBuffer);
                    return TRUE;
                }
			}
		}
	}
#endif
    // We free can free DecryptedBuffer as it's no longer needed
    free(DecryptedBuffer);
    
    return FALSE;
}

//**************************************************************************************
int DumpMemory(LPCVOID Buffer, unsigned int Size)
//**************************************************************************************
{
	char *OutputFilename, *FullPathName;
	DWORD RetVal, dwBytesWritten;
	HANDLE hOutputFile;

	OutputFilename = (char*) malloc(MAX_PATH);
	FullPathName = (char*) malloc(MAX_PATH);

    if (OutputFilename == NULL || FullPathName == NULL)
    {
		DoOutputErrorString("DumpMemory: Error allocating memory for strings");
		return 0;    
    }
    
	GetHash((LPVOID)Buffer, Size, (char*)OutputFilename);
    
    DoOutputDebugString("GetHash returned: %s", OutputFilename);

    sprintf_s((OutputFilename+2*MD5LEN), MAX_PATH*sizeof(char)-2*MD5LEN, ".bin");

	// We want to dump CAPE output to the 'analyzer' directory
    memset(FullPathName, 0, MAX_PATH);
	
    strncpy_s(FullPathName, MAX_PATH, g_config.analyzer, strlen(g_config.analyzer)+1);

	if (strlen(FullPathName) + strlen("\\CAPE\\") + strlen(OutputFilename) >= MAX_PATH)
	{
		DoOutputDebugString("Error, CAPE destination path too long.");
        free(OutputFilename); free(FullPathName);
		return 0;
	}

    PathAppend(FullPathName, "CAPE");

	RetVal = CreateDirectory(FullPathName, NULL);

	if (RetVal == 0 && GetLastError() != ERROR_ALREADY_EXISTS)
	{
		DoOutputDebugString("Error creating output directory");
        free(OutputFilename); free(FullPathName);
		return 0;
	}

    PathAppend(FullPathName, OutputFilename);
	
    DoOutputDebugString("DEBUG: FullPathName = %s", FullPathName);
    
	hOutputFile = CreateFile(FullPathName, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    
	DoOutputDebugString("CreateFile returned: 0x%x", hOutputFile);
    
	if (hOutputFile == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_EXISTS)
	{
		DoOutputDebugString("CAPE output filename exists already: %s", FullPathName);
        free(OutputFilename); free(FullPathName);
		return 0;
	}

	DoOutputDebugString("Passed file_exists check");
	
	if (hOutputFile == INVALID_HANDLE_VALUE)
	{
		DoOutputErrorString("Could not create CAPE output file");
        free(OutputFilename); free(FullPathName);
		return 0;		
	}	
	DoOutputDebugString("Passed invalid_handle check");
	
	dwBytesWritten = 0;
    
    DoOutputDebugString("CAPE output file succssfully created:%s", FullPathName);

	if (FALSE == WriteFile(hOutputFile, Buffer, Size, &dwBytesWritten, NULL))
	{
		DoOutputDebugString("WriteFile error on CAPE output file");
        free(OutputFilename); free(FullPathName);
		return 0;
	}

	DoOutputDebugString("CAPE output filename: %s", FullPathName);

	CloseHandle(hOutputFile);
    
    CapeOutputFile(FullPathName);
    
    // We can free the filename buffers
    free(OutputFilename); free(FullPathName);
	
    return 1;
}

//**************************************************************************************
int DumpCurrentProcessFixImports(DWORD NewEP)
//**************************************************************************************
{
	if (ScyllaDumpCurrentProcessFixImports(NewEP))
	{
		return 1;
	}

	return 0;
}

//**************************************************************************************
int DumpCurrentProcessNewEP(DWORD NewEP)
//**************************************************************************************
{
	if (ScyllaDumpCurrentProcess(NewEP))
	{
		return 1;
	}

	return 0;
}

//**************************************************************************************
int DumpCurrentProcess()
//**************************************************************************************
{
	if (ScyllaDumpCurrentProcess(0))
	{
		return 1;
	}

	return 0;
}

//**************************************************************************************
int DumpProcess(HANDLE hProcess, DWORD_PTR ImageBase)
//**************************************************************************************
{
	if (ScyllaDumpProcess(hProcess, ImageBase, 0))
	{
		return 1;
	}

	return 0;
}

//**************************************************************************************
int DumpPE(LPCVOID Buffer)
//**************************************************************************************
{
	if (ScyllaDumpPE((DWORD_PTR)Buffer))
	{
		return 1;
	}

	return 0;
}

void init_CAPE()
{
    // Initialise CAPE global variables
    //
    
#ifndef _WIN64	 
    // Start the debugger thread if required
    //launch_debugger();
#endif
    
    return;
}