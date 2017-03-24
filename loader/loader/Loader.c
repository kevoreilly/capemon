// Copyright 2014-2015 Optiv, Inc. (brad.spengler@optiv.com)
// This file is published under the GNU GPL v3
// http://www.gnu.org/licenses/gpl.html

#include "Loader.h"
#include <tchar.h>
#include <stddef.h>
#include <stdio.h>

typedef HRESULT (WINAPI *PDLLREGRSRV)(void);
typedef void (cdecl *PPLUGXPAYLOAD)(void);

#define BUFSIZE 512

static int grant_debug_privileges(void)
{
    HANDLE token = NULL;
    TOKEN_PRIVILEGES priv;
    LUID privval;
    int ret;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
        return 0;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &privval)) {
        CloseHandle(token);
        return 0;
    }
    priv.PrivilegeCount = 1;
    priv.Privileges[0].Luid = privval;
    priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    ret = AdjustTokenPrivileges(token, FALSE, &priv, sizeof(priv), NULL, NULL);
    CloseHandle(token);

    return ret;
}

static BOOLEAN is_suspended(int pid, int tid)
{
	ULONG length;
	PSYSTEM_PROCESS_INFORMATION pspi = NULL, proc;
	ULONG requestedlen = 16384;
	_NtQuerySystemInformation pNtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
	BOOLEAN ret = FALSE;

	pspi = malloc(requestedlen);
	if (pspi == NULL)
		goto out;

	while (pNtQuerySystemInformation(SystemProcessInformation, pspi, requestedlen, &length) == STATUS_INFO_LENGTH_MISMATCH) {
		free(pspi);
		requestedlen <<= 1;
		pspi = malloc(requestedlen);
		if (pspi == NULL)
			goto out;
	}
	// now we have a valid list of process information
	proc = pspi;
	while (1) {
		ULONG i;
		if ((int)(ULONG_PTR)proc->UniqueProcessId != pid)
			goto next;
		for (i = 0; i < proc->NumberOfThreads; i++) {
			PSYSTEM_THREAD thread = &proc->Threads[i];
			if (tid && (int)(ULONG_PTR)thread->ClientId.UniqueThread != tid)
				continue;
			if (thread->WaitReason != Suspended)
				goto out;
		}
next:
		if (!proc->NextEntryOffset)
			break;
		proc = (PSYSTEM_PROCESS_INFORMATION)((PCHAR)proc + proc->NextEntryOffset);
	}
	ret = TRUE;
out:
	if (pspi)
		free(pspi);
	return ret;
}

static unsigned int get_shellcode(unsigned char *buf, PVOID injstruct)
{
#ifndef _WIN64
    buf[0] = 0xb8; // mov eax, injstructaddr
    memcpy(&buf[1], &injstruct, sizeof(injstruct));
    buf[5] = 0x53; // push ebx
    buf[6] = 0x8d; // lea ebx, injstructaddr+offsetof(INJECT_STRUCT.OutHandle)
    buf[7] = 0x58;
    buf[8] = (UCHAR)offsetof(INJECT_STRUCT, OutHandle);
    buf[9] = 0x53; // push ebx ; ModuleHandle arg
    buf[10] = 0x8d; // lea ebx, injstructaddr+offsetof(INJECT_STRUCT.DllName)
    buf[11] = 0x58;
    buf[12] = (UCHAR)offsetof(INJECT_STRUCT, DllName);
    buf[13] = 0x53; // push ebx ; ModuleFileName arg
    buf[14] = 0x6a; // push 0 (flags arg)
    buf[15] = 0x00;
    buf[16] = 0x6a; // push 0 (PathToFile arg)
    buf[17] = 0x00;
    buf[18] = 0x8b; // mov ebx, injstructaddr+offsetof(INJECT_STRUCT.LdrLoadDllAddress)
    buf[19] = 0x58;
    buf[20] = (UCHAR)offsetof(INJECT_STRUCT, LdrLoadDllAddress);
    buf[21] = 0xff; // call ebx
    buf[22] = 0xd3;
    buf[23] = 0x5b; // pop ebx
    buf[24] = 0xc2; // retn 0x4
    buf[25] = 0x04;
    buf[26] = 0x00;
    return 27;
#else
    buf[0] = 0x53; // push rbx
    buf[1] = 0x48; // sub rsp, 0x20
    buf[2] = 0x83;
    buf[3] = 0xec;
    buf[4] = 0x20;
    buf[5] = 0x48; // mov rax, rcx (injection address)
    buf[6] = 0x8b;
    buf[7] = 0xc1;
    buf[8] = 0x48; // lea rbx, injstructaddr+offsetof(INJECT_STRUCT.OutHandle)
    buf[9] = 0x8d;
    buf[10] = 0x58;
    buf[11] = (UCHAR)offsetof(INJECT_STRUCT, OutHandle);
    buf[12] = 0x49; // mov r9, rbx ; ModuleHandle arg
    buf[13] = 0x89;
    buf[14] = 0xd9;
    buf[15] = 0x48; // lea rbx, injstructaddr+offsetof(INJECT_STRUCT.DllName)
    buf[16] = 0x8d;
    buf[17] = 0x58;
    buf[18] = (UCHAR)offsetof(INJECT_STRUCT, DllName);
    buf[19] = 0x49; // mov r8, rbx ; ModuleFileName arg
    buf[20] = 0x89;
    buf[21] = 0xd8;
    buf[22] = 0x48; // xor rdx, rdx ; Flags arg
    buf[23] = 0x31;
    buf[24] = 0xd2;
    buf[25] = 0x48; // xor rcx, rcx ; PathToFile arg
    buf[26] = 0x31;
    buf[27] = 0xd1;
    buf[28] = 0x48; // mov rbx, injstructaddr+offsetof(INJECT_STRUCT.LdrLoadDllAddress)
    buf[29] = 0x8b; 
    buf[30] = 0x58;
    buf[31] = (UCHAR)offsetof(INJECT_STRUCT, LdrLoadDllAddress);
    buf[32] = 0xff; // call ebx
    buf[33] = 0xd3;
    buf[34] = 0x48; // add rsp, 0x20
    buf[35] = 0x83;
    buf[36] = 0xc4;
    buf[37] = 0x20; 
    buf[38] = 0x5b; // pop rbx
    buf[39] = 0xc3; // ret
    return 40;
#endif
}

// returns < 0 if injection failed, 0 if injection succeeded and process is alive, and 1 if we injected but the process is suspended, so we shouldn't wait for it
static int inject(int pid, int tid, const char *dllpath, BOOLEAN suspended, int injectmode)
{
    HANDLE prochandle = NULL;
    HANDLE ThreadHandle = NULL;
    LPVOID dllpathbuf;
    LPVOID injstructbuf;
    LPVOID loadlibraryaddr;
    LPVOID shellcodeaddr;
    unsigned int shellcodelen;
    unsigned char shellcodebuf[64];
    PWSTR wbuf = NULL;
    INJECT_STRUCT inj;
    int pathlen;
    int i;

    SIZE_T byteswritten = 0;
    int ret = ERROR_INVALID_PARAM;

    if (pid <= 0 || tid < 0)
        goto out;

    if (injectmode == INJECT_QUEUEUSERAPC && tid == 0 && suspended)    
        goto out;
        
    if (tid == 0)
        injectmode = INJECT_CREATEREMOTETHREAD;

    prochandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (prochandle == NULL) {
        ret = ERROR_PROCESS_OPEN;
        goto out;
    }

    if (tid > 0) {
        ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
        if (ThreadHandle == NULL) {
            ret = ERROR_THREAD_OPEN;
            goto out;
        }
    }

    pathlen = (int)strlen(dllpath);
    wbuf = calloc(1, (pathlen + 1) * sizeof(WCHAR));
    if (wbuf == NULL) {
        ret = ERROR_ALLOCATE;
        goto out;
    }
    for (i = 0; i < pathlen; i++) {
        wbuf[i] = (unsigned short)dllpath[i];
    }

    dllpathbuf = VirtualAllocEx(prochandle, NULL, (wcslen(wbuf) + 1) * sizeof(WCHAR), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (dllpathbuf == NULL) {
        ret = ERROR_ALLOCATE;
        goto out;
    }

    if (!WriteProcessMemory(prochandle, dllpathbuf, wbuf, (wcslen(wbuf) + 1) * sizeof(WCHAR), &byteswritten)) {
        ret = ERROR_WRITEMEMORY;
        goto out;
    }

    loadlibraryaddr = GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrLoadDll");

    inj.LdrLoadDllAddress = (ULONG_PTR)loadlibraryaddr;
    inj.DllName.Buffer = dllpathbuf;
    inj.DllName.Length = inj.DllName.MaximumLength = (USHORT)(wcslen(wbuf) * sizeof(WCHAR));

    injstructbuf = VirtualAllocEx(prochandle, NULL, sizeof(INJECT_STRUCT), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (injstructbuf == NULL) {
        ret = ERROR_ALLOCATE;
        goto out;
    }

    if (!WriteProcessMemory(prochandle, injstructbuf, &inj, sizeof(INJECT_STRUCT), &byteswritten)) {
        ret = ERROR_WRITEMEMORY;
        goto out;
    }

    shellcodelen = get_shellcode(shellcodebuf, injstructbuf);

    shellcodeaddr = VirtualAllocEx(prochandle, NULL, shellcodelen, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (shellcodeaddr == NULL) {
        ret = ERROR_ALLOCATE;
        goto out;
    }

    if (!WriteProcessMemory(prochandle, shellcodeaddr, shellcodebuf, shellcodelen, &byteswritten)) {
        ret = ERROR_WRITEMEMORY;
        goto out;
    }

    if (injectmode == INJECT_QUEUEUSERAPC) {
        if (!QueueUserAPC(shellcodeaddr, ThreadHandle, (ULONG_PTR)injstructbuf)) {
            ret = ERROR_QUEUEUSERAPC;
            goto out;
        }
    }
    else if (injectmode == INJECT_CREATEREMOTETHREAD) {
        DWORD threadid;
        HANDLE newhandle;
        newhandle = CreateRemoteThread(prochandle, NULL, 0, shellcodeaddr, injstructbuf, 0, &threadid);
        if (newhandle)
            CloseHandle(newhandle);
        else {
            if (GetLastError() == ERROR_NOT_ENOUGH_MEMORY) {
                /* Bypass Vista+ userland session restrictions on thread injection */
                PVOID pCsrClientCallServer = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "CsrClientCallServer");
                DWORD oldprot;
                unsigned char origbuf[16];
                // we hardcode the offsets obtained from reversing because all the definitions of 
                // PORT_MESSAGE/CSRSS_MESSAGE/etc available online are incorrect for x64, assuming ULONG size of various fields 
                // due to copy+pasting from Gary Nebbet's Windows 2000 Native API Reference book

#ifdef _WIN64
                const unsigned char payload[] = { 0x33, 0xc0, 0x89, 0x41, 0x34, 0xc3 }; // xor eax, eax / mov dword ptr [rcx+<offset of status>], eax / ret
#else
                const unsigned char payload[] = { 0x33, 0xc0, 0x8b, 0x4c, 0x24, 0x04, 0x89, 0x41, 0x20, 0xc2, 0x10, 0x00 }; // xor eax, eax, / mov ecx, [esp+4] / mov [ecx+<offset of status>], eax / retn 0x10
#endif
                VirtualProtect(pCsrClientCallServer, sizeof(payload), PAGE_EXECUTE_READWRITE, &oldprot);

                memcpy(origbuf, pCsrClientCallServer, sizeof(payload));
                memcpy(pCsrClientCallServer, payload, sizeof(payload));

                newhandle = CreateRemoteThread(prochandle, NULL, 0, shellcodeaddr, injstructbuf, 0, &threadid);

                memcpy(pCsrClientCallServer, origbuf, sizeof(payload));

                if (newhandle)
                    CloseHandle(newhandle);

                VirtualProtect(pCsrClientCallServer, sizeof(payload), oldprot, &oldprot);
                if (newhandle)
                    goto success;
            }
            ret = ERROR_CREATEREMOTETHREAD;
            goto out;
        }
    }
//	else if (injectmode == INJECT_NTCREATETHREADEX) {
//	}
//	else if (injectmode == INJECT_RTLCREATEUSERTHREAD) {
//	}
//	else {
//		ret = ERROR_INJECTMODE;
//		goto out;
//	}

success:
    if (suspended)
        ret = 1;
    else
        ret = 0;
out:
    if (prochandle)
        CloseHandle(prochandle);
    if (ThreadHandle)
        CloseHandle(ThreadHandle);
    if (wbuf)
        free(wbuf);

    return ret;
}

static void fixpe(ULONG_PTR base, char *buf, DWORD bufsize)
{
    PIMAGE_DOS_HEADER doshdr;
    PIMAGE_NT_HEADERS nthdr;
    PIMAGE_NT_HEADERS32 nthdr32;
    PIMAGE_NT_HEADERS64 nthdr64;
    PIMAGE_SECTION_HEADER sechdr;
    unsigned short numsecs;
    unsigned short i;

    doshdr = (PIMAGE_DOS_HEADER)buf;

    if (doshdr->e_magic != IMAGE_DOS_SIGNATURE)
        return;

    if (doshdr->e_magic > bufsize - (sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_DOS_HEADER)))
        return;

    nthdr = (PIMAGE_NT_HEADERS)(buf + doshdr->e_lfanew);
    if (nthdr->Signature != IMAGE_NT_SIGNATURE)
        return;

    if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        nthdr32 = (PIMAGE_NT_HEADERS32)nthdr;
        nthdr32->OptionalHeader.ImageBase = (DWORD)base;
        numsecs = nthdr32->FileHeader.NumberOfSections;
        if (bufsize < sizeof(IMAGE_NT_HEADERS32) - sizeof(IMAGE_OPTIONAL_HEADER32) + sizeof(IMAGE_DOS_HEADER) + nthdr32->FileHeader.SizeOfOptionalHeader + (numsecs * sizeof(IMAGE_SECTION_HEADER)))
            return;
        sechdr = (PIMAGE_SECTION_HEADER)((PCHAR)&nthdr32->OptionalHeader + nthdr32->FileHeader.SizeOfOptionalHeader);
        for (i = 0; i < numsecs; i++) {
            sechdr[i].PointerToRawData = sechdr[i].VirtualAddress;
            sechdr[i].SizeOfRawData = sechdr[i].Misc.VirtualSize;
        }
        // zero out the relocation table since relocations have already been applied
        if (nthdr32->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
            nthdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
            nthdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
            nthdr32->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
        }
    }
    else if (nthdr->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        nthdr64 = (PIMAGE_NT_HEADERS64)nthdr;
        nthdr64->OptionalHeader.ImageBase = base;
        numsecs = nthdr64->FileHeader.NumberOfSections;
        if (bufsize < sizeof(IMAGE_NT_HEADERS64) - sizeof(IMAGE_OPTIONAL_HEADER64) + sizeof(IMAGE_DOS_HEADER) + nthdr64->FileHeader.SizeOfOptionalHeader + (numsecs * sizeof(IMAGE_SECTION_HEADER)))
            return;
        sechdr = (PIMAGE_SECTION_HEADER)((PCHAR)&nthdr64->OptionalHeader + nthdr64->FileHeader.SizeOfOptionalHeader);
        for (i = 0; i < numsecs; i++) {
            sechdr[i].PointerToRawData = sechdr[i].VirtualAddress;
            sechdr[i].SizeOfRawData = sechdr[i].Misc.VirtualSize;
        }
        // zero out the relocation table since relocations have already been applied
        if (nthdr64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
            nthdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
            nthdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
            nthdr64->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
        }
    }

    return;
}

static int dump(int pid, char *dumpfile)
{
    SYSTEM_INFO sysinfo;
    PUCHAR addr;
    MEMORY_BASIC_INFORMATION meminfo;
    HANDLE f;
    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (proc == NULL)
        return ERROR_PROCESS_OPEN;

    f = CreateFileA(dumpfile, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        CloseHandle(proc);
        return ERROR_FILE_OPEN;
    }

    GetSystemInfo(&sysinfo);

    // for now just do this the lame way, later we'll dump processes properly
    // in a way that's compatible with copymemII/shrinker/etc by communicating
    // with a dumper thread in our hooked process
    for (addr = (PUCHAR)sysinfo.lpMinimumApplicationAddress; addr < (PUCHAR)sysinfo.lpMaximumApplicationAddress;) {
        if (VirtualQueryEx(proc, addr, &meminfo, sizeof(meminfo))) {
            if ((meminfo.State & MEM_COMMIT) && (meminfo.Type & (MEM_IMAGE | MEM_MAPPED | MEM_PRIVATE))) {
                char *buf;
                LARGE_INTEGER bufaddr;
                DWORD bufsize;
                DWORD byteswritten;
                SIZE_T bytesread;
                bufaddr.QuadPart = (ULONGLONG)addr;
                bufsize = (DWORD)meminfo.RegionSize;
                buf = calloc(1, bufsize);
                if (buf == NULL) {
                    CloseHandle(f);
                    CloseHandle(proc);
                    return ERROR_ALLOCATE;
                }
                if (ReadProcessMemory(proc, addr, buf, bufsize, &bytesread) || GetLastError() == ERROR_PARTIAL_COPY) {
                    WriteFile(f, &bufaddr, sizeof(bufaddr), &byteswritten, NULL);
                    WriteFile(f, &bufsize, sizeof(bufsize), &byteswritten, NULL);
                    WriteFile(f, &meminfo.State, sizeof(meminfo.State), &byteswritten, NULL);
                    WriteFile(f, &meminfo.Type, sizeof(meminfo.Type), &byteswritten, NULL);
                    WriteFile(f, &meminfo.Protect, sizeof(meminfo.Protect), &byteswritten, NULL);
                    fixpe((ULONG_PTR)addr, buf, bufsize);
                    WriteFile(f, buf, bufsize, &byteswritten, NULL);
                }
                free(buf);
            }
            addr += meminfo.RegionSize;
        }
        else {
            addr += 0x1000;
        }
    }
    CloseHandle(f);
    CloseHandle(proc);
    return 1;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    if (__argc < 2)
        return ERROR_ARGCOUNT;
    
    if (!grant_debug_privileges())
        return ERROR_DEBUGPRIV;

    if (!strcmp(__argv[1], "inject")) {
        int pid, tid, injectmode;
        if (__argc != 6)
            return ERROR_ARGCOUNT;
        pid = atoi(__argv[2]);
        tid = atoi(__argv[3]);
        injectmode = atoi(__argv[5]);        
        return inject(pid, tid, __argv[4], is_suspended(pid, tid), injectmode);
    } else if (!strcmp(__argv[1], "load")) {
        // usage: loader.exe load <binary> <commandline> <dll to load>
        PROCESS_INFORMATION pi;
        STARTUPINFOA si;
        int ret;
        memset(&si, 0, sizeof(si));
        if (__argc != 5)
            return ERROR_ARGCOUNT;
        CreateProcessA(__argv[2], __argv[3], NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
        ret = inject(pi.dwProcessId, pi.dwThreadId, __argv[4], TRUE, INJECT_QUEUEUSERAPC);
        if (ret == 1) {
            HANDLE ThreadHandle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, pi.dwThreadId);
            if (ThreadHandle) {
                ResumeThread(ThreadHandle);
                CloseHandle(ThreadHandle);
            }
        }
    } 
    else if (!strcmp(__argv[1], "plugx")) 
    {
        // usage: loader.exe plugx <payload file>
        HANDLE hInputFile;
        LARGE_INTEGER InputFileSize;
        BYTE *PayloadBuffer = NULL;
        DWORD dwBytesRead, dwBytesToWrite;
        
        PPLUGXPAYLOAD Payload;

        hInputFile = CreateFile(__argv[2], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (!hInputFile || hInputFile == INVALID_HANDLE_VALUE)
        {
            //Error opening input file
            return 0;
        }

        if (!GetFileSizeEx(hInputFile, &InputFileSize))
        {
            //GetFileSizeEx error on input file
            return 0;
        }

        if (InputFileSize.HighPart)
        {
            //Input file is too big!
            return 0;
        }

        dwBytesToWrite = InputFileSize.LowPart;
        
        PayloadBuffer = (BYTE*)VirtualAlloc(NULL, InputFileSize.LowPart, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        
        if (PayloadBuffer == NULL)
        {
            //Error allocating memory for file buffer
            return 0;
        }

        memset(PayloadBuffer, 0, InputFileSize.LowPart);
        
        if (FALSE == ReadFile(hInputFile, PayloadBuffer, InputFileSize.LowPart, &dwBytesRead, NULL))
        {
            //ReadFile error on input file
            return 0;
        }
            
        Payload = (PPLUGXPAYLOAD)PayloadBuffer;
        
        Payload();
        
        free(PayloadBuffer);
        CloseHandle(hInputFile);
        return 1;
    } 
    else if (!strcmp(__argv[1], "derusbi")) 
    {
        PDLLREGRSRV pDllRegisterServer;
        HRESULT 	ReturnVal;
        BOOL		UnregisterServer = FALSE;
        HMODULE 	hDerusbi;
        
        if (__argc == 4 && !strncmp(__argv[2], "-u", 2))
            UnregisterServer = TRUE;

        hDerusbi = LoadLibrary(__argv[__argc-1]);

        if (hDerusbi != NULL)
        {
            if (UnregisterServer == TRUE)
                pDllRegisterServer = (PDLLREGRSRV) GetProcAddress(hDerusbi, "DllUnregisterServer");
            else
                pDllRegisterServer = (PDLLREGRSRV) GetProcAddress(hDerusbi, "DllRegisterServer");
            
            if (!pDllRegisterServer)
            {
                // handle the error
                FreeLibrary(hDerusbi);
                return 0;
            }
            else
            {
                // call the function
                ReturnVal = pDllRegisterServer();
            }		
            
        }
        else
        {
            //ErrorDisplay(TEXT("LoadLibrary"));
        }
        return ReturnVal;
    }
    else if (!strcmp(__argv[1], "debug")) 
    {
        // usage: loader.exe debug <binary> <commandline> <dll debugger>
        int pid, tid;
        int RetVal;
        TCHAR DebugOutput[MAX_PATH];
        HANDLE hProcess, hThread; 

        if (__argc != 7)
            return ERROR_ARGCOUNT;
        pid = atoi(__argv[2]);
        tid = atoi(__argv[3]);
    
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);
        if (hProcess == NULL) 
        {
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("OpenProcess failed, GLE=%d.\n"), GetLastError());
            OutputDebugString(DebugOutput);
            return -18;
        }
        
        hThread = OpenThread(THREAD_ALL_ACCESS, TRUE, tid);
        if (hThread == NULL) 
        {
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("OpenThread failed, GLE=%d.\n"), GetLastError());
            OutputDebugString(DebugOutput);
            return -19;
        }
    
        RetVal = inject(pid, tid, __argv[6], TRUE, INJECT_CREATEREMOTETHREAD);

        CloseHandle(hProcess);
        CloseHandle(hThread);
        
        return RetVal;
    } 
    else if (!strcmp(__argv[1], "debug_load")) 
    {
        // usage: loader.exe debug <binary> <commandline> <dll debugger>
        int pid, tid;
        BOOL fSuccess, fConnected;
        int RetVal;
        CONTEXT ctx;
        TCHAR DebugOutput[MAX_PATH];
        DWORD cbBytesRead, cbWritten, cbReplyBytes;
        DWORD_PTR OEP, RemoteFuncAddress;
        HANDLE hPipe, hProcess, hThread; 
        char lpszPipename[MAX_PATH];

        if (__argc != 7)
            return ERROR_ARGCOUNT;
        pid = atoi(__argv[2]);
        tid = atoi(__argv[3]);

        memset(lpszPipename, 0, MAX_PATH*sizeof(CHAR));
        sprintf_s(lpszPipename, MAX_PATH, "\\\\.\\pipe\\CAPEpipe_%x", pid);
    
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);
        if (hProcess == NULL) 
        {
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("Loader: OpenProcess failed, GLE=%d.\n"), GetLastError());
            OutputDebugString(DebugOutput);
            return -18;
        }
        
        hThread = OpenThread(THREAD_ALL_ACCESS, TRUE, tid);
        if (hThread == NULL) 
        {
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("Loader: OpenThread failed, GLE=%d.\n"), GetLastError());
            OutputDebugString(DebugOutput);
            return -19;
        }
        
        RemoteFuncAddress = 0;
        fConnected = FALSE; 
        hPipe = INVALID_HANDLE_VALUE;

        hPipe = CreateNamedPipe
        ( 
            lpszPipename,             	// pipe name 
            PIPE_ACCESS_DUPLEX,       	// read/write access 
            PIPE_TYPE_MESSAGE |       	// message type pipe 
            PIPE_READMODE_MESSAGE |   	// message-read mode 
            PIPE_WAIT,                	// blocking mode 
            PIPE_UNLIMITED_INSTANCES, 	// max. instances  
            BUFSIZE,                  	// output buffer size 
            BUFSIZE,                  	// input buffer size 
            0,                        	// client time-out 
            NULL
        );								// default security attribute 

        if (hPipe == INVALID_HANDLE_VALUE) 
        {
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("Loader: CreateNamedPipe failed, GLE=%d.\n"), GetLastError());
            OutputDebugString(DebugOutput);
            return -14;
        }
     
        RetVal = inject(pid, tid, __argv[6], TRUE, INJECT_CREATEREMOTETHREAD);

        // Wait for the client to connect; if it succeeds, 
        // the function returns a nonzero value. If the function
        // returns zero, GetLastError returns ERROR_PIPE_CONNECTED. 

        fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); 
        fSuccess = FALSE;
        cbBytesRead = 0;
        
        if (fConnected) 
        { 
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("Loader: Client connected\n"));
            OutputDebugString(DebugOutput);	
            
            fSuccess = ReadFile
            ( 
                hPipe,        			    // handle to pipe 
                &RemoteFuncAddress,         // buffer to receive data 
                sizeof(DWORD_PTR),			// size of buffer 
                &cbBytesRead, 			    // number of bytes read 
                NULL          			    // not overlapped I/O
            );
        } 
        else 
        {
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("Loader: The client could not connect, closing pipe.\n"));
            OutputDebugString(DebugOutput);		
            CloseHandle(hPipe);
            return -15;
        }
        
        if (!fSuccess || cbBytesRead == 0)
        {   
            if (GetLastError() == ERROR_BROKEN_PIPE)
            {
                memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
                _stprintf_s(DebugOutput, MAX_PATH, TEXT("Loader: Client disconnected, GLE=%d.\n"), GetLastError());
                OutputDebugString(DebugOutput);
            }
            else
            {
                memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
                _stprintf_s(DebugOutput, MAX_PATH, TEXT("Loader: ReadFile failed, last error=%d.\n"), GetLastError());
                OutputDebugString(DebugOutput);
            }
        }

        if (!RemoteFuncAddress)
        {
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("Loader: Successfully read from pipe, however RemoteFuncAddress = 0, last error=%d.\n"), GetLastError());
            OutputDebugString(DebugOutput);
            return -16;
        }
        
        memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
        _stprintf_s(DebugOutput, MAX_PATH, TEXT("Loader: Successfully received debugger init address: 0x%x.\n"), RemoteFuncAddress);
        OutputDebugString(DebugOutput);		

        ctx.ContextFlags = CONTEXT_ALL;
        if (!GetThreadContext(hThread, &ctx))
        {
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("GetThreadContext failed - FATAL\n"));
            OutputDebugString(DebugOutput);		
            return -17;
        }

#ifndef _WIN64       
        OEP = ctx.Eax;  // eax holds eip on 32-bit
#else
        OEP = ctx.Rcx;  // rcx holds rip on 64-bit
#endif        
        memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
#ifndef _WIN64       
        _stprintf_s(DebugOutput, MAX_PATH, TEXT("GetThreadContext gives OEP=0x%x\n"), ctx.Eax);
#else
        _stprintf_s(DebugOutput, MAX_PATH, TEXT("GetThreadContext gives OEP=0x%x\n"), ctx.Rcx);
#endif        
        OutputDebugString(DebugOutput);		
        
        cbWritten = 0;
        cbReplyBytes = sizeof(DWORD_PTR);
        
        // Write the reply to the pipe. 
        fSuccess = WriteFile
        ( 
            hPipe,        		// handle to pipe 
            &OEP,				// buffer to write from 
            cbReplyBytes, 		// number of bytes to write 
            &cbWritten,   		// number of bytes written 
            NULL          		// not overlapped I/O 
        );
        if (!fSuccess || cbReplyBytes != cbWritten)
        {   
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("Failed to send OEP via pipe, last error=%d.\n"), GetLastError());
            OutputDebugString(DebugOutput);					
        }
        else
        {   
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("Sent OEP 0x%x via pipe\n"), OEP);
            OutputDebugString(DebugOutput);					
        }

        if (RetVal == 1)
        {
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("Loader: Child process created, suspended, DLL successfully injected\n"));
            OutputDebugString(DebugOutput);

            ctx.ContextFlags = CONTEXT_ALL;
#ifndef _WIN64       
            ctx.Eax = RemoteFuncAddress;		// eax holds new entry point
#else
            ctx.Rcx = RemoteFuncAddress;		// rcx holds new entry point
#endif        
            if (!SetThreadContext(hThread, &ctx))
            {
                memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
                _stprintf_s(DebugOutput, MAX_PATH, TEXT("Failed to set new EP\n"));
                OutputDebugString(DebugOutput);
            }
            else
            {
                memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
#ifndef _WIN64       
                _stprintf_s(DebugOutput, MAX_PATH, TEXT("Set new EP to 0x%x\n"), ctx.Eax);
#else
                _stprintf_s(DebugOutput, MAX_PATH, TEXT("Set new EP to 0x%x\n"), ctx.Rcx);
#endif        
                OutputDebugString(DebugOutput);                
            }
        }
        CloseHandle(hPipe);
        CloseHandle(hProcess);
        CloseHandle(hThread);
        
        return 1;
        
    } 
    else if (!strcmp(__argv[1], "test")) 
    {
        // usage: loader.exe test <binary> <commandline> <dll debugger>
        PROCESS_INFORMATION pi;
        STARTUPINFOA si;
        BOOL fSuccess, fConnected;
        int RetVal;
        CONTEXT ctx;
        TCHAR DebugOutput[MAX_PATH];
        DWORD  dwThreadId, cbBytesRead, cbWritten, cbReplyBytes, ExitCode;
        DWORD_PTR OEP, RemoteFuncAddress;
        HANDLE hPipe; 
        char lpszPipename[MAX_PATH]; 
                
        RemoteFuncAddress = 0;
        fConnected = FALSE; 
        dwThreadId = 0; 
        hPipe = INVALID_HANDLE_VALUE;
        
        memset(&si, 0, sizeof(si));
        if (__argc != 5)
            return ERROR_ARGCOUNT;
        
        if (!CreateProcessA(__argv[2], __argv[3], NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
        {
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("Failed to create process, last error=%d.\n"), GetLastError());
            OutputDebugString(DebugOutput);
            return -6;        
        }
        else
        {
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("CreateProcess succeeded.\n"));
            OutputDebugString(DebugOutput);
        }        

        memset(lpszPipename, 0, MAX_PATH*sizeof(CHAR));
        sprintf_s(lpszPipename, MAX_PATH, "\\\\.\\pipe\\CAPEpipe_%x", pi.dwProcessId);

        hPipe = CreateNamedPipe
        ( 
            lpszPipename,             	// pipe name 
            PIPE_ACCESS_DUPLEX,       	// read/write access 
            PIPE_TYPE_MESSAGE |       	// message type pipe 
            PIPE_READMODE_MESSAGE |   	// message-read mode 
            PIPE_WAIT,                	// blocking mode 
            PIPE_UNLIMITED_INSTANCES, 	// max. instances  
            BUFSIZE,                  	// output buffer size 
            BUFSIZE,                  	// input buffer size 
            0,                        	// client time-out 
            NULL
        );								// default security attribute 

        if (hPipe == INVALID_HANDLE_VALUE) 
        {
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("CreateNamedPipe failed, GLE=%d.\n"), GetLastError());
            OutputDebugString(DebugOutput);
            return -5;
        }
        else
        {
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("CreateNamedPipe succeeded.\n"));
            OutputDebugString(DebugOutput);
        }
        
        RetVal = inject(pi.dwProcessId, pi.dwThreadId, __argv[4], TRUE, INJECT_CREATEREMOTETHREAD);

        memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
        _stprintf_s(DebugOutput, MAX_PATH, TEXT("Returned from inject, about to call ConnectNamedPipe.\n"));
        OutputDebugString(DebugOutput);
        
        // Wait for the client to connect; if it succeeds, 
        // the function returns a nonzero value. If the function
        // returns zero, GetLastError returns ERROR_PIPE_CONNECTED. 

        fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); 
        fSuccess = FALSE;
        cbBytesRead = 0;
        
        if (fConnected) 
        { 
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("Client connected\n"));
            OutputDebugString(DebugOutput);	
            
            fSuccess = ReadFile
            ( 
                hPipe,        			    // handle to pipe 
                &RemoteFuncAddress,         // buffer to receive data 
                sizeof(DWORD_PTR),			// size of buffer 
                &cbBytesRead, 			    // number of bytes read 
                NULL          			    // not overlapped I/O
            );
        } 
        else 
        {
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("The client could not connect, closing pipe.\n"));
            OutputDebugString(DebugOutput);		
            CloseHandle(hPipe);
            return -7;
        }
        
        if (!fSuccess || cbBytesRead == 0)
        {   
            if (GetLastError() == ERROR_BROKEN_PIPE)
            {
                memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
                _stprintf_s(DebugOutput, MAX_PATH, TEXT("Client disconnected, GLE=%d.\n"), GetLastError());
                OutputDebugString(DebugOutput);
            }
            else
            {
                memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
                _stprintf_s(DebugOutput, MAX_PATH, TEXT("ReadFile failed, last error=%d.\n"), GetLastError());
                OutputDebugString(DebugOutput);
            }
        }

        if (!RemoteFuncAddress)
        {
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("Successfully read from pipe, however RemoteFuncAddress = 0, last error=%d.\n"), GetLastError());
            OutputDebugString(DebugOutput);
            return -8;
        }
        
        memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
        _stprintf_s(DebugOutput, MAX_PATH, TEXT("Successfully received debugger init address: 0x%x.\n"), RemoteFuncAddress);
        OutputDebugString(DebugOutput);		

        ctx.ContextFlags = CONTEXT_ALL;
        if (!GetThreadContext(pi.hThread, &ctx))
        {
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("GetThreadContext failed - FATAL\n"));
            OutputDebugString(DebugOutput);		
            return -9;
        }

#ifndef _WIN64       
        OEP = ctx.Eax;  // eax holds eip on 32-bit
#else                 
        OEP = ctx.Rcx;  // rcx holds rip on 64-bit
#endif        
        
        memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
#ifndef _WIN64       
        _stprintf_s(DebugOutput, MAX_PATH, TEXT("GetThreadContext gives OEP=0x%x\n"), ctx.Eax);
#else
        _stprintf_s(DebugOutput, MAX_PATH, TEXT("GetThreadContext gives OEP=0x%x\n"), ctx.Rcx);
#endif        
        OutputDebugString(DebugOutput);	
        
        cbWritten = 0;
        cbReplyBytes = sizeof(DWORD_PTR);
        
        // Write the reply to the pipe. 
        fSuccess = WriteFile
        ( 
            hPipe,        		// handle to pipe 
            &OEP,				// buffer to write from 
            cbReplyBytes, 		// number of bytes to write 
            &cbWritten,   		// number of bytes written 
            NULL          		// not overlapped I/O 
        );
        if (!fSuccess || cbReplyBytes != cbWritten)
        {   
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("Failed to send OEP via pipe, last error=%d.\n"), GetLastError());
            OutputDebugString(DebugOutput);					
        }
        else
        {   
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("Sent OEP 0x%x via pipe\n"), OEP);
            OutputDebugString(DebugOutput);					
        }

        if (RetVal == 1)
        {
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("Loader: Child process created, suspended, DLL successfully injected\n"));
            OutputDebugString(DebugOutput);

            ctx.ContextFlags = CONTEXT_ALL;
#ifndef _WIN64       
            ctx.Eax = RemoteFuncAddress;		// eax holds new entry point
#else
            ctx.Rcx = RemoteFuncAddress;		// rcx holds new entry point
#endif        
            if (!SetThreadContext(pi.hThread, &ctx))
            {
                memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
                _stprintf_s(DebugOutput, MAX_PATH, TEXT("Failed to set new EP\n"));
                OutputDebugString(DebugOutput);
            }
            else
            {
                memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
#ifndef _WIN64       
                _stprintf_s(DebugOutput, MAX_PATH, TEXT("Set new EP to 0x%x\n"), ctx.Eax);
#else
                _stprintf_s(DebugOutput, MAX_PATH, TEXT("Set new EP to 0x%x\n"), ctx.Rcx);
#endif        
                OutputDebugString(DebugOutput);                
            }
        }
        
        Sleep(1000);
        
        CloseHandle(hPipe);
        
        ResumeThread(pi.hThread);
        
        Sleep(5000);
        
        if (GetExitCodeProcess(pi.hProcess, &ExitCode))
        {
            memset(DebugOutput, 0, MAX_PATH*sizeof(TCHAR));
            _stprintf_s(DebugOutput, MAX_PATH, TEXT("Exit code: 0x%x\n"), ExitCode);
            OutputDebugString(DebugOutput);                        
        }
        
        return 1;
    }
    else if (!strcmp(__argv[1], "dump")) 
    {
        int pid;
        char *dumpfile;
        
        if (__argc != 4)
            return ERROR_ARGCOUNT;
        pid = atoi(__argv[2]);
        dumpfile = __argv[3];
        return dump(pid, dumpfile);
    }
#ifdef CUCKOODBG
	else if (!strcmp(__argv[1], "pipe")) {
		// usage: loader.exe pipe <pipe name> <dll to load>
		HANDLE pipehandle;
		char pipe_name[512];
		FILE *f = fopen("c:\\cmds.log", "a");

		if (__argc != 4)
			return ERROR_ARGCOUNT;

		_snprintf(pipe_name, sizeof(pipe_name)-1, "\\\\.\\PIPE\\%s", __argv[2]);

		while (1) {
			pipehandle = CreateNamedPipeA(pipe_name, PIPE_ACCESS_DUPLEX,
				PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
				PIPE_UNLIMITED_INSTANCES,
				16384,
				16384,
				0,
				NULL);
			if (ConnectNamedPipe(pipehandle, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
				char buf[16384];
				char response[16384];
				int response_len = 0;
				int bytes_read = 0;
				int bytes_written = 0;
				memset(buf, 0, sizeof(buf));
				ReadFile(pipehandle, buf, sizeof(buf), &bytes_read, NULL);
				fprintf(f, "%s\n", buf);
				fflush(f);
				if (!strncmp(buf, "PROCESS:", 8)) {
					int pid = -1, tid = -1;
					char *p;
					if ((p = strchr(buf, ','))) {
						*p = '\0';
						pid = atoi(&buf[8]);
						tid = atoi(p + 1);
					}
					else {
						pid = atoi(&buf[8]);
					}
					inject(pid, tid, __argv[3], is_suspended(pid, tid), INJECT_QUEUEUSERAPC);
				}
				WriteFile(pipehandle, response, response_len, &bytes_written, NULL);
				CloseHandle(pipehandle);
			}
		}
		fclose(f);
	}
#endif
	return ERROR_MODE;
}