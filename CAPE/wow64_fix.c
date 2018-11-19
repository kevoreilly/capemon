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
#ifndef _WIN64
#include "w64wow64\w64wow64.h"
// Based upon ReWolf's wow64ext library:
// https://github.com/rwfpl/rewolf-wow64ext

#define DR7_MASK_RWE0 0xFFFDFFFF    // 11111111111111011111111111111111
#define DR7_MASK_RWE1 0xFFDFFFFF    // 11111111110111111111111111111111
#define DR7_MASK_RWE2 0xFDFFFFFF    // 11111101111111111111111111111111
#define DR7_MASK_RWE3 0xDFFFFFFF    // 11011111111111111111111111111111

const int PAGE_SIZE = 0x1000;

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);

BOOL WoW64HookInstalled;

DWORD64 lpHookCode = (DWORD64)NULL;
DWORD64 lpNewJumpLocation;

DWORD64 pfnKiUserExceptionDispatcher;
DWORD64 pfnNtSetContextThread;
DWORD64 pfnWow64PrepareForException;

//**************************************************************************************
extern BOOL WoW64PatchBreakpoint(unsigned int Register)
//**************************************************************************************
{
    if (WoW64HookInstalled == FALSE)
        return FALSE;

    DoOutputDebugString("WoW64PatchBreakpoint entry, debug register: %d, current DR7 mask = 0x%x\n", Register, *(DWORD*)(((PBYTE)lpNewJumpLocation)+37));

    switch(Register)
	{
      case 0:
        *(DWORD*)(((PBYTE)lpNewJumpLocation)+37) = (*(DWORD*)(((PBYTE)lpNewJumpLocation)+37) & DR7_MASK_RWE0);
        break;
      case 1:
        *(DWORD*)(((PBYTE)lpNewJumpLocation)+37) = (*(DWORD*)(((PBYTE)lpNewJumpLocation)+37) & DR7_MASK_RWE1);
        break;
      case 2:
        *(DWORD*)(((PBYTE)lpNewJumpLocation)+37) = (*(DWORD*)(((PBYTE)lpNewJumpLocation)+37) & DR7_MASK_RWE2);
        break;
      case 3:
        *(DWORD*)(((PBYTE)lpNewJumpLocation)+37) = (*(DWORD*)(((PBYTE)lpNewJumpLocation)+37) & DR7_MASK_RWE3);
        break;
    }

    DoOutputDebugString("WoW64PatchBreakpoint: patched DR7 mask = 0x%x\n", *(DWORD*)(((PBYTE)lpNewJumpLocation)+37));

    return TRUE;
}

//**************************************************************************************
extern BOOL WoW64UnpatchBreakpoint(unsigned int Register)
//**************************************************************************************
{
    if (WoW64HookInstalled == FALSE)
        return FALSE;

    DoOutputDebugString("WoW64UnpatchBreakpoint entry, debug register: %d, current DR7 mask = 0x%x\n", Register, *(DWORD*)(((PBYTE)lpNewJumpLocation)+37));

    switch(Register)
	{
      case 0:
        *(DWORD*)(((PBYTE)lpNewJumpLocation)+37) = (*(DWORD*)(((PBYTE)lpNewJumpLocation)+37) | ~DR7_MASK_RWE0);
        break;
      case 1:
        *(DWORD*)(((PBYTE)lpNewJumpLocation)+37) = (*(DWORD*)(((PBYTE)lpNewJumpLocation)+37) | ~DR7_MASK_RWE1);
        break;
      case 2:
        *(DWORD*)(((PBYTE)lpNewJumpLocation)+37) = (*(DWORD*)(((PBYTE)lpNewJumpLocation)+37) | ~DR7_MASK_RWE2);
        break;
      case 3:
        *(DWORD*)(((PBYTE)lpNewJumpLocation)+37) = (*(DWORD*)(((PBYTE)lpNewJumpLocation)+37) | ~DR7_MASK_RWE3);
        break;
    }

    DoOutputDebugString("WoW64UnpatchBreakpoint: unpatched DR7 mask = 0x%x\n", *(DWORD*)(((PBYTE)lpNewJumpLocation)+37));

    return TRUE;
}

//**************************************************************************************
const DWORD64 CreateHook(const DWORD_PTR pKiUserExceptionDispatcher, const DWORD_PTR pNtSetContextThread64, const DWORD_PTR pWow64PrepareForException)
//**************************************************************************************
// credit to Omega Red http://pastebin.ca/raw/475547
{
    unsigned char HookBytes[] =
    {
        0x81, 0xBC, 0x24, 0xF0, 0x04, 0x00, 0x00, 0x1E, 0x00, 0x00, 0x40,   //cmp 	dword [rsp+0x4f0], 0x4000001e	; wow64 single step?    0
        0x75, 0x37,                                                         //jne 	hook_end                                                11

        0x49, 0x89, 0xCC,                                                   //mov     r12, rcx                                              13
        0x49, 0x89, 0xD5,                                                   //mov     r13, rdx                                              16
        0x4D, 0x89, 0xC6,                                                   //mov     r14, r8                                               19
        0x4D, 0x89, 0xCF,                                                   //mov     r15, r9                                               22
        0xC7, 0x44, 0x24, 0x30, 0x10, 0x00, 0x10, 0x00,                     //mov     dword ptr [rsp+30h], 100010h                          25
        0x81, 0x64, 0x24, 0x70, 0xFF, 0xFF, 0xFF, 0xFF,                     //and     dword ptr [rsp+70h], 0xFFFFFFFF                       33
        0x48, 0xC7, 0xC1, 0xFE, 0xFF, 0xFF, 0xFF,                           //mov     rcx, 0FFFFFFFFFFFFFFFEh                               41
        0x48, 0x89, 0xE2,                                                   //mov     rdx, rsp                                              48
        0xE8, 0xBE, 0x07, 0xAF, 0x77,                                       //call    near ptr Xh                                           51
        0x4C, 0x89, 0xE1,                                                   //mov     rcx, r12                                              56
        0x4C, 0x89, 0xEA,                                                   //mov     rdx, r13                                              59
        0x4D, 0x89, 0xF0,                                                   //mov     r8, r14                                               62
        0x4D, 0x89, 0xF9,                                                   //mov     r9, r15                                               65
//hook_end
        0xFC,                                                               //cld  - first two instructions from KiUserExceptionDispatcher  68
        0x48, 0xB8, 0xDD, 0xCC, 0xBB, 0xAA, 0x00, 0x00, 0x00, 0x00,         //mov     rax, 0AABBCCDDh                                       69
        0x50,                                                               //push    rax - jump back to KiUserExceptionDispatcher+8        79
        0x48, 0xB8, 0xDD, 0xCC, 0xBB, 0xAA, 0x00, 0x00, 0x00, 0x00,         //mov     rax, 0AABBCCDDh                                       80
        0x48, 0x87, 0x04, 0x24,                                             //xchg    rax, [rsp]                                            90
        0xC3                                                                //ret                                                           94
    };                                                                      //                                                              86

    lpHookCode = VirtualAllocEx64((HANDLE) -1, (DWORD64)NULL, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    //insert relative address of NtSetContextThread64 from instruction after call
    DWORD RelativeOffset = pNtSetContextThread64 - ((DWORD)lpHookCode + 56);
    memcpy(&HookBytes[52], &RelativeOffset, sizeof(DWORD_PTR));

    //insert VA of Wow64PrepareForException
    memcpy(&HookBytes[71], &pWow64PrepareForException, sizeof(DWORD_PTR));

    //insert address to return to from hook code at 8 bytes into KiUserExceptionDispatcher
    DWORD ReturnAddress = pKiUserExceptionDispatcher + 8;
    memcpy(&HookBytes[82], &ReturnAddress, sizeof(DWORD_PTR)); //(8 is address of third instruction)

    //copy it to newly created page
    memcpy((LPVOID)lpHookCode, (const void *)HookBytes, sizeof(HookBytes));

    return lpHookCode;
}

//**************************************************************************************
const void EnableWow64Hook()
//**************************************************************************************
{
    unsigned char trampolineBytes[] =
    {
        0xE9, 0xDD, 0xCC, 0xBB, 0xAA,                              // jmp +0xAABBCCDDEE+5
        0xCC, 0xCC, 0xCC                                           //
    };
    DWORD pNew = (DWORD)lpNewJumpLocation;
	DWORD pOrig = (DWORD)pfnKiUserExceptionDispatcher + 5;
    DWORD RelativeOffset = pNew - pOrig;
    memcpy(&trampolineBytes[1], (PVOID)&RelativeOffset, sizeof(DWORD_PTR));

    DWORD dwOldProtect = 0;
    if (!VirtualProtectEx64((HANDLE)-1, (DWORD64)pfnKiUserExceptionDispatcher, PAGE_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtect))
    {
        DoOutputErrorString("VirtualProtectEx64 failed to set PAGE_EXECUTE_READWRITE");
        return;
    }

    memcpy((PVOID)pfnKiUserExceptionDispatcher, &trampolineBytes, sizeof(trampolineBytes));

    if (!VirtualProtectEx64((HANDLE)-1, (DWORD64)pfnKiUserExceptionDispatcher, PAGE_SIZE, dwOldProtect, &dwOldProtect))
    {
        DoOutputErrorString("VirtualProtect failed to restore dwOldProtect");
        return;
    }
}

//**************************************************************************************
extern BOOL WoW64fix(void)
//**************************************************************************************
{
    IsWow64Process(GetCurrentProcess(), &WoW64HookInstalled);
    if (WoW64HookInstalled == FALSE)
    {
        DoOutputDebugString("WoW64 not detected.\n");
        return FALSE;
    }

    //DWORD ntdll64 = getNTDLL64();
    //DWORD wow64dll = GetModuleHandle64(L"wow64.dll");

    DWORD64 ntdll64 = GetModuleBase64(L"ntdll.dll");
    DWORD64 wow64dll = GetModuleBase64(L"wow64.dll");
    DWORD64 pfnWow64PrepareForException = GetProcAddress64(wow64dll, "Wow64PrepareForException");
    pfnKiUserExceptionDispatcher = GetProcAddress64(ntdll64, "KiUserExceptionDispatcher");
    pfnNtSetContextThread = GetProcAddress64(ntdll64, "NtSetContextThread");

    DoOutputDebugString("WoW64 detected: 64-bit ntdll base: 0x%x, KiUserExceptionDispatcher: 0x%x, NtSetContextThread: 0x%x, Wow64PrepareForException: 0x%x\n", ntdll64, pfnKiUserExceptionDispatcher, pfnNtSetContextThread, pfnWow64PrepareForException);

    lpNewJumpLocation = CreateHook((DWORD_PTR)pfnKiUserExceptionDispatcher, (DWORD_PTR)pfnNtSetContextThread, (DWORD_PTR)pfnWow64PrepareForException);

    EnableWow64Hook();

    DoOutputDebugString("WoW64 workaround: KiUserExceptionDispatcher hook installed at: 0x%x\n", lpNewJumpLocation);

    return TRUE;
}
#endif