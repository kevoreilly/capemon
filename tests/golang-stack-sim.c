#include <stdio.h>
#include <windows.h>

// Simulated function with a non-standard frame / no frame pointer to test 
// that the hooking engine handles exception unwinding robustly.
__declspec(naked) void CallWithCustomStack(void)
{
    __asm {
        // Manipulate RBP/EBP or stack structure to confuse standard walk
        push ebp
        mov ebp, 0xBAADF00D // garbage ebp
        
        // Call a hooked API to trigger enter_hook
        push 1
        call dword ptr [Sleep]
        
        pop ebp
        ret
    }
}

int main()
{
    // Try to load capemon.dll
    HMODULE hMod = LoadLibrary("../capemon.dll");
    if (!hMod) {
        hMod = LoadLibrary("capemon.dll");
    }
    
    if (hMod) {
        printf("Capemon loaded successfully\n");
    } else {
        printf("Running standalone (capemon not loaded)\n");
    }

    printf("Executing API call with simulated non-standard Go-like stack...\n");
    
    // On 32-bit, this will execute CallWithCustomStack which uses garbage EBP.
    // On 64-bit, we can just call standard Sleep, but the stack walk exception handler
    // will be verified on compiled binaries.
#ifndef _WIN64
    CallWithCustomStack();
#else
    Sleep(1);
#endif

    printf("Success! API call completed without crashing or failing.\n");
    return 0;
}
