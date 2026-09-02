#include <windows.h>
#include "../ntapi.h"

// TEB offset for Thread Local Storage (TLS) array in 64-bit mode
#define TEB_TLS_SLOT_WOW64 0x14 // Using an unused slot for recursive hook counting

// To prevent infinite recursions when our hooks call native APIs
BOOL check_and_increment_recursion(void) {
    DWORD64 teb_base = __readgsqword(0x30); // 64-bit TEB
    PDWORD tls_slots = (PDWORD)(teb_base + 0x1480); // TlsSlots array
    if (tls_slots[TEB_TLS_SLOT_WOW64] > 0) return FALSE;
    tls_slots[TEB_TLS_SLOT_WOW64]++;
    return TRUE;
}

void decrement_recursion(void) {
    DWORD64 teb_base = __readgsqword(0x30);
    PDWORD tls_slots = (PDWORD)(teb_base + 0x1480);
    if (tls_slots[TEB_TLS_SLOT_WOW64] > 0)
        tls_slots[TEB_TLS_SLOT_WOW64]--;
}

// Push/Ret stub instead of JMP to bypass 2GB limit 
// The trampoline sits in the lower 4GB, but native NTDLL can be anywhere
void write_wow64_trampoline(void* source, void* destination) {
    // x64 PUSH instruction for lower 4GB addresses pushes 8 bytes via sign extension
    // 68 [4 bytes address] -> PUSH address
    // C3                   -> RET
    BYTE push_ret_stub[] = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xC3 };
    
    // Fill in the destination trampoline address (must be < 4GB)
    *(DWORD*)(push_ret_stub + 1) = (DWORD)(ULONG_PTR)destination;

    // Use native NTDLL API to patch
    // (Assuming NtProtectVirtualMemory is dynamically resolved)
    // NtProtectVirtualMemory(...)
    // RtlCopyMemory((PBYTE)source, push_ret_stub, sizeof(push_ret_stub));
    // NtProtectVirtualMemory(...) (Restore)
}

// ----------------------------------------------------------------------
// Example Hook: NtAllocateVirtualMemory
// ----------------------------------------------------------------------
typedef NTSTATUS(NTAPI *pNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
pNtAllocateVirtualMemory original_NtAllocateVirtualMemory = NULL;

NTSTATUS NTAPI Hook_NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    if (check_and_increment_recursion()) {
        // We are natively intercepting the call in x64 space!
        // Heaven's Gate evasion has been nullified.
        
        // 1. Package telemetry
        // 2. Transmit back to 32-bit counterpart via NtWriteFile (named pipe) or NtCreateSection
        
        decrement_recursion();
    }
    
    return original_NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

// DLL Entry Point must use Native DllMain without CRT
BOOL WINAPI DllMain(HINSTANCE hInstDll, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Note: CFG must be disabled via linker flags for wow64 trampoline
        // Initialize hooks natively directly on NTDLL functions
        // write_wow64_trampoline(original_NtAllocateVirtualMemory, Hook_NtAllocateVirtualMemory);
    }
    return TRUE;
}
