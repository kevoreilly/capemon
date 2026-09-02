// capemon_wow64 - native x64 monitor injected alongside the 32-bit monitor into a
// WOW64 target, so calls made through Heaven's Gate (far call/jmp to 0x33 to run
// native x64 ntdll syscalls) are still observed.
//
// This DLL is deliberately standalone and CRT-less: it does NOT include capemon's
// ntapi.h / alloc.h (those pull in the whole NT surface plus externs that would need
// to link against the main monitor). Only the few NT types it uses are declared here.

#include <windows.h>

#ifndef NT_SUCCESS
typedef LONG NTSTATUS;
#endif
#define WOW64_STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)

// x64 TEB.TlsSlots is a PVOID[64] array at offset 0x1480 (stable on Win10/11 x64).
// TODO: replace this fixed slot with a TlsAlloc()'d index - TlsAlloc hands out low
// indices first, so a high slot is the least-bad interim choice.
#define TEB_TLS_SLOTS_OFFSET 0x1480
#define TEB_TLS_SLOT_WOW64   63

// Prevent infinite recursion when our hooks call native APIs. Per-thread state (TEB),
// so the non-atomic read/modify/write is safe.
static BOOL check_and_increment_recursion(void)
{
    DWORD64 teb_base = __readgsqword(0x30); // 64-bit TEB
    volatile ULONG_PTR *tls_slots = (volatile ULONG_PTR *)(teb_base + TEB_TLS_SLOTS_OFFSET);
    if (tls_slots[TEB_TLS_SLOT_WOW64] > 0)
        return FALSE;
    tls_slots[TEB_TLS_SLOT_WOW64]++;
    return TRUE;
}

static void decrement_recursion(void)
{
    DWORD64 teb_base = __readgsqword(0x30);
    volatile ULONG_PTR *tls_slots = (volatile ULONG_PTR *)(teb_base + TEB_TLS_SLOTS_OFFSET);
    if (tls_slots[TEB_TLS_SLOT_WOW64] > 0)
        tls_slots[TEB_TLS_SLOT_WOW64]--;
}

// PUSH imm32 / RET instead of a JMP: the trampoline lives in the low 4GB (so the
// sign-extended imm32 is exact) while native ntdll can sit anywhere in the address space.
void write_wow64_trampoline(void *source, void *destination)
{
    // 68 <imm32>  PUSH destination
    // C3          RET
    BYTE push_ret_stub[] = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xC3 };
    *(DWORD *)(push_ret_stub + 1) = (DWORD)(ULONG_PTR)destination;

    // TODO: patch `source` with push_ret_stub via NtProtectVirtualMemory (RW) ->
    // copy -> NtProtectVirtualMemory (restore), using natively-resolved ntdll exports.
    (void)source;
}

// ----------------------------------------------------------------------
// Example hook: NtAllocateVirtualMemory
// ----------------------------------------------------------------------
typedef NTSTATUS (NTAPI *fnNtAllocateVirtualMemory)(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
static fnNtAllocateVirtualMemory original_NtAllocateVirtualMemory = NULL;

NTSTATUS NTAPI Hook_NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    if (check_and_increment_recursion())
    {
        // Intercepted natively in x64 space - Heaven's Gate evasion is nullified here.
        // TODO: package telemetry and transmit to the 32-bit counterpart
        //       (named pipe via NtWriteFile, or a shared NtCreateSection).
        decrement_recursion();
    }

    // original_ is wired up by write_wow64_trampoline() at init; guard until then.
    if (!original_NtAllocateVirtualMemory)
        return WOW64_STATUS_NOT_IMPLEMENTED;

    return original_NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

// CRT-less entry point (linker: /ENTRY:DllMain, IgnoreAllDefaultLibraries).
BOOL WINAPI DllMain(HINSTANCE hInstDll, DWORD fdwReason, LPVOID lpvReserved)
{
    UNREFERENCED_PARAMETER(hInstDll);
    UNREFERENCED_PARAMETER(lpvReserved);

    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        // TODO: resolve ntdll exports natively and install hooks, e.g.
        // write_wow64_trampoline(real_NtAllocateVirtualMemory, Hook_NtAllocateVirtualMemory);
    }
    return TRUE;
}
