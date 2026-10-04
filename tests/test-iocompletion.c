#include <stdio.h>
#include <windows.h>

typedef NTSTATUS (WINAPI *pfnNtSetIoCompletion)(
    HANDLE IoCompletionHandle,
    PVOID KeyContext,
    PVOID ApcContext,
    NTSTATUS IoStatus,
    ULONG_PTR IoStatusInformation
);

int main()
{
    LoadLibrary("../capemon.dll");

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("Failed to get ntdll handle\n");
        return 1;
    }

    pfnNtSetIoCompletion pNtSetIoCompletion = (pfnNtSetIoCompletion)GetProcAddress(hNtdll, "NtSetIoCompletion");
    if (!pNtSetIoCompletion) {
        printf("NtSetIoCompletion not found in ntdll\n");
        return 1;
    }

    HANDLE hIocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
    if (!hIocp) {
        printf("CreateIoCompletionPort failed: %lu\n", GetLastError());
        return 1;
    }

    // Test queuing an I/O completion packet via NtSetIoCompletion
    NTSTATUS status = pNtSetIoCompletion(hIocp, (PVOID)0x1337, (PVOID)0x4242, 0, 100);
    printf("NtSetIoCompletion -> 0x%08lX\n", (unsigned long)status);

    DWORD bytes = 0;
    ULONG_PTR key = 0;
    LPOVERLAPPED overlapped = NULL;
    BOOL ok = GetQueuedCompletionStatus(hIocp, &bytes, &key, &overlapped, 1000);
    printf("GetQueuedCompletionStatus: ok=%d, bytes=%lu, key=0x%p, overlapped=0x%p\n",
        ok, bytes, (void*)key, (void*)overlapped);

    CloseHandle(hIocp);
    return 0;
}
