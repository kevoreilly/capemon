#define _WIN32_WINNT 0x0601
#include <stdio.h>
#include <windows.h>

typedef NTSTATUS (WINAPI *pfnNtSetIoCompletion)(
    HANDLE IoCompletionHandle,
    PVOID KeyContext,
    PVOID ApcContext,
    NTSTATUS IoStatus,
    ULONG_PTR IoStatusInformation
);

static volatile LONG g_wait_callback_fired = 0;

static VOID CALLBACK WaitCallback(
    PTP_CALLBACK_INSTANCE Instance,
    PVOID Context,
    PTP_WAIT Wait,
    TP_WAIT_RESULT WaitResult
) {
    (void)Instance;
    (void)Wait;
    (void)WaitResult;
    InterlockedIncrement(&g_wait_callback_fired);
    printf("WaitCallback fired, context=%p\n", Context);
}

int main(void)
{
    LoadLibrary("../capemon.dll");

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("Failed to get ntdll handle\n");
        return 1;
    }

    pfnNtSetIoCompletion pNtSetIoCompletion = (pfnNtSetIoCompletion)(void *)GetProcAddress(hNtdll, "NtSetIoCompletion");
    if (!pNtSetIoCompletion) {
        printf("NtSetIoCompletion not found in ntdll\n");
        return 1;
    }

    HANDLE hIocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
    if (!hIocp) {
        printf("CreateIoCompletionPort failed: %lu\n", GetLastError());
        return 1;
    }

    // 1. Test queuing an I/O completion packet via NtSetIoCompletion
    NTSTATUS status = pNtSetIoCompletion(hIocp, (PVOID)0x1337, (PVOID)0x4242, 0, 100);
    printf("NtSetIoCompletion -> 0x%08lX\n", (unsigned long)status);

    DWORD bytes = 0;
    ULONG_PTR key = 0;
    LPOVERLAPPED overlapped = NULL;
    BOOL ok = GetQueuedCompletionStatus(hIocp, &bytes, &key, &overlapped, 1000);
    printf("GetQueuedCompletionStatus: ok=%d, bytes=%lu, key=0x%p, overlapped=0x%p\n",
        ok, bytes, (void*)key, (void*)overlapped);

    CloseHandle(hIocp);

    // 2. Test ThreadPool wait callback execution (CreateThreadpoolWait + SetThreadpoolWait + SetEvent)
    HANDLE hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!hEvent) {
        printf("CreateEventW failed: %lu\n", GetLastError());
        return 1;
    }

    PTP_WAIT pWait = CreateThreadpoolWait(WaitCallback, (PVOID)0xCAFE, NULL);
    if (!pWait) {
        printf("CreateThreadpoolWait failed: %lu\n", GetLastError());
        CloseHandle(hEvent);
        return 1;
    }

    SetThreadpoolWait(pWait, hEvent, NULL);
    SetEvent(hEvent);
    WaitForThreadpoolWaitCallbacks(pWait, FALSE);
    CloseThreadpoolWait(pWait);
    CloseHandle(hEvent);

    printf("WaitCallback count=%ld\n", (long)g_wait_callback_fired);
    return 0;
}
