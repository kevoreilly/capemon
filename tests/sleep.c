#include <stdio.h>
#include <windows.h>

DWORD WINAPI thread(LPVOID lpNothing)
{
    return 0;
}

int main()
{
    LoadLibrary("../cuckoomon.dll");

    // sleep for five seconds (skipped)
    for (int i = 0; i < 100; i++) {
        Sleep(50);

        printf("tick: %ld\n", GetTickCount());
    }

    // sleep for 10 seconds (skipped)
    Sleep(10000);

    printf("tick: %ld\n", GetTickCount());

    printf("starting second thread\n");
    CloseHandle(CreateThread(NULL, 0, &thread, NULL, 0, NULL));

    // sleep for 5 seconds (not skipped)
    Sleep(5000);
}
