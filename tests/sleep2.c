#include <stdio.h>
#include <windows.h>

int main()
{
    LoadLibrary("../cuckoomon.dll");

    unsigned int start = GetTickCount();
    printf("%d\n", start);

    Sleep(1000);

    printf("%d -> %d\n", GetTickCount(), GetTickCount() - start);

    for (int i = 0; i < 10; i++) {
        for (int j = 0; j < 0xfffffff; j++);
    }

    printf("%d -> %d\n", GetTickCount(), GetTickCount() - start);

    Sleep(1000);

    printf("%d -> %d\n", GetTickCount(), GetTickCount() - start);
}
