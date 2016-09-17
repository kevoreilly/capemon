#include <stdio.h>
#include <windows.h>

int main()
{
    // process identifier of explorer.exe on my VM
    CloseHandle(OpenProcess(PROCESS_ALL_ACCESS, FALSE, 468));
}
