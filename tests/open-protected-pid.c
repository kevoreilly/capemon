#include <stdio.h>
#include <windows.h>

int main()
{
    // this is the process identifier of agent.py on my VM
    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 1576);
    printf("process-handle: %p -> %d\n", process_handle, GetLastError());
    return 0;
}
