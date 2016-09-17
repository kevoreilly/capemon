#include <stdio.h>
#include <windows.h>

/* multiple ways to inject into another process */

int main(int argc, char *argv[])
{
    if(argc == 2) {
        printf("Child process %s.. exiting..\n", argv[1]);
        ExitProcess(0);
    }

    char buf[256];

    // WinExec
    sprintf(buf, "\"%s\" a", argv[0]);
    WinExec(buf, SW_SHOW);

    // ShellExecute
    ShellExecute(NULL, NULL, argv[0], "b", NULL, SW_SHOW);

    // CreateProcess
    sprintf(buf, "\"%s\" c", argv[0]);
    STARTUPINFO si = {sizeof(si)}; PROCESS_INFORMATION pi = {};
    CreateProcess(NULL, buf, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

    // system
    sprintf(buf, "\"%s\" d", argv[0]);
    system(buf);

    return 0;
}
