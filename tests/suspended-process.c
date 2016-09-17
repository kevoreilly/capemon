#include <stdio.h>
#include <windows.h>

int main(int argc, char *argv[])
{
    if(argc != 1) {
        printf("arg: %s\n", argv[1]);
        fflush(stdout);
        return 1337;
    }

    STARTUPINFO si = {sizeof(si)}; PROCESS_INFORMATION pi; char buf[256];

    sprintf(buf, "\"%s\" a", argv[0]);

    BOOL ret = CreateProcess(argv[0], buf, NULL, NULL, FALSE,
        CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    printf("ret: %d\n", ret);
    fflush(stdout);

    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hThread, INFINITE);
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    printf("ret: %d\n", exit_code);
    fflush(stdout);
}
