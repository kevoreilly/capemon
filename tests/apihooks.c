#include <stdio.h>
#include <windows.h>
#include <direct.h>

DWORD WINAPI dummy(LPVOID lpValue)
{
    printf("dummy here!\n");
    return 0;
}

int main()
{
    // there we go
    LoadLibrary("../cuckoomon.dll");

    FILE *fp = fopen("test-hello", "r");
    if(fp != NULL) fclose(fp);

    fp = fopen("test-hello", "wb");
    fwrite("whatsup", 1, 6, fp);
    fclose(fp);

    fp = fopen("test-hello", "rb");
    char buf[6];
    fread(buf, 1, 6, fp);
    fclose(fp);

    _mkdir("abc");

    DeleteFile("test-hello");

    HKEY hKey;
    if(RegCreateKeyEx(HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, 0,
            KEY_ALL_ACCESS, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegQueryInfoKey(hKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL);
        RegSetValueEx(hKey, "TestApiHooks", 0, REG_SZ, (BYTE *) "Hoi", 3);
        RegDeleteValue(hKey, "TestApiHooks");
        RegCloseKey(hKey);
    }

    system("echo hai");

    WinExec("echo hi there", SW_SHOW);

    CreateMutex(NULL, FALSE, "MutexNam3");
    OpenMutex(MUTEX_ALL_ACCESS, FALSE, "OpenMutexName");

    // just some random dll
    LoadLibrary("urlmon.dll");

    FARPROC sleep = GetProcAddress(GetModuleHandle("kernel32"), "Sleep");
    sleep(1000);

    printf("debugger: %d\n", IsDebuggerPresent());

    CloseHandle(CreateThread(NULL, 0, &dummy, NULL, 0, NULL));

    HANDLE thread_handle = CreateRemoteThread(GetCurrentProcess(), NULL, 0,
        &dummy, NULL, 0, NULL);
    WaitForSingleObject(thread_handle, INFINITE);
    CloseHandle(thread_handle);
}
