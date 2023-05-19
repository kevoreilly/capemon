
#include <stdio.h>
#include <Windows.h>


int main() {

    CloseHandle(
        CreateFile2(L"test.txt", 0, 0, CREATE_ALWAYS, NULL));

    CopyFile2(L"test.txt", L"test2.txt", NULL);

    DeleteFileW(L"test.txt"); system("DEL / Q test2.txt");

    return EXIT_SUCCESS;
}