#include <stdio.h>
#include <windows.h>

int main(int argc, char *argv[])
{
    if(argc == 4) {
        Sleep(5000);
        return 0;
    }

    Sleep(10000);

    char buf[256];
    sprintf(buf, "%s a b c", argv[0]);
    system(buf);
}
