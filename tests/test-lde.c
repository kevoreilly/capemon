#include <stdio.h>
#include "../hooking.h"

int main()
{
    unsigned char b[][8] = {
        {0x55},
        {0x89, 0xe5},
        {0x83, 0xec, 0x18},
    };

    for (int i = 0; i < sizeof(b)/sizeof(b[0]); i++) {
        printf("%d\n", lde(b[i]));
    }
}
