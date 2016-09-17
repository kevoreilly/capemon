#include <stdio.h>
#include <stdint.h>
#include <windows.h>

// Idea originally taken from the following article
// http://spth.virii.lu/v4/articles/m0sa/evade.html

int main()
{
    if(GetTickCount() < 10 * 60 * 1000) {
        printf("Running under a VM!\n");
    }
    else {
        printf("This computer is ok! Uptime: %d\n", GetTickCount());
    }
}
