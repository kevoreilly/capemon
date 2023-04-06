
/*
    from: http://www.rohitab.com/discuss/topic/43926-setwindowshookex-dll-injection-my-code-and-some-questions/
*/

#include <stdio.h>
#include <windows.h>


int main() {

    // there we go
    LoadLibrary("../cuckoomon.dll");

    PostThreadMessage(GetCurrentThread(), WM_NULL, NULL, NULL);

    PostThreadMessage(-2, WM_USER + 1, NULL, NULL);

    return EXIT_SUCCESS;
}