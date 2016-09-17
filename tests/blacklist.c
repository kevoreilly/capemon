#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "ignore.h"
#include "ntapi.h"

int main()
{
    const wchar_t *unicode[] = {
        L"abcd",
        L"\\??\\IDE#what's up bro?",
    };
    for (int i = 0; i < ARRAYSIZE(unicode); i++) {
        printf("%d <= %S\n",
            is_ignored_file_unicode(unicode[i], wcslen(unicode[i])),
            unicode[i]);
    }
}
