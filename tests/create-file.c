#include <stdio.h>
#include <windows.h>

int main()
{
    const char *modes[] = {"r", "r+", "w", "w+", "a", "a+"};
    const char *fname = "abc";

    for (int i = 0; i < sizeof(modes)/sizeof(char *); i++) {
        DeleteFile(fname);
        FILE *fp = fopen(fname, modes[i]);
        if(fp != NULL) {
            fclose(fp);
        }
    }

    fclose(fopen(fname, "w"));
    for (int i = 0; i < sizeof(modes)/sizeof(char *); i++) {
        FILE *fp = fopen(fname, modes[i]);
        if(fp != NULL) {
            fclose(fp);
        }
    }
}
