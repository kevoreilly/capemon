#include <stdio.h>
#include <stdlib.h>

int main()
{
    const char *fnames[] = {
        "C:\\a.txt",
        "C:\\b.txt",
        "C:\\c.txt",
        "C:\\d.txt",
        "C:\\e.txt",
    };

    FILE *fp[3];
    for (int i = 0; i < 5; i++) {
        fp[i] = fopen(fnames[i], "w");
    }

    for (int i = 0; i < 20; i++) {
        fprintf(fp[rand() % 5], "Hello %d\n", i);
    }

    for (int i = 0; i < 20; i++) {
        int idx = rand() % 5;
        if(fp[idx] != NULL) {
            fclose(fp[idx]);
            fp[idx] = NULL;
        }
    }
}
