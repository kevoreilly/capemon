#include <stdio.h>
#include <string.h>
#include "lookup.h"

typedef struct _entry_t {
    struct _entry_t *next;
    unsigned int id;
    unsigned int size;
    unsigned char data[0];
} entry_t;

int main()
{
    lookup_t a;

    lookup_init(&a);
    strcpy((char *) lookup_add(&a, 1, 10), "abc");
    strcpy((char *) lookup_add(&a, 2, 20), "def");
    lookup_del(&a, 1);
    strcpy((char *) lookup_add(&a, 3, 30), "ghi");
    strcpy((char *) lookup_add(&a, 4, 40), "jkl");
    lookup_del(&a, 4);

    for (int i = 0; i < 5; i++) {
        printf("%d -> %p\n", i, lookup_get(&a, i, NULL));
    }

    for (entry_t *p = a.root; p != NULL; p = p->next) {
        printf("%p %d %d\n", p, p->id, p->size);
    }
}
