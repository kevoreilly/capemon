/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2014 Cuckoo Sandbox Developers

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ntapi.h"
#include <windows.h>
#include "lookup.h"
#include "pipe.h"

#define ENTER() EnterCriticalSection(&d->cs)
#define LEAVE() LeaveCriticalSection(&d->cs)

void lookup_init(lookup_t *d)
{
    d->root = NULL;
    InitializeCriticalSection(&d->cs);
}

void lookup_init_no_cs(lookup_t *d)
{
    d->root = NULL;
}

void lookup_free(lookup_t *d)
{
    // TODO
}

void *lookup_add(lookup_t *d, ULONG_PTR id, unsigned int size)
{
    entry_t *t = (entry_t *) malloc(sizeof(entry_t) + size);
    ENTER();
	memset(t, 0, sizeof(*t));
	t->next = d->root;
	t->id = id;
	t->size = size;
    d->root = t;
    LEAVE();
    return t->data;
}

void *lookup_add_no_cs(lookup_t *d, ULONG_PTR id, unsigned int size)
{
    entry_t *t = (entry_t *) malloc(sizeof(entry_t) + size);
	memset(t, 0, sizeof(*t));
	t->next = d->root;
	t->id = id;
	t->size = size;
    d->root = t;
    return t->data;
}

void *lookup_get(lookup_t *d, ULONG_PTR id, unsigned int *size)
{
	entry_t *p;
    ENTER();
    for (p = d->root; p != NULL; p = p->next) {
        if(p->id == id) {
			void *data;
            if(size != NULL) {
                *size = p->size;
            }
            data = p->data;
            LEAVE();
            return data;
        }
    }
    LEAVE();
    return NULL;
}

void *lookup_get_no_cs(lookup_t *d, ULONG_PTR id, unsigned int *size)
{
	entry_t *p;
    for (p = d->root; p != NULL; p = p->next) {
        if(p->id == id) {
			void *data;
            if(size != NULL) {
                *size = p->size;
            }
            data = p->data;
            return data;
        }
    }
    return NULL;
}

void lookup_del(lookup_t *d, ULONG_PTR id)
{
	entry_t *p;
	entry_t *last;

    ENTER();
    p = d->root;
    // edge case; we want to delete the first entry
    if(p != NULL && p->id == id) {
        entry_t *t = p->next;
        free(d->root);
        d->root = t;
        LEAVE();
        return;
    }
    for (last = NULL; p != NULL; last = p, p = p->next) {
        if(p->id == id) {
            last->next = p->next;
            free(p);
            break;
        }
    }
    LEAVE();
}

void lookup_del_no_cs(lookup_t *d, ULONG_PTR id)
{
	entry_t *p;
	entry_t *last;

    p = d->root;
    // edge case; we want to delete the first entry
    if(p != NULL && p->id == id) {
        entry_t *t = p->next;
        free(d->root);
        d->root = t;
        return;
    }
    for (last = NULL; p != NULL; last = p, p = p->next) {
        if(p->id == id) {
            last->next = p->next;
            free(p);
            break;
        }
    }
}
