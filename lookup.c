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

#include "ntapi.h"
#include "lookup.h"

void lookup_free(lookup_t *d)
{
	entry_t *p = (entry_t *)d->root;
	while (p) {
		entry_t *next = p->next;
		free(p);
		p = next;
	}
	d->root = NULL;
}

void *lookup_add(lookup_t *d, ULONG_PTR id, unsigned int size)
{
	entry_t *t = (entry_t *) calloc(1, sizeof(entry_t) + size);
	memset(t, 0, sizeof(*t));
	t->id = id;
	t->size = size;
	// Insert at head atomically. Loops internally until the insert succeeds
	do t->next = (entry_t *)d->root;
	while (InterlockedCompareExchangePointer((PVOID volatile *)&d->root, t, t->next) != t->next);
	return t->data;
}

void *lookup_get(lookup_t *d, ULONG_PTR id, unsigned int *size)
{
	entry_t *p;
	for (p = d->root; p != NULL; p = p->next) {
		if (p->id == id) {
			void *data;
			if (size != NULL)
				*size = p->size;
			data = p->data;
			return data;
		}
	}
	return NULL;
}

void *lookup_get_or_create(lookup_t *d, ULONG_PTR id, unsigned int size) {
	void *p = lookup_get(d, id, NULL);
	if (p == NULL) {
		p = lookup_add(d, id, size);
		memset(p, 0, size);
	}
	return p;
}

void lookup_del(lookup_t *d, ULONG_PTR id)
{
	entry_t *p, *last;
	// Head removal races with concurrent lookup_add (both touch d->root) — needs CAS
	for (;;) {
		p = (entry_t *)d->root;
		if (p == NULL || p->id != id)
			break;
		if (InterlockedCompareExchangePointer((PVOID volatile *)&d->root, p->next, p) == p)
			return; // unlinked, memory intentionally not freed
	}
	// Interior removal never races with lookup_add, so a plain write is safe here
	for (last = (entry_t *)d->root; last != NULL; last = last->next) {
		if (last->next && last->next->id == id) {
			last->next = last->next->next;
			return;
		}
	}
}
