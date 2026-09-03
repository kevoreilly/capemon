#pragma once
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

#include <windows.h>

#define LOOKUP_SHARED(table, type) ((type *)lookup_get_or_create((table), 1, sizeof(type)))	// Idiom 1: shared singleton state, replaces a critical-section-guarded global
#define LOOKUP_THREAD(table, type) ((type *)lookup_get_or_create((table), (ULONG_PTR)GetCurrentThreadId(), sizeof(type)))	// Idiom 2: per-thread state, replaces TlsAlloc/TlsGetValue/TlsSetValue
#define LOOKUP_MARK_SEEN(table, id) do { if (!lookup_get((table), (ULONG_PTR)(id), NULL)) lookup_add((table), (ULONG_PTR)(id), 0); } while (0)	// Idiom 3: mark seen / dedup by arbitrary key, no payload

typedef struct _lookup_internal_t {
	void *root;
} lookup_t;

typedef struct _entry_t {
	struct _entry_t *next;
	ULONG_PTR id;
	unsigned int size;
	unsigned char data[0];
} entry_t;

void *lookup_add(lookup_t *d, ULONG_PTR id, unsigned int size);
void *lookup_get(lookup_t *d, ULONG_PTR id, unsigned int *size);
void *lookup_get_or_create(lookup_t *d, ULONG_PTR id, unsigned int size);
void lookup_del(lookup_t *d, ULONG_PTR id);
