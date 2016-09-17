/*
Copyright(C) 2014,2015 Optiv, Inc. (brad.spengler@optiv.com)

This program is free software : you can redistribute it and / or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.If not, see <http://www.gnu.org/licenses/>.
*/

#include "hooking.h"
#include "alloc.h"
#include <Windows.h>

#ifdef USE_PRIVATE_HEAP
void *cm_alloc(size_t size)
{
	void *ret;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);
	ret = HeapAlloc(g_heap, 0, size);
	set_lasterrors(&lasterror);
	return ret;
}

void *cm_calloc(size_t count, size_t size)
{
	void *ret;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);
	ret = HeapAlloc(g_heap, HEAP_ZERO_MEMORY, count * size);
	set_lasterrors(&lasterror);
	return ret;
}

void *cm_realloc(void *ptr, size_t size)
{
	void *ret;
	lasterror_t lasterror;
	get_lasterrors(&lasterror);
	ret = HeapReAlloc(g_heap, 0, ptr, size);
	set_lasterrors(&lasterror);
	return ret;
}

void cm_free(void *ptr)
{
	lasterror_t lasterror;
	get_lasterrors(&lasterror);
	HeapFree(g_heap, 0, ptr);
	set_lasterrors(&lasterror);
}
#else
void *cm_alloc(size_t size)
{
	PVOID BaseAddress = NULL;
	SIZE_T RegionSize = size + CM_ALLOC_METASIZE + 0x1000;
	struct cm_alloc_header *hdr;
	DWORD oldprot;
	LONG status;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);
	status = pNtAllocateVirtualMemory(GetCurrentProcess(), &BaseAddress, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (status < 0) {
		set_lasterrors(&lasterror);
		return NULL;
	}
	hdr = (struct cm_alloc_header *)BaseAddress;
	hdr->Magic = CM_ALLOC_MAGIC;
	hdr->Used = size + CM_ALLOC_METASIZE;
	hdr->Max = RegionSize - 0x1000;

	// add a guard page to the end of every allocation
	assert(VirtualProtect((PCHAR)BaseAddress + RegionSize - 0x1000, 0x1000, PAGE_NOACCESS, &oldprot));
	set_lasterrors(&lasterror);
	return (PCHAR)BaseAddress + CM_ALLOC_METASIZE;
}

void cm_free(void *ptr)
{
	PVOID BaseAddress;
	SIZE_T RegionSize;
	LONG status;
	struct cm_alloc_header *hdr;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);
	hdr = GET_CM_ALLOC_HEADER(ptr);

	assert(hdr->Magic == CM_ALLOC_MAGIC);
	BaseAddress = (PVOID)hdr;
	RegionSize = 0;
	status = pNtFreeVirtualMemory(GetCurrentProcess(), &BaseAddress, &RegionSize, MEM_RELEASE);
	assert(status >= 0);
	set_lasterrors(&lasterror);
}

void *cm_realloc(void *ptr, size_t size)
{
	struct cm_alloc_header *hdr;
	char *buf;

	hdr = GET_CM_ALLOC_HEADER(ptr);

	assert(hdr->Magic == CM_ALLOC_MAGIC);

	if (hdr->Max >= (size + CM_ALLOC_METASIZE)) {
		hdr->Used = size + CM_ALLOC_METASIZE;
		return ptr;
	}
	buf = cm_alloc(size);
	if (buf == NULL)
		return buf;
	memcpy(buf, ptr, hdr->Used - CM_ALLOC_METASIZE);
	cm_free(ptr);
	return buf;
}

#endif