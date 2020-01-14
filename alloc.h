#ifndef __ALLOC_H
#define __ALLOC_H

#include <assert.h>

typedef NTSTATUS(WINAPI * _NtAllocateVirtualMemory)(
	_In_     HANDLE ProcessHandle,
	_Inout_  PVOID *BaseAddress,
	_In_     ULONG_PTR ZeroBits,
	_Inout_  PSIZE_T RegionSize,
	_In_     ULONG AllocationType,
	_In_     ULONG Protect);
typedef NTSTATUS(WINAPI * _NtProtectVirtualMemory)(
	_In_     HANDLE ProcessHandle,
	_Inout_  PVOID *BaseAddress,
	_Inout_  PSIZE_T NumberOfBytesToProtect,
	_In_     ULONG NewAccessProtection,
	_In_     PULONG OldAccessProtection);
typedef NTSTATUS(WINAPI * _NtFreeVirtualMemory)(
	_In_     HANDLE ProcessHandle,
	_Inout_  PVOID *BaseAddress,
	_Inout_  PSIZE_T RegionSize,
	_In_     ULONG FreeType);

extern _NtAllocateVirtualMemory pNtAllocateVirtualMemory;
extern _NtProtectVirtualMemory pNtProtectVirtualMemory;
extern _NtFreeVirtualMemory pNtFreeVirtualMemory;

#define USE_PRIVATE_HEAP

#ifdef USE_PRIVATE_HEAP
extern HANDLE g_heap;
#else
struct cm_alloc_header {
	DWORD Magic;
	SIZE_T Used;
	SIZE_T Max;
};

#define CM_ALLOC_METASIZE		(sizeof(struct cm_alloc_header))
#define GET_CM_ALLOC_HEADER(x)	(struct cm_alloc_header *)((PCHAR)(x) - CM_ALLOC_METASIZE)
#define CM_ALLOC_MAGIC			0xdeadc01d

#endif

extern void *cm_alloc(size_t size);
extern void *cm_realloc(void *ptr, size_t size);
extern void cm_free(void *ptr);
#ifdef USE_PRIVATE_HEAP
extern void *cm_calloc(size_t count, size_t size);
#else
static __inline void *cm_calloc(size_t count, size_t size)
{
	char *buf = cm_alloc(count * size);
	if (buf)
		memset(buf, 0, count * size);
	return buf;
}
#endif

static __inline char *cm_strdup(const char *ptr)
{
	char *buf = cm_alloc(strlen(ptr) + 1);
	if (buf)
		strncpy(buf, ptr, strlen(ptr) + 1);
	return buf;
}

#define calloc	cm_calloc
#define malloc	cm_alloc
#define free	cm_free
#define realloc	cm_realloc
#define strdup	cm_strdup

#endif