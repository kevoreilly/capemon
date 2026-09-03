#ifndef _TRAMPOLINE_64_H
#define _TRAMPOLINE_64_H

#include <windows.h>
#include <distorm.h>

#ifndef EXTERN_C
#ifdef __cplusplus
#define EXTERN_C extern "C"
#else
#define EXTERN_C extern
#endif
#endif

// We need addr_map_t which is in hooking.h but hooking.h includes a bunch of things
// We'll just define it here to decouple if it doesn't exist, else we include it.
// Actually hooking.h has addr_map_t.
#ifndef CAPEMONWOW64_EXPORTS
#include "hooking.h"
#else
typedef struct _addr_map_t {
	ULONG_PTR map[40][2];
} addr_map_t;
#endif

int lde(void *addr);
int hook_create_trampoline(unsigned char *addr, int len, unsigned char *tramp);

#endif
