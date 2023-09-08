#include <stdio.h>
#include "hooking.h"
#include "log.h"
#include "pipe.h"
#include "misc.h"
#include "CAPE\CAPE.h"
#include "CAPE\YaraHarness.h"

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);

PVOID ClrJIT;

HOOKDEF(int, WINAPI, compileMethod,
	PVOID			this,
	PVOID			compHnd,
	PVOID			methodInfo,
	unsigned int	flags,
	uint8_t**		entryAddress,
	uint32_t*		nativeSizeOfCode
)
{
    int ret;
	ret = Old_compileMethod(this, compHnd, methodInfo, flags, entryAddress, nativeSizeOfCode);
	if (!ClrJIT)
		ClrJIT = GetAllocationBase(*entryAddress);
	SilentYaraScan(*entryAddress, *nativeSizeOfCode);
	return ret;
}
