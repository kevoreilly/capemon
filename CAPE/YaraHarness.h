#pragma once

#include <Windows.h>

// The libyara backend (YaraHarness.c) needs libyara's header; the YARA-X
// backend (YaraHarnessX.c, built when CAPE_USE_YARA_X is defined) does not,
// and nothing in this header depends on a YR_* type.
#ifndef CAPE_USE_YARA_X
#include "yara.h"
#endif

typedef struct
{
	PCHAR FunctionName;
	PVOID Address;
} NameByAddress;

BOOL YaraInit();
BOOL ScanForRulesCanary(PVOID Address, SIZE_T Size);
void YaraScan(PVOID Address, SIZE_T Size);
void SilentYaraScan(PVOID Address, SIZE_T Size);
PVOID GetAddressByYara(HMODULE ModuleBase, PCHAR FunctionName);
NameByAddress* GetAddressesByYara(HMODULE ModuleBase, PCHAR FunctionNames[], SIZE_T FunctionCount, SIZE_T* OutFoundCount);
void YaraShutdown();