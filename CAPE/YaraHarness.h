#pragma once

#include <Windows.h>

#include "yara.h"

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