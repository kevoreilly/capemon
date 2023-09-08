#pragma once

#include <Windows.h>

#include "yara.h"

BOOL YaraInit();
BOOL ScanForRulesCanary(PVOID Address, SIZE_T Size);
void YaraScan(PVOID Address, SIZE_T Size);
void SilentYaraScan(PVOID Address, SIZE_T Size);
void YaraShutdown();