#pragma once

#include <Windows.h>

#include "yara.h"

BOOL YaraInit();
void YaraScan(PVOID Address, SIZE_T Size);
void YaraShutdown();