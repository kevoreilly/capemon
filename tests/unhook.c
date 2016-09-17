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

#include <stdio.h>
#include <windows.h>

int main(int argc, char *argv[])
{
    FARPROC fp = GetProcAddress(
        GetModuleHandle("kernel32"), "IsDebuggerPresent");

    unsigned long old_protect;
    VirtualProtect(fp, 0x1000, PAGE_EXECUTE_READWRITE, &old_protect);

    // Corrupt the hook.
    memset(fp, 0xcc, 32);

    fp = GetProcAddress(GetModuleHandle("kernel32"), "CopyFileA");

    VirtualProtect(fp, 0x1000, PAGE_EXECUTE_READWRITE, &old_protect);

    // Restore the hook.
    memcpy(fp, "\x8b\xff\x55\x8b\xec", 5);

    Sleep(10000);
}
