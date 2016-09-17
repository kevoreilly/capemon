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

#define _WIN32_WINNT 0x0500
#include <stdio.h>
#include <stdint.h>
#include <windows.h>

int main()
{
    LoadLibrary("../cuckoomon.dll");

    FARPROC sleep = GetProcAddress(GetModuleHandle("kernel32"), "Sleep");

    for (uint32_t tid = 2000; ; tid += 4) {
        HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
        if(thread_handle != NULL) {
            printf("tid %d .. :)\n", tid);
            QueueUserAPC((PAPCFUNC) sleep, thread_handle, 1337);
            CloseHandle(thread_handle);
            break;
        }
    }
}
