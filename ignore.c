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
#include "ntapi.h"
#include "ignore.h"
#include "misc.h"
#include "pipe.h"

//
// Protected Processes
//

static DWORD g_pids[MAX_PROTECTED_PIDS];
static DWORD g_pid_count;

void add_protected_pid(DWORD pid)
{
    g_pids[g_pid_count++] = pid;
}

int is_protected_pid(DWORD pid)
{
	DWORD i;

    for (i = 0; i < g_pid_count; i++) {
        if(pid == g_pids[i]) {
            return 1;
        }
    }
    return 0;
}

//
// Blacklist for Dumping Files
//

#define S(s, f) {L##s, sizeof(s)-1, f}

#define FLAG_NONE           0
#define FLAG_BEGINS_WITH    1

static struct _ignored_file_t {
    const wchar_t   *unicode;
    unsigned int    length;
    unsigned int    flags;
} g_ignored_files[] = {
    S("\\??\\PIPE\\lsarpc", FLAG_NONE),
    S("\\??\\IDE#", FLAG_BEGINS_WITH),
    S("\\??\\STORAGE#", FLAG_BEGINS_WITH),
    S("\\??\\MountPointManager", FLAG_NONE),
    S("\\??\\root#", FLAG_BEGINS_WITH),
    S("\\Device\\", FLAG_BEGINS_WITH),
};

int is_ignored_file_unicode(const wchar_t *fname, unsigned int length)
{
    struct _ignored_file_t *f = g_ignored_files;
	unsigned int i;
    for (i = 0; i < ARRAYSIZE(g_ignored_files); i++, f++) {
        if(f->flags == FLAG_NONE && length == f->length &&
                !wcsnicmp(fname, f->unicode, length)) {
            return 1;
        }
        else if(f->flags == FLAG_BEGINS_WITH && length >= f->length &&
                !wcsnicmp(fname, f->unicode, f->length)) {
            return 1;
        }
    }
    return 0;
}

int is_ignored_file_objattr(const OBJECT_ATTRIBUTES *obj)
{
    return is_ignored_file_unicode(obj->ObjectName->Buffer,
        obj->ObjectName->Length / sizeof(wchar_t));
}
