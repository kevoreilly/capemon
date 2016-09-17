#include <stdio.h>
#include <windows.h>
#include "hooking.h"
#include "ntapi.h"

#define HOOK(library, funcname) {L###library, #funcname, NULL, \
    &New_##funcname##0, (void **) &Old_##funcname##0}

HOOKDEF(BOOL, WINAPI, DeleteFileW0,
  __in  LPWSTR lpFileName
) {
    BOOL ret = Old_DeleteFileW0(lpFileName);

    printf("ret: %d, lasterr: %d, %d\n", ret, GetLastError(),
        hook_get_last_error());

    SetLastError(0x1337);

    printf("ret: %d, lasterr: %d, %d\n", ret, GetLastError(),
        hook_get_last_error());

    hook_set_last_error(0xb00b);

    printf("ret: %d, lasterr: %d, %d\n", ret, GetLastError(),
        hook_get_last_error());

    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenFile0,
  __out  PHANDLE FileHandle,
  __in   ACCESS_MASK DesiredAccess,
  __in   POBJECT_ATTRIBUTES ObjectAttributes,
  __out  PIO_STATUS_BLOCK IoStatusBlock,
  __in   ULONG ShareAccess,
  __in   ULONG OpenOptions
) {
    NTSTATUS ret = Old_NtOpenFile0(FileHandle, DesiredAccess, ObjectAttributes,
        IoStatusBlock, ShareAccess, OpenOptions);
    SetLastError(0x1338);
    printf("OMG!!! %d\n", GetLastError());
    return ret;
}

int main()
{
    static hook_t hook[] = {
        HOOK(kernel32, DeleteFileW),
        HOOK(ntdll, NtOpenFile),
    };

    DWORD old_protect;
    VirtualProtect(hook, sizeof(hook), PAGE_EXECUTE_READWRITE, &old_protect);

    hook_api(&hook[0], HOOK_JMP_DIRECT);
    hook_api(&hook[1], HOOK_JMP_DIRECT);

    DeleteFile("hoi");
    printf("lasterr: %d\n", GetLastError());
}
