/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2015 Cuckoo Sandbox Developers, Optiv, Inc. (brad.spengler@optiv.com)

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
#include "hooking.h"
#include "log.h"
#include "pipe.h"
#include "misc.h"
#include "config.h"

HOOKDEF(NTSTATUS, WINAPI, NtCreateKey,
    __out       PHANDLE KeyHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in        POBJECT_ATTRIBUTES ObjectAttributes,
    __reserved  ULONG TitleIndex,
    __in_opt    PUNICODE_STRING Class,
    __in        ULONG CreateOptions,
    __out_opt   PULONG Disposition
) {
	NTSTATUS ret;
	ENSURE_ULONG(Disposition);
	ret = Old_NtCreateKey(KeyHandle, DesiredAccess, ObjectAttributes,
        TitleIndex, Class, CreateOptions, Disposition);
    LOQ_ntstatus("registry", "PhpoKoI", "KeyHandle", KeyHandle, "DesiredAccess", DesiredAccess,
		"ObjectAttributesHandle", handle_from_objattr(ObjectAttributes),
		"ObjectAttributesName", unistr_from_objattr(ObjectAttributes),
		"ObjectAttributes", ObjectAttributes, "Class", Class,
		"Disposition", Disposition);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenKey,
    __out  PHANDLE KeyHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes
) {
	NTSTATUS ret = Old_NtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);
    LOQ_ntstatus("registry", "PhpoK", "KeyHandle", KeyHandle, "DesiredAccess", DesiredAccess,
		"ObjectAttributesHandle", handle_from_objattr(ObjectAttributes),
		"ObjectAttributesName", unistr_from_objattr(ObjectAttributes),
		"ObjectAttributes", ObjectAttributes);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenKeyEx,
    __out  PHANDLE KeyHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes,
    __in   ULONG OpenOptions
) {
	NTSTATUS ret = Old_NtOpenKeyEx(KeyHandle, DesiredAccess, ObjectAttributes,
        OpenOptions);
    LOQ_ntstatus("registry", "PhpoK", "KeyHandle", KeyHandle, "DesiredAccess", DesiredAccess,
		"ObjectAttributesHandle", handle_from_objattr(ObjectAttributes),
		"ObjectAttributesName", unistr_from_objattr(ObjectAttributes),
		"ObjectAttributes", ObjectAttributes);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtRenameKey,
    __in  HANDLE KeyHandle,
    __in  PUNICODE_STRING NewName
) {
    NTSTATUS ret = Old_NtRenameKey(KeyHandle, NewName);
    LOQ_ntstatus("registry", "po", "KeyHandle", KeyHandle, "NewName", NewName);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtReplaceKey,
    __in  POBJECT_ATTRIBUTES NewHiveFileName,
    __in  HANDLE KeyHandle,
    __in  POBJECT_ATTRIBUTES BackupHiveFileName
) {
    NTSTATUS ret = Old_NtReplaceKey(NewHiveFileName, KeyHandle,
        BackupHiveFileName);
    LOQ_ntstatus("registry", "pOO", "KeyHandle", KeyHandle,
        "NewHiveFileName", NewHiveFileName,
        "BackupHiveFileName", BackupHiveFileName);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtEnumerateKey,
    __in       HANDLE KeyHandle,
    __in       ULONG Index,
    __in       KEY_INFORMATION_CLASS KeyInformationClass,
    __out_opt  PVOID KeyInformation,
    __in       ULONG Length,
    __out      PULONG ResultLength
) {
    NTSTATUS ret = Old_NtEnumerateKey(KeyHandle, Index, KeyInformationClass,
        KeyInformation, Length, ResultLength);
    LOQ_ntstatus("registry", "pi", "KeyHandle", KeyHandle, "Index", Index);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtEnumerateValueKey,
    __in       HANDLE KeyHandle,
    __in       ULONG Index,
    __in       KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    __out_opt  PVOID KeyValueInformation,
    __in       ULONG Length,
    __out      PULONG ResultLength
) {
    NTSTATUS ret = Old_NtEnumerateValueKey(KeyHandle, Index,
        KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
    LOQ_ntstatus("registry", "pii", "KeyHandle", KeyHandle, "Index", Index,
        "KeyValueInformationClass", KeyValueInformationClass);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtSetValueKey,
    __in      HANDLE KeyHandle,
    __in      PUNICODE_STRING ValueName,
    __in_opt  ULONG TitleIndex,
    __in      ULONG Type,
    __in_opt  PVOID Data,
    __in      ULONG DataSize
) {
    NTSTATUS ret = Old_NtSetValueKey(KeyHandle, ValueName, TitleIndex,
        Type, Data, DataSize);
    if(NT_SUCCESS(ret)) {
        LOQ_ntstatus("registry", "poiRik", "KeyHandle", KeyHandle, "ValueName", ValueName,
			"Type", Type, "Buffer", Type, DataSize, Data, "BufferLength", DataSize,
			"FullName", KeyHandle, ValueName);
    }
    else {
        LOQ_ntstatus("registry", "poik", "KeyHandle", KeyHandle, "ValueName", ValueName,
            "Type", Type, "FullName", KeyHandle, ValueName);
    }
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryValueKey,
    __in       HANDLE KeyHandle,
    __in       PUNICODE_STRING ValueName,
    __in       KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    __out_opt  PVOID KeyValueInformation,
    __in       ULONG Length,
    __out      PULONG ResultLength
) {
	NTSTATUS ret;
    ENSURE_ULONG_ZERO(ResultLength);

    ret = Old_NtQueryValueKey(KeyHandle, ValueName,
        KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
    if(NT_SUCCESS(ret) && KeyValueInformation && 
            *ResultLength >= sizeof(ULONG) * 3) {
		unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
		PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
		wchar_t *keypath = get_full_keyvalue_pathUS(KeyHandle, ValueName, keybuf, allocsize);
		ULONG Type, DataLength = 0; UCHAR *Data = NULL;

        // someday add support for Name and NameLength, if there's use for it

        Type = ((KEY_VALUE_PARTIAL_INFORMATION *) KeyValueInformation)->Type;
        if(KeyValueInformationClass == KeyValueFullInformation) {
            KEY_VALUE_FULL_INFORMATION *p =
                (KEY_VALUE_FULL_INFORMATION *) KeyValueInformation;
            DataLength = p->DataLength;
            Data = (UCHAR *) KeyValueInformation + p->DataOffset;
        }
        else if(KeyValueInformationClass == KeyValuePartialInformation) {
            KEY_VALUE_PARTIAL_INFORMATION *p =
                (KEY_VALUE_PARTIAL_INFORMATION *) KeyValueInformation;
            DataLength = p->DataLength;
            Data = p->Data;
        }

        LOQ_ntstatus("registry", "poiRu", "KeyHandle", KeyHandle, "ValueName", ValueName,
            "Type", Type, "Information", Type, DataLength, Data,
			"FullName", keypath);

		if (!g_config.no_stealth)
			perform_unicode_registry_fakery(keypath, Data, DataLength);

		free(keybuf);
	}
    else {
        LOQ_ntstatus("registry", "pok", "KeyHandle", KeyHandle, "ValueName", ValueName,
			"FullName", KeyHandle, ValueName);
    }

    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryMultipleValueKey,
    __in       HANDLE KeyHandle,
    __inout    PKEY_VALUE_ENTRY ValueEntries,
    __in       ULONG EntryCount,
    __out      PVOID ValueBuffer,
    __inout    PULONG BufferLength,
    __out_opt  PULONG RequiredBufferLength
) {
    NTSTATUS ret = Old_NtQueryMultipleValueKey(KeyHandle, ValueEntries,
        EntryCount, ValueBuffer, BufferLength, RequiredBufferLength);
	ULONG i;
	for (i = 0; i < EntryCount; i++) {
		PKEY_VALUE_ENTRY tmp = &ValueEntries[i];
		if (NT_SUCCESS(ret))
			LOQ_ntstatus("registry", "poRk", "KeyHandle", KeyHandle, "ValueName", tmp->ValueName,
			"ValueBuffer", tmp->Type, tmp->DataLength, (PCHAR)ValueBuffer + tmp->DataOffset, "FullName", KeyHandle, tmp->ValueName);
		else
			LOQ_ntstatus("registry", "pok", "KeyHandle", KeyHandle, "ValueName", tmp->ValueName, "FullName", KeyHandle, tmp->ValueName);
	}
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtDeleteKey,
    __in  HANDLE KeyHandle
) {
    NTSTATUS ret = Old_NtDeleteKey(KeyHandle);
    LOQ_ntstatus("registry", "p", "KeyHandle", KeyHandle);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtDeleteValueKey,
    __in  HANDLE KeyHandle,
    __in  PUNICODE_STRING ValueName
) {
    NTSTATUS ret = Old_NtDeleteValueKey(KeyHandle, ValueName);
    LOQ_ntstatus("registry", "pok", "KeyHandle", KeyHandle, "ValueName", ValueName,
		"FullName", KeyHandle, ValueName);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtLoadKey,
    __in  POBJECT_ATTRIBUTES TargetKey,
    __in  POBJECT_ATTRIBUTES SourceFile
) {
	unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
	PKEY_NAME_INFORMATION keybuf = calloc(1, allocsize);
	NTSTATUS ret = Old_NtLoadKey(TargetKey, SourceFile);
    LOQ_ntstatus("registry", "pouO","TargetKeyHandle", handle_from_objattr(TargetKey),
		"TargetKeyName", unistr_from_objattr(TargetKey),
		"TargetKey", get_key_path(TargetKey, keybuf, allocsize),
		"SourceFile", SourceFile);
	free(keybuf);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtLoadKey2,
    __in  POBJECT_ATTRIBUTES TargetKey,
    __in  POBJECT_ATTRIBUTES SourceFile,
    __in  ULONG Flags
) {
	NTSTATUS ret = Old_NtLoadKey2(TargetKey, SourceFile, Flags);
    LOQ_ntstatus("registry", "poKOi", "TargetKeyHandle", handle_from_objattr(TargetKey),
		"TargetKeyName", unistr_from_objattr(TargetKey),
		"TargetKey", TargetKey, "SourceFile", SourceFile, "Flags", Flags);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtLoadKeyEx,
    __in      POBJECT_ATTRIBUTES TargetKey,
    __in      POBJECT_ATTRIBUTES SourceFile,
    __in      ULONG Flags,
    __in_opt  HANDLE TrustClassKey
) {
	NTSTATUS ret = Old_NtLoadKeyEx(TargetKey, SourceFile, Flags,
        TrustClassKey);
    LOQ_ntstatus("registry", "ppoKOh", "TrustClassKey", TrustClassKey,
        "TargetKeyHandle", handle_from_objattr(TargetKey),
		"TargetKeyName", unistr_from_objattr(TargetKey),
		"TargetKey", TargetKey, "SourceFile", SourceFile, "Flags", Flags);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryKey,
    __in       HANDLE KeyHandle,
    __in       KEY_INFORMATION_CLASS KeyInformationClass,
    __out_opt  PVOID KeyInformation,
    __in       ULONG Length,
    __out      PULONG ResultLength
) {
    NTSTATUS ret = Old_NtQueryKey(KeyHandle, KeyInformationClass,
        KeyInformation, Length, ResultLength);
	if (KeyInformationClass == KeyNameInformation && KeyInformation) {
		PKEY_NAME_INFORMATION info = (PKEY_NAME_INFORMATION)KeyInformation;
		LOQ_ntstatus("registry", "pUl", "KeyHandle", KeyHandle,
			"KeyInformation", info->KeyNameLength/sizeof(WCHAR), info->KeyName,
			"KeyInformationClass", KeyInformationClass);
	} else {
		LOQ_ntstatus("registry", "pSl", "KeyHandle", KeyHandle,
			"KeyInformation", Length, KeyInformation,
			"KeyInformationClass", KeyInformationClass);
	}
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtSaveKey,
    __in  HANDLE KeyHandle,
    __in  HANDLE FileHandle
) {
    NTSTATUS ret = Old_NtSaveKey(KeyHandle, FileHandle);
    LOQ_ntstatus("registry", "pp", "KeyHandle", KeyHandle, "FileHandle", FileHandle);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtSaveKeyEx,
    __in  HANDLE KeyHandle,
    __in  HANDLE FileHandle,
    __in  ULONG Format
) {
    NTSTATUS ret = Old_NtSaveKeyEx(KeyHandle, FileHandle, Format);
    LOQ_ntstatus("registry", "ppi", "KeyHandle", KeyHandle, "FileHandle", FileHandle,
        "Format", Format);
    return ret;
}