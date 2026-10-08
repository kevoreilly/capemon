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
#include "misc.h"
#include "hook_sleep.h"
#include "config.h"
#include "CAPE\CAPE.h"
#include "CAPE\Debugger.h"
#include "CAPE\Unpacker.h"


HOOKDEF(NTSTATUS, WINAPI, NtCreateMutant,
	__out	   PHANDLE MutantHandle,
	__in		ACCESS_MASK DesiredAccess,
	__in_opt	POBJECT_ATTRIBUTES ObjectAttributes,
	__in		BOOLEAN InitialOwner
) {
	NTSTATUS ret = Old_NtCreateMutant(MutantHandle, DesiredAccess,
		ObjectAttributes, InitialOwner);
	LOQ_ntstatus("synchronization", "Poi", "Handle", MutantHandle,
		"MutexName", unistr_from_objattr(ObjectAttributes),
		"InitialOwner", InitialOwner);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenMutant,
	__out	   PHANDLE MutantHandle,
	__in		ACCESS_MASK DesiredAccess,
	__in		POBJECT_ATTRIBUTES ObjectAttributes
) {
	NTSTATUS ret = Old_NtOpenMutant(MutantHandle, DesiredAccess,
		ObjectAttributes);
	LOQ_ntstatus("synchronization", "Po", "Handle", MutantHandle,
		"MutexName", unistr_from_objattr(ObjectAttributes));
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtReleaseMutant,
	__in		HANDLE MutantHandle,
	__out_opt   PLONG PreviousCount
) {
	NTSTATUS ret = Old_NtReleaseMutant(MutantHandle, PreviousCount);
	LOQ_ntstatus("synchronization", "h", "Handle", MutantHandle);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateEvent,
	__out		PHANDLE EventHandle,
	__in		ACCESS_MASK DesiredAccess,
	__in_opt	POBJECT_ATTRIBUTES ObjectAttributes,
	__in		DWORD EventType,
	__in		BOOLEAN InitialState
) {
	NTSTATUS ret = Old_NtCreateEvent(EventHandle, DesiredAccess,
		ObjectAttributes, EventType, InitialState);
	UNICODE_STRING *eventname = unistr_from_objattr(ObjectAttributes);
	if (eventname && eventname->Length) {
		LOQ_ntstatus("synchronization", "Poii", "Handle", EventHandle,
			"EventName", eventname, "EventType", EventType, "InitialState", InitialState);
	}
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenEvent,
	__out		PHANDLE EventHandle,
	__in		ACCESS_MASK DesiredAccess,
	__in		POBJECT_ATTRIBUTES ObjectAttributes
) {
	NTSTATUS ret = Old_NtOpenEvent(EventHandle, DesiredAccess,
		ObjectAttributes);
	LOQ_ntstatus("synchronization", "Po", "Handle", EventHandle,
		"EventName", unistr_from_objattr(ObjectAttributes));
	return ret;

}

HOOKDEF(NTSTATUS, WINAPI, NtCreateNamedPipeFile,
	OUT		PHANDLE NamedPipeFileHandle,
	IN		ACCESS_MASK DesiredAccess,
	IN		POBJECT_ATTRIBUTES ObjectAttributes,
	OUT		PIO_STATUS_BLOCK IoStatusBlock,
	IN		ULONG ShareAccess,
	IN		ULONG CreateDisposition,
	IN		ULONG CreateOptions,
	IN		ULONG NamedPipeType,
	IN		ULONG ReadMode,
	IN		ULONG CompletionMode,
	IN		ULONG MaxInstances,
	IN		ULONG InBufferSize,
	IN		ULONG OutBufferSize,
	IN		PLARGE_INTEGER DefaultTimeOut
) {
	NTSTATUS ret = Old_NtCreateNamedPipeFile(NamedPipeFileHandle,
		DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess,
		CreateDisposition, CreateOptions, NamedPipeType, ReadMode,
		CompletionMode, MaxInstances, InBufferSize, OutBufferSize,
		DefaultTimeOut);
	LOQ_ntstatus("synchronization", "PhOi", "NamedPipeHandle", NamedPipeFileHandle,
		"DesiredAccess", DesiredAccess, "PipeName", ObjectAttributes,
		"ShareAccess", ShareAccess);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtAddAtom,
	IN	PWCHAR AtomName,
	IN	ULONG	AtomNameLength,
	OUT PRTL_ATOM Atom
) {
	NTSTATUS ret = Old_NtAddAtom(AtomName, AtomNameLength, Atom);
	LOQ_ntstatus("synchronization", "uh", "AtomName", AtomName, "Atom", *Atom);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtDeleteAtom,
	IN RTL_ATOM Atom
) {
	NTSTATUS ret = Old_NtDeleteAtom(Atom);
	LOQ_ntstatus("synchronization", "h", "Atom", Atom);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtFindAtom,
	IN	PWCHAR AtomName,
	IN	ULONG AtomNameLength,
	OUT PRTL_ATOM Atom OPTIONAL
) {
	ENSURE_RTL_ATOM(Atom);
	NTSTATUS ret = Old_NtFindAtom(AtomName, AtomNameLength, Atom);
	LOQ_ntstatus("synchronization", "uh", "AtomName", AtomName, "Atom", *Atom);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtAddAtomEx,
	IN	PWCHAR AtomName,
	IN	ULONG	AtomNameLength,
	OUT PRTL_ATOM Atom,
	IN	PVOID	Unknown
) {
	NTSTATUS ret = Old_NtAddAtomEx(AtomName, AtomNameLength, Atom, Unknown);
	LOQ_ntstatus("synchronization", "uh", "AtomName", AtomName, "Atom", *Atom);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryInformationAtom,
	IN	RTL_ATOM Atom,
	IN	ATOM_INFORMATION_CLASS AtomInformationClass,
	OUT PVOID AtomInformation,
	IN  ULONG AtomInformationLength,
	OUT PULONG ReturnLength OPTIONAL
) {
	WCHAR* AtomName;
	ULONG AtomNameLength;
	
	NTSTATUS ret = Old_NtQueryInformationAtom(Atom, AtomInformationClass, AtomInformation, AtomInformationLength, ReturnLength);
	
	if (NT_SUCCESS(ret) && AtomInformationClass == AtomBasicInformation)
	{
		AtomNameLength = (ULONG)((PATOM_BASIC_INFORMATION)AtomInformation)->NameLength;
		AtomName = ((PATOM_BASIC_INFORMATION)AtomInformation)->Name;
		LOQ_ntstatus("synchronization", "bih", "AtomName", AtomNameLength, AtomName, "Size", AtomNameLength, "Atom", Atom);
	}
	else
		LOQ_ntstatus("synchronization", "h", "Atom", Atom);
	
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtSetIoCompletion,
	__in		HANDLE IoCompletionHandle,
	__in_opt	PVOID KeyContext,
	__in_opt	PVOID ApcContext,
	__in		NTSTATUS IoStatus,
	__in		ULONG_PTR IoStatusInformation
) {
	NTSTATUS ret = Old_NtSetIoCompletion(IoCompletionHandle, KeyContext,
		ApcContext, IoStatus, IoStatusInformation);

	LOQ_ntstatus("synchronization", "ppphl",
		"IoCompletionHandle", IoCompletionHandle,
		"KeyContext", KeyContext,
		"ApcContext", ApcContext,
		"IoStatus", IoStatus,
		"IoStatusInformation", IoStatusInformation);

	if (NT_SUCCESS(ret)) {
		if (g_config.unpacker) {
			if (KeyContext)
				NewThreadHandler(KeyContext);
			if (ApcContext)
				NewThreadHandler(ApcContext);
		}
		disable_sleep_skip();
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtSetIoCompletionEx,
	__in		HANDLE IoCompletionHandle,
	__in_opt	HANDLE IoCompletionPacketHandle,
	__in_opt	PVOID KeyContext,
	__in_opt	PVOID ApcContext,
	__in		NTSTATUS IoStatus,
	__in		ULONG_PTR IoStatusInformation
) {
	NTSTATUS ret = Old_NtSetIoCompletionEx(IoCompletionHandle, IoCompletionPacketHandle,
		KeyContext, ApcContext, IoStatus, IoStatusInformation);

	LOQ_ntstatus("synchronization", "pppphl",
		"IoCompletionHandle", IoCompletionHandle,
		"IoCompletionPacketHandle", IoCompletionPacketHandle,
		"KeyContext", KeyContext,
		"ApcContext", ApcContext,
		"IoStatus", IoStatus,
		"IoStatusInformation", IoStatusInformation);

	if (NT_SUCCESS(ret)) {
		if (g_config.unpacker) {
			if (KeyContext)
				NewThreadHandler(KeyContext);
			if (ApcContext)
				NewThreadHandler(ApcContext);
		}
		disable_sleep_skip();
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtAssociateWaitCompletionPacket,
	__in		HANDLE WaitCompletionPacketHandle,
	__in		HANDLE IoCompletionHandle,
	__in		HANDLE TargetObjectHandle,
	__in_opt	PVOID KeyContext,
	__in_opt	PVOID ApcContext,
	__in		NTSTATUS IoStatus,
	__in		ULONG_PTR IoStatusInformation,
	__out_opt	PBOOLEAN AlreadySignaled
) {
	BOOLEAN already_signaled = FALSE;
	NTSTATUS ret = Old_NtAssociateWaitCompletionPacket(
		WaitCompletionPacketHandle, IoCompletionHandle, TargetObjectHandle,
		KeyContext, ApcContext, IoStatus, IoStatusInformation, AlreadySignaled);

	if (NT_SUCCESS(ret) && AlreadySignaled && is_valid_address_range((ULONG_PTR)AlreadySignaled, sizeof(BOOLEAN)))
		already_signaled = *AlreadySignaled;

	LOQ_ntstatus("synchronization", "ppppphli",
		"WaitCompletionPacketHandle", WaitCompletionPacketHandle,
		"IoCompletionHandle", IoCompletionHandle,
		"TargetObjectHandle", TargetObjectHandle,
		"KeyContext", KeyContext,
		"ApcContext", ApcContext,
		"IoStatus", IoStatus,
		"IoStatusInformation", IoStatusInformation,
		"AlreadySignaled", already_signaled);

	if (NT_SUCCESS(ret)) {
		if (g_config.unpacker) {
			if (KeyContext)
				NewThreadHandler(KeyContext);
			if (ApcContext)
				NewThreadHandler(ApcContext);
		}
		disable_sleep_skip();
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, TpAllocWait,
	__out		PVOID *WaitReturn,
	__in		PVOID Callback,
	__inout_opt	PVOID Context,
	__in_opt	PVOID CallbackEnviron
) {
	unsigned int offset = 0;
	char *module_name = NULL, *function_name = NULL;
	NTSTATUS ret = Old_TpAllocWait(WaitReturn, Callback, Context, CallbackEnviron);

	module_name = convert_address_to_dll_name_and_offset((ULONG_PTR)Callback, &offset);
	function_name = GetExportNameByAddress(Callback);

	LOQ_ntstatus("synchronization", "Ppppss",
		"Wait", WaitReturn,
		"Callback", Callback,
		"Context", Context,
		"CallbackEnviron", CallbackEnviron,
		"Module", module_name,
		"Name", function_name);

	if (module_name)
		free(module_name);

	if (NT_SUCCESS(ret)) {
		if (g_config.unpacker && Callback)
			NewThreadHandler(Callback);
		disable_sleep_skip();
	}

	return ret;
}

HOOKDEF(VOID, WINAPI, TpSetWait,
	__inout		PVOID Wait,
	__in_opt	HANDLE Handle,
	__in_opt	PLARGE_INTEGER Timeout
) {
	int ret = 0;
	Old_TpSetWait(Wait, Handle, Timeout);

	LOQ_void("synchronization", "ppX",
		"Wait", Wait,
		"Handle", Handle,
		"Timeout", Timeout);

	if (Handle)
		disable_sleep_skip();
}

HOOKDEF(NTSTATUS, WINAPI, TpSetWaitEx,
	__inout		PVOID Wait,
	__in_opt	HANDLE Handle,
	__in_opt	PLARGE_INTEGER Timeout,
	__in_opt	PVOID Reserved
) {
	NTSTATUS ret = Old_TpSetWaitEx(Wait, Handle, Timeout, Reserved);

	LOQ_ntstatus("synchronization", "ppXp",
		"Wait", Wait,
		"Handle", Handle,
		"Timeout", Timeout,
		"Reserved", Reserved);

	if (Handle)
		disable_sleep_skip();

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, TpAllocWork,
	__out		PVOID *WorkReturn,
	__in		PVOID Callback,
	__inout_opt	PVOID Context,
	__in_opt	PVOID CallbackEnviron
) {
	unsigned int offset = 0;
	char *module_name = NULL, *function_name = NULL;
	NTSTATUS ret = Old_TpAllocWork(WorkReturn, Callback, Context, CallbackEnviron);

	module_name = convert_address_to_dll_name_and_offset((ULONG_PTR)Callback, &offset);
	function_name = GetExportNameByAddress(Callback);

	LOQ_ntstatus("synchronization", "Ppppss",
		"Work", WorkReturn,
		"Callback", Callback,
		"Context", Context,
		"CallbackEnviron", CallbackEnviron,
		"Module", module_name,
		"Name", function_name);

	if (module_name)
		free(module_name);

	if (NT_SUCCESS(ret)) {
		if (g_config.unpacker && Callback)
			NewThreadHandler(Callback);
		disable_sleep_skip();
	}

	return ret;
}

HOOKDEF(VOID, WINAPI, TpPostWork,
	__inout		PVOID Work
) {
	int ret = 0;
	Old_TpPostWork(Work);

	LOQ_void("synchronization", "p", "Work", Work);

	disable_sleep_skip();
}

HOOKDEF(NTSTATUS, WINAPI, TpSimpleTryPost,
	__in		PVOID Callback,
	__inout_opt	PVOID Context,
	__in_opt	PVOID CallbackEnviron
) {
	unsigned int offset = 0;
	char *module_name = NULL, *function_name = NULL;
	NTSTATUS ret = Old_TpSimpleTryPost(Callback, Context, CallbackEnviron);

	module_name = convert_address_to_dll_name_and_offset((ULONG_PTR)Callback, &offset);
	function_name = GetExportNameByAddress(Callback);

	LOQ_ntstatus("synchronization", "pppss",
		"Callback", Callback,
		"Context", Context,
		"CallbackEnviron", CallbackEnviron,
		"Module", module_name,
		"Name", function_name);

	if (module_name)
		free(module_name);

	if (NT_SUCCESS(ret)) {
		if (g_config.unpacker && Callback)
			NewThreadHandler(Callback);
		disable_sleep_skip();
	}

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, TpAllocTimer,
	__out		PVOID *Timer,
	__in		PVOID Callback,
	__inout_opt	PVOID Context,
	__in_opt	PVOID CallbackEnviron
) {
	unsigned int offset = 0;
	char *module_name = NULL, *function_name = NULL;
	NTSTATUS ret = Old_TpAllocTimer(Timer, Callback, Context, CallbackEnviron);

	module_name = convert_address_to_dll_name_and_offset((ULONG_PTR)Callback, &offset);
	function_name = GetExportNameByAddress(Callback);

	LOQ_ntstatus("synchronization", "Ppppss",
		"Timer", Timer,
		"Callback", Callback,
		"Context", Context,
		"CallbackEnviron", CallbackEnviron,
		"Module", module_name,
		"Name", function_name);

	if (module_name)
		free(module_name);

	if (NT_SUCCESS(ret)) {
		if (g_config.unpacker && Callback)
			NewThreadHandler(Callback);
		disable_sleep_skip();
	}

	return ret;
}

HOOKDEF(VOID, WINAPI, TpSetTimer,
	__inout		PVOID Timer,
	__in_opt	PLARGE_INTEGER DueTime,
	__in		ULONG Period,
	__in_opt	ULONG WindowLength
) {
	int ret = 0;
	Old_TpSetTimer(Timer, DueTime, Period, WindowLength);

	LOQ_void("synchronization", "pXii",
		"Timer", Timer,
		"DueTime", DueTime,
		"Period", Period,
		"WindowLength", WindowLength);

	if (DueTime)
		disable_sleep_skip();
}

HOOKDEF(NTSTATUS, WINAPI, TpSetTimerEx,
	__inout		PVOID Timer,
	__in_opt	PLARGE_INTEGER DueTime,
	__in		ULONG Period,
	__in_opt	PVOID Parameters
) {
	NTSTATUS ret = Old_TpSetTimerEx(Timer, DueTime, Period, Parameters);

	LOQ_ntstatus("synchronization", "pXip",
		"Timer", Timer,
		"DueTime", DueTime,
		"Period", Period,
		"Parameters", Parameters);

	if (DueTime)
		disable_sleep_skip();

	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, TpAllocIoCompletion,
	__out		PVOID *IoReturn,
	__in		HANDLE File,
	__in		PVOID Callback,
	__inout_opt	PVOID Context,
	__in_opt	PVOID CallbackEnviron
) {
	unsigned int offset = 0;
	char *module_name = NULL, *function_name = NULL;
	NTSTATUS ret = Old_TpAllocIoCompletion(IoReturn, File, Callback, Context, CallbackEnviron);

	module_name = convert_address_to_dll_name_and_offset((ULONG_PTR)Callback, &offset);
	function_name = GetExportNameByAddress(Callback);

	LOQ_ntstatus("synchronization", "Pppppss",
		"IoCompletion", IoReturn,
		"FileHandle", File,
		"Callback", Callback,
		"Context", Context,
		"CallbackEnviron", CallbackEnviron,
		"Module", module_name,
		"Name", function_name);

	if (module_name)
		free(module_name);

	if (NT_SUCCESS(ret)) {
		if (g_config.unpacker && Callback)
			NewThreadHandler(Callback);
		disable_sleep_skip();
	}

	return ret;
}
