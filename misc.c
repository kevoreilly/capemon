/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2016 Cuckoo Sandbox Developers, Optiv, Inc. (brad.spengler@optiv.com), Brad Spengler

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
#include <ctype.h>
#include "ntapi.h"
#include <Psapi.h>
#include <shlwapi.h>
#include <sddl.h>
#include "misc.h"
#include "hooking.h"
#include "log.h"
#include "pipe.h"
#include "config.h"

extern char *our_process_name;
extern int path_is_system(const wchar_t *path_w);
extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);

static _NtQueryInformationProcess pNtQueryInformationProcess;
static _NtQueryInformationThread pNtQueryInformationThread;
static _RtlGenRandom pRtlGenRandom;
static _NtQueryAttributesFile pNtQueryAttributesFile;
static _NtQueryObject pNtQueryObject;
static _NtQueryKey pNtQueryKey;
static _NtDelayExecution pNtDelayExecution;
static _NtQuerySystemInformation pNtQuerySystemInformation;
static _RtlEqualUnicodeString pRtlEqualUnicodeString;
_NtMapViewOfSection pNtMapViewOfSection;
_NtUnmapViewOfSection pNtUnmapViewOfSection;
_NtAllocateVirtualMemory pNtAllocateVirtualMemory;
_NtProtectVirtualMemory pNtProtectVirtualMemory;
_NtFreeVirtualMemory pNtFreeVirtualMemory;
_LdrRegisterDllNotification pLdrRegisterDllNotification;
_RtlNtStatusToDosError pRtlNtStatusToDosError;

void resolve_runtime_apis(void)
{
	HMODULE ntdllbase = GetModuleHandle("ntdll");

	if (!ntdllbase)
		return;

	*(FARPROC *)&pNtDelayExecution = GetProcAddress(ntdllbase, "NtDelayExecution");
	*(FARPROC *)&pNtQuerySystemInformation = GetProcAddress(ntdllbase, "NtQuerySystemInformation");
	*(FARPROC *)&pNtQueryInformationProcess = GetProcAddress(ntdllbase, "NtQueryInformationProcess");
	*(FARPROC *)&pNtSetInformationProcess = GetProcAddress(ntdllbase, "NtSetInformationProcess");
	*(FARPROC *)&pNtQueryInformationThread = GetProcAddress(ntdllbase, "NtQueryInformationThread");
	*(FARPROC *)&pNtQueryObject = GetProcAddress(ntdllbase, "NtQueryObject");
	*(FARPROC *)&pNtQueryKey = GetProcAddress(ntdllbase, "NtQueryKey");
	*(FARPROC *)&pNtQueryAttributesFile = GetProcAddress(ntdllbase, "NtQueryAttributesFile");
	*(FARPROC *)&pNtAllocateVirtualMemory = GetProcAddress(ntdllbase, "NtAllocateVirtualMemory");
	*(FARPROC *)&pNtProtectVirtualMemory = GetProcAddress(ntdllbase, "NtProtectVirtualMemory");
	*(FARPROC *)&pNtFreeVirtualMemory = GetProcAddress(ntdllbase, "NtFreeVirtualMemory");
	*(FARPROC *)&pLdrRegisterDllNotification = GetProcAddress(ntdllbase, "LdrRegisterDllNotification");
	*(FARPROC *)&pRtlGenRandom = GetProcAddress(GetModuleHandle("advapi32"), "SystemFunction036");
	*(FARPROC *)&pNtMapViewOfSection = GetProcAddress(ntdllbase, "NtMapViewOfSection");
	*(FARPROC *)&pRtlEqualUnicodeString = GetProcAddress(ntdllbase, "RtlEqualUnicodeString");
	*(FARPROC *)&pNtUnmapViewOfSection = GetProcAddress(ntdllbase, "NtUnmapViewOfSection");
	*(FARPROC *)&pRtlAdjustPrivilege = GetProcAddress(ntdllbase, "RtlAdjustPrivilege");
	*(FARPROC *)&pRtlNtStatusToDosError = GetProcAddress(ntdllbase, "RtlNtStatusToDosError");
}

ULONG_PTR g_our_dll_base;
DWORD g_our_dll_size;

BOOLEAN is_address_in_monitor(ULONG_PTR address)
{
	if (!g_our_dll_base)
		return FALSE;

	if (!g_our_dll_size)
		g_our_dll_size = get_image_size(g_our_dll_base);

	if (address >= g_our_dll_base && address < (g_our_dll_base + g_our_dll_size))
		return TRUE;

	return FALSE;
}
void raw_sleep(int msecs)
{
	LARGE_INTEGER interval;
	interval.QuadPart = -(msecs * 10000);

	pNtDelayExecution(FALSE, &interval);
}

// snprintf can end up acquiring the process' heap lock which will be unsafe in the context of a hooked
// NtAllocate/FreeVirtualMemory
void num_to_string(char *buf, unsigned int buflen, unsigned int num)
{
	unsigned int dec = 1000000000;
	unsigned int i = 0;

	if (!buflen)
		return;

	while (dec) {
		if (!i && ((num / dec) || dec == 1))
			buf[i++] = '0' + (num / dec);
		else if (i)
			buf[i++] = '0' + (num / dec);
		if (i == buflen - 1)
			break;
		num = num % dec;
		dec /= 10;
	}
	buf[i] = '\0';
}

unsigned short our_htons(unsigned short num)
{
	return (num >> 8) | ((num & 0xFF) << 8);
}

unsigned int our_htonl(unsigned int num)
{
	return (num >> 24) | ((num & 0x00FF0000) >> 8) | ((num & 0x0000FF00) << 8) | ((num & 0xFF) << 24);
}

void addr_to_string(const IN_ADDR addr, char *string)
{
	const unsigned char *chunk = (const unsigned char *)&addr;
	string[0] = '\0';
	num_to_string(string, 4, chunk[0]);
	strcat(string, ".");
	num_to_string(string+strlen(string), 4, chunk[1]);
	strcat(string, ".");
	num_to_string(string+strlen(string), 4, chunk[2]);
	strcat(string, ".");
	num_to_string(string+strlen(string), 4, chunk[3]);
}

wchar_t *ascii_to_unicode_dup(char *str)
{
	unsigned int len = (unsigned int)strlen(str);
	unsigned int i;
	wchar_t *rtmp = calloc(1, (len + 1) * sizeof(wchar_t));
	for (i = 0; i < len; i++)
		rtmp[i] = (wchar_t)(unsigned short)str[i];
	return rtmp;
}

int is_stack_pivoted(void)
{
	hook_info_t *hookinfo = hook_info();
	ULONG_PTR bottom, top;
	bottom = get_stack_bottom();
	top = get_stack_top();
	if (hookinfo->stack_pointer >= bottom && hookinfo->stack_pointer < top)
		return 0;
	return 1;
}

static PCHAR memmem(PCHAR haystack, ULONG hlen, PCHAR needle, ULONG nlen)
{
  if (nlen > hlen)
	return NULL;

  ULONG i;
  for (i = 0; i < hlen - nlen + 1; i++) {
	if (!memcmp(haystack + i, needle, nlen))
	  return haystack + i;
  }

  return NULL;
}

BOOL is_bytes_in_buf(PCHAR buf, ULONG len, PCHAR memstr, ULONG memlen, ULONG maxsearchbytes)
{
	return memmem(buf, min(maxsearchbytes, len), memstr, memlen) ? TRUE : FALSE;
}

void replace_string_in_buf(PCHAR buf, ULONG len, PCHAR findstr, PCHAR repstr)
{
	unsigned int findlen = (unsigned int)strlen(findstr);
	unsigned int replen = (unsigned int)strlen(repstr);
	ULONG i;

	if ((findlen != replen) || len < findlen)
		return;

	for (i = 0; i <= len - findlen; i++) {
		if (!memcmp(&buf[i], findstr, findlen)) {
			memcpy(&buf[i], repstr, replen);
			i += replen - 1;
		}
	}
}

void replace_ci_string_in_buf(PCHAR buf, ULONG len, PCHAR findstr, PCHAR repstr)
{
	unsigned int findlen = (unsigned int)strlen(findstr);
	unsigned int replen = (unsigned int)strlen(repstr);
	ULONG i;

	if ((findlen != replen) || len < findlen)
		return;

	for (i = 0; i <= len - findlen; i++) {
		if (!_strnicmp(&buf[i], findstr, findlen)) {
			memcpy(&buf[i], repstr, replen);
			i += replen - 1;
		}
	}
}

// len is in characters
void replace_wstring_in_buf(PWCHAR buf, ULONG len, PWCHAR findstr, PWCHAR repstr)
{
	unsigned int findlen = (unsigned int)wcslen(findstr);
	unsigned int replen = (unsigned int)wcslen(repstr);
	ULONG i;

	if ((findlen != replen) || len < findlen)
		return;

	for (i = 0; i <= len - findlen; i++) {
		if (!memcmp(&buf[i], findstr, findlen * sizeof(wchar_t))) {
			memcpy(&buf[i], repstr, replen * sizeof(wchar_t));
			i += replen - 1;
		}
	}
}

void replace_ci_wstring_in_buf(PWCHAR buf, ULONG len, PWCHAR findstr, PWCHAR repstr)
{
	unsigned int findlen = (unsigned int)wcslen(findstr);
	unsigned int replen = (unsigned int)wcslen(repstr);
	ULONG i;

	if ((findlen != replen) || len < findlen)
		return;

	for (i = 0; i <= len - findlen; i++) {
		if (!_wcsnicmp(&buf[i], findstr, findlen)) {
			memcpy(&buf[i], repstr, replen * sizeof(wchar_t));
			i += replen - 1;
		}
	}
}

// https://stackoverflow.com/questions/27303062/strstr-function-like-that-ignores-upper-or-lower-case
char* stristr(char* haystack, char* needle) {
	int c = tolower(*needle);
	if (c == '\0')
		return haystack;
	for (; *haystack; haystack++) {
		if (tolower(*haystack) == c) {
			for (size_t i = 0;;) {
				if (needle[++i] == '\0')
					return haystack;
				if (tolower(haystack[i]) != tolower(needle[i]))
					break;
			}
		}
	}
	return NULL;
}

void perform_device_fakery(PVOID OutputBuffer, ULONG OutputBufferLength, ULONG IoControlCode)
{
	/* Fake harddrive size to 256GB */
	if (OutputBufferLength >= sizeof(GET_LENGTH_INFORMATION) && IoControlCode == IOCTL_DISK_GET_LENGTH_INFO) {
		((PGET_LENGTH_INFORMATION)OutputBuffer)->Length.QuadPart = 256060514304L;
	}

	if (OutputBufferLength >= sizeof(DISK_GEOMETRY) && IoControlCode == IOCTL_DISK_GET_DRIVE_GEOMETRY) {
		PDISK_GEOMETRY geo = (PDISK_GEOMETRY)OutputBuffer;
		geo->Cylinders.QuadPart = 31130;
		geo->TracksPerCylinder = 255;
		geo->BytesPerSector = 512;
		geo->SectorsPerTrack = 63;
	}

	if (OutputBufferLength >= sizeof(DISK_GEOMETRY) && IoControlCode == IOCTL_DISK_GET_DRIVE_GEOMETRY_EX) {
		PDISK_GEOMETRY_EX geo = (PDISK_GEOMETRY_EX)OutputBuffer;
		geo->Geometry.Cylinders.QuadPart = 31130;
		geo->Geometry.TracksPerCylinder = 255;
		geo->Geometry.BytesPerSector = 512;
		geo->Geometry.SectorsPerTrack = 63;
		if (OutputBufferLength >= (sizeof(DISK_GEOMETRY) + sizeof(LARGE_INTEGER)))
			geo->DiskSize.QuadPart = 256060514304L;
	}

	/* fake model name */
	if (IoControlCode == IOCTL_STORAGE_QUERY_PROPERTY) {
		replace_string_in_buf(OutputBuffer, OutputBufferLength, "QEMU", "DELL");
		replace_string_in_buf(OutputBuffer, OutputBufferLength, "VBOX", "DELL");
		replace_string_in_buf(OutputBuffer, OutputBufferLength, "VMware", "DELL__");
		replace_string_in_buf(OutputBuffer, OutputBufferLength, "Virtual", "C300_BD");
	}

	/* WMI fakery */
	if (IoControlCode == 0x00224000) {
		replace_string_in_buf(OutputBuffer, OutputBufferLength, "Xen", "VIA");
		replace_string_in_buf(OutputBuffer, OutputBufferLength, "QEMU", "DELL");
		replace_string_in_buf(OutputBuffer, OutputBufferLength, "VBOX", "DELL");
		replace_string_in_buf(OutputBuffer, OutputBufferLength, "vbox", "dell");
		replace_string_in_buf(OutputBuffer, OutputBufferLength, "VMware", "DELL  ");
		replace_string_in_buf(OutputBuffer, OutputBufferLength, "Red Hat", "Lenovo ");
		replace_string_in_buf(OutputBuffer, OutputBufferLength, "Virtual", "Compute");
		replace_string_in_buf(OutputBuffer, OutputBufferLength, "innotek GmbH", "ASUS Systems");
		replace_string_in_buf(OutputBuffer, OutputBufferLength, "MS_VM_CERT/SHA1", "Dell System	");
	}
}

void perform_create_time_fakery(FILETIME *createtime)
{
	createtime->dwHighDateTime = 0x1CA0431;
	if (createtime->dwLowDateTime == 0xFDB0C77C)
		createtime->dwLowDateTime++;
}

void perform_ascii_registry_fakery(PWCHAR keypath, LPVOID Data, ULONG DataLength)
{
	if (keypath == NULL || Data == NULL)
		return;

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0\\Identifier")) {
		replace_string_in_buf(Data, DataLength, "QEMU", "DELL");
		replace_string_in_buf(Data, DataLength, "VMware", "DELL__");
		replace_string_in_buf(Data, DataLength, "Virtual", "C300_BD");
		replace_string_in_buf(Data, DataLength, "VBOX", "DELL");
	}

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0\\Identifier")) {
		replace_string_in_buf(Data, DataLength, "QEMU", "DELL");
		replace_string_in_buf(Data, DataLength, "VMware", "DELL__");
		replace_string_in_buf(Data, DataLength, "Virtual", "C300_BD");
		replace_string_in_buf(Data, DataLength, "VBOX", "DELL");
	}

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0\\Identifier")) {
		replace_string_in_buf(Data, DataLength, "QEMU", "DELL");
		replace_string_in_buf(Data, DataLength, "VMware", "DELL__");
		replace_string_in_buf(Data, DataLength, "Virtual", "C300_BD");
		replace_string_in_buf(Data, DataLength, "VBOX", "DELL");
	}

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\HARDWARE\\Description\\System\\SystemBiosVersion")) {
		replace_string_in_buf(Data, DataLength, "VBOX", "DELL");
		replace_string_in_buf(Data, DataLength, "BOCHS", "Award");
	}

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\HARDWARE\\Description\\System\\VideoBiosVersion")) {
		replace_string_in_buf(Data, DataLength, "Oracle VM VirtualBox", "Intel VideoBios v1.3");
	}

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\HARDWARE\\Description\\System\\SystemBiosDate")) {
		replace_string_in_buf(Data, DataLength, "06/23/99", "01/01/02");
	}

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data\\AcpiData") ||
		!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\mssmbios\\Data\\AcpiData")) {
		replace_string_in_buf(Data, DataLength, "VBOX", "DELL");
	}

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data\\SMBiosData") ||
		!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\mssmbios\\Data\\SMBiosData")) {
		replace_string_in_buf(Data, DataLength, "vbox", "DELL");
		replace_string_in_buf(Data, DataLength, "VirtualBox", "Gigabyte__");
		replace_string_in_buf(Data, DataLength, "innotek GmbH", "HP Pavillion");
	}

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\DSDT\\VBOX__\\VBOXBIOS\\00000002\\00000000") ||
		!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\FADT\\VBOX__\\VBOXFACP\\00000001\\00000000") ||
		!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\RSDT\\VBOX__\\VBOXRSDT\\00000001\\00000000")) {
		replace_string_in_buf(Data, DataLength, "VBOX", "DELL");
	}

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\Disk\\Enum\\0")) {
		replace_string_in_buf(Data, DataLength, "QEMU", "DELL");
		replace_string_in_buf(Data, DataLength, "VMware", "DELL__");
		replace_string_in_buf(Data, DataLength, "Virtual", "C300_BD");
		replace_string_in_buf(Data, DataLength, "VBOX", "DELL");
	}

	if (!wcsnicmp(keypath, L"HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor", 63) &&
		!wcsicmp(keypath + wcslen(keypath) - wcslen(L"ProcessorNameString"), L"ProcessorNameString")) {
		replace_string_in_buf(Data, DataLength, "QEMU Virtual CPU version 2.0.0", "Intel(R) Core(TM) i7 CPU @3GHz");
		replace_string_in_buf(Data, DataLength, "Xeon(R) ", "Core(TM)");
	}

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemManufacturer") ||
		!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemProductName")) {
		replace_string_in_buf(Data, DataLength, "VMware", "Lenovo");
		replace_string_in_buf(Data, DataLength, "Virtual Platform", "X230 ThinkPad PC");
	}

	// fake the manufacturer name
	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\SystemInformation\\SystemManufacturer"))
		replace_string_in_buf(Data, DataLength, "QEMU", "DELL");

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Enum\\IDE\\") ||
		!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Enum\\SCSI\\")) {
		replace_string_in_buf(Data, DataLength, "VMware", "Lenovo");
		replace_string_in_buf(Data, DataLength, "VMWar", "Lenov");
		replace_string_in_buf(Data, DataLength, "VBOX", "DELL");
	}

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\DeviceClasses\\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}")) {
		replace_string_in_buf(Data, DataLength, "VMware", "Lenovo");
		replace_string_in_buf(Data, DataLength, "VMWar", "Lenov");
		replace_string_in_buf(Data, DataLength, "VBOX", "DELL");
	}

	// Zloader macro checks using reg.exe to check macros are not enabled
	if ((!wcsicmp(keypath, L"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\14.0\\Excel\\Security\\VBAWarnings")
		|| !wcsicmp(keypath, L"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\15.0\\Excel\\Security\\VBAWarnings")
		|| !wcsicmp(keypath, L"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\VBAWarnings"))
		&& stricmp(our_process_name, "excel.exe")) {
		if (*(DWORD*)Data == 1) {
			*(DWORD*)Data = (DWORD)4;   // The most secure setting
			DebugOutput("VBAWarnings reg check detected! Patching data: 0x%x, (%s) %d", *(DWORD*)Data, our_process_name, stricmp(our_process_name, "excel.exe"));
		}
	}

	if ((!wcsicmp(keypath, L"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\14.0\\Excel\\Security\\AccessVBOM")
		|| !wcsicmp(keypath, L"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\15.0\\Excel\\Security\\AccessVBOM")
		|| !wcsicmp(keypath, L"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\AccessVBOM"))
		&& stricmp(our_process_name, "excel.exe")) {
		if (*(DWORD*)Data == 1) {
			*(DWORD*)Data = (DWORD)0;
			DebugOutput("AccessVBOM reg check detected! Patching data: 0x%x", *(DWORD*)Data);
		}
	}
}

void perform_unicode_registry_fakery(PWCHAR keypath, LPVOID Data, ULONG DataLength)
{
	if (keypath == NULL || Data == NULL)
		return;

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0\\Identifier")) {
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"QEMU", L"DELL");
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"VMware", L"DELL__");
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"Virtual", L"C300_BD");
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"VBOX", L"DELL");
	}

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\HARDWARE\\Description\\System\\SystemBiosVersion")) {
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"VBOX", L"DELL");
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"BOCHS", L"Award");
	}

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\HARDWARE\\Description\\System\\SystemBiosDate")) {
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"06/23/99", L"01/01/02");
	}

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\HARDWARE\\Description\\System\\VideoBiosVersion")) {
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"Oracle VM VirtualBox", L"Intel VideoBios v1.3");
	}

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data\\AcpiData") ||
		!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\mssmbios\\Data\\AcpiData")) {
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"VBOX", L"DELL");
	}

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data\\SMBiosData") ||
		!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\mssmbios\\Data\\SMBiosData")) {
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"vbox", L"DELL");
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"VirtualBox", L"Gigabyte__");
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"innotek GmbH", L"HP Pavillion");
	}

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\DSDT\\VBOX__\\VBOXBIOS\\00000002\\00000000") ||
		!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\FADT\\VBOX__\\VBOXFACP\\00000001\\00000000") ||
		!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\RSDT\\VBOX__\\VBOXRSDT\\00000001\\00000000")) {
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"VBOX", L"DELL");
	}

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\Disk\\Enum\\0")) {
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"QEMU", L"DELL");
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"VMware", L"DELL__");
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"Virtual", L"C300_BD");
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"VBOX", L"DELL");
	}

	if (!wcsnicmp(keypath, L"HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor", 63) &&
		!wcsicmp(keypath + wcslen(keypath) - wcslen(L"ProcessorNameString"), L"ProcessorNameString")) {
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"QEMU Virtual CPU version 2.0.0", L"Intel(R) Core(TM) i7 CPU @3GHz");
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"Xeon(R) ", L"Core(TM)");
	}

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemManufacturer") ||
		!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemProductName")) {
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"VMware", L"Lenovo");
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"Virtual Platform", L"X230 ThinkPad PC");
	}

	// fake the manufacturer name
	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\SystemInformation\\SystemManufacturer"))
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"QEMU", L"DELL");

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Enum\\IDE\\") ||
		!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Enum\\SCSI\\")) {
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"VMware", L"Lenovo");
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"VMWar", L"Lenov");
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"VBOX", L"DELL");
	}

	if (!wcsicmp(keypath, L"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\DeviceClasses\\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}")) {
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"VMware", L"Lenovo");
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"VMWar", L"Lenov");
		replace_wstring_in_buf(Data, DataLength / sizeof(wchar_t), L"VBOX", L"DELL");
	}

	// Zloader macro checks using reg.exe to check macros are not enabled
	if ((!wcsicmp(keypath, L"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\14.0\\Excel\\Security\\VBAWarnings")
		|| !wcsicmp(keypath, L"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\15.0\\Excel\\Security\\VBAWarnings")
		|| !wcsicmp(keypath, L"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\VBAWarnings"))
		&& stricmp(our_process_name, "excel.exe")) {
		if (*(DWORD*)Data == 1) {
			*(DWORD*)Data = (DWORD)4;   // The most secure setting
			DebugOutput("VBAWarnings reg check detected! Patching data: 0x%x, (%s) %d", *(DWORD*)Data, our_process_name, stricmp(our_process_name, "excel.exe"));
		}
	}

	if ((!wcsicmp(keypath, L"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\14.0\\Excel\\Security\\AccessVBOM")
		|| !wcsicmp(keypath, L"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\15.0\\Excel\\Security\\AccessVBOM")
		|| !wcsicmp(keypath, L"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\AccessVBOM"))
		&& stricmp(our_process_name, "excel.exe")) {
		if (*(DWORD*)Data == 1) {
			*(DWORD*)Data = (DWORD)0;
			DebugOutput("AccessVBOM reg check detected! Patching data: 0x%x", *(DWORD*)Data);
		}
	}
}

DWORD get_image_size(ULONG_PTR base)
{
	PIMAGE_DOS_HEADER doshdr = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS nthdr = (PIMAGE_NT_HEADERS)(base + doshdr->e_lfanew);
	return nthdr->OptionalHeader.SizeOfImage;
}

BOOLEAN is_valid_address_range(ULONG_PTR start, DWORD len)
{
	MEMORY_BASIC_INFORMATION meminfo;

	if (!VirtualQuery((LPCVOID)start, &meminfo, sizeof(meminfo)))
		return FALSE;

	if (start < (ULONG_PTR)meminfo.BaseAddress || (start + len) > ((ULONG_PTR)meminfo.BaseAddress + meminfo.RegionSize))
		return FALSE;

	if (!(meminfo.State & MEM_COMMIT))
		return FALSE;

	if (meminfo.Protect & (PAGE_NOACCESS | PAGE_GUARD))
		return FALSE;

	return TRUE;
}

DWORD parent_process_id() // By Napalm @ NetCore2K (rohitab.com)
{
	PROCESS_BASIC_INFORMATION pbi;
	ULONG ulSize = 0;

	if (pNtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &ulSize) >= 0 && ulSize == sizeof(pbi))
		return (DWORD)pbi.ParentProcessId;

	return 0;
}

DWORD pid_from_process_handle(HANDLE process_handle)
{
	PROCESS_BASIC_INFORMATION pbi;
	ULONG ulSize;
	HANDLE dup_handle = process_handle;
	DWORD PID = 0;
	BOOL duped;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	if (process_handle == GetCurrentProcess()) {
		PID = GetCurrentProcessId();
		goto out;
	}

	memset(&pbi, 0, sizeof(pbi));

	duped = DuplicateHandle(GetCurrentProcess(), process_handle, GetCurrentProcess(), &dup_handle, PROCESS_QUERY_INFORMATION, FALSE, 0);

	if (pNtQueryInformationProcess(dup_handle, 0, &pbi, sizeof(pbi), &ulSize) >= 0 && ulSize == sizeof(pbi))
		PID = (DWORD)pbi.UniqueProcessId;

	if (duped)
		CloseHandle(dup_handle);

out:
	set_lasterrors(&lasterror);

	return PID;
}

static BOOL cid_from_thread_handle(HANDLE thread_handle, PCLIENT_ID cid)
{
	THREAD_BASIC_INFORMATION tbi;
	ULONG ulSize;
	HANDLE dup_handle = thread_handle;
	BOOL duped;
	BOOL ret = FALSE;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	memset(&tbi, 0, sizeof(tbi));

	duped = DuplicateHandle(GetCurrentProcess(), thread_handle, GetCurrentProcess(), &dup_handle, THREAD_QUERY_INFORMATION, FALSE, 0);

	if (duped) {
        if (pNtQueryInformationThread(dup_handle, 0, &tbi, sizeof(tbi), &ulSize) >= 0 && ulSize == sizeof(tbi)) {
            memcpy(cid, &tbi.ClientId, sizeof(CLIENT_ID));
            ret = TRUE;
        }

		CloseHandle(dup_handle);
    }

	set_lasterrors(&lasterror);

	return ret;
}

DWORD pid_from_thread_handle(HANDLE thread_handle)
{
	CLIENT_ID cid;
	BOOL ret;

	memset(&cid, 0, sizeof(cid));

	ret = cid_from_thread_handle(thread_handle, &cid);
	return (DWORD)(ULONG_PTR)cid.UniqueProcess;
}

DWORD tid_from_thread_handle(HANDLE thread_handle)
{
	CLIENT_ID cid;
	BOOL ret;

	memset(&cid, 0, sizeof(cid));

	ret = cid_from_thread_handle(thread_handle, &cid);
	return (DWORD)(ULONG_PTR)cid.UniqueThread;
}

DWORD our_getprocessid(HANDLE Process)
{
	DWORD ret;
	lasterror_t lasterror;
	get_lasterrors(&lasterror);
	if (Process == NtCurrentProcess())
		ret = GetCurrentProcessId();
	else
		ret = GetProcessId(Process);
	set_lasterrors(&lasterror);
	return ret;
}

DWORD random()
{
	DWORD ret, realret;
	lasterror_t lasterror;

	if (!pRtlGenRandom)
		return 0;

	get_lasterrors(&lasterror);

	realret = pRtlGenRandom(&ret, sizeof(ret)) ? ret : rand();

	set_lasterrors(&lasterror);

	return realret;
}

DWORD randint(DWORD min, DWORD max)
{
	return min + (random() % (max - min + 1));
}

BOOL is_directory_objattr(const OBJECT_ATTRIBUTES *obj)
{
	FILE_BASIC_INFORMATION basic_information;
	if (NT_SUCCESS(pNtQueryAttributesFile(obj, &basic_information)))
		return (BOOL)basic_information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY;
	return FALSE;
}

BOOL file_exists(const OBJECT_ATTRIBUTES *obj)
{
	FILE_BASIC_INFORMATION basic_information;
	wchar_t pipe_base_name[] = L"\\??\\pipe\\";
	if (!wcsnicmp(obj->ObjectName->Buffer, pipe_base_name, wcslen(pipe_base_name)))
		return FALSE;
	NTSTATUS ret = pNtQueryAttributesFile(obj, &basic_information);
	if (NT_SUCCESS(ret) || ret == STATUS_INVALID_DEVICE_REQUEST)
		return TRUE;
	return FALSE;
}

DWORD loaded_dlls;
struct dll_range dll_ranges[MAX_DLLS];

void add_dll_range(ULONG_PTR start, ULONG_PTR end)
{
	DWORD tmp_loaded_dlls = loaded_dlls;
	if (tmp_loaded_dlls >= MAX_DLLS)
		return;
	if (is_in_dll_range(start))
		return;
	dll_ranges[tmp_loaded_dlls].start = start;
	dll_ranges[tmp_loaded_dlls].end = end;

	loaded_dlls++;
}

BOOL is_in_dll_range(ULONG_PTR addr)
{
	DWORD i;
	for (i = 0; i < loaded_dlls; i++)
		if (addr >= dll_ranges[i].start && addr < dll_ranges[i].end)
			return TRUE;
	return FALSE;
}

ULONG_PTR base_of_dll_of_interest;

void set_dll_of_interest(ULONG_PTR BaseAddress)
{
	base_of_dll_of_interest = BaseAddress;
}

void add_all_dlls_to_dll_ranges(void)
{
	LDR_DATA_TABLE_ENTRY * mod;
	PLIST_ENTRY pHeadEntry;
	PLIST_ENTRY pListEntry;
	UNICODE_STRING ProcessPath, ModulePath;
	PEB *peb = (PEB *)get_peb();

	pHeadEntry = &peb->LoaderData->InLoadOrderModuleList;
	pListEntry = pHeadEntry->Flink;
	mod = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
	ProcessPath.MaximumLength = ProcessPath.Length = mod->FullDllName.Length - mod->BaseDllName.Length;
	ProcessPath.Buffer = calloc(ProcessPath.Length/sizeof(WCHAR) + 1, sizeof(WCHAR));
	memcpy(ProcessPath.Buffer, mod->FullDllName.Buffer, ProcessPath.Length);

	// skip the base image
	for (pListEntry = pHeadEntry->Flink->Flink;
		pListEntry != pHeadEntry;
		pListEntry = pListEntry->Flink)
	{
		mod = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
		// skip dlls in same directory as exe
		if (!path_is_system(ProcessPath.Buffer)) {
			ModulePath.MaximumLength = ModulePath.Length = mod->FullDllName.Length - mod->BaseDllName.Length;
			ModulePath.Buffer = calloc(ModulePath.Length/sizeof(WCHAR) + 1, sizeof(WCHAR));
			memcpy(ModulePath.Buffer, mod->FullDllName.Buffer, ModulePath.Length);
			if (pRtlEqualUnicodeString(&ProcessPath, &ModulePath, FALSE) || (ULONG_PTR)mod->BaseAddress == base_of_dll_of_interest) {
				free(ModulePath.Buffer);
				continue;
			}
			free(ModulePath.Buffer);
		}
		add_dll_range((ULONG_PTR)mod->BaseAddress, (ULONG_PTR)mod->BaseAddress + mod->SizeOfImage);
	}

	free(ProcessPath.Buffer);
}

char *convert_address_to_dll_name_and_offset(ULONG_PTR addr, unsigned int *offset)
{
	PLDR_DATA_TABLE_ENTRY mod;
	PLIST_ENTRY pHeadEntry;
	PLIST_ENTRY pListEntry;
	PEB *peb = (PEB *)get_peb();

	if (addr >= g_our_dll_base && addr < (g_our_dll_base + g_our_dll_size))
	{
#ifdef _WIN64
		char our_dll_name[] = "capemon_x64.dll";
#else
		char our_dll_name[] = "capemon.dll";
#endif
		char *buf = calloc(1, strlen(our_dll_name) + 1);
		if (buf == NULL)
			return NULL;
		strcpy(buf, our_dll_name);
		*offset = (unsigned int)(addr - g_our_dll_base);
		return buf;
	}

	pHeadEntry = &peb->LoaderData->InLoadOrderModuleList;
	for(pListEntry = pHeadEntry->Flink;
		pListEntry != pHeadEntry;
		pListEntry = pListEntry->Flink)
	{
		mod = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
		char *buf;
		unsigned int i;

		if (addr < (ULONG_PTR)mod->BaseAddress || addr >= ((ULONG_PTR)mod->BaseAddress + mod->SizeOfImage))
			continue;
		buf = calloc(1, (mod->BaseDllName.Length / sizeof(wchar_t)) + 1);
		if (buf == NULL)
			return NULL;
		for (i = 0; i < (mod->BaseDllName.Length / sizeof(wchar_t)); i++)
			buf[i] = (char)mod->BaseDllName.Buffer[i];
		*offset = (unsigned int)(addr - (ULONG_PTR)mod->BaseAddress);
		return buf;
	}
	return NULL;
}

// hide our module from PEB
// http://www.openrce.org/blog/view/844/How_to_hide_dll

#define CUT_LIST(item) \
	item.Blink->Flink = item.Flink; \
	item.Flink->Blink = item.Blink

void hide_module_from_peb(HMODULE module_handle)
{
	PLDR_DATA_TABLE_ENTRY mod;
	PLIST_ENTRY pHeadEntry;
	PLIST_ENTRY pListEntry;
	PEB *peb = (PEB *)get_peb();

	pHeadEntry = &peb->LoaderData->InLoadOrderModuleList;
	for(pListEntry = pHeadEntry->Flink;
		pListEntry != pHeadEntry;
		pListEntry = pListEntry->Flink)
	{
		mod = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

		if (mod->BaseAddress == module_handle) {
			CUT_LIST(mod->InLoadOrderModuleList);
			CUT_LIST(mod->InInitializationOrderModuleList);
			CUT_LIST(mod->InMemoryOrderModuleList);

			// TODO test whether this list is really used as a linked list
			// like InLoadOrderModuleList etc
			CUT_LIST(mod->HashTableEntry);

			break;
		}
	}
}

PUNICODE_STRING get_basename_of_module(HMODULE module_handle)
{
	PLDR_DATA_TABLE_ENTRY mod;
	PLIST_ENTRY pHeadEntry;
	PLIST_ENTRY pListEntry;
	PEB* peb = (PEB*)get_peb();

	pHeadEntry = &peb->LoaderData->InLoadOrderModuleList;
	for(pListEntry = pHeadEntry->Flink;
		pListEntry != pHeadEntry;
		pListEntry = pListEntry->Flink)
	{
		mod = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

		if (mod->BaseAddress == module_handle)
			return &mod->BaseDllName;
	}

	return NULL;
}

BOOL loader_lock_held()
{
	PEB *peb = (PEB*)get_peb();
	return (HANDLE)(DWORD_PTR)GetCurrentThreadId() == peb->LoaderLock->OwningThread;
}

uint32_t path_from_handle(HANDLE handle,
	wchar_t *path, uint32_t path_buffer_len)
{
	POBJECT_NAME_INFORMATION resolvedName;
	ULONG returnLength;
	NTSTATUS status;
	uint32_t length = 0;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	resolvedName = (POBJECT_NAME_INFORMATION)calloc(1, OBJECT_NAME_INFORMATION_REQUIRED_SIZE);

	status = pNtQueryObject(handle, ObjectNameInformation,
		resolvedName, OBJECT_NAME_INFORMATION_REQUIRED_SIZE, &returnLength);

	if (NT_SUCCESS(status)) {
		length = min(resolvedName->Name.Length / sizeof(wchar_t), path_buffer_len - 1);
		// NtQueryInformationFile omits the "C:" part in a
		// filename, apparently
		memcpy(path, resolvedName->NameBuffer, length * sizeof(wchar_t));
	}
	if (path_buffer_len)
		path[length] = L'\0';

	free(resolvedName);

	set_lasterrors(&lasterror);

	return length;
}

uint32_t path_from_object_attributes(const OBJECT_ATTRIBUTES *obj,
	wchar_t *path, uint32_t buffer_length)
{
	uint32_t copylen, obj_length, length;

	if (obj->ObjectName == NULL || obj->ObjectName->Buffer == NULL) {
		return path_from_handle(obj->RootDirectory, path, buffer_length);;
	}

	// ObjectName->Length is actually the size in bytes.
	obj_length = obj->ObjectName->Length / sizeof(wchar_t);

	copylen = min(obj_length, buffer_length - 1);

	if (obj->RootDirectory == NULL) {
		memcpy(path, obj->ObjectName->Buffer, copylen * sizeof(wchar_t));
		path[copylen] = L'\0';
		return copylen;
	}

	length = path_from_handle(obj->RootDirectory, path, buffer_length);

	path[length++] = L'\\';
	if (length >= (buffer_length - 1))
		copylen = 0;
	else
		copylen = buffer_length - 1 - length;
	copylen = min(copylen, obj_length);
	memcpy(&path[length], obj->ObjectName->Buffer, copylen * sizeof(wchar_t));
	path[length + copylen] = L'\0';
	return length + copylen;
}

static char *system32dir_a;
static char *sysnativedir_a;
static wchar_t *system32dir_w;
static wchar_t *sysnativedir_w;
static unsigned int system32dir_len;
static unsigned int sysnativedir_len;

char *ensure_absolute_ascii_path(char *out, const char *in)
{
	char tmpout[MAX_PATH];
	char nonexistent[MAX_PATH];
	char *pathcomponent;
	unsigned int nonexistentidx;
	unsigned int pathcomponentlen;
	unsigned int lenchars;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	if (!GetFullPathNameA(in, MAX_PATH, tmpout, NULL))
		goto normal_copy;

	lenchars = 0;
	nonexistentidx = MAX_PATH - 1;
	nonexistent[nonexistentidx] = '\0';
	while (lenchars == 0) {
		lenchars = GetLongPathNameA(tmpout, out, MAX_PATH);
		if (lenchars)
			break;
		if (GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND && GetLastError() != ERROR_INVALID_NAME)
			goto normal_copy;
		pathcomponent = strrchr(tmpout, '\\');
		if (pathcomponent == NULL)
			goto normal_copy;
		pathcomponentlen = (unsigned int)strlen(pathcomponent);
		nonexistentidx -= pathcomponentlen;
		memcpy(nonexistent + nonexistentidx, pathcomponent, pathcomponentlen * sizeof(char));
		*pathcomponent = '\0';
	}
	strncat(out, nonexistent + nonexistentidx, MAX_PATH - strlen(out));
	goto out;

normal_copy:
	__try {
		strncpy(out, in, MAX_PATH);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		out[0] = '\0';
	}
out:
	if (is_wow64_fs_redirection_disabled() && !_strnicmp(out, system32dir_a, system32dir_len)) {
		memmove(out + system32dir_len + 1, out + system32dir_len, strlen(out + system32dir_len) + 1);
		memcpy(out, sysnativedir_a, sysnativedir_len);
	}
	out[MAX_PATH - 1] = '\0';
	if (out[1] == ':' && out[2] == '\\')
		out[0] = toupper(out[0]);

	set_lasterrors(&lasterror);

	return out;
}

wchar_t *ensure_absolute_unicode_path(wchar_t *out, const wchar_t *in)
{
	wchar_t *tmpout = NULL;
	wchar_t *nonexistent = NULL;
	unsigned int lenchars;
	unsigned int nonexistentidx;
	wchar_t *pathcomponent = NULL;
	unsigned int pathcomponentlen;
	const wchar_t *inadj = NULL;
	unsigned int inlen;
	int is_globalroot = 0;

	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	__try {
		if (!wcsncmp(in, L"\\??\\", 4)) {
			inadj = in + 4;
			is_globalroot = 1;
		}
		else if (!wcsnicmp(in, L"\\\\?\\globalroot", 14)) {
			inadj = in + 14;
			is_globalroot = 1;
		}
		else
			inadj = in;

		inlen = lstrlenW(inadj);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		out[0] = L'\0';
		goto out;
	}

	tmpout = malloc(32768 * sizeof(wchar_t));
	nonexistent = malloc(32768 * sizeof(wchar_t));

	if (tmpout == NULL || nonexistent == NULL)
		goto normal_copy;

	if (!wcsnicmp(inadj, L"\\device\\", 8) || !wcsnicmp(inadj, L"\\systemroot", 11)) {
		// handle \\Device\\* and \\systemroot\\*
		unsigned int matchlen;
		wchar_t *tmpout2;
		wchar_t *retstr = get_matching_unicode_specialname(inadj, &matchlen);
		if (retstr == NULL)
			goto normal_copy;
		// rewrite \\Device\\HarddiskVolumeX etc to the appropriate drive letter
		tmpout2 = malloc(32768 * sizeof(wchar_t));
		if (tmpout2 == NULL)
			goto normal_copy;

		wcscpy(tmpout2, L"\\\\?\\");
		wcscat(tmpout2, retstr);
		wcsncat(tmpout2, inadj + matchlen, 32768 - 4 - 3);
		if (!GetFullPathNameW(tmpout2, 32768, tmpout, NULL)) {
			free(tmpout2);
			goto normal_copy;
		}
		free(tmpout2);
	}
	else if (inlen > 1 && inadj[1] == L':') {
		wchar_t *tmpout2;

		tmpout2 = malloc(32768 * sizeof(wchar_t));
		if (tmpout2 == NULL)
			goto normal_copy;

		wcscpy(tmpout2, L"\\\\?\\");
		wcsncat(tmpout2, inadj, 32768 - 4);
		if (!GetFullPathNameW(tmpout2, 32768, tmpout, NULL)) {
			free(tmpout2);
			goto normal_copy;
		}
		free(tmpout2);
	}
	else if (is_globalroot) {
		// handle \\??\\*\\*
		goto globalroot_copy;
	}
	else {
		if (!GetFullPathNameW(inadj, 32768, tmpout, NULL))
			goto normal_copy;
	}

	lenchars = 0;
	nonexistentidx = 32767;
	nonexistent[nonexistentidx] = L'\0';
	while (lenchars == 0) {
		lenchars = GetLongPathNameW(tmpout, out, 32768);
		if (lenchars)
			break;
		if (GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND && GetLastError() != ERROR_INVALID_NAME)
			goto normal_copy;
		pathcomponent = wcsrchr(tmpout, L'\\');
		if (pathcomponent == NULL)
			goto normal_copy;
		pathcomponentlen = lstrlenW(pathcomponent);
		nonexistentidx -= pathcomponentlen;
		memcpy(nonexistent + nonexistentidx, pathcomponent, pathcomponentlen * sizeof(wchar_t));
		*pathcomponent = L'\0';
	}
	wcsncat(out, nonexistent + nonexistentidx, 32768 - lstrlenW(out));

	if (!wcsncmp(out, L"\\\\?\\", 4))
		memmove(out, out + 4, (lstrlenW(out) + 1 - 4) * sizeof(wchar_t));

	if (is_wow64_fs_redirection_disabled() && !wcsnicmp(out, system32dir_w, system32dir_len)) {
		memmove(out + system32dir_len + 1, out + system32dir_len, (lstrlenW(out + system32dir_len) + 1) * sizeof(wchar_t));
		memcpy(out, sysnativedir_w, sysnativedir_len * sizeof(wchar_t));
	}

	goto out;

globalroot_copy:
	wcscpy(out, L"\\??\\");
	wcsncat(out, inadj, 32768 - 4);
	goto out;

normal_copy:
	wcsncpy(out, inadj, 32768);
	if (!wcsncmp(out, L"\\\\?\\", 4))
		memmove(out, out + 4, (lstrlenW(out) + 1 - 4) * sizeof(wchar_t));
out:
	out[32767] = L'\0';
	if (tmpout)
		free(tmpout);
	if (nonexistent)
		free(nonexistent);
	if (out[1] == L':' && out[2] == L'\\')
		out[0] = toupper(out[0]);

	set_lasterrors(&lasterror);

	return out;
}

static unsigned int get_encoded_unicode_string_len(const wchar_t *buf, USHORT len)
{
	unsigned int numnulls = 0;
	unsigned int i;

	for (i = 0; i < len / sizeof(wchar_t); i++) {
		if (buf[i] == L'\0')
			numnulls++;
	}

	return len + (numnulls * 4 * sizeof(wchar_t));
}

static void copy_encoded_unicode_string(wchar_t *out, const wchar_t *in, unsigned int origlen, unsigned int newlen)
{
	unsigned int i, x;

	for (i = 0, x = 0; i < origlen / sizeof(wchar_t); i++) {
		if (in[i] == L'\0') {
			out[x++] = L'\\';
			out[x++] = L'x';
			out[x++] = L'0';
			out[x++] = L'0';
		}
		else
			out[x++] = in[i];
	}
	out[newlen / sizeof(wchar_t)] = L'\0';
}

wchar_t *get_full_keyvalue_pathA(HKEY registry, const char *in, PKEY_NAME_INFORMATION keybuf, unsigned int len)
{
	if (in && in[0] != '\0')
		return get_full_key_pathA(registry, in, keybuf, len);
	else
		return get_full_key_pathA(registry, "(Default)", keybuf, len);
}
wchar_t *get_full_keyvalue_pathW(HKEY registry, const wchar_t *in, PKEY_NAME_INFORMATION keybuf, unsigned int len)
{
	if (in && in[0] != L'\0')
		return get_full_key_pathW(registry, in, keybuf, len);
	else
		return get_full_key_pathW(registry, L"(Default)", keybuf, len);
}
wchar_t *get_full_keyvalue_pathUS(HKEY registry, const PUNICODE_STRING in, PKEY_NAME_INFORMATION keybuf, unsigned int len)
{
	wchar_t *ret;
	if (in && in->Buffer && in->Length) {
		unsigned int newlen = get_encoded_unicode_string_len(in->Buffer, in->Length);
		wchar_t *incpy = malloc(newlen + (1 * sizeof(wchar_t)));
		copy_encoded_unicode_string(incpy, in->Buffer, in->Length, newlen);
		ret = get_full_key_pathW(registry, incpy, keybuf, len);
		free(incpy);
	}
	else {
		ret = get_full_key_pathW(registry, L"(Default)", keybuf, len);
	}
	return ret;
}

wchar_t *get_full_key_pathA(HKEY registry, const char *in, PKEY_NAME_INFORMATION keybuf, unsigned int len)
{
	wchar_t *widein = NULL;
	const char *p;
	wchar_t *u;
	unsigned int widelen = 0;
	wchar_t *ret;

	if (in) {
		widelen = (unsigned int)((strlen(in) + 1) * sizeof(wchar_t));
		widein = calloc(1, widelen);
		for (u = widein, p = in; *p; p++, u++)
			*u = (wchar_t)(unsigned short)*p;
	}

	ret = get_full_key_pathW(registry, widein, keybuf, len);

	if (widein)
		free(widein);

	return ret;
}

wchar_t *get_full_key_pathW(HKEY registry, const wchar_t *in, PKEY_NAME_INFORMATION keybuf, unsigned int len)
{
	OBJECT_ATTRIBUTES objattr;
	UNICODE_STRING keystr;
	const wchar_t *p;
	wchar_t *u;
	wchar_t *ret;
	unsigned short idx = 0;

	memset(&objattr, 0, sizeof(objattr));

	keystr.Buffer = calloc(1, MAX_KEY_BUFLEN);
	keystr.MaximumLength = MAX_KEY_BUFLEN;
	objattr.ObjectName = &keystr;

	if (in) {
		for (p = in, u = keystr.Buffer; *p && idx < (MAX_KEY_BUFLEN / sizeof(wchar_t) - 1); p++, u++, idx++) {
			*u = *p;
			// normalize duplicate backslashes in the user-provided string as the registry APIs will use them without error
			if (*p == L'\\') {
				while (*(p + 1) == L'\\')
					p++;
			}
		}
		keystr.Length = idx * sizeof(wchar_t);
	}
	else {
		keystr.Buffer[0] = L'\0';
		keystr.Length = 0;
	}

	objattr.RootDirectory = registry;

	ret = get_key_path(&objattr, keybuf, len);
	free(keystr.Buffer);
	return ret;
}

wchar_t *get_key_path(POBJECT_ATTRIBUTES ObjectAttributes, PKEY_NAME_INFORMATION keybuf, unsigned int len)
{
	NTSTATUS status;
	ULONG reslen;
	unsigned int maxlen = len - sizeof(KEY_NAME_INFORMATION);
	unsigned int maxlen_chars = maxlen / sizeof(WCHAR);
	unsigned int remaining;
	unsigned int curlen;
	HKEY rootkey;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	if (ObjectAttributes == NULL || ObjectAttributes->ObjectName == NULL)
		goto error;
	if (ObjectAttributes->RootDirectory == NULL) {
		unsigned int copylen = min(maxlen, ObjectAttributes->ObjectName->Length);
		unsigned int newlen = get_encoded_unicode_string_len(ObjectAttributes->ObjectName->Buffer, copylen);
		copy_encoded_unicode_string(keybuf->KeyName, ObjectAttributes->ObjectName->Buffer, copylen, newlen);
		keybuf->KeyNameLength = newlen;
		goto normal;
	}

	keybuf->KeyName[0] = L'\0';
	keybuf->KeyNameLength = 0;

	/* mingw doesn't like case statements with pointer values */
	rootkey = (HKEY)ObjectAttributes->RootDirectory;
	if (rootkey == HKEY_CLASSES_ROOT)
		wcscpy(keybuf->KeyName, L"HKEY_CLASSES_ROOT");
	else if (rootkey == HKEY_CURRENT_USER)
		wcscpy(keybuf->KeyName, L"HKEY_CURRENT_USER");
	else if (rootkey == HKEY_LOCAL_MACHINE)
		wcscpy(keybuf->KeyName, L"HKEY_LOCAL_MACHINE");
	else if (rootkey == HKEY_USERS)
		wcscpy(keybuf->KeyName, L"HKEY_USERS");
	else if (rootkey == HKEY_PERFORMANCE_DATA)
		wcscpy(keybuf->KeyName, L"HKEY_PERFORMANCE_DATA");
	else if (rootkey == HKEY_PERFORMANCE_TEXT)
		wcscpy(keybuf->KeyName, L"HKEY_PERFORMANCE_TEXT");
	else if (rootkey == HKEY_PERFORMANCE_NLSTEXT)
		wcscpy(keybuf->KeyName, L"HKEY_PERFORMANCE_NLSTEXT");
	else if (rootkey == HKEY_CURRENT_CONFIG)
		wcscpy(keybuf->KeyName, L"HKEY_CURRENT_CONFIG");
	else if (rootkey == HKEY_DYN_DATA)
		wcscpy(keybuf->KeyName, L"HKEY_DYN_DATA");
	else if (rootkey == HKEY_CURRENT_USER_LOCAL_SETTINGS)
		wcscpy(keybuf->KeyName, L"HKEY_CURRENT_USER_LOCAL_SETTINGS");

	keybuf->KeyNameLength = lstrlenW(keybuf->KeyName) * sizeof(wchar_t);
	if (!keybuf->KeyNameLength) {
		status = pNtQueryKey(ObjectAttributes->RootDirectory, KeyNameInformation, keybuf, len, &reslen);
		if (status < 0)
			goto error;
	}

	keybuf->KeyName[keybuf->KeyNameLength / sizeof(WCHAR)] = 0;

	curlen = (unsigned int)wcslen(keybuf->KeyName);
	remaining = maxlen_chars - (unsigned int)wcslen(keybuf->KeyName) - 1;

	if (ObjectAttributes->ObjectName == NULL) {
		if (remaining < 10)
			goto error;
		wcscat(keybuf->KeyName, L"(Default)");
		keybuf->KeyNameLength = (curlen + 9) * sizeof(WCHAR);
	}
	else {
		unsigned int newlen = get_encoded_unicode_string_len(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);

		if ((remaining * sizeof(WCHAR)) < newlen + (1 * sizeof(WCHAR)))
			goto error;

		keybuf->KeyName[curlen++] = L'\\';
		copy_encoded_unicode_string(keybuf->KeyName + curlen, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, newlen);
		keybuf->KeyNameLength = curlen * sizeof(WCHAR) + newlen;
	}

normal:
	if (!wcsnicmp(keybuf->KeyName, g_hkcu.hkcu_string, g_hkcu.len) && (keybuf->KeyName[g_hkcu.len] == L'\\' || keybuf->KeyName[g_hkcu.len] == L'\0')) {
		unsigned int ourlen = lstrlenW(L"HKEY_CURRENT_USER");
		memcpy(keybuf->KeyName, L"HKEY_CURRENT_USER", ourlen * sizeof(WCHAR));
		memmove(keybuf->KeyName + ourlen, keybuf->KeyName + g_hkcu.len, keybuf->KeyNameLength + (1 * sizeof(WCHAR)) - ((g_hkcu.len) * sizeof(WCHAR)));
		keybuf->KeyNameLength -= (g_hkcu.len - ourlen) * sizeof(WCHAR);
	}
	else if (!wcsnicmp(keybuf->KeyName, g_hkcu.hkcu_string, g_hkcu.len) && !wcsnicmp(&keybuf->KeyName[g_hkcu.len], L"_Classes", 8)) {
		unsigned int ourlen = lstrlenW(L"HKEY_CURRENT_USER\\Software\\Classes");
		unsigned int existlen = g_hkcu.len + 8;
		memmove(keybuf->KeyName + ourlen, keybuf->KeyName + existlen, keybuf->KeyNameLength + (1 * sizeof(WCHAR)) - (existlen * sizeof(WCHAR)));
		memcpy(keybuf->KeyName, L"HKEY_CURRENT_USER\\Software\\Classes", ourlen * sizeof(WCHAR));
		keybuf->KeyNameLength -= (existlen - ourlen) * sizeof(WCHAR);
	}
	else if (!wcsnicmp(keybuf->KeyName, L"\\REGISTRY\\MACHINE", 17) && (keybuf->KeyName[17] == L'\\' || keybuf->KeyName[17] == L'\0')) {
		unsigned int ourlen = 18;
		memmove(keybuf->KeyName + ourlen, keybuf->KeyName + 17, keybuf->KeyNameLength + (1 * sizeof(WCHAR)) - (17 * sizeof(WCHAR)));
		memcpy(keybuf->KeyName, L"HKEY_LOCAL_MACHINE", ourlen * sizeof(WCHAR));
		keybuf->KeyNameLength += (ourlen - 17) * sizeof(WCHAR);
	}
	else if (!wcsnicmp(keybuf->KeyName, L"\\REGISTRY\\USER", 14) && (keybuf->KeyName[14] == L'\\' || keybuf->KeyName[14] == L'\0')) {
		unsigned int ourlen = 10;
		memmove(keybuf->KeyName + ourlen, keybuf->KeyName + 14, keybuf->KeyNameLength + (1 * sizeof(WCHAR)) - (14 * sizeof(WCHAR)));
		memcpy(keybuf->KeyName, L"HKEY_USERS", ourlen * sizeof(WCHAR));
		keybuf->KeyNameLength -= (14 - ourlen) * sizeof(WCHAR);
	}

	goto out;

error:
	keybuf->KeyName[0] = 0;
	keybuf->KeyNameLength = 0;
out:
	set_lasterrors(&lasterror);

	return keybuf->KeyName;
}

static PSID GetSID(void)
{
	HANDLE token;
	DWORD retlen;
	PTOKEN_USER userinfo = NULL;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_QUERY_SOURCE, &token))
		return NULL;
	if (GetTokenInformation(token, TokenUser, 0, 0, &retlen) || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		CloseHandle(token);
		return NULL;
	}
	userinfo = malloc(retlen);
	if (userinfo) {
		if (!GetTokenInformation(token, TokenUser, userinfo, retlen, &retlen)) {
			free(userinfo);
			CloseHandle(token);
			return NULL;
		}
		CloseHandle(token);
		return userinfo->User.Sid;
	}
	CloseHandle(token);
	return NULL;
}

void hkcu_init(void)
{
	PSID sid = GetSID();
	LPWSTR sidstr;

	ConvertSidToStringSidW(sid, &sidstr);

	g_hkcu.len = lstrlenW(sidstr) + lstrlenW(L"\\REGISTRY\\USER\\");
	g_hkcu.hkcu_string = malloc((g_hkcu.len + 1) * sizeof(wchar_t));
	wcscpy(g_hkcu.hkcu_string, L"\\REGISTRY\\USER\\");
	wcscat(g_hkcu.hkcu_string, sidstr);
	LocalFree(sidstr);
}

extern int process_shutting_down;

int is_shutting_down()
{
	lasterror_t lasterror;
	int ret = 0;
	HANDLE mutex_handle;

	if (process_shutting_down)
		return 1;

	get_lasterrors(&lasterror);

	mutex_handle = OpenMutex(SYNCHRONIZE, FALSE, g_config.shutdown_mutex);
	if (mutex_handle != NULL) {
		log_flush();
		CloseHandle(mutex_handle);
		ret = 1;
	}

	set_lasterrors(&lasterror);

	return ret;
}

static char *g_specialnames_a[27];
static char *g_targetnames_a[27];

static wchar_t *g_specialnames_w[27];
static wchar_t *g_targetnames_w[27];
static unsigned int g_num_specialnames;

wchar_t *get_matching_unicode_specialname(const wchar_t *path, unsigned int *matchlen)
{
	unsigned int i;
	for (i = 0; i < g_num_specialnames; i++) {
		if (!wcsnicmp(path, g_targetnames_w[i], wcslen(g_targetnames_w[i]))) {
			*matchlen = lstrlenW(g_targetnames_w[i]);
			return g_specialnames_w[i];
		}
	}
	return NULL;
}

void specialname_map_init(void)
{
	char letter[3];
	char buf[MAX_PATH];
	char c;
	unsigned int idx = 0;
	unsigned int i, x;
	size_t len;
	letter[1] = ':';
	letter[2] = '\0';
	for (c = 'A'; c <= 'Z'; c++) {
		letter[0] = c;
		if (QueryDosDeviceA(letter, buf, MAX_PATH)) {
			g_specialnames_a[idx] = strdup(letter);
			g_targetnames_a[idx] = strdup(buf);
			idx++;
		}
	}

	if (!GetWindowsDirectoryA(buf, MAX_PATH)) {
		DebugOutput("specialname_map_init: Unable to query Windows directory");
		return;
	}

	g_targetnames_a[idx] = strdup("\\systemroot");
	g_specialnames_a[idx] = strdup(buf);
	idx++;

	len = strlen(buf) + strlen("\\system32");
	system32dir_a = calloc(1, len + 1);
	system32dir_w = calloc(1, (len + 1) * sizeof(wchar_t));
	strcpy(system32dir_a, buf);
	strcat(system32dir_a, "\\system32");
	for (x = 0; x < len - strlen("\\system32"); x++)
		system32dir_w[x] = (wchar_t)buf[x];
	wcscat(system32dir_w, L"\\system32");
	system32dir_len = (unsigned int)len;

	len = strlen(buf) + strlen("\\sysnative");
	sysnativedir_a = calloc(1, len + 1);
	sysnativedir_w = calloc(1, (len + 1) * sizeof(wchar_t));
	strcpy(sysnativedir_a, buf);
	strcat(sysnativedir_a, "\\sysnative");
	for (x = 0; x < len - strlen("\\sysnative"); x++)
		sysnativedir_w[x] = (wchar_t)buf[x];
	wcscat(sysnativedir_w, L"\\sysnative");
	sysnativedir_len = (unsigned int)len;

	for (i = 0; i < idx; i++) {
		len = strlen(g_specialnames_a[i]) + 1;
		g_specialnames_w[i] = (wchar_t *)malloc(len * sizeof(wchar_t));
		for (x = 0; x < len; x++)
			g_specialnames_w[i][x] = (wchar_t)g_specialnames_a[i][x];
		len = strlen(g_targetnames_a[i]) + 1;
		g_targetnames_w[i] = (wchar_t *)malloc(len * sizeof(wchar_t));
		for (x = 0; x < len; x++)
			g_targetnames_w[i][x] = (wchar_t)g_targetnames_a[i][x];
	}

	g_num_specialnames = idx;

}

int is_wow64_fs_redirection_disabled(void)
{
#ifdef _WIN64
	return 1;
#else
	if (is_64bit_os) {
		__try {
			PCHAR teb = (PCHAR)NtCurrentTeb();
			PCHAR ptr1 = (PCHAR)(ULONG_PTR)*(DWORD *)(teb + 0xf70);
			if (ptr1 == NULL)
				return 0;
			if (*(DWORD *)(ptr1 + 0x14c0) == 1 && *(DWORD *)(ptr1 + 0x14c4) == 0)
				return 1;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			;
		}
	}
	return 0;
#endif
}

DWORD get_pid_by_tid(DWORD tid)
{
	DWORD ret = 0;
	THREAD_BASIC_INFORMATION threadinfo;
	ULONG retlen;
	NTSTATUS status;
	HANDLE th = NULL;
	lasterror_t lasterrors;

	get_lasterrors(&lasterrors);

	th = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
	if (th == NULL)
		goto out;

	status = pNtQueryInformationThread(th, ThreadBasicInformation, &threadinfo, sizeof(threadinfo), &retlen);
	if (!NT_SUCCESS(status))
		goto out;

	ret = (DWORD)(ULONG_PTR)threadinfo.ClientId.UniqueProcess;

out:
	if (th)
		CloseHandle(th);

	set_lasterrors(&lasterrors);

	return ret;
}

BOOLEAN is_suspended(DWORD pid, DWORD tid)
{
	ULONG length;
	PSYSTEM_PROCESS_INFORMATION pspi = NULL, proc;
	ULONG requestedlen = 16384;
	lasterror_t lasterror;
	BOOLEAN ret = FALSE;

	get_lasterrors(&lasterror);

	pspi = malloc(requestedlen);
	if (pspi == NULL)
		goto out;

	while (pNtQuerySystemInformation(SystemProcessInformation, pspi, requestedlen, &length) == STATUS_INFO_LENGTH_MISMATCH) {
		free(pspi);
		requestedlen <<= 1;
		pspi = malloc(requestedlen);
		if (pspi == NULL)
			goto out;
	}
	// now we have a valid list of process information
	proc = pspi;
	while (1) {
		ULONG i;

		if ((DWORD)(ULONG_PTR)proc->UniqueProcessId != pid)
			goto next;
		for (i = 0; i < proc->NumberOfThreads; i++) {
			PSYSTEM_THREAD thread = &proc->Threads[i];
			if (tid && (DWORD)(ULONG_PTR)thread->ClientId.UniqueThread != tid)
				continue;
			if (thread->WaitReason != Suspended)
				goto out;
		}
		break;
next:
		if (!proc->NextEntryOffset)
			break;
		proc = (PSYSTEM_PROCESS_INFORMATION)((PCHAR)proc + proc->NextEntryOffset);
	}
	ret = TRUE;
out:
	if (pspi)
		free(pspi);

	set_lasterrors(&lasterror);

	return ret;
}

static PUCHAR get_rel_target(PUCHAR buf)
{
	return buf + 5 + *(int *)&buf[1];
}

static PUCHAR find_first_caller_of_target(PUCHAR start, PUCHAR end, PUCHAR target)
{
	PUCHAR p;

	for (p = start; p < end - 5; p++) {
		if (p[0] == 0xe8 && get_rel_target(p) == target)
			return p;
	}
	return NULL;
}

static PUCHAR find_first_imm_push_of_target(PUCHAR start, PUCHAR end, PUCHAR target)
{
	PUCHAR p;

	for (p = start; p < end - 5; p++) {
		if (p[0] == 0x68 && *(DWORD *)&p[1] == (DWORD)(ULONG_PTR)target)
			return p;
	}
	return NULL;
}

static PUCHAR find_first_lea_of_target(PUCHAR start, PUCHAR end, PUCHAR target)
{
	PUCHAR p;

	for (p = start; p < end - 7; p++) {
		if (p[0] == 0x48 && p[1] == 0x8d && get_rel_target(&p[2]) == target)
			return p;
	}
	return NULL;
}

static PUCHAR find_first_mov_reg_of_target(PUCHAR start, PUCHAR end, PUCHAR target)
{
	PUCHAR p;

	for (p = start; p < end - 5; p++) {
		if (((p[0] & 0xf8) == 0xb8) && *(DWORD *)&p[1] == (DWORD)(ULONG_PTR)target)
			return p;
	}
	return NULL;

}

static PUCHAR find_string_in_bounds(PUCHAR start, PUCHAR end, PUCHAR str, DWORD len)
{
	PUCHAR p;

	for (p = start; p < end - len; p++)
		if (!memcmp(p, str, len))
			return p;
	return NULL;
}

static PUCHAR find_next_relative_call(PUCHAR start, PUCHAR end, PUCHAR target)
{
	PUCHAR p;

	for (p = target; p < end - 5; p++) {
		if (p[0] == 0xe8) {
			PUCHAR resolv = get_rel_target(p);
			if (resolv >= start && resolv < end)
				return p;
		}
	}
	return NULL;
}

static PUCHAR find_function_prologue(PUCHAR start, PUCHAR end, PUCHAR target)
{
	PUCHAR p;
#ifdef _WIN64
	for (p = target - 5; p >(target - 0x1000) && p >= start; p--)
		if (!memcmp(p, "\x90\x90\x90\x90\x90", 5))
			return p + 6;
#else
	for (p = target - 5; p > (target - 0x1000) && p >= start; p--)
		if (!memcmp(p, "\x8b\xff\x55\x8b\xec", 5))
			return p;
#endif
	return NULL;
}

static BOOL get_section_bounds(HMODULE mod, const char * sectionname, PUCHAR *start, PUCHAR *end)
{
	PUCHAR buf = (PUCHAR)mod;
	PIMAGE_DOS_HEADER doshdr;
	PIMAGE_NT_HEADERS nthdr;
	PIMAGE_SECTION_HEADER sechdr;
	unsigned int numsecs, i;

	doshdr = (PIMAGE_DOS_HEADER)buf;
	nthdr = (PIMAGE_NT_HEADERS)(buf + doshdr->e_lfanew);
	sechdr = (PIMAGE_SECTION_HEADER)((PUCHAR)&nthdr->OptionalHeader + nthdr->FileHeader.SizeOfOptionalHeader);
	numsecs = nthdr->FileHeader.NumberOfSections;

	for (i = 0; i < numsecs; i++) {
		if (memcmp(sechdr[i].Name, sectionname, strlen(sectionname)))
			continue;
		*start = buf + sechdr[i].VirtualAddress;
		*end = *start + sechdr[i].Misc.VirtualSize;
		return TRUE;
	}
	return FALSE;
}

ULONG_PTR get_connectex_addr(HMODULE mod)
{
	PUCHAR start, end;
	PUCHAR p;

	if (!get_section_bounds(mod, ".data", &start, &end))
		return 0;
	p = find_string_in_bounds(start, end, (PUCHAR)"\xb9\x07\xa2\x25\xf3\xdd\x60\x46\x8e\xe9\x76\xe5\x8c\x74\x06\x3e", 16);
	if (p == NULL)
		return 0;
	return *(ULONG_PTR *)(p + 16);
}

ULONG_PTR get_jseval_addr(HMODULE mod)
{
	PUCHAR start, end;
	PUCHAR p;

	if (!get_section_bounds(mod, ".text", &start, &end))
		return 0;
	p = find_string_in_bounds(start, end, (PUCHAR)L"eval code", 20);
	if (p == NULL)
		return 0;
#ifdef _WIN64
	p = find_first_lea_of_target(start, end, p);
#else
	p = find_first_imm_push_of_target(start, end, p);
#endif
	if (p == NULL)
		return 0;
	p = find_function_prologue(start, end, p);
	return (ULONG_PTR)p;
}

ULONG_PTR get_olescript_compile_addr(HMODULE mod)
{
	PUCHAR start, end;
	PUCHAR p;

	if (!get_section_bounds(mod, ".text", &start, &end))
		return 0;
	p = find_string_in_bounds(start, end, (PUCHAR)L"eval code", 20);
	if (p == NULL)
		return 0;
#ifdef _WIN64
	p = find_first_lea_of_target(start, end, p);
#else
	p = find_first_imm_push_of_target(start, end, p);
#endif
	if (p == NULL)
		return 0;
	p = find_next_relative_call(start, end, p);
	if (p == NULL)
		return 0;
	p = get_rel_target(p);
	return (ULONG_PTR)p;
}

PCHAR get_exe_basename(PCHAR ModulePath)
{
	PCHAR end, start;
	end = strrchr(ModulePath, '.');
	start = strrchr(ModulePath, '\\');
	if (start && end && !stricmp(end, ".exe"))
		return start + 1;
	return NULL;
}

PWCHAR get_dll_basename(PWCHAR ModulePath)
{
	PWCHAR dllname, end, start, start2;
	end = wcsrchr(ModulePath, L'.');
	start = wcsrchr(ModulePath, L'\\');
	start2 = wcsrchr(ModulePath, L'/');
	if (end && !wcsicmp(end, L".dll"))
		*end = L'\0';
	if (start2 && start2 > start)
		dllname = start2 + 1;
	else if (start && start > start2)
		dllname = start + 1;
	else
		dllname = ModulePath;
	return dllname;
}

ULONG_PTR get_olescript_parsescripttext_addr(HMODULE mod)
{
	PUCHAR start, end;
	PUCHAR p;
	PUCHAR scriptblockaddr;

	if (!get_section_bounds(mod, ".text", &start, &end))
		return 0;
	scriptblockaddr = find_string_in_bounds(start, end, (PUCHAR)L"script block", 26);
	if (scriptblockaddr == NULL)
		return 0;
#ifdef _WIN64
	p = find_first_lea_of_target(start, end, scriptblockaddr);
#else
	p = find_first_imm_push_of_target(start, end, scriptblockaddr);
	if (p == NULL)
		p = find_first_mov_reg_of_target(start, end, scriptblockaddr);
#endif
	if (p == NULL)
		return 0;
	p = find_function_prologue(start, end, p);
	if (p == NULL)
		return 0;
	p = find_first_caller_of_target(start, end, p);
	if (p == NULL)
		return 0;
	p = find_function_prologue(start, end, p);
	return (ULONG_PTR)p;
}

ULONG_PTR get_cdocument_write_addr(HMODULE mod)
{
	PUCHAR start, end;
	PUCHAR p;
	PUCHAR newline;

	if (!get_section_bounds(mod, ".text", &start, &end))
		return 0;
	newline = find_string_in_bounds(start, end, (PUCHAR)L"\r\n", 6);
	if (newline == NULL)
		return 0;

#ifdef _WIN64
	for (p = start; p < end - 10; p++) {
		if (p[0] == 0x48 && p[1] == 0x8d && p[2] == 0x15 && (get_rel_target(&p[2]) == newline) && p[7] == 0xe8) {
			PUCHAR x;
			PUCHAR firstfunc = NULL, secondfunc = NULL;
			PUCHAR writelnstart = find_function_prologue(start, end, p);
			if (writelnstart == NULL)
				goto next_iter;
			// find function with 3 calls, the first and third being to the same function
			for (x = writelnstart; x < p; x++) {
				if (x[0] == 0xe8) {
					PUCHAR target = get_rel_target(x);
					if (target >= start && target < end) {
						if (firstfunc == NULL)
							firstfunc = target;
						else if (secondfunc == NULL)
							secondfunc = target;
						else if (target != firstfunc)
							goto next_iter;
					}
				}
			}
			if (firstfunc && secondfunc)
				return (ULONG_PTR)secondfunc;
		}
next_iter:
		;
	}
#else
	// got the newline, now find a push of the address of it followed immediately by a relative call within short distance of a retn 8
	// this will give us CDocument::writeln
	for (p = start; p < end - 10; p++) {
		if (p[0] == 0x68 && *(DWORD *)&p[1] == (DWORD)newline && p[5] == 0xe8) {
			PUCHAR x;
			for (x = p + 10; x < p + 0x80; x++) {
				if (!memcmp(x, "\xc2\x08\x00", 3)) {
					PUCHAR y;
					// found the retn 8
					// now scan back to find a call pointing into .text preceded immediately by some form of a push (register or indirect through ebp plus offset)
					for (y = p; y > p - 0x80; y--) {
						if (y[0] == 0xe8) {
							PUCHAR target = get_rel_target(y);
							if (target > start && target < end) {
								// if we find it, the target of the call is CDocument::write
								if (*(y - 3) == 0xff && *(y - 2) == 0x75 && *(y - 1) < 0x20)
									return (ULONG_PTR)target;
								else if ((*(y - 1) & 0xf8) == 0x50)
									return (ULONG_PTR)target;
							}
						}
					}
				}
			}
		}
	}
#endif

	return 0;
}

typedef struct _DLL_NOTIFICATION_STRUCT {
	struct _DLL_NOTIFICATION_STRUCT *Next;
	DWORD Unused;
	PLDR_DLL_NOTIFICATION_FUNCTION RegistrationFptr;
	PVOID Context;
} DLL_NOTIFICATION_STRUCT, *PDLL_NOTIFICATION_STRUCT;


void register_dll_notification_manually(PLDR_DLL_NOTIFICATION_FUNCTION notify)
{
#ifdef _WIN64
	return;
#else
	PUCHAR p, start, end;

	if (!get_section_bounds(GetModuleHandleA("ntdll"), ".text", &start, &end))
		return;
	for (p = start; p < end - 30; p++){
		if (p[0] == 0xb8 && p[5] == 0xa3 && p[10] == 0xa3 && p[15] == 0xb8 && p[20] == 0xa3 && p[25] == 0xa3) {
			DWORD addr1, addr2;
			PDLL_NOTIFICATION_STRUCT next, our;

			addr1 = *(DWORD *)&p[1];
			addr2 = *(DWORD *)&p[16];
			// throw out RtlpLeakList/RtlpBusyList
			if (addr1 == addr2 + 8)
				continue;
			next = ((PDLL_NOTIFICATION_STRUCT)(addr2))->Next;
			our = (PDLL_NOTIFICATION_STRUCT)calloc(1, sizeof(DLL_NOTIFICATION_STRUCT));
			our->Next = next;
			our->RegistrationFptr = notify;
			*(PDLL_NOTIFICATION_STRUCT *)(addr2) = our;
			return;
		}
	}
#endif
}

unsigned int address_is_in_stack(PVOID address)
{
	if (((ULONG_PTR)address < get_stack_bottom()) && ((ULONG_PTR)address > get_stack_top()))
		return 1;
	return 0;
}

PVOID get_process_image_base(HANDLE process_handle)
{
	PROCESS_BASIC_INFORMATION pbi;
	ULONG ulSize;
	HANDLE dup_handle = process_handle;
	PVOID pPEB = 0, ImageBase = 0;
	PEB Peb;
	SIZE_T dwBytesRead;
	lasterror_t lasterror;

	get_lasterrors(&lasterror);

	if (process_handle == GetCurrentProcess())
	{
		ImageBase = GetModuleHandle(NULL);
		goto out;
	}

	memset(&pbi, 0, sizeof(pbi));

	if (pNtQueryInformationProcess(process_handle, 0, &pbi, sizeof(pbi), &ulSize) >= 0 && ulSize == sizeof(pbi))
	{
		pPEB = pbi.PebBaseAddress;

		if (ReadProcessMemory(process_handle, pPEB, &Peb, sizeof(Peb), &dwBytesRead))
		{
			ImageBase = Peb.ImageBaseAddress;
		}
		else return NULL;
	}

out:
	set_lasterrors(&lasterror);

	return ImageBase;
}

ULONG_PTR ntdll_base;
DWORD ntdll_size;

BOOLEAN is_address_in_ntdll(ULONG_PTR address)
{
	if (!ntdll_base)
		return FALSE;

	if (!ntdll_size)
		ntdll_size = get_image_size(ntdll_base);

	if (address >= ntdll_base && address < (ntdll_base + ntdll_size))
		return TRUE;

	return FALSE;
}

ULONG_PTR win32u_base;
DWORD win32u_size;

BOOLEAN is_address_in_win32u(ULONG_PTR address)
{
	if (!win32u_base)
		return FALSE;

	if (!win32u_size)
		win32u_size = get_image_size(win32u_base);

	if (address >= win32u_base && address < (win32u_base + win32u_size))
		return TRUE;

	return FALSE;
}

BOOLEAN prevent_module_unloading(PVOID BaseAddress) {
	// Some code may attempt to unmap a previously mapped view of, say, ntdll
	// e.g. Xenos dll injector (https://github.com/DarthTon/Xenos - def1c2f12307d598e42506a55f1a06ed5e652af0d260aac9572469429f10d04d)
	wchar_t *whitelist[] = {
		L"ntdll.dll",
		NULL
	};

	// check against the whitelist
	for (int i = 0; whitelist[i]; i++) {
		// is this a whitelisted module?
		HMODULE address = GetModuleHandleW(whitelist[i]);
		if (address == BaseAddress)
			return FALSE;
	}

	return TRUE;
}

void prevent_module_reloading(PVOID *BaseAddress) {
	// prevent hook evasion via mapping system libraries (e.g. ntdll.dll) from disk
	// this still won't stop reading the file using NtReadFile and mapping it manually
	wchar_t *whitelist[] = {
		L"C:\\Windows\\System32\\ntdll.dll",
		L"C:\\Windows\\SysWOW64\\ntdll.dll",
		NULL
	};

	// get the file path for the mapped section
	wchar_t *filepath = malloc(MAX_PATH * sizeof(wchar_t));
	GetMappedFileNameW(GetCurrentProcess(), *BaseAddress, filepath, MAX_PATH);

	// convert device path to an actual path
	wchar_t *absolutepath = malloc(32768 * sizeof(wchar_t));
	ensure_absolute_unicode_path(absolutepath, filepath);
	free(filepath);

	// check against the whitelist
	for (int i = 0; whitelist[i]; i++) {
		if (!wcsicmp(whitelist[i], absolutepath)) {
			// is this a loaded module?
			HMODULE address = GetModuleHandleW(absolutepath);
			if (address != NULL) {
				DebugOutput("Sample attempted to remap module '%ws' at 0x%p, returning original module address instead: 0x%p", absolutepath, *BaseAddress, address);
				pNtUnmapViewOfSection(GetCurrentProcess(), *BaseAddress);
				*BaseAddress = (LPVOID)address;
			}
			break;
		}
	}

	free(absolutepath);
}
