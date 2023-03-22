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

#ifdef _MSC_VER
#include <WinSock2.h>
#endif
#include <windows.h>
#include <wincrypt.h>
#include <stdint.h>

#ifndef __NTAPI_H__
#define __NTAPI_H__

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#ifndef _MSC_VER
#define __out
#define __in
#define __in_opt
#define __reserved
#define __out_opt
#define __inout
#define __inout_opt
#define _In_
#define _In_opt_
#define _Out_
#define _Out_opt_
#define _Inout_
#define _Inout_opt_
#define _Reserved_
#endif

#ifdef _MSC_VER
#define alloca _alloca
#define wcsnicmp _wcsnicmp
#define wcsicmp _wcsicmp
#define snprintf _snprintf

// Disable warning for deprecated GetVersionEx
#pragma warning( disable : 4996)
#endif

#define Suspended 5
#define OptionShutdownSystem 6
// NTSTATUS
#define STATUS_INFO_LENGTH_MISMATCH  0xc0000004
#define STATUS_CONFLICTING_ADDRESSES 0xc0000018
#define STATUS_OBJECT_NAME_NOT_FOUND 0xc0000034
#define STATUS_INVALID_DEVICE_REQUEST 0xc0000010
#define STATUS_ACCESS_DENIED ((NTSTATUS) 0xc0000022)
#define STATUS_IMAGE_NOT_AT_BASE ((NTSTATUS) 0x40000003)

typedef struct _STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR  Buffer;
} ANSI_STRING, *PANSI_STRING;

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID	Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG		   Length;
	HANDLE		  RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG		   Attributes;
	PVOID		   SecurityDescriptor;
	PVOID		   SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

// for now..
typedef void *PIO_APC_ROUTINE;

#ifndef _MSC_VER
#ifndef ARRAYSIZE
#define ARRAYSIZE(a) (sizeof(a) / sizeof(*(a)))
#endif

typedef void *HINTERNET;

typedef struct addrinfo {
  int			 ai_flags;
  int			 ai_family;
  int			 ai_socktype;
  int			 ai_protocol;
  size_t		  ai_addrlen;
  char			*ai_canonname;
  struct sockaddr  *ai_addr;
  struct addrinfo  *ai_next;
} ADDRINFOA, *PADDRINFOA;

typedef struct addrinfoW {
  int			  ai_flags;
  int			  ai_family;
  int			  ai_socktype;
  int			  ai_protocol;
  size_t		   ai_addrlen;
  PWSTR			ai_canonname;
  struct sockaddr  *ai_addr;
  struct addrinfoW  *ai_next;
} ADDRINFOW, *PADDRINFOW;
#endif

typedef enum _KEY_INFORMATION_CLASS {
  KeyBasicInformation			= 0,
  KeyNodeInformation			 = 1,
  KeyFullInformation			 = 2,
  KeyNameInformation			 = 3,
  KeyCachedInformation		   = 4,
  KeyFlagsInformation			= 5,
  KeyVirtualizationInformation   = 6,
  KeyHandleTagsInformation	   = 7,
  MaxKeyInfoClass				= 8
} KEY_INFORMATION_CLASS;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
  KeyValueBasicInformation			= 0,
  KeyValueFullInformation			 = 1,
  KeyValuePartialInformation		  = 2,
  KeyValueFullInformationAlign64	  = 3,
  KeyValuePartialInformationAlign64   = 4,
  MaxKeyValueInfoClass				= 5
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _KEY_VALUE_BASIC_INFORMATION {
  ULONG TitleIndex;
  ULONG Type;
  ULONG NameLength;
  WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_FULL_INFORMATION {
  ULONG TitleIndex;
  ULONG Type;
  ULONG DataOffset;
  ULONG DataLength;
  ULONG NameLength;
  WCHAR Name[1];
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
  ULONG TitleIndex;
  ULONG Type;
  ULONG DataLength;
  UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

typedef struct _KEY_VALUE_ENTRY {
	PUNICODE_STRING	ValueName;
	ULONG		DataLength;
	ULONG		DataOffset;
	ULONG		Type;
} KEY_VALUE_ENTRY, *PKEY_VALUE_ENTRY;

typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PVOID PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	ULONG_PTR ParentProcessId;
} PROCESS_BASIC_INFORMATION;

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
	ULONG Version;
	ULONG Reserved;
	PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, *PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;
typedef PVOID HDEVINFO; 
typedef struct _SP_DEVINFO_DATA {
	DWORD	 cbSize;
	GUID	  ClassGuid;
	DWORD	 DevInst;
	ULONG_PTR Reserved;
} SP_DEVINFO_DATA, *PSP_DEVINFO_DATA;

typedef struct _CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef ULONG_PTR KAFFINITY;
typedef LONG KPRIORITY;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	KAFFINITY AffinityMask;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _SYSTEM_THREAD {
	LARGE_INTEGER		   KernelTime;
	LARGE_INTEGER		   UserTime;
	LARGE_INTEGER		   CreateTime;
	ULONG				   WaitTime;
	PVOID				   StartAddress;
	CLIENT_ID			   ClientId;
	KPRIORITY			   Priority;
	LONG					BasePriority;
	ULONG				   ContextSwitchCount;
	ULONG				   State;
	ULONG				   WaitReason;
} SYSTEM_THREAD, *PSYSTEM_THREAD;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG				   NextEntryOffset;
	ULONG				   NumberOfThreads;
	LARGE_INTEGER		   Reserved[3];
	LARGE_INTEGER		   CreateTime;
	LARGE_INTEGER		   UserTime;
	LARGE_INTEGER		   KernelTime;
	UNICODE_STRING		  ImageName;
	KPRIORITY			   BasePriority;
	HANDLE					UniqueProcessId;
	HANDLE					InheritedFromProcessId;
	ULONG					HandleCount;
	BYTE					Reserved4[4];
	PVOID					Reserved5[11];
	SIZE_T					PeakPagefileUsage;
	SIZE_T					PrivatePageCount;
	LARGE_INTEGER			Reserved6[6];
	SYSTEM_THREAD			Threads[0];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION {
	LARGE_INTEGER IdleTime;
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER DpcTime;
	LARGE_INTEGER InterruptTime;
	ULONG InterruptCount;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, *PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

typedef struct _INITIAL_TEB {
  PVOID StackBase;
  PVOID StackLimit;
  PVOID StackCommit;
  PVOID StackCommitMax;
  PVOID StackReserved;
} INITIAL_TEB, *PINITIAL_TEB;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_BASIC_INFORMATION {
	ULONG 	Reserved;
	ULONG 	TimerResolution;
	ULONG 	PageSize;
	ULONG 	NumberOfPhysicalPages;
	ULONG 	LowestPhysicalPageNumber;
	ULONG 	HighestPhysicalPageNumber;
	ULONG 	AllocationGranularity;
	ULONG_PTR 	MinimumUserModeAddress;
	ULONG_PTR 	MaximumUserModeAddress;
	ULONG_PTR 	ActiveProcessorsAffinityMask;
	CCHAR 	NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

typedef enum _FILE_INFORMATION_CLASS {
  FileDirectoryInformation = 1,
  FileFullDirectoryInformation,
  FileBothDirectoryInformation,
  FileBasicInformation,
  FileStandardInformation,
  FileInternalInformation,
  FileEaInformation,
  FileAccessInformation,
  FileNameInformation,
  FileRenameInformation,
  FileLinkInformation,
  FileNamesInformation,
  FileDispositionInformation,
  FilePositionInformation,
  FileFullEaInformation,
  FileModeInformation,
  FileAlignmentInformation,
  FileAllInformation,
  FileAllocationInformation,
  FileEndOfFileInformation,
  FileAlternateNameInformation,
  FileStreamInformation,
  FilePipeInformation,
  FilePipeLocalInformation,
  FilePipeRemoteInformation,
  FileMailslotQueryInformation,
  FileMailslotSetInformation,
  FileCompressionInformation,
  FileObjectIdInformation,
  FileCompletionInformation,
  FileMoveClusterInformation,
  FileQuotaInformation,
  FileReparsePointInformation,
  FileNetworkOpenInformation,
  FileAttributeTagInformation,
  FileTrackingInformation,
  FileIdBothDirectoryInformation,
  FileIdFullDirectoryInformation,
  FileValidDataLengthInformation,
  FileShortNameInformation,
  FileIoCompletionNotificationInformation,
  FileIoStatusBlockRangeInformation,
  FileIoPriorityHintInformation,
  FileSfioReserveInformation,
  FileSfioVolumeInformation,
  FileHardLinkInformation,
  FileProcessIdsUsingFileInformation,
  FileNormalizedNameInformation,
  FileNetworkPhysicalNameInformation,
  FileIdGlobalTxDirectoryInformation,
  FileIsRemoteDeviceInformation,
  FileAttributeCacheInformation,
  FileNumaNodeInformation,
  FileStandardLinkInformation,
  FileRemoteProtocolInformation,
  FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef struct _FILE_BASIC_INFORMATION {
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	ULONG FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _FILE_RENAME_INFORMATION {
  BOOLEAN ReplaceIfExists;
  HANDLE  RootDirectory;
  ULONG   FileNameLength;
  WCHAR   FileName[1];
} FILE_RENAME_INFORMATION, *PFILE_RENAME_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION {
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG		 FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG				   MaximumLength;
	ULONG				   Length;
	ULONG				   Flags;
	ULONG				   DebugFlags;
	PVOID				   ConsoleHandle;
	ULONG				   ConsoleFlags;
	HANDLE				  StdInputHandle;
	HANDLE				  StdOutputHandle;
	HANDLE				  StdErrorHandle;
	UNICODE_STRING		  CurrentDirectoryPath;
	HANDLE				  CurrentDirectoryHandle;
	UNICODE_STRING		  DllPath;
	UNICODE_STRING		  ImagePathName;
	UNICODE_STRING		  CommandLine;
	PVOID				   Environment;
	ULONG				   StartingPositionLeft;
	ULONG				   StartingPositionTop;
	ULONG				   Width;
	ULONG				   Height;
	ULONG				   CharWidth;
	ULONG				   CharHeight;
	ULONG				   ConsoleTextAttributes;
	ULONG				   WindowFlags;
	ULONG				   ShowWindowFlags;
	UNICODE_STRING		  WindowTitle;
	UNICODE_STRING		  DesktopName;
	UNICODE_STRING		  ShellInfo;
	UNICODE_STRING		  RuntimeData;
	RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef void *PPS_CREATE_INFO, *PPS_ATTRIBUTE_LIST;

typedef struct _PROC_THREAD_ATTRIBUTE_ENTRY
{
	ULONG_PTR Attribute;
	SIZE_T cbSize;
	PVOID lpValue;
} PROC_THREAD_ATTRIBUTE_ENTRY, *LPPROC_THREAD_ATTRIBUTE_ENTRY;

typedef struct _PROC_THREAD_ATTRIBUTE_LIST
{
	DWORD dwFlags;
	ULONG Size;
	ULONG Count;
	ULONG Reserved;
	PULONG Unknown;
	PROC_THREAD_ATTRIBUTE_ENTRY Entries[1];
} PROC_THREAD_ATTRIBUTE_LIST, *LPPROC_THREAD_ATTRIBUTE_LIST;

typedef void *PVOID, **PPVOID;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID BaseAddress;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

#ifdef _WIN64
typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN Spare;
	HANDLE  Mutant;
	PVOID   ImageBaseAddress;
	PPEB_LDR_DATA LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID   SubSystemData;
	PVOID   ProcessHeap;
	PVOID   FastPebLock;
	void   *FastPebLockRoutine;
	void   *FastPebUnlockRoutine;
	ULONG   EnvironmentUpdateCount;
	PPVOID  KernelCallbackTable;
	PVOID   EventLogSection;
	PVOID   EventLog;
	void   *FreeList;
	ULONG   TlsExpansionCounter;
	PVOID   TlsBitmap;
	ULONG   TlsBitmapBits[0x2];
	PVOID   ReadOnlySharedMemoryBase;
	PVOID   ReadOnlySharedMemoryHeap;
	PPVOID  ReadOnlyStaticServerData;
	PVOID   AnsiCodePageData;
	PVOID   OemCodePageData;
	PVOID   UnicodeCaseTableData;
	ULONG   NumberOfProcessors;
	ULONG   NtGlobalFlag;
	BYTE	Spare2[0x4];
	LARGE_INTEGER CriticalSectionTimeout;
	ULONG   HeapSegmentReserve;
	ULONG   HeapSegmentCommit;
	ULONG   HeapDeCommitTotalFreeThreshold;
	ULONG   HeapDeCommitFreeBlockThreshold;
	ULONG   NumberOfHeaps;
	ULONG   MaximumNumberOfHeaps;
	PPVOID *ProcessHeaps;
	PVOID   GdiSharedHandleTable;
	PVOID   ProcessStarterHelper;
	PVOID   GdiDCAttributeList;
	RTL_CRITICAL_SECTION *LoaderLock;
	ULONG   OSMajorVersion;
	ULONG   OSMinorVersion;
	ULONG   OSBuildNumber;
	ULONG   OSPlatformId;
	ULONG   ImageSubSystem;
	ULONG   ImageSubSystemMajorVersion;
	ULONG   ImageSubSystemMinorVersion;
	ULONG   GdiHandleBuffer[0x22];
	PVOID PostProcessInitRoutine;
	BYTE Reserved4[136];
	ULONG SessionId;
} PEB;
#else
typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN Spare;
	HANDLE  Mutant;
	PVOID   ImageBaseAddress;
	PPEB_LDR_DATA LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID   SubSystemData;
	PVOID   ProcessHeap;
	PVOID   FastPebLock;
	void   *FastPebLockRoutine;
	void   *FastPebUnlockRoutine;
	ULONG   EnvironmentUpdateCount;
	PPVOID  KernelCallbackTable;
	PVOID   EventLogSection;
	PVOID   EventLog;
	void   *FreeList;
	ULONG   TlsExpansionCounter;
	PVOID   TlsBitmap;
	ULONG   TlsBitmapBits[0x2];
	PVOID   ReadOnlySharedMemoryBase;
	PVOID   ReadOnlySharedMemoryHeap;
	PPVOID  ReadOnlyStaticServerData;
	PVOID   AnsiCodePageData;
	PVOID   OemCodePageData;
	PVOID   UnicodeCaseTableData;
	ULONG   NumberOfProcessors;
	ULONG   NtGlobalFlag;
	BYTE	Spare2[0x4];
	LARGE_INTEGER CriticalSectionTimeout;
	ULONG   HeapSegmentReserve;
	ULONG   HeapSegmentCommit;
	ULONG   HeapDeCommitTotalFreeThreshold;
	ULONG   HeapDeCommitFreeBlockThreshold;
	ULONG   NumberOfHeaps;
	ULONG   MaximumNumberOfHeaps;
	PPVOID *ProcessHeaps;
	PVOID   GdiSharedHandleTable;
	PVOID   ProcessStarterHelper;
	PVOID   GdiDCAttributeList;
	RTL_CRITICAL_SECTION *LoaderLock;
	ULONG   OSMajorVersion;
	ULONG   OSMinorVersion;
	ULONG   OSBuildNumber;
	ULONG   OSPlatformId;
	ULONG   ImageSubSystem;
	ULONG   ImageSubSystemMajorVersion;
	ULONG   ImageSubSystemMinorVersion;
	ULONG   GdiHandleBuffer[0x22];
	ULONG   PostProcessInitRoutine;
	ULONG   TlsExpansionBitmap;
	BYTE	TlsExpansionBitmapBits[0x80];
	ULONG   SessionId;
} PEB, *PPEB;
#endif

typedef enum _DBG_STATE
{
	DbgIdle,
	DbgReplyPending,
	DbgCreateThreadStateChange,
	DbgCreateProcessStateChange,
	DbgExitThreadStateChange,
	DbgExitProcessStateChange,
	DbgExceptionStateChange,
	DbgBreakpointStateChange,
	DbgSingleStepStateChange,
	DbgLoadDllStateChange,
	DbgUnloadDllStateChange
} DBG_STATE, *PDBG_STATE;

typedef struct _DBGKM_EXCEPTION
{
	EXCEPTION_RECORD ExceptionRecord;
	ULONG FirstChance;
} DBGKM_EXCEPTION, *PDBGKM_EXCEPTION;

typedef struct _DBGKM_CREATE_THREAD
{
	ULONG SubSystemKey;
	PVOID StartAddress;
} DBGKM_CREATE_THREAD, *PDBGKM_CREATE_THREAD;

typedef struct _DBGKM_CREATE_PROCESS
{
	ULONG SubSystemKey;
	HANDLE FileHandle;
	PVOID BaseOfImage;
	ULONG DebugInfoFileOffset;
	ULONG DebugInfoSize;
	DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, *PDBGKM_CREATE_PROCESS;

typedef struct _DBGKM_EXIT_THREAD
{
	NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, *PDBGKM_EXIT_THREAD;

typedef struct _DBGKM_EXIT_PROCESS
{
	NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, *PDBGKM_EXIT_PROCESS;

typedef struct _DBGKM_LOAD_DLL
{
	HANDLE FileHandle;
	PVOID BaseOfDll;
	ULONG DebugInfoFileOffset;
	ULONG DebugInfoSize;
	PVOID NamePointer;
} DBGKM_LOAD_DLL, *PDBGKM_LOAD_DLL;

typedef struct _DBGKM_UNLOAD_DLL
{
	PVOID BaseAddress;
} DBGKM_UNLOAD_DLL, *PDBGKM_UNLOAD_DLL;

typedef struct _DBGUI_WAIT_STATE_CHANGE
{
	DBG_STATE NewState;
	CLIENT_ID AppClientId;
	union
	{
		struct
		{
			HANDLE HandleToThread;
			DBGKM_CREATE_THREAD NewThread;
		} CreateThread;
		struct
		{
			HANDLE HandleToProcess;
			HANDLE HandleToThread;
			DBGKM_CREATE_PROCESS NewProcess;
		} CreateProcessInfo;
		DBGKM_EXIT_THREAD ExitThread;
		DBGKM_EXIT_PROCESS ExitProcess;
		DBGKM_EXCEPTION Exception;
		DBGKM_LOAD_DLL LoadDll;
		DBGKM_UNLOAD_DLL UnloadDll;
	} StateInfo;
} DBGUI_WAIT_STATE_CHANGE, *PDBGUI_WAIT_STATE_CHANGE;

#ifndef _MSC_VER
typedef struct _STARTUPINFOEXA {
	STARTUPINFOA StartupInfo;
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
} STARTUPINFOEXA, *LPSTARTUPINFOEXA;

typedef struct _STARTUPINFOEXW {
	STARTUPINFOW StartupInfo;
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
} STARTUPINFOEXW, *LPSTARTUPINFOEXW;
#endif

#if 0
static inline unsigned int __readfsdword(unsigned int index)
{
	unsigned int ret;
	__asm__("movl %%fs:(%1), %0" : "=r" (ret) : "r" (index));
	return ret;
}

static inline void __writefsdword(unsigned int index, unsigned int value)
{
	__asm__("movl %0, %%fs:(%1)" :: "r" (value), "r" (index));
}
#endif

#ifndef HKEY_CURRENT_USER_LOCAL_SETTINGS
(( HKEY ) (ULONG_PTR)((LONG)0x80000007) )
#endif

typedef unsigned short RTL_ATOM, *PRTL_ATOM;

typedef enum _ATOM_INFORMATION_CLASS {
	AtomBasicInformation,
	AtomTableInformation
} ATOM_INFORMATION_CLASS;

typedef struct _ATOM_BASIC_INFORMATION {
	USHORT UsageCount;
	USHORT Flags;
	USHORT NameLength;
	WCHAR Name[ 1 ];
} ATOM_BASIC_INFORMATION, *PATOM_BASIC_INFORMATION;

typedef struct _ATOM_TABLE_INFORMATION {
	ULONG NumberOfAtoms;
	RTL_ATOM Atoms[ 1 ];
} ATOM_TABLE_INFORMATION, *PATOM_TABLE_INFORMATION;

typedef struct _SECTION_IMAGE_INFORMATION {
	VOID*			   TransferAddress;
	uint32_t			ZeroBits;
	uint8_t			 _PADDING0_[0x4];
	uint64_t			MaximumStackSize;
	uint64_t			CommittedStackSize;
	uint32_t			SubSystemType;
	union {
		struct {
			uint16_t	SubSystemMinorVersion;
			uint16_t	SubSystemMajorVersion;
		} _;
		uint32_t		SubSystemVersion;
	} _;
	uint32_t			GpValue;
	uint16_t			ImageCharacteristics;
	uint16_t			DllCharacteristics;
	uint16_t			Machine;
	uint8_t			 ImageContainsCode;
	union {
		uint8_t		 ImageFlags;
		struct {
			uint8_t	 ComPlusNativeReady : 1;
			uint8_t	 ComPlusILOnly : 1;
			uint8_t	 ImageDynamicallyRelocated : 1;
			uint8_t	 ImageMappedFlat : 1;
			uint8_t	 Reserved : 4;
		} _;
	} __;
	uint32_t			LoaderFlags;
	uint32_t			ImageFileSize;
	uint32_t			CheckSum;
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

typedef struct _RTL_USER_PROCESS_INFORMATION {
	ULONG Size;
	HANDLE ProcessHandle;
	HANDLE ThreadHandle;
	CLIENT_ID ClientId;
	SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

#define FILE_NAME_INFORMATION_REQUIRED_SIZE \
	sizeof(FILE_NAME_INFORMATION) + sizeof(wchar_t) * 32768

typedef struct _FILE_NAME_INFORMATION {
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;

typedef struct _KEY_NAME_INFORMATION {
	ULONG KeyNameLength;
	WCHAR KeyName[1];
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION {
	UNICODE_STRING Name;
	WCHAR NameBuffer[1];
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

#define OBJECT_NAME_INFORMATION_REQUIRED_SIZE \
	sizeof(OBJECT_NAME_INFORMATION) + sizeof(wchar_t) * 32768

typedef enum {
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllInformation,
	ObjectDataInformation
} OBJECT_INFORMATION_CLASS;

typedef enum  {
	FileFsVolumeInformation	   = 1,
	FileFsLabelInformation		= 2,
	FileFsSizeInformation		 = 3,
	FileFsDeviceInformation	   = 4,
	FileFsAttributeInformation	= 5,
	FileFsControlInformation	  = 6,
	FileFsFullSizeInformation	 = 7,
	FileFsObjectIdInformation	 = 8,
	FileFsDriverPathInformation   = 9,
	FileFsVolumeFlagsInformation  = 10,
	FileFsSectorSizeInformation   = 11
} FS_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,		  // Note: this is kernel mode only
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	ProcessDeviceMap,
	ProcessSessionInformation,
	ProcessForegroundInformation,
	ProcessWow64Information,
	ProcessImageFileName,
	ProcessLUIDDeviceMapsEnabled,
	ProcessBreakOnTermination,
	ProcessDebugObjectHandle,
	ProcessDebugFlags,
	ProcessHandleTracing,
	ProcessIoPriority,
	ProcessExecuteFlags,
	ProcessTlsInformation,
	ProcessCookie,
	ProcessImageInformation,
	ProcessCycleTime,
	ProcessPagePriority,
	ProcessInstrumentationCallback,
	ProcessThreadStackAllocation,
	ProcessWorkingSetWatchEx,
	ProcessImageFileNameWin32,
	ProcessImageFileMapping,
	ProcessAffinityUpdateMode,
	ProcessMemoryAllocationMode,
	ProcessGroupInformation,
	ProcessTokenVirtualizationEnabled,
	ProcessConsoleHostProcess,
	ProcessWindowInformation,
	ProcessHandleInformation,
	ProcessMitigationPolicy,
	ProcessDynamicFunctionTableInformation,
	ProcessHandleCheckingMode,
	ProcessKeepAliveCount,
	ProcessRevokeFileHandles,
	ProcessWorkingSetControl,
	MaxProcessInfoClass			 // MaxProcessInfoClass should always be the last enum
} PROCESSINFOCLASS;

typedef enum _THREADINFOCLASS {
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair_Reusable,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,   // Obsolete
	ThreadIsIoPending,
	ThreadHideFromDebugger,
	ThreadBreakOnTermination,
	ThreadSwitchLegacyState,
	ThreadIsTerminated,
	ThreadLastSystemCall,
	ThreadIoPriority,
	ThreadCycleTime,
	ThreadPagePriority,
	ThreadActualBasePriority,
	ThreadTebInformation,
	ThreadCSwitchMon,		  // Obsolete
	ThreadCSwitchPmu,
	ThreadWow64Context,
	ThreadGroupInformation,
	ThreadUmsInformation,	  // UMS
	ThreadCounterProfiling,
	ThreadIdealProcessorEx,
	ThreadCpuAccountingInformation,
	MaxThreadInfoClass
} THREADINFOCLASS;

typedef struct _FILE_FS_VOLUME_INFORMATION {
	LARGE_INTEGER VolumeCreationTime;
	ULONG		 VolumeSerialNumber;
	ULONG		 VolumeLabelLength;
	BOOLEAN	   SupportsObjects;
	WCHAR		 VolumeLabel[1];
} FILE_FS_VOLUME_INFORMATION, *PFILE_FS_VOLUME_INFORMATION;

typedef struct _TIMER_SET_COALESCABLE_TIMER_INFO {
	LARGE_INTEGER DueTime;
	PVOID TimerApcRoutine;
	PVOID TimerContext;
	PVOID WakeContext;
	ULONG Period;
	ULONG TolerableDelay;
	PBOOLEAN PreviousState;
} TIMER_SET_COALESCABLE_TIMER_INFO, *PTIMER_SET_COALESCABLE_TIMER_INFO;

typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

static __inline UNICODE_STRING *unistr_from_objattr(OBJECT_ATTRIBUTES *obj)
{
	return obj != NULL ? obj->ObjectName : NULL;
}

static __inline HANDLE handle_from_objattr(OBJECT_ATTRIBUTES *obj)
{
	return obj != NULL ? obj->RootDirectory : (HANDLE)NULL;
}

extern void disable_tail_call_optimization(void);

#define NtCurrentProcess() ((HANDLE)-1)
#include "alloc.h"

extern BOOL is_64bit_os;

extern DWORD raw_gettickcount(void);
extern ULONGLONG raw_gettickcount64(void);

extern OSVERSIONINFOA g_osverinfo;

#endif