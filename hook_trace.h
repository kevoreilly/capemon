#include <guiddef.h>
#include <inttypes.h>

#define EVENT_TRACE_CONTROL_QUERY           0
#define EVENT_TRACE_CONTROL_STOP            1
#define EVENT_TRACE_CONTROL_UPDATE          2
#define EVENT_TRACE_CONTROL_FLUSH           3
#define EVENT_TRACE_CONTROL_INCREMENT_FILE  4
#define EVENT_TRACE_CONTROL_CONVERT_TO_REALTIME  5 

#define EVENT_CONTROL_CODE_DISABLE_PROVIDER 0
#define EVENT_CONTROL_CODE_ENABLE_PROVIDER  1
#define EVENT_CONTROL_CODE_CAPTURE_STATE    2

#ifndef _TRACEHANDLE_DEFINED
#define _TRACEHANDLE_DEFINED
typedef ULONG64 TRACEHANDLE, *PTRACEHANDLE;
#endif

#define PEVENT_TRACE_LOGFILE            PEVENT_TRACE_LOGFILEA

typedef struct _EVENT_TRACE_LOGFILEW
EVENT_TRACE_LOGFILEW, *PEVENT_TRACE_LOGFILEW;

typedef struct _EVENT_TRACE_LOGFILEA
EVENT_TRACE_LOGFILEA, *PEVENT_TRACE_LOGFILEA;

typedef ULONG(WINAPI * PEVENT_TRACE_BUFFER_CALLBACKW)
(PEVENT_TRACE_LOGFILEW Logfile);

typedef ULONG(WINAPI * PEVENT_TRACE_BUFFER_CALLBACKA)
(PEVENT_TRACE_LOGFILEA Logfile);

typedef ULONGLONG REGHANDLE, *PREGHANDLE;

typedef struct _ETW_BUFFER_CONTEXT {
	union {
		struct {
			UCHAR ProcessorNumber;
			UCHAR Alignment;
		} DUMMYSTRUCTNAME;
		USHORT ProcessorIndex;
	} DUMMYUNIONNAME;
	USHORT  LoggerId;
} ETW_BUFFER_CONTEXT, *PETW_BUFFER_CONTEXT;

typedef struct _EVENT_DESCRIPTOR {

	USHORT Id;
	UCHAR Version;
	UCHAR Channel;
	UCHAR Level;
	UCHAR Opcode;
	USHORT Task;
	ULONGLONG Keyword;

} EVENT_DESCRIPTOR, *PEVENT_DESCRIPTOR;

typedef struct _EVENT_HEADER {

	USHORT              Size;                   // Event Size
	USHORT              HeaderType;             // Header Type
	USHORT              Flags;                  // Flags
	USHORT              EventProperty;          // User given event property
	ULONG               ThreadId;               // Thread Id
	ULONG               ProcessId;              // Process Id
	LARGE_INTEGER       TimeStamp;              // Event Timestamp
	GUID                ProviderId;             // Provider Id
	EVENT_DESCRIPTOR    EventDescriptor;        // Event Descriptor
	union {
		struct {
			ULONG       KernelTime;             // Kernel Mode CPU ticks
			ULONG       UserTime;               // User mode CPU ticks
		} DUMMYSTRUCTNAME;
		ULONG64         ProcessorTime;          // Processor Clock
												// for private session events
	} DUMMYUNIONNAME;
	GUID                ActivityId;             // Activity Id

} EVENT_HEADER, *PEVENT_HEADER;

typedef struct _EVENT_HEADER_EXTENDED_DATA_ITEM {

	USHORT      Reserved1;                      // Reserved for internal use
	USHORT      ExtType;                        // Extended info type
	struct {
		USHORT  Linkage : 1;       // Indicates additional extended
												// data item
		USHORT  Reserved2 : 15;
	};
	USHORT      DataSize;                       // Size of extended info data
	ULONGLONG   DataPtr;                        // Pointer to extended info data

} EVENT_HEADER_EXTENDED_DATA_ITEM, *PEVENT_HEADER_EXTENDED_DATA_ITEM;

typedef struct _EVENT_RECORD {
	EVENT_HEADER                     EventHeader;
	ETW_BUFFER_CONTEXT               BufferContext;
	USHORT                           ExtendedDataCount;
	USHORT                           UserDataLength;
	PEVENT_HEADER_EXTENDED_DATA_ITEM ExtendedData;
	PVOID                            UserData;
	PVOID                            UserContext;
} EVENT_RECORD, *PEVENT_RECORD;

typedef struct _EVENT_TRACE_HEADER {        // overlays WNODE_HEADER
	USHORT          Size;                   // Size of entire record
	union {
		USHORT      FieldTypeFlags;         // Indicates valid fields
		struct {
			UCHAR   HeaderType;             // Header type - internal use only
			UCHAR   MarkerFlags;            // Marker - internal use only
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;
	union {
		ULONG       Version;
		struct {
			UCHAR   Type;                   // event type
			UCHAR   Level;                  // trace instrumentation level
			USHORT  Version;                // version of trace record
		} Class;
	} DUMMYUNIONNAME2;
	ULONG           ThreadId;               // Thread Id
	ULONG           ProcessId;              // Process Id
	LARGE_INTEGER   TimeStamp;              // time when event happens
	union {
		GUID        Guid;                   // Guid that identifies event
		ULONGLONG   GuidPtr;                // use with WNODE_FLAG_USE_GUID_PTR
	} DUMMYUNIONNAME3;
	union {
		struct {
			ULONG   KernelTime;             // Kernel Mode CPU ticks
			ULONG   UserTime;               // User mode CPU ticks
		} DUMMYSTRUCTNAME;
		ULONG64     ProcessorTime;          // Processor Clock
		struct {
			ULONG   ClientContext;          // Reserved
			ULONG   Flags;                  // Event Flags
		} DUMMYSTRUCTNAME2;
	} DUMMYUNIONNAME4;
} EVENT_TRACE_HEADER, *PEVENT_TRACE_HEADER;

typedef struct _EVENT_TRACE {
	EVENT_TRACE_HEADER      Header;             // Event trace header
	ULONG                   InstanceId;         // Instance Id of this event
	ULONG                   ParentInstanceId;   // Parent Instance Id.
	GUID                    ParentGuid;         // Parent Guid;
	PVOID                   MofData;            // Pointer to Variable Data
	ULONG                   MofLength;          // Variable Datablock Length
	union {
		ULONG               ClientContext;
		ETW_BUFFER_CONTEXT  BufferContext;
	} DUMMYUNIONNAME;
} EVENT_TRACE, *PEVENT_TRACE;

typedef VOID(WINAPI *PEVENT_CALLBACK)(PEVENT_TRACE pEvent);

typedef VOID(WINAPI *PEVENT_RECORD_CALLBACK) (PEVENT_RECORD EventRecord);

typedef struct _TRACE_LOGFILE_HEADER {
	ULONG           BufferSize;         // Logger buffer size in Kbytes
	union {
		ULONG       Version;            // Logger version
		struct {
			UCHAR   MajorVersion;
			UCHAR   MinorVersion;
			UCHAR   SubVersion;
			UCHAR   SubMinorVersion;
		} VersionDetail;
	} DUMMYUNIONNAME;
	ULONG           ProviderVersion;    // defaults to NT version
	ULONG           NumberOfProcessors; // Number of Processors
	LARGE_INTEGER   EndTime;            // Time when logger stops
	ULONG           TimerResolution;    // assumes timer is constant!!!
	ULONG           MaximumFileSize;    // Maximum in Mbytes
	ULONG           LogFileMode;        // specify logfile mode
	ULONG           BuffersWritten;     // used to file start of Circular File
	union {
		GUID LogInstanceGuid;           // For RealTime Buffer Delivery
		struct {
			ULONG   StartBuffers;       // Count of buffers written at start.
			ULONG   PointerSize;        // Size of pointer type in bits
			ULONG   EventsLost;         // Events lost during log session
			ULONG   CpuSpeedInMHz;      // Cpu Speed in MHz
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME2;
#if defined(_WMIKM_)
	PWCHAR          LoggerName;
	PWCHAR          LogFileName;
	RTL_TIME_ZONE_INFORMATION TimeZone;
#else
	LPWSTR          LoggerName;
	LPWSTR          LogFileName;
	TIME_ZONE_INFORMATION TimeZone;
#endif
	LARGE_INTEGER   BootTime;
	LARGE_INTEGER   PerfFreq;           // Reserved
	LARGE_INTEGER   StartTime;          // Reserved
	ULONG           ReservedFlags;      // ClockType
	ULONG           BuffersLost;
} TRACE_LOGFILE_HEADER, *PTRACE_LOGFILE_HEADER;

struct _EVENT_TRACE_LOGFILEW {
	LPWSTR                  LogFileName;      // Logfile Name
	LPWSTR                  LoggerName;       // LoggerName
	LONGLONG                CurrentTime;      // timestamp of last event
	ULONG                   BuffersRead;      // buffers read to date
	union {
		// Mode of the logfile
		ULONG               LogFileMode;
		// Processing flags used on Vista and above
		ULONG               ProcessTraceMode;
	} DUMMYUNIONNAME;
	EVENT_TRACE             CurrentEvent;     // Current Event from this stream.
	TRACE_LOGFILE_HEADER    LogfileHeader;    // logfile header structure
	PEVENT_TRACE_BUFFER_CALLBACKW             // callback before each buffer
		BufferCallback;   // is read
//
// following variables are filled for BufferCallback.
//
	ULONG                   BufferSize;
	ULONG                   Filled;
	ULONG                   EventsLost;
	//
	// following needs to be propagated to each buffer
	//
	union {
		// Callback with EVENT_TRACE
		PEVENT_CALLBACK         EventCallback;
		// Callback with EVENT_RECORD on Vista and above
		PEVENT_RECORD_CALLBACK  EventRecordCallback;
	} DUMMYUNIONNAME2;

	ULONG                   IsKernelTrace;    // TRUE for kernel logfile

	PVOID                   Context;          // reserved for internal use
};

struct _EVENT_TRACE_LOGFILEA {
	LPSTR                   LogFileName;      // Logfile Name
	LPSTR                   LoggerName;       // LoggerName
	LONGLONG                CurrentTime;      // timestamp of last event
	ULONG                   BuffersRead;      // buffers read to date
	union {
		ULONG               LogFileMode;      // Mode of the logfile
		ULONG               ProcessTraceMode; // Processing flags
	} DUMMYUNIONNAME;
	EVENT_TRACE             CurrentEvent;     // Current Event from this stream
	TRACE_LOGFILE_HEADER    LogfileHeader;    // logfile header structure
	PEVENT_TRACE_BUFFER_CALLBACKA             // callback before each buffer
		BufferCallback;   // is read

//
// following variables are filled for BufferCallback.
//
	ULONG                   BufferSize;
	ULONG                   Filled;
	ULONG                   EventsLost;
	//
	// following needs to be propagated to each buffer
	//
	union {
		PEVENT_CALLBACK         EventCallback;  // callback for every event
		PEVENT_RECORD_CALLBACK  EventRecordCallback;
	} DUMMYUNIONNAME2;


	ULONG                   IsKernelTrace;  // TRUE for kernel logfile

	PVOID                   Context;        // reserved for internal use
};

typedef enum _EVENT_INFO_CLASS {
	EventProviderBinaryTrackInfo, /*
		Requests that the ETW runtime add the full path to the binary that
		registered the provider into each trace. The full path is important if
		if the binary contains the mc.exe-generated decoding resources but is
		not globally registered. Decoding tools can use the path to locate the
		binary and extract the decoding resources. */
	EventProviderSetReserved1, /*
		Not used. */
	EventProviderSetTraits, /*
		Provides the ETW runtime with additional information about the
		provider, potentially including the provider name and a group GUID.
		Refer the the MSDN Provider Traits topic for more information about the
		format of the data to be used with this control code.
		Setting this trait also configures the ETW runtime to respect the
		Type field of EVENT_DATA_DESCRIPTOR (by default the Type field is
		ignored). */
	EventProviderUseDescriptorType, /*
		Configures whether the ETW runtime should respect the Type field of the
		EVENT_DATA_DESCRIPTOR. The data for this control code is a BOOLEAN
		(1 byte, value FALSE or TRUE). */
	MaxEventInfo
} EVENT_INFO_CLASS;

typedef struct _WNODE_HEADER
{
	ULONG BufferSize;        // Size of entire buffer inclusive of this ULONG
	ULONG ProviderId;    // Provider Id of driver returning this buffer
	union
	{
		ULONG64 HistoricalContext;  // Logger use
		struct
		{
			ULONG Version;           // Reserved
			ULONG Linkage;           // Linkage field reserved for WMI
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;

	union
	{
		ULONG CountLost;         // Reserved
		HANDLE KernelHandle;     // Kernel handle for data block
		LARGE_INTEGER TimeStamp; // Timestamp as returned in units of 100ns
								 // since 1/1/1601
	} DUMMYUNIONNAME2;
	GUID Guid;                  // Guid for data block returned with results
	ULONG ClientContext;
	ULONG Flags;             // Flags, see below
} WNODE_HEADER, *PWNODE_HEADER;

typedef struct _EVENT_FILTER_DESCRIPTOR {

	ULONGLONG   Ptr;  // Pointer to filter data. Set to (ULONGLONG)(ULONG_PTR)pData.
	ULONG       Size; // Size of filter data in bytes.
	ULONG       Type; // EVENT_FILTER_TYPE value.

} EVENT_FILTER_DESCRIPTOR, *PEVENT_FILTER_DESCRIPTOR;

typedef struct _EVENT_TRACE_PROPERTIES {
	WNODE_HEADER Wnode;
	//
	// data provided by caller
	ULONG BufferSize;                   // buffer size for logging (kbytes)
	ULONG MinimumBuffers;               // minimum to preallocate
	ULONG MaximumBuffers;               // maximum buffers allowed
	ULONG MaximumFileSize;              // maximum logfile size (in MBytes)
	ULONG LogFileMode;                  // sequential, circular
	ULONG FlushTimer;                   // buffer flush timer, in seconds
	ULONG EnableFlags;                  // trace enable flags
	union {
		LONG  AgeLimit;                 // unused
		LONG  FlushThreshold;           // Number of buffers to fill before flushing
	} DUMMYUNIONNAME;

	// data returned to caller
	ULONG NumberOfBuffers;              // no of buffers in use
	ULONG FreeBuffers;                  // no of buffers free
	ULONG EventsLost;                   // event records lost
	ULONG BuffersWritten;               // no of buffers written to file
	ULONG LogBuffersLost;               // no of logfile write failures
	ULONG RealTimeBuffersLost;          // no of rt delivery failures
	HANDLE LoggerThreadId;              // thread id of Logger
	ULONG LogFileNameOffset;            // Offset to LogFileName
	ULONG LoggerNameOffset;             // Offset to LoggerName
} EVENT_TRACE_PROPERTIES, *PEVENT_TRACE_PROPERTIES;

typedef struct _ENABLE_TRACE_PARAMETERS {
	ULONG                    Version;
	ULONG                    EnableProperty;
	ULONG                    ControlFlags;
	GUID                     SourceId;
	PEVENT_FILTER_DESCRIPTOR EnableFilterDesc;
	ULONG                    FilterDescCount;
} ENABLE_TRACE_PARAMETERS, *PENABLE_TRACE_PARAMETERS;

typedef
VOID
(NTAPI *PENABLECALLBACK) (
	_In_ LPCGUID SourceId,
	_In_ ULONG IsEnabled,
	_In_ UCHAR Level,
	_In_ ULONGLONG MatchAnyKeyword,
	_In_ ULONGLONG MatchAllKeyword,
	_In_opt_ PEVENT_FILTER_DESCRIPTOR FilterData,
	_Inout_opt_ PVOID CallbackContext
	);