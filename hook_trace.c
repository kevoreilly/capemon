#include <stdio.h>
#include "log.h"
#include "misc.h"
#include "config.h"
#include "hook_trace.h"

#define DEBUG_COMMENTS

#define IMAX_BITS(m) ((m)/((m)%255+1) / 255%255*8 + 7-86/((m)%255+12))
#define LOG2_10_N  28
#define LOG2_10_D  93
#define UNSIGNED_LONG_STRING_SIZE (IMAX_BITS(ULONG_MAX)*LOG2_10_N/LOG2_10_D + 2)
#define GUID_SIZE 68

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);

void safe_string_to_guid(char *s, size_t max_size, LPCGUID guid) {
	if (guid == NULL) {
		snprintf(s, max_size, "%s", "NULL");
	} else {
		__try {
			snprintf(s, max_size, "%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX", 
			  guid->Data1, guid->Data2, guid->Data3, 
			  guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
			  guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			snprintf(s, max_size, "%s", "INVALID");
		}
	}
}

void safe_string_to_sid(PSID Sid, char *out_str, size_t out_len) {
	if (Sid == NULL) {
		snprintf(out_str, out_len, "%s", "NULL");
		return;
	}
	__try {
		PISID pSid = (PISID)Sid;
		size_t offset = snprintf(out_str, out_len, "S-%u-%u", pSid->Revision,
			(pSid->IdentifierAuthority.Value[0] << 24) |
			(pSid->IdentifierAuthority.Value[1] << 16) |
			(pSid->IdentifierAuthority.Value[2] << 8) |
			(pSid->IdentifierAuthority.Value[3]));
		
		for (DWORD i = 0; i < pSid->SubAuthorityCount; i++) {
			if (offset >= out_len) break;
			offset += snprintf(out_str + offset, out_len - offset, "-%u", pSid->SubAuthority[i]);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		snprintf(out_str, out_len, "%s", "INVALID");
	}
}

HOOKDEF(ULONG, WINAPI, CloseTrace,
	_In_ TRACEHANDLE TraceHandle
) {
	ULONG ret = Old_CloseTrace(TraceHandle);
	LOQ_zero("Trace", "x", "TraceHandle", TraceHandle);
	return ret;
}

HOOKDEF(ULONG, WINAPI, ControlTraceA,
	_In_ TRACEHANDLE TraceHandle,
	_In_ LPCTSTR InstanceName,
	_Inout_ PEVENT_TRACE_PROPERTIES Properties,
	_In_ ULONG ControlCode
) {
	ULONG ret = Old_ControlTraceA(TraceHandle,InstanceName,Properties,ControlCode);
    char S_GUID[64] = "NULL";
    if (Properties) {
		safe_string_to_guid(S_GUID, sizeof(S_GUID), &Properties->Wnode.Guid);
	}
	char *ControlValues[] = {"QUERY","STOP","UPDATE","FLUSH","INCREMENT_FILE","CONVERT_TO_REALTIME"};
    char ControlValue[32] = "";
    switch(ControlCode){
        case EVENT_TRACE_CONTROL_QUERY:
            strncpy(ControlValue,ControlValues[0], sizeof(ControlValue) - 1);
            break;
        case EVENT_TRACE_CONTROL_STOP:
            strncpy(ControlValue,ControlValues[1], sizeof(ControlValue) - 1);
            break;
        case EVENT_TRACE_CONTROL_UPDATE:
            strncpy(ControlValue,ControlValues[2], sizeof(ControlValue) - 1);
            break;
        case EVENT_TRACE_CONTROL_FLUSH:
            strncpy(ControlValue,ControlValues[3], sizeof(ControlValue) - 1);
            break;
        case EVENT_TRACE_CONTROL_INCREMENT_FILE:
            strncpy(ControlValue,ControlValues[4], sizeof(ControlValue) - 1);
            break;
        case EVENT_TRACE_CONTROL_CONVERT_TO_REALTIME:
            strncpy(ControlValue,ControlValues[5], sizeof(ControlValue) - 1);
            break;
        default:
            snprintf(ControlValue,sizeof(ControlValue),"%lu",ControlCode);
    } 
    if(ret == ERROR_SUCCESS)
	    LOQ_zero("Trace", "xsss","TraceHandle", TraceHandle,"InstanceName", InstanceName, "ControlCode", ControlValue, "GUID", S_GUID);
    else
        LOQ_zero("Trace", "sss","InstanceName", InstanceName, "ControlCode", ControlValue, "GUID", S_GUID);
	return ret;
}

HOOKDEF(ULONG, WINAPI, ControlTraceW,
	_In_ TRACEHANDLE TraceHandle,
	_In_ LPCWSTR InstanceName,
	_Inout_ PEVENT_TRACE_PROPERTIES Properties,
	_In_ ULONG ControlCode
) {
	ULONG ret = Old_ControlTraceW(TraceHandle,InstanceName,Properties,ControlCode);
    char S_GUID[64] = "NULL";
    if (Properties) {
		safe_string_to_guid(S_GUID, sizeof(S_GUID), &Properties->Wnode.Guid);
	}
	char *ControlValues[] = {"QUERY","STOP","UPDATE","FLUSH","INCREMENT_FILE","CONVERT_TO_REALTIME"};
    char ControlValue[32] = "";
    switch(ControlCode){
        case EVENT_TRACE_CONTROL_QUERY:
            strncpy(ControlValue,ControlValues[0], sizeof(ControlValue) - 1);
            break;
        case EVENT_TRACE_CONTROL_STOP:
            strncpy(ControlValue,ControlValues[1], sizeof(ControlValue) - 1);
            break;
        case EVENT_TRACE_CONTROL_UPDATE:
            strncpy(ControlValue,ControlValues[2], sizeof(ControlValue) - 1);
            break;
        case EVENT_TRACE_CONTROL_FLUSH:
            strncpy(ControlValue,ControlValues[3], sizeof(ControlValue) - 1);
            break;
        case EVENT_TRACE_CONTROL_INCREMENT_FILE:
            strncpy(ControlValue,ControlValues[4], sizeof(ControlValue) - 1);
            break;
        case EVENT_TRACE_CONTROL_CONVERT_TO_REALTIME:
            strncpy(ControlValue,ControlValues[5], sizeof(ControlValue) - 1);
            break;
        default:
            snprintf(ControlValue,sizeof(ControlValue),"%lu",ControlCode);
    } 
    if(ret == ERROR_SUCCESS)
	    LOQ_zero("Trace", "xuss","TraceHandle", TraceHandle,"InstanceName", InstanceName, "ControlCode", ControlValue, "GUID", S_GUID);
    else
        LOQ_zero("Trace", "uss","InstanceName", InstanceName, "ControlCode", ControlValue, "GUID", S_GUID);
	return ret;
}

HOOKDEF(ULONG, WINAPI, EnableTrace,
	_In_ ULONG Enable,
	_In_ ULONG EnableFlag,
	_In_ ULONG EnableLevel,
	_In_ LPCGUID ControlGuid,
	_In_ TRACEHANDLE SessionHandle
) {
    char S_ControlGuid[64] = "";
    safe_string_to_guid(S_ControlGuid, sizeof(S_ControlGuid), ControlGuid);
	ULONG ret = Old_EnableTrace(Enable,EnableFlag,EnableLevel,ControlGuid,SessionHandle);
	LOQ_zero("Trace", "iiixs", "Enable", Enable, "EnableFlag", EnableFlag, "EnableLevel", EnableLevel, "TraceHandle", SessionHandle, "ControlGUID", S_ControlGuid);
	return ret;
}

HOOKDEF(ULONG, WINAPI, EnableTraceEx,
	_In_ LPCGUID ProviderId,
	_In_opt_ LPCGUID SourceId,
	_In_ TRACEHANDLE TraceHandle,
	_In_ ULONG IsEnabled,
	_In_ UCHAR Level,
	_In_ ULONGLONG MatchAnyKeyword,
	_In_ ULONGLONG MatchAllKeyword,
	_In_ ULONG EnableProperty,
	_In_opt_ PEVENT_FILTER_DESCRIPTOR EnableFilterDesc
) {
    char S_ProviderId[64] = "";
    safe_string_to_guid(S_ProviderId, sizeof(S_ProviderId), ProviderId);
	char S_SourceId[64] = "";
    if (SourceId != NULL && SourceId != &GUID_NULL) {
        safe_string_to_guid(S_SourceId, sizeof(S_SourceId), SourceId);
    }
    else {
		snprintf(S_SourceId, sizeof(S_SourceId), "%s", "NULL");
    }
	ULONG ret = Old_EnableTraceEx(ProviderId,SourceId,TraceHandle,IsEnabled,Level,MatchAnyKeyword,MatchAllKeyword,EnableProperty,EnableFilterDesc);
	LOQ_zero("Trace","ssxixxxi", "ProviderId", S_ProviderId, "SourceId", S_SourceId, "TraceHandle", TraceHandle, "Enabled", IsEnabled, "Level", Level,
     "MatchAnyKeyword", MatchAnyKeyword, "MatchAllKeyword", MatchAllKeyword, "EnableProperty", EnableProperty);
	return ret;
}

HOOKDEF(ULONG, WINAPI, EnableTraceEx2,
	_In_ TRACEHANDLE TraceHandle,
	_In_ LPCGUID ProviderId,
	_In_ ULONG ControlCode,
	_In_ UCHAR Level,
	_In_ ULONGLONG MatchAnyKeyword,
	_In_ ULONGLONG MatchAllKeyword,
	_In_ ULONG Timeout,
	_In_opt_ PENABLE_TRACE_PARAMETERS EnableParameters
) {
    char S_ProviderId[64] = "";
    safe_string_to_guid(S_ProviderId, sizeof(S_ProviderId), ProviderId);
	ULONG ret = Old_EnableTraceEx2(TraceHandle,ProviderId,ControlCode,Level,MatchAnyKeyword,MatchAllKeyword,Timeout,EnableParameters);
	char *ControlValues[] = {"DISABLE","ENABLE","CAPTURE"};
    char ControlValue[32] = "";
    switch(ControlCode){
        case EVENT_CONTROL_CODE_DISABLE_PROVIDER:
            strncpy(ControlValue,ControlValues[0], sizeof(ControlValue) - 1);
            break;
        case EVENT_CONTROL_CODE_ENABLE_PROVIDER:
            strncpy(ControlValue,ControlValues[1], sizeof(ControlValue) - 1);
            break;
        case EVENT_CONTROL_CODE_CAPTURE_STATE:
            strncpy(ControlValue,ControlValues[2], sizeof(ControlValue) - 1);
            break;
        default:
            snprintf(ControlValue,sizeof(ControlValue),"%lu",ControlCode);
    } 
    LOQ_zero("Trace","sxsixxi", "ProviderId", S_ProviderId, "TraceHandle", TraceHandle, "ControlCode", ControlValue, "Level", Level,
     "MatchAnyKeyword", MatchAnyKeyword, "MatchAllKeyword", MatchAllKeyword, "Timeout", Timeout);
	return ret;
}

HOOKDEF(TRACEHANDLE, WINAPI, OpenTraceA,
	_Inout_ PEVENT_TRACE_LOGFILEA Logfile
){
	TRACEHANDLE ret = Old_OpenTraceA(Logfile);
	if (Logfile) {
		LOQ_void("Trace", "ss","LogFileName",Logfile->LogFileName,"LoggerName", Logfile->LoggerName); 
	}
	return ret;
}

HOOKDEF(TRACEHANDLE, WINAPI, OpenTraceW,
	_Inout_ PEVENT_TRACE_LOGFILEW Logfile
) {
	TRACEHANDLE ret = Old_OpenTraceW(Logfile);
	if (Logfile) {
		LOQ_void("Trace", "uu","LogFileName",Logfile->LogFileName,"LoggerName", Logfile->LoggerName); 
	}
	return ret;
}

HOOKDEF(ULONG, WINAPI, QueryAllTracesA,
	_Out_ PEVENT_TRACE_PROPERTIES* PropertyArray,
	_In_ ULONG PropertyArrayCount,
	_Out_ PULONG LoggerCount
) {
	ULONG ret = Old_QueryAllTracesA(PropertyArray,PropertyArrayCount,LoggerCount);
	return ret;
}

HOOKDEF(ULONG, WINAPI, QueryAllTracesW,
	_Out_ PEVENT_TRACE_PROPERTIES* PropertyArray,
	_In_ ULONG PropertyArrayCount,
	_Out_ PULONG LoggerCount
){
	ULONG ret = Old_QueryAllTracesW(PropertyArray,PropertyArrayCount,LoggerCount);
	return ret;
}

HOOKDEF(ULONG, WINAPI, QueryTraceA,
	_In_ TRACEHANDLE TraceHandle,
	_In_ LPCTSTR InstanceName,
	_Inout_ PEVENT_TRACE_PROPERTIES Properties
) {
	ULONG ret = Old_QueryTraceA(TraceHandle,InstanceName,Properties);
	LOQ_zero("Trace", "xs","TraceHandle", TraceHandle,"InstanceName", InstanceName);
	return ret;
}

HOOKDEF(ULONG, WINAPI, QueryTraceW,
	_In_ TRACEHANDLE TraceHandle,
	_In_ LPCWSTR InstanceName,
	_Inout_ PEVENT_TRACE_PROPERTIES Properties
) {
	ULONG ret = Old_QueryTraceW(TraceHandle,InstanceName,Properties);
	LOQ_zero("Trace", "xu","TraceHandle", TraceHandle,"InstanceName", InstanceName);
	return ret;
}

HOOKDEF(ULONG, WINAPI, StartTraceA,
	_Out_ PTRACEHANDLE TraceHandle,
	_In_ LPCTSTR InstanceName,
	_Inout_ PEVENT_TRACE_PROPERTIES Properties
) {
	ULONG ret = Old_StartTraceA(TraceHandle,InstanceName,Properties);
    char S_GUID[64] = "NULL";
    if (Properties) {
		safe_string_to_guid(S_GUID, sizeof(S_GUID), &Properties->Wnode.Guid);
	}
    if(ret == ERROR_SUCCESS)
	    LOQ_zero("Trace", "xss","TraceHandle", TraceHandle ? *TraceHandle : 0,"InstanceName", InstanceName, "GUID", S_GUID);
    else
        LOQ_zero("Trace", "ss","InstanceName", InstanceName, "GUID", S_GUID);
	return ret;
}

HOOKDEF(ULONG, WINAPI, StartTraceW,
	_Out_ PTRACEHANDLE TraceHandle,
	_In_ LPCWSTR InstanceName,
	_Inout_ PEVENT_TRACE_PROPERTIES Properties
) {
	ULONG ret = Old_StartTraceW(TraceHandle,InstanceName,Properties);
	char S_GUID[64] = "NULL";
    if (Properties) {
		safe_string_to_guid(S_GUID, sizeof(S_GUID), &Properties->Wnode.Guid);
	}
    if(ret == ERROR_SUCCESS)
	    LOQ_zero("Trace", "xus","TraceHandle", TraceHandle ? *TraceHandle : 0,"InstanceName", InstanceName, "GUID", S_GUID);
    else
        LOQ_zero("Trace", "us","InstanceName", InstanceName, "GUID", S_GUID);
	return ret;
}

HOOKDEF(ULONG, WINAPI, StopTraceA,
	_In_ TRACEHANDLE TraceHandle,
	_In_ LPCTSTR InstanceName,
	_Out_ PEVENT_TRACE_PROPERTIES Properties
) {
	ULONG ret = Old_StopTraceA(TraceHandle,InstanceName,Properties);
	char S_GUID[64] = "NULL";
    if (Properties) {
		safe_string_to_guid(S_GUID, sizeof(S_GUID), &Properties->Wnode.Guid);
	}
    if(ret == ERROR_SUCCESS)
	    LOQ_zero("Trace", "xss","TraceHandle", TraceHandle,"InstanceName", InstanceName, "GUID", S_GUID);
    else
        LOQ_zero("Trace", "ss","InstanceName", InstanceName, "GUID", S_GUID);
	return ret;
}

HOOKDEF(ULONG, WINAPI, StopTraceW,
	_In_ TRACEHANDLE TraceHandle,
	_In_ LPCWSTR InstanceName,
	_Out_ PEVENT_TRACE_PROPERTIES Properties
) {
	ULONG ret = Old_StopTraceW(TraceHandle,InstanceName,Properties);
	char S_GUID[64] = "NULL";
    if (Properties) {
		safe_string_to_guid(S_GUID, sizeof(S_GUID), &Properties->Wnode.Guid);
	}
    if(ret == ERROR_SUCCESS)
	    LOQ_zero("Trace", "xus","TraceHandle", TraceHandle,"InstanceName", InstanceName, "GUID", S_GUID);
    else
        LOQ_zero("Trace", "us","InstanceName", InstanceName, "GUID", S_GUID);
	return ret;
}

HOOKDEF(ULONG, WINAPI, UpdateTraceA,
	_In_ TRACEHANDLE TraceHandle,
	_In_ LPCTSTR InstanceName,
	_Inout_ PEVENT_TRACE_PROPERTIES Properties
) {
	ULONG ret = Old_UpdateTraceA(TraceHandle,InstanceName,Properties);
	if(Properties && Properties->LogFileNameOffset != 0){
        char *NewLogFileName = (char *)Properties + Properties->LogFileNameOffset;
        LOQ_zero("Trace", "xsis","TraceHandle", TraceHandle,"InstanceName", InstanceName,"EnableFlags", Properties->EnableFlags, "NewLogFileName", NewLogFileName ); 
    }
    else if (Properties) {
        LOQ_zero("Trace", "xsi","TraceHandle", TraceHandle,"InstanceName", InstanceName,"EnableFlags", Properties->EnableFlags); 
    }
	return ret;
}

HOOKDEF(ULONG, WINAPI, UpdateTraceW,
	_In_ TRACEHANDLE TraceHandle,
	_In_ LPCWSTR InstanceName,
	_Inout_ PEVENT_TRACE_PROPERTIES Properties
) {
	ULONG ret = Old_UpdateTraceW(TraceHandle,InstanceName,Properties);
	if(Properties && Properties->LogFileNameOffset != 0){
        wchar_t *NewLogFileName = (wchar_t *)((char *)Properties + Properties->LogFileNameOffset);
        LOQ_zero("Trace", "xuis","TraceHandle", TraceHandle,"InstanceName", InstanceName,"EnableFlags", Properties->EnableFlags, "NewLogFileName", NewLogFileName ); 
    }
    else if (Properties) {
        LOQ_zero("Trace", "xui","TraceHandle", TraceHandle,"InstanceName", InstanceName,"EnableFlags", Properties->EnableFlags); 
    }
	return ret;
}

HOOKDEF(LONG, WINAPI, CveEventWrite,
	_In_ PCWSTR CveId,
	_In_opt_ PCWSTR AdditionalDetails
) {
	LONG ret = Old_CveEventWrite(CveId,AdditionalDetails);
    LOQ_zero("Trace", "uu", "CVE", CveId, "AdditionalDetails", AdditionalDetails);
	return ret;
}

HOOKDEF(ULONG, WINAPI, EventAccessControl,
	_In_ LPGUID Guid,
	_In_ ULONG Operation,
	_In_ PSID Sid,
	_In_ ULONG Rights,
	_In_ BOOLEAN AllowOrDeny
) {
	ULONG ret = Old_EventAccessControl(Guid,Operation,Sid,Rights,AllowOrDeny);
	char S_GUID[64] = "NULL";
    safe_string_to_guid(S_GUID, sizeof(S_GUID), Guid);
    char S_SID[128] = "NULL";
    safe_string_to_sid(Sid, S_SID, sizeof(S_SID));
	LOQ_zero("Trace", "sxshi", "GUID", S_GUID, "Operation", Operation, "SID", S_SID, "Rights", Rights, "Allow_OR_Deny", AllowOrDeny);
	return ret;
}

HOOKDEF(ULONG, WINAPI, EventAccessQuery,
	_In_ LPGUID Guid,
	_Inout_ PSECURITY_DESCRIPTOR Buffer,
	_Inout_ PULONG BufferSize
) {
	ULONG ret = Old_EventAccessQuery(Guid,Buffer,BufferSize);
	char S_GUID[64] = "NULL";
    safe_string_to_guid(S_GUID, sizeof(S_GUID), Guid);
	LOQ_zero("Trace", "s", "GUID", S_GUID);
	return ret;
}

HOOKDEF(ULONG, WINAPI, EventAccessRemove,
	_In_ LPGUID Guid
) {
	ULONG ret = Old_EventAccessRemove(Guid);
	char S_GUID[64] = "NULL";
    safe_string_to_guid(S_GUID, sizeof(S_GUID), Guid);
	LOQ_zero("Trace", "s", "GUID", S_GUID);
	return ret;
}

HOOKDEF(ULONG, WINAPI, EventRegister,
	_In_ LPCGUID ProviderId,
	_In_opt_ PENABLECALLBACK EnableCallback,
	_In_opt_ PVOID CallbackContext,
	_Out_ PREGHANDLE RegHandle
) {
	ULONG ret = Old_EventRegister(ProviderId,EnableCallback,CallbackContext,RegHandle);
	char S_ProviderID[64] = "NULL";
    safe_string_to_guid(S_ProviderID , sizeof(S_ProviderID), ProviderId);
	LOQ_zero("Trace", "s", "ProviderId", S_ProviderID );
	return ret;
}

HOOKDEF(ULONG, WINAPI, EventSetInformation,
	_In_ REGHANDLE RegHandle,
	_In_ EVENT_INFO_CLASS InformationClass,
	_In_ PVOID EventInformation,
	_In_ ULONG InformationLength
) {
	ULONG ret = Old_EventSetInformation(RegHandle,InformationClass,EventInformation,InformationLength);
    char *InformationClasses[] = {"TRACKINFO","RESERVED","SETTRAITS","DESCRIPTORTYPE","INVALID"};
    char ControlValue[32] = "";
    switch(InformationClass){
        case EventProviderBinaryTrackInfo:
            strncpy(ControlValue,InformationClasses[0], sizeof(ControlValue) - 1);
            break;
        case EventProviderSetReserved1:
            strncpy(ControlValue,InformationClasses[1], sizeof(ControlValue) - 1);
            break;
        case EventProviderSetTraits:
            strncpy(ControlValue,InformationClasses[2], sizeof(ControlValue) - 1);
            break;
        case EventProviderUseDescriptorType:
            strncpy(ControlValue,InformationClasses[3], sizeof(ControlValue) - 1);
            break;
        case MaxEventInfo:
            strncpy(ControlValue,InformationClasses[4], sizeof(ControlValue) - 1);
            break;
        default:
            snprintf(ControlValue,sizeof(ControlValue),"%lu",(ULONG)InformationClass);
    } 

	LOQ_zero("Trace", "xsb", "Handle", RegHandle, "Information_Class", ControlValue, "EventInformation", InformationLength, EventInformation);
	return ret;
}

HOOKDEF(ULONG, WINAPI, EventUnregister,
	_In_ REGHANDLE RegHandle
) {
	ULONG ret = Old_EventUnregister(RegHandle);
	LOQ_zero("Trace", "x", "Handle", RegHandle );
	return ret;
}