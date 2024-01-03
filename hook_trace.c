#include <stdio.h>
#include <limits.h>
#include "hooking.h"
#include "log.h"
#include "CAPE\CAPE.h"
#include "hook_trace.h"

#define DEBUG_COMMENTS

#define IMAX_BITS(m) ((m)/((m)%255+1) / 255%255*8 + 7-86/((m)%255+12))
#define LOG2_10_N  28
#define LOG2_10_D  93
#define UNSIGNED_LONG_STRING_SIZE (IMAX_BITS(ULONG_MAX)*LOG2_10_N/LOG2_10_D + 2)
#define GUID_SIZE 68

#define G32 "%8" SCNx32
#define G16 "%4" SCNx16
#define G8  "%2" SCNx8

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);

void string_to_sid(PISID pSid,LPWSTR *pstr) {
    DWORD sz, i;
    LPWSTR str;
    WCHAR fmt[] = { 
        'S','-','%','u','-','%','2','X','%','2','X','%','X','%','X','%','X','%','X',0 };
    WCHAR subauthfmt[] = { '-','%','u',0 };

    sz = 14 + pSid->SubAuthorityCount * 11;
    str = malloc(sz*sizeof(WCHAR) );
    sprintf( str, fmt, pSid->Revision, 
        pSid->IdentifierAuthority.Value[2],
        pSid->IdentifierAuthority.Value[3],
        pSid->IdentifierAuthority.Value[0]&0x0f,
        pSid->IdentifierAuthority.Value[4]&0x0f,
        pSid->IdentifierAuthority.Value[1]&0x0f,
        pSid->IdentifierAuthority.Value[5]&0x0f);
    for( i=0; i<pSid->SubAuthorityCount; i++ )
        sprintf( str + strlen(str), subauthfmt, pSid->SubAuthority[i] );
    *pstr = str;
    return TRUE;
}

void string_to_guid(char * s,GUID guid) {
    snprintf(s,GUID_SIZE + 1,"%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX", 
      guid.Data1, guid.Data2, guid.Data3, 
      guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
      guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
}

HOOKDEF(ULONG, WINAPI, CloseTrace,
	_In_ TRACEHANDLE TraceHandle
) {
	DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked CloseTrace\n");
	ULONG ret = Old_CloseTrace(TraceHandle);
	LOQ_zero("Trace", "i", "TraceHandle", TraceHandle);
	return ret;
}

HOOKDEF(ULONG, WINAPI, ControlTraceA,
	_In_ TRACEHANDLE TraceHandle,
	_In_ LPCTSTR InstanceName,
	_Inout_ PEVENT_TRACE_PROPERTIES Properties,
	_In_ ULONG ControlCode
) {
    DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked ControlTrace\n");
    char *ControlValues[] = {"FLUSH","QUERY","STOP","UPDATE","INCREMENT_FILE","CONVERT_TO_REALTIME"};
    char *ControlValue = NULL;
    ControlValue = malloc(sizeof(char)*UNSIGNED_LONG_STRING_SIZE);
	ULONG ret = Old_ControlTraceA(TraceHandle,InstanceName,Properties,ControlCode);
    switch(ControlCode){
        case EVENT_TRACE_CONTROL_FLUSH:
            strncpy(ControlValue,ControlValues[0], strlen(ControlValues[0]) + 1);
            LOQ_zero("Trace", "iss","TraceHandle", TraceHandle,"InstanceName", InstanceName,"ControlCode", ControlValue );
            break;
        case EVENT_TRACE_CONTROL_QUERY:
            strncpy(ControlValue,ControlValues[1], strlen(ControlValues[1]) + 1);
            LOQ_zero("Trace", "iss","TraceHandle", TraceHandle,"InstanceName", InstanceName,"ControlCode", ControlValue );
            break;
        case EVENT_TRACE_CONTROL_STOP:
            strncpy(ControlValue,ControlValues[2], strlen(ControlValues[2]) + 1);
            LOQ_zero("Trace", "iss","TraceHandle", TraceHandle,"InstanceName", InstanceName,"ControlCode", ControlValue );
            break;
        case EVENT_TRACE_CONTROL_UPDATE:
            strncpy(ControlValue,ControlValues[3], strlen(ControlValues[3]) + 1);
            if(Properties->LogFileNameOffset != 0){
                char *NewLogFileName = NULL;
                NewLogFileName = malloc(sizeof(char)*1025);
                strncpy(NewLogFileName, &Properties + Properties->LogFileNameOffset, strlen(&Properties + Properties->LogFileNameOffset) + 1);
                LOQ_zero("Trace", "issis","TraceHandle", TraceHandle,"InstanceName", InstanceName,"ControlCode", ControlValue,"EnableFlags", Properties->EnableFlags, "NewLogFileName", NewLogFileName ); 
                free(NewLogFileName);
            }
            else{
                LOQ_zero("Trace", "issi","TraceHandle", TraceHandle,"InstanceName", InstanceName,"ControlCode", ControlValue,"EnableFlags", Properties->EnableFlags);
            }
            break;
        case EVENT_TRACE_CONTROL_INCREMENT_FILE:
            strncpy(ControlValue,ControlValues[4], strlen(ControlValues[4]) + 1);
            LOQ_zero("Trace", "iss","TraceHandle", TraceHandle,"InstanceName", InstanceName,"ControlCode", ControlValue );
            break;
        case EVENT_TRACE_CONTROL_CONVERT_TO_REALTIME:
            strncpy(ControlValue,ControlValues[5], strlen(ControlValues[5]) + 1);
            LOQ_zero("Trace", "iss","TraceHandle", TraceHandle,"InstanceName", InstanceName,"ControlCode", ControlValue );
            break;
        default:
            snprintf(ControlValue,UNSIGNED_LONG_STRING_SIZE,"%lu",ControlCode);
            LOQ_zero("Trace", "iss","TraceHandle", TraceHandle,"InstanceName", InstanceName,"ControlCode", ControlValue );
    } 
    free(ControlValue);
	return ret;
}

HOOKDEF(ULONG, WINAPI, ControlTraceW,
	_In_ TRACEHANDLE TraceHandle,
	_In_ LPCWSTR InstanceName,
	_Inout_ PEVENT_TRACE_PROPERTIES Properties,
	_In_ ULONG ControlCode
) {
    DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked ControlTrace\n");
	char *ControlValues[] = {"FLUSH","QUERY","STOP","UPDATE","INCREMENT_FILE","CONVERT_TO_REALTIME"};
    char *ControlValue = NULL;
    ControlValue = malloc(sizeof(char)*UNSIGNED_LONG_STRING_SIZE);
	ULONG ret = Old_ControlTraceW(TraceHandle,InstanceName,Properties,ControlCode);
    switch(ControlCode){
        case EVENT_TRACE_CONTROL_FLUSH:
            strncpy(ControlValue,ControlValues[0], strlen(ControlValues[0]) + 1);
            LOQ_zero("Trace", "ius","TraceHandle", TraceHandle,"InstanceName", InstanceName,"ControlCode", ControlValue );
            break;
        case EVENT_TRACE_CONTROL_QUERY:
            strncpy(ControlValue,ControlValues[1], strlen(ControlValues[1]) + 1);
            LOQ_zero("Trace", "ius","TraceHandle", TraceHandle,"InstanceName", InstanceName,"ControlCode", ControlValue );
            break;
        case EVENT_TRACE_CONTROL_STOP:
            strncpy(ControlValue,ControlValues[2], strlen(ControlValues[2]) + 1);
            LOQ_zero("Trace", "ius","TraceHandle", TraceHandle,"InstanceName", InstanceName,"ControlCode", ControlValue );
            break;
        case EVENT_TRACE_CONTROL_UPDATE:
            strncpy(ControlValue,ControlValues[3], strlen(ControlValues[3]) + 1);
            if(Properties->LogFileNameOffset != 0){
                char *NewLogFileName = NULL;
                NewLogFileName = malloc(sizeof(char)*1025);
                strncpy(NewLogFileName, &Properties + Properties->LogFileNameOffset, strlen(&Properties + Properties->LogFileNameOffset) + 1);
                LOQ_zero("Trace", "iusis","TraceHandle", TraceHandle,"InstanceName", InstanceName,"ControlCode", ControlValue,"EnableFlags", Properties->EnableFlags, "NewLogFileName", NewLogFileName ); 
                free(NewLogFileName);
            }
            else{
                LOQ_zero("Trace", "iusi","TraceHandle", TraceHandle,"InstanceName", InstanceName,"ControlCode", ControlValue,"EnableFlags", Properties->EnableFlags);
            }
            break;
        case EVENT_TRACE_CONTROL_INCREMENT_FILE:
            strncpy(ControlValue,ControlValues[4], strlen(ControlValues[4]) + 1);
            LOQ_zero("Trace", "ius","TraceHandle", TraceHandle,"InstanceName", InstanceName,"ControlCode", ControlValue );
            break;
        case EVENT_TRACE_CONTROL_CONVERT_TO_REALTIME:
            strncpy(ControlValue,ControlValues[5], strlen(ControlValues[5]) + 1);
            LOQ_zero("Trace", "ius","TraceHandle", TraceHandle,"InstanceName", InstanceName,"ControlCode", ControlValue );
            break;
        default:
            snprintf(ControlValue,UNSIGNED_LONG_STRING_SIZE,"%lu",ControlCode);
            LOQ_zero("Trace", "ius","TraceHandle", TraceHandle,"InstanceName", InstanceName,"ControlCode", ControlValue );
    } 
    free(ControlValue);
	return ret;
}

HOOKDEF(ULONG, WINAPI, EnableTrace,
	_In_ ULONG Enable,
	_In_ ULONG EnableFlag,
	_In_ ULONG EnableLevel,
	_In_ LPCGUID ControlGuid,
	_In_ TRACEHANDLE SessionHandle
) {
    DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked EnableTrace\n");
    char *S_ControlGuid = NULL;
    S_ControlGuid = malloc(sizeof(char)*(GUID_SIZE+1));
    string_to_guid(S_ControlGuid,*ControlGuid);
	ULONG ret = Old_EnableTrace(Enable,EnableFlag,EnableLevel,ControlGuid,SessionHandle);
	LOQ_zero("Trace", "iiiis", "Enable", Enable, "EnableFlag", EnableFlag, "EnableLevel", EnableLevel, "TraceHandle", SessionHandle, "ControlGUID", S_ControlGuid);
    free(S_ControlGuid);
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
	DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked EnableTraceEx\n");
    char *S_ProviderId = NULL;
    S_ProviderId = malloc(sizeof(char)*(GUID_SIZE+1));
    string_to_guid(S_ProviderId,*ProviderId);
	char *S_SourceId = NULL;
    if(SourceId != &GUID_NULL){
        S_SourceId = malloc(sizeof(char)*(GUID_SIZE+1));
        string_to_guid(S_SourceId,*SourceId);
    }
    else {
		snprintf(S_SourceId, UNSIGNED_LONG_STRING_SIZE, "%s", "NULL");
    }
	ULONG ret = Old_EnableTraceEx(ProviderId,SourceId,TraceHandle,IsEnabled,Level,MatchAnyKeyword,MatchAllKeyword,EnableProperty,EnableFilterDesc);
	LOQ_zero("Trace","ssiiilli", "ProviderId", S_ProviderId, "SourceId", S_SourceId, "TraceHandle", TraceHandle, "Enabled", IsEnabled, "Level", Level,
     "MatchAnyKeyword", MatchAnyKeyword, "MatchAllKeyword", MatchAllKeyword, "EnableProperty", EnableProperty);
    free(S_ProviderId);
	free(S_SourceId);
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
	DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked EnableTraceEx2\n");
    char *S_ProviderId = NULL;
    S_ProviderId = malloc(sizeof(char)*(GUID_SIZE+1));
    string_to_guid(S_ProviderId,*ProviderId);
	ULONG ret = Old_EnableTraceEx2(TraceHandle,ProviderId,ControlCode,Level,MatchAnyKeyword,MatchAllKeyword,Timeout,EnableParameters);
	char *ControlValues[] = {"DISABLE","ENABLE","CAPTURE"};
    char *ControlValue = NULL;
    ControlValue = malloc(sizeof(char)*UNSIGNED_LONG_STRING_SIZE);
    switch(ControlCode){
        case EVENT_CONTROL_CODE_DISABLE_PROVIDER:
            strncpy(ControlValue,ControlValues[0], strlen(ControlValues[0]) + 1);
            break;
        case EVENT_CONTROL_CODE_ENABLE_PROVIDER:
            strncpy(ControlValue,ControlValues[1], strlen(ControlValues[1]) + 1);
            break;
        case EVENT_CONTROL_CODE_CAPTURE_STATE:
            strncpy(ControlValue,ControlValues[2], strlen(ControlValues[2]) + 1);
            break;
        default:
            snprintf(ControlValue,UNSIGNED_LONG_STRING_SIZE,"%lu",ControlCode);
    } 
    LOQ_zero("Trace","sisilll", "ProviderId", S_ProviderId, "TraceHandle", TraceHandle, "ControlCode", ControlValue, "Level", Level,
     "MatchAnyKeyword", MatchAnyKeyword, "MatchAllKeyword", MatchAllKeyword, "Timeout", Timeout);
    free(ControlValue);
	return ret;
}

HOOKDEF(TRACEHANDLE, WINAPI, OpenTraceA,
	_Inout_ PEVENT_TRACE_LOGFILEA Logfile
){
	DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked OpenTrace\n");
	TRACEHANDLE ret = Old_OpenTraceA(Logfile);
	LOQ_void("Trace", "ss","LogFileName",Logfile->LogFileName,"LoggerName", Logfile->LoggerName); 
	return ret;
}

HOOKDEF(TRACEHANDLE, WINAPI, OpenTraceW,
	_Inout_ PEVENT_TRACE_LOGFILEW Logfile
) {
	DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked OpenTrace\n");
	TRACEHANDLE ret = Old_OpenTraceW(Logfile);
	LOQ_void("Trace", "uu","LogFileName",Logfile->LogFileName,"LoggerName", Logfile->LoggerName); 
	return ret;
}

HOOKDEF(ULONG, WINAPI, QueryAllTracesA,
	_Out_ PEVENT_TRACE_PROPERTIES* PropertyArray,
	_In_ ULONG PropertyArrayCount,
	_Out_ PULONG LoggerCount
) {
	DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked QueryAllTraces\n");
	ULONG ret = Old_QueryAllTracesA(PropertyArray,PropertyArrayCount,LoggerCount);
	return ret;
}

HOOKDEF(ULONG, WINAPI, QueryAllTracesW,
	_Out_ PEVENT_TRACE_PROPERTIES* PropertyArray,
	_In_ ULONG PropertyArrayCount,
	_Out_ PULONG LoggerCount
){
	DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked QueryAllTraces\n");
	ULONG ret = Old_QueryAllTracesW(PropertyArray,PropertyArrayCount,LoggerCount);
	return ret;
}

HOOKDEF(ULONG, WINAPI, QueryTraceA,
	_In_ TRACEHANDLE TraceHandle,
	_In_ LPCTSTR InstanceName,
	_Inout_ PEVENT_TRACE_PROPERTIES Properties
) {
	DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked QueryTrace\n");
	ULONG ret = Old_QueryTraceA(TraceHandle,InstanceName,Properties);
	LOQ_zero("Trace", "is","TraceHandle", TraceHandle,"InstanceName", InstanceName);
	return ret;
}

HOOKDEF(ULONG, WINAPI, QueryTraceW,
	_In_ TRACEHANDLE TraceHandle,
	_In_ LPCWSTR InstanceName,
	_Inout_ PEVENT_TRACE_PROPERTIES Properties
) {
	DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked QueryTrace\n");
	ULONG ret = Old_QueryTraceW(TraceHandle,InstanceName,Properties);
	LOQ_zero("Trace", "iu","TraceHandle", TraceHandle,"InstanceName", InstanceName);
	return ret;
}

HOOKDEF(ULONG, WINAPI, StartTraceA,
	_Out_ PTRACEHANDLE TraceHandle,
	_In_ LPCTSTR InstanceName,
	_Inout_ PEVENT_TRACE_PROPERTIES Properties
) {
	DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked StartTrace\n");
	ULONG ret = Old_StartTraceA(TraceHandle,InstanceName,Properties);
    char *S_GUID = NULL;
    S_GUID = malloc(sizeof(char)*(GUID_SIZE+1));
    string_to_guid(S_GUID,Properties->Wnode.Guid);
    if(ret == ERROR_SUCCESS)
	    LOQ_zero("Trace", "iss","TraceHandle", TraceHandle,"InstanceName", InstanceName, "GUID", S_GUID);
    else
        LOQ_zero("Trace", "ss","InstanceName", InstanceName, "GUID", S_GUID);
    free(S_GUID);
	return ret;
}

HOOKDEF(ULONG, WINAPI, StartTraceW,
	_Out_ PTRACEHANDLE TraceHandle,
	_In_ LPCWSTR InstanceName,
	_Inout_ PEVENT_TRACE_PROPERTIES Properties
) {
	DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked StartTrace\n");
	ULONG ret = Old_StartTraceW(TraceHandle,InstanceName,Properties);
	char *S_GUID = NULL;
    S_GUID = malloc(sizeof(char)*(GUID_SIZE+1));
    string_to_guid(S_GUID,Properties->Wnode.Guid);
    if(ret == ERROR_SUCCESS)
	    LOQ_zero("Trace", "ius","TraceHandle", TraceHandle,"InstanceName", InstanceName, "GUID", S_GUID);
    else
        LOQ_zero("Trace", "us","InstanceName", InstanceName, "GUID", S_GUID);
    free(S_GUID);
	return ret;
}

HOOKDEF(ULONG, WINAPI, StopTraceA,
	_In_ TRACEHANDLE TraceHandle,
	_In_ LPCTSTR InstanceName,
	_Out_ PEVENT_TRACE_PROPERTIES Properties
) {
	DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked StopTrace\n");
	ULONG ret = Old_StopTraceA(TraceHandle,InstanceName,Properties);
	char *S_GUID = NULL;
    S_GUID = malloc(sizeof(char)*(GUID_SIZE+1));
    string_to_guid(S_GUID,Properties->Wnode.Guid);
    if(ret == ERROR_SUCCESS)
	    LOQ_zero("Trace", "iss","TraceHandle", TraceHandle,"InstanceName", InstanceName, "GUID", S_GUID);
    else
        LOQ_zero("Trace", "ss","InstanceName", InstanceName, "GUID", S_GUID);
    free(S_GUID);
	return ret;
}

HOOKDEF(ULONG, WINAPI, StopTraceW,
	_In_ TRACEHANDLE TraceHandle,
	_In_ LPCWSTR InstanceName,
	_Out_ PEVENT_TRACE_PROPERTIES Properties
) {
	DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked StopTrace\n");
	ULONG ret = Old_StopTraceW(TraceHandle,InstanceName,Properties);
	char *S_GUID = NULL;
    S_GUID = malloc(sizeof(char)*(GUID_SIZE+1));
    string_to_guid(S_GUID,Properties->Wnode.Guid);
    if(ret == ERROR_SUCCESS)
	    LOQ_zero("Trace", "ius","TraceHandle", TraceHandle,"InstanceName", InstanceName, "GUID", S_GUID);
    else
        LOQ_zero("Trace", "us","InstanceName", InstanceName, "GUID", S_GUID);
    free(S_GUID);
	return ret;
}

HOOKDEF(ULONG, WINAPI, UpdateTraceA,
	_In_ TRACEHANDLE TraceHandle,
	_In_ LPCTSTR InstanceName,
	_Inout_ PEVENT_TRACE_PROPERTIES Properties
) {
	DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked UpdateTrace\n");
	ULONG ret = Old_UpdateTraceA(TraceHandle,InstanceName,Properties);
	if(Properties->LogFileNameOffset != 0){
        char *NewLogFileName = NULL;
        NewLogFileName = malloc(sizeof(char)*1025);
        strncpy(NewLogFileName, &Properties + Properties->LogFileNameOffset, strlen(&Properties + Properties->LogFileNameOffset) + 1);
        LOQ_zero("Trace", "isis","TraceHandle", TraceHandle,"InstanceName", InstanceName,"EnableFlags", Properties->EnableFlags, "NewLogFileName", NewLogFileName ); 
        free(NewLogFileName);
    }
    else{
        LOQ_zero("Trace", "isi","TraceHandle", TraceHandle,"InstanceName", InstanceName,"EnableFlags", Properties->EnableFlags); 
    }
	return ret;
}

HOOKDEF(ULONG, WINAPI, UpdateTraceW,
	_In_ TRACEHANDLE TraceHandle,
	_In_ LPCWSTR InstanceName,
	_Inout_ PEVENT_TRACE_PROPERTIES Properties
) {
	DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked UpdateTrace\n");
	ULONG ret = Old_UpdateTraceW(TraceHandle,InstanceName,Properties);
	if(Properties->LogFileNameOffset != 0){
        char *NewLogFileName = NULL;
        NewLogFileName = malloc(sizeof(char)*1025);
        strncpy(NewLogFileName, &Properties + Properties->LogFileNameOffset, strlen(&Properties + Properties->LogFileNameOffset) + 1);
        LOQ_zero("Trace", "iuis","TraceHandle", TraceHandle,"InstanceName", InstanceName,"EnableFlags", Properties->EnableFlags, "NewLogFileName", NewLogFileName ); 
        free(NewLogFileName);
    }
    else{
        LOQ_zero("Trace", "iui","TraceHandle", TraceHandle,"InstanceName", InstanceName,"EnableFlags", Properties->EnableFlags); 
    }
	return ret;
}

HOOKDEF(LONG, WINAPI, CveEventWrite,
	_In_ PCWSTR CveId,
	_In_opt_ PCWSTR AdditionalDetails
) {
	DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked CveEventWrite\n");
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
	DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked EventAccessControl\n");
	ULONG ret = Old_EventAccessControl(Guid,Operation,Sid,Rights,AllowOrDeny);
	char *S_GUID = NULL;
    S_GUID = malloc(sizeof(char)*(GUID_SIZE+1));
    string_to_guid(S_GUID,*Guid);
    WCHAR *S_SID = NULL;
	PISID SID_Struct = Sid;
    S_SID = malloc((14 + SID_Struct->SubAuthorityCount * 11)*sizeof(WCHAR));
    string_to_sid(Sid,S_SID);
	LOQ_zero("Trace", "sluli", "GUID", S_GUID, "Operation", Operation, "SID", S_SID, "Rights", Rights, "Allow_OR_Deny", AllowOrDeny);
    free(S_SID);
	return ret;
}

HOOKDEF(ULONG, WINAPI, EventAccessQuery,
	_In_ LPGUID Guid,
	_Inout_ PSECURITY_DESCRIPTOR Buffer,
	_Inout_ PULONG BufferSize
) {
	DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked EventAccessQuery\n");
	ULONG ret = Old_EventAccessQuery(Guid,Buffer,BufferSize);
	char *S_GUID = NULL;
    S_GUID = malloc(sizeof(char)*(GUID_SIZE+1));
    string_to_guid(S_GUID,*Guid);
	LOQ_zero("Trace", "s", "GUID", S_GUID);
	return ret;
}

HOOKDEF(ULONG, WINAPI, EventAccessRemove,
	_In_ LPGUID Guid
) {
	DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked EventAccessRemove\n");
	ULONG ret = Old_EventAccessRemove(Guid);
	char *S_GUID = NULL;
    S_GUID = malloc(sizeof(char)*(GUID_SIZE+1));
    string_to_guid(S_GUID,*Guid);
	LOQ_zero("Trace", "s", "GUID", S_GUID);
	return ret;
}

HOOKDEF(ULONG, WINAPI, EventRegister,
	_In_ LPCGUID ProviderId,
	_In_opt_ PENABLECALLBACK EnableCallback,
	_In_opt_ PVOID CallbackContext,
	_Out_ PREGHANDLE RegHandle
) {
	DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked EventRegister\n");
	ULONG ret = Old_EventRegister(ProviderId,EnableCallback,CallbackContext,RegHandle);
	char *S_ProviderID = NULL;
    S_ProviderID = malloc(sizeof(char)*(GUID_SIZE+1));
    string_to_guid(S_ProviderID ,*ProviderId);
	LOQ_zero("Trace", "s", "ProviderId", S_ProviderID );
	return ret;
}

HOOKDEF(ULONG, WINAPI, EventSetInformation,
	_In_ REGHANDLE RegHandle,
	_In_ EVENT_INFO_CLASS InformationClass,
	_In_ PVOID EventInformation,
	_In_ ULONG InformationLength
) {
	DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked EventSetInformation\n");
	ULONG ret = Old_EventSetInformation(RegHandle,InformationClass,EventInformation,InformationLength);
    char *InformationClasses[] = {"TRACKINFO","RESERVED","SETTRAITS","DESCRIPTORTYPE","INVALID"};
    char *S_InformationClass = NULL;
    S_InformationClass = malloc(sizeof(char)*UNSIGNED_LONG_STRING_SIZE);
    switch(InformationClass){
        case EventProviderBinaryTrackInfo:
            strncpy(S_InformationClass,InformationClasses[0], strlen(InformationClasses[0]) + 1);
            break;
        case EventProviderSetReserved1:
            strncpy(S_InformationClass,InformationClasses[1], strlen(InformationClasses[1]) + 1);
            break;
        case EventProviderSetTraits:
            strncpy(S_InformationClass,InformationClasses[2], strlen(InformationClasses[2]) + 1);
            break;
        case EventProviderUseDescriptorType:
            strncpy(S_InformationClass,InformationClasses[3], strlen(InformationClasses[3]) + 1);
            break;
        case MaxEventInfo:
            strncpy(S_InformationClass,InformationClasses[4], strlen(InformationClasses[4]) + 1);
            break;
        default:
            snprintf(S_InformationClass,UNSIGNED_LONG_STRING_SIZE,"%lu",InformationClass);
    } 

	LOQ_zero("Trace", "lsb", "Handle", RegHandle, "Information_Class", InformationClass, "EventInformation", InformationLength, EventInformation);
	return ret;
}

HOOKDEF(ULONG, WINAPI, EventUnregister,
	_In_ REGHANDLE RegHandle
) {
	DebuggerOutput("[***** DEBUG MESSAGE - EXTENDED HOOKS *****] Hooked EventUnregister\n");
	ULONG ret = Old_EventUnregister(RegHandle);
	LOQ_zero("Trace", "l", "Handle", RegHandle );
	return ret;
}