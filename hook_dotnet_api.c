/*
CAPE - Config And Payload Extraction
Copyright(C) 2026 CAPE Sandbox developers

This program is free software : you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.If not, see <http://www.gnu.org/licenses/>.
*/

// .NET "interesting API" tracing, the managed counterpart of the Go allowlist in
// hook_go.c.
//
// Names come from the compileMethod hook (hook_clr.c): every method the JIT
// compiles is matched against the allowlist below and, on a hit, gets a
// persistent software breakpoint on its native entry. The breakpoint callback
// decodes the arguments per the managed calling convention and emits exactly
// one "DotNetApi" behaviour-log record per call in the entry's category.
//
// Coverage note: BCL code is normally precompiled (NGEN on Framework, R2R on
// Core) and never passes through compileMethod. DllMain therefore calls
// DotNetApiDisablePrecompiledImages() before the runtime can start, which sets
// the CLR knobs that turn those images off so the whole BCL is JIT compiled.
// A process whose CLR was already running when the monitor arrived keeps its
// precompiled code; only tiered re-JITs on Core are seen there.
//
// Overloads: the name resolver provides no signature, so an entry may fire for
// several overloads of the same name. Argument decoders therefore validate
// what they read (string: MethodTable learned from an unambiguous call site or
// structural sanity; byte[] for Assembly.Load: PE magic) and log the field as
// empty when the object does not look like the expected type.

#include <stdio.h>
#include <stdint.h>
#include "hooking.h"
#include "log.h"
#include "misc.h"
#include "lookup.h"
#include "config.h"
#include "CAPE\CAPE.h"
#include "CAPE\Debugger.h"
#include "hook_dotnet_api.h"

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern lookup_t SoftBPs;

// Managed object layout, identical on every CLR from 2.0 to 10:
//   System.String: [MethodTable*][int32 Length][WCHAR Chars[Length]][WCHAR 0]
//   T[]:           [MethodTable*][size_t Length ][T Data[Length]]
#define MANAGED_STRING_LENGTH_OFFSET	(sizeof(PVOID))
#define MANAGED_STRING_CHARS_OFFSET		(sizeof(PVOID) + sizeof(DWORD))
#define MANAGED_ARRAY_LENGTH_OFFSET		(sizeof(PVOID))
#define MANAGED_ARRAY_DATA_OFFSET		(2 * sizeof(PVOID))

// CLR MethodTable m_dwFlags (offset 0) across Framework 2.0-4.8 and Core/5-10:
// bit 31 (0x80000000) is enum_flag_HasComponentSize (set only on System.String
// and Array types); the low 16 bits hold the element size in bytes (2 for
// WCHAR in System.String, 1 for byte[]/sbyte[]/bool[]).
#define MT_FLAGS_HAS_COMPONENT_SIZE		0x80000000U
#define MT_FLAGS_COMPONENT_SIZE_MASK	0x8000FFFFU
#define MT_FLAGS_STRING					(MT_FLAGS_HAS_COMPONENT_SIZE | sizeof(WCHAR))
#define MT_FLAGS_BYTE_ARRAY				(MT_FLAGS_HAS_COMPONENT_SIZE | sizeof(BYTE))

// Caps. Strings longer than this are truncated in the log, arrays larger than
// DOTNET_API_BUFFER_LOG_MAX are truncated in the log (loq applies its own
// buffer_log_max on top), and Assembly.Load payloads above
// DOTNET_ASSEMBLY_DUMP_MAX are not dumped.
#define DOTNET_API_STRING_MAX_RAW_LEN	0x100000	// WCHAR sanity bound before NUL terminator check
#define DOTNET_API_STRING_LOG_MAX		4096		// WCHARs
#define DOTNET_API_STRING_PROBE_MAX		2048		// WCHARs accepted by structural probing
#define DOTNET_API_BUFFER_LOG_MAX		0x10000		// bytes
#define DOTNET_ASSEMBLY_DUMP_MAX		0x4000000	// 64 MB
#define DOTNET_ASSEMBLY_DUMP_LIMIT		16			// payload dumps per process

// Managed calling convention, argument slots as seen at function entry.
//   x64: RCX, RDX, R8, R9, then [RSP + 8 (return address) + 0x20 (home space)]
//   x86: ECX, EDX, then the stack. The x86 managed convention's stack order is
//        not decoded here: a slot >= 2 is read only when the overload has a
//        single stack argument (StackArgsX86 == 1), where it is [ESP + 4].
#define DOTNET_API_MAX_ARGS				3

typedef enum {
	DNARG_NONE = 0,
	DNARG_STRING,			// System.String, logged as 'U'
	DNARG_STRING_PROBE,		// System.String if it passes validation, else empty (ambiguous overload)
	DNARG_BYTES,			// byte[], logged as 'b'
	DNARG_BYTES_PE_DUMP,	// byte[] starting with 'MZ': dumped as DOTNET_ASSEMBLY, logged as length
	DNARG_INT				// int32, logged as 'i'
} dotnet_arg_kind_t;

typedef struct _DOTNET_API_ENTRY {
	const char *Class;			// "Namespace.Class" as the resolver reports it
	const char *Method;
	const char *Category;		// behaviour log category
	BOOLEAN Noisy;				// only registered with dotnet-api-strings=1
	BYTE StackArgsX86;			// stack argument count of the targeted overload on x86
	BYTE ArgCount;
	BYTE ArgSlot[DOTNET_API_MAX_ARGS];
	BYTE ArgKind[DOTNET_API_MAX_ARGS];
	const char *ArgName[DOTNET_API_MAX_ARGS];
	volatile LONG LogIndex;		// lazily allocated behaviour-log id, one per entry
} DOTNET_API_ENTRY;

// Slot numbering counts 'this' as slot 0 for instance methods; static methods
// start their first parameter at slot 0.
static DOTNET_API_ENTRY g_dotnet_api_table[] = {
	// network
	{ "System.Net.WebClient", "DownloadString",	"network", FALSE, 0, 1, {1},	{DNARG_STRING_PROBE},				{"Url"} },
	{ "System.Net.WebClient", "DownloadData",	"network", FALSE, 0, 1, {1},	{DNARG_STRING_PROBE},				{"Url"} },
	{ "System.Net.WebClient", "DownloadFile",	"network", FALSE, 1, 2, {1, 2},	{DNARG_STRING_PROBE, DNARG_STRING_PROBE}, {"Url", "FileName"} },
	{ "System.Net.WebClient", "UploadString",	"network", FALSE, 1, 2, {1, 2},	{DNARG_STRING_PROBE, DNARG_STRING_PROBE}, {"Url", "Data"} },
	{ "System.Net.WebClient", "UploadData",		"network", FALSE, 1, 2, {1, 2},	{DNARG_STRING_PROBE, DNARG_BYTES},	{"Url", "Data"} },
	{ "System.Net.WebRequest", "Create",		"network", FALSE, 0, 1, {0},	{DNARG_STRING_PROBE},				{"Url"} },
	{ "System.Net.Http.HttpClient", "GetAsync",			"network", FALSE, 0, 1, {1}, {DNARG_STRING_PROBE},		{"Url"} },
	{ "System.Net.Http.HttpClient", "GetStringAsync",	"network", FALSE, 0, 1, {1}, {DNARG_STRING_PROBE},		{"Url"} },
	{ "System.Net.Http.HttpClient", "GetByteArrayAsync","network", FALSE, 0, 1, {1}, {DNARG_STRING_PROBE},		{"Url"} },
	{ "System.Net.Http.HttpClient", "PostAsync",		"network", FALSE, 1, 1, {1}, {DNARG_STRING_PROBE},		{"Url"} },
	{ "System.Net.Sockets.TcpClient", ".ctor",	"network", FALSE, 1, 2, {1, 2},	{DNARG_STRING_PROBE, DNARG_INT},	{"Host", "Port"} },
	{ "System.Net.Dns", "GetHostAddresses",		"network", FALSE, 0, 1, {0},	{DNARG_STRING_PROBE},				{"Host"} },
	{ "System.Net.Dns", "GetHostEntry",			"network", FALSE, 0, 1, {0},	{DNARG_STRING_PROBE},				{"Host"} },
	// process
	{ "System.Diagnostics.Process", "Start",	"process", FALSE, 0, 2, {0, 1},	{DNARG_STRING_PROBE, DNARG_STRING_PROBE}, {"FileName", "Arguments"} },
	// loader
	{ "System.Reflection.Assembly", "Load",		"loader", FALSE, 0, 1, {0},		{DNARG_BYTES_PE_DUMP},				{"AssemblySize"} },
	{ "System.Reflection.Assembly", "LoadFile",	"loader", FALSE, 0, 1, {0},		{DNARG_STRING},						{"Path"} },
	{ "System.Reflection.Assembly", "LoadFrom",	"loader", FALSE, 0, 1, {0},		{DNARG_STRING_PROBE},				{"Path"} },
	{ "System.AppDomain", "Load",				"loader", FALSE, 0, 1, {1},		{DNARG_BYTES_PE_DUMP},				{"AssemblySize"} },
	// reflection (method only; the target name lives in runtime-private structures)
	{ "System.Reflection.MethodBase", "Invoke",	"reflection", FALSE, 0, 0, {0}, {DNARG_NONE}, {NULL} },
	{ "System.Reflection.RuntimeMethodInfo", "Invoke", "reflection", FALSE, 0, 0, {0}, {DNARG_NONE}, {NULL} },
	{ "System.Type", "InvokeMember",			"reflection", FALSE, 0, 1, {1},	{DNARG_STRING},						{"Name"} },
	{ "System.Activator", "CreateInstance",		"reflection", FALSE, 0, 0, {0}, {DNARG_NONE}, {NULL} },
	// crypto
	{ "System.Security.Cryptography.SymmetricAlgorithm", "CreateDecryptor", "crypto", FALSE, 1, 2, {1, 2}, {DNARG_BYTES, DNARG_BYTES}, {"Key", "IV"} },
	{ "System.Security.Cryptography.SymmetricAlgorithm", "CreateEncryptor", "crypto", FALSE, 1, 2, {1, 2}, {DNARG_BYTES, DNARG_BYTES}, {"Key", "IV"} },
	{ "System.Security.Cryptography.RijndaelManaged", "CreateDecryptor", "crypto", FALSE, 1, 2, {1, 2}, {DNARG_BYTES, DNARG_BYTES}, {"Key", "IV"} },
	{ "System.Security.Cryptography.AesCryptoServiceProvider", "CreateDecryptor", "crypto", FALSE, 1, 2, {1, 2}, {DNARG_BYTES, DNARG_BYTES}, {"Key", "IV"} },
	{ "System.Security.Cryptography.AesManaged", "CreateDecryptor", "crypto", FALSE, 1, 2, {1, 2}, {DNARG_BYTES, DNARG_BYTES}, {"Key", "IV"} },
	{ "System.Security.Cryptography.TripleDESCryptoServiceProvider", "CreateDecryptor", "crypto", FALSE, 1, 2, {1, 2}, {DNARG_BYTES, DNARG_BYTES}, {"Key", "IV"} },
	{ "System.Security.Cryptography.SymmetricAlgorithm", "set_Key", "crypto", FALSE, 0, 1, {1}, {DNARG_BYTES}, {"Key"} },
	{ "System.Security.Cryptography.SymmetricAlgorithm", "set_IV",  "crypto", FALSE, 0, 1, {1}, {DNARG_BYTES}, {"IV"} },
	{ "System.Security.Cryptography.Rfc2898DeriveBytes", ".ctor", "crypto", FALSE, 2, 1, {1}, {DNARG_STRING_PROBE}, {"Password"} },
	// filesystem / registry
	{ "System.IO.File", "WriteAllBytes",		"filesystem", FALSE, 0, 2, {0, 1}, {DNARG_STRING, DNARG_BYTES},		{"Path", "Data"} },
	{ "System.IO.File", "WriteAllText",			"filesystem", FALSE, 0, 2, {0, 1}, {DNARG_STRING, DNARG_STRING_PROBE},	{"Path", "Text"} },
	{ "System.IO.File", "Copy",					"filesystem", FALSE, 0, 2, {0, 1}, {DNARG_STRING, DNARG_STRING},		{"Source", "Destination"} },
	{ "System.IO.File", "Move",					"filesystem", FALSE, 0, 2, {0, 1}, {DNARG_STRING, DNARG_STRING},		{"Source", "Destination"} },
	{ "System.IO.File", "Delete",				"filesystem", FALSE, 0, 1, {0},	   {DNARG_STRING},						{"Path"} },
	{ "Microsoft.Win32.RegistryKey", "SetValue","registry",   FALSE, 1, 1, {1},	   {DNARG_STRING},						{"ValueName"} },
	// string helpers: high volume, opt-in via dotnet-api-strings=1
	{ "System.Convert", "FromBase64String",		"strings", TRUE, 0, 1, {0},		{DNARG_STRING},						{"Input"} },
	{ "System.Text.Encoding", "GetString",		"strings", TRUE, 0, 1, {1},		{DNARG_BYTES},						{"Bytes"} },
};

#define DOTNET_API_TABLE_SIZE (sizeof(g_dotnet_api_table) / sizeof(g_dotnet_api_table[0]))

// Native entry -> table entry. Written before the breakpoint is armed, never removed.
static lookup_t g_dotnet_api_bps;

// System.String MethodTable, learned from the first DNARG_STRING argument that
// decodes cleanly. Lets DNARG_STRING_PROBE reject non-string objects exactly
// instead of structurally. Zero until learned.
static PVOID volatile g_string_methodtable;

static volatile LONG g_assembly_dump_count;
static PVOID volatile g_last_assembly_data;
static volatile LONG g_last_assembly_length;

typedef struct _DECODED_ARG {
	dotnet_arg_kind_t Kind;
	BOOL Decoded;
	int Length;		// WCHARs for strings, bytes for arrays
	PVOID Data;
	int Value;
} DECODED_ARG;

//**************************************************************************************
static ULONG_PTR GetManagedArg(PCONTEXT Context, unsigned int Slot, unsigned int StackArgsX86)
//**************************************************************************************
{
	ULONG_PTR *StackArg;

#ifdef _WIN64
	(void)StackArgsX86;
	switch (Slot) {
	case 0: return Context->Rcx;
	case 1: return Context->Rdx;
	case 2: return Context->R8;
	case 3: return Context->R9;
	default:
		StackArg = (ULONG_PTR *)(Context->Rsp + sizeof(PVOID) + 0x20 + (Slot - 4) * sizeof(PVOID));
		break;
	}
#else
	switch (Slot) {
	case 0: return Context->Ecx;
	case 1: return Context->Edx;
	case 2:
		if (StackArgsX86 != 1)
			return 0;
		StackArg = (ULONG_PTR *)(Context->Esp + sizeof(PVOID));
		break;
	default:
		return 0;
	}
#endif

	if (our_isbadreadptr(StackArg, sizeof(ULONG_PTR)))
		return 0;

	return *StackArg;
}

//**************************************************************************************
static BOOL LooksLikeText(PWCHAR Chars, int Length)
//**************************************************************************************
{
	int i, n = Length < 32 ? Length : 32;

	if (Length < 1)
		return FALSE;

	for (i = 0; i < n; i++) {
		WCHAR c = Chars[i];
		if (c < 0x20 && c != L'\t' && c != L'\r' && c != L'\n')
			return FALSE;
	}

	return TRUE;
}

//**************************************************************************************
static BOOL ReadManagedString(ULONG_PTR Object, BOOL Probe, DECODED_ARG *Out)
//**************************************************************************************
{
	int RawLength, Length;
	PWCHAR Chars;
	PVOID MethodTable, KnownMT;

	if (!Object || (Object & (sizeof(PVOID) - 1)) != 0)
		return FALSE;

	if (our_isbadreadptr((PVOID)Object, MANAGED_STRING_CHARS_OFFSET + sizeof(WCHAR)))
		return FALSE;

	MethodTable = *(PVOID *)Object;
	if (!MethodTable || ((ULONG_PTR)MethodTable & (sizeof(PVOID) - 1)) != 0 ||
	    our_isbadreadptr(MethodTable, sizeof(DWORD)))
		return FALSE;

	if ((*(DWORD *)MethodTable & MT_FLAGS_COMPONENT_SIZE_MASK) != MT_FLAGS_STRING)
		return FALSE;

	KnownMT = g_string_methodtable;
	if (KnownMT && MethodTable != KnownMT)
		return FALSE;

	RawLength = *(int *)(Object + MANAGED_STRING_LENGTH_OFFSET);
	if (RawLength < 0 || RawLength > DOTNET_API_STRING_MAX_RAW_LEN)
		return FALSE;

	Chars = (PWCHAR)(Object + MANAGED_STRING_CHARS_OFFSET);
	if (our_isbadreadptr(Chars, (ULONG)(((SIZE_T)RawLength + 1) * sizeof(WCHAR))) || Chars[RawLength] != L'\0')
		return FALSE;

	if (Probe && !KnownMT) {
		if (RawLength > DOTNET_API_STRING_PROBE_MAX || (RawLength > 0 && !LooksLikeText(Chars, RawLength)))
			return FALSE;
	}

	if (!Probe && !KnownMT)
		InterlockedCompareExchangePointer(&g_string_methodtable, MethodTable, NULL);

	Length = RawLength > DOTNET_API_STRING_LOG_MAX ? DOTNET_API_STRING_LOG_MAX : RawLength;

	Out->Kind = DNARG_STRING;
	Out->Decoded = TRUE;
	Out->Length = Length;
	Out->Data = Chars;
	return TRUE;
}

//**************************************************************************************
static BOOL ReadManagedByteArray(ULONG_PTR Object, SIZE_T MaxLength, BOOL TruncateToMax, DECODED_ARG *Out)
//**************************************************************************************
{
	ULONG_PTR RawLength;
	SIZE_T Length;
	PBYTE Data;
	PVOID MethodTable;

	if (!Object || (Object & (sizeof(PVOID) - 1)) != 0)
		return FALSE;

	if (our_isbadreadptr((PVOID)Object, MANAGED_ARRAY_DATA_OFFSET))
		return FALSE;

	MethodTable = *(PVOID *)Object;
	if (!MethodTable || ((ULONG_PTR)MethodTable & (sizeof(PVOID) - 1)) != 0 ||
	    our_isbadreadptr(MethodTable, sizeof(DWORD)))
		return FALSE;

	if ((*(DWORD *)MethodTable & MT_FLAGS_COMPONENT_SIZE_MASK) != MT_FLAGS_BYTE_ARRAY)
		return FALSE;

	RawLength = *(ULONG_PTR *)(Object + MANAGED_ARRAY_LENGTH_OFFSET);
	if (RawLength > DOTNET_ASSEMBLY_DUMP_MAX)
		return FALSE;

	if (RawLength > MaxLength) {
		if (!TruncateToMax)
			return FALSE;
		Length = MaxLength;
	}
	else {
		Length = (SIZE_T)RawLength;
	}

	Data = (PBYTE)(Object + MANAGED_ARRAY_DATA_OFFSET);
	if (Length && our_isbadreadptr(Data, (ULONG)Length))
		return FALSE;

	Out->Kind = DNARG_BYTES;
	Out->Decoded = TRUE;
	Out->Length = (int)Length;
	Out->Data = Data;
	return TRUE;
}

// Returns TRUE when the array holds a PE image (the Assembly.Load(byte[]) /
// AppDomain.Load(byte[]) overloads); other overloads of the same name pass a
// string or an AssemblyName and are skipped.
//**************************************************************************************
static BOOL DumpManagedAssembly(DECODED_ARG *Arg)
//**************************************************************************************
{
	if (Arg->Length < 2 || *(PWORD)Arg->Data != IMAGE_DOS_SIGNATURE)
		return FALSE;

	// AppDomain.Load(byte[]) delegates to Assembly.Load(byte[], ...) on the same
	// buffer; avoid dumping and logging the same in-memory PE twice.
	if (g_last_assembly_data == Arg->Data && g_last_assembly_length == Arg->Length)
		return FALSE;

	if (InterlockedIncrement(&g_assembly_dump_count) > DOTNET_ASSEMBLY_DUMP_LIMIT) {
		InterlockedDecrement(&g_assembly_dump_count);
		DebugOutput("DotNetApi: assembly dump limit (%d) reached, skipping 0x%p.\n", DOTNET_ASSEMBLY_DUMP_LIMIT, Arg->Data);
		return TRUE;
	}

	SetCapeMetaData(DOTNET_ASSEMBLY, 0, NULL, NULL);
	if (DumpMemoryRaw(Arg->Data, (SIZE_T)Arg->Length)) {
		g_last_assembly_data = Arg->Data;
		g_last_assembly_length = Arg->Length;
		DebugOutput("DotNetApi: dumped in-memory assembly at 0x%p (size 0x%x).\n", Arg->Data, Arg->Length);
	}
	else
		InterlockedDecrement(&g_assembly_dump_count);

	return TRUE;
}

//**************************************************************************************
static void DecodeArg(DOTNET_API_ENTRY *Entry, PCONTEXT Context, unsigned int i, DECODED_ARG *Arg)
//**************************************************************************************
{
	ULONG_PTR Raw = GetManagedArg(Context, Entry->ArgSlot[i], Entry->StackArgsX86);

	memset(Arg, 0, sizeof(*Arg));
	Arg->Kind = (dotnet_arg_kind_t)Entry->ArgKind[i];

	switch (Entry->ArgKind[i]) {
	case DNARG_STRING:
		if (!ReadManagedString(Raw, FALSE, Arg))
			Arg->Length = 0, Arg->Data = NULL;
		break;
	case DNARG_STRING_PROBE:
		Arg->Kind = DNARG_STRING;
		if (!ReadManagedString(Raw, TRUE, Arg))
			Arg->Length = 0, Arg->Data = NULL;
		break;
	case DNARG_BYTES:
		if (!ReadManagedByteArray(Raw, DOTNET_API_BUFFER_LOG_MAX, TRUE, Arg))
			Arg->Length = 0, Arg->Data = NULL;
		break;
	case DNARG_BYTES_PE_DUMP:
		Arg->Kind = DNARG_INT;
		{
			DECODED_ARG Bytes;
			if (ReadManagedByteArray(Raw, DOTNET_ASSEMBLY_DUMP_MAX, FALSE, &Bytes) && DumpManagedAssembly(&Bytes)) {
				Arg->Decoded = TRUE;
				Arg->Value = Bytes.Length;
			}
		}
		break;
	case DNARG_INT:
		Arg->Decoded = TRUE;
		Arg->Value = (int)Raw;
		break;
	default:
		break;
	}
}

//**************************************************************************************
static char ArgKindFormatChar(BYTE Kind)
//**************************************************************************************
{
	switch (Kind) {
	case DNARG_STRING:
	case DNARG_STRING_PROBE:
		return 'U';
	case DNARG_BYTES:
		return 'b';
	default:
		return 'i';
	}
}

// Shares a single behaviour-log id across table entries that emit the same
// (Category, Fmt, ArgName[]) explain schema so the 39-entry table consumes at
// most 21 slots in logtbl_explained[256].
//**************************************************************************************
static LONG GetDotNetApiLogIndex(DOTNET_API_ENTRY *Entry)
//**************************************************************************************
{
	DOTNET_API_ENTRY *Canonical = Entry;
	unsigned int i, j;

	if (Entry->LogIndex != 0)
		return Entry->LogIndex;

	for (i = 0; i < DOTNET_API_TABLE_SIZE; i++) {
		DOTNET_API_ENTRY *Candidate = &g_dotnet_api_table[i];
		BOOL Same = TRUE;

		if (Candidate == Entry)
			break;
		if (Candidate->ArgCount != Entry->ArgCount || strcmp(Candidate->Category, Entry->Category))
			continue;

		for (j = 0; j < Entry->ArgCount; j++) {
			if (ArgKindFormatChar(Candidate->ArgKind[j]) != ArgKindFormatChar(Entry->ArgKind[j]) ||
			    strcmp(Candidate->ArgName[j], Entry->ArgName[j])) {
				Same = FALSE;
				break;
			}
		}
		if (Same) {
			Canonical = Candidate;
			break;
		}
	}

	if (Canonical->LogIndex == 0) {
		LONG NewIndex = InterlockedIncrement(&g_log_index);
		InterlockedCompareExchange(&Canonical->LogIndex, NewIndex, 0);
	}

	if (Canonical != Entry)
		InterlockedCompareExchange(&Entry->LogIndex, Canonical->LogIndex, 0);

	return Canonical->LogIndex;
}

// One behaviour-log record per hit. The format string is fixed per entry by its
// ArgKind[] list, and the log id is shared per (Category, Fmt, ArgName[]) shape,
// so the explain record emitted for that id matches every subsequent record.
// 'Method' is the first field on every record so processing can key on it
// regardless of the entry's shape.
//**************************************************************************************
static void LogDotNetApiCall(DOTNET_API_ENTRY *Entry, PCONTEXT Context)
//**************************************************************************************
{
	DECODED_ARG Arg[DOTNET_API_MAX_ARGS];
	char Fmt[DOTNET_API_MAX_ARGS + 2];
	char Method[256];
	LONG LogIndex;
	unsigned int i, n = Entry->ArgCount > DOTNET_API_MAX_ARGS ? DOTNET_API_MAX_ARGS : Entry->ArgCount;

	Fmt[0] = 's';
	for (i = 0; i < n; i++) {
		DecodeArg(Entry, Context, i, &Arg[i]);
		Fmt[i + 1] = Arg[i].Kind == DNARG_STRING ? 'U' : Arg[i].Kind == DNARG_BYTES ? 'b' : 'i';
	}
	Fmt[n + 1] = '\0';

	// Skip non-matching or self-delegated overloads whose primary managed object
	// argument did not match the expected type (e.g. WebClient/HttpClient Uri
	// overloads delegated from the string overload, parameterless TcpClient..ctor
	// or CreateDecryptor(), or Assembly.Load(AssemblyName)).
	if (n > 0 && !Arg[0].Decoded)
		return;

	LogIndex = GetDotNetApiLogIndex(Entry);
	_snprintf_s(Method, sizeof(Method), _TRUNCATE, "%s.%s", Entry->Class, Entry->Method);

	// loq is variadic: 'U' expects (int len, PWCHAR), 'b' expects (size_t len, PVOID),
	// and 'i' expects (int).
	switch (n) {
	case 0:
		loq(LogIndex, Entry->Category, "DotNetApi", TRUE, 0, Fmt, "Method", Method);
		break;
	case 1:
		if (Arg[0].Kind == DNARG_INT)
			loq(LogIndex, Entry->Category, "DotNetApi", TRUE, 0, Fmt, "Method", Method, Entry->ArgName[0], Arg[0].Value);
		else if (Arg[0].Kind == DNARG_BYTES)
			loq(LogIndex, Entry->Category, "DotNetApi", TRUE, 0, Fmt, "Method", Method, Entry->ArgName[0], (SIZE_T)Arg[0].Length, Arg[0].Data);
		else
			loq(LogIndex, Entry->Category, "DotNetApi", TRUE, 0, Fmt, "Method", Method, Entry->ArgName[0], Arg[0].Length, Arg[0].Data);
		break;
	case 2:
		if (Arg[0].Kind == DNARG_STRING && Arg[1].Kind == DNARG_STRING)
			loq(LogIndex, Entry->Category, "DotNetApi", TRUE, 0, Fmt, "Method", Method,
				Entry->ArgName[0], Arg[0].Length, Arg[0].Data, Entry->ArgName[1], Arg[1].Length, Arg[1].Data);
		else if (Arg[0].Kind == DNARG_STRING && Arg[1].Kind == DNARG_BYTES)
			loq(LogIndex, Entry->Category, "DotNetApi", TRUE, 0, Fmt, "Method", Method,
				Entry->ArgName[0], Arg[0].Length, Arg[0].Data, Entry->ArgName[1], (SIZE_T)Arg[1].Length, Arg[1].Data);
		else if (Arg[0].Kind == DNARG_BYTES && Arg[1].Kind == DNARG_BYTES)
			loq(LogIndex, Entry->Category, "DotNetApi", TRUE, 0, Fmt, "Method", Method,
				Entry->ArgName[0], (SIZE_T)Arg[0].Length, Arg[0].Data, Entry->ArgName[1], (SIZE_T)Arg[1].Length, Arg[1].Data);
		else if (Arg[0].Kind == DNARG_STRING && Arg[1].Kind == DNARG_INT)
			loq(LogIndex, Entry->Category, "DotNetApi", TRUE, 0, Fmt, "Method", Method,
				Entry->ArgName[0], Arg[0].Length, Arg[0].Data, Entry->ArgName[1], Arg[1].Value);
		else if (Arg[0].Kind == DNARG_BYTES && Arg[1].Kind == DNARG_INT)
			loq(LogIndex, Entry->Category, "DotNetApi", TRUE, 0, Fmt, "Method", Method,
				Entry->ArgName[0], (SIZE_T)Arg[0].Length, Arg[0].Data, Entry->ArgName[1], Arg[1].Value);
		else
			loq(LogIndex, Entry->Category, "DotNetApi", TRUE, 0, Fmt, "Method", Method,
				Entry->ArgName[0], Arg[0].Value, Entry->ArgName[1], Arg[1].Value);
		break;
	default:
		// Three-argument shapes are not used by the table; log the method only.
		Fmt[1] = '\0';
		loq(LogIndex, Entry->Category, "DotNetApi", TRUE, 0, Fmt, "Method", Method);
		break;
	}
}

//**************************************************************************************
BOOL DotNetApiBreakpointHandler(struct _EXCEPTION_POINTERS* ExceptionInfo)
//**************************************************************************************
{
	DOTNET_API_ENTRY **Slot;
	PCONTEXT Context;
	hook_info_t *hookinfo;
	ULONG_PTR saved_retaddr = 0, saved_main_caller = 0, saved_parent_caller = 0;

	if (!ExceptionInfo || !ExceptionInfo->ExceptionRecord || !ExceptionInfo->ContextRecord)
		return FALSE;

	Slot = (DOTNET_API_ENTRY **)lookup_get(&g_dotnet_api_bps, (ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress, NULL);
	if (!Slot || !*Slot)
		return FALSE;

	Context = ExceptionInfo->ContextRecord;
	hookinfo = hook_info();
	if (hookinfo) {
		PULONG_PTR Sp;
		saved_retaddr = hookinfo->return_address;
		saved_main_caller = hookinfo->main_caller_retaddr;
		saved_parent_caller = hookinfo->parent_caller_retaddr;
		hookinfo->return_address = (ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress;
		hookinfo->main_caller_retaddr = 0;
		hookinfo->parent_caller_retaddr = 0;
#ifdef _WIN64
		Sp = (PULONG_PTR)Context->Rsp;
#else
		Sp = (PULONG_PTR)Context->Esp;
#endif
		if (!our_isbadreadptr(Sp, sizeof(ULONG_PTR)))
			hookinfo->main_caller_retaddr = Sp[0];
	}

	hook_disable();
	__try {
		LogDotNetApiCall(*Slot, Context);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DebugOutput("DotNetApi: exception decoding %s.%s at 0x%p.\n", (*Slot)->Class, (*Slot)->Method, ExceptionInfo->ExceptionRecord->ExceptionAddress);
	}
	hook_enable();

	if (hookinfo) {
		hookinfo->return_address = saved_retaddr;
		hookinfo->main_caller_retaddr = saved_main_caller;
		hookinfo->parent_caller_retaddr = saved_parent_caller;
	}

	return TRUE;
}

// CLRConfig reads these through GetEnvironmentVariable on the process block at
// EE startup, so setting them in our DllMain is equivalent to the parent having
// exported them. ZapDisable: Framework NGEN images (also in CoreCLR's table).
// ReadyToRun: CoreCLR R2R images. Both prefixes are set so the knob is read by
// every runtime generation (COMPlus_ is accepted by all, DOTNET_ by Core 6+).
//**************************************************************************************
void DotNetApiDisablePrecompiledImages(void)
//**************************************************************************************
{
	static const char *Knobs[][2] = {
		{ "COMPlus_ZapDisable",  "1" },
		{ "DOTNET_ZapDisable",   "1" },
		{ "COMPlus_ReadyToRun",  "0" },
		{ "DOTNET_ReadyToRun",   "0" },
	};
	unsigned int i;

	for (i = 0; i < sizeof(Knobs) / sizeof(Knobs[0]); i++)
		if (!SetEnvironmentVariableA(Knobs[i][0], Knobs[i][1]))
			DebugOutput("DotNetApi: SetEnvironmentVariable(%s) failed, error %u.\n", Knobs[i][0], GetLastError());

	DebugOutput("DotNetApi: precompiled .NET images disabled for this process (ZapDisable=1, ReadyToRun=0).\n");
}

//**************************************************************************************
void DotNetApiOnMethodCompiled(const char *NamespaceName, const char *ClassName, const char *MethodName, PVOID NativeCode)
//**************************************************************************************
{
	char FullClass[256];
	unsigned int i;

	if (!g_config.dotnet_api_trace || !NativeCode || !ClassName || !MethodName)
		return;

	// Framework V2 ABI hands back "Namespace.Class" in ClassName with no
	// namespace; the Core ABIs split them.
	if (NamespaceName && *NamespaceName)
		_snprintf_s(FullClass, sizeof(FullClass), _TRUNCATE, "%s.%s", NamespaceName, ClassName);
	else
		_snprintf_s(FullClass, sizeof(FullClass), _TRUNCATE, "%s", ClassName);

	for (i = 0; i < DOTNET_API_TABLE_SIZE; i++) {
		DOTNET_API_ENTRY *Entry = &g_dotnet_api_table[i];
		DOTNET_API_ENTRY **Slot;

		if (strcmp(Entry->Method, MethodName) || strcmp(Entry->Class, FullClass))
			continue;

		if (Entry->Noisy && !g_config.dotnet_api_strings)
			return;

		// Tiered compilation re-JITs a method to a new entry; each entry gets its
		// own breakpoint, the same entry already armed is left alone.
		if (lookup_get(&g_dotnet_api_bps, (ULONG_PTR)NativeCode, NULL))
			return;

		Slot = (DOTNET_API_ENTRY **)lookup_add(&g_dotnet_api_bps, (ULONG_PTR)NativeCode, sizeof(PVOID));
		if (!Slot)
			return;
		*Slot = Entry;

		if (SetSoftwareBreakpointEx(&SoftBPs, NativeCode, DotNetApiBreakpointHandler, TRUE))
			DebugOutput("DotNetApi: tracing %s.%s at 0x%p.\n", FullClass, MethodName, NativeCode);
		else {
			lookup_del(&g_dotnet_api_bps, (ULONG_PTR)NativeCode);
			DebugOutput("DotNetApi: failed to set breakpoint on %s.%s at 0x%p.\n", FullClass, MethodName, NativeCode);
		}
		return;
	}
}
