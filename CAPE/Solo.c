/*
CAPE - Config And Payload Extraction
Copyright(C) 2019 kevoreilly@gmail.com

This program is free software : you can redistribute it and / or modify
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
//#define DEBUG_COMMENTS
#include <stdio.h>
#include <distorm.h>
#include "..\hooking.h"
#include <tlhelp32.h>
#include "..\misc.h"
#include "Debugger.h"
#include "CAPE.h"
#include "uthash.h"

#define SOLO_PIPE "\\\\.\\pipe\\debugger_pipe"
#define BUFFER_SIZE 1024*65
#define BYTES_PER_LINE 16
#define MAX_LINES 256
#define MAX_STACK_SLOTS 512
#define SLOTS_BEFORE 255
#define EST_LINE 80
#define INITIAL_CAPACITY 16
#define MAX_ENTRIES ((BUFFER_SIZE - 16) / sizeof(MBIEntry))
#define PAGE_SIZE 4096
#define OUTPUT_BUFFER_SIZE 2048
#define CHUNKSIZE 16

// Structure for MBI entry
typedef struct 
{
	uintptr_t  BaseAddress;
	SIZE_T RegionSize;
	DWORD Protect;
} MBIEntry;

typedef struct 
{
	MBIEntry* data;
	size_t size;
	size_t capacity;
} MBIEntryArray;

typedef const char* (*CmdHandler)(struct _EXCEPTION_POINTERS* ExceptionInfo, const char* data);

typedef struct 
{
	char name[3];
	CmdHandler handler;
	UT_hash_handle hh;
} CommandEntry;

static BOOL CommandMapInitialized = FALSE;
static CommandEntry* CommandMap = NULL;

extern DWORD g_terminate_event_thread_id, g_procname_watcher_thread_id, g_unhook_detect_thread_id, g_unhook_watcher_thread_id;
extern _NtQueryInformationThread pNtQueryInformationThread;
extern int StepOverRegister;
extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);

BOOL InteractiveBreakpointCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo);
char* InteractiveDebuggerPipe(_In_ LPCTSTR lpOutputString, ...);
char* DumpMemoryView(HANDLE hProcess, PCONTEXT ctx, ULONG_PTR RequestedAddr, int numLines);
char* GetStackWindowView(HANDLE hProcess, PCONTEXT ctx, int numSlots);
void PushBack(MBIEntryArray* array, MBIEntry entry);
void FreeArray(MBIEntryArray* array);
static BOOL SetRegister(PCONTEXT Context, char* RegString, PVOID Target);
uint32_t GetPageChecksum(HANDLE hProcess, uintptr_t Address);
BOOL InteractiveTrace(struct _EXCEPTION_POINTERS* ExceptionInfo);
void InitCommands(void);
const char* DispatchCommand(struct _EXCEPTION_POINTERS* ExceptionInfo, const char* Command);
void RegisterCommand(const char* name, CmdHandler func);

static CONTEXT LastContext;

// Serialises interactive debugger sessions. The frontend tracks a single break
// at a time (one shared command/response slot and register view), so only one
// target thread may drive the session at once. Initialised in DllMain.
CRITICAL_SECTION g_interactive_debugger_lock;

static const uint32_t crc32Table[256] = {
	0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,  0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
	0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,  0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
	0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,  0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
	0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,  0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
	0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,  0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
	0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,  0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
	0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,  0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
	0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,  0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
	0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,  0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
	0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,  0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
	0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,  0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
	0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,  0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
	0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,  0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
	0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,  0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
	0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,  0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
	0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,  0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
	0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,  0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
	0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,  0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
	0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,  0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
	0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,  0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
	0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,  0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
	0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,  0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
	0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,  0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
	0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,  0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
	0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,  0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
	0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,  0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
	0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,  0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
	0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,  0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
	0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,  0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
	0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,  0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
	0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,  0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
	0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,  0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

void RegisterCommand(const char* name, CmdHandler func) 
{
	if (!name || strlen(name) != 2) return;

	CommandEntry* entry = (CommandEntry*)malloc(sizeof(CommandEntry));
	snprintf(entry->name, sizeof(entry->name), "%.2s", name);
	entry->name[2] = '\0';
	entry->handler = func;
	HASH_ADD_STR(CommandMap, name, entry);
}

const char* DispatchCommand(struct _EXCEPTION_POINTERS* ExceptionInfo, const char* Command)
{
	char DbgCmd[3] = { 0 };
	char* CmdData = NULL;

	if (Command && *Command)
	{
		char* Sep = strchr(Command, ':');
		if (Sep && Sep - Command >= 2)
		{
			DbgCmd[0] = Command[0];
			DbgCmd[1] = Command[1];
			DbgCmd[2] = '\0';
			CmdData = Sep + 1;

		}
		else
		{
			return InteractiveDebuggerPipe("Malformed command: %s\n", Command);
		}
	}
	else
	{
		return InteractiveDebuggerPipe("Empty command received.\n");
	}

	CommandEntry* Entry = NULL;
	HASH_FIND_STR(CommandMap, DbgCmd, Entry);

	if (Entry && Entry->handler)
	{
		return Entry->handler(ExceptionInfo, CmdData);
	}
	else
	{
		return InteractiveDebuggerPipe("Unknown command: %s\n", DbgCmd);
	}
}


static BOOL ParseHex(const char* input, ULONG_PTR* output)
{
	int base = 16;

	if (!input || !*input) return FALSE;

	char* endp = NULL;
	unsigned long long tmp = strtoull(input, &endp, base);
	if (endp == input || *endp != '\0') return FALSE;
	
	*output = (ULONG_PTR)tmp;
	return TRUE;
}

void VerifyCommandMapInitialized(void)
{
	if (!CommandMapInitialized)
	{
		InitCommands();
		CommandMapInitialized = TRUE;
	}
}

char* InteractiveDebuggerPipe(_In_ LPCTSTR lpOutputString, ...)
{
	va_list args;
	va_start(args, lpOutputString);

	CHAR DebuggerLine[BUFFER_SIZE];
	static CHAR DebuggerCommand[BUFFER_SIZE];
	CHAR TempBuffer[BUFFER_SIZE];
	int BytesRead = 0;

	memset(DebuggerLine, 0, sizeof(DebuggerLine));
	memset(TempBuffer, 0, sizeof(TempBuffer));
	memset(DebuggerCommand, 0, sizeof(DebuggerCommand));

	_vsnprintf_s(TempBuffer, BUFFER_SIZE, _TRUNCATE, lpOutputString, args);
	_snprintf_s(DebuggerLine, BUFFER_SIZE, _TRUNCATE, "BREAK:%s", TempBuffer);


	char* Character = DebuggerLine;
	while (*Character)
	{   // Restrict to ASCII range
		if (*Character < 0x0a || *Character > 0x7E)
			*Character = 0x3F;  // '?'
		Character++;
	}

	int Length = (int)strlen(DebuggerLine);

	BOOL Success = CallNamedPipe(SOLO_PIPE, DebuggerLine, Length, DebuggerCommand, BUFFER_SIZE, (unsigned long*)&BytesRead, NMPWAIT_WAIT_FOREVER);
	DWORD Error = GetLastError();

	va_end(args);

	// A failed transaction means there is no working frontend (not attached, or the
	// pipe broke mid-session). Return the continue sentinel so the debugged thread
	// resumes, rather than silently treating a dead pipe as an empty command.
	if (!Success || BytesRead == 0)
	{
		DebugOutput("InteractiveDebuggerPipe: pipe transaction failed (error %u) - continuing.\n", Error);
		return "__DONE__";
	}

	// Defensively terminate the reply within the bytes actually read
	if ((unsigned int)BytesRead >= BUFFER_SIZE)
		BytesRead = BUFFER_SIZE - 1;
	DebuggerCommand[BytesRead] = '\0';

	return DebuggerCommand;
}

char* OutputRegisters(PCONTEXT Context)
{
	static char OutputBuffer[OUTPUT_BUFFER_SIZE];
	memset(OutputBuffer, 0, sizeof(OutputBuffer));
	void* teb = NtCurrentTeb();

#ifdef _WIN64
	size_t len = _snprintf_s(OutputBuffer, sizeof(OutputBuffer), _TRUNCATE,
		"RAX: %016I64X    CF:%d\n"
		"RBX: %016I64X    PF:%d\n"
		"RCX: %016I64X    AF:%d\n"
		"RDX: %016I64X    ZF:%d\n"
		"RSI: %016I64X    SF:%d\n"
		"RDI: %016I64X    TF:%d\n"
		"RSP: %016I64X    IF:%d\n"
		"RBP: %016I64X    DF:%d\n"
		"R8 : %016I64X    OF:%d\n"
		"R9 : %016I64X    ID:%d\n"
		"R10: %016I64X    NT:%d\n"
		"R11: %016I64X    RF:%d\n"
		"R12: %016I64X    VM:%d\n"
		"R13: %016I64X    AC:%d\n"
		"R14: %016I64X   VIF:%d\n"
		"R15: %016I64X   VIP:%d\n"
		"RIP: %016I64X  IOPL:%d\n\n"
		"GS: %p\n\n",
		Context->Rax, (Context->EFlags & 0x00000001) ? 1 : 0,
		Context->Rbx, (Context->EFlags & 0x00000004) ? 1 : 0,
		Context->Rcx, (Context->EFlags & 0x00000010) ? 1 : 0,
		Context->Rdx, (Context->EFlags & 0x00000040) ? 1 : 0,
		Context->Rsi, (Context->EFlags & 0x00000080) ? 1 : 0,
		Context->Rdi, (Context->EFlags & 0x00000100) ? 1 : 0,
		Context->Rsp, (Context->EFlags & 0x00000200) ? 1 : 0,
		Context->Rbp, (Context->EFlags & 0x00000400) ? 1 : 0,
		Context->R8, (Context->EFlags & 0x00000800) ? 1 : 0,
		Context->R9, (Context->EFlags & 0x00200000) ? 1 : 0,
		Context->R10, (Context->EFlags & 0x00004000) ? 1 : 0,
		Context->R11, (Context->EFlags & 0x00010000) ? 1 : 0,
		Context->R12, (Context->EFlags & 0x00020000) ? 1 : 0,
		Context->R13, (Context->EFlags & 0x00040000) ? 1 : 0,
		Context->R14, (Context->EFlags & 0x00080000) ? 1 : 0,
		Context->R15, (Context->EFlags & 0x00100000) ? 1 : 0,
		Context->Rip, (int)((Context->EFlags >> 12) & 0x3),
		teb
	);

	const M128A* xmm = &Context->Xmm0;
	for (int i = 0; i < 16; ++i)
	{
		size_t remaining = sizeof(OutputBuffer) > len ? sizeof(OutputBuffer) - len : 0;
		if (remaining)
		{
			int written = _snprintf_s(OutputBuffer + len, remaining, _TRUNCATE,
				"XMM%02d.Low : %016I64X   XMM%02d.High: %016I64X\n",
				i, (unsigned __int64)xmm[i].Low, i, (unsigned __int64)xmm[i].High);
			if (written < 0)
			{
				break;
			}
			len += written;
		}
	}
#else
	size_t len = _snprintf_s(OutputBuffer, sizeof(OutputBuffer), _TRUNCATE,
		"EAX: %08X    CF:%d\n"
		"EBX: %08X    AF:%d\n"
		"ECX: %08X    SF:%d\n"
		"EDX: %08X    IF:%d\n"
		"ESI: %08X    OF:%d\n"
		"EDI: %08X    NT:%d\n"
		"ESP: %08X    PF:%d\n"
		"EBP: %08X    ZF:%d\n"
		"EIP: %08X    TF:%d    IOPL:%d\n\n"
		"FS: %p\n\n",
		Context->Eax, (Context->EFlags & 0x00000001) ? 1 : 0,
		Context->Ebx, (Context->EFlags & 0x00000010) ? 1 : 0,
		Context->Ecx, (Context->EFlags & 0x00000080) ? 1 : 0,
		Context->Edx, (Context->EFlags & 0x00000200) ? 1 : 0,
		Context->Esi, (Context->EFlags & 0x00000800) ? 1 : 0,
		Context->Edi, (Context->EFlags & 0x00004000) ? 1 : 0,
		Context->Esp, (Context->EFlags & 0x00000004) ? 1 : 0,
		Context->Ebp, (Context->EFlags & 0x00000040) ? 1 : 0,
		Context->Eip, (Context->EFlags & 0x00000100) ? 1 : 0,
		(int)((Context->EFlags >> 12) & 0x3),
		teb
	);

	// XMM registers begin at offset 160 within the x86 FXSAVE area (ExtendedRegisters)
	const BYTE* xmm_base = Context->ExtendedRegisters + 160;
	for (int i = 0; i < 8; ++i)
	{
		size_t remaining = sizeof(OutputBuffer) > len ? sizeof(OutputBuffer) - len : 0;
		if (remaining)
		{
			unsigned __int64 low, high;
			memcpy(&low, xmm_base + i * 16, sizeof(low));
			memcpy(&high, xmm_base + i * 16 + 8, sizeof(high));

			int written = _snprintf_s(OutputBuffer + len, remaining, _TRUNCATE,
				"XMM%02d.Low : %016I64X   XMM%02d.High: %016I64X\n",
				i, low, i, high);
			if (written < 0)
			{
				break;
			}
			len += written;
		}
	}
#endif

	return InteractiveDebuggerPipe("%s\n", OutputBuffer);
}


uint32_t ComputeCRC32(const uint8_t* buf, size_t len)
{
	uint32_t crc = 0xFFFFFFFFU;
	for (size_t i = 0; i < len; ++i)
	{
		crc = (crc >> 8) ^ crc32Table[(crc ^ buf[i]) & 0xFF];
	}

	return crc ^ 0xFFFFFFFFU;
}

uint32_t GetPageChecksum(HANDLE hProcess, uintptr_t Address) {
	uintptr_t base = Address & ~(PAGE_SIZE - 1);
	unsigned char page[PAGE_SIZE];
	SIZE_T BytesRead = 0;
	if (!ReadProcessMemory(hProcess, (LPCVOID)base, page, PAGE_SIZE, &BytesRead) || BytesRead != PAGE_SIZE) return 0;
	return ComputeCRC32(page, PAGE_SIZE);
}


char* GetStackWindowView(HANDLE hProcess, PCONTEXT ctx, int numSlots)
{
	if (numSlots > MAX_STACK_SLOTS) numSlots = MAX_STACK_SLOTS;

	int estimate = numSlots * EST_LINE + 1;
	char* out = (char*)malloc(estimate);
	if (!out) return NULL;
	out[0] = '\0';

	char* p = out;
	int rem = estimate;
	ULONG_PTR sp;

#ifdef _WIN64
	sp = ctx->Rsp;
#else
	sp = ctx->Esp;
#endif

	ULONG_PTR offset = (ULONG_PTR)SLOTS_BEFORE * sizeof(ULONG_PTR);
	ULONG_PTR base = (sp > offset) ? (sp - offset) : (ULONG_PTR)0;


	for (int i = 0; i < numSlots; i++)
	{
		ULONG_PTR addr = base + (ULONG_PTR)i * sizeof(ULONG_PTR);
		ULONG_PTR val = 0;
		SIZE_T    rd = 0;

		if (!ReadProcessMemory(hProcess, (LPCVOID)addr, &val, sizeof(val), &rd) || rd != sizeof(val)) break;

#ifdef _WIN64
		int n = _snprintf_s(p, rem, _TRUNCATE, "%016I64X,%016I64X\n", (unsigned __int64)addr, (unsigned __int64)val);
#else
		int n = _snprintf_s(p, rem, _TRUNCATE, "%08X,%08X\n", (unsigned)addr, (unsigned)val);
#endif
		if (n <= 0) break;

		p += n;
		rem -= n;
	}

	return out;
}

char* DumpMemoryView(HANDLE hProcess, PCONTEXT ctx, ULONG_PTR RequestedAddr, int numLines)
{
	ULONG_PTR base = RequestedAddr;
	unsigned char probe;
	SIZE_T rd;

	if (base == 0 || ReadProcessMemory(hProcess, (LPCVOID)base, &probe, 1, &rd) != TRUE || rd != 1)
	{
#ifdef _WIN64
		base = ctx->Rsp;
#else
		base = ctx->Esp;
#endif
	}

	int estimate = numLines * (20 + BYTES_PER_LINE * 3 + 1) + 1;
	char* out = (char*)malloc(estimate);
	if (!out) return NULL;

	out[0] = '\0';

	char* p = out;
	int   rem = estimate;
	unsigned char buf[BYTES_PER_LINE];

	for (int line = 0; line < numLines; line++)
	{
		ULONG_PTR addr = base + (ULONG_PTR)line * BYTES_PER_LINE;
		SIZE_T    BytesRead = 0;

		if (!ReadProcessMemory(hProcess, (LPCVOID)addr, buf, BYTES_PER_LINE, &BytesRead) || BytesRead == 0) break;

#ifdef _WIN64
		int n = _snprintf_s(p, rem, _TRUNCATE, "%016I64X,", (unsigned __int64)addr);
#else
		int n = _snprintf_s(p, rem, _TRUNCATE, "%08X,", (unsigned)addr);
#endif
		if (n <= 0) break;
		p += n; rem -= n;

		for (int i = 0; i < BYTES_PER_LINE; i++)
		{
			if (i < (int)BytesRead)
				n = _snprintf_s(p, rem, _TRUNCATE, "%02X ", buf[i]);
			else
				n = _snprintf_s(p, rem, _TRUNCATE, "   ");
			if (n <= 0) break;
			p += n; rem -= n;
		}

		if (rem < 2) break;
		*p++ = '\n';
		*p = '\0';
		rem--;
	}

	return out;
}

char* RetrievePage(HANDLE hProcess, uintptr_t Address, uintptr_t* OutBase) {
	uintptr_t base = Address & ~((uintptr_t)PAGE_SIZE - 1);
	if (OutBase) *OutBase = base;

	// Bound the read to the accessible portion of the region so a page at the
	// end of a committed region (with the next page unmapped) still returns data
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQueryEx(hProcess, (LPCVOID)base, &mbi, sizeof(mbi)) != sizeof(mbi))
		return NULL;

	if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
		return NULL;

	SIZE_T RegionAvail = (SIZE_T)(((uintptr_t)mbi.BaseAddress + mbi.RegionSize) - base);
	SIZE_T ToRead = RegionAvail < PAGE_SIZE ? RegionAvail : PAGE_SIZE;

	unsigned char page[PAGE_SIZE];
	SIZE_T BytesRead = 0;

	if (!ReadProcessMemory(hProcess, (LPCVOID)base, page, ToRead, &BytesRead) || BytesRead == 0) return NULL;

	char* hexPage = malloc(BytesRead * 2 + 1);
	if (!hexPage) return NULL;

	for (SIZE_T i = 0; i < BytesRead; ++i)
		sprintf_s(hexPage + i * 2, 3, "%02X", page[i]);

	hexPage[BytesRead * 2] = '\0';

	return hexPage;
}

// Helper functions for dynamic array
static MBIEntryArray CreateArray(void)
{
	MBIEntryArray array =
	{
		.data = (MBIEntry*)malloc(INITIAL_CAPACITY * sizeof(MBIEntry)),
		.size = 0,
		.capacity = INITIAL_CAPACITY,
	};
	return array;
}

void PushBack(MBIEntryArray* array, MBIEntry entry)
{
	if (array->size >= MAX_ENTRIES) return;

	if (array->size + 1 >= array->capacity)
	{
		size_t newCap = array->capacity * 2;
		if (newCap > MAX_ENTRIES) newCap = MAX_ENTRIES;

		MBIEntry* p = realloc(array->data, newCap * sizeof(MBIEntry));
		if (!p) return;

		array->data = p;
		array->capacity = newCap;
	}

	array->data[array->size++] = entry;
}

void FreeArray(MBIEntryArray* array)
{
	free(array->data);
	array->data = NULL;
	array->size = 0;
	array->capacity = 0;
}

static BOOL SetRegister(PCONTEXT Context, char* RegString, PVOID Target)
{
	if (!Context || !RegString)
		return FALSE;

	DWORD_PTR Value = (DWORD_PTR)Target;

	__try
	{
#ifdef _WIN64
		if (!stricmp(RegString, "eax") || !stricmp(RegString, "rax"))
			Context->Rax = Value;
		else if (!stricmp(RegString, "ebx") || !stricmp(RegString, "rbx"))
			Context->Rbx = Value;
		else if (!stricmp(RegString, "ecx") || !stricmp(RegString, "rcx"))
			Context->Rcx = Value;
		else if (!stricmp(RegString, "edx") || !stricmp(RegString, "rdx"))
			Context->Rdx = Value;
		else if (!stricmp(RegString, "esi") || !stricmp(RegString, "rsi"))
			Context->Rsi = Value;
		else if (!stricmp(RegString, "edi") || !stricmp(RegString, "rdi"))
			Context->Rdi = Value;
		else if (!stricmp(RegString, "esp") || !stricmp(RegString, "rsp"))
			Context->Rsp = Value;
		else if (!stricmp(RegString, "ebp") || !stricmp(RegString, "rbp"))
			Context->Rbp = Value;
		else if (!stricmp(RegString, "eip") || !stricmp(RegString, "rip"))
			Context->Rip = Value;
		else if (!stricmp(RegString, "r8"))
			Context->R8 = Value;
		else if (!stricmp(RegString, "r9"))
			Context->R9 = Value;
		else if (!stricmp(RegString, "r10"))
			Context->R10 = Value;
		else if (!stricmp(RegString, "r11"))
			Context->R11 = Value;
		else if (!stricmp(RegString, "r12"))
			Context->R12 = Value;
		else if (!stricmp(RegString, "r13"))
			Context->R13 = Value;
		else if (!stricmp(RegString, "r14"))
			Context->R14 = Value;
		else if (!stricmp(RegString, "r15"))
			Context->R15 = Value;
		else
			return FALSE;
#else
		if (!stricmp(RegString, "eax"))
			Context->Eax = Value;
		else if (!stricmp(RegString, "ebx"))
			Context->Ebx = Value;
		else if (!stricmp(RegString, "ecx"))
			Context->Ecx = Value;
		else if (!stricmp(RegString, "edx"))
			Context->Edx = Value;
		else if (!stricmp(RegString, "esi"))
			Context->Esi = Value;
		else if (!stricmp(RegString, "edi"))
			Context->Edi = Value;
		else if (!stricmp(RegString, "esp"))
			Context->Esp = Value;
		else if (!stricmp(RegString, "ebp"))
			Context->Ebp = Value;
		else if (!stricmp(RegString, "eip"))
			Context->Eip = Value;
		else
			return FALSE;
#endif
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DebugOutput("Failed to set register %s.\n", RegString);
		return FALSE;
	}

	return TRUE;
}

void InteractiveCommandHandler(struct _EXCEPTION_POINTERS* ExceptionInfo, char* InitialCommand)
{
	LastContext = *ExceptionInfo->ContextRecord;
	const char* Command = InitialCommand;
	while (Command && *Command && strcmp(Command, "__DONE__") != 0)
	{
		const char* NextCommand = DispatchCommand(ExceptionInfo, Command);
		if (strcmp(NextCommand, "__DONE__") == 0)
			break;
				
		Command = NextCommand;
		Sleep(100);
	}
}

const char* HandleInstructionPage(struct _EXCEPTION_POINTERS* ExceptionInfo, const char* data)
{
	ULONG_PTR RequestedAddr = 0;
	SIZE_T rd = 0;
	unsigned char probe = 0;
	HANDLE DebuggerProcessHandle = GetCurrentProcess();

	if (data && *data) {
		if (!ParseHex(data, &RequestedAddr)) 
		{
			return InteractiveDebuggerPipe("Failed with invalid instruction address: %s", data);
		}

		if (!ReadProcessMemory(DebuggerProcessHandle, (LPCVOID)RequestedAddr, &probe, 1, &rd) || rd != 1)
		{
			return InteractiveDebuggerPipe("%p|UNREADABLE", (PVOID)(RequestedAddr & ~((ULONG_PTR)PAGE_SIZE - 1)));
		}
	}

	uintptr_t PageBase = RequestedAddr & ~((uintptr_t)PAGE_SIZE - 1);
	char* InstructionPage = RetrievePage(DebuggerProcessHandle, RequestedAddr, &PageBase);
	if (InstructionPage)
	{
		const char* Command = InteractiveDebuggerPipe("%p|%s", (PVOID)PageBase, InstructionPage);
		free(InstructionPage);
		return Command;
	}
	else
	{
		return InteractiveDebuggerPipe("%p|NODATA", (PVOID)PageBase);
	}
}

const char* HandlePageMap(struct _EXCEPTION_POINTERS* ExceptionInfo, const char* data)
{
	MEMORY_BASIC_INFORMATION mbi;
	MBIEntryArray entries = CreateArray();
	PBYTE address = NULL;

	while (VirtualQueryEx(GetCurrentProcess(), (LPCVOID)address, &mbi, sizeof(mbi)) == sizeof(mbi)) 
	{
		MBIEntry entry = { (uintptr_t)mbi.BaseAddress, mbi.RegionSize, mbi.Protect };
		PushBack(&entries, entry);
		address = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
	}

	const char* Command = NULL;

	if (entries.size > 0) 
	{
		size_t cap = entries.size * 64 + 1;
		char* payload = malloc(cap);
		if (payload) 
		{
			char* p = payload;
			for (size_t i = 0; i < entries.size; ++i)
			{
				int n = sprintf(p, "0x%Ix,%Iu,0x%x", entries.data[i].BaseAddress, entries.data[i].RegionSize, entries.data[i].Protect);
				p += n;
				if (i + 1 < entries.size) *p++ = '|';
			}

			*p = '\0';
			Command = InteractiveDebuggerPipe("%s\n", payload);
			free(payload);
		}
	}
	else 
	{
		return InteractiveDebuggerPipe("Failed with no memory regions found.\n");
	}

	FreeArray(&entries);
	return Command;
}

const char* HandleRegisters(struct _EXCEPTION_POINTERS* ExceptionInfo, const char* data)
{
	return OutputRegisters(&LastContext);
}

const char* HandleContinue(struct _EXCEPTION_POINTERS* ExceptionInfo, const char* data)
{
	// The command map is process-lived and reused on the next break, so it is
	// left intact here rather than torn down and rebuilt on every continue.
	ClearSingleStepMode(ExceptionInfo->ContextRecord);
	return "__DONE__";
}

const char* HandleStepIn(struct _EXCEPTION_POINTERS* ExceptionInfo, const char* data) {
	if (SetSingleStepMode(ExceptionInfo->ContextRecord, InteractiveTrace)) 
	{
		LastContext = *ExceptionInfo->ContextRecord;
		return "__DONE__";
	}
	return InteractiveDebuggerPipe("Failed to set single step mode.\n");
}

const char* HandleStepOver(struct _EXCEPTION_POINTERS* ExceptionInfo, const char* data)
{
	PVOID cip;
#ifdef _WIN64
	cip = (PVOID)ExceptionInfo->ContextRecord->Rip;
#else
	cip = (PVOID)ExceptionInfo->ContextRecord->Eip;
#endif
	_DecodedInst inst;
	unsigned int count = 0;

	_DecodeResult res = distorm_decode(0, (const unsigned char*)cip, 32, sizeof(void*) == 8 ? Decode64Bits : Decode32Bits, &inst, 1, &count);

	if (inst.size == 0) 
	{
		return InteractiveDebuggerPipe("Failed could not disassemble instruction at 0x%p\n", cip);
	}

	PVOID RetAddr = (PVOID)((PUCHAR)cip + inst.size);
	if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &StepOverRegister, 0, (BYTE*)RetAddr, 0, 1, InteractiveBreakpointCallback)) 
	{
		LastContext = *ExceptionInfo->ContextRecord;
		ClearSingleStepMode(ExceptionInfo->ContextRecord);
		RetAddr = NULL;
		return "__DONE__";
	}
	else 
	{
		return InteractiveDebuggerPipe("Failed to set step-over breakpoint at 0x%p\n", RetAddr);
	}
}

const char* HandleStepOut(struct _EXCEPTION_POINTERS* ExceptionInfo, const char* data)
{
#ifdef _WIN64
	PVOID StackPtr = (PVOID)ExceptionInfo->ContextRecord->Rsp;
	SIZE_T AddressSize = sizeof(ULONG64);
#else
	PVOID StackPtr = (PVOID)ExceptionInfo->ContextRecord->Esp;
	SIZE_T AddressSize = sizeof(ULONG32);
#endif

	ULONG_PTR ReturnAddress = 0;
	SIZE_T BytesRead = 0;

	if (!ReadProcessMemory(GetCurrentProcess(), StackPtr, &ReturnAddress, AddressSize, &BytesRead) || BytesRead != AddressSize)
	{
		return InteractiveDebuggerPipe("Failed to read return address\n");
	}

	if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &StepOverRegister, 0, (BYTE*)ReturnAddress, 0, 1, InteractiveBreakpointCallback))
	{
		ClearSingleStepMode(ExceptionInfo->ContextRecord);
		LastContext = *ExceptionInfo->ContextRecord;
		return "__DONE__";
	}

	return InteractiveDebuggerPipe("Failed to set step-out breakpoint at 0x%p\n", (PVOID)ReturnAddress);
}

const char* HandleMemoryDump(struct _EXCEPTION_POINTERS* ExceptionInfo, const char* data)
{
	ULONG_PTR RequestedAddr = 0;
	SIZE_T RequestedSize = 0;
	SIZE_T BytesRead = 0;
	unsigned char Probe = 0;
	HANDLE ProcessHandle = GetCurrentProcess();

	if (data && *data)
	{
		char* SizeSep = strchr(data, '|');
		if (SizeSep) *SizeSep++ = '\0';

		if (!ParseHex(data, &RequestedAddr))
			return InteractiveDebuggerPipe("Failed with invalid dump address: %s\n", data);

		if (SizeSep && *SizeSep)
		{
			if (!ParseHex(SizeSep, &RequestedSize))
				return InteractiveDebuggerPipe("Failed with invalid dump size: %s\n", SizeSep);

			if (RequestedSize > OUTPUT_BUFFER_SIZE)
				return InteractiveDebuggerPipe("Failed: requested size %zu exceeds max buffer size %d.\n", RequestedSize, OUTPUT_BUFFER_SIZE);

			unsigned char* Buffer = (unsigned char*)malloc(RequestedSize);
			if (!Buffer)
				return InteractiveDebuggerPipe("Failed with memory allocation.\n");

			if (!ReadProcessMemory(ProcessHandle, (LPCVOID)RequestedAddr, Buffer, RequestedSize, &BytesRead) || BytesRead != RequestedSize)
			{
				free(Buffer);
				return InteractiveDebuggerPipe("0x%p|Failed with unreadable memory\n", (PVOID)RequestedAddr);
			}

			char* HexOutput = (char*)malloc(RequestedSize * 2 + 1);
			if (!HexOutput)
			{
				free(Buffer);
				return InteractiveDebuggerPipe("0x%p|Failed with hex formatting.\n", (PVOID)RequestedAddr);
			}

			for (SIZE_T I = 0; I < RequestedSize; ++I)
			{
				sprintf(HexOutput + I * 2, "%02X", Buffer[I]);
			}

			const char* Command = InteractiveDebuggerPipe("0x%p|%s\n", (PVOID)RequestedAddr, HexOutput);
			free(HexOutput);
			free(Buffer);
			return Command;
		}

		if (!ReadProcessMemory(ProcessHandle, (LPCVOID)RequestedAddr, &Probe, 1, &BytesRead) || BytesRead != 1)
		{
			return InteractiveDebuggerPipe("0x%p|Failed with unreadable dump address\n", (PVOID)RequestedAddr);
		}
	}

	char* MemDump = DumpMemoryView(ProcessHandle, ExceptionInfo->ContextRecord, RequestedAddr, MAX_LINES);
	if (MemDump)
	{
		const char* Command = InteractiveDebuggerPipe("0x%p|%s\n", (PVOID)RequestedAddr, MemDump);
		free(MemDump);
		return Command;
	}

	return InteractiveDebuggerPipe("Failed to dump memory.\n");
}


const char* HandleStackView(struct _EXCEPTION_POINTERS* ExceptionInfo, const char* data)
{
	HANDLE ProcessHandle = GetCurrentProcess();
	char* StackDump = GetStackWindowView(ProcessHandle, ExceptionInfo->ContextRecord, MAX_STACK_SLOTS);

	if (StackDump)
	{
		const char* Command = InteractiveDebuggerPipe("%s\n", StackDump);
		free(StackDump);
		return Command;
	}

	return InteractiveDebuggerPipe("Failed to dump stack view.\n");
}

const char* HandleListBreakpoints(struct _EXCEPTION_POINTERS* ExceptionInfo, const char* data)
{
	CONTEXT* ctx = ExceptionInfo->ContextRecord;
	int len = 0;
	const int MaxPerLine = 32;
	const int MaxEntries = 4;


	size_t BufSize = MaxEntries * MaxPerLine + 1;
	char* Output = (char*)malloc(BufSize);
	if (!Output)
	{
		return InteractiveDebuggerPipe("Failed to allocate memory.\n");
	}

	ULONG_PTR dr[4] =
	{
		(ULONG_PTR)ctx->Dr0,
		(ULONG_PTR)ctx->Dr1,
		(ULONG_PTR)ctx->Dr2,
		(ULONG_PTR)ctx->Dr3
	};

	for (int i = 0; i < 4; ++i)
	{
		if (dr[i])
		{
			len += sprintf(Output + len, "%d,%p|", i, (PVOID)dr[i]);
		}
	}

	if (len == 0)
	{
		free(Output);
		return InteractiveDebuggerPipe("No hardware breakpoints set.\n");
	}

	if (Output[len - 1] == '|') Output[len - 1] = '\0';

	const char* Command = InteractiveDebuggerPipe("%s\n", Output);
	free(Output);
	return Command;
}

const char* HandleFlagMod(struct _EXCEPTION_POINTERS* ExceptionInfo, const char* data)
{
	if (!data || !*data)
	{
		return InteractiveDebuggerPipe("Failed missing flag directive.\n");
	}

	if (_stricmp(data, "ClearZeroFlag") == 0) ClearZeroFlag(ExceptionInfo->ContextRecord);
	else if (_stricmp(data, "SetZeroFlag") == 0) SetZeroFlag(ExceptionInfo->ContextRecord);
	else if (_stricmp(data, "FlipZeroFlag") == 0) FlipZeroFlag(ExceptionInfo->ContextRecord);
	else if (_stricmp(data, "ClearSignFlag") == 0) ClearSignFlag(ExceptionInfo->ContextRecord);
	else if (_stricmp(data, "SetSignFlag") == 0) SetSignFlag(ExceptionInfo->ContextRecord);
	else if (_stricmp(data, "FlipSignFlag") == 0) FlipSignFlag(ExceptionInfo->ContextRecord);
	else if (_stricmp(data, "ClearCarryFlag") == 0) ClearCarryFlag(ExceptionInfo->ContextRecord);
	else if (_stricmp(data, "SetCarryFlag") == 0) SetCarryFlag(ExceptionInfo->ContextRecord);
	else if (_stricmp(data, "FlipCarryFlag") == 0) FlipCarryFlag(ExceptionInfo->ContextRecord);
	else
	{
		return InteractiveDebuggerPipe("Failed invalid flag modifier: %s\n", data);
	}

	return OutputRegisters(ExceptionInfo->ContextRecord);
}

const char* HandleRunUntil(struct _EXCEPTION_POINTERS* ExceptionInfo, const char* data)
{
	ULONG_PTR Addr = 0;
	if (!data || !ParseHex(data, &Addr))
	{
		return InteractiveDebuggerPipe("Failed with invalid run-until address: %s\n", data);
	}

	if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &StepOverRegister, 0, (BYTE*)Addr, 0, 1, InteractiveBreakpointCallback))
	{
		ClearSingleStepMode(ExceptionInfo->ContextRecord);
		LastContext = *ExceptionInfo->ContextRecord;
		return "__DONE__";
	}

	return InteractiveDebuggerPipe("Failed to set run-until breakpoint at 0x%p\n", (PVOID)Addr);
}

const char* HandleListThreads(struct _EXCEPTION_POINTERS* ExceptionInfo, const char* data)
{
	DWORD ExcludeTids[] =
	{
		g_terminate_event_thread_id,
		g_procname_watcher_thread_id,
		g_unhook_detect_thread_id,
		g_unhook_watcher_thread_id
	};

	size_t ExcludeTidCount = sizeof(ExcludeTids) / sizeof(ExcludeTids[0]);

	typedef enum _THREADINFOCLASS
	{
		ThreadBasicInformation,
		ThreadQuerySetWin32StartAddress = 9
	} THREADINFOCLASS;

	typedef NTSTATUS(NTAPI* PFN_NTQIT)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);

	PFN_NTQIT pNtQIT = (PFN_NTQIT)pNtQueryInformationThread;

	DWORD pid = GetCurrentProcessId();
	DWORD CurrentTid = GetCurrentThreadId();
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 te = { sizeof(te) };
	NTSTATUS status;

	if (hSnap == INVALID_HANDLE_VALUE)
	{
		return InteractiveDebuggerPipe("Failed to snapshot threads.\n");
	}

	size_t capacity = OUTPUT_BUFFER_SIZE;
	char* Output = (char*)malloc(capacity);

	if (!Output)
	{
		CloseHandle(hSnap);
		return InteractiveDebuggerPipe("Faile memory allocation failed.\n");
	}

	int  len = 0;

	for (BOOL ok = Thread32First(hSnap, &te); ok; ok = Thread32Next(hSnap, &te))
	{
		if (te.th32OwnerProcessID != pid) continue;

		BOOL skip = FALSE;
		for (size_t i = 0; i < ExcludeTidCount; ++i)
		{
			if (te.th32ThreadID == ExcludeTids[i])
			{
				skip = TRUE;
				break;
			}
		}

		if (skip) continue;

		const char* mark = (te.th32ThreadID == CurrentTid) ? "+" : "-";

		HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
		PVOID StartAddr = NULL;

		if (hThread && pNtQIT)
		{
			status = pNtQIT(hThread, ThreadQuerySetWin32StartAddress, &StartAddr, sizeof(StartAddr), NULL);
			if (!NT_SUCCESS(status)) StartAddr = NULL;
		}

		if (hThread) CloseHandle(hThread);

		int needed = snprintf(NULL, 0, "%s|%lu|%p\n", mark, te.th32ThreadID, StartAddr);
		if ((size_t)(len + needed + 1) >= capacity)
		{
			capacity *= 2;
			char* NewOutput = (char*)realloc(Output, capacity);
			if (!NewOutput)
			{
				free(Output);
				CloseHandle(hSnap);
				return InteractiveDebuggerPipe("Buffer reallocation failed.\n");
			}
			Output = NewOutput;
		}

		len += sprintf(Output + len, "%s|%lu|%p\n", mark, te.th32ThreadID, StartAddr);
	}

	CloseHandle(hSnap);

	if (len > 0)
	{
		const char* Command = InteractiveDebuggerPipe("%s\n", Output);
		free(Output);
		return Command;
	}
	else
	{
		free(Output);
		return InteractiveDebuggerPipe("Failed no modules found.\n");
	}
}

const char* HandleListModules(struct _EXCEPTION_POINTERS* ExceptionInfo, const char* data)
{
	DWORD Pid = GetCurrentProcessId();
	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, Pid);
	if (Snapshot == INVALID_HANDLE_VALUE)
		return InteractiveDebuggerPipe("Failed to snapshot modules.\n");

	MODULEENTRY32 Me = { 0 };
	Me.dwSize = sizeof(Me);

	size_t capacity = OUTPUT_BUFFER_SIZE * 2;
	char* Output = (char*)malloc(capacity);
	if (!Output)
	{
		CloseHandle(Snapshot);
		return InteractiveDebuggerPipe("Memory allocation failed.\n");
	}

	int Len = 0;

	if (Module32First(Snapshot, &Me))
	{
		do
		{
			int needed = snprintf(
				NULL,
				0,
				"%p,%08X,%s,%s|",
				Me.modBaseAddr,
				Me.modBaseSize,
				Me.szModule,
				Me.szExePath
			);

			if ((size_t)(Len + needed + 1) >= capacity)
			{
				capacity *= 2;
				char* NewOutput = (char*)realloc(Output, capacity);
				if (!NewOutput)
				{
					free(Output);
					CloseHandle(Snapshot);
					return InteractiveDebuggerPipe("Buffer reallocation failed.\n");
				}
				Output = NewOutput;
			}

			Len += sprintf(
				Output + Len,
				"%p,%08X,%s,%s|",
				Me.modBaseAddr,
				Me.modBaseSize,
				Me.szModule,
				Me.szExePath
			);

		} while (Module32Next(Snapshot, &Me));
	}

	CloseHandle(Snapshot);

	if (Len > 0)
	{
		if (Output[Len - 1] == '|') Output[Len - 1] = '\0';
		const char* Command = InteractiveDebuggerPipe("%s\n", Output);
		free(Output);
		return Command;
	}
	else
	{
		free(Output);
		return InteractiveDebuggerPipe("Failed no modules found.\n");
	}
}


const char* HandleSetBreakpoint(struct _EXCEPTION_POINTERS* ExceptionInfo, const char* data)
{
	if (!data || !*data)
		return InteractiveDebuggerPipe("Invalid breakpoint command: missing input.\n");

	char Input[MAX_PATH];
	strncpy_s(Input, sizeof(Input), data, _TRUNCATE);
	char* Sep = strchr(Input, '|');
	if (!Sep)
		return InteractiveDebuggerPipe("Failed with malformed breakpoint command (missing '|')\n");
	
	*Sep = '\0';
	const char* RegStr = Input;
	const char* AddrStr = Sep + 1;
	int Register = -1;

	if (strcmp(RegStr, "next") != 0)
	{
		char* Endp = NULL;
		long r = strtol(RegStr, &Endp, 0);
		if (Endp == RegStr || *Endp != '\0' || r < 0 || r > 3)
			return InteractiveDebuggerPipe("Failed with invalid register: %s\n", RegStr);

		Register = (int)r;
	}

	char* Endp = NULL;
	unsigned long long addr = strtoull(AddrStr, &Endp, 0);
	if (Endp == AddrStr || *Endp != '\0')
		return InteractiveDebuggerPipe("Failed with invalid breakpoint address: %s\n", AddrStr);

	ULONG_PTR BpAddress = (ULONG_PTR)addr;
	if (Register == -1)
	{
		if (ContextSetNextAvailableBreakpoint(ExceptionInfo->ContextRecord, &StepOverRegister, 0, (BYTE*)BpAddress, BP_EXEC, 0, InteractiveBreakpointCallback))
		{
			return InteractiveDebuggerPipe("Breakpoint %d set at 0x%p\n", StepOverRegister, (PVOID)BpAddress);
		}
		else
		{
			return InteractiveDebuggerPipe("Failed to set breakpoint %d at 0x%p\n", StepOverRegister, (PVOID)BpAddress);
		}
	}
	else
	{
		if (ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, Register, 0, (BYTE*)BpAddress, BP_EXEC, 0, InteractiveBreakpointCallback))
		{
			return InteractiveDebuggerPipe("Breakpoint %d set at 0x%p\n", Register, (PVOID)BpAddress);
		}
		else
		{
			return InteractiveDebuggerPipe("Failed to set breakpoint %d at 0x%p\n", Register, (PVOID)BpAddress);
		}
	}
}

const char* HandleDeleteBreakpoint(struct _EXCEPTION_POINTERS* ExceptionInfo, const char* data)
{
	if (!data || !*data)
		return InteractiveDebuggerPipe("Failed to delete breakpoint: missing input.\n");

	char* Endptr = NULL;
	unsigned long idx = strtoul(data, &Endptr, 0);
	if (Endptr == data || *Endptr != '\0' || idx > 3)
		return InteractiveDebuggerPipe("Failed to delete breakpoint: invalid breakpoint index '%s'\n", data);

	int index = (int)idx;
	CONTEXT* ctx = ExceptionInfo->ContextRecord;
	ULONG_PTR BpAddress = 0;
	switch (index) {
		case 0: BpAddress = ctx->Dr0; break;
		case 1: BpAddress = ctx->Dr1; break;
		case 2: BpAddress = ctx->Dr2; break;
		case 3: BpAddress = ctx->Dr3; break;
	}

	if (!ContextClearBreakpoint(ExceptionInfo->ContextRecord, index))
		return InteractiveDebuggerPipe("Failed to clear breakpoint index %d\n", index);

	return InteractiveDebuggerPipe("Breakpoint %d cleared at 0x%p\n", index, (PVOID)BpAddress);
}

const char* HandleExports(struct _EXCEPTION_POINTERS* ExceptionInfo, const char* data)
{
	if (!data || !*data)
		return InteractiveDebuggerPipe("Failed to get exports: missing input.\n");

	char input[MAX_PATH];
	strncpy_s(input, sizeof(input), data, _TRUNCATE);
	char* sep = strchr(input, '|');

	if (!sep)
	{
		return InteractiveDebuggerPipe("Failed to get exports: malformed command.\n");
	}

	*sep = '\0';
	char OriginalModName[MAX_MODULE_NAME32];
	strcpy_s(OriginalModName, sizeof(OriginalModName), input);
	int page = atoi(sep + 1);
	char modulePath[MAX_PATH] = { 0 };
	BOOL found = FALSE;

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
	MODULEENTRY32 me = { .dwSize = sizeof(me) };

	if (Module32First(hSnap, &me))
	{
		do
		{
			char modNameLower[MAX_MODULE_NAME32];
			strcpy_s(modNameLower, sizeof(modNameLower), OriginalModName);
			_strlwr_s(modNameLower, sizeof(modNameLower));

			char snapNameLower[MAX_MODULE_NAME32];
			strcpy_s(snapNameLower, sizeof(snapNameLower), me.szModule);
			_strlwr_s(snapNameLower, sizeof(snapNameLower));

			if (strcmp(snapNameLower, modNameLower) == 0)
			{
				strcpy_s(modulePath, sizeof(modulePath), me.szExePath);
				found = TRUE;
				break;
			}
		} while (Module32Next(hSnap, &me));
	}
	CloseHandle(hSnap);

	if (!found)
	{
		return InteractiveDebuggerPipe("Failed to get exports: module not found.\n");
	}

	HMODULE hMod = LoadLibraryExA(modulePath, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!hMod)
	{
		return InteractiveDebuggerPipe("Failed to get exports: module not loaded.\n");
	}

	const size_t MaxEntryLen = 256;

	BYTE* base = (BYTE*)hMod;
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

	DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD RvaSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	BOOL HasExports = (rva && RvaSize && !IsBadReadPtr(base + rva, RvaSize));

	// Size the entry table to the actual export count, capped as a sanity bound
	size_t MaxSymbols = 0;
	if (HasExports)
	{
		MaxSymbols = ((PIMAGE_EXPORT_DIRECTORY)(base + rva))->NumberOfFunctions;
		if (MaxSymbols > (size_t)BUFFER_SIZE)
			MaxSymbols = (size_t)BUFFER_SIZE;
	}

	char** entries = NULL;
	int EntryCount = 0;
	if (MaxSymbols)
	{
		entries = (char**)malloc(MaxSymbols * sizeof(char*));
		if (!entries)
		{
			FreeLibrary(hMod);
			return InteractiveDebuggerPipe("Memory allocation failed.\n");
		}
	}

	if (HasExports && entries)
	{
		PIMAGE_EXPORT_DIRECTORY ed = (PIMAGE_EXPORT_DIRECTORY)(base + rva);
		DWORD* FuncRvas = (DWORD*)(base + ed->AddressOfFunctions);
		DWORD* NameRvas = (DWORD*)(base + ed->AddressOfNames);
		WORD* ordinals = (WORD*)(base + ed->AddressOfNameOrdinals);

		for (DWORD i = 0; i < ed->NumberOfFunctions && (size_t)EntryCount < MaxSymbols; ++i)
		{
			DWORD FuncRva = FuncRvas[i];
			if (!FuncRva) continue;

			const char* name = NULL;
			for (DWORD j = 0; j < ed->NumberOfNames; ++j)
			{
				if (ordinals[j] == i)
				{
					DWORD NameOffset = NameRvas[j];
					if (NameOffset > nt->OptionalHeader.SizeOfImage) break;
					const char* TestName = (const char*)(base + NameOffset);
					if (!IsBadReadPtr(TestName, 1))
						name = TestName;
					break;
				}
			}

			char fallback[32];
			if (!name)
			{
				snprintf(fallback, sizeof(fallback), "ord_%04u", ed->Base + i);
				name = fallback;
			}

			uintptr_t AbsAddr = (uintptr_t)me.modBaseAddr + FuncRva;

			char* entry = (char*)malloc(MaxEntryLen);
			if (!entry) continue;

			unsigned int written = snprintf(entry, MaxEntryLen, "%llu,%s", (unsigned long long)AbsAddr, name);
			if (written <= 0 || written >= MaxEntryLen)
			{
				free(entry);
				continue;
			}

			entries[EntryCount++] = entry;
		}
	}

	FreeLibrary(hMod);

	const int SymbolsPerPage = 512;
	int start = page * SymbolsPerPage;
	int end = start + SymbolsPerPage;
	int CurLen = 0;

	char* PageBuffer = (char*)malloc(BUFFER_SIZE);
	if (!PageBuffer)
	{
		for (int i = 0; i < EntryCount; i++) free(entries[i]);
		free(entries);
		return InteractiveDebuggerPipe("Memory allocation failed.\n");
	}

	for (int i = start; i < EntryCount && i < end; i++)
	{
		int len = (int)strlen(entries[i]);
		if (CurLen + len + 1 >= BUFFER_SIZE - 64)
			break;

		if (CurLen > 0) PageBuffer[CurLen++] = '|';
		memcpy(PageBuffer + CurLen, entries[i], len);
		CurLen += len;
	}

	BOOL HasMore = (end < EntryCount);
	strcat_s(PageBuffer, BUFFER_SIZE, HasMore ? "||MORE" : "||END");
	
	for (int i = 0; i < EntryCount; i++) free(entries[i]);
	free(entries);

	char* FinalBuffer = (char*)malloc(BUFFER_SIZE);
	if (!FinalBuffer)
	{
		free(PageBuffer);
		return InteractiveDebuggerPipe("Memory allocation failed.\n");
	}

	_snprintf_s(FinalBuffer, BUFFER_SIZE, _TRUNCATE, "%s||%s", OriginalModName, PageBuffer);

	free(PageBuffer);
	if (strlen(FinalBuffer) >= BUFFER_SIZE - 1)
		DebugOutput("Failed: Exports final buffer overflow for %s\n", OriginalModName);
	
	const char* Command = InteractiveDebuggerPipe("%s\n", FinalBuffer);
	free(FinalBuffer);
	return Command;
}

const char* HandleSetRegister(struct _EXCEPTION_POINTERS* ExceptionInfo, const char* data)
{
	if (!data || !*data)
		return InteractiveDebuggerPipe("Failed with invalid input data.\n");

	char InputBuffer[MAX_PATH];
	strncpy_s(InputBuffer, sizeof(InputBuffer), data, _TRUNCATE);

	char* Sep = strchr(InputBuffer, '|');
	if (!Sep)
		return InteractiveDebuggerPipe("Failed with malformed command, expected REGISTER|VALUE.\n");

	*Sep = '\0';
	char RegName[16];
	char ValueStr[32];

	strncpy_s(RegName, sizeof(RegName), InputBuffer, _TRUNCATE);
	strncpy_s(ValueStr, sizeof(ValueStr), Sep + 1, _TRUNCATE);

	ULONG_PTR NewValue = 0;
	if (!ParseHex(ValueStr, &NewValue))
		return InteractiveDebuggerPipe("Failed with invalid value for register %s: %s.", RegName, ValueStr);

	BOOL result = SetRegister(ExceptionInfo->ContextRecord, RegName, (PVOID)NewValue);
	if (!result)
		return InteractiveDebuggerPipe("Failed to set register %s to %llu.\n", RegName, NewValue);

	LastContext = *ExceptionInfo->ContextRecord;
	return OutputRegisters(&LastContext);
}

const char* HandleNopInstruction(struct _EXCEPTION_POINTERS* ExceptionInfo, const char* data)
{
	ULONG_PTR Address = 0;
	if (!data || !ParseHex(data, &Address))
		return InteractiveDebuggerPipe("Invalid instruction address: %s\n", data);

	_DecodeType DecodeType;
	_DecodeResult Result;
	_OffsetType Offset = 0;
	_DecodedInst DecodedInstruction;
	unsigned int DecodedInstructionsCount = 0;
	DWORD OldProtect;

#ifdef _WIN64
	DecodeType = Decode64Bits;
#else
	DecodeType = Decode32Bits;
#endif

	if (Address)
		Result = distorm_decode(Offset, (const unsigned char*)Address, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount);

	if (!DecodedInstruction.size)
		return InteractiveDebuggerPipe("Failed Nop instruction at 0x%p\n", Address);

	VirtualProtect((LPVOID)Address, DecodedInstruction.size, PAGE_EXECUTE_READWRITE, &OldProtect);
	for (unsigned int i = 0; i < DecodedInstruction.size; i++) 
		*((BYTE*)Address + i) = 0x90;

	VirtualProtect((LPVOID)Address, DecodedInstruction.size, OldProtect, &OldProtect);
	return InteractiveDebuggerPipe("%p|%u\n", Address, DecodedInstruction.size);
}

const char* HandlePatchBytes(struct _EXCEPTION_POINTERS* ExceptionInfo, const char* data)
{
	if (!data || !*data)
		return InteractiveDebuggerPipe("Failed with invalid input data.\n");

	char* Sep = strchr(data, '|');
	if (!Sep)
		return InteractiveDebuggerPipe("Failed with bad data format\n");
		
	*Sep++ = '\0';
	ULONG_PTR Address = 0;

	if (!ParseHex(data, &Address))
		return InteractiveDebuggerPipe("Failed with invalid patch address: %s\n", data);

	if (!Address || !IsAddressAccessible((PVOID)Address))
		return InteractiveDebuggerPipe("Failed address is not accessible: 0x%p", Address);

	size_t HexLen = strlen(Sep);
	size_t MaxBytes = HexLen / 2 + 1;
	BYTE* Patch = (BYTE*)malloc(MaxBytes);
	if (!Patch)
		return InteractiveDebuggerPipe("Failed with memory allocation.\n");

	size_t ByteCount = 0;
	char* HexPtr = Sep;
	while (*HexPtr)
	{
		while (*HexPtr && isspace((unsigned char)*HexPtr)) HexPtr++;

		if (!*HexPtr) break;

		if (!isxdigit((unsigned char)*HexPtr) || !isxdigit((unsigned char)*(HexPtr + 1))) break;

		char HexByte[3] = { *HexPtr, *(HexPtr + 1), '\0' };
		Patch[ByteCount++] = (BYTE)strtol(HexByte, NULL, 16);
		HexPtr += 2;
	}

	if (ByteCount == 0)
	{
		free(Patch);
		return InteractiveDebuggerPipe("Failed with no bytes to patch.\n");
	}

	DWORD OldProtect;
	if (!VirtualProtect((LPVOID)Address, ByteCount, PAGE_EXECUTE_READWRITE, &OldProtect))
	{
		free(Patch);
		return InteractiveDebuggerPipe("Failed unable to change memory protection at 0x%p", Address);
	}

	BYTE* dest = (BYTE*)Address;
	BYTE* src = Patch;
	for (size_t i = 0; i < ByteCount; ++i, ++dest, ++src) 
	{
		*dest = *src;
	}

	VirtualProtect((LPVOID)Address, ByteCount, OldProtect, &OldProtect);
	free(Patch);

	return InteractiveDebuggerPipe("Patched %p|%u\n", Address, ByteCount);
}

void InitCommands(void) 
{
	RegisterCommand("IN", HandleInstructionPage);
	RegisterCommand("PM", HandlePageMap);
	RegisterCommand("RG", HandleRegisters);
	RegisterCommand("CT", HandleContinue);
	RegisterCommand("SI", HandleStepIn);
	RegisterCommand("SO", HandleStepOver);
	RegisterCommand("OU", HandleStepOut);
	RegisterCommand("SK", HandleStackView);
	RegisterCommand("MD", HandleMemoryDump);
	RegisterCommand("LB", HandleListBreakpoints);
	RegisterCommand("FL", HandleFlagMod);
	RegisterCommand("RU", HandleRunUntil);
	RegisterCommand("TH", HandleListThreads);
	RegisterCommand("LM", HandleListModules);
	RegisterCommand("BP", HandleSetBreakpoint);
	RegisterCommand("DB", HandleDeleteBreakpoint);
	RegisterCommand("EX", HandleExports);
	RegisterCommand("SR", HandleSetRegister);
	RegisterCommand("NI", HandleNopInstruction);
	RegisterCommand("PB", HandlePatchBytes);
}

BOOL InteractiveTrace(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	return InteractiveBreakpointCallback(NULL, ExceptionInfo);
}

BOOL InteractiveBreakpointCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID CIP;
	char* Command = NULL;

	// Hold the session lock for the whole break so a second thread that breaks
	// concurrently waits here until this session continues. The lock is recursive
	// (CRITICAL_SECTION), so a nested break on this same thread will not deadlock.
	EnterCriticalSection(&g_interactive_debugger_lock);

#ifdef _WIN64
	CIP = (PVOID)ExceptionInfo->ContextRecord->Rip;
#else
	CIP = (PVOID)ExceptionInfo->ContextRecord->Eip;
#endif

	if (pBreakpointInfo)
	{
		if (StepOverRegister != -1 && pBreakpointInfo->Register == StepOverRegister)
		{
			StepOverRegister = -1;
		}
		Command = InteractiveDebuggerPipe("Breakpoint %i => 0x%p\n", pBreakpointInfo->Register, CIP);
	}
	else
	{
		Command = InteractiveDebuggerPipe("Single step at 0x%p\n", CIP);
	}

	VerifyCommandMapInitialized();
	InteractiveCommandHandler(ExceptionInfo, Command);

	LeaveCriticalSection(&g_interactive_debugger_lock);
	return TRUE;
}