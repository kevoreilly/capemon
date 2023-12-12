#ifndef _WIN64
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
#include <stddef.h>
#include "ntapi.h"
#include <distorm.h>
#include "hooking.h"
#include "ignore.h"
#include "unhook.h"
#include "misc.h"
#include "pipe.h"
#include "config.h"

extern DWORD GetTimeStamp(LPVOID Address);
extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern PVOID GetExportAddress(HMODULE ModuleBase, PCHAR FunctionName);

// length disassembler engine
int lde(void *addr)
{
	// the length of an instruction is 16 bytes max, but there can also be
	// 16 instructions of length one, so.. we support "decomposing" 16
	// instructions at once, max
	unsigned int used_instruction_count; _DInst instructions[16];
	_CodeInfo code_info = { 0, 0, addr, 16, Decode32Bits };
	_DecodeResult ret = distorm_decompose(&code_info, instructions, 16,
		&used_instruction_count);

	return ret == DECRES_SUCCESS ? instructions[0].size : 0;
}

// instruction disassembler engine
int ide(_DecodedInst* instruction, void *addr)
{
	unsigned int used_instruction_count; _DecodedInst instructions[16];
	_DecodeResult ret = distorm_decode(0, addr, 16, Decode32Bits, instructions, 1, &used_instruction_count);
	if (ret)
		*instruction = instructions[0];

	return ret;
}

// create a trampoline at the given address, that is, we are going to replace
// the original instructions at this particular address. So, in order to
// call the original function from our hook, we have to execute the original
// instructions *before* jumping into addr+offset, where offset is the length
// which totals the size of the instructions which we place in the `tramp'.
// returns 0 on failure, or a positive integer defining the size of the tramp
// NOTE: tramp represents the memory address where the trampoline will be
// placed, copying it to another memory address will result into failure
static int hook_create_trampoline(unsigned char *addr, int len,
	unsigned char *tramp)
{
	const unsigned char *base = tramp;

	// our trampoline should contain at least enough bytes to fit the given
	// length
	while (len > 0) {

		// obtain the length of this instruction
		int length = lde(addr);

		// error?
		if(length == 0) {
			return 0;
		}

		// how many bytes left?
		len -= length;

		// check the type of instruction at this particular address, if it's
		// a jump or a call instruction, then we have to calculate some fancy
		// addresses, otherwise we can simply copy the instruction to our
		// trampoline

		// it's a (conditional) jump or call with 32bit relative offset
		if(*addr == 0xe9 || *addr == 0xe8 || (*addr == 0x0f &&
				addr[1] >= 0x80 && addr[1] < 0x90)) {
			unsigned long jmp_addr;

			// copy the jmp or call instruction (conditional jumps are two
			// bytes, the rest is one byte)
			*tramp++ = *addr++;
			if(addr[-1] != 0xe9 && addr[-1] != 0xe8) {
				*tramp++ = *addr++;
			}

			// when a jmp/call is performed, then the relative offset +
			// the instruction pointer + the size of the instruction is the
			// calculated address, so that's our target address as well.
			// (note that `addr' is already increased by one or two, so the
			// 4 represents the 32bit offset of this particular instruction)
			jmp_addr = *(int *) addr + 4 + (unsigned long) addr;
			addr += 4;

			// trampoline is already filled with the opcode itself (the jump
			// instruction), now we will actually jump to the location by
			// calculating the relative offset which points to the real
			// address (this is the reverse operation of the one to calculate
			// the absolute address of a jump)
			*(unsigned long *) tramp = jmp_addr - (unsigned long) tramp - 4;
			tramp += 4;

			// because an unconditional jump denotes the end of a basic block
			// we will return failure if we have not yet processed enough room
			// to store our hook code
			if(tramp[-5] == 0xe9 && len > 0) return 0;
		}
		// (conditional) jump with 8bit relative offset
		else if(*addr == 0xeb || (*addr >= 0x70 && *addr < 0x80)) {

			// same rules apply as with the 32bit relative offsets, except
			// for the fact that both conditional and unconditional 8bit
			// relative jumps take only one byte for the opcode

			// 8bit relative offset, we have to sign-extend it (by casting it
			// as signed char) in order to calculate the correct address
			unsigned long jmp_addr = (unsigned long) addr + 2 +
				*(signed char *)(addr + 1);

			// the chance is *fairly* high that we will not be able to perform
			// a jump from the trampoline to the original function, so instead
			// we will use 32bit relative offset jumps
			if(*addr == 0xeb) {
				*tramp++ = 0xe9;
			}
			else {
				// hex representation of the two types of 32bit jumps
				// 8bit relative conditional jumps:	 70..80
				// 32bit relative conditional jumps: 0f 80..90
				// so we will simply add 0x10 to the opcode of 8bit relative
				// offset jump to obtain the 32bit relative offset jump opcode
				*tramp++ = 0x0f;
				*tramp++ = *addr + 0x10;
			}

			// calculate the correct relative offset address
			*(unsigned long *) tramp = jmp_addr - (unsigned long) tramp - 4;
			tramp += 4;

			// again, end of basic block, check for length
			if(*addr == 0xeb && len > 0) {
				return 0;
			}

			// add the instruction length
			addr += 2;
		}
		// return instruction, indicates end of basic block as well, so we
		// have to check if we already have enough space for our hook..
		else if((*addr == 0xc3 || *addr == 0xc2) && len > 0) {
			return 0;
		}
		else {
			// copy the instruction directly to the trampoline
			while (length-- != 0) {
				*tramp++ = *addr++;
			}
		}
	}

	// append a jump from the trampoline to the original function
	*tramp++ = 0xe9;
	emit_rel(tramp, tramp, addr);
	tramp += 4;

	// return the length of this trampoline
	return tramp - base;
}

// this function constructs the so-called pre-trampoline, this pre-trampoline
// determines if a hook should really be executed. An example will be the
// easiest; imagine we have a hook on CreateProcessInternalW() and on
// NtCreateProcessEx() (this is actually the case currently), now, if all goes
// well, a call to CreateProcess() will call CreateProcessInternalW() followed
// by a call to NtCreateProcessEx(). Because we already hook the higher-level
// API CreateProcessInternalW() it is not really useful to us to log the
// information retrieved in the NtCreateProcessEx() function as well,
// therefore, because one is called by the other, we can tell the hooking
// engine "once inside a hook, don't hook further API calls" by setting the
// allow_hook_recursion flag to false. The example above is what happens when
// the hook recursion is not allowed.
static void hook_create_pre_tramp(hook_t *h)
{
	unsigned char *p;
	unsigned int off;

	unsigned char pre_tramp1[] = {
		// pushf
		0x9c,
		// pusha
		0x60,
		// cld
		0xfc,
		// push ebp
		0x55,
		// lea eax, dword ptr [esp+40]
		0x8d, 0x44, 0x24, 0x28,
		// push eax
		0x50,
		// push h
		0x68, 0x00, 0x00, 0x00, 0x00,
		// call enter_hook, returns 0 if we should call the original func, otherwise 1 if we should call our New_ version
		0xe8, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char pre_tramp2[] = {
		// test eax, eax
		0x85, 0xc0,
		// popad
		0x61,
		// jnz 0x6
		0x75, 0x06,
			// popf
			0x9d,
			// jmp h->tramp (original function)
			0xe9, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char pre_tramp3[] = {
		// popf
		0x9d,
		// jmp h->new_func (New_ func)
		0xe9, 0x00, 0x00, 0x00, 0x00
	};


	if (disable_this_hook(h)) {
		h->hookdata->pre_tramp[0] = 0xe9;
		emit_rel(h->hookdata->pre_tramp + 1, h->hookdata->pre_tramp + 1, h->hookdata->tramp);
		return;
	}

	p = h->hookdata->pre_tramp;
	off = sizeof(pre_tramp1) - sizeof(unsigned int);
	emit_rel(pre_tramp1 + off, p + off, (unsigned char *)&enter_hook);
	off = sizeof(pre_tramp1) - 1 - (2 * sizeof(unsigned int));
	*(DWORD *)(pre_tramp1 + off) = (DWORD)h;
	memcpy(p, pre_tramp1, sizeof(pre_tramp1));
	p += sizeof(pre_tramp1);

	off = sizeof(pre_tramp2) - sizeof(unsigned int);
	emit_rel(pre_tramp2 + off, p + off, h->hookdata->tramp);
	memcpy(p, pre_tramp2, sizeof(pre_tramp2));
	p += sizeof(pre_tramp2);

	off = sizeof(pre_tramp3) - sizeof(unsigned int);
	emit_rel(pre_tramp3 + off, p + off, h->new_func);
	memcpy(p, pre_tramp3, sizeof(pre_tramp3));
	p += sizeof(pre_tramp3);

	assert ((ULONG_PTR)(p - h->hookdata->pre_tramp) < MAX_PRETRAMP_SIZE);
}

static void hook_create_pre_tramp_notail(hook_t *h)
{
	unsigned char *p;
	unsigned int off;

	unsigned char pre_tramp1[] = {
		// pushf
		0x9c,
		// pusha
		0x60,
		// cld
		0xfc,
		// push ebp
		0x55,
		// lea eax, dword ptr [esp+40]
		0x8d, 0x44, 0x24, 0x28,
		// push eax
		0x50,
		// push h
		0x68, 0x00, 0x00, 0x00, 0x00,
		// call enter_hook, returns 0 if we should call the original func, otherwise 1 if we should call our New_ version
		0xe8, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char pre_tramp2[] = {
		// test eax, eax
		0x85, 0xc0,
		// jnz 0x7
		0x75, 0x07,
		// popad
		0x61,
		// popf
		0x9d,
		// jmp h->tramp (original function)
		0xe9, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char pre_tramp3[] = {
		// mov ecx, numargs
		0xb9, h->numargs, 0x00, 0x00, 0x00,
		// mov eax, ecx
		0x8b, 0xc1,
		// shl eax, 2 (eax = eax * 4)
		0xc1, 0xe0, 0x02,
		// lea esi, [esp+40]
		0x8d, 0x74, 0x24, 0x28,
		// sub esp, eax
		0x29, 0xc4,
		// mov edi, esp
		0x89, 0xe7,
		// repne movsd
		0xf2, 0xa5,
		// call h->new_func
		0xe8, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char pre_tramp4[] = {
		// test eax, eax
		0x85, 0xc0,
		// jnz 0x7
		0x75, 0x07,
		// popad
		0x61,
		// popf
		0x9d,
		// jmp h->tramp (original function)
		0xe9, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char pre_tramp5[] = {
		// popad
		0x61,
		// popf
		0x9d,
		// jmp h->alt_func
		0xe9, 0x00, 0x00, 0x00, 0x00
	};

	if (disable_this_hook(h)) {
		h->hookdata->pre_tramp[0] = 0xe9;
		emit_rel(h->hookdata->pre_tramp + 1, h->hookdata->pre_tramp + 1, h->hookdata->tramp);
		return;
	}

	p = h->hookdata->pre_tramp;
	off = sizeof(pre_tramp1) - sizeof(unsigned int);
	emit_rel(pre_tramp1 + off, p + off, (unsigned char *)&enter_hook);
	off = sizeof(pre_tramp1) - 1 - (2 * sizeof(unsigned int));
	*(DWORD *)(pre_tramp1 + off) = (DWORD)h;
	memcpy(p, pre_tramp1, sizeof(pre_tramp1));
	p += sizeof(pre_tramp1);

	off = sizeof(pre_tramp2) - sizeof(unsigned int);
	emit_rel(pre_tramp2 + off, p + off, h->hookdata->tramp);
	memcpy(p, pre_tramp2, sizeof(pre_tramp2));
	p += sizeof(pre_tramp2);

	off = sizeof(pre_tramp3) - sizeof(unsigned int);
	emit_rel(pre_tramp3 + off, p + off, h->new_func);
	memcpy(p, pre_tramp3, sizeof(pre_tramp3));
	p += sizeof(pre_tramp3);

	off = sizeof(pre_tramp4) - sizeof(unsigned int);
	emit_rel(pre_tramp4 + off, p + off, h->hookdata->tramp);
	memcpy(p, pre_tramp4, sizeof(pre_tramp4));
	p += sizeof(pre_tramp4);

	off = sizeof(pre_tramp5) - sizeof(unsigned int);
	emit_rel(pre_tramp5 + off, p + off, h->alt_func);
	memcpy(p, pre_tramp5, sizeof(pre_tramp5));
	p += sizeof(pre_tramp5);

	assert ((ULONG_PTR)(p - h->hookdata->pre_tramp) < MAX_PRETRAMP_SIZE);
}

static int hook_api_jmp_direct(hook_t *h, unsigned char *from,
	unsigned char *to)
{
	// unconditional jump opcode
	*from = 0xe9;

	// store the relative address from this opcode to our hook function
	*(unsigned long *)(from + 1) = (unsigned char *) to - from - 5;
	return 0;
}

static int hook_api_nop_jmp_direct(hook_t *h, unsigned char *from,
	unsigned char *to)
{
	// nop
	*from++ = 0x90;

	return hook_api_jmp_direct(h, from, to);
}

static int hook_api_hotpatch_jmp_direct(hook_t *h, unsigned char *from,
	unsigned char *to)
{
	// mov edi, edi
	*from++ = 0x8b;
	*from++ = 0xff;

	return hook_api_jmp_direct(h, from, to);
}

static int hook_api_push_retn(hook_t *h, unsigned char *from,
	unsigned char *to)
{
	// push addr
	*from++ = 0x68;
	*(unsigned char **) from = to;

	// retn
	from[4] = 0xc3;

	return 0;
}

static int hook_api_nop_push_retn(hook_t *h, unsigned char *from,
	unsigned char *to)
{
	// nop
	*from++ = 0x90;

	return hook_api_push_retn(h, from, to);
}

static int hook_api_jmp_indirect(hook_t *h, unsigned char *from,
	unsigned char *to)
{
	// jmp dword [hook_data]
	*from++ = 0xff;
	*from++ = 0x25;

	*(unsigned char **)from = h->hookdata->hook_data;

	// the real address is stored in hook_data
	memcpy(h->hookdata->hook_data, &to, sizeof(to));
	return 0;
}

static int hook_api_hotpatch_jmp_indirect(hook_t *h, unsigned char *from,
	unsigned char *to)
{
	// mov edi, edi
	*from++ = 0x8b;
	*from++ = 0xff;

	return hook_api_jmp_indirect(h, from, to);
}

static int hook_api_mov_eax_jmp_eax(hook_t *h, unsigned char *from,
	unsigned char *to)
{
	// mov eax, address
	*from++ = 0xb8;
	*(unsigned char **) from = to;
	from += 4;

	// jmp eax
	*from++ = 0xff;
	*from++ = 0xe0;
	return 0;
}

static int hook_api_mov_eax_push_retn(hook_t *h, unsigned char *from,
	unsigned char *to)
{
	// mov eax, address
	*from++ = 0xb8;
	*(unsigned char **) from = to;
	from += 4;

	// push eax
	*from++ = 0x50;

	// retn
	*from++ = 0xc3;
	return 0;
}

static int hook_api_mov_eax_indirect_jmp_eax(hook_t *h, unsigned char *from,
	unsigned char *to)
{
	// mov eax, [hook_data]
	*from++ = 0xa1;
	*(unsigned char **)from = h->hookdata->hook_data;
	from += 4;

	// store the address at hook_data
	memcpy(h->hookdata->hook_data, &to, sizeof(to));

	// jmp eax
	*from++ = 0xff;
	*from++ = 0xe0;
	return 0;
}

static int hook_api_mov_eax_indirect_push_retn(hook_t *h, unsigned char *from,
	unsigned char *to)
{
	// mov eax, [hook_data]
	*from++ = 0xa1;
	*(unsigned char **)from = h->hookdata->hook_data;
	from += 4;

	// store the address at hook_data
	memcpy(h->hookdata->hook_data, &to, sizeof(to));

	// push eax
	*from++ = 0x50;

	// retn
	*from++ = 0xc3;
	return 0;
}

#if HOOK_ENABLE_FPU
static int hook_api_push_fpu_retn(hook_t *h, unsigned char *from,
	unsigned char *to)
{
	// push ebp
	*from++ = 0x55;

	// fld qword [hook_data]
	*from++ = 0xdd;
	*from++ = 0x05;

	*(unsigned char **) from = h->hook_data;
	from += 4;

	// fistp dword [esp]
	*from++ = 0xdb;
	*from++ = 0x1c;
	*from++ = 0xe4;

	// retn
	*from++ = 0xc3;

	// store the address as double
	double addr = (double) (unsigned long) to;
	memcpy(h->hook_data, &addr, sizeof(addr));
	return 0;
}
#endif

static int hook_api_special_jmp(hook_t *h, unsigned char *from,
	unsigned char *to)
{
	// our largest hook in use is currently 7 bytes. so we have to make sure
	// that this special hook (a hook that will be patched over again later)
	// is atleast seven bytes.
	*from++ = 0x90;
	*from++ = 0x90;
	return hook_api_jmp_direct(h, from, to);
}

static int hook_api_native_jmp_indirect(hook_t *h, unsigned char *from,
	unsigned char *to)
{
	// hook used for Native API functions where the first instruction specifies the syscall number
	// we'll leave in that mov instruction and repeat it before calling the original function
	from += 5;
	return hook_api_jmp_indirect(h, from, to);
}

static int hook_api_safest(hook_t *h, unsigned char *from, unsigned char *to)
{
	hook_api_jmp_direct(h, from - 5, to);
	*from++ = 0xeb;
	*from++ = 0xf9;
	return 0;
}

hook_data_t *alloc_hookdata_near(void *addr)
{
	DWORD oldprot;
	hook_data_t *ret = calloc(1, sizeof(hook_data_t));

	VirtualProtect(ret, sizeof(hook_data_t), PAGE_EXECUTE_READWRITE, &oldprot);

	return ret;
}

static ULONG_PTR get_near_rel_target(unsigned char *buf)
{
	if (buf[0] == 0xe9 || buf[0] == 0xe8)
		return (ULONG_PTR)buf + 5 + *(int *)&buf[1];
	else if (buf[0] == 0x0f && buf[1] >= 0x80 && buf[1] < 0x90)
		return (ULONG_PTR)buf + 6 + *(int *)&buf[2];

	assert(0);
	return 0;
}

static ULONG_PTR get_short_rel_target(unsigned char *buf)
{
	if (buf[0] == 0xeb || buf[0] == 0xe3 || (buf[0] >= 0x70 && buf[0] < 0x80))
		return (ULONG_PTR)buf + 2 + *(char *)&buf[1];

	assert(0);
	return 0;
}

int hook_api(hook_t *h, int type)
{
	unsigned char *addr;
	int ret = -1;
	DWORD old_protect;
	BOOL delay_loaded = FALSE;

	// table with all possible hooking types
	static struct {
		int(*hook)(hook_t *h, unsigned char *from, unsigned char *to);
		int len;
		int offset;
	} hook_types[] = {
		/* HOOK_JMP_DIRECT */ {&hook_api_jmp_direct, 5, 0},
		/* HOOK_NOP_JMP_DIRECT */ {&hook_api_nop_jmp_direct, 6, 0},
		/* HOOK_HOTPATCH_JMP_DIRECT */ {&hook_api_hotpatch_jmp_direct, 7, 0},
		/* HOOK_PUSH_RETN */ {&hook_api_push_retn, 6, 0},
		/* HOOK_NOP_PUSH_RETN */ {&hook_api_nop_push_retn, 7, 0},
		/* HOOK_JMP_INDIRECT */ {&hook_api_jmp_indirect, 6, 0},
		/* HOOK_MOV_EAX_JMP_EAX */ {&hook_api_mov_eax_jmp_eax, 7, 0},
		/* HOOK_MOV_EAX_PUSH_RETN */ {&hook_api_mov_eax_push_retn, 7, 0},
		/* HOOK_MOV_EAX_INDIRECT_JMP_EAX */
			{&hook_api_mov_eax_indirect_jmp_eax, 7, 0},
		/* HOOK_MOV_EAX_INDIRECT_PUSH_RETN */
			{&hook_api_mov_eax_indirect_push_retn, 7, 0},
#if HOOK_ENABLE_FPU
		/* HOOK_PUSH_FPU_RETN */ {&hook_api_push_fpu_retn, 11, 0},
#endif
		/* HOOK_SPECIAL_JMP */ {&hook_api_special_jmp, 7, 0},
		/* HOOK_NATIVE_JMP_INDIRECT */ {&hook_api_native_jmp_indirect, 11, 0},
		/* HOOK_HOTPATCH_JMP_INDIRECT */{ &hook_api_hotpatch_jmp_indirect, 8, 0},
		/* HOOK_SAFEST */{ &hook_api_safest, 2, 5},
	};

	// is this address already hooked?
	if (h->is_hooked != 0) {
		return 0;
	}

	if (hook_is_excluded(h))
		return 0;

	// resolve the address to hook
	addr = h->addr;

	if (addr == NULL && h->library != NULL && h->funcname != NULL) {
		HMODULE hmod = GetModuleHandleW(h->library);
		/* if the DLL isn't loaded, don't bother attempting anything else */
		if (hmod == NULL)
			return 0;

		if (!strcmp(h->funcname, "RtlDispatchException")) {
			// RtlDispatchException is the first relative call in KiUserExceptionDispatcher
			unsigned char *baseaddr = (unsigned char *)GetProcAddress(hmod, "KiUserExceptionDispatcher");
			int instroff = 0;
			while (baseaddr[instroff] != 0xe8) {
				instroff += lde(&baseaddr[instroff]);
			}
			addr = (unsigned char *)get_near_rel_target(&baseaddr[instroff]);
		}
		else if (!strcmp(h->funcname, "ConnectEx")) {
			addr = (unsigned char *)get_connectex_addr(hmod);
		}
		else if (!wcscmp(h->library, L"kernel32") && !strcmp(h->funcname, "MoveFileWithProgressTransactedW")) {
			unsigned char *tmpaddr = (unsigned char *)GetProcAddress(hmod, "MoveFileWithProgressW");
			if (tmpaddr[22] == 0xe8 && tmpaddr[28] == 0xc2) {
				addr = (unsigned char *)get_near_rel_target(tmpaddr + 22);
			}
			else
				addr = (unsigned char *)GetProcAddress(hmod, h->funcname);
		}
		else if (!strcmp(h->funcname, "JsEval")) {
			type = HOOK_JMP_DIRECT;
			addr = (unsigned char *)get_jseval_addr(hmod);
		}
		else if (!strcmp(h->funcname, "COleScript_ParseScriptText")) {
			type = HOOK_JMP_DIRECT;
			addr = (unsigned char *)get_olescript_parsescripttext_addr(hmod);
		}
		else if (!strcmp(h->funcname, "CDocument_write")) {
			type = HOOK_JMP_DIRECT;
			addr = (unsigned char *)get_cdocument_write_addr(hmod);
		}
		else if (!wcscmp(h->library, L"combase")) {
			PVOID getprocaddr = (PVOID)GetProcAddress(hmod, h->funcname);
			addr = (unsigned char *)GetExportAddress(hmod, (PCHAR)h->funcname);
			if (addr && (PVOID)addr != getprocaddr)
				DebugOutput("hook_api: combase::%s export address 0x%p differs from GetProcAddress -> 0x%p\n", h->funcname, addr, getprocaddr);
		}
		else {
			PVOID exportaddr = GetExportAddress(hmod, (PCHAR)h->funcname);
			addr = (unsigned char *)GetProcAddress(hmod, h->funcname);
			if (exportaddr && addr && (PVOID)addr != exportaddr) {
				unsigned int offset;
				char *module_name = convert_address_to_dll_name_and_offset((ULONG_PTR)addr, &offset);
				DebugOutput("hook_api: Warning - %s export address 0x%p differs from GetProcAddress -> 0x%p (%s::0x%x)\n", h->funcname, exportaddr, addr, module_name, offset);
			}
			else if (exportaddr && !addr) {
				addr = exportaddr;
				DebugOutput("hook_api: %s address 0x%p obtained via GetExportAddress\n", h->funcname, addr);
			}
		}

		if (addr == NULL && h->timestamp != 0 && h->rva != 0) {
			DWORD timestamp = GetTimeStamp(hmod);
			if (timestamp == h->timestamp)
				addr = (unsigned char *)hmod + h->rva;
		}
	}

	if (addr == NULL || addr == (unsigned char *)0xffbadd11) {
		// function doesn't exist in this DLL, not a critical error
		return 0;
	}

	// the following applies for "inlined" functions on windows 7,
	// some functions are inlined into kernelbase.dll, rather than
	// kernelbase.dll jumping to e.g. kernel32.dll. for these
	// functions there is a short relative jump, followed by the
	// inlined function.
	if (!memcmp(addr, "\xeb\x02", 2) &&
		!memcmp(addr - 5, "\xcc\xcc\xcc\xcc\xcc", 5)) {
		// step over the short jump and the relative offset
		addr += 4;
	}

	// e.g. GetCommandLine APIs
	if (!memcmp(addr, "\xeb\x05\x90\x90\x90\x90\x90", 7))
		// step over the jump and the nops
		addr += 7;

	// windows 7 has a DLL called kernelbase.dll which basically acts
	// as a layer between the program and kernel32 (and related?) it
	// allows easy hotpatching of a set of functions which is why
	// there's a short relative jump and an indirect jump. we want to
	// resolve the address of the real function, so we follow these
	// two jumps.
	if (addr[0] == 0xeb) {
		PUCHAR target = (PUCHAR)get_short_rel_target(addr);
		if (!memcmp(target, "\xff\x25", 2)) {
			addr = **(unsigned char ***)(target + 2);
			delay_loaded = TRUE;
		}
	}

	// Some functions don't just have the short jump and indirect
	// jump, but also an empty function prolog
	// ("mov edi, edi ; push ebp ; mov ebp, esp ; pop ebp"). Other
	// than that, this edge case is equivalent to the case above.
	else if (!memcmp(addr, "\x8b\xff\x55\x8b\xec\x5d", 6)) {
		if (addr[6] == 0xeb) {
			PUCHAR target = (PUCHAR)get_short_rel_target(addr + 6);
			if (!memcmp(target, "\xff\x25", 2)) {
				addr = **(unsigned char ***)(target + 2);
				delay_loaded = TRUE;
			}
		}
		else if (addr[6] == 0xe9) {
			PUCHAR target = (PUCHAR)get_near_rel_target(&addr[6]);
			if (!memcmp(target, "\xff\x25", 2)) {
				addr = **(unsigned char ***)(target + 2);
				delay_loaded = TRUE;
			}
		}
	}

	if (!wcscmp(h->library, L"ntdll") && addr[0] == 0xb8) {
		// hooking a native API, leave in the mov eax, <syscall nr> instruction
		// as some malware depends on this for direct syscalls
		// missing a few syscalls is better than crashing and getting no information
		// at all
		type = HOOK_NATIVE_JMP_INDIRECT;
	}

	/* works around some poorly-written malware doing emulation of assumed bytes
	   instead of proper code-stealing
	 */
	if (!strcmp(h->funcname, "GetSystemTime"))
		type = HOOK_JMP_DIRECT;

	/* Some versions of Windows will leave us with a short jump over
	   a looped pause instruction in the bytes we want to modify for a
	   small number of APIs (GetTickCount/GetSystemTimeAsFileTime)
	 */
	if (!memcmp(addr, "\x8b\xff\x55\x8b\xec\xeb\x02", 7)) {
		type = HOOK_JMP_DIRECT;
	}
	if (!memcmp(addr, "\xeb\x02\xf3\x90", 4))
		addr += 4;

	// check if this is a valid hook type
	if (type < 0 && type >= ARRAYSIZE(hook_types)) {
		pipe("WARNING: Provided invalid hook type: %d", type);
		return ret;
	}

	if (delay_loaded == TRUE) {
		if (addr[0] == 0xb8 && addr[5] == 0xe9) {
			// skip this particular hook, we'll hook the delay-loaded DLL at the time
			// is is loaded.  This means we will have duplicate "hook" entries
			// but to avoid any problems, we will check before hooking to see
			// if the final function has already been hooked
			return 0;
		}
	}

	// make sure we aren't trying to hook the same address twice, as could
	// happen due to delay-loaded DLLs
	if (address_already_hooked(addr))
		return 0;

	if (type == HOOK_SAFEST && (memcmp(addr, "\x8b\xff", 2) ||
		(memcmp(addr - 5, "\xcc\xcc\xcc\xcc\xcc", 5) && memcmp(addr - 5, "\x90\x90\x90\x90\x90", 5))))
		type = HOOK_JMP_DIRECT;

	// make the address writable
	if (VirtualProtect(addr - hook_types[type].offset, hook_types[type].offset + hook_types[type].len, PAGE_EXECUTE_READWRITE, &old_protect)) {

		h->hookdata = alloc_hookdata_near(addr);

		if (h->hookdata && hook_create_trampoline(addr, hook_types[type].len, h->hookdata->tramp)) {
			//hook_store_exception_info(h);
			uint8_t orig[16];
			memcpy(orig, addr, 16);

			if (h->notail)
				hook_create_pre_tramp_notail(h);
			else
				hook_create_pre_tramp(h);

			// insert the hook (jump from the api to the
			// pre-trampoline)
			ret = hook_types[type].hook(h, addr, h->hookdata->pre_tramp);

			// Add unhook detection for our newly created hook.
			// Ensure any changes behind our hook are also caught by
			// making the buffersize 16.
			unhook_detect_add_region(h, addr - hook_types[type].offset, orig, addr - hook_types[type].offset, 16);

			// if successful, assign the trampoline address to *old_func
			if (ret == 0) {
				// This will be NULL in cases where we don't care to call the original function from our hook (NOTAIL)
				if (h->old_func)
					*h->old_func = h->hookdata->tramp;

				// successful hook is successful
				h->is_hooked = 1;
				h->hook_addr = addr;
			}
		}
		else {
			pipe("WARNING:Unable to place hook on %z", h->funcname);
		}

		// restore the old protection
		VirtualProtect(addr - hook_types[type].offset, hook_types[type].offset + hook_types[type].len, old_protect, &old_protect);
	}
	else {
		pipe("WARNING:Unable to change protection for hook on %z", h->funcname);
	}

	return ret;
}

int already_hooked(void)
{
	unsigned char *baseaddr = (unsigned char *)GetProcAddress(GetModuleHandle("ntdll"), "KiUserExceptionDispatcher"), *RtlDispatchException;
	int instroff = 0;
	while (baseaddr[instroff] != 0xe8) {
		instroff += lde(&baseaddr[instroff]);
	}
	RtlDispatchException = (unsigned char *)get_near_rel_target(&baseaddr[instroff]);

	/* Doesn't handle all hook types, modify as necessary */
	if (!memcmp(RtlDispatchException, "\x8b\xff\xff\x25", 4) || !memcmp(RtlDispatchException, "\xff\x25", 2) ||
		!memcmp(RtlDispatchException, "\x8b\xff\xe9", 3) || !memcmp(RtlDispatchException, "\xe9", 1) ||
		!memcmp(RtlDispatchException, "\xeb\xf9", 2))
		return 1;
	return 0;
}

int operate_on_backtrace(ULONG_PTR _esp, ULONG_PTR _ebp, void *extra, int(*func)(void *, ULONG_PTR))
{
	int ret = -1;

	ULONG_PTR top = get_stack_top();
	ULONG_PTR bottom = get_stack_bottom();

	unsigned int count = HOOK_BACKTRACE_DEPTH;

	__try
	{
		if (_esp >= bottom && _esp <= (top - sizeof(ULONG_PTR))) {
			ret = func(extra, *(ULONG_PTR *)_esp);
			if (ret)
				return ret;
		}

		while (_ebp >= bottom && _ebp <= (top - (2 * sizeof(ULONG_PTR))) && count-- != 0)
		{
			// obtain the return address and the next value of ebp
			ULONG_PTR addr = *(ULONG_PTR *)(_ebp + sizeof(ULONG_PTR));
			_ebp = *(ULONG_PTR *)_ebp;

			ret = func(extra, addr);
			if (ret)
				return ret;
		}

		return ret;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return -1;
	}
}
#endif