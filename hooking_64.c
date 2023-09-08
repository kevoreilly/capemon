#ifdef _WIN64
/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com), Cuckoo Sandbox Developers

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

extern void DebugOutput(_In_ LPCTSTR lpOutputString, ...);
extern DWORD GetTimeStamp(LPVOID Address);
extern PVOID GetExportAddress(HMODULE ModuleBase, PCHAR FunctionName);

PVOID LdrpInvertedFunctionTableSRWLock;

// length disassembler engine
int lde(void *addr)
{
	// the length of an instruction is 16 bytes max, but there can also be
	// 16 instructions of length one, so.. we support "decomposing" 16
	// instructions at once, max
	unsigned int used_instruction_count; _DInst instructions[16];
	_CodeInfo code_info = { 0, 0, addr, 16, Decode64Bits };
	_DecodeResult ret = distorm_decompose(&code_info, instructions, 16,
		&used_instruction_count);

	return ret == DECRES_SUCCESS ? instructions[0].size : 0;
}

// instruction disassembler engine
int ide(_DecodedInst* instruction, void *addr)
{
	unsigned int used_instruction_count; _DecodedInst instructions[16];
	_DecodeResult ret = distorm_decode(0, addr, 16, Decode64Bits, instructions, 1, &used_instruction_count);
	if (ret)
		*instruction = instructions[0];

	return ret;
}

static _DInst *get_insn(void *addr)
{
	unsigned int used_instruction_count; _DInst instructions[16];
	_CodeInfo code_info = { 0, 0, addr, 16, Decode64Bits };
	_DecodeResult ret = distorm_decompose(&code_info, instructions, 16,
		&used_instruction_count);
	if (ret == DECRES_SUCCESS) {
		_DInst *insn = malloc(sizeof(_DInst));
		memcpy(insn, &instructions[0], sizeof(_DInst));
		return insn;
	}
	return NULL;
}

static void put_insn(_DInst *insn)
{
	free(insn);
}

static unsigned char *emit_indirect_jmp(unsigned char *buf, ULONG_PTR addr)
{
	*buf++ = 0xff;
	*buf++ = 0x25;
	*(DWORD *)buf = 0;
	buf += sizeof(DWORD);
	*(ULONG_PTR *)buf = addr;
	buf += sizeof(ULONG_PTR);
	return buf;
}

static unsigned char *emit_indirect_call(unsigned char *buf, ULONG_PTR addr)
{
	*buf++ = 0xff;
	*buf++ = 0x15;
	*(DWORD *)buf = 2;
	buf += sizeof(DWORD);
	*buf++ = 0xeb;
	*buf++ = 0x08;
	*(ULONG_PTR *)buf = addr;
	buf += sizeof(ULONG_PTR);
	return buf;
}

static unsigned char *emit_indirect_jcc(unsigned char condcode, unsigned char *buf, ULONG_PTR addr)
{
	*buf++ = condcode;
	*buf++ = 2 + 4 + 8;

	*buf++ = 0xff;
	*buf++ = 0x25;
	*(DWORD *)buf = 0;
	buf += sizeof(DWORD);
	*(ULONG_PTR *)buf = (ULONG_PTR)buf + 2 + 4 + 8 + 8;
	buf += sizeof(ULONG_PTR);

	*buf++ = 0xff;
	*buf++ = 0x25;
	*(DWORD *)buf = 0;
	buf += sizeof(DWORD);
	*(ULONG_PTR *)buf = addr;
	buf += sizeof(ULONG_PTR);

	return buf;
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

static ULONG_PTR get_indirect_target(unsigned char *buf)
{
	return *(ULONG_PTR *)(buf + 6 + *(int *)&buf[2]);
}

static ULONG_PTR get_corresponding_tramp_target(addr_map_t *map, ULONG_PTR addr)
{
	unsigned int i = 0;
	while (map->map[i][1]) {
		if (map->map[i][1] == addr)
			return map->map[i][0];
	}
	return 0;
}

static int addr_is_in_range(ULONG_PTR addr, const unsigned char *buf, DWORD size)
{
	ULONG_PTR start = (ULONG_PTR)buf;
	ULONG_PTR end = start + size;

	if (addr >= start && addr < end)
		return 1;
	return 0;
}

static void retarget_rip_relative_displacement(unsigned char **tramp, unsigned char **addr, _DInst *insn)
{
	unsigned short length = insn->size;
	unsigned char offset = (unsigned char)(length - insn->imm_encoded_size - sizeof(int));
	unsigned char *newtramp = *tramp;
	unsigned char *newaddr = *addr;
	ULONG_PTR target;
	int rel = *(int *)(newaddr + offset);
	target = (ULONG_PTR)(newaddr + length + rel);
	// copy the instruction directly to the trampoline
	while (length-- != 0) {
		*newtramp++ = *newaddr++;
	}
	// now replace the displacement
	rel = (int)(target - (ULONG_PTR)newtramp);
	*(int *)(newtramp - insn->imm_encoded_size - sizeof(int)) = rel;

	*tramp = newtramp;
	*addr = newaddr;
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
	addr_map_t addrmap;
	ULONG_PTR target;
	const unsigned char *base = tramp;
	const unsigned char *origaddr = addr;
	unsigned char insnidx = 0;
	int stoleninstrlen = 0;
	_DInst *insn;

	memset(&addrmap, 0, sizeof(addrmap));

	// our trampoline should contain at least enough bytes to fit the given
	// length
	while (len > 0) {
		int length;

		insn = get_insn(addr);
		if (insn == NULL)
			goto error;
		length = insn->size;

		// how many bytes left?
		len -= length;
		stoleninstrlen += length;

		addrmap.map[insnidx][0] = (ULONG_PTR)tramp;
		addrmap.map[insnidx][1] = (ULONG_PTR)addr;

		// check the type of instruction at this particular address, if it's
		// a jump or a call instruction, then we have to calculate some fancy
		// addresses, otherwise we can simply copy the instruction to our
		// trampoline

		if (addr[0] == 0xe8 || addr[0] == 0xe9 || (addr[0] == 0x0f && addr[1] >= 0x80 && addr[1] < 0x90) ||
			(insn->flags & FLAG_RIP_RELATIVE)) {
			retarget_rip_relative_displacement(&tramp, &addr, insn);
			if (addr[0] == 0xe9 && len > 0)
				goto error;
		}

		else if (addr[0] == 0xeb) {
			target = get_short_rel_target(addr);
			if (addr_is_in_range(target, origaddr, stoleninstrlen))
				target = get_corresponding_tramp_target(&addrmap, target);
			tramp = emit_indirect_jmp(tramp, target);
			addr += length;
			if (len > 0)
				goto error;
		}
		else if (addr[0] == 0xe3 || ((addr[0] & 0xf0) == 0x70)) {
			target = get_short_rel_target(addr);
			if (addr_is_in_range(target, origaddr, stoleninstrlen))
				target = get_corresponding_tramp_target(&addrmap, target);
			tramp = emit_indirect_jcc(addr[0], tramp, target);
			addr += length;
		}
		// return instruction, indicates end of basic block as well, so we
		// have to check if we already have enough space for our hook..
		else if ((addr[0] == 0xc3 || addr[0] == 0xc2) && len > 0) {
			goto error;
		}
		else {
			// copy the instruction directly to the trampoline
			while (length-- != 0) {
				*tramp++ = *addr++;
			}
		}
		put_insn(insn);
	}

	// append a jump from the trampoline to the original function
	*tramp++ = 0xe9;
	emit_rel(tramp, tramp, addr);
	tramp += 4;

	// return the length of this trampoline
	return (int)(tramp - base);
error:
	if (insn)
		put_insn(insn);
	return 0;
}

// needs to be updated whenever the assembly below changes
void add_unwind_info(hook_t *h)
{
	RUNTIME_FUNCTION *functable;
	UNWIND_INFO *unwindinfo;
	BYTE regs1[] = { 11, 10, 9, 8 };
	BYTE regs2[] = { 3, 2, 1, 0 };
	int i, x;

	/* would be really nice if MSDN had any mention whatsoever that the RUNTIME_FUNCTION needs to have
	a global allocation -- it doesn't copy the contents of the tiny 12-byte RUNTIME_FUNCTION, it merely
	stores the same pointer you provide to the API.  If you allocate it on the stack, or call the API multiple
	times with the same pointer value, you'll end up with completely broken unwind information that fails
	in spectacular ways.
	*/
	functable = malloc(sizeof(RUNTIME_FUNCTION));
	unwindinfo = &h->hookdata->unwind_info;

	functable->BeginAddress = offsetof(hook_data_t, pre_tramp);
	functable->EndAddress = offsetof(hook_data_t, pre_tramp) + sizeof(h->hookdata->pre_tramp);
	functable->UnwindData = offsetof(hook_data_t, unwind_info);

	unwindinfo->Version = 1;
	unwindinfo->Flags = UNW_FLAG_NHANDLER;
	if (h->notail && h->numargs > 4) {
		unwindinfo->SizeOfProlog = 0xad;
	}
	else if (h->notail) {
		unwindinfo->SizeOfProlog = 0x7d;
	}
	else {
		unwindinfo->SizeOfProlog = 50;
	}
	unwindinfo->FrameRegister = 0;
	unwindinfo->FrameOffset = 0;

	i = 0;
	if (h->notail && h->numargs > 4) {
		unwindinfo->UnwindCode[i].UnwindOp = UWOP_ALLOC_SMALL;
		unwindinfo->UnwindCode[i].CodeOffset = 0xa7;
		unwindinfo->UnwindCode[i].OpInfo = 3; // (3 + 1) * 8 = 0x20
		i++;

		unwindinfo->UnwindCode[i].UnwindOp = UWOP_ALLOC_SMALL;
		unwindinfo->UnwindCode[i].CodeOffset = 0x9a;
		unwindinfo->UnwindCode[i].OpInfo = h->numargs - 5;
		i++;

		if (h->numargs & 1) {
			unwindinfo->UnwindCode[i].UnwindOp = UWOP_ALLOC_SMALL;
			unwindinfo->UnwindCode[i].CodeOffset = 0x97;
			unwindinfo->UnwindCode[i].OpInfo = 0; // (0 + 1) * 8 = 8
			i++;
		}
	}

	if (h->notail) {
		unwindinfo->UnwindCode[i].UnwindOp = UWOP_ALLOC_SMALL;
		unwindinfo->UnwindCode[i].CodeOffset = 0x2e;
		unwindinfo->UnwindCode[i].OpInfo = 3; // (3 + 1) * 8 = 0x20
		i++;

		for (x = 0; x < ARRAYSIZE(regs1); x++) {
			unwindinfo->UnwindCode[x + i].UnwindOp = UWOP_PUSH_NONVOL;
			unwindinfo->UnwindCode[x + i].CodeOffset = 16 - (2 * x);
			unwindinfo->UnwindCode[x + i].OpInfo = regs1[x];
		}
		i += x;


		for (x = 0; x < ARRAYSIZE(regs2); x++) {
			unwindinfo->UnwindCode[x + i].UnwindOp = UWOP_PUSH_NONVOL;
			unwindinfo->UnwindCode[x + i].CodeOffset = 8 - x;
			unwindinfo->UnwindCode[x + i].OpInfo = regs2[x];
		}
		i += x;

		// rdi
		unwindinfo->UnwindCode[i].UnwindOp = UWOP_PUSH_NONVOL;
		unwindinfo->UnwindCode[i].CodeOffset = 4;
		unwindinfo->UnwindCode[i].OpInfo = 7;
		i++;

		// rsi
		unwindinfo->UnwindCode[i].UnwindOp = UWOP_PUSH_NONVOL;
		unwindinfo->UnwindCode[i].CodeOffset = 3;
		unwindinfo->UnwindCode[i].OpInfo = 6;
		i++;

	}
	else {
		unwindinfo->UnwindCode[i].UnwindOp = UWOP_ALLOC_SMALL;
		unwindinfo->UnwindCode[i].CodeOffset = 44;
		unwindinfo->UnwindCode[i].OpInfo = 3; // (3 + 1) * 8 = 0x20
		i++;

		for (x = 0; x < ARRAYSIZE(regs1); x++) {
			unwindinfo->UnwindCode[x + i].UnwindOp = UWOP_PUSH_NONVOL;
			unwindinfo->UnwindCode[x + i].CodeOffset = 14 - (2 * x);
			unwindinfo->UnwindCode[x + i].OpInfo = regs1[x];
		}
		i += x;


		for (x = 0; x < ARRAYSIZE(regs2); x++) {
			unwindinfo->UnwindCode[x + i].UnwindOp = UWOP_PUSH_NONVOL;
			unwindinfo->UnwindCode[x + i].CodeOffset = 6 - x;
			unwindinfo->UnwindCode[x + i].OpInfo = regs2[x];
		}
		i += x;
	}

	unwindinfo->UnwindCode[i].UnwindOp = UWOP_ALLOC_SMALL;
	unwindinfo->UnwindCode[i].CodeOffset = 1;
	unwindinfo->UnwindCode[i].OpInfo = 0; // (0 + 1) * 8 = 8
	i++;

	unwindinfo->CountOfCodes = i;

	RtlAddFunctionTable(functable, 1, (DWORD64)h->hookdata);
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
		// pushfq
		0x9c,
		// cld
		0xfc,
		// push rax/rcx/rdx/rbx
		0x50, 0x51, 0x52, 0x53,
		// push r8, r9, r10, r11
		0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
		// call $+0
		0xe8, 0x00, 0x00, 0x00, 0x00,
		// pop r8
		0x41, 0x58,
		// sub r8, 19
		0x49, 0x83, 0xe8, 0x13,
		// mov r8, qword ptr [rsp+0x48]
		// 0x4c, 0x8b, 0x44, 0x24, 0x48,
		// lea rdx, [rsp+0x48]
		0x48, 0x8d, 0x54, 0x24, 0x48,
		// mov rcx, h
		0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	// 40
	unsigned char pre_tramp12[] = {
		// sub rsp, 0x20
		0x48, 0x83, 0xec, 0x20,
		// call enter_hook, returns 0 if we should call the original func, otherwise 1 if we should call our New_ version
		0xff, 0x15, 0x02, 0x00, 0x00, 0x00,
		// jmp $+8
		0xeb, 0x08,
		// address of enter_hook
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char pre_tramp2[] = {
		// test eax, eax
		0x85, 0xc0,
		// jnz 0x1f
		0x75, 0x1f,
		// add rsp, 0x20
		0x48, 0x83, 0xc4, 0x20,
		// pop r11, r10, r9, r8
		0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58,
		// pop rbx/rdx/rcx/rax
		0x5b, 0x5a, 0x59, 0x58,
		// popfq
		0x9d,
		// jmp h->tramp (original function)
		0xff, 0x25, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char pre_tramp3[] = {
		// add rsp, 0x20
		0x48, 0x83, 0xc4, 0x20,
		// pop r11, r10, r9, r8
		0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58,
		// pop rbx/rdx/rcx/rax
		0x5b, 0x5a, 0x59, 0x58,
		// popfq
		0x9d,
		// jmp h->new_func (New_ func)
		0xff, 0x25, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	if (disable_this_hook(h)) {
		memcpy(h->hookdata->pre_tramp, "\xff\x25\x00\x00\x00\x00", 6);
		*(ULONG_PTR *)(h->hookdata->pre_tramp + 6) = (ULONG_PTR)h->hookdata->tramp;
		return;
	}

	p = h->hookdata->pre_tramp;
	off = sizeof(pre_tramp1) - sizeof(ULONG_PTR);
	*(ULONG_PTR *)(pre_tramp1 + off) = (ULONG_PTR)h;
	memcpy(p, pre_tramp1, sizeof(pre_tramp1));
	p += sizeof(pre_tramp1);

	off = sizeof(pre_tramp12) - sizeof(ULONG_PTR);
	*(ULONG_PTR *)(pre_tramp12 + off) = (ULONG_PTR)&enter_hook;
	memcpy(p, pre_tramp12, sizeof(pre_tramp12));
	p += sizeof(pre_tramp12);

	off = sizeof(pre_tramp2) - sizeof(ULONG_PTR);
	*(ULONG_PTR *)(pre_tramp2 + off) = (ULONG_PTR)h->hookdata->tramp;
	memcpy(p, pre_tramp2, sizeof(pre_tramp2));
	p += sizeof(pre_tramp2);

	off = sizeof(pre_tramp3) - sizeof(ULONG_PTR);
	*(ULONG_PTR *)(pre_tramp3 + off) = (ULONG_PTR)h->new_func;
	memcpy(p, pre_tramp3, sizeof(pre_tramp3));
	p += sizeof(pre_tramp3);

	assert((ULONG_PTR)(p - h->hookdata->pre_tramp) < MAX_PRETRAMP_SIZE);

	/* now add the necessary unwind information so that stack traces at enter_hook work
	 * properly.  must be modified whenever the assembly above changes
	 */
	add_unwind_info(h);
}

static void hook_create_pre_tramp_notail(hook_t *h)
{
	unsigned char *p;
	unsigned int off;

	unsigned char pre_tramp1[] = {
		// pushfq
		0x9c,
		// cld
		0xfc,
		// push rsi/rdi
		0x56, 0x57,
		// push rax/rcx/rdx/rbx
		0x50, 0x51, 0x52, 0x53,
		// push r8, r9, r10, r11
		0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
		// call $+0
		0xe8, 0x00, 0x00, 0x00, 0x00,
		// pop r8
		0x41, 0x58,
		// sub r8, 0x15
		0x49, 0x83, 0xe8, 0x15,
		// lea rdx, [rsp+0x58]
		0x48, 0x8d, 0x54, 0x24, 0x58,
		// mov rcx, h
		0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	unsigned char pre_tramp12[] = {
		// sub rsp, 0x20
		0x48, 0x83, 0xec, 0x20,
		// call enter_hook, returns 0 if we should call the original func, otherwise 1 if we should call our New_ version
		0xff, 0x15, 0x02, 0x00, 0x00, 0x00,
		// jmp $+8
		0xeb, 0x08,
		// address of enter_hook
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char pre_tramp2[] = {
		// test eax, eax
		0x85, 0xc0,
		// jnz 0x21
		0x75, 0x21,
		// add rsp, 0x20
		0x48, 0x83, 0xc4, 0x20,
		// pop r11, r10, r9, r8
		0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58,
		// pop rbx/rdx/rcx/rax
		0x5b, 0x5a, 0x59, 0x58,
		// pop rdi/rsi
		0x5f, 0x5e,
		// popfq
		0x9d,
		// jmp h->tramp (original function)
		0xff, 0x25, 0x00, 0x00, 0x00, 0x00,
		// address of original function
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char pre_tramp3_nostack[] = {
		// mov rcx, [rsp+0x50]
		0x48, 0x8b, 0x4c, 0x24, 0x50,
		// mov rdx, [rsp+0x48]
		0x48, 0x8b, 0x54, 0x24, 0x48,
		// mov r8, [rsp+0x38]
		0x4c, 0x8b, 0x44, 0x24, 0x38,
		// mov r9, [rsp+0x30]
		0x4c, 0x8b, 0x4c, 0x24, 0x30,
		// 112
		// call h->new_func (New_ func)
		0xff, 0x15, 0x02, 0x00, 0x00, 0x00,
		// jmp $+8
		0xeb, 0x08,
		// address of new function
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char pre_tramp3_stack[] = {
		// mov ecx, numargs
		0xb9, h->numargs, 0x00, 0x00, 0x00,
		// sub ecx, 0x4
		0x83, 0xe9, 0x04,
		// mov eax, ecx
		0x89, 0xc8,
		// lea rsi, [rsp+0xa0]
		0x48, 0x8d, 0xb4, 0x24, 0xa0, 0x00, 0x00, 0x00,
		// shl eax, 3
		0xc1, 0xe0, 0x03,
		// mov r10, [rsp+0x50], this is RCX, we're storing it in a temp reg for now
		0x4c, 0x8b, 0x54, 0x24, 0x50,
		// mov rdx, [rsp+0x48]
		0x48, 0x8b, 0x54, 0x24, 0x48,
		// mov r8, [rsp+0x38]
		0x4c, 0x8b, 0x44, 0x24, 0x38,
		// mov r9, [rsp+0x30]
		0x4c, 0x8b, 0x4c, 0x24, 0x30,
		// test eax, 8
		0xa9, 0x08, 0x00, 0x00, 0x00,
		// jz $+0x4
		0x74, 0x04,
		// sub rsp, 8
		0x48, 0x83, 0xec, 0x08,
		// sub rsp, rax
		0x48, 0x29, 0xc4,
		// mov rdi, rsp
		0x48, 0x89, 0xe7,
		// repne movsq
		0xf2, 0x48, 0xa5,
		// mov rcx, r10
		0x4c, 0x89, 0xd1,
		// sub rsp, 0x20
		0x48, 0x83, 0xec, 0x20,
		// call h->new_func (New_ func)
		0xff, 0x15, 0x02, 0x00, 0x00, 0x00,
		// jmp $+8
		0xeb, 0x08,
		// address of new function
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char pre_tramp4_nostack[] = {
		// test eax, eax
		0x85, 0xc0,
		// jnz 0x21
		0x75, 0x21,
		// add rsp, 0x20 (from pre_tramp12)
		0x48, 0x83, 0xc4, 0x20,
		// pop r11, r10, r9, r8
		0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58,
		// pop rbx/rdx/rcx/rax
		0x5b, 0x5a, 0x59, 0x58,
		// pop rdi/rsi
		0x5f, 0x5e,
		// popfq
		0x9d,
		// jmp h->tramp (original function)
		0xff, 0x25, 0x00, 0x00, 0x00, 0x00,
		// address of original function
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char pre_tramp4_stack[] = {
		// test eax, eax
		0x85, 0xc0,
		// jnz 0x3c
		0x75, 0x3c,
		// mov eax, numargs
		0xb8, h->numargs, 0x00, 0x00, 0x00,
		// sub eax, 0x4
		0x83, 0xe8, 0x04,
		// shl eax, 3
		0xc1, 0xe0, 0x03,
		// test eax, 8
		0xa9, 0x08, 0x00, 0x00, 0x00,
		// jz $+0x3
		0x74, 0x03,
		// add eax, 8
		0x83, 0xc0, 0x08,
		// add eax, 0x20
		0x83, 0xc0, 0x20,
		// add rsp, rax
		0x48, 0x01, 0xc4,
		// add rsp, 0x20 (from pre_tramp12)
		0x48, 0x83, 0xc4, 0x20,
		// pop r11, r10, r9, r8
		0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58,
		// pop rbx/rdx/rcx/rax
		0x5b, 0x5a, 0x59, 0x58,
		// pop rdi/rsi
		0x5f, 0x5e,
		// popfq
		0x9d,
		// jmp h->tramp (original function)
		0xff, 0x25, 0x00, 0x00, 0x00, 0x00,
		// address of original function
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char pre_tramp5_nostack[] = {
		// add rsp, 0x20 (from pre_tramp12)
		0x48, 0x83, 0xc4, 0x20,
		// pop r11, r10, r9, r8
		0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58,
		// pop rbx/rdx/rcx/rax
		0x5b, 0x5a, 0x59, 0x58,
		// pop rdi/rsi
		0x5f, 0x5e,
		// popfq
		0x9d,
		// jmp h->alt_func
		0xff, 0x25, 0x00, 0x00, 0x00, 0x00,
		// address of alternate function
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char pre_tramp5_stack[] = {
		// mov eax, numargs
		0xb8, h->numargs, 0x00, 0x00, 0x00,
		// sub eax, 0x4
		0x83, 0xe8, 0x04,
		// shl eax, 3
		0xc1, 0xe0, 0x03,
		// test eax, 8
		0xa9, 0x08, 0x00, 0x00, 0x00,
		// jz $+0x3
		0x74, 0x03,
		// add eax, 8
		0x83, 0xc0, 0x08,
		// add eax, 0x20
		0x83, 0xc0, 0x20,
		// add rsp, rax
		0x48, 0x01, 0xc4,
		// add rsp, 0x20 (from pre_tramp12)
		0x48, 0x83, 0xc4, 0x20,
		// pop r11, r10, r9, r8
		0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58,
		// pop rbx/rdx/rcx/rax
		0x5b, 0x5a, 0x59, 0x58,
		// pop rdi/rsi
		0x5f, 0x5e,
		// popfq
		0x9d,
		// jmp h->alt_func
		0xff, 0x25, 0x00, 0x00, 0x00, 0x00,
		// address of alternate function
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	if (disable_this_hook(h)) {
		memcpy(h->hookdata->pre_tramp, "\xff\x25\x00\x00\x00\x00", 6);
		*(ULONG_PTR *)(h->hookdata->pre_tramp + 6) = (ULONG_PTR)h->hookdata->tramp;
		return;
	}

	p = h->hookdata->pre_tramp;
	off = sizeof(pre_tramp1) - sizeof(ULONG_PTR);
	*(ULONG_PTR *)(pre_tramp1 + off) = (ULONG_PTR)h;
	memcpy(p, pre_tramp1, sizeof(pre_tramp1));
	p += sizeof(pre_tramp1);

	off = sizeof(pre_tramp12) - sizeof(ULONG_PTR);
	*(ULONG_PTR *)(pre_tramp12 + off) = (ULONG_PTR)&enter_hook;
	memcpy(p, pre_tramp12, sizeof(pre_tramp12));
	p += sizeof(pre_tramp12);

	off = sizeof(pre_tramp2) - sizeof(ULONG_PTR);
	*(ULONG_PTR *)(pre_tramp2 + off) = (ULONG_PTR)h->hookdata->tramp;
	memcpy(p, pre_tramp2, sizeof(pre_tramp2));
	p += sizeof(pre_tramp2);

	if (h->numargs > 4) {
		off = sizeof(pre_tramp3_stack) - sizeof(ULONG_PTR);
		*(ULONG_PTR *)(pre_tramp3_stack + off) = (ULONG_PTR)h->new_func;
		memcpy(p, pre_tramp3_stack, sizeof(pre_tramp3_stack));
		p += sizeof(pre_tramp3_stack);

		off = sizeof(pre_tramp4_stack) - sizeof(ULONG_PTR);
		*(ULONG_PTR *)(pre_tramp4_stack + off) = (ULONG_PTR)h->hookdata->tramp;
		memcpy(p, pre_tramp4_stack, sizeof(pre_tramp4_stack));
		p += sizeof(pre_tramp4_stack);

		off = sizeof(pre_tramp5_stack) - sizeof(ULONG_PTR);
		*(ULONG_PTR *)(pre_tramp5_stack + off) = (ULONG_PTR)h->alt_func;
		memcpy(p, pre_tramp5_stack, sizeof(pre_tramp5_stack));
		p += sizeof(pre_tramp5_stack);
	}
	else {
		off = sizeof(pre_tramp3_nostack) - sizeof(ULONG_PTR);
		*(ULONG_PTR *)(pre_tramp3_nostack + off) = (ULONG_PTR)h->new_func;
		memcpy(p, pre_tramp3_nostack, sizeof(pre_tramp3_nostack));
		p += sizeof(pre_tramp3_nostack);

		off = sizeof(pre_tramp4_nostack) - sizeof(ULONG_PTR);
		*(ULONG_PTR *)(pre_tramp4_nostack + off) = (ULONG_PTR)h->hookdata->tramp;
		memcpy(p, pre_tramp4_nostack, sizeof(pre_tramp4_nostack));
		p += sizeof(pre_tramp4_nostack);

		off = sizeof(pre_tramp5_nostack) - sizeof(ULONG_PTR);
		*(ULONG_PTR *)(pre_tramp5_nostack + off) = (ULONG_PTR)h->alt_func;
		memcpy(p, pre_tramp5_nostack, sizeof(pre_tramp5_nostack));
		p += sizeof(pre_tramp5_nostack);
	}

	assert((ULONG_PTR)(p - h->hookdata->pre_tramp) < MAX_PRETRAMP_SIZE);

	/* now add the necessary unwind information so that stack traces at enter_hook work
	* properly.  must be modified whenever the assembly above changes
	*/
	add_unwind_info(h);
}

static int hook_api_jmp_indirect(hook_t *h, unsigned char *from,
	unsigned char *to)
{
	// jmp dword [hook_data]
	*from++ = 0xff;
	*from++ = 0x25;

	*(int *)from = (int)((ULONG_PTR)h->hookdata->hook_data - ((ULONG_PTR)from + 4));

	// the real address is stored in hook_data
	memcpy(h->hookdata->hook_data, &to, sizeof(to));
	return 0;
}

static int hook_api_native_jmp_indirect(hook_t *h, unsigned char *from,
	unsigned char *to)
{
	// hook used for Native API functions where the second instruction specifies the syscall number
	// we'll leave in that mov instruction and repeat it before calling the original function
	from += 8;
	return hook_api_jmp_indirect(h, from, to);
}

hook_data_t *alloc_hookdata_near(void *addr)
{
	PVOID BaseAddress;
	int offset = -(1024 * 1024 * 1024);
	SIZE_T RegionSize = sizeof(hook_data_t);
	LONG status;

	do {
		if (offset < 0 && (ULONG_PTR)addr < (ULONG_PTR)-offset)
			offset = 0x10000;
		BaseAddress = (PCHAR)addr + offset;
		status = pNtAllocateVirtualMemory(GetCurrentProcess(), &BaseAddress, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (status >= 0)
			return (hook_data_t *)BaseAddress;
		offset += 0x10000;
	} while (status < 0 && offset <= (1024 * 1024 * 1024));

	return NULL;
}

unsigned char *handle_stub(hook_t *h, unsigned char *addr)
{
	unsigned char stack_offset = 0;
	unsigned char *p = addr;
	unsigned char *new_addr = NULL;
	int found_call = 0;

	while (*p != 0xc3 && *p != 0xe9 && *p != 0xeb) {
		if (!memcmp(p, "\x48\x83\xec", 3)) {
			if (stack_offset)
				goto out;
			stack_offset = p[3];
			p += 4;
		}
		else if (!memcmp(p, "\x48\x8b\x44\x24", 4))
			p += 5;
		else if (!memcmp(p, "\x48\x8b\x84\x24", 4))
			p += 8;
		else if (!memcmp(p, "\x8b\x44\x24", 3))
			p += 4;
		else if (!memcmp(p, "\x8b\x84\x24", 3))
			p += 7;
		else if (!memcmp(p, "\x48\x89\x44\x24", 4))
			p += 5;
		else if (!memcmp(p, "\x89\x44\x24", 3))
			p += 4;
		else if (!memcmp(p, "\x48\x83\xc4", 3)) {
			if (!stack_offset || *(unsigned char *)&p[3] != stack_offset)
				goto out;
			p += 4;
		}
		else if (p[0] == 0xe8) {
			unsigned char *target;
			target = (unsigned char *)get_near_rel_target(p);
			if (target[0] != 0xff || target[1] != 0x25)
				goto out;
			new_addr = (unsigned char *)get_indirect_target(target);
			found_call = 1;
			p += 5;
		}
		else
			goto out;
	}
	if (new_addr)
		return new_addr;
out:
	return addr;
}

int hook_api(hook_t *h, int type)
{
	DWORD old_protect;
	int ret = -1;
	unsigned char *addr;

	// table with all possible hooking types
	static struct {
		int(*hook)(hook_t *h, unsigned char *from, unsigned char *to);
		int len;
	} hook_types[] = {
		/* HOOK_NATIVE_JMP_INDIRECT */{ &hook_api_native_jmp_indirect, 14 },
		/* HOOK_JMP_INDIRECT */{ &hook_api_jmp_indirect, 6 },
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
			if (tmpaddr[18] == 0xe8 && tmpaddr[27] == 0xc3) {
				addr = (unsigned char *)get_near_rel_target(tmpaddr + 18);
			} else
				addr = (unsigned char *)GetProcAddress(hmod, h->funcname);
		}
		else if (!strcmp(h->funcname, "JsEval"))
			addr = (unsigned char *)get_jseval_addr(hmod);
		else if (!strcmp(h->funcname, "COleScript_ParseScriptText"))
			addr = (unsigned char *)get_olescript_parsescripttext_addr(hmod);
		else if (!strcmp(h->funcname, "CDocument_write"))
			addr = (unsigned char *)get_cdocument_write_addr(hmod);
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
	if (addr == NULL) {
		// function doesn't exist in this DLL, not a critical error
		return 0;
	}

	addr = handle_stub(h, addr);

	if (addr[0] == 0xeb) {
		PUCHAR target = (PUCHAR)get_short_rel_target(addr);
		if (target[0] == 0xff && target[1] == 0x25) {
			PUCHAR origaddr = addr;
			addr = (PUCHAR)get_indirect_target(target);
			// handle delay-loaded DLL stubs
			if (!memcmp(addr, "\x48\x8d\x05", 3) && addr[7] == 0xe9) {
				// skip this particular hook, we'll hook the delay-loaded DLL at the time
				// is is loaded.  This means we will have duplicate "hook" entries
				// but to avoid any problems, we will check before hooking to see
				// if the final function has already been hooked
				return 0;
			}
		}
	}
	else if (addr[0] == 0xe9) {
		PUCHAR target = (PUCHAR)get_near_rel_target(addr);
		unhook_detect_add_region(h, addr, addr, addr, 5);
		if (target[0] == 0xff && target[1] == 0x25) {
			addr = (PUCHAR)get_indirect_target(target);
			// handle delay-loaded DLL stubs
			if (!memcmp(addr, "\x48\x8d\x05", 3) && addr[7] == 0xe9) {
				// skip this particular hook, we'll hook the delay-loaded DLL at the time
				// is is loaded.  This means we will have duplicate "hook" entries
				// but to avoid any problems, we will check before hooking to see
				// if the final function has already been hooked
				return 0;
			}
		}
		else {
			addr = target;
		}
	}

	addr = handle_stub(h, addr);

	/*
	if (!wcscmp(h->library, L"ntdll") && !memcmp(addr, "\x4c\x8b\xd1\xb8", 4)) {
		// hooking a native API, leave in the mov eax, <syscall nr> instruction
		// as some malware depends on this for direct syscalls
		// missing a few syscalls is better than crashing and getting no information
		// at all
		type = HOOK_NATIVE_JMP_INDIRECT;
	}
	*/

	// check if this is a valid hook type
	if (type < 0 && type >= ARRAYSIZE(hook_types)) {
		pipe("WARNING: Provided invalid hook type: %d", type);
		return ret;
	}

	// make sure we aren't trying to hook the same address twice, as could
	// happen due to delay-loaded DLLs
	if (address_already_hooked(addr))
		return 0;

	// make the address writable
	if (VirtualProtect(addr, hook_types[type].len, PAGE_EXECUTE_READWRITE,
		&old_protect)) {

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
			unhook_detect_add_region(h, addr, orig, addr, hook_types[type].len);

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
		VirtualProtect(addr, hook_types[type].len, old_protect,
			&old_protect);
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

BOOL srw_lock_held()
{
	if (!LdrpInvertedFunctionTableSRWLock)
		return FALSE;
	if (*(PVOID*)LdrpInvertedFunctionTableSRWLock)
		return TRUE;
	return FALSE;
}

static int our_stackwalk(ULONG_PTR _rip, ULONG_PTR sp, PVOID *backtrace, unsigned int count)
{
	/* derived from http://www.nynaeve.net/Code/StackWalk64.cpp */
	__declspec(align(64)) CONTEXT ctx;
	DWORD64 imgbase;
	PRUNTIME_FUNCTION runfunc;
	KNONVOLATILE_CONTEXT_POINTERS nvctx;
	PVOID handlerdata;
	ULONG_PTR establisherframe;
	unsigned int frame;

	if (srw_lock_held())
		return -1;

	__try
	{
		RtlCaptureContext(&ctx);

		for (frame = 0; frame < count; frame++) {
			backtrace[frame] = (PVOID)ctx.Rip;
			runfunc = RtlLookupFunctionEntry(ctx.Rip, &imgbase, NULL);	// needs LdrpInvertedFunctionTableSRWLock on Win10
			memset(&nvctx, 0, sizeof(nvctx));
			if (runfunc == NULL) {
				ctx.Rip = (ULONG_PTR)(*(ULONG_PTR *)ctx.Rsp);
				ctx.Rsp += 8;
			}
			else {
				RtlVirtualUnwind(UNW_FLAG_NHANDLER, imgbase, ctx.Rip, runfunc, &ctx, &handlerdata, &establisherframe, &nvctx);
			}
			if (!ctx.Rip)
				break;
		}

		return frame + 1;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return -1;
	}
}

int operate_on_backtrace(ULONG_PTR sp, ULONG_PTR _rip, void *extra, int(*func)(void *, ULONG_PTR))
{
	PVOID backtrace[HOOK_BACKTRACE_DEPTH];
	lasterror_t lasterror;
	int i, frames, ret = -1;

	get_lasterrors(&lasterror);

	hook_disable();

	frames = our_stackwalk(_rip, sp, backtrace, HOOK_BACKTRACE_DEPTH);

	for (i = 0; i < frames; i++) {
		if (!addr_in_our_dll_range(NULL, (ULONG_PTR)backtrace[i]))
			break;
	}

	if (i < frames && ((PUCHAR)backtrace[i])[0] == 0xeb && ((PUCHAR)backtrace[i])[1] == 0x08)
		i++;

	for (; i < frames; i++) {
		ret = func(extra, (ULONG_PTR)backtrace[i]);
		if (ret)
			goto out;
	}

out:
	hook_enable();
	set_lasterrors(&lasterror);
	return ret;
}
#endif