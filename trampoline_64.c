#include "trampoline_64.h"
#include <assert.h>
#ifndef CAPEMONWOW64_EXPORTS
#include "misc.h"
#else
// Mock assert
#undef assert
#define assert(x) 
extern void *memcpy(void *dest, const void *src, size_t n);
extern void *memset(void *s, int c, size_t n);
#endif

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

static int get_insn(void *addr, _DInst* insn)
{
	unsigned int used_instruction_count; _DInst instructions[16];
	_CodeInfo code_info = { 0, 0, (uint8_t*)addr, 16, Decode64Bits };
	_DecodeResult ret = distorm_decompose(&code_info, instructions, 16,
		&used_instruction_count);
	if (ret == DECRES_SUCCESS) {
		memcpy(insn, &instructions[0], sizeof(_DInst));
		return 1;
	}
	return 0;
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

static void retarget_relative_displacement(unsigned char **tramp, unsigned char **addr, _DInst *insn)
{
	unsigned short length = insn->size;
	unsigned char *newtramp = *tramp;
	unsigned char *newaddr = *addr;

	unsigned char offset = (unsigned char)(length - insn->imm_encoded_size - sizeof(int));
	ULONG_PTR target = (ULONG_PTR)(newaddr + length + *(int *)(newaddr + offset));
	int64_t rel = (int64_t)(target - (ULONG_PTR)(newtramp + length));

	if (rel >= INT_MIN && rel <= INT_MAX) {
		while (length-- != 0)
			*newtramp++ = *newaddr++;
		*(int *)(newtramp - insn->imm_encoded_size - sizeof(int)) = (int)rel;
	}
	else {
		// mov r11, far target
		*((WORD*)newtramp)++ = 0xBB49;
		*((ULONG_PTR *)newtramp)++ = (ULONG_PTR)target;
		if (*newaddr == 0xE8) {
			// replace call near target with call far r11
			*((WORD*)newtramp)++ = 0xFF41;
			*newtramp++ = 0xD3;
		}
		else if (*newaddr == 0xE9) {
			// replace jmp near target with jmp far r11
			*((WORD*)newtramp)++ = 0xFF41;
			*newtramp++ = 0xE3;
		}
		else if (insn->flags & FLAG_RIP_RELATIVE) {
			// rewrite instruction to use rll
			if ((*newaddr & 0xF0) == 0x40)
				// modify REX prefix to use r11
				*newtramp++ = *newaddr++ | 0x41;
			*newtramp++ = *newaddr++;
			// modify ModR/M byte to use R11
			*newtramp++ = (*newaddr++ & 0xF8) | 3;
		}
		newaddr += 4;
	}

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
int hook_create_trampoline(unsigned char *addr, int len,
	unsigned char *tramp)
{
	addr_map_t addrmap;
	ULONG_PTR target;
	const unsigned char *base = tramp;
	const unsigned char *origaddr = addr;
	unsigned char insnidx = 0;
	int stoleninstrlen = 0;
	_DInst insn_st;
	_DInst *insn;

	memset(&addrmap, 0, sizeof(addrmap));

	// our trampoline should contain at least enough bytes to fit the given
	// length
	while (len > 0) {
		int length;

		if (!get_insn(addr, &insn_st))
			goto error;
		insn = &insn_st;
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

		if (addr[0] == 0xe8 || addr[0] == 0xe9 || (addr[0] == 0x0f && addr[1] >= 0x80 && addr[1] < 0x90) || (insn->flags & FLAG_RIP_RELATIVE)) {
			retarget_relative_displacement(&tramp, &addr, insn);
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
		else if ((addr[0] == 0xc3 || addr[0] == 0xc2) && len > 0)
			goto error;
		else {
			// copy the instruction directly to the trampoline
			while (length-- != 0) {
				*tramp++ = *addr++;
			}
		}

	}

	// append a jump from the trampoline to the original function
	*((WORD*)tramp)++ = 0x25FF;
	*((DWORD*)tramp)++ = 0;
	*((uintptr_t*)tramp)++ = (uintptr_t)addr;

	// return the length of this trampoline
	return (int)(tramp - base);
error:
	if (insn)

	return 0;
}