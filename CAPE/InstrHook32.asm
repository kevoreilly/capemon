include CallConv.inc
.model flat

extern _InstrumentationCallback:near

.code
_InstrHook proc

	pushad
	pushfd
    cld
	push eax
	push ecx
    call _InstrumentationCallback
	add esp, 8	
	popfd
	popad

ReturnToCaller:
	jmp ecx

_InstrHook endp

end
