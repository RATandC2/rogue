;
; ROGUE
;
; GuidePoint Security LLC
;
; Threat and Attack Simulation Team
;
[BITS 32]

;
; Exports
;
GLOBAL	_GetIp

;
; Section
;
[SECTION .text$C]

;
; Purpose:
;
; Calculates the address of itself and
; returns a pointer.
;
_GetIp:
	; execute the next instruction
	call	_get_ret_ptr
	_return_addr:
	_get_ret_ptr:
	; pop the address of the stack
	pop	eax

	; sub the diff between return
	sub	eax, 5

	; return the addr of GetIp
	ret

_Leave:
	db 'ENDOFCODE'
