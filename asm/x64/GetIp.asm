;
; ROGUE
;
; GuidePoint Security LLC
;
; Threat and Attack Simulation Team
;
[BITS 64]

;
; Exports
;
GLOBAL	GetIp


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
GetIp:
	; execute the next instruction
	call	get_ret_ptr
	return_addr:
	get_ret_ptr:
	; pop the address of the stack
	pop	rax

	; sub the diff between return
	sub	rax, 5

	; return the addr of GetIp
	ret

Leave:
	db 'ENDOFCODE'
