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
GLOBAL	_Start

;
; Imports
;
EXTERN	_Entry

;
; Section
;
[SECTION .text$A]

;
; Purpose:
;
; Start of the code, aligns the stack and calls
; the entrypoint of the C portion.
;
_Start:
	; prepare the stack and align it
	push	ebp
	mov	ebp, esp

	; execute the entrypoint
	call	_Entry

	; cleanup
	mov	esp, ebp
	pop	ebp

	; return
	ret
