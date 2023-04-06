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
GLOBAL	Start

;
; Imports
;
EXTERN	Entry

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
Start:
	; prepare the stack and align it
	push	rsi
	mov	rsi, rsp
	and	rsp, 0FFFFFFFFFFFFFFF0h

	; execute the entrypoint
	call	Entry

	; cleanup
	mov	rsp, rsi
	pop	rsi

	; return
	ret
