; Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
; Use of this source code is governed by a MIT-style license that can be
; found in the LICENSE file.

;
; This module implements all assembler code
;
.686p
.model flat, stdcall
.MMX
.XMM

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; References to C functions
;
EXTERN  g_idt_routines: DWORD

EXTERN  MyIdtHandler1@8 : PROC
EXTERN  MyIdtHandler2@8 : PROC

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; constants
;
.CONST

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; macros
;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; implementations
;
.CODE

AsmThreadReturnStub PROC
    assume fs:nothing

	cli
	push  0
	pushfd
	push  edx
	push  ecx
	push  eax

	; -> 2
	mov   ecx, dword ptr fs:[1Ch]    ; KPCR
	cmp   dword ptr [ecx + 520h], 2  
	jz    NO_SWITCH
	mov   dword ptr [ecx + 520h], 2
	mov   eax, cr3        
	mov   ecx, cr4        
	mov   edx, ecx
	and   ecx, 0FFFFFF7Fh 
	mov   cr4, ecx
	mov   cr3, eax
	mov   cr4, edx
	mov   eax, 0             
	mov   ecx, 2
	db    0fh, 01h, 0d4h  
NO_SWITCH:

	; 
	mov   ecx, dword ptr fs:[124h]  ; ETHREAD
	mov   eax, [ecx + 43ch]         ; 43c
	mov   [esp + 16],  eax
	mov   byte ptr [ecx + 442h], 0  ; 

	pop   eax
	pop   ecx
	pop   edx
	popfd
	sti

	ret

AsmThreadReturnStub ENDP

AsmInterruptDispatch PROC
    assume fs:nothing
	push  edx
	push  ecx
	push  eax
	push  fs

	mov   ax,  30h    
    mov   fs,  ax     
	mov   ecx, dword ptr fs:[124h]  ; ETHREAD
	cmp   word ptr [ecx + 440h], 0BBAAh
	jnz   SKIP_RET  

	mov   al, byte ptr [ecx + 442h]
	cmp   al, 0
	jnz   SKIP_RET  

    mov   eax, dword ptr [esp + 20]
	cmp   eax, 80000000h       
	jae   SKIP_RET  


    mov   [ecx + 43ch], eax    
	mov   byte ptr [ecx + 442h], 0CCh 
	mov   dword ptr [esp + 20], AsmThreadReturnStub

	;  -> 1
	mov   ecx, dword ptr fs:[1Ch]   ;KPCR       
	cmp   dword ptr [ecx + 520h], 1
	jz    SKIP_RET
	mov   dword ptr [ecx + 520h], 1   
	mov   eax, cr3        
	mov   ecx, cr4        
	mov   edx, ecx
	and   ecx, 0FFFFFF7Fh 
	mov   cr4, ecx
	mov   cr3, eax
	mov   cr4, edx
	mov   eax, 0             
	mov   ecx, 1
	db    0fh, 01h, 0d4h 

SKIP_RET:
    mov  ecx, offset g_idt_routines
	mov  eax, [esp + 16]     ; idt vector
	mov  eax, [ecx + eax*4]
	mov  [esp + 16], eax     ; replaced by original idt routine

	pop  fs
	pop  eax
    pop  ecx
	pop  edx
	ret

CHECK_ERROR:
    int  3

AsmInterruptDispatch ENDP

KiInterruptStub30 PROC
	push 30h
	jmp  AsmInterruptDispatch
KiInterruptStub30 ENDP

KiInterruptStub31 PROC
	push 31h
	jmp  AsmInterruptDispatch
KiInterruptStub31 ENDP

KiInterruptStub32 PROC
	push 32h
	jmp  AsmInterruptDispatch
KiInterruptStub32 ENDP

KiInterruptStub33 PROC
	push 33h
	jmp  AsmInterruptDispatch
KiInterruptStub33 ENDP

KiInterruptStub34 PROC
	push 34h
	jmp  AsmInterruptDispatch
KiInterruptStub34 ENDP

KiInterruptStub35 PROC
	push 35h
	jmp  AsmInterruptDispatch
KiInterruptStub35 ENDP

KiInterruptStub36 PROC
	push 36h
	jmp  AsmInterruptDispatch
KiInterruptStub36 ENDP

KiInterruptStub37 PROC
	push 37h
	jmp  AsmInterruptDispatch
KiInterruptStub37 ENDP

KiInterruptStub38 PROC
	push 38h
	jmp  AsmInterruptDispatch
KiInterruptStub38 ENDP

KiInterruptStub39 PROC
	push 39h
	jmp  AsmInterruptDispatch
KiInterruptStub39 ENDP

KiInterruptStub3A PROC
	push 3Ah
	jmp  AsmInterruptDispatch
KiInterruptStub3A ENDP

KiInterruptStub3B PROC
	push 3Bh
	jmp  AsmInterruptDispatch
KiInterruptStub3B ENDP

KiInterruptStub3C PROC
	push 3Ch
	jmp  AsmInterruptDispatch
KiInterruptStub3C ENDP

KiInterruptStub3D PROC
	push 3Dh
	jmp  AsmInterruptDispatch
KiInterruptStub3D ENDP

KiInterruptStub3E PROC
	push 3Eh
	jmp  AsmInterruptDispatch
KiInterruptStub3E ENDP

KiInterruptStub3F PROC
	push 3Fh
	jmp  AsmInterruptDispatch
KiInterruptStub3F ENDP

KiInterruptStub40 PROC
	push 40h
	jmp  AsmInterruptDispatch
KiInterruptStub40 ENDP

KiInterruptStub41 PROC
	push 41h
	jmp  AsmInterruptDispatch
KiInterruptStub41 ENDP

KiInterruptStub42 PROC
	push 42h
	jmp  AsmInterruptDispatch
KiInterruptStub42 ENDP

KiInterruptStub43 PROC
	push 43h
	jmp  AsmInterruptDispatch
KiInterruptStub43 ENDP

KiInterruptStub44 PROC
	push 44h
	jmp  AsmInterruptDispatch
KiInterruptStub44 ENDP

KiInterruptStub45 PROC
	push 45h
	jmp  AsmInterruptDispatch
KiInterruptStub45 ENDP

KiInterruptStub46 PROC
	push 46h
	jmp  AsmInterruptDispatch
KiInterruptStub46 ENDP

KiInterruptStub47 PROC
	push 47h
	jmp  AsmInterruptDispatch
KiInterruptStub47 ENDP

KiInterruptStub48 PROC
	push 48h
	jmp  AsmInterruptDispatch
KiInterruptStub48 ENDP

KiInterruptStub49 PROC
	push 49h
	jmp  AsmInterruptDispatch
KiInterruptStub49 ENDP

KiInterruptStub4A PROC
	push 4Ah
	jmp  AsmInterruptDispatch
KiInterruptStub4A ENDP

KiInterruptStub4B PROC
	push 4Bh
	jmp  AsmInterruptDispatch
KiInterruptStub4B ENDP

KiInterruptStub4C PROC
	push 4Ch
	jmp  AsmInterruptDispatch
KiInterruptStub4C ENDP

KiInterruptStub4D PROC
	push 4Dh
	jmp  AsmInterruptDispatch
KiInterruptStub4D ENDP

KiInterruptStub4E PROC
	push 4Eh
	jmp  AsmInterruptDispatch
KiInterruptStub4E ENDP

KiInterruptStub4F PROC
	push 4Fh
	jmp  AsmInterruptDispatch
KiInterruptStub4F ENDP

KiInterruptStub50 PROC
	push 50h
	jmp  AsmInterruptDispatch
KiInterruptStub50 ENDP

KiInterruptStub51 PROC
	push 51h
	jmp  AsmInterruptDispatch
KiInterruptStub51 ENDP

KiInterruptStub52 PROC
	push 52h
	jmp  AsmInterruptDispatch
KiInterruptStub52 ENDP

KiInterruptStub53 PROC
	push 53h
	jmp  AsmInterruptDispatch
KiInterruptStub53 ENDP

KiInterruptStub54 PROC
	push 54h
	jmp  AsmInterruptDispatch
KiInterruptStub54 ENDP

KiInterruptStub55 PROC
	push 55h
	jmp  AsmInterruptDispatch
KiInterruptStub55 ENDP

KiInterruptStub56 PROC
	push 56h
	jmp  AsmInterruptDispatch
KiInterruptStub56 ENDP

KiInterruptStub57 PROC
	push 57h
	jmp  AsmInterruptDispatch
KiInterruptStub57 ENDP

KiInterruptStub58 PROC
	push 58h
	jmp  AsmInterruptDispatch
KiInterruptStub58 ENDP

KiInterruptStub59 PROC
	push 59h
	jmp  AsmInterruptDispatch
KiInterruptStub59 ENDP

KiInterruptStub5A PROC
	push 5Ah
	jmp  AsmInterruptDispatch
KiInterruptStub5A ENDP

KiInterruptStub5B PROC
	push 5Bh
	jmp  AsmInterruptDispatch
KiInterruptStub5B ENDP

KiInterruptStub5C PROC
	push 5Ch
	jmp  AsmInterruptDispatch
KiInterruptStub5C ENDP

KiInterruptStub5D PROC
	push 5Dh
	jmp  AsmInterruptDispatch
KiInterruptStub5D ENDP

KiInterruptStub5E PROC
	push 5Eh
	jmp  AsmInterruptDispatch
KiInterruptStub5E ENDP

KiInterruptStub5F PROC
	push 5Fh
	jmp  AsmInterruptDispatch
KiInterruptStub5F ENDP

KiInterruptStub60 PROC
	push 60h
	jmp  AsmInterruptDispatch
KiInterruptStub60 ENDP

KiInterruptStub61 PROC
	push 61h
	jmp  AsmInterruptDispatch
KiInterruptStub61 ENDP

KiInterruptStub62 PROC
	push 62h
	jmp  AsmInterruptDispatch
KiInterruptStub62 ENDP

KiInterruptStub63 PROC
	push 63h
	jmp  AsmInterruptDispatch
KiInterruptStub63 ENDP

KiInterruptStub64 PROC
	push 64h
	jmp  AsmInterruptDispatch
KiInterruptStub64 ENDP

KiInterruptStub65 PROC
	push 65h
	jmp  AsmInterruptDispatch
KiInterruptStub65 ENDP

KiInterruptStub66 PROC
	push 66h
	jmp  AsmInterruptDispatch
KiInterruptStub66 ENDP

KiInterruptStub67 PROC
	push 67h
	jmp  AsmInterruptDispatch
KiInterruptStub67 ENDP

KiInterruptStub68 PROC
	push 68h
	jmp  AsmInterruptDispatch
KiInterruptStub68 ENDP

KiInterruptStub69 PROC
	push 69h
	jmp  AsmInterruptDispatch
KiInterruptStub69 ENDP

KiInterruptStub6A PROC
	push 6Ah
	jmp  AsmInterruptDispatch
KiInterruptStub6A ENDP

KiInterruptStub6B PROC
	push 6Bh
	jmp  AsmInterruptDispatch
KiInterruptStub6B ENDP

KiInterruptStub6C PROC
	push 6Ch
	jmp  AsmInterruptDispatch
KiInterruptStub6C ENDP

KiInterruptStub6D PROC
	push 6Dh
	jmp  AsmInterruptDispatch
KiInterruptStub6D ENDP

KiInterruptStub6E PROC
	push 6Eh
	jmp  AsmInterruptDispatch
KiInterruptStub6E ENDP

KiInterruptStub6F PROC
	push 6Fh
	jmp  AsmInterruptDispatch
KiInterruptStub6F ENDP

KiInterruptStub70 PROC
	push 70h
	jmp  AsmInterruptDispatch
KiInterruptStub70 ENDP

KiInterruptStub71 PROC
	push 71h
	jmp  AsmInterruptDispatch
KiInterruptStub71 ENDP

KiInterruptStub72 PROC
	push 72h
	jmp  AsmInterruptDispatch
KiInterruptStub72 ENDP

KiInterruptStub73 PROC
	push 73h
	jmp  AsmInterruptDispatch
KiInterruptStub73 ENDP

KiInterruptStub74 PROC
	push 74h
	jmp  AsmInterruptDispatch
KiInterruptStub74 ENDP

KiInterruptStub75 PROC
	push 75h
	jmp  AsmInterruptDispatch
KiInterruptStub75 ENDP

KiInterruptStub76 PROC
	push 76h
	jmp  AsmInterruptDispatch
KiInterruptStub76 ENDP

KiInterruptStub77 PROC
	push 77h
	jmp  AsmInterruptDispatch
KiInterruptStub77 ENDP

KiInterruptStub78 PROC
	push 78h
	jmp  AsmInterruptDispatch
KiInterruptStub78 ENDP

KiInterruptStub79 PROC
	push 79h
	jmp  AsmInterruptDispatch
KiInterruptStub79 ENDP

KiInterruptStub7A PROC
	push 7Ah
	jmp  AsmInterruptDispatch
KiInterruptStub7A ENDP

KiInterruptStub7B PROC
	push 7Bh
	jmp  AsmInterruptDispatch
KiInterruptStub7B ENDP

KiInterruptStub7C PROC
	push 7Ch
	jmp  AsmInterruptDispatch
KiInterruptStub7C ENDP

KiInterruptStub7D PROC
	push 7Dh
	jmp  AsmInterruptDispatch
KiInterruptStub7D ENDP

KiInterruptStub7E PROC
	push 7Eh
	jmp  AsmInterruptDispatch
KiInterruptStub7E ENDP

KiInterruptStub7F PROC
	push 7Fh
	jmp  AsmInterruptDispatch
KiInterruptStub7F ENDP

KiInterruptStub80 PROC
	push 80h
	jmp  AsmInterruptDispatch
KiInterruptStub80 ENDP

KiInterruptStub81 PROC
	push 81h
	jmp  AsmInterruptDispatch
KiInterruptStub81 ENDP

KiInterruptStub82 PROC
	push 82h
	jmp  AsmInterruptDispatch
KiInterruptStub82 ENDP

KiInterruptStub83 PROC
	push 83h
	jmp  AsmInterruptDispatch
KiInterruptStub83 ENDP

KiInterruptStub84 PROC
	push 84h
	jmp  AsmInterruptDispatch
KiInterruptStub84 ENDP

KiInterruptStub85 PROC
	push 85h
	jmp  AsmInterruptDispatch
KiInterruptStub85 ENDP

KiInterruptStub86 PROC
	push 86h
	jmp  AsmInterruptDispatch
KiInterruptStub86 ENDP

KiInterruptStub87 PROC
	push 87h
	jmp  AsmInterruptDispatch
KiInterruptStub87 ENDP

KiInterruptStub88 PROC
	push 88h
	jmp  AsmInterruptDispatch
KiInterruptStub88 ENDP

KiInterruptStub89 PROC
	push 89h
	jmp  AsmInterruptDispatch
KiInterruptStub89 ENDP

KiInterruptStub8A PROC
	push 8Ah
	jmp  AsmInterruptDispatch
KiInterruptStub8A ENDP

KiInterruptStub8B PROC
	push 8Bh
	jmp  AsmInterruptDispatch
KiInterruptStub8B ENDP

KiInterruptStub8C PROC
	push 8Ch
	jmp  AsmInterruptDispatch
KiInterruptStub8C ENDP

KiInterruptStub8D PROC
	push 8Dh
	jmp  AsmInterruptDispatch
KiInterruptStub8D ENDP

KiInterruptStub8E PROC
	push 8Eh
	jmp  AsmInterruptDispatch
KiInterruptStub8E ENDP

KiInterruptStub8F PROC
	push 8Fh
	jmp  AsmInterruptDispatch
KiInterruptStub8F ENDP

KiInterruptStub90 PROC
	push 90h
	jmp  AsmInterruptDispatch
KiInterruptStub90 ENDP

KiInterruptStub91 PROC
	push 91h
	jmp  AsmInterruptDispatch
KiInterruptStub91 ENDP

KiInterruptStub92 PROC
	push 92h
	jmp  AsmInterruptDispatch
KiInterruptStub92 ENDP

KiInterruptStub93 PROC
	push 93h
	jmp  AsmInterruptDispatch
KiInterruptStub93 ENDP

KiInterruptStub94 PROC
	push 94h
	jmp  AsmInterruptDispatch
KiInterruptStub94 ENDP

KiInterruptStub95 PROC
	push 95h
	jmp  AsmInterruptDispatch
KiInterruptStub95 ENDP

KiInterruptStub96 PROC
	push 96h
	jmp  AsmInterruptDispatch
KiInterruptStub96 ENDP

KiInterruptStub97 PROC
	push 97h
	jmp  AsmInterruptDispatch
KiInterruptStub97 ENDP

KiInterruptStub98 PROC
	push 98h
	jmp  AsmInterruptDispatch
KiInterruptStub98 ENDP

KiInterruptStub99 PROC
	push 99h
	jmp  AsmInterruptDispatch
KiInterruptStub99 ENDP

KiInterruptStub9A PROC
	push 9Ah
	jmp  AsmInterruptDispatch
KiInterruptStub9A ENDP

KiInterruptStub9B PROC
	push 9Bh
	jmp  AsmInterruptDispatch
KiInterruptStub9B ENDP

KiInterruptStub9C PROC
	push 9Ch
	jmp  AsmInterruptDispatch
KiInterruptStub9C ENDP

KiInterruptStub9D PROC
	push 9Dh
	jmp  AsmInterruptDispatch
KiInterruptStub9D ENDP

KiInterruptStub9E PROC
	push 9Eh
	jmp  AsmInterruptDispatch
KiInterruptStub9E ENDP

KiInterruptStub9F PROC
	push 9Fh
	jmp  AsmInterruptDispatch
KiInterruptStub9F ENDP

KiInterruptStubA0 PROC
	push 0A0h
	jmp  AsmInterruptDispatch
KiInterruptStubA0 ENDP

KiInterruptStubA1 PROC
	push 0A1h
	jmp  AsmInterruptDispatch
KiInterruptStubA1 ENDP

KiInterruptStubA2 PROC
	push 0A2h
	jmp  AsmInterruptDispatch
KiInterruptStubA2 ENDP

KiInterruptStubA3 PROC
	push 0A3h
	jmp  AsmInterruptDispatch
KiInterruptStubA3 ENDP

KiInterruptStubA4 PROC
	push 0A4h
	jmp  AsmInterruptDispatch
KiInterruptStubA4 ENDP

KiInterruptStubA5 PROC
	push 0A5h
	jmp  AsmInterruptDispatch
KiInterruptStubA5 ENDP

KiInterruptStubA6 PROC
	push 0A6h
	jmp  AsmInterruptDispatch
KiInterruptStubA6 ENDP

KiInterruptStubA7 PROC
	push 0A7h
	jmp  AsmInterruptDispatch
KiInterruptStubA7 ENDP

KiInterruptStubA8 PROC
	push 0A8h
	jmp  AsmInterruptDispatch
KiInterruptStubA8 ENDP

KiInterruptStubA9 PROC
	push 0A9h
	jmp  AsmInterruptDispatch
KiInterruptStubA9 ENDP

KiInterruptStubAA PROC
	push 0AAh
	jmp  AsmInterruptDispatch
KiInterruptStubAA ENDP

KiInterruptStubAB PROC
	push 0ABh
	jmp  AsmInterruptDispatch
KiInterruptStubAB ENDP

KiInterruptStubAC PROC
	push 0ACh
	jmp  AsmInterruptDispatch
KiInterruptStubAC ENDP

KiInterruptStubAD PROC
	push 0ADh
	jmp  AsmInterruptDispatch
KiInterruptStubAD ENDP

KiInterruptStubAE PROC
	push 0AEh
	jmp  AsmInterruptDispatch
KiInterruptStubAE ENDP

KiInterruptStubAF PROC
	push 0AFh
	jmp  AsmInterruptDispatch
KiInterruptStubAF ENDP

KiInterruptStubB0 PROC
	push 0B0h
	jmp  AsmInterruptDispatch
KiInterruptStubB0 ENDP

KiInterruptStubB1 PROC
	push 0B1h
	jmp  AsmInterruptDispatch
KiInterruptStubB1 ENDP

KiInterruptStubB2 PROC
	push 0B2h
	jmp  AsmInterruptDispatch
KiInterruptStubB2 ENDP

KiInterruptStubB3 PROC
	push 0B3h
	jmp  AsmInterruptDispatch
KiInterruptStubB3 ENDP

KiInterruptStubB4 PROC
	push 0B4h
	jmp  AsmInterruptDispatch
KiInterruptStubB4 ENDP

KiInterruptStubB5 PROC
	push 0B5h
	jmp  AsmInterruptDispatch
KiInterruptStubB5 ENDP

KiInterruptStubB6 PROC
	push 0B6h
	jmp  AsmInterruptDispatch
KiInterruptStubB6 ENDP

KiInterruptStubB7 PROC
	push 0B7h
	jmp  AsmInterruptDispatch
KiInterruptStubB7 ENDP

KiInterruptStubB8 PROC
	push 0B8h
	jmp  AsmInterruptDispatch
KiInterruptStubB8 ENDP

KiInterruptStubB9 PROC
	push 0B9h
	jmp  AsmInterruptDispatch
KiInterruptStubB9 ENDP

KiInterruptStubBA PROC
	push 0BAh
	jmp  AsmInterruptDispatch
KiInterruptStubBA ENDP

KiInterruptStubBB PROC
	push 0BBh
	jmp  AsmInterruptDispatch
KiInterruptStubBB ENDP

KiInterruptStubBC PROC
	push 0BCh
	jmp  AsmInterruptDispatch
KiInterruptStubBC ENDP

KiInterruptStubBD PROC
	push 0BDh
	jmp  AsmInterruptDispatch
KiInterruptStubBD ENDP

KiInterruptStubBE PROC
	push 0BEh
	jmp  AsmInterruptDispatch
KiInterruptStubBE ENDP

KiInterruptStubBF PROC
	push 0BFh
	jmp  AsmInterruptDispatch
KiInterruptStubBF ENDP

KiInterruptStubC0 PROC
	push 0C0h
	jmp  AsmInterruptDispatch
KiInterruptStubC0 ENDP

KiInterruptStubC1 PROC
	push 0C1h
	jmp  AsmInterruptDispatch
KiInterruptStubC1 ENDP

KiInterruptStubC2 PROC
	push 0C2h
	jmp  AsmInterruptDispatch
KiInterruptStubC2 ENDP

KiInterruptStubC3 PROC
	push 0C3h
	jmp  AsmInterruptDispatch
KiInterruptStubC3 ENDP

KiInterruptStubC4 PROC
	push 0C4h
	jmp  AsmInterruptDispatch
KiInterruptStubC4 ENDP

KiInterruptStubC5 PROC
	push 0C5h
	jmp  AsmInterruptDispatch
KiInterruptStubC5 ENDP

KiInterruptStubC6 PROC
	push 0C6h
	jmp  AsmInterruptDispatch
KiInterruptStubC6 ENDP

KiInterruptStubC7 PROC
	push 0C7h
	jmp  AsmInterruptDispatch
KiInterruptStubC7 ENDP

KiInterruptStubC8 PROC
	push 0C8h
	jmp  AsmInterruptDispatch
KiInterruptStubC8 ENDP

KiInterruptStubC9 PROC
	push 0C9h
	jmp  AsmInterruptDispatch
KiInterruptStubC9 ENDP

KiInterruptStubCA PROC
	push 0CAh
	jmp  AsmInterruptDispatch
KiInterruptStubCA ENDP

KiInterruptStubCB PROC
	push 0CBh
	jmp  AsmInterruptDispatch
KiInterruptStubCB ENDP

KiInterruptStubCC PROC
	push 0CCh
	jmp  AsmInterruptDispatch
KiInterruptStubCC ENDP

KiInterruptStubCD PROC
	push 0CDh
	jmp  AsmInterruptDispatch
KiInterruptStubCD ENDP

KiInterruptStubCE PROC
	push 0CEh
	jmp  AsmInterruptDispatch
KiInterruptStubCE ENDP

KiInterruptStubCF PROC
	push 0CFh
	jmp  AsmInterruptDispatch
KiInterruptStubCF ENDP

KiInterruptStubD0 PROC
	push 0D0h
	jmp  AsmInterruptDispatch
KiInterruptStubD0 ENDP

KiInterruptStubD1 PROC
	push 0D1h
	jmp  AsmInterruptDispatch
KiInterruptStubD1 ENDP

KiInterruptStubD2 PROC
	push 0D2h
	jmp  AsmInterruptDispatch
KiInterruptStubD2 ENDP

KiInterruptStubD3 PROC
	push 0D3h
	jmp  AsmInterruptDispatch
KiInterruptStubD3 ENDP

KiInterruptStubD4 PROC
	push 0D4h
	jmp  AsmInterruptDispatch
KiInterruptStubD4 ENDP

KiInterruptStubD5 PROC
	push 0D5h
	jmp  AsmInterruptDispatch
KiInterruptStubD5 ENDP

KiInterruptStubD6 PROC
	push 0D6h
	jmp  AsmInterruptDispatch
KiInterruptStubD6 ENDP

KiInterruptStubD7 PROC
	push 0D7h
	jmp  AsmInterruptDispatch
KiInterruptStubD7 ENDP

KiInterruptStubD8 PROC
	push 0D8h
	jmp  AsmInterruptDispatch
KiInterruptStubD8 ENDP

KiInterruptStubD9 PROC
	push 0D9h
	jmp  AsmInterruptDispatch
KiInterruptStubD9 ENDP

KiInterruptStubDA PROC
	push 0DAh
	jmp  AsmInterruptDispatch
KiInterruptStubDA ENDP

KiInterruptStubDB PROC
	push 0DBh
	jmp  AsmInterruptDispatch
KiInterruptStubDB ENDP

KiInterruptStubDC PROC
	push 0DCh
	jmp  AsmInterruptDispatch
KiInterruptStubDC ENDP

KiInterruptStubDD PROC
	push 0DDh
	jmp  AsmInterruptDispatch
KiInterruptStubDD ENDP

KiInterruptStubDE PROC
	push 0DEh
	jmp  AsmInterruptDispatch
KiInterruptStubDE ENDP

KiInterruptStubDF PROC
	push 0DFh
	jmp  AsmInterruptDispatch
KiInterruptStubDF ENDP

KiInterruptStubE0 PROC
	push 0E0h
	jmp  AsmInterruptDispatch
KiInterruptStubE0 ENDP

KiInterruptStubE1 PROC
	push 0E1h
	jmp  AsmInterruptDispatch
KiInterruptStubE1 ENDP

KiInterruptStubE2 PROC
	push 0E2h
	jmp  AsmInterruptDispatch
KiInterruptStubE2 ENDP

KiInterruptStubE3 PROC
	push 0E3h
	jmp  AsmInterruptDispatch
KiInterruptStubE3 ENDP

KiInterruptStubE4 PROC
	push 0E4h
	jmp  AsmInterruptDispatch
KiInterruptStubE4 ENDP

KiInterruptStubE5 PROC
	push 0E5h
	jmp  AsmInterruptDispatch
KiInterruptStubE5 ENDP

KiInterruptStubE6 PROC
	push 0E6h
	jmp  AsmInterruptDispatch
KiInterruptStubE6 ENDP

KiInterruptStubE7 PROC
	push 0E7h
	jmp  AsmInterruptDispatch
KiInterruptStubE7 ENDP

KiInterruptStubE8 PROC
	push 0E8h
	jmp  AsmInterruptDispatch
KiInterruptStubE8 ENDP

KiInterruptStubE9 PROC
	push 0E9h
	jmp  AsmInterruptDispatch
KiInterruptStubE9 ENDP

KiInterruptStubEA PROC
	push 0EAh
	jmp  AsmInterruptDispatch
KiInterruptStubEA ENDP

KiInterruptStubEB PROC
	push 0EBh
	jmp  AsmInterruptDispatch
KiInterruptStubEB ENDP

KiInterruptStubEC PROC
	push 0ECh
	jmp  AsmInterruptDispatch
KiInterruptStubEC ENDP

KiInterruptStubED PROC
	push 0EDh
	jmp  AsmInterruptDispatch
KiInterruptStubED ENDP

KiInterruptStubEE PROC
	push 0EEh
	jmp  AsmInterruptDispatch
KiInterruptStubEE ENDP

KiInterruptStubEF PROC
	push 0EFh
	jmp  AsmInterruptDispatch
KiInterruptStubEF ENDP

KiInterruptStubF0 PROC
	push 0F0h
	jmp  AsmInterruptDispatch
KiInterruptStubF0 ENDP

KiInterruptStubF1 PROC
	push 0F1h
	jmp  AsmInterruptDispatch
KiInterruptStubF1 ENDP

KiInterruptStubF2 PROC
	push 0F2h
	jmp  AsmInterruptDispatch
KiInterruptStubF2 ENDP

KiInterruptStubF3 PROC
	push 0F3h
	jmp  AsmInterruptDispatch
KiInterruptStubF3 ENDP

KiInterruptStubF4 PROC
	push 0F4h
	jmp  AsmInterruptDispatch
KiInterruptStubF4 ENDP

KiInterruptStubF5 PROC
	push 0F5h
	jmp  AsmInterruptDispatch
KiInterruptStubF5 ENDP

KiInterruptStubF6 PROC
	push 0F6h
	jmp  AsmInterruptDispatch
KiInterruptStubF6 ENDP

KiInterruptStubF7 PROC
	push 0F7h
	jmp  AsmInterruptDispatch
KiInterruptStubF7 ENDP

KiInterruptStubF8 PROC
	push 0F8h
	jmp  AsmInterruptDispatch
KiInterruptStubF8 ENDP

KiInterruptStubF9 PROC
	push 0F9h
	jmp  AsmInterruptDispatch
KiInterruptStubF9 ENDP

KiInterruptStubFA PROC
	push 0FAh
	jmp  AsmInterruptDispatch
KiInterruptStubFA ENDP

KiInterruptStubFB PROC
	push 0FBh
	jmp  AsmInterruptDispatch
KiInterruptStubFB ENDP

KiInterruptStubFC PROC
	push 0FCh
	jmp  AsmInterruptDispatch
KiInterruptStubFC ENDP

KiInterruptStubFD PROC
	push 0FDh
	jmp  AsmInterruptDispatch
KiInterruptStubFD ENDP

KiInterruptStubFE PROC
	push 0FEh
	jmp  AsmInterruptDispatch
KiInterruptStubFE ENDP

KiInterruptStubFF PROC
	push 0FFh
	jmp  AsmInterruptDispatch
KiInterruptStubFF ENDP

END
