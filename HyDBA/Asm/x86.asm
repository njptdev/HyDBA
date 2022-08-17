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
EXTERN VmmVmExitHandler@4 : PROC
EXTERN VmmVmxFailureHandler@4 : PROC
EXTERN UtilDumpGpRegisters@8 : PROC

EXTERN IntKiTrapCheckStubHandler@4 : PROC

EXTERN IntEptVoilationHandler@8 : PROC
EXTERN IntEptCommonHandler@8 : PROC

EXTERN IntAnalysisThreadPageFaultHandler@8 : PROC
EXTERN IntTargetThreadPageFaultHandler@8 : PROC

EXTERN IntKiFastCallEntryHandler@4 : PROC
EXTERN g_TrampoKiFastCallEntry: DWORD
EXTERN IntKiServiceExitHandler@4 : PROC
EXTERN g_TrampoKiServiceExit: DWORD
EXTERN IntKei386HelperExitHandler@4 : PROC
EXTERN g_TrampoKei386HelperExit: DWORD
EXTERN IntKiCallUserModeExitHandler@4 : PROC
EXTERN g_TrampoKiCallUserModeExit: DWORD

EXTERN g_pKiTrap0E: DWORD
EXTERN g_target_pid: DWORD
EXTERN processor_list: DWORD
EXTERN UtilVmCall@8 : PROC
EXTERN g_local_apic: DWORD

EXTERN IntSwapOutHandler@8 : PROC

EXTERN g_target_eprocess: DWORD
EXTERN g_SwapContextBack: DWORD
EXTERN g_SwapContextOldBack: DWORD
EXTERN g_MmCreateTebBack: DWORD
EXTERN g_checkCodePage: DWORD

EXTERN MySwapInHandler1@8 : PROC
EXTERN MySwapInHandler2@12 : PROC
EXTERN MySwapOutHandler@16 : PROC

EXTERN MyMmCreateTebHandler@4 : PROC
EXTERN AnalysisCheckBuffer@16 : PROC

EXTERN MyDebugPrint1@4 : PROC

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; constants
;
.CONST

VMX_OK                      EQU     0
VMX_ERROR_WITH_STATUS       EQU     1
VMX_ERROR_WITHOUT_STATUS    EQU     2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; macros
;

; Dumps all general purpose registers and a flag register.
ASM_DUMP_REGISTERS MACRO
    pushfd
    pushad                      ; -4 * 8
    mov ecx, esp                ; all_regs
    mov edx, esp
    add edx, 4*9                ; stack_pointer

    push ecx
    push edx
    call UtilDumpGpRegisters@8  ; UtilDumpGpRegisters(all_regs, stack_pointer);

    popad
    popfd
ENDM


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; implementations
;
.CODE

; bool __stdcall AsmInitializeVm(
;     _In_ void (*vm_initialization_routine)(_In_ ULONG_PTR, _In_ ULONG_PTR,
;                                            _In_opt_ void *),
;     _In_opt_ void *context);
AsmInitializeVm PROC vm_initialization_routine, context
    pushfd
    pushad                  ; -4 * 8

    mov ecx, esp            ; esp

    ; vm_initialization_routine(rsp, asmResumeVm, context)
    push context
    push asmResumeVm
    push ecx
    call vm_initialization_routine

    popad
    popfd
    xor eax, eax            ; return false
    ret

    ; This is where the virtualized guest start to execute after successful
    ; vmlaunch.
asmResumeVm:
    nop                     ; keep this nop for ease of debugging
    popad
    popfd
    ASM_DUMP_REGISTERS
    xor eax, eax
    inc eax                 ; return true
    ret
AsmInitializeVm ENDP

; void __stdcall AsmVmmEntryPoint();
AsmVmmEntryPoint PROC
    ; No need to save the flag registers since it is restored from the VMCS at
    ; the time of vmresume.
    pushad                  ; -4 * 8
    mov eax, esp

    ; save volatile XMM registers
    sub esp, 68h            ; +8 for alignment
    mov ecx, cr0
    mov edx, ecx            ; save original CR0
    and cl, 0f1h            ; clear MP, EM, TS bits for floating point access
    mov cr0, ecx            ; update CR0
    movaps xmmword ptr [esp +  0h], xmm0
    movaps xmmword ptr [esp + 10h], xmm1
    movaps xmmword ptr [esp + 20h], xmm2
    movaps xmmword ptr [esp + 30h], xmm3
    movaps xmmword ptr [esp + 40h], xmm4
    movaps xmmword ptr [esp + 50h], xmm5
    mov cr0, edx            ; restore the original CR0

    push eax
    call VmmVmExitHandler@4 ; bool vm_continue = VmmVmExitHandler(guest_context);

    ; restore XMM registers
    mov ecx, cr0
    mov edx, ecx            ; save original CR0
    and cl, 0f1h            ; clear MP, EM, TS bits for floating point access
    mov cr0, ecx            ; update CR0
    movaps xmm0, xmmword ptr [esp +  0h]
    movaps xmm1, xmmword ptr [esp + 10h]
    movaps xmm2, xmmword ptr [esp + 20h]
    movaps xmm3, xmmword ptr [esp + 30h]
    movaps xmm4, xmmword ptr [esp + 40h]
    movaps xmm5, xmmword ptr [esp + 50h]
    mov cr0, edx            ; restore the original CR0
    add esp, 68h            ; +8 for alignment

    test al, al
    jz exitVm               ; if (!vm_continue) jmp exitVm

    popad
    vmresume
    jmp vmxError

exitVm:
    ; Executes vmxoff and ends virtualization
    ;   eax = Guest's eflags
    ;   edx = Guest's esp
    ;   ecx = Guest's eip for the next instruction
    popad
    vmxoff
    jz vmxError             ; if (ZF) jmp
    jc vmxError             ; if (CF) jmp
    push eax
    popfd                   ; eflags <= GurstFlags
    mov esp, edx            ; esp <= GuestRsp
    push ecx
    ret                     ; jmp AddressToReturn

vmxError:
    ; Diagnose a critical error
    pushfd
    pushad                      ; -4 * 8
    mov ecx, esp                ; all_regs
    push ecx
    call VmmVmxFailureHandler@4 ; VmmVmxFailureHandler(all_regs);
    int 3
AsmVmmEntryPoint ENDP

; unsigned char __stdcall AsmVmxCall(_In_ ULONG_PTR hypercall_number,
;                                    _In_opt_ void *context);
AsmVmxCall PROC hypercall_number, context
    mov ecx, hypercall_number
    mov edx, context
    vmcall                  ; vmcall(hypercall_number, context)
    jz errorWithCode        ; if (ZF) jmp
    jc errorWithoutCode     ; if (CF) jmp
    xor eax, eax            ; return VMX_OK
    ret

errorWithoutCode:
    mov eax, VMX_ERROR_WITHOUT_STATUS
    ret

errorWithCode:
    mov eax, VMX_ERROR_WITH_STATUS
    ret
AsmVmxCall ENDP

; void __stdcall AsmWriteGDT(_In_ const GDTR *gdtr);
AsmWriteGDT PROC gdtr
    mov ecx, gdtr
    lgdt fword ptr [ecx]
    ret
AsmWriteGDT ENDP

; void __stdcall AsmReadGDT(_Out_ GDTR *gdtr);
AsmReadGDT PROC gdtr
    mov ecx, gdtr
    sgdt [ecx]
    ret
AsmReadGDT ENDP

; void __stdcall AsmWriteLDTR(_In_ USHORT local_segmeng_selector);
AsmWriteLDTR PROC local_segmeng_selector
    mov ecx, local_segmeng_selector
    lldt cx
    ret
AsmWriteLDTR ENDP

; USHORT __stdcall AsmReadLDTR();
AsmReadLDTR PROC
    sldt ax
    ret
AsmReadLDTR ENDP

; void __stdcall AsmWriteTR(_In_ USHORT task_register);
AsmWriteTR PROC task_register
    mov ecx, task_register
    ltr cx
    ret
AsmWriteTR ENDP

; USHORT __stdcall AsmReadTR();
AsmReadTR PROC
    str ax
    ret
AsmReadTR ENDP

; void __stdcall AsmWriteES(_In_ USHORT segment_selector);
AsmWriteES PROC segment_selector
    mov ecx, segment_selector
    mov es, cx
    ret
AsmWriteES ENDP

; USHORT __stdcall AsmReadES();
AsmReadES PROC
    mov ax, es
    ret
AsmReadES ENDP

; void __stdcall AsmWriteCS(_In_ USHORT segment_selector);
AsmWriteCS PROC segment_selector
    mov ecx, segment_selector
    mov cs, cx
    ret
AsmWriteCS ENDP

; USHORT __stdcall AsmReadCS();
AsmReadCS PROC
    mov ax, cs
    ret
AsmReadCS ENDP

; void __stdcall AsmWriteSS(_In_ USHORT segment_selector);
AsmWriteSS PROC segment_selector
    mov ecx, segment_selector
    mov ss, cx
    ret
AsmWriteSS ENDP

; USHORT __stdcall AsmReadSS();
AsmReadSS PROC
    mov ax, ss
    ret
AsmReadSS ENDP

; void __stdcall AsmWriteDS(_In_ USHORT segment_selector);
AsmWriteDS PROC segment_selector
    mov ecx, segment_selector
    mov ds, cx
    ret
AsmWriteDS ENDP

; USHORT __stdcall AsmReadDS();
AsmReadDS PROC
    mov ax, ds
    ret
AsmReadDS ENDP

; void __stdcall AsmWriteFS(_In_ USHORT segment_selector);
AsmWriteFS PROC segment_selector
    mov ecx, segment_selector
    mov fs, cx
    ret
AsmWriteFS ENDP

; USHORT __stdcall AsmReadFS();
AsmReadFS PROC
    mov ax, fs
    ret
AsmReadFS ENDP

; void __stdcall AsmWriteGS(_In_ USHORT segment_selector);
AsmWriteGS PROC segment_selector
    mov ecx, segment_selector
    mov gs, cx
    ret
AsmWriteGS ENDP

; USHORT __stdcall AsmReadGS();
AsmReadGS PROC
    mov ax, gs
    ret
AsmReadGS ENDP

; ULONG_PTR __stdcall AsmLoadAccessRightsByte(
;    _In_ ULONG_PTR segment_selector);
AsmLoadAccessRightsByte PROC segment_selector
    mov ecx, segment_selector
    lar eax, ecx
    ret
AsmLoadAccessRightsByte ENDP

; void __stdcall AsmInvalidateInternalCaches();
AsmInvalidateInternalCaches PROC
    invd
    ret
AsmInvalidateInternalCaches ENDP

; ULONG __stdcall AsmReadCR2();
AsmReadCR2 PROC
    mov eax, cr2
    ret
AsmReadCR2 ENDP

; void __stdcall AsmWriteCR2(_In_ ULONG_PTR cr2_value);
AsmWriteCR2 PROC cr2_value
    mov ecx, cr2_value
    mov cr2, ecx
    ret
AsmWriteCR2 ENDP

; unsigned char __stdcall AsmInvept(
;     _In_ InvEptType invept_type,
;     _In_ const InvEptDescriptor *invept_descriptor);
AsmInvept PROC invept_type, invept_descriptor
    mov ecx, invept_type
    mov edx, invept_descriptor
    ; invept  ecx, oword ptr [edx]
    db  66h, 0fh, 38h, 80h, 0ah
    jz errorWithCode        ; if (ZF) jmp
    jc errorWithoutCode     ; if (CF) jmp
    xor eax, eax            ; return VMX_OK
    ret

errorWithoutCode:
    mov eax, VMX_ERROR_WITHOUT_STATUS
    ret

errorWithCode:
    mov eax, VMX_ERROR_WITH_STATUS
    ret
AsmInvept ENDP

; unsigned char __stdcall AsmInvvpid(
;     _In_ InvVpidType invvpid_type,
;     _In_ const InvVpidDescriptor *invvpid_descriptor);
AsmInvvpid PROC invvpid_type, invvpid_descriptor
    mov ecx, invvpid_type
    mov edx, invvpid_descriptor
    ; invvpid  ecx, oword ptr [rdx]
    db  66h, 0fh, 38h, 81h, 0ah
    jz errorWithCode        ; if (ZF) jmp
    jc errorWithoutCode     ; if (CF) jmp
    xor eax, eax            ; return VMX_OK
    ret

errorWithoutCode:
    mov eax, VMX_ERROR_WITHOUT_STATUS
    ret

errorWithCode:
    mov eax, VMX_ERROR_WITH_STATUS
    ret
AsmInvvpid ENDP


; ULONG __stdcall AsmReadEPROCESS();
AsmReadEPROCESS PROC
	assume fs:nothing
    push ebx
	mov ebx, dword ptr fs:[124h]
	mov eax, [ebx+150h]
	pop ebx
    ret
AsmReadEPROCESS ENDP

; ULONG __stdcall AsmReadProcessId();
AsmReadProcessId PROC
	assume fs:nothing
    push ebx
	mov ebx, dword ptr fs:[124h]
	mov eax, [ebx+150h]
	mov eax, [eax+0b4h]
	pop ebx
    ret
AsmReadProcessId ENDP

; ULONG __stdcall GetCpuId();
GetCpuId PROC
	assume fs:nothing
	xor eax,eax
	mov al, byte ptr fs:[51h]
    ret
GetCpuId ENDP

DisableInterrupt PROC
    pushfd
	pop  eax
	and  eax, 200h
	shr  eax, 9
	cli
    ret
DisableInterrupt ENDP

; ULONG __stdcall CloseInterrupt();
CloseInterrupt PROC
    cli
    ret
CloseInterrupt ENDP

; ULONG __stdcall StartInterrupt();
StartInterrupt PROC
    sti
    ret
StartInterrupt ENDP

KiTrapPageFault4 PROC
	test    dword ptr [esp+12], 40000h  ; if bit 18 is set, it must come from simulated execution
	je      normalCode
	cmp     dword ptr [esp+20], 0badfbadfh ; magic number of hard mode
	jne     simpleMode

hardMode:
	push    eax
	mov     eax, hardModeReturn      ;hardModeReturn
	mov     [esp+8], eax             ;overwrite original
	push    ecx                 ;resume ept
	mov     ecx,30h
	mov     fs,cx
	mov		eax, 0                  
	mov		ecx, 1
	db		0fh, 01h, 0d4h
	pop		ecx
	pop		eax
	jmp     normalCode

hardModeReturn:
    push    eax
	push    ecx
	mov     ecx, dword ptr [esp+8]
	mov     [ecx], edi
	mov     [ecx+4],esi
	mov     [ecx+8],ebp
	mov     [ecx+10h],ebx
	mov     [ecx+14h],edx
	mov     [ecx+1Ch],eax
	pushfd
	pop     eax
	and     eax, 0FFFBFFFFh ; clear bit 18
	push    eax
	pop     dword ptr [ecx+20h]
	mov		eax, 0            ; clear ept      
	mov		ecx, 0
	db		0fh, 01h, 0d4h
	mov     eax, dword ptr [esp+8]
	pop     dword ptr [eax+18h] ;ecx
	pop     eax
	add     esp, 8
	pop     eax
	pop     ecx
	pop     edx
	pop     ebx
	pop     ebp
	pop     esi
	pop     edi
	popfd
	pop     fs
	ret

simpleMode:      
	push    eax                   
	mov     eax, [esp+24]  ;after call execution
	mov     [esp+8], eax   ;overwrite original
	mov     eax, [esp+28]
	mov     [esp+32], eax  ;back                   
	push    ecx            ;resume ept
	push    fs
	mov     ecx,30h
	mov     fs,cx
	mov		eax, 0                  
	mov		ecx, 1
	db		0fh, 01h, 0d4h
	pop     fs
	pop		ecx
	pop		eax

normalCode:
    test    dword ptr [esp+12], 200h
	jne     HasIF
	push    ecx                        ; set IF = 1
	mov     ecx,dword ptr [esp+16]
	or      ecx,200h
	mov     dword ptr [esp+16],ecx
	pop     ecx

HasIF:
	jmp dword ptr [g_pKiTrap0E]

KiTrapPageFault4 ENDP

AsmSaveProcessorData PROC arg1, arg2, arg3
    assume fs:nothing
	mov eax, arg1
	mov dword ptr fs:[4f4h], eax
	mov eax, arg2
	mov dword ptr fs:[4f8h], eax
	mov eax, arg3
	mov dword ptr fs:[4fch], eax
	mov dword ptr fs:[500h], 0
	mov dword ptr fs:[504h], 0
	ret
AsmSaveProcessorData ENDP

AsmStopSMEP PROC
    mov eax, cr4
	and eax, 0FFEFFFFFh
	mov cr4, eax
	ret
AsmStopSMEP ENDP


AsmSwitchToShadowCode PROC log_buf, gpr_buf, start_addr, thread_ctx
	assume fs:nothing
	pushfd
	push eax
	push ecx
	push edx
	push ebx
	push ebp
	push esi
	push edi
	mov   eax, thread_ctx
	push  eax

	mov   ebx, log_buf
	sub   ebx, 4
	mov   edx, gpr_buf
	;add   edx, 110h       ;origin fs:[110h]
	mov   eax, start_addr
	call  eax

RETURN_ADDR:
	;mov  word ptr [edx - 90h], 101h ;finish shadow 

    add esp, 4
	pop edi
	pop esi
	pop ebp
	pop ebx
	pop edx
	pop ecx
	pop eax
	popfd
	ret
AsmSwitchToShadowCode ENDP

KiFastCallEntry PROC
    pushfd                            ; saveeflags
	push ebp              
	push ebx 
	push esi
	push edi
	push eax
	push ecx
	push edx
	push fs

	push esp                         ; KTRAP_FRAME3
	call IntKiFastCallEntryHandler@4

	pop fs      
	pop edx
	pop ecx
	pop eax
	pop edi
	pop esi
	pop ebx
	pop ebp
	popfd
	jmp dword ptr [g_TrampoKiFastCallEntry]
KiFastCallEntry ENDP

KiServiceExit PROC
    push ebp
	push eax
	push ecx
	push edx
	pushfd

	push ebp                         ;ktrap_frame
    call IntKiServiceExitHandler@4

	popfd
	pop  edx
	pop  ecx
	pop  eax
	pop  ebp
	jmp  dword ptr [g_TrampoKiServiceExit]
KiServiceExit ENDP

Kei386HelperExit PROC
	cmp  word ptr [ebp+6Ch], 8
	jz   KERNEL_CODE

	; User
	push ebp              ; ebp -> _KTRAP_FRAME
    call IntKei386HelperExitHandler@4

	jmp  dword ptr [g_TrampoKei386HelperExit]

	; kernel
KERNEL_CODE:
	mov   ecx, dword ptr fs:[124h]  ; ETHREAD
	cmp   word ptr [ecx + 440h], 0BBAAh
	jnz   SKIP_RET  ; 

	cmp   dword ptr [ebp + 68h], 80000000h
	jae   SKIP_RET  ; 

	; 
	cmp   byte ptr [ecx + 443h], 0
	jz    CHECK_ERROR

	mov   byte ptr [ecx + 443h], 0  ; 
	;  -> 2
	mov   ecx, dword ptr fs:[1Ch]   ; KPCR
	cmp   dword ptr [ecx + 520h], 2  
	jz    SKIP_RET
	mov   dword ptr [ecx + 520h], 2
	mov   eax, cr3        ; TLB global TLB£¬bit7 PGE
	mov   ecx, cr4        
	mov   edx, ecx
	and   ecx, 0FFFFFF7Fh 
	mov   cr4, ecx
	mov   cr3, eax
	mov   cr4, edx
	mov   eax, 0             
	mov   ecx, 2
	db    0fh, 01h, 0d4h  ;
SKIP_RET:

	jmp  dword ptr [g_TrampoKei386HelperExit]

CHECK_ERROR:
    int  3

Kei386HelperExit ENDP


KiCallUserModeExit PROC
	push ebp
	push edx
	push ecx
	push eax
	pushfd

	push eax
	call IntKiCallUserModeExitHandler@4

	popfd
	pop  eax
	pop  ecx
	pop  edx
	pop  ebp
	jmp  dword ptr [g_TrampoKiCallUserModeExit]
KiCallUserModeExit ENDP

; ULONG __stdcall AsmGetApicId();
AsmGetApicId PROC
    push ebx
    mov eax, 1
	cpuid
	mov eax, ebx
	shr eax, 24
	and eax, 0FFh
	pop ebx
    ret
AsmGetApicId ENDP

KiTrapEptViolation PROC
    assume fs:nothing
	push eax
	push ecx
	push edx
	push fs

	mov  eax,30h
	mov  fs,ax
	mov  eax, fs:[4f8h]         ; ve->except_mask = 0
	mov  dword ptr [eax + 4], 0 
	test dword ptr [eax + 8], 4 ; ve->exit
	jz   NOT_EXECUTE_VIOLATION  
	
	push ebx                    ; 
	                 
	push esp                    ; KEPT_FAULT_FRAME
	mov  eax, fs:[4f4h]              
	push eax                    ; ProcessorData
	cld
    call IntEptVoilationHandler@8
	cmp  eax, 0
	jz  NormalExit
	cmp  eax, 1
	jz  CheckStub

    mov  byte ptr fs:[504h], 1        ; TF
	mov  eax, dword ptr [esp + 28]    
	xor  ecx, ecx
	test eax, 200h
	jz   DebugExit_NoIF
	and  eax, 0FFFFFDFFh
	inc  ecx
DebugExit_NoIF:
    mov  byte ptr fs:[505h], cl       
	or   eax, 100h
	mov  dword ptr [esp + 28], eax    

NormalExit:
	pop ebx

	pop fs      
	pop edx
	pop ecx
	pop eax
	iretd

CheckStub:
	push ebp
	push ebx
	push esi
	push edi

	push esp                    ; KEPT_JUMP_FRAME
	call IntKiTrapCheckStubHandler@4

	pop edi
	pop esi
	pop ebx
	pop ebp

	pop fs      
	pop edx
	pop ecx
	pop eax
	iretd

NOT_EXECUTE_VIOLATION:
    push ebp
	push ebx
	push esi
	push edi

	push esp                    ; KEPT_JUMP_FRAME
	mov  eax, fs:[4f4h]              
	push eax                    ; ProcessorData
	call IntEptCommonHandler@8

	pop edi
	pop esi
	pop ebx
	pop ebp

	pop fs      
	pop edx
	pop ecx
	pop eax
	iretd  

KiTrapEptViolation ENDP

KiTrapDebugException PROC
    push ecx
	push eax
	push fs                  ;r3/r0
	mov  eax, 30h
	mov  fs, ax
	movzx  eax, byte ptr fs:[504h]
	test al, 1
	jz  DefaultTrap

	mov    byte ptr fs:[504h], 0   ; DB
	movzx  eax, byte ptr fs:[505h] ; IF
	mov  ecx, dword ptr [esp + 20]
	test al, 1
	jz   NoIF
	or   ecx, 200h         ;IF
NoIF:
    and   ecx, 0FFFFFEFFh  
	mov   dword ptr [esp + 20], ecx
	mov   eax, 0
	mov   ecx, 1
	db    0fh, 01h, 0d4h   
	pop   fs
	pop   eax
	pop   ecx
	iretd

DefaultTrap:
    mov   eax, fs:[4f4h]
	mov   eax, [eax + 1Ch]   ;processor_data->kitrap01
	push  eax
	mov   eax, 0
	mov   ecx, 1
	db    0fh, 01h, 0d4h     
	add   esp, 4
	pop   fs
	pop   eax
	pop   ecx
	jmp   dword ptr [esp-16]

KiTrapDebugException ENDP

KiTrapPageFault PROC
	cmp    word ptr [esp], 15h 
	jz     SPECIAL_CASE            ; error_code = 15h

    push    fs
    push    eax
	mov     ax,  30h              
	mov     fs,  ax                 ; fs=30h
	mov     eax, fs:[124h]          ; ETHREAD 
	mov     eax, [eax + 150h]
	cmp     eax,  g_target_eprocess 
	jnz     CHECK_NEXT             

TARGET_THREAD:    
	mov     eax, dword ptr [esp+20]
    test    eax, 200h                ; decode
	jne     HAS_IF                                 
	or      eax, 200h
	mov     dword ptr [esp+20], eax  
HAS_IF:
    cmp     word ptr [esp + 4], 30h
	jz      DEFAULT_PROC             

	mov     eax,  cr2
	cmp     eax,  80000000h        
	jb      DEFAULT_PROC             
	
	push    ecx     
	push    edx
	push    esp    
	push    eax     ; ExceptionAddress
	cld
    call    IntTargetThreadPageFaultHandler@8
	pop     edx
	pop     ecx
	pop     eax
	pop     fs
	add     esp, 4  
	iretd
	
SPECIAL_CASE:
	push   fs
	push   eax
	mov    ax,  30h                   ; fs=30h
	mov    fs,  ax
	mov    eax,  fs:[124h]            ; ETHREAD     
	mov    eax,  [eax + 150h]      
	cmp    eax,  g_target_eprocess   
	jnz    SP_END_EXIT                
	mov    eax,  cr2
	invlpg [eax]
SP_END_EXIT:
    pop    eax
	pop    fs
	add    esp, 4
	iretd

CHECK_NEXT:	
	mov     eax,  fs:[124h]
	cmp     word  ptr [eax + 440h], 0BBAAh 
	jnz     DEFAULT_PROC  

ANALYSIS_THREAD:    
	cmp     byte ptr [eax + 443h], 0
	jnz     CHECK_ERROR2
	;jnz     DEFAULT_PROC  

	
	push    ecx
	push    edx
	push    esp     ; KBITMAP_FAULT_FRAME
	mov     eax, cr2
	push    eax     ; ExceptionAddress

	;  -> 1
	mov    ecx, dword ptr fs:[1Ch]  ; KPCR       
	cmp    dword ptr [ecx + 520h], 1
	;jz     CHECK_ERROR1  
	jz     NO_SWITCH_1
	mov    dword ptr [ecx + 520h], 1   
	mov    eax, cr3       
	mov    ecx, cr4        
	mov    edx, ecx
	and    ecx, 0FFFFFF7Fh 
	mov    cr4, ecx
	mov    cr3, eax
	mov    cr4, edx
	mov    eax, 0             
	mov    ecx, 1
	db     0fh, 01h, 0d4h 
NO_SWITCH_1:
    mov    ecx, dword ptr fs:[124h]
	mov    byte ptr [ecx + 443h], 0DDh   
	
	call   IntAnalysisThreadPageFaultHandler@8
	cli
	cmp    eax, 0
	jnz    EXT_DEFAULT_PROC ; 

	; -> 2
	mov    ecx, dword ptr fs:[1Ch]   ; KPCR
	cmp    dword ptr [ecx + 520h], 2   
	jz     NO_SWITCH_2
	mov    dword ptr [ecx + 520h], 2
	mov    eax, cr3        
	mov    ecx, cr4        
	mov    edx, ecx
	and    ecx, 0FFFFFF7Fh 
	mov    cr4, ecx
	mov    cr3, eax
	mov    cr4, edx
	mov    eax, 0             
	mov    ecx, 2
	db     0fh, 01h, 0d4h  
NO_SWITCH_2:
    mov    ecx, dword ptr fs:[124h]
	mov    byte ptr [ecx + 443h], 0h   

	pop     edx
	pop     ecx
	pop     eax
	pop     fs
	add     esp, 4   
	iretd    

EXT_DEFAULT_PROC:
    pop    edx
	pop    ecx

DEFAULT_PROC:
	pop    eax
	pop    fs
    jmp    dword ptr [g_pKiTrap0E]

CHECK_ERROR1:
    int  3
CHECK_ERROR2:
    int  3

KiTrapPageFault ENDP

AsmInvept2 PROC invept_type, invept_descriptor
    mov ecx, invept_type
    mov edx, invept_descriptor
    invept  ecx, oword ptr [edx]
	jz errorWithCode        ; if (ZF) jmp
    jc errorWithoutCode     ; if (CF) jmp
    xor eax, eax            ; return VMX_OK
    ret

errorWithoutCode:
    mov eax, VMX_ERROR_WITHOUT_STATUS
    ret

errorWithCode:
    mov eax, VMX_ERROR_WITH_STATUS
    ret
AsmInvept2 ENDP

; void __stdcall AsmVmFunc();
AsmVmFunc PROC func, eptp
    push eax
	push ecx
    mov eax, func
	mov ecx, eptp
	db  0fh, 01h, 0d4h
	pop ecx
	pop eax
    ret
AsmVmFunc ENDP

; void __stdcall AsmGetRegister();
AsmGetRegister PROC
	pushfd
	pop eax
    ret
AsmGetRegister ENDP


MySwapContextOld PROC
    mov   eax, [edi + 150h]  ; _ETHREAD -> Process
	cmp   eax, g_target_eprocess 
	jz    OUT_TARGET_THREAD 
	cmp   byte ptr [edi + 440h], 0AAh 
	jnz   EXIT_RET           

	; £¬-> 1
	pushfd
	pop   edx
	and   edx, 200h
	shr   edx, 9
	cli                   

	mov   ecx, dword ptr fs:[1Ch]   ; KPCR
	cmp   dword ptr [ecx + 520h], 1
	jz    NO_SWITCH
	mov   dword ptr [ecx + 520h], 1
	mov   eax, cr3        
	mov   cr3, eax
	mov   eax, cr4
	mov   ecx, eax
	and   eax, 0FFFFFF7Fh 
	mov   cr4, eax
	mov   cr4, ecx
	mov   eax, 0             
    mov   ecx, 1
	db    0fh, 01h, 0d4h  
NO_SWITCH:
	cmp   edx,  1
	jnz   NO_IF
	sti

NO_IF:

	;pushfd              ; ef
	;push   esi          ; new
	;push   edi          ; old ETHREAD
	;push   ebx          ; KPCR
	;call   MySwapOutHandler@16

	mov   eax, [edi + 340h] 
	mov   edx, [edi + 344h]
	jmp   dword ptr [g_SwapContextOldBack]

OUT_TARGET_THREAD:
    mov   eax, [edi + 440h]
	cmp   eax, 0
	jz    EXIT_RET           

	push  eax                ; p_thread_ctx 
	mov   eax, [ebx + 4f4h]  ; ProcessorData          
	push  eax                    
	call  IntSwapOutHandler@8

EXIT_RET:	
	mov   eax, [edi + 340h] 
	mov   edx, [edi + 344h]
	jmp   dword ptr [g_SwapContextOldBack]

MySwapContextOld ENDP


MySwapContext PROC   
    mov   eax, [esi + 150h]  
	cmp   eax, g_target_eprocess 
	jz    IN_TARGET_THREAD 
	cmp   word ptr [esi + 440h], 0BBAAh
	jnz   EXIT_RET                      

	cmp   byte ptr [esi + 442h], 0CCh   
	jz    EXIT_RET                      

	cmp   byte ptr [esi + 443h], 0DDh   
	jz    EXIT_RET                      


	push  ecx  
	push  edx   
	pushfd               
	pop   edx
	and   edx, 200h
	shr   edx, 9 
	cli                
	
    ; -> 2
	mov   ecx, dword ptr fs:[1Ch]  ; KPCR
	cmp   dword ptr [ecx + 520h], 2
	jz    SWITCH_OK
	mov   dword ptr [ecx + 520h], 2
	mov   eax, cr3      
	mov   cr3, eax
	mov   eax, cr4
	mov   ecx, eax
	and   eax, 0FFFFFF7Fh 
	mov   cr4, eax
	mov   cr4, ecx
	mov   eax, 0
    mov   ecx, 2   
	db    0fh, 01h, 0d4h  

SWITCH_OK:
	cmp   edx,  1
	jnz   NO_IF
	sti
NO_IF:
	pop   edx
	pop   ecx

	;push  ecx  ; Save regs
	;push  edx
	;push  esi  ; ETHREAD
	;push  ebx  ; KPCR
	;call  MySwapInHandler1@8
	;pop   edx
	;pop   ecx

	mov   eax, [esi + 440h] ;
	mov   [ecx + 62h], ax
	jmp   dword ptr [g_SwapContextBack]

IN_TARGET_THREAD:
    mov   word ptr [ecx + 38h], 0ffffh 

	mov   eax, [esi + 440h]
	cmp   eax, 0
	jz    EXIT_RET 

	;push  ecx  ; Save regs
	;push  edx
	;push  eax  ; thread_ctx
	;push  esi  ; ETHREAD
	;push  ebx  ; KPCR
	;call  MySwapInHandler2@12
	;pop   edx
	;pop   ecx

EXIT_RET: 
	mov   eax, [esi + 440h] 
	mov   [ecx + 62h], ax
	jmp   dword ptr [g_SwapContextBack]
              
MySwapContext ENDP

MyMmCreateTeb PROC
	push  ebx
	call  MyMmCreateTebHandler@4
	cmp   eax, 0
	jnz   TARGET_PROCESS

	lea   eax, [ebp - 38h]
	push  eax
	push  1000h
	xor   edx, edx
    jmp   dword ptr [g_MmCreateTebBack]

TARGET_PROCESS:
    lea   eax, [ebp - 38h]
	push  eax
	push  2000h
	xor   edx, edx
    jmp   dword ptr [g_MmCreateTebBack]

MyMmCreateTeb ENDP

AsmAnalysisCheckStub PROC
   mov   ecx, dword ptr [esp + 8]
   push  edx                  ; save reg

   ; -> 1 
   cli
   push  eax
   push  ecx

   mov   ecx, dword ptr fs:[1Ch]   ; KPCR
   cmp   dword ptr [ecx + 520h], 1
   jz    NO_SWITCH_1
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

NO_SWITCH_1:
   mov   ecx, dword ptr fs:[124h]    ; ETHREAD
   mov   word ptr [ecx + 440h], 0AAh
   pop   ecx
   pop   eax
   sti

   push  ebp                  
   push  esp                  ; buffer limit reference
   push  ebx                  ; buffer current address
   push  eax                  ; buffer probe address
   push  ecx                  ; thread_ctx

   call  AnalysisCheckBuffer@16
   mov   ebx, eax
   mov   ebp, [esp]
   add   esp, 4

   ; -> 2
   cli
   push  eax
   push  ecx

   mov   ecx, dword ptr fs:[1Ch]   ; KPCR
   cmp   dword ptr [ecx + 520h], 2
   jz    NO_SWITCH_2
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
NO_SWITCH_2:
   mov   ecx, dword ptr fs:[124h]   ; ETHREAD
   mov   word ptr [ecx + 440h], 0BBAAh
   pop   ecx
   pop   eax
   sti

   pop   edx
   ret
   
AsmAnalysisCheckStub ENDP

AsmEnterIntoAnalysisCode PROC code_addr, buf_base, buf_limit, ctx_state, thread_ctx
	assume fs:nothing

	push ebx
	push esi
	push edi
	push ebp

	mov  eax, g_checkCodePage     
	mov  eax, dword ptr [eax + 4]

	cli
	mov   ecx, dword ptr fs:[1Ch] ; KPCR
	cmp   dword ptr [ecx + 520h], 2
	jz    NO_SWITCH_2
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
NO_SWITCH_2:
	sti

	;push  ebp
	;call  MyDebugPrint1@4

	mov  ecx, thread_ctx
	push ecx
	mov  ebx, buf_base
	mov  edx, ctx_state
	mov  ecx, code_addr
	mov  ebp, buf_limit        
	call ecx            ; ...| thread_ctx | RETURN_ADDR |
RETURN_ADDR:

	cli
    mov   ecx, dword ptr fs:[1Ch]   ; KPCR
    cmp   dword ptr [ecx + 520h], 1
    jz    NO_SWITCH_1
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
NO_SWITCH_1:
	sti
	mov  eax, g_checkCodePage  
	mov  eax, dword ptr [eax + 8]
	
	add  esp, 4
	pop  ebp
	pop  edi
	pop  esi
	pop  ebx
	ret

AsmEnterIntoAnalysisCode ENDP

AsmGetPcr PROC
    assume fs:nothing
    mov  eax, fs:[1Ch]
	ret
AsmGetPcr ENDP

AsmToMonitorFlush PROC
    assume fs:nothing
	cli

	mov   eax, 0             
	mov   ecx, 1
	db    0fh, 01h, 0d4h  

	mov   eax, fs:[1Ch]
	mov   dword ptr [eax + 520h], 1
	
	mov   eax, cr3       
	mov   cr3, eax
	mov   eax, cr4
	mov   ecx, eax
	and   eax, 0FFFFFF7Fh 
	mov   cr4, eax
	mov   cr4, ecx
	sti

	ret
AsmToMonitorFlush ENDP

AsmFlushGlobalTlb PROC
    assume fs:nothing
	
	mov   eax, cr4
	mov   ecx, eax
	and   eax, 0FFFFFF7Fh 
	mov   cr4, eax
	mov   cr4, ecx

	ret
AsmFlushGlobalTlb ENDP

AsmFlushAllTlb PROC
    assume fs:nothing
	
	mov   eax, cr3       
	mov   cr3, eax
	mov   eax, cr4
	mov   ecx, eax
	and   eax, 0FFFFFF7Fh
	mov   cr4, eax
	mov   cr4, ecx

	ret
AsmFlushAllTlb ENDP

PURGE ASM_DUMP_REGISTERS
END
