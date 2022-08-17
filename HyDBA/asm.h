// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Declares interfaces to assembly functions.

#ifndef HYPERPLATFORM_ASM_H_
#define HYPERPLATFORM_ASM_H_

#include "ia32_type.h"

extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

/// A wrapper for vm_initialization_routine.
/// @param vm_initialization_routine  A function pointer for entering VMX-mode
/// @param context  A context parameter for vm_initialization_routine
/// @return true if vm_initialization_routine was successfully executed
bool __stdcall AsmInitializeVm(
    _In_ void (*vm_initialization_routine)(_In_ ULONG_PTR, _In_ ULONG_PTR,
                                           _In_opt_ void *),
    _In_opt_ void *context);

/// An entry point of VMM where gets called whenever VM-exit occurred.
void __stdcall AsmVmmEntryPoint();

/// Executes VMCALL with the given hypercall number and a context.
/// @param hypercall_number   A hypercall number
/// @param context  A context parameter for VMCALL
/// @return Equivalent to #VmxStatus
unsigned char __stdcall AsmVmxCall(_In_ ULONG_PTR hypercall_number,
                                   _In_opt_ void *context);

/// Writes to GDT
/// @param gdtr   A value to write
void __stdcall AsmWriteGDT(_In_ const Gdtr *gdtr);

/// Reads SGDT
/// @param gdtr   A pointer to read GDTR
void __stdcall AsmReadGDT(_Out_ Gdtr *gdtr);

/// Reads SLDT
/// @return LDT
USHORT __stdcall AsmReadLDTR();

/// Writes to TR
/// @param task_register   A value to write
void __stdcall AsmWriteTR(_In_ USHORT task_register);

/// Reads STR
/// @return TR
USHORT __stdcall AsmReadTR();

/// Writes to ES
/// @param segment_selector   A value to write
void __stdcall AsmWriteES(_In_ USHORT segment_selector);

/// Reads ES
/// @return ES
USHORT __stdcall AsmReadES();

/// Writes to CS
/// @param segment_selector   A value to write
void __stdcall AsmWriteCS(_In_ USHORT segment_selector);

/// Reads CS
/// @return CS
USHORT __stdcall AsmReadCS();

/// Writes to SS
/// @param segment_selector   A value to write
void __stdcall AsmWriteSS(_In_ USHORT segment_selector);

/// Reads SS
/// @return SS
USHORT __stdcall AsmReadSS();

/// Writes to DS
/// @param segment_selector   A value to write
void __stdcall AsmWriteDS(_In_ USHORT segment_selector);

/// Reads DS
/// @return DS
USHORT __stdcall AsmReadDS();

/// Writes to FS
/// @param segment_selector   A value to write
void __stdcall AsmWriteFS(_In_ USHORT segment_selector);

/// Reads FS
/// @return FS
USHORT __stdcall AsmReadFS();

/// Writes to GS
/// @param segment_selector   A value to write
void __stdcall AsmWriteGS(_In_ USHORT segment_selector);

/// Reads GS
/// @return GS
USHORT __stdcall AsmReadGS();

/// Loads access rights byte
/// @param segment_selector   A value to get access rights byte
/// @return An access rights byte
ULONG_PTR __stdcall AsmLoadAccessRightsByte(_In_ ULONG_PTR segment_selector);

/// Invalidates internal caches
void __stdcall AsmInvalidateInternalCaches();

/// Writes to CR2
/// @param cr2_value  A value to write
void __stdcall AsmWriteCR2(_In_ ULONG_PTR cr2_value);

ULONG __stdcall AsmReadCR2();

/// Invalidates translations derived from EPT
/// @param invept_type  A type of invalidation
/// @param invept_descriptor  A reference to EPTP to invalidate
/// @return 0 on success, 1 w/ an error code or 2 w/o an error code on failure
unsigned char __stdcall AsmInvept(
    _In_ InvEptType invept_type,
    _In_ const InvEptDescriptor *invept_descriptor);

/// Invalidate translations based on VPID
/// @param invvpid_type  A type of invalidation
/// @param invvpid_descriptor  A description of translations to invalidate
/// @return 0 on success, 1 w/ an error code or 2 w/o an error code on failure
unsigned char __stdcall AsmInvvpid(
    _In_ InvVpidType invvpid_type,
    _In_ const InvVpidDescriptor *invvpid_descriptor);


void __stdcall AsmSwitchToShadowCode(PVOID log_buf, PVOID gpr_buf, PVOID start_addr, PVOID thread_ctx);

//ÐÞ¸Ä,x86
ULONG __stdcall AsmReadEPROCESS();
ULONG __stdcall AsmReadProcessId();
ULONG __stdcall GetCpuId();
ULONG __stdcall StartInterrupt();
ULONG __stdcall CloseInterrupt();
ULONG __stdcall DisableInterrupt();
VOID __stdcall AsmSaveProcessorData(PVOID arg1, PVOID arg2, PVOID arg3);

ULONG __stdcall AsmGetApicId();
ULONG __stdcall AsmGetPcr();
ULONG __stdcall AsmToMonitorFlush();
ULONG __stdcall AsmFlushGlobalTlb();
ULONG __stdcall AsmFlushAllTlb();

void  KiEmuIpiInterrupt();

VOID __stdcall AsmStopSMEP();

void  MySwapContextOld();
void  MySwapContext();
void  MyMmCreateTeb();

void  KiFastCallEntry();
void  KiServiceExit();
void  Kei386HelperExit();
void  KiCallUserModeExit();

void KiTrapEptViolationNull();
void KiTrapDebugExceptionNull();
void KiTrapPageFaultNull();

void  KiTrapEptViolation();
void  KiTrapEptViolation2();
void  KiTrapEptViolation3();
void  KiTrapEptViolation4();

void  KiTrapDebugException();
void  KiTrapDebugException2();
void  KiTrapDebugException3();
void  KiTrapDebugException4();

void  KiTrapPageFault();
void  KiTrapPageFault3();
void  KiTrapPageFault4();
//idt stub
void  KiInterruptStub30();
void  KiInterruptStub31();
void  KiInterruptStub32();
void  KiInterruptStub33();
void  KiInterruptStub34();
void  KiInterruptStub35();
void  KiInterruptStub36();
void  KiInterruptStub37();
void  KiInterruptStub38();
void  KiInterruptStub39();
void  KiInterruptStub3A();
void  KiInterruptStub3B();
void  KiInterruptStub3C();
void  KiInterruptStub3D();
void  KiInterruptStub3E();
void  KiInterruptStub3F();
void  KiInterruptStub40();
void  KiInterruptStub41();
void  KiInterruptStub42();
void  KiInterruptStub43();
void  KiInterruptStub44();
void  KiInterruptStub45();
void  KiInterruptStub46();
void  KiInterruptStub47();
void  KiInterruptStub48();
void  KiInterruptStub49();
void  KiInterruptStub4A();
void  KiInterruptStub4B();
void  KiInterruptStub4C();
void  KiInterruptStub4D();
void  KiInterruptStub4E();
void  KiInterruptStub4F();
void  KiInterruptStub50();
void  KiInterruptStub51();
void  KiInterruptStub52();
void  KiInterruptStub53();
void  KiInterruptStub54();
void  KiInterruptStub55();
void  KiInterruptStub56();
void  KiInterruptStub57();
void  KiInterruptStub58();
void  KiInterruptStub59();
void  KiInterruptStub5A();
void  KiInterruptStub5B();
void  KiInterruptStub5C();
void  KiInterruptStub5D();
void  KiInterruptStub5E();
void  KiInterruptStub5F();
void  KiInterruptStub60();
void  KiInterruptStub61();
void  KiInterruptStub62();
void  KiInterruptStub63();
void  KiInterruptStub64();
void  KiInterruptStub65();
void  KiInterruptStub66();
void  KiInterruptStub67();
void  KiInterruptStub68();
void  KiInterruptStub69();
void  KiInterruptStub6A();
void  KiInterruptStub6B();
void  KiInterruptStub6C();
void  KiInterruptStub6D();
void  KiInterruptStub6E();
void  KiInterruptStub6F();
void  KiInterruptStub70();
void  KiInterruptStub71();
void  KiInterruptStub72();
void  KiInterruptStub73();
void  KiInterruptStub74();
void  KiInterruptStub75();
void  KiInterruptStub76();
void  KiInterruptStub77();
void  KiInterruptStub78();
void  KiInterruptStub79();
void  KiInterruptStub7A();
void  KiInterruptStub7B();
void  KiInterruptStub7C();
void  KiInterruptStub7D();
void  KiInterruptStub7E();
void  KiInterruptStub7F();
void  KiInterruptStub80();
void  KiInterruptStub81();
void  KiInterruptStub82();
void  KiInterruptStub83();
void  KiInterruptStub84();
void  KiInterruptStub85();
void  KiInterruptStub86();
void  KiInterruptStub87();
void  KiInterruptStub88();
void  KiInterruptStub89();
void  KiInterruptStub8A();
void  KiInterruptStub8B();
void  KiInterruptStub8C();
void  KiInterruptStub8D();
void  KiInterruptStub8E();
void  KiInterruptStub8F();
void  KiInterruptStub90();
void  KiInterruptStub91();
void  KiInterruptStub92();
void  KiInterruptStub93();
void  KiInterruptStub94();
void  KiInterruptStub95();
void  KiInterruptStub96();
void  KiInterruptStub97();
void  KiInterruptStub98();
void  KiInterruptStub99();
void  KiInterruptStub9A();
void  KiInterruptStub9B();
void  KiInterruptStub9C();
void  KiInterruptStub9D();
void  KiInterruptStub9E();
void  KiInterruptStub9F();
void  KiInterruptStubA0();
void  KiInterruptStubA1();
void  KiInterruptStubA2();
void  KiInterruptStubA3();
void  KiInterruptStubA4();
void  KiInterruptStubA5();
void  KiInterruptStubA6();
void  KiInterruptStubA7();
void  KiInterruptStubA8();
void  KiInterruptStubA9();
void  KiInterruptStubAA();
void  KiInterruptStubAB();
void  KiInterruptStubAC();
void  KiInterruptStubAD();
void  KiInterruptStubAE();
void  KiInterruptStubAF();
void  KiInterruptStubB0();
void  KiInterruptStubB1();
void  KiInterruptStubB2();
void  KiInterruptStubB3();
void  KiInterruptStubB4();
void  KiInterruptStubB5();
void  KiInterruptStubB6();
void  KiInterruptStubB7();
void  KiInterruptStubB8();
void  KiInterruptStubB9();
void  KiInterruptStubBA();
void  KiInterruptStubBB();
void  KiInterruptStubBC();
void  KiInterruptStubBD();
void  KiInterruptStubBE();
void  KiInterruptStubBF();
void  KiInterruptStubC0();
void  KiInterruptStubC1();
void  KiInterruptStubC2();
void  KiInterruptStubC3();
void  KiInterruptStubC4();
void  KiInterruptStubC5();
void  KiInterruptStubC6();
void  KiInterruptStubC7();
void  KiInterruptStubC8();
void  KiInterruptStubC9();
void  KiInterruptStubCA();
void  KiInterruptStubCB();
void  KiInterruptStubCC();
void  KiInterruptStubCD();
void  KiInterruptStubCE();
void  KiInterruptStubCF();
void  KiInterruptStubD0();
void  KiInterruptStubD1();
void  KiInterruptStubD2();
void  KiInterruptStubD3();
void  KiInterruptStubD4();
void  KiInterruptStubD5();
void  KiInterruptStubD6();
void  KiInterruptStubD7();
void  KiInterruptStubD8();
void  KiInterruptStubD9();
void  KiInterruptStubDA();
void  KiInterruptStubDB();
void  KiInterruptStubDC();
void  KiInterruptStubDD();
void  KiInterruptStubDE();
void  KiInterruptStubDF();
void  KiInterruptStubE0();
void  KiInterruptStubE1();
void  KiInterruptStubE2();
void  KiInterruptStubE3();
void  KiInterruptStubE4();
void  KiInterruptStubE5();
void  KiInterruptStubE6();
void  KiInterruptStubE7();
void  KiInterruptStubE8();
void  KiInterruptStubE9();
void  KiInterruptStubEA();
void  KiInterruptStubEB();
void  KiInterruptStubEC();
void  KiInterruptStubED();
void  KiInterruptStubEE();
void  KiInterruptStubEF();
void  KiInterruptStubF0();
void  KiInterruptStubF1();
void  KiInterruptStubF2();
void  KiInterruptStubF3();
void  KiInterruptStubF4();
void  KiInterruptStubF5();
void  KiInterruptStubF6();
void  KiInterruptStubF7();
void  KiInterruptStubF8();
void  KiInterruptStubF9();
void  KiInterruptStubFA();
void  KiInterruptStubFB();
void  KiInterruptStubFC();
void  KiInterruptStubFD();
void  KiInterruptStubFE();
void  KiInterruptStubFF();

void __stdcall AsmAnalysisCheckStub();
void __stdcall AsmEnterIntoAnalysisCode(PVOID code_addr, PVOID buf_base, 
	PVOID buf_limit, PVOID ctx_state, PVOID thread_ctx);

unsigned char __stdcall AsmInvept2(
	_In_ InvEptType invept_type,
	_In_ const InvEptDescriptor *invept_descriptor);
void __stdcall AsmVmFunc(ULONG func, ULONG eptp);

ULONG __stdcall AsmGetRegister();
////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

/// Writes to GDT
/// @param gdtr   A value to write
inline void __sgdt(_Out_ void *gdtr) { AsmReadGDT(static_cast<Gdtr *>(gdtr)); }

/// Reads SGDT
/// @param gdtr   A pointer to read GDTR
inline void __lgdt(_In_ void *gdtr) { AsmWriteGDT(static_cast<Gdtr *>(gdtr)); }

// Followings are oringal implementations of Microsoft VMX intrinsic functions
// which are not avaiable on x86.
#if defined(_X86_)

/// Activates virtual machine extensions (VMX) operation in the processor
/// @param vms_support_physical_address   A pointer to a 64 bit physical address
///        that points to a virtual machine control structure(VMCS)
/// @return Equivalent to #VmxStatus
inline unsigned char __vmx_on(
    _In_ unsigned __int64 *vms_support_physical_address) {
  FlagRegister flags = {};
  PHYSICAL_ADDRESS physical_address = {};
  physical_address.QuadPart = *vms_support_physical_address;
  __asm {
    push physical_address.HighPart
    push physical_address.LowPart

    _emit  0xF3
    _emit  0x0F
    _emit  0xC7
    _emit  0x34
    _emit  0x24  // VMXON [ESP]

    pushfd
    pop flags.all

    add esp, 8
  }
  if (flags.fields.cf) {
    return 2;
  }
  if (flags.fields.zf) {
    return 1;
  }
  return 0;
}

/// Initializes the specified VMCS and sets its launch state to Clear
/// @param vmcs_physical_address  A pointer to a 64-bit memory location that
///        contains the physical address of the VMCS to clear
/// @return Equivalent to #VmxStatus
inline unsigned char __vmx_vmclear(
    _In_ unsigned __int64 *vmcs_physical_address) {
  FlagRegister flags = {};
  PHYSICAL_ADDRESS physical_address = {};
  physical_address.QuadPart = *vmcs_physical_address;
  __asm {
    push physical_address.HighPart
    push physical_address.LowPart

    _emit 0x66
    _emit 0x0F
    _emit 0xc7
    _emit 0x34
    _emit 0x24  // VMCLEAR [ESP]

    pushfd
    pop flags.all

    add esp, 8
  }
  if (flags.fields.cf) {
    return 2;
  }
  if (flags.fields.zf) {
    return 1;
  }
  return 0;
}

/// Places the calling application in VMX non-root operation state (VM enter)
/// @return Equivalent to #VmxStatus
inline unsigned char __vmx_vmlaunch() {
  FlagRegister flags = {};
  __asm {
    _emit 0x0f
    _emit 0x01
    _emit 0xc2  // VMLAUNCH

    pushfd
    pop flags.all
  }
  if (flags.fields.cf) {
    return 2;
  }
  if (flags.fields.zf) {
    return 1;
  }
  /* UNREACHABLE */
  return 0;
}

/// Loads the pointer to the current VMCS from the specified address
/// @param vmcs_physical_address  The address where the VMCS pointer is stored
/// @return Equivalent to #VmxStatus
inline unsigned char __vmx_vmptrld(
    _In_ unsigned __int64 *vmcs_physical_address) {
  FlagRegister flags = {};
  PHYSICAL_ADDRESS physical_address = {};
  physical_address.QuadPart = *vmcs_physical_address;
  __asm {
    push physical_address.HighPart
    push physical_address.LowPart

    _emit 0x0F
    _emit 0xC7
    _emit 0x34
    _emit 0x24  // VMPTRLD [ESP]

    pushfd
    pop flags.all

    add esp, 8
  }
  if (flags.fields.cf) {
    return 2;
  }
  if (flags.fields.zf) {
    return 1;
  }
  return 0;
}

/// Reads a specified field from the current VMCS
/// @param field  The VMCS field to read
/// @param field_value  A pointer to the location to store the value read from
///        the VMCS field specified by the Field parameter
/// @return Equivalent to #VmxStatus
inline unsigned char __vmx_vmread(_In_ size_t field,
                                  _Out_ size_t *field_value) {
  FlagRegister flags = {};
  __asm {
    pushad
    mov eax, field

    _emit 0x0F
    _emit 0x78
    _emit 0xC3  // VMREAD  EBX, EAX

    pushfd
    pop flags.all

    mov eax, field_value
    mov [eax], ebx
    popad
  }
  if (flags.fields.cf) {
    return 2;
  }
  if (flags.fields.zf) {
    return 1;
  }
  return 0;
}

/// Writes the specified value to the specified field in the current VMCS
/// @param field  The VMCS field to write
/// @param field_value  The value to write to the VMCS field
/// @return Equivalent to #VmxStatus
inline unsigned char __vmx_vmwrite(_In_ size_t field, _In_ size_t field_value) {
  FlagRegister flags = {};
  __asm {
    pushad
    push field_value
    mov eax, field

    _emit 0x0F
    _emit 0x79
    _emit 0x04
    _emit 0x24  // VMWRITE EAX, [ESP]

    pushfd
    pop flags.all

    add esp, 4
    popad
  }
  if (flags.fields.cf) {
    return 2;
  }
  if (flags.fields.zf) {
    return 1;
  }
  return 0;
}

#endif

}  // extern "C"

#endif  // HYPERPLATFORM_ASM_H_
