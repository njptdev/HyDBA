// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Declares interfaces to VMM functions.

#ifndef HYPERPLATFORM_VMM_H_
#define HYPERPLATFORM_VMM_H_

#include <fltKernel.h>
#include "udis86.h"
#include "int.h"
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
#define EPT_MAX_EPTP_LIST	512
		
#define EPTP_NORMAL			0
#define EPTP_MONITOR1		1
#define EPTP_ANALYSIS		2

/// Represents VMM related data shared across all processors
struct SharedProcessorData {
  volatile long reference_count;  //!< Number of processors sharing this data
  void* msr_bitmap;               //!< Bitmap to activate MSR I/O VM-exit
  void* io_bitmap_a;              //!< Bitmap to activate IO VM-exit (~ 0x7FFF)
  void* io_bitmap_b;              //!< Bitmap to activate IO VM-exit (~ 0xffff)
  struct EptData *ept_data_list[EPT_MAX_EPTP_LIST]; //512
  ULONG64        *ept_ptr_list;
  void* target_eprocess;
  ULONG target_pid;
};

struct EptVoilation
{
	void*      ip;
	ud_mnemonic_code mnemonic;
	ULONG64    fault_pa;
	ULONG64    fault_va;
	ULONG64    pa_value;
	ULONG      access_type;
	bool     is_update_pte;
	bool     is_write_only;
	ULONG    map_type;  
	void*    ept_entry;
};

struct EptUpdateContext
{
	ULONG64  fault_pa;
	ULONG64  old_pa_value;
	ULONG64  new_pa_value;
	void*    old_ept_entry;
	void*    new_ept_entry;
	ULONG    monitor_type;
};

struct ExecutionStatus
{
	ULONG         cpu_num;
	bool          internal_trap;
	EptVoilation  ept_voilation;
	bool          is_target_process;
	bool          enable_interrupt;
	thread_ctx_t *thread_ctx;
	bool          is_executing;
	bool          is_translation;
	UCHAR         op_code;
};

struct VeExceptInfo 
{
	ULONG   reason;		/* EXIT_REASON_EPT_VIOLATION  */
	ULONG   except_mask;	/* FFFFFFFF (set to 0 to deliver more)  */
	ULONG64 exit;		/* normal exit qualification bits, see above  */
	ULONG64 gla;		/* guest linear address */
	ULONG64 gpa;		/* guest physical address  */
	USHORT  eptp;		/* current EPTP index  */
};
#define HELPER_STACK_SIZE 64
#define BLOCK_INS_COUNT   64
#define MAX_ALLOCATE_NUMBER  16

typedef struct _INS_INFO
{
	ULONG            address;
	USHORT           length;
	USHORT           skip;
	ud_mnemonic_code mnemonic;
	ud_operand       operand[2];
}INS_INFO, *PINS_INFO;

struct EmulatorHelper
{
	void           *emu_region;      //PAGE_SIZE
	UCHAR          *emu_ptr;
};

/// Represents VMM related data associated with each processor
struct ProcessorData {
  SharedProcessorData* shared_data;         //!< Shared data
  void* vmm_stack_limit;                    //!< A head of VA for VMM stack
  struct VmControlStructure* vmxon_region;  //!< VA of a VMXON region
  struct VmControlStructure* vmcs_region;   //!< VA of a VMCS region
  //Add
  struct VeExceptInfo*    ve;
  void                   *emu_region;  
  UCHAR                  *emu_ptr;
  struct EmulatorHelper*  emu_helper;
  ULONG_PTR               kitrap01;
  ULONG_PTR               kitrap0e;
  ud_t                    ud_obj;
  PMDL                    buf_mdl;
  ULONG                   buf_base;
  ULONG                   buf_ptr;
  ULONG					  asbuf_base;
  ULONG					  asbuf_ptr;
  ULONG					  hdbuf_base;
  ULONG					  hdbuf_ptr;
  ULONG					  tmpbuf_base;
  ULONG					  tmpbuf_ptr;
  ULONG          dis_ip;
  UCHAR          *code_ptr;
  ULONG64         counter_0;
  ULONG64         counter_1;
  ULONG64         counter_2;
  ULONG64         counter_3;
  ULONG64         counter_4;
  ULONG64         counter_5;
  ULONG64         counter_6;
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

#endif  // HYPERPLATFORM_VMM_H_
