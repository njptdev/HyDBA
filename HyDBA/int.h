#ifndef HYPERPLATFORM_EMU_H_
#define HYPERPLATFORM_EMU_H_

#include <fltKernel.h>
#include "driver.h"

extern "C" {


typedef NTSTATUS(__stdcall* PfnZwProtectVirtualMemory)(HANDLE ProcessHandle, 
	PVOID *BaseAddress, PULONG ProtectSize, ULONG NewProtect, PULONG OldProtect);
typedef NTSTATUS(__stdcall* PfnZwWriteVirtualMemory)(HANDLE ProcessHandle, 
	PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength);
typedef BOOLEAN(NTAPI * PfnKeInsertQueueApc)(
	IN PRKAPC Apc,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2,
	IN KPRIORITY Increment
	);
typedef NTSTATUS(NTAPI *PfnNtQueryVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
	_Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
	_In_ SIZE_T MemoryInformationLength,
	_Out_opt_ PSIZE_T ReturnLength
	);

#define   LOG_SYSENTER_FLAG          0xEEEE
#define   ANALYSIS_CODE_FAULT_BASE   0xAAA00000
#define   ANALYSIS_THREAD_CTX        0xAA

#define CTX_OFFSET 0x440
//ETHREAD/KTHREAD +440h UserGsBase; for 32
#define GET_THREAD_CTX() \
	(thread_ctx_t *)*(ULONG_PTR *)((PUCHAR)PsGetCurrentThread() + CTX_OFFSET)

typedef struct _FAULT_HEADER
{
	ULONG      FaultIp;   //debug
	ULONG      CodeBytePtr;
	ULONG      InsInfoPtr;
	ULONG      FarOffset;
	ULONG      NearOffset;
	KSPIN_LOCK Lock;
	SINGLE_LIST_ENTRY FromListHead; //jmp src
}FAULT_HEADER, *PFAULT_HEADER;

typedef struct _BLOCK_PROFILER
{
	ULONG  FaultIp;        //fault_ip£¬block_ip
	ULONG  BranchOffset1;  //far
	ULONG  BranchOffset2;  //near£¬next
	USHORT Flag;           
	USHORT Syscall;
	ULONG  BlockSize;
	ULONG  BlockHash;
	ULONG  CodeBytesPtr;    
	PVOID  AnalysisCodePtr; 
	ULONG  SbOffset1;
	ULONG  SbOffset2;
	ULONG  CompOffset2;     //near
	KSPIN_LOCK        Lock;
	SINGLE_LIST_ENTRY FromListHead;
}BLOCK_PROFILER, *PBLOCK_PROFILER;

typedef struct _OFFSET_SHADOW
{
	ULONG  SbOffset1;       //far
	ULONG  SbOffset2;       //near
	ULONG  CompOffset2;     
}OFFSET_SHADOW;

typedef struct _FROM_NODE
{
	SINGLE_LIST_ENTRY ListEntry;
	PBLOCK_PROFILER   Profiler;
}FROM_NODE, *PFROM_NODE;

typedef struct _FAULT_PROFILER
{
	ULONG  FaultIp;       
	ULONG  BranchOffset1; //far
	ULONG  BranchOffset2; //near/next
	USHORT Flag;         
	USHORT Syscall;
	ULONG  BlockSize;
	ULONG  BlockHash;
	ULONG  CodeBytesPtr;   
}FAULT_PROFILER, *PFAULT_PROFILER;

typedef struct _KBITMAP_FAULT_FRAME
{
	ULONG Edx;
	ULONG Ecx;
	ULONG Eax;
	ULONG SegFs;
	ULONG ErrCode;
	ULONG Eip;
	ULONG SegCs;
	ULONG EFlags;
	ULONG HardwareEsp;
	ULONG HardwareSegSs;
} KBITMAP_FAULT_FRAME, *PKBITMAP_FAULT_FRAME;

typedef struct _KEPT_FAULT_FRAME
{
	ULONG Ebx;    
	ULONG SegFs;
	ULONG Edx;
	ULONG Ecx;
	ULONG Eax; 
	ULONG Eip;
	ULONG SegCs;
	ULONG EFlags;
	ULONG HardwareEsp;
	ULONG HardwareSegSs;
} KEPT_FAULT_FRAME, *PKEPT_FAULT_FRAME;

typedef struct _KEPT_JUMP_FRAME
{
	ULONG Edi;
	ULONG Esi;
	ULONG Ebx;
	ULONG Ebp;
	ULONG SegFs;
	ULONG Edx;
	ULONG Ecx;
	ULONG Eax;
	ULONG Eip;
	ULONG SegCs;
	ULONG EFlags;
	ULONG HardwareEsp;
	ULONG HardwareSegSs;
} KEPT_JUMP_FRAME, *PKEPT_JUMP_FRAME;

typedef struct _MMPTE_HARDWARE {
	ULONG64 Valid : 1;
	ULONG64 Writable : 1;        // changed for MP version
	ULONG64 Owner : 1;   
	ULONG64 WriteThrough : 1;
	ULONG64 CacheDisable : 1;
	ULONG64 Accessed : 1;
	ULONG64 Dirty : 1;
	ULONG64 LargePage : 1;   // 80h
	ULONG64 Global : 1;
	ULONG64 CopyOnWrite : 1; // software field, 200h
	ULONG64 Prototype : 1;   // software field, 400h
	ULONG64 Write : 1;       // software field - MP change
	ULONG64 PageFrameNumber : 26;
	ULONG64 reserved1 : 25;
	ULONG64 NoExecute : 1;
} MMPTE_HARDWARE, *PMMPTE_HARDWARE;

typedef struct _MMPTE_SOFTWARE {
	ULONG64 Valid : 1;
	ULONG64 PageFileLow : 4;
	ULONG64 Protection : 5;
	ULONG64 Prototype : 1;   //bit 10, 400h
	ULONG64 Transition : 1;  //800h
	ULONG64 PageFileReserved : 1;
	ULONG64 PageFileAllocated : 1;
	ULONG64 Unused : 18;
	ULONG64 PageFileHigh : 32;
} MMPTE_SOFTWARE, *PMMPTE_SOFTWARE;

typedef struct _U4_MMPFN {
	ULONG PteFrame : 24;     //containing page, 0:24
	ULONG AweAllocation : 1; //These pages are either noaccess, readonly or readwrite.
	ULONG Unknown1 : 1;
	ULONG Unknown2 : 1;
	ULONG PrototypePte : 1;  
	ULONG Unknown3 : 4;
}U4_MMPFN;

typedef struct _MMPFN {
	ULONG           WsIndex;     //u1
	PMMPTE_HARDWARE PteAddress;
	MMPTE_SOFTWARE  OriginalPte; //ZwSetInformationProcess/NX
	ULONG           ShareCount;  //u2
	USHORT          ReferenceCount;
	UCHAR           e1;          //u3
	UCHAR           e2;
	U4_MMPFN        u4;
} MMPFN, *PMMPFN;

typedef struct _IPI_CONTEXT_FLUSH
{
	ULONG CpuNum;
	ULONG BlockIp;
	PVOID EptEntry;
}IPI_CONTEXT_FLUSH, *PIPI_CONTEXT_FLUSH;

typedef struct _KTRAP_FRAME_INT
{
	ULONG SegFs;
	ULONG Edx;
	ULONG Ecx;
	ULONG Eax;
	ULONG Edi;
	ULONG Esi;
	ULONG Ebx;
	ULONG Ebp;
	//
	ULONG Eip;
	ULONG SegCs;
	ULONG EFlags;
	ULONG HardwareEsp;
	ULONG HardwareSegSs;
} KTRAP_FRAME_INT, *PKTRAP_FRAME_INT;



#define SHADOW_PAGE_SIZE  64
typedef struct {
	ULONG       base;
	ULONG       limit;
	ULONG       committed;
	ULONG       shadow_base;
	ULONG       shadow_limit;
	ULONG       copied;
	ULONG       pte[16];
	//test
	ULONG       shadow_pa[SHADOW_PAGE_SIZE];
	PVOID       current;
}stack_info;

typedef struct {
	LIST_ENTRY  listhead;
	KSPIN_LOCK  spinlock;
	KSEMAPHORE  semaphore;
}BUFFER_LIST;

typedef struct {
	LIST_ENTRY  entry;
	PVOID       base;
	PVOID       limit;
	PVOID       curr;
	PVOID       real;
}LIST_ELEMENT;

typedef struct {
	ULONG  edi;
	ULONG  esi;
	ULONG  ebp;
	ULONG  esp;
	ULONG  ebx;
	ULONG  edx;
	ULONG  ecx;
	ULONG  eax;
}CONTEXT_STATE;

typedef struct {
	ULONG        start;
	ULONG        tid;
	ULONG        write_copy;
	ULONG        fault_ip;
	ULONG        fault_va;
	ULONG        va_value;
	stack_info   st_info;
	PETHREAD     ethread;
	ULONG        teb;
	PMDL         teb_extend_mdl;
	PVOID        teb_extend_va;
	KEVENT       exit_event;
	ULONG        is_last;
	ULONG        is_exit;
	HANDLE       athread_handle;
	BUFFER_LIST  free_list;
	BUFFER_LIST  full_list;
	LIST_ELEMENT *in_buffer;
	LIST_ELEMENT *out_buffer;
	LIST_ELEMENT list_element[LOG_BLOCK_NUM];
	ULONG64      guard_pa[LOG_BLOCK_NUM];
	PVOID        record_buffer;
	KDPC         dpc_c;
	KAPC         apc_f;
	KDPC         dpc_f;
	ULONG        fault_pending;
	ULONG        in_buffer_pending;
	KEVENT       in_buffer_event;
	PVOID        monitor_page_base;
	PVOID        analysis_base;
	PVOID        check_buffer;
	PVOID        check_ptr;
	ULONG        check_count;
	ULONG        need_check;
	PVOID        set_buffer;
	PVOID        set_ptr;
	ULONG        set_count;
	ULONG        need_set;
	PVOID        ctx_state;
	ULONG        running;
	ULONG        is_flush;
	//PVOID        last_header;
	//PVOID        last_ins;
	//UCHAR        last_buf[LOG_TAIL_SIZE]; //32/4=8
	//ULONG        last_size;
} thread_ctx_t;

ULONG QueryTimeMillisecond();

}
#endif
