// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements an entry point of the driver.

#ifndef POOL_NX_OPTIN
#define POOL_NX_OPTIN 1
#endif

#include "common.h"
#include "global_object.h"
#include "hotplug_callback.h"
#include "log.h"
#include "power_callback.h"
#include "util.h"
#include "vm.h"
#include "performance.h"
#include "ept.h"
#include "vmm.h"
#include "asm.h"
#include <intrin.h>
#include "driver.h"
#include "int.h"
#include "ntddk.h"
#include <ntimage.h>

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

DRIVER_INITIALIZE DriverEntry;

static DRIVER_UNLOAD DriverpDriverUnload;

_IRQL_requires_max_(PASSIVE_LEVEL) bool DriverpIsSuppoetedOS();

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverpDriverUnload)
#pragma alloc_text(INIT, DriverpIsSuppoetedOS)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

#define BITMAP_OFFSET 0

PVOID g_mydriver_start;
PVOID g_mydriver_end;

ULONG        g_monitor_start = 1;
PUCHAR       g_white_bitmap = NULL;
#define      WHITE_MAP_SIZE   (0x7FFFF/4 + 4)


ULONG64 g_RAM_Size = 0x100000000ull; //4GB
ULONG64 g_usb_base_addr = 0xDF030000; //real
ULONG64 g_usb_base_addr2 = 0xDF130000;

CHAR    g_process_name[] = "systeminfo.exe";


HANDLE  g_target_pid = (HANDLE)-1;
ULONG   g_target_cr3 = 0;
PVOID   g_target_eprocess = NULL;

KSPIN_LOCK g_ipi_spinlock;

ULONG   g_start_time;

ULONG   g_ntdll_base = 0;
ULONG   g_kernel_base = 0;
ULONG   g_user32_base = 0;
ULONG   g_module_addr[4] = { 0 };

ULONG   g_module_count = 0;

ULONG   g_allacated_size = 0;
ULONG   g_thread_count = 0;
ULONG   g_exec_count = 0;
ULONG   g_exec_count2 = 0;
ULONG   g_sb_alloc_count = 0;
ULONG   g_sb_free_count = 0;
ULONG   g_sb_recycle_count = 0;

ULONG   g_sb_overflow_count = 0;
BUFFER_ENTRY *g_overflow_entry = NULL;

ULONG   g_athread_count = 0;
KEVENT  g_athread_event;

ULONG   g_MiAllocateWsle = NULL;
PVOID   g_TrampoMiAllocateWsle = NULL;
ULONG   g_MiCopyOnWriteEx = NULL;
PVOID   g_TrampoMiCopyOnWriteEx = NULL;
ULONG   g_MiDeletePteRun = NULL;
PVOID   g_TrampoMiDeletePteRun = NULL;

ULONG   g_MiDeleteVirtualAddresses = NULL;
PVOID   g_TrampoMiDeleteVirtualAddresses = NULL;

ULONG   g_MiSetProtectionOnSection = NULL;
PVOID   g_TrampoMiSetProtectionOnSection = NULL;

ULONG   g_KiFastCallEntry = NULL;
PVOID   g_TrampoKiFastCallEntry = NULL;
ULONG   g_KiServiceExit = NULL;
PVOID   g_TrampoKiServiceExit = NULL;
ULONG   g_Kei386HelperExit = NULL;
PVOID   g_TrampoKei386HelperExit = NULL;
ULONG   g_KiCallUserModeExit = NULL;
PVOID   g_TrampoKiCallUserModeExit = NULL;

//teb
ULONG   g_MmCreateTeb = NULL;
ULONG   g_MmCreateTebBack = NULL;
PVOID   g_TrampoMmCreateTeb = NULL;
//context
ULONG   g_SwapContextOld = NULL;
LONG64  g_SwapContextOldBytes = 0;
ULONG   g_SwapContextOldBack = NULL;
ULONG   g_SwapContext = NULL;
LONG64  g_SwapContextBytes = 0;
ULONG   g_SwapContextBack = NULL;

SharedProcessorData *g_shared_data = nullptr;

extern ProcessorData *processor_list[];

typedef struct _REDIRECT_INFO
{
	ULONG OldPa;
	PVOID KernelVa;
}REDIRECT_INFO, *PREDIRECT_INFO;

REDIRECT_INFO  *g_redirect_table = NULL;
ULONG     *g_page_state = NULL;

PVOID     *g_code_table = NULL;
PMDL       g_code_table_mdl = NULL;

ULONG      g_MmPfnDatabase = 0;

ULONG     g_local_apic = 0;
ULONG     g_cpu_apid_id[8] = { 0 };

ULONG     g_debug_flag = 0;

//idt
ULONG     g_idt_routines[256] = {0};

PVOID     *g_entry_table = NULL;

#define   RD_ALLOCATE_SIZE        8*1024*1024  

bool       g_target_active = false;


LIST_ENTRY            g_entries_list;
KSPIN_LOCK            g_entries_lock;
LIST_ENTRY            g_free_entries_list;
KSPIN_LOCK            g_free_entries_lock;
PVOID                 g_entries_base = NULL;
PVOID                 g_entries_ptr = NULL;

PVOID           g_alloc_state_base[CACHE_STATE_ALLOCATE_NUM] = { 0 };
PMDL            g_alloc_state_mdl[CACHE_STATE_ALLOCATE_NUM] = { 0 };
ULONG           g_alloc_state_count = 0;

PVOID           g_alloc_state_kernel_base[CACHE_STATE_ALLOCATE_NUM] = { 0 };
ULONG           g_alloc_state_kernel_count = 0;

KGUARDED_MUTEX  g_ptAllocMutex;
PVOID           g_alloc_pt_base = NULL;  
PVOID           g_alloc_pt_ptr = NULL;
ULONG           g_pt_map_count = 0;
PVOID           g_pt_map[4][512] = { 0 }; //2*512*PAGE_SIZE = 4M
PVOID           g_alloc_pd_base = NULL;
PVOID           g_pd_map[4] = { 0 };    


KGUARDED_MUTEX  g_allocMutex;
PVOID           g_alloc_code_base = NULL;
PMDL            g_alloc_code_mdl = NULL;
PVOID           g_alloc_code_ptr = NULL;


KGUARDED_MUTEX  g_rdAllocMutex;
PVOID       g_rdAllocBase = NULL;
PVOID       g_rdAllocPtr = NULL;

ULONG       g_aCountAddr = 0;
ULONG       g_syncCountAddr = 0;

ULONG       g_process_init_va[16] = { 0 };
ULONG64     g_process_init_pa[16] = { 0 };
ULONG       g_init_page_num = 0;

ULONG       g_process_init_map_va[16] = { 0 };
ULONG64     g_process_init_map_pa[16] = { 0 };
ULONG       g_init_map_num = 0;

ULONG64     g_total_counter[10] = { 0 };

//function test
ULONG       g_send_count = 0;
ULONG       g_write_count = 0;
ULONG       g_recv_bytes = 0;// 4 * 1024;   //4k£¬ pscp 0
ULONG       g_read_bytes = 4 * 1024;   //4k
ULONG       g_taint_set = 0;


VOID AssistedAnalysisThread(PVOID lpParam);
KDEFERRED_ROUTINE     DpcContextSwitchBuffer;
KDEFERRED_ROUTINE     DpcFaultSwitchBuffer;
void  ApcFaultRequireBuffer(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);

NTKERNELAPI CHAR* PsGetProcessImageFileName(__in PEPROCESS Process);
void  SetVirtualAddrType(PVOID BaseAddress, ULONG_PTR Size, ULONG Type);
//32
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY     InLoadOrderLinks;
	LIST_ENTRY     InMemoryOrderLinks;
	LIST_ENTRY     InInitializationOrderLinks;
	PVOID          DllBase;
	PVOID          EntryPoint;
	ULONG          SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
	ULONG       Length;
	ULONG       Initialized;
	PVOID       SsHandle;
	LIST_ENTRY  InLoadOrderModuleList;
	LIST_ENTRY  InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
	UCHAR                         InheritedAddressSpace;
	UCHAR                         ReadImageFileExecOptions;
	UCHAR                         BeingDebugged;
	UCHAR                         BitField;
	PVOID                         Mutant;
	PVOID                         ImageBaseAddress;
	PPEB_LDR_DATA                 Ldr;
} PEB, *PPEB;

typedef PPEB(__stdcall *FuncPsGetProcessPeb)(PEPROCESS);


#define SYSCALL_ZwInitializeNlsFiles      0x10e
#define SYSCALL_ZwGetNlsSectionPtr        0x114
#define SYSCALL_ZwAllocateVirtualMemory   0x1a3
#define SYSCALL_ZwFreeVirtualMemory       0x121
#define SYSCALL_ZwProtectVirtualMemory    0xc8
#define SYSCALL_ZwReadFile                0x8c
#define SYSCALL_ZwWriteFile               0x7
#define SYSCALL_ZwDeviceIoControlFile     0x13c
#define SYSCALL_ZwRemoveIoCompletion      0x7e

#define SYSCALL_NtCreateSection          0x15A
#define SYSCALL_NtMapViewOfSection       0xFA

#define GDI32_ExtTextOutW                0xA7C50

typedef
NTSTATUS
(NTAPI *PfnNtInitializeNlsFiles)(
	_Out_ PVOID *BaseAddress,
	_Out_ PLCID DefaultLocaleId,
	_Out_ PLARGE_INTEGER DefaultCasingTableSize
	);
PfnNtInitializeNlsFiles origNtInitializeNlsFiles = NULL;

typedef NTSTATUS
(NTAPI *PfnNtGetNlsSectionPtr)(
	__in ULONG SectionType,
	__in ULONG SectionData,
	__in PVOID ContextData,
	__out PVOID *SectionPointer,
	__out PULONG SectionSize
	);
PfnNtGetNlsSectionPtr origNtGetNlsSectionPtr = NULL;

typedef NTSTATUS(NTAPI *PfnNtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG ZeroBits,
	PULONG AllocationSize,
	ULONG AllocationType,
	ULONG Protect);
PfnNtAllocateVirtualMemory origNtAllocateVirtualMemory = NULL;

typedef NTSTATUS(NTAPI *PfnNtFreeVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	PULONG FreeSize,
	ULONG  FreeType);
PfnNtFreeVirtualMemory origNtFreeVirtualMemory = NULL;

typedef  NTSTATUS (NTAPI *PfnNtProtectVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID * BaseAddress,
	PSIZE_T RegionSize,
	ULONG NewProtectWin32,
	PULONG OldProtect);
PfnNtProtectVirtualMemory origNtProtectVirtualMemory = NULL;

typedef NTSTATUS (NTAPI *PfnNtQueryVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
	_Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
	_In_ SIZE_T MemoryInformationLength,
	_Out_opt_ PSIZE_T ReturnLength
);

typedef NTSTATUS(NTAPI *PfnNtCreateSection)(
	PHANDLE            SectionHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER     MaximumSize,
	ULONG              SectionPageProtection,
	ULONG              AllocationAttributes,
	HANDLE             FileHandle
	);
PfnNtCreateSection orgNtCreateSection = NULL;
ULONG           gNtCreateSectionCount = 0;

typedef NTSTATUS(NTAPI *PfnNtMapViewOfSection)(
	HANDLE          SectionHandle,
	HANDLE          ProcessHandle,
	PVOID           *BaseAddress,
	ULONG_PTR       ZeroBits,
	SIZE_T          CommitSize,
	PLARGE_INTEGER  SectionOffset,
	PSIZE_T         ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG           AllocationType,
	ULONG           Win32Protect
	);
PfnNtMapViewOfSection orgNtMapViewOfSection = NULL;
ULONG           gNtMapViewOfSectionCount = 0;

HANDLE  g_fileReadSectionHandle = NULL;
ULONG   g_mapViewAddress = 0;
ULONG   g_gdi32ExtTextOutW = 0;

ULONG   g_notepad_7955 = 0;

typedef NTSTATUS (NTAPI *PfnNtReadFile)(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	PLARGE_INTEGER   ByteOffset,
	PULONG           Key
);
PfnNtReadFile        origNtReadFile = NULL;
ULONG           gNtReadFileCount = 0;
typedef   NTSTATUS(NTAPI *PfnNtWriteFile)(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	PLARGE_INTEGER   ByteOffset,
	PULONG           Key
	);
PfnNtWriteFile        origNtWriteFile = NULL;
ULONG           gNtWriteFileCount = 0;

typedef  NTSTATUS (NTAPI *PfnNtDeviceIoControlFile)(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG            IoControlCode,
	PVOID            InputBuffer,
	ULONG            InputBufferLength,
	PVOID            OutputBuffer,
	ULONG            OutputBufferLength
);
PfnNtDeviceIoControlFile origNtDeviceIoControlFile = NULL;
ULONG           gNtDeviceIoCount = 0;

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef  NTSTATUS (NTAPI * PfnKeInitializeApc)(
	PKAPC Apc,
	PETHREAD Thread,
	KAPC_ENVIRONMENT Environment,
	PVOID KernelRoutine,  //PKKERNEL_ROUTINE
	PVOID RundownRoutine, //PKRUNDOWN_ROUTINE
	PVOID NormalRoutine,  //PKNORMAL_ROUTINE
	KPROCESSOR_MODE ProcessorMode,
	PVOID NormalContext
);
PfnKeInitializeApc KeInitializeApc = NULL;

typedef BOOLEAN (NTAPI * PfnKeInsertQueueApc)(
	IN PRKAPC Apc,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2,
	IN KPRIORITY Increment
	);
PfnKeInsertQueueApc KeInsertQueueApc = NULL;

typedef struct AFD_WSABUF
{
	ULONG len;
	PCHAR buf;
}AFD_WSABUF, *PAFD_WSABUF;

typedef struct AFD_INFO
{
	PAFD_WSABUF    BufferArray;
	ULONG BufferCount;
	ULONG AfdFlags;
	ULONG TdiFlags;
}AFD_INFO, *PAFD_INFO;

typedef ULONG (__fastcall* PfnMiAllocateWsle)(ULONG a1, ULONG a2, ULONG a3, ULONG a4,
	ULONG a5, ULONG a6, ULONG a7);

typedef int (__fastcall* PfnMiCopyOnWriteEx)(ULONG_PTR a1, ULONG a2, ULONG a3, ULONG a4, ULONG a5);

typedef int (__fastcall* PfnMiDeletePteRun)(ULONG a1, ULONG a2, ULONG a3, ULONG a4, ULONG a5);

typedef int(__fastcall* PfnMiDeleteVirtualAddresses)(ULONG a1, ULONG a2, ULONG a3, ULONG a4, ULONG a5);

typedef  int(__fastcall* PfnMyMiSetProtectionOnSection)(ULONG eproc, ULONG vad, ULONG start_va, ULONG end_va,
	ULONG new_prot, ULONG out_old_prot, ULONG charge, ULONG locked);

PfnNtProtectVirtualMemory pNtProtectVirtualMemory = NULL;
PfnZwWriteVirtualMemory   pZwWriteVirtualMemory = NULL;

PfnNtQueryVirtualMemory   pNtQueryVirtualMemory = NULL;

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //Used only in checked build
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} SSDT_ENTRY;
#pragma pack()

__declspec(dllimport)   SSDT_ENTRY KeServiceDescriptorTable;
#define SYSTEMSERVICE(_index)  KeServiceDescriptorTable.ServiceTableBase[_index]
////////////////////////////////////////////////////////////////////////////////
//
// implementations
//
extern ULONG  output_flag;
extern ULONG  output_flag2;

ULONG g_codeDispatchAddr = 0;
ULONG g_faultCodePage;
ULONG g_checkCodePage;
BLOCK_PROFILER *g_retCodeProfiler = NULL;
ULONG g_initCodePage;
ULONG g_divisor;

UCHAR code_dispatch_template[] = {
	0x9C,                               // pushfd
	0x50,                               // push        eax
	0x53,                               // push        ebx
	0x8B, 0xD9,                         // mov         ebx, ecx 
	0x8B, 0xC1,                         // mov         eax, ecx  
	0xC1, 0xE8, 0x0C,                   // shr         eax, 0Ch
	0x8B, 0x0C, 0x85, 0x00, 0x00, 0x00, 0x00, // mov   ecx, dword ptr [eax * 4 + g_code_table]
	0xE3, 0x11,                         // jecxz       FAULT
	0x8B, 0xC3,                         // mov         eax, ebx
	0x25, 0xFF, 0x0F, 0x00, 0x00,       // and         eax, 0FFFh
	0x8B, 0x0C, 0x81,                   // mov         ecx, dword ptr [ecx + eax*4]                 
	0xE3, 0x05,                         // jecxz       FAULT
	0x83, 0xC1, 0x14,                   // add         ecx, 20 //offset
	0x8B, 0xD9,                         // mov         ebx,ecx
	//FAULT
	0x8B, 0xCB,                         // mov         ecx,ebx  	
	0x5B,                               // pop         ebx
	0x58,                               // pop         eax
	0x9D,                               // popfd
	0xC3,                               // ret
};

void ApcKernelRoutine(IN struct _KAPC *Apc,
	IN OUT PVOID *NormalRoutine, //PKNORMAL_ROUTINE
	IN OUT PVOID *NormalContext,
	IN OUT PVOID *SystemArgument1,
	IN OUT PVOID *SystemArgument2)
{
}

VOID UpdateEptEntry(EptData *ept_data, ULONG64 pa, ULONG ept_value)
{
	const auto ept_entry = EptGetEptPtEntry(ept_data, pa);
	if (!ept_entry)
	{
		HYPERPLATFORM_LOG_DEBUG("[CHECK] UpdateEptEntry error, entry does not exist. %llx", pa);
		return;
	}
	ULONG64 new_entry_value = (ept_entry->all & (~0x3ull)) | ept_value;
	InterlockedExchange64((LONGLONG *)&ept_entry->all, new_entry_value);
}

void InitTargetProcessPfnMap(EptData *ept_data, ULONG64 pa, ULONG monitor_type)
{
	PUCHAR   pfn_bitmap;
	pfn_bitmap = ept_data->pfn_bitmap;

	ULONG64 pfn = pa >> PAGE_SHIFT;
	ULONG64 byte_offset = PFN2BYTE(pfn);
	ULONG   bits_offset = 2 * PFN2BIT(pfn);
	pfn_bitmap[byte_offset] = (UCHAR)((pfn_bitmap[byte_offset] & ~(0x3u << bits_offset)) | (monitor_type << bits_offset));
}

PVOID ClearPageEptEntryAndBitmap(EptData *ept_data, ULONG64 pa)
{
	UCHAR *pfn_bitmap = ept_data->pfn_bitmap;

	ULONG64 pfn = pa >> PAGE_SHIFT;
	ULONG64 byte_offset = PFN2BYTE(pfn);
	ULONG   bits_offset = 2 * PFN2BIT(pfn);

	const auto ept_entry = EptGetEptPtEntry(ept_data, pa);
	if (!ept_entry)
	{
		HYPERPLATFORM_LOG_DEBUG("[CHECK] ClearPageEptEntryAndBitmap error, entry does not exist. %llx", pa);
		return 0;
	}
	ept_entry->all = ept_entry->all | 0x3ull;
	//Interlocked
	pfn_bitmap[byte_offset] = (UCHAR)(pfn_bitmap[byte_offset] & ~(0x3u << bits_offset));
	
	return ept_entry;
}

void StartEptMonitor32(ULONG_PTR  cr3_pa)
{
	ULONG64 pdpt_va[4];
	PULONG64 pd_mapped_va = NULL;
	PULONG64 pt_mapped_va = NULL;
	PHYSICAL_ADDRESS PhysicalAddress;
	PhysicalAddress.QuadPart = cr3_pa;
	PULONG64 pMappedVa = (PULONG64)MmMapIoSpace(PhysicalAddress, 0x20, MmNonCached);
	if (!pMappedVa)
	{
		DbgPrint("StartEptMonitor32 error. pdpt\n");
		return;
	}
	RtlCopyMemory(pdpt_va, pMappedVa, 0x20);
	MmUnmapIoSpace(pMappedVa, 0x20);
	//kernel
	//for (ULONG i = 2; i < 4; i++)
	//{
	//	if (pdpt_va[i] & 0x1ull)
	//	{
	//		ULONG64 pd_pa = pdpt_va[i] & 0x7FFFFFFFFFFFF000ull;
	//		//PD
	//		PVOID   allocva = (PVOID)((ULONG)g_alloc_pd_base + i*PAGE_SIZE);
	//		PHYSICAL_ADDRESS lpa = MmGetPhysicalAddress(allocva);
	//		g_pd_map[i] = allocva;
	//		auto ept_entry = EptGetEptPtEntry(g_shared_data->ept_data_list[EPTP_ANALYSIS], pd_pa);
	//		ept_entry->fields.physial_address = lpa.QuadPart >> 12;
	//		DbgPrint("[PD] index %u, pa %llx -> shadow va %x, pa %llx, ept_entry %x\n",
	//			i, pd_pa, allocva, lpa.QuadPart, ept_entry);
	//	}
	//}
	//PDPTE, bits 31:30, 3-level. PAE£¬0xC0600000
	for (ULONG i = 0; i < 2; i++) 
	{
		if (pdpt_va[i] & 0x1ull) 
		{
			ULONG64 pd_pa = pdpt_va[i] & 0x7FFFFFFFFFFFF000ull;
			PVOID   allocva = (PVOID)((ULONG)g_alloc_pd_base + i*PAGE_SIZE);
			PHYSICAL_ADDRESS lpa = MmGetPhysicalAddress(allocva);
			g_pd_map[i] = allocva;
			auto ept_entry = EptGetEptPtEntry(g_shared_data->ept_data_list[EPTP_ANALYSIS], pd_pa);
			ept_entry->fields.physial_address = lpa.QuadPart >> 12;
			DbgPrint("[PD], index %u, pa %llx -> shadow va %x, pa %llx, ept_entry %x\n",
				i, pd_pa, allocva, lpa.QuadPart, ept_entry);

			PhysicalAddress.QuadPart = pd_pa;
			PULONG64 pd_mapped_va = (PULONG64)MmMapIoSpace(PhysicalAddress, PAGE_SIZE, MmNonCached);
			if (!pd_mapped_va)
			{
				DbgPrint("StartEptMonitor32 error. pd\n");
				return;
			}
			//InitTargetProcessPfnMap(ept_data, pd_pa, 3);
			DbgPrint("PDPTE paddr: %llx\n", pd_pa);
			for (ULONG j = 0; j < 512; j++) 
			{
				if (pd_mapped_va[j] & 0x1ull)
				{
					ULONG64 pt_pa = pd_mapped_va[j] & 0x7FFFFFFFFFFFF000ull;
					PhysicalAddress.QuadPart = pt_pa;
					PULONG64 pt_mapped_va = (PULONG64)MmMapIoSpace(PhysicalAddress, PAGE_SIZE, MmNonCached);
					if (!pt_mapped_va)
					{
						DbgPrint("StartEptMonitor32 error. pt\n");
						return;
					}
					//InitTargetProcessPfnMap(ept_data, pt_pa, 2);
					DbgPrint(" [%x] PDE paddr: %llx\n", j, pt_pa);
					ULONG k_max = 512;
					if ((i == 1) && (j == 511)) //Ignore shared user data£¬ 0x7ffe0000<->0xffdf0000
					{
						k_max = 480; //max 7ffe0000
					}
					for (ULONG k = 0; k < k_max; k++)
					{
						if (pt_mapped_va[k] & 0x1ull)
						{
							ULONG64 page_4k_pa = pt_mapped_va[k] & 0xFFFFFFFFFFFFF000ull;
							ULONG   vpfn = (i << 18) + (j << 9) + k;
							DbgPrint("  [%x] PTE va: %x, paddr: %llx.\n", k, vpfn << 12, page_4k_pa);
							g_process_init_map_va[g_init_map_num] = vpfn;
							g_process_init_map_pa[g_init_map_num] = pt_mapped_va[k];
							g_init_map_num++;
							if (!(page_4k_pa >> 63)) 
							{
								g_process_init_va[g_init_page_num] = vpfn;
								g_process_init_pa[g_init_page_num] = page_4k_pa;
								g_init_page_num++;
								DbgPrint("  Execute [%x] PTE va: %x, paddr: %llx.\n", k, vpfn << 12, page_4k_pa);
							}
						}
					}
					for (ULONG k = k_max; k < 512; k++)
					{
						if (pt_mapped_va[k] & 0x1ull)
						{
							ULONG64 page_4k_pa = pt_mapped_va[k] & 0xFFFFFFFFFFFFF000ull;
							ULONG   vpfn = (i << 18) + (j << 9) + k;
							g_process_init_map_va[g_init_map_num] = vpfn;
							g_process_init_map_pa[g_init_map_num] = pt_mapped_va[k];
							g_init_map_num++;
							DbgPrint("  Special [%x] PTE va: %x, paddr: %llx.\n", k, vpfn << 12, page_4k_pa);
						}
					}
					MmUnmapIoSpace(pt_mapped_va, PAGE_SIZE);
				}
			}
			MmUnmapIoSpace(pd_mapped_va, PAGE_SIZE);
		}
	}
}

NTSTATUS OutputProcessorCounter(void *context)
{
	ProcessorData *processor_data = nullptr;
	auto status = UtilVmCall(HypercallNumber::kGetProcessorData, &processor_data);
	if (!NT_SUCCESS(status)) 
	{
		return status;
	}
	ULONG buf_used = processor_data->buf_ptr - processor_data->buf_base;
	ULONG buf_used2 = processor_data->asbuf_ptr - processor_data->asbuf_base;
	DbgPrint("[%d] c0 %llu, c1 %llu, c2 %llu, c3 %llu, c4 %llu, c5 %llu, c6 %llu, buf_used %u %u.\n",
		KeGetCurrentProcessorNumberEx(nullptr),
		processor_data->counter_0,
		processor_data->counter_1,
		processor_data->counter_2,
		processor_data->counter_3,
		processor_data->counter_4, 
		processor_data->counter_5,
		processor_data->counter_6,
		buf_used, buf_used2);
	
	g_total_counter[0] += processor_data->counter_0;
	g_total_counter[1] += processor_data->counter_1;
	g_total_counter[2] += processor_data->counter_2;
	g_total_counter[3] += processor_data->counter_3;
	g_total_counter[4] += processor_data->counter_4;
	g_total_counter[5] += processor_data->counter_5;
	g_total_counter[6] += processor_data->counter_6;
	g_total_counter[7] += buf_used;
	g_total_counter[8] += buf_used2;

	//Unlock
	MmUnlockPages(processor_data->buf_mdl);
	IoFreeMdl(processor_data->buf_mdl);

	HANDLE            hProcess;
	OBJECT_ATTRIBUTES ObjAttr = { 0 };
	CLIENT_ID         ClientId = { 0 };
	ClientId.UniqueProcess = context;
	status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjAttr, &ClientId);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("OutputProcessorCounter ZwOpenProcess Error -- %#X", status);
		ZwClose(hProcess);
		return 0;
	}
	SIZE_T ReginSize = 0;
	ZwFreeVirtualMemory(hProcess, (PVOID*)&processor_data->buf_base, &ReginSize, MEM_RELEASE);
	ZwClose(hProcess);

	return STATUS_SUCCESS;
}

ULONG QueryTimeMillisecond()
{
	LARGE_INTEGER CurTime, Freq;
	CurTime = KeQueryPerformanceCounter(&Freq);
	return (ULONG)((CurTime.QuadPart * 1000) / Freq.QuadPart);
}

ULONG_PTR IpiEptToNormal(ULONG_PTR Argument)
{
	AsmVmFunc(0, EPTP_NORMAL);
	ULONG pcr = AsmGetPcr();
	*(ULONG *)(pcr + KPCR_EPTP_OFFSET) = EPTP_NORMAL;

	//vm exit
	UtilVmCall(HypercallNumber::kInvalidEpt, NULL);
	//flush tlb
	AsmFlushAllTlb();

	return 0;
}

ULONG_PTR IpiEptToMonitor(ULONG_PTR Argument)
{
	AsmVmFunc(0, EPTP_MONITOR1);

	ULONG pcr = AsmGetPcr();
	*(ULONG *)(pcr + KPCR_EPTP_OFFSET) = EPTP_MONITOR1;

	return 0;
}

ULONG_PTR IpiToAnalysis(ULONG_PTR Argument)
{
	AsmVmFunc(0, EPTP_ANALYSIS);

	ULONG pcr = AsmGetPcr();
	*(ULONG *)(pcr + KPCR_EPTP_OFFSET) = EPTP_ANALYSIS;

	return 0;
}

ULONG_PTR IpiEptMonitorUpdatePage(ULONG_PTR Argument)
{
	ULONG page = Argument;

	ULONG pcr = AsmGetPcr();
	ULONG eptp = *(ULONG *)(pcr + KPCR_EPTP_OFFSET);
	if (eptp == EPTP_MONITOR1)
	{
		AsmVmFunc(0, EPTP_MONITOR1);
		__invlpg((PVOID)page);
	}
	/*else
	{
		DbgPrint("[IpiEptMonitorUpdatePage] cpu %d, tid %d, eptp %d\n", 
			KeGetCurrentProcessorNumber(), PsGetCurrentThreadId(), eptp);
	}*/
	

	return 0;
}

ULONG_PTR IpiEptMonitorSetGuardPages(ULONG_PTR Argument)
{
	ULONG pcr = AsmGetPcr();
	if (*(ULONG *)(pcr + KPCR_EPTP_OFFSET) == EPTP_MONITOR1)
	{
		AsmVmFunc(0, EPTP_MONITOR1);
	}

	return 0;
}

PVOID  AllocateFromUserspace(HANDLE pid, SIZE_T size)
{
	HANDLE            hProcess;
	OBJECT_ATTRIBUTES ObjAttr = { 0 };
	CLIENT_ID         ClientId = { 0 };
	ClientId.UniqueProcess = pid;

	NTSTATUS status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjAttr, &ClientId);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("ZwOpenProcess Error -- %#X\n", status);
		HYPERPLATFORM_COMMON_DBG_BREAK();
		return 0;
	}
	SIZE_T ReginSize = size;
	PVOID  allocBase = 0;
	ULONG  allocType = MEM_COMMIT;

	status = ZwAllocateVirtualMemory(hProcess, &allocBase, 0, &ReginSize, allocType, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("ZwAllocateVirtualMemory Error -- %#X\n", status);
		HYPERPLATFORM_COMMON_DBG_BREAK();
		ZwClose(hProcess);
		return 0;
	}
	ZwClose(hProcess);
	return allocBase;
}

PVOID AllocatePageTableFromCache()
{
	PVOID allocAddr = NULL;

	KeAcquireGuardedMutex(&g_ptAllocMutex);

	if (((ULONG_PTR)g_alloc_pt_ptr + PAGE_SIZE) > ((ULONG_PTR)g_alloc_pt_base + CACHE_CODE_TABLE_SIZE))
	{
		DbgPrint("AllocatePageTableFromCache, g_alloc_pt_ptr %x, g_alloc_pt_base %x, g_pt_map_count %u.\n",
			g_alloc_pt_ptr, g_alloc_pt_base, g_pt_map_count);
		HYPERPLATFORM_COMMON_DBG_BREAK();
		KeReleaseGuardedMutex(&g_ptAllocMutex);
		ZwTerminateProcess(NtCurrentProcess(), 1);
	}
	allocAddr = g_alloc_pt_ptr;
	g_alloc_pt_ptr = (PVOID)((ULONG_PTR)g_alloc_pt_ptr + PAGE_SIZE);

	g_pt_map_count++;

	KeReleaseGuardedMutex(&g_ptAllocMutex);

	return allocAddr;
}


_Use_decl_annotations_ void ApcSwapOutStatePage(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	PVOID va = SystemArgument1;
	PVOID sva = SystemArgument2;

	HANDLE  hFile;
	IO_STATUS_BLOCK   IoStatusBlock;
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING FilePath;
	WCHAR  wPath[64] = L"";

	//DbgPrint("[ApcSwapOutStatePage] tid %d, va %x, sva %x.\n", PsGetCurrentThreadId(), va, sva);

	swprintf(wPath, L"\\??\\d:\\log\\s_page_%05x", (ULONG)va >> 12);
	RtlInitUnicodeString(&FilePath, wPath);
	InitializeObjectAttributes(&ObjectAttributes, &FilePath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	KAPC_STATE kApc;
	KeStackAttachProcess((PRKPROCESS)g_target_eprocess, &kApc);

	status = ZwCreateFile(&hFile,
		GENERIC_WRITE, &ObjectAttributes, &IoStatusBlock, NULL,
		FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OVERWRITE_IF,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0); //FILE_WRITE_THROUGH
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[CHECK] SwapOutStatePage, create file error - %#x\n", status);
		HYPERPLATFORM_COMMON_DBG_BREAK();
	}

	status = ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatusBlock, sva, PAGE_SIZE, NULL, NULL);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[CHECK] SwapOutStatePage, write file error - %x\n", status);
		HYPERPLATFORM_COMMON_DBG_BREAK();
	}


	ZwClose(hFile);

	ULONG   pdpt_index = (ULONG)va >> 30;
	ULONG   pd_index = ((ULONG)va >> 21) & 0x1FF;
	ULONG   pt_index = ((ULONG)va >> 12) & 0x1FF;
	PVOID   pt_map_va = g_pt_map[pdpt_index][pd_index];
	*(ULONG *)((ULONG)pt_map_va + 8 * pt_index + 4) |= 0x80000000; //bit63=1

	KeUnstackDetachProcess(&kApc);
}

void ApcSwapKernelRoutine(IN struct _KAPC *Apc,
	IN OUT PVOID *NormalRoutine, //PKNORMAL_ROUTINE
	IN OUT PVOID *NormalContext,
	IN OUT PVOID *SystemArgument1,
	IN OUT PVOID *SystemArgument2)
{
	ExFreePool(Apc);
}

PVOID AllocateFromUserSpaceBufferEntries(ULONG va)
{
	PVOID alloc_va = NULL;

	BUFFER_ENTRY *entry = (BUFFER_ENTRY *)ExInterlockedRemoveHeadList(&g_entries_list, &g_entries_lock);
	if (entry == NULL)
	{
		while (1)
		{
			BUFFER_ENTRY *free_entry = (BUFFER_ENTRY *)ExInterlockedRemoveHeadList(&g_free_entries_list, &g_free_entries_lock);
			if (!free_entry)
			{
				entry = g_overflow_entry;
				g_sb_overflow_count++;

				//DbgPrint("[CHECK] g_free_entries_list null, va %x, g_overflow_entry %x, g_sb_recycle_count %u, g_sb_alloc_count %u, g_sb_free_count %u.\n",
				//	va, g_overflow_entry, g_sb_recycle_count, g_sb_alloc_count, g_sb_free_count);

				break;
			}
			else if (free_entry->MappedVa & 2)  
			{
				free_entry->MappedVa &= 0xFFFFFFFC;
				continue;
			}
			else 
			{
				ULONG oldva = free_entry->MappedVa & 0xFFFFF000;
				//DbgPrint("[g_free_entries_list] recycle, tid %d, free_entry %x, old_va %x, new_va %x.\n",
				//	PsGetCurrentThreadId(), free_entry, oldva, va, g_sb_alloc_count, g_sb_free_count);
				/*PKAPC swapApc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
				KeInitializeApc(swapApc, PsGetCurrentThread(), OriginalApcEnvironment, ApcSwapKernelRoutine,
					NULL, ApcSwapOutStatePage, KernelMode, NULL);
				BOOLEAN  status = KeInsertQueueApc(swapApc, (PVOID)oldva, free_entry->Address, 0);*/

				ULONG   pdpt_index = oldva >> 30;
				ULONG   pd_index = (oldva >> 21) & 0x1FF;
				ULONG   pt_index = (oldva >> 12) & 0x1FF;
				PVOID   pt_map_va = g_pt_map[pdpt_index][pd_index];
				*(ULONG *)((ULONG)pt_map_va + 8 * pt_index) &= 0xFFFFFFFE; //p=0

				free_entry->MappedVa = 0;
				entry = free_entry;
		
				g_sb_recycle_count++;

				break;
			}
		}
	}

	entry->MappedVa = va & 0xFFFFF000;
	alloc_va = entry->Address;

	InterlockedExchange((LONG *)&g_entry_table[va >> 12], (LONG)entry);

	g_sb_alloc_count++;


	return alloc_va;
}

PVOID DeallocateUserSpaceBufferEntries(ULONG vfn)
{
	PVOID  alloc_va = NULL;
	BUFFER_ENTRY *entry = (BUFFER_ENTRY *)g_entry_table[vfn];
	if (entry)
	{
		alloc_va = entry->Address;
		InterlockedExchange((LONG *)&g_entry_table[vfn], 0);
		ExInterlockedInsertTailList(&g_entries_list, &entry->ListEntry, &g_entries_lock);

		g_sb_free_count++;
	}

	return alloc_va;
}

VOID AnalysisAllocateMapEntry(ULONG va, ULONG pa)
{

	ULONG   pdpt_index = va >> 30;
	ULONG   pd_index = (va >> 21) & 0x1FF;
	ULONG   pt_index = (va >> 12) & 0x1FF;
	PVOID   pt_map_va = g_pt_map[pdpt_index][pd_index];
	if (!pt_map_va)
	{
		pt_map_va = AllocatePageTableFromCache();
		g_pt_map[pdpt_index][pd_index] = pt_map_va;

		PHYSICAL_ADDRESS pt_lpa = MmGetPhysicalAddress(pt_map_va);
		*(ULONG *)((ULONG)g_pd_map[pdpt_index] + 8 * pd_index) = pt_lpa.LowPart | 0x867;
	}

	PVOID  allocva = AllocateFromUserSpaceBufferEntries(va);
	PHYSICAL_ADDRESS lpa = MmGetPhysicalAddress(allocva);
	*(ULONG *)((ULONG)pt_map_va + 8 * pt_index) = lpa.LowPart | 0x867;
}

VOID AnalysisConstructMapEntry(ULONG va)
{
	ULONG  pte = 0xc0000000 + (((ULONG)va >> 9) & 0x7ffff8);
	ULONG  pdpt_index = va >> 30;
	ULONG  pd_index = (va >> 21) & 0x1FF;
	ULONG  pt_index = (va >> 12) & 0x1FF;
	PVOID  pt_map_va = g_pt_map[pdpt_index][pd_index];
	if (!pt_map_va)
	{
		pt_map_va = AllocatePageTableFromCache();
		g_pt_map[pdpt_index][pd_index] = pt_map_va;

		PHYSICAL_ADDRESS pt_lpa = MmGetPhysicalAddress(pt_map_va);
		*(ULONG *)((ULONG)g_pd_map[pdpt_index] + 8 * pd_index) = pt_lpa.LowPart | 0x867;
	}

	*(ULONG64 *)((ULONG)pt_map_va + 8 * pt_index) = *(ULONG64 *)pte;
}

NTSTATUS AllocateExecutePageProcessorsUser(void *context)
{
	HANDLE pid = (HANDLE)context;

	ULONG cpu_num = KeGetCurrentProcessorNumber();
	ProcessorData *processor_data = processor_list[cpu_num];

	//Test
	AsmStopSMEP();

	PVOID allocBase = AllocateFromUserspace(pid, PER_CPU_ALLOCATE_SIZE);
	processor_data->buf_base = (ULONG)allocBase;
	processor_data->buf_ptr = processor_data->buf_base;

	//Lock
	KAPC_STATE kApc;
	PEPROCESS  pEprocess;
	PsLookupProcessByProcessId(pid, &pEprocess);
	KeStackAttachProcess(pEprocess, &kApc);

	processor_data->buf_mdl = IoAllocateMdl(allocBase, PER_CPU_ALLOCATE_SIZE, FALSE, FALSE, NULL);
	__try
	{
		MmProbeAndLockPages(processor_data->buf_mdl, UserMode, IoWriteAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("Lock buf_mdl error code = %x", GetExceptionCode());
		__debugbreak();
	}

	ULONG count = 0;
	for (ULONG pg = 0; pg < PER_CPU_ALLOCATE_SIZE; pg += PAGE_SIZE)
	{
		ULONG  va = (ULONG)allocBase + pg;
		g_page_state[va >> 12] = 1; //Mark user
		AnalysisConstructMapEntry(va);
	}

	KeUnstackDetachProcess(&kApc);
	ObDereferenceObject(pEprocess);

	processor_data->asbuf_base = (ULONG)allocBase + PER_CPU_CODE_BUF_SIZE;
	processor_data->asbuf_ptr = processor_data->asbuf_base;
	processor_data->hdbuf_base = processor_data->asbuf_base + PER_CPU_ANALYSIS_BUF_SIZE;
	processor_data->hdbuf_ptr = processor_data->hdbuf_base;
	processor_data->tmpbuf_base = processor_data->hdbuf_base + PER_CPU_HEAD_BUF_SIZE;
	processor_data->tmpbuf_ptr = processor_data->tmpbuf_base;

	DbgPrint("[Allocation] Processors. cpu %d, buf_base %08x, hdbuf_base %08x, tmpbuf_base %08x.\n",
		cpu_num, processor_data->buf_base, processor_data->hdbuf_base, processor_data->tmpbuf_base);

	return STATUS_SUCCESS;
}

PVOID AllocateFromUserSpaceCache(SIZE_T size)
{
	PVOID allocAddr = NULL;

	KeAcquireGuardedMutex(&g_allocMutex);

	if (((ULONG_PTR)g_alloc_code_ptr + size) > ((ULONG_PTR)g_alloc_code_base + CACHE_CODE_TABLE_SIZE))
	{
		DbgPrint("AllocateFromUserSpaceCache, alloc_code_ptr %x, alloc_code_base %x, g_exec_count %u %u.\n", 
			g_alloc_code_ptr, g_alloc_code_base, g_exec_count, g_exec_count2);
		HYPERPLATFORM_COMMON_DBG_BREAK();
		KeReleaseGuardedMutex(&g_allocMutex);
		ZwTerminateProcess(NtCurrentProcess(), 1);	
		//Unhandled...
	}
	allocAddr = g_alloc_code_ptr;
	g_alloc_code_ptr = (PVOID)((ULONG_PTR)g_alloc_code_ptr + size);

	KeReleaseGuardedMutex(&g_allocMutex);

	return allocAddr;
}

PVOID AllocRedirectPageFromUserSpaceCache(SIZE_T size)
{
	PVOID allocAddr = NULL;

	KeAcquireGuardedMutex(&g_rdAllocMutex);

	if (((ULONG_PTR)g_rdAllocPtr + size) > ((ULONG_PTR)g_rdAllocBase + RD_ALLOCATE_SIZE))
	{
		//Unhandled...
		DbgPrint("AllocRedirectPageFromUserSpaceCache, space is not enough.\n");
		HYPERPLATFORM_COMMON_DBG_BREAK();
		KeReleaseGuardedMutex(&g_allocMutex);
		ZwTerminateProcess(NtCurrentProcess(), 1);
	}
	allocAddr = g_rdAllocPtr;
	g_rdAllocPtr = (PVOID)((ULONG_PTR)g_rdAllocPtr + size);

	KeReleaseGuardedMutex(&g_rdAllocMutex);

	return allocAddr;
}

void __stdcall InitCodePageInterception(ULONG vfn, ULONG64 old_pa)
{
	PVOID    startVa = (PVOID)(vfn << 12);
	ULONG64  pa = old_pa;
	if ((old_pa & 0x7ull) != 0x7ull)
	{
		ULONG w = *(ULONG *)startVa;
		ULONG size = PAGE_SIZE;
		ULONG oldProt;
		__invlpg(startVa);
		ULONG_PTR pteAddr = 0xc0000000 + (((ULONG)startVa >> 9) & 0x7ffff8);
		pa = *(ULONG64 *)pteAddr;
	}

	PVOID  allocBase = AllocateFromUserSpaceCache(PAGE_SIZE * 4);
	for (ULONG i = 0; i < PAGE_SIZE; i++)
	{
		((PULONG)allocBase)[i] = ((ULONG)startVa & 0xFFFFF000) + i; 
	}
	InterlockedExchange((LONG *)(g_code_table + vfn), (LONG)allocBase);

	EptPtEntry *ept_entry = (EptPtEntry *)EptGetEptPtEntry(g_shared_data->ept_data_list[EPTP_MONITOR1], pa);
	ept_entry->fields.execute_access = 0;
	DbgPrint("InitCodePageInterception. va %08x, pa %llx -> %llx\n", startVa, old_pa, pa);
}

void __stdcall RedirectCodePage(ULONG pte_addr, ULONG64 old_pa)
{
	ULONG   vfn = (pte_addr - 0xC0000000) >> 3;
	ULONG   va = vfn << 12;
	PMMPFN  p_mmpfn = (PMMPFN)(g_MmPfnDatabase + (old_pa >> 12) * 0x1C);
	ULONG64 pa = old_pa;

	if (p_mmpfn->PteAddress != (PVOID)pte_addr)
	{
		PVOID  codePage = g_code_table[vfn];
		if (((ULONG)codePage & 0xFFF00000) == ANALYSIS_CODE_FAULT_BASE)
		{
			codePage = AllocateFromUserSpaceCache(PAGE_SIZE * 4);
			for (ULONG i = 0; i < PAGE_SIZE; i++)
			{
				((PULONG)codePage)[i] = (va & 0xFFFFF000) + i;
			}
			g_code_table[vfn] = codePage;	
			g_exec_count++;
		}
		//2
		PVOID new_va = ExAllocatePoolWithTag(NonPagedPoolExecute, PAGE_SIZE,
			kHyperPlatformCommonPoolTag);
		if (!new_va)
		{
			HYPERPLATFORM_LOG_DEBUG("[CHECK] code_map alloc error. %x", vfn);
		}
		RtlCopyMemory(new_va, (PVOID)va, PAGE_SIZE);
		//3
		g_redirect_table[vfn].OldPa = (ULONG)old_pa;
		g_redirect_table[vfn].KernelVa = new_va;
		//4
		ULONG64 new_pa = *(ULONG64 *)(0xC0000000 + (((ULONG)new_va >> 9) & 0x7ffff8));
		PMMPFN p_new_mmpfn = (PMMPFN)(g_MmPfnDatabase + (new_pa >> 12) * 0x1C);
		p_new_mmpfn->OriginalPte.Protection = 6;   
		p_new_mmpfn->u4.PrototypePte = 1;         
		p_new_mmpfn->WsIndex = p_mmpfn->WsIndex;  
		pa = (new_pa & 0x7FFFFFFFFFFFF000ull) | 0x25;
		*(ULONG64 *)pte_addr = pa;
		//*(ULONG64 *)pte_addr = new_pa;
		__invlpg((PVOID)va);
		//DbgPrint("RedirectCodePage share. va %x - > %x, pa %llx -> %llx, p_new_mmpfn %x\n", 
		//	va, new_va, old_pa, pa, p_new_mmpfn);
	}
	EptPtEntry *ept_entry = (EptPtEntry *)EptGetEptPtEntry(g_shared_data->ept_data_list[EPTP_MONITOR1], pa);
	if (!ept_entry)
	{
		HYPERPLATFORM_LOG_DEBUG("[CHECK] RedirectCodePage error, entry does not exist. %llx", pa);
	}
	//DbgPrint("RedirectCodePage. va %x, pa %llx -> %llx, ept_entry1 %x\n", va, old_pa, pa, ept_entry);
	//if (pa & 0x2)
	//{
	//	ept_entry->fields.write_access = 0;
	//	//DbgPrint("RedirectCodePage write. va %x, pa %llx -> %llx\n", va, old_pa, pa);
	//}
	ept_entry->fields.execute_access = 0;
	KeIpiGenericCall(&IpiEptMonitorUpdatePage, (ULONG)va);
}

ULONG __stdcall MyMmCreateTebHandler(PEPROCESS eprocess)
{
	if (!g_target_eprocess)
	{
		CHAR *pProcName = PsGetProcessImageFileName(eprocess);
		if (!_strnicmp(pProcName, "7z.exe", 7))
		{
			g_target_eprocess = eprocess;
			return 1;
		}
	}
	else if (g_target_eprocess == eprocess)
	{
		return 2;
	}

	return 0;
}

void ProcessNotifyRoutineEx(
	PEPROCESS pEprocess,
	HANDLE ProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	NTSTATUS  status;

	CHAR *pProcName = PsGetProcessImageFileName(pEprocess);

	if (g_target_eprocess == pEprocess)
	{
		if (CreateInfo != NULL)
		{
			g_target_pid = ProcessId;
			//g_target_eprocess = pEprocess;
			ULONG  ulPhyDirBase = *(ULONG *)((PCHAR)pEprocess + 0x18);
			g_target_cr3 = ulPhyDirBase;
			DbgPrint("\nTarget process create, Time(ms): %u, pid: %x, EPROCESS: %x, name: %s\n",
				QueryTimeMillisecond(), ProcessId, pEprocess, pProcName);
			auto vmcall_status = UtilVmCall(HypercallNumber::kGetSharedProcessorData, &g_shared_data);
			if (!NT_SUCCESS(vmcall_status))
			{
				DbgPrint("UtilVmCall: kGetSharedProcessorData error.");
			}
			DbgPrint("UtilVmCall: kGetSharedProcessorData, addr %x\n", g_shared_data);
			if (g_monitor_start)
			{	
				//8MB
				g_alloc_pd_base = ExAllocatePoolWithTag(NonPagedPool, 2 * PAGE_SIZE, kHyperPlatformCommonPoolTag);
				if (!g_alloc_pd_base)
				{
					HYPERPLATFORM_LOG_DEBUG("ExAllocatePoolWithTag g_alloc_pd_base error.");
				}
				memset(g_alloc_pd_base, 0, 2 * PAGE_SIZE);
				g_alloc_pt_base = ExAllocatePoolWithTag(NonPagedPool, 2 * 512 * PAGE_SIZE, kHyperPlatformCommonPoolTag);
				if (!g_alloc_pt_base)
				{
					HYPERPLATFORM_LOG_DEBUG("ExAllocatePoolWithTag g_alloc_pt_base error.");
				}
				memset(g_alloc_pt_base, 0, 2 * 512 * PAGE_SIZE);
				g_alloc_pt_ptr = g_alloc_pt_base;

				KAPC_STATE kApc;
				KeStackAttachProcess(pEprocess, &kApc); 
				StartEptMonitor32(ulPhyDirBase);
				KeUnstackDetachProcess(&kApc);

				auto status = UtilForEachProcessor(AllocateExecutePageProcessorsUser, ProcessId);
				if (NT_SUCCESS(status))
				{
					HYPERPLATFORM_LOG_DEBUG("AllocateExecutePageProcessors success.");
				}
				else
				{
					HYPERPLATFORM_LOG_DEBUG("AllocateExecutePageProcessors error (%08x).", status);
				}

				//16MB
				g_entries_base = ExAllocatePoolWithTag(NonPagedPool, BUFFER_ENTRY_SIZE, kHyperPlatformCommonPoolTag);
				if (!g_entries_base)
				{
					HYPERPLATFORM_LOG_DEBUG("ExAllocatePoolWithTag g_entries_base error (%08x).", status);
				}
				//2MB
				g_entry_table = (PVOID *)ExAllocatePoolWithTag(NonPagedPool, 0x80000 * 4, kHyperPlatformCommonPoolTag);
				if (!g_entry_table)
				{
					HYPERPLATFORM_LOG_DEBUG("ExAllocatePoolWithTag g_entry_table error (%08x).", status);
				}
				memset(g_entry_table, 0, 0x80000 * 4);
				g_entries_ptr = g_entries_base;
				InitializeListHead(&g_entries_list);
				KeInitializeSpinLock(&g_entries_lock);
				InitializeListHead(&g_free_entries_list);
				KeInitializeSpinLock(&g_free_entries_lock);
	
				//attach
				KeStackAttachProcess(pEprocess, &kApc);
				g_code_table = (PVOID *)AllocateFromUserspace(ProcessId, MAPPING_TABLE_SIZE);
				for (ULONG i = 0; i < MAPPING_TABLE_SIZE; i += PAGE_SIZE)
				{
					ULONG va = (ULONG)g_code_table + i;
					g_page_state[va >> 12] = 1;
				}
				//memset(g_code_table, 0, MAPPING_TABLE_SIZE);
				for (ULONG i = 0; i < MAPPING_TABLE_SIZE / 4; i++)
				{
					((PULONG)g_code_table)[i] = ANALYSIS_CODE_FAULT_BASE + i;
				}
				g_code_table_mdl = IoAllocateMdl(g_code_table, MAPPING_TABLE_SIZE, FALSE, FALSE, NULL);
				__try
				{
					MmProbeAndLockPages(g_code_table_mdl, UserMode, IoWriteAccess);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Lock code_table_mdl error code = %x", GetExceptionCode());
					__debugbreak();
				}
				g_alloc_code_base = (PVOID *)AllocateFromUserspace(ProcessId, CACHE_CODE_TABLE_SIZE);
				for (ULONG i = 0; i < CACHE_CODE_TABLE_SIZE; i += PAGE_SIZE)
				{
					ULONG va = (ULONG)g_alloc_code_base + i;
					g_page_state[va >> 12] = 1;
				}
				memset(g_alloc_code_base, 0, CACHE_CODE_TABLE_SIZE);
				g_alloc_code_ptr = g_alloc_code_base;
				g_alloc_code_mdl = IoAllocateMdl(g_alloc_code_base, CACHE_CODE_TABLE_SIZE, FALSE, FALSE, NULL);
				__try
				{
					MmProbeAndLockPages(g_alloc_code_mdl, UserMode, IoWriteAccess);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("Lock alloc_code_base error code = %x", GetExceptionCode());
					__debugbreak();
				}

				ULONG entry_count = 0;
				for (ULONG i = 0; i < CACHE_STATE_ALLOCATE_NUM; i++)
				{
					PVOID localAllocBase = (PVOID *)AllocateFromUserspace(ProcessId, CACHE_STATE_ALLOCATE_SIZE);
					memset(localAllocBase, 0, CACHE_STATE_ALLOCATE_SIZE);
					g_alloc_state_base[g_alloc_state_count] = localAllocBase;
					g_alloc_state_mdl[g_alloc_state_count] = IoAllocateMdl(localAllocBase, CACHE_STATE_ALLOCATE_SIZE, FALSE, FALSE, NULL);
					__try
					{
						MmProbeAndLockPages(g_alloc_state_mdl[g_alloc_state_count], UserMode, IoWriteAccess);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						DbgPrint("Lock g_alloc_state_mdl error code = %x", GetExceptionCode());
						__debugbreak();
					}
					g_alloc_state_count++;
					for (ULONG size = 0; size < CACHE_STATE_ALLOCATE_SIZE; size += PAGE_SIZE)
					{
						BUFFER_ENTRY *node = (BUFFER_ENTRY *)g_entries_ptr;
						node->Address = (PVOID)((ULONG)localAllocBase + size);
						node->MappedVa = NULL;
						AnalysisConstructMapEntry((ULONG)node->Address);
						InsertTailList(&g_entries_list, &node->ListEntry);
						g_entries_ptr = (PVOID)((ULONG)g_entries_ptr + sizeof(BUFFER_ENTRY));
						entry_count++;

						ULONG va = (ULONG)node->Address;
						g_page_state[va >> 12] = 1;
					}
				}
				g_overflow_entry = (BUFFER_ENTRY *)RemoveHeadList(&g_entries_list);
				
				for (ULONG i = 0; i < g_init_map_num; i++)
				{
					ULONG   va = g_process_init_map_va[i] << 12;
					ULONG64 pa = g_process_init_map_pa[i];
					AnalysisAllocateMapEntry(va, pa);
				}

				for (ULONG i = 0; i < g_init_page_num; i++)
				{
					InitCodePageInterception(g_process_init_va[i], g_process_init_pa[i]);
				}

				ProcessorData *processor_data = processor_list[KeGetCurrentProcessorNumber()];
				g_faultCodePage = processor_data->buf_ptr;
				processor_data->buf_ptr += PAGE_SIZE;
				g_checkCodePage = processor_data->buf_ptr;
				processor_data->buf_ptr += PAGE_SIZE;
				PHYSICAL_ADDRESS pa = MmGetPhysicalAddress((PVOID)g_faultCodePage);
				EptPtEntry *ept_entry = (EptPtEntry *)EptGetEptPtEntry(g_shared_data->ept_data_list[EPTP_MONITOR1], pa.QuadPart);
				ept_entry->fields.execute_access = 0;
				ept_entry = (EptPtEntry *)EptGetEptPtEntry(g_shared_data->ept_data_list[EPTP_ANALYSIS], pa.QuadPart);
				ept_entry->fields.execute_access = 0;

				pa = MmGetPhysicalAddress((PVOID)g_checkCodePage);
				ept_entry = (EptPtEntry *)EptGetEptPtEntry(g_shared_data->ept_data_list[EPTP_MONITOR1], pa.QuadPart);
				ept_entry->fields.read_access = 0; 
				ept_entry->fields.write_access = 0;
				ept_entry = (EptPtEntry *)EptGetEptPtEntry(g_shared_data->ept_data_list[EPTP_ANALYSIS], pa.QuadPart);
				ept_entry->fields.read_access = 0; 
				ept_entry->fields.write_access = 0;

				UCHAR *stubCode = (UCHAR *)processor_data->asbuf_ptr;
				processor_data->asbuf_ptr += PAGE_SIZE;
				g_retCodeProfiler = (BLOCK_PROFILER *)processor_data->hdbuf_ptr;
				processor_data->hdbuf_ptr += sizeof(BLOCK_PROFILER);
				*(UINT8 *)stubCode = 0xC3;       //ret
				g_retCodeProfiler->AnalysisCodePtr = (PVOID)stubCode;
			
				DbgPrint("[Allocation] code_table %x, code_alloc_base %x, state_buffer_entries %u, cache_size %x,\n"
					"num %u, g_retCodeProfiler %x, g_faultCodePage %x, g_checkCodePage %x,\n"
					"g_alloc_pd_base %x, g_alloc_pt_base %x, g_overflow_entry %x.\n",
					g_code_table, g_alloc_code_base, entry_count, CACHE_STATE_ALLOCATE_SIZE, CACHE_STATE_ALLOCATE_NUM,
					g_retCodeProfiler, g_faultCodePage, g_checkCodePage, g_alloc_pd_base, g_alloc_pt_base, g_overflow_entry);

				//detach
				KeUnstackDetachProcess(&kApc);
					
				g_shared_data->target_pid = (ULONG)ProcessId;
				g_target_active = true;
				
				KeIpiGenericCall(&IpiEptToMonitor, 0);
				g_start_time = QueryTimeMillisecond();

				LARGE_INTEGER currTime;
				LARGE_INTEGER localTime;
				TIME_FIELDS  timeFields;
				KeQuerySystemTime(&currTime);
				ExSystemTimeToLocalTime(&currTime, &localTime);
				RtlTimeToTimeFields(&localTime, &timeFields);

				DbgPrint("Target analysis Start, Time(ms): %u ms, %u:%u:%u.\n\n", 
					g_start_time, timeFields.Hour, timeFields.Minute, timeFields.Milliseconds);

			}
		}
		else
		{
			g_target_active = false;
			ULONG finishTime = QueryTimeMillisecond();
			DbgPrint("\nTarget process exit, Time(ms): %u, elapsed: %u ms, pid %x, name %s, thread %u, module %u\n"
				"execute_page %u %u, alloc %u - free %u recycle %u overflow %u, g_pt_map_count %u\n",
				finishTime, finishTime - g_start_time, ProcessId, pProcName, 
				g_thread_count, g_module_count, g_exec_count, g_exec_count2, g_sb_alloc_count,
				g_sb_free_count, g_sb_recycle_count, g_sb_overflow_count, g_pt_map_count);

			KeWaitForSingleObject(&g_athread_event, Executive, KernelMode, FALSE, NULL);
			DbgPrint("\nReceive notification exit, Time(ms): %u\n", QueryTimeMillisecond());

			KeIpiGenericCall(&IpiEptToNormal, 0);
			//HYPERPLATFORM_COMMON_DBG_BREAK();
			
			//Release
			ULONG tableCount = 0;
			if (g_code_table)
			{
				tableCount = 0;
				for (ULONG i = 0; i < 0x80000; i++)
				{
					//if ((ULONG)g_code_table[i] != NULL)
					if (((ULONG)g_code_table[i] & 0xFFF00000) != ANALYSIS_CODE_FAULT_BASE)
					{
						tableCount++;
					}
				}
				//Unlock
				MmUnlockPages(g_code_table_mdl);
				IoFreeMdl(g_code_table_mdl);
				SIZE_T ReginSize = 0;
				ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&g_code_table, &ReginSize, MEM_RELEASE);
				DbgPrint(" Free g_code_table, mapped page count %d\n", tableCount);
			}
			auto status = UtilForEachProcessor(OutputProcessorCounter, g_target_pid);
			if (NT_SUCCESS(status)) {
				DbgPrint("OutputProcessorCounter success.\n");
			}
			else {
				DbgPrint("OutputProcessorCounter error (%08x).\n", status);
			}
			DbgPrint(" Total c0 %llu, c1 %llu, c2 %llu, c3 %llu, c4 %llu, c5 %llu, c6 %llu, buf_used %llu - %llu\n", 
				g_total_counter[0], g_total_counter[1], 
				g_total_counter[2], g_total_counter[3], 
				g_total_counter[4], g_total_counter[5], g_total_counter[6], 
				g_total_counter[7], g_total_counter[8]);
			
			/*ULONG freeAllocCount = 0;
			for (ULONG i = 0; i < 0x80000; i++)
			{
				BUFFER_ENTRY *entry = (BUFFER_ENTRY *)g_entry_table[i];
				if (entry && (entry->MappedVa & 2))
				{
					ULONG  base = entry->MappedVa & 0xFFFFF000;
					SIZE_T size = PAGE_SIZE;
					NtFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&base, &size, MEM_RELEASE);
					freeAllocCount++;
				}
			}
			DbgPrint("[NtFreeVirtualMemory] allocated address, count %u.\n", freeAllocCount);*/

			for (ULONG i = 0; i < 0x80000; i++)
			{
				ULONG old_pa = g_redirect_table[i].OldPa;
				PVOID new_va = g_redirect_table[i].KernelVa;
				if (old_pa)
				{
					ULONG old_va = i << 12;
					ULONG pte_addr = 0xC0000000 + (old_va >> 9);
					*(ULONG *)pte_addr = old_pa;
					__invlpg((PVOID)old_va);
					ULONG new_pa = *(ULONG *)(0xC0000000 + (((ULONG)new_va >> 9) & 0x7ffff8));
					PMMPFN  p_new_mmpfn = (PMMPFN)(g_MmPfnDatabase + (new_pa >> 12) * 0x1C);
					//DbgPrint(" old_va %x, old_pa %x. new_va %x, new_pa %x, p_new_mmpfn %x\n",
					//	old_va, old_pa, new_va, new_pa, p_new_mmpfn);
					//Restore mmpfn
					p_new_mmpfn->u4.PrototypePte = 0;
					p_new_mmpfn->ShareCount = 1;
					p_new_mmpfn->e1 = (p_new_mmpfn->e1 & 8) | 6;
					p_new_mmpfn->ReferenceCount = 1;
					ExFreePoolWithTag(new_va, kHyperPlatformCommonPoolTag);
					//
					g_redirect_table[i].OldPa = 0;
					g_redirect_table[i].KernelVa = 0;
				}
			}

			ExFreePoolWithTag(g_alloc_pd_base, kHyperPlatformCommonPoolTag);
			ExFreePoolWithTag(g_alloc_pt_base, kHyperPlatformCommonPoolTag);
			ExFreePoolWithTag(g_entries_base, kHyperPlatformCommonPoolTag);
			ExFreePoolWithTag(g_entry_table, kHyperPlatformCommonPoolTag);

			MmUnlockPages(g_alloc_code_mdl);
			IoFreeMdl(g_alloc_code_mdl);
			SIZE_T ReginSize = CACHE_CODE_TABLE_SIZE;
			ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)g_alloc_code_base, &ReginSize, MEM_RELEASE);
			for (ULONG i = 0; i < g_alloc_state_count; i++)
			{
				MmUnlockPages(g_alloc_state_mdl[i]);
				IoFreeMdl(g_alloc_state_mdl[i]);
				SIZE_T ReginSize = CACHE_STATE_ALLOCATE_SIZE;
				ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&g_alloc_state_base[i], &ReginSize, MEM_RELEASE);
			}	
			
			g_target_cr3 = 0;
			g_target_pid = (HANDLE)-1;
			g_target_eprocess = NULL;
		}
	}
}

VOID CreateThreadNotifyRoutineEx(
	HANDLE ProcessId,
	HANDLE ThreadId,
	BOOLEAN Create)
{
	if (g_target_pid == ProcessId)
	{
		thread_ctx_t *p_thread_ctx = NULL;
		PETHREAD   p_thread = NULL;
		PUCHAR     p_teb = NULL;
		PHYSICAL_ADDRESS pa;
		p_thread = PsGetCurrentThread();
		p_teb = (PUCHAR)*(ULONG *)((PUCHAR)p_thread + 0xa8);
		if (Create)
		{
			DbgPrint("[ThreadNotifyRoutine] create, tid %d, pid %d\n", ThreadId, ProcessId);
			p_thread_ctx = (thread_ctx_t *)ExAllocatePoolWithTag(NonPagedPool, sizeof(thread_ctx_t), kHyperPlatformCommonPoolTag);
			if (!p_thread_ctx)
			{
				DbgPrint("[CHECK] thread created: allcate error.\n");
				return;
			}
			RtlZeroMemory(p_thread_ctx, sizeof(thread_ctx_t));

			p_thread_ctx->ethread = p_thread;
			p_thread_ctx->tid = (ULONG)ThreadId;
			p_thread_ctx->st_info.base = *(ULONG *)(p_teb + 4);
			p_thread_ctx->st_info.limit = *(ULONG *)(p_teb + 8);
			p_thread_ctx->teb = (ULONG)p_teb;

			InitializeListHead(&p_thread_ctx->free_list.listhead);
			KeInitializeSpinLock(&p_thread_ctx->free_list.spinlock);
			KeInitializeSemaphore(&p_thread_ctx->free_list.semaphore, 0, 0x7FFFFFFF);
			InitializeListHead(&p_thread_ctx->full_list.listhead);
			KeInitializeSpinLock(&p_thread_ctx->full_list.spinlock);
			KeInitializeSemaphore(&p_thread_ctx->full_list.semaphore, 0, 0x7FFFFFFF);
			//LOG_ALLOCATE_SIZE
			p_thread_ctx->record_buffer = ExAllocatePoolWithTag(NonPagedPool, LOG_BLOCK_NUM*LOG_BLOCK_SIZE,
				kHyperPlatformCommonPoolTag);
			if (!p_thread_ctx->record_buffer)
			{
				ExFreePoolWithTag(p_thread_ctx, kHyperPlatformCommonPoolTag);
				DbgPrint("[CHECK] IOCTL_THREAD_CREATED: allcate record_buffer error.\n");
				return;
			}
			//kva
			for (ULONG size = 0; size < LOG_BLOCK_NUM*LOG_BLOCK_SIZE; size += PAGE_SIZE)
			{
				ULONG pageVa = (ULONG)p_thread_ctx->record_buffer + size;
				ULONG pPDE = 0xc0600000 + (((ULONG)pageVa >> 18) & 0x3ff8);
				ULONG pPTE = 0xc0000000 + (((ULONG)pageVa >> 9) & 0x7ffff8);
				*(ULONG *)pPDE = *(ULONG *)pPDE | 0x4;
				*(ULONG *)pPTE = *(ULONG *)pPTE | 0x4;
				__invlpg((PVOID)pageVa);
			}
			/*for (ULONG i = 0; i < LOG_BLOCK_NUM; i++)
			{
				ULONG guard_page = (ULONG)p_thread_ctx->record_buffer + i*LOG_BLOCK_SIZE;
				pa = MmGetPhysicalAddress((PVOID)guard_page);
				UpdateEptEntry(g_shared_data->ept_data_list[EPTP_MONITOR1], pa.QuadPart, 0);
				p_thread_ctx->guard_pa[i] = pa.QuadPart;
				p_thread_ctx->list_element[i].base = (PVOID)((ULONG)p_thread_ctx->record_buffer + (i + 1)*LOG_BLOCK_SIZE);
				InsertTailList(&p_thread_ctx->free_list.listhead, &p_thread_ctx->list_element[i].entry);
			}*/	
			for (ULONG i = 0; i < LOG_BLOCK_NUM; i++)
			{	
				p_thread_ctx->list_element[i].base = (PVOID)((ULONG)p_thread_ctx->record_buffer + i*LOG_BLOCK_SIZE + PAGE_SIZE);
				ULONG guard_page = (ULONG)p_thread_ctx->record_buffer + (i+1)*LOG_BLOCK_SIZE - PAGE_SIZE;
				p_thread_ctx->list_element[i].limit = (PVOID)guard_page;
				pa = MmGetPhysicalAddress((PVOID)guard_page);
				UpdateEptEntry(g_shared_data->ept_data_list[EPTP_MONITOR1], pa.QuadPart, 0);
				p_thread_ctx->guard_pa[i] = pa.QuadPart;

				InsertTailList(&p_thread_ctx->free_list.listhead, &p_thread_ctx->list_element[i].entry);
				
				//PHYSICAL_ADDRESS pa1 = MmGetPhysicalAddress(p_thread_ctx->list_element[i].base);
				//DbgPrint(" [tid %d, guard_page %x, pa %llx, base %x, %llx]\n", 
				//	ThreadId, guard_page, pa.QuadPart, p_thread_ctx->list_element[i].base, pa1);
			}
			KeIpiGenericCall(&IpiEptMonitorSetGuardPages, 0);

			*(ULONG *)(p_teb + PAGE_SIZE) = 0;
			p_thread_ctx->teb_extend_mdl = IoAllocateMdl(p_teb + PAGE_SIZE, PAGE_SIZE, FALSE, FALSE, NULL);
			__try
			{
				MmProbeAndLockPages(p_thread_ctx->teb_extend_mdl, UserMode, IoWriteAccess);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrint("Lock teb_extend_mdl error code = %x", GetExceptionCode());
				__debugbreak();
			}
			p_thread_ctx->teb_extend_va = MmMapLockedPagesSpecifyCache(p_thread_ctx->teb_extend_mdl,
				KernelMode, MmCached, NULL, FALSE, NormalPagePriority);	

			//DPC & APC
			KeInitializeDpc(&p_thread_ctx->dpc_c, DpcContextSwitchBuffer, p_thread_ctx);
			KeInitializeDpc(&p_thread_ctx->dpc_f, DpcFaultSwitchBuffer, p_thread_ctx);
			KeSetImportanceDpc(&p_thread_ctx->dpc_c, HighImportance);
			KeSetImportanceDpc(&p_thread_ctx->dpc_f, HighImportance);
			KeInitializeApc(&p_thread_ctx->apc_f, p_thread, OriginalApcEnvironment, ApcKernelRoutine,
				NULL, ApcFaultRequireBuffer, KernelMode, p_thread_ctx);
			KeInitializeEvent(&p_thread_ctx->in_buffer_event, SynchronizationEvent, FALSE);
			KeInitializeEvent(&p_thread_ctx->exit_event, NotificationEvent, FALSE);
			NTSTATUS status = PsCreateSystemThread(&p_thread_ctx->athread_handle, THREAD_ALL_ACCESS,
				NULL, NULL, NULL, (PKSTART_ROUTINE)AssistedAnalysisThread, p_thread_ctx);
			//Aided stack
			p_thread_ctx->check_buffer = AllocateFromUserSpaceCache(2*PAGE_SIZE);
			for (ULONG i = 0; i < 2; i++)
			{
				ULONG va = (ULONG)p_thread_ctx->check_buffer + i * PAGE_SIZE;
				AnalysisConstructMapEntry(va);
			}	
			p_thread_ctx->check_ptr = p_thread_ctx->check_buffer;
			//set
			p_thread_ctx->set_buffer = AllocateFromUserSpaceCache(2 * PAGE_SIZE);
			for (ULONG i = 0; i < 2; i++)
			{
				ULONG va = (ULONG)p_thread_ctx->set_buffer + i * PAGE_SIZE;
				AnalysisConstructMapEntry(va);
			}
			p_thread_ctx->set_ptr = p_thread_ctx->set_buffer;

			p_thread_ctx->ctx_state = AllocateFromUserSpaceCache(PAGE_SIZE);
			AnalysisConstructMapEntry((ULONG)p_thread_ctx->ctx_state);

			PVOID teb_sva = NULL;
			PHYSICAL_ADDRESS teb_spa = { 0 };
			BUFFER_ENTRY *teb_entry = (BUFFER_ENTRY *)g_entry_table[(ULONG)p_teb >> 12];
			if (!teb_entry)
			{
				pa = MmGetPhysicalAddress((PVOID)p_teb);
				AnalysisAllocateMapEntry((ULONG)p_teb, pa.LowPart);

				//teb_sva = AllocateFromUserSpaceBufferEntries((ULONG)p_teb);
				//teb_spa = MmGetPhysicalAddress(teb_sva);
				//pa = MmGetPhysicalAddress((PVOID)p_teb);
				//auto ept_entry = EptGetEptPtEntry(g_shared_data->ept_data_list[EPTP_ANALYSIS], pa.QuadPart);
				//ept_entry->fields.physial_address = teb_spa.QuadPart >> 12;
			}
			else
			{
				teb_sva = teb_entry->Address;
				//DbgPrint("teb_entry existed %x\n", teb_entry);
			}
	
			p_thread_ctx->in_buffer = (LIST_ELEMENT *)RemoveHeadList(&p_thread_ctx->free_list.listhead);
			*(ULONG *)p_thread_ctx->teb_extend_va = (ULONG)p_thread_ctx->in_buffer->base;
			KeReleaseSemaphore(&p_thread_ctx->free_list.semaphore, IO_NO_INCREMENT, LOG_BLOCK_NUM - 1, FALSE);

			DbgPrint(" [%d thread_ctx %x, stack %x - %x, ethread %x, teb %x --> %x %llx, teb_ext_va %x, in_buffer %x, ff_list %x %x]\n",
				ThreadId, p_thread_ctx, p_thread_ctx->st_info.base, p_thread_ctx->st_info.limit, p_thread,
				p_thread_ctx->teb, teb_sva, teb_spa.QuadPart, p_thread_ctx->teb_extend_va, p_thread_ctx->in_buffer,
				&p_thread_ctx->full_list, &p_thread_ctx->free_list);

			*(ULONG_PTR *)((PUCHAR)p_thread + CTX_OFFSET) = (ULONG_PTR)p_thread_ctx;
			//p_thread_ctx->start = 1; //old
			g_thread_count++;
		}
		else
		{
			DbgPrint("[ThreadNotifyRoutine] exit. %d, time %u\n", ThreadId, QueryTimeMillisecond());
			p_thread_ctx = (thread_ctx_t *)*(ULONG_PTR *)((PUCHAR)PsGetCurrentThread() + CTX_OFFSET);
			if (p_thread_ctx)
			{
				p_thread_ctx->is_last = 1;

				ULONG  lastBufPtr = *(ULONG *)p_thread_ctx->teb_extend_va;
				p_thread_ctx->in_buffer->curr = (PVOID)lastBufPtr;
				p_thread_ctx->in_buffer->real = p_thread_ctx->in_buffer->curr;
				DbgPrint(" %d [teb_extend_va %x, in_buffer %x, base %x, real %x, Flink %x\n", 
					ThreadId, p_thread_ctx->teb_extend_va, p_thread_ctx->in_buffer, p_thread_ctx->in_buffer->base,
					p_thread_ctx->in_buffer->real, p_thread_ctx->in_buffer->entry.Flink);

				if (p_thread_ctx->in_buffer->entry.Flink == NULL)
				{		
					ExInterlockedInsertTailList(&p_thread_ctx->full_list.listhead, &p_thread_ctx->in_buffer->entry,
						&p_thread_ctx->full_list.spinlock);
					KeReleaseSemaphore(&p_thread_ctx->full_list.semaphore, IO_NO_INCREMENT, 1, FALSE);
				}

				KeWaitForSingleObject(&p_thread_ctx->free_list.semaphore, Executive, KernelMode, FALSE, NULL);
				p_thread_ctx->in_buffer = (LIST_ELEMENT *)ExInterlockedRemoveHeadList(&p_thread_ctx->free_list.listhead,
					&p_thread_ctx->free_list.spinlock);
				//RET profiler
				lastBufPtr = (ULONG)p_thread_ctx->in_buffer->base;
				*(ULONG *)(lastBufPtr) = (ULONG)g_retCodeProfiler; 
				p_thread_ctx->in_buffer->curr = (PVOID)(lastBufPtr + 4);
				p_thread_ctx->in_buffer->real = p_thread_ctx->in_buffer->curr;
				DbgPrint(" %d [final in_buffer %x, base %x, real %x\n", ThreadId, p_thread_ctx->in_buffer, 
					p_thread_ctx->in_buffer->base, p_thread_ctx->in_buffer->real);
				ExInterlockedInsertTailList(&p_thread_ctx->full_list.listhead, &p_thread_ctx->in_buffer->entry,
					&p_thread_ctx->full_list.spinlock);
				KeReleaseSemaphore(&p_thread_ctx->full_list.semaphore, IO_NO_INCREMENT, 1, FALSE);

				//Unlock
				MmUnmapLockedPages(p_thread_ctx->teb_extend_va, p_thread_ctx->teb_extend_mdl);
				MmUnlockPages(p_thread_ctx->teb_extend_mdl);
				IoFreeMdl(p_thread_ctx->teb_extend_mdl);

				p_thread_ctx->start = 0;
				p_thread_ctx->is_exit = 1;
				//clean
				KeSetEvent(&p_thread_ctx->exit_event, IO_NO_INCREMENT, FALSE);
				*(ULONG_PTR *)((PUCHAR)p_thread + CTX_OFFSET) = NULL;
			}
		}
	}
	return;
}

VOID WPOFF()
{
	ULONG_PTR cr0 = 0;
	cr0 = __readcr0();
	cr0 &= ~0x10000ull;
	__writecr0(cr0);
}

VOID WPON()
{
	ULONG_PTR cr0 = __readcr0();
	cr0 |= 0x10000;
	__writecr0(cr0);
}

VOID LoadImageNotifyCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO pImageInfo)
{
	PEPROCESS           Process;
	UNICODE_STRING		ustrFileName;
	HANDLE              ProcessHandle = NULL;
	NTSTATUS            status;
	WCHAR               pwDupName[260];

	if (!FullImageName || !FullImageName->Length || ProcessId == (HANDLE)0 ||
		ProcessId == (HANDLE)4 || pImageInfo->SystemModeImage)
		return;

	if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
	{
		PCHAR ProcessName = (PCHAR)PsGetProcessImageFileName(Process);

		if (ProcessName && (g_target_pid == ProcessId))
		{
			g_module_count++;
			//KdPrint(("[TARGET] Process: %d, Addr: %x, Image: %wZ\n", ProcessId, pImageInfo->ImageBase, FullImageName));
			DbgPrint("[TARGET] Process: %d, Addr: %x, Image: %wZ\n", ProcessId, pImageInfo->ImageBase, FullImageName);
			memcpy(pwDupName, FullImageName->Buffer, FullImageName->Length);
			WCHAR *pwlwrDupName = _wcslwr(pwDupName);
			if (0 == _wcsnicmp(FullImageName->Buffer, L"\\SystemRoot\\System32\\ntdll.dll", sizeof("\\SystemRoot\\System32\\ntdll.dll") * 2))
			{
				g_ntdll_base = (ULONG)pImageInfo->ImageBase;
			}
			else if (wcsstr(pwlwrDupName, L"\\system32\\user32.dll"))
			{
				g_user32_base = (ULONG)pImageInfo->ImageBase;
			}
			else if (wcsstr(pwlwrDupName, L"\\system32\\kernelbase.dll"))
			{
				g_kernel_base = (ULONG)pImageInfo->ImageBase;
				//DbgPrint(" Get Image: %wZ\n", FullImageName);
				//output_flag = 1;
				//g_module_addr[0] = (ULONG)pImageInfo->ImageBase;
			}
			else if (wcsstr(pwlwrDupName, L"\\system32\\gdi32.dll"))
			{
				g_gdi32ExtTextOutW = (ULONG)pImageInfo->ImageBase + GDI32_ExtTextOutW;
			}
			else if (wcsstr(pwlwrDupName, L"notepad.exe"))
			{
				g_notepad_7955 = (ULONG)pImageInfo->ImageBase + 0x7955;
			}
		}
		ObDereferenceObject(Process);
	}
}

void EptHandlerTermination()
{
	PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, TRUE);
	PsRemoveCreateThreadNotifyRoutine(CreateThreadNotifyRoutineEx);
	PsRemoveLoadImageNotifyRoutine(LoadImageNotifyCallback);
}

NTSTATUS EptHandlerInitialization()
{
	NTSTATUS status;
	status = PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)ProcessNotifyRoutineEx, FALSE);
	status = PsSetCreateThreadNotifyRoutineEx(PsCreateThreadNotifyNonSystem, CreateThreadNotifyRoutineEx);
	status = PsSetLoadImageNotifyRoutine(LoadImageNotifyCallback);
	return status;
}

NTSTATUS
HpIoctlCreateClose(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


void  SetVirtualAddrType(PVOID BaseAddress, ULONG_PTR Size, ULONG Type)
{
	ULONG_PTR start_frame = (ULONG_PTR)BaseAddress >> 12;
	ULONG_PTR end_frame = ((ULONG_PTR)BaseAddress + Size - 1) >> 12;
	ULONG_PTR vpfn;
	
	for (vpfn = start_frame; vpfn <= end_frame; vpfn += 1)
	{
		ULONG_PTR byte_loc = vpfn >> 2;
		ULONG     bit_loc = 2*(vpfn & 0x3u);
		UCHAR     new_byte_value = (UCHAR)((g_white_bitmap[byte_loc] & ~(0x3u << bit_loc)) | (Type << bit_loc));
		//InterlockedExchange8((CHAR *)(g_white_bitmap + byte_loc), new_byte_value);
		g_white_bitmap[byte_loc] = new_byte_value;
	}
}

NTSTATUS HpIoctlDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION  irpSp;// Pointer to current stack location
	NTSTATUS            ntStatus = STATUS_SUCCESS;// Assume success
	ULONG               inBufLength; // Input buffer length
	ULONG               outBufLength; // Output buffer length
	PVOID               inBuf, outBuf; // pointer to Input and output buffer
	PCHAR               buffer = NULL;

	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();

	irpSp = IoGetCurrentIrpStackLocation(Irp);
	inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	inBuf = Irp->AssociatedIrp.SystemBuffer;
	outBuf = Irp->AssociatedIrp.SystemBuffer;
	/*if (!inBufLength)
	{
		ntStatus = STATUS_INVALID_PARAMETER;
		goto End;
	}*/
	PADDR_INFO pAddrInfoInput = NULL;
	PSTART_INFO pStartInfo = NULL;
	PEPROCESS pEprocess = NULL;
	NTSTATUS status;
	thread_ctx_t *p_thread_ctx = NULL;
	PTAG_INFO pTagInfo = NULL;
	ULONG i;
	ULONG del_pid;
	PETHREAD del_thread = NULL;
	PDEBUG_INFO pDebugInfo = NULL;

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_HYPERPLATFORM_START_MONITOR:
		DbgPrint("IOCTL_START_MONITOR.\n");
		g_monitor_start = 1;
		pStartInfo = (PSTART_INFO)inBuf;
		status = PsLookupProcessByProcessId((HANDLE)pStartInfo->Pid, &pEprocess);
		if (NT_SUCCESS(status))
		{
			CHAR *pProcName = PsGetProcessImageFileName(pEprocess);
			if (strstr(pProcName, g_process_name)){
			}
			ObDereferenceObject(pEprocess);
		}
		Irp->IoStatus.Information = 0;
		break;
	case IOCTL_HYPERPLATFORM_BITMAP_SET:
		pTagInfo = (PTAG_INFO)inBuf;
		DbgPrint("IOCTL_HYPERPLATFORM_BITMAP_SET: %d, %x %x.\n", PsGetCurrentThreadId(), pTagInfo->Base, pTagInfo->Size);
		break;
	case IOCTL_HYPERPLATFORM_BITMAP_CHECK:
		pTagInfo = (PTAG_INFO)inBuf;
		DbgPrint("IOCTL_HYPERPLATFORM_BITMAP_CHECK: %d, %x %x.\n", PsGetCurrentThreadId(), pTagInfo->Base, pTagInfo->Size);
		break;
	default:
		ntStatus = STATUS_INVALID_DEVICE_REQUEST;
		DbgPrint("ERROR: unrecognized IOCTL %x\n", irpSp->Parameters.DeviceIoControl.IoControlCode);
		break;
	}
//End:
	Irp->IoStatus.Status = ntStatus;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return ntStatus;
}

NTSTATUS
NTAPI MyNtGetNlsSectionPtr(
	__in ULONG SectionType,
	__in ULONG SectionData,
	__in PVOID ContextData,
	__out PVOID *SectionPointer,
	__out PULONG SectionSize
)
{
	NTSTATUS status;
	PEPROCESS Process = PsGetCurrentProcess();
	PCHAR ProcessName = (PCHAR)PsGetProcessImageFileName(Process);
	status = origNtGetNlsSectionPtr(SectionType, SectionData, ContextData, SectionPointer, SectionSize);

	if (ProcessName && !_strnicmp(ProcessName, g_process_name, strlen(g_process_name)))
	{
		DbgPrint("NtGetNlsSectionPtr base %x, size %x\n", *SectionPointer, *SectionSize);
		SetVirtualAddrType(*SectionPointer, *SectionSize, 1);
	}
	return status;
}

NTSTATUS
NTAPI MyNtInitializeNlsFiles(
	_Out_ PVOID *BaseAddress,
	_Out_ PLCID DefaultLocaleId,
	_Out_ PLARGE_INTEGER DefaultCasingTableSize
)
{
	NTSTATUS status;
	PEPROCESS Process = PsGetCurrentProcess();
	PCHAR ProcessName = (PCHAR)PsGetProcessImageFileName(Process);
	status = origNtInitializeNlsFiles(BaseAddress, DefaultLocaleId, DefaultCasingTableSize);
	//locale.nls, 0xBE000
	if (ProcessName && !_strnicmp(ProcessName, g_process_name, strlen(g_process_name)))
	{
		DbgPrint("NtInitializeNlsFiles. BaseAddress %x\n", *BaseAddress);
		SetVirtualAddrType(*BaseAddress, 0xBE000, 1);
	}
	return status;
}

NTSTATUS NTAPI MyNtAllocateVirtualMemory(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG ZeroBits,
	PULONG AllocationSize,
	ULONG AllocationType,
	ULONG Protect)
{
	NTSTATUS status = 0;
	bool     is_target = false;

	if ((g_target_cr3 == __readcr3()) && g_target_active)
	{
		is_target = true;
		DbgPrint("<NtAllocateVirtualMemory> before. base %x, size %x, type %x, prot %x.\n",
			*BaseAddress, *AllocationSize, AllocationType, Protect);
	}
	status = origNtAllocateVirtualMemory(
		ProcessHandle,
		BaseAddress,
		ZeroBits,
		AllocationSize,
		AllocationType,
		Protect);
	if (is_target)
	{
		DbgPrint("<NtAllocateVirtualMemory> after. status %x, base %x, size %x, type %x, prot %x.\n", 
			status, *BaseAddress, *AllocationSize, AllocationType, Protect);
	}
	return status;
}

NTSTATUS __stdcall MyNtProtectVirtualMemory(
	HANDLE ProcessHandle,
	PVOID * BaseAddress,
	PSIZE_T RegionSize,
	ULONG NewProtectWin32,
	PULONG OldProtect)
{
	NTSTATUS status = 0;
	status = origNtProtectVirtualMemory(
		ProcessHandle,
		BaseAddress,
		RegionSize,
		NewProtectWin32,
		OldProtect);
	if (g_target_cr3 == __readcr3())
	{
		if (NT_SUCCESS(status))
		{
			DbgPrint("NtProtectVirtualMemory: Base %x, Size %x, new %x, old %x.\n",
				*BaseAddress, *RegionSize, NewProtectWin32, *OldProtect);
		}
	}
	return status;
}

NTSTATUS __stdcall MyNtFreeVirtualMemory(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	PULONG FreeSize,
	ULONG  FreeType)
{
	NTSTATUS status = 0;
	status = origNtFreeVirtualMemory(
		ProcessHandle,
		BaseAddress,
		FreeSize,
		FreeType);
	if ((g_target_cr3 == __readcr3()) && g_target_active)
	{
		if (NT_SUCCESS(status))
		{
			DbgPrint("<NtFreeVirtualMemory> base %x, size %x, type %x.\n",
				*BaseAddress, *FreeSize, FreeType);
			PVOID baseAddr = *BaseAddress;
			for (ULONG offset = 0; offset < (*FreeSize); offset += PAGE_SIZE)
			{
			}		
		}
	}
	return status;
}

NTSTATUS __stdcall MyNtReadFile(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	PLARGE_INTEGER   ByteOffset,
	PULONG           Key
	)
{
	NTSTATUS status;

	InterlockedIncrement((LONG *)&gNtReadFileCount);

	if (g_target_pid != PsGetCurrentProcessId())
	{
		InterlockedDecrement((LONG *)&gNtReadFileCount);
		return origNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
			Buffer, Length, ByteOffset, Key);
	}
	status = origNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
		Buffer, Length, ByteOffset, Key);
	if (status == STATUS_SUCCESS)
	{
		PFILE_OBJECT pFileObj;
		ObReferenceObjectByHandle(FileHandle, GENERIC_READ, *IoFileObjectType,
			KernelMode, (PVOID *)&pFileObj, NULL);
		POBJECT_NAME_INFORMATION pFullPath;
		ULONG uRealSize;
		pFullPath = (POBJECT_NAME_INFORMATION)ExAllocatePool(NonPagedPool, 1024);
		ObQueryNameString(pFileObj, pFullPath, 1024, &uRealSize);
		ObDereferenceObject(pFileObj);
		PHYSICAL_ADDRESS lpa = MmGetPhysicalAddress((PVOID)Buffer);

		/*DbgPrint("<NtReadFile> tid %d, time %u, file %wZ, buffer %x %llx, length 0x%x, readed 0x%x.\n",
			PsGetCurrentThreadId(), QueryTimeMillisecond(), &pFullPath->Name,
			Buffer, lpa.QuadPart, Length, IoStatusBlock->Information);*/

		//if (IoStatusBlock->Information == 100) //tb
		//{
		//	thread_ctx_t *p_thread_ctx = (thread_ctx_t *)*(ULONG_PTR *)((PUCHAR)PsGetCurrentThread() + CTX_OFFSET);
		//	if (p_thread_ctx)
		//	{
		//		if (p_thread_ctx->in_buffer_pending)
		//		{
		//			p_thread_ctx->need_set = 1;  //delay
		//		}
		//		else
		//		{
		//			CloseInterrupt();
		//			ULONG  lastBufPtr = *(ULONG *)p_thread_ctx->teb_extend_va;
		//			*(ULONG *)(lastBufPtr - 4) = g_checkCodePage + 12;
		//			StartInterrupt();
		//		}

		//		ULONG p = (ULONG)p_thread_ctx->set_ptr;
		//		*(ULONG *)(p) = (ULONG)Buffer;                  
		//		*(ULONG *)(p + 4) = IoStatusBlock->Information;
		//		p_thread_ctx->set_ptr = (PVOID)(p + 8);
		//	}
		//	DbgPrint("[TAINT] Set point, tid %d, buf %x, len 0x%x, g_entry_table %x\n",
		//		PsGetCurrentThreadId(), Buffer, IoStatusBlock->Information, g_entry_table);

		//	g_taint_set = 1;
		//}

		//7z.exe...
		if (wcsstr(pFullPath->Name.Buffer, L"1M.txt") || wcsstr(pFullPath->Name.Buffer, L"1M.wav"))
		{
			if (g_read_bytes)
			{
				ULONG realReadLen = IoStatusBlock->Information;
				ULONG taintLen = g_read_bytes;
				if (g_read_bytes > realReadLen)
				{
					taintLen = realReadLen;
				}
				g_read_bytes -= taintLen;

				thread_ctx_t *p_thread_ctx = (thread_ctx_t *)*(ULONG_PTR *)((PUCHAR)PsGetCurrentThread() + CTX_OFFSET);
				if (p_thread_ctx)
				{
					if (p_thread_ctx->in_buffer_pending)
					{
						p_thread_ctx->need_set = 1;
					}
					else
					{
						CloseInterrupt();
						ULONG  lastBufPtr = *(ULONG *)p_thread_ctx->teb_extend_va;
						*(ULONG *)(lastBufPtr - 4) = g_checkCodePage + 12;
						StartInterrupt();
					}
					ULONG p = (ULONG)p_thread_ctx->set_ptr;
					*(ULONG *)(p) = (ULONG)Buffer;     
					*(ULONG *)(p + 4) = taintLen;       
					p_thread_ctx->set_ptr = (PVOID)(p + 8);

					DbgPrint("[TAINT] Set point, tid %d, buf %x, taintLen %u, realReadLen %u, g_entry_table %x\n",
						PsGetCurrentThreadId(), Buffer, taintLen, realReadLen, g_entry_table);

					g_taint_set = 1;
				}
			}
		}

		ExFreePool(pFullPath);
	}

	InterlockedDecrement((LONG *)&gNtReadFileCount);
	return status;
}

NTSTATUS __stdcall MyNtWriteFile(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	PLARGE_INTEGER   ByteOffset,
	PULONG           Key)
{
	HANDLE   pid = PsGetCurrentProcessId();

	InterlockedIncrement((LONG *)&gNtWriteFileCount);

	if (pid == g_target_pid)
	{
		PFILE_OBJECT pFileObj;
		ObReferenceObjectByHandle(FileHandle, GENERIC_READ, *IoFileObjectType,
			KernelMode, (PVOID *)&pFileObj, NULL);
		POBJECT_NAME_INFORMATION pFullPath;
		ULONG uRealSize;
		pFullPath = (POBJECT_NAME_INFORMATION)ExAllocatePool(NonPagedPool, 1024);
		ObQueryNameString(pFileObj, pFullPath, 1024, &uRealSize);
		ObDereferenceObject(pFileObj);

		PHYSICAL_ADDRESS lpa = MmGetPhysicalAddress((PVOID)Buffer);

		//if (!wcsstr(pFullPath->Name.Buffer, L"ConDrv")) //Ignore
		//{
		//	DbgPrint("<NtWriteFile> tid %d, time %u, file %wZ, buffer %x, pa %llx, length %d.\n",
		//		PsGetCurrentThreadId(), QueryTimeMillisecond(), &pFullPath->Name,
		//		Buffer, lpa.QuadPart, Length);
		//}	

		//7z curl...
		if (wcsstr(pFullPath->Name.Buffer, L"1M.7z") || wcsstr(pFullPath->Name.Buffer, L"1M.mp3") ||
			wcsstr(pFullPath->Name.Buffer, L"CryptnetUrlCache") || wcsstr(pFullPath->Name.Buffer, L".htm") ||
			wcsstr(pFullPath->Name.Buffer, L"cab"))
		{
			if ((g_write_count++) < 8)
			{
				thread_ctx_t *p_thread_ctx = (thread_ctx_t *)*(ULONG_PTR *)((PUCHAR)PsGetCurrentThread() + CTX_OFFSET);
				if (p_thread_ctx)
				{
					if (p_thread_ctx->in_buffer_pending)
					{
						p_thread_ctx->need_check = 1;
					}
					else
					{
						CloseInterrupt();
						ULONG  lastBufPtr = *(ULONG *)p_thread_ctx->teb_extend_va; 
						*(ULONG *)(lastBufPtr - 4) = g_checkCodePage;     
						StartInterrupt();
					}
					
					ULONG p = (ULONG)p_thread_ctx->check_ptr;
					*(ULONG *)(p) = (ULONG)Buffer;
					*(ULONG *)(p + 4) = Length;
					p_thread_ctx->check_ptr = (PVOID)(p + 8);
				}
				DbgPrint("[TAINT] Check point, tid %d, buf %x, len %u\n", PsGetCurrentThreadId(), Buffer, Length);
			}
		}

		ExFreePool(pFullPath);
	}
	NTSTATUS status = origNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer,
		Length, ByteOffset, Key);

	InterlockedDecrement((LONG *)&gNtWriteFileCount);

	return status;
}

NTSTATUS __stdcall MyNtDeviceIoControlFile(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG            IoControlCode,
	PVOID            InputBuffer,
	ULONG            InputBufferLength,
	PVOID            OutputBuffer,
	ULONG            OutputBufferLength)
{
	NTSTATUS status;
	HANDLE pid = PsGetCurrentProcessId();

	InterlockedIncrement((LONG *)&gNtDeviceIoCount);

	if (pid == g_target_pid)
	{
		if (IoControlCode == 0x1201f) //IOCTL_AFD_SEND
		{
			PAFD_INFO pAfdInfo = (PAFD_INFO)InputBuffer;

			//DbgPrint("<NtDeviceIoControlFile> tid %d, time %u, socket handle %x, send len %u\n",
			//	PsGetCurrentThreadId(), QueryTimeMillisecond(), FileHandle, pAfdInfo->BufferArray->len);

			if (g_taint_set)
			{
				if ((g_send_count++) < 10)
				{
					thread_ctx_t *p_thread_ctx = (thread_ctx_t *)*(ULONG_PTR *)((PUCHAR)PsGetCurrentThread() + CTX_OFFSET);
					if (p_thread_ctx)
					{
						if (p_thread_ctx->in_buffer_pending)
						{
							p_thread_ctx->need_check = 1;
						}
						else
						{
							CloseInterrupt();
							ULONG  lastBufPtr = *(ULONG *)p_thread_ctx->teb_extend_va; 
							*(ULONG *)(lastBufPtr - 4) = g_checkCodePage;
							StartInterrupt();
						}

						ULONG p = (ULONG)p_thread_ctx->check_ptr;
						*(ULONG *)(p) = (ULONG)pAfdInfo->BufferArray->buf;
						*(ULONG *)(p + 4) = pAfdInfo->BufferArray->len;
						p_thread_ctx->check_ptr = (PVOID)(p + 8);

						DbgPrint("[TAINT] Check point, tid %d, buf %x, len %u.\n", PsGetCurrentThreadId(),
							pAfdInfo->BufferArray->buf, pAfdInfo->BufferArray->len);
					}			
				}
			}		
		}
		else if (IoControlCode == 0x12017) //IOCTL_AFD_RECV
		{
			status = origNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
				IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
			PAFD_INFO pAfdInfo = (PAFD_INFO)InputBuffer;
			if (status == STATUS_SUCCESS)
			{
				PVOID recvBuf = pAfdInfo->BufferArray->buf;
				ULONG recvLen = IoStatusBlock->Information;

				//DbgPrint("<NtDeviceIoControlFile> tid %d, time %u, socket handle %x, sync recv len %d, buf %x, input len %d\n",
				//	PsGetCurrentThreadId(), QueryTimeMillisecond(), FileHandle, recvLen, recvBuf, pAfdInfo->BufferArray->len);
				
				//curl..
				if (g_recv_bytes)
				{
					ULONG taintLen = g_recv_bytes;
					if (g_recv_bytes > recvLen)
					{
						taintLen = recvLen;
					}
					g_recv_bytes -= taintLen;

					thread_ctx_t *p_thread_ctx = (thread_ctx_t *)*(ULONG_PTR *)((PUCHAR)PsGetCurrentThread() + CTX_OFFSET);
					if (p_thread_ctx)
					{
						if (p_thread_ctx->in_buffer_pending)
						{
							p_thread_ctx->need_set = 1;
						}
						else
						{
							CloseInterrupt();
							ULONG  lastBufPtr = *(ULONG *)p_thread_ctx->teb_extend_va;
							*(ULONG *)(lastBufPtr - 4) = g_checkCodePage + 12;
							StartInterrupt();
						}

						ULONG p = (ULONG)p_thread_ctx->set_ptr;
						*(ULONG *)(p) = (ULONG)recvBuf;
						*(ULONG *)(p + 4) = taintLen;
						p_thread_ctx->set_ptr = (PVOID)(p + 8);

						DbgPrint("[TAINT] Set point, tid %d, buf %x, taintLen %u, realRecvLen %u, g_entry_table %x\n",
							PsGetCurrentThreadId(), recvBuf, taintLen, recvLen, g_entry_table);
					}
				}
			}
			else if (status == STATUS_PENDING)
			{
				PFILE_OBJECT pFileObj;
				ObReferenceObjectByHandle(FileHandle, GENERIC_READ, *IoFileObjectType,
					KernelMode, (PVOID *)&pFileObj, NULL);

				/*DbgPrint("<NtDeviceIoControlFile> tid %d, time %u, socket handle %x, async recv, buf %x, ApcRoutine %x, FileObj %x\n",
					PsGetCurrentThreadId(), QueryTimeMillisecond(), FileHandle, 
					pAfdInfo->BufferArray->buf, ApcRoutine, pFileObj);*/

				ObDereferenceObject(pFileObj);
			}
			InterlockedDecrement((LONG *)&gNtDeviceIoCount);
			return status;
		}
	}
	status = origNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext,
		IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength,
		OutputBuffer, OutputBufferLength);

	InterlockedDecrement((LONG *)&gNtDeviceIoCount);

	return status;
}

NTSTATUS __stdcall MyNtCreateSection(
	PHANDLE            SectionHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER     MaximumSize,
	ULONG              SectionPageProtection,
	ULONG              AllocationAttributes,
	HANDLE             FileHandle)
{
	NTSTATUS status;
	HANDLE   pid = PsGetCurrentProcessId();
	InterlockedIncrement((LONG *)&gNtCreateSectionCount);

	status = orgNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize,
		SectionPageProtection, AllocationAttributes, FileHandle);

	if (pid == g_target_pid)
	{
		if (FileHandle)
		{
			IO_STATUS_BLOCK       isb = { 0 };
			PWCHAR allocNameBuf = (PWCHAR)ExAllocatePool(NonPagedPool, 1024);
			PFILE_NAME_INFORMATION pFNI = (PFILE_NAME_INFORMATION)allocNameBuf;
			NTSTATUS s = ZwQueryInformationFile(FileHandle, &isb, pFNI, 1024, FileNameInformation);
			if (STATUS_SUCCESS == s)
			{
				pFNI->FileName[pFNI->FileNameLength / 2] = 0x00;
				if (wcsstr(pFNI->FileName, L"1.txt"))
				{
					g_fileReadSectionHandle = *SectionHandle;
					DbgPrint("[MyNtCreateSection] Tid %d, FileName %ws, SectionHandle %x\n",
						PsGetCurrentThreadId(), pFNI->FileName, g_fileReadSectionHandle);
				}
			}
			else
			{
				DbgPrint("ZwQueryInformationFile error %x\n", s);
			}
			ExFreePool(allocNameBuf);
		}
	}

	InterlockedDecrement((LONG *)&gNtCreateSectionCount);
	return status;
}

NTSTATUS __stdcall MyNtMapViewOfSection(
	HANDLE          SectionHandle,
	HANDLE          ProcessHandle,
	PVOID           *BaseAddress,
	ULONG_PTR       ZeroBits,
	SIZE_T          CommitSize,
	PLARGE_INTEGER  SectionOffset,
	PSIZE_T         ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG           AllocationType,
	ULONG           Win32Protect)
{
	NTSTATUS status;
	HANDLE   pid = PsGetCurrentProcessId();
	InterlockedIncrement((LONG *)&gNtMapViewOfSectionCount);

	status = orgNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize,
		SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);

	if (pid == g_target_pid)
	{
		if (g_fileReadSectionHandle && (g_fileReadSectionHandle == SectionHandle))
		{
			ULONG viewSize = *ViewSize;
			if (viewSize == 0x1000)
			{
				ULONG  buf = (ULONG)*BaseAddress;
				ULONG  len = 256;

				DbgPrint("[MyNtMapViewOfSection] Tid %d, BaseAddress %x, CommitSize %x, ViewSize %x\n",
					PsGetCurrentThreadId(), *BaseAddress, CommitSize, viewSize);
				g_mapViewAddress = buf;

				thread_ctx_t *p_thread_ctx = (thread_ctx_t *)*(ULONG_PTR *)((PUCHAR)PsGetCurrentThread() + CTX_OFFSET);
				if (p_thread_ctx)
				{
					if (p_thread_ctx->in_buffer_pending)
					{
						p_thread_ctx->need_check = 1;
					}
					else
					{
						CloseInterrupt();
						ULONG  lastBufPtr = *(ULONG *)p_thread_ctx->teb_extend_va;
						*(ULONG *)(lastBufPtr - 4) = g_checkCodePage + 12;
						StartInterrupt();
					}
						
					ULONG p = (ULONG)p_thread_ctx->set_ptr;
					*(ULONG *)(p) = buf;               
					*(ULONG *)(p + 4) = len;           
					p_thread_ctx->set_ptr = (PVOID)(p + 8);
				}
				DbgPrint("[TAINT] Set point, tid %d, buf %x, len %u, g_entry_table %x\n",
					PsGetCurrentThreadId(), buf, len, g_entry_table);

				//g_fileReadSectionHandle = NULL;
			}
		}
	}

	InterlockedDecrement((LONG *)&gNtMapViewOfSectionCount);
	return status;
}

VOID WriteJumpKernel(VOID *pAddress, ULONG_PTR JumpTo)
{
	UCHAR *pCur = (UCHAR *)pAddress;
#ifdef _M_IX86

	*pCur = 0xff;     // jmp [addr]
	*(++pCur) = 0x25;
	pCur++;
	*((ULONG *)pCur) = (ULONG)(((ULONG_PTR)pCur) + sizeof(ULONG));
	pCur += sizeof(ULONG);
	*((ULONG_PTR *)pCur) = JumpTo;

#else ifdef _M_AMD64

	*pCur = 0xff;		// jmp [rip+addr]
	*(++pCur) = 0x25;
	*((ULONG *) ++pCur) = 0; // addr = 0
	pCur += sizeof(ULONG);
	*((ULONG_PTR *)pCur) = JumpTo;

#endif
}

PVOID InlineHookFunction(ULONG_PTR OriginalFunction, ULONG_PTR NewFunction, ULONG InsSize)
{
	UCHAR *pBridgeBuffer = (UCHAR *)ExAllocatePoolWithTag(NonPagedPool, 32, kHyperPlatformCommonPoolTag);
	if (pBridgeBuffer == NULL)
	{
		DbgPrint("InlineHookFunction ExAllocatePoolWithTag error\n");
		return NULL;
	}

	memcpy(pBridgeBuffer, (VOID *)OriginalFunction, InsSize);
	WriteJumpKernel(&pBridgeBuffer[InsSize], OriginalFunction + InsSize);
	WriteJumpKernel((VOID *)OriginalFunction, NewFunction);

	return pBridgeBuffer;
}

VOID InlineUnHookFunction(ULONG_PTR OriginalFunction, ULONG_PTR BridgeBuffer, ULONG InsSize)
{
	memcpy((VOID *)OriginalFunction, (VOID *)BridgeBuffer, InsSize);
}

ULONG __fastcall MyMiAllocateWsle(ULONG a1, ULONG pte, ULONG a3, ULONG a4, 
	ULONG a5, ULONG pfn_l, ULONG pfn_h)
{
	bool    is_target = false;
	ULONG64 old_pa;
	//cr3£¬attach
	if ((g_target_cr3 == __readcr3()) && g_target_active && (pte < 0xC0400000))
	{
		is_target = true;
		old_pa = *(ULONG64 *)pte;
	}
	ULONG ws_index = ((PfnMiAllocateWsle)g_TrampoMiAllocateWsle)(a1,pte,a3,a4,a5,pfn_l,pfn_h);

	if (ws_index && is_target)
	{	
		ULONG64 pa = *(ULONG64 *)pte;
		ULONG   va = (pte - 0xC0000000) << 9;

		thread_ctx_t *p_thread_ctx = GET_THREAD_CTX();
		if (p_thread_ctx)
		{
			//DbgPrint("MyMiAllocateWsle. p_thread_ctx %x, pte %x, va %08x, pa %016llx\n", p_thread_ctx, pte, va, pa);
			if ((UCHAR)p_thread_ctx == 0xAA)
			{
				DbgPrint("[MyMiAllocateWsle] analysis thread. tid %d, va %08x, pa %016llx\n",
					PsGetCurrentThreadId(), va, pa);
				HYPERPLATFORM_COMMON_DBG_BREAK();
				return ws_index;
			}
			if (va == (p_thread_ctx->teb + PAGE_SIZE)) //extended teb 
			{
				DbgPrint("[MyMiAllocateWsle] ignore extended teb. pte %x, va %08x, pa %016llx\n", pte, va, pa);
				return ws_index;
			}
			if (va == (p_thread_ctx->teb))
			{
				DbgPrint("[MyMiAllocateWsle] TEB. pte %x, va %08x, pa %016llx\n", pte, va, pa);
			}
			
		}
		else
		{
			//DbgPrint("MyMiAllocateWsle attach. ethread %x, va %x, pa %llx\n",PsGetCurrentThread(), va, pa);
		}

		if ((g_mapViewAddress & 0xFFFFF000) == va)
		{
			DbgPrint("[ViewAddress] Alloc. p_thread_ctx %x, pte %x, va %08x, pa %016llx\n", p_thread_ctx, pte, va, pa);
		}

		if (g_page_state[va >> 12] == 1)
		{
			DbgPrint("MyMiAllocateWsle reserved. p_thread_ctx %x, pte %x, va %08x, pa %016llx\n", p_thread_ctx, pte, va, pa);
			return ws_index;
		}

		BUFFER_ENTRY *entry = (BUFFER_ENTRY *)g_entry_table[va >> 12];
		if (!entry)
		{
			AnalysisAllocateMapEntry(va, pa);
		}
		else //reuse
		{
			entry->MappedVa |= 2;
		}

		if (!(pa >> 63)) //nx = 0
		{
			RedirectCodePage(pte, pa);
		}
	}
	return ws_index;
}

int __fastcall MyMiCopyOnWriteEx(ULONG_PTR va, ULONG pte, ULONG a3, ULONG a4, ULONG a5)
{
	ULONG64 orig_pa = *(ULONG64 *)pte;
	int result = ((PfnMiCopyOnWriteEx)g_TrampoMiCopyOnWriteEx)(va, pte, a3, a4, a5);
	if (result && (g_target_cr3 == __readcr3()) && g_target_active && (pte < 0xC0400000))
	{
		ULONG64 pa = *(ULONG64 *)pte;
		ULONG   va = (pte - 0xC0000000) << 9;
	
		if (g_page_state[va >> 12] == 1)
		{
			DbgPrint("MyMiCopyOnWriteEx reserved. va %08x, pa %016llx, org %016llx\n", va, pa, orig_pa);
			return result;
		}
		
		BUFFER_ENTRY *entry = (BUFFER_ENTRY *)g_entry_table[va >> 12];
		if (!entry)
		{
			AnalysisAllocateMapEntry(va, pa);
		}
		else
		{
			entry->MappedVa |= 2;
		}

		if (!(pa >> 63)) //nx = 0
		{
			RedirectCodePage(pte, pa);
		}	
	}
	return result;
}

void __fastcall MyMiDeleteVirtualAddresses(ULONG start_va, ULONG end_va, ULONG a3, ULONG a4, ULONG a5)
{
	if ((g_target_cr3 == __readcr3()) && (start_va < 0x80000000))
	{
		for (ULONG va = start_va; va <= end_va; va += 0x1000)
		{
			ULONG pte_addr = 0xC0000000 + (va >> 9);
			ULONG vfn = va >> 12;
			ULONG original_pa = (ULONG)g_redirect_table[vfn].OldPa;
			if (original_pa)
			{
				PVOID new_va = g_redirect_table[vfn].KernelVa;
				ULONG new_pa = *(ULONG *)(0xC0000000 + (((ULONG)new_va >> 9) & 0x7ffff8));
				PMMPFN  p_new_mmpfn = (PMMPFN)(g_MmPfnDatabase + (new_pa >> 12) * 0x1C);
				//restore
				p_new_mmpfn->u4.PrototypePte = 0;
				p_new_mmpfn->ShareCount = 1;
				p_new_mmpfn->e1 = (p_new_mmpfn->e1 & 8) | 6;
				p_new_mmpfn->ReferenceCount = 1;
				//DbgPrint(" [MiDeleteVa] va %x, new_va %x, original_pa %x, new_pa %x, p_new_mmpfn %x\n", 
				//	va, new_va, original_pa, new_pa, p_new_mmpfn);

				ExFreePoolWithTag(new_va, kHyperPlatformCommonPoolTag);
				g_redirect_table[vfn].OldPa = 0;
				g_redirect_table[vfn].KernelVa = 0;
				*(ULONG *)pte_addr = original_pa;
				__invlpg((PVOID)va);
			}	
			if (g_target_active)
			{
				BUFFER_ENTRY *entry = (BUFFER_ENTRY *)g_entry_table[vfn];
				if (entry)
				{
					if (!(entry->MappedVa & 1))
					{	
						entry->MappedVa |= 1;   //b0=1
						ExInterlockedInsertTailList(&g_free_entries_list, &entry->ListEntry, &g_free_entries_lock);	
						g_sb_free_count++;
					}
					else
					{
						entry->MappedVa &= 0xFFFFFFFD; //clear bit1£¬b1=0£¬b0=1
					}
				}
			}
		}
		if (g_target_active)
		{
			ULONG pte1 = 0xC0000000 + (start_va >> 9);
			ULONG pte2 = 0xC0000000 + (end_va >> 9);
			//DbgPrint("[MiDeleteVirtualAddresses] %08x - %08x, pte %x - %x\n", start_va, end_va, pte1, pte2);
		}
	}

	((PfnMiDeleteVirtualAddresses)g_TrampoMiDeleteVirtualAddresses)(start_va, end_va, a3, a4, a5);
}

int __fastcall MyMiDeletePteRun(ULONG start_pte, ULONG end_pte, ULONG a3, ULONG a4, ULONG a5)
{
	if ((g_target_cr3 == __readcr3()) && (start_pte < 0xC0400000) && g_target_active)
	{
		ULONG user_pte = end_pte;
		if (end_pte >= 0xC0400000)
		{
			user_pte = 0xC0400000 - 8;
		}
		for (ULONG pte = start_pte; pte <= user_pte; pte += 8)
		{
			//ULONG vfn = (pte - 0xC0000000) >> 3;
			//DeallocateUserSpaceBufferEntries(vfn);
			//ULONG64 pa = *(ULONG64 *)pte;
			//auto  ept_entry = EptGetEptPtEntry(g_shared_data->ept_data_list[EPTP_ANALYSIS], pa);
			//DbgPrint("[MiDeletePteRun] tid %d, vfn %x, pa %llx, ept2 %llx\n", PsGetCurrentThreadId(), 
			//	vfn, pa, ept_entry->all);
			//ept_entry->fields.physial_address = pa >> 12;
		}
	}
	return ((PfnMiDeletePteRun)g_TrampoMiDeletePteRun)(start_pte, end_pte, a3, a4, a5);
}

int __fastcall MyMiSetProtectionOnSection(ULONG eproc, ULONG vad, ULONG start_va, ULONG end_va,
	ULONG new_prot, ULONG out_old_prot, ULONG charge, ULONG locked)
{
	ULONG is_target = 0;
	if ((g_target_cr3 == __readcr3()) && g_target_active && (start_va < 0x80000000))
	{
		is_target = 1;
		for (ULONG va = start_va; va <= end_va; va += 0x1000)
		{
			ULONG vfn = va >> 12;
			ULONG original_pa = (ULONG)g_redirect_table[vfn].OldPa;
			if (original_pa)
			{
				PVOID new_va = g_redirect_table[vfn].KernelVa;
				ULONG new_pa = *(ULONG *)(0xC0000000 + (((ULONG)new_va >> 9) & 0x7ffff8));
				PMMPFN  p_new_mmpfn = (PMMPFN)(g_MmPfnDatabase + (new_pa >> 12) * 0x1C);

				p_new_mmpfn->u4.PrototypePte = 0;
				p_new_mmpfn->ShareCount = 1;
				p_new_mmpfn->e1 = (p_new_mmpfn->e1 & 8) | 6;
				p_new_mmpfn->ReferenceCount = 1;

				ExFreePoolWithTag(new_va, kHyperPlatformCommonPoolTag);
				g_redirect_table[vfn].OldPa = 0;
				g_redirect_table[vfn].KernelVa = 0;
				ULONG pte_addr = 0xC0000000 + (va >> 9);
				DbgPrint("MyMiSetProtectionOnSection restore, va %08x, pa %08x -> %08x\n",
					va, *(ULONG *)pte_addr, original_pa);
				*(ULONG *)pte_addr = original_pa;
				__invlpg((PVOID)va);
			}
		}
	}
	int status = ((PfnMyMiSetProtectionOnSection)g_TrampoMiSetProtectionOnSection)(eproc,
		vad, start_va, end_va, new_prot, out_old_prot, charge, locked);
	if (is_target && NT_SUCCESS(status))
	{
		//CopyOnWrite
		if (new_prot & 0xF0) 
		{
			DbgPrint("MyMiSetProtectionOnSection execute. va %08x -> %08x, prot %x -> %x.\n",
				start_va, end_va, out_old_prot, new_prot);
			for (ULONG va = start_va; va <= end_va; va += 0x1000)
			{
				ULONG   old_pte = 0xC0000000 + (va >> 9);
				ULONG64 old_pa = *(ULONG64 *)old_pte;
				if (old_pa & 0x200) //p=1,w=0 CopyOnWrite£¬Paging file£¿
				{
					DbgPrint("MyMiSetProtectionOnSection CopyOnWrite. va %08x, pa %llx\n", va, old_pa);
					continue;
				}
				ULONG original_pa = (ULONG)g_redirect_table[va >> 12].OldPa;
				if (!original_pa)
				{
					if (!(old_pa >> 63))
					{
						RedirectCodePage(old_pte, old_pa);
					}		
				}
			}
		}
	}
	return status;
}


LONG64 InlineHookSpecial(ULONG_PTR OriginAddr, ULONG_PTR NewAddr)
{
	char jmpBuf[8] = { 0xe9, 0, 0, 0, 0, 0x90, 0x90, 0x90};
	*(ULONG *)((char *)jmpBuf + 1) = NewAddr - OriginAddr - 5;
	LONG64 originBytes = InterlockedExchange64((LONG64 *)OriginAddr, *(LONG64 *)jmpBuf);

	return originBytes;
}

VOID InlineUnHookSpecial(ULONG_PTR OriginAddr, LONG64 OriginBytes)
{
	InterlockedExchange64((LONG64 *)OriginAddr, OriginBytes);
}

void HookSSDT()
{
	WPOFF();
	//function test
	/*origNtGetNlsSectionPtr = (PfnNtGetNlsSectionPtr)InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_ZwGetNlsSectionPtr),
		(LONG)MyNtGetNlsSectionPtr);
	DbgPrint("NtGetNlsSectionPtr Old Addr: %x, New: %x\n", origNtGetNlsSectionPtr, MyNtGetNlsSectionPtr);
	origNtInitializeNlsFiles = (PfnNtInitializeNlsFiles)InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_ZwInitializeNlsFiles),
		(LONG)MyNtInitializeNlsFiles);
	DbgPrint("NtInitializeNlsFiles Old Addr: %x, New: %x\n", origNtInitializeNlsFiles, MyNtInitializeNlsFiles);*/
	//origNtAllocateVirtualMemory = (PfnNtAllocateVirtualMemory)InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_ZwAllocateVirtualMemory),
	//	(LONG)MyNtAllocateVirtualMemory);
	//origNtFreeVirtualMemory = (PfnNtFreeVirtualMemory)InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_ZwFreeVirtualMemory),
	//	(LONG)MyNtFreeVirtualMemory);
	//origNtProtectVirtualMemory = (PfnNtProtectVirtualMemory)InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_ZwProtectVirtualMemory),
	//	(LONG)MyNtProtectVirtualMemory);

	//hook readfileºÍntiodevicecontrol
	origNtReadFile = (PfnNtReadFile)InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_ZwReadFile),
		(LONG)MyNtReadFile);
	origNtDeviceIoControlFile = (PfnNtDeviceIoControlFile)InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_ZwDeviceIoControlFile),
		(LONG)MyNtDeviceIoControlFile);
	origNtWriteFile = (PfnNtWriteFile)InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_ZwWriteFile),
		(LONG)MyNtWriteFile);
	//notepad
	/*orgNtCreateSection = (PfnNtCreateSection)InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_NtCreateSection),
		(LONG)MyNtCreateSection);
	orgNtMapViewOfSection = (PfnNtMapViewOfSection)InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_NtMapViewOfSection),
		(LONG)MyNtMapViewOfSection);*/

	//g_monitor_start = 0;
	//inline
	g_TrampoMiAllocateWsle = InlineHookFunction(g_MiAllocateWsle, (ULONG_PTR)MyMiAllocateWsle, 11);
	g_TrampoMiCopyOnWriteEx = InlineHookFunction(g_MiCopyOnWriteEx, (ULONG_PTR)MyMiCopyOnWriteEx, 14);
	g_TrampoMiDeletePteRun = InlineHookFunction(g_MiDeletePteRun, (ULONG_PTR)MyMiDeletePteRun, 14);
	g_TrampoMiDeleteVirtualAddresses = InlineHookFunction(g_MiDeleteVirtualAddresses, (ULONG_PTR)MyMiDeleteVirtualAddresses, 14);
	g_TrampoMiSetProtectionOnSection = InlineHookFunction(g_MiSetProtectionOnSection, (ULONG_PTR)MyMiSetProtectionOnSection, 14);
	//TEB
	g_TrampoMmCreateTeb = InlineHookFunction(g_MmCreateTeb, (ULONG_PTR)MyMmCreateTeb, 11);
	//Context
	g_SwapContextOldBytes = InlineHookSpecial(g_SwapContextOld, (ULONG_PTR)MySwapContextOld);
	g_SwapContextBytes = InlineHookSpecial(g_SwapContext, (ULONG_PTR)MySwapContext);
	//syscall
	g_TrampoKiFastCallEntry = InlineHookFunction(g_KiFastCallEntry, (ULONG_PTR)KiFastCallEntry, 10);
	g_TrampoKiServiceExit = InlineHookFunction(g_KiServiceExit, (ULONG_PTR)KiServiceExit, 10);
	g_TrampoKei386HelperExit = InlineHookFunction(g_Kei386HelperExit, (ULONG_PTR)Kei386HelperExit, 14);
	g_TrampoKiCallUserModeExit = InlineHookFunction(g_KiCallUserModeExit, (ULONG_PTR)KiCallUserModeExit, 10);
	WPON();
}

void UnhookSSDT()
{
	WPOFF();
	//InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_ZwGetNlsSectionPtr), (LONG)origNtGetNlsSectionPtr);
	//InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_ZwInitializeNlsFiles), (LONG)origNtInitializeNlsFiles);
	//InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_ZwAllocateVirtualMemory), (LONG)origNtAllocateVirtualMemory);
	//InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_ZwFreeVirtualMemory), (LONG)origNtFreeVirtualMemory);
	//InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_ZwProtectVirtualMemory), (LONG)origNtProtectVirtualMemory);

	InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_ZwReadFile), (LONG)origNtReadFile);
	InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_ZwDeviceIoControlFile), (LONG)origNtDeviceIoControlFile);
	InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_ZwWriteFile), (LONG)origNtWriteFile);

	//notepad
	/*InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_NtCreateSection), (LONG)orgNtCreateSection);
	InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_NtMapViewOfSection), (LONG)orgNtMapViewOfSection);*/

	if (g_TrampoMiAllocateWsle)
	{
		InlineUnHookFunction(g_MiAllocateWsle, (ULONG_PTR)g_TrampoMiAllocateWsle, 11);
	}
	if (g_TrampoMiCopyOnWriteEx)
	{
		InlineUnHookFunction(g_MiCopyOnWriteEx, (ULONG_PTR)g_TrampoMiCopyOnWriteEx, 14);
	}
	if (g_TrampoMiDeletePteRun)
	{
		InlineUnHookFunction(g_MiDeletePteRun, (ULONG_PTR)g_TrampoMiDeletePteRun, 14);
	}
	if (g_TrampoMiDeleteVirtualAddresses)
	{
		InlineUnHookFunction(g_MiDeleteVirtualAddresses, (ULONG_PTR)g_TrampoMiDeleteVirtualAddresses, 14);
	}
	if (g_TrampoMiSetProtectionOnSection)
	{
		InlineUnHookFunction(g_MiSetProtectionOnSection, (ULONG_PTR)g_TrampoMiSetProtectionOnSection, 14);
	}
	//TEB
	if (g_TrampoMmCreateTeb)
	{
		InlineUnHookFunction(g_MmCreateTeb, (ULONG_PTR)g_TrampoMmCreateTeb, 11);
	}
	//Context
	if (g_SwapContextBytes)
	{
		InlineUnHookSpecial(g_SwapContext, g_SwapContextBytes);
	}
	if (g_SwapContextOldBytes)
	{
		InlineUnHookSpecial(g_SwapContextOld, g_SwapContextOldBytes);
	}

	if (g_TrampoKiFastCallEntry)
	{
		InlineUnHookFunction(g_KiFastCallEntry, (ULONG_PTR)g_TrampoKiFastCallEntry, 10);
	}
	if (g_TrampoKiServiceExit)
	{
		InlineUnHookFunction(g_KiServiceExit, (ULONG_PTR)g_TrampoKiServiceExit, 10);
	}
	if (g_TrampoKei386HelperExit)
	{
		InlineUnHookFunction(g_Kei386HelperExit, (ULONG_PTR)g_TrampoKei386HelperExit, 14);
	}
	if (g_TrampoKiCallUserModeExit)
	{
		InlineUnHookFunction(g_KiCallUserModeExit, (ULONG_PTR)g_TrampoKiCallUserModeExit, 10);
	}
	
	WPON();
}

NTSTATUS GetApicIdForEachProcessor()
{
	NTSTATUS status;
	const auto number_of_processors =
		KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	for (ULONG processor_index = 0; processor_index < number_of_processors;
		processor_index++) {
		PROCESSOR_NUMBER processor_number = {};
		status =
			KeGetProcessorNumberFromIndex(processor_index, &processor_number);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		// Switch the current processor
		GROUP_AFFINITY affinity = {};
		affinity.Group = processor_number.Group;
		affinity.Mask = 1ull << processor_number.Number;
		GROUP_AFFINITY previous_affinity = {};
		KeSetSystemGroupAffinityThread(&affinity, &previous_affinity);

		// Execute callback
		ULONG apic_id = AsmGetApicId();
		g_cpu_apid_id[processor_number.Number] = apic_id;

		KeRevertToUserGroupAffinityThread(&previous_affinity);
		if (!NT_SUCCESS(status)) {
			return status;
		}
	}
	return STATUS_SUCCESS;
}

// A driver entry point
_Use_decl_annotations_ NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object,
                                            PUNICODE_STRING registry_path) {
  UNREFERENCED_PARAMETER(registry_path);
  PAGED_CODE();

  static const wchar_t kLogFilePath[] = L"\\SystemRoot\\HyDBA.log";
  static const auto kLogLevel =
      (IsReleaseBuild()) ? kLogPutLevelInfo | kLogOptDisableFunctionName
                         : kLogPutLevelDebug | kLogOptDisableFunctionName;

  auto status = STATUS_UNSUCCESSFUL;
  driver_object->DriverUnload = DriverpDriverUnload;
  g_mydriver_start = driver_object->DriverStart;
  g_mydriver_end = (PUCHAR)g_mydriver_start + driver_object->DriverSize;

  LDR_DATA_TABLE_ENTRY *pLdrTable = NULL;
  pLdrTable = (LDR_DATA_TABLE_ENTRY*)driver_object->DriverSection;
  PLIST_ENTRY pModuleEntry = pLdrTable->InLoadOrderLinks.Flink;
  while (pModuleEntry != &pLdrTable->InLoadOrderLinks)
  {
	  LDR_DATA_TABLE_ENTRY *pCurModule = (LDR_DATA_TABLE_ENTRY *)pModuleEntry;
	  if (wcsstr(pCurModule->BaseDllName.Buffer, L"ntoskrnl"))
	  {
		  g_MiAllocateWsle = (ULONG)pCurModule->DllBase + 0xD2790;
		  g_MiCopyOnWriteEx = (ULONG)pCurModule->DllBase + 0x5C120;
		  g_MiDeletePteRun = (ULONG)pCurModule->DllBase + 0xCB850;
		  g_MiDeleteVirtualAddresses = (ULONG)pCurModule->DllBase + 0xD3CD0;
		  g_MiSetProtectionOnSection = (ULONG)pCurModule->DllBase + 0xCE960;
		  //teb
		  g_MmCreateTeb = (ULONG)pCurModule->DllBase + 0x2D67FE;
		  g_MmCreateTebBack = (ULONG)pCurModule->DllBase + 0x2D6809;
		  //context
		  g_SwapContextOld = (ULONG)pCurModule->DllBase + 0x13902A;
		  g_SwapContextOldBack = (ULONG)pCurModule->DllBase + 0x139036;
		  g_SwapContext = (ULONG)pCurModule->DllBase + 0x1390F6;
		  g_SwapContextBack = (ULONG)pCurModule->DllBase + 0x139100;
		  //sysexit
		  g_KiFastCallEntry = (ULONG)pCurModule->DllBase + 0x134A61;
		  g_KiServiceExit = (ULONG)pCurModule->DllBase + 0x134CD4;    //0x134CD4 10;
		  g_Kei386HelperExit = (ULONG)pCurModule->DllBase + 0x135829;
		  g_KiCallUserModeExit = (ULONG)pCurModule->DllBase + 0x12619D; //10
		  g_MmPfnDatabase = *(ULONG *)((ULONG)pCurModule->DllBase + 0x27132C);
		  //pNtProtectVirtualMemory = (PfnNtProtectVirtualMemory)((ULONG)pCurModule->DllBase + 0x377330);
		  //pZwWriteVirtualMemory = (PfnZwWriteVirtualMemory)((ULONG)pCurModule->DllBase + 0x123BC0);
		  pNtQueryVirtualMemory = (PfnNtQueryVirtualMemory)((ULONG)pCurModule->DllBase + 0x38018E);
		  //Apc
		  KeInitializeApc = (PfnKeInitializeApc)((ULONG)pCurModule->DllBase + 0x2D010);
		  KeInsertQueueApc = (PfnKeInsertQueueApc)((ULONG)pCurModule->DllBase + 0x7A454);
		  DbgPrint("Win10 32 1503 MiAllocateWsle: %x, MiCopyOnWriteEx: %x, MiDeletePteRun: %x\n", 
			  g_MiAllocateWsle, g_MiCopyOnWriteEx, g_MiDeletePteRun);
	  }
	  else if (wcsstr(pCurModule->BaseDllName.Buffer, L"hal"))
	  {
		  g_local_apic = *(ULONG *)((ULONG)pCurModule->DllBase + 0x3E5FC);
		  DbgPrint("Win10 32 1503 HalpLocalApic: %x\n", g_local_apic);
	  }
	  pModuleEntry = pModuleEntry->Flink;
  }
  KeInitializeGuardedMutex(&g_ptAllocMutex);
  KeInitializeGuardedMutex(&g_allocMutex);
  KeInitializeGuardedMutex(&g_rdAllocMutex);
  KeInitializeEvent(&g_athread_event, NotificationEvent, FALSE);
  KeInitializeSpinLock(&g_ipi_spinlock);

  //apic id
  GetApicIdForEachProcessor();

  //idt
  CloseInterrupt();
  Idtr idtr = {};
  __sidt(&idtr);
  PIDTENTRY idt_base = (PIDTENTRY)idtr.base;
  for (ULONG i = 0; i < 256; i++)
  {
	  g_idt_routines[i] = (idt_base[i].HiOffset << 16) | idt_base[i].LowOffset;
  }
  StartInterrupt();

  DbgPrint("idt_base %x, g_idt_routines base %x\n", idt_base, g_idt_routines);

  /*for (ULONG i = 0; i < CACHE_STATE_ALLOCATE_NUM; i++)
  {
	  PVOID kAllocBase = ExAllocatePoolWithTag(NonPagedPool, CACHE_STATE_ALLOCATE_SIZE, kHyperPlatformCommonPoolTag);
	  if (!kAllocBase)
	  {
		  HYPERPLATFORM_LOG_DEBUG("ExAllocatePoolWithTag alloc_state error (%08x).", status);
	  }
	  memset(kAllocBase, 0, CACHE_STATE_ALLOCATE_SIZE);
	  g_alloc_state_kernel_base[g_alloc_state_kernel_count++] = kAllocBase;
  }*/

  //4MB
  g_redirect_table = (REDIRECT_INFO *)ExAllocatePoolWithTag(NonPagedPool, 
	  0x80000 * sizeof(REDIRECT_INFO), kHyperPlatformCommonPoolTag);
  if (!g_redirect_table)
  {
	  DbgPrint("ExAllocatePoolWithTag g_redirect_table error.\n");
	  return STATUS_UNSUCCESSFUL;
  }
  RtlZeroMemory(g_redirect_table, 0x80000 * sizeof(REDIRECT_INFO));

  //2MB
  g_page_state = (ULONG *)ExAllocatePoolWithTag(NonPagedPool, 0x80000 * 4, kHyperPlatformCommonPoolTag);
  if (!g_page_state)
  {
	  HYPERPLATFORM_LOG_DEBUG("ExAllocatePoolWithTag g_page_state error.\n");
  }
  RtlZeroMemory(g_page_state, 0x80000 * 4);

  UNICODE_STRING  ntUnicodeString; 
  UNICODE_STRING  ntWin32NameString;
  PDEVICE_OBJECT  deviceObject = NULL;
  RtlInitUnicodeString(&ntUnicodeString, NT_DEVICE_NAME);
  status = IoCreateDevice(
	  driver_object,                   // Our Driver Object
	  0,                              // We don't use a device extension
	  &ntUnicodeString,               // Device name "\Device\SIOCTL"
	  FILE_DEVICE_UNKNOWN,            // Device type
	  FILE_DEVICE_SECURE_OPEN,     // Device characteristics
	  FALSE,                          // Not an exclusive device
	  &deviceObject);                // Returned ptr to Device Object
  if (!NT_SUCCESS(status))
  {
	  DbgPrint("Couldn't create the device object\n");
	  return status;
  }
  DbgPrint("DriverObject: %x, DeviceObject: %x\n", driver_object, deviceObject);
  driver_object->MajorFunction[IRP_MJ_CREATE] = HpIoctlCreateClose;
  driver_object->MajorFunction[IRP_MJ_CLOSE] = HpIoctlCreateClose;
  driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HpIoctlDeviceControl;
  RtlInitUnicodeString(&ntWin32NameString, DOS_DEVICE_NAME);
  status = IoCreateSymbolicLink(&ntWin32NameString, &ntUnicodeString);
  if (!NT_SUCCESS(status))
  {
	  DbgPrint("Couldn't create symbolic link\n");
	  IoDeleteDevice(deviceObject);
  }

  //ssdthook
  HookSSDT();

  HYPERPLATFORM_COMMON_DBG_BREAK();

  // Request NX Non-Paged Pool when available
  ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

  // Initialize log functions
  bool need_reinitialization = false;
  status = LogInitialization(kLogLevel, kLogFilePath);
  if (status == STATUS_REINITIALIZATION_NEEDED) {
    need_reinitialization = true;
  } else if (!NT_SUCCESS(status)) {
    return status;
  }

  // Test if the system is supported
  if (!DriverpIsSuppoetedOS()) {
    LogTermination();
    return STATUS_CANCELLED;
  }


  // Initialize global variables
  status = GlobalObjectInitialization();
  if (!NT_SUCCESS(status)) {
    LogTermination();
    return status;
  }

  // Initialize perf functions
  status = PerfInitialization();
  if (!NT_SUCCESS(status)) {
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Initialize utility functions
  status = UtilInitialization(driver_object);
  if (!NT_SUCCESS(status)) {
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Initialize power callback
  status = PowerCallbackInitialization();
  if (!NT_SUCCESS(status)) {
    UtilTermination();
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Initialize hot-plug callback
  status = HotplugCallbackInitialization();
  if (!NT_SUCCESS(status)) {
    PowerCallbackTermination();
    UtilTermination();
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }
  EptHandlerInitialization();

  // Virtualize all processors
  status = VmInitialization();
  if (!NT_SUCCESS(status)) {
    HotplugCallbackTermination();
    PowerCallbackTermination();
    UtilTermination();
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Register re-initialization for the log functions if needed
  if (need_reinitialization) {
    LogRegisterReinitialization(driver_object);
  }

  HYPERPLATFORM_LOG_INFO("The VMM has been installed.");

  return status;
}

// Unload handler
_Use_decl_annotations_ static void DriverpDriverUnload(PDRIVER_OBJECT driver_object) 
{
  UNREFERENCED_PARAMETER(driver_object);
  PAGED_CODE();

  UnhookSSDT();

  DbgPrint("DriverpDriverUnload wait...\n");
  while (gNtReadFileCount || gNtWriteFileCount || gNtDeviceIoCount ||
	  gNtMapViewOfSectionCount || gNtCreateSectionCount)
  {
	  LARGE_INTEGER my_interval;
	  my_interval.QuadPart = (-10 * 1000); //1ms
	  KeDelayExecutionThread(KernelMode, 0, &my_interval);
  }
  
  if (g_redirect_table)
  {
	  ExFreePoolWithTag(g_redirect_table, kHyperPlatformCommonPoolTag);
  }

  if (g_page_state)
  {
	  ExFreePoolWithTag(g_page_state, kHyperPlatformCommonPoolTag);
  }

  for (ULONG i = 0; i < g_alloc_state_kernel_count; i++)
  {
	  ExFreePoolWithTag(g_alloc_state_kernel_base[i], kHyperPlatformCommonPoolTag);
  }

  UNICODE_STRING  ntWin32NameString;
  RtlInitUnicodeString(&ntWin32NameString, DOS_DEVICE_NAME);
  IoDeleteSymbolicLink(&ntWin32NameString);
  if(driver_object->DeviceObject)
	  IoDeleteDevice(driver_object->DeviceObject);

  
  VmTermination();
  EptHandlerTermination();
  HotplugCallbackTermination();
  PowerCallbackTermination();
  UtilTermination();
  PerfTermination();
  GlobalObjectTermination();
  LogTermination();
}

// Test if the system is one of supported OS versions
_Use_decl_annotations_ bool DriverpIsSuppoetedOS() {
  PAGED_CODE();

  RTL_OSVERSIONINFOW os_version = {};
  auto status = RtlGetVersion(&os_version);
  if (!NT_SUCCESS(status)) {
    return false;
  }
  if (os_version.dwMajorVersion != 6 && os_version.dwMajorVersion != 10) {
    return false;
  }
  // 4-gigabyte tuning (4GT) should not be enabled
  if (!IsX64() &&
      reinterpret_cast<ULONG_PTR>(MmSystemRangeStart) != 0x80000000) {
    return false;
  }
  return true;
}

}  // extern "C"
