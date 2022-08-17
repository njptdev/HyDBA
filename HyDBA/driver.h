// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// @brief Declares interfaces to driver functions.

#ifndef HYPERPLATFORM_DRIVER_H_
#define HYPERPLATFORM_DRIVER_H_

extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//
#define NT_DEVICE_NAME      L"\\Device\\HyDBADevice"
#define DOS_DEVICE_NAME     L"\\DosDevices\\HyDBAIoctl"

////////////////////////////////////////////////////////////////////////////////
//
// types
//

//557.xz_r
//analysis state
//#define   BUFFER_ENTRY_SIZE           8*1024*1024   //8*1024*1024/12 = 1, 398,101*4k = 
//#define   CACHE_STATE_ALLOCATE_NUM    8             //8
//#define   CACHE_STATE_ALLOCATE_SIZE   64*1024*1024  //64MB*8 = 512MB, overflow entry
//
////executable code mapping
//#define   MAPPING_TABLE_SIZE      0x80000 * 4    //2MB
//#define   CACHE_CODE_TABLE_SIZE   6*1024*1024    //6MB, 6*1024*1024/4096 = 1024 pages
//
////code rewriting (processor)
//#define   PER_CPU_ALLOCATE_SIZE      12*1024*1024  //12MB*4=48MB£¬rewriting
//#define   PER_CPU_CODE_BUF_SIZE       6*1024*1024  
//#define   PER_CPU_ANALYSIS_BUF_SIZE   3*1024*1024  
//#define   PER_CPU_HEAD_BUF_SIZE       2*1024*1024  
//#define   PER_CPU_TEMP_BUF_SIZE       1*1024*1024 

//benchmark program
////analysis state
//#define   BUFFER_ENTRY_SIZE           12*1024*1024  //16*1024*1024/12 = 1, 398,101*4k = 
//#define   CACHE_STATE_ALLOCATE_NUM    8             //8
//#define   CACHE_STATE_ALLOCATE_SIZE   64*1024*1024  //64MB*8 = 512MB
//
////executable code mapping
//#define   MAPPING_TABLE_SIZE          0x80000 * 4   //2MB
//#define   CACHE_CODE_TABLE_SIZE      38*1024*1024  //48MB, 48*1024*1024/4096 = 12288 pages ~ 3000 count
//
////code rewriting (processor)
//#define   PER_CPU_ALLOCATE_SIZE      40*1024*1024  //40MB£¬rewriting
//#define   PER_CPU_CODE_BUF_SIZE      22*1024*1024  
//#define   PER_CPU_ANALYSIS_BUF_SIZE  10*1024*1024  
//#define   PER_CPU_HEAD_BUF_SIZE       7*1024*1024  
//#define   PER_CPU_TEMP_BUF_SIZE       1*1024*1024 

//function test
#define   BUFFER_ENTRY_SIZE           12*1024*1024  //16*1024*1024/12 = 1, 398,101*4k = 
#define   CACHE_STATE_ALLOCATE_NUM    8             //8
#define   CACHE_STATE_ALLOCATE_SIZE   64*1024*1024  //64MB*8 = 512MB

//executable code mapping
#define   MAPPING_TABLE_SIZE          0x80000 * 4   //2MB
#define   CACHE_CODE_TABLE_SIZE      48*1024*1024   //48MB, 48*1024*1024/4096 = 12,288 pages

//code rewriting (processor)
#define   PER_CPU_ALLOCATE_SIZE      40*1024*1024   //40MB£¬rewriting
#define   PER_CPU_CODE_BUF_SIZE      22*1024*1024   
#define   PER_CPU_ANALYSIS_BUF_SIZE  10*1024*1024   
#define   PER_CPU_HEAD_BUF_SIZE       7*1024*1024  
#define   PER_CPU_TEMP_BUF_SIZE       1*1024*1024 

//-------------------------------------

#define   LOG_BLOCK_NUM              4
#define   LOG_BLOCK_SIZE             512*1024      

//-------------------------------------


#define   TEB_PROFILER_OFFSET        0x50

#define   KPCR_EPTP_OFFSET           0x520

#define   LOG_BUFFER_PTR_OFFSET      PAGE_SIZE
#define   REG_STATE_SLOT_OFFSET      PAGE_SIZE + 0x10  
#define   THREAD_STATUS_OFFSET       PAGE_SIZE + 0x30  
#define   STATE_CACHE_OFFSET         PAGE_SIZE + 0x34  
#define   RUNTIME_RECORD_OFFSET      PAGE_SIZE + 0x40  

typedef struct _BUFFER_ENTRY {
	LIST_ENTRY        ListEntry;
	PVOID             Address;
	ULONG             MappedVa;
}BUFFER_ENTRY, *PBUFFER_ENTRY;

typedef struct _ADDR_INFO
{
	LIST_ENTRY    ListEntry;
	PVOID         BaseAddress;
	ULONG         AllocationSize;
	ULONG         AllocationType;
	ULONG         Protect;
}ADDR_INFO, *PADDR_INFO;

typedef struct _START_INFO
{
	PVOID    TrampAddr1;
	PVOID    TrampAddr2;
	ULONG    TrampSize;
	ULONG    Pid;
}START_INFO, *PSTART_INFO;

typedef struct _TAG_INFO
{
	PVOID  Base;
	ULONG  Size;
}TAG_INFO, *PTAG_INFO;

typedef struct _DEBUG_INFO
{
	PVOID  Value1;
	PVOID  Value2;
	PVOID  Value3;
	PVOID  Value4;
}DEBUG_INFO, *PDEBUG_INFO;

#define IOCTL_HYPERPLATFORM_START_MONITOR         CTL_CODE(FILE_DEVICE_UNKNOWN,0X900,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_HYPERPLATFORM_ADDRESS_ALLOCATED     CTL_CODE(FILE_DEVICE_UNKNOWN,0X901,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_HYPERPLATFORM_ADDRESS_FREED         CTL_CODE(FILE_DEVICE_UNKNOWN,0X902,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_HYPERPLATFORM_THREAD_CREATED        CTL_CODE(FILE_DEVICE_UNKNOWN,0X903,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_HYPERPLATFORM_THREAD_DELETED        CTL_CODE(FILE_DEVICE_UNKNOWN,0X904,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_HYPERPLATFORM_BITMAP_SET            CTL_CODE(FILE_DEVICE_UNKNOWN,0X905,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_HYPERPLATFORM_BITMAP_CHECK          CTL_CODE(FILE_DEVICE_UNKNOWN,0X906,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_HYPERPLATFORM_DEBUG_NOTIFY          CTL_CODE(FILE_DEVICE_UNKNOWN,0X907,METHOD_BUFFERED,FILE_ANY_ACCESS)

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

}  // extern "C"

#endif  // HYPERPLATFORM_DRIVER_H_
