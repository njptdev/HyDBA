// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Declares interfaces to EPT functions.

#ifndef HYPERPLATFORM_EPT_H_
#define HYPERPLATFORM_EPT_H_

#include <fltKernel.h>
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

struct EptData;

/// A structure made up of mutual fields across all EPT entry types
union EptCommonEntry {
  ULONG64 all;
  struct {
    ULONG64 read_access : 1;       //!< [0]
    ULONG64 write_access : 1;      //!< [1]
    ULONG64 execute_access : 1;    //!< [2]
    ULONG64 memory_type : 3;       //!< [3:5]
    ULONG64 reserved1 : 6;         //!< [6:11]
    ULONG64 physial_address : 36;  //!< [12:48-1]
    ULONG64 reserved2 : 16;        //!< [48:63]
  } fields;
};
static_assert(sizeof(EptCommonEntry) == 8, "Size check");


#define PFN2BYTE(pfn)	((pfn) >> 2)
#define PFN2BIT(pfn)	((pfn) & 0x3ull)

//ÐÞ¸Ä
// EPT related data stored in ProcessorData
struct EptData {
	EptPointer *ept_pointer;
	EptCommonEntry *ept_pml4;

	EptCommonEntry **preallocated_entries;  // An array of pre-allocated entries
	volatile long preallocated_entries_count;  // # of used pre-allocated entries

	//ÐÞ¸Ä
	UCHAR      *pfn_bitmap;
	ULONG_PTR   bitmap_size;
};



////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

/// Checks if the system supports EPT technology sufficient enough
/// @return true if the system supports EPT
_IRQL_requires_max_(PASSIVE_LEVEL) bool EptIsEptAvailable();

/// Returns an EPT pointer from \a ept_data
/// @param ept_data   EptData to get an EPT pointer
/// @return An EPT pointer
ULONG64 EptGetEptPointer(_In_ EptData* ept_data);

/// Reads and stores all MTRRs to set a correct memory type for EPT
_IRQL_requires_max_(PASSIVE_LEVEL) void EptInitializeMtrrEntries();

/// Builds EPT, allocates pre-allocated entires, initializes and returns EptData
/// @return An allocated EptData on success, or nullptr
///
/// A driver must call EptTermination() with a returned value when this function
/// succeeded.
_IRQL_requires_max_(PASSIVE_LEVEL) EptData* EptInitialization();

/// De-allocates \a ept_data and all resources referenced in it
/// @param ept_data   A returned value of EptInitialization()
void EptTermination(_In_ EptData* ept_data);

/// Handles VM-exit triggered by EPT violation
/// @param ept_data   EptData to get an EPT pointer
_IRQL_requires_min_(DISPATCH_LEVEL) void EptHandleEptViolation(
    _In_ EptData* ept_data);

_Use_decl_annotations_ void EptHandleEptViolationExit(EptData *ept_data, ULONG64 fault_pa);

/// Returns an EPT entry corresponds to \a physical_address
/// @param ept_data   EptData to get an EPT entry
/// @param physical_address   Physical address to get an EPT entry
/// @return An EPT entry, or nullptr if not allocated yet
EptCommonEntry* EptGetEptPtEntry(_In_ EptData* ept_data,
                                 _In_ ULONG64 physical_address);

void EptHandleEptException(EptData *ept_data, ULONG64 fault_pa);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

}  // extern "C"

#endif  // HYPERPLATFORM_EPT_H_
