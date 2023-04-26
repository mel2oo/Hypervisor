#pragma once

#include "vmx.h"
#include "msr.h"

// Memory
UINT64
VirtualToPhysicalAddress(void * va);
UINT64
PhysicalToVirtualAddress(UINT64 pa);

BOOLEAN
AllocateVmxonRegion(VIRTUAL_MACHINE_STATE * GuestState);
BOOLEAN
AllocateVmcsRegion(VIRTUAL_MACHINE_STATE * GuestState);