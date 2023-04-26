#pragma once

#include <ntddk.h>
#include <intrin.h>

#define ALIGNMENT_PAGE_SIZE 4096
#define VMCS_SIZE           4096
#define VMXON_SIZE          4096

#define POOLTAG 'HVD'

typedef struct _VIRTUAL_MACHINE_STATE
{
    UINT64 VmxonRegion; // VMXON region
    UINT64 VmcsRegion;  // VMCS region
} VIRTUAL_MACHINE_STATE, *PVIRTUAL_MACHINE_STATE;

extern VIRTUAL_MACHINE_STATE * g_GuestState;
extern int                     g_ProcessorCounts;

BOOLEAN
InitializeVmx();
VOID
TerminateVmx();
