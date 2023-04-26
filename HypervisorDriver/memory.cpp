#include "memory.h"
#include <intrin.h>
#include <windef.h>

UINT64
VirtualToPhysicalAddress(void * va)
{
    return MmGetPhysicalAddress(va).QuadPart;
}

UINT64
PhysicalToVirtualAddress(UINT64 pa)
{
    PHYSICAL_ADDRESS Address = {0};
    Address.QuadPart         = pa;

    return (UINT64)MmGetVirtualForPhysical(Address);
}

BOOLEAN
AllocateVmxonRegion(VIRTUAL_MACHINE_STATE * GuestState)
{
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        KeRaiseIrqlToDpcLevel();

    PHYSICAL_ADDRESS PhysicalAddress = {0};
    PhysicalAddress.QuadPart         = MAXULONG64;
    INT64            VMXONSize       = 2 * VMXON_SIZE;
    BYTE *           Buffer          = (BYTE *)MmAllocateContiguousMemory(VMXONSize + ALIGNMENT_PAGE_SIZE, PhysicalAddress);
    PHYSICAL_ADDRESS Highest         = {0};
    Highest.QuadPart                 = ~0;

    if (Buffer == NULL)
    {
        DbgPrint("[-] Can't Allocate Buffer for VMXON Region.\n");
        return FALSE;
    }

    UINT64 PhysicalBuffer = VirtualToPhysicalAddress(Buffer);

    RtlSecureZeroMemory(Buffer, VMXONSize + ALIGNMENT_PAGE_SIZE);
    UINT64 AlignedPhysicalBuffer = (ULONG_PTR)(PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1);
    UINT64 AlignedVirtualBuffer  = (ULONG_PTR)(Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1);

    DbgPrint("[*] Virtual allocated buffer for VMXON at %llx.\n", (ULONG64)Buffer);
    DbgPrint("[*] Virtual aligned allocated buffer for VMXON at %llx.\n", AlignedVirtualBuffer);
    DbgPrint("[*] Aligned physical buffer allocated for VMXON at %llx.\n", AlignedPhysicalBuffer);

    IA32_VMX_BASIC_MSR VmxBasic = {0};
    VmxBasic.All                = __readmsr(MSR_IA32_VMX_BASIC);

    DbgPrint("[*] MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier %llx.\n", (ULONG64)VmxBasic.Fields.RevisionIdentifier);

    *(UINT64 *)AlignedVirtualBuffer = VmxBasic.Fields.RevisionIdentifier;

    int Status = __vmx_on(&AlignedPhysicalBuffer);
    if (Status)
    {
        DbgPrint("[-] VMXON failed with status %d\n", Status);
        return FALSE;
    }

    GuestState->VmxonRegion = AlignedPhysicalBuffer;

    return TRUE;
}

BOOLEAN
AllocateVmcsRegion(VIRTUAL_MACHINE_STATE * GuestState)
{
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        KeRaiseIrqlToDpcLevel();

    PHYSICAL_ADDRESS PhysicalMax = {0};
    PhysicalMax.QuadPart         = MAXULONG64;
    INT64            VMCSSize    = 2 * VMCS_SIZE;
    BYTE *           Buffer      = (BYTE *)MmAllocateContiguousMemory(VMCSSize + ALIGNMENT_PAGE_SIZE, PhysicalMax);
    PHYSICAL_ADDRESS Highest     = {0};
    Highest.QuadPart             = ~0;

    UINT64 PhysicalBuffer = VirtualToPhysicalAddress(Buffer);
    if (Buffer == NULL)
    {
        DbgPrint("[-] Can't Allocate Buffer for VMCS Region.\n");
        return FALSE;
    }

    RtlSecureZeroMemory(Buffer, VMCSSize + ALIGNMENT_PAGE_SIZE);
    UINT64 AlignedPhysicalBuffer = (ULONG_PTR)(PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1);
    UINT64 AlignedVirtualBuffer  = (ULONG_PTR)(Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1);

    DbgPrint("[*] Virtual allocated buffer for VMCS at %llx.\n", (ULONG64)Buffer);
    DbgPrint("[*] Virtual aligned allocated buffer for VMCS at %llx.\n", AlignedVirtualBuffer);
    DbgPrint("[*] Aligned physical buffer allocated for VMCS at %llx.\n", AlignedPhysicalBuffer);

    IA32_VMX_BASIC_MSR VmxBasic = {0};
    VmxBasic.All                = __readmsr(MSR_IA32_VMX_BASIC);

    DbgPrint("[*] MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier %llx.\n", (ULONG64)VmxBasic.Fields.RevisionIdentifier);

    *(UINT64 *)AlignedVirtualBuffer = VmxBasic.Fields.RevisionIdentifier;

    int Status = __vmx_vmptrld(&AlignedPhysicalBuffer);
    if (Status)
    {
        DbgPrint("[-] VMCS failed with status %d\n", Status);
        return FALSE;
    }

    GuestState->VmcsRegion = AlignedPhysicalBuffer;

    return TRUE;
}
