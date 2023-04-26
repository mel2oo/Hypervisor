#include "vmx.h"
#include "memory.h"
#include "processor.h"

#pragma warning(disable : 4996)
#pragma warning(disable : 6385)

VIRTUAL_MACHINE_STATE * g_GuestState;
int                     g_ProcessorCounts;

BOOLEAN
InitializeVmx()
{
    if (!IsVmxSupported())
    {
        DbgPrint("[-] VMX is not supported.\n");
        return FALSE;
    }

    g_ProcessorCounts = KeQueryActiveProcessorCount(0);

    g_GuestState = (VIRTUAL_MACHINE_STATE *)ExAllocatePoolWithTag(NonPagedPool,
                                                                  sizeof(VIRTUAL_MACHINE_STATE) * g_ProcessorCounts,
                                                                  POOLTAG);

    if (g_GuestState == NULL)
    {
        DbgPrint("[-] Can't Allocate Buffer for GuestState.\n");
        return FALSE;
    }

    DbgPrint("[*] =====================================================\n");

    KAFFINITY AffinityMask = 0;
    for (int i = 0; i < g_ProcessorCounts; i++)
    {
        AffinityMask = MathPower(2, i);

        KeSetSystemAffinityThread(AffinityMask);
        DbgPrint("[*] Current thread is executing in processor %d.\n", i);

        AsmEnableVmxOperation();
        DbgPrint("[+] VMX Operation Enabled Successfully!\n");

        AllocateVmxonRegion(&g_GuestState[i]);
        AllocateVmcsRegion(&g_GuestState[i]);

        DbgPrint("[*] VMCS Region is allocated at [%llx].\n", (g_GuestState[i].VmcsRegion));
        DbgPrint("[*] VMXON Region is allocated at [%llx].\n", (g_GuestState[i].VmxonRegion));

        DbgPrint("[*] =====================================================\n");
    }

    return TRUE;
}

VOID
TerminateVmx()
{
    DbgPrint("[*] Terminating VMX...\n");

    KAFFINITY AffinityMask;
    for (int i = 0; i < g_ProcessorCounts; i++)
    {
        AffinityMask = MathPower(2, i);
        KeSetSystemAffinityThread(AffinityMask);
        DbgPrint("[*] Current thread is executing in %d th logical processor.\n", i);

        __vmx_off();
        MmFreeContiguousMemory((PVOID)PhysicalToVirtualAddress(g_GuestState[i].VmxonRegion));
        MmFreeContiguousMemory((PVOID)PhysicalToVirtualAddress(g_GuestState[i].VmcsRegion));
    }

    DbgPrint("[+] VMX Operation turned off successfully.\n");
}
