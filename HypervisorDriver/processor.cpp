#include "processor.h"
#include "msr.h"

BOOLEAN
IsVmxSupported()
{
    CPUID cpuid = {0};

    __cpuid((int *)&cpuid, 1);
    if (!(cpuid.eax & (1 << 5)))
        return FALSE;

    IA32_FEATURE_CONTROL_MSR Control = {0};
    Control.All                      = __readmsr(MSR_IA32_FEATURE_CONTROL);

    if (Control.Fields.Lock == 0)
    {
        Control.Fields.Lock        = 1;
        Control.Fields.EnableVmxon = 1;
        __writemsr(MSR_IA32_FEATURE_CONTROL, Control.All);
    }
    else if (Control.Fields.EnableVmxon == 0)
    {
        DbgPrint("[-] VMX locked off in BIOS.\n");
        return FALSE;
    }

    return TRUE;
}

int
MathPower(int Base, int Exponent)
{
    int Result = 1;

    for (;;)
    {
        if (Exponent & 1)
        {
            Result *= Base;
        }

        Exponent >>= 1;
        if (!Exponent)
        {
            break;
        }

        Base *= Base;
    }

    return Result;
}
