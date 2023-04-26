#pragma once

#include <ntddk.h>
#include <intrin.h>

EXTERN_C
VOID AsmEnableVmxOperation(VOID);

BOOLEAN
IsVmxSupported();

int
MathPower(int Base, int Exponent);