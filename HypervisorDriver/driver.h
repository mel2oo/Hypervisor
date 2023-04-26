#pragma once

#include <ntddk.h>

#define HYPERVISOR_DEVICE_NAME        L"\\Device\\HypervisorDriver"
#define HYPERVISOR_SYMBOLIC_LINK_NAME L"\\DosDevices\\HypervisorDriver"

EXTERN_C
VOID
DriverUnload(PDRIVER_OBJECT pDriverObject);

EXTERN_C
NTSTATUS
DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);

EXTERN_C
NTSTATUS
DispatchRoutine(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);

EXTERN_C
NTSTATUS
DispatchRoutineCreate(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);

EXTERN_C
NTSTATUS
DispatchRoutineClose(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);

EXTERN_C
NTSTATUS
DispatchRoutineRead(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);

EXTERN_C
NTSTATUS
DispatchRoutineWrite(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);

EXTERN_C
NTSTATUS
DispatchRoutineDeviceControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);

VOID
PrintChars(PCHAR BufferAddress, size_t CountChars);
VOID
PrintIrpInfo(PIRP pIrp);

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)
#pragma alloc_text(PAGE, DispatchRoutine)
#pragma alloc_text(PAGE, DispatchRoutineCreate)
#pragma alloc_text(PAGE, DispatchRoutineClose)
#pragma alloc_text(PAGE, DispatchRoutineRead)
#pragma alloc_text(PAGE, DispatchRoutineWrite)
#pragma alloc_text(PAGE, DispatchRoutineDeviceControl)

#define SIOCTL_TYPE 40000

#define IOCTL_SIOCTL_METHOD_IN_DIRECT \
    CTL_CODE(SIOCTL_TYPE, 0x900, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define IOCTL_SIOCTL_METHOD_OUT_DIRECT \
    CTL_CODE(SIOCTL_TYPE, 0x901, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define IOCTL_SIOCTL_METHOD_BUFFERED \
    CTL_CODE(SIOCTL_TYPE, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SIOCTL_METHOD_NEITHER \
    CTL_CODE(SIOCTL_TYPE, 0x903, METHOD_NEITHER, FILE_ANY_ACCESS)