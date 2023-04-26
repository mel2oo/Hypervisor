#include "driver.h"
#include "vmx.h"
#include "ept.h"

VOID
DriverUnload(PDRIVER_OBJECT pDriverObject)
{
    UNICODE_STRING SymbolicLinkName;

    DbgPrint("[*] Entry Hypervisor DriverUnload\n");

    RtlInitUnicodeString(&SymbolicLinkName, HYPERVISOR_SYMBOLIC_LINK_NAME);
    IoDeleteSymbolicLink(&SymbolicLinkName);

    IoDeleteDevice(pDriverObject->DeviceObject);
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    UNREFERENCED_PARAMETER(pRegistryPath);

    NTSTATUS       status        = STATUS_SUCCESS;
    PDEVICE_OBJECT pDeviceObject = NULL;
    UNICODE_STRING DeviceName, SymbolicLinkName;

    DbgPrint("[*] Entry Hypervisor Driver\n");

    RtlInitUnicodeString(&DeviceName, HYPERVISOR_DEVICE_NAME);
    RtlInitUnicodeString(&SymbolicLinkName, HYPERVISOR_SYMBOLIC_LINK_NAME);

    status = IoCreateDevice(
        pDriverObject,
        0,
        &DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &pDeviceObject);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[-] IoCreateDevice Failed, 0x%x\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[-] IoCreateSymbolicLink Failed, 0x%x\n", status);
        IoDeleteDevice(pDeviceObject);
        return status;
    }

    for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
    {
        pDriverObject->MajorFunction[i] = DispatchRoutine;
    }

    pDriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchRoutineCreate;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchRoutineClose;
    pDriverObject->MajorFunction[IRP_MJ_READ]           = DispatchRoutineRead;
    pDriverObject->MajorFunction[IRP_MJ_WRITE]          = DispatchRoutineWrite;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchRoutineDeviceControl;
    pDriverObject->DriverUnload                         = DriverUnload;

    if (InitializeEptp() == NULL)
    {
        DbgPrint("[-] EPT Initialization Failed.\n");
        IoDeleteSymbolicLink(&SymbolicLinkName);
        IoDeleteDevice(pDriverObject->DeviceObject);
        return STATUS_UNSUCCESSFUL;
    }

    return status;
}

NTSTATUS
DispatchRoutine(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    UNREFERENCED_PARAMETER(pDeviceObject);

    DbgPrint("[*] Enter DispatchRoutine\n");

    pIrp->IoStatus.Status      = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DispatchRoutineCreate(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    UNREFERENCED_PARAMETER(pDeviceObject);

    DbgPrint("[*] Enter DispatchRoutineCreate\n");

    if (InitializeVmx())
    {
        DbgPrint("[+] VMX Initiated Successfully.\n");
    }

    pIrp->IoStatus.Status      = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DispatchRoutineClose(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    UNREFERENCED_PARAMETER(pDeviceObject);

    DbgPrint("[*] Enter DispatchRoutineCreate\n");

    TerminateVmx();

    pIrp->IoStatus.Status      = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DispatchRoutineRead(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    UNREFERENCED_PARAMETER(pDeviceObject);

    DbgPrint("[*] Enter DispatchRoutineCreate\n");

    pIrp->IoStatus.Status      = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DispatchRoutineWrite(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    UNREFERENCED_PARAMETER(pDeviceObject);

    DbgPrint("[*] Enter DispatchRoutineCreate\n");

    pIrp->IoStatus.Status      = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DispatchRoutineDeviceControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    PIO_STACK_LOCATION pIrpStack    = NULL;
    NTSTATUS           status       = STATUS_SUCCESS;
    ULONG              InBufLength  = 0;
    ULONG              OutBufLength = 0;
    PCHAR              InBuf, OutBuf;

    UNREFERENCED_PARAMETER(pDeviceObject);

    PAGED_CODE();

    pIrpStack      = IoGetCurrentIrpStackLocation(pIrp);
    InBufLength    = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
    OutBufLength   = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
    PCHAR  Data    = "This String is from Device Driver !!!";
    size_t DataLen = strlen(Data) + 1;
    PMDL   Mdl     = NULL;
    PCHAR  Buffer  = NULL;

    if (!InBufLength || !OutBufLength)
    {
        status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    switch (pIrpStack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_SIOCTL_METHOD_BUFFERED:

        //
        // In this method the I/O manager allocates a buffer large enough to
        // to accommodate larger of the user input buffer and output buffer,
        // assigns the address to pIrp->AssociatedIrp.SystemBuffer, and
        // copies the content of the user input buffer into this SystemBuffer
        //

        DbgPrint("[*] =====> Called IOCTL_SIOCTL_METHOD_BUFFERED\n");
        PrintIrpInfo(pIrp);

        //
        // Input buffer and output buffer is same in this case, read the
        // content of the buffer before writing to it
        //

        InBuf  = (PCHAR)pIrp->AssociatedIrp.SystemBuffer;
        OutBuf = (PCHAR)pIrp->AssociatedIrp.SystemBuffer;

        //
        // Read the data from the buffer
        //

        DbgPrint("[*] Data from User :");
        //
        // We are using the following function to print characters instead
        // DebugPrint with %s format because we string we get may or
        // may not be null terminated.
        //
        DbgPrint(InBuf);
        PrintChars(InBuf, InBufLength);

        //
        // Write to the buffer over-writes the input buffer content
        //

        RtlCopyBytes(OutBuf, Data, OutBufLength);

        DbgPrint(("[*] Data to User : "));
        PrintChars(OutBuf, DataLen);

        //
        // Assign the length of the data copied to IoStatus.Information
        // of the pIrp and complete the pIrp.
        //

        pIrp->IoStatus.Information = (OutBufLength < DataLen ? OutBufLength : DataLen);

        //
        // When the pIrp is completed the content of the SystemBuffer
        // is copied to the User output buffer and the SystemBuffer is
        // is freed.
        //

        break;

    case IOCTL_SIOCTL_METHOD_NEITHER:

        //
        // In this type of transfer the I/O manager assigns the user input
        // to Type3InputBuffer and the output buffer to UserBuffer of the pIrp.
        // The I/O manager doesn't copy or map the buffers to the kernel
        // buffers. Nor does it perform any validation of user buffer's address
        // range.
        //

        DbgPrint("[*] =====> Called IOCTL_SIOCTL_METHOD_NEITHER\n");

        PrintIrpInfo(pIrp);

        //
        // A driver may access these buffers directly if it is a highest level
        // driver whose Dispatch routine runs in the context
        // of the thread that made this request. The driver should always
        // check the validity of the user buffer's address range and check whether
        // the appropriate read or write access is permitted on the buffer.
        // It must also wrap its accesses to the buffer's address range within
        // an exception handler in case another user thread deallocates the buffer
        // or attempts to change the access rights for the buffer while the driver
        // is accessing memory.
        //

        InBuf  = (PCHAR)pIrpStack->Parameters.DeviceIoControl.Type3InputBuffer;
        OutBuf = (PCHAR)pIrp->UserBuffer;

        //
        // Access the buffers directly if only if you are running in the
        // context of the calling process. Only top level drivers are
        // guaranteed to have the context of process that made the request.
        //

        __try
        {
            //
            // Before accessing user buffer, you must probe for read/write
            // to make sure the buffer is indeed an userbuffer with proper access
            // rights and length. ProbeForRead/Write will raise an exception if it's otherwise.
            //
            ProbeForRead(InBuf, InBufLength, sizeof(UCHAR));

            //
            // Since the buffer access rights can be changed or buffer can be freed
            // anytime by another thread of the same process, you must always access
            // it within an exception handler.
            //

            DbgPrint("[*] Data from User :");
            DbgPrint(InBuf);
            PrintChars(InBuf, InBufLength);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
            DbgPrint("[-] Exception while accessing InBuf 0X%08X in METHOD_NEITHER\n", status);
            break;
        }

        //
        // If you are accessing these buffers in an arbitrary thread context,
        // say in your DPC or ISR, if you are using it for DMA, or passing these buffers to the
        // next level driver, you should map them in the system process address space.
        // First allocate an MDL large enough to describe the buffer
        // and initilize it. Please note that on a x86 system, the maximum size of a buffer
        // that an MDL can describe is 65508 KB.
        //

        Mdl = IoAllocateMdl(InBuf, InBufLength, FALSE, TRUE, NULL);
        if (!Mdl)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        __try
        {
            //
            // Probe and lock the pages of this buffer in physical memory.
            // You can specify IoReadAccess, IoWriteAccess or IoModifyAccess
            // Always perform this operation in a try except block.
            //  MmProbeAndLockPages will raise an exception if it fails.
            //
            MmProbeAndLockPages(Mdl, UserMode, IoReadAccess);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
            DbgPrint("[-] Exception while locking InBuf 0X%08X in METHOD_NEITHER\n", status);
            IoFreeMdl(Mdl);
            break;
        }

        //
        // Map the physical pages described by the MDL into system space.
        // Note: double mapping the buffer this way causes lot of
        // system overhead for large size buffers.
        //

        Buffer = (PCHAR)MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority | MdlMappingNoExecute);

        if (!Buffer)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            MmUnlockPages(Mdl);
            IoFreeMdl(Mdl);
            break;
        }

        //
        // Now you can safely read the data from the buffer.
        //
        DbgPrint("[*] Data from User (SystemAddress) : ");
        DbgPrint(Buffer);
        DbgPrint("\n");
        PrintChars(Buffer, InBufLength);

        //
        // Once the read is over unmap and unlock the pages.
        //

        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);

        //
        // The same steps can be followed to access the output buffer.
        //

        Mdl = IoAllocateMdl(OutBuf, OutBufLength, FALSE, TRUE, NULL);
        if (!Mdl)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        __try
        {
            //
            // Probe and lock the pages of this buffer in physical memory.
            // You can specify IoReadAccess, IoWriteAccess or IoModifyAccess.
            //

            MmProbeAndLockPages(Mdl, UserMode, IoWriteAccess);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
            DbgPrint("[-] Exception while locking OutBuf 0X%08X in METHOD_NEITHER\n", status);
            IoFreeMdl(Mdl);
            break;
        }

        Buffer = (PCHAR)MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority | MdlMappingNoExecute);

        if (!Buffer)
        {
            MmUnlockPages(Mdl);
            IoFreeMdl(Mdl);
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        //
        // Write to the buffer
        //

        RtlCopyBytes(Buffer, Data, OutBufLength);

        DbgPrint("[*] Data to User : %s\n", Buffer);
        PrintChars(Buffer, DataLen);

        MmUnlockPages(Mdl);

        //
        // Free the allocated MDL
        //

        IoFreeMdl(Mdl);

        //
        // Assign the length of the data copied to IoStatus.Information
        // of the pIrp and complete the pIrp.
        //

        pIrp->IoStatus.Information = (OutBufLength < DataLen ? OutBufLength : DataLen);

        break;

    case IOCTL_SIOCTL_METHOD_IN_DIRECT:

        //
        // In this type of transfer,  the I/O manager allocates a system buffer
        // large enough to accommodatethe User input buffer, sets the buffer address
        // in pIrp->AssociatedIrp.SystemBuffer and copies the content of user input buffer
        // into the SystemBuffer. For the user output buffer, the  I/O manager
        // probes to see whether the virtual address is readable in the callers
        // access mode, locks the pages in memory and passes the pointer to
        // MDL describing the buffer in pIrp->MdlAddress.
        //

        DbgPrint("[*] =====> Called IOCTL_SIOCTL_METHOD_IN_DIRECT\n");

        PrintIrpInfo(pIrp);

        InBuf = (PCHAR)pIrp->AssociatedIrp.SystemBuffer;

        DbgPrint("[*] Data from User in InputBuffer: ");
        DbgPrint(InBuf);
        PrintChars(InBuf, InBufLength);

        //
        // To access the output buffer, just get the system address
        // for the buffer. For this method, this buffer is intended for transfering data
        // from the application to the driver.
        //

        Buffer = (PCHAR)MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);

        if (!Buffer)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        DbgPrint("[*] Data from User in OutputBuffer: ");
        DbgPrint(Buffer);
        PrintChars(Buffer, OutBufLength);

        //
        // Return total bytes read from the output buffer.
        // Note OutBufLength = MmGetMdlByteCount(pIrp->MdlAddress)
        //

        pIrp->IoStatus.Information = MmGetMdlByteCount(pIrp->MdlAddress);

        //
        // NOTE: Changes made to the  SystemBuffer are not copied
        // to the user input buffer by the I/O manager
        //

        break;

    case IOCTL_SIOCTL_METHOD_OUT_DIRECT:

        //
        // In this type of transfer, the I/O manager allocates a system buffer
        // large enough to accommodate the User input buffer, sets the buffer address
        // in pIrp->AssociatedIrp.SystemBuffer and copies the content of user input buffer
        // into the SystemBuffer. For the output buffer, the I/O manager
        // probes to see whether the virtual address is writable in the callers
        // access mode, locks the pages in memory and passes the pointer to MDL
        // describing the buffer in pIrp->MdlAddress.
        //

        DbgPrint("[*] =====> Called IOCTL_SIOCTL_METHOD_OUT_DIRECT\n");

        PrintIrpInfo(pIrp);

        InBuf = (PCHAR)pIrp->AssociatedIrp.SystemBuffer;

        DbgPrint("[*] Data from User : ");
        DbgPrint(InBuf);
        PrintChars(InBuf, InBufLength);

        //
        // To access the output buffer, just get the system address
        // for the buffer. For this method, this buffer is intended for transfering data
        // from the driver to the application.
        //

        Buffer = (PCHAR)MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);

        if (!Buffer)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        //
        // Write data to be sent to the user in this buffer
        //
        RtlCopyBytes(Buffer, Data, OutBufLength);

        DbgPrint("[*] Data to User : ");
        PrintChars(Buffer, DataLen);

        pIrp->IoStatus.Information = (OutBufLength < DataLen ? OutBufLength : DataLen);

        //
        // NOTE: Changes made to the  SystemBuffer are not copied
        // to the user input buffer by the I/O manager
        //
        break;

    default:

        //
        // The specified I/O control code is unrecognized by this driver.
        //
        status = STATUS_INVALID_DEVICE_REQUEST;
        DbgPrint("[-] unrecognized IOCTL %x\n", pIrpStack->Parameters.DeviceIoControl.IoControlCode);
        break;
    }

end:
    pIrp->IoStatus.Status = status;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return status;
}

VOID
PrintChars(
    PCHAR  BufferAddress,
    size_t CountChars)
{
    PAGED_CODE();

    if (CountChars)
    {
        while (CountChars--)
        {
            if (*BufferAddress > 31 && *BufferAddress != 127)
            {
                KdPrint(("%c", *BufferAddress));
            }
            else
            {
                KdPrint(("."));
            }
            BufferAddress++;
        }
        KdPrint(("\n"));
    }
    return;
}

VOID
PrintIrpInfo(
    PIRP pIrp)
{
    PIO_STACK_LOCATION pIrpStack;
    pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

    PAGED_CODE();

    DbgPrint("[*] Irp->AssociatedIrp.SystemBuffer = 0x%p\n",
             pIrp->AssociatedIrp.SystemBuffer);
    DbgPrint("[*] Irp->UserBuffer = 0x%p\n", pIrp->UserBuffer);
    DbgPrint("[*] IrpStack->Parameters.DeviceIoControl.Type3InputBuffer = 0x%p\n",
             pIrpStack->Parameters.DeviceIoControl.Type3InputBuffer);
    DbgPrint("[*] IrpStack->Parameters.DeviceIoControl.InputBufferLength = %d\n",
             pIrpStack->Parameters.DeviceIoControl.InputBufferLength);
    DbgPrint("[*] IrpStack->Parameters.DeviceIoControl.OutputBufferLength = %d\n",
             pIrpStack->Parameters.DeviceIoControl.OutputBufferLength);
    return;
}
