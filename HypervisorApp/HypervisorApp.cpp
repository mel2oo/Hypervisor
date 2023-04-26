#include <iostream>
#include <conio.h>
#include <windows.h>
#include <strsafe.h>

#include "ioctl.h"

std::string GetCpuID()
{
	char        SysType[13];
	std::string CpuID;

	_asm {
		// Execute CPUID with EAX = 0 to get the CPU producer
		XOR EAX, EAX
		CPUID
		// MOV EBX to EAX and get the characters one by one by using shift out right bitwise operation.
		MOV EAX, EBX
		MOV SysType[0], AL
		MOV SysType[1], AH
		SHR EAX, 16
		MOV SysType[2], AL
		MOV SysType[3], AH
		// Get the second part the same way but these values are stored in EDX
		MOV EAX, EDX
		MOV SysType[4], AL
		MOV SysType[5], AH
		SHR EAX, 16
		MOV SysType[6], AL
		MOV SysType[7], AH
		// Get the third part
		MOV EAX, ECX
		MOV SysType[8], AL
		MOV SysType[9], AH
		SHR EAX, 16
		MOV SysType[10], AL
		MOV SysType[11], AH
		MOV SysType[12], 00
	}

	CpuID.assign(SysType, 12);
	return CpuID;
}

bool DetectVmxSupport()
{
	bool VMX = false;

	_asm {
		XOR    EAX, EAX
		INC    EAX
		CPUID
		BT     ECX, 0x5
		JC     VMXSupport
		VMXNotSupport :
		JMP     NopInstr
			VMXSupport :
		MOV    VMX, 0x1
			NopInstr :
			NOP
	}

	return VMX;
}

bool
TestIoctl(HANDLE Handle)
{
    char  OutputBuffer[1000];
    char  InputBuffer[1000];
    ULONG BytesReturned;
    BOOL  Result;

    //
    // Performing METHOD_BUFFERED
    //
    StringCbCopy(InputBuffer, sizeof(InputBuffer), "This String is from User Application; using METHOD_BUFFERED");

    printf("\nCalling DeviceIoControl METHOD_BUFFERED:\n");

    memset(OutputBuffer, 0, sizeof(OutputBuffer));

    Result = DeviceIoControl(Handle,
                             (DWORD)IOCTL_SIOCTL_METHOD_BUFFERED,
                             &InputBuffer,
                             (DWORD)strlen(InputBuffer) + 1,
                             &OutputBuffer,
                             sizeof(OutputBuffer),
                             &BytesReturned,
                             NULL);

    if (!Result)
    {
        printf("Error in DeviceIoControl : %d", GetLastError());
        return false;
    }
    printf("    OutBuffer (%d): %s\n", BytesReturned, OutputBuffer);

    //
    // Performing METHOD_NIETHER
    //

    printf("\nCalling DeviceIoControl METHOD_NEITHER\n");

    StringCbCopy(InputBuffer, sizeof(InputBuffer), "This String is from User Application; using METHOD_NEITHER");
    memset(OutputBuffer, 0, sizeof(OutputBuffer));

    Result = DeviceIoControl(Handle,
                             (DWORD)IOCTL_SIOCTL_METHOD_NEITHER,
                             &InputBuffer,
                             (DWORD)strlen(InputBuffer) + 1,
                             &OutputBuffer,
                             sizeof(OutputBuffer),
                             &BytesReturned,
                             NULL);

    if (!Result)
    {
        printf("Error in DeviceIoControl : %d\n", GetLastError());
        return false;
    }

    printf("    OutBuffer (%d): %s\n", BytesReturned, OutputBuffer);

    //
    // Performing METHOD_IN_DIRECT
    //

    printf("\nCalling DeviceIoControl METHOD_IN_DIRECT\n");

    StringCbCopy(InputBuffer, sizeof(InputBuffer), "This String is from User Application; using METHOD_IN_DIRECT");
    StringCbCopy(OutputBuffer, sizeof(OutputBuffer), "This String is from User Application in OutBuffer; using METHOD_IN_DIRECT");

    Result = DeviceIoControl(Handle,
                             (DWORD)IOCTL_SIOCTL_METHOD_IN_DIRECT,
                             &InputBuffer,
                             (DWORD)strlen(InputBuffer) + 1,
                             &OutputBuffer,
                             sizeof(OutputBuffer),
                             &BytesReturned,
                             NULL);

    if (!Result)
    {
        printf("Error in DeviceIoControl : %d", GetLastError());
        return false;
    }

    printf("    Number of bytes transfered from OutBuffer: %d\n",
           BytesReturned);

    //
    // Performing METHOD_OUT_DIRECT
    //

    printf("\nCalling DeviceIoControl METHOD_OUT_DIRECT\n");

    StringCbCopy(InputBuffer, sizeof(InputBuffer), "This String is from User Application; using METHOD_OUT_DIRECT");

    memset(OutputBuffer, 0, sizeof(OutputBuffer));

    Result = DeviceIoControl(Handle,
                             (DWORD)IOCTL_SIOCTL_METHOD_OUT_DIRECT,
                             &InputBuffer,
                             (DWORD)strlen(InputBuffer) + 1,
                             &OutputBuffer,
                             sizeof(OutputBuffer),
                             &BytesReturned,
                             NULL);

    if (!Result)
    {
        printf("Error in DeviceIoControl : %d", GetLastError());
        return false;
    }

    printf("    OutBuffer (%d): %s\n", BytesReturned, OutputBuffer);

    return true;
}


int main()
{
	std::string cpuid = GetCpuID();

	if (cpuid == "GenuineIntel")
	{
		printf("[*] The Processor virtualization technology is VT-x. \n");
	}
	else
	{
		printf("[*] This program is not designed to run in a non-VT-x environment !\n");
		return 1;
	}

	if (DetectVmxSupport())
	{
		printf("[*] VMX Operation is supported by your processor .\n");
	}
	else
	{
		printf("[*] VMX Operation is not supported by your processor .\n");
		return 1;
	}

	HANDLE hDevice = CreateFile(
		"\\\\.\\HypervisorDriver",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("[-] CreateFile Fail, 0x%x\n", GetLastError());
		return 1;
	}

	_getch();

    TestIoctl(hDevice);

    _getch();

	CloseHandle(hDevice);

	return 0;
}
