#include <windows.h>
#include <winternl.h>
#include <iostream>

typedef NTSTATUS(WINAPI* NTQUERYINFOPROC64)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG_PTR       ReturnLength
	);

//Paste your shellcode in here
unsigned char shellcode[1] = {
	0x01
};