#include <windows.h>
#include <winternl.h>

typedef NTSTATUS(WINAPI* NTQUERYINFOPROC64)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG_PTR       ReturnLength
);

// Paste your actual shellcode here
unsigned char shellcode[1] = {
    0x01
};
