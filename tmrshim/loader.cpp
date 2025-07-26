#include "pch.h"
#include <intrin.h>

wil::unique_hmodule load_dll(_In_ HANDLE hProcess, _In_opt_ PCWSTR _dllName, _Out_ PUSHORT targetMachine) {
    USHORT processMachine, nativeMachine;

    if (!IsWow64Process2(hProcess, &processMachine, &nativeMachine))
        throw std::system_error(GetLastError(), std::system_category(), "error reading process arch");

    std::wstring dllName;
    if (processMachine == IMAGE_FILE_MACHINE_UNKNOWN)
        processMachine = nativeMachine;
    if (_dllName) {
        dllName = _dllName;
    }
    else {
        dllName = L"tmrdll";
        switch (processMachine) {
        case IMAGE_FILE_MACHINE_I386:
            dllName += L".x86.dll";
            break;
        case IMAGE_FILE_MACHINE_AMD64:
            dllName += L".x64.dll";
            break;
        case IMAGE_FILE_MACHINE_ARM64:
            dllName += L"ARM64.dll";
            break;
        }
    }

    auto hModule = LoadLibraryW(dllName.c_str());
    THROW_LAST_ERROR_IF_NULL_MSG(hModule, "error loading target dll '%s'", dllName.c_str());
    *targetMachine = processMachine;
    return wil::unique_hmodule(hModule);
}

std::span<const uint8_t> get_shellcode(_In_ HMODULE hModule, _In_ PCSTR entryPoint, _Out_ PDWORD entryOffset, _Out_ PDWORD virtualSize) {
    PCHAR base = (PCHAR)((ULONG_PTR)hModule & ~(ULONG_PTR)3);

    PIMAGE_NT_HEADERS32 _ntHdr = (PIMAGE_NT_HEADERS32)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);

    PIMAGE_DATA_DIRECTORY dirExport;
    PIMAGE_SECTION_HEADER sectionTable;
    switch (_ntHdr->FileHeader.Machine) {
    case IMAGE_FILE_MACHINE_I386: {
        dirExport = &(((PIMAGE_NT_HEADERS32)_ntHdr)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
        sectionTable = (PIMAGE_SECTION_HEADER)(((PIMAGE_NT_HEADERS32)_ntHdr) + 1);
        break;
    }
    case IMAGE_FILE_MACHINE_AMD64:
    case IMAGE_FILE_MACHINE_ARM64: {
        dirExport = &(((PIMAGE_NT_HEADERS64)_ntHdr)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
        sectionTable = (PIMAGE_SECTION_HEADER)(((PIMAGE_NT_HEADERS64)_ntHdr) + 1);
        break;
    }
    default:
        throw std::invalid_argument("unknown dll arch");
    }

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + dirExport->VirtualAddress);
    PDWORD nameTable = (PDWORD)(base + exports->AddressOfNames);
    PWORD nameOrdTable = (PWORD)(base + exports->AddressOfNameOrdinals);
    PDWORD funcTable = (PDWORD)(base + exports->AddressOfFunctions);
    DWORD funcOffset = MAXDWORD;
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        PCHAR name = base + nameTable[i];
        if (!strcmp(entryPoint, name)) {
            WORD ord = nameOrdTable[i];
            funcOffset = funcTable[ord];
        }
    }
    if (funcOffset == MAXDWORD)
        throw std::invalid_argument("cannot find entrypoint");

    PIMAGE_SECTION_HEADER section = NULL;
    for (WORD i = 0; i < _ntHdr->FileHeader.NumberOfSections; i++) {
        DWORD sectionEnd = sectionTable[i].VirtualAddress + sectionTable[i].SizeOfRawData;
        if (sectionEnd < sectionTable[i].VirtualAddress)
            continue;
        if (funcOffset >= sectionTable[i].VirtualAddress && funcOffset < sectionEnd)
            section = &sectionTable[i];
    }
    if (!section)
        throw std::invalid_argument("cannot find dll section");

    *entryOffset = funcOffset - section->VirtualAddress;
    *virtualSize = section->Misc.VirtualSize;
    return std::span<const uint8_t>((const uint8_t*)hModule + section->VirtualAddress, (size_t)section->SizeOfRawData);
}
