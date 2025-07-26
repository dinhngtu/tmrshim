#include "pch.h"
#include <intrin.h>

#pragma comment(lib, "Pathcch.lib")

wil::unique_mapview_ptr<> load_dll(_In_ HANDLE hProcess, _In_opt_ PCWSTR _dllName, _Outref_ wil::unique_hfile& file, _Outref_ wil::unique_handle& mapping, _Out_ PUSHORT targetMachine) {
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
        auto exePath = wil::GetModuleFileNameW();
        size_t parentLen;
        if (!wil::try_get_parent_path_range(exePath.get(), &parentLen))
            throw std::runtime_error("cannot resolve exe path");

        dllName = std::wstring(exePath.get(), exePath.get() + parentLen);
        dllName += L"\\tmrdll";

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

    file = wil::open_file(dllName.c_str());

    LARGE_INTEGER fileSize = { 0 };
    THROW_IF_WIN32_BOOL_FALSE_MSG(GetFileSizeEx(file.get(), &fileSize), "cannot get file size");
    if (fileSize.HighPart > 0 || fileSize.QuadPart == 0)
        throw std::invalid_argument("unacceptable file size");

    mapping = wil::unique_handle(CreateFileMappingW(
        file.get(),
        NULL,
        PAGE_READONLY,
        fileSize.HighPart,
        fileSize.LowPart,
        NULL));
    THROW_LAST_ERROR_IF_MSG(!mapping.is_valid(), "cannot create mapping");

    auto mapped = wil::unique_mapview_ptr<>(
        MapViewOfFile(
            mapping.get(),
            FILE_MAP_READ,
            0,
            0,
            fileSize.QuadPart));
    THROW_LAST_ERROR_IF_NULL_MSG(mapped.get(), "cannot map file");
    *targetMachine = processMachine;
    return mapped;
}

static void check(PVOID _mapped, SIZE_T mapsize, PVOID _p, SIZE_T slice, SIZE_T mul = 1) {
    ULONG_PTR mapped = (ULONG_PTR)_mapped, p = (ULONG_PTR)_p;
    if (mapped + mapsize < mapped)
        throw std::invalid_argument("mapping overflow");
    if (slice > MAXSIZE_T / mul)
        throw std::invalid_argument("slice overflow");
    auto slicesize = slice * mul;
    if (p < mapped || p > mapped + mapsize)
        throw std::invalid_argument("failed begin check");
    if ((p + slice) < p || (p + slice) > (mapped + mapsize))
        throw std::invalid_argument("failed end check");
}

static void check_off(PVOID _mapped, SIZE_T mapsize, ULONG_PTR o, SIZE_T slice, SIZE_T mul = 1) {
    ULONG_PTR p = (ULONG_PTR)_mapped + o;
    if (p < (ULONG_PTR)_mapped)
        throw std::invalid_argument("offset overflow");
    check(_mapped, mapsize, (PVOID)p, slice, mul);
}

std::span<const uint8_t> get_shellcode(_In_ PVOID mapped, _In_ SIZE_T mapSize, _In_ PCSTR entryPoint, _Out_ PDWORD entryOffset, _Out_ PDWORD virtualSize) {
    PCHAR base = (PCHAR)mapped;

    auto e_lfanew = ((PIMAGE_DOS_HEADER)base)->e_lfanew;
    if (e_lfanew < 0)
        throw std::invalid_argument("invalid e_lfanew");
    check_off(mapped, mapSize, (ULONG_PTR)e_lfanew, sizeof(PIMAGE_NT_HEADERS32));
    PIMAGE_NT_HEADERS32 _ntHdr = (PIMAGE_NT_HEADERS32)(base + e_lfanew);

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
        check_off(mapped, mapSize, (ULONG_PTR)e_lfanew, sizeof(PIMAGE_NT_HEADERS64));
        dirExport = &(((PIMAGE_NT_HEADERS64)_ntHdr)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
        sectionTable = (PIMAGE_SECTION_HEADER)(((PIMAGE_NT_HEADERS64)_ntHdr) + 1);
        break;
    }
    default:
        throw std::invalid_argument("unknown dll arch");
    }

    check(mapped, mapSize, sectionTable, _ntHdr->FileHeader.NumberOfSections, sizeof(WORD));
    for (WORD i = 0; i < _ntHdr->FileHeader.NumberOfSections; i++) {
        check_off(mapped, mapSize, sectionTable[i].PointerToRawData, sectionTable[i].SizeOfRawData);
    }

    if (!dirExport->VirtualAddress || dirExport->Size < sizeof(IMAGE_EXPORT_DIRECTORY))
        throw std::invalid_argument("cannot find entrypoint");
    PIMAGE_SECTION_HEADER exportSection = NULL;
    for (WORD i = 0; i < _ntHdr->FileHeader.NumberOfSections; i++) {
        DWORD sectionEnd = sectionTable[i].VirtualAddress + sectionTable[i].SizeOfRawData;
        if (dirExport->VirtualAddress >= sectionTable[i].VirtualAddress && dirExport->VirtualAddress < sectionEnd)
            exportSection = &sectionTable[i];
    }
    if (!exportSection)
        throw std::invalid_argument("cannot find dll section");
    auto exportPhysOff = dirExport->VirtualAddress - exportSection->VirtualAddress;
    check_off(mapped, mapSize, exportPhysOff, sizeof(IMAGE_EXPORT_DIRECTORY));

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + exportPhysOff);
    PDWORD nameTable = (PDWORD)(base + exports->AddressOfNames);
    PWORD nameOrdTable = (PWORD)(base + exports->AddressOfNameOrdinals);
    PDWORD funcTable = (PDWORD)(base + exports->AddressOfFunctions);
    DWORD funcOffset = MAXDWORD;
    check(mapped, mapSize, nameTable, exports->NumberOfNames, sizeof(DWORD));
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        PCHAR name = base + nameTable[i];
        check(mapped, mapSize, name, strlen(entryPoint) + 1);
        if (!strcmp(entryPoint, name)) {
            WORD ord = nameOrdTable[i];
            funcOffset = funcTable[ord];
        }
    }
    if (funcOffset == MAXDWORD)
        throw std::invalid_argument("cannot find entrypoint");

    PIMAGE_SECTION_HEADER entrySection = NULL;
    for (WORD i = 0; i < _ntHdr->FileHeader.NumberOfSections; i++) {
        DWORD sectionEnd = sectionTable[i].VirtualAddress + sectionTable[i].SizeOfRawData;
        if (funcOffset >= sectionTable[i].VirtualAddress && funcOffset < sectionEnd)
            entrySection = &sectionTable[i];
    }
    if (!entrySection)
        throw std::invalid_argument("cannot find dll section");

    *entryOffset = funcOffset - entrySection->VirtualAddress;
    *virtualSize = entrySection->Misc.VirtualSize;
    return std::span<const uint8_t>((const uint8_t*)mapped + entrySection->VirtualAddress, (size_t)entrySection->SizeOfRawData);
}
