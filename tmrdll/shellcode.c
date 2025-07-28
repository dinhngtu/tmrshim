#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <intrin.h>
#include "shellcode_abi.h"

#ifdef _DEBUG
#define TMR_DEBUGBREAK() __debugbreak()
#else
#define TMR_DEBUGBREAK() ((void)0)
#endif

typedef HMODULE(_Ret_maybenull_ WINAPI* LoadLibraryWFunc)(_In_ LPCWSTR lpLibFileName);
typedef FARPROC(WINAPI* GetProcAddressFunc)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);
typedef DWORD(_Check_return_ _Post_equals_last_error_ WINAPI* GetLastErrorFunc)(VOID);

#pragma section(".shcode", read, execute)

static __declspec(safebuffers, code_seg(".shcode")) __forceinline bool sc_streq(PCSTR a, PCSTR b, size_t N) {
    if (!b)
        return false;
    for (size_t i = 0; i < N; i++)
        if (a[i] != b[i])
            return false;
    return true;
}

static __declspec(safebuffers, code_seg(".shcode")) __forceinline bool sc_strcaseeqW(PCWSTR a, PCWSTR b, size_t N) {
    if (!b)
        return false;
    for (size_t i = 0; i < N; i++)
        if ((a[i] | 32) != (b[i] | 32))
            return false;
    return true;
}

static __declspec(safebuffers, code_seg(".shcode")) __forceinline PPEB getpeb() {
#if defined(_M_X64)
    return (PPEB)(__readgsqword(offsetof(TEB, ProcessEnvironmentBlock)));
#elif defined(_M_IX86)
    return (PPEB)(__readfsdword(offsetof(TEB, ProcessEnvironmentBlock)));
#elif defined(_M_ARM64)
    return ((PTEB)__getReg(18))->ProcessEnvironmentBlock;
#else
#error "unknown architecture"
#endif
}

__declspec(safebuffers, code_seg(".shcode"), noinline) DWORD WINAPI tmr_entry(_In_ LPVOID arg) {
    WCHAR sKernel32Dll[] = { L'k', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', 0 };
    CHAR sLoadLibraryW[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'W', 0 };
    CHAR sGetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0 };
    CHAR sGetLastError[] = { 'G', 'e', 't', 'L', 'a', 's', 't', 'E', 'r', 'r', 'o', 'r', 0 };

    if (!arg) {
        TMR_DEBUGBREAK();
        return ERROR_INVALID_PARAMETER;
    }

    PSHELLCODE_ARGS parg = (PSHELLCODE_ARGS)arg;
    PPEB ppeb = getpeb();
    PLIST_ENTRY link = ppeb->Ldr->InMemoryOrderModuleList.Flink;

    PCHAR k32Base = NULL;
    while (link) {
        PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (sc_strcaseeqW(sKernel32Dll, (&entry->FullDllName)[1].Buffer, ARRAYSIZE(sKernel32Dll))) {
            k32Base = (PCHAR)entry->DllBase;
            break;
        }
        link = link->Flink;
        if (link == ppeb->Ldr->InMemoryOrderModuleList.Flink)
            break;
    }
    if (!k32Base || ((PIMAGE_DOS_HEADER)k32Base)->e_magic != IMAGE_DOS_SIGNATURE) {
        TMR_DEBUGBREAK();
        return ERROR_INVALID_FUNCTION;
    }

    LoadLibraryWFunc fLoadLibraryW = NULL;
    GetProcAddressFunc fGetProcAddress = NULL;
    GetLastErrorFunc fGetLastError = NULL;

    PIMAGE_NT_HEADERS k32NtHdr = (PIMAGE_NT_HEADERS)(k32Base + ((PIMAGE_DOS_HEADER)k32Base)->e_lfanew);
    PIMAGE_DATA_DIRECTORY k32DirExport = &(k32NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    PIMAGE_EXPORT_DIRECTORY k32Exports = (PIMAGE_EXPORT_DIRECTORY)(k32Base + k32DirExport->VirtualAddress);
    PDWORD k32NameTable = (PDWORD)(k32Base + k32Exports->AddressOfNames);
    PWORD k32NameOrdTable = (PWORD)(k32Base + k32Exports->AddressOfNameOrdinals);
    PDWORD k32FuncTable = (PDWORD)(k32Base + k32Exports->AddressOfFunctions);
    for (DWORD i = 0; i < k32Exports->NumberOfNames; i++) {
        PCHAR name = k32Base + k32NameTable[i];
        if (!fLoadLibraryW && sc_streq(sLoadLibraryW, name, ARRAYSIZE(sLoadLibraryW))) {
            WORD ord = k32NameOrdTable[i];
            DWORD func = k32FuncTable[ord];
            fLoadLibraryW = (LoadLibraryWFunc)(k32Base + func);
        }
        else if (!fGetProcAddress && sc_streq(sGetProcAddress, name, ARRAYSIZE(sGetProcAddress))) {
            WORD ord = k32NameOrdTable[i];
            DWORD func = k32FuncTable[ord];
            fGetProcAddress = (GetProcAddressFunc)(k32Base + func);
        }
        else if (!fGetLastError && sc_streq(sGetLastError, name, ARRAYSIZE(sGetLastError))) {
            WORD ord = k32NameOrdTable[i];
            DWORD func = k32FuncTable[ord];
            fGetLastError = (GetLastErrorFunc)(k32Base + func);
        }
    }

    if (!fLoadLibraryW || !fGetProcAddress || !fGetLastError) {
        TMR_DEBUGBREAK();
        return ERROR_INVALID_FUNCTION;
    }

    HMODULE shimDll = fLoadLibraryW(parg->PayloadPath);
    if (!shimDll) {
        TMR_DEBUGBREAK();
        return fGetLastError();
    }
    PSHIMFUNC fShimFunc = (PSHIMFUNC)fGetProcAddress(shimDll, parg->ShimFunction);
    if (!fShimFunc) {
        TMR_DEBUGBREAK();
        return fGetLastError();
    }
    return fShimFunc(shimDll, parg);
}
