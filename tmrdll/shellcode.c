#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <intrin.h>
#include <shellcode_abi.h>

#ifdef _DEBUG
#define TMR_DEBUGBREAK() __debugbreak()
#else
#define TMR_DEBUGBREAK() ((void)0)
#endif

typedef HMODULE(_Ret_maybenull_ WINAPI* LoadLibraryWFunc)(_In_ LPCWSTR lpLibFileName);
typedef FARPROC(WINAPI* GetProcAddressFunc)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);
typedef DWORD(_Check_return_ _Post_equals_last_error_ WINAPI* GetLastErrorFunc)(VOID);
typedef HANDLE(_Ret_maybenull_ WINAPI* CreateThreadFunc)(
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ SIZE_T dwStackSize,
    _In_ LPTHREAD_START_ROUTINE lpStartAddress,
    _In_opt_ __drv_aliasesMem LPVOID lpParameter,
    _In_ DWORD dwCreationFlags,
    _Out_opt_ LPDWORD lpThreadId
    );
typedef BOOL(WINAPI* CloseHandleFunc)(_In_ _Post_ptr_invalid_ HANDLE hObject);

struct tmr_shimdata {
    PCHAR k32Base;
    LoadLibraryWFunc fLoadLibraryW;
    GetProcAddressFunc fGetProcAddress;
    GetLastErrorFunc fGetLastError;
    CreateThreadFunc fCreateThread;
    CloseHandleFunc fCloseHandle;
    HMODULE shimDll;
    PSHIMFUNC shimFunc;
};

#pragma section(".shcode", read, execute)

static __declspec(code_seg(".shcode")) __forceinline bool sc_memeq(PCSTR a, PCSTR b, size_t N) {
    if (!b)
        return false;
    for (size_t i = 0; i < N; i++)
        if (a[i] != b[i])
            return false;
    return true;
}

static __declspec(code_seg(".shcode")) __forceinline bool sc_memcaseeqW(PCWSTR a, PCWSTR b, size_t N) {
    if (!b)
        return false;
    for (size_t i = 0; i < N; i++)
        if ((a[i] | 32) != (b[i] | 32))
            return false;
    return true;
}

static __declspec(code_seg(".shcode")) __forceinline PPEB getpeb() {
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

static __declspec(code_seg(".shcode")) __forceinline LSTATUS tmr_get_kernel32(_Out_ PVOID* pK32Base) {
    WCHAR sKernel32Dll[] = { L'k', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', 0 };

    PPEB ppeb = getpeb();
    PLIST_ENTRY link = ppeb->Ldr->InMemoryOrderModuleList.Flink;

    PCHAR k32Base = NULL;
    while (link) {
        PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (sc_memcaseeqW(sKernel32Dll, (&entry->FullDllName)[1].Buffer, ARRAYSIZE(sKernel32Dll))) {
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

    *pK32Base = k32Base;
    return ERROR_SUCCESS;
}

_Ret_maybenull_ static FARPROC tmr_get_function(PCHAR k32Base, PSTR wantedName, SIZE_T nameLen) {
    FARPROC fun = NULL;

    PIMAGE_NT_HEADERS k32NtHdr = (PIMAGE_NT_HEADERS)(k32Base + ((PIMAGE_DOS_HEADER)k32Base)->e_lfanew);
    PIMAGE_DATA_DIRECTORY k32DirExport = &(k32NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    PIMAGE_EXPORT_DIRECTORY k32Exports = (PIMAGE_EXPORT_DIRECTORY)(k32Base + k32DirExport->VirtualAddress);
    PDWORD k32NameTable = (PDWORD)(k32Base + k32Exports->AddressOfNames);
    PWORD k32NameOrdTable = (PWORD)(k32Base + k32Exports->AddressOfNameOrdinals);
    PDWORD k32FuncTable = (PDWORD)(k32Base + k32Exports->AddressOfFunctions);
    for (DWORD i = 0; i < k32Exports->NumberOfNames; i++) {
        PCHAR name = k32Base + k32NameTable[i];
        if (!fun && sc_memeq(wantedName, name, nameLen)) {
            WORD ord = k32NameOrdTable[i];
            DWORD func = k32FuncTable[ord];
            fun = (FARPROC)(k32Base + func);
        }
    }

    return fun;
}

__declspec(code_seg(".shcode")) static LSTATUS tmr_get_shimdata(_In_ LPVOID arg, _Out_ struct tmr_shimdata* shimData) {
    CHAR sLoadLibraryW[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'W', 0 };
    CHAR sGetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0 };
    CHAR sGetLastError[] = { 'G', 'e', 't', 'L', 'a', 's', 't', 'E', 'r', 'r', 'o', 'r', 0 };
    CHAR sCreateThread[] = { 'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 0 };
    CHAR sCloseHandle[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0 };
    DWORD err;

    PSHELLCODE_ARGS parg = (PSHELLCODE_ARGS)arg;
    err = tmr_get_kernel32(&shimData->k32Base);
    if (err != ERROR_SUCCESS) {
        TMR_DEBUGBREAK();
        return err;
    }

    shimData->fLoadLibraryW = (LoadLibraryWFunc)tmr_get_function(shimData->k32Base, sLoadLibraryW, ARRAYSIZE(sLoadLibraryW));
    if (!shimData->fLoadLibraryW) {
        TMR_DEBUGBREAK();
        return ERROR_INVALID_FUNCTION;
    }

    shimData->fGetProcAddress = (GetProcAddressFunc)tmr_get_function(shimData->k32Base, sGetProcAddress, ARRAYSIZE(sGetProcAddress));
    if (!shimData->fGetProcAddress) {
        TMR_DEBUGBREAK();
        return ERROR_INVALID_FUNCTION;
    }

    shimData->fGetLastError = (GetLastErrorFunc)tmr_get_function(shimData->k32Base, sGetLastError, ARRAYSIZE(sGetLastError));
    if (!shimData->fGetLastError) {
        TMR_DEBUGBREAK();
        return ERROR_INVALID_FUNCTION;
    }

    shimData->fCreateThread = (CreateThreadFunc)tmr_get_function(shimData->k32Base, sCreateThread, ARRAYSIZE(sCreateThread));
    if (!shimData->fCreateThread) {
        TMR_DEBUGBREAK();
        return ERROR_INVALID_FUNCTION;
    }

    shimData->fCloseHandle = (CloseHandleFunc)tmr_get_function(shimData->k32Base, sCloseHandle, ARRAYSIZE(sCloseHandle));
    if (!shimData->fCloseHandle) {
        TMR_DEBUGBREAK();
        return ERROR_INVALID_FUNCTION;
    }

    shimData->shimDll = shimData->fLoadLibraryW(parg->PayloadPath);
    if (!shimData->shimDll) {
        TMR_DEBUGBREAK();
        return shimData->fGetLastError();
    }

    shimData->shimFunc = (PSHIMFUNC)shimData->fGetProcAddress(shimData->shimDll, parg->ShimFunction);
    if (!shimData->shimFunc) {
        TMR_DEBUGBREAK();
        return shimData->fGetLastError();
    }

    return ERROR_SUCCESS;
}

__declspec(code_seg(".shcode")) DWORD WINAPI tmr_entry(_In_ LPVOID arg) {
    struct tmr_shimdata shimData;
    LSTATUS err;

    if (!arg) {
        TMR_DEBUGBREAK();
        return ERROR_INVALID_PARAMETER;
    }

    err = tmr_get_shimdata(arg, &shimData);
    if (err != ERROR_SUCCESS) {
        TMR_DEBUGBREAK();
        return shimData.fGetLastError();
    }
    return shimData.shimFunc(shimData.shimDll, arg);
}

__declspec(code_seg(".shcode")) VOID NTAPI tmr_entry_apc_direct(_In_ ULONG_PTR arg) {
    tmr_entry((PVOID)arg);
}

__declspec(code_seg(".shcode")) VOID NTAPI tmr_entry_apc(_In_ ULONG_PTR arg) {
    struct tmr_shimdata shimData;
    LSTATUS err;

    if (!arg) {
        TMR_DEBUGBREAK();
        return;
    }

    PSHELLCODE_ARGS parg = (PSHELLCODE_ARGS)arg;

    err = tmr_get_shimdata((PVOID)arg, &shimData);
    if (err != ERROR_SUCCESS) {
        TMR_DEBUGBREAK();
        return;
    }

    HANDLE newThread = shimData.fCreateThread(NULL, 0, parg->ThreadEntry, (PVOID)arg, 0, NULL);
    if (!newThread) {
        TMR_DEBUGBREAK();
        return;
    }
    shimData.fCloseHandle(newThread);
}
