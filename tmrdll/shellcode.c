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

typedef struct _TMR_SHIMDATA {
    PCHAR K32Base;
    LoadLibraryWFunc ImpLoadLibraryW;
    GetProcAddressFunc ImpGetProcAddress;
    GetLastErrorFunc ImpGetLastError;
    CreateThreadFunc ImpCreateThread;
    CloseHandleFunc ImpCloseHandle;
    HMODULE ShimDll;
    PSHIMFUNC ShimFunc;
} TMR_SHIMDATA, * PTMR_SHIMDATA;

#pragma section(".shcode", read, execute)
#define SHELLCODE __declspec(code_seg(".shcode"))

static __forceinline SHELLCODE bool sc_memeq(PCSTR a, PCSTR b, size_t N) {
    if (!b)
        return false;
    for (size_t i = 0; i < N; i++)
        if (a[i] != b[i])
            return false;
    return true;
}

static __forceinline SHELLCODE bool sc_memcaseeqW(PCWSTR a, PCWSTR b, size_t N) {
    if (!b)
        return false;
    for (size_t i = 0; i < N; i++)
        if ((a[i] | 32) != (b[i] | 32))
            return false;
    return true;
}

static __forceinline SHELLCODE PPEB getpeb() {
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

static __forceinline SHELLCODE LSTATUS tmr_get_kernel32(_Out_ PVOID* pK32Base) {
    WCHAR sKernel32Dll[] = { L'k', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', 0 };

    PPEB ppeb = getpeb();
    PLIST_ENTRY link = ppeb->Ldr->InMemoryOrderModuleList.Flink;

    PCHAR k32Base = NULL;
    while (link) {
        PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(
            link,
            LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks);
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

_Ret_maybenull_ static SHELLCODE FARPROC tmr_get_function(
    _In_ PCHAR k32Base,
    _In_reads_(nameLen) PSTR wantedName,
    _In_ SIZE_T nameLen) {
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

static SHELLCODE LSTATUS tmr_get_shimdata(_In_ LPVOID arg, _Out_ PTMR_SHIMDATA shimData) {
    CHAR sLoadLibraryW[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'W', 0 };
    CHAR sGetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0 };
    CHAR sGetLastError[] = { 'G', 'e', 't', 'L', 'a', 's', 't', 'E', 'r', 'r', 'o', 'r', 0 };
    CHAR sCreateThread[] = { 'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 0 };
    CHAR sCloseHandle[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0 };
    DWORD err;

    PSHELLCODE_ARGS parg = (PSHELLCODE_ARGS)arg;
    err = tmr_get_kernel32(&shimData->K32Base);
    if (err != ERROR_SUCCESS) {
        TMR_DEBUGBREAK();
        return err;
    }

    shimData->ImpLoadLibraryW = (LoadLibraryWFunc)tmr_get_function(
        shimData->K32Base,
        sLoadLibraryW,
        ARRAYSIZE(sLoadLibraryW));
    if (!shimData->ImpLoadLibraryW) {
        TMR_DEBUGBREAK();
        return ERROR_INVALID_FUNCTION;
    }

    shimData->ImpGetProcAddress = (GetProcAddressFunc)tmr_get_function(
        shimData->K32Base,
        sGetProcAddress,
        ARRAYSIZE(sGetProcAddress));
    if (!shimData->ImpGetProcAddress) {
        TMR_DEBUGBREAK();
        return ERROR_INVALID_FUNCTION;
    }

    shimData->ImpGetLastError = (GetLastErrorFunc)tmr_get_function(
        shimData->K32Base,
        sGetLastError,
        ARRAYSIZE(sGetLastError));
    if (!shimData->ImpGetLastError) {
        TMR_DEBUGBREAK();
        return ERROR_INVALID_FUNCTION;
    }

    shimData->ImpCreateThread = (CreateThreadFunc)tmr_get_function(
        shimData->K32Base,
        sCreateThread,
        ARRAYSIZE(sCreateThread));
    if (!shimData->ImpCreateThread) {
        TMR_DEBUGBREAK();
        return ERROR_INVALID_FUNCTION;
    }

    shimData->ImpCloseHandle = (CloseHandleFunc)tmr_get_function(
        shimData->K32Base,
        sCloseHandle,
        ARRAYSIZE(sCloseHandle));
    if (!shimData->ImpCloseHandle) {
        TMR_DEBUGBREAK();
        return ERROR_INVALID_FUNCTION;
    }

    shimData->ShimDll = shimData->ImpLoadLibraryW(parg->PayloadPath);
    if (!shimData->ShimDll) {
        TMR_DEBUGBREAK();
        return shimData->ImpGetLastError();
    }

    shimData->ShimFunc = (PSHIMFUNC)shimData->ImpGetProcAddress(shimData->ShimDll, parg->ShimFunction);
    if (!shimData->ShimFunc) {
        TMR_DEBUGBREAK();
        return shimData->ImpGetLastError();
    }

    return ERROR_SUCCESS;
}

SHELLCODE DWORD WINAPI tmr_entry(_In_ LPVOID arg) {
    TMR_SHIMDATA shimData;
    LSTATUS err;

    if (!arg) {
        TMR_DEBUGBREAK();
        return ERROR_INVALID_PARAMETER;
    }

    err = tmr_get_shimdata(arg, &shimData);
    if (err != ERROR_SUCCESS) {
        TMR_DEBUGBREAK();
        return shimData.ImpGetLastError();
    }
    return shimData.ShimFunc(shimData.ShimDll, arg);
}

SHELLCODE VOID NTAPI tmr_entry_apc_direct(_In_ ULONG_PTR arg) {
    tmr_entry((PVOID)arg);
}

SHELLCODE VOID NTAPI tmr_entry_apc(_In_ ULONG_PTR arg) {
    TMR_SHIMDATA shimData;
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

    HANDLE newThread = shimData.ImpCreateThread(NULL, 0, parg->ThreadEntry, (PVOID)arg, 0, NULL);
    if (!newThread) {
        TMR_DEBUGBREAK();
        return;
    }
    shimData.ImpCloseHandle(newThread);
}
