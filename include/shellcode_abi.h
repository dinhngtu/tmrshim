#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#define SHELLCODE_FLAG_EARLYBIRD 1U
#define SHELLCODE_FLAG_NOCLEANUP 2U

#define SHELLCODE_PTR(type, name) \
    union { \
        type name; \
        ULONG64 _##name; \
    }

typedef struct _SHELLCODE_ARGS {
    SHELLCODE_PTR(PVOID, ShellcodeBase);
    SHELLCODE_PTR(PCWSTR, PayloadPath);
    SHELLCODE_PTR(PCSTR, ShimFunction);
    SHELLCODE_PTR(PCWSTR, ShimFunctionArgs);
    DWORD Flags;
} SHELLCODE_ARGS, * PSHELLCODE_ARGS;

typedef DWORD(__cdecl SHIMFUNC)(HMODULE instance, PSHELLCODE_ARGS pi);
typedef SHIMFUNC* PSHIMFUNC;
