#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#define SHELLCODE_FLAG_EARLYBIRD 1U

typedef struct _SHELLCODE_ARGS {
    union {
        PVOID ShellcodeBase;
        ULONG64 _ShellcodeBase;
    };
    union {
        PCWSTR PayloadPath;
        ULONG64 _PayloadPath;
    };
    union {
        PCSTR ShimFunction;
        ULONG64 _ShimFunction;
    };
    union {
        PCWSTR ShimFunctionArgs;
        ULONG64 _ShimFunctionArgs;
    };
    DWORD Flags;
} SHELLCODE_ARGS, * PSHELLCODE_ARGS;

typedef DWORD(__cdecl SHIMFUNC)(HMODULE instance, PSHELLCODE_ARGS pi);
typedef SHIMFUNC* PSHIMFUNC;
