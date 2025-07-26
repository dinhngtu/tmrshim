#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

typedef struct _SHELLCODE_ARGS {
    union {
        PCWSTR DllPath;
        ULONG64 _DllPath;
    };
    union {
        PCSTR ShimFunction;
        ULONG64 _ShimFunction;
    };
    union {
        PCWSTR ShimFunctionArgs;
        ULONG64 _ShimFunctionArgs;
    };
} SHELLCODE_ARGS, * PSHELLCODE_ARGS;
