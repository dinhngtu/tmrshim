#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

typedef struct _SHELLCODE_ARGS {
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
} SHELLCODE_ARGS, * PSHELLCODE_ARGS;
