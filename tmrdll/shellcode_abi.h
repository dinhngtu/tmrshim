#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

typedef struct _SHELLCODE_ARGS {
    PCWSTR DllPath;
    PCSTR EntryPoint;
    PVOID EntryPointArgs;
} SHELLCODE_ARGS, * PSHELLCODE_ARGS;
