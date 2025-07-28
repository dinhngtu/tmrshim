#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <stdlib.h>
#include <shellcode_abi.h>

void tmr_cleanup(HMODULE instance, PSHELLCODE_ARGS pi, DWORD exitcode);
