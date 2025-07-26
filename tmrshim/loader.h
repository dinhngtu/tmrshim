#pragma once

#include "pch.h"

wil::unique_hmodule load_dll(_In_ HANDLE hProcess, _In_opt_ PCWSTR _dllName, _Outref_ wil::unique_hlocal_string& dllPath, _Out_ PUSHORT targetMachine);
std::span<const uint8_t> get_shellcode(_In_ HMODULE hModule, _In_ PCSTR entryPoint, _Out_ PDWORD entryOffset, _Out_ PDWORD virtualSize);
