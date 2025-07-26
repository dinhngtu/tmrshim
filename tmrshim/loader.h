#pragma once

#include "pch.h"

wil::unique_mapview_ptr<> load_dll(_In_ HANDLE hProcess, _In_opt_ PCWSTR _dllName, _Outref_ wil::unique_hfile& file, _Outref_ wil::unique_handle& mapping, _Out_ PUSHORT targetMachine);
std::span<const uint8_t> get_shellcode(_In_ PVOID mapped, _In_ SIZE_T mapSize, _In_ PCSTR entryPoint, _Out_ PDWORD entryOffset, _Out_ PDWORD virtualSize);
