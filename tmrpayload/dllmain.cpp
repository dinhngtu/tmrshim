// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "shellcode_abi.h"

#pragma comment(lib, "Winmm.lib")

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved) {
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);

    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

DWORD __cdecl tmr_clockres(PSHELLCODE_ARGS pi) {
    TIMECAPS tc;

    UNREFERENCED_PARAMETER(pi);

    if (timeGetDevCaps(&tc, sizeof(tc)) != MMSYSERR_NOERROR)
        return ERROR_INVALID_PARAMETER;
    timeBeginPeriod(tc.wPeriodMin);
    Sleep(INFINITE);

    return ERROR_SUCCESS;
}

DWORD __cdecl tmr_msgbox(PSHELLCODE_ARGS pi) {
    MessageBoxW(NULL, pi->ShimFunctionArgs, L"Shim", MB_OK);
    return ERROR_SUCCESS;
}
