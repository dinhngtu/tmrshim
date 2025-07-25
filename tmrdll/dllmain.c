// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "shellcode_abi.h"

#pragma comment(lib, "Winmm.lib")

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

DWORD __cdecl ShimIncreaseTimerFrequency(PSHELLCODE_ARGS pi) {
    TIMECAPS tc;

    if (timeGetDevCaps(&tc, sizeof(tc)) != MMSYSERR_NOERROR)
        return ERROR_INVALID_PARAMETER;
    timeBeginPeriod(tc.wPeriodMin);
    Sleep(INFINITE);

    return ERROR_SUCCESS;
}
