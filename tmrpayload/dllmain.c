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

static void tmr_cleanup(HMODULE instance, PSHELLCODE_ARGS pi, DWORD exitcode) {
    DWORD earlybird = pi->Flags & SHELLCODE_FLAG_EARLYBIRD;
    // if earlybird, must keep the shellcode return path alive since we still need to return from the APC
    // this means the earlybird shellcode memory and payload dll will be leaked
    if (!earlybird)
        VirtualFree(pi->ShellcodeBase, 0, MEM_RELEASE);
    VirtualFree(pi, 0, MEM_RELEASE);
    if (!earlybird)
        FreeLibraryAndExitThread(instance, exitcode);
}

SHIMFUNC tmr_clockres;
DWORD __cdecl tmr_clockres(HMODULE instance, PSHELLCODE_ARGS pi) {
    TIMECAPS tc;
    DWORD result = ERROR_SUCCESS;

    UNREFERENCED_PARAMETER(pi);

    if (timeGetDevCaps(&tc, sizeof(tc)) != MMSYSERR_NOERROR) {
        result = ERROR_INVALID_PARAMETER;
        goto cleanup;
    }
    timeBeginPeriod(tc.wPeriodMin);
    Sleep(INFINITE);

cleanup:
    tmr_cleanup(instance, pi, result);
}

SHIMFUNC tmr_msgbox;
DWORD __cdecl tmr_msgbox(HMODULE instance, PSHELLCODE_ARGS pi) {
    MessageBoxW(NULL, pi->ShimFunctionArgs, L"Shim", MB_OK);

    tmr_cleanup(instance, pi, ERROR_SUCCESS);
}
