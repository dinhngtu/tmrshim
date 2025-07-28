#include "dogwalk.h"

typedef struct _TMR_APC_CLEANUP {
    HMODULE instance;
    PSHELLCODE_ARGS pi;
    // the thread that ran the entry APC
    HANDLE target;
} TMR_APC_CLEANUP, * PTMR_APC_CLEANUP;

// the final cleanup/exitthread
static DECLSPEC_NORETURN void do_tmr_cleanup(HMODULE instance, PSHELLCODE_ARGS pi, DWORD exitcode) {
    VirtualFree(pi->ShellcodeBase, 0, MEM_RELEASE);
    VirtualFree(pi, 0, MEM_RELEASE);
    FreeLibraryAndExitThread(instance, exitcode);
}

static DWORD WINAPI tmr_cleanup_worker(LPVOID _arg) {
    TMR_APC_CLEANUP arg = *(PTMR_APC_CLEANUP)_arg;

    // there's no safe way to ensure no injected APC is running,
    // so we just wait for the original main thread to die
    // this means by default the injected DLL gets unloaded when the main thread exits!
    WaitForSingleObject(arg.target, INFINITE);
    CloseHandle(arg.target);
    free(_arg);
    do_tmr_cleanup(arg.instance, arg.pi, ERROR_SUCCESS);
}

static void tmr_prepare_cleanup_earlybird(HMODULE instance, PSHELLCODE_ARGS pi) {
    PTMR_APC_CLEANUP cleanup = calloc(1, sizeof(*cleanup));
    if (!cleanup)
        goto fail_calloc;

    cleanup->instance = instance;
    cleanup->pi = pi;
    if (!DuplicateHandle(
        GetCurrentProcess(),
        GetCurrentThread(),
        GetCurrentProcess(),
        &cleanup->target,
        0,
        FALSE,
        DUPLICATE_SAME_ACCESS))
        goto fail_dup;

    HANDLE cleanup_thread = CreateThread(
        NULL,
        0,
        &tmr_cleanup_worker,
        cleanup,
        0,
        NULL);
    if (cleanup_thread == NULL)
        goto fail_createthread;

    CloseHandle(cleanup_thread);
    return;

fail_createthread:
    CloseHandle(cleanup->target);

fail_dup:
    free(cleanup);

fail_calloc:
    return;
}

void tmr_cleanup(HMODULE instance, PSHELLCODE_ARGS pi, DWORD exitcode) {
    if (pi->Flags & SHELLCODE_FLAG_NOCLEANUP)
        return;
    if (pi->Flags & SHELLCODE_FLAG_EARLYBIRD)
        tmr_prepare_cleanup_earlybird(instance, pi);
    else
        do_tmr_cleanup(instance, pi, exitcode);
}
