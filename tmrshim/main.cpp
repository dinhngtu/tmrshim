#include "pch.h"
#include "loader.h"
#include <shellcode_abi.h>

#pragma comment(lib, "Pathcch.lib")

static void PrintUsage(wchar_t* name) {
    wprintf(
        L"Usage: %s "
        "[--dllname <dllname>] "
        "[--entrypoint <entrypoint>] "
        "[--entrypoint-early <entrypoint_early>] "
        "[--payloadname <payloadname>] "
        "[--nocleanup] "
        "<pid>|--earlybird <cmd> "
        "<func> [<funcarg>]\n", name);
}

static std::vector<uint8_t> prepare_shellcode_args(
    PCWSTR payloadPath,
    PCSTR shimFuncAscii,
    PCWSTR shimFuncArg,
    _Out_opt_ ULONG64* payloadPathOffset = NULL,
    _Out_opt_ ULONG64* shimFuncNameOffset = NULL,
    _Out_opt_ ULONG64* shimFuncArgOffset = NULL) {
    std::vector<uint8_t> argBytes(sizeof(SHELLCODE_ARGS));

    if (payloadPathOffset)
        *payloadPathOffset = argBytes.size();

    argBytes.insert(argBytes.end(), (uint8_t*)payloadPath, (uint8_t*)payloadPath + (wcslen(payloadPath) + 1) * sizeof(WCHAR));

    if (shimFuncNameOffset)
        *shimFuncNameOffset = argBytes.size();

    argBytes.insert(argBytes.end(), shimFuncAscii, shimFuncAscii + strlen(shimFuncAscii) + 1);
    argBytes.push_back(0);

    while (argBytes.size() % alignof(WCHAR) != 0)
        argBytes.push_back(0);

    if (shimFuncArgOffset)
        *shimFuncArgOffset = argBytes.size();

    argBytes.insert(argBytes.end(), (uint8_t*)shimFuncArg, (uint8_t*)shimFuncArg + (wcslen(shimFuncArg) + 1) * sizeof(WCHAR));

    return argBytes;
}

int wmain(int argc, wchar_t** argv) {
    PCWSTR dllName = NULL;
    PCWSTR entryPoint = NULL;
    PCWSTR entryPointEarly = NULL;
    PCWSTR payloadName = NULL;
    BOOL earlybird = FALSE;
    BOOL nocleanup = FALSE;
    PCWSTR target = NULL;
    PCWSTR shimFunc = NULL;
    PCWSTR shimArgString = NULL;

    for (int i = 1; i < argc; i++) {
        if (CompareStringOrdinal(L"--dllname", -1, argv[i], -1, TRUE) == CSTR_EQUAL) {
            if (i >= argc - 1)
                goto help;
            dllName = argv[++i];
        }
        else if (CompareStringOrdinal(L"--entrypoint", -1, argv[i], -1, TRUE) == CSTR_EQUAL) {
            if (i >= argc - 1)
                goto help;
            entryPoint = argv[++i];
        }
        else if (CompareStringOrdinal(L"--entrypoint-early", -1, argv[i], -1, TRUE) == CSTR_EQUAL) {
            if (i >= argc - 1)
                goto help;
            entryPointEarly = argv[++i];
        }
        else if (CompareStringOrdinal(L"--payloadname", -1, argv[i], -1, TRUE) == CSTR_EQUAL) {
            if (i >= argc - 1)
                goto help;
            payloadName = argv[++i];
        }
        else if (CompareStringOrdinal(L"--earlybird", -1, argv[i], -1, TRUE) == CSTR_EQUAL) {
            if (i >= argc - 1)
                goto help;
            target = argv[++i];
            earlybird = TRUE;
        }
        else if (CompareStringOrdinal(L"--nocleanup", -1, argv[i], -1, TRUE) == CSTR_EQUAL) {
            nocleanup = TRUE;
        }
        else if (!earlybird && !target) {
            target = argv[i];
        }
        else if (!shimFunc) {
            shimFunc = argv[i];
        }
        else if (!shimArgString) {
            shimArgString = argv[i];
        }
        else {
            goto help;
        }
    }
    if (!target || !shimFunc)
        goto help;
    if (!entryPoint)
        entryPoint = L"tmr_entry";
    if (earlybird && !entryPointEarly)
        entryPointEarly = L"tmr_entry_apc";
    if (!shimArgString)
        shimArgString = L"";

    try {
        if (argc < 2)
            throw std::invalid_argument("command line error");

        HANDLE hProcess;
        wil::unique_process_information pi; // earlybird
        if (earlybird) {
            std::wstring cmdline(target);
            STARTUPINFOW si{ sizeof(si) };
            THROW_IF_WIN32_BOOL_FALSE_MSG(
                CreateProcessW(
                    NULL,
                    cmdline.data(),
                    NULL,
                    NULL,
                    FALSE,
                    CREATE_SUSPENDED,
                    NULL,
                    NULL,
                    &si,
                    &pi),
                "can't create child process");
            hProcess = pi.hProcess;
        }
        else {
            errno = 0;
            DWORD pid = wcstoul(target, NULL, 0);
            if (errno)
                throw std::system_error(errno, std::generic_category(), "error parsing PID");

            hProcess = OpenProcess(
                PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                FALSE,
                pid);
            THROW_LAST_ERROR_IF_NULL_MSG(hProcess, "error opening process %lu", pid);
        }

        USHORT targetMachine;
        auto dll = load_dll(hProcess, dllName, &targetMachine);

        wil::unique_hlocal_string payloadPath;
        if (payloadName) {
            payloadPath = wil::make_hlocal_string(payloadName);
        }
        else {
            switch (targetMachine) {
            case IMAGE_FILE_MACHINE_I386:
                payloadName = L"tmrpayload.x86.dll";
                break;
            case IMAGE_FILE_MACHINE_AMD64:
                payloadName = L"tmrpayload.x64.dll";
                break;
            case IMAGE_FILE_MACHINE_ARM64:
                payloadName = L"tmrpayload.ARM64.dll";
                break;
            default:
                throw std::invalid_argument("unsupported machine");
            }

            auto exePath = wil::GetModuleFileNameW();
            size_t parentLen;
            if (!wil::try_get_parent_path_range(exePath.get(), &parentLen))
                throw std::runtime_error("cannot get app dir path");
            std::wstring parentPath(exePath.get(), exePath.get() + parentLen);
            PWSTR _payloadPath;
            THROW_IF_FAILED(PathAllocCombine(parentPath.c_str(), payloadName, PATHCCH_NONE, &_payloadPath));
            payloadPath = wil::unique_hlocal_string(_payloadPath);
        }

        std::wstring entryPointWide(entryPoint);
        std::string entryPointAscii(entryPointWide.begin(), entryPointWide.end());
        DWORD entryOffset, virtualSize;
        auto shellcodeSection = get_shellcode(dll.get(), entryPointAscii.c_str(), &entryOffset, &virtualSize);

        DWORD entryOffsetEarly = entryOffset;
        if (earlybird) {
            std::wstring entryPointEarlyWide(entryPointEarly);
            std::string entryPointEarlyAscii(entryPointEarlyWide.begin(), entryPointEarlyWide.end());
            auto shellcodeSectionEarly = get_shellcode(dll.get(), entryPointEarlyAscii.c_str(), &entryOffsetEarly, &virtualSize);
            if (shellcodeSection.data() != shellcodeSectionEarly.data())
                throw std::runtime_error("thread and early entry points are not in the same section");
        }

        auto shellcodeMem = VirtualAllocEx(
            hProcess,
            NULL,
            std::max(shellcodeSection.size_bytes(), (size_t)virtualSize),
            MEM_COMMIT,
            PAGE_EXECUTE_READ);
        THROW_LAST_ERROR_IF_NULL_MSG(shellcodeMem, "error allocating remote memory");

        SIZE_T written;
        THROW_IF_WIN32_BOOL_FALSE_MSG(
            WriteProcessMemory(
                hProcess,
                shellcodeMem,
                shellcodeSection.data(),
                shellcodeSection.size(),
                &written),
            "error writing remote shellcode");
        if (written != shellcodeSection.size_bytes())
            throw std::runtime_error("WriteProcessMemory didn't write enough data (shellcode)");

        std::wstring shimFuncWide(shimFunc);
        std::string shimFuncAscii(shimFuncWide.begin(), shimFuncWide.end());

        ULONG64 payloadPathOffset, shimFuncNameOffset, shimFuncArgOffset;
        std::vector<uint8_t> argBytes = prepare_shellcode_args(
            payloadPath.get(),
            shimFuncAscii.c_str(),
            shimArgString,
            &payloadPathOffset,
            &shimFuncNameOffset,
            &shimFuncArgOffset);

        auto argMem = VirtualAllocEx(
            hProcess,
            NULL,
            argBytes.size(),
            MEM_COMMIT,
            PAGE_READWRITE);
        THROW_LAST_ERROR_IF_NULL_MSG(argMem, "error allocating remote memory");

        SHELLCODE_ARGS realArgs = {
            ._ShellcodeBase = (ULONG64)shellcodeMem,
            ._ThreadEntry = earlybird ? (ULONG64)shellcodeMem + entryOffset : NULL,
            ._PayloadPath = (ULONG64)argMem + payloadPathOffset,
            ._ShimFunction = (ULONG64)argMem + shimFuncNameOffset,
            ._ShimFunctionArgs = (ULONG64)argMem + shimFuncArgOffset,
            .Flags = (earlybird ? SHELLCODE_FLAG_EARLYBIRD : 0U) |
                (nocleanup ? SHELLCODE_FLAG_NOCLEANUP : 0U),
        };
        memcpy(argBytes.data(), &realArgs, sizeof(realArgs));

        THROW_IF_WIN32_BOOL_FALSE_MSG(
            WriteProcessMemory(
                hProcess,
                argMem,
                argBytes.data(),
                argBytes.size(),
                &written),
            "error writing remote arg");
        if (written != argBytes.size())
            throw std::runtime_error("WriteProcessMemory didn't write enough data (args)");

        if (earlybird) {
            THROW_LAST_ERROR_IF_MSG(
                !QueueUserAPC(
                    (PAPCFUNC)((ULONG_PTR)shellcodeMem + entryOffsetEarly),
                    pi.hThread,
                    (ULONG_PTR)argMem),
                "error queuing APC");
            ResumeThread(pi.hThread);
        }
        else {
            HANDLE remoteThread = THROW_LAST_ERROR_IF_NULL_MSG(
                CreateRemoteThread(
                    hProcess,
                    NULL,
                    0,
                    (LPTHREAD_START_ROUTINE)((ULONG_PTR)shellcodeMem + entryOffset),
                    argMem,
                    0,
                    NULL),
                "error starting remote thread");
            CloseHandle(remoteThread);
        }

        return 0;
    }
    catch (const std::exception& ex) {
        wprintf(L"Error: %S\n", ex.what());
        return 1;
    }

help:
    PrintUsage(argv[0]);
    return 1;
}
