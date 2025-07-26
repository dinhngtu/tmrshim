#include "pch.h"
#include "loader.h"
#include "..\tmrdll\shellcode_abi.h"

static void PrintUsage(wchar_t* name) {
    wprintf(L"Usage: %s [--dllname <dllname>] [--entrypoint <entrypoint>] <pid> <func> <args>\n", name);
}

static std::vector<uint8_t> prepare_shellcode_args(
    PCWSTR dllPath,
    PCSTR shimFuncAscii,
    PCWSTR shimFuncArg,
    _Out_opt_ ULONG64* dllPathOffset = NULL,
    _Out_opt_ ULONG64* shimFuncNameOffset = NULL,
    _Out_opt_ ULONG64* shimFuncArgOffset = NULL) {
    std::vector<uint8_t> argBytes(sizeof(SHELLCODE_ARGS));

    if (dllPathOffset)
        *dllPathOffset = argBytes.size();

    argBytes.insert(argBytes.end(), (uint8_t*)dllPath, (uint8_t*)dllPath + (wcslen(dllPath) + 1) * sizeof(WCHAR));

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
    PCWSTR pid = NULL;
    PCWSTR dllName = NULL;
    PCWSTR entryPoint = L"shellcode";
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
        else if (!pid) {
            pid = argv[i];
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
    if (!pid || !shimFunc)
        goto help;
    if (!shimArgString)
        shimArgString = L"";

    try {
        if (argc < 2)
            throw std::invalid_argument("command line error");

        errno = 0;
        DWORD pid = wcstoul(argv[1], NULL, 0);
        if (errno)
            throw std::system_error(errno, std::generic_category(), "error parsing PID");

        auto hProcess = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            FALSE,
            pid);
        THROW_LAST_ERROR_IF_NULL_MSG(hProcess, "error opening process %lu", pid);

        USHORT targetMachine;
        auto dll = load_dll(hProcess, dllName, &targetMachine);

        std::wstring entryPointWide(entryPoint);
        std::string entryPointAscii(entryPointWide.begin(), entryPointWide.end());
        DWORD entryOffset, virtualSize;
        auto shellcodeSection = get_shellcode(dll.get(), entryPointAscii.c_str(), &entryOffset, &virtualSize);

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

        auto dllPath = wil::GetModuleFileNameW(dll.get());
        std::wstring shimFuncWide(shimFunc);
        std::string shimFuncAscii(shimFuncWide.begin(), shimFuncWide.end());

        ULONG64 dllPathOffset, shimFuncNameOffset, shimFuncArgOffset;
        std::vector<uint8_t> argBytes = prepare_shellcode_args(
            dllPath.get(),
            shimFuncAscii.c_str(),
            shimArgString,
            &dllPathOffset,
            &shimFuncNameOffset,
            &shimFuncArgOffset);

        auto argMem = VirtualAllocEx(
            hProcess,
            NULL,
            argBytes.size(),
            MEM_COMMIT,
            PAGE_EXECUTE_READ);
        THROW_LAST_ERROR_IF_NULL_MSG(shellcodeMem, "error allocating remote memory");

        SHELLCODE_ARGS realArgs = {
            ._DllPath = (ULONG64)argMem + dllPathOffset,
            ._ShimFunction = (ULONG64)argMem + shimFuncNameOffset,
            ._ShimFunctionArgs = (ULONG64)argMem + shimFuncArgOffset,
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

        THROW_LAST_ERROR_IF_NULL_MSG(
            CreateRemoteThread(
                hProcess,
                NULL,
                0,
                (LPTHREAD_START_ROUTINE)((ULONG_PTR)shellcodeMem + entryOffset),
                argMem,
                0,
                NULL),
            "error starting remote thread");

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
