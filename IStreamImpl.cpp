#include "IStreamImpl.h"
#include <string.h>

namespace ImpersonatePPPotato {

IStreamImpl::IStreamImpl(const BYTE* pData, DWORD cbData)
    : m_pos(0)
    , m_lRefCount(1)
{
    m_pData = new BYTE[cbData];
    memcpy(m_pData, pData, cbData);
    m_cbData = cbData;
}

IStreamImpl::~IStreamImpl() {
    if (m_pData) {
        delete[] m_pData;
        m_pData = nullptr;
    }
}

HRESULT STDMETHODCALLTYPE IStreamImpl::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    *ppv = nullptr;

    if (riid == IID_IUnknown) {
        *ppv = static_cast<IUnknown*>(this);
    }
    else if (riid == IID_IStream) {
        *ppv = static_cast<IStream*>(this);
    }
    else {
        return E_NOINTERFACE;
    }

    AddRef();
    return S_OK;
}

ULONG STDMETHODCALLTYPE IStreamImpl::AddRef() {
    return InterlockedIncrement(&m_lRefCount);
}

ULONG STDMETHODCALLTYPE IStreamImpl::Release() {
    LONG ref = InterlockedDecrement(&m_lRefCount);
    if (ref == 0) {
        delete this;
    }
    return ref;
}

HRESULT STDMETHODCALLTYPE IStreamImpl::Read(void* pv, ULONG cb, ULONG* pcbRead) {
    if (!pv) return STG_E_INVALIDPOINTER;

    ULONG remaining = m_cbData - m_pos;
    ULONG toRead = (cb < remaining) ? cb : remaining;

    memcpy(pv, m_pData + m_pos, toRead);
    m_pos += toRead;

    if (pcbRead) {
        *pcbRead = toRead;
    }

    return (toRead == cb) ? S_OK : S_FALSE;
}

HRESULT STDMETHODCALLTYPE IStreamImpl::Write(void const* pv, ULONG cb, ULONG* pcbWritten) {
    if (!pv) return STG_E_INVALIDPOINTER;

    if (m_pos + cb > m_cbData) {
        DWORD newSize = m_pos + cb;
        BYTE* pNewData = new BYTE[newSize];
        memcpy(pNewData, m_pData, m_cbData);
        delete[] m_pData;
        m_pData = pNewData;
        m_cbData = newSize;
    }

    memcpy(m_pData + m_pos, pv, cb);
    m_pos += cb;

    if (pcbWritten) {
        *pcbWritten = cb;
    }

    return S_OK;
}

HRESULT STDMETHODCALLTYPE IStreamImpl::Seek(LARGE_INTEGER dlibMove, DWORD dwOrigin, ULARGE_INTEGER* plibNewPosition) {
    LARGE_INTEGER newPos;
    newPos.QuadPart = 0;

    switch (dwOrigin) {
        case STREAM_SEEK_SET:
            newPos.QuadPart = dlibMove.QuadPart;
            break;
        case STREAM_SEEK_CUR:
            newPos.QuadPart = m_pos + dlibMove.QuadPart;
            break;
        case STREAM_SEEK_END:
            newPos.QuadPart = m_cbData + dlibMove.QuadPart;
            break;
        default:
            return STG_E_INVALIDFUNCTION;
    }

    if (newPos.QuadPart < 0 || newPos.QuadPart > m_cbData) {
        return STG_E_INVALIDPOINTER;
    }

    m_pos = (DWORD)newPos.QuadPart;

    if (plibNewPosition) {
        plibNewPosition->QuadPart = newPos.QuadPart;
    }

    return S_OK;
}

HRESULT STDMETHODCALLTYPE IStreamImpl::SetSize(ULARGE_INTEGER libNewSize) {
    if (libNewSize.QuadPart > m_cbData) {
        BYTE* pNewData = new BYTE[(size_t)libNewSize.QuadPart];
        memcpy(pNewData, m_pData, m_cbData);
        delete[] m_pData;
        m_pData = pNewData;
        m_cbData = (DWORD)libNewSize.QuadPart;
    }
    return S_OK;
}

HRESULT STDMETHODCALLTYPE IStreamImpl::CopyTo(IStream* pstm, ULARGE_INTEGER cb, ULARGE_INTEGER* pcbRead, ULARGE_INTEGER* pcbWritten) {
    if (!pstm) return STG_E_INVALIDPOINTER;

    ULONG toCopy = (ULONG)((cb.QuadPart < (m_cbData - m_pos)) ? cb.QuadPart : (m_cbData - m_pos));
    ULONG written = 0;

    HRESULT hr = pstm->Write(m_pData + m_pos, toCopy, &written);

    m_pos += written;

    if (pcbRead) pcbRead->QuadPart = written;
    if (pcbWritten) pcbWritten->QuadPart = written;

    return hr;
}

HRESULT STDMETHODCALLTYPE IStreamImpl::Commit(DWORD grfCommitFlags) {
    return S_OK;
}

HRESULT STDMETHODCALLTYPE IStreamImpl::Revert() {
    return S_OK;
}

HRESULT STDMETHODCALLTYPE IStreamImpl::LockRegion(ULARGE_INTEGER libOffset, ULARGE_INTEGER cb, DWORD dwLockType) {
    return STG_E_INVALIDFUNCTION;
}

HRESULT STDMETHODCALLTYPE IStreamImpl::UnlockRegion(ULARGE_INTEGER libOffset, ULARGE_INTEGER cb, DWORD dwLockType) {
    return STG_E_INVALIDFUNCTION;
}

HRESULT STDMETHODCALLTYPE IStreamImpl::Stat(STATSTG* pstatstg, DWORD grfStatFlag) {
    if (!pstatstg) return STG_E_INVALIDPOINTER;

    memset(pstatstg, 0, sizeof(STATSTG));
    pstatstg->type = STGTY_STREAM;
    pstatstg->cbSize.QuadPart = m_cbData;

    return S_OK;
}

HRESULT STDMETHODCALLTYPE IStreamImpl::Clone(IStream** ppstm) {
    if (!ppstm) return STG_E_INVALIDPOINTER;

    IStreamImpl* pClone = new IStreamImpl(m_pData, m_cbData);
    pClone->m_pos = m_pos;

    *ppstm = pClone;
    return S_OK;
}

}
