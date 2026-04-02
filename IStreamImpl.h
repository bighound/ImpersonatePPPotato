#pragma once

#ifndef ISTREAMIMPL_H
#define ISTREAMIMPL_H

#include <objbase.h>
#include <assert.h>

namespace ImpersonatePPPotato {

class IStreamImpl : public IStream {
public:
    IStreamImpl(const BYTE* pData, DWORD cbData);
    virtual ~IStreamImpl();

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override;
    ULONG STDMETHODCALLTYPE AddRef() override;
    ULONG STDMETHODCALLTYPE Release() override;

    HRESULT STDMETHODCALLTYPE Read(void* pv, ULONG cb, ULONG* pcbRead) override;
    HRESULT STDMETHODCALLTYPE Write(void const* pv, ULONG cb, ULONG* pcbWritten) override;
    HRESULT STDMETHODCALLTYPE Seek(LARGE_INTEGER dlibMove, DWORD dwOrigin, ULARGE_INTEGER* plibNewPosition) override;
    HRESULT STDMETHODCALLTYPE SetSize(ULARGE_INTEGER libNewSize) override;
    HRESULT STDMETHODCALLTYPE CopyTo(IStream* pstm, ULARGE_INTEGER cb, ULARGE_INTEGER* pcbRead, ULARGE_INTEGER* pcbWritten) override;
    HRESULT STDMETHODCALLTYPE Commit(DWORD grfCommitFlags) override;
    HRESULT STDMETHODCALLTYPE Revert() override;
    HRESULT STDMETHODCALLTYPE LockRegion(ULARGE_INTEGER libOffset, ULARGE_INTEGER cb, DWORD dwLockType) override;
    HRESULT STDMETHODCALLTYPE UnlockRegion(ULARGE_INTEGER libOffset, ULARGE_INTEGER cb, DWORD dwLockType) override;
    HRESULT STDMETHODCALLTYPE Stat(STATSTG* pstatstg, DWORD grfStatFlag) override;
    HRESULT STDMETHODCALLTYPE Clone(IStream** ppstm) override;

private:
    BYTE* m_pData;
    DWORD m_cbData;
    DWORD m_pos;
    LONG m_lRefCount;
};

}

#endif
