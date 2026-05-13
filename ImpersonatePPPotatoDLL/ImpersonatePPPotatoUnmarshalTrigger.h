#pragma once

#ifndef IMPERSONATEPPPOTATOUNMARSHALTRIGGER_H
#define IMPERSONATEPPPOTATOUNMARSHALTRIGGER_H

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <objbase.h>
#include <combaseapi.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <iostream>
#include <mutex>
#include <condition_variable>

namespace ImpersonatePPPotato {
    class ImpersonatePPPotatoContext;
}

namespace ImpersonatePPPotato {

class ImpersonatePPPotatoUnmarshalTrigger {
public:

    ImpersonatePPPotatoUnmarshalTrigger(ImpersonatePPPotatoContext* impersonatePPPotatoContext);

    int Trigger();

    static IUnknown* GetFakeObject() { return s_pIUnknown; }
    static IBindCtx* GetBindCtx() { return s_pBindCtx; }
    static IMoniker* GetMoniker() { return s_pMoniker; }

private:
    std::wstring GetMonikerDisplayName();

private:
    ImpersonatePPPotatoContext* m_ImpersonatePPPotatoContext;

    static IUnknown* s_pIUnknown;
    static IBindCtx* s_pBindCtx;
    static IMoniker* s_pMoniker;
    static BOOL s_bInitialized;
};

}

#endif
