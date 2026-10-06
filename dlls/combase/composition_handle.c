/*
 * Windows.Foundation.Handles.Internal.CompositionHandle
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#define COBJMACROS
#include "objbase.h"
#include "roapi.h"
#include "winstring.h"
#include <stdlib.h>
#include <wchar.h>

#include "combase_private.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(combase);

static const WCHAR composition_handle_name[] =
    L"Windows.Foundation.Handles.Internal.CompositionHandle";

static const GUID IID_ICompositionHandleStatics =
    {0x011681b7, 0x9ece, 0x462e, {0x89, 0xf5, 0xbe, 0x22, 0x15, 0x21, 0x9a, 0xbb}};
static const GUID IID_ICompositionHandleWrapperFactory =
    {0x1f5cee95, 0xa9e9, 0x464e, {0xbe, 0x2f, 0x57, 0xbb, 0xb1, 0x31, 0xe7, 0xec}};
static const GUID IID_ICompositionHandle =
    {0xcfde6f9a, 0x4afe, 0x45b3, {0x81, 0xb5, 0x20, 0xd1, 0x3c, 0xd8, 0xa8, 0x1a}};
static const GUID IID_IUnwrapCompositionHandle =
    {0xbe4059cd, 0xd6d0, 0x40d9, {0x99, 0x9d, 0x60, 0xc7, 0xa6, 0x34, 0x0d, 0xcc}};

typedef struct ICompositionHandleStatics ICompositionHandleStatics;
typedef struct ICompositionHandleWrapperFactory ICompositionHandleWrapperFactory;
typedef struct IUnwrapCompositionHandle IUnwrapCompositionHandle;

typedef struct ICompositionHandleStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT (WINAPI *QueryInterface)(ICompositionHandleStatics *, REFIID, void **);
    ULONG (WINAPI *AddRef)(ICompositionHandleStatics *);
    ULONG (WINAPI *Release)(ICompositionHandleStatics *);
    HRESULT (WINAPI *GetIids)(ICompositionHandleStatics *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(ICompositionHandleStatics *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(ICompositionHandleStatics *, TrustLevel *);
    HRESULT (WINAPI *DuplicateWithSameAccess)(ICompositionHandleStatics *, IInspectable *, IInspectable **);
    HRESULT (WINAPI *DuplicateWithRestrictedAccess)(ICompositionHandleStatics *, IInspectable *, UINT32,
                                                     IInspectable **);
    END_INTERFACE
} ICompositionHandleStaticsVtbl;
struct ICompositionHandleStatics { const ICompositionHandleStaticsVtbl *lpVtbl; };

typedef struct ICompositionHandleWrapperFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT (WINAPI *QueryInterface)(ICompositionHandleWrapperFactory *, REFIID, void **);
    ULONG (WINAPI *AddRef)(ICompositionHandleWrapperFactory *);
    ULONG (WINAPI *Release)(ICompositionHandleWrapperFactory *);
    HRESULT (WINAPI *GetIids)(ICompositionHandleWrapperFactory *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(ICompositionHandleWrapperFactory *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(ICompositionHandleWrapperFactory *, TrustLevel *);
    HRESULT (WINAPI *CreateAndAttachHandle)(ICompositionHandleWrapperFactory *, HANDLE *, REFIID, void **);
    HRESULT (WINAPI *CreateWithDuplicatedHandle)(ICompositionHandleWrapperFactory *, HANDLE, REFIID, void **);
    END_INTERFACE
} ICompositionHandleWrapperFactoryVtbl;
struct ICompositionHandleWrapperFactory { const ICompositionHandleWrapperFactoryVtbl *lpVtbl; };

typedef struct IUnwrapCompositionHandleVtbl
{
    BEGIN_INTERFACE
    HRESULT (WINAPI *QueryInterface)(IUnwrapCompositionHandle *, REFIID, void **);
    ULONG (WINAPI *AddRef)(IUnwrapCompositionHandle *);
    ULONG (WINAPI *Release)(IUnwrapCompositionHandle *);
    HRESULT (WINAPI *GetIids)(IUnwrapCompositionHandle *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(IUnwrapCompositionHandle *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(IUnwrapCompositionHandle *, TrustLevel *);
    HRESULT (WINAPI *CopyTo)(IUnwrapCompositionHandle *, HANDLE *);
    END_INTERFACE
} IUnwrapCompositionHandleVtbl;
struct IUnwrapCompositionHandle { const IUnwrapCompositionHandleVtbl *lpVtbl; };

struct composition_handle_factory
{
    IActivationFactory IActivationFactory_iface;
    ICompositionHandleStatics ICompositionHandleStatics_iface;
    ICompositionHandleWrapperFactory ICompositionHandleWrapperFactory_iface;
};

struct composition_handle
{
    IUnwrapCompositionHandle IUnwrapCompositionHandle_iface;
    LONG ref;
    HANDLE handle;
};

static struct composition_handle_factory composition_handle_factory;

static HRESULT get_iids(REFIID iid, ULONG *count, IID **iids)
{
    if (!count || !iids) return E_POINTER;
    *count = 0;
    if (!(*iids = CoTaskMemAlloc(sizeof(**iids)))) return E_OUTOFMEMORY;
    **iids = *iid;
    *count = 1;
    return S_OK;
}

static HRESULT get_runtime_class_name(HSTRING *class_name)
{
    if (!class_name) return E_POINTER;
    return WindowsCreateString(composition_handle_name, ARRAY_SIZE(composition_handle_name) - 1, class_name);
}

static HRESULT get_trust_level(TrustLevel *trust_level)
{
    if (!trust_level) return E_POINTER;
    *trust_level = BaseTrust;
    return S_OK;
}

static HRESULT factory_query_interface(REFIID iid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;

    if (IsEqualIID(iid, &IID_IUnknown) || IsEqualIID(iid, &IID_IInspectable) ||
        IsEqualIID(iid, &IID_IAgileObject) || IsEqualIID(iid, &IID_IActivationFactory))
        *out = &composition_handle_factory.IActivationFactory_iface;
    else if (IsEqualIID(iid, &IID_ICompositionHandleStatics))
        *out = &composition_handle_factory.ICompositionHandleStatics_iface;
    else if (IsEqualIID(iid, &IID_ICompositionHandleWrapperFactory))
        *out = &composition_handle_factory.ICompositionHandleWrapperFactory_iface;
    else
        return E_NOINTERFACE;

    IActivationFactory_AddRef(&composition_handle_factory.IActivationFactory_iface);
    return S_OK;
}

static HRESULT WINAPI activation_factory_QueryInterface(IActivationFactory *iface, REFIID iid, void **out)
{
    return factory_query_interface(iid, out);
}

static ULONG WINAPI activation_factory_AddRef(IActivationFactory *iface) { return 2; }
static ULONG WINAPI activation_factory_Release(IActivationFactory *iface) { return 1; }

static HRESULT WINAPI activation_factory_GetIids(IActivationFactory *iface, ULONG *count, IID **iids)
{
    return get_iids(&IID_ICompositionHandleStatics, count, iids);
}

static HRESULT WINAPI activation_factory_GetRuntimeClassName(IActivationFactory *iface, HSTRING *class_name)
{
    return get_runtime_class_name(class_name);
}

static HRESULT WINAPI activation_factory_GetTrustLevel(IActivationFactory *iface, TrustLevel *trust_level)
{
    return get_trust_level(trust_level);
}

static HRESULT WINAPI activation_factory_ActivateInstance(IActivationFactory *iface, IInspectable **instance)
{
    if (!instance) return E_POINTER;
    *instance = NULL;
    return E_NOTIMPL;
}

static const IActivationFactoryVtbl activation_factory_vtbl =
{
    activation_factory_QueryInterface,
    activation_factory_AddRef,
    activation_factory_Release,
    activation_factory_GetIids,
    activation_factory_GetRuntimeClassName,
    activation_factory_GetTrustLevel,
    activation_factory_ActivateInstance,
};

static inline struct composition_handle *impl_from_IUnwrapCompositionHandle(IUnwrapCompositionHandle *iface)
{
    return CONTAINING_RECORD(iface, struct composition_handle, IUnwrapCompositionHandle_iface);
}

static BOOL composition_handle_supports_iid(REFIID iid)
{
    return IsEqualIID(iid, &IID_IUnknown) || IsEqualIID(iid, &IID_IInspectable) ||
           IsEqualIID(iid, &IID_IAgileObject) || IsEqualIID(iid, &IID_ICompositionHandle) ||
           IsEqualIID(iid, &IID_IUnwrapCompositionHandle);
}

static HRESULT WINAPI composition_handle_QueryInterface(IUnwrapCompositionHandle *iface, REFIID iid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (composition_handle_supports_iid(iid))
    {
        *out = iface;
        iface->lpVtbl->AddRef(iface);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG WINAPI composition_handle_AddRef(IUnwrapCompositionHandle *iface)
{
    struct composition_handle *impl = impl_from_IUnwrapCompositionHandle(iface);
    return InterlockedIncrement(&impl->ref);
}

static ULONG WINAPI composition_handle_Release(IUnwrapCompositionHandle *iface)
{
    struct composition_handle *impl = impl_from_IUnwrapCompositionHandle(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);

    if (!ref)
    {
        if (impl->handle) CloseHandle(impl->handle);
        free(impl);
    }
    return ref;
}

static HRESULT WINAPI composition_handle_GetIids(IUnwrapCompositionHandle *iface, ULONG *count, IID **iids)
{
    return get_iids(&IID_ICompositionHandle, count, iids);
}

static HRESULT WINAPI composition_handle_GetRuntimeClassName(IUnwrapCompositionHandle *iface, HSTRING *class_name)
{
    return get_runtime_class_name(class_name);
}

static HRESULT WINAPI composition_handle_GetTrustLevel(IUnwrapCompositionHandle *iface, TrustLevel *trust_level)
{
    return get_trust_level(trust_level);
}

static HRESULT WINAPI composition_handle_CopyTo(IUnwrapCompositionHandle *iface, HANDLE *handle)
{
    struct composition_handle *impl = impl_from_IUnwrapCompositionHandle(iface);

    if (!handle) return E_POINTER;
    *handle = NULL;
    if (!DuplicateHandle(GetCurrentProcess(), impl->handle, GetCurrentProcess(), handle, 0, FALSE,
                         DUPLICATE_SAME_ACCESS))
        return HRESULT_FROM_WIN32(GetLastError());
    return S_OK;
}

static const IUnwrapCompositionHandleVtbl composition_handle_vtbl =
{
    composition_handle_QueryInterface,
    composition_handle_AddRef,
    composition_handle_Release,
    composition_handle_GetIids,
    composition_handle_GetRuntimeClassName,
    composition_handle_GetTrustLevel,
    composition_handle_CopyTo,
};

static HRESULT create_composition_handle(HANDLE handle, REFIID iid, void **out)
{
    struct composition_handle *impl;
    HRESULT hr;

    if (!out) return E_POINTER;
    *out = NULL;
    if (!handle || handle == INVALID_HANDLE_VALUE) return E_HANDLE;
    if (!composition_handle_supports_iid(iid)) return E_NOINTERFACE;
    if (!(impl = calloc(1, sizeof(*impl)))) return E_OUTOFMEMORY;

    impl->IUnwrapCompositionHandle_iface.lpVtbl = &composition_handle_vtbl;
    impl->ref = 1;
    impl->handle = handle;
    hr = composition_handle_QueryInterface(&impl->IUnwrapCompositionHandle_iface, iid, out);
    composition_handle_Release(&impl->IUnwrapCompositionHandle_iface);
    return hr;
}

static HRESULT WINAPI wrapper_factory_CreateAndAttachHandle(ICompositionHandleWrapperFactory *iface,
                                                            HANDLE *handle, REFIID iid, void **out)
{
    HRESULT hr;

    if (!handle || !out) return E_POINTER;
    hr = create_composition_handle(*handle, iid, out);
    if (SUCCEEDED(hr)) *handle = NULL;
    return hr;
}

static HRESULT WINAPI wrapper_factory_CreateWithDuplicatedHandle(ICompositionHandleWrapperFactory *iface,
                                                                 HANDLE handle, REFIID iid, void **out)
{
    HANDLE duplicate;
    HRESULT hr;

    if (!out) return E_POINTER;
    *out = NULL;
    if (!handle || handle == INVALID_HANDLE_VALUE) return E_HANDLE;
    if (!DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(), &duplicate, 0, FALSE,
                         DUPLICATE_SAME_ACCESS))
        return HRESULT_FROM_WIN32(GetLastError());
    hr = create_composition_handle(duplicate, iid, out);
    if (FAILED(hr)) CloseHandle(duplicate);
    return hr;
}

static HRESULT WINAPI wrapper_factory_QueryInterface(ICompositionHandleWrapperFactory *iface,
                                                      REFIID iid, void **out)
{
    return factory_query_interface(iid, out);
}

static ULONG WINAPI wrapper_factory_AddRef(ICompositionHandleWrapperFactory *iface) { return 2; }
static ULONG WINAPI wrapper_factory_Release(ICompositionHandleWrapperFactory *iface) { return 1; }

static HRESULT WINAPI wrapper_factory_GetIids(ICompositionHandleWrapperFactory *iface, ULONG *count, IID **iids)
{
    return get_iids(&IID_ICompositionHandleWrapperFactory, count, iids);
}

static HRESULT WINAPI wrapper_factory_GetRuntimeClassName(ICompositionHandleWrapperFactory *iface,
                                                          HSTRING *class_name)
{
    return get_runtime_class_name(class_name);
}

static HRESULT WINAPI wrapper_factory_GetTrustLevel(ICompositionHandleWrapperFactory *iface,
                                                     TrustLevel *trust_level)
{
    return get_trust_level(trust_level);
}

static const ICompositionHandleWrapperFactoryVtbl wrapper_factory_vtbl =
{
    wrapper_factory_QueryInterface,
    wrapper_factory_AddRef,
    wrapper_factory_Release,
    wrapper_factory_GetIids,
    wrapper_factory_GetRuntimeClassName,
    wrapper_factory_GetTrustLevel,
    wrapper_factory_CreateAndAttachHandle,
    wrapper_factory_CreateWithDuplicatedHandle,
};

static HRESULT WINAPI statics_QueryInterface(ICompositionHandleStatics *iface, REFIID iid, void **out)
{
    return factory_query_interface(iid, out);
}

static ULONG WINAPI statics_AddRef(ICompositionHandleStatics *iface) { return 2; }
static ULONG WINAPI statics_Release(ICompositionHandleStatics *iface) { return 1; }

static HRESULT WINAPI statics_GetIids(ICompositionHandleStatics *iface, ULONG *count, IID **iids)
{
    return get_iids(&IID_ICompositionHandleStatics, count, iids);
}

static HRESULT WINAPI statics_GetRuntimeClassName(ICompositionHandleStatics *iface, HSTRING *class_name)
{
    return get_runtime_class_name(class_name);
}

static HRESULT WINAPI statics_GetTrustLevel(ICompositionHandleStatics *iface, TrustLevel *trust_level)
{
    return get_trust_level(trust_level);
}

static HRESULT WINAPI statics_DuplicateWithSameAccess(ICompositionHandleStatics *iface,
                                                      IInspectable *source, IInspectable **out)
{
    IUnwrapCompositionHandle *unwrap;
    HANDLE handle;
    HRESULT hr;

    if (!out) return E_POINTER;
    *out = NULL;
    if (!source) return E_INVALIDARG;
    if (FAILED(hr = IInspectable_QueryInterface(source, &IID_IUnwrapCompositionHandle, (void **)&unwrap)))
        return hr;
    hr = unwrap->lpVtbl->CopyTo(unwrap, &handle);
    unwrap->lpVtbl->Release(unwrap);
    if (FAILED(hr)) return hr;
    hr = create_composition_handle(handle, &IID_ICompositionHandle, (void **)out);
    if (FAILED(hr)) CloseHandle(handle);
    return hr;
}

static HRESULT WINAPI statics_DuplicateWithRestrictedAccess(ICompositionHandleStatics *iface,
                                                            IInspectable *source, UINT32 access,
                                                            IInspectable **out)
{
    FIXME("Ignoring composition handle access restrictions %#x.\n", access);
    return statics_DuplicateWithSameAccess(iface, source, out);
}

static const ICompositionHandleStaticsVtbl statics_vtbl =
{
    statics_QueryInterface,
    statics_AddRef,
    statics_Release,
    statics_GetIids,
    statics_GetRuntimeClassName,
    statics_GetTrustLevel,
    statics_DuplicateWithSameAccess,
    statics_DuplicateWithRestrictedAccess,
};

static struct composition_handle_factory composition_handle_factory =
{
    {&activation_factory_vtbl},
    {&statics_vtbl},
    {&wrapper_factory_vtbl},
};

HRESULT composition_handle_get_factory(HSTRING classid, IActivationFactory **factory)
{
    const WCHAR *name;
    UINT32 length;

    if (!factory) return E_POINTER;
    *factory = NULL;
    name = WindowsGetStringRawBuffer(classid, &length);
    if (length != ARRAY_SIZE(composition_handle_name) - 1 ||
        wmemcmp(name, composition_handle_name, length))
        return REGDB_E_CLASSNOTREG;

    *factory = &composition_handle_factory.IActivationFactory_iface;
    IActivationFactory_AddRef(*factory);
    return S_OK;
}
