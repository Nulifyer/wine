/*
 * Windows.Foundation.ExtensionCatalog implementation
 *
 * Copyright 2026 Nulify
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#define COBJMACROS
#include <wchar.h>

#include "objbase.h"
#include "roapi.h"
#include "winstring.h"

#include "combase_private.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(combase);

static const WCHAR extension_catalog_name[] = L"Windows.Foundation.ExtensionCatalog";

static const GUID IID_IExtensionCatalog =
    {0x07cee0d8, 0xd555, 0x4d61, {0x9c, 0x37, 0x01, 0xc1, 0x94, 0xb0, 0xf2, 0x08}};
static const GUID IID_IIterator_IExtensionRegistration =
    {0xb4d4a79e, 0xfe15, 0x5272, {0x99, 0x88, 0x61, 0x7a, 0x34, 0xd8, 0x30, 0x0b}};

typedef struct IExtensionCatalog IExtensionCatalog;
typedef struct IExtensionCatalogVtbl
{
    BEGIN_INTERFACE
    HRESULT (WINAPI *QueryInterface)(IExtensionCatalog *, REFIID, void **);
    ULONG (WINAPI *AddRef)(IExtensionCatalog *);
    ULONG (WINAPI *Release)(IExtensionCatalog *);
    HRESULT (WINAPI *GetIids)(IExtensionCatalog *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(IExtensionCatalog *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(IExtensionCatalog *, TrustLevel *);
    HRESULT (WINAPI *QueryCatalog)(IExtensionCatalog *, HSTRING, void **);
    HRESULT (WINAPI *QueryCatalogByPackageFamilyName)(IExtensionCatalog *, HSTRING, HSTRING, void **);
    END_INTERFACE
} IExtensionCatalogVtbl;
struct IExtensionCatalog { const IExtensionCatalogVtbl *lpVtbl; };

typedef struct IIterator_IExtensionRegistration IIterator_IExtensionRegistration;
typedef struct IIterator_IExtensionRegistrationVtbl
{
    BEGIN_INTERFACE
    HRESULT (WINAPI *QueryInterface)(IIterator_IExtensionRegistration *, REFIID, void **);
    ULONG (WINAPI *AddRef)(IIterator_IExtensionRegistration *);
    ULONG (WINAPI *Release)(IIterator_IExtensionRegistration *);
    HRESULT (WINAPI *GetIids)(IIterator_IExtensionRegistration *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(IIterator_IExtensionRegistration *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(IIterator_IExtensionRegistration *, TrustLevel *);
    HRESULT (WINAPI *get_Current)(IIterator_IExtensionRegistration *, IInspectable **);
    HRESULT (WINAPI *get_HasCurrent)(IIterator_IExtensionRegistration *, boolean *);
    HRESULT (WINAPI *MoveNext)(IIterator_IExtensionRegistration *, boolean *);
    HRESULT (WINAPI *GetMany)(IIterator_IExtensionRegistration *, UINT32, IInspectable **, UINT32 *);
    END_INTERFACE
} IIterator_IExtensionRegistrationVtbl;
struct IIterator_IExtensionRegistration { const IIterator_IExtensionRegistrationVtbl *lpVtbl; };

struct extension_catalog
{
    IExtensionCatalog IExtensionCatalog_iface;
    LONG ref;
};

struct empty_iterator
{
    IIterator_IExtensionRegistration IIterator_IExtensionRegistration_iface;
    LONG ref;
};

static HRESULT inspectable_get_iids(const IID *iid, ULONG *count, IID **iids)
{
    if (!count || !iids) return E_POINTER;
    *count = 0;
    *iids = CoTaskMemAlloc(sizeof(**iids));
    if (!*iids) return E_OUTOFMEMORY;
    **iids = *iid;
    *count = 1;
    return S_OK;
}

static HRESULT inspectable_get_runtime_class_name(const WCHAR *name, HSTRING *class_name)
{
    if (!class_name) return E_POINTER;
    return WindowsCreateString(name, wcslen(name), class_name);
}

static HRESULT validate_string(HSTRING string)
{
    const WCHAR *buffer;
    UINT32 length;

    buffer = WindowsGetStringRawBuffer(string, &length);
    if (!length || wcsnlen(buffer, length) != length) return E_INVALIDARG;
    return S_OK;
}

static inline struct empty_iterator *impl_from_IIterator_IExtensionRegistration(IIterator_IExtensionRegistration *iface)
{
    return CONTAINING_RECORD(iface, struct empty_iterator, IIterator_IExtensionRegistration_iface);
}

static HRESULT WINAPI empty_iterator_QueryInterface(IIterator_IExtensionRegistration *iface, REFIID iid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualIID(iid, &IID_IUnknown) || IsEqualIID(iid, &IID_IInspectable) ||
        IsEqualIID(iid, &IID_IAgileObject) || IsEqualIID(iid, &IID_IIterator_IExtensionRegistration))
    {
        *out = iface;
        iface->lpVtbl->AddRef(iface);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG WINAPI empty_iterator_AddRef(IIterator_IExtensionRegistration *iface)
{
    struct empty_iterator *impl = impl_from_IIterator_IExtensionRegistration(iface);
    return InterlockedIncrement(&impl->ref);
}

static ULONG WINAPI empty_iterator_Release(IIterator_IExtensionRegistration *iface)
{
    struct empty_iterator *impl = impl_from_IIterator_IExtensionRegistration(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);
    if (!ref) free(impl);
    return ref;
}

static HRESULT WINAPI empty_iterator_GetIids(IIterator_IExtensionRegistration *iface, ULONG *count, IID **iids)
{
    return inspectable_get_iids(&IID_IIterator_IExtensionRegistration, count, iids);
}

static HRESULT WINAPI empty_iterator_GetRuntimeClassName(IIterator_IExtensionRegistration *iface, HSTRING *class_name)
{
    return inspectable_get_runtime_class_name(L"Windows.Foundation.Collections.IIterator`1<Windows.Foundation.IExtensionRegistration>", class_name);
}

static HRESULT WINAPI empty_iterator_GetTrustLevel(IIterator_IExtensionRegistration *iface, TrustLevel *trust_level)
{
    if (!trust_level) return E_POINTER;
    *trust_level = BaseTrust;
    return S_OK;
}

static HRESULT WINAPI empty_iterator_get_Current(IIterator_IExtensionRegistration *iface, IInspectable **value)
{
    if (!value) return E_POINTER;
    *value = NULL;
    return E_BOUNDS;
}

static HRESULT WINAPI empty_iterator_get_HasCurrent(IIterator_IExtensionRegistration *iface, boolean *value)
{
    if (!value) return E_POINTER;
    *value = FALSE;
    return S_OK;
}

static HRESULT WINAPI empty_iterator_MoveNext(IIterator_IExtensionRegistration *iface, boolean *value)
{
    if (!value) return E_POINTER;
    *value = FALSE;
    return E_BOUNDS;
}

static HRESULT WINAPI empty_iterator_GetMany(IIterator_IExtensionRegistration *iface, UINT32 capacity,
                                              IInspectable **items, UINT32 *count)
{
    if (!count || (capacity && !items)) return E_POINTER;
    *count = 0;
    return S_OK;
}

static const IIterator_IExtensionRegistrationVtbl empty_iterator_vtbl =
{
    empty_iterator_QueryInterface,
    empty_iterator_AddRef,
    empty_iterator_Release,
    empty_iterator_GetIids,
    empty_iterator_GetRuntimeClassName,
    empty_iterator_GetTrustLevel,
    empty_iterator_get_Current,
    empty_iterator_get_HasCurrent,
    empty_iterator_MoveNext,
    empty_iterator_GetMany,
};

static HRESULT empty_iterator_create(void **out)
{
    struct empty_iterator *impl;

    if (!out) return E_POINTER;
    *out = NULL;
    if (!(impl = calloc(1, sizeof(*impl)))) return E_OUTOFMEMORY;
    impl->IIterator_IExtensionRegistration_iface.lpVtbl = &empty_iterator_vtbl;
    impl->ref = 1;
    *out = &impl->IIterator_IExtensionRegistration_iface;
    return S_OK;
}

static inline struct extension_catalog *impl_from_IExtensionCatalog(IExtensionCatalog *iface)
{
    return CONTAINING_RECORD(iface, struct extension_catalog, IExtensionCatalog_iface);
}

static HRESULT WINAPI extension_catalog_QueryInterface(IExtensionCatalog *iface, REFIID iid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualIID(iid, &IID_IUnknown) || IsEqualIID(iid, &IID_IInspectable) ||
        IsEqualIID(iid, &IID_IAgileObject) || IsEqualIID(iid, &IID_IExtensionCatalog))
    {
        *out = iface;
        iface->lpVtbl->AddRef(iface);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG WINAPI extension_catalog_AddRef(IExtensionCatalog *iface)
{
    struct extension_catalog *impl = impl_from_IExtensionCatalog(iface);
    return InterlockedIncrement(&impl->ref);
}

static ULONG WINAPI extension_catalog_Release(IExtensionCatalog *iface)
{
    struct extension_catalog *impl = impl_from_IExtensionCatalog(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);
    if (!ref) free(impl);
    return ref;
}

static HRESULT WINAPI extension_catalog_GetIids(IExtensionCatalog *iface, ULONG *count, IID **iids)
{
    return inspectable_get_iids(&IID_IExtensionCatalog, count, iids);
}

static HRESULT WINAPI extension_catalog_GetRuntimeClassName(IExtensionCatalog *iface, HSTRING *class_name)
{
    return inspectable_get_runtime_class_name(extension_catalog_name, class_name);
}

static HRESULT WINAPI extension_catalog_GetTrustLevel(IExtensionCatalog *iface, TrustLevel *trust_level)
{
    if (!trust_level) return E_POINTER;
    *trust_level = BaseTrust;
    return S_OK;
}

static HRESULT WINAPI extension_catalog_QueryCatalog(IExtensionCatalog *iface, HSTRING contract_id, void **iterator)
{
    HRESULT hr;

    TRACE("iface %p, contract_id %s, iterator %p.\n", iface, debugstr_hstring(contract_id), iterator);
    if (!iterator) return E_POINTER;
    *iterator = NULL;
    if (FAILED(hr = validate_string(contract_id))) return hr;
    return empty_iterator_create(iterator);
}

static HRESULT WINAPI extension_catalog_QueryCatalogByPackageFamilyName(IExtensionCatalog *iface, HSTRING contract_id,
                                                                         HSTRING family_name, void **iterator)
{
    HRESULT hr;

    TRACE("iface %p, contract_id %s, family_name %s, iterator %p.\n", iface, debugstr_hstring(contract_id),
          debugstr_hstring(family_name), iterator);
    if (!iterator) return E_POINTER;
    *iterator = NULL;
    if (FAILED(hr = validate_string(contract_id)) || FAILED(hr = validate_string(family_name))) return hr;
    return empty_iterator_create(iterator);
}

static const IExtensionCatalogVtbl extension_catalog_vtbl =
{
    extension_catalog_QueryInterface,
    extension_catalog_AddRef,
    extension_catalog_Release,
    extension_catalog_GetIids,
    extension_catalog_GetRuntimeClassName,
    extension_catalog_GetTrustLevel,
    extension_catalog_QueryCatalog,
    extension_catalog_QueryCatalogByPackageFamilyName,
};

static HRESULT extension_catalog_create(IInspectable **out)
{
    struct extension_catalog *impl;

    if (!out) return E_POINTER;
    *out = NULL;
    if (!(impl = calloc(1, sizeof(*impl)))) return E_OUTOFMEMORY;
    impl->IExtensionCatalog_iface.lpVtbl = &extension_catalog_vtbl;
    impl->ref = 1;
    *out = (IInspectable *)&impl->IExtensionCatalog_iface;
    return S_OK;
}

static HRESULT WINAPI factory_QueryInterface(IActivationFactory *iface, REFIID iid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualIID(iid, &IID_IUnknown) || IsEqualIID(iid, &IID_IInspectable) ||
        IsEqualIID(iid, &IID_IAgileObject) || IsEqualIID(iid, &IID_IActivationFactory))
    {
        *out = iface;
        IActivationFactory_AddRef(iface);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG WINAPI factory_AddRef(IActivationFactory *iface) { return 2; }
static ULONG WINAPI factory_Release(IActivationFactory *iface) { return 1; }

static HRESULT WINAPI factory_GetIids(IActivationFactory *iface, ULONG *count, IID **iids)
{
    return inspectable_get_iids(&IID_IActivationFactory, count, iids);
}

static HRESULT WINAPI factory_GetRuntimeClassName(IActivationFactory *iface, HSTRING *class_name)
{
    return inspectable_get_runtime_class_name(extension_catalog_name, class_name);
}

static HRESULT WINAPI factory_GetTrustLevel(IActivationFactory *iface, TrustLevel *trust_level)
{
    if (!trust_level) return E_POINTER;
    *trust_level = BaseTrust;
    return S_OK;
}

static HRESULT WINAPI factory_ActivateInstance(IActivationFactory *iface, IInspectable **instance)
{
    return extension_catalog_create(instance);
}

static const IActivationFactoryVtbl factory_vtbl =
{
    factory_QueryInterface,
    factory_AddRef,
    factory_Release,
    factory_GetIids,
    factory_GetRuntimeClassName,
    factory_GetTrustLevel,
    factory_ActivateInstance,
};

static IActivationFactory extension_catalog_factory = {&factory_vtbl};

HRESULT extension_catalog_get_factory(HSTRING classid, IActivationFactory **factory)
{
    const WCHAR *name;
    UINT32 length;

    if (!factory) return E_POINTER;
    *factory = NULL;
    name = WindowsGetStringRawBuffer(classid, &length);
    if (length != ARRAY_SIZE(extension_catalog_name) - 1 ||
        wmemcmp(name, extension_catalog_name, length)) return REGDB_E_CLASSNOTREG;

    *factory = &extension_catalog_factory;
    IActivationFactory_AddRef(*factory);
    return S_OK;
}
