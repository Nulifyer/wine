/*
 * Windows.Foundation.ExtensionCatalog implementation
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

#include "combase_private.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(combase);

struct extension_catalog;
struct extension_iterator;

struct extension_catalog_vtbl
{
    HRESULT (WINAPI *QueryInterface)(struct extension_catalog *, REFIID, void **);
    ULONG (WINAPI *AddRef)(struct extension_catalog *);
    ULONG (WINAPI *Release)(struct extension_catalog *);
    HRESULT (WINAPI *GetIids)(struct extension_catalog *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(struct extension_catalog *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(struct extension_catalog *, TrustLevel *);
    HRESULT (WINAPI *QueryCatalog)(struct extension_catalog *, HSTRING, struct extension_iterator **);
    HRESULT (WINAPI *QueryCatalogByPackageFamilyName)(struct extension_catalog *, HSTRING, HSTRING,
                                                       struct extension_iterator **);
};

struct extension_catalog
{
    const struct extension_catalog_vtbl *lpVtbl;
    LONG ref;
};

struct extension_iterator_vtbl
{
    HRESULT (WINAPI *QueryInterface)(struct extension_iterator *, REFIID, void **);
    ULONG (WINAPI *AddRef)(struct extension_iterator *);
    ULONG (WINAPI *Release)(struct extension_iterator *);
    HRESULT (WINAPI *GetIids)(struct extension_iterator *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(struct extension_iterator *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(struct extension_iterator *, TrustLevel *);
    HRESULT (WINAPI *get_Current)(struct extension_iterator *, IInspectable **);
    HRESULT (WINAPI *get_HasCurrent)(struct extension_iterator *, boolean *);
    HRESULT (WINAPI *MoveNext)(struct extension_iterator *, boolean *);
    HRESULT (WINAPI *GetMany)(struct extension_iterator *, UINT32, IInspectable **, UINT32 *);
};

struct extension_iterator
{
    const struct extension_iterator_vtbl *lpVtbl;
    LONG ref;
};

static const IID IID_IExtensionCatalog =
    {0x07cee0d8, 0xd555, 0x4d61, {0x9c, 0x37, 0x01, 0xc1, 0x94, 0xb0, 0xf2, 0x08}};
static const IID IID_IIterator_IExtensionRegistration =
    {0xb4d4a79e, 0xfe15, 0x5272, {0x99, 0x88, 0x61, 0x7a, 0x34, 0xd8, 0x30, 0x0b}};
static const WCHAR extension_catalog_name[] = L"Windows.Foundation.ExtensionCatalog";

static HRESULT copy_iids(const IID *source, ULONG source_count, ULONG *count, IID **iids)
{
    if (!count || !iids) return E_POINTER;
    *count = 0;
    *iids = NULL;
    if (!(*iids = CoTaskMemAlloc(source_count * sizeof(**iids)))) return E_OUTOFMEMORY;
    memcpy(*iids, source, source_count * sizeof(**iids));
    *count = source_count;
    return S_OK;
}

static HRESULT WINAPI extension_iterator_QueryInterface(struct extension_iterator *iface, REFIID iid,
                                                         void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IAgileObject) || IsEqualGUID(iid, &IID_IIterator_IExtensionRegistration))
    {
        *out = iface;
        iface->lpVtbl->AddRef(iface);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG WINAPI extension_iterator_AddRef(struct extension_iterator *iface)
{
    return InterlockedIncrement(&iface->ref);
}

static ULONG WINAPI extension_iterator_Release(struct extension_iterator *iface)
{
    ULONG ref = InterlockedDecrement(&iface->ref);
    if (!ref) free(iface);
    return ref;
}

static HRESULT WINAPI extension_iterator_GetIids(struct extension_iterator *iface, ULONG *count, IID **iids)
{
    static const IID supported[] =
    {
        {0xb4d4a79e, 0xfe15, 0x5272, {0x99, 0x88, 0x61, 0x7a, 0x34, 0xd8, 0x30, 0x0b}},
        {0x00000038, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}},
    };
    return copy_iids(supported, ARRAY_SIZE(supported), count, iids);
}

static HRESULT WINAPI extension_iterator_GetRuntimeClassName(struct extension_iterator *iface, HSTRING *name)
{
    if (!name) return E_POINTER;
    *name = NULL;
    return E_NOTIMPL;
}

static HRESULT WINAPI extension_iterator_GetTrustLevel(struct extension_iterator *iface, TrustLevel *level)
{
    if (!level) return E_POINTER;
    *level = BaseTrust;
    return E_NOTIMPL;
}

static HRESULT WINAPI extension_iterator_get_Current(struct extension_iterator *iface, IInspectable **current)
{
    if (!current) return E_POINTER;
    *current = NULL;
    return E_BOUNDS;
}

static HRESULT WINAPI extension_iterator_get_HasCurrent(struct extension_iterator *iface, boolean *has_current)
{
    if (!has_current) return E_POINTER;
    *has_current = FALSE;
    return S_OK;
}

static HRESULT WINAPI extension_iterator_MoveNext(struct extension_iterator *iface, boolean *has_current)
{
    if (!has_current) return E_POINTER;
    *has_current = FALSE;
    return E_BOUNDS;
}

static HRESULT WINAPI extension_iterator_GetMany(struct extension_iterator *iface, UINT32 capacity,
                                                  IInspectable **items, UINT32 *actual)
{
    if (!actual || (capacity && !items)) return E_POINTER;
    *actual = 0;
    return S_OK;
}

static const struct extension_iterator_vtbl extension_iterator_vtbl =
{
    extension_iterator_QueryInterface,
    extension_iterator_AddRef,
    extension_iterator_Release,
    extension_iterator_GetIids,
    extension_iterator_GetRuntimeClassName,
    extension_iterator_GetTrustLevel,
    extension_iterator_get_Current,
    extension_iterator_get_HasCurrent,
    extension_iterator_MoveNext,
    extension_iterator_GetMany,
};

static HRESULT create_empty_iterator(struct extension_iterator **out)
{
    struct extension_iterator *iterator;

    if (!out) return E_POINTER;
    *out = NULL;
    if (!(iterator = calloc(1, sizeof(*iterator)))) return E_OUTOFMEMORY;
    iterator->lpVtbl = &extension_iterator_vtbl;
    iterator->ref = 1;
    *out = iterator;
    return S_OK;
}

static HRESULT WINAPI extension_catalog_QueryInterface(struct extension_catalog *iface, REFIID iid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IAgileObject) || IsEqualGUID(iid, &IID_IExtensionCatalog))
    {
        *out = iface;
        iface->lpVtbl->AddRef(iface);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG WINAPI extension_catalog_AddRef(struct extension_catalog *iface)
{
    return InterlockedIncrement(&iface->ref);
}

static ULONG WINAPI extension_catalog_Release(struct extension_catalog *iface)
{
    ULONG ref = InterlockedDecrement(&iface->ref);
    if (!ref) free(iface);
    return ref;
}

static HRESULT WINAPI extension_catalog_GetIids(struct extension_catalog *iface, ULONG *count, IID **iids)
{
    static const IID supported[] =
    {
        {0x07cee0d8, 0xd555, 0x4d61, {0x9c, 0x37, 0x01, 0xc1, 0x94, 0xb0, 0xf2, 0x08}},
        {0x00000038, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}},
    };
    return copy_iids(supported, ARRAY_SIZE(supported), count, iids);
}

static HRESULT WINAPI extension_catalog_GetRuntimeClassName(struct extension_catalog *iface, HSTRING *name)
{
    if (!name) return E_POINTER;
    return WindowsCreateString(extension_catalog_name, ARRAY_SIZE(extension_catalog_name) - 1, name);
}

static HRESULT WINAPI extension_catalog_GetTrustLevel(struct extension_catalog *iface, TrustLevel *level)
{
    if (!level) return E_POINTER;
    *level = FullTrust;
    return S_OK;
}

static HRESULT WINAPI extension_catalog_QueryCatalog(struct extension_catalog *iface, HSTRING extension_name,
                                                      struct extension_iterator **iterator)
{
    TRACE("extension_name %s, iterator %p.\n", debugstr_hstring(extension_name), iterator);
    return create_empty_iterator(iterator);
}

static HRESULT WINAPI extension_catalog_QueryCatalogByPackageFamilyName(struct extension_catalog *iface,
                                                                         HSTRING extension_name,
                                                                         HSTRING package_family_name,
                                                                         struct extension_iterator **iterator)
{
    TRACE("extension_name %s, package_family_name %s, iterator %p.\n",
          debugstr_hstring(extension_name), debugstr_hstring(package_family_name), iterator);
    return create_empty_iterator(iterator);
}

static const struct extension_catalog_vtbl extension_catalog_vtbl =
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

static HRESULT WINAPI extension_factory_QueryInterface(IActivationFactory *iface, REFIID iid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IActivationFactory))
    {
        *out = iface;
        IActivationFactory_AddRef(iface);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG WINAPI extension_factory_AddRef(IActivationFactory *iface)
{
    return 2;
}

static ULONG WINAPI extension_factory_Release(IActivationFactory *iface)
{
    return 1;
}

static HRESULT WINAPI extension_factory_GetIids(IActivationFactory *iface, ULONG *count, IID **iids)
{
    return copy_iids(&IID_IActivationFactory, 1, count, iids);
}

static HRESULT WINAPI extension_factory_GetRuntimeClassName(IActivationFactory *iface, HSTRING *name)
{
    if (!name) return E_POINTER;
    *name = NULL;
    return E_ILLEGAL_METHOD_CALL;
}

static HRESULT WINAPI extension_factory_GetTrustLevel(IActivationFactory *iface, TrustLevel *level)
{
    if (!level) return E_POINTER;
    *level = FullTrust;
    return S_OK;
}

static HRESULT WINAPI extension_factory_ActivateInstance(IActivationFactory *iface, IInspectable **out)
{
    struct extension_catalog *catalog;

    if (!out) return E_POINTER;
    *out = NULL;
    if (!(catalog = calloc(1, sizeof(*catalog)))) return E_OUTOFMEMORY;
    catalog->lpVtbl = &extension_catalog_vtbl;
    catalog->ref = 1;
    *out = (IInspectable *)catalog;
    return S_OK;
}

static const IActivationFactoryVtbl extension_factory_vtbl =
{
    extension_factory_QueryInterface,
    extension_factory_AddRef,
    extension_factory_Release,
    extension_factory_GetIids,
    extension_factory_GetRuntimeClassName,
    extension_factory_GetTrustLevel,
    extension_factory_ActivateInstance,
};

static IActivationFactory extension_factory = {&extension_factory_vtbl};

HRESULT extension_catalog_get_factory(HSTRING classid, IActivationFactory **factory)
{
    const WCHAR *name;

    if (!factory) return E_POINTER;
    *factory = NULL;
    name = WindowsGetStringRawBuffer(classid, NULL);
    if (!name || wcscmp(name, extension_catalog_name)) return REGDB_E_CLASSNOTREG;
    IActivationFactory_AddRef(&extension_factory);
    *factory = &extension_factory;
    return S_OK;
}
