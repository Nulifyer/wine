/* LinuxNT WinUI XAML metadata compatibility adapter
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

/* Wine does not currently generate the Windows.UI.Xaml.Markup interfaces. */
struct xaml_type_name
{
    HSTRING name;
    INT32 kind;
};

struct xaml_xmlns_definition
{
    HSTRING xml_namespace;
    HSTRING type_namespace;
};

typedef struct linuxnt_xaml_metadata_provider linuxnt_xaml_metadata_provider;
typedef struct linuxnt_xaml_metadata_provider_vtbl
{
    HRESULT (WINAPI *QueryInterface)(linuxnt_xaml_metadata_provider *, REFIID, void **);
    ULONG (WINAPI *AddRef)(linuxnt_xaml_metadata_provider *);
    ULONG (WINAPI *Release)(linuxnt_xaml_metadata_provider *);
    HRESULT (WINAPI *GetIids)(linuxnt_xaml_metadata_provider *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(linuxnt_xaml_metadata_provider *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(linuxnt_xaml_metadata_provider *, TrustLevel *);
    HRESULT (WINAPI *GetXamlType)(linuxnt_xaml_metadata_provider *, struct xaml_type_name, IInspectable **);
    HRESULT (WINAPI *GetXamlTypeByFullName)(linuxnt_xaml_metadata_provider *, HSTRING, IInspectable **);
    HRESULT (WINAPI *GetXmlnsDefinitions)(linuxnt_xaml_metadata_provider *, UINT32 *,
                                           struct xaml_xmlns_definition **);
} linuxnt_xaml_metadata_provider_vtbl;

struct linuxnt_xaml_metadata_provider
{
    const linuxnt_xaml_metadata_provider_vtbl *lpVtbl;
};

static const IID IID_IXamlMetadataProvider =
    {0xb3765d69, 0x68a5, 0x4b32, {0x88, 0x61, 0xfd, 0xb9, 0x0c, 0x1f, 0x58, 0x36}};

struct metadata_provider
{
    linuxnt_xaml_metadata_provider linuxnt_xaml_metadata_provider_iface;
    linuxnt_xaml_metadata_provider *inner;
    LONG ref;
};

static inline struct metadata_provider *impl_from_metadata_provider(linuxnt_xaml_metadata_provider *iface)
{
    return CONTAINING_RECORD(iface, struct metadata_provider, linuxnt_xaml_metadata_provider_iface);
}

static HRESULT WINAPI metadata_provider_QueryInterface(linuxnt_xaml_metadata_provider *iface, REFIID iid,
                                                        void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;

    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IAgileObject) || IsEqualGUID(iid, &IID_IXamlMetadataProvider))
    {
        *out = iface;
        iface->lpVtbl->AddRef(iface);
        return S_OK;
    }

    return E_NOINTERFACE;
}

static ULONG WINAPI metadata_provider_AddRef(linuxnt_xaml_metadata_provider *iface)
{
    struct metadata_provider *impl = impl_from_metadata_provider(iface);
    return InterlockedIncrement(&impl->ref);
}

static ULONG WINAPI metadata_provider_Release(linuxnt_xaml_metadata_provider *iface)
{
    struct metadata_provider *impl = impl_from_metadata_provider(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);

    if (!ref)
    {
        impl->inner->lpVtbl->Release(impl->inner);
        free(impl);
    }
    return ref;
}

static HRESULT WINAPI metadata_provider_GetIids(linuxnt_xaml_metadata_provider *iface, ULONG *count,
                                                IID **iids)
{
    struct metadata_provider *impl = impl_from_metadata_provider(iface);
    return impl->inner->lpVtbl->GetIids(impl->inner, count, iids);
}

static HRESULT WINAPI metadata_provider_GetRuntimeClassName(linuxnt_xaml_metadata_provider *iface,
                                                            HSTRING *class_name)
{
    struct metadata_provider *impl = impl_from_metadata_provider(iface);
    return impl->inner->lpVtbl->GetRuntimeClassName(impl->inner, class_name);
}

static HRESULT WINAPI metadata_provider_GetTrustLevel(linuxnt_xaml_metadata_provider *iface,
                                                      TrustLevel *trust_level)
{
    struct metadata_provider *impl = impl_from_metadata_provider(iface);
    return impl->inner->lpVtbl->GetTrustLevel(impl->inner, trust_level);
}

static HRESULT project_winui_type_name(HSTRING source, HSTRING *projected)
{
    static const WCHAR source_prefix[] = L"Windows.UI.Xaml.";
    static const WCHAR target_prefix[] = L"Microsoft.UI.Xaml.";
    const UINT32 source_prefix_len = ARRAY_SIZE(source_prefix) - 1;
    const UINT32 target_prefix_len = ARRAY_SIZE(target_prefix) - 1;
    const WCHAR *source_buffer;
    WCHAR *buffer;
    UINT32 source_len, projected_len;
    HRESULT hr;

    *projected = NULL;
    source_buffer = WindowsGetStringRawBuffer(source, &source_len);
    if (source_len < source_prefix_len || wcsncmp(source_buffer, source_prefix, source_prefix_len))
        return S_FALSE;

    projected_len = target_prefix_len + source_len - source_prefix_len;
    if (!(buffer = malloc((projected_len + 1) * sizeof(*buffer)))) return E_OUTOFMEMORY;
    memcpy(buffer, target_prefix, target_prefix_len * sizeof(*buffer));
    memcpy(buffer + target_prefix_len, source_buffer + source_prefix_len,
           (source_len - source_prefix_len) * sizeof(*buffer));
    buffer[projected_len] = 0;
    hr = WindowsCreateString(buffer, projected_len, projected);
    free(buffer);
    return hr;
}

static HRESULT WINAPI metadata_provider_GetXamlType(linuxnt_xaml_metadata_provider *iface,
                                                    struct xaml_type_name type, IInspectable **result)
{
    struct metadata_provider *impl = impl_from_metadata_provider(iface);
    struct xaml_type_name projected_type;
    HSTRING projected;
    HRESULT hr;

    hr = impl->inner->lpVtbl->GetXamlType(impl->inner, type, result);
    if (FAILED(hr) || (result && *result)) return hr;

    hr = project_winui_type_name(type.name, &projected);
    if (hr != S_OK) return hr == S_FALSE ? S_OK : hr;
    projected_type.name = projected;
    projected_type.kind = type.kind;
    TRACE("projecting XAML type %s to %s.\n", debugstr_hstring(type.name),
          debugstr_hstring(projected));
    hr = impl->inner->lpVtbl->GetXamlType(impl->inner, projected_type, result);
    WindowsDeleteString(projected);
    return hr;
}

static HRESULT WINAPI metadata_provider_GetXamlTypeByFullName(linuxnt_xaml_metadata_provider *iface,
                                                              HSTRING full_name, IInspectable **result)
{
    struct metadata_provider *impl = impl_from_metadata_provider(iface);
    HSTRING projected;
    HRESULT hr;

    hr = impl->inner->lpVtbl->GetXamlTypeByFullName(impl->inner, full_name, result);
    if (FAILED(hr) || (result && *result)) return hr;

    hr = project_winui_type_name(full_name, &projected);
    if (hr != S_OK) return hr == S_FALSE ? S_OK : hr;
    TRACE("projecting XAML type %s to %s.\n", debugstr_hstring(full_name),
          debugstr_hstring(projected));
    hr = impl->inner->lpVtbl->GetXamlTypeByFullName(impl->inner, projected, result);
    WindowsDeleteString(projected);
    return hr;
}

static HRESULT WINAPI metadata_provider_GetXmlnsDefinitions(linuxnt_xaml_metadata_provider *iface,
                                                             UINT32 *count,
                                                             struct xaml_xmlns_definition **definitions)
{
    struct metadata_provider *impl = impl_from_metadata_provider(iface);
    return impl->inner->lpVtbl->GetXmlnsDefinitions(impl->inner, count, definitions);
}

static const linuxnt_xaml_metadata_provider_vtbl metadata_provider_vtbl =
{
    metadata_provider_QueryInterface,
    metadata_provider_AddRef,
    metadata_provider_Release,
    metadata_provider_GetIids,
    metadata_provider_GetRuntimeClassName,
    metadata_provider_GetTrustLevel,
    metadata_provider_GetXamlType,
    metadata_provider_GetXamlTypeByFullName,
    metadata_provider_GetXmlnsDefinitions,
};

struct metadata_factory
{
    IActivationFactory IActivationFactory_iface;
    IActivationFactory *inner;
    LONG ref;
};

static inline struct metadata_factory *impl_from_activation_factory(IActivationFactory *iface)
{
    return CONTAINING_RECORD(iface, struct metadata_factory, IActivationFactory_iface);
}

static HRESULT WINAPI metadata_factory_QueryInterface(IActivationFactory *iface, REFIID iid, void **out)
{
    struct metadata_factory *impl = impl_from_activation_factory(iface);

    if (!out) return E_POINTER;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IAgileObject) || IsEqualGUID(iid, &IID_IActivationFactory))
    {
        *out = iface;
        IActivationFactory_AddRef(iface);
        return S_OK;
    }
    return IActivationFactory_QueryInterface(impl->inner, iid, out);
}

static ULONG WINAPI metadata_factory_AddRef(IActivationFactory *iface)
{
    struct metadata_factory *impl = impl_from_activation_factory(iface);
    return InterlockedIncrement(&impl->ref);
}

static ULONG WINAPI metadata_factory_Release(IActivationFactory *iface)
{
    struct metadata_factory *impl = impl_from_activation_factory(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);

    if (!ref)
    {
        IActivationFactory_Release(impl->inner);
        free(impl);
    }
    return ref;
}

static HRESULT WINAPI metadata_factory_GetIids(IActivationFactory *iface, ULONG *count, IID **iids)
{
    struct metadata_factory *impl = impl_from_activation_factory(iface);
    return IActivationFactory_GetIids(impl->inner, count, iids);
}

static HRESULT WINAPI metadata_factory_GetRuntimeClassName(IActivationFactory *iface, HSTRING *class_name)
{
    struct metadata_factory *impl = impl_from_activation_factory(iface);
    return IActivationFactory_GetRuntimeClassName(impl->inner, class_name);
}

static HRESULT WINAPI metadata_factory_GetTrustLevel(IActivationFactory *iface, TrustLevel *trust_level)
{
    struct metadata_factory *impl = impl_from_activation_factory(iface);
    return IActivationFactory_GetTrustLevel(impl->inner, trust_level);
}

static HRESULT WINAPI metadata_factory_ActivateInstance(IActivationFactory *iface, IInspectable **instance)
{
    struct metadata_factory *impl = impl_from_activation_factory(iface);
    linuxnt_xaml_metadata_provider *provider;
    struct metadata_provider *wrapper;
    IInspectable *inner;
    HRESULT hr;

    if (!instance) return E_POINTER;
    *instance = NULL;
    if (FAILED(hr = IActivationFactory_ActivateInstance(impl->inner, &inner))) return hr;

    hr = IInspectable_QueryInterface(inner, &IID_IXamlMetadataProvider, (void **)&provider);
    IInspectable_Release(inner);
    if (FAILED(hr)) return hr;

    if (!(wrapper = calloc(1, sizeof(*wrapper))))
    {
        provider->lpVtbl->Release(provider);
        return E_OUTOFMEMORY;
    }
    wrapper->linuxnt_xaml_metadata_provider_iface.lpVtbl = &metadata_provider_vtbl;
    wrapper->inner = provider;
    wrapper->ref = 1;
    *instance = (IInspectable *)&wrapper->linuxnt_xaml_metadata_provider_iface;
    TRACE("wrapped WinUI XAML metadata provider %p as %p.\n", provider, *instance);
    return S_OK;
}

static const IActivationFactoryVtbl metadata_factory_vtbl =
{
    metadata_factory_QueryInterface,
    metadata_factory_AddRef,
    metadata_factory_Release,
    metadata_factory_GetIids,
    metadata_factory_GetRuntimeClassName,
    metadata_factory_GetTrustLevel,
    metadata_factory_ActivateInstance,
};

IActivationFactory *linuxnt_wrap_xaml_metadata_factory(IActivationFactory *factory)
{
    struct metadata_factory *wrapper;

    if (!(wrapper = calloc(1, sizeof(*wrapper)))) return factory;
    wrapper->IActivationFactory_iface.lpVtbl = &metadata_factory_vtbl;
    wrapper->inner = factory;
    wrapper->ref = 1;
    TRACE("wrapped WinUI XAML metadata factory %p as %p.\n", factory,
          &wrapper->IActivationFactory_iface);
    return &wrapper->IActivationFactory_iface;
}
