/*
 * Copyright 2014 Martin Storsjo
 * Copyright 2016 Michael Müller
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#define COBJMACROS
#include "objbase.h"
#include "cguid.h"
#include "ctxtcall.h"
#include "comsvcs.h"
#include "initguid.h"
#include "roapi.h"
#include "roparameterizediid.h"
#include "roerrorapi.h"
#include "winstring.h"
#include "errhandlingapi.h"

#include "combase_private.h"
#include "winrtprovider.h"

#include "wine/exception.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(combase);

enum ro_apartment_type
{
    RO_APARTMENT_STA,
    RO_APARTMENT_ASTA,
    RO_APARTMENT_MTA,
    RO_APARTMENT_NA,
    RO_APARTMENT_BSTA,
};

struct activatable_class_data
{
    ULONG size;
    DWORD unk;
    DWORD module_len;
    DWORD module_offset;
    DWORD threading_model;
};

struct activation_factory_registration;

struct activation_factory_entry
{
    struct list entry;
    IWineActivationFactoryProvider IWineActivationFactoryProvider_iface;
    HSTRING classid;
    PFNGETACTIVATIONFACTORY callback;
    HMODULE module;
    DWORD rpc_cookie;
    void *rpc_context;
    struct activation_factory_registration *registration;
};

struct activation_factory_registration
{
    LONG refs;
    UINT32 count;
    struct activation_factory_entry entries[1];
};

static SRWLOCK activation_factory_lock = SRWLOCK_INIT;
static struct list activation_factory_list = LIST_INIT(activation_factory_list);

static inline struct activation_factory_entry *impl_from_activation_factory_provider(IWineActivationFactoryProvider *iface)
{
    return CONTAINING_RECORD(iface, struct activation_factory_entry, IWineActivationFactoryProvider_iface);
}

HRESULT package_get_class_path(const WCHAR *classid, WCHAR **path);
BOOL WINAPI QuirkIsEnabled(void *quirk);
HRESULT composition_handle_get_factory(HSTRING classid, IActivationFactory **factory);
HRESULT extension_catalog_get_factory(HSTRING classid, IActivationFactory **factory);

/***********************************************************************
 *      IsErrorPropagationEnabled (combase.@)
 */
BOOL WINAPI IsErrorPropagationEnabled(void)
{
    return !QuirkIsEnabled((void *)(ULONG_PTR)0x30000);
}

static HRESULT get_library_for_classid(const WCHAR *classid, WCHAR **out)
{
    ACTCTX_SECTION_KEYED_DATA data;
    HKEY hkey_root, hkey_class;
    DWORD type, size;
    HRESULT hr;
    WCHAR *buf = NULL;

    *out = NULL;

    /* search activation context first */
    data.cbSize = sizeof(data);
    if (FindActCtxSectionStringW(FIND_ACTCTX_SECTION_KEY_RETURN_HACTCTX, NULL,
            ACTIVATION_CONTEXT_SECTION_WINRT_ACTIVATABLE_CLASSES, classid, &data))
    {
        struct activatable_class_data *activatable_class = (struct activatable_class_data *)data.lpData;
        void *ptr = (BYTE *)data.lpSectionBase + activatable_class->module_offset;
        *out = wcsdup(ptr);
        return S_OK;
    }

    /* Select the package registration before the system namespace. A failed
     * selected provider is not retried through a different registration. */
    if ((hr = package_get_class_path(classid, out)) != S_FALSE) return hr;

    /* load class registry key */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\WindowsRuntime\\ActivatableClassId",
                      0, KEY_READ, &hkey_root))
        return REGDB_E_READREGDB;
    if (RegOpenKeyExW(hkey_root, classid, 0, KEY_READ, &hkey_class))
    {
        WARN("Class %s not found in registry\n", debugstr_w(classid));
        RegCloseKey(hkey_root);
        return REGDB_E_CLASSNOTREG;
    }
    RegCloseKey(hkey_root);

    /* load (and expand) DllPath registry value */
    if (RegQueryValueExW(hkey_class, L"DllPath", NULL, &type, NULL, &size))
    {
        hr = REGDB_E_READREGDB;
        goto done;
    }
    if (type != REG_SZ && type != REG_EXPAND_SZ)
    {
        hr = REGDB_E_READREGDB;
        goto done;
    }
    if (!(buf = malloc(size)))
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }
    if (RegQueryValueExW(hkey_class, L"DllPath", NULL, NULL, (BYTE *)buf, &size))
    {
        hr = REGDB_E_READREGDB;
        goto done;
    }
    if (type == REG_EXPAND_SZ)
    {
        WCHAR *expanded;
        DWORD len = ExpandEnvironmentStringsW(buf, NULL, 0);
        if (!(expanded = malloc(len * sizeof(WCHAR))))
        {
            hr = E_OUTOFMEMORY;
            goto done;
        }
        ExpandEnvironmentStringsW(buf, expanded, len);
        free(buf);
        buf = expanded;
    }

    *out = buf;
    RegCloseKey(hkey_class);
    return S_OK;

done:
    free(buf);
    RegCloseKey(hkey_class);
    return hr;
}

static ULONG activation_factory_registration_release(struct activation_factory_registration *registration)
{
    LONG refs;
    UINT32 i;

    if ((refs = InterlockedDecrement(&registration->refs))) return refs;

    for (i = 0; i < registration->count; ++i)
    {
        WindowsDeleteString(registration->entries[i].classid);
        if (registration->entries[i].module) FreeLibrary(registration->entries[i].module);
    }
    free(registration);
    return 0;
}

static HRESULT get_activation_factory_from_callback(struct activation_factory_entry *entry,
        REFIID iid, void **factory, HRESULT empty_factory_error)
{
    IActivationFactory *activation_factory = NULL;
    HRESULT hr;

    hr = entry->callback(entry->classid, &activation_factory);
    if (SUCCEEDED(hr))
    {
        if (activation_factory)
            hr = IActivationFactory_QueryInterface(activation_factory, iid, factory);
        else
            hr = empty_factory_error;
    }
    if (activation_factory) IActivationFactory_Release(activation_factory);
    return hr;
}

static HRESULT WINAPI activation_factory_provider_QueryInterface(IWineActivationFactoryProvider *iface, REFIID iid, void **out)
{
    struct activation_factory_entry *entry = impl_from_activation_factory_provider(iface);

    TRACE("provider %s query %s\n", debugstr_hstring(entry->classid), debugstr_guid(iid));

    if (!out) return E_POINTER;
    *out = NULL;

    if (IsEqualIID(iid, &IID_IUnknown) || IsEqualIID(iid, &IID_IWineActivationFactoryProvider))
    {
        *out = iface;
        IWineActivationFactoryProvider_AddRef(iface);
        return S_OK;
    }

    return E_NOINTERFACE;
}

static HRESULT WINAPI activation_factory_provider_GetActivationFactory(IWineActivationFactoryProvider *iface,
        REFIID iid, IUnknown **out)
{
    struct activation_factory_entry *entry = impl_from_activation_factory_provider(iface);

    if (!out) return E_POINTER;
    *out = NULL;
    return get_activation_factory_from_callback(entry, iid, (void **)out, RPC_E_SERVERFAULT);
}

static ULONG WINAPI activation_factory_provider_AddRef(IWineActivationFactoryProvider *iface)
{
    struct activation_factory_entry *entry = impl_from_activation_factory_provider(iface);
    return InterlockedIncrement(&entry->registration->refs);
}

static ULONG WINAPI activation_factory_provider_Release(IWineActivationFactoryProvider *iface)
{
    struct activation_factory_entry *entry = impl_from_activation_factory_provider(iface);
    return activation_factory_registration_release(entry->registration);
}

static const IWineActivationFactoryProviderVtbl activation_factory_provider_vtbl =
{
    activation_factory_provider_QueryInterface,
    activation_factory_provider_AddRef,
    activation_factory_provider_Release,
    activation_factory_provider_GetActivationFactory,
};

static HRESULT create_stream_from_mip(const MInterfacePointer *mip, IStream **stream)
{
    LARGE_INTEGER zero = {{0}};
    ULONG written;
    HRESULT hr;

    if (FAILED(hr = CreateStreamOnHGlobal(NULL, TRUE, stream))) return hr;
    if (FAILED(hr = IStream_Write(*stream, mip->abData, mip->ulCntData, &written)) ||
            written != mip->ulCntData)
    {
        if (SUCCEEDED(hr)) hr = STG_E_WRITEFAULT;
        IStream_Release(*stream);
        *stream = NULL;
        return hr;
    }
    if (FAILED(hr = IStream_Seek(*stream, zero, STREAM_SEEK_SET, NULL)))
    {
        IStream_Release(*stream);
        *stream = NULL;
    }
    return hr;
}

static HRESULT marshal_activation_factory_provider(IWineActivationFactoryProvider *provider, MInterfacePointer **mip)
{
    LARGE_INTEGER zero = {{0}};
    IStream *stream = NULL;
    HGLOBAL global;
    SIZE_T size;
    void *data;
    HRESULT hr;

    *mip = NULL;
    if (FAILED(hr = CreateStreamOnHGlobal(NULL, TRUE, &stream))) return hr;
    if (FAILED(hr = CoMarshalInterface(stream, &IID_IWineActivationFactoryProvider, (IUnknown *)provider,
            MSHCTX_LOCAL | MSHCTX_NOSHAREDMEM, NULL, MSHLFLAGS_TABLESTRONG))) goto done;
    if (FAILED(hr = GetHGlobalFromStream(stream, &global))) goto release_marshal;
    if ((size = GlobalSize(global)) > ULONG_MAX || !(data = GlobalLock(global)))
    {
        hr = size > ULONG_MAX ? E_OUTOFMEMORY : HRESULT_FROM_WIN32(GetLastError());
        goto release_marshal;
    }
    if (!(*mip = malloc(FIELD_OFFSET(MInterfacePointer, abData[size]))))
        hr = E_OUTOFMEMORY;
    else
    {
        (*mip)->ulCntData = size;
        memcpy((*mip)->abData, data, size);
        hr = S_OK;
    }
    GlobalUnlock(global);
    if (SUCCEEDED(hr)) goto done;

release_marshal:
    IStream_Seek(stream, zero, STREAM_SEEK_SET, NULL);
    CoReleaseMarshalData(stream);
done:
    IStream_Release(stream);
    return hr;
}

static HRESULT release_marshaled_activation_factory(MInterfacePointer *mip)
{
    IStream *stream;
    HRESULT hr;

    if (FAILED(hr = create_stream_from_mip(mip, &stream))) return hr;
    hr = CoReleaseMarshalData(stream);
    IStream_Release(stream);
    return hr;
}

static HRESULT get_remote_activation_factory(HSTRING classid, REFIID iid, void **factory, BOOL *found)
{
    MInterfacePointer *mip = NULL;
    IWineActivationFactoryProvider *provider = NULL;
    IStream *stream = NULL;
    HRESULT hr;

    *found = FALSE;
    hr = rpc_get_activation_factory(WindowsGetStringRawBuffer(classid, NULL), &mip);
    TRACE("shared activation lookup %s returned %#lx\n", debugstr_hstring(classid), hr);
    if (hr == REGDB_E_CLASSNOTREG) return hr;
    if (FAILED(hr)) return hr;
    *found = TRUE;

    if (SUCCEEDED(hr = create_stream_from_mip(mip, &stream)))
        hr = CoUnmarshalInterface(stream, &IID_IWineActivationFactoryProvider, (void **)&provider);
    if (SUCCEEDED(hr)) hr = IWineActivationFactoryProvider_GetActivationFactory(provider, iid, (IUnknown **)factory);

    if (provider) IWineActivationFactoryProvider_Release(provider);
    if (stream) IStream_Release(stream);
    free(mip);
    return hr;
}

static HRESULT get_registered_activation_factory(HSTRING classid, REFIID iid, void **factory, BOOL *found)
{
    struct activation_factory_registration *registration = NULL;
    struct activation_factory_entry *entry;
    INT32 order;
    HRESULT hr;

    *found = FALSE;

    AcquireSRWLockShared(&activation_factory_lock);
    LIST_FOR_EACH_ENTRY(entry, &activation_factory_list, struct activation_factory_entry, entry)
    {
        if (FAILED(WindowsCompareStringOrdinal(entry->classid, classid, &order)) || order) continue;

        registration = entry->registration;
        InterlockedIncrement(&registration->refs);
        *found = TRUE;
        break;
    }
    ReleaseSRWLockShared(&activation_factory_lock);

    if (!registration) return REGDB_E_CLASSNOTREG;

    hr = get_activation_factory_from_callback(entry, iid, factory, E_UNEXPECTED);
    activation_factory_registration_release(registration);
    return hr;
}


/***********************************************************************
 *      RoInitialize (combase.@)
 */
HRESULT WINAPI RoInitialize(RO_INIT_TYPE type)
{
    switch (type) {
    case RO_INIT_SINGLETHREADED:
        return CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    default:
        FIXME("type %d\n", type);
    case RO_INIT_MULTITHREADED:
        return CoInitializeEx(NULL, COINIT_MULTITHREADED);
    }
}

/***********************************************************************
 *      RoInitializeStrict (combase.@)
 */
HRESULT WINAPI RoInitializeStrict(enum ro_apartment_type type)
{
    switch (type)
    {
    case RO_APARTMENT_STA:
        return CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    case RO_APARTMENT_ASTA:
    case RO_APARTMENT_BSTA:
        FIXME("Apartment type %u treated as STA.\n", type);
        return CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    case RO_APARTMENT_MTA:
        return CoInitializeEx(NULL, COINIT_MULTITHREADED);
    case RO_APARTMENT_NA:
        return CO_E_NOT_SUPPORTED;
    default:
        return E_INVALIDARG;
    }
}

/***********************************************************************
 *      RoInitializeASTA (combase.134)
 */
HRESULT WINAPI RoInitializeASTA(void)
{
    return RoInitializeStrict(RO_APARTMENT_ASTA);
}

/***********************************************************************
 *      RoGetDesignMode (combase.90)
 */
HRESULT WINAPI RoGetDesignMode(BOOL *enabled)
{
    if (!enabled) return E_INVALIDARG;
    *enabled = FALSE;
    return S_OK;
}

/***********************************************************************
 *      RoGetDesignModeV2 (combase.157)
 */
HRESULT WINAPI RoGetDesignModeV2(BOOL *enabled)
{
    if (!enabled) return E_INVALIDARG;
    *enabled = FALSE;
    return S_OK;
}

/***********************************************************************
 *      RoUninitialize (combase.@)
 */
void WINAPI RoUninitialize(void)
{
    CoUninitialize();
}

/***********************************************************************
 *      RoGetActivationFactory (combase.@)
 */
HRESULT WINAPI DECLSPEC_HOTPATCH RoGetActivationFactory(HSTRING classid, REFIID iid, void **class_factory)
{
    PFNGETACTIVATIONFACTORY pDllGetActivationFactory;
    IActivationFactory *factory;
    WCHAR *library;
    HMODULE module;
    BOOL found;
    HRESULT hr;

    FIXME("(%s, %s, %p): semi-stub\n", debugstr_hstring(classid), debugstr_guid(iid), class_factory);

    if (!iid || !class_factory)
        return E_INVALIDARG;

    if (FAILED(hr = ensure_mta()))
        return hr;

    if (classid && (SUCCEEDED(hr = get_registered_activation_factory(classid, iid, class_factory, &found)) || found))
        return hr;
    if (classid && (SUCCEEDED(hr = get_remote_activation_factory(classid, iid, class_factory, &found)) || found))
        return hr;

    hr = get_library_for_classid(WindowsGetStringRawBuffer(classid, NULL), &library);
    if (FAILED(hr))
    {
        ERR("Failed to find library for %s\n", debugstr_hstring(classid));
        return hr;
    }

    if (!(module = LoadLibraryW(library)))
    {
        ERR("Failed to load module %s\n", debugstr_w(library));
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto done;
    }

    if (!(pDllGetActivationFactory = (void *)GetProcAddress(module, "DllGetActivationFactory")))
    {
        ERR("Module %s does not implement DllGetActivationFactory\n", debugstr_w(library));
        hr = E_FAIL;
        goto done;
    }

    TRACE("Found library %s for class %s\n", debugstr_w(library), debugstr_hstring(classid));

    hr = pDllGetActivationFactory(classid, &factory);
    if (SUCCEEDED(hr))
    {
        hr = IActivationFactory_QueryInterface(factory, iid, class_factory);
        if (SUCCEEDED(hr))
        {
            TRACE("Created interface %p\n", *class_factory);
            module = NULL;
        }
        IActivationFactory_Release(factory);
    }
    else
    {
        ERR("Class %s not found in %s, hr %#lx.\n", wine_dbgstr_hstring(classid), debugstr_w(library), hr);
    }

done:
    free(library);
    if (module) FreeLibrary(module);
    return hr;
}

/***********************************************************************
 *      RoGetParameterizedTypeInstanceIID (combase.@)
 */
HRESULT WINAPI RoGetParameterizedTypeInstanceIID(UINT32 name_element_count, const WCHAR **name_elements,
                                                 const IRoMetaDataLocator *meta_data_locator, GUID *iid,
                                                 ROPARAMIIDHANDLE *hiid)
{
    FIXME("stub: %d %p %p %p %p\n", name_element_count, name_elements, meta_data_locator, iid, hiid);
    if (iid) *iid = GUID_NULL;
    if (hiid) *hiid = INVALID_HANDLE_VALUE;
    return E_NOTIMPL;
}

/***********************************************************************
 *      RoActivateInstance (combase.@)
 */
HRESULT WINAPI RoActivateInstance(HSTRING classid, IInspectable **instance)
{
    IActivationFactory *factory;
    HRESULT hr;

    FIXME("(%p, %p): semi-stub\n", classid, instance);

    hr = RoGetActivationFactory(classid, &IID_IActivationFactory, (void **)&factory);
    if (SUCCEEDED(hr))
    {
        hr = IActivationFactory_ActivateInstance(factory, instance);
        IActivationFactory_Release(factory);
    }

    return hr;
}

/***********************************************************************
 *      RoActivateInstanceAsUser (combase.147)
 */
HRESULT WINAPI RoActivateInstanceAsUser(HSTRING classid, UINT64 user_context, IInspectable **instance)
{
    FIXME("(%p, %s, %p): ignoring user context\n", classid, wine_dbgstr_longlong(user_context), instance);
    return RoActivateInstance(classid, instance);
}

/***********************************************************************
 *      RoGetActivationFactoryAsUser (combase.148)
 */
HRESULT WINAPI RoGetActivationFactoryAsUser(HSTRING classid, UINT64 user_context, REFIID iid, void **factory)
{
    FIXME("(%p, %s, %s, %p): ignoring user context\n", classid, wine_dbgstr_longlong(user_context),
            debugstr_guid(iid), factory);
    return RoGetActivationFactory(classid, iid, factory);
}

struct agile_reference
{
    IAgileReference IAgileReference_iface;
    enum AgileReferenceOptions option;
    IStream *marshal_stream;
    CRITICAL_SECTION cs;
    IUnknown *obj;
    BOOLEAN is_agile;
    IUnknown *ctx;
    LONG ref;
};

static HRESULT marshal_object_in_agile_reference(struct agile_reference *ref, REFIID riid, IUnknown *obj)
{
    HRESULT hr;

    hr = CreateStreamOnHGlobal(0, TRUE, &ref->marshal_stream);
    if (FAILED(hr))
        return hr;

    hr = CoMarshalInterface(ref->marshal_stream, riid, obj, MSHCTX_INPROC, NULL, MSHLFLAGS_TABLESTRONG);
    if (FAILED(hr))
    {
        IStream_Release(ref->marshal_stream);
        ref->marshal_stream = NULL;
    }
    return hr;
}

static inline struct agile_reference *impl_from_IAgileReference(IAgileReference *iface)
{
    return CONTAINING_RECORD(iface, struct agile_reference, IAgileReference_iface);
}

static HRESULT WINAPI agile_ref_QueryInterface(IAgileReference *iface, REFIID riid, void **obj)
{
    TRACE("(%p, %s, %p)\n", iface, debugstr_guid(riid), obj);

    if (!riid || !obj) return E_INVALIDARG;

    if (IsEqualGUID(riid, &IID_IUnknown)
        || IsEqualGUID(riid, &IID_IAgileObject)
        || IsEqualGUID(riid, &IID_IAgileReference))
    {
        IUnknown_AddRef(iface);
        *obj = iface;
        return S_OK;
    }

    *obj = NULL;
    FIXME("interface %s is not implemented\n", debugstr_guid(riid));
    return E_NOINTERFACE;
}

static ULONG WINAPI agile_ref_AddRef(IAgileReference *iface)
{
    struct agile_reference *impl = impl_from_IAgileReference(iface);
    return InterlockedIncrement(&impl->ref);
}

static ULONG WINAPI agile_ref_Release(IAgileReference *iface)
{
    struct agile_reference *impl = impl_from_IAgileReference(iface);
    LONG ref = InterlockedDecrement(&impl->ref);

    if (!ref)
    {
        TRACE("destroying %p\n", iface);

        if (impl->obj)
            IUnknown_Release(impl->obj);

        if (impl->marshal_stream)
        {
            LARGE_INTEGER zero = {0};

            IStream_Seek(impl->marshal_stream, zero, STREAM_SEEK_SET, NULL);
            CoReleaseMarshalData(impl->marshal_stream);
            IStream_Release(impl->marshal_stream);
        }
        DeleteCriticalSection(&impl->cs);
        free(impl);
    }

    return ref;
}

struct marshal_context_params
{
    struct agile_reference *impl;
    REFIID iid;
};

static HRESULT WINAPI marshal_object_in_context(ComCallData *arg)
{
    struct marshal_context_params *params = (struct marshal_context_params *)arg;
    HRESULT hr;

    hr = marshal_object_in_agile_reference(params->impl, params->iid, params->impl->obj);
    IUnknown_Release(params->impl->obj);
    params->impl->obj = NULL;
    return hr;
}

static HRESULT WINAPI agile_ref_Resolve(IAgileReference *iface, REFIID riid, void **obj)
{
    struct agile_reference *impl = impl_from_IAgileReference(iface);
    LARGE_INTEGER zero = {0};
    void *cur_ctx;
    HRESULT hr;

    TRACE("(%p, %s, %p)\n", iface, debugstr_guid(riid), obj);

    if (impl->is_agile)
        return IUnknown_QueryInterface(impl->obj, riid, obj);

    if (FAILED(hr = CoGetContextToken((ULONG_PTR *)&cur_ctx)))
        return hr;

    EnterCriticalSection(&impl->cs);
    if (impl->option == AGILEREFERENCE_DELAYEDMARSHAL && impl->marshal_stream == NULL)
    {
        struct marshal_context_params params = { impl, riid };
        IContextCallback *ctx;

        if (FAILED(hr = IUnknown_QueryInterface(impl->ctx, &IID_IContextCallback, (void **)&ctx)))
        {
            LeaveCriticalSection(&impl->cs);
            return hr;
        }

        hr = IContextCallback_ContextCallback(ctx, marshal_object_in_context, (ComCallData *)&params,
                                              &IID_IContextCallback, 5, NULL);
        IContextCallback_Release(ctx);
        if (FAILED(hr))
        {
            LeaveCriticalSection(&impl->cs);
            return hr;
        }
    }

    if (SUCCEEDED(hr = IStream_Seek(impl->marshal_stream, zero, STREAM_SEEK_SET, NULL)))
        hr = CoUnmarshalInterface(impl->marshal_stream, riid, obj);

    LeaveCriticalSection(&impl->cs);
    return hr;
}

static const IAgileReferenceVtbl agile_ref_vtbl =
{
    agile_ref_QueryInterface,
    agile_ref_AddRef,
    agile_ref_Release,
    agile_ref_Resolve,
};

static BOOL object_has_interface(IUnknown *obj, REFIID iid)
{
    IUnknown *unk;
    HRESULT hr;

    hr = IUnknown_QueryInterface(obj, iid, (void **)&unk);
    if (SUCCEEDED(hr))
        IUnknown_Release(unk);
    return SUCCEEDED(hr);
}

/***********************************************************************
 *      RoGetAgileReference (combase.@)
 */
HRESULT WINAPI RoGetAgileReference(enum AgileReferenceOptions option, REFIID riid, IUnknown *obj,
                                   IAgileReference **agile_reference)
{
    struct apartment *apt;
    struct agile_reference *impl;
    HRESULT hr;

    TRACE("(%d, %s, %p, %p).\n", option, debugstr_guid(riid), obj, agile_reference);

    if (option != AGILEREFERENCE_DEFAULT && option != AGILEREFERENCE_DELAYEDMARSHAL)
        return E_INVALIDARG;

    if (!(apt = apartment_get_current_or_mta()))
    {
        ERR("Apartment not initialized\n");
        return CO_E_NOTINITIALIZED;
    }
    rpc_start_remoting(apt);
    apartment_release(apt);

    if (!object_has_interface(obj, riid))
        return E_NOINTERFACE;
    if (object_has_interface(obj, &IID_INoMarshal))
        return CO_E_NOT_SUPPORTED;

    impl = calloc(1, sizeof(*impl));
    if (!impl)
        return E_OUTOFMEMORY;

    impl->IAgileReference_iface.lpVtbl = &agile_ref_vtbl;
    impl->option = option;
    impl->is_agile = object_has_interface(obj, &IID_IAgileObject);
    impl->ref = 1;
    if (FAILED(hr = CoGetContextToken((ULONG_PTR *)&impl->ctx)))
    {
        free( impl );
        return hr;
    }

    if (option == AGILEREFERENCE_DELAYEDMARSHAL || impl->is_agile)
    {
        impl->obj = obj;
        IUnknown_AddRef(impl->obj);
    }
    else if (option == AGILEREFERENCE_DEFAULT)
    {
        if (FAILED(hr = marshal_object_in_agile_reference(impl, riid, obj)))
        {
            free(impl);
            return hr;
        }
    }

    InitializeCriticalSection(&impl->cs);

    *agile_reference = &impl->IAgileReference_iface;
    return S_OK;
}

/***********************************************************************
 *      RoFailFastWithErrorContextInternal2 (combase.@)
 */
void WINAPI RoFailFastWithErrorContextInternal2(HRESULT error, ULONG exception_count, /* PSTOWED_EXCEPTION_INFORMATION_V2 */void *information)
{
    FIXME("%#lx, %lu, %p stub.\n", error, exception_count, information);
    RaiseFailFastException(NULL, NULL, 0);
}

/***********************************************************************
 *      RoGetApartmentIdentifier (combase.@)
 */
HRESULT WINAPI RoGetApartmentIdentifier(UINT64 *identifier)
{
    struct apartment *apt;

    if (!identifier)
        return E_INVALIDARG;

    if (!(apt = apartment_get_current_or_mta()))
        return CO_E_NOTINITIALIZED;

    *identifier = apartment_getoxid(apt);
    apartment_release(apt);

    TRACE("(%p): %s\n", identifier, wine_dbgstr_longlong(*identifier));
    return S_OK;
}

/***********************************************************************
 *      RoRegisterForApartmentShutdown (combase.@)
 */
HRESULT WINAPI RoRegisterForApartmentShutdown(IApartmentShutdown *callback,
        UINT64 *identifier, APARTMENT_SHUTDOWN_REGISTRATION_COOKIE *cookie)
{
    HRESULT hr;

    FIXME("(%p, %p, %p): stub\n", callback, identifier, cookie);

    hr = RoGetApartmentIdentifier(identifier);
    if (FAILED(hr))
        return hr;

    if (cookie)
        *cookie = (void *)0xcafecafe;
    return S_OK;
}

/***********************************************************************
 *      RoGetServerActivatableClasses (combase.@)
 */
HRESULT WINAPI RoGetServerActivatableClasses(HSTRING name, HSTRING **classes, DWORD *count)
{
    FIXME("(%p, %p, %p): stub\n", name, classes, count);

    if (count)
        *count = 0;
    return S_OK;
}

/***********************************************************************
 *      RoRegisterActivationFactories (combase.@)
 */
HRESULT WINAPI RoRegisterActivationFactories(HSTRING *classes, PFNGETACTIVATIONFACTORY *callbacks,
                                             UINT32 count, RO_REGISTRATION_COOKIE *cookie)
{
    struct activation_factory_registration *registration;
    struct activation_factory_entry *entry;
    MInterfacePointer *mip = NULL;
    struct apartment *apt;
    SIZE_T size;
    UINT32 i, j;
    HRESULT hr;

    TRACE("(%p, %p, %u, %p)\n", classes, callbacks, count, cookie);

    if (!cookie) return E_POINTER;
    *cookie = NULL;
    if (!classes || !callbacks || !count) return E_INVALIDARG;

    if (!(apt = apartment_get_current_or_mta())) return CO_E_NOTINITIALIZED;
    apartment_release(apt);

    size = count * sizeof(*registration->entries);
    if (size / sizeof(*registration->entries) != count ||
            size > SIZE_MAX - offsetof(struct activation_factory_registration, entries))
        return E_OUTOFMEMORY;
    size += offsetof(struct activation_factory_registration, entries);
    if (!(registration = calloc(1, size))) return E_OUTOFMEMORY;

    registration->refs = 1;
    registration->count = count;
    for (i = 0; i < count; ++i)
    {
        entry = &registration->entries[i];
        entry->IWineActivationFactoryProvider_iface.lpVtbl = &activation_factory_provider_vtbl;
        entry->callback = callbacks[i];
        entry->registration = registration;
        if (!classes[i] || !callbacks[i])
        {
            hr = E_INVALIDARG;
            goto failed;
        }
        if (FAILED(hr = WindowsDuplicateString(classes[i], &entry->classid))) goto failed;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                (const WCHAR *)(ULONG_PTR)callbacks[i], &entry->module))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto failed;
        }
        for (j = 0; j < i; ++j)
        {
            INT32 order;

            if (SUCCEEDED(WindowsCompareStringOrdinal(registration->entries[j].classid, classes[i], &order)) && !order)
            {
                hr = CO_E_ALREADYINITIALIZED;
                goto failed;
            }
        }
    }

    for (i = 0; i < count; ++i)
    {
        entry = &registration->entries[i];
        if (FAILED(hr = marshal_activation_factory_provider(&entry->IWineActivationFactoryProvider_iface, &mip))) goto failed;
        hr = rpc_register_activation_factory(WindowsGetStringRawBuffer(entry->classid, NULL), mip,
                &entry->rpc_cookie, &entry->rpc_context);
        if (FAILED(hr))
        {
            release_marshaled_activation_factory(mip);
            free(mip);
            mip = NULL;
            goto failed;
        }
        TRACE("published activation factory %s with cookie %lu\n",
                debugstr_hstring(entry->classid), entry->rpc_cookie);
        free(mip);
        mip = NULL;
    }

    AcquireSRWLockExclusive(&activation_factory_lock);
    LIST_FOR_EACH_ENTRY(entry, &activation_factory_list, struct activation_factory_entry, entry)
    {
        for (i = 0; i < count; ++i)
        {
            INT32 order;

            if (SUCCEEDED(WindowsCompareStringOrdinal(entry->classid, classes[i], &order)) && !order)
            {
                ReleaseSRWLockExclusive(&activation_factory_lock);
                hr = CO_E_ALREADYINITIALIZED;
                goto failed;
            }
        }
    }
    for (i = 0; i < count; ++i)
        list_add_tail(&activation_factory_list, &registration->entries[i].entry);
    ReleaseSRWLockExclusive(&activation_factory_lock);

    *cookie = (RO_REGISTRATION_COOKIE)registration;
    return S_OK;

failed:
    free(mip);
    for (i = 0; i < count; ++i)
    {
        MInterfacePointer *registered_mip = NULL;

        if (registration->entries[i].rpc_cookie &&
                SUCCEEDED(rpc_revoke_activation_factory(registration->entries[i].rpc_cookie,
                        &registration->entries[i].rpc_context, &registered_mip)))
        {
            release_marshaled_activation_factory(registered_mip);
            free(registered_mip);
        }
    }
    activation_factory_registration_release(registration);
    return hr;
}

/***********************************************************************
 *      RoRevokeActivationFactories (combase.@)
 */
void WINAPI RoRevokeActivationFactories(RO_REGISTRATION_COOKIE cookie)
{
    struct activation_factory_registration *registration =
            (struct activation_factory_registration *)cookie;
    UINT32 i;

    TRACE("(%p)\n", cookie);

    if (!registration) return;

    AcquireSRWLockExclusive(&activation_factory_lock);
    for (i = 0; i < registration->count; ++i)
        list_remove(&registration->entries[i].entry);
    ReleaseSRWLockExclusive(&activation_factory_lock);

    for (i = 0; i < registration->count; ++i)
    {
        MInterfacePointer *mip = NULL;

        if (SUCCEEDED(rpc_revoke_activation_factory(registration->entries[i].rpc_cookie,
                &registration->entries[i].rpc_context, &mip)))
        {
            release_marshaled_activation_factory(mip);
            free(mip);
        }
    }

    activation_factory_registration_release(registration);
}

struct restricted_error_info
{
    IRestrictedErrorInfo IRestrictedErrorInfo_iface;
    IErrorInfo IErrorInfo_iface;
    ILanguageExceptionErrorInfo2 ILanguageExceptionErrorInfo2_iface;
    IRestrictedErrorInfo *previous;
    IRestrictedErrorInfo *propagation_head;
    IUnknown *language_exception;
    BSTR description;
    BSTR restricted_description;
    HRESULT code;
    UINT propagation_count;
    LONG ref;
};

static HRESULT restricted_error_info_create(HRESULT code, ULONG len_msg, const WCHAR *message, ULONG len_desc,
        const WCHAR *desc, IRestrictedErrorInfo *previous, IUnknown *language_exception, IErrorInfo **info);

static inline struct restricted_error_info *impl_from_IRestrictedErrorInfo(IRestrictedErrorInfo *iface)
{
    return CONTAINING_RECORD(iface, struct restricted_error_info, IRestrictedErrorInfo_iface);
}

static HRESULT WINAPI restricted_error_info_QueryInterface(IRestrictedErrorInfo *iface, REFIID iid, void **out)
{
    struct restricted_error_info *impl = impl_from_IRestrictedErrorInfo(iface);

    TRACE("(%p, %s, %p)\n", iface, debugstr_guid(iid), out);

    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IRestrictedErrorInfo))
    {
        IRestrictedErrorInfo_AddRef((*out = &impl->IRestrictedErrorInfo_iface));
        return S_OK;
    }
    if (IsEqualGUID(iid, &IID_IErrorInfo))
    {
        IErrorInfo_AddRef((*out = &impl->IErrorInfo_iface));
        return S_OK;
    }
    if (IsEqualGUID(iid, &IID_ILanguageExceptionErrorInfo) ||
            IsEqualGUID(iid, &IID_ILanguageExceptionErrorInfo2))
    {
        ILanguageExceptionErrorInfo2_AddRef((*out = &impl->ILanguageExceptionErrorInfo2_iface));
        return S_OK;
    }

    *out = NULL;
    FIXME("%s not implemented, returning E_NOINTERFACE.", debugstr_guid(iid));
    return E_NOINTERFACE;
}

static ULONG WINAPI restricted_error_info_AddRef(IRestrictedErrorInfo *iface)
{
    struct restricted_error_info *impl = impl_from_IRestrictedErrorInfo(iface);
    TRACE("(%p)\n", iface);
    return InterlockedIncrement(&impl->ref);
}

static ULONG WINAPI restricted_error_info_Release(IRestrictedErrorInfo *iface)
{
    struct restricted_error_info *impl = impl_from_IRestrictedErrorInfo(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);

    TRACE("(%p)\n", iface);

    if (!ref)
    {
        if (impl->previous) IRestrictedErrorInfo_Release(impl->previous);
        if (impl->propagation_head) IRestrictedErrorInfo_Release(impl->propagation_head);
        if (impl->language_exception) IUnknown_Release(impl->language_exception);
        SysFreeString(impl->description);
        SysFreeString(impl->restricted_description);
        free(impl);
    }
    return ref;
}

static HRESULT WINAPI restricted_error_info_GetErrorDetails(IRestrictedErrorInfo *iface, BSTR *ret_desc, HRESULT *code,
                                                            BSTR *ret_restricted_desc, BSTR *sid)
{
    struct restricted_error_info *impl = impl_from_IRestrictedErrorInfo(iface);
    static LONG e_fail_count;
    BSTR desc, restricted_desc;

    TRACE("(%p, %p, %p, %p, %p)\n", iface, ret_desc, code, ret_restricted_desc, sid);

    /* There are no terminating NUL characters, so we can use SysStringLen. */
    if (!(desc = SysAllocStringLen(impl->description, SysStringLen(impl->description)))) return E_OUTOFMEMORY;
    if (!(restricted_desc = SysAllocStringLen(impl->restricted_description, SysStringLen(impl->restricted_description))))
    {
        SysFreeString(desc);
        return E_OUTOFMEMORY;
    }
    *code = impl->code;
    *ret_desc = desc;
    *ret_restricted_desc = restricted_desc;

    if (impl->code == E_FAIL && InterlockedIncrement(&e_fail_count) <= 64)
        ERR("linuxnt-restricted-error code=%#lx description=%s restricted=%s previous=%p language_exception=%p\n",
            impl->code, debugstr_w(impl->description), debugstr_w(impl->restricted_description),
            impl->previous, impl->language_exception);

    return S_OK;
}

static HRESULT WINAPI restricted_error_info_GetReference(IRestrictedErrorInfo *iface, BSTR *reference)
{
    FIXME("(%p, %p): semi-stub!\n", iface, reference);
    *reference = NULL;
    return S_OK;
}

static IRestrictedErrorInfoVtbl restricted_error_info_vtbl =
{
    /* IUnknown */
    restricted_error_info_QueryInterface,
    restricted_error_info_AddRef,
    restricted_error_info_Release,
    /* IRestrictedErrorInfo */
    restricted_error_info_GetErrorDetails,
    restricted_error_info_GetReference,
};

static inline struct restricted_error_info *impl_from_IErrorInfo(IErrorInfo *iface)
{
    return CONTAINING_RECORD(iface, struct restricted_error_info, IErrorInfo_iface);
}

static HRESULT WINAPI error_info_QueryInterface(IErrorInfo *iface, REFIID iid, void **out)
{
    struct restricted_error_info *impl = impl_from_IErrorInfo(iface);
    TRACE("(%p, %s, %p)\n", iface, debugstr_guid(iid), out);
    return IRestrictedErrorInfo_QueryInterface(&impl->IRestrictedErrorInfo_iface, iid, out);
}

static ULONG WINAPI error_info_AddRef(IErrorInfo *iface)
{
    struct restricted_error_info *impl = impl_from_IErrorInfo(iface);
    TRACE("(%p)\n", iface);
    return IRestrictedErrorInfo_AddRef(&impl->IRestrictedErrorInfo_iface);
}

static ULONG WINAPI error_info_Release(IErrorInfo *iface)
{
    struct restricted_error_info *impl = impl_from_IErrorInfo(iface);
    TRACE("(%p)\n", iface);
    return IRestrictedErrorInfo_Release(&impl->IRestrictedErrorInfo_iface);
}

static HRESULT WINAPI error_info_GetDescription(IErrorInfo *iface, BSTR *description)
{
    struct restricted_error_info *impl = impl_from_IErrorInfo(iface);

    TRACE("(%p, %p)\n", iface, description);

    *description = SysAllocStringLen(impl->description, SysStringLen(impl->description));
    return *description ? S_OK : E_OUTOFMEMORY;
}

static HRESULT WINAPI error_info_GetGUID(IErrorInfo *iface, GUID *guid)
{
    TRACE("(%p, %p)\n", iface, guid);
    memset(guid, 0, sizeof(*guid));
    return S_OK;
}

static HRESULT WINAPI error_info_GetHelpContext(IErrorInfo *iface, DWORD *context)
{
    TRACE("(%p, %p)\n", iface, context);
    *context = 0;
    return S_OK;
}

static HRESULT WINAPI error_info_GetHelpFile(IErrorInfo *iface, BSTR *file)
{
    TRACE("(%p, %p)\n", iface, file);
    *file = NULL;
    return S_OK;
}

static HRESULT WINAPI error_info_GetSource(IErrorInfo *iface, BSTR *source)
{
    TRACE("(%p, %p)\n", iface, source);
    *source = NULL;
    return S_OK;
}

static const IErrorInfoVtbl error_info_vtbl =
{
    /* IUnknown */
    error_info_QueryInterface,
    error_info_AddRef,
    error_info_Release,
    /* IErrorInfo */
    error_info_GetGUID,
    error_info_GetSource,
    error_info_GetDescription,
    error_info_GetHelpFile,
    error_info_GetHelpContext
};

static inline struct restricted_error_info *impl_from_ILanguageExceptionErrorInfo2(
        ILanguageExceptionErrorInfo2 *iface)
{
    return CONTAINING_RECORD(iface, struct restricted_error_info, ILanguageExceptionErrorInfo2_iface);
}

static HRESULT WINAPI language_exception_error_info_QueryInterface(ILanguageExceptionErrorInfo2 *iface,
        REFIID iid, void **out)
{
    struct restricted_error_info *impl = impl_from_ILanguageExceptionErrorInfo2(iface);

    return IRestrictedErrorInfo_QueryInterface(&impl->IRestrictedErrorInfo_iface, iid, out);
}

static ULONG WINAPI language_exception_error_info_AddRef(ILanguageExceptionErrorInfo2 *iface)
{
    struct restricted_error_info *impl = impl_from_ILanguageExceptionErrorInfo2(iface);

    return IRestrictedErrorInfo_AddRef(&impl->IRestrictedErrorInfo_iface);
}

static ULONG WINAPI language_exception_error_info_Release(ILanguageExceptionErrorInfo2 *iface)
{
    struct restricted_error_info *impl = impl_from_ILanguageExceptionErrorInfo2(iface);

    return IRestrictedErrorInfo_Release(&impl->IRestrictedErrorInfo_iface);
}

static HRESULT WINAPI language_exception_error_info_GetLanguageException(ILanguageExceptionErrorInfo2 *iface,
        IUnknown **language_exception)
{
    struct restricted_error_info *impl = impl_from_ILanguageExceptionErrorInfo2(iface);

    *language_exception = impl->language_exception;
    if (*language_exception) IUnknown_AddRef(*language_exception);
    return S_OK;
}

static HRESULT WINAPI language_exception_error_info_GetPreviousLanguageExceptionErrorInfo(
        ILanguageExceptionErrorInfo2 *iface, ILanguageExceptionErrorInfo2 **previous)
{
    struct restricted_error_info *impl = impl_from_ILanguageExceptionErrorInfo2(iface);

    if (!previous) return E_INVALIDARG;
    *previous = NULL;
    if (!impl->previous) return S_OK;
    return IRestrictedErrorInfo_QueryInterface(impl->previous, &IID_ILanguageExceptionErrorInfo2,
                                               (void **)previous);
}

static HRESULT WINAPI language_exception_error_info_CapturePropagationContext(
        ILanguageExceptionErrorInfo2 *iface, IUnknown *language_exception)
{
    struct restricted_error_info *impl = impl_from_ILanguageExceptionErrorInfo2(iface);
    IRestrictedErrorInfo *head = NULL;
    IErrorInfo *error_info = NULL;
    UINT32 flags;
    HRESULT hr;

    if (impl->propagation_count >= 150) return S_OK;
    RoGetErrorReportingFlags(&flags);
    if ((flags & RO_ERROR_REPORTING_SUPPRESSSETERRORINFO) ||
            (!(flags & RO_ERROR_REPORTING_USESETERRORINFO) && !IsDebuggerPresent()))
        return S_OK;

    hr = restricted_error_info_create(impl->code, SysStringLen(impl->restricted_description),
            impl->restricted_description, SysStringLen(impl->description), impl->description,
            impl->propagation_head, language_exception, &error_info);
    if (FAILED(hr)) return hr;

    hr = IErrorInfo_QueryInterface(error_info, &IID_IRestrictedErrorInfo, (void **)&head);
    IErrorInfo_Release(error_info);
    if (FAILED(hr)) return hr;

    if (impl->propagation_head) IRestrictedErrorInfo_Release(impl->propagation_head);
    impl->propagation_head = head;
    ++impl->propagation_count;
    return S_OK;
}

static HRESULT WINAPI language_exception_error_info_GetPropagationContextHead(
        ILanguageExceptionErrorInfo2 *iface, ILanguageExceptionErrorInfo2 **head)
{
    struct restricted_error_info *impl = impl_from_ILanguageExceptionErrorInfo2(iface);

    if (!head) return E_INVALIDARG;
    *head = NULL;
    if (!impl->propagation_head) return S_OK;
    return IRestrictedErrorInfo_QueryInterface(impl->propagation_head, &IID_ILanguageExceptionErrorInfo2,
                                               (void **)head);
}

static const ILanguageExceptionErrorInfo2Vtbl language_exception_error_info_vtbl =
{
    language_exception_error_info_QueryInterface,
    language_exception_error_info_AddRef,
    language_exception_error_info_Release,
    language_exception_error_info_GetLanguageException,
    language_exception_error_info_GetPreviousLanguageExceptionErrorInfo,
    language_exception_error_info_CapturePropagationContext,
    language_exception_error_info_GetPropagationContextHead,
};

static HRESULT restricted_error_info_create(HRESULT code, ULONG len_msg, const WCHAR *message, ULONG len_desc,
        const WCHAR *desc, IRestrictedErrorInfo *previous, IUnknown *language_exception, IErrorInfo **info)
{
    struct restricted_error_info *impl;

    if (!(impl = calloc(1, sizeof(*impl)))) return E_OUTOFMEMORY;

    impl->IRestrictedErrorInfo_iface.lpVtbl = &restricted_error_info_vtbl;
    impl->IErrorInfo_iface.lpVtbl = &error_info_vtbl;
    impl->ILanguageExceptionErrorInfo2_iface.lpVtbl = &language_exception_error_info_vtbl;
    impl->previous = previous;
    if (previous) IRestrictedErrorInfo_AddRef(previous);
    impl->language_exception = language_exception;
    if (language_exception) IUnknown_AddRef(language_exception);
    impl->code = code;
    impl->ref = 1;
    if (!(impl->description = SysAllocStringLen(desc, len_desc)))
    {
        if (language_exception) IUnknown_Release(language_exception);
        if (previous) IRestrictedErrorInfo_Release(previous);
        free(impl);
        return E_OUTOFMEMORY;
    }
    /* If the caller did not provide a message, use the description. */
    if (!len_msg)
    {
        message = impl->description;
        len_msg = len_desc;
    }
    if (!(impl->restricted_description = SysAllocStringLen(message, len_msg)))
    {
        if (language_exception) IUnknown_Release(language_exception);
        if (previous) IRestrictedErrorInfo_Release(previous);
        SysFreeString(impl->description);
        free(impl);
        return E_OUTOFMEMORY;
    }
    *info = &impl->IErrorInfo_iface;
    return S_OK;
}

/***********************************************************************
 *      GetRestrictedErrorInfo (combase.@)
 */
HRESULT WINAPI GetRestrictedErrorInfo(IRestrictedErrorInfo **info)
{
    IErrorInfo *error_info;
    HRESULT hr;

    TRACE("(%p)\n", info);

    *info = NULL;
    hr = get_error_info(&error_info);
    if (hr != S_OK) return hr;

    hr = IErrorInfo_QueryInterface(error_info, &IID_IRestrictedErrorInfo, (void **)info);
    IErrorInfo_Release(error_info);
    return FAILED(hr) ? S_FALSE : S_OK;
}

/***********************************************************************
 *      SetRestrictedErrorInfo (combase.@)
 */
HRESULT WINAPI SetRestrictedErrorInfo(IRestrictedErrorInfo *info)
{
    IErrorInfo *error_info = NULL;
    HRESULT hr;

    TRACE("(%p)\n", info);

    if (!info)
        return set_error_info(NULL);

    hr = IRestrictedErrorInfo_QueryInterface(info, &IID_IErrorInfo, (void **)&error_info);
    if (FAILED(hr))
        return hr;

    hr = set_error_info(error_info);
    IErrorInfo_Release(error_info);
    return hr;
}

/***********************************************************************
 *      OriginateOrTransformError (combase.176)
 */
void WINAPI OriginateOrTransformError(HRESULT error)
{
    TRACE("%#lx\n", error);

    RoOriginateError(error, NULL);
}

/***********************************************************************
 *      SetChainRestrictedErrors (combase.177)
 */
HRESULT WINAPI SetChainRestrictedErrors(void)
{
    struct tlsdata *data;
    HRESULT hr;

    TRACE("\n");

    if (FAILED(hr = com_get_tlsdata(&data))) return hr;
    data->chain_restricted_errors = TRUE;
    return S_OK;
}

/***********************************************************************
 *      ClearChainRestrictedErrors (combase.178)
 */
void WINAPI ClearChainRestrictedErrors(void)
{
    struct tlsdata *data;

    TRACE("\n");

    if (SUCCEEDED(com_get_tlsdata(&data))) data->chain_restricted_errors = FALSE;
}

/***********************************************************************
 *      RpcMarshalRestrictedErrorFromTlsToExtent (combase.164)
 */
HRESULT WINAPI RpcMarshalRestrictedErrorFromTlsToExtent(void *reserved, ORPC_EXTENT **extent)
{
    FIXME("%p, %p: semi-stub\n", reserved, extent);

    if (!extent) return E_INVALIDARG;
    *extent = NULL;
    return S_OK;
}

/***********************************************************************
 *      RpcMarshalRestrictedErrorFromTls (combase.165)
 */
HRESULT WINAPI RpcMarshalRestrictedErrorFromTls(void *reserved, MInterfacePointer **marshaled_error)
{
    FIXME("%p, %p: semi-stub\n", reserved, marshaled_error);

    if (!marshaled_error) return E_INVALIDARG;
    *marshaled_error = NULL;
    return S_OK;
}

/***********************************************************************
 *      RpcUnmarshalRestrictedErrorToTls (combase.166)
 */
HRESULT WINAPI RpcUnmarshalRestrictedErrorToTls(void *reserved, MInterfacePointer *marshaled_error)
{
    FIXME("%p, %p: semi-stub\n", reserved, marshaled_error);
    return marshaled_error ? E_NOTIMPL : S_OK;
}

/***********************************************************************
 *      RoGetRegistrationStoreContext (combase.153)
 */
HRESULT WINAPI RoGetRegistrationStoreContext(UINT32 scope, void *sid, UINT32 flags, REFIID iid, void **out)
{
    FIXME("%u, %p, %#x, %s, %p: stub\n", scope, sid, flags, debugstr_guid(iid), out);

    if (!out) return E_INVALIDARG;
    *out = NULL;
    return E_NOTIMPL;
}

static BOOL ro_originate_error(HRESULT error, UINT max_len, const WCHAR *message,
        IUnknown *language_exception);

/***********************************************************************
 *      RoOriginateLanguageException (combase.@)
 */
BOOL WINAPI RoOriginateLanguageException(HRESULT error, HSTRING message, IUnknown *language_exception)
{
    const WCHAR *buf;
    UINT32 len;

    TRACE("%#lx, %s, %p\n", error, debugstr_hstring(message), language_exception);

    buf = WindowsGetStringRawBuffer(message, &len);
    return ro_originate_error(error, len, buf, language_exception);
}

/***********************************************************************
 *      RoOriginateError (combase.@)
 */
BOOL WINAPI RoOriginateError(HRESULT error, HSTRING message)
{
    const WCHAR *buf;
    UINT32 len;

    TRACE("%#lx, %s\n", error, debugstr_hstring(message));

    buf = WindowsGetStringRawBuffer(message, &len);
    return RoOriginateErrorW(error, len, buf);
}

static LONG WINAPI rooriginate_handler(EXCEPTION_POINTERS *ptrs)
{
    EXCEPTION_RECORD *rec = ptrs->ExceptionRecord;
    return (rec->ExceptionCode == EXCEPTION_RO_ORIGINATEERROR) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}

/***********************************************************************
 *      RoOriginateErrorW (combase.@)
 */
BOOL WINAPI RoOriginateErrorW(HRESULT error, UINT max_len, const WCHAR *message)
{
    return ro_originate_error(error, max_len, message, NULL);
}

static BOOL ro_originate_error(HRESULT error, UINT max_len, const WCHAR *message,
        IUnknown *language_exception)
{
    BOOL set_error, raise_exception, ret = TRUE;
    UINT32 flags, len_msg = 0, len_desc;
    WCHAR desc[512];

    TRACE("%#lx, %u, %p\n", error, max_len, message);

    if (SUCCEEDED(error)) return FALSE;
    RoGetErrorReportingFlags(&flags); /* RoGetErrorReportingFlags is infalliable with a valid pointer. */
    /* We call SetErrorInfo if USESETERRORINFO is set and SUPPRESSSETERRORINFO is *not* set. */
    set_error = flags & RO_ERROR_REPORTING_USESETERRORINFO && !(flags & RO_ERROR_REPORTING_SUPPRESSSETERRORINFO);
    /* We raise a structured exception if a debugger is present and SUPPRESSEXCEPTIONS is not set.
     * However, FORCEEXCEPTIONS being set will always cause an exception to be raised. */
    raise_exception = (IsDebuggerPresent() && !(flags & RO_ERROR_REPORTING_SUPPRESSEXCEPTIONS)) ||
                      (flags & RO_ERROR_REPORTING_FORCEEXCEPTIONS);
    if (set_error || raise_exception)
    {
        /* Get the HRESULT description. */
        if (!(len_desc = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, 0, desc, ARRAY_SIZE(desc), NULL)))
            len_desc = swprintf(desc, ARRAY_SIZE(desc), L"Error code '%#lx'.\r\n", error);
        /* If the caller provided a message, find the terminating NUL and truncate it to 512 characters. */
        if (message)
        {
            max_len = max_len ? min(max_len, 512) : 512;
            while (len_msg < max_len && message[len_msg]) len_msg++;
        }
    }
    if (set_error)
    {
        IErrorInfo *info = NULL;
        HRESULT hr;

        if (FAILED(restricted_error_info_create(error, len_msg, message, len_desc, desc, NULL,
                                                language_exception, &info)))
            ret = FALSE;
        /* If restricted_error_info_create failed, this clears the current error object. */
        if (FAILED(hr = set_error_info(info)))
        {
            FIXME("Failed to set current error: %#lx\n", hr);
            ret = FALSE;
        }
        if (info) IErrorInfo_Release(info);
    }
    if (raise_exception)
    {
        const WCHAR *src = len_msg ? message : desc;
        ULONG len = len_msg ? len_msg : len_desc;
        WCHAR *str;

        if (!(str = malloc(sizeof(WCHAR) * (len + 1)))) return ret;
        memcpy(str, src, len * sizeof(WCHAR));
        str[len] = L'\0';

        __TRY
        {
            ULONG_PTR args[3];

            args[0] = error;
            args[1] = len;
            args[2] = (ULONG_PTR)str;
            RaiseException(EXCEPTION_RO_ORIGINATEERROR, 0, 3, args);
        }
        __EXCEPT(rooriginate_handler)
        {
        }
        __ENDTRY;
        free(str);
    }

    return ret;
}

/***********************************************************************
 *      RoClearError (combase.@)
 */
void WINAPI RoClearError(void)
{
    struct tlsdata *data = NtCurrentTeb()->ReservedForOle;

    TRACE("\n");

    if (!data || !data->errorinfo) return;
    IErrorInfo_Release(data->errorinfo);
    data->errorinfo = NULL;
}

static LONG WINAPI rotransform_handler(EXCEPTION_POINTERS *ptrs)
{
    EXCEPTION_RECORD *rec = ptrs->ExceptionRecord;
    return (rec->ExceptionCode == EXCEPTION_RO_TRANSFORMERROR) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}

static IRestrictedErrorInfo *get_matching_previous_error(HRESULT old_error)
{
    IRestrictedErrorInfo *previous = NULL;
    BSTR description = NULL, restricted = NULL, sid = NULL;
    HRESULT code = S_OK, hr;

    hr = GetRestrictedErrorInfo(&previous);
    if (hr != S_OK || !previous) return NULL;

    hr = IRestrictedErrorInfo_GetErrorDetails(previous, &description, &code, &restricted, &sid);
    SysFreeString(description);
    SysFreeString(restricted);
    SysFreeString(sid);
    if (FAILED(hr) || code != old_error)
    {
        IRestrictedErrorInfo_Release(previous);
        return NULL;
    }
    return previous;
}

/***********************************************************************
 *      RoTransformError (combase.@)
 */
BOOL WINAPI RoTransformError(HRESULT old_error, HRESULT new_error, HSTRING message)
{
    const WCHAR *buf;
    UINT32 len;

    TRACE("%#lx, %#lx, %s\n", old_error, new_error, debugstr_hstring(message));

    buf = WindowsGetStringRawBuffer(message, &len);
    return RoTransformErrorW(old_error, new_error, len, buf);
}

/***********************************************************************
 *      RoTransformErrorW (combase.@)
 */
BOOL WINAPI RoTransformErrorW(HRESULT old_error, HRESULT new_error, UINT max_len, const WCHAR *message)
{
    IRestrictedErrorInfo *previous = NULL;
    BOOL set_error, raise_exception, ret = TRUE;
    UINT32 flags, len_msg = 0, len_desc;
    WCHAR desc[512];

    TRACE("%#lx, %#lx, %u, %p\n", old_error, new_error, max_len, message);

    if (old_error == new_error || (SUCCEEDED(old_error) && SUCCEEDED(new_error))) return FALSE;
    if (SUCCEEDED(new_error)) RoClearError();

    RoGetErrorReportingFlags(&flags);
    set_error = flags & RO_ERROR_REPORTING_USESETERRORINFO && !(flags & RO_ERROR_REPORTING_SUPPRESSSETERRORINFO);
    raise_exception = (IsDebuggerPresent() && !(flags & RO_ERROR_REPORTING_SUPPRESSEXCEPTIONS)) ||
                      (flags & RO_ERROR_REPORTING_FORCEEXCEPTIONS);
    if (set_error || raise_exception)
    {
        if (!(len_desc = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, NULL, new_error, 0, desc, ARRAY_SIZE(desc), NULL)))
            len_desc = swprintf(desc, ARRAY_SIZE(desc), L"Error code '%#lx'.\r\n", new_error);
        if (message)
        {
            max_len = max_len ? min(max_len, 512) : 512;
            while (len_msg < max_len && message[len_msg]) len_msg++;
        }
    }

    if (raise_exception)
    {
        const WCHAR *src = len_msg ? message : desc;
        ULONG len = len_msg ? len_msg : len_desc;
        WCHAR *str;

        if ((str = malloc(sizeof(WCHAR) * (len + 1))))
        {
            memcpy(str, src, len * sizeof(WCHAR));
            str[len] = L'\0';
            __TRY
            {
                ULONG_PTR args[4];

                args[0] = old_error;
                args[1] = new_error;
                args[2] = len;
                args[3] = (ULONG_PTR)str;
                RaiseException(EXCEPTION_RO_TRANSFORMERROR, 0, 4, args);
            }
            __EXCEPT(rotransform_handler)
            {
            }
            __ENDTRY;
            free(str);
        }
    }

    if (set_error && FAILED(new_error))
    {
        IErrorInfo *info = NULL;
        HRESULT hr;

        previous = get_matching_previous_error(old_error);
        if (FAILED(restricted_error_info_create(new_error, len_msg, message, len_desc, desc, previous,
                                                NULL, &info)))
            ret = FALSE;
        if (FAILED(hr = set_error_info(info)))
        {
            FIXME("Failed to set transformed error: %#lx\n", hr);
            ret = FALSE;
        }
        if (info) IErrorInfo_Release(info);
        if (previous) IRestrictedErrorInfo_Release(previous);
    }

    return ret;
}

/***********************************************************************
 *      RoGetMatchingRestrictedErrorInfo (combase.@)
 */
HRESULT WINAPI RoGetMatchingRestrictedErrorInfo(HRESULT error, IRestrictedErrorInfo **info)
{
    BSTR description = NULL, restricted = NULL, sid = NULL;
    HRESULT hr, current_error;

    TRACE("%#lx, %p\n", error, info);

    hr = GetRestrictedErrorInfo(info);
    if (FAILED(hr)) return hr;
    if (*info)
    {
        hr = IRestrictedErrorInfo_GetErrorDetails(*info, &description, &current_error, &restricted, &sid);
        SysFreeString(description);
        SysFreeString(restricted);
        SysFreeString(sid);
        if (SUCCEEDED(hr) && current_error == error) return S_OK;
        IRestrictedErrorInfo_Release(*info);
        *info = NULL;
    }
    RoOriginateError(error, NULL);
    hr = GetRestrictedErrorInfo(info);
    if (FAILED(hr)) return hr;
    return *info ? S_OK : E_UNEXPECTED;
}

/***********************************************************************
 *      RoReportUnhandledError (combase.@)
 */
HRESULT WINAPI RoReportUnhandledError(IRestrictedErrorInfo *info)
{
    FIXME("(%p): stub\n", info);
    return S_OK;
}

static LONG error_reporting_flags = RO_ERROR_REPORTING_USESETERRORINFO;
/***********************************************************************
 *      RoSetErrorReportingFlags (combase.@)
 */
HRESULT WINAPI RoSetErrorReportingFlags(UINT32 flags)
{
    UINT32 valid_flags = RO_ERROR_REPORTING_SUPPRESSEXCEPTIONS | RO_ERROR_REPORTING_FORCEEXCEPTIONS |
                         RO_ERROR_REPORTING_USESETERRORINFO | RO_ERROR_REPORTING_SUPPRESSSETERRORINFO;

    TRACE("(%08x)\n", flags);

    if (flags & ~valid_flags) return E_INVALIDARG;
    WriteRelease(&error_reporting_flags, flags);
    return S_OK;
}

/***********************************************************************
 *      RoGetErrorReportingFlags (combase.@)
 */
HRESULT WINAPI RoGetErrorReportingFlags(UINT32 *flags)
{
    TRACE("(%p)\n", flags);

    if (!flags)
        return E_POINTER;

    *flags = ReadAcquire(&error_reporting_flags);
    return S_OK;
}


/***********************************************************************
 *      CleanupOleStateInAllTls (combase.@)
 *
 * Native combase uses this entry point to walk its private process-wide
 * TLS table and release an OLE-owned object embedded in each record.  Wine
 * has neither that private table nor the separate OLE object; its complete
 * COM TLS record is released on thread detach instead.
 */
void WINAPI CleanupOleStateInAllTls(void)
{
    TRACE("()\n");
}

/***********************************************************************
 *      CleanupTlsOleState (combase.@)
 */
void WINAPI CleanupTlsOleState(void *unknown)
{
    FIXME("(%p): stub\n", unknown);
}

/***********************************************************************
 *      DllGetActivationFactory (combase.@)
 */
HRESULT WINAPI DllGetActivationFactory(HSTRING classid, IActivationFactory **factory)
{
    HRESULT hr;

    TRACE("(%s, %p)\n", debugstr_hstring(classid), factory);

    hr = composition_handle_get_factory(classid, factory);
    if (hr != REGDB_E_CLASSNOTREG) return hr;
    return extension_catalog_get_factory(classid, factory);
}

/***********************************************************************
 *      RoFailFastWithErrorContext (combase.@)
 */
void WINAPI RoFailFastWithErrorContext(HRESULT hr)
{
    FIXME("(0x%08lx)\n", hr);
    RaiseFailFastException(NULL, NULL, 0);
}
