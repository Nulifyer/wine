/*
 * Copyright 2024 Zhiyi Zhang for CodeWeavers
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

#include "private.h"

WINE_DEFAULT_DEBUG_CHANNEL(dataexchange);

/* Windows.UI.Xaml uses this private factory interface to bind drag/drop to a
 * XAML island's core object instead of to a CoreWindow or HWND. */
DEFINE_GUID(IID_ICoreDragDropManagerInternalStatics, 0xacbedab7, 0xe1fa, 0x4fd6,
            0xa9, 0x9e, 0x88, 0xbf, 0x0b, 0x0b, 0xe7, 0xfa);

typedef struct ICoreDragDropManagerInternalStatics ICoreDragDropManagerInternalStatics;
typedef struct ICoreDragDropManagerInternalStaticsVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICoreDragDropManagerInternalStatics *, REFIID, void **);
    ULONG (STDMETHODCALLTYPE *AddRef)(ICoreDragDropManagerInternalStatics *);
    ULONG (STDMETHODCALLTYPE *Release)(ICoreDragDropManagerInternalStatics *);
    HRESULT (STDMETHODCALLTYPE *GetIids)(ICoreDragDropManagerInternalStatics *, ULONG *, IID **);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeClassName)(ICoreDragDropManagerInternalStatics *, HSTRING *);
    HRESULT (STDMETHODCALLTYPE *GetTrustLevel)(ICoreDragDropManagerInternalStatics *, TrustLevel *);
    HRESULT (STDMETHODCALLTYPE *GetForCoreObject)(ICoreDragDropManagerInternalStatics *,
                                                  IInspectable *, IInspectable **);
} ICoreDragDropManagerInternalStaticsVtbl;

struct ICoreDragDropManagerInternalStatics
{
    const ICoreDragDropManagerInternalStaticsVtbl *lpVtbl;
};

struct dataexchange
{
    IActivationFactory IActivationFactory_iface;
    ICoreDragDropManagerStatics ICoreDragDropManagerStatics_iface;
    ICoreDragDropManagerInternalStatics ICoreDragDropManagerInternalStatics_iface;
    IDragDropManagerInterop IDragDropManagerInterop_iface;
    LONG ref;
};

static inline struct dataexchange *impl_from_IActivationFactory(IActivationFactory *iface)
{
    return CONTAINING_RECORD(iface, struct dataexchange, IActivationFactory_iface);
}

static HRESULT STDMETHODCALLTYPE dataexchange_QueryInterface(IActivationFactory *iface, REFIID iid,
                                                             void **out)
{
    struct dataexchange *impl = impl_from_IActivationFactory(iface);

    TRACE("iface %p, iid %s, out %p.\n", iface, debugstr_guid(iid), out);

    if (IsEqualGUID(iid, &IID_IUnknown)
        || IsEqualGUID(iid, &IID_IInspectable)
        || IsEqualGUID(iid, &IID_IAgileObject)
        || IsEqualGUID(iid, &IID_IActivationFactory))
    {
        IUnknown_AddRef(iface);
        *out = iface;
        return S_OK;
    }
    else if (IsEqualGUID(iid, &IID_ICoreDragDropManagerStatics))
    {
        ICoreDragDropManagerStatics_AddRef(&impl->ICoreDragDropManagerStatics_iface);
        *out = &impl->ICoreDragDropManagerStatics_iface;
        return S_OK;
    }
    else if (IsEqualGUID(iid, &IID_ICoreDragDropManagerInternalStatics))
    {
        IUnknown_AddRef(iface);
        *out = &impl->ICoreDragDropManagerInternalStatics_iface;
        return S_OK;
    }
    else if (IsEqualGUID(iid, &IID_IDragDropManagerInterop))
    {
        IDragDropManagerInterop_AddRef(&impl->IDragDropManagerInterop_iface);
        *out = &impl->IDragDropManagerInterop_iface;
        return S_OK;
    }

    FIXME("%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE dataexchange_AddRef(IActivationFactory *iface)
{
    struct dataexchange *impl = impl_from_IActivationFactory(iface);
    ULONG ref = InterlockedIncrement(&impl->ref);
    TRACE("iface %p, ref %lu.\n", iface, ref);
    return ref;
}

static ULONG STDMETHODCALLTYPE dataexchange_Release(IActivationFactory *iface)
{
    struct dataexchange *impl = impl_from_IActivationFactory(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);
    TRACE("iface %p, ref %lu.\n", iface, ref);
    return ref;
}

static HRESULT STDMETHODCALLTYPE dataexchange_GetIids(IActivationFactory *iface, ULONG *iid_count,
                                                      IID **iids)
{
    FIXME("iface %p, iid_count %p, iids %p stub!\n", iface, iid_count, iids);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dataexchange_GetRuntimeClassName(IActivationFactory *iface,
                                                                  HSTRING *class_name)
{
    FIXME("iface %p, class_name %p stub!\n", iface, class_name);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dataexchange_GetTrustLevel(IActivationFactory *iface,
                                                            TrustLevel *trust_level)
{
    FIXME("iface %p, trust_level %p stub!\n", iface, trust_level);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dataexchange_ActivateInstance(IActivationFactory *iface,
                                                               IInspectable **instance)
{
    FIXME("iface %p, instance %p stub!\n", iface, instance);
    return E_NOTIMPL;
}

static const struct IActivationFactoryVtbl activation_factory_vtbl =
{
    dataexchange_QueryInterface,
    dataexchange_AddRef,
    dataexchange_Release,
    /* IInspectable methods */
    dataexchange_GetIids,
    dataexchange_GetRuntimeClassName,
    dataexchange_GetTrustLevel,
    /* IActivationFactory methods */
    dataexchange_ActivateInstance,
};

struct core_dragdrop_manager
{
    ICoreDragDropManager ICoreDragDropManager_iface;
    HWND hwnd;
    ITypedEventHandler_CoreDragDropManager_CoreDropOperationTargetRequestedEventArgs *target_requested;
    EventRegistrationToken target_requested_token;
    boolean concurrent_operations_enabled;
    LONG ref;
};

static LONG next_target_requested_token;

static inline struct core_dragdrop_manager *impl_from_ICoreDragDropManager(ICoreDragDropManager *iface)
{
    return CONTAINING_RECORD(iface, struct core_dragdrop_manager, ICoreDragDropManager_iface);
}

static HRESULT STDMETHODCALLTYPE core_dragdrop_manager_QueryInterface(ICoreDragDropManager *iface,
                                                                      REFIID iid, void **out)
{
    TRACE("iface %p, iid %s, out %p.\n", iface, debugstr_guid(iid), out);

    if (IsEqualGUID(iid, &IID_IUnknown)
        || IsEqualGUID(iid, &IID_IInspectable)
        || IsEqualGUID(iid, &IID_ICoreDragDropManager))
    {
        IUnknown_AddRef(iface);
        *out = iface;
        return S_OK;
    }

    FIXME("%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE core_dragdrop_manager_AddRef(ICoreDragDropManager *iface)
{
    struct core_dragdrop_manager *impl = impl_from_ICoreDragDropManager(iface);
    ULONG ref = InterlockedIncrement(&impl->ref);
    TRACE("iface %p, ref %lu.\n", iface, ref);
    return ref;
}

static ULONG STDMETHODCALLTYPE core_dragdrop_manager_Release(ICoreDragDropManager *iface)
{
    struct core_dragdrop_manager *impl = impl_from_ICoreDragDropManager(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);

    TRACE("iface %p, ref %lu.\n", iface, ref);

    if (!ref)
    {
        if (impl->target_requested)
            ITypedEventHandler_CoreDragDropManager_CoreDropOperationTargetRequestedEventArgs_Release(
                impl->target_requested );
        free(impl);
    }

    return ref;
}

static HRESULT STDMETHODCALLTYPE core_dragdrop_manager_GetIids(ICoreDragDropManager *iface,
                                                               ULONG *iid_count, IID **iids)
{
    FIXME("iface %p, iid_count %p, iids %p stub!\n", iface, iid_count, iids);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE core_dragdrop_manager_GetRuntimeClassName(ICoreDragDropManager *iface,
                                                                           HSTRING *class_name)
{
    FIXME("iface %p, class_name %p stub!\n", iface, class_name);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE core_dragdrop_manager_GetTrustLevel(ICoreDragDropManager *iface,
                                                                     TrustLevel *trust_level)
{
    FIXME("iface %p, trust_level %p stub!\n", iface, trust_level);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE core_dragdrop_manager_add_TargetRequested(ICoreDragDropManager *iface,
                                                                           ITypedEventHandler_CoreDragDropManager_CoreDropOperationTargetRequestedEventArgs *value,
                                                                           EventRegistrationToken *return_value)
{
    struct core_dragdrop_manager *impl = impl_from_ICoreDragDropManager(iface);

    TRACE("iface %p, value %p, return_value %p.\n", iface, value, return_value);

    if (!value || !return_value) return E_POINTER;
    if (impl->target_requested)
        ITypedEventHandler_CoreDragDropManager_CoreDropOperationTargetRequestedEventArgs_Release(
            impl->target_requested );

    ITypedEventHandler_CoreDragDropManager_CoreDropOperationTargetRequestedEventArgs_AddRef(value);
    impl->target_requested = value;
    impl->target_requested_token.value = InterlockedIncrement(&next_target_requested_token);
    return_value->value = impl->target_requested_token.value;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE core_dragdrop_manager_remove_TargetRequested(ICoreDragDropManager *iface,
                                                                              EventRegistrationToken value)
{
    struct core_dragdrop_manager *impl = impl_from_ICoreDragDropManager(iface);

    TRACE("iface %p, value %#I64x.\n", iface, value.value);

    if (impl->target_requested && value.value == impl->target_requested_token.value)
    {
        ITypedEventHandler_CoreDragDropManager_CoreDropOperationTargetRequestedEventArgs_Release(
            impl->target_requested );
        impl->target_requested = NULL;
        impl->target_requested_token.value = 0;
    }
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE core_dragdrop_manager_get_AreConcurrentOperationsEnabled(ICoreDragDropManager *iface,
                                                                                          boolean *value)
{
    struct core_dragdrop_manager *impl = impl_from_ICoreDragDropManager(iface);

    TRACE("iface %p, value %p.\n", iface, value);
    if (!value) return E_POINTER;
    *value = impl->concurrent_operations_enabled;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE core_dragdrop_manager_put_AreConcurrentOperationsEnabled(ICoreDragDropManager *iface,
                                                                                          boolean value)
{
    struct core_dragdrop_manager *impl = impl_from_ICoreDragDropManager(iface);

    TRACE("iface %p, value %d.\n", iface, value);
    impl->concurrent_operations_enabled = value;
    return S_OK;
}

static const struct ICoreDragDropManagerVtbl core_dragdrop_manager_vtbl =
{
    core_dragdrop_manager_QueryInterface,
    core_dragdrop_manager_AddRef,
    core_dragdrop_manager_Release,
    /* IInspectable methods */
    core_dragdrop_manager_GetIids,
    core_dragdrop_manager_GetRuntimeClassName,
    core_dragdrop_manager_GetTrustLevel,
    /* ICoreDragDropManager methods */
    core_dragdrop_manager_add_TargetRequested,
    core_dragdrop_manager_remove_TargetRequested,
    core_dragdrop_manager_get_AreConcurrentOperationsEnabled,
    core_dragdrop_manager_put_AreConcurrentOperationsEnabled,
};

static HRESULT create_core_dragdrop_manager(HWND hwnd, REFIID iid, void **out)
{
    struct core_dragdrop_manager *manager;
    HRESULT hr;

    if (!IsWindow(hwnd))
        return HRESULT_FROM_WIN32(ERROR_INVALID_WINDOW_HANDLE);

    if (hwnd == GetDesktopWindow())
        return E_ACCESSDENIED;

    if (!(manager = calloc(1, sizeof(*manager))))
        return E_OUTOFMEMORY;

    manager->ICoreDragDropManager_iface.lpVtbl = &core_dragdrop_manager_vtbl;
    manager->hwnd = hwnd;
    manager->ref = 1;
    hr = ICoreDragDropManager_QueryInterface(&manager->ICoreDragDropManager_iface, iid, out);
    ICoreDragDropManager_Release(&manager->ICoreDragDropManager_iface);
    return hr;
}

static HRESULT create_core_dragdrop_manager_for_core_object(IInspectable *core_object,
                                                             IInspectable **out)
{
    struct core_dragdrop_manager *manager;
    HRESULT hr;

    if (!core_object || !out) return E_POINTER;
    *out = NULL;

    if (!(manager = calloc(1, sizeof(*manager))))
        return E_OUTOFMEMORY;

    manager->ICoreDragDropManager_iface.lpVtbl = &core_dragdrop_manager_vtbl;
    manager->ref = 1;
    hr = ICoreDragDropManager_QueryInterface(&manager->ICoreDragDropManager_iface,
                                              &IID_IInspectable, (void **)out);
    ICoreDragDropManager_Release(&manager->ICoreDragDropManager_iface);
    return hr;
}

DEFINE_IINSPECTABLE(core_dragdrop_manager_statics, ICoreDragDropManagerStatics, struct dataexchange,
                    IActivationFactory_iface)

static BOOL CALLBACK find_thread_window(HWND hwnd, LPARAM param)
{
    HWND *result = (HWND *)param;

    *result = hwnd;
    return FALSE;
}

static HRESULT STDMETHODCALLTYPE core_dragdrop_manager_statics_GetForCurrentView(ICoreDragDropManagerStatics *iface,
                                                                                 ICoreDragDropManager **value)
{
    HWND hwnd = NULL;

    TRACE("iface %p, value %p.\n", iface, value);
    if (!value) return E_POINTER;
    *value = NULL;

    EnumThreadWindows(GetCurrentThreadId(), find_thread_window, (LPARAM)&hwnd);
    if (!hwnd) return E_FAIL;

    return create_core_dragdrop_manager(hwnd, &IID_ICoreDragDropManager, (void **)value);
}

static const struct ICoreDragDropManagerStaticsVtbl core_dragdrop_manager_statics_vtbl =
{
    core_dragdrop_manager_statics_QueryInterface,
    core_dragdrop_manager_statics_AddRef,
    core_dragdrop_manager_statics_Release,
    /* IInspectable methods */
    core_dragdrop_manager_statics_GetIids,
    core_dragdrop_manager_statics_GetRuntimeClassName,
    core_dragdrop_manager_statics_GetTrustLevel,
    /* ICoreDragDropManagerStatics methods */
    core_dragdrop_manager_statics_GetForCurrentView,
};

DEFINE_IINSPECTABLE(core_dragdrop_manager_internal_statics, ICoreDragDropManagerInternalStatics,
                    struct dataexchange, IActivationFactory_iface)

static HRESULT STDMETHODCALLTYPE core_dragdrop_manager_internal_statics_GetForCoreObject(
    ICoreDragDropManagerInternalStatics *iface, IInspectable *core_object, IInspectable **value)
{
    TRACE("iface %p, core_object %p, value %p.\n", iface, core_object, value);
    return create_core_dragdrop_manager_for_core_object(core_object, value);
}

static const ICoreDragDropManagerInternalStaticsVtbl core_dragdrop_manager_internal_statics_vtbl =
{
    core_dragdrop_manager_internal_statics_QueryInterface,
    core_dragdrop_manager_internal_statics_AddRef,
    core_dragdrop_manager_internal_statics_Release,
    core_dragdrop_manager_internal_statics_GetIids,
    core_dragdrop_manager_internal_statics_GetRuntimeClassName,
    core_dragdrop_manager_internal_statics_GetTrustLevel,
    core_dragdrop_manager_internal_statics_GetForCoreObject,
};

DEFINE_IINSPECTABLE(dragdrop_manager_interop, IDragDropManagerInterop, struct dataexchange,
                    IActivationFactory_iface)

static HRESULT STDMETHODCALLTYPE dragdrop_manager_interop_GetForWindow(IDragDropManagerInterop *iface,
                                                                       HWND hwnd, REFIID iid, void **out)
{
    FIXME("iface %p, hwnd %p, iid %s, out %p semi-stub!\n", iface, hwnd, debugstr_guid(iid), out);

    return create_core_dragdrop_manager(hwnd, iid, out);
}

static const struct IDragDropManagerInteropVtbl dragdrop_manager_interop_vtbl =
{
    dragdrop_manager_interop_QueryInterface,
    dragdrop_manager_interop_AddRef,
    dragdrop_manager_interop_Release,
    /* IInspectable methods */
    dragdrop_manager_interop_GetIids,
    dragdrop_manager_interop_GetRuntimeClassName,
    dragdrop_manager_interop_GetTrustLevel,
    /* IDragDropManagerInterop methods */
    dragdrop_manager_interop_GetForWindow,
};

static struct dataexchange dataexchange =
{
    {&activation_factory_vtbl},
    {&core_dragdrop_manager_statics_vtbl},
    {&core_dragdrop_manager_internal_statics_vtbl},
    {&dragdrop_manager_interop_vtbl},
    1
};

HRESULT WINAPI DllGetClassObject(REFCLSID clsid, REFIID riid, void **out)
{
    FIXME("clsid %s, riid %s, out %p stub!\n", debugstr_guid(clsid), debugstr_guid(riid), out);
    return CLASS_E_CLASSNOTAVAILABLE;
}

HRESULT WINAPI DllGetActivationFactory(HSTRING classid, IActivationFactory **factory)
{
    TRACE("classid %s, factory %p.\n", debugstr_hstring(classid), factory);
    *factory = &dataexchange.IActivationFactory_iface;
    IUnknown_AddRef(*factory);
    return S_OK;
}
