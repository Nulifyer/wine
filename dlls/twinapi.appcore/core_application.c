/* WinRT Windows.ApplicationModel.Core.CoreApplication implementation
 *
 * Copyright 2025 Zhiyi Zhang for CodeWeavers
 * Copyright 2026 Nulifyer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "private.h"

#include "roapi.h"
#include "wine/list.h"

WINE_DEFAULT_DEBUG_CHANNEL(twinapi);

/* Private Windows 11 interface used by inbox framework components. */
typedef struct ICoreApplicationPrivate ICoreApplicationPrivate;
typedef struct ICoreApplicationPrivateVtbl
{
    HRESULT (WINAPI *QueryInterface)(ICoreApplicationPrivate *, REFIID, void **);
    ULONG (WINAPI *AddRef)(ICoreApplicationPrivate *);
    ULONG (WINAPI *Release)(ICoreApplicationPrivate *);
    HRESULT (WINAPI *GetIids)(ICoreApplicationPrivate *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(ICoreApplicationPrivate *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(ICoreApplicationPrivate *, TrustLevel *);
    HRESULT (WINAPI *get_Properties)(ICoreApplicationPrivate *, IPropertySet **);
    HRESULT (WINAPI *get_PrivateProperties)(ICoreApplicationPrivate *, IPropertySet **);
    HRESULT (WINAPI *GetWindowFromThreadId)(ICoreApplicationPrivate *, DWORD, IInspectable **);
    HRESULT (WINAPI *GetViewFromThreadId)(ICoreApplicationPrivate *, DWORD, IInspectable **);
    HRESULT (WINAPI *GetAppDisplayName)(ICoreApplicationPrivate *, HSTRING *);
    HRESULT (WINAPI *add_FinalUnhandledErrorDetected)(ICoreApplicationPrivate *, IUnknown *, EventRegistrationToken *);
    HRESULT (WINAPI *remove_FinalUnhandledErrorDetected)(ICoreApplicationPrivate *, EventRegistrationToken);
    HRESULT (WINAPI *GetDispatcherFromHwnd)(ICoreApplicationPrivate *, UINT, IInspectable **);
    HRESULT (WINAPI *IsMainWindowCreated)(ICoreApplicationPrivate *, boolean *);
    HRESULT (WINAPI *GetComponentSiteFromSiteId)(ICoreApplicationPrivate *, GUID, IInspectable **);
    HRESULT (WINAPI *GetCurrentView)(ICoreApplicationPrivate *, UINT, ICoreApplicationView **);
    HRESULT (WINAPI *GetHwndFromViewOnASTA)(ICoreApplicationPrivate *, ICoreApplicationView *, UINT *);
    HRESULT (WINAPI *GetComponentSiteByViewInstanceId)(ICoreApplicationPrivate *, UINT, IInspectable **);
} ICoreApplicationPrivateVtbl;

struct ICoreApplicationPrivate { const ICoreApplicationPrivateVtbl *lpVtbl; };

static const IID IID_ICoreApplicationPrivate =
    {0x17b0e613, 0x942a, 0x422d, {0x90, 0x4c, 0xf9, 0x0d, 0xc7, 0x1a, 0x7d, 0xae}};

struct factory
{
    IActivationFactory IActivationFactory_iface;
    ICoreApplication ICoreApplication_iface;
    ICoreApplication2 ICoreApplication2_iface;
    ICoreApplication3 ICoreApplication3_iface;
    ICoreApplicationExit ICoreApplicationExit_iface;
    ICoreApplicationUnhandledError ICoreApplicationUnhandledError_iface;
    ICoreApplicationUseCount ICoreApplicationUseCount_iface;
    ICoreImmersiveApplication ICoreImmersiveApplication_iface;
    ICoreImmersiveApplication2 ICoreImmersiveApplication2_iface;
    ICoreImmersiveApplication3 ICoreImmersiveApplication3_iface;
    ICoreApplicationPrivate ICoreApplicationPrivate_iface;
    LONG ref, use_count;
};

struct event_handler
{
    struct list entry;
    EventRegistrationToken token;
    IUnknown *handler;
};

struct event_source { SRWLOCK lock; struct list handlers; };
#define EVENT_SOURCE_INIT(name) {SRWLOCK_INIT, LIST_INIT(name.handlers)}

static struct event_source suspending_handlers = EVENT_SOURCE_INIT(suspending_handlers);
static struct event_source resuming_handlers = EVENT_SOURCE_INIT(resuming_handlers);
static struct event_source background_handlers = EVENT_SOURCE_INIT(background_handlers);
static struct event_source leaving_background_handlers = EVENT_SOURCE_INIT(leaving_background_handlers);
static struct event_source entered_background_handlers = EVENT_SOURCE_INIT(entered_background_handlers);
static struct event_source exiting_handlers = EVENT_SOURCE_INIT(exiting_handlers);
static struct event_source unhandled_error_handlers = EVENT_SOURCE_INIT(unhandled_error_handlers);
static struct event_source final_unhandled_error_handlers = EVENT_SOURCE_INIT(final_unhandled_error_handlers);
static LONG64 next_event_token;

static SRWLOCK properties_lock = SRWLOCK_INIT;
static IPropertySet *properties, *private_properties;

static inline struct factory *impl_from_IActivationFactory(IActivationFactory *iface)
{
    return CONTAINING_RECORD(iface, struct factory, IActivationFactory_iface);
}

static HRESULT event_source_add(struct event_source *source, IUnknown *handler, EventRegistrationToken *token)
{
    struct event_handler *entry;
    if (!handler || !token) return E_INVALIDARG;
    if (!(entry = calloc(1, sizeof(*entry)))) return E_OUTOFMEMORY;
    IUnknown_AddRef(entry->handler = handler);
    entry->token.value = InterlockedIncrement64(&next_event_token);
    AcquireSRWLockExclusive(&source->lock);
    list_add_tail(&source->handlers, &entry->entry);
    ReleaseSRWLockExclusive(&source->lock);
    *token = entry->token;
    return S_OK;
}

static HRESULT event_source_remove(struct event_source *source, EventRegistrationToken token)
{
    struct event_handler *entry, *next;
    AcquireSRWLockExclusive(&source->lock);
    LIST_FOR_EACH_ENTRY_SAFE(entry, next, &source->handlers, struct event_handler, entry)
    {
        if (entry->token.value != token.value) continue;
        list_remove(&entry->entry);
        ReleaseSRWLockExclusive(&source->lock);
        IUnknown_Release(entry->handler);
        free(entry);
        return S_OK;
    }
    ReleaseSRWLockExclusive(&source->lock);
    return S_OK;
}

static HRESULT get_property_set(IPropertySet **storage, IPropertySet **value)
{
    const WCHAR *class_name = RuntimeClass_Windows_Foundation_Collections_PropertySet;
    IInspectable *instance = NULL;
    HSTRING_HEADER header;
    HSTRING str;
    HRESULT hr;

    if (!value) return E_POINTER;
    *value = NULL;
    AcquireSRWLockShared(&properties_lock);
    if (*storage)
    {
        IPropertySet_AddRef(*value = *storage);
        ReleaseSRWLockShared(&properties_lock);
        return S_OK;
    }
    ReleaseSRWLockShared(&properties_lock);

    if (FAILED(hr = WindowsCreateStringReference(class_name, wcslen(class_name), &header, &str))) return hr;
    if (FAILED(hr = RoActivateInstance(str, &instance))) return hr;
    hr = IInspectable_QueryInterface(instance, &IID_IPropertySet, (void **)value);
    IInspectable_Release(instance);
    if (FAILED(hr)) return hr;

    AcquireSRWLockExclusive(&properties_lock);
    if (!*storage) IPropertySet_AddRef(*storage = *value);
    else
    {
        IPropertySet_Release(*value);
        IPropertySet_AddRef(*value = *storage);
    }
    ReleaseSRWLockExclusive(&properties_lock);
    return S_OK;
}

static HRESULT WINAPI activation_factory_QueryInterface(IActivationFactory *iface, REFIID iid, void **out)
{
    struct factory *impl = impl_from_IActivationFactory(iface);
    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IAgileObject) || IsEqualGUID(iid, &IID_IActivationFactory))
        *out = &impl->IActivationFactory_iface;
    else if (IsEqualGUID(iid, &IID_ICoreApplication)) *out = &impl->ICoreApplication_iface;
    else if (IsEqualGUID(iid, &IID_ICoreApplication2)) *out = &impl->ICoreApplication2_iface;
    else if (IsEqualGUID(iid, &IID_ICoreApplication3)) *out = &impl->ICoreApplication3_iface;
    else if (IsEqualGUID(iid, &IID_ICoreApplicationExit)) *out = &impl->ICoreApplicationExit_iface;
    else if (IsEqualGUID(iid, &IID_ICoreApplicationUnhandledError)) *out = &impl->ICoreApplicationUnhandledError_iface;
    else if (IsEqualGUID(iid, &IID_ICoreApplicationUseCount)) *out = &impl->ICoreApplicationUseCount_iface;
    else if (IsEqualGUID(iid, &IID_ICoreImmersiveApplication)) *out = &impl->ICoreImmersiveApplication_iface;
    else if (IsEqualGUID(iid, &IID_ICoreImmersiveApplication2)) *out = &impl->ICoreImmersiveApplication2_iface;
    else if (IsEqualGUID(iid, &IID_ICoreImmersiveApplication3)) *out = &impl->ICoreImmersiveApplication3_iface;
    else if (IsEqualGUID(iid, &IID_ICoreApplicationPrivate)) *out = &impl->ICoreApplicationPrivate_iface;
    else return E_NOINTERFACE;
    IActivationFactory_AddRef(&impl->IActivationFactory_iface);
    return S_OK;
}

static ULONG WINAPI activation_factory_AddRef(IActivationFactory *iface)
{
    return InterlockedIncrement(&impl_from_IActivationFactory(iface)->ref);
}

static ULONG WINAPI activation_factory_Release(IActivationFactory *iface)
{
    return InterlockedDecrement(&impl_from_IActivationFactory(iface)->ref);
}

static HRESULT WINAPI activation_factory_GetIids(IActivationFactory *iface, ULONG *count, IID **iids)
{
    IID supported[9];
    if (!count || !iids) return E_POINTER;
    supported[0] = IID_ICoreApplication;
    supported[1] = IID_ICoreApplication2;
    supported[2] = IID_ICoreApplication3;
    supported[3] = IID_ICoreApplicationExit;
    supported[4] = IID_ICoreApplicationUnhandledError;
    supported[5] = IID_ICoreApplicationUseCount;
    supported[6] = IID_ICoreImmersiveApplication;
    supported[7] = IID_ICoreImmersiveApplication2;
    supported[8] = IID_ICoreImmersiveApplication3;
    *count = 0;
    if (!(*iids = CoTaskMemAlloc(sizeof(supported)))) return E_OUTOFMEMORY;
    memcpy(*iids, supported, sizeof(supported));
    *count = ARRAY_SIZE(supported);
    return S_OK;
}

static HRESULT WINAPI activation_factory_GetRuntimeClassName(IActivationFactory *iface, HSTRING *name)
{
    if (!name) return E_POINTER;
    return WindowsCreateString(RuntimeClass_Windows_ApplicationModel_Core_CoreApplication,
            wcslen(RuntimeClass_Windows_ApplicationModel_Core_CoreApplication), name);
}

static HRESULT WINAPI activation_factory_GetTrustLevel(IActivationFactory *iface, TrustLevel *level)
{
    if (!level) return E_POINTER;
    *level = BaseTrust;
    return S_OK;
}

static HRESULT WINAPI activation_factory_ActivateInstance(IActivationFactory *iface, IInspectable **instance)
{
    if (instance) *instance = NULL;
    return E_NOTIMPL;
}

static const IActivationFactoryVtbl activation_factory_vtbl = {activation_factory_QueryInterface,
    activation_factory_AddRef, activation_factory_Release, activation_factory_GetIids,
    activation_factory_GetRuntimeClassName, activation_factory_GetTrustLevel,
    activation_factory_ActivateInstance};

DEFINE_IINSPECTABLE(core, ICoreApplication, struct factory, IActivationFactory_iface)
static HRESULT WINAPI core_get_Id(ICoreApplication *iface, HSTRING *value)
{
    if (!value) return E_POINTER;
    return WindowsCreateString(NULL, 0, value);
}
static HRESULT WINAPI core_add_Suspending(ICoreApplication *iface, IEventHandler_SuspendingEventArgs *handler, EventRegistrationToken *token)
{ return event_source_add(&suspending_handlers, (IUnknown *)handler, token); }
static HRESULT WINAPI core_remove_Suspending(ICoreApplication *iface, EventRegistrationToken token)
{ return event_source_remove(&suspending_handlers, token); }
static HRESULT WINAPI core_add_Resuming(ICoreApplication *iface, IEventHandler_IInspectable *handler, EventRegistrationToken *token)
{ return event_source_add(&resuming_handlers, (IUnknown *)handler, token); }
static HRESULT WINAPI core_remove_Resuming(ICoreApplication *iface, EventRegistrationToken token)
{ return event_source_remove(&resuming_handlers, token); }
static HRESULT WINAPI core_get_Properties(ICoreApplication *iface, IPropertySet **value)
{ return get_property_set(&properties, value); }
static HRESULT WINAPI core_GetCurrentView(ICoreApplication *iface, ICoreApplicationView **value)
{ if (!value) return E_POINTER; *value = NULL; return HRESULT_FROM_WIN32(ERROR_NOT_FOUND); }
static HRESULT WINAPI core_Run(ICoreApplication *iface, IFrameworkViewSource *source)
{ FIXME("framework-view hosting is not implemented.\n"); return E_NOTIMPL; }
static HRESULT WINAPI core_RunWithActivationFactories(ICoreApplication *iface, IGetActivationFactory *factory)
{ FIXME("activation-factory hosting is not implemented.\n"); return E_NOTIMPL; }
static const ICoreApplicationVtbl core_vtbl = {core_QueryInterface, core_AddRef, core_Release,
    core_GetIids, core_GetRuntimeClassName, core_GetTrustLevel, core_get_Id, core_add_Suspending,
    core_remove_Suspending, core_add_Resuming, core_remove_Resuming, core_get_Properties,
    core_GetCurrentView, core_Run, core_RunWithActivationFactories};

DEFINE_IINSPECTABLE(core2, ICoreApplication2, struct factory, IActivationFactory_iface)
static HRESULT WINAPI core2_add_BackgroundActivated(ICoreApplication2 *iface, IEventHandler_BackgroundActivatedEventArgs *handler, EventRegistrationToken *token)
{ return event_source_add(&background_handlers, (IUnknown *)handler, token); }
static HRESULT WINAPI core2_remove_BackgroundActivated(ICoreApplication2 *iface, EventRegistrationToken token)
{ return event_source_remove(&background_handlers, token); }
static HRESULT WINAPI core2_add_LeavingBackground(ICoreApplication2 *iface, IEventHandler_LeavingBackgroundEventArgs *handler, EventRegistrationToken *token)
{ return event_source_add(&leaving_background_handlers, (IUnknown *)handler, token); }
static HRESULT WINAPI core2_remove_LeavingBackground(ICoreApplication2 *iface, EventRegistrationToken token)
{ return event_source_remove(&leaving_background_handlers, token); }
static HRESULT WINAPI core2_add_EnteredBackground(ICoreApplication2 *iface, IEventHandler_EnteredBackgroundEventArgs *handler, EventRegistrationToken *token)
{ return event_source_add(&entered_background_handlers, (IUnknown *)handler, token); }
static HRESULT WINAPI core2_remove_EnteredBackground(ICoreApplication2 *iface, EventRegistrationToken token)
{ return event_source_remove(&entered_background_handlers, token); }
static HRESULT WINAPI core2_EnablePrelaunch(ICoreApplication2 *iface, boolean value) { return S_OK; }
static const ICoreApplication2Vtbl core2_vtbl = {core2_QueryInterface, core2_AddRef, core2_Release,
    core2_GetIids, core2_GetRuntimeClassName, core2_GetTrustLevel, core2_add_BackgroundActivated,
    core2_remove_BackgroundActivated, core2_add_LeavingBackground, core2_remove_LeavingBackground,
    core2_add_EnteredBackground, core2_remove_EnteredBackground, core2_EnablePrelaunch};

DEFINE_IINSPECTABLE(core3, ICoreApplication3, struct factory, IActivationFactory_iface)
static HRESULT WINAPI core3_RequestRestartAsync(ICoreApplication3 *iface, HSTRING args, IAsyncOperation_AppRestartFailureReason **operation)
{ if (operation) *operation = NULL; return E_NOTIMPL; }
static HRESULT WINAPI core3_RequestRestartForUserAsync(ICoreApplication3 *iface,
        __x_ABI_CWindows_CSystem_CIUser *user, HSTRING args, IAsyncOperation_AppRestartFailureReason **operation)
{ if (operation) *operation = NULL; return E_NOTIMPL; }
static const ICoreApplication3Vtbl core3_vtbl = {core3_QueryInterface, core3_AddRef, core3_Release,
    core3_GetIids, core3_GetRuntimeClassName, core3_GetTrustLevel,
    core3_RequestRestartAsync, core3_RequestRestartForUserAsync};

DEFINE_IINSPECTABLE(core_exit, ICoreApplicationExit, struct factory, IActivationFactory_iface)
static HRESULT WINAPI core_exit_Exit(ICoreApplicationExit *iface) { return E_NOTIMPL; }
static HRESULT WINAPI core_exit_add_Exiting(ICoreApplicationExit *iface, IEventHandler_IInspectable *handler, EventRegistrationToken *token)
{ return event_source_add(&exiting_handlers, (IUnknown *)handler, token); }
static HRESULT WINAPI core_exit_remove_Exiting(ICoreApplicationExit *iface, EventRegistrationToken token)
{ return event_source_remove(&exiting_handlers, token); }
static const ICoreApplicationExitVtbl core_exit_vtbl = {core_exit_QueryInterface, core_exit_AddRef,
    core_exit_Release, core_exit_GetIids, core_exit_GetRuntimeClassName, core_exit_GetTrustLevel,
    core_exit_Exit, core_exit_add_Exiting, core_exit_remove_Exiting};

DEFINE_IINSPECTABLE(core_unhandled, ICoreApplicationUnhandledError, struct factory, IActivationFactory_iface)
static HRESULT WINAPI core_unhandled_add_UnhandledErrorDetected(ICoreApplicationUnhandledError *iface, IEventHandler_UnhandledErrorDetectedEventArgs *handler, EventRegistrationToken *token)
{ return event_source_add(&unhandled_error_handlers, (IUnknown *)handler, token); }
static HRESULT WINAPI core_unhandled_remove_UnhandledErrorDetected(ICoreApplicationUnhandledError *iface, EventRegistrationToken token)
{ return event_source_remove(&unhandled_error_handlers, token); }
static const ICoreApplicationUnhandledErrorVtbl core_unhandled_vtbl = {core_unhandled_QueryInterface,
    core_unhandled_AddRef, core_unhandled_Release, core_unhandled_GetIids,
    core_unhandled_GetRuntimeClassName, core_unhandled_GetTrustLevel,
    core_unhandled_add_UnhandledErrorDetected, core_unhandled_remove_UnhandledErrorDetected};

DEFINE_IINSPECTABLE(core_use, ICoreApplicationUseCount, struct factory, IActivationFactory_iface)
static HRESULT WINAPI core_use_IncrementApplicationUseCount(ICoreApplicationUseCount *iface)
{ InterlockedIncrement(&impl_from_ICoreApplicationUseCount(iface)->use_count); return S_OK; }
static HRESULT WINAPI core_use_DecrementApplicationUseCount(ICoreApplicationUseCount *iface)
{
    struct factory *impl = impl_from_ICoreApplicationUseCount(iface);
    LONG count;
    do { count = impl->use_count; if (!count) return E_ILLEGAL_METHOD_CALL; }
    while (InterlockedCompareExchange(&impl->use_count, count - 1, count) != count);
    return S_OK;
}
static const ICoreApplicationUseCountVtbl core_use_vtbl = {core_use_QueryInterface, core_use_AddRef,
    core_use_Release, core_use_GetIids, core_use_GetRuntimeClassName, core_use_GetTrustLevel,
    core_use_IncrementApplicationUseCount, core_use_DecrementApplicationUseCount};

struct empty_view_vector { IVectorView_CoreApplicationView iface; LONG ref; };
static inline struct empty_view_vector *impl_from_empty_vector(IVectorView_CoreApplicationView *iface)
{ return CONTAINING_RECORD(iface, struct empty_view_vector, iface); }
static HRESULT WINAPI empty_vector_QueryInterface(IVectorView_CoreApplicationView *iface, REFIID iid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (!IsEqualGUID(iid, &IID_IUnknown) && !IsEqualGUID(iid, &IID_IInspectable) &&
        !IsEqualGUID(iid, &IID_IAgileObject) && !IsEqualGUID(iid, &IID_IVectorView_CoreApplicationView)) return E_NOINTERFACE;
    IVectorView_CoreApplicationView_AddRef(iface); *out = iface; return S_OK;
}
static ULONG WINAPI empty_vector_AddRef(IVectorView_CoreApplicationView *iface)
{ return InterlockedIncrement(&impl_from_empty_vector(iface)->ref); }
static ULONG WINAPI empty_vector_Release(IVectorView_CoreApplicationView *iface)
{ return InterlockedDecrement(&impl_from_empty_vector(iface)->ref); }
static HRESULT WINAPI empty_vector_GetIids(IVectorView_CoreApplicationView *iface, ULONG *count, IID **iids)
{
    if (!count || !iids) return E_POINTER; *count = 0;
    if (!(*iids = CoTaskMemAlloc(sizeof(**iids)))) return E_OUTOFMEMORY;
    **iids = IID_IVectorView_CoreApplicationView; *count = 1; return S_OK;
}
static HRESULT WINAPI empty_vector_GetRuntimeClassName(IVectorView_CoreApplicationView *iface, HSTRING *name)
{ if (!name) return E_POINTER; *name = NULL; return S_OK; }
static HRESULT WINAPI empty_vector_GetTrustLevel(IVectorView_CoreApplicationView *iface, TrustLevel *level)
{ if (!level) return E_POINTER; *level = BaseTrust; return S_OK; }
static HRESULT WINAPI empty_vector_GetAt(IVectorView_CoreApplicationView *iface, UINT32 index, ICoreApplicationView **value)
{ if (!value) return E_POINTER; *value = NULL; return E_BOUNDS; }
static HRESULT WINAPI empty_vector_get_Size(IVectorView_CoreApplicationView *iface, UINT32 *value)
{ if (!value) return E_POINTER; *value = 0; return S_OK; }
static HRESULT WINAPI empty_vector_IndexOf(IVectorView_CoreApplicationView *iface, ICoreApplicationView *element, UINT32 *index, boolean *found)
{ if (!index || !found) return E_POINTER; *index = 0; *found = FALSE; return S_OK; }
static HRESULT WINAPI empty_vector_GetMany(IVectorView_CoreApplicationView *iface, UINT32 start, UINT32 size, ICoreApplicationView **items, UINT32 *value)
{ if (!value) return E_POINTER; *value = 0; return start ? E_BOUNDS : S_OK; }
static const IVectorView_CoreApplicationViewVtbl empty_vector_vtbl = {empty_vector_QueryInterface,
    empty_vector_AddRef, empty_vector_Release, empty_vector_GetIids,
    empty_vector_GetRuntimeClassName, empty_vector_GetTrustLevel, empty_vector_GetAt,
    empty_vector_get_Size, empty_vector_IndexOf, empty_vector_GetMany};
static struct empty_view_vector empty_vector = {{&empty_vector_vtbl}, 1};

DEFINE_IINSPECTABLE(immersive, ICoreImmersiveApplication, struct factory, IActivationFactory_iface)
static HRESULT WINAPI immersive_get_Views(ICoreImmersiveApplication *iface, IVectorView_CoreApplicationView **value)
{ if (!value) return E_POINTER; IVectorView_CoreApplicationView_AddRef(&empty_vector.iface); *value = &empty_vector.iface; return S_OK; }
static HRESULT WINAPI immersive_CreateNewView(ICoreImmersiveApplication *iface, HSTRING runtime, HSTRING entry, ICoreApplicationView **view)
{ if (view) *view = NULL; return E_NOTIMPL; }
static HRESULT WINAPI immersive_get_MainView(ICoreImmersiveApplication *iface, ICoreApplicationView **value)
{ if (!value) return E_POINTER; *value = NULL; return HRESULT_FROM_WIN32(ERROR_NOT_FOUND); }
static const ICoreImmersiveApplicationVtbl immersive_vtbl = {immersive_QueryInterface, immersive_AddRef,
    immersive_Release, immersive_GetIids, immersive_GetRuntimeClassName, immersive_GetTrustLevel,
    immersive_get_Views, immersive_CreateNewView, immersive_get_MainView};

DEFINE_IINSPECTABLE(immersive2, ICoreImmersiveApplication2, struct factory, IActivationFactory_iface)
static HRESULT WINAPI immersive2_CreateNewViewFromMainView(ICoreImmersiveApplication2 *iface, ICoreApplicationView **view)
{ if (view) *view = NULL; return E_NOTIMPL; }
static const ICoreImmersiveApplication2Vtbl immersive2_vtbl = {immersive2_QueryInterface,
    immersive2_AddRef, immersive2_Release, immersive2_GetIids, immersive2_GetRuntimeClassName,
    immersive2_GetTrustLevel, immersive2_CreateNewViewFromMainView};

DEFINE_IINSPECTABLE(immersive3, ICoreImmersiveApplication3, struct factory, IActivationFactory_iface)
static HRESULT WINAPI immersive3_CreateNewViewWithViewSource(ICoreImmersiveApplication3 *iface, IFrameworkViewSource *source, ICoreApplicationView **view)
{ if (view) *view = NULL; return E_NOTIMPL; }
static const ICoreImmersiveApplication3Vtbl immersive3_vtbl = {immersive3_QueryInterface,
    immersive3_AddRef, immersive3_Release, immersive3_GetIids, immersive3_GetRuntimeClassName,
    immersive3_GetTrustLevel, immersive3_CreateNewViewWithViewSource};

static inline struct factory *impl_from_ICoreApplicationPrivate(ICoreApplicationPrivate *iface)
{ return CONTAINING_RECORD(iface, struct factory, ICoreApplicationPrivate_iface); }
static HRESULT WINAPI private_QueryInterface(ICoreApplicationPrivate *iface, REFIID iid, void **out)
{ return IActivationFactory_QueryInterface(&impl_from_ICoreApplicationPrivate(iface)->IActivationFactory_iface, iid, out); }
static ULONG WINAPI private_AddRef(ICoreApplicationPrivate *iface)
{ return IActivationFactory_AddRef(&impl_from_ICoreApplicationPrivate(iface)->IActivationFactory_iface); }
static ULONG WINAPI private_Release(ICoreApplicationPrivate *iface)
{ return IActivationFactory_Release(&impl_from_ICoreApplicationPrivate(iface)->IActivationFactory_iface); }
static HRESULT WINAPI private_GetIids(ICoreApplicationPrivate *iface, ULONG *count, IID **iids)
{ return IActivationFactory_GetIids(&impl_from_ICoreApplicationPrivate(iface)->IActivationFactory_iface, count, iids); }
static HRESULT WINAPI private_GetRuntimeClassName(ICoreApplicationPrivate *iface, HSTRING *name)
{ return IActivationFactory_GetRuntimeClassName(&impl_from_ICoreApplicationPrivate(iface)->IActivationFactory_iface, name); }
static HRESULT WINAPI private_GetTrustLevel(ICoreApplicationPrivate *iface, TrustLevel *level)
{ return IActivationFactory_GetTrustLevel(&impl_from_ICoreApplicationPrivate(iface)->IActivationFactory_iface, level); }
static HRESULT WINAPI private_get_Properties(ICoreApplicationPrivate *iface, IPropertySet **value)
{ return get_property_set(&properties, value); }
static HRESULT WINAPI private_get_PrivateProperties(ICoreApplicationPrivate *iface, IPropertySet **value)
{ return get_property_set(&private_properties, value); }
#define PRIVATE_NOT_FOUND(name, keytype, outtype) \
    static HRESULT WINAPI name(ICoreApplicationPrivate *iface, keytype key, outtype **value) \
    { if (!value) return E_POINTER; *value = NULL; return HRESULT_FROM_WIN32(ERROR_NOT_FOUND); }
PRIVATE_NOT_FOUND(private_GetWindowFromThreadId, DWORD, IInspectable)
PRIVATE_NOT_FOUND(private_GetViewFromThreadId, DWORD, IInspectable)
static HRESULT WINAPI private_GetAppDisplayName(ICoreApplicationPrivate *iface, HSTRING *value)
{ if (!value) return E_POINTER; return WindowsCreateString(NULL, 0, value); }
static HRESULT WINAPI private_add_FinalUnhandledErrorDetected(ICoreApplicationPrivate *iface, IUnknown *handler, EventRegistrationToken *token)
{ return event_source_add(&final_unhandled_error_handlers, handler, token); }
static HRESULT WINAPI private_remove_FinalUnhandledErrorDetected(ICoreApplicationPrivate *iface, EventRegistrationToken token)
{ return event_source_remove(&final_unhandled_error_handlers, token); }
PRIVATE_NOT_FOUND(private_GetDispatcherFromHwnd, UINT, IInspectable)
static HRESULT WINAPI private_IsMainWindowCreated(ICoreApplicationPrivate *iface, boolean *value)
{ if (!value) return E_POINTER; *value = FALSE; return S_OK; }
static HRESULT WINAPI private_GetComponentSiteFromSiteId(ICoreApplicationPrivate *iface, GUID id, IInspectable **value)
{ if (!value) return E_POINTER; *value = NULL; return HRESULT_FROM_WIN32(ERROR_NOT_FOUND); }
static HRESULT WINAPI private_GetCurrentView(ICoreApplicationPrivate *iface, UINT options, ICoreApplicationView **value)
{ if (!value) return E_POINTER; *value = NULL; return HRESULT_FROM_WIN32(ERROR_NOT_FOUND); }
static HRESULT WINAPI private_GetHwndFromViewOnASTA(ICoreApplicationPrivate *iface, ICoreApplicationView *view, UINT *hwnd)
{ if (!hwnd) return E_POINTER; *hwnd = 0; return HRESULT_FROM_WIN32(ERROR_NOT_FOUND); }
PRIVATE_NOT_FOUND(private_GetComponentSiteByViewInstanceId, UINT, IInspectable)
static const ICoreApplicationPrivateVtbl private_vtbl = {private_QueryInterface, private_AddRef,
    private_Release, private_GetIids, private_GetRuntimeClassName, private_GetTrustLevel,
    private_get_Properties, private_get_PrivateProperties, private_GetWindowFromThreadId,
    private_GetViewFromThreadId, private_GetAppDisplayName, private_add_FinalUnhandledErrorDetected,
    private_remove_FinalUnhandledErrorDetected, private_GetDispatcherFromHwnd,
    private_IsMainWindowCreated, private_GetComponentSiteFromSiteId, private_GetCurrentView,
    private_GetHwndFromViewOnASTA, private_GetComponentSiteByViewInstanceId};

static struct factory factory = {{&activation_factory_vtbl}, {&core_vtbl}, {&core2_vtbl},
    {&core3_vtbl}, {&core_exit_vtbl}, {&core_unhandled_vtbl}, {&core_use_vtbl},
    {&immersive_vtbl}, {&immersive2_vtbl}, {&immersive3_vtbl}, {&private_vtbl}, 1, 0};

IActivationFactory *core_application_factory = &factory.IActivationFactory_iface;
