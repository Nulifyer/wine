/*
 * Standard COM activator and its per-instance session properties.
 * Copyright 2026 Nulifyer
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 or
 * any later version.
 */

#define COBJMACROS
#include "objbase.h"
#include "combase_private.h"
#include "initguid.h"
#include "stdactivator.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(stdactivator);

const CLSID CLSID_ComActivator = {0x0000033c, 0, 0, {0xc0, 0, 0, 0, 0, 0, 0, 0x46}};

struct standard_activator
{
    IStandardActivator IStandardActivator_iface;
    ISpecialSystemProperties ISpecialSystemProperties_iface;
    LONG refs;
    SRWLOCK lock;
    BOOL properties_present;
    DWORD session;
    BOOL console;
    BOOL remote;
    BOOL impersonating;
};

static struct standard_activator *impl_from_IStandardActivator(IStandardActivator *iface)
{
    return CONTAINING_RECORD(iface, struct standard_activator, IStandardActivator_iface);
}

static struct standard_activator *impl_from_ISpecialSystemProperties(ISpecialSystemProperties *iface)
{
    return CONTAINING_RECORD(iface, struct standard_activator, ISpecialSystemProperties_iface);
}

static HRESULT WINAPI activator_QueryInterface(IStandardActivator *iface, REFIID iid, void **object)
{
    struct standard_activator *activator = impl_from_IStandardActivator(iface);

    if (!object) return E_POINTER;
    *object = NULL;
    if (IsEqualIID(iid, &IID_IUnknown) || IsEqualIID(iid, &IID_IStandardActivator))
        *object = &activator->IStandardActivator_iface;
    else if (IsEqualIID(iid, &IID_ISpecialSystemProperties))
        *object = &activator->ISpecialSystemProperties_iface;
    else return E_NOINTERFACE;
    IStandardActivator_AddRef(iface);
    return S_OK;
}

static ULONG WINAPI activator_AddRef(IStandardActivator *iface)
{
    return InterlockedIncrement(&impl_from_IStandardActivator(iface)->refs);
}

static ULONG WINAPI activator_Release(IStandardActivator *iface)
{
    struct standard_activator *activator = impl_from_IStandardActivator(iface);
    ULONG refs = InterlockedDecrement(&activator->refs);

    if (!refs) free(activator);
    return refs;
}

/* S_FALSE selects the shared registered-server owner. Other methods retain
 * their guard until their explicit-session activation contracts are covered. */
static HRESULT activation_context(struct standard_activator *activator, DWORD context,
                                  BOOL allow_scoped, DWORD *target_session)
{
    BOOL present, console, remote, impersonating;
    DWORD session, current;

    AcquireSRWLockShared(&activator->lock);
    present = activator->properties_present;
    console = activator->console;
    remote = activator->remote;
    impersonating = activator->impersonating;
    session = activator->session;
    ReleaseSRWLockShared(&activator->lock);
    if (!present) return S_OK;
    if (impersonating) return E_NOTIMPL;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &current))
        return HRESULT_FROM_WIN32(GetLastError());
    /* Native AddHydraSessionID uses the current process when the third
     * property is false. Stored getters still return the original state. */
    if (!remote)
    {
        session = current;
        console = FALSE;
    }
    if (context & (CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER))
    {
        if (!allow_scoped || console || session == ~0u || !(context & CLSCTX_LOCAL_SERVER) ||
            (context & ~(CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER | CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER)))
            return E_NOTIMPL;
        *target_session = session;
        return S_FALSE;
    }
    if (console) session = WTSGetActiveConsoleSessionId();
    if (session == ~0u || session != current) return E_NOTIMPL;
    return S_OK;
}

static HRESULT WINAPI activator_StandardGetClassObject(IStandardActivator *iface, REFCLSID clsid,
        DWORD context, COSERVERINFO *server, REFIID iid, void **object)
{
    DWORD session;
    HRESULT hr;

    TRACE("class %s context %#lx iid %s\n", debugstr_guid(clsid), context, debugstr_guid(iid));
    if (!object) return E_POINTER;
    *object = NULL;
    hr = activation_context(impl_from_IStandardActivator(iface), context, TRUE, &session);
    if (FAILED(hr)) return hr;
    if (hr == S_FALSE)
    {
        if (server) return E_NOTIMPL;
        return rpc_get_local_class_object_session(clsid, iid, session, context, object);
    }
    return CoGetClassObject(clsid, context, server, iid, object);
}

static HRESULT WINAPI activator_StandardCreateInstance(IStandardActivator *iface, REFCLSID clsid,
        IUnknown *outer, DWORD context, COSERVERINFO *server, DWORD count, MULTI_QI *results)
{
    HRESULT hr;

    if (FAILED(hr = activation_context(impl_from_IStandardActivator(iface), context, FALSE, NULL))) return hr;
    return CoCreateInstanceEx(clsid, outer, context, server, count, results);
}

static HRESULT WINAPI activator_StandardGetInstanceFromFile(IStandardActivator *iface,
        COSERVERINFO *server, CLSID *clsid, IUnknown *outer, DWORD context, DWORD mode,
        OLECHAR *name, DWORD count, MULTI_QI *results)
{
    HRESULT hr;

    if (FAILED(hr = activation_context(impl_from_IStandardActivator(iface), context, FALSE, NULL))) return hr;
    return CoGetInstanceFromFile(server, clsid, outer, context, mode, name, count, results);
}

static HRESULT WINAPI activator_StandardGetInstanceFromIStorage(IStandardActivator *iface,
        COSERVERINFO *server, CLSID *clsid, IUnknown *outer, DWORD context, IStorage *storage,
        DWORD count, MULTI_QI *results)
{
    HRESULT hr;

    if (FAILED(hr = activation_context(impl_from_IStandardActivator(iface), context, FALSE, NULL))) return hr;
    return CoGetInstanceFromIStorage(server, clsid, outer, context, storage, count, results);
}

static HRESULT WINAPI activator_Reset(IStandardActivator *iface)
{
    struct standard_activator *activator = impl_from_IStandardActivator(iface);

    AcquireSRWLockExclusive(&activator->lock);
    activator->properties_present = FALSE;
    activator->session = 0;
    activator->console = activator->remote = activator->impersonating = FALSE;
    ReleaseSRWLockExclusive(&activator->lock);
    return S_OK;
}

static const IStandardActivatorVtbl activator_vtbl =
{
    activator_QueryInterface,
    activator_AddRef,
    activator_Release,
    activator_StandardGetClassObject,
    activator_StandardCreateInstance,
    activator_StandardGetInstanceFromFile,
    activator_StandardGetInstanceFromIStorage,
    activator_Reset,
};

static HRESULT WINAPI properties_QueryInterface(ISpecialSystemProperties *iface, REFIID iid, void **object)
{
    return activator_QueryInterface(&impl_from_ISpecialSystemProperties(iface)->IStandardActivator_iface, iid, object);
}

static ULONG WINAPI properties_AddRef(ISpecialSystemProperties *iface)
{
    return activator_AddRef(&impl_from_ISpecialSystemProperties(iface)->IStandardActivator_iface);
}

static ULONG WINAPI properties_Release(ISpecialSystemProperties *iface)
{
    return activator_Release(&impl_from_ISpecialSystemProperties(iface)->IStandardActivator_iface);
}

static HRESULT WINAPI properties_SetSessionId(ISpecialSystemProperties *iface, DWORD session,
        BOOL console, BOOL remote)
{
    struct standard_activator *activator = impl_from_ISpecialSystemProperties(iface);

    TRACE("session %lu console %d remote %d\n", session, console, remote);
    AcquireSRWLockExclusive(&activator->lock);
    activator->properties_present = TRUE;
    activator->session = console ? 0 : session;
    activator->console = !!console;
    activator->remote = remote;
    ReleaseSRWLockExclusive(&activator->lock);
    return S_OK;
}

static HRESULT WINAPI properties_GetSessionId2(ISpecialSystemProperties *iface, DWORD *session,
        BOOL *console, BOOL *remote)
{
    struct standard_activator *activator = impl_from_ISpecialSystemProperties(iface);
    HRESULT hr = E_INVALIDARG;

    if (!session || !console || !remote) return E_POINTER;
    AcquireSRWLockShared(&activator->lock);
    if (activator->properties_present)
    {
        *session = activator->session;
        *console = activator->console;
        *remote = activator->remote;
        hr = S_OK;
    }
    ReleaseSRWLockShared(&activator->lock);
    return hr;
}

static HRESULT WINAPI properties_GetSessionId(ISpecialSystemProperties *iface, DWORD *session, BOOL *console)
{
    BOOL remote;

    return properties_GetSessionId2(iface, session, console, &remote);
}

static HRESULT WINAPI properties_SetClientImpersonating(ISpecialSystemProperties *iface, BOOL value)
{
    struct standard_activator *activator = impl_from_ISpecialSystemProperties(iface);
    HRESULT hr = E_INVALIDARG;

    AcquireSRWLockExclusive(&activator->lock);
    if (activator->properties_present)
    {
        activator->impersonating = value;
        hr = S_OK;
    }
    ReleaseSRWLockExclusive(&activator->lock);
    return hr;
}

static HRESULT WINAPI properties_GetClientImpersonating(ISpecialSystemProperties *iface, BOOL *value)
{
    struct standard_activator *activator = impl_from_ISpecialSystemProperties(iface);
    HRESULT hr = E_INVALIDARG;

    if (!value) return E_POINTER;
    AcquireSRWLockShared(&activator->lock);
    if (activator->properties_present)
    {
        *value = activator->impersonating;
        hr = S_OK;
    }
    ReleaseSRWLockShared(&activator->lock);
    return hr;
}

/* Retain native slot widths, including the pointer-sized LUA window value. Unimplemented activation policy must not report success. */
#define UNSUPPORTED(name, args) \
    static HRESULT WINAPI properties_##name args { return E_NOTIMPL; }
UNSUPPORTED(SetPartitionId, (ISpecialSystemProperties *iface, REFGUID partition))
UNSUPPORTED(GetPartitionId, (ISpecialSystemProperties *iface, GUID *partition))
UNSUPPORTED(SetProcessRequestType, (ISpecialSystemProperties *iface, DWORD type))
UNSUPPORTED(GetProcessRequestType, (ISpecialSystemProperties *iface, DWORD *type))
UNSUPPORTED(SetOrigClsctx, (ISpecialSystemProperties *iface, DWORD context))
UNSUPPORTED(GetOrigClsctx, (ISpecialSystemProperties *iface, DWORD *context))
UNSUPPORTED(GetDefaultAuthenticationLevel, (ISpecialSystemProperties *iface, DWORD *level))
UNSUPPORTED(SetDefaultAuthenticationLevel, (ISpecialSystemProperties *iface, DWORD level))
UNSUPPORTED(GetLUARunLevel, (ISpecialSystemProperties *iface, DWORD *level, ULONG_PTR *window))
UNSUPPORTED(SetLUARunLevel, (ISpecialSystemProperties *iface, DWORD level, ULONG_PTR window))
UNSUPPORTED(FlagQuery, (ISpecialSystemProperties *iface, DWORD flags))
UNSUPPORTED(FlagSet, (ISpecialSystemProperties *iface, DWORD flags))
UNSUPPORTED(FlagClear, (ISpecialSystemProperties *iface, DWORD flags))
UNSUPPORTED(SetServiceId, (ISpecialSystemProperties *iface, DWORD service))
UNSUPPORTED(GetServiceId, (ISpecialSystemProperties *iface, DWORD *service))
#undef UNSUPPORTED

static const ISpecialSystemPropertiesVtbl properties_vtbl =
{
    properties_QueryInterface,
    properties_AddRef,
    properties_Release,
    properties_SetSessionId,
    properties_GetSessionId,
    properties_GetSessionId2,
    properties_SetClientImpersonating,
    properties_GetClientImpersonating,
    properties_SetPartitionId,
    properties_GetPartitionId,
    properties_SetProcessRequestType,
    properties_GetProcessRequestType,
    properties_SetOrigClsctx,
    properties_GetOrigClsctx,
    properties_GetDefaultAuthenticationLevel,
    properties_SetDefaultAuthenticationLevel,
    properties_GetLUARunLevel,
    properties_SetLUARunLevel,
    properties_FlagQuery,
    properties_FlagSet,
    properties_FlagClear,
    properties_SetServiceId,
    properties_GetServiceId,
};

static HRESULT WINAPI factory_QueryInterface(IClassFactory *iface, REFIID iid, void **object)
{
    if (!object) return E_POINTER;
    *object = NULL;
    if (!IsEqualIID(iid, &IID_IUnknown) && !IsEqualIID(iid, &IID_IClassFactory)) return E_NOINTERFACE;
    *object = iface;
    IClassFactory_AddRef(iface);
    return S_OK;
}

static ULONG WINAPI factory_AddRef(IClassFactory *iface) { return 2; }
static ULONG WINAPI factory_Release(IClassFactory *iface) { return 1; }

static HRESULT WINAPI factory_CreateInstance(IClassFactory *iface, IUnknown *outer,
        REFIID iid, void **object)
{
    struct standard_activator *activator;
    HRESULT hr;

    if (!object) return E_POINTER;
    *object = NULL;
    TRACE("outer %p iid %s\n", outer, debugstr_guid(iid));
    if (outer) return CLASS_E_NOAGGREGATION;
    if (!(activator = calloc(1, sizeof(*activator)))) return E_OUTOFMEMORY;
    activator->IStandardActivator_iface.lpVtbl = &activator_vtbl;
    activator->ISpecialSystemProperties_iface.lpVtbl = &properties_vtbl;
    activator->refs = 1;
    InitializeSRWLock(&activator->lock);
    hr = activator_QueryInterface(&activator->IStandardActivator_iface, iid, object);
    activator_Release(&activator->IStandardActivator_iface);
    return hr;
}

static HRESULT WINAPI factory_LockServer(IClassFactory *iface, BOOL lock)
{
    TRACE("lock %d\n", lock);
    return S_OK;
}

static const IClassFactoryVtbl factory_vtbl =
{
    factory_QueryInterface, factory_AddRef, factory_Release, factory_CreateInstance, factory_LockServer,
};
static IClassFactory factory = { &factory_vtbl };

HRESULT standard_activator_get_class_factory(REFIID iid, void **object)
{
    return IClassFactory_QueryInterface(&factory, iid, object);
}
