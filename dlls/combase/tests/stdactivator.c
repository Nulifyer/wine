/*
 * Standard-activator identity, state and delegation.
 * Copyright 2026 Nulifyer
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 or
 * any later version.
 */

#define COBJMACROS
#include "objbase.h"
#include "initguid.h"
#include "../stdactivator.h"
#include "wine/test.h"

C_ASSERT(FIELD_OFFSET(IStandardActivatorVtbl, StandardGetClassObject) == 3 * sizeof(void *));
C_ASSERT(FIELD_OFFSET(IStandardActivatorVtbl, Reset) == 7 * sizeof(void *));
C_ASSERT(FIELD_OFFSET(ISpecialSystemPropertiesVtbl, SetSessionId) == 3 * sizeof(void *));
C_ASSERT(FIELD_OFFSET(ISpecialSystemPropertiesVtbl, GetSessionId2) == 5 * sizeof(void *));
C_ASSERT(FIELD_OFFSET(ISpecialSystemPropertiesVtbl, SetLUARunLevel) == 17 * sizeof(void *));

static const CLSID activator_clsid = {0x0000033c, 0, 0, {0xc0, 0, 0, 0, 0, 0, 0, 0x46}};
static const CLSID test_clsid = {0xe306dd02, 0xc68a, 0x419e, {0x94, 0x99, 0xc7, 0x40, 0x14, 0x19, 0x03, 0xba}};
static LONG create_calls;

static HRESULT WINAPI test_QueryInterface(IClassFactory *iface, REFIID iid, void **object)
{
    *object = NULL;
    if (!IsEqualIID(iid, &IID_IUnknown) && !IsEqualIID(iid, &IID_IClassFactory)) return E_NOINTERFACE;
    *object = iface;
    IClassFactory_AddRef(iface);
    return S_OK;
}
static ULONG WINAPI test_AddRef(IClassFactory *iface) { return 2; }
static ULONG WINAPI test_Release(IClassFactory *iface) { return 1; }
static HRESULT WINAPI test_CreateInstance(IClassFactory *iface, IUnknown *outer, REFIID iid, void **object)
{
    InterlockedIncrement(&create_calls);
    if (outer) return CLASS_E_NOAGGREGATION;
    return test_QueryInterface(iface, iid, object);
}
static HRESULT WINAPI test_LockServer(IClassFactory *iface, BOOL lock) { return S_OK; }
static const IClassFactoryVtbl test_vtbl =
{
    test_QueryInterface, test_AddRef, test_Release, test_CreateInstance, test_LockServer,
};
static IClassFactory test_factory = { &test_vtbl };

static void test_activator(void)
{
    IStandardActivator *activator, *second;
    ISpecialSystemProperties *properties, *second_properties;
    IClassFactory *factory;
    IUnknown *identity, *other_identity, *object;
    BOOL console, remote, impersonating;
    DWORD session, current, cookie;
    HRESULT hr;
    MULTI_QI results[2];
    LONG calls;

    hr = CoGetClassObject(&activator_clsid, CLSCTX_INPROC_SERVER, NULL, &IID_IClassFactory, (void **)&factory);
    ok(hr == S_OK, "Activator class factory returned %#lx.\n", hr);
    if (FAILED(hr)) return;
    hr = IClassFactory_LockServer(factory, TRUE);
    ok(hr == S_OK, "Factory lock returned %#lx.\n", hr);
    hr = IClassFactory_LockServer(factory, FALSE);
    ok(hr == S_OK, "Factory unlock returned %#lx.\n", hr);
    hr = IClassFactory_CreateInstance(factory, NULL, &IID_IStandardActivator, (void **)&activator);
    ok(hr == S_OK, "Activator creation returned %#lx.\n", hr);
    IClassFactory_Release(factory);
    if (FAILED(hr)) return;
    hr = IStandardActivator_QueryInterface(activator, &IID_ISpecialSystemProperties, (void **)&properties);
    ok(hr == S_OK, "Properties query returned %#lx.\n", hr);
    if (FAILED(hr))
    {
        IStandardActivator_Release(activator);
        return;
    }
    hr = IStandardActivator_QueryInterface(activator, &IID_IUnknown, (void **)&identity);
    ok(hr == S_OK, "Identity query returned %#lx.\n", hr);
    hr = ISpecialSystemProperties_QueryInterface(properties, &IID_IUnknown, (void **)&other_identity);
    ok(hr == S_OK && identity == other_identity, "Properties identity differs, hr %#lx.\n", hr);
    IUnknown_Release(other_identity);
    IUnknown_Release(identity);

    session = 0xdeadbeef;
    console = remote = 0x1234;
    hr = ISpecialSystemProperties_GetSessionId2(properties, &session, &console, &remote);
    ok(hr == E_INVALIDARG && session == 0xdeadbeef && console == 0x1234 && remote == 0x1234,
       "Cold session query returned %#lx, %lu, %d, %d.\n", hr, session, console, remote);
    hr = ISpecialSystemProperties_SetClientImpersonating(properties, TRUE);
    ok(hr == E_INVALIDARG, "Cold impersonating setter returned %#lx.\n", hr);

    hr = ISpecialSystemProperties_SetSessionId(properties, 17, FALSE, 7);
    ok(hr == S_OK, "Session setter returned %#lx.\n", hr);
    hr = ISpecialSystemProperties_GetSessionId2(properties, &session, &console, &remote);
    ok(hr == S_OK && session == 17 && !console && remote == 7,
       "Session state returned %#lx, %lu, %d, %d.\n", hr, session, console, remote);
    hr = ISpecialSystemProperties_GetClientImpersonating(properties, &impersonating);
    ok(hr == S_OK && !impersonating, "Initial impersonating state returned %#lx, %d.\n", hr, impersonating);
    hr = ISpecialSystemProperties_SetClientImpersonating(properties, 3);
    ok(hr == S_OK, "Impersonating setter returned %#lx.\n", hr);
    hr = ISpecialSystemProperties_GetClientImpersonating(properties, &impersonating);
    ok(hr == S_OK && impersonating == 3, "Impersonating state returned %#lx, %d.\n", hr, impersonating);
    hr = ISpecialSystemProperties_SetSessionId(properties, 41, 9, FALSE);
    ok(hr == S_OK, "Console setter returned %#lx.\n", hr);
    hr = ISpecialSystemProperties_GetSessionId2(properties, &session, &console, &remote);
    ok(hr == S_OK && !session && console == TRUE && !remote,
       "Console state returned %#lx, %lu, %d, %d.\n", hr, session, console, remote);

    hr = CoCreateInstance(&activator_clsid, NULL, CLSCTX_INPROC_SERVER, &IID_IStandardActivator, (void **)&second);
    ok(hr == S_OK, "Second activator creation returned %#lx.\n", hr);
    if (SUCCEEDED(hr))
    {
        hr = IStandardActivator_QueryInterface(second, &IID_ISpecialSystemProperties, (void **)&second_properties);
        ok(hr == S_OK, "Second properties query returned %#lx.\n", hr);
        if (SUCCEEDED(hr))
        {
            hr = ISpecialSystemProperties_GetSessionId(second_properties, &session, &console);
            ok(hr == E_INVALIDARG, "Session state leaked between activators, %#lx.\n", hr);
            ISpecialSystemProperties_Release(second_properties);
        }
        IStandardActivator_Release(second);
    }
    hr = IStandardActivator_Reset(activator);
    ok(hr == S_OK, "Reset returned %#lx.\n", hr);
    hr = ISpecialSystemProperties_GetSessionId(properties, &session, &console);
    ok(hr == E_INVALIDARG, "Reset did not clear session state, %#lx.\n", hr);

    hr = CoRegisterClassObject(&test_clsid, (IUnknown *)&test_factory, CLSCTX_INPROC_SERVER,
                             REGCLS_MULTIPLEUSE, &cookie);
    ok(hr == S_OK, "Controlled class registration returned %#lx.\n", hr);
    if (SUCCEEDED(hr))
    {
        hr = IStandardActivator_StandardGetClassObject(activator, &test_clsid, CLSCTX_INPROC_SERVER,
                                                     NULL, &IID_IClassFactory, (void **)&factory);
        ok(hr == S_OK && factory == &test_factory, "Delegation returned %#lx, %p.\n", hr, factory);
        if (SUCCEEDED(hr)) IClassFactory_Release(factory);
        memset(results, 0, sizeof(results));
        results[0].pIID = &IID_IUnknown;
        results[1].pIID = &IID_IClassFactory;
        calls = create_calls;
        hr = IStandardActivator_StandardCreateInstance(activator, &test_clsid, NULL, CLSCTX_INPROC_SERVER,
                                                       NULL, 2, results);
        ok(hr == S_OK && create_calls == calls + 1, "Instance delegation returned %#lx, calls %ld.\n", hr, create_calls);
        ok(results[0].hr == S_OK && results[1].hr == S_OK && results[0].pItf == results[1].pItf,
           "Multi-interface result differs, %#lx, %#lx.\n", results[0].hr, results[1].hr);
        if (results[0].pItf) IUnknown_Release(results[0].pItf);
        if (results[1].pItf) IUnknown_Release(results[1].pItf);

        ok(ProcessIdToSessionId(GetCurrentProcessId(), &current), "Cannot query current session.\n");
        hr = ISpecialSystemProperties_SetSessionId(properties, current, FALSE, TRUE);
        ok(hr == S_OK, "Current-session setter returned %#lx.\n", hr);
        hr = IStandardActivator_StandardGetClassObject(activator, &test_clsid, CLSCTX_INPROC_SERVER,
                                                     NULL, &IID_IClassFactory, (void **)&factory);
        ok(hr == S_OK && factory == &test_factory, "Current-session delegation returned %#lx.\n", hr);
        if (SUCCEEDED(hr)) IClassFactory_Release(factory);
        if (!strcmp(winetest_platform, "wine"))
        {
            factory = (void *)0xdeadbeef;
            hr = IStandardActivator_StandardGetClassObject(activator, &test_clsid, CLSCTX_LOCAL_SERVER,
                                                         NULL, &IID_IClassFactory, (void **)&factory);
            ok(hr == E_NOTIMPL && !factory, "Explicit session used unscoped registry, %#lx, %p.\n", hr, factory);
            hr = ISpecialSystemProperties_SetSessionId(properties, current + 1, FALSE, TRUE);
            ok(hr == S_OK, "Foreign-session setter returned %#lx.\n", hr);
            factory = (void *)0xdeadbeef;
            hr = IStandardActivator_StandardGetClassObject(activator, &test_clsid, CLSCTX_INPROC_SERVER,
                                                         NULL, &IID_IClassFactory, (void **)&factory);
            ok(hr == E_NOTIMPL && !factory, "Foreign session silently routed locally, %#lx, %p.\n", hr, factory);
            hr = ISpecialSystemProperties_SetLUARunLevel(properties, 1, (ULONG_PTR)0x123456789abcdef0ULL);
            ok(hr == E_NOTIMPL, "Unimplemented LUA policy returned %#lx.\n", hr);
        }
        CoRevokeClassObject(cookie);
    }

    /* A retained properties reference owns the instance after the original
     * interface is released, and can recover its controlling identity. */
    IStandardActivator_Release(activator);
    hr = ISpecialSystemProperties_QueryInterface(properties, &IID_IStandardActivator, (void **)&activator);
    ok(hr == S_OK, "Retained properties lost the activator, %#lx.\n", hr);
    if (SUCCEEDED(hr))
    {
        hr = IStandardActivator_Reset(activator);
        ok(hr == S_OK, "Retained activator reset returned %#lx.\n", hr);
        IStandardActivator_Release(activator);
    }
    hr = ISpecialSystemProperties_QueryInterface(properties, &test_clsid, (void **)&object);
    ok(hr == E_NOINTERFACE && !object, "Unknown interface returned %#lx, %p.\n", hr, object);
    ISpecialSystemProperties_Release(properties);
}

START_TEST(stdactivator)
{
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);

    ok(hr == S_OK, "COM initialization returned %#lx.\n", hr);
    if (FAILED(hr)) return;
    test_activator();
    CoUninitialize();
}
