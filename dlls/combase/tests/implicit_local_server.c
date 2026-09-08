/* Local class activation from an implicit MTA.
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */
#define COBJMACROS
#include <stdarg.h>
#include "windef.h"
#include "winbase.h"
#include "objbase.h"
#include "wine/test.h"

static GUID clsid;
static HRESULT WINAPI factory_query(IClassFactory *iface, REFIID iid, void **out)
{
    *out = NULL;
    if (!IsEqualGUID(iid, &IID_IUnknown) && !IsEqualGUID(iid, &IID_IClassFactory)) return E_NOINTERFACE;
    *out = iface;
    IClassFactory_AddRef(iface);
    return S_OK;
}
static ULONG WINAPI factory_addref(IClassFactory *iface) { return 2; }
static ULONG WINAPI factory_release(IClassFactory *iface) { return 1; }
static HRESULT WINAPI factory_create(IClassFactory *iface, IUnknown *outer, REFIID iid, void **out)
{
    *out = NULL;
    return E_NOTIMPL;
}
static HRESULT WINAPI factory_lock(IClassFactory *iface, BOOL lock) { return S_OK; }
static const IClassFactoryVtbl factory_vtbl =
{
    factory_query, factory_addref, factory_release, factory_create, factory_lock
};
static IClassFactory factory = {&factory_vtbl};

static DWORD WINAPI activate(void *param)
{
    DWORD context = *(DWORD *)param;
    IClassFactory *object = NULL;
    APTTYPE type = APTTYPE_CURRENT;
    APTTYPEQUALIFIER qualifier = APTTYPEQUALIFIER_NONE;
    HRESULT hr = CoGetApartmentType(&type, &qualifier);

    ok(hr == S_OK, "CoGetApartmentType returned %#lx.\n", hr);
    ok(type == APTTYPE_MTA, "Unexpected apartment %u.\n", type);
    ok(qualifier == APTTYPEQUALIFIER_IMPLICIT_MTA, "Unexpected qualifier %u.\n", qualifier);
    hr = CoGetClassObject(&clsid, context, NULL, &IID_IClassFactory, (void **)&object);
    trace("context %#lx returned %#lx, object %p.\n", context, hr, object);
    if (context & CLSCTX_APPCONTAINER)
    {
        /* Windows rejects this request. Wine currently permits it, but must
         * not crash while querying its local-server service provider. */
        todo_wine ok(hr == E_INVALIDARG, "Expected E_INVALIDARG, got %#lx.\n", hr);
        todo_wine ok(!object, "Expected no factory, got %p.\n", object);
    }
    else
    {
        ok(hr == S_OK, "CoGetClassObject returned %#lx.\n", hr);
        ok(!!object, "Missing factory.\n");
    }
    if (object) IClassFactory_Release(object);
    return 0;
}

START_TEST(implicit_local_server)
{
    DWORD cookie = 0, wait, context;
    HANDLE thread;
    HRESULT hr;
    unsigned int i;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(hr == S_OK, "CoInitializeEx returned %#lx.\n", hr);
    if (FAILED(hr)) return;
    hr = CoCreateGuid(&clsid);
    ok(hr == S_OK, "CoCreateGuid returned %#lx.\n", hr);
    hr = CoRegisterClassObject(&clsid, (IUnknown *)&factory, CLSCTX_LOCAL_SERVER,
            REGCLS_MULTIPLEUSE, &cookie);
    ok(hr == S_OK, "CoRegisterClassObject returned %#lx.\n", hr);
    if (SUCCEEDED(hr))
    {
        for (i = 0; i < 2; ++i)
        {
            context = CLSCTX_LOCAL_SERVER | (i ? CLSCTX_APPCONTAINER : 0);
            thread = CreateThread(NULL, 0, activate, &context, 0, NULL);
            ok(!!thread, "CreateThread failed: %lu.\n", GetLastError());
            if (!thread) break;
            wait = WaitForSingleObject(thread, 15000);
            ok(wait == WAIT_OBJECT_0, "Activation thread wait returned %#lx.\n", wait);
            CloseHandle(thread);
            if (wait != WAIT_OBJECT_0) ExitProcess(1);
        }
        hr = CoRevokeClassObject(cookie);
        ok(hr == S_OK, "CoRevokeClassObject returned %#lx.\n", hr);
    }
    CoUninitialize();
}
