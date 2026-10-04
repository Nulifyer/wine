/* ActiveX proxy catalog tests.
 *
 * Copyright 2026 Nulifyer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>

#define COBJMACROS
#include "windef.h"
#include "winbase.h"
#include "objbase.h"
#include "rpcproxy.h"

#include "wine/test.h"

typedef HRESULT (WINAPI *dll_get_class_object_fn)(REFCLSID, REFIID, void **);
typedef HRESULT (WINAPI *dll_register_server_fn)(void);

static const CLSID actxprxy_factory_clsid =
    {0xb8da6310, 0xe19b, 0x11d0, {0x93, 0x3c, 0x00, 0xa0, 0xc9, 0x0d, 0xca, 0xa9}};
static const IID settings_flow_controller_iid =
    {0x87324ffd, 0xbd0a, 0x4de8, {0x84, 0x0a, 0xb6, 0x0e, 0x34, 0x5a, 0x33, 0x6f}};

static HRESULT WINAPI marker_QueryInterface(IUnknown *iface, REFIID iid, void **out)
{
    if (IsEqualIID(iid, &IID_IUnknown) || IsEqualIID(iid, &settings_flow_controller_iid))
    {
        *out = iface;
        IUnknown_AddRef(iface);
        return S_OK;
    }

    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI marker_AddRef(IUnknown *iface)
{
    return 2;
}

static ULONG WINAPI marker_Release(IUnknown *iface)
{
    return 1;
}

static const IUnknownVtbl marker_vtbl =
{
    marker_QueryInterface,
    marker_AddRef,
    marker_Release,
};

static IUnknown marker = {&marker_vtbl};

static void test_settings_flow_controller(void)
{
    dll_get_class_object_fn get_class_object;
    dll_register_server_fn register_server;
    IRpcProxyBuffer *proxy = NULL;
    IRpcStubBuffer *stub = NULL;
    IPSFactoryBuffer *factory = NULL;
    IUnknown *object = NULL;
    HMODULE module;
    CLSID clsid;
    HRESULT hr;

    module = LoadLibraryW(L"actxprxy.dll");
    ok(!!module, "Failed to load actxprxy.dll, error %lu.\n", GetLastError());
    if (!module) return;

    get_class_object = (void *)GetProcAddress(module, "DllGetClassObject");
    register_server = (void *)GetProcAddress(module, "DllRegisterServer");
    ok(!!get_class_object, "DllGetClassObject is absent.\n");
    ok(!!register_server, "DllRegisterServer is absent.\n");
    if (!get_class_object || !register_server) goto done;

    hr = get_class_object(&actxprxy_factory_clsid, &IID_IPSFactoryBuffer, (void **)&factory);
    ok(hr == S_OK, "DllGetClassObject returned %#lx.\n", hr);
    ok(!!factory, "DllGetClassObject returned a NULL factory.\n");
    if (!factory) goto done;

    hr = IPSFactoryBuffer_CreateStub(factory, &settings_flow_controller_iid, &marker, &stub);
    ok(hr == S_OK, "CreateStub returned %#lx.\n", hr);
    ok(!!stub, "CreateStub returned a NULL stub.\n");

    hr = IPSFactoryBuffer_CreateProxy(factory, NULL, &settings_flow_controller_iid,
            &proxy, (void **)&object);
    ok(hr == S_OK, "CreateProxy returned %#lx.\n", hr);
    ok(!!proxy, "CreateProxy returned a NULL proxy buffer.\n");
    ok(!!object, "CreateProxy returned a NULL interface.\n");

    hr = register_server();
    ok(hr == S_OK, "DllRegisterServer returned %#lx.\n", hr);
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(hr == S_OK, "CoInitializeEx returned %#lx.\n", hr);
    if (SUCCEEDED(hr))
    {
        hr = CoGetPSClsid(&settings_flow_controller_iid, &clsid);
        ok(hr == S_OK, "CoGetPSClsid returned %#lx.\n", hr);
        ok(IsEqualCLSID(&clsid, &actxprxy_factory_clsid), "Unexpected factory %s.\n",
                wine_dbgstr_guid(&clsid));
        CoUninitialize();
    }

done:
    if (stub) IRpcStubBuffer_Release(stub);
    if (object) IUnknown_Release(object);
    if (proxy) IRpcProxyBuffer_Release(proxy);
    if (factory) IPSFactoryBuffer_Release(factory);
    FreeLibrary(module);
}

START_TEST(catalog)
{
    test_settings_flow_controller();
}
