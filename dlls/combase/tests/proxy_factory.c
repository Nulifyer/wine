/* Standard DCOM proxy/stub factory ownership tests.
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

#include "wine/test.h"

typedef HRESULT (WINAPI *dll_get_class_object_fn)(REFCLSID, REFIID, void **);

static const CLSID psfactory_clsid =
    {0x00000320, 0, 0, {0xc0, 0, 0, 0, 0, 0, 0, 0x46}};
static const IID irundown_iid =
    {0x00000134, 0, 0, {0xc0, 0, 0, 0, 0, 0, 0, 0x46}};
static const IID unknown_iid =
    {0x9d512b93, 0x74ee, 0x4cb2, {0xa0, 0x42, 0x91, 0x7e, 0x50, 0x67, 0x65, 0xd1}};

static IPSFactoryBuffer *get_proxy_factory(dll_get_class_object_fn get_class_object)
{
    IPSFactoryBuffer *factory = NULL;
    HRESULT hr;

    hr = get_class_object(&psfactory_clsid, &IID_IPSFactoryBuffer, (void **)&factory);
    ok(hr == S_OK, "DllGetClassObject returned %#lx.\n", hr);
    ok(!!factory, "DllGetClassObject returned a NULL proxy factory.\n");
    return factory;
}

static void test_direct_class_object(void)
{
    dll_get_class_object_fn get_class_object;
    IClassFactory *class_factory = NULL;
    IPSFactoryBuffer *proxy_factory;
    IUnknown *unknown = NULL;
    HMODULE module;
    HRESULT hr;
    void *obj;

    module = GetModuleHandleW(L"combase.dll");
    ok(!!module, "combase.dll is not loaded.\n");
    if (!module) return;
    get_class_object = (void *)GetProcAddress(module, "DllGetClassObject");
    ok(!!get_class_object, "combase.dll has no DllGetClassObject export.\n");
    if (!get_class_object) return;

    hr = get_class_object(&psfactory_clsid, &IID_IUnknown, (void **)&unknown);
    ok(hr == S_OK, "IUnknown query returned %#lx.\n", hr);
    ok(!!unknown, "IUnknown query returned NULL.\n");
    if (unknown) IUnknown_Release(unknown);

    hr = get_class_object(&psfactory_clsid, &IID_IClassFactory, (void **)&class_factory);
    ok(hr == S_OK, "IClassFactory query returned %#lx.\n", hr);
    ok(!!class_factory, "IClassFactory query returned NULL.\n");
    if (class_factory) IClassFactory_Release(class_factory);

    proxy_factory = get_proxy_factory(get_class_object);
    if (proxy_factory) IPSFactoryBuffer_Release(proxy_factory);

    obj = (void *)0xdeadbeef;
    hr = get_class_object(&psfactory_clsid, &unknown_iid, &obj);
    ok(hr == E_NOINTERFACE, "unknown interface query returned %#lx.\n", hr);
    ok(!obj, "unknown interface query returned %p.\n", obj);
}

static void test_irundown_proxy(void)
{
    IPSFactoryBuffer *factory = NULL;
    IRpcProxyBuffer *proxy = NULL;
    void *iface = NULL;
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(hr == S_OK, "CoInitializeEx returned %#lx.\n", hr);
    if (FAILED(hr)) return;

    hr = CoGetClassObject(&psfactory_clsid, CLSCTX_INPROC_SERVER | CLSCTX_PS_DLL,
            NULL, &IID_IPSFactoryBuffer, (void **)&factory);
    ok(hr == S_OK, "CoGetClassObject returned %#lx.\n", hr);
    ok(!!factory, "CoGetClassObject returned a NULL proxy factory.\n");

    if (factory)
    {
        hr = IPSFactoryBuffer_CreateProxy(factory, NULL, &irundown_iid, &proxy, &iface);
        ok(hr == S_OK, "CreateProxy(IID_IRundown) returned %#lx.\n", hr);
        ok(!!proxy, "CreateProxy returned a NULL IRpcProxyBuffer.\n");
        ok(!!iface, "CreateProxy returned a NULL interface.\n");
    }

    if (iface) IUnknown_Release((IUnknown *)iface);
    if (proxy) IRpcProxyBuffer_Release(proxy);
    if (factory) IPSFactoryBuffer_Release(factory);
    CoUninitialize();
}

START_TEST(proxy_factory)
{
    test_direct_class_object();
    test_irundown_proxy();
}
