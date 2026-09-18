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
#include "activation.h"
#include "inspectable.h"
#include "roapi.h"
#include "winstring.h"

#include "wine/test.h"

typedef HRESULT (WINAPI *dll_get_class_object_fn)(REFCLSID, REFIID, void **);

static const CLSID psfactory_clsid =
    {0x00000320, 0, 0, {0xc0, 0, 0, 0, 0, 0, 0, 0x46}};
static const IID irundown_iid =
    {0x00000134, 0, 0, {0xc0, 0, 0, 0, 0, 0, 0, 0x46}};
static const IID unknown_iid =
    {0x9d512b93, 0x74ee, 0x4cb2, {0xa0, 0x42, 0x91, 0x7e, 0x50, 0x67, 0x65, 0xd1}};

struct inspectable_object
{
    IInspectable IInspectable_iface;
    LONG refcount;
};

static inline struct inspectable_object *impl_from_IInspectable(IInspectable *iface)
{
    return CONTAINING_RECORD(iface, struct inspectable_object, IInspectable_iface);
}

static HRESULT WINAPI inspectable_QueryInterface(IInspectable *iface, REFIID iid, void **out)
{
    if (IsEqualIID(iid, &IID_IUnknown) || IsEqualIID(iid, &IID_IInspectable))
    {
        *out = iface;
        IInspectable_AddRef(iface);
        return S_OK;
    }

    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI inspectable_AddRef(IInspectable *iface)
{
    struct inspectable_object *impl = impl_from_IInspectable(iface);
    return InterlockedIncrement(&impl->refcount);
}

static ULONG WINAPI inspectable_Release(IInspectable *iface)
{
    struct inspectable_object *impl = impl_from_IInspectable(iface);
    return InterlockedDecrement(&impl->refcount);
}

static HRESULT WINAPI inspectable_GetIids(IInspectable *iface, ULONG *count, IID **iids)
{
    if (!count || !iids) return E_POINTER;
    if (!(*iids = CoTaskMemAlloc(sizeof(**iids)))) return E_OUTOFMEMORY;
    **iids = IID_IInspectable;
    *count = 1;
    return S_OK;
}

static HRESULT WINAPI inspectable_GetRuntimeClassName(IInspectable *iface, HSTRING *name)
{
    static const WCHAR class_name[] = L"Wine.Test.Inspectable";
    return WindowsCreateString(class_name, ARRAY_SIZE(class_name) - 1, name);
}

static HRESULT WINAPI inspectable_GetTrustLevel(IInspectable *iface, TrustLevel *level)
{
    if (!level) return E_POINTER;
    *level = FullTrust;
    return S_OK;
}

static const IInspectableVtbl inspectable_vtbl =
{
    inspectable_QueryInterface,
    inspectable_AddRef,
    inspectable_Release,
    inspectable_GetIids,
    inspectable_GetRuntimeClassName,
    inspectable_GetTrustLevel,
};

static struct inspectable_object inspectable = {{&inspectable_vtbl}, 1};

struct activation_factory_object
{
    IActivationFactory IActivationFactory_iface;
    LONG refcount;
    LONG activate_count;
    HRESULT call_context_hr;
    HRESULT impersonate_hr;
    HRESULT revert_hr;
    BOOL impersonating_before;
    BOOL impersonating_during;
    BOOL impersonating_after;
    IServerSecurity *retained_security;
};

static inline struct activation_factory_object *impl_from_IActivationFactory(IActivationFactory *iface)
{
    return CONTAINING_RECORD(iface, struct activation_factory_object, IActivationFactory_iface);
}

static HRESULT WINAPI activation_factory_QueryInterface(IActivationFactory *iface, REFIID iid, void **out)
{
    if (IsEqualIID(iid, &IID_IUnknown) || IsEqualIID(iid, &IID_IInspectable) ||
            IsEqualIID(iid, &IID_IActivationFactory))
    {
        *out = iface;
        IActivationFactory_AddRef(iface);
        return S_OK;
    }

    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI activation_factory_AddRef(IActivationFactory *iface)
{
    struct activation_factory_object *impl = impl_from_IActivationFactory(iface);
    return InterlockedIncrement(&impl->refcount);
}

static ULONG WINAPI activation_factory_Release(IActivationFactory *iface)
{
    struct activation_factory_object *impl = impl_from_IActivationFactory(iface);
    return InterlockedDecrement(&impl->refcount);
}

static HRESULT WINAPI activation_factory_GetIids(IActivationFactory *iface, ULONG *count, IID **iids)
{
    if (!count || !iids) return E_POINTER;
    if (!(*iids = CoTaskMemAlloc(sizeof(**iids)))) return E_OUTOFMEMORY;
    **iids = IID_IActivationFactory;
    *count = 1;
    return S_OK;
}

static HRESULT WINAPI activation_factory_GetRuntimeClassName(IActivationFactory *iface, HSTRING *name)
{
    static const WCHAR class_name[] = L"Wine.Test.ActivationFactory";
    return WindowsCreateString(class_name, ARRAY_SIZE(class_name) - 1, name);
}

static HRESULT WINAPI activation_factory_GetTrustLevel(IActivationFactory *iface, TrustLevel *level)
{
    if (!level) return E_POINTER;
    *level = FullTrust;
    return S_OK;
}

static HRESULT WINAPI activation_factory_ActivateInstance(IActivationFactory *iface, IInspectable **instance)
{
    struct activation_factory_object *impl = impl_from_IActivationFactory(iface);
    IServerSecurity *security = NULL;

    if (!instance) return E_POINTER;
    InterlockedIncrement(&impl->activate_count);
    impl->call_context_hr = CoGetCallContext(&IID_IServerSecurity, (void **)&security);
    if (SUCCEEDED(impl->call_context_hr))
    {
        impl->impersonating_before = IServerSecurity_IsImpersonating(security);
        impl->impersonate_hr = CoImpersonateClient();
        impl->impersonating_during = IServerSecurity_IsImpersonating(security);
        impl->revert_hr = CoRevertToSelf();
        impl->impersonating_after = IServerSecurity_IsImpersonating(security);
        impl->retained_security = security;
    }
    IInspectable_AddRef((*instance = &inspectable.IInspectable_iface));
    return S_OK;
}

static const IActivationFactoryVtbl activation_factory_vtbl =
{
    activation_factory_QueryInterface,
    activation_factory_AddRef,
    activation_factory_Release,
    activation_factory_GetIids,
    activation_factory_GetRuntimeClassName,
    activation_factory_GetTrustLevel,
    activation_factory_ActivateInstance,
};

static struct activation_factory_object activation_factory = {{&activation_factory_vtbl}, 1, 0};

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

struct inspectable_thread_args
{
    IStream *stream;
    HRESULT unmarshal_hr;
    HRESULT get_iids_hr;
    HRESULT get_name_hr;
    HRESULT get_trust_hr;
    ULONG iid_count;
    IID iid;
    WCHAR class_name[64];
    TrustLevel trust_level;
};

struct activation_factory_thread_args
{
    IStream *stream;
    HRESULT unmarshal_hr;
    HRESULT get_iids_hr;
    HRESULT get_name_hr;
    HRESULT get_trust_hr;
    HRESULT activate_hr;
    ULONG iid_count;
    IID iid;
    WCHAR class_name[64];
    TrustLevel trust_level;
};

static DWORD WINAPI inspectable_client_thread(void *param)
{
    struct inspectable_thread_args *args = param;
    IInspectable *proxy = NULL;
    const WCHAR *name;
    HSTRING class_name = NULL;
    IID *iids = NULL;
    UINT32 length;
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ok(hr == S_OK, "CoInitializeEx returned %#lx.\n", hr);
    if (FAILED(hr)) return 0;

    args->unmarshal_hr = CoGetInterfaceAndReleaseStream(args->stream, &IID_IInspectable,
            (void **)&proxy);
    args->stream = NULL;
    if (SUCCEEDED(args->unmarshal_hr))
    {
        args->get_iids_hr = IInspectable_GetIids(proxy, &args->iid_count, &iids);
        if (SUCCEEDED(args->get_iids_hr) && args->iid_count) args->iid = iids[0];
        CoTaskMemFree(iids);

        args->get_name_hr = IInspectable_GetRuntimeClassName(proxy, &class_name);
        if (SUCCEEDED(args->get_name_hr))
        {
            name = WindowsGetStringRawBuffer(class_name, &length);
            lstrcpynW(args->class_name, name, ARRAY_SIZE(args->class_name));
            WindowsDeleteString(class_name);
        }

        args->get_trust_hr = IInspectable_GetTrustLevel(proxy, &args->trust_level);
        IInspectable_Release(proxy);
    }

    CoUninitialize();
    return 0;
}

static DWORD WINAPI activation_factory_client_thread(void *param)
{
    struct activation_factory_thread_args *args = param;
    IActivationFactory *proxy = NULL;
    IInspectable *instance = NULL;
    const WCHAR *name;
    HSTRING class_name = NULL;
    IID *iids = NULL;
    UINT32 length;
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ok(hr == S_OK, "CoInitializeEx returned %#lx.\n", hr);
    if (FAILED(hr)) return 0;

    args->unmarshal_hr = CoGetInterfaceAndReleaseStream(args->stream, &IID_IActivationFactory,
            (void **)&proxy);
    args->stream = NULL;
    if (SUCCEEDED(args->unmarshal_hr))
    {
        args->get_iids_hr = IActivationFactory_GetIids(proxy, &args->iid_count, &iids);
        if (SUCCEEDED(args->get_iids_hr) && args->iid_count) args->iid = iids[0];
        CoTaskMemFree(iids);

        args->get_name_hr = IActivationFactory_GetRuntimeClassName(proxy, &class_name);
        if (SUCCEEDED(args->get_name_hr))
        {
            name = WindowsGetStringRawBuffer(class_name, &length);
            lstrcpynW(args->class_name, name, ARRAY_SIZE(args->class_name));
            WindowsDeleteString(class_name);
        }

        args->get_trust_hr = IActivationFactory_GetTrustLevel(proxy, &args->trust_level);
        args->activate_hr = IActivationFactory_ActivateInstance(proxy, &instance);
        if (instance) IInspectable_Release(instance);
        IActivationFactory_Release(proxy);
    }

    CoUninitialize();
    return 0;
}

static void test_inspectable_proxy(void)
{
    static const WCHAR expected_name[] = L"Wine.Test.Inspectable";
    struct inspectable_thread_args args = {0};
    IPSFactoryBuffer *factory = NULL;
    IRpcStubBuffer *stub = NULL;
    IRpcProxyBuffer *proxy = NULL;
    IInspectable *proxy_iface = NULL;
    IStream *stream = NULL;
    HANDLE thread;
    CLSID clsid;
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(hr == S_OK, "CoInitializeEx returned %#lx.\n", hr);
    if (FAILED(hr)) return;

    hr = CoGetPSClsid(&IID_IInspectable, &clsid);
    ok(hr == S_OK, "CoGetPSClsid(IInspectable) returned %#lx.\n", hr);
    ok(IsEqualCLSID(&clsid, &psfactory_clsid), "got proxy CLSID %s.\n", wine_dbgstr_guid(&clsid));

    hr = CoGetClassObject(&psfactory_clsid, CLSCTX_INPROC_SERVER | CLSCTX_PS_DLL, NULL,
            &IID_IPSFactoryBuffer, (void **)&factory);
    ok(hr == S_OK, "CoGetClassObject returned %#lx.\n", hr);
    if (SUCCEEDED(hr))
    {
        hr = IPSFactoryBuffer_CreateStub(factory, &IID_IInspectable,
                (IUnknown *)&inspectable.IInspectable_iface, &stub);
        ok(hr == S_OK, "CreateStub(IInspectable) returned %#lx.\n", hr);
        ok(!!stub, "CreateStub returned a NULL stub.\n");
        if (stub) IRpcStubBuffer_Release(stub);

        hr = IPSFactoryBuffer_CreateProxy(factory, NULL, &IID_IInspectable, &proxy,
                (void **)&proxy_iface);
        ok(hr == S_OK, "CreateProxy(IInspectable) returned %#lx.\n", hr);
        ok(!!proxy, "CreateProxy returned a NULL proxy.\n");
        ok(!!proxy_iface, "CreateProxy returned a NULL interface.\n");
        if (proxy_iface) IInspectable_Release(proxy_iface);
        if (proxy) IRpcProxyBuffer_Release(proxy);
        IPSFactoryBuffer_Release(factory);
    }

    hr = CoMarshalInterThreadInterfaceInStream(&IID_IInspectable,
            (IUnknown *)&inspectable.IInspectable_iface, &stream);
    ok(hr == S_OK, "CoMarshalInterThreadInterfaceInStream returned %#lx.\n", hr);
    if (SUCCEEDED(hr))
    {
        args.stream = stream;
        thread = CreateThread(NULL, 0, inspectable_client_thread, &args, 0, NULL);
        ok(!!thread, "CreateThread failed, error %lu.\n", GetLastError());
        if (thread)
        {
            ok(WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0, "client thread timed out.\n");
            CloseHandle(thread);
        }
        else IStream_Release(stream);

        ok(args.unmarshal_hr == S_OK, "CoGetInterfaceAndReleaseStream returned %#lx.\n", args.unmarshal_hr);
        ok(args.get_iids_hr == S_OK, "GetIids returned %#lx.\n", args.get_iids_hr);
        ok(args.iid_count == 1, "GetIids returned %lu IIDs.\n", args.iid_count);
        ok(IsEqualIID(&args.iid, &IID_IInspectable), "GetIids returned %s.\n", wine_dbgstr_guid(&args.iid));
        ok(args.get_name_hr == S_OK, "GetRuntimeClassName returned %#lx.\n", args.get_name_hr);
        ok(!lstrcmpW(args.class_name, expected_name), "got class name %s.\n", wine_dbgstr_w(args.class_name));
        ok(args.get_trust_hr == S_OK, "GetTrustLevel returned %#lx.\n", args.get_trust_hr);
        ok(args.trust_level == FullTrust, "got trust level %u.\n", args.trust_level);
    }

    CoUninitialize();
}

static void test_activation_factory_proxy(void)
{
    static const WCHAR expected_name[] = L"Wine.Test.ActivationFactory";
    struct activation_factory_thread_args args = {0};
    IPSFactoryBuffer *factory = NULL;
    IRpcStubBuffer *stub = NULL;
    IRpcProxyBuffer *proxy = NULL;
    IActivationFactory *proxy_iface = NULL;
    IActivationFactory *resolved_factory = NULL;
    IAgileReference *agile_reference = NULL;
    IInspectable *instance = NULL;
    IStream *stream = NULL;
    HANDLE thread;
    CLSID clsid;
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(hr == S_OK, "CoInitializeEx returned %#lx.\n", hr);
    if (FAILED(hr)) return;

    hr = CoGetPSClsid(&IID_IActivationFactory, &clsid);
    ok(hr == S_OK, "CoGetPSClsid(IActivationFactory) returned %#lx.\n", hr);
    ok(IsEqualCLSID(&clsid, &psfactory_clsid), "got proxy CLSID %s.\n", wine_dbgstr_guid(&clsid));

    hr = CoGetClassObject(&psfactory_clsid, CLSCTX_INPROC_SERVER | CLSCTX_PS_DLL, NULL,
            &IID_IPSFactoryBuffer, (void **)&factory);
    ok(hr == S_OK, "CoGetClassObject returned %#lx.\n", hr);
    if (SUCCEEDED(hr))
    {
        hr = IPSFactoryBuffer_CreateStub(factory, &IID_IActivationFactory,
                (IUnknown *)&activation_factory.IActivationFactory_iface, &stub);
        ok(hr == S_OK, "CreateStub(IActivationFactory) returned %#lx.\n", hr);
        ok(!!stub, "CreateStub returned a NULL stub.\n");
        if (stub) IRpcStubBuffer_Release(stub);

        hr = IPSFactoryBuffer_CreateProxy(factory, NULL, &IID_IActivationFactory, &proxy,
                (void **)&proxy_iface);
        ok(hr == S_OK, "CreateProxy(IActivationFactory) returned %#lx.\n", hr);
        ok(!!proxy, "CreateProxy returned a NULL IRpcProxyBuffer.\n");
        ok(!!proxy_iface, "CreateProxy returned a NULL interface.\n");
        if (proxy_iface) IActivationFactory_Release(proxy_iface);
        if (proxy) IRpcProxyBuffer_Release(proxy);
        IPSFactoryBuffer_Release(factory);
    }

    hr = CoMarshalInterThreadInterfaceInStream(&IID_IActivationFactory,
            (IUnknown *)&activation_factory.IActivationFactory_iface, &stream);
    ok(hr == S_OK, "CoMarshalInterThreadInterfaceInStream returned %#lx.\n", hr);
    if (SUCCEEDED(hr))
    {
        args.stream = stream;
        thread = CreateThread(NULL, 0, activation_factory_client_thread, &args, 0, NULL);
        ok(!!thread, "CreateThread failed, error %lu.\n", GetLastError());
        if (thread)
        {
            ok(WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0, "client thread timed out.\n");
            CloseHandle(thread);
        }
        else IStream_Release(stream);

        ok(args.unmarshal_hr == S_OK, "CoGetInterfaceAndReleaseStream returned %#lx.\n", args.unmarshal_hr);
        ok(args.get_iids_hr == S_OK, "GetIids returned %#lx.\n", args.get_iids_hr);
        ok(args.iid_count == 1, "GetIids returned %lu IIDs.\n", args.iid_count);
        ok(IsEqualIID(&args.iid, &IID_IActivationFactory), "GetIids returned %s.\n", wine_dbgstr_guid(&args.iid));
        ok(args.get_name_hr == S_OK, "GetRuntimeClassName returned %#lx.\n", args.get_name_hr);
        ok(!lstrcmpW(args.class_name, expected_name), "got class name %s.\n", wine_dbgstr_w(args.class_name));
        ok(args.get_trust_hr == S_OK, "GetTrustLevel returned %#lx.\n", args.get_trust_hr);
        ok(args.trust_level == FullTrust, "got trust level %u.\n", args.trust_level);
        ok(args.activate_hr == S_OK, "ActivateInstance returned %#lx.\n", args.activate_hr);
        ok(activation_factory.activate_count == 1, "ActivateInstance was called %ld times.\n",
                activation_factory.activate_count);
        ok(activation_factory.call_context_hr == S_OK, "CoGetCallContext returned %#lx.\n",
                activation_factory.call_context_hr);
        ok(!activation_factory.impersonating_before, "call started impersonating.\n");
        ok(activation_factory.impersonate_hr == S_OK, "CoImpersonateClient returned %#lx.\n",
                activation_factory.impersonate_hr);
        ok(activation_factory.impersonating_during, "call was not impersonating.\n");
        ok(activation_factory.revert_hr == S_OK, "CoRevertToSelf returned %#lx.\n",
                activation_factory.revert_hr);
        ok(!activation_factory.impersonating_after, "call remained impersonating.\n");
        ok(!!activation_factory.retained_security, "missing retained call context.\n");
        if (activation_factory.retained_security)
        {
            ok(!IServerSecurity_IsImpersonating(activation_factory.retained_security),
                    "completed call remained impersonating.\n");
            hr = IServerSecurity_ImpersonateClient(activation_factory.retained_security);
            ok(hr == RPC_E_CALL_COMPLETE, "completed call impersonation returned %#lx.\n", hr);
            IServerSecurity_Release(activation_factory.retained_security);
            activation_factory.retained_security = NULL;
        }
    }

    hr = RoGetAgileReference(AGILEREFERENCE_DEFAULT, &IID_IActivationFactory,
            (IUnknown *)&activation_factory.IActivationFactory_iface, &agile_reference);
    ok(hr == S_OK, "RoGetAgileReference(IActivationFactory) returned %#lx.\n", hr);
    if (SUCCEEDED(hr))
    {
        hr = IAgileReference_Resolve(agile_reference, &IID_IActivationFactory,
                (void **)&resolved_factory);
        ok(hr == S_OK, "Resolve(IActivationFactory) returned %#lx.\n", hr);
        if (SUCCEEDED(hr))
        {
            hr = IActivationFactory_ActivateInstance(resolved_factory, &instance);
            ok(hr == S_OK, "resolved ActivateInstance returned %#lx.\n", hr);
            if (instance) IInspectable_Release(instance);
            IActivationFactory_Release(resolved_factory);
        }
        IAgileReference_Release(agile_reference);
    }
    ok(activation_factory.activate_count == 2, "ActivateInstance was called %ld times.\n",
            activation_factory.activate_count);

    CoUninitialize();
}

START_TEST(proxy_factory)
{
    test_direct_class_object();
    test_irundown_proxy();
    test_inspectable_proxy();
    test_activation_factory_proxy();
}
