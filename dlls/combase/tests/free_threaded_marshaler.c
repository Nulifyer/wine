/* Free-threaded marshaler class ownership tests.
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

struct test_object
{
    IUnknown IUnknown_iface;
    LONG refcount;
    IUnknown *marshaler;
};

static inline struct test_object *impl_from_IUnknown(IUnknown *iface)
{
    return CONTAINING_RECORD(iface, struct test_object, IUnknown_iface);
}

static HRESULT WINAPI test_object_QueryInterface(IUnknown *iface, REFIID riid, void **obj)
{
    struct test_object *object = impl_from_IUnknown(iface);

    if (IsEqualIID(riid, &IID_IUnknown))
    {
        *obj = iface;
        IUnknown_AddRef(iface);
        return S_OK;
    }
    if (IsEqualIID(riid, &IID_IMarshal))
        return IUnknown_QueryInterface(object->marshaler, riid, obj);

    *obj = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI test_object_AddRef(IUnknown *iface)
{
    struct test_object *object = impl_from_IUnknown(iface);
    return InterlockedIncrement(&object->refcount);
}

static ULONG WINAPI test_object_Release(IUnknown *iface)
{
    struct test_object *object = impl_from_IUnknown(iface);
    return InterlockedDecrement(&object->refcount);
}

static const IUnknownVtbl test_object_vtbl =
{
    test_object_QueryInterface,
    test_object_AddRef,
    test_object_Release,
};

static void test_direct_class_object(void)
{
    dll_get_class_object_fn get_class_object;
    IClassFactory *factory = NULL;
    HMODULE module;
    IUnknown *unknown = (IUnknown *)0xdeadbeef;
    HRESULT hr;

    module = GetModuleHandleW(L"combase.dll");
    ok(!!module, "combase.dll is not loaded.\n");
    if (!module) return;

    get_class_object = (void *)GetProcAddress(module, "DllGetClassObject");
    ok(!!get_class_object, "combase.dll has no DllGetClassObject export.\n");
    if (!get_class_object) return;

    hr = get_class_object(&CLSID_InProcFreeMarshaler, &IID_IClassFactory, (void **)&factory);
    ok(hr == S_OK, "IClassFactory query returned %#lx.\n", hr);
    ok(!!factory, "IClassFactory query returned NULL.\n");
    if (factory) ok(!IClassFactory_Release(factory), "factory still has references.\n");

    hr = get_class_object(&CLSID_InProcFreeMarshaler, &IID_IMarshal, (void **)&unknown);
    ok(hr == E_NOINTERFACE, "IMarshal class-object query returned %#lx.\n", hr);
    ok(!unknown, "IMarshal class-object query returned %p.\n", unknown);
}

static void test_custom_unmarshal(void)
{
    static const LARGE_INTEGER zero;
    struct test_object object = {{&test_object_vtbl}, 1, NULL};
    IMarshal *marshal = NULL;
    IUnknown *unmarshaled = NULL;
    IStream *stream = NULL;
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(hr == S_OK, "CoInitializeEx returned %#lx.\n", hr);
    if (FAILED(hr)) return;

    hr = CoCreateInstance(&CLSID_InProcFreeMarshaler, NULL, CLSCTX_INPROC_SERVER,
            &IID_IMarshal, (void **)&marshal);
    ok(hr == S_OK, "CoCreateInstance returned %#lx.\n", hr);
    ok(!!marshal, "CoCreateInstance returned NULL.\n");
    if (marshal) IMarshal_Release(marshal);

    hr = CoCreateFreeThreadedMarshaler(&object.IUnknown_iface, &object.marshaler);
    ok(hr == S_OK, "CoCreateFreeThreadedMarshaler returned %#lx.\n", hr);

    hr = CreateStreamOnHGlobal(NULL, TRUE, &stream);
    ok(hr == S_OK, "CreateStreamOnHGlobal returned %#lx.\n", hr);
    if (SUCCEEDED(hr) && object.marshaler)
    {
        hr = CoMarshalInterface(stream, &IID_IUnknown, &object.IUnknown_iface,
                MSHCTX_INPROC, NULL, MSHLFLAGS_NORMAL);
        ok(hr == S_OK, "CoMarshalInterface returned %#lx.\n", hr);

        if (SUCCEEDED(hr))
        {
            hr = IStream_Seek(stream, zero, STREAM_SEEK_SET, NULL);
            ok(hr == S_OK, "IStream_Seek returned %#lx.\n", hr);
            hr = CoUnmarshalInterface(stream, &IID_IUnknown, (void **)&unmarshaled);
            ok(hr == S_OK, "CoUnmarshalInterface returned %#lx.\n", hr);
            ok(unmarshaled == &object.IUnknown_iface, "got object %p, expected %p.\n",
                    unmarshaled, &object.IUnknown_iface);
            if (unmarshaled) IUnknown_Release(unmarshaled);
        }
    }

    if (stream) IStream_Release(stream);
    if (object.marshaler) IUnknown_Release(object.marshaler);
    ok(object.refcount == 1, "object refcount is %ld.\n", object.refcount);
    CoUninitialize();
}

START_TEST(free_threaded_marshaler)
{
    test_direct_class_object();
    test_custom_unmarshal();
}
