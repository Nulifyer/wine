/* Standard client marshaler lifecycle tests.
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

struct test_object
{
    IUnknown IUnknown_iface;
    LONG references;
};

static HRESULT WINAPI object_QueryInterface(IUnknown *iface, REFIID iid, void **out)
{
    *out = NULL;
    if (!IsEqualIID(iid, &IID_IUnknown)) return E_NOINTERFACE;
    *out = iface;
    IUnknown_AddRef(iface);
    return S_OK;
}

static ULONG WINAPI object_AddRef(IUnknown *iface)
{
    struct test_object *object = CONTAINING_RECORD(iface, struct test_object, IUnknown_iface);
    return InterlockedIncrement(&object->references);
}

static ULONG WINAPI object_Release(IUnknown *iface)
{
    struct test_object *object = CONTAINING_RECORD(iface, struct test_object, IUnknown_iface);
    return InterlockedDecrement(&object->references);
}

static const IUnknownVtbl object_vtbl = {object_QueryInterface, object_AddRef, object_Release};
static const LARGE_INTEGER zero;

static void test_arguments(void)
{
    IMarshal *marshal = (IMarshal *)0xdeadbeef;
    HRESULT hr;

    hr = CoGetStandardMarshal(&IID_IUnknown, NULL, MSHCTX_LOCAL, NULL, MSHLFLAGS_NORMAL, NULL);
    ok(hr == E_INVALIDARG, "Missing output returned %#lx.\n", hr);
    hr = CoGetStandardMarshal(&IID_IUnknown, NULL, 6, NULL, MSHLFLAGS_NORMAL, &marshal);
    ok(hr == E_INVALIDARG, "Invalid context returned %#lx.\n", hr);
    ok(marshal == (IMarshal *)0xdeadbeef, "Invalid context changed output.\n");
    hr = CoGetStandardMarshal(&IID_IUnknown, NULL, MSHCTX_LOCAL, (void *)1, MSHLFLAGS_NORMAL, &marshal);
    ok(hr == E_INVALIDARG, "Reserved context data returned %#lx.\n", hr);
    ok(marshal == (IMarshal *)0xdeadbeef, "Invalid context data changed output.\n");
    hr = CoGetStandardMarshal(&IID_IUnknown, NULL, MSHCTX_LOCAL, NULL, 0x8000, &marshal);
    ok(hr == E_INVALIDARG, "Invalid flags returned %#lx.\n", hr);
    ok(marshal == (IMarshal *)0xdeadbeef, "Invalid flags changed output.\n");
    hr = CoGetStandardMarshal(&IID_IUnknown, NULL, MSHCTX_LOCAL, NULL, MSHLFLAGS_NORMAL, &marshal);
    ok(hr == CO_E_NOTINITIALIZED, "Before initialization returned %#lx.\n", hr);
    ok(!marshal, "Initialization failure did not clear output.\n");
    if (SUCCEEDED(hr) && marshal) IMarshal_Release(marshal);
}

static void test_roundtrip(DWORD context, DWORD flags)
{
    struct test_object object = {{&object_vtbl}, 1};
    IUnknown *identity, *result;
    IMarshal *marshal, *retained;
    IStream *stream;
    LONG references;
    HRESULT hr;
    unsigned int i, count = flags == MSHLFLAGS_NORMAL ? 1 : 2;

    winetest_push_context("context %lu flags %lu", context, flags);
    hr = CreateStreamOnHGlobal(NULL, TRUE, &stream);
    ok(hr == S_OK, "Create stream returned %#lx.\n", hr);
    if (FAILED(hr)) goto done;
    hr = CoMarshalInterface(stream, &IID_IUnknown, &object.IUnknown_iface, context, NULL, flags);
    ok(hr == S_OK, "Marshal object returned %#lx.\n", hr);
    if (FAILED(hr)) goto release_stream;
    references = object.references;
    marshal = NULL;
    hr = CoGetStandardMarshal(&IID_IUnknown, NULL, context, NULL, flags, &marshal);
    ok(hr == S_OK, "Create client marshaler returned %#lx.\n", hr);
    if (FAILED(hr))
    {
        IStream_Seek(stream, zero, STREAM_SEEK_SET, NULL);
        CoReleaseMarshalData(stream);
        goto release_stream;
    }
    ok(object.references == references, "Client creation changed target references.\n");
    hr = IMarshal_QueryInterface(marshal, &IID_IUnknown, (void **)&identity);
    ok(hr == S_OK, "Marshaler identity returned %#lx.\n", hr);
    if (SUCCEEDED(hr))
    {
        IMarshal_Release(marshal);
        hr = IUnknown_QueryInterface(identity, &IID_IMarshal, (void **)&retained);
        ok(hr == S_OK, "Retained client marshaler returned %#lx.\n", hr);
        IUnknown_Release(identity);
        if (FAILED(hr)) goto release_stream;
        marshal = retained;
    }
    for (i = 0; i < count; ++i)
    {
        hr = IStream_Seek(stream, zero, STREAM_SEEK_SET, NULL);
        ok(hr == S_OK, "Seek returned %#lx.\n", hr);
        result = NULL;
        hr = IMarshal_UnmarshalInterface(marshal, stream, &IID_IUnknown, (void **)&result);
        ok(hr == S_OK, "Client unmarshal %u returned %#lx.\n", i, hr);
        if (SUCCEEDED(hr))
        {
            ok(result == &object.IUnknown_iface, "Same-apartment identity changed.\n");
            IUnknown_Release(result);
        }
    }
    if (flags != MSHLFLAGS_NORMAL)
    {
        IStream_Seek(stream, zero, STREAM_SEEK_SET, NULL);
        hr = IMarshal_ReleaseMarshalData(marshal, stream);
        ok(hr == S_OK, "Client release data returned %#lx.\n", hr);
    }
    IMarshal_Release(marshal);
release_stream:
    IStream_Release(stream);
    ok(object.references == 1, "Target retained %ld references.\n", object.references);
done:
    winetest_pop_context();
}

static void test_release_without_unmarshal(void)
{
    struct test_object object = {{&object_vtbl}, 1};
    IMarshal *marshal;
    IStream *stream;
    HRESULT hr;

    hr = CreateStreamOnHGlobal(NULL, TRUE, &stream);
    ok(hr == S_OK, "Create stream returned %#lx.\n", hr);
    if (FAILED(hr)) return;
    hr = CoMarshalInterface(stream, &IID_IUnknown, &object.IUnknown_iface,
                           MSHCTX_LOCAL, NULL, MSHLFLAGS_NORMAL);
    ok(hr == S_OK, "Marshal object returned %#lx.\n", hr);
    if (FAILED(hr)) goto done;
    hr = CoGetStandardMarshal(&IID_IUnknown, NULL, MSHCTX_LOCAL, NULL, MSHLFLAGS_NORMAL, &marshal);
    ok(hr == S_OK, "Create release-only client returned %#lx.\n", hr);
    IStream_Seek(stream, zero, STREAM_SEEK_SET, NULL);
    if (SUCCEEDED(hr))
    {
        hr = IMarshal_ReleaseMarshalData(marshal, stream);
        ok(hr == S_OK, "Release without consuming returned %#lx.\n", hr);
        IMarshal_Release(marshal);
    }
    else CoReleaseMarshalData(stream);
done:
    IStream_Release(stream);
    ok(object.references == 1, "Release-only client retained %ld references.\n", object.references);
}

static void test_bad_stream(void)
{
    struct {DWORD signature, flags; IID iid;} header = {0, 1, {0}};
    IUnknown *result = NULL;
    IMarshal *marshal;
    IStream *stream;
    HRESULT hr;

    hr = CoGetStandardMarshal(&IID_IUnknown, NULL, MSHCTX_LOCAL, NULL, MSHLFLAGS_NORMAL, &marshal);
    ok(hr == S_OK, "Create malformed-stream client returned %#lx.\n", hr);
    if (FAILED(hr)) return;
    hr = CreateStreamOnHGlobal(NULL, TRUE, &stream);
    ok(hr == S_OK, "Create stream returned %#lx.\n", hr);
    if (SUCCEEDED(hr))
    {
        hr = IMarshal_UnmarshalInterface(marshal, stream, &IID_IUnknown, (void **)&result);
        ok(FAILED(hr), "Empty stream succeeded, %#lx.\n", hr);
        ok(!result, "Empty stream produced an object.\n");
        IStream_Seek(stream, zero, STREAM_SEEK_SET, NULL);
        IStream_Write(stream, &header, sizeof(header), NULL);
        IStream_Seek(stream, zero, STREAM_SEEK_SET, NULL);
        hr = IMarshal_UnmarshalInterface(marshal, stream, &IID_IUnknown, (void **)&result);
        ok(FAILED(hr), "Invalid signature succeeded, %#lx.\n", hr);
        ok(!result, "Invalid signature produced an object.\n");
        IStream_Release(stream);
    }
    IMarshal_Release(marshal);
}

START_TEST(standard_client_marshal)
{
    static const DWORD contexts[] = {MSHCTX_LOCAL, MSHCTX_INPROC};
    static const DWORD flags[] = {MSHLFLAGS_NORMAL, MSHLFLAGS_TABLESTRONG, MSHLFLAGS_TABLEWEAK};
    unsigned int i, j;
    HRESULT hr;

    test_arguments();
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ok(hr == S_OK, "Initialize COM returned %#lx.\n", hr);
    if (FAILED(hr)) return;
    for (i = 0; i < ARRAY_SIZE(contexts); ++i)
        for (j = 0; j < ARRAY_SIZE(flags); ++j) test_roundtrip(contexts[i], flags[j]);
    test_release_without_unmarshal();
    test_bad_stream();
    CoUninitialize();
}
