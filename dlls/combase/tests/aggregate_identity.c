/*
 * COM aggregate identity tests
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

typedef HRESULT (WINAPI *create_agg_id_fn)(REFCLSID, void **);
typedef HRESULT (WINAPI *set_agg_id_handler_fn)(void *, IUnknown *);
typedef ULONG (WINAPI *release_agg_id_fn)(void *);
typedef IInternalUnknown *(WINAPI *get_internal_unknown_fn)(IUnknown *);
typedef ULONG (WINAPI *update_identity_flags_fn)(IUnknown *, ULONG);
typedef IUnknown *(WINAPI *get_proxy_manager_fn)(IUnknown *);

static const GUID test_handler_iid =
    {0xf7518c88, 0xb43f, 0x4e8e, {0xad, 0x5a, 0xf0, 0x2c, 0xb2, 0x38, 0x03, 0x8a}};
static const GUID identity_unmarshal_iid =
    {0x0000001b, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static const GUID internal_unknown_iid =
    {0x00000021, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

struct test_handler
{
    IUnknown IUnknown_iface;
    LONG refs;
    LONG query_count;
};

static inline struct test_handler *impl_from_IUnknown(IUnknown *iface)
{
    return CONTAINING_RECORD(iface, struct test_handler, IUnknown_iface);
}

static HRESULT WINAPI test_handler_QueryInterface(IUnknown *iface, REFIID iid, void **out)
{
    struct test_handler *handler = impl_from_IUnknown(iface);

    InterlockedIncrement(&handler->query_count);
    if (IsEqualIID(iid, &IID_IUnknown) || IsEqualIID(iid, &test_handler_iid))
    {
        *out = iface;
        IUnknown_AddRef(iface);
        return S_OK;
    }
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI test_handler_AddRef(IUnknown *iface)
{
    struct test_handler *handler = impl_from_IUnknown(iface);
    return InterlockedIncrement(&handler->refs);
}

static ULONG WINAPI test_handler_Release(IUnknown *iface)
{
    struct test_handler *handler = impl_from_IUnknown(iface);
    return InterlockedDecrement(&handler->refs);
}

static const IUnknownVtbl test_handler_vtbl =
{
    test_handler_QueryInterface,
    test_handler_AddRef,
    test_handler_Release,
};

static void test_aggregate_identity(void)
{
    static const CLSID credential_framework =
        {0x7a872d34, 0xbc6b, 0x4f83, {0xb1, 0x99, 0x22, 0xe9, 0xc0, 0xa9, 0x1d, 0xdc}};
    struct test_handler first = {{&test_handler_vtbl}, 1, 0};
    struct test_handler second = {{&test_handler_vtbl}, 1, 0};
    HMODULE module = GetModuleHandleW(L"combase.dll");
    set_agg_id_handler_fn set_handler;
    release_agg_id_fn release;
    create_agg_id_fn create;
    get_internal_unknown_fn get_internal_unknown;
    update_identity_flags_fn update_identity_flags;
    get_proxy_manager_fn get_proxy_manager;
    IInternalUnknown *internal_unknown;
    IUnknown *unknown, *identity_unmarshal, *controlling_unknown;
    void *agg_id, *out;
    HRESULT hr;
    ULONG refs;

    ok(!!module, "combase.dll is not loaded.\n");
    if (!module) return;
    create = (void *)GetProcAddress(module, "InternalCreateCAggId");
    set_handler = (void *)GetProcAddress(module, "InternalCAggIdSetHandler");
    release = (void *)GetProcAddress(module, "InternalCAggIdRelease");
    get_internal_unknown = (void *)GetProcAddress(module, "InternalCStdIdentityGetInternalUnk");
    update_identity_flags = (void *)GetProcAddress(module, "InternalCStdIdentityUpdateFlags");
    get_proxy_manager = (void *)GetProcAddress(module, "InternalCStdIdentityGetIProxyManager");
    ok(!!create, "InternalCreateCAggId is unavailable.\n");
    ok(!!set_handler, "InternalCAggIdSetHandler is unavailable.\n");
    ok(!!release, "InternalCAggIdRelease is unavailable.\n");
    ok(!!get_internal_unknown, "InternalCStdIdentityGetInternalUnk is unavailable.\n");
    ok(!!update_identity_flags, "InternalCStdIdentityUpdateFlags is unavailable.\n");
    ok(!!get_proxy_manager, "InternalCStdIdentityGetIProxyManager is unavailable.\n");
    if (!create || !set_handler || !release) return;

    agg_id = (void *)0xdeadbeef;
    hr = create(&credential_framework, &agg_id);
    ok(hr == S_OK, "InternalCreateCAggId returned %#lx.\n", hr);
    ok(agg_id && agg_id != (void *)0xdeadbeef, "Got aggregate identity %p.\n", agg_id);
    if (FAILED(hr) || !agg_id || agg_id == (void *)0xdeadbeef) return;

    unknown = agg_id;
    out = (void *)0xdeadbeef;
    hr = IUnknown_QueryInterface(unknown, &IID_IUnknown, &out);
    ok(hr == S_OK, "IUnknown query returned %#lx.\n", hr);
    ok(out == agg_id, "IUnknown query returned %p, expected %p.\n", out, agg_id);
    if (SUCCEEDED(hr))
    {
        refs = IUnknown_Release((IUnknown *)out);
        ok(refs == 1, "IUnknown release returned %lu.\n", refs);
    }

    hr = set_handler(agg_id, &first.IUnknown_iface);
    ok(hr == S_OK, "First handler set returned %#lx.\n", hr);
    ok(first.refs == 2, "First handler has %ld references.\n", first.refs);
    hr = set_handler(agg_id, &second.IUnknown_iface);
    ok(hr == E_FAIL, "Second handler set returned %#lx.\n", hr);
    ok(second.refs == 1, "Second handler has %ld references.\n", second.refs);

    out = (void *)0xdeadbeef;
    hr = IUnknown_QueryInterface(unknown, &test_handler_iid, &out);
    ok(hr == S_OK, "Delegated query returned %#lx.\n", hr);
    ok(out == &first.IUnknown_iface, "Delegated query returned %p.\n", out);
    ok(first.query_count == 1, "First handler received %ld queries.\n", first.query_count);
    if (SUCCEEDED(hr)) IUnknown_Release((IUnknown *)out);

    identity_unmarshal = NULL;
    hr = IUnknown_QueryInterface(unknown, &identity_unmarshal_iid, (void **)&identity_unmarshal);
    ok(hr == S_OK, "Identity-unmarshal query returned %#lx.\n", hr);
    ok(!!identity_unmarshal, "Identity-unmarshal query returned %p.\n", identity_unmarshal);
    ok(identity_unmarshal != unknown, "Identity-unmarshal interface aliases aggregate %p.\n", unknown);
    ok(first.query_count == 1, "Identity-unmarshal query reached handler; count %ld.\n", first.query_count);
    if (SUCCEEDED(hr) && identity_unmarshal)
    {
        controlling_unknown = NULL;
        hr = IUnknown_QueryInterface(identity_unmarshal, &IID_IUnknown,
                (void **)&controlling_unknown);
        ok(hr == S_OK, "Identity-unmarshal IUnknown query returned %#lx.\n", hr);
        ok(!!controlling_unknown, "Identity-unmarshal IUnknown query returned %p.\n",
                controlling_unknown);
        trace("aggregate %p identity-unmarshal %p controlling unknown %p\n",
                unknown, identity_unmarshal, controlling_unknown);
        if (controlling_unknown) IUnknown_Release(controlling_unknown);

        if (get_internal_unknown)
        {
            internal_unknown = get_internal_unknown(identity_unmarshal);
            ok(!!internal_unknown, "Internal unknown is %p.\n", internal_unknown);
            ok((void *)internal_unknown != (void *)identity_unmarshal,
                    "Internal unknown aliases identity-unmarshal %p.\n", identity_unmarshal);
            ok(get_internal_unknown(identity_unmarshal) == internal_unknown,
                    "Internal unknown accessor is unstable.\n");
            out = (void *)0xdeadbeef;
            hr = IInternalUnknown_QueryInterface(internal_unknown, &IID_IUnknown, &out);
            ok(hr == S_OK, "Internal unknown IUnknown query returned %#lx.\n", hr);
            ok(out != unknown && out != identity_unmarshal,
                    "Internal unknown IUnknown aliases an outer identity %p.\n", out);
            ok(out == (BYTE *)internal_unknown + sizeof(void *),
                    "Internal unknown IUnknown is %p, expected %p.\n",
                    out, (BYTE *)internal_unknown + sizeof(void *));
            if (SUCCEEDED(hr)) IUnknown_Release((IUnknown *)out);

            out = (void *)0xdeadbeef;
            hr = IInternalUnknown_QueryInterface(internal_unknown, &internal_unknown_iid, &out);
            ok(hr == S_OK, "Internal unknown self query returned %#lx.\n", hr);
            ok(out == internal_unknown, "Internal unknown self query returned %p.\n", out);
            if (SUCCEEDED(hr)) IUnknown_Release((IUnknown *)out);

            out = (void *)0xdeadbeef;
            hr = IInternalUnknown_QueryInternalInterface(internal_unknown, &test_handler_iid, &out);
            ok(hr == E_NOINTERFACE, "Internal handler query returned %#lx.\n", hr);
            ok(!out, "Internal handler query returned %p.\n", out);
            ok(first.query_count == 1, "Internal handler query reached handler; count %ld.\n",
                    first.query_count);
            if (SUCCEEDED(hr)) IUnknown_Release((IUnknown *)out);
        }
        if (update_identity_flags)
        {
            ULONG initial_flags, updated_flags;

            initial_flags = update_identity_flags(identity_unmarshal, 0);
            updated_flags = update_identity_flags(identity_unmarshal, 0x40000000);
            ok(updated_flags == (initial_flags | 0x40000000),
                    "Updated identity flags %#lx, initial %#lx.\n", updated_flags, initial_flags);
            ok(update_identity_flags(identity_unmarshal, 0) == updated_flags,
                    "Identity flag update did not persist.\n");
        }
        if (get_proxy_manager)
            ok(get_proxy_manager(identity_unmarshal) == identity_unmarshal,
                    "Proxy manager does not preserve identity %p.\n", identity_unmarshal);
        IUnknown_Release(identity_unmarshal);
    }

    refs = release(agg_id);
    ok(!refs, "Final aggregate identity release returned %lu.\n", refs);
    ok(first.refs == 1, "First handler retained %ld references.\n", first.refs);
    ok(!IUnknown_Release(&first.IUnknown_iface), "First handler was not released.\n");
    ok(!IUnknown_Release(&second.IUnknown_iface), "Second handler was not released.\n");
}

START_TEST(aggregate_identity)
{
    test_aggregate_identity();
}
