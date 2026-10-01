/*
 * Copyright 2026
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#define COBJMACROS
#include "objbase.h"

#include "wine/test.h"

typedef HRESULT (WINAPI *co_impersonate_client_of_object_fn)(IUnknown *, BOOL *);
typedef HRESULT (WINAPI *co_get_call_context_of_object_fn)(IUnknown *, REFIID, void **);
typedef HRESULT (WINAPI *co_get_call_locality_fn)(IUnknown *, INT *);

static HRESULT WINAPI unknown_QueryInterface(IUnknown *iface, REFIID iid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualIID(iid, &IID_IUnknown))
    {
        *out = iface;
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG WINAPI unknown_AddRef(IUnknown *iface)
{
    return 2;
}

static ULONG WINAPI unknown_Release(IUnknown *iface)
{
    return 1;
}

static const IUnknownVtbl unknown_vtbl =
{
    unknown_QueryInterface,
    unknown_AddRef,
    unknown_Release,
};

static void test_CoImpersonateClientOfObject(void)
{
    co_impersonate_client_of_object_fn co_impersonate;
    IUnknown object = {&unknown_vtbl};
    HMODULE module;
    HRESULT hr;
    BOOL found;

    module = GetModuleHandleW(L"combase.dll");
    co_impersonate = (co_impersonate_client_of_object_fn)GetProcAddress(module, (const char *)168);
    ok(!!co_impersonate, "CoImpersonateClientOfObject is not exported.\n");
    if (!co_impersonate) return;

    found = 0x55;
    hr = co_impersonate(&object, &found);
    ok(hr == S_OK, "Got hr %#lx.\n", hr);
    ok(!found, "Expected no matching incoming call, got %d.\n", found);

    found = 0x55;
    hr = co_impersonate(NULL, &found);
    ok(hr == S_OK, "Got hr %#lx.\n", hr);
    ok(!found, "Expected no matching incoming call, got %d.\n", found);
}

static void test_object_call_context(void)
{
    co_get_call_context_of_object_fn get_context;
    co_get_call_locality_fn get_locality;
    IUnknown object = {&unknown_vtbl};
    IUnknown *context;
    HMODULE module;
    HRESULT hr;
    INT locality;

    module = GetModuleHandleW(L"combase.dll");
    get_context = (co_get_call_context_of_object_fn)GetProcAddress(module, (const char *)167);
    get_locality = (co_get_call_locality_fn)GetProcAddress(module, (const char *)184);
    ok(!!get_context, "CoGetCallContextOfObject is not exported.\n");
    ok(!!get_locality, "CoGetCallLocality is not exported.\n");
    if (!get_context || !get_locality) return;

    context = (IUnknown *)0xdeadbeef;
    hr = get_context(&object, &IID_IUnknown, (void **)&context);
    ok(hr == S_OK, "Got hr %#lx.\n", hr);
    ok(!context, "Expected no incoming call context, got %p.\n", context);

    context = (IUnknown *)0xdeadbeef;
    hr = get_context(NULL, &IID_IUnknown, (void **)&context);
    ok(hr == S_OK, "Got hr %#lx.\n", hr);
    ok(!context, "Expected no incoming call context, got %p.\n", context);

    locality = 0x55555555;
    hr = get_locality(&object, &locality);
    ok(hr == S_OK, "Got hr %#lx.\n", hr);
    ok(locality == 0, "Expected same-process locality, got %d.\n", locality);

    locality = 0x55555555;
    hr = get_locality(NULL, &locality);
    ok(hr == S_OK, "Got hr %#lx.\n", hr);
    ok(locality == 0, "Expected same-process locality, got %d.\n", locality);
}

START_TEST(impersonation)
{
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(hr == S_OK, "CoInitializeEx returned %#lx.\n", hr);
    test_CoImpersonateClientOfObject();
    test_object_call_context();
    CoUninitialize();
}
