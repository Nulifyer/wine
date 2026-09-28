/* Tests for COM window-property interface marshaling.
 *
 * Copyright 2026 Nulifyer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#define COBJMACROS
#include "objbase.h"
#include "winuser.h"

#include "wine/test.h"

typedef HRESULT (WINAPI *register_window_prop_interface_fn)(HWND, REFIID, IUnknown *, DWORD, UINT64 *);
typedef HRESULT (WINAPI *get_window_prop_interface_fn)(HWND, UINT64, DWORD, REFIID, void **, DWORD *);
typedef HRESULT (WINAPI *revoke_window_prop_interface_fn)(HWND, UINT64, REFIID, DWORD *, DWORD *);

struct test_object
{
    IUnknown IUnknown_iface;
    LONG refs;
};

static inline struct test_object *impl_from_IUnknown(IUnknown *iface)
{
    return CONTAINING_RECORD(iface, struct test_object, IUnknown_iface);
}

static HRESULT WINAPI test_object_QueryInterface(IUnknown *iface, REFIID iid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (!IsEqualIID(iid, &IID_IUnknown)) return E_NOINTERFACE;
    *out = iface;
    IUnknown_AddRef(iface);
    return S_OK;
}

static ULONG WINAPI test_object_AddRef(IUnknown *iface)
{
    return InterlockedIncrement(&impl_from_IUnknown(iface)->refs);
}

static ULONG WINAPI test_object_Release(IUnknown *iface)
{
    return InterlockedDecrement(&impl_from_IUnknown(iface)->refs);
}

static const IUnknownVtbl test_object_vtbl =
{
    test_object_QueryInterface,
    test_object_AddRef,
    test_object_Release,
};

START_TEST(windowprop)
{
    register_window_prop_interface_fn register_interface;
    get_window_prop_interface_fn get_interface;
    revoke_window_prop_interface_fn revoke_interface;
    struct test_object object = {{&test_object_vtbl}, 1};
    IUnknown *result = NULL;
    DWORD context, process_id, thread_id;
    HMODULE module = GetModuleHandleW(L"combase.dll");
    UINT64 cookie = 0xdeadbeef;
    HWND hwnd;
    HRESULT hr;

    register_interface = (void *)GetProcAddress(module, "InternalRegisterWindowPropInterface2");
    get_interface = (void *)GetProcAddress(module, "InternalGetWindowPropInterface2");
    revoke_interface = (void *)GetProcAddress(module, "InternalRevokeWindowPropInterface");
    ok(!!register_interface && !!get_interface && !!revoke_interface,
            "window-property interface exports are unavailable.\n");
    if (!register_interface || !get_interface || !revoke_interface) return;

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ok(hr == S_OK, "CoInitializeEx returned %#lx.\n", hr);
    if (FAILED(hr)) return;

    hwnd = CreateWindowW(L"static", L"windowprop", WS_OVERLAPPED, 0, 0, 100, 100,
            NULL, NULL, NULL, NULL);
    ok(!!hwnd, "CreateWindowW failed, error %lu.\n", GetLastError());

    cookie = 0xdeadbeef;
    hr = register_interface((HWND)0xdeadbeef, &IID_IUnknown, &object.IUnknown_iface, 0, &cookie);
    ok(hr == HRESULT_FROM_WIN32(ERROR_INVALID_WINDOW_HANDLE), "invalid window returned %#lx.\n", hr);
    ok(!cookie, "invalid window returned cookie %#I64x.\n", cookie);

    hr = register_interface(hwnd, &IID_IUnknown, &object.IUnknown_iface, 0, &cookie);
    ok(hr == S_OK, "registration returned %#lx.\n", hr);
    ok(!!cookie, "registration returned a zero cookie.\n");
    ok(object.refs > 1, "registration did not retain the object, refs %ld.\n", object.refs);

    context = 0xdeadbeef;
    hr = get_interface(hwnd, cookie, 0, &IID_IUnknown, (void **)&result, &context);
    ok(hr == S_OK, "lookup returned %#lx.\n", hr);
    ok(result == &object.IUnknown_iface, "lookup returned %p, expected %p.\n",
            result, &object.IUnknown_iface);
    ok(!context, "lookup returned context %#lx.\n", context);
    if (result) IUnknown_Release(result);

    process_id = thread_id = 0xdeadbeef;
    hr = revoke_interface(hwnd, cookie, &IID_IUnknown, &thread_id, &process_id);
    ok(hr == S_OK, "revoke returned %#lx.\n", hr);
    ok(process_id == GetCurrentProcessId(), "revoke returned process %lu.\n", process_id);
    ok(thread_id == GetCurrentThreadId(), "revoke returned thread %lu.\n", thread_id);
    ok(object.refs == 1, "revoke left object refs at %ld.\n", object.refs);

    result = (IUnknown *)0xdeadbeef;
    context = 0xdeadbeef;
    hr = get_interface(hwnd, cookie, 0, &IID_IUnknown, (void **)&result, &context);
    ok(FAILED(hr), "lookup after revoke returned %#lx.\n", hr);
    ok(!result, "lookup after revoke returned %p.\n", result);
    ok(!context, "lookup after revoke returned context %#lx.\n", context);

    DestroyWindow(hwnd);
    CoUninitialize();
}
