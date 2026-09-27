/*
 * Tests for current Windows private combase ordinals
 *
 * Copyright 2026 Nulifyer
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

typedef HRESULT (WINAPI *set_chain_restricted_errors_fn)(void);
typedef void (WINAPI *clear_chain_restricted_errors_fn)(void);
typedef void (WINAPI *originate_or_transform_error_fn)(HRESULT);
typedef HRESULT (WINAPI *marshal_restricted_error_fn)(void *, void **);
typedef HRESULT (WINAPI *unmarshal_restricted_error_fn)(void *, void *);
typedef HRESULT (WINAPI *get_registration_store_context_fn)(UINT32, void *, UINT32, REFIID, void **);
typedef HRESULT (WINAPI *ro_initialize_strict_fn)(UINT32);
typedef BOOL (WINAPI *is_error_propagation_enabled_fn)(void);
typedef BOOL (WINAPI *is_apartment_initialized_fn)(void);
typedef BOOL (WINAPI *quirk_is_enabled_fn)(void *);
typedef HRESULT (WINAPI *register_disconnect_fn)(IUnknown *, DWORD, IUnknown *, void *, void **);
typedef HRESULT (WINAPI *unregister_disconnect_fn)(void *);
typedef BOOL (WINAPI *other_side_marshaling_fn)(void *);

struct test_unknown
{
    IUnknown IUnknown_iface;
    LONG refs;
};

struct test_disconnect_sink
{
    IUnknown IUnknown_iface;
    LONG refs;
    LONG calls;
    void *context;
};

struct test_disconnect_sink_vtbl
{
    HRESULT (WINAPI *QueryInterface)(IUnknown *, REFIID, void **);
    ULONG (WINAPI *AddRef)(IUnknown *);
    ULONG (WINAPI *Release)(IUnknown *);
    void (WINAPI *OnDisconnect)(IUnknown *, void *);
};

static HRESULT WINAPI test_unknown_QueryInterface(IUnknown *iface, REFIID iid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (!IsEqualIID(iid, &IID_IUnknown)) return E_NOINTERFACE;
    *out = iface;
    IUnknown_AddRef(iface);
    return S_OK;
}

static ULONG WINAPI test_unknown_AddRef(IUnknown *iface)
{
    struct test_unknown *object = CONTAINING_RECORD(iface, struct test_unknown, IUnknown_iface);
    return InterlockedIncrement(&object->refs);
}

static ULONG WINAPI test_unknown_Release(IUnknown *iface)
{
    struct test_unknown *object = CONTAINING_RECORD(iface, struct test_unknown, IUnknown_iface);
    return InterlockedDecrement(&object->refs);
}

static const IUnknownVtbl test_unknown_vtbl =
{
    test_unknown_QueryInterface,
    test_unknown_AddRef,
    test_unknown_Release,
};

static HRESULT WINAPI test_sink_QueryInterface(IUnknown *iface, REFIID iid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (!IsEqualIID(iid, &IID_IUnknown)) return E_NOINTERFACE;
    *out = iface;
    IUnknown_AddRef(iface);
    return S_OK;
}

static ULONG WINAPI test_sink_AddRef(IUnknown *iface)
{
    struct test_disconnect_sink *sink = CONTAINING_RECORD(iface, struct test_disconnect_sink, IUnknown_iface);
    return InterlockedIncrement(&sink->refs);
}

static ULONG WINAPI test_sink_Release(IUnknown *iface)
{
    struct test_disconnect_sink *sink = CONTAINING_RECORD(iface, struct test_disconnect_sink, IUnknown_iface);
    return InterlockedDecrement(&sink->refs);
}

static void WINAPI test_sink_OnDisconnect(IUnknown *iface, void *context)
{
    struct test_disconnect_sink *sink = CONTAINING_RECORD(iface, struct test_disconnect_sink, IUnknown_iface);
    sink->context = context;
    InterlockedIncrement(&sink->calls);
}

static const struct test_disconnect_sink_vtbl test_sink_vtbl =
{
    test_sink_QueryInterface,
    test_sink_AddRef,
    test_sink_Release,
    test_sink_OnDisconnect,
};

struct apartment_test
{
    ro_initialize_strict_fn initialize;
    UINT32 requested;
    HRESULT hr;
    HRESULT apartment_hr;
    APTTYPE apartment;
    APTTYPEQUALIFIER qualifier;
};

static DWORD WINAPI apartment_thread(void *param)
{
    struct apartment_test *test = param;

    test->apartment = 0xdeadbeef;
    test->qualifier = 0xdeadbeef;
    test->hr = test->initialize(test->requested);
    if (SUCCEEDED(test->hr))
    {
        test->apartment_hr = CoGetApartmentType(&test->apartment, &test->qualifier);
        CoUninitialize();
    }
    return 0;
}

static void test_apartment_type(ro_initialize_strict_fn initialize, UINT32 requested,
        HRESULT expected_hr, APTTYPE expected_apartment)
{
    struct apartment_test test = {initialize, requested, E_UNEXPECTED, E_UNEXPECTED};
    HANDLE thread;

    thread = CreateThread(NULL, 0, apartment_thread, &test, 0, NULL);
    ok(!!thread, "Failed to create apartment test thread, error %lu.\n", GetLastError());
    if (!thread) return;
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    ok(test.hr == expected_hr, "Apartment type %u returned %#lx, expected %#lx.\n",
            requested, test.hr, expected_hr);
    if (SUCCEEDED(test.hr))
    {
        ok(test.apartment_hr == S_OK, "CoGetApartmentType returned %#lx.\n", test.apartment_hr);
        if (expected_apartment == APTTYPE_STA)
            ok(test.apartment == APTTYPE_STA || test.apartment == APTTYPE_MAINSTA,
                    "Apartment type %u produced apartment %u.\n", requested, test.apartment);
        else
            ok(test.apartment == expected_apartment, "Apartment type %u produced apartment %u.\n",
                    requested, test.apartment);
        ok(test.qualifier == APTTYPEQUALIFIER_NONE, "Apartment type %u produced qualifier %u.\n",
                requested, test.qualifier);
    }
}

static void test_disconnect_callbacks(register_disconnect_fn register_callback,
        unregister_disconnect_fn unregister_callback)
{
    struct test_unknown object = {{&test_unknown_vtbl}, 1};
    struct test_disconnect_sink sink = {{(const IUnknownVtbl *)&test_sink_vtbl}, 1};
    void *context = (void *)0x12345678, *cookie = (void *)0xdeadbeef;
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ok(hr == S_OK, "CoInitializeEx returned %#lx.\n", hr);
    if (FAILED(hr)) return;

    hr = unregister_callback(NULL);
    ok(hr == E_INVALIDARG, "Unregistering a NULL callback returned %#lx.\n", hr);

    hr = register_callback(&object.IUnknown_iface, MSHLFLAGS_NORMAL,
            &sink.IUnknown_iface, context, &cookie);
    ok(hr == S_OK, "Registering a disconnect callback returned %#lx.\n", hr);
    ok(cookie != NULL, "Registration returned a NULL cookie.\n");
    ok(sink.refs == 2, "Disconnect sink has %ld references.\n", sink.refs);

    hr = unregister_callback(cookie);
    ok(hr == S_OK, "Unregistering a disconnect callback returned %#lx.\n", hr);
    ok(sink.calls == 0, "Unregistered sink was called %ld times.\n", sink.calls);
    ok(sink.refs == 1, "Disconnect sink has %ld references after unregister.\n", sink.refs);

    cookie = NULL;
    hr = register_callback(&object.IUnknown_iface, MSHLFLAGS_NORMAL,
            &sink.IUnknown_iface, context, &cookie);
    ok(hr == S_OK, "Registering a second disconnect callback returned %#lx.\n", hr);

    hr = CoDisconnectObject(&object.IUnknown_iface, 0);
    ok(hr == S_OK, "CoDisconnectObject returned %#lx.\n", hr);
    ok(sink.calls == 1, "Disconnect sink was called %ld times.\n", sink.calls);
    ok(sink.context == context, "Disconnect sink received context %p.\n", sink.context);
    ok(sink.refs == 1, "Disconnect sink has %ld references after disconnect.\n", sink.refs);
    ok(object.refs == 1, "Object has %ld references after disconnect.\n", object.refs);

    CoUninitialize();
}

static void test_native_ordinals(void)
{
    originate_or_transform_error_fn originate;
    set_chain_restricted_errors_fn set_chain;
    clear_chain_restricted_errors_fn clear_chain;
    marshal_restricted_error_fn marshal_extent, marshal_error;
    unmarshal_restricted_error_fn unmarshal_error;
    get_registration_store_context_fn get_registration_store_context;
    ro_initialize_strict_fn ro_initialize_strict;
    is_error_propagation_enabled_fn is_error_propagation_enabled;
    is_apartment_initialized_fn is_apartment_initialized;
    quirk_is_enabled_fn quirk_is_enabled;
    register_disconnect_fn register_disconnect;
    unregister_disconnect_fn unregister_disconnect;
    other_side_marshaling_fn needs_trailing_padding, supports_udt;
    HMODULE module = GetModuleHandleW(L"combase.dll");
    HMODULE kernelbase = GetModuleHandleW(L"kernelbase.dll");
    FARPROC co_unmarshal_hresult, co_unmarshal_interface;
    FARPROC windows_inspect_string, windows_inspect_string2, windows_is_string_empty;
    ULONG_PTR marshal_context[3] = {0};
    void *output;
    HRESULT hr;

    ok(!!module, "combase.dll is not loaded.\n");
    if (!module) return;

    originate = (void *)GetProcAddress(module, (const char *)176);
    set_chain = (void *)GetProcAddress(module, (const char *)177);
    clear_chain = (void *)GetProcAddress(module, (const char *)178);
    marshal_extent = (void *)GetProcAddress(module, (const char *)164);
    marshal_error = (void *)GetProcAddress(module, (const char *)165);
    unmarshal_error = (void *)GetProcAddress(module, (const char *)166);
    get_registration_store_context = (void *)GetProcAddress(module, (const char *)153);
    ro_initialize_strict = (void *)GetProcAddress(module, (const char *)179);
    needs_trailing_padding = (void *)GetProcAddress(module, (const char *)180);
    supports_udt = (void *)GetProcAddress(module, (const char *)181);
    co_unmarshal_hresult = GetProcAddress(module, "CoUnmarshalHresult");
    co_unmarshal_interface = GetProcAddress(module, "CoUnmarshalInterface");
    windows_inspect_string = GetProcAddress(module, "WindowsInspectString");
    windows_inspect_string2 = GetProcAddress(module, "WindowsInspectString2");
    windows_is_string_empty = GetProcAddress(module, "WindowsIsStringEmpty");
    is_error_propagation_enabled = (void *)GetProcAddress(module, "IsErrorPropagationEnabled");
    is_apartment_initialized = (void *)GetProcAddress(module, "InternalIsApartmentInitialized");
    register_disconnect = (void *)GetProcAddress(module, "InternalCoRegisterDisconnectCallback");
    unregister_disconnect = (void *)GetProcAddress(module, "InternalCoUnregisterDisconnectCallback");
    quirk_is_enabled = kernelbase ? (void *)GetProcAddress(kernelbase, "QuirkIsEnabled") : NULL;

    ok(!!originate, "Ordinal 176 is unavailable.\n");
    ok(!!set_chain, "Ordinal 177 is unavailable.\n");
    ok(!!clear_chain, "Ordinal 178 is unavailable.\n");
    ok(!!marshal_extent, "Ordinal 164 is unavailable.\n");
    ok(!!marshal_error, "Ordinal 165 is unavailable.\n");
    ok(!!unmarshal_error, "Ordinal 166 is unavailable.\n");
    ok(!!get_registration_store_context, "Ordinal 153 is unavailable.\n");
    ok(!!ro_initialize_strict, "Ordinal 179 is unavailable.\n");
    ok(!!needs_trailing_padding, "Ordinal 180 is unavailable.\n");
    ok(!!supports_udt, "Ordinal 181 is unavailable.\n");
    ok(!!is_error_propagation_enabled, "IsErrorPropagationEnabled is unavailable.\n");
    ok(!!is_apartment_initialized, "InternalIsApartmentInitialized is unavailable.\n");
    ok(!!register_disconnect, "InternalCoRegisterDisconnectCallback is unavailable.\n");
    ok(!!unregister_disconnect, "InternalCoUnregisterDisconnectCallback is unavailable.\n");
    ok(!!quirk_is_enabled, "QuirkIsEnabled is unavailable.\n");
    ok((void *)originate != (void *)GetProcAddress(module, "CoVrfReleaseThreadState"),
            "Ordinal 176 still resolves to CoVrfReleaseThreadState.\n");
    ok((void *)set_chain != (void *)GetProcAddress(module, "CoWaitForMultipleHandles"),
            "Ordinal 177 still resolves to CoWaitForMultipleHandles.\n");
    ok((void *)ro_initialize_strict != (void *)co_unmarshal_hresult,
            "Ordinal 179 still resolves to CoUnmarshalHresult.\n");
    ok((FARPROC)needs_trailing_padding != co_unmarshal_interface,
            "Ordinal 180 still resolves to CoUnmarshalInterface.\n");
    ok(GetProcAddress(module, (const char *)2) == GetProcAddress(module, "ObjectStublessClient3"),
            "Ordinal 2 does not resolve to ObjectStublessClient3.\n");
    ok(GetProcAddress(module, (const char *)32) == GetProcAddress(module, "NdrProxyForwardingFunction3"),
            "Ordinal 32 does not resolve to NdrProxyForwardingFunction3.\n");
    ok(GetProcAddress(module, (const char *)359) == co_unmarshal_hresult,
            "Ordinal 359 does not resolve to CoUnmarshalHresult.\n");
    ok(GetProcAddress(module, (const char *)360) == co_unmarshal_interface,
            "Ordinal 360 does not resolve to CoUnmarshalInterface.\n");
    ok(GetProcAddress(module, (const char *)598) == windows_inspect_string,
            "Ordinal 598 does not resolve to WindowsInspectString.\n");
    ok(GetProcAddress(module, (const char *)599) == windows_inspect_string2,
            "Ordinal 599 does not resolve to WindowsInspectString2.\n");
    ok(GetProcAddress(module, (const char *)600) == windows_is_string_empty,
            "Ordinal 600 does not resolve to WindowsIsStringEmpty.\n");
    ok(GetProcAddress(module, (const char *)513) == (FARPROC)is_apartment_initialized,
            "Ordinal 513 does not resolve to InternalIsApartmentInitialized.\n");

    if (needs_trailing_padding)
        ok(!needs_trailing_padding(marshal_context), "Unexpected trailing-padding support.\n");
    if (supports_udt)
        ok(supports_udt(marshal_context), "Expected UDT marshaling support.\n");

    if (is_apartment_initialized)
    {
        CO_MTA_USAGE_COOKIE mta_cookie;

        ok(!is_apartment_initialized(), "Apartment is initialized before COM entry.\n");
        hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        ok(hr == S_OK, "CoInitializeEx returned %#lx.\n", hr);
        ok(is_apartment_initialized(), "STA is not reported as initialized.\n");
        CoUninitialize();
        ok(!is_apartment_initialized(), "Apartment remains initialized after CoUninitialize.\n");

        hr = CoIncrementMTAUsage(&mta_cookie);
        ok(hr == S_OK, "CoIncrementMTAUsage returned %#lx.\n", hr);
        ok(is_apartment_initialized(), "Process MTA is not reported as initialized.\n");
        CoDecrementMTAUsage(mta_cookie);
        ok(!is_apartment_initialized(), "Apartment remains initialized after releasing the process MTA.\n");
    }

    if (is_error_propagation_enabled && quirk_is_enabled)
        ok(is_error_propagation_enabled() == !quirk_is_enabled((void *)(ULONG_PTR)0x30000),
                "Error propagation state does not match quirk 0x30000.\n");

    if (register_disconnect && unregister_disconnect)
        test_disconnect_callbacks(register_disconnect, unregister_disconnect);

    if (ro_initialize_strict)
    {
        test_apartment_type(ro_initialize_strict, 0, S_OK, APTTYPE_STA);
        test_apartment_type(ro_initialize_strict, 1, S_OK, APTTYPE_STA);
        test_apartment_type(ro_initialize_strict, 2, S_OK, APTTYPE_MTA);
        test_apartment_type(ro_initialize_strict, 3, CO_E_NOT_SUPPORTED, APTTYPE_CURRENT);
        test_apartment_type(ro_initialize_strict, 4, S_OK, APTTYPE_STA);
        test_apartment_type(ro_initialize_strict, 5, E_INVALIDARG, APTTYPE_CURRENT);
    }

    if (set_chain)
    {
        hr = set_chain();
        ok(hr == S_OK, "SetChainRestrictedErrors returned %#lx.\n", hr);
    }
    if (clear_chain) clear_chain();
    if (originate) originate(E_FAIL);

    if (marshal_extent)
    {
        output = (void *)0xdeadbeef;
        hr = marshal_extent(NULL, &output);
        ok(hr == S_OK, "RpcMarshalRestrictedErrorFromTlsToExtent returned %#lx.\n", hr);
        ok(!output, "Got extent %p.\n", output);
    }

    if (marshal_error)
    {
        output = (void *)0xdeadbeef;
        hr = marshal_error(NULL, &output);
        ok(hr == S_OK, "RpcMarshalRestrictedErrorFromTls returned %#lx.\n", hr);
        ok(!output, "Got marshaled error %p.\n", output);
    }

    if (unmarshal_error)
    {
        hr = unmarshal_error(NULL, NULL);
        ok(hr == S_OK, "RpcUnmarshalRestrictedErrorToTls returned %#lx.\n", hr);
    }
}

START_TEST(native_ordinals)
{
    test_native_ordinals();
}
