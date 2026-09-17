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
typedef BOOL (WINAPI *quirk_is_enabled_fn)(void *);

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
    quirk_is_enabled_fn quirk_is_enabled;
    HMODULE module = GetModuleHandleW(L"combase.dll");
    HMODULE kernelbase = GetModuleHandleW(L"kernelbase.dll");
    FARPROC co_unmarshal_hresult, co_unmarshal_interface;
    FARPROC windows_inspect_string, windows_inspect_string2, windows_is_string_empty;
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
    co_unmarshal_hresult = GetProcAddress(module, "CoUnmarshalHresult");
    co_unmarshal_interface = GetProcAddress(module, "CoUnmarshalInterface");
    windows_inspect_string = GetProcAddress(module, "WindowsInspectString");
    windows_inspect_string2 = GetProcAddress(module, "WindowsInspectString2");
    windows_is_string_empty = GetProcAddress(module, "WindowsIsStringEmpty");
    is_error_propagation_enabled = (void *)GetProcAddress(module, "IsErrorPropagationEnabled");
    quirk_is_enabled = kernelbase ? (void *)GetProcAddress(kernelbase, "QuirkIsEnabled") : NULL;

    ok(!!originate, "Ordinal 176 is unavailable.\n");
    ok(!!set_chain, "Ordinal 177 is unavailable.\n");
    ok(!!clear_chain, "Ordinal 178 is unavailable.\n");
    ok(!!marshal_extent, "Ordinal 164 is unavailable.\n");
    ok(!!marshal_error, "Ordinal 165 is unavailable.\n");
    ok(!!unmarshal_error, "Ordinal 166 is unavailable.\n");
    ok(!!get_registration_store_context, "Ordinal 153 is unavailable.\n");
    ok(!!ro_initialize_strict, "Ordinal 179 is unavailable.\n");
    ok(!!is_error_propagation_enabled, "IsErrorPropagationEnabled is unavailable.\n");
    ok(!!quirk_is_enabled, "QuirkIsEnabled is unavailable.\n");
    ok((void *)originate != (void *)GetProcAddress(module, "CoVrfReleaseThreadState"),
            "Ordinal 176 still resolves to CoVrfReleaseThreadState.\n");
    ok((void *)set_chain != (void *)GetProcAddress(module, "CoWaitForMultipleHandles"),
            "Ordinal 177 still resolves to CoWaitForMultipleHandles.\n");
    ok((void *)ro_initialize_strict != (void *)co_unmarshal_hresult,
            "Ordinal 179 still resolves to CoUnmarshalHresult.\n");
    ok(GetProcAddress(module, (const char *)180) == co_unmarshal_interface,
            "Ordinal 180 no longer preserves the CoUnmarshalInterface alias.\n");
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

    if (is_error_propagation_enabled && quirk_is_enabled)
        ok(is_error_propagation_enabled() == !quirk_is_enabled((void *)(ULONG_PTR)0x30000),
                "Error propagation state does not match quirk 0x30000.\n");

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
