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

static void test_native_ordinals(void)
{
    originate_or_transform_error_fn originate;
    set_chain_restricted_errors_fn set_chain;
    clear_chain_restricted_errors_fn clear_chain;
    marshal_restricted_error_fn marshal_extent, marshal_error;
    unmarshal_restricted_error_fn unmarshal_error;
    get_registration_store_context_fn get_registration_store_context;
    HMODULE module = GetModuleHandleW(L"combase.dll");
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

    ok(!!originate, "Ordinal 176 is unavailable.\n");
    ok(!!set_chain, "Ordinal 177 is unavailable.\n");
    ok(!!clear_chain, "Ordinal 178 is unavailable.\n");
    ok(!!marshal_extent, "Ordinal 164 is unavailable.\n");
    ok(!!marshal_error, "Ordinal 165 is unavailable.\n");
    ok(!!unmarshal_error, "Ordinal 166 is unavailable.\n");
    ok(!!get_registration_store_context, "Ordinal 153 is unavailable.\n");
    ok((void *)originate != (void *)GetProcAddress(module, "CoVrfReleaseThreadState"),
            "Ordinal 176 still resolves to CoVrfReleaseThreadState.\n");
    ok((void *)set_chain != (void *)GetProcAddress(module, "CoWaitForMultipleHandles"),
            "Ordinal 177 still resolves to CoWaitForMultipleHandles.\n");

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
