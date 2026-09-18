/* COM custom-unmarshaler policy tests.
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

#define OBJREF_SIGNATURE 0x574f454d
#define OBJREF_CUSTOM 0x4

static const CLSID test_unmarshaler =
    {0xa5183349, 0x82de, 0x4bfc, {0x9c, 0x13, 0x7d, 0x9d, 0xc5, 0x78, 0x72, 0x9c}};

struct custom_objref
{
    DWORD signature;
    DWORD flags;
    IID iid;
    CLSID clsid;
    DWORD extension_size;
    ULONG data_size;
};

static HRESULT unmarshal_test_class(REFCLSID clsid)
{
    static const LARGE_INTEGER zero;
    struct custom_objref objref =
    {
        OBJREF_SIGNATURE,
        OBJREF_CUSTOM,
        {0x00000000, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}},
        {0xa5183349, 0x82de, 0x4bfc, {0x9c, 0x13, 0x7d, 0x9d, 0xc5, 0x78, 0x72, 0x9c}},
        0,
        0,
    };
    IUnknown *object = NULL;
    IStream *stream;
    HRESULT hr;

    objref.clsid = *clsid;
    hr = CreateStreamOnHGlobal(NULL, TRUE, &stream);
    ok(hr == S_OK, "CreateStreamOnHGlobal returned %#lx.\n", hr);
    if (FAILED(hr)) return hr;

    hr = IStream_Write(stream, &objref, sizeof(objref), NULL);
    ok(hr == S_OK, "IStream_Write returned %#lx.\n", hr);
    if (SUCCEEDED(hr)) hr = IStream_Seek(stream, zero, STREAM_SEEK_SET, NULL);
    ok(hr == S_OK, "IStream_Seek returned %#lx.\n", hr);
    if (SUCCEEDED(hr)) hr = CoUnmarshalInterface(stream, &IID_IUnknown, (void **)&object);
    if (object) IUnknown_Release(object);
    IStream_Release(stream);
    return hr;
}

START_TEST(custom_unmarshaler_policy)
{
    HRESULT hr;

    hr = CoAllowUnmarshalerCLSID(&test_unmarshaler);
    ok(hr == CO_E_NOTINITIALIZED, "CoAllowUnmarshalerCLSID before COM returned %#lx.\n", hr);

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(hr == S_OK, "CoInitializeEx returned %#lx.\n", hr);
    if (FAILED(hr)) return;

    hr = CoAllowUnmarshalerCLSID(&test_unmarshaler);
    ok(hr == E_FAIL, "CoAllowUnmarshalerCLSID before security returned %#lx.\n", hr);

    hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NO_CUSTOM_MARSHAL, NULL);
    ok(hr == S_OK, "CoInitializeSecurity returned %#lx.\n", hr);

    hr = unmarshal_test_class(&test_unmarshaler);
    ok(hr == E_ACCESSDENIED, "Blocked custom unmarshal returned %#lx.\n", hr);

    hr = CoAllowUnmarshalerCLSID(&test_unmarshaler);
    ok(hr == S_OK, "CoAllowUnmarshalerCLSID returned %#lx.\n", hr);
    hr = CoAllowUnmarshalerCLSID(&test_unmarshaler);
    ok(hr == S_OK, "Repeated CoAllowUnmarshalerCLSID returned %#lx.\n", hr);

    hr = unmarshal_test_class(&test_unmarshaler);
    ok(hr == REGDB_E_CLASSNOTREG, "Allowed custom unmarshal returned %#lx.\n", hr);

    hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    ok(hr == RPC_E_TOO_LATE, "Repeated CoInitializeSecurity returned %#lx.\n", hr);

    CoUninitialize();
}
