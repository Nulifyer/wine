/*
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#define COBJMACROS
#include "dxgi.h"
#include "wine/test.h"

START_TEST(vblank)
{
    IDXGIFactory *factory;
    IDXGIAdapter *adapter;
    IDXGIOutput *output;
    HRESULT hr;

    hr = CreateDXGIFactory(&IID_IDXGIFactory, (void **)&factory);
    if (FAILED(hr))
    {
        skip("Failed to create a DXGI factory, hr %#lx.\n", hr);
        return;
    }

    hr = IDXGIFactory_EnumAdapters(factory, 0, &adapter);
    if (FAILED(hr))
    {
        skip("Failed to enumerate a DXGI adapter, hr %#lx.\n", hr);
        IDXGIFactory_Release(factory);
        return;
    }

    hr = IDXGIAdapter_EnumOutputs(adapter, 0, &output);
    if (hr == DXGI_ERROR_NOT_FOUND)
    {
        skip("Adapter does not have any outputs.\n");
        IDXGIAdapter_Release(adapter);
        IDXGIFactory_Release(factory);
        return;
    }
    ok(hr == S_OK, "Failed to enumerate a DXGI output, hr %#lx.\n", hr);
    if (SUCCEEDED(hr))
    {
        hr = IDXGIOutput_WaitForVBlank(output);
        ok(hr == S_OK, "WaitForVBlank failed, hr %#lx.\n", hr);
        IDXGIOutput_Release(output);
    }

    IDXGIAdapter_Release(adapter);
    IDXGIFactory_Release(factory);
}
