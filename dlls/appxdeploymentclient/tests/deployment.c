/* AppX deployment client tests
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winerror.h"

#include "wine/test.h"

START_TEST(deployment)
{
    HRESULT (WINAPI *pIsSharedAppsEnabled)(BOOL *);
    HMODULE module;
    BOOL enabled = 0xdeadbeef;
    HRESULT hr;

    module = LoadLibraryW( L"appxdeploymentclient.dll" );
    ok( !!module, "failed to load appxdeploymentclient.dll, error %lu.\n", GetLastError() );
    if (!module) return;

    pIsSharedAppsEnabled = (void *)GetProcAddress( module, "IsSharedAppsEnabled" );
    ok( !!pIsSharedAppsEnabled, "IsSharedAppsEnabled is not exported.\n" );
    if (!pIsSharedAppsEnabled)
    {
        FreeLibrary( module );
        return;
    }

    hr = pIsSharedAppsEnabled( &enabled );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    ok( enabled == FALSE, "got enabled %d.\n", enabled );

    hr = pIsSharedAppsEnabled( NULL );
    ok( hr == E_INVALIDARG, "got hr %#lx.\n", hr );

    FreeLibrary( module );
}
