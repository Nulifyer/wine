/* Tests for private window-band entry points.
 *
 * Copyright 2026 Kyle Leddy
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "windows.h"
#include "wine/test.h"

static HWND (WINAPI *pCreateWindowInBandEx)(DWORD, LPCWSTR, LPCWSTR, DWORD, INT, INT,
                                             INT, INT, HWND, HMENU, HINSTANCE, void *,
                                             DWORD, DWORD);
static BOOL (WINAPI *pGetWindowBand)(HWND, DWORD *);

static void test_create_window_in_band_ex(void)
{
    static const struct
    {
        const char *name;
        DWORD band;
        DWORD type_flags;
        DWORD error;
    }
    denied_cases[] =
    {
        {"desktop_type_1", 1, 1, ERROR_ACCESS_DENIED},
        {"genuine_windows", 14, 0, ERROR_ACCESS_DENIED},
        {"lock", 17, 0, ERROR_ACCESS_DENIED},
        {"above_lock", 18, 0, ERROR_ACCESS_DENIED},
        {"invalid", ~0u, 0, ERROR_INVALID_PARAMETER},
    };
    DWORD band, error;
    HWND hwnd;
    unsigned int i;

    hwnd = pCreateWindowInBandEx( 0, L"static", NULL, WS_POPUP, 0, 0, 32, 32,
                                  NULL, NULL, NULL, NULL, 0, 0 );
    ok( !!hwnd, "default band creation failed, error %lu\n", GetLastError() );
    band = 0x7f7f7f7f;
    SetLastError( 0x13579bdf );
    ok( pGetWindowBand( hwnd, &band ), "GetWindowBand failed, error %lu\n", GetLastError() );
    ok( band == 1, "default creation reported band %lu\n", band );
    ok( GetLastError() == 0x13579bdf, "GetWindowBand changed last error to %lu\n", GetLastError() );
    ok( DestroyWindow( hwnd ), "DestroyWindow failed, error %lu\n", GetLastError() );

    hwnd = pCreateWindowInBandEx( 0, L"static", NULL, WS_POPUP, 0, 0, 32, 32,
                                  NULL, NULL, NULL, NULL, 1, 0 );
    ok( !!hwnd, "desktop band creation failed, error %lu\n", GetLastError() );
    band = 0x7f7f7f7f;
    ok( pGetWindowBand( hwnd, &band ), "GetWindowBand failed, error %lu\n", GetLastError() );
    ok( band == 1, "desktop creation reported band %lu\n", band );
    ok( DestroyWindow( hwnd ), "DestroyWindow failed, error %lu\n", GetLastError() );

    for (i = 0; i < ARRAY_SIZE(denied_cases); ++i)
    {
        SetLastError( 0x13579bdf );
        hwnd = pCreateWindowInBandEx( 0, L"static", NULL, WS_POPUP, 0, 0, 32, 32,
                                      NULL, NULL, NULL, NULL, denied_cases[i].band,
                                      denied_cases[i].type_flags );
        error = GetLastError();
        ok( !hwnd, "%s unexpectedly created window %p\n", denied_cases[i].name, hwnd );
        ok( error == denied_cases[i].error, "%s returned error %lu\n",
            denied_cases[i].name, error );
        if (hwnd) DestroyWindow( hwnd );
    }
}

START_TEST(window_band)
{
    HMODULE user32 = GetModuleHandleW( L"user32.dll" );

    pCreateWindowInBandEx = (void *)GetProcAddress( user32, "CreateWindowInBandEx" );
    pGetWindowBand = (void *)GetProcAddress( user32, "GetWindowBand" );
    if (!pCreateWindowInBandEx || !pGetWindowBand)
    {
        win_skip( "window-band entry points are unavailable\n" );
        return;
    }
    test_create_window_in_band_ex();
}
