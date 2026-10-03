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
static BOOL (WINAPI *pSetWindowBand)(HWND, HWND, DWORD);

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

static void test_set_window_band(void)
{
    static const struct
    {
        const char *name;
        HWND insert_after;
        DWORD band;
        DWORD error;
    }
    denied_cases[] =
    {
        {"default", HWND_TOP, 0, ERROR_ACCESS_DENIED},
        {"desktop", HWND_TOP, 1, ERROR_ACCESS_DENIED},
        {"uiaccess", HWND_TOP, 2, ERROR_ACCESS_DENIED},
        {"genuine_windows", HWND_TOP, 14, ERROR_ACCESS_DENIED},
        {"lock", HWND_TOP, 17, ERROR_ACCESS_DENIED},
        {"above_lock", HWND_TOP, 18, ERROR_ACCESS_DENIED},
        {"invalid", HWND_TOP, ~0u, ERROR_ACCESS_DENIED},
        {"desktop_bottom", HWND_BOTTOM, 1, ERROR_ACCESS_DENIED},
        {"desktop_topmost", HWND_TOPMOST, 1, ERROR_ACCESS_DENIED},
        {"desktop_notopmost", HWND_NOTOPMOST, 1, ERROR_ACCESS_DENIED},
        {"uiaccess_topmost", HWND_TOPMOST, 2, ERROR_INVALID_PARAMETER},
    };
    DWORD band, error;
    HWND hwnd, stale;
    unsigned int i;
    BOOL ret;

    SetLastError( 0x13579bdf );
    ret = pSetWindowBand( NULL, HWND_TOP, 1 );
    ok( !ret, "null target unexpectedly succeeded\n" );
    ok( GetLastError() == ERROR_INVALID_WINDOW_HANDLE, "null target returned error %lu\n",
        GetLastError() );

    SetLastError( 0x13579bdf );
    ret = pSetWindowBand( (HWND)0x1234, HWND_TOP, 1 );
    ok( !ret, "invalid target unexpectedly succeeded\n" );
    ok( GetLastError() == ERROR_INVALID_WINDOW_HANDLE, "invalid target returned error %lu\n",
        GetLastError() );

    stale = CreateWindowW( L"static", NULL, WS_POPUP, 0, 0, 32, 32, NULL, NULL, NULL, NULL );
    ok( !!stale, "failed to create stale target, error %lu\n", GetLastError() );
    ok( DestroyWindow( stale ), "failed to destroy stale target, error %lu\n", GetLastError() );
    SetLastError( 0x13579bdf );
    ret = pSetWindowBand( stale, HWND_TOP, 1 );
    ok( !ret, "stale target unexpectedly succeeded\n" );
    ok( GetLastError() == ERROR_INVALID_WINDOW_HANDLE, "stale target returned error %lu\n",
        GetLastError() );

    SetLastError( 0x13579bdf );
    ret = pSetWindowBand( GetDesktopWindow(), HWND_TOP, 1 );
    ok( !ret, "desktop target unexpectedly succeeded\n" );
    ok( GetLastError() == 0x13579bdf, "desktop target changed last error to %lu\n",
        GetLastError() );

    for (i = 0; i < ARRAY_SIZE(denied_cases); ++i)
    {
        hwnd = CreateWindowW( L"static", NULL, WS_POPUP, 0, 0, 32, 32,
                              NULL, NULL, NULL, NULL );
        ok( !!hwnd, "%s failed to create target, error %lu\n",
            denied_cases[i].name, GetLastError() );
        band = 0x7f7f7f7f;
        ok( pGetWindowBand( hwnd, &band ), "%s initial query failed, error %lu\n",
            denied_cases[i].name, GetLastError() );
        ok( band == 1, "%s initial band is %lu\n", denied_cases[i].name, band );

        SetLastError( 0x13579bdf );
        ret = pSetWindowBand( hwnd, denied_cases[i].insert_after, denied_cases[i].band );
        error = GetLastError();
        ok( !ret, "%s unexpectedly changed the band\n", denied_cases[i].name );
        ok( error == denied_cases[i].error, "%s returned error %lu\n",
            denied_cases[i].name, error );
        band = 0x7f7f7f7f;
        ok( pGetWindowBand( hwnd, &band ), "%s final query failed, error %lu\n",
            denied_cases[i].name, GetLastError() );
        ok( band == 1, "%s changed band to %lu\n", denied_cases[i].name, band );
        ok( DestroyWindow( hwnd ), "%s failed to destroy target, error %lu\n",
            denied_cases[i].name, GetLastError() );
    }
}

START_TEST(window_band)
{
    HMODULE user32 = GetModuleHandleW( L"user32.dll" );

    pCreateWindowInBandEx = (void *)GetProcAddress( user32, "CreateWindowInBandEx" );
    pGetWindowBand = (void *)GetProcAddress( user32, "GetWindowBand" );
    pSetWindowBand = (void *)GetProcAddress( user32, "SetWindowBand" );
    if (!pCreateWindowInBandEx || !pGetWindowBand || !pSetWindowBand)
    {
        win_skip( "window-band entry points are unavailable\n" );
        return;
    }
    test_create_window_in_band_ex();
    test_set_window_band();
}
