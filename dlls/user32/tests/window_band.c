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
static BOOL (WINAPI *pIsShellFrameWindow)(HWND);
static BOOL (WINAPI *pSetActiveProcessForMonitor)(DWORD, HMONITOR);
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

static void test_is_shell_frame_window(void)
{
    const struct
    {
        const char *name;
        HWND hwnd;
    }
    shared_cases[] =
    {
        {"desktop", GetDesktopWindow()},
        {"shell", GetShellWindow()},
        {"foreground", GetForegroundWindow()},
    };
    HWND hwnd, child, stale;
    unsigned int i;
    BOOL ret;

    SetLastError( 0x13579bdf );
    ret = pIsShellFrameWindow( NULL );
    ok( !ret, "null window unexpectedly reported a shell frame\n" );
    ok( GetLastError() == ERROR_INVALID_PARAMETER, "null window returned error %lu\n",
        GetLastError() );

    SetLastError( 0x13579bdf );
    ret = pIsShellFrameWindow( (HWND)0x1234 );
    ok( !ret, "invalid window unexpectedly reported a shell frame\n" );
    ok( GetLastError() == ERROR_INVALID_PARAMETER, "invalid window returned error %lu\n",
        GetLastError() );

    stale = CreateWindowW( L"static", NULL, WS_POPUP, 0, 0, 32, 32,
                           NULL, NULL, NULL, NULL );
    ok( !!stale, "failed to create stale window, error %lu\n", GetLastError() );
    ok( DestroyWindow( stale ), "failed to destroy stale window, error %lu\n", GetLastError() );
    SetLastError( 0x13579bdf );
    ret = pIsShellFrameWindow( stale );
    ok( !ret, "stale window unexpectedly reported a shell frame\n" );
    ok( GetLastError() == ERROR_INVALID_PARAMETER, "stale window returned error %lu\n",
        GetLastError() );

    for (i = 0; i < ARRAY_SIZE(shared_cases); ++i)
    {
        if (!shared_cases[i].hwnd) continue;
        SetLastError( 0x13579bdf );
        ret = pIsShellFrameWindow( shared_cases[i].hwnd );
        ok( !ret, "%s window unexpectedly reported a shell frame\n", shared_cases[i].name );
        ok( GetLastError() == 0x13579bdf, "%s window changed last error to %lu\n",
            shared_cases[i].name, GetLastError() );
    }

    hwnd = CreateWindowW( L"static", NULL, WS_POPUP, 0, 0, 32, 32,
                          NULL, NULL, NULL, NULL );
    ok( !!hwnd, "failed to create popup window, error %lu\n", GetLastError() );
    SetLastError( 0x13579bdf );
    ret = pIsShellFrameWindow( hwnd );
    ok( !ret, "popup window unexpectedly reported a shell frame\n" );
    ok( GetLastError() == 0x13579bdf, "popup window changed last error to %lu\n",
        GetLastError() );

    child = CreateWindowW( L"static", NULL, WS_CHILD, 0, 0, 32, 32,
                           hwnd, NULL, NULL, NULL );
    ok( !!child, "failed to create child window, error %lu\n", GetLastError() );
    SetLastError( 0x13579bdf );
    ret = pIsShellFrameWindow( child );
    ok( !ret, "child window unexpectedly reported a shell frame\n" );
    ok( GetLastError() == 0x13579bdf, "child window changed last error to %lu\n",
        GetLastError() );
    ok( DestroyWindow( hwnd ), "failed to destroy popup window, error %lu\n", GetLastError() );

    hwnd = CreateWindowW( L"static", NULL, 0, 0, 0, 32, 32,
                          HWND_MESSAGE, NULL, NULL, NULL );
    ok( !!hwnd, "failed to create message window, error %lu\n", GetLastError() );
    SetLastError( 0x13579bdf );
    ret = pIsShellFrameWindow( hwnd );
    ok( !ret, "message window unexpectedly reported a shell frame\n" );
    ok( GetLastError() == 0x13579bdf, "message window changed last error to %lu\n",
        GetLastError() );
    ok( DestroyWindow( hwnd ), "failed to destroy message window, error %lu\n", GetLastError() );
}

static void test_set_active_process_for_monitor(void)
{
    HMONITOR monitor = MonitorFromPoint( (POINT){0, 0}, MONITOR_DEFAULTTOPRIMARY );
    static const DWORD process_ids[] = {0, ~0u};
    unsigned int i;
    BOOL ret;

    ok( !!monitor, "failed to find the primary monitor, error %lu\n", GetLastError() );

    for (i = 0; i < ARRAY_SIZE(process_ids); ++i)
    {
        SetLastError( 0x13579bdf );
        ret = pSetActiveProcessForMonitor( process_ids[i], NULL );
        ok( !ret, "process %lu unexpectedly succeeded\n", process_ids[i] );
        ok( GetLastError() == ERROR_ACCESS_DENIED, "process %lu returned error %lu\n",
            process_ids[i], GetLastError() );
    }

    SetLastError( 0x13579bdf );
    ret = pSetActiveProcessForMonitor( GetCurrentProcessId(), NULL );
    ok( !ret, "current process unexpectedly succeeded\n" );
    ok( GetLastError() == ERROR_ACCESS_DENIED, "current process returned error %lu\n",
        GetLastError() );

    SetLastError( 0x13579bdf );
    ret = pSetActiveProcessForMonitor( GetCurrentProcessId(), monitor );
    ok( !ret, "current process with primary monitor unexpectedly succeeded\n" );
    ok( GetLastError() == ERROR_ACCESS_DENIED, "primary monitor returned error %lu\n",
        GetLastError() );

    SetLastError( 0x13579bdf );
    ret = pSetActiveProcessForMonitor( GetCurrentProcessId(), (HMONITOR)0x1234 );
    ok( !ret, "current process with invalid monitor unexpectedly succeeded\n" );
    ok( GetLastError() == ERROR_ACCESS_DENIED, "invalid monitor returned error %lu\n",
        GetLastError() );
}

START_TEST(window_band)
{
    HMODULE user32 = GetModuleHandleW( L"user32.dll" );

    pCreateWindowInBandEx = (void *)GetProcAddress( user32, "CreateWindowInBandEx" );
    pGetWindowBand = (void *)GetProcAddress( user32, "GetWindowBand" );
    pIsShellFrameWindow = (void *)GetProcAddress( user32, (const char *)2573 );
    pSetActiveProcessForMonitor = (void *)GetProcAddress( user32, (const char *)2513 );
    pSetWindowBand = (void *)GetProcAddress( user32, "SetWindowBand" );
    if (!pCreateWindowInBandEx || !pGetWindowBand || !pIsShellFrameWindow ||
        !pSetActiveProcessForMonitor || !pSetWindowBand)
    {
        win_skip( "window-band entry points are unavailable\n" );
        return;
    }
    test_create_window_in_band_ex();
    test_set_window_band();
    test_is_shell_frame_window();
    test_set_active_process_for_monitor();
}
