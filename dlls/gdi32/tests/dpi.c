/*
 * Private GDI DPI information tests
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <string.h>

#include "wine/test.h"
#include "winbase.h"
#include "winerror.h"
#include "winuser.h"
#include "wingdi.h"

struct current_dpi_info
{
    DWORD values[24];
};

static INT (WINAPI *pGetDCDpiScaleValue)(HDC);
static INT (WINAPI *pNtGdiGetDCDpiScaleValue)(HDC);

static void check_identity_scale( HDC dc )
{
    INT ret;

    SetLastError( 0xdeadbeef );
    ret = pGetDCDpiScaleValue( dc );
    ok( ret == 1, "DC %p has scale %d\n", dc, ret );
    ok( GetLastError() == 0xdeadbeef, "public query changed error to %lu\n", GetLastError() );
    SetLastError( 0xdeadbeef );
    ret = pNtGdiGetDCDpiScaleValue( dc );
    ok( ret == 1, "native DC %p has scale %d\n", dc, ret );
    ok( GetLastError() == 0xdeadbeef, "native query changed error to %lu\n", GetLastError() );
}

static void test_dc_dpi_scale(void)
{
    XFORM transform = {2.5f, 0, 0, 3.5f, 4, 5};
    HDC dc;

    pGetDCDpiScaleValue = (void *)GetProcAddress( GetModuleHandleA( "gdi32.dll" ), "GetDCDpiScaleValue" );
    pNtGdiGetDCDpiScaleValue = (void *)GetProcAddress( LoadLibraryA( "win32u.dll" ), "NtGdiGetDCDpiScaleValue" );
    if (!pGetDCDpiScaleValue || !pNtGdiGetDCDpiScaleValue)
    {
        win_skip( "DC DPI scale exports unavailable\n" );
        return;
    }
    check_identity_scale( NULL );
    check_identity_scale( (HDC)(ULONG_PTR)0x1234 );
    check_identity_scale( (HDC)(LONG_PTR)-1 );
    check_identity_scale( (HDC)GetStockObject( WHITE_BRUSH ) );
    dc = CreateCompatibleDC( NULL );
    ok( !!dc, "CreateCompatibleDC failed %lu\n", GetLastError() );
    if (!dc) return;
    check_identity_scale( dc );
    ok( !!SetMapMode( dc, MM_ANISOTROPIC ), "SetMapMode failed\n" );
    ok( SetWindowExtEx( dc, 100, 100, NULL ), "SetWindowExtEx failed\n" );
    ok( SetViewportExtEx( dc, 200, 300, NULL ), "SetViewportExtEx failed\n" );
    check_identity_scale( dc );
    ok( !!SetGraphicsMode( dc, GM_ADVANCED ), "SetGraphicsMode failed\n" );
    ok( SetWorldTransform( dc, &transform ), "SetWorldTransform failed\n" );
    check_identity_scale( dc );
    ok( DeleteDC( dc ), "DeleteDC failed\n" );
    check_identity_scale( dc );
}

START_TEST(dpi)
{
    BOOL (WINAPI *pGetCurrentDpiInfo)(HMONITOR, struct current_dpi_info *);
    struct current_dpi_info info, first;
    DPI_AWARENESS_CONTEXT contexts[] =
    {
        DPI_AWARENESS_CONTEXT_UNAWARE,
        DPI_AWARENESS_CONTEXT_SYSTEM_AWARE,
        DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE,
        DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
        DPI_AWARENESS_CONTEXT_UNAWARE_GDISCALED,
    };
    DPI_AWARENESS_CONTEXT previous;
    HMONITOR monitor;
    MONITORINFO monitor_info = {sizeof(monitor_info)};
    POINT point = {0};
    BOOL ret;
    unsigned int i, j;

    test_dc_dpi_scale();

    pGetCurrentDpiInfo = (void *)GetProcAddress( GetModuleHandleA( "gdi32.dll" ),
                                                 "GetCurrentDpiInfo" );
    if (!pGetCurrentDpiInfo)
    {
        win_skip( "GetCurrentDpiInfo is unavailable\n" );
        return;
    }

    memset( &info, 0xcc, sizeof(info) );
    SetLastError( 0xdeadbeef );
    ret = pGetCurrentDpiInfo( NULL, &info );
    ok( !ret, "GetCurrentDpiInfo succeeded for a null monitor\n" );
    ok( GetLastError() == ERROR_INVALID_HANDLE, "got error %lu\n", GetLastError() );
    for (i = 0; i < ARRAY_SIZE(info.values); ++i)
        ok( info.values[i] == 0xcccccccc, "value %u changed to %#lx\n", i, info.values[i] );

    monitor = MonitorFromPoint( point, MONITOR_DEFAULTTOPRIMARY );
    ok( !!monitor, "MonitorFromPoint failed, error %lu\n", GetLastError() );
    if (!monitor) return;

    memset( &first, 0xcc, sizeof(first) );
    for (i = 0; i < ARRAY_SIZE(contexts); ++i)
    {
        previous = SetThreadDpiAwarenessContext( contexts[i] );
        ok( !!previous, "SetThreadDpiAwarenessContext failed for context %u, error %lu\n",
            i, GetLastError() );

        memset( &info, 0xcc, sizeof(info) );
        SetLastError( 0xdeadbeef );
        ret = pGetCurrentDpiInfo( monitor, &info );
        ok( ret, "GetCurrentDpiInfo failed for context %u, error %lu\n", i, GetLastError() );
        ok( GetLastError() == 0xdeadbeef, "context %u changed last error to %lu\n",
            i, GetLastError() );
        for (j = 0; j < ARRAY_SIZE(info.values); ++j)
            ok( info.values[j] != 0xcccccccc, "context %u left value %u untouched\n", i, j );

        if (!i) first = info;
        else ok( !memcmp( &info, &first, sizeof(info) ),
                 "context %u returned a different DPI record\n", i );

        SetThreadDpiAwarenessContext( previous );
    }

    previous = SetThreadDpiAwarenessContext( DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 );
    ret = GetMonitorInfoW( monitor, &monitor_info );
    ok( ret, "GetMonitorInfoW failed, error %lu\n", GetLastError() );
    SetThreadDpiAwarenessContext( previous );

    if (winetest_platform_is_wine)
    {
        for (i = 0; i < 4; ++i)
            ok( first.values[i] == 100, "scale value %u is %lu\n", i, first.values[i] );
        for (i = 4; i < ARRAY_SIZE(first.values); ++i)
        {
            if (i == 8 || i == 9 || i == 22 || i == 23) continue;
            ok( !first.values[i], "reserved value %u is %#lx\n", i, first.values[i] );
        }
        ok( first.values[8] == monitor_info.rcMonitor.right - monitor_info.rcMonitor.left,
            "width is %lu, expected %ld\n", first.values[8],
            monitor_info.rcMonitor.right - monitor_info.rcMonitor.left );
        ok( first.values[9] == monitor_info.rcMonitor.bottom - monitor_info.rcMonitor.top,
            "height is %lu, expected %ld\n", first.values[9],
            monitor_info.rcMonitor.bottom - monitor_info.rcMonitor.top );
        ok( first.values[22] == 1, "state value is %#lx\n", first.values[22] );
        ok( first.values[23] == 0x20, "flags value is %#lx\n", first.values[23] );
    }
}
