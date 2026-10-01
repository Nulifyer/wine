/*
 * GDI DPI tests
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <windows.h>

#include "wine/test.h"

static void test_GetCurrentDpiInfo(void)
{
    BOOL (WINAPI *pGetCurrentDpiInfo)(HMONITOR, void *);
    unsigned char buffer[64], expected[64];
    HMONITOR monitor;
    BOOL ret;

    pGetCurrentDpiInfo = (void *)GetProcAddress( GetModuleHandleA("gdi32.dll"),
                                                "GetCurrentDpiInfo" );
    ok(!!pGetCurrentDpiInfo, "GetCurrentDpiInfo is not exported\n");
    if (!pGetCurrentDpiInfo) return;

    memset(buffer, 0, sizeof(buffer));
    memcpy(expected, buffer, sizeof(buffer));
    SetLastError( 0xdeadbeef );
    ret = pGetCurrentDpiInfo( NULL, buffer );
    ok(!ret, "expected failure, got %d\n", ret);
    ok(GetLastError() == ERROR_INVALID_HANDLE, "got error %lu\n", GetLastError());
    ok(!memcmp(buffer, expected, sizeof(buffer)), "output buffer was modified\n");

    monitor = MonitorFromPoint( (POINT){0, 0}, MONITOR_DEFAULTTOPRIMARY );
    if (!monitor)
    {
        skip("No primary monitor is available\n");
        return;
    }

    SetLastError( 0xdeadbeef );
    ret = pGetCurrentDpiInfo( monitor, buffer );
    ok(!ret, "expected failure, got %d\n", ret);
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "got error %lu\n", GetLastError());
    ok(!memcmp(buffer, expected, sizeof(buffer)), "output buffer was modified\n");
}

START_TEST(dpi)
{
    test_GetCurrentDpiInfo();
}
