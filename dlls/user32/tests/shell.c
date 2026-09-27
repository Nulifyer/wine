/* Unit tests for shell-owned desktop state.
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
#include "wingdi.h"
#include "winuser.h"

#include "wine/test.h"

static DWORD WINAPI shell_change_notify_thread( void *arg )
{
    HDESK desktop = arg;
    HMODULE user32 = GetModuleHandleA( "user32.dll" );
    HWND (WINAPI *get_shell_change_notify_window)(void);
    BOOL (WINAPI *set_shell_change_notify_window)(HWND);
    BOOL (WINAPI *set_shell_window)(HWND);
    HWND hwnd;
    BOOL ret;

    ret = SetThreadDesktop( desktop );
    ok( ret, "failed to select test desktop, error %lu\n", GetLastError() );

    get_shell_change_notify_window = (void *)GetProcAddress( user32, "GetShellChangeNotifyWindow" );
    set_shell_change_notify_window = (void *)GetProcAddress( user32, "SetShellChangeNotifyWindow" );
    set_shell_window = (void *)GetProcAddress( user32, "SetShellWindow" );
    ok( !!get_shell_change_notify_window, "GetShellChangeNotifyWindow is unavailable\n" );
    ok( !!set_shell_change_notify_window, "SetShellChangeNotifyWindow is unavailable\n" );
    ok( !!set_shell_window, "SetShellWindow is unavailable\n" );
    if (!get_shell_change_notify_window || !set_shell_change_notify_window || !set_shell_window)
        return 0;

    hwnd = CreateWindowExA( 0, "#32770", "shell notify test", WS_OVERLAPPEDWINDOW,
                            0, 0, 100, 100, NULL, NULL, GetModuleHandleA( NULL ), NULL );
    ok( !!hwnd, "failed to create test window, error %lu\n", GetLastError() );
    if (!hwnd) return 0;

    ok( !get_shell_change_notify_window(), "new desktop has a shell change notify window\n" );
    ret = set_shell_change_notify_window( hwnd );
    ok( !ret, "set shell change notify window without a registered shell succeeded\n" );

    ret = set_shell_window( hwnd );
    ok( ret, "failed to register shell window, error %lu\n", GetLastError() );
    ret = set_shell_change_notify_window( hwnd );
    ok( ret, "failed to set shell change notify window, error %lu\n", GetLastError() );
    ok( get_shell_change_notify_window() == hwnd, "wrong shell change notify window %p\n",
        get_shell_change_notify_window() );

    ret = set_shell_change_notify_window( NULL );
    ok( ret, "failed to clear shell change notify window, error %lu\n", GetLastError() );
    ok( !get_shell_change_notify_window(), "shell change notify window was not cleared\n" );
    DestroyWindow( hwnd );
    return 0;
}

START_TEST(shell)
{
    HDESK desktop;
    HANDLE thread;

    desktop = CreateDesktopA( "shell_notify_test", NULL, NULL, 0, GENERIC_ALL, NULL );
    ok( !!desktop, "failed to create test desktop, error %lu\n", GetLastError() );
    if (!desktop) return;

    thread = CreateThread( NULL, 0, shell_change_notify_thread, desktop, 0, NULL );
    ok( !!thread, "failed to create test thread, error %lu\n", GetLastError() );
    if (thread)
    {
        WaitForSingleObject( thread, INFINITE );
        CloseHandle( thread );
    }
    CloseDesktop( desktop );
}
