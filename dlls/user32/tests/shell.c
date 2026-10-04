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
    HWND (WINAPI *create_window_in_band)(DWORD, LPCWSTR, LPCWSTR, DWORD, INT, INT,
                                          INT, INT, HWND, HMENU, HINSTANCE, void *, DWORD);
    HWND (WINAPI *get_shell_change_notify_window)(void);
    BOOL (WINAPI *get_window_band)(HWND, DWORD *);
    BOOL (WINAPI *acquire_iam_key)(ULONGLONG *);
    BOOL (WINAPI *enable_iam_access)(ULONGLONG, BOOL);
    BOOL (WINAPI *set_shell_change_notify_window)(HWND);
    BOOL (WINAPI *set_shell_window)(HWND);
    BOOL (WINAPI *set_active_process_for_monitor)(DWORD, HMONITOR);
    BOOL (WINAPI *register_window_arrangement_callout)(HWND, BOOL);
    BOOL (WINAPI *shell_register_hot_key)(HWND, INT, UINT, UINT, HWND);
    ULONGLONG key, second_key;
    DWORD band;
    HMONITOR monitor;
    HWND band_hwnd, hwnd;
    HWND arrangement_hwnd, ordinary_message_hwnd;
    BOOL ret;

    ret = SetThreadDesktop( desktop );
    ok( ret, "failed to select test desktop, error %lu\n", GetLastError() );

    create_window_in_band = (void *)GetProcAddress( user32, "CreateWindowInBand" );
    get_shell_change_notify_window = (void *)GetProcAddress( user32, "GetShellChangeNotifyWindow" );
    get_window_band = (void *)GetProcAddress( user32, "GetWindowBand" );
    acquire_iam_key = (void *)GetProcAddress( user32, (const char *)2509 );
    enable_iam_access = (void *)GetProcAddress( user32, (const char *)2510 );
    set_shell_change_notify_window = (void *)GetProcAddress( user32, "SetShellChangeNotifyWindow" );
    set_shell_window = (void *)GetProcAddress( user32, "SetShellWindow" );
    set_active_process_for_monitor = (void *)GetProcAddress( user32, (const char *)2513 );
    register_window_arrangement_callout = (void *)GetProcAddress( user32, (const char *)2564 );
    shell_register_hot_key = (void *)GetProcAddress( user32, (const char *)2671 );
    ok( !!create_window_in_band, "CreateWindowInBand is unavailable\n" );
    ok( !!get_shell_change_notify_window, "GetShellChangeNotifyWindow is unavailable\n" );
    ok( !!get_window_band, "GetWindowBand is unavailable\n" );
    ok( !!acquire_iam_key, "AcquireIAMKey is unavailable\n" );
    ok( !!enable_iam_access, "EnableIAMAccess is unavailable\n" );
    ok( !!set_shell_change_notify_window, "SetShellChangeNotifyWindow is unavailable\n" );
    ok( !!set_shell_window, "SetShellWindow is unavailable\n" );
    ok( !!set_active_process_for_monitor, "SetActiveProcessForMonitor is unavailable\n" );
    ok( !!register_window_arrangement_callout,
        "RegisterWindowArrangementCallout is unavailable\n" );
    ok( !!shell_register_hot_key, "ShellRegisterHotKey is unavailable\n" );
    if (!create_window_in_band || !get_shell_change_notify_window || !get_window_band ||
        !acquire_iam_key || !enable_iam_access || !set_shell_change_notify_window ||
        !set_shell_window || !set_active_process_for_monitor ||
        !register_window_arrangement_callout || !shell_register_hot_key)
        return 0;

    SetLastError( 0x13579bdf );
    ret = register_window_arrangement_callout( NULL, FALSE );
    ok( !ret, "unregistered a null arrangement callout window\n" );
    ok( GetLastError() == ERROR_INVALID_WINDOW_HANDLE,
        "null arrangement unregister returned error %lu\n", GetLastError() );
    SetLastError( 0x13579bdf );
    ret = register_window_arrangement_callout( NULL, TRUE );
    ok( !ret, "registered a null arrangement callout window\n" );
    ok( GetLastError() == ERROR_INVALID_WINDOW_HANDLE,
        "null arrangement registration returned error %lu\n", GetLastError() );

    hwnd = CreateWindowExA( 0, "#32770", "shell notify test", WS_OVERLAPPEDWINDOW,
                            0, 0, 100, 100, NULL, NULL, GetModuleHandleA( NULL ), NULL );
    ok( !!hwnd, "failed to create test window, error %lu\n", GetLastError() );
    if (!hwnd) return 0;

    ok( !get_shell_change_notify_window(), "new desktop has a shell change notify window\n" );
    ret = set_shell_change_notify_window( hwnd );
    ok( !ret, "set shell change notify window without a registered shell succeeded\n" );

    key = 0xdeadbeefdeadbeef;
    SetLastError( 0xdeadbeef );
    ret = acquire_iam_key( &key );
    ok( !ret, "acquired IAM key without a registered shell\n" );
    ok( GetLastError() == ERROR_ACCESS_DENIED, "expected access denied, got %lu\n", GetLastError() );
    ok( key == 0xdeadbeefdeadbeef, "IAM key changed to %#I64x on failure\n", key );

    ret = set_shell_window( hwnd );
    ok( ret, "failed to register shell window, error %lu\n", GetLastError() );

    SetLastError( 0x13579bdf );
    ret = shell_register_hot_key( hwnd, 0x1234, 0x10, VK_F24, NULL );
    ok( !ret, "invalid shell hotkey modifier unexpectedly succeeded\n" );
    ok( GetLastError() == ERROR_INVALID_FLAGS, "invalid shell hotkey modifier returned error %lu\n",
        GetLastError() );

    SetLastError( 0x13579bdf );
    ret = shell_register_hot_key( (HWND)0x1234, 0x1234, 0, VK_F24, NULL );
    ok( !ret, "invalid shell hotkey window unexpectedly succeeded\n" );
    ok( GetLastError() == ERROR_INVALID_WINDOW_HANDLE,
        "invalid shell hotkey window returned error %lu\n", GetLastError() );

    SetLastError( 0x13579bdf );
    ret = shell_register_hot_key( hwnd, 0x1234, 0, VK_F24, (HWND)0x1234 );
    ok( !ret, "invalid shell hotkey foreground window unexpectedly succeeded\n" );
    ok( GetLastError() == ERROR_INVALID_WINDOW_HANDLE,
        "invalid shell hotkey foreground window returned error %lu\n", GetLastError() );

    SetLastError( 0x13579bdf );
    ret = shell_register_hot_key( hwnd, 0x1234, MOD_CONTROL, VK_F24, NULL );
    ok( ret, "failed to register shell hotkey, error %lu\n", GetLastError() );
    ok( GetLastError() == 0x13579bdf, "shell hotkey registration changed last error to %lu\n",
        GetLastError() );

    SetLastError( 0x13579bdf );
    ret = shell_register_hot_key( hwnd, 0x1235, MOD_CONTROL, VK_F24, NULL );
    ok( !ret, "duplicate shell hotkey unexpectedly succeeded\n" );
    ok( GetLastError() == ERROR_HOTKEY_ALREADY_REGISTERED,
        "duplicate shell hotkey returned error %lu\n", GetLastError() );
    ret = UnregisterHotKey( hwnd, 0x1234 );
    ok( ret, "failed to unregister shell hotkey, error %lu\n", GetLastError() );

    SetLastError( 0x13579bdf );
    ret = shell_register_hot_key( NULL, 0x1236, MOD_SHIFT, VK_F23, hwnd );
    ok( ret, "failed to register shell hotkey with foreground target, error %lu\n", GetLastError() );
    ok( GetLastError() == 0x13579bdf,
        "shell hotkey foreground registration changed last error to %lu\n", GetLastError() );
    ret = UnregisterHotKey( NULL, 0x1236 );
    ok( ret, "failed to unregister shell hotkey with foreground target, error %lu\n",
        GetLastError() );

    monitor = MonitorFromPoint( (POINT){0, 0}, MONITOR_DEFAULTTOPRIMARY );
    ok( !!monitor, "failed to find primary monitor, error %lu\n", GetLastError() );
    SetLastError( 0x13579bdf );
    ret = set_active_process_for_monitor( GetCurrentProcessId(), NULL );
    ok( ret, "failed to select current process, error %lu\n", GetLastError() );
    ok( GetLastError() == 0x13579bdf, "current process changed last error to %lu\n",
        GetLastError() );
    SetLastError( 0x13579bdf );
    ret = set_active_process_for_monitor( GetCurrentProcessId(), monitor );
    ok( ret, "failed to select current process for primary monitor, error %lu\n", GetLastError() );
    ok( GetLastError() == 0x13579bdf, "primary monitor changed last error to %lu\n",
        GetLastError() );
    SetLastError( 0x13579bdf );
    ret = set_active_process_for_monitor( GetCurrentProcessId(), (HMONITOR)0x1234 );
    ok( !ret, "invalid monitor unexpectedly succeeded\n" );
    ok( GetLastError() == ERROR_INVALID_PARAMETER, "invalid monitor returned error %lu\n",
        GetLastError() );
    SetLastError( 0x13579bdf );
    ret = set_active_process_for_monitor( ~0u, NULL );
    ok( !ret, "invalid process unexpectedly succeeded\n" );
    ok( GetLastError() == ERROR_INVALID_PARAMETER, "invalid process returned error %lu\n",
        GetLastError() );

    key = 0;
    ret = acquire_iam_key( &key );
    ok( ret, "failed to acquire IAM key, error %lu\n", GetLastError() );
    ok( key != 0, "acquired a zero IAM key\n" );

    ret = enable_iam_access( key, TRUE );
    ok( ret, "failed to enable IAM access, error %lu\n", GetLastError() );

    ordinary_message_hwnd = CreateWindowExA( 0, "static", "ordinary message window", WS_POPUP,
                                              0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, NULL );
    ok( !!ordinary_message_hwnd, "failed to create ordinary message window, error %lu\n",
        GetLastError() );
    arrangement_hwnd = create_window_in_band( 0, L"static", L"arrangement callout", WS_POPUP,
                                               0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, NULL, 2 );
    ok( !!arrangement_hwnd, "failed to create arrangement callout window, error %lu\n",
        GetLastError() );
    if (ordinary_message_hwnd)
    {
        SetLastError( 0x13579bdf );
        ret = register_window_arrangement_callout( ordinary_message_hwnd, TRUE );
        ok( !ret, "registered a band-1 arrangement callout window\n" );
        ok( GetLastError() == ERROR_INVALID_PARAMETER,
            "band-1 arrangement callout returned error %lu\n", GetLastError() );
    }

    if (arrangement_hwnd)
    {
        SetLastError( 0x13579bdf );
        ret = register_window_arrangement_callout( arrangement_hwnd, TRUE );
        ok( ret, "failed to register arrangement callout, error %lu\n", GetLastError() );
        ok( GetLastError() == 0x13579bdf,
            "arrangement callout registration changed last error to %lu\n", GetLastError() );

        SetLastError( 0x13579bdf );
        ret = register_window_arrangement_callout( arrangement_hwnd, TRUE );
        ok( !ret, "duplicate arrangement callout registration succeeded\n" );
        ok( GetLastError() == ERROR_ALREADY_REGISTERED,
            "duplicate arrangement callout returned error %lu\n", GetLastError() );

        if (ordinary_message_hwnd)
        {
            SetLastError( 0x13579bdf );
            ret = register_window_arrangement_callout( ordinary_message_hwnd, FALSE );
            ok( !ret, "unregistered arrangement callout through the wrong window\n" );
            ok( GetLastError() == ERROR_ACCESS_DENIED,
                "wrong-window arrangement unregister returned error %lu\n", GetLastError() );
        }

        ret = shell_register_hot_key( arrangement_hwnd, 0xf060, MOD_SHIFT, VK_F22, NULL );
        ok( ret, "failed to register arrangement callout hotkey, error %lu\n", GetLastError() );

        SetLastError( 0x13579bdf );
        ret = register_window_arrangement_callout( arrangement_hwnd, FALSE );
        ok( ret, "failed to unregister arrangement callout, error %lu\n", GetLastError() );
        ok( GetLastError() == 0x13579bdf,
            "arrangement callout unregister changed last error to %lu\n", GetLastError() );
        ret = UnregisterHotKey( arrangement_hwnd, 0xf060 );
        ok( !ret, "arrangement callout unregister left its hotkey registered\n" );

        SetLastError( 0x13579bdf );
        ret = register_window_arrangement_callout( arrangement_hwnd, FALSE );
        ok( ret, "repeated arrangement callout unregister failed, error %lu\n", GetLastError() );
        ok( GetLastError() == 0x13579bdf,
            "repeated arrangement unregister changed last error to %lu\n", GetLastError() );
    }
    if (arrangement_hwnd) DestroyWindow( arrangement_hwnd );
    if (ordinary_message_hwnd) DestroyWindow( ordinary_message_hwnd );

    band_hwnd = create_window_in_band( 0, L"static", NULL, WS_POPUP, 0, 0, 32, 32,
                                       NULL, NULL, NULL, NULL, 12 );
    ok( !!band_hwnd, "failed to create IAM window in band 12, error %lu\n", GetLastError() );
    if (band_hwnd)
    {
        band = ~0u;
        ret = get_window_band( band_hwnd, &band );
        ok( ret, "failed to query IAM window band, error %lu\n", GetLastError() );
        ok( band == 12, "expected band 12, got %lu\n", band );
        DestroyWindow( band_hwnd );
    }

    ret = enable_iam_access( key, FALSE );
    ok( ret, "failed to disable IAM access, error %lu\n", GetLastError() );

    SetLastError( 0xdeadbeef );
    band_hwnd = create_window_in_band( 0, L"static", NULL, WS_POPUP, 0, 0, 32, 32,
                                       NULL, NULL, NULL, NULL, 12 );
    ok( !!band_hwnd, "shell process failed to create band 12 window without thread IAM, error %lu\n",
        GetLastError() );
    if (band_hwnd)
    {
        band = ~0u;
        ret = get_window_band( band_hwnd, &band );
        ok( ret, "failed to query shell window band, error %lu\n", GetLastError() );
        ok( band == 12, "expected band 12, got %lu\n", band );
        DestroyWindow( band_hwnd );
    }

    SetLastError( 0xdeadbeef );
    ret = enable_iam_access( key ^ 1, TRUE );
    ok( !ret, "enabled IAM access with the wrong key\n" );
    ok( GetLastError() == ERROR_ACCESS_DENIED, "expected access denied, got %lu\n", GetLastError() );

    second_key = 0xdeadbeefdeadbeef;
    SetLastError( 0xdeadbeef );
    ret = acquire_iam_key( &second_key );
    ok( !ret, "acquired IAM key more than once\n" );
    ok( GetLastError() == ERROR_ACCESS_DENIED, "expected access denied, got %lu\n", GetLastError() );
    ok( second_key == 0xdeadbeefdeadbeef, "second IAM key changed to %#I64x\n", second_key );

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
