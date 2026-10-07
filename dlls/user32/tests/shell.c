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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windef.h"
#include "winbase.h"
#include "wingdi.h"
#include "winuser.h"

#include "wine/test.h"

#define CAPABILITY_MESSAGE 0x02cd
#define CAPABILITY_RESULT  0x13572468

typedef BOOL (WINAPI *set_window_message_capability_fn)(HWND, UINT, PSID, ULONG);

static unsigned int capability_message_count;

static LRESULT CALLBACK capability_window_proc( HWND hwnd, UINT message, WPARAM wparam,
                                                LPARAM lparam )
{
    if (message == CAPABILITY_MESSAGE)
    {
        capability_message_count++;
        return CAPABILITY_RESULT;
    }
    return DefWindowProcW( hwnd, message, wparam, lparam );
}

static void capability_sender_child( char **argv )
{
    union
    {
        SID sid;
        BYTE bytes[SECURITY_MAX_SID_SIZE];
    } world;
    set_window_message_capability_fn set_capability;
    ULONG_PTR result = 0xfeedface;
    DWORD size = sizeof(world.bytes);
    HWND hwnd = NULL;
    BOOL expected, ret;

    sscanf( argv[3], "%p", &hwnd );
    expected = atoi( argv[4] );
    set_capability = (void *)GetProcAddress( GetModuleHandleA( "user32.dll" ),
                                             "SetWindowMessageCapability" );
    ok( !!set_capability, "SetWindowMessageCapability is unavailable\n" );
    if (!set_capability) return;

    if (atoi( argv[5] ))
    {
        ret = CreateWellKnownSid( WinWorldSid, NULL, world.bytes, &size );
        ok( ret, "failed to create World SID, error %lu\n", GetLastError() );
        if (ret)
        {
            SetLastError( 0x12345678 );
            ret = set_capability( hwnd, CAPABILITY_MESSAGE, world.bytes, 0 );
            ok( !ret, "registered a capability on a foreign-process window\n" );
            ok( GetLastError() == ERROR_ACCESS_DENIED,
                "foreign-process registration returned error %lu\n", GetLastError() );
        }
    }

    SetLastError( 0x12345678 );
    ret = SendMessageTimeoutW( hwnd, CAPABILITY_MESSAGE, 0x1234, 0x5678,
                               SMTO_ABORTIFHUNG, 2000, &result );
    ok( !!ret == expected, "message delivery returned %d, expected %d, error %lu\n",
        ret, expected, GetLastError() );
    ok( GetLastError() == 0x12345678, "message delivery changed last error to %lu\n",
        GetLastError() );
    if (expected)
        ok( result == CAPABILITY_RESULT, "message returned %#Ix, expected %#x\n",
            result, CAPABILITY_RESULT );
    else
        ok( !result, "rejected message returned %#Ix\n", result );
}

static BOOL run_capability_sender( char **argv, HWND hwnd, BOOL expected,
                                   BOOL check_registration )
{
    STARTUPINFOA startup = { .cb = sizeof(startup) };
    PROCESS_INFORMATION process = {0};
    char command[MAX_PATH * 3];
    DWORD wait;
    MSG message;
    BOOL ret;

    sprintf( command, "\"%s\" %s capability-child %p %u %u", argv[0], argv[1], hwnd,
             expected, check_registration );
    ret = CreateProcessA( NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process );
    ok( ret, "failed to create capability sender, error %lu\n", GetLastError() );
    if (!ret) return FALSE;

    for (;;)
    {
        wait = MsgWaitForMultipleObjects( 1, &process.hProcess, FALSE, 10000, QS_ALLINPUT );
        if (wait == WAIT_OBJECT_0) break;
        if (wait != WAIT_OBJECT_0 + 1)
        {
            ok( 0, "capability sender wait returned %#lx\n", wait );
            TerminateProcess( process.hProcess, 1 );
            break;
        }
        while (PeekMessageW( &message, NULL, 0, 0, PM_REMOVE ))
        {
            TranslateMessage( &message );
            DispatchMessageW( &message );
        }
    }
    wait_child_process( &process );
    CloseHandle( process.hThread );
    CloseHandle( process.hProcess );
    return wait == WAIT_OBJECT_0;
}

static void test_window_message_capability( char **argv )
{
    union
    {
        SID sid;
        BYTE bytes[SECURITY_MAX_SID_SIZE];
    } world;
    set_window_message_capability_fn set_capability;
    WNDCLASSW cls = {0};
    DWORD size = sizeof(world.bytes);
    HWND hwnd, stale;
    BOOL ret;

    set_capability = (void *)GetProcAddress( GetModuleHandleA( "user32.dll" ),
                                             "SetWindowMessageCapability" );
    if (!set_capability)
    {
        win_skip( "SetWindowMessageCapability is unavailable\n" );
        return;
    }

    ret = CreateWellKnownSid( WinWorldSid, NULL, world.bytes, &size );
    ok( ret, "failed to create World SID, error %lu\n", GetLastError() );
    if (!ret) return;

    SetLastError( 0x12345678 );
    ret = set_capability( NULL, CAPABILITY_MESSAGE, world.bytes, 0 );
    ok( !ret, "registered a capability on a null window\n" );
    ok( GetLastError() == ERROR_INVALID_WINDOW_HANDLE,
        "null-window registration returned error %lu\n", GetLastError() );

    cls.lpfnWndProc = capability_window_proc;
    cls.hInstance = GetModuleHandleW( NULL );
    cls.lpszClassName = L"WineWindowMessageCapabilityTest";
    ret = RegisterClassW( &cls );
    ok( ret, "failed to register capability window class, error %lu\n", GetLastError() );
    if (!ret) return;
    hwnd = CreateWindowExW( 0, cls.lpszClassName, L"capability", WS_OVERLAPPED,
                            0, 0, 16, 16, NULL, NULL, cls.hInstance, NULL );
    ok( !!hwnd, "failed to create capability window, error %lu\n", GetLastError() );
    if (!hwnd) goto done;

    SetLastError( 0x12345678 );
    ret = set_capability( hwnd, CAPABILITY_MESSAGE, NULL, 0 );
    ok( !ret, "registered a null SID\n" );
    ok( GetLastError() == 0x12345678, "null SID changed last error to %lu\n", GetLastError() );
    SetLastError( 0x12345678 );
    ret = set_capability( hwnd, CAPABILITY_MESSAGE, (PSID)(UINT_PTR)0xdeadbeef, 0 );
    ok( !ret, "registered an invalid SID pointer\n" );
    ok( GetLastError() == 0x12345678, "invalid SID changed last error to %lu\n", GetLastError() );

    SetLastError( 0x12345678 );
    ret = set_capability( hwnd, CAPABILITY_MESSAGE + 1, world.bytes, ~0u );
    ok( !ret, "removed an absent capability\n" );
    ok( GetLastError() == 0x12345678,
        "absent capability removal changed last error to %lu\n", GetLastError() );

    SetLastError( 0x12345678 );
    ret = set_capability( hwnd, CAPABILITY_MESSAGE + 1, world.bytes, 0 );
    ok( ret, "failed to add a capability, error %lu\n", GetLastError() );
    ret = set_capability( hwnd, CAPABILITY_MESSAGE + 1, world.bytes, 0 );
    ok( ret, "failed to add a duplicate capability, error %lu\n", GetLastError() );
    ret = set_capability( hwnd, CAPABILITY_MESSAGE + 1, world.bytes, 1 );
    ok( ret, "failed to remove the first capability, error %lu\n", GetLastError() );
    ret = set_capability( hwnd, CAPABILITY_MESSAGE + 1, world.bytes, 2 );
    ok( ret, "failed to remove the duplicate capability with action 2, error %lu\n",
        GetLastError() );
    SetLastError( 0x12345678 );
    ret = set_capability( hwnd, CAPABILITY_MESSAGE + 1, world.bytes, ~0u );
    ok( !ret, "removed a capability after both entries were removed\n" );
    ok( GetLastError() == 0x12345678,
        "final capability removal changed last error to %lu\n", GetLastError() );

    capability_message_count = 0;
    if (!run_capability_sender( argv, hwnd, FALSE, TRUE )) goto destroy;
    ok( !capability_message_count, "received %u rejected capability messages\n",
        capability_message_count );

    SetLastError( 0x12345678 );
    ret = set_capability( hwnd, CAPABILITY_MESSAGE, world.bytes, 0 );
    ok( ret, "failed to grant the World SID, error %lu\n", GetLastError() );
    ok( GetLastError() == 0x12345678, "capability grant changed last error to %lu\n",
        GetLastError() );
    if (!run_capability_sender( argv, hwnd, TRUE, FALSE )) goto destroy;
    ok( capability_message_count == 1, "received %u granted capability messages\n",
        capability_message_count );

    SetLastError( 0x12345678 );
    ret = set_capability( hwnd, CAPABILITY_MESSAGE, world.bytes, 1 );
    ok( ret, "failed to remove the World SID, error %lu\n", GetLastError() );
    ok( GetLastError() == 0x12345678, "capability removal changed last error to %lu\n",
        GetLastError() );
    if (!run_capability_sender( argv, hwnd, TRUE, FALSE )) goto destroy;
    ok( capability_message_count == 2,
        "owner descriptor did not retain same-user access, count %u\n", capability_message_count );

destroy:
    stale = hwnd;
    DestroyWindow( hwnd );
    SetLastError( 0x12345678 );
    ret = set_capability( stale, CAPABILITY_MESSAGE, world.bytes, 0 );
    ok( !ret, "registered a capability on a stale window\n" );
    ok( GetLastError() == ERROR_INVALID_WINDOW_HANDLE,
        "stale-window registration returned error %lu\n", GetLastError() );
done:
    UnregisterClassW( cls.lpszClassName, cls.hInstance );
}

static HWND next_ordering_window( HWND hwnd, HWND shell, HWND peer, HWND later )
{
    unsigned int count = 0;

    while ((hwnd = GetWindow( hwnd, GW_HWNDNEXT )) && count++ < 256)
        if (hwnd == shell || hwnd == peer || hwnd == later) return hwnd;
    return NULL;
}

static void test_shell_bottommost( HWND shell )
{
    const UINT flags = SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE;
    const HWND requests[] = { HWND_TOP, HWND_TOPMOST, HWND_NOTOPMOST };
    HWND peer, later;
    unsigned int i;
    BOOL ret;

    peer = CreateWindowExA( 0, "#32770", "shell ordering peer", WS_OVERLAPPEDWINDOW,
                           0, 0, 100, 100, NULL, NULL, GetModuleHandleA( NULL ), NULL );
    ok( !!peer, "failed to create ordering peer, error %lu\n", GetLastError() );
    if (!peer) return;
    for (i = 0; i < ARRAY_SIZE(requests); ++i)
    {
        ret = SetWindowPos( shell, requests[i], 0, 0, 0, 0, flags );
        ok( ret, "shell order request %u failed, error %lu\n", i, GetLastError() );
        ok( next_ordering_window( peer, shell, peer, NULL ) == shell, "request %u raised the shell\n", i );
        ok( !(GetWindowLongW( shell, GWL_EXSTYLE ) & WS_EX_TOPMOST),
            "request %u made the shell topmost\n", i );
    }
    ret = SetWindowPos( peer, HWND_BOTTOM, 0, 0, 0, 0, flags );
    ok( ret, "peer bottom request failed, error %lu\n", GetLastError() );
    ok( next_ordering_window( peer, shell, peer, NULL ) == shell, "peer moved below the shell\n" );
    ret = SetWindowPos( peer, shell, 0, 0, 0, 0, flags );
    ok( ret, "peer after-shell request failed, error %lu\n", GetLastError() );
    ok( next_ordering_window( peer, shell, peer, NULL ) == shell, "peer insertion moved below the shell\n" );

    later = CreateWindowExA( 0, "#32770", "later ordering peer", WS_OVERLAPPEDWINDOW,
                            0, 0, 100, 100, NULL, NULL, GetModuleHandleA( NULL ), NULL );
    ok( !!later, "failed to create later ordering peer, error %lu\n", GetLastError() );
    if (later)
    {
        ok( next_ordering_window( later, shell, peer, later ) == peer, "new peer has incorrect order\n" );
        ret = SetWindowPos( later, HWND_BOTTOM, 0, 0, 0, 0, flags );
        ok( ret, "later bottom request failed, error %lu\n", GetLastError() );
        ok( next_ordering_window( peer, shell, peer, later ) == later, "later peer did not move below peer\n" );
        ok( next_ordering_window( later, shell, peer, later ) == shell, "later peer moved below shell\n" );
        ret = SetWindowPos( later, shell, 0, 0, 0, 0, flags );
        ok( ret, "later after-shell request failed, error %lu\n", GetLastError() );
        ok( next_ordering_window( later, shell, peer, later ) == shell, "later insertion moved below shell\n" );
        ret = SetWindowPos( shell, peer, 0, 0, 0, 0, flags );
        ok( ret, "shell after-peer request failed, error %lu\n", GetLastError() );
        ok( next_ordering_window( later, shell, peer, later ) == shell, "after-peer request raised shell\n" );
        DestroyWindow( later );
    }
    DestroyWindow( peer );
}

#define SHELL_NOTIFY_MESSAGE 0x0342

/* This fixture tests Wine's registered-shell role. The genuine Windows
 * notification payload is established separately by the native observer. */
static ULONGLONG shell_notification_records[8][10];
static unsigned int shell_notification_count;
static BOOL shell_notification_nested;
static unsigned int shell_ordinary_hotkey_count;
static WNDPROC shell_notification_original_proc;

static LRESULT CALLBACK shell_notification_proc( HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam )
{
    if (message == SHELL_NOTIFY_MESSAGE)
    {
        ULONGLONG before[10];
        MSG msg;
        ok( !wparam, "notification wparam is %#Ix\n", wparam );
        ok( !!lparam, "notification payload is null\n" );
        if (!lparam) return 0;
        memcpy( before, (void *)lparam, sizeof(before) );
        ok( shell_notification_count < ARRAY_SIZE(shell_notification_records), "notification overflow\n" );
        if (shell_notification_count < ARRAY_SIZE(shell_notification_records))
            memcpy( shell_notification_records[shell_notification_count++], before, sizeof(before) );
        if (shell_notification_nested)
        {
            shell_notification_nested = FALSE;
            PeekMessageW( &msg, NULL, 0, 0, PM_NOREMOVE );
            ok( !memcmp( before, (void *)lparam, sizeof(before) ), "nested receive changed outer payload\n" );
        }
        return 0;
    }
    return CallWindowProcW( shell_notification_original_proc, hwnd, message, wparam, lparam );
}

static void shell_notification_key( WORD key, BOOL release )
{
    INPUT input = {0};
    UINT ret;
    input.type = INPUT_KEYBOARD;
    input.ki.wVk = key;
    input.ki.dwFlags = release ? KEYEVENTF_KEYUP : 0;
    if (key == VK_LWIN || key == VK_RWIN) input.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
    ret = SendInput( 1, &input, sizeof(input) );
    ok( ret == 1, "SendInput key %#x release %u returned %u, error %lu\n", key, release, ret, GetLastError() );
}

static void shell_notification_pump(void)
{
    MSG msg;
    while (PeekMessageW( &msg, NULL, 0, 0, PM_REMOVE ))
    {
        if (msg.message == WM_HOTKEY && !msg.hwnd)
        {
            ok( msg.wParam == 0x1222, "ordinary hotkey id is %#Ix\n", msg.wParam );
            ok( msg.lParam == MAKELPARAM( MOD_ALT, VK_F24 ), "ordinary hotkey key is %#Ix\n", msg.lParam );
            shell_ordinary_hotkey_count++;
        }
        TranslateMessage( &msg );
        DispatchMessageW( &msg );
    }
}

static DWORD WINAPI shell_notification_forgery_thread( void *arg )
{
    HWND hwnd = arg;
    BOOL ret;
    SetLastError( 0xdeadbeef );
    ret = SendNotifyMessageW( hwnd, SHELL_NOTIFY_MESSAGE, 0, 0xdeadbeef );
    ok( !ret, "accepted forged asynchronous notification\n" );
    ok( GetLastError() == ERROR_ACCESS_DENIED, "forged notify error %lu\n", GetLastError() );
    SetLastError( 0xdeadbeef );
    ret = PostMessageW( hwnd, SHELL_NOTIFY_MESSAGE, 0, 0xdeadbeef );
    ok( !ret, "accepted forged posted notification\n" );
    ok( GetLastError() == ERROR_ACCESS_DENIED, "forged post error %lu\n", GetLastError() );
    return 0;
}

static void test_shell_hotkey_notifications( HWND hwnd, HDESK desktop )
{
    BOOL (WINAPI *shell_register_hot_key)(HWND, INT, UINT, UINT, HWND);
    HDESK original;
    HANDLE thread;
    unsigned int i, j;
    BOOL ret;

    if (strcmp( winetest_platform, "wine" )) return;
    shell_register_hot_key = (void *)GetProcAddress( GetModuleHandleA( "user32.dll" ), (const char *)2671 );
    original = OpenInputDesktop( 0, FALSE, DESKTOP_READOBJECTS | DESKTOP_SWITCHDESKTOP );
    ok( !!original, "failed to open input desktop, error %lu\n", GetLastError() );
    if (!original) return;
    ret = SwitchDesktop( desktop );
    ok( ret, "failed to select input desktop, error %lu\n", GetLastError() );
    if (!ret) goto done;
    shell_notification_original_proc = (WNDPROC)SetWindowLongPtrW( hwnd, GWLP_WNDPROC,
                                                                   (LONG_PTR)shell_notification_proc );
    ok( !!shell_notification_original_proc, "failed to set notification procedure\n" );
    ret = shell_register_hot_key( NULL, 1, MOD_WIN, 0, NULL );
    ok( ret, "Windows-only registration failed, error %lu\n", GetLastError() );
    ret = shell_register_hot_key( NULL, 2, MOD_CONTROL, VK_ESCAPE, NULL );
    ok( ret, "Ctrl+Esc registration failed, error %lu\n", GetLastError() );

    shell_notification_count = 0;
    thread = CreateThread( NULL, 0, shell_notification_forgery_thread, hwnd, 0, NULL );
    ok( !!thread, "failed to create forged notification sender\n" );
    if (thread)
    {
        ok( WaitForSingleObject( thread, 5000 ) == WAIT_OBJECT_0, "forgery sender did not finish\n" );
        CloseHandle( thread );
    }
    shell_notification_pump();
    ok( !shell_notification_count, "forged notification reached the callback\n" );
    shell_notification_key( VK_LWIN, FALSE );
    shell_notification_pump();
    ok( !shell_notification_count, "Windows key notified on key down\n" );
    shell_notification_key( VK_LWIN, TRUE );
    shell_notification_pump();
    ok( shell_notification_count == 1, "left release produced %u notifications\n", shell_notification_count );
    shell_notification_key( VK_RWIN, FALSE );
    shell_notification_key( VK_RWIN, TRUE );
    shell_notification_pump();
    ok( shell_notification_count == 2, "right release produced %u notifications\n", shell_notification_count );

    shell_notification_key( VK_LWIN, FALSE );
    shell_notification_key( VK_F24, FALSE );
    shell_notification_key( VK_F24, TRUE );
    shell_notification_key( VK_LWIN, TRUE );
    shell_notification_pump();
    ok( shell_notification_count == 2, "nonmodifier chord did not cancel release\n" );
    shell_notification_key( VK_CONTROL, FALSE );
    shell_notification_key( VK_ESCAPE, FALSE );
    shell_notification_pump();
    ok( shell_notification_count == 3, "Ctrl+Esc did not notify on Escape down\n" );
    shell_notification_key( VK_ESCAPE, TRUE );
    shell_notification_key( VK_CONTROL, TRUE );
    shell_notification_pump();
    ok( shell_notification_count == 3, "Ctrl+Esc release produced an extra notification\n" );
    for (i = 0; i < min( shell_notification_count, 3 ); i++)
    {
        ok( !shell_notification_records[i][0], "record %u has a context window\n", i );
        ok( shell_notification_records[i][1] == 13, "record %u kind is %I64u\n", i, shell_notification_records[i][1] );
        ok( shell_notification_records[i][2] == (i == 2 ? 2 : 1), "record %u id is %I64u\n", i, shell_notification_records[i][2] );
        ok( shell_notification_records[i][3] == (i == 2 ? 0x1b0002 : 8), "record %u key is %#I64x\n", i, shell_notification_records[i][3] );
        for (j = 4; j < 10; j++)
            ok( !shell_notification_records[i][j], "record %u field %u is %#I64x\n", i, j, shell_notification_records[i][j] );
    }

    shell_notification_nested = TRUE;
    shell_notification_key( VK_LWIN, FALSE );
    shell_notification_key( VK_LWIN, TRUE );
    shell_notification_key( VK_RWIN, FALSE );
    shell_notification_key( VK_RWIN, TRUE );
    shell_notification_pump();
    ok( shell_notification_count == 5, "nested receive produced %u notifications\n", shell_notification_count );
    ok( !shell_notification_nested, "nested callback was not exercised\n" );
    ret = UnregisterHotKey( NULL, 1 );
    ok( ret, "failed to unregister Windows-only hotkey\n" );
    ret = UnregisterHotKey( NULL, 2 );
    ok( ret, "failed to unregister Ctrl+Esc hotkey\n" );
    shell_notification_key( VK_LWIN, FALSE );
    shell_notification_key( VK_LWIN, TRUE );
    shell_notification_pump();
    ok( shell_notification_count == 5, "unregistered hotkey still notified\n" );
    shell_ordinary_hotkey_count = 0;
    ret = RegisterHotKey( NULL, 0x1222, MOD_ALT, VK_F24 );
    ok( ret, "ordinary hotkey registration failed, error %lu\n", GetLastError() );
    shell_notification_key( VK_MENU, FALSE );
    shell_notification_key( VK_F24, FALSE );
    shell_notification_key( VK_F24, TRUE );
    shell_notification_key( VK_MENU, TRUE );
    shell_notification_pump();
    ok( shell_ordinary_hotkey_count == 1, "ordinary hotkey count is %u\n", shell_ordinary_hotkey_count );
    ok( shell_notification_count == 5, "ordinary hotkey produced private notification\n" );
    ret = UnregisterHotKey( NULL, 0x1222 );
    ok( ret, "ordinary hotkey unregister failed\n" );
    SetWindowLongPtrW( hwnd, GWLP_WNDPROC, (LONG_PTR)shell_notification_original_proc );
    ret = SwitchDesktop( original );
    ok( ret, "failed to restore input desktop, error %lu\n", GetLastError() );
done:
    CloseDesktop( original );
}

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
    BOOL (WINAPI *enable_shell_window_management_behavior)(UINT, UINT);
    BOOL (WINAPI *shell_register_hot_key)(HWND, INT, UINT, UINT, HWND);
    ULONGLONG key, second_key;
    DWORD band;
    DPI_AWARENESS_CONTEXT dpi_context;
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
    enable_shell_window_management_behavior = (void *)GetProcAddress( user32, (const char *)2567 );
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
    ok( !!enable_shell_window_management_behavior,
        "EnableShellWindowManagementBehavior is unavailable\n" );
    ok( !!shell_register_hot_key, "ShellRegisterHotKey is unavailable\n" );
    if (!create_window_in_band || !get_shell_change_notify_window || !get_window_band ||
        !acquire_iam_key || !enable_iam_access || !set_shell_change_notify_window ||
        !set_shell_window || !set_active_process_for_monitor ||
        !register_window_arrangement_callout || !enable_shell_window_management_behavior ||
        !shell_register_hot_key)
        return 0;

    SetLastError( 0x13579bdf );
    ret = enable_shell_window_management_behavior( 0, 0 );
    ok( !ret, "enabled zero shell-window behavior without IAM access\n" );
    ok( GetLastError() == ERROR_ACCESS_DENIED,
        "zero behavior without IAM returned error %lu\n", GetLastError() );
    SetLastError( 0x13579bdf );
    ret = enable_shell_window_management_behavior( 0x800, 0x800 );
    ok( !ret, "enabled invalid shell-window behavior without IAM access\n" );
    ok( GetLastError() == ERROR_ACCESS_DENIED,
        "invalid behavior without IAM returned error %lu\n", GetLastError() );

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

    if (ret) test_shell_bottommost( hwnd );

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

    SetLastError( 0x13579bdf );
    ret = enable_shell_window_management_behavior( 0, 0 );
    ok( ret, "failed to retain zero behavior without a callout, error %lu\n", GetLastError() );
    ok( GetLastError() == 0x13579bdf,
        "zero behavior without a callout changed last error to %lu\n", GetLastError() );
    SetLastError( 0x13579bdf );
    ret = enable_shell_window_management_behavior( 1, 1 );
    ok( !ret, "enabled nonzero behavior without a callout\n" );
    ok( GetLastError() == ERROR_INVALID_STATE,
        "nonzero behavior without a callout returned error %lu\n", GetLastError() );
    SetLastError( 0x13579bdf );
    ret = enable_shell_window_management_behavior( 0x800, 0x800 );
    ok( !ret, "enabled a reserved shell-window behavior bit\n" );
    ok( GetLastError() == ERROR_INVALID_PARAMETER,
        "reserved behavior bit returned error %lu\n", GetLastError() );

    dpi_context = SetThreadDpiAwarenessContext( DPI_AWARENESS_CONTEXT_UNAWARE );
    ok( !!dpi_context, "failed to select DPI-unaware context, error %lu\n", GetLastError() );
    ordinary_message_hwnd = CreateWindowExA( 0, "static", "DPI-unaware message window", WS_POPUP,
                                              0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, NULL );
    ok( !!ordinary_message_hwnd, "failed to create DPI-unaware message window, error %lu\n",
        GetLastError() );
    ok( !!SetThreadDpiAwarenessContext( DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 ),
        "failed to select per-monitor-v2 context, error %lu\n", GetLastError() );
    arrangement_hwnd = CreateWindowExW( 0, L"static", L"arrangement callout", WS_POPUP,
                                        0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, NULL );
    ok( !!SetThreadDpiAwarenessContext( dpi_context ),
        "failed to restore DPI context, error %lu\n", GetLastError() );
    ok( !!arrangement_hwnd, "failed to create arrangement callout window, error %lu\n",
        GetLastError() );
    if (ordinary_message_hwnd)
    {
        SetLastError( 0x13579bdf );
        ret = register_window_arrangement_callout( ordinary_message_hwnd, TRUE );
        ok( !ret, "registered a DPI-unaware arrangement callout window\n" );
        ok( GetLastError() == ERROR_INVALID_PARAMETER,
            "DPI-unaware arrangement callout returned error %lu\n", GetLastError() );
    }

    if (arrangement_hwnd)
    {
        SetLastError( 0x13579bdf );
        ret = register_window_arrangement_callout( arrangement_hwnd, TRUE );
        ok( ret, "failed to register arrangement callout, error %lu\n", GetLastError() );
        ok( GetLastError() == 0x13579bdf,
            "arrangement callout registration changed last error to %lu\n", GetLastError() );

        SetLastError( 0x13579bdf );
        ret = enable_shell_window_management_behavior( 1, 1 );
        ok( ret, "failed to enable shell-window behavior bit 0, error %lu\n", GetLastError() );
        ok( GetLastError() == 0x13579bdf,
            "behavior bit 0 changed last error to %lu\n", GetLastError() );
        SetLastError( 0x13579bdf );
        ret = enable_shell_window_management_behavior( 2, 2 );
        ok( ret, "failed to merge shell-window behavior bit 1, error %lu\n", GetLastError() );
        ok( GetLastError() == 0x13579bdf,
            "behavior bit 1 changed last error to %lu\n", GetLastError() );
        ret = enable_shell_window_management_behavior( 1, 0 );
        ok( ret, "failed to clear shell-window behavior bit 0, error %lu\n", GetLastError() );
        ret = enable_shell_window_management_behavior( 1, 4 );
        ok( ret, "unmasked behavior value unexpectedly failed, error %lu\n", GetLastError() );
        SetLastError( 0x13579bdf );
        ret = enable_shell_window_management_behavior( 0x800, 0x800 );
        ok( !ret, "enabled a reserved behavior bit while registered\n" );
        ok( GetLastError() == ERROR_INVALID_PARAMETER,
            "registered reserved behavior bit returned error %lu\n", GetLastError() );

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

        test_shell_hotkey_notifications( arrangement_hwnd, desktop );

        ret = shell_register_hot_key( arrangement_hwnd, 0xf060, MOD_SHIFT, VK_F22, NULL );
        ok( ret, "failed to register arrangement callout hotkey, error %lu\n", GetLastError() );

        SetLastError( 0x13579bdf );
        ret = register_window_arrangement_callout( arrangement_hwnd, FALSE );
        ok( ret, "failed to unregister arrangement callout, error %lu\n", GetLastError() );
        ok( GetLastError() == 0x13579bdf,
            "arrangement callout unregister changed last error to %lu\n", GetLastError() );
        SetLastError( 0x13579bdf );
        ret = enable_shell_window_management_behavior( 0, 0 );
        ok( ret, "unregister did not clear shell-window behavior, error %lu\n", GetLastError() );
        ok( GetLastError() == 0x13579bdf,
            "post-unregister behavior query changed last error to %lu\n", GetLastError() );
        SetLastError( 0x13579bdf );
        ret = enable_shell_window_management_behavior( 1, 1 );
        ok( !ret, "enabled behavior after unregister\n" );
        ok( GetLastError() == ERROR_INVALID_STATE,
            "behavior after unregister returned error %lu\n", GetLastError() );
        ret = UnregisterHotKey( arrangement_hwnd, 0xf060 );
        ok( !ret, "arrangement callout unregister left its hotkey registered\n" );

        SetLastError( 0x13579bdf );
        ret = register_window_arrangement_callout( arrangement_hwnd, FALSE );
        ok( ret, "repeated arrangement callout unregister failed, error %lu\n", GetLastError() );
        ok( GetLastError() == 0x13579bdf,
            "repeated arrangement unregister changed last error to %lu\n", GetLastError() );

        ret = register_window_arrangement_callout( arrangement_hwnd, TRUE );
        ok( ret, "failed to re-register arrangement callout, error %lu\n", GetLastError() );
        ret = enable_shell_window_management_behavior( 4, 4 );
        ok( ret, "failed to enable behavior before destroying callout, error %lu\n",
            GetLastError() );
        ret = DestroyWindow( arrangement_hwnd );
        ok( ret, "failed to destroy arrangement callout, error %lu\n", GetLastError() );
        arrangement_hwnd = NULL;
        SetLastError( 0x13579bdf );
        ret = enable_shell_window_management_behavior( 0, 0 );
        ok( ret, "callout destruction did not clear shell-window behavior, error %lu\n",
            GetLastError() );
        ok( GetLastError() == 0x13579bdf,
            "post-destroy behavior query changed last error to %lu\n", GetLastError() );
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
    if (!strcmp( winetest_platform, "wine" ))
    {
        ret = enable_iam_access( key, TRUE );
        ok( ret, "failed to enable IAM before shell teardown\n" );
        DestroyWindow( hwnd );
        /* The client IAM bit survives shell teardown. The server must reject
         * registration once this process is no longer the desktop shell. */
        ret = shell_register_hot_key( NULL, 0xf070, MOD_SHIFT, VK_F21, NULL );
        ok( !ret, "stale client IAM access registered a private hotkey\n" );
        ret = UnregisterHotKey( NULL, 0xf070 );
        ok( !ret, "rejected private registration was retained\n" );
    }
    else DestroyWindow( hwnd );
    return 0;
}

START_TEST(shell)
{
    char **argv;
    int argc;
    HDESK desktop;
    HANDLE thread;

    argc = winetest_get_mainargs( &argv );
    if (argc == 6 && !strcmp( argv[2], "capability-child" ))
    {
        capability_sender_child( argv );
        return;
    }

    test_window_message_capability( argv );

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
