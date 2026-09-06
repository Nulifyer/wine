/*
 * CoreMessaging USER tests
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

typedef HANDLE (WINAPI *init_thread_coremessaging_iocp2_fn)( HWND, DWORD * );

static const char window_class[] = "CoreMessagingTestWindow";

struct foreign_window_state
{
    HANDLE ready;
    HANDLE release;
    HWND hwnd;
};

static LRESULT CALLBACK window_proc( HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam )
{
    return DefWindowProcA( hwnd, message, wparam, lparam );
}

static DWORD WINAPI foreign_window_thread( void *context )
{
    struct foreign_window_state *state = context;

    state->hwnd = CreateWindowExA( 0, window_class, "", 0, 0, 0, 0, 0,
                                   HWND_MESSAGE, NULL, GetModuleHandleA( NULL ), NULL );
    SetEvent( state->ready );
    WaitForSingleObject( state->release, INFINITE );
    if (state->hwnd) DestroyWindow( state->hwnd );
    return 0;
}

static void test_init_thread_coremessaging_iocp2(void)
{
    init_thread_coremessaging_iocp2_fn init;
    struct foreign_window_state foreign = {0};
    WNDCLASSA cls = {0};
    HANDLE first, second, third, thread;
    HWND hwnd1, hwnd2, destroyed;
    DWORD mode, flags, error;
    BOOL ret;

    init = (void *)GetProcAddress( GetModuleHandleA( "user32.dll" ), MAKEINTRESOURCEA( 2669 ));
    if (!init)
    {
        win_skip( "InitThreadCoreMessagingIocp2 is not available.\n" );
        return;
    }

    cls.lpfnWndProc = window_proc;
    cls.hInstance = GetModuleHandleA( NULL );
    cls.lpszClassName = window_class;
    ok( RegisterClassA( &cls ), "RegisterClassA failed, error %lu.\n", GetLastError() );

    hwnd1 = CreateWindowExA( 0, window_class, "", 0, 0, 0, 0, 0,
                             HWND_MESSAGE, NULL, cls.hInstance, NULL );
    hwnd2 = CreateWindowExA( 0, window_class, "", 0, 0, 0, 0, 0,
                             HWND_MESSAGE, NULL, cls.hInstance, NULL );
    ok( !!hwnd1 && !!hwnd2, "Failed to create test windows, error %lu.\n", GetLastError() );

    mode = 0xcccccccc;
    SetLastError( 0xdeadbeef );
    first = init( hwnd1, &mode );
    ok( !!first, "First registration failed, error %lu.\n", GetLastError() );
    ok( mode == 0, "Expected first mode 0, got %#lx.\n", mode );
    ok( GetLastError() == 0xdeadbeef, "Expected unchanged error, got %lu.\n", GetLastError() );

    flags = 0;
    ret = GetHandleInformation( first, &flags );
    ok( ret, "GetHandleInformation failed, error %lu.\n", GetLastError() );
    ok( flags == HANDLE_FLAG_PROTECT_FROM_CLOSE, "Expected protected handle, got flags %#lx.\n", flags );

    mode = 0xcccccccc;
    SetLastError( 0xdeadbeef );
    second = init( hwnd1, &mode );
    ok( !second, "Duplicate registration returned %p.\n", second );
    ok( mode == 0xcccccccc, "Duplicate registration changed mode to %#lx.\n", mode );
    ok( GetLastError() == ERROR_INVALID_PARAMETER, "Expected error 87, got %lu.\n", GetLastError() );

    mode = 0xcccccccc;
    SetLastError( 0xdeadbeef );
    third = init( hwnd2, &mode );
    ok( third == first, "Expected shared port %p, got %p.\n", first, third );
    ok( mode == 1, "Expected subsequent mode 1, got %#lx.\n", mode );
    ok( GetLastError() == 0xdeadbeef, "Expected unchanged error, got %lu.\n", GetLastError() );

    SetLastError( 0xdeadbeef );
    ret = CloseHandle( first );
    error = GetLastError();
    ok( !ret, "Protected completion port was closed.\n" );
    ok( error == ERROR_INVALID_HANDLE, "Expected error 6, got %lu.\n", error );

    foreign.ready = CreateEventA( NULL, TRUE, FALSE, NULL );
    foreign.release = CreateEventA( NULL, TRUE, FALSE, NULL );
    thread = CreateThread( NULL, 0, foreign_window_thread, &foreign, 0, NULL );
    ok( !!foreign.ready && !!foreign.release && !!thread,
        "Failed to create foreign-window thread, error %lu.\n", GetLastError() );
    WaitForSingleObject( foreign.ready, INFINITE );

    mode = 0xcccccccc;
    SetLastError( 0xdeadbeef );
    second = init( foreign.hwnd, &mode );
    ok( !second, "Foreign-thread registration returned %p.\n", second );
    ok( mode == 0xcccccccc, "Foreign-thread registration changed mode to %#lx.\n", mode );
    ok( GetLastError() == ERROR_ACCESS_DENIED, "Expected error 5, got %lu.\n", GetLastError() );

    destroyed = CreateWindowExA( 0, window_class, "", 0, 0, 0, 0, 0,
                                  HWND_MESSAGE, NULL, cls.hInstance, NULL );
    DestroyWindow( destroyed );
    mode = 0xcccccccc;
    SetLastError( 0xdeadbeef );
    second = init( destroyed, &mode );
    ok( !second, "Destroyed-window registration returned %p.\n", second );
    ok( mode == 0xcccccccc, "Destroyed-window registration changed mode to %#lx.\n", mode );
    ok( GetLastError() == ERROR_INVALID_WINDOW_HANDLE, "Expected error 1400, got %lu.\n", GetLastError() );

    mode = 0xcccccccc;
    SetLastError( 0xdeadbeef );
    second = init( NULL, &mode );
    ok( !second, "NULL-window registration returned %p.\n", second );
    ok( mode == 0xcccccccc, "NULL-window registration changed mode to %#lx.\n", mode );
    ok( GetLastError() == ERROR_INVALID_WINDOW_HANDLE, "Expected error 1400, got %lu.\n", GetLastError() );

    SetEvent( foreign.release );
    WaitForSingleObject( thread, INFINITE );
    CloseHandle( thread );
    CloseHandle( foreign.release );
    CloseHandle( foreign.ready );
    DestroyWindow( hwnd2 );
    DestroyWindow( hwnd1 );
}

START_TEST(coremessaging)
{
    test_init_thread_coremessaging_iocp2();
}
