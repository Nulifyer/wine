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
#include <winternl.h>

#include "wine/test.h"

typedef HANDLE (WINAPI *init_thread_coremessaging_iocp2_fn)( HWND, DWORD * );
typedef ULONG_PTR (WINAPI *drain_thread_coremessaging_completions2_fn)( HWND );
typedef INT (WINAPI *schedule_dispatch_notification_fn)( HWND );
typedef NTSTATUS (WINAPI *create_wait_completion_packet_fn)( HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES * );
typedef NTSTATUS (WINAPI *associate_wait_completion_packet_fn)( HANDLE, HANDLE, HANDLE, void *, void *,
                                                                 NTSTATUS, ULONG_PTR, BOOLEAN * );

static const char window_class[] = "CoreMessagingTestWindow";
static HWND first_window, second_window;
static unsigned int first_dispatches, second_dispatches;
static unsigned int first_completions, second_completions;
static LPARAM last_completion;
static WPARAM last_dispatch_wparam;
static LPARAM last_dispatch_lparam;

struct foreign_window_state
{
    HANDLE ready;
    HANDLE release;
    HWND hwnd;
};

static LRESULT CALLBACK window_proc( HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam )
{
    if (message == 0x0060)
    {
        last_dispatch_wparam = wparam;
        last_dispatch_lparam = lparam;
        if (hwnd == first_window)
        {
            first_dispatches++;
            if (wparam == 8) first_completions++;
        }
        if (hwnd == second_window)
        {
            second_dispatches++;
            if (wparam == 8) second_completions++;
        }
        if (wparam == 8) last_completion = lparam;
    }
    return DefWindowProcA( hwnd, message, wparam, lparam );
}

static void wait_and_pump_messages(void)
{
    UINT_PTR timer;
    MSG message;

    timer = SetTimer( NULL, 0, 100, NULL );
    ok( !!timer, "SetTimer failed, error %lu.\n", GetLastError() );
    while (GetMessageA( &message, NULL, 0, 0 ) > 0)
    {
        if (!message.hwnd && message.message == WM_TIMER && message.wParam == timer) break;
        TranslateMessage( &message );
        DispatchMessageA( &message );
    }
    KillTimer( NULL, timer );
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
    drain_thread_coremessaging_completions2_fn drain;
    schedule_dispatch_notification_fn schedule;
    create_wait_completion_packet_fn create_packet;
    associate_wait_completion_packet_fn associate_packet;
    struct foreign_window_state foreign = {0};
    WNDCLASSA cls = {0};
    HANDLE first, second, third, thread, packet, event;
    void *wake_node[2], *core_data[4], **client_data, *saved_client_data;
    HWND hwnd1, hwnd2, destroyed;
    DWORD mode, flags, error, bytes, wait_ret;
    ULONG_PTR drain_ret, key;
    OVERLAPPED *overlapped;
    BOOLEAN already_signaled;
    NTSTATUS status;
    BOOL ret;

    init = (void *)GetProcAddress( GetModuleHandleA( "user32.dll" ), MAKEINTRESOURCEA( 2669 ));
    drain = (void *)GetProcAddress( GetModuleHandleA( "user32.dll" ), MAKEINTRESOURCEA( 2670 ));
    schedule = (void *)GetProcAddress( GetModuleHandleA( "user32.dll" ), MAKEINTRESOURCEA( 2582 ));
    create_packet = (void *)GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtCreateWaitCompletionPacket" );
    associate_packet = (void *)GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtAssociateWaitCompletionPacket" );
    if (!init || !drain || !schedule || !create_packet || !associate_packet)
    {
        win_skip( "CoreMessaging thread integration exports are not available.\n" );
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
    first_window = hwnd1;
    second_window = hwnd2;
    ok( !!hwnd1 && !!hwnd2, "Failed to create test windows, error %lu.\n", GetLastError() );

    first_dispatches = 0;
    ret = schedule( hwnd1 );
    ok( ret == 2, "ScheduleDispatchNotification returned %d.\n", ret );
    wait_and_pump_messages();
    ok( first_dispatches == 1, "Expected one dispatch, got %u.\n", first_dispatches );

    SetLastError( 0xdeadbeef );
    drain_ret = drain( NULL );
    ok( !drain_ret, "NULL window returned %Ix.\n", drain_ret );
    ok( GetLastError() == ERROR_INVALID_WINDOW_HANDLE, "Expected error 1400, got %lu.\n", GetLastError() );

    SetLastError( 0xdeadbeef );
    drain_ret = drain( hwnd1 );
    ok( !drain_ret, "Unregistered window returned %Ix.\n", drain_ret );
    ok( GetLastError() == ERROR_ACCESS_DENIED, "Expected error 5, got %lu.\n", GetLastError() );

    mode = 0xcccccccc;
    SetLastError( 0xdeadbeef );
    first = init( hwnd1, &mode );
    ok( !!first, "First registration failed, error %lu.\n", GetLastError() );
    ok( mode == 0, "Expected first mode 0, got %#lx.\n", mode );
    ok( GetLastError() == 0xdeadbeef, "Expected unchanged error, got %lu.\n", GetLastError() );

    SetLastError( 0xdeadbeef );
    drain_ret = drain( hwnd1 );
    ok( drain_ret == TRUE, "Registered window returned %Ix.\n", drain_ret );
    ok( GetLastError() == 0xdeadbeef, "Expected unchanged error, got %lu.\n", GetLastError() );

    saved_client_data = (void *)NtCurrentTeb()->Win32ClientInfo[61];
    memset( core_data, 0, sizeof(core_data) );
    NtCurrentTeb()->Win32ClientInfo[61] = (ULONG_PTR)core_data;
    client_data = (void **)NtCurrentTeb()->Win32ClientInfo[61];
    wake_node[0] = (void *)0xdeadbeef;
    wake_node[1] = (void *)0x12345678;
    packet = NULL;
    status = create_packet( &packet, GENERIC_ALL, NULL );
    ok( !status, "NtCreateWaitCompletionPacket returned %#lx.\n", status );
    event = CreateEventW( NULL, TRUE, FALSE, NULL );
    ok( !!event, "CreateEventW failed, error %lu.\n", GetLastError() );
    status = associate_packet( packet, first, event, wake_node, NULL, 0, 0, NULL );
    ok( !status, "NtAssociateWaitCompletionPacket returned %#lx.\n", status );
    SetEvent( event );
    drain_ret = drain( hwnd1 );
    ok( drain_ret == TRUE, "Registered window returned %Ix.\n", drain_ret );
    ok( client_data[1] == wake_node, "Expected queue head %p, got %p.\n",
        wake_node, client_data[1] );
    ok( !wake_node[0], "Expected a null next node, got %p.\n", wake_node[0] );
    ok( wake_node[1] == (void *)0x12345678, "Completion payload changed to %p.\n",
        wake_node[1] );
    NtCurrentTeb()->Win32ClientInfo[61] = (ULONG_PTR)saved_client_data;
    CloseHandle( event );
    CloseHandle( packet );

    packet = NULL;
    status = create_packet( &packet, GENERIC_ALL, NULL );
    ok( !status, "NtCreateWaitCompletionPacket returned %#lx.\n", status );
    event = CreateEventW( NULL, TRUE, FALSE, NULL );
    ok( !!event, "CreateEventW failed, error %lu.\n", GetLastError() );
    already_signaled = 0xcc;
    status = associate_packet( packet, first, event, (void *)0x1111, NULL,
                               0, 0x3333, &already_signaled );
    ok( !status, "NtAssociateWaitCompletionPacket returned %#lx.\n", status );
    ok( !already_signaled, "Expected an unsignaled association, got %u.\n", already_signaled );

    first_dispatches = second_dispatches = 0;
    first_completions = second_completions = 0;
    last_completion = 0;
    last_dispatch_wparam = ~(WPARAM)0;
    last_dispatch_lparam = ~(LPARAM)0;
    SetEvent( event );
    wait_and_pump_messages();
    ok( first_dispatches == 1 && !second_dispatches,
        "Expected one registered-window dispatch, got %u and %u.\n",
        first_dispatches, second_dispatches );
    ok( !first_completions && !second_completions,
        "Expected no subtype-8 completion, got %u and %u.\n",
        first_completions, second_completions );
    ok( last_dispatch_wparam == 3 && !last_dispatch_lparam,
        "Expected null-context dispatch 3, 0; got %Ix, %Ix.\n",
        (ULONG_PTR)last_dispatch_wparam, (ULONG_PTR)last_dispatch_lparam );

    SetLastError( 0xdeadbeef );
    ret = GetQueuedCompletionStatus( first, &bytes, &key, &overlapped, 0 );
    ok( !ret, "Wait completion remained queued.\n" );
    ok( GetLastError() == WAIT_TIMEOUT, "Expected error 258, got %lu.\n", GetLastError() );
    CloseHandle( event );
    CloseHandle( packet );

    SetLastError( 0xdeadbeef );
    drain_ret = drain( hwnd2 );
    ok( !drain_ret, "Unregistered second window returned %Ix.\n", drain_ret );
    ok( GetLastError() == ERROR_INVALID_PARAMETER, "Expected error 87, got %lu.\n", GetLastError() );

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

    first_dispatches = second_dispatches = 0;
    first_completions = second_completions = 0;
    last_completion = 0;
    SetLastError( 0xdeadbeef );
    ret = PostQueuedCompletionStatus( first, 0x1234, 0x5678,
                                      (OVERLAPPED *)(ULONG_PTR)0x9abc );
    ok( ret, "PostQueuedCompletionStatus failed, error %lu.\n", GetLastError() );
    wait_and_pump_messages();
    ok( first_dispatches == 1 && second_dispatches == 1,
        "Expected one dispatch per window, got %u and %u.\n",
        first_dispatches, second_dispatches );
    ok( first_completions == 1 && second_completions == 1,
        "Expected one completion per window, got %u and %u.\n",
        first_completions, second_completions );
    ok( last_completion == 0x9abc, "Expected completion context 0x9abc, got %Ix.\n",
        (ULONG_PTR)last_completion );

    SetLastError( 0xdeadbeef );
    ret = GetQueuedCompletionStatus( first, &bytes, &key, &overlapped, 0 );
    ok( !ret, "CoreMessaging completion remained queued.\n" );
    ok( GetLastError() == WAIT_TIMEOUT, "Expected error 258, got %lu.\n", GetLastError() );

    first_dispatches = second_dispatches = 0;
    first_completions = second_completions = 0;
    last_dispatch_wparam = ~(WPARAM)0;
    last_dispatch_lparam = ~(LPARAM)0;
    SetLastError( 0xdeadbeef );
    ret = PostQueuedCompletionStatus( first, 0x4321, 0x8765, NULL );
    ok( ret, "PostQueuedCompletionStatus failed, error %lu.\n", GetLastError() );
    wait_and_pump_messages();
    ok( first_dispatches == 1 && !second_dispatches,
        "Expected one primary-window null-context dispatch, got %u and %u.\n",
        first_dispatches, second_dispatches );
    ok( !first_completions && !second_completions,
        "Expected no subtype-8 completion, got %u and %u.\n",
        first_completions, second_completions );
    ok( last_dispatch_wparam == 3 && !last_dispatch_lparam,
        "Expected null-context dispatch 3, 0; got %Ix, %Ix.\n",
        (ULONG_PTR)last_dispatch_wparam, (ULONG_PTR)last_dispatch_lparam );

    SetLastError( 0xdeadbeef );
    ret = GetQueuedCompletionStatus( first, &bytes, &key, &overlapped, 0 );
    ok( !ret, "Null-context completion remained queued.\n" );
    ok( GetLastError() == WAIT_TIMEOUT, "Expected error 258, got %lu.\n", GetLastError() );

    first_dispatches = second_dispatches = 0;
    first_completions = second_completions = 0;
    last_completion = 0;
    SetLastError( 0xdeadbeef );
    ret = PostQueuedCompletionStatus( first, 0x1112, 0x2223,
                                      (OVERLAPPED *)(ULONG_PTR)0x3334 );
    ok( ret, "PostQueuedCompletionStatus failed, error %lu.\n", GetLastError() );
    wait_ret = MsgWaitForMultipleObjectsEx( 0, NULL, 1000, QS_ALLINPUT, MWMO_INPUTAVAILABLE );
    ok( wait_ret == WAIT_OBJECT_0, "CoreMessaging wait returned %#lx.\n", wait_ret );
    drain_ret = drain( hwnd1 );
    ok( drain_ret == TRUE, "Registered first window returned %Ix.\n", drain_ret );
    wait_and_pump_messages();
    ok( first_dispatches == 1 && second_dispatches == 1,
        "Expected drain to retain both window dispatches, got %u and %u.\n",
        first_dispatches, second_dispatches );
    ok( first_completions == 1 && second_completions == 1,
        "Expected drain to retain both completions, got %u and %u.\n",
        first_completions, second_completions );
    ok( last_completion == 0x3334, "Expected completion context 0x3334, got %Ix.\n",
        (ULONG_PTR)last_completion );

    SetLastError( 0xdeadbeef );
    ret = GetQueuedCompletionStatus( first, &bytes, &key, &overlapped, 0 );
    ok( !ret, "Drained CoreMessaging completion remained queued.\n" );
    ok( GetLastError() == WAIT_TIMEOUT, "Expected error 258, got %lu.\n", GetLastError() );

    SetLastError( 0xdeadbeef );
    drain_ret = drain( hwnd2 );
    ok( drain_ret == TRUE, "Registered second window returned %Ix.\n", drain_ret );
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
