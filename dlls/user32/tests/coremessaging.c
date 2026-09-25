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

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include <windows.h>

#include "wine/test.h"
#include "winternl.h"

typedef HANDLE (WINAPI *init_thread_coremessaging_iocp_fn)( HWND );
typedef HANDLE (WINAPI *init_thread_coremessaging_iocp2_fn)( HWND, DWORD * );
typedef ULONG_PTR (WINAPI *drain_thread_coremessaging_completions_fn)(void);
typedef ULONG_PTR (WINAPI *drain_thread_coremessaging_completions2_fn)( HWND );
typedef NTSTATUS (WINAPI *nt_set_io_completion_fn)( HANDLE, ULONG_PTR, ULONG_PTR,
                                                    NTSTATUS, ULONG_PTR );
typedef NTSTATUS (WINAPI *nt_create_wait_completion_packet_fn)( HANDLE *, ACCESS_MASK,
                                                                OBJECT_ATTRIBUTES * );
typedef NTSTATUS (WINAPI *nt_associate_wait_completion_packet_fn)( HANDLE, HANDLE, HANDLE,
                                                                   void *, void *, NTSTATUS,
                                                                   ULONG_PTR, BOOLEAN * );

static const char window_class[] = "CoreMessagingTestWindow";

struct foreign_window_state
{
    HANDLE ready;
    HANDLE release;
    HWND hwnd;
};

struct core_messaging_completion
{
    struct core_messaging_completion *next;
    ULONG_PTR local_handle;
};

struct delayed_post_state
{
    HWND hwnd;
    HANDLE release;
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

static DWORD WINAPI delayed_post_thread( void *context )
{
    struct delayed_post_state *state = context;

    if (WaitForSingleObject( state->release, 1000 ) == WAIT_TIMEOUT)
        PostMessageA( state->hwnd, 0x60, 0xdead, 0xbeef );
    return 0;
}

static void test_init_thread_coremessaging_iocp2(void)
{
    init_thread_coremessaging_iocp_fn init_legacy;
    init_thread_coremessaging_iocp2_fn init;
    drain_thread_coremessaging_completions_fn drain_legacy;
    drain_thread_coremessaging_completions2_fn drain;
    nt_set_io_completion_fn set_io_completion;
    nt_create_wait_completion_packet_fn create_wait_completion_packet;
    nt_associate_wait_completion_packet_fn associate_wait_completion_packet;
    struct foreign_window_state foreign = {0};
    struct core_messaging_completion completion1 = {0}, completion2 = {0}, completion3 = {0};
    struct core_messaging_completion completion4 = {0}, completion5 = {0};
    struct delayed_post_state delayed_post = {0};
    void *completion_lists[3] = {0};
    WNDCLASSA cls = {0};
    HANDLE first, second, third, thread, delayed_thread, packet, timer;
    ULONG_PTR saved_completion_lists;
    HWND hwnd1, hwnd2, hwnd3, destroyed;
    DWORD mode, flags, error, wait_ret, queue_status;
    ULONG_PTR drain_ret;
    NTSTATUS status;
    MSG msg;
    BOOL ret;

    init_legacy = (void *)GetProcAddress( GetModuleHandleA( "user32.dll" ), MAKEINTRESOURCEA( 2612 ));
    init = (void *)GetProcAddress( GetModuleHandleA( "user32.dll" ), MAKEINTRESOURCEA( 2669 ));
    drain_legacy = (void *)GetProcAddress( GetModuleHandleA( "user32.dll" ), MAKEINTRESOURCEA( 2613 ));
    drain = (void *)GetProcAddress( GetModuleHandleA( "user32.dll" ), MAKEINTRESOURCEA( 2670 ));
    set_io_completion = (void *)GetProcAddress( GetModuleHandleA( "ntdll.dll" ),
                                                "NtSetIoCompletion" );
    create_wait_completion_packet = (void *)GetProcAddress( GetModuleHandleA( "ntdll.dll" ),
                                                            "NtCreateWaitCompletionPacket" );
    associate_wait_completion_packet = (void *)GetProcAddress( GetModuleHandleA( "ntdll.dll" ),
                                                               "NtAssociateWaitCompletionPacket" );
    if (!init_legacy || !init || !drain_legacy || !drain)
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
    hwnd3 = CreateWindowExA( 0, window_class, "", 0, 0, 0, 0, 0,
                             HWND_MESSAGE, NULL, cls.hInstance, NULL );
    ok( !!hwnd1 && !!hwnd2 && !!hwnd3, "Failed to create test windows, error %lu.\n",
        GetLastError() );

    while (PeekMessageA( &msg, hwnd1, WM_APP + 0x60, WM_APP + 0x60, PM_REMOVE )) {}
    while (PeekMessageA( &msg, hwnd2, WM_APP + 0x60, WM_APP + 0x60, PM_REMOVE )) {}
    GetQueueStatus( QS_POSTMESSAGE | QS_ALLPOSTMESSAGE );
    ok( PostMessageA( hwnd2, WM_APP + 0x60, 0x666, 0 ), "Failed to post test message.\n" );
    ret = PeekMessageA( &msg, hwnd1, 0, 0, PM_REMOVE | PM_NOYIELD );
    ok( !ret, "Window-filtered peek unexpectedly returned message %#x for %p.\n",
        msg.message, msg.hwnd );
    queue_status = GetQueueStatus( QS_POSTMESSAGE | QS_ALLPOSTMESSAGE );
    ok( HIWORD(queue_status) == (QS_POSTMESSAGE | QS_ALLPOSTMESSAGE),
        "Expected unchanged posted-message status, got %#lx.\n", queue_status );
    ok( !LOWORD(queue_status), "Expected cleared new-message status, got %#lx.\n", queue_status );
    ret = PeekMessageA( &msg, hwnd2, WM_APP + 0x60, WM_APP + 0x60,
                        PM_REMOVE | PM_NOYIELD );
    ok( ret && msg.wParam == 0x666,
        "Expected retained test message, got %d message %#x parameters %Ix/%Ix.\n",
        ret, msg.message, msg.wParam, msg.lParam );

    SetLastError( 0xdeadbeef );
    drain_ret = drain_legacy();
    ok( !drain_ret, "Unregistered legacy drain returned %Ix.\n", drain_ret );
    ok( GetLastError() == ERROR_ACCESS_DENIED, "Expected error 5, got %lu.\n", GetLastError() );

    SetLastError( 0xdeadbeef );
    drain_ret = drain( NULL );
    ok( !drain_ret, "NULL window returned %Ix.\n", drain_ret );
    ok( GetLastError() == ERROR_INVALID_WINDOW_HANDLE, "Expected error 1400, got %lu.\n", GetLastError() );

    SetLastError( 0xdeadbeef );
    drain_ret = drain( hwnd1 );
    ok( !drain_ret, "Unregistered window returned %Ix.\n", drain_ret );
    ok( GetLastError() == ERROR_INVALID_WINDOW_HANDLE, "Expected error 1400, got %lu.\n", GetLastError() );

    SetLastError( 0xdeadbeef );
    first = init_legacy( hwnd1 );
    ok( !!first, "First registration failed, error %lu.\n", GetLastError() );
    ok( GetLastError() == 0xdeadbeef, "Expected unchanged error, got %lu.\n", GetLastError() );

    SetLastError( 0xdeadbeef );
    drain_ret = drain( hwnd1 );
    ok( drain_ret == TRUE, "Registered window returned %Ix.\n", drain_ret );
    ok( GetLastError() == 0xdeadbeef, "Expected unchanged error, got %lu.\n", GetLastError() );

    SetLastError( 0xdeadbeef );
    drain_ret = drain( hwnd2 );
    ok( !drain_ret, "Unregistered second window returned %Ix.\n", drain_ret );
    ok( GetLastError() == ERROR_INVALID_WINDOW_HANDLE, "Expected error 1400, got %lu.\n", GetLastError() );

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

    SetLastError( 0xdeadbeef );
    second = init_legacy( hwnd2 );
    ok( !second, "Second legacy registration returned %p.\n", second );
    ok( GetLastError() == ERROR_ALREADY_INITIALIZED, "Expected error 1247, got %lu.\n",
        GetLastError() );

    SetLastError( 0xdeadbeef );
    drain_ret = drain( hwnd2 );
    ok( !drain_ret, "Failed legacy registration retained window, returned %Ix.\n", drain_ret );
    ok( GetLastError() == ERROR_INVALID_WINDOW_HANDLE, "Expected error 1400, got %lu.\n",
        GetLastError() );

    mode = 0xcccccccc;
    SetLastError( 0xdeadbeef );
    third = init( hwnd2, &mode );
    ok( third == first, "Expected shared port %p, got %p.\n", first, third );
    ok( mode == 1, "Expected subsequent mode 1, got %#lx.\n", mode );
    ok( GetLastError() == 0xdeadbeef, "Expected unchanged error, got %lu.\n", GetLastError() );

    mode = 0xcccccccc;
    SetLastError( 0xdeadbeef );
    second = init( hwnd3, &mode );
    ok( !second, "Third registration returned %p.\n", second );
    ok( mode == 0xcccccccc, "Third registration changed mode to %#lx.\n", mode );
    ok( GetLastError() == ERROR_ALREADY_REGISTERED, "Expected error 1242, got %lu.\n",
        GetLastError() );

    SetLastError( 0xdeadbeef );
    drain_ret = drain( hwnd2 );
    ok( drain_ret == TRUE, "Registered second window returned %Ix.\n", drain_ret );
    ok( GetLastError() == 0xdeadbeef, "Expected unchanged error, got %lu.\n", GetLastError() );

    if (set_io_completion)
    {
        saved_completion_lists = NtCurrentTeb()->Win32ClientInfo[61];
        NtCurrentTeb()->Win32ClientInfo[61] = (ULONG_PTR)completion_lists;

        while (PeekMessageA( &msg, hwnd1, 0x60, 0x60, PM_REMOVE )) {}
        completion4.local_handle = 0x4444;
        status = set_io_completion( first, (ULONG_PTR)&completion4, 0,
                                    STATUS_SUCCESS, 0 );
        ok( status == STATUS_SUCCESS, "NtSetIoCompletion failed, status %#lx.\n", status );
        wait_ret = MsgWaitForMultipleObjectsEx( 0, NULL, 1000, QS_POSTMESSAGE, 0 );
        ok( wait_ret == WAIT_OBJECT_0, "Message wait returned %#lx.\n", wait_ret );
        ok( completion_lists[1] == &completion4,
            "Expected completion4 at head, got %p.\n", completion_lists[1] );
        ok( PeekMessageA( &msg, hwnd1, 0x60, 0x60, PM_REMOVE ),
            "Expected a CoreMessaging message-wait notification.\n" );
        ok( msg.wParam == 1 && !msg.lParam, "Unexpected notification parameters %Ix/%Ix.\n",
            msg.wParam, msg.lParam );
        completion_lists[1] = NULL;

        if (create_wait_completion_packet && associate_wait_completion_packet)
        {
            OBJECT_ATTRIBUTES attr;
            LARGE_INTEGER due = {{0}};
            BOOLEAN already_signaled;
            unsigned int cycle;

            InitializeObjectAttributes( &attr, NULL, 0, NULL, NULL );
            packet = NULL;
            status = create_wait_completion_packet( &packet, GENERIC_ALL, &attr );
            ok( status == STATUS_SUCCESS, "NtCreateWaitCompletionPacket failed, status %#lx.\n",
                status );
            timer = CreateWaitableTimerExW( NULL, NULL, CREATE_WAITABLE_TIMER_MANUAL_RESET,
                                            TIMER_ALL_ACCESS );
            ok( !!timer, "CreateWaitableTimerExW failed, error %lu.\n", GetLastError() );

            for (cycle = 0; packet && timer && cycle < 2; ++cycle)
            {
                completion4.next = NULL;
                completion4.local_handle = 0x4444 + cycle;
                already_signaled = 0xcc;
                status = associate_wait_completion_packet( packet, first, timer,
                                                            &completion4, 0,
                                                            STATUS_SUCCESS, cycle,
                                                            &already_signaled );
                ok( status == STATUS_SUCCESS,
                    "Cycle %u NtAssociateWaitCompletionPacket failed, status %#lx.\n",
                    cycle, status );
                ok( already_signaled == (cycle != 0),
                    "Cycle %u returned already-signaled %u.\n", cycle, already_signaled );
                ret = SetWaitableTimer( timer, &due, 0, NULL, NULL, FALSE );
                ok( ret, "Cycle %u SetWaitableTimer failed, error %lu.\n", cycle,
                    GetLastError() );
                wait_ret = MsgWaitForMultipleObjectsEx( 0, NULL, 1000, QS_POSTMESSAGE, 0 );
                ok( wait_ret == WAIT_OBJECT_0, "Cycle %u message wait returned %#lx.\n",
                    cycle, wait_ret );
                ok( completion_lists[1] == &completion4,
                    "Cycle %u expected timer completion at head, got %p.\n",
                    cycle, completion_lists[1] );
                ok( PeekMessageA( &msg, hwnd1, 0x60, 0x60, PM_REMOVE ),
                    "Cycle %u expected a CoreMessaging notification.\n", cycle );
                completion_lists[1] = NULL;
            }
            if (timer) CloseHandle( timer );
            if (packet) CloseHandle( packet );
        }
        else win_skip( "Wait completion packet exports are not available.\n" );

        while (PeekMessageA( &msg, hwnd1, 0x60, 0x60, PM_REMOVE )) {}
        completion5.local_handle = 0x5555;
        status = set_io_completion( first, (ULONG_PTR)&completion5, 0,
                                    STATUS_SUCCESS, 0 );
        ok( status == STATUS_SUCCESS, "NtSetIoCompletion failed, status %#lx.\n", status );
        delayed_post.hwnd = hwnd1;
        delayed_post.release = CreateEventA( NULL, TRUE, FALSE, NULL );
        delayed_thread = CreateThread( NULL, 0, delayed_post_thread, &delayed_post, 0, NULL );
        ok( !!delayed_post.release && !!delayed_thread,
            "Failed to create delayed post thread, error %lu.\n", GetLastError() );
        ret = GetMessageA( &msg, hwnd1, 0x60, 0x60 );
        ok( ret, "GetMessage failed, error %lu.\n", GetLastError() );
        ok( msg.wParam == 1 && !msg.lParam,
            "Expected a CoreMessaging GetMessage notification, got %Ix/%Ix.\n",
            msg.wParam, msg.lParam );
        ok( completion_lists[1] == &completion5,
            "Expected completion5 at head, got %p.\n", completion_lists[1] );
        SetEvent( delayed_post.release );
        WaitForSingleObject( delayed_thread, INFINITE );
        CloseHandle( delayed_thread );
        CloseHandle( delayed_post.release );
        while (PeekMessageA( &msg, hwnd1, 0x60, 0x60, PM_REMOVE )) {}
        if (completion_lists[1] != &completion5) drain( hwnd1 );
        completion_lists[1] = NULL;

        completion1.local_handle = 0x1111;
        completion2.local_handle = 0x2222;
        status = set_io_completion( first, (ULONG_PTR)&completion1, 0,
                                    STATUS_SUCCESS, 0 );
        ok( status == STATUS_SUCCESS, "NtSetIoCompletion failed, status %#lx.\n", status );
        status = set_io_completion( first, (ULONG_PTR)&completion2, 0,
                                    STATUS_SUCCESS, 0 );
        ok( status == STATUS_SUCCESS, "NtSetIoCompletion failed, status %#lx.\n", status );
        drain_ret = drain( hwnd1 );
        ok( drain_ret == TRUE, "Completion drain returned %Ix.\n", drain_ret );
        ok( completion_lists[1] == &completion2, "Expected completion2 at head, got %p.\n",
            completion_lists[1] );
        ok( completion2.next == &completion1, "Expected completion1 next, got %p.\n",
            completion2.next );
        ok( !completion1.next, "Expected a null tail, got %p.\n", completion1.next );
        completion_lists[1] = NULL;

        while (PeekMessageA( &msg, hwnd1, 0x60, 0x60, PM_REMOVE )) {}
        completion1.next = NULL;
        status = set_io_completion( first, (ULONG_PTR)&completion1, 0,
                                    STATUS_SUCCESS, 0 );
        ok( status == STATUS_SUCCESS, "NtSetIoCompletion failed, status %#lx.\n", status );
        GetQueueStatus( QS_POSTMESSAGE );
        ok( completion_lists[1] == &completion1,
            "Expected queue-status completion at head, got %p.\n", completion_lists[1] );
        ok( !completion1.next, "Expected a null queue-status tail, got %p.\n",
            completion1.next );
        ok( PeekMessageA( &msg, hwnd1, 0x60, 0x60, PM_REMOVE ),
            "Expected a queue-status CoreMessaging notification.\n" );
        ok( msg.wParam == 1 && !msg.lParam, "Unexpected notification parameters %Ix/%Ix.\n",
            msg.wParam, msg.lParam );
        completion_lists[1] = NULL;

        completion1.next = NULL;
        completion2.next = NULL;
        status = set_io_completion( first, (ULONG_PTR)&completion1, 0,
                                    STATUS_SUCCESS, 0 );
        ok( status == STATUS_SUCCESS, "NtSetIoCompletion failed, status %#lx.\n", status );
        status = set_io_completion( first, (ULONG_PTR)&completion2, 0,
                                    STATUS_SUCCESS, 0 );
        ok( status == STATUS_SUCCESS, "NtSetIoCompletion failed, status %#lx.\n", status );
        SetLastError( 0xdeadbeef );
        drain_ret = drain_legacy();
        ok( drain_ret == TRUE, "Legacy completion drain returned %Ix.\n", drain_ret );
        ok( GetLastError() == 0xdeadbeef, "Expected unchanged error, got %lu.\n",
            GetLastError() );
        ok( completion_lists[1] == &completion2, "Expected completion2 at head, got %p.\n",
            completion_lists[1] );
        ok( completion2.next == &completion1, "Expected completion1 next, got %p.\n",
            completion2.next );
        ok( !completion1.next, "Expected a null tail, got %p.\n", completion1.next );
        completion_lists[1] = NULL;

        while (PeekMessageA( &msg, hwnd2, 0x60, 0x60, PM_REMOVE )) {}
        completion3.local_handle = 0x3333;
        status = set_io_completion( first, (ULONG_PTR)&completion3, 1,
                                    STATUS_SUCCESS, 0 );
        ok( status == STATUS_SUCCESS, "NtSetIoCompletion failed, status %#lx.\n", status );
        drain_ret = drain( hwnd1 );
        ok( drain_ret == TRUE, "Cross-context completion drain returned %Ix.\n", drain_ret );
        ok( completion_lists[2] == &completion3, "Expected completion3 at head, got %p.\n",
            completion_lists[2] );
        ok( PeekMessageA( &msg, hwnd2, 0x60, 0x60, PM_REMOVE ),
            "Expected a CoreMessaging notification.\n" );
        ok( msg.wParam == 1 && !msg.lParam, "Unexpected notification parameters %Ix/%Ix.\n",
            msg.wParam, msg.lParam );

        NtCurrentTeb()->Win32ClientInfo[61] = saved_completion_lists;
    }
    else win_skip( "NtSetIoCompletion is not available.\n" );

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
    DestroyWindow( hwnd3 );
    DestroyWindow( hwnd2 );
    DestroyWindow( hwnd1 );
}

START_TEST(coremessaging)
{
    test_init_thread_coremessaging_iocp2();
}
