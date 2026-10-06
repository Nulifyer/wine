/*
 * DirectComposition syscall tests
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "ntstatus.h"
#define WIN32_NO_STATUS

#include "wine/test.h"

#include "winbase.h"
#include "wingdi.h"
#include "winuser.h"
#include "winternl.h"
#include "ntgdi.h"
#include "ntuser.h"

#define DESKTOP_ALL_ACCESS 0x01ff

struct kst_test
{
    BOOL update;
    BOOL initialized;
    DWORD initialize_error;
    UINT reason;
    UINT stop_reason;
};

static BOOL WINAPI input_notification_callback( void *message )
{
    return message != NULL;
}

static DWORD WINAPI manipulation_thread( void *arg )
{
    SetLastError( 0xdeadbeef );
    if (!NtUserRegisterManipulationThread( arg )) return 1;
    return GetLastError() == 0xdeadbeef ? 0 : 2;
}

struct coremsg_message
{
    ALPC_PORT_MESSAGE header;
    unsigned char data[296];
};

struct dwm_session_message
{
    ALPC_PORT_MESSAGE header;
    DWORD data[64];
};

struct dwm_shell_thread_context
{
    HDESK desktop;
    HANDLE ready;
    HANDLE repaint;
    HANDLE repainted;
    HANDLE release;
    HWND window;
    BOOL desktop_selected;
    BOOL shell_registered;
    DWORD error;
};

struct coremsg_registrar_context
{
    unsigned char guid[16];
    NTSTATUS status;
};

struct token_thread_context
{
    struct token_manager_thread_info info;
    NTSTATUS status;
};

struct dcomp_test_protocol_list
{
    struct
    {
        void *next;
        void *previous;
    } head;
    struct
    {
        void *next;
        void *previous;
        UINT type;
        UINT size;
        BYTE data[8];
    } block;
};

static void check_dcomp_batch_payload( const struct dcomposition_connection_batch *record,
                                       UINT channel, const UINT *expected, UINT expected_size,
                                       const char *context );

static void init_dcomp_test_protocol_list( struct dcomp_test_protocol_list *list )
{
    static const UINT command[] = {8, 0x24};

    memset( list, 0, sizeof(*list) );
    list->head.next = &list->block;
    list->head.previous = &list->block;
    list->block.next = &list->head;
    list->block.previous = &list->head;
    list->block.type = 0x200;
    list->block.size = sizeof(list->block.data);
    memcpy( list->block.data, command, sizeof(command) ); /* Valid no-handle MIL command. */
}

static DWORD WINAPI token_thread( void *arg )
{
    struct token_thread_context *context = arg;

    context->status = NtTokenManagerThread( &context->info );
    return 0;
}

static void init_alpc_attributes( ALPC_PORT_ATTRIBUTES *attributes )
{
    memset( attributes, 0, sizeof(*attributes) );
    attributes->SecurityQos.Length = sizeof(attributes->SecurityQos);
    attributes->SecurityQos.ImpersonationLevel = SecurityIdentification;
    attributes->SecurityQos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
    attributes->MaxMessageLength = 0x400;
}

static void put_u32( unsigned char *data, DWORD value )
{
    memcpy( data, &value, sizeof(value) );
}

static DWORD WINAPI dwm_shell_thread( void *arg )
{
    struct dwm_shell_thread_context *context = arg;
    HANDLE events[2];

    context->desktop_selected = SetThreadDesktop( context->desktop );
    if (context->desktop_selected)
    {
        context->window = CreateWindowExA( WS_EX_NOREDIRECTIONBITMAP, "static",
                                            "DWM shell window", WS_POPUP | WS_VISIBLE,
                                            0, 0, 64, 64, NULL, NULL, NULL, NULL );
        if (context->window)
            context->shell_registered = NtUserSetShellWindowEx( context->window,
                                                                  context->window );
    }
    context->error = GetLastError();
    SetEvent( context->ready );
    events[0] = context->repaint;
    events[1] = context->release;
    if (WaitForMultipleObjects( ARRAY_SIZE(events), events, FALSE, 5000 ) == WAIT_OBJECT_0)
    {
        RedrawWindow( context->window, NULL, NULL,
                      RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_UPDATENOW );
        SetEvent( context->repainted );
        WaitForSingleObject( context->release, 5000 );
    }
    if (context->window) DestroyWindow( context->window );
    return 0;
}

static DWORD WINAPI coremsg_registrar_client( void *arg )
{
    static const WCHAR name_buffer[] = L"\\BaseNamedObjects\\CoreMessagingRegistrar";
    UNICODE_STRING name = RTL_CONSTANT_STRING(name_buffer);
    struct coremsg_registrar_context *context = arg;
    ALPC_PORT_ATTRIBUTES attributes;
    struct coremsg_message request = {0}, reply = {0};
    HANDLE port = NULL;
    SIZE_T size;

    init_alpc_attributes( &attributes );
    context->status = NtAlpcConnectPort( &port, &name, NULL, &attributes,
                                         ALPC_SYNC_CONNECTION, NULL, NULL, NULL,
                                         NULL, NULL, NULL );
    if (context->status) return context->status;

    request.header.DataLength = 132;
    request.header.TotalLength = sizeof(request.header) + request.header.DataLength;
    put_u32( request.data + 16, 2 );
    put_u32( request.data + 20, 0x42 );
    put_u32( request.data + 24, 0x10000 );
    put_u32( request.data + 32, 92 );
    put_u32( request.data + 40, 23 );
    request.data[44] = 1;
    request.data[46] = 12;
    put_u32( request.data + 48, sizeof(L"Kernel\\MIT\\InputPort") );
    memcpy( request.data + 52, L"Kernel\\MIT\\InputPort", sizeof(L"Kernel\\MIT\\InputPort") );
    put_u32( request.data + 96, 24 );
    put_u32( request.data + 100, 1 );
    put_u32( request.data + 124, 4 );
    put_u32( request.data + 128, 1 );
    size = sizeof(reply);
    context->status = NtAlpcSendWaitReceivePort( port, ALPC_MSGFLG_SYNC_REQUEST,
                                                 &request.header, NULL, &reply.header,
                                                 &size, NULL, NULL );
    if (!context->status && (reply.header.DataLength != 108 || reply.data[20] != 0x42 ||
                             reply.data[44] || reply.data[46] != 15 ||
                             !reply.data[60]))
        context->status = STATUS_INVALID_MESSAGE;
    if (!context->status) memcpy( context->guid, reply.data + 92, sizeof(context->guid) );
    NtClose( port );
    return context->status;
}

static BOOL query_coremsg_kernel_guid( unsigned char guid[16] )
{
    static const WCHAR name_buffer[] = L"\\BaseNamedObjects\\CoreMessagingRegistrar";
    UNICODE_STRING name = RTL_CONSTANT_STRING(name_buffer);
    struct coremsg_registrar_context context = {0};
    ALPC_PORT_ATTRIBUTES attributes;
    OBJECT_ATTRIBUTES object_attributes;
    struct coremsg_message connection = {0};
    HANDLE listener = NULL, server = NULL, thread = NULL;
    NTSTATUS status;
    SIZE_T size;
    BOOL ret = FALSE;

    init_alpc_attributes( &attributes );
    InitializeObjectAttributes( &object_attributes, &name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    status = NtAlpcCreatePort( &listener, &object_attributes, &attributes );
    ok( !status, "registrar listener creation returned %#lx\n", status );
    if (status) goto done;

    thread = CreateThread( NULL, 0, coremsg_registrar_client, &context, 0, NULL );
    ok( !!thread, "failed to create registrar client, error %lu\n", GetLastError() );
    if (!thread) goto done;

    size = sizeof(connection);
    status = NtAlpcSendWaitReceivePort( listener, 0, NULL, NULL, &connection.header,
                                        &size, NULL, NULL );
    ok( !status, "registrar connection receive returned %#lx\n", status );
    ok( !status && (connection.header.Type & 0xff) == ALPC_MESSAGE_TYPE_CONNECTION_REQUEST,
        "unexpected registrar connection type %#x\n", connection.header.Type );
    if (status || (connection.header.Type & 0xff) != ALPC_MESSAGE_TYPE_CONNECTION_REQUEST)
        goto done;

    status = NtAlpcAcceptConnectPort( &server, listener, 0, NULL, &attributes, NULL,
                                      &connection.header, NULL, TRUE );
    ok( !status, "registrar connection accept returned %#lx\n", status );
    if (status) goto done;

    ok( WaitForSingleObject( thread, 5000 ) == WAIT_OBJECT_0,
        "registrar client did not finish\n" );
    ok( !context.status, "registrar lookup returned %#lx\n", context.status );
    if (!context.status)
    {
        memcpy( guid, context.guid, sizeof(context.guid) );
        ret = TRUE;
    }

done:
    if (thread) CloseHandle( thread );
    if (server) NtClose( server );
    if (listener) NtClose( listener );
    return ret;
}

static void make_coremsg_listener_name( const unsigned char guid[16], WCHAR name[80] )
{
    static const WCHAR prefix[] = L"\\BaseNamedObjects\\[CoreMsgK]-";
    static const WCHAR hex[] = L"0123456789abcdef";
    static const unsigned char order[16] = {3,2,1,0,5,4,7,6,8,9,10,11,12,13,14,15};
    unsigned int i, pos = ARRAY_SIZE(prefix) - 1;

    memcpy( name, prefix, sizeof(prefix) );
    name[pos++] = '{';
    for (i = 0; i < ARRAY_SIZE(order); ++i)
    {
        name[pos++] = hex[guid[order[i]] >> 4];
        name[pos++] = hex[guid[order[i]] & 0x0f];
        if (i == 3 || i == 5 || i == 7 || i == 9) name[pos++] = '-';
    }
    name[pos++] = '}';
    name[pos] = 0;
}

static NTSTATUS connect_coremsg_kernel_listener( const unsigned char guid[16], BOOL send_params,
                                                 HANDLE *port )
{
    struct
    {
        ALPC_PORT_MESSAGE header;
        unsigned char params[24];
    } connection = {0};
    ALPC_PORT_ATTRIBUTES attributes;
    WCHAR name_buffer[80];
    UNICODE_STRING name;
    SIZE_T size = sizeof(connection);
    NTSTATUS status;

    *port = NULL;
    make_coremsg_listener_name( guid, name_buffer );
    RtlInitUnicodeString( &name, name_buffer );
    init_alpc_attributes( &attributes );
    connection.header.DataLength = sizeof(connection.params);
    connection.header.TotalLength = sizeof(connection);
    status = NtAlpcConnectPort( port, &name, NULL, &attributes, 0, NULL,
                                send_params ? &connection.header : NULL,
                                send_params ? &size : NULL, NULL, NULL, NULL );
    return status;
}

static void coremsg_selector_child( DWORD pid, DWORD tid, UINT selector )
{
    unsigned char routing_info[40] = {0};
    NTSTATUS status;

    memcpy( routing_info, &pid, sizeof(pid) );
    memcpy( routing_info + 4, &tid, sizeof(tid) );
    status = NtMITCoreMsgKOpenConnectionTo( selector, routing_info );
    ok( status == STATUS_SUCCESS, "child got selector status %#lx\n", status );
}

static BOOL run_coremsg_selector_child( DWORD pid, DWORD tid, UINT selector )
{
    STARTUPINFOA startup = {sizeof(startup)};
    PROCESS_INFORMATION info = {0};
    char cmdline[2 * MAX_PATH], **argv;
    DWORD exit_code = 0xdeadbeef;

    winetest_get_mainargs( &argv );
    sprintf( cmdline, "%s dcomp coremsg_selector_child %lx %lx %x", argv[0], pid, tid, selector );
    ok( CreateProcessA( NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &info ),
        "failed to create selector child, error %lu\n", GetLastError() );
    if (!info.hProcess) return FALSE;

    ok( WaitForSingleObject( info.hProcess, 5000 ) == WAIT_OBJECT_0,
        "selector child did not exit\n" );
    ok( GetExitCodeProcess( info.hProcess, &exit_code ) && !exit_code,
        "selector child exit code %lu\n", exit_code );
    CloseHandle( info.hThread );
    CloseHandle( info.hProcess );
    return !exit_code;
}

static void test_input_registration(void)
{
    unsigned char routing_info[40] = {0};
    unsigned char guid[16];
    HANDLE coremsg_port, thread;
    DWORD pid = GetCurrentProcessId(), tid = GetCurrentThreadId();
    DWORD exit_code;
    NTSTATUS status;

    if (!winetest_platform_is_wine)
    {
        win_skip( "private ISM/WIN32U registration behavior is Wine-specific\n" );
        return;
    }

    status = NtMITCoreMsgKOpenConnectionTo( 23, routing_info );
    ok( status == STATUS_INVALID_PARAMETER, "got out-of-range selector status %#lx\n", status );
    status = NtMITCoreMsgKOpenConnectionTo( 0, NULL );
    ok( status == STATUS_INVALID_PARAMETER, "got null-routing status %#lx\n", status );
    status = NtMITCoreMsgKOpenConnectionTo( 0, routing_info );
    ok( status == STATUS_NOT_FOUND, "got pre-registration status %#lx\n", status );

    SetLastError( 0xdeadbeef );
    ok( NtMITSetInputCallbacks( input_notification_callback ), "failed to register input callback\n" );
    ok( GetLastError() == 0xdeadbeef, "input callback registration changed last error to %lu\n",
        GetLastError() );
    status = NtMITCoreMsgKOpenConnectionTo( 0, routing_info );
    ok( status == STATUS_UNSUCCESSFUL, "got unmatched-routing status %#lx\n", status );

    if (query_coremsg_kernel_guid( guid ))
    {
        status = connect_coremsg_kernel_listener( guid, FALSE, &coremsg_port );
        ok( status == STATUS_INVALID_PARAMETER,
            "parameterless kernel listener connection returned %#lx\n", status );
        status = connect_coremsg_kernel_listener( guid, TRUE, &coremsg_port );
        ok( !status, "kernel listener connection returned %#lx\n", status );
        if (status) goto done_input_registration;

        memcpy( routing_info, &pid, sizeof(pid) );
        memcpy( routing_info + 4, &tid, sizeof(tid) );
        status = NtMITCoreMsgKOpenConnectionTo( 0, routing_info );
        ok( status == STATUS_SUCCESS, "got connection status %#lx\n", status );
        status = NtMITCoreMsgKOpenConnectionTo( 0, routing_info );
        ok( status == STATUS_ALREADY_REGISTERED, "got duplicate selector status %#lx\n", status );
        status = NtMITCoreMsgKOpenConnectionTo( 22, routing_info );
        ok( status == STATUS_SUCCESS, "got boundary selector status %#lx\n", status );

        if (run_coremsg_selector_child( pid, tid, 7 ))
        {
            status = NtMITCoreMsgKOpenConnectionTo( 7, routing_info );
            ok( status == STATUS_SUCCESS, "selector survived owner teardown, status %#lx\n", status );
        }

        NtClose( coremsg_port );
        status = NtMITCoreMsgKOpenConnectionTo( 1, routing_info );
        ok( status == STATUS_UNSUCCESSFUL, "got disconnected-routing status %#lx\n", status );
    }
done_input_registration:
    ok( NtMITSetInputCallbacks( NULL ), "failed to clear input callback\n" );
    status = NtMITCoreMsgKOpenConnectionTo( 1, routing_info );
    ok( status == STATUS_UNSUCCESSFUL, "got post-callback routing status %#lx\n", status );

    SetLastError( 0xdeadbeef );
    ok( NtUserRegisterManipulationThread( NULL ), "failed to register current manipulation thread\n" );
    ok( GetLastError() == 0xdeadbeef, "manipulation registration changed last error to %lu\n",
        GetLastError() );

    thread = CreateThread( NULL, 0, manipulation_thread, (void *)0x1234, 0, NULL );
    ok( !!thread, "failed to create manipulation thread, error %lu\n", GetLastError() );
    if (!thread) return;
    ok( WaitForSingleObject( thread, 5000 ) == WAIT_OBJECT_0, "manipulation thread did not exit\n" );
    ok( GetExitCodeThread( thread, &exit_code ) && !exit_code,
        "got manipulation thread exit code %lu\n", exit_code );
    CloseHandle( thread );
}

static DWORD WINAPI kst_thread( void *arg )
{
    struct kst_test *test = arg;
    HANDLE events[2];

    events[0] = CreateEventW( NULL, FALSE, FALSE, NULL );
    events[1] = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!events[0] && !!events[1], "failed to create KST events, error %lu\n", GetLastError() );
    if (!events[0] || !events[1]) return 1;

    SetLastError( 0xdeadbeef );
    test->initialized = NtKSTInitialize( events[0], events[1] );
    test->initialize_error = GetLastError();
    if (test->initialized)
    {
        ok( SetEvent( events[test->update] ), "failed to signal KST event, error %lu\n", GetLastError() );
        test->reason = NtKSTWait();
        if (test->update)
        {
            ok( SetEvent( events[0] ), "failed to signal KST stop event, error %lu\n", GetLastError() );
            test->stop_reason = NtKSTWait();
        }
    }
    CloseHandle( events[1] );
    CloseHandle( events[0] );
    return 0;
}

static void test_kst(void)
{
    struct kst_test test;
    HANDLE thread;
    DWORD exit_code;
    UINT reason;

    SetLastError( 0xdeadbeef );
    reason = NtKSTWait();
    ok( reason == 1, "got uninitialized KST reason %u\n", reason );
    ok( GetLastError() == ERROR_INVALID_STATE, "got uninitialized KST error %lu\n", GetLastError() );

    SetLastError( 0xdeadbeef );
    ok( !NtKSTInitialize( NULL, NULL ), "KST initialize unexpectedly accepted null events\n" );
    ok( GetLastError() == ERROR_INVALID_HANDLE, "got null-event KST error %lu\n", GetLastError() );

    memset( &test, 0xcc, sizeof(test) );
    test.update = FALSE;
    thread = CreateThread( NULL, 0, kst_thread, &test, 0, NULL );
    ok( !!thread, "failed to create KST stop thread, error %lu\n", GetLastError() );
    if (thread)
    {
        ok( WaitForSingleObject( thread, 5000 ) == WAIT_OBJECT_0, "KST stop thread did not exit\n" );
        ok( GetExitCodeThread( thread, &exit_code ) && !exit_code, "got KST stop exit code %lu\n", exit_code );
        CloseHandle( thread );
        ok( test.initialized, "KST stop initialize failed, error %lu\n", test.initialize_error );
        ok( test.initialize_error == 0xdeadbeef, "KST stop changed last error to %lu\n", test.initialize_error );
        ok( test.reason == 0, "got KST stop reason %u\n", test.reason );
    }

    memset( &test, 0xcc, sizeof(test) );
    test.update = TRUE;
    thread = CreateThread( NULL, 0, kst_thread, &test, 0, NULL );
    ok( !!thread, "failed to create KST update thread, error %lu\n", GetLastError() );
    if (thread)
    {
        ok( WaitForSingleObject( thread, 5000 ) == WAIT_OBJECT_0, "KST update thread did not exit\n" );
        ok( GetExitCodeThread( thread, &exit_code ) && !exit_code, "got KST update exit code %lu\n", exit_code );
        CloseHandle( thread );
        ok( test.initialized, "KST update initialize failed, error %lu\n", test.initialize_error );
        ok( test.initialize_error == 0xdeadbeef, "KST update changed last error to %lu\n", test.initialize_error );
        ok( test.reason == 2, "got KST update reason %u\n", test.reason );
        ok( test.stop_reason == 0, "got KST post-update stop reason %u\n", test.stop_reason );
    }
}

static void test_frame_statistics(void)
{
    struct dcomposition_frame_statistics statistics, second;
    struct dcomposition_capability_info capabilities;
    LARGE_INTEGER before, after, frequency;
    NTSTATUS status;

    memset( &statistics, 0xcc, sizeof(statistics) );
    memset( &capabilities, 0xcc, sizeof(capabilities) );
    QueryPerformanceFrequency( &frequency );
    QueryPerformanceCounter( &before );
    SetLastError( 0xdeadbeef );
    status = NtDCompositionGetFrameStatistics( &statistics, &capabilities );
    QueryPerformanceCounter( &after );

    ok( status == STATUS_SUCCESS, "got status %#lx\n", status );
    ok( GetLastError() == 0xdeadbeef, "got last error %lu\n", GetLastError() );
    ok( statistics.current_time.QuadPart >= before.QuadPart,
        "current time %s predates call %s\n", wine_dbgstr_longlong(statistics.current_time.QuadPart),
        wine_dbgstr_longlong(before.QuadPart) );
    ok( statistics.current_time.QuadPart <= after.QuadPart,
        "current time %s follows call %s\n", wine_dbgstr_longlong(statistics.current_time.QuadPart),
        wine_dbgstr_longlong(after.QuadPart) );
    ok( statistics.time_frequency.QuadPart == frequency.QuadPart,
        "got frequency %s, expected %s\n", wine_dbgstr_longlong(statistics.time_frequency.QuadPart),
        wine_dbgstr_longlong(frequency.QuadPart) );
    ok( statistics.current_composition_rate.numerator > 1,
        "got rate numerator %u\n", statistics.current_composition_rate.numerator );
    ok( statistics.current_composition_rate.denominator == 1,
        "got rate denominator %u\n", statistics.current_composition_rate.denominator );
    ok( statistics.last_frame_time.QuadPart <= statistics.current_time.QuadPart,
        "last frame %s follows current time %s\n", wine_dbgstr_longlong(statistics.last_frame_time.QuadPart),
        wine_dbgstr_longlong(statistics.current_time.QuadPart) );
    ok( statistics.next_estimated_frame_time.QuadPart > statistics.current_time.QuadPart,
        "next frame %s does not follow current time %s\n",
        wine_dbgstr_longlong(statistics.next_estimated_frame_time.QuadPart),
        wine_dbgstr_longlong(statistics.current_time.QuadPart) );
    ok( !capabilities.values[0], "capability 0 is %#x\n", capabilities.values[0] );
    ok( !capabilities.values[1], "capability 1 is %#x\n", capabilities.values[1] );
    ok( !capabilities.values[2], "WARP capability is %#x\n", capabilities.values[2] );
    ok( capabilities.values[3] == 1, "effects-supported capability is %#x\n",
        capabilities.values[3] );
    ok( !capabilities.values[4], "capability 4 is %#x\n", capabilities.values[4] );

    Sleep( 30 );
    memset( &second, 0xcc, sizeof(second) );
    status = NtDCompositionGetFrameStatistics( &second, NULL );
    ok( status == STATUS_SUCCESS, "got status %#lx\n", status );
    ok( second.current_time.QuadPart > statistics.current_time.QuadPart,
        "second current time %s did not advance from %s\n", wine_dbgstr_longlong(second.current_time.QuadPart),
        wine_dbgstr_longlong(statistics.current_time.QuadPart) );

    status = NtDCompositionGetFrameStatistics( NULL, &capabilities );
    ok( status == STATUS_INVALID_PARAMETER, "got null-output status %#lx\n", status );
}

static void test_composition_input_sink(void)
{
    BYTE descriptor[0x128] = {0};
    BYTE queue[0x38] = {0};
    HANDLE sink = NULL, duplicate = NULL, implicit = NULL;
    LUID luid = {0}, duplicate_luid = {0}, drop_target_luid = {0};
    UINT view_id = 0xdeadbeef;
    NTSTATUS status;

    *(UINT *)descriptor = sizeof(descriptor);
    status = NtCreateCompositionInputSink( NULL, &sink );
    ok( status == STATUS_INVALID_PARAMETER, "expected STATUS_INVALID_PARAMETER, got %#lx\n", status );
    status = NtCreateCompositionInputSink( descriptor, NULL );
    ok( status == STATUS_INVALID_PARAMETER, "expected STATUS_INVALID_PARAMETER, got %#lx\n", status );

    *(UINT *)(descriptor + 8) = 5;
    status = NtCreateCompositionInputSink( descriptor, &sink );
    ok( status == STATUS_INVALID_PARAMETER, "expected STATUS_INVALID_PARAMETER, got %#lx\n", status );
    *(UINT *)(descriptor + 8) = 2;

    status = NtCreateCompositionInputSink( descriptor, &sink );
    ok( !status, "NtCreateCompositionInputSink returned %#lx\n", status );
    ok( !!sink, "expected a composition input sink handle\n" );
    status = NtQueryCompositionInputSinkLuid( sink, &luid );
    ok( !status, "NtQueryCompositionInputSinkLuid returned %#lx\n", status );
    ok( luid.LowPart || luid.HighPart, "expected a nonzero input sink LUID\n" );
    status = NtQueryCompositionInputSinkViewId( sink, &view_id );
    ok( !status, "NtQueryCompositionInputSinkViewId returned %#lx\n", status );
    ok( !view_id, "expected view id 0, got %u\n", view_id );

    status = NtCompositionSetDropTarget( sink, NULL, NULL );
    ok( status == STATUS_INVALID_PARAMETER, "expected STATUS_INVALID_PARAMETER, got %#lx\n", status );
    *(UINT *)queue = 4;
    status = NtCompositionSetDropTarget( sink, queue, NULL );
    ok( status == STATUS_INVALID_PARAMETER, "expected STATUS_INVALID_PARAMETER, got %#lx\n", status );
    *(UINT *)queue = 1;
    status = NtCompositionSetDropTarget( sink, queue, &drop_target_luid );
    ok( !status, "NtCompositionSetDropTarget returned %#lx\n", status );
    ok( !memcmp( &luid, &drop_target_luid, sizeof(luid) ), "drop target returned a different LUID\n" );

    status = NtDuplicateObject( GetCurrentProcess(), sink, GetCurrentProcess(), &duplicate,
                                0, 0, DUPLICATE_SAME_ACCESS );
    ok( !status, "NtDuplicateObject returned %#lx\n", status );
    status = NtQueryCompositionInputSinkLuid( duplicate, &duplicate_luid );
    ok( !status, "duplicate LUID query returned %#lx\n", status );
    ok( !memcmp( &luid, &duplicate_luid, sizeof(luid) ), "duplicate changed the sink LUID\n" );
    memset( queue, 0, sizeof(queue) );
    status = NtCompositionSetDropTarget( duplicate, queue, NULL );
    ok( !status, "drop-target replacement through duplicate returned %#lx\n", status );

    status = NtCreateImplicitCompositionInputSink( descriptor, &implicit );
    ok( !status, "NtCreateImplicitCompositionInputSink returned %#lx\n", status );
    if (implicit) NtCloseCompositionInputSink( implicit );
    if (duplicate) NtCloseCompositionInputSink( duplicate );
    if (sink) NtCloseCompositionInputSink( sink );
}

static void test_connection_lifetime(void)
{
    struct dcomposition_connection_batch *record = (void *)0xdeadbeef;
    HANDLE event, connection = (HANDLE)0xdeadbeef;
    UINT64 cookie = 0;
    NTSTATUS status;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "CreateEventW failed, error %lu\n", GetLastError() );
    if (!event) return;

    status = NtDCompositionCreateConnection( FALSE, event, &connection );
    ok( status == STATUS_SUCCESS, "got status %#lx\n", status );
    ok( connection && connection != (HANDLE)0xdeadbeef, "got connection %p\n", connection );
    ok( connection != event, "connection unexpectedly aliases work event %p\n", event );

    CloseHandle( event );
    if (!status)
    {
        status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
        ok( status == STATUS_ACCESS_DENIED, "got ordinary queue status %#lx\n", status );
        ok( !record, "ordinary queue returned %p\n", record );
        status = NtDCompositionDestroyConnection( connection );
        ok( status == STATUS_SUCCESS, "got destroy status %#lx\n", status );
        status = NtDCompositionDestroyConnection( connection );
        ok( status == STATUS_INVALID_HANDLE, "got second destroy status %#lx\n", status );
    }
}

static void test_channel_lifetime(void)
{
    struct dcomp_test_protocol_list protocol_list;
    BYTE *buffer = (BYTE *)0xdeadbeef, *second_buffer = (BYTE *)0xdeadbeef;
    HANDLE internal_event = NULL;
    UINT size = 0x1000, second_size = 0x1000;
    UINT channel = 0xcccccccc, second_channel = 0xcccccccc;
    ULONG processed;
    BYTE released, state;
    UINT batch, selector;
    NTSTATUS status;
    unsigned int i;
    static const UINT flag_values[] = {0x10, 0x80, 0x90, 0xffffffff};

    init_dcomp_test_protocol_list( &protocol_list );

    SetLastError( 0xdeadbeef );
    status = NtDCompositionCreateChannel( &channel, &size, (void **)&buffer, 0 );
    ok( status == STATUS_SUCCESS, "got status %#lx\n", status );
    ok( GetLastError() == 0xdeadbeef, "got last error %lu\n", GetLastError() );
    ok( channel && channel != 0xcccccccc, "got channel %#x\n", channel );
    ok( size == 0x1000, "got section size %u\n", size );
    ok( buffer && buffer != (BYTE *)0xdeadbeef, "got buffer %p\n", buffer );
    if (status) return;
    for (i = 0; i < 32; ++i) ok( !buffer[i], "buffer byte %u is %#x\n", i, buffer[i] );
    status = NtDCompositionSetChannelConnectionId( channel, 0, 1 );
    ok( status == STATUS_ACCESS_DENIED, "got bind-without-DWM status %#lx\n", status );

    for (selector = 0; selector < 4; ++selector)
    {
        batch = 0xcccccccc;
        status = NtDCompositionGetBatchId( channel, selector, &batch );
        ok( status == STATUS_SUCCESS, "selector %u got status %#lx\n", selector, status );
        ok( batch == (selector ? 0 : 1), "selector %u got batch %u\n", selector, batch );
    }

    processed = 0xcccccccc;
    released = 0xcc;
    status = NtDCompositionProcessChannelBatchBuffer( channel, 0, &processed, &released );
    ok( status == STATUS_SUCCESS, "got empty process status %#lx\n", status );
    ok( !processed, "got empty processed count %lu\n", processed );
    ok( !released, "got empty released flag %#x\n", released );

    ((UINT *)buffer)[0] = 2;
    ((UINT *)buffer)[1] = 1;
    ((UINT *)buffer)[2] = 13;
    ((UINT *)buffer)[3] = 0;
    processed = 0xcccccccc;
    released = 0xcc;
    status = NtDCompositionProcessChannelBatchBuffer( channel, 16, &processed, &released );
    ok( status == STATUS_SUCCESS, "got create process status %#lx\n", status );
    ok( processed == 1, "got create processed count %lu\n", processed );
    ok( !released, "got create released flag %#x\n", released );

    ((UINT *)buffer)[0] = 11;
    ((UINT *)buffer)[1] = 1;
    ((UINT *)buffer)[2] = 2;
    ((UINT *)buffer)[3] = 0x55667788;
    ((UINT *)buffer)[4] = 0x11223344;
    ((UINT *)buffer)[5] = 0;
    status = NtDCompositionProcessChannelBatchBuffer( channel, 24, &processed, &released );
    ok( status == STATUS_SUCCESS, "got property process status %#lx\n", status );
    ok( processed == 1, "got property processed count %lu\n", processed );

    ((UINT *)buffer)[0] = 4;
    ((UINT *)buffer)[1] = 1;
    status = NtDCompositionProcessChannelBatchBuffer( channel, 8, &processed, &released );
    ok( status == STATUS_SUCCESS, "got release process status %#lx\n", status );
    ok( processed == 1, "got release processed count %lu\n", processed );
    ok( released == 1, "got release flag %#x\n", released );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 8, &processed, &released );
    ok( status == STATUS_ACCESS_DENIED, "got repeated release status %#lx\n", status );
    ok( processed == 1, "got repeated release processed count %lu\n", processed );

    ((UINT *)buffer)[0] = 0xffffffff;
    status = NtDCompositionProcessChannelBatchBuffer( channel, 4, &processed, &released );
    ok( status == STATUS_INVALID_PARAMETER, "got unknown command status %#lx\n", status );
    ok( processed == 1, "got unknown command processed count %lu\n", processed );
    status = NtDCompositionProcessChannelBatchBuffer( 0xdeadbeef, 0, &processed, &released );
    ok( status == STATUS_ACCESS_DENIED, "got invalid-channel process status %#lx\n", status );

    processed = 0xcccccccc;
    released = 0xcc;
    status = NtDCompositionProcessChannelBatchBuffer( channel, size + 1, &processed, &released );
    ok( status == STATUS_INVALID_PARAMETER, "got oversized process status %#lx\n", status );
    ok( !processed, "got oversized processed count %lu\n", processed );
    ok( !released, "got oversized released flag %#x\n", released );

    status = NtDCompositionProcessChannelBatchBuffer( channel, 0, NULL, &released );
    ok( status == STATUS_INVALID_PARAMETER, "got null-processed status %#lx\n", status );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 0, &processed, NULL );
    ok( status == STATUS_INVALID_PARAMETER, "got null-released status %#lx\n", status );

    ((UINT *)buffer)[0] = 15;
    ((UINT *)buffer)[1] = 1;
    ((UINT *)buffer)[2] = 2;
    ((UINT *)buffer)[3] = UINT_MAX;
    status = NtDCompositionProcessChannelBatchBuffer( channel, 16, &processed, &released );
    ok( status == STATUS_INVALID_PARAMETER, "got malformed-variable process status %#lx\n", status );
    ok( processed == 1, "got malformed-variable processed count %lu\n", processed );

    status = NtDCompositionCreateChannel( &second_channel, &second_size, (void **)&second_buffer, 0 );
    ok( status == STATUS_SUCCESS, "got second status %#lx\n", status );
    ok( second_channel && second_channel != channel, "got second channel %#x\n", second_channel );
    ok( second_buffer && second_buffer != buffer, "got second buffer %p\n", second_buffer );
    internal_event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!internal_event, "failed to create internal completion event, error %lu\n", GetLastError() );
    status = NtDCompositionSetChannelCommitCompletionEvent( second_channel, internal_event, TRUE );
    ok( status == STATUS_SUCCESS, "got internal completion-event status %#lx\n", status );
    CloseHandle( internal_event );
    internal_event = NULL;

    for (i = 0; i < ARRAY_SIZE(flag_values); ++i)
    {
        UINT flag_channel = 0xcccccccc, flag_size = 0x1000;
        BYTE *flag_buffer = (BYTE *)0xdeadbeef;

        status = NtDCompositionCreateChannel( &flag_channel, &flag_size, (void **)&flag_buffer, flag_values[i] );
        ok( status == STATUS_SUCCESS, "flags %#x got status %#lx\n", flag_values[i], status );
        ok( flag_channel && flag_channel != channel && flag_channel != second_channel,
            "flags %#x got channel %#x\n", flag_values[i], flag_channel );
        ok( flag_size == 0x1000, "flags %#x got size %u\n", flag_values[i], flag_size );
        ok( flag_buffer && flag_buffer != buffer && flag_buffer != second_buffer,
            "flags %#x got buffer %p\n", flag_values[i], flag_buffer );
        if (!status)
        {
            status = NtDCompositionDestroyChannel( flag_channel );
            ok( status == STATUS_SUCCESS, "flags %#x destroy got status %#lx\n", flag_values[i], status );
        }
    }

    batch = 0xcccccccc;
    state = 0xcc;
    SetLastError( 0xdeadbeef );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got commit status %#lx\n", status );
    ok( batch == 2, "got commit batch %u\n", batch );
    ok( !state, "got commit state %#x\n", state );
    ok( GetLastError() == 0xdeadbeef, "got last error %lu\n", GetLastError() );

    batch = 0xcccccccc;
    status = NtDCompositionCommitChannel( channel, &batch, NULL, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_INVALID_PARAMETER, "got null-state status %#lx\n", status );
    ok( batch == 0xcccccccc, "null-state batch changed to %u\n", batch );

    state = 0xcc;
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL,
                                           &protocol_list.head, NULL, 0 );
    ok( status == STATUS_INVALID_PARAMETER, "got ordinary protocol-list status %#lx\n", status );
    ok( state == 0xcc, "ordinary protocol-list state changed to %#x\n", state );

    status = NtDCompositionDestroyChannel( channel );
    ok( status == STATUS_SUCCESS, "got destroy status %#lx\n", status );
    batch = 0xcccccccc;
    status = NtDCompositionGetBatchId( channel, 2, &batch );
    ok( status == STATUS_ACCESS_DENIED, "got post-destroy status %#lx\n", status );
    ok( batch == 0xcccccccc, "post-destroy batch changed to %u\n", batch );
    status = NtDCompositionDestroyChannel( channel );
    ok( status == STATUS_ACCESS_DENIED, "got second destroy status %#lx\n", status );
    status = NtDCompositionDestroyChannel( 0xdeadbeef );
    ok( status == STATUS_ACCESS_DENIED, "got arbitrary destroy status %#lx\n", status );

    status = NtDCompositionDestroyChannel( second_channel );
    ok( status == STATUS_SUCCESS, "got second destroy status %#lx\n", status );
    if (internal_event) CloseHandle( internal_event );
}

static void test_channel_synchronization(void)
{
    BYTE *buffer = NULL, *second_buffer = NULL;
    UINT size = 0x1000, second_size = 0x1000;
    UINT channel = 0, second_channel = 0, batch;
    UINT64 first = 0, second = 0, other = 0;
    BYTE state;
    NTSTATUS status;

    status = NtDCompositionSynchronize( 0xdeadbeef, &first );
    ok( status == STATUS_ACCESS_DENIED, "got invalid-channel status %#lx\n", status );
    ok( !first, "invalid-channel ID changed to %s\n", wine_dbgstr_longlong(first) );

    status = NtDCompositionCreateChannel( &channel, &size, (void **)&buffer, 0 );
    ok( status == STATUS_SUCCESS, "got channel creation status %#lx\n", status );
    status = NtDCompositionCreateChannel( &second_channel, &second_size,
                                          (void **)&second_buffer, 0 );
    ok( status == STATUS_SUCCESS, "got second channel creation status %#lx\n", status );
    if (!channel || !second_channel) goto done;

    status = NtDCompositionSynchronize( channel, &first );
    ok( status == STATUS_SUCCESS, "got first synchronization status %#lx\n", status );
    ok( first != 0, "got zero first synchronization ID\n" );

    second = 0xccccccccccccccccULL;
    status = NtDCompositionSynchronize( channel, &second );
    ok( status == STATUS_ACCESS_DENIED, "got repeated synchronization status %#lx\n", status );
    ok( second == 0xccccccccccccccccULL, "repeated synchronization changed ID to %s\n",
        wine_dbgstr_longlong(second) );

    status = NtDCompositionSynchronize( second_channel, &other );
    ok( status == STATUS_SUCCESS, "got other-channel synchronization status %#lx\n", status );
    ok( other != 0 && other != first, "got other-channel synchronization ID %s after %s\n",
        wine_dbgstr_longlong(other), wine_dbgstr_longlong(first) );

    batch = 0xcccccccc;
    state = 0xcc;
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got synchronized commit status %#lx\n", status );
    status = NtDCompositionSynchronize( channel, &second );
    ok( status == STATUS_SUCCESS, "got next-batch synchronization status %#lx\n", status );
    ok( second != 0 && second != first && second != other,
        "got next-batch synchronization ID %s\n", wine_dbgstr_longlong(second) );

    state = 0xcc;
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got second synchronized commit status %#lx\n", status );
    status = NtDCompositionSynchronize( channel, NULL );
    ok( status == STATUS_INVALID_PARAMETER, "got null-output status %#lx\n", status );
    second = 0xccccccccccccccccULL;
    status = NtDCompositionSynchronize( channel, &second );
    ok( status == STATUS_ACCESS_DENIED, "got post-null synchronization status %#lx\n", status );
    ok( second == 0xccccccccccccccccULL, "post-null synchronization changed ID to %s\n",
        wine_dbgstr_longlong(second) );

done:
    if (second_channel) NtDCompositionDestroyChannel( second_channel );
    if (channel) NtDCompositionDestroyChannel( channel );
}

static void test_synchronized_connection_queue(void)
{
    struct dcomp_test_protocol_list first_protocol, second_protocol;
    struct dcomposition_connection_batch *record = NULL;
    struct dcomposition_frame_info frame_info = {0};
    struct dcomposition_confirm_frame_info confirm_info = {0};
    HANDLE event, connection = NULL;
    BYTE *first_buffer = NULL, *second_buffer = NULL;
    UINT first_channel = 0, second_channel = 0;
    UINT first_size = 0x1000, second_size = 0x1000, batch, first_batch, second_batch, received;
    UINT second_opcode = 0x2e;
    UINT64 first_id = 0, second_id = 0, frame_id = 0, selector = 0;
    BYTE state;
    NTSTATUS status;

    init_dcomp_test_protocol_list( &first_protocol );
    init_dcomp_test_protocol_list( &second_protocol );
    memcpy( second_protocol.block.data + 4, &second_opcode, sizeof(second_opcode) );

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create synchronized-queue event, error %lu\n", GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got synchronized-queue connection status %#lx\n", status );
    status = NtDCompositionCreateChannel( &first_channel, &first_size,
                                           (void **)&first_buffer, 0 );
    ok( status == STATUS_SUCCESS, "got first synchronized channel status %#lx\n", status );
    status = NtDCompositionCreateChannel( &second_channel, &second_size,
                                           (void **)&second_buffer, 0 );
    ok( status == STATUS_SUCCESS, "got second synchronized channel status %#lx\n", status );
    if (!connection || !first_channel || !second_channel) goto done;

    status = NtDCompositionSetChannelConnectionId( first_channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got first synchronized bind status %#lx\n", status );
    status = NtDCompositionSetChannelConnectionId( second_channel, 0, 2 );
    ok( status == STATUS_SUCCESS, "got second synchronized bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &selector, &record );
    ok( status == STATUS_SUCCESS && record && record->next,
        "got synchronized create records status %#lx record %p\n", status, record );

    status = NtDCompositionSynchronize( first_channel, &first_id );
    ok( status == STATUS_SUCCESS && first_id,
        "got first queue synchronization status %#lx ID %s\n",
        status, wine_dbgstr_longlong(first_id) );
    status = NtDCompositionCommitChannel( first_channel, &batch, &state, 0, NULL,
                                           &first_protocol.head, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got first synchronized commit status %#lx\n", status );

    status = NtDCompositionSynchronize( second_channel, &second_id );
    ok( status == STATUS_SUCCESS && second_id && second_id != first_id,
        "got second queue synchronization status %#lx ID %s\n",
        status, wine_dbgstr_longlong(second_id) );
    status = NtDCompositionCommitChannel( second_channel, &batch, &state, 0, NULL,
                                           &second_protocol.head, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got second synchronized commit status %#lx\n", status );

    status = NtDCompositionBeginFrame( connection, &frame_info, &frame_id );
    ok( status == STATUS_SUCCESS && frame_id && frame_id != first_id && frame_id != second_id,
        "got queue frame status %#lx ID %s\n", status, wine_dbgstr_longlong(frame_id) );
    selector = frame_id;
    status = NtDCompositionGetConnectionBatch( connection, &selector, &record );
    ok( status == STATUS_SUCCESS, "got frame batch set status %#lx\n", status );
    ok( record && record->next && !record->next->next,
        "got unexpected frame batch list %p\n", record );
    if (record && record->next)
    {
        ok( record->type == 7 && record->u.batch.channel == first_channel &&
            record->u.batch.size == sizeof(first_protocol.block.data) &&
            !memcmp( record->u.batch.data, first_protocol.block.data,
                     sizeof(first_protocol.block.data) ),
            "got unexpected first frame batch\n" );
        record = record->next;
        ok( record->type == 7 && record->u.batch.channel == second_channel &&
            record->u.batch.size == sizeof(second_protocol.block.data) &&
            !memcmp( record->u.batch.data, second_protocol.block.data,
                     sizeof(second_protocol.block.data) ),
            "got unexpected second frame batch\n" );
    }
    confirm_info.frame_id = frame_id;
    status = NtDCompositionConfirmFrame( connection, &confirm_info );
    ok( status == STATUS_SUCCESS, "got queue frame confirmation status %#lx\n", status );

    status = NtDCompositionSynchronize( first_channel, &first_id );
    ok( status == STATUS_SUCCESS, "got repeated first synchronization status %#lx\n", status );
    status = NtDCompositionCommitChannel( first_channel, &batch, &state, 0, NULL,
                                           &first_protocol.head, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got repeated first commit status %#lx\n", status );
    status = NtDCompositionSynchronize( second_channel, &second_id );
    ok( status == STATUS_SUCCESS, "got repeated second synchronization status %#lx\n", status );
    status = NtDCompositionCommitChannel( second_channel, &batch, &state, 0, NULL,
                                           &second_protocol.head, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got repeated second commit status %#lx\n", status );

    selector = second_id;
    status = NtDCompositionGetConnectionBatch( connection, &selector, &record );
    ok( status == STATUS_SUCCESS, "got exact second batch status %#lx\n", status );
    ok( record && !record->next && record->type == 7 &&
        record->u.batch.channel == second_channel &&
        record->u.batch.size == sizeof(second_protocol.block.data) &&
        !memcmp( record->u.batch.data, second_protocol.block.data,
                 sizeof(second_protocol.block.data) ),
        "got unexpected exact second batch %p\n", record );

    selector = first_id;
    status = NtDCompositionGetConnectionBatch( connection, &selector, &record );
    ok( status == STATUS_SUCCESS, "got exact first batch status %#lx\n", status );
    ok( record && !record->next && record->type == 7 &&
        record->u.batch.channel == first_channel &&
        record->u.batch.size == sizeof(first_protocol.block.data) &&
        !memcmp( record->u.batch.data, first_protocol.block.data,
                 sizeof(first_protocol.block.data) ),
        "got unexpected exact first batch %p\n", record );

    selector = second_id;
    status = NtDCompositionGetConnectionBatch( connection, &selector, &record );
    ok( status == STATUS_NOT_FOUND, "got consumed synchronization status %#lx\n", status );
    ok( !record, "consumed synchronization returned %p\n", record );

    selector = 0;
    status = NtDCompositionGetConnectionBatch( connection, &selector, &record );
    ok( status == STATUS_SUCCESS, "got final synchronized queue status %#lx\n", status );
    ok( !record, "final synchronized queue returned %p\n", record );

    status = NtDCompositionSynchronize( first_channel, &first_id );
    ok( status == STATUS_SUCCESS, "got same-channel first synchronization status %#lx\n", status );
    status = NtDCompositionCommitChannel( first_channel, &first_batch, &state, 0, NULL,
                                           &first_protocol.head, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got same-channel first commit status %#lx\n", status );
    status = NtDCompositionSynchronize( first_channel, &second_id );
    ok( status == STATUS_SUCCESS, "got same-channel second synchronization status %#lx\n", status );
    status = NtDCompositionCommitChannel( first_channel, &second_batch, &state, 0, NULL,
                                           &second_protocol.head, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got same-channel second commit status %#lx\n", status );

    received = 0xcccccccc;
    status = NtDCompositionGetBatchId( first_channel, 1, &received );
    ok( status == STATUS_SUCCESS, "got pre-receipt batch status %#lx\n", status );
    ok( received == first_batch - 1, "got pre-receipt batch %u, expected %u\n",
        received, first_batch - 1 );

    selector = second_id;
    status = NtDCompositionGetConnectionBatch( connection, &selector, &record );
    ok( status == STATUS_SUCCESS && record && !record->next,
        "got same-channel second batch status %#lx record %p\n", status, record );
    received = 0xcccccccc;
    status = NtDCompositionGetBatchId( first_channel, 1, &received );
    ok( status == STATUS_SUCCESS, "got gapped receipt batch status %#lx\n", status );
    ok( received == first_batch - 1, "gapped receipt advanced to %u, expected %u\n",
        received, first_batch - 1 );

    selector = first_id;
    status = NtDCompositionGetConnectionBatch( connection, &selector, &record );
    ok( status == STATUS_SUCCESS && record && !record->next,
        "got same-channel first batch status %#lx record %p\n", status, record );
    received = 0xcccccccc;
    status = NtDCompositionGetBatchId( first_channel, 1, &received );
    ok( status == STATUS_SUCCESS, "got contiguous receipt batch status %#lx\n", status );
    ok( received == second_batch, "got contiguous receipt batch %u, expected %u\n",
        received, second_batch );

done:
    if (second_channel) NtDCompositionDestroyChannel( second_channel );
    if (first_channel) NtDCompositionDestroyChannel( first_channel );
    if (connection) NtDCompositionDestroyConnection( connection );
    CloseHandle( event );
}

static void test_connection_queue(void)
{
    static const BYTE expected_resource_batch[] = {
        0x10, 0, 0, 0, 0x28, 0, 0, 0, 1, 0, 0, 0, 13, 0, 0, 0,
        8, 0, 0, 0, 0x24, 0, 0, 0,
    };
    static const BYTE expected_release_batch[] = {
        8, 0, 0, 0, 0x24, 0, 0, 0,
        0x0c, 0, 0, 0, 0x29, 0, 0, 0, 1, 0, 0, 0,
    };
    struct dcomp_test_protocol_list protocol_list;
    struct dcomposition_connection_batch *record = (void *)0xdeadbeef;
    HANDLE event, connection = NULL, completion_event = NULL, completion_wait = NULL;
    BYTE *buffer = (BYTE *)0xdeadbeef;
    UINT channel = 0xcccccccc, size = 0x1000, batch = 0xcccccccc;
    UINT64 cookie = 0;
    ULONG processed;
    BYTE released, state = 0xcc;
    NTSTATUS status;

    init_dcomp_test_protocol_list( &protocol_list );

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create event, error %lu\n", GetLastError() );
    if (!event) return;
    /* In regular Wine mode TRUE remains the built-in compositor adapter hint.
     * Native startup identifies genuine DWM through its registered session
     * port; genuine DWM itself passes FALSE for the reached startup call. */
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got connection status %#lx\n", status );
    status = NtDCompositionCreateChannel( &channel, &size, (void **)&buffer, 0x90 );
    ok( status == STATUS_SUCCESS, "got channel status %#lx\n", status );
    if (status) goto done;

    status = NtDCompositionSetChannelCommitCompletionEvent( channel, NULL, FALSE );
    ok( status == STATUS_INVALID_PARAMETER, "got null completion-event status %#lx\n", status );
    status = NtDCompositionSetChannelCommitCompletionEvent( 0xdeadbeef, event, FALSE );
    ok( status == STATUS_ACCESS_DENIED, "got invalid-channel completion status %#lx\n", status );
    status = NtDCompositionSetChannelCommitCompletionEvent( channel, (HANDLE)0xdeadbeef, FALSE );
    ok( status == STATUS_INVALID_HANDLE, "got invalid completion-event status %#lx\n", status );
    completion_event = CreateEventW( NULL, TRUE, FALSE, NULL );
    ok( !!completion_event, "failed to create completion event, error %lu\n", GetLastError() );
    ok( DuplicateHandle( GetCurrentProcess(), completion_event, GetCurrentProcess(), &completion_wait,
                         SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, 0 ),
        "failed to duplicate completion event, error %lu\n", GetLastError() );
    status = NtDCompositionSetChannelCommitCompletionEvent( channel, completion_event, FALSE );
    ok( status == STATUS_SUCCESS, "got completion-event status %#lx\n", status );
    status = NtDCompositionSetChannelCommitCompletionEvent( channel, (HANDLE)0xdeadbeef, TRUE );
    ok( status == STATUS_ACCESS_DENIED, "got duplicate completion-event status %#lx\n", status );
    CloseHandle( completion_event );
    completion_event = NULL;
    ok( WaitForSingleObject( completion_wait, 0 ) == WAIT_TIMEOUT,
        "completion event was initially signaled\n" );

    status = NtDCompositionSetChannelConnectionId( channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got bind status %#lx\n", status );
    status = NtDCompositionSetChannelConnectionId( channel, 1, 2 );
    ok( status == STATUS_SUCCESS, "got second-slot bind status %#lx\n", status );
    status = NtDCompositionSetChannelConnectionId( channel, 1, 3 );
    ok( status == STATUS_INVALID_PARAMETER, "got occupied second-slot bind status %#lx\n", status );
    status = NtDCompositionSetChannelConnectionId( channel, 1, 0 );
    ok( status == STATUS_SUCCESS, "got second-slot clear status %#lx\n", status );
    status = NtDCompositionSetChannelConnectionId( channel, 1, 3 );
    ok( status == STATUS_SUCCESS, "got second-slot rebind status %#lx\n", status );
    status = NtDCompositionSetChannelConnectionId( channel, 0, 1 );
    ok( status == STATUS_INVALID_PARAMETER, "got repeated bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got create record status %#lx\n", status );
    ok( !cookie, "batch selector changed to %s\n", wine_dbgstr_longlong(cookie) );
    ok( !!record, "create record is null\n" );
    if (record)
    {
        ok( record->type == 5, "got create record type %u\n", record->type );
        ok( !record->next, "got create record next %p\n", record->next );
        ok( record->u.create.channel == channel, "got create channel %#x\n", record->u.create.channel );
        ok( record->u.create.flags == 0x90, "got create flags %#x\n", record->u.create.flags );
        ok( record->u.create.connection == 1, "got create connection %s\n",
            wine_dbgstr_longlong(record->u.create.connection) );
        ok( !record->u.create.object, "got create object %p\n", record->u.create.object );
    }
    status = NtDCompositionSetChannelConnectionId( channel, 0, 0 );
    ok( status == STATUS_SUCCESS, "got first-slot clear status %#lx\n", status );
    status = NtDCompositionSetChannelConnectionId( channel, 0, 4 );
    ok( status == STATUS_SUCCESS, "got first-slot rebind status %#lx\n", status );
    record = (void *)0xdeadbeef;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got post-rebind queue status %#lx\n", status );
    ok( !record, "post-rebind queue returned duplicate create record %p\n", record );

    ((UINT *)buffer)[0] = 2;
    ((UINT *)buffer)[1] = 1;
    ((UINT *)buffer)[2] = 13;
    ((UINT *)buffer)[3] = 0;
    status = NtDCompositionProcessChannelBatchBuffer( channel, 16, &processed, &released );
    ok( status == STATUS_SUCCESS, "got resource process status %#lx\n", status );
    ok( processed == 1, "got resource process count %lu\n", processed );

    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL,
                                           &protocol_list.head, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got commit status %#lx\n", status );
    ok( !state, "got commit state %#x\n", state );
    {
        UINT received = 0xcccccccc;

        status = NtDCompositionGetBatchId( channel, 1, &received );
        ok( status == STATUS_SUCCESS, "got pre-dequeue receipt status %#lx\n", status );
        ok( !received, "receipt advanced before dequeue to %u\n", received );
    }
    ok( WaitForSingleObject( completion_wait, 0 ) == WAIT_TIMEOUT,
        "completion event signaled before consumer dequeue\n" );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got batch record status %#lx\n", status );
    {
        UINT received = 0xcccccccc;

        status = NtDCompositionGetBatchId( channel, 1, &received );
        ok( status == STATUS_SUCCESS, "got post-dequeue receipt status %#lx\n", status );
        ok( received == batch, "got post-dequeue receipt %u, expected %u\n", received, batch );
    }
    ok( WaitForSingleObject( completion_wait, 0 ) == WAIT_OBJECT_0,
        "completion event was not signaled after consumer dequeue\n" );
    ok( !!record, "batch record is null\n" );
    if (record)
    {
        ok( record->type == 7, "got batch record type %u\n", record->type );
        ok( record->u.batch.channel == channel, "got batch channel %#x\n", record->u.batch.channel );
        ok( record->u.batch.size == sizeof(expected_resource_batch),
            "got batch size %u\n", record->u.batch.size );
        ok( record->u.batch.size != sizeof(expected_resource_batch) ||
            !memcmp( record->u.batch.data, expected_resource_batch,
                     sizeof(expected_resource_batch) ),
            "got unexpected resource-prefixed batch\n" );
    }

    batch = 0xcccccccc;
    state = 0xcc;
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL,
                                           &protocol_list.head, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got repeated commit status %#lx\n", status );
    ok( !state, "got repeated commit state %#x\n", state );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got repeated batch record status %#lx\n", status );
    ok( !!record, "repeated batch record is null\n" );
    if (record)
    {
        ok( record->type == 7, "got repeated batch record type %u\n", record->type );
        ok( record->u.batch.size == sizeof(protocol_list.block.data),
            "got repeated batch size %u\n", record->u.batch.size );
        ok( record->u.batch.size != sizeof(protocol_list.block.data) ||
            !memcmp( record->u.batch.data, protocol_list.block.data,
                     sizeof(protocol_list.block.data) ),
            "repeated batch unexpectedly recreated the resource\n" );
    }

    protocol_list.block.type = 0x201;
    state = 0xcc;
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL,
                                           &protocol_list.head, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got alternate-type protocol status %#lx\n", status );
    ok( !state, "got alternate-type protocol state %#x\n", state );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got alternate-type batch record status %#lx\n", status );
    ok( !!record, "alternate-type batch record is null\n" );
    if (record)
    {
        ok( record->type == 7, "got alternate-type record type %u\n", record->type );
        ok( record->u.batch.size == sizeof(protocol_list.block.data),
            "got alternate-type batch size %u\n", record->u.batch.size );
        ok( record->u.batch.size != sizeof(protocol_list.block.data) ||
            !memcmp( record->u.batch.data, protocol_list.block.data,
                     sizeof(protocol_list.block.data) ),
            "alternate block type changed the protocol payload\n" );
    }
    protocol_list.block.type = 0x200;

    ((UINT *)buffer)[0] = 4;
    ((UINT *)buffer)[1] = 1;
    status = NtDCompositionProcessChannelBatchBuffer( channel, 8, &processed, &released );
    ok( status == STATUS_SUCCESS, "got resource release status %#lx\n", status );
    ok( processed == 1, "got resource release count %lu\n", processed );
    ok( released == 1, "got resource release flag %#x\n", released );

    state = 0xcc;
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL,
                                           &protocol_list.head, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got release commit status %#lx\n", status );
    ok( !state, "got release commit state %#x\n", state );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got release batch record status %#lx\n", status );
    ok( !!record, "release batch record is null\n" );
    if (record)
    {
        ok( record->type == 7, "got release batch record type %u\n", record->type );
        ok( record->u.batch.size == sizeof(expected_release_batch),
            "got release batch size %u\n", record->u.batch.size );
        ok( record->u.batch.size != sizeof(expected_release_batch) ||
            !memcmp( record->u.batch.data, expected_release_batch,
                     sizeof(expected_release_batch) ),
            "got unexpected release batch\n" );
    }

    ((UINT *)buffer)[0] = 2;
    ((UINT *)buffer)[1] = 1;
    ((UINT *)buffer)[2] = 13;
    ((UINT *)buffer)[3] = 0;
    status = NtDCompositionProcessChannelBatchBuffer( channel, 16, &processed, &released );
    ok( status == STATUS_SUCCESS, "got reused resource process status %#lx\n", status );
    ok( processed == 1, "got reused resource process count %lu\n", processed );

    state = 0xcc;
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL,
                                           &protocol_list.head, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got reused resource commit status %#lx\n", status );
    ok( !state, "got reused resource commit state %#x\n", state );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got reused resource batch status %#lx\n", status );
    ok( !!record, "reused resource batch is null\n" );
    if (record)
    {
        ok( record->u.batch.size == sizeof(expected_resource_batch),
            "got reused resource batch size %u\n", record->u.batch.size );
        ok( record->u.batch.size != sizeof(expected_resource_batch) ||
            !memcmp( record->u.batch.data, expected_resource_batch,
                     sizeof(expected_resource_batch) ),
            "reused resource was not recreated\n" );
    }

    status = NtDCompositionDestroyChannel( channel );
    ok( status == STATUS_SUCCESS, "got channel destroy status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got close record status %#lx\n", status );
    ok( !!record, "close record is null\n" );
    if (record)
    {
        ok( record->type == 6, "got close record type %u\n", record->type );
        ok( record->u.close.channel == channel, "got close channel %#x\n", record->u.close.channel );
    }
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got empty queue status %#lx\n", status );
    ok( !record, "empty queue returned %p\n", record );
    buffer = NULL;

done:
    if (buffer && buffer != (BYTE *)0xdeadbeef) NtDCompositionDestroyChannel( channel );
    if (connection) NtDCompositionDestroyConnection( connection );
    if (completion_wait) CloseHandle( completion_wait );
    if (completion_event) CloseHandle( completion_event );
    CloseHandle( event );
}

static void test_large_connection_batch(void)
{
    enum { resource_count = 5000, command_words = 4 };
    struct dcomposition_connection_batch *record = NULL;
    HANDLE event, connection = NULL;
    BYTE *buffer = NULL, released = 0xcc, state = 0xcc;
    UINT channel = 0, size = 0x20000, batch = 0xcccccccc;
    UINT64 cookie = 0;
    ULONG processed = 0;
    NTSTATUS status;
    UINT *command;
    unsigned int i;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create large-batch event, error %lu\n", GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got large-batch connection status %#lx\n", status );
    status = NtDCompositionCreateChannel( &channel, &size, (void **)&buffer, 0 );
    ok( status == STATUS_SUCCESS, "got large-batch channel status %#lx\n", status );
    if (status) goto done;
    ok( size >= resource_count * command_words * sizeof(*command),
        "got large-batch channel size %#x\n", size );

    status = NtDCompositionSetChannelConnectionId( channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got large-batch bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5,
        "got large-batch create record status %#lx record %p type %u\n",
        status, record, record ? record->type : 0 );

    command = (UINT *)buffer;
    for (i = 0; i < resource_count; ++i)
    {
        command[i * command_words] = 2;
        command[i * command_words + 1] = i + 1;
        command[i * command_words + 2] = 13;
        command[i * command_words + 3] = 0;
    }
    status = NtDCompositionProcessChannelBatchBuffer( channel,
                                                       resource_count * command_words * sizeof(*command),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got large-batch process status %#lx\n", status );
    ok( processed == resource_count, "got large-batch process count %lu\n", processed );

    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got large-batch commit status %#lx\n", status );
    ok( !state, "got large-batch commit state %#x\n", state );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 7,
        "got large-batch record status %#lx record %p type %u\n",
        status, record, record ? record->type : 0 );
    if (record && record->type == 7)
    {
        const UINT expected_size = resource_count * command_words * sizeof(UINT);
        const UINT *payload = (const UINT *)record->u.batch.data;

        ok( record->u.batch.size == expected_size,
            "got large-batch payload size %#x\n", record->u.batch.size );
        if (record->u.batch.size == expected_size)
        {
            const UINT *last = payload + (resource_count - 1) * command_words;

            ok( payload[0] == 16 && payload[1] == 0x28 && payload[2] == 1 && payload[3] == 13,
                "got large-batch first command %#x/%#x/%#x/%#x\n",
                payload[0], payload[1], payload[2], payload[3] );
            ok( last[0] == 16 && last[1] == 0x28 &&
                last[2] == resource_count && last[3] == 13,
                "got large-batch last command %#x/%#x/%#x/%#x\n",
                last[0], last[1], last[2], last[3] );
        }
    }

done:
    if (channel) NtDCompositionDestroyChannel( channel );
    if (connection) NtDCompositionDestroyConnection( connection );
    CloseHandle( event );
}

static void test_referenced_resource_id_reuse(void)
{
    static const UINT expected_recreate[] = {16, 0x28, 3, 0x16};
    UINT expected_begin[] = {16, 0x26, 3, 0};
    static const UINT expected_complete[] = {12, 0x27, 2};
    static const UINT expected_replace[] = {
        16, 0x16e, 1, 3,
        12, 0x29, 2,
    };
    struct dcomposition_connection_batch *record = NULL;
    HANDLE event, connection = NULL, shared = NULL;
    BYTE *buffer = NULL, *reader_buffer = NULL, released, state;
    UINT channel = 0, reader_channel = 0, size = 0x1000, reader_size = 0x1000;
    UINT batch, command[12];
    UINT64 cookie = 0;
    ULONG processed;
    NTSTATUS status;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create resource-id event, error %lu\n", GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got resource-id connection status %#lx\n", status );
    status = NtDCompositionCreateChannel( &channel, &size, (void **)&buffer, 0 );
    ok( status == STATUS_SUCCESS, "got resource-id channel status %#lx\n", status );
    if (status) goto done;
    status = NtDCompositionSetChannelConnectionId( channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got resource-id bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5,
        "got resource-id create record status %#lx record %p type %u\n",
        status, record, record ? record->type : 0 );

    command[0] = 2; command[1] = 1; command[2] = 0xa6; command[3] = 0;
    command[4] = 2; command[5] = 2; command[6] = 0x16; command[7] = 0;
    command[8] = 16; command[9] = 1; command[10] = 0x34; command[11] = 2;
    memcpy( buffer, command, sizeof(command) );
    status = NtDCompositionProcessChannelBatchBuffer( channel, sizeof(command),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS && processed == 3,
        "got initial resource-id process status %#lx count %lu\n", status, processed );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got initial resource-id commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record, "got initial resource-id batch status %#lx record %p\n",
        status, record );

    command[0] = 4; command[1] = 2;
    command[2] = 2; command[3] = 2; command[4] = 0x16; command[5] = 1;
    command[6] = 9; command[7] = 2; command[8] = 0; command[9] = 0;
    memcpy( buffer, command, 40 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 40, &processed, &released );
    memcpy( &shared, buffer + 32, sizeof(shared) );
    ok( status == STATUS_SUCCESS && processed == 3,
        "got retained resource-id reuse status %#lx count %lu\n", status, processed );
    ok( released == 1, "got retained resource-id release flag %#x\n", released );
    ok( !!shared, "got null retained resource-id shared handle\n" );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got reused resource-id commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got reused resource-id batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_recreate, sizeof(expected_recreate),
                               "retained resource-id recreate" );

    status = NtDCompositionCreateChannel( &reader_channel, &reader_size,
                                           (void **)&reader_buffer, 0 );
    ok( status == STATUS_SUCCESS, "got retained resource-id reader channel status %#lx\n", status );
    if (status) goto done;
    status = NtDCompositionSetChannelConnectionId( reader_channel, 0, 2 );
    ok( status == STATUS_SUCCESS, "got retained resource-id reader bind status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5,
        "got retained resource-id reader create status %#lx record %p\n", status, record );

    command[0] = 3; command[1] = 2;
    memcpy( command + 2, &shared, sizeof(shared) );
    command[4] = 0x16; command[5] = 0;
    memcpy( reader_buffer, command, 24 );
    status = NtDCompositionProcessChannelBatchBuffer( reader_channel, 24,
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got retained resource-id shared open status %#lx\n", status );
    status = NtDCompositionCommitChannel( reader_channel, &batch, &state, 0,
                                           NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got retained resource-id reader commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->next,
        "got retained resource-id duplicate records status %#lx record %p\n", status, record );
    expected_begin[3] = reader_channel;
    check_dcomp_batch_payload( record, channel, expected_begin, sizeof(expected_begin),
                               "retained resource-id begin duplicate" );
    check_dcomp_batch_payload( record ? record->next : NULL, reader_channel,
                               expected_complete, sizeof(expected_complete),
                               "retained resource-id complete duplicate" );

    command[0] = 16; command[1] = 1; command[2] = 0x34; command[3] = 2;
    memcpy( buffer, command, 16 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 16, &processed, &released );
    ok( status == STATUS_SUCCESS, "got replacement root status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got replacement root commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got replacement root batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_replace, sizeof(expected_replace),
                               "retained resource-id replacement" );

done:
    if (shared) CloseHandle( shared );
    if (reader_channel) NtDCompositionDestroyChannel( reader_channel );
    if (channel) NtDCompositionDestroyChannel( channel );
    if (connection) NtDCompositionDestroyConnection( connection );
    CloseHandle( event );
}

static void test_shared_section_lifecycle(void)
{
    struct dcomp_test_protocol_list protocol_list;
    struct dcomposition_connection_batch *record = (void *)0xdeadbeef;
    HANDLE event, connection = NULL, section = (HANDLE)0xdeadbeef, consumer_section = NULL;
    BYTE *buffer = (BYTE *)0xdeadbeef;
    UINT channel = 0xcccccccc, channel_size = 0x1000, batch;
    UINT64 cookie = 0, consumer_value;
    SIZE_T view_size;
    ULONG processed;
    BYTE released, state;
    void *address;
    NTSTATUS status;

    init_dcomp_test_protocol_list( &protocol_list );
    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create shared-section event, error %lu\n", GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got connection status %#lx\n", status );
    status = NtDCompositionCreateChannel( &channel, &channel_size, (void **)&buffer, 0 );
    ok( status == STATUS_SUCCESS, "got channel status %#lx\n", status );
    if (status) goto done;
    status = NtDCompositionSetChannelConnectionId( channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5,
        "got create record status %#lx record %p type %u\n", status, record,
        record ? record->type : 0 );

    ((UINT *)buffer)[0] = 2;
    ((UINT *)buffer)[1] = 1;
    ((UINT *)buffer)[2] = 0x9d;
    ((UINT *)buffer)[3] = 0;
    status = NtDCompositionProcessChannelBatchBuffer( channel, 16, &processed, &released );
    ok( status == STATUS_SUCCESS, "got shared resource process status %#lx\n", status );
    ((UINT *)buffer)[1] = 2;
    ((UINT *)buffer)[2] = 13;
    status = NtDCompositionProcessChannelBatchBuffer( channel, 16, &processed, &released );
    ok( status == STATUS_SUCCESS, "got ordinary resource process status %#lx\n", status );

    status = NtDCompositionCreateAndBindSharedSection( 0xdeadbeef, 1, 0x2000, &section );
    ok( status == STATUS_ACCESS_DENIED, "got invalid-channel status %#lx\n", status );
    ok( section == (HANDLE)0xdeadbeef, "invalid-channel changed section to %p\n", section );
    status = NtDCompositionCreateAndBindSharedSection( channel, 3, 0x2000, &section );
    ok( status == STATUS_INVALID_PARAMETER, "got absent-resource status %#lx\n", status );
    status = NtDCompositionCreateAndBindSharedSection( channel, 2, 0x2000, &section );
    ok( status == STATUS_INVALID_PARAMETER, "got wrong-resource-type status %#lx\n", status );
    ((UINT *)buffer)[0] = 4;
    ((UINT *)buffer)[1] = 2;
    status = NtDCompositionProcessChannelBatchBuffer( channel, 8, &processed, &released );
    ok( status == STATUS_SUCCESS, "got ordinary resource cleanup status %#lx\n", status );
    status = NtDCompositionCreateAndBindSharedSection( channel, 1, 0, &section );
    ok( status == STATUS_INVALID_PARAMETER, "got zero-size status %#lx\n", status );

    section = NULL;
    status = NtDCompositionCreateAndBindSharedSection( channel, 1, 0x2000, &section );
    ok( status == STATUS_SUCCESS, "got create-and-bind status %#lx\n", status );
    ok( !!section, "got null owner section\n" );
    status = NtDCompositionCreateAndBindSharedSection( channel, 1, 0x2000, &consumer_section );
    ok( status == STATUS_INVALID_PARAMETER, "got duplicate-bind status %#lx\n", status );
    ok( !consumer_section, "duplicate bind changed output to %p\n", consumer_section );

    address = NULL;
    view_size = 0;
    status = NtMapViewOfSection( section, GetCurrentProcess(), &address, 0, 0, NULL, &view_size,
                                 ViewUnmap, 0, PAGE_READWRITE );
    ok( status == STATUS_SUCCESS, "got owner map status %#lx\n", status );
    ok( view_size == 0x2000, "got owner map size %Iu\n", view_size );
    if (!status)
    {
        *(UINT *)address = 0x12345678;
        NtUnmapViewOfSection( GetCurrentProcess(), address );
    }
    CloseHandle( section );
    section = NULL;

    state = 0xcc;
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL,
                                           &protocol_list.head, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got shared-section commit status %#lx\n", status );
    record = (void *)0xdeadbeef;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 7,
        "got shared batch status %#lx record %p type %u\n", status, record,
        record ? record->type : 0 );
    if (!status && record && record->type == 7)
    {
        ok( record->u.batch.size == 52, "got shared batch size %u\n", record->u.batch.size );
        ok( *(UINT *)(record->u.batch.data + 16) == 28,
            "got shared update size %u\n", *(UINT *)(record->u.batch.data + 16) );
        ok( *(UINT *)(record->u.batch.data + 20) == 0x1d1,
            "got shared update opcode %#x\n", *(UINT *)(record->u.batch.data + 20) );
        ok( *(UINT *)(record->u.batch.data + 24) == 1,
            "got shared update resource %#x\n", *(UINT *)(record->u.batch.data + 24) );
        memcpy( &consumer_value, record->u.batch.data + 28, sizeof(consumer_value) );
        consumer_section = (HANDLE)(UINT_PTR)consumer_value;
        ok( !!consumer_section, "got null consumer section\n" );
        ok( *(UINT *)(record->u.batch.data + 36) == 0x2000,
            "got shared update section size %#x\n", *(UINT *)(record->u.batch.data + 36) );
        address = NULL;
        view_size = 0;
        status = NtMapViewOfSection( consumer_section, GetCurrentProcess(), &address, 0, 0, NULL,
                                     &view_size, ViewUnmap, 0, PAGE_READONLY );
        ok( status == STATUS_SUCCESS, "got consumer map status %#lx\n", status );
        ok( view_size == 0x2000, "got consumer map size %Iu\n", view_size );
        if (!status)
        {
            ok( *(UINT *)address == 0x12345678, "got shared value %#x\n", *(UINT *)address );
            NtUnmapViewOfSection( GetCurrentProcess(), address );
        }
        address = NULL;
        view_size = 0;
        status = NtMapViewOfSection( consumer_section, GetCurrentProcess(), &address, 0, 0, NULL,
                                     &view_size, ViewUnmap, 0, PAGE_READWRITE );
        ok( status == STATUS_ACCESS_DENIED, "got consumer write-map status %#lx\n", status );
        CloseHandle( consumer_section );
        consumer_section = NULL;
    }

    ((UINT *)buffer)[0] = 4;
    ((UINT *)buffer)[1] = 1;
    status = NtDCompositionProcessChannelBatchBuffer( channel, 8, &processed, &released );
    ok( status == STATUS_SUCCESS, "got shared resource release status %#lx\n", status );
    state = 0xcc;
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL,
                                           &protocol_list.head, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got shared release commit status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got shared release batch status %#lx\n", status );

    ((UINT *)buffer)[0] = 2;
    ((UINT *)buffer)[1] = 1;
    ((UINT *)buffer)[2] = 0x9d;
    ((UINT *)buffer)[3] = 0;
    status = NtDCompositionProcessChannelBatchBuffer( channel, 16, &processed, &released );
    ok( status == STATUS_SUCCESS, "got reused shared resource status %#lx\n", status );
    status = NtDCompositionCreateAndBindSharedSection( channel, 1, 0x1000, &section );
    ok( status == STATUS_SUCCESS, "got reused shared bind status %#lx\n", status );

done:
    if (consumer_section) CloseHandle( consumer_section );
    if (section) CloseHandle( section );
    if (channel != 0xcccccccc) NtDCompositionDestroyChannel( channel );
    if (connection) NtDCompositionDestroyConnection( connection );
    CloseHandle( event );
}

static void check_dcomp_batch_payload( const struct dcomposition_connection_batch *record,
                                       UINT channel, const UINT *expected, UINT expected_size,
                                       const char *context )
{
    ok( !!record, "%s batch record is null\n", context );
    if (!record) return;
    ok( record->type == 7, "%s got record type %u\n", context, record->type );
    ok( record->u.batch.channel == channel, "%s got channel %#x\n",
        context, record->u.batch.channel );
    ok( record->u.batch.size == expected_size, "%s got batch size %u, expected %u\n",
        context, record->u.batch.size, expected_size );
    ok( record->u.batch.size != expected_size ||
        !memcmp( record->u.batch.data, expected, expected_size ),
        "%s got unexpected batch payload\n", context );
}

static void test_channel_application_id(void)
{
    static const WCHAR first_id[] = L"LockApp";
    static const WCHAR second_id[] = L"LogonUI";
    struct dcomposition_connection_batch *record = NULL;
    HANDLE event, connection = NULL;
    BYTE *buffer = NULL, state;
    UINT expected[(12 + sizeof(second_id) + 3) / 4] = {0};
    UINT expected_size = (12 + sizeof(second_id) + 3) & ~3;
    UINT channel = 0, size = 0x1000, batch;
    UINT64 selector = 0;
    NTSTATUS status;

    status = NtDCompositionTelemetrySetApplicationId( 0xdeadbeef, 0, NULL );
    ok( status == STATUS_INVALID_PARAMETER, "got null application-id status %#lx\n", status );
    status = NtDCompositionTelemetrySetApplicationId( 0xdeadbeef, 1, first_id );
    ok( status == STATUS_INVALID_PARAMETER, "got odd application-id status %#lx\n", status );
    status = NtDCompositionTelemetrySetApplicationId( 0xdeadbeef, 302, first_id );
    ok( status == STATUS_INVALID_PARAMETER, "got oversized application-id status %#lx\n", status );
    status = NtDCompositionTelemetrySetApplicationId( 0xdeadbeef, sizeof(first_id), first_id );
    ok( status == STATUS_ACCESS_DENIED, "got unknown-channel application-id status %#lx\n", status );

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create application-id event, error %lu\n", GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got application-id connection status %#lx\n", status );
    status = NtDCompositionCreateChannel( &channel, &size, (void **)&buffer, 0 );
    ok( status == STATUS_SUCCESS, "got application-id channel status %#lx\n", status );
    if (!connection || !channel) goto done;
    status = NtDCompositionSetChannelConnectionId( channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got application-id bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &selector, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5,
        "got application-id create status %#lx record %p\n", status, record );

    status = NtDCompositionTelemetrySetApplicationId( channel, sizeof(first_id), first_id );
    ok( status == STATUS_SUCCESS, "got first application-id status %#lx\n", status );
    status = NtDCompositionTelemetrySetApplicationId( channel, sizeof(second_id), second_id );
    ok( status == STATUS_SUCCESS, "got replacement application-id status %#lx\n", status );

    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got application-id commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &selector, &record );
    ok( status == STATUS_SUCCESS, "got application-id batch status %#lx\n", status );
    expected[0] = expected_size;
    expected[1] = 0x2b;
    expected[2] = sizeof(second_id);
    memcpy( expected + 3, second_id, sizeof(second_id) );
    check_dcomp_batch_payload( record, channel, expected, expected_size, "application id" );

    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got clean application-id commit status %#lx\n", status );
    record = (void *)0xdeadbeef;
    status = NtDCompositionGetConnectionBatch( connection, &selector, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 7,
        "got clean application-id batch status %#lx record %p\n", status, record );
    if (record)
        ok( !record->u.batch.size, "clean application-id batch has size %u\n",
            record->u.batch.size );

done:
    if (channel) NtDCompositionDestroyChannel( channel );
    if (connection) NtDCompositionDestroyConnection( connection );
    CloseHandle( event );
}

enum published_shared_resource_case
{
    CLOSE_BEFORE_DESTINATION_COMMIT,
    CLOSE_AFTER_DESTINATION_COMMIT,
    DESTROY_DESTINATION_BEFORE_SOURCE_COMMIT,
    DESTROY_SOURCE_BEFORE_SOURCE_COMMIT,
};

static void test_published_shared_resource_ordering_case(
        enum published_shared_resource_case test_case)
{
    static const UINT expected_owner[] =
    {
        16, 0x28, 1, 0x6a,
        60, 0xf4, 1, 0, 0, 0, 0, 0, 0, 0x3f800000, 0x3f800000, 0x3f800000, 0, 0, 0,
        16, 0xf5, 1, 0,
    };
    UINT expected_begin[] = {16, 0x26, 1, 0};
    static const UINT expected_complete[] = {12, 0x27, 2};
    struct dcomposition_connection_batch *record = NULL;
    HANDLE event, connection = NULL, shared = NULL;
    BYTE *owner_buffer = NULL, *reader_buffer = NULL, state, released;
    UINT owner_channel = 0, reader_channel = 0;
    UINT owner_size = 0x1000, reader_size = 0x1000;
    UINT create[] = {2, 1, 0x6a, 1};
    UINT publish[] = {9, 1, 0, 0};
    UINT open[] = {3, 2, 0, 0, 0x6a, 0};
    UINT batch;
    UINT64 cookie = 0;
    ULONG processed;
    NTSTATUS status;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create published-order event, error %lu\n", GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got published-order connection status %#lx\n", status );
    status = NtDCompositionCreateChannel( &owner_channel, &owner_size,
                                           (void **)&owner_buffer, 0 );
    ok( status == STATUS_SUCCESS, "got published-order owner channel status %#lx\n", status );
    status = NtDCompositionCreateChannel( &reader_channel, &reader_size,
                                           (void **)&reader_buffer, 0 );
    ok( status == STATUS_SUCCESS, "got published-order reader channel status %#lx\n", status );
    if (!owner_buffer || !reader_buffer) goto done;
    status = NtDCompositionSetChannelConnectionId( reader_channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got published-order reader bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5 && !record->next,
        "got published-order reader create status %#lx record %p\n", status, record );

    memcpy( owner_buffer, create, sizeof(create) );
    status = NtDCompositionProcessChannelBatchBuffer( owner_channel, sizeof(create),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got published-order create status %#lx\n", status );
    memcpy( owner_buffer, publish, sizeof(publish) );
    status = NtDCompositionProcessChannelBatchBuffer( owner_channel, sizeof(publish),
                                                       &processed, &released );
    memcpy( &shared, owner_buffer + 8, sizeof(shared) );
    ok( status == STATUS_SUCCESS, "got published-order publish status %#lx\n", status );
    ok( !!shared, "got null published-order handle\n" );

    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5 && !record->next,
        "got published-order owner create status %#lx record %p\n", status, record );
    if (record) ok( record->u.create.channel == owner_channel,
                    "got published-order owner channel %#x\n", record->u.create.channel );

    memcpy( open + 2, &shared, sizeof(shared) );
    memcpy( reader_buffer, open, sizeof(open) );
    status = NtDCompositionProcessChannelBatchBuffer( reader_channel, sizeof(open),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got published-order open status %#lx\n", status );
    record = (void *)0xdeadbeef;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && !record,
        "published-order begin escaped before source commit, status %#lx record %p\n",
        status, record );

    if (test_case != CLOSE_AFTER_DESTINATION_COMMIT)
    {
        CloseHandle( shared );
        shared = NULL;
    }

    if (test_case == DESTROY_DESTINATION_BEFORE_SOURCE_COMMIT)
    {
        NtDCompositionDestroyChannel( reader_channel );
        status = NtDCompositionCommitChannel( owner_channel, &batch, &state, 0,
                                               NULL, NULL, NULL, 0 );
        ok( status == STATUS_SUCCESS, "got post-destroy owner commit status %#lx\n", status );
        record = NULL;
        status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
        ok( status == STATUS_SUCCESS && record && record->type == 6 &&
            record->u.close.channel == reader_channel && record->next && !record->next->next,
            "got post-destroy owner record status %#lx record %p\n", status, record );
        check_dcomp_batch_payload( record ? record->next : NULL, owner_channel, expected_owner,
                                   sizeof(expected_owner), "post-destroy published owner" );
        reader_channel = 0;
        goto done;
    }

    status = NtDCompositionCommitChannel( reader_channel, &batch, &state, 0,
                                           NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got published-order reader commit status %#lx\n", status );
    record = (void *)0xdeadbeef;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && !record,
        "published-order destination escaped before source, status %#lx record %p\n",
        status, record );

    if (test_case == CLOSE_AFTER_DESTINATION_COMMIT)
    {
        CloseHandle( shared );
        shared = NULL;
    }

    if (test_case == DESTROY_SOURCE_BEFORE_SOURCE_COMMIT)
    {
        NtDCompositionDestroyChannel( owner_channel );
        owner_channel = 0;
        record = NULL;
        status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
        ok( status == STATUS_SUCCESS && record && record->type == 6 && !record->next,
            "source destruction released an unmatched complete, status %#lx record %p\n",
            status, record );
        goto done;
    }

    status = NtDCompositionCommitChannel( owner_channel, &batch, &state, 0,
                                           NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got published-order owner commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->next && record->next->next,
        "got published-order records status %#lx record %p\n", status, record );
    check_dcomp_batch_payload( record, owner_channel, expected_owner,
                               sizeof(expected_owner), "published owner" );
    expected_begin[3] = reader_channel;
    check_dcomp_batch_payload( record ? record->next : NULL, owner_channel, expected_begin,
                               sizeof(expected_begin), "published begin" );
    check_dcomp_batch_payload( record && record->next ? record->next->next : NULL,
                               reader_channel, expected_complete,
                               sizeof(expected_complete), "published complete" );

done:
    if (shared) CloseHandle( shared );
    if (reader_channel) NtDCompositionDestroyChannel( reader_channel );
    if (owner_channel) NtDCompositionDestroyChannel( owner_channel );
    if (connection) NtDCompositionDestroyConnection( connection );
    CloseHandle( event );
}

static void test_published_shared_resource_ordering(void)
{
    test_published_shared_resource_ordering_case( CLOSE_BEFORE_DESTINATION_COMMIT );
    test_published_shared_resource_ordering_case( CLOSE_AFTER_DESTINATION_COMMIT );
    test_published_shared_resource_ordering_case( DESTROY_DESTINATION_BEFORE_SOURCE_COMMIT );
    test_published_shared_resource_ordering_case( DESTROY_SOURCE_BEFORE_SOURCE_COMMIT );
}

static void test_published_shared_resource_target_fifo(void)
{
    static const UINT expected_interaction[] = {
        16, 0x28, 1, 0x59,
        16, 0xb9, 1, 0,
    };
    static const UINT expected_manipulation[] =
    {
        16, 0x28, 1, 0x6a,
        60, 0xf4, 1, 0, 0, 0, 0, 0, 0, 0x3f800000, 0x3f800000, 0x3f800000, 0, 0, 0,
        16, 0xf5, 1, 0,
    };
    UINT expected_interaction_begin[4] = {16, 0x26, 1, 0};
    UINT expected_manipulation_begin[4] = {16, 0x26, 1, 0};
    static const UINT expected_target[] =
    {
        12, 0x27, 0x10,
        12, 0x27, 0x11,
        12, 0x27, 0x12,
        12, 0x29, 0x10,
    };
    struct dcomposition_connection_batch *record = NULL;
    HANDLE event, connection = NULL, interaction = NULL, manipulation = NULL;
    BYTE *interaction_buffer = NULL, *manipulation_buffer = NULL, *reader_buffer = NULL;
    BYTE state, released;
    UINT interaction_channel = 0, manipulation_channel = 0, reader_channel = 0;
    UINT interaction_size = 0x1000, manipulation_size = 0x1000, reader_size = 0x1000;
    UINT create[4] = {2, 1, 0, 1};
    UINT publish[4] = {9, 1, 0, 0};
    UINT open[6] = {3, 0, 0, 0, 0, 0};
    UINT release[2] = {4, 0x10};
    UINT batch;
    UINT64 cookie = 0;
    ULONG processed;
    NTSTATUS status;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create target-fifo event, error %lu\n", GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got target-fifo connection status %#lx\n", status );
    status = NtDCompositionCreateChannel( &interaction_channel, &interaction_size,
                                           (void **)&interaction_buffer, 0 );
    ok( status == STATUS_SUCCESS, "got interaction source status %#lx\n", status );
    status = NtDCompositionCreateChannel( &manipulation_channel, &manipulation_size,
                                           (void **)&manipulation_buffer, 0 );
    ok( status == STATUS_SUCCESS, "got manipulation source status %#lx\n", status );
    status = NtDCompositionCreateChannel( &reader_channel, &reader_size,
                                           (void **)&reader_buffer, 0 );
    ok( status == STATUS_SUCCESS, "got target-fifo reader status %#lx\n", status );
    if (!interaction_buffer || !manipulation_buffer || !reader_buffer) goto done;

    status = NtDCompositionSetChannelConnectionId( reader_channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got target-fifo reader bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5 && !record->next,
        "got target-fifo reader create status %#lx record %p\n", status, record );

    create[2] = 0x59;
    memcpy( interaction_buffer, create, sizeof(create) );
    status = NtDCompositionProcessChannelBatchBuffer( interaction_channel, sizeof(create),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got interaction create status %#lx\n", status );
    memcpy( interaction_buffer, publish, sizeof(publish) );
    status = NtDCompositionProcessChannelBatchBuffer( interaction_channel, sizeof(publish),
                                                       &processed, &released );
    memcpy( &interaction, interaction_buffer + 8, sizeof(interaction) );
    ok( status == STATUS_SUCCESS && interaction,
        "got interaction publish status %#lx handle %p\n", status, interaction );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5 && !record->next,
        "got interaction channel create status %#lx record %p\n", status, record );

    create[2] = 0x6a;
    memcpy( manipulation_buffer, create, sizeof(create) );
    status = NtDCompositionProcessChannelBatchBuffer( manipulation_channel, sizeof(create),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got manipulation create status %#lx\n", status );
    memcpy( manipulation_buffer, publish, sizeof(publish) );
    status = NtDCompositionProcessChannelBatchBuffer( manipulation_channel, sizeof(publish),
                                                       &processed, &released );
    memcpy( &manipulation, manipulation_buffer + 8, sizeof(manipulation) );
    ok( status == STATUS_SUCCESS && manipulation,
        "got manipulation publish status %#lx handle %p\n", status, manipulation );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5 && !record->next,
        "got manipulation channel create status %#lx record %p\n", status, record );

    open[1] = 0x10;
    memcpy( open + 2, &interaction, sizeof(interaction) );
    open[4] = 0x59;
    memcpy( reader_buffer, open, sizeof(open) );
    status = NtDCompositionProcessChannelBatchBuffer( reader_channel, sizeof(open),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got first interaction open status %#lx\n", status );
    memcpy( reader_buffer, release, sizeof(release) );
    status = NtDCompositionProcessChannelBatchBuffer( reader_channel, sizeof(release),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got first interaction release status %#lx\n", status );
    open[1] = 0x11;
    memcpy( open + 2, &manipulation, sizeof(manipulation) );
    open[4] = 0x6a;
    memcpy( reader_buffer, open, sizeof(open) );
    status = NtDCompositionProcessChannelBatchBuffer( reader_channel, sizeof(open),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got manipulation open status %#lx\n", status );
    open[1] = 0x12;
    memcpy( open + 2, &interaction, sizeof(interaction) );
    open[4] = 0x59;
    memcpy( reader_buffer, open, sizeof(open) );
    status = NtDCompositionProcessChannelBatchBuffer( reader_channel, sizeof(open),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got second interaction open status %#lx\n", status );

    status = NtDCompositionCommitChannel( reader_channel, &batch, &state, 0,
                                           NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got target-fifo reader commit status %#lx\n", status );
    record = (void *)0xdeadbeef;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && !record,
        "target-fifo reader escaped before sources, status %#lx record %p\n", status, record );

    status = NtDCompositionCommitChannel( interaction_channel, &batch, &state, 0,
                                           NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got interaction source commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->next && !record->next->next,
        "got interaction source records status %#lx record %p\n", status, record );
    check_dcomp_batch_payload( record, interaction_channel, expected_interaction,
                               sizeof(expected_interaction), "target-fifo interaction source" );
    expected_interaction_begin[3] = reader_channel;
    check_dcomp_batch_payload( record ? record->next : NULL, interaction_channel,
                               expected_interaction_begin, sizeof(expected_interaction_begin),
                               "target-fifo first interaction begin" );

    status = NtDCompositionCommitChannel( manipulation_channel, &batch, &state, 0,
                                           NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got manipulation source commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->next && record->next->next &&
        record->next->next->next && !record->next->next->next->next,
        "got manipulation completion records status %#lx record %p\n", status, record );
    check_dcomp_batch_payload( record, manipulation_channel, expected_manipulation,
                               sizeof(expected_manipulation), "target-fifo manipulation source" );
    expected_manipulation_begin[3] = reader_channel;
    check_dcomp_batch_payload( record ? record->next : NULL, manipulation_channel,
                               expected_manipulation_begin, sizeof(expected_manipulation_begin),
                               "target-fifo manipulation begin" );
    check_dcomp_batch_payload( record && record->next ? record->next->next : NULL,
                               interaction_channel, expected_interaction_begin,
                               sizeof(expected_interaction_begin),
                               "target-fifo second interaction begin" );
    check_dcomp_batch_payload( record && record->next && record->next->next ?
                               record->next->next->next : NULL, reader_channel,
                               expected_target, sizeof(expected_target),
                               "target-fifo completes and release" );

done:
    if (manipulation) CloseHandle( manipulation );
    if (interaction) CloseHandle( interaction );
    if (reader_channel) NtDCompositionDestroyChannel( reader_channel );
    if (manipulation_channel) NtDCompositionDestroyChannel( manipulation_channel );
    if (interaction_channel) NtDCompositionDestroyChannel( interaction_channel );
    if (connection) NtDCompositionDestroyConnection( connection );
    CloseHandle( event );
}

static void test_duplicate_prerequisite_selection(void)
{
    static const UINT expected_source[] = {
        16, 0x28, 1, 0x59,
        16, 0xb9, 1, 0,
    };
    static const UINT expected_system[] = {16, 0x28, 1, 0x82};
    UINT expected_source_begin[4] = {16, 0x26, 1, 0};
    UINT expected_system_begin[4] = {16, 0x26, 1, 0};
    static const UINT expected_synchronized_complete[] =
    {
        12, 0x27, 0x10,
        12, 0x27, 0x11,
    };
    static const UINT expected_framed_complete[] =
    {
        12, 0x27, 0x12,
        12, 0x27, 0x13,
    };
    struct dcomposition_confirm_frame_info confirm_info = {0};
    struct dcomposition_connection_batch *record = NULL;
    struct dcomposition_frame_info frame_info = {0};
    HANDLE event, connection = NULL, shared = NULL, system = NULL;
    BYTE *source_buffer = NULL, *target_buffer = NULL, state, released;
    UINT source_channel = 0, target_channel = 0, system_channel = 0;
    UINT source_size = 0x1000, target_size = 0x1000;
    UINT create[4] = {2, 1, 0x59, 1};
    UINT publish[4] = {9, 1, 0, 0};
    UINT open[6] = {3, 0, 0, 0, 0, 0};
    UINT64 selector = 0, synchronization_id = 0, frame_id = 0;
    UINT batch;
    ULONG processed;
    NTSTATUS status;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create prerequisite-selection event, error %lu\n",
        GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got prerequisite-selection connection status %#lx\n",
        status );
    status = NtDCompositionCreateChannel( &source_channel, &source_size,
                                           (void **)&source_buffer, 0 );
    ok( status == STATUS_SUCCESS, "got prerequisite source status %#lx\n", status );
    status = NtDCompositionCreateChannel( &target_channel, &target_size,
                                           (void **)&target_buffer, 0 );
    ok( status == STATUS_SUCCESS, "got prerequisite target status %#lx\n", status );
    if (!connection || !source_buffer || !target_buffer) goto done;

    status = NtDCompositionSetChannelConnectionId( target_channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got prerequisite target bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &selector, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5 && !record->next,
        "got prerequisite target create status %#lx record %p\n", status, record );

    memcpy( source_buffer, create, sizeof(create) );
    status = NtDCompositionProcessChannelBatchBuffer( source_channel, sizeof(create),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got prerequisite source create status %#lx\n", status );
    memcpy( source_buffer, publish, sizeof(publish) );
    status = NtDCompositionProcessChannelBatchBuffer( source_channel, sizeof(publish),
                                                       &processed, &released );
    memcpy( &shared, source_buffer + 8, sizeof(shared) );
    ok( status == STATUS_SUCCESS && shared,
        "got prerequisite publish status %#lx handle %p\n", status, shared );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &selector, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5 && !record->next,
        "got prerequisite source channel status %#lx record %p\n", status, record );
    status = NtDCompositionCommitChannel( source_channel, &batch, &state, 0,
                                           NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got prerequisite source commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &selector, &record );
    ok( status == STATUS_SUCCESS, "got prerequisite source batch status %#lx\n", status );
    check_dcomp_batch_payload( record, source_channel, expected_source,
                               sizeof(expected_source), "prerequisite source" );

    status = NtDCompositionCreateSharedResourceHandle( 0x82, &system );
    ok( status == STATUS_SUCCESS && system,
        "got prerequisite system resource status %#lx handle %p\n", status, system );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &selector, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5 && record->next &&
        !record->next->next,
        "got prerequisite system records status %#lx record %p\n", status, record );
    if (record && record->type == 5) system_channel = record->u.create.channel;
    check_dcomp_batch_payload( record ? record->next : NULL, system_channel,
                               expected_system, sizeof(expected_system),
                               "prerequisite system create" );

    status = NtDCompositionSynchronize( target_channel, &synchronization_id );
    ok( status == STATUS_SUCCESS && synchronization_id,
        "got prerequisite synchronization status %#lx ID %s\n",
        status, wine_dbgstr_longlong(synchronization_id) );
    open[1] = 0x10;
    memcpy( open + 2, &shared, sizeof(shared) );
    open[4] = 0x59;
    memcpy( target_buffer, open, sizeof(open) );
    status = NtDCompositionProcessChannelBatchBuffer( target_channel, sizeof(open),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got synchronized source open status %#lx\n", status );
    open[1] = 0x11;
    memcpy( open + 2, &system, sizeof(system) );
    open[4] = 0x82;
    memcpy( target_buffer, open, sizeof(open) );
    status = NtDCompositionProcessChannelBatchBuffer( target_channel, sizeof(open),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got synchronized system open status %#lx\n", status );
    status = NtDCompositionCommitChannel( target_channel, &batch, &state, 0,
                                           NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got synchronized prerequisite commit status %#lx\n", status );

    selector = synchronization_id;
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &selector, &record );
    ok( status == STATUS_SUCCESS && record && record->next && record->next->next &&
        !record->next->next->next,
        "got synchronized prerequisite records status %#lx record %p\n", status, record );
    expected_source_begin[3] = target_channel;
    expected_system_begin[3] = target_channel;
    check_dcomp_batch_payload( record, source_channel, expected_source_begin,
                               sizeof(expected_source_begin), "synchronized source begin" );
    check_dcomp_batch_payload( record ? record->next : NULL, system_channel,
                               expected_system_begin, sizeof(expected_system_begin),
                               "synchronized system begin" );
    check_dcomp_batch_payload( record && record->next ? record->next->next : NULL,
                               target_channel, expected_synchronized_complete,
                               sizeof(expected_synchronized_complete),
                               "synchronized completes" );
    selector = 0;
    record = (void *)0xdeadbeef;
    status = NtDCompositionGetConnectionBatch( connection, &selector, &record );
    ok( status == STATUS_SUCCESS && !record,
        "synchronized prerequisites leaked to default selector, status %#lx record %p\n",
        status, record );

    open[1] = 0x12;
    memcpy( open + 2, &shared, sizeof(shared) );
    open[4] = 0x59;
    memcpy( target_buffer, open, sizeof(open) );
    status = NtDCompositionProcessChannelBatchBuffer( target_channel, sizeof(open),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got framed source open status %#lx\n", status );
    open[1] = 0x13;
    memcpy( open + 2, &system, sizeof(system) );
    open[4] = 0x82;
    memcpy( target_buffer, open, sizeof(open) );
    status = NtDCompositionProcessChannelBatchBuffer( target_channel, sizeof(open),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got framed system open status %#lx\n", status );
    status = NtDCompositionBeginFrame( connection, &frame_info, &frame_id );
    ok( status == STATUS_SUCCESS && frame_id,
        "got prerequisite frame status %#lx ID %s\n",
        status, wine_dbgstr_longlong(frame_id) );
    status = NtDCompositionCommitChannel( target_channel, &batch, &state, 0,
                                           NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got framed prerequisite commit status %#lx\n", status );
    selector = frame_id;
    record = (void *)0xdeadbeef;
    status = NtDCompositionGetConnectionBatch( connection, &selector, &record );
    ok( status == STATUS_SUCCESS && !record,
        "frame split duplicate prerequisites, status %#lx record %p\n", status, record );
    confirm_info.frame_id = frame_id;
    status = NtDCompositionConfirmFrame( connection, &confirm_info );
    ok( status == STATUS_SUCCESS, "got prerequisite frame confirmation status %#lx\n", status );

    selector = 0;
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &selector, &record );
    ok( status == STATUS_SUCCESS && record && record->next && record->next->next &&
        !record->next->next->next,
        "got post-frame prerequisite records status %#lx record %p\n", status, record );
    check_dcomp_batch_payload( record, source_channel, expected_source_begin,
                               sizeof(expected_source_begin), "post-frame source begin" );
    check_dcomp_batch_payload( record ? record->next : NULL, system_channel,
                               expected_system_begin, sizeof(expected_system_begin),
                               "post-frame system begin" );
    check_dcomp_batch_payload( record && record->next ? record->next->next : NULL,
                               target_channel, expected_framed_complete,
                               sizeof(expected_framed_complete), "post-frame completes" );

done:
    if (system) CloseHandle( system );
    if (shared) CloseHandle( shared );
    if (target_channel) NtDCompositionDestroyChannel( target_channel );
    if (source_channel) NtDCompositionDestroyChannel( source_channel );
    if (connection) NtDCompositionDestroyConnection( connection );
    CloseHandle( event );
}

static void test_held_release_wire_id_reuse(void)
{
    static const UINT expected_initial[] = {
        16, 0x28, 1, 0x59,
        16, 0xb9, 1, 0,
    };
    static const UINT expected_source[] =
    {
        16, 0x28, 1, 0x6a,
        60, 0xf4, 1, 0, 0, 0, 0, 0, 0, 0x3f800000, 0x3f800000, 0x3f800000, 0, 0, 0,
        16, 0xf5, 1, 0,
    };
    static const UINT expected_held[] =
    {
        12, 0x27, 2,
        16, 0xb4, 1, 0x4321,
        12, 0x29, 1,
    };
    static const UINT expected_recreate[] =
    {
        16, 0x28, 3, 0x6a,
        60, 0xf4, 3, 0, 0, 0, 0, 0, 0, 0x3f800000, 0x3f800000, 0x3f800000, 0, 0, 0,
        16, 0xf5, 3, 0,
        16, 0xf5, 3, 0x1234,
    };
    struct
    {
        struct { void *next, *previous; } head;
        struct
        {
            void *next, *previous;
            UINT type, size;
            UINT data[4];
        } block;
    } protocol_list;
    UINT expected_begin[4] = {16, 0x26, 1, 0};
    struct dcomposition_connection_batch *record = NULL;
    HANDLE event, connection = NULL, shared = NULL;
    BYTE *source_buffer = NULL, *target_buffer = NULL, state, released;
    UINT source_channel = 0, target_channel = 0;
    UINT source_size = 0x1000, target_size = 0x1000;
    UINT command[6], batch;
    UINT64 cookie = 0;
    ULONG processed;
    NTSTATUS status;

    memset( &protocol_list, 0, sizeof(protocol_list) );
    protocol_list.head.next = protocol_list.head.previous = &protocol_list.block;
    protocol_list.block.next = protocol_list.block.previous = &protocol_list.head;
    protocol_list.block.type = 0x200;
    protocol_list.block.size = sizeof(protocol_list.block.data);
    protocol_list.block.data[0] = sizeof(protocol_list.block.data);
    protocol_list.block.data[1] = 0xb4;
    protocol_list.block.data[2] = 1;
    protocol_list.block.data[3] = 0x4321;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create held-release event, error %lu\n", GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got held-release connection status %#lx\n", status );
    status = NtDCompositionCreateChannel( &source_channel, &source_size,
                                           (void **)&source_buffer, 0 );
    ok( status == STATUS_SUCCESS, "got held-release source channel status %#lx\n", status );
    status = NtDCompositionCreateChannel( &target_channel, &target_size,
                                           (void **)&target_buffer, 0 );
    ok( status == STATUS_SUCCESS, "got held-release target channel status %#lx\n", status );
    if (!source_buffer || !target_buffer) goto done;
    status = NtDCompositionSetChannelConnectionId( target_channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got held-release target bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5 && !record->next,
        "got held-release target create status %#lx record %p\n", status, record );

    command[0] = 2; command[1] = 1; command[2] = 0x59; command[3] = 0;
    memcpy( target_buffer, command, 16 );
    status = NtDCompositionProcessChannelBatchBuffer( target_channel, 16,
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got held-release initial create status %#lx\n", status );
    status = NtDCompositionCommitChannel( target_channel, &batch, &state, 0,
                                           NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got held-release initial commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got held-release initial batch status %#lx\n", status );
    check_dcomp_batch_payload( record, target_channel, expected_initial,
                               sizeof(expected_initial), "held-release initial" );

    command[0] = 2; command[1] = 1; command[2] = 0x6a; command[3] = 1;
    memcpy( source_buffer, command, 16 );
    status = NtDCompositionProcessChannelBatchBuffer( source_channel, 16,
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got held-release source create status %#lx\n", status );
    command[0] = 9; command[1] = 1; command[2] = command[3] = 0;
    memcpy( source_buffer, command, 16 );
    status = NtDCompositionProcessChannelBatchBuffer( source_channel, 16,
                                                       &processed, &released );
    memcpy( &shared, source_buffer + 8, sizeof(shared) );
    ok( status == STATUS_SUCCESS && shared,
        "got held-release publish status %#lx handle %p\n", status, shared );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5 && !record->next,
        "got held-release source create record status %#lx record %p\n", status, record );

    command[0] = 3; command[1] = 2;
    memcpy( command + 2, &shared, sizeof(shared) );
    command[4] = 0x6a; command[5] = 0;
    memcpy( target_buffer, command, 24 );
    status = NtDCompositionProcessChannelBatchBuffer( target_channel, 24,
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got held-release open status %#lx\n", status );
    command[0] = 4; command[1] = 1;
    memcpy( target_buffer, command, 8 );
    status = NtDCompositionProcessChannelBatchBuffer( target_channel, 8,
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got held-release release status %#lx\n", status );
    status = NtDCompositionCommitChannel( target_channel, &batch, &state, 0,
                                           NULL, &protocol_list.head, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got held-release blocked commit status %#lx\n", status );
    record = (void *)0xdeadbeef;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && !record,
        "held-release batch escaped before source, status %#lx record %p\n", status, record );

    command[0] = 2; command[1] = 1; command[2] = 0x6a; command[3] = 0;
    memcpy( target_buffer, command, 16 );
    status = NtDCompositionProcessChannelBatchBuffer( target_channel, 16,
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got held-release recreation status %#lx\n", status );
    protocol_list.block.data[1] = 0xf5;
    protocol_list.block.data[3] = 0x1234;
    status = NtDCompositionCommitChannel( target_channel, &batch, &state, 0,
                                           NULL, &protocol_list.head, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got held-release recreation commit status %#lx\n", status );
    record = (void *)0xdeadbeef;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && !record,
        "held-release recreation escaped before source, status %#lx record %p\n", status, record );

    status = NtDCompositionCommitChannel( source_channel, &batch, &state, 0,
                                           NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got held-release source commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->next && record->next->next &&
        record->next->next->next && !record->next->next->next->next,
        "got held-release delivery status %#lx record %p\n", status, record );
    check_dcomp_batch_payload( record, source_channel, expected_source,
                               sizeof(expected_source), "held-release source" );
    expected_begin[3] = target_channel;
    check_dcomp_batch_payload( record ? record->next : NULL, source_channel,
                               expected_begin, sizeof(expected_begin), "held-release begin" );
    check_dcomp_batch_payload( record && record->next ? record->next->next : NULL,
                               target_channel, expected_held, sizeof(expected_held),
                               "held-release blocked batch" );
    check_dcomp_batch_payload( record && record->next && record->next->next ?
                               record->next->next->next : NULL, target_channel,
                               expected_recreate, sizeof(expected_recreate),
                               "held-release recreation batch" );

done:
    if (shared) CloseHandle( shared );
    if (target_channel) NtDCompositionDestroyChannel( target_channel );
    if (source_channel) NtDCompositionDestroyChannel( source_channel );
    if (connection) NtDCompositionDestroyConnection( connection );
    CloseHandle( event );
}

static void test_created_shared_resource_duplication(void)
{
    static const UINT expected_system_resource[] = {16, 0x28, 1, 0x82};
    UINT expected_complete[] = {12, 0x27, 2};
    struct dcomposition_connection_batch *record = NULL;
    HANDLE event, connection = NULL, shared = NULL, duplicate = NULL;
    BYTE *first_buffer = NULL, *second_buffer = NULL, state, released;
    UINT first_channel = 0, second_channel = 0, system_channel = 0;
    UINT first_size = 0x1000, second_size = 0x1000;
    UINT expected_begin[4] = {16, 0x26, 1, 0};
    UINT command[6], batch;
    UINT64 cookie = 0;
    ULONG processed;
    NTSTATUS status;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create shared-resource event, error %lu\n", GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got shared-resource connection status %#lx\n", status );
    status = NtDCompositionCreateChannel( &first_channel, &first_size,
                                           (void **)&first_buffer, 0 );
    ok( status == STATUS_SUCCESS, "got first shared-resource channel status %#lx\n", status );
    status = NtDCompositionCreateChannel( &second_channel, &second_size,
                                           (void **)&second_buffer, 0 );
    ok( status == STATUS_SUCCESS, "got second shared-resource channel status %#lx\n", status );
    if (!first_buffer || !second_buffer) goto done;
    status = NtDCompositionSetChannelConnectionId( first_channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got first shared-resource bind status %#lx\n", status );
    status = NtDCompositionSetChannelConnectionId( second_channel, 0, 2 );
    ok( status == STATUS_SUCCESS, "got second shared-resource bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->next,
        "got destination create records status %#lx record %p\n", status, record );

    status = NtDCompositionCreateSharedResourceHandle( 0x82, &shared );
    ok( status == STATUS_SUCCESS, "got shared-resource handle status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5 && record->next,
        "got system-channel create status %#lx record %p\n", status, record );
    if (record)
    {
        system_channel = record->u.create.channel;
        check_dcomp_batch_payload( record->next, system_channel, expected_system_resource,
                                   sizeof(expected_system_resource), "system shared resource" );
    }

    command[0] = 3;
    command[1] = 1;
    memcpy( command + 2, &shared, sizeof(shared) );
    command[4] = 0x82;
    command[5] = 0;
    memcpy( first_buffer, command, sizeof(command) );
    status = NtDCompositionProcessChannelBatchBuffer( first_channel, sizeof(command),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got first shared-resource open status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    expected_begin[3] = first_channel;
    check_dcomp_batch_payload( record, system_channel, expected_begin,
                               sizeof(expected_begin), "first system begin" );

    status = NtDuplicateObject( NtCurrentProcess(), shared, NtCurrentProcess(), &duplicate,
                                0, 0, DUPLICATE_SAME_ACCESS );
    ok( status == STATUS_SUCCESS, "got shared-resource duplicate status %#lx\n", status );
    command[1] = 2;
    memcpy( command + 2, &duplicate, sizeof(duplicate) );
    memcpy( second_buffer, command, sizeof(command) );
    status = NtDCompositionProcessChannelBatchBuffer( second_channel, sizeof(command),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got second shared-resource open status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    expected_begin[3] = second_channel;
    check_dcomp_batch_payload( record, system_channel, expected_begin,
                               sizeof(expected_begin), "second system begin" );

    status = NtDCompositionCommitChannel( second_channel, &batch, &state, 0,
                                           NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got second shared-resource commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    check_dcomp_batch_payload( record, second_channel, expected_complete,
                               sizeof(expected_complete), "second shared-resource complete" );

    expected_complete[2] = 1;
    status = NtDCompositionCommitChannel( first_channel, &batch, &state, 0,
                                           NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got first shared-resource commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    check_dcomp_batch_payload( record, first_channel, expected_complete,
                               sizeof(expected_complete),
                               "first shared-resource complete" );

done:
    if (duplicate) NtClose( duplicate );
    if (shared) NtClose( shared );
    if (second_channel) NtDCompositionDestroyChannel( second_channel );
    if (first_channel) NtDCompositionDestroyChannel( first_channel );
    if (connection) NtDCompositionDestroyConnection( connection );
    CloseHandle( event );
}

static void test_multi_source_shared_resource_duplication(void)
{
    static const UINT expected_first_resource[] = {16, 0x28, 1, 0x82};
    static const UINT expected_second_resource[] = {16, 0x28, 2, 0x82};
    static const UINT expected_complete[] = {12, 0x27, 5, 12, 0x27, 6, 12, 0x27, 7};
    struct dcomposition_connection_batch *record = NULL;
    HANDLE event, connection = NULL, shared[2] = {NULL};
    BYTE *buffer = NULL, state, released;
    UINT channel = 0, system_channel = 0, size = 0x1000;
    UINT expected_begin[4] = {16, 0x26, 0, 0};
    UINT commands[18], batch;
    static const UINT source_order[] = {0, 1, 0};
    UINT64 cookie = 0;
    ULONG processed;
    NTSTATUS status;
    unsigned int i;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create multi-resource event, error %lu\n", GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got multi-resource connection status %#lx\n", status );
    status = NtDCompositionCreateChannel( &channel, &size, (void **)&buffer, 0 );
    ok( status == STATUS_SUCCESS, "got multi-resource channel status %#lx\n", status );
    if (!buffer) goto done;

    for (i = 0; i < ARRAY_SIZE(shared); ++i)
    {
        status = NtDCompositionCreateSharedResourceHandle( 0x82, &shared[i] );
        ok( status == STATUS_SUCCESS, "got shared resource %u status %#lx\n", i, status );
    }
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5 && record->next &&
        record->next->next, "got system resource records status %#lx record %p\n",
        status, record );
    if (record)
    {
        system_channel = record->u.create.channel;
        check_dcomp_batch_payload( record->next, system_channel, expected_first_resource,
                                   sizeof(expected_first_resource), "first system resource" );
        check_dcomp_batch_payload( record->next ? record->next->next : NULL,
                                   system_channel, expected_second_resource,
                                   sizeof(expected_second_resource), "second system resource" );
    }

    memset( commands, 0, sizeof(commands) );
    for (i = 0; i < ARRAY_SIZE(source_order); ++i)
    {
        commands[i * 6] = 3;
        commands[i * 6 + 1] = i + 5;
        memcpy( commands + i * 6 + 2, &shared[source_order[i]], sizeof(shared[0]) );
        commands[i * 6 + 4] = 0x82;
    }
    memcpy( buffer, commands, sizeof(commands) );
    status = NtDCompositionProcessChannelBatchBuffer( channel, sizeof(commands),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got multi-resource opens status %#lx\n", status );
    record = (void *)0xdeadbeef;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && !record,
        "multi-resource begins escaped before destination bind, status %#lx record %p\n",
        status, record );

    status = NtDCompositionSetChannelConnectionId( channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got multi-resource bind status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5 && record->next &&
        record->next->next && record->next->next->next,
        "got multi-resource begins status %#lx record %p\n", status, record );
    expected_begin[2] = 1;
    expected_begin[3] = channel;
    check_dcomp_batch_payload( record ? record->next : NULL, system_channel, expected_begin,
                               sizeof(expected_begin), "first system begin" );
    expected_begin[2] = 2;
    check_dcomp_batch_payload( record && record->next ? record->next->next : NULL,
                               system_channel, expected_begin,
                               sizeof(expected_begin), "second system begin" );
    expected_begin[2] = 1;
    check_dcomp_batch_payload( record && record->next && record->next->next ?
                               record->next->next->next : NULL, system_channel, expected_begin,
                               sizeof(expected_begin), "repeated first system begin" );

    status = NtDCompositionCommitChannel( channel, &batch, &state, 0,
                                           NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got multi-resource commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    check_dcomp_batch_payload( record, channel, expected_complete,
                               sizeof(expected_complete), "multi-resource complete" );

done:
    for (i = 0; i < ARRAY_SIZE(shared); ++i)
        if (shared[i]) NtClose( shared[i] );
    if (channel) NtDCompositionDestroyChannel( channel );
    if (connection) NtDCompositionDestroyConnection( connection );
    CloseHandle( event );
}
static NTSTATUS process_dcomp_test_command( UINT channel, BYTE *buffer,
                                             const UINT *command, UINT size )
{
    ULONG processed;
    BYTE released;

    memcpy( buffer, command, size );
    return NtDCompositionProcessChannelBatchBuffer( channel, size, &processed, &released );
}

static void test_region_clip_protocol(void)
{
    static const UINT create[] = {2, 1, 0x82, 0};
    static const UINT expected_create[] = {16, 0x28, 1, 0x82};
    static const UINT rectangles[] =
    {
        15, 1, 5, 32,
        10, 20, 110, 220,
        300, 400, 500, 600,
    };
    static const UINT expected_rectangles[] =
    {
        48, 0x234, 1, 32,
        10, 20, 110, 220,
        300, 400, 500, 600,
    };
    static const UINT replacement[] = {15, 1, 5, 16, 1, 2, 3, 4};
    static const UINT expected_replacement[] = {32, 0x234, 1, 16, 1, 2, 3, 4};
    static const UINT empty[] = {15, 1, 5, 0};
    static const UINT expected_empty[] = {16, 0x234, 1, 0};
    static const UINT bad_property[] = {15, 1, 4, 0};
    static const UINT bad_size[] = {15, 1, 5, 4, 0};
    struct dcomposition_connection_batch *record = NULL;
    HANDLE event, connection = NULL;
    BYTE *buffer = NULL, state;
    UINT channel = 0, size = 0x1000, batch;
    UINT64 cookie = 0;
    NTSTATUS status;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create region-clip event, error %lu\n", GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got region-clip connection status %#lx\n", status );
    status = NtDCompositionCreateChannel( &channel, &size, (void **)&buffer, 0 );
    ok( status == STATUS_SUCCESS, "got region-clip channel status %#lx\n", status );
    if (status) goto done;
    status = NtDCompositionSetChannelConnectionId( channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got region-clip bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5,
        "got region-clip create record status %#lx record %p type %u\n",
        status, record, record ? record->type : 0 );

    status = process_dcomp_test_command( channel, buffer, create, sizeof(create) );
    ok( status == STATUS_SUCCESS, "got region-clip create status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got region-clip create commit status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got region-clip create batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_create,
                               sizeof(expected_create), "region-clip create" );

    status = process_dcomp_test_command( channel, buffer, bad_property, sizeof(bad_property) );
    ok( status == STATUS_INVALID_PARAMETER, "got region-clip bad property status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, bad_size, sizeof(bad_size) );
    ok( status == STATUS_INVALID_PARAMETER, "got region-clip bad size status %#lx\n", status );

    status = process_dcomp_test_command( channel, buffer, rectangles, sizeof(rectangles) );
    ok( status == STATUS_SUCCESS, "got region-clip rectangle status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got region-clip rectangle commit status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got region-clip rectangle batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_rectangles,
                               sizeof(expected_rectangles), "region-clip rectangles" );

    status = process_dcomp_test_command( channel, buffer, replacement, sizeof(replacement) );
    ok( status == STATUS_SUCCESS, "got region-clip replacement status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got region-clip replacement commit status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got region-clip replacement batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_replacement,
                               sizeof(expected_replacement), "region-clip replacement" );

    status = process_dcomp_test_command( channel, buffer, empty, sizeof(empty) );
    ok( status == STATUS_SUCCESS, "got region-clip empty status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got region-clip empty commit status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got region-clip empty batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_empty,
                               sizeof(expected_empty), "region-clip empty" );

done:
    if (buffer) NtDCompositionDestroyChannel( channel );
    if (connection) NtDCompositionDestroyConnection( connection );
    CloseHandle( event );
}

static void test_expression_graph(void)
{
    static const UINT expected[] = {
        16, 0x28, 1, 0x7c,
        16, 0x28, 2, 0x9d,
        16, 0x28, 3, 0x3c,
        32, 0x135, 1, 0, 0, 0x12, 1, 0x3f800000,
        92, 0x135, 1, 1, 4, 0x109, 1,
            0x3f800000, 0, 0, 0,
            0, 0x3f800000, 0, 0,
            0, 0, 0x3f800000, 0,
            0, 0, 0, 0x3f800000,
        32, 0x135, 1, 2, 68, 0x11, 1, 1,
        32, 0x135, 1, 3, 69, 0x11, 1, 0,
        44, 0x11, 3, 0x7c, 1, 7, 0, 0, 0, 0, 0x109,
        16, 0x12, 3, 0,
        24, 0x89, 3, 1, 1, 1,
        40, 0x88, 3, 1, 1, 5, 0x109, 0x20, 0x30, 0x40,
        24, 0x86, 3, 2, 0x100, 0x20,
    };
    static const UINT expected_property_update[] = {
        32, 0x135, 1, 0, 0, 0x12, 0, 0x3f000000,
    };
    static const UINT create[] = {
        2, 1, 0x7c, 0,
        2, 2, 0x9d, 0,
        2, 3, 0x3c, 0,
    };
    static const UINT property[] = {15, 1, 1, 16, 0, 0, 0x12, 0x3f800000};
    static const UINT matrix_property[] = {
        15, 1, 1, 76, 1, 4, 0x109,
        0x3f800000, 0, 0, 0,
        0, 0x3f800000, 0, 0,
        0, 0, 0x3f800000, 0,
        0, 0, 0, 0x3f800000,
    };
    static const UINT boolean_property[] = {15, 1, 1, 16, 2, 68, 0x11, 1};
    static const UINT second_boolean_property[] = {15, 1, 1, 16, 3, 69, 0x11, 0};
    static const UINT property_update[] = {15, 1, 2, 16, 0, 0, 0x12, 0x3f000000};
    static const UINT shared_reference[] = {16, 3, 0x0a, 2};
    static const UINT node_offset[] = {11, 3, 0x0b, 0, 0x100, 0};
    static const UINT node_size[] = {11, 3, 0x0c, 0, 0x20, 0};
    static const UINT expression_type[] = {11, 3, 0, 0, 0x109, 0};
    static const UINT sources[] = {17, 3, 0x0d, 1, 1};
    static const UINT reference_info[] = {15, 3, 0x0e, 20, 5, 0x109, 0x20, 0x30, 0x40};
    static const UINT property_reference[] = {16, 3, 2, 1};
    static const UINT property_index[] = {11, 3, 3, 0, 7, 0};
    static const UINT property_enabled[] = {11, 3, 1, 0, 1, 0};
    static const UINT empty_metadata[] = {15, 3, 5, 0};
    struct dcomposition_connection_batch *record = NULL;
    HANDLE event, connection = NULL;
    BYTE *buffer = NULL, state;
    UINT channel = 0, size = 0x1000, batch;
    UINT64 cookie = 0;
    NTSTATUS status;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create expression event, error %lu\n", GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got expression connection status %#lx\n", status );
    status = NtDCompositionCreateChannel( &channel, &size, (void **)&buffer, 0 );
    ok( status == STATUS_SUCCESS, "got expression channel status %#lx\n", status );
    if (status) goto done;
    status = NtDCompositionSetChannelConnectionId( channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got expression bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5,
        "got expression create record status %#lx record %p type %u\n",
        status, record, record ? record->type : 0 );

    status = process_dcomp_test_command( channel, buffer, create, sizeof(create) );
    ok( status == STATUS_SUCCESS, "got expression create status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, property, sizeof(property) );
    ok( status == STATUS_SUCCESS, "got property-set status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, matrix_property,
                                         sizeof(matrix_property) );
    ok( status == STATUS_SUCCESS, "got matrix property-set status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, boolean_property,
                                         sizeof(boolean_property) );
    ok( status == STATUS_SUCCESS, "got boolean property-set status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, second_boolean_property,
                                         sizeof(second_boolean_property) );
    ok( status == STATUS_SUCCESS, "got second boolean property-set status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, shared_reference,
                                         sizeof(shared_reference) );
    ok( status == STATUS_SUCCESS, "got shared reference status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, node_offset, sizeof(node_offset) );
    ok( status == STATUS_SUCCESS, "got node-offset status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, node_size, sizeof(node_size) );
    ok( status == STATUS_SUCCESS, "got node-size status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, expression_type,
                                         sizeof(expression_type) );
    ok( status == STATUS_SUCCESS, "got expression-type status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, sources, sizeof(sources) );
    ok( status == STATUS_SUCCESS, "got expression sources status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, reference_info,
                                         sizeof(reference_info) );
    ok( status == STATUS_SUCCESS, "got reference-info status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, property_reference,
                                         sizeof(property_reference) );
    ok( status == STATUS_SUCCESS, "got property reference status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, property_index,
                                         sizeof(property_index) );
    ok( status == STATUS_SUCCESS, "got property index status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, property_enabled,
                                         sizeof(property_enabled) );
    ok( status == STATUS_SUCCESS, "got property enabled status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, empty_metadata,
                                         sizeof(empty_metadata) );
    ok( status == STATUS_SUCCESS, "got expression metadata status %#lx\n", status );

    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got expression commit status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got expression batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected, sizeof(expected), "expression graph" );

    status = process_dcomp_test_command( channel, buffer, property_update,
                                         sizeof(property_update) );
    ok( status == STATUS_SUCCESS, "got property update status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got property update commit status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got property update batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_property_update,
                               sizeof(expected_property_update), "property update" );

    status = process_dcomp_test_command( channel, buffer, sources, sizeof(sources) );
    ok( status == STATUS_ACCESS_DENIED, "got repeated expression sources status %#lx\n", status );

done:
    if (buffer) NtDCompositionDestroyChannel( channel );
    if (connection) NtDCompositionDestroyConnection( connection );
    CloseHandle( event );
}

static void test_expression_weak_reference_reuse(void)
{
    static const UINT expected_source[] = {16, 0x28, 1, 0x7c};
    static const UINT expected_expression[] = {
        16, 0x28, 2, 0x3c,
        16, 0x28, 3, 0x28,
        44, 0x11, 2, 0, 0, 0, 0, 0, 0, 0, 0,
        16, 0x12, 2, 0,
        24, 0x89, 2, 1, 1, 0,
        12, 0x29, 1,
    };
    static const UINT create_source[] = {2, 1, 0x7c, 0};
    static const UINT create_expression[] = {2, 2, 0x3c, 0};
    static const UINT sources[] = {17, 2, 0x0d, 1, 1};
    static const UINT property_reference[] = {16, 2, 2, 1};
    static const UINT property_enabled[] = {11, 2, 1, 0, 1, 0};
    static const UINT release_source[] = {4, 1};
    static const UINT create_replacement[] = {2, 1, 0x28, 0};
    struct dcomposition_connection_batch *record = NULL;
    HANDLE event, connection = NULL;
    BYTE *buffer = NULL, state;
    UINT channel = 0, size = 0x1000, batch;
    UINT64 cookie = 0;
    NTSTATUS status;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create expression weak-reference event, error %lu\n",
        GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got expression weak-reference connection status %#lx\n",
        status );
    status = NtDCompositionCreateChannel( &channel, &size, (void **)&buffer, 0 );
    ok( status == STATUS_SUCCESS, "got expression weak-reference channel status %#lx\n",
        status );
    if (status) goto done;
    status = NtDCompositionSetChannelConnectionId( channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got expression weak-reference bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5,
        "got expression weak-reference create record status %#lx record %p type %u\n",
        status, record, record ? record->type : 0 );

    status = process_dcomp_test_command( channel, buffer, create_source, sizeof(create_source) );
    ok( status == STATUS_SUCCESS, "got expression source create status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got expression source commit status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got expression source batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_source,
                               sizeof(expected_source), "expression source" );

    status = process_dcomp_test_command( channel, buffer, create_expression,
                                         sizeof(create_expression) );
    ok( status == STATUS_SUCCESS, "got expression reuse create status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, sources, sizeof(sources) );
    ok( status == STATUS_SUCCESS, "got expression reuse sources status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, property_reference,
                                         sizeof(property_reference) );
    ok( status == STATUS_SUCCESS, "got expression reuse property reference status %#lx\n",
        status );
    status = process_dcomp_test_command( channel, buffer, property_enabled,
                                         sizeof(property_enabled) );
    ok( status == STATUS_SUCCESS, "got expression reuse property enabled status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, release_source,
                                         sizeof(release_source) );
    ok( status == STATUS_SUCCESS, "got expression source release status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, create_replacement,
                                         sizeof(create_replacement) );
    ok( status == STATUS_SUCCESS, "got expression source replacement status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got expression reuse commit status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got expression reuse batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_expression,
                               sizeof(expected_expression), "expression weak-reference reuse" );

done:
    if (buffer) NtDCompositionDestroyChannel( channel );
    if (connection) NtDCompositionDestroyConnection( connection );
    CloseHandle( event );
}

static void test_keyframe_animation_protocol(void)
{
    static const UINT expected[] = {
        16, 0x28, 1, 0x9d,
        16, 0x28, 2, 0x02,
        16, 0x28, 3, 0x5c,
        24, 9, 2, 1, 0x80, 0x60,
        16, 8, 2, 1,
        28, 10, 2, 0x1234, 0, 0, 0,
        12, 6, 2,
        44, 0x11, 3, 0, 0, 0, 0, 0, 0, 0, 0x12,
        16, 0x12, 3, 0,
        72, 0xd4, 3, 7, 1, 0x1388, 0x150, 0, 0x3f800000,
            0, 0, 0, 2, 0, 0, 0, 0, 0,
        36, 0xda, 3, 0, 0, 0, 0, 1, 0,
        16, 0xd7, 3, 0,
        16, 0xd8, 3, 0,
        16, 0xd6, 3, 0x3f800000,
    };
    static const UINT create[] = {
        2, 1, 0x9d, 0,
        2, 2, 0x02, 0,
        2, 3, 0x5c, 0,
    };
    static const UINT primitive_reference[] = {16, 2, 0, 1};
    static const UINT primitive_offset[] = {11, 2, 1, 0, 0x80, 0};
    static const UINT primitive_size[] = {11, 2, 2, 0, 0x60, 0};
    static const UINT instance[] = {11, 2, 0x0a, 0, 1, 0};
    static const UINT paused[] = {15, 2, 0x0b, 1, 1};
    static const UINT seek[] = {15, 2, 0x0c, 8, 0x1234, 0};
    static const UINT expression_type[] = {11, 3, 0, 0, 0x12, 0};
    static const UINT keyframe_type[] = {11, 3, 0x0a, 0, 7, 0};
    static const UINT duration[] = {11, 3, 0x0c, 0, 0x1388, 0};
    static const UINT iterations[] = {11, 3, 0x0d, 0, 0x150, 0};
    static const UINT value_reference[] = {16, 3, 0x0b, 1};
    static const UINT animation_reference[] = {16, 3, 0x18, 2};
    struct dcomposition_connection_batch *record = NULL;
    HANDLE event, connection = NULL;
    BYTE *buffer = NULL, state;
    UINT channel = 0, size = 0x1000, batch;
    UINT64 cookie = 0;
    NTSTATUS status;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create keyframe event, error %lu\n", GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got keyframe connection status %#lx\n", status );
    status = NtDCompositionCreateChannel( &channel, &size, (void **)&buffer, 0 );
    ok( status == STATUS_SUCCESS, "got keyframe channel status %#lx\n", status );
    if (status) goto done;
    status = NtDCompositionSetChannelConnectionId( channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got keyframe bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5,
        "got keyframe create record status %#lx record %p type %u\n",
        status, record, record ? record->type : 0 );

    status = process_dcomp_test_command( channel, buffer, create, sizeof(create) );
    ok( status == STATUS_SUCCESS, "got keyframe create status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, primitive_reference,
                                         sizeof(primitive_reference) );
    ok( status == STATUS_SUCCESS, "got animation primitive reference status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, primitive_offset,
                                         sizeof(primitive_offset) );
    ok( status == STATUS_SUCCESS, "got animation primitive offset status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, primitive_size,
                                         sizeof(primitive_size) );
    ok( status == STATUS_SUCCESS, "got animation primitive size status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, instance, sizeof(instance) );
    ok( status == STATUS_SUCCESS, "got animation instance status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, paused, sizeof(paused) );
    ok( status == STATUS_SUCCESS, "got animation paused status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, seek, sizeof(seek) );
    ok( status == STATUS_SUCCESS, "got animation seek status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, expression_type,
                                         sizeof(expression_type) );
    ok( status == STATUS_SUCCESS, "got keyframe expression type status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, keyframe_type,
                                         sizeof(keyframe_type) );
    ok( status == STATUS_SUCCESS, "got keyframe type status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, duration, sizeof(duration) );
    ok( status == STATUS_SUCCESS, "got keyframe duration status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, iterations, sizeof(iterations) );
    ok( status == STATUS_SUCCESS, "got keyframe iteration status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, value_reference,
                                         sizeof(value_reference) );
    ok( status == STATUS_SUCCESS, "got keyframe value reference status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, animation_reference,
                                         sizeof(animation_reference) );
    ok( status == STATUS_SUCCESS, "got keyframe animation reference status %#lx\n", status );

    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got keyframe commit status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got keyframe batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected, sizeof(expected),
                               "keyframe animation" );

done:
    if (buffer) NtDCompositionDestroyChannel( channel );
    if (connection) NtDCompositionDestroyConnection( connection );
    CloseHandle( event );
}

static void test_shared_manipulation_transform(void)
{
    struct dcomposition_connection_batch *record = NULL;
    static const float components[12] =
    {
        1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f,
        7.0f, 8.0f, 9.0f, 10.0f, 11.0f, 12.0f,
    };
    static const float update[3] = {13.0f, 14.0f, 15.0f};
    BYTE expected_owner[92] = {0}, expected_update[60] = {0};
    struct dcomp_test_protocol_list protocol_list;
    UINT owner_command[16], reader_command[6], expected_begin[4], expected_reader[5];
    HANDLE event, connection = NULL, shared = NULL;
    BYTE *owner_buffer = NULL, *reader_buffer = NULL, state, released;
    UINT owner_channel = 0, reader_channel = 0, owner_size = 0x1000, reader_size = 0x1000;
    UINT batch, property, expected[15];
    UINT64 cookie = 0;
    ULONG processed;
    NTSTATUS status;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create shared-transform event, error %lu\n", GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got shared-transform connection status %#lx\n", status );
    status = NtDCompositionCreateChannel( &owner_channel, &owner_size,
                                           (void **)&owner_buffer, 0x90 );
    ok( status == STATUS_SUCCESS, "got owner channel status %#lx\n", status );
    status = NtDCompositionCreateChannel( &reader_channel, &reader_size,
                                           (void **)&reader_buffer, 0 );
    ok( status == STATUS_SUCCESS, "got reader channel status %#lx\n", status );
    if (!owner_buffer || !reader_buffer) goto done;
    status = NtDCompositionSetChannelConnectionId( reader_channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got reader bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5,
        "got reader create status %#lx record %p type %u\n",
        status, record, record ? record->type : 0 );

    owner_command[0] = 2;
    owner_command[1] = 1;
    owner_command[2] = 0x6a;
    owner_command[3] = 1;
    memcpy( owner_buffer, owner_command, 16 );
    status = NtDCompositionProcessChannelBatchBuffer( owner_channel, 16,
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got shared-transform create status %#lx\n", status );
    owner_command[0] = 15;
    owner_command[1] = 1;
    owner_command[2] = 1;
    owner_command[3] = 8;
    memcpy( owner_buffer, owner_command, 24 );
    status = NtDCompositionProcessChannelBatchBuffer( owner_channel, 24,
                                                       &processed, &released );
    ok( status == STATUS_INVALID_PARAMETER, "got short property status %#lx\n", status );
    owner_command[2] = 5;
    owner_command[3] = 12;
    memcpy( owner_buffer, owner_command, 28 );
    status = NtDCompositionProcessChannelBatchBuffer( owner_channel, 28,
                                                       &processed, &released );
    ok( status == STATUS_INVALID_PARAMETER, "got unknown property status %#lx\n", status );
    for (property = 1; property <= 4; ++property)
    {
        owner_command[0] = 15;
        owner_command[1] = 1;
        owner_command[2] = property;
        owner_command[3] = 12;
        memcpy( owner_command + 4, components + (property - 1) * 3, 12 );
        memcpy( owner_buffer, owner_command, 28 );
        status = NtDCompositionProcessChannelBatchBuffer( owner_channel, 28,
                                                           &processed, &released );
        ok( status == STATUS_SUCCESS, "property %u got status %#lx\n", property, status );
    }
    owner_command[0] = 11;
    owner_command[1] = 1;
    owner_command[2] = 6;
    owner_command[3] = 0;
    owner_command[4] = 0x12345678;
    owner_command[5] = 0;
    memcpy( owner_buffer, owner_command, 24 );
    status = NtDCompositionProcessChannelBatchBuffer( owner_channel, 24,
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got tracing-cookie status %#lx\n", status );
    status = NtDCompositionCommitChannel( owner_channel, &batch, &state, 0,
                                           NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got owner commit status %#lx\n", status );
    record = (void *)0xdeadbeef;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && !record,
        "unpublished owner returned status %#lx record %p\n", status, record );

    owner_command[0] = 9;
    owner_command[1] = 1;
    owner_command[2] = owner_command[3] = 0;
    memcpy( owner_buffer, owner_command, 16 );
    status = NtDCompositionProcessChannelBatchBuffer( owner_channel, 16,
                                                       &processed, &released );
    memcpy( &shared, owner_buffer + 8, sizeof(shared) );
    ok( status == STATUS_SUCCESS, "got publish status %#lx\n", status );
    ok( !!shared, "got null published handle\n" );

    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5,
        "got owner create status %#lx record %p type %u\n",
        status, record, record ? record->type : 0 );
    if (record) ok( record->u.create.channel == owner_channel,
                    "got owner create channel %#x\n", record->u.create.channel );
    if (record) record = record->next;

    expected[0] = 16; expected[1] = 0x28; expected[2] = 1; expected[3] = 0x6a;
    memcpy( expected_owner, expected, 16 );
    expected[0] = 60; expected[1] = 0xf4; expected[2] = 1;
    memcpy( expected + 3, components, sizeof(components) );
    memcpy( expected_owner + 16, expected, 60 );
    expected[0] = 16; expected[1] = 0xf5; expected[2] = 1; expected[3] = 0x12345678;
    memcpy( expected_owner + 76, expected, 16 );
    check_dcomp_batch_payload( record, owner_channel, (const UINT *)expected_owner,
                               sizeof(expected_owner), "shared-transform owner" );

    reader_command[0] = 3;
    reader_command[1] = 0x11;
    memcpy( reader_command + 2, &shared, sizeof(shared) );
    reader_command[4] = 0x6a;
    reader_command[5] = 1;
    memcpy( reader_buffer, reader_command, sizeof(reader_command) );
    status = NtDCompositionProcessChannelBatchBuffer( reader_channel,
                                                       sizeof(reader_command),
                                                       &processed, &released );
    ok( status == STATUS_NOT_SUPPORTED, "got unsupported shared mode status %#lx\n", status );
    reader_command[4] = 0x6b;
    reader_command[5] = 0;
    memcpy( reader_buffer, reader_command, sizeof(reader_command) );
    status = NtDCompositionProcessChannelBatchBuffer( reader_channel,
                                                       sizeof(reader_command),
                                                       &processed, &released );
    ok( status == STATUS_INVALID_PARAMETER, "got mismatched shared type status %#lx\n", status );
    reader_command[4] = 0x6a;
    memcpy( reader_buffer, reader_command, sizeof(reader_command) );
    status = NtDCompositionProcessChannelBatchBuffer( reader_channel,
                                                       sizeof(reader_command),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got shared open status %#lx\n", status );
    expected_begin[0] = 16;
    expected_begin[1] = 0x26;
    expected_begin[2] = 1;
    expected_begin[3] = reader_channel;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got begin-duplicate status %#lx\n", status );
    check_dcomp_batch_payload( record, owner_channel, expected_begin,
                               sizeof(expected_begin), "shared-transform begin" );

    init_dcomp_test_protocol_list( &protocol_list );
    status = NtDCompositionCommitChannel( reader_channel, &batch, &state, 0,
                                           NULL, &protocol_list.head, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got reader commit status %#lx\n", status );
    expected_reader[0] = 12;
    expected_reader[1] = 0x27;
    expected_reader[2] = 0x11;
    memcpy( expected_reader + 3, protocol_list.block.data,
            sizeof(protocol_list.block.data) );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got complete-duplicate status %#lx\n", status );
    check_dcomp_batch_payload( record, reader_channel, expected_reader,
                               sizeof(expected_reader), "shared-transform complete" );

    owner_command[0] = 15;
    owner_command[1] = 1;
    owner_command[2] = 2;
    owner_command[3] = 12;
    memcpy( owner_command + 4, update, sizeof(update) );
    memcpy( owner_buffer, owner_command, 28 );
    status = NtDCompositionProcessChannelBatchBuffer( owner_channel, 28,
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got shared update status %#lx\n", status );
    status = NtDCompositionCommitChannel( owner_channel, &batch, &state, 0,
                                           NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got shared update commit status %#lx\n", status );
    expected[0] = 60; expected[1] = 0xf4; expected[2] = 1;
    memcpy( expected + 3, components, sizeof(components) );
    memcpy( expected + 6, update, sizeof(update) );
    memcpy( expected_update, expected, sizeof(expected_update) );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got shared update payload status %#lx\n", status );
    check_dcomp_batch_payload( record, owner_channel, (const UINT *)expected_update,
                               sizeof(expected_update), "shared-transform update" );

done:
    if (shared) CloseHandle( shared );
    if (reader_channel) NtDCompositionDestroyChannel( reader_channel );
    if (owner_channel) NtDCompositionDestroyChannel( owner_channel );
    if (connection) NtDCompositionDestroyConnection( connection );
    CloseHandle( event );
}

static void test_shared_host_visual_lifecycle(void)
{
    static const UINT expected_system_resource[] = {16, 0x28, 1, 0xb8};
    static const UINT expected[] =
    {
        16, 0x28, 1, 0xb8,
        12, 0x27, 2,
        24, 0x185, 1, 2, 0, 1,
    };
    struct dcomposition_connection_batch *record = NULL;
    HANDLE event, connection = NULL, target = NULL;
    BYTE *buffer = NULL, state, released;
    UINT channel = 0, system_channel = 0, size = 0x1000, batch, command[10];
    UINT expected_begin[4] = {16, 0x26, 1, 0};
    UINT64 cookie = 0, shared;
    ULONG processed;
    NTSTATUS status;
    HWND hwnd = NULL;
    BOOL ret;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create host-visual event, error %lu\n", GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got host-visual connection status %#lx\n", status );
    hwnd = CreateWindowExA( 0, "static", "host visual target", WS_POPUP, 0, 0, 32, 32,
                            NULL, NULL, NULL, NULL );
    ok( !!hwnd, "failed to create host-visual window, error %lu\n", GetLastError() );
    ret = hwnd && NtUserCreateDCompositionHwndTarget( hwnd, 1, &target );
    ok( ret, "failed to create host-visual target, status %#lx\n", RtlGetLastNtStatus() );
    if (!ret) goto done;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5 && record->next,
        "got host-visual system records status %#lx record %p\n", status, record );
    if (record)
    {
        system_channel = record->u.create.channel;
        check_dcomp_batch_payload( record->next, system_channel, expected_system_resource,
                                   sizeof(expected_system_resource), "host-visual system resource" );
    }
    status = NtDCompositionCreateChannel( &channel, &size, (void **)&buffer, 0 );
    ok( status == STATUS_SUCCESS, "got host-visual channel status %#lx\n", status );
    if (status) goto done;
    status = NtDCompositionSetChannelConnectionId( channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got host-visual bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5,
        "got host-visual create record status %#lx record %p type %u\n",
        status, record, record ? record->type : 0 );

    command[0] = 2; command[1] = 1; command[2] = 0xb8; command[3] = 0;
    command[4] = 3; command[5] = 2;
    shared = (UINT_PTR)target;
    memcpy( command + 6, &shared, sizeof(shared) );
    command[8] = 0xb8; command[9] = 1;
    memcpy( buffer, command, sizeof(command) );
    status = NtDCompositionProcessChannelBatchBuffer( channel, sizeof(command),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got host-visual open status %#lx\n", status );
    ok( processed == 2, "got host-visual open process count %lu\n", processed );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    expected_begin[3] = channel;
    check_dcomp_batch_payload( record, system_channel, expected_begin,
                               sizeof(expected_begin), "host-visual system begin" );

    command[0] = 20; command[1] = 1; command[2] = 2; command[3] = 1; command[4] = 0;
    memcpy( buffer, command, 20 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 20, &processed, &released );
    ok( status == STATUS_SUCCESS, "got host-visual child status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got host-visual commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got host-visual batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected, sizeof(expected), "host visual" );

done:
    if (channel) NtDCompositionDestroyChannel( channel );
    if (target) CloseHandle( target );
    if (connection) NtDCompositionDestroyConnection( connection );
    if (hwnd) DestroyWindow( hwnd );
    CloseHandle( event );
}

static void test_window_target_shared_identity(void)
{
    static const UINT expected_system_resource[] = {16, 0x28, 1, 0xb8};
    UINT expected_begin[4] = {16, 0x26, 1, 0};
    UINT expected_complete[3] = {12, 0x27, 1};
    struct dcomposition_connection_batch *record = NULL;
    HANDLE event, connection = NULL, target = NULL;
    BYTE *first_buffer = NULL, *second_buffer = NULL, state, released;
    UINT first_channel = 0, second_channel = 0, system_channel = 0;
    UINT first_size = 0x1000, second_size = 0x1000;
    UINT command[6], batch;
    UINT64 cookie = 0, shared;
    ULONG processed;
    NTSTATUS status;
    HWND hwnd = NULL;
    BOOL ret;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create shared-target event, error %lu\n", GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got shared-target connection status %#lx\n", status );
    hwnd = CreateWindowExA( 0, "static", "shared target", WS_POPUP, 0, 0, 32, 32,
                            NULL, NULL, NULL, NULL );
    ok( !!hwnd, "failed to create shared-target window, error %lu\n", GetLastError() );
    ret = hwnd && NtUserCreateDCompositionHwndTarget( hwnd, 0, &target );
    ok( ret, "failed to create shared target, status %#lx\n", RtlGetLastNtStatus() );
    if (!ret) goto done;

    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5 && record->next,
        "got shared-target system records status %#lx record %p\n", status, record );
    if (record)
    {
        system_channel = record->u.create.channel;
        check_dcomp_batch_payload( record->next, system_channel, expected_system_resource,
                                   sizeof(expected_system_resource), "shared-target system resource" );
    }

    status = NtDCompositionCreateChannel( &first_channel, &first_size,
                                           (void **)&first_buffer, 0 );
    ok( status == STATUS_SUCCESS, "got first shared-target channel status %#lx\n", status );
    status = NtDCompositionCreateChannel( &second_channel, &second_size,
                                           (void **)&second_buffer, 0 );
    ok( status == STATUS_SUCCESS, "got second shared-target channel status %#lx\n", status );
    if (!first_buffer || !second_buffer) goto done;
    status = NtDCompositionSetChannelConnectionId( first_channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got first shared-target bind status %#lx\n", status );
    status = NtDCompositionSetChannelConnectionId( second_channel, 0, 2 );
    ok( status == STATUS_SUCCESS, "got second shared-target bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->next,
        "got shared-target channel records status %#lx record %p\n", status, record );

    command[0] = 3;
    command[1] = 1;
    shared = (UINT_PTR)target;
    memcpy( command + 2, &shared, sizeof(shared) );
    command[4] = 0xb8;
    command[5] = 0;
    memcpy( first_buffer, command, sizeof(command) );
    status = NtDCompositionProcessChannelBatchBuffer( first_channel, sizeof(command),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS && processed == 1,
        "got first shared-target open status %#lx count %lu\n", status, processed );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    expected_begin[3] = first_channel;
    check_dcomp_batch_payload( record, system_channel, expected_begin,
                               sizeof(expected_begin), "first shared-target begin" );

    command[1] = 2;
    command[5] = 1;
    memcpy( second_buffer, command, sizeof(command) );
    status = NtDCompositionProcessChannelBatchBuffer( second_channel, sizeof(command),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS && processed == 1,
        "got second shared-target open status %#lx count %lu\n", status, processed );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    expected_begin[3] = second_channel;
    check_dcomp_batch_payload( record, system_channel, expected_begin,
                               sizeof(expected_begin), "second shared-target begin" );

    status = NtDCompositionCommitChannel( second_channel, &batch, &state, 0,
                                           NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got second shared-target commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    expected_complete[2] = 2;
    check_dcomp_batch_payload( record, second_channel, expected_complete,
                               sizeof(expected_complete), "second shared-target complete" );

    status = NtDCompositionCommitChannel( first_channel, &batch, &state, 0,
                                           NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got first shared-target commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    expected_complete[2] = 1;
    check_dcomp_batch_payload( record, first_channel, expected_complete,
                               sizeof(expected_complete), "first shared-target complete" );

done:
    if (second_channel) NtDCompositionDestroyChannel( second_channel );
    if (first_channel) NtDCompositionDestroyChannel( first_channel );
    if (target) CloseHandle( target );
    if (connection) NtDCompositionDestroyConnection( connection );
    if (hwnd) DestroyWindow( hwnd );
    CloseHandle( event );
}
static void test_window_node_properties(void)
{
    static const UINT commands[] =
    {
        2, 1, 0xc0, 0,
        2, 2, 0x43, 0,
        2, 3, 0x41, 0,
        2, 4, 0x82, 0,
        15, 1, 0x34, 16, 0x34000001, 0x34000002, 0x34000003, 0x34000004,
        15, 1, 0x35, 16, 0x35000001, 0x35000002, 0x35000003, 0x35000004,
        15, 1, 0x36, 16, 0x36000001, 0x36000002, 0x36000003, 0x36000004,
        15, 1, 0x37, 8, 0x37000001, 0x37000002,
        15, 1, 0x38, 16, 0x38000001, 0x38000002, 0x38000003, 0x38000004,
        13, 1, 0x39, 0, 0x39000001, 0x39000002,
        16, 1, 0x3a, 2,
        11, 1, 0x3b, 0, 1, 0,
        11, 1, 0x3c, 0, 1, 0,
        11, 1, 0x3d, 0, 1, 0,
        11, 1, 0x3e, 0, 1, 0,
        15, 1, 0x3f, 16, 0x3f000001, 0x3f000002, 0x3f000003, 0x3f000004,
        15, 1, 0x40, 16, 0x40000001, 0x40000002, 0x40000003, 0x40000004,
        15, 1, 0x41, 16, 0x41000001, 0x41000002, 0x41000003, 0x41000004,
        16, 1, 0x42, 3,
        16, 1, 0x43, 4,
        15, 1, 0x44, 8, 0x44000001, 0x44000002,
        15, 1, 0x45, 8, 0x45000001, 0x45000002,
    };
    static const UINT expected[] =
    {
        16, 0x28, 1, 0xc0,
        16, 0x28, 2, 0x43,
        16, 0x28, 3, 0x41,
        16, 0x28, 4, 0x82,
        28, 0x295, 1, 0x34000001, 0x34000002, 0x34000003, 0x34000004,
        28, 0x296, 1, 0x35000001, 0x35000002, 0x35000003, 0x35000004,
        28, 0x297, 1, 0x36000001, 0x36000002, 0x36000003, 0x36000004,
        20, 0x298, 1, 0x37000001, 0x37000002,
        28, 0x299, 1, 0x38000001, 0x38000002, 0x38000003, 0x38000004,
        20, 0x29a, 1, 0x39000001, 0x39000002,
        16, 0x29b, 1, 2,
        16, 0x29c, 1, 1,
        16, 0x29d, 1, 1,
        16, 0x29e, 1, 1,
        16, 0x29f, 1, 1,
        28, 0x2a0, 1, 0x3f000001, 0x3f000002, 0x3f000003, 0x3f000004,
        28, 0x2a1, 1, 0x40000001, 0x40000002, 0x40000003, 0x40000004,
        28, 0x2a2, 1, 0x41000001, 0x41000002, 0x41000003, 0x41000004,
        16, 0x2a3, 1, 3,
        16, 0x2a4, 1, 4,
        20, 0x2a5, 1, 0x44000001, 0x44000002,
        20, 0x2a6, 1, 0x45000001, 0x45000002,
    };
    static const UINT expected_release[] =
    {
        12, 0x29, 1,
        12, 0x29, 2,
        12, 0x29, 3,
        12, 0x29, 4,
    };
    static const UINT bad_buffer[] = {15, 1, 0x34, 12, 1, 2, 3};
    static const UINT bad_reference[] = {16, 1, 0x42, 2};
    static const UINT bad_handle[] = {13, 1, 0x3a, 0, 1, 0};
    static const UINT release_references[] = {4, 2, 4, 3, 4, 4};
    static const UINT release_window[] = {4, 1};
    struct dcomposition_connection_batch *record = NULL;
    HANDLE event, connection = NULL;
    BYTE *buffer = NULL, state;
    UINT channel = 0, size = 0x1000, batch;
    UINT64 cookie = 0;
    NTSTATUS status;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create window-node event, error %lu\n", GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got window-node connection status %#lx\n", status );
    status = NtDCompositionCreateChannel( &channel, &size, (void **)&buffer, 0 );
    ok( status == STATUS_SUCCESS, "got window-node channel status %#lx\n", status );
    if (status) goto done;
    status = NtDCompositionSetChannelConnectionId( channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got window-node bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5,
        "got window-node create record status %#lx record %p type %u\n",
        status, record, record ? record->type : 0 );

    status = process_dcomp_test_command( channel, buffer, commands, sizeof(commands) );
    ok( status == STATUS_SUCCESS, "got window-node property status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, bad_buffer, sizeof(bad_buffer) );
    ok( status == STATUS_INVALID_PARAMETER, "got bad window-node buffer status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, bad_reference, sizeof(bad_reference) );
    ok( status == STATUS_INVALID_PARAMETER, "got bad window-node reference status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, bad_handle, sizeof(bad_handle) );
    ok( status == STATUS_INVALID_PARAMETER, "got bad window-node handle status %#lx\n", status );

    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got window-node commit status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got window-node batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected, sizeof(expected), "window node" );

    status = process_dcomp_test_command( channel, buffer, release_references,
                                         sizeof(release_references) );
    ok( status == STATUS_SUCCESS, "got window-node reference release status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, release_window, sizeof(release_window) );
    ok( status == STATUS_SUCCESS, "got window-node release status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got window-node release commit status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got window-node release batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_release,
                               sizeof(expected_release), "window-node release" );

done:
    if (channel) NtDCompositionDestroyChannel( channel );
    if (connection) NtDCompositionDestroyConnection( connection );
    CloseHandle( event );
}

static void test_gdi_sprite_bitmap_protocol(void)
{
    static const UINT create[] =
    {
        2, 1, 0x41, 0,
        11, 1, 3, 0, 0x87654321, 0x12345678,
        11, 1, 1, 0, 0x57, 0,
        11, 1, 2, 0, 1, 0,
    };
    static const UINT expected_create[] =
    {
        16, 0x28, 1, 0x41,
        20, 0x20c, 1, 0x87654321, 0x12345678,
        16, 0x20a, 1, 0x57,
        16, 0x20b, 1, 1,
    };
    static const UINT update[] =
    {
        11, 1, 3, 0, 0x87654321, 0x12345678,
        11, 1, 1, 0, 0x1c, 0,
        11, 1, 2, 0, 0, 0,
    };
    static const UINT expected_update[] =
    {
        16, 0x20a, 1, 0x1c,
        16, 0x20b, 1, 0,
    };
    static const UINT bad_property[] = {11, 1, 4, 0, 1, 0};
    static const UINT bad_format[] = {11, 1, 1, 0, 0, 1};
    static const UINT release[] = {4, 1};
    static const UINT expected_release[] = {12, 0x29, 1};
    struct dcomposition_connection_batch *record = NULL;
    HANDLE event, connection = NULL;
    BYTE *buffer = NULL, state;
    UINT channel = 0, size = 0x1000, batch;
    UINT64 cookie = 0;
    NTSTATUS status;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create GDI-sprite event, error %lu\n", GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got GDI-sprite connection status %#lx\n", status );
    status = NtDCompositionCreateChannel( &channel, &size, (void **)&buffer, 0 );
    ok( status == STATUS_SUCCESS, "got GDI-sprite channel status %#lx\n", status );
    if (status) goto done;
    status = NtDCompositionSetChannelConnectionId( channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got GDI-sprite bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5,
        "got GDI-sprite create record status %#lx record %p type %u\n",
        status, record, record ? record->type : 0 );

    status = process_dcomp_test_command( channel, buffer, create, sizeof(create) );
    ok( status == STATUS_SUCCESS, "got GDI-sprite property status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, bad_property, sizeof(bad_property) );
    ok( status == STATUS_INVALID_PARAMETER, "got bad GDI-sprite property status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, bad_format, sizeof(bad_format) );
    ok( status == STATUS_INVALID_PARAMETER, "got bad GDI-sprite format status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got GDI-sprite create commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got GDI-sprite create batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_create,
                               sizeof(expected_create), "GDI-sprite create" );

    status = process_dcomp_test_command( channel, buffer, update, sizeof(update) );
    ok( status == STATUS_SUCCESS, "got GDI-sprite update status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got GDI-sprite update commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got GDI-sprite update batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_update,
                               sizeof(expected_update), "GDI-sprite update" );

    status = process_dcomp_test_command( channel, buffer, release, sizeof(release) );
    ok( status == STATUS_SUCCESS, "got GDI-sprite release status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got GDI-sprite release commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got GDI-sprite release batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_release,
                               sizeof(expected_release), "GDI-sprite release" );

done:
    if (channel) NtDCompositionDestroyChannel( channel );
    if (connection) NtDCompositionDestroyConnection( connection );
    CloseHandle( event );
}

static void test_composition_surface_brush_protocol(void)
{
    static const UINT create[] =
    {
        2, 1, 0xa9, 0,
        2, 2, 0x2a, 0,
        2, 3, 0x1d, 0,
    };
    static const UINT surface_flags[] =
    {
        11, 2, 1, 0, 1, 0,
        11, 2, 2, 0, 0, 0,
        11, 2, 3, 0, 0x1234, 0,
    };
    static const UINT brush_properties[] =
    {
        16, 1, 0, 2,
        15, 1, 1, 16, 10, 20, 110, 220,
        15, 1, 2, 16, 30, 40, 50, 60,
        15, 1, 8, 1, 1,
        15, 1, 9, 1, 1,
        15, 1, 10, 1, 1,
        12, 1, 3, 0x3e800000,
        12, 1, 4, 0x3f400000,
        11, 1, 5, 0, 3, 0,
        11, 1, 6, 0, 4, 0,
        16, 1, 7, 3,
    };
    static const UINT dirty_update[] = {15, 1, 2, 16, 30, 40, 50, 60};
    static const UINT unchanged_brush[] =
    {
        16, 1, 7, 3,
        11, 1, 5, 0, 3, 0,
        11, 1, 6, 0, 4, 0,
    };
    static const UINT create_invalid_surface[] = {2, 4, 0x87, 0};
    static const UINT set_invalid_surface[] = {16, 1, 0, 4};
    static const UINT release_invalid_surface[] = {4, 4};
    UINT expected[] =
    {
        16, 0x28, 1, 0xa9,
        16, 0x28, 2, 0x2a,
        16, 0x28, 3, 0x1d,
        28, 0x70, 2, 0, 0, 1, 0,
        52, 0x175, 1, 2, 10, 20, 110, 220, 10, 20, 110, 220, 1,
        16, 0x176, 1, 3,
        16, 0x170, 1, 0x3e800000,
        16, 0x177, 1, 0x3f400000,
        16, 0x173, 1, 3,
        16, 0x171, 1, 4,
        16, 0x172, 1, 1,
        16, 0x174, 1, 1,
    };
    static const UINT expected_dirty[] =
    {
        52, 0x175, 1, 2, 10, 20, 110, 220, 40, 60, 60, 80, 1,
    };
    struct dcomposition_connection_batch *record = NULL;
    BYTE buffer_info[0x520] = {0};
    HANDLE event, connection = NULL, surface = NULL, ordinary = NULL, consumer_surface = NULL;
    BYTE *buffer = NULL, state;
    UINT channel = 0, size = 0x1000, batch, handle_command[6] = {13, 2, 0};
    UINT64 binding_id, cookie = 0, handle_value;
    NTSTATUS status;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create surface-brush event, error %lu\n", GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got surface-brush connection status %#lx\n", status );
    status = NtDCompositionCreateChannel( &channel, &size, (void **)&buffer, 0 );
    ok( status == STATUS_SUCCESS, "got surface-brush channel status %#lx\n", status );
    if (status) goto done;
    status = NtDCompositionSetChannelConnectionId( channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got surface-brush bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5,
        "got surface-brush create record status %#lx record %p type %u\n",
        status, record, record ? record->type : 0 );

    status = process_dcomp_test_command( channel, buffer, create, sizeof(create) );
    ok( status == STATUS_SUCCESS, "got surface-brush resource status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, create_invalid_surface,
                                         sizeof(create_invalid_surface) );
    ok( status == STATUS_SUCCESS, "got invalid surface resource status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, set_invalid_surface,
                                         sizeof(set_invalid_surface) );
    ok( status == STATUS_INVALID_PARAMETER,
        "got invalid surface-brush reference status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, release_invalid_surface,
                                         sizeof(release_invalid_surface) );
    ok( status == STATUS_SUCCESS, "got invalid surface release status %#lx\n", status );

    ordinary = CreateEventW( NULL, FALSE, FALSE, NULL );
    handle_value = (UINT_PTR)ordinary;
    memcpy( handle_command + 4, &handle_value, sizeof(handle_value) );
    status = process_dcomp_test_command( channel, buffer, handle_command,
                                         sizeof(handle_command) );
    ok( status == STATUS_OBJECT_TYPE_MISMATCH,
        "got ordinary surface handle status %#lx\n", status );

    status = NtCreateCompositionSurfaceHandle( NULL, 3, &surface );
    ok( status == STATUS_SUCCESS, "got surface creation status %#lx\n", status );
    if (status) goto done;
    status = NtBindCompositionSurface( surface, TRUE, 0, FALSE, buffer_info, &binding_id );
    ok( status == STATUS_SUCCESS, "got surface binding status %#lx\n", status );
    if (status) goto done;
    handle_value = (UINT_PTR)surface;
    memcpy( handle_command + 4, &handle_value, sizeof(handle_value) );
    status = process_dcomp_test_command( channel, buffer, handle_command,
                                         sizeof(handle_command) );
    ok( status == STATUS_SUCCESS, "got retained surface status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, surface_flags,
                                         sizeof(surface_flags) );
    ok( status == STATUS_SUCCESS, "got surface flags status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, brush_properties,
                                         sizeof(brush_properties) );
    ok( status == STATUS_SUCCESS, "got surface-brush properties status %#lx\n", status );

    NtClose( surface );
    surface = NULL;
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0,
                                           NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got surface-brush commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got surface-brush batch status %#lx\n", status );
    if (record && record->u.batch.size >= 68)
    {
        memcpy( &handle_value, record->u.batch.data + 60, sizeof(handle_value) );
        consumer_surface = (HANDLE)(UINT_PTR)handle_value;
        memcpy( expected + 15, &handle_value, sizeof(handle_value) );
    }
    check_dcomp_batch_payload( record, channel, expected, sizeof(expected), "surface brush" );

    status = process_dcomp_test_command( channel, buffer, dirty_update,
                                         sizeof(dirty_update) );
    ok( status == STATUS_SUCCESS, "got surface-brush dirty status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, surface_flags,
                                         sizeof(surface_flags) );
    ok( status == STATUS_SUCCESS, "got unchanged surface flags status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, unchanged_brush,
                                         sizeof(unchanged_brush) );
    ok( status == STATUS_SUCCESS, "got unchanged surface-brush status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0,
                                           NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got surface-brush dirty commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got surface-brush dirty batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_dirty,
                               sizeof(expected_dirty), "surface brush dirty" );

done:
    if (consumer_surface) NtClose( consumer_surface );
    if (surface) NtClose( surface );
    if (ordinary) CloseHandle( ordinary );
    if (channel) NtDCompositionDestroyChannel( channel );
    if (connection) NtDCompositionDestroyConnection( connection );
    CloseHandle( event );
}

static void test_mask_brush_protocol(void)
{
    static const UINT create[] =
    {
        2, 1, 0x6b, 0,
        2, 2, 0x16, 0,
        2, 3, 0xa9, 0,
        2, 4, 0x87, 0,
        2, 5, 0x63, 0,
        2, 6, 0x7e, 0,
    };
    static const UINT references[] =
    {
        16, 1, 0, 2,
        16, 1, 1, 3,
    };
    static const UINT expected[] =
    {
        16, 0x28, 1, 0x6b,
        16, 0x28, 2, 0x16,
        16, 0x28, 3, 0xa9,
        16, 0x28, 4, 0x87,
        16, 0x28, 5, 0x63,
        16, 0x28, 6, 0x7e,
        16, 0xf7, 1, 2,
        16, 0xf6, 1, 3,
    };
    static const UINT gradient_references[] =
    {
        16, 1, 0, 5,
        16, 1, 1, 6,
    };
    static const UINT expected_gradient[] =
    {
        16, 0xf7, 1, 5,
        16, 0xf6, 1, 6,
    };
    static const UINT clear[] =
    {
        16, 1, 0, 0,
        16, 1, 1, 0,
    };
    static const UINT expected_clear[] =
    {
        16, 0xf7, 1, 0,
        16, 0xf6, 1, 0,
    };
    static const UINT bad_property[] = {16, 1, 2, 2};
    static const UINT bad_source[] = {16, 1, 0, 4};
    static const UINT bad_mask[] = {16, 1, 1, 2};
    struct dcomposition_connection_batch *record = NULL;
    HANDLE event, connection = NULL;
    BYTE *buffer = NULL, state;
    UINT channel = 0, size = 0x1000, batch;
    UINT64 cookie = 0;
    NTSTATUS status;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create mask-brush event, error %lu\n", GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got mask-brush connection status %#lx\n", status );
    status = NtDCompositionCreateChannel( &channel, &size, (void **)&buffer, 0 );
    ok( status == STATUS_SUCCESS, "got mask-brush channel status %#lx\n", status );
    if (status) goto done;
    status = NtDCompositionSetChannelConnectionId( channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got mask-brush bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5,
        "got mask-brush create record status %#lx record %p type %u\n",
        status, record, record ? record->type : 0 );

    status = process_dcomp_test_command( channel, buffer, create, sizeof(create) );
    ok( status == STATUS_SUCCESS, "got mask-brush resource status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, bad_property, sizeof(bad_property) );
    ok( status == STATUS_INVALID_PARAMETER, "got mask-brush bad property status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, bad_source, sizeof(bad_source) );
    ok( status == STATUS_INVALID_PARAMETER, "got mask-brush bad source status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, bad_mask, sizeof(bad_mask) );
    ok( status == STATUS_INVALID_PARAMETER, "got mask-brush bad mask status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, references, sizeof(references) );
    ok( status == STATUS_SUCCESS, "got mask-brush references status %#lx\n", status );

    status = NtDCompositionCommitChannel( channel, &batch, &state, 0,
                                           NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got mask-brush commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got mask-brush batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected, sizeof(expected), "mask brush" );

    status = process_dcomp_test_command( channel, buffer, gradient_references,
                                         sizeof(gradient_references) );
    ok( status == STATUS_SUCCESS, "got mask-brush gradient references status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0,
                                           NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got mask-brush gradient commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got mask-brush gradient batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_gradient,
                               sizeof(expected_gradient), "mask brush gradient" );

    status = process_dcomp_test_command( channel, buffer, clear, sizeof(clear) );
    ok( status == STATUS_SUCCESS, "got mask-brush clear status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0,
                                           NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got mask-brush clear commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got mask-brush clear batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_clear,
                               sizeof(expected_clear), "mask brush clear" );

done:
    if (channel) NtDCompositionDestroyChannel( channel );
    if (connection) NtDCompositionDestroyConnection( connection );
    CloseHandle( event );
}

static void test_legacy_render_target_protocol(void)
{
    static const UINT commands[] =
    {
        2, 1, 0x60, 0,
        2, 2, 0x36, 0,
        2, 3, 0xb8, 0,
        15, 1, 2, 8, 0x02000001, 0x02000002,
        11, 1, 3, 0, 0x303, 0,
        11, 1, 4, 0, 0x1c, 0,
        11, 1, 5, 0, 0x505, 0,
        11, 1, 0xb, 0, 0xb0b, 0,
        11, 1, 1, 0, 0x01010101, 0x01010102,
        15, 1, 6, 16, 0x3f800000, 0x40000000, 0x42c80000, 0x43480000,
        12, 1, 7, 0x3fc00000,
        12, 1, 8, 0x40000000,
        15, 1, 9, 16, 1, 2, 100, 200,
        11, 1, 10, 0, 3, 0,
        12, 1, 12, 0x3fa00000,
        11, 1, 13, 0, 1, 0,
        16, 1, 0, 2,
        15, 2, 0, 8, 0x36000001, 0x36000002,
        16, 2, 1, 3,
    };
    static const UINT expected[] =
    {
        16, 0x28, 1, 0x60,
        16, 0x28, 2, 0x36,
        16, 0x28, 3, 0xb8,
        36, 0xe0, 1, 0x02000001, 0x02000002, 0x303, 0x1c, 0x505, 0xb0b,
        16, 0xe1, 1, 2,
        68, 0xe3, 1, 0x01010101, 0x01010102,
            0x3f800000, 0x40000000, 0x42c80000, 0x43480000,
            0x3fc00000, 0x40000000, 1, 2, 100, 200, 3, 0,
        16, 0xe2, 1, 0x3fa00000,
        12, 0x151, 1,
        20, 0x203, 2, 0x36000001, 0x36000002,
        16, 0x204, 2, 3,
    };
    static const UINT expected_release[] =
    {
        12, 0x29, 1,
        12, 0x29, 2,
        12, 0x29, 3,
    };
    static const UINT bad_buffer[] = {15, 1, 6, 12, 1, 2, 3};
    static const UINT bad_float[] = {12, 1, 7, 0};
    static const UINT bad_target_reference[] = {16, 1, 0, 3};
    static const UINT bad_tree_reference[] = {16, 2, 1, 1};
    static const UINT release_references[] = {4, 3, 4, 2};
    static const UINT release_target[] = {4, 1};
    struct dcomposition_connection_batch *record = NULL;
    HANDLE event, connection = NULL;
    BYTE *buffer = NULL, state;
    UINT channel = 0, size = 0x1000, batch;
    UINT64 cookie = 0;
    NTSTATUS status;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create render-target event, error %lu\n", GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got render-target connection status %#lx\n", status );
    status = NtDCompositionCreateChannel( &channel, &size, (void **)&buffer, 0 );
    ok( status == STATUS_SUCCESS, "got render-target channel status %#lx\n", status );
    if (status) goto done;
    status = NtDCompositionSetChannelConnectionId( channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got render-target bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5,
        "got render-target create record status %#lx record %p type %u\n",
        status, record, record ? record->type : 0 );

    status = process_dcomp_test_command( channel, buffer, commands, sizeof(commands) );
    ok( status == STATUS_SUCCESS, "got render-target property status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, bad_buffer, sizeof(bad_buffer) );
    ok( status == STATUS_INVALID_PARAMETER, "got bad render-target buffer status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, bad_float, sizeof(bad_float) );
    ok( status == STATUS_INVALID_PARAMETER, "got bad render-target float status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, bad_target_reference,
                                         sizeof(bad_target_reference) );
    ok( status == STATUS_INVALID_PARAMETER, "got bad render-target reference status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, bad_tree_reference,
                                         sizeof(bad_tree_reference) );
    ok( status == STATUS_INVALID_PARAMETER, "got bad desktop-tree reference status %#lx\n", status );

    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got render-target commit status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got render-target batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected, sizeof(expected), "render target" );

    status = process_dcomp_test_command( channel, buffer, release_references,
                                         sizeof(release_references) );
    ok( status == STATUS_SUCCESS, "got render-target reference release status %#lx\n", status );
    status = process_dcomp_test_command( channel, buffer, release_target, sizeof(release_target) );
    ok( status == STATUS_SUCCESS, "got render-target release status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got render-target release commit status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got render-target release batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_release,
                               sizeof(expected_release), "render-target release" );

done:
    if (channel) NtDCompositionDestroyChannel( channel );
    if (connection) NtDCompositionDestroyConnection( connection );
    CloseHandle( event );
}

static void test_visual_target_root_lifecycle(void)
{
    static const UINT expected_system_resource[] = {16, 0x28, 1, 0xb8};
    static const UINT expected_initial[] = {
        12, 0x27, 1,
        16, 0x28, 2, 0xb8,
        16, 0x28, 3, 0xb8,
        16, 0x28, 4, 13,
        12, 0x187, 1,
        24, 0x185, 1, 2, 0, 1,
    };
    static const UINT expected_replace[] = {
        12, 0x187, 1,
        24, 0x185, 1, 3, 0, 1,
        12, 0x29, 2,
    };
    static const UINT expected_visual_update[] = {
        24, 0x185, 3, 2, 0, 1,
        52, 0x19c, 2, 0x7e, 1, 0, 0, 0, 0, 1, 0, 0, 0,
        16, 0x197, 3, 0x100,
        20, 0x19b, 3, 0x3f800000, 0x3f800000,
    };
    static const UINT expected_visual_geometry[] = {
        24, 0x195, 2, 0x3f800000, 0x40000000, 0x40400000,
        16, 0x196, 2, 0x3f000000,
        24, 0x19a, 2, 0x3e800000, 0x3f000000, 0x3f400000,
        20, 0x19b, 2, 0x3f000000, 0x3f800000,
        20, 0x19e, 2, 0x40800000, 0x40a00000,
    };
    static const UINT expected_visual_offset[] = {
        24, 0x195, 2, 0x40c00000, 0x40e00000, 0x41000000,
    };
    static const UINT expected_visual_content[] = {
        16, 0x28, 5, 0xa6,
        16, 0x28, 6, 0x16,
        16, 0x28, 7, 0x7f,
        16, 0x28, 8, 0x1e,
        16, 0x28, 9, 0x59,
        28, 0x31, 6, 0x3f800000, 0x3f000000, 0x3e800000, 0x3f800000,
        48, 0x13f, 7, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        16, 0x13d, 7, 0x3f800000,
        16, 0x142, 7, 0x40000000,
        16, 0x140, 7, 0x40400000,
        16, 0x13c, 7, 0x40800000,
        20, 0x3d, 8, 0, 0,
        24, 0x3e, 8, 0, 0, 0,
        24, 0x3f, 8, 0, 0, 0,
        28, 0x40, 8, 0, 0, 0, 0x3f800000,
        24, 0x42, 8, 0, 0, 0x3f800000,
        16, 0x41, 8, 0,
        24, 0x43, 8, 0x3f2aaaab, 0x3f2aaaab, 0x3f800000,
        76, 0x44, 8,
            0x3f800000, 0, 0, 0,
            0, 0x3f800000, 0, 0,
            0, 0, 0x3f800000, 0,
            0, 0, 0, 0x3f800000,
        16, 0xb9, 9, 0,
        16, 0x194, 3, 9,
        16, 0x1a0, 3, 8,
        16, 0x18c, 3, 7,
        16, 0x16e, 5, 6,
    };
    static const UINT expected_interaction_update[] = {
        24, 0xbb, 9, 0, 0x101, 1,
        36, 0xba, 9, 1, 0, 1, 1, 1, 5,
        28, 0xba, 9, 1, 1, 4, 2,
    };
    static const UINT expected_rectangle_float_update[] = {
        48, 0x13f, 7,
            0x41100000, 0x41200000, 0x41300000, 0x41400000,
            0x41500000, 0x41600000, 0x41700000, 0x41800000, 1,
        16, 0x13d, 7, 0x40a00000,
        16, 0x142, 7, 0x40c00000,
        16, 0x140, 7, 0x40e00000,
        16, 0x13c, 7, 0x41000000,
    };
    static const UINT expected_interaction_clear[] = {
        16, 0x194, 3, 0,
        12, 0x29, 9,
    };
    static const UINT expected_transform_matrix[] = {
        76, 0x44, 8,
            0x3f800000, 0, 0, 0,
            0, 0x3f800000, 0, 0,
            0, 0, 0x3f800000, 0,
            0x41200000, 0x41a00000, 0, 0x3f800000,
    };
    static const UINT expected_transform_scale[] = {
        24, 0x43, 8, 0x40000000, 0x40400000, 0x40800000,
    };
    static const UINT expected_visual_clear[] = {12, 0x187, 3};
    static const UINT expected_clear[] = {
        12, 0x187, 1,
        12, 0x29, 3,
    };
    static const UINT expected_recreate[] = {
        16, 0x28, 2, 0xb8,
        12, 0x187, 1,
        24, 0x185, 1, 2, 0, 1,
    };
    static const UINT expected_target_release[] = {
        12, 0x187, 1,
        12, 0x29, 1,
    };
    static const UINT expected_root_release[] = {12, 0x29, 2};
    struct dcomposition_connection_batch *record = NULL;
    HANDLE event, connection = NULL, target_handle = NULL;
    BYTE *buffer = NULL, state;
    UINT channel = 0, system_channel = 0, size = 0x1000, batch, command[72];
    UINT expected_begin[4] = {16, 0x26, 1, 0};
    UINT64 cookie = 0, shared;
    ULONG processed;
    BYTE released;
    NTSTATUS status;
    HWND hwnd = NULL;
    BOOL ret;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create visual-root event, error %lu\n", GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got visual-root connection status %#lx\n", status );
    hwnd = CreateWindowExA( 0, "static", "visual-root target", WS_POPUP, 0, 0, 32, 32,
                            NULL, NULL, NULL, NULL );
    ok( !!hwnd, "failed to create visual-root window, error %lu\n", GetLastError() );
    ret = hwnd && NtUserCreateDCompositionHwndTarget( hwnd, 0, &target_handle );
    ok( ret, "failed to create visual-root target, status %#lx\n", RtlGetLastNtStatus() );
    if (!ret) goto done;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5 && record->next,
        "got visual-root system records status %#lx record %p\n", status, record );
    if (record)
    {
        system_channel = record->u.create.channel;
        check_dcomp_batch_payload( record->next, system_channel, expected_system_resource,
                                   sizeof(expected_system_resource), "visual-root system resource" );
    }
    status = NtDCompositionCreateChannel( &channel, &size, (void **)&buffer, 0 );
    ok( status == STATUS_SUCCESS, "got visual-root channel status %#lx\n", status );
    if (status) goto done;
    status = NtDCompositionSetChannelConnectionId( channel, 0, 1 );
    ok( status == STATUS_SUCCESS, "got visual-root bind status %#lx\n", status );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS && record && record->type == 5,
        "got visual-root create record status %#lx record %p type %u\n",
        status, record, record ? record->type : 0 );

    command[0] = 3; command[1] = 1;
    shared = (UINT_PTR)target_handle;
    memcpy( command + 2, &shared, sizeof(shared) );
    command[4] = 0xb8; command[5] = 0;
    command[6] = 2; command[7] = 2; command[8] = 0xb8; command[9] = 0;
    command[10] = 2; command[11] = 3; command[12] = 0xb8; command[13] = 0;
    command[14] = 2; command[15] = 4; command[16] = 13; command[17] = 0;
    command[18] = 16; command[19] = 1; command[20] = 0x34; command[21] = 2;
    memcpy( buffer, command, 88 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 88,
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "got initial visual-root process status %#lx\n", status );
    ok( processed == 5, "got initial visual-root process count %lu\n", processed );
    ok( !released, "got initial visual-root released flag %#x\n", released );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    expected_begin[3] = channel;
    check_dcomp_batch_payload( record, system_channel, expected_begin,
                               sizeof(expected_begin), "visual-root system begin" );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got initial visual-root commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got initial visual-root batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_initial, sizeof(expected_initial), "initial visual-root" );

    command[0] = 20; command[1] = 3; command[2] = 2; command[3] = 0; command[4] = 0;
    command[5] = 15; command[6] = 3; command[7] = 0x1f; command[8] = 8;
    command[9] = 0x3f800000; command[10] = 0x3f800000;
    command[11] = 11; command[12] = 2; command[13] = 8; command[14] = 0;
    command[15] = 1; command[16] = 0;
    command[17] = 11; command[18] = 2; command[19] = 0xe; command[20] = 0;
    command[21] = 1; command[22] = 0;
    command[23] = 11; command[24] = 3; command[25] = 0x1b; command[26] = 0;
    command[27] = 1; command[28] = 0;
    memcpy( buffer, command, 116 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 116, &processed, &released );
    ok( status == STATUS_SUCCESS, "got visual update process status %#lx\n", status );
    ok( processed == 5, "got visual update process count %lu\n", processed );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got visual update commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got visual update batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_visual_update,
                               sizeof(expected_visual_update), "visual update" );

    command[0] = 12; command[1] = 2; command[2] = 1; command[3] = 0x3f800000;
    command[4] = 12; command[5] = 2; command[6] = 2; command[7] = 0x40000000;
    command[8] = 12; command[9] = 2; command[10] = 3; command[11] = 0x40400000;
    command[12] = 12; command[13] = 2; command[14] = 0x18; command[15] = 0x40800000;
    command[16] = 12; command[17] = 2; command[18] = 0x19; command[19] = 0x40a00000;
    command[20] = 12; command[21] = 2; command[22] = 0x1a; command[23] = 0x3f000000;
    command[24] = 12; command[25] = 2; command[26] = 0x20; command[27] = 0x3e800000;
    command[28] = 12; command[29] = 2; command[30] = 0x21; command[31] = 0x3f000000;
    command[32] = 12; command[33] = 2; command[34] = 0x22; command[35] = 0x3f400000;
    command[36] = 12; command[37] = 2; command[38] = 0x23; command[39] = 0x3f000000;
    command[40] = 12; command[41] = 2; command[42] = 0x24; command[43] = 0x3f800000;
    memcpy( buffer, command, 176 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 176, &processed, &released );
    ok( status == STATUS_SUCCESS, "got visual geometry process status %#lx\n", status );
    ok( processed == 11, "got visual geometry process count %lu\n", processed );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got visual geometry commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got visual geometry batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_visual_geometry,
                               sizeof(expected_visual_geometry), "visual geometry" );

    command[0] = 15; command[1] = 2; command[2] = 0x1c; command[3] = 12;
    command[4] = 0x40c00000; command[5] = 0x40e00000; command[6] = 0x41000000;
    memcpy( buffer, command, 28 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 28, &processed, &released );
    ok( status == STATUS_SUCCESS, "got packed visual offset process status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got packed visual offset commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got packed visual offset batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_visual_offset,
                               sizeof(expected_visual_offset), "packed visual offset" );

    command[0] = 2; command[1] = 5; command[2] = 0xa6; command[3] = 0;
    command[4] = 2; command[5] = 6; command[6] = 0x16; command[7] = 0;
    command[8] = 2; command[9] = 7; command[10] = 0x7f; command[11] = 0;
    command[12] = 2; command[13] = 8; command[14] = 0x1e; command[15] = 0;
    command[16] = 2; command[17] = 9; command[18] = 0x59; command[19] = 0;
    command[20] = 15; command[21] = 8; command[22] = 8; command[23] = 12;
    command[24] = 0x3f2aaaab; command[25] = 0x3f2aaaab; command[26] = 0x3f800000;
    command[27] = 15; command[28] = 6; command[29] = 0; command[30] = 16;
    command[31] = 0x3f800000; command[32] = 0x3f000000;
    command[33] = 0x3e800000; command[34] = 0x3f800000;
    command[35] = 11; command[36] = 7; command[37] = 0x15; command[38] = 0;
    command[39] = 1; command[40] = 0;
    command[41] = 15; command[42] = 7; command[43] = 0x11; command[44] = 16;
    command[45] = 0x3f800000; command[46] = 0x40000000;
    command[47] = 0x40400000; command[48] = 0x40800000;
    command[49] = 16; command[50] = 3; command[51] = 4; command[52] = 8;
    command[53] = 16; command[54] = 3; command[55] = 7; command[56] = 7;
    command[57] = 16; command[58] = 5; command[59] = 0x34; command[60] = 6;
    command[61] = 16; command[62] = 3; command[63] = 0x17; command[64] = 9;
    memcpy( buffer, command, 260 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 260, &processed, &released );
    ok( status == STATUS_SUCCESS, "got visual content process status %#lx\n", status );
    ok( processed == 13, "got visual content process count %lu\n", processed );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got visual content commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got visual content batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_visual_content,
                               sizeof(expected_visual_content), "visual content" );

    command[0] = 12; command[1] = 7; command[2] = 5; command[3] = 0x40a00000;
    command[4] = 12; command[5] = 7; command[6] = 6; command[7] = 0x40c00000;
    command[8] = 12; command[9] = 7; command[10] = 7; command[11] = 0x40e00000;
    command[12] = 12; command[13] = 7; command[14] = 8; command[15] = 0x41000000;
    command[16] = 12; command[17] = 7; command[18] = 9; command[19] = 0x41100000;
    command[20] = 12; command[21] = 7; command[22] = 10; command[23] = 0x41200000;
    command[24] = 12; command[25] = 7; command[26] = 11; command[27] = 0x41300000;
    command[28] = 12; command[29] = 7; command[30] = 12; command[31] = 0x41400000;
    command[32] = 12; command[33] = 7; command[34] = 13; command[35] = 0x41500000;
    command[36] = 12; command[37] = 7; command[38] = 14; command[39] = 0x41600000;
    command[40] = 12; command[41] = 7; command[42] = 15; command[43] = 0x41700000;
    command[44] = 12; command[45] = 7; command[46] = 16; command[47] = 0x41800000;
    memcpy( buffer, command, 192 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 192, &processed, &released );
    ok( status == STATUS_SUCCESS, "got rectangle float update process status %#lx\n", status );
    ok( processed == 12, "got rectangle float update process count %lu\n", processed );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got rectangle float update commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got rectangle float update batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_rectangle_float_update,
                               sizeof(expected_rectangle_float_update), "rectangle float update" );

    command[0] = 11; command[1] = 9; command[2] = 10; command[3] = 0;
    command[4] = 1; command[5] = 0;
    command[6] = 11; command[7] = 9; command[8] = 11; command[9] = 0;
    command[10] = 1; command[11] = 0;
    command[12] = 11; command[13] = 9; command[14] = 0x11; command[15] = 0;
    command[16] = 1; command[17] = 0;
    command[18] = 15; command[19] = 9; command[20] = 1; command[21] = 16;
    command[22] = 1; command[23] = 1; command[24] = 1; command[25] = 3;
    command[26] = 15; command[27] = 9; command[28] = 1; command[29] = 16;
    command[30] = 1; command[31] = 1; command[32] = 1; command[33] = 4;
    command[34] = 15; command[35] = 9; command[36] = 2; command[37] = 16;
    command[38] = 1; command[39] = 1; command[40] = 1; command[41] = 2;
    command[42] = 15; command[43] = 9; command[44] = 8; command[45] = 16;
    command[46] = 4; command[47] = 3; command[48] = 0; command[49] = 0;
    command[50] = 15; command[51] = 9; command[52] = 9; command[53] = 16;
    command[54] = 4; command[55] = 1; command[56] = 0; command[57] = 0;
    memcpy( buffer, command, 232 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 232, &processed, &released );
    ok( status == STATUS_SUCCESS, "got interaction update process status %#lx\n", status );
    ok( processed == 8, "got interaction update process count %lu\n", processed );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got interaction update commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got interaction update batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_interaction_update,
                               sizeof(expected_interaction_update), "interaction update" );

    command[0] = 15; command[1] = 8; command[2] = 8; command[3] = 12;
    command[4] = 0x40000000; command[5] = 0x40400000; command[6] = 0x40800000;
    memcpy( buffer, command, 28 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 28, &processed, &released );
    ok( status == STATUS_SUCCESS, "got transform-scale process status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got transform-scale commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got transform-scale batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_transform_scale,
                               sizeof(expected_transform_scale), "transform scale" );

    command[0] = 15; command[1] = 8; command[2] = 9; command[3] = 64;
    memset( command + 4, 0, 64 );
    command[4] = command[9] = command[14] = command[19] = 0x3f800000;
    command[16] = 0x41200000; command[17] = 0x41a00000;
    memcpy( buffer, command, 80 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 80, &processed, &released );
    ok( status == STATUS_SUCCESS, "got transform-matrix process status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got transform-matrix commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got transform-matrix batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_transform_matrix,
                               sizeof(expected_transform_matrix), "transform matrix" );

    command[0] = 16; command[1] = 5; command[2] = 0x34; command[3] = 8;
    memcpy( buffer, command, 16 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 16, &processed, &released );
    ok( status == STATUS_INVALID_PARAMETER, "got invalid sprite content status %#lx\n", status );
    command[1] = 3; command[2] = 4; command[3] = 7;
    memcpy( buffer, command, 16 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 16, &processed, &released );
    ok( status == STATUS_INVALID_PARAMETER, "got invalid visual transform status %#lx\n", status );
    command[2] = 7; command[3] = 8;
    memcpy( buffer, command, 16 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 16, &processed, &released );
    ok( status == STATUS_INVALID_PARAMETER, "got invalid visual clip status %#lx\n", status );
    command[2] = 0x17; command[3] = 8;
    memcpy( buffer, command, 16 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 16, &processed, &released );
    ok( status == STATUS_INVALID_PARAMETER, "got invalid visual interaction status %#lx\n", status );
    command[0] = 15; command[1] = 6; command[2] = 0; command[3] = 8;
    command[4] = 0; command[5] = 0;
    memcpy( buffer, command, 24 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 24, &processed, &released );
    ok( status == STATUS_INVALID_PARAMETER, "got invalid color buffer status %#lx\n", status );
    command[0] = 11; command[1] = 7; command[2] = 0x15; command[3] = 0;
    command[4] = 1; command[5] = 0;
    memcpy( buffer, command, 24 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 24, &processed, &released );
    ok( status == STATUS_INVALID_PARAMETER, "got repeated rectangle mode status %#lx\n", status );

    command[0] = 16; command[1] = 3; command[2] = 0x17; command[3] = 0;
    command[4] = 4; command[5] = 9;
    memcpy( buffer, command, 24 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 24, &processed, &released );
    ok( status == STATUS_SUCCESS, "got interaction clear process status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got interaction clear commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got interaction clear batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_interaction_clear,
                               sizeof(expected_interaction_clear), "interaction clear" );

    command[0] = 23; command[1] = 3; command[2] = 0;
    memcpy( buffer, command, 12 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 12, &processed, &released );
    ok( status == STATUS_SUCCESS, "got visual clear process status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got visual clear commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got visual clear batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_visual_clear,
                               sizeof(expected_visual_clear), "visual clear" );

    command[0] = 4; command[1] = 2;
    command[2] = 16; command[3] = 1; command[4] = 0x34; command[5] = 3;
    memcpy( buffer, command, 24 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 24, &processed, &released );
    ok( status == STATUS_SUCCESS, "got replacement process status %#lx\n", status );
    ok( processed == 2, "got replacement process count %lu\n", processed );
    ok( released == 1, "got replacement released flag %#x\n", released );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got replacement commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got replacement batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_replace, sizeof(expected_replace), "replacement" );

    command[0] = 4; command[1] = 3;
    command[2] = 16; command[3] = 1; command[4] = 0x34; command[5] = 0;
    memcpy( buffer, command, 24 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 24, &processed, &released );
    ok( status == STATUS_SUCCESS, "got root-clear process status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got root-clear commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got root-clear batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_clear, sizeof(expected_clear), "root-clear" );

    command[0] = 16; command[1] = 1; command[2] = 0x35; command[3] = 0;
    memcpy( buffer, command, 16 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 16, &processed, &released );
    ok( status == STATUS_INVALID_PARAMETER, "got invalid root property status %#lx\n", status );
    command[1] = 4; command[2] = 0x34;
    memcpy( buffer, command, 16 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 16, &processed, &released );
    ok( status == STATUS_SUCCESS, "got generic reference-property status %#lx\n", status );
    command[1] = 1; command[3] = 4;
    memcpy( buffer, command, 16 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 16, &processed, &released );
    ok( status == STATUS_INVALID_PARAMETER, "got invalid root reference status %#lx\n", status );

    command[0] = 2; command[1] = 2; command[2] = 0xb8; command[3] = 0;
    command[4] = 16; command[5] = 1; command[6] = 0x34; command[7] = 2;
    memcpy( buffer, command, 32 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 32, &processed, &released );
    ok( status == STATUS_SUCCESS, "got root recreation process status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got root recreation commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got root recreation batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_recreate, sizeof(expected_recreate), "root recreation" );

    command[0] = 4; command[1] = 1;
    memcpy( buffer, command, 8 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 8, &processed, &released );
    ok( status == STATUS_SUCCESS, "got target release process status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got target release commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got target release batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_target_release,
                               sizeof(expected_target_release), "target release" );

    command[0] = 4; command[1] = 2;
    memcpy( buffer, command, 8 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 8, &processed, &released );
    ok( status == STATUS_SUCCESS, "got retained root release process status %#lx\n", status );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got retained root release commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got retained root release batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_root_release,
                               sizeof(expected_root_release), "retained root release" );

done:
    if (channel) NtDCompositionDestroyChannel( channel );
    if (target_handle) CloseHandle( target_handle );
    if (connection) NtDCompositionDestroyConnection( connection );
    if (hwnd) DestroyWindow( hwnd );
    CloseHandle( event );
}

static void test_hwnd_target_lifecycle(void)
{
    BYTE *buffer = (BYTE *)0xdeadbeef;
    HANDLE handles[3] = {NULL, NULL, NULL}, event;
    UINT channel = 0xcccccccc, size = 0x1000;
    HWND hwnd, destroyed_hwnd;
    ULONG processed;
    BYTE released;
    NTSTATUS status;
    BOOL ret;

    hwnd = CreateWindowExA( 0, "static", "dcomp target", WS_POPUP, 0, 0, 32, 32,
                            NULL, NULL, NULL, NULL );
    ok( !!hwnd, "failed to create target window, error %lu\n", GetLastError() );
    if (!hwnd) return;

    ret = NtUserCreateDCompositionHwndTarget( hwnd, 0, NULL );
    ok( !ret, "null-output create succeeded\n" );
    ok( RtlGetLastNtStatus() == STATUS_INVALID_PARAMETER, "got status %#lx\n",
        RtlGetLastNtStatus() );
    handles[0] = (HANDLE)0xdeadbeef;
    ret = NtUserCreateDCompositionHwndTarget( hwnd, 3, &handles[0] );
    ok( !ret, "invalid-type create succeeded\n" );
    ok( handles[0] == (HANDLE)0xdeadbeef, "invalid create changed handle to %p\n", handles[0] );
    handles[0] = NULL;

    for (size = 0; size < ARRAY_SIZE(handles); ++size)
    {
        ret = NtUserCreateDCompositionHwndTarget( hwnd, size, &handles[size] );
        ok( ret, "type %u create failed, status %#lx\n", size, RtlGetLastNtStatus() );
        ok( handles[size] && handles[size] != INVALID_HANDLE_VALUE,
            "type %u returned handle %p\n", size, handles[size] );
    }
    ret = NtUserCreateDCompositionHwndTarget( hwnd, 0, &event );
    ok( !ret, "duplicate create succeeded\n" );
    ok( RtlGetLastNtStatus() == STATUS_DCOMPOSITION_TARGET_ALREADY_EXISTS, "got duplicate status %#lx\n",
        RtlGetLastNtStatus() );

    size = 0x1000;
    status = NtDCompositionCreateChannel( &channel, &size, (void **)&buffer, 0 );
    ok( status == STATUS_SUCCESS, "got channel status %#lx\n", status );
    if (!status)
    {
        UINT64 shared;
        UINT command[6] = {3, 1, 0, 0, 0xb8, 0};

        event = CreateEventW( NULL, FALSE, FALSE, NULL );
        ok( !!event, "failed to create event, error %lu\n", GetLastError() );
        shared = (UINT_PTR)event;
        memcpy( command + 2, &shared, sizeof(shared) );
        memcpy( buffer, command, sizeof(command) );
        status = NtDCompositionProcessChannelBatchBuffer( channel, sizeof(command),
                                                           &processed, &released );
        ok( status != STATUS_SUCCESS, "non-target shared handle succeeded\n" );
        CloseHandle( event );

        shared = (UINT_PTR)handles[0];
        memcpy( command + 2, &shared, sizeof(shared) );
        memcpy( buffer, command, sizeof(command) );
        status = NtDCompositionProcessChannelBatchBuffer( channel, sizeof(command),
                                                           &processed, &released );
        ok( status == STATUS_SUCCESS, "target open command returned %#lx\n", status );
        ok( processed == 1, "got target open process count %lu\n", processed );

        command[0] = 10;
        command[1] = 1;
        command[2] = 0;
        memcpy( buffer, command, 12 );
        status = NtDCompositionProcessChannelBatchBuffer( channel, 12, &processed, &released );
        ok( status == STATUS_SUCCESS, "target property command returned %#lx\n", status );

        command[0] = 4;
        command[1] = 1;
        memcpy( buffer, command, 8 );
        status = NtDCompositionProcessChannelBatchBuffer( channel, 8, &processed, &released );
        ok( status == STATUS_SUCCESS, "target release command returned %#lx\n", status );

        destroyed_hwnd = CreateWindowExA( 0, "static", "destroyed dcomp target", WS_POPUP,
                                          0, 0, 32, 32, NULL, NULL, NULL, NULL );
        ok( !!destroyed_hwnd, "failed to create teardown window, error %lu\n", GetLastError() );
        event = NULL;
        ret = NtUserCreateDCompositionHwndTarget( destroyed_hwnd, 0, &event );
        ok( ret, "teardown target create failed, status %#lx\n", RtlGetLastNtStatus() );
        ret = DestroyWindow( destroyed_hwnd );
        ok( ret, "failed to destroy target window, error %lu\n", GetLastError() );
        command[0] = 3;
        command[1] = 2;
        shared = (UINT_PTR)event;
        memcpy( command + 2, &shared, sizeof(shared) );
        command[4] = 0xb8;
        command[5] = 0;
        memcpy( buffer, command, sizeof(command) );
        status = NtDCompositionProcessChannelBatchBuffer( channel, sizeof(command),
                                                           &processed, &released );
        ok( status == STATUS_ACCESS_DENIED, "destroyed-window target returned %#lx\n", status );
        CloseHandle( event );

        status = NtDCompositionDestroyChannel( channel );
        ok( status == STATUS_SUCCESS, "got channel destroy status %#lx\n", status );
    }

    CloseHandle( handles[0] );
    handles[0] = NULL;
    ret = NtUserCreateDCompositionHwndTarget( hwnd, 0, &event );
    ok( !ret, "target detached when its shared handle closed\n" );
    ret = NtUserDestroyDCompositionHwndTarget( hwnd, 0 );
    ok( ret, "target destroy failed, status %#lx\n", RtlGetLastNtStatus() );
    ret = NtUserCreateDCompositionHwndTarget( hwnd, 0, &handles[0] );
    ok( ret, "recreate after destroy failed, status %#lx\n", RtlGetLastNtStatus() );

    for (size = 0; size < ARRAY_SIZE(handles); ++size)
    {
        CloseHandle( handles[size] );
        ret = NtUserDestroyDCompositionHwndTarget( hwnd, size );
        ok( ret, "type %u destroy failed, status %#lx\n", size, RtlGetLastNtStatus() );
        ret = NtUserDestroyDCompositionHwndTarget( hwnd, size );
        ok( !ret, "type %u repeated destroy succeeded\n", size );
        ok( RtlGetLastNtStatus() == STATUS_NOT_FOUND, "type %u got status %#lx\n",
            size, RtlGetLastNtStatus() );
    }
    DestroyWindow( hwnd );
}

static void test_shared_resource_handle_lifecycle(void)
{
    static const UINT valid_types[] = {0x13, 0x82, 0xb8};
    static const UINT invalid_types[] = {0, 0x12, 0x14, 0x81, 0x83, 0xb7, 0xb9};
    BYTE *buffer = (BYTE *)0xdeadbeef;
    HANDLE handles[ARRAY_SIZE(valid_types)] = {0}, base_handle = NULL, event = NULL;
    UINT command[6], channel = 0xcccccccc, size = 0x1000, i;
    ULONG processed;
    BYTE released;
    NTSTATUS status;

    for (i = 0; i < ARRAY_SIZE(invalid_types); ++i)
    {
        HANDLE handle = (HANDLE)0xdeadbeef;

        status = NtDCompositionCreateSharedResourceHandle( invalid_types[i], &handle );
        ok( status == STATUS_INVALID_PARAMETER, "type %#x returned %#lx\n",
            invalid_types[i], status );
        ok( handle == (HANDLE)0xdeadbeef, "type %#x changed output to %p\n",
            invalid_types[i], handle );
    }
    status = NtDCompositionCreateSharedResourceHandle( 0xb8, NULL );
    ok( status == STATUS_INVALID_PARAMETER, "null output returned %#lx\n", status );

    status = NtDCompositionCreateChannel( &channel, &size, (void **)&buffer, 0 );
    ok( status == STATUS_SUCCESS, "got channel status %#lx\n", status );
    if (status) return;

    for (i = 0; i < ARRAY_SIZE(valid_types); ++i)
    {
        status = NtDCompositionCreateSharedResourceHandle( valid_types[i], &handles[i] );
        ok( status == STATUS_SUCCESS, "type %#x returned %#lx\n", valid_types[i], status );
        ok( !!handles[i] && handles[i] != INVALID_HANDLE_VALUE,
            "type %#x returned handle %p\n", valid_types[i], handles[i] );
        if (status) continue;

        command[0] = 3;
        command[1] = i + 1;
        memcpy( command + 2, &handles[i], sizeof(handles[i]) );
        command[4] = valid_types[i];
        command[5] = 0;
        memcpy( buffer, command, sizeof(command) );
        status = NtDCompositionProcessChannelBatchBuffer( channel, sizeof(command),
                                                           &processed, &released );
        ok( status == STATUS_SUCCESS, "type %#x open returned %#lx\n",
            valid_types[i], status );
        ok( processed == 1, "type %#x processed %lu commands\n",
            valid_types[i], processed );
    }

    command[0] = 3;
    command[1] = 4;
    memcpy( command + 2, &handles[1], sizeof(handles[1]) );
    command[4] = 0x82;
    command[5] = 1;
    memcpy( buffer, command, sizeof(command) );
    status = NtDCompositionProcessChannelBatchBuffer( channel, sizeof(command),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "type 0x82 mode 1 returned %#lx\n", status );
    ok( processed == 1, "type 0x82 mode 1 processed %lu commands\n", processed );

    ok( DuplicateHandle( GetCurrentProcess(), handles[1], GetCurrentProcess(), &base_handle,
                         0, FALSE, DUPLICATE_SAME_ACCESS ),
        "failed to duplicate type 0x82 handle, error %lu\n", GetLastError() );
    command[1] = 5;
    memcpy( command + 2, &base_handle, sizeof(base_handle) );
    command[4] = 0x43;
    command[5] = 0;
    memcpy( buffer, command, sizeof(command) );
    status = NtDCompositionProcessChannelBatchBuffer( channel, sizeof(command),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "type 0x82 base open returned %#lx\n", status );
    ok( processed == 1, "type 0x82 base open processed %lu commands\n", processed );

    command[1] = 6;
    memcpy( command + 2, &handles[2], sizeof(handles[2]) );
    command[4] = 0x82;
    command[5] = 0;
    memcpy( buffer, command, sizeof(command) );
    status = NtDCompositionProcessChannelBatchBuffer( channel, sizeof(command),
                                                       &processed, &released );
    ok( status == STATUS_INVALID_PARAMETER, "mismatched type returned %#lx\n", status );

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create event, error %lu\n", GetLastError() );
    command[1] = 6;
    memcpy( command + 2, &event, sizeof(event) );
    command[4] = 0xb8;
    memcpy( buffer, command, sizeof(command) );
    status = NtDCompositionProcessChannelBatchBuffer( channel, sizeof(command),
                                                       &processed, &released );
    ok( status == STATUS_OBJECT_TYPE_MISMATCH, "event handle returned %#lx\n", status );

    for (i = 1; i <= 5; ++i)
    {
        command[0] = 4;
        command[1] = i;
        memcpy( buffer, command, 8 );
        status = NtDCompositionProcessChannelBatchBuffer( channel, 8, &processed, &released );
        ok( status == STATUS_SUCCESS, "resource %u release returned %#lx\n", i, status );
    }

    if (event) CloseHandle( event );
    if (base_handle) CloseHandle( base_handle );
    for (i = 0; i < ARRAY_SIZE(handles); ++i) if (handles[i]) CloseHandle( handles[i] );
    status = NtDCompositionDestroyChannel( channel );
    ok( status == STATUS_SUCCESS, "got channel destroy status %#lx\n", status );
}

static void test_frame_lifecycle(void)
{
    struct dcomposition_frame_info frame_info = {0};
    struct dcomposition_confirm_frame_info confirm_info = {0};
    HANDLE event, ordinary_connection = NULL, connection = NULL;
    UINT64 frame_id = 0xcccccccccccccccc, queried_id;
    UINT token_count;
    BOOL has_more;
    NTSTATUS status;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create event, error %lu\n", GetLastError() );
    if (!event) return;

    status = NtDCompositionBeginFrame( NULL, NULL, NULL );
    ok( status == STATUS_INVALID_PARAMETER, "got null begin status %#lx\n", status );
    status = NtDCompositionConfirmFrame( NULL, NULL );
    ok( status == STATUS_INVALID_PARAMETER, "got null confirm status %#lx\n", status );
    status = NtDCompositionGetFrameId( 3, &queried_id );
    ok( status == STATUS_INVALID_PARAMETER, "got invalid type status %#lx\n", status );

    status = NtDCompositionCreateConnection( FALSE, event, &ordinary_connection );
    ok( status == STATUS_SUCCESS, "got ordinary connection status %#lx\n", status );
    status = NtDCompositionBeginFrame( ordinary_connection, &frame_info, &frame_id );
    ok( status == STATUS_ACCESS_DENIED, "got ordinary begin status %#lx\n", status );
    if (ordinary_connection) NtDCompositionDestroyConnection( ordinary_connection );

    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "got connection status %#lx\n", status );
    queried_id = 0xcccccccccccccccc;
    status = NtDCompositionGetFrameId( 0, &queried_id );
    ok( status == STATUS_UNSUCCESSFUL, "got initial query status %#lx\n", status );
    ok( queried_id == 0xcccccccccccccccc, "initial query changed id %s\n",
        wine_dbgstr_longlong(queried_id) );

    status = NtDCompositionBeginFrame( connection, &frame_info, NULL );
    ok( status == STATUS_INVALID_PARAMETER, "got null-output begin status %#lx\n", status );
    status = NtDCompositionBeginFrame( connection, &frame_info, &frame_id );
    ok( status == STATUS_SUCCESS, "got begin status %#lx\n", status );
    ok( frame_id && frame_id != 0xcccccccccccccccc, "got frame id %s\n",
        wine_dbgstr_longlong(frame_id) );
    token_count = 0xcccccccc;
    has_more = 0xcccccccc;
    status = NtDCompositionGetFrameLegacyTokens( &frame_id, &token_count, &has_more );
    ok( status == STATUS_SUCCESS, "got legacy-token status %#lx\n", status );
    ok( !token_count, "got legacy-token count %u\n", token_count );
    ok( !has_more, "got legacy-token continuation %u\n", has_more );
    queried_id = frame_id + 1;
    token_count = 0xcccccccc;
    has_more = 0xcccccccc;
    status = NtDCompositionGetFrameLegacyTokens( &queried_id, &token_count, &has_more );
    ok( status == STATUS_NOT_FOUND, "got unknown legacy-token status %#lx\n", status );
    ok( !token_count, "unknown legacy-token count %u\n", token_count );
    ok( !has_more, "unknown legacy-token continuation %u\n", has_more );
    token_count = 0xcccccccc;
    has_more = 0xcccccccc;
    status = NtDCompositionGetFrameSurfaceUpdates( &frame_id, &token_count, &has_more );
    ok( status == STATUS_SUCCESS, "got surface-update status %#lx\n", status );
    ok( !token_count, "got surface-update count %u\n", token_count );
    ok( !has_more, "got surface-update continuation %u\n", has_more );
    token_count = 0xcccccccc;
    has_more = 0xcccccccc;
    status = NtDCompositionGetFrameSurfaceUpdates( &queried_id, &token_count, &has_more );
    ok( status == STATUS_NOT_FOUND, "got unknown surface-update status %#lx\n", status );
    ok( !token_count, "unknown surface-update count %u\n", token_count );
    ok( !has_more, "unknown surface-update continuation %u\n", has_more );
    queried_id = 0;
    status = NtDCompositionGetFrameId( 0, &queried_id );
    ok( status == STATUS_SUCCESS, "got current query status %#lx\n", status );
    ok( queried_id == frame_id, "got current id %s expected %s\n", wine_dbgstr_longlong(queried_id),
        wine_dbgstr_longlong(frame_id) );
    status = NtDCompositionBeginFrame( connection, &frame_info, &queried_id );
    ok( status == STATUS_RESOURCE_IN_USE, "got repeated begin status %#lx\n", status );

    confirm_info.frame_id = frame_id + 1;
    status = NtDCompositionConfirmFrame( connection, &confirm_info );
    ok( status == STATUS_NOT_FOUND, "got unknown confirm status %#lx\n", status );
    confirm_info.frame_id = frame_id;
    confirm_info.update_count = 1;
    status = NtDCompositionConfirmFrame( connection, &confirm_info );
    ok( status == STATUS_INVALID_PARAMETER, "got missing updates status %#lx\n", status );
    confirm_info.update_count = 0;
    status = NtDCompositionConfirmFrame( connection, &confirm_info );
    ok( status == STATUS_SUCCESS, "got confirm status %#lx\n", status );

    queried_id = 0;
    status = NtDCompositionGetFrameId( 1, &queried_id );
    ok( status == STATUS_SUCCESS, "got confirmed query status %#lx\n", status );
    ok( queried_id == frame_id, "got confirmed id %s expected %s\n", wine_dbgstr_longlong(queried_id),
        wine_dbgstr_longlong(frame_id) );
    queried_id = 0;
    status = NtDCompositionGetFrameId( 2, &queried_id );
    ok( status == STATUS_SUCCESS, "got completed query status %#lx\n", status );
    ok( queried_id == frame_id, "got completed id %s expected %s\n", wine_dbgstr_longlong(queried_id),
        wine_dbgstr_longlong(frame_id) );

    if (connection) NtDCompositionDestroyConnection( connection );
    CloseHandle( event );
}

static void test_resource_retirement(void)
{
    void *resources = (void *)0xcccccccc;
    BYTE *buffer = (BYTE *)0xdeadbeef, released;
    UINT channel = 0xcccccccc, size = 0x1000, count;
    NTSTATUS status;

    count = 0xcccccccc;
    status = NtDCompositionGetDeletedResources( 0xdeadbeef, 0, &resources, &count );
    ok( status == STATUS_INVALID_PARAMETER, "got invalid zero-capacity status %#lx\n", status );
    ok( resources == (void *)0xcccccccc, "invalid zero-capacity resources changed to %p\n", resources );
    ok( count == 0xcccccccc, "invalid zero-capacity count changed to %#x\n", count );

    released = 0xcc;
    status = NtDCompositionReleaseAllResources( 0xdeadbeef, &released );
    ok( status == STATUS_ACCESS_DENIED, "got invalid release status %#lx\n", status );
    ok( released == 0xcc, "invalid release byte changed to %#x\n", released );
    status = NtDCompositionCreateChannel( &channel, &size, (void **)&buffer, 0 );
    ok( status == STATUS_SUCCESS, "got channel status %#lx\n", status );
    if (status) return;

    resources = (void *)0xcccccccc;
    count = 0xcccccccc;
    status = NtDCompositionGetDeletedResources( channel, 0, &resources, &count );
    ok( status == STATUS_INVALID_PARAMETER, "got zero-capacity status %#lx\n", status );
    ok( resources == (void *)0xcccccccc, "zero-capacity resources changed to %p\n", resources );
    ok( count == 0xcccccccc, "zero-capacity count changed to %#x\n", count );
    status = NtDCompositionGetDeletedResources( channel, 1, &resources, &count );
    ok( status == STATUS_SUCCESS, "got empty deleted-resource status %#lx\n", status );
    ok( !resources, "got empty deleted resources %p\n", resources );
    ok( !count, "got empty deleted-resource count %#x\n", count );

    released = 0xcc;
    status = NtDCompositionReleaseAllResources( channel, &released );
    ok( status == STATUS_SUCCESS, "got release status %#lx\n", status );
    ok( !released, "got release byte %#x\n", released );
    released = 0x55;
    status = NtDCompositionReleaseAllResources( channel, &released );
    ok( status == STATUS_SUCCESS, "got repeated release status %#lx\n", status );
    ok( !released, "got repeated release byte %#x\n", released );

    status = NtDCompositionDestroyChannel( channel );
    ok( status == STATUS_SUCCESS, "got destroy status %#lx\n", status );
    buffer = NULL;
    released = 0xcc;
    status = NtDCompositionReleaseAllResources( channel, &released );
    ok( status == STATUS_ACCESS_DENIED, "got stale release status %#lx\n", status );
    ok( released == 0xcc, "stale release byte changed to %#x\n", released );
    resources = (void *)0xcccccccc;
    count = 0xcccccccc;
    status = NtDCompositionGetDeletedResources( channel, 1, &resources, &count );
    ok( status == STATUS_ACCESS_DENIED, "got stale deleted-resource status %#lx\n", status );
    ok( resources == (void *)0xcccccccc, "stale deleted resources changed to %p\n", resources );
    ok( count == 0xcccccccc, "stale deleted-resource count changed to %#x\n", count );
}

static void test_composition_surface_lifecycle(void)
{
    struct dcomposition_token_surface_update updates[2] = {0};
    OBJECT_ATTRIBUTES attributes = {0};
    UINT64 connection = 1, device = 2, binding_id = 0, second_binding_id;
    BYTE buffer_info[0x520] = {0};
    BYTE queried_info[0x520] = {0};
    BYTE realization[0x178], zero_realization[0x178] = {0};
    BYTE dirty_region[0xa4], dirty_region_sentinel[0xa4];
    HANDLE surface, token, second_token, ordinary, mapping = NULL, queried_mapping = NULL;
    void *mapping_view = NULL;
    LUID luid;
    NTSTATUS status;

    ordinary = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!ordinary, "failed to create ordinary surface-test handle, error %lu\n",
        GetLastError() );
    if (!ordinary) return;
    luid.LowPart = 0xcccccccc;
    luid.HighPart = 0xcccccccc;
    status = NtValidateCompositionSurfaceHandle( ordinary, &luid );
    ok( status == STATUS_OBJECT_TYPE_MISMATCH, "got ordinary validation status %#lx\n", status );
    ok( luid.LowPart == 0xcccccccc && luid.HighPart == 0xcccccccc,
        "ordinary validation changed luid %#lx:%#lx\n", luid.HighPart, luid.LowPart );
    memset( realization, 0xcc, sizeof(realization) );
    status = NtQueryCompositionSurfaceRenderingRealization( ordinary, realization );
    ok( status == STATUS_OBJECT_TYPE_MISMATCH, "got ordinary realization status %#lx\n", status );
    ok( !memcmp( realization, zero_realization, sizeof(realization) ),
        "ordinary realization did not clear output\n" );
    memset( dirty_region, 0xcc, sizeof(dirty_region) );
    memcpy( dirty_region_sentinel, dirty_region, sizeof(dirty_region) );
    status = NtOpenCompositionSurfaceDirtyRegion( ordinary, &binding_id,
                                                   buffer_info + 0xa0, dirty_region );
    ok( status == STATUS_OBJECT_TYPE_MISMATCH, "got ordinary dirty-region status %#lx\n", status );
    ok( !memcmp( dirty_region, dirty_region_sentinel, sizeof(dirty_region) ),
        "ordinary dirty-region query changed output\n" );

    status = NtCreateCompositionSurfaceHandle(NULL, 3, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "got status %#lx\n", status);

    attributes.Length = sizeof(attributes) - 1;
    surface = (HANDLE)0xdeadbeef;
    status = NtCreateCompositionSurfaceHandle(&attributes, 3, &surface);
    ok(status == STATUS_INVALID_PARAMETER, "got status %#lx\n", status);
    ok(surface == INVALID_HANDLE_VALUE, "got surface %p\n", surface);

    status = NtCreateCompositionSurfaceHandle(NULL, 3, &surface);
    ok(status == STATUS_SUCCESS, "got status %#lx\n", status);
    ok(surface && surface != INVALID_HANDLE_VALUE, "got surface %p\n", surface);
    if (status)
    {
        CloseHandle( ordinary );
        return;
    }

    status = NtValidateCompositionSurfaceHandle( surface, NULL );
    ok( status == STATUS_INVALID_PARAMETER, "got null luid validation status %#lx\n", status );
    luid.LowPart = 0;
    luid.HighPart = 0;
    status = NtValidateCompositionSurfaceHandle( surface, &luid );
    ok( status == STATUS_SUCCESS, "got surface validation status %#lx\n", status );
    ok( luid.LowPart || luid.HighPart, "got zero surface luid\n" );
    memset( realization, 0xcc, sizeof(realization) );
    status = NtQueryCompositionSurfaceRenderingRealization( surface, realization );
    ok( status == STATUS_UNSUCCESSFUL, "got unbound realization status %#lx\n", status );
    ok( !memcmp( realization, zero_realization, sizeof(realization) ),
        "unbound realization did not clear output\n" );
    status = NtQueryCompositionSurfaceRenderingRealization( surface, NULL );
    ok( status == STATUS_INVALID_PARAMETER, "got null realization status %#lx\n", status );
    status = NtOpenCompositionSurfaceDirtyRegion( surface, NULL,
                                                   buffer_info + 0xa0, dirty_region );
    ok( status == STATUS_INVALID_PARAMETER, "got null binding dirty-region status %#lx\n", status );
    status = NtOpenCompositionSurfaceDirtyRegion( surface, &binding_id, NULL, dirty_region );
    ok( status == STATUS_INVALID_PARAMETER, "got null info dirty-region status %#lx\n", status );
    status = NtOpenCompositionSurfaceDirtyRegion( surface, &binding_id,
                                                   buffer_info + 0xa0, NULL );
    ok( status == STATUS_INVALID_PARAMETER, "got null output dirty-region status %#lx\n", status );
    status = NtOpenCompositionSurfaceDirtyRegion( surface, &binding_id,
                                                   buffer_info + 0xa0, dirty_region );
    ok( status == STATUS_NOT_FOUND, "got unbound dirty-region status %#lx\n", status );

    mapping = CreateFileMappingW( INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x1000, NULL );
    ok( !!mapping, "failed to create composition realization, error %lu\n", GetLastError() );
    *(UINT *)(buffer_info + 0x00) = 1;
    *(UINT *)(buffer_info + 0x54) = 1;
    *(UINT *)(buffer_info + 0x98) = 2;
    *(UINT *)(buffer_info + 0x9c) = 1;
    *(UINT *)(buffer_info + 0xa0) = 2;
    *(HANDLE *)(buffer_info + 0xa8) = mapping;
    buffer_info[0x120] = 0x5a;
    binding_id = 0xdeadbeef;
    status = NtBindCompositionSurface(surface, TRUE, 0, FALSE, NULL, &binding_id);
    ok(status == STATUS_INVALID_PARAMETER, "got status %#lx\n", status);
    status = NtBindCompositionSurface(surface, TRUE, 0, FALSE, buffer_info, &binding_id);
    ok(status == STATUS_SUCCESS, "got status %#lx\n", status);
    ok(binding_id != 0, "got binding id %I64u\n", binding_id);
    ok( binding_id == (((UINT64)(UINT)luid.HighPart << 32) | luid.LowPart),
        "got binding id %I64u, luid %#lx:%#lx\n", binding_id, luid.HighPart, luid.LowPart );
    CloseHandle( mapping );
    mapping = NULL;

    memset( dirty_region, 0xcc, sizeof(dirty_region) );
    status = NtOpenCompositionSurfaceDirtyRegion( surface, &binding_id,
                                                   buffer_info + 0xa0, dirty_region );
    ok( status == STATUS_SUCCESS, "got bound dirty-region status %#lx\n", status );
    ok( !*(UINT *)(dirty_region + 0xa0), "got bound dirty-region count %u\n",
        *(UINT *)(dirty_region + 0xa0) );
    second_binding_id = binding_id + 1;
    memset( dirty_region, 0xcc, sizeof(dirty_region) );
    memcpy( dirty_region_sentinel, dirty_region, sizeof(dirty_region) );
    status = NtOpenCompositionSurfaceDirtyRegion( surface, &second_binding_id,
                                                   buffer_info + 0xa0, dirty_region );
    ok( status == STATUS_NOT_FOUND, "got mismatched dirty-region binding status %#lx\n", status );
    ok( !memcmp( dirty_region, dirty_region_sentinel, sizeof(dirty_region) ),
        "mismatched dirty-region query changed output\n" );
    *(UINT *)(buffer_info + 0xa4) = 1;
    status = NtOpenCompositionSurfaceDirtyRegion( surface, &binding_id,
                                                   buffer_info + 0xa0, dirty_region );
    ok( status == STATUS_NOT_FOUND, "got mismatched realization status %#lx\n", status );
    *(UINT *)(buffer_info + 0xa4) = 0;

    status = NtQueryCompositionSurfaceBinding( surface, &binding_id, queried_info );
    ok( status == STATUS_SUCCESS, "got binding query status %#lx\n", status );
    queried_mapping = *(HANDLE *)(queried_info + 0xa8);
    ok( !!queried_mapping, "got null queried realization\n" );
    *(HANDLE *)(buffer_info + 0xa8) = NULL;
    *(HANDLE *)(queried_info + 0xa8) = NULL;
    ok( !memcmp( queried_info, buffer_info, sizeof(buffer_info) ),
        "queried binding information differs from bound information\n" );
    if (queried_mapping)
    {
        mapping_view = MapViewOfFile( queried_mapping, FILE_MAP_READ, 0, 0, 0x1000 );
        ok( !!mapping_view, "failed to map queried realization, error %lu\n", GetLastError() );
        if (mapping_view) UnmapViewOfFile( mapping_view );
        CloseHandle( queried_mapping );
        queried_mapping = NULL;
    }
    second_binding_id = binding_id + 1;
    status = NtQueryCompositionSurfaceBinding( surface, &second_binding_id, queried_info );
    ok( status == STATUS_NOT_FOUND, "got mismatched binding query status %#lx\n", status );

    updates[0].surface = surface;
    updates[0].right = 16;
    updates[0].bottom = 16;
    updates[1] = updates[0];
    updates[1].left = 16;
    updates[1].right = 32;
    token = (HANDLE)0xdeadbeef;
    status = NtTokenManagerCreateCompositionTokenHandle(updates, 2, 0,
            &connection, &device, &token);
    ok(status == STATUS_INVALID_PARAMETER, "got status %#lx\n", status);
    ok(token == (HANDLE)0xdeadbeef, "got token %p\n", token);

    status = NtTokenManagerCreateCompositionTokenHandle(updates, 2, 1,
            &connection, &device, &token);
    ok(status == STATUS_SUCCESS, "got status %#lx\n", status);
    ok(token && token != INVALID_HANDLE_VALUE, "got token %p\n", token);

    status = NtUnBindCompositionSurface(surface, TRUE, FALSE);
    ok(status == STATUS_SUCCESS, "got status %#lx\n", status);
    status = NtQueryCompositionSurfaceBinding( surface, &binding_id, queried_info );
    ok( status == STATUS_NOT_FOUND, "got unbound binding query status %#lx\n", status );
    second_token = (HANDLE)0xdeadbeef;
    status = NtTokenManagerCreateCompositionTokenHandle(updates, 2, 1,
            &connection, &device, &second_token);
    ok(status == STATUS_ACCESS_DENIED, "got status %#lx\n", status);
    ok(second_token == INVALID_HANDLE_VALUE, "got token %p\n", second_token);

    status = NtBindCompositionSurface(surface, TRUE, 0, FALSE, buffer_info, &second_binding_id);
    ok(status == STATUS_SUCCESS, "got status %#lx\n", status);
    ok(second_binding_id == binding_id, "got binding ids %I64u and %I64u\n",
            binding_id, second_binding_id);

    if (token && token != INVALID_HANDLE_VALUE) NtClose(token);
    if (mapping) CloseHandle(mapping);
    if (queried_mapping) CloseHandle(queried_mapping);
    NtClose(surface);
    if (ordinary) CloseHandle(ordinary);
}

static void test_token_manager_lifetime(void)
{
    HANDLE work_event, ordinary_connection = NULL, dwm_connection = NULL;
    HANDLE token_stop, thread;
    HANDLE section = NULL, event_a = NULL, event_b = NULL;
    HANDLE section2 = NULL, event_a2 = NULL, event_b2 = NULL;
    SIZE_T section_size = ~(SIZE_T)0, section_size2 = ~(SIZE_T)0;
    NTSTATUS status;
    struct token_manager_adapter_info adapter = {0};
    struct token_thread_context thread_context = {0};
    void *view;

    work_event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!work_event, "CreateEventW failed, error %lu\n", GetLastError() );
    if (!work_event) return;
    token_stop = CreateEventW( NULL, TRUE, FALSE, NULL );
    ok( !!token_stop, "CreateEventW failed, error %lu\n", GetLastError() );
    if (!token_stop)
    {
        CloseHandle( work_event );
        return;
    }

    thread_context.info.stop_event = token_stop;
    thread_context.info.adapters = &adapter;
    thread_context.info.adapter_count = 1;
    status = NtTokenManagerThread( NULL );
    ok( status == STATUS_INVALID_PARAMETER, "got null-info status %#lx\n", status );
    thread_context.info.adapter_count = 0;
    status = NtTokenManagerThread( &thread_context.info );
    ok( status == STATUS_INVALID_PARAMETER, "got zero-count status %#lx\n", status );
    thread_context.info.adapter_count = 1;
    thread_context.info.adapters = (void *)1;
    status = NtTokenManagerThread( &thread_context.info );
    ok( status == STATUS_INVALID_PARAMETER, "got invalid-adapter status %#lx\n", status );
    thread_context.info.adapters = &adapter;

    status = NtDCompositionCreateConnection( FALSE, work_event, &ordinary_connection );
    ok( status == STATUS_SUCCESS, "got status %#lx\n", status );
    status = NtTokenManagerOpenSectionAndEvents( &section, &section_size, &event_a, &event_b );
    ok( status == STATUS_ACCESS_DENIED, "got status %#lx\n", status );
    status = NtTokenManagerThread( &thread_context.info );
    ok( status == STATUS_ACCESS_DENIED, "got ordinary worker status %#lx\n", status );
    ok( section == INVALID_HANDLE_VALUE, "got section %p\n", section );
    ok( !section_size, "got section size %Iu\n", section_size );
    ok( event_a == INVALID_HANDLE_VALUE, "got event_a %p\n", event_a );
    ok( event_b == INVALID_HANDLE_VALUE, "got event_b %p\n", event_b );
    if (ordinary_connection) NtDCompositionDestroyConnection( ordinary_connection );

    status = NtDCompositionCreateConnection( TRUE, work_event, &dwm_connection );
    ok( status == STATUS_SUCCESS, "got status %#lx\n", status );
    status = NtTokenManagerOpenSectionAndEvents( &section, &section_size, &event_a, &event_b );
    ok( status == STATUS_SUCCESS, "got status %#lx\n", status );
    ok( section && section != INVALID_HANDLE_VALUE, "got section %p\n", section );
    ok( section_size == 0x1000, "got section size %Iu\n", section_size );
    ok( event_a && event_a != INVALID_HANDLE_VALUE, "got event_a %p\n", event_a );
    ok( event_b && event_b != INVALID_HANDLE_VALUE, "got event_b %p\n", event_b );
    view = MapViewOfFile( section, FILE_MAP_READ, 0, 0, section_size );
    ok( !!view, "MapViewOfFile failed, error %lu\n", GetLastError() );
    if (view) UnmapViewOfFile( view );

    status = NtTokenManagerOpenSectionAndEvents( &section2, &section_size2, &event_a2, &event_b2 );
    ok( status == STATUS_SUCCESS, "got status %#lx\n", status );
    ok( section_size2 == section_size, "got section size %Iu\n", section_size2 );
    ok( SetEvent( event_a ), "SetEvent failed, error %lu\n", GetLastError() );
    ok( WaitForSingleObject( event_a2, 0 ) == WAIT_OBJECT_0, "event_a handles do not share state\n" );
    ok( WaitForSingleObject( event_a, 0 ) == WAIT_OBJECT_0, "event_a is not manual reset\n" );
    ok( ResetEvent( event_a ), "ResetEvent failed, error %lu\n", GetLastError() );
    ok( SetEvent( event_b ), "SetEvent failed, error %lu\n", GetLastError() );
    ok( WaitForSingleObject( event_b2, 0 ) == WAIT_OBJECT_0, "event_b handles do not share state\n" );
    ok( WaitForSingleObject( event_b, 0 ) == WAIT_TIMEOUT, "event_b is not auto reset\n" );

    thread_context.status = 0xdeadbeef;
    thread = CreateThread( NULL, 0, token_thread, &thread_context, 0, NULL );
    ok( !!thread, "CreateThread failed, error %lu\n", GetLastError() );
    if (thread)
    {
        Sleep(50);
        ok( WaitForSingleObject( thread, 0 ) == WAIT_TIMEOUT, "token worker returned early, status %#lx\n",
            thread_context.status );
        ok( SetEvent( event_b ), "SetEvent failed, error %lu\n", GetLastError() );
        Sleep(10);
        ok( SetEvent( token_stop ), "SetEvent failed, error %lu\n", GetLastError() );
        ok( WaitForSingleObject( thread, 2000 ) == WAIT_OBJECT_0, "token worker did not stop\n" );
        ok( thread_context.status == STATUS_SUCCESS, "got token worker status %#lx\n", thread_context.status );
        CloseHandle( thread );
    }

    CloseHandle( section );
    CloseHandle( event_a );
    CloseHandle( event_b );
    CloseHandle( section2 );
    CloseHandle( event_a2 );
    CloseHandle( event_b2 );
    if (dwm_connection) NtDCompositionDestroyConnection( dwm_connection );

    section = NULL;
    event_a = NULL;
    event_b = NULL;
    section_size = ~(SIZE_T)0;
    status = NtTokenManagerOpenSectionAndEvents( &section, &section_size, &event_a, &event_b );
    ok( status == STATUS_ACCESS_DENIED, "got status %#lx\n", status );
    CloseHandle( token_stop );
    CloseHandle( work_event );
}

struct hlsurf_test_surface_info
{
    UINT type;
    UINT width;
    UINT height;
    UINT stride;
    UINT flags;
    UINT64 update_id;
    LUID adapter_luid;
    HANDLE section;
};

struct hlsurf_test_dirty_info
{
    UINT64 update_id;
    HRGN dirty_region;
    HRGN valid_region;
    HRGN invalid_region;
    UINT64 signal_id;
    UINT64 present_id;
    UINT present_flags;
    UINT reserved;
};

struct hlsurf_test_signal_info
{
    BOOL enable;
    UINT reserved;
    HANDLE event;
    LUID adapter_luid;
};

struct hlsurf_test_redirection_info
{
    UINT style;
    UINT width;
    UINT height;
    LUID adapter_luid;
    UINT reserved;
    HANDLE section;
};

static void test_hlsurf_protocol(HWND window, HANDLE surface)
{
    BOOL (WINAPI *pDwmHLSurfOpenCompositorRef)(HANDLE);
    BOOL (WINAPI *pDwmHLSurfCloseCompositorRef)(HANDLE);
    BOOL (WINAPI *pDwmGetSurfaceData)(HANDLE, void *);
    BOOL (WINAPI *pDwmGetRedirectionStyle)(HANDLE, void *);
    BOOL (WINAPI *pDwmHLSurfGetDirtyRgn)(HANDLE, UINT64, HRGN *, HRGN *, HRGN *, UINT64 *, UINT64 *, UINT *, UINT *);
    BOOL (WINAPI *pDwmHLSurfSetSignalOnDirty)(HANDLE, LUID, HANDLE, BOOL);
    BOOL (WINAPI *pDwmHLsurfSetPresentFlags)(HANDLE, UINT);
    BOOL (WINAPI *pDwmHLsurfSetUpdatedId)(HANDLE, const UINT64 *);
    BOOL (WINAPI *pDwmGetDirtyRgn)(HANDLE, UINT64, HRGN *, HRGN *, HRGN *);
    struct hlsurf_test_surface_info surface_info = {0};
    struct hlsurf_test_dirty_info dirty_info = {0};
    struct hlsurf_test_redirection_info redirection_info = {0};
    HMODULE gdi32 = GetModuleHandleA( "gdi32.dll" );
    SIZE_T view_size = 0;
    UINT64 update_id = 0x123456789abcdef0, signal_id = 0, present_id = 0;
    UINT present_flags = 0x24, reserved = 0;
    void *view = NULL;
    HANDLE event;
    LUID adapter_luid = {0};
    HBRUSH brush;
    RECT rect;
    HDC hdc;
    BOOL ret;
    NTSTATUS status;

    pDwmHLSurfSetSignalOnDirty = (void *)GetProcAddress( gdi32, (const char *)(UINT_PTR)1000 );
    pDwmHLsurfSetPresentFlags = (void *)GetProcAddress( gdi32, (const char *)(UINT_PTR)1001 );
    pDwmHLsurfSetUpdatedId = (void *)GetProcAddress( gdi32, (const char *)(UINT_PTR)1002 );
    pDwmGetSurfaceData = (void *)GetProcAddress( gdi32, (const char *)(UINT_PTR)1003 );
    pDwmGetRedirectionStyle = (void *)GetProcAddress( gdi32, (const char *)(UINT_PTR)1006 );
    pDwmHLSurfGetDirtyRgn = (void *)GetProcAddress( gdi32, (const char *)(UINT_PTR)1007 );
    pDwmGetDirtyRgn = (void *)GetProcAddress( gdi32, (const char *)(UINT_PTR)1008 );
    pDwmHLSurfOpenCompositorRef = (void *)GetProcAddress( gdi32, (const char *)(UINT_PTR)1009 );
    pDwmHLSurfCloseCompositorRef = (void *)GetProcAddress( gdi32, (const char *)(UINT_PTR)1010 );
    ok( pDwmHLSurfSetSignalOnDirty && pDwmHLsurfSetPresentFlags &&
        pDwmHLsurfSetUpdatedId && pDwmGetSurfaceData && pDwmGetRedirectionStyle &&
        pDwmHLSurfGetDirtyRgn && pDwmGetDirtyRgn && pDwmHLSurfOpenCompositorRef &&
        pDwmHLSurfCloseCompositorRef, "missing private GDI32 HLSURF exports\n" );
    if (!pDwmHLSurfSetSignalOnDirty || !pDwmHLsurfSetPresentFlags ||
        !pDwmHLsurfSetUpdatedId || !pDwmGetSurfaceData || !pDwmGetRedirectionStyle ||
        !pDwmHLSurfGetDirtyRgn || !pDwmGetDirtyRgn || !pDwmHLSurfOpenCompositorRef ||
        !pDwmHLSurfCloseCompositorRef) return;

    SetLastError( 0xdeadbeef );
    ret = pDwmHLSurfOpenCompositorRef( surface );
    ok( ret, "logical-surface open failed, error %lu\n", GetLastError() );
    if (!ret) return;

    ret = pDwmHLsurfSetPresentFlags( surface, present_flags );
    ok( ret, "present-flags update failed, error %lu\n", GetLastError() );
    ret = pDwmHLsurfSetUpdatedId( surface, &update_id );
    ok( ret, "update-ID update failed, error %lu\n", GetLastError() );

    ret = pDwmGetSurfaceData( surface, &surface_info );
    ok( ret, "surface-data query failed, error %lu\n", GetLastError() );
    ok( surface_info.type == 1, "got surface type %u\n", surface_info.type );
    ok( surface_info.width >= 32 && surface_info.height >= 32,
        "got surface size %ux%u\n", surface_info.width, surface_info.height );
    ok( surface_info.stride >= surface_info.width * 4,
        "got surface stride %u for width %u\n", surface_info.stride, surface_info.width );
    ok( !!surface_info.section, "surface section is null\n" );
    ok( surface_info.update_id == update_id, "got update ID %#I64x\n", surface_info.update_id );
    if (surface_info.section)
    {
        status = NtMapViewOfSection( surface_info.section, GetCurrentProcess(), &view,
                                     0, 0, NULL, &view_size, ViewUnmap, 0, PAGE_READONLY );
        ok( !status, "surface section map returned %#lx\n", status );
        if (view) NtUnmapViewOfSection( GetCurrentProcess(), view );
        CloseHandle( surface_info.section );
    }

    ret = pDwmGetRedirectionStyle( surface, &redirection_info );
    ok( ret, "redirection-style query failed, error %lu\n", GetLastError() );
    ok( redirection_info.style == 1, "got redirection style %u\n", redirection_info.style );
    ok( redirection_info.width == surface_info.width && redirection_info.height == surface_info.height,
        "got redirection size %ux%u, expected %ux%u\n", redirection_info.width,
        redirection_info.height, surface_info.width, surface_info.height );
    ok( !!redirection_info.section, "redirection section is null\n" );
    if (redirection_info.section) CloseHandle( redirection_info.section );

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "dirty event creation failed, error %lu\n", GetLastError() );
    if (event)
    {
        ret = pDwmHLSurfSetSignalOnDirty( surface, adapter_luid, event, TRUE );
        ok( ret, "dirty-event registration failed, error %lu\n", GetLastError() );

        GetClientRect( window, &rect );
        hdc = GetDC( window );
        brush = CreateSolidBrush( RGB( 0x24, 0x68, 0xac ) );
        ok( !!hdc && !!brush, "paint setup failed, dc %p brush %p\n", hdc, brush );
        if (hdc && brush) FillRect( hdc, &rect, brush );
        if (brush) DeleteObject( brush );
        if (hdc) ReleaseDC( window, hdc );
        GdiFlush();
        ok( MsgWaitForMultipleObjects( 1, &event, FALSE, 2000, QS_ALLINPUT ) == WAIT_OBJECT_0,
            "logical-surface dirty event was not signaled\n" );

        ret = pDwmHLSurfSetSignalOnDirty( surface, adapter_luid, NULL, FALSE );
        ok( ret, "dirty-event unregister failed, error %lu\n", GetLastError() );
        CloseHandle( event );
    }

    ret = pDwmHLSurfGetDirtyRgn( surface, 0, &dirty_info.dirty_region,
                                 &dirty_info.valid_region, &dirty_info.invalid_region,
                                 &signal_id, &present_id, &dirty_info.present_flags, &reserved );
    ok( ret, "dirty-region query failed, error %lu\n", GetLastError() );
    ok( !!dirty_info.dirty_region && !!dirty_info.valid_region && !!dirty_info.invalid_region,
        "got dirty regions %p, %p, %p\n", dirty_info.dirty_region,
        dirty_info.valid_region, dirty_info.invalid_region );
    ok( dirty_info.present_flags == present_flags, "got present flags %#x\n",
        dirty_info.present_flags );
    if (dirty_info.dirty_region) DeleteObject( dirty_info.dirty_region );
    if (dirty_info.valid_region) DeleteObject( dirty_info.valid_region );
    if (dirty_info.invalid_region) DeleteObject( dirty_info.invalid_region );

    SetLastError( 0xdeadbeef );
    ret = pDwmGetDirtyRgn( surface, 0, NULL, NULL, NULL );
    ok( !ret && GetLastError() == ERROR_NOT_SUPPORTED,
        "legacy dirty-region query returned %u, error %lu\n", ret, GetLastError() );

    ret = pDwmHLSurfCloseCompositorRef( surface );
    ok( ret, "logical-surface close failed, error %lu\n", GetLastError() );
}

static void test_hlsurf_destroyed_window_lifetime(HANDLE surface)
{
    BOOL (WINAPI *open_surface)(HANDLE);
    BOOL (WINAPI *get_surface)(HANDLE, void *);
    BOOL (WINAPI *close_surface)(HANDLE);
    struct hlsurf_test_surface_info info = {0};
    HMODULE gdi32 = GetModuleHandleA( "gdi32.dll" );
    BOOL ret;

    open_surface = (void *)GetProcAddress( gdi32, (const char *)(UINT_PTR)1009 );
    get_surface = (void *)GetProcAddress( gdi32, (const char *)(UINT_PTR)1003 );
    close_surface = (void *)GetProcAddress( gdi32, (const char *)(UINT_PTR)1010 );
    if (!open_surface || !get_surface || !close_surface) return;

    ret = open_surface( surface );
    ok( ret, "queued logical surface did not outlive its HWND, error %lu\n", GetLastError() );
    if (!ret) return;
    ret = get_surface( surface, &info );
    ok( ret && info.section, "destroyed-window surface query returned %u, section %p, error %lu\n",
        ret, info.section, GetLastError() );
    if (info.section) CloseHandle( info.section );
    ret = close_surface( surface );
    ok( ret, "destroyed-window surface close failed, error %lu\n", GetLastError() );
}

static void test_blurred_wallpaper_surface_delivery( HANDLE port, LARGE_INTEGER *timeout )
{
    struct dwm_session_message received = {0};
    RECT rect = {-32, -16, 1280, 800}, received_rect = {0};
    HANDLE event = NULL, connection = NULL, surface = NULL, wrong_type = NULL, dwm_surface = NULL;
    UINT channel = 0, channel_size = 0x1000;
    UINT create[] = {2, 1, 0xbe, 1};
    UINT publish[] = {9, 1, 0, 0};
    BYTE *buffer = NULL, released;
    ULONG processed;
    NTSTATUS status;
    SIZE_T size;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "wallpaper connection event creation failed, error %lu\n", GetLastError() );
    if (!event) return;
    status = NtDCompositionCreateConnection( TRUE, event, &connection );
    ok( status == STATUS_SUCCESS, "wallpaper connection creation returned %#lx\n", status );
    if (status) goto done;
    status = NtDCompositionCreateChannel( &channel, &channel_size, (void **)&buffer, 0 );
    ok( status == STATUS_SUCCESS, "wallpaper channel creation returned %#lx\n", status );
    if (status) goto done;

    memcpy( buffer, create, sizeof(create) );
    status = NtDCompositionProcessChannelBatchBuffer( channel, sizeof(create),
                                                       &processed, &released );
    ok( status == STATUS_SUCCESS, "wallpaper surface creation returned %#lx\n", status );
    memcpy( buffer, publish, sizeof(publish) );
    status = NtDCompositionProcessChannelBatchBuffer( channel, sizeof(publish),
                                                       &processed, &released );
    memcpy( &surface, buffer + 8, sizeof(surface) );
    ok( status == STATUS_SUCCESS && !!surface,
        "wallpaper surface publish returned %#lx, handle %p\n", status, surface );
    if (status || !surface) goto done;

    status = NtDCompositionSetBlurredWallpaperSurface( surface, NULL );
    ok( status == STATUS_INVALID_PARAMETER,
        "wallpaper surface without rectangle returned %#lx\n", status );

    status = NtDCompositionCreateSharedResourceHandle( 0xb8, &wrong_type );
    ok( status == STATUS_SUCCESS, "wrong-type wallpaper handle returned %#lx\n", status );
    if (!status)
    {
        status = NtDCompositionSetBlurredWallpaperSurface( wrong_type, &rect );
        ok( status == STATUS_INVALID_PARAMETER,
            "wrong-type wallpaper surface returned %#lx\n", status );
    }

    status = NtDCompositionSetBlurredWallpaperSurface( surface, &rect );
    ok( status == STATUS_SUCCESS, "wallpaper surface set returned %#lx\n", status );
    memset( &received, 0, sizeof(received) );
    size = sizeof(received);
    status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                        &size, NULL, timeout );
    ok( status == STATUS_SUCCESS, "wallpaper surface receive returned %#lx\n", status );
    ok( !status && received.header.Type == (ALPC_MESSAGE_TYPE_DATAGRAM | 0x8000),
        "got wallpaper surface type %#x\n", received.header.Type );
    ok( !status && received.header.DataLength == 28,
        "got wallpaper surface length %#x\n", received.header.DataLength );
    ok( !status && received.data[0] == 0x40000058,
        "got wallpaper surface command %#lx\n", received.data[0] );
    if (!status)
    {
        memcpy( &dwm_surface, received.data + 1, sizeof(dwm_surface) );
        memcpy( &received_rect, received.data + 3, sizeof(received_rect) );
    }
    ok( !!dwm_surface && dwm_surface != surface,
        "got DWM wallpaper handle %p, source %p\n", dwm_surface, surface );
    ok( EqualRect( &received_rect, &rect ), "got wallpaper rectangle %s, expected %s\n",
        wine_dbgstr_rect( &received_rect ), wine_dbgstr_rect( &rect ) );
    if (dwm_surface) CloseHandle( dwm_surface );

    status = NtDCompositionSetBlurredWallpaperSurface( NULL, NULL );
    ok( status == STATUS_SUCCESS, "wallpaper surface clear returned %#lx\n", status );
    memset( &received, 0, sizeof(received) );
    size = sizeof(received);
    status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                        &size, NULL, timeout );
    ok( status == STATUS_SUCCESS, "wallpaper surface clear receive returned %#lx\n", status );
    ok( !status && received.header.DataLength == 28 &&
        received.data[0] == 0x40000058 && !received.data[1] && !received.data[2],
        "got wallpaper surface clear length %#x payload %#lx/%#lx/%#lx\n",
        received.header.DataLength, received.data[0], received.data[1], received.data[2] );
    if (!status)
    {
        memcpy( &received_rect, received.data + 3, sizeof(received_rect) );
        ok( IsRectEmpty( &received_rect ), "got nonempty clear rectangle %s\n",
            wine_dbgstr_rect( &received_rect ) );
    }

done:
    if (wrong_type) CloseHandle( wrong_type );
    if (surface) CloseHandle( surface );
    if (channel) NtDCompositionDestroyChannel( channel );
    if (connection) NtDCompositionDestroyConnection( connection );
    if (event) CloseHandle( event );
}

static void test_dwm_session_message_delivery(void)
{
    BOOL (WINAPI *pCheckProcessSession)(DWORD);
    BOOL (WINAPI *pGetDesktopID)(UINT, UINT64 *);
    BOOL (WINAPI *pIsWindowGdiScaledX)(HWND);
    ALPC_PORT_ATTRIBUTES attributes = {0};
    OBJECT_ATTRIBUTES object_attributes;
    struct dwm_session_message message = {0}, received = {0};
    WCHAR name_buffer[64];
    UNICODE_STRING name;
    LARGE_INTEGER timeout = {0};
    BOOLEAN previous, ignored;
    DWORD session_id;
    UINT64 input_id, repeated_id, default_id, logon_id = 0, desktop_id, lifecycle_id = 0;
    BOOL saw_input = FALSE, saw_default = FALSE, saw_logon = FALSE, saw_startup_begin = FALSE;
    BOOL saw_window_create = FALSE, saw_window_link = FALSE;
    struct dwm_shell_thread_context shell_context = {0};
    HDESK lifecycle_desktop = NULL;
    HDESK logon_desktop = NULL;
    HWND target_window = NULL, child_target_window = NULL;
    HWND no_redirection_window = NULL, unlinked_anchor_window = NULL;
    HANDLE target = NULL, child_target = NULL, dwm_target = NULL, no_redirection_target = NULL;
    HANDLE port = NULL;
    UINT64 logical_surface_token = 0;
    DPI_AWARENESS_CONTEXT previous_dpi_context;
    BOOL registered, scaled, saw_no_redirection_context = FALSE;
    NTSTATUS status;
    SIZE_T size;
    unsigned int i, j;

    pCheckProcessSession = (void *)GetProcAddress( GetModuleHandleW( L"user32.dll" ),
                                                   "CheckProcessSession" );
    pGetDesktopID = (void *)GetProcAddress( GetModuleHandleW( L"user32.dll" ), "GetDesktopID" );
    pIsWindowGdiScaledX = (void *)GetProcAddress( GetModuleHandleW( L"user32.dll" ),
                                                  (const char *)2635 );
    ok( !!pCheckProcessSession, "CheckProcessSession is not exported\n" );
    ok( !!pGetDesktopID, "GetDesktopID is not exported\n" );
    ok( !!pIsWindowGdiScaledX, "IsWindowGdiScaledX is not exported\n" );

    if (pIsWindowGdiScaledX)
    {
        SetLastError( 0xdeadbeef );
        scaled = pIsWindowGdiScaledX( NULL );
        ok( !scaled, "NULL window is GDI-scaled without a compositor owner\n" );
        ok( GetLastError() == 0xdeadbeef, "non-composited query changed error to %lu\n",
            GetLastError() );
    }

    input_id = 0xdeadbeefdeadbeefULL;
    SetLastError( 0xdeadbeef );
    registered = NtUserGetDesktopID( 1, &input_id );
    ok( !registered, "unauthenticated NtUserGetDesktopID succeeded\n" );
    ok( GetLastError() == ERROR_ACCESS_DENIED, "got error %lu\n", GetLastError() );
    ok( input_id == 0xdeadbeefdeadbeefULL, "output changed to %#I64x\n", input_id );

    SetLastError( 0xdeadbeef );
    registered = NtUserCheckProcessSession( GetCurrentProcessId() );
    ok( !registered, "unauthenticated NtUserCheckProcessSession succeeded\n" );
    ok( GetLastError() == ERROR_ACCESS_DENIED, "got error %lu\n", GetLastError() );

    if (!ProcessIdToSessionId( GetCurrentProcessId(), &session_id ))
    {
        win_skip( "could not query the process session, error %lu\n", GetLastError() );
        return;
    }
    status = RtlAdjustPrivilege( SE_TCB_PRIVILEGE, TRUE, FALSE, &previous );
    if (status == STATUS_PRIVILEGE_NOT_HELD)
    {
        win_skip( "SeTcbPrivilege is unavailable\n" );
        return;
    }
    ok( !status, "RtlAdjustPrivilege returned %#lx\n", status );
    if (status) return;

    wsprintfW( name_buffer, L"\\Sessions\\%lu\\Windows\\DwmApiPort", session_id );
    RtlInitUnicodeString( &name, name_buffer );
    InitializeObjectAttributes( &object_attributes, &name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    attributes.Flags = 0x60000;
    attributes.SecurityQos.Length = sizeof(attributes.SecurityQos);
    attributes.SecurityQos.ImpersonationLevel = SecurityIdentification;
    attributes.SecurityQos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
    attributes.SecurityQos.EffectiveOnly = TRUE;
    attributes.MaxMessageLength = 0x200;
    status = NtAlpcCreatePort( &port, &object_attributes, &attributes );
    ok( !status, "NtAlpcCreatePort returned %#lx\n", status );
    if (status) goto done;
    SetLastError( 0xdeadbeef );
    registered = NtUserRegisterSessionPort( port );
    ok( registered, "NtUserRegisterSessionPort failed, error %lu\n", GetLastError() );
    ok( !registered || GetLastError() == 0xdeadbeef, "last error changed to %lu\n", GetLastError() );
    if (!registered) goto done;

    SetLastError( 0xdeadbeef );
    ok( NtUserCheckProcessSession( GetCurrentProcessId() ),
        "same-session process check failed, error %lu\n", GetLastError() );
    ok( GetLastError() == 0xdeadbeef, "last error changed to %lu\n", GetLastError() );
    if (pCheckProcessSession)
    {
        SetLastError( 0xdeadbeef );
        ok( pCheckProcessSession( GetCurrentProcessId() ),
            "USER32 same-session process check failed, error %lu\n", GetLastError() );
        ok( GetLastError() == 0xdeadbeef, "last error changed to %lu\n", GetLastError() );
    }

    SetLastError( 0xdeadbeef );
    ok( !NtUserCheckProcessSession( 0xffffffff ), "invalid process check succeeded\n" );
    ok( GetLastError() == ERROR_INVALID_PARAMETER, "got error %lu\n", GetLastError() );

    input_id = 0;
    SetLastError( 0xdeadbeef );
    ok( NtUserGetDesktopID( 1, &input_id ), "input desktop query failed, error %lu\n", GetLastError() );
    ok( input_id != 0, "input desktop ID is zero\n" );
    ok( GetLastError() == 0xdeadbeef, "last error changed to %lu\n", GetLastError() );

    repeated_id = 0;
    ok( NtUserGetDesktopID( 1, &repeated_id ), "repeated input desktop query failed, error %lu\n", GetLastError() );
    ok( repeated_id == input_id, "desktop ID changed from %#I64x to %#I64x\n", input_id, repeated_id );

    default_id = 0;
    ok( NtUserGetDesktopID( 2, &default_id ), "default desktop query failed, error %lu\n", GetLastError() );
    ok( default_id != 0, "default desktop ID is zero\n" );

    logon_desktop = CreateDesktopW( L"Winlogon", NULL, NULL, 0, DESKTOP_ALL_ACCESS, NULL );
    ok( !!logon_desktop, "CreateDesktopW failed, error %lu\n", GetLastError() );
    if (logon_desktop)
    {
        logon_id = 0;
        ok( NtUserGetDesktopID( 4, &logon_id ), "logon desktop query failed, error %lu\n", GetLastError() );
        ok( logon_id != 0, "logon desktop ID is zero\n" );
        ok( logon_id != default_id, "logon and default desktops have ID %#I64x\n", logon_id );
    }

    repeated_id = 0xdeadbeefdeadbeefULL;
    SetLastError( 0xdeadbeef );
    ok( !NtUserGetDesktopID( 3, &repeated_id ), "invalid selector succeeded\n" );
    ok( repeated_id == 0xdeadbeefdeadbeefULL, "invalid selector changed output to %#I64x\n", repeated_id );
    ok( GetLastError() == 0xdeadbeef, "invalid selector changed last error to %lu\n", GetLastError() );

    if (pGetDesktopID)
    {
        repeated_id = 0;
        ok( pGetDesktopID( 1, &repeated_id ), "USER32 GetDesktopID failed, error %lu\n", GetLastError() );
        ok( repeated_id == input_id, "USER32 returned %#I64x, expected %#I64x\n", repeated_id, input_id );
    }

    message.header.DataLength = 8;
    message.header.TotalLength = sizeof(message.header) + message.header.DataLength;
    message.data[0] = 0x40000025;
    status = NtAlpcSendWaitReceivePort( port, 0x10000, &message.header,
                                        NULL, NULL, NULL, NULL, NULL );
    ok( !status, "initializing send returned %#lx\n", status );
    memset( &received, 0, sizeof(received) );
    size = sizeof(received);
    status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                        &size, NULL, &timeout );
    ok( status == STATUS_TIMEOUT || status == STATUS_UNSUCCESSFUL,
        "initializing record was delivered before desktop replay, status %#lx\n", status );

    SetLastError( 0xdeadbeef );
    ok( NtUserDwmKernelStartup(), "NtUserDwmKernelStartup failed, error %lu\n", GetLastError() );
    ok( GetLastError() == 0xdeadbeef, "last error changed to %lu\n", GetLastError() );

    for (;;)
    {
        memset( &received, 0, sizeof(received) );
        size = sizeof(received);
        status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                            &size, NULL, &timeout );
        /* Wine's zero-time receive currently reports STATUS_UNSUCCESSFUL for
         * an empty registered kernel port; either result ends the drain. */
        if (status == STATUS_TIMEOUT || status == STATUS_UNSUCCESSFUL) break;
        ok( !status, "desktop replay receive returned %#lx\n", status );
        if (status) break;
        if (received.header.Type != (ALPC_MESSAGE_TYPE_DATAGRAM | 0x8000))
        {
            ok( received.header.Type == ALPC_MESSAGE_TYPE_DATAGRAM,
                "got initializing message type %#x\n", received.header.Type );
            ok( received.header.DataLength == 8,
                "got initializing data length %#x\n", received.header.DataLength );
            ok( received.data[0] == 0x40000025 && !received.data[1],
                "got initializing payload %#lx, %#lx\n", received.data[0], received.data[1] );
            saw_startup_begin = received.data[0] == 0x40000025 && !received.data[1];
            break;
        }
        if (received.data[0] == 0x4000000e)
        {
            ok( received.header.DataLength == 12, "got desktop data length %#x\n", received.header.DataLength );
            memcpy( &desktop_id, received.data + 1, sizeof(desktop_id) );
            if (desktop_id == input_id) saw_input = TRUE;
            if (desktop_id == default_id) saw_default = TRUE;
            if (desktop_id == logon_id) saw_logon = TRUE;
        }
        else if (received.data[0] == 0x40000011)
        {
            ok( received.header.DataLength == 124, "got window create length %#x\n", received.header.DataLength );
            ok( !saw_window_link, "window create followed a window link during replay\n" );
            saw_window_create = TRUE;
        }
        else if (received.data[0] == 0x40000012)
        {
            ok( received.header.DataLength == 32, "got window link length %#x\n", received.header.DataLength );
            saw_window_link = TRUE;
        }
        else if (received.data[0] == 0x40000007)
            ok( received.header.DataLength == 16, "got window visibility length %#x\n",
                received.header.DataLength );
        else if (received.data[0] == 0x40000002)
            ok( received.header.DataLength == 180, "got sprite create length %#x\n",
                received.header.DataLength );
        else if (received.data[0] == 0x40000006)
            ok( received.header.DataLength == 196, "got sprite update length %#x\n",
                received.header.DataLength );
        else ok( 0, "got unexpected startup command %#lx\n", received.data[0] );
    }
    ok( saw_input, "DWM startup did not replay input desktop %#I64x\n", input_id );
    ok( saw_default, "DWM startup did not replay default desktop %#I64x\n", default_id );
    ok( saw_logon, "DWM startup did not replay logon desktop %#I64x\n", logon_id );
    ok( saw_window_create, "DWM startup did not replay a window context\n" );
    ok( saw_window_link, "DWM startup did not replay a window tree link\n" );
    ok( saw_startup_begin, "DWM startup did not release the initializing record after desktop replay\n" );

    /* The startup delimiter may be followed by contexts that were already
     * queued during replay.  Drain those before checking the new window. */
    for (i = 0; i < 512; ++i)
    {
        memset( &received, 0, sizeof(received) );
        size = sizeof(received);
        status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                            &size, NULL, &timeout );
        if (status == STATUS_TIMEOUT || status == STATUS_UNSUCCESSFUL) break;
        ok( !status, "post-startup drain returned %#lx\n", status );
        if (status) break;
    }
    ok( i < 512, "post-startup message drain did not quiesce\n" );

    no_redirection_window = CreateWindowExA( WS_EX_NOREDIRECTIONBITMAP, "static",
                                              "DWM host-only output", WS_POPUP,
                                              0, 0, 32, 32, NULL, NULL, NULL, NULL );
    ok( !!no_redirection_window, "no-redirection window creation failed, error %lu\n",
        GetLastError() );
    if (no_redirection_window)
    {
        for (i = 0; i < 512; ++i)
        {
            HWND message_window = NULL;

            memset( &received, 0, sizeof(received) );
            size = sizeof(received);
            status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                                &size, NULL, &timeout );
            if (status == STATUS_TIMEOUT || status == STATUS_UNSUCCESSFUL) break;
            ok( !status, "no-redirection receive returned %#lx\n", status );
            if (status) break;
            if (received.data[0] != 0x40000011) continue;
            memcpy( &message_window, received.data + 1, sizeof(message_window) );
            if (message_window == no_redirection_window)
                saw_no_redirection_context = TRUE;
        }
        ok( i < 512, "no-redirection message drain did not quiesce\n" );
        ok( !saw_no_redirection_context,
            "no-redirection window entered DwmRedir context tracking\n" );

        registered = NtUserCreateDCompositionHwndTarget( no_redirection_window, 0,
                                                          &no_redirection_target );
        ok( registered, "no-redirection target creation failed, status %#lx\n",
            RtlGetLastNtStatus() );
        if (registered)
        {
            BOOL saw_context = FALSE, saw_sprite_create = FALSE;
            BOOL saw_sprite_update = FALSE, saw_link = FALSE;

            for (i = 0; i < 512; ++i)
            {
                HWND message_window = NULL;

                memset( &received, 0, sizeof(received) );
                size = sizeof(received);
                status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL,
                                                    &received.header, &size, NULL,
                                                    &timeout );
                if (status == STATUS_TIMEOUT || status == STATUS_UNSUCCESSFUL) break;
                ok( !status, "no-redirection target receive returned %#lx\n", status );
                if (status) break;
                memcpy( &message_window, received.data + 1, sizeof(message_window) );
                if (message_window != no_redirection_window) continue;
                if (received.data[0] == 0x40000011) saw_context = TRUE;
                else if (received.data[0] == 0x40000002) saw_sprite_create = TRUE;
                else if (received.data[0] == 0x40000006) saw_sprite_update = TRUE;
                else if (received.data[0] == 0x40000012) saw_link = TRUE;
                if (saw_context && saw_sprite_create && saw_sprite_update && saw_link) break;
            }
            ok( saw_context, "no-redirection DComp target has no window context\n" );
            ok( saw_sprite_create, "no-redirection DComp target has no sprite\n" );
            ok( saw_sprite_update, "no-redirection DComp target has no sprite update\n" );
            ok( saw_link, "no-redirection DComp target has no window link\n" );
            registered = NtUserDestroyDCompositionHwndTarget( no_redirection_window, 0 );
            ok( registered, "no-redirection target destruction failed, status %#lx\n",
                RtlGetLastNtStatus() );
            NtClose( no_redirection_target );
            no_redirection_target = NULL;
        }
        ok( DestroyWindow( no_redirection_window ),
            "no-redirection window destruction failed, error %lu\n", GetLastError() );
        no_redirection_window = NULL;

        for (i = 0; i < 512; ++i)
        {
            memset( &received, 0, sizeof(received) );
            size = sizeof(received);
            status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                                &size, NULL, &timeout );
            if (status == STATUS_TIMEOUT || status == STATUS_UNSUCCESSFUL) break;
            ok( !status, "post-no-redirection drain returned %#lx\n", status );
            if (status) break;
        }
        ok( i < 512, "post-no-redirection message drain did not quiesce\n" );
    }

    if (pIsWindowGdiScaledX)
    {
        SetLastError( 0xdeadbeef );
        scaled = pIsWindowGdiScaledX( GetDesktopWindow() );
        ok( !scaled, "desktop window unexpectedly reports GDI scaling\n" );
        ok( GetLastError() == 0xdeadbeef, "ordinary-window query changed error to %lu\n",
            GetLastError() );

        SetLastError( 0xdeadbeef );
        scaled = pIsWindowGdiScaledX( (HWND)(UINT_PTR)0xdeadbeef );
        ok( !scaled, "invalid window unexpectedly reports GDI scaling\n" );
        ok( GetLastError() == ERROR_INVALID_PARAMETER, "invalid window set error %lu\n",
            GetLastError() );
    }

    lifecycle_desktop = CreateDesktopW( L"LinuxNTDwmLifecycle", NULL, NULL, 0,
                                        DESKTOP_ALL_ACCESS, NULL );
    ok( !!lifecycle_desktop, "lifecycle CreateDesktopW failed, error %lu\n", GetLastError() );
    if (lifecycle_desktop)
    {
        memset( &received, 0, sizeof(received) );
        size = sizeof(received);
        status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                            &size, NULL, &timeout );
        ok( !status, "desktop create receive returned %#lx\n", status );
        ok( !status && received.header.Type == (ALPC_MESSAGE_TYPE_DATAGRAM | 0x8000),
            "got desktop create type %#x\n", received.header.Type );
        ok( !status && received.header.DataLength == 12, "got desktop create length %#x\n", received.header.DataLength );
        ok( !status && received.data[0] == 0x4000000e, "got desktop create command %#lx\n", received.data[0] );
        if (!status) memcpy( &lifecycle_id, received.data + 1, sizeof(lifecycle_id) );
        ok( lifecycle_id != 0, "desktop create ID is zero\n" );

        shell_context.desktop = lifecycle_desktop;
        shell_context.ready = CreateEventW( NULL, TRUE, FALSE, NULL );
        shell_context.repaint = CreateEventW( NULL, TRUE, FALSE, NULL );
        shell_context.repainted = CreateEventW( NULL, TRUE, FALSE, NULL );
        shell_context.release = CreateEventW( NULL, TRUE, FALSE, NULL );
        ok( !!shell_context.ready && !!shell_context.repaint &&
            !!shell_context.repainted && !!shell_context.release,
            "shell thread event creation failed, error %lu\n", GetLastError() );
        if (shell_context.ready && shell_context.repaint &&
            shell_context.repainted && shell_context.release)
        {
            BOOL saw_context = FALSE, saw_link = FALSE, saw_visibility = FALSE;
            BOOL saw_shell_change = FALSE, saw_sprite = FALSE;
            UINT64 shell_window = 0, shell_desktop = 0;
            HANDLE thread;

            thread = CreateThread( NULL, 0, dwm_shell_thread, &shell_context, 0, NULL );
            ok( !!thread, "shell thread creation failed, error %lu\n", GetLastError() );
            if (thread)
            {
                ok( WaitForSingleObject( shell_context.ready, 5000 ) == WAIT_OBJECT_0,
                    "shell thread did not publish its window\n" );
                ok( shell_context.desktop_selected,
                    "shell thread failed to select its desktop, error %lu\n",
                    shell_context.error );
                ok( !!shell_context.window, "shell window creation failed, error %lu\n",
                    shell_context.error );
                ok( shell_context.shell_registered,
                    "shell window registration failed, error %lu\n", shell_context.error );

                for (i = 0; i < 512; ++i)
                {
                    HWND message_window = NULL;

                    memset( &received, 0, sizeof(received) );
                    size = sizeof(received);
                    status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL,
                                                        &received.header, &size, NULL,
                                                        &timeout );
                    if (status == STATUS_TIMEOUT || status == STATUS_UNSUCCESSFUL) break;
                    ok( !status, "shell window receive returned %#lx\n", status );
                    if (status) break;
                    if (received.data[0] == 0x4000000d)
                    {
                        ok( received.header.DataLength == 20,
                            "got shell change length %#x\n", received.header.DataLength );
                        memcpy( &shell_window, received.data + 1, sizeof(shell_window) );
                        memcpy( &shell_desktop, received.data + 3, sizeof(shell_desktop) );
                        if (shell_window == (UINT64)(UINT_PTR)shell_context.window)
                        {
                            ok( shell_desktop == lifecycle_id,
                                "got shell desktop %#I64x, expected %#I64x\n",
                                shell_desktop, lifecycle_id );
                            saw_shell_change = TRUE;
                        }
                        continue;
                    }
                    memcpy( &message_window, received.data + 1, sizeof(message_window) );
                    if (message_window != shell_context.window) continue;
                    if (received.data[0] == 0x40000011) saw_context = TRUE;
                    else if (received.data[0] == 0x40000012) saw_link = TRUE;
                    else if (received.data[0] == 0x40000007) saw_visibility = TRUE;
                    else if (received.data[0] == 0x40000002 ||
                             received.data[0] == 0x40000006) saw_sprite = TRUE;
                }
                ok( i < 512, "shell window message drain did not quiesce\n" );
                ok( saw_context, "no-redirection shell has no DWM window context\n" );
                ok( saw_link, "no-redirection shell has no DWM window link\n" );
                ok( saw_visibility, "visible shell has no DWM visibility record\n" );
                ok( saw_shell_change, "DWM did not receive the registered shell window\n" );
                ok( !saw_sprite, "no-redirection shell unexpectedly gained a sprite\n" );

                SetEvent( shell_context.repaint );
                ok( WaitForSingleObject( shell_context.repainted, 5000 ) == WAIT_OBJECT_0,
                    "shell thread did not repaint its window\n" );
                {
                    BOOL saw_sprite_create = FALSE, saw_surface_update = FALSE;

                    for (i = 0; i < 512; ++i)
                    {
                        HWND message_window = NULL;

                        memset( &received, 0, sizeof(received) );
                        size = sizeof(received);
                        status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL,
                                                            &received.header, &size, NULL,
                                                            &timeout );
                        if (status == STATUS_TIMEOUT || status == STATUS_UNSUCCESSFUL) break;
                        ok( !status, "painted shell receive returned %#lx\n", status );
                        if (status) break;
                        memcpy( &message_window, received.data + 1, sizeof(message_window) );
                        if (message_window != shell_context.window) continue;
                        if (received.data[0] == 0x40000002)
                        {
                            ok( received.header.DataLength == 180,
                                "got shell sprite create length %#x\n",
                                received.header.DataLength );
                            saw_sprite_create = TRUE;
                        }
                        else if (received.data[0] == 0x40000006)
                        {
                            UINT64 logical_surface = 0;

                            ok( saw_sprite_create,
                                "shell surface update preceded its sprite creation\n" );
                            ok( received.header.DataLength == 196,
                                "got shell sprite update length %#x\n",
                                received.header.DataLength );
                            memcpy( &logical_surface, received.data + 42,
                                    sizeof(logical_surface) );
                            if (logical_surface && received.data[45] && received.data[46])
                                saw_surface_update = TRUE;
                        }
                    }
                    ok( i < 512, "painted shell message drain did not quiesce\n" );
                    ok( saw_sprite_create,
                        "painted no-redirection shell has no DWM sprite\n" );
                    ok( saw_surface_update,
                        "painted no-redirection shell has no logical surface\n" );
                }

                SetEvent( shell_context.release );
                ok( WaitForSingleObject( thread, 5000 ) == WAIT_OBJECT_0,
                    "shell thread did not destroy its window\n" );
                CloseHandle( thread );

                saw_shell_change = FALSE;
                for (i = 0; i < 512; ++i)
                {
                    memset( &received, 0, sizeof(received) );
                    size = sizeof(received);
                    status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL,
                                                        &received.header, &size, NULL,
                                                        &timeout );
                    if (status == STATUS_TIMEOUT || status == STATUS_UNSUCCESSFUL) break;
                    ok( !status, "shell teardown receive returned %#lx\n", status );
                    if (status) break;
                    if (received.data[0] != 0x4000000d) continue;
                    memcpy( &shell_window, received.data + 1, sizeof(shell_window) );
                    memcpy( &shell_desktop, received.data + 3, sizeof(shell_desktop) );
                    if (!shell_window && shell_desktop == lifecycle_id)
                        saw_shell_change = TRUE;
                }
                ok( i < 512, "shell teardown message drain did not quiesce\n" );
                ok( saw_shell_change, "DWM did not receive shell window removal\n" );
            }
        }
        if (shell_context.release) SetEvent( shell_context.release );
        if (shell_context.ready) CloseHandle( shell_context.ready );
        if (shell_context.repaint) CloseHandle( shell_context.repaint );
        if (shell_context.repainted) CloseHandle( shell_context.repainted );
        if (shell_context.release) CloseHandle( shell_context.release );

        CloseDesktop( lifecycle_desktop );
        lifecycle_desktop = NULL;
    }

    /* Selecting a desktop on a process thread keeps the process desktop
     * reference alive through teardown.  Use a never-selected desktop for
     * the independent create/free lifetime contract. */
    lifecycle_desktop = CreateDesktopW( L"LinuxNTDwmFree", NULL, NULL, 0,
                                        DESKTOP_ALL_ACCESS, NULL );
    ok( !!lifecycle_desktop, "disposable CreateDesktopW failed, error %lu\n", GetLastError() );
    if (lifecycle_desktop)
    {
        memset( &received, 0, sizeof(received) );
        size = sizeof(received);
        status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                            &size, NULL, &timeout );
        ok( !status, "disposable desktop create receive returned %#lx\n", status );
        ok( !status && received.data[0] == 0x4000000e,
            "got disposable desktop create command %#lx\n", received.data[0] );
        if (!status) memcpy( &lifecycle_id, received.data + 1, sizeof(lifecycle_id) );

        CloseDesktop( lifecycle_desktop );
        lifecycle_desktop = NULL;
        memset( &received, 0, sizeof(received) );
        size = sizeof(received);
        status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                            &size, NULL, &timeout );
        ok( !status, "desktop free receive returned %#lx\n", status );
        ok( !status && received.header.Type == (ALPC_MESSAGE_TYPE_DATAGRAM | 0x8000),
            "got desktop free type %#x\n", received.header.Type );
        ok( !status && received.header.DataLength == 12,
            "got desktop free length %#x\n", received.header.DataLength );
        ok( !status && received.data[0] == 0x40000010,
            "got desktop free command %#lx\n", received.data[0] );
        if (!status) memcpy( &desktop_id, received.data + 1, sizeof(desktop_id) );
        ok( !status && desktop_id == lifecycle_id,
            "desktop free ID %#I64x, expected %#I64x\n", desktop_id, lifecycle_id );
    }

    /* Keep a no-redirection sibling outside DWM tracking.  A later live link
     * must skip it instead of naming a window that DwmRedir cannot resolve as
     * an insertion anchor. */
    unlinked_anchor_window = CreateWindowExA( WS_EX_NOREDIRECTIONBITMAP, "static",
                                               "unlinked DWM anchor", WS_POPUP,
                                               0, 0, 32, 32, NULL, NULL, NULL, NULL );
    ok( !!unlinked_anchor_window, "unlinked anchor creation failed, error %lu\n",
        GetLastError() );
    if (unlinked_anchor_window)
    {
        BOOL saw_unlinked_anchor_context = FALSE;

        for (i = 0; i < 512; ++i)
        {
            HWND message_window = NULL;

            memset( &received, 0, sizeof(received) );
            size = sizeof(received);
            status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                                &size, NULL, &timeout );
            if (status == STATUS_TIMEOUT || status == STATUS_UNSUCCESSFUL) break;
            ok( !status, "unlinked-anchor drain returned %#lx\n", status );
            if (status) break;
            if (received.data[0] != 0x40000011) continue;
            memcpy( &message_window, received.data + 1, sizeof(message_window) );
            if (message_window == unlinked_anchor_window)
                saw_unlinked_anchor_context = TRUE;
        }
        ok( i < 512, "unlinked-anchor message drain did not quiesce\n" );
        ok( !saw_unlinked_anchor_context,
            "unlinked anchor entered DwmRedir context tracking\n" );
    }

    previous_dpi_context = SetThreadDpiAwarenessContext( DPI_AWARENESS_CONTEXT_UNAWARE_GDISCALED );
    ok( previous_dpi_context != NULL, "failed to set GDI-scaled context, error %lu\n",
        GetLastError() );
    target_window = CreateWindowExA( 0, "static", "DWM target replay", WS_POPUP,
                                     0, 0, 32, 32, NULL, NULL, NULL, NULL );
    if (previous_dpi_context) SetThreadDpiAwarenessContext( previous_dpi_context );
    ok( !!target_window, "target window creation failed, error %lu\n", GetLastError() );
    if (target_window && pIsWindowGdiScaledX)
    {
        scaled = pIsWindowGdiScaledX( target_window );
        ok( scaled, "GDI-scaled target window was not recognized\n" );
    }
    if (target_window)
    {
        HWND message_window = NULL, message_parent = NULL;
        HWND immediate_link_anchor = GetWindow( target_window, GW_HWNDNEXT );
        HWND expected_link_anchor = unlinked_anchor_window
                                    ? GetWindow( unlinked_anchor_window, GW_HWNDNEXT )
                                    : immediate_link_anchor;
        UINT64 message_desktop = 0, message_sequence = 0;
        DWORD message_style = 0, message_ex_style = 0, message_pid = 0;
        BOOL saw_sprite_create = FALSE, saw_sprite_update = FALSE;
        BOOL saw_target_link = FALSE;

        if (unlinked_anchor_window)
            ok( immediate_link_anchor == unlinked_anchor_window,
                "got immediate sibling %p, expected unlinked anchor %p\n",
                immediate_link_anchor, unlinked_anchor_window );

        memset( &received, 0, sizeof(received) );
        size = sizeof(received);
        status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                            &size, NULL, &timeout );
        ok( !status, "window create receive returned %#lx\n", status );
        ok( !status && received.header.Type == (ALPC_MESSAGE_TYPE_DATAGRAM | 0x8000),
            "got window create type %#x\n", received.header.Type );
        ok( !status && received.header.DataLength == 124,
            "got window create length %#x\n", received.header.DataLength );
        ok( !status && received.data[0] == 0x40000011,
            "got window create command %#lx\n", received.data[0] );
        if (!status)
        {
            memcpy( &message_window, received.data + 1, sizeof(message_window) );
            memcpy( &message_parent, received.data + 3, sizeof(message_parent) );
            message_style = received.data[5];
            message_ex_style = received.data[6];
            memcpy( &message_desktop, received.data + 26, sizeof(message_desktop) );
            message_pid = received.data[28];
            memcpy( &message_sequence, received.data + 29, sizeof(message_sequence) );
        }
        ok( message_window == target_window, "got window create HWND %p, expected %p\n",
            message_window, target_window );
        ok( !!message_parent, "window create parent is null\n" );
        ok( message_style & WS_POPUP, "window create style %#lx lacks WS_POPUP\n", message_style );
        ok( !message_ex_style, "got window create extended style %#lx\n", message_ex_style );
        ok( message_desktop == default_id, "got window desktop %#I64x, expected %#I64x\n",
            message_desktop, default_id );
        ok( message_pid == GetCurrentProcessId(), "got window PID %lu, expected %lu\n",
            message_pid, GetCurrentProcessId() );
        ok( !!message_sequence, "window process sequence is zero\n" );

        for (i = 0; i < 512; ++i)
        {
            memset( &received, 0, sizeof(received) );
            size = sizeof(received);
            status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                                &size, NULL, &timeout );
            if (status == STATUS_TIMEOUT || status == STATUS_UNSUCCESSFUL) break;
            ok( !status, "window lifecycle receive returned %#lx\n", status );
            if (status) break;
            ok( received.header.Type == (ALPC_MESSAGE_TYPE_DATAGRAM | 0x8000),
                "got window lifecycle type %#x\n", received.header.Type );
            memcpy( &message_window, received.data + 1, sizeof(message_window) );
            if (received.data[0] == 0x40000011)
            {
                ok( received.header.DataLength == 124, "got intervening create length %#x\n",
                    received.header.DataLength );
                continue;
            }
            if (received.data[0] == 0x40000002)
            {
                HWND sprite = NULL, sprite_window = NULL;
                RECT sprite_rect, mini_window_rect, mini_client_rect;
                UINT64 sprite_desktop = 0;

                ok( received.header.DataLength == 180, "got sprite create length %#x\n",
                    received.header.DataLength );
                memcpy( &sprite, received.data + 1, sizeof(sprite) );
                memcpy( &sprite_window, received.data + 3, sizeof(sprite_window) );
                if (sprite_window != target_window) continue;
                ok( !saw_sprite_update, "sprite create followed its update\n" );
                memcpy( &sprite_rect, received.data + 5, sizeof(sprite_rect) );
                memcpy( &mini_window_rect, received.data + 10, sizeof(mini_window_rect) );
                memcpy( &mini_client_rect, received.data + 14, sizeof(mini_client_rect) );
                memcpy( &sprite_desktop, received.data + 22, sizeof(sprite_desktop) );
                ok( sprite == target_window, "got sprite %p, expected %p\n", sprite, target_window );
                ok( sprite_window == target_window, "got sprite HWND %p, expected %p\n",
                    sprite_window, target_window );
                ok( EqualRect( &sprite_rect, &mini_window_rect ),
                    "sprite and mini window rectangles differ\n" );
                ok( received.data[18] == message_style, "got mini style %#lx, expected %#lx\n",
                    received.data[18], message_style );
                ok( received.data[19] == message_ex_style,
                    "got mini extended style %#lx, expected %#lx\n",
                    received.data[19], message_ex_style );
                ok( sprite_desktop == default_id, "got sprite desktop %#I64x, expected %#I64x\n",
                    sprite_desktop, default_id );
                ok( received.data[44] == 0x0a00, "got sprite compatibility version %#lx\n",
                    received.data[44] );
                ok( mini_client_rect.right >= mini_client_rect.left &&
                    mini_client_rect.bottom >= mini_client_rect.top,
                    "got invalid mini client rectangle %s\n", wine_dbgstr_rect( &mini_client_rect ) );
                saw_sprite_create = TRUE;
                continue;
            }
            if (received.data[0] == 0x40000006)
            {
                HWND sprite = NULL;
                UINT64 logical_surface = 0, sprite_desktop = 0;

                ok( saw_sprite_create, "sprite update preceded its create\n" );
                ok( received.header.DataLength == 196, "got sprite update length %#x\n",
                    received.header.DataLength );
                memcpy( &sprite, received.data + 1, sizeof(sprite) );
                if (sprite != target_window) continue;
                memcpy( &sprite_desktop, received.data + 17, sizeof(sprite_desktop) );
                memcpy( &logical_surface, received.data + 42, sizeof(logical_surface) );
                ok( sprite == target_window, "got updated sprite %p, expected %p\n",
                    sprite, target_window );
                ok( !(received.data[3] & 0x8),
                    "unpainted sprite update flags %#lx contain surface state\n",
                    received.data[3] );
                ok( received.data[4] == 1, "got mini-window-present value %#lx\n",
                    received.data[4] );
                ok( sprite_desktop == default_id,
                    "got updated sprite desktop %#I64x, expected %#I64x\n",
                    sprite_desktop, default_id );
                ok( !logical_surface, "unpainted sprite has logical surface %#I64x\n",
                    logical_surface );
                ok( !received.data[45] && !received.data[46],
                    "unpainted sprite has surface size %lux%lu\n",
                    received.data[45], received.data[46] );
                saw_sprite_update = TRUE;
                continue;
            }
            if (received.data[0] == 0x40000016)
            {
                ok( received.header.DataLength == 20, "got intervening style length %#x\n",
                    received.header.DataLength );
                continue;
            }
            if (received.data[0] == 0x40000007)
            {
                ok( received.header.DataLength == 16, "got intervening visibility length %#x\n",
                    received.header.DataLength );
                continue;
            }
            ok( received.data[0] == 0x40000012, "got window link command %#lx\n",
                received.data[0] );
            ok( saw_sprite_create, "window link preceded sprite creation\n" );
            ok( saw_sprite_update, "window link preceded sprite surface update\n" );
            ok( received.header.DataLength == 32, "got window link length %#x\n",
                received.header.DataLength );
            if (received.data[0] != 0x40000012) continue;
            if (message_window == target_window)
            {
                HWND link_parent, link_anchor;

                memcpy( &link_parent, received.data + 3, sizeof(link_parent) );
                memcpy( &link_anchor, received.data + 5, sizeof(link_anchor) );
                ok( link_parent == message_parent, "got link parent %p, expected %p\n",
                    link_parent, message_parent );
                ok( link_anchor == (expected_link_anchor ? expected_link_anchor : (HWND)1),
                    "got link anchor %p, expected %p\n", link_anchor,
                    expected_link_anchor ? expected_link_anchor : (HWND)1 );
                ok( received.data[7] == 1, "got window band %lu\n", received.data[7] );
                saw_target_link = TRUE;
            }
        }
        ok( saw_target_link, "target window link was not delivered\n" );
        ok( saw_sprite_create, "target sprite create was not delivered\n" );
        ok( saw_sprite_update, "target sprite update was not delivered\n" );

        for (i = 0; i < 3; ++i)
        {
            HWND style_window = NULL;
            LONG style_offset = 0;
            DWORD style_value = 0;
            BOOL saw_style = FALSE;
            BOOL saw_visibility = FALSE;
            BOOL show = i != 1;

            ShowWindow( target_window, show ? SW_SHOW : SW_HIDE );
            if (!i) UpdateWindow( target_window );
            for (j = 0; j < 512; ++j)
            {
                memset( &received, 0, sizeof(received) );
                size = sizeof(received);
                status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                                    &size, NULL, &timeout );
                if (status == STATUS_TIMEOUT || status == STATUS_UNSUCCESSFUL) break;
                ok( !status, "window style receive returned %#lx\n", status );
                if (status) break;
                memcpy( &style_window, received.data + 1, sizeof(style_window) );
                if (style_window != target_window) continue;
                if (received.data[0] == 0x40000016)
                {
                    ok( received.header.Type == (ALPC_MESSAGE_TYPE_DATAGRAM | 0x8000),
                        "got window style type %#x\n", received.header.Type );
                    ok( received.header.DataLength == 20,
                        "got window style length %#x\n", received.header.DataLength );
                    memcpy( &style_offset, received.data + 3, sizeof(style_offset) );
                    style_value = received.data[4];
                    saw_style = TRUE;
                }
                else if (received.data[0] == 0x40000007)
                {
                    ok( saw_style, "window visibility preceded its style change\n" );
                    ok( received.header.Type == (ALPC_MESSAGE_TYPE_DATAGRAM | 0x8000),
                        "got window visibility type %#x\n", received.header.Type );
                    ok( received.header.DataLength == 16,
                        "got window visibility length %#x\n", received.header.DataLength );
                    ok( !!received.data[3] == show, "got visibility %lu, expected %u\n",
                        received.data[3], show );
                    saw_visibility = TRUE;
                }
                else if (!i && received.data[0] == 0x40000006 &&
                         (received.data[3] & 0x8))
                {
                    memcpy( &logical_surface_token, received.data + 42,
                            sizeof(logical_surface_token) );
                    ok( !!logical_surface_token, "painted sprite has no logical surface\n" );
                    ok( received.data[45] && received.data[46],
                        "painted sprite has surface size %lux%lu\n",
                        received.data[45], received.data[46] );
                }
                if (saw_style && saw_visibility && (i || logical_surface_token)) break;
            }
            ok( saw_style, "window style change was not delivered\n" );
            ok( saw_visibility, "window visibility change was not delivered\n" );
            ok( style_window == target_window, "got style HWND %p, expected %p\n",
                style_window, target_window );
            ok( style_offset == GWL_STYLE, "got style offset %ld\n", style_offset );
            ok( !!(style_value & WS_VISIBLE) == show,
                "got style %#lx, expected visible %u\n", style_value, show );
            if (!i)
            {
                ok( !!logical_surface_token, "logical surface was not published after paint\n" );
                if (logical_surface_token)
                    test_hlsurf_protocol( target_window,
                                          (HANDLE)(UINT_PTR)logical_surface_token );
            }
        }

        for (i = 0; i < 2; ++i)
        {
            HWND style_window = NULL;
            LONG style_offset = 0;
            DWORD old_ex_style = GetWindowLongA( target_window, GWL_EXSTYLE );
            DWORD expected_ex_style = i ? old_ex_style & ~WS_EX_TOOLWINDOW : old_ex_style | WS_EX_TOOLWINDOW;
            DWORD style_value = 0;
            BOOL saw_style = FALSE;

            SetWindowLongA( target_window, GWL_EXSTYLE, expected_ex_style );
            for (j = 0; j < 512; ++j)
            {
                memset( &received, 0, sizeof(received) );
                size = sizeof(received);
                status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                                    &size, NULL, &timeout );
                if (status == STATUS_TIMEOUT || status == STATUS_UNSUCCESSFUL) break;
                ok( !status, "window extended style receive returned %#lx\n", status );
                if (status) break;
                memcpy( &style_window, received.data + 1, sizeof(style_window) );
                memcpy( &style_offset, received.data + 3, sizeof(style_offset) );
                if (received.data[0] != 0x40000016 || style_window != target_window ||
                    style_offset != GWL_EXSTYLE)
                    continue;
                ok( received.header.Type == (ALPC_MESSAGE_TYPE_DATAGRAM | 0x8000),
                    "got window extended style type %#x\n", received.header.Type );
                ok( received.header.DataLength == 20,
                    "got window extended style length %#x\n", received.header.DataLength );
                style_value = received.data[4];
                saw_style = TRUE;
                break;
            }
            ok( saw_style, "window extended style change was not delivered\n" );
            ok( style_window == target_window, "got extended style HWND %p, expected %p\n",
                style_window, target_window );
            ok( style_offset == GWL_EXSTYLE, "got extended style offset %ld\n", style_offset );
            ok( style_value == expected_ex_style, "got extended style %#lx, expected %#lx\n",
                style_value, expected_ex_style );
        }

        SetWindowPos( target_window, NULL, 1, 2, 40, 36, SWP_NOZORDER | SWP_NOACTIVATE );
        for (i = 0; i < 512; ++i)
        {
            HWND sprite = NULL;
            RECT updated_rect;

            memset( &received, 0, sizeof(received) );
            size = sizeof(received);
            status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                                &size, NULL, &timeout );
            if (status == STATUS_TIMEOUT || status == STATUS_UNSUCCESSFUL) break;
            ok( !status, "sprite geometry receive returned %#lx\n", status );
            if (status) break;
            if (received.data[0] != 0x40000006) continue;
            memcpy( &sprite, received.data + 1, sizeof(sprite) );
            if (sprite != target_window) continue;
            memcpy( &updated_rect, received.data + 5, sizeof(updated_rect) );
            ok( received.header.DataLength == 196, "got geometry update length %#x\n",
                received.header.DataLength );
            ok( updated_rect.right - updated_rect.left == 40 &&
                updated_rect.bottom - updated_rect.top == 36,
                "got updated window rectangle %s\n", wine_dbgstr_rect( &updated_rect ) );
            ok( received.data[45] >= 40 && received.data[46] >= 36,
                "got undersized sprite surface %lux%lu\n", received.data[45], received.data[46] );
            break;
        }
        ok( i < 512, "sprite geometry update was not delivered\n" );

        registered = NtUserCreateDCompositionHwndTarget( target_window, 0, &target );
        ok( registered, "target creation failed, status %#lx\n", RtlGetLastNtStatus() );
    }

    memset( &message, 0, sizeof(message) );
    message.header.DataLength = 8;
    message.header.TotalLength = sizeof(message.header) + message.header.DataLength;
    message.data[0] = 0x40000026;
    status = NtAlpcSendWaitReceivePort( port, 0x10000, &message.header,
                                        NULL, NULL, NULL, NULL, NULL );
    ok( !status, "ready send returned %#lx\n", status );
    memset( &received, 0, sizeof(received) );
    size = sizeof(received);
    status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                        &size, NULL, &timeout );
    ok( !status, "ready receive returned %#lx\n", status );
    ok( !status && received.header.DataLength == 8, "got data length %#x\n", received.header.DataLength );
    ok( !status && received.data[0] == 0x40000026 && !received.data[1],
        "got ready payload %#lx, %#lx\n", received.data[0], received.data[1] );

    if (target)
    {
        HWND message_window = NULL;
        UINT message_type = 0xcccccccc;
        RECT region_rect = {0}, client_rect = {0};

        memset( &received, 0, sizeof(received) );
        size = sizeof(received);
        status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                            &size, NULL, &timeout );
        ok( !status, "target visible-region receive returned %#lx\n", status );
        ok( !status && received.header.Type == (ALPC_MESSAGE_TYPE_DATAGRAM | 0x8000),
            "got visible-region type %#x\n", received.header.Type );
        ok( !status && received.header.DataLength == 44,
            "got visible-region length %#x\n", received.header.DataLength );
        ok( !status && received.data[0] == 0x40000096,
            "got visible-region command %#lx\n", received.data[0] );
        if (!status)
        {
            memcpy( &message_window, received.data + 1, sizeof(message_window) );
            memcpy( &region_rect, received.data + 7, sizeof(region_rect) );
        }
        GetClientRect( target_window, &client_rect );
        ok( message_window == target_window, "got visible-region window %p, expected %p\n",
            message_window, target_window );
        ok( received.data[3] == 0 && received.data[4] == 1 &&
            received.data[5] == 1 && received.data[6] == 1,
            "got visible-region chunk %lu/%lu type %lu count %lu\n",
            received.data[3], received.data[4], received.data[5], received.data[6] );
        ok( !IsRectEmpty( &region_rect ) && EqualRect( &region_rect, &client_rect ),
            "got visible region %s, expected client %s\n", wine_dbgstr_rect( &region_rect ),
            wine_dbgstr_rect( &client_rect ) );

        memset( &received, 0, sizeof(received) );
        size = sizeof(received);
        status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                            &size, NULL, &timeout );
        ok( !status, "target replay receive returned %#lx\n", status );
        ok( !status && received.header.Type == (ALPC_MESSAGE_TYPE_DATAGRAM | 0x8000),
            "got target replay type %#x\n", received.header.Type );
        ok( !status && received.header.DataLength == 24,
            "got target replay length %#x\n", received.header.DataLength );
        ok( !status && received.data[0] == 0x40000045,
            "got target replay command %#lx\n", received.data[0] );
        if (!status)
        {
            memcpy( &message_window, received.data + 1, sizeof(message_window) );
            memcpy( &message_type, received.data + 3, sizeof(message_type) );
            memcpy( &dwm_target, received.data + 4, sizeof(dwm_target) );
        }
        ok( message_window == target_window, "got target replay window %p, expected %p\n",
            message_window, target_window );
        ok( message_type == 0, "got target replay type %u\n", message_type );
        ok( dwm_target && dwm_target != target, "got DWM target handle %p, client handle %p\n",
            dwm_target, target );
        if (dwm_target) CloseHandle( dwm_target );
        dwm_target = NULL;

        registered = NtUserDestroyDCompositionHwndTarget( target_window, 0 );
        ok( registered, "target destruction failed, status %#lx\n", RtlGetLastNtStatus() );
        memset( &received, 0, sizeof(received) );
        size = sizeof(received);
        status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                            &size, NULL, &timeout );
        ok( !status, "target destroy receive returned %#lx\n", status );
        ok( !status && received.header.Type == (ALPC_MESSAGE_TYPE_DATAGRAM | 0x8000),
            "got target destroy type %#x\n", received.header.Type );
        ok( !status && received.header.DataLength == 16,
            "got target destroy length %#x\n", received.header.DataLength );
        ok( !status && received.data[0] == 0x40000046,
            "got target destroy command %#lx\n", received.data[0] );
        if (!status)
        {
            memcpy( &message_window, received.data + 1, sizeof(message_window) );
            memcpy( &message_type, received.data + 3, sizeof(message_type) );
        }
        ok( message_window == target_window, "got target destroy window %p, expected %p\n",
            message_window, target_window );
        ok( message_type == 0, "got target destroy type %u\n", message_type );

        memset( &received, 0, sizeof(received) );
        size = sizeof(received);
        status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                            &size, NULL, &timeout );
        ok( !status, "target visible-region clear receive returned %#lx\n", status );
        ok( !status && received.header.Type == (ALPC_MESSAGE_TYPE_DATAGRAM | 0x8000),
            "got visible-region clear type %#x\n", received.header.Type );
        ok( !status && received.header.DataLength == 28,
            "got visible-region clear length %#x\n", received.header.DataLength );
        ok( !status && received.data[0] == 0x40000096,
            "got visible-region clear command %#lx\n", received.data[0] );
        if (!status) memcpy( &message_window, received.data + 1, sizeof(message_window) );
        ok( message_window == target_window,
            "got visible-region clear window %p, expected %p\n", message_window, target_window );
        ok( received.data[3] == 0 && received.data[4] == 0 &&
            received.data[5] == 1 && received.data[6] == 0,
            "got visible-region clear chunk %lu/%lu type %lu count %lu\n",
            received.data[3], received.data[4], received.data[5], received.data[6] );
    }

    if (target_window)
    {
        BOOL saw_context = FALSE, saw_link = FALSE, saw_region = FALSE, saw_target = FALSE;
        BOOL saw_sprite = FALSE;

        child_target_window = CreateWindowExA( 0, "static", "DWM child target",
                                                WS_CHILD | WS_VISIBLE, 2, 3, 20, 18,
                                                target_window, NULL, NULL, NULL );
        ok( !!child_target_window, "child target window creation failed, error %lu\n",
            GetLastError() );
        registered = child_target_window && NtUserCreateDCompositionHwndTarget(
                child_target_window, 0, &child_target );
        ok( registered, "child target creation failed, status %#lx\n", RtlGetLastNtStatus() );
        if (registered)
        {
            for (i = 0; i < 16 && !(saw_context && saw_link && saw_region && saw_target); ++i)
            {
                HWND message_window = NULL;

                memset( &received, 0, sizeof(received) );
                size = sizeof(received);
                status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                                    &size, NULL, &timeout );
                if (status == STATUS_TIMEOUT || status == STATUS_UNSUCCESSFUL) break;
                ok( !status, "child target receive returned %#lx\n", status );
                if (status) break;
                memcpy( &message_window, received.data + 1, sizeof(message_window) );
                if (message_window != child_target_window) continue;
                if (received.data[0] == 0x40000011) saw_context = TRUE;
                else if (received.data[0] == 0x40000012) saw_link = TRUE;
                else if (received.data[0] == 0x40000096) saw_region = TRUE;
                else if (received.data[0] == 0x40000045) saw_target = TRUE;
                else if (received.data[0] == 0x40000002 || received.data[0] == 0x40000006)
                    saw_sprite = TRUE;
            }
            ok( saw_context, "child DComp target has no window context\n" );
            ok( saw_link, "child DComp target has no window link\n" );
            ok( saw_region, "child DComp target has no visible region\n" );
            ok( saw_target, "child DComp target was not delivered\n" );
            ok( !saw_sprite, "child DComp target unexpectedly gained a redirection sprite\n" );
            registered = NtUserDestroyDCompositionHwndTarget( child_target_window, 0 );
            ok( registered, "child target destruction failed, status %#lx\n",
                RtlGetLastNtStatus() );
        }
        if (child_target) CloseHandle( child_target );
        child_target = NULL;
        if (child_target_window) DestroyWindow( child_target_window );
        child_target_window = NULL;
        for (i = 0; i < 16; ++i)
        {
            memset( &received, 0, sizeof(received) );
            size = sizeof(received);
            status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                                &size, NULL, &timeout );
            if (status == STATUS_TIMEOUT || status == STATUS_UNSUCCESSFUL) break;
            ok( !status, "child target teardown drain returned %#lx\n", status );
            if (status) break;
        }
        ok( i < 16, "child target teardown did not quiesce\n" );
    }

    if (target_window)
    {
        HWND message_window = NULL;
        BOOL saw_sprite_destroy = FALSE, saw_destroy = FALSE;

        ok( DestroyWindow( target_window ), "target window destruction failed, error %lu\n", GetLastError() );
        if (logical_surface_token)
            test_hlsurf_destroyed_window_lifetime( (HANDLE)(UINT_PTR)logical_surface_token );
        for (i = 0; i < 16; ++i)
        {
            memset( &received, 0, sizeof(received) );
            size = sizeof(received);
            status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                                &size, NULL, &timeout );
            ok( !status, "window lifecycle teardown receive returned %#lx\n", status );
            if (status) break;
            memcpy( &message_window, received.data + 1, sizeof(message_window) );
            if (message_window != target_window) continue;
            if (received.data[0] == 0x40000013)
                ok( received.header.DataLength == 20, "got window unlink length %#x\n",
                    received.header.DataLength );
            else if (received.data[0] == 0x40000003)
            {
                ok( received.header.DataLength == 12, "got sprite destroy length %#x\n",
                    received.header.DataLength );
                saw_sprite_destroy = TRUE;
            }
            else if (received.data[0] == 0x40000014)
            {
                ok( saw_sprite_destroy, "window context was destroyed before its sprite\n" );
                ok( received.header.DataLength == 12, "got window destroy length %#x\n",
                    received.header.DataLength );
                saw_destroy = TRUE;
                break;
            }
        }
        ok( saw_sprite_destroy, "target sprite destroy was not delivered\n" );
        ok( saw_destroy, "target window destroy was not delivered\n" );
        target_window = NULL;
    }

    test_blurred_wallpaper_surface_delivery( port, &timeout );

done:
    if (child_target) CloseHandle( child_target );
    if (child_target_window) DestroyWindow( child_target_window );
    if (dwm_target) CloseHandle( dwm_target );
    if (no_redirection_target) CloseHandle( no_redirection_target );
    if (target) CloseHandle( target );
    if (target_window) DestroyWindow( target_window );
    if (unlinked_anchor_window) DestroyWindow( unlinked_anchor_window );
    if (lifecycle_desktop) CloseDesktop( lifecycle_desktop );
    if (logon_desktop) CloseDesktop( logon_desktop );
    if (port)
    {
        NtUserDwmKernelShutdown();
        NtClose( port );
    }
    status = RtlAdjustPrivilege( SE_TCB_PRIVILEGE, previous, FALSE, &ignored );
    ok( !status, "restoring SeTcbPrivilege returned %#lx\n", status );
}

START_TEST(dcomp)
{
    unsigned int argc;
    char **argv;

    argc = winetest_get_mainargs( &argv );
    if (argc == 6 && !strcmp( argv[2], "coremsg_selector_child" ))
    {
        coremsg_selector_child( strtoul( argv[3], NULL, 16 ), strtoul( argv[4], NULL, 16 ),
                                strtoul( argv[5], NULL, 16 ) );
        return;
    }

    test_input_registration();
    test_kst();
    test_frame_statistics();
    test_composition_input_sink();
    test_channel_lifetime();
    test_channel_application_id();
    test_channel_synchronization();
    test_synchronized_connection_queue();
    test_shared_resource_handle_lifecycle();
    test_published_shared_resource_ordering();
    test_published_shared_resource_target_fifo();
    test_duplicate_prerequisite_selection();
    test_held_release_wire_id_reuse();
    test_created_shared_resource_duplication();
    test_multi_source_shared_resource_duplication();
    test_hwnd_target_lifecycle();
    test_connection_queue();
    test_large_connection_batch();
    test_referenced_resource_id_reuse();
    test_visual_target_root_lifecycle();
    test_shared_host_visual_lifecycle();
    test_window_target_shared_identity();
    test_window_node_properties();
    test_gdi_sprite_bitmap_protocol();
    test_composition_surface_brush_protocol();
    test_mask_brush_protocol();
    test_region_clip_protocol();
    test_legacy_render_target_protocol();
    test_expression_graph();
    test_expression_weak_reference_reuse();
    test_keyframe_animation_protocol();
    test_shared_manipulation_transform();
    test_shared_section_lifecycle();
    test_frame_lifecycle();
    test_resource_retirement();
    test_composition_surface_lifecycle();
    test_connection_lifetime();
    test_token_manager_lifetime();
    test_dwm_session_message_delivery();
}
