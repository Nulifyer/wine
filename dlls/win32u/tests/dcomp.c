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
    DWORD data[6];
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

static void init_dcomp_test_protocol_list( struct dcomp_test_protocol_list *list )
{
    memset( list, 0, sizeof(*list) );
    list->head.next = &list->block;
    list->head.previous = &list->block;
    list->block.next = &list->head;
    list->block.previous = &list->head;
    list->block.type = 0x200;
    list->block.size = sizeof(list->block.data);
    list->block.data[0] = 0x12;
    list->block.data[1] = 0x34;
    list->block.data[2] = 0x56;
    list->block.data[3] = 0x78;
    list->block.data[4] = 0x9a;
    list->block.data[5] = 0xbc;
    list->block.data[6] = 0xde;
    list->block.data[7] = 0xf0;
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
    UINT i;

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
    for (i = 0; i < ARRAY_SIZE(capabilities.values); ++i)
        ok( !capabilities.values[i], "capability %u is %#x\n", i, capabilities.values[i] );

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

static void test_connection_lifetime(void)
{
    struct dcomposition_connection_batch *record = (void *)0xdeadbeef;
    HANDLE event, connection = (HANDLE)0xdeadbeef;
    UINT64 cookie = 0x1122334455667788;
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

static void test_connection_queue(void)
{
    static const BYTE expected_resource_batch[] = {
        0x10, 0, 0, 0, 0x28, 0, 0, 0, 1, 0, 0, 0, 13, 0, 0, 0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    };
    static const BYTE expected_release_batch[] = {
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x0c, 0, 0, 0, 0x29, 0, 0, 0, 1, 0, 0, 0,
    };
    struct dcomp_test_protocol_list protocol_list;
    struct dcomposition_connection_batch *record = (void *)0xdeadbeef;
    HANDLE event, connection = NULL, completion_event = NULL, completion_wait = NULL;
    BYTE *buffer = (BYTE *)0xdeadbeef;
    UINT channel = 0xcccccccc, size = 0x1000, batch = 0xcccccccc;
    UINT64 cookie = 0x1122334455667788;
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
    ok( cookie == 0x1122334455667788, "cookie changed to %s\n", wine_dbgstr_longlong(cookie) );
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
    ok( WaitForSingleObject( completion_wait, 0 ) == WAIT_TIMEOUT,
        "completion event signaled before consumer dequeue\n" );
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got batch record status %#lx\n", status );
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

static void test_shared_section_lifecycle(void)
{
    struct dcomp_test_protocol_list protocol_list;
    struct dcomposition_connection_batch *record = (void *)0xdeadbeef;
    HANDLE event, connection = NULL, section = (HANDLE)0xdeadbeef, consumer_section = NULL;
    BYTE *buffer = (BYTE *)0xdeadbeef;
    UINT channel = 0xcccccccc, channel_size = 0x1000, batch;
    UINT64 cookie = 0x1122334455667788, consumer_value;
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

static NTSTATUS process_dcomp_test_command( UINT channel, BYTE *buffer,
                                             const UINT *command, UINT size )
{
    ULONG processed;
    BYTE released;

    memcpy( buffer, command, size );
    return NtDCompositionProcessChannelBatchBuffer( channel, size, &processed, &released );
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

static void test_visual_target_root_lifecycle(void)
{
    static const UINT expected_initial[] = {
        16, 0x28, 1, 0xb8,
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
    static const UINT expected_visual_content[] = {
        16, 0x28, 5, 0xa6,
        16, 0x28, 6, 0x16,
        16, 0x28, 7, 0x7f,
        16, 0x28, 8, 0x1e,
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
        24, 0x43, 8, 0x3f800000, 0x3f800000, 0x3f800000,
        76, 0x44, 8,
            0x3f800000, 0, 0, 0,
            0, 0x3f800000, 0, 0,
            0, 0, 0x3f800000, 0,
            0, 0, 0, 0x3f800000,
        16, 0x1a0, 3, 8,
        16, 0x18c, 3, 7,
        16, 0x16e, 5, 6,
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
    UINT channel = 0, size = 0x1000, batch, command[64];
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

    command[0] = 2; command[1] = 5; command[2] = 0xa6; command[3] = 0;
    command[4] = 2; command[5] = 6; command[6] = 0x16; command[7] = 0;
    command[8] = 2; command[9] = 7; command[10] = 0x7f; command[11] = 0;
    command[12] = 2; command[13] = 8; command[14] = 0x1e; command[15] = 0;
    command[16] = 15; command[17] = 6; command[18] = 0; command[19] = 16;
    command[20] = 0x3f800000; command[21] = 0x3f000000;
    command[22] = 0x3e800000; command[23] = 0x3f800000;
    command[24] = 11; command[25] = 7; command[26] = 0x15; command[27] = 0;
    command[28] = 1; command[29] = 0;
    command[30] = 15; command[31] = 7; command[32] = 0x11; command[33] = 16;
    command[34] = 0x3f800000; command[35] = 0x40000000;
    command[36] = 0x40400000; command[37] = 0x40800000;
    command[38] = 16; command[39] = 3; command[40] = 4; command[41] = 8;
    command[42] = 16; command[43] = 3; command[44] = 7; command[45] = 7;
    command[46] = 16; command[47] = 5; command[48] = 0x34; command[49] = 6;
    memcpy( buffer, command, 200 );
    status = NtDCompositionProcessChannelBatchBuffer( channel, 200, &processed, &released );
    ok( status == STATUS_SUCCESS, "got visual content process status %#lx\n", status );
    ok( processed == 10, "got visual content process count %lu\n", processed );
    status = NtDCompositionCommitChannel( channel, &batch, &state, 0, NULL, NULL, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got visual content commit status %#lx\n", status );
    record = NULL;
    status = NtDCompositionGetConnectionBatch( connection, &cookie, &record );
    ok( status == STATUS_SUCCESS, "got visual content batch status %#lx\n", status );
    check_dcomp_batch_payload( record, channel, expected_visual_content,
                               sizeof(expected_visual_content), "visual content" );

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
    HANDLE handles[ARRAY_SIZE(valid_types)] = {0}, event = NULL;
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
    memcpy( command + 2, &handles[2], sizeof(handles[2]) );
    command[4] = 0x82;
    command[5] = 0;
    memcpy( buffer, command, sizeof(command) );
    status = NtDCompositionProcessChannelBatchBuffer( channel, sizeof(command),
                                                       &processed, &released );
    ok( status == STATUS_INVALID_PARAMETER, "mismatched type returned %#lx\n", status );

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "failed to create event, error %lu\n", GetLastError() );
    command[1] = 4;
    memcpy( command + 2, &event, sizeof(event) );
    command[4] = 0xb8;
    memcpy( buffer, command, sizeof(command) );
    status = NtDCompositionProcessChannelBatchBuffer( channel, sizeof(command),
                                                       &processed, &released );
    ok( status == STATUS_OBJECT_TYPE_MISMATCH, "event handle returned %#lx\n", status );

    for (i = 0; i < ARRAY_SIZE(valid_types); ++i)
    {
        if (!handles[i]) continue;
        command[0] = 4;
        command[1] = i + 1;
        memcpy( buffer, command, 8 );
        status = NtDCompositionProcessChannelBatchBuffer( channel, 8, &processed, &released );
        ok( status == STATUS_SUCCESS, "type %#x release returned %#lx\n",
            valid_types[i], status );
    }

    if (event) CloseHandle( event );
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
    UINT64 connection = 1, device = 2, binding_id, second_binding_id;
    BYTE buffer_info[0x520] = {0};
    HANDLE surface, token, second_token;
    NTSTATUS status;

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
    if (status) return;

    binding_id = 0xdeadbeef;
    status = NtBindCompositionSurface(surface, TRUE, 0, FALSE, NULL, &binding_id);
    ok(status == STATUS_INVALID_PARAMETER, "got status %#lx\n", status);
    status = NtBindCompositionSurface(surface, TRUE, 0, FALSE, buffer_info, &binding_id);
    ok(status == STATUS_SUCCESS, "got status %#lx\n", status);
    ok(binding_id != 0, "got binding id %I64u\n", binding_id);

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
    NtClose(surface);
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

static void test_dwm_session_message_delivery(void)
{
    BOOL (WINAPI *pGetDesktopID)(UINT, UINT64 *);
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
    HDESK lifecycle_desktop = NULL;
    HDESK logon_desktop = NULL;
    HWND target_window = NULL;
    HANDLE target = NULL, dwm_target = NULL;
    HANDLE port = NULL;
    BOOL registered;
    NTSTATUS status;
    SIZE_T size;

    pGetDesktopID = (void *)GetProcAddress( GetModuleHandleW( L"user32.dll" ), "GetDesktopID" );
    ok( !!pGetDesktopID, "GetDesktopID is not exported\n" );

    input_id = 0xdeadbeefdeadbeefULL;
    SetLastError( 0xdeadbeef );
    registered = NtUserGetDesktopID( 1, &input_id );
    ok( !registered, "unauthenticated NtUserGetDesktopID succeeded\n" );
    ok( GetLastError() == ERROR_ACCESS_DENIED, "got error %lu\n", GetLastError() );
    ok( input_id == 0xdeadbeefdeadbeefULL, "output changed to %#I64x\n", input_id );

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
        ok( received.header.DataLength == 12, "got desktop data length %#x\n", received.header.DataLength );
        ok( received.data[0] == 0x4000000e, "got desktop command %#lx\n", received.data[0] );
        memcpy( &desktop_id, received.data + 1, sizeof(desktop_id) );
        if (desktop_id == input_id) saw_input = TRUE;
        if (desktop_id == default_id) saw_default = TRUE;
        if (desktop_id == logon_id) saw_logon = TRUE;
    }
    ok( saw_input, "DWM startup did not replay input desktop %#I64x\n", input_id );
    ok( saw_default, "DWM startup did not replay default desktop %#I64x\n", default_id );
    ok( saw_logon, "DWM startup did not replay logon desktop %#I64x\n", logon_id );
    ok( saw_startup_begin, "DWM startup did not release the initializing record after desktop replay\n" );

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

        CloseDesktop( lifecycle_desktop );
        lifecycle_desktop = NULL;
        memset( &received, 0, sizeof(received) );
        size = sizeof(received);
        status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &received.header,
                                            &size, NULL, &timeout );
        ok( !status, "desktop free receive returned %#lx\n", status );
        ok( !status && received.header.Type == (ALPC_MESSAGE_TYPE_DATAGRAM | 0x8000),
            "got desktop free type %#x\n", received.header.Type );
        ok( !status && received.header.DataLength == 12, "got desktop free length %#x\n", received.header.DataLength );
        ok( !status && received.data[0] == 0x40000010, "got desktop free command %#lx\n", received.data[0] );
        if (!status) memcpy( &desktop_id, received.data + 1, sizeof(desktop_id) );
        ok( !status && desktop_id == lifecycle_id, "desktop free ID %#I64x, expected %#I64x\n",
            desktop_id, lifecycle_id );
    }

    target_window = CreateWindowExA( 0, "static", "DWM target replay", WS_POPUP,
                                     0, 0, 32, 32, NULL, NULL, NULL, NULL );
    ok( !!target_window, "target window creation failed, error %lu\n", GetLastError() );
    if (target_window)
    {
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
    }

done:
    if (dwm_target) CloseHandle( dwm_target );
    if (target) CloseHandle( target );
    if (target_window) DestroyWindow( target_window );
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
    test_channel_lifetime();
    test_shared_resource_handle_lifecycle();
    test_hwnd_target_lifecycle();
    test_connection_queue();
    test_visual_target_root_lifecycle();
    test_expression_graph();
    test_shared_manipulation_transform();
    test_shared_section_lifecycle();
    test_frame_lifecycle();
    test_resource_retirement();
    test_composition_surface_lifecycle();
    test_connection_lifetime();
    test_token_manager_lifetime();
    test_dwm_session_message_delivery();
}
