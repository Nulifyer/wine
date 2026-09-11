/*
 * LinuxNT Security Reference Monitor boundary tests
 *
 * Copyright 2026 Nulifyer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>
#include <stdio.h>

#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "ntstatus.h"
#include "wine/test.h"

#define SRM_MAX_MESSAGE 0x200
#define SRM_PAYLOAD_LIMIT 0x1d4

struct srm_message
{
    ALPC_PORT_MESSAGE header;
    BYTE data[SRM_PAYLOAD_LIMIT];
};

struct connect_context
{
    HANDLE port;
    NTSTATUS status;
};

static void init_port_attributes( ALPC_PORT_ATTRIBUTES *attributes )
{
    memset( attributes, 0, sizeof(*attributes) );
    attributes->SecurityQos.Length = sizeof(attributes->SecurityQos);
    attributes->SecurityQos.ImpersonationLevel = SecurityIdentification;
    attributes->SecurityQos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
    attributes->MaxMessageLength = SRM_MAX_MESSAGE;
}

static DWORD WINAPI connect_to_rm( void *arg )
{
    static const WCHAR name_buffer[] = L"\\SeRmCommandPort";
    UNICODE_STRING name = RTL_CONSTANT_STRING(name_buffer);
    ALPC_PORT_ATTRIBUTES attributes;
    struct connect_context *context = arg;

    init_port_attributes( &attributes );
    context->status = NtAlpcConnectPort( &context->port, &name, NULL, &attributes,
                                         ALPC_SYNC_CONNECTION, NULL, NULL, NULL,
                                         NULL, NULL, NULL );
    return context->status;
}

static BOOL start_server(void)
{
    SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
    STARTUPINFOW startup = {sizeof(startup)};
    PROCESS_INFORMATION process = {0};
    WCHAR command[128];
    HANDLE ready_event, handles[2];
    DWORD wait, exit_code = ~0u;

    ready_event = CreateEventW( &security, TRUE, FALSE, NULL );
    ok( !!ready_event, "CreateEventW failed, error %lu\n", GetLastError() );
    if (!ready_event) return FALSE;
    if (swprintf( command, ARRAY_SIZE(command), L"linuxntsrm-server.exe --serve %Ix",
                  (ULONG_PTR)ready_event ) < 0)
    {
        CloseHandle( ready_event );
        return FALSE;
    }
    if (!CreateProcessW( NULL, command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL,
                         &startup, &process ))
    {
        win_skip( "linuxntsrm-server.exe is unavailable, error %lu\n", GetLastError() );
        CloseHandle( ready_event );
        return FALSE;
    }
    handles[0] = ready_event;
    handles[1] = process.hProcess;
    wait = WaitForMultipleObjects( ARRAY_SIZE(handles), handles, FALSE, 30000 );
    ok( wait == WAIT_OBJECT_0, "server readiness wait returned %#lx\n", wait );
    if (wait != WAIT_OBJECT_0)
    {
        if (wait == WAIT_OBJECT_0 + 1 && GetExitCodeProcess( process.hProcess, &exit_code ))
            ok( 0, "server exited %lu before becoming ready\n", exit_code );
        else
            ok( 0, "server readiness failed, error %lu\n", GetLastError() );
        TerminateProcess( process.hProcess, ERROR_TIMEOUT );
    }
    CloseHandle( process.hThread );
    CloseHandle( process.hProcess );
    CloseHandle( ready_event );
    return wait == WAIT_OBJECT_0;
}

static void test_lsa_handshake(void)
{
    static const WCHAR name_buffer[] = L"\\SeLsaCommandPort";
    UNICODE_STRING name = RTL_CONSTANT_STRING(name_buffer);
    ALPC_PORT_ATTRIBUTES attributes;
    OBJECT_ATTRIBUTES object_attributes;
    struct connect_context context = {0};
    struct srm_message message;
    HANDLE lsa_port, reverse_port, thread;
    SIZE_T size;
    NTSTATUS status, command_status;
    DWORD wait;
    ULONG command = 1;

    init_port_attributes( &attributes );
    InitializeObjectAttributes( &object_attributes, &name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    status = NtAlpcCreatePort( &lsa_port, &object_attributes, &attributes );
    ok( !status, "NtAlpcCreatePort returned %#lx\n", status );
    if (status) return;
    if (!start_server())
    {
        NtClose( lsa_port );
        return;
    }

    thread = CreateThread( NULL, 0, connect_to_rm, &context, 0, NULL );
    ok( !!thread, "CreateThread failed, error %lu\n", GetLastError() );
    if (!thread)
    {
        NtClose( lsa_port );
        return;
    }

    memset( &message, 0, sizeof(message) );
    size = sizeof(message);
    status = NtAlpcSendWaitReceivePort( lsa_port, 0, NULL, NULL, &message.header,
                                        &size, NULL, NULL );
    ok( !status, "reverse connection receive returned %#lx\n", status );
    ok( (message.header.Type & 0xff) == ALPC_MESSAGE_TYPE_CONNECTION_REQUEST,
        "unexpected reverse message type %#x\n", message.header.Type );
    ok( message.header.DataLength == 0, "reverse connection carried %u data bytes\n",
        message.header.DataLength );
    status = NtAlpcAcceptConnectPort( &reverse_port, lsa_port, 0, NULL, &attributes,
                                      NULL, &message.header, NULL, TRUE );
    ok( !status, "reverse connection accept returned %#lx\n", status );

    wait = WaitForSingleObject( thread, 30000 );
    ok( wait == WAIT_OBJECT_0, "forward connection wait returned %#lx\n", wait );
    ok( !context.status, "forward connection returned %#lx\n", context.status );
    CloseHandle( thread );
    if (status || context.status)
    {
        if (!status) NtClose( reverse_port );
        if (!context.status) NtClose( context.port );
        NtClose( lsa_port );
        return;
    }

    memset( &message, 0, sizeof(message) );
    message.header.DataLength = sizeof(command);
    message.header.TotalLength = sizeof(message.header) + message.header.DataLength;
    memcpy( message.data, &command, sizeof(command) );
    size = sizeof(message);
    status = NtAlpcSendWaitReceivePort( context.port, ALPC_MSGFLG_SYNC_REQUEST,
                                        &message.header, NULL, &message.header, &size, NULL, NULL );
    ok( !status, "command request returned %#lx\n", status );
    ok( message.header.DataLength == sizeof(command_status), "reply has %u data bytes\n",
        message.header.DataLength );
    memcpy( &command_status, message.data, sizeof(command_status) );
    ok( command_status == STATUS_NOT_IMPLEMENTED, "command status is %#lx\n", command_status );

    NtClose( context.port );
    NtClose( reverse_port );
    NtClose( lsa_port );
}

START_TEST(srm)
{
    test_lsa_handshake();
}
