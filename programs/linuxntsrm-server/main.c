/*
 * LinuxNT user-mode Security Reference Monitor boundary
 *
 * Copyright 2026 Nulifyer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>

#include "windef.h"
#include "winternl.h"
#include "ntstatus.h"

#define SRM_MAX_MESSAGE 0x200
#define SRM_PAYLOAD_LIMIT 0x1d4

struct srm_message
{
    ALPC_PORT_MESSAGE header;
    BYTE data[SRM_PAYLOAD_LIMIT];
};

static void zero_memory( void *ptr, SIZE_T size )
{
    BYTE *bytes = ptr;

    while (size--) *bytes++ = 0;
}

static BOOL unicode_contains( const UNICODE_STRING *string, const WCHAR *needle )
{
    SIZE_T string_len = string->Length / sizeof(WCHAR), needle_len = 0, i, j;

    while (needle[needle_len]) needle_len++;
    if (needle_len > string_len) return FALSE;
    for (i = 0; i <= string_len - needle_len; i++)
    {
        for (j = 0; j < needle_len && string->Buffer[i + j] == needle[j]; j++);
        if (j == needle_len) return TRUE;
    }
    return FALSE;
}

static HANDLE parse_serve_event( const UNICODE_STRING *command )
{
    static const WCHAR marker[] = L"--serve ";
    SIZE_T length = command->Length / sizeof(WCHAR), marker_len = ARRAY_SIZE(marker) - 1;
    ULONG_PTR value = 0;
    SIZE_T i, j;

    if (marker_len >= length) return NULL;
    for (i = 0; i <= length - marker_len; i++)
    {
        for (j = 0; j < marker_len && command->Buffer[i + j] == marker[j]; j++);
        if (j != marker_len) continue;

        i += marker_len;
        if (i == length) return NULL;
        for (; i < length && command->Buffer[i] != ' '; i++)
        {
            WCHAR ch = command->Buffer[i];
            ULONG digit;

            if (ch >= '0' && ch <= '9') digit = ch - '0';
            else if (ch >= 'a' && ch <= 'f') digit = ch - 'a' + 10;
            else if (ch >= 'A' && ch <= 'F') digit = ch - 'A' + 10;
            else return NULL;
            if (value > (~(ULONG_PTR)0 >> 4)) return NULL;
            value = (value << 4) | digit;
        }
        return (HANDLE)value;
    }
    return NULL;
}

static void init_port_attributes( ALPC_PORT_ATTRIBUTES *attributes )
{
    zero_memory( attributes, sizeof(*attributes) );
    attributes->SecurityQos.Length = sizeof(attributes->SecurityQos);
    attributes->SecurityQos.ImpersonationLevel = SecurityIdentification;
    attributes->SecurityQos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
    attributes->MaxMessageLength = SRM_MAX_MESSAGE;
}

static NTSTATUS send_status_reply( HANDLE port, const ALPC_PORT_MESSAGE *request, NTSTATUS command_status )
{
    struct srm_message reply;
    SIZE_T i;

    zero_memory( &reply, sizeof(reply) );
    reply.header.DataLength = sizeof(command_status);
    reply.header.TotalLength = sizeof(reply.header) + reply.header.DataLength;
    reply.header.MessageId = request->MessageId;
    for (i = 0; i < sizeof(command_status); i++) reply.data[i] = ((BYTE *)&command_status)[i];
    return NtAlpcSendWaitReceivePort( port, ALPC_MSGFLG_REPLY_MESSAGE, &reply.header, NULL,
                                      NULL, NULL, NULL, NULL );
}

static NTSTATUS serve_lsa_commands( HANDLE command_port )
{
    struct srm_message request;
    NTSTATUS status;

    for (;;)
    {
        SIZE_T size = sizeof(request);

        zero_memory( &request, sizeof(request) );
        status = NtAlpcSendWaitReceivePort( command_port, 0, NULL, NULL, &request.header,
                                            &size, NULL, NULL );
        if (status) return status;
        if ((request.header.Type & 0xff) == ALPC_MESSAGE_TYPE_PORT_CLOSED) return STATUS_PORT_DISCONNECTED;
        if ((request.header.Type & 0xff) != ALPC_MESSAGE_TYPE_REQUEST ||
            request.header.DataLength < sizeof(ULONG))
            continue;

        /* Each command is enabled only after its Windows contract is mapped.
         * Returning an explicit status preserves the genuine LSA caller's
         * error path while the lower LinuxNT implementation is filled in. */
        status = send_status_reply( command_port, &request.header, STATUS_NOT_IMPLEMENTED );
        if (status) return status;
    }
}

static NTSTATUS run_server( HANDLE ready_event )
{
    static const WCHAR rm_name_buffer[] = L"\\SeRmCommandPort";
    static const WCHAR lsa_name_buffer[] = L"\\SeLsaCommandPort";
    UNICODE_STRING rm_name = RTL_CONSTANT_STRING(rm_name_buffer);
    UNICODE_STRING lsa_name = RTL_CONSTANT_STRING(lsa_name_buffer);
    ALPC_PORT_ATTRIBUTES attributes;
    OBJECT_ATTRIBUTES object_attributes;
    struct srm_message connection_request;
    HANDLE command_port = NULL, lsa_server_port = NULL, lsa_command_port = NULL;
    SIZE_T size;
    NTSTATUS status;

    init_port_attributes( &attributes );
    InitializeObjectAttributes( &object_attributes, &rm_name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    status = NtAlpcCreatePort( &command_port, &object_attributes, &attributes );
    if (status) return status;

    if (ready_event)
    {
        status = NtSetEvent( ready_event, NULL );
        NtClose( ready_event );
        if (status)
        {
            NtClose( command_port );
            return status;
        }
    }

    size = sizeof(connection_request);
    zero_memory( &connection_request, sizeof(connection_request) );
    status = NtAlpcSendWaitReceivePort( command_port, 0, NULL, NULL, &connection_request.header,
                                        &size, NULL, NULL );
    if (status) goto done;
    if ((connection_request.header.Type & 0xff) != ALPC_MESSAGE_TYPE_CONNECTION_REQUEST)
    {
        status = STATUS_INVALID_MESSAGE;
        goto done;
    }

    status = NtAlpcAcceptConnectPort( &lsa_server_port, command_port, 0, NULL, &attributes,
                                      NULL, &connection_request.header, NULL, TRUE );
    if (status) goto done;

    status = NtAlpcConnectPort( &lsa_command_port, &lsa_name, NULL, &attributes,
                                ALPC_SYNC_CONNECTION, NULL, NULL, NULL, NULL, NULL, NULL );
    if (status) goto done;

    status = serve_lsa_commands( command_port );

done:
    if (lsa_command_port) NtClose( lsa_command_port );
    if (lsa_server_port) NtClose( lsa_server_port );
    NtClose( command_port );
    return status;
}

void WINAPI NtProcessStartup( PEB *peb )
{
    RTL_USER_PROCESS_PARAMETERS *params = peb->ProcessParameters;
    HANDLE ready_event = parse_serve_event( &params->CommandLine );
    NTSTATUS status;

    if (ready_event)
        status = run_server( ready_event );
    else if (unicode_contains( &params->CommandLine, L"--direct" ))
        status = run_server( NULL );
    else
        status = STATUS_INVALID_PARAMETER;
    RtlExitUserProcess( status );
}
