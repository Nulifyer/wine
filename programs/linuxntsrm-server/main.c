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
#define LSA_CONNECT_RETRY_COUNT 2400
#define LSA_CONNECT_RETRY_100NS 500000
#define POLICY_INIT_TIMEOUT_SECONDS 120

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

static NTSTATUS receive_message( HANDLE port, struct srm_message *message, SIZE_T *size )
{
    LARGE_INTEGER retry_delay;
    NTSTATUS status;

    retry_delay.QuadPart = -LSA_CONNECT_RETRY_100NS;
    for (;;)
    {
        zero_memory( message, sizeof(*message) );
        *size = sizeof(*message);
        status = NtAlpcSendWaitReceivePort( port, 0, NULL, NULL, &message->header,
                                            size, NULL, NULL );
        /* Wine can expose STATUS_PENDING while an empty ALPC listener wait is
         * being armed.  Retry until a message or terminal status is present. */
        if (status != STATUS_PENDING) return status;
        NtDelayExecution( FALSE, &retry_delay );
    }
}

static NTSTATUS serve_lsa_commands( HANDLE command_port )
{
    struct srm_message request;
    SIZE_T size;
    NTSTATUS status;

    for (;;)
    {
        status = receive_message( command_port, &request, &size );
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

static NTSTATUS connect_to_lsa( HANDLE *port, UNICODE_STRING *name,
                                ALPC_PORT_ATTRIBUTES *attributes )
{
    LARGE_INTEGER delay;
    NTSTATUS status;
    ULONG attempt;

    delay.QuadPart = -LSA_CONNECT_RETRY_100NS;
    for (attempt = 0; attempt < LSA_CONNECT_RETRY_COUNT; attempt++)
    {
        status = NtAlpcConnectPort( port, name, NULL, attributes, ALPC_SYNC_CONNECTION,
                                    NULL, NULL, NULL, NULL, NULL, NULL );
        if (!status) return status;
        if (status != STATUS_OBJECT_NAME_NOT_FOUND && status != STATUS_OBJECT_PATH_NOT_FOUND)
            return status;
        NtDelayExecution( FALSE, &delay );
    }
    return STATUS_TIMEOUT;
}

static NTSTATUS ensure_default_audit_policy(void)
{
    static const WCHAR security_name_buffer[] = L"\\Registry\\Machine\\Security";
    static const WCHAR revision_name_buffer[] = L"Policy\\PolRevision";
    static const WCHAR audit_name_buffer[] = L"Policy\\PolAdtEv";
    static const ULONG default_audit_policy[] = {FALSE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9};
    UNICODE_STRING security_name = RTL_CONSTANT_STRING(security_name_buffer);
    UNICODE_STRING revision_name = RTL_CONSTANT_STRING(revision_name_buffer);
    UNICODE_STRING audit_name = RTL_CONSTANT_STRING(audit_name_buffer);
    UNICODE_STRING default_name = {0, 0, NULL};
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io;
    LARGE_INTEGER timeout;
    HANDLE security = NULL, security_notify = NULL, event = NULL, key = NULL;
    BOOL notification_pending = FALSE;
    ULONG disposition;
    NTSTATUS status;

    /* The source SECURITY hive is an empty root.  Materialize only that root;
     * genuine LSASS must remain responsible for creating the policy database
     * and its protected state through RXACT. */
    InitializeObjectAttributes( &attributes, &security_name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    status = NtCreateKey( &security, KEY_CREATE_SUB_KEY, &attributes, 0, NULL,
                          REG_OPTION_NON_VOLATILE, &disposition );
    if (status) return status;

    InitializeObjectAttributes( &attributes, &security_name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    status = NtOpenKey( &security_notify, KEY_NOTIFY, &attributes );
    if (status) goto done;

    status = NtCreateEvent( &event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE );
    if (status) goto done;

    status = NtQuerySystemTime( &timeout );
    if (status) goto done;
    timeout.QuadPart += (LONGLONG)POLICY_INIT_TIMEOUT_SECONDS * 10000000;

    for (;;)
    {
        status = NtNotifyChangeKey( security_notify, event, NULL, NULL, &io,
                                    REG_NOTIFY_CHANGE_NAME, TRUE, NULL, 0, TRUE );
        if (status != STATUS_PENDING) goto done;
        notification_pending = TRUE;

        InitializeObjectAttributes( &attributes, &revision_name, OBJ_CASE_INSENSITIVE,
                                    security, NULL );
        status = NtOpenKey( &key, KEY_READ, &attributes );
        if (!status)
        {
            NtClose( key );
            key = NULL;
            break;
        }
        if (status != STATUS_OBJECT_NAME_NOT_FOUND && status != STATUS_OBJECT_PATH_NOT_FOUND)
            goto done;

        status = NtWaitForSingleObject( event, FALSE, &timeout );
        if (status) goto done;
        notification_pending = FALSE;
        NtResetEvent( event, NULL );
    }

    NtClose( security_notify );
    security_notify = NULL;
    status = NtWaitForSingleObject( event, FALSE, NULL );
    notification_pending = FALSE;
    if (status) goto done;

    InitializeObjectAttributes( &attributes, &audit_name, OBJ_CASE_INSENSITIVE, security, NULL );
    status = NtOpenKey( &key, KEY_READ, &attributes );
    if (!status) goto done;
    if (status != STATUS_OBJECT_NAME_NOT_FOUND && status != STATUS_OBJECT_PATH_NOT_FOUND) goto done;

    status = NtCreateKey( &key, KEY_SET_VALUE, &attributes, 0, NULL, REG_OPTION_NON_VOLATILE,
                          &disposition );
    if (status || disposition != REG_CREATED_NEW_KEY) goto done;
    status = NtSetValueKey( key, &default_name, 0, REG_NONE, default_audit_policy,
                            sizeof(default_audit_policy) );

done:
    if (key) NtClose( key );
    if (security_notify) NtClose( security_notify );
    if (notification_pending) NtWaitForSingleObject( event, FALSE, NULL );
    if (event) NtClose( event );
    if (security) NtClose( security );
    return status;
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

    /* Genuine LSASS creates SeLsaCommandPort, then connects to SeRmCommandPort.
     * Accept that forward connection before opening the reverse command port. */
    status = receive_message( command_port, &connection_request, &size );
    if (status) goto done;
    if ((connection_request.header.Type & 0xff) != ALPC_MESSAGE_TYPE_CONNECTION_REQUEST)
    {
        status = STATUS_INVALID_MESSAGE;
        goto done;
    }

    status = NtAlpcAcceptConnectPort( &lsa_server_port, command_port, 0, NULL, &attributes,
                                      NULL, &connection_request.header, NULL, TRUE );
    if (status) goto done;

    status = connect_to_lsa( &lsa_command_port, &lsa_name, &attributes );
    if (status) goto done;

    status = ensure_default_audit_policy();
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
