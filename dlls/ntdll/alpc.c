/*
 * Advanced Local Procedure Call
 *
 * Copyright 2026 Zhiyi Zhang for CodeWeavers
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

#include <stdarg.h>
#include <windef.h>
#include <winternl.h>
#include <ntstatus.h>
#include "wine/debug.h"
#include "wine/alpc.h"
#include "wine/server.h"

WINE_DEFAULT_DEBUG_CHANNEL(alpc);

/***********************************************************************
 *           RtlConnectToSm    (NTDLL.@)
 */
NTSTATUS WINAPI RtlConnectToSm( UNICODE_STRING *api_port_name, HANDLE api_port_handle,
                                ULONG process_image_type, HANDLE *connection_handle )
{
    static const WCHAR default_name_buffer[] = L"\\SmApiPort";
    UNICODE_STRING default_name = RTL_CONSTANT_STRING(default_name_buffer);
    BYTE connection_buffer[0x120] = {0};
    ALPC_PORT_MESSAGE *message = (ALPC_PORT_MESSAGE *)connection_buffer;
    ALPC_PORT_ATTRIBUTES attributes = {0};
    SIZE_T message_size = sizeof(connection_buffer);

    TRACE( "%s %p %#lx %p\n", api_port_name ?
           wine_dbgstr_wn(api_port_name->Buffer, api_port_name->Length / sizeof(WCHAR)) : "(null)", api_port_handle,
           process_image_type, connection_handle );

    if (!connection_handle) return STATUS_ACCESS_VIOLATION;
    if (api_port_name)
    {
        if (!api_port_handle || !process_image_type) return STATUS_INVALID_PARAMETER_MIX;
        if (api_port_name->Length >= 0xf0) return STATUS_INVALID_PARAMETER;
        *(ULONG *)(connection_buffer + 0x28) = process_image_type;
        memcpy( connection_buffer + 0x2c, api_port_name->Buffer, api_port_name->Length );
    }

    /* The server opens a named subsystem port from the connection payload;
     * api_port_handle is required by the contract but is not transferred. */
    message->DataLength = 0xf4;
    message->TotalLength = 0x11c;
    attributes.Flags = 0x10000;
    attributes.SecurityQos.ImpersonationLevel = SecurityImpersonation;
    attributes.SecurityQos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    attributes.SecurityQos.EffectiveOnly = TRUE;
    attributes.MaxMessageLength = 0x148;
    attributes.MaxPoolUsage = 0x2900;
    return NtAlpcConnectPort( connection_handle, &default_name, NULL, &attributes, 0x20000,
                              NULL, message, &message_size, NULL, NULL, NULL );
}

/***********************************************************************
 *           RtlSendMsgToSm    (NTDLL.@)
 */
NTSTATUS WINAPI RtlSendMsgToSm( HANDLE connection_handle, ALPC_PORT_MESSAGE *message )
{
    static const USHORT data_sizes[] = {0, 8, 0, 0x70, 0x44, 0x118, 4, 0x10, 8};
    ULONG api_number;
    SIZE_T reply_size = 0x148;
    NTSTATUS status;

    if (!message) return STATUS_ACCESS_VIOLATION;
    api_number = *(ULONG *)((BYTE *)message + 0x28);
    TRACE( "%p %p api %lu\n", connection_handle, message, api_number );
    if (api_number >= ARRAY_SIZE(data_sizes)) return STATUS_NOT_IMPLEMENTED;

    memset( message, 0, sizeof(*message) );
    message->DataLength = data_sizes[api_number] + sizeof(ULONGLONG);
    message->TotalLength = message->DataLength + sizeof(*message);
    status = NtAlpcSendWaitReceivePort( connection_handle, 0x20000, message, NULL,
                                        message, &reply_size, NULL, NULL );
    if (status < 0) return status;
    return *(NTSTATUS *)((BYTE *)message + 0x2c);
}

/***********************************************************************
 *           NtAlpcConnectPortEx    (NTDLL.@)
 *
 * The extended entry point names the connection port through object
 * attributes.  Wine's existing connection owner takes the same lookup
 * attributes separately from the name, so the security-neutral subset can
 * be adapted without adding a second ALPC connection implementation.
 */
NTSTATUS WINAPI NtAlpcConnectPortEx( HANDLE *port_handle,
                                     OBJECT_ATTRIBUTES *connection_port_attributes,
                                     OBJECT_ATTRIBUTES *client_port_attributes,
                                     ALPC_PORT_ATTRIBUTES *port_attributes, ULONG flags,
                                     SECURITY_DESCRIPTOR *server_security_requirements,
                                     ALPC_PORT_MESSAGE *connection_message, SIZE_T *buffer_length,
                                     ALPC_MESSAGE_ATTRIBUTES *out_message_attributes,
                                     ALPC_MESSAGE_ATTRIBUTES *in_message_attributes,
                                     LARGE_INTEGER *timeout )
{
    OBJECT_ATTRIBUTES lookup_attributes;

    TRACE( "%p %p %p %p %#lx %p %p %p %p %p %p\n", port_handle,
           connection_port_attributes, client_port_attributes, port_attributes, flags,
           server_security_requirements, connection_message, buffer_length,
           out_message_attributes, in_message_attributes, timeout );

    if (!port_handle || !connection_port_attributes) return STATUS_ACCESS_VIOLATION;
    if (connection_port_attributes->Length != sizeof(*connection_port_attributes) ||
        !connection_port_attributes->ObjectName)
        return STATUS_INVALID_PARAMETER;

    /* The current server does not yet model client-port object attributes or
     * server security-descriptor authorization.  Do not silently discard
     * either contract. */
    if (client_port_attributes || server_security_requirements) return STATUS_NOT_IMPLEMENTED;

    lookup_attributes = *connection_port_attributes;
    lookup_attributes.ObjectName = NULL;
    return NtAlpcConnectPort( port_handle, connection_port_attributes->ObjectName,
                              &lookup_attributes, port_attributes, flags, NULL,
                              connection_message, buffer_length, out_message_attributes,
                              in_message_attributes, timeout );
}

/***********************************************************************
 *           NtAlpcQueryInformation    (NTDLL.@)
 */
NTSTATUS WINAPI NtAlpcQueryInformation( HANDLE port_handle, ULONG information_class,
                                        void *information, ULONG length, ULONG *return_length )
{
    ALPC_BASIC_INFORMATION *basic = information;
    NTSTATUS status;

    TRACE( "%p %lu %p %lu %p\n", port_handle, information_class, information,
           length, return_length );

    if (information_class) return STATUS_INVALID_INFO_CLASS;
    if (return_length) *return_length = sizeof(*basic);
    if (length < sizeof(*basic)) return STATUS_INFO_LENGTH_MISMATCH;
    if (!basic) return STATUS_ACCESS_VIOLATION;

    SERVER_START_REQ( alpc_query_information )
    {
        req->handle = wine_server_obj_handle( port_handle );
        if (!(status = wine_server_call( req )))
        {
            basic->Flags = reply->flags;
            basic->SequenceNo = reply->sequence;
            basic->PortContext = wine_server_get_ptr( reply->context );
        }
    }
    SERVER_END_REQ;
    return status;
}

SIZE_T WINAPI AlpcGetHeaderSize(ULONG attribute_flags)
{
    TRACE("%#lx.\n", attribute_flags);
    return wine_alpc_get_header_size( attribute_flags );
}

void * WINAPI AlpcGetMessageAttribute(ALPC_MESSAGE_ATTRIBUTES *attributes, ULONG attribute_flag)
{
    TRACE("%p, %lx.\n", attributes, attribute_flag);

    return wine_alpc_get_attribute( attributes, attribute_flag );
}

NTSTATUS WINAPI AlpcInitializeMessageAttribute(ULONG attribute_flags, ALPC_MESSAGE_ATTRIBUTES *buffer,
                                               SIZE_T buffer_size, SIZE_T *required_buffer_size)
{
    TRACE("%#lx, %p, %Ix, %p.\n", attribute_flags, buffer, buffer_size, required_buffer_size);

    *required_buffer_size = AlpcGetHeaderSize(attribute_flags);

    if (buffer_size < *required_buffer_size)
        return STATUS_BUFFER_TOO_SMALL;

    if (buffer)
    {
        buffer->AllocatedAttributes = attribute_flags;
        buffer->ValidAttributes = 0;
    }

    return STATUS_SUCCESS;

}
