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

SIZE_T WINAPI AlpcGetHeaderSize(ULONG attribute_flags)
{
    static const struct
    {
        ULONG attribute;
        SIZE_T size;
    } attribute_sizes[] =
    {
        /* Attribute with a higher bit is stored before that with a lower bit */
        {ALPC_MESSAGE_SECURITY_ATTRIBUTE, sizeof(ALPC_SECURITY_ATTR)},
        {ALPC_MESSAGE_VIEW_ATTRIBUTE, sizeof(ALPC_VIEW_ATTR)},
        {ALPC_MESSAGE_CONTEXT_ATTRIBUTE, sizeof(ALPC_CONTEXT_ATTR)},
        {ALPC_MESSAGE_HANDLE_ATTRIBUTE, sizeof(ALPC_HANDLE_ATTR)},
        {ALPC_MESSAGE_TOKEN_ATTRIBUTE, sizeof(ALPC_TOKEN_ATTR)},
        {ALPC_MESSAGE_DIRECT_ATTRIBUTE, sizeof(ALPC_DIRECT_ATTR)},
        {ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE, sizeof(ALPC_WORK_ON_BEHALF_ATTR)},
    };
    unsigned int i;
    SIZE_T size;

    TRACE("%#lx.\n", attribute_flags);

    size = sizeof(ALPC_MESSAGE_ATTRIBUTES);
    for (i = 0; i < ARRAY_SIZE(attribute_sizes); i++)
    {
        if (attribute_flags & attribute_sizes[i].attribute)
            size += attribute_sizes[i].size;
    }

    return size;
}

void * WINAPI AlpcGetMessageAttribute(ALPC_MESSAGE_ATTRIBUTES *attributes, ULONG attribute_flag)
{
    TRACE("%p, %lx.\n", attributes, attribute_flag);

    /* If no flag is specified */
    if (!attribute_flag)
        return NULL;

    /* If more than one flag is specified */
    if (attribute_flag & (attribute_flag - 1))
        return NULL;

    /* If the specified flag is not in allocated attributes */
    if ((attribute_flag & attributes->AllocatedAttributes & ALPC_MESSAGE_ATTRIBUTE_ALL) != attribute_flag)
        return NULL;

    return (unsigned char *)attributes + AlpcGetHeaderSize(attributes->AllocatedAttributes & ~(attribute_flag | (attribute_flag - 1)));
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
