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
    ALPC_PORT_ATTRIBUTES attributes = {0};

    TRACE( "%s %p %#lx %p\n", api_port_name ?
           wine_dbgstr_wn(api_port_name->Buffer, api_port_name->Length / sizeof(WCHAR)) : "(null)", api_port_handle,
           process_image_type, connection_handle );

    if (!connection_handle) return STATUS_ACCESS_VIOLATION;
    if (api_port_name) return STATUS_INVALID_PORT_ATTRIBUTES;

    /* The default client form does not admit a subsystem, so Windows ignores
     * the supplied server handle and image type. The named form carries that
     * admission data and remains a separate contract. */
    attributes.Flags = 0x20000;
    attributes.MaxMessageLength = 0x148;
    attributes.MaxPoolUsage = 1000000;
    return NtAlpcConnectPort( connection_handle, &default_name, NULL, &attributes, 0,
                              NULL, NULL, NULL, NULL, NULL, NULL );
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
