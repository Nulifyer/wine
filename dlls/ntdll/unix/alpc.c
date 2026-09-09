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

#if 0
#pragma makedep unix
#endif

#include "ntstatus.h"
#include "wine/debug.h"
#include "wine/server.h"
#include "unix_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(alpc);

NTSTATUS WINAPI NtAlpcAcceptConnectPort( HANDLE *communication_port, HANDLE connection_port,
                                         DWORD flags, OBJECT_ATTRIBUTES *obj_attr,
                                         ALPC_PORT_ATTRIBUTES *port_attr, void *port_context,
                                         ALPC_PORT_MESSAGE *send_msg,
                                         ALPC_MESSAGE_ATTRIBUTES *send_msg_attr, BOOLEAN accept )
{
    NTSTATUS status;
    if (!communication_port || !send_msg) return STATUS_ACCESS_VIOLATION;
    if (flags || send_msg_attr || (obj_attr && (obj_attr->ObjectName || obj_attr->SecurityDescriptor)))
        return STATUS_NOT_IMPLEMENTED;
    if (send_msg->TotalLength != sizeof(*send_msg) + send_msg->DataLength) return STATUS_INVALID_PARAMETER;
    SERVER_START_REQ( alpc_accept_connect_port )
    {
        req->connection = wine_server_obj_handle( connection_port );
        req->port_flags = port_attr ? port_attr->Flags : 0;
        req->max_msg_len = port_attr ? port_attr->MaxMessageLength : 65535;
        req->attributes = obj_attr ? obj_attr->Attributes : 0;
        req->message_id = send_msg->MessageId;
        req->sender_pid = HandleToULong( send_msg->ClientId.UniqueProcess );
        req->sender_tid = HandleToULong( send_msg->ClientId.UniqueThread );
        req->context = wine_server_client_ptr( port_context );
        req->accept = accept;
        if (accept) wine_server_add_data( req, send_msg + 1, send_msg->DataLength );
        status = wine_server_call( req );
        if (!status && accept) *communication_port = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return status;
}

NTSTATUS WINAPI NtAlpcConnectPort( HANDLE *port_handle, UNICODE_STRING *port_name,
                                   OBJECT_ATTRIBUTES *obj_attr, ALPC_PORT_ATTRIBUTES *port_attr,
                                   DWORD flags, PSID required_server_sid,
                                   ALPC_PORT_MESSAGE *connect_msg, SIZE_T *connect_msg_size,
                                   ALPC_MESSAGE_ATTRIBUTES *send_msg_attr,
                                   ALPC_MESSAGE_ATTRIBUTES *recv_msg_attr, LARGE_INTEGER *timeout )
{
    HANDLE handle = NULL;
    NTSTATUS status;
    SIZE_T capacity = connect_msg_size ? *connect_msg_size : 0;
    ULONG sid_size = 0;

    if (!port_handle || !port_name) return STATUS_ACCESS_VIOLATION;
    if (send_msg_attr || recv_msg_attr || flags & ~ALPC_SYNC_CONNECTION || !port_attr ||
        !(port_attr->Flags & 0x40000) || (obj_attr && obj_attr->SecurityDescriptor))
        return STATUS_NOT_IMPLEMENTED;
    if (!port_name->Buffer || port_name->Length % sizeof(WCHAR)) return STATUS_OBJECT_NAME_INVALID;
    if (connect_msg && (!connect_msg_size || capacity < sizeof(*connect_msg) || capacity > ~(data_size_t)0 ||
                        connect_msg->TotalLength != sizeof(*connect_msg) + connect_msg->DataLength))
        return STATUS_INVALID_PARAMETER;
    if (required_server_sid)
    {
        const SID *sid = required_server_sid;
        if (sid->Revision != SID_REVISION || sid->SubAuthorityCount > SID_MAX_SUB_AUTHORITIES)
            return STATUS_INVALID_SID;
        sid_size = offsetof( SID, SubAuthority[sid->SubAuthorityCount] );
    }
    SERVER_START_REQ( alpc_connect_port )
    {
        req->rootdir = wine_server_obj_handle( obj_attr ? obj_attr->RootDirectory : NULL );
        req->attributes = obj_attr ? obj_attr->Attributes : 0;
        req->flags = flags;
        req->port_flags = port_attr->Flags;
        req->max_msg_len = port_attr->MaxMessageLength;
        req->name_size = port_name->Length;
        req->sid_size = sid_size;
        req->wow64 = is_wow64();
        wine_server_add_data( req, port_name->Buffer, port_name->Length );
        if (sid_size) wine_server_add_data( req, required_server_sid, sid_size );
        if (connect_msg) wine_server_add_data( req, connect_msg + 1, connect_msg->DataLength );
        status = wine_server_call( req );
        if (!status) handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    if (status) return status;

    /* Exactly one wait owns the caller's timeout. A pending request is canceled
     * by closing the private client handle, with the server also canceling it on thread termination. */
    status = NtWaitForSingleObject( handle, FALSE, timeout );
    if (!status)
    {
        SERVER_START_REQ( alpc_get_connect_result )
        {
            req->handle = wine_server_obj_handle( handle );
            if (connect_msg && (flags & ALPC_SYNC_CONNECTION))
                wine_server_set_reply( req, connect_msg + 1, capacity - sizeof(*connect_msg) );
            status = wine_server_call( req );
            if (!status) status = reply->status;
            if (connect_msg && (flags & ALPC_SYNC_CONNECTION) && (!status || status == STATUS_BUFFER_TOO_SMALL))
                *connect_msg_size = sizeof(*connect_msg) + reply->message_size;
            if (connect_msg && !status && (flags & ALPC_SYNC_CONNECTION))
            {
                memset( connect_msg, 0, sizeof(*connect_msg) );
                connect_msg->DataLength = reply->message_size;
                connect_msg->TotalLength = sizeof(*connect_msg) + reply->message_size;
                connect_msg->Type = reply->message_type;
                connect_msg->MessageId = reply->message_id;
                connect_msg->ClientId.UniqueProcess = ULongToHandle( reply->sender_pid );
                connect_msg->ClientId.UniqueThread = ULongToHandle( reply->sender_tid );
            }
        }
        SERVER_END_REQ;
    }
    if (status) NtClose( handle );
    else *port_handle = handle;
    return status;
}

NTSTATUS WINAPI NtAlpcCreatePort( HANDLE *port_handle, OBJECT_ATTRIBUTES *attr, ALPC_PORT_ATTRIBUTES *port_attr )
{
    struct object_attributes *objattr = NULL;
    unsigned int status;
    data_size_t len = 0;

    TRACE( "%p, %p, %p.\n", port_handle, attr, port_attr );

    if (!port_handle) return STATUS_ACCESS_VIOLATION;

    *port_handle = NULL;

    if (port_attr)
        TRACE( "port attributes: flags %#x qos (length %#x impersonation_level %d tracking_mode %d "
               "effective only %d) max_msg_length %#lx memory_bandwidth %#lx max_pool_usage %#lx "
               "max_section_size %#lx max_view_size %#lx max_total_section_size %#lx.\n",
               port_attr->Flags, port_attr->SecurityQos.Length, port_attr->SecurityQos.ImpersonationLevel,
               port_attr->SecurityQos.ContextTrackingMode, port_attr->SecurityQos.EffectiveOnly,
               port_attr->MaxMessageLength, port_attr->MemoryBandwidth, port_attr->MaxPoolUsage,
               port_attr->MaxSectionSize, port_attr->MaxViewSize, port_attr->MaxTotalSectionSize );

    if (port_attr && port_attr->Flags & 0x100000) return STATUS_INVALID_PARAMETER;

    if (attr)
    {
        if (attr->ObjectName) TRACE( "name %s.\n", debugstr_us( attr->ObjectName ) );
        if ((status = wine_server_alloc_object_attributes( attr, &objattr, &len ))) return status;
    }

    SERVER_START_REQ( alpc_create_port )
    {
        if (port_attr)
        {
            req->flags = port_attr->Flags;
            req->max_msg_len = port_attr->MaxMessageLength;
        }
        else
        {
            req->flags = 0;
            req->max_msg_len = 65535;
        }
        wine_server_add_data( req, objattr, len );
        if (!(status = wine_server_call( req )))
        {
            *port_handle = wine_server_ptr_handle( reply->handle );
            TRACE( "created %p.\n", *port_handle );
        }
        else
        {
            WARN( "status %#x.\n", status );
        }
    }
    SERVER_END_REQ;
    free( objattr );
    return status;
}

NTSTATUS WINAPI NtAlpcDisconnectPort( HANDLE port_handle, ULONG flags )
{
    NTSTATUS status;
    if (flags) return STATUS_NOT_IMPLEMENTED;
    SERVER_START_REQ( alpc_disconnect_port )
    {
        req->handle = wine_server_obj_handle( port_handle );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}

NTSTATUS WINAPI NtAlpcSendWaitReceivePort( HANDLE port_handle, ULONG flags,
                                           ALPC_PORT_MESSAGE *send_msg,
                                           ALPC_MESSAGE_ATTRIBUTES *send_msg_attr,
                                           ALPC_PORT_MESSAGE *recv_msg, SIZE_T *recv_buffer_size,
                                           ALPC_MESSAGE_ATTRIBUTES *recv_msg_attr,
                                           LARGE_INTEGER *timeout )
{
    SIZE_T capacity = recv_buffer_size ? *recv_buffer_size : 0;
    NTSTATUS status;

    TRACE( "%p, %#x, %p, %p, %p, %p, %p, %p.\n", port_handle, (unsigned int)flags,
           send_msg, send_msg_attr, recv_msg, recv_buffer_size, recv_msg_attr, timeout );
    if (send_msg_attr || recv_msg_attr || flags & ~(1 | 0x10000)) return STATUS_NOT_IMPLEMENTED;
    if (send_msg && (send_msg->MessageId || send_msg->ClientId.UniqueProcess ||
                     send_msg->ClientId.UniqueThread)) return STATUS_NOT_IMPLEMENTED;
    if (recv_msg && !recv_buffer_size) return STATUS_INVALID_PARAMETER;
    if (recv_msg && capacity < sizeof(*recv_msg)) return STATUS_BUFFER_TOO_SMALL;
    if (capacity > ~(data_size_t)0) return STATUS_INVALID_PARAMETER;
    if (send_msg && send_msg->TotalLength != sizeof(*send_msg) + send_msg->DataLength)
        return STATUS_INVALID_PARAMETER;

    SERVER_START_REQ( alpc_send_receive )
    {
        req->handle = wine_server_obj_handle( port_handle );
        req->flags = flags;
        req->message_id = send_msg ? send_msg->MessageId : 0;
        req->send = !!send_msg;
        req->receive = !!recv_msg;
        req->wow64 = is_wow64();
        if (send_msg) wine_server_add_data( req, send_msg + 1, send_msg->DataLength );
        if (recv_msg) wine_server_set_reply( req, recv_msg + 1, capacity - sizeof(*recv_msg) );
        status = wine_server_call( req );
        if (recv_msg && status == STATUS_BUFFER_TOO_SMALL)
            *recv_buffer_size = reply->message_size + sizeof(*recv_msg);
        if (recv_msg && !status)
        {
            memset( recv_msg, 0, sizeof(*recv_msg) );
            recv_msg->DataLength = reply->message_size;
            recv_msg->TotalLength = sizeof(*recv_msg) + reply->message_size;
            recv_msg->Type = reply->message_type;
            recv_msg->ClientId.UniqueProcess = ULongToHandle( reply->sender_pid );
            recv_msg->ClientId.UniqueThread = ULongToHandle( reply->sender_tid );
            recv_msg->MessageId = reply->message_id;
        }
    }
    SERVER_END_REQ;
    return status;
}

NTSTATUS WINAPI NtAlpcImpersonateClientOfPort( HANDLE port_handle, ALPC_PORT_MESSAGE *msg, void *reserved )
{
    FIXME( "%p, %p, %p stub!\n", port_handle, msg, reserved );
    return STATUS_NOT_IMPLEMENTED;
}
