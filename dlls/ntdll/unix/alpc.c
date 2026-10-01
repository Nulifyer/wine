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

static void *get_alpc_message_attribute( ALPC_MESSAGE_ATTRIBUTES *attributes, ULONG flag )
{
    static const struct
    {
        ULONG flag;
        SIZE_T size;
    } attributes_layout[] =
    {
        { ALPC_MESSAGE_SECURITY_ATTRIBUTE, sizeof(ALPC_SECURITY_ATTR) },
        { ALPC_MESSAGE_VIEW_ATTRIBUTE, sizeof(ALPC_VIEW_ATTR) },
        { ALPC_MESSAGE_CONTEXT_ATTRIBUTE, sizeof(ALPC_CONTEXT_ATTR) },
        { ALPC_MESSAGE_HANDLE_ATTRIBUTE, sizeof(ALPC_HANDLE_ATTR) },
        { ALPC_MESSAGE_TOKEN_ATTRIBUTE, sizeof(ALPC_TOKEN_ATTR) },
        { ALPC_MESSAGE_DIRECT_ATTRIBUTE, sizeof(ALPC_DIRECT_ATTR) },
        { ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE, sizeof(ALPC_WORK_ON_BEHALF_ATTR) },
    };
    unsigned char *ptr = (unsigned char *)(attributes + 1);
    unsigned int i;

    if (!attributes || !(attributes->AllocatedAttributes & flag)) return NULL;
    for (i = 0; i < ARRAY_SIZE(attributes_layout); ++i)
    {
        if (attributes_layout[i].flag == flag) return ptr;
        if (attributes->AllocatedAttributes & attributes_layout[i].flag)
            ptr += attributes_layout[i].size;
    }
    return NULL;
}

static client_ptr_t get_alpc_message_context( ALPC_MESSAGE_ATTRIBUTES *attributes )
{
    ALPC_CONTEXT_ATTR *context;

    if (!attributes || !(attributes->ValidAttributes & ALPC_MESSAGE_CONTEXT_ATTRIBUTE)) return 0;
    if (!(context = get_alpc_message_attribute( attributes, ALPC_MESSAGE_CONTEXT_ATTRIBUTE ))) return 0;
    return wine_server_client_ptr( context->MessageContext );
}

static ULONGLONG get_alpc_work_on_behalf( ALPC_MESSAGE_ATTRIBUTES *attributes )
{
    ALPC_WORK_ON_BEHALF_ATTR *work;

    if (!attributes || !(attributes->ValidAttributes & ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE)) return 0;
    if (!(work = get_alpc_message_attribute( attributes, ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE ))) return 0;
    return work->Ticket;
}

static void set_alpc_message_context( ALPC_MESSAGE_ATTRIBUTES *attributes, client_ptr_t port_context,
                                      client_ptr_t message_context, unsigned int message_id )
{
    ALPC_CONTEXT_ATTR *context;

    if (!attributes || !(context = get_alpc_message_attribute( attributes,
                                                                ALPC_MESSAGE_CONTEXT_ATTRIBUTE ))) return;
    context->PortContext = wine_server_get_ptr( port_context );
    context->MessageContext = wine_server_get_ptr( message_context );
    context->Sequence = 0;
    context->MessageId = message_id;
    context->CallbackId = 0;
    attributes->ValidAttributes |= ALPC_MESSAGE_CONTEXT_ATTRIBUTE;
}

static void set_alpc_work_on_behalf( ALPC_MESSAGE_ATTRIBUTES *attributes, ULONGLONG ticket )
{
    ALPC_WORK_ON_BEHALF_ATTR *work;

    if (!attributes || !(work = get_alpc_message_attribute( attributes,
                                                              ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE ))) return;
    work->Ticket = ticket;
    attributes->ValidAttributes |= ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE;
}

static data_size_t get_alpc_message_size( const ALPC_PORT_MESSAGE *message )
{
    if (!message) return 0;
    return sizeof(*message) + message->DataLength;
}

static void trace_alpc_payload( const char *label, const void *data, data_size_t size )
{
    const char *bytes = data;
    data_size_t offset;

    if (!TRACE_ON(alpc)) return;
    for (offset = 0; offset < size; offset += 16)
        TRACE( "%s payload +%04x %s.\n", label, offset,
               debugstr_an( bytes + offset, min( size - offset, 16 ) ) );
}

NTSTATUS WINAPI NtAlpcAcceptConnectPort( HANDLE *communication_port, HANDLE connection_port,
                                         DWORD flags, OBJECT_ATTRIBUTES *obj_attr,
                                         ALPC_PORT_ATTRIBUTES *port_attr, void *port_context,
                                         ALPC_PORT_MESSAGE *send_msg,
                                         ALPC_MESSAGE_ATTRIBUTES *send_msg_attr, BOOLEAN accept )
{
    data_size_t send_size = get_alpc_message_size( send_msg );
    NTSTATUS status;

    TRACE( "%p, %p, %#x, %p, %p, %p, %p, %p, %d.\n", communication_port, connection_port,
           (unsigned int)flags, obj_attr, port_attr, port_context, send_msg, send_msg_attr, accept );

    if (!communication_port) return STATUS_ACCESS_VIOLATION;
    *communication_port = NULL;
    if (!send_msg || !send_size) return STATUS_INVALID_PARAMETER;

    SERVER_START_REQ( alpc_accept_connect_port )
    {
        req->connection = wine_server_obj_handle( connection_port );
        req->flags = flags;
        req->attributes = obj_attr ? obj_attr->Attributes : 0;
        req->accept = accept;
        req->message_id = send_msg->MessageId;
        req->max_msg_len = port_attr ? port_attr->MaxMessageLength : 65535;
        req->port_context = wine_server_client_ptr( port_context );
        req->message_context = get_alpc_message_context( send_msg_attr );
        if (accept && send_size) wine_server_add_data( req, send_msg, send_size );
        status = wine_server_call( req );
        if (!status && accept) *communication_port = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    TRACE( "accept status %#x, communication port %p.\n", (unsigned int)status,
           communication_port ? *communication_port : NULL );
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
    data_size_t message_size = get_alpc_message_size( connect_msg );
    SIZE_T reply_size = connect_msg_size ? *connect_msg_size : 0;
    unsigned int connection_message_id = 0;
    NTSTATUS status;

    TRACE( "%p, %s, %p, %p, %#x, %p, %p, %p, %p, %p, %p.\n", port_handle,
           debugstr_us( port_name ), obj_attr, port_attr, (unsigned int)flags, required_server_sid,
           connect_msg, connect_msg_size, send_msg_attr, recv_msg_attr, timeout );

    if (!port_handle || !port_name) return STATUS_ACCESS_VIOLATION;
    *port_handle = NULL;
    if (!port_name->Buffer || (port_name->Length & (sizeof(WCHAR) - 1))) return STATUS_OBJECT_NAME_INVALID;
    if ((connect_msg && !connect_msg_size) || (!connect_msg && connect_msg_size)) return STATUS_INVALID_PARAMETER;
    if (connect_msg && !message_size) return STATUS_INVALID_PARAMETER;
    if (reply_size > ~(data_size_t)0) return STATUS_INVALID_PARAMETER;
    if (required_server_sid) FIXME( "required server SID is not enforced.\n" );
    if (send_msg_attr) FIXME( "send attributes %#x are only partially supported.\n",
                              send_msg_attr->ValidAttributes );

    SERVER_START_REQ( alpc_connect_port )
    {
        req->flags = flags;
        req->attributes = obj_attr ? obj_attr->Attributes : 0;
        req->rootdir = wine_server_obj_handle( obj_attr ? obj_attr->RootDirectory : NULL );
        req->max_msg_len = port_attr ? port_attr->MaxMessageLength : 65535;
        req->name_size = port_name->Length;
        wine_server_add_data( req, port_name->Buffer, port_name->Length );
        if (message_size) wine_server_add_data( req, connect_msg, message_size );
        status = wine_server_call( req );
        if (!status) handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    TRACE( "initial connect status %#x, handle %p.\n", (unsigned int)status, handle );
    if (status) return status;

    for (;;)
    {
        SERVER_START_REQ( alpc_get_connect_result )
        {
            req->handle = wine_server_obj_handle( handle );
            if (connect_msg && reply_size) wine_server_set_reply( req, connect_msg, reply_size );
            status = wine_server_call( req );
            if (!status)
            {
                if (connect_msg_size) *connect_msg_size = reply->message_size;
                connection_message_id = reply->message_id;
                status = reply->status;
            }
            else if (status == STATUS_BUFFER_TOO_SMALL && connect_msg_size)
                *connect_msg_size = reply->message_size;
        }
        SERVER_END_REQ;

        if (status != STATUS_PENDING) break;
        TRACE( "connection pending on %p.\n", handle );
        status = NtWaitForSingleObject( handle, FALSE, timeout );
        TRACE( "connection wait returned %#x.\n", (unsigned int)status );
        if (status) break;
    }

    if (status)
    {
        NtClose( handle );
        return status;
    }
    if (connect_msg)
    {
        connect_msg->Type = ALPC_MESSAGE_TYPE_CONNECTION_REPLY;
        connect_msg->MessageId = connection_message_id;
    }
    if (recv_msg_attr) recv_msg_attr->ValidAttributes = 0;
    *port_handle = handle;
    TRACE( "connected %p.\n", handle );
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI NtAlpcConnectPortEx( HANDLE *port_handle, OBJECT_ATTRIBUTES *connection_attr,
                                     OBJECT_ATTRIBUTES *client_attr, ALPC_PORT_ATTRIBUTES *port_attr,
                                     DWORD flags, SECURITY_DESCRIPTOR *server_security,
                                     ALPC_PORT_MESSAGE *connect_msg, SIZE_T *connect_msg_size,
                                     ALPC_MESSAGE_ATTRIBUTES *send_msg_attr,
                                     ALPC_MESSAGE_ATTRIBUTES *recv_msg_attr, LARGE_INTEGER *timeout )
{
    TRACE( "%p, %p, %p, %p, %#x, %p, %p, %p, %p, %p, %p.\n", port_handle,
           connection_attr, client_attr, port_attr, (unsigned int)flags, server_security,
           connect_msg, connect_msg_size, send_msg_attr, recv_msg_attr, timeout );

    if (!connection_attr) return STATUS_ACCESS_VIOLATION;
    if (!connection_attr->ObjectName) return STATUS_OBJECT_NAME_INVALID;
    if (client_attr) FIXME( "client port object attributes are not applied.\n" );
    if (server_security) FIXME( "server security requirements are not enforced.\n" );

    /* The Ex entry point moves the connection port name and root directory
     * into OBJECT_ATTRIBUTES.  Wine's ALPC server already accepts those
     * fields through the older entry point, so keep one transport path. */
    return NtAlpcConnectPort( port_handle, connection_attr->ObjectName, connection_attr,
                              port_attr, flags, NULL, connect_msg, connect_msg_size,
                              send_msg_attr, recv_msg_attr, timeout );
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

    TRACE( "%p, %#x.\n", port_handle, (unsigned int)flags );
    SERVER_START_REQ( alpc_disconnect_port )
    {
        req->handle = wine_server_obj_handle( port_handle );
        req->flags = flags;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}

NTSTATUS WINAPI NtAlpcQueryInformation( HANDLE port_handle, ALPC_PORT_INFORMATION_CLASS class,
                                        void *buffer, ULONG length, ULONG *return_length )
{
    ALPC_BASIC_INFORMATION *info = buffer;
    NTSTATUS status;

    TRACE( "%p, %u, %p, %u, %p.\n", port_handle, class, buffer, length, return_length );

    if (class != AlpcBasicInformation) return STATUS_INVALID_INFO_CLASS;
    if (return_length) *return_length = sizeof(*info);
    if (length < sizeof(*info)) return STATUS_INFO_LENGTH_MISMATCH;
    if (!info) return STATUS_ACCESS_VIOLATION;

    SERVER_START_REQ( alpc_query_information )
    {
        req->handle = wine_server_obj_handle( port_handle );
        status = wine_server_call( req );
        if (!status)
        {
            info->Flags = reply->flags;
            info->SequenceNo = reply->sequence;
            info->PortContext = wine_server_get_ptr( reply->context );
        }
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
    data_size_t send_size = get_alpc_message_size( send_msg );
    SIZE_T buffer_size = recv_buffer_size ? *recv_buffer_size : 0;
    unsigned int sent = 0;
    NTSTATUS status;

    TRACE( "%p, %#x, %p, %p, %p, %p, %p, %p.\n", port_handle, (unsigned int)flags, send_msg,
           send_msg_attr, recv_msg, recv_buffer_size, recv_msg_attr, timeout );
    if (send_msg)
    {
        TRACE( "send message data %u total %u type %u id %u.\n", send_msg->DataLength,
               send_msg->TotalLength, send_msg->Type, send_msg->MessageId );
        trace_alpc_payload( "send", send_msg + 1, send_msg->DataLength );
    }

    if ((recv_msg && !recv_buffer_size) || (!recv_msg && recv_buffer_size)) return STATUS_INVALID_PARAMETER;
    if (send_msg && !send_size) return STATUS_INVALID_PARAMETER;
    if (buffer_size > ~(data_size_t)0) return STATUS_INVALID_PARAMETER;
    if (send_msg_attr && (send_msg_attr->ValidAttributes & ~ALPC_MESSAGE_CONTEXT_ATTRIBUTE))
        FIXME( "send attributes %#x are only partially supported.\n", send_msg_attr->ValidAttributes );

    for (;;)
    {
        unsigned int pending = 0, message_id = 0, message_type = 0;
        process_id_t sender_pid = 0;
        thread_id_t sender_tid = 0;
        client_ptr_t port_context = 0, message_context = 0;
        data_size_t received_size = 0;

        SERVER_START_REQ( alpc_send_receive )
        {
            req->handle = wine_server_obj_handle( port_handle );
            req->flags = flags;
            req->send_size = sent ? 0 : send_size;
            req->message_id = send_msg ? send_msg->MessageId : 0;
            req->valid_attributes = !sent && send_msg_attr ? send_msg_attr->ValidAttributes : 0;
            req->message_context = get_alpc_message_context( send_msg_attr );
            req->work_on_behalf = get_alpc_work_on_behalf( send_msg_attr );
            if (!sent && send_size) wine_server_add_data( req, send_msg, send_size );
            if (recv_msg && buffer_size) wine_server_set_reply( req, recv_msg, buffer_size );
            status = wine_server_call( req );
            pending = reply->pending;
            message_id = reply->message_id;
            sender_pid = reply->sender_pid;
            sender_tid = reply->sender_tid;
            message_type = reply->message_type;
            received_size = reply->message_size;
            port_context = reply->port_context;
            message_context = reply->message_context;
            if (recv_msg_attr) recv_msg_attr->ValidAttributes = 0;
            if (reply->valid_attributes & ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE)
                set_alpc_work_on_behalf( recv_msg_attr, reply->work_on_behalf );
        }
        SERVER_END_REQ;

        TRACE( "send/receive status %#x pending %u id %u type %u size %u.\n",
               (unsigned int)status, pending, message_id, message_type, (unsigned int)received_size );

        sent = 1;
        if (recv_buffer_size && (status == STATUS_BUFFER_TOO_SMALL || !status))
            *recv_buffer_size = received_size;
        if (status) return status;
        if (!recv_msg) return STATUS_SUCCESS;
        if (!pending)
        {
            trace_alpc_payload( "receive", recv_msg + 1,
                                received_size > sizeof(*recv_msg) ? received_size - sizeof(*recv_msg) : 0 );
            recv_msg->Type = message_type;
            recv_msg->ClientId.UniqueProcess = ULongToHandle( sender_pid );
            recv_msg->ClientId.UniqueThread = ULongToHandle( sender_tid );
            recv_msg->MessageId = message_id;
            set_alpc_message_context( recv_msg_attr, port_context, message_context, message_id );
            return STATUS_SUCCESS;
        }
        status = NtWaitForSingleObject( port_handle, FALSE, timeout );
        TRACE( "receive wait returned %#x.\n", (unsigned int)status );
        if (status) return status;
    }
}

NTSTATUS WINAPI NtAlpcImpersonateClientOfPort( HANDLE port_handle, ALPC_PORT_MESSAGE *msg, void *reserved )
{
    NTSTATUS status;

    TRACE( "%p, %p, %p.\n", port_handle, msg, reserved );
    if (!msg) return STATUS_INVALID_PARAMETER;
    if (reserved) FIXME( "reserved argument %p is ignored.\n", reserved );
    SERVER_START_REQ( alpc_impersonate_client )
    {
        req->handle = wine_server_obj_handle( port_handle );
        req->message_id = msg->MessageId;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}
