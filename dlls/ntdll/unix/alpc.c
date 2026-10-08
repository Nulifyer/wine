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
#include "wine/alpc.h"

WINE_DEFAULT_DEBUG_CHANNEL(alpc);
WINE_DECLARE_DEBUG_CHANNEL(alpcpayload);

C_ASSERT( sizeof(ALPC_PORT_MESSAGE32) == 24 );
C_ASSERT( offsetof(ALPC_PORT_MESSAGE32, MessageId) == 16 );

static void trace_message_data( const char *direction, HANDLE port_handle,
                                const ALPC_PORT_MESSAGE *message )
{
    const char *data;
    unsigned int offset;

    if (!TRACE_ON(alpcpayload) || !message) return;
    data = (const char *)(message + 1);
    TRACE_(alpcpayload)( "%s port %p id %#x type %#x total %u data %u.\n", direction, port_handle,
                         message->MessageId, message->Type, message->TotalLength, message->DataLength );
    for (offset = 0; offset < message->DataLength; offset += 64)
    {
        unsigned int size = message->DataLength - offset;
        if (size > 64) size = 64;
        TRACE_(alpcpayload)( "%s port %p +%04x %s\n", direction, port_handle, offset,
                             debugstr_an( data + offset, size ) );
    }
}

/* Resource-bearing input attributes remain outside the current contract. */
static NTSTATUS validate_message_attributes( const ALPC_MESSAGE_ATTRIBUTES *send,
                                             const ALPC_MESSAGE_ATTRIBUTES *receive, BOOL accept_metadata )
{
    const ALPC_VIEW_ATTR *view;

    if ((send && (send->AllocatedAttributes & ~ALPC_MESSAGE_ATTRIBUTE_ALL)) ||
        (receive && (receive->AllocatedAttributes & ~ALPC_MESSAGE_ATTRIBUTE_ALL)))
        return STATUS_NOT_IMPLEMENTED;
    if (send && (send->ValidAttributes & ~send->AllocatedAttributes)) return STATUS_INVALID_PARAMETER;
    if (send && (send->ValidAttributes & ~(ALPC_MESSAGE_CONTEXT_ATTRIBUTE |
                                           ALPC_MESSAGE_VIEW_ATTRIBUTE |
                                           ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE |
                                           (accept_metadata ? ALPC_MESSAGE_TOKEN_ATTRIBUTE : 0))))
        return STATUS_NOT_IMPLEMENTED;
    if (send && (send->ValidAttributes & ALPC_MESSAGE_VIEW_ATTRIBUTE))
    {
        view = wine_alpc_get_attribute( send, ALPC_MESSAGE_VIEW_ATTRIBUTE );
        /* An empty view is metadata-only. Resource-bearing views still need
         * cross-process section mapping and lifetime support. */
        if (!view || view->SectionHandle || view->ViewBase || view->ViewSize)
            return STATUS_NOT_IMPLEMENTED;
    }
    return STATUS_SUCCESS;
}

static client_ptr_t get_message_context( const ALPC_MESSAGE_ATTRIBUTES *attributes )
{
    const ALPC_CONTEXT_ATTR *context;
    if (!attributes || !(attributes->ValidAttributes & ALPC_MESSAGE_CONTEXT_ATTRIBUTE)) return 0;
    context = wine_alpc_get_attribute( attributes, ALPC_MESSAGE_CONTEXT_ATTRIBUTE );
    return wine_server_client_ptr( context->MessageContext );
}

/* The payload stays at message + 1. Its token prefix temporarily occupies
 * header bytes rebuilt on success, so waits need no additional heap buffer.
 * No variable reply bytes may be written on a short or failed operation. */
C_ASSERT( sizeof(ALPC_PORT_MESSAGE) >= sizeof(struct token_identity) + sizeof(ULONGLONG) );
static unsigned int receive_attributes( const ALPC_MESSAGE_ATTRIBUTES *attributes )
{
    return attributes ? attributes->AllocatedAttributes &
                        (ALPC_MESSAGE_TOKEN_ATTRIBUTE | ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE) : 0;
}

static data_size_t receipt_size( unsigned int attributes )
{
    data_size_t size = 0;
    if (attributes & ALPC_MESSAGE_TOKEN_ATTRIBUTE) size += sizeof(struct token_identity);
    if (attributes & ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE) size += sizeof(ULONGLONG);
    return size;
}

static void *receive_buffer( ALPC_PORT_MESSAGE *message, unsigned int attributes,
                             void *fallback )
{
    if (!message) return fallback;
    return (char *)(message + 1) - receipt_size( attributes );
}

static data_size_t receive_capacity( ALPC_PORT_MESSAGE *message, SIZE_T capacity, unsigned int attributes )
{
    return (message ? capacity - sizeof(*message) : 0) +
           receipt_size( attributes );
}

/* Admission, ordinary receives, and private waits serialize one result shape.
 * Sequence zero means no message metadata was produced; preserve attributes. */
static void receive_message_info( NTSTATUS status, const struct alpc_message_info *info,
                                  ALPC_PORT_MESSAGE *message, SIZE_T *size, BOOL actual_size,
                                  ALPC_MESSAGE_ATTRIBUTES *attributes, const void *receipt )
{
    ALPC_CONTEXT_ATTR *context;
    struct token_identity identity;
    ALPC_TOKEN_ATTR *token;
    ALPC_WORK_ON_BEHALF_ATTR *work;
    unsigned int requested = receive_attributes( attributes );
    const unsigned char *receipt_bytes = receipt;
    ULONGLONG work_ticket = 0;
    void *work_slot;
    if (status && status != STATUS_BUFFER_TOO_SMALL) return;
    if (message && size && (actual_size || status == STATUS_BUFFER_TOO_SMALL))
        *size = sizeof(*message) + info->size;
    if (!status && (info->attributes_valid & requested & ALPC_MESSAGE_TOKEN_ATTRIBUTE))
        memcpy( &identity, receipt_bytes, sizeof(identity) );
    if (requested & ALPC_MESSAGE_TOKEN_ATTRIBUTE) receipt_bytes += sizeof(identity);
    if (!status && (info->attributes_valid & requested & ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE))
        memcpy( &work_ticket, receipt_bytes, sizeof(work_ticket) );
    if (attributes && info->sequence)
    {
        attributes->ValidAttributes = info->attributes_valid & attributes->AllocatedAttributes;
        if (status) attributes->ValidAttributes &= ~(ALPC_MESSAGE_TOKEN_ATTRIBUTE |
                                                       ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE);
        if (attributes->ValidAttributes & ALPC_MESSAGE_TOKEN_ATTRIBUTE)
        {
            token = wine_alpc_get_attribute( attributes, ALPC_MESSAGE_TOKEN_ATTRIBUTE );
            memcpy( &token->TokenId, &identity.token_id, sizeof(token->TokenId) );
            memcpy( &token->AuthenticationId, &identity.authentication_id, sizeof(token->AuthenticationId) );
            memcpy( &token->ModifiedId, &identity.modified_id, sizeof(token->ModifiedId) );
        }
        if (attributes->ValidAttributes & ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE)
        {
            work = wine_alpc_get_attribute( attributes, ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE );
            work->Ticket = work_ticket;
        }
        else if (!status && (work_slot = wine_alpc_get_receipt_work_slot( attributes )))
            memset( work_slot, 0, sizeof(ULONGLONG) );
        if (attributes->AllocatedAttributes & ALPC_MESSAGE_CONTEXT_ATTRIBUTE)
        {
            context = wine_alpc_get_attribute( attributes, ALPC_MESSAGE_CONTEXT_ATTRIBUTE );
            context->PortContext = wine_server_get_ptr( info->port_context );
            context->MessageContext = wine_server_get_ptr( info->message_context );
            context->Sequence = info->sequence;
            context->MessageId = info->id;
            context->CallbackId = info->callback_id;
        }
    }
    if (message && !status)
    {
        memset( message, 0, sizeof(*message) );
        message->DataLength = info->size;
        message->TotalLength = sizeof(*message) + info->size;
        message->Type = info->type;
        message->MessageId = info->id;
        message->ClientId.UniqueProcess = ULongToHandle( info->pid );
        message->ClientId.UniqueThread = ULongToHandle( info->tid );
        message->ClientViewSize = info->callback_id;
    }
}

NTSTATUS WINAPI NtAlpcAcceptConnectPort( HANDLE *communication_port, HANDLE connection_port,
                                         DWORD flags, OBJECT_ATTRIBUTES *obj_attr,
                                         ALPC_PORT_ATTRIBUTES *port_attr, void *port_context,
                                         ALPC_PORT_MESSAGE *send_msg,
                                         ALPC_MESSAGE_ATTRIBUTES *send_msg_attr, BOOLEAN accept )
{
    NTSTATUS status;
    if (!communication_port || !send_msg) return STATUS_ACCESS_VIOLATION;
    if (flags || (obj_attr && (obj_attr->ObjectName || obj_attr->SecurityDescriptor)))
        return STATUS_NOT_IMPLEMENTED;
    /* Acceptance returns receive-side token metadata. It does not submit a
     * token: the server retains the connecting thread's authoritative token. */
    if ((status = validate_message_attributes( send_msg_attr, NULL, TRUE ))) return status;
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

static NTSTATUS connect_port( HANDLE *port_handle, UNICODE_STRING *port_name,
                              OBJECT_ATTRIBUTES *obj_attr, ALPC_PORT_ATTRIBUTES *port_attr,
                              DWORD flags, PSID required_server_sid,
                              SECURITY_DESCRIPTOR *server_security_requirements,
                              BOOL security_context,
                              ALPC_PORT_MESSAGE *connect_msg, SIZE_T *connect_msg_size,
                              ALPC_MESSAGE_ATTRIBUTES *send_msg_attr,
                              ALPC_MESSAGE_ATTRIBUTES *recv_msg_attr, LARGE_INTEGER *timeout )
{
    HANDLE handle = NULL, wait_handle = NULL;
    NTSTATUS status;
    SIZE_T capacity = connect_msg_size ? *connect_msg_size : 0;
    struct alpc_security_qos qos;
    struct object_attributes *server_objattr = NULL;
    const struct security_descriptor *server_sd = NULL;
    data_size_t server_objattr_size = 0, server_sd_size = 0;
    ULONG sid_size = 0;
    unsigned char receipt[sizeof(struct token_identity) + sizeof(ULONGLONG)];
    unsigned int recv_attributes = receive_attributes( recv_msg_attr );

    if (!port_handle || !port_name) return STATUS_ACCESS_VIOLATION;
    if (flags & ~(ALPC_SYNC_CONNECTION | ALPC_PORTFLG_ALLOW_DUP_OBJECT) || !port_attr ||
        (obj_attr && obj_attr->SecurityDescriptor))
        return STATUS_NOT_IMPLEMENTED;
    if ((status = validate_message_attributes( send_msg_attr, recv_msg_attr, FALSE ))) return status;
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
    if (server_security_requirements)
    {
        OBJECT_ATTRIBUTES attributes = { sizeof(attributes), 0, NULL, 0,
                                         server_security_requirements, NULL };
        if ((status = wine_server_alloc_object_attributes( &attributes, &server_objattr,
                                                            &server_objattr_size ))) return status;
        server_sd_size = server_objattr->sd_len;
        server_sd = (const struct security_descriptor *)(server_objattr + 1);
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
        req->server_sd_size = server_sd_size;
        req->client_flags = (is_wow64() ? 1 : 0) | (security_context ? 2 : 0);
        req->message_context = get_message_context( send_msg_attr );
        qos.impersonation_level = port_attr->SecurityQos.ImpersonationLevel;
        qos.tracking_mode = port_attr->SecurityQos.ContextTrackingMode;
        qos.effective_only = port_attr->SecurityQos.EffectiveOnly;
        wine_server_add_data( req, &qos, sizeof(qos) );
        wine_server_add_data( req, port_name->Buffer, port_name->Length );
        if (sid_size) wine_server_add_data( req, required_server_sid, sid_size );
        if (server_sd_size) wine_server_add_data( req, server_sd, server_sd_size );
        if (connect_msg) wine_server_add_data( req, connect_msg + 1, connect_msg->DataLength );
        status = wine_server_call( req );
        if (!status)
        {
            handle = wine_server_ptr_handle( reply->handle );
            wait_handle = wine_server_ptr_handle( reply->wait_handle );
        }
    }
    SERVER_END_REQ;
    free( server_objattr );
    if (status) return status;
    if (!wait_handle)
    {
        /* Asynchronous admission returns the client handle before acceptance.
         * Its result is delivered through the port's ordinary receive queue. */
        *port_handle = handle;
        return STATUS_SUCCESS;
    }

    /* Exactly one wait owns the caller's timeout. A pending request is canceled
     * by closing the private client handle, with the server also canceling it on thread termination. */
    status = NtWaitForSingleObject( wait_handle, FALSE, timeout );
    if (!status)
    {
        SERVER_START_REQ( alpc_get_connect_result )
        {
            req->handle = wine_server_obj_handle( handle );
            req->receive_attributes = flags & ALPC_SYNC_CONNECTION ? recv_attributes : 0;
            if (flags & ALPC_SYNC_CONNECTION)
                wine_server_set_reply( req, receive_buffer( connect_msg, recv_attributes, &receipt ),
                                        receive_capacity( connect_msg, capacity, recv_attributes ) );
            status = wine_server_call( req );
            if (!status) status = reply->status;
            if (flags & ALPC_SYNC_CONNECTION)
                receive_message_info( status, &reply->info, connect_msg, connect_msg_size, TRUE, recv_msg_attr,
                                      receive_buffer( connect_msg, recv_attributes, &receipt ) );
        }
        SERVER_END_REQ;
    }
    if (status) NtClose( handle );
    else *port_handle = handle;
    return status;
}

NTSTATUS WINAPI NtAlpcConnectPort( HANDLE *port_handle, UNICODE_STRING *port_name,
                                   OBJECT_ATTRIBUTES *obj_attr, ALPC_PORT_ATTRIBUTES *port_attr,
                                   DWORD flags, PSID required_server_sid,
                                   ALPC_PORT_MESSAGE *connect_msg, SIZE_T *connect_msg_size,
                                   ALPC_MESSAGE_ATTRIBUTES *send_msg_attr,
                                   ALPC_MESSAGE_ATTRIBUTES *recv_msg_attr, LARGE_INTEGER *timeout )
{
    NTSTATUS status;

    status = connect_port( port_handle, port_name, obj_attr, port_attr, flags, required_server_sid, NULL, FALSE,
                           connect_msg, connect_msg_size, send_msg_attr, recv_msg_attr, timeout );
    if (port_name && port_name->Buffer && port_name->Length == 8 * sizeof(WCHAR) &&
        port_name->Buffer[0] == '\\' && port_name->Buffer[1] == 'P' && port_name->Buffer[2] == 'd' &&
        port_name->Buffer[3] == 'c' && port_name->Buffer[4] == 'P' && port_name->Buffer[5] == 'o' &&
        port_name->Buffer[6] == 'r' && port_name->Buffer[7] == 't')
        ERR( "linuxnt-pdc-connect name=%s status=%#x handle=%p\n",
             debugstr_wn( port_name->Buffer, port_name->Length / sizeof(WCHAR) ), (unsigned int)status,
             status ? NULL : *port_handle );
    return status;
}

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
    BOOL security_context = FALSE;

    if (!port_handle || !connection_port_attributes) return STATUS_ACCESS_VIOLATION;
    if (connection_port_attributes->Length != sizeof(*connection_port_attributes) ||
        !connection_port_attributes->ObjectName) return STATUS_INVALID_PARAMETER;
    if (client_port_attributes)
    {
        if (client_port_attributes->Length != sizeof(*client_port_attributes)) return STATUS_INVALID_PARAMETER;
        if (client_port_attributes->RootDirectory || client_port_attributes->ObjectName ||
            client_port_attributes->Attributes || client_port_attributes->SecurityDescriptor ||
            client_port_attributes->SecurityQualityOfService) return STATUS_NOT_IMPLEMENTED;
    }
    if (out_message_attributes && out_message_attributes->ValidAttributes == ALPC_MESSAGE_SECURITY_ATTRIBUTE &&
        out_message_attributes->AllocatedAttributes == ALPC_MESSAGE_SECURITY_ATTRIBUTE)
    {
        const ALPC_SECURITY_ATTR *security = wine_alpc_get_attribute( out_message_attributes,
                                                                      ALPC_MESSAGE_SECURITY_ATTRIBUTE );
        if (!security || security->Flags || security->QoS || security->ContextHandle != NtCurrentThread())
            return STATUS_NOT_IMPLEMENTED;
        security_context = TRUE;
        out_message_attributes = NULL;
    }

    lookup_attributes = *connection_port_attributes;
    lookup_attributes.ObjectName = NULL;
    return connect_port( port_handle, connection_port_attributes->ObjectName, &lookup_attributes,
                         port_attributes, flags, NULL, server_security_requirements, security_context, connection_message,
                         buffer_length, out_message_attributes, in_message_attributes, timeout );
}

NTSTATUS WINAPI NtAlpcQueryInformationMessage( HANDLE port_handle, ALPC_PORT_MESSAGE *message,
                                               ALPC_MESSAGE_INFORMATION_CLASS info_class,
                                               void *info, ULONG length, ULONG *return_length )
{
    unsigned char data[SECURITY_MAX_SID_SIZE];
    ULONG required = 0;
    NTSTATUS status;

    TRACE( "%p %p %u %p %u %p\n", port_handle, message, (unsigned int)info_class,
           info, (unsigned int)length, return_length );
    /* The input message probe precedes handle access, including a null message
     * combined with an invalid or zero-access handle. */
    if (!message || (!info && length)) return STATUS_ACCESS_VIOLATION;
    SERVER_START_REQ( alpc_query_message_security )
    {
        req->handle = wine_server_obj_handle( port_handle );
        req->message_id = message->MessageId;
        req->callback_id = message->ClientViewSize;
        req->info_class = info_class;
        req->length = length;
        wine_server_set_reply( req, data, min( length, sizeof(data) ) );
        status = wine_server_call( req );
        required = reply->required;
    }
    SERVER_END_REQ;
    if (!status)
    {
        /* A null full-size output faults without publishing ReturnLength. */
        if (!info) return STATUS_ACCESS_VIOLATION;
        memcpy( info, data, required );
    }
    if ((!status || status == STATUS_BUFFER_TOO_SMALL) && return_length)
        *return_length = required;
    return status;
}

static NTSTATUS open_alpc_sender( HANDLE *output, HANDLE port_handle, ALPC_PORT_MESSAGE *message,
                                  ULONG flags, ACCESS_MASK access, OBJECT_ATTRIBUTES *attributes,
                                  BOOL open_thread )
{
    ALPC_PORT_MESSAGE header = {0};
    OBJECT_ATTRIBUTES attr = {0};
    HANDLE before, handle = NULL;
    NTSTATUS status, capture_status = STATUS_SUCCESS;

    if (NtReadVirtualMemory( GetCurrentProcess(), attributes, &attr, sizeof(attr), NULL ))
        capture_status = STATUS_ACCESS_VIOLATION;
    if (!(flags & 0x40000000) && (flags & ALPC_MSGFLG_WOW64_CALL))
    {
        ALPC_PORT_MESSAGE32 header32;
        if (NtReadVirtualMemory( GetCurrentProcess(), message, &header32, sizeof(header32), NULL ))
            capture_status = STATUS_ACCESS_VIOLATION;
        else
        {
            header.MessageId = header32.MessageId;
            header.ClientViewSize = header32.ClientViewSize;
            header.ClientId.UniqueProcess = ULongToHandle( header32.ClientId.UniqueProcess );
            header.ClientId.UniqueThread = ULongToHandle( header32.ClientId.UniqueThread );
        }
    }
    else if (NtReadVirtualMemory( GetCurrentProcess(), message, &header, sizeof(header), NULL ))
        capture_status = STATUS_ACCESS_VIOLATION;
    /* Validate publication before object allocation. Probe with the original
     * bytes so failures leave native output unchanged. Buffer publication is
     * local and must not depend on remote-process memory access. */
    if (NtReadVirtualMemory( GetCurrentProcess(), output, &before, sizeof(before), NULL ) ||
        virtual_uninterrupted_write_memory( output, &before, sizeof(before) ))
        capture_status = STATUS_ACCESS_VIOLATION;

    SERVER_START_REQ( alpc_open_sender )
    {
        req->handle = wine_server_obj_handle( port_handle );
        req->message_id = header.MessageId;
        req->callback_id = header.ClientViewSize;
        req->sender_pid = HandleToULong( header.ClientId.UniqueProcess );
        req->sender_tid = HandleToULong( header.ClientId.UniqueThread );
        req->access = access;
        req->attributes = attr.Attributes;
        req->open_thread = open_thread;
        req->named = !!attr.ObjectName;
        req->capture_status = capture_status;
        status = wine_server_call( req );
        if (!status) handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    if (!status && virtual_uninterrupted_write_memory( output, &handle, sizeof(handle) ))
    {
        NtClose( handle );
        status = STATUS_ACCESS_VIOLATION;
    }
    return status;
}

NTSTATUS WINAPI NtAlpcOpenSenderProcess( HANDLE *process_handle, HANDLE port_handle,
                                         ALPC_PORT_MESSAGE *message, ULONG flags,
                                         ACCESS_MASK access, OBJECT_ATTRIBUTES *attributes )
{
    return open_alpc_sender( process_handle, port_handle, message, flags, access, attributes, FALSE );
}

NTSTATUS WINAPI NtAlpcOpenSenderThread( HANDLE *thread_handle, HANDLE port_handle,
                                        ALPC_PORT_MESSAGE *message, ULONG flags,
                                        ACCESS_MASK access, OBJECT_ATTRIBUTES *attributes )
{
    return open_alpc_sender( thread_handle, port_handle, message, flags, access, attributes, TRUE );
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
    if (flags & ~1) return STATUS_NOT_SUPPORTED;
    SERVER_START_REQ( alpc_disconnect_port )
    {
        req->handle = wine_server_obj_handle( port_handle );
        req->flags = flags;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}

NTSTATUS WINAPI NtAlpcCancelMessage( HANDLE port_handle, ULONG flags, ALPC_CONTEXT_ATTR *context )
{
    struct alpc_context_attr32
    {
        ULONG port_context;
        ULONG message_context;
        ULONG sequence;
        ULONG message_id;
        ULONG callback_id;
    };
    client_ptr_t message_context;
    ULONG message_id, callback_id;
    NTSTATUS status;

    if (flags & ~0xf) return STATUS_INVALID_PARAMETER;
#ifdef _WIN64
    if (flags & 4)
    {
        const struct alpc_context_attr32 *context32 = (const struct alpc_context_attr32 *)context;
        message_context = context32->message_context;
        message_id = context32->message_id;
        callback_id = context32->callback_id;
    }
    else
#endif
    {
        message_context = wine_server_client_ptr( context->MessageContext );
        message_id = context->MessageId;
        callback_id = context->CallbackId;
    }
    if (!message_id) return STATUS_MESSAGE_NOT_FOUND;

    SERVER_START_REQ( alpc_cancel_message )
    {
        req->handle = wine_server_obj_handle( port_handle );
        req->flags = flags & ~4;
        req->message_context = message_context;
        req->message_id = message_id;
        req->callback_id = callback_id;
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
    SIZE_T capacity = recv_buffer_size ? *recv_buffer_size : 65535;
    NTSTATUS status;
    BOOL packed32 = (flags & ALPC_MSGFLG_WOW64_CALL) && !is_wow64();
    SIZE_T header_size = packed32 ? sizeof(ALPC_PORT_MESSAGE32) : sizeof(*send_msg);
    ULONG message_id = 0;
    HANDLE wait_handle = NULL;
    unsigned char receipt[sizeof(struct token_identity) + sizeof(ULONGLONG)];
    unsigned int recv_attributes = recv_msg ? receive_attributes( recv_msg_attr ) : 0;

    TRACE( "%p, %#x, %p, %p, %p, %p, %p, %p.\n", port_handle, (unsigned int)flags,
           send_msg, send_msg_attr, recv_msg, recv_buffer_size, recv_msg_attr, timeout );
    /* Native RPC adds 0x400000 to ordinary sends and released replies.
     * Plain messages retain the same delivery and continuation semantics;
     * transferred resources still pass the attribute validator below. */
    if (flags & ~(ALPC_MSGFLG_REPLY_MESSAGE | ALPC_MSGFLG_RELEASE_MESSAGE |
                  ALPC_MSGFLG_SYNC_REQUEST | ALPC_MSGFLG_TRACK_PORT_REFERENCES |
                  ALPC_MSGFLG_WOW64_CALL | 0x400000)) return STATUS_NOT_IMPLEMENTED;
    /* The ordinary WoW64 thunk has already widened its message. An explicit
     * x64 WOW64_CALL uses the packed wire header only for this send partition. */
    if (packed32 && recv_msg) return STATUS_NOT_IMPLEMENTED;
    if (send_msg) message_id = packed32 ? ((ALPC_PORT_MESSAGE32 *)send_msg)->MessageId : send_msg->MessageId;
    if ((status = validate_message_attributes( send_msg_attr, recv_msg_attr, FALSE ))) return status;
    /* Native servers combine a reply with a synchronous receive to return the
     * current result and wait for the next request in one call. */
    if ((flags & 0x20000) &&
        (!send_msg || (message_id && !recv_msg) || (flags & 0x10000)))
        return STATUS_INVALID_PARAMETER_2;
    if (recv_msg && capacity < sizeof(*recv_msg)) return STATUS_BUFFER_TOO_SMALL;
    if (capacity > ~(data_size_t)0) return STATUS_INVALID_PARAMETER;
    if (send_msg && (send_msg->TotalLength < header_size + send_msg->DataLength ||
        (!packed32 && send_msg->TotalLength != header_size + send_msg->DataLength)))
        return STATUS_INVALID_PARAMETER;
    if (!packed32) trace_message_data( "send", port_handle, send_msg );

    SERVER_START_REQ( alpc_send_receive )
    {
        req->handle = wine_server_obj_handle( port_handle );
        req->flags = flags;
        req->message_id = message_id;
        req->send = !!send_msg;
        req->receive = !!recv_msg;
        req->receive_attributes = recv_attributes;
        req->wow64 = is_wow64();
        req->send_attributes = send_msg_attr ? send_msg_attr->ValidAttributes : 0;
        req->message_context = get_message_context( send_msg_attr );
        req->no_wait = timeout && !timeout->QuadPart;
        if (send_msg) wine_server_add_data( req, (const char *)send_msg + header_size, send_msg->DataLength );
        if (recv_msg) wine_server_set_reply( req, receive_buffer( recv_msg, recv_attributes, &receipt ),
                                            receive_capacity( recv_msg, capacity, recv_attributes ) );
        status = wine_server_call( req );
        if (status == STATUS_PENDING) wait_handle = wine_server_ptr_handle( reply->wait_handle );
        if (recv_msg)
            receive_message_info( status, &reply->info, recv_msg, recv_buffer_size, FALSE, recv_msg_attr,
                                  receive_buffer( recv_msg, recv_attributes, &receipt ) );
    }
    SERVER_END_REQ;
    if (wait_handle)
    {
        NTSTATUS wait_status = NtWaitForSingleObject( wait_handle, FALSE, timeout );
        SERVER_START_REQ( alpc_get_message_result )
        {
            req->handle = wine_server_obj_handle( wait_handle );
            req->wait_status = wait_status;
            req->receive_attributes = recv_attributes;
            wine_server_set_reply( req, receive_buffer( recv_msg, recv_attributes, &receipt ),
                                    receive_capacity( recv_msg, capacity, recv_attributes ) );
            status = wine_server_call( req );
            receive_message_info( status, &reply->info, recv_msg, recv_buffer_size,
                                  !!(flags & 0x20000), recv_msg_attr,
                                  receive_buffer( recv_msg, recv_attributes, &receipt ) );
        }
        SERVER_END_REQ;
        NtClose( wait_handle );
    }
    if (!status) trace_message_data( "receive", port_handle, recv_msg );
    return status;
}

NTSTATUS WINAPI NtAlpcImpersonateClientOfPort( HANDLE port_handle, ALPC_PORT_MESSAGE *msg, void *reserved )
{
    ALPC_PORT_MESSAGE message;
    NTSTATUS status;

    TRACE( "%p %p %p.\n", port_handle, msg, reserved );
    if (msg && virtual_uninterrupted_read_memory( msg, &message, sizeof(message) ) != sizeof(message))
        return STATUS_ACCESS_VIOLATION;
    if ((ULONG_PTR)reserved & ~0xf) return STATUS_INVALID_PARAMETER;
    SERVER_START_REQ( alpc_impersonate_client )
    {
        req->handle = wine_server_obj_handle( port_handle );
        req->flags = (ULONG_PTR)reserved;
        req->message_present = !!msg;
        req->message_id = msg ? message.MessageId : 0;
        req->callback_id = msg ? message.ClientViewSize : 0;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    TRACE( "status %#x.\n", status );
    return status;
}

NTSTATUS WINAPI NtAlpcSetInformation( HANDLE handle, ULONG class, void *info, ULONG length )
{
    const ALPC_PORT_ASSOCIATE_COMPLETION_PORT *association = info;
    NTSTATUS status;

    if (!handle) return STATUS_INVALID_PARAMETER;
    if (class != 2) return STATUS_NOT_IMPLEMENTED;
    if (length != sizeof(*association)) return STATUS_INFO_LENGTH_MISMATCH;
    if (!association->CompletionPort) return STATUS_INVALID_PARAMETER;
    SERVER_START_REQ( alpc_set_completion )
    {
        req->handle = wine_server_obj_handle( handle );
        req->completion = wine_server_obj_handle( association->CompletionPort );
        req->key = (ULONG_PTR)association->CompletionKey;
        req->lease = 0;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}

NTSTATUS WINAPI NtSetDefaultHardErrorPort( HANDLE handle )
{
    NTSTATUS status;

    SERVER_START_REQ( set_default_hard_error_port )
    {
        req->handle = wine_server_obj_handle( handle );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}
