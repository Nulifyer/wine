/*
 * Server-side Windows Notification Facility states
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

#if 0
#pragma makedep unix
#endif
#include "ntstatus.h"
#include "wine/debug.h"
#include "wine/server.h"
#include "unix_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(wnf);

NTSTATUS WINAPI NtCreateWnfStateName( ULONGLONG *name, ULONG lifetime, ULONG scope,
                                      BOOLEAN persist, const GUID *type, ULONG maximum,
                                      const SECURITY_DESCRIPTOR *sd )
{
    OBJECT_ATTRIBUTES attr;
    struct object_attributes *objattr;
    data_size_t size;
    NTSTATUS status;
    TRACE( "(%p %u %u %u %s %u %p)\n", name, lifetime, scope, persist, debugstr_guid(type), maximum, sd );
    if (!name || !sd) return STATUS_ACCESS_VIOLATION;
    InitializeObjectAttributes( &attr, NULL, 0, NULL, (void *)sd );
    if ((status = wine_server_alloc_object_attributes( &attr, &objattr, &size ))) return status;
    SERVER_START_REQ( create_wnf_state_name )
    {
        req->name_lifetime = lifetime;
        req->data_scope = scope;
        req->persist_data = persist;
        req->maximum_size = maximum;
        req->has_type = !!type;
        if (type)
        {
            memcpy( &req->type_low, type, 8 );
            memcpy( &req->type_high, (const char *)type + 8, 8 );
        }
        wine_server_add_data( req, objattr, size );
        status = wine_server_call( req );
        if (!status) *name = reply->state_name;
    }
    SERVER_END_REQ;
    free( objattr );
    return status;
}

NTSTATUS WINAPI NtDeleteWnfStateName( const ULONGLONG *name )
{
    NTSTATUS status;
    if (!name) return STATUS_ACCESS_VIOLATION;
    SERVER_START_REQ( delete_wnf_state_name )
    {
        req->state_name = *name;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}

NTSTATUS WINAPI NtQueryWnfStateData( const ULONGLONG *name, const GUID *type,
                                    const void *scope, ULONG *stamp, void *buffer, ULONG *size )
{
    char data[4096];
    ULONG total = 0, new_stamp = 0, capacity;
    NTSTATUS status;
    if (!name || !size || !stamp) return STATUS_ACCESS_VIOLATION;
    capacity = *size;
    SERVER_START_REQ( query_wnf_state_data )
    {
        req->state_name = *name;
        req->explicit_scope = !!scope;
        req->session_id = scope ? *(const ULONG *)scope : 0;
        req->has_type = !!type;
        if (type)
        {
            memcpy( &req->type_low, type, 8 );
            memcpy( &req->type_high, (const char *)type + 8, 8 );
        }
        wine_server_set_reply( req, data, sizeof(data) );
        status = wine_server_call( req );
        if (!status) { total = reply->total; new_stamp = reply->change_stamp; }
    }
    SERVER_END_REQ;
    if (status) return status;
    *size = total;
    *stamp = new_stamp;
    if (capacity < total) return STATUS_BUFFER_TOO_SMALL;
    if (total && !buffer) return STATUS_ACCESS_VIOLATION;
    if (total) memcpy( buffer, data, total );
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI NtUpdateWnfStateData( const ULONGLONG *name, const void *buffer, ULONG size,
                                     const GUID *type, const void *scope, ULONG matching, ULONG check )
{
    NTSTATUS status;
    if (!name || (!buffer && size)) return STATUS_ACCESS_VIOLATION;
    if (size > 4096) return STATUS_INVALID_PARAMETER;
    SERVER_START_REQ( update_wnf_state_data )
    {
        req->state_name = *name;
        req->explicit_scope = !!scope;
        req->session_id = scope ? *(const ULONG *)scope : 0;
        req->has_type = !!type;
        req->matching_stamp = matching;
        req->check_stamp = !!check;
        if (type)
        {
            memcpy( &req->type_low, type, 8 );
            memcpy( &req->type_high, (const char *)type + 8, 8 );
        }
        wine_server_add_data( req, buffer, size );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}

NTSTATUS WINAPI NtSubscribeWnfStateChange( const ULONGLONG *name, ULONG stamp,
                                          ULONG events, ULONGLONG *id )
{
    NTSTATUS status;
    if (!name) return STATUS_ACCESS_VIOLATION;
    SERVER_START_REQ( subscribe_wnf_state )
    {
        req->state_name = *name;
        req->change_stamp = stamp;
        req->events = events;
        status = wine_server_call( req );
        if (!status && id) *id = reply->subscription_id;
    }
    SERVER_END_REQ;
    return status;
}
NTSTATUS WINAPI NtUnsubscribeWnfStateChange( const ULONGLONG *name )
{
    NTSTATUS status;
    if (!name) return STATUS_ACCESS_VIOLATION;
    SERVER_START_REQ( unsubscribe_wnf_state )
    {
        req->state_name = *name;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}
NTSTATUS WINAPI NtSetWnfProcessNotificationEvent( HANDLE event )
{
    NTSTATUS status;
    SERVER_START_REQ( set_wnf_process_event )
    {
        req->handle = wine_server_obj_handle( event );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}
NTSTATUS WINAPI NtQueryWnfStateNameInformation( const ULONGLONG *name, ULONG info,
                                               const void *scope, void *buffer, ULONG size )
{
    NTSTATUS status;
    ULONG value;
    if (info > 2) return STATUS_INVALID_INFO_CLASS;
    if (size != sizeof(ULONG)) return STATUS_INVALID_PARAMETER;
    if (!name || !buffer) return STATUS_ACCESS_VIOLATION;
    SERVER_START_REQ( query_wnf_state_info )
    {
        req->state_name = *name;
        req->info_class = info;
        req->explicit_scope = !!scope;
        req->session_id = scope ? *(const ULONG *)scope : 0;
        status = wine_server_call( req );
        value = reply->value;
    }
    SERVER_END_REQ;
    if (!status) memcpy( buffer, &value, sizeof(value) );
    return status;
}
NTSTATUS WINAPI NtGetCompleteWnfStateSubscription( const ULONGLONG *old_name,
                                                  const ULONGLONG *old_id, ULONG events,
                                                  ULONG completion_status,
                                                  WNF_DELIVERY_DESCRIPTOR *descriptor, ULONG size )
{
    WNF_DELIVERY_DESCRIPTOR result = {0};
    char data[4096];
    NTSTATUS status;
    C_ASSERT(sizeof(result) == 48);
    if (!!old_name != !!old_id) return STATUS_INVALID_PARAMETER;
    if (descriptor && size < sizeof(result) + sizeof(data)) return STATUS_BUFFER_TOO_SMALL;
    if (!descriptor && size) return STATUS_ACCESS_VIOLATION;
    SERVER_START_REQ( complete_wnf_subscription )
    {
        req->acknowledge = !!old_name;
        req->state_name = old_name ? *old_name : 0;
        req->subscription_id = old_id ? *old_id : 0;
        req->events = events;
        req->completion_status = completion_status;
        req->retrieve = !!descriptor;
        if (descriptor) wine_server_set_reply( req, data, sizeof(data) );
        status = wine_server_call( req );
        if (!status && descriptor)
        {
            result.SubscriptionId = reply->subscription_id;
            result.StateName = reply->state_name;
            result.ChangeStamp = reply->change_stamp;
            result.EventMask = reply->events;
            result.StateDataSize = wine_server_reply_size( reply );
            result.StateDataOffset = sizeof(result);
            memcpy( &result.TypeId, &reply->type_low, 8 );
            memcpy( (char *)&result.TypeId + 8, &reply->type_high, 8 );
        }
    }
    SERVER_END_REQ;
    if (!status && descriptor)
    {
        memcpy( descriptor, &result, sizeof(result) );
        if (result.StateDataSize) memcpy( descriptor + 1, data, result.StateDataSize );
    }
    return status;
}
