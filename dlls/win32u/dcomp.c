/*
 * DirectComposition system calls
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

#include "config.h"

#include <pthread.h>
#include <string.h>

#include "ntstatus.h"
#include "win32u_private.h"
#include "wine/server.h"

WINE_DEFAULT_DEBUG_CHANNEL(dcomp);

C_ASSERT( sizeof(struct dcomposition_frame_statistics) == 40 );
C_ASSERT( sizeof(struct dcomposition_capability_info) == 20 );
C_ASSERT( sizeof(struct dcomposition_connection_batch) == 40 );
C_ASSERT( offsetof(struct dcomposition_connection_batch, next) == 8 );
C_ASSERT( offsetof(struct dcomposition_connection_batch, u.create.channel) == 16 );
C_ASSERT( offsetof(struct dcomposition_connection_batch, u.create.connection) == 24 );
C_ASSERT( offsetof(struct dcomposition_connection_batch, u.create.object) == 32 );

struct dcomp_channel_view
{
    struct list entry;
    UINT channel;
    void *address;
    SIZE_T size;
};

struct dcomp_connection_batch_view
{
    struct list entry;
    HANDLE connection;
    struct dcomposition_connection_batch *batch;
};

static pthread_mutex_t dcomp_channel_lock = PTHREAD_MUTEX_INITIALIZER;
static struct list dcomp_channel_views = LIST_INIT( dcomp_channel_views );
static struct list dcomp_connection_batch_views = LIST_INIT( dcomp_connection_batch_views );

static struct dcomp_channel_view *find_dcomp_channel_view( UINT channel )
{
    struct dcomp_channel_view *view;

    LIST_FOR_EACH_ENTRY( view, &dcomp_channel_views, struct dcomp_channel_view, entry )
        if (view->channel == channel) return view;
    return NULL;
}

static struct dcomp_connection_batch_view *find_dcomp_connection_batch_view( HANDLE connection )
{
    struct dcomp_connection_batch_view *view;

    LIST_FOR_EACH_ENTRY( view, &dcomp_connection_batch_views, struct dcomp_connection_batch_view, entry )
        if (view->connection == connection) return view;
    return NULL;
}

static UINT get_composition_refresh_rate(void)
{
    DEVMODEW mode = {0};

    mode.dmSize = sizeof(mode);
    if (NtUserEnumDisplaySettings( NULL, ENUM_CURRENT_SETTINGS, &mode, 0 ) &&
        (mode.dmFields & DM_DISPLAYFREQUENCY) && mode.dmDisplayFrequency > 1)
        return mode.dmDisplayFrequency;

    WARN( "Failed to query the primary display refresh rate, using 60 Hz.\n" );
    return 60;
}

NTSTATUS WINAPI NtDCompositionCreateConnection( BOOL is_dwm, HANDLE event, HANDLE *connection )
{
    NTSTATUS status;

    TRACE( "is_dwm %u, event %p, connection %p\n", is_dwm, event, connection );

    if (!connection) return STATUS_INVALID_PARAMETER;
    *connection = NULL;

    SERVER_START_REQ( create_dcomp_connection )
    {
        req->is_dwm = is_dwm;
        req->event = wine_server_obj_handle( event );
        status = wine_server_call( req );
        if (!status) *connection = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return status;
}

NTSTATUS WINAPI NtDCompositionDestroyConnection( HANDLE connection )
{
    struct dcomp_connection_batch_view *view;
    NTSTATUS status;

    TRACE( "connection %p\n", connection );

    SERVER_START_REQ( destroy_dcomp_connection )
    {
        req->handle = wine_server_obj_handle( connection );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    if (!status)
    {
        pthread_mutex_lock( &dcomp_channel_lock );
        view = find_dcomp_connection_batch_view( connection );
        if (view) list_remove( &view->entry );
        pthread_mutex_unlock( &dcomp_channel_lock );
        if (view)
        {
            free( view->batch );
            free( view );
        }
    }
    return status;
}

NTSTATUS WINAPI NtDCompositionCreateChannel( UINT *channel, UINT *section_size,
                                              void **mapped_address, UINT flags )
{
    struct dcomp_channel_view *view;
    HANDLE section = NULL;
    SIZE_T view_size;
    UINT requested_size;
    NTSTATUS status;
    UINT id = 0;
    void *address = NULL;

    TRACE( "channel %p, section_size %p, mapped_address %p, flags %#x\n",
           channel, section_size, mapped_address, flags );

    if (!channel || !section_size || !mapped_address) return STATUS_INVALID_PARAMETER;
    requested_size = *section_size;
    *channel = 0;
    *mapped_address = NULL;

    SERVER_START_REQ( create_dcomp_channel )
    {
        req->size = requested_size;
        req->flags = flags;
        status = wine_server_call( req );
        if (!status)
        {
            id = reply->channel;
            section = wine_server_ptr_handle( reply->section );
            view_size = reply->size;
        }
    }
    SERVER_END_REQ;
    if (status) return status;

    status = NtMapViewOfSection( section, GetCurrentProcess(), &address, 0, 0, NULL, &view_size,
                                 ViewUnmap, 0, PAGE_READWRITE );
    NtClose( section );
    if (status) goto failed;

    if (!(view = calloc( 1, sizeof(*view) )))
    {
        status = STATUS_NO_MEMORY;
        NtUnmapViewOfSection( GetCurrentProcess(), address );
        goto failed;
    }
    view->channel = id;
    view->address = address;
    view->size = view_size;
    pthread_mutex_lock( &dcomp_channel_lock );
    list_add_tail( &dcomp_channel_views, &view->entry );
    pthread_mutex_unlock( &dcomp_channel_lock );

    *channel = id;
    *section_size = view_size;
    *mapped_address = address;
    return STATUS_SUCCESS;

failed:
    SERVER_START_REQ( destroy_dcomp_channel )
    {
        req->channel = id;
        wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}

NTSTATUS WINAPI NtDCompositionDestroyChannel( UINT channel )
{
    struct dcomp_channel_view *view;
    NTSTATUS status;

    TRACE( "channel %#x\n", channel );

    SERVER_START_REQ( destroy_dcomp_channel )
    {
        req->channel = channel;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    if (status) return status;

    pthread_mutex_lock( &dcomp_channel_lock );
    view = find_dcomp_channel_view( channel );
    if (view) list_remove( &view->entry );
    pthread_mutex_unlock( &dcomp_channel_lock );
    if (view)
    {
        NtUnmapViewOfSection( GetCurrentProcess(), view->address );
        free( view );
    }
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI NtDCompositionGetBatchId( UINT channel, UINT selector, UINT *batch_id )
{
    NTSTATUS status;

    TRACE( "channel %#x, selector %u, batch_id %p\n", channel, selector, batch_id );

    if (!batch_id) return STATUS_INVALID_PARAMETER;
    SERVER_START_REQ( get_dcomp_channel_batch_id )
    {
        req->channel = channel;
        req->selector = selector;
        status = wine_server_call( req );
        if (!status) *batch_id = reply->batch_id;
    }
    SERVER_END_REQ;
    return status;
}

NTSTATUS WINAPI NtDCompositionSetChannelConnectionId( UINT channel, INT connection_id, UINT64 connection )
{
    NTSTATUS status;

    TRACE( "channel %#x, connection_id %d, connection %#llx\n",
           channel, connection_id, (unsigned long long)connection );
    SERVER_START_REQ( set_dcomp_channel_connection )
    {
        req->channel = channel;
        req->connection_id = connection_id;
        req->connection = connection;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}

NTSTATUS WINAPI NtDCompositionGetConnectionBatch( HANDLE connection, UINT64 *batch_id,
                                                    struct dcomposition_connection_batch **batch )
{
    struct dcomp_connection_batch_view *view;
    struct dcomposition_connection_batch *record = NULL;
    BYTE *data;
    data_size_t size = 0;
    NTSTATUS status;
    const data_size_t capacity = 0x10000;

    TRACE( "connection %p, batch_id %p, batch %p\n", connection, batch_id, batch );

    if (!batch_id || !batch) return STATUS_INVALID_PARAMETER;
    *batch = NULL;
    if (!(data = malloc( capacity ))) return STATUS_NO_MEMORY;

    pthread_mutex_lock( &dcomp_channel_lock );
    view = find_dcomp_connection_batch_view( connection );
    if (view)
    {
        free( view->batch );
        view->batch = NULL;
    }
    SERVER_START_REQ( get_dcomp_connection_batch )
    {
        req->connection = wine_server_obj_handle( connection );
        wine_server_set_reply( req, data, capacity );
        status = wine_server_call( req );
        if (!status && reply->type)
        {
            size = wine_server_reply_size( reply );
            if (reply->type == 7 && size != reply->value) status = STATUS_INVALID_PARAMETER;
            else if ((record = calloc( 1, sizeof(*record) + size )))
            {
                record->type = reply->type;
                if (reply->type == 5)
                {
                    record->u.create.channel = reply->channel;
                    record->u.create.flags = reply->value;
                    record->u.create.connection = reply->connection;
                    record->u.create.object = wine_server_get_ptr( reply->object );
                }
                else if (reply->type == 6) record->u.close.channel = reply->channel;
                else if (reply->type == 7)
                {
                    record->u.batch.channel = reply->channel;
                    record->u.batch.size = reply->value;
                    record->u.batch.data = (BYTE *)(record + 1);
                    memcpy( record->u.batch.data, data, size );
                }
                else
                {
                    free( record );
                    record = NULL;
                    status = STATUS_INVALID_PARAMETER;
                }
            }
            else status = STATUS_NO_MEMORY;
        }
    }
    SERVER_END_REQ;
    free( data );

    if (!status && record)
    {
        if (!view)
        {
            if (!(view = calloc( 1, sizeof(*view) )))
            {
                free( record );
                record = NULL;
                status = STATUS_NO_MEMORY;
            }
            else
            {
                view->connection = connection;
                list_add_tail( &dcomp_connection_batch_views, &view->entry );
            }
        }
        if (view) view->batch = record;
    }
    pthread_mutex_unlock( &dcomp_channel_lock );
    if (!status) *batch = record;
    return status;
}

NTSTATUS WINAPI NtDCompositionCommitChannel( UINT channel, UINT *batch_id, BYTE *buffer,
                                              ULONG length, HANDLE resource,
                                              const void *resource_data, const UINT *resources,
                                              UINT resource_count )
{
    struct dcomp_channel_view *view;
    NTSTATUS status;

    TRACE( "channel %#x, batch_id %p, buffer %p, length %u, resource %p, resource_data %p, "
           "resources %p, resource_count %u\n", channel, batch_id, buffer, length, resource,
           resource_data, resources, resource_count );

    if (!batch_id) return STATUS_INVALID_PARAMETER;
    if (resource || resource_data || resources || resource_count) return STATUS_NOT_SUPPORTED;

    pthread_mutex_lock( &dcomp_channel_lock );
    view = find_dcomp_channel_view( channel );
    if (!view)
    {
        pthread_mutex_unlock( &dcomp_channel_lock );
        return STATUS_ACCESS_DENIED;
    }
    if (buffer != view->address || length > view->size)
    {
        pthread_mutex_unlock( &dcomp_channel_lock );
        return STATUS_INVALID_PARAMETER;
    }

    SERVER_START_REQ( commit_dcomp_channel )
    {
        req->channel = channel;
        req->length = length;
        wine_server_add_data( req, buffer, length );
        status = wine_server_call( req );
        if (!status) *batch_id = reply->batch_id;
    }
    SERVER_END_REQ;
    pthread_mutex_unlock( &dcomp_channel_lock );
    return status;
}

NTSTATUS WINAPI NtDCompositionGetFrameStatistics( struct dcomposition_frame_statistics *statistics,
                                                   struct dcomposition_capability_info *capabilities )
{
    LARGE_INTEGER current, frequency;
    LONGLONG period, last_frame, next_frame;
    DWORD last_error;
    UINT refresh_rate;

    TRACE( "statistics %p, capabilities %p\n", statistics, capabilities );

    if (!statistics) return STATUS_INVALID_PARAMETER;

    NtQueryPerformanceCounter( &current, &frequency );
    last_error = RtlGetLastWin32Error();
    refresh_rate = get_composition_refresh_rate();
    RtlSetLastWin32Error( last_error );
    period = frequency.QuadPart / refresh_rate;
    if (period < 1) period = 1;
    last_frame = current.QuadPart - current.QuadPart % period;
    next_frame = last_frame + period;

    statistics->last_frame_time.QuadPart = last_frame;
    statistics->current_composition_rate.numerator = refresh_rate;
    statistics->current_composition_rate.denominator = 1;
    statistics->current_time = current;
    statistics->time_frequency = frequency;
    statistics->next_estimated_frame_time.QuadPart = next_frame;

    /* These fields describe compositor/device capabilities rather than clock state.
     * Leave unsupported capabilities disabled until their backing paths exist. */
    if (capabilities) memset( capabilities, 0, sizeof(*capabilities) );

    return STATUS_SUCCESS;
}

NTSTATUS WINAPI NtTokenManagerOpenSectionAndEvents( HANDLE *section, SIZE_T *section_size,
                                                     HANDLE *event_a, HANDLE *event_b )
{
    NTSTATUS status;

    TRACE( "section %p, section_size %p, event_a %p, event_b %p\n",
           section, section_size, event_a, event_b );

    if (!section || !section_size || !event_a || !event_b) return STATUS_INVALID_PARAMETER;
    *section = INVALID_HANDLE_VALUE;
    *section_size = 0;
    *event_a = INVALID_HANDLE_VALUE;
    *event_b = INVALID_HANDLE_VALUE;

    SERVER_START_REQ( open_token_manager )
    {
        status = wine_server_call( req );
        if (!status)
        {
            *section = wine_server_ptr_handle( reply->section );
            *section_size = reply->section_size;
            *event_a = wine_server_ptr_handle( reply->event_a );
            *event_b = wine_server_ptr_handle( reply->event_b );
        }
    }
    SERVER_END_REQ;
    return status;
}
