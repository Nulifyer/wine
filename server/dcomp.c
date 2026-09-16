/*
 * Server-side DirectComposition connection management
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

#include "config.h"

#include <assert.h>
#include <stdio.h>

#include "ntstatus.h"
#include "windef.h"
#include "winternl.h"

#include "handle.h"
#include "file.h"
#include "object.h"
#include "process.h"
#include "request.h"

#define TOKEN_MANAGER_SECTION_SIZE 0x10000
#define DCOMP_CHANNEL_MAX_SIZE 0x1000000

struct dcomp_connection
{
    struct object obj;
    struct list entry;
    struct list records;
    struct process *owner;
    struct event *work_event;
    int is_dwm;
};

struct token_manager
{
    struct list entry;
    unsigned int session_id;
    struct mapping *section;
    struct event *event_a;
    struct event *event_b;
};

struct dcomp_batch
{
    struct list entry;
    unsigned int id;
    data_size_t size;
    void *data;
};

enum dcomp_record_type
{
    DCOMP_RECORD_CREATE = 5,
    DCOMP_RECORD_CLOSE = 6,
    DCOMP_RECORD_BATCH = 7,
};

struct dcomp_record
{
    struct list entry;
    unsigned int type;
    unsigned int channel;
    unsigned int value;
    unsigned __int64 connection;
    unsigned __int64 object;
    data_size_t size;
    void *data;
};

struct dcomp_channel
{
    struct object obj;
    struct list entry;
    struct mapping *section;
    struct list batches;
    struct process *owner;
    struct dcomp_connection *connection;
    obj_handle_t owner_handle;
    unsigned int id;
    int connection_id;
    mem_size_t size;
    unsigned int flags;
    unsigned int batch_ids[4];
};

static struct list dcomp_connections = LIST_INIT( dcomp_connections );
static struct list dcomp_channels = LIST_INIT( dcomp_channels );
static struct list token_managers = LIST_INIT( token_managers );
static unsigned int next_dcomp_channel_id = 1;

static void dcomp_connection_dump( struct object *obj, int verbose );
static void dcomp_connection_destroy( struct object *obj );
static void dcomp_channel_dump( struct object *obj, int verbose );
static void dcomp_channel_destroy( struct object *obj );

static const struct object_ops dcomp_connection_ops =
{
    .size    = sizeof(struct dcomp_connection),
    .type    = &no_type,
    .dump    = dcomp_connection_dump,
    .destroy = dcomp_connection_destroy,
};

static const struct object_ops dcomp_channel_ops =
{
    .size    = sizeof(struct dcomp_channel),
    .type    = &no_type,
    .dump    = dcomp_channel_dump,
    .destroy = dcomp_channel_destroy,
};

static void dcomp_connection_dump( struct object *obj, int verbose )
{
    struct dcomp_connection *connection = (struct dcomp_connection *)obj;

    assert( obj->ops == &dcomp_connection_ops );
    fprintf( stderr, "DirectComposition connection is_dwm=%u work_event=%p\n",
             connection->is_dwm, connection->work_event );
}

static void dcomp_channel_dump( struct object *obj, int verbose )
{
    struct dcomp_channel *channel = (struct dcomp_channel *)obj;

    assert( obj->ops == &dcomp_channel_ops );
    fprintf( stderr, "DirectComposition channel id=%#x connection_id=%d size=%llu flags=%#x next_batch=%u\n",
             channel->id, channel->connection_id, (unsigned long long)channel->size,
             channel->flags, channel->batch_ids[0] );
}

static void dcomp_channel_destroy( struct object *obj )
{
    struct dcomp_channel *channel = (struct dcomp_channel *)obj;
    struct dcomp_batch *batch, *next;

    assert( obj->ops == &dcomp_channel_ops );
    if (channel->connection)
    {
        struct dcomp_record *record;

        if ((record = mem_alloc( sizeof(*record) )))
        {
            record->type = DCOMP_RECORD_CLOSE;
            record->channel = channel->id;
            record->value = 0;
            record->connection = 0;
            record->object = 0;
            record->size = 0;
            record->data = NULL;
            list_add_tail( &channel->connection->records, &record->entry );
            set_event( channel->connection->work_event );
        }
        release_object( channel->connection );
    }
    LIST_FOR_EACH_ENTRY_SAFE( batch, next, &channel->batches, struct dcomp_batch, entry )
    {
        list_remove( &batch->entry );
        free( batch->data );
        free( batch );
    }
    list_remove( &channel->entry );
    release_object( channel->owner );
    release_object( channel->section );
}

static struct dcomp_channel *get_dcomp_channel( unsigned int id )
{
    struct dcomp_channel *channel;

    LIST_FOR_EACH_ENTRY( channel, &dcomp_channels, struct dcomp_channel, entry )
        if (channel->id == id && channel->owner == current->process)
            return (struct dcomp_channel *)grab_object( channel );
    set_error( STATUS_ACCESS_DENIED );
    return NULL;
}

static int dcomp_channel_id_exists( unsigned int id )
{
    struct dcomp_channel *channel;

    LIST_FOR_EACH_ENTRY( channel, &dcomp_channels, struct dcomp_channel, entry )
        if (channel->id == id) return 1;
    return 0;
}

static unsigned int alloc_dcomp_channel_id(void)
{
    unsigned int id, attempts;

    for (attempts = 0; attempts < 0xffff; ++attempts)
    {
        if (!(id = next_dcomp_channel_id++) || id >= 0x10000)
        {
            next_dcomp_channel_id = 2;
            id = 1;
        }
        if (!dcomp_channel_id_exists( id )) return id;
    }
    set_error( STATUS_NO_MEMORY );
    return 0;
}

static struct dcomp_connection *find_dwm_connection( unsigned int session_id )
{
    struct dcomp_connection *connection;

    LIST_FOR_EACH_ENTRY( connection, &dcomp_connections, struct dcomp_connection, entry )
        if (connection->owner->session_id == session_id && connection->is_dwm) return connection;
    return NULL;
}

static int queue_dcomp_record( struct dcomp_connection *connection, unsigned int type,
                               unsigned int channel, unsigned int value,
                               unsigned __int64 connection_id, unsigned __int64 object,
                               const void *data, data_size_t size )
{
    struct dcomp_record *record;

    if (!(record = mem_alloc( sizeof(*record) ))) return 0;
    record->data = NULL;
    if (size && !(record->data = memdup( data, size )))
    {
        free( record );
        return 0;
    }
    record->type = type;
    record->channel = channel;
    record->value = value;
    record->connection = connection_id;
    record->object = object;
    record->size = size;
    list_add_tail( &connection->records, &record->entry );
    set_event( connection->work_event );
    return 1;
}

static int session_has_dwm_connection( unsigned int session_id )
{
    struct dcomp_connection *connection;

    LIST_FOR_EACH_ENTRY( connection, &dcomp_connections, struct dcomp_connection, entry )
        if (connection->owner->session_id == session_id && connection->is_dwm) return 1;
    return 0;
}

static void release_token_manager( unsigned int session_id )
{
    struct token_manager *manager;

    LIST_FOR_EACH_ENTRY( manager, &token_managers, struct token_manager, entry )
    {
        if (manager->session_id != session_id) continue;
        list_remove( &manager->entry );
        release_object( manager->event_b );
        release_object( manager->event_a );
        release_object( manager->section );
        free( manager );
        return;
    }
}

static void dcomp_connection_destroy( struct object *obj )
{
    struct dcomp_connection *connection = (struct dcomp_connection *)obj;
    struct dcomp_record *record, *next;
    unsigned int session_id;

    assert( obj->ops == &dcomp_connection_ops );
    LIST_FOR_EACH_ENTRY_SAFE( record, next, &connection->records, struct dcomp_record, entry )
    {
        list_remove( &record->entry );
        free( record->data );
        free( record );
    }
    session_id = connection->owner->session_id;
    list_remove( &connection->entry );
    release_object( connection->owner );
    if (connection->work_event) release_object( connection->work_event );
    if (connection->is_dwm && !session_has_dwm_connection( session_id )) release_token_manager( session_id );
}

static int process_has_dwm_connection( const struct process *process )
{
    struct dcomp_connection *connection;

    LIST_FOR_EACH_ENTRY( connection, &dcomp_connections, struct dcomp_connection, entry )
        if (connection->owner == process && connection->is_dwm) return 1;
    return 0;
}

static struct token_manager *get_token_manager( unsigned int session_id )
{
    struct token_manager *manager;

    LIST_FOR_EACH_ENTRY( manager, &token_managers, struct token_manager, entry )
        if (manager->session_id == session_id) return manager;

    if (!(manager = mem_alloc( sizeof(*manager) ))) return NULL;
    manager->session_id = session_id;
    manager->section = NULL;
    manager->event_a = NULL;
    manager->event_b = NULL;
    if (!(manager->section = create_anonymous_mapping( TOKEN_MANAGER_SECTION_SIZE,
                                                       FILE_READ_DATA | FILE_WRITE_DATA )) ||
        !(manager->event_a = create_event( NULL, empty_str, 0, 0, 0, NULL )) ||
        !(manager->event_b = create_event( NULL, empty_str, 0, 0, 0, NULL )))
    {
        if (manager->event_b) release_object( manager->event_b );
        if (manager->event_a) release_object( manager->event_a );
        if (manager->section) release_object( manager->section );
        free( manager );
        return NULL;
    }
    list_add_tail( &token_managers, &manager->entry );
    return manager;
}

DECL_HANDLER(create_dcomp_connection)
{
    struct dcomp_connection *connection;
    struct event *event;

    if (!(event = get_event_obj( current->process, req->event, SYNCHRONIZE ))) return;
    if (!(connection = alloc_object( &dcomp_connection_ops )))
    {
        release_object( event );
        return;
    }

    connection->work_event = event;
    connection->owner = (struct process *)grab_object( current->process );
    connection->is_dwm = !!req->is_dwm;
    list_init( &connection->records );
    list_add_tail( &dcomp_connections, &connection->entry );
    reply->handle = alloc_handle_no_access_check( current->process, connection, 0, 0 );
    release_object( connection );
}

DECL_HANDLER(destroy_dcomp_connection)
{
    struct dcomp_connection *connection;
    unsigned int status;

    if (!(connection = (struct dcomp_connection *)get_handle_obj( current->process, req->handle,
                                                                  0, &dcomp_connection_ops ))) return;
    status = close_handle( current->process, req->handle );
    release_object( connection );
    set_error( status );
}

DECL_HANDLER(open_token_manager)
{
    struct token_manager *manager;

    if (!process_has_dwm_connection( current->process ))
    {
        set_error( STATUS_ACCESS_DENIED );
        return;
    }
    if (!(manager = get_token_manager( current->process->session_id ))) return;

    if (!(reply->section = alloc_handle_no_access_check( current->process, manager->section,
                                                         SECTION_QUERY | SECTION_MAP_READ, 0 ))) return;
    if (!(reply->event_a = alloc_handle_no_access_check( current->process, manager->event_a,
                                                         EVENT_ALL_ACCESS, 0 )))
        goto failed;
    if (!(reply->event_b = alloc_handle_no_access_check( current->process, manager->event_b,
                                                         EVENT_ALL_ACCESS, 0 )))
        goto failed;
    reply->section_size = TOKEN_MANAGER_SECTION_SIZE;
    return;

failed:
    if (reply->event_a) close_handle( current->process, reply->event_a );
    close_handle( current->process, reply->section );
    reply->section = 0;
    reply->event_a = 0;
}

DECL_HANDLER(create_dcomp_channel)
{
    struct dcomp_channel *channel;
    struct mapping *section;
    unsigned int id;

    if (!req->size || req->size > DCOMP_CHANNEL_MAX_SIZE)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    if (!(id = alloc_dcomp_channel_id())) return;
    if (!(section = create_anonymous_mapping( req->size, FILE_READ_DATA | FILE_WRITE_DATA ))) return;
    if (!(channel = alloc_object( &dcomp_channel_ops )))
    {
        release_object( section );
        return;
    }

    channel->section = section;
    channel->owner = (struct process *)grab_object( current->process );
    channel->connection = NULL;
    channel->owner_handle = 0;
    channel->id = id;
    channel->connection_id = -1;
    channel->size = req->size;
    channel->flags = req->flags;
    channel->batch_ids[0] = 1;
    channel->batch_ids[1] = 0;
    channel->batch_ids[2] = 0;
    channel->batch_ids[3] = 0;
    list_init( &channel->batches );
    list_add_tail( &dcomp_channels, &channel->entry );

    reply->section = alloc_handle_no_access_check( current->process, section,
                                                    SECTION_QUERY | SECTION_MAP_READ | SECTION_MAP_WRITE, 0 );
    if (!reply->section) goto done;
    channel->owner_handle = alloc_handle_no_access_check( current->process, channel, 0, 0 );
    if (!channel->owner_handle)
    {
        close_handle( current->process, reply->section );
        reply->section = 0;
        goto done;
    }
    reply->channel = channel->id;
    reply->size = channel->size;

done:
    release_object( channel );
}

DECL_HANDLER(destroy_dcomp_channel)
{
    struct dcomp_channel *channel;
    obj_handle_t handle;

    if (!(channel = get_dcomp_channel( req->channel ))) return;
    handle = channel->owner_handle;
    release_object( channel );
    if (close_handle( current->process, handle )) set_error( STATUS_ACCESS_DENIED );
}

DECL_HANDLER(set_dcomp_channel_connection)
{
    struct dcomp_connection *connection;
    struct dcomp_channel *channel;
    struct dcomp_batch *batch, *next;

    if (!(channel = get_dcomp_channel( req->channel ))) return;
    if (!(connection = find_dwm_connection( current->process->session_id )))
    {
        set_error( STATUS_ACCESS_DENIED );
        goto done;
    }
    if (channel->connection)
    {
        set_error( STATUS_INVALID_PARAMETER );
        goto done;
    }
    if (!queue_dcomp_record( connection, DCOMP_RECORD_CREATE, channel->id, channel->flags,
                             req->connection, 0, NULL, 0 )) goto done;
    channel->connection = (struct dcomp_connection *)grab_object( connection );
    channel->connection_id = req->connection_id;
    LIST_FOR_EACH_ENTRY_SAFE( batch, next, &channel->batches, struct dcomp_batch, entry )
    {
        if (!queue_dcomp_record( connection, DCOMP_RECORD_BATCH, channel->id, batch->size,
                                 0, 0, batch->data, batch->size )) break;
        list_remove( &batch->entry );
        free( batch->data );
        free( batch );
    }

done:
    release_object( channel );
}

DECL_HANDLER(get_dcomp_connection_batch)
{
    struct dcomp_connection *connection;
    struct dcomp_record *record;

    if (!(connection = (struct dcomp_connection *)get_handle_obj( current->process, req->connection,
                                                                   0, &dcomp_connection_ops ))) return;
    if (!connection->is_dwm)
    {
        set_error( STATUS_ACCESS_DENIED );
        goto done;
    }
    if (list_empty( &connection->records ))
    {
        reset_event( connection->work_event );
        goto done;
    }
    record = LIST_ENTRY( list_head( &connection->records ), struct dcomp_record, entry );
    if (record->size > get_reply_max_size())
    {
        set_error( STATUS_BUFFER_TOO_SMALL );
        goto done;
    }
    if (record->size && !set_reply_data( record->data, record->size )) goto done;
    reply->type = record->type;
    reply->channel = record->channel;
    reply->value = record->value;
    reply->connection = record->connection;
    reply->object = record->object;
    list_remove( &record->entry );
    free( record->data );
    free( record );
    if (list_empty( &connection->records )) reset_event( connection->work_event );
    else set_event( connection->work_event );

done:
    release_object( connection );
}

DECL_HANDLER(release_all_dcomp_resources)
{
    struct dcomp_channel *channel;

    if (!(channel = get_dcomp_channel( req->channel ))) return;
    reply->result = 0;
    release_object( channel );
}

DECL_HANDLER(get_deleted_dcomp_resources)
{
    struct dcomp_channel *channel;

    if (!req->capacity)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    if (!(channel = get_dcomp_channel( req->channel ))) return;
    reply->count = 0;
    release_object( channel );
}

DECL_HANDLER(get_dcomp_channel_batch_id)
{
    struct dcomp_channel *channel;

    if (!(channel = get_dcomp_channel( req->channel ))) return;
    if (req->selector >= ARRAY_SIZE(channel->batch_ids)) set_error( STATUS_INVALID_PARAMETER );
    else reply->batch_id = channel->batch_ids[req->selector];
    release_object( channel );
}

DECL_HANDLER(commit_dcomp_channel)
{
    struct dcomp_channel *channel;
    struct dcomp_batch *batch;
    data_size_t size = get_req_data_size();

    if (!(channel = get_dcomp_channel( req->channel ))) return;
    if (req->length != size || size > channel->size)
    {
        set_error( STATUS_INVALID_PARAMETER );
        goto done;
    }
    if (!(batch = mem_alloc( sizeof(*batch) ))) goto done;
    batch->data = NULL;
    if (size && !(batch->data = memdup( get_req_data(), size )))
    {
        free( batch );
        goto done;
    }
    batch->id = ++channel->batch_ids[0];
    batch->size = size;
    list_add_tail( &channel->batches, &batch->entry );
    reply->batch_id = batch->id;
    if (channel->connection &&
        queue_dcomp_record( channel->connection, DCOMP_RECORD_BATCH, channel->id, size,
                            0, 0, batch->data, batch->size ))
    {
        list_remove( &batch->entry );
        free( batch->data );
        free( batch );
    }

done:
    release_object( channel );
}
