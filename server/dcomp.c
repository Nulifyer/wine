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
#include <stdlib.h>

#include "ntstatus.h"
#include "windef.h"
#include "winternl.h"

#include "handle.h"
#include "file.h"
#include "object.h"
#include "process.h"
#include "request.h"
#include "thread.h"
#include "user.h"
#include "alpc.h"

#define TOKEN_MANAGER_SECTION_SIZE 0x1000
#define DCOMP_CHANNEL_MAX_SIZE 0x1000000
#define DCOMP_PROTOCOL_MAX_SIZE 0x10000

struct dcomp_connection
{
    struct object obj;
    struct list entry;
    struct list records;
    struct process *owner;
    struct event *work_event;
    int is_dwm;
    int is_consumer;
    unsigned __int64 next_frame_id;
    unsigned __int64 current_frame_id;
    unsigned __int64 confirmed_frame_id;
    unsigned __int64 completed_frame_id;
    int frame_active;
};

struct token_manager
{
    struct list entry;
    unsigned int session_id;
    struct mapping *section;
    struct event *event_a;
    struct event *event_b;
    process_id_t worker_pid;
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
    struct list shared_sections;
    struct process *owner;
    struct dcomp_connection *connection;
    struct event *commit_completion_event;
    int commit_completion_internal;
    obj_handle_t owner_handle;
    unsigned int id;
    client_ptr_t connection_ids[2];
    mem_size_t size;
    unsigned int flags;
    unsigned int batch_ids[4];
};

struct dcomp_shared_section
{
    struct list entry;
    struct mapping *mapping;
    unsigned int resource;
    mem_size_t size;
};

struct dcomp_shared_resource
{
    struct object obj;
    struct dcomp_channel *channel;
    unsigned int resource;
    unsigned int type;
};

struct dcomp_surface
{
    struct object obj;
    struct process *owner;
    unsigned int session_id;
    unsigned __int64 binding_id;
    int bound;
};

struct dcomp_surface_update
{
    struct dcomp_surface *surface;
    int left;
    int top;
    int right;
    int bottom;
};

struct dcomp_token
{
    struct object obj;
    struct process *owner;
    struct dcomp_surface_update *updates;
    struct dcomp_surface **surfaces;
    unsigned int session_id;
    unsigned int update_count;
    unsigned int surface_count;
    client_ptr_t connection;
    client_ptr_t device;
};

struct dcomp_window_target
{
    struct object obj;
    struct list entry;
    struct process *owner;
    user_handle_t window;
    unsigned int type;
    int attached;
};

struct dcomp_surface_update_wire
{
    obj_handle_t surface;
    int left;
    int top;
    int right;
    int bottom;
};

static struct list dcomp_connections = LIST_INIT( dcomp_connections );
static struct list dcomp_channels = LIST_INIT( dcomp_channels );
static struct list token_managers = LIST_INIT( token_managers );
static struct list dcomp_window_targets = LIST_INIT( dcomp_window_targets );
static unsigned int next_dcomp_channel_id = 1;
static unsigned __int64 next_dcomp_surface_binding_id = 1;

static void dcomp_connection_dump( struct object *obj, int verbose );
static void dcomp_connection_destroy( struct object *obj );
static void dcomp_channel_dump( struct object *obj, int verbose );
static void dcomp_channel_destroy( struct object *obj );
static void dcomp_surface_dump( struct object *obj, int verbose );
static void dcomp_surface_destroy( struct object *obj );
static void dcomp_shared_resource_dump( struct object *obj, int verbose );
static void dcomp_shared_resource_destroy( struct object *obj );
static void dcomp_token_dump( struct object *obj, int verbose );
static void dcomp_token_destroy( struct object *obj );
static void dcomp_window_target_dump( struct object *obj, int verbose );
static void dcomp_window_target_destroy( struct object *obj );
static int process_has_dcomp_consumer_connection( const struct process *process );

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

static const struct object_ops dcomp_surface_ops =
{
    .size    = sizeof(struct dcomp_surface),
    .type    = &no_type,
    .dump    = dcomp_surface_dump,
    .destroy = dcomp_surface_destroy,
};

static const struct object_ops dcomp_shared_resource_ops =
{
    .size    = sizeof(struct dcomp_shared_resource),
    .type    = &no_type,
    .dump    = dcomp_shared_resource_dump,
    .destroy = dcomp_shared_resource_destroy,
};

static const struct object_ops dcomp_token_ops =
{
    .size    = sizeof(struct dcomp_token),
    .type    = &no_type,
    .dump    = dcomp_token_dump,
    .destroy = dcomp_token_destroy,
};

static const struct object_ops dcomp_window_target_ops =
{
    .size    = sizeof(struct dcomp_window_target),
    .type    = &no_type,
    .dump    = dcomp_window_target_dump,
    .destroy = dcomp_window_target_destroy,
};

static void dcomp_connection_dump( struct object *obj, int verbose )
{
    struct dcomp_connection *connection = (struct dcomp_connection *)obj;

    assert( obj->ops == &dcomp_connection_ops );
    fprintf( stderr, "DirectComposition connection flag=%u consumer=%u work_event=%p\n",
             connection->is_dwm, connection->is_consumer, connection->work_event );
}

static void dcomp_channel_dump( struct object *obj, int verbose )
{
    struct dcomp_channel *channel = (struct dcomp_channel *)obj;

    assert( obj->ops == &dcomp_channel_ops );
    fprintf( stderr, "DirectComposition channel id=%#x connections=%#llx/%#llx completion_event=%p "
             "internal=%u size=%llu flags=%#x next_batch=%u\n",
             channel->id, (unsigned long long)channel->connection_ids[0],
             (unsigned long long)channel->connection_ids[1],
             channel->commit_completion_event, channel->commit_completion_internal,
             (unsigned long long)channel->size,
             channel->flags, channel->batch_ids[0] );
}

static void dcomp_surface_dump( struct object *obj, int verbose )
{
    struct dcomp_surface *surface = (struct dcomp_surface *)obj;

    assert( obj->ops == &dcomp_surface_ops );
    fprintf( stderr, "DirectComposition surface session=%u binding=%llu bound=%u\n",
             surface->session_id, (unsigned long long)surface->binding_id, surface->bound );
}

static void dcomp_shared_resource_dump( struct object *obj, int verbose )
{
    struct dcomp_shared_resource *resource = (struct dcomp_shared_resource *)obj;

    assert( obj->ops == &dcomp_shared_resource_ops );
    fprintf( stderr, "DirectComposition shared resource channel=%#x resource=%#x type=%#x\n",
             resource->channel->id, resource->resource, resource->type );
}

static void dcomp_shared_resource_destroy( struct object *obj )
{
    struct dcomp_shared_resource *resource = (struct dcomp_shared_resource *)obj;

    assert( obj->ops == &dcomp_shared_resource_ops );
    release_object( resource->channel );
}

static void dcomp_surface_destroy( struct object *obj )
{
    struct dcomp_surface *surface = (struct dcomp_surface *)obj;

    assert( obj->ops == &dcomp_surface_ops );
    release_object( surface->owner );
}

static void dcomp_token_dump( struct object *obj, int verbose )
{
    struct dcomp_token *token = (struct dcomp_token *)obj;

    assert( obj->ops == &dcomp_token_ops );
    fprintf( stderr, "DirectComposition token session=%u updates=%u surfaces=%u\n",
             token->session_id, token->update_count, token->surface_count );
}

static void dcomp_token_destroy( struct object *obj )
{
    struct dcomp_token *token = (struct dcomp_token *)obj;
    unsigned int i;

    assert( obj->ops == &dcomp_token_ops );
    for (i = 0; i < token->update_count; ++i)
        release_object( token->updates[i].surface );
    free( token->surfaces );
    free( token->updates );
    release_object( token->owner );
}

static void dcomp_window_target_dump( struct object *obj, int verbose )
{
    struct dcomp_window_target *target = (struct dcomp_window_target *)obj;

    assert( obj->ops == &dcomp_window_target_ops );
    fprintf( stderr, "DirectComposition HWND target window=%#x type=%u attached=%u\n",
             target->window, target->type, target->attached );
}

static void dcomp_window_target_destroy( struct object *obj )
{
    struct dcomp_window_target *target = (struct dcomp_window_target *)obj;

    assert( obj->ops == &dcomp_window_target_ops );
    assert( !target->attached );
    release_object( target->owner );
}

static struct dcomp_window_target *find_dcomp_window_target( struct process *owner,
                                                              user_handle_t window,
                                                              unsigned int type )
{
    struct dcomp_window_target *target;

    LIST_FOR_EACH_ENTRY( target, &dcomp_window_targets, struct dcomp_window_target, entry )
        if (target->owner == owner && target->window == window && target->type == type)
            return target;
    return NULL;
}

static void detach_dcomp_window_target( struct dcomp_window_target *target )
{
    assert( target->attached );
    target->attached = 0;
    list_remove( &target->entry );
    release_object( target );
}

void cleanup_dcomp_window_targets( user_handle_t window )
{
    struct dcomp_window_target *target, *next;

    LIST_FOR_EACH_ENTRY_SAFE( target, next, &dcomp_window_targets,
                              struct dcomp_window_target, entry )
        if (target->window == window) detach_dcomp_window_target( target );
}

static void dcomp_channel_destroy( struct object *obj )
{
    struct dcomp_channel *channel = (struct dcomp_channel *)obj;
    struct dcomp_batch *batch, *next;
    struct dcomp_shared_section *section, *section_next;

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
    LIST_FOR_EACH_ENTRY_SAFE( section, section_next, &channel->shared_sections,
                              struct dcomp_shared_section, entry )
    {
        list_remove( &section->entry );
        release_object( section->mapping );
        free( section );
    }
    if (channel->commit_completion_event) release_object( channel->commit_completion_event );
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

static struct dcomp_shared_section *find_dcomp_shared_section( struct dcomp_channel *channel,
                                                               unsigned int resource )
{
    struct dcomp_shared_section *section;

    LIST_FOR_EACH_ENTRY( section, &channel->shared_sections, struct dcomp_shared_section, entry )
        if (section->resource == resource) return section;
    return NULL;
}

static void release_dcomp_shared_section( struct dcomp_shared_section *section )
{
    list_remove( &section->entry );
    release_object( section->mapping );
    free( section );
}

static struct dcomp_channel *find_dcomp_channel( unsigned int id )
{
    struct dcomp_channel *channel;

    LIST_FOR_EACH_ENTRY( channel, &dcomp_channels, struct dcomp_channel, entry )
        if (channel->id == id) return channel;
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

/* The private create flag is not compositor identity: genuine DWM creates its
 * startup connection with FALSE.  Native startup therefore derives authority
 * from the process that registered the session DWM port.  Retain the flag as
 * the regular Wine adapter, whose built-in compositor has no native port. */
static int is_dcomp_consumer_connection( struct dcomp_connection *connection )
{
    if (connection->is_consumer) return 1;
    if (connection->owner->native_dwm_owner || (!is_native_machine() && connection->is_dwm))
        connection->is_consumer = 1;
    return connection->is_consumer;
}

static struct dcomp_connection *find_dcomp_consumer_connection( unsigned int session_id )
{
    struct dcomp_connection *connection;

    LIST_FOR_EACH_ENTRY( connection, &dcomp_connections, struct dcomp_connection, entry )
        if (connection->owner->session_id == session_id && is_dcomp_consumer_connection( connection ))
            return connection;
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

static int attach_internal_dcomp_channel( struct dcomp_channel *channel )
{
    struct dcomp_connection *connection;
    struct dcomp_batch *batch, *next;

    if (!(connection = channel->connection))
    {
        if (!(connection = find_dcomp_consumer_connection( channel->owner->session_id )))
        {
            set_error( STATUS_ACCESS_DENIED );
            return 0;
        }
        if (!queue_dcomp_record( connection, DCOMP_RECORD_CREATE, channel->id, channel->flags,
                                 0, 0, NULL, 0 )) return 0;
        channel->connection = (struct dcomp_connection *)grab_object( connection );
    }
    LIST_FOR_EACH_ENTRY_SAFE( batch, next, &channel->batches, struct dcomp_batch, entry )
    {
        if (!queue_dcomp_record( connection, DCOMP_RECORD_BATCH, channel->id, batch->size,
                                 0, 0, batch->data, batch->size )) return 0;
        list_remove( &batch->entry );
        free( batch->data );
        free( batch );
    }
    return 1;
}

static int session_has_dcomp_consumer_connection( unsigned int session_id )
{
    struct dcomp_connection *connection;

    LIST_FOR_EACH_ENTRY( connection, &dcomp_connections, struct dcomp_connection, entry )
        if (connection->owner->session_id == session_id && is_dcomp_consumer_connection( connection ))
            return 1;
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

static void release_token_manager_worker( unsigned int session_id, process_id_t process_id )
{
    struct token_manager *manager;

    LIST_FOR_EACH_ENTRY( manager, &token_managers, struct token_manager, entry )
    {
        if (manager->session_id != session_id || manager->worker_pid != process_id) continue;
        manager->worker_pid = 0;
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
    if (connection->is_consumer && !process_has_dcomp_consumer_connection( connection->owner ))
        release_token_manager_worker( session_id, connection->owner->id );
    release_object( connection->owner );
    if (connection->work_event) release_object( connection->work_event );
    if (connection->is_consumer && !session_has_dcomp_consumer_connection( session_id ))
        release_token_manager( session_id );
}

static int process_has_dcomp_consumer_connection( const struct process *process )
{
    struct dcomp_connection *connection;

    LIST_FOR_EACH_ENTRY( connection, &dcomp_connections, struct dcomp_connection, entry )
        if (connection->owner == process && is_dcomp_consumer_connection( connection )) return 1;
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
    manager->worker_pid = 0;
    if (!(manager->section = create_anonymous_mapping( TOKEN_MANAGER_SECTION_SIZE,
                                                       FILE_READ_DATA | FILE_WRITE_DATA )) ||
        !(manager->event_a = create_event( NULL, empty_str, 0, 1, 0, NULL )) ||
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
    connection->is_consumer = current->process->native_dwm_owner ||
                              (!is_native_machine() && connection->is_dwm);
    connection->next_frame_id = 1;
    connection->current_frame_id = 0;
    connection->confirmed_frame_id = 0;
    connection->completed_frame_id = 0;
    connection->frame_active = 0;
    if (getenv( "LINUXNT_DEBUG_PROCESS_EXITS" ))
        fprintf( stderr, "linuxnt: server dcomp-connection winpid=%04x session=%u flag=%u consumer=%u\n",
                 current->process->id, current->process->session_id,
                 connection->is_dwm, connection->is_consumer );
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

DECL_HANDLER(begin_dcomp_frame)
{
    struct dcomp_connection *connection;

    if (!(connection = (struct dcomp_connection *)get_handle_obj( current->process, req->connection,
                                                                   0, &dcomp_connection_ops ))) return;
    if (!is_dcomp_consumer_connection( connection )) set_error( STATUS_ACCESS_DENIED );
    else if (connection->frame_active) set_error( STATUS_RESOURCE_IN_USE );
    else
    {
        if (!(reply->frame_id = connection->next_frame_id++))
            reply->frame_id = connection->next_frame_id++;
        connection->current_frame_id = reply->frame_id;
        connection->frame_active = 1;
    }
    release_object( connection );
}

DECL_HANDLER(confirm_dcomp_frame)
{
    struct dcomp_connection *connection;

    if (!(connection = (struct dcomp_connection *)get_handle_obj( current->process, req->connection,
                                                                   0, &dcomp_connection_ops ))) return;
    if (!is_dcomp_consumer_connection( connection )) set_error( STATUS_ACCESS_DENIED );
    else if (!connection->frame_active || connection->current_frame_id != req->frame_id)
        set_error( STATUS_NOT_FOUND );
    else
    {
        connection->confirmed_frame_id = req->frame_id;
        connection->completed_frame_id = req->frame_id;
        connection->frame_active = 0;
    }
    release_object( connection );
}

DECL_HANDLER(discard_dcomp_frame)
{
    struct dcomp_connection *connection;

    if (!(connection = (struct dcomp_connection *)get_handle_obj( current->process, req->connection,
                                                                   0, &dcomp_connection_ops ))) return;
    if (!is_dcomp_consumer_connection( connection )) set_error( STATUS_ACCESS_DENIED );
    else if (!connection->frame_active || connection->current_frame_id != req->frame_id)
        set_error( STATUS_NOT_FOUND );
    else connection->frame_active = 0;
    release_object( connection );
}

static struct dcomp_connection *find_process_dcomp_consumer( struct process *process )
{
    struct dcomp_connection *connection;

    LIST_FOR_EACH_ENTRY( connection, &dcomp_connections, struct dcomp_connection, entry )
    {
        if (connection->owner == process && is_dcomp_consumer_connection( connection )) return connection;
    }
    return NULL;
}

DECL_HANDLER(get_dcomp_frame_id)
{
    struct dcomp_connection *connection;

    if (req->type > 2)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    if ((connection = find_process_dcomp_consumer( current->process )))
    {
        if (!req->type) reply->frame_id = connection->current_frame_id;
        else if (req->type == 1) reply->frame_id = connection->confirmed_frame_id;
        else reply->frame_id = connection->completed_frame_id;
        if (!reply->frame_id) set_error( STATUS_UNSUCCESSFUL );
        return;
    }
    set_error( STATUS_ACCESS_DENIED );
}

DECL_HANDLER(get_dcomp_frame_legacy_tokens)
{
    struct dcomp_connection *connection;

    if (!req->frame_id)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    if ((connection = find_process_dcomp_consumer( current->process )))
    {
        if (connection->current_frame_id != req->frame_id)
        {
            set_error( STATUS_NOT_FOUND );
            return;
        }
        reply->token_count = 0;
        reply->has_more = 0;
        return;
    }
    set_error( STATUS_ACCESS_DENIED );
}

DECL_HANDLER(get_dcomp_frame_surface_updates)
{
    struct dcomp_connection *connection;

    if (!req->frame_id)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    if ((connection = find_process_dcomp_consumer( current->process )))
    {
        if (connection->current_frame_id != req->frame_id)
        {
            set_error( STATUS_NOT_FOUND );
            return;
        }
        reply->update_count = 0;
        reply->has_more = 0;
        return;
    }
    set_error( STATUS_ACCESS_DENIED );
}

DECL_HANDLER(open_token_manager)
{
    struct token_manager *manager;

    if (!process_has_dcomp_consumer_connection( current->process ))
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

DECL_HANDLER(begin_token_manager_thread)
{
    struct token_manager *manager;
    struct event *stop_event;

    if (!req->adapter_count)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    if (!(stop_event = get_event_obj( current->process, req->stop_event, SYNCHRONIZE ))) return;
    release_object( stop_event );
    if (!process_has_dcomp_consumer_connection( current->process ))
    {
        set_error( STATUS_ACCESS_DENIED );
        return;
    }
    if (!(manager = get_token_manager( current->process->session_id ))) return;
    if (manager->worker_pid)
    {
        set_error( STATUS_DEVICE_BUSY );
        return;
    }
    if (!(reply->notification_event = alloc_handle_no_access_check( current->process, manager->event_b,
                                                                     SYNCHRONIZE, 0 ))) return;
    manager->worker_pid = current->process->id;
}

DECL_HANDLER(end_token_manager_thread)
{
    struct token_manager *manager;

    LIST_FOR_EACH_ENTRY( manager, &token_managers, struct token_manager, entry )
    {
        if (manager->session_id != current->process->session_id) continue;
        if (manager->worker_pid != current->process->id)
        {
            set_error( STATUS_ACCESS_DENIED );
            return;
        }
        manager->worker_pid = 0;
        return;
    }
    set_error( STATUS_ACCESS_DENIED );
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
    channel->commit_completion_event = NULL;
    channel->commit_completion_internal = 0;
    channel->owner_handle = 0;
    channel->id = id;
    channel->connection_ids[0] = 0;
    channel->connection_ids[1] = 0;
    channel->size = req->size;
    channel->flags = req->flags;
    channel->batch_ids[0] = 1;
    channel->batch_ids[1] = 0;
    channel->batch_ids[2] = 0;
    channel->batch_ids[3] = 0;
    list_init( &channel->batches );
    list_init( &channel->shared_sections );
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
    unsigned int slot = !!req->connection_id;

    if (!(channel = get_dcomp_channel( req->channel ))) return;
    if (req->connection && channel->connection_ids[slot])
    {
        set_error( STATUS_INVALID_PARAMETER );
        goto done;
    }
    if (!req->connection)
    {
        channel->connection_ids[slot] = 0;
        goto done;
    }
    if (channel->connection)
    {
        channel->connection_ids[slot] = req->connection;
        goto done;
    }
    if (!(connection = find_dcomp_consumer_connection( current->process->session_id )))
    {
        if (getenv( "LINUXNT_DEBUG_PROCESS_EXITS" ))
            fprintf( stderr, "linuxnt: server dcomp-bind winpid=%04x session=%u channel=%#x "
                     "slot=%d connection=%#llx status=%#x\n", current->process->id,
                     current->process->session_id, req->channel, req->connection_id,
                     (unsigned long long)req->connection, STATUS_ACCESS_DENIED );
        set_error( STATUS_ACCESS_DENIED );
        goto done;
    }
    if (!queue_dcomp_record( connection, DCOMP_RECORD_CREATE, channel->id, channel->flags,
                             req->connection, 0, NULL, 0 )) goto done;
    channel->connection = (struct dcomp_connection *)grab_object( connection );
    channel->connection_ids[slot] = req->connection;
    if (getenv( "LINUXNT_DEBUG_PROCESS_EXITS" ))
        fprintf( stderr, "linuxnt: server dcomp-bind winpid=%04x session=%u channel=%#x "
                 "slot=%d connection=%#llx consumer=%04x status=0\n", current->process->id,
                 current->process->session_id, channel->id, slot,
                 (unsigned long long)req->connection, connection->owner->id );
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

DECL_HANDLER(create_dcomp_shared_section)
{
    struct dcomp_shared_section *section;
    struct dcomp_channel *channel;

    reply->section = 0;
    if (!(channel = get_dcomp_channel( req->channel ))) return;
    if (find_dcomp_shared_section( channel, req->resource ))
    {
        set_error( STATUS_INVALID_PARAMETER );
        goto done;
    }
    if (!(section = mem_alloc( sizeof(*section) ))) goto done;
    if (!(section->mapping = create_anonymous_mapping( req->size,
                                                        FILE_READ_DATA | FILE_WRITE_DATA )))
    {
        free( section );
        goto done;
    }
    if (!(reply->section = alloc_handle_no_access_check( current->process, section->mapping,
                                                          SECTION_MAP_READ | SECTION_MAP_WRITE, 0 )))
    {
        release_object( section->mapping );
        free( section );
        goto done;
    }
    section->resource = req->resource;
    section->size = req->size;
    list_add_tail( &channel->shared_sections, &section->entry );

done:
    release_object( channel );
}

DECL_HANDLER(get_dcomp_shared_section_update)
{
    struct dcomp_shared_section *section;
    struct dcomp_channel *channel;

    reply->section = 0;
    reply->size = 0;
    if (!(channel = get_dcomp_channel( req->channel ))) return;
    if (!(section = find_dcomp_shared_section( channel, req->resource )))
    {
        set_error( STATUS_INVALID_PARAMETER );
        goto done;
    }
    reply->size = section->size;
    if (channel->connection)
        reply->section = alloc_handle_no_access_check( channel->connection->owner, section->mapping,
                                                        SECTION_MAP_READ, 0 );

done:
    release_object( channel );
}

DECL_HANDLER(release_dcomp_shared_section)
{
    struct dcomp_shared_section *section;
    struct dcomp_channel *channel;

    if (!(channel = get_dcomp_channel( req->channel ))) return;
    if (!(section = find_dcomp_shared_section( channel, req->resource )))
        set_error( STATUS_INVALID_PARAMETER );
    else
        release_dcomp_shared_section( section );
    release_object( channel );
}

DECL_HANDLER(publish_dcomp_resource)
{
    struct dcomp_shared_resource *resource;
    struct dcomp_channel *channel;

    reply->handle = 0;
    if (!req->resource || !req->type)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    if (!(channel = get_dcomp_channel( req->channel ))) return;
    if (!attach_internal_dcomp_channel( channel )) goto done;
    if (!(resource = alloc_object( &dcomp_shared_resource_ops ))) goto done;
    resource->channel = (struct dcomp_channel *)grab_object( channel );
    resource->resource = req->resource;
    resource->type = req->type;
    reply->handle = alloc_handle_no_access_check( current->process, resource, 0, 0 );
    release_object( resource );

done:
    release_object( channel );
}

DECL_HANDLER(begin_dcomp_resource_duplicate)
{
    struct dcomp_shared_resource *resource;
    struct dcomp_channel *target;
    unsigned int command[4];

    if (!(resource = (struct dcomp_shared_resource *)get_handle_obj( current->process,
            req->handle, 0, &dcomp_shared_resource_ops ))) return;
    if (!(target = get_dcomp_channel( req->channel ))) goto done;
    if (resource->type != req->type ||
        resource->channel->owner->session_id != target->owner->session_id)
    {
        set_error( STATUS_INVALID_PARAMETER );
        goto done_target;
    }
    if (!resource->channel->connection && !attach_internal_dcomp_channel( resource->channel ))
        goto done_target;
    command[0] = sizeof(command);
    command[1] = 0x26; /* MILCMD_CHANNEL_BEGINDUPLICATERESOURCE */
    command[2] = resource->resource;
    command[3] = target->id;
    if (!queue_dcomp_record( resource->channel->connection, DCOMP_RECORD_BATCH,
                             resource->channel->id, sizeof(command), 0, 0,
                             command, sizeof(command) )) goto done_target;

done_target:
    release_object( target );
done:
    release_object( resource );
}

DECL_HANDLER(get_dcomp_connection_batch)
{
    struct dcomp_connection *connection;
    struct dcomp_record *record;

    if (!(connection = (struct dcomp_connection *)get_handle_obj( current->process, req->connection,
                                                                   0, &dcomp_connection_ops ))) return;
    if (!is_dcomp_consumer_connection( connection ))
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
    if (record->type == DCOMP_RECORD_BATCH)
    {
        struct dcomp_channel *channel = find_dcomp_channel( record->channel );

        if (channel && channel->commit_completion_event)
            set_event( channel->commit_completion_event );
    }
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
    if (req->payload_size != size || size > DCOMP_PROTOCOL_MAX_SIZE)
    {
        set_error( STATUS_INVALID_PARAMETER );
        goto done;
    }
    if (req->protocol_blocks && !process_has_dcomp_consumer_connection( current->process ))
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
    reply->state = 0;
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

DECL_HANDLER(set_dcomp_channel_completion_event)
{
    struct dcomp_channel *channel;
    struct event *event;

    if (!(channel = get_dcomp_channel( req->channel ))) return;
    if (channel->commit_completion_event)
    {
        set_error( STATUS_ACCESS_DENIED );
        goto done;
    }
    if (!(event = get_event_obj( current->process, req->event, EVENT_MODIFY_STATE ))) goto done;
    channel->commit_completion_event = event;
    channel->commit_completion_internal = !!req->internal;

done:
    release_object( channel );
}

DECL_HANDLER(initialize_kst)
{
    struct event *stop_event, *update_event;

    if (is_native_machine() && !current->process->native_dwm_owner)
    {
        set_error( STATUS_ACCESS_DENIED );
        return;
    }
    if (!(stop_event = get_event_obj( current->process, req->stop_event, SYNCHRONIZE ))) return;
    if (!(update_event = get_event_obj( current->process, req->update_event, SYNCHRONIZE )))
    {
        release_object( stop_event );
        return;
    }
    if (getenv( "LINUXNT_DEBUG_PROCESS_EXITS" ))
        fprintf( stderr, "linuxnt: server kst-initialize winpid=%04x wintid=%04x session=%u\n",
                 current->process->id, current->id, current->process->session_id );
    release_object( update_event );
    release_object( stop_event );
}

DECL_HANDLER(set_mit_input_callbacks)
{
    if (is_native_machine() && !current->process->native_dwm_owner)
    {
        set_error( STATUS_ACCESS_DENIED );
        return;
    }
    if (!set_coremsg_input_port_ready( current->process, !!req->enabled )) return;
    current->process->mit_input_callbacks = !!req->enabled;
    if (getenv( "LINUXNT_DEBUG_PROCESS_EXITS" ))
        fprintf( stderr, "linuxnt: server mit-input-callbacks winpid=%04x enabled=%u session=%u\n",
                 current->process->id, current->process->mit_input_callbacks,
                 current->process->session_id );
}

DECL_HANDLER(register_manipulation_thread)
{
    if (is_native_machine() && !current->process->native_dwm_owner)
    {
        set_error( STATUS_ACCESS_DENIED );
        return;
    }
    current->manipulation_registered = 1;
    if (getenv( "LINUXNT_DEBUG_PROCESS_EXITS" ))
        fprintf( stderr, "linuxnt: server manipulation-thread winpid=%04x wintid=%04x session=%u\n",
                 current->process->id, current->id, current->process->session_id );
}

DECL_HANDLER(create_dcomp_surface)
{
    struct dcomp_surface *surface;

    if (!(surface = alloc_object( &dcomp_surface_ops ))) return;
    surface->owner = (struct process *)grab_object( current->process );
    surface->session_id = current->process->session_id;
    if (!(surface->binding_id = next_dcomp_surface_binding_id++))
        surface->binding_id = next_dcomp_surface_binding_id++;
    surface->bound = 0;
    reply->handle = alloc_handle_no_access_check( current->process, surface, req->access, 0 );
    release_object( surface );
}

DECL_HANDLER(set_dcomp_surface_bound)
{
    struct dcomp_surface *surface;

    if (!(surface = (struct dcomp_surface *)get_handle_obj( current->process, req->handle,
                                                            0, &dcomp_surface_ops ))) return;
    if (surface->owner != current->process || surface->session_id != current->process->session_id)
        set_error( STATUS_ACCESS_DENIED );
    else
    {
        surface->bound = !!req->bound;
        reply->binding_id = surface->binding_id;
    }
    release_object( surface );
}

DECL_HANDLER(create_dcomp_token)
{
    const struct dcomp_surface_update_wire *wire = get_req_data();
    struct dcomp_token *token = NULL;
    data_size_t size = get_req_data_size();
    unsigned int count, i;

    if (!size || size % sizeof(*wire))
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    count = size / sizeof(*wire);
    if (!(token = alloc_object( &dcomp_token_ops ))) return;
    token->owner = (struct process *)grab_object( current->process );
    token->updates = NULL;
    token->surfaces = NULL;
    token->session_id = current->process->session_id;
    token->update_count = 0;
    token->surface_count = 0;
    token->connection = req->connection;
    token->device = req->device;
    if (!req->surface_count || req->surface_count > count)
    {
        set_error( STATUS_INVALID_PARAMETER );
        goto done;
    }
    if (!(token->updates = mem_alloc( count * sizeof(*token->updates) ))) goto done;
    if (!(token->surfaces = mem_alloc( req->surface_count * sizeof(*token->surfaces) ))) goto done;

    for (i = 0; i < count; ++i)
    {
        struct dcomp_surface *surface;
        unsigned int j;

        if (!(surface = (struct dcomp_surface *)get_handle_obj( current->process, wire[i].surface,
                                                                0, &dcomp_surface_ops ))) goto done;
        if (surface->owner != current->process || surface->session_id != token->session_id ||
            !surface->bound)
        {
            set_error( STATUS_ACCESS_DENIED );
            release_object( surface );
            goto done;
        }
        token->updates[i].surface = surface;
        token->updates[i].left = wire[i].left;
        token->updates[i].top = wire[i].top;
        token->updates[i].right = wire[i].right;
        token->updates[i].bottom = wire[i].bottom;
        token->update_count++;
        for (j = 0; j < token->surface_count; ++j)
            if (token->surfaces[j] == surface) break;
        if (j == token->surface_count)
        {
            if (token->surface_count == req->surface_count)
            {
                set_error( STATUS_INVALID_PARAMETER );
                goto done;
            }
            token->surfaces[token->surface_count++] = surface;
        }
    }
    if (token->surface_count != req->surface_count)
    {
        set_error( STATUS_INVALID_PARAMETER );
        goto done;
    }
    reply->handle = alloc_handle_no_access_check( current->process, token, 0, 0 );

done:
    release_object( token );
}

DECL_HANDLER(present_dcomp_token)
{
    const obj_handle_t *handles = get_req_data();
    struct dcomp_token *token;
    data_size_t size = get_req_data_size();
    unsigned int count, i;

    if (!size || size % sizeof(*handles))
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    count = size / sizeof(*handles);
    if (!(token = (struct dcomp_token *)get_handle_obj( current->process, req->token,
                                                        0, &dcomp_token_ops ))) return;
    if (token->owner != current->process || token->session_id != current->process->session_id)
        set_error( STATUS_ACCESS_DENIED );
    else if (count != token->surface_count)
        set_error( STATUS_INVALID_PARAMETER );
    else for (i = 0; i < count; ++i)
    {
        struct dcomp_surface *surface;

        if (!(surface = (struct dcomp_surface *)get_handle_obj( current->process, handles[i],
                                                                0, &dcomp_surface_ops ))) break;
        if (surface != token->surfaces[i] || !surface->bound)
            set_error( STATUS_INVALID_PARAMETER );
        release_object( surface );
        if (get_error()) break;
    }
    release_object( token );
}

DECL_HANDLER(create_dcomp_window_target)
{
    struct dcomp_window_target *target;
    struct thread *thread;

    if (req->type > 2)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    if (!(thread = get_window_thread( req->window )))
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    if (thread->process != current->process)
    {
        release_object( thread );
        set_error( STATUS_ACCESS_DENIED );
        return;
    }
    release_object( thread );
    if (find_dcomp_window_target( current->process, req->window, req->type ))
    {
        set_error( STATUS_DCOMPOSITION_TARGET_ALREADY_EXISTS );
        return;
    }
    if (!(target = alloc_object( &dcomp_window_target_ops ))) return;
    target->owner = (struct process *)grab_object( current->process );
    target->window = req->window;
    target->type = req->type;
    target->attached = 1;
    list_add_tail( &dcomp_window_targets, &target->entry );
    reply->handle = alloc_handle_no_access_check( current->process, target, 0, 0 );
    if (!reply->handle) detach_dcomp_window_target( target );
    /* The allocation reference owns the HWND attachment. The handle owns its
     * own reference and can close before the target is detached. */
}

DECL_HANDLER(destroy_dcomp_window_target)
{
    struct dcomp_window_target *target;
    struct thread *thread;

    if (req->type > 2)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    if (!(thread = get_window_thread( req->window )))
    {
        set_error( STATUS_UNSUCCESSFUL );
        return;
    }
    if (thread->process != current->process)
    {
        release_object( thread );
        set_error( STATUS_ACCESS_DENIED );
        return;
    }
    release_object( thread );
    if (!(target = find_dcomp_window_target( current->process, req->window, req->type )))
    {
        set_error( STATUS_NOT_FOUND );
        return;
    }
    detach_dcomp_window_target( target );
}

DECL_HANDLER(validate_dcomp_window_target)
{
    struct dcomp_window_target *target;

    if (req->resource_type != 0xb8)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    if (!(target = (struct dcomp_window_target *)get_handle_obj( current->process, req->handle,
                                                                 0, &dcomp_window_target_ops ))) return;
    if (!target->attached || target->owner != current->process)
        set_error( STATUS_ACCESS_DENIED );
    release_object( target );
}
