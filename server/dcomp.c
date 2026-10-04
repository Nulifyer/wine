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
#include <unistd.h>

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
#define DCOMP_SURFACE_UPDATE_SIZE 0x178
#define TOKEN_MANAGER_SURFACE_UPDATE_CAPACITY \
    (TOKEN_MANAGER_SECTION_SIZE / DCOMP_SURFACE_UPDATE_SIZE)
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
    unsigned __int64 synchronization_id;
    unsigned int pending_duplicates;
    int queued;
    int received;
    data_size_t size;
    void *data;
};

struct dcomp_synchronization_manager
{
    struct list entry;
    unsigned int session_id;
    unsigned int next_id;
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
    unsigned __int64 synchronization_id;
    unsigned __int64 frame_id;
    unsigned int batch_id;
    unsigned int prerequisite_channel;
    unsigned int prerequisite_batch_id;
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
    unsigned int delivered_batch_id;
    unsigned __int64 synchronization_id;
    unsigned int pending_batch_duplicates;
    unsigned __int64 next_duplicate_sequence;
    int flushing_batches;
    WCHAR *application_id;
    data_size_t application_id_size;
    int application_id_dirty;
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
    struct list entry;
    struct dcomp_channel *channel;
    unsigned int session_id;
    unsigned int resource;
    unsigned int type;
    int source_ready;
    unsigned int source_batch_id;
    struct dcomp_system_resource *system_resource;
};

struct dcomp_system_channel
{
    struct list entry;
    struct list resources;
    struct process *owner;
    struct dcomp_connection *connection;
    unsigned int id;
    unsigned int next_resource;
};

struct dcomp_system_resource
{
    struct list entry;
    struct dcomp_system_channel *channel;
    unsigned int id;
    unsigned int type;
    unsigned int references;
};

struct dcomp_system_duplicate
{
    struct list entry;
    struct dcomp_system_resource *resource;
    struct dcomp_channel *target;
    unsigned int batch_id;
    unsigned __int64 sequence;
    int begun;
};

struct dcomp_surface
{
    struct object obj;
    struct process *owner;
    struct object *realization;
    unsigned int session_id;
    unsigned __int64 binding_id;
    unsigned int ink_cookie;
    unsigned int present_count;
    unsigned int bind_flags;
    unsigned char buffer_info[0x520];
    struct region *dirty_region;
    int bind_shared;
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

struct dcomp_frame_surface_update
{
    struct list entry;
    struct region *dirty_region;
    unsigned int session_id;
    unsigned __int64 binding_id;
    unsigned __int64 frame_id;
    unsigned char data[DCOMP_SURFACE_UPDATE_SIZE];
    int delivered;
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
    struct dcomp_system_resource *system_resource;
    user_handle_t window;
    unsigned int type;
    int attached;
};

struct dcomp_window_target_duplicate
{
    struct list entry;
    struct dcomp_channel *source;
    unsigned int source_resource;
    unsigned int source_batch_id;
    struct dcomp_channel *channel;
    unsigned int batch_id;
    unsigned __int64 sequence;
    int source_ready;
    int begun;
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
static struct list dcomp_system_channels = LIST_INIT( dcomp_system_channels );
static struct list dcomp_system_duplicates = LIST_INIT( dcomp_system_duplicates );
static struct list dcomp_synchronization_managers = LIST_INIT( dcomp_synchronization_managers );
static struct list dcomp_shared_resources = LIST_INIT( dcomp_shared_resources );
static struct list dcomp_pending_duplicates = LIST_INIT( dcomp_pending_duplicates );
static struct list token_managers = LIST_INIT( token_managers );
static struct list dcomp_window_targets = LIST_INIT( dcomp_window_targets );
static struct list dcomp_frame_surface_updates = LIST_INIT( dcomp_frame_surface_updates );

static void resolve_dcomp_duplicates( struct dcomp_channel *source, unsigned int batch_id );
static int flush_dcomp_pending_duplicates(void);
static void cleanup_dcomp_pending_duplicates( struct dcomp_channel *channel );
static void release_dcomp_system_resource( struct dcomp_system_resource *resource );
static int flush_dcomp_system_duplicates( struct dcomp_channel *target,
                                           struct dcomp_connection *connection );
static void cleanup_dcomp_system_duplicates( struct dcomp_channel *target );
static void remove_pending_dcomp_surface_updates( const struct dcomp_surface *surface );
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
    fprintf( stderr, "DirectComposition shared resource session=%u channel=%#x resource=%#x type=%#x\n",
             resource->session_id, resource->channel ? resource->channel->id : 0,
             resource->resource, resource->type );
}

static void dcomp_shared_resource_destroy( struct object *obj )
{
    struct dcomp_shared_resource *resource = (struct dcomp_shared_resource *)obj;

    assert( obj->ops == &dcomp_shared_resource_ops );
    list_remove( &resource->entry );
    if (resource->channel) release_object( resource->channel );
    if (resource->system_resource) release_dcomp_system_resource( resource->system_resource );
}

static void dcomp_surface_destroy( struct object *obj )
{
    struct dcomp_surface *surface = (struct dcomp_surface *)obj;

    assert( obj->ops == &dcomp_surface_ops );
    remove_pending_dcomp_surface_updates( surface );
    if (surface->realization) release_object( surface->realization );
    free_region( surface->dirty_region );
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
    release_dcomp_system_resource( target->system_resource );
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

static void detach_dcomp_window_target( struct dcomp_window_target *target, int notify )
{
    assert( target->attached );
    if (notify)
        notify_dwm_window_target_destroyed( target->owner->session_id,
                                            target->window, target->type );
    remove_dwm_window_target( target->window, target->type );
    target->attached = 0;
    list_remove( &target->entry );
    release_object( target );
}

void cleanup_dcomp_window_targets( user_handle_t window )
{
    struct dcomp_window_target *target, *next;

    LIST_FOR_EACH_ENTRY_SAFE( target, next, &dcomp_window_targets,
                              struct dcomp_window_target, entry )
        if (target->window == window) detach_dcomp_window_target( target, 1 );
}

void replay_dcomp_window_targets( unsigned int session_id )
{
    struct dcomp_window_target *target;

    LIST_FOR_EACH_ENTRY( target, &dcomp_window_targets, struct dcomp_window_target, entry )
        if (target->attached && target->owner->session_id == session_id)
            if (ensure_dwm_window_context( target->window ))
            {
                sync_dwm_window_target( target->window, target->type );
                notify_dwm_window_target_created( session_id, target->window, target->type,
                                                  &target->obj );
            }
}

static void dcomp_channel_destroy( struct object *obj )
{
    struct dcomp_channel *channel = (struct dcomp_channel *)obj;
    struct dcomp_batch *batch, *next;
    struct dcomp_shared_section *section, *section_next;

    assert( obj->ops == &dcomp_channel_ops );
    cleanup_dcomp_pending_duplicates( channel );
    cleanup_dcomp_system_duplicates( channel );
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
            record->synchronization_id = 0;
            record->frame_id = 0;
            record->batch_id = 0;
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
    free( channel->application_id );
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
    struct dcomp_system_channel *system_channel;

    LIST_FOR_EACH_ENTRY( channel, &dcomp_channels, struct dcomp_channel, entry )
        if (channel->id == id) return 1;
    LIST_FOR_EACH_ENTRY( system_channel, &dcomp_system_channels,
                         struct dcomp_system_channel, entry )
        if (system_channel->id == id) return 1;
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

static struct dcomp_synchronization_manager *get_dcomp_synchronization_manager( unsigned int session_id )
{
    struct dcomp_synchronization_manager *manager;

    LIST_FOR_EACH_ENTRY( manager, &dcomp_synchronization_managers,
                         struct dcomp_synchronization_manager, entry )
        if (manager->session_id == session_id) return manager;

    if (!(manager = mem_alloc( sizeof(*manager) ))) return NULL;
    manager->session_id = session_id;
    manager->next_id = 0;
    list_add_tail( &dcomp_synchronization_managers, &manager->entry );
    return manager;
}

static unsigned __int64 alloc_dcomp_synchronization_id( unsigned int session_id )
{
    struct dcomp_synchronization_manager *manager;

    if (!(manager = get_dcomp_synchronization_manager( session_id ))) return 0;
    while (!++manager->next_id);
    return manager->next_id;
}

static void free_dcomp_frame_surface_update( struct dcomp_frame_surface_update *update )
{
    list_remove( &update->entry );
    free_region( update->dirty_region );
    free( update );
}

static struct dcomp_frame_surface_update *find_pending_dcomp_surface_update(
        const struct dcomp_surface *surface )
{
    struct dcomp_frame_surface_update *update;

    LIST_FOR_EACH_ENTRY( update, &dcomp_frame_surface_updates,
                         struct dcomp_frame_surface_update, entry )
    {
        if (!update->frame_id && update->session_id == surface->session_id &&
            update->binding_id == surface->binding_id)
            return update;
    }
    return NULL;
}

static struct dcomp_frame_surface_update *get_pending_dcomp_surface_update(
        const struct dcomp_surface *surface )
{
    struct dcomp_frame_surface_update *update;

    if ((update = find_pending_dcomp_surface_update( surface ))) return update;
    if (!(update = mem_alloc( sizeof(*update) ))) return NULL;
    if (!(update->dirty_region = create_empty_region()))
    {
        free( update );
        return NULL;
    }
    update->session_id = surface->session_id;
    update->binding_id = surface->binding_id;
    update->frame_id = 0;
    update->delivered = 0;
    memset( update->data, 0, sizeof(update->data) );
    list_add_tail( &dcomp_frame_surface_updates, &update->entry );
    return update;
}

static void assign_pending_dcomp_surface_updates( unsigned int session_id,
                                                   unsigned __int64 frame_id )
{
    struct dcomp_frame_surface_update *update;

    LIST_FOR_EACH_ENTRY( update, &dcomp_frame_surface_updates,
                         struct dcomp_frame_surface_update, entry )
    {
        if (update->session_id == session_id && !update->frame_id)
        {
            update->frame_id = frame_id;
            update->delivered = 0;
        }
    }
}

static void remove_dcomp_frame_surface_updates( unsigned int session_id,
                                                 unsigned __int64 frame_id )
{
    struct dcomp_frame_surface_update *update, *next;

    LIST_FOR_EACH_ENTRY_SAFE( update, next, &dcomp_frame_surface_updates,
                              struct dcomp_frame_surface_update, entry )
        if (update->session_id == session_id && update->frame_id == frame_id)
            free_dcomp_frame_surface_update( update );
}

static void remove_pending_dcomp_surface_updates( const struct dcomp_surface *surface )
{
    struct dcomp_frame_surface_update *update, *next;

    LIST_FOR_EACH_ENTRY_SAFE( update, next, &dcomp_frame_surface_updates,
                              struct dcomp_frame_surface_update, entry )
        if (!update->frame_id && update->session_id == surface->session_id &&
            update->binding_id == surface->binding_id)
            free_dcomp_frame_surface_update( update );
}

static int copy_dcomp_dirty_region( struct region *region, unsigned char *data )
{
    struct rectangle bounds, *rects;
    data_size_t size = 0;

    memset( data, 0, 0xa4 );
    if (is_region_empty( region )) return 1;
    if ((rects = get_region_data( region, 10 * sizeof(*rects), &size )))
    {
        memcpy( data, rects, size );
        free( rects );
        *(unsigned int *)(data + 0xa0) = size / sizeof(*rects);
        return 1;
    }
    if (get_error() != STATUS_BUFFER_OVERFLOW) return 0;
    clear_error();
    get_region_extents( region, &bounds );
    if (get_error()) return 0;
    memcpy( data, &bounds, sizeof(bounds) );
    *(unsigned int *)(data + 0xa0) = 1;
    return 1;
}

static void update_dcomp_frame_surface_data( struct dcomp_frame_surface_update *update,
                                              const struct dcomp_surface *surface )
{
    unsigned char *data = update->data;

    memset( data, 0, sizeof(update->data) );
    *(unsigned int *)(data + 0x00) = 2; /* single-buffer realization */
    memcpy( data + 0x04, &surface->binding_id, sizeof(surface->binding_id) );
    memcpy( data + 0x10, &surface->binding_id, sizeof(surface->binding_id) );
    *(unsigned int *)(data + 0x18) = 0;
    *(unsigned int *)(data + 0x1c) = surface->present_count;
    memcpy( data + 0xe0, surface->buffer_info + 0x10, 0x90 );
    *(unsigned int *)(data + 0x174) = surface->present_count;
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

static int queue_dcomp_synchronized_record( struct dcomp_connection *connection, unsigned int type,
                                            unsigned int channel, unsigned int value,
                                            unsigned __int64 connection_id, unsigned __int64 object,
                                            unsigned __int64 synchronization_id, unsigned int batch_id,
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
    record->synchronization_id = synchronization_id;
    record->frame_id = 0;
    record->batch_id = batch_id;
    record->prerequisite_channel = 0;
    record->prerequisite_batch_id = 0;
    record->size = size;
    list_add_tail( &connection->records, &record->entry );
    set_event( connection->work_event );
    return 1;
}

static int queue_dcomp_record( struct dcomp_connection *connection, unsigned int type,
                               unsigned int channel, unsigned int value,
                               unsigned __int64 connection_id, unsigned __int64 object,
                               const void *data, data_size_t size )
{
    return queue_dcomp_synchronized_record( connection, type, channel, value,
                                             connection_id, object, 0, 0, data, size );
}

static int queue_dcomp_prerequisite_record( struct dcomp_connection *connection,
                                             unsigned int type, unsigned int channel,
                                             unsigned int value,
                                             unsigned __int64 synchronization_id,
                                             unsigned int prerequisite_channel,
                                             unsigned int prerequisite_batch_id,
                                             const void *data, data_size_t size )
{
    struct dcomp_record *record;

    if (!queue_dcomp_synchronized_record( connection, type, channel, value, 0, 0,
                                          synchronization_id, 0, data, size )) return 0;
    record = LIST_ENTRY( list_tail( &connection->records ), struct dcomp_record, entry );
    record->prerequisite_channel = prerequisite_channel;
    record->prerequisite_batch_id = prerequisite_batch_id;
    return 1;
}

static void publish_dcomp_batch_prerequisites( struct dcomp_connection *connection,
                                                unsigned int channel,
                                                unsigned int batch_id,
                                                unsigned __int64 synchronization_id )
{
    struct dcomp_record *record;

    LIST_FOR_EACH_ENTRY( record, &connection->records, struct dcomp_record, entry )
    {
        if (record->prerequisite_channel != channel ||
            record->prerequisite_batch_id != batch_id) continue;
        record->synchronization_id = synchronization_id;
        record->prerequisite_channel = 0;
        record->prerequisite_batch_id = 0;
    }
}

static struct dcomp_record *find_dcomp_selected_record( struct dcomp_connection *connection,
                                                        unsigned __int64 selector )
{
    struct dcomp_record *record;

    LIST_FOR_EACH_ENTRY( record, &connection->records, struct dcomp_record, entry )
    {
        if (!selector && !record->frame_id) return record;
        if (selector && (record->synchronization_id == selector || record->frame_id == selector))
            return record;
    }
    return NULL;
}

static struct dcomp_system_channel *find_dcomp_system_channel( struct process *owner )
{
    struct dcomp_system_channel *channel;

    LIST_FOR_EACH_ENTRY( channel, &dcomp_system_channels, struct dcomp_system_channel, entry )
        if (channel->owner == owner) return channel;
    return NULL;
}

static int queue_dcomp_system_command( struct dcomp_connection *connection,
                                       struct dcomp_system_channel *channel,
                                       unsigned int command_type, unsigned int resource,
                                       unsigned int value )
{
    unsigned int command[4];
    data_size_t size = command_type == 0x29 ? 12 : 16;

    command[0] = size;
    command[1] = command_type;
    command[2] = resource;
    command[3] = value;
    return queue_dcomp_record( connection, DCOMP_RECORD_BATCH, channel->id,
                               size, 0, 0, command, size );
}

static int announce_dcomp_system_channel( struct dcomp_system_channel *channel,
                                           struct dcomp_connection *connection )
{
    struct dcomp_system_resource *resource;

    if (channel->connection == connection) return 1;
    if (!queue_dcomp_record( connection, DCOMP_RECORD_CREATE, channel->id, 0,
                             0, 0, NULL, 0 )) return 0;
    LIST_FOR_EACH_ENTRY( resource, &channel->resources, struct dcomp_system_resource, entry )
        if (!queue_dcomp_system_command( connection, channel, 0x28,
                                         resource->id, resource->type )) return 0;
    channel->connection = connection;
    return 1;
}

static struct dcomp_system_resource *create_dcomp_system_resource( struct process *owner,
                                                                    unsigned int type )
{
    struct dcomp_system_resource *resource;
    struct dcomp_system_channel *channel;
    struct dcomp_connection *connection;
    int new_channel = 0;

    if (!(channel = find_dcomp_system_channel( owner )))
    {
        if (!(channel = mem_alloc( sizeof(*channel) ))) return NULL;
        if (!(channel->id = alloc_dcomp_channel_id()))
        {
            free( channel );
            return NULL;
        }
        channel->owner = (struct process *)grab_object( owner );
        channel->connection = NULL;
        channel->next_resource = 0;
        list_init( &channel->resources );
        list_add_tail( &dcomp_system_channels, &channel->entry );
        new_channel = 1;
    }
    if (!(resource = mem_alloc( sizeof(*resource) ))) goto failed;
    resource->channel = channel;
    while (!(resource->id = ++channel->next_resource));
    resource->type = type;
    resource->references = 1;
    list_add_tail( &channel->resources, &resource->entry );

    if ((connection = find_dcomp_consumer_connection( owner->session_id )))
    {
        if (channel->connection != connection)
        {
            if (!announce_dcomp_system_channel( channel, connection )) goto failed_resource;
        }
        else if (!queue_dcomp_system_command( connection, channel, 0x28,
                                               resource->id, resource->type ))
            goto failed_resource;
    }
    return resource;

failed_resource:
    list_remove( &resource->entry );
    free( resource );
failed:
    if (new_channel)
    {
        list_remove( &channel->entry );
        release_object( channel->owner );
        free( channel );
    }
    return NULL;
}

static int begin_dcomp_system_resource_duplicate( struct dcomp_system_resource *resource,
                                                   struct dcomp_channel *target )
{
    struct dcomp_system_duplicate *duplicate;

    if (!(duplicate = mem_alloc( sizeof(*duplicate) ))) return 0;
    duplicate->resource = resource;
    duplicate->target = (struct dcomp_channel *)grab_object( target );
    duplicate->batch_id = target->batch_ids[0] + 1;
    duplicate->sequence = ++target->next_duplicate_sequence;
    duplicate->begun = 0;
    resource->references++;
    target->pending_batch_duplicates++;
    list_add_tail( &dcomp_system_duplicates, &duplicate->entry );
    return flush_dcomp_pending_duplicates();
}

static int flush_dcomp_system_duplicates( struct dcomp_channel *target,
                                           struct dcomp_connection *connection )
{
    assert( target->connection == connection );
    return flush_dcomp_pending_duplicates();
}

static void cleanup_dcomp_system_duplicates( struct dcomp_channel *target )
{
    struct dcomp_system_duplicate *duplicate, *next;

    LIST_FOR_EACH_ENTRY_SAFE( duplicate, next, &dcomp_system_duplicates,
                              struct dcomp_system_duplicate, entry )
        if (duplicate->target == target)
        {
            list_remove( &duplicate->entry );
            release_object( duplicate->target );
            release_dcomp_system_resource( duplicate->resource );
            free( duplicate );
        }
}

static void release_dcomp_system_resource( struct dcomp_system_resource *resource )
{
    struct dcomp_system_channel *channel;

    if (!resource) return;
    assert( resource->references );
    if (--resource->references) return;
    channel = resource->channel;
    if (channel->connection)
        queue_dcomp_system_command( channel->connection, channel, 0x29, resource->id, 0 );
    list_remove( &resource->entry );
    free( resource );
    if (!list_empty( &channel->resources )) return;
    if (channel->connection)
        queue_dcomp_record( channel->connection, DCOMP_RECORD_CLOSE, channel->id,
                            0, 0, 0, NULL, 0 );
    list_remove( &channel->entry );
    release_object( channel->owner );
    free( channel );
}

static int flush_dcomp_channel_batches( struct dcomp_channel *channel )
{
    struct dcomp_batch *batch, *next;
    unsigned int batch_id;
    int success = 1;

    if (!channel->connection) return 0;
    if (channel->flushing_batches) return 1;
    channel->flushing_batches = 1;
    LIST_FOR_EACH_ENTRY_SAFE( batch, next, &channel->batches, struct dcomp_batch, entry )
    {
        if (batch->queued) continue;
        if (batch->pending_duplicates) break;
        if (!queue_dcomp_synchronized_record( channel->connection, DCOMP_RECORD_BATCH,
                                              channel->id, batch->size, 0, 0,
                                              batch->synchronization_id, batch->id,
                                              batch->data, batch->size ))
        {
            success = 0;
            break;
        }
        batch_id = batch->id;
        batch->queued = 1;
        channel->delivered_batch_id = batch_id;
        free( batch->data );
        batch->data = NULL;
        resolve_dcomp_duplicates( channel, batch_id );
    }
    channel->flushing_batches = 0;
    return success;
}

static struct dcomp_batch *find_dcomp_channel_batch( struct dcomp_channel *channel,
                                                      unsigned int batch_id )
{
    struct dcomp_batch *batch;

    LIST_FOR_EACH_ENTRY( batch, &channel->batches, struct dcomp_batch, entry )
        if (batch->id == batch_id) return batch;
    return NULL;
}

static void receive_dcomp_channel_batch( struct dcomp_channel *channel, unsigned int batch_id )
{
    struct dcomp_batch *batch, *next;

    LIST_FOR_EACH_ENTRY( batch, &channel->batches, struct dcomp_batch, entry )
    {
        if (batch->id != batch_id) continue;
        assert( batch->queued );
        batch->received = 1;
        break;
    }

    LIST_FOR_EACH_ENTRY_SAFE( batch, next, &channel->batches, struct dcomp_batch, entry )
    {
        if (!batch->queued || !batch->received) break;
        channel->batch_ids[1] = batch->id;
        list_remove( &batch->entry );
        free( batch->data );
        free( batch );
    }
}

static void resolve_dcomp_batch_dependency( struct dcomp_channel *channel,
                                            unsigned int batch_id )
{
    struct dcomp_batch *batch;

    LIST_FOR_EACH_ENTRY( batch, &channel->batches, struct dcomp_batch, entry )
    {
        if (batch->id != batch_id) continue;
        assert( batch->pending_duplicates );
        batch->pending_duplicates--;
        return;
    }
    assert( batch_id == channel->batch_ids[0] + 1 );
    assert( channel->pending_batch_duplicates );
    channel->pending_batch_duplicates--;
}

static int resolve_dcomp_pending_duplicate( struct dcomp_window_target_duplicate *duplicate )
{
    struct dcomp_batch *batch = find_dcomp_channel_batch( duplicate->channel,
                                                           duplicate->batch_id );
    unsigned int command[4];

    command[0] = sizeof(command);
    command[1] = 0x26; /* MILCMD_CHANNEL_BEGINDUPLICATERESOURCE */
    command[2] = duplicate->source_resource;
    command[3] = duplicate->channel->id;
    if (!duplicate->begun)
    {
        if (!queue_dcomp_prerequisite_record( duplicate->source->connection,
                                              DCOMP_RECORD_BATCH, duplicate->source->id,
                                              sizeof(command), batch ? batch->synchronization_id : 0,
                                              duplicate->channel->id, duplicate->batch_id,
                                              command, sizeof(command) )) return 0;
        duplicate->begun = 1;
    }
    if (!batch) return 1;
    publish_dcomp_batch_prerequisites( duplicate->source->connection,
                                       duplicate->channel->id, duplicate->batch_id,
                                       batch->synchronization_id );
    /* Dependencies belong to the destination batch that contains their
     * complete-duplicate command.  A later unresolved batch must not hold an
     * earlier ready batch, while every dependency in one batch must publish
     * its begin record before that batch is visible. */
    resolve_dcomp_batch_dependency( duplicate->channel, duplicate->batch_id );
    list_remove( &duplicate->entry );
    flush_dcomp_channel_batches( duplicate->channel );
    free( duplicate );
    return 1;
}

static int resolve_dcomp_system_duplicate( struct dcomp_system_duplicate *duplicate )
{
    struct dcomp_system_resource *resource = duplicate->resource;
    struct dcomp_system_channel *channel = resource->channel;
    struct dcomp_channel *target = duplicate->target;
    struct dcomp_connection *connection = target->connection;
    struct dcomp_batch *batch = find_dcomp_channel_batch( target, duplicate->batch_id );
    unsigned int command[4];

    command[0] = sizeof(command);
    command[1] = 0x26; /* MILCMD_CHANNEL_BEGINDUPLICATERESOURCE */
    command[2] = resource->id;
    command[3] = target->id;
    if (!connection) return 0;
    if (!duplicate->begun)
    {
        if (!announce_dcomp_system_channel( channel, connection ) ||
            !queue_dcomp_prerequisite_record( connection, DCOMP_RECORD_BATCH, channel->id,
                                              sizeof(command), batch ? batch->synchronization_id : 0,
                                              target->id, duplicate->batch_id,
                                              command, sizeof(command) )) return 0;
        duplicate->begun = 1;
    }
    if (!batch) return 1;
    publish_dcomp_batch_prerequisites( connection, target->id, duplicate->batch_id,
                                       batch->synchronization_id );
    resolve_dcomp_batch_dependency( target, duplicate->batch_id );
    list_remove( &duplicate->entry );
    flush_dcomp_channel_batches( target );
    release_object( target );
    release_dcomp_system_resource( resource );
    free( duplicate );
    return 1;
}

static int has_earlier_dcomp_duplicate( struct dcomp_channel *target,
                                        unsigned __int64 sequence )
{
    struct dcomp_window_target_duplicate *pending;
    struct dcomp_system_duplicate *system;

    LIST_FOR_EACH_ENTRY( pending, &dcomp_pending_duplicates,
                         struct dcomp_window_target_duplicate, entry )
        if (pending->channel == target && pending->sequence < sequence && !pending->begun)
            return 1;
    LIST_FOR_EACH_ENTRY( system, &dcomp_system_duplicates,
                         struct dcomp_system_duplicate, entry )
        if (system->target == target && system->sequence < sequence && !system->begun)
            return 1;
    return 0;
}

static int flush_dcomp_pending_duplicates(void)
{
    static int flushing;
    struct dcomp_window_target_duplicate *duplicate, *candidate;
    struct dcomp_system_duplicate *system, *system_candidate;
    int success = 1;

    if (flushing) return 1;
    flushing = 1;
    for (;;)
    {
        candidate = NULL;
        system_candidate = NULL;
        LIST_FOR_EACH_ENTRY( duplicate, &dcomp_pending_duplicates,
                             struct dcomp_window_target_duplicate, entry )
        {
            if (duplicate->source_ready && duplicate->source->connection &&
                (!duplicate->begun ||
                 find_dcomp_channel_batch( duplicate->channel, duplicate->batch_id )) &&
                !has_earlier_dcomp_duplicate( duplicate->channel, duplicate->sequence ))
            {
                candidate = duplicate;
                break;
            }
        }
        if (!candidate)
            LIST_FOR_EACH_ENTRY( system, &dcomp_system_duplicates,
                                 struct dcomp_system_duplicate, entry )
            {
                if (system->target->connection &&
                    (!system->begun ||
                     find_dcomp_channel_batch( system->target, system->batch_id )) &&
                    !has_earlier_dcomp_duplicate( system->target, system->sequence ))
                {
                    system_candidate = system;
                    break;
                }
            }
        if (!candidate && !system_candidate) break;
        if ((candidate && !resolve_dcomp_pending_duplicate( candidate )) ||
            (system_candidate && !resolve_dcomp_system_duplicate( system_candidate )))
        {
            success = 0;
            break;
        }
    }
    flushing = 0;
    return success;
}

static void resolve_dcomp_duplicates( struct dcomp_channel *source, unsigned int batch_id )
{
    struct dcomp_shared_resource *resource;
    struct dcomp_window_target_duplicate *duplicate;

    LIST_FOR_EACH_ENTRY( resource, &dcomp_shared_resources, struct dcomp_shared_resource, entry )
    {
        if (resource->channel != source || resource->source_ready ||
            resource->source_batch_id > batch_id) continue;
        resource->source_ready = 1;
    }
    LIST_FOR_EACH_ENTRY( duplicate, &dcomp_pending_duplicates,
                         struct dcomp_window_target_duplicate, entry )
    {
        if (duplicate->source != source || duplicate->source_batch_id > batch_id) continue;
        duplicate->source_ready = 1;
    }
    flush_dcomp_pending_duplicates();
}

static void cleanup_dcomp_pending_duplicates( struct dcomp_channel *channel )
{
    struct dcomp_window_target_duplicate *duplicate, *next;

    LIST_FOR_EACH_ENTRY_SAFE( duplicate, next, &dcomp_pending_duplicates,
                              struct dcomp_window_target_duplicate, entry )
    {
        if (duplicate->source != channel && duplicate->channel != channel) continue;
        list_remove( &duplicate->entry );
        /* If the source disappears before its resource reaches DWM, there is
         * no valid begin-duplicate record to pair with the destination's
         * complete command.  Keep that destination batch blocked; releasing
         * it would shift DWM's per-channel duplicate FIFO and alias every
         * later completion to the wrong resource class. */
        free( duplicate );
    }
    flush_dcomp_pending_duplicates();
}

static int attach_internal_dcomp_channel( struct dcomp_channel *channel )
{
    struct dcomp_connection *connection;

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
        if (!flush_dcomp_system_duplicates( channel, connection )) return 0;
    }
    return flush_dcomp_channel_batches( channel );
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
    struct dcomp_system_channel *system_channel;
    struct dcomp_record *record, *next;
    unsigned int session_id;

    assert( obj->ops == &dcomp_connection_ops );
    if (connection->frame_active)
        remove_dcomp_frame_surface_updates( connection->owner->session_id,
                                             connection->current_frame_id );
    LIST_FOR_EACH_ENTRY_SAFE( record, next, &connection->records, struct dcomp_record, entry )
    {
        list_remove( &record->entry );
        free( record->data );
        free( record );
    }
    session_id = connection->owner->session_id;
    LIST_FOR_EACH_ENTRY( system_channel, &dcomp_system_channels,
                         struct dcomp_system_channel, entry )
        if (system_channel->connection == connection) system_channel->connection = NULL;
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
    struct dcomp_record *record;
    unsigned __int64 id;

    if (!(connection = (struct dcomp_connection *)get_handle_obj( current->process, req->connection,
                                                                   0, &dcomp_connection_ops ))) return;
    if (!is_dcomp_consumer_connection( connection )) set_error( STATUS_ACCESS_DENIED );
    else if (connection->frame_active) set_error( STATUS_RESOURCE_IN_USE );
    else
    {
        if (!(id = alloc_dcomp_synchronization_id( connection->owner->session_id )))
            goto done;
        LIST_FOR_EACH_ENTRY( record, &connection->records, struct dcomp_record, entry )
            if (!record->frame_id && !record->prerequisite_channel)
                record->frame_id = id;
        reply->frame_id = id;
        connection->current_frame_id = id;
        connection->frame_active = 1;
        assign_pending_dcomp_surface_updates( connection->owner->session_id, id );
    }

done:
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
        remove_dcomp_frame_surface_updates( connection->owner->session_id, req->frame_id );
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
    else
    {
        remove_dcomp_frame_surface_updates( connection->owner->session_id, req->frame_id );
        connection->frame_active = 0;
    }
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
    struct dcomp_frame_surface_update *update;
    struct token_manager *manager;
    struct fd *fd;
    unsigned char data[TOKEN_MANAGER_SURFACE_UPDATE_CAPACITY * DCOMP_SURFACE_UPDATE_SIZE];
    unsigned int count = 0;
    int unix_fd;

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
        LIST_FOR_EACH_ENTRY( update, &dcomp_frame_surface_updates,
                             struct dcomp_frame_surface_update, entry )
        {
            if (update->session_id != current->process->session_id ||
                update->frame_id != req->frame_id || update->delivered)
                continue;
            if (count == TOKEN_MANAGER_SURFACE_UPDATE_CAPACITY) break;
            if (!copy_dcomp_dirty_region( update->dirty_region,
                                           update->data + 0x20 )) return;
            memcpy( data + count * DCOMP_SURFACE_UPDATE_SIZE, update->data,
                    DCOMP_SURFACE_UPDATE_SIZE );
            ++count;
        }
        if (count)
        {
            if (!(manager = get_token_manager( current->process->session_id ))) return;
            if (!(fd = get_obj_fd( (struct object *)manager->section ))) return;
            unix_fd = get_unix_fd( fd );
            if (unix_fd == -1 || pwrite( unix_fd, data,
                                         count * DCOMP_SURFACE_UPDATE_SIZE, 0 ) !=
                                 count * DCOMP_SURFACE_UPDATE_SIZE)
            {
                if (unix_fd != -1) file_set_error();
                release_object( fd );
                return;
            }
            release_object( fd );
            count = 0;
            LIST_FOR_EACH_ENTRY( update, &dcomp_frame_surface_updates,
                                 struct dcomp_frame_surface_update, entry )
            {
                if (update->session_id != current->process->session_id ||
                    update->frame_id != req->frame_id || update->delivered)
                    continue;
                update->delivered = 1;
                if (++count == TOKEN_MANAGER_SURFACE_UPDATE_CAPACITY) break;
            }
        }
        reply->update_count = count;
        reply->has_more = 0;
        LIST_FOR_EACH_ENTRY( update, &dcomp_frame_surface_updates,
                             struct dcomp_frame_surface_update, entry )
        {
            if (update->session_id == current->process->session_id &&
                update->frame_id == req->frame_id && !update->delivered)
            {
                reply->has_more = 1;
                break;
            }
        }
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
    channel->delivered_batch_id = 0;
    channel->synchronization_id = 0;
    channel->pending_batch_duplicates = 0;
    channel->next_duplicate_sequence = 0;
    channel->flushing_batches = 0;
    channel->application_id = NULL;
    channel->application_id_size = 0;
    channel->application_id_dirty = 0;
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
    cleanup_dcomp_system_duplicates( channel );
    handle = channel->owner_handle;
    release_object( channel );
    if (close_handle( current->process, handle )) set_error( STATUS_ACCESS_DENIED );
}

DECL_HANDLER(set_dcomp_channel_connection)
{
    struct dcomp_connection *connection;
    struct dcomp_channel *channel;
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
    if (!flush_dcomp_system_duplicates( channel, connection )) goto done;
    if (getenv( "LINUXNT_DEBUG_PROCESS_EXITS" ))
        fprintf( stderr, "linuxnt: server dcomp-bind winpid=%04x session=%u channel=%#x "
                 "slot=%d connection=%#llx consumer=%04x status=0\n", current->process->id,
                 current->process->session_id, channel->id, slot,
                 (unsigned long long)req->connection, connection->owner->id );
    flush_dcomp_channel_batches( channel );

done:
    release_object( channel );
}

DECL_HANDLER(set_dcomp_channel_application_id)
{
    const WCHAR *input = get_req_data();
    data_size_t input_size = get_req_data_size();
    struct dcomp_channel *channel;
    data_size_t length;
    WCHAR *application_id;

    if (!input_size || input_size > 300 || (input_size & 1))
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    if (!(channel = get_dcomp_channel( req->channel ))) return;

    for (length = 0; length < input_size; length += sizeof(WCHAR))
    {
        WCHAR value;

        memcpy( &value, (const char *)input + length, sizeof(value) );
        if (!value) break;
    }
    if (!(application_id = mem_alloc( length + sizeof(WCHAR) ))) goto done;
    memcpy( application_id, input, length );
    application_id[length / sizeof(WCHAR)] = 0;

    free( channel->application_id );
    channel->application_id = application_id;
    channel->application_id_size = length + sizeof(WCHAR);
    channel->application_id_dirty = 1;

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
    resource->session_id = channel->owner->session_id;
    resource->resource = req->resource;
    resource->type = req->type;
    resource->source_batch_id = req->source_ready ? channel->batch_ids[0] :
                                                    channel->batch_ids[0] + 1;
    resource->source_ready = channel->delivered_batch_id >= resource->source_batch_id;
    resource->system_resource = NULL;
    list_add_tail( &dcomp_shared_resources, &resource->entry );
    reply->handle = alloc_handle_no_access_check( current->process, resource, 0, 0 );
    release_object( resource );

done:
    release_object( channel );
}

DECL_HANDLER(create_dcomp_shared_resource)
{
    struct dcomp_shared_resource *resource;

    reply->handle = 0;
    if (req->type != 0x13 && req->type != 0x82 && req->type != 0xb8)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    if (!(resource = alloc_object( &dcomp_shared_resource_ops ))) return;
    resource->channel = NULL;
    resource->session_id = current->process->session_id;
    resource->resource = 0;
    resource->type = req->type;
    resource->source_ready = 0;
    resource->source_batch_id = 0;
    if (!(resource->system_resource = create_dcomp_system_resource( current->process,
                                                                    req->type )))
    {
        release_object( resource );
        return;
    }
    list_add_tail( &dcomp_shared_resources, &resource->entry );
    reply->handle = alloc_handle_no_access_check( current->process, resource, 0, 0 );
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
    if (!(record = find_dcomp_selected_record( connection, req->synchronization_id )))
    {
        if (req->synchronization_id &&
            req->synchronization_id != connection->current_frame_id)
            set_error( STATUS_NOT_FOUND );
        goto done;
    }
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
        if (channel && record->batch_id)
            receive_dcomp_channel_batch( channel, record->batch_id );
    }
    list_remove( &record->entry );
    reply->more = !!find_dcomp_selected_record( connection, req->synchronization_id );
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

DECL_HANDLER(synchronize_dcomp_channel)
{
    struct dcomp_channel *channel;
    unsigned __int64 id;

    if (!(channel = get_dcomp_channel( req->channel ))) return;
    if (channel->synchronization_id) set_error( STATUS_ACCESS_DENIED );
    else if ((id = alloc_dcomp_synchronization_id( channel->owner->session_id )))
    {
        channel->synchronization_id = id;
        reply->synchronization_id = id;
    }
    release_object( channel );
}

DECL_HANDLER(commit_dcomp_channel)
{
    struct dcomp_channel *channel;
    struct dcomp_batch *batch;
    data_size_t size = get_req_data_size();
    data_size_t application_command_size = 0;

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
    if (!channel->connection && current->process->native_dwm_owner &&
        find_dcomp_consumer_connection( current->process->session_id ) &&
        !attach_internal_dcomp_channel( channel )) goto done;
    if (!(batch = mem_alloc( sizeof(*batch) ))) goto done;
    if (channel->application_id_dirty)
        application_command_size = (12 + channel->application_id_size + 3) & ~3;
    batch->data = NULL;
    if (size + application_command_size &&
        !(batch->data = mem_alloc( size + application_command_size )))
    {
        free( batch );
        goto done;
    }
    if (application_command_size)
    {
        unsigned int *command = batch->data;

        memset( command, 0, application_command_size );
        command[0] = application_command_size;
        command[1] = 0x2b;
        command[2] = channel->application_id_size;
        memcpy( command + 3, channel->application_id, channel->application_id_size );
        channel->application_id_dirty = 0;
    }
    if (size) memcpy( (char *)batch->data + application_command_size, get_req_data(), size );
    batch->id = ++channel->batch_ids[0];
    batch->synchronization_id = channel->synchronization_id;
    batch->pending_duplicates = channel->pending_batch_duplicates;
    batch->queued = 0;
    batch->received = 0;
    batch->size = size + application_command_size;
    list_add_tail( &channel->batches, &batch->entry );
    channel->synchronization_id = 0;
    channel->pending_batch_duplicates = 0;
    reply->batch_id = batch->id;
    reply->state = 0;
    flush_dcomp_pending_duplicates();
    if (channel->connection) flush_dcomp_channel_batches( channel );

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
    surface->realization = NULL;
    surface->session_id = current->process->session_id;
    if (!(surface->binding_id = next_dcomp_surface_binding_id++))
        surface->binding_id = next_dcomp_surface_binding_id++;
    surface->ink_cookie = 0;
    surface->present_count = 0;
    surface->bind_flags = 0;
    memset( surface->buffer_info, 0, sizeof(surface->buffer_info) );
    if (!(surface->dirty_region = create_empty_region()))
    {
        release_object( surface );
        return;
    }
    surface->bind_shared = 0;
    surface->bound = 0;
    reply->handle = alloc_handle_no_access_check( current->process, surface, req->access, 0 );
    release_object( surface );
}

DECL_HANDLER(set_dcomp_surface_bound)
{
    const unsigned char *info = get_req_data();
    data_size_t info_size = get_req_data_size();
    struct object *realization = NULL;
    struct dcomp_surface *surface;
    obj_handle_t handle = 0;
    unsigned int type = 0;

    if (!(surface = (struct dcomp_surface *)get_handle_obj( current->process, req->handle,
                                                            0, &dcomp_surface_ops ))) return;
    if (surface->owner != current->process || surface->session_id != current->process->session_id)
        set_error( STATUS_ACCESS_DENIED );
    else if (req->bound && info_size != sizeof(surface->buffer_info))
        set_error( STATUS_INVALID_PARAMETER );
    else
    {
        remove_pending_dcomp_surface_updates( surface );
        if (req->bound)
        {
            memcpy( &type, info, sizeof(type) );
            if (type == 1 || type == 2)
            {
                memcpy( &handle, info + 0xa8, sizeof(handle) );
                if (handle && !(realization = get_handle_obj( current->process, handle,
                                                               SECTION_MAP_READ, NULL )))
                    goto done;
            }
            memcpy( surface->buffer_info, info, sizeof(surface->buffer_info) );
            surface->bind_flags = req->flags;
            surface->bind_shared = !!req->shared;
        }
        else
        {
            memset( surface->buffer_info, 0, sizeof(surface->buffer_info) );
            surface->bind_flags = 0;
            surface->bind_shared = 0;
        }
        if (surface->realization) release_object( surface->realization );
        surface->realization = realization;
        realization = NULL;
        surface->bound = !!req->bound;
        surface->present_count = 0;
        {
            const struct rectangle empty = {0};
            set_region_rect( surface->dirty_region, &empty );
        }
        reply->binding_id = surface->binding_id;
    }
done:
    if (realization) release_object( realization );
    release_object( surface );
}

DECL_HANDLER(duplicate_dcomp_surface)
{
    struct dcomp_connection *connection;
    struct dcomp_surface *surface;
    struct process *target;

    if (!(surface = (struct dcomp_surface *)get_handle_obj( current->process, req->handle,
                                                            0, &dcomp_surface_ops ))) return;
    target = current->process;
    if (surface->owner != current->process || surface->session_id != current->process->session_id)
        set_error( STATUS_ACCESS_DENIED );
    else if (req->consumer)
    {
        if (!surface->bound)
            set_error( STATUS_INVALID_PARAMETER );
        else if (!(connection = find_dcomp_consumer_connection( surface->session_id )))
            set_error( STATUS_NOT_FOUND );
        else
            target = connection->owner;
    }
    if (!get_error())
    {
        reply->handle = alloc_handle_no_access_check( target, surface, 0, 0 );
        reply->binding_id = surface->binding_id;
    }
    release_object( surface );
}

DECL_HANDLER(set_dcomp_surface_ink_cookie)
{
    struct dcomp_surface *surface;

    if (!(surface = (struct dcomp_surface *)get_handle_obj( current->process, req->handle,
                                                            0, &dcomp_surface_ops ))) return;
    if (surface->owner != current->process || surface->session_id != current->process->session_id)
        set_error( STATUS_ACCESS_DENIED );
    else
        surface->ink_cookie = req->cookie;
    release_object( surface );
}

DECL_HANDLER(get_dcomp_surface_state)
{
    unsigned char info[0x520];
    struct dcomp_surface *surface;
    obj_handle_t realization = 0;

    if (!(surface = (struct dcomp_surface *)get_handle_obj( current->process, req->handle,
                                                            0, &dcomp_surface_ops ))) return;
    if (req->include_info && !surface->bound)
    {
        set_error( STATUS_NOT_FOUND );
        goto done;
    }
    if (req->include_info) memcpy( info, surface->buffer_info, sizeof(info) );
    if (req->include_info && surface->realization)
    {
        realization = alloc_handle_no_access_check( current->process, surface->realization,
                                                     SECTION_QUERY | SECTION_MAP_READ, 0 );
        if (!realization) goto done;
        if (*(unsigned int *)info == 1)
            memcpy( info + 0xa8, &realization, sizeof(realization) );
    }
    reply->binding_id = surface->binding_id;
    reply->ink_cookie = surface->ink_cookie;
    reply->present_count = surface->present_count;
    reply->bound = surface->bound;
    reply->realization = realization;
    if (req->include_info) set_reply_data( info, sizeof(info) );
done:
    release_object( surface );
}

DECL_HANDLER(open_dcomp_surface_dirty_region)
{
    unsigned char data[0xa4] = {0};
    const struct rectangle empty = {0};
    struct rectangle bounds, *rects;
    struct dcomp_surface *surface;
    data_size_t size = 0;

    if (!(surface = (struct dcomp_surface *)get_handle_obj( current->process, req->handle,
                                                            0, &dcomp_surface_ops ))) return;
    if (!surface->bound || req->binding_id != surface->binding_id || req->realization)
    {
        set_error( STATUS_NOT_FOUND );
        goto done;
    }

    reply->present_count = surface->present_count;
    if (!is_region_empty( surface->dirty_region ))
    {
        if ((rects = get_region_data( surface->dirty_region, 10 * sizeof(*rects), &size )))
        {
            memcpy( data, rects, size );
            free( rects );
            *(unsigned int *)(data + 0xa0) = size / sizeof(*rects);
        }
        else if (get_error() == STATUS_BUFFER_OVERFLOW)
        {
            clear_error();
            get_region_extents( surface->dirty_region, &bounds );
            memcpy( data, &bounds, sizeof(bounds) );
            *(unsigned int *)(data + 0xa0) = 1;
        }
        if (get_error()) goto done;
    }
    set_reply_data( data, sizeof(data) );
    if (!get_error()) set_region_rect( surface->dirty_region, &empty );
done:
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
    struct dcomp_connection *connection;
    struct token_manager *manager;
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
    if (!get_error()) for (i = 0; i < count; ++i)
        if (!get_pending_dcomp_surface_update( token->surfaces[i] )) break;
    if (!get_error()) for (i = 0; i < token->update_count; ++i)
    {
        const struct dcomp_surface_update *update = &token->updates[i];
        struct dcomp_frame_surface_update *frame_update;
        struct rectangle rect = {update->left, update->top, update->right, update->bottom};
        struct region *region;

        if (rect.left >= rect.right || rect.top >= rect.bottom) continue;
        if (!(frame_update = get_pending_dcomp_surface_update( update->surface ))) break;
        if (!(region = create_empty_region())) break;
        set_region_rect( region, &rect );
        if (!get_error())
            union_region( frame_update->dirty_region, frame_update->dirty_region, region );
        if (!get_error())
            union_region( update->surface->dirty_region, update->surface->dirty_region, region );
        free_region( region );
        if (get_error()) break;
    }
    if (!get_error()) for (i = 0; i < count; ++i)
    {
        struct dcomp_frame_surface_update *frame_update;
        struct dcomp_surface *surface = token->surfaces[i];

        if (!(frame_update = find_pending_dcomp_surface_update( surface )))
        {
            set_error( STATUS_UNSUCCESSFUL );
            break;
        }
        if (!++surface->present_count) ++surface->present_count;
        update_dcomp_frame_surface_data( frame_update, surface );
    }
    if (!get_error() && (connection = find_dcomp_consumer_connection( token->session_id )))
    {
        set_event( connection->work_event );
        if ((manager = get_token_manager( token->session_id ))) set_event( manager->event_a );
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
    ensure_dwm_window_context( req->window );
    if (!(target = alloc_object( &dcomp_window_target_ops ))) return;
    target->owner = (struct process *)grab_object( current->process );
    target->system_resource = NULL;
    target->window = req->window;
    target->type = req->type;
    target->attached = 0;
    if (!(target->system_resource = create_dcomp_system_resource( current->process, 0xb8 )))
    {
        release_object( target );
        return;
    }
    target->attached = 1;
    list_add_tail( &dcomp_window_targets, &target->entry );
    add_dwm_window_target( target->window, target->type );
    reply->handle = alloc_handle_no_access_check( current->process, target, 0, 0 );
    if (!reply->handle ||
        !notify_dwm_window_target_created( current->process->session_id, target->window,
                                           target->type, &target->obj ))
    {
        if (reply->handle)
        {
            close_handle( current->process, reply->handle );
            reply->handle = 0;
        }
        detach_dcomp_window_target( target, 0 );
    }
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
    detach_dcomp_window_target( target, 1 );
}

DECL_HANDLER(open_dcomp_shared_resource)
{
    struct dcomp_shared_resource *resource;
    struct dcomp_window_target_duplicate *duplicate;
    struct dcomp_window_target *window_target;
    struct dcomp_channel *channel;
    struct object *obj;

    reply->window_target = 0;

    if (!(obj = get_handle_obj( current->process, req->handle, 0, NULL ))) return;
    if (!(channel = get_dcomp_channel( req->channel ))) goto done;

    if (obj->ops == &dcomp_window_target_ops)
    {
        window_target = (struct dcomp_window_target *)obj;
        if (req->type != 0xb8)
            set_error( STATUS_INVALID_PARAMETER );
        else if (!window_target->attached ||
                 (window_target->owner != current->process &&
                  (!current->process->native_dwm_owner ||
                   window_target->owner->session_id != current->process->session_id)))
            set_error( STATUS_ACCESS_DENIED );
        else if (!req->resource)
            set_error( STATUS_INVALID_PARAMETER );
        else if (!channel->connection && current->process->native_dwm_owner &&
                 !attach_internal_dcomp_channel( channel ))
            goto done_channel;
        else if (begin_dcomp_system_resource_duplicate( window_target->system_resource,
                                                         channel ))
            reply->window_target = 1;
    }
    else if (obj->ops == &dcomp_shared_resource_ops)
    {
        resource = (struct dcomp_shared_resource *)obj;
        if (resource->type != req->type ||
            resource->session_id != channel->owner->session_id)
            set_error( STATUS_INVALID_PARAMETER );
        else if (!req->resource)
            set_error( STATUS_INVALID_PARAMETER );
        else if (resource->system_resource)
        {
            if (begin_dcomp_system_resource_duplicate( resource->system_resource, channel ))
                reply->window_target = 1;
        }
        else if (!resource->channel)
        {
            /* A standalone shared-resource handle acquires its canonical MIL
             * identity on the first channel that opens it.  Only later opens
             * duplicate that identity into another channel. */
            resource->channel = (struct dcomp_channel *)grab_object( channel );
            resource->resource = req->resource;
            resource->source_batch_id = channel->batch_ids[0] + 1;
            reply->window_target = 2;
        }
        else
        {
            if (!(duplicate = mem_alloc( sizeof(*duplicate) ))) goto done_channel;
            duplicate->source = resource->channel;
            duplicate->source_resource = resource->resource;
            duplicate->source_batch_id = resource->source_batch_id;
            duplicate->channel = channel;
            duplicate->batch_id = channel->batch_ids[0] + 1;
            duplicate->sequence = ++channel->next_duplicate_sequence;
            duplicate->source_ready = resource->source_ready;
            duplicate->begun = 0;
            channel->pending_batch_duplicates++;
            list_add_tail( &dcomp_pending_duplicates, &duplicate->entry );
            if (!flush_dcomp_pending_duplicates()) goto done_channel;
            reply->window_target = 1;
        }
    }
    else set_error( STATUS_OBJECT_TYPE_MISMATCH );

done_channel:
    release_object( channel );
done:
    release_object( obj );
}
