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

#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "ntstatus.h"
#include "win32u_private.h"
#include "ntuser_private.h"
#include "wine/server.h"

WINE_DEFAULT_DEBUG_CHANNEL(dcomp);

C_ASSERT( sizeof(struct dcomposition_frame_statistics) == 40 );
C_ASSERT( sizeof(struct dcomposition_capability_info) == 20 );
C_ASSERT( sizeof(struct dcomposition_connection_batch) == 40 );
C_ASSERT( offsetof(struct dcomposition_connection_batch, next) == 8 );
C_ASSERT( offsetof(struct dcomposition_connection_batch, u.create.channel) == 16 );
C_ASSERT( offsetof(struct dcomposition_connection_batch, u.create.connection) == 24 );
C_ASSERT( offsetof(struct dcomposition_connection_batch, u.create.object) == 32 );
#ifdef _WIN64
C_ASSERT( sizeof(struct dcomposition_frame_info) == 160 );
C_ASSERT( sizeof(struct dcomposition_confirm_frame_info) == 56 );
C_ASSERT( sizeof(struct token_manager_adapter_info) == 24 );
C_ASSERT( sizeof(struct token_manager_thread_info) == 24 );
#endif

struct dcomp_channel_view
{
    struct list entry;
    struct list resources;
    UINT channel;
    void *address;
    SIZE_T size;
    BOOL released_resources;
};

struct dcomp_resource_view
{
    struct list entry;
    UINT id;
    UINT type;
    UINT references;
    struct dcomp_resource_view *root;
    struct dcomp_resource_view *parent;
    struct dcomp_resource_view *first_child;
    struct dcomp_resource_view *next_sibling;
    BOOL announced;
    BOOL client_released;
    BOOL released;
    BOOL visual;
    BOOL visual_target;
    BOOL root_dirty;
    BOOL children_clear_dirty;
    BOOL connection_announced;
    BOOL remove_dirty;
    UINT remove_parent_id;
    INT visual_mode_8;
    INT visual_mode_9;
    INT visual_mode_10;
    INT visual_mode_14;
    INT visual_mode_15;
    INT visual_mode_16;
    BYTE visual_flags_134;
    BYTE visual_flags_135;
    BOOL visual_modes_dirty;
    BOOL visual_flags_dirty;
    BOOL visual_relative_size_dirty;
    BOOL visual_size_dirty;
    float visual_relative_size[2];
    float visual_size[2];
    BOOL shared_section_bound;
    BOOL shared_section_announced;
};

struct dcomp_connection_batch_view
{
    struct list entry;
    HANDLE connection;
    struct dcomposition_connection_batch *batch;
};

struct dcomp_protocol_block_header
{
    const void *next;
    const void *previous;
    UINT type;
    UINT size;
};

#define DCOMP_PROTOCOL_MAX_SIZE 0x10000
#define DCOMP_PROTOCOL_MAX_BLOCKS 4096

static pthread_mutex_t dcomp_channel_lock = PTHREAD_MUTEX_INITIALIZER;
static struct list dcomp_channel_views = LIST_INIT( dcomp_channel_views );
static struct list dcomp_connection_batch_views = LIST_INIT( dcomp_connection_batch_views );

static void set_last_status( NTSTATUS status )
{
    NtCurrentTeb()->LastStatusValue = status;
    RtlSetLastWin32Error( RtlNtStatusToDosError( status ) );
}

static struct dcomp_channel_view *find_dcomp_channel_view( UINT channel )
{
    struct dcomp_channel_view *view;

    LIST_FOR_EACH_ENTRY( view, &dcomp_channel_views, struct dcomp_channel_view, entry )
        if (view->channel == channel) return view;
    return NULL;
}

static struct dcomp_resource_view *find_dcomp_resource_view( struct dcomp_channel_view *view, UINT id )
{
    struct dcomp_resource_view *resource;

    LIST_FOR_EACH_ENTRY( resource, &view->resources, struct dcomp_resource_view, entry )
        if (resource->id == id && !resource->client_released) return resource;
    return NULL;
}

static void release_dcomp_resource_reference( struct dcomp_resource_view *resource )
{
    struct dcomp_resource_view *child, *root;
    BOOL clear_children = FALSE;

    if (--resource->references) return;

    if ((root = resource->root))
    {
        resource->root = NULL;
        resource->root_dirty = TRUE;
        release_dcomp_resource_reference( root );
    }
    while ((child = resource->first_child))
    {
        resource->first_child = child->next_sibling;
        child->next_sibling = NULL;
        child->parent = NULL;
        if (child->connection_announced) clear_children = TRUE;
        child->connection_announced = FALSE;
        release_dcomp_resource_reference( child );
    }
    if (clear_children) resource->children_clear_dirty = TRUE;
    resource->released = TRUE;
}

static void remove_unannounced_dcomp_resources( struct dcomp_channel_view *view )
{
    struct dcomp_resource_view *resource, *next;

    LIST_FOR_EACH_ENTRY_SAFE( resource, next, &view->resources, struct dcomp_resource_view, entry )
    {
        if (!resource->announced && resource->released)
        {
            list_remove( &resource->entry );
            free( resource );
        }
    }
}

static BOOL is_dcomp_visual_resource_type( UINT type )
{
    /* Descendants of MIL_RESOURCE_TYPE 0xb8 in the Windows resource-parent table. */
    switch (type)
    {
    case 0x32:
    case 0x5d:
    case 0x81:
    case 0x9a:
    case 0x9c:
    case 0xa6:
    case 0xa7:
    case 0xad:
    case 0xb8:
    case 0xc0:
        return TRUE;
    default:
        return FALSE;
    }
}

static void initialize_dcomp_resource_view( struct dcomp_resource_view *resource,
                                             UINT id, UINT type )
{
    resource->id = id;
    resource->type = type;
    resource->references = 1;
    resource->visual = is_dcomp_visual_resource_type( type );
}

static NTSTATUS add_dcomp_visual_child( struct dcomp_channel_view *view,
                                        UINT parent_id, UINT child_id,
                                        INT insert_after, UINT reference_id )
{
    struct dcomp_resource_view *parent, *child, *reference = NULL, **cursor;

    if (!(parent = find_dcomp_resource_view( view, parent_id )) ||
        !(child = find_dcomp_resource_view( view, child_id )))
        return STATUS_ACCESS_DENIED;
    if (!parent->visual || !child->visual || child->parent) return STATUS_INVALID_PARAMETER;
    if (reference_id)
    {
        if (!(reference = find_dcomp_resource_view( view, reference_id )))
            return STATUS_ACCESS_DENIED;
        if (!reference->visual || reference->parent != parent) return STATUS_INVALID_PARAMETER;
    }

    if (insert_after)
    {
        if (reference)
        {
            child->next_sibling = reference->next_sibling;
            reference->next_sibling = child;
        }
        else
        {
            child->next_sibling = parent->first_child;
            parent->first_child = child;
        }
    }
    else
    {
        cursor = &parent->first_child;
        while (*cursor != reference) cursor = &(*cursor)->next_sibling;
        child->next_sibling = reference;
        *cursor = child;
    }
    child->parent = parent;
    child->references++;
    return STATUS_SUCCESS;
}

static void detach_dcomp_visual_child( struct dcomp_resource_view *parent,
                                        struct dcomp_resource_view *child,
                                        struct dcomp_resource_view **cursor )
{
    *cursor = child->next_sibling;
    child->next_sibling = NULL;
    child->parent = NULL;
    if (child->connection_announced)
    {
        child->remove_dirty = TRUE;
        child->remove_parent_id = parent->id;
        child->connection_announced = FALSE;
    }
    release_dcomp_resource_reference( child );
}

static NTSTATUS remove_dcomp_visual_child( struct dcomp_channel_view *view,
                                           UINT parent_id, UINT child_id )
{
    struct dcomp_resource_view *parent, *child, **cursor;
    BOOL clear_children = FALSE;

    if (!(parent = find_dcomp_resource_view( view, parent_id ))) return STATUS_ACCESS_DENIED;
    if (!parent->visual) return STATUS_INVALID_PARAMETER;

    cursor = &parent->first_child;
    if (child_id)
    {
        if (!(child = find_dcomp_resource_view( view, child_id ))) return STATUS_ACCESS_DENIED;
        while (*cursor && *cursor != child) cursor = &(*cursor)->next_sibling;
        if (!*cursor) return STATUS_INVALID_PARAMETER;
        detach_dcomp_visual_child( parent, child, cursor );
    }
    else
    {
        while ((child = *cursor))
        {
            if (child->connection_announced) clear_children = TRUE;
            *cursor = child->next_sibling;
            child->next_sibling = NULL;
            child->parent = NULL;
            child->connection_announced = FALSE;
            release_dcomp_resource_reference( child );
        }
        if (clear_children) parent->children_clear_dirty = TRUE;
    }
    remove_unannounced_dcomp_resources( view );
    return STATUS_SUCCESS;
}

static NTSTATUS set_dcomp_visual_integer_property( struct dcomp_resource_view *resource,
                                                    UINT property, INT64 value )
{
    INT int_value = value;

    switch (property)
    {
    case 8:
        if ((value < -1 || value > 1) && value != 6) return STATUS_INVALID_PARAMETER;
        if (resource->visual_mode_8 == int_value) return STATUS_SUCCESS;
        resource->visual_mode_8 = int_value;
        resource->visual_modes_dirty = TRUE;
        break;
    case 9:
        if (value < -1 || value > 1) return STATUS_INVALID_PARAMETER;
        if (resource->visual_mode_9 == int_value) return STATUS_SUCCESS;
        resource->visual_mode_9 = int_value;
        resource->visual_modes_dirty = TRUE;
        break;
    case 0xe:
        if (value < -1 || value > 1) return STATUS_INVALID_PARAMETER;
        if (resource->visual_mode_14 == int_value) return STATUS_SUCCESS;
        resource->visual_mode_14 = int_value;
        resource->visual_modes_dirty = TRUE;
        break;
    case 0x1b:
        if (!!value == !!(resource->visual_flags_134 & 8)) return STATUS_SUCCESS;
        if (value) resource->visual_flags_134 |= 8;
        else resource->visual_flags_134 &= ~8;
        resource->visual_flags_dirty = TRUE;
        break;
    case 0x25:
        if (!!value == !!(resource->visual_flags_134 & 0x10)) return STATUS_SUCCESS;
        if (value) resource->visual_flags_134 |= 0x10;
        else resource->visual_flags_134 &= ~0x10;
        resource->visual_flags_dirty = TRUE;
        break;
    default:
        return STATUS_NOT_SUPPORTED;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS set_dcomp_visual_buffer_property( struct dcomp_resource_view *resource,
                                                   UINT property, const BYTE *data, UINT size )
{
    if (property == 0x1d && size == sizeof(resource->visual_size))
    {
        if (!memcmp( resource->visual_size, data, size )) return STATUS_SUCCESS;
        memcpy( resource->visual_size, data, size );
        resource->visual_size_dirty = TRUE;
        return STATUS_SUCCESS;
    }
    if (property == 0x1f && size == sizeof(resource->visual_relative_size))
    {
        if (!memcmp( resource->visual_relative_size, data, size )) return STATUS_SUCCESS;
        memcpy( resource->visual_relative_size, data, size );
        resource->visual_relative_size_dirty = TRUE;
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS set_dcomp_visual_target_root( struct dcomp_channel_view *view,
                                               struct dcomp_resource_view *target,
                                               UINT property, UINT root_id )
{
    struct dcomp_resource_view *root = NULL, *previous;

    if (property != 0x34) return STATUS_INVALID_PARAMETER;
    if (root_id)
    {
        if (!(root = find_dcomp_resource_view( view, root_id ))) return STATUS_ACCESS_DENIED;
        if (!is_dcomp_visual_resource_type( root->type )) return STATUS_INVALID_PARAMETER;
        root->references++;
    }

    previous = target->root;
    target->root = root;
    target->root_dirty = TRUE;
    if (previous) release_dcomp_resource_reference( previous );
    remove_unannounced_dcomp_resources( view );
    return STATUS_SUCCESS;
}

static struct dcomp_resource_view *find_any_dcomp_resource_view( struct dcomp_channel_view *view,
                                                                 UINT id )
{
    struct dcomp_resource_view *resource;

    LIST_FOR_EACH_ENTRY( resource, &view->resources, struct dcomp_resource_view, entry )
        if (resource->id == id) return resource;
    return NULL;
}

static NTSTATUS release_dcomp_shared_section( UINT channel, UINT resource )
{
    NTSTATUS status;

    SERVER_START_REQ( release_dcomp_shared_section )
    {
        req->channel = channel;
        req->resource = resource;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}

static NTSTATUS get_dcomp_shared_section_update( UINT channel, UINT resource,
                                                  UINT64 *section, UINT64 *size )
{
    NTSTATUS status;

    *section = 0;
    *size = 0;
    SERVER_START_REQ( get_dcomp_shared_section_update )
    {
        req->channel = channel;
        req->resource = resource;
        status = wine_server_call( req );
        if (!status)
        {
            *section = (UINT_PTR)wine_server_ptr_handle( reply->section );
            *size = reply->size;
        }
    }
    SERVER_END_REQ;
    return status;
}

static void free_dcomp_resource_views( struct dcomp_channel_view *view )
{
    struct dcomp_resource_view *resource, *next;

    LIST_FOR_EACH_ENTRY_SAFE( resource, next, &view->resources, struct dcomp_resource_view, entry )
    {
        list_remove( &resource->entry );
        free( resource );
    }
}

static BOOL dcomp_command_size( const BYTE *buffer, UINT remaining, UINT *size )
{
    UINT count, type, total;

    if (remaining < sizeof(type)) return FALSE;
    memcpy( &type, buffer, sizeof(type) );
    switch (type)
    {
    case 0:   total = 24; break; /* indirect command buffer */
    case 1:   total = 8; break;  /* activate trigger */
    case 2:   total = 16; break; /* create resource */
    case 3:   total = 24; break; /* open shared resource */
    case 4:   total = 8; break;  /* release resource */
    case 5:   total = 16; break; /* channel property */
    case 6:   total = 24; break;
    case 7:   total = 24; break;
    case 8:   total = 12; break;
    case 9:   total = 16; break;
    case 10:  total = 12; break;
    case 11:  total = 24; break;
    case 12:  total = 16; break;
    case 13:  total = 24; break;
    case 14:
        if (remaining < 16) return FALSE;
        memcpy( &count, buffer + 12, sizeof(count) );
        if (count > (UINT_MAX - 16) / 8) return FALSE;
        total = 16 + count * 8;
        break;
    case 15:
        if (remaining < 16) return FALSE;
        memcpy( &count, buffer + 12, sizeof(count) );
        if (count > UINT_MAX - 3) return FALSE;
        count = (count + 3) & ~3u;
        if (count > UINT_MAX - 16) return FALSE;
        total = 16 + count;
        break;
    case 16:  total = 16; break;
    case 17:
        if (remaining < 16) return FALSE;
        memcpy( &count, buffer + 12, sizeof(count) );
        if (count > (UINT_MAX - 16) / 4) return FALSE;
        total = 16 + count * 4;
        break;
    case 18:  total = 16; break;
    case 19:  total = 16; break;
    case 20:  total = 20; break;
    case 21:  total = 72; break;
    case 22:  total = 16; break;
    case 23:  total = 12; break;
    default: return FALSE;
    }
    if (total > remaining) return FALSE;
    *size = total;
    return TRUE;
}

static NTSTATUS validate_dcomp_window_target( HANDLE handle, UINT resource_type )
{
    NTSTATUS status;

    SERVER_START_REQ( validate_dcomp_window_target )
    {
        req->handle = wine_server_obj_handle( handle );
        req->resource_type = resource_type;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}

static NTSTATUS process_dcomp_commands( struct dcomp_channel_view *view, const BYTE *buffer,
                                        UINT length, BOOL allow_indirect, ULONG *processed )
{
    struct dcomp_resource_view *resource;
    UINT command_size, id, indirect_size, type;
    const BYTE *indirect;
    NTSTATUS status;

    while (length)
    {
        ++*processed;
        if (!dcomp_command_size( buffer, length, &command_size )) return STATUS_INVALID_PARAMETER;
        memcpy( &type, buffer, sizeof(type) );

        if (!type)
        {
            if (!allow_indirect) return STATUS_INVALID_PARAMETER;
            memcpy( &indirect, buffer + 8, sizeof(indirect) );
            memcpy( &indirect_size, buffer + 16, sizeof(indirect_size) );
            if (!indirect || !indirect_size) return STATUS_INVALID_PARAMETER;
            status = process_dcomp_commands( view, indirect, indirect_size, FALSE, processed );
            if (status) return status;
        }
        else if (type == 2)
        {
            memcpy( &id, buffer + 4, sizeof(id) );
            memcpy( &type, buffer + 8, sizeof(type) );
            if (!id || !type || type > 0xc1) return STATUS_INVALID_PARAMETER;
            if (find_any_dcomp_resource_view( view, id )) return STATUS_ACCESS_DENIED;
            if (!(resource = calloc( 1, sizeof(*resource) ))) return STATUS_NO_MEMORY;
            initialize_dcomp_resource_view( resource, id, type );
            list_add_tail( &view->resources, &resource->entry );
        }
        else if (type == 3)
        {
            HANDLE handle;
            UINT resource_type;

            memcpy( &id, buffer + 4, sizeof(id) );
            memcpy( &handle, buffer + 8, sizeof(handle) );
            memcpy( &resource_type, buffer + 16, sizeof(resource_type) );
            if (!id || !handle || !resource_type) return STATUS_INVALID_PARAMETER;
            if (find_any_dcomp_resource_view( view, id )) return STATUS_ACCESS_DENIED;
            if (resource_type == 0xb8 &&
                (status = validate_dcomp_window_target( handle, resource_type ))) return status;
            if (!(resource = calloc( 1, sizeof(*resource) ))) return STATUS_NO_MEMORY;
            initialize_dcomp_resource_view( resource, id, resource_type );
            resource->visual_target = resource_type == 0xb8;
            if (resource->visual_target) resource->visual = FALSE;
            list_add_tail( &view->resources, &resource->entry );
        }
        else if (type == 4)
        {
            memcpy( &id, buffer + 4, sizeof(id) );
            if (!(resource = find_dcomp_resource_view( view, id ))) return STATUS_ACCESS_DENIED;
            if (resource->shared_section_bound)
            {
                status = release_dcomp_shared_section( view->channel, resource->id );
                if (status) return status;
                resource->shared_section_bound = FALSE;
            }
            resource->client_released = TRUE;
            release_dcomp_resource_reference( resource );
            remove_unannounced_dcomp_resources( view );
            view->released_resources = TRUE;
        }
        else if (type == 11)
        {
            INT64 value;
            UINT property;

            memcpy( &id, buffer + 4, sizeof(id) );
            memcpy( &property, buffer + 8, sizeof(property) );
            memcpy( &value, buffer + 16, sizeof(value) );
            if (!(resource = find_dcomp_resource_view( view, id ))) return STATUS_ACCESS_DENIED;
            if (resource->visual)
            {
                status = set_dcomp_visual_integer_property( resource, property, value );
                if (status != STATUS_NOT_SUPPORTED && status) return status;
            }
        }
        else if (type == 15)
        {
            UINT property, size;

            memcpy( &id, buffer + 4, sizeof(id) );
            memcpy( &property, buffer + 8, sizeof(property) );
            memcpy( &size, buffer + 12, sizeof(size) );
            if (!(resource = find_dcomp_resource_view( view, id ))) return STATUS_ACCESS_DENIED;
            if (resource->visual)
            {
                status = set_dcomp_visual_buffer_property( resource, property, buffer + 16, size );
                if (status != STATUS_NOT_SUPPORTED && status) return status;
            }
        }
        else if (type == 16)
        {
            UINT property, root_id;

            memcpy( &id, buffer + 4, sizeof(id) );
            memcpy( &property, buffer + 8, sizeof(property) );
            memcpy( &root_id, buffer + 12, sizeof(root_id) );
            if (!(resource = find_dcomp_resource_view( view, id ))) return STATUS_ACCESS_DENIED;
            if (resource->visual_target &&
                (status = set_dcomp_visual_target_root( view, resource, property, root_id )))
                return status;
        }
        else if (type == 20)
        {
            UINT child_id, insert_after, reference_id;

            memcpy( &id, buffer + 4, sizeof(id) );
            memcpy( &child_id, buffer + 8, sizeof(child_id) );
            memcpy( &insert_after, buffer + 12, sizeof(insert_after) );
            memcpy( &reference_id, buffer + 16, sizeof(reference_id) );
            if ((status = add_dcomp_visual_child( view, id, child_id,
                                                   insert_after, reference_id )))
                return status;
        }
        else if (type == 23)
        {
            UINT child_id;

            memcpy( &id, buffer + 4, sizeof(id) );
            memcpy( &child_id, buffer + 8, sizeof(child_id) );
            if ((status = remove_dcomp_visual_child( view, id, child_id ))) return status;
        }
        else if (type >= 6 && type <= 23)
        {
            memcpy( &id, buffer + 4, sizeof(id) );
            if (!find_dcomp_resource_view( view, id )) return STATUS_ACCESS_DENIED;
        }

        buffer += command_size;
        length -= command_size;
    }
    return STATUS_SUCCESS;
}

static struct dcomp_connection_batch_view *find_dcomp_connection_batch_view( HANDLE connection )
{
    struct dcomp_connection_batch_view *view;

    LIST_FOR_EACH_ENTRY( view, &dcomp_connection_batch_views, struct dcomp_connection_batch_view, entry )
        if (view->connection == connection) return view;
    return NULL;
}

static NTSTATUS copy_dcomp_protocol_blocks( const void *list, BYTE **data,
                                             data_size_t *data_size )
{
    struct dcomp_protocol_block_header header;
    const void *next;
    BYTE *new_data;
    SIZE_T size = 0;
    UINT count = 0;
    NTSTATUS status = STATUS_SUCCESS;

    *data = NULL;
    *data_size = 0;
    if (!list) return STATUS_SUCCESS;

    __TRY
    {
        memcpy( &next, list, sizeof(next) );
    }
    __EXCEPT
    {
        return STATUS_INVALID_PARAMETER;
    }
    __ENDTRY

    while (next != list)
    {
        if (!next || count++ == DCOMP_PROTOCOL_MAX_BLOCKS)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        __TRY
        {
            memcpy( &header, next, sizeof(header) );
        }
        __EXCEPT
        {
            status = STATUS_INVALID_PARAMETER;
        }
        __ENDTRY
        if (status) break;
        if (header.type != 0x200)
        {
            status = STATUS_NOT_SUPPORTED;
            break;
        }
        if (header.size < 8 || (header.size & 3) ||
            header.size > DCOMP_PROTOCOL_MAX_SIZE - size)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (!(new_data = realloc( *data, size + header.size )))
        {
            status = STATUS_NO_MEMORY;
            break;
        }
        *data = new_data;
        __TRY
        {
            memcpy( new_data + size, (const BYTE *)next + sizeof(header), header.size );
        }
        __EXCEPT
        {
            status = STATUS_INVALID_PARAMETER;
        }
        __ENDTRY
        if (status) break;
        size += header.size;
        next = header.next;
    }

    if (status)
    {
        free( *data );
        *data = NULL;
        return status;
    }
    *data_size = size;
    return STATUS_SUCCESS;
}

static NTSTATUS build_dcomp_commit_payload( struct dcomp_channel_view *view,
                                             BYTE **data, data_size_t *data_size )
{
    struct dcomp_resource_view *child, *resource;
    data_size_t resource_size = 0;
    BYTE *new_data, *cursor;
    NTSTATUS status;

    LIST_FOR_EACH_ENTRY( resource, &view->resources, struct dcomp_resource_view, entry )
    {
        if (!resource->announced) resource_size += 16;
        if (resource->shared_section_bound && !resource->shared_section_announced &&
            !resource->released) resource_size += 28;
        if (resource->remove_dirty) resource_size += 16;
        if (resource->root_dirty) resource_size += 12 + (resource->root ? 24 : 0);
        if (resource->children_clear_dirty) resource_size += 12;
        for (child = resource->first_child; child; child = child->next_sibling)
            if (!child->connection_announced) resource_size += 24;
        if (resource->visual_modes_dirty) resource_size += 52;
        if (resource->visual_flags_dirty) resource_size += 16;
        if (resource->visual_relative_size_dirty) resource_size += 20;
        if (resource->visual_size_dirty) resource_size += 20;
        if (resource->released) resource_size += 12;
    }
    if (resource_size > DCOMP_PROTOCOL_MAX_SIZE - *data_size) return STATUS_INVALID_PARAMETER;
    if (!resource_size) return STATUS_SUCCESS;
    if (!(new_data = malloc( resource_size + *data_size ))) return STATUS_NO_MEMORY;

    cursor = new_data;
    LIST_FOR_EACH_ENTRY( resource, &view->resources, struct dcomp_resource_view, entry )
    {
        UINT command[4];

        if (resource->announced || resource->released) continue;
        command[0] = sizeof(command);
        command[1] = 0x28; /* MILCMD_CHANNEL_CREATERESOURCE */
        command[2] = resource->id;
        command[3] = resource->type;
        memcpy( cursor, command, sizeof(command) );
        cursor += sizeof(command);
    }
    LIST_FOR_EACH_ENTRY( resource, &view->resources, struct dcomp_resource_view, entry )
    {
        UINT64 section, section_size;
        UINT value;

        if (!resource->shared_section_bound || resource->shared_section_announced ||
            resource->released) continue;
        if ((status = get_dcomp_shared_section_update( view->channel, resource->id,
                                                        &section, &section_size )))
        {
            free( new_data );
            return status;
        }
        memset( cursor, 0, 28 );
        value = 28;
        memcpy( cursor, &value, sizeof(value) );
        value = 0x1d1; /* MILCMD_SHAREDSECTION_UPDATE */
        memcpy( cursor + 4, &value, sizeof(value) );
        memcpy( cursor + 8, &resource->id, sizeof(resource->id) );
        memcpy( cursor + 12, &section, sizeof(section) );
        value = (UINT)section_size;
        memcpy( cursor + 20, &value, sizeof(value) );
        cursor += 28;
    }
    LIST_FOR_EACH_ENTRY( resource, &view->resources, struct dcomp_resource_view, entry )
    {
        UINT command[4];

        if (!resource->remove_dirty) continue;
        command[0] = sizeof(command);
        command[1] = 0x188; /* MILCMD_VISUAL_REMOVECHILD */
        command[2] = resource->remove_parent_id;
        command[3] = resource->id;
        memcpy( cursor, command, sizeof(command) );
        cursor += sizeof(command);
    }
    LIST_FOR_EACH_ENTRY( resource, &view->resources, struct dcomp_resource_view, entry )
    {
        UINT command[6] = {12, 0x187, resource->id};

        if (resource->root_dirty)
        {
            memcpy( cursor, command, 12 );
            cursor += 12;
            if (resource->root)
            {
                command[0] = sizeof(command);
                command[1] = 0x185;
                command[2] = resource->id;
                command[3] = resource->root->id;
                command[4] = 0;
                command[5] = 1;
                memcpy( cursor, command, sizeof(command) );
                cursor += sizeof(command);
            }
        }
        if (resource->children_clear_dirty)
        {
            command[0] = 12;
            command[1] = 0x187; /* MILCMD_VISUAL_REMOVEALLCHILDREN */
            command[2] = resource->id;
            memcpy( cursor, command, 12 );
            cursor += 12;
        }
    }
    LIST_FOR_EACH_ENTRY( resource, &view->resources, struct dcomp_resource_view, entry )
    {
        UINT previous_id = 0;

        for (child = resource->first_child; child; child = child->next_sibling)
        {
            UINT command[6] = {24, 0x185, resource->id, child->id, previous_id, 1};

            if (!child->connection_announced)
            {
                memcpy( cursor, command, sizeof(command) );
                cursor += sizeof(command);
            }
            previous_id = child->id;
        }
    }
    LIST_FOR_EACH_ENTRY( resource, &view->resources, struct dcomp_resource_view, entry )
    {
        if (resource->visual_modes_dirty)
        {
            UINT command[13] = {52, 0x19c, resource->id, 0x7e,
                                resource->visual_mode_8, resource->visual_mode_9, 0, 0,
                                resource->visual_mode_10, resource->visual_mode_14,
                                resource->visual_mode_15, resource->visual_mode_16, 0};

            memcpy( cursor, command, sizeof(command) );
            cursor += sizeof(command);
        }
        if (resource->visual_flags_dirty)
        {
            UINT flags = (!!(resource->visual_flags_134 & 0x10)) |
                         ((!!(resource->visual_flags_134 & 8)) << 8) |
                         ((!!(resource->visual_flags_135 & 1)) << 16) |
                         ((!!(resource->visual_flags_135 & 2)) << 24);
            UINT command[4] = {16, 0x197, resource->id, flags};

            memcpy( cursor, command, sizeof(command) );
            cursor += sizeof(command);
        }
        if (resource->visual_relative_size_dirty)
        {
            UINT command[5] = {20, 0x19b, resource->id};

            memcpy( command + 3, resource->visual_relative_size,
                    sizeof(resource->visual_relative_size) );
            memcpy( cursor, command, sizeof(command) );
            cursor += sizeof(command);
        }
        if (resource->visual_size_dirty)
        {
            UINT command[5] = {20, 0x19e, resource->id};

            memcpy( command + 3, resource->visual_size, sizeof(resource->visual_size) );
            memcpy( cursor, command, sizeof(command) );
            cursor += sizeof(command);
        }
    }
    memcpy( cursor, *data, *data_size );
    cursor += *data_size;
    LIST_FOR_EACH_ENTRY( resource, &view->resources, struct dcomp_resource_view, entry )
    {
        UINT command[3];

        if (!resource->announced || !resource->released) continue;
        command[0] = sizeof(command);
        command[1] = 0x29; /* MILCMD_CHANNEL_RELEASERESOURCE */
        command[2] = resource->id;
        memcpy( cursor, command, sizeof(command) );
        cursor += sizeof(command);
    }
    free( *data );
    *data = new_data;
    *data_size += resource_size;
    return STATUS_SUCCESS;
}

static void commit_dcomp_resource_views( struct dcomp_channel_view *view )
{
    struct dcomp_resource_view *resource, *next;

    LIST_FOR_EACH_ENTRY( resource, &view->resources, struct dcomp_resource_view, entry )
        if (resource->parent) resource->connection_announced = TRUE;

    LIST_FOR_EACH_ENTRY_SAFE( resource, next, &view->resources, struct dcomp_resource_view, entry )
    {
        if (resource->released)
        {
            list_remove( &resource->entry );
            free( resource );
        }
        else
        {
            resource->announced = TRUE;
            resource->remove_dirty = FALSE;
            resource->root_dirty = FALSE;
            resource->children_clear_dirty = FALSE;
            resource->visual_modes_dirty = FALSE;
            resource->visual_flags_dirty = FALSE;
            resource->visual_relative_size_dirty = FALSE;
            resource->visual_size_dirty = FALSE;
            if (resource->shared_section_bound) resource->shared_section_announced = TRUE;
        }
    }
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

BOOL WINAPI NtUserRegisterSessionPort( HANDLE port )
{
    BOOL ret;

    TRACE( "port %p\n", port );
    SERVER_START_REQ( register_dwm_session_port )
    {
        req->handle = wine_server_obj_handle( port );
        ret = !wine_server_call_err( req );
    }
    SERVER_END_REQ;
    return ret;
}

BOOL WINAPI NtUserCreateDCompositionHwndTarget( HWND hwnd, UINT type, HANDLE *handle )
{
    HANDLE target = NULL;
    NTSTATUS status;

    TRACE( "hwnd %p, type %u, handle %p\n", hwnd, type, handle );

    if (!handle || type > 2)
    {
        set_last_status( STATUS_INVALID_PARAMETER );
        return FALSE;
    }
    SERVER_START_REQ( create_dcomp_window_target )
    {
        req->window = wine_server_user_handle( hwnd );
        req->type = type;
        status = wine_server_call( req );
        if (!status) target = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    if (status)
    {
        set_last_status( status );
        return FALSE;
    }
    __TRY
    {
        *handle = target;
    }
    __EXCEPT
    {
        status = STATUS_INVALID_PARAMETER;
    }
    __ENDTRY
    if (status)
    {
        NtUserDestroyDCompositionHwndTarget( hwnd, type );
        NtClose( target );
        set_last_status( status );
        return FALSE;
    }
    return TRUE;
}

BOOL WINAPI NtUserDestroyDCompositionHwndTarget( HWND hwnd, UINT type )
{
    NTSTATUS status;

    TRACE( "hwnd %p, type %u\n", hwnd, type );

    SERVER_START_REQ( destroy_dcomp_window_target )
    {
        req->window = wine_server_user_handle( hwnd );
        req->type = type;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    if (status) set_last_status( status );
    return !status;
}

BOOL WINAPI NtUserDwmKernelStartup(void)
{
    BOOL ret;

    TRACE( "\n" );
    SERVER_START_REQ( start_dwm_kernel )
    {
        ret = !wine_server_call_err( req );
    }
    SERVER_END_REQ;
    return ret;
}

BOOL WINAPI NtUserDwmKernelShutdown(void)
{
    BOOL ret;

    TRACE( "\n" );
    SERVER_START_REQ( stop_dwm_kernel )
    {
        ret = !wine_server_call_err( req );
    }
    SERVER_END_REQ;
    return ret;
}

BOOL WINAPI NtKSTInitialize( HANDLE stop_event, HANDLE update_event )
{
    struct user_thread_info *info = get_user_thread_info();
    BOOL ret;

    TRACE( "stop_event %p, update_event %p\n", stop_event, update_event );

    SERVER_START_REQ( initialize_kst )
    {
        req->stop_event = wine_server_obj_handle( stop_event );
        req->update_event = wine_server_obj_handle( update_event );
        ret = !wine_server_call_err( req );
    }
    SERVER_END_REQ;
    if (!ret) return FALSE;

    info->kst_events[0] = stop_event;
    info->kst_events[1] = update_event;
    info->kst_initialized = TRUE;
    return TRUE;
}

UINT WINAPI NtKSTWait(void)
{
    struct user_thread_info *info = get_user_thread_info();
    NTSTATUS status;

    TRACE( "\n" );

    if (!info->kst_initialized)
    {
        RtlSetLastWin32Error( ERROR_INVALID_STATE );
        return 1;
    }
    status = NtWaitForMultipleObjects( 2, info->kst_events, WaitAny, FALSE, NULL );
    if (status == STATUS_WAIT_0)
    {
        info->kst_initialized = FALSE;
        return 0;
    }
    if (status == STATUS_WAIT_0 + 1) return 2;

    RtlSetLastWin32Error( RtlNtStatusToDosError( status ) );
    return 1;
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

NTSTATUS WINAPI NtDCompositionBeginFrame( HANDLE connection,
                                           const struct dcomposition_frame_info *user_info,
                                           UINT64 *frame_id )
{
    struct dcomposition_frame_info info;
    const UINT64 *references;
    UINT64 id = 0;
    UINT64 value;
    UINT reference_count;
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    TRACE( "connection %p, info %p, frame_id %p\n", connection, user_info, frame_id );

    if (!user_info || !frame_id) return STATUS_INVALID_PARAMETER;
    __TRY
    {
        info = *user_info;
        memcpy( &references, info.data + 144, sizeof(references) );
        memcpy( &reference_count, info.data + 152, sizeof(reference_count) );
        if (!references && reference_count)
            status = STATUS_INVALID_PARAMETER;
        else if (reference_count > 0x1fffffff)
            status = STATUS_INTEGER_OVERFLOW;
        else if (reference_count && ((ULONG_PTR)references & 7))
            status = STATUS_DATATYPE_MISALIGNMENT;
        else
        {
            if (reference_count)
            {
                memcpy( &value, references, sizeof(value) );
                memcpy( &value, references + reference_count - 1, sizeof(value) );
                (void)value;
            }
            status = STATUS_SUCCESS;
        }
    }
    __EXCEPT
    {
        status = STATUS_INVALID_PARAMETER;
    }
    __ENDTRY
    if (status) return status;

    SERVER_START_REQ( begin_dcomp_frame )
    {
        req->connection = wine_server_obj_handle( connection );
        status = wine_server_call( req );
        if (!status) id = reply->frame_id;
    }
    SERVER_END_REQ;
    if (status) return status;

    __TRY
    {
        *frame_id = id;
        status = STATUS_SUCCESS;
    }
    __EXCEPT
    {
        status = STATUS_INVALID_PARAMETER;
    }
    __ENDTRY

    if (!status) return STATUS_SUCCESS;

    SERVER_START_REQ( discard_dcomp_frame )
    {
        req->connection = wine_server_obj_handle( connection );
        req->frame_id = id;
        wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}

NTSTATUS WINAPI NtDCompositionConfirmFrame( HANDLE connection,
                                             const struct dcomposition_confirm_frame_info *user_info )
{
    struct dcomposition_confirm_frame_info info;
    const BYTE *updates;
    BYTE value;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    UINT update_count, i;

    TRACE( "connection %p, info %p\n", connection, user_info );

    if (!user_info) return STATUS_INVALID_PARAMETER;
    __TRY
    {
        info = *user_info;
        update_count = min( info.update_count, 256u );
        updates = info.updates;
        if (!info.frame_id || (update_count && !updates)) status = STATUS_INVALID_PARAMETER;
        else
        {
            for (i = 0; i < update_count * 120; ++i) value = updates[i];
            if (update_count) (void)value;
            status = STATUS_SUCCESS;
        }
    }
    __EXCEPT
    {
        status = STATUS_INVALID_PARAMETER;
    }
    __ENDTRY
    if (status) return status;

    SERVER_START_REQ( confirm_dcomp_frame )
    {
        req->connection = wine_server_obj_handle( connection );
        req->frame_id = info.frame_id;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}

NTSTATUS WINAPI NtDCompositionGetFrameId( UINT type, UINT64 *frame_id )
{
    UINT64 id = 0;
    NTSTATUS status;

    TRACE( "type %u, frame_id %p\n", type, frame_id );

    if (!frame_id || type > 2) return STATUS_INVALID_PARAMETER;
    SERVER_START_REQ( get_dcomp_frame_id )
    {
        req->type = type;
        status = wine_server_call( req );
        if (!status) id = reply->frame_id;
    }
    SERVER_END_REQ;
    if (status) return status;
    __TRY
    {
        *frame_id = id;
    }
    __EXCEPT
    {
        status = STATUS_INVALID_PARAMETER;
    }
    __ENDTRY
    return status;
}

NTSTATUS WINAPI NtDCompositionGetFrameLegacyTokens( const UINT64 *user_frame_id,
                                                     UINT *token_count, BOOL *has_more )
{
    UINT64 frame_id = 0;
    UINT count = 0;
    BOOL more = FALSE;
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    TRACE( "frame_id %p, token_count %p, has_more %p\n", user_frame_id, token_count, has_more );

    if (!user_frame_id || !token_count || !has_more) return STATUS_INVALID_PARAMETER;
    __TRY
    {
        frame_id = *user_frame_id;
        *token_count = 0;
        *has_more = FALSE;
        status = frame_id ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
    }
    __EXCEPT
    {
        status = STATUS_INVALID_PARAMETER;
    }
    __ENDTRY
    if (status) return status;

    SERVER_START_REQ( get_dcomp_frame_legacy_tokens )
    {
        req->frame_id = frame_id;
        status = wine_server_call( req );
        if (!status)
        {
            count = reply->token_count;
            more = reply->has_more;
        }
    }
    SERVER_END_REQ;
    if (status) return status;

    __TRY
    {
        *token_count = count;
        *has_more = more;
    }
    __EXCEPT
    {
        status = STATUS_INVALID_PARAMETER;
    }
    __ENDTRY
    return status;
}

NTSTATUS WINAPI NtDCompositionGetFrameSurfaceUpdates( const UINT64 *user_frame_id,
                                                       UINT *update_count, BOOL *has_more )
{
    UINT64 frame_id = 0;
    UINT count = 0;
    BOOL more = FALSE;
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    TRACE( "frame_id %p, update_count %p, has_more %p\n", user_frame_id, update_count, has_more );

    if (!user_frame_id || !update_count || !has_more) return STATUS_INVALID_PARAMETER;
    __TRY
    {
        frame_id = *user_frame_id;
        *update_count = 0;
        *has_more = FALSE;
        status = frame_id ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
    }
    __EXCEPT
    {
        status = STATUS_INVALID_PARAMETER;
    }
    __ENDTRY
    if (status) return status;

    SERVER_START_REQ( get_dcomp_frame_surface_updates )
    {
        req->frame_id = frame_id;
        status = wine_server_call( req );
        if (!status)
        {
            count = reply->update_count;
            more = reply->has_more;
        }
    }
    SERVER_END_REQ;
    if (status) return status;

    __TRY
    {
        *update_count = count;
        *has_more = more;
    }
    __EXCEPT
    {
        status = STATUS_INVALID_PARAMETER;
    }
    __ENDTRY
    return status;
}

struct dcomp_surface_update_wire
{
    obj_handle_t surface;
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
};

NTSTATUS WINAPI NtCreateCompositionSurfaceHandle( const OBJECT_ATTRIBUTES *attributes,
                                                   ACCESS_MASK access, HANDLE *surface )
{
    HANDLE handle = INVALID_HANDLE_VALUE;
    NTSTATUS status;

    TRACE( "attributes %p, access %#x, surface %p\n", attributes, (unsigned int)access, surface );

    if (!surface) return STATUS_INVALID_PARAMETER;
    __TRY
    {
        *surface = INVALID_HANDLE_VALUE;
        if (attributes && attributes->Length != sizeof(*attributes))
            status = STATUS_INVALID_PARAMETER;
        else if (attributes && attributes->ObjectName)
            status = STATUS_NOT_SUPPORTED;
        else status = STATUS_SUCCESS;
    }
    __EXCEPT
    {
        status = STATUS_INVALID_PARAMETER;
    }
    __ENDTRY
    if (status) return status;

    SERVER_START_REQ( create_dcomp_surface )
    {
        req->access = access;
        status = wine_server_call( req );
        if (!status) handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    if (status) return status;

    __TRY
    {
        *surface = handle;
    }
    __EXCEPT
    {
        NtClose( handle );
        status = STATUS_INVALID_PARAMETER;
    }
    __ENDTRY
    return status;
}

NTSTATUS WINAPI NtBindCompositionSurface( HANDLE surface, BOOL enable, UINT flags,
                                           BOOL shared, const void *buffer_info,
                                           UINT64 *binding_id )
{
    volatile const BYTE *info = buffer_info;
    UINT64 id = 0;
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    TRACE( "surface %p, enable %u, flags %#x, shared %u, info %p, binding_id %p\n",
           surface, enable, flags, shared, buffer_info, binding_id );

    if (!buffer_info || !binding_id) return STATUS_INVALID_PARAMETER;
    __TRY
    {
        (void)info[0];
        (void)info[0x51f];
        *binding_id = 0;
        status = STATUS_SUCCESS;
    }
    __EXCEPT
    {
        status = STATUS_INVALID_PARAMETER;
    }
    __ENDTRY
    if (status) return status;

    SERVER_START_REQ( set_dcomp_surface_bound )
    {
        req->handle = wine_server_obj_handle( surface );
        req->bound = TRUE;
        status = wine_server_call( req );
        if (!status) id = reply->binding_id;
    }
    SERVER_END_REQ;
    if (status) return status;

    __TRY
    {
        *binding_id = id;
    }
    __EXCEPT
    {
        status = STATUS_INVALID_PARAMETER;
    }
    __ENDTRY
    return status;
}

NTSTATUS WINAPI NtUnBindCompositionSurface( HANDLE surface, BOOL release, BOOL shared )
{
    NTSTATUS status;

    TRACE( "surface %p, release %u, shared %u\n", surface, release, shared );

    SERVER_START_REQ( set_dcomp_surface_bound )
    {
        req->handle = wine_server_obj_handle( surface );
        req->bound = FALSE;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}

NTSTATUS WINAPI NtTokenManagerCreateCompositionTokenHandle(
        const struct dcomposition_token_surface_update *user_updates, UINT update_count, UINT surface_count,
        const UINT64 *user_connection, const UINT64 *user_device, HANDLE *token )
{
    struct dcomp_surface_update_wire *updates = NULL;
    UINT64 connection = 0, device = 0;
    HANDLE handle = INVALID_HANDLE_VALUE;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    SIZE_T size;
    UINT i;

    TRACE( "updates %p, update_count %u, surface_count %u, connection %p, device %p, token %p\n",
           user_updates, update_count, surface_count, user_connection, user_device, token );

    if (!user_updates || !update_count || !surface_count || surface_count > update_count ||
        !user_connection || !user_device || !token ||
        update_count > ~(data_size_t)0 / sizeof(*updates))
        return STATUS_INVALID_PARAMETER;
    size = update_count * sizeof(*updates);
    if (!(updates = malloc( size ))) return STATUS_NO_MEMORY;
    __TRY
    {
        connection = *user_connection;
        device = *user_device;
        *token = INVALID_HANDLE_VALUE;
        for (i = 0; i < update_count; ++i)
        {
            updates[i].surface = wine_server_obj_handle( user_updates[i].surface );
            updates[i].left = user_updates[i].left;
            updates[i].top = user_updates[i].top;
            updates[i].right = user_updates[i].right;
            updates[i].bottom = user_updates[i].bottom;
        }
        status = STATUS_SUCCESS;
    }
    __EXCEPT
    {
        status = STATUS_INVALID_PARAMETER;
    }
    __ENDTRY
    if (status) goto done;

    SERVER_START_REQ( create_dcomp_token )
    {
        req->surface_count = surface_count;
        req->connection = connection;
        req->device = device;
        wine_server_add_data( req, updates, size );
        status = wine_server_call( req );
        if (!status) handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    if (status) goto done;

    __TRY
    {
        *token = handle;
    }
    __EXCEPT
    {
        NtClose( handle );
        status = STATUS_INVALID_PARAMETER;
    }
    __ENDTRY

done:
    free( updates );
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
    list_init( &view->resources );
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

NTSTATUS WINAPI NtDCompositionCreateAndBindSharedSection( UINT channel, UINT resource_id,
                                                            UINT64 size, HANDLE *section_handle )
{
    struct dcomp_resource_view *resource;
    struct dcomp_channel_view *view;
    HANDLE section = NULL;
    NTSTATUS status;

    TRACE( "channel %#x, resource %#x, size %s, section_handle %p\n", channel, resource_id,
           wine_dbgstr_longlong(size), section_handle );

    pthread_mutex_lock( &dcomp_channel_lock );
    if (!(view = find_dcomp_channel_view( channel ))) status = STATUS_ACCESS_DENIED;
    else if (!(resource = find_dcomp_resource_view( view, resource_id )) ||
             resource->type != 0x9d || resource->shared_section_bound)
        status = STATUS_INVALID_PARAMETER;
    else
    {
        SERVER_START_REQ( create_dcomp_shared_section )
        {
            req->channel = channel;
            req->resource = resource_id;
            req->size = size;
            status = wine_server_call( req );
            if (!status) section = wine_server_ptr_handle( reply->section );
        }
        SERVER_END_REQ;
        if (!status) resource->shared_section_bound = TRUE;
    }
    pthread_mutex_unlock( &dcomp_channel_lock );
    if (status) return status;

    __TRY
    {
        *section_handle = section;
    }
    __EXCEPT
    {
        status = STATUS_INVALID_PARAMETER;
    }
    __ENDTRY
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
        free_dcomp_resource_views( view );
        NtUnmapViewOfSection( GetCurrentProcess(), view->address );
        free( view );
    }
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI NtDCompositionProcessChannelBatchBuffer( UINT channel, UINT length,
                                                          ULONG *processed, BYTE *released )
{
    struct dcomp_channel_view *view;
    ULONG command_count = 0;
    BYTE released_resources = 0;
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    TRACE( "channel %#x, length %u, processed %p, released %p\n",
           channel, length, processed, released );

    if (!processed || !released) return STATUS_INVALID_PARAMETER;
    __TRY
    {
        *processed = 0;
        *released = 0;
    }
    __EXCEPT
    {
        return STATUS_INVALID_PARAMETER;
    }
    __ENDTRY

    pthread_mutex_lock( &dcomp_channel_lock );
    if (!(view = find_dcomp_channel_view( channel ))) status = STATUS_ACCESS_DENIED;
    else if (length > view->size) status = STATUS_INVALID_PARAMETER;
    else
    {
        __TRY
        {
            status = process_dcomp_commands( view, view->address, length, TRUE, &command_count );
            released_resources = view->released_resources;
            view->released_resources = FALSE;
        }
        __EXCEPT
        {
            status = STATUS_INVALID_PARAMETER;
        }
        __ENDTRY
    }
    pthread_mutex_unlock( &dcomp_channel_lock );

    __TRY
    {
        *processed = command_count;
        *released = released_resources;
    }
    __EXCEPT
    {
        status = STATUS_INVALID_PARAMETER;
    }
    __ENDTRY
    return status;
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

NTSTATUS WINAPI NtDCompositionSetChannelCommitCompletionEvent( UINT channel, HANDLE event,
                                                                BOOL internal )
{
    NTSTATUS status;

    TRACE( "channel %#x, event %p, internal %u\n", channel, event, internal );
    if (!event) return STATUS_INVALID_PARAMETER;
    SERVER_START_REQ( set_dcomp_channel_completion_event )
    {
        req->channel = channel;
        req->event = wine_server_obj_handle( event );
        req->internal = !!internal;
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

NTSTATUS WINAPI NtDCompositionReleaseAllResources( UINT channel, BYTE *result )
{
    NTSTATUS status;

    TRACE( "channel %#x, result %p\n", channel, result );

    if (!result) return STATUS_INVALID_PARAMETER;
    SERVER_START_REQ( release_all_dcomp_resources )
    {
        req->channel = channel;
        status = wine_server_call( req );
        if (!status) *result = reply->result;
    }
    SERVER_END_REQ;
    return status;
}

NTSTATUS WINAPI NtDCompositionGetDeletedResources( UINT channel, UINT capacity,
                                                     void **resources, UINT *count )
{
    NTSTATUS status;

    TRACE( "channel %#x, capacity %u, resources %p, count %p\n",
           channel, capacity, resources, count );

    if (!capacity || !resources || !count) return STATUS_INVALID_PARAMETER;
    SERVER_START_REQ( get_deleted_dcomp_resources )
    {
        req->channel = channel;
        req->capacity = capacity;
        status = wine_server_call( req );
        if (!status)
        {
            *resources = NULL;
            *count = reply->count;
        }
    }
    SERVER_END_REQ;
    return status;
}

NTSTATUS WINAPI NtDCompositionCommitChannel( UINT channel, UINT *batch_id, BYTE *state,
                                              ULONG flags, HANDLE sync_object,
                                              const void *protocol_blocks, const UINT *resources,
                                              UINT resource_count )
{
    struct dcomp_channel_view *view;
    data_size_t protocol_size = 0;
    BYTE *protocol_data = NULL;
    UINT committed_batch_id = 0;
    BYTE committed_state = 0;
    NTSTATUS status;

    TRACE( "channel %#x, batch_id %p, state %p, flags %#x, sync_object %p, "
           "protocol_blocks %p, resources %p, resource_count %u\n", channel, batch_id, state,
           flags, sync_object, protocol_blocks, resources, resource_count );

    if (!state) return STATUS_INVALID_PARAMETER;
    if (sync_object || resources || resource_count) return STATUS_NOT_SUPPORTED;
    if ((status = copy_dcomp_protocol_blocks( protocol_blocks, &protocol_data, &protocol_size )))
        return status;

    pthread_mutex_lock( &dcomp_channel_lock );
    view = find_dcomp_channel_view( channel );
    if (!view)
    {
        pthread_mutex_unlock( &dcomp_channel_lock );
        free( protocol_data );
        return STATUS_ACCESS_DENIED;
    }
    if ((status = build_dcomp_commit_payload( view, &protocol_data, &protocol_size )))
    {
        pthread_mutex_unlock( &dcomp_channel_lock );
        free( protocol_data );
        return status;
    }

    SERVER_START_REQ( commit_dcomp_channel )
    {
        req->channel = channel;
        req->protocol_blocks = !!protocol_blocks;
        req->payload_size = protocol_size;
        wine_server_add_data( req, protocol_data, protocol_size );
        status = wine_server_call( req );
        if (!status)
        {
            committed_batch_id = reply->batch_id;
            committed_state = reply->state;
            commit_dcomp_resource_views( view );
        }
    }
    SERVER_END_REQ;
    pthread_mutex_unlock( &dcomp_channel_lock );
    free( protocol_data );
    if (status) return status;

    __TRY
    {
        if (batch_id) *batch_id = committed_batch_id;
        *state = committed_state;
    }
    __EXCEPT
    {
        status = STATUS_INVALID_PARAMETER;
    }
    __ENDTRY
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

NTSTATUS WINAPI NtTokenManagerThread( const struct token_manager_thread_info *user_info )
{
    struct token_manager_adapter_info inline_adapters[5], *adapters = inline_adapters;
    struct token_manager_thread_info info;
    HANDLE events[2], notification_event = NULL;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    SIZE_T size;

    TRACE( "info %p\n", user_info );

    if (!user_info) return STATUS_INVALID_PARAMETER;
    __TRY
    {
        info = *user_info;
    }
    __EXCEPT
    {
        return STATUS_INVALID_PARAMETER;
    }
    __ENDTRY
    if (!info.adapter_count || !info.adapters ||
        info.adapter_count > ~(UINT)0 / sizeof(*adapters))
        return STATUS_INVALID_PARAMETER;

    size = (SIZE_T)info.adapter_count * sizeof(*adapters);
    if (info.adapter_count > ARRAY_SIZE(inline_adapters) && !(adapters = malloc( size )))
        return STATUS_NO_MEMORY;
    __TRY
    {
        memcpy( adapters, info.adapters, size );
        status = STATUS_SUCCESS;
    }
    __EXCEPT
    {
        status = STATUS_INVALID_PARAMETER;
    }
    __ENDTRY
    if (status) goto done;

    SERVER_START_REQ( begin_token_manager_thread )
    {
        req->stop_event = wine_server_obj_handle( info.stop_event );
        req->adapter_count = info.adapter_count;
        status = wine_server_call( req );
        if (!status) notification_event = wine_server_ptr_handle( reply->notification_event );
    }
    SERVER_END_REQ;
    if (status) goto done;

    events[0] = info.stop_event;
    events[1] = notification_event;
    do
        status = NtWaitForMultipleObjects( ARRAY_SIZE(events), events, WaitAny, FALSE, NULL );
    while (status == STATUS_WAIT_0 + 1);
    if (status == STATUS_WAIT_0) status = STATUS_SUCCESS;

    NtClose( notification_event );
    SERVER_START_REQ( end_token_manager_thread )
    {
        NTSTATUS end_status = wine_server_call( req );
        if (!status) status = end_status;
    }
    SERVER_END_REQ;

done:
    if (adapters != inline_adapters) free( adapters );
    return status;
}
