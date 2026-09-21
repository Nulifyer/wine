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

struct dcomp_property_value
{
    UINT offset;
    UINT type;
    UINT size;
    BYTE data[64];
    BOOL dirty;
    BOOL added;
};

struct dcomp_resource_view
{
    struct list entry;
    UINT id;
    UINT type;
    UINT references;
    struct dcomp_resource_view *root;
    struct dcomp_resource_view *visual_transform;
    struct dcomp_resource_view *visual_clip;
    struct dcomp_resource_view *sprite_content;
    struct dcomp_resource_view *window_flip_surface_clip;
    struct dcomp_resource_view *window_sprite_bitmap;
    struct dcomp_resource_view *window_sprite_clip;
    struct dcomp_resource_view *expression_shared_section;
    struct dcomp_resource_view *render_target_desktop_tree;
    struct dcomp_resource_view *desktop_tree_root;
    struct dcomp_resource_view *parent;
    struct dcomp_resource_view *first_child;
    struct dcomp_resource_view *next_sibling;
    BOOL announced;
    BOOL client_released;
    BOOL released;
    BOOL visual;
    BOOL visual_target;
    BOOL visual_transform_dirty;
    BOOL visual_clip_dirty;
    BOOL sprite_content_dirty;
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
    UINT window_node_dirty;
    BYTE window_alpha_margins[16];
    BYTE window_content_relative_client_rect[16];
    BYTE window_content_relative_window_rect[16];
    BYTE window_content_size[8];
    BYTE window_extended_bounds[16];
    UINT64 window_flip_surface;
    BYTE window_flags[4];
    BYTE window_maximized_clip_margins[16];
    BYTE window_process_attribution[16];
    BYTE window_source_modifications[16];
    UINT64 window_sprite_handle;
    UINT64 window_handle;
    UINT64 render_target_monitor;
    UINT64 render_target_adapter_luid;
    UINT render_target_display_id;
    UINT render_target_format;
    UINT render_target_color_space;
    UINT render_target_flags;
    float render_target_float_rect[4];
    float render_target_scale;
    float render_target_scale2;
    UINT render_target_rect[4];
    UINT render_target_rotation;
    float render_target_sdr_to_hdr;
    BOOL render_target_create_dirty;
    BOOL render_target_desktop_tree_dirty;
    BOOL render_target_transform_dirty;
    BOOL render_target_hdr_dirty;
    BOOL render_target_refresh_dirty;
    UINT64 desktop_tree_adapter_luid;
    BOOL desktop_tree_adapter_dirty;
    BOOL desktop_tree_root_dirty;
    BOOL color_dirty;
    float color[4];
    UINT rectangle_dirty;
    float rectangle[12];
    BYTE rectangle_mode;
    BYTE rectangle_expression_mode;
    BYTE rectangle_flag;
    struct dcomp_property_value *properties;
    UINT property_count;
    UINT property_data_size;
    UINT expression_property_resource_id;
    UINT *expression_sources;
    UINT expression_source_count;
    BYTE *expression_reference_info;
    UINT expression_reference_count;
    UINT expression_type;
    UINT expression_property_3;
    UINT expression_property_4;
    UINT64 expression_node_offset;
    UINT64 expression_node_size;
    BYTE expression_metadata[16];
    UINT expression_metadata_size;
    BOOL expression_property_enabled;
    BOOL expression_base_dirty;
    BOOL expression_property_4_dirty;
    BOOL expression_sources_dirty;
    BOOL expression_reference_info_dirty;
    BOOL expression_nodes_dirty;
    BOOL shared_section_bound;
    BOOL shared_section_announced;
    BOOL shared_write;
    BOOL shared_duplicate;
    float manipulation_components[12];
    UINT manipulation_tracing_cookie;
    BOOL manipulation_components_dirty;
    BOOL manipulation_cookie_dirty;
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
    struct dcomp_resource_view *child, *reference, *root;
    BOOL clear_children = FALSE;

    if (--resource->references) return;

    if ((root = resource->root))
    {
        resource->root = NULL;
        resource->root_dirty = TRUE;
        release_dcomp_resource_reference( root );
    }
    if ((reference = resource->visual_transform))
    {
        resource->visual_transform = NULL;
        release_dcomp_resource_reference( reference );
    }
    if ((reference = resource->visual_clip))
    {
        resource->visual_clip = NULL;
        release_dcomp_resource_reference( reference );
    }
    if ((reference = resource->sprite_content))
    {
        resource->sprite_content = NULL;
        release_dcomp_resource_reference( reference );
    }
    if ((reference = resource->window_flip_surface_clip))
    {
        resource->window_flip_surface_clip = NULL;
        release_dcomp_resource_reference( reference );
    }
    if ((reference = resource->window_sprite_bitmap))
    {
        resource->window_sprite_bitmap = NULL;
        release_dcomp_resource_reference( reference );
    }
    if ((reference = resource->window_sprite_clip))
    {
        resource->window_sprite_clip = NULL;
        release_dcomp_resource_reference( reference );
    }
    if ((reference = resource->expression_shared_section))
    {
        resource->expression_shared_section = NULL;
        release_dcomp_resource_reference( reference );
    }
    if ((reference = resource->render_target_desktop_tree))
    {
        resource->render_target_desktop_tree = NULL;
        release_dcomp_resource_reference( reference );
    }
    if ((reference = resource->desktop_tree_root))
    {
        resource->desktop_tree_root = NULL;
        release_dcomp_resource_reference( reference );
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

static void free_dcomp_resource_view( struct dcomp_resource_view *resource )
{
    free( resource->properties );
    free( resource->expression_sources );
    free( resource->expression_reference_info );
    free( resource );
}

static void remove_unannounced_dcomp_resources( struct dcomp_channel_view *view )
{
    struct dcomp_resource_view *resource, *next;

    LIST_FOR_EACH_ENTRY_SAFE( resource, next, &view->resources, struct dcomp_resource_view, entry )
    {
        if (!resource->announced && resource->released)
        {
            list_remove( &resource->entry );
            free_dcomp_resource_view( resource );
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

static BOOL is_dcomp_transform3d_resource_type( UINT type )
{
    /* Descendants of MIL_RESOURCE_TYPE 0xaf in the Windows resource-parent table. */
    switch (type)
    {
    case 0x1e:
    case 0x6a:
    case 0x6d:
    case 0x6e:
    case 0x88:
    case 0x89:
    case 0x8c:
    case 0x8d:
    case 0xa1:
    case 0xae:
    case 0xaf:
    case 0xb0:
    case 0xb1:
    case 0xb2:
    case 0xb3:
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOL is_dcomp_clip_resource_type( UINT type )
{
    /* Descendants of MIL_RESOURCE_TYPE 0x43 in the Windows resource-parent table. */
    switch (type)
    {
    case 0x1b:
    case 0x3b:
    case 0x43:
    case 0x46:
    case 0x66:
    case 0x73:
    case 0x7d:
    case 0x7f:
    case 0x82:
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOL is_dcomp_brush_resource_type( UINT type )
{
    /* Descendants of MIL_RESOURCE_TYPE 0x11 in the Windows resource-parent table. */
    switch (type)
    {
    case 0x09:
    case 0x0f:
    case 0x11:
    case 0x15:
    case 0x16:
    case 0x25:
    case 0x39:
    case 0x49:
    case 0x63:
    case 0x6b:
    case 0x71:
    case 0x7e:
    case 0xa9:
    case 0xbf:
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOL is_dcomp_derived_resource_type( UINT type, UINT base )
{
    /* Windows' MIL resource-parent table. */
    static const BYTE parent[0xc2] =
    {
        0xc2, 0x3d, 0x0a, 0x7b, 0x87, 0x7b, 0x3d, 0x2f,
        0x87, 0x11, 0x87, 0x72, 0x87, 0x55, 0x3d, 0x11,
        0x3d, 0x87, 0x55, 0x87, 0x86, 0x11, 0x00, 0x87,
        0x3d, 0x87, 0x00, 0x43, 0x72, 0x7b, 0xaf, 0x3d,
        0x24, 0x00, 0x2f, 0xac, 0x87, 0x11, 0x87, 0x24,
        0x7b, 0x24, 0x2f, 0xac, 0x87, 0x0b, 0xb5, 0x87,
        0x9e, 0x00, 0xb8, 0x87, 0x86, 0xa8, 0x87, 0x28,
        0x7b, 0x11, 0x38, 0x43, 0x0b, 0x38, 0x87, 0x3d,
        0x00, 0x87, 0xa8, 0x7b, 0x87, 0x44, 0x43, 0x87,
        0x2f, 0x11, 0x5f, 0x72, 0x00, 0x87, 0x00, 0x3d,
        0x5f, 0x87, 0x86, 0x0b, 0x2f, 0x87, 0x72, 0x00,
        0x0b, 0xb8, 0x87, 0x00, 0x86, 0x60, 0x87, 0x49,
        0x4a, 0x3d, 0x43, 0x86, 0x00, 0x72, 0xae, 0x11,
        0x87, 0xae, 0xaf, 0x44, 0x0b, 0x11, 0x87, 0x43,
        0x87, 0x00, 0x2f, 0x00, 0x7b, 0x00, 0x72, 0x7b,
        0x43, 0x49, 0x43, 0x87, 0xb8, 0x43, 0x86, 0x00,
        0x2f, 0x87, 0xc2, 0xae, 0xaf, 0x3d, 0x0a, 0xae,
        0xaf, 0x96, 0x87, 0x00, 0x96, 0x98, 0x97, 0x2c,
        0x96, 0x87, 0x8f, 0x8e, 0x90, 0xb8, 0x3d, 0xb8,
        0x9e, 0x87, 0x00, 0xae, 0x2f, 0x87, 0x5f, 0xb5,
        0xb8, 0x00, 0x2f, 0x11, 0xa8, 0x3d, 0x87, 0xb8,
        0xaf, 0x38, 0xaf, 0xae, 0x00, 0xaf, 0x3d, 0x87,
        0x00, 0x14, 0x7b, 0x2f, 0x86, 0x87, 0x00, 0xbc,
        0x87, 0x11, 0xb8, 0x2f,
    };
    UINT count = 0;

    while (type < ARRAY_SIZE(parent) && count++ < ARRAY_SIZE(parent))
    {
        if (type == base) return TRUE;
        type = parent[type];
    }
    return FALSE;
}

static void initialize_dcomp_resource_view( struct dcomp_resource_view *resource,
                                             UINT id, UINT type )
{
    resource->id = id;
    resource->type = type;
    resource->references = 1;
    resource->visual = is_dcomp_visual_resource_type( type );
    if (type == 0x7f)
    {
        resource->rectangle[0] = resource->rectangle[1] = -2097152.0f;
        resource->rectangle[2] = resource->rectangle[3] = 2097152.0f;
    }
    if (type == 0x3c) resource->expression_base_dirty = resource->expression_property_4_dirty = TRUE;
    if (type == 0x60)
    {
        resource->render_target_scale2 = 1.0f;
        resource->render_target_sdr_to_hdr = 1.0f;
    }
    if (type == 0x6a)
    {
        resource->manipulation_components[6] = 1.0f;
        resource->manipulation_components[7] = 1.0f;
        resource->manipulation_components[8] = 1.0f;
        resource->manipulation_components_dirty = TRUE;
        resource->manipulation_cookie_dirty = TRUE;
    }
}

static NTSTATUS set_dcomp_manipulation_integer_property( struct dcomp_resource_view *resource,
                                                          UINT property, INT64 value )
{
    if (property != 6) return STATUS_NOT_SUPPORTED;
    resource->manipulation_tracing_cookie = value;
    resource->manipulation_cookie_dirty = TRUE;
    return STATUS_SUCCESS;
}

static NTSTATUS set_dcomp_manipulation_buffer_property( struct dcomp_resource_view *resource,
                                                         UINT property, const BYTE *data,
                                                         UINT size )
{
    if (property < 1 || property > 4 || size != 3 * sizeof(float))
        return STATUS_INVALID_PARAMETER;
    memcpy( resource->manipulation_components + (property - 1) * 3, data, size );
    resource->manipulation_components_dirty = TRUE;
    return STATUS_SUCCESS;
}

static void replace_dcomp_resource_reference( struct dcomp_resource_view **slot,
                                               struct dcomp_resource_view *resource )
{
    struct dcomp_resource_view *previous = *slot;

    if (previous == resource) return;
    if (resource) resource->references++;
    *slot = resource;
    if (previous) release_dcomp_resource_reference( previous );
}

static NTSTATUS set_dcomp_legacy_target_integer_property( struct dcomp_resource_view *resource,
                                                           UINT property, INT64 value )
{
    UINT int_value = value;

    switch (property)
    {
    case 1:
        if (resource->render_target_monitor == value) return STATUS_SUCCESS;
        resource->render_target_monitor = value;
        resource->render_target_transform_dirty = TRUE;
        break;
    case 3:
        if (resource->render_target_display_id) return STATUS_INVALID_PARAMETER;
        resource->render_target_display_id = int_value;
        resource->render_target_create_dirty = TRUE;
        break;
    case 4:
        if (resource->render_target_format ||
            (int_value != 10 && int_value != 0x18 && int_value != 0x1c && int_value != 0x57))
            return STATUS_INVALID_PARAMETER;
        resource->render_target_format = int_value;
        resource->render_target_create_dirty = TRUE;
        break;
    case 5:
        if (resource->render_target_color_space == int_value) return STATUS_SUCCESS;
        resource->render_target_color_space = int_value;
        resource->render_target_create_dirty = TRUE;
        break;
    case 10:
        if (int_value < 1 || int_value > 4) return STATUS_INVALID_PARAMETER;
        if (resource->render_target_rotation == int_value) return STATUS_SUCCESS;
        resource->render_target_rotation = int_value;
        resource->render_target_transform_dirty = TRUE;
        break;
    case 11:
        if (resource->render_target_flags == int_value) return STATUS_SUCCESS;
        resource->render_target_flags = int_value;
        resource->render_target_create_dirty = TRUE;
        break;
    case 13:
        resource->render_target_refresh_dirty = TRUE;
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS set_dcomp_legacy_target_float_property( struct dcomp_resource_view *resource,
                                                         UINT property, float value )
{
    float *target;
    BOOL *dirty;

    switch (property)
    {
    case 7:
        target = &resource->render_target_scale;
        dirty = &resource->render_target_transform_dirty;
        if (!(value > 0.0f)) return STATUS_INVALID_PARAMETER;
        break;
    case 8:
        target = &resource->render_target_scale2;
        dirty = &resource->render_target_transform_dirty;
        if (!(value > 0.0f)) return STATUS_INVALID_PARAMETER;
        break;
    case 12:
        target = &resource->render_target_sdr_to_hdr;
        dirty = &resource->render_target_hdr_dirty;
        if (!(value >= 1.0f)) return STATUS_INVALID_PARAMETER;
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }
    if (*target == value) return STATUS_SUCCESS;
    *target = value;
    *dirty = TRUE;
    return STATUS_SUCCESS;
}

static NTSTATUS set_dcomp_legacy_target_buffer_property( struct dcomp_resource_view *resource,
                                                          UINT property, const BYTE *data,
                                                          UINT size )
{
    float float_rect[4];
    UINT rect[4];
    UINT64 luid;

    switch (property)
    {
    case 2:
        if (size != sizeof(luid) || resource->render_target_adapter_luid)
            return STATUS_INVALID_PARAMETER;
        memcpy( &luid, data, sizeof(luid) );
        resource->render_target_adapter_luid = luid;
        resource->render_target_create_dirty = TRUE;
        break;
    case 6:
        if (size != sizeof(float_rect)) return STATUS_INVALID_PARAMETER;
        memcpy( float_rect, data, sizeof(float_rect) );
        if (float_rect[0] != float_rect[0] || float_rect[1] != float_rect[1] ||
            float_rect[2] < float_rect[0] || float_rect[3] < float_rect[1])
            return STATUS_INVALID_PARAMETER;
        if (!memcmp( resource->render_target_float_rect, float_rect, sizeof(float_rect) ))
            return STATUS_SUCCESS;
        memcpy( resource->render_target_float_rect, float_rect, sizeof(float_rect) );
        resource->render_target_transform_dirty = TRUE;
        break;
    case 9:
        if (size != sizeof(rect)) return STATUS_INVALID_PARAMETER;
        memcpy( rect, data, sizeof(rect) );
        if (rect[2] <= rect[0] || rect[3] <= rect[1]) return STATUS_INVALID_PARAMETER;
        if (!memcmp( resource->render_target_rect, rect, sizeof(rect) ))
            return STATUS_SUCCESS;
        memcpy( resource->render_target_rect, rect, sizeof(rect) );
        resource->render_target_transform_dirty = TRUE;
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS set_dcomp_desktop_tree_buffer_property( struct dcomp_resource_view *resource,
                                                         UINT property, const BYTE *data,
                                                         UINT size )
{
    UINT64 luid;

    if (property || size != sizeof(luid)) return STATUS_INVALID_PARAMETER;
    memcpy( &luid, data, sizeof(luid) );
    if (resource->desktop_tree_adapter_luid == luid) return STATUS_SUCCESS;
    resource->desktop_tree_adapter_luid = luid;
    resource->desktop_tree_adapter_dirty = TRUE;
    return STATUS_SUCCESS;
}

static NTSTATUS set_dcomp_render_target_reference_property( struct dcomp_channel_view *view,
                                                             struct dcomp_resource_view *resource,
                                                             UINT property, UINT reference_id )
{
    struct dcomp_resource_view *reference = NULL;
    struct dcomp_resource_view **slot;
    BOOL *dirty;

    if (reference_id && !(reference = find_dcomp_resource_view( view, reference_id )))
        return STATUS_ACCESS_DENIED;
    if (resource->type == 0x60)
    {
        if (property || (reference && reference->type != 0x36))
            return STATUS_INVALID_PARAMETER;
        slot = &resource->render_target_desktop_tree;
        dirty = &resource->render_target_desktop_tree_dirty;
    }
    else
    {
        if (resource->type != 0x36 || property != 1 ||
            (reference && !is_dcomp_derived_resource_type( reference->type, 0xb8 )))
            return STATUS_INVALID_PARAMETER;
        slot = &resource->desktop_tree_root;
        dirty = &resource->desktop_tree_root_dirty;
    }
    replace_dcomp_resource_reference( slot, reference );
    *dirty = TRUE;
    remove_unannounced_dcomp_resources( view );
    return STATUS_SUCCESS;
}

static NTSTATUS set_dcomp_visual_reference_property( struct dcomp_channel_view *view,
                                                      struct dcomp_resource_view *resource,
                                                      UINT property, UINT reference_id )
{
    struct dcomp_resource_view *reference = NULL;

    if (reference_id && !(reference = find_dcomp_resource_view( view, reference_id )))
        return STATUS_ACCESS_DENIED;

    if (resource->type == 0xa6 && property == 0x34)
    {
        if (reference && !is_dcomp_brush_resource_type( reference->type ))
            return STATUS_INVALID_PARAMETER;
        replace_dcomp_resource_reference( &resource->sprite_content, reference );
        resource->sprite_content_dirty = TRUE;
        remove_unannounced_dcomp_resources( view );
        return STATUS_SUCCESS;
    }
    if (resource->type == 0xc0 &&
        (property == 0x3a || property == 0x42 || property == 0x43))
    {
        struct dcomp_resource_view **slot;
        UINT base, dirty;

        switch (property)
        {
        case 0x3a:
            slot = &resource->window_flip_surface_clip;
            base = 0x43;
            dirty = 0x40;
            break;
        case 0x42:
            slot = &resource->window_sprite_bitmap;
            base = 0x41;
            dirty = 0x4000;
            break;
        case 0x43:
            slot = &resource->window_sprite_clip;
            base = 0x82;
            dirty = 0x8000;
            break;
        }
        if (reference && !is_dcomp_derived_resource_type( reference->type, base ))
            return STATUS_INVALID_PARAMETER;
        replace_dcomp_resource_reference( slot, reference );
        resource->window_node_dirty |= dirty;
        remove_unannounced_dcomp_resources( view );
        return STATUS_SUCCESS;
    }
    if (property == 4)
    {
        if (reference && !is_dcomp_transform3d_resource_type( reference->type ))
            return STATUS_INVALID_PARAMETER;
        replace_dcomp_resource_reference( &resource->visual_transform, reference );
        resource->visual_transform_dirty = TRUE;
        remove_unannounced_dcomp_resources( view );
        return STATUS_SUCCESS;
    }
    if (property == 7)
    {
        if (reference && !is_dcomp_clip_resource_type( reference->type ))
            return STATUS_INVALID_PARAMETER;
        replace_dcomp_resource_reference( &resource->visual_clip, reference );
        resource->visual_clip_dirty = TRUE;
        remove_unannounced_dcomp_resources( view );
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_SUPPORTED;
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

    if (resource->type == 0xc0 && property >= 0x3b && property <= 0x3e)
    {
        BYTE *flag = &resource->window_flags[property - 0x3b];
        UINT dirty = 0x80 << (property - 0x3b);

        if (*flag == !!value) return STATUS_SUCCESS;
        *flag = !!value;
        resource->window_node_dirty |= dirty;
        return STATUS_SUCCESS;
    }

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
    BYTE *target = NULL;
    UINT expected_size = 0, dirty = 0;

    if (resource->type == 0xc0)
    {
        switch (property)
        {
        case 0x34:
            target = resource->window_alpha_margins;
            expected_size = sizeof(resource->window_alpha_margins);
            dirty = 0x1;
            break;
        case 0x35:
            target = resource->window_content_relative_client_rect;
            expected_size = sizeof(resource->window_content_relative_client_rect);
            dirty = 0x2;
            break;
        case 0x36:
            target = resource->window_content_relative_window_rect;
            expected_size = sizeof(resource->window_content_relative_window_rect);
            dirty = 0x4;
            break;
        case 0x37:
            target = resource->window_content_size;
            expected_size = sizeof(resource->window_content_size);
            dirty = 0x8;
            break;
        case 0x38:
            target = resource->window_extended_bounds;
            expected_size = sizeof(resource->window_extended_bounds);
            dirty = 0x10;
            break;
        case 0x3f:
            target = resource->window_maximized_clip_margins;
            expected_size = sizeof(resource->window_maximized_clip_margins);
            dirty = 0x800;
            break;
        case 0x40:
            target = resource->window_process_attribution;
            expected_size = sizeof(resource->window_process_attribution);
            dirty = 0x1000;
            break;
        case 0x41:
            target = resource->window_source_modifications;
            expected_size = sizeof(resource->window_source_modifications);
            dirty = 0x2000;
            break;
        case 0x44:
            target = (BYTE *)&resource->window_sprite_handle;
            expected_size = sizeof(resource->window_sprite_handle);
            dirty = 0x10000;
            break;
        case 0x45:
            target = (BYTE *)&resource->window_handle;
            expected_size = sizeof(resource->window_handle);
            dirty = 0x20000;
            break;
        }
        if (target)
        {
            if (size != expected_size) return STATUS_INVALID_PARAMETER;
            memcpy( target, data, size );
            resource->window_node_dirty |= dirty;
            return STATUS_SUCCESS;
        }
    }
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

static NTSTATUS set_dcomp_window_node_handle_property( struct dcomp_resource_view *resource,
                                                        UINT property, UINT64 handle )
{
    /* Windows retains a Dxgk composition object and opens it in DWM. Preserve the
     * value until Wine has an equivalent server-backed composition-object owner. */
    if (resource->type != 0xc0) return STATUS_NOT_SUPPORTED;
    if (property != 0x39) return STATUS_INVALID_PARAMETER;
    if (resource->window_flip_surface == handle) return STATUS_SUCCESS;
    resource->window_flip_surface = handle;
    resource->window_node_dirty |= 0x20;
    return STATUS_SUCCESS;
}

static NTSTATUS set_dcomp_color_brush_buffer_property( struct dcomp_resource_view *resource,
                                                        UINT property, const BYTE *data, UINT size )
{
    if (property || size != sizeof(resource->color)) return STATUS_INVALID_PARAMETER;
    memcpy( resource->color, data, size );
    resource->color_dirty = TRUE;
    return STATUS_SUCCESS;
}

static float clamp_dcomp_rectangle_value( float value )
{
    if (value <= -2097152.0f) return -2097152.0f;
    if (value <= 2097152.0f) return value;
    return 2097152.0f;
}

static NTSTATUS set_dcomp_rectangle_integer_property( struct dcomp_resource_view *resource,
                                                       UINT property, INT64 value )
{
    if (property == 0x15)
    {
        if (resource->rectangle_mode || resource->rectangle_expression_mode || !value)
            return STATUS_INVALID_PARAMETER;
        resource->rectangle_mode = TRUE;
        resource->rectangle_dirty |= 1;
        return STATUS_SUCCESS;
    }
    if (property == 0x16)
    {
        if (resource->rectangle_expression_mode || resource->rectangle_mode || !value)
            return STATUS_INVALID_PARAMETER;
        resource->rectangle_expression_mode = TRUE;
        memset( resource->rectangle, 0, 4 * sizeof(float) );
        resource->rectangle_dirty |= 0x1f;
        return STATUS_SUCCESS;
    }
    if (property == 0x17)
    {
        if (resource->rectangle_flag == !!value) return STATUS_SUCCESS;
        resource->rectangle_flag = !!value;
        resource->rectangle_dirty |= 1;
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS set_dcomp_rectangle_buffer_property( struct dcomp_resource_view *resource,
                                                      UINT property, const BYTE *data, UINT size )
{
    float rectangle[4];
    UINT i;

    if (property != 0x11 || size != sizeof(rectangle) || resource->rectangle_expression_mode)
        return STATUS_INVALID_PARAMETER;
    memcpy( rectangle, data, sizeof(rectangle) );
    for (i = 0; i < ARRAY_SIZE(rectangle); ++i)
    {
        rectangle[i] = clamp_dcomp_rectangle_value( rectangle[i] );
        if (resource->rectangle[i] == rectangle[i]) continue;
        resource->rectangle[i] = rectangle[i];
        resource->rectangle_dirty |= 2 << i;
    }
    return STATUS_SUCCESS;
}

static UINT dcomp_property_value_size( UINT type )
{
    switch (type)
    {
    case 0x11:
    case 0x12:  return 4;
    case 0x23:  return 8;
    case 0x34:  return 12;
    case 0x45:
    case 0x46:
    case 0x47:  return 16;
    case 0x68:  return 24;
    case 0x109: return 64;
    default:    return 0;
    }
}

static NTSTATUS set_dcomp_property_set_buffer_property( struct dcomp_resource_view *resource,
                                                         UINT property, const BYTE *data, UINT size )
{
    struct dcomp_property_value *values, *value;
    UINT index, offset, type, value_size;

    if ((property != 1 && property != 2) || size < 12) return STATUS_INVALID_PARAMETER;
    memcpy( &index, data, sizeof(index) );
    memcpy( &offset, data + 4, sizeof(offset) );
    memcpy( &type, data + 8, sizeof(type) );
    if (!(value_size = dcomp_property_value_size( type )) || size != value_size + 12)
        return STATUS_INVALID_PARAMETER;

    if (property == 1)
    {
        if (index != resource->property_count || offset != resource->property_data_size)
            return STATUS_INVALID_PARAMETER;
        if (!(values = realloc( resource->properties,
                                (resource->property_count + 1) * sizeof(*values) )))
            return STATUS_NO_MEMORY;
        resource->properties = values;
        value = &values[resource->property_count++];
        memset( value, 0, sizeof(*value) );
        value->offset = offset;
        value->type = type;
        value->size = value_size;
        value->added = TRUE;
        resource->property_data_size += value_size;
    }
    else
    {
        if (index >= resource->property_count) return STATUS_INVALID_PARAMETER;
        value = &resource->properties[index];
        if (value->offset != offset || value->type != type || value->size != value_size)
            return STATUS_INVALID_PARAMETER;
    }
    memcpy( value->data, data + 12, value_size );
    value->dirty = TRUE;
    return STATUS_SUCCESS;
}

static BOOL is_dcomp_expression_type( UINT type )
{
    switch (type)
    {
    case 0x0b:
    case 0x11:
    case 0x12:
    case 0x23:
    case 0x2a:
    case 0x34:
    case 0x45:
    case 0x46:
    case 0x47:
    case 0x68:
    case 0x109:
        return TRUE;
    default:
        return FALSE;
    }
}

static NTSTATUS set_dcomp_expression_integer_property( struct dcomp_resource_view *resource,
                                                        UINT property, INT64 value )
{
    switch (property)
    {
    case 0:
        if (!is_dcomp_expression_type( value )) return STATUS_INVALID_PARAMETER;
        if (resource->expression_type == value) return STATUS_SUCCESS;
        resource->expression_type = value;
        resource->expression_base_dirty = TRUE;
        return STATUS_SUCCESS;
    case 1:
        if (resource->expression_property_enabled == !!value) return STATUS_SUCCESS;
        resource->expression_property_enabled = !!value;
        resource->expression_base_dirty = TRUE;
        return STATUS_SUCCESS;
    case 3:
        if (resource->expression_property_3 == (UINT)value) return STATUS_SUCCESS;
        resource->expression_property_3 = value;
        resource->expression_base_dirty = TRUE;
        return STATUS_SUCCESS;
    case 4:
        if (resource->expression_property_4 == (UINT)value) return STATUS_SUCCESS;
        resource->expression_property_4 = value;
        resource->expression_property_4_dirty = TRUE;
        return STATUS_SUCCESS;
    case 0x0b:
        if (resource->expression_node_offset == value) return STATUS_SUCCESS;
        resource->expression_node_offset = value;
        resource->expression_nodes_dirty = TRUE;
        return STATUS_SUCCESS;
    case 0x0c:
        if (resource->expression_node_size == value) return STATUS_SUCCESS;
        resource->expression_node_size = value;
        resource->expression_nodes_dirty = TRUE;
        return STATUS_SUCCESS;
    default:
        return STATUS_NOT_SUPPORTED;
    }
}

static NTSTATUS set_dcomp_expression_buffer_property( struct dcomp_resource_view *resource,
                                                       UINT property, const BYTE *data, UINT size )
{
    BYTE *copy;
    UINT metadata_type;

    if (property == 5)
    {
        if (resource->expression_metadata_size) return STATUS_ACCESS_DENIED;
        if (size != 0 && size != 12 && size != 16) return STATUS_INVALID_PARAMETER;
        if (size)
        {
            memcpy( &metadata_type, data, sizeof(metadata_type) );
            if ((size == 12 && metadata_type != 1) ||
                (size == 16 && metadata_type != 2)) return STATUS_INVALID_PARAMETER;
        }
        if (size) memcpy( resource->expression_metadata, data, size );
        resource->expression_metadata_size = size;
        resource->expression_base_dirty = TRUE;
        return STATUS_SUCCESS;
    }
    if (property != 0x0e || resource->expression_reference_info)
        return property == 0x0e ? STATUS_ACCESS_DENIED : STATUS_NOT_SUPPORTED;
    if (size % 20) return STATUS_INVALID_PARAMETER;
    if (size)
    {
        if (!(copy = malloc( size ))) return STATUS_NO_MEMORY;
        memcpy( copy, data, size );
        resource->expression_reference_info = copy;
    }
    resource->expression_reference_count = size / 20;
    resource->expression_reference_info_dirty = TRUE;
    return STATUS_SUCCESS;
}

static NTSTATUS set_dcomp_expression_reference_property( struct dcomp_channel_view *view,
                                                          struct dcomp_resource_view *resource,
                                                          UINT property, UINT reference_id )
{
    struct dcomp_resource_view *reference = NULL;

    if (reference_id && !(reference = find_dcomp_resource_view( view, reference_id )))
        return STATUS_ACCESS_DENIED;
    if (property == 2)
    {
        if (reference && !is_dcomp_derived_resource_type( reference->type, 0x87 ))
            return STATUS_INVALID_PARAMETER;
        resource->expression_property_resource_id = reference_id;
        resource->expression_base_dirty = TRUE;
        return STATUS_SUCCESS;
    }
    if (property == 0x0a)
    {
        if (reference && resource->type == 0x3c && reference->type != 0x9d)
            return STATUS_INVALID_PARAMETER;
        replace_dcomp_resource_reference( &resource->expression_shared_section, reference );
        resource->expression_nodes_dirty = TRUE;
        remove_unannounced_dcomp_resources( view );
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS set_dcomp_expression_reference_array_property( struct dcomp_channel_view *view,
                                                                struct dcomp_resource_view *resource,
                                                                UINT property, const BYTE *data,
                                                                UINT count )
{
    struct dcomp_resource_view *reference;
    UINT *sources, i, id;

    if (property != 0x0d || !data) return STATUS_INVALID_PARAMETER;
    if (resource->expression_sources) return STATUS_ACCESS_DENIED;
    if (count > UINT_MAX / sizeof(*sources)) return STATUS_NO_MEMORY;
    if (count && !(sources = malloc( count * sizeof(*sources) ))) return STATUS_NO_MEMORY;
    for (i = 0; i < count; ++i)
    {
        memcpy( &id, data + i * sizeof(id), sizeof(id) );
        if (!id || !(reference = find_dcomp_resource_view( view, id )))
        {
            free( sources );
            return id ? STATUS_ACCESS_DENIED : STATUS_INVALID_PARAMETER;
        }
        sources[i] = id;
    }
    resource->expression_sources = count ? sources : NULL;
    resource->expression_source_count = count;
    resource->expression_sources_dirty = TRUE;
    return STATUS_SUCCESS;
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

static NTSTATUS publish_dcomp_resource( UINT channel, UINT resource, UINT type, HANDLE *handle )
{
    NTSTATUS status;

    *handle = NULL;
    SERVER_START_REQ( publish_dcomp_resource )
    {
        req->channel = channel;
        req->resource = resource;
        req->type = type;
        status = wine_server_call( req );
        if (!status) *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return status;
}

static NTSTATUS create_dcomp_shared_resource( UINT type, HANDLE *handle )
{
    NTSTATUS status;

    SERVER_START_REQ( create_dcomp_shared_resource )
    {
        req->type = type;
        status = wine_server_call( req );
        if (!status) *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return status;
}

static NTSTATUS open_dcomp_shared_resource( HANDLE handle, UINT channel, UINT type )
{
    NTSTATUS status;

    SERVER_START_REQ( open_dcomp_shared_resource )
    {
        req->handle = wine_server_obj_handle( handle );
        req->channel = channel;
        req->type = type;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    TRACE( "handle %p, channel %#x, type %#x, status %#x\n", handle, channel, type, status );
    return status;
}

static void free_dcomp_resource_views( struct dcomp_channel_view *view )
{
    struct dcomp_resource_view *resource, *next;

    LIST_FOR_EACH_ENTRY_SAFE( resource, next, &view->resources, struct dcomp_resource_view, entry )
    {
        list_remove( &resource->entry );
        free_dcomp_resource_view( resource );
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

static NTSTATUS process_dcomp_commands( struct dcomp_channel_view *view, BYTE *buffer,
                                        UINT length, BOOL allow_indirect, ULONG *processed )
{
    struct dcomp_resource_view *resource;
    UINT command_size, id, indirect_size, type;
    BYTE *indirect;
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
            UINT flags;

            memcpy( &id, buffer + 4, sizeof(id) );
            memcpy( &type, buffer + 8, sizeof(type) );
            memcpy( &flags, buffer + 12, sizeof(flags) );
            if (!id || !type || type > 0xc1) return STATUS_INVALID_PARAMETER;
            if (find_any_dcomp_resource_view( view, id )) return STATUS_ACCESS_DENIED;
            if (!(resource = calloc( 1, sizeof(*resource) ))) return STATUS_NO_MEMORY;
            initialize_dcomp_resource_view( resource, id, type );
            resource->shared_write = !!flags;
            list_add_tail( &view->resources, &resource->entry );
        }
        else if (type == 3)
        {
            HANDLE handle;
            UINT mode, resource_type;

            memcpy( &id, buffer + 4, sizeof(id) );
            memcpy( &handle, buffer + 8, sizeof(handle) );
            memcpy( &resource_type, buffer + 16, sizeof(resource_type) );
            memcpy( &mode, buffer + 20, sizeof(mode) );
            if (!id || !handle || !resource_type) return STATUS_INVALID_PARAMETER;
            if (find_any_dcomp_resource_view( view, id )) return STATUS_ACCESS_DENIED;
            if (resource_type != 0xb8 && mode) return STATUS_NOT_SUPPORTED;
            if ((status = open_dcomp_shared_resource( handle, view->channel,
                                                       resource_type ))) return status;
            if (!(resource = calloc( 1, sizeof(*resource) ))) return STATUS_NO_MEMORY;
            initialize_dcomp_resource_view( resource, id, resource_type );
            resource->visual_target = resource_type == 0xb8 && !mode;
            resource->shared_duplicate = resource_type != 0xb8 || !!mode;
            if (resource->shared_duplicate)
            {
                resource->manipulation_components_dirty = FALSE;
                resource->manipulation_cookie_dirty = FALSE;
            }
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
            else if (resource->type == 0x7f)
            {
                status = set_dcomp_rectangle_integer_property( resource, property, value );
                if (status != STATUS_NOT_SUPPORTED && status) return status;
            }
            else if (resource->type == 0x3c)
            {
                status = set_dcomp_expression_integer_property( resource, property, value );
                if (status != STATUS_NOT_SUPPORTED && status) return status;
            }
            else if (resource->type == 0x6a && !resource->shared_duplicate)
            {
                status = set_dcomp_manipulation_integer_property( resource, property, value );
                if (status != STATUS_NOT_SUPPORTED && status) return status;
            }
            else if (resource->type == 0x60)
            {
                if ((status = set_dcomp_legacy_target_integer_property( resource,
                                                                         property, value )))
                    return status;
            }
        }
        else if (type == 12)
        {
            float value;
            UINT property;

            memcpy( &id, buffer + 4, sizeof(id) );
            memcpy( &property, buffer + 8, sizeof(property) );
            memcpy( &value, buffer + 12, sizeof(value) );
            if (!(resource = find_dcomp_resource_view( view, id ))) return STATUS_ACCESS_DENIED;
            if (resource->type == 0x60 &&
                (status = set_dcomp_legacy_target_float_property( resource, property, value )))
                return status;
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
            else if (resource->type == 0x16)
            {
                if ((status = set_dcomp_color_brush_buffer_property( resource, property,
                                                                      buffer + 16, size )))
                    return status;
            }
            else if (resource->type == 0x7f)
            {
                if ((status = set_dcomp_rectangle_buffer_property( resource, property,
                                                                    buffer + 16, size )))
                    return status;
            }
            else if (resource->type == 0x7c)
            {
                if ((status = set_dcomp_property_set_buffer_property( resource, property,
                                                                       buffer + 16, size )))
                    return status;
            }
            else if (resource->type == 0x3c)
            {
                status = set_dcomp_expression_buffer_property( resource, property,
                                                                buffer + 16, size );
                if (status != STATUS_NOT_SUPPORTED && status) return status;
            }
            else if (resource->type == 0x6a && !resource->shared_duplicate)
            {
                if ((status = set_dcomp_manipulation_buffer_property( resource, property,
                                                                       buffer + 16, size )))
                    return status;
            }
            else if (resource->type == 0x60)
            {
                if ((status = set_dcomp_legacy_target_buffer_property( resource, property,
                                                                        buffer + 16, size )))
                    return status;
            }
            else if (resource->type == 0x36)
            {
                if ((status = set_dcomp_desktop_tree_buffer_property( resource, property,
                                                                       buffer + 16, size )))
                    return status;
            }
        }
        else if (type == 13)
        {
            UINT property;
            UINT64 handle;

            memcpy( &id, buffer + 4, sizeof(id) );
            memcpy( &property, buffer + 8, sizeof(property) );
            memcpy( &handle, buffer + 16, sizeof(handle) );
            if (!(resource = find_dcomp_resource_view( view, id ))) return STATUS_ACCESS_DENIED;
            status = set_dcomp_window_node_handle_property( resource, property, handle );
            if (status != STATUS_NOT_SUPPORTED && status) return status;
        }
        else if (type == 9)
        {
            HANDLE handle;

            memcpy( &id, buffer + 4, sizeof(id) );
            if (!(resource = find_dcomp_resource_view( view, id ))) return STATUS_ACCESS_DENIED;
            if (!resource->shared_write) return STATUS_INVALID_PARAMETER;
            if ((status = publish_dcomp_resource( view->channel, resource->id,
                                                   resource->type, &handle ))) return status;
            memcpy( buffer + 8, &handle, sizeof(handle) );
        }
        else if (type == 16)
        {
            UINT property, root_id;

            memcpy( &id, buffer + 4, sizeof(id) );
            memcpy( &property, buffer + 8, sizeof(property) );
            memcpy( &root_id, buffer + 12, sizeof(root_id) );
            if (!(resource = find_dcomp_resource_view( view, id ))) return STATUS_ACCESS_DENIED;
            if (resource->visual_target)
            {
                if ((status = set_dcomp_visual_target_root( view, resource, property, root_id )))
                    return status;
            }
            else if (resource->visual)
            {
                status = set_dcomp_visual_reference_property( view, resource, property, root_id );
                if (status != STATUS_NOT_SUPPORTED && status) return status;
            }
            else if (resource->type == 0x3c)
            {
                status = set_dcomp_expression_reference_property( view, resource,
                                                                   property, root_id );
                if (status != STATUS_NOT_SUPPORTED && status) return status;
            }
            else if (resource->type == 0x60 || resource->type == 0x36)
            {
                if ((status = set_dcomp_render_target_reference_property( view, resource,
                                                                           property, root_id )))
                    return status;
            }
        }
        else if (type == 17)
        {
            UINT count, property;

            memcpy( &id, buffer + 4, sizeof(id) );
            memcpy( &property, buffer + 8, sizeof(property) );
            memcpy( &count, buffer + 12, sizeof(count) );
            if (!(resource = find_dcomp_resource_view( view, id ))) return STATUS_ACCESS_DENIED;
            if (resource->type == 0x3c)
            {
                status = set_dcomp_expression_reference_array_property( view, resource, property,
                                                                         buffer + 16, count );
                if (status != STATUS_NOT_SUPPORTED && status) return status;
            }
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

static void free_dcomp_connection_batches( struct dcomposition_connection_batch *batch )
{
    while (batch)
    {
        struct dcomposition_connection_batch *next = batch->next;

        free( batch );
        batch = next;
    }
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
        /* Native win32k validates and copies every block payload but clears
         * the caller's block type before passing the private list to the
         * channel parser.  The type is producer metadata, not a protocol
         * discriminator at this boundary. */
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

static data_size_t dcomp_rectangle_update_size( const struct dcomp_resource_view *resource )
{
    UINT dirty = resource->announced ? resource->rectangle_dirty : 0x1f;
    data_size_t size = 0;

    if (dirty & 1) size += 48;
    if (dirty & 2) size += 16;
    if (dirty & 4) size += 16;
    if (dirty & 8) size += 16;
    if (dirty & 0x10) size += 16;
    return size;
}

static BYTE *emit_dcomp_reference_update( BYTE *cursor, UINT opcode, UINT id,
                                           const struct dcomp_resource_view *reference )
{
    UINT command[4] = {16, opcode, id, reference ? reference->id : 0};

    memcpy( cursor, command, sizeof(command) );
    return cursor + sizeof(command);
}

static data_size_t dcomp_window_node_update_size( const struct dcomp_resource_view *resource )
{
    static const BYTE sizes[] =
    {
        28, 28, 28, 20, 28, 20, 16, 16, 16,
        16, 16, 28, 28, 28, 16, 16, 20, 20,
    };
    data_size_t size = 0;
    UINT dirty = resource->window_node_dirty;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(sizes); ++i)
        if (dirty & (1u << i)) size += sizes[i];
    return size;
}

static BYTE *emit_dcomp_window_node_value( BYTE *cursor, UINT opcode, UINT id,
                                            const void *value, UINT value_size )
{
    UINT size = 12 + value_size;

    memcpy( cursor, &size, sizeof(size) );
    memcpy( cursor + 4, &opcode, sizeof(opcode) );
    memcpy( cursor + 8, &id, sizeof(id) );
    memcpy( cursor + 12, value, value_size );
    return cursor + size;
}

static BYTE *emit_dcomp_window_node_updates( BYTE *cursor,
                                              const struct dcomp_resource_view *resource )
{
    UINT dirty = resource->window_node_dirty, value;

    if (dirty) TRACE( "window node %#x dirty %#x\n", resource->id, dirty );
    if (dirty & 0x1)
        cursor = emit_dcomp_window_node_value( cursor, 0x295, resource->id,
                                               resource->window_alpha_margins, 16 );
    if (dirty & 0x2)
        cursor = emit_dcomp_window_node_value( cursor, 0x296, resource->id,
                                               resource->window_content_relative_client_rect, 16 );
    if (dirty & 0x4)
        cursor = emit_dcomp_window_node_value( cursor, 0x297, resource->id,
                                               resource->window_content_relative_window_rect, 16 );
    if (dirty & 0x8)
        cursor = emit_dcomp_window_node_value( cursor, 0x298, resource->id,
                                               resource->window_content_size, 8 );
    if (dirty & 0x10)
        cursor = emit_dcomp_window_node_value( cursor, 0x299, resource->id,
                                               resource->window_extended_bounds, 16 );
    if (dirty & 0x20)
        cursor = emit_dcomp_window_node_value( cursor, 0x29a, resource->id,
                                               &resource->window_flip_surface, 8 );
    if (dirty & 0x40)
    {
        value = resource->window_flip_surface_clip ?
                resource->window_flip_surface_clip->id : 0;
        cursor = emit_dcomp_window_node_value( cursor, 0x29b, resource->id, &value, 4 );
    }
    if (dirty & 0x80)
    {
        value = resource->window_flags[0];
        cursor = emit_dcomp_window_node_value( cursor, 0x29c, resource->id, &value, 4 );
    }
    if (dirty & 0x100)
    {
        value = resource->window_flags[1];
        cursor = emit_dcomp_window_node_value( cursor, 0x29d, resource->id, &value, 4 );
    }
    if (dirty & 0x200)
    {
        value = resource->window_flags[2];
        cursor = emit_dcomp_window_node_value( cursor, 0x29e, resource->id, &value, 4 );
    }
    if (dirty & 0x400)
    {
        value = resource->window_flags[3];
        cursor = emit_dcomp_window_node_value( cursor, 0x29f, resource->id, &value, 4 );
    }
    if (dirty & 0x800)
        cursor = emit_dcomp_window_node_value( cursor, 0x2a0, resource->id,
                                               resource->window_maximized_clip_margins, 16 );
    if (dirty & 0x1000)
        cursor = emit_dcomp_window_node_value( cursor, 0x2a1, resource->id,
                                               resource->window_process_attribution, 16 );
    if (dirty & 0x2000)
        cursor = emit_dcomp_window_node_value( cursor, 0x2a2, resource->id,
                                               resource->window_source_modifications, 16 );
    if (dirty & 0x4000)
    {
        value = resource->window_sprite_bitmap ? resource->window_sprite_bitmap->id : 0;
        cursor = emit_dcomp_window_node_value( cursor, 0x2a3, resource->id, &value, 4 );
    }
    if (dirty & 0x8000)
    {
        value = resource->window_sprite_clip ? resource->window_sprite_clip->id : 0;
        cursor = emit_dcomp_window_node_value( cursor, 0x2a4, resource->id, &value, 4 );
    }
    if (dirty & 0x10000)
        cursor = emit_dcomp_window_node_value( cursor, 0x2a5, resource->id,
                                               &resource->window_sprite_handle, 8 );
    if (dirty & 0x20000)
        cursor = emit_dcomp_window_node_value( cursor, 0x2a6, resource->id,
                                               &resource->window_handle, 8 );
    return cursor;
}

static data_size_t dcomp_desktop_tree_update_size( const struct dcomp_resource_view *resource )
{
    data_size_t size = 0;

    if (resource->desktop_tree_adapter_dirty) size += 20;
    if (resource->desktop_tree_root_dirty) size += 16;
    return size;
}

static BYTE *emit_dcomp_desktop_tree_updates( BYTE *cursor,
                                               const struct dcomp_resource_view *resource )
{
    UINT command[5];

    if (resource->desktop_tree_adapter_dirty)
    {
        command[0] = 20;
        command[1] = 0x203; /* MILCMD_DESKTOPCOMPOSITIONTREE_SETADAPTERLUID */
        command[2] = resource->id;
        memcpy( command + 3, &resource->desktop_tree_adapter_luid,
                sizeof(resource->desktop_tree_adapter_luid) );
        memcpy( cursor, command, 20 );
        cursor += 20;
    }
    if (resource->desktop_tree_root_dirty)
        cursor = emit_dcomp_reference_update( cursor, 0x204, resource->id,
                                               resource->desktop_tree_root );
    return cursor;
}

static data_size_t dcomp_legacy_target_update_size( const struct dcomp_resource_view *resource )
{
    data_size_t size = 0;

    if (resource->render_target_create_dirty) size += 36;
    if (resource->render_target_desktop_tree_dirty) size += 16;
    if (resource->render_target_transform_dirty) size += 68;
    if (resource->render_target_hdr_dirty) size += 16;
    if (resource->render_target_refresh_dirty) size += 12;
    return size;
}

static BYTE *emit_dcomp_legacy_target_updates( BYTE *cursor,
                                                const struct dcomp_resource_view *resource )
{
    UINT command[17];

    if (resource->render_target_create_dirty)
    {
        memset( command, 0, 36 );
        command[0] = 36;
        command[1] = 0xe0; /* MILCMD_LEGACYRENDERTARGET_CREATE */
        command[2] = resource->id;
        memcpy( command + 3, &resource->render_target_adapter_luid,
                sizeof(resource->render_target_adapter_luid) );
        command[5] = resource->render_target_display_id;
        command[6] = resource->render_target_format;
        command[7] = resource->render_target_color_space;
        command[8] = resource->render_target_flags;
        memcpy( cursor, command, 36 );
        cursor += 36;
    }
    if (resource->render_target_desktop_tree_dirty)
        cursor = emit_dcomp_reference_update( cursor, 0xe1, resource->id,
                                               resource->render_target_desktop_tree );
    if (resource->render_target_transform_dirty)
    {
        memset( command, 0, sizeof(command) );
        command[0] = sizeof(command);
        command[1] = 0xe3; /* MILCMD_LEGACYRENDERTARGET_UPDATETRANSFORM */
        command[2] = resource->id;
        memcpy( command + 3, &resource->render_target_monitor,
                sizeof(resource->render_target_monitor) );
        memcpy( command + 5, resource->render_target_float_rect,
                sizeof(resource->render_target_float_rect) );
        memcpy( command + 9, &resource->render_target_scale,
                sizeof(resource->render_target_scale) );
        memcpy( command + 10, &resource->render_target_scale2,
                sizeof(resource->render_target_scale2) );
        memcpy( command + 11, resource->render_target_rect,
                sizeof(resource->render_target_rect) );
        command[15] = resource->render_target_rotation;
        memcpy( cursor, command, sizeof(command) );
        cursor += sizeof(command);
    }
    if (resource->render_target_hdr_dirty)
    {
        command[0] = 16;
        command[1] = 0xe2; /* MILCMD_LEGACYRENDERTARGET_UPDATESDRTOHDRMULTIPLIER */
        command[2] = resource->id;
        memcpy( command + 3, &resource->render_target_sdr_to_hdr,
                sizeof(resource->render_target_sdr_to_hdr) );
        memcpy( cursor, command, 16 );
        cursor += 16;
    }
    if (resource->render_target_refresh_dirty)
    {
        command[0] = 12;
        command[1] = 0x151; /* MILCMD_RENDERTARGET_UPDATEREFRESHRATE */
        command[2] = resource->id;
        memcpy( cursor, command, 12 );
        cursor += 12;
    }
    return cursor;
}

static BYTE *emit_dcomp_rectangle_updates( BYTE *cursor,
                                            const struct dcomp_resource_view *resource )
{
    static const UINT edge_opcodes[4] = {0x13d, 0x142, 0x140, 0x13c};
    UINT dirty = resource->announced ? resource->rectangle_dirty : 0x1f;
    UINT command[12], i;

    if (dirty & 1)
    {
        memset( command, 0, sizeof(command) );
        command[0] = sizeof(command);
        command[1] = 0x13f;
        command[2] = resource->id;
        memcpy( command + 3, resource->rectangle + 4, 8 * sizeof(float) );
        ((BYTE *)&command[11])[0] = resource->rectangle_mode;
        ((BYTE *)&command[11])[1] = resource->rectangle_expression_mode;
        ((BYTE *)&command[11])[2] = resource->rectangle_flag;
        memcpy( cursor, command, sizeof(command) );
        cursor += sizeof(command);
    }
    for (i = 0; i < 4; ++i)
    {
        if (!(dirty & (2 << i))) continue;
        command[0] = 16;
        command[1] = edge_opcodes[i];
        command[2] = resource->id;
        memcpy( command + 3, resource->rectangle + i, sizeof(float) );
        memcpy( cursor, command, 16 );
        cursor += 16;
    }
    return cursor;
}

static BYTE *emit_dcomp_component_transform3d_defaults( BYTE *cursor, UINT id )
{
    UINT command[19];

    memset( command, 0, sizeof(command) );
    command[0] = 20; command[1] = 0x3d; command[2] = id;
    memcpy( cursor, command, 20 ); cursor += 20;
    command[0] = 24; command[1] = 0x3e;
    memcpy( cursor, command, 24 ); cursor += 24;
    command[1] = 0x3f;
    memcpy( cursor, command, 24 ); cursor += 24;
    command[0] = 28; command[1] = 0x40; command[6] = 0x3f800000;
    memcpy( cursor, command, 28 ); cursor += 28;
    memset( command + 3, 0, 4 * sizeof(UINT) );
    command[0] = 24; command[1] = 0x42; command[5] = 0x3f800000;
    memcpy( cursor, command, 24 ); cursor += 24;
    command[0] = 16; command[1] = 0x41; command[3] = 0;
    memcpy( cursor, command, 16 ); cursor += 16;
    command[0] = 24; command[1] = 0x43;
    command[3] = command[4] = command[5] = 0x3f800000;
    memcpy( cursor, command, 24 ); cursor += 24;
    memset( command, 0, sizeof(command) );
    command[0] = sizeof(command); command[1] = 0x44; command[2] = id;
    command[3] = command[8] = command[13] = command[18] = 0x3f800000;
    memcpy( cursor, command, sizeof(command) );
    return cursor + sizeof(command);
}

static data_size_t dcomp_property_set_update_size( const struct dcomp_resource_view *resource )
{
    data_size_t size = 0;
    UINT i;

    for (i = 0; i < resource->property_count; ++i)
        if (resource->properties[i].dirty) size += 28 + resource->properties[i].size;
    return size;
}

static BYTE *emit_dcomp_property_set_updates( BYTE *cursor,
                                               const struct dcomp_resource_view *resource )
{
    const struct dcomp_property_value *value;
    UINT command[7], i;

    for (i = 0; i < resource->property_count; ++i)
    {
        value = &resource->properties[i];
        if (!value->dirty) continue;
        memset( command, 0, sizeof(command) );
        command[0] = sizeof(command) + value->size;
        command[1] = 0x135;
        command[2] = resource->id;
        command[3] = i;
        command[4] = value->offset;
        command[5] = value->type;
        ((BYTE *)&command[6])[0] = value->added;
        memcpy( cursor, command, sizeof(command) );
        memcpy( cursor + sizeof(command), value->data, value->size );
        cursor += sizeof(command) + value->size;
    }
    return cursor;
}

static data_size_t dcomp_manipulation_update_size( const struct dcomp_resource_view *resource )
{
    data_size_t size = 0;

    if (resource->shared_duplicate) return 0;
    if (resource->manipulation_components_dirty) size += 60;
    if (resource->manipulation_cookie_dirty) size += 16;
    return size;
}

static BYTE *emit_dcomp_manipulation_updates( BYTE *cursor,
                                               const struct dcomp_resource_view *resource )
{
    /* Duplicate state is supplied by its owner channel.  Keep this predicate
     * paired with dcomp_manipulation_update_size() so the 12-byte
     * complete-duplicate payload cannot be overrun by owner-only defaults. */
    if (resource->shared_duplicate) return cursor;

    if (resource->manipulation_components_dirty)
    {
        UINT command[15] = {60, 0xf4, resource->id};

        memcpy( command + 3, resource->manipulation_components,
                sizeof(resource->manipulation_components) );
        memcpy( cursor, command, sizeof(command) );
        cursor += sizeof(command);
    }
    if (resource->manipulation_cookie_dirty)
    {
        UINT command[4] = {16, 0xf5, resource->id,
                           resource->manipulation_tracing_cookie};

        memcpy( cursor, command, sizeof(command) );
        cursor += sizeof(command);
    }
    return cursor;
}

static data_size_t dcomp_expression_update_size( const struct dcomp_resource_view *resource )
{
    data_size_t size = 0;

    if (resource->expression_base_dirty) size += 44;
    if (resource->expression_property_4_dirty) size += 16;
    if (resource->expression_sources_dirty) size += 20 + 4 * resource->expression_source_count;
    if (resource->expression_reference_info_dirty)
        size += 20 + 20 * resource->expression_reference_count;
    if (resource->expression_nodes_dirty && resource->expression_shared_section &&
        resource->expression_node_size) size += 24;
    return size;
}

static BYTE *emit_dcomp_expression_updates( struct dcomp_channel_view *view, BYTE *cursor,
                                             const struct dcomp_resource_view *resource )
{
    struct dcomp_resource_view *reference;
    UINT command[11], i, metadata_kind = 0;
    UINT64 metadata_value = 0;

    if (resource->expression_base_dirty)
    {
        memset( command, 0, sizeof(command) );
        command[0] = sizeof(command);
        command[1] = 0x11;
        command[2] = resource->id;
        if (resource->expression_property_enabled &&
            (reference = find_dcomp_resource_view( view,
                                                    resource->expression_property_resource_id )))
        {
            command[3] = reference->type;
            command[4] = reference->id;
        }
        command[5] = resource->expression_property_3;
        if (resource->expression_metadata_size)
        {
            memcpy( &metadata_kind, resource->expression_metadata, sizeof(metadata_kind) );
            if (metadata_kind == 1)
                metadata_value = resource->expression_metadata[8];
            else if (metadata_kind == 2)
                memcpy( &metadata_value, resource->expression_metadata + 8,
                        sizeof(metadata_value) );
            memcpy( command + 7, &metadata_value, sizeof(metadata_value) );
            ((USHORT *)&command[9])[0] = resource->expression_metadata[4];
            memcpy( (BYTE *)command + 38, resource->expression_metadata, sizeof(USHORT) );
        }
        command[10] = resource->expression_type;
        memcpy( cursor, command, sizeof(command) );
        cursor += sizeof(command);
    }
    if (resource->expression_property_4_dirty)
    {
        UINT property_command[4] = {16, 0x12, resource->id,
                                    resource->expression_property_4};

        memcpy( cursor, property_command, sizeof(property_command) );
        cursor += sizeof(property_command);
    }
    if (resource->expression_sources_dirty)
    {
        command[0] = 20 + 4 * resource->expression_source_count;
        command[1] = 0x89;
        command[2] = resource->id;
        command[3] = resource->expression_source_count;
        command[4] = resource->expression_source_count;
        memcpy( cursor, command, 20 );
        cursor += 20;
        for (i = 0; i < resource->expression_source_count; ++i)
        {
            UINT id = 0;

            if ((reference = find_dcomp_resource_view( view,
                                                        resource->expression_sources[i] )))
                id = reference->id;
            memcpy( cursor, &id, sizeof(id) );
            cursor += sizeof(id);
        }
    }
    if (resource->expression_reference_info_dirty)
    {
        command[0] = 20 + 20 * resource->expression_reference_count;
        command[1] = 0x88;
        command[2] = resource->id;
        command[3] = resource->expression_reference_count;
        command[4] = resource->expression_reference_count;
        memcpy( cursor, command, 20 );
        cursor += 20;
        memcpy( cursor, resource->expression_reference_info,
                20 * resource->expression_reference_count );
        cursor += 20 * resource->expression_reference_count;
    }
    if (resource->expression_nodes_dirty && resource->expression_shared_section &&
        resource->expression_node_size)
    {
        UINT nodes_command[6] = {24, 0x86, resource->id,
                                 resource->expression_shared_section->id,
                                 resource->expression_node_offset,
                                 resource->expression_node_size};

        memcpy( cursor, nodes_command, sizeof(nodes_command) );
        cursor += sizeof(nodes_command);
    }
    return cursor;
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
        if (!resource->announced) resource_size += resource->shared_duplicate ? 12 : 16;
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
        if (!resource->released && resource->type == 0xc0)
            resource_size += dcomp_window_node_update_size( resource );
        if (!resource->released && resource->type == 0x36)
            resource_size += dcomp_desktop_tree_update_size( resource );
        if (!resource->released && resource->type == 0x60)
            resource_size += dcomp_legacy_target_update_size( resource );
        if (!resource->released && resource->color_dirty) resource_size += 28;
        if (!resource->released && resource->type == 0x7f)
            resource_size += dcomp_rectangle_update_size( resource );
        if (!resource->released && resource->type == 0x1e && !resource->announced)
            resource_size += 236;
        if (!resource->released && resource->type == 0x7c)
            resource_size += dcomp_property_set_update_size( resource );
        if (!resource->released && resource->type == 0x3c)
            resource_size += dcomp_expression_update_size( resource );
        if (!resource->released && resource->type == 0x6a)
            resource_size += dcomp_manipulation_update_size( resource );
        if (!resource->released && resource->visual_transform_dirty) resource_size += 16;
        if (!resource->released && resource->visual_clip_dirty) resource_size += 16;
        if (!resource->released && resource->sprite_content_dirty) resource_size += 16;
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
        if (resource->shared_duplicate)
        {
            command[0] = 12;
            command[1] = 0x27; /* MILCMD_CHANNEL_COMPLETEDUPLICATERESOURCE */
            command[2] = resource->id;
            memcpy( cursor, command, 12 );
            cursor += 12;
        }
        else
        {
            command[0] = sizeof(command);
            command[1] = 0x28; /* MILCMD_CHANNEL_CREATERESOURCE */
            command[2] = resource->id;
            command[3] = resource->type;
            memcpy( cursor, command, sizeof(command) );
            cursor += sizeof(command);
        }
    }
    /* Preserve proxy creation order.  Genuine clients create the legacy target
     * before its desktop tree and send the target association before later tree
     * updates. */
    LIST_FOR_EACH_ENTRY( resource, &view->resources, struct dcomp_resource_view, entry )
    {
        if (resource->released) continue;
        if (resource->type == 0x60)
            cursor = emit_dcomp_legacy_target_updates( cursor, resource );
        else if (resource->type == 0x36)
            cursor = emit_dcomp_desktop_tree_updates( cursor, resource );
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
        if (!resource->released && resource->type == 0xc0)
            cursor = emit_dcomp_window_node_updates( cursor, resource );
    }
    LIST_FOR_EACH_ENTRY( resource, &view->resources, struct dcomp_resource_view, entry )
    {
        UINT command[7] = {28, 0x31, resource->id};

        if (resource->released) continue;
        if (resource->color_dirty)
        {
            memcpy( command + 3, resource->color, sizeof(resource->color) );
            memcpy( cursor, command, sizeof(command) );
            cursor += sizeof(command);
        }
        if (resource->type == 0x7f)
            cursor = emit_dcomp_rectangle_updates( cursor, resource );
        if (resource->type == 0x1e && !resource->announced)
            cursor = emit_dcomp_component_transform3d_defaults( cursor, resource->id );
        if (resource->type == 0x7c)
            cursor = emit_dcomp_property_set_updates( cursor, resource );
        if (resource->type == 0x3c)
            cursor = emit_dcomp_expression_updates( view, cursor, resource );
        if (resource->type == 0x6a)
            cursor = emit_dcomp_manipulation_updates( cursor, resource );
    }
    LIST_FOR_EACH_ENTRY( resource, &view->resources, struct dcomp_resource_view, entry )
    {
        if (resource->released) continue;
        if (resource->visual_transform_dirty)
            cursor = emit_dcomp_reference_update( cursor, 0x1a0, resource->id,
                                                   resource->visual_transform );
        if (resource->visual_clip_dirty)
            cursor = emit_dcomp_reference_update( cursor, 0x18c, resource->id,
                                                   resource->visual_clip );
        if (resource->sprite_content_dirty)
            cursor = emit_dcomp_reference_update( cursor, 0x16e, resource->id,
                                                   resource->sprite_content );
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
            free_dcomp_resource_view( resource );
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
            resource->window_node_dirty = 0;
            resource->render_target_create_dirty = FALSE;
            resource->render_target_desktop_tree_dirty = FALSE;
            resource->render_target_transform_dirty = FALSE;
            resource->render_target_hdr_dirty = FALSE;
            resource->render_target_refresh_dirty = FALSE;
            resource->desktop_tree_adapter_dirty = FALSE;
            resource->desktop_tree_root_dirty = FALSE;
            resource->color_dirty = FALSE;
            resource->rectangle_dirty = 0;
            resource->visual_transform_dirty = FALSE;
            resource->visual_clip_dirty = FALSE;
            resource->sprite_content_dirty = FALSE;
            if (resource->type == 0x7c)
            {
                UINT i;

                for (i = 0; i < resource->property_count; ++i)
                {
                    resource->properties[i].dirty = FALSE;
                    resource->properties[i].added = FALSE;
                }
            }
            resource->expression_base_dirty = FALSE;
            resource->expression_property_4_dirty = FALSE;
            resource->expression_sources_dirty = FALSE;
            resource->expression_reference_info_dirty = FALSE;
            resource->expression_nodes_dirty = FALSE;
            resource->manipulation_components_dirty = FALSE;
            resource->manipulation_cookie_dirty = FALSE;
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

NTSTATUS WINAPI NtDCompositionCreateSharedResourceHandle( UINT type, HANDLE *handle )
{
    TRACE( "type %#x, handle %p\n", type, handle );

    if (type != 0x13 && type != 0x82 && type != 0xb8) return STATUS_INVALID_PARAMETER;
    if (!handle) return STATUS_INVALID_PARAMETER;
    return create_dcomp_shared_resource( type, handle );
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
            free_dcomp_connection_batches( view->batch );
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
    struct dcomposition_connection_batch *record, *records = NULL, **next = &records;
    BYTE *data;
    data_size_t size = 0;
    UINT count = 0;
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
        free_dcomp_connection_batches( view->batch );
        view->batch = NULL;
    }
    do
    {
        record = NULL;
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
        if (record)
        {
            *next = record;
            next = &record->next;
            count++;
        }
    } while (!status && record && count < DCOMP_PROTOCOL_MAX_BLOCKS);
    free( data );

    if (status)
    {
        free_dcomp_connection_batches( records );
        records = NULL;
    }
    else if (records)
    {
        if (!view)
        {
            if (!(view = calloc( 1, sizeof(*view) )))
            {
                free_dcomp_connection_batches( records );
                records = NULL;
                status = STATUS_NO_MEMORY;
            }
            else
            {
                view->connection = connection;
                list_add_tail( &dcomp_connection_batch_views, &view->entry );
            }
        }
        if (view) view->batch = records;
    }
    pthread_mutex_unlock( &dcomp_channel_lock );
    TRACE( "returning status %#x with %u records\n", status, count );
    if (!status) *batch = records;
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
