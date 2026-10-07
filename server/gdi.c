/*
 * Session GDI object identities
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */
#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "wingdi.h"
#include "winternl.h"
#include "ntgdi.h"
#include "object.h"
#include "request.h"
#include "process.h"
#include "handle.h"
#include "file.h"
#include "user.h"

#define FIRST_DYNAMIC_GDI_HANDLE 64

struct gdi_selection
{
    struct list entry;
    process_id_t pid;
    unsigned int count, readers;
};
struct gdi_slot
{
    process_id_t owner;
    unsigned char type, generation, stock;
    unsigned int selected, readers;
    struct list selections;
    struct object *section;
    struct gdi_bitmap_data *bitmap;
};
struct gdi_table
{
    struct list entry;
    unsigned int session_id, cursor;
    struct gdi_slot slots[GDI_MAX_HANDLE_COUNT];
};
static struct list gdi_tables = LIST_INIT(gdi_tables);

static struct gdi_table *get_gdi_table( unsigned int session_id, int create )
{
    struct gdi_table *table;
    LIST_FOR_EACH_ENTRY( table, &gdi_tables, struct gdi_table, entry )
        if (table->session_id == session_id) return table;
    if (!create) return NULL;
    if (!(table = calloc( 1, sizeof(*table) )))
    {
        set_error( STATUS_NO_MEMORY );
        return NULL;
    }
    table->session_id = session_id;
    table->cursor = FIRST_DYNAMIC_GDI_HANDLE;
    list_add_tail( &gdi_tables, &table->entry );
    return table;
}

static unsigned int slot_handle( struct gdi_slot *slot, unsigned int index )
{
    return index | ((slot->generation << 8 | slot->type | (slot->stock ? 0x80 : 0)) << 16);
}

static struct gdi_slot *find_gdi_slot( unsigned int handle, int owner_only )
{
    struct gdi_table *table = get_gdi_table( current->process->session_id, 0 );
    unsigned int index = handle & 0xffff;
    struct gdi_slot *slot;
    if (!table || index < FIRST_DYNAMIC_GDI_HANDLE) goto invalid;
    slot = &table->slots[index];
    if (!slot->type || ((handle >> 16) && handle != slot_handle( slot, index ))) goto invalid;
    if ((owner_only || !slot->stock) && slot->owner != current->process->id) goto invalid;
    return slot;
invalid:
    set_error( STATUS_INVALID_HANDLE );
    return NULL;
}

static void destroy_gdi_slot( struct gdi_slot *slot )
{
    struct gdi_selection *selection, *next;
    LIST_FOR_EACH_ENTRY_SAFE( selection, next, &slot->selections, struct gdi_selection, entry )
    {
        list_remove( &selection->entry );
        free( selection );
    }
    if (slot->section) release_object( slot->section );
    free( slot->bitmap );
    slot->section = NULL;
    slot->bitmap = NULL;
    slot->owner = slot->selected = slot->readers = slot->stock = slot->type = 0;
}

void cleanup_process_gdi_objects( struct process *process )
{
    struct gdi_table *table = get_gdi_table( process->session_id, 0 );
    struct gdi_selection *selection, *next;
    unsigned int i;
    if (!table) return;
    for (i = FIRST_DYNAMIC_GDI_HANDLE; i < GDI_MAX_HANDLE_COUNT; i++)
    {
        struct gdi_slot *slot = &table->slots[i];
        if (!slot->type) continue;
        LIST_FOR_EACH_ENTRY_SAFE( selection, next, &slot->selections, struct gdi_selection, entry )
            if (selection->pid == process->id)
            {
                slot->selected -= selection->count;
                slot->readers -= selection->readers;
                list_remove( &selection->entry );
                free( selection );
            }
        if (slot->owner == process->id) destroy_gdi_slot( slot );
    }
}

DECL_HANDLER(alloc_gdi_object)
{
    struct gdi_table *table;
    struct gdi_slot *slot;
    unsigned int i, index, type = req->type >> NTGDI_HANDLE_TYPE_SHIFT;
    switch (req->type)
    {
    case NTGDI_OBJ_DC: case NTGDI_OBJ_ENHMETADC: case NTGDI_OBJ_REGION:
    case NTGDI_OBJ_SURF: case NTGDI_OBJ_METAFILE: case NTGDI_OBJ_ENHMETAFILE:
    case NTGDI_OBJ_METADC: case NTGDI_OBJ_PAL: case NTGDI_OBJ_BITMAP:
    case NTGDI_OBJ_FONT: case NTGDI_OBJ_BRUSH: case NTGDI_OBJ_PEN:
    case NTGDI_OBJ_EXTPEN: case NTGDI_OBJ_MEMDC:
        break;
    default:
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    if (!(table = get_gdi_table( current->process->session_id, 1 ))) return;
    for (i = FIRST_DYNAMIC_GDI_HANDLE; i < GDI_MAX_HANDLE_COUNT; i++)
    {
        index = table->cursor++;
        if (table->cursor == GDI_MAX_HANDLE_COUNT) table->cursor = FIRST_DYNAMIC_GDI_HANDLE;
        slot = &table->slots[index];
        if (slot->type) continue;
        list_init( &slot->selections );
        slot->type = type;
        slot->owner = current->process->id;
        if (++slot->generation == 0x80) slot->generation = 1;
        reply->handle = index | ((slot->generation << 8 | type) << NTGDI_HANDLE_TYPE_SHIFT);
        return;
    }
    set_error( STATUS_NO_MEMORY );
}

DECL_HANDLER(free_gdi_object)
{
    struct gdi_slot *slot = find_gdi_slot( req->handle, 1 );
    if (!slot) return;
    if (slot->selected || slot->readers)
    {
        set_error( STATUS_DEVICE_BUSY );
        return;
    }
    destroy_gdi_slot( slot );
}

static int valid_bitmap_data( const struct gdi_bitmap_data *data, mem_size_t size )
{
    unsigned __int64 stride, bytes, height;
    if (data->width <= 0 || !data->height || data->height == INT_MIN || data->color_count > 256)
        return 0;
    switch (data->bpp)
    {
    case 1: case 4: case 8: case 16: case 24: case 32: break;
    default: return 0;
    }
    if (data->compression != BI_RGB && data->compression != BI_BITFIELDS) return 0;
    if (data->compression == BI_BITFIELDS && data->bpp != 16 && data->bpp != 32) return 0;
    if (data->color_count > (data->bpp <= 8 ? 1u << data->bpp : 0)) return 0;
    if (data->kind != GDI_BITMAP_DDB && data->kind != GDI_BITMAP_SESSION) return 0;
    stride = (((unsigned __int64)data->width * data->bpp + 31) / 32) * 4;
    height = data->height < 0 ? -(long long)data->height : data->height;
    bytes = stride * height;
    return stride == data->stride && bytes <= UINT_MAX && !(data->offset & 3) &&
           data->offset <= size && bytes <= size - data->offset;
}

static int check_bitmap_logon_actor(void)
{
    struct winstation *winstation = get_process_winstation( current->process, 0 );
    int allowed;
    if (!winstation) return 0;
    allowed = winstation->logon_process_id == current->process->id;
    release_object( winstation );
    if (!allowed) set_error( STATUS_ACCESS_DENIED );
    return allowed;
}

DECL_HANDLER(check_gdi_bitmap_creator)
{
    check_bitmap_logon_actor();
}

DECL_HANDLER(bind_gdi_bitmap)
{
    struct gdi_slot *slot = find_gdi_slot( req->handle, 1 );
    struct gdi_bitmap_data data;
    struct object *section;
    mem_size_t size;
    if (!slot) return;
    if (slot->type != NTGDI_OBJ_BITMAP >> 16 || slot->stock || slot->selected || slot->section ||
        get_req_data_size() != sizeof(data)) goto invalid;
    memcpy( &data, get_req_data(), sizeof(data) );
    if (data.kind == GDI_BITMAP_SESSION && !check_bitmap_logon_actor()) return;
    if (!(section = get_gdi_section( current->process, req->section, &size ))) return;
    if (!valid_bitmap_data( &data, size ))
    {
        release_object( section );
        goto invalid;
    }
    if (!(slot->bitmap = memdup( &data, sizeof(data) )))
    {
        release_object( section );
        return;
    }
    slot->section = section;
    return;
invalid:
    set_error( STATUS_INVALID_PARAMETER );
}

DECL_HANDLER(query_gdi_object)
{
    struct gdi_slot *slot = find_gdi_slot( req->handle, 0 );
    if (!slot) return;
    reply->handle = slot_handle( slot, req->handle & 0xffff );
    if (!req->backing || !slot->section) return;
    /* The validated GDI identity grants access to its retained storage.  Do
     * not reopen the creator's section through the consumer's object DACL. */
    reply->section = alloc_handle_no_access_check( current->process, slot->section,
                                                  SECTION_MAP_READ | SECTION_MAP_WRITE, 0 );
    if (reply->section) set_reply_data( slot->bitmap, sizeof(*slot->bitmap) );
}

DECL_HANDLER(set_gdi_bitmap_stock)
{
    struct gdi_slot *slot = find_gdi_slot( req->handle, req->stock );
    if (!slot) return;
    if (slot->type != NTGDI_OBJ_BITMAP >> 16 || !slot->section || slot->selected || slot->readers || slot->stock == !!req->stock)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    slot->stock = !!req->stock;
    slot->owner = slot->stock ? 0 : current->process->id;
    reply->handle = slot_handle( slot, req->handle & 0xffff );
}

DECL_HANDLER(select_gdi_bitmap)
{
    struct gdi_slot *slot = find_gdi_slot( req->handle, 0 );
    struct gdi_selection *selection;
    unsigned int *total, *count;
    if (!slot) return;
    if (slot->type != NTGDI_OBJ_BITMAP >> 16 ||
        (req->delta != 1 && req->delta != -1 && req->delta != 2 && req->delta != -2)) goto invalid;
    if (req->delta == 1 && slot->selected) goto invalid;
    LIST_FOR_EACH_ENTRY( selection, &slot->selections, struct gdi_selection, entry )
        if (selection->pid == current->process->id) break;
    if (&selection->entry == &slot->selections)
    {
        if (req->delta < 0) goto invalid;
        if (!(selection = mem_alloc( sizeof(*selection) ))) return;
        selection->pid = current->process->id;
        selection->count = selection->readers = 0;
        list_add_tail( &slot->selections, &selection->entry );
    }
    if (req->delta == 2 || req->delta == -2)
    {
        total = &slot->readers;
        count = &selection->readers;
    }
    else
    {
        total = &slot->selected;
        count = &selection->count;
    }
    if (req->delta > 0)
    {
        if (*total == UINT_MAX || *count == UINT_MAX) goto invalid;
        (*count)++;
        (*total)++;
    }
    else
    {
        if (!*count) goto invalid;
        (*count)--;
        (*total)--;
        if (!selection->count && !selection->readers)
        {
            list_remove( &selection->entry );
            free( selection );
        }
    }
    reply->count = *total;
    return;
invalid:
    set_error( STATUS_INVALID_PARAMETER );
}
