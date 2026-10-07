/*
 * Server-backed public bitmap storage
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */
#if 0
#pragma makedep unix
#endif
#include <stdlib.h>
#include <string.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "ntgdi_private.h"
#include "wine/server.h"

BOOL session_bitmap_authorized(void)
{
    NTSTATUS status;
    SERVER_START_REQ(check_gdi_bitmap_creator)
    {
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    if (status) RtlSetLastWin32Error( ERROR_ACCESS_DENIED );
    return !status;
}

static void describe_bitmap( BITMAPOBJ *bitmap, struct gdi_bitmap_data *data )
{
    memset( data, 0, sizeof(*data) );
    data->width = bitmap->dib.dsBm.bmWidth;
    data->height = is_bitmapobj_dib( bitmap ) ? bitmap->dib.dsBmih.biHeight : -bitmap->dib.dsBm.bmHeight;
    data->stride = get_dib_stride( data->width, bitmap->dib.dsBm.bmBitsPixel );
    data->bpp = bitmap->dib.dsBm.bmBitsPixel;
    data->compression = is_bitmapobj_dib( bitmap ) ? bitmap->dib.dsBmih.biCompression : BI_RGB;
    data->offset = bitmap->session_mapped ? bitmap->dib.dsOffset : 0;
    data->kind = bitmap->session_mapped ? GDI_BITMAP_SESSION : GDI_BITMAP_DDB;
    memcpy( data->masks, bitmap->dib.dsBitfields, sizeof(data->masks) );
    if (bitmap->color_table)
    {
        data->color_count = bitmap->dib.dsBmih.biClrUsed;
        if (data->color_count <= 256)
            memcpy( data->colors, bitmap->color_table, data->color_count * sizeof(RGBQUAD) );
    }
}

BOOL bind_shared_bitmap( HBITMAP handle, BITMAPOBJ *bitmap, HANDLE section )
{
    struct gdi_bitmap_data data;
    NTSTATUS status;
    describe_bitmap( bitmap, &data );
    SERVER_START_REQ(bind_gdi_bitmap)
    {
        req->handle = HandleToULong( handle );
        req->section = wine_server_obj_handle( section );
        wine_server_add_data( req, &data, sizeof(data) );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    if (status == STATUS_ACCESS_DENIED) RtlSetLastWin32Error( ERROR_ACCESS_DENIED );
    return !status;
}

BOOL prepare_public_bitmap( HBITMAP handle, BITMAPOBJ *bitmap )
{
    LARGE_INTEGER size, offset = {0};
    SIZE_T view_size = 0;
    HANDLE section;
    void *view = NULL;
    if (bitmap->shared_section || bitmap->session_mapped) return TRUE;
    if (is_bitmapobj_dib( bitmap )) return FALSE;
    size.QuadPart = (ULONGLONG)get_dib_stride( bitmap->dib.dsBm.bmWidth, bitmap->dib.dsBm.bmBitsPixel ) * bitmap->dib.dsBm.bmHeight;
    if (NtCreateSection( &section, SECTION_ALL_ACCESS, NULL, &size, PAGE_READWRITE, SEC_COMMIT, 0 )) return FALSE;
    if (NtMapViewOfSection( section, GetCurrentProcess(), &view, zero_bits, 0, &offset,
                           &view_size, ViewShare, 0, PAGE_READWRITE ))
    {
        NtClose( section );
        return FALSE;
    }
    memcpy( view, bitmap->dib.dsBm.bmBits, size.QuadPart );
    if (!bind_shared_bitmap( handle, bitmap, section ))
    {
        NtUnmapViewOfSection( GetCurrentProcess(), view );
        NtClose( section );
        return FALSE;
    }
    free( bitmap->dib.dsBm.bmBits );
    bitmap->dib.dsBm.bmBits = view;
    bitmap->shared_view = view;
    bitmap->shared_section = section;
    return TRUE;
}

void destroy_shared_bitmap_cache( BITMAPOBJ *bitmap )
{
    NtUnmapViewOfSection( GetCurrentProcess(), bitmap->shared_view );
    if (bitmap->shared_section) NtClose( bitmap->shared_section );
    free( bitmap->color_table );
    free( bitmap );
}

BITMAPOBJ *import_shared_bitmap( HBITMAP handle )
{
    struct gdi_bitmap_data data;
    LARGE_INTEGER offset;
    SIZE_T view_size;
    HANDLE section = NULL;
    BITMAPOBJ *bitmap;
    void *view = NULL;
    NTSTATUS status;
    memset( &data, 0, sizeof(data) );
    SERVER_START_REQ(query_gdi_object)
    {
        req->handle = HandleToULong( handle );
        req->backing = TRUE;
        wine_server_set_reply( req, &data, sizeof(data) );
        status = wine_server_call( req );
        if (!status) section = wine_server_ptr_handle( reply->section );
    }
    SERVER_END_REQ;
    if (!section) return NULL;
    if (!(bitmap = calloc( 1, sizeof(*bitmap) ))) goto failed;
    offset.QuadPart = data.offset & ~0xffffu;
    view_size = (SIZE_T)data.stride * abs(data.height) + (data.offset - offset.QuadPart);
    if (NtMapViewOfSection( section, GetCurrentProcess(), &view, zero_bits, 0, &offset,
                           &view_size, ViewShare, 0, PAGE_READWRITE )) goto failed;
    bitmap->shared_section = section;
    bitmap->shared_view = view;
    bitmap->session_mapped = data.kind == GDI_BITMAP_SESSION;
    bitmap->obj.funcs = bitmap->session_mapped ? &dib_funcs : &bitmap_funcs;
    bitmap->obj.system = !!(HandleToULong(handle) & NTGDI_HANDLE_STOCK_OBJECT);
    bitmap->dib.dsBm.bmWidth = data.width;
    bitmap->dib.dsBm.bmHeight = abs(data.height);
    bitmap->dib.dsBm.bmWidthBytes = bitmap->session_mapped ? data.stride : get_bitmap_stride( data.width, data.bpp );
    bitmap->dib.dsBm.bmPlanes = 1;
    bitmap->dib.dsBm.bmBitsPixel = data.bpp;
    bitmap->dib.dsBm.bmBits = (char *)view + data.offset - offset.QuadPart;
    if (bitmap->session_mapped)
    {
        bitmap->dib.dsBmih.biSize = sizeof(BITMAPINFOHEADER);
        bitmap->dib.dsBmih.biWidth = data.width;
        bitmap->dib.dsBmih.biHeight = data.height;
        bitmap->dib.dsBmih.biPlanes = 1;
        bitmap->dib.dsBmih.biBitCount = data.bpp;
        bitmap->dib.dsBmih.biCompression = data.compression;
        bitmap->dib.dsBmih.biSizeImage = data.stride * abs(data.height);
        bitmap->dib.dsBmih.biClrUsed = data.color_count;
        memcpy( bitmap->dib.dsBitfields, data.masks, sizeof(data.masks) );
        bitmap->dib.dshSection = section;
        bitmap->dib.dsOffset = data.offset;
    }
    if (data.color_count)
    {
        if (!(bitmap->color_table = malloc( data.color_count * sizeof(RGBQUAD) ))) goto failed;
        memcpy( bitmap->color_table, data.colors, data.color_count * sizeof(RGBQUAD) );
    }
    return bitmap;
failed:
    if (view) NtUnmapViewOfSection( GetCurrentProcess(), view );
    NtClose( section );
    free( bitmap );
    return NULL;
}
