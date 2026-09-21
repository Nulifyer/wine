/*
 * Private desktop-composition GDI entry points
 *
 * Copyright 2026
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "gdi_private.h"
#include "ntgdi.h"
#include "ntuser.h"

struct hlsurf_dirty_info
{
    UINT64 update_id;
    HRGN dirty_region;
    HRGN valid_region;
    HRGN invalid_region;
    UINT64 signal_id;
    UINT64 present_id;
    UINT present_flags;
    UINT reserved;
};

struct hlsurf_signal_info
{
    BOOL enable;
    UINT reserved;
    HANDLE event;
    LUID adapter_luid;
};

/***********************************************************************
 *           DwmQueryCompositionId (GDI32.@)
 *
 * Return the generation of the composed-event object owned by the active
 * DWM session port. Windows publishes this through win32k shared state;
 * Wine keeps the equivalent session state in the server.
 */
UINT WINAPI DwmQueryCompositionId(void)
{
    return NtUserCallNoParam( NtUserCallNoParam_GetDwmCompositionId );
}

BOOL WINAPI DwmHLSurfOpenCompositorRef( HANDLE surface )
{
    return NtGdiHLSurfSetInformation( surface, 7, NULL, 0 );
}

BOOL WINAPI DwmHLSurfCloseCompositorRef( HANDLE surface )
{
    return NtGdiHLSurfSetInformation( surface, 8, NULL, 0 );
}

BOOL WINAPI DwmGetSurfaceData( HANDLE surface, void *data )
{
    UINT size = 48;
    return NtGdiHLSurfGetInformation( surface, 3, data, &size );
}

BOOL WINAPI DwmGetRedirectionStyle( HANDLE surface, void *data )
{
    UINT size = 32;
    return NtGdiHLSurfGetInformation( surface, 6, data, &size );
}

BOOL WINAPI DwmHLSurfGetDirtyRgn( HANDLE surface, UINT64 update_id, HRGN *dirty,
                                  HRGN *valid, HRGN *invalid, UINT64 *signal_id,
                                  UINT64 *present_id, UINT *present_flags, UINT *reserved )
{
    struct hlsurf_dirty_info info = {.update_id = update_id};
    UINT size = sizeof(info);
    BOOL ret;

    ret = NtGdiHLSurfGetInformation( surface, signal_id ? 9 : 4, &info, &size );
    if (dirty) *dirty = info.dirty_region;
    else if (info.dirty_region) DeleteObject( info.dirty_region );
    if (valid) *valid = info.valid_region;
    else if (info.valid_region) DeleteObject( info.valid_region );
    if (invalid) *invalid = info.invalid_region;
    else if (info.invalid_region) DeleteObject( info.invalid_region );
    if (signal_id) *signal_id = info.signal_id;
    if (present_id) *present_id = info.present_id;
    if (present_flags) *present_flags = info.present_flags;
    if (reserved) *reserved = info.reserved;
    return ret;
}

BOOL WINAPI DwmHLSurfSetSignalOnDirty( HANDLE surface, LUID adapter_luid,
                                       HANDLE event, BOOL enable )
{
    struct hlsurf_signal_info info = {enable, 0, event, adapter_luid};
    return NtGdiHLSurfSetInformation( surface, 5, &info, sizeof(info) );
}

BOOL WINAPI DwmHLsurfSetPresentFlags( HANDLE surface, UINT flags )
{
    return NtGdiHLSurfSetInformation( surface, 1, &flags, sizeof(flags) );
}

BOOL WINAPI DwmHLsurfSetUpdatedId( HANDLE surface, const UINT64 *update_id )
{
    return NtGdiHLSurfSetInformation( surface, 2, update_id, sizeof(*update_id) );
}

BOOL WINAPI DwmGetDirtyRgn( HANDLE surface, UINT64 update_id, HRGN *dirty,
                            HRGN *valid, HRGN *invalid )
{
    (void)surface;
    (void)update_id;
    (void)dirty;
    (void)valid;
    (void)invalid;
    SetLastError( ERROR_NOT_SUPPORTED );
    return FALSE;
}
