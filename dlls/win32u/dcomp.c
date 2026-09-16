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

#include "ntstatus.h"
#include "win32u_private.h"
#include "wine/server.h"

WINE_DEFAULT_DEBUG_CHANNEL(dcomp);

C_ASSERT( sizeof(struct dcomposition_frame_statistics) == 40 );
C_ASSERT( sizeof(struct dcomposition_capability_info) == 20 );

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
    NTSTATUS status;

    TRACE( "connection %p\n", connection );

    SERVER_START_REQ( destroy_dcomp_connection )
    {
        req->handle = wine_server_obj_handle( connection );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
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
