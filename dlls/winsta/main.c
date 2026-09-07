/*
 * Winstation library implementation
 *
 * Copyright 2011 Austin English
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
#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "wine/debug.h"
#include "winsta.h"

WINE_DEFAULT_DEBUG_CHANNEL(winsta);

static DWORD get_effective_session_id( ULONG *session )
{
    HANDLE token;
    NTSTATUS status;

    status = NtOpenThreadToken( GetCurrentThread(), TOKEN_QUERY, TRUE, &token );
    if (status == STATUS_NO_TOKEN)
        status = NtOpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &token );
    if (status) return RtlNtStatusToDosError( status );
    status = NtQueryInformationToken( token, TokenSessionId, session, sizeof(*session), NULL );
    NtClose( token );
    return RtlNtStatusToDosError( status );
}

BOOLEAN WINAPI WinStationIsCurrentSessionRemoteable( BOOLEAN *remoteable )
{
    ULONG session;
    DWORD error;

    TRACE( "%p\n", remoteable );

    /* The output is a BOOLEAN, not a BOOL, and is cleared before querying. */
    *remoteable = FALSE;
    if ((error = get_effective_session_id( &session )))
    {
        SetLastError( error );
        return FALSE;
    }
    /* Wine's service and interactive console sessions have no remote transport.
     * Do not claim capabilities for other token session IDs. */
    if (session > 1)
    {
        SetLastError( ERROR_NOT_SUPPORTED );
        return FALSE;
    }
    SetLastError( ERROR_SUCCESS );
    return TRUE;
}

BOOLEAN WINAPI WinStationIsSessionRemoteable( HANDLE server, ULONG session, BOOLEAN *remoteable )
{
    ULONG current;
    DWORD error;

    TRACE( "%p %lu %p\n", server, session, remoteable );

    if (session == LOGONID_CURRENT) return WinStationIsCurrentSessionRemoteable( remoteable );
    if ((error = get_effective_session_id( &current )))
    {
        SetLastError( error );
        return FALSE;
    }
    /* Native current-session queries bypass the server handle entirely. */
    if (session == current) return WinStationIsCurrentSessionRemoteable( remoteable );
    if (server || !remoteable)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }
    *remoteable = FALSE;
    if (session > 1)
    {
        SetLastError( session == (ULONG)-2 ? ERROR_FILE_NOT_FOUND : ERROR_INVALID_PARAMETER );
        return FALSE;
    }
    SetLastError( ERROR_SUCCESS );
    return TRUE;
}

BOOLEAN WINAPI WinStationQueryInformationA( HANDLE server, ULONG logon_id, WINSTATIONINFOCLASS class,
                                            void *info, ULONG len, ULONG *ret_len )
{
    return WinStationQueryInformationW( server, logon_id, class, info, len, ret_len );
}

BOOLEAN WINAPI WinStationQueryInformationW( HANDLE server, ULONG logon_id, WINSTATIONINFOCLASS class,
                                            void *info, ULONG len, ULONG *ret_len )
{
    ULONG session_type;

    TRACE( "%p %lu %u %p %lu %p\n", server, logon_id, class, info, len, ret_len );

    if (class == WinStationType)
    {
        if (!info || len < sizeof(session_type))
        {
            SetLastError( ERROR_INVALID_PARAMETER );
            return FALSE;
        }

        if (logon_id == LOGONID_CURRENT) logon_id = NtCurrentTeb()->Peb->SessionId;

        /* Wine currently exposes the service session and one interactive console session. */
        if (!logon_id)
            session_type = SESSIONTYPE_SERVICES;
        else if (logon_id == 1)
            session_type = SESSIONTYPE_REGULARDESKTOP;
        else
        {
            SetLastError( ERROR_FILE_NOT_FOUND );
            return FALSE;
        }

        *(ULONG *)info = session_type;
        if (ret_len) *ret_len = sizeof(session_type);
        SetLastError( ERROR_SUCCESS );
        return TRUE;
    }

    FIXME( "%p %lu %u %p %lu %p\n", server, logon_id, class, info, len, ret_len );
    SetLastError( ERROR_CALL_NOT_IMPLEMENTED );
    return FALSE;
}

BOOLEAN WINAPI WinStationRegisterConsoleNotification( HANDLE server, HWND hwnd, ULONG flags )
{
    FIXME( "%p %p 0x%lx\n", server, hwnd, flags );
    SetLastError( ERROR_CALL_NOT_IMPLEMENTED );
    return FALSE;
}

BOOLEAN WINAPI WinStationUnRegisterConsoleNotification( HANDLE server, HWND hwnd )
{
    FIXME( "%p %p\n", server, hwnd );
    SetLastError( ERROR_CALL_NOT_IMPLEMENTED );
    return FALSE;
}

BOOLEAN WINAPI WinStationGetAllProcesses( HANDLE server, ULONG level,
                                          ULONG *process_count, PTS_ALL_PROCESSES_INFO *info )
{
    FIXME( "%p %lu %p %p\n", server, level, process_count, info );
    *process_count = 0;
    SetLastError( ERROR_CALL_NOT_IMPLEMENTED );
    return FALSE;
}

BOOLEAN WINAPI WinStationGetProcessSid( HANDLE server, ULONG process_id, FILETIME process_start_time,
                                        PVOID process_user_sid, PULONG sid_size )
{
    FIXME( "(%p, %ld, %I64x, %p, %p): stub\n", server, process_id,
           ((UINT64)process_start_time.dwHighDateTime << 32) | process_start_time.dwLowDateTime,
           process_user_sid, sid_size);
    SetLastError( ERROR_CALL_NOT_IMPLEMENTED );
    return FALSE;
}

BOOL WINAPI WinStationVirtualOpen( PVOID a, PVOID b, PVOID c )
{
    FIXME( "%p %p %p\n", a, b, c );
    SetLastError( ERROR_CALL_NOT_IMPLEMENTED );
    return FALSE;
}

BOOLEAN WINAPI WinStationEnumerateW( HANDLE server, PSESSIONIDW *sessionids, ULONG *count )
{
    FIXME( "%p %p %p\n", server, sessionids, count );
    SetLastError( ERROR_CALL_NOT_IMPLEMENTED );
    return FALSE;
}
