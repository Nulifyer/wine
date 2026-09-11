/*
 * Server-side Windows Notification Facility states
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

#include <stdarg.h>
#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "wow64_private.h"

NTSTATUS WINAPI wow64_NtCreateWnfStateName( UINT *args )
{
    ULONGLONG *name = get_ptr( &args );
    ULONG lifetime = get_ulong( &args );
    ULONG scope = get_ulong( &args );
    BOOLEAN persist = get_ulong( &args );
    const GUID *type = get_ptr( &args );
    ULONG maximum = get_ulong( &args );
    SECURITY_DESCRIPTOR *sd32 = get_ptr( &args ), sd;
    return NtCreateWnfStateName( name, lifetime, scope, persist, type, maximum, secdesc_32to64( &sd, sd32 ) );
}
NTSTATUS WINAPI wow64_NtDeleteWnfStateName( UINT *args )
{
    const ULONGLONG *name = get_ptr( &args );
    return NtDeleteWnfStateName( name );
}
NTSTATUS WINAPI wow64_NtQueryWnfStateData( UINT *args )
{
    const ULONGLONG *name = get_ptr( &args );
    const GUID *type = get_ptr( &args );
    const void *scope = get_ptr( &args );
    ULONG *stamp = get_ptr( &args );
    void *data = get_ptr( &args );
    ULONG *size = get_ptr( &args );
    return NtQueryWnfStateData( name, type, scope, stamp, data, size );
}
NTSTATUS WINAPI wow64_NtUpdateWnfStateData( UINT *args )
{
    const ULONGLONG *name = get_ptr( &args );
    const void *data = get_ptr( &args );
    ULONG size = get_ulong( &args );
    const GUID *type = get_ptr( &args );
    const void *scope = get_ptr( &args );
    ULONG matching = get_ulong( &args );
    ULONG check = get_ulong( &args );
    return NtUpdateWnfStateData( name, data, size, type, scope, matching, check );
}

NTSTATUS WINAPI wow64_NtSubscribeWnfStateChange( UINT *args )
{
    const ULONGLONG *name = get_ptr( &args );
    ULONG stamp = get_ulong( &args );
    ULONG events = get_ulong( &args );
    ULONGLONG *id = get_ptr( &args );
    return NtSubscribeWnfStateChange( name, stamp, events, id );
}
NTSTATUS WINAPI wow64_NtUnsubscribeWnfStateChange( UINT *args )
{
    const ULONGLONG *name = get_ptr( &args );
    return NtUnsubscribeWnfStateChange( name );
}
NTSTATUS WINAPI wow64_NtSetWnfProcessNotificationEvent( UINT *args )
{
    HANDLE event = get_handle( &args );
    return NtSetWnfProcessNotificationEvent( event );
}
NTSTATUS WINAPI wow64_NtQueryWnfStateNameInformation( UINT *args )
{
    const ULONGLONG *name = get_ptr( &args );
    ULONG info = get_ulong( &args );
    const void *scope = get_ptr( &args );
    void *buffer = get_ptr( &args );
    ULONG size = get_ulong( &args );
    return NtQueryWnfStateNameInformation( name, info, scope, buffer, size );
}
NTSTATUS WINAPI wow64_NtGetCompleteWnfStateSubscription( UINT *args )
{
    const ULONGLONG *name = get_ptr( &args );
    const ULONGLONG *id = get_ptr( &args );
    ULONG events = get_ulong( &args );
    ULONG status = get_ulong( &args );
    WNF_DELIVERY_DESCRIPTOR *descriptor = get_ptr( &args );
    ULONG size = get_ulong( &args );
    return NtGetCompleteWnfStateSubscription( name, id, events, status, descriptor, size );
}
