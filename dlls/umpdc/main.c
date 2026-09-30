/*
 * Power Dependency Coordinator client compatibility
 *
 * Copyright 2026 LinuxNT project
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>

#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "winternl.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(umpdc);

struct pdc_context
{
    DWORD magic;
    DWORD kind;
};

static NTSTATUS create_context( DWORD kind, void **out )
{
    struct pdc_context *context;

    if (!out) return STATUS_INVALID_PARAMETER;
    *out = NULL;
    if (!(context = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*context) )))
        return STATUS_NO_MEMORY;
    context->magic = 0x43445057; /* WPDC */
    context->kind = kind;
    *out = context;
    return STATUS_SUCCESS;
}

static NTSTATUS destroy_context( void *context )
{
    if (!context) return STATUS_INVALID_PARAMETER;
    HeapFree( GetProcessHeap(), 0, context );
    return STATUS_SUCCESS;
}

void *WINAPI PdcAllocate( void *unused, ULONGLONG size )
{
    return HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)size );
}

void WINAPI PdcFree( void *memory )
{
    HeapFree( GetProcessHeap(), 0, memory );
}

void WINAPI PdcRwLockInitialize( RTL_SRWLOCK *lock )
{
    RtlInitializeSRWLock( lock );
}

void WINAPI PdcAcquireRwLockExclusive( RTL_SRWLOCK *lock )
{
    RtlAcquireSRWLockExclusive( lock );
}

void WINAPI PdcReleaseRwLockExclusive( RTL_SRWLOCK *lock )
{
    RtlReleaseSRWLockExclusive( lock );
}

NTSTATUS WINAPI Pdcv2ActivationClientRegister( DWORD client_id, const void *registration, void **context )
{
    TRACE( "client_id %lu registration %p context %p\n", client_id, registration, context );
    if (!client_id || !registration) return STATUS_INVALID_PARAMETER;
    return create_context( 1, context );
}

NTSTATUS WINAPI Pdcv2ActivationClientUnregister( void *context, void *reserved )
{
    TRACE( "context %p reserved %p\n", context, reserved );
    return destroy_context( context );
}

NTSTATUS WINAPI Pdcv2ActivationClientActivate( void *context, const void *parameters, void *callback_context,
                                                DWORD activity_type, const WCHAR *name, DWORD name_length,
                                                void **activation, void *error_detail )
{
    TRACE( "%p %p %p %lu %s %lu %p %p\n", context, parameters, callback_context, activity_type,
           debugstr_wn(name, name_length), name_length, activation, error_detail );
    if (!context) return STATUS_INVALID_PARAMETER;
    if (error_detail) memset( error_detail, 0, 16 );
    return create_context( 2, activation );
}

NTSTATUS WINAPI Pdcv2ActivationClientDeactivate( void *activation )
{
    return destroy_context( activation );
}

NTSTATUS WINAPI Pdcv2ActivationClientRenewActivation( void *activation, const void *parameters,
                                                       void *error_detail )
{
    TRACE( "%p %p %p\n", activation, parameters, error_detail );
    if (!activation) return STATUS_INVALID_PARAMETER;
    if (error_detail) memset( error_detail, 0, 16 );
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI Pdcv2ActivationClientSetBrokeredProcessId( void *context, DWORD process_id )
{
    TRACE( "%p %lu\n", context, process_id );
    return context ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}

NTSTATUS WINAPI PdcNotificationClientRegister( void *client_id, const void *registration,
                                                void *callback_context, void **context )
{
    TRACE( "%p %p %p %p\n", client_id, registration, callback_context, context );
    return create_context( 3, context );
}

NTSTATUS WINAPI PdcNotificationClientUnregister( void *context )
{
    return destroy_context( context );
}

NTSTATUS WINAPI PdcNotificationClientAcknowledge( void *context, DWORD notification )
{
    TRACE( "%p %lu\n", context, notification );
    return context ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}

NTSTATUS WINAPI SleepstudyHelperCreateLibraryEx( const void *options, void **library )
{
    TRACE( "%p %p\n", options, library );
    return create_context( 4, library );
}

NTSTATUS WINAPI SleepstudyHelperCreateLibrary( DWORD flags, void **library )
{
    TRACE( "%#lx %p\n", flags, library );
    return create_context( 4, library );
}

NTSTATUS WINAPI SleepstudyHelperDestroyLibrary( void *library )
{
    return destroy_context( library );
}

NTSTATUS WINAPI SleepstudyHelperCreateBlockerFromGuid( void *library, const GUID *guid, void *parent,
                                                       const WCHAR *name, DWORD name_length, void **builder )
{
    TRACE( "%p %s %p %s %lu %p\n", library, debugstr_guid(guid), parent,
           debugstr_wn(name, name_length), name_length, builder );
    if (!library) return STATUS_INVALID_PARAMETER;
    return create_context( 5, builder );
}

NTSTATUS WINAPI SleepstudyHelperBuildBlocker( void *builder, void **blocker )
{
    if (!builder) return STATUS_INVALID_PARAMETER;
    return create_context( 6, blocker );
}

NTSTATUS WINAPI SleepstudyHelperDestroyBlockerBuilder( void *builder )
{
    return destroy_context( builder );
}

NTSTATUS WINAPI SleepstudyHelperDestroyBlocker( void *blocker )
{
    return destroy_context( blocker );
}

NTSTATUS WINAPI SleepstudyHelperBlockerActiveReference( void *blocker )
{
    return blocker ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}

NTSTATUS WINAPI SleepstudyHelperBlockerActiveDereference( void *blocker )
{
    return blocker ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}

NTSTATUS WINAPI SleepstudyHelperSetBlockerParentHandle( void *blocker, void *parent )
{
    return blocker ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}

NTSTATUS WINAPI SleepstudyHelperSetBlockerFriendlyName( void *blocker, const WCHAR *name )
{
    return blocker ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}

NTSTATUS WINAPI SleepstudyHelperSetBlockerVisible( void *blocker, BOOL visible )
{
    return blocker ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}

NTSTATUS WINAPI SleepstudyHelperGetBlockerGuid( void *blocker, GUID *guid )
{
    if (!blocker || !guid) return STATUS_INVALID_PARAMETER;
    memset( guid, 0, sizeof(*guid) );
    return STATUS_SUCCESS;
}

/* Legacy client families use the same inert registration lifetime. */
NTSTATUS WINAPI PdcActivationClientRegister( DWORD client_id, void **context ) { return create_context( 7, context ); }
NTSTATUS WINAPI PdcActivationClientUnregister( void *context ) { return destroy_context( context ); }
NTSTATUS WINAPI PdcActivationClientActivityRequest( void *context, DWORD type, BOOL active, ULONGLONG value )
{ return context ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER; }
NTSTATUS WINAPI PdcSignalClientRegister( const void *registration, void **context ) { return create_context( 8, context ); }
NTSTATUS WINAPI PdcSignalClientUnregister( void *context ) { return destroy_context( context ); }
void WINAPI PdcSignalClientPulse( void *context, const WCHAR *name ) { TRACE( "%p %s\n", context, debugstr_w(name) ); }
void WINAPI PdcSignalClientSetActive( void *context, BOOL active, const WCHAR *name )
{ TRACE( "%p %u %s\n", context, active, debugstr_w(name) ); }
NTSTATUS WINAPI PdcTaskClientRegister( DWORD client_id, void **context ) { return create_context( 9, context ); }
NTSTATUS WINAPI PdcTaskClientUnregister( void *context ) { return destroy_context( context ); }
NTSTATUS WINAPI PdcTaskClientRequest( void *context, BOOL active ) { return context ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER; }
NTSTATUS WINAPI PdcPpmProfileClientRegister( const void *registration, void **context ) { return create_context( 10, context ); }
NTSTATUS WINAPI PdcPpmProfileClientUnregister( void *context ) { return destroy_context( context ); }
NTSTATUS WINAPI PdcPpmProfileEnable( void *context, BOOL enabled ) { return context ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER; }
void WINAPI PdcPpmProfileDisable( void *context ) { TRACE( "%p\n", context ); }
NTSTATUS WINAPI PdcResiliencyClientRegister( DWORD client_id, const void *registration,
                                             void *callback_context, void **context )
{ return create_context( 11, context ); }
NTSTATUS WINAPI PdcResiliencyClientUnregister( void *context ) { return destroy_context( context ); }
NTSTATUS WINAPI PdcResiliencyClientAcknowledge(void) { return STATUS_SUCCESS; }

void WINAPI PdcSleep( DWORD milliseconds ) { Sleep( milliseconds ); }

/* The builtin provider does not expose the private kernel-port protocol. */
NTSTATUS WINAPI PdcPortOpen( DWORD client_id, DWORD type, void *context, void *callback, void *data,
                             DWORD data_size, void *name, void **port )
{ return create_context( 12, port ); }
NTSTATUS WINAPI PdcPortClose( void *port ) { return destroy_context( port ); }
NTSTATUS WINAPI PdcPortSendMessage( void *port, void *message, DWORD size )
{ return port ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER; }
NTSTATUS WINAPI PdcPortSendMessageSynchronously( void *port, void *message, DWORD size )
{ return port ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER; }
