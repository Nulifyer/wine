/* WNF tests
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "wine/test.h"

#define WNF_FT_LAST_PROCESS_PROMOTION_TRIGGER 0x41c61a2ba3bc2875ULL

typedef NTSTATUS (WINAPI *wnf_callback)( ULONGLONG, ULONG, const GUID *, void *, const void *, ULONG );
static NTSTATUS (WINAPI *pNtQueryWnfStateData)( const ULONGLONG *, const GUID *, const void *,
                                               ULONG *, void *, ULONG * );
static NTSTATUS (WINAPI *pRtlPublishWnfStateData)( ULONGLONG, const GUID *, const void *, ULONG,
                                                  const void * );
static NTSTATUS (WINAPI *pRtlTestAndPublishWnfStateData)( ULONGLONG, const GUID *, const void *, ULONG,
                                                         const void *, ULONG );
static NTSTATUS (WINAPI *pRtlSubscribeWnfStateChangeNotification)( void **, ULONGLONG, ULONG,
                                                                  wnf_callback, void *, const GUID *,
                                                                  ULONG, ULONG );
static NTSTATUS (WINAPI *pRtlUnsubscribeWnfNotificationWaitForCompletion)( void * );
static NTSTATUS (WINAPI *pRtlUnsubscribeWnfStateChangeNotification)( void * );

static NTSTATUS WINAPI callback( ULONGLONG name, ULONG stamp, const GUID *type, void *context,
                                 const void *data, ULONG size )
{
    (void)type;
    (void)context;
    (void)data;
    ok( 0, "unexpected callback for %#I64x, stamp %lu, size %lu\n", name, stamp, size );
    return STATUS_SUCCESS;
}

START_TEST(wnf)
{
    const ULONGLONG name = WNF_FT_LAST_PROCESS_PROMOTION_TRIGGER;
    HMODULE ntdll = GetModuleHandleW( L"ntdll.dll" );
    void *subscription;
    ULONG stamp, size;
    NTSTATUS status;

    pNtQueryWnfStateData = (void *)GetProcAddress( ntdll, "NtQueryWnfStateData" );
    pRtlPublishWnfStateData = (void *)GetProcAddress( ntdll, "RtlPublishWnfStateData" );
    pRtlTestAndPublishWnfStateData =
        (void *)GetProcAddress( ntdll, "RtlTestAndPublishWnfStateData" );
    pRtlSubscribeWnfStateChangeNotification =
        (void *)GetProcAddress( ntdll, "RtlSubscribeWnfStateChangeNotification" );
    pRtlUnsubscribeWnfNotificationWaitForCompletion =
        (void *)GetProcAddress( ntdll, "RtlUnsubscribeWnfNotificationWaitForCompletion" );
    pRtlUnsubscribeWnfStateChangeNotification =
        (void *)GetProcAddress( ntdll, "RtlUnsubscribeWnfStateChangeNotification" );
    if (!pNtQueryWnfStateData || !pRtlPublishWnfStateData ||
        !pRtlTestAndPublishWnfStateData || !pRtlSubscribeWnfStateChangeNotification ||
        !pRtlUnsubscribeWnfNotificationWaitForCompletion ||
        !pRtlUnsubscribeWnfStateChangeNotification)
    {
        win_skip( "WNF functions are unavailable\n" );
        return;
    }

    status = pRtlPublishWnfStateData( name, NULL, NULL, 0, NULL );
    ok( status == STATUS_ACCESS_DENIED, "expected STATUS_ACCESS_DENIED, got %#lx\n", status );
    status = pRtlTestAndPublishWnfStateData( name, NULL, NULL, 0, NULL, 0 );
    ok( status == STATUS_ACCESS_DENIED, "expected STATUS_ACCESS_DENIED, got %#lx\n", status );

    stamp = 0xdeadbeef;
    size = 0xdeadbeef;
    status = pNtQueryWnfStateData( &name, NULL, NULL, &stamp, NULL, &size );
    ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
    ok( !stamp, "expected stamp 0, got %lu\n", stamp );
    ok( !size, "expected size 0, got %lu\n", size );

    subscription = (void *)0xdeadbeef;
    status = pRtlSubscribeWnfStateChangeNotification( &subscription, name, 0, callback,
                                                      NULL, NULL, 0, 0 );
    ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
    ok( subscription && subscription != (void *)0xdeadbeef,
        "expected a new subscription, got %p\n", subscription );
    if (!status)
    {
        status = pRtlUnsubscribeWnfNotificationWaitForCompletion( subscription );
        ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
    }

    subscription = NULL;
    status = pRtlSubscribeWnfStateChangeNotification( &subscription, name, 0, callback,
                                                      NULL, NULL, 0, 0 );
    ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
    ok( !!subscription, "expected a subscription\n" );
    if (!status)
    {
        status = pRtlUnsubscribeWnfStateChangeNotification( subscription );
        ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
    }
}
