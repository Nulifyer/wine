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
#define WNF_PNPA_DEVNODES_CHANGED 0x0096003da3bc0875ULL
#define WNF_PNPA_DEVNODES_CHANGED_SESSION 0x0096003da3bc1035ULL
#define WNF_PNPA_VOLUMES_CHANGED 0x0096003da3bc1875ULL
#define WNF_PNPA_VOLUMES_CHANGED_SESSION 0x0096003da3bc2035ULL
#define WNF_PNPA_HARDWAREPROFILES_CHANGED 0x0096003da3bc2875ULL
#define WNF_PNPA_HARDWAREPROFILES_CHANGED_SESSION 0x0096003da3bc3035ULL
#define WNF_PNPA_PORTS_CHANGED 0x0096003da3bc3875ULL
#define WNF_PNPA_PORTS_CHANGED_SESSION 0x0096003da3bc4035ULL
#define WNF_PO_SCENARIO_CHANGE 0x41c6013da3bce875ULL
#define WNF_RPCF_FWMAN_RUNNING 0x07851e3fa3bc0875ULL

typedef NTSTATUS (WINAPI *wnf_callback)( ULONGLONG, ULONG, const GUID *, void *, const void *, ULONG );
static NTSTATUS (WINAPI *pNtCreateWnfStateName)( ULONGLONG *, ULONG, ULONG, BOOLEAN, const GUID *,
                                                ULONG, const SECURITY_DESCRIPTOR * );
static NTSTATUS (WINAPI *pNtDeleteWnfStateData)( const ULONGLONG *, const void * );
static NTSTATUS (WINAPI *pNtDeleteWnfStateName)( const ULONGLONG * );
static NTSTATUS (WINAPI *pNtQueryWnfStateData)( const ULONGLONG *, const GUID *, const void *,
                                               ULONG *, void *, ULONG * );
static NTSTATUS (WINAPI *pNtUpdateWnfStateData)( const ULONGLONG *, const void *, ULONG, const GUID *,
                                                const void *, ULONG, ULONG );
static NTSTATUS (WINAPI *pNtSubscribeWnfStateChange)( const ULONGLONG *, ULONG, ULONG, ULONGLONG * );
static NTSTATUS (WINAPI *pNtUnsubscribeWnfStateChange)( const ULONGLONG * );
static ULONG (WINAPI *pRtlAllocateWnfSerializationGroup)( void );
static NTSTATUS (WINAPI *pRtlPublishWnfStateData)( ULONGLONG, const GUID *, const void *, ULONG,
                                                  const void * );
static NTSTATUS (WINAPI *pRtlQueryWnfStateData)( ULONG *, ULONGLONG, wnf_callback, void *,
                                                const GUID * );
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

static NTSTATUS WINAPI query_callback( ULONGLONG name, ULONG stamp, const GUID *type, void *context,
                                       const void *data, ULONG size )
{
    ULONG *calls = context;

    (*calls)++;
    ok( name == WNF_FT_LAST_PROCESS_PROMOTION_TRIGGER, "unexpected state name %#I64x\n", name );
    ok( !stamp, "expected stamp 0, got %lu\n", stamp );
    ok( !type, "expected no type, got %p\n", type );
    ok( !!data, "expected a query buffer\n" );
    ok( !size, "expected size 0, got %lu\n", size );
    return STATUS_RETRY;
}

START_TEST(wnf)
{
    static const GUID type = {0x11223344, 0x5566, 0x7788, {0x90,0xab,0xcd,0xef,0x12,0x34,0x56,0x78}};
    const ULONGLONG name = WNF_FT_LAST_PROCESS_PROMOTION_TRIGGER;
    HMODULE ntdll = GetModuleHandleW( L"ntdll.dll" );
    void *subscription;
    ULONG stamp, size;
    NTSTATUS status;

    pNtCreateWnfStateName = (void *)GetProcAddress( ntdll, "NtCreateWnfStateName" );
    pNtDeleteWnfStateData = (void *)GetProcAddress( ntdll, "NtDeleteWnfStateData" );
    pNtDeleteWnfStateName = (void *)GetProcAddress( ntdll, "NtDeleteWnfStateName" );
    pNtQueryWnfStateData = (void *)GetProcAddress( ntdll, "NtQueryWnfStateData" );
    pNtUpdateWnfStateData = (void *)GetProcAddress( ntdll, "NtUpdateWnfStateData" );
    pNtSubscribeWnfStateChange = (void *)GetProcAddress( ntdll, "NtSubscribeWnfStateChange" );
    pNtUnsubscribeWnfStateChange = (void *)GetProcAddress( ntdll, "NtUnsubscribeWnfStateChange" );
    pRtlAllocateWnfSerializationGroup =
        (void *)GetProcAddress( ntdll, "RtlAllocateWnfSerializationGroup" );
    pRtlPublishWnfStateData = (void *)GetProcAddress( ntdll, "RtlPublishWnfStateData" );
    pRtlQueryWnfStateData = (void *)GetProcAddress( ntdll, "RtlQueryWnfStateData" );
    pRtlTestAndPublishWnfStateData =
        (void *)GetProcAddress( ntdll, "RtlTestAndPublishWnfStateData" );
    pRtlSubscribeWnfStateChangeNotification =
        (void *)GetProcAddress( ntdll, "RtlSubscribeWnfStateChangeNotification" );
    pRtlUnsubscribeWnfNotificationWaitForCompletion =
        (void *)GetProcAddress( ntdll, "RtlUnsubscribeWnfNotificationWaitForCompletion" );
    pRtlUnsubscribeWnfStateChangeNotification =
        (void *)GetProcAddress( ntdll, "RtlUnsubscribeWnfStateChangeNotification" );
    if (!pNtQueryWnfStateData || !pNtSubscribeWnfStateChange ||
        !pNtUnsubscribeWnfStateChange || !pRtlPublishWnfStateData || !pRtlQueryWnfStateData ||
        !pRtlTestAndPublishWnfStateData || !pRtlSubscribeWnfStateChangeNotification ||
        !pRtlUnsubscribeWnfNotificationWaitForCompletion ||
        !pRtlUnsubscribeWnfStateChangeNotification)
    {
        win_skip( "WNF functions are unavailable\n" );
        return;
    }

    if (pNtCreateWnfStateName && pNtDeleteWnfStateData && pNtDeleteWnfStateName &&
        pNtUpdateWnfStateData)
    {
        SECURITY_DESCRIPTOR sd;
        ULONGLONG temporary = 0;
        ULONG value = 0x12345678, queried = 0, query_size, old_stamp;

        InitializeSecurityDescriptor( &sd, SECURITY_DESCRIPTOR_REVISION );
        SetSecurityDescriptorDacl( &sd, TRUE, NULL, FALSE );
        status = pNtCreateWnfStateName( &temporary, 3, 0, FALSE, &type, sizeof(value), &sd );
        ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
        if (!status)
        {
            status = pNtUpdateWnfStateData( &temporary, &value, sizeof(value), &type, NULL, 0, FALSE );
            ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
            query_size = sizeof(queried);
            old_stamp = 0;
            status = pNtQueryWnfStateData( &temporary, &type, NULL, &old_stamp, &queried, &query_size );
            ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
            ok( queried == value, "expected %#lx, got %#lx\n", value, queried );

            status = pNtDeleteWnfStateData( &temporary, NULL );
            ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
            query_size = sizeof(queried);
            stamp = 0;
            status = pNtQueryWnfStateData( &temporary, &type, NULL, &stamp, &queried, &query_size );
            ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
            ok( !query_size, "expected no state data, got %lu bytes\n", query_size );
            ok( stamp == old_stamp + 1, "expected change stamp %lu, got %lu\n", old_stamp + 1, stamp );

            status = pNtDeleteWnfStateName( &temporary );
            ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
        }
    }
    else win_skip( "WNF state-data deletion functions are unavailable\n" );

    if (pRtlAllocateWnfSerializationGroup)
    {
        ULONG group = pRtlAllocateWnfSerializationGroup();
        ULONG next_group = pRtlAllocateWnfSerializationGroup();

        ok( group != 0, "expected a nonzero serialization group\n" );
        ok( next_group != 0 && next_group != group,
            "expected a distinct serialization group, got %lu then %lu\n", group, next_group );

        subscription = NULL;
        status = pRtlSubscribeWnfStateChangeNotification( &subscription, name, 0, callback,
                                                          NULL, NULL, group, 0 );
        ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
        ok( !!subscription, "expected a subscription\n" );
        if (!status)
        {
            status = pRtlUnsubscribeWnfStateChangeNotification( subscription );
            ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
        }
    }
    else win_skip( "RtlAllocateWnfSerializationGroup is unavailable\n" );

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

    {
        ULONG calls = 0;

        stamp = 0xdeadbeef;
        status = pRtlQueryWnfStateData( &stamp, name, query_callback, &calls, NULL );
        ok( status == STATUS_RETRY, "expected callback status STATUS_RETRY, got %#lx\n", status );
        ok( !stamp, "expected stamp 0, got %lu\n", stamp );
        ok( calls == 1, "expected one callback, got %lu\n", calls );
    }

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

    {
        const ULONGLONG well_known_names[] =
        {
            WNF_PNPA_DEVNODES_CHANGED,
            WNF_PNPA_DEVNODES_CHANGED_SESSION,
            WNF_PNPA_VOLUMES_CHANGED,
            WNF_PNPA_VOLUMES_CHANGED_SESSION,
            WNF_PNPA_HARDWAREPROFILES_CHANGED,
            WNF_PNPA_HARDWAREPROFILES_CHANGED_SESSION,
            WNF_PNPA_PORTS_CHANGED,
            WNF_PNPA_PORTS_CHANGED_SESSION,
            WNF_PO_SCENARIO_CHANGE,
            WNF_RPCF_FWMAN_RUNNING,
        };
        ULONGLONG id = 0xdeadbeef;
        unsigned int i;

        for (i = 0; i < ARRAY_SIZE(well_known_names); i++)
        {
            id = 0xdeadbeef;
            status = pNtSubscribeWnfStateChange( &well_known_names[i], 0, 0x11, &id );
            ok( status == STATUS_SUCCESS, "%#I64x: expected STATUS_SUCCESS, got %#lx\n",
                well_known_names[i], status );
            ok( id && id != 0xdeadbeef, "%#I64x: expected a new subscription id, got %#I64x\n",
                well_known_names[i], id );
            if (!status)
            {
                status = pNtUnsubscribeWnfStateChange( &well_known_names[i] );
                ok( status == STATUS_SUCCESS, "%#I64x: expected STATUS_SUCCESS, got %#lx\n",
                    well_known_names[i], status );
            }
        }
    }
}
