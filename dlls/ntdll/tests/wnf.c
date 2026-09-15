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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "wine/test.h"

#define WNF_FT_LAST_PROCESS_PROMOTION_TRIGGER 0x41c61a2ba3bc2875ULL
#define WNF_GPOL_SYSTEM_CHANGES 0x0d891e2aa3bc0875ULL
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

struct cross_process_callback_context
{
    HANDLE event;
    LONG calls;
    ULONGLONG name;
    ULONG stamp, size, value;
    const GUID *type;
};

static NTSTATUS WINAPI cross_process_callback( ULONGLONG name, ULONG stamp, const GUID *type,
                                               void *context, const void *data, ULONG size )
{
    struct cross_process_callback_context *callback = context;

    callback->name = name;
    callback->stamp = stamp;
    callback->type = type;
    callback->size = size;
    callback->value = size == sizeof(callback->value) ? *(const ULONG *)data : 0;
    InterlockedIncrement( &callback->calls );
    SetEvent( callback->event );
    return STATUS_SUCCESS;
}

static void test_cross_process_notification( char **argv, ULONG lifetime )
{
    struct cross_process_callback_context callback = {0};
    STARTUPINFOA startup = { .cb = sizeof(startup) };
    PROCESS_INFORMATION process = {0};
    SECURITY_DESCRIPTOR sd;
    ULONGLONG state = 0;
    void *subscription = NULL;
    char command[MAX_PATH * 3];
    DWORD wait;
    NTSTATUS status;
    BOOL ret;

    InitializeSecurityDescriptor( &sd, SECURITY_DESCRIPTOR_REVISION );
    SetSecurityDescriptorDacl( &sd, TRUE, NULL, FALSE );
    status = pNtCreateWnfStateName( &state, lifetime, 0, FALSE, NULL, sizeof(callback.value), &sd );
    ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
    if (status) return;

    callback.event = CreateEventW( NULL, TRUE, FALSE, NULL );
    ok( !!callback.event, "failed to create callback event, error %lu\n", GetLastError() );
    if (!callback.event) goto done;

    status = pRtlSubscribeWnfStateChangeNotification( &subscription, state, 0,
                                                      cross_process_callback, &callback,
                                                      NULL, 0, 0 );
    ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
    if (status) goto done;

    sprintf( command, "\"%s\" %s wnf-publisher %I64x", argv[0], argv[1], state );
    ret = CreateProcessA( NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process );
    ok( ret, "failed to create publisher process, error %lu\n", GetLastError() );
    if (!ret) goto done;

    wait = WaitForSingleObject( callback.event, 5000 );
    ok( wait == WAIT_OBJECT_0, "expected callback event, wait returned %lu\n", wait );
    wait_child_process( &process );

    ok( callback.calls == 1, "expected one callback, got %ld\n", callback.calls );
    ok( callback.name == state, "expected state %#I64x, got %#I64x\n", state, callback.name );
    ok( callback.stamp == 1, "expected change stamp 1, got %lu\n", callback.stamp );
    ok( !callback.type, "expected no type, got %p\n", callback.type );
    ok( callback.size == sizeof(callback.value), "expected %Iu bytes, got %lu\n",
        sizeof(callback.value), callback.size );
    ok( callback.value == 2, "expected value 2, got %lu\n", callback.value );

done:
    if (subscription)
    {
        status = pRtlUnsubscribeWnfNotificationWaitForCompletion( subscription );
        ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
    }
    if (callback.event) CloseHandle( callback.event );
    status = pNtDeleteWnfStateName( &state );
    ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
}

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
    char **argv;
    int argc;

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

    argc = winetest_get_mainargs( &argv );
    if (argc > 3 && !strcmp( argv[2], "wnf-publisher" ))
    {
        ULONGLONG state = _strtoui64( argv[3], NULL, 16 );
        ULONG value = 2;

        status = pRtlPublishWnfStateData( state, NULL, &value, sizeof(value), NULL );
        ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
        return;
    }

    if (pNtCreateWnfStateName && pNtDeleteWnfStateData && pNtDeleteWnfStateName &&
        pNtUpdateWnfStateData)
    {
        static const ULONG lifetimes[] = {2, 3};
        SECURITY_DESCRIPTOR sd;
        ULONG value = 0x12345678, queried = 0, query_size, old_stamp;
        unsigned int i;

        InitializeSecurityDescriptor( &sd, SECURITY_DESCRIPTOR_REVISION );
        SetSecurityDescriptorDacl( &sd, TRUE, NULL, FALSE );
        for (i = 0; i < ARRAY_SIZE(lifetimes); i++)
        {
            ULONGLONG state = 0;

            status = pNtCreateWnfStateName( &state, lifetimes[i], 0, FALSE, &type,
                                            sizeof(value), &sd );
            ok( status == STATUS_SUCCESS, "lifetime %lu: expected STATUS_SUCCESS, got %#lx\n",
                lifetimes[i], status );
            if (!status)
            {
                status = pNtUpdateWnfStateData( &state, &value, sizeof(value), &type, NULL, 0, FALSE );
                ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
                query_size = sizeof(queried);
                old_stamp = 0;
                status = pNtQueryWnfStateData( &state, &type, NULL, &old_stamp, &queried, &query_size );
                ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
                ok( queried == value, "expected %#lx, got %#lx\n", value, queried );

                status = pNtDeleteWnfStateData( &state, NULL );
                ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
                query_size = sizeof(queried);
                stamp = 0;
                status = pNtQueryWnfStateData( &state, &type, NULL, &stamp, &queried, &query_size );
                ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
                ok( !query_size, "expected no state data, got %lu bytes\n", query_size );
                ok( stamp == old_stamp + 1, "expected change stamp %lu, got %lu\n", old_stamp + 1, stamp );

                status = pNtDeleteWnfStateName( &state );
                ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
            }
        }

        for (i = 0; i < ARRAY_SIZE(lifetimes); i++)
        {
            winetest_push_context( "cross-process lifetime %lu", lifetimes[i] );
            test_cross_process_notification( argv, lifetimes[i] );
            winetest_pop_context();
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

    subscription = (void *)0xdeadbeef;
    status = pRtlSubscribeWnfStateChangeNotification( &subscription, name, 0, callback,
                                                      NULL, NULL, 0, 1 );
    ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
    ok( subscription && subscription != (void *)0xdeadbeef,
        "expected a new subscription, got %p\n", subscription );
    if (!status)
    {
        status = pRtlUnsubscribeWnfStateChangeNotification( subscription );
        ok( status == STATUS_SUCCESS, "expected STATUS_SUCCESS, got %#lx\n", status );
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
            WNF_GPOL_SYSTEM_CHANGES,
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
