/*
 * Windows feature configuration query tests
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

struct rtl_feature_configuration
{
    ULONG feature_id;
    ULONG flags;
    ULONG variant_payload;
};

struct rtl_internal_feature_configuration
{
    ULONG feature_id;
    ULONG flags;
    ULONG variant_payload;
    ULONG reserved;
};

static NTSTATUS (WINAPI *pRtlQueryFeatureConfiguration)(ULONG, ULONG, ULONGLONG *,
                                                        struct rtl_feature_configuration *);
static ULONGLONG (WINAPI *pRtlQueryFeatureConfigurationChangeStamp)(void);
static NTSTATUS (WINAPI *pRtlQueryAllFeatureConfigurations)(ULONGLONG, ULONGLONG *,
                                                            struct rtl_feature_configuration *,
                                                            ULONGLONG *);
static NTSTATUS (WINAPI *pRtlQueryInternalFeatureConfiguration)(ULONGLONG, ULONG, ULONGLONG *,
                                                                struct rtl_internal_feature_configuration *);
static NTSTATUS (WINAPI *pRtlQueryFeatureUsageNotificationSubscriptions)(void *, ULONGLONG *);
static NTSTATUS (WINAPI *pRtlNotifyFeatureUsage)(const void *);
static NTSTATUS (WINAPI *pRtlSetFeatureConfigurations)(const ULONGLONG *, ULONG, const void *, ULONGLONG);
static void (WINAPI *pRtlSubscribeForFeatureUsageNotification)(const void *, ULONGLONG);
static void (WINAPI *pRtlUnsubscribeFromFeatureUsageNotifications)(const void *, ULONGLONG);
static NTSTATUS (WINAPI *pRtlRegisterFeatureConfigurationChangeNotification)(
    void (CALLBACK *)(void *), void *, const ULONGLONG *, void **);
static void (WINAPI *pRtlUnregisterFeatureConfigurationChangeNotification)(void *);

struct change_callback_context
{
    HANDLE event;
    LONG calls;
};

static void CALLBACK feature_change_callback(void *context)
{
    struct change_callback_context *callback = context;

    InterlockedIncrement( &callback->calls );
    SetEvent( callback->event );
}

static void test_query_feature_configuration(void)
{
    struct rtl_feature_configuration configuration;
    ULONGLONG stamp;
    NTSTATUS status;

    if (!pRtlQueryFeatureConfiguration)
    {
        win_skip( "RtlQueryFeatureConfiguration is unavailable.\n" );
        return;
    }

    stamp = 0x1111222233334444;
    configuration = (struct rtl_feature_configuration){0x55556666, 0x77778888, 0x9999aaaa};
    SetLastError( 0x13579bdf );
    status = pRtlQueryFeatureConfiguration( 0x038419ca, 0, &stamp, &configuration );
    ok( status == STATUS_SUCCESS, "got status %#lx.\n", status );
    ok( stamp == 1, "got stamp %s.\n", wine_dbgstr_longlong(stamp) );
    ok( configuration.feature_id == 0x038419ca, "got feature %#lx.\n", configuration.feature_id );
    ok( configuration.flags == 0x2f, "got flags %#lx.\n", configuration.flags );
    ok( !configuration.variant_payload, "got payload %#lx.\n", configuration.variant_payload );
    ok( GetLastError() == 0x13579bdf, "last error changed to %#lx.\n", GetLastError() );

    stamp = 0x1111222233334444;
    configuration = (struct rtl_feature_configuration){0x55556666, 0x77778888, 0x9999aaaa};
    status = pRtlQueryFeatureConfiguration( 0x12345678, 1, &stamp, &configuration );
    ok( status == STATUS_NOT_FOUND, "got status %#lx.\n", status );
    ok( stamp == 1, "got stamp %s.\n", wine_dbgstr_longlong(stamp) );
    ok( configuration.feature_id == 0x55556666 && configuration.flags == 0x77778888 &&
        configuration.variant_payload == 0x9999aaaa, "configuration was modified.\n" );

    stamp = 0x1111222233334444;
    configuration = (struct rtl_feature_configuration){0x55556666, 0x77778888, 0x9999aaaa};
    status = pRtlQueryFeatureConfiguration( 0x038419ca, 2, &stamp, &configuration );
    ok( status == STATUS_INVALID_PARAMETER, "got status %#lx.\n", status );
    ok( stamp == 0x1111222233334444, "got stamp %s.\n", wine_dbgstr_longlong(stamp) );
    ok( configuration.feature_id == 0x55556666 && configuration.flags == 0x77778888 &&
        configuration.variant_payload == 0x9999aaaa, "configuration was modified.\n" );
}

static void test_feature_change_notification(void)
{
    struct change_callback_context callback = {0};
    ULONGLONG stamp;
    void *registration;
    NTSTATUS status;
    DWORD wait;

    if (!pRtlQueryFeatureConfigurationChangeStamp ||
        !pRtlRegisterFeatureConfigurationChangeNotification ||
        !pRtlUnregisterFeatureConfigurationChangeNotification)
    {
        win_skip( "Feature-configuration change notification exports are unavailable.\n" );
        return;
    }

    callback.event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!callback.event, "CreateEventW failed, error %lu.\n", GetLastError() );
    if (!callback.event) return;

    stamp = pRtlQueryFeatureConfigurationChangeStamp();
    ok( stamp == 1, "got change stamp %s.\n", wine_dbgstr_longlong(stamp) );

    registration = NULL;
    status = pRtlRegisterFeatureConfigurationChangeNotification(
        feature_change_callback, &callback, NULL, &registration );
    ok( status == STATUS_SUCCESS, "null-stamp registration returned %#lx.\n", status );
    ok( !!registration, "null-stamp registration returned no handle.\n" );
    wait = WaitForSingleObject( callback.event, 0 );
    ok( wait == WAIT_TIMEOUT, "null-stamp registration invoked callback, wait %#lx.\n", wait );
    pRtlUnregisterFeatureConfigurationChangeNotification( registration );

    registration = NULL;
    status = pRtlRegisterFeatureConfigurationChangeNotification(
        feature_change_callback, &callback, &stamp, &registration );
    ok( status == STATUS_SUCCESS, "current-stamp registration returned %#lx.\n", status );
    ok( !!registration, "current-stamp registration returned no handle.\n" );
    wait = WaitForSingleObject( callback.event, 0 );
    ok( wait == WAIT_TIMEOUT, "current-stamp registration invoked callback, wait %#lx.\n", wait );
    pRtlUnregisterFeatureConfigurationChangeNotification( registration );

    stamp = 0;
    registration = NULL;
    status = pRtlRegisterFeatureConfigurationChangeNotification(
        feature_change_callback, &callback, &stamp, &registration );
    ok( status == STATUS_SUCCESS, "stale-stamp registration returned %#lx.\n", status );
    ok( !!registration, "stale-stamp registration returned no handle.\n" );
    wait = WaitForSingleObject( callback.event, 5000 );
    ok( wait == WAIT_OBJECT_0, "stale-stamp callback wait returned %#lx.\n", wait );
    pRtlUnregisterFeatureConfigurationChangeNotification( registration );
    ok( callback.calls == 1, "got %ld callback calls.\n", callback.calls );

    CloseHandle( callback.event );
}

static void test_feature_configuration_surface(void)
{
    struct rtl_feature_configuration configurations[7];
    struct rtl_internal_feature_configuration internal = {0};
    ULONGLONG stamp, count;
    NTSTATUS status;
    ULONG usage = 0;

    if (!pRtlQueryAllFeatureConfigurations || !pRtlQueryInternalFeatureConfiguration ||
        !pRtlQueryFeatureUsageNotificationSubscriptions || !pRtlNotifyFeatureUsage ||
        !pRtlSetFeatureConfigurations || !pRtlSubscribeForFeatureUsageNotification ||
        !pRtlUnsubscribeFromFeatureUsageNotifications)
    {
        win_skip( "Feature-configuration surface exports are unavailable.\n" );
        return;
    }

    stamp = 0x1111222233334444;
    count = 0;
    status = pRtlQueryAllFeatureConfigurations( 0, &stamp, NULL, &count );
    ok( status == STATUS_BUFFER_OVERFLOW, "size query returned %#lx.\n", status );
    ok( count == ARRAY_SIZE(configurations), "got count %s.\n", wine_dbgstr_longlong(count) );
    ok( stamp == 0x1111222233334444, "overflow changed stamp to %s.\n", wine_dbgstr_longlong(stamp) );

    memset( configurations, 0xcc, sizeof(configurations) );
    status = pRtlQueryAllFeatureConfigurations( 0, &stamp, configurations, &count );
    ok( status == STATUS_SUCCESS, "bulk query returned %#lx.\n", status );
    ok( stamp == 1, "got stamp %s.\n", wine_dbgstr_longlong(stamp) );
    ok( configurations[0].feature_id == 0x038419ca && configurations[0].flags == 0x2f,
        "got first feature %#lx flags %#lx.\n", configurations[0].feature_id, configurations[0].flags );

    stamp = 0;
    status = pRtlQueryInternalFeatureConfiguration( 0x038419ca, 1, &stamp, &internal );
    ok( status == STATUS_SUCCESS, "internal query returned %#lx.\n", status );
    ok( stamp == 1, "got internal stamp %s.\n", wine_dbgstr_longlong(stamp) );
    ok( internal.feature_id == 0x038419ca && internal.flags == 0x2f && !internal.reserved,
        "got internal feature %#lx flags %#lx reserved %#lx.\n",
        internal.feature_id, internal.flags, internal.reserved );

    count = 4;
    status = pRtlQueryFeatureUsageNotificationSubscriptions( configurations, &count );
    ok( status == STATUS_SUCCESS, "subscription query returned %#lx.\n", status );
    ok( !count, "got subscription count %s.\n", wine_dbgstr_longlong(count) );

    status = pRtlNotifyFeatureUsage( NULL );
    ok( status == STATUS_INVALID_PARAMETER, "null usage returned %#lx.\n", status );
    status = pRtlNotifyFeatureUsage( &usage );
    ok( status == STATUS_SUCCESS, "usage notification returned %#lx.\n", status );

    status = pRtlSetFeatureConfigurations( &stamp, 0, NULL, 1 );
    ok( status == STATUS_INVALID_PARAMETER, "null configuration update returned %#lx.\n", status );
    status = pRtlSetFeatureConfigurations( &stamp, 0, NULL, 0 );
    ok( status == STATUS_SUCCESS, "empty configuration update returned %#lx.\n", status );

    pRtlSubscribeForFeatureUsageNotification( NULL, 0 );
    pRtlUnsubscribeFromFeatureUsageNotifications( NULL, 0 );
}

START_TEST(feature)
{
    pRtlQueryFeatureConfiguration = (void *)GetProcAddress( GetModuleHandleA( "ntdll.dll" ),
                                                            "RtlQueryFeatureConfiguration" );
    pRtlQueryFeatureConfigurationChangeStamp = (void *)GetProcAddress(
        GetModuleHandleA( "ntdll.dll" ), "RtlQueryFeatureConfigurationChangeStamp" );
    pRtlQueryAllFeatureConfigurations = (void *)GetProcAddress(
        GetModuleHandleA( "ntdll.dll" ), "RtlQueryAllFeatureConfigurations" );
    pRtlQueryInternalFeatureConfiguration = (void *)GetProcAddress(
        GetModuleHandleA( "ntdll.dll" ), "RtlQueryInternalFeatureConfiguration" );
    pRtlQueryFeatureUsageNotificationSubscriptions = (void *)GetProcAddress(
        GetModuleHandleA( "ntdll.dll" ), "RtlQueryFeatureUsageNotificationSubscriptions" );
    pRtlNotifyFeatureUsage = (void *)GetProcAddress(
        GetModuleHandleA( "ntdll.dll" ), "RtlNotifyFeatureUsage" );
    pRtlSetFeatureConfigurations = (void *)GetProcAddress(
        GetModuleHandleA( "ntdll.dll" ), "RtlSetFeatureConfigurations" );
    pRtlSubscribeForFeatureUsageNotification = (void *)GetProcAddress(
        GetModuleHandleA( "ntdll.dll" ), "RtlSubscribeForFeatureUsageNotification" );
    pRtlUnsubscribeFromFeatureUsageNotifications = (void *)GetProcAddress(
        GetModuleHandleA( "ntdll.dll" ), "RtlUnsubscribeFromFeatureUsageNotifications" );
    pRtlRegisterFeatureConfigurationChangeNotification = (void *)GetProcAddress(
        GetModuleHandleA( "ntdll.dll" ), "RtlRegisterFeatureConfigurationChangeNotification" );
    pRtlUnregisterFeatureConfigurationChangeNotification = (void *)GetProcAddress(
        GetModuleHandleA( "ntdll.dll" ), "RtlUnregisterFeatureConfigurationChangeNotification" );
    test_query_feature_configuration();
    test_feature_configuration_surface();
    test_feature_change_notification();
}
