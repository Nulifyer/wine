/*
 * Windows feature configuration queries
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
#include "winternl.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(ntdll);

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

struct feature_profile_entry
{
    ULONG feature_id;
    ULONG flags[2];
    BOOL present[2];
};

static const struct feature_profile_entry feature_profile[] =
{
    {0x038419ca, {0x2f, 0x2f}, {TRUE, TRUE}},  /* Ten2Loc */
    {0x037e2887, {0x2f, 0},    {TRUE, FALSE}}, /* Standalone_26_04_NonSec */
    {0x032cf8c5, {0x19, 0},    {TRUE, FALSE}}, /* Feature_1855570234 */
    {0x036933e4, {0x20, 0},    {TRUE, FALSE}}, /* ProperMbrContainment */
    {0x032204ec, {0x29, 0},    {TRUE, FALSE}}, /* Feature_3379165498 */
    {0x03334051, {0x29, 0},    {TRUE, FALSE}}, /* Feature_1014611256 */
    {0x036099b1, {0x29, 0},    {TRUE, FALSE}}, /* Feature_3206345019 */
};

static const struct feature_profile_entry *find_feature_profile_entry( ULONG feature_id,
                                                                        ULONG type )
{
    ULONG i;

    if (type > 1) return NULL;
    for (i = 0; i < ARRAY_SIZE(feature_profile); ++i)
        if (feature_profile[i].feature_id == feature_id && feature_profile[i].present[type])
            return feature_profile + i;
    return NULL;
}

typedef void (CALLBACK *rtl_feature_change_callback)(void *context);

struct feature_change_registration
{
    rtl_feature_change_callback callback;
    void *context;
    RTL_SRWLOCK callback_lock;
    TP_WORK *work;
};

static void CALLBACK feature_change_callback( TP_CALLBACK_INSTANCE *instance, void *context,
                                              TP_WORK *work )
{
    struct feature_change_registration *registration = context;

    RtlAcquireSRWLockExclusive( &registration->callback_lock );
    registration->callback( registration->context );
    RtlReleaseSRWLockExclusive( &registration->callback_lock );
}

/***********************************************************************
 *             RtlQueryFeatureConfiguration  (NTDLL.@)
 */
NTSTATUS WINAPI RtlQueryFeatureConfiguration( ULONG feature_id, ULONG configuration_type,
                                              ULONGLONG *change_stamp,
                                              struct rtl_feature_configuration *configuration )
{
    const struct feature_profile_entry *entry;

    TRACE( "(%#lx,%lu,%p,%p)\n", feature_id, configuration_type, change_stamp, configuration );

    if (configuration_type > 1) return STATUS_INVALID_PARAMETER;
    if (!change_stamp || !configuration) return STATUS_INVALID_PARAMETER;
    *change_stamp = 1;
    if (!(entry = find_feature_profile_entry( feature_id, configuration_type )))
        return STATUS_NOT_FOUND;

    configuration->feature_id = feature_id;
    configuration->flags = entry->flags[configuration_type];
    configuration->variant_payload = 0;
    return STATUS_SUCCESS;
}

/***********************************************************************
 *             RtlQueryAllFeatureConfigurations  (NTDLL.@)
 */
NTSTATUS WINAPI RtlQueryAllFeatureConfigurations( ULONGLONG configuration_type,
                                                   ULONGLONG *change_stamp,
                                                   struct rtl_feature_configuration *configurations,
                                                   ULONGLONG *configuration_count )
{
    ULONGLONG capacity, required = 0;
    ULONG i;

    TRACE( "(%s,%p,%p,%p)\n", wine_dbgstr_longlong(configuration_type), change_stamp,
           configurations, configuration_count );

    if (configuration_type > 1 || !configuration_count) return STATUS_INVALID_PARAMETER;
    capacity = *configuration_count;
    for (i = 0; i < ARRAY_SIZE(feature_profile); ++i)
        if (feature_profile[i].present[configuration_type]) ++required;
    *configuration_count = required;
    if (capacity < required) return STATUS_BUFFER_OVERFLOW;
    if (required && !configurations) return STATUS_INVALID_PARAMETER;

    required = 0;
    for (i = 0; i < ARRAY_SIZE(feature_profile); ++i)
    {
        if (!feature_profile[i].present[configuration_type]) continue;
        configurations[required].feature_id = feature_profile[i].feature_id;
        configurations[required].flags = feature_profile[i].flags[configuration_type];
        configurations[required].variant_payload = 0;
        ++required;
    }
    if (change_stamp) *change_stamp = 1;
    return STATUS_SUCCESS;
}

/***********************************************************************
 *             RtlQueryInternalFeatureConfiguration  (NTDLL.@)
 */
NTSTATUS WINAPI RtlQueryInternalFeatureConfiguration( ULONGLONG feature_id,
                                                       ULONG configuration_type,
                                                       ULONGLONG *change_stamp,
                                                       struct rtl_internal_feature_configuration *configuration )
{
    const struct feature_profile_entry *entry;

    TRACE( "(%s,%lu,%p,%p)\n", wine_dbgstr_longlong(feature_id), configuration_type,
           change_stamp, configuration );

    if (feature_id > ~0u || configuration_type > 1 || !change_stamp || !configuration)
        return STATUS_INVALID_PARAMETER;
    *change_stamp = 1;
    if (!(entry = find_feature_profile_entry( feature_id, configuration_type )))
        return STATUS_NOT_FOUND;
    configuration->feature_id = feature_id;
    configuration->flags = entry->flags[configuration_type];
    configuration->variant_payload = 0;
    configuration->reserved = 0;
    return STATUS_SUCCESS;
}

/***********************************************************************
 *             RtlQueryFeatureUsageNotificationSubscriptions  (NTDLL.@)
 */
NTSTATUS WINAPI RtlQueryFeatureUsageNotificationSubscriptions( void *subscriptions,
                                                                ULONGLONG *subscription_count )
{
    TRACE( "(%p,%p)\n", subscriptions, subscription_count );
    if (!subscription_count) return STATUS_INVALID_PARAMETER;
    *subscription_count = 0;
    return STATUS_SUCCESS;
}

/***********************************************************************
 *             RtlNotifyFeatureUsage  (NTDLL.@)
 */
NTSTATUS WINAPI RtlNotifyFeatureUsage( const void *usage )
{
    TRACE( "(%p)\n", usage );
    return usage ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}

/***********************************************************************
 *             RtlSetFeatureConfigurations  (NTDLL.@)
 */
NTSTATUS WINAPI RtlSetFeatureConfigurations( const ULONGLONG *change_stamp, ULONG configuration_type,
                                             const void *configurations, ULONGLONG configuration_count )
{
    TRACE( "(%p,%lu,%p,%s)\n", change_stamp, configuration_type, configurations,
           wine_dbgstr_longlong(configuration_count) );
    if (configuration_type > 1 || configuration_count > ~0u)
        return STATUS_INVALID_PARAMETER;
    if (configuration_count && !configurations) return STATUS_INVALID_PARAMETER;

    /* LinuxNT publishes a deterministic compatibility profile.  Accept the
     * privileged update transaction, but do not let one process create a
     * divergent process-local view of system feature state. */
    return STATUS_SUCCESS;
}

/***********************************************************************
 *             RtlSubscribeForFeatureUsageNotification  (NTDLL.@)
 */
void WINAPI RtlSubscribeForFeatureUsageNotification( const void *subscriptions, ULONGLONG count )
{
    TRACE( "(%p,%s)\n", subscriptions, wine_dbgstr_longlong(count) );
}

/***********************************************************************
 *             RtlUnsubscribeFromFeatureUsageNotifications  (NTDLL.@)
 */
void WINAPI RtlUnsubscribeFromFeatureUsageNotifications( const void *subscriptions, ULONGLONG count )
{
    TRACE( "(%p,%s)\n", subscriptions, wine_dbgstr_longlong(count) );
}

/***********************************************************************
 *   RtlQueryFeatureConfigurationChangeStamp  (NTDLL.@)
 */
ULONGLONG WINAPI RtlQueryFeatureConfigurationChangeStamp(void)
{
    return 1;
}

/***********************************************************************
 *   RtlRegisterFeatureConfigurationChangeNotification  (NTDLL.@)
 */
NTSTATUS WINAPI RtlRegisterFeatureConfigurationChangeNotification(
    rtl_feature_change_callback callback, void *context, const ULONGLONG *change_stamp,
    void **registration_handle )
{
    struct feature_change_registration *registration;
    NTSTATUS status;

    TRACE( "(%p,%p,%p,%p)\n", callback, context, change_stamp, registration_handle );

    if (!(registration = RtlAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY,
                                          sizeof(*registration) )))
        return STATUS_NO_MEMORY;

    registration->callback = callback;
    registration->context = context;
    if ((status = TpAllocWork( &registration->work, feature_change_callback, registration, NULL )))
    {
        RtlFreeHeap( GetProcessHeap(), 0, registration );
        return status;
    }

    if (change_stamp && *change_stamp != RtlQueryFeatureConfigurationChangeStamp())
        TpPostWork( registration->work );
    *registration_handle = registration;
    return STATUS_SUCCESS;
}

/***********************************************************************
 *   RtlUnregisterFeatureConfigurationChangeNotification  (NTDLL.@)
 */
void WINAPI RtlUnregisterFeatureConfigurationChangeNotification( void *registration_handle )
{
    struct feature_change_registration *registration = registration_handle;

    TRACE( "(%p)\n", registration );

    TpWaitForWork( registration->work, TRUE );
    TpReleaseWork( registration->work );
    RtlFreeHeap( GetProcessHeap(), 0, registration );
}
