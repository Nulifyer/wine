/*
 * Helper functions for ntdll
 *
 * Copyright 2000 Juergen Schmied
 * Copyright 2010 Marcus Meissner
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

#include <time.h>
#include <string.h>

#include "ntstatus.h"
#include "wine/debug.h"
#include "wine/server.h"
#include "ntdll_misc.h"
#include "wmistr.h"
#include "evntrace.h"
#include "evntprov.h"

WINE_DEFAULT_DEBUG_CHANNEL(ntdll);

#define WNF_SUBSCRIPTION_MAGIC 0x4c4e54574e465355ULL
#define FEATURE_CONFIGURATION_REGISTRATION_MAGIC 0x4c4e544643524547ULL

static LONG wnf_serialization_group;

struct feature_configuration
{
    ULONG feature_id;
    ULONG flags;
    ULONG variant_payload;
};

typedef void (WINAPI *FEATURE_CONFIGURATION_CHANGE_CALLBACK)( void *context );

struct feature_configuration_registration
{
    ULONGLONG magic;
    FEATURE_CONFIGURATION_CHANGE_CALLBACK callback;
    void *context;
};

/***********************************************************************
 *      RtlGetFeatureToggleConfiguration   (NTDLL.@)
 *
 * The second argument is the caller's packed default configuration. Wine's
 * feature configuration is immutable, so there is no process-local override
 * to apply to that default.
 */
ULONGLONG WINAPI RtlGetFeatureToggleConfiguration( ULONG feature_id, ULONGLONG default_configuration )
{
    TRACE( "(%#lx %#I64x)\n", feature_id, default_configuration );
    return default_configuration;
}

/***********************************************************************
 *      RtlGetFeatureTogglesChangeToken   (NTDLL.@)
 */
ULONG WINAPI RtlGetFeatureTogglesChangeToken(void)
{
    return 1;
}

/***********************************************************************
 *      RtlNotifyFeatureToggleUsage   (NTDLL.@)
 */
NTSTATUS WINAPI RtlNotifyFeatureToggleUsage( ULONG feature_id, ULONGLONG configuration,
                                              ULONG reporting_kind )
{
    TRACE( "(%#lx %#I64x %lu)\n", feature_id, configuration, reporting_kind );
    return STATUS_SUCCESS;
}

/***********************************************************************
 *      RtlQueryFeatureConfiguration   (NTDLL.@)
 */
NTSTATUS WINAPI RtlQueryFeatureConfiguration( ULONG feature_id, ULONG configuration_type,
                                               ULONGLONG *change_stamp,
                                               struct feature_configuration *configuration )
{
    ULONG flags = 0;

    TRACE( "(%#lx %lu %p %p)\n", feature_id, configuration_type,
           change_stamp, configuration );

    if (!change_stamp || !configuration || configuration_type > 1)
        return STATUS_INVALID_PARAMETER;

    if (feature_id == 0x038419ca && configuration_type <= 1)
        flags = 0x2f;
    else if (feature_id == 0x037e2887 && configuration_type == 0)
        flags = 0x2f;
    else if (feature_id == 0x032cf8c5 && configuration_type == 0)
        flags = 0x19;
    else if ((feature_id == 0x032204ec || feature_id == 0x03334051 ||
              feature_id == 0x036099b1) && configuration_type == 0)
        flags = 0x29;
    else if (feature_id == 0x036933e4 && configuration_type == 0)
        flags = 0x20;

    *change_stamp = 1;
    if (!flags) return STATUS_NOT_FOUND;

    configuration->feature_id = feature_id;
    configuration->flags = flags;
    configuration->variant_payload = 0;
    return STATUS_SUCCESS;
}

/***********************************************************************
 *      RtlRegisterFeatureConfigurationChangeNotification   (NTDLL.@)
 */
NTSTATUS WINAPI RtlRegisterFeatureConfigurationChangeNotification(
    FEATURE_CONFIGURATION_CHANGE_CALLBACK callback, void *context,
    const ULONGLONG *observed_change_stamp, void **registration )
{
    struct feature_configuration_registration *entry;

    TRACE( "(%p %p %p %p)\n", callback, context, observed_change_stamp, registration );

    if (!callback || !registration) return STATUS_INVALID_PARAMETER;
    *registration = NULL;

    if (!(entry = RtlAllocateHeap( GetProcessHeap(), 0, sizeof(*entry) )))
        return STATUS_NO_MEMORY;
    entry->magic = FEATURE_CONFIGURATION_REGISTRATION_MAGIC;
    entry->callback = callback;
    entry->context = context;
    *registration = entry;

    /* Wine's feature configuration is immutable.  There is consequently no
     * newer change stamp to deliver after a successful registration. */
    return STATUS_SUCCESS;
}

/***********************************************************************
 *      RtlUnregisterFeatureConfigurationChangeNotification   (NTDLL.@)
 */
NTSTATUS WINAPI RtlUnregisterFeatureConfigurationChangeNotification( void *registration )
{
    struct feature_configuration_registration *entry = registration;

    TRACE( "(%p)\n", registration );

    if (!entry || !RtlValidateHeap( GetProcessHeap(), 0, entry ) ||
        entry->magic != FEATURE_CONFIGURATION_REGISTRATION_MAGIC)
        return STATUS_INVALID_HANDLE;
    entry->magic = 0;

    /* Windows exposes this entry as NTSTATUS but returns the BOOLEAN result
     * of freeing a valid registration object. */
    return RtlFreeHeap( GetProcessHeap(), 0, entry );
}

/***********************************************************************
 *      RtlAllocateWnfSerializationGroup   (NTDLL.@)
 */
ULONG WINAPI RtlAllocateWnfSerializationGroup(void)
{
    ULONG group;

    do group = InterlockedIncrement( &wnf_serialization_group );
    while (!group);
    return group;
}

/***********************************************************************
 *      NtSerializeBoot   (NTDLL.@)
 */
NTSTATUS WINAPI NtSerializeBoot(void)
{
    return STATUS_SUCCESS;
}

/***********************************************************************
 *      NtCreateWnfStateName   (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateWnfStateName( ULONGLONG *state_name, ULONG name_lifetime,
                                      ULONG data_scope, BOOLEAN persist_data,
                                      const GUID *type_id, ULONG maximum_size,
                                      const void *security_descriptor )
{
    NTSTATUS status;

    TRACE( "(%p %lu %lu %u %s %lu %p)\n", state_name, name_lifetime, data_scope,
           persist_data, debugstr_guid(type_id), maximum_size, security_descriptor );

    if (!state_name || persist_data > 1 || name_lifetime > 3 || data_scope > 5 || !maximum_size)
        return STATUS_INVALID_PARAMETER;

    SERVER_START_REQ( create_wnf_state_name )
    {
        req->name_lifetime = name_lifetime;
        req->data_scope = data_scope;
        req->maximum_size = maximum_size;
        req->persist_data = persist_data;
        req->type_id = !!type_id;
        req->security_descriptor = !!security_descriptor;
        status = wine_server_call( req );
        if (!status) *state_name = reply->state_name;
    }
    SERVER_END_REQ;
    return status;
}

/***********************************************************************
 *      NtDeleteWnfStateName   (NTDLL.@)
 */
NTSTATUS WINAPI NtDeleteWnfStateName( const ULONGLONG *state_name )
{
    NTSTATUS status;

    TRACE( "(%p %#I64x)\n", state_name, state_name ? *state_name : 0 );
    if (!state_name || !*state_name) return STATUS_INVALID_PARAMETER;

    SERVER_START_REQ( delete_wnf_state_name )
    {
        req->state_name = *state_name;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}

/***********************************************************************
 *      NtQuerySecurityAttributesToken   (NTDLL.@)
 */
NTSTATUS WINAPI NtQuerySecurityAttributesToken( HANDLE token, const UNICODE_STRING *attributes,
                                                 ULONG count, void *buffer, ULONG length,
                                                 ULONG *return_length )
{
    ULONG i;

    TRACE( "(%p %p %lu %p %lu %p)\n", token, attributes, count, buffer, length,
           return_length );
    for (i = 0; i < count; ++i)
        TRACE( "attribute[%lu] %s\n", i, debugstr_us(attributes + i) );

    /* Wine currently synthesizes the package-token attribute set as a
     * single block.  Returning that complete set also satisfies callers
     * querying named members; selective packing can be added when a caller
     * depends on the response containing only the requested names. */
    return NtQueryInformationToken( token, TokenSecurityAttributes, buffer, length,
                                    return_length );
}

typedef NTSTATUS (WINAPI *WNF_USER_CALLBACK)( ULONGLONG state_name, ULONG change_stamp,
                                              const GUID *type_id, void *context,
                                              const void *buffer, ULONG buffer_size );

struct wnf_subscription
{
    ULONGLONG magic;
    ULONGLONG state_name;
    ULONG change_stamp;
    ULONG serialization_group;
    ULONG flags;
    WNF_USER_CALLBACK callback;
    void *callback_context;
    GUID type_id;
    BOOL has_type_id;
};

/***********************************************************************
 *      NtUpdateWnfStateData   (NTDLL.@)
 */
NTSTATUS WINAPI NtUpdateWnfStateData( const ULONGLONG *state_name, const void *buffer,
                                      ULONG length, const GUID *type_id,
                                      const void *explicit_scope, ULONG matching_change_stamp,
                                      ULONG check_stamp )
{
    NTSTATUS status;

    TRACE( "(%p %#I64x %p %lu %s %p %lu %lu)\n", state_name,
           state_name ? *state_name : 0, buffer, length, debugstr_guid(type_id),
           explicit_scope, matching_change_stamp, check_stamp );

    if (!state_name || !*state_name || (!buffer && length) || check_stamp > 1)
        return STATUS_INVALID_PARAMETER;
    if (explicit_scope && (((*state_name ^ 0x41c64e6da3bc0074ULL) >> 6) & 0xf) != 1)
        return STATUS_INVALID_PARAMETER;

    SERVER_START_REQ( update_wnf_state_data )
    {
        req->state_name = *state_name;
        req->matching_stamp = matching_change_stamp;
        req->check_stamp = check_stamp;
        req->explicit_scope = !!explicit_scope;
        req->session_id = explicit_scope ? *(const ULONG *)explicit_scope : 0;
        wine_server_add_data( req, buffer, length );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}

/***********************************************************************
 *      RtlPublishWnfStateData   (NTDLL.@)
 */
NTSTATUS WINAPI RtlPublishWnfStateData( ULONGLONG state_name, const GUID *type_id,
                                        const void *buffer, ULONG length,
                                        const void *explicit_scope )
{
    return NtUpdateWnfStateData( &state_name, buffer, length, type_id,
                                 explicit_scope, 0, FALSE );
}

/***********************************************************************
 *      NtQueryWnfStateData   (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryWnfStateData( const ULONGLONG *state_name, const GUID *type_id,
                                     const void *explicit_scope, ULONG *change_stamp,
                                     void *buffer, ULONG *buffer_size )
{
    unsigned char state_data[4096];
    ULONG capacity, size = 0, stamp = 0;
    NTSTATUS status;

    TRACE( "(%p %s %p %p %p %p)\n", state_name, debugstr_guid(type_id), explicit_scope,
           change_stamp, buffer, buffer_size );

    if (!state_name || !buffer_size) return STATUS_INVALID_PARAMETER;
    if (explicit_scope && (((*state_name ^ 0x41c64e6da3bc0074ULL) >> 6) & 0xf) != 1)
        return STATUS_INVALID_PARAMETER;
    capacity = *buffer_size;

    SERVER_START_REQ( query_wnf_state_data )
    {
        req->state_name = *state_name;
        req->explicit_scope = !!explicit_scope;
        req->session_id = explicit_scope ? *(const ULONG *)explicit_scope : 0;
        wine_server_set_reply( req, state_data, sizeof(state_data) );
        status = wine_server_call( req );
        if (!status)
        {
            stamp = reply->change_stamp;
            size = reply->total;
        }
    }
    SERVER_END_REQ;
    if (status) return status;

    if (change_stamp) *change_stamp = stamp;
    *buffer_size = size;
    if (capacity < size) return STATUS_BUFFER_TOO_SMALL;
    if (size && !buffer) return STATUS_ACCESS_VIOLATION;
    if (size) memcpy( buffer, state_data, size );
    return STATUS_SUCCESS;
}

/***********************************************************************
 *      RtlQueryWnfStateData   (NTDLL.@)
 */
NTSTATUS WINAPI RtlQueryWnfStateData( ULONG *change_stamp, ULONGLONG state_name,
                                      WNF_USER_CALLBACK callback, void *callback_context,
                                      const GUID *type_id )
{
    ULONGLONG empty_data[2] = {0};
    ULONG stamp, size = sizeof(empty_data);
    NTSTATUS status;

    TRACE( "(%p %#I64x %p %p %s)\n", change_stamp, state_name, callback,
           callback_context, debugstr_guid(type_id) );

    /* An encoded WNF name has version one in the low nibble after XOR with
     * the WNF state-name key, hence an encoded low nibble of five. */
    if (!change_stamp || !callback || (state_name & 0xf) != 5)
        return STATUS_INVALID_PARAMETER;

    stamp = *change_stamp;
    status = NtQueryWnfStateData( &state_name, type_id, NULL, &stamp,
                                  empty_data, &size );
    if (status == STATUS_OBJECT_NAME_NOT_FOUND)
    {
        /* Windows invokes the callback with a non-NULL, zero-filled buffer
         * even when a permanent state currently has no payload. */
        stamp = 0;
        size = 0;
        status = STATUS_SUCCESS;
    }
    if (status) return status;

    *change_stamp = stamp;
    return callback( state_name, stamp, type_id, callback_context,
                     empty_data, size );
}

/***********************************************************************
 *      RtlQueryWnfMetaNotification   (NTDLL.@)
 */
NTSTATUS WINAPI RtlQueryWnfMetaNotification( ULONG *value, ULONG info_class,
                                              ULONGLONG state_name,
                                              const void *explicit_scope )
{
    ULONG size = 0;
    NTSTATUS status;

    TRACE( "(%p %lu %#I64x %p)\n", value, info_class, state_name, explicit_scope );

    if (!value) return STATUS_ACCESS_VIOLATION;
    if ((state_name & 0xf) != 5 || info_class > 2 || explicit_scope)
        return STATUS_INVALID_PARAMETER;

    status = NtQueryWnfStateData( &state_name, NULL, NULL, NULL, NULL, &size );
    if (status == STATUS_OBJECT_NAME_NOT_FOUND && !info_class)
    {
        *value = FALSE;
        return STATUS_SUCCESS;
    }
    if (status != STATUS_SUCCESS && status != STATUS_BUFFER_TOO_SMALL) return status;

    switch (info_class)
    {
    case 0: /* WnfInfoStateNameExist */
        *value = TRUE;
        break;
    case 1: /* WnfInfoSubscribersPresent */
        /* The current WNF partition does not deliver subscriptions. */
        *value = FALSE;
        break;
    case 2: /* WnfInfoIsQuiescent */
        /* With no delivery engine there can be no outstanding delivery. */
        *value = TRUE;
        break;
    }
    return STATUS_SUCCESS;
}

/***********************************************************************
 *      RtlSubscribeWnfStateChangeNotification   (NTDLL.@)
 */
NTSTATUS WINAPI RtlSubscribeWnfStateChangeNotification( void **subscription, ULONGLONG state_name,
                                                         ULONG change_stamp, WNF_USER_CALLBACK callback,
                                                         void *callback_context, const GUID *type_id,
                                                         ULONG serialization_group, ULONG flags )
{
    struct wnf_subscription *entry;

    TRACE( "(%p %#I64x %lu %p %p %s %lu %#lx)\n", subscription, state_name, change_stamp,
           callback, callback_context, debugstr_guid(type_id), serialization_group, flags );

    if (!subscription || !callback) return STATUS_INVALID_PARAMETER;
    *subscription = NULL;

    if (!(entry = RtlAllocateHeap( GetProcessHeap(), 0, sizeof(*entry) ))) return STATUS_NO_MEMORY;
    entry->magic = WNF_SUBSCRIPTION_MAGIC;
    entry->state_name = state_name;
    entry->change_stamp = change_stamp;
    entry->serialization_group = serialization_group;
    entry->flags = flags;
    entry->callback = callback;
    entry->callback_context = callback_context;
    entry->has_type_id = !!type_id;
    if (type_id) entry->type_id = *type_id;
    *subscription = entry;
    return STATUS_SUCCESS;
}

static NTSTATUS unsubscribe_wnf_state_change( void *subscription )
{
    struct wnf_subscription *entry = subscription;

    TRACE( "(%p)\n", subscription );

    if (!entry || !RtlValidateHeap( GetProcessHeap(), 0, entry ) ||
        entry->magic != WNF_SUBSCRIPTION_MAGIC)
        return STATUS_INVALID_HANDLE;

    entry->magic = 0;
    if (!RtlFreeHeap( GetProcessHeap(), 0, entry )) return STATUS_UNSUCCESSFUL;
    return STATUS_SUCCESS;
}

/***********************************************************************
 *      RtlUnsubscribeWnfStateChangeNotification   (NTDLL.@)
 */
NTSTATUS WINAPI RtlUnsubscribeWnfStateChangeNotification( void *subscription )
{
    return unsubscribe_wnf_state_change( subscription );
}

/***********************************************************************
 *      RtlUnsubscribeWnfNotificationWaitForCompletion   (NTDLL.@)
 */
NTSTATUS WINAPI RtlUnsubscribeWnfNotificationWaitForCompletion( void *subscription )
{
    return unsubscribe_wnf_state_change( subscription );
}

LPCSTR debugstr_us( const UNICODE_STRING *us )
{
    if (!us) return "<null>";
    return debugstr_wn(us->Buffer, us->Length / sizeof(WCHAR));
}

static int __cdecl compare_wrapper(void *ctx, const void *e1, const void *e2)
{
    int (__cdecl *compare)( const void *, const void * ) = ctx;
    return compare( e1, e2 );
}

static inline void swap(char *l, char *r, size_t size)
{
    char tmp;

    while(size--) {
        tmp = *l;
        *l++ = *r;
        *r++ = tmp;
    }
}

static void small_sort(void *base, size_t nmemb, size_t size,
        int (CDECL *compar)(void *, const void *, const void *), void *context)
{
    size_t e, i;
    char *max, *p;

    for(e=nmemb; e>1; e--) {
        max = base;
        for(i=1; i<e; i++) {
            p = (char*)base + i*size;
            if(compar(context, p, max) > 0)
                max = p;
        }

        if(p != max)
            swap(p, max, size);
    }
}

static void quick_sort(void *base, size_t nmemb, size_t size,
        int (CDECL *compar)(void *, const void *, const void *), void *context)
{
    size_t stack_lo[8*sizeof(size_t)], stack_hi[8*sizeof(size_t)];
    size_t beg, end, lo, hi, med;
    int stack_pos;

    stack_pos = 0;
    stack_lo[stack_pos] = 0;
    stack_hi[stack_pos] = nmemb-1;

#define X(i) ((char*)base+size*(i))
    while(stack_pos >= 0) {
        beg = stack_lo[stack_pos];
        end = stack_hi[stack_pos--];

        if(end-beg < 8) {
            small_sort(X(beg), end-beg+1, size, compar, context);
            continue;
        }

        lo = beg;
        hi = end;
        med = lo + (hi-lo+1)/2;
        if(compar(context, X(lo), X(med)) > 0)
            swap(X(lo), X(med), size);
        if(compar(context, X(lo), X(hi)) > 0)
            swap(X(lo), X(hi), size);
        if(compar(context, X(med), X(hi)) > 0)
            swap(X(med), X(hi), size);

        lo++;
        hi--;
        while(1) {
            while(lo <= hi) {
                if(lo!=med && compar(context, X(lo), X(med))>0)
                    break;
                lo++;
            }

            while(med != hi) {
                if(compar(context, X(hi), X(med)) <= 0)
                    break;
                hi--;
            }

            if(hi < lo)
                break;

            swap(X(lo), X(hi), size);
            if(hi == med)
                med = lo;
            lo++;
            hi--;
        }

        while(hi > beg) {
            if(hi!=med && compar(context, X(hi), X(med))!=0)
                break;
            hi--;
        }

        if(hi-beg >= end-lo) {
            stack_lo[++stack_pos] = beg;
            stack_hi[stack_pos] = hi;
            stack_lo[++stack_pos] = lo;
            stack_hi[stack_pos] = end;
        }else {
            stack_lo[++stack_pos] = lo;
            stack_hi[stack_pos] = end;
            stack_lo[++stack_pos] = beg;
            stack_hi[stack_pos] = hi;
        }
    }
#undef X
}


/*********************************************************************
 *                  qsort_s   (NTDLL.@)
 */
void __cdecl qsort_s( void *base, size_t nmemb, size_t size,
                      int (__cdecl *compar)(void *, const void *, const void *), void *context )
{
    const size_t total_size = nmemb * size;

    if (!base && nmemb) return;
    if (!size) return;
    if (!compar) return;
    if (total_size / size != nmemb) return;
    if (nmemb < 2) return;
    quick_sort( base, nmemb, size, compar, context );
}


/*********************************************************************
 *                  qsort   (NTDLL.@)
 */
void __cdecl qsort( void *base, size_t nmemb, size_t size,
                    int (__cdecl *compar)(const void *, const void *) )
{
    qsort_s( base, nmemb, size, compare_wrapper, compar );
}


/*********************************************************************
 *                  bsearch_s   (NTDLL.@)
 */
void * __cdecl bsearch_s( const void *key, const void *base, size_t nmemb, size_t size,
                          int (__cdecl *compare)(void *, const void *, const void *), void *ctx )
{
    ssize_t min = 0;
    ssize_t max = nmemb - 1;

    if (!size) return NULL;
    if (!compare) return NULL;

    while (min <= max)
    {
        ssize_t cursor = min + (max - min) / 2;
        int ret = compare(ctx, key,(const char *)base+(cursor*size));
        if (!ret)
            return (char*)base+(cursor*size);
        if (ret < 0)
            max = cursor - 1;
        else
            min = cursor + 1;
    }
    return NULL;
}


/*********************************************************************
 *                  bsearch   (NTDLL.@)
 */
void * __cdecl bsearch( const void *key, const void *base, size_t nmemb,
                        size_t size, int (__cdecl *compar)(const void *, const void *) )
{
    return bsearch_s( key, base, nmemb, size, compare_wrapper, compar );
}



/*********************************************************************
 *                  _lfind   (NTDLL.@)
 */
void * __cdecl _lfind( const void *key, const void *base, unsigned int *nmemb,
                       size_t size, int(__cdecl *compar)(const void *, const void *) )
{
    size_t i, n = *nmemb;

    for (i=0;i<n;i++)
        if (!compar(key,(char*)base+(size*i)))
            return (char*)base+(size*i);
    return NULL;
}

/******************************************************************************
 *                  WinSqmEndSession   (NTDLL.@)
 */
NTSTATUS WINAPI WinSqmEndSession(HANDLE session)
{
    FIXME("(%p): stub\n", session);
    return STATUS_NOT_IMPLEMENTED;
}

/*********************************************************************
 *          WinSqmIncrementDWORD (NTDLL.@)
 */
void WINAPI WinSqmIncrementDWORD(DWORD unk1, DWORD unk2, DWORD unk3)
{
    FIXME("(%ld, %ld, %ld): stub\n", unk1, unk2, unk3);
}

/*********************************************************************
 *                  WinSqmIsOptedIn   (NTDLL.@)
 */
BOOL WINAPI WinSqmIsOptedIn(void)
{
    FIXME("(): stub\n");
    return FALSE;
}

/******************************************************************************
 *                  WinSqmStartSession   (NTDLL.@)
 */
HANDLE WINAPI WinSqmStartSession(GUID *sessionguid, DWORD sessionid, DWORD unknown1)
{
    FIXME("(%p, 0x%lx, 0x%lx): stub\n", sessionguid, sessionid, unknown1);
    return INVALID_HANDLE_VALUE;
}

/***********************************************************************
 *          WinSqmSetDWORD (NTDLL.@)
 */
void WINAPI WinSqmSetDWORD(HANDLE session, DWORD datapoint_id, DWORD datapoint_value)
{
    FIXME("(%p, %ld, %ld): stub\n", session, datapoint_id, datapoint_value);
}

/******************************************************************************
 *          WinSqmSetIfMaxDWORD (NTDLL.@)
 */
void WINAPI WinSqmSetIfMaxDWORD(DWORD unk1, DWORD unk2, DWORD unk3)
{
    FIXME("(0x%lx, 0x%lx, 0x%lx): stub\n", unk1, unk2, unk3);
}

/***********************************************************************
 *          WinSqmSetString (NTDLL.@)
 */
void WINAPI WinSqmSetString(HANDLE session, DWORD datapoint_id, const WCHAR *value, DWORD length)
{
    FIXME("(%p, %lu, %s, %lu): stub\n", session, datapoint_id, debugstr_w(value), length);
}

/******************************************************************************
 *                  EtwEventActivityIdControl (NTDLL.@)
 */
ULONG WINAPI EtwEventActivityIdControl(ULONG code, GUID *guid)
{
    static int once;

    if (!once++) FIXME("0x%lx, %p: stub\n", code, guid);
    return ERROR_SUCCESS;
}

/******************************************************************************
 *                  EtwEventProviderEnabled (NTDLL.@)
 */
BOOLEAN WINAPI EtwEventProviderEnabled( REGHANDLE handle, UCHAR level, ULONGLONG keyword )
{
    WARN("%s, %u, %s: stub\n", wine_dbgstr_longlong(handle), level, wine_dbgstr_longlong(keyword));
    return FALSE;
}

/******************************************************************************
 *                  EtwEventRegister (NTDLL.@)
 */
ULONG WINAPI EtwEventRegister( LPCGUID provider, PENABLECALLBACK callback, PVOID context,
                PREGHANDLE handle )
{
    WARN("(%s, %p, %p, %p) stub.\n", debugstr_guid(provider), callback, context, handle);

    if (!handle) return ERROR_INVALID_PARAMETER;

    *handle = 0xdeadbeef;
    return ERROR_SUCCESS;
}

/******************************************************************************
 *                  EtwEventUnregister (NTDLL.@)
 */
ULONG WINAPI EtwEventUnregister( REGHANDLE handle )
{
    WARN("(%s) stub.\n", wine_dbgstr_longlong(handle));
    return ERROR_SUCCESS;
}

/*********************************************************************
 *                  EtwEventSetInformation   (NTDLL.@)
 */
ULONG WINAPI EtwEventSetInformation( REGHANDLE handle, EVENT_INFO_CLASS class, void *info,
                                     ULONG length )
{
    FIXME("(%s, %u, %p, %lu) stub\n", wine_dbgstr_longlong(handle), class, info, length);
    return ERROR_SUCCESS;
}

/******************************************************************************
 *                  EtwEventWriteString   (NTDLL.@)
 */
ULONG WINAPI EtwEventWriteString( REGHANDLE handle, UCHAR level, ULONGLONG keyword, PCWSTR string )
{
    FIXME("%s, %u, %s, %s: stub\n", wine_dbgstr_longlong(handle), level,
          wine_dbgstr_longlong(keyword), debugstr_w(string));
    return ERROR_SUCCESS;
}

/******************************************************************************
 *                  EtwEventWriteTransfer   (NTDLL.@)
 */
ULONG WINAPI EtwEventWriteTransfer( REGHANDLE handle, PCEVENT_DESCRIPTOR descriptor, LPCGUID activity,
                                    LPCGUID related, ULONG count, PEVENT_DATA_DESCRIPTOR data )
{
    FIXME("%s, %p, %s, %s, %lu, %p: stub\n", wine_dbgstr_longlong(handle), descriptor,
          debugstr_guid(activity), debugstr_guid(related), count, data);
    return ERROR_SUCCESS;
}

/******************************************************************************
 *                  EtwRegisterTraceGuidsW (NTDLL.@)
 *
 * Register an event trace provider and the event trace classes that it uses
 * to generate events.
 *
 * PARAMS
 *  RequestAddress     [I]   ControlCallback function
 *  RequestContext     [I]   Optional provider-defined context
 *  ControlGuid        [I]   GUID of the registering provider
 *  GuidCount          [I]   Number of elements in the TraceGuidReg array
 *  TraceGuidReg       [I/O] Array of TRACE_GUID_REGISTRATION structures
 *  MofImagePath       [I]   not supported, set to NULL
 *  MofResourceName    [I]   not supported, set to NULL
 *  RegistrationHandle [O]   Provider's registration handle
 *
 * RETURNS
 *  Success: ERROR_SUCCESS
 *  Failure: System error code
 */
ULONG WINAPI EtwRegisterTraceGuidsW( WMIDPREQUEST RequestAddress,
                void *RequestContext, const GUID *ControlGuid, ULONG GuidCount,
                TRACE_GUID_REGISTRATION *TraceGuidReg, const WCHAR *MofImagePath,
                const WCHAR *MofResourceName, TRACEHANDLE *RegistrationHandle )
{
    WARN("(%p, %p, %s, %lu, %p, %s, %s, %p): stub\n", RequestAddress, RequestContext,
          debugstr_guid(ControlGuid), GuidCount, TraceGuidReg, debugstr_w(MofImagePath),
          debugstr_w(MofResourceName), RegistrationHandle);

    if (TraceGuidReg)
    {
        ULONG i;
        for (i = 0; i < GuidCount; i++)
        {
            FIXME("  register trace class %s\n", debugstr_guid(TraceGuidReg[i].Guid));
            TraceGuidReg[i].RegHandle = (HANDLE)0xdeadbeef;
        }
    }
    *RegistrationHandle = (TRACEHANDLE)0xdeadbeef;
    return ERROR_SUCCESS;
}

/******************************************************************************
 *                  EtwRegisterTraceGuidsA (NTDLL.@)
 */
ULONG WINAPI EtwRegisterTraceGuidsA( WMIDPREQUEST RequestAddress,
                void *RequestContext, const GUID *ControlGuid, ULONG GuidCount,
                TRACE_GUID_REGISTRATION *TraceGuidReg, const char *MofImagePath,
                const char *MofResourceName, TRACEHANDLE *RegistrationHandle )
{
    WARN("(%p, %p, %s, %lu, %p, %s, %s, %p): stub\n", RequestAddress, RequestContext,
          debugstr_guid(ControlGuid), GuidCount, TraceGuidReg, debugstr_a(MofImagePath),
          debugstr_a(MofResourceName), RegistrationHandle);
    return ERROR_SUCCESS;
}

/******************************************************************************
 *                  EtwUnregisterTraceGuids (NTDLL.@)
 */
ULONG WINAPI EtwUnregisterTraceGuids( TRACEHANDLE RegistrationHandle )
{
    if (!RegistrationHandle)
         return ERROR_INVALID_PARAMETER;

    WARN("%s: stub\n", wine_dbgstr_longlong(RegistrationHandle));
    return ERROR_SUCCESS;
}

/******************************************************************************
 *                  EtwEventEnabled (NTDLL.@)
 */
BOOLEAN WINAPI EtwEventEnabled( REGHANDLE handle, const EVENT_DESCRIPTOR *descriptor )
{
    WARN("(%s, %p): stub\n", wine_dbgstr_longlong(handle), descriptor);
    return FALSE;
}

/******************************************************************************
 *                  EtwEventWrite (NTDLL.@)
 */
ULONG WINAPI EtwEventWrite( REGHANDLE handle, const EVENT_DESCRIPTOR *descriptor, ULONG count,
    EVENT_DATA_DESCRIPTOR *data )
{
    FIXME("(%s, %p, %lu, %p): stub\n", wine_dbgstr_longlong(handle), descriptor, count, data);
    return ERROR_SUCCESS;
}

/******************************************************************************
 *                  EtwEventWriteEx (NTDLL.@)
 */
ULONG WINAPI EtwEventWriteEx( REGHANDLE handle, const EVENT_DESCRIPTOR *descriptor, ULONG64 filter,
                            ULONG flags, const GUID *activity_id, const GUID *related_activity_id,
                            ULONG data_count, EVENT_DATA_DESCRIPTOR *data )
{
    FIXME( "(%s, %p, %#I64x, %lu, %p, %p, %lu, %p): stub\n", wine_dbgstr_longlong(handle), descriptor, filter,
           flags, activity_id, related_activity_id, data_count, data );
    return ERROR_SUCCESS;
}

/******************************************************************************
 *                  EtwGetTraceEnableFlags (NTDLL.@)
 */
ULONG WINAPI EtwGetTraceEnableFlags( TRACEHANDLE handle )
{
    FIXME("(%s) stub\n", wine_dbgstr_longlong(handle));
    return 0;
}

/******************************************************************************
 *                  EtwGetTraceEnableLevel (NTDLL.@)
 */
UCHAR WINAPI EtwGetTraceEnableLevel( TRACEHANDLE handle )
{
    FIXME("(%s) stub\n", wine_dbgstr_longlong(handle));
    return TRACE_LEVEL_VERBOSE;
}

/******************************************************************************
 *                  EtwGetTraceLoggerHandle (NTDLL.@)
 */
TRACEHANDLE WINAPI EtwGetTraceLoggerHandle( PVOID buf )
{
    FIXME("(%p) stub\n", buf);
    return INVALID_PROCESSTRACE_HANDLE;
}

/******************************************************************************
 *                  EtwLogTraceEvent (NTDLL.@)
 */
ULONG WINAPI EtwLogTraceEvent( TRACEHANDLE SessionHandle, PEVENT_TRACE_HEADER EventTrace )
{
    FIXME("%s %p\n", wine_dbgstr_longlong(SessionHandle), EventTrace);
    return ERROR_CALL_NOT_IMPLEMENTED;
}

/******************************************************************************
 *                  EtwTraceMessageVa (NTDLL.@)
 */
ULONG WINAPI EtwTraceMessageVa( TRACEHANDLE handle, ULONG flags, LPGUID guid, USHORT number,
                                va_list args )
{
    FIXME("(%s %lx %s %d) : stub\n", wine_dbgstr_longlong(handle), flags, debugstr_guid(guid), number);
    return ERROR_SUCCESS;
}

/******************************************************************************
 *                  EtwTraceMessage (NTDLL.@)
 */
ULONG WINAPIV EtwTraceMessage( TRACEHANDLE handle, ULONG flags, LPGUID guid, /*USHORT*/ ULONG number, ... )
{
    va_list valist;
    ULONG ret;

    va_start( valist, number );
    ret = EtwTraceMessageVa( handle, flags, guid, number, valist );
    va_end( valist );
    return ret;
}
