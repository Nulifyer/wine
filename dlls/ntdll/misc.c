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

#include "ntstatus.h"
#include "wine/debug.h"
#include "ntdll_misc.h"
#include "wmistr.h"
#include "evntrace.h"
#include "evntprov.h"

WINE_DEFAULT_DEBUG_CHANNEL(ntdll);

static BOOL linuxnt_debug_etw_payloads(void)
{
    static const WCHAR name[] = L"LINUXNT_DEBUG_ETW_PAYLOADS";
    WCHAR value[2];
    SIZE_T length;

    return !RtlQueryEnvironmentVariable( NULL, name, ARRAY_SIZE(name) - 1,
                                         value, ARRAY_SIZE(value), &length );
}

/******************************************************************************
 *                  RtlQueryResourcePolicy (NTDLL.@)
 */
NTSTATUS WINAPI RtlQueryResourcePolicy( ULONG resource, ULONG flags, ULONG *policy, SIZE_T size )
{
    if (!policy || flags || size != sizeof(*policy)) return STATUS_INVALID_PARAMETER;

    switch (resource)
    {
    case 2: /* disk speed */
        /* Windows uses this value when the volume speed query is unsupported. */
        *policy = 10;
        return STATUS_SUCCESS;
    case 0: /* physical memory */
    case 1: /* disk space */
    case 3: /* disk write constraint */
        FIXME( "resource %lu is not implemented\n", resource );
        return STATUS_NOT_IMPLEMENTED;
    default:
        return STATUS_INVALID_INFO_CLASS;
    }
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
 *          WinSqmAddToStream (NTDLL.@)
 */
void WINAPI WinSqmAddToStream(HANDLE session, DWORD datapoint_id, DWORD count, const void *data)
{
    TRACE("(%p, %lu, %lu, %p)\n", session, datapoint_id, count, data);
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

/******************************************************************************
 *                  EvtIntReportEventAndSourceAsync (NTDLL.@)
 */
BOOL WINAPI EvtIntReportEventAndSourceAsync( HANDLE handle, const WCHAR *source, USHORT type,
                                             USHORT category, ULONG event_id, PSID user_sid,
                                             USHORT string_count, ULONG data_size,
                                             const WCHAR **strings, void *data )
{
    unsigned int i;

    FIXME("(%p, %s, %u, %u, %#lx, %p, %u, %lu, %p, %p): stub\n", handle,
          debugstr_w(source), type, category, event_id, user_sid, string_count, data_size,
          strings, data);
    if (source && !wcsicmp(source, L"Service Control Manager") &&
        event_id >= 0xc0001b50 && event_id <= 0xc0001b7f && strings)
        for (i = 0; i < string_count; ++i)
            FIXME("event %lu string[%u]=%s\n", event_id & 0xffff, i, debugstr_w(strings[i]));

    RtlSetLastWin32Error( ERROR_SUCCESS );
    return TRUE;
}

/******************************************************************************
 *                  EtwpGetCpuSpeed (NTDLL.@)
 */
NTSTATUS WINAPI EtwpGetCpuSpeed( ULONG *speed )
{
    static const WCHAR path[] =
        L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";
    struct
    {
        KEY_VALUE_PARTIAL_INFORMATION info;
        ULONG extra;
    } buffer;
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING key_name, value_name;
    ULONG size, value;
    HANDLE key;
    NTSTATUS status;

    RtlInitUnicodeString( &key_name, path );
    InitializeObjectAttributes( &attr, &key_name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    if ((status = NtOpenKey( &key, KEY_QUERY_VALUE, &attr ))) return status;

    RtlInitUnicodeString( &value_name, L"~MHz" );
    status = NtQueryValueKey( key, &value_name, KeyValuePartialInformation,
                              &buffer, sizeof(buffer), &size );
    NtClose( key );
    if (status) return status;
    if (buffer.info.Type != REG_DWORD || buffer.info.DataLength != sizeof(value))
        return STATUS_OBJECT_TYPE_MISMATCH;

    memcpy( &value, buffer.info.Data, sizeof(value) );
    *speed = value;
    return STATUS_SUCCESS;
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
    static const GUID broker_infrastructure_provider =
        {0x63b6c2d2, 0x0440, 0x44de, {0xa6,0x74,0xaa,0x51,0xa2,0x51,0xb1,0x23}};
    static const GUID app_extensions_provider =
        {0xe86ff119, 0x662f, 0x5d23, {0x69,0xb1,0x0e,0xd8,0xbf,0x76,0x86,0xc2}};
    WARN("(%s, %p, %p, %p) stub.\n", debugstr_guid(provider), callback, context, handle);

    if (linuxnt_debug_etw_payloads())
        ERR("linuxnt-etw-register provider=%s callback=%p context=%p target=%u\n",
            debugstr_guid(provider), callback, context,
            provider && IsEqualGUID( provider, &app_extensions_provider ));

    if (!provider || !handle) return ERROR_INVALID_PARAMETER;

    *handle = 0xdeadbeef;
    if (provider && callback &&
        (IsEqualGUID( provider, &broker_infrastructure_provider ) ||
         (linuxnt_debug_etw_payloads() && IsEqualGUID( provider, &app_extensions_provider ))))
    {
        if (linuxnt_debug_etw_payloads())
            ERR("linuxnt-etw-enable provider=%s level=5 keywords=%s\n",
                debugstr_guid(provider), wine_dbgstr_longlong(~0ULL));
        callback( provider, 1, 5, ~0ULL, 0, NULL, context );
    }
    return ERROR_SUCCESS;
}

/******************************************************************************
 *                  EtwRegisterSecurityProvider (NTDLL.@)
 */
ULONG WINAPI EtwRegisterSecurityProvider(void)
{
    WARN("stub.\n");
    return ERROR_SUCCESS;
}

struct etw_private_logger_request
{
    ULONG type;
    ULONG size;
    ULONGLONG reserved[6];
    ULONGLONG context[2];
    WNODE_HEADER logger;
};

/******************************************************************************
 *                  EtwProcessPrivateLoggerRequest (NTDLL.@)
 */
ULONG WINAPI EtwProcessPrivateLoggerRequest( struct etw_private_logger_request *request )
{
    static const GUID system_trace_control_guid =
        {0x9e814aad, 0x3204, 0x11d2, {0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39}};
    ULONGLONG context[2];
    ULONG error;

    if (request->size < 0xf8) return ERROR_WMI_INSTANCE_NOT_FOUND;

    if (request->logger.BufferSize < 0xb0 ||
        !(request->logger.Flags & WNODE_FLAG_TRACED_GUID) ||
        memcmp( &request->logger.Guid, &system_trace_control_guid, sizeof(GUID) ))
        error = ERROR_INVALID_DATA;
    else if (request->logger.ProviderId < 1 || request->logger.ProviderId > 6)
        error = ERROR_INVALID_PARAMETER;
    else
        error = ERROR_WMI_INSTANCE_NOT_FOUND;

    FIXME( "request %lu size %lu logger size %lu flags %#lx, returning %lu\n",
           request->logger.ProviderId, request->size, request->logger.BufferSize,
           request->logger.Flags, error );

    memcpy( context, request->context, sizeof(context) );
    memset( request->reserved, 0, 4 * sizeof(ULONGLONG) );
    request->reserved[3] = HandleToUlong( NtCurrentTeb()->ClientId.UniqueProcess );
    memcpy( request->reserved + 4, context, sizeof(context) );
    memset( request->context, 0, sizeof(request->context) );
    request->size = 0x4c;
    request->type = 4;
    request->logger.BufferSize = error;
    return ERROR_SUCCESS;
}

/******************************************************************************
 *                  EtwWriteUMSecurityEvent (NTDLL.@)
 */
ULONG WINAPI EtwWriteUMSecurityEvent( PCEVENT_DESCRIPTOR descriptor, USHORT event_property,
                                      ULONG count, PEVENT_DATA_DESCRIPTOR data )
{
    FIXME("(%p, %u, %lu, %p) stub.\n", descriptor, event_property, count, data);

    if (!descriptor) return ERROR_INVALID_PARAMETER;
    return ERROR_SUCCESS;
}

/******************************************************************************
 *                  EtwEventUnregister (NTDLL.@)
 */
ULONG WINAPI EtwEventUnregister( REGHANDLE handle )
{
    WARN("(%s) stub.\n", wine_dbgstr_longlong(handle));
    if (!handle) return ERROR_INVALID_HANDLE;
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
    if (!handle) return ERROR_INVALID_HANDLE;
    if (!string) return ERROR_INVALID_PARAMETER;
    return ERROR_SUCCESS;
}

static ULONG etw_write_event( REGHANDLE handle, const GUID *provider,
                              const EVENT_DESCRIPTOR *descriptor, const GUID *activity,
                              const GUID *related, ULONG count, const EVENT_DATA_DESCRIPTOR *data )
{
    ULONG i;

    if ((!handle && !provider) || !descriptor || (count && !data)) return ERROR_INVALID_PARAMETER;
    if (!linuxnt_debug_etw_payloads()) return ERROR_SUCCESS;

    ERR("linuxnt-etw handle=%s provider=%s event=%u level=%u keyword=%s activity=%s related=%s count=%lu\n",
        wine_dbgstr_longlong(handle), debugstr_guid(provider), descriptor->Id, descriptor->Level,
        wine_dbgstr_longlong(descriptor->Keyword), debugstr_guid(activity), debugstr_guid(related), count);
    for (i = 0; i < count; i++)
    {
        ULONGLONG value = 0;
        ULONG size = min( data[i].Size, (ULONG)sizeof(value) );
        ULONG preview = min( data[i].Size, 128u );

        if (data[i].Ptr && size) memcpy( &value, (const void *)(ULONG_PTR)data[i].Ptr, size );
        ERR("linuxnt-etw data[%lu] size=%lu value=%s bytes=%s wide=%s\n", i, data[i].Size,
            wine_dbgstr_longlong(value),
            data[i].Ptr ? debugstr_an((const char *)(ULONG_PTR)data[i].Ptr, preview) : "(null)",
            data[i].Ptr && !(preview % sizeof(WCHAR))
                ? debugstr_wn((const WCHAR *)(ULONG_PTR)data[i].Ptr, preview / sizeof(WCHAR)) : "(odd)");
    }
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
    if (!handle) return ERROR_INVALID_HANDLE;
    return etw_write_event( handle, NULL, descriptor, activity, related, count, data );
}

/******************************************************************************
 *                  EtwEventWriteNoRegistration   (NTDLL.@)
 */
ULONG WINAPI EtwEventWriteNoRegistration( LPCGUID provider, PCEVENT_DESCRIPTOR descriptor,
                                          ULONG count, PEVENT_DATA_DESCRIPTOR data )
{
    TRACE("%s, %p, %lu, %p\n", debugstr_guid(provider), descriptor, count, data);
    return etw_write_event( 0, provider, descriptor, NULL, NULL, count, data );
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
    if (!handle) return ERROR_INVALID_HANDLE;
    return etw_write_event( handle, NULL, descriptor, NULL, NULL, count, data );
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
    if (!handle) return ERROR_INVALID_HANDLE;
    return etw_write_event( handle, NULL, descriptor, activity_id, related_activity_id,
                            data_count, data );
}

/******************************************************************************
 *                  EtwEventWriteFull (NTDLL.@)
 */
ULONG WINAPI EtwEventWriteFull( REGHANDLE handle, const EVENT_DESCRIPTOR *descriptor, USHORT event_property,
                                const GUID *activity_id, const GUID *related_activity_id,
                                ULONG data_count, EVENT_DATA_DESCRIPTOR *data )
{
    return EtwEventWriteEx( handle, descriptor, 0, event_property, activity_id, related_activity_id,
                            data_count, data );
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
