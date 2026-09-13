/*
 * Copyright (C) 2023 Mohamad Al-Jaf
 * Copyright (C) 2025 Vibhav Pant
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

#include "cfgmgr32_private.h"
#include "plugplay.h"
#include "wine/exception.h"
#include "wine/list.h"

WINE_DEFAULT_DEBUG_CHANNEL(setupapi);

static const char *debugstr_CM_NOTIFY_FILTER( const CM_NOTIFY_FILTER *filter )
{
    if (!filter) return "(null)";
    switch (filter->FilterType)
    {
    case CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE:
        return wine_dbg_sprintf( "{%#lx %lx CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE %lu {{%s}}}", filter->cbSize,
                                 filter->Flags, filter->Reserved, debugstr_guid( &filter->u.DeviceInterface.ClassGuid ) );
    case CM_NOTIFY_FILTER_TYPE_DEVICEHANDLE:
        return wine_dbg_sprintf( "{%#lx %lx CM_NOTIFY_FILTER_TYPE_DEVICEHANDLE %lu {{%p}}}", filter->cbSize,
                                 filter->Flags, filter->Reserved, filter->u.DeviceHandle.hTarget );
    case CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE:
        return wine_dbg_sprintf( "{%#lx %lx CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE %lu {{%s}}}", filter->cbSize,
                                 filter->Flags, filter->Reserved, debugstr_w( filter->u.DeviceInstance.InstanceId ) );
    default:
        return wine_dbg_sprintf( "{%#lx %lx (unknown FilterType %d) %lu}", filter->cbSize, filter->Flags,
                                 filter->FilterType, filter->Reserved );
    }
}

#define CM_NOTIFY_CONTEXT_MAGIC 0xbeef4dad

struct cm_notify_context
{
    DWORD magic;
    struct list entry;
    WCHAR *path;
    void *user_data;
    PCM_NOTIFY_CALLBACK callback;
    CM_NOTIFY_FILTER filter;
};

struct cm_notify_event
{
    struct list entry;
    HCMNOTIFICATION notify;
    void *user_data;
    PCM_NOTIFY_CALLBACK callback;
    CM_NOTIFY_ACTION action;
    DWORD size;
    CM_NOTIFY_EVENT_DATA data[];
};

static HANDLE notify_thread;
static struct list notify_list = LIST_INIT(notify_list);
static SRWLOCK notify_lock = SRWLOCK_INIT;

void __RPC_FAR *__RPC_USER MIDL_user_allocate( SIZE_T len )
{
    return malloc( len );
}

void __RPC_USER MIDL_user_free( void __RPC_FAR *ptr )
{
    free( ptr );
}

static LONG WINAPI rpc_filter( EXCEPTION_POINTERS *eptr )
{
    return I_RpcExceptionFilter( eptr->ExceptionRecord->ExceptionCode );
}

static BOOL notification_filter_matches( const struct cm_notify_context *ctx, DEV_BROADCAST_HDR *header,
                                         const WCHAR *event_path )
{
    switch (ctx->filter.FilterType)
    {
    case CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE:
    {
        DEV_BROADCAST_DEVICEINTERFACE_W *iface = (DEV_BROADCAST_DEVICEINTERFACE_W *)header;

        if (header->dbch_devicetype != DBT_DEVTYP_DEVICEINTERFACE) return FALSE;
        if (ctx->filter.Flags & CM_NOTIFY_FILTER_FLAG_ALL_INTERFACE_CLASSES) return TRUE;
        return IsEqualGUID( &ctx->filter.u.DeviceInterface.ClassGuid, &iface->dbcc_classguid );
    }
    case CM_NOTIFY_FILTER_TYPE_DEVICEHANDLE:
        return header->dbch_devicetype == DBT_DEVTYP_HANDLE && event_path && ctx->path &&
               !wcscmp( ctx->path, event_path );
    default:
        return FALSE;
    }
}

static struct cm_notify_event *create_notify_event( const struct cm_notify_context *ctx, DWORD flags,
                                                    DEV_BROADCAST_HDR *header )
{
    struct cm_notify_event *event;
    CM_NOTIFY_EVENT_DATA *event_data;
    CM_NOTIFY_ACTION action;
    DWORD size;

    TRACE( "(%p, %#lx, %p)\n", ctx, flags, header );

    switch (flags)
    {
    case DBT_DEVICEARRIVAL:
        action = CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL;
        break;
    case DBT_DEVICEREMOVECOMPLETE:
        FIXME( "CM_NOTIFY_ACTION_DEVICEREMOVECOMPLETE not implemented\n" );
        action = CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL;
        break;
    case DBT_CUSTOMEVENT:
        action = CM_NOTIFY_ACTION_DEVICECUSTOMEVENT;
        break;
    default:
        FIXME( "Unexpected flags value: %#lx\n", flags );
        return NULL;
    }

    switch (header->dbch_devicetype)
    {
    case DBT_DEVTYP_DEVICEINTERFACE:
    {
        const DEV_BROADCAST_DEVICEINTERFACE_W *iface = (DEV_BROADCAST_DEVICEINTERFACE_W *)header;
        UINT data_size = wcslen( iface->dbcc_name ) + 1;

        size = offsetof( CM_NOTIFY_EVENT_DATA, u.DeviceInterface.SymbolicLink[data_size] );
        if (!(event = calloc( 1, sizeof(*event) + size ))) return NULL;
        event_data = event->data;

        event_data->FilterType = CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE;
        event_data->u.DeviceInterface.ClassGuid = iface->dbcc_classguid;
        memcpy( event_data->u.DeviceInterface.SymbolicLink, iface->dbcc_name, data_size * sizeof(WCHAR) );
        break;
    }
    case DBT_DEVTYP_HANDLE:
    {
        const DEV_BROADCAST_HANDLE *handle = (DEV_BROADCAST_HANDLE *)header;
        UINT data_size = handle->dbch_size - 2 * sizeof(WCHAR) - offsetof( DEV_BROADCAST_HANDLE, dbch_data );

        size = offsetof( CM_NOTIFY_EVENT_DATA, u.DeviceHandle.Data[data_size] );
        if (!(event = calloc( 1, sizeof(*event) + size ))) return NULL;
        event_data = event->data;

        event_data->FilterType = CM_NOTIFY_FILTER_TYPE_DEVICEHANDLE;
        event_data->u.DeviceHandle.EventGuid = handle->dbch_eventguid;
        event_data->u.DeviceHandle.NameOffset = handle->dbch_nameoffset;
        event_data->u.DeviceHandle.DataSize = data_size;
        memcpy( event_data->u.DeviceHandle.Data, handle->dbch_data, data_size );
        break;
    }
    default:
        FIXME( "Unexpected devicetype value: %#lx\n", header->dbch_devicetype );
        return NULL;
    }

    event->notify = (HCMNOTIFICATION)ctx;
    event->user_data = ctx->user_data;
    event->callback = ctx->callback;
    event->action = action;
    event->size = size;
    return event;
}

static DWORD WINAPI notify_proc( void *arg )
{
    WCHAR endpoint[] = L"\\pipe\\wine_plugplay";
    WCHAR protseq[] = L"ncacn_np";
    struct cm_notify_context *ctx;
    struct cm_notify_event *event, *next;
    struct list events = LIST_INIT(events);
    plugplay_rpc_handle handle = NULL;
    RPC_WSTR binding_str;
    unsigned int size;
    HANDLE thread;
    DWORD code, err;
    WCHAR *path;
    BYTE *buf;

    if ((err = RpcStringBindingComposeW( NULL, protseq, NULL, endpoint, NULL, &binding_str ))) goto done;
    err = RpcBindingFromStringBindingW( binding_str, &plugplay_binding_handle );
    RpcStringFreeW( &binding_str );
    if (err) goto done;

    __TRY
    {
        handle = plugplay_register_listener();
    }
    __EXCEPT(rpc_filter)
    {
        err = GetExceptionCode();
    }
    __ENDTRY

    if (!handle) goto done;

    for (;;)
    {
        path = NULL;
        buf = NULL;
        __TRY
        {
            code = plugplay_get_event( handle, &path, &buf, &size );
            err = ERROR_SUCCESS;
        }
        __EXCEPT(rpc_filter)
        {
            err = GetExceptionCode();
        }
        __ENDTRY

        if (err) break;

        AcquireSRWLockShared( &notify_lock );
        LIST_FOR_EACH_ENTRY( ctx, &notify_list, struct cm_notify_context, entry )
        {
            if (!notification_filter_matches( ctx, (DEV_BROADCAST_HDR *)buf, path )) continue;
            if (!(event = create_notify_event( ctx, code, (DEV_BROADCAST_HDR *)buf ))) continue;
            list_add_tail( &events, &event->entry );
        }
        ReleaseSRWLockShared( &notify_lock );

        LIST_FOR_EACH_ENTRY_SAFE( event, next, &events, struct cm_notify_event, entry )
        {
            event->callback( event->notify, event->user_data, event->action, event->data, event->size );
            list_remove( &event->entry );
            free( event );
        }

        MIDL_user_free( buf );
        MIDL_user_free( path );
    }

    __TRY
    {
        if (handle) plugplay_unregister_listener( handle );
    }
    __EXCEPT(rpc_filter)
    {
    }
    __ENDTRY

done:
    if (plugplay_binding_handle) RpcBindingFree( &plugplay_binding_handle );
    AcquireSRWLockExclusive( &notify_lock );
    thread = notify_thread;
    notify_thread = NULL;
    ReleaseSRWLockExclusive( &notify_lock );
    if (thread) CloseHandle( thread );
    return err;
}

static CONFIGRET create_notify_context( const CM_NOTIFY_FILTER *filter, const WCHAR *service_name,
                                        HCMNOTIFICATION *notify_handle, PCM_NOTIFY_CALLBACK callback,
                                        void *user_data )
{
    struct cm_notify_context *ctx;
    static const GUID GUID_NULL;

    switch (filter->FilterType)
    {
    case CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE:
        if (filter->Flags & CM_NOTIFY_FILTER_FLAG_ALL_INTERFACE_CLASSES)
        {
            if (!IsEqualGUID( &filter->u.DeviceInterface.ClassGuid, &GUID_NULL )) return CR_INVALID_DATA;
        }
        break;
    case CM_NOTIFY_FILTER_TYPE_DEVICEHANDLE:
        break;
    case CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE:
        FIXME( "CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE is not supported!\n" );
        return CR_CALL_NOT_IMPLEMENTED;
    default:
        return CR_INVALID_DATA;
    }

    if (!(ctx = calloc( 1, sizeof(*ctx) ))) return CR_OUT_OF_MEMORY;

    ctx->magic = CM_NOTIFY_CONTEXT_MAGIC;
    ctx->user_data = user_data;
    ctx->callback = callback;
    ctx->filter = *filter;

    if (filter->FilterType == CM_NOTIFY_FILTER_TYPE_DEVICEHANDLE)
    {
        WCHAR buffer[sizeof(OBJECT_NAME_INFORMATION) + MAX_PATH * sizeof(WCHAR)];
        OBJECT_NAME_INFORMATION *info = (OBJECT_NAME_INFORMATION *)buffer;
        ULONG dummy;

        if (NtQueryObject( filter->u.DeviceHandle.hTarget, ObjectNameInformation, buffer, sizeof(buffer), &dummy ) ||
            !(ctx->path = calloc( 1, info->Name.Length + sizeof(WCHAR) )))
        {
            free( ctx );
            return CR_OUT_OF_MEMORY;
        }
        memcpy( ctx->path, info->Name.Buffer, info->Name.Length );
    }

    if (service_name) TRACE( "ignoring service name %s\n", debugstr_w(service_name) );

    AcquireSRWLockExclusive( &notify_lock );
    list_add_tail( &notify_list, &ctx->entry );
    if (!notify_thread) notify_thread = CreateThread( NULL, 0, notify_proc, NULL, 0, NULL );
    ReleaseSRWLockExclusive( &notify_lock );

    *notify_handle = ctx;
    return CR_SUCCESS;
}

/***********************************************************************
 *           CMP_Register_Notification (cfgmgr32.@)
 */
CONFIGRET WINAPI CMP_Register_Notification( CM_NOTIFY_FILTER *filter, void *context,
                                            PCM_NOTIFY_CALLBACK callback, const WCHAR *service_name,
                                            HCMNOTIFICATION *notify_context )
{
    TRACE( "(%s %p %p %s %p)\n", debugstr_CM_NOTIFY_FILTER( filter ), context, callback,
           debugstr_w(service_name), notify_context );

    if (!notify_context) return CR_FAILURE;
    if (!filter || !callback || filter->cbSize != sizeof(*filter)) return CR_INVALID_DATA;

    return create_notify_context( filter, service_name, notify_context, callback, context );
}

/***********************************************************************
 *           CM_Register_Notification (cfgmgr32.@)
 */
CONFIGRET WINAPI CM_Register_Notification( CM_NOTIFY_FILTER *filter, void *context,
                                           PCM_NOTIFY_CALLBACK callback, HCMNOTIFICATION *notify_context )
{
    return CMP_Register_Notification( filter, context, callback, NULL, notify_context );
}

/***********************************************************************
 *           CM_Unregister_Notification (cfgmgr32.@)
 */
CONFIGRET WINAPI CM_Unregister_Notification( HCMNOTIFICATION notify )
{
    struct cm_notify_context *ctx = notify;
    CONFIGRET ret = CR_SUCCESS;

    TRACE( "(%p)\n", notify );

    if (!notify) return CR_INVALID_DATA;

    __TRY
    {
        if (ctx->magic == CM_NOTIFY_CONTEXT_MAGIC)
        {
            AcquireSRWLockExclusive( &notify_lock );
            list_remove( &ctx->entry );
            ReleaseSRWLockExclusive( &notify_lock );
            free( ctx->path );
            free( ctx );
        }
        else
            ret = CR_INVALID_DATA;
    }
    __EXCEPT_PAGE_FAULT
    {
        ret = CR_FAILURE;
    }
    __ENDTRY

    return ret;
}
