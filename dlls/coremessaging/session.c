/* Core UI session and message-loop implementation
 *
 * Copyright (C) 2026 Nulifyer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "private.h"

#include "winuser.h"

WINE_DEFAULT_DEBUG_CHANNEL(messaging);

static const GUID IID_IMessageSession =
    {0x4b2edab9, 0x129b, 0x4733, {0xbe, 0x15, 0x35, 0x68, 0x53, 0xd5, 0x5a, 0xce}};
static const GUID IID_IMessageLoopExtensions =
    {0x50e345cc, 0xb3ef, 0x4d17, {0x89, 0x2d, 0xd4, 0xcf, 0xbf, 0xcc, 0x69, 0xfe}};
static const GUID IID_IMessageConversation =
    {0xf5da6aa2, 0xbfb5, 0x4292, {0xb8, 0x2b, 0xc9, 0x65, 0xe1, 0x8e, 0xa8, 0x21}};
static const GUID IID_IExportDispatcherQueueInterop =
    {0x8dfddcea, 0x6bfd, 0x4323, {0x83, 0x2b, 0x17, 0x58, 0x1d, 0x16, 0xac, 0x52}};

struct message_session;

struct message_session_iface
{
    const struct message_session_vtbl *lpVtbl;
};

struct message_loop_extensions_iface
{
    const struct message_loop_extensions_vtbl *lpVtbl;
};

struct dispatcher_queue_interop_iface
{
    const struct dispatcher_queue_interop_vtbl *lpVtbl;
};

struct message_conversation_iface;

typedef HRESULT (WINAPI *dispatch_callback)( void *, BOOL, FILETIME * );
typedef HRESULT (WINAPI *simple_callback)( void * );
typedef HRESULT (WINAPI *wait_callback)( void *, ULONG, void * );
typedef HRESULT (__cdecl *conversation_item_callback)( void *, UINT, UINT, const void * );

struct message_session_vtbl
{
    HRESULT (WINAPI *QueryInterface)( struct message_session_iface *, REFIID, void ** );
    ULONG (WINAPI *AddRef)( struct message_session_iface * );
    ULONG (WINAPI *Release)( struct message_session_iface * );
    HRESULT (WINAPI *GetMessageRegistrar)( struct message_session_iface *, IUnknown ** );
    HRESULT (WINAPI *GetMessageInfo)( struct message_session_iface *, IUnknown ** );
    HRESULT (WINAPI *GetMessageLoopExtensions)( struct message_session_iface *, struct message_loop_extensions_iface ** );
    HRESULT (WINAPI *CreatePort)( struct message_session_iface *, void *, const WCHAR *, UINT, void *, UINT, IUnknown ** );
    HRESULT (WINAPI *CreateNamedPort)( struct message_session_iface *, void *, const WCHAR *, IUnknown ** );
    HRESULT (WINAPI *CreateAnonymousPort)( struct message_session_iface *, void *, IUnknown ** );
    HRESULT (WINAPI *OpenScopedPort)( struct message_session_iface *, const WCHAR *, UINT, IUnknown ** );
    HRESULT (WINAPI *OpenPort)( struct message_session_iface *, const WCHAR *, IUnknown ** );
    HRESULT (WINAPI *CreateGroup)( struct message_session_iface *, simple_callback, void *, simple_callback, void *, IUnknown ** );
    HRESULT (WINAPI *CreateGroupWithSignal)( struct message_session_iface *, void *, void *, simple_callback, void *, IUnknown ** );
    HRESULT (WINAPI *CreateEndpointOnPort)( struct message_session_iface *, void *, void *, IUnknown *, UINT64 * );
    HRESULT (WINAPI *CreateEndpoint)( struct message_session_iface *, void *, void *, UINT64 * );
    HRESULT (WINAPI *OpenEndpoint)( struct message_session_iface *, void *, UINT64 * );
    HRESULT (WINAPI *GetMessagePort)( struct message_session_iface *, UINT64, IUnknown ** );
    HRESULT (WINAPI *GetEndpointInfo)( struct message_session_iface *, UINT64, void * );
    HRESULT (WINAPI *CreateTimer)( struct message_session_iface *, simple_callback, void *, IUnknown ** );
    HRESULT (WINAPI *DeferInvoke)( struct message_session_iface *, simple_callback, void *, UINT );
    HRESULT (WINAPI *CloseEndpoint)( struct message_session_iface *, UINT64 );
    HRESULT (WINAPI *CloseEndpointEx)( struct message_session_iface *, UINT64, UINT );
    HRESULT (WINAPI *Send)( struct message_session_iface *, UINT64, void *, UINT );
    HRESULT (WINAPI *SendWithPriority)( struct message_session_iface *, UINT64, UINT, void *, UINT );
    HRESULT (WINAPI *SendInPlace)( struct message_session_iface *, UINT64, UINT, void ** );
    HRESULT (WINAPI *SendInPlaceWithPriority)( struct message_session_iface *, UINT64, UINT, UINT, void ** );
    HRESULT (WINAPI *CancelSendInPlace)( struct message_session_iface *, void * );
    HRESULT (WINAPI *DisconnectClient)( struct message_session_iface *, UINT, UINT );
    HRESULT (WINAPI *DisconnectClientEx)( struct message_session_iface *, const GUID *, UINT, UINT );
    HRESULT (WINAPI *Run)( struct message_session_iface * );
    HRESULT (WINAPI *Exit)( struct message_session_iface * );
    HRESULT (WINAPI *RegisterDispatchCallback)( struct message_session_iface *, dispatch_callback, void * );
    HRESULT (WINAPI *RegisterDispatchCallbackEx)( struct message_session_iface *, dispatch_callback, void *, int );
    HRESULT (WINAPI *UnregisterDispatchCallback)( struct message_session_iface *, dispatch_callback, void * );
    HRESULT (WINAPI *RegisterWait)( struct message_session_iface *, HANDLE, wait_callback, void * );
    HRESULT (WINAPI *UnregisterWait)( struct message_session_iface *, HANDLE );
    HRESULT (WINAPI *GetPrivateInterface)( struct message_session_iface *, IUnknown ** );
    HRESULT (WINAPI *JoinConversationAsServer)( struct message_session_iface *, const WCHAR *, IUnknown *, GUID, UINT, UINT, UINT, IUnknown *, UINT *, struct message_conversation_iface ** );
    HRESULT (WINAPI *JoinConversationAsNamedServer)( struct message_session_iface *, const WCHAR *, const WCHAR *, IUnknown *, GUID, UINT, UINT, UINT, IUnknown *, UINT *, struct message_conversation_iface ** );
    HRESULT (WINAPI *JoinConversationAsClient)( struct message_session_iface *, const WCHAR *, GUID, IUnknown *, UINT *, struct message_conversation_iface ** );
    HRESULT (WINAPI *JoinConversationAsManualClient)( struct message_session_iface *, const WCHAR *, GUID, IUnknown *, UINT *, UINT64 *, struct message_conversation_iface ** );
    HRESULT (WINAPI *ImpersonateCaller)( struct message_session_iface * );
    HRESULT (WINAPI *JoinConversationAsEagerClient)( struct message_session_iface *, const WCHAR *, const WCHAR *, GUID, UINT, UINT, UINT, IUnknown *, UINT *, UINT64 *, struct message_conversation_iface ** );
};

struct message_conversation_iface
{
    const struct message_conversation_vtbl *lpVtbl;
};

struct message_conversation_vtbl
{
    HRESULT (WINAPI *QueryInterface)( struct message_conversation_iface *, REFIID, void ** );
    ULONG (WINAPI *AddRef)( struct message_conversation_iface * );
    ULONG (WINAPI *Release)( struct message_conversation_iface * );
    HRESULT (WINAPI *AllocateItemForPeer)( struct message_conversation_iface *, UINT, void *, UINT * );
    HRESULT (WINAPI *AllocateItemForPeerWithCustomID)( struct message_conversation_iface *, UINT, UINT, void * );
    HRESULT (WINAPI *SetItemData)( struct message_conversation_iface *, UINT, UINT, void * );
    HRESULT (WINAPI *GetItem)( struct message_conversation_iface *, UINT, UINT, void ** );
    HRESULT (WINAPI *RemoveItem)( struct message_conversation_iface *, UINT, UINT, BOOL, void ** );
    HRESULT (WINAPI *Send)( struct message_conversation_iface *, UINT, UINT, void *, UINT );
    HRESULT (WINAPI *EnumerateItems)( struct message_conversation_iface *, UINT, BOOL, BOOL, void *, void * );
    HRESULT (WINAPI *FlushItemDeletion)( struct message_conversation_iface *, UINT, UINT, BOOL );
    HRESULT (WINAPI *SetDeferMessageDelivery)( struct message_conversation_iface *, BOOL );
    HRESULT (WINAPI *GetDeferMessageDelivery)( struct message_conversation_iface *, BOOL * );
    HRESULT (WINAPI *ReserveCustomIDSpace)( struct message_conversation_iface *, UINT, void * );
    HRESULT (WINAPI *SkipBatchingAndFlushNow)( struct message_conversation_iface *, UINT );
};

struct message_loop_extensions_vtbl
{
    HRESULT (WINAPI *QueryInterface)( struct message_loop_extensions_iface *, REFIID, void ** );
    ULONG (WINAPI *AddRef)( struct message_loop_extensions_iface * );
    ULONG (WINAPI *Release)( struct message_loop_extensions_iface * );
    HRESULT (WINAPI *Run)( struct message_loop_extensions_iface *, UINT );
    HRESULT (WINAPI *Wait)( struct message_loop_extensions_iface *, UINT, HANDLE *, UINT, UINT, DWORD * );
    HRESULT (WINAPI *GetIsRunning)( struct message_loop_extensions_iface *, BOOL * );
    HRESULT (WINAPI *UrgentExit)( struct message_loop_extensions_iface * );
    HRESULT (WINAPI *AssumeLoopActive)( struct message_loop_extensions_iface * );
    HRESULT (WINAPI *RegisterThreadCompletionHandler)( struct message_loop_extensions_iface *, HANDLE, void *, void * );
    HRESULT (WINAPI *DeferWindowMessageDispatch)( struct message_loop_extensions_iface *, BOOL );
    HRESULT (WINAPI *GetThreadID)( struct message_loop_extensions_iface *, DWORD * );
    HRESULT (WINAPI *GetDispatchingThreadID)( struct message_loop_extensions_iface *, DWORD * );
    HRESULT (WINAPI *PauseNewDispatch)( struct message_loop_extensions_iface * );
    HRESULT (WINAPI *ResumeDispatch)( struct message_loop_extensions_iface * );
    HRESULT (WINAPI *WaitOnOutboundMessages)( struct message_loop_extensions_iface *, UINT, BOOL * );
    HRESULT (WINAPI *RunUntilExitFlag)( struct message_loop_extensions_iface *, UINT, const BOOL * );
    HRESULT (WINAPI *EnableNestedDispatch)( struct message_loop_extensions_iface * );
};

struct dispatcher_queue_interop_vtbl
{
    HRESULT (WINAPI *QueryInterface)( struct dispatcher_queue_interop_iface *, REFIID, void ** );
    ULONG (WINAPI *AddRef)( struct dispatcher_queue_interop_iface * );
    ULONG (WINAPI *Release)( struct dispatcher_queue_interop_iface * );
    HRESULT (WINAPI *SetDispatcherQueue)( struct dispatcher_queue_interop_iface *, IUnknown *, BOOL );
    HRESULT (WINAPI *GetDispatcherQueue)( struct dispatcher_queue_interop_iface *, IUnknown ** );
    HRESULT (WINAPI *TryDeferInvoke)( struct dispatcher_queue_interop_iface *, void *, void *, UINT, BOOL, BOOL * );
    HRESULT (WINAPI *Exit)( struct dispatcher_queue_interop_iface * );
};

struct message_session
{
    struct message_session_iface session_iface;
    struct message_loop_extensions_iface loop_iface;
    struct dispatcher_queue_interop_iface queue_interop_iface;
    LONG ref;
    DWORD thread_id;
    IUnknown *dispatcher_queue;
    BOOL running;
    BOOL exit_requested;
    BOOL dispatch_paused;
    BOOL nested_dispatch;
};

struct message_conversation
{
    struct message_conversation_iface iface;
    LONG ref;
    IUnknown *host;
    UINT item_id;
    UINT64 conversation_id;
    BOOL defer_delivery;
    SRWLOCK lock;
    struct conversation_item *items;
    UINT next_item_id;
};

struct conversation_item
{
    struct conversation_item *next;
    UINT owner;
    UINT id;
    void *data;
};

static INIT_ONCE session_init_once = INIT_ONCE_STATIC_INIT;
static DWORD session_fls = FLS_OUT_OF_INDEXES;
static SRWLOCK free_session_lock = SRWLOCK_INIT;
static struct message_session *free_session;
static LONG next_conversation_item_id;
static LONG64 next_conversation_id;

static HRESULT WINAPI loop_Run( struct message_loop_extensions_iface *iface, UINT mode );
static HRESULT WINAPI loop_UrgentExit( struct message_loop_extensions_iface *iface );

static inline struct message_session *impl_from_session( struct message_session_iface *iface )
{
    return CONTAINING_RECORD( iface, struct message_session, session_iface );
}

static inline struct message_session *impl_from_loop( struct message_loop_extensions_iface *iface )
{
    return CONTAINING_RECORD( iface, struct message_session, loop_iface );
}

static inline struct message_session *impl_from_queue_interop( struct dispatcher_queue_interop_iface *iface )
{
    return CONTAINING_RECORD( iface, struct message_session, queue_interop_iface );
}

static ULONG message_session_addref( struct message_session *session )
{
    return InterlockedIncrement( &session->ref );
}

static ULONG message_session_release( struct message_session *session )
{
    ULONG ref = InterlockedDecrement( &session->ref );

    if (!ref)
    {
        if (session->dispatcher_queue) IUnknown_Release( session->dispatcher_queue );
        free( session );
    }
    return ref;
}

static void WINAPI session_fls_callback( void *value )
{
    if (value) message_session_release( value );
}

static BOOL CALLBACK session_global_init( INIT_ONCE *once, void *param, void **context )
{
    return (session_fls = FlsAlloc( session_fls_callback )) != FLS_OUT_OF_INDEXES;
}

static HRESULT session_query_interface( struct message_session *session, REFIID iid, void **out )
{
    if (!out) return E_POINTER;
    *out = NULL;

    if (IsEqualGUID( iid, &IID_IUnknown ) || IsEqualGUID( iid, &IID_IMessageSession ))
        *out = &session->session_iface;
    else if (IsEqualGUID( iid, &IID_IMessageLoopExtensions ))
        *out = &session->loop_iface;
    else if (IsEqualGUID( iid, &IID_IExportDispatcherQueueInterop ))
        *out = &session->queue_interop_iface;
    else
        return E_NOINTERFACE;

    message_session_addref( session );
    return S_OK;
}

static HRESULT WINAPI session_QueryInterface( struct message_session_iface *iface, REFIID iid, void **out )
{
    return session_query_interface( impl_from_session( iface ), iid, out );
}

static ULONG WINAPI session_AddRef( struct message_session_iface *iface )
{
    return message_session_addref( impl_from_session( iface ) );
}

static ULONG WINAPI session_Release( struct message_session_iface *iface )
{
    return message_session_release( impl_from_session( iface ) );
}

static HRESULT WINAPI session_GetMessageRegistrar( struct message_session_iface *iface, IUnknown **out )
{
    if (!out) return E_POINTER;
    *out = NULL;
    FIXME( "iface %p, registrar %p not implemented.\n", iface, out );
    return E_NOTIMPL;
}

static HRESULT WINAPI session_GetMessageInfo( struct message_session_iface *iface, IUnknown **out )
{
    if (!out) return E_POINTER;
    *out = NULL;
    FIXME( "iface %p, message info %p not implemented.\n", iface, out );
    return E_NOTIMPL;
}

static HRESULT WINAPI session_GetMessageLoopExtensions( struct message_session_iface *iface,
                                                         struct message_loop_extensions_iface **out )
{
    struct message_session *session = impl_from_session( iface );

    if (!out) return E_POINTER;
    message_session_addref( session );
    *out = &session->loop_iface;
    return S_OK;
}

static HRESULT clear_unknown( IUnknown **out )
{
    if (!out) return E_POINTER;
    *out = NULL;
    return E_NOTIMPL;
}

static HRESULT WINAPI session_CreatePort( struct message_session_iface *iface, void *callback, const WCHAR *name,
                                          UINT kind, void *security, UINT flags, IUnknown **out )
{
    FIXME( "iface %p, callback %p, name %s, kind %u, security %p, flags %#x not implemented.\n",
           iface, callback, debugstr_w(name), kind, security, flags );
    return clear_unknown( out );
}

static HRESULT WINAPI session_CreateNamedPort( struct message_session_iface *iface, void *callback,
                                               const WCHAR *name, IUnknown **out )
{
    FIXME( "iface %p, callback %p, name %s not implemented.\n", iface, callback, debugstr_w(name) );
    return clear_unknown( out );
}

static HRESULT WINAPI session_CreateAnonymousPort( struct message_session_iface *iface, void *callback, IUnknown **out )
{
    FIXME( "iface %p, callback %p not implemented.\n", iface, callback );
    return clear_unknown( out );
}

static HRESULT WINAPI session_OpenScopedPort( struct message_session_iface *iface, const WCHAR *name,
                                              UINT scope, IUnknown **out )
{
    FIXME( "iface %p, name %s, scope %u not implemented.\n", iface, debugstr_w(name), scope );
    return clear_unknown( out );
}

static HRESULT WINAPI session_OpenPort( struct message_session_iface *iface, const WCHAR *name, IUnknown **out )
{
    FIXME( "iface %p, name %s not implemented.\n", iface, debugstr_w(name) );
    return clear_unknown( out );
}

static HRESULT WINAPI session_CreateGroup( struct message_session_iface *iface, simple_callback callback,
                                           void *context, simple_callback cancel, void *cancel_context,
                                           IUnknown **out )
{
    FIXME( "iface %p, callback %p, context %p, cancel %p, cancel context %p not implemented.\n",
           iface, callback, context, cancel, cancel_context );
    return clear_unknown( out );
}

static HRESULT WINAPI session_CreateGroupWithSignal( struct message_session_iface *iface, void *callback,
                                                     void *context, simple_callback cancel, void *cancel_context,
                                                     IUnknown **out )
{
    FIXME( "iface %p, callback %p, context %p, cancel %p, cancel context %p not implemented.\n",
           iface, callback, context, cancel, cancel_context );
    return clear_unknown( out );
}

static HRESULT WINAPI session_CreateEndpointOnPort( struct message_session_iface *iface, void *callback,
                                                    void *context, IUnknown *port, UINT64 *endpoint )
{
    if (!endpoint) return E_POINTER;
    *endpoint = 0;
    FIXME( "iface %p, callback %p, context %p, port %p not implemented.\n", iface, callback, context, port );
    return E_NOTIMPL;
}

static HRESULT WINAPI session_CreateEndpoint( struct message_session_iface *iface, void *callback,
                                              void *context, UINT64 *endpoint )
{
    return session_CreateEndpointOnPort( iface, callback, context, NULL, endpoint );
}

static HRESULT WINAPI session_OpenEndpoint( struct message_session_iface *iface, void *routing, UINT64 *endpoint )
{
    if (!endpoint) return E_POINTER;
    *endpoint = 0;
    FIXME( "iface %p, routing %p not implemented.\n", iface, routing );
    return E_NOTIMPL;
}

static HRESULT WINAPI session_GetMessagePort( struct message_session_iface *iface, UINT64 endpoint, IUnknown **out )
{
    FIXME( "iface %p, endpoint %s not implemented.\n", iface, wine_dbgstr_longlong(endpoint) );
    return clear_unknown( out );
}

static HRESULT WINAPI session_GetEndpointInfo( struct message_session_iface *iface, UINT64 endpoint, void *routing )
{
    FIXME( "iface %p, endpoint %s, routing %p not implemented.\n", iface,
           wine_dbgstr_longlong(endpoint), routing );
    return routing ? E_NOTIMPL : E_POINTER;
}

static HRESULT WINAPI session_CreateTimer( struct message_session_iface *iface, simple_callback callback,
                                           void *context, IUnknown **out )
{
    FIXME( "iface %p, callback %p, context %p not implemented.\n", iface, callback, context );
    return clear_unknown( out );
}

static HRESULT WINAPI session_DeferInvoke( struct message_session_iface *iface, simple_callback callback,
                                           void *context, UINT priority )
{
    FIXME( "iface %p, callback %p, context %p, priority %u not implemented.\n",
           iface, callback, context, priority );
    return E_NOTIMPL;
}

static HRESULT WINAPI session_CloseEndpoint( struct message_session_iface *iface, UINT64 endpoint )
{
    FIXME( "iface %p, endpoint %s not implemented.\n", iface, wine_dbgstr_longlong(endpoint) );
    return E_NOTIMPL;
}

static HRESULT WINAPI session_CloseEndpointEx( struct message_session_iface *iface, UINT64 endpoint, UINT flags )
{
    FIXME( "iface %p, endpoint %s, flags %#x not implemented.\n", iface,
           wine_dbgstr_longlong(endpoint), flags );
    return E_NOTIMPL;
}

static HRESULT WINAPI session_Send( struct message_session_iface *iface, UINT64 endpoint, void *buffer, UINT size )
{
    FIXME( "iface %p, endpoint %s, buffer %p, size %u not implemented.\n", iface,
           wine_dbgstr_longlong(endpoint), buffer, size );
    return E_NOTIMPL;
}

static HRESULT WINAPI session_SendWithPriority( struct message_session_iface *iface, UINT64 endpoint,
                                                UINT priority, void *buffer, UINT size )
{
    FIXME( "iface %p, endpoint %s, priority %u, buffer %p, size %u not implemented.\n", iface,
           wine_dbgstr_longlong(endpoint), priority, buffer, size );
    return E_NOTIMPL;
}

static HRESULT WINAPI session_SendInPlace( struct message_session_iface *iface, UINT64 endpoint,
                                           UINT size, void **buffer )
{
    if (!buffer) return E_POINTER;
    *buffer = NULL;
    FIXME( "iface %p, endpoint %s, size %u not implemented.\n", iface,
           wine_dbgstr_longlong(endpoint), size );
    return E_NOTIMPL;
}

static HRESULT WINAPI session_SendInPlaceWithPriority( struct message_session_iface *iface, UINT64 endpoint,
                                                       UINT priority, UINT size, void **buffer )
{
    if (!buffer) return E_POINTER;
    *buffer = NULL;
    FIXME( "iface %p, endpoint %s, priority %u, size %u not implemented.\n", iface,
           wine_dbgstr_longlong(endpoint), priority, size );
    return E_NOTIMPL;
}

static HRESULT WINAPI session_CancelSendInPlace( struct message_session_iface *iface, void *buffer )
{
    FIXME( "iface %p, buffer %p not implemented.\n", iface, buffer );
    return E_NOTIMPL;
}

static HRESULT WINAPI session_DisconnectClient( struct message_session_iface *iface, UINT process_id, UINT flags )
{
    FIXME( "iface %p, process %u, flags %#x not implemented.\n", iface, process_id, flags );
    return E_NOTIMPL;
}

static HRESULT WINAPI session_DisconnectClientEx( struct message_session_iface *iface, const GUID *id,
                                                  UINT process_id, UINT flags )
{
    FIXME( "iface %p, id %s, process %u, flags %#x not implemented.\n", iface,
           debugstr_guid(id), process_id, flags );
    return E_NOTIMPL;
}

static HRESULT WINAPI session_Run( struct message_session_iface *iface )
{
    return loop_Run( &impl_from_session(iface)->loop_iface, 0 );
}

static HRESULT WINAPI session_Exit( struct message_session_iface *iface )
{
    return loop_UrgentExit( &impl_from_session(iface)->loop_iface );
}

static HRESULT WINAPI session_RegisterDispatchCallback( struct message_session_iface *iface,
                                                        dispatch_callback callback, void *context )
{
    FIXME( "iface %p, callback %p, context %p not implemented.\n", iface, callback, context );
    return E_NOTIMPL;
}

static HRESULT WINAPI session_RegisterDispatchCallbackEx( struct message_session_iface *iface,
                                                          dispatch_callback callback, void *context, int flags )
{
    FIXME( "iface %p, callback %p, context %p, flags %#x not implemented.\n", iface, callback, context, flags );
    return E_NOTIMPL;
}

static HRESULT WINAPI session_UnregisterDispatchCallback( struct message_session_iface *iface,
                                                          dispatch_callback callback, void *context )
{
    FIXME( "iface %p, callback %p, context %p not implemented.\n", iface, callback, context );
    return E_NOTIMPL;
}

static HRESULT WINAPI session_RegisterWait( struct message_session_iface *iface, HANDLE handle,
                                            wait_callback callback, void *context )
{
    FIXME( "iface %p, handle %p, callback %p, context %p not implemented.\n", iface, handle, callback, context );
    return E_NOTIMPL;
}

static HRESULT WINAPI session_UnregisterWait( struct message_session_iface *iface, HANDLE handle )
{
    FIXME( "iface %p, handle %p not implemented.\n", iface, handle );
    return E_NOTIMPL;
}

static HRESULT WINAPI session_GetPrivateInterface( struct message_session_iface *iface, IUnknown **out )
{
    FIXME( "iface %p not implemented.\n", iface );
    return clear_unknown( out );
}

static HRESULT clear_conversation( UINT *item_id, UINT64 *conversation_id,
                                   struct message_conversation_iface **out )
{
    if (item_id) *item_id = 0;
    if (conversation_id) *conversation_id = 0;
    if (!out) return E_POINTER;
    *out = NULL;
    return E_NOTIMPL;
}

static HRESULT WINAPI session_JoinConversationAsServer( struct message_session_iface *iface, const WCHAR *name,
                                                        IUnknown *port, GUID scope, UINT owner, UINT style,
                                                        UINT mode, IUnknown *host, UINT *item_id,
                                                        struct message_conversation_iface **out )
{
    FIXME( "iface %p, name %s, port %p, owner %u, style %u, mode %u, host %p not implemented.\n",
           iface, debugstr_w(name), port, owner, style, mode, host );
    return clear_conversation( item_id, NULL, out );
}

static HRESULT WINAPI session_JoinConversationAsNamedServer( struct message_session_iface *iface,
                                                             const WCHAR *name, const WCHAR *peer, IUnknown *port,
                                                             GUID scope, UINT owner, UINT style, UINT mode,
                                                             IUnknown *host, UINT *item_id,
                                                             struct message_conversation_iface **out )
{
    FIXME( "iface %p, name %s, peer %s, port %p, owner %u, style %u, mode %u, host %p not implemented.\n",
           iface, debugstr_w(name), debugstr_w(peer), port, owner, style, mode, host );
    return clear_conversation( item_id, NULL, out );
}

static HRESULT WINAPI session_JoinConversationAsClient( struct message_session_iface *iface, const WCHAR *name,
                                                        GUID scope, IUnknown *host, UINT *item_id,
                                                        struct message_conversation_iface **out )
{
    FIXME( "iface %p, name %s, host %p not implemented.\n", iface, debugstr_w(name), host );
    return clear_conversation( item_id, NULL, out );
}

static HRESULT WINAPI session_JoinConversationAsManualClient( struct message_session_iface *iface,
                                                              const WCHAR *name, GUID scope, IUnknown *host,
                                                              UINT *item_id, UINT64 *conversation_id,
                                                              struct message_conversation_iface **out )
{
    FIXME( "iface %p, name %s, host %p not implemented.\n", iface, debugstr_w(name), host );
    return clear_conversation( item_id, conversation_id, out );
}

static HRESULT WINAPI session_ImpersonateCaller( struct message_session_iface *iface )
{
    FIXME( "iface %p not implemented.\n", iface );
    return E_NOTIMPL;
}

static inline struct message_conversation *impl_from_conversation( struct message_conversation_iface *iface )
{
    return CONTAINING_RECORD( iface, struct message_conversation, iface );
}

static HRESULT WINAPI conversation_QueryInterface( struct message_conversation_iface *iface, REFIID iid, void **out )
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (!IsEqualGUID( iid, &IID_IUnknown ) && !IsEqualGUID( iid, &IID_IMessageConversation ))
        return E_NOINTERFACE;
    *out = iface;
    iface->lpVtbl->AddRef( iface );
    return S_OK;
}

static ULONG WINAPI conversation_AddRef( struct message_conversation_iface *iface )
{
    return InterlockedIncrement( &impl_from_conversation(iface)->ref );
}

static ULONG WINAPI conversation_Release( struct message_conversation_iface *iface )
{
    struct message_conversation *conversation = impl_from_conversation( iface );
    struct conversation_item *item, *next;
    ULONG ref = InterlockedDecrement( &conversation->ref );

    if (!ref)
    {
        for (item = conversation->items; item; item = next)
        {
            next = item->next;
            free( item );
        }
        if (conversation->host) IUnknown_Release( conversation->host );
        free( conversation );
    }
    return ref;
}

static struct conversation_item *conversation_find_item( struct message_conversation *conversation,
                                                         UINT owner, UINT item_id )
{
    struct conversation_item *item;

    for (item = conversation->items; item; item = item->next)
        if (item->owner == owner && item->id == item_id) return item;
    return NULL;
}

static HRESULT conversation_add_item( struct message_conversation *conversation, UINT owner,
                                      UINT item_id, void *data )
{
    struct conversation_item *item;

    if (!(item = malloc( sizeof(*item) ))) return E_OUTOFMEMORY;
    item->owner = owner;
    item->id = item_id;
    item->data = data;
    AcquireSRWLockExclusive( &conversation->lock );
    if (conversation_find_item( conversation, owner, item_id ))
    {
        ReleaseSRWLockExclusive( &conversation->lock );
        free( item );
        return HRESULT_FROM_WIN32( ERROR_ALREADY_EXISTS );
    }
    item->next = conversation->items;
    conversation->items = item;
    ReleaseSRWLockExclusive( &conversation->lock );
    return S_OK;
}

static HRESULT WINAPI conversation_AllocateItemForPeer( struct message_conversation_iface *iface, UINT peer,
                                                        void *data, UINT *item_id )
{
    struct message_conversation *conversation = impl_from_conversation( iface );
    UINT id;
    HRESULT hr;

    if (!item_id) return E_POINTER;
    *item_id = 0;
    if (!data) return E_POINTER;
    if (!peer || peer > 3) return E_INVALIDARG;
    do id = InterlockedIncrement( (LONG *)&conversation->next_item_id );
    while (!id || id == conversation->item_id);
    if (FAILED(hr = conversation_add_item( conversation, peer, id, data ))) return hr;
    *item_id = id;
    TRACE( "iface %p allocated item %u for peer %u, data %p.\n", iface, id, peer, data );
    return S_OK;
}

static HRESULT WINAPI conversation_AllocateItemForPeerWithCustomID( struct message_conversation_iface *iface,
                                                                    UINT peer, UINT item_id, void *data )
{
    if (!data) return E_POINTER;
    if (!peer || peer > 3 || !item_id || item_id > 0x3fffffff) return E_INVALIDARG;
    return conversation_add_item( impl_from_conversation(iface), peer, item_id, data );
}

static HRESULT WINAPI conversation_ReserveCustomIDSpace( struct message_conversation_iface *iface,
                                                         UINT count, void *reservation )
{
    struct message_conversation *conversation = impl_from_conversation( iface );
    UINT *range = reservation, first;

    if (!reservation) return E_POINTER;
    memset( reservation, 0, sizeof(UINT) * 4 );
    if (!count || count > 0x1fffff) return E_INVALIDARG;
    AcquireSRWLockExclusive( &conversation->lock );
    first = conversation->next_item_id + 1;
    if (!first || first > 0x3fffffff || count - 1 > 0x3fffffff - first)
    {
        ReleaseSRWLockExclusive( &conversation->lock );
        return HRESULT_FROM_WIN32( ERROR_NOT_ENOUGH_MEMORY );
    }
    conversation->next_item_id += count;
    ReleaseSRWLockExclusive( &conversation->lock );
    range[0] = first;
    range[1] = first + count - 1;
    range[2] = 0xc0000000;
    range[3] = 0;
    return S_OK;
}

static HRESULT WINAPI conversation_GetItem( struct message_conversation_iface *iface, UINT owner,
                                            UINT item_id, void **data )
{
    struct message_conversation *conversation = impl_from_conversation( iface );
    struct conversation_item *item;

    if (!data) return E_POINTER;
    *data = NULL;
    AcquireSRWLockShared( &conversation->lock );
    item = conversation_find_item( conversation, owner, item_id );
    if (item) *data = item->data;
    ReleaseSRWLockShared( &conversation->lock );
    return item ? S_OK : HRESULT_FROM_WIN32( ERROR_NOT_FOUND );
}

static HRESULT WINAPI conversation_SetItemData( struct message_conversation_iface *iface, UINT owner,
                                                UINT item_id, void *data )
{
    struct message_conversation *conversation = impl_from_conversation( iface );
    struct conversation_item *item;

    if (!data) return E_POINTER;
    AcquireSRWLockExclusive( &conversation->lock );
    item = conversation_find_item( conversation, owner, item_id );
    if (item) item->data = data;
    ReleaseSRWLockExclusive( &conversation->lock );
    return item ? S_OK : HRESULT_FROM_WIN32( ERROR_NOT_FOUND );
}

static HRESULT WINAPI conversation_Send( struct message_conversation_iface *iface, UINT owner, UINT item_id,
                                         void *buffer, UINT size )
{
    struct message_conversation *conversation = impl_from_conversation( iface );
    struct conversation_item *item;

    TRACE( "iface %p, owner %u, item %u, buffer %p, size %u.\n", iface, owner, item_id, buffer, size );
    if ((!buffer && size) || owner > 3) return E_INVALIDARG;
    AcquireSRWLockShared( &conversation->lock );
    item = conversation_find_item( conversation, owner, item_id );
    ReleaseSRWLockShared( &conversation->lock );
    return item ? S_OK : HRESULT_FROM_WIN32( ERROR_NOT_FOUND );
}

static HRESULT WINAPI conversation_RemoveItem( struct message_conversation_iface *iface, UINT owner,
                                               UINT item_id, BOOL flush, void **data )
{
    struct message_conversation *conversation = impl_from_conversation( iface );
    struct conversation_item **cursor, *item;

    if (!data) return E_POINTER;
    *data = NULL;
    AcquireSRWLockExclusive( &conversation->lock );
    for (cursor = &conversation->items; (item = *cursor); cursor = &item->next)
    {
        if (item->owner != owner || item->id != item_id) continue;
        *cursor = item->next;
        *data = item->data;
        break;
    }
    ReleaseSRWLockExclusive( &conversation->lock );
    if (!item) return HRESULT_FROM_WIN32( ERROR_NOT_FOUND );
    free( item );
    TRACE( "iface %p removed owner %u item %u, flush %d.\n", iface, owner, item_id, flush );
    return S_OK;
}

static HRESULT WINAPI conversation_EnumerateItems( struct message_conversation_iface *iface, UINT owner,
                                                   BOOL include_local, BOOL include_remote,
                                                   void *callback, void *context )
{
    struct message_conversation *conversation = impl_from_conversation( iface );
    struct conversation_item *item;
    struct item_snapshot { UINT owner, id; void *data; } *items = NULL;
    conversation_item_callback invoke = callback;
    UINT count = 0, i = 0;
    HRESULT hr = S_OK;

    if (!callback) return E_POINTER;
    if (!include_local && !include_remote) return E_INVALIDARG;
    AcquireSRWLockShared( &conversation->lock );
    for (item = conversation->items; item; item = item->next)
        if (!owner || item->owner == owner) count++;
    if (count && !(items = malloc( count * sizeof(*items) )))
    {
        ReleaseSRWLockShared( &conversation->lock );
        return E_OUTOFMEMORY;
    }
    for (item = conversation->items; item; item = item->next)
    {
        if (owner && item->owner != owner) continue;
        items[i].owner = item->owner;
        items[i].id = item->id;
        items[i++].data = item->data;
    }
    ReleaseSRWLockShared( &conversation->lock );
    for (i = 0; i < count && SUCCEEDED(hr); i++)
        hr = invoke( context, items[i].owner, items[i].id, items[i].data );
    free( items );
    return hr;
}

static HRESULT WINAPI conversation_FlushItemDeletion( struct message_conversation_iface *iface, UINT owner,
                                                      UINT item_id, BOOL flush )
{
    TRACE( "iface %p, owner %u, item %u, flush %d.\n", iface, owner, item_id, flush );
    return owner && item_id ? S_OK : E_INVALIDARG;
}

static HRESULT WINAPI conversation_SetDeferMessageDelivery( struct message_conversation_iface *iface, BOOL defer )
{
    impl_from_conversation(iface)->defer_delivery = defer;
    return S_OK;
}

static HRESULT WINAPI conversation_GetDeferMessageDelivery( struct message_conversation_iface *iface, BOOL *defer )
{
    if (!defer) return E_POINTER;
    *defer = impl_from_conversation(iface)->defer_delivery;
    return S_OK;
}

static HRESULT WINAPI conversation_SkipBatchingAndFlushNow( struct message_conversation_iface *iface, UINT flags )
{
    struct message_conversation *conversation = impl_from_conversation( iface );
    struct conversation_item *item;

    AcquireSRWLockShared( &conversation->lock );
    for (item = conversation->items; item; item = item->next)
        if (item->id == flags) break;
    ReleaseSRWLockShared( &conversation->lock );
    return item ? S_OK : HRESULT_FROM_WIN32( ERROR_NOT_FOUND );
}

static const struct message_conversation_vtbl message_conversation_vtbl =
{
    conversation_QueryInterface,
    conversation_AddRef,
    conversation_Release,
    conversation_AllocateItemForPeer,
    conversation_AllocateItemForPeerWithCustomID,
    conversation_SetItemData,
    conversation_GetItem,
    conversation_RemoveItem,
    conversation_Send,
    conversation_EnumerateItems,
    conversation_FlushItemDeletion,
    conversation_SetDeferMessageDelivery,
    conversation_GetDeferMessageDelivery,
    conversation_ReserveCustomIDSpace,
    conversation_SkipBatchingAndFlushNow,
};

static HRESULT WINAPI session_JoinConversationAsEagerClient( struct message_session_iface *iface,
                                                             const WCHAR *name, const WCHAR *peer, GUID scope,
                                                             UINT owner, UINT style, UINT mode, IUnknown *host,
                                                             UINT *item_id, UINT64 *conversation_id,
                                                             struct message_conversation_iface **out )
{
    struct message_conversation *conversation;
    HRESULT hr;

    TRACE( "iface %p, name %s, peer %s, owner %u, style %u, mode %u, host %p.\n",
           iface, debugstr_w(name), debugstr_w(peer), owner, style, mode, host );
    if (item_id) *item_id = 0;
    if (conversation_id) *conversation_id = 0;
    if (!name || !peer || !host || !item_id || !conversation_id || !out) return E_POINTER;
    *out = NULL;
    if (owner > 3 || style > 2 || mode > 2) return E_INVALIDARG;
    if (!(conversation = calloc( 1, sizeof(*conversation) ))) return E_OUTOFMEMORY;

    conversation->iface.lpVtbl = &message_conversation_vtbl;
    conversation->ref = 1;
    IUnknown_AddRef( (conversation->host = host) );
    conversation->item_id = InterlockedIncrement( &next_conversation_item_id );
    conversation->conversation_id = InterlockedIncrement64( &next_conversation_id );
    conversation->next_item_id = conversation->item_id;
    if (FAILED(hr = conversation_add_item( conversation, owner, conversation->item_id, NULL )))
    {
        IUnknown_Release( conversation->host );
        free( conversation );
        return hr;
    }
    *item_id = conversation->item_id;
    *conversation_id = conversation->conversation_id;
    *out = &conversation->iface;
    return S_OK;
}

static const struct message_session_vtbl message_session_vtbl =
{
    session_QueryInterface,
    session_AddRef,
    session_Release,
    session_GetMessageRegistrar,
    session_GetMessageInfo,
    session_GetMessageLoopExtensions,
    session_CreatePort,
    session_CreateNamedPort,
    session_CreateAnonymousPort,
    session_OpenScopedPort,
    session_OpenPort,
    session_CreateGroup,
    session_CreateGroupWithSignal,
    session_CreateEndpointOnPort,
    session_CreateEndpoint,
    session_OpenEndpoint,
    session_GetMessagePort,
    session_GetEndpointInfo,
    session_CreateTimer,
    session_DeferInvoke,
    session_CloseEndpoint,
    session_CloseEndpointEx,
    session_Send,
    session_SendWithPriority,
    session_SendInPlace,
    session_SendInPlaceWithPriority,
    session_CancelSendInPlace,
    session_DisconnectClient,
    session_DisconnectClientEx,
    session_Run,
    session_Exit,
    session_RegisterDispatchCallback,
    session_RegisterDispatchCallbackEx,
    session_UnregisterDispatchCallback,
    session_RegisterWait,
    session_UnregisterWait,
    session_GetPrivateInterface,
    session_JoinConversationAsServer,
    session_JoinConversationAsNamedServer,
    session_JoinConversationAsClient,
    session_JoinConversationAsManualClient,
    session_ImpersonateCaller,
    session_JoinConversationAsEagerClient,
};

static HRESULT WINAPI loop_QueryInterface( struct message_loop_extensions_iface *iface, REFIID iid, void **out )
{
    return session_query_interface( impl_from_loop( iface ), iid, out );
}

static ULONG WINAPI loop_AddRef( struct message_loop_extensions_iface *iface )
{
    return message_session_addref( impl_from_loop( iface ) );
}

static ULONG WINAPI loop_Release( struct message_loop_extensions_iface *iface )
{
    return message_session_release( impl_from_loop( iface ) );
}

static BOOL dispatch_one_message( BOOL wait )
{
    MSG message;
    BOOL ret;

    if (wait)
    {
        ret = GetMessageW( &message, NULL, 0, 0 );
        if (ret <= 0) return FALSE;
    }
    else
    {
        if (!PeekMessageW( &message, NULL, 0, 0, PM_REMOVE )) return FALSE;
        if (message.message == WM_QUIT)
        {
            PostQuitMessage( (int)message.wParam );
            return FALSE;
        }
    }

    TranslateMessage( &message );
    DispatchMessageW( &message );
    return TRUE;
}

static HRESULT WINAPI loop_Run( struct message_loop_extensions_iface *iface, UINT mode )
{
    struct message_session *session = impl_from_loop( iface );

    TRACE( "iface %p, mode %u.\n", iface, mode );
    if (session->thread_id && session->thread_id != GetCurrentThreadId()) return RPC_E_WRONG_THREAD;
    if (mode > 2) return E_INVALIDARG;
    if (session->dispatch_paused) return S_OK;

    session->running = TRUE;
    session->exit_requested = FALSE;
    if (mode == 0)
        while (!session->exit_requested && dispatch_one_message( TRUE ));
    else if (mode == 1)
        dispatch_one_message( FALSE );
    else
        while (!session->exit_requested && dispatch_one_message( FALSE ));
    session->running = FALSE;
    return S_OK;
}

static HRESULT WINAPI loop_Wait( struct message_loop_extensions_iface *iface, UINT count, HANDLE *handles,
                                 UINT timeout, UINT flags, DWORD *status )
{
    struct message_session *session = impl_from_loop( iface );
    DWORD ret;

    if (!status) return E_POINTER;
    if (session->thread_id && session->thread_id != GetCurrentThreadId()) return RPC_E_WRONG_THREAD;
    if (count && !handles) return E_POINTER;
    ret = MsgWaitForMultipleObjectsEx( count, handles, timeout, QS_ALLINPUT,
                                      (flags & 1 ? MWMO_ALERTABLE : 0) | MWMO_INPUTAVAILABLE );
    if (ret == WAIT_FAILED) return HRESULT_FROM_WIN32( GetLastError() );
    *status = ret;
    return S_OK;
}

static HRESULT WINAPI loop_GetIsRunning( struct message_loop_extensions_iface *iface, BOOL *running )
{
    if (!running) return E_POINTER;
    *running = impl_from_loop( iface )->running;
    return S_OK;
}

static HRESULT WINAPI loop_UrgentExit( struct message_loop_extensions_iface *iface )
{
    struct message_session *session = impl_from_loop( iface );

    session->exit_requested = TRUE;
    if (session->thread_id) PostThreadMessageW( session->thread_id, WM_QUIT, 0, 0 );
    return S_OK;
}

static HRESULT WINAPI loop_AssumeLoopActive( struct message_loop_extensions_iface *iface )
{
    impl_from_loop( iface )->running = TRUE;
    return S_OK;
}

static HRESULT WINAPI loop_RegisterThreadCompletionHandler( struct message_loop_extensions_iface *iface,
                                                             HANDLE thread, void *callback, void *context )
{
    FIXME( "iface %p, thread %p, callback %p, context %p not implemented.\n", iface, thread, callback, context );
    return E_NOTIMPL;
}

static HRESULT WINAPI loop_DeferWindowMessageDispatch( struct message_loop_extensions_iface *iface, BOOL defer )
{
    TRACE( "iface %p, defer %d.\n", iface, defer );
    return S_OK;
}

static HRESULT WINAPI loop_GetThreadID( struct message_loop_extensions_iface *iface, DWORD *thread_id )
{
    if (!thread_id) return E_POINTER;
    *thread_id = impl_from_loop( iface )->thread_id;
    return S_OK;
}

static HRESULT WINAPI loop_GetDispatchingThreadID( struct message_loop_extensions_iface *iface, DWORD *thread_id )
{
    return loop_GetThreadID( iface, thread_id );
}

static HRESULT WINAPI loop_PauseNewDispatch( struct message_loop_extensions_iface *iface )
{
    impl_from_loop( iface )->dispatch_paused = TRUE;
    return S_OK;
}

static HRESULT WINAPI loop_ResumeDispatch( struct message_loop_extensions_iface *iface )
{
    impl_from_loop( iface )->dispatch_paused = FALSE;
    return S_OK;
}

static HRESULT WINAPI loop_WaitOnOutboundMessages( struct message_loop_extensions_iface *iface,
                                                    UINT timeout, BOOL *completed )
{
    if (!completed) return E_POINTER;
    *completed = TRUE;
    return S_OK;
}

static HRESULT WINAPI loop_RunUntilExitFlag( struct message_loop_extensions_iface *iface,
                                              UINT options, const BOOL *exit_flag )
{
    struct message_session *session = impl_from_loop( iface );

    if (!exit_flag) return E_POINTER;
    if (session->thread_id && session->thread_id != GetCurrentThreadId()) return RPC_E_WRONG_THREAD;
    session->running = TRUE;
    while (!*exit_flag && !session->exit_requested && dispatch_one_message( TRUE ));
    session->running = FALSE;
    return S_OK;
}

static HRESULT WINAPI loop_EnableNestedDispatch( struct message_loop_extensions_iface *iface )
{
    impl_from_loop( iface )->nested_dispatch = TRUE;
    return S_OK;
}

static const struct message_loop_extensions_vtbl message_loop_extensions_vtbl =
{
    loop_QueryInterface,
    loop_AddRef,
    loop_Release,
    loop_Run,
    loop_Wait,
    loop_GetIsRunning,
    loop_UrgentExit,
    loop_AssumeLoopActive,
    loop_RegisterThreadCompletionHandler,
    loop_DeferWindowMessageDispatch,
    loop_GetThreadID,
    loop_GetDispatchingThreadID,
    loop_PauseNewDispatch,
    loop_ResumeDispatch,
    loop_WaitOnOutboundMessages,
    loop_RunUntilExitFlag,
    loop_EnableNestedDispatch,
};

static HRESULT WINAPI queue_interop_QueryInterface( struct dispatcher_queue_interop_iface *iface,
                                                    REFIID iid, void **out )
{
    return session_query_interface( impl_from_queue_interop( iface ), iid, out );
}

static ULONG WINAPI queue_interop_AddRef( struct dispatcher_queue_interop_iface *iface )
{
    return message_session_addref( impl_from_queue_interop( iface ) );
}

static ULONG WINAPI queue_interop_Release( struct dispatcher_queue_interop_iface *iface )
{
    return message_session_release( impl_from_queue_interop( iface ) );
}

static HRESULT WINAPI queue_interop_SetDispatcherQueue( struct dispatcher_queue_interop_iface *iface,
                                                        IUnknown *queue, BOOL dedicated )
{
    struct message_session *session = impl_from_queue_interop( iface );

    TRACE( "iface %p, queue %p, dedicated %d.\n", iface, queue, dedicated );
    if (session->thread_id && session->thread_id != GetCurrentThreadId()) return RPC_E_WRONG_THREAD;
    if (queue) IUnknown_AddRef( queue );
    if (session->dispatcher_queue) IUnknown_Release( session->dispatcher_queue );
    session->dispatcher_queue = queue;
    return S_OK;
}

static HRESULT WINAPI queue_interop_GetDispatcherQueue( struct dispatcher_queue_interop_iface *iface,
                                                        IUnknown **queue )
{
    struct message_session *session = impl_from_queue_interop( iface );
    IDispatcherQueue *current = NULL;
    HRESULT hr;

    if (!queue) return E_POINTER;
    *queue = NULL;
    if (session->dispatcher_queue)
    {
        IUnknown_AddRef( (*queue = session->dispatcher_queue) );
        return S_OK;
    }
    if (FAILED(hr = dispatcher_queue_get_for_current_thread( &current ))) return hr;
    *queue = (IUnknown *)current;
    return S_OK;
}

static HRESULT WINAPI queue_interop_TryDeferInvoke( struct dispatcher_queue_interop_iface *iface,
                                                    void *callback, void *context, UINT priority,
                                                    BOOL allow_reentrancy, BOOL *deferred )
{
    if (!deferred) return E_POINTER;
    *deferred = FALSE;
    FIXME( "iface %p, callback %p, context %p, priority %u, reentrancy %d not implemented.\n",
           iface, callback, context, priority, allow_reentrancy );
    return E_NOTIMPL;
}

static HRESULT WINAPI queue_interop_Exit( struct dispatcher_queue_interop_iface *iface )
{
    return loop_UrgentExit( &impl_from_queue_interop( iface )->loop_iface );
}

static const struct dispatcher_queue_interop_vtbl dispatcher_queue_interop_vtbl =
{
    queue_interop_QueryInterface,
    queue_interop_AddRef,
    queue_interop_Release,
    queue_interop_SetDispatcherQueue,
    queue_interop_GetDispatcherQueue,
    queue_interop_TryDeferInvoke,
    queue_interop_Exit,
};

static HRESULT message_session_alloc( DWORD thread_id, struct message_session **out )
{
    struct message_session *session;
    IDispatcherQueue *queue = NULL;

    *out = NULL;
    if (!(session = calloc( 1, sizeof(*session) ))) return E_OUTOFMEMORY;
    session->session_iface.lpVtbl = &message_session_vtbl;
    session->loop_iface.lpVtbl = &message_loop_extensions_vtbl;
    session->queue_interop_iface.lpVtbl = &dispatcher_queue_interop_vtbl;
    session->ref = 1;
    session->thread_id = thread_id;
    if (thread_id && SUCCEEDED(dispatcher_queue_get_for_current_thread( &queue )))
        session->dispatcher_queue = (IUnknown *)queue;
    *out = session;
    return S_OK;
}

static HRESULT message_session_get( DWORD flags, struct message_session_iface **out )
{
    struct message_session *session;
    HRESULT hr;

    if (!out) return E_POINTER;
    *out = NULL;
    if (flags & ~3) return E_INVALIDARG;

    if (flags & 2)
    {
        AcquireSRWLockExclusive( &free_session_lock );
        if (!free_session && SUCCEEDED(hr = message_session_alloc( 0, &free_session )))
            TRACE( "created free-threaded session %p.\n", free_session );
        else if (!free_session)
        {
            ReleaseSRWLockExclusive( &free_session_lock );
            return hr;
        }
        session = free_session;
        message_session_addref( session );
        ReleaseSRWLockExclusive( &free_session_lock );
    }
    else
    {
        if (!InitOnceExecuteOnce( &session_init_once, session_global_init, NULL, NULL ))
            return HRESULT_FROM_WIN32( GetLastError() );
        if ((session = FlsGetValue( session_fls )))
            message_session_addref( session );
        else
        {
            if (FAILED(hr = message_session_alloc( GetCurrentThreadId(), &session ))) return hr;
            message_session_addref( session ); /* thread-context ownership */
            if (!FlsSetValue( session_fls, session ))
            {
                message_session_release( session );
                message_session_release( session );
                return HRESULT_FROM_WIN32( GetLastError() );
            }
            TRACE( "created thread session %p for thread %lu.\n", session, session->thread_id );
        }
    }

    *out = &session->session_iface;
    return S_OK;
}

HRESULT WINAPI CoreUICreate( struct message_session_iface **out )
{
    TRACE( "out %p.\n", out );
    return message_session_get( 0, out );
}

HRESULT WINAPI CoreUICreateEx( DWORD flags, struct message_session_iface **out )
{
    TRACE( "flags %#lx, out %p.\n", flags, out );
    return message_session_get( flags, out );
}

HRESULT WINAPI CoreUIOpenExisting( struct message_session_iface **out )
{
    struct message_session *session;

    TRACE( "out %p.\n", out );
    if (!out) return E_POINTER;
    *out = NULL;
    if (!InitOnceExecuteOnce( &session_init_once, session_global_init, NULL, NULL ))
        return HRESULT_FROM_WIN32( GetLastError() );
    if ((session = FlsGetValue( session_fls )))
    {
        message_session_addref( session );
        *out = &session->session_iface;
    }
    return S_OK;
}

HRESULT WINAPI GetDispatcherQueueForCurrentThread( IDispatcherQueue **out )
{
    TRACE( "out %p.\n", out );
    return dispatcher_queue_get_for_current_thread( out );
}

HRESULT WINAPI CreateDispatcherQueueForCurrentThread( IDispatcherQueue **out )
{
    TRACE( "out %p.\n", out );
    return dispatcher_queue_create_for_current_thread( out );
}
