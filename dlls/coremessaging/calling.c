/* Core UI calling host implementation
 *
 * Copyright (C) 2026 Nulifyer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "private.h"

WINE_DEFAULT_DEBUG_CHANNEL(messaging);

static const GUID IID_IMessageCallSendHost =
    {0x205d9071, 0xdb4b, 0x45a5, {0xae, 0xdd, 0x06, 0x41, 0x48, 0x7b, 0x8e, 0x95}};
static const GUID IID_IMessageCallReceiveHost =
    {0x07ab7121, 0x8053, 0x46c0, {0x90, 0x3f, 0x99, 0xf2, 0x87, 0xf9, 0x45, 0x1e}};

struct message_call_send_host;
struct message_call_receive_host;

struct message_call_send_host_vtbl
{
    HRESULT (WINAPI *QueryInterface)( struct message_call_send_host *, REFIID, void ** );
    ULONG (WINAPI *AddRef)( struct message_call_send_host * );
    ULONG (WINAPI *Release)( struct message_call_send_host * );
    HRESULT (WINAPI *AllocateBuffer)( struct message_call_send_host *, UINT64 *, UINT, UINT, void ** );
    HRESULT (WINAPI *SubmitBuffer)( struct message_call_send_host *, UINT64 *, UINT, void *, UINT );
    HRESULT (WINAPI *CancelBuffer)( struct message_call_send_host *, UINT64 *, UINT, void *, UINT );
    HRESULT (WINAPI *NotifyInvalid)( struct message_call_send_host *, void * );
};

struct message_call_receive_host_vtbl
{
    HRESULT (WINAPI *QueryInterface)( struct message_call_receive_host *, REFIID, void ** );
    ULONG (WINAPI *AddRef)( struct message_call_receive_host * );
    ULONG (WINAPI *Release)( struct message_call_receive_host * );
    HRESULT (WINAPI *NotifyInvalid)( struct message_call_receive_host *, void * );
    HRESULT (WINAPI *NotifyProtocolViolation)( struct message_call_receive_host *, void * );
};

struct message_call_send_host
{
    const struct message_call_send_host_vtbl *lpVtbl;
};

struct message_call_receive_host
{
    const struct message_call_receive_host_vtbl *lpVtbl;
};

struct message_call_host
{
    struct message_call_send_host send_iface;
    struct message_call_receive_host receive_iface;
    IUnknown *session;
    IUnknown *conversation;
    LONG ref;
    LONG inline_busy;
    BYTE inline_buffer[256];
};

static inline struct message_call_host *impl_from_send( struct message_call_send_host *iface )
{
    return CONTAINING_RECORD( iface, struct message_call_host, send_iface );
}

static inline struct message_call_host *impl_from_receive( struct message_call_receive_host *iface )
{
    return CONTAINING_RECORD( iface, struct message_call_host, receive_iface );
}

static HRESULT call_host_query_interface( struct message_call_host *host, REFIID iid, void **out )
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualGUID( iid, &IID_IUnknown ) || IsEqualGUID( iid, &IID_IMessageCallSendHost ))
        *out = &host->send_iface;
    else if (IsEqualGUID( iid, &IID_IMessageCallReceiveHost ))
        *out = &host->receive_iface;
    else
        return E_NOINTERFACE;
    InterlockedIncrement( &host->ref );
    return S_OK;
}

static ULONG call_host_release( struct message_call_host *host )
{
    ULONG ref = InterlockedDecrement( &host->ref );

    if (!ref)
    {
        IUnknown_Release( host->conversation );
        IUnknown_Release( host->session );
        free( host );
    }
    return ref;
}

static HRESULT WINAPI send_QueryInterface( struct message_call_send_host *iface, REFIID iid, void **out )
{
    return call_host_query_interface( impl_from_send(iface), iid, out );
}

static ULONG WINAPI send_AddRef( struct message_call_send_host *iface )
{
    return InterlockedIncrement( &impl_from_send(iface)->ref );
}

static ULONG WINAPI send_Release( struct message_call_send_host *iface )
{
    return call_host_release( impl_from_send(iface) );
}

static HRESULT WINAPI send_AllocateBuffer( struct message_call_send_host *iface, UINT64 *state,
                                           UINT type, UINT size, void **out )
{
    struct message_call_host *host = impl_from_send( iface );
    void *buffer;

    TRACE( "iface %p, state %p, type %u, size %u, out %p.\n", iface, state, type, size, out );
    if (!out) return E_POINTER;
    *out = NULL;
    if (size < sizeof(host->inline_buffer) && !InterlockedCompareExchange( &host->inline_busy, 1, 0 ))
        buffer = host->inline_buffer;
    else if (!(buffer = malloc( size ? size : 1 )))
        return E_OUTOFMEMORY;
    *out = buffer;
    return S_OK;
}

static void call_host_retire_buffer( struct message_call_host *host, void *buffer )
{
    if (buffer == host->inline_buffer)
        InterlockedExchange( &host->inline_busy, 0 );
    else
        free( buffer );
}

static HRESULT WINAPI send_SubmitBuffer( struct message_call_send_host *iface, UINT64 *state,
                                         UINT type, void *buffer, UINT size )
{
    struct message_call_host *host = impl_from_send( iface );
    typedef HRESULT (WINAPI *conversation_send_fn)( IUnknown *, UINT, UINT, void *, UINT );
    conversation_send_fn send;
    HRESULT hr;

    TRACE( "iface %p, state %p, type %u, buffer %p, size %u.\n", iface, state, type, buffer, size );
    if (!state || !buffer) return E_POINTER;
    if (type != 2) return E_INVALIDARG;
    send = (conversation_send_fn)((void **)host->conversation->lpVtbl)[8];
    hr = send( host->conversation, (UINT)state[0], (UINT)state[1], buffer, size );
    if (SUCCEEDED(hr)) call_host_retire_buffer( host, buffer );
    return hr;
}

static HRESULT WINAPI send_CancelBuffer( struct message_call_send_host *iface, UINT64 *state,
                                         UINT type, void *buffer, UINT size )
{
    TRACE( "iface %p, state %p, type %u, buffer %p, size %u.\n", iface, state, type, buffer, size );
    if (!buffer) return E_POINTER;
    call_host_retire_buffer( impl_from_send(iface), buffer );
    return S_OK;
}

static HRESULT WINAPI send_NotifyInvalid( struct message_call_send_host *iface, void *state )
{
    TRACE( "iface %p, state %p.\n", iface, state );
    return S_OK;
}

static const struct message_call_send_host_vtbl send_vtbl =
{
    send_QueryInterface,
    send_AddRef,
    send_Release,
    send_AllocateBuffer,
    send_SubmitBuffer,
    send_CancelBuffer,
    send_NotifyInvalid,
};

static HRESULT WINAPI receive_QueryInterface( struct message_call_receive_host *iface, REFIID iid, void **out )
{
    return call_host_query_interface( impl_from_receive(iface), iid, out );
}

static ULONG WINAPI receive_AddRef( struct message_call_receive_host *iface )
{
    return InterlockedIncrement( &impl_from_receive(iface)->ref );
}

static ULONG WINAPI receive_Release( struct message_call_receive_host *iface )
{
    return call_host_release( impl_from_receive(iface) );
}

static HRESULT WINAPI receive_NotifyInvalid( struct message_call_receive_host *iface, void *state )
{
    TRACE( "iface %p, state %p.\n", iface, state );
    return S_OK;
}

static HRESULT WINAPI receive_NotifyProtocolViolation( struct message_call_receive_host *iface, void *state )
{
    TRACE( "iface %p, state %p.\n", iface, state );
    return S_OK;
}

static const struct message_call_receive_host_vtbl receive_vtbl =
{
    receive_QueryInterface,
    receive_AddRef,
    receive_Release,
    receive_NotifyInvalid,
    receive_NotifyProtocolViolation,
};

HRESULT WINAPI CoreUICallCreateConversationHost( IUnknown *session, IUnknown *conversation,
                                                 struct message_call_send_host **send,
                                                 struct message_call_receive_host **receive )
{
    struct message_call_host *host;

    TRACE( "session %p, conversation %p, send %p, receive %p.\n", session, conversation, send, receive );
    if (send) *send = NULL;
    if (receive) *receive = NULL;
    if (!session || !conversation || (!send && !receive)) return E_POINTER;
    if (!(host = calloc( 1, sizeof(*host) ))) return E_OUTOFMEMORY;
    host->send_iface.lpVtbl = &send_vtbl;
    host->receive_iface.lpVtbl = &receive_vtbl;
    IUnknown_AddRef( (host->session = session) );
    IUnknown_AddRef( (host->conversation = conversation) );
    if (send)
    {
        InterlockedIncrement( &host->ref );
        *send = &host->send_iface;
    }
    if (receive)
    {
        InterlockedIncrement( &host->ref );
        *receive = &host->receive_iface;
    }
    return S_OK;
}
