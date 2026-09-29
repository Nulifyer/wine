/*
 * Copyright (C) 2025 Mohamad Al-Jaf
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
#define COBJMACROS
#include "initguid.h"
#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winstring.h"

#include "roapi.h"

#define WIDL_using_Windows_Foundation
#include "windows.foundation.h"
#define WIDL_using_Windows_System
#include "windows.system.h"

#include "dispatcherqueue.h"

#include "wine/test.h"

static const GUID IID_IMessageSession =
    {0x4b2edab9, 0x129b, 0x4733, {0xbe, 0x15, 0x35, 0x68, 0x53, 0xd5, 0x5a, 0xce}};
static const GUID IID_IMessageLoopExtensions =
    {0x50e345cc, 0xb3ef, 0x4d17, {0x89, 0x2d, 0xd4, 0xcf, 0xbf, 0xcc, 0x69, 0xfe}};
static const GUID IID_IMessageConversation =
    {0xf5da6aa2, 0xbfb5, 0x4292, {0xb8, 0x2b, 0xc9, 0x65, 0xe1, 0x8e, 0xa8, 0x21}};
static const GUID IID_IExportDispatcherQueueInterop =
    {0x8dfddcea, 0x6bfd, 0x4323, {0x83, 0x2b, 0x17, 0x58, 0x1d, 0x16, 0xac, 0x52}};
static const GUID IID_IMessageCallSendHost =
    {0x205d9071, 0xdb4b, 0x45a5, {0xae, 0xdd, 0x06, 0x41, 0x48, 0x7b, 0x8e, 0x95}};
static const GUID IID_IMessageCallReceiveHost =
    {0x07ab7121, 0x8053, 0x46c0, {0x90, 0x3f, 0x99, 0xf2, 0x87, 0xf9, 0x45, 0x1e}};

HRESULT WINAPI CoreUICreate( IUnknown **session );
HRESULT WINAPI CoreUICreateEx( DWORD flags, IUnknown **session );
HRESULT WINAPI CoreUIOpenExisting( IUnknown **session );
HRESULT WINAPI CoreUICallCreateConversationHost( IUnknown *session, IUnknown *conversation,
                                                 IUnknown **send, IUnknown **receive );
HRESULT WINAPI CreateDispatcherQueueForCurrentThread( IDispatcherQueue **queue );
HRESULT WINAPI GetDispatcherQueueForCurrentThread( IDispatcherQueue **queue );

typedef HRESULT (WINAPI *session_get_object_fn)( IUnknown *, IUnknown ** );
typedef HRESULT (WINAPI *loop_run_fn)( IUnknown *, UINT );
typedef HRESULT (WINAPI *loop_get_bool_fn)( IUnknown *, BOOL * );
typedef HRESULT (WINAPI *loop_get_thread_id_fn)( IUnknown *, DWORD * );
typedef HRESULT (WINAPI *queue_interop_get_fn)( IUnknown *, IUnknown ** );
typedef HRESULT (WINAPI *join_eager_fn)( IUnknown *, const WCHAR *, const WCHAR *, GUID, UINT, UINT, UINT,
                                        IUnknown *, UINT *, UINT64 *, IUnknown ** );
typedef HRESULT (WINAPI *call_allocate_fn)( IUnknown *, UINT64 *, UINT, UINT, void ** );
typedef HRESULT (WINAPI *call_buffer_fn)( IUnknown *, UINT64 *, UINT, void *, UINT );
typedef HRESULT (WINAPI *conversation_allocate_fn)( IUnknown *, UINT, void *, UINT * );
typedef HRESULT (WINAPI *conversation_custom_fn)( IUnknown *, UINT, UINT, void * );
typedef HRESULT (WINAPI *conversation_item_fn)( IUnknown *, UINT, UINT, void * );
typedef HRESULT (WINAPI *conversation_item_out_fn)( IUnknown *, UINT, UINT, void ** );
typedef HRESULT (WINAPI *conversation_remove_fn)( IUnknown *, UINT, UINT, BOOL, void ** );
typedef HRESULT (WINAPI *conversation_enumerate_fn)( IUnknown *, UINT, BOOL, BOOL, void *, void * );
typedef HRESULT (WINAPI *conversation_bool_set_fn)( IUnknown *, BOOL );
typedef HRESULT (WINAPI *conversation_bool_get_fn)( IUnknown *, BOOL * );
typedef HRESULT (WINAPI *conversation_reserve_fn)( IUnknown *, UINT, void * );
typedef HRESULT (WINAPI *conversation_flush_fn)( IUnknown *, UINT );

static void *private_method( IUnknown *iface, unsigned int slot )
{
    return ((void **)iface->lpVtbl)[slot];
}

struct conversation_enum_context
{
    UINT count;
    UINT ids[4];
};

static HRESULT __cdecl conversation_enum_callback( void *context, UINT owner, UINT item_id, const void *data )
{
    struct conversation_enum_context *enum_context = context;

    ok( owner > 0 && owner <= 3, "got owner %u.\n", owner );
    ok( !!item_id, "got zero item id.\n" );
    if (enum_context->count < ARRAY_SIZE(enum_context->ids))
        enum_context->ids[enum_context->count] = item_id;
    enum_context->count++;
    return S_OK;
}

#define check_interface( obj, iid ) check_interface_( __LINE__, obj, iid )
static void check_interface_( unsigned int line, void *obj, const IID *iid )
{
    IUnknown *iface = obj;
    IUnknown *unk;
    HRESULT hr;

    hr = IUnknown_QueryInterface( iface, iid, (void **)&unk );
    ok_(__FILE__, line)( hr == S_OK, "got hr %#lx.\n", hr );
    IUnknown_Release( unk );
}

struct typed_event_handler_dispatcher_queue
{
    ITypedEventHandler_DispatcherQueue_IInspectable ITypedEventHandler_DispatcherQueue_IInspectable_iface;
    LONG ref;

    HANDLE event;
};

static struct typed_event_handler_dispatcher_queue *impl_from_ITypedEventHandler_DispatcherQueue_IInspectable( ITypedEventHandler_DispatcherQueue_IInspectable *iface )
{
    return CONTAINING_RECORD( iface, struct typed_event_handler_dispatcher_queue, ITypedEventHandler_DispatcherQueue_IInspectable_iface );
}

static HRESULT WINAPI typed_event_handler_dispatcher_queue_QueryInterface( ITypedEventHandler_DispatcherQueue_IInspectable *iface, REFIID iid, void **out )
{
    if (IsEqualGUID( iid, &IID_ITypedEventHandler_DispatcherQueue_IInspectable ) ||
        IsEqualGUID( iid, &IID_IAgileObject ) ||
        IsEqualGUID( iid, &IID_IInspectable ) ||
        IsEqualGUID( iid, &IID_IUnknown ))
    {
        *out = iface;
        ITypedEventHandler_DispatcherQueue_IInspectable_AddRef( iface );
        return S_OK;
    }

    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI typed_event_handler_dispatcher_queue_AddRef( ITypedEventHandler_DispatcherQueue_IInspectable *iface )
{
    struct typed_event_handler_dispatcher_queue *handler = impl_from_ITypedEventHandler_DispatcherQueue_IInspectable( iface );
    return InterlockedIncrement( &handler->ref );
}

static ULONG WINAPI typed_event_handler_dispatcher_queue_Release( ITypedEventHandler_DispatcherQueue_IInspectable *iface )
{
    struct typed_event_handler_dispatcher_queue *handler = impl_from_ITypedEventHandler_DispatcherQueue_IInspectable( iface );
    ULONG ref = InterlockedDecrement( &handler->ref );

    if (!ref)
    {
        CloseHandle( handler->event );
        free( handler );
    }

    return ref;
}

static HRESULT WINAPI typed_event_handler_dispatcher_queue_Invoke( ITypedEventHandler_DispatcherQueue_IInspectable *iface, IDispatcherQueue *queue, IInspectable *inspectable )
{
    struct typed_event_handler_dispatcher_queue *handler = impl_from_ITypedEventHandler_DispatcherQueue_IInspectable( iface );

    SetEvent( handler->event );
    return S_OK;
}

static const ITypedEventHandler_DispatcherQueue_IInspectableVtbl typed_event_handler_dispatcher_queue_vtbl =
{
    typed_event_handler_dispatcher_queue_QueryInterface,
    typed_event_handler_dispatcher_queue_AddRef,
    typed_event_handler_dispatcher_queue_Release,
    typed_event_handler_dispatcher_queue_Invoke,
};

static HRESULT create_typed_event_handler_dispatcher_queue( ITypedEventHandler_DispatcherQueue_IInspectable **handler )
{
    struct typed_event_handler_dispatcher_queue *impl;

    *handler = NULL;

    if (!(impl = calloc( 1, sizeof( *impl ) ))) return E_OUTOFMEMORY;

    impl->ITypedEventHandler_DispatcherQueue_IInspectable_iface.lpVtbl = &typed_event_handler_dispatcher_queue_vtbl;
    impl->ref = 1;
    impl->event = CreateEventW( NULL, TRUE, FALSE, NULL );

    *handler = &impl->ITypedEventHandler_DispatcherQueue_IInspectable_iface;
    return S_OK;
}

struct dispatcher_queue_handler
{
    IDispatcherQueueHandler IDispatcherQueueHandler_iface;
    LONG ref;

    HANDLE event;
    HANDLE invoked_event;
    LONG *order;
    LONG invocation_order;
    DWORD invocation_thread;
};

static struct dispatcher_queue_handler *impl_from_IDispatcherQueueHandler( IDispatcherQueueHandler *iface )
{
    return CONTAINING_RECORD( iface, struct dispatcher_queue_handler, IDispatcherQueueHandler_iface );
}

static HRESULT WINAPI dispatcher_queue_handler_QueryInterface( IDispatcherQueueHandler *iface, REFIID iid, void **out )
{
    if (IsEqualGUID( iid, &IID_IDispatcherQueueHandler ) ||
        IsEqualGUID( iid, &IID_IAgileObject ) ||
        IsEqualGUID( iid, &IID_IInspectable ) ||
        IsEqualGUID( iid, &IID_IUnknown ))
    {
        *out = iface;
        IDispatcherQueueHandler_AddRef( iface );
        return S_OK;
    }

    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI dispatcher_queue_handler_AddRef( IDispatcherQueueHandler *iface )
{
    struct dispatcher_queue_handler *handler = impl_from_IDispatcherQueueHandler( iface );
    return InterlockedIncrement( &handler->ref );
}

static ULONG WINAPI dispatcher_queue_handler_Release( IDispatcherQueueHandler *iface )
{
    struct dispatcher_queue_handler *handler = impl_from_IDispatcherQueueHandler( iface );
    ULONG ref = InterlockedDecrement( &handler->ref );

    if (!ref)
    {
        CloseHandle( handler->event );
        CloseHandle( handler->invoked_event );
        free( handler );
    }

    return ref;
}

static HRESULT WINAPI dispatcher_queue_handler_Invoke( IDispatcherQueueHandler *iface )
{
    struct dispatcher_queue_handler *handler = impl_from_IDispatcherQueueHandler( iface );
    DWORD ret;

    handler->invocation_thread = GetCurrentThreadId();
    ret = WaitForSingleObject( handler->event, 5000 );
    ok( !ret, "Unexpected wait result %lu.\n", ret );
    if (handler->order) handler->invocation_order = InterlockedIncrement( handler->order );
    SetEvent( handler->invoked_event );

    return S_OK;
}

static const IDispatcherQueueHandlerVtbl dispatcher_queue_handler_vtbl =
{
    dispatcher_queue_handler_QueryInterface,
    dispatcher_queue_handler_AddRef,
    dispatcher_queue_handler_Release,
    dispatcher_queue_handler_Invoke,
};

static HRESULT create_dispatcher_queue_handler( IDispatcherQueueHandler **handler )
{
    struct dispatcher_queue_handler *impl;

    *handler = NULL;

    if (!(impl = calloc( 1, sizeof( *impl ) ))) return E_OUTOFMEMORY;

    impl->IDispatcherQueueHandler_iface.lpVtbl = &dispatcher_queue_handler_vtbl;
    impl->ref = 1;
    impl->event = CreateEventW( NULL, TRUE, FALSE, NULL );
    impl->invoked_event = CreateEventW( NULL, TRUE, FALSE, NULL );

    *handler = &impl->IDispatcherQueueHandler_iface;
    return S_OK;
}

#define wait_messages( a ) msg_wait_for_events_( __FILE__, __LINE__, 0, NULL, a )
#define msg_wait_for_events( a, b, c ) msg_wait_for_events_( __FILE__, __LINE__, a, b, c )
static DWORD msg_wait_for_events_( const char *file, int line, DWORD count, HANDLE *events, DWORD timeout )
{
    DWORD ret, end = GetTickCount() + min( timeout, 5000 );
    MSG msg;

    while ((ret = MsgWaitForMultipleObjects( count, events, FALSE, min( timeout, 5000 ), QS_ALLINPUT )) <= count)
    {
        while (PeekMessageW( &msg, 0, 0, 0, PM_REMOVE ))
        {
            TranslateMessage( &msg );
            DispatchMessageW( &msg );
        }
        if (ret < count) return ret;
        if (timeout >= 5000) continue;
        if (end <= GetTickCount()) timeout = 0;
        else timeout = end - GetTickCount();
    }

    if (timeout >= 5000) ok_(file, line)( 0, "MsgWaitForMultipleObjects returned %#lx\n", ret );
    else ok_(file, line)( ret == WAIT_TIMEOUT, "MsgWaitForMultipleObjects returned %#lx\n", ret );
    return ret;
}

#define check_create_dispatcher_queue_controller( size, thread_type, apartment_type, expected_hr ) \
        check_create_dispatcher_queue_controller_( __LINE__, size, thread_type, apartment_type, expected_hr )
static void check_create_dispatcher_queue_controller_( unsigned int line, DWORD size, DISPATCHERQUEUE_THREAD_TYPE thread_type,
                                                       DISPATCHERQUEUE_THREAD_APARTMENTTYPE apartment_type, HRESULT expected_hr )
{
    ITypedEventHandler_DispatcherQueue_IInspectable *event_handler_iface = NULL;
    struct typed_event_handler_dispatcher_queue *event_handler = NULL;
    IDispatcherQueueController *dispatcher_queue_controller = NULL;
    struct dispatcher_queue_handler *queue_handler = NULL;
    IDispatcherQueueHandler *handler_iface = NULL;
    struct DispatcherQueueOptions options = { 0 };
    IDispatcherQueue2 *dispatcher_queue2 = NULL;
    IDispatcherQueue *dispatcher_queue = NULL;
    IAsyncAction *operation = NULL;
    IAsyncInfo *async_info = NULL;
    EventRegistrationToken token;
    AsyncStatus status;
    boolean result;
    HRESULT hr;
    DWORD ret;
    LONG ref;

    options.dwSize = size;
    options.threadType = thread_type;
    options.apartmentType = apartment_type;

    hr = CreateDispatcherQueueController( options, &dispatcher_queue_controller );
    ok_(__FILE__, line)( hr == expected_hr, "got CreateDispatcherQueueController hr %#lx.\n", hr );
    if (hr == E_INVALIDARG) return;

    hr = IDispatcherQueueController_get_DispatcherQueue( dispatcher_queue_controller, &dispatcher_queue );
    ok_(__FILE__, line)( hr == S_OK, "got IDispatcherQueueController_get_DispatcherQueue hr %#lx.\n", hr );
    if (FAILED(hr)) goto done;

    hr = IDispatcherQueue_QueryInterface( dispatcher_queue, &IID_IDispatcherQueue2, (void **)&dispatcher_queue2 );
    ok_(__FILE__, line)( hr == S_OK || broken(hr == E_NOINTERFACE) /* w1064v1809 */, "got IDispatcherQueue_QueryInterface hr %#lx.\n", hr );
    if (SUCCEEDED(hr))
    {
        hr = IDispatcherQueue2_get_HasThreadAccess( dispatcher_queue2, &result );
        ok_(__FILE__, line)( hr == S_OK, "got IDispatcherQueue2_get_HasThreadAccess hr %#lx.\n", hr );
        ok_(__FILE__, line)( result == (thread_type == DQTYPE_THREAD_CURRENT ? TRUE : FALSE), "got IDispatcherQueue2_get_HasThreadAccess result %d.\n", result );
        ref = IDispatcherQueue2_Release( dispatcher_queue2 );
        ok_(__FILE__, line)( ref == (thread_type == DQTYPE_THREAD_CURRENT ? 2 : 3), "got IDispatcherQueue2_Release ref %ld.\n", ref );
    }

    hr = create_dispatcher_queue_handler( &handler_iface );
    ok_(__FILE__, line)( hr == S_OK, "create_dispatcher_queue_handler failed, hr %#lx.\n", hr );
    queue_handler = impl_from_IDispatcherQueueHandler( handler_iface );

    hr = IDispatcherQueue_TryEnqueue( dispatcher_queue, handler_iface, &result );
    ok_(__FILE__, line)( hr == S_OK, "got IDispatcherQueue_TryEnqueue hr %#lx.\n", hr );
    ok_(__FILE__, line)( result == TRUE, "got IDispatcherQueue_TryEnqueue result %d.\n", result );

    hr = create_typed_event_handler_dispatcher_queue( &event_handler_iface );
    ok_(__FILE__, line)( hr == S_OK, "create_typed_event_handler_dispatcher_queue failed, hr %#lx.\n", hr );
    event_handler = impl_from_ITypedEventHandler_DispatcherQueue_IInspectable( event_handler_iface );

    hr = IDispatcherQueue_add_ShutdownCompleted( dispatcher_queue, event_handler_iface, &token );
    ok_(__FILE__, line)( hr == S_OK, "got IDispatcherQueue_add_ShutdownCompleted hr %#lx.\n", hr );
    hr = IDispatcherQueueController_ShutdownQueueAsync( dispatcher_queue_controller, &operation );
    ok_(__FILE__, line)( hr == S_OK, "got IDispatcherQueueController_ShutdownQueueAsync hr %#lx.\n", hr );

    hr = IAsyncAction_QueryInterface( operation, &IID_IAsyncInfo, (void **)&async_info );
    ok_(__FILE__, line)( hr == S_OK, "got IAsyncAction_QueryInterface hr %#lx.\n", hr );

    hr = IAsyncInfo_get_Status( async_info, &status );
    ok_(__FILE__, line)( hr == S_OK, "got IAsyncInfo_get_Status hr %#lx.\n", hr );
    ok_(__FILE__, line)( status == Started, "got IAsyncInfo_get_Status status %d.\n", status );

    /* shutdown waits for queued handlers */
    if (winetest_platform_is_wine) Sleep( 200 );
    ret = WaitForSingleObject( event_handler->event, 100 );
    ok_(__FILE__, line)( ret == WAIT_TIMEOUT, "Unexpected wait result %lu.\n", ret );
    SetEvent( queue_handler->event );

    /* queue uses the message loop when dispatched on current thread */
    if (thread_type == DQTYPE_THREAD_CURRENT)
    {
        ret = WaitForSingleObject( event_handler->event, 100 );
        ok_(__FILE__, line)( ret == WAIT_TIMEOUT, "Unexpected wait result %lu.\n", ret );
        ret = msg_wait_for_events( 1, &event_handler->event, 5000 );
        ok_(__FILE__, line)( !ret, "Unexpected wait result %lu.\n", ret );
    }
    else
    {
        ret = WaitForSingleObject( event_handler->event, 5000 );
        ok_(__FILE__, line)( !ret, "Unexpected wait result %lu.\n", ret );
    }
    ok_(__FILE__, line)( !!queue_handler->invocation_thread, "handler was not invoked.\n" );
    ok_(__FILE__, line)( (queue_handler->invocation_thread == GetCurrentThreadId()) ==
                         (thread_type == DQTYPE_THREAD_CURRENT), "handler ran on thread %lu, caller %lu.\n",
                         queue_handler->invocation_thread, GetCurrentThreadId() );

    hr = IAsyncInfo_get_Status( async_info, &status );
    ok_(__FILE__, line)( hr == S_OK, "got IAsyncInfo_get_Status hr %#lx.\n", hr );
    ok_(__FILE__, line)( status == Completed, "got IAsyncInfo_get_Status status %d.\n", status );

    hr = IAsyncInfo_Close( async_info );
    ok_(__FILE__, line)( hr == S_OK, "got IAsyncInfo_Close hr %#lx.\n", hr );
    ref = IAsyncInfo_Release( async_info );
    ok_(__FILE__, line)( ref == 2, "got IAsyncInfo_Release ref %ld.\n", ref );
    ref = IAsyncAction_Release( operation );
    ok_(__FILE__, line)( ref == 1, "got IAsyncAction_Release ref %ld.\n", ref );
    hr = IDispatcherQueue_remove_ShutdownCompleted( dispatcher_queue, token );
    ok_(__FILE__, line)( hr == S_OK, "got IDispatcherQueue_remove_ShutdownCompleted hr %#lx.\n", hr );

    ref = ITypedEventHandler_DispatcherQueue_IInspectable_Release( event_handler_iface );
    ok_(__FILE__, line)( ref == 0, "got ITypedEventHandler_DispatcherQueue_IInspectable_Release ref %ld.\n", ref );
    ref = IDispatcherQueueHandler_Release( handler_iface );
    ok_(__FILE__, line)( ref == 0, "got IDispatcherQueueHandler_Release ref %ld.\n", ref );
    IDispatcherQueue_Release( dispatcher_queue );
done:
    IDispatcherQueueController_Release( dispatcher_queue_controller );
}

static void test_CreateDispatcherQueueController(void)
{
    IDispatcherQueueController *dispatcher_queue_controller = (void *)0xdeadbeef;
    struct DispatcherQueueOptions options = { 0 };
    HRESULT hr;

    hr = CreateDispatcherQueueController( options, NULL );
    ok( hr == E_POINTER || hr == 0x80000005 /* win10 22h2 */, "got hr %#lx.\n", hr );
    hr = CreateDispatcherQueueController( options, &dispatcher_queue_controller );
    ok( hr == E_INVALIDARG, "got hr %#lx.\n", hr );
    ok( dispatcher_queue_controller == (void *)0xdeadbeef, "got dispatcher_queue_controller %p.\n", dispatcher_queue_controller );

    /* Invalid args */

    check_create_dispatcher_queue_controller( 0,                                    0,                       DQTAT_COM_NONE, E_INVALIDARG );
    check_create_dispatcher_queue_controller( 0,                                    0,                       DQTAT_COM_ASTA, E_INVALIDARG );
    check_create_dispatcher_queue_controller( 0,                                    0,                       DQTAT_COM_STA,  E_INVALIDARG );
    check_create_dispatcher_queue_controller( 0,                                    DQTYPE_THREAD_CURRENT,   DQTAT_COM_NONE, E_INVALIDARG );
    check_create_dispatcher_queue_controller( 0,                                    DQTYPE_THREAD_CURRENT,   DQTAT_COM_ASTA, E_INVALIDARG );
    check_create_dispatcher_queue_controller( 0,                                    DQTYPE_THREAD_CURRENT,   DQTAT_COM_STA,  E_INVALIDARG );
    check_create_dispatcher_queue_controller( 0,                                    DQTYPE_THREAD_DEDICATED, DQTAT_COM_NONE, E_INVALIDARG );
    check_create_dispatcher_queue_controller( 0,                                    DQTYPE_THREAD_DEDICATED, DQTAT_COM_ASTA, E_INVALIDARG );
    check_create_dispatcher_queue_controller( 0,                                    DQTYPE_THREAD_DEDICATED, DQTAT_COM_STA,  E_INVALIDARG );
    check_create_dispatcher_queue_controller( sizeof( DispatcherQueueOptions ),     0,                       DQTAT_COM_NONE, E_INVALIDARG );
    check_create_dispatcher_queue_controller( sizeof( DispatcherQueueOptions ),     0,                       DQTAT_COM_ASTA, E_INVALIDARG );
    check_create_dispatcher_queue_controller( sizeof( DispatcherQueueOptions ),     0,                       DQTAT_COM_STA,  E_INVALIDARG );
    check_create_dispatcher_queue_controller( sizeof( DispatcherQueueOptions ),     0xdeadbeef,              DQTAT_COM_NONE, E_INVALIDARG );
    check_create_dispatcher_queue_controller( sizeof( DispatcherQueueOptions ),     0xdeadbeef,              DQTAT_COM_ASTA, E_INVALIDARG );
    check_create_dispatcher_queue_controller( sizeof( DispatcherQueueOptions ),     0xdeadbeef,              DQTAT_COM_STA,  E_INVALIDARG );
    check_create_dispatcher_queue_controller( sizeof( DispatcherQueueOptions ) - 1, DQTYPE_THREAD_CURRENT,   DQTAT_COM_NONE, E_INVALIDARG );
    check_create_dispatcher_queue_controller( sizeof( DispatcherQueueOptions ) + 1, DQTYPE_THREAD_CURRENT,   DQTAT_COM_NONE, E_INVALIDARG );

    if (0) /* Silently crashes in Windows */
    {
    check_create_dispatcher_queue_controller( sizeof( DispatcherQueueOptions ), DQTYPE_THREAD_DEDICATED, 0xdeadbeef,     S_OK );
    check_create_dispatcher_queue_controller( sizeof( DispatcherQueueOptions ), DQTYPE_THREAD_DEDICATED, DQTAT_COM_NONE, S_OK );
    }

    /* Valid args */

    check_create_dispatcher_queue_controller( sizeof( DispatcherQueueOptions ), DQTYPE_THREAD_CURRENT,   0xdeadbeef,     S_OK );
    check_create_dispatcher_queue_controller( sizeof( DispatcherQueueOptions ), DQTYPE_THREAD_CURRENT,   DQTAT_COM_NONE, S_OK );
    check_create_dispatcher_queue_controller( sizeof( DispatcherQueueOptions ), DQTYPE_THREAD_CURRENT,   DQTAT_COM_ASTA, S_OK );
    check_create_dispatcher_queue_controller( sizeof( DispatcherQueueOptions ), DQTYPE_THREAD_CURRENT,   DQTAT_COM_STA,  S_OK );

    check_create_dispatcher_queue_controller( sizeof( DispatcherQueueOptions ), DQTYPE_THREAD_DEDICATED, DQTAT_COM_ASTA, S_OK );
    check_create_dispatcher_queue_controller( sizeof( DispatcherQueueOptions ), DQTYPE_THREAD_DEDICATED, DQTAT_COM_STA,  S_OK );
}

static void test_DispatcherQueueController_Statics(void)
{
    static const WCHAR *dispatcher_queue_controller_statics_name = L"Windows.System.DispatcherQueueController";
    IDispatcherQueueControllerStatics *dispatcher_queue_controller_statics = (void *)0xdeadbeef;
    ITypedEventHandler_DispatcherQueue_IInspectable *event_handler_iface = (void *)0xdeadbeef;
    struct typed_event_handler_dispatcher_queue *event_handler = (void *)0xdeadbeef;
    IDispatcherQueueController *dispatcher_queue_controller = (void *)0xdeadbeef;
    struct dispatcher_queue_handler *queue_handler = (void *)0xdeadbeef;
    IDispatcherQueueHandler *handler_iface = (void *)0xdeadbeef;
    IDispatcherQueue2 *dispatcher_queue2 = (void *)0xdeadbeef;
    IDispatcherQueue *dispatcher_queue = (void *)0xdeadbeef;
    IActivationFactory *factory = (void *)0xdeadbeef;
    IAsyncAction *operation = (void *)0xdeadbeef;
    IAsyncInfo *async_info = (void *)0xdeadbeef;
    EventRegistrationToken token;
    AsyncStatus status;
    HSTRING str = NULL;
    boolean result;
    HRESULT hr;
    DWORD ret;
    LONG ref;

    hr = WindowsCreateString( dispatcher_queue_controller_statics_name, wcslen( dispatcher_queue_controller_statics_name ), &str );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    hr = RoGetActivationFactory( str, &IID_IActivationFactory, (void **)&factory );
    WindowsDeleteString( str );
    ok( hr == S_OK || broken(hr == REGDB_E_CLASSNOTREG), "got hr %#lx.\n", hr );
    if (hr == REGDB_E_CLASSNOTREG)
    {
        win_skip( "%s runtimeclass not registered, skipping tests.\n", wine_dbgstr_w( dispatcher_queue_controller_statics_name ) );
        return;
    }

    check_interface( factory, &IID_IUnknown );
    check_interface( factory, &IID_IInspectable );
    check_interface( factory, &IID_IAgileObject );

    hr = IActivationFactory_QueryInterface( factory, &IID_IDispatcherQueueControllerStatics, (void **)&dispatcher_queue_controller_statics );
    ok( hr == S_OK, "got hr %#lx.\n", hr );

    hr = IDispatcherQueueControllerStatics_CreateOnDedicatedThread( dispatcher_queue_controller_statics, NULL );
    ok( hr == E_POINTER || hr == 0x80000005 /* win10 22h2 */, "got hr %#lx.\n", hr );
    hr = IDispatcherQueueControllerStatics_CreateOnDedicatedThread( dispatcher_queue_controller_statics, &dispatcher_queue_controller );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    if (FAILED(hr)) goto done;

    hr = IDispatcherQueueController_get_DispatcherQueue( dispatcher_queue_controller, NULL );
    ok( hr == E_POINTER || hr == 0x80000005 /* win10 22h2 */, "got hr %#lx.\n", hr );
    hr = IDispatcherQueueController_get_DispatcherQueue( dispatcher_queue_controller, &dispatcher_queue );
    ok( hr == S_OK, "got hr %#lx.\n", hr );

    check_interface( dispatcher_queue, &IID_IUnknown );
    check_interface( dispatcher_queue, &IID_IInspectable );
    check_interface( dispatcher_queue, &IID_IAgileObject );

    hr = create_dispatcher_queue_handler( &handler_iface );
    ok( hr == S_OK, "Unexpected hr %#lx.\n", hr );
    queue_handler = impl_from_IDispatcherQueueHandler( handler_iface );

    hr = IDispatcherQueue_TryEnqueue( dispatcher_queue, handler_iface, &result );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    ok( result == TRUE, "got result %d.\n", result );

    hr = IDispatcherQueue_QueryInterface( dispatcher_queue, &IID_IDispatcherQueue2, (void **)&dispatcher_queue2 );
    ok( hr == S_OK || broken(hr == E_NOINTERFACE) /* w1064v1809 */, "got hr %#lx.\n", hr );
    if (SUCCEEDED(hr))
    {
        hr = IDispatcherQueue2_get_HasThreadAccess( dispatcher_queue2, &result );
        ok( hr == S_OK, "got hr %#lx.\n", hr );
        ok( result == FALSE, "got result %d.\n", result );
        ref = IDispatcherQueue2_Release( dispatcher_queue2 );
        ok( ref == 3, "got ref %ld.\n", ref );
    }

    hr = create_typed_event_handler_dispatcher_queue( &event_handler_iface );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    event_handler = impl_from_ITypedEventHandler_DispatcherQueue_IInspectable( event_handler_iface );
    hr = IDispatcherQueue_add_ShutdownCompleted( dispatcher_queue, event_handler_iface, &token );
    ok( hr == S_OK, "got hr %#lx.\n", hr );

    hr = IDispatcherQueueController_ShutdownQueueAsync( dispatcher_queue_controller, NULL );
    ok( hr == E_POINTER || hr == 0x80000005 /* win10 22h2 */, "got hr %#lx.\n", hr );
    hr = IDispatcherQueueController_ShutdownQueueAsync( dispatcher_queue_controller, &operation );
    ok( hr == S_OK, "got hr %#lx.\n", hr );

    check_interface( operation, &IID_IInspectable );
    check_interface( operation, &IID_IAgileObject );
    check_interface( operation, &IID_IAsyncAction );

    hr = IAsyncAction_QueryInterface( operation, &IID_IAsyncInfo, (void **)&async_info );
    ok( hr == S_OK, "got hr %#lx.\n", hr );

    hr = IAsyncInfo_get_Status( async_info, &status );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    ok( status == Started, "got status %d.\n", status );

    /* shutdown waits for queued handlers */
    if (winetest_platform_is_wine) Sleep( 200 );
    ret = WaitForSingleObject( event_handler->event, 100 );
    ok( ret == WAIT_TIMEOUT, "Unexpected wait result %lu.\n", ret );

    SetEvent( queue_handler->event );
    ret = WaitForSingleObject( event_handler->event, 5000 );
    ok( !ret, "Unexpected wait result %lu.\n", ret );
    ok( !!queue_handler->invocation_thread, "handler was not invoked.\n" );
    ok( queue_handler->invocation_thread != GetCurrentThreadId(), "handler ran on caller thread.\n" );

    hr = IAsyncInfo_get_Status( async_info, &status );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    ok( status == Completed, "got status %d.\n", status );

    hr = IAsyncInfo_Close( async_info );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    ref = IAsyncInfo_Release( async_info );
    ok( ref == 2, "got ref %ld.\n", ref );
    ref = IAsyncAction_Release( operation );
    ok( ref == 1, "got ref %ld.\n", ref );
    hr = IDispatcherQueue_remove_ShutdownCompleted( dispatcher_queue, token );
    ok( hr == S_OK, "got hr %#lx.\n", hr );

    hr = IDispatcherQueue_TryEnqueue( dispatcher_queue, handler_iface, &result );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    ok( result == FALSE, "got result %d.\n", result );

    ref = ITypedEventHandler_DispatcherQueue_IInspectable_Release( event_handler_iface );
    ok( ref == 0, "got ref %ld.\n", ref );
    ref = IDispatcherQueueHandler_Release( handler_iface );
    ok( ref == 0, "got ref %ld.\n", ref );
    IDispatcherQueue_Release( dispatcher_queue );
    IDispatcherQueueController_Release( dispatcher_queue_controller );
done:
    ref = IDispatcherQueueControllerStatics_Release( dispatcher_queue_controller_statics );
    ok( ref == 2, "got ref %ld.\n", ref );
    ref = IActivationFactory_Release( factory );
    ok( ref == 1, "got ref %ld.\n", ref );
}

static void test_DispatcherQueue_priority(void)
{
    ITypedEventHandler_DispatcherQueue_IInspectable *event_handler_iface;
    struct typed_event_handler_dispatcher_queue *event_handler;
    IDispatcherQueueController *controller;
    IDispatcherQueueController *duplicate = (void *)0xdeadbeef;
    struct dispatcher_queue_handler *high, *normal, *low;
    IDispatcherQueueHandler *high_iface, *normal_iface, *low_iface;
    struct DispatcherQueueOptions options = {sizeof(options), DQTYPE_THREAD_CURRENT, DQTAT_COM_ASTA};
    IDispatcherQueue *queue;
    IAsyncAction *operation;
    EventRegistrationToken token;
    boolean result;
    LONG order = 0;
    HRESULT hr;
    DWORD ret;

    hr = CreateDispatcherQueueController( options, &controller );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    hr = CreateDispatcherQueueController( options, &duplicate );
    ok( FAILED(hr), "duplicate current-thread queue returned hr %#lx.\n", hr );
    ok( duplicate == NULL, "got duplicate controller %p.\n", duplicate );
    hr = IDispatcherQueueController_get_DispatcherQueue( controller, &queue );
    ok( hr == S_OK, "got hr %#lx.\n", hr );

    hr = create_dispatcher_queue_handler( &low_iface );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    hr = create_dispatcher_queue_handler( &normal_iface );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    hr = create_dispatcher_queue_handler( &high_iface );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    low = impl_from_IDispatcherQueueHandler( low_iface );
    normal = impl_from_IDispatcherQueueHandler( normal_iface );
    high = impl_from_IDispatcherQueueHandler( high_iface );
    low->order = normal->order = high->order = &order;
    SetEvent( low->event );
    SetEvent( normal->event );
    SetEvent( high->event );

    hr = IDispatcherQueue_TryEnqueueWithPriority( queue, DispatcherQueuePriority_Low, low_iface, &result );
    ok( hr == S_OK && result, "got hr %#lx, result %d.\n", hr, result );
    hr = IDispatcherQueue_TryEnqueueWithPriority( queue, DispatcherQueuePriority_Normal, normal_iface, &result );
    ok( hr == S_OK && result, "got hr %#lx, result %d.\n", hr, result );
    hr = IDispatcherQueue_TryEnqueueWithPriority( queue, DispatcherQueuePriority_High, high_iface, &result );
    ok( hr == S_OK && result, "got hr %#lx, result %d.\n", hr, result );

    ret = msg_wait_for_events( 1, &low->invoked_event, 5000 );
    ok( !ret, "Unexpected wait result %lu.\n", ret );
    ok( high->invocation_order == 1, "high priority ran at %ld.\n", high->invocation_order );
    ok( normal->invocation_order == 2, "normal priority ran at %ld.\n", normal->invocation_order );
    ok( low->invocation_order == 3, "low priority ran at %ld.\n", low->invocation_order );
    ok( high->invocation_thread == GetCurrentThreadId(), "high priority ran on thread %lu.\n", high->invocation_thread );
    ok( normal->invocation_thread == GetCurrentThreadId(), "normal priority ran on thread %lu.\n", normal->invocation_thread );
    ok( low->invocation_thread == GetCurrentThreadId(), "low priority ran on thread %lu.\n", low->invocation_thread );

    hr = create_typed_event_handler_dispatcher_queue( &event_handler_iface );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    event_handler = impl_from_ITypedEventHandler_DispatcherQueue_IInspectable( event_handler_iface );
    hr = IDispatcherQueue_add_ShutdownCompleted( queue, event_handler_iface, &token );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    hr = IDispatcherQueueController_ShutdownQueueAsync( controller, &operation );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    ret = msg_wait_for_events( 1, &event_handler->event, 5000 );
    ok( !ret, "Unexpected wait result %lu.\n", ret );

    IAsyncAction_Release( operation );
    IDispatcherQueue_remove_ShutdownCompleted( queue, token );
    ITypedEventHandler_DispatcherQueue_IInspectable_Release( event_handler_iface );
    IDispatcherQueueHandler_Release( high_iface );
    IDispatcherQueueHandler_Release( normal_iface );
    IDispatcherQueueHandler_Release( low_iface );
    IDispatcherQueue_Release( queue );
    IDispatcherQueueController_Release( controller );
}

struct session_thread_context
{
    IUnknown *session;
    DWORD thread_id;
    HRESULT open_hr;
    HRESULT create_hr;
};

static DWORD WINAPI session_thread_proc( void *param )
{
    struct session_thread_context *context = param;
    IUnknown *existing = (void *)0xdeadbeef;

    context->thread_id = GetCurrentThreadId();
    context->open_hr = CoreUIOpenExisting( &existing );
    ok( context->open_hr == S_OK, "CoreUIOpenExisting failed, hr %#lx.\n", context->open_hr );
    ok( !existing, "got existing session %p on a new thread.\n", existing );
    context->create_hr = CoreUICreate( &context->session );
    return 0;
}

static void test_CoreUI_session(void)
{
    static const WCHAR dispatcher_queue_name[] = L"Windows.System.DispatcherQueue";
    session_get_object_fn get_loop;
    loop_get_thread_id_fn get_thread_id;
    loop_get_bool_fn get_is_running;
    queue_interop_get_fn get_dispatcher_queue;
    IDispatcherQueue *queue = (void *)0xdeadbeef, *queue2 = (void *)0xdeadbeef;
    struct session_thread_context context = {0};
    IUnknown *session = (void *)0xdeadbeef, *session2 = (void *)0xdeadbeef;
    IUnknown *loop = NULL, *interop = NULL, *queue_unknown = NULL;
    IDispatcherQueueStatics *queue_statics = NULL;
    HSTRING class_name = NULL;
    HANDLE thread;
    DWORD thread_id = 0;
    BOOL running = TRUE;
    HRESULT hr;

    hr = CoreUIOpenExisting( NULL );
    ok( hr == E_POINTER, "got CoreUIOpenExisting hr %#lx.\n", hr );
    hr = CoreUICreate( NULL );
    ok( hr == E_POINTER, "got CoreUICreate hr %#lx.\n", hr );
    hr = CoreUICreateEx( 4, &session );
    ok( hr == E_INVALIDARG, "got CoreUICreateEx hr %#lx.\n", hr );
    ok( !session, "got session %p.\n", session );

    hr = CoreUIOpenExisting( &session );
    ok( hr == S_OK, "CoreUIOpenExisting failed, hr %#lx.\n", hr );
    ok( !session, "got unexpected session %p.\n", session );

    hr = CoreUICreate( &session );
    ok( hr == S_OK, "CoreUICreate failed, hr %#lx.\n", hr );
    ok( !!session, "got null session.\n" );
    check_interface( session, &IID_IMessageSession );
    check_interface( session, &IID_IMessageLoopExtensions );
    check_interface( session, &IID_IExportDispatcherQueueInterop );

    hr = CoreUICreate( &session2 );
    ok( hr == S_OK, "second CoreUICreate failed, hr %#lx.\n", hr );
    ok( session2 == session, "session identity changed, %p != %p.\n", session2, session );
    IUnknown_Release( session2 );
    session2 = NULL;

    hr = CoreUIOpenExisting( &session2 );
    ok( hr == S_OK, "CoreUIOpenExisting failed, hr %#lx.\n", hr );
    ok( session2 == session, "existing session identity changed, %p != %p.\n", session2, session );
    IUnknown_Release( session2 );

    get_loop = private_method( session, 5 );
    hr = get_loop( session, &loop );
    ok( hr == S_OK, "GetMessageLoopExtensions failed, hr %#lx.\n", hr );
    ok( !!loop, "got null loop extensions.\n" );
    get_thread_id = private_method( loop, 10 );
    hr = get_thread_id( loop, &thread_id );
    ok( hr == S_OK, "GetThreadID failed, hr %#lx.\n", hr );
    ok( thread_id == GetCurrentThreadId(), "got thread id %lu, expected %lu.\n",
        thread_id, GetCurrentThreadId() );
    get_is_running = private_method( loop, 5 );
    hr = get_is_running( loop, &running );
    ok( hr == S_OK, "GetIsRunning failed, hr %#lx.\n", hr );
    ok( !running, "loop is unexpectedly running.\n" );
    hr = ((loop_run_fn)private_method( loop, 3 ))( loop, 3 );
    ok( hr == E_INVALIDARG, "got Run invalid-mode hr %#lx.\n", hr );
    hr = ((loop_run_fn)private_method( loop, 3 ))( loop, 2 );
    ok( hr == S_OK, "Run drain failed, hr %#lx.\n", hr );

    hr = GetDispatcherQueueForCurrentThread( &queue );
    ok( hr == S_OK, "GetDispatcherQueueForCurrentThread failed, hr %#lx.\n", hr );
    ok( !queue, "got unexpected queue %p.\n", queue );
    hr = CreateDispatcherQueueForCurrentThread( &queue );
    ok( hr == S_OK, "CreateDispatcherQueueForCurrentThread failed, hr %#lx.\n", hr );
    ok( !!queue, "got null queue.\n" );
    hr = GetDispatcherQueueForCurrentThread( &queue2 );
    ok( hr == S_OK, "GetDispatcherQueueForCurrentThread failed, hr %#lx.\n", hr );
    ok( queue2 == queue, "queue identity changed, %p != %p.\n", queue2, queue );

    hr = WindowsCreateString( dispatcher_queue_name, ARRAY_SIZE(dispatcher_queue_name) - 1, &class_name );
    ok( hr == S_OK, "WindowsCreateString failed, hr %#lx.\n", hr );
    hr = RoGetActivationFactory( class_name, &IID_IDispatcherQueueStatics, (void **)&queue_statics );
    ok( hr == S_OK, "DispatcherQueue activation failed, hr %#lx.\n", hr );
    WindowsDeleteString( class_name );
    if (SUCCEEDED(hr))
    {
        IDispatcherQueue *queue3 = NULL;

        hr = IDispatcherQueueStatics_GetForCurrentThread( queue_statics, &queue3 );
        ok( hr == S_OK, "GetForCurrentThread failed, hr %#lx.\n", hr );
        ok( queue3 == queue, "static queue identity changed, %p != %p.\n", queue3, queue );
        if (queue3) IDispatcherQueue_Release( queue3 );
        IDispatcherQueueStatics_Release( queue_statics );
    }

    hr = IUnknown_QueryInterface( session, &IID_IExportDispatcherQueueInterop, (void **)&interop );
    ok( hr == S_OK, "dispatcher interop query failed, hr %#lx.\n", hr );
    get_dispatcher_queue = private_method( interop, 4 );
    hr = get_dispatcher_queue( interop, &queue_unknown );
    ok( hr == S_OK, "interop GetDispatcherQueue failed, hr %#lx.\n", hr );
    ok( queue_unknown == (IUnknown *)queue, "interop queue identity changed, %p != %p.\n",
        queue_unknown, queue );
    IUnknown_Release( queue_unknown );
    IUnknown_Release( interop );
    IDispatcherQueue_Release( queue2 );
    IDispatcherQueue_Release( queue );

    thread = CreateThread( NULL, 0, session_thread_proc, &context, 0, NULL );
    ok( !!thread, "CreateThread failed, error %lu.\n", GetLastError() );
    WaitForSingleObject( thread, INFINITE );
    CloseHandle( thread );
    ok( context.create_hr == S_OK, "thread CoreUICreate failed, hr %#lx.\n", context.create_hr );
    ok( !!context.session, "thread got null session.\n" );
    ok( context.session != session, "thread reused session %p.\n", session );
    IUnknown_Release( context.session );

    IUnknown_Release( loop );
    IUnknown_Release( session );
}

static void test_CoreUI_conversation_calling(void)
{
    static const GUID scope = {0x13c90ef2, 0x9df0, 0x48e8, {0xb9, 0xf1, 0x4f, 0xcb, 0x0f, 0xd4, 0x3a, 0x71}};
    IUnknown *session = NULL, *conversation = (void *)0xdeadbeef;
    IUnknown *send = (void *)0xdeadbeef, *receive = (void *)0xdeadbeef, *unknown = NULL, *queried = NULL;
    UINT64 conversation_id = 0, state[2];
    UINT item_id = 0, created_item_id;
    void *buffer = (void *)0xdeadbeef, *buffer2 = (void *)0xdeadbeef;
    join_eager_fn join_eager;
    call_allocate_fn allocate;
    call_buffer_fn submit, cancel;
    conversation_allocate_fn allocate_item;
    conversation_custom_fn allocate_custom;
    conversation_item_fn set_item;
    conversation_item_out_fn get_item;
    conversation_remove_fn remove_item;
    conversation_enumerate_fn enumerate_items;
    conversation_bool_set_fn set_defer;
    conversation_bool_get_fn get_defer;
    conversation_reserve_fn reserve_ids;
    conversation_flush_fn flush_item;
    struct conversation_enum_context enum_context = {0};
    UINT allocated_item = 0, range[4];
    int item_data1, item_data2;
    void *item_data = (void *)0xdeadbeef;
    BOOL defer = FALSE;
    HRESULT hr;

    hr = CoreUICreate( &session );
    ok( hr == S_OK, "CoreUICreate failed, hr %#lx.\n", hr );
    join_eager = private_method( session, 42 );

    hr = join_eager( session, L"test.conversation", L"test.peer", scope, 3, 2, 0,
                     session, &item_id, &conversation_id, &conversation );
    ok( hr == S_OK, "JoinConversationAsEagerClient failed, hr %#lx.\n", hr );
    ok( !!conversation, "got null conversation.\n" );
    check_interface( conversation, &IID_IMessageConversation );
    ok( !!item_id, "got zero item id.\n" );
    ok( !!conversation_id, "got zero conversation id.\n" );
    created_item_id = item_id;

    hr = join_eager( session, NULL, L"test.peer", scope, 3, 2, 0,
                     session, &item_id, &conversation_id, &queried );
    ok( hr == E_POINTER, "got null-name hr %#lx.\n", hr );
    ok( !item_id && !conversation_id && !queried, "outputs not cleared: %u, %s, %p.\n",
        item_id, wine_dbgstr_longlong(conversation_id), queried );

    hr = CoreUICallCreateConversationHost( NULL, conversation, &send, &receive );
    ok( hr == E_POINTER, "got null-session hr %#lx.\n", hr );
    ok( !send && !receive, "outputs not cleared: %p, %p.\n", send, receive );
    hr = CoreUICallCreateConversationHost( session, conversation, NULL, NULL );
    ok( hr == E_POINTER, "got missing-outputs hr %#lx.\n", hr );

    hr = CoreUICallCreateConversationHost( session, conversation, &send, &receive );
    ok( hr == S_OK, "CoreUICallCreateConversationHost failed, hr %#lx.\n", hr );
    ok( !!send && !!receive && send != receive, "got send %p, receive %p.\n", send, receive );
    check_interface( send, &IID_IMessageCallSendHost );
    check_interface( send, &IID_IMessageCallReceiveHost );
    check_interface( receive, &IID_IMessageCallSendHost );
    check_interface( receive, &IID_IMessageCallReceiveHost );
    hr = IUnknown_QueryInterface( receive, &IID_IUnknown, (void **)&unknown );
    ok( hr == S_OK, "receive IUnknown query failed, hr %#lx.\n", hr );
    ok( unknown == send, "IUnknown identity %p differs from send %p.\n", unknown, send );
    IUnknown_Release( unknown );

    allocate_item = private_method( conversation, 3 );
    allocate_custom = private_method( conversation, 4 );
    set_item = private_method( conversation, 5 );
    get_item = private_method( conversation, 6 );
    remove_item = private_method( conversation, 7 );
    enumerate_items = private_method( conversation, 9 );
    set_defer = private_method( conversation, 11 );
    get_defer = private_method( conversation, 12 );
    reserve_ids = private_method( conversation, 13 );
    flush_item = private_method( conversation, 14 );
    hr = allocate_item( conversation, 1, &item_data1, &allocated_item );
    ok( hr == S_OK && !!allocated_item, "AllocateItemForPeer failed, hr %#lx, item %u.\n", hr, allocated_item );
    hr = get_item( conversation, 1, allocated_item, &item_data );
    ok( hr == S_OK && item_data == &item_data1, "GetItem failed, hr %#lx, data %p.\n", hr, item_data );
    hr = set_item( conversation, 1, allocated_item, &item_data2 );
    ok( hr == S_OK, "SetItemData failed, hr %#lx.\n", hr );
    hr = get_item( conversation, 1, allocated_item, &item_data );
    ok( hr == S_OK && item_data == &item_data2, "updated GetItem failed, hr %#lx, data %p.\n", hr, item_data );
    hr = allocate_custom( conversation, 2, 100, &item_data1 );
    ok( hr == S_OK, "AllocateItemForPeerWithCustomID failed, hr %#lx.\n", hr );
    hr = allocate_custom( conversation, 2, 100, &item_data2 );
    ok( hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS), "got duplicate custom ID hr %#lx.\n", hr );
    hr = enumerate_items( conversation, 0, TRUE, TRUE, conversation_enum_callback, &enum_context );
    ok( hr == S_OK, "EnumerateItems failed, hr %#lx.\n", hr );
    ok( enum_context.count == 3, "enumerated %u items.\n", enum_context.count );
    hr = set_defer( conversation, TRUE );
    ok( hr == S_OK, "SetDeferMessageDelivery failed, hr %#lx.\n", hr );
    hr = get_defer( conversation, &defer );
    ok( hr == S_OK && defer, "GetDeferMessageDelivery failed, hr %#lx, defer %d.\n", hr, defer );
    memset( range, 0xcc, sizeof(range) );
    hr = reserve_ids( conversation, 4, range );
    ok( hr == S_OK && range[0] && range[1] == range[0] + 3,
        "ReserveCustomIDSpace failed, hr %#lx, range %u-%u.\n", hr, range[0], range[1] );
    hr = flush_item( conversation, 100 );
    ok( hr == S_OK, "SkipBatchingAndFlushNow failed, hr %#lx.\n", hr );
    hr = remove_item( conversation, 1, allocated_item, TRUE, &item_data );
    ok( hr == S_OK && item_data == &item_data2, "RemoveItem failed, hr %#lx, data %p.\n", hr, item_data );
    item_data = (void *)0xdeadbeef;
    hr = get_item( conversation, 1, allocated_item, &item_data );
    ok( hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND) && !item_data,
        "removed GetItem got hr %#lx, data %p.\n", hr, item_data );

    allocate = private_method( send, 3 );
    submit = private_method( send, 4 );
    cancel = private_method( send, 5 );
    state[0] = 3;
    state[1] = created_item_id;
    hr = allocate( send, state, 2, 32, &buffer );
    ok( hr == S_OK && !!buffer, "AllocateBuffer failed, hr %#lx, buffer %p.\n", hr, buffer );
    hr = allocate( send, state, 2, 32, &buffer2 );
    ok( hr == S_OK && !!buffer2 && buffer2 != buffer,
        "second AllocateBuffer failed, hr %#lx, buffers %p/%p.\n", hr, buffer, buffer2 );
    hr = submit( send, state, 1, buffer, 32 );
    ok( hr == E_INVALIDARG, "got invalid call type hr %#lx.\n", hr );
    hr = submit( send, state, 2, buffer, 32 );
    ok( hr == S_OK, "SubmitBuffer failed, hr %#lx.\n", hr );
    hr = cancel( send, state, 2, buffer2, 32 );
    ok( hr == S_OK, "CancelBuffer failed, hr %#lx.\n", hr );

    IUnknown_Release( receive );
    IUnknown_Release( send );
    IUnknown_Release( conversation );
    IUnknown_Release( session );
}

START_TEST(coremessaging)
{
    HRESULT hr;

    hr = RoInitialize( RO_INIT_MULTITHREADED );
    ok( hr == S_OK, "RoInitialize failed, hr %#lx\n", hr );

    test_CreateDispatcherQueueController();
    test_DispatcherQueueController_Statics();
    test_DispatcherQueue_priority();
    test_CoreUI_session();
    test_CoreUI_conversation_calling();

    RoUninitialize();
}
