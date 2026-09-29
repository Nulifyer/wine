/* WinRT DispatcherQueue implementation
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
#include "wine/list.h"

WINE_DEFAULT_DEBUG_CHANNEL(messaging);

#define DISPATCH_QUEUE_MESSAGE (WM_APP + 0x3d)

static const WCHAR dispatcher_queue_window_class[] = L"WineCoreMessagingDispatcherQueue";
static INIT_ONCE dispatcher_queue_init_once = INIT_ONCE_STATIC_INIT;
static DWORD dispatcher_queue_tls = TLS_OUT_OF_INDEXES;

struct dispatcher_queue_task
{
    struct list entry;
    IDispatcherQueueHandler *handler;
};

struct dispatcher_queue_event
{
    struct list entry;
    EventRegistrationToken token;
    IUnknown *handler;
};

struct dispatcher_queue
{
    IDispatcherQueue IDispatcherQueue_iface;
    IDispatcherQueue2 IDispatcherQueue2_iface;
    LONG ref;

    CRITICAL_SECTION cs;
    struct list tasks[3];
    struct list shutdown_starting_handlers;
    struct list shutdown_completed_handlers;
    LONGLONG next_token;

    DWORD thread_id;
    HANDLE thread;
    HANDLE ready_event;
    HANDLE shutdown_event;
    IAsyncAction *shutdown_action;
    HWND window;
    HRESULT init_hr;
    BOOL dedicated;
    BOOL accepting;
    BOOL dispatch_scheduled;
    BOOL shutting_down;
    BOOL shutdown_starting_notified;
    BOOL shutdown_complete;
};

struct dispatcher_queue_controller
{
    IDispatcherQueueController IDispatcherQueueController_iface;
    LONG ref;
    struct dispatcher_queue *queue;
    IAsyncAction *shutdown_action;
};

static inline struct dispatcher_queue *impl_from_IDispatcherQueue( IDispatcherQueue *iface )
{
    return CONTAINING_RECORD( iface, struct dispatcher_queue, IDispatcherQueue_iface );
}

static inline struct dispatcher_queue *impl_from_IDispatcherQueue2( IDispatcherQueue2 *iface )
{
    return CONTAINING_RECORD( iface, struct dispatcher_queue, IDispatcherQueue2_iface );
}

static inline struct dispatcher_queue_controller *impl_from_IDispatcherQueueController( IDispatcherQueueController *iface )
{
    return CONTAINING_RECORD( iface, struct dispatcher_queue_controller, IDispatcherQueueController_iface );
}

static void dispatcher_queue_process( struct dispatcher_queue *queue );

static LRESULT CALLBACK dispatcher_queue_window_proc( HWND window, UINT message, WPARAM wparam, LPARAM lparam )
{
    struct dispatcher_queue *queue = (void *)GetWindowLongPtrW( window, GWLP_USERDATA );

    if (message == WM_NCCREATE)
    {
        CREATESTRUCTW *create = (CREATESTRUCTW *)lparam;

        queue = create->lpCreateParams;
        SetWindowLongPtrW( window, GWLP_USERDATA, (LONG_PTR)queue );
    }
    else if (message == DISPATCH_QUEUE_MESSAGE && queue)
    {
        dispatcher_queue_process( queue );
        return 0;
    }

    return DefWindowProcW( window, message, wparam, lparam );
}

static BOOL CALLBACK dispatcher_queue_global_init( INIT_ONCE *once, void *param, void **context )
{
    WNDCLASSW class = {0};
    ATOM atom;

    class.lpfnWndProc = dispatcher_queue_window_proc;
    class.hInstance = GetModuleHandleW( L"coremessaging.dll" );
    class.lpszClassName = dispatcher_queue_window_class;
    atom = RegisterClassW( &class );
    if (!atom && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return FALSE;

    if ((dispatcher_queue_tls = TlsAlloc()) == TLS_OUT_OF_INDEXES) return FALSE;
    return TRUE;
}

static HRESULT dispatcher_queue_create_window( struct dispatcher_queue *queue )
{
    HINSTANCE instance = GetModuleHandleW( L"coremessaging.dll" );

    queue->window = CreateWindowExW( 0, dispatcher_queue_window_class, NULL, 0, 0, 0, 0, 0,
                                     HWND_MESSAGE, NULL, instance, queue );
    if (!queue->window) return HRESULT_FROM_WIN32( GetLastError() );
    return S_OK;
}

static struct dispatcher_queue_task *dispatcher_queue_pop_task( struct dispatcher_queue *queue )
{
    struct dispatcher_queue_task *task;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(queue->tasks); ++i)
    {
        if (list_empty( &queue->tasks[i] )) continue;
        task = LIST_ENTRY( list_head( &queue->tasks[i] ), struct dispatcher_queue_task, entry );
        list_remove( &task->entry );
        return task;
    }
    return NULL;
}

static void dispatcher_queue_notify_shutdown_starting( struct dispatcher_queue *queue )
{
    ITypedEventHandler_DispatcherQueue_DispatcherQueueShutdownStartingEventArgs *handler;
    struct dispatcher_queue_event *event, *copy, *next;
    struct list copies = LIST_INIT(copies);

    EnterCriticalSection( &queue->cs );
    LIST_FOR_EACH_ENTRY( event, &queue->shutdown_starting_handlers, struct dispatcher_queue_event, entry )
    {
        if (!(copy = calloc( 1, sizeof(*copy) ))) continue;
        IUnknown_AddRef( (copy->handler = event->handler) );
        list_add_tail( &copies, &copy->entry );
    }
    LIST_FOR_EACH_ENTRY_SAFE( copy, next, &copies, struct dispatcher_queue_event, entry )
    {
        handler = (void *)copy->handler;
        ITypedEventHandler_DispatcherQueue_DispatcherQueueShutdownStartingEventArgs_Invoke(
                handler, &queue->IDispatcherQueue_iface, NULL );
        list_remove( &copy->entry );
        IUnknown_Release( copy->handler );
        free( copy );
    }
    LeaveCriticalSection( &queue->cs );
}

static void dispatcher_queue_notify_shutdown_completed( struct dispatcher_queue *queue )
{
    ITypedEventHandler_DispatcherQueue_IInspectable *handler;
    struct dispatcher_queue_event *event, *copy, *next;
    struct list copies = LIST_INIT(copies);

    EnterCriticalSection( &queue->cs );
    LIST_FOR_EACH_ENTRY( event, &queue->shutdown_completed_handlers, struct dispatcher_queue_event, entry )
    {
        if (!(copy = calloc( 1, sizeof(*copy) ))) continue;
        IUnknown_AddRef( (copy->handler = event->handler) );
        list_add_tail( &copies, &copy->entry );
    }
    LIST_FOR_EACH_ENTRY_SAFE( copy, next, &copies, struct dispatcher_queue_event, entry )
    {
        handler = (void *)copy->handler;
        ITypedEventHandler_DispatcherQueue_IInspectable_Invoke( handler, &queue->IDispatcherQueue_iface, NULL );
        list_remove( &copy->entry );
        IUnknown_Release( copy->handler );
        free( copy );
    }
    LeaveCriticalSection( &queue->cs );
}

static void dispatcher_queue_finish( struct dispatcher_queue *queue )
{
    IAsyncAction *shutdown_action;
    IAsyncInfo *async_info;
    AsyncStatus status;
    HWND window;

    EnterCriticalSection( &queue->cs );
    if (queue->shutdown_complete)
    {
        LeaveCriticalSection( &queue->cs );
        return;
    }
    queue->shutdown_complete = TRUE;
    queue->dispatch_scheduled = FALSE;
    window = queue->window;
    queue->window = NULL;
    LeaveCriticalSection( &queue->cs );

    if (TlsGetValue( dispatcher_queue_tls ) == queue) TlsSetValue( dispatcher_queue_tls, NULL );
    if (window)
    {
        SetWindowLongPtrW( window, GWLP_USERDATA, 0 );
        DestroyWindow( window );
    }

    SetEvent( queue->shutdown_event );
    EnterCriticalSection( &queue->cs );
    shutdown_action = queue->shutdown_action;
    queue->shutdown_action = NULL;
    LeaveCriticalSection( &queue->cs );
    if (shutdown_action)
    {
        if (SUCCEEDED(IAsyncAction_QueryInterface( shutdown_action, &IID_IAsyncInfo, (void **)&async_info )))
        {
            do
            {
                IAsyncInfo_get_Status( async_info, &status );
                if (status == Started) SwitchToThread();
            } while (status == Started);
            IAsyncInfo_Release( async_info );
        }
        IAsyncAction_Release( shutdown_action );
    }
    dispatcher_queue_notify_shutdown_completed( queue );
    if (queue->dedicated) PostQuitMessage( 0 );
}

static void dispatcher_queue_process( struct dispatcher_queue *queue )
{
    struct dispatcher_queue_task *task;
    BOOL notify_starting = FALSE;
    BOOL finish;

    EnterCriticalSection( &queue->cs );
    if (queue->shutting_down && !queue->shutdown_starting_notified)
    {
        queue->shutdown_starting_notified = TRUE;
        notify_starting = TRUE;
    }
    LeaveCriticalSection( &queue->cs );

    if (notify_starting) dispatcher_queue_notify_shutdown_starting( queue );

    for (;;)
    {
        EnterCriticalSection( &queue->cs );
        task = dispatcher_queue_pop_task( queue );
        if (!task)
        {
            finish = queue->shutting_down;
            if (!finish) queue->dispatch_scheduled = FALSE;
            LeaveCriticalSection( &queue->cs );
            if (finish) dispatcher_queue_finish( queue );
            return;
        }
        LeaveCriticalSection( &queue->cs );

        IDispatcherQueueHandler_Invoke( task->handler );
        IDispatcherQueueHandler_Release( task->handler );
        free( task );
    }
}

static HRESULT dispatcher_queue_event_add( struct dispatcher_queue *queue, struct list *events,
                                           IUnknown *handler, EventRegistrationToken *token )
{
    struct dispatcher_queue_event *event;

    if (!handler || !token) return E_POINTER;
    if (!(event = calloc( 1, sizeof(*event) ))) return E_OUTOFMEMORY;
    IUnknown_AddRef( (event->handler = handler) );

    EnterCriticalSection( &queue->cs );
    if (queue->shutdown_complete)
    {
        LeaveCriticalSection( &queue->cs );
        IUnknown_Release( event->handler );
        free( event );
        return E_ILLEGAL_METHOD_CALL;
    }
    event->token.value = queue->next_token++;
    *token = event->token;
    list_add_tail( events, &event->entry );
    LeaveCriticalSection( &queue->cs );
    return S_OK;
}

static HRESULT dispatcher_queue_event_remove( struct dispatcher_queue *queue, struct list *events,
                                              EventRegistrationToken token )
{
    struct dispatcher_queue_event *event, *found = NULL;

    EnterCriticalSection( &queue->cs );
    LIST_FOR_EACH_ENTRY( event, events, struct dispatcher_queue_event, entry )
    {
        if (event->token.value != token.value) continue;
        list_remove( &event->entry );
        found = event;
        break;
    }
    LeaveCriticalSection( &queue->cs );

    if (found)
    {
        IUnknown_Release( found->handler );
        free( found );
    }
    return S_OK;
}

static HRESULT WINAPI dispatcher_queue_QueryInterface( IDispatcherQueue *iface, REFIID iid, void **out )
{
    struct dispatcher_queue *queue = impl_from_IDispatcherQueue( iface );

    TRACE( "iface %p, iid %s, out %p.\n", iface, debugstr_guid( iid ), out );

    if (IsEqualGUID( iid, &IID_IUnknown ) || IsEqualGUID( iid, &IID_IInspectable ) ||
        IsEqualGUID( iid, &IID_IAgileObject ) || IsEqualGUID( iid, &IID_IDispatcherQueue ))
        *out = &queue->IDispatcherQueue_iface;
    else if (IsEqualGUID( iid, &IID_IDispatcherQueue2 ))
        *out = &queue->IDispatcherQueue2_iface;
    else
    {
        *out = NULL;
        return E_NOINTERFACE;
    }

    IInspectable_AddRef( (IInspectable *)*out );
    return S_OK;
}

static ULONG WINAPI dispatcher_queue_AddRef( IDispatcherQueue *iface )
{
    struct dispatcher_queue *queue = impl_from_IDispatcherQueue( iface );
    return InterlockedIncrement( &queue->ref );
}

static void dispatcher_queue_destroy( struct dispatcher_queue *queue )
{
    struct dispatcher_queue_task *task, *task_next;
    struct dispatcher_queue_event *event, *event_next;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(queue->tasks); ++i)
    {
        LIST_FOR_EACH_ENTRY_SAFE( task, task_next, &queue->tasks[i], struct dispatcher_queue_task, entry )
        {
            list_remove( &task->entry );
            IDispatcherQueueHandler_Release( task->handler );
            free( task );
        }
    }
    LIST_FOR_EACH_ENTRY_SAFE( event, event_next, &queue->shutdown_starting_handlers,
                              struct dispatcher_queue_event, entry )
    {
        list_remove( &event->entry );
        IUnknown_Release( event->handler );
        free( event );
    }
    LIST_FOR_EACH_ENTRY_SAFE( event, event_next, &queue->shutdown_completed_handlers,
                              struct dispatcher_queue_event, entry )
    {
        list_remove( &event->entry );
        IUnknown_Release( event->handler );
        free( event );
    }
    if (queue->thread_id == GetCurrentThreadId() && TlsGetValue( dispatcher_queue_tls ) == queue)
        TlsSetValue( dispatcher_queue_tls, NULL );
    if (queue->window && queue->thread_id == GetCurrentThreadId()) DestroyWindow( queue->window );
    if (queue->thread) CloseHandle( queue->thread );
    CloseHandle( queue->ready_event );
    CloseHandle( queue->shutdown_event );
    queue->cs.DebugInfo->Spare[0] = 0;
    DeleteCriticalSection( &queue->cs );
    free( queue );
}

static ULONG WINAPI dispatcher_queue_Release( IDispatcherQueue *iface )
{
    struct dispatcher_queue *queue = impl_from_IDispatcherQueue( iface );
    ULONG ref = InterlockedDecrement( &queue->ref );

    if (!ref) dispatcher_queue_destroy( queue );
    return ref;
}

static HRESULT WINAPI dispatcher_queue_GetIids( IDispatcherQueue *iface, ULONG *iid_count, IID **iids )
{
    FIXME( "iface %p, iid_count %p, iids %p stub!\n", iface, iid_count, iids );
    return E_NOTIMPL;
}

static HRESULT WINAPI dispatcher_queue_GetRuntimeClassName( IDispatcherQueue *iface, HSTRING *class_name )
{
    return WindowsCreateString( L"Windows.System.DispatcherQueue",
                                ARRAY_SIZE(L"Windows.System.DispatcherQueue") - 1, class_name );
}

static HRESULT WINAPI dispatcher_queue_GetTrustLevel( IDispatcherQueue *iface, TrustLevel *trust_level )
{
    FIXME( "iface %p, trust_level %p stub!\n", iface, trust_level );
    return E_NOTIMPL;
}

static HRESULT WINAPI dispatcher_queue_CreateTimer( IDispatcherQueue *iface, IDispatcherQueueTimer **result )
{
    FIXME( "iface %p, result %p stub!\n", iface, result );
    if (result) *result = NULL;
    return E_NOTIMPL;
}

static unsigned int dispatcher_queue_priority_index( DispatcherQueuePriority priority )
{
    if (priority == DispatcherQueuePriority_High) return 0;
    if (priority == DispatcherQueuePriority_Normal) return 1;
    return 2;
}

static HRESULT WINAPI dispatcher_queue_TryEnqueueWithPriority( IDispatcherQueue *iface,
                                                               DispatcherQueuePriority priority,
                                                               IDispatcherQueueHandler *callback,
                                                               boolean *result )
{
    struct dispatcher_queue *queue = impl_from_IDispatcherQueue( iface );
    struct dispatcher_queue_task *task;
    BOOL post = FALSE;

    TRACE( "iface %p, priority %d, callback %p, result %p.\n", iface, priority, callback, result );

    if (!callback || !result) return E_POINTER;
    if (priority != DispatcherQueuePriority_Low && priority != DispatcherQueuePriority_Normal &&
        priority != DispatcherQueuePriority_High) return E_INVALIDARG;
    *result = FALSE;
    if (!(task = calloc( 1, sizeof(*task) ))) return E_OUTOFMEMORY;
    IDispatcherQueueHandler_AddRef( (task->handler = callback) );

    EnterCriticalSection( &queue->cs );
    if (queue->accepting)
    {
        list_add_tail( &queue->tasks[dispatcher_queue_priority_index( priority )], &task->entry );
        if (!queue->dispatch_scheduled)
        {
            queue->dispatch_scheduled = TRUE;
            post = TRUE;
        }
        *result = TRUE;
    }
    LeaveCriticalSection( &queue->cs );

    if (!*result)
    {
        IDispatcherQueueHandler_Release( task->handler );
        free( task );
    }
    else if (post && !PostMessageW( queue->window, DISPATCH_QUEUE_MESSAGE, 0, 0 ))
    {
        WARN( "failed to post dispatcher queue message, error %lu.\n", GetLastError() );
        EnterCriticalSection( &queue->cs );
        list_remove( &task->entry );
        queue->dispatch_scheduled = FALSE;
        LeaveCriticalSection( &queue->cs );
        IDispatcherQueueHandler_Release( task->handler );
        free( task );
        *result = FALSE;
    }
    return S_OK;
}

static HRESULT WINAPI dispatcher_queue_TryEnqueue( IDispatcherQueue *iface, IDispatcherQueueHandler *callback,
                                                   boolean *result )
{
    return dispatcher_queue_TryEnqueueWithPriority( iface, DispatcherQueuePriority_Normal, callback, result );
}

static HRESULT WINAPI dispatcher_queue_add_ShutdownStarting(
        IDispatcherQueue *iface,
        ITypedEventHandler_DispatcherQueue_DispatcherQueueShutdownStartingEventArgs *handler,
        EventRegistrationToken *token )
{
    struct dispatcher_queue *queue = impl_from_IDispatcherQueue( iface );
    return dispatcher_queue_event_add( queue, &queue->shutdown_starting_handlers, (IUnknown *)handler, token );
}

static HRESULT WINAPI dispatcher_queue_remove_ShutdownStarting( IDispatcherQueue *iface,
                                                                EventRegistrationToken token )
{
    struct dispatcher_queue *queue = impl_from_IDispatcherQueue( iface );
    return dispatcher_queue_event_remove( queue, &queue->shutdown_starting_handlers, token );
}

static HRESULT WINAPI dispatcher_queue_add_ShutdownCompleted(
        IDispatcherQueue *iface, ITypedEventHandler_DispatcherQueue_IInspectable *handler,
        EventRegistrationToken *token )
{
    struct dispatcher_queue *queue = impl_from_IDispatcherQueue( iface );
    return dispatcher_queue_event_add( queue, &queue->shutdown_completed_handlers, (IUnknown *)handler, token );
}

static HRESULT WINAPI dispatcher_queue_remove_ShutdownCompleted( IDispatcherQueue *iface,
                                                                 EventRegistrationToken token )
{
    struct dispatcher_queue *queue = impl_from_IDispatcherQueue( iface );
    return dispatcher_queue_event_remove( queue, &queue->shutdown_completed_handlers, token );
}

static const struct IDispatcherQueueVtbl dispatcher_queue_vtbl =
{
    dispatcher_queue_QueryInterface,
    dispatcher_queue_AddRef,
    dispatcher_queue_Release,
    dispatcher_queue_GetIids,
    dispatcher_queue_GetRuntimeClassName,
    dispatcher_queue_GetTrustLevel,
    dispatcher_queue_CreateTimer,
    dispatcher_queue_TryEnqueue,
    dispatcher_queue_TryEnqueueWithPriority,
    dispatcher_queue_add_ShutdownStarting,
    dispatcher_queue_remove_ShutdownStarting,
    dispatcher_queue_add_ShutdownCompleted,
    dispatcher_queue_remove_ShutdownCompleted,
};

static HRESULT WINAPI dispatcher_queue2_QueryInterface( IDispatcherQueue2 *iface, REFIID iid, void **out )
{
    struct dispatcher_queue *queue = impl_from_IDispatcherQueue2( iface );
    return IDispatcherQueue_QueryInterface( &queue->IDispatcherQueue_iface, iid, out );
}

static ULONG WINAPI dispatcher_queue2_AddRef( IDispatcherQueue2 *iface )
{
    struct dispatcher_queue *queue = impl_from_IDispatcherQueue2( iface );
    return IDispatcherQueue_AddRef( &queue->IDispatcherQueue_iface );
}

static ULONG WINAPI dispatcher_queue2_Release( IDispatcherQueue2 *iface )
{
    struct dispatcher_queue *queue = impl_from_IDispatcherQueue2( iface );
    return IDispatcherQueue_Release( &queue->IDispatcherQueue_iface );
}

static HRESULT WINAPI dispatcher_queue2_GetIids( IDispatcherQueue2 *iface, ULONG *iid_count, IID **iids )
{
    struct dispatcher_queue *queue = impl_from_IDispatcherQueue2( iface );
    return IDispatcherQueue_GetIids( &queue->IDispatcherQueue_iface, iid_count, iids );
}

static HRESULT WINAPI dispatcher_queue2_GetRuntimeClassName( IDispatcherQueue2 *iface, HSTRING *class_name )
{
    struct dispatcher_queue *queue = impl_from_IDispatcherQueue2( iface );
    return IDispatcherQueue_GetRuntimeClassName( &queue->IDispatcherQueue_iface, class_name );
}

static HRESULT WINAPI dispatcher_queue2_GetTrustLevel( IDispatcherQueue2 *iface, TrustLevel *trust_level )
{
    struct dispatcher_queue *queue = impl_from_IDispatcherQueue2( iface );
    return IDispatcherQueue_GetTrustLevel( &queue->IDispatcherQueue_iface, trust_level );
}

static HRESULT WINAPI dispatcher_queue2_get_HasThreadAccess( IDispatcherQueue2 *iface, boolean *value )
{
    struct dispatcher_queue *queue = impl_from_IDispatcherQueue2( iface );

    if (!value) return E_POINTER;
    *value = queue->thread_id == GetCurrentThreadId();
    return S_OK;
}

static const struct IDispatcherQueue2Vtbl dispatcher_queue2_vtbl =
{
    dispatcher_queue2_QueryInterface,
    dispatcher_queue2_AddRef,
    dispatcher_queue2_Release,
    dispatcher_queue2_GetIids,
    dispatcher_queue2_GetRuntimeClassName,
    dispatcher_queue2_GetTrustLevel,
    dispatcher_queue2_get_HasThreadAccess,
};

static DWORD WINAPI dispatcher_queue_thread_proc( void *param )
{
    struct dispatcher_queue *queue = param;
    HRESULT hr;
    MSG message;

    queue->thread_id = GetCurrentThreadId();
    TlsSetValue( dispatcher_queue_tls, queue );
    hr = RoInitialize( RO_INIT_SINGLETHREADED );
    queue->init_hr = FAILED(hr) ? hr : dispatcher_queue_create_window( queue );
    SetEvent( queue->ready_event );

    if (SUCCEEDED(queue->init_hr))
        while (GetMessageW( &message, NULL, 0, 0 ) > 0)
        {
            TranslateMessage( &message );
            DispatchMessageW( &message );
        }

    TlsSetValue( dispatcher_queue_tls, NULL );
    if (SUCCEEDED(hr)) RoUninitialize();
    IDispatcherQueue_Release( &queue->IDispatcherQueue_iface );
    return 0;
}

static HRESULT dispatcher_queue_create( DispatcherQueueOptions options, struct dispatcher_queue **out )
{
    struct dispatcher_queue *queue;
    unsigned int i;
    HRESULT hr;

    *out = NULL;
    if (!InitOnceExecuteOnce( &dispatcher_queue_init_once, dispatcher_queue_global_init, NULL, NULL ))
        return HRESULT_FROM_WIN32( GetLastError() );
    if (options.threadType == DQTYPE_THREAD_CURRENT && TlsGetValue( dispatcher_queue_tls ))
        return HRESULT_FROM_WIN32( ERROR_ALREADY_EXISTS );
    if (!(queue = calloc( 1, sizeof(*queue) ))) return E_OUTOFMEMORY;

    queue->IDispatcherQueue_iface.lpVtbl = &dispatcher_queue_vtbl;
    queue->IDispatcherQueue2_iface.lpVtbl = &dispatcher_queue2_vtbl;
    queue->ref = 1;
    queue->next_token = 1;
    queue->dedicated = options.threadType == DQTYPE_THREAD_DEDICATED;
    queue->accepting = TRUE;
    for (i = 0; i < ARRAY_SIZE(queue->tasks); ++i) list_init( &queue->tasks[i] );
    list_init( &queue->shutdown_starting_handlers );
    list_init( &queue->shutdown_completed_handlers );
    InitializeCriticalSectionEx( &queue->cs, 0, RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO );
    queue->cs.DebugInfo->Spare[0] = (DWORD_PTR)( __FILE__ ": dispatcher_queue.cs" );

    if (!(queue->ready_event = CreateEventW( NULL, TRUE, FALSE, NULL )) ||
        !(queue->shutdown_event = CreateEventW( NULL, TRUE, FALSE, NULL )))
    {
        hr = HRESULT_FROM_WIN32( GetLastError() );
        dispatcher_queue_destroy( queue );
        return hr;
    }

    if (!queue->dedicated)
    {
        queue->thread_id = GetCurrentThreadId();
        if (FAILED(hr = dispatcher_queue_create_window( queue )))
        {
            dispatcher_queue_destroy( queue );
            return hr;
        }
        if (!TlsSetValue( dispatcher_queue_tls, queue ))
        {
            hr = HRESULT_FROM_WIN32( GetLastError() );
            dispatcher_queue_destroy( queue );
            return hr;
        }
    }
    else
    {
        IDispatcherQueue_AddRef( &queue->IDispatcherQueue_iface );
        if (!(queue->thread = CreateThread( NULL, 0, dispatcher_queue_thread_proc, queue, 0, NULL )))
        {
            hr = HRESULT_FROM_WIN32( GetLastError() );
            IDispatcherQueue_Release( &queue->IDispatcherQueue_iface );
            dispatcher_queue_destroy( queue );
            return hr;
        }
        WaitForSingleObject( queue->ready_event, INFINITE );
        if (FAILED(queue->init_hr))
        {
            hr = queue->init_hr;
            WaitForSingleObject( queue->thread, INFINITE );
            dispatcher_queue_destroy( queue );
            return hr;
        }
    }

    *out = queue;
    return S_OK;
}

HRESULT dispatcher_queue_get_for_current_thread( IDispatcherQueue **out )
{
    struct dispatcher_queue *queue;

    if (!out) return E_POINTER;
    *out = NULL;
    if (!InitOnceExecuteOnce( &dispatcher_queue_init_once, dispatcher_queue_global_init, NULL, NULL ))
        return HRESULT_FROM_WIN32( GetLastError() );

    if ((queue = TlsGetValue( dispatcher_queue_tls )))
        IDispatcherQueue_AddRef( (*out = &queue->IDispatcherQueue_iface) );
    return S_OK;
}

HRESULT dispatcher_queue_create_for_current_thread( IDispatcherQueue **out )
{
    DispatcherQueueOptions options = {sizeof(options), DQTYPE_THREAD_CURRENT, DQTAT_COM_NONE};
    struct dispatcher_queue *queue;
    HRESULT hr;

    if (!out) return E_POINTER;
    *out = NULL;
    if (FAILED(hr = dispatcher_queue_create( options, &queue ))) return hr;
    *out = &queue->IDispatcherQueue_iface;
    return S_OK;
}

static HRESULT WINAPI dispatcher_queue_controller_QueryInterface( IDispatcherQueueController *iface,
                                                                  REFIID iid, void **out )
{
    if (IsEqualGUID( iid, &IID_IUnknown ) || IsEqualGUID( iid, &IID_IInspectable ) ||
        IsEqualGUID( iid, &IID_IAgileObject ) || IsEqualGUID( iid, &IID_IDispatcherQueueController ))
    {
        *out = iface;
        IDispatcherQueueController_AddRef( iface );
        return S_OK;
    }
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI dispatcher_queue_controller_AddRef( IDispatcherQueueController *iface )
{
    struct dispatcher_queue_controller *controller = impl_from_IDispatcherQueueController( iface );
    return InterlockedIncrement( &controller->ref );
}

static ULONG WINAPI dispatcher_queue_controller_Release( IDispatcherQueueController *iface )
{
    struct dispatcher_queue_controller *controller = impl_from_IDispatcherQueueController( iface );
    ULONG ref = InterlockedDecrement( &controller->ref );

    if (!ref)
    {
        if (controller->shutdown_action) IAsyncAction_Release( controller->shutdown_action );
        IDispatcherQueue_Release( &controller->queue->IDispatcherQueue_iface );
        free( controller );
    }
    return ref;
}

static HRESULT WINAPI dispatcher_queue_controller_GetIids( IDispatcherQueueController *iface,
                                                           ULONG *iid_count, IID **iids )
{
    FIXME( "iface %p, iid_count %p, iids %p stub!\n", iface, iid_count, iids );
    return E_NOTIMPL;
}

static HRESULT WINAPI dispatcher_queue_controller_GetRuntimeClassName( IDispatcherQueueController *iface,
                                                                       HSTRING *class_name )
{
    return WindowsCreateString( L"Windows.System.DispatcherQueueController",
                                ARRAY_SIZE(L"Windows.System.DispatcherQueueController") - 1, class_name );
}

static HRESULT WINAPI dispatcher_queue_controller_GetTrustLevel( IDispatcherQueueController *iface,
                                                                 TrustLevel *trust_level )
{
    FIXME( "iface %p, trust_level %p stub!\n", iface, trust_level );
    return E_NOTIMPL;
}

static HRESULT WINAPI dispatcher_queue_controller_get_DispatcherQueue( IDispatcherQueueController *iface,
                                                                       IDispatcherQueue **value )
{
    struct dispatcher_queue_controller *controller = impl_from_IDispatcherQueueController( iface );

    if (!value) return E_POINTER;
    IDispatcherQueue_AddRef( (*value = &controller->queue->IDispatcherQueue_iface) );
    return S_OK;
}

static HRESULT dispatcher_queue_begin_shutdown( struct dispatcher_queue *queue )
{
    BOOL post = FALSE;

    EnterCriticalSection( &queue->cs );
    if (queue->shutting_down)
    {
        LeaveCriticalSection( &queue->cs );
        return E_ILLEGAL_METHOD_CALL;
    }
    queue->accepting = FALSE;
    queue->shutting_down = TRUE;
    if (!queue->dispatch_scheduled)
    {
        queue->dispatch_scheduled = TRUE;
        post = TRUE;
    }
    LeaveCriticalSection( &queue->cs );

    if (post && !PostMessageW( queue->window, DISPATCH_QUEUE_MESSAGE, 0, 0 ))
        return HRESULT_FROM_WIN32( GetLastError() );
    return S_OK;
}

static HRESULT shutdown_queue_async( IUnknown *invoker, IUnknown *param, PROPVARIANT *result, BOOL called_async )
{
    struct dispatcher_queue *queue = impl_from_IDispatcherQueue( (IDispatcherQueue *)invoker );

    if (!called_async) return STATUS_PENDING;
    WaitForSingleObject( queue->shutdown_event, INFINITE );
    return S_OK;
}

static HRESULT WINAPI dispatcher_queue_controller_ShutdownQueueAsync( IDispatcherQueueController *iface,
                                                                      IAsyncAction **operation )
{
    struct dispatcher_queue_controller *controller = impl_from_IDispatcherQueueController( iface );
    HRESULT hr;

    if (!operation) return E_POINTER;
    *operation = NULL;
    if (controller->shutdown_action) return E_ILLEGAL_METHOD_CALL;
    if (FAILED(hr = async_action_create( (IUnknown *)&controller->queue->IDispatcherQueue_iface,
                                         shutdown_queue_async, operation ))) return hr;
    IAsyncAction_AddRef( (controller->shutdown_action = *operation) );
    IAsyncAction_AddRef( (controller->queue->shutdown_action = *operation) );
    if (FAILED(hr = dispatcher_queue_begin_shutdown( controller->queue )))
    {
        SetEvent( controller->queue->shutdown_event );
        IAsyncAction_Release( controller->queue->shutdown_action );
        controller->queue->shutdown_action = NULL;
        IAsyncAction_Release( controller->shutdown_action );
        controller->shutdown_action = NULL;
        IAsyncAction_Release( *operation );
        *operation = NULL;
        return hr;
    }
    return S_OK;
}

static const struct IDispatcherQueueControllerVtbl dispatcher_queue_controller_vtbl =
{
    dispatcher_queue_controller_QueryInterface,
    dispatcher_queue_controller_AddRef,
    dispatcher_queue_controller_Release,
    dispatcher_queue_controller_GetIids,
    dispatcher_queue_controller_GetRuntimeClassName,
    dispatcher_queue_controller_GetTrustLevel,
    dispatcher_queue_controller_get_DispatcherQueue,
    dispatcher_queue_controller_ShutdownQueueAsync,
};

HRESULT dispatcher_queue_controller_create( DispatcherQueueOptions options, IDispatcherQueueController **out )
{
    struct dispatcher_queue_controller *controller;
    struct dispatcher_queue *queue;
    HRESULT hr;

    *out = NULL;
    if (FAILED(hr = dispatcher_queue_create( options, &queue ))) return hr;
    if (!(controller = calloc( 1, sizeof(*controller) )))
    {
        IDispatcherQueue_Release( &queue->IDispatcherQueue_iface );
        return E_OUTOFMEMORY;
    }

    controller->IDispatcherQueueController_iface.lpVtbl = &dispatcher_queue_controller_vtbl;
    controller->ref = 1;
    controller->queue = queue;
    *out = &controller->IDispatcherQueueController_iface;
    return S_OK;
}
