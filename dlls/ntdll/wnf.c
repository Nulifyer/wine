/*
 * WNF callback delivery over the shared NT subscription transport
 *
 * Copyright 2026 LinuxNT contributors
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

#include <stdarg.h>
#include "ntstatus.h"
#include "winternl.h"
#include "wine/debug.h"
#include "wine/list.h"
#include "ntdll_misc.h"

WINE_DEFAULT_DEBUG_CHANNEL(wnf);

typedef NTSTATUS (WINAPI *wnf_callback)( ULONGLONG, ULONG, const GUID *, void *, const void *, ULONG );
struct rtl_wnf_subscription
{
    struct list entry;
    wnf_callback callback;
    void *context;
    ULONG stamp, references;
    ULONGLONG delivery_serial;
    HANDLE executing_thread;
};
struct rtl_wnf_name
{
    struct list entry, subscriptions;
    ULONGLONG name, id, delivery_serial;
    TP_WORK *work;
    BOOL busy;
    union { WNF_DELIVERY_DESCRIPTOR descriptor; char bytes[4144]; } delivery;
};
static struct list names = LIST_INIT(names);
static RTL_CRITICAL_SECTION lock = { NULL, -1, 0, 0, 0, 0 };
static RTL_CONDITION_VARIABLE completion;
static HANDLE notification_event;
static NTSTATUS dispatcher_error;

static void release_subscription( struct rtl_wnf_subscription *sub )
{
    if (!--sub->references) RtlFreeHeap( GetProcessHeap(), 0, sub );
}
static void destroy_name( struct rtl_wnf_name *name )
{
    list_remove( &name->entry );
    TpReleaseWork( name->work );
    RtlFreeHeap( GetProcessHeap(), 0, name );
}
static void CALLBACK deliver_callbacks( TP_CALLBACK_INSTANCE *instance, void *context, TP_WORK *work )
{
    struct rtl_wnf_name *name = context;
    WNF_DELIVERY_DESCRIPTOR *delivery = &name->delivery.descriptor;
    struct rtl_wnf_subscription *sub, *selected;
    NTSTATUS status;
    RtlEnterCriticalSection( &lock );
    for (;;)
    {
        selected = NULL;
        LIST_FOR_EACH_ENTRY( sub, &name->subscriptions, struct rtl_wnf_subscription, entry )
            if (sub->delivery_serial != name->delivery_serial &&
                ((delivery->EventMask & 16) || sub->stamp != delivery->ChangeStamp))
            { selected = sub; break; }
        if (!selected) break;
        sub = selected;
        sub->stamp = delivery->ChangeStamp;
        sub->delivery_serial = name->delivery_serial;
        sub->references++;
        sub->executing_thread = NtCurrentTeb()->ClientId.UniqueThread;
        RtlLeaveCriticalSection( &lock );
        status = sub->callback( name->name, delivery->ChangeStamp, NULL, sub->context,
                                name->delivery.bytes + delivery->StateDataOffset,
                                delivery->StateDataSize );
        if (status) FIXME( "callback returned %#lx; retry policy is not established\n", status );
        RtlEnterCriticalSection( &lock );
        sub->executing_thread = NULL;
        RtlWakeAllConditionVariable( &completion );
        release_subscription( sub );
    }
    NtGetCompleteWnfStateSubscription( &delivery->StateName, &delivery->SubscriptionId,
                                      delivery->EventMask, STATUS_SUCCESS, NULL, 0 );
    name->busy = FALSE;
    if (list_empty( &name->subscriptions )) destroy_name( name );
    RtlLeaveCriticalSection( &lock );
}
static void WINAPI dispatch_notifications( void *unused )
{
    union { WNF_DELIVERY_DESCRIPTOR descriptor; char bytes[4144]; } delivery;
    struct rtl_wnf_name *name, *selected;
    NTSTATUS status;
    for (;;)
    {
        if ((status = NtWaitForSingleObject( notification_event, FALSE, NULL ))) break;
        while (!(status = NtGetCompleteWnfStateSubscription( NULL, NULL, 0, 0,
                                                            &delivery.descriptor, sizeof(delivery) )))
        {
            RtlEnterCriticalSection( &lock );
            selected = NULL;
            LIST_FOR_EACH_ENTRY( name, &names, struct rtl_wnf_name, entry )
                if (name->name == delivery.descriptor.StateName && name->id == delivery.descriptor.SubscriptionId)
                { selected = name; break; }
            if (selected)
            {
                /* One outstanding NT descriptor gates work for each name. */
                name = selected;
                name->busy = TRUE;
                name->delivery_serial++;
                memcpy( &name->delivery, &delivery, sizeof(delivery) );
                TpPostWork( name->work );
            }
            else NtGetCompleteWnfStateSubscription( &delivery.descriptor.StateName,
                                                    &delivery.descriptor.SubscriptionId,
                                                    delivery.descriptor.EventMask, STATUS_SUCCESS, NULL, 0 );
            RtlLeaveCriticalSection( &lock );
        }
        if (status != STATUS_NO_MORE_ENTRIES) break;
    }
    RtlEnterCriticalSection( &lock );
    dispatcher_error = status;
    RtlLeaveCriticalSection( &lock );
    ERR( "notification dispatcher stopped with %#lx\n", status );
    RtlExitUserThread( status );
}
static NTSTATUS start_dispatcher(void)
{
    HANDLE event, thread;
    NTSTATUS status;
    if (dispatcher_error) return dispatcher_error;
    if (notification_event) return STATUS_SUCCESS;
    if ((status = NtCreateEvent( &event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ))) return status;
    status = RtlCreateUserThread( GetCurrentProcess(), NULL, TRUE, 0, 0, 0,
                                 dispatch_notifications, NULL, &thread, NULL );
    if (status) { NtClose( event ); return status; }
    if ((status = NtSetWnfProcessNotificationEvent( event )))
    {
        NtTerminateThread( thread, status );
        NtClose( thread );
        NtClose( event );
        return status;
    }
    notification_event = event;
    if ((status = NtResumeThread( thread, NULL )))
    {
        NtTerminateThread( thread, status );
        dispatcher_error = status;
    }
    NtClose( thread );
    return status;
}
NTSTATUS WINAPI RtlSubscribeWnfStateChangeNotification( void **subscription, ULONGLONG state,
                                                        ULONG stamp, wnf_callback callback, void *context,
                                                        const GUID *type, ULONG group, ULONG flags )
{
    struct rtl_wnf_name *name, *selected = NULL;
    struct rtl_wnf_subscription *sub;
    BOOL created = FALSE;
    NTSTATUS status;
    if (!subscription || !callback) return STATUS_INVALID_PARAMETER;
    if (type || group || flags) return STATUS_NOT_IMPLEMENTED;
    if (!(sub = RtlAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*sub) ))) return STATUS_NO_MEMORY;
    sub->callback = callback;
    sub->context = context;
    sub->stamp = stamp;
    sub->references = 1;
    RtlEnterCriticalSection( &lock );
    if ((status = start_dispatcher())) goto failed;
    LIST_FOR_EACH_ENTRY( name, &names, struct rtl_wnf_name, entry )
        if (name->name == state && !list_empty( &name->subscriptions )) { selected = name; break; }
    name = selected;
    if (!name)
    {
        if (!(name = RtlAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*name) )))
        { status = STATUS_NO_MEMORY; goto failed; }
        name->name = state;
        list_init( &name->subscriptions );
        if ((status = TpAllocWork( &name->work, deliver_callbacks, name, NULL )))
        { RtlFreeHeap( GetProcessHeap(), 0, name ); goto failed; }
        list_add_tail( &names, &name->entry );
        created = TRUE;
    }
    if ((status = NtSubscribeWnfStateChange( &state, created ? stamp : 0, 17, &name->id )))
    {
        if (created) destroy_name( name );
        goto failed;
    }
    sub->delivery_serial = name->delivery_serial;
    list_add_tail( &name->subscriptions, &sub->entry );
    *subscription = sub;
    RtlLeaveCriticalSection( &lock );
    return STATUS_SUCCESS;
failed:
    RtlLeaveCriticalSection( &lock );
    RtlFreeHeap( GetProcessHeap(), 0, sub );
    return status;
}
NTSTATUS WINAPI RtlUnsubscribeWnfStateChangeNotification( void *subscription )
{
    struct rtl_wnf_name *name, *owner = NULL;
    struct rtl_wnf_subscription *sub, *selected = NULL;
    RtlEnterCriticalSection( &lock );
    LIST_FOR_EACH_ENTRY( name, &names, struct rtl_wnf_name, entry )
    {
        LIST_FOR_EACH_ENTRY( sub, &name->subscriptions, struct rtl_wnf_subscription, entry )
            if (sub == subscription) { selected = sub; owner = name; break; }
        if (selected) break;
    }
    if (!selected) { RtlLeaveCriticalSection( &lock ); return STATUS_INVALID_PARAMETER; }
    sub = selected;
    list_remove( &sub->entry );
    if (list_empty( &owner->subscriptions ))
    {
        NtUnsubscribeWnfStateChange( &owner->name );
        if (!owner->busy) destroy_name( owner );
    }
    while (sub->executing_thread && sub->executing_thread != NtCurrentTeb()->ClientId.UniqueThread)
        RtlSleepConditionVariableCS( &completion, &lock, NULL );
    release_subscription( sub );
    RtlLeaveCriticalSection( &lock );
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI RtlUnsubscribeWnfNotificationWaitForCompletion( void *subscription )
{
    return RtlUnsubscribeWnfStateChangeNotification( subscription );
}
