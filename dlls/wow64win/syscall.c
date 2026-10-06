/*
 * WoW64 syscall wrapping
 *
 * Copyright 2021 Alexandre Julliard
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
#include "windef.h"
#include "winbase.h"
#include "winnt.h"
#include "winternl.h"
#include "rtlsupportapi.h"
#include "wow64win_private.h"

static void DECLSPEC_NORETURN stub_syscall( const char *name )
{
    EXCEPTION_RECORD record;

    record.ExceptionCode    = EXCEPTION_WINE_STUB;
    record.ExceptionFlags   = EXCEPTION_NONCONTINUABLE;
    record.ExceptionRecord  = NULL;
    record.ExceptionAddress = stub_syscall;
    record.NumberParameters = 2;
    record.ExceptionInformation[0] = (ULONG_PTR)"win32u";
    record.ExceptionInformation[1] = (ULONG_PTR)name;
    for (;;) RtlRaiseException( &record );
}

struct dcomposition_confirm_frame_info32
{
    UINT64 frame_id;
    BYTE data[32];
    UINT update_count;
    UINT reserved;
    ULONG updates;
};

struct dcomposition_token_surface_update32
{
    ULONG surface;
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
};

struct token_manager_adapter_info32
{
    LUID adapter_luid;
    ULONG render_fence;
    UINT64 reserved;
};

struct token_manager_thread_info32
{
    ULONG stop_event;
    ULONG adapters;
    UINT adapter_count;
    UINT reserved;
};

NTSTATUS WINAPI wow64_NtCreateCompositionSurfaceHandle( UINT *args )
{
    OBJECT_ATTRIBUTES32 *attributes32 = get_ptr( &args );
    ACCESS_MASK access = get_ulong( &args );
    ULONG *surface32 = get_ptr( &args );
    struct object_attr64 attributes;
    HANDLE surface;
    NTSTATUS status;

    status = NtCreateCompositionSurfaceHandle( objattr_32to64( &attributes, attributes32 ),
                                               access, surface32 ? &surface : NULL );
    if (!status) put_handle( surface32, surface );
    return status;
}

NTSTATUS WINAPI wow64_NtBindCompositionSurface( UINT *args )
{
    HANDLE surface = get_handle( &args );
    BOOL enable = get_ulong( &args );
    UINT flags = get_ulong( &args );
    BOOL shared = get_ulong( &args );
    const void *buffer_info = get_ptr( &args );
    UINT64 *binding_id = get_ptr( &args );

    return NtBindCompositionSurface( surface, enable, flags, shared, buffer_info, binding_id );
}

NTSTATUS WINAPI wow64_NtUnBindCompositionSurface( UINT *args )
{
    HANDLE surface = get_handle( &args );
    BOOL release = get_ulong( &args );
    BOOL shared = get_ulong( &args );

    return NtUnBindCompositionSurface( surface, release, shared );
}

NTSTATUS WINAPI wow64_NtDCompositionCreateConnection( UINT *args )
{
    BOOL is_dwm = get_ulong( &args );
    HANDLE event = get_handle( &args );
    ULONG *connection32 = get_ptr( &args );
    HANDLE connection;
    NTSTATUS status;

    status = NtDCompositionCreateConnection( is_dwm, event, connection32 ? &connection : NULL );
    if (!status) put_handle( connection32, connection );
    return status;
}

NTSTATUS WINAPI wow64_NtDCompositionCreateSharedResourceHandle( UINT *args )
{
    UINT type = get_ulong( &args );
    ULONG *handle32 = get_ptr( &args );
    HANDLE handle;
    NTSTATUS status;

    status = NtDCompositionCreateSharedResourceHandle( type, handle32 ? &handle : NULL );
    if (!status) put_handle( handle32, handle );
    return status;
}

NTSTATUS WINAPI wow64_NtDCompositionSetBlurredWallpaperSurface( UINT *args )
{
    HANDLE surface = get_handle( &args );
    const RECT *rect = get_ptr( &args );

    return NtDCompositionSetBlurredWallpaperSurface( surface, rect );
}

NTSTATUS WINAPI wow64_NtDCompositionDestroyConnection( UINT *args )
{
    return NtDCompositionDestroyConnection( get_handle( &args ) );
}

NTSTATUS WINAPI wow64_NtDCompositionBeginFrame( UINT *args )
{
    HANDLE connection = get_handle( &args );
    const struct dcomposition_frame_info *info = get_ptr( &args );
    UINT64 *frame_id = get_ptr( &args );

    return NtDCompositionBeginFrame( connection, info, frame_id );
}

NTSTATUS WINAPI wow64_NtDCompositionConfirmFrame( UINT *args )
{
    HANDLE connection = get_handle( &args );
    const struct dcomposition_confirm_frame_info32 *info32 = get_ptr( &args );
    struct dcomposition_confirm_frame_info info;

    if (!info32) return NtDCompositionConfirmFrame( connection, NULL );
    info.frame_id = info32->frame_id;
    memcpy( info.data, info32->data, sizeof(info.data) );
    info.update_count = info32->update_count;
    info.reserved = info32->reserved;
    info.updates = ULongToPtr( info32->updates );
    return NtDCompositionConfirmFrame( connection, &info );
}

NTSTATUS WINAPI wow64_NtDCompositionGetFrameId( UINT *args )
{
    UINT type = get_ulong( &args );
    UINT64 *frame_id = get_ptr( &args );

    return NtDCompositionGetFrameId( type, frame_id );
}

NTSTATUS WINAPI wow64_NtDCompositionGetFrameLegacyTokens( UINT *args )
{
    const UINT64 *frame_id = get_ptr( &args );
    UINT *token_count = get_ptr( &args );
    BOOL *has_more = get_ptr( &args );

    return NtDCompositionGetFrameLegacyTokens( frame_id, token_count, has_more );
}

NTSTATUS WINAPI wow64_NtDCompositionGetFrameSurfaceUpdates( UINT *args )
{
    const UINT64 *frame_id = get_ptr( &args );
    UINT *update_count = get_ptr( &args );
    BOOL *has_more = get_ptr( &args );

    return NtDCompositionGetFrameSurfaceUpdates( frame_id, update_count, has_more );
}

NTSTATUS WINAPI wow64_NtDCompositionCreateChannel( UINT *args )
{
    UINT *channel = get_ptr( &args );
    UINT *section_size = get_ptr( &args );
    ULONG *address32 = get_ptr( &args );
    UINT flags = get_ulong( &args );
    void *address;
    NTSTATUS status;

    status = NtDCompositionCreateChannel( channel, section_size,
                                          address32 ? &address : NULL, flags );
    if (!status) put_addr( address32, address );
    return status;
}

NTSTATUS WINAPI wow64_NtDCompositionCreateAndBindSharedSection( UINT *args )
{
    UINT channel = get_ulong( &args );
    UINT resource_id = get_ulong( &args );
    UINT64 size = get_ulong( &args );
    ULONG *section32 = get_ptr( &args );
    HANDLE section;
    NTSTATUS status;

    status = NtDCompositionCreateAndBindSharedSection( channel, resource_id, size,
                                                       section32 ? &section : NULL );
    if (!status) put_handle( section32, section );
    return status;
}

NTSTATUS WINAPI wow64_NtDCompositionDestroyChannel( UINT *args )
{
    return NtDCompositionDestroyChannel( get_ulong( &args ) );
}

NTSTATUS WINAPI wow64_NtDCompositionProcessChannelBatchBuffer( UINT *args )
{
    UINT channel = get_ulong( &args );
    UINT length = get_ulong( &args );
    ULONG *processed = get_ptr( &args );
    BYTE *released = get_ptr( &args );

    return NtDCompositionProcessChannelBatchBuffer( channel, length, processed, released );
}

NTSTATUS WINAPI wow64_NtDCompositionGetBatchId( UINT *args )
{
    UINT channel = get_ulong( &args );
    UINT selector = get_ulong( &args );
    UINT *batch_id = get_ptr( &args );

    return NtDCompositionGetBatchId( channel, selector, batch_id );
}

NTSTATUS WINAPI wow64_NtDCompositionSetChannelConnectionId( UINT *args )
{
    UINT channel = get_ulong( &args );
    INT connection_id = get_ulong( &args );
    UINT64 connection = get_ulong( &args );

    return NtDCompositionSetChannelConnectionId( channel, connection_id, connection );
}

NTSTATUS WINAPI wow64_NtDCompositionSetChannelCommitCompletionEvent( UINT *args )
{
    UINT channel = get_ulong( &args );
    HANDLE event = get_handle( &args );
    BOOL internal = get_ulong( &args );

    return NtDCompositionSetChannelCommitCompletionEvent( channel, event, internal );
}

NTSTATUS WINAPI wow64_NtDCompositionGetConnectionBatch( UINT *args )
{
    HANDLE connection = get_handle( &args );
    UINT64 *batch_id = get_ptr( &args );
    ULONG *batch32 = get_ptr( &args );
    struct dcomposition_connection_batch *batch;
    NTSTATUS status;

    status = NtDCompositionGetConnectionBatch( connection, batch_id,
                                                batch32 ? &batch : NULL );
    if (!status) put_addr( batch32, batch );
    return status;
}

NTSTATUS WINAPI wow64_NtDCompositionReleaseAllResources( UINT *args )
{
    UINT channel = get_ulong( &args );
    BYTE *result = get_ptr( &args );

    return NtDCompositionReleaseAllResources( channel, result );
}

NTSTATUS WINAPI wow64_NtDCompositionGetDeletedResources( UINT *args )
{
    UINT channel = get_ulong( &args );
    UINT capacity = get_ulong( &args );
    ULONG *resources32 = get_ptr( &args );
    UINT *count = get_ptr( &args );
    void *resources;
    NTSTATUS status;

    status = NtDCompositionGetDeletedResources( channel, capacity,
                                                 resources32 ? &resources : NULL, count );
    if (!status) put_addr( resources32, resources );
    return status;
}

NTSTATUS WINAPI wow64_NtDCompositionCommitChannel( UINT *args )
{
    UINT channel = get_ulong( &args );
    UINT *batch_id = get_ptr( &args );
    BYTE *state = get_ptr( &args );
    ULONG flags = get_ulong( &args );
    HANDLE sync_object = get_handle( &args );
    const void *protocol_blocks = get_ptr( &args );
    const UINT *resources = get_ptr( &args );
    UINT resource_count = get_ulong( &args );

    return NtDCompositionCommitChannel( channel, batch_id, state, flags, sync_object,
                                        protocol_blocks, resources, resource_count );
}

NTSTATUS WINAPI wow64_NtDCompositionGetFrameStatistics( UINT *args )
{
    struct dcomposition_frame_statistics *statistics = get_ptr( &args );
    struct dcomposition_capability_info *capabilities = get_ptr( &args );

    return NtDCompositionGetFrameStatistics( statistics, capabilities );
}

NTSTATUS WINAPI wow64_NtKSTInitialize( UINT *args )
{
    HANDLE stop_event = get_handle( &args );
    HANDLE update_event = get_handle( &args );

    return NtKSTInitialize( stop_event, update_event );
}

NTSTATUS WINAPI wow64_NtKSTWait( UINT *args )
{
    return NtKSTWait();
}

NTSTATUS WINAPI wow64_NtMITCoreMsgKOpenConnectionTo( UINT *args )
{
    UINT selector = get_ulong( &args );
    const void *routing_info = get_ptr( &args );

    return NtMITCoreMsgKOpenConnectionTo( selector, routing_info );
}

NTSTATUS WINAPI wow64_NtMITSetInputCallbacks( UINT *args )
{
    return NtMITSetInputCallbacks( get_ptr( &args ) );
}

NTSTATUS WINAPI wow64_NtUserRegisterManipulationThread( UINT *args )
{
    return NtUserRegisterManipulationThread( get_ptr( &args ) );
}

NTSTATUS WINAPI wow64_NtTokenManagerCreateCompositionTokenHandle( UINT *args )
{
    const struct dcomposition_token_surface_update32 *updates32 = get_ptr( &args );
    UINT update_count = get_ulong( &args );
    UINT surface_count = get_ulong( &args );
    const UINT64 *connection = get_ptr( &args );
    const UINT64 *device = get_ptr( &args );
    ULONG *token32 = get_ptr( &args );
    struct dcomposition_token_surface_update *updates = NULL;
    HANDLE token;
    NTSTATUS status;
    UINT i;

    if (update_count)
    {
        if (!updates32 || !(updates = RtlAllocateHeap( NtCurrentTeb()->Peb->ProcessHeap, 0,
                                                       update_count * sizeof(*updates) )))
            return STATUS_NO_MEMORY;
        for (i = 0; i < update_count; ++i)
        {
            updates[i].surface = LongToHandle( updates32[i].surface );
            updates[i].left = updates32[i].left;
            updates[i].top = updates32[i].top;
            updates[i].right = updates32[i].right;
            updates[i].bottom = updates32[i].bottom;
        }
    }
    status = NtTokenManagerCreateCompositionTokenHandle( updates, update_count, surface_count,
                                                          connection, device,
                                                          token32 ? &token : NULL );
    RtlFreeHeap( NtCurrentTeb()->Peb->ProcessHeap, 0, updates );
    if (!status) put_handle( token32, token );
    return status;
}

NTSTATUS WINAPI wow64_NtTokenManagerOpenSectionAndEvents( UINT *args )
{
    ULONG *section32 = get_ptr( &args );
    ULONG *section_size32 = get_ptr( &args );
    ULONG *event_a32 = get_ptr( &args );
    ULONG *event_b32 = get_ptr( &args );
    HANDLE section, event_a, event_b;
    SIZE_T section_size;
    NTSTATUS status;

    status = NtTokenManagerOpenSectionAndEvents( section32 ? &section : NULL,
                                                 section_size32 ? &section_size : NULL,
                                                 event_a32 ? &event_a : NULL,
                                                 event_b32 ? &event_b : NULL );
    if (!status)
    {
        put_handle( section32, section );
        put_size( section_size32, section_size );
        put_handle( event_a32, event_a );
        put_handle( event_b32, event_b );
    }
    return status;
}

NTSTATUS WINAPI wow64_NtTokenManagerThread( UINT *args )
{
    const struct token_manager_thread_info32 *info32 = get_ptr( &args );
    struct token_manager_adapter_info *adapters = NULL;
    struct token_manager_thread_info info;
    NTSTATUS status;
    UINT i;

    if (!info32) return NtTokenManagerThread( NULL );
    if (info32->adapter_count)
    {
        const struct token_manager_adapter_info32 *adapters32 = ULongToPtr( info32->adapters );

        if (!adapters32 || !(adapters = RtlAllocateHeap( NtCurrentTeb()->Peb->ProcessHeap, 0,
                                                         info32->adapter_count * sizeof(*adapters) )))
            return STATUS_NO_MEMORY;
        for (i = 0; i < info32->adapter_count; ++i)
        {
            adapters[i].adapter_luid = adapters32[i].adapter_luid;
            adapters[i].render_fence = LongToHandle( adapters32[i].render_fence );
            adapters[i].reserved = adapters32[i].reserved;
        }
    }
    info.stop_event = LongToHandle( info32->stop_event );
    info.adapters = adapters;
    info.adapter_count = info32->adapter_count;
    info.reserved = info32->reserved;
    status = NtTokenManagerThread( &info );
    RtlFreeHeap( NtCurrentTeb()->Peb->ProcessHeap, 0, adapters );
    return status;
}

#define SYSCALL_STUB(name) NTSTATUS WINAPI wow64_ ## name( UINT *args ) { stub_syscall( #name ); }
ALL_SYSCALL_STUBS

/* These native interfaces have no 32-bit argument/state adapter yet.  Reuse
 * Wine's existing noncontinuable stub exception rather than returning a value
 * which a BOOL, handle or status consumer could mistake for success.  Remove
 * the corresponding entry when its real WoW64 adapter is implemented. */
SYSCALL_STUB( NtCloseCompositionInputSink )
SYSCALL_STUB( NtCompositionSetDropTarget )
SYSCALL_STUB( NtCreateCompositionInputSink )
SYSCALL_STUB( NtCreateImplicitCompositionInputSink )
SYSCALL_STUB( NtDCompositionSynchronize )
SYSCALL_STUB( NtDCompositionTelemetrySetApplicationId )
SYSCALL_STUB( NtDuplicateCompositionInputSink )
SYSCALL_STUB( NtEnableOneCoreTransformMode )
SYSCALL_STUB( NtGdiDdDDIGetMemoryBudgetTarget )
SYSCALL_STUB( NtGdiDdDDIGetYieldPercentage )
SYSCALL_STUB( NtIsOneCoreTransformMode )
SYSCALL_STUB( NtOpenCompositionSurfaceDirtyRegion )
SYSCALL_STUB( NtOpenCompositionSurfaceRealizationInfo )
SYSCALL_STUB( NtQueryCompositionInputSink )
SYSCALL_STUB( NtQueryCompositionInputSinkLuid )
SYSCALL_STUB( NtQueryCompositionInputSinkViewId )
SYSCALL_STUB( NtQueryCompositionSurfaceBinding )
SYSCALL_STUB( NtQueryCompositionSurfaceRenderingRealization )
SYSCALL_STUB( NtUserAcquireIAMKey )
SYSCALL_STUB( NtUserConfigureActivationObject )
SYSCALL_STUB( NtUserCreateActivationObject )
SYSCALL_STUB( NtUserDestroyActivationObject )
SYSCALL_STUB( NtUserEnableIAMAccess )
SYSCALL_STUB( NtUserForceEnableNumpadTranslation )
SYSCALL_STUB( NtUserGhostWindowFromHungWindow )
SYSCALL_STUB( NtUserHungWindowFromGhostWindow )
SYSCALL_STUB( NtUserIsTopLevelWindow )
SYSCALL_STUB( NtUserIsWindowBroadcastingDpiToChildren )
SYSCALL_STUB( NtUserQueryActivationObject )
SYSCALL_STUB( NtUserReportInertia )
SYSCALL_STUB( NtUserSetForegroundRedirectionForActivationObject )
SYSCALL_STUB( NtUserSetInformationThread )
SYSCALL_STUB( NtUserSetShellChangeNotifyHWND )
SYSCALL_STUB( NtUserSetWindowCompositionTransition )
SYSCALL_STUB( NtValidateCompositionSurfaceHandle )

static void * const win32_syscalls[] =
{
#define SYSCALL_ENTRY(id,name,args) wow64_ ## name,
    ALL_SYSCALLS32
#undef SYSCALL_ENTRY
};

static BYTE arguments[ARRAY_SIZE(win32_syscalls)] =
{
#define SYSCALL_ENTRY(id,name,args) args,
    ALL_SYSCALLS32
#undef SYSCALL_ENTRY
};

const SYSTEM_SERVICE_TABLE sdwhwin32 =
{
    (ULONG_PTR *)win32_syscalls,
    NULL,
    ARRAY_SIZE(win32_syscalls),
    arguments
};


BOOL WINAPI DllMain( HINSTANCE inst, DWORD reason, void *reserved )
{
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    LdrDisableThreadCalloutsForDll( inst );
    NtCurrentTeb()->Peb->KernelCallbackTable = user_callbacks;
    return TRUE;
}
