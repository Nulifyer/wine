/*
 * Client/server runtime connections
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>
#include <string.h>
#include <wchar.h>

#include "ntstatus.h"
#include "winternl.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(ntdll);

static NTSTATUS (WINAPI *server_dispatch)( void *, void * );
static RTL_SRWLOCK client_lock = RTL_SRWLOCK_INIT;
static HANDLE client_port, client_heap;
static void *client_view, *peer_view;
static SIZE_T client_view_size;

struct csr_connection
{
    ULONGLONG shared_base, static_data, server_pid, reserved;
    ULONG index;
    NTSTATUS status;
    ULONGLONG info;
};

struct csr_capture
{
    ULONG length;
    void *related;
    ULONG count;
    void *free;
    ULONG_PTR offsets[1];
};

struct csr_message
{
    ALPC_PORT_MESSAGE header;
    struct csr_capture *capture;
    ULONG api;
    NTSTATUS status;
    ULONG reserved[2];
    BYTE data[888];
};

struct csr_module_data
{
    ULONG index;
    void *info;
    ULONG length;
};

C_ASSERT( sizeof(struct csr_connection) == 48 );
#ifdef _WIN64
C_ASSERT( FIELD_OFFSET(struct csr_capture, offsets) == 32 );
C_ASSERT( FIELD_OFFSET(struct csr_message, data) == 64 );
C_ASSERT( sizeof(struct csr_message) == 0x3b8 );
C_ASSERT( FIELD_OFFSET(struct csr_module_data, info) == 8 );
C_ASSERT( sizeof(struct csr_module_data) == 24 );
#endif

/* Establish transport and storage before publishing process-local state. */
static NTSTATUS connect_client( const WCHAR *directory, ULONG index, const void *info,
                                ULONG length, NTSTATUS *inline_status )
{
    static const WCHAR section_suffix[] = L"\\SharedSection";
    static const WCHAR port_suffix[] = L"\\ApiPort";
    SECURITY_QUALITY_OF_SERVICE qos = { sizeof(qos), SecurityImpersonation, SECURITY_DYNAMIC_TRACKING, TRUE };
    LPC_SECTION_WRITE write = { sizeof(write) };
    LPC_SECTION_READ read = { sizeof(read) };
    struct csr_connection connection = {0};
    PEB *peb = NtCurrentTeb()->Peb;
    LARGE_INTEGER section_size;
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING name;
    SIZE_T directory_len, shared_size = 0, static_offset;
    ULONG connection_size = sizeof(connection), max_len;
    HANDLE shared_section = NULL, port = NULL, heap = NULL;
    void *shared = NULL;
    WCHAR *path;
    NTSTATUS status;
    ULONG_PTR zero_bits = 0;

    if (!directory) return STATUS_INVALID_PARAMETER;
    directory_len = wcslen( directory );
    if (directory_len > (65535 - sizeof(section_suffix)) / sizeof(WCHAR)) return STATUS_NAME_TOO_LONG;
    if (!(path = RtlAllocateHeap( peb->ProcessHeap, 0,
                                 directory_len * sizeof(WCHAR) + sizeof(section_suffix) )))
        return STATUS_NO_MEMORY;
    memcpy( path, directory, directory_len * sizeof(WCHAR) );
    memcpy( path + directory_len, section_suffix, sizeof(section_suffix) );
    RtlInitUnicodeString( &name, path );
    InitializeObjectAttributes( &attributes, &name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    status = NtOpenSection( &shared_section, SECTION_MAP_READ, &attributes );
    if (status) goto done;

    section_size.QuadPart = 0x10000;
    status = NtCreateSection( &write.SectionHandle, SECTION_ALL_ACCESS, NULL, &section_size,
                              PAGE_READWRITE, SEC_RESERVE, NULL );
    if (status) goto done;
    write.ViewSize = section_size.QuadPart;
    if (index == 1 && length == sizeof(connection.info))
    {
        connection.index = index;
        memcpy( &connection.info, info, length );
    }
    else connection.status = STATUS_INVALID_PARAMETER;
    memcpy( path + directory_len, port_suffix, sizeof(port_suffix) );
    RtlInitUnicodeString( &name, path );
    status = NtConnectPort( &port, &name, &qos, &write, &read, &max_len,
                            &connection, &connection_size );
    NtClose( write.SectionHandle );
    write.SectionHandle = NULL;
    if (status) goto done;
    if (connection_size != sizeof(connection) || !write.ViewBase || !write.TargetViewBase ||
        write.ViewSize < 0x10000 || !connection.shared_base || connection.static_data < connection.shared_base)
    { status = STATUS_INVALID_PARAMETER; goto done; }

#ifdef _WIN64
    /* The WoW64 adapter publishes these actual mappings to the 32-bit PEB. */
    if (NtCurrentTeb()->WowTebOffset) zero_bits = ~0u;
#endif
    status = NtMapViewOfSection( shared_section, NtCurrentProcess(), &shared, zero_bits, 0,
                                 NULL, &shared_size, ViewUnmap, MEM_TOP_DOWN, PAGE_READONLY );
    if (status) goto done;
    static_offset = connection.static_data - connection.shared_base;
    if (static_offset >= shared_size || static_offset % sizeof(ULONG_PTR))
    { status = STATUS_INVALID_PARAMETER; goto done; }
    if (!(heap = RtlCreateHeap( 0x8000, write.ViewBase, write.ViewSize, 0x1000, NULL, NULL )))
    { status = STATUS_NO_MEMORY; goto done; }

    client_heap = heap;
    client_view = write.ViewBase;
    peer_view = write.TargetViewBase;
    client_view_size = write.ViewSize;
    peb->ReadOnlySharedMemoryBase = shared;
    peb->ReadOnlyStaticServerData = (void **)((char *)shared + static_offset);
    peb->CsrServerReadOnlySharedMemoryBase = connection.shared_base;
    client_port = port;
    *inline_status = connection.status;
    port = NULL;
    shared = NULL;
    TRACE( "CSR client connected, view %p peer %p size %#Ix\n", client_view, peer_view, client_view_size );
done:
    if (port) NtClose( port );
    if (shared) NtUnmapViewOfSection( NtCurrentProcess(), shared );
    if (write.SectionHandle) NtClose( write.SectionHandle );
    if (shared_section) NtClose( shared_section );
    RtlFreeHeap( peb->ProcessHeap, 0, path );
    return status;
}

/***********************************************************************
 *           CsrAllocateCaptureBuffer (NTDLL.@)
 */
void *WINAPI CsrAllocateCaptureBuffer( ULONG count, ULONG size )
{
    struct csr_capture *capture = NULL;

#ifdef __i386__
    if (NtCurrentTeb()->WowTebOffset)
        return ULongToPtr( NtWow64CsrAllocateCaptureBuffer( count, size ) );
#endif
#ifdef _WIN64
    ULONG available, allocation_size;

    if (size >= 0x7fffffdc || count >= 0x10000000) return NULL;
    available = 0x7fffffdc - size;
    if (count * 8 >= available || count + 1 >= (available - count * 8) / 3) return NULL;
    allocation_size = (count * 11 + size + 35) & ~3;
    if (client_heap && (capture = RtlAllocateHeap( client_heap, HEAP_ZERO_MEMORY, allocation_size )))
    {
        capture->length = allocation_size;
        capture->free = capture->offsets + count;
    }
#endif
    return capture;
}

/***********************************************************************
 *           CsrFreeCaptureBuffer (NTDLL.@)
 */
void WINAPI CsrFreeCaptureBuffer( void *capture )
{
#ifdef __i386__
    if (NtCurrentTeb()->WowTebOffset)
    {
        NtWow64CsrFreeCaptureBuffer( capture );
        return;
    }
#endif
    RtlFreeHeap( client_heap, 0, capture );
}

/***********************************************************************
 *           CsrAllocateMessagePointer (NTDLL.@)
 */
ULONG WINAPI CsrAllocateMessagePointer( void *buffer, ULONG size, void **pointer )
{
#ifdef __i386__
    if (NtCurrentTeb()->WowTebOffset)
        return NtWow64CsrAllocateMessagePointer( buffer, size, pointer );
#endif
#ifdef _WIN64
    struct csr_capture *capture = buffer;
    ULONG aligned;
    SIZE_T offset, free_offset;

    if (!capture || !pointer || !client_heap || !RtlValidateHeap( client_heap, 0, capture )) return 0;
    if (capture->length < FIELD_OFFSET(struct csr_capture, offsets) ||
        capture->length > RtlSizeHeap( client_heap, 0, capture )) return 0;
    offset = FIELD_OFFSET(struct csr_capture, offsets) + (SIZE_T)capture->count * sizeof(ULONG_PTR);
    free_offset = (ULONG_PTR)capture->free - (ULONG_PTR)capture;
    if (offset > capture->length || sizeof(ULONG_PTR) > capture->length - offset ||
        free_offset < offset + sizeof(ULONG_PTR) || free_offset > capture->length || size > 0x7ffffffe)
        return 0;
    aligned = (size + 3) & ~3;
    if (aligned > capture->length - free_offset) return 0;
    *pointer = size ? capture->free : NULL;
    capture->free = (char *)capture->free + aligned;
    capture->offsets[capture->count++] = size ? (ULONG_PTR)pointer : 0;
    return aligned;
#else
    return 0;
#endif
}

/***********************************************************************
 *           CsrCaptureMessageBuffer (NTDLL.@)
 */
void WINAPI CsrCaptureMessageBuffer( void *capture, const void *source, ULONG size, void **pointer )
{
#ifdef __i386__
    if (NtCurrentTeb()->WowTebOffset)
    {
        NtWow64CsrCaptureMessageBuffer( capture, source, size, pointer );
        return;
    }
#endif
    if (CsrAllocateMessagePointer( capture, size, pointer ) && source && size)
        memcpy( *pointer, source, size );
}

#ifdef _WIN64
struct csr_pointer_state
{
    ULONG_PTR slot, pointer;
};

/* Snapshot mutable shared metadata before dispatch. Restore through validated
 * original slots, never through offsets supplied by the peer. */
static NTSTATUS call_server( struct csr_message *message, struct csr_capture *capture,
                             ULONG api, ULONG length, SIZE_T *reply_size )
{
    struct csr_pointer_state *pointers = NULL;
    struct csr_capture *remote_capture = NULL;
    ULONG count = 0, capture_length = 0, i;
    ULONG_PTR delta = (ULONG_PTR)peer_view - (ULONG_PTR)client_view;
    SIZE_T size = sizeof(*message), offset;
    NTSTATUS status;

    if ((LONG)length < 0)
    {
        length = -length;
        message->header.Type = 0;
    }
    else message->header.Type = message->header.DataInfoOffset = 0;
    message->capture = NULL;
    message->api = api & ~0x10000000;
    if (length > sizeof(message->data)) return message->status = STATUS_INVALID_PARAMETER;
    message->header.DataLength = length + FIELD_OFFSET(struct csr_message, data) - sizeof(message->header);
    message->header.TotalLength = length + FIELD_OFFSET(struct csr_message, data);

    if (server_dispatch)
    {
        message->header.ClientId = NtCurrentTeb()->ClientId;
        status = server_dispatch( message, message );
        if (status < 0) message->status = status;
        return message->status;
    }
    if (!client_port) return message->status = STATUS_PORT_DISCONNECTED;
    if (capture)
    {
        offset = (ULONG_PTR)capture - (ULONG_PTR)client_view;
        if (offset >= client_view_size || client_view_size - offset < FIELD_OFFSET(struct csr_capture, offsets) ||
            !RtlValidateHeap( client_heap, 0, capture ))
            return message->status = STATUS_INVALID_PARAMETER;
        capture_length = capture->length;
        count = capture->count;
        if (capture_length < FIELD_OFFSET(struct csr_capture, offsets) ||
            capture_length > client_view_size - offset || capture_length > RtlSizeHeap( client_heap, 0, capture ) ||
            count > (capture_length - FIELD_OFFSET(struct csr_capture, offsets)) / sizeof(ULONG_PTR))
            return message->status = STATUS_INVALID_PARAMETER;
        if (count && !(pointers = RtlAllocateHeap( NtCurrentTeb()->Peb->ProcessHeap, 0,
                                                  count * sizeof(*pointers) )))
            return message->status = STATUS_NO_MEMORY;
        for (i = 0; i < count; i++)
        {
            pointers[i].slot = capture->offsets[i];
            pointers[i].pointer = 0;
            if (!pointers[i].slot) continue;
            offset = pointers[i].slot - (ULONG_PTR)message;
            if (offset < FIELD_OFFSET(struct csr_message, data) || offset > message->header.TotalLength ||
                sizeof(ULONG_PTR) > message->header.TotalLength - offset) goto invalid;
            memcpy( &pointers[i].pointer, (char *)message + offset, sizeof(ULONG_PTR) );
            offset = pointers[i].pointer - (ULONG_PTR)capture;
            if (offset < FIELD_OFFSET(struct csr_capture, offsets) + count * sizeof(ULONG_PTR) ||
                offset >= capture_length) goto invalid;
        }
        remote_capture = (struct csr_capture *)((ULONG_PTR)capture + delta);
        message->capture = remote_capture;
        capture->free = NULL;
        for (i = 0; i < count; i++)
        {
            if (!pointers[i].slot) continue;
            offset = pointers[i].pointer + delta;
            memcpy( (void *)pointers[i].slot, &offset, sizeof(ULONG_PTR) );
            capture->offsets[i] = pointers[i].slot - (ULONG_PTR)message;
        }
    }
    TRACE( "CSR request api %#lx length %#lx capture %p\n", message->api, length, capture );
    status = NtAlpcSendWaitReceivePort( client_port, ALPC_MSGFLG_SYNC_REQUEST,
                                       &message->header, NULL, &message->header, &size, NULL, NULL );
    if (reply_size) *reply_size = size;
    if (status >= 0 && (size < FIELD_OFFSET(struct csr_message, data) + length ||
        message->header.DataLength < length + FIELD_OFFSET(struct csr_message, data) - sizeof(message->header) ||
        message->capture != remote_capture)) status = STATUS_INVALID_PARAMETER;
    if (capture)
    {
        message->capture = capture;
        if (capture->count != count || capture->length != capture_length) status = STATUS_INVALID_PARAMETER;
        capture->count = count;
        capture->length = capture_length;
        for (i = 0; i < count; i++)
        {
            ULONG_PTR pointer;

            if (capture->offsets[i] != (pointers[i].slot ? pointers[i].slot - (ULONG_PTR)message : 0))
                status = STATUS_INVALID_PARAMETER;
            capture->offsets[i] = pointers[i].slot;
            if (!pointers[i].slot) continue;
            memcpy( &pointer, (void *)pointers[i].slot, sizeof(pointer) );
            offset = pointer - (ULONG_PTR)remote_capture;
            if (offset < FIELD_OFFSET(struct csr_capture, offsets) + count * sizeof(ULONG_PTR) ||
                offset >= capture_length)
            {
                status = STATUS_INVALID_PARAMETER;
                pointer = pointers[i].pointer;
            }
            else pointer -= delta;
            memcpy( (void *)pointers[i].slot, &pointer, sizeof(pointer) );
        }
        capture->free = NULL;
    }
    RtlFreeHeap( NtCurrentTeb()->Peb->ProcessHeap, 0, pointers );
    if (status < 0) message->status = status;
    TRACE( "CSR reply api %#lx transport %#lx status %#lx\n", message->api, status, message->status );
    return message->status;

invalid:
    RtlFreeHeap( NtCurrentTeb()->Peb->ProcessHeap, 0, pointers );
    return message->status = STATUS_INVALID_PARAMETER;
}
#endif

/***********************************************************************
 *           CsrClientCallServer (NTDLL.@)
 */
NTSTATUS WINAPI CsrClientCallServer( void *message, void *capture, ULONG api, ULONG length )
{
#ifdef __i386__
    if (NtCurrentTeb()->WowTebOffset)
        return NtWow64CsrClientCallServer( message, capture, api, length );
#endif
#ifdef _WIN64
    return call_server( message, capture, api, length, NULL );
#else
    return STATUS_NOT_SUPPORTED;
#endif
}

/* Cached module requests share public capture and dispatch ownership. Copy back
 * only a nonnegative, structurally valid reply, including the original length. */
static NTSTATUS connect_module( ULONG index, void *info, ULONG length )
{
#ifdef _WIN64
    struct csr_message message = {0};
    struct csr_module_data *data = (struct csr_module_data *)message.data;
    struct csr_capture *capture;
    void *local_data;
    SIZE_T size = 0;
    NTSTATUS status;

    if (length > 0x7fffffc8 || !(capture = CsrAllocateCaptureBuffer( 1, length ))) return STATUS_NO_MEMORY;
    data->index = index;
    data->length = length;
    CsrCaptureMessageBuffer( capture, info, length, &data->info );
    local_data = data->info;
    status = call_server( &message, capture, 0, sizeof(*data), &size );
    if (status >= 0)
    {
        if (size < FIELD_OFFSET(struct csr_message, data) + sizeof(*data) ||
            data->info != local_data || data->length != length) status = STATUS_INVALID_PARAMETER;
        else memcpy( info, local_data, length );
    }
    CsrFreeCaptureBuffer( capture );
    return status;
#else
    return STATUS_NOT_SUPPORTED;
#endif
}

/***********************************************************************
 *           CsrClientConnectToServer (NTDLL.@)
 */
NTSTATUS WINAPI CsrClientConnectToServer( const WCHAR *directory, ULONG index, void *info,
                                        ULONG length, BOOLEAN *server )
{
    PEB *peb = NtCurrentTeb()->Peb;
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING name;
    ANSI_STRING export;
    HMODULE module;

    TRACE( "%p, %lu, %p, %lu, %p\n", directory, index, info, length, server );

#ifdef __i386__
    if (NtCurrentTeb()->WowTebOffset)
    {
        BOOLEAN native_server;

        status = NtWow64CsrClientConnectToServer( directory, index, info, length, &native_server );
        if (status >= 0 && server) *server = native_server;
        return status;
    }
#endif
    if (info && !length) return STATUS_INVALID_PARAMETER;

    if (RtlImageNtHeader( peb->ImageBaseAddress )->OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_NATIVE)
    {
        if (info)
        {
            NTSTATUS inline_status = STATUS_UNSUCCESSFUL;

#ifdef __i386__
            /* A classic 32-bit runtime has no native 64-bit CSR provider. */
            return STATUS_NOT_SUPPORTED;
#endif
            RtlAcquireSRWLockExclusive( &client_lock );
            if (!client_port) status = connect_client( directory, index, info, length, &inline_status );
            RtlReleaseSRWLockExclusive( &client_lock );
            if (status) return status;
            if (inline_status < 0) status = connect_module( index, info, length );
        }
        if (server) *server = FALSE;
        return status;
    }

    RtlEnterCriticalSection( peb->LoaderLock );
    if (!server_dispatch)
    {
        RtlInitUnicodeString( &name, L"csrsrv.dll" );
        status = LdrGetDllHandleEx( LDR_GET_DLL_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   NULL, NULL, &name, &module );
        if (!status)
        {
            RtlInitAnsiString( &export, "CsrCallServerFromServer" );
            status = LdrGetProcedureAddressForCaller( module, &export, 0, (void **)&server_dispatch,
                                                     0, __builtin_return_address(0) );
        }
    }
    RtlLeaveCriticalSection( peb->LoaderLock );

    /* CSRSRV owns and publishes the shared section and static server data. */
    if (!status && server) *server = TRUE;
    return status;
}
