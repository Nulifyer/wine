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

struct csr_connect_request
{
    ALPC_PORT_MESSAGE header;
    struct csr_capture *capture;
    ULONG api;
    NTSTATUS status;
    ULONG reserved[2];
    ULONG index;
    void *info;
    ULONG length;
};

C_ASSERT( sizeof(struct csr_connection) == 48 );
#ifdef _WIN64
C_ASSERT( FIELD_OFFSET(struct csr_capture, offsets) == 32 );
C_ASSERT( FIELD_OFFSET(struct csr_connect_request, index) == 64 );
C_ASSERT( FIELD_OFFSET(struct csr_connect_request, info) == 72 );
C_ASSERT( sizeof(struct csr_connect_request) == 88 );
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

/* One captured pointer is sufficient for the module connection request.
 * Its storage belongs to the actual port view, never the ordinary process heap. */
static NTSTATUS connect_module( ULONG index, void *info, ULONG length )
{
    struct csr_connect_request request = {0};
    struct csr_capture *capture;
    ULONG allocation_size;
    SIZE_T size = sizeof(request), offset;
    void *data, *remote_data;
    NTSTATUS status;

    if (length > 0x7fffffc8) return STATUS_NO_MEMORY;
    allocation_size = (length + 46) & ~3;
    if (!(capture = RtlAllocateHeap( client_heap, HEAP_ZERO_MEMORY, allocation_size )))
        return STATUS_NO_MEMORY;
    offset = (char *)capture - (char *)client_view;
    if (offset >= client_view_size || allocation_size > client_view_size - offset)
    { status = STATUS_INVALID_PARAMETER; goto done; }
    data = capture + 1;
    remote_data = (char *)peer_view + offset + sizeof(*capture);
    capture->length = allocation_size;
    capture->count = 1;
    capture->offsets[0] = FIELD_OFFSET(struct csr_connect_request, info);
    memcpy( data, info, length );
    request.header.DataLength = sizeof(request) - sizeof(request.header);
    request.header.TotalLength = sizeof(request);
    request.capture = (struct csr_capture *)((char *)peer_view + offset);
    request.index = index;
    request.info = remote_data;
    request.length = length;
    status = NtAlpcSendWaitReceivePort( client_port, ALPC_MSGFLG_SYNC_REQUEST,
                                       &request.header, NULL, &request.header, &size, NULL, NULL );
    if (!status)
    {
        if (size < sizeof(request) || request.header.DataLength < sizeof(request) - sizeof(request.header) ||
            request.capture != (struct csr_capture *)((char *)peer_view + offset) ||
            request.info != remote_data || request.length != length)
            status = STATUS_INVALID_PARAMETER;
        else status = request.status;
    }
    if (status >= 0) memcpy( info, data, length );
done:
    RtlFreeHeap( client_heap, 0, capture );
    return status;
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
