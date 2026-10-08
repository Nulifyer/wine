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

#include "ntstatus.h"
#include "winternl.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(ntdll);

static NTSTATUS (WINAPI *server_dispatch)( void *, void * );

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
            FIXME( "Win32 CSR transport is not implemented\n" );
            return STATUS_NOT_IMPLEMENTED;
        }
        if (server) *server = FALSE;
        return STATUS_SUCCESS;
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
