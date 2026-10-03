/*
 * Copyright 2001, Ove Kåven, TransGaming Technologies Inc.
 * Copyright 2002 Greg Turner
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

#include <stdio.h>
#include <stdarg.h>
#include <limits.h>
#include <assert.h>
#include <stddef.h>

#include "windef.h"
#include "winbase.h"
#include "winnt.h"
#include "winternl.h"
#include "winsvc.h"
#include "irot.h"
#include "epm.h"
#include "irpcss.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(ole);

static WCHAR rpcssW[] = L"RpcSs";
static HANDLE exit_event;
static SERVICE_STATUS_HANDLE service_handle;

HRESULT __cdecl irpcss_get_thread_seq_id(handle_t h, DWORD *id)
{
    static LONG thread_seq_id;
    *id = InterlockedIncrement(&thread_seq_id);
    return S_OK;
}

static RPC_STATUS RPCSS_Initialize(void)
{
    static unsigned short irot_protseq[] = IROT_PROTSEQ;
    static unsigned short irot_endpoint[] = IROT_ENDPOINT;
    static unsigned short epm_protseq[] = L"ncacn_np";
    static unsigned short epm_endpoint[] = L"\\pipe\\epmapper";
    static unsigned short epm_protseq_lrpc[] = L"ncalrpc";
    static unsigned short epm_endpoint_lrpc[] = L"epmapper";
    static unsigned short wine_epm_endpoint_lrpc[] = L"wine_epmapper";
    static unsigned short irpcss_protseq[] = IRPCSS_PROTSEQ;
    static unsigned short irpcss_endpoint[] = IRPCSS_ENDPOINT;
    static const struct protseq_map
    {
        unsigned short *protseq;
        unsigned short *endpoint;
    } protseqs[] =
    {
        { epm_protseq, epm_endpoint },
        { epm_protseq_lrpc, epm_endpoint_lrpc },
        { epm_protseq_lrpc, wine_epm_endpoint_lrpc },
        { irot_protseq, irot_endpoint },
        { irpcss_protseq, irpcss_endpoint },
    };
    RPC_IF_HANDLE ifspecs[] =
    {
        epm_v3_0_s_ifspec,
        Irot_v0_2_s_ifspec,
        Irpcss_v0_0_s_ifspec,
    };
    RPC_STATUS status;
    int i, j;

    WINE_TRACE("\n");

    for (i = 0, j = 0; i < ARRAY_SIZE(ifspecs); ++i, j = i)
    {
        status = RpcServerRegisterIf(ifspecs[i], NULL, NULL);
        if (status != RPC_S_OK)
            goto fail;
    }

    for (i = 0; i < ARRAY_SIZE(protseqs); ++i)
    {
        status = RpcServerUseProtseqEpW(protseqs[i].protseq, RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
                protseqs[i].endpoint, NULL);
        if (status != RPC_S_OK)
            goto fail;
    }

    status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
    if (status != RPC_S_OK)
        goto fail;

    return RPC_S_OK;

fail:
    for (i = 0; i < j; ++i)
        RpcServerUnregisterIf(ifspecs[i], NULL, FALSE);

    return status;
}

static DWORD WINAPI service_handler( DWORD ctrl, DWORD event_type, LPVOID event_data, LPVOID context )
{
    SERVICE_STATUS status;

    status.dwServiceType             = SERVICE_WIN32;
    status.dwControlsAccepted        = SERVICE_ACCEPT_STOP;
    status.dwWin32ExitCode           = 0;
    status.dwServiceSpecificExitCode = 0;
    status.dwCheckPoint              = 0;
    status.dwWaitHint                = 0;

    switch (ctrl)
    {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        TRACE( "shutting down\n" );
        RpcMgmtStopServerListening( NULL );
        RpcServerUnregisterIf( epm_v3_0_s_ifspec, NULL, TRUE );
        RpcServerUnregisterIf( Irot_v0_2_s_ifspec, NULL, TRUE );
        status.dwCurrentState = SERVICE_STOP_PENDING;
        status.dwControlsAccepted = 0;
        SetServiceStatus( service_handle, &status );
        SetEvent( exit_event );
        return NO_ERROR;
    default:
        FIXME( "got service ctrl %lx\n", ctrl );
        status.dwCurrentState = SERVICE_RUNNING;
        SetServiceStatus( service_handle, &status );
        return NO_ERROR;
    }
}

static void WINAPI ServiceMain( DWORD argc, LPWSTR *argv )
{
    SERVICE_STATUS status;
    RPC_STATUS ret;

    TRACE( "starting service\n" );

    if ((ret = RPCSS_Initialize()))
    {
        WARN("Failed to initialize rpc interfaces, status %ld.\n", ret);
        return;
    }

    exit_event = CreateEventW( NULL, TRUE, FALSE, NULL );

    service_handle = RegisterServiceCtrlHandlerExW( rpcssW, service_handler, NULL );
    if (!service_handle) return;

    status.dwServiceType             = SERVICE_WIN32;
    status.dwCurrentState            = SERVICE_RUNNING;
    status.dwControlsAccepted        = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    status.dwWin32ExitCode           = 0;
    status.dwServiceSpecificExitCode = 0;
    status.dwCheckPoint              = 0;
    status.dwWaitHint                = 10000;
    SetServiceStatus( service_handle, &status );

    WaitForSingleObject( exit_event, INFINITE );

    status.dwCurrentState     = SERVICE_STOPPED;
    status.dwControlsAccepted = 0;
    SetServiceStatus( service_handle, &status );
    TRACE( "service stopped\n" );
}

static int run_standalone(HANDLE stop_event, HANDLE ready_event)
{
    static const WCHAR mutex_name[] = L"__wine_rpcss_standalone_mutex";
    HANDLE shutdown_event = stop_event;
    HANDLE mutex;
    RPC_STATUS ret;
    NTSTATUS status;

    TRACE( "starting standalone host adapter\n" );

    if (!(mutex = CreateMutexW( NULL, TRUE, mutex_name )))
    {
        DWORD error = GetLastError();
        WARN( "Failed to create standalone ownership mutex, error %lu.\n", error );
        return error;
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        TRACE( "standalone host adapter is already running\n" );
        CloseHandle( mutex );
        return 0;
    }

    if ((ret = RPCSS_Initialize()))
    {
        WARN( "Failed to initialize standalone rpc interfaces, status %ld.\n", ret );
        CloseHandle( mutex );
        return ret;
    }

    if (ready_event) SetEvent(ready_event);

    status = 0;
    if (!shutdown_event)
        status = NtSetInformationProcess( GetCurrentProcess(), ProcessWineMakeProcessSystem,
                                          &shutdown_event, sizeof(shutdown_event) );
    if (status || !shutdown_event)
    {
        WARN( "Failed to acquire standalone shutdown event, status %#lx.\n", status );
        RpcMgmtStopServerListening( NULL );
    }
    else
    {
        WaitForSingleObject( shutdown_event, INFINITE );
        RpcMgmtStopServerListening( NULL );
    }
    RpcServerUnregisterIf( epm_v3_0_s_ifspec, NULL, TRUE );
    RpcServerUnregisterIf( Irot_v0_2_s_ifspec, NULL, TRUE );
    RpcServerUnregisterIf( Irpcss_v0_0_s_ifspec, NULL, TRUE );
    RpcMgmtWaitServerListen();
    if (shutdown_event) CloseHandle( shutdown_event );
    if (ready_event) CloseHandle( ready_event );
    CloseHandle( mutex );
    return status ? RtlNtStatusToDosError( status ) : 0;
}

static HANDLE parse_inherited_handle( const WCHAR *string )
{
    WCHAR *end;
    ULONGLONG value;
    DWORD flags;
    HANDLE handle;

    value = wcstoull( string, &end, 16 );
    if (!string[0] || *end || !value || (ULONGLONG)(ULONG_PTR)value != value)
        return NULL;

    handle = (HANDLE)(ULONG_PTR)value;
    if (!GetHandleInformation( handle, &flags )) return NULL;
    return handle;
}

int __cdecl wmain( int argc, WCHAR *argv[] )
{
    static const SERVICE_TABLE_ENTRYW service_table[] =
    {
        { rpcssW, ServiceMain },
        { NULL, NULL }
    };

    if (argc == 2 && !wcscmp( argv[1], L"--standalone" )) return run_standalone( NULL, NULL );
    if (argc == 4 && !wcscmp( argv[1], L"--adapter-child" ))
    {
        HANDLE stop_event = parse_inherited_handle( argv[2] );
        HANDLE ready_event = parse_inherited_handle( argv[3] );

        if (!stop_event || !ready_event) return ERROR_INVALID_HANDLE;
        return run_standalone( stop_event, ready_event );
    }
    StartServiceCtrlDispatcherW( service_table );
    return 0;
}
