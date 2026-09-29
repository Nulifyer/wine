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
#include "wine/list.h"

WINE_DEFAULT_DEBUG_CHANNEL(ole);
WINE_DECLARE_DEBUG_CHANNEL(rpcss);

static WCHAR rpcssW[] = L"RpcSs";
static HANDLE exit_event;
static SERVICE_STATUS_HANDLE service_handle;

struct registered_class
{
    struct list entry;
    GUID clsid;
    unsigned int cookie;
    PMInterfacePointer object;
    HANDLE process;
    HANDLE token;
    DWORD process_id;
    DWORD session_id;
    LUID authentication_id;
    unsigned int single_use : 1;
};

static CRITICAL_SECTION registered_classes_cs = { NULL, -1, 0, 0, 0, 0 };
static struct list registered_classes = LIST_INIT(registered_classes);

/* Identity comes from the local RPC transport, not registration arguments or
 * the server thread's impersonation token. Keep the process object alive so
 * a recycled client PID cannot acquire ownership of an old registration. */
static HRESULT scm_get_publisher(handle_t binding, struct registered_class *entry)
{
    TOKEN_STATISTICS statistics;
    DWORD size;
    NTSTATUS status;
    HRESULT hr;

    status = I_RpcOpenClientProcess(binding, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, &entry->process);
    if (status) return HRESULT_FROM_WIN32(RtlNtStatusToDosError(status));
    entry->process_id = GetProcessId(entry->process);
    if (!OpenProcessToken(entry->process, TOKEN_QUERY, &entry->token) ||
        !GetTokenInformation(entry->token, TokenSessionId, &entry->session_id, sizeof(entry->session_id), &size) ||
        !GetTokenInformation(entry->token, TokenStatistics, &statistics, sizeof(statistics), &size))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        if (entry->token) CloseHandle(entry->token);
        CloseHandle(entry->process);
        entry->process = entry->token = NULL;
        return hr;
    }
    entry->authentication_id = statistics.AuthenticationId;
    return S_OK;
}

static void scm_revoke_class(struct registered_class *entry)
{
    list_remove(&entry->entry);
    CloseHandle(entry->token);
    CloseHandle(entry->process);
    free(entry->object);
    free(entry);
}

/* Reap on registry operations, without background polling or callbacks which
 * could race explicit revoke. The retained process handle identifies exit. */
static void scm_reap_classes(void)
{
    struct registered_class *cur, *next;

    LIST_FOR_EACH_ENTRY_SAFE(cur, next, &registered_classes, struct registered_class, entry)
    {
        if (WaitForSingleObject(cur->process, 0) != WAIT_OBJECT_0) continue;
        TRACE_(rpcss)("retiring class %s cookie %u publisher %04lx session %lu\n",
              debugstr_guid(&cur->clsid), cur->cookie, cur->process_id, cur->session_id);
        scm_revoke_class(cur);
    }
}

HRESULT __cdecl irpcss_server_register(handle_t h, const GUID *clsid, unsigned int flags,
        PMInterfacePointer object, unsigned int *cookie)
{
    struct registered_class *entry;
    static LONG next_cookie;
    size_t size;
    HRESULT hr;

    *cookie = 0;
    if (!(entry = calloc(1, sizeof(*entry))))
        return E_OUTOFMEMORY;

    if (FAILED(hr = scm_get_publisher(h, entry)))
    {
        TRACE_(rpcss)("rejecting class %s publisher %04lx identity query %#lx\n",
                     debugstr_guid(clsid), entry->process_id, hr);
        free(entry);
        return hr;
    }

    entry->clsid = *clsid;
    entry->single_use = !(flags & (REGCLS_MULTIPLEUSE | REGCLS_MULTI_SEPARATE));
    size = offsetof(MInterfacePointer, abData) + (size_t)object->ulCntData;
    if (size < object->ulCntData || !(entry->object = malloc(size)))
    {
        CloseHandle(entry->token);
        CloseHandle(entry->process);
        free(entry);
        return E_OUTOFMEMORY;
    }
    entry->object->ulCntData = object->ulCntData;
    memcpy(&entry->object->abData, object->abData, object->ulCntData);
    if (!(entry->cookie = InterlockedIncrement(&next_cookie)))
        entry->cookie = InterlockedIncrement(&next_cookie);

    EnterCriticalSection(&registered_classes_cs);
    scm_reap_classes();
    list_add_tail(&registered_classes, &entry->entry);
    *cookie = entry->cookie;
    TRACE_(rpcss)("registered class %s cookie %u publisher %04lx session %lu authentication %08lx:%08lx\n",
          debugstr_guid(clsid), entry->cookie, entry->process_id, entry->session_id,
          entry->authentication_id.HighPart, entry->authentication_id.LowPart);
    LeaveCriticalSection(&registered_classes_cs);

    return S_OK;
}

HRESULT __cdecl irpcss_server_revoke(handle_t h, unsigned int cookie)
{
    struct registered_class *cur;
    HANDLE process;
    NTSTATUS status;
    DWORD process_id;
    HRESULT hr = S_OK;

    status = I_RpcOpenClientProcess(h, PROCESS_QUERY_LIMITED_INFORMATION, &process);
    if (status) return HRESULT_FROM_WIN32(RtlNtStatusToDosError(status));
    process_id = GetProcessId(process);

    EnterCriticalSection(&registered_classes_cs);
    scm_reap_classes();

    LIST_FOR_EACH_ENTRY(cur, &registered_classes, struct registered_class, entry)
    {
        if (cur->cookie == cookie)
        {
            if (cur->process_id != process_id)
            {
                TRACE_(rpcss)("denying revoke cookie %u caller %04lx publisher %04lx session %lu\n",
                             cookie, process_id, cur->process_id, cur->session_id);
                hr = E_ACCESSDENIED;
            }
            else scm_revoke_class(cur);
            break;
        }
    }

    LeaveCriticalSection(&registered_classes_cs);
    CloseHandle(process);

    return hr;
}

HRESULT __cdecl irpcss_get_class_object(handle_t h, const GUID *clsid,
        PMInterfacePointer *object)
{
    struct registered_class *cur;
    HRESULT hr = E_NOINTERFACE;

    *object = NULL;

    EnterCriticalSection(&registered_classes_cs);
    scm_reap_classes();

    LIST_FOR_EACH_ENTRY(cur, &registered_classes, struct registered_class, entry)
    {
        if (!memcmp(clsid, &cur->clsid, sizeof(*clsid)))
        {
            *object = MIDL_user_allocate(offsetof(MInterfacePointer, abData) + (size_t)cur->object->ulCntData);
            if (*object)
            {
                (*object)->ulCntData = cur->object->ulCntData;
                memcpy((*object)->abData, cur->object->abData, cur->object->ulCntData);
                hr = S_OK;
                if (cur->single_use) scm_revoke_class(cur);
            }
            else hr = E_OUTOFMEMORY;

            break;
        }
    }

    LeaveCriticalSection(&registered_classes_cs);

    return hr;
}

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

static int run_standalone(void)
{
    HANDLE shutdown_event = NULL;
    RPC_STATUS ret;
    NTSTATUS status;

    TRACE( "starting standalone host adapter\n" );

    if ((ret = RPCSS_Initialize()))
    {
        WARN( "Failed to initialize standalone rpc interfaces, status %ld.\n", ret );
        return ret;
    }

    status = NtSetInformationProcess( GetCurrentProcess(), ProcessWineMakeProcessSystem,
                                      &shutdown_event, sizeof(shutdown_event) );
    if (status)
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
    return status ? RtlNtStatusToDosError( status ) : 0;
}

int __cdecl wmain( int argc, WCHAR *argv[] )
{
    static const SERVICE_TABLE_ENTRYW service_table[] =
    {
        { rpcssW, ServiceMain },
        { NULL, NULL }
    };

    if (argc == 2 && !wcscmp( argv[1], L"--standalone" )) return run_standalone();

    StartServiceCtrlDispatcherW( service_table );
    return 0;
}
