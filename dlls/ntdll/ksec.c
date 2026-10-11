/*
 * Private host adapter for the server-owned Ksec connection transaction.
 * RPCRT4 remains responsible for the native callback and opaque RPC context.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 or later.
 */

#include <stdarg.h>
#include "ntstatus.h"
#include "windef.h"
#include "winternl.h"
#include "wine/exception.h"
#include "wine/debug.h"
#include "ntdll_misc.h"
#include "ksec_rpc.h"

CLIENT_CALL_RETURN (RPC_VAR_ENTRY *ksec_ndr_client_call)(PMIDL_STUB_DESC, PFORMAT_STRING, ...);

void *__RPC_USER MIDL_user_allocate( SIZE_T size )
{
    return RtlAllocateHeap( NtCurrentTeb()->Peb->ProcessHeap, 0, size );
}

void __RPC_USER MIDL_user_free( void *ptr )
{
    RtlFreeHeap( NtCurrentTeb()->Peb->ProcessHeap, 0, ptr );
}

#ifdef __x86_64__
WINE_DEFAULT_DEBUG_CHANNEL(ntdll);

struct ksec_rpc_functions
{
    HMODULE module;
    RPC_STATUS (RPC_ENTRY *compose)(RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR *);
    RPC_STATUS (RPC_ENTRY *from_string)(RPC_WSTR, RPC_BINDING_HANDLE *);
    RPC_STATUS (RPC_ENTRY *free_string)(RPC_WSTR *);
    RPC_STATUS (RPC_ENTRY *free_binding)(RPC_BINDING_HANDLE *);
    void (RPC_ENTRY *destroy_context)(void **);
};

struct ksec_context_work
{
    struct ksec_rpc_functions rpc;
    struct ksec_receipt receipt;
    RPC_BINDING_HANDLE binding;
    KSEC_CONTEXT context;
    HANDLE ready, revoked;
};

static NTSTATUS resolve_ksec_rpc( struct ksec_rpc_functions *rpc )
{
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"rpcrt4.dll");
    ANSI_STRING symbol;
    HMODULE module;
    NTSTATUS status;

    /* No loader mutation or fallback: use the already selected provider. */
    if ((status = LdrGetDllHandleEx( 0, NULL, NULL, &name, &module ))) return status;
    rpc->module = module;
#define RESOLVE(field, export) \
    RtlInitAnsiString( &symbol, export ); \
    if ((status = LdrGetProcedureAddress( module, &symbol, 0, (void **)&field ))) return status
    RESOLVE( rpc->compose, "RpcStringBindingComposeW" );
    RESOLVE( rpc->from_string, "RpcBindingFromStringBindingW" );
    RESOLVE( rpc->free_string, "RpcStringFreeW" );
    RESOLVE( rpc->free_binding, "RpcBindingFree" );
    RESOLVE( rpc->destroy_context, "RpcSsDestroyClientContext" );
    RESOLVE( ksec_ndr_client_call, "NdrClientCall2" );
#undef RESOLVE
    return STATUS_SUCCESS;
}

static DWORD WINAPI cleanup_ksec_context( void *arg )
{
    struct ksec_context_work *work = arg;
    NTSTATUS status;

    /* Publication precedes ready. Revocation can occur before callback return,
     * but cannot let this worker read a partly published context. */
    status = NtWaitForSingleObject( work->ready, FALSE, NULL );
    if (!status) status = NtWaitForSingleObject( work->revoked, FALSE, NULL );
    if (!status)
    {
        __TRY
        {
            if (work->context) work->rpc.destroy_context( &work->context );
            if (work->binding && work->rpc.free_binding( &work->binding )) status = STATUS_UNSUCCESSFUL;
            if (work->context || work->binding) status = STATUS_UNSUCCESSFUL;
        }
        __EXCEPT_ALL
        {
            status = GetExceptionCode();
        }
        __ENDTRY
    }
    work->receipt.cleanup = 1;
    work->receipt.status = status;
    /* A successful local destructor is only an acknowledgement. The server
     * also requires observed transport closure before reusing the generation. */
    WINE_UNIX_CALL( unix_ksec_receipt, &work->receipt );
    NtClose( work->ready );
    NtClose( work->revoked );
    LdrUnloadDll( work->rpc.module );
    MIDL_user_free( work );
    return 0;
}

NTSTATUS dispatch_ksec_connection( const struct ksec_callback_args *args, ULONG len )
{
    struct ksec_context_work *work;
    struct ksec_receipt failed = {0};
    RPC_WSTR string = NULL;
    LONG first = 0, second = 0;
    char device_name[] = "KSecDD";
    NTSTATUS status;
    RPC_STATUS rpc_status = 0;

    if (len != sizeof(*args) || !args->generation || !args->revoked) return STATUS_INVALID_PARAMETER;
    failed.generation = args->generation;
    if (!(work = MIDL_user_allocate( sizeof(*work) ))) status = STATUS_NO_MEMORY;
    else
    {
        memset( work, 0, sizeof(*work) );
        work->revoked = args->revoked;
        work->receipt.generation = args->generation;
        status = resolve_ksec_rpc( &work->rpc );
        if (!status) status = NtCreateEvent( &work->ready, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE );
        if (!status) status = RtlQueueWorkItem( cleanup_ksec_context, work, WT_EXECUTELONGFUNCTION );
    }
    if (status)
    {
        failed.status = status;
        WINE_UNIX_CALL( unix_ksec_receipt, &failed );
        failed.cleanup = 1;
        failed.status = 0; /* No native call or cleanup worker was started. */
        WINE_UNIX_CALL( unix_ksec_receipt, &failed );
        if (work)
        {
            if (work->ready) NtClose( work->ready );
            if (work->rpc.module) LdrUnloadDll( work->rpc.module );
            MIDL_user_free( work );
        }
        NtClose( args->revoked );
        return STATUS_SUCCESS; /* Event ownership was resolved here. */
    }

    TRACE( "Ksec callback provider %p NdrClientCall2 %p generation %s\n", work->rpc.module,
           ksec_ndr_client_call, wine_dbgstr_longlong(args->generation) );
    __TRY
    {
        rpc_status = work->rpc.compose( NULL, (RPC_WSTR)L"ncalrpc", NULL,
                                        (RPC_WSTR)L"lsasspirpc", NULL, &string );
        if (!rpc_status) rpc_status = work->rpc.from_string( string, &work->binding );
        if (string) work->rpc.free_string( &string );
        if (!rpc_status)
            rpc_status = ksec_rpc_connect( work->binding, device_name, 1, &first, &second, &work->context );
        status = rpc_status ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
    }
    __EXCEPT_ALL
    {
        rpc_status = GetExceptionCode();
        status = STATUS_UNSUCCESSFUL;
    }
    __ENDTRY
    if (string) work->rpc.free_string( &string );
    work->receipt.status = status;
    work->receipt.rpc_status = rpc_status;
    work->receipt.has_context = !!work->context;
    work->receipt.first = first;
    work->receipt.second = second;
    status = WINE_UNIX_CALL( unix_ksec_receipt, &work->receipt );
    TRACE( "Ksec connection generation %s rpc=%#lx first=%#lx second=%#lx context=%lu receipt=%#lx\n",
           wine_dbgstr_longlong(args->generation), rpc_status, first, second,
           work->receipt.has_context, status );
    NtSetEvent( work->ready, NULL );
    /* Worker owns the context and both events, including on failed receipt. */
    return STATUS_SUCCESS;
}
#endif
