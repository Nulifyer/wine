/* Local COM exporter process identity.
 * Copyright 2026 Nulifyer
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 or
 * any later version.
 */
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>

#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "objbase.h"
#include "rpcdcep.h"
#include "irpcss.h"
#include "wine/list.h"

struct registered_exporter
{
    struct list entry;
    OXID oxid;
    HANDLE process;
};

struct exporter_context
{
    HANDLE server, client;
};

static CRITICAL_SECTION exporters_cs = { NULL, -1, 0, 0, 0, 0 };
static struct list exporters = LIST_INIT(exporters);

static HRESULT get_client_process(handle_t binding, HANDLE *process)
{
    NTSTATUS status = I_RpcOpenClientProcess(binding, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, process);
    return status ? HRESULT_FROM_WIN32(RtlNtStatusToDosError(status)) : S_OK;
}

/* Every retained process object prevents PID reuse from changing ownership.
 * Registry cleanup is demand driven; existing resolver contexts remain valid. */
static struct registered_exporter *find_exporter(OXID oxid)
{
    struct registered_exporter *entry, *next, *found = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(entry, next, &exporters, struct registered_exporter, entry)
    {
        if (WaitForSingleObject(entry->process, 0) == WAIT_OBJECT_0)
        {
            list_remove(&entry->entry);
            CloseHandle(entry->process);
            free(entry);
        }
        else if (entry->oxid == oxid) found = entry;
    }
    return found;
}

HRESULT __cdecl irpcss_register_oxid(handle_t binding, OXID oxid)
{
    struct registered_exporter *entry;
    HANDLE process;
    HRESULT hr = get_client_process(binding, &process);
    if (FAILED(hr)) return hr;

    /* Validate the current Wine identifier format against the transport owner.
     * Identity returned to clients always comes from the retained process. */
    if ((oxid >> 32) != GetProcessId(process))
    {
        CloseHandle(process);
        return E_ACCESSDENIED;
    }
    EnterCriticalSection(&exporters_cs);
    if ((entry = find_exporter(oxid)))
        hr = GetProcessId(entry->process) == GetProcessId(process) ? S_OK : E_ACCESSDENIED;
    else if (!(entry = malloc(sizeof(*entry)))) hr = E_OUTOFMEMORY;
    else
    {
        entry->oxid = oxid;
        entry->process = process;
        process = NULL;
        list_add_tail(&exporters, &entry->entry);
    }
    LeaveCriticalSection(&exporters_cs);
    if (process) CloseHandle(process);
    return hr;
}

HRESULT __cdecl irpcss_revoke_oxid(handle_t binding, OXID oxid)
{
    struct registered_exporter *entry;
    HANDLE process;
    HRESULT hr = get_client_process(binding, &process);
    if (FAILED(hr)) return hr;
    EnterCriticalSection(&exporters_cs);
    if (!(entry = find_exporter(oxid))) hr = CO_E_OBJNOTCONNECTED;
    else if (GetProcessId(entry->process) != GetProcessId(process)) hr = E_ACCESSDENIED;
    else
    {
        list_remove(&entry->entry);
        CloseHandle(entry->process);
        free(entry);
    }
    LeaveCriticalSection(&exporters_cs);
    CloseHandle(process);
    return hr;
}

HRESULT __cdecl irpcss_resolve_oxid(handle_t binding, OXID oxid, ExporterContext *context,
        DWORD *process_id, BOOL *app_silo, HRESULT *app_silo_status)
{
    struct registered_exporter *entry;
    struct exporter_context *result;
    HANDLE process, token;
    DWORD size;
    HRESULT hr;

    *context = NULL;
    *process_id = 0;
    *app_silo = FALSE;
    *app_silo_status = CO_E_NOT_SUPPORTED;
    hr = get_client_process(binding, &process);
    if (FAILED(hr)) return hr;
    if (!(result = malloc(sizeof(*result))))
    {
        CloseHandle(process);
        return E_OUTOFMEMORY;
    }
    result->client = process;
    EnterCriticalSection(&exporters_cs);
    if (!(entry = find_exporter(oxid))) hr = CO_E_OBJNOTCONNECTED;
    else if (!DuplicateHandle(GetCurrentProcess(), entry->process, GetCurrentProcess(),
                              &result->server, 0, FALSE, DUPLICATE_SAME_ACCESS))
        hr = HRESULT_FROM_WIN32(GetLastError());
    LeaveCriticalSection(&exporters_cs);
    if (FAILED(hr))
    {
        CloseHandle(process);
        free(result);
        return hr;
    }
    *process_id = GetProcessId(result->server);
    if (OpenProcessToken(result->server, TOKEN_QUERY, &token))
    {
        if (GetTokenInformation(token, TokenIsAppSilo, app_silo, sizeof(*app_silo), &size))
            *app_silo_status = S_OK;
        CloseHandle(token);
    }
    *context = result;
    return S_OK;
}

static HRESULT check_context_client(handle_t binding, struct exporter_context *context)
{
    HANDLE process;
    HRESULT hr = get_client_process(binding, &process);
    if (FAILED(hr)) return hr;
    hr = GetProcessId(process) == GetProcessId(context->client) ? S_OK : E_ACCESSDENIED;
    CloseHandle(process);
    return hr;
}

HRESULT __cdecl irpcss_query_exporter(handle_t binding, ExporterContext context, BOOL *alive)
{
    struct exporter_context *entry = context;
    HRESULT hr = check_context_client(binding, entry);
    *alive = FALSE;
    if (SUCCEEDED(hr)) *alive = WaitForSingleObject(entry->server, 0) == WAIT_TIMEOUT;
    return hr;
}

void __RPC_USER ExporterContext_rundown(ExporterContext context)
{
    struct exporter_context *entry = context;
    CloseHandle(entry->server);
    CloseHandle(entry->client);
    free(entry);
}

HRESULT __cdecl irpcss_release_exporter(handle_t binding, ExporterContext *context)
{
    HRESULT hr = check_context_client(binding, *context);
    if (FAILED(hr)) return hr;
    ExporterContext_rundown(*context);
    *context = NULL;
    return S_OK;
}
