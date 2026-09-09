/*
 * Implementation of svchost.exe
 *
 * Copyright 2007 Google (Roy Shea)
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

/* Usage:
 * Starting a service group:
 *
 *      svchost /k service_group_name
 */

#include <stdarg.h>
#include <ntstatus.h>

#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "winsvc.h"
#include "winternl.h"
#include "rpc.h"
#include "rpcdcep.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(svchost);

static const WCHAR service_reg_path[] = L"System\\CurrentControlSet\\Services";
static const WCHAR svchost_path[] = L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Svchost";

typedef LONG (WINAPI *svchost_start_rpc_server)(RPC_WSTR, RPC_IF_HANDLE);
typedef LONG (WINAPI *svchost_stop_rpc_server)(RPC_IF_HANDLE);
typedef DWORD (WINAPI *svchost_register_stop_callback)(HANDLE *, const WCHAR *, HANDLE,
                                                       WAITORTIMERCALLBACK, void *, DWORD);

/* Only the legacy view starting at sids is exposed. The version-prefixed Ex
 * view and its additional callbacks are not implemented. The three NetBIOS
 * callbacks are NULL on the observed Windows 11 reference. */
struct svchost_global_data
{
    DWORD version;
    DWORD padding;
    PSID sids[18];
    svchost_start_rpc_server start_rpc_server;
    svchost_stop_rpc_server stop_rpc_server;
    svchost_stop_rpc_server stop_rpc_server_ex;
    void *net_bios_open;
    void *net_bios_close;
    void *net_bios_reset;
    svchost_register_stop_callback register_stop_callback_deprecated;
    void *register_stop_callback;
    void *unregister_stop_callback;
};

C_ASSERT(FIELD_OFFSET(struct svchost_global_data, register_stop_callback_deprecated) -
         FIELD_OFFSET(struct svchost_global_data, sids) == 24 * sizeof(void *));

union sid_buffer
{
    SID alignment;
    BYTE bytes[SECURITY_MAX_SID_SIZE];
};

static struct svchost_global_data svchost_globals;
static union sid_buffer sid_buffers[18];
static LONG rpc_server_count;
static SRWLOCK rpc_server_lock = SRWLOCK_INIT;

struct hosted_service
{
    const WCHAR *name;
    SRWLOCK lock;
    WAITORTIMERCALLBACK stop_callback;
};

struct stop_callback_context
{
    struct hosted_service *service;
    void *context;
};

/* Names and callback records share the lifetime of the service-host process,
 * as do its loaded service DLLs. */
static struct hosted_service *hosted_services;
static DWORD hosted_service_count;

static LONG map_rpc_status(RPC_STATUS status)
{
    return I_RpcMapWin32Status(status);
}

static LONG start_rpc_server_locked(RPC_WSTR endpoint, RPC_IF_HANDLE interface)
{
    static const WCHAR pipe_prefix[] = L"\\PIPE\\";
    RPC_STATUS status;
    WCHAR *pipe;
    SIZE_T size;

    if (!endpoint || !interface) return STATUS_INVALID_PARAMETER;

    size = (lstrlenW(pipe_prefix) + lstrlenW((WCHAR *)endpoint) + 1) * sizeof(WCHAR);
    if (!(pipe = HeapAlloc(GetProcessHeap(), 0, size))) return STATUS_NO_MEMORY;
    lstrcpyW(pipe, pipe_prefix);
    lstrcatW(pipe, (WCHAR *)endpoint);

    status = RpcServerUseProtseqEpW((RPC_WSTR)L"ncacn_np", RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
                                    (RPC_WSTR)pipe, NULL);
    HeapFree(GetProcessHeap(), 0, pipe);
    if (status != RPC_S_OK && status != RPC_S_DUPLICATE_ENDPOINT) return map_rpc_status(status);

    status = RpcServerRegisterIf(interface, NULL, NULL);
    if (status != RPC_S_OK) return map_rpc_status(status);

    if (InterlockedIncrement(&rpc_server_count) == 1)
    {
        status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
        if (status != RPC_S_OK && status != RPC_S_ALREADY_LISTENING)
        {
            InterlockedDecrement(&rpc_server_count);
            RpcServerUnregisterIf(interface, NULL, TRUE);
            return map_rpc_status(status);
        }
    }
    return STATUS_SUCCESS;
}

static LONG WINAPI start_rpc_server(RPC_WSTR endpoint, RPC_IF_HANDLE interface)
{
    LONG status;

    AcquireSRWLockExclusive(&rpc_server_lock);
    status = start_rpc_server_locked(endpoint, interface);
    ReleaseSRWLockExclusive(&rpc_server_lock);
    return status;
}

static LONG stop_rpc_server_common(RPC_IF_HANDLE interface, BOOL wait)
{
    RPC_STATUS status;

    if (!interface) return STATUS_INVALID_PARAMETER;
    if (wait) status = RpcServerUnregisterIfEx(interface, NULL, TRUE);
    else status = RpcServerUnregisterIf(interface, NULL, TRUE);
    if (status != RPC_S_OK) return map_rpc_status(status);

    AcquireSRWLockExclusive(&rpc_server_lock);
    if (InterlockedDecrement(&rpc_server_count) == 0)
    {
        RpcMgmtStopServerListening(NULL);
        RpcMgmtWaitServerListen();
    }
    ReleaseSRWLockExclusive(&rpc_server_lock);
    return STATUS_SUCCESS;
}

static LONG WINAPI stop_rpc_server(RPC_IF_HANDLE interface)
{
    return stop_rpc_server_common(interface, FALSE);
}

static LONG WINAPI stop_rpc_server_ex(RPC_IF_HANDLE interface)
{
    return stop_rpc_server_common(interface, TRUE);
}

static void CALLBACK dispatch_stop_callback(void *context, BOOLEAN timed_out)
{
    struct stop_callback_context *call = context;
    WAITORTIMERCALLBACK callback;

    AcquireSRWLockExclusive(&call->service->lock);
    callback = call->service->stop_callback;
    call->service->stop_callback = NULL;
    ReleaseSRWLockExclusive(&call->service->lock);
    callback(call->context, timed_out);
    HeapFree(GetProcessHeap(), 0, call);
}

static DWORD WINAPI register_stop_callback(HANDLE *wait, const WCHAR *service_name, HANDLE object,
                                           WAITORTIMERCALLBACK callback, void *context, DWORD flags)
{
    struct hosted_service *service = NULL;
    struct stop_callback_context *call;
    DWORD i, error = ERROR_SUCCESS;

    if (!wait || !service_name || !object || !callback) return ERROR_INVALID_PARAMETER;
    for (i = 0; i < hosted_service_count; ++i)
        if (CompareStringOrdinal(service_name, -1, hosted_services[i].name, -1, TRUE) == CSTR_EQUAL)
        {
            service = &hosted_services[i];
            break;
        }
    if (!service) return ERROR_INVALID_DATA;

    AcquireSRWLockExclusive(&service->lock);
    if (service->stop_callback) error = ERROR_INVALID_DATA;
    else if (flags != WT_EXECUTEONLYONCE) error = ERROR_NOT_SUPPORTED;
    else if (!(call = HeapAlloc(GetProcessHeap(), 0, sizeof(*call)))) error = ERROR_NOT_ENOUGH_MEMORY;
    else
    {
        call->service = service;
        call->context = context;
        service->stop_callback = callback;
        if (!RegisterWaitForSingleObject(wait, object, dispatch_stop_callback, call, INFINITE, flags))
        {
            error = GetLastError();
            service->stop_callback = NULL;
            HeapFree(GetProcessHeap(), 0, call);
        }
    }
    ReleaseSRWLockExclusive(&service->lock);
    return error;
}

static BOOL initialize_svchost_globals(void)
{
    static const WELL_KNOWN_SID_TYPE sid_types[] =
    {
        WinNullSid, WinWorldSid, WinLocalSid, WinNetworkSid, WinLocalSystemSid,
        WinLocalServiceSid, WinNetworkServiceSid, WinBuiltinDomainSid,
        WinAuthenticatedUserSid, WinAnonymousSid, WinBuiltinAdministratorsSid,
        WinBuiltinUsersSid, WinBuiltinGuestsSid, WinBuiltinPowerUsersSid,
        WinBuiltinAccountOperatorsSid, WinBuiltinSystemOperatorsSid,
        WinBuiltinPrintOperatorsSid, WinBuiltinBackupOperatorsSid,
    };
    unsigned int i;

    svchost_globals.version = 1;
    for (i = 0; i < ARRAY_SIZE(sid_types); ++i)
    {
        DWORD size = sizeof(sid_buffers[i].bytes);
        if (!CreateWellKnownSid(sid_types[i], NULL, sid_buffers[i].bytes, &size))
        {
            WINE_ERR("failed to create well-known SID %u: %lu\n", sid_types[i], GetLastError());
            return FALSE;
        }
        svchost_globals.sids[i] = sid_buffers[i].bytes;
    }

    svchost_globals.start_rpc_server = start_rpc_server;
    svchost_globals.stop_rpc_server = stop_rpc_server;
    svchost_globals.stop_rpc_server_ex = stop_rpc_server_ex;
    svchost_globals.register_stop_callback_deprecated = register_stop_callback;
    return TRUE;
}

/* Allocate and initialize a WSTR containing the queried value */
static LPWSTR GetRegValue(HKEY service_key, const WCHAR *value_name)
{
    DWORD type;
    DWORD reg_size;
    DWORD size;
    LONG ret;
    LPWSTR value;

    WINE_TRACE("\n");

    ret = RegQueryValueExW(service_key, value_name, NULL, &type, NULL, &reg_size);
    if (ret != ERROR_SUCCESS)
    {
        return NULL;
    }

    /* Add space for potentially missing NULL terminators in initial alloc.
     * The worst case REG_MULTI_SZ requires two NULL terminators. */
    size = reg_size + (2 * sizeof(WCHAR));
    value = HeapAlloc(GetProcessHeap(), 0, size);

    ret = RegQueryValueExW(service_key, value_name, NULL, &type,
            (LPBYTE)value, &reg_size);
    if (ret != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, value);
        return NULL;
    }

    /* Explicitly NULL terminate the result */
    value[size / sizeof(WCHAR) - 1] = '\0';
    value[size / sizeof(WCHAR) - 2] = '\0';

    return value;
}

/* Allocate and initialize a WSTR containing the expanded string */
static LPWSTR ExpandEnv(LPWSTR string)
{
    DWORD size;
    LPWSTR expanded_string;

    WINE_TRACE("\n");

    size = 0;
    size = ExpandEnvironmentStringsW(string, NULL, size);
    if (size == 0)
    {
        WINE_ERR("cannot expand env vars in %s: %lu\n",
                wine_dbgstr_w(string), GetLastError());
        return NULL;
    }
    expanded_string = HeapAlloc(GetProcessHeap(), 0,
            (size + 1) * sizeof(WCHAR));
    if (ExpandEnvironmentStringsW(string, expanded_string, size) == 0)
    {
        WINE_ERR("cannot expand env vars in %s: %lu\n",
                wine_dbgstr_w(string), GetLastError());
        HeapFree(GetProcessHeap(), 0, expanded_string);
        return NULL;
    }
    return expanded_string;
}

/* Fill in service table entry for a specified service */
static BOOL AddServiceElem(LPWSTR service_name,
        SERVICE_TABLE_ENTRYW *service_table_entry)
{
    LONG ret;
    HKEY service_hkey = NULL;
    LPWSTR service_param_key = NULL;
    LPWSTR dll_name_short = NULL;
    LPWSTR dll_name_long = NULL;
    LPSTR dll_service_main = NULL;
    HMODULE library = NULL;
    LPSERVICE_MAIN_FUNCTIONW service_main_func = NULL;
    BOOL success = FALSE;
    DWORD reg_size;
    DWORD size;

    WINE_TRACE("Adding element for %s\n", wine_dbgstr_w(service_name));

    /* Construct registry path to the service's parameters key */
    size = lstrlenW(service_reg_path) + lstrlenW(L"\\") + lstrlenW(service_name) + lstrlenW(L"\\") +
           lstrlenW(L"Parameters") + 1;
    service_param_key = HeapAlloc(GetProcessHeap(), 0, size * sizeof(WCHAR));
    lstrcpyW(service_param_key, service_reg_path);
    lstrcatW(service_param_key, L"\\");
    lstrcatW(service_param_key, service_name);
    lstrcatW(service_param_key, L"\\");
    lstrcatW(service_param_key, L"Parameters");
    service_param_key[size - 1] = '\0';
    ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, service_param_key, 0,
            KEY_READ, &service_hkey);
    if (ret != ERROR_SUCCESS)
    {
        WINE_ERR("cannot open key %s, err=%ld\n",
                wine_dbgstr_w(service_param_key), ret);
        goto cleanup;
    }

    /* Find DLL associate with service from key */
    dll_name_short = GetRegValue(service_hkey, L"ServiceDll");
    if (!dll_name_short)
    {
        WINE_ERR("cannot find registry value ServiceDll for service %s\n",
                wine_dbgstr_w(service_name));
        RegCloseKey(service_hkey);
        goto cleanup;
    }

    /* Expand environment variables in ServiceDll name*/
    dll_name_long = ExpandEnv(dll_name_short);
    if (!dll_name_long)
    {
        WINE_ERR("failed to expand string %s\n",
                wine_dbgstr_w(dll_name_short));
        RegCloseKey(service_hkey);
        goto cleanup;
    }

    /* Look for alternate to default ServiceMain entry point */
    ret = RegQueryValueExA(service_hkey, "ServiceMain", NULL, NULL, NULL, &reg_size);
    if (ret == ERROR_SUCCESS)
    {
        /* Add space for potentially missing NULL terminator, allocate, and
         * fill with the registry value */
        size = reg_size + 1;
        dll_service_main = HeapAlloc(GetProcessHeap(), 0, size);
        ret = RegQueryValueExA(service_hkey, "ServiceMain", NULL, NULL,
                (LPBYTE)dll_service_main, &reg_size);
        if (ret != ERROR_SUCCESS)
        {
            RegCloseKey(service_hkey);
            goto cleanup;
        }
        dll_service_main[size - 1] = '\0';
    }
    RegCloseKey(service_hkey);

    /* Load the DLL and obtain a pointer to ServiceMain entry point */
    library = LoadLibraryExW(dll_name_long, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!library)
    {
        WINE_ERR("failed to load library %s, err=%lu\n",
                wine_dbgstr_w(dll_name_long), GetLastError());
        goto cleanup;
    }
    if (dll_service_main)
    {
        service_main_func =
            (LPSERVICE_MAIN_FUNCTIONW) GetProcAddress(library, dll_service_main);
    }
    else
    {
        service_main_func =
            (LPSERVICE_MAIN_FUNCTIONW) GetProcAddress(library, "ServiceMain");
    }
    if (!service_main_func)
    {
        WINE_ERR("cannot locate ServiceMain procedure in DLL for %s\n",
                wine_dbgstr_w(service_name));
        FreeLibrary(library);
        goto cleanup;
    }

    if (GetProcAddress(library, "SvchostPushServiceGlobals"))
    {
        void (WINAPI *push_service_globals)(void *) =
            (void *)GetProcAddress(library, "SvchostPushServiceGlobals");

        /* The legacy export receives the SID/callback view, without the
         * version prefix used by SvchostPushServiceGlobalsEx. */
        push_service_globals(svchost_globals.sids);
    }

    /* Fill in the service table entry */
    service_table_entry->lpServiceName = service_name;
    service_table_entry->lpServiceProc = service_main_func;
    success = TRUE;

cleanup:
    HeapFree(GetProcessHeap(), 0, service_param_key);
    HeapFree(GetProcessHeap(), 0, dll_name_short);
    HeapFree(GetProcessHeap(), 0, dll_name_long);
    HeapFree(GetProcessHeap(), 0, dll_service_main);
    return success;
}

/* Initialize the service table for a list (REG_MULTI_SZ) of services */
static BOOL StartGroupServices(LPWSTR services)
{
    LPWSTR service_name = NULL;
    WCHAR *names;
    SERVICE_TABLE_ENTRYW *service_table = NULL;
    DWORD service_count;
    DWORD i;
    SIZE_T names_size;
    BOOL ret;

    /* Count the services to load */
    service_count = 0;
    service_name = services;
    while (*service_name != '\0')
    {
        ++service_count;
        service_name = service_name + lstrlenW(service_name);
        ++service_name;
    }
    WINE_TRACE("Service group contains %ld services\n", service_count);

    names_size = (service_name - services + 1) * sizeof(WCHAR);
    if (service_count > (~(SIZE_T)0 - names_size) / sizeof(*hosted_services))
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    if (!(hosted_services = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                     service_count * sizeof(*hosted_services) + names_size)))
        return FALSE;
    hosted_service_count = service_count;
    names = (WCHAR *)(hosted_services + service_count);
    memcpy(names, services, names_size);
    for (i = 0; i < service_count; ++i)
    {
        hosted_services[i].name = names;
        names += lstrlenW(names) + 1;
    }

    /* Populate the service table */
    if (!(service_table = HeapAlloc(GetProcessHeap(), 0,
            (service_count + 1) * sizeof(SERVICE_TABLE_ENTRYW)))) return FALSE;
    service_count = 0;
    service_name = services;
    while (*service_name != '\0')
    {
        if (!AddServiceElem(service_name, &service_table[service_count]))
        {
            HeapFree(GetProcessHeap(), 0, service_table);
            return FALSE;
        }
        ++service_count;
        service_name = service_name + lstrlenW(service_name);
        ++service_name;
    }
    service_table[service_count].lpServiceName = NULL;
    service_table[service_count].lpServiceProc = NULL;

    /* Start the services */
    if (!(ret = StartServiceCtrlDispatcherW(service_table)))
        WINE_ERR("StartServiceCtrlDispatcherW failed to start %s: %lu\n",
                wine_dbgstr_w(services), GetLastError());

    HeapFree(GetProcessHeap(), 0, service_table);
    return ret;
}

/* Find the list of services associated with a group name and start those
 * services */
static BOOL LoadGroup(PWCHAR group_name)
{
    HKEY group_hkey = NULL;
    LPWSTR services = NULL;
    LONG ret;

    WINE_TRACE("Loading service group for %s\n", wine_dbgstr_w(group_name));

    /* Lookup group_name value of svchost registry entry */
    ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, svchost_path, 0,
            KEY_READ, &group_hkey);
    if (ret != ERROR_SUCCESS)
    {
        WINE_ERR("cannot open key %s, err=%ld\n",
                wine_dbgstr_w(svchost_path), ret);
        return FALSE;
    }
    services = GetRegValue(group_hkey, group_name);
    RegCloseKey(group_hkey);
    if (!services)
    {
        WINE_ERR("cannot find registry value %s in %s\n",
                wine_dbgstr_w(group_name), wine_dbgstr_w(svchost_path));
        return FALSE;
    }

    /* Start services */
    if (!(ret = StartGroupServices(services)))
        WINE_TRACE("Failed to start service group\n");

    HeapFree(GetProcessHeap(), 0, services);
    return ret;
}

/* Load svchost group specified on the command line via the /k option */
int __cdecl wmain(int argc, WCHAR *argv[])
{
    int option_index;

    WINE_TRACE("\n");

    if (!initialize_svchost_globals()) return 0;

    for (option_index = 1; option_index < argc; option_index++)
    {
        if (lstrcmpiW(argv[option_index], L"/k") == 0 || lstrcmpiW(argv[option_index], L"-k") == 0)
        {
            ++option_index;
            if (option_index >= argc)
            {
                WINE_ERR("Must specify group to initialize\n");
                return 0;
            }
            if (!LoadGroup(argv[option_index]))
            {
                WINE_ERR("Failed to load requested group: %s\n",
                        wine_dbgstr_w(argv[option_index]));
                return 0;
            }
        }
        else
        {
            WINE_FIXME("Unrecognized option: %s\n",
                    wine_dbgstr_w(argv[option_index]));
            return 0;
        }
    }

    return 0;
}
