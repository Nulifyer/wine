/* Out-of-box experience state and notification lifetime
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
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "winternl.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(kernel);

#define SHELL_OOBE_STATE 0x0d83063ea3bc2475ULL
#define DEPLOYMENT_OOBE_STATE 0x41960b29a3bc0c75ULL

struct oobe_wait
{
    void (WINAPI *callback)(void *);
    void *context, *subscription;
};
static INIT_ONCE support_once = INIT_ONCE_STATIC_INIT;
static INIT_ONCE state_once = INIT_ONCE_STATIC_INIT;
static BOOL wnf_supported;
static ULONGLONG oobe_state;

static BOOL read_dword(const WCHAR *path, const WCHAR *name, DWORD *value)
{
    DWORD size = sizeof(*value);
    HKEY key;
    LSTATUS status;
    status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE, &key);
    if (!status)
    {
        status = RegQueryValueExW(key, name, NULL, NULL, (BYTE *)value, &size);
        RegCloseKey(key);
    }
    if (status) SetLastError(status);
    return !status;
}

static BOOL CALLBACK initialize_support(INIT_ONCE *once, void *parameter, void **context)
{
    DWORD value = 0, error;
    if (!read_dword(L"SYSTEM\\Setup", L"SetupSupported", &value))
    {
        error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) return FALSE;
        SetLastError(0);
    }
    if (!value && !read_dword(L"Software\\Microsoft\\Shell\\Oobe", L"OobeCompleteWnfSupported", &value))
    {
        error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) return FALSE;
        SetLastError(0);
    }
    wnf_supported = !!value;
    return TRUE;
}

static BOOL CALLBACK initialize_state(INIT_ONCE *once, void *parameter, void **context)
{
    OSVERSIONINFOEXW version = {sizeof(version)};
    UNICODE_STRING license = RTL_CONSTANT_STRING(L"OOBE-ServerIsClient");
    DWORD headless = 0, server_is_client = 0, size;
    BOOL server;
    if (!read_dword(L"SYSTEM\\CurrentControlSet\\Control\\WinInit", L"Headless", &headless)) return FALSE;
    if (!GetVersionExW((OSVERSIONINFOW *)&version)) return FALSE;
    server = version.wProductType == VER_NT_DOMAIN_CONTROLLER || version.wProductType == VER_NT_SERVER;
    if (server && !NtQueryLicenseValue(&license, NULL, &server_is_client, sizeof(server_is_client), &size))
        server = !server_is_client;
    oobe_state = headless || server ? DEPLOYMENT_OOBE_STATE : SHELL_OOBE_STATE;
    return TRUE;
}

static BOOL get_oobe_state(void)
{
    if (!InitOnceExecuteOnce(&support_once, initialize_support, NULL, NULL)) return FALSE;
    if (!wnf_supported)
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    return InitOnceExecuteOnce(&state_once, initialize_state, NULL, NULL);
}

static BOOL set_status(NTSTATUS status)
{
    if (status < 0)
    {
        SetLastError(RtlNtStatusToDosError(status));
        return FALSE;
    }
    return TRUE;
}

static NTSTATUS WINAPI query_completed(ULONGLONG state, ULONG stamp, const GUID *type,
                                      void *context, const void *data, ULONG size)
{
    *(BOOL *)context = size == sizeof(DWORD) && *(const DWORD *)data != 0;
    return STATUS_SUCCESS;
}

static NTSTATUS WINAPI notify_completed(ULONGLONG state, ULONG stamp, const GUID *type,
                                       void *context, const void *data, ULONG size)
{
    struct oobe_wait *wait = context;
    if (size == sizeof(DWORD) && *(const DWORD *)data == 1)
        wait->callback(wait->context);
    /* The caller may have unregistered and freed its record in the callback. */
    return STATUS_SUCCESS;
}

/***********************************************************************
 *           OOBEComplete   (KERNEL32.@)
 */
BOOL WINAPI OOBEComplete(BOOL *complete)
{
    UNICODE_STRING license = RTL_CONSTANT_STRING(L"Kernel-SkipOOBE");
    DWORD skip = 0, size;
    ULONG stamp;
    BOOL value = FALSE;
    TRACE("complete %p.\n", complete);
    if (!complete)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    /* Wine's existing license owner supplies the product capability. Optional
     * external QueryOOBESupport providers are outside this partition. */
    if (!NtQueryLicenseValue(&license, NULL, &skip, sizeof(skip), &size) && skip)
    {
        *complete = TRUE;
        return TRUE;
    }
    if (!get_oobe_state()) return FALSE;
    if (!set_status(RtlQueryWnfStateData(&stamp, oobe_state, query_completed, &value, NULL))) return FALSE;
    *complete = value;
    TRACE("state %#I64x complete %d stamp %lu.\n", oobe_state, value, stamp);
    return TRUE;
}

/***********************************************************************
 *           RegisterWaitUntilOOBECompleted   (KERNEL32.@)
 */
BOOL WINAPI RegisterWaitUntilOOBECompleted(void (WINAPI *callback)(void *), void *context, void **out)
{
    struct oobe_wait *wait;
    ULONG stamp;
    BOOL complete = FALSE;
    NTSTATUS status;
    TRACE("callback %p context %p out %p.\n", callback, context, out);
    if (!callback || !out)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!get_oobe_state()) return FALSE;
    if (!set_status(RtlQueryWnfStateData(&stamp, oobe_state, query_completed, &complete, NULL))) return FALSE;
    if (complete)
    {
        SetLastError(ERROR_INVALID_STATE);
        return FALSE;
    }
    if (!(wait = HeapAlloc(GetProcessHeap(), 0, sizeof(*wait)))) return set_status(STATUS_NO_MEMORY);
    wait->callback = callback;
    wait->context = context;
    status = RtlSubscribeWnfStateChangeNotification(&wait->subscription, oobe_state, stamp,
                                                    notify_completed, wait, NULL, 0, 1);
    if (!set_status(status))
    {
        HeapFree(GetProcessHeap(), 0, wait);
        return FALSE;
    }
    *out = wait;
    TRACE("state %#I64x stamp %lu wait %p.\n", oobe_state, stamp, wait);
    return TRUE;
}

/***********************************************************************
 *           UnregisterWaitUntilOOBECompleted   (KERNEL32.@)
 */
BOOL WINAPI UnregisterWaitUntilOOBECompleted(void *opaque)
{
    struct oobe_wait *wait = opaque;
    TRACE("wait %p.\n", wait);
    if (!wait)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!set_status(RtlUnsubscribeWnfStateChangeNotification(wait->subscription))) return FALSE;
    HeapFree(GetProcessHeap(), 0, wait);
    return TRUE;
}
