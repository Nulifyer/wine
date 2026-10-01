/*
 * User manager client APIs
 *
 * Copyright 2026 LinuxNT project
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "winnt.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(usermgrcli);

HRESULT WINAPI UMgrOpenProcessHandleForAccess(ACCESS_MASK access, ULONG process_id,
                                               HANDLE *process)
{
    HANDLE handle;

    TRACE("%#lx, %lu, %p\n", access, process_id, process);

    if (!process) return E_INVALIDARG;
    *process = NULL;

    handle = OpenProcess(access, FALSE, process_id);
    if (!handle) return HRESULT_FROM_WIN32(GetLastError());

    *process = handle;
    return S_OK;
}

HRESULT WINAPI UMgrOpenProcessTokenForQuery(ULONG process_id, HANDLE *token)
{
    HANDLE process;
    DWORD error;

    TRACE("%lu, %p\n", process_id, token);

    if (!token) return E_INVALIDARG;
    *token = NULL;

    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id);
    if (!process) return HRESULT_FROM_WIN32(GetLastError());

    if (!OpenProcessToken(process, TOKEN_QUERY, token))
    {
        error = GetLastError();
        CloseHandle(process);
        return HRESULT_FROM_WIN32(error);
    }

    CloseHandle(process);
    return S_OK;
}

HRESULT WINAPI UMgrQueryUserContext(HANDLE token, ULONGLONG *context)
{
    TOKEN_STATISTICS stats;
    DWORD size;

    TRACE("%p, %p\n", token, context);

    if (!context) return E_INVALIDARG;
    *context = 0;

    if (!GetTokenInformation(token, TokenStatistics, &stats, sizeof(stats), &size))
        return HRESULT_FROM_WIN32(GetLastError());

    /* Windows returns an opaque, stable identifier for the logged-on user.
     * Wine has no User Manager service, so use its per-logon authentication
     * LUID as the corresponding user-context key. */
    *context = ((ULONGLONG)(ULONG)stats.AuthenticationId.HighPart << 32) |
               stats.AuthenticationId.LowPart;
    return S_OK;
}
