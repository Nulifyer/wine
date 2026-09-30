/*
 * AppModel application state
 *
 * Copyright 2026 LinuxNT contributors
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
#include "winreg.h"
#include "winternl.h"
#include "appmodel.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(appmodel);

extern LONG WINAPI GetCurrentPackageFamilyName(UINT32 *length, WCHAR *name);

/***********************************************************************
 *         OpenState   (kernelbase.@)
 */
void * WINAPI OpenState(void)
{
    UINT32 length = 0;
    LONG status;

    status = GetCurrentPackageFamilyName(&length, NULL);
    if (status != APPMODEL_ERROR_NO_PACKAGE)
    {
        FIXME("packaged state spaces are not implemented, package query returned %#lx.\n", status);
        status = ERROR_CALL_NOT_IMPLEMENTED;
    }

    SetLastError(status);
    return NULL;
}


/* State-space pointers are process-local objects, not kernel handles. The
 * captured SID and family are immutable; registry admission belongs to the
 * registry APIs when the caller later uses the returned root and path. */
struct state_space
{
    WCHAR *system_app_data_path;
    UINT32 path_length;
};

extern LONG WINAPI PackageNameAndPublisherIdFromFamilyName(const WCHAR *, UINT32 *, WCHAR *, UINT32 *, WCHAR *);

/***********************************************************************
 *         OpenStateExplicit   (kernelbase.@)
 */
void * WINAPI OpenStateExplicit(HANDLE token, const WCHAR *family)
{
    static const WCHAR system_app_data[] =
        L"\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\SystemAppData\\";
    struct state_space *state = NULL;
    TOKEN_USER *user = NULL;
    UNICODE_STRING sid = {0};
    UINT32 name_length = 0, publisher_length = 0, family_length;
    DWORD size, error, appcontainer;
    NTSTATUS status;

    TRACE("token %p, family %s.\n", token, debugstr_w(family));
    if (token == (HANDLE)(LONG_PTR)-1) error = ERROR_INVALID_HANDLE;
    else if (!family || !token) error = ERROR_INVALID_PARAMETER;
    else
    {
        GetTokenInformation(token, TokenUser, NULL, 0, &size);
        error = GetLastError();
        if (error != ERROR_INSUFFICIENT_BUFFER) goto done;
        if (!(user = RtlAllocateHeap(GetProcessHeap(), 0, size)))
        {
            error = ERROR_OUTOFMEMORY;
            goto done;
        }
        if (!GetTokenInformation(token, TokenUser, user, size, &size))
        {
            error = GetLastError();
            goto done;
        }
        status = RtlConvertSidToUnicodeString(&sid, user->User.Sid, TRUE);
        if (status)
        {
            error = RtlNtStatusToDosError(status);
            goto done;
        }
        for (family_length = 0; family_length <= PACKAGE_FAMILY_NAME_MAX_LENGTH; ++family_length)
            if (!family[family_length]) break;
        if (family_length > PACKAGE_FAMILY_NAME_MAX_LENGTH)
        {
            error = ERROR_INVALID_PARAMETER;
            goto done;
        }
        error = PackageNameAndPublisherIdFromFamilyName(family, &name_length, NULL, &publisher_length, NULL);
        if (error != ERROR_INSUFFICIENT_BUFFER) goto done;

        /* Container-specific state roots and moniker admission are a separate
         * partition. Do not advertise those contracts through this object. */
        if (!GetTokenInformation((HANDLE)(LONG_PTR)-6, TokenIsAppContainer, &appcontainer,
                                 sizeof(appcontainer), &size))
        {
            error = GetLastError();
            goto done;
        }
        if (appcontainer)
        {
            error = ERROR_CALL_NOT_IMPLEMENTED;
            goto done;
        }
        if (!(state = RtlAllocateHeap(GetProcessHeap(), 0, sizeof(*state))))
        {
            error = ERROR_OUTOFMEMORY;
            goto done;
        }
        state->path_length = sid.Length / sizeof(WCHAR) + ARRAY_SIZE(system_app_data) + family_length;
        if (!(state->system_app_data_path = RtlAllocateHeap(GetProcessHeap(), 0, state->path_length * sizeof(WCHAR))))
        {
            RtlFreeHeap(GetProcessHeap(), 0, state);
            state = NULL;
            error = ERROR_OUTOFMEMORY;
            goto done;
        }
        memcpy(state->system_app_data_path, sid.Buffer, sid.Length);
        memcpy(state->system_app_data_path + sid.Length / sizeof(WCHAR), system_app_data,
               sizeof(system_app_data) - sizeof(WCHAR));
        memcpy(state->system_app_data_path + state->path_length - family_length - 1,
               family, (family_length + 1) * sizeof(WCHAR));
        error = ERROR_SUCCESS;
    }
done:
    RtlFreeUnicodeString(&sid);
    RtlFreeHeap(GetProcessHeap(), 0, user);
    SetLastError(error);
    return state;
}

/***********************************************************************
 *         CloseState   (kernelbase.@)
 */
BOOL WINAPI CloseState(void *handle)
{
    struct state_space *state = handle;
    if (!state)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    RtlFreeHeap(GetProcessHeap(), 0, state->system_app_data_path);
    RtlFreeHeap(GetProcessHeap(), 0, state);
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

/***********************************************************************
 *         GetSystemAppDataKey   (kernelbase.@)
 */
BOOL WINAPI GetSystemAppDataKey(void *handle, HKEY *key, WCHAR *path, UINT32 *length)
{
    const struct state_space *state = handle;
    DWORD error;

    if (!state) error = ERROR_INVALID_HANDLE;
    else if (!length || (*length && !path)) error = ERROR_INVALID_PARAMETER;
    else if (!path || *length < state->path_length)
    {
        *length = state->path_length;
        error = ERROR_INSUFFICIENT_BUFFER;
    }
    else
    {
        memcpy(path, state->system_app_data_path, state->path_length * sizeof(WCHAR));
        *length = state->path_length;
        if (key) *key = HKEY_USERS;
        error = ERROR_SUCCESS;
    }
    SetLastError(error);
    return !error;
}
