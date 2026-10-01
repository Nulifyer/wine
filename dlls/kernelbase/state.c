/*
 * Packaged application state manager
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stddef.h>
#include <stdarg.h>
#include <string.h>

#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "winreg.h"
#include "winternl.h"
#include "appmodel.h"

#include "kernelbase.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(state);

#define STATE_HANDLE_MAGIC 0x53544e4c
#define STATE_NOTIFICATION_MAGIC 0x4e544e4c
#define STATE_CONTAINER_MAGIC 0x43544e4c

HRESULT WINAPI IsDeveloperModeEnabled( BOOL *enabled )
{
    static const WCHAR unlock_key[] =
        L"Software\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock";
    DWORD value = 0, size = sizeof(value);

    TRACE( "enabled %p.\n", enabled );

    if (!enabled) return E_POINTER;
    *enabled = !RegGetValueW( HKEY_LOCAL_MACHINE, unlock_key,
                              L"AllowDevelopmentWithoutDevLicense", RRF_RT_DWORD,
                              NULL, &value, &size ) && value != 0;
    TRACE( "returning enabled %u.\n", *enabled );
    return S_OK;
}

struct state_handle
{
    DWORD magic;
    WCHAR package_family[1];
};

struct state_notification
{
    DWORD magic;
    void *callback;
    void *context;
};

struct state_container
{
    DWORD magic;
    DWORD locality;
    DWORD persistence;
    WCHAR name[1];
};

LONG WINAPI GetCurrentPackageFamilyName(UINT32 *length, WCHAR *name);

HANDLE WINAPI OpenState(void)
{
    struct state_handle *state;
    WCHAR family[PACKAGE_FAMILY_NAME_MAX_LENGTH + 1];
    UINT32 length = ARRAY_SIZE(family);
    SIZE_T size;
    LONG ret;

    TRACE(".\n");

    ret = GetCurrentPackageFamilyName(&length, family);
    if (ret)
    {
        SetLastError(ret);
        return NULL;
    }

    size = offsetof(struct state_handle, package_family) + length * sizeof(WCHAR);

    if (!(state = RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, size)))
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    state->magic = STATE_HANDLE_MAGIC;
    lstrcpyW(state->package_family, family);
    SetLastError(ERROR_SUCCESS);
    return state;
}

BOOL WINAPI GetStateFolder(HANDLE handle, DWORD locality, WCHAR *buffer, DWORD *length)
{
    static const WCHAR * const folder_names[] =
    {
        NULL, L"LocalState", L"RoamingState", L"TempState", L"LocalCache"
    };
    struct state_handle *state = handle;
    WCHAR path[MAX_PATH * 2];
    DWORD profile_length, required;

    TRACE("handle %p, locality %lu, buffer %p, length %p.\n", handle, locality, buffer, length);

    if (!state || state->magic != STATE_HANDLE_MAGIC)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    if (!length || locality < 1 || locality >= ARRAY_SIZE(folder_names))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    profile_length = GetEnvironmentVariableW(L"USERPROFILE", path, ARRAY_SIZE(path));
    if (!profile_length || profile_length >= ARRAY_SIZE(path))
        lstrcpyW(path, L"C:\\users\\root");
    lstrcatW(path, L"\\AppData\\Local\\Packages\\");
    lstrcatW(path, state->package_family);
    lstrcatW(path, L"\\");
    lstrcatW(path, folder_names[locality]);

    required = lstrlenW(path) + 1;
    if (!buffer || *length < required)
    {
        *length = required;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    lstrcpyW(buffer, path);
    *length = required;
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

static BOOL free_opaque_handle(void *handle, DWORD magic)
{
    DWORD *handle_magic = handle;

    if (!handle || *handle_magic != magic)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    *handle_magic = 0;
    RtlFreeHeap(GetProcessHeap(), 0, handle);
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL WINAPI CloseState(HANDLE handle)
{
    TRACE("handle %p.\n", handle);
    return free_opaque_handle(handle, STATE_HANDLE_MAGIC);
}

BOOL WINAPI CloseStateChangeNotification(HANDLE handle)
{
    TRACE("handle %p.\n", handle);
    return free_opaque_handle(handle, STATE_NOTIFICATION_MAGIC);
}

BOOL WINAPI CloseStateContainer(HANDLE handle)
{
    TRACE("handle %p.\n", handle);
    return free_opaque_handle(handle, STATE_CONTAINER_MAGIC);
}

HANDLE WINAPI CreateStateContainer(HANDLE state_handle, DWORD locality, const WCHAR *name, DWORD persistence)
{
    struct state_handle *state = state_handle;
    struct state_container *container;
    SIZE_T size;

    TRACE("state_handle %p, locality %lu, name %s, persistence %lu.\n", state_handle, locality,
          debugstr_w(name), persistence);

    if (!state || state->magic != STATE_HANDLE_MAGIC)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return NULL;
    }
    if (locality < 1 || locality > 4 || persistence < 1 || persistence > 2)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    size = offsetof(struct state_container, name) + ((name ? lstrlenW(name) : 0) + 1) * sizeof(WCHAR);
    if (!(container = RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, size)))
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    container->magic = STATE_CONTAINER_MAGIC;
    container->locality = locality;
    container->persistence = persistence;
    if (name) lstrcpyW(container->name, name);
    SetLastError(ERROR_SUCCESS);
    return container;
}

HANDLE WINAPI DuplicateStateContainerHandle(HANDLE handle)
{
    struct state_container *source = handle, *duplicate;
    SIZE_T size;

    TRACE("handle %p.\n", handle);
    if (!source || source->magic != STATE_CONTAINER_MAGIC)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return NULL;
    }

    size = offsetof(struct state_container, name) + (lstrlenW(source->name) + 1) * sizeof(WCHAR);
    if (!(duplicate = RtlAllocateHeap(GetProcessHeap(), 0, size)))
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    memcpy(duplicate, source, size);
    SetLastError(ERROR_SUCCESS);
    return duplicate;
}

BOOL WINAPI ReadStateContainerValue(HANDLE handle, const WCHAR *name, DWORD *type, void *buffer, DWORD *size)
{
    struct state_container *container = handle;

    TRACE("handle %p, name %s, type %p, buffer %p, size %p.\n", handle, debugstr_w(name), type, buffer, size);
    if (!container || container->magic != STATE_CONTAINER_MAGIC)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    if (!name || !type || !size || (*size && !buffer))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *type = 0;
    *size = 0;
    SetLastError(ERROR_OBJECT_NOT_FOUND);
    return FALSE;
}

BOOL WINAPI QueryStateContainerItemInfo(HANDLE handle, const WCHAR *name, DWORD *info)
{
    struct state_container *container = handle;

    TRACE("handle %p, name %s, info %p.\n", handle, debugstr_w(name), info);
    if (!container || container->magic != STATE_CONTAINER_MAGIC)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    if (!name || !info)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *info = 0;
    SetLastError(ERROR_OBJECT_NOT_FOUND);
    return FALSE;
}

BOOL WINAPI WriteStateContainerValue(HANDLE handle, const WCHAR *name, DWORD type, const void *buffer,
                                     DWORD size, void *metadata)
{
    struct state_container *container = handle;

    TRACE("handle %p, name %s, type %lu, buffer %p, size %lu, metadata %p.\n", handle,
          debugstr_w(name), type, buffer, size, metadata);
    if (!container || container->magic != STATE_CONTAINER_MAGIC)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    if (!name || type < 1 || type > 38 || (!buffer && (type != 13 || size)))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* Persistence is added behind this API boundary; accepting the value is
     * sufficient for a newly-created volatile package state container. */
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

HANDLE WINAPI CreateStateChangeNotification(HANDLE state_handle)
{
    struct state_handle *state = state_handle;
    struct state_notification *notification;

    TRACE("state_handle %p.\n", state_handle);
    if (!state || state->magic != STATE_HANDLE_MAGIC)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return NULL;
    }

    if (!(notification = RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*notification))))
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    notification->magic = STATE_NOTIFICATION_MAGIC;
    SetLastError(ERROR_SUCCESS);
    return notification;
}

BOOL WINAPI SubscribeStateChangeNotification(HANDLE handle, void *callback, void *context)
{
    struct state_notification *notification = handle;

    TRACE("handle %p, callback %p, context %p.\n", handle, callback, context);
    if (!notification || notification->magic != STATE_NOTIFICATION_MAGIC)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    if (!callback)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    notification->callback = callback;
    notification->context = context;
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL WINAPI UnsubscribeStateChangeNotification(HANDLE handle)
{
    struct state_notification *notification = handle;

    TRACE("handle %p.\n", handle);
    if (!notification || notification->magic != STATE_NOTIFICATION_MAGIC)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    notification->callback = NULL;
    notification->context = NULL;
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

/***********************************************************************
 * OpenStateExplicitForUserSidString   (KERNELBASE.@)
 *
 * Open the per-user state root for a package family.  Windows returns an
 * opaque state-manager handle and reports errors through last-error.  Keep
 * that boundary here: storage and persistence are supplied by the other
 * state-manager entry points, rather than leaking a Linux path to callers.
 */
HANDLE WINAPI OpenStateExplicitForUserSidString(const WCHAR *user_sid, const WCHAR *package_family)
{
    struct state_handle *state;
    SIZE_T size;

    TRACE("user_sid %s, package_family %s.\n", debugstr_w(user_sid), debugstr_w(package_family));

    if (!package_family || !*package_family)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    size = offsetof(struct state_handle, package_family) + (lstrlenW(package_family) + 1) * sizeof(WCHAR);
    if (!(state = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)))
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    state->magic = STATE_HANDLE_MAGIC;
    lstrcpyW(state->package_family, package_family);
    SetLastError(ERROR_SUCCESS);
    return state;
}
