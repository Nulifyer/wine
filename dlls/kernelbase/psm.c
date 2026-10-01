/*
 * Process State Manager identity keys
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
#include "winternl.h"
#include "appmodel.h"

#include "kernelbase.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(state);

static NTSTATUS copy_psm_key_part(const WCHAR *start, SIZE_T chars, WCHAR *buffer, ULONG *size)
{
    ULONG required;

    if (!start || !size || chars > (~(ULONG)0 / sizeof(WCHAR)) - 1)
        return STATUS_INVALID_PARAMETER;
    required = (chars + 1) * sizeof(WCHAR);
    if (!buffer || *size < required)
    {
        *size = required;
        return STATUS_BUFFER_TOO_SMALL;
    }
    memcpy(buffer, start, chars * sizeof(WCHAR));
    buffer[chars] = 0;
    *size = required;
    return STATUS_SUCCESS;
}

/***********************************************************************
 *         PsmCreateKey   (kernelbase.@)
 */
NTSTATUS WINAPI PsmCreateKey(const WCHAR *package_full_name, const WCHAR *application_id,
        WCHAR *key, ULONG *size)
{
    SIZE_T package_len, application_len, chars;
    ULONG required;

    TRACE("(%s %s %p %p)\n", debugstr_w(package_full_name), debugstr_w(application_id),
            key, size);
    if (!package_full_name || !application_id || !size) return STATUS_INVALID_PARAMETER;
    package_len = wcslen(package_full_name);
    application_len = wcslen(application_id);
    chars = package_len + 1 + application_len + 1;
    if (chars > ~(ULONG)0 / sizeof(WCHAR)) return STATUS_INVALID_PARAMETER;
    required = chars * sizeof(WCHAR);
    if (!key || *size < required)
    {
        *size = required;
        return STATUS_BUFFER_TOO_SMALL;
    }

    memcpy(key, package_full_name, package_len * sizeof(WCHAR));
    key[package_len] = L'+';
    memcpy(key + package_len + 1, application_id, (application_len + 1) * sizeof(WCHAR));
    *size = required;
    return STATUS_SUCCESS;
}

static NTSTATUS get_current_psm_key(WCHAR *key, ULONG *size, UINT64 *dynamic_id)
{
    WCHAR package_full_name[PACKAGE_FULL_NAME_MAX_LENGTH + 1];
    WCHAR application_id[APPLICATION_USER_MODEL_ID_MAX_LENGTH + 1];
    UINT32 package_length = ARRAY_SIZE(package_full_name);
    DWORD application_length;
    LONG ret;

    ret = GetCurrentPackageFullName(&package_length, package_full_name);
    if (ret == APPMODEL_ERROR_NO_PACKAGE) return STATUS_NOT_FOUND;
    if (ret == ERROR_INSUFFICIENT_BUFFER) return STATUS_BUFFER_TOO_SMALL;
    if (ret) return STATUS_UNSUCCESSFUL;

    application_length = GetEnvironmentVariableW(L"LINUXNT_APPLICATION_ID",
            application_id, ARRAY_SIZE(application_id));
    if (!application_length || application_length >= ARRAY_SIZE(application_id))
        lstrcpyW(application_id, L"App");
    if (dynamic_id) *dynamic_id = 0;
    return PsmCreateKey(package_full_name, application_id, key, size);
}

/***********************************************************************
 *         PsmGetKeyFromToken   (kernelbase.@)
 */
NTSTATUS WINAPI PsmGetKeyFromToken(HANDLE token, WCHAR *key, ULONG *size, UINT64 *dynamic_id)
{
    TRACE("(%p %p %p %p)\n", token, key, size, dynamic_id);
    if (!token || !size) return STATUS_INVALID_PARAMETER;
    return get_current_psm_key(key, size, dynamic_id);
}

/***********************************************************************
 *         PsmGetKeyFromProcess   (kernelbase.@)
 */
NTSTATUS WINAPI PsmGetKeyFromProcess(HANDLE process, WCHAR *key, ULONG *size, UINT64 *dynamic_id)
{
    TRACE("(%p %p %p %p)\n", process, key, size, dynamic_id);
    if (!process || !size) return STATUS_INVALID_PARAMETER;
    return get_current_psm_key(key, size, dynamic_id);
}

/***********************************************************************
 *         PsmGetPackageFullNameFromKey   (kernelbase.@)
 */
NTSTATUS WINAPI PsmGetPackageFullNameFromKey(const WCHAR *key, WCHAR *package_full_name,
        ULONG *size)
{
    const WCHAR *separator;

    TRACE("(%s %p %p)\n", debugstr_w(key), package_full_name, size);
    if (!key || !(separator = wcschr(key, L'+'))) return STATUS_INVALID_PARAMETER;
    return copy_psm_key_part(key, separator - key, package_full_name, size);
}

/***********************************************************************
 *         PsmGetApplicationNameFromKey   (kernelbase.@)
 */
NTSTATUS WINAPI PsmGetApplicationNameFromKey(const WCHAR *key, WCHAR *application_id, ULONG *size)
{
    const WCHAR *separator, *end;

    TRACE("(%s %p %p)\n", debugstr_w(key), application_id, size);
    if (!key || !(separator = wcschr(key, L'+'))) return STATUS_INVALID_PARAMETER;
    ++separator;
    end = wcschr(separator, L'#');
    if (!end) end = separator + wcslen(separator);
    return copy_psm_key_part(separator, end - separator, application_id, size);
}
