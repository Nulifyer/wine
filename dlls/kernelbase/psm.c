/*
 * Process state management key representation
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "appmodel.h"
#include "strsafe.h"
#include "kernelbase.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(appmodel);

static NTSTATUS copy_component(const WCHAR *source, UINT32 length, WCHAR *buffer, UINT32 *bytes)
{
    UINT32 required = (length + 1) * sizeof(WCHAR);
    NTSTATUS status = STATUS_BUFFER_TOO_SMALL;

    if (*bytes >= required)
    {
        memcpy(buffer, source, length * sizeof(*buffer));
        buffer[length] = 0;
        status = STATUS_SUCCESS;
    }
    *bytes = required;
    return status;
}

NTSTATUS WINAPI PsmCreateKey(const WCHAR *package, const WCHAR *application, WCHAR *key, UINT32 *bytes)
{
    SIZE_T required = (wcslen(package) + wcslen(application) + 2) * sizeof(WCHAR);
    NTSTATUS status = STATUS_BUFFER_TOO_SMALL;

    TRACE("%s, %s, %p, %p.\n", debugstr_w(package), debugstr_w(application), key, bytes);
    if (required > UINT_MAX) return STATUS_NAME_TOO_LONG;
    if (*bytes >= required)
    {
        swprintf(key, *bytes / sizeof(*key), L"%s+%s", package, application);
        status = STATUS_SUCCESS;
    }
    *bytes = required;
    return status;
}

NTSTATUS WINAPI PsmCreateKeyWithDynamicId(const WCHAR *package, const WCHAR *application,
                                        const GUID *id, WCHAR *key, UINT32 *bytes)
{
    SIZE_T required = (wcslen(package) + wcslen(application) + 40) * sizeof(WCHAR);
    WCHAR suffix[40];
    NTSTATUS status = STATUS_BUFFER_TOO_SMALL;

    TRACE("%s, %s, %s, %p, %p.\n", debugstr_w(package), debugstr_w(application), debugstr_guid(id), key, bytes);
    if (required > UINT_MAX) return STATUS_NAME_TOO_LONG;
    swprintf(suffix, ARRAY_SIZE(suffix), L"#{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
             id->Data1, id->Data2, id->Data3, id->Data4[0], id->Data4[1], id->Data4[2],
             id->Data4[3], id->Data4[4], id->Data4[5], id->Data4[6], id->Data4[7]);
    if (*bytes >= required)
    {
        /* The reported size excludes the terminator; native ignores formatting failure. */
        StringCbPrintfExW(key, *bytes, NULL, NULL, STRSAFE_NULL_ON_FAILURE, L"%s+%s%s",
                         package, application, suffix);
        status = STATUS_SUCCESS;
    }
    *bytes = required;
    return status;
}

NTSTATUS WINAPI PsmGetPackageFullNameFromKey(const WCHAR *key, WCHAR *buffer, UINT32 *bytes)
{
    const WCHAR *separator;
    UINT32 length;

    TRACE("%s, %p, %p.\n", debugstr_w(key), buffer, bytes);
    if (!(separator = wcschr(key, L'+'))) return STATUS_BAD_KEY;
    length = separator - key;
    if (!length || length > PACKAGE_FULL_NAME_MAX_LENGTH) return STATUS_BAD_KEY;
    return copy_component(key, length, buffer, bytes);
}

NTSTATUS WINAPI PsmGetApplicationNameFromKey(const WCHAR *key, WCHAR *buffer, UINT32 *bytes)
{
    const WCHAR *application, *end;
    UINT32 length;

    TRACE("%s, %p, %p.\n", debugstr_w(key), buffer, bytes);
    if (!(application = wcschr(key, L'+'))) return STATUS_BAD_KEY;
    ++application;
    for (end = application; *end && *end != L'#' && *end != L'*'; ++end) ;
    length = end - application;
    if (!length || length >= PACKAGE_RELATIVE_APPLICATION_ID_MAX_LENGTH) return STATUS_BAD_KEY;
    return copy_component(application, length, buffer, bytes);
}

BOOLEAN WINAPI PsmIsValidKey(const WCHAR *key)
{
    int separator = -1, dynamic = -1, application_length;
    unsigned int i;

    TRACE("%s.\n", debugstr_w(key));
    for (i = 0; i < 232; ++i)
    {
        WCHAR ch = key[i];
        if (!ch) break;
        if (ch == L'!') return FALSE;
        if (ch == L'+')
        {
            if (separator != -1) return FALSE;
            separator = i;
        }
        else if (ch == L'#')
        {
            if (dynamic != -1 || separator == -1) return FALSE;
            dynamic = i;
        }
    }
    if (i == 232 || separator < 1 || separator > PACKAGE_FULL_NAME_MAX_LENGTH) return FALSE;
    application_length = (dynamic == -1 ? i : dynamic) - separator - 1;
    if (application_length < 1 || application_length >= PACKAGE_RELATIVE_APPLICATION_ID_MAX_LENGTH) return FALSE;
    return dynamic == -1 || i - dynamic == 39;
}

BOOLEAN WINAPI PsmIsDynamicKey(const WCHAR *key)
{
    TRACE("%s.\n", debugstr_w(key));
    return !!wcschr(key, L'#');
}

NTSTATUS WINAPI PsmGetDynamicIdFromKey(const WCHAR *key, GUID *id)
{
    const WCHAR *dynamic;
    UNICODE_STRING string;

    TRACE("%s, %p.\n", debugstr_w(key), id);
    if (!PsmIsValidKey(key)) return STATUS_BAD_KEY;
    if (!(dynamic = wcschr(key, L'#'))) return STATUS_NOT_FOUND;
    RtlInitUnicodeString(&string, dynamic + 1);
    RtlGUIDFromString(&string, id);
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI PsmGetAumidFromKey(const WCHAR *key, UINT32 *length, WCHAR *aumid)
{
    WCHAR package[PACKAGE_FULL_NAME_MAX_LENGTH + 1], family[PACKAGE_FAMILY_NAME_MAX_LENGTH + 1];
    WCHAR application[PACKAGE_RELATIVE_APPLICATION_ID_MAX_LENGTH];
    UINT32 size = sizeof(package), family_length = ARRAY_SIZE(family);
    NTSTATUS status;

    TRACE("%s, %p, %p.\n", debugstr_w(key), length, aumid);
    if ((status = PsmGetPackageFullNameFromKey(key, package, &size))) return status;
    if (PackageFamilyNameFromFullName(package, &family_length, family)) return STATUS_INVALID_PARAMETER;
    size = sizeof(application);
    if ((status = PsmGetApplicationNameFromKey(key, application, &size))) return status;
    return FormatApplicationUserModelId(family, application, length, aumid) ? STATUS_BUFFER_TOO_SMALL : STATUS_SUCCESS;
}

BOOLEAN WINAPI PsmEqualPackage(const WCHAR *first, const WCHAR *second)
{
    WCHAR a[PACKAGE_FULL_NAME_MAX_LENGTH + 1], b[PACKAGE_FULL_NAME_MAX_LENGTH + 1];
    UINT32 size = sizeof(a);

    TRACE("%s, %s.\n", debugstr_w(first), debugstr_w(second));
    if (PsmGetPackageFullNameFromKey(first, a, &size)) return FALSE;
    size = sizeof(b);
    if (PsmGetPackageFullNameFromKey(second, b, &size)) return FALSE;
    return !wcsicmp(a, b);
}

BOOLEAN WINAPI PsmEqualApplication(const WCHAR *first, const WCHAR *second)
{
    WCHAR a[PACKAGE_RELATIVE_APPLICATION_ID_MAX_LENGTH], b[PACKAGE_RELATIVE_APPLICATION_ID_MAX_LENGTH];
    UINT32 size = sizeof(a);

    TRACE("%s, %s.\n", debugstr_w(first), debugstr_w(second));
    if (!PsmEqualPackage(first, second)) return FALSE;
    if (PsmGetApplicationNameFromKey(first, a, &size)) return FALSE;
    size = sizeof(b);
    if (PsmGetApplicationNameFromKey(second, b, &size)) return FALSE;
    return !wcsicmp(a, b);
}

BOOLEAN WINAPI PsmIsChildKey(const WCHAR *parent, const WCHAR *child)
{
    TRACE("%s, %s.\n", debugstr_w(parent), debugstr_w(child));
    return PsmEqualApplication(parent, child) && !PsmIsDynamicKey(parent) && PsmIsDynamicKey(child);
}
