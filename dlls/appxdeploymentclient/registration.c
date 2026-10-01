/* Package registration state helpers
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "private.h"
#include "objbase.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(appx);

HRESULT WINAPI IsSharedAppsEnabled( BOOL *enabled )
{
    TRACE( "enabled %p.\n", enabled );

    if (!enabled) return E_INVALIDARG;
    *enabled = FALSE;
    return S_OK;
}

HRESULT WINAPI GetPackageRegistrationStatusForUserAndDefaultAccount(
    const WCHAR *package_family_name, UINT64 user_context_token,
    BOOL should_register_if_unknown, BOOL *is_registration_required,
    BOOL *is_registration_corrupt, BOOL *should_higher_version_be_removed,
    BOOL *is_registration_required_default_account, WCHAR **known_package_full_name)
{
    static const WCHAR packages_path[] = L"C:\\Program Files\\WindowsApps\\";
    const WCHAR *publisher_id;
    WIN32_FIND_DATAW data;
    WCHAR search[MAX_PATH];
    HANDLE find;
    SIZE_T length, name_length, publisher_length;

    TRACE( "family %s, user token %s, register unknown %u, required %p, corrupt %p, "
           "remove higher %p, default required %p, known full name %p.\n",
           debugstr_w(package_family_name), wine_dbgstr_longlong(user_context_token),
           should_register_if_unknown, is_registration_required, is_registration_corrupt,
           should_higher_version_be_removed, is_registration_required_default_account,
           known_package_full_name );

    if (!package_family_name || !is_registration_required) return E_INVALIDARG;

    *is_registration_required = FALSE;
    if (is_registration_corrupt) *is_registration_corrupt = FALSE;
    if (should_higher_version_be_removed) *should_higher_version_be_removed = FALSE;
    if (is_registration_required_default_account)
        *is_registration_required_default_account = FALSE;
    if (known_package_full_name) *known_package_full_name = NULL;

    if (!(publisher_id = wcsrchr( package_family_name, L'_' )) ||
        publisher_id == package_family_name || !publisher_id[1])
        return E_INVALIDARG;

    name_length = publisher_id - package_family_name;
    publisher_length = lstrlenW( publisher_id + 1 );
    if (ARRAY_SIZE(packages_path) + name_length + publisher_length + 3 > ARRAY_SIZE(search))
        return E_INVALIDARG;

    lstrcpyW( search, packages_path );
    memcpy( search + ARRAY_SIZE(packages_path) - 1, package_family_name,
            name_length * sizeof(*search) );
    search[ARRAY_SIZE(packages_path) - 1 + name_length] = 0;
    lstrcatW( search, L"_*_" );
    lstrcatW( search, publisher_id + 1 );

    find = FindFirstFileW( search, &data );
    if (find == INVALID_HANDLE_VALUE)
    {
        *is_registration_required = !!should_register_if_unknown;
        return S_OK;
    }

    do
    {
        if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (!known_package_full_name) break;

        length = lstrlenW( data.cFileName ) + 1;
        if (!(*known_package_full_name = CoTaskMemAlloc( length * sizeof(WCHAR) )))
        {
            FindClose( find );
            return E_OUTOFMEMORY;
        }
        memcpy( *known_package_full_name, data.cFileName, length * sizeof(WCHAR) );
        break;
    } while (FindNextFileW( find, &data ));

    FindClose( find );
    return S_OK;
}
