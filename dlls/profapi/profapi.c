/*
 * Profile directory helpers
 *
 * Copyright 2026 LinuxNT contributors
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

#include <stdarg.h>
#include <string.h>

#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(profapi);

#define PROFILE_DATA_BYTES 128
#define PROFILE_PATH_CHARS 128

static const WCHAR profile_list[] =
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
static const WCHAR appcontainer_storage[] =
    L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\";
static const WCHAR system_sid[] = L"S-1-5-18";

static HRESULT hresult_from_win32( DWORD status )
{
    if (!status) return S_OK;
    return (HRESULT)(0x80070000u | (status & 0xffff));
}

static BOOL bounded_string_length( const WCHAR *string, SIZE_T maximum, SIZE_T *length )
{
    SIZE_T i;

    for (i = 0; i < maximum; ++i)
    {
        if (!string[i])
        {
            *length = i;
            return TRUE;
        }
    }
    return FALSE;
}

HRESULT WINAPI profapi_get_directory( DWORD selector, const WCHAR *sid, WCHAR *output,
                                      DWORD capacity )
{
    WCHAR key[PROFILE_PATH_CHARS], source[PROFILE_DATA_BYTES / sizeof(WCHAR)];
    const WCHAR *subkey = profile_list, *value;
    DWORD type = 0, size = sizeof(source), status;
    SIZE_T length, copied;

    TRACE( "(%lu,%s,%p,%lu)\n", selector, debugstr_w(sid), output, capacity );

    switch (selector)
    {
    case 1:
        value = L"ProfilesDirectory";
        break;
    case 2:
        value = L"Default";
        break;
    case 3:
        value = L"Public";
        break;
    case 4:
        value = L"ProgramData";
        break;
    case 5:
        if (!sid) sid = system_sid;
        if (!bounded_string_length( sid, PROFILE_PATH_CHARS, &length ) ||
            ARRAY_SIZE(profile_list) + length >= ARRAY_SIZE(key))
            return E_INVALIDARG;
        memcpy( key, profile_list, sizeof(profile_list) - sizeof(WCHAR) );
        key[ARRAY_SIZE(profile_list) - 1] = '\\';
        memcpy( key + ARRAY_SIZE(profile_list), sid, (length + 1) * sizeof(WCHAR) );
        subkey = key;
        value = L"ProfileImagePath";
        break;
    default:
        return E_INVALIDARG;
    }

    status = RegGetValueW( HKEY_LOCAL_MACHINE, subkey, value, RRF_RT_REG_SZ,
                           &type, source, &size );
    if (status) return hresult_from_win32( status );
    if (type != REG_SZ || size < sizeof(WCHAR) || size > sizeof(source) || size % sizeof(WCHAR) ||
        source[size / sizeof(WCHAR) - 1])
        return E_INVALIDARG;

    length = size / sizeof(WCHAR) - 1;
    if (!capacity || capacity > 0x7fffffff || !output) return E_INVALIDARG;
    copied = min( length, capacity - 1 );
    memcpy( output, source, copied * sizeof(WCHAR) );
    output[copied] = 0;
    return copied == length ? S_OK : HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
}

HRESULT WINAPI profapi_open_package_registry( const WCHAR *family, const WCHAR *child,
                                               const WCHAR *subkey, REGSAM access, HKEY *key )
{
    static const WCHAR children[] = L"\\Children\\";
    SIZE_T family_len, child_len = 0, subkey_len = 0, length, maximum;
    WCHAR *path, *cursor;
    HKEY current_user;
    LSTATUS status;

    TRACE( "(%s,%s,%s,%#lx,%p)\n", debugstr_w(family), debugstr_w(child),
           debugstr_w(subkey), access, key );

    if (!family || !key) return E_INVALIDARG;
    *key = NULL;

    family_len = wcslen( family );
    if (child) child_len = wcslen( child );
    if (subkey) subkey_len = wcslen( subkey );
    maximum = ~(SIZE_T)0 / sizeof(WCHAR);
    if (family_len > maximum - ARRAY_SIZE(appcontainer_storage)) return E_OUTOFMEMORY;
    length = ARRAY_SIZE(appcontainer_storage) + family_len;
    if (child && child_len > maximum - length - (ARRAY_SIZE(children) - 1))
        return E_OUTOFMEMORY;
    if (child) length += ARRAY_SIZE(children) - 1 + child_len;
    if (subkey && subkey_len > maximum - length - 1) return E_OUTOFMEMORY;
    if (subkey) length += 1 + subkey_len;

    if (!(path = HeapAlloc( GetProcessHeap(), 0, length * sizeof(WCHAR) )))
        return E_OUTOFMEMORY;

    cursor = path;
    memcpy( cursor, appcontainer_storage, sizeof(appcontainer_storage) - sizeof(WCHAR) );
    cursor += ARRAY_SIZE(appcontainer_storage) - 1;
    memcpy( cursor, family, family_len * sizeof(WCHAR) );
    cursor += family_len;
    if (child)
    {
        memcpy( cursor, children, sizeof(children) - sizeof(WCHAR) );
        cursor += ARRAY_SIZE(children) - 1;
        memcpy( cursor, child, child_len * sizeof(WCHAR) );
        cursor += child_len;
    }
    if (subkey)
    {
        *cursor++ = '\\';
        memcpy( cursor, subkey, subkey_len * sizeof(WCHAR) );
        cursor += subkey_len;
    }
    *cursor = 0;

    status = RegOpenCurrentUser( KEY_READ | KEY_WOW64_64KEY, &current_user );
    if (!status)
    {
        status = RegOpenKeyExW( current_user, path, 0, access, key );
        RegCloseKey( current_user );
    }
    HeapFree( GetProcessHeap(), 0, path );
    return hresult_from_win32( status );
}
