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
