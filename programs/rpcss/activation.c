/*
 * COM class policy and caller admission.
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
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "winreg.h"
#include "objbase.h"
#include "rpcss_private.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(rpcss);

static HRESULT scm_read_permission( HKEY key, const WCHAR *name, SECURITY_DESCRIPTOR **descriptor, DWORD *length )
{
    DWORD type;
    LSTATUS ret;

    *descriptor = NULL;
    *length = 0;
    ret = RegQueryValueExW( key, name, NULL, &type, NULL, length );
    if (ret) return HRESULT_FROM_WIN32( ret );
    if (type != REG_BINARY) return HRESULT_FROM_WIN32( ERROR_INVALID_SECURITY_DESCR );
    /* Large padded registry values are outside this supported policy partition. */
    if (*length > 1024 * 1024) return E_NOTIMPL;
    if (!(*descriptor = malloc( *length ? *length : 1 ))) return E_OUTOFMEMORY;
    ret = RegQueryValueExW( key, name, NULL, &type, (BYTE *)*descriptor, length );
    if (!ret && type == REG_BINARY && RtlValidRelativeSecurityDescriptor( *descriptor, *length, 0 )) return S_OK;
    free( *descriptor );
    *descriptor = NULL;
    return ret ? HRESULT_FROM_WIN32( ret ) : HRESULT_FROM_WIN32( ERROR_INVALID_SECURITY_DESCR );
}

static HRESULT scm_check_permission( SECURITY_DESCRIPTOR *descriptor, HANDLE token )
{
    GENERIC_MAPPING mapping = { 0, 0, 0x7f, 0 };
    SECURITY_DESCRIPTOR filtered_descriptor;
    PRIVILEGE_SET privileges;
    DWORD privilege_size = sizeof(privileges), granted = 0;
    ACL *acl, *sacl, *filtered;
    ACE_HEADER *ace;
    BYTE *next;
    SID *owner, *group;
    BOOL present, defaulted, status, conditional = FALSE;
    int format = -1;
    unsigned int i;
    DWORD mask;
    HRESULT hr = E_ACCESSDENIED;

    if (!GetSecurityDescriptorSacl( descriptor, &present, &sacl, &defaulted ))
        return HRESULT_FROM_WIN32( GetLastError() );
    if (present && sacl) return E_NOTIMPL;
    if (!GetSecurityDescriptorDacl( descriptor, &present, &acl, &defaulted ))
        return HRESULT_FROM_WIN32( GetLastError() );
    if (!present || !acl) return S_OK;

    if (!(filtered = malloc( acl->AclSize ))) return E_OUTOFMEMORY;
    memcpy( filtered, acl, sizeof(*acl) );
    filtered->AceCount = 0;
    next = (BYTE *)(filtered + 1);
    ace = (ACE_HEADER *)(acl + 1);
    for (i = 0; i < acl->AceCount; ++i)
    {
        int ace_format;

        if (ace->AceType != ACCESS_ALLOWED_ACE_TYPE && ace->AceType != ACCESS_DENIED_ACE_TYPE &&
            ace->AceType != ACCESS_ALLOWED_CALLBACK_ACE_TYPE)
        {
            hr = E_NOTIMPL;
            goto done;
        }
        memcpy( &mask, (BYTE *)ace + offsetof(ACCESS_ALLOWED_ACE, Mask), sizeof(mask) );
        /* COM descriptors cannot mix execute-only and extended-rights ACEs. */
        if (!(mask & COM_RIGHTS_EXECUTE) || (mask & ~(0x7f | GENERIC_EXECUTE)))
        {
            hr = E_NOTIMPL;
            goto done;
        }
        ace_format = mask != COM_RIGHTS_EXECUTE;
        if (format != -1 && format != ace_format)
        {
            hr = E_NOTIMPL;
            goto done;
        }
        format = ace_format;
        if (ace->AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE) conditional = TRUE;
        else
        {
            memcpy( next, ace, ace->AceSize );
            next += ace->AceSize;
            ++filtered->AceCount;
        }
        ace = (ACE_HEADER *)((BYTE *)ace + ace->AceSize);
    }
    filtered->AclSize = next - (BYTE *)filtered;
    if (!GetSecurityDescriptorOwner( descriptor, (void **)&owner, &defaulted ) ||
        !GetSecurityDescriptorGroup( descriptor, (void **)&group, &defaulted ))
    {
        hr = HRESULT_FROM_WIN32( GetLastError() );
        goto done;
    }
    InitializeSecurityDescriptor( &filtered_descriptor, SECURITY_DESCRIPTOR_REVISION );
    SetSecurityDescriptorOwner( &filtered_descriptor, owner, FALSE );
    SetSecurityDescriptorGroup( &filtered_descriptor, group, FALSE );
    SetSecurityDescriptorDacl( &filtered_descriptor, TRUE, filtered, FALSE );
    if (!AccessCheckByType( &filtered_descriptor, NULL, token, MAXIMUM_ALLOWED, NULL, 0,
                           &mapping, &privileges, &privilege_size, &granted, &status ))
    {
        hr = HRESULT_FROM_WIN32( GetLastError() );
        goto done;
    }
    if (status && ((granted & COM_RIGHTS_ACTIVATE_LOCAL) ||
                   (format == 0 && !(granted & 0x7e) && (granted & COM_RIGHTS_EXECUTE)))) hr = S_OK;
    else if (conditional) hr = E_NOTIMPL;
done:
    free( filtered );
    return hr;
}

static HRESULT scm_read_string( HKEY key, const WCHAR *name, WCHAR *value, DWORD capacity )
{
    DWORD type, size = (capacity - 1) * sizeof(WCHAR);
    LSTATUS ret = RegQueryValueExW( key, name, NULL, &type, (BYTE *)value, &size );

    if (ret) return HRESULT_FROM_WIN32( ret );
    if (type != REG_SZ || !size || size % sizeof(WCHAR)) return E_INVALIDARG;
    value[size / sizeof(WCHAR)] = 0;
    return S_OK;
}

HRESULT scm_class_admission( const GUID *clsid, HANDLE token )
{
    WCHAR path[128], appid[64], run_as[64];
    RPC_WSTR uuid_string = NULL;
    GUID appid_guid;
    HKEY class_key = NULL, appid_key = NULL, machine_key = NULL;
    SECURITY_DESCRIPTOR *descriptor = NULL;
    DWORD flags = 0, type, size, length;
    LSTATUS ret;
    RPC_STATUS rpc_status;
    HRESULT hr;

    rpc_status = UuidToStringW( (UUID *)clsid, &uuid_string );
    if (rpc_status) return HRESULT_FROM_WIN32( rpc_status );
    swprintf( path, ARRAY_SIZE(path), L"Software\\Classes\\CLSID\\{%s}", uuid_string );
    RpcStringFreeW( &uuid_string );
    ret = RegOpenKeyExW( HKEY_LOCAL_MACHINE, path, 0, KEY_READ | KEY_WOW64_64KEY, &class_key );
    if (ret) return HRESULT_FROM_WIN32( ret );
    hr = scm_read_string( class_key, L"AppID", appid, ARRAY_SIZE(appid) );
    RegCloseKey( class_key );
    if (FAILED(hr)) return hr;
    if (appid[0] == '{' && wcslen(appid) == 38 && appid[37] == '}')
    {
        appid[37] = 0;
        rpc_status = UuidFromStringW( (RPC_WSTR)(appid + 1), &appid_guid );
    }
    else rpc_status = UuidFromStringW( (RPC_WSTR)appid, &appid_guid );
    if (rpc_status) return E_INVALIDARG;
    rpc_status = UuidToStringW( &appid_guid, &uuid_string );
    if (rpc_status) return HRESULT_FROM_WIN32( rpc_status );
    swprintf( path, ARRAY_SIZE(path), L"Software\\Classes\\AppID\\{%s}", uuid_string );
    RpcStringFreeW( &uuid_string );
    ret = RegOpenKeyExW( HKEY_LOCAL_MACHINE, path, 0, KEY_READ | KEY_WOW64_64KEY, &appid_key );
    if (ret) return HRESULT_FROM_WIN32( ret );
    hr = scm_read_string( appid_key, L"RunAs", run_as, ARRAY_SIZE(run_as) );
    if (FAILED(hr)) goto done;
    if (wcsicmp( run_as, L"Interactive User" ))
    {
        hr = E_NOTIMPL;
        goto done;
    }
    /* Service/surrogate identity and nonzero AppID flags need their own
     * selection semantics; never ignore them to force this partition. */
    ret = RegQueryValueExW( appid_key, L"LocalService", NULL, NULL, NULL, NULL );
    if (ret != ERROR_FILE_NOT_FOUND)
    {
        hr = ret ? HRESULT_FROM_WIN32( ret ) : E_NOTIMPL;
        goto done;
    }
    ret = RegQueryValueExW( appid_key, L"DllSurrogate", NULL, NULL, NULL, NULL );
    if (ret != ERROR_FILE_NOT_FOUND)
    {
        hr = ret ? HRESULT_FROM_WIN32( ret ) : E_NOTIMPL;
        goto done;
    }
    size = sizeof(flags);
    ret = RegQueryValueExW( appid_key, L"AppIDFlags", NULL, &type, (BYTE *)&flags, &size );
    if (ret != ERROR_FILE_NOT_FOUND && (ret || type != REG_DWORD || size != sizeof(flags)))
    {
        hr = ret ? HRESULT_FROM_WIN32( ret ) : E_INVALIDARG;
        goto done;
    }
    if (flags)
    {
        hr = E_NOTIMPL;
        goto done;
    }
    ret = RegOpenKeyExW( HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Ole", 0,
                        KEY_READ | KEY_WOW64_64KEY, &machine_key );
    if (ret)
    {
        hr = HRESULT_FROM_WIN32( ret );
        goto done;
    }
    hr = scm_read_permission( machine_key, L"MachineLaunchRestriction", &descriptor, &length );
    if (FAILED(hr)) goto done;
    hr = scm_check_permission( descriptor, token );
    free( descriptor );
    descriptor = NULL;
    if (FAILED(hr))
    {
        TRACE( "class %s machine launch restriction failed %#lx\n", debugstr_guid(clsid), hr );
        goto done;
    }
    hr = scm_read_permission( appid_key, L"LaunchPermission", &descriptor, &length );
    if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
        hr = scm_read_permission( machine_key, L"DefaultLaunchPermission", &descriptor, &length );
    if (SUCCEEDED(hr)) hr = scm_check_permission( descriptor, token );
    if (FAILED(hr)) TRACE( "class %s application launch permission failed %#lx\n", debugstr_guid(clsid), hr );
done:
    free( descriptor );
    if (machine_key) RegCloseKey( machine_key );
    RegCloseKey( appid_key );
    return hr;
}
