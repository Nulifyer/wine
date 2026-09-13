/*
 * Copyright 2016 Hans Leidekker for CodeWeavers
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
#include <stdlib.h>

#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "rpc.h"
#include "sspi.h"
#include "wincred.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(sspicli);

static void *query_token_info( HANDLE token, TOKEN_INFORMATION_CLASS class )
{
    void *buffer;
    ULONG size = 0;
    NTSTATUS status;

    status = NtQueryInformationToken( token, class, NULL, 0, &size );
    if (status != STATUS_BUFFER_TOO_SMALL)
    {
        SetLastError( RtlNtStatusToDosError( status ));
        return NULL;
    }
    if (!(buffer = HeapAlloc( GetProcessHeap(), 0, size )))
    {
        SetLastError( ERROR_NOT_ENOUGH_MEMORY );
        return NULL;
    }
    if ((status = NtQueryInformationToken( token, class, buffer, size, &size )))
    {
        HeapFree( GetProcessHeap(), 0, buffer );
        SetLastError( RtlNtStatusToDosError( status ));
        return NULL;
    }
    return buffer;
}

static NTSTATUS create_supported_well_known_sid( WELL_KNOWN_SID_TYPE type, SID *sid )
{
    static const SID_IDENTIFIER_AUTHORITY world_authority = { SECURITY_WORLD_SID_AUTHORITY };
    static const SID_IDENTIFIER_AUTHORITY local_authority = { SECURITY_LOCAL_SID_AUTHORITY };
    static const SID_IDENTIFIER_AUTHORITY nt_authority = { SECURITY_NT_AUTHORITY };
    const SID_IDENTIFIER_AUTHORITY *authority;
    DWORD subauthorities[2];
    BYTE count;
    NTSTATUS status;

    switch (type)
    {
    case WinWorldSid:
        authority = &world_authority;
        count = 1;
        subauthorities[0] = SECURITY_WORLD_RID;
        break;
    case WinLocalSid:
        authority = &local_authority;
        count = 1;
        subauthorities[0] = SECURITY_LOCAL_RID;
        break;
    case WinNetworkSid:
        authority = &nt_authority;
        count = 1;
        subauthorities[0] = SECURITY_NETWORK_RID;
        break;
    case WinServiceSid:
        authority = &nt_authority;
        count = 1;
        subauthorities[0] = SECURITY_SERVICE_RID;
        break;
    case WinAuthenticatedUserSid:
        authority = &nt_authority;
        count = 1;
        subauthorities[0] = SECURITY_AUTHENTICATED_USER_RID;
        break;
    case WinLocalServiceSid:
        authority = &nt_authority;
        count = 1;
        subauthorities[0] = SECURITY_LOCAL_SERVICE_RID;
        break;
    case WinNetworkServiceSid:
        authority = &nt_authority;
        count = 1;
        subauthorities[0] = SECURITY_NETWORK_SERVICE_RID;
        break;
    case WinBuiltinUsersSid:
        authority = &nt_authority;
        count = 2;
        subauthorities[0] = SECURITY_BUILTIN_DOMAIN_RID;
        subauthorities[1] = DOMAIN_ALIAS_RID_USERS;
        break;
    default:
        return STATUS_NOT_SUPPORTED;
    }

    status = RtlInitializeSid( sid, (SID_IDENTIFIER_AUTHORITY *)authority, count );
    if (status) return status;
    while (count--) *RtlSubAuthoritySid( sid, count ) = subauthorities[count];
    return STATUS_SUCCESS;
}

static BOOL clone_system_token_with_groups( HANDLE source_token, const TOKEN_GROUPS *extra_groups,
                                            HANDLE *token )
{
    TOKEN_DEFAULT_DACL *default_dacl = NULL;
    TOKEN_PRIMARY_GROUP *primary_group = NULL;
    TOKEN_PRIVILEGES *privileges = NULL;
    TOKEN_STATISTICS *statistics = NULL;
    TOKEN_GROUPS *source_groups = NULL, *combined_groups = NULL;
    TOKEN_OWNER *owner = NULL;
    TOKEN_SOURCE source = {{0}};
    TOKEN_USER *user = NULL;
    OBJECT_ATTRIBUTES attributes;
    ULONG extra_count = extra_groups ? extra_groups->GroupCount : 0;
    ULONG source_count, count, i;
    SIZE_T size;
    NTSTATUS status;
    BOOL ret = FALSE;

    *token = NULL;
    if (!(default_dacl = query_token_info( source_token, TokenDefaultDacl )) ||
        !(primary_group = query_token_info( source_token, TokenPrimaryGroup )) ||
        !(privileges = query_token_info( source_token, TokenPrivileges )) ||
        !(statistics = query_token_info( source_token, TokenStatistics )) ||
        !(source_groups = query_token_info( source_token, TokenGroups )) ||
        !(owner = query_token_info( source_token, TokenOwner )) ||
        !(user = query_token_info( source_token, TokenUser )))
        goto done;

    source_count = source_groups->GroupCount;
    if (extra_count > MAXDWORD - source_count)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        goto done;
    }
    count = source_count + extra_count;
    if (count > (MAXDWORD - FIELD_OFFSET( TOKEN_GROUPS, Groups )) / sizeof(*combined_groups->Groups))
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        goto done;
    }
    size = FIELD_OFFSET( TOKEN_GROUPS, Groups ) + count * sizeof(*combined_groups->Groups);
    if (!(combined_groups = HeapAlloc( GetProcessHeap(), 0, size )))
    {
        SetLastError( ERROR_NOT_ENOUGH_MEMORY );
        goto done;
    }
    combined_groups->GroupCount = count;
    for (i = 0; i < source_count; ++i) combined_groups->Groups[i] = source_groups->Groups[i];
    for (i = 0; i < extra_count; ++i)
        combined_groups->Groups[source_count + i] = extra_groups->Groups[i];

    memcpy( source.SourceName, "SspiCli", sizeof("SspiCli") - 1 );
    NtAllocateLocallyUniqueId( &source.SourceIdentifier );
    InitializeObjectAttributes( &attributes, NULL, 0, NULL, NULL );
    status = NtCreateToken( token, MAXIMUM_ALLOWED, &attributes, TokenPrimary,
                            &statistics->AuthenticationId, &statistics->ExpirationTime,
                            user, combined_groups, privileges, owner, primary_group,
                            default_dacl, &source );
    if (status)
        SetLastError( RtlNtStatusToDosError( status ));
    else
        ret = TRUE;

done:
    HeapFree( GetProcessHeap(), 0, user );
    HeapFree( GetProcessHeap(), 0, owner );
    HeapFree( GetProcessHeap(), 0, combined_groups );
    HeapFree( GetProcessHeap(), 0, source_groups );
    HeapFree( GetProcessHeap(), 0, statistics );
    HeapFree( GetProcessHeap(), 0, privileges );
    HeapFree( GetProcessHeap(), 0, primary_group );
    HeapFree( GetProcessHeap(), 0, default_dacl );
    return ret;
}

static BOOL create_service_token( WELL_KNOWN_SID_TYPE user_type, DWORD authentication_id,
                                  const TOKEN_GROUPS *extra_groups, HANDLE *token )
{
    static const WELL_KNOWN_SID_TYPE group_types[] =
    {
        WinWorldSid,
        WinLocalSid,
        WinAuthenticatedUserSid,
        WinBuiltinUsersSid,
        WinServiceSid,
        WinNetworkSid,
    };
    union sid_buffer
    {
        SID sid;
        BYTE bytes[SECURITY_MAX_SID_SIZE];
    } user_buffer, group_buffers[ARRAY_SIZE(group_types)];
    struct token_privileges
    {
        DWORD PrivilegeCount;
        LUID_AND_ATTRIBUTES Privileges[4];
    } privileges;
    TOKEN_DEFAULT_DACL default_dacl = {NULL};
    TOKEN_PRIMARY_GROUP primary_group;
    TOKEN_GROUPS *combined_groups = NULL;
    TOKEN_OWNER owner;
    TOKEN_SOURCE source = {{0}};
    TOKEN_USER user;
    OBJECT_ATTRIBUTES attributes;
    LARGE_INTEGER expiration;
    LUID auth_id = {authentication_id, 0};
    ULONG base_count = user_type == WinNetworkServiceSid ? ARRAY_SIZE(group_types) :
                                                          ARRAY_SIZE(group_types) - 1;
    ULONG extra_count = extra_groups ? extra_groups->GroupCount : 0;
    ULONG count, i, size;
    NTSTATUS status;

    *token = NULL;
    if (extra_count > MAXDWORD - base_count ||
        base_count + extra_count >
        (MAXDWORD - FIELD_OFFSET( TOKEN_GROUPS, Groups )) / sizeof(*combined_groups->Groups))
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }

    status = create_supported_well_known_sid( user_type, &user_buffer.sid );
    if (status)
    {
        SetLastError( RtlNtStatusToDosError( status ));
        return FALSE;
    }
    count = base_count + extra_count;
    size = FIELD_OFFSET( TOKEN_GROUPS, Groups ) + count * sizeof(*combined_groups->Groups);
    if (!(combined_groups = HeapAlloc( GetProcessHeap(), 0, size )))
    {
        SetLastError( ERROR_NOT_ENOUGH_MEMORY );
        return FALSE;
    }
    combined_groups->GroupCount = count;
    for (i = 0; i < base_count; ++i)
    {
        status = create_supported_well_known_sid( group_types[i], &group_buffers[i].sid );
        if (status)
        {
            SetLastError( RtlNtStatusToDosError( status ));
            goto done;
        }
        combined_groups->Groups[i].Sid = &group_buffers[i].sid;
        combined_groups->Groups[i].Attributes = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT |
                                                SE_GROUP_ENABLED;
    }
    for (i = 0; i < extra_count; ++i)
        combined_groups->Groups[base_count + i] = extra_groups->Groups[i];

    privileges.PrivilegeCount = ARRAY_SIZE(privileges.Privileges);
    privileges.Privileges[0].Luid.LowPart = SE_CHANGE_NOTIFY_PRIVILEGE;
    privileges.Privileges[0].Luid.HighPart = 0;
    privileges.Privileges[1].Luid.LowPart = SE_IMPERSONATE_PRIVILEGE;
    privileges.Privileges[1].Luid.HighPart = 0;
    privileges.Privileges[2].Luid.LowPart = SE_CREATE_GLOBAL_PRIVILEGE;
    privileges.Privileges[2].Luid.HighPart = 0;
    privileges.Privileges[3].Luid.LowPart = SE_AUDIT_PRIVILEGE;
    privileges.Privileges[3].Luid.HighPart = 0;
    for (i = 0; i < privileges.PrivilegeCount; ++i)
        privileges.Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;

    user.User.Sid = &user_buffer.sid;
    user.User.Attributes = 0;
    owner.Owner = &user_buffer.sid;
    primary_group.PrimaryGroup = &group_buffers[3].sid; /* BUILTIN\\Users */
    memcpy( source.SourceName, "SspiCli", sizeof("SspiCli") - 1 );
    NtAllocateLocallyUniqueId( &source.SourceIdentifier );
    expiration.QuadPart = 0x7fffffffffffffff;
    InitializeObjectAttributes( &attributes, NULL, 0, NULL, NULL );
    status = NtCreateToken( token, MAXIMUM_ALLOWED, &attributes, TokenPrimary, &auth_id,
                            &expiration, &user, combined_groups,
                            (TOKEN_PRIVILEGES *)&privileges, &owner, &primary_group,
                            &default_dacl, &source );
    if (status)
    {
        SetLastError( RtlNtStatusToDosError( status ));
        goto done;
    }

    TRACE( "created service token %p for SID type %u, authentication id %#lx:%#lx\n",
           *token, user_type, auth_id.HighPart, auth_id.LowPart );

    HeapFree( GetProcessHeap(), 0, combined_groups );
    return TRUE;

done:
    HeapFree( GetProcessHeap(), 0, combined_groups );
    return FALSE;
}

static BOOL copy_logon_sid( HANDLE token, const TOKEN_GROUPS *groups, SID **logon_sid )
{
    TOKEN_USER *user = NULL;
    const SID *sid = NULL;
    DWORD i, size;
    NTSTATUS status;
    BOOL ret = FALSE;

    if (!logon_sid) return TRUE;
    *logon_sid = NULL;

    if (groups)
    {
        for (i = 0; i < groups->GroupCount; ++i)
        {
            if ((groups->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
            {
                sid = groups->Groups[i].Sid;
                break;
            }
        }
    }

    if (!sid)
    {
        if (!(user = query_token_info( token, TokenUser ))) goto done;
        sid = user->User.Sid;
    }

    if (!RtlValidSid( (SID *)sid ))
    {
        SetLastError( ERROR_INVALID_SID );
        goto done;
    }
    size = RtlLengthSid( (SID *)sid );
    if (!(*logon_sid = LocalAlloc( LMEM_FIXED, size ))) goto done;
    if ((status = RtlCopySid( size, *logon_sid, (SID *)sid )))
    {
        LocalFree( *logon_sid );
        *logon_sid = NULL;
        SetLastError( RtlNtStatusToDosError( status ));
        goto done;
    }
    ret = TRUE;

done:
    HeapFree( GetProcessHeap(), 0, user );
    return ret;
}

/***********************************************************************
 *              LogonUserExExW (SSPICLI.@)
 *
 * Native services.exe uses this entry point to obtain the primary token
 * for service hosts. Construct the supported service identities directly on
 * the Wine token boundary instead of entering the native LSA/ALPC path.
 */
BOOL WINAPI LogonUserExExW( const WCHAR *username, const WCHAR *domain, const WCHAR *password,
                            DWORD logon_type, DWORD provider, TOKEN_GROUPS *groups,
                            HANDLE *token, SID **logon_sid, void **profile_buffer,
                            DWORD *profile_length, QUOTA_LIMITS *quota_limits )
{
    HANDLE process_token, result_token;
    NTSTATUS status;
    BOOL ret;

    FIXME( "username %s, domain %s, password %p, type %lu, provider %lu, groups %p, "
           "token %p, logon sid %p, profile %p, profile length %p, quotas %p semi-stub\n",
           debugstr_w(username), debugstr_w(domain), password, logon_type, provider, groups,
           token, logon_sid, profile_buffer, profile_length, quota_limits );

    if (token) *token = NULL;
    if (logon_sid) *logon_sid = NULL;
    if (profile_buffer) *profile_buffer = NULL;
    if (profile_length) *profile_length = 0;
    if (quota_limits) memset( quota_limits, 0, sizeof(*quota_limits) );

    if (!username)
    {
        SetLastError( ERROR_LOGON_FAILURE );
        return FALSE;
    }

    if (!lstrcmpiW( username, L"LocalSystem" ) || !lstrcmpiW( username, L"SYSTEM" ))
    {
        status = NtOpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &process_token );
        if (status)
        {
            SetLastError( RtlNtStatusToDosError( status ));
            return FALSE;
        }
        ret = clone_system_token_with_groups( process_token, groups, &result_token );
        NtClose( process_token );
    }
    else if (!lstrcmpiW( username, L"LocalService" ))
        ret = create_service_token( WinLocalServiceSid, 0x3e5, groups, &result_token );
    else if (!lstrcmpiW( username, L"NetworkService" ))
        ret = create_service_token( WinNetworkServiceSid, 0x3e4, groups, &result_token );
    else
    {
        SetLastError( ERROR_LOGON_FAILURE );
        return FALSE;
    }
    if (!ret)
    {
        TRACE( "service-token creation for %s failed with error %lu\n",
               debugstr_w(username), GetLastError() );
        return FALSE;
    }

    if (!copy_logon_sid( result_token, groups, logon_sid ))
    {
        NtClose( result_token );
        return FALSE;
    }

    if (token) *token = result_token;
    else NtClose( result_token );
    return TRUE;
}

struct auth_identity_marshalled
{
    ULONG version;
    ULONG length;
    ULONG user_off;
    ULONG user_len;
    ULONG domain_off;
    ULONG domain_len;
    ULONG password_off;
    ULONG password_len;
    ULONG flags;
    ULONG package_list_off;
    ULONG package_list_len;
};

/***********************************************************************
 *		SspiEncodeStringsAsAuthIdentity (SECUR32.0)
 */
SECURITY_STATUS SEC_ENTRY SspiEncodeStringsAsAuthIdentity(
    const WCHAR *username, const WCHAR *domainname, const WCHAR *creds,
    PSEC_WINNT_AUTH_IDENTITY_OPAQUE *opaque_id )
{
    SEC_WINNT_AUTH_IDENTITY_EXW *id;
    DWORD len_username = 0, len_domainname = 0, len_password = 0, size;
    WCHAR *ptr;

    TRACE( "%s %s %s %p\n", debugstr_w(username), debugstr_w(domainname),
           debugstr_w(creds), opaque_id );

    if (!username && !domainname && !creds) return SEC_E_INVALID_TOKEN;

    if (username) len_username = lstrlenW( username );
    if (domainname) len_domainname = lstrlenW( domainname );
    if (creds) len_password = lstrlenW( creds );

    size = sizeof(*id) + (len_username + len_domainname + len_password) * sizeof(WCHAR) + sizeof(DWORD);
    if (!(id = calloc( 1, size ))) return ERROR_OUTOFMEMORY;
    ptr = (WCHAR *)(id + 1);

    id->Version = SEC_WINNT_AUTH_IDENTITY_VERSION;
    id->Length = sizeof(*id);
    id->Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE | SEC_WINNT_AUTH_IDENTITY_MARSHALLED;
    if (username)
    {
        memcpy( ptr, username, len_username * sizeof(WCHAR) );
        id->User       = ptr;
        id->UserLength = len_username;
        ptr += len_username;
    }
    if (domainname)
    {
        memcpy( ptr, domainname, len_domainname * sizeof(WCHAR) );
        id->Domain       = ptr;
        id->DomainLength = len_domainname;
        ptr += len_domainname;
    }
    if (creds)
    {
        memcpy( ptr, creds, len_password * sizeof(WCHAR) );
        id->Password       = ptr;
        id->PasswordLength = len_password;
    }

    *opaque_id = id;
    return SEC_E_OK;
}

/***********************************************************************
 *		SspiZeroAuthIdentity (SECUR32.0)
 */
void SEC_ENTRY SspiZeroAuthIdentity( PSEC_WINNT_AUTH_IDENTITY_OPAQUE opaque_id )
{
    SEC_WINNT_AUTH_IDENTITY_EXW *idex = (SEC_WINNT_AUTH_IDENTITY_EXW *)opaque_id;
    ULONG char_size;

    TRACE( "%p\n", opaque_id );

    if (!idex) return;

    if (idex->Version >= 0x10000)
    {
        SEC_WINNT_AUTH_IDENTITY_W *id = (SEC_WINNT_AUTH_IDENTITY_W *)opaque_id;

        char_size = id->Flags & SEC_WINNT_AUTH_IDENTITY_ANSI ? sizeof(char) : sizeof(WCHAR);
        memset( id->Password, 0, id->PasswordLength * char_size );
    }
    else if (idex->Version == SEC_WINNT_AUTH_IDENTITY_VERSION)
    {
        char_size = idex->Flags & SEC_WINNT_AUTH_IDENTITY_ANSI ? sizeof(char) : sizeof(WCHAR);
        memset( idex->Password, 0, idex->PasswordLength * char_size );
    }
    else if (idex->Version == SEC_WINNT_AUTH_IDENTITY_VERSION_2)
    {
        SEC_WINNT_AUTH_IDENTITY_EX2 *id = (SEC_WINNT_AUTH_IDENTITY_EX2 *)opaque_id;

        memset( (char *)id + id->PackedCredentialsOffset, 0, id->PackedCredentialsLength );
    }
    else
    {
        FIXME( "auth identity format not handled: %lu\n", idex->Version );
    }
}

static WCHAR *dup_auth_str( void *data, ULONG len, ULONG flags )
{
    ULONG ret_len;
    WCHAR *ret;

    if (!len) return NULL;

    if (flags & SEC_WINNT_AUTH_IDENTITY_ANSI)
    {
        ret_len = MultiByteToWideChar( CP_ACP, 0, data, len, NULL, 0 );
        ret = LocalAlloc( LMEM_FIXED, (ret_len + 1) * sizeof(WCHAR) );
        if (!ret) return ret;
        MultiByteToWideChar( CP_ACP, 0, data, len, ret, ret_len );
        ret[ret_len] = 0;
        return ret;
    }

    ret = LocalAlloc( LMEM_FIXED, (len + 1) * sizeof(WCHAR) );
    if (!ret) return ret;
    memcpy( ret, data, len * sizeof(WCHAR) );
    ret[len] = 0;
    return ret;
}

/***********************************************************************
 *		SspiEncodeAuthIdentityAsStrings (SECUR32.0)
 */
SECURITY_STATUS SEC_ENTRY SspiEncodeAuthIdentityAsStrings(
    PSEC_WINNT_AUTH_IDENTITY_OPAQUE opaque_id, PCWSTR *username,
    PCWSTR *domainname, PCWSTR *creds )
{
    SEC_WINNT_AUTH_IDENTITY_EXW *idex = (SEC_WINNT_AUTH_IDENTITY_EXW *)opaque_id;

    TRACE("%p %p %p %p\n", opaque_id, username, domainname, creds);

    if (idex->Version >= 0x10000)
    {
        SEC_WINNT_AUTH_IDENTITY_W *id = (SEC_WINNT_AUTH_IDENTITY_W *)opaque_id;

        *username = dup_auth_str( id->User, id->UserLength, id->Flags );
        *domainname = dup_auth_str( id->Domain, id->DomainLength, id->Flags );
        *creds = dup_auth_str( id->Password, id->PasswordLength, id->Flags );

    }
    else if (idex->Version == SEC_WINNT_AUTH_IDENTITY_VERSION)
    {
        *username = dup_auth_str( idex->User, idex->UserLength, idex->Flags );
        *domainname = dup_auth_str( idex->Domain, idex->DomainLength, idex->Flags );
        *creds = dup_auth_str( idex->Password, idex->PasswordLength, idex->Flags );
    }
    else
    {
        FIXME( "auth identity format not handled: %lu\n", idex->Version );
        return SEC_E_INTERNAL_ERROR;
    }

    return SEC_E_OK;
}

/***********************************************************************
 *		SspiFreeAuthIdentity (SECUR32.0)
 */
void SEC_ENTRY SspiFreeAuthIdentity( PSEC_WINNT_AUTH_IDENTITY_OPAQUE opaque_id )
{
    SEC_WINNT_AUTH_IDENTITY_EXW *idex = (SEC_WINNT_AUTH_IDENTITY_EXW *)opaque_id;

    TRACE( "%p\n", opaque_id );

    SspiZeroAuthIdentity( opaque_id );

    if (idex->Version >= 0x10000)
    {
        SEC_WINNT_AUTH_IDENTITY_W *id = (SEC_WINNT_AUTH_IDENTITY_W *)opaque_id;

        if (!(id->Flags & SEC_WINNT_AUTH_IDENTITY_MARSHALLED))
        {
            SspiLocalFree( id->User );
            SspiLocalFree( id->Domain );
            SspiLocalFree( id->Password );
        }
    }
    else if (idex->Version == SEC_WINNT_AUTH_IDENTITY_VERSION)
    {
        if (!(idex->Flags & SEC_WINNT_AUTH_IDENTITY_MARSHALLED))
        {
            SspiLocalFree( idex->User );
            SspiLocalFree( idex->Domain );
            SspiLocalFree( idex->Password );
        }
    }
    else if (idex->Version != SEC_WINNT_AUTH_IDENTITY_VERSION_2)
    {
        FIXME( "auth identity format not handled: %lu\n", idex->Version );
    }
    SspiLocalFree( opaque_id );
}

/***********************************************************************
 *		SspiLocalFree (SECUR32.0)
 */
void SEC_ENTRY SspiLocalFree( void *ptr )
{
    TRACE( "%p\n", ptr );
    LocalFree( ptr );
}

/***********************************************************************
 *		SspiPrepareForCredWrite (SECUR32.0)
 */
SECURITY_STATUS SEC_ENTRY SspiPrepareForCredWrite( PSEC_WINNT_AUTH_IDENTITY_OPAQUE opaque_id,
    PCWSTR target, PULONG type, PCWSTR *targetname, PCWSTR *username, PUCHAR *blob, PULONG size )
{
    const WCHAR *user, *domain, *password;
    SECURITY_STATUS status;
    WCHAR *str, *str2;
    ULONG len;

    FIXME( "%p %s %p %p %p %p %p\n", opaque_id, debugstr_w(target), type, targetname, username,
           blob, size );

    status = SspiEncodeAuthIdentityAsStrings( opaque_id, &user, &domain, &password );
    if (status) return status;

    if (domain)
    {
        len = (wcslen( user ) + wcslen( domain ) + 2) * sizeof(WCHAR);
        if (!(str = LocalAlloc( LMEM_FIXED, len ))) goto err;
        wcscpy( str, domain );
        wcscat( str, L"\\" );
        wcscat( str, user );
    }
    else
    {
        len = (wcslen( user ) + 1) * sizeof(WCHAR);
        if (!(str = LocalAlloc( LMEM_FIXED, len ))) goto err;
        wcscpy( str, user );
    }

    str2 = LocalAlloc( LMEM_FIXED, target ? (wcslen( target ) + 1) * sizeof(WCHAR) : len );
    str2 = target ? wcsdup( target ) : wcsdup( str );
    if (!str2) goto err;
    wcscpy( str2, target ? target : str );

    SspiLocalFree( (void *)user );
    SspiLocalFree( (void *)domain );

    *type = CRED_TYPE_DOMAIN_PASSWORD;
    *username = str;
    *targetname = str2;
    *blob = (UCHAR *)password;
    *size = wcslen( password ) * sizeof(WCHAR);
    return SEC_E_OK;

err:
    SspiLocalFree( (void *)user );
    SspiLocalFree( (void *)domain );
    if (password) SecureZeroMemory( (void *)password, wcslen(password) * sizeof(WCHAR) );
    SspiLocalFree( (void *)password );
    SspiLocalFree( (void *)str );
    return SEC_E_INSUFFICIENT_MEMORY;
}

/***********************************************************************
 *		SspiMarshalAuthIdentity
 */
SECURITY_STATUS SEC_ENTRY SspiMarshalAuthIdentity(
        PSEC_WINNT_AUTH_IDENTITY_OPAQUE opaque_id, ULONG *len, char **byte_array )
{
    SEC_WINNT_AUTH_IDENTITY_EXW *idex = opaque_id;
    struct auth_identity_marshalled *marshalled;
    ULONG size, char_size;
    BYTE *data;

    TRACE( "%p %p %p\n", opaque_id, len, byte_array );

    if (idex->Version >= 0x10000)
    {
        SEC_WINNT_AUTH_IDENTITY_W *id = (SEC_WINNT_AUTH_IDENTITY_W *)opaque_id;

        char_size = id->Flags & SEC_WINNT_AUTH_IDENTITY_ANSI ? sizeof(char) : sizeof(WCHAR);
        size = id->UserLength + id->DomainLength + id->PasswordLength;
        size = sizeof(*marshalled) + size * char_size + sizeof(DWORD);

        marshalled = LocalAlloc( LMEM_FIXED, size );
        if (!marshalled) return SEC_E_INSUFFICIENT_MEMORY;
        memset( marshalled, 0, sizeof(*marshalled) );
        data = (BYTE *)(marshalled + 1);

        marshalled->version = SEC_WINNT_AUTH_IDENTITY_VERSION;
        marshalled->length = sizeof(*marshalled);
        if (id->User)
        {
            marshalled->user_off = data - (BYTE *)marshalled;
            memcpy( data, id->User, id->UserLength * char_size );
            data += id->UserLength * char_size;
        }
        marshalled->user_len = id->UserLength;
        if (id->Domain)
        {
            marshalled->domain_off = data - (BYTE *)marshalled;
            memcpy( data, id->Domain, id->DomainLength * char_size );
            data += id->DomainLength * char_size;
        }
        marshalled->domain_len = id->DomainLength;
        if (id->Password)
        {
            marshalled->password_off = data - (BYTE *)marshalled;
            memcpy( data, id->Password, id->PasswordLength * char_size );
            data += id->PasswordLength * char_size;
        }
        marshalled->password_len = id->PasswordLength;
        marshalled->flags = id->Flags;

        *len = size;
        *byte_array = (char *)marshalled;
    }
    else if (idex->Version == SEC_WINNT_AUTH_IDENTITY_VERSION)
    {
        char_size = idex->Flags & SEC_WINNT_AUTH_IDENTITY_ANSI ? sizeof(char) : sizeof(WCHAR);
        size = idex->UserLength + idex->DomainLength + idex->PasswordLength + idex->PackageListLength;
        size = sizeof(*marshalled) + size * char_size + sizeof(DWORD);

        marshalled = LocalAlloc( LMEM_FIXED, size );
        if (!marshalled) return SEC_E_INSUFFICIENT_MEMORY;
        memset( marshalled, 0, sizeof(*marshalled) );
        data = (BYTE *)(marshalled + 1);

        marshalled->version = SEC_WINNT_AUTH_IDENTITY_VERSION;
        marshalled->length = sizeof(*marshalled);
        if (idex->User)
        {
            marshalled->user_off = data - (BYTE *)marshalled;
            memcpy( data, idex->User, idex->UserLength * char_size );
            data += idex->UserLength * char_size;
        }
        marshalled->user_len = idex->UserLength;
        if (idex->Domain)
        {
            marshalled->domain_off = data - (BYTE *)marshalled;
            memcpy( data, idex->Domain, idex->DomainLength * char_size );
            data += idex->DomainLength * char_size;
        }
        marshalled->domain_len = idex->DomainLength;
        if (idex->Password)
        {
            marshalled->password_off = data - (BYTE *)marshalled;
            memcpy( data, idex->Password, idex->PasswordLength * char_size );
            data += idex->PasswordLength * char_size;
        }
        marshalled->password_len = idex->PasswordLength;
        marshalled->flags = idex->Flags;
        if (idex->PackageList)
        {
            marshalled->package_list_off = data - (BYTE *)marshalled;
            memcpy( data, idex->PackageList, idex->PackageListLength * char_size );
            data += idex->PackageListLength * char_size;
        }
        marshalled->package_list_len = idex->PackageListLength;

        *len = size;
        *byte_array = (char *)marshalled;
    }
    else if (idex->Version == SEC_WINNT_AUTH_IDENTITY_VERSION_2)
    {
        SEC_WINNT_AUTH_IDENTITY_EX2 *id = (SEC_WINNT_AUTH_IDENTITY_EX2 *)opaque_id;

        *byte_array = LocalAlloc( LMEM_FIXED, id->cbStructureLength );
        if (!*byte_array) return SEC_E_INSUFFICIENT_MEMORY;
        memcpy( *byte_array, id, id->cbStructureLength );

        *len = id->cbStructureLength;
    }
    else
    {
        FIXME( "auth identity format not handled: %lu\n", idex->Version );
        return SEC_E_INTERNAL_ERROR;
    }

    return SEC_E_OK;
}

/***********************************************************************
 *		SspiUnmarshalAuthIdentity
 */
SECURITY_STATUS SEC_ENTRY SspiUnmarshalAuthIdentity(
        ULONG len, char *byte_array, PSEC_WINNT_AUTH_IDENTITY_OPAQUE *opaque_id )
{
    struct auth_identity_marshalled *marshalled = (struct auth_identity_marshalled *)byte_array;

    TRACE( "%lu %p %p\n", len, byte_array, opaque_id );

    if (len < sizeof(*marshalled)) return SEC_E_INVALID_TOKEN;

    if (marshalled->version == SEC_WINNT_AUTH_IDENTITY_VERSION)
    {
        SEC_WINNT_AUTH_IDENTITY_EXW *ret;
        ULONG size, char_size;
        BYTE *data;

        if (marshalled->length != sizeof(*marshalled)) return SEC_E_INVALID_TOKEN;

        char_size = marshalled->flags & SEC_WINNT_AUTH_IDENTITY_ANSI ? sizeof(char) : sizeof(WCHAR);
        size = marshalled->user_len + marshalled->domain_len +
            marshalled->password_len + marshalled->package_list_len;
        size = sizeof(*ret) + size * char_size;
        ret = LocalAlloc( LMEM_FIXED, size );
        if (!ret) return SEC_E_INSUFFICIENT_MEMORY;
        memset( ret, 0, size );

        data = (BYTE *)(ret + 1);
        ret->Version = SEC_WINNT_AUTH_IDENTITY_VERSION;
        ret->Length = sizeof(*ret);
        if (marshalled->user_off)
        {
            ret->User = (WCHAR *)data;
            memcpy( data, (BYTE *)marshalled + marshalled->user_off, marshalled->user_len * char_size );
            data += marshalled->user_len * char_size;
        }
        ret->UserLength = marshalled->user_len;
        if (marshalled->domain_off)
        {
            ret->Domain = (WCHAR *)data;
            memcpy( data, (BYTE *)marshalled + marshalled->domain_off, marshalled->domain_len * char_size );
            data += marshalled->domain_len * char_size;
        }
        ret->DomainLength = marshalled->domain_len;
        if (marshalled->password_off)
        {
            ret->Password = (WCHAR *)data;
            memcpy( data, (BYTE *)marshalled + marshalled->password_off, marshalled->password_len * char_size );
            data += marshalled->password_len * char_size;
        }
        ret->PasswordLength = marshalled->password_len;
        ret->Flags = marshalled->flags | SEC_WINNT_AUTH_IDENTITY_MARSHALLED;
        if (marshalled->package_list_off)
        {
            ret->PackageList = (WCHAR *)data;
            memcpy( data, (BYTE *)marshalled + marshalled->package_list_off,
                    marshalled->package_list_len * char_size );
            data += marshalled->package_list_len * char_size;
        }
        ret->PackageListLength = marshalled->package_list_len;

        *opaque_id = ret;
        return SEC_E_OK;
    }
    else if (marshalled->version == SEC_WINNT_AUTH_IDENTITY_VERSION_2)
    {
        SEC_WINNT_AUTH_IDENTITY_EX2 *id, *ret;

        id = (SEC_WINNT_AUTH_IDENTITY_EX2 *)marshalled;
        if (id->cbStructureLength > len) return SEC_E_INVALID_TOKEN;
        ret = LocalAlloc( LMEM_FIXED, sizeof(*ret) );
        if (!ret) return SEC_E_INSUFFICIENT_MEMORY;
        memcpy( ret, id, id->cbStructureLength );

        *opaque_id = ret;
        return SEC_E_OK;
    }

    return SEC_E_INVALID_TOKEN;
}
