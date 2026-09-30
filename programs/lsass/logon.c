/* Local interactive logon transaction owned by Wine LSASS. */

#include <stdarg.h>
#include <stdlib.h>
#include <wchar.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "ntsecapi.h"
#include "lmaccess.h"
#include "rpc.h"
#include "rpcdce.h"
#include "lsass.h"
#include "lsass_private.h"
#include "local_accounts.h"
#include "ksec.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(secur32);

#define LSASS_LOGON_CONTEXT_MAGIC 0x4c534c47
#define KERB_INTERACTIVE_LOGON_MESSAGE 2
#define KERB_WORKSTATION_UNLOCK_LOGON_MESSAGE 7
#define MSV1_0_INTERACTIVE_PROFILE_MESSAGE 2
#define SSPIEX_LOGON_USER_MESSAGE 0x8001

struct sspiex_logon_user
{
    ULONG message_type;
    ULONG flags;
    ULONG auth_len;
    ULONG reserved;
    void *client_auth_base;
};

struct kerb_interactive_logon
{
    ULONG message_type;
    UNICODE_STRING domain;
    UNICODE_STRING user;
    UNICODE_STRING password;
};

struct kerb_interactive_unlock_logon
{
    struct kerb_interactive_logon logon;
    LUID logon_id;
};

struct lsass_logon_context
{
    DWORD magic;
    DWORD process_id;
    HANDLE process;
    char name[128];
};

union sid_buffer
{
    SID sid;
    BYTE bytes[SECURITY_MAX_SID_SIZE];
};

static BOOL caller_has_tcb_privilege( handle_t binding )
{
    PRIVILEGE_SET privileges;
    HANDLE token;
    BOOL allowed = FALSE;
    RPC_STATUS rpc_status;
    DWORD error = ERROR_SUCCESS;

    if ((rpc_status = RpcImpersonateClient( binding )) != RPC_S_OK)
    {
        ERR( "linuxnt-lsa-tcb impersonate status=%lu\n", rpc_status );
        return FALSE;
    }
    if (OpenThreadToken( GetCurrentThread(), TOKEN_QUERY, TRUE, &token ))
    {
        privileges.PrivilegeCount = 1;
        privileges.Control = PRIVILEGE_SET_ALL_NECESSARY;
        privileges.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValueW( NULL, L"SeTcbPrivilege", &privileges.Privilege[0].Luid ))
            PrivilegeCheck( token, &privileges, &allowed );
        CloseHandle( token );
    }
    else error = GetLastError();
    ERR( "linuxnt-lsa-tcb open_error=%lu allowed=%u\n", error, allowed );
    RpcRevertToSelf();
    return allowed;
}

static void destroy_logon_context( struct lsass_logon_context *context )
{
    if (!context || context->magic != LSASS_LOGON_CONTEXT_MAGIC) return;
    context->magic = 0;
    if (context->process) CloseHandle( context->process );
    SecureZeroMemory( context, sizeof(*context) );
    free( context );
}

void __RPC_USER LSASS_LOGON_HANDLE_rundown( LSASS_LOGON_HANDLE handle )
{
    destroy_logon_context( handle );
}

NTSTATUS __cdecl register_logon_process( handle_t binding, DWORD thread_id, BYTE *name,
                                         ULONG name_len, ULONG *security_mode,
                                         LSASS_LOGON_HANDLE *handle )
{
    struct lsass_logon_context *context;
    CLIENT_ID cid;
    NTSTATUS status;
    DWORD process_id = 0;

    if (!security_mode || !handle || (!name && name_len) || name_len >= sizeof(context->name))
        return STATUS_INVALID_PARAMETER;
    *security_mode = 0;
    *handle = NULL;
    if (!caller_has_tcb_privilege( binding ))
    {
        ERR( "linuxnt-lsa-register-server privilege-not-held tid=%lu\n", thread_id );
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    status = I_RpcBindingInqLocalClientPID( binding, &process_id );
    if (status != RPC_S_OK || !process_id)
    {
        ERR( "linuxnt-lsa-register-server pid-status=%#lx pid=%lu tid=%lu\n",
             status, process_id, thread_id );
        return STATUS_ACCESS_DENIED;
    }
    if (!(context = calloc( 1, sizeof(*context) ))) return STATUS_NO_MEMORY;
    cid.UniqueProcess = ULongToHandle( process_id );
    cid.UniqueThread = NULL;
    status = NtOpenProcess( &context->process, PROCESS_QUERY_LIMITED_INFORMATION, NULL, &cid );
    if (status)
    {
        ERR( "linuxnt-lsa-register-server open-process pid=%lu status=%#lx\n",
             process_id, status );
        free( context );
        return status;
    }

    context->magic = LSASS_LOGON_CONTEXT_MAGIC;
    context->process_id = process_id;
    if (name_len) memcpy( context->name, name, name_len );
    context->name[name_len] = 0;
    *handle = context;
    TRACE( "registered trusted logon process %s pid %lu tid %lu\n",
           debugstr_a(context->name), process_id, thread_id );
    return STATUS_SUCCESS;
}

NTSTATUS __cdecl deregister_logon_process( LSASS_LOGON_HANDLE *handle )
{
    struct lsass_logon_context *context;

    if (!handle || !(context = *handle) || context->magic != LSASS_LOGON_CONTEXT_MAGIC)
        return STATUS_INVALID_HANDLE;
    destroy_logon_context( context );
    *handle = NULL;
    return STATUS_SUCCESS;
}

static NTSTATUS copy_auth_string( const BYTE *auth_buf, const void *client_base, ULONG auth_len,
                                  const UNICODE_STRING *source, WCHAR **result )
{
    ULONG_PTR base = (ULONG_PTR)client_base, address = (ULONG_PTR)source->Buffer;
    SIZE_T offset;
    WCHAR *copy;

    *result = NULL;
    if ((source->Length & 1) || source->Length > source->MaximumLength) return STATUS_INVALID_PARAMETER;
    if (!source->Length)
    {
        if (!(copy = calloc( 1, sizeof(WCHAR) ))) return STATUS_NO_MEMORY;
        *result = copy;
        return STATUS_SUCCESS;
    }
    if (!source->Buffer) return STATUS_INVALID_PARAMETER;
    offset = address < base ? address : address - base;
    if (offset > auth_len || source->Length > auth_len - offset) return STATUS_INVALID_PARAMETER;
    if (!(copy = malloc( source->Length + sizeof(WCHAR) ))) return STATUS_NO_MEMORY;
    memcpy( copy, auth_buf + offset, source->Length );
    copy[source->Length / sizeof(WCHAR)] = 0;
    *result = copy;
    return STATUS_SUCCESS;
}

static NTSTATUS create_profile( const WCHAR *user, LSASS_INTERACTIVE_PROFILE *profile )
{
    WCHAR computer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD computer_len = ARRAY_SIZE(computer);
    FILETIME now;

    if (!GetComputerNameW( computer, &computer_len )) return STATUS_UNSUCCESSFUL;
    if (swprintf( profile->ProfilePath, ARRAY_SIZE(profile->ProfilePath),
                  L"C:\\users\\%s", user ) < 0)
        return STATUS_NAME_TOO_LONG;
    if (wcslen(user) >= ARRAY_SIZE(profile->FullName)) return STATUS_NAME_TOO_LONG;
    profile->LogonServer[0] = '\\';
    profile->LogonServer[1] = '\\';
    memcpy( profile->LogonServer + 2, computer, (computer_len + 1) * sizeof(WCHAR) );

    GetSystemTimeAsFileTime( &now );
    profile->LogonTime.LowPart = now.dwLowDateTime;
    profile->LogonTime.HighPart = now.dwHighDateTime;
    profile->LogoffTime.LowPart = ~0u;
    profile->LogoffTime.HighPart = 0x7fffffff;
    profile->KickOffTime = profile->LogoffTime;
    profile->PasswordMustChange = profile->LogoffTime;
    profile->LogonCount = 1;
    wcscpy( profile->HomeDirectory, profile->ProfilePath );
    wcscpy( profile->FullName, user );
    return STATUS_SUCCESS;
}

static NTSTATUS initialize_sid( SID *sid, const SID_IDENTIFIER_AUTHORITY *authority,
                                BYTE count, const DWORD *subauthorities )
{
    NTSTATUS status;
    BYTE i;

    if ((status = RtlInitializeSid( sid, (SID_IDENTIFIER_AUTHORITY *)authority, count ))) return status;
    for (i = 0; i < count; ++i) *RtlSubAuthoritySid( sid, i ) = subauthorities[i];
    return STATUS_SUCCESS;
}

static NTSTATUS get_client_session_id( handle_t binding, DWORD *session_id )
{
    HANDLE token;
    RPC_STATUS rpc_status;
    NTSTATUS status;

    if ((rpc_status = RpcImpersonateClient( binding )) != RPC_S_OK)
    {
        WARN( "could not impersonate the logon client, status %lu\n", rpc_status );
        return STATUS_ACCESS_DENIED;
    }

    status = NtOpenThreadToken( GetCurrentThread(), TOKEN_QUERY, TRUE, &token );
    if (!status)
    {
        status = NtQueryInformationToken( token, TokenSessionId, session_id,
                                          sizeof(*session_id), NULL );
        NtClose( token );
    }
    if (RpcRevertToSelfEx( binding ) != RPC_S_OK && !status) status = STATUS_ACCESS_DENIED;
    return status;
}

static NTSTATUS create_local_token( const struct lsa_local_account *account, DWORD session_id,
                                    const BYTE source_name[8], const LUID *source_id,
                                    const LSASS_TOKEN_GROUP *extra_groups, ULONG extra_count,
                                    LUID *logon_id, HANDLE *token )
{
    static const SID_IDENTIFIER_AUTHORITY world_authority = { SECURITY_WORLD_SID_AUTHORITY };
    static const SID_IDENTIFIER_AUTHORITY local_authority = { SECURITY_LOCAL_SID_AUTHORITY };
    static const SID_IDENTIFIER_AUTHORITY nt_authority = { SECURITY_NT_AUTHORITY };
    static const DWORD world_subauth[] = { SECURITY_WORLD_RID };
    static const DWORD local_subauth[] = { SECURITY_LOCAL_RID };
    static const DWORD authenticated_subauth[] = { SECURITY_AUTHENTICATED_USER_RID };
    static const DWORD users_subauth[] = { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS };
    static const DWORD admins_subauth[] = { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS };
    static const DWORD interactive_subauth[] = { SECURITY_INTERACTIVE_RID };
    static const DWORD system_subauth[] = { SECURITY_LOCAL_SYSTEM_RID };
    union sid_buffer world, local, authenticated, users, admins, interactive, logon, system;
    BYTE default_dacl_buffer[sizeof(ACL) + 2 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + SECURITY_MAX_SID_SIZE)];
    DWORD logon_subauth[3];
    TOKEN_GROUPS *groups = NULL;
    SID_AND_ATTRIBUTES *group_entries;
    struct
    {
        DWORD PrivilegeCount;
        LUID_AND_ATTRIBUTES Privileges[1];
    } privileges;
    TOKEN_DEFAULT_DACL default_dacl;
    TOKEN_PRIMARY_GROUP primary_group;
    TOKEN_OWNER owner;
    TOKEN_SOURCE source;
    TOKEN_USER user;
    OBJECT_ATTRIBUTES attributes;
    LARGE_INTEGER expiration;
    SID *user_sid;
    ULONG group_count, i;
    BOOL have_logon_id = FALSE;
    NTSTATUS status;

    *token = NULL;
    if (!(user_sid = lsa_allocate_local_account_sid( account->rid ))) return STATUS_NO_MEMORY;
    if (extra_count > 1024)
    {
        status = STATUS_INVALID_PARAMETER;
        goto done;
    }
    for (i = 0; i < extra_count; ++i)
    {
        const SID *sid = (const SID *)extra_groups[i].Sid;

        TRACE( "supplemental group %lu: revision %u authority %u count %u first %#lx length %lu attributes %#lx\n",
               i, sid->Revision, sid->IdentifierAuthority.Value[5], sid->SubAuthorityCount,
               sid->SubAuthorityCount ? sid->SubAuthority[0] : 0,
               extra_groups[i].SidLength, extra_groups[i].Attributes );

        if (!extra_groups[i].SidLength || extra_groups[i].SidLength > sizeof(extra_groups[i].Sid) ||
            !RtlValidSid( (SID *)sid ) || RtlLengthSid( (SID *)sid ) != extra_groups[i].SidLength)
        {
            status = STATUS_INVALID_SID;
            goto done;
        }
        if ((extra_groups[i].Attributes & SE_GROUP_LOGON_ID) && sid->SubAuthorityCount == 3 &&
            !memcmp( &sid->IdentifierAuthority, &nt_authority, sizeof(nt_authority) ) &&
            sid->SubAuthority[0] == SECURITY_LOGON_IDS_RID)
        {
            logon_id->HighPart = sid->SubAuthority[1];
            logon_id->LowPart = sid->SubAuthority[2];
            have_logon_id = TRUE;
        }
    }
    if (!have_logon_id && (status = NtAllocateLocallyUniqueId( logon_id ))) goto done;
    logon_subauth[0] = SECURITY_LOGON_IDS_RID;
    logon_subauth[1] = logon_id->HighPart;
    logon_subauth[2] = logon_id->LowPart;
    if ((status = initialize_sid( &world.sid, &world_authority, 1, world_subauth )) ||
        (status = initialize_sid( &local.sid, &local_authority, 1, local_subauth )) ||
        (status = initialize_sid( &authenticated.sid, &nt_authority, 1, authenticated_subauth )) ||
        (status = initialize_sid( &users.sid, &nt_authority, 2, users_subauth )) ||
        (status = initialize_sid( &admins.sid, &nt_authority, 2, admins_subauth )) ||
        (status = initialize_sid( &interactive.sid, &nt_authority, 1, interactive_subauth )) ||
        (status = initialize_sid( &logon.sid, &nt_authority, 3, logon_subauth )) ||
        (status = initialize_sid( &system.sid, &nt_authority, 1, system_subauth )))
        goto done;

    default_dacl.DefaultDacl = (ACL *)default_dacl_buffer;
    if ((status = RtlCreateAcl( default_dacl.DefaultDacl, sizeof(default_dacl_buffer), ACL_REVISION )) ||
        (status = RtlAddAccessAllowedAce( default_dacl.DefaultDacl, ACL_REVISION, GENERIC_ALL, &system.sid )) ||
        (status = RtlAddAccessAllowedAce( default_dacl.DefaultDacl, ACL_REVISION, GENERIC_ALL, user_sid )))
        goto done;

    group_count = 6 + extra_count + !have_logon_id;
    if (!(groups = malloc( FIELD_OFFSET(TOKEN_GROUPS, Groups[group_count]) )))
    {
        status = STATUS_NO_MEMORY;
        goto done;
    }
    groups->GroupCount = group_count;
    group_entries = groups->Groups;
#define SET_GROUP(index, sid_value, attrs) \
    do { group_entries[index].Sid = &(sid_value).sid; group_entries[index].Attributes = (attrs); } while (0)
    SET_GROUP( 0, world, SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED );
    SET_GROUP( 1, local, SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED );
    SET_GROUP( 2, authenticated, SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED );
    SET_GROUP( 3, users, SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED );
    SET_GROUP( 4, admins, SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED );
    SET_GROUP( 5, interactive, SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED );
    if (!have_logon_id)
        SET_GROUP( 6, logon, SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT |
                             SE_GROUP_ENABLED | SE_GROUP_LOGON_ID );
#undef SET_GROUP
    for (i = 0; i < extra_count; ++i)
    {
        ULONG index = 6 + !have_logon_id + i;
        group_entries[index].Sid = (SID *)extra_groups[i].Sid;
        group_entries[index].Attributes = extra_groups[i].Attributes;
    }

    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid.LowPart = SE_CHANGE_NOTIFY_PRIVILEGE;
    privileges.Privileges[0].Luid.HighPart = 0;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    user.User.Sid = user_sid;
    user.User.Attributes = 0;
    owner.Owner = user_sid;
    primary_group.PrimaryGroup = &users.sid;
    memcpy( source.SourceName, source_name, sizeof(source.SourceName) );
    source.SourceIdentifier = *source_id;
    expiration.QuadPart = 0x7fffffffffffffff;
    InitializeObjectAttributes( &attributes, NULL, 0, NULL, NULL );
    status = NtCreateToken( token, TOKEN_ALL_ACCESS, &attributes, TokenPrimary, logon_id,
                            &expiration, &user, groups,
                            (TOKEN_PRIVILEGES *)&privileges, &owner, &primary_group,
                            &default_dacl, &source );
    TRACE( "NtCreateToken returned %#lx for %lu groups\n", status, group_count );
    if (status) goto done;
    status = NtSetInformationToken( *token, TokenSessionId, &session_id, sizeof(session_id) );
    if (status)
    {
        NtClose( *token );
        *token = NULL;
    }

done:
    free( groups );
    MIDL_user_free( user_sid );
    return status;
}

static void unprotect_interactive_password( WCHAR **password, USHORT password_length )
{
    typedef BOOL (WINAPI *cred_is_protected_fn)(WCHAR *, DWORD *);
    typedef BOOL (WINAPI *cred_unprotect_fn)(BOOL, WCHAR *, DWORD, WCHAR *, DWORD *);
    cred_is_protected_fn cred_is_protected;
    cred_unprotect_fn cred_unprotect;
    LDR_DATA_TABLE_ENTRY *entry;
    DWORD protection, clear_chars = 0;
    HMODULE module;
    WCHAR *clear;

    if (!password || !*password || password_length < 16) return;
    if (!(module = GetModuleHandleW( L"sechost.dll" )) ||
        LdrFindEntryForAddress( module, &entry ) || (entry->Flags & LDR_WINE_INTERNAL))
        return;
    if (!(cred_is_protected = (void *)GetProcAddress( module, "CredIsProtectedW" )) ||
        !(cred_unprotect = (void *)GetProcAddress( module, "CredUnprotectW" )) ||
        !cred_is_protected( *password, &protection ) || !protection)
        return;

    cred_unprotect( FALSE, *password, password_length / sizeof(WCHAR), NULL, &clear_chars );
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !clear_chars ||
        !(clear = calloc( clear_chars, sizeof(WCHAR) )))
        return;
    if (!cred_unprotect( FALSE, *password, password_length / sizeof(WCHAR), clear, &clear_chars ))
    {
        SecureZeroMemory( clear, clear_chars * sizeof(WCHAR) );
        free( clear );
        return;
    }

    SecureZeroMemory( *password, (password_length / sizeof(WCHAR) + 1) * sizeof(WCHAR) );
    free( *password );
    *password = clear;
    TRACE( "unprotected an interactive credential of type %lu\n", protection );
}

NTSTATUS __cdecl logon_user( handle_t binding, DWORD thread_id, LSASS_LOGON_HANDLE handle,
                             BYTE *origin, ULONG origin_len, ULONG logon_type, ULONG package_id,
                             BYTE *auth_buf, void *client_auth_base, ULONG auth_len,
                             LSASS_TOKEN_GROUP *local_groups, ULONG local_group_count,
                             BYTE source_name[8], LUID source_id,
                             LSASS_INTERACTIVE_PROFILE *profile, LUID *logon_id,
                             ULONG64 *token, LSASS_QUOTA_LIMITS *quotas, NTSTATUS *substatus )
{
    struct lsass_logon_context *context = handle;
    const struct kerb_interactive_logon *logon;
    struct lsa_local_account account;
    WCHAR *domain = NULL, *user = NULL, *password = NULL;
    HANDLE local_token = NULL, remote_token = NULL;
    DWORD process_id, session_id;
    NTSTATUS status;

    TRACE( "handle %p, type %lu, package %lu, auth length %lu, local groups %lu\n",
           handle, logon_type, package_id, auth_len, local_group_count );

    if (!profile || !logon_id || !token || !quotas || !substatus) return STATUS_INVALID_PARAMETER;
    memset( profile, 0, sizeof(*profile) );
    memset( logon_id, 0, sizeof(*logon_id) );
    *token = 0;
    memset( quotas, 0, sizeof(*quotas) );
    *substatus = STATUS_SUCCESS;
    if (!context || context->magic != LSASS_LOGON_CONTEXT_MAGIC) return STATUS_INVALID_HANDLE;
    if ((!origin && origin_len) || origin_len > 127 || !auth_buf || !client_auth_base ||
        (!local_groups && local_group_count))
        return STATUS_INVALID_PARAMETER;
    if (I_RpcBindingInqLocalClientPID( binding, &process_id ) != RPC_S_OK ||
        process_id != context->process_id)
        return STATUS_ACCESS_DENIED;
    if (logon_type != Interactive && logon_type != Unlock) return STATUS_INVALID_LOGON_TYPE;
    if (!lsa_package_supports_local_interactive( package_id )) return STATUS_NO_SUCH_PACKAGE;

    if (auth_len >= sizeof(struct sspiex_logon_user) &&
        *(const ULONG *)auth_buf == SSPIEX_LOGON_USER_MESSAGE)
    {
        const struct sspiex_logon_user *request = (const struct sspiex_logon_user *)auth_buf;

        if (request->auth_len > auth_len - sizeof(*request)) return STATUS_INVALID_PARAMETER;
        client_auth_base = request->client_auth_base;
        auth_buf += sizeof(*request);
        auth_len = request->auth_len;
        TRACE( "unwrapped SspiEx logon flags %#lx, auth base %p, auth length %lu\n",
               request->flags, client_auth_base, auth_len );
    }
    if (auth_len < sizeof(*logon)) return STATUS_INVALID_PARAMETER;

    logon = (const struct kerb_interactive_logon *)auth_buf;
    if (logon->message_type != KERB_INTERACTIVE_LOGON_MESSAGE &&
        logon->message_type != KERB_WORKSTATION_UNLOCK_LOGON_MESSAGE)
        return STATUS_BAD_VALIDATION_CLASS;
    if (logon->message_type == KERB_WORKSTATION_UNLOCK_LOGON_MESSAGE &&
        auth_len < sizeof(struct kerb_interactive_unlock_logon))
        return STATUS_INVALID_PARAMETER;
    TRACE( "auth base %p domain {%u,%u,%p} user {%u,%u,%p} password {%u,%u,%p}\n",
           client_auth_base, logon->domain.Length, logon->domain.MaximumLength, logon->domain.Buffer,
           logon->user.Length, logon->user.MaximumLength, logon->user.Buffer,
           logon->password.Length, logon->password.MaximumLength, logon->password.Buffer );
    if ((status = copy_auth_string( auth_buf, client_auth_base, auth_len, &logon->domain, &domain )) ||
        (status = copy_auth_string( auth_buf, client_auth_base, auth_len, &logon->user, &user )) ||
        (status = copy_auth_string( auth_buf, client_auth_base, auth_len, &logon->password, &password )))
        goto done;

    TRACE( "interactive credentials domain %s user %s\n", debugstr_w(domain), debugstr_w(user) );
    unprotect_interactive_password( &password, logon->password.Length );
    status = lsa_validate_local_credentials( domain, user, password, &account, substatus );
    TRACE( "credential validation returned %#lx, substatus %#lx, local account %s\n",
           status, *substatus, debugstr_w(account.name) );
    if (status) goto done;
    if ((status = create_profile( account.name, profile ))) goto done;
    if ((status = get_client_session_id( binding, &session_id ))) goto done;
    if ((status = create_local_token( &account, session_id, source_name, &source_id,
                                      local_groups, local_group_count,
                                      logon_id, &local_token )))
    {
        TRACE( "local token creation returned %#lx\n", status );
        goto done;
    }
    status = lsa_ksec_transfer_handle( local_token, context->process, package_id, &remote_token );
    if (!status)
    {
        *token = (ULONG_PTR)remote_token;
        TRACE( "interactive logon committed for %s through %s pid %lu tid %lu\n",
               debugstr_w(account.name), debugstr_a(context->name), process_id, thread_id );
    }

done:
    if (local_token) NtClose( local_token );
    if (status) memset( profile, 0, sizeof(*profile) );
    if (password)
    {
        SecureZeroMemory( password, (wcslen(password) + 1) * sizeof(WCHAR) );
        free( password );
    }
    free( user );
    free( domain );
    return status;
}
