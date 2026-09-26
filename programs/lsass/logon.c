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

    if (RpcImpersonateClient( binding ) != RPC_S_OK) return FALSE;
    if (OpenThreadToken( GetCurrentThread(), TOKEN_QUERY, TRUE, &token ))
    {
        privileges.PrivilegeCount = 1;
        privileges.Control = PRIVILEGE_SET_ALL_NECESSARY;
        privileges.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValueW( NULL, L"SeTcbPrivilege", &privileges.Privilege[0].Luid ))
            PrivilegeCheck( token, &privileges, &allowed );
        CloseHandle( token );
    }
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
    DWORD process_id;

    if (!security_mode || !handle || (!name && name_len) || name_len >= sizeof(context->name))
        return STATUS_INVALID_PARAMETER;
    *security_mode = 0;
    *handle = NULL;
    if (!caller_has_tcb_privilege( binding )) return STATUS_PRIVILEGE_NOT_HELD;
    if (I_RpcBindingInqLocalClientPID( binding, &process_id ) != RPC_S_OK || !process_id)
        return STATUS_ACCESS_DENIED;
    if (!(context = calloc( 1, sizeof(*context) ))) return STATUS_NO_MEMORY;
    cid.UniqueProcess = ULongToHandle( process_id );
    cid.UniqueThread = NULL;
    status = NtOpenProcess( &context->process, PROCESS_QUERY_LIMITED_INFORMATION, NULL, &cid );
    if (status)
    {
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
    if (!source->Buffer || address < base) return STATUS_INVALID_PARAMETER;
    offset = address - base;
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

static NTSTATUS create_local_token( const struct lsa_local_account *account, DWORD client_process_id,
                                    const BYTE source_name[8], const LUID *source_id,
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
    union sid_buffer world, local, authenticated, users, admins, interactive, logon;
    DWORD logon_subauth[3];
    struct
    {
        DWORD GroupCount;
        SID_AND_ATTRIBUTES Groups[7];
    } groups;
    struct
    {
        DWORD PrivilegeCount;
        LUID_AND_ATTRIBUTES Privileges[1];
    } privileges;
    TOKEN_DEFAULT_DACL default_dacl = {NULL};
    TOKEN_PRIMARY_GROUP primary_group;
    TOKEN_OWNER owner;
    TOKEN_SOURCE source;
    TOKEN_USER user;
    OBJECT_ATTRIBUTES attributes;
    LARGE_INTEGER expiration;
    SID *user_sid;
    DWORD session_id;
    NTSTATUS status;

    *token = NULL;
    if (!(user_sid = lsa_allocate_local_account_sid( account->rid ))) return STATUS_NO_MEMORY;
    if ((status = NtAllocateLocallyUniqueId( logon_id ))) goto done;
    logon_subauth[0] = SECURITY_LOGON_IDS_RID;
    logon_subauth[1] = logon_id->HighPart;
    logon_subauth[2] = logon_id->LowPart;
    if ((status = initialize_sid( &world.sid, &world_authority, 1, world_subauth )) ||
        (status = initialize_sid( &local.sid, &local_authority, 1, local_subauth )) ||
        (status = initialize_sid( &authenticated.sid, &nt_authority, 1, authenticated_subauth )) ||
        (status = initialize_sid( &users.sid, &nt_authority, 2, users_subauth )) ||
        (status = initialize_sid( &admins.sid, &nt_authority, 2, admins_subauth )) ||
        (status = initialize_sid( &interactive.sid, &nt_authority, 1, interactive_subauth )) ||
        (status = initialize_sid( &logon.sid, &nt_authority, 3, logon_subauth )))
        goto done;

    groups.GroupCount = ARRAY_SIZE(groups.Groups);
#define SET_GROUP(index, sid_value, attrs) \
    do { groups.Groups[index].Sid = &(sid_value).sid; groups.Groups[index].Attributes = (attrs); } while (0)
    SET_GROUP( 0, world, SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED );
    SET_GROUP( 1, local, SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED );
    SET_GROUP( 2, authenticated, SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED );
    SET_GROUP( 3, users, SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED );
    SET_GROUP( 4, admins, SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED );
    SET_GROUP( 5, interactive, SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED );
    SET_GROUP( 6, logon, SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT |
                         SE_GROUP_ENABLED | SE_GROUP_LOGON_ID );
#undef SET_GROUP

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
                            &expiration, &user, (TOKEN_GROUPS *)&groups,
                            (TOKEN_PRIVILEGES *)&privileges, &owner, &primary_group,
                            &default_dacl, &source );
    if (status) goto done;
    if (!ProcessIdToSessionId( client_process_id, &session_id ))
        status = STATUS_UNSUCCESSFUL;
    else
        status = NtSetInformationToken( *token, TokenSessionId, &session_id, sizeof(session_id) );
    if (status)
    {
        NtClose( *token );
        *token = NULL;
    }

done:
    MIDL_user_free( user_sid );
    return status;
}

NTSTATUS __cdecl logon_user( handle_t binding, DWORD thread_id, LSASS_LOGON_HANDLE handle,
                             BYTE *origin, ULONG origin_len, ULONG logon_type, ULONG package_id,
                             BYTE *auth_buf, void *client_auth_base, ULONG auth_len,
                             BYTE source_name[8], LUID source_id,
                             LSASS_INTERACTIVE_PROFILE *profile, LUID *logon_id,
                             ULONG64 *token, LSASS_QUOTA_LIMITS *quotas, NTSTATUS *substatus )
{
    struct lsass_logon_context *context = handle;
    const struct kerb_interactive_logon *logon;
    struct lsa_local_account account;
    WCHAR *domain = NULL, *user = NULL, *password = NULL;
    HANDLE local_token = NULL, remote_token = NULL;
    DWORD process_id;
    NTSTATUS status;

    if (!profile || !logon_id || !token || !quotas || !substatus) return STATUS_INVALID_PARAMETER;
    memset( profile, 0, sizeof(*profile) );
    memset( logon_id, 0, sizeof(*logon_id) );
    *token = 0;
    memset( quotas, 0, sizeof(*quotas) );
    *substatus = STATUS_SUCCESS;
    if (!context || context->magic != LSASS_LOGON_CONTEXT_MAGIC) return STATUS_INVALID_HANDLE;
    if ((!origin && origin_len) || origin_len > 127 || !auth_buf || !client_auth_base)
        return STATUS_INVALID_PARAMETER;
    if (I_RpcBindingInqLocalClientPID( binding, &process_id ) != RPC_S_OK ||
        process_id != context->process_id)
        return STATUS_ACCESS_DENIED;
    if (logon_type != Interactive && logon_type != Unlock) return STATUS_INVALID_LOGON_TYPE;
    if (!lsa_package_supports_local_interactive( package_id )) return STATUS_NO_SUCH_PACKAGE;
    if (auth_len < sizeof(*logon)) return STATUS_INVALID_PARAMETER;

    logon = (const struct kerb_interactive_logon *)auth_buf;
    if (logon->message_type != KERB_INTERACTIVE_LOGON_MESSAGE &&
        logon->message_type != KERB_WORKSTATION_UNLOCK_LOGON_MESSAGE)
        return STATUS_BAD_VALIDATION_CLASS;
    if (logon->message_type == KERB_WORKSTATION_UNLOCK_LOGON_MESSAGE &&
        auth_len < sizeof(struct kerb_interactive_unlock_logon))
        return STATUS_INVALID_PARAMETER;
    if ((status = copy_auth_string( auth_buf, client_auth_base, auth_len, &logon->domain, &domain )) ||
        (status = copy_auth_string( auth_buf, client_auth_base, auth_len, &logon->user, &user )) ||
        (status = copy_auth_string( auth_buf, client_auth_base, auth_len, &logon->password, &password )))
        goto done;

    status = lsa_validate_local_credentials( domain, user, password, &account, substatus );
    if (status) goto done;
    if ((status = create_profile( account.name, profile ))) goto done;
    if ((status = create_local_token( &account, process_id, source_name, &source_id,
                                      logon_id, &local_token )))
        goto done;
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
