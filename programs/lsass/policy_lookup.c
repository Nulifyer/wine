/*
 * LSA local policy lookup RPC interface
 *
 * Copyright 2026
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "lmcons.h"
#include "winternl.h"
#include "ntsecapi.h"
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "lsapolicylookup.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(secur32);

#define POLICY_LOOKUP_CONTEXT_MAGIC 0x4c504c53

struct policy_lookup_context
{
    DWORD magic;
    ACCESS_MASK access;
};

static BOOL copy_rpc_string( LSA_POLICY_LOOKUP_UNICODE_STRING *dst, const WCHAR *src,
                             USHORT length );

handle_t __RPC_USER LSA_POLICY_LOOKUP_SERVER_NAME_bind( LSA_POLICY_LOOKUP_SERVER_NAME name )
{
    return NULL;
}

void __RPC_USER LSA_POLICY_LOOKUP_SERVER_NAME_unbind( LSA_POLICY_LOOKUP_SERVER_NAME name,
                                                       handle_t binding )
{
}

void __RPC_USER LSA_POLICY_LOOKUP_HANDLE_rundown( LSA_POLICY_LOOKUP_HANDLE handle )
{
    struct policy_lookup_context *context = handle;

    if (!context) return;
    context->magic = 0;
    free( context );
}

NTSTATUS policy_lookup_open( LSA_POLICY_LOOKUP_SERVER_NAME server_name,
                             LSA_POLICY_LOOKUP_OBJECT_ATTRIBUTES *attributes,
                             ULONG access, LSA_POLICY_LOOKUP_HANDLE *handle )
{
    struct policy_lookup_context *context;

    TRACE( "server %s, attributes %p, access %#lx, handle %p\n",
           debugstr_w(server_name), attributes, access, handle );

    if (!attributes || !handle) return STATUS_INVALID_PARAMETER;
    if (!(context = malloc( sizeof(*context) ))) return STATUS_NO_MEMORY;

    context->magic = POLICY_LOOKUP_CONTEXT_MAGIC;
    context->access = access;
    TRACE( "created context %p, magic %#lx\n", context, context->magic );
    *handle = context;
    return STATUS_SUCCESS;
}

NTSTATUS policy_lookup_close( LSA_POLICY_LOOKUP_HANDLE *handle )
{
    struct policy_lookup_context *context;

    if (!handle || !(context = *handle) || context->magic != POLICY_LOOKUP_CONTEXT_MAGIC)
        return STATUS_INVALID_HANDLE;

    context->magic = 0;
    free( context );
    *handle = NULL;
    return STATUS_SUCCESS;
}

static BOOL rpc_string_equal( const WCHAR *buffer, USHORT length, const WCHAR *value )
{
    SIZE_T value_length = wcslen( value );

    return length == value_length * sizeof(WCHAR) &&
           !wcsnicmp( buffer, value, value_length );
}

static SID *create_rpc_nt_sid( BYTE subauthority_count, const DWORD *subauthorities )
{
    static const SID_IDENTIFIER_AUTHORITY authority = { SECURITY_NT_AUTHORITY };
    SIZE_T size = offsetof( SID, SubAuthority ) + subauthority_count * sizeof(DWORD);
    SID *sid;

    if (!(sid = MIDL_user_allocate( size ))) return NULL;
    sid->Revision = SID_REVISION;
    sid->SubAuthorityCount = subauthority_count;
    sid->IdentifierAuthority = authority;
    if (subauthority_count)
        memcpy( sid->SubAuthority, subauthorities, subauthority_count * sizeof(DWORD) );
    return sid;
}

enum policy_lookup_domain
{
    POLICY_LOOKUP_DOMAIN_NONE,
    POLICY_LOOKUP_DOMAIN_NT_AUTHORITY,
    POLICY_LOOKUP_DOMAIN_NT_SERVICE
};

static SID *lookup_rpc_name( const LSA_POLICY_LOOKUP_UNICODE_STRING *name,
                             enum policy_lookup_domain *domain,
                             LSA_POLICY_LOOKUP_SID_NAME_USE *use )
{
    const WCHAR *separator = NULL, *account;
    USHORT domain_length, account_length;
    DWORD rid;
    ULONG i, size;
    UNICODE_STRING service_name;
    SID *sid;
    NTSTATUS status;

    *domain = POLICY_LOOKUP_DOMAIN_NONE;
    *use = LsaPolicyLookupSidTypeUnknown;
    for (i = 0; i < name->Length / sizeof(WCHAR); i++)
        if (name->Buffer[i] == '\\') separator = name->Buffer + i;
    if (!separator) return NULL;

    domain_length = (separator - name->Buffer) * sizeof(WCHAR);
    account = separator + 1;
    account_length = name->Length - domain_length - sizeof(WCHAR);
    if (rpc_string_equal( name->Buffer, domain_length, L"NT AUTHORITY" ))
    {
        if (rpc_string_equal( account, account_length, L"SYSTEM" ) ||
            rpc_string_equal( account, account_length, L"LOCALSYSTEM" ))
            rid = SECURITY_LOCAL_SYSTEM_RID;
        else if (rpc_string_equal( account, account_length, L"LOCAL SERVICE" ) ||
                 rpc_string_equal( account, account_length, L"LOCALSERVICE" ))
            rid = SECURITY_LOCAL_SERVICE_RID;
        else if (rpc_string_equal( account, account_length, L"NETWORK SERVICE" ) ||
                 rpc_string_equal( account, account_length, L"NETWORKSERVICE" ))
            rid = SECURITY_NETWORK_SERVICE_RID;
        else
            return NULL;

        *domain = POLICY_LOOKUP_DOMAIN_NT_AUTHORITY;
        *use = LsaPolicyLookupSidTypeWellKnownGroup;
        return create_rpc_nt_sid( 1, &rid );
    }
    if (!rpc_string_equal( name->Buffer, domain_length, L"NT SERVICE" ) || !account_length)
        return NULL;

    service_name.Buffer = (WCHAR *)account;
    service_name.Length = account_length;
    service_name.MaximumLength = account_length;
    size = SECURITY_MAX_SID_SIZE;
    if (!(sid = MIDL_user_allocate( size ))) return NULL;
    status = RtlCreateServiceSid( &service_name, sid, &size );
    if (status)
    {
        MIDL_user_free( sid );
        return NULL;
    }
    *domain = POLICY_LOOKUP_DOMAIN_NT_SERVICE;
    *use = LsaPolicyLookupSidTypeWellKnownGroup;
    return sid;
}

static BOOL add_rpc_domain( LSA_POLICY_LOOKUP_REFERENCED_DOMAIN_LIST *domains,
                            enum policy_lookup_domain domain, LONG *index )
{
    static const DWORD service_rid = SECURITY_SERVICE_ID_BASE_RID;
    const WCHAR *name;
    SID *sid;
    ULONG i;

    name = domain == POLICY_LOOKUP_DOMAIN_NT_AUTHORITY ? L"NT AUTHORITY" : L"NT SERVICE";
    for (i = 0; i < domains->Entries; i++)
    {
        if (rpc_string_equal( domains->Domains[i].Name.Buffer,
                              domains->Domains[i].Name.Length, name ))
        {
            *index = i;
            return TRUE;
        }
    }

    if (domain == POLICY_LOOKUP_DOMAIN_NT_AUTHORITY)
        sid = create_rpc_nt_sid( 0, NULL );
    else
        sid = create_rpc_nt_sid( 1, &service_rid );
    if (!sid) return FALSE;
    if (!copy_rpc_string( &domains->Domains[domains->Entries].Name, name,
                          wcslen( name ) * sizeof(WCHAR) ))
    {
        MIDL_user_free( sid );
        return FALSE;
    }
    domains->Domains[domains->Entries].Sid = sid;
    *index = domains->Entries++;
    return TRUE;
}

static void free_rpc_referenced_domains( LSA_POLICY_LOOKUP_REFERENCED_DOMAIN_LIST *domains )
{
    ULONG i;

    if (!domains) return;
    for (i = 0; i < domains->Entries; i++)
    {
        MIDL_user_free( domains->Domains[i].Name.Buffer );
        MIDL_user_free( domains->Domains[i].Sid );
    }
    MIDL_user_free( domains->Domains );
    MIDL_user_free( domains );
}

static void free_rpc_translated_names( LSA_POLICY_LOOKUP_TRANSLATED_NAMES_EX *translated_names )
{
    ULONG i;

    if (!translated_names || !translated_names->Names) return;
    for (i = 0; i < translated_names->Entries; i++)
        MIDL_user_free( translated_names->Names[i].Name.Buffer );
    MIDL_user_free( translated_names->Names );
    translated_names->Entries = 0;
    translated_names->Names = NULL;
}

static SID *copy_rpc_domain_sid( SID *sid, SID_NAME_USE use )
{
    BYTE count;
    SIZE_T size;
    SID *copy;

    if (!IsValidSid( sid )) return NULL;
    count = *GetSidSubAuthorityCount( sid );
    if (use != SidTypeDomain && count) count--;
    size = offsetof( SID, SubAuthority ) + count * sizeof(DWORD);
    if (!(copy = MIDL_user_allocate( size ))) return NULL;
    memcpy( copy, sid, size );
    copy->SubAuthorityCount = count;
    return copy;
}

static BOOL add_rpc_sid_domain( LSA_POLICY_LOOKUP_REFERENCED_DOMAIN_LIST *domains,
                                const WCHAR *name, SID *sid, SID_NAME_USE use, LONG *index )
{
    SID *domain_sid;
    ULONG i;

    if (!name[0])
    {
        *index = -1;
        return TRUE;
    }
    if (!(domain_sid = copy_rpc_domain_sid( sid, use ))) return FALSE;
    for (i = 0; i < domains->Entries; i++)
    {
        if (EqualSid( domains->Domains[i].Sid, domain_sid ))
        {
            MIDL_user_free( domain_sid );
            *index = i;
            return TRUE;
        }
    }
    if (!copy_rpc_string( &domains->Domains[domains->Entries].Name, name,
                          wcslen( name ) * sizeof(WCHAR) ))
    {
        MIDL_user_free( domain_sid );
        return FALSE;
    }
    domains->Domains[domains->Entries].Sid = domain_sid;
    *index = domains->Entries++;
    return TRUE;
}

NTSTATUS policy_lookup_translate_sids(
    LSA_POLICY_LOOKUP_HANDLE handle, LSA_POLICY_LOOKUP_SID_ENUM_BUFFER *sid_enum,
    LSA_POLICY_LOOKUP_REFERENCED_DOMAIN_LIST **referenced_domains,
    LSA_POLICY_LOOKUP_TRANSLATED_NAMES_EX *translated_names, ULONG *mapped_count,
    ULONG lookup_options, ULONG client_revision )
{
    struct policy_lookup_context *context = handle;
    LSA_POLICY_LOOKUP_REFERENCED_DOMAIN_LIST *rpc_domains = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG count, i, mapped = 0;

    TRACE( "handle %p, sids %p, domains %p, names %p, mapped %p, options %#lx, "
           "revision %lu, magic %#lx\n", handle, sid_enum, referenced_domains,
           translated_names, mapped_count, lookup_options, client_revision,
           context ? context->magic : 0 );

    if (!context || context->magic != POLICY_LOOKUP_CONTEXT_MAGIC) return STATUS_INVALID_HANDLE;
    if (!sid_enum || !referenced_domains || !translated_names || !mapped_count ||
        (sid_enum->Entries && !sid_enum->SidInfo))
        return STATUS_INVALID_PARAMETER;

    count = sid_enum->Entries;
    *referenced_domains = NULL;
    translated_names->Entries = 0;
    translated_names->Names = NULL;
    *mapped_count = 0;

    if (!(rpc_domains = MIDL_user_allocate( sizeof(*rpc_domains) )))
        return STATUS_NO_MEMORY;
    memset( rpc_domains, 0, sizeof(*rpc_domains) );
    rpc_domains->MaxEntries = count;
    if (count)
    {
        if (!(rpc_domains->Domains = MIDL_user_allocate( count * sizeof(*rpc_domains->Domains) )))
        {
            status = STATUS_NO_MEMORY;
            goto done;
        }
        memset( rpc_domains->Domains, 0, count * sizeof(*rpc_domains->Domains) );
        if (!(translated_names->Names = MIDL_user_allocate( count * sizeof(*translated_names->Names) )))
        {
            status = STATUS_NO_MEMORY;
            goto done;
        }
        memset( translated_names->Names, 0, count * sizeof(*translated_names->Names) );
    }
    translated_names->Entries = count;

    for (i = 0; i < count; i++)
    {
        LSA_POLICY_LOOKUP_TRANSLATED_NAME_EX *dst = &translated_names->Names[i];
        WCHAR account[UNLEN + 1], domain[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD account_size = ARRAY_SIZE(account), domain_size = ARRAY_SIZE(domain);
        SID_NAME_USE use;
        SID *sid = sid_enum->SidInfo[i].Sid;

        dst->Use = LsaPolicyLookupSidTypeUnknown;
        dst->DomainIndex = -1;
        if (!sid || !IsValidSid( sid ))
        {
            TRACE( "sid[%lu] invalid\n", i );
            continue;
        }
        TRACE( "sid[%lu] revision %u, subauthorities %u\n", i, sid->Revision,
               sid->SubAuthorityCount );
        if (!LookupAccountSidW( NULL, sid, account, &account_size, domain, &domain_size, &use ))
            continue;
        if (!copy_rpc_string( &dst->Name, account, account_size * sizeof(WCHAR) ) ||
            !add_rpc_sid_domain( rpc_domains, domain, sid, use, &dst->DomainIndex ))
        {
            status = STATUS_NO_MEMORY;
            goto done;
        }
        dst->Use = (LSA_POLICY_LOOKUP_SID_NAME_USE)use;
        mapped++;
    }

    *mapped_count = mapped;
    *referenced_domains = rpc_domains;
    rpc_domains = NULL;
    if (!mapped && count) status = STATUS_NONE_MAPPED;
    else if (mapped != count) status = STATUS_SOME_NOT_MAPPED;

done:
    if (status != STATUS_SUCCESS && status != STATUS_SOME_NOT_MAPPED &&
        status != STATUS_NONE_MAPPED)
        free_rpc_translated_names( translated_names );
    free_rpc_referenced_domains( rpc_domains );
    return status;
}

static void free_rpc_translated_sids( LSA_POLICY_LOOKUP_TRANSLATED_SIDS_EX2 *translated_sids )
{
    ULONG i;

    if (!translated_sids || !translated_sids->Sids) return;
    for (i = 0; i < translated_sids->Entries; i++)
        MIDL_user_free( translated_sids->Sids[i].Sid );
    MIDL_user_free( translated_sids->Sids );
    translated_sids->Entries = 0;
    translated_sids->Sids = NULL;
}

NTSTATUS policy_lookup_translate_names( LSA_POLICY_LOOKUP_HANDLE handle, ULONG count,
                                        LSA_POLICY_LOOKUP_UNICODE_STRING *names,
                                        LSA_POLICY_LOOKUP_REFERENCED_DOMAIN_LIST **referenced_domains,
                                        LSA_POLICY_LOOKUP_TRANSLATED_SIDS_EX2 *translated_sids,
                                        ULONG *mapped_count, ULONG lookup_options,
                                        ULONG client_revision )
{
    struct policy_lookup_context *context = handle;
    LSA_POLICY_LOOKUP_REFERENCED_DOMAIN_LIST *rpc_domains = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i, mapped = 0;

    TRACE( "handle %p, count %lu, names %p, domains %p, sids %p, mapped %p, "
           "options %#lx, revision %lu, magic %#lx\n", handle, count, names,
           referenced_domains, translated_sids, mapped_count, lookup_options, client_revision,
           context ? context->magic : 0 );

    if (!context || context->magic != POLICY_LOOKUP_CONTEXT_MAGIC) return STATUS_INVALID_HANDLE;
    if (!referenced_domains || !translated_sids || !mapped_count || (count && !names))
        return STATUS_INVALID_PARAMETER;
    for (i = 0; i < count; i++)
        TRACE( "name[%lu] %s\n", i,
               debugstr_wn( names[i].Buffer, names[i].Length / sizeof(WCHAR) ) );
    *referenced_domains = NULL;
    translated_sids->Entries = 0;
    translated_sids->Sids = NULL;
    *mapped_count = 0;

    if (!(rpc_domains = MIDL_user_allocate( sizeof(*rpc_domains) )))
    {
        status = STATUS_NO_MEMORY;
        goto done;
    }
    memset( rpc_domains, 0, sizeof(*rpc_domains) );
    rpc_domains->MaxEntries = count;
    if (count)
    {
        if (!(rpc_domains->Domains = MIDL_user_allocate( count *
                                                         sizeof(*rpc_domains->Domains) )))
        {
            status = STATUS_NO_MEMORY;
            goto done;
        }
        memset( rpc_domains->Domains, 0, count * sizeof(*rpc_domains->Domains) );
    }

    translated_sids->Entries = count;
    if (count)
    {
        if (!(translated_sids->Sids = MIDL_user_allocate( count *
                                                          sizeof(*translated_sids->Sids) )))
        {
            status = STATUS_NO_MEMORY;
            goto done;
        }
        memset( translated_sids->Sids, 0, count * sizeof(*translated_sids->Sids) );
        for (i = 0; i < count; i++)
        {
            LSA_POLICY_LOOKUP_TRANSLATED_SID_EX2 *dst = &translated_sids->Sids[i];
            enum policy_lookup_domain domain;

            dst->Use = LsaPolicyLookupSidTypeUnknown;
            dst->DomainIndex = -1;
            dst->Flags = 0;
            dst->Sid = lookup_rpc_name( &names[i], &domain, &dst->Use );
            if (!dst->Sid) continue;
            if (!add_rpc_domain( rpc_domains, domain, &dst->DomainIndex ))
            {
                MIDL_user_free( dst->Sid );
                dst->Sid = NULL;
                status = STATUS_NO_MEMORY;
                goto done;
            }
            mapped++;
        }
    }

    *mapped_count = mapped;
    *referenced_domains = rpc_domains;
    rpc_domains = NULL;
    if (!mapped && count) status = STATUS_NONE_MAPPED;
    else if (mapped != count) status = STATUS_SOME_NOT_MAPPED;

done:
    if (status != STATUS_SUCCESS && status != STATUS_SOME_NOT_MAPPED &&
        status != STATUS_NONE_MAPPED)
        free_rpc_translated_sids( translated_sids );
    free_rpc_referenced_domains( rpc_domains );
    return status;
}

NTSTATUS policy_lookup_manage_cache( LSA_POLICY_LOOKUP_SERVER_NAME server_name,
                                     LSA_SID_NAME_MAPPING_OPERATION_TYPE operation_type,
                                     LSA_SID_NAME_MAPPING_OPERATION_INPUT *operation_input,
                                     LSA_SID_NAME_MAPPING_OPERATION_OUTPUT **operation_output )
{
    LSA_SID_NAME_MAPPING_OPERATION_OUTPUT *output;

    TRACE( "server %s, operation %u, input %p, output %p\n",
           debugstr_w(server_name), operation_type, operation_input, operation_output );

    if (!operation_input || !operation_output) return STATUS_INVALID_PARAMETER;
    *operation_output = NULL;
    if (operation_type < LsaSidNameMappingOperation_Add ||
        operation_type > LsaSidNameMappingOperation_AddMultiple)
        return STATUS_INVALID_PARAMETER;

    if (!(output = MIDL_user_allocate( sizeof(*output) ))) return STATUS_NO_MEMORY;
    output->AddOutput.ErrorCode = LsaSidNameMappingOperation_Success;
    *operation_output = output;
    return STATUS_SUCCESS;
}

static BOOL copy_rpc_string( LSA_POLICY_LOOKUP_UNICODE_STRING *dst, const WCHAR *src, USHORT length )
{
    dst->Length = length;
    dst->MaximumLength = length + sizeof(WCHAR);
    if (!(dst->Buffer = MIDL_user_allocate( dst->MaximumLength ))) return FALSE;
    if (length) memcpy( dst->Buffer, src, length );
    dst->Buffer[length / sizeof(WCHAR)] = 0;
    return TRUE;
}

static SID *create_rpc_computer_sid(void)
{
    static const SID_IDENTIFIER_AUTHORITY authority = { SECURITY_NT_AUTHORITY };
    const DWORD size = offsetof( SID, SubAuthority[4] );
    SID *dst;

    if (!(dst = MIDL_user_allocate( size ))) return NULL;
    dst->Revision = SID_REVISION;
    dst->SubAuthorityCount = 4;
    dst->IdentifierAuthority = authority;
    dst->SubAuthority[0] = SECURITY_NT_NON_UNIQUE;
    dst->SubAuthority[1] = 0;
    dst->SubAuthority[2] = 0;
    dst->SubAuthority[3] = 0;
    return dst;
}

static void free_rpc_domain_info( LSA_POLICY_LOOKUP_DOMAIN_INFO *info,
                                  LSA_POLICY_LOOKUP_DOMAIN_INFO_CLASS info_class )
{
    if (!info) return;
    if (info_class == LsaPolicyLookupAccountDomainInformation)
    {
        MIDL_user_free( info->AccountDomainInformation.DomainName.Buffer );
        MIDL_user_free( info->AccountDomainInformation.DomainSid );
    }
    else
    {
        MIDL_user_free( info->DnsDomainInformation.Name.Buffer );
        MIDL_user_free( info->DnsDomainInformation.DnsDomainName.Buffer );
        MIDL_user_free( info->DnsDomainInformation.DnsForestName.Buffer );
        MIDL_user_free( info->DnsDomainInformation.Sid );
    }
    MIDL_user_free( info );
}

NTSTATUS policy_lookup_get_domain_info( LSA_POLICY_LOOKUP_HANDLE handle,
                                        LSA_POLICY_LOOKUP_DOMAIN_INFO_CLASS info_class,
                                        LSA_POLICY_LOOKUP_DOMAIN_INFO **domain_info )
{
    struct policy_lookup_context *context = handle;
    LSA_POLICY_LOOKUP_DOMAIN_INFO *rpc_info;
    WCHAR computer_name[MAX_COMPUTERNAME_LENGTH + 1] = L"LINUXNT";
    DWORD computer_name_len = ARRAY_SIZE(computer_name);
    NTSTATUS status = STATUS_SUCCESS;

    TRACE( "handle %p, info class %u, domain info %p\n", handle, info_class, domain_info );

    if (!context || context->magic != POLICY_LOOKUP_CONTEXT_MAGIC) return STATUS_INVALID_HANDLE;
    if (!domain_info) return STATUS_INVALID_PARAMETER;
    *domain_info = NULL;

    if (info_class != LsaPolicyLookupAccountDomainInformation &&
        info_class != LsaPolicyLookupDnsDomainInformation)
        return STATUS_INVALID_INFO_CLASS;

    if (!(rpc_info = calloc( 1, sizeof(*rpc_info) )))
        return STATUS_NO_MEMORY;

    if (info_class == LsaPolicyLookupAccountDomainInformation)
    {
        LSA_POLICY_LOOKUP_ACCOUNT_DOMAIN_INFO *rpc = &rpc_info->AccountDomainInformation;

        if (!GetComputerNameW( computer_name, &computer_name_len ))
            computer_name_len = lstrlenW( computer_name );
        if (!copy_rpc_string( &rpc->DomainName, computer_name,
                              computer_name_len * sizeof(WCHAR) ) ||
            !(rpc->DomainSid = create_rpc_computer_sid()))
            status = STATUS_NO_MEMORY;
    }
    else
    {
        LSA_POLICY_LOOKUP_DNS_DOMAIN_INFO *rpc = &rpc_info->DnsDomainInformation;

        if (!GetComputerNameW( computer_name, &computer_name_len ))
            computer_name_len = lstrlenW( computer_name );
        if (!copy_rpc_string( &rpc->Name, computer_name,
                              computer_name_len * sizeof(WCHAR) ) ||
            !copy_rpc_string( &rpc->DnsDomainName, L"", 0 ) ||
            !copy_rpc_string( &rpc->DnsForestName, L"", 0 ) ||
            !(rpc->Sid = create_rpc_computer_sid()))
            status = STATUS_NO_MEMORY;
    }

    if (!status) *domain_info = rpc_info;
    else free_rpc_domain_info( rpc_info, info_class );
    return status;
}

NTSTATUS policy_lookup_user_account_type( LSA_POLICY_LOOKUP_SERVER_NAME server_name, SID *sid,
                                          LSA_POLICY_LOOKUP_USER_ACCOUNT_TYPE *account_type )
{
    static const SID_IDENTIFIER_AUTHORITY nt_authority = { SECURITY_NT_AUTHORITY };
    static const SID_IDENTIFIER_AUTHORITY internet_authority = {{0, 0, 0, 0, 0, 11}};
    static const SID_IDENTIFIER_AUTHORITY microsoft_account_authority = {{0, 0, 0, 0, 0, 12}};

    TRACE( "server %s, sid %p, account_type %p\n", debugstr_w(server_name), sid, account_type );

    if (!sid || !account_type) return STATUS_INVALID_PARAMETER;
    if (!IsValidSid( sid )) return STATUS_INVALID_SID;

    *account_type = LsaPolicyLookupUnknownUserAccountType;
    if (!memcmp( GetSidIdentifierAuthority(sid), &nt_authority, sizeof(nt_authority) ) &&
        *GetSidSubAuthorityCount(sid) >= 4 &&
        *GetSidSubAuthority( sid, 0 ) == SECURITY_NT_NON_UNIQUE)
        *account_type = LsaPolicyLookupLocalUserAccountType;
    else if (!memcmp( GetSidIdentifierAuthority(sid), &microsoft_account_authority,
                       sizeof(microsoft_account_authority) ) &&
             *GetSidSubAuthorityCount(sid) && *GetSidSubAuthority( sid, 0 ) == 1)
        *account_type = LsaPolicyLookupAadUserAccountType;
    else if (!memcmp( GetSidIdentifierAuthority(sid), &internet_authority,
                       sizeof(internet_authority) ))
        *account_type = LsaPolicyLookupInternetUserAccountType;

    return STATUS_SUCCESS;
}
