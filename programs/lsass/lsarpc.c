/*
 * Local Security Authority policy RPC entry point
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
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "lsarpc.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(secur32);

#define LSARPC_CONTEXT_MAGIC 0x4c534150

struct lsarpc_context
{
    DWORD magic;
    ACCESS_MASK access;
};

static NTSTATUS create_policy_context( ACCESS_MASK access, LSARPC_HANDLE *handle )
{
    struct lsarpc_context *context;

    if (!access || !handle) return STATUS_INVALID_PARAMETER;
    if (!(context = malloc( sizeof(*context) ))) return STATUS_NO_MEMORY;

    context->magic = LSARPC_CONTEXT_MAGIC;
    context->access = access;
    *handle = context;
    return STATUS_SUCCESS;
}

void __RPC_USER LSARPC_HANDLE_rundown( LSARPC_HANDLE handle )
{
    struct lsarpc_context *context = handle;

    if (!context) return;
    context->magic = 0;
    free( context );
}

NTSTATUS lsarpc_close( LSARPC_HANDLE *handle )
{
    struct lsarpc_context *context;

    if (!handle || !(context = *handle) || context->magic != LSARPC_CONTEXT_MAGIC)
        return STATUS_INVALID_HANDLE;

    context->magic = 0;
    free( context );
    *handle = NULL;
    return STATUS_SUCCESS;
}

#define DEFINE_UNUSED_OPNUM(n) \
    NTSTATUS lsarpc_unused_##n(void) { return STATUS_NOT_IMPLEMENTED; }

DEFINE_UNUSED_OPNUM(1)
DEFINE_UNUSED_OPNUM(2)
DEFINE_UNUSED_OPNUM(3)
DEFINE_UNUSED_OPNUM(4)
DEFINE_UNUSED_OPNUM(5)
DEFINE_UNUSED_OPNUM(6)
DEFINE_UNUSED_OPNUM(7)
DEFINE_UNUSED_OPNUM(8)
DEFINE_UNUSED_OPNUM(9)
DEFINE_UNUSED_OPNUM(10)
DEFINE_UNUSED_OPNUM(11)
DEFINE_UNUSED_OPNUM(12)
DEFINE_UNUSED_OPNUM(13)
DEFINE_UNUSED_OPNUM(14)
DEFINE_UNUSED_OPNUM(15)
DEFINE_UNUSED_OPNUM(16)
DEFINE_UNUSED_OPNUM(17)
DEFINE_UNUSED_OPNUM(18)
DEFINE_UNUSED_OPNUM(19)
DEFINE_UNUSED_OPNUM(20)
DEFINE_UNUSED_OPNUM(21)
DEFINE_UNUSED_OPNUM(22)
DEFINE_UNUSED_OPNUM(23)
DEFINE_UNUSED_OPNUM(24)
DEFINE_UNUSED_OPNUM(25)
DEFINE_UNUSED_OPNUM(26)
DEFINE_UNUSED_OPNUM(27)
DEFINE_UNUSED_OPNUM(28)
DEFINE_UNUSED_OPNUM(29)
DEFINE_UNUSED_OPNUM(30)
DEFINE_UNUSED_OPNUM(31)
DEFINE_UNUSED_OPNUM(32)
DEFINE_UNUSED_OPNUM(33)
DEFINE_UNUSED_OPNUM(34)
DEFINE_UNUSED_OPNUM(35)
DEFINE_UNUSED_OPNUM(36)
DEFINE_UNUSED_OPNUM(37)
DEFINE_UNUSED_OPNUM(38)
DEFINE_UNUSED_OPNUM(39)
DEFINE_UNUSED_OPNUM(40)
DEFINE_UNUSED_OPNUM(41)
DEFINE_UNUSED_OPNUM(42)
DEFINE_UNUSED_OPNUM(43)

NTSTATUS lsarpc_open_policy2( WCHAR *server_name, LSARPC_OBJECT_ATTRIBUTES *attributes,
                              ULONG access, LSARPC_HANDLE *handle )
{
    TRACE( "server %s, attributes %p, access %#lx, handle %p\n",
           debugstr_w(server_name), attributes, access, handle );

    if (!attributes || attributes->RootDirectory) return STATUS_INVALID_PARAMETER;
    return create_policy_context( access, handle );
}

NTSTATUS lsarpc_get_user_name( WCHAR *server_name, LSARPC_UNICODE_STRING **user_name,
                               LSARPC_UNICODE_STRING **domain_name )
{
    TRACE( "server %s, user name %p, domain name %p\n",
           debugstr_w(server_name), user_name, domain_name );
    return STATUS_NOT_IMPLEMENTED;
}

static BOOL copy_rpc_unicode_string( LSARPC_UNICODE_STRING *dst, const WCHAR *src,
                                     USHORT length )
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
    SID *sid;

    if (!(sid = MIDL_user_allocate( size ))) return NULL;
    sid->Revision = SID_REVISION;
    sid->SubAuthorityCount = 4;
    sid->IdentifierAuthority = authority;
    sid->SubAuthority[0] = SECURITY_NT_NON_UNIQUE;
    sid->SubAuthority[1] = 0;
    sid->SubAuthority[2] = 0;
    sid->SubAuthority[3] = 0;
    return sid;
}

static void free_policy_information( LSARPC_POLICY_INFORMATION *info,
                                     LSARPC_POLICY_INFORMATION_CLASS info_class )
{
    if (!info) return;
    if (info_class == LsarpcPolicyAccountDomainInformation ||
        info_class == LsarpcPolicyLocalAccountDomainInformation)
    {
        LSARPC_POLICY_ACCOUNT_DOMAIN_INFO *domain =
            info_class == LsarpcPolicyAccountDomainInformation ?
            &info->AccountDomainInformation : &info->LocalAccountDomainInformation;

        MIDL_user_free( domain->DomainName.Buffer );
        MIDL_user_free( domain->DomainSid );
    }
    else
    {
        LSARPC_POLICY_DNS_DOMAIN_INFO *domain =
            info_class == LsarpcPolicyDnsDomainInformation ?
            &info->DnsDomainInformation : &info->DnsDomainInformationInt;

        MIDL_user_free( domain->Name.Buffer );
        MIDL_user_free( domain->DnsDomainName.Buffer );
        MIDL_user_free( domain->DnsForestName.Buffer );
        MIDL_user_free( domain->Sid );
    }
    MIDL_user_free( info );
}

NTSTATUS lsarpc_query_information_policy2( LSARPC_HANDLE handle,
                                           LSARPC_POLICY_INFORMATION_CLASS info_class,
                                           LSARPC_POLICY_INFORMATION **info )
{
    struct lsarpc_context *context = handle;
    LSARPC_POLICY_INFORMATION *rpc_info;
    WCHAR computer_name[MAX_COMPUTERNAME_LENGTH + 1] = L"LINUXNT";
    DWORD computer_name_len = ARRAY_SIZE(computer_name);
    NTSTATUS status = STATUS_SUCCESS;

    TRACE( "handle %p, info class %u, info %p\n", handle, info_class, info );

    if (!context || context->magic != LSARPC_CONTEXT_MAGIC) return STATUS_INVALID_HANDLE;
    if (!info) return STATUS_INVALID_PARAMETER;
    *info = NULL;

    if (info_class != LsarpcPolicyAccountDomainInformation &&
        info_class != LsarpcPolicyDnsDomainInformation &&
        info_class != LsarpcPolicyDnsDomainInformationInt &&
        info_class != LsarpcPolicyLocalAccountDomainInformation)
        return STATUS_INVALID_INFO_CLASS;
    if (!(rpc_info = calloc( 1, sizeof(*rpc_info) ))) return STATUS_NO_MEMORY;

    if (!GetComputerNameW( computer_name, &computer_name_len ))
        computer_name_len = lstrlenW( computer_name );
    if (info_class == LsarpcPolicyAccountDomainInformation ||
        info_class == LsarpcPolicyLocalAccountDomainInformation)
    {
        LSARPC_POLICY_ACCOUNT_DOMAIN_INFO *domain =
            info_class == LsarpcPolicyAccountDomainInformation ?
            &rpc_info->AccountDomainInformation : &rpc_info->LocalAccountDomainInformation;

        if (!copy_rpc_unicode_string( &domain->DomainName, computer_name,
                                      computer_name_len * sizeof(WCHAR) ) ||
            !(domain->DomainSid = create_rpc_computer_sid()))
            status = STATUS_NO_MEMORY;
    }
    else
    {
        LSARPC_POLICY_DNS_DOMAIN_INFO *domain =
            info_class == LsarpcPolicyDnsDomainInformation ?
            &rpc_info->DnsDomainInformation : &rpc_info->DnsDomainInformationInt;

        if (!copy_rpc_unicode_string( &domain->Name, computer_name,
                                      computer_name_len * sizeof(WCHAR) ) ||
            !copy_rpc_unicode_string( &domain->DnsDomainName, L"", 0 ) ||
            !copy_rpc_unicode_string( &domain->DnsForestName, L"", 0 ) ||
            !(domain->Sid = create_rpc_computer_sid()))
            status = STATUS_NO_MEMORY;
    }

    if (!status) *info = rpc_info;
    else free_policy_information( rpc_info, info_class );
    return status;
}

DEFINE_UNUSED_OPNUM(47)
DEFINE_UNUSED_OPNUM(48)
DEFINE_UNUSED_OPNUM(49)
DEFINE_UNUSED_OPNUM(50)
DEFINE_UNUSED_OPNUM(51)
DEFINE_UNUSED_OPNUM(52)
DEFINE_UNUSED_OPNUM(53)
DEFINE_UNUSED_OPNUM(54)
DEFINE_UNUSED_OPNUM(55)
DEFINE_UNUSED_OPNUM(56)
DEFINE_UNUSED_OPNUM(57)
DEFINE_UNUSED_OPNUM(58)
DEFINE_UNUSED_OPNUM(59)
DEFINE_UNUSED_OPNUM(60)
DEFINE_UNUSED_OPNUM(61)
DEFINE_UNUSED_OPNUM(62)
DEFINE_UNUSED_OPNUM(63)
DEFINE_UNUSED_OPNUM(64)
DEFINE_UNUSED_OPNUM(65)
DEFINE_UNUSED_OPNUM(66)
DEFINE_UNUSED_OPNUM(67)
DEFINE_UNUSED_OPNUM(68)
DEFINE_UNUSED_OPNUM(69)
DEFINE_UNUSED_OPNUM(70)
DEFINE_UNUSED_OPNUM(71)
DEFINE_UNUSED_OPNUM(72)
DEFINE_UNUSED_OPNUM(73)
DEFINE_UNUSED_OPNUM(74)
DEFINE_UNUSED_OPNUM(75)
DEFINE_UNUSED_OPNUM(76)
DEFINE_UNUSED_OPNUM(77)
DEFINE_UNUSED_OPNUM(78)
DEFINE_UNUSED_OPNUM(79)
DEFINE_UNUSED_OPNUM(80)
DEFINE_UNUSED_OPNUM(81)
DEFINE_UNUSED_OPNUM(82)
DEFINE_UNUSED_OPNUM(83)
DEFINE_UNUSED_OPNUM(84)
DEFINE_UNUSED_OPNUM(85)
DEFINE_UNUSED_OPNUM(86)
DEFINE_UNUSED_OPNUM(87)
DEFINE_UNUSED_OPNUM(88)
DEFINE_UNUSED_OPNUM(89)
DEFINE_UNUSED_OPNUM(90)
DEFINE_UNUSED_OPNUM(91)
DEFINE_UNUSED_OPNUM(92)
DEFINE_UNUSED_OPNUM(93)
DEFINE_UNUSED_OPNUM(94)
DEFINE_UNUSED_OPNUM(95)
DEFINE_UNUSED_OPNUM(96)
DEFINE_UNUSED_OPNUM(97)
DEFINE_UNUSED_OPNUM(98)
DEFINE_UNUSED_OPNUM(99)
DEFINE_UNUSED_OPNUM(100)
DEFINE_UNUSED_OPNUM(101)
DEFINE_UNUSED_OPNUM(102)
DEFINE_UNUSED_OPNUM(103)
DEFINE_UNUSED_OPNUM(104)
DEFINE_UNUSED_OPNUM(105)
DEFINE_UNUSED_OPNUM(106)
DEFINE_UNUSED_OPNUM(107)
DEFINE_UNUSED_OPNUM(108)
DEFINE_UNUSED_OPNUM(109)
DEFINE_UNUSED_OPNUM(110)
DEFINE_UNUSED_OPNUM(111)
DEFINE_UNUSED_OPNUM(112)
DEFINE_UNUSED_OPNUM(113)
DEFINE_UNUSED_OPNUM(114)
DEFINE_UNUSED_OPNUM(115)
DEFINE_UNUSED_OPNUM(116)
DEFINE_UNUSED_OPNUM(117)
DEFINE_UNUSED_OPNUM(118)
DEFINE_UNUSED_OPNUM(119)
DEFINE_UNUSED_OPNUM(120)
DEFINE_UNUSED_OPNUM(121)
DEFINE_UNUSED_OPNUM(122)
DEFINE_UNUSED_OPNUM(123)
DEFINE_UNUSED_OPNUM(124)
DEFINE_UNUSED_OPNUM(125)
DEFINE_UNUSED_OPNUM(126)
DEFINE_UNUSED_OPNUM(127)
DEFINE_UNUSED_OPNUM(128)
DEFINE_UNUSED_OPNUM(129)

NTSTATUS lsarpc_open_policy3( WCHAR *server_name, LSARPC_OBJECT_ATTRIBUTES *attributes,
                              ULONG access, ULONG in_version,
                              LSARPC_REVISION_INFO *in_revision_info, ULONG *out_version,
                              LSARPC_REVISION_INFO *out_revision_info, LSARPC_HANDLE *handle )
{
    TRACE( "server %s, attributes %p, access %#lx, version %lu, revision %p, "
           "out version %p, out revision %p, handle %p\n", debugstr_w(server_name),
           attributes, access, in_version, in_revision_info, out_version,
           out_revision_info, handle );

    if (!attributes || attributes->RootDirectory || in_version != 1 ||
        !in_revision_info || !out_version || !out_revision_info)
        return STATUS_INVALID_PARAMETER;

    *out_version = 1;
    out_revision_info->V1.Revision = 1;
    out_revision_info->V1.SupportedFeatures = 0;
    return create_policy_context( access, handle );
}
