/*
 * Security Account Manager RPC tests
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
#include "lmaccess.h"
#include "winternl.h"
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "rpc.h"
#include "rpcdce.h"
#include "samr_test.h"

#include "wine/test.h"

#define SAMR_SERVER_CONNECT 0x00000001
#define SAMR_SERVER_ENUMERATE_DOMAINS 0x00000010
#define SAMR_SERVER_LOOKUP_DOMAIN 0x00000020
#define SAMR_DOMAIN_LIST_ACCOUNTS 0x00000100
#define SAMR_DOMAIN_OPEN_ACCOUNT 0x00000200
#define SAMR_USER_READ_GENERAL 0x00000001
#define SAMR_USER_READ_PREFERENCES 0x00000002
#define SAMR_USER_READ_LOGON 0x00000008
#define SAMR_USER_READ_ACCOUNT 0x00000010
#define SAMR_USER_LIST_GROUPS 0x00000100
#define SAMR_USER_READ_GROUP_INFORMATION 0x00000200
#define SAMR_LOCAL_USER_RID 1000
#define SAMR_SHACCT_USER_ACCESS (STANDARD_RIGHTS_READ | SAMR_USER_READ_GENERAL | \
                                 SAMR_USER_READ_PREFERENCES | SAMR_USER_READ_LOGON | \
                                 SAMR_USER_READ_ACCOUNT | SAMR_USER_LIST_GROUPS | \
                                 SAMR_USER_READ_GROUP_INFORMATION)

void *__RPC_USER MIDL_user_allocate( SIZE_T size )
{
    return malloc( size );
}

void __RPC_USER MIDL_user_free( void *ptr )
{
    free( ptr );
}

static BOOL create_sid( SID *sid, BYTE count, DWORD first, DWORD second,
                        DWORD third, DWORD fourth )
{
    static const SID_IDENTIFIER_AUTHORITY authority = {SECURITY_NT_AUTHORITY};

    sid->Revision = SID_REVISION;
    sid->SubAuthorityCount = count;
    sid->IdentifierAuthority = authority;
    sid->SubAuthority[0] = first;
    if (count > 1) sid->SubAuthority[1] = second;
    if (count > 2) sid->SubAuthority[2] = third;
    if (count > 3) sid->SubAuthority[3] = fourth;
    return TRUE;
}

static void free_enumeration_buffer( SAMR_ENUMERATION_BUFFER *buffer )
{
    ULONG i;

    if (!buffer) return;
    if (buffer->Buffer)
    {
        for (i = 0; i < buffer->EntriesRead; ++i)
            MIDL_user_free( buffer->Buffer[i].Name.Buffer );
        MIDL_user_free( buffer->Buffer );
    }
    MIDL_user_free( buffer );
}

static void free_ulong_array( SAMR_ULONG_ARRAY *array )
{
    MIDL_user_free( array->Element );
    array->Element = NULL;
    array->Count = 0;
}

static void free_returned_names( SAMR_RETURNED_USTRING_ARRAY *names )
{
    ULONG i;

    for (i = 0; i < names->Count; ++i) MIDL_user_free( names->Element[i].Buffer );
    MIDL_user_free( names->Element );
    names->Element = NULL;
    names->Count = 0;
}

static BOOL wait_for_server(void)
{
    STARTUPINFOW startup = {sizeof(startup)};
    PROCESS_INFORMATION process = {0};
    WCHAR command[] = L"lsass.exe";
    RPC_STATUS rpc_status;
    unsigned int attempt;

    if (!CreateProcessW( NULL, command, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                         NULL, NULL, &startup, &process ))
    {
        win_skip( "lsass.exe is unavailable, error %lu\n", GetLastError() );
        return FALSE;
    }
    CloseHandle( process.hThread );

    for (attempt = 0; attempt < 300; ++attempt)
    {
        rpc_status = RpcMgmtIsServerListening( samr_binding );
        if (rpc_status == RPC_S_OK) break;
        if (WaitForSingleObject( process.hProcess, 10 ) == WAIT_OBJECT_0) break;
    }
    if (rpc_status != RPC_S_OK)
        ok( 0, "SAMR server did not become ready, status %ld\n", rpc_status );
    CloseHandle( process.hProcess );
    return rpc_status == RPC_S_OK;
}

static void free_user_info( SAMR_USER_INFO_BUFFER *info,
                            SAMR_USER_INFORMATION_CLASS info_class )
{
    if (!info) return;
    if (info_class == SamrUserAllInformation)
    {
        MIDL_user_free( info->All.UserName.Buffer );
        MIDL_user_free( info->All.LogonHours.LogonHours );
    }
    MIDL_user_free( info );
}

static void test_user_information( SAMR_HANDLE domain, const WCHAR *user_name )
{
    SAMR_USER_INFO_BUFFER *info;
    SAMR_HANDLE user = NULL, maximum_user = NULL, empty_user = NULL;
    NTSTATUS status;
    ULONG i;

    info = NULL;
    status = samr_query_information_user( domain, SamrUserAllInformation, &info );
    ok( status == STATUS_INVALID_HANDLE, "domain query returned %#lx\n", status );
    ok( !info, "domain query returned buffer %p\n", info );

    status = samr_open_user( domain, SAMR_SHACCT_USER_ACCESS, 999, &user );
    ok( status == STATUS_NO_SUCH_USER, "unknown RID returned %#lx\n", status );
    ok( !user, "unknown RID returned handle %p\n", user );

    status = samr_open_user( domain, 0x04000000, SAMR_LOCAL_USER_RID, &user );
    ok( status == STATUS_ACCESS_DENIED, "unsupported access returned %#lx\n", status );
    ok( !user, "unsupported access returned handle %p\n", user );

    status = samr_open_user( domain, SAMR_SHACCT_USER_ACCESS,
                             SAMR_LOCAL_USER_RID, &user );
    ok( status == STATUS_SUCCESS && user, "user open returned %#lx, %p\n", status, user );

    info = NULL;
    status = samr_query_information_user( user, SamrUserAllInformation, &info );
    ok( status == STATUS_SUCCESS && info, "all-information query returned %#lx, %p\n",
        status, info );
    if (info)
    {
        ok( info->All.WhichFields == 0x00ffffff,
            "all-information fields are %#lx\n", info->All.WhichFields );
        ok( info->All.UserId == SAMR_LOCAL_USER_RID, "user RID is %lu\n",
            info->All.UserId );
        ok( info->All.PrimaryGroupId == DOMAIN_GROUP_RID_USERS,
            "primary group is %lu\n", info->All.PrimaryGroupId );
        ok( info->All.UserAccountControl == (UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD),
            "account control is %#lx\n", info->All.UserAccountControl );
        ok( info->All.UserName.Buffer && !wcsicmp( info->All.UserName.Buffer, user_name ),
            "user name is %s\n", wine_dbgstr_w(info->All.UserName.Buffer) );
        ok( info->All.LogonHours.UnitsPerWeek == 168,
            "logon-hours units are %u\n", info->All.LogonHours.UnitsPerWeek );
        ok( info->All.LogonHours.LogonHours != NULL, "logon-hours data is null\n" );
        if (info->All.LogonHours.LogonHours)
            for (i = 0; i < 21; ++i)
                ok( info->All.LogonHours.LogonHours[i] == 0xff,
                    "logon-hours byte %lu is %#x\n", i,
                    info->All.LogonHours.LogonHours[i] );
        ok( info->All.AccountExpires.LowPart == ~0u &&
            info->All.AccountExpires.HighPart == 0x7fffffff,
            "account expiry is %#lx:%#lx\n", info->All.AccountExpires.HighPart,
            info->All.AccountExpires.LowPart );
        ok( !info->All.PrivateData.Buffer && !info->All.SecurityDescriptor.SecurityDescriptor,
            "private data or security descriptor was exposed\n" );
    }
    free_user_info( info, SamrUserAllInformation );

    info = NULL;
    status = samr_query_information_user( user, SamrUserExtendedInformation, &info );
    ok( status == STATUS_SUCCESS && info, "extended query returned %#lx, %p\n", status, info );
    if (info)
    {
        ok( !info->Extended.ExtendedWhichFields, "extended fields are %#lx\n",
            info->Extended.ExtendedWhichFields );
        ok( !info->Extended.UserTile.Data && !info->Extended.PasswordHint.Buffer &&
            !info->Extended.ShellAdminObjectProperties.Data &&
            !info->Extended.ReservedString1.Buffer && !info->Extended.ReservedString2.Buffer &&
            !info->Extended.ReservedString3.Buffer && !info->Extended.ReservedBlob1.Data &&
            !info->Extended.ReservedBlob2.Data,
            "empty extended information returned nested data\n" );
    }
    free_user_info( info, SamrUserExtendedInformation );

    info = NULL;
    status = samr_query_information_user( user, SamrUserLogonUIInformation, &info );
    ok( status == STATUS_SUCCESS && info, "LogonUI query returned %#lx, %p\n", status, info );
    if (info)
    {
        ok( info->LogonUI.PasswordIsBlank, "password was reported nonblank\n" );
        ok( !info->LogonUI.AccountIsDisabled, "account was reported disabled\n" );
    }
    free_user_info( info, SamrUserLogonUIInformation );

    info = NULL;
    status = samr_query_information_user( user, SamrUserAuthInformation, &info );
    ok( status == STATUS_ACCESS_DENIED, "auth query without force access returned %#lx\n", status );
    ok( !info, "denied auth query returned buffer %p\n", info );

    status = samr_open_user( domain, MAXIMUM_ALLOWED, SAMR_LOCAL_USER_RID, &maximum_user );
    ok( status == STATUS_SUCCESS && maximum_user,
        "maximum-access user open returned %#lx, %p\n", status, maximum_user );
    info = NULL;
    status = samr_query_information_user( maximum_user, SamrUserAuthInformation, &info );
    ok( status == STATUS_NOT_SUPPORTED, "auth query returned %#lx\n", status );
    ok( !info, "unsupported auth query returned buffer %p\n", info );

    status = samr_open_user( domain, 0, SAMR_LOCAL_USER_RID, &empty_user );
    ok( status == STATUS_SUCCESS && empty_user,
        "zero-access user open returned %#lx, %p\n", status, empty_user );
    info = NULL;
    status = samr_query_information_user( empty_user, SamrUserAllInformation, &info );
    ok( status == STATUS_SUCCESS && info, "zero-access query returned %#lx, %p\n", status, info );
    if (info) ok( !info->All.WhichFields, "zero-access fields are %#lx\n", info->All.WhichFields );
    free_user_info( info, SamrUserAllInformation );

    status = samr_close_handle( &empty_user );
    ok( status == STATUS_SUCCESS && !empty_user, "zero-access close returned %#lx, %p\n",
        status, empty_user );
    status = samr_close_handle( &maximum_user );
    ok( status == STATUS_SUCCESS && !maximum_user, "maximum close returned %#lx, %p\n",
        status, maximum_user );
    status = samr_close_handle( &user );
    ok( status == STATUS_SUCCESS && !user, "user close returned %#lx, %p\n", status, user );
}

static void test_account_enumeration(void)
{
    struct
    {
        SID sid;
        DWORD extra[3];
    } account_sid, unknown_sid;
    SID builtin_sid;
    SAMR_IN_REVISION_INFO in_revision = {{3, 0}};
    SAMR_OUT_REVISION_INFO out_revision = {{0}};
    SAMR_ENUMERATION_BUFFER *buffer;
    SAMR_HANDLE server = NULL, domain = NULL;
    WCHAR user_name[UNLEN + 1];
    DWORD user_name_chars = ARRAY_SIZE(user_name);
    ULONG out_version, enumeration_context, count;
    NTSTATUS status;

    create_sid( &account_sid.sid, 4, SECURITY_NT_NON_UNIQUE, 0, 0, 0 );
    create_sid( &unknown_sid.sid, 4, SECURITY_NT_NON_UNIQUE, 1, 2, 3 );
    create_sid( &builtin_sid, 1, SECURITY_BUILTIN_DOMAIN_RID, 0, 0, 0 );

    out_version = 0;
    status = samr_connect5( NULL, READ_CONTROL | SAMR_SERVER_CONNECT |
                            SAMR_SERVER_ENUMERATE_DOMAINS |
                            SAMR_SERVER_LOOKUP_DOMAIN, 1, &in_revision,
                            &out_version, &out_revision, &server );
    ok( status == STATUS_SUCCESS, "samr_connect5 returned %#lx\n", status );
    ok( server != NULL, "samr_connect5 returned a null handle\n" );
    ok( out_version == 1, "out version is %lu\n", out_version );
    ok( out_revision.V1.Revision == 3, "revision is %lu\n", out_revision.V1.Revision );
    ok( out_revision.V1.SupportedFeatures == 0, "features are %#lx\n",
        out_revision.V1.SupportedFeatures );

    enumeration_context = count = 0;
    buffer = NULL;
    status = samr_enumerate_domains_in_server( server, &enumeration_context, &buffer,
                                               ~0u, &count );
    ok( status == STATUS_SUCCESS, "domain enumeration returned %#lx\n", status );
    ok( enumeration_context == 2 && count == 2 && buffer && buffer->EntriesRead == 2,
        "domain enumeration returned context %lu, count %lu, buffer %p\n",
        enumeration_context, count, buffer );
    if (buffer && buffer->EntriesRead == 2)
    {
        WCHAR computer[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD computer_len = ARRAY_SIZE(computer);
        SID *domain_sid = NULL;

        ok( !wcsicmp(buffer->Buffer[0].Name.Buffer, L"BUILTIN"), "first domain is %s\n",
            wine_dbgstr_w(buffer->Buffer[0].Name.Buffer) );
        ok( GetComputerNameW( computer, &computer_len ), "GetComputerNameW failed: %lu\n",
            GetLastError() );
        ok( !wcsicmp(buffer->Buffer[1].Name.Buffer, computer), "account domain is %s\n",
            wine_dbgstr_w(buffer->Buffer[1].Name.Buffer) );
        status = samr_lookup_domain_in_server( server, &buffer->Buffer[0].Name, &domain_sid );
        ok( status == STATUS_SUCCESS && domain_sid &&
            *GetSidSubAuthorityCount(domain_sid) == 1 &&
            *GetSidSubAuthority(domain_sid, 0) == SECURITY_BUILTIN_DOMAIN_RID,
            "builtin lookup returned %#lx, sid %p\n", status, domain_sid );
        MIDL_user_free( domain_sid );
        domain_sid = NULL;
        status = samr_lookup_domain_in_server( server, &buffer->Buffer[1].Name, &domain_sid );
        ok( status == STATUS_SUCCESS && domain_sid &&
            *GetSidSubAuthorityCount(domain_sid) == 4,
            "account lookup returned %#lx, sid %p\n", status, domain_sid );
        MIDL_user_free( domain_sid );
    }
    free_enumeration_buffer( buffer );

    status = samr_open_domain( server, READ_CONTROL | SAMR_DOMAIN_LIST_ACCOUNTS,
                               &unknown_sid.sid, &domain );
    ok( status == STATUS_NO_SUCH_DOMAIN, "unknown domain returned %#lx\n", status );
    ok( domain == NULL, "unknown domain returned handle %p\n", domain );

    status = samr_open_domain( server, READ_CONTROL | SAMR_DOMAIN_LIST_ACCOUNTS |
                               SAMR_DOMAIN_OPEN_ACCOUNT,
                               &account_sid.sid, &domain );
    ok( status == STATUS_SUCCESS, "account domain returned %#lx\n", status );
    ok( domain != NULL, "account domain returned a null handle\n" );

    enumeration_context = count = 0;
    buffer = NULL;
    status = samr_enumerate_users_in_domain( domain, &enumeration_context, 0,
                                             &buffer, 1, &count );
    ok( status == STATUS_MORE_ENTRIES, "short enumeration returned %#lx\n", status );
    ok( !enumeration_context, "short enumeration changed context to %lu\n",
        enumeration_context );
    ok( !count && !buffer, "short enumeration returned count %lu, buffer %p\n",
        count, buffer );

    status = samr_enumerate_users_in_domain( domain, &enumeration_context, 0,
                                             &buffer, ~0u, &count );
    ok( status == STATUS_SUCCESS, "enumeration returned %#lx\n", status );
    ok( enumeration_context == 1, "enumeration context is %lu\n", enumeration_context );
    ok( count == 1, "enumeration count is %lu\n", count );
    ok( buffer && buffer->EntriesRead == 1, "entries read is %lu\n",
        buffer ? buffer->EntriesRead : 0 );
    if (buffer && buffer->EntriesRead)
    {
        ok( buffer->Buffer[0].RelativeId == SAMR_LOCAL_USER_RID, "RID is %lu\n",
            buffer->Buffer[0].RelativeId );
        ok( GetUserNameW( user_name, &user_name_chars ), "GetUserNameW failed: %lu\n",
            GetLastError() );
        ok( buffer->Buffer[0].Name.Length == (user_name_chars - 1) * sizeof(WCHAR),
            "name length is %u\n", buffer->Buffer[0].Name.Length );
        ok( !wcsicmp( buffer->Buffer[0].Name.Buffer, user_name ), "name is %s\n",
            wine_dbgstr_w(buffer->Buffer[0].Name.Buffer) );
    }
    free_enumeration_buffer( buffer );

    enumeration_context = count = 0;
    buffer = NULL;
    status = samr_enumerate_users_in_domain2( domain, &enumeration_context, 0, 1,
                                              &buffer, ~0u, &count );
    ok( status == STATUS_SUCCESS, "private local enumeration returned %#lx\n", status );
    ok( enumeration_context == 1, "private local enumeration context is %lu\n",
        enumeration_context );
    ok( count == 1 && buffer && buffer->EntriesRead == 1,
        "private local enumeration returned count %lu, buffer %p\n", count, buffer );
    if (buffer && buffer->EntriesRead)
        ok( buffer->Buffer[0].RelativeId == SAMR_LOCAL_USER_RID,
            "private local enumeration RID is %lu\n", buffer->Buffer[0].RelativeId );
    free_enumeration_buffer( buffer );

    enumeration_context = count = 0;
    buffer = NULL;
    status = samr_enumerate_users_in_domain2( domain, &enumeration_context, 0, 2,
                                              &buffer, ~0u, &count );
    ok( status == STATUS_SUCCESS, "private connected enumeration returned %#lx\n", status );
    ok( enumeration_context == 1 && !count && !buffer,
        "private connected enumeration returned context %lu, count %lu, buffer %p\n",
        enumeration_context, count, buffer );

    {
        SAMR_UNICODE_STRING lookup_names[2];
        SAMR_ULONG_ARRAY ids = {0}, use = {0};
        SAMR_RETURNED_USTRING_ARRAY returned_names = {0};
        ULONG lookup_ids[2] = {SAMR_LOCAL_USER_RID, 999};
        WCHAR missing[] = L"missing-user";
        SID *user_sid = NULL;

        lookup_names[0].Length = (user_name_chars - 1) * sizeof(WCHAR);
        lookup_names[0].MaximumLength = user_name_chars * sizeof(WCHAR);
        lookup_names[0].Buffer = user_name;
        lookup_names[1].Length = wcslen(missing) * sizeof(WCHAR);
        lookup_names[1].MaximumLength = sizeof(missing);
        lookup_names[1].Buffer = missing;

        status = samr_lookup_names_in_domain2( domain, 1, lookup_names, &ids, &use );
        ok( status == STATUS_SUCCESS, "private name lookup returned %#lx\n", status );
        ok( ids.Count == 1 && ids.Element[0] == SAMR_LOCAL_USER_RID,
            "private lookup returned count %lu, RID %lu\n", ids.Count,
            ids.Count ? ids.Element[0] : 0 );
        ok( use.Count == 1 && use.Element[0] == 1,
            "private lookup returned use count %lu, type %lu\n", use.Count,
            use.Count ? use.Element[0] : 0 );
        free_ulong_array( &ids );
        free_ulong_array( &use );

        status = samr_lookup_names_in_domain( domain, 2, lookup_names, &ids, &use );
        ok( status == STATUS_SOME_NOT_MAPPED, "mixed name lookup returned %#lx\n", status );
        ok( ids.Count == 2 && ids.Element[0] == SAMR_LOCAL_USER_RID && !ids.Element[1],
            "mixed lookup returned count %lu, RIDs %lu/%lu\n", ids.Count,
            ids.Count ? ids.Element[0] : 0, ids.Count > 1 ? ids.Element[1] : 0 );
        ok( use.Count == 2 && use.Element[0] == 1 && use.Element[1] == 8,
            "mixed lookup returned types %lu/%lu\n",
            use.Count ? use.Element[0] : 0, use.Count > 1 ? use.Element[1] : 0 );
        free_ulong_array( &ids );
        free_ulong_array( &use );

        status = samr_lookup_ids_in_domain( domain, 2, lookup_ids, &returned_names, &use );
        ok( status == STATUS_SOME_NOT_MAPPED, "mixed RID lookup returned %#lx\n", status );
        ok( returned_names.Count == 2 && returned_names.Element[0].Buffer &&
            !wcsicmp( returned_names.Element[0].Buffer, user_name ) &&
            !returned_names.Element[1].Buffer,
            "mixed RID lookup returned unexpected names\n" );
        ok( use.Count == 2 && use.Element[0] == 1 && use.Element[1] == 8,
            "mixed RID lookup returned types %lu/%lu\n",
            use.Count ? use.Element[0] : 0, use.Count > 1 ? use.Element[1] : 0 );
        free_returned_names( &returned_names );
        free_ulong_array( &use );

        status = samr_rid_to_sid( domain, SAMR_LOCAL_USER_RID, &user_sid );
        ok( status == STATUS_SUCCESS && user_sid, "RID-to-SID returned %#lx, %p\n",
            status, user_sid );
        ok( user_sid && *GetSidSubAuthorityCount(user_sid) == 5 &&
            *GetSidSubAuthority(user_sid, 4) == SAMR_LOCAL_USER_RID,
            "RID-to-SID returned an unexpected SID\n" );
        MIDL_user_free( user_sid );
    }

    test_user_information( domain, user_name );

    buffer = NULL;
    count = 7;
    status = samr_enumerate_users_in_domain( domain, &enumeration_context, 0,
                                             &buffer, ~0u, &count );
    ok( status == STATUS_SUCCESS, "completed enumeration returned %#lx\n", status );
    ok( !count && !buffer, "completed enumeration returned count %lu, buffer %p\n",
        count, buffer );

    status = samr_close_handle( &domain );
    ok( status == STATUS_SUCCESS && !domain, "domain close returned %#lx, %p\n",
        status, domain );

    status = samr_open_domain( server, READ_CONTROL | SAMR_DOMAIN_LIST_ACCOUNTS,
                               &builtin_sid, &domain );
    ok( status == STATUS_SUCCESS, "builtin domain returned %#lx\n", status );
    enumeration_context = count = 0;
    buffer = NULL;
    status = samr_enumerate_users_in_domain( domain, &enumeration_context, 0,
                                             &buffer, ~0u, &count );
    ok( status == STATUS_SUCCESS && !count && !buffer,
        "builtin enumeration returned %#lx, count %lu, buffer %p\n", status, count, buffer );
    status = samr_close_handle( &domain );
    ok( status == STATUS_SUCCESS && !domain, "builtin close returned %#lx, %p\n",
        status, domain );
    status = samr_close_handle( &server );
    ok( status == STATUS_SUCCESS && !server, "server close returned %#lx, %p\n",
        status, server );
}

static void test_connect_contract(void)
{
    SAMR_IN_REVISION_INFO revision = {{3, 0}};
    SAMR_OUT_REVISION_INFO output = {{0}};
    SAMR_HANDLE server = NULL, domain = NULL;
    ULONG out_version = 0;
    NTSTATUS status;
    struct
    {
        SID sid;
        DWORD extra[3];
    } account_sid;

    status = samr_connect5( NULL, 0x04000000, 1, &revision,
                            &out_version, &output, &server );
    ok( status == STATUS_ACCESS_DENIED, "unsupported access returned %#lx\n", status );
    ok( !server, "unsupported access returned handle %p\n", server );
    ok( out_version == 1, "out version is %lu\n", out_version );
    ok( output.V1.Revision == 3, "revision is %lu\n", output.V1.Revision );

    status = samr_connect4( NULL, &server, 3, SAMR_SERVER_CONNECT );
    ok( status == STATUS_SUCCESS && server, "samr_connect4 returned %#lx, %p\n",
        status, server );
    create_sid( &account_sid.sid, 4, SECURITY_NT_NON_UNIQUE, 0, 0, 0 );
    status = samr_open_domain( server, SAMR_DOMAIN_LIST_ACCOUNTS,
                               &account_sid.sid, &domain );
    ok( status == STATUS_ACCESS_DENIED, "lookup without access returned %#lx\n", status );
    ok( !domain, "lookup without access returned handle %p\n", domain );
    status = samr_close_handle( &server );
    ok( status == STATUS_SUCCESS && !server, "connect4 close returned %#lx, %p\n",
        status, server );
}

START_TEST(samr)
{
    RPC_WSTR string_binding;
    RPC_STATUS status;

    ok( sizeof(SAMR_USER_ALL_INFORMATION) == 0x13c,
        "all-information size is %#Ix\n", sizeof(SAMR_USER_ALL_INFORMATION) );
    ok( sizeof(SAMR_USER_EXTENDED_INFORMATION) == 0xa8,
        "extended-information size is %#Ix\n", sizeof(SAMR_USER_EXTENDED_INFORMATION) );
    ok( sizeof(SAMR_USER_LOGON_UI_INFORMATION) == 2,
        "LogonUI-information size is %#Ix\n", sizeof(SAMR_USER_LOGON_UI_INFORMATION) );
    ok( sizeof(SAMR_USER_AUTH_INFORMATION) == 0x18,
        "auth-information size is %#Ix\n", sizeof(SAMR_USER_AUTH_INFORMATION) );

    status = RpcStringBindingComposeW( NULL, (RPC_WSTR)L"ncalrpc", NULL,
                                       (RPC_WSTR)L"samss lpc", NULL, &string_binding );
    ok( status == RPC_S_OK, "RpcStringBindingComposeW returned %ld\n", status );
    if (status != RPC_S_OK) return;
    status = RpcBindingFromStringBindingW( string_binding, &samr_binding );
    RpcStringFreeW( &string_binding );
    ok( status == RPC_S_OK, "RpcBindingFromStringBindingW returned %ld\n", status );
    if (status != RPC_S_OK) return;

    if (wait_for_server())
    {
        test_connect_contract();
        test_account_enumeration();
    }
    RpcBindingFree( &samr_binding );
}
