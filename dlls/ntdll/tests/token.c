/*
 * Token information tests
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "wine/test.h"

static NTSTATUS (WINAPI *pRtlGetAppContainerNamedObjectPath)(HANDLE, PSID, BOOLEAN, UNICODE_STRING *);
static NTSTATUS (WINAPI *pRtlGetAppContainerSidType)(PSID, ULONG *);
static NTSTATUS (WINAPI *pRtlCheckSandboxedToken)(HANDLE, BOOLEAN *);
static NTSTATUS (WINAPI *pNtSetUuidSeed)(UCHAR *);

struct token_security_attributes_information
{
    USHORT version;
    USHORT reserved;
    ULONG count;
    void *attributes;
};

#define IOCTL_KSEC_CONNECT_LSA 0x398000
#define IOCTL_KSEC_DUPLICATE_HANDLE 0x390034

struct ksec_duplicate_handle_request
{
    ULONGLONG source_handle;
    ULONGLONG target_process;
    ULONGLONG package_id;
};

static void check_token_object_dacl( HANDLE token, const char *context )
{
    SECURITY_DESCRIPTOR *sd;
    BOOLEAN present, defaulted;
    ACL *dacl = NULL;
    ULONG size = 0;
    NTSTATUS status;

    status = NtQuerySecurityObject( token, DACL_SECURITY_INFORMATION, NULL, 0, &size );
    ok( status == STATUS_BUFFER_TOO_SMALL, "%s: NtQuerySecurityObject returned %#lx.\n", context, status );
    ok( size >= SECURITY_DESCRIPTOR_MIN_LENGTH, "%s: got size %lu.\n", context, size );
    if (status != STATUS_BUFFER_TOO_SMALL || size < SECURITY_DESCRIPTOR_MIN_LENGTH) return;

    sd = malloc( size );
    ok( !!sd, "%s: failed to allocate %lu bytes.\n", context, size );
    if (!sd) return;

    status = NtQuerySecurityObject( token, DACL_SECURITY_INFORMATION, sd, size, &size );
    ok( status == STATUS_SUCCESS, "%s: NtQuerySecurityObject returned %#lx.\n", context, status );
    if (!status)
    {
        status = RtlGetDaclSecurityDescriptor( sd, &present, &dacl, &defaulted );
        ok( status == STATUS_SUCCESS, "%s: RtlGetDaclSecurityDescriptor returned %#lx.\n", context, status );
        if (!status)
        {
            ok( present, "%s: DACL is not present.\n", context );
            ok( !!dacl, "%s: DACL is null.\n", context );
        }
    }
    free( sd );
}

static void test_ksec_duplicate_handle(void)
{
    struct ksec_duplicate_handle_request request;
    TOKEN_STATISTICS source_stats, duplicate_stats;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK io;
    UNICODE_STRING name;
    ULONG system_pid, length;
    HANDLE ksec, source, process, duplicate;
    NTSTATUS status;

    if (!winetest_platform_is_wine)
    {
        win_skip( "KSecDD LSA registration is reserved by the system on Windows.\n" );
        return;
    }
    if (sizeof(void *) != sizeof(ULONGLONG))
    {
        win_skip( "The protected LSA handle-transfer request is 64-bit only.\n" );
        return;
    }

    RtlInitUnicodeString( &name, L"\\Device\\KsecDD" );
    InitializeObjectAttributes( &attr, &name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    status = NtOpenFile( &ksec, FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE, &attr, &io,
                         FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_NON_DIRECTORY_FILE );
    ok( status == STATUS_SUCCESS, "NtOpenFile returned %#lx.\n", status );
    if (status != STATUS_SUCCESS) return;

    system_pid = 0;
    status = NtDeviceIoControlFile( ksec, NULL, NULL, NULL, &io, IOCTL_KSEC_CONNECT_LSA,
                                    NULL, 0, &system_pid, sizeof(system_pid) );
    ok( status == STATUS_SUCCESS, "KSecDD LSA registration returned %#lx.\n", status );
    ok( io.Status == STATUS_SUCCESS, "got I/O status %#lx.\n", io.Status );
    ok( io.Information == sizeof(system_pid), "got information %Iu.\n", io.Information );
    ok( system_pid == 4, "got system process id %lu.\n", system_pid );
    if (status != STATUS_SUCCESS)
    {
        NtClose( ksec );
        return;
    }

    status = NtOpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &source );
    ok( status == STATUS_SUCCESS, "NtOpenProcessToken returned %#lx.\n", status );
    process = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId() );
    ok( !!process, "OpenProcess failed: %lu.\n", GetLastError() );
    if (status != STATUS_SUCCESS || !process)
    {
        if (status == STATUS_SUCCESS) NtClose( source );
        NtClose( ksec );
        return;
    }

    request.source_handle = HandleToULong( source );
    request.target_process = HandleToULong( process );
    request.package_id = ~0u;
    duplicate = NULL;
    status = NtDeviceIoControlFile( ksec, NULL, NULL, NULL, &io, IOCTL_KSEC_DUPLICATE_HANDLE,
                                    &request, sizeof(request), &duplicate, sizeof(duplicate) );
    ok( status == STATUS_SUCCESS, "KSecDD handle transfer returned %#lx.\n", status );
    ok( io.Status == STATUS_SUCCESS, "got I/O status %#lx.\n", io.Status );
    ok( io.Information == sizeof(duplicate), "got information %Iu.\n", io.Information );
    ok( !!duplicate, "expected a duplicated handle.\n" );

    if (status == STATUS_SUCCESS)
    {
        length = 0;
        status = NtQueryInformationToken( source, TokenStatistics, &source_stats,
                                          sizeof(source_stats), &length );
        ok( status == STATUS_SUCCESS, "source query returned %#lx.\n", status );
        status = NtQueryInformationToken( duplicate, TokenStatistics, &duplicate_stats,
                                          sizeof(duplicate_stats), &length );
        ok( status == STATUS_SUCCESS, "duplicate query returned %#lx.\n", status );
        ok( !memcmp( &source_stats.TokenId, &duplicate_stats.TokenId,
                     sizeof(source_stats.TokenId) ), "duplicated a different token.\n" );
        NtClose( duplicate );
    }

    NtClose( process );
    NtClose( source );
    NtClose( ksec );
}

static void test_session_reference(void)
{
    HANDLE adjust_token, query_token;
    BOOLEAN previous, ignored;
    ULONG reference = 0;
    NTSTATUS status;

    status = NtOpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_DEFAULT, &adjust_token );
    ok( status == STATUS_SUCCESS, "NtOpenProcessToken returned %#lx.\n", status );
    if (status != STATUS_SUCCESS) return;

    status = NtSetInformationToken( adjust_token, TokenSessionReference, NULL, 0 );
    ok( status == STATUS_INFO_LENGTH_MISMATCH, "got status %#lx.\n", status );
    status = NtSetInformationToken( adjust_token, TokenSessionReference, NULL, sizeof(reference) );
    ok( status == STATUS_ACCESS_VIOLATION, "got status %#lx.\n", status );
    status = NtSetInformationToken( (HANDLE)0xdead, TokenSessionReference,
                                    &reference, sizeof(reference) );
    ok( status == STATUS_INVALID_HANDLE, "got status %#lx.\n", status );

    status = NtOpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &query_token );
    ok( status == STATUS_SUCCESS, "NtOpenProcessToken returned %#lx.\n", status );
    if (status == STATUS_SUCCESS)
    {
        status = NtSetInformationToken( query_token, TokenSessionReference,
                                        &reference, sizeof(reference) );
        ok( status == STATUS_ACCESS_DENIED, "got status %#lx.\n", status );
        NtClose( query_token );
    }

    status = RtlAdjustPrivilege( SE_TCB_PRIVILEGE, TRUE, FALSE, &previous );
    if (status == STATUS_PRIVILEGE_NOT_HELD)
    {
        win_skip( "SeTcbPrivilege is unavailable.\n" );
    }
    else
    {
        ok( status == STATUS_SUCCESS, "RtlAdjustPrivilege returned %#lx.\n", status );
        if (status == STATUS_SUCCESS)
        {
            reference = 1;
            status = NtSetInformationToken( adjust_token, TokenSessionReference,
                                            &reference, sizeof(reference) );
            ok( status == STATUS_SUCCESS, "got status %#lx.\n", status );
            reference = 0;
            status = NtSetInformationToken( adjust_token, TokenSessionReference,
                                            &reference, sizeof(reference) );
            ok( status == STATUS_SUCCESS, "got status %#lx.\n", status );
            status = RtlAdjustPrivilege( SE_TCB_PRIVILEGE, previous, FALSE, &ignored );
            ok( status == STATUS_SUCCESS, "RtlAdjustPrivilege returned %#lx.\n", status );
        }
    }

    NtClose( adjust_token );
}

static void test_session_id(void)
{
    HANDLE adjust_token, query_token;
    BOOLEAN previous, ignored;
    ULONG original, session_id, length;
    NTSTATUS status;

    status = NtOpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_SESSIONID | TOKEN_QUERY,
                                 &adjust_token );
    ok( status == STATUS_SUCCESS, "NtOpenProcessToken returned %#lx.\n", status );
    if (status != STATUS_SUCCESS) return;

    length = 0;
    status = NtQueryInformationToken( adjust_token, TokenSessionId, &original,
                                      sizeof(original), &length );
    ok( status == STATUS_SUCCESS, "NtQueryInformationToken returned %#lx.\n", status );
    ok( length == sizeof(original), "got length %lu.\n", length );
    if (status != STATUS_SUCCESS)
    {
        NtClose( adjust_token );
        return;
    }

    session_id = original == 7 ? 6 : 7;
    status = NtSetInformationToken( adjust_token, TokenSessionId, &session_id,
                                    sizeof(session_id) - 1 );
    ok( status == STATUS_INFO_LENGTH_MISMATCH, "got status %#lx.\n", status );
    status = NtSetInformationToken( adjust_token, TokenSessionId, &session_id,
                                    sizeof(session_id) + 1 );
    ok( status == STATUS_INFO_LENGTH_MISMATCH, "got status %#lx.\n", status );
    status = NtSetInformationToken( adjust_token, TokenSessionId, NULL, sizeof(session_id) );
    ok( status == STATUS_ACCESS_VIOLATION, "got status %#lx.\n", status );
    status = NtSetInformationToken( (HANDLE)0xdead, TokenSessionId, &session_id,
                                    sizeof(session_id) );
    ok( status == STATUS_INVALID_HANDLE, "got status %#lx.\n", status );

    status = NtOpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &query_token );
    ok( status == STATUS_SUCCESS, "NtOpenProcessToken returned %#lx.\n", status );
    if (status == STATUS_SUCCESS)
    {
        status = NtSetInformationToken( query_token, TokenSessionId, &session_id,
                                        sizeof(session_id) );
        ok( status == STATUS_ACCESS_DENIED, "got status %#lx.\n", status );
        NtClose( query_token );
    }

    status = RtlAdjustPrivilege( SE_TCB_PRIVILEGE, TRUE, FALSE, &previous );
    if (status == STATUS_PRIVILEGE_NOT_HELD)
    {
        win_skip( "SeTcbPrivilege is unavailable.\n" );
    }
    else
    {
        ok( status == STATUS_SUCCESS, "RtlAdjustPrivilege returned %#lx.\n", status );
        if (status == STATUS_SUCCESS)
        {
            status = NtSetInformationToken( adjust_token, TokenSessionId, &session_id,
                                            sizeof(session_id) );
            ok( status == STATUS_SUCCESS, "got status %#lx.\n", status );
            length = 0;
            session_id = ~0u;
            status = NtQueryInformationToken( adjust_token, TokenSessionId, &session_id,
                                              sizeof(session_id), &length );
            ok( status == STATUS_SUCCESS, "NtQueryInformationToken returned %#lx.\n", status );
            ok( session_id == (original == 7 ? 6 : 7), "got session id %lu.\n", session_id );

            status = RtlAdjustPrivilege( SE_TCB_PRIVILEGE, FALSE, FALSE, &ignored );
            ok( status == STATUS_SUCCESS, "RtlAdjustPrivilege returned %#lx.\n", status );
            status = NtSetInformationToken( adjust_token, TokenSessionId, &original,
                                            sizeof(original) );
            ok( status == STATUS_PRIVILEGE_NOT_HELD, "got status %#lx.\n", status );

            status = RtlAdjustPrivilege( SE_TCB_PRIVILEGE, TRUE, FALSE, &ignored );
            ok( status == STATUS_SUCCESS, "RtlAdjustPrivilege returned %#lx.\n", status );
            status = NtSetInformationToken( adjust_token, TokenSessionId, &original,
                                            sizeof(original) );
            ok( status == STATUS_SUCCESS, "got status %#lx.\n", status );
            status = RtlAdjustPrivilege( SE_TCB_PRIVILEGE, previous, FALSE, &ignored );
            ok( status == STATUS_SUCCESS, "RtlAdjustPrivilege returned %#lx.\n", status );
        }
    }

    NtClose( adjust_token );
}

static void test_mandatory_policy(void)
{
    TOKEN_MANDATORY_POLICY policy;
    HANDLE adjust_token, query_token;
    ULONG length;
    NTSTATUS status;

    status = NtOpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_DEFAULT | TOKEN_QUERY,
                                 &adjust_token );
    ok( status == STATUS_SUCCESS, "NtOpenProcessToken returned %#lx.\n", status );
    if (status != STATUS_SUCCESS) return;

    status = NtSetInformationToken( adjust_token, TokenMandatoryPolicy, NULL, 0 );
    ok( status == STATUS_INFO_LENGTH_MISMATCH, "got status %#lx.\n", status );
    status = NtSetInformationToken( adjust_token, TokenMandatoryPolicy, NULL, sizeof(policy) );
    ok( status == STATUS_ACCESS_VIOLATION, "got status %#lx.\n", status );

    policy.Policy = ~TOKEN_MANDATORY_POLICY_VALID_MASK;
    status = NtSetInformationToken( adjust_token, TokenMandatoryPolicy, &policy, sizeof(policy) );
    ok( status == STATUS_INVALID_PARAMETER, "got status %#lx.\n", status );

    policy.Policy = TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN;
    status = NtSetInformationToken( (HANDLE)0xdead, TokenMandatoryPolicy, &policy, sizeof(policy) );
    ok( status == STATUS_INVALID_HANDLE, "got status %#lx.\n", status );

    status = NtOpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &query_token );
    ok( status == STATUS_SUCCESS, "NtOpenProcessToken returned %#lx.\n", status );
    if (status == STATUS_SUCCESS)
    {
        status = NtSetInformationToken( query_token, TokenMandatoryPolicy, &policy, sizeof(policy) );
        ok( status == STATUS_ACCESS_DENIED, "got status %#lx.\n", status );
        NtClose( query_token );
    }

    status = NtSetInformationToken( adjust_token, TokenMandatoryPolicy, &policy, sizeof(policy) );
    ok( status == STATUS_SUCCESS, "got status %#lx.\n", status );

    policy.Policy = 0xdeadbeef;
    length = 0;
    status = NtQueryInformationToken( adjust_token, TokenMandatoryPolicy, &policy,
                                      sizeof(policy), &length );
    ok( status == STATUS_SUCCESS, "got status %#lx.\n", status );
    ok( length == sizeof(policy), "got length %lu.\n", length );
    ok( policy.Policy == TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN,
        "got policy %#lx.\n", policy.Policy );

    NtClose( adjust_token );
}

static void test_audit_policy_and_origin(void)
{
    TOKEN_AUDIT_POLICY audit_policy, queried_policy;
    TOKEN_ORIGIN origin, queried_origin;
    HANDLE adjust_token, query_token;
    ULONG i, length;
    NTSTATUS status;

    status = NtOpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_DEFAULT | TOKEN_QUERY,
                                 &adjust_token );
    ok( status == STATUS_SUCCESS, "NtOpenProcessToken returned %#lx.\n", status );
    if (status != STATUS_SUCCESS) return;

    status = NtSetInformationToken( adjust_token, TokenAuditPolicy, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got status %#lx.\n", status );
    status = NtSetInformationToken( adjust_token, TokenAuditPolicy, NULL,
                                    sizeof(audit_policy) );
    ok( status == STATUS_ACCESS_VIOLATION, "got status %#lx.\n", status );

    for (i = 0; i < sizeof(audit_policy.PerUserPolicy); i++)
        audit_policy.PerUserPolicy[i] = i ^ 0x5a;
    status = NtSetInformationToken( (HANDLE)0xdead, TokenAuditPolicy, &audit_policy,
                                    sizeof(audit_policy) );
    ok( status == STATUS_INVALID_HANDLE, "got status %#lx.\n", status );

    status = NtOpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &query_token );
    ok( status == STATUS_SUCCESS, "NtOpenProcessToken returned %#lx.\n", status );
    if (status == STATUS_SUCCESS)
    {
        status = NtSetInformationToken( query_token, TokenAuditPolicy, &audit_policy,
                                        sizeof(audit_policy) );
        ok( status == STATUS_ACCESS_DENIED, "got status %#lx.\n", status );
        NtClose( query_token );
    }

    status = NtSetInformationToken( adjust_token, TokenAuditPolicy, &audit_policy,
                                    sizeof(audit_policy) );
    ok( status == STATUS_SUCCESS, "got status %#lx.\n", status );
    memset( &queried_policy, 0, sizeof(queried_policy) );
    length = 0;
    status = NtQueryInformationToken( adjust_token, TokenAuditPolicy, &queried_policy,
                                      sizeof(queried_policy), &length );
    ok( status == STATUS_SUCCESS, "got status %#lx.\n", status );
    ok( length == sizeof(queried_policy), "got length %lu.\n", length );
    ok( !memcmp( &queried_policy, &audit_policy, sizeof(audit_policy) ),
        "audit policy did not round-trip.\n" );

    status = NtSetInformationToken( adjust_token, TokenAuditPolicy, NULL, 0 );
    ok( status == STATUS_SUCCESS, "got status %#lx.\n", status );
    memset( &queried_policy, 0xff, sizeof(queried_policy) );
    status = NtQueryInformationToken( adjust_token, TokenAuditPolicy, &queried_policy,
                                      sizeof(queried_policy), &length );
    ok( status == STATUS_SUCCESS, "got status %#lx.\n", status );
    for (i = 0; i < sizeof(queried_policy.PerUserPolicy); i++)
        ok( !queried_policy.PerUserPolicy[i], "got policy byte %lu = %#x.\n",
            i, queried_policy.PerUserPolicy[i] );

    status = NtSetInformationToken( adjust_token, TokenOrigin, NULL, 0 );
    ok( status == STATUS_INFO_LENGTH_MISMATCH, "got status %#lx.\n", status );
    status = NtSetInformationToken( adjust_token, TokenOrigin, NULL, sizeof(origin) );
    ok( status == STATUS_ACCESS_VIOLATION, "got status %#lx.\n", status );

    origin.OriginatingLogonSession.LowPart = 0x12345678;
    origin.OriginatingLogonSession.HighPart = 0x76543210;
    status = NtSetInformationToken( (HANDLE)0xdead, TokenOrigin, &origin, sizeof(origin) );
    ok( status == STATUS_INVALID_HANDLE, "got status %#lx.\n", status );
    status = NtSetInformationToken( adjust_token, TokenOrigin, &origin, sizeof(origin) );
    ok( status == STATUS_SUCCESS, "got status %#lx.\n", status );

    memset( &queried_origin, 0, sizeof(queried_origin) );
    length = 0;
    status = NtQueryInformationToken( adjust_token, TokenOrigin, &queried_origin,
                                      sizeof(queried_origin), &length );
    ok( status == STATUS_SUCCESS, "got status %#lx.\n", status );
    ok( length == sizeof(queried_origin), "got length %lu.\n", length );
    ok( queried_origin.OriginatingLogonSession.LowPart ==
        origin.OriginatingLogonSession.LowPart,
        "got origin low part %#lx.\n", queried_origin.OriginatingLogonSession.LowPart );
    ok( queried_origin.OriginatingLogonSession.HighPart ==
        origin.OriginatingLogonSession.HighPart,
        "got origin high part %#lx.\n", queried_origin.OriginatingLogonSession.HighPart );

    NtClose( adjust_token );
}

static void test_security_attributes(void)
{
    struct token_security_attributes_information attributes;
    HANDLE token;
    ULONG length;
    NTSTATUS status;

    if (!winetest_platform_is_wine)
    {
        win_skip( "The empty security-attribute model is Wine-specific.\n" );
        return;
    }

    status = NtOpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &token );
    ok( status == STATUS_SUCCESS, "NtOpenProcessToken returned %#lx.\n", status );
    if (status) return;

    length = 0;
    status = NtQueryInformationToken( token, TokenSecurityAttributes, NULL, 0, &length );
    ok( status == STATUS_BUFFER_TOO_SMALL, "got status %#lx.\n", status );
    ok( length == sizeof(attributes), "got length %lu.\n", length );

    memset( &attributes, 0xcc, sizeof(attributes) );
    status = NtQueryInformationToken( token, TokenSecurityAttributes, &attributes,
                                      sizeof(attributes), &length );
    ok( status == STATUS_SUCCESS, "got status %#lx.\n", status );
    ok( length == sizeof(attributes), "got length %lu.\n", length );
    ok( attributes.version == 1, "got version %u.\n", attributes.version );
    ok( !attributes.reserved, "got reserved value %u.\n", attributes.reserved );
    ok( !attributes.count, "got attribute count %lu.\n", attributes.count );
    ok( !attributes.attributes, "got attribute pointer %p.\n", attributes.attributes );

    NtClose( token );
}

static void test_adjust_groups(void)
{
    struct
    {
        ULONG GroupCount;
        SID_AND_ATTRIBUTES Groups[2];
    } token_groups;
    struct
    {
        ULONG GroupCount;
        SID_AND_ATTRIBUTES Groups[1];
    } new_state;
    BYTE query_buffer[256], previous_buffer[256];
    TOKEN_GROUPS *queried = (TOKEN_GROUPS *)query_buffer;
    TOKEN_GROUPS *previous = (TOKEN_GROUPS *)previous_buffer;
    SECURITY_QUALITY_OF_SERVICE qos;
    TOKEN_DEFAULT_DACL default_dacl = {0};
    TOKEN_PRIMARY_GROUP primary_group;
    TOKEN_PRIVILEGES privileges = {0};
    TOKEN_SOURCE source = {{0}};
    TOKEN_ELEVATION_TYPE elevation_type;
    TOKEN_LINKED_TOKEN linked_token;
    ULONG session_id;
    OBJECT_ATTRIBUTES attr;
    TOKEN_OWNER owner;
    TOKEN_USER user;
    LARGE_INTEGER expire;
    LUID token_id;
    HANDLE token;
    ULONG i, length;
    NTSTATUS status;
    SID user_sid = {SID_REVISION, 1, {SECURITY_NT_AUTHORITY}, {SECURITY_LOCAL_SYSTEM_RID}};
    SID world_sid = {SID_REVISION, 1, {SECURITY_WORLD_SID_AUTHORITY}, {SECURITY_WORLD_RID}};
    struct
    {
        SID sid;
        DWORD extra_subauthority;
    } admins_sid = {{SID_REVISION, 2, {SECURITY_NT_AUTHORITY},
                     {SECURITY_BUILTIN_DOMAIN_RID}}, DOMAIN_ALIAS_RID_ADMINS};

    if (!winetest_platform_is_wine)
    {
        win_skip( "The controlled token fixture requires Wine's server token authority.\n" );
        return;
    }

    user.User.Sid = &user_sid;
    user.User.Attributes = 0;
    token_groups.GroupCount = 2;
    token_groups.Groups[0].Sid = &world_sid;
    token_groups.Groups[0].Attributes = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT |
                                        SE_GROUP_ENABLED;
    token_groups.Groups[1].Sid = &admins_sid.sid;
    token_groups.Groups[1].Attributes = SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED;
    owner.Owner = &admins_sid.sid;
    primary_group.PrimaryGroup = &admins_sid.sid;
    NtAllocateLocallyUniqueId( &token_id );
    expire.QuadPart = 0x7fffffffffffffff;
    memcpy( source.SourceName, "group", 5 );
    NtAllocateLocallyUniqueId( &source.SourceIdentifier );
    qos.Length = sizeof(qos);
    qos.ImpersonationLevel = SecurityImpersonation;
    qos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
    qos.EffectiveOnly = FALSE;
    InitializeObjectAttributes( &attr, NULL, 0, NULL, NULL );
    attr.SecurityQualityOfService = &qos;

    status = NtCreateToken( &token, TOKEN_ALL_ACCESS, &attr, TokenPrimary, &token_id, &expire,
                            &user, (TOKEN_GROUPS *)&token_groups, &privileges, &owner,
                            &primary_group, &default_dacl, &source );
    ok( status == STATUS_SUCCESS, "NtCreateToken returned %#lx.\n", status );
    if (status) return;

    check_token_object_dacl( token, "created token" );

    status = NtQueryInformationToken( token, TokenElevationType, &elevation_type,
                                      sizeof(elevation_type), &length );
    ok( status == STATUS_SUCCESS, "TokenElevationType returned %#lx.\n", status );
    ok( elevation_type == TokenElevationTypeDefault, "got elevation type %u.\n", elevation_type );

    status = NtQueryInformationToken( token, TokenSessionId, &session_id,
                                      sizeof(session_id), &length );
    ok( status == STATUS_SUCCESS, "TokenSessionId returned %#lx.\n", status );
    ok( session_id == NtCurrentTeb()->Peb->SessionId, "got session id %lu, expected %lu.\n",
        session_id, NtCurrentTeb()->Peb->SessionId );

    linked_token.LinkedToken = (HANDLE)0xdeadbeef;
    status = NtQueryInformationToken( token, TokenLinkedToken, &linked_token,
                                      sizeof(linked_token), &length );
    ok( status == STATUS_SUCCESS, "TokenLinkedToken returned %#lx.\n", status );
    ok( !linked_token.LinkedToken, "got linked token %p.\n", linked_token.LinkedToken );

    {
        TOKEN_STATISTICS statistics;

        status = NtQueryInformationToken( token, TokenStatistics, &statistics,
                                          sizeof(statistics), &length );
        ok( status == STATUS_SUCCESS, "TokenStatistics returned %#lx.\n", status );
        ok( statistics.AuthenticationId.LowPart == token_id.LowPart &&
            statistics.AuthenticationId.HighPart == token_id.HighPart,
            "got authentication id %08lx:%08lx, expected %08lx:%08lx.\n",
            statistics.AuthenticationId.HighPart, statistics.AuthenticationId.LowPart,
            token_id.HighPart, token_id.LowPart );
    }

    new_state.GroupCount = 1;
    new_state.Groups[0].Sid = &admins_sid.sid;
    new_state.Groups[0].Attributes = 0;

    memset( previous_buffer, 0xcc, sizeof(previous_buffer) );
    length = 0;
    status = NtAdjustGroupsToken( token, FALSE, (TOKEN_GROUPS *)&new_state, 0,
                                  previous, &length );
    ok( status == STATUS_BUFFER_TOO_SMALL, "got status %#lx.\n", status );
    ok( length > FIELD_OFFSET(TOKEN_GROUPS, Groups), "got length %lu.\n", length );

    status = NtQueryInformationToken( token, TokenGroups, queried, sizeof(query_buffer), &length );
    ok( status == STATUS_SUCCESS, "NtQueryInformationToken returned %#lx.\n", status );
    for (i = 0; status == STATUS_SUCCESS && i < queried->GroupCount; i++)
        if (EqualSid( queried->Groups[i].Sid, &admins_sid.sid )) break;
    ok( i < queried->GroupCount, "administrators group not found.\n" );
    if (i < queried->GroupCount)
        ok( queried->Groups[i].Attributes & SE_GROUP_ENABLED,
            "buffer failure changed group attributes %#lx.\n", queried->Groups[i].Attributes );

    status = NtAdjustGroupsToken( token, FALSE, (TOKEN_GROUPS *)&new_state,
                                  sizeof(previous_buffer), previous, &length );
    ok( status == STATUS_SUCCESS, "got status %#lx.\n", status );
    ok( previous->GroupCount == 1, "got group count %lu.\n", previous->GroupCount );
    if (previous->GroupCount == 1)
    {
        ok( EqualSid( previous->Groups[0].Sid, &admins_sid.sid ), "got unexpected previous SID.\n" );
        ok( previous->Groups[0].Attributes & SE_GROUP_ENABLED,
            "got previous attributes %#lx.\n", previous->Groups[0].Attributes );
    }

    status = NtQueryInformationToken( token, TokenGroups, queried, sizeof(query_buffer), &length );
    ok( status == STATUS_SUCCESS, "NtQueryInformationToken returned %#lx.\n", status );
    for (i = 0; status == STATUS_SUCCESS && i < queried->GroupCount; i++)
        if (EqualSid( queried->Groups[i].Sid, &admins_sid.sid )) break;
    ok( i < queried->GroupCount, "administrators group not found.\n" );
    if (i < queried->GroupCount)
        ok( !(queried->Groups[i].Attributes & SE_GROUP_ENABLED),
            "got disabled attributes %#lx.\n", queried->Groups[i].Attributes );

    status = NtAdjustGroupsToken( token, TRUE, NULL, 0, NULL, NULL );
    ok( status == STATUS_SUCCESS, "reset returned %#lx.\n", status );
    status = NtQueryInformationToken( token, TokenGroups, queried, sizeof(query_buffer), &length );
    ok( status == STATUS_SUCCESS, "NtQueryInformationToken returned %#lx.\n", status );
    for (i = 0; status == STATUS_SUCCESS && i < queried->GroupCount; i++)
        if (EqualSid( queried->Groups[i].Sid, &admins_sid.sid )) break;
    ok( i < queried->GroupCount, "administrators group not found.\n" );
    if (i < queried->GroupCount)
        ok( queried->Groups[i].Attributes & SE_GROUP_ENABLED,
            "reset produced attributes %#lx.\n", queried->Groups[i].Attributes );

    new_state.Groups[0].Sid = &user_sid;
    status = NtAdjustGroupsToken( token, FALSE, (TOKEN_GROUPS *)&new_state, 0, NULL, NULL );
    ok( status == STATUS_SUCCESS, "absent group returned %#lx.\n", status );

    new_state.Groups[0].Sid = &admins_sid.sid;
    status = NtAdjustGroupsToken( token, FALSE, (TOKEN_GROUPS *)&new_state, 0, NULL, NULL );
    ok( status == STATUS_SUCCESS, "no-previous-state adjustment returned %#lx.\n", status );
    status = NtAdjustGroupsToken( token, TRUE, NULL, 0, NULL, NULL );
    ok( status == STATUS_SUCCESS, "second reset returned %#lx.\n", status );

    new_state.Groups[0].Sid = &world_sid;
    status = NtAdjustGroupsToken( token, FALSE, (TOKEN_GROUPS *)&new_state, 0, NULL, NULL );
    ok( status == STATUS_CANT_DISABLE_MANDATORY, "got status %#lx.\n", status );

    NtClose( token );

    primary_group.PrimaryGroup = &user_sid;
    status = NtCreateToken( &token, TOKEN_ALL_ACCESS, &attr, TokenPrimary, &token_id, &expire,
                            &user, (TOKEN_GROUPS *)&token_groups, &privileges, &owner,
                            &primary_group, &default_dacl, &source );
    ok( status == STATUS_SUCCESS, "user primary group returned %#lx.\n", status );
    if (!status)
    {
        BYTE primary_buffer[sizeof(TOKEN_PRIMARY_GROUP) + SECURITY_MAX_SID_SIZE];
        TOKEN_PRIMARY_GROUP *queried_primary = (TOKEN_PRIMARY_GROUP *)primary_buffer;

        status = NtQueryInformationToken( token, TokenPrimaryGroup, queried_primary,
                                          sizeof(primary_buffer), &length );
        ok( status == STATUS_SUCCESS, "TokenPrimaryGroup returned %#lx.\n", status );
        if (!status)
            ok( EqualSid( queried_primary->PrimaryGroup, &user_sid ),
                "primary group does not match the user SID.\n" );

        status = NtQueryInformationToken( token, TokenGroups, queried, sizeof(query_buffer), &length );
        ok( status == STATUS_SUCCESS, "TokenGroups returned %#lx.\n", status );
        if (!status)
        {
            ok( queried->GroupCount == token_groups.GroupCount, "got group count %lu.\n",
                queried->GroupCount );
            for (i = 0; i < queried->GroupCount; ++i)
                ok( !EqualSid( queried->Groups[i].Sid, &user_sid ),
                    "user SID was added to TokenGroups.\n" );
        }
        NtClose( token );
    }
}

static void test_appcontainer_named_object_path(void)
{
    SID sid = {SID_REVISION, 1, {SECURITY_APP_PACKAGE_AUTHORITY}, {SECURITY_APP_PACKAGE_BASE_RID}};
    UNICODE_STRING path = {0xdead, 0xbeef, (WCHAR *)(ULONG_PTR)0xdeadbeef};
    NTSTATUS status;

    if (!pRtlGetAppContainerNamedObjectPath)
    {
        win_skip( "RtlGetAppContainerNamedObjectPath is unavailable.\n" );
        return;
    }

    status = pRtlGetAppContainerNamedObjectPath( NULL, NULL, FALSE, NULL );
    ok( status == STATUS_INVALID_PARAMETER, "got status %#lx.\n", status );

    status = pRtlGetAppContainerNamedObjectPath( GetCurrentProcessToken(), &sid, FALSE, &path );
    ok( status == STATUS_INVALID_PARAMETER_MIX, "got status %#lx.\n", status );

    status = pRtlGetAppContainerNamedObjectPath( NULL, NULL, FALSE, &path );
    ok( status == STATUS_SUCCESS, "got status %#lx.\n", status );
    ok( !path.Length, "got length %u.\n", path.Length );
    ok( !path.MaximumLength, "got maximum length %u.\n", path.MaximumLength );
    ok( !path.Buffer, "got buffer %p.\n", path.Buffer );
}

static void test_appcontainer_sid_type(void)
{
    static const SID_IDENTIFIER_AUTHORITY authority = {SECURITY_APP_PACKAGE_AUTHORITY};
    BYTE buffer[SECURITY_MAX_SID_SIZE];
    SID *sid = (SID *)buffer;
    NTSTATUS status;
    ULONG type;

    if (!pRtlGetAppContainerSidType)
    {
        win_skip( "RtlGetAppContainerSidType is unavailable.\n" );
        return;
    }

    memset( buffer, 0, sizeof(buffer) );
    sid->Revision = SID_REVISION;
    sid->IdentifierAuthority = authority;
    sid->SubAuthority[0] = SECURITY_APP_PACKAGE_BASE_RID;

    sid->SubAuthorityCount = 8;
    type = 0xdeadbeef;
    status = pRtlGetAppContainerSidType( sid, &type );
    ok( status == STATUS_SUCCESS, "got status %#lx.\n", status );
    ok( type == 2, "got type %lu.\n", type );

    sid->SubAuthorityCount = 12;
    type = 0xdeadbeef;
    status = pRtlGetAppContainerSidType( sid, &type );
    ok( status == STATUS_SUCCESS, "got status %#lx.\n", status );
    ok( type == 1, "got type %lu.\n", type );

    sid->SubAuthorityCount = 3;
    type = 0xdeadbeef;
    status = pRtlGetAppContainerSidType( sid, &type );
    ok( status == STATUS_NOT_APPCONTAINER, "got status %#lx.\n", status );
    ok( type == 3, "got type %lu.\n", type );

    sid->SubAuthorityCount = 1;
    type = 0xdeadbeef;
    status = pRtlGetAppContainerSidType( sid, &type );
    ok( status == STATUS_NOT_APPCONTAINER, "got status %#lx.\n", status );
    ok( type == 0, "got type %lu.\n", type );

    sid->SubAuthorityCount = 8;
    sid->SubAuthority[0] = SECURITY_APP_PACKAGE_BASE_RID + 1;
    type = 0xdeadbeef;
    status = pRtlGetAppContainerSidType( sid, &type );
    ok( status == STATUS_NOT_APPCONTAINER, "got status %#lx.\n", status );
    ok( type == 0, "got type %lu.\n", type );
}

static void test_set_uuid_seed(void)
{
    UCHAR seed[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    NTSTATUS status;

    if (!pNtSetUuidSeed)
    {
        win_skip( "NtSetUuidSeed is unavailable.\n" );
        return;
    }

    status = pNtSetUuidSeed( seed );
    ok( status == STATUS_ACCESS_DENIED, "NtSetUuidSeed returned %#lx.\n", status );
    status = pNtSetUuidSeed( NULL );
    ok( status == STATUS_ACCESS_DENIED, "NtSetUuidSeed(NULL) returned %#lx.\n", status );
}

static void test_sandboxed_token(void)
{
    BOOLEAN sandboxed = 0xcc;
    DWORD value = 0xcccccccc;
    ULONG size = 0;
    NTSTATUS status;

    if (!pRtlCheckSandboxedToken)
    {
        win_skip( "RtlCheckSandboxedToken is unavailable.\n" );
        return;
    }

    status = pRtlCheckSandboxedToken( NULL, &sandboxed );
    ok( status == STATUS_SUCCESS, "RtlCheckSandboxedToken returned %#lx.\n", status );
    ok( !sandboxed, "current token reported sandboxed.\n" );

    status = NtQueryInformationToken( GetCurrentProcessToken(), TokenIsSandboxed,
                                      &value, sizeof(value), &size );
    ok( status == STATUS_SUCCESS, "TokenIsSandboxed returned %#lx.\n", status );
    ok( size == sizeof(value), "got size %lu.\n", size );
    ok( !value, "current token reported sandboxed.\n" );

    sandboxed = 0xcc;
    status = pRtlCheckSandboxedToken( (HANDLE)0xdeadbeef, &sandboxed );
    ok( status == STATUS_INVALID_HANDLE, "invalid token returned %#lx.\n", status );
    ok( !sandboxed, "invalid token left sandboxed set.\n" );
}

START_TEST(token)
{
    HMODULE ntdll = GetModuleHandleA( "ntdll.dll" );

    pRtlGetAppContainerNamedObjectPath = (void *)GetProcAddress( ntdll, "RtlGetAppContainerNamedObjectPath" );
    pRtlGetAppContainerSidType = (void *)GetProcAddress( ntdll, "RtlGetAppContainerSidType" );
    pRtlCheckSandboxedToken = (void *)GetProcAddress( ntdll, "RtlCheckSandboxedToken" );
    pNtSetUuidSeed = (void *)GetProcAddress( ntdll, "NtSetUuidSeed" );

    test_ksec_duplicate_handle();
    test_session_reference();
    test_session_id();
    test_mandatory_policy();
    test_audit_policy_and_origin();
    test_security_attributes();
    test_adjust_groups();
    test_appcontainer_named_object_path();
    test_appcontainer_sid_type();
    test_sandboxed_token();
    test_set_uuid_seed();
}
