/*
 * Access-check audit syscall tests
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
#include "winnt.h"
#include "winternl.h"
#include "wine/test.h"

static NTSTATUS (WINAPI *pNtAccessCheckAndAuditAlarm)(UNICODE_STRING *, HANDLE,
        UNICODE_STRING *, UNICODE_STRING *, PSECURITY_DESCRIPTOR, ACCESS_MASK,
        GENERIC_MAPPING *, BOOLEAN, ACCESS_MASK *, NTSTATUS *, BOOLEAN *);

START_TEST(access_audit)
{
    BYTE acl_buffer[sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + SECURITY_MAX_SID_SIZE];
    SID_IDENTIFIER_AUTHORITY world_authority = SECURITY_WORLD_SID_AUTHORITY;
    GENERIC_MAPPING mapping = { 1, 2, 4, 7 };
    UNICODE_STRING subsystem, type, name;
    SECURITY_DESCRIPTOR descr;
    ACCESS_MASK granted;
    NTSTATUS status, access_status;
    PSID world_sid;
    BOOLEAN onclose;
    BOOL ret;

    pNtAccessCheckAndAuditAlarm = (void *)GetProcAddress( GetModuleHandleA("ntdll.dll"),
                                                          "NtAccessCheckAndAuditAlarm" );
    if (!pNtAccessCheckAndAuditAlarm)
    {
        win_skip( "NtAccessCheckAndAuditAlarm is unavailable.\n" );
        return;
    }

    RtlInitUnicodeString( &subsystem, L"WineTest" );
    RtlInitUnicodeString( &type, L"WineTestObject" );
    RtlInitUnicodeString( &name, L"WineTestName" );
    RevertToSelf();
    status = pNtAccessCheckAndAuditAlarm( &subsystem, NULL, &type, &name, &descr, 1,
                                          &mapping, FALSE, &granted, &access_status, &onclose );
    ok( status == STATUS_NO_TOKEN, "got status %#lx.\n", status );

    ret = AllocateAndInitializeSid( &world_authority, 1, SECURITY_WORLD_RID,
                                    0, 0, 0, 0, 0, 0, 0, &world_sid );
    ok( ret, "AllocateAndInitializeSid failed: %lu.\n", GetLastError() );
    if (!ret) return;
    ret = InitializeAcl( (ACL *)acl_buffer, sizeof(acl_buffer), ACL_REVISION );
    ok( ret, "InitializeAcl failed: %lu.\n", GetLastError() );
    ret = AddAccessAllowedAce( (ACL *)acl_buffer, ACL_REVISION, 1, world_sid );
    ok( ret, "AddAccessAllowedAce failed: %lu.\n", GetLastError() );
    ret = InitializeSecurityDescriptor( &descr, SECURITY_DESCRIPTOR_REVISION );
    ok( ret, "InitializeSecurityDescriptor failed: %lu.\n", GetLastError() );
    ret = SetSecurityDescriptorOwner( &descr, world_sid, FALSE );
    ok( ret, "SetSecurityDescriptorOwner failed: %lu.\n", GetLastError() );
    ret = SetSecurityDescriptorGroup( &descr, world_sid, FALSE );
    ok( ret, "SetSecurityDescriptorGroup failed: %lu.\n", GetLastError() );
    ret = SetSecurityDescriptorDacl( &descr, TRUE, (ACL *)acl_buffer, FALSE );
    ok( ret, "SetSecurityDescriptorDacl failed: %lu.\n", GetLastError() );

    ret = ImpersonateSelf( SecurityImpersonation );
    ok( ret, "ImpersonateSelf failed: %lu.\n", GetLastError() );
    granted = 0xdeadbeef;
    access_status = STATUS_UNSUCCESSFUL;
    onclose = TRUE;
    status = pNtAccessCheckAndAuditAlarm( &subsystem, NULL, &type, &name, &descr, 1,
                                          &mapping, FALSE, &granted, &access_status, &onclose );
    ok( status == STATUS_SUCCESS, "got status %#lx.\n", status );
    ok( access_status == STATUS_SUCCESS, "got access status %#lx.\n", access_status );
    ok( granted == 1, "got granted access %#lx.\n", granted );
    ok( !onclose, "expected no close audit.\n" );

    RevertToSelf();
    FreeSid( world_sid );
}
