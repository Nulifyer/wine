/*
 * Privilege object audit notification tests
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

static NTSTATUS (WINAPI *pNtOpenProcessToken)(HANDLE, DWORD, HANDLE *);
static NTSTATUS (WINAPI *pNtPrivilegeObjectAuditAlarm)(UNICODE_STRING *, HANDLE, HANDLE,
                                                       ULONG, PRIVILEGE_SET *, BOOLEAN);

START_TEST(privilege_audit)
{
    HMODULE ntdll = GetModuleHandleA( "ntdll.dll" );
    PRIVILEGE_SET before, privileges;
    UNICODE_STRING subsystem;
    HANDLE query_token, no_query_token;
    NTSTATUS status;

    pNtOpenProcessToken = (void *)GetProcAddress( ntdll, "NtOpenProcessToken" );
    pNtPrivilegeObjectAuditAlarm = (void *)GetProcAddress( ntdll, "NtPrivilegeObjectAuditAlarm" );
    if (!pNtPrivilegeObjectAuditAlarm)
    {
        win_skip( "NtPrivilegeObjectAuditAlarm is not available.\n" );
        return;
    }

    RtlInitUnicodeString( &subsystem, L"Services" );
    memset( &privileges, 0, sizeof(privileges) );
    privileges.PrivilegeCount = 1;
    privileges.Control = PRIVILEGE_SET_ALL_NECESSARY;
    privileges.Privilege[0].Luid.LowPart = 19;

    status = pNtOpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &query_token );
    ok( status == STATUS_SUCCESS, "NtOpenProcessToken returned %#lx.\n", status );
    if (status != STATUS_SUCCESS) return;
    status = pNtOpenProcessToken( GetCurrentProcess(), TOKEN_DUPLICATE, &no_query_token );
    ok( status == STATUS_SUCCESS, "NtOpenProcessToken returned %#lx.\n", status );
    if (status != STATUS_SUCCESS)
    {
        NtClose( query_token );
        return;
    }

    before = privileges;
    status = pNtPrivilegeObjectAuditAlarm( &subsystem, NULL, query_token, 0,
                                           &privileges, FALSE );
    ok( status == STATUS_SUCCESS, "NtPrivilegeObjectAuditAlarm returned %#lx.\n", status );
    ok( !memcmp( &privileges, &before, sizeof(privileges) ), "privilege set changed.\n" );

    privileges.Privilege[0].Attributes = SE_PRIVILEGE_USED_FOR_ACCESS;
    before = privileges;
    status = pNtPrivilegeObjectAuditAlarm( &subsystem, NULL, query_token, 0x02000000,
                                           &privileges, TRUE );
    ok( status == STATUS_SUCCESS, "NtPrivilegeObjectAuditAlarm returned %#lx.\n", status );
    ok( !memcmp( &privileges, &before, sizeof(privileges) ), "privilege set changed.\n" );

    status = pNtPrivilegeObjectAuditAlarm( &subsystem, NULL, (HANDLE)0xdead, 0,
                                           &privileges, FALSE );
    ok( status == STATUS_INVALID_HANDLE, "got status %#lx.\n", status );
    status = pNtPrivilegeObjectAuditAlarm( &subsystem, NULL, no_query_token, 0,
                                           &privileges, FALSE );
    ok( status == STATUS_ACCESS_DENIED, "got status %#lx.\n", status );

    NtClose( no_query_token );
    NtClose( query_token );
}
