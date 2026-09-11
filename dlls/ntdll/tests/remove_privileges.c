/*
 * RtlRemovePrivileges tests
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

static NTSTATUS (WINAPI *remove_privileges)(HANDLE, const ULONG *, ULONG);

START_TEST(remove_privileges)
{
    ULONG invalid_keep = 37, valid_keep = 19;
    HANDLE query_only, adjust_only, token;
    NTSTATUS status;

    remove_privileges = (void *)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                                "RtlRemovePrivileges");
    if (!remove_privileges)
    {
        win_skip("RtlRemovePrivileges is not available.\n");
        return;
    }

    status = NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                                &token);
    ok(status == STATUS_SUCCESS, "NtOpenProcessToken returned %#lx.\n", status);
    if (status) return;

    status = remove_privileges(token, NULL, 1);
    ok(status == STATUS_INVALID_PARAMETER, "got status %#lx.\n", status);
    status = remove_privileges(token, &invalid_keep, 1);
    ok(status == STATUS_INVALID_PARAMETER, "got status %#lx.\n", status);

    status = NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &query_only);
    ok(status == STATUS_SUCCESS, "NtOpenProcessToken returned %#lx.\n", status);
    if (!status)
    {
        status = remove_privileges(query_only, NULL, 0);
        ok(status == STATUS_ACCESS_DENIED, "got status %#lx.\n", status);
        NtClose(query_only);
    }

    status = NtOpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &adjust_only);
    ok(status == STATUS_SUCCESS, "NtOpenProcessToken returned %#lx.\n", status);
    if (!status)
    {
        status = remove_privileges(adjust_only, &valid_keep, 1);
        ok(status == STATUS_ACCESS_DENIED, "got status %#lx.\n", status);
        NtClose(adjust_only);
    }

    status = remove_privileges((HANDLE)0xdead, &valid_keep, 1);
    ok(status == STATUS_INVALID_HANDLE, "got status %#lx.\n", status);
    NtClose(token);
}
