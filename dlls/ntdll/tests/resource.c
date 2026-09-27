/* Unit tests for NTDLL resource policy support.
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

static void test_query_resource_policy(void)
{
    NTSTATUS (WINAPI *query_resource_policy)(ULONG, ULONG, ULONG *, SIZE_T);
    HMODULE ntdll = GetModuleHandleA( "ntdll.dll" );
    ULONG policy;
    NTSTATUS status;

    query_resource_policy = (void *)GetProcAddress( ntdll, "RtlQueryResourcePolicy" );
    ok( !!query_resource_policy, "RtlQueryResourcePolicy is unavailable\n" );
    if (!query_resource_policy) return;

    policy = 0xdeadbeef;
    status = query_resource_policy( 2, 0, &policy, sizeof(policy) );
    ok( status == STATUS_SUCCESS, "got status %#lx\n", status );
    ok( policy == 10, "got disk speed policy %lu\n", policy );

    status = query_resource_policy( 2, 0, NULL, sizeof(policy) );
    ok( status == STATUS_INVALID_PARAMETER, "got status %#lx\n", status );
    status = query_resource_policy( 2, 1, &policy, sizeof(policy) );
    ok( status == STATUS_INVALID_PARAMETER, "got status %#lx\n", status );
    status = query_resource_policy( 2, 0, &policy, sizeof(policy) - 1 );
    ok( status == STATUS_INVALID_PARAMETER, "got status %#lx\n", status );
    status = query_resource_policy( 4, 0, &policy, sizeof(policy) );
    ok( status == STATUS_INVALID_INFO_CLASS, "got status %#lx\n", status );
}

START_TEST(resource)
{
    test_query_resource_policy();
}
