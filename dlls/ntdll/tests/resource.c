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

static const WCHAR expected_string[] = L"LinuxNT RtlLoadString";

static void test_load_string(void)
{
    NTSTATUS (WINAPI *load_string)(HMODULE, USHORT, const WCHAR *, ULONG,
                                   const WCHAR **, USHORT *, void *, void *);
    HMODULE ntdll = GetModuleHandleA( "ntdll.dll" );
    const WCHAR *string = (void *)0xdeadbeef;
    USHORT length = 0xdead;
    NTSTATUS status;

    load_string = (void *)GetProcAddress( ntdll, "RtlLoadString" );
    ok( !!load_string, "RtlLoadString is unavailable\n" );
    if (!load_string) return;

    status = load_string( GetModuleHandleW( NULL ), 0x1234, NULL, 0, &string, &length, NULL, NULL );
    ok( status == STATUS_SUCCESS, "got status %#lx\n", status );
    ok( length == ARRAY_SIZE(expected_string) - 1, "got length %u\n", length );
    ok( string && !memcmp( string, expected_string, sizeof(expected_string) - sizeof(WCHAR) ),
        "got string %s\n", debugstr_wn(string, length) );

    string = (void *)0xdeadbeef;
    length = 0xdead;
    status = load_string( GetModuleHandleW( NULL ), 0x1234, L"", 1, &string, &length, NULL, NULL );
    ok( status == STATUS_SUCCESS, "got status %#lx\n", status );
    ok( length == ARRAY_SIZE(expected_string) - 1, "got length %u\n", length );
    ok( string && !memcmp( string, expected_string, sizeof(expected_string) - sizeof(WCHAR) ),
        "got string %s\n", debugstr_wn(string, length) );

    status = load_string( NULL, 0x1234, NULL, 0, &string, &length, NULL, NULL );
    ok( status == STATUS_INVALID_PARAMETER, "got status %#lx\n", status );
    status = load_string( GetModuleHandleW( NULL ), 0x1234, NULL, 0, NULL, &length, NULL, NULL );
    ok( status == STATUS_INVALID_PARAMETER, "got status %#lx\n", status );
    status = load_string( GetModuleHandleW( NULL ), 0x1234, NULL, 2, &string, &length, NULL, NULL );
    ok( status == STATUS_INVALID_PARAMETER, "got status %#lx\n", status );
    status = load_string( GetModuleHandleW( NULL ), 0x1234, NULL, 1, &string, &length,
                          (void *)string, NULL );
    ok( status == STATUS_NOT_SUPPORTED, "got status %#lx\n", status );
}

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
    test_load_string();
    test_query_resource_policy();
}
