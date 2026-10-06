/*
 * Secure-setting queries with an unconfigured signed-policy store
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

START_TEST(security_policy)
{
    NTSTATUS (WINAPI *query)(const UNICODE_STRING *, const UNICODE_STRING *,
                            const UNICODE_STRING *, ULONG *, void *, ULONG *);
    UNICODE_STRING provider, key, name, empty;
    unsigned int i, j;

    query = (void *)GetProcAddress( GetModuleHandleA("ntdll.dll"), "NtQuerySecurityPolicy" );
    if (!query) { win_skip( "NtQuerySecurityPolicy is unavailable.\n" ); return; }
    RtlInitUnicodeString( &provider, L"LinuxNT.Unconfigured.20261006" );
    RtlInitUnicodeString( &key, L"MissingKey" );
    RtlInitUnicodeString( &name, L"MissingValue" );
    RtlInitUnicodeString( &empty, L"" );
    for (i = 0; i < 21; ++i)
    {
        ULONG type = 0xabababab, size = i == 1 || i == 12 || i == 15 ? 0 :
                                     i == 2 ? 1 : i == 20 ? ~0u : 32;
        ULONG initial_size = size;
        UNICODE_STRING modified = provider;
        const UNICODE_STRING *p = i == 3 ? &empty : i == 6 || i == 13 || i == 14 ? NULL : &modified;
        const UNICODE_STRING *k = i == 4 ? &empty : i == 7 ? NULL : &key;
        const UNICODE_STRING *n = i == 5 ? &empty : i == 8 ? NULL : &name;
        NTSTATUS status, expected = STATUS_NOT_FOUND;
        BYTE buffer[32];

        if (i == 16) modified.Length = 1;
        if (i == 17) modified.MaximumLength = 0;
        if (i == 18 || i == 19) modified.Buffer = NULL;
        if (i == 19) modified.Length = 0;
        if (i == 1 || (i >= 6 && i <= 8) || (i >= 12 && i <= 14)) expected = STATUS_INVALID_PARAMETER;
        if (i == 9 || i == 10 || i == 15 || i == 18 || i == 20) expected = STATUS_ACCESS_VIOLATION;
        memset( buffer, 0x5a, sizeof(buffer) );
        SetLastError( 0xdeadbeef );
        status = query( p, k, n, i == 9 || i == 13 || i == 15 ? NULL : &type,
                        i == 1 || i == 11 ? NULL : buffer, i == 10 || i == 14 ? NULL : &size );
        ok( status == expected, "case %u status %#lx expected %#lx.\n", i, status, expected );
        ok( type == 0xabababab && size == initial_size,
            "case %u changed outputs to %#lx, %lu.\n", i, type, size );
        ok( GetLastError() == 0xdeadbeef, "case %u changed last error to %#lx.\n", i, GetLastError() );
        for (j = 0; j < sizeof(buffer) && buffer[j] == 0x5a; ++j) {}
        ok( j == sizeof(buffer), "case %u changed value at byte %u.\n", i, j );
    }
}
