/*
 * Persisted-state location policy tests
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

static NTSTATUS (WINAPI *pRtlGetPersistedStateLocation)(const WCHAR *, const WCHAR *,
                                                        const WCHAR *, ULONG, WCHAR *,
                                                        ULONG, ULONG *);

START_TEST(persisted_state)
{
    static const WCHAR service_state[] = L"U:\\ServiceState";
    static const WCHAR registry_state[] = L"SYSTEM\\CurrentControlSet\\Services";
    WCHAR output[64];
    ULONG required;
    NTSTATUS status;

    pRtlGetPersistedStateLocation = (void *)GetProcAddress(
        GetModuleHandleA( "ntdll.dll" ), "RtlGetPersistedStateLocation" );
    if (!pRtlGetPersistedStateLocation)
    {
        win_skip( "RtlGetPersistedStateLocation is not available.\n" );
        return;
    }

    memset( output, 0xcc, sizeof(output) );
    required = 0xdeadbeef;
    status = pRtlGetPersistedStateLocation( L"Services", NULL, service_state, 2,
                                            output, sizeof(output), &required );
    ok( status == STATUS_INVALID_PARAMETER_4, "got status %#lx.\n", status );
    ok( required == 0xdeadbeef, "changed required size to %lu.\n", required );
    ok( output[0] == 0xcccc, "changed output to %#x.\n", output[0] );

    status = pRtlGetPersistedStateLocation( L"Services", NULL, NULL, 1,
                                            output, sizeof(output), &required );
    ok( status == STATUS_OBJECT_NAME_NOT_FOUND, "got status %#lx.\n", status );
    ok( required == 0xdeadbeef, "changed required size to %lu.\n", required );
    ok( output[0] == 0xcccc, "changed output to %#x.\n", output[0] );

    status = pRtlGetPersistedStateLocation( L"Services", NULL, service_state, 1,
                                            output, 0, &required );
    ok( status == STATUS_BUFFER_OVERFLOW, "got status %#lx.\n", status );
    ok( required == sizeof(service_state), "got required size %lu.\n", required );
    ok( output[0] == 0xcccc, "changed output to %#x.\n", output[0] );

    status = pRtlGetPersistedStateLocation( L"Services", NULL, service_state, 1,
                                            output, sizeof(service_state) - sizeof(WCHAR), &required );
    ok( status == STATUS_BUFFER_OVERFLOW, "got status %#lx.\n", status );
    ok( output[0] == 0xcccc, "changed output to %#x.\n", output[0] );

    status = pRtlGetPersistedStateLocation( L"Services", NULL, service_state, 1,
                                            output, sizeof(service_state), &required );
    ok( status == STATUS_SUCCESS, "got status %#lx.\n", status );
    ok( required == sizeof(service_state), "got required size %lu.\n", required );
    ok( !memcmp( output, service_state, sizeof(service_state) ), "wrong service path.\n" );

    memset( output, 0xcc, sizeof(output) );
    status = pRtlGetPersistedStateLocation( L"Services", NULL, registry_state, 0,
                                            output, sizeof(output), NULL );
    ok( status == STATUS_SUCCESS, "got status %#lx.\n", status );
    ok( !memcmp( output, registry_state, sizeof(registry_state) ), "wrong registry path.\n" );
}
