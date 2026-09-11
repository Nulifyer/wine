/* Unit tests for LinuxNT boot status support.
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

START_TEST(boot_status)
{
    ULONG value, length;
    NTSTATUS status;

    value = 0xcccccccc;
    length = 0xdddddddd;
    status = RtlGetSystemBootStatus( 17, &value, sizeof(value), &length );
    ok( status == STATUS_SUCCESS, "got status %#lx\n", status );
    ok( value == 4, "got feature configuration state %lu\n", value );
    ok( length == sizeof(value), "got return length %lu\n", length );

    value = 0xcccccccc;
    length = 0xdddddddd;
    status = RtlGetSystemBootStatus( 17, &value, sizeof(value) - 1, &length );
    ok( status == STATUS_BUFFER_TOO_SMALL, "got status %#lx\n", status );
    ok( value == 0xcccccccc, "modified value to %#lx\n", value );
    ok( length == 0xdddddddd, "modified return length to %#lx\n", length );

    value = 0xcccccccc;
    status = RtlGetSystemBootStatus( 17, &value, sizeof(value) + 1, NULL );
    ok( status == STATUS_SUCCESS, "got status %#lx\n", status );
    ok( value == 4, "got feature configuration state %lu\n", value );

    status = RtlGetSystemBootStatus( 19, &value, sizeof(value), &length );
    ok( status == STATUS_INVALID_PARAMETER, "got status %#lx\n", status );

    status = RtlGetSystemBootStatus( 17, NULL, sizeof(value), &length );
    ok( status == STATUS_INVALID_PARAMETER, "got status %#lx\n", status );
}
