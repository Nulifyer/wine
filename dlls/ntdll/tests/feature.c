/*
 * Windows feature configuration query tests
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

struct rtl_feature_configuration
{
    ULONG feature_id;
    ULONG flags;
    ULONG variant_payload;
};

static NTSTATUS (WINAPI *pRtlQueryFeatureConfiguration)(ULONG, ULONG, ULONGLONG *,
                                                        struct rtl_feature_configuration *);

static void test_query_feature_configuration(void)
{
    struct rtl_feature_configuration configuration;
    ULONGLONG stamp;
    NTSTATUS status;

    if (!pRtlQueryFeatureConfiguration)
    {
        win_skip( "RtlQueryFeatureConfiguration is unavailable.\n" );
        return;
    }

    stamp = 0x1111222233334444;
    configuration = (struct rtl_feature_configuration){0x55556666, 0x77778888, 0x9999aaaa};
    SetLastError( 0x13579bdf );
    status = pRtlQueryFeatureConfiguration( 0x038419ca, 0, &stamp, &configuration );
    ok( status == STATUS_SUCCESS, "got status %#lx.\n", status );
    ok( stamp == 1, "got stamp %s.\n", wine_dbgstr_longlong(stamp) );
    ok( configuration.feature_id == 0x038419ca, "got feature %#lx.\n", configuration.feature_id );
    ok( configuration.flags == 0x2f, "got flags %#lx.\n", configuration.flags );
    ok( !configuration.variant_payload, "got payload %#lx.\n", configuration.variant_payload );
    ok( GetLastError() == 0x13579bdf, "last error changed to %#lx.\n", GetLastError() );

    stamp = 0x1111222233334444;
    configuration = (struct rtl_feature_configuration){0x55556666, 0x77778888, 0x9999aaaa};
    status = pRtlQueryFeatureConfiguration( 0x12345678, 1, &stamp, &configuration );
    ok( status == STATUS_NOT_FOUND, "got status %#lx.\n", status );
    ok( stamp == 1, "got stamp %s.\n", wine_dbgstr_longlong(stamp) );
    ok( configuration.feature_id == 0x55556666 && configuration.flags == 0x77778888 &&
        configuration.variant_payload == 0x9999aaaa, "configuration was modified.\n" );

    stamp = 0x1111222233334444;
    configuration = (struct rtl_feature_configuration){0x55556666, 0x77778888, 0x9999aaaa};
    status = pRtlQueryFeatureConfiguration( 0x038419ca, 2, &stamp, &configuration );
    ok( status == STATUS_INVALID_PARAMETER, "got status %#lx.\n", status );
    ok( stamp == 0x1111222233334444, "got stamp %s.\n", wine_dbgstr_longlong(stamp) );
    ok( configuration.feature_id == 0x55556666 && configuration.flags == 0x77778888 &&
        configuration.variant_payload == 0x9999aaaa, "configuration was modified.\n" );
}

START_TEST(feature)
{
    pRtlQueryFeatureConfiguration = (void *)GetProcAddress( GetModuleHandleA( "ntdll.dll" ),
                                                            "RtlQueryFeatureConfiguration" );
    test_query_feature_configuration();
}
