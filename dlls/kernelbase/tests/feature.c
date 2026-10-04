/*
 * KernelBase feature-staging tests
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "wine/test.h"

typedef void (WINAPI *log_staged_feature_usage_fn)(UINT32, UINT32, BYTE);

static void test_log_staged_feature_usage(void)
{
    log_staged_feature_usage_fn log_usage;
    unsigned int i;

    log_usage = (void *)GetProcAddress( GetModuleHandleW( L"kernelbase.dll" ),
                                        "LogStagedFeatureUsage" );
    if (!log_usage)
    {
        win_skip( "LogStagedFeatureUsage is unavailable.\n" );
        return;
    }

    for (i = 0; i < 5; ++i)
    {
        SetLastError( 0x13570000 + i );
        log_usage( 0x12345678, 9, i );
        ok( GetLastError() == 0x13570000 + i,
            "reporting kind %u changed last error to %#lx.\n", i, GetLastError() );
    }
}

START_TEST(feature)
{
    test_log_staged_feature_usage();
}
