/*
 * KernelBase application-compatibility quirk policy tests
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

typedef BOOL (WINAPI *quirk_is_enabled_fn)(void *);

static void test_quirk_is_enabled(void)
{
    static const struct
    {
        ULONG_PTR id;
        BOOL enabled;
    }
    tests[] =
    {
        {0x200bb, TRUE},
        {0x30000, TRUE},
        {0x50000, TRUE},
        {0x90007, FALSE},
        {0x90008, TRUE},
    };
    quirk_is_enabled_fn quirk_is_enabled;
    unsigned int i;
    BOOL result;

    quirk_is_enabled = (void *)GetProcAddress( GetModuleHandleW( L"kernelbase.dll" ),
                                               "QuirkIsEnabled" );
    if (!quirk_is_enabled)
    {
        win_skip( "QuirkIsEnabled is unavailable.\n" );
        return;
    }

    for (i = 0; i < ARRAY_SIZE(tests); ++i)
    {
        SetLastError( 0x13579bdf );
        result = quirk_is_enabled( (void *)tests[i].id );
        ok( result == tests[i].enabled, "quirk %#Ix returned %d.\n", tests[i].id, result );
        ok( GetLastError() == 0x13579bdf, "quirk %#Ix changed last error to %#lx.\n",
            tests[i].id, GetLastError() );
    }
}

START_TEST(quirks)
{
    test_quirk_is_enabled();
}
