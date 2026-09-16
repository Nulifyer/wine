/*
 * AppModel application state tests
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
#include "winerror.h"
#include "wine/test.h"

static void test_open_state_unpackaged_identity(void)
{
    void *(WINAPI *open_state)(void);
    LONG (WINAPI *get_current_package_family_name)(UINT32 *, WCHAR *);
    UINT32 length = 0;
    unsigned int i;
    LONG status;
    void *state;

    open_state = (void *)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "OpenState");
    get_current_package_family_name = (void *)GetProcAddress(GetModuleHandleA("kernelbase.dll"),
                                                             "GetCurrentPackageFamilyName");
    if (!open_state || !get_current_package_family_name)
    {
        win_skip("OpenState is not available.\n");
        return;
    }

    SetLastError(0x0badf00d);
    status = get_current_package_family_name(&length, NULL);
    ok(status == APPMODEL_ERROR_NO_PACKAGE, "got package status %#lx.\n", status);
    ok(!length, "got package family length %u.\n", length);
    ok(GetLastError() == 0x0badf00d, "package query changed last error to %lu.\n", GetLastError());

    for (i = 0; i < 2; ++i)
    {
        SetLastError(0x13579bdf + i);
        state = open_state();
        ok(!state, "call %u returned state %p.\n", i, state);
        ok(GetLastError() == APPMODEL_ERROR_NO_PACKAGE, "call %u set last error to %lu.\n",
           i, GetLastError());
    }
}

START_TEST(appmodel_state)
{
    test_open_state_unpackaged_identity();
}
