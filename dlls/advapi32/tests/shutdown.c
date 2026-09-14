/*
 * ADVAPI32 shutdown tests
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "windows.h"
#include "wine/test.h"

static DWORD (WINAPI *pCheckForHiberboot)(BOOLEAN *, BOOLEAN);

static void test_hiberboot(void)
{
    BOOLEAN hiberboot;
    DWORD ret;

    hiberboot = TRUE;
    SetLastError(0xdeadbeef);
    ret = pCheckForHiberboot(&hiberboot, FALSE);
    ok(ret == ERROR_SUCCESS, "got error %lu\n", ret);
    ok(!hiberboot, "expected a cold startup\n");
    ok(GetLastError() == 0xdeadbeef, "last error changed to %lu\n", GetLastError());

    hiberboot = TRUE;
    ret = pCheckForHiberboot(&hiberboot, TRUE);
    ok(ret == ERROR_SUCCESS, "got error %lu\n", ret);
    ok(!hiberboot, "expected a cold startup after refresh\n");
}

START_TEST(shutdown)
{
    HMODULE module = GetModuleHandleA("advapi32.dll");

    pCheckForHiberboot = (void *)GetProcAddress(module, "CheckForHiberboot");
    ok(!!pCheckForHiberboot, "CheckForHiberboot is not exported\n");
    if (pCheckForHiberboot) test_hiberboot();
}
