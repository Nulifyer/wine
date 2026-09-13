/*
 * Copyright 2026 Nulifyer
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

static void test_cleanup_flags(void)
{
    void (WINAPI *clear_cleanup_flag)(DWORD);
    void (WINAPI *set_cleanup_flag)(DWORD);
    HMODULE module;

    module = GetModuleHandleW(L"combase.dll");
    ok(!!module, "combase.dll is not loaded.\n");
    if (!module) return;

    clear_cleanup_flag = (void *)GetProcAddress(module, "ClearCleanupFlag");
    set_cleanup_flag = (void *)GetProcAddress(module, "SetCleanupFlag");
    ok(!!clear_cleanup_flag, "ClearCleanupFlag is not exported.\n");
    ok(!!set_cleanup_flag, "SetCleanupFlag is not exported.\n");
    if (!clear_cleanup_flag || !set_cleanup_flag) return;

    set_cleanup_flag(0x1);
    set_cleanup_flag(0x2);
    clear_cleanup_flag(0x1);
    clear_cleanup_flag(0x2);
}

START_TEST(cleanup)
{
    test_cleanup_flags();
}
