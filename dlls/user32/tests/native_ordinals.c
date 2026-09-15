/*
 * Tests for current Windows private user32 ordinals
 *
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
#include "winuser.h"

#include "wine/test.h"

typedef BOOL (WINAPI *is_current_process_gdi_scaled_fn)(void);
typedef BOOL (WINAPI *enable_mouse_in_pointer_for_thread_fn)(void);

static void test_gdi_scaled_process(void)
{
    is_current_process_gdi_scaled_fn is_current_process_gdi_scaled;
    enable_mouse_in_pointer_for_thread_fn enable_mouse_in_pointer_for_thread;
    HMODULE module = GetModuleHandleW(L"user32.dll");
    BOOL ret;

    ok(!!module, "user32.dll is not loaded.\n");
    if (!module) return;

    is_current_process_gdi_scaled = (void *)GetProcAddress(module, (const char *)2565);
    enable_mouse_in_pointer_for_thread = (void *)GetProcAddress(module, (const char *)2561);
    ok(!!is_current_process_gdi_scaled, "Ordinal 2565 is unavailable.\n");
    ok(!!enable_mouse_in_pointer_for_thread, "Ordinal 2561 is unavailable.\n");
    if (!is_current_process_gdi_scaled) return;

    if (enable_mouse_in_pointer_for_thread)
    {
        ret = enable_mouse_in_pointer_for_thread();
        ok(ret, "EnableMouseInPointerForThread failed, error %lu.\n", GetLastError());
    }

    ret = is_current_process_gdi_scaled();
    ok(!ret, "Default process unexpectedly reports GDI scaling.\n");

    ret = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_UNAWARE_GDISCALED);
    ok(ret, "SetProcessDpiAwarenessContext failed, error %lu.\n", GetLastError());
    if (!ret) return;

    ret = is_current_process_gdi_scaled();
    ok(ret, "GDI-scaled process does not report GDI scaling.\n");
}

START_TEST(native_ordinals)
{
    test_gdi_scaled_process();
}
