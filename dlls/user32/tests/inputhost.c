/* InputHost-facing private USER32 helpers.
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

typedef BOOL (WINAPI *create_activation_object_fn)(UINT, const ULONGLONG *, ULONGLONG *);
typedef BOOL (WINAPI *enable_mouse_in_pointer_for_window_fn)(HWND, BOOL);
typedef BOOL (WINAPI *enable_resize_layout_synchronization_fn)(HWND, BOOL);
typedef BOOL (WINAPI *is_resize_layout_synchronization_enabled_fn)(HWND);
typedef BOOL (WINAPI *internal_clip_cursor_fn)(HWND, BOOL);

static void test_create_activation_object(HMODULE module)
{
    create_activation_object_fn create_activation_object;
    ULONGLONG identity = 0x123456789abcdef0, activation_object = 0;
    BOOL ret;

    create_activation_object = (void *)GetProcAddress(module, (const char *)2633);
    ok(!!create_activation_object, "CreateActivationObject ordinal is unavailable.\n");
    if (!create_activation_object) return;

    ret = create_activation_object(1, &identity, &activation_object);
    ok(ret, "CreateActivationObject failed, error %lu.\n", GetLastError());
    ok(activation_object == identity, "got activation object %#I64x.\n", activation_object);

    SetLastError(0xdeadbeef);
    ret = create_activation_object(1, NULL, &activation_object);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
       "null identity returned %d, error %lu.\n", ret, GetLastError());

    SetLastError(0xdeadbeef);
    ret = create_activation_object(1, &identity, NULL);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
       "null output returned %d, error %lu.\n", ret, GetLastError());
}

static void test_window_helpers(HMODULE module)
{
    enable_mouse_in_pointer_for_window_fn enable_mouse_in_pointer_for_window;
    enable_resize_layout_synchronization_fn enable_resize_layout_synchronization;
    is_resize_layout_synchronization_enabled_fn is_resize_layout_synchronization_enabled;
    internal_clip_cursor_fn internal_clip_cursor;
    BOOL setting = FALSE;
    HWND hwnd;
    BOOL ret;

    internal_clip_cursor = (void *)GetProcAddress(module, (const char *)2534);
    enable_resize_layout_synchronization = (void *)GetProcAddress(module, (const char *)2615);
    is_resize_layout_synchronization_enabled = (void *)GetProcAddress(module, (const char *)2617);
    enable_mouse_in_pointer_for_window = (void *)GetProcAddress(module, (const char *)2656);
    ok(!!internal_clip_cursor, "InternalClipCursor ordinal is unavailable.\n");
    ok(!!enable_resize_layout_synchronization,
       "EnableResizeLayoutSynchronization ordinal is unavailable.\n");
    ok(!!is_resize_layout_synchronization_enabled,
       "IsResizeLayoutSynchronizationEnabled ordinal is unavailable.\n");
    ok(!!enable_mouse_in_pointer_for_window, "EnableMouseInPointerForWindow ordinal is unavailable.\n");
    if (!internal_clip_cursor || !enable_resize_layout_synchronization ||
        !is_resize_layout_synchronization_enabled || !enable_mouse_in_pointer_for_window) return;

    hwnd = CreateWindowExW(0, L"static", L"input-host", WS_OVERLAPPED,
                           0, 0, 100, 100, NULL, NULL, NULL, NULL);
    ok(!!hwnd, "CreateWindowExW failed, error %lu.\n", GetLastError());
    if (!hwnd) return;

    ret = enable_mouse_in_pointer_for_window(hwnd, TRUE);
    ok(ret, "EnableMouseInPointerForWindow failed, error %lu.\n", GetLastError());
    ok(!is_resize_layout_synchronization_enabled(hwnd), "resize synchronization is enabled by default.\n");
    ret = enable_resize_layout_synchronization(hwnd, TRUE);
    ok(ret, "enabling resize synchronization failed, error %lu.\n", GetLastError());
    ok(is_resize_layout_synchronization_enabled(hwnd), "resize synchronization was not enabled.\n");
    ret = enable_resize_layout_synchronization(hwnd, FALSE);
    ok(ret, "disabling resize synchronization failed, error %lu.\n", GetLastError());
    ok(!is_resize_layout_synchronization_enabled(hwnd), "resize synchronization was not disabled.\n");
    ret = internal_clip_cursor(hwnd, TRUE);
    ok(ret, "InternalClipCursor enable failed, error %lu.\n", GetLastError());
    ret = internal_clip_cursor(hwnd, FALSE);
    ok(ret, "InternalClipCursor disable failed, error %lu.\n", GetLastError());

    ret = SetWindowFeedbackSetting(hwnd, FEEDBACK_TOUCH_CONTACTVISUALIZATION,
                                   0, sizeof(setting), &setting);
    ok(ret, "SetWindowFeedbackSetting failed, error %lu.\n", GetLastError());
    DestroyWindow(hwnd);
}

START_TEST(inputhost)
{
    HMODULE module = GetModuleHandleW(L"user32.dll");

    if (!winetest_platform_is_wine)
    {
        win_skip("Wine compatibility fallbacks are implementation-specific.\n");
        return;
    }
    ok(!!module, "user32.dll is not loaded.\n");
    if (!module) return;
    test_create_activation_object(module);
    test_window_helpers(module);
}
