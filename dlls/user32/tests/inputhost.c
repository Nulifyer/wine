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

struct activation_object_data
{
    LUID luid;
    HWND hwnd;
    ULONGLONG cookie;
    UINT state;
    DWORD process_id;
    DWORD thread_id;
};

typedef BOOL (WINAPI *configure_activation_object_fn)(const LUID *, UINT, UINT, UINT, UINT);
typedef BOOL (WINAPI *create_activation_object_fn)(HWND, const ULONGLONG *, LUID *);
typedef BOOL (WINAPI *destroy_activation_object_fn)(const LUID *);
typedef BOOL (WINAPI *query_activation_object_fn)(const LUID *, struct activation_object_data *);
typedef BOOL (WINAPI *set_activation_object_redirection_fn)(const LUID *, const LUID *);
typedef BOOL (WINAPI *enable_mouse_in_pointer_for_window_fn)(HWND, BOOL);
typedef BOOL (WINAPI *enable_resize_layout_synchronization_fn)(HWND, BOOL);
typedef BOOL (WINAPI *is_resize_layout_synchronization_enabled_fn)(HWND);
typedef BOOL (WINAPI *internal_clip_cursor_fn)(HWND, BOOL);

static BOOL luid_equal(const LUID *left, const LUID *right)
{
    return left->LowPart == right->LowPart && left->HighPart == right->HighPart;
}

struct activation_thread_context
{
    create_activation_object_fn create;
    ULONGLONG cookie;
    LUID luid;
    BOOL ret;
};

struct activation_destroy_context
{
    destroy_activation_object_fn destroy;
    LUID luid;
    BOOL ret;
    DWORD error;
};

static DWORD WINAPI create_activation_object_thread(void *arg)
{
    struct activation_thread_context *context = arg;
    HWND hwnd;

    hwnd = CreateWindowExW(0, L"static", L"activation-thread", WS_OVERLAPPED,
                           0, 0, 100, 100, NULL, NULL, NULL, NULL);
    context->ret = context->create(hwnd, &context->cookie, &context->luid);
    DestroyWindow(hwnd);
    return 0;
}

static DWORD WINAPI destroy_activation_object_thread(void *arg)
{
    struct activation_destroy_context *context = arg;

    SetLastError(0xdeadbeef);
    context->ret = context->destroy(&context->luid);
    context->error = GetLastError();
    return 0;
}

static void test_activation_objects(HMODULE module)
{
    configure_activation_object_fn configure;
    create_activation_object_fn create;
    destroy_activation_object_fn destroy;
    query_activation_object_fn query;
    set_activation_object_redirection_fn set_redirection;
    struct activation_thread_context thread_context = {0};
    struct activation_destroy_context destroy_context = {0};
    struct activation_object_data data;
    ULONGLONG cookie = 0x123456789abcdef0;
    LUID cookie_luid = {0x9abcdef0, 0x12345678};
    LUID first = {0}, second = {0}, missing = {0xdeadbeef, 0x12345678}, zero = {0};
    HANDLE thread;
    HWND hwnd;
    BOOL ret;

    create = (void *)GetProcAddress(module, (const char *)2633);
    configure = (void *)GetProcAddress(module, (const char *)2647);
    destroy = (void *)GetProcAddress(module, (const char *)2648);
    set_redirection = (void *)GetProcAddress(module, "SetForegroundRedirectionForActivationObject");
    query = (void *)GetProcAddress(GetModuleHandleW(L"win32u.dll"), "NtUserQueryActivationObject");
    ok(!!create, "CreateActivationObject ordinal is unavailable.\n");
    ok(!!configure, "ConfigureActivationObject ordinal is unavailable.\n");
    ok(!!destroy, "DestroyActivationObject ordinal is unavailable.\n");
    ok(!!set_redirection, "SetForegroundRedirectionForActivationObject is unavailable.\n");
    ok(!!query, "NtUserQueryActivationObject is unavailable.\n");
    if (!create || !configure || !destroy || !set_redirection || !query) return;

    hwnd = CreateWindowExW(0, L"static", L"activation-owner", WS_OVERLAPPED,
                           0, 0, 100, 100, NULL, NULL, NULL, NULL);
    ok(!!hwnd, "CreateWindowExW failed, error %lu.\n", GetLastError());
    if (!hwnd) return;

    SetLastError(0xdeadbeef);
    ret = create(hwnd, &cookie, &first);
    ok(ret, "CreateActivationObject failed, error %lu.\n", GetLastError());
    ok(GetLastError() == 0xdeadbeef, "success changed error to %lu.\n", GetLastError());
    ok(first.LowPart || first.HighPart, "CreateActivationObject returned a zero LUID.\n");
    ok(!luid_equal(&first, &cookie_luid), "activation LUID copied the cookie.\n");

    memset(&data, 0xcc, sizeof(data));
    ret = query(&first, &data);
    ok(ret, "query failed, error %lu.\n", GetLastError());
    ok(luid_equal(&data.luid, &first), "query returned a different LUID.\n");
    ok(data.hwnd == hwnd, "query returned hwnd %p, expected %p.\n", data.hwnd, hwnd);
    ok(data.cookie == cookie, "query returned cookie %#I64x.\n", data.cookie);
    ok(data.state == 1, "initial state is %#x.\n", data.state);
    ok(data.process_id == GetCurrentProcessId(), "query returned process %lu.\n", data.process_id);
    ok(data.thread_id == GetCurrentThreadId(), "query returned thread %lu.\n", data.thread_id);

    ret = create(hwnd, &cookie, &second);
    ok(ret, "second create failed, error %lu.\n", GetLastError());
    ok(!luid_equal(&first, &second), "separate activation objects reused one LUID.\n");

    ret = configure(&first, 0, 0, 2, 2);
    ok(ret, "setting suppress-spatial failed, error %lu.\n", GetLastError());
    ret = configure(&first, 0, 1, 2, 2);
    ok(ret, "foreground-authorized configuration failed, error %lu.\n", GetLastError());
    ret = query(&first, &data);
    ok(ret && data.state == 3, "state after configure is %#x, error %lu.\n", data.state, GetLastError());
    ret = configure(&first, 2, 0, 1, 1);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
       "invalid reason returned %d, error %lu.\n", ret, GetLastError());
    ret = configure(&first, 0, 2, 1, 1);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
       "invalid behavior returned %d, error %lu.\n", ret, GetLastError());
    ret = configure(&first, 1, 0, 1, 1);
    ok(!ret && GetLastError() == ERROR_ACCESS_DENIED,
       "ordinary DWM reason returned %d, error %lu.\n", ret, GetLastError());

    ret = configure(&first, 0, 0, 1, 0);
    ok(ret, "disabling failed, error %lu.\n", GetLastError());
    ret = configure(&first, 0, 0, 4, 4);
    ok(!ret, "disabled object became foreground.\n");
    ret = configure(&first, 0, 0, 7, 5);
    ok(ret, "enabling foreground failed, error %lu.\n", GetLastError());
    ret = query(&first, &data);
    ok(ret && data.state == 5, "foreground state is %#x, error %lu.\n", data.state, GetLastError());

    ret = set_redirection(&first, &second);
    ok(ret, "foreground redirection failed, error %lu.\n", GetLastError());
    ret = query(&first, &data);
    ok(ret && !(data.state & 4), "redirected source remained foreground, state %#x.\n", data.state);
    ret = query(&second, &data);
    ok(ret && (data.state & 4), "redirect target did not become foreground, state %#x.\n", data.state);
    ret = set_redirection(&first, &zero);
    ok(ret, "clearing foreground redirection failed, error %lu.\n", GetLastError());
    ret = set_redirection(&first, &missing);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
       "missing redirect target returned %d, error %lu.\n", ret, GetLastError());

    destroy_context.destroy = destroy;
    destroy_context.luid = first;
    thread = CreateThread(NULL, 0, destroy_activation_object_thread, &destroy_context, 0, NULL);
    ok(!!thread, "CreateThread failed, error %lu.\n", GetLastError());
    if (thread)
    {
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
        ok(!destroy_context.ret && destroy_context.error == ERROR_ACCESS_DENIED,
           "cross-thread destroy returned %d, error %lu.\n",
           destroy_context.ret, destroy_context.error);
        ret = query(&first, &data);
        ok(ret, "cross-thread destroy removed the object, error %lu.\n", GetLastError());
    }

    thread_context.create = create;
    thread_context.cookie = cookie + 1;
    thread = CreateThread(NULL, 0, create_activation_object_thread, &thread_context, 0, NULL);
    ok(!!thread, "CreateThread failed, error %lu.\n", GetLastError());
    if (thread)
    {
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
        ok(thread_context.ret, "worker CreateActivationObject failed.\n");
        ret = query(&thread_context.luid, &data);
        ok(!ret && GetLastError() == ERROR_NOT_FOUND,
           "thread-owned object survived thread exit, ret %d error %lu.\n", ret, GetLastError());
        ret = destroy(&thread_context.luid);
        ok(ret, "destroying an already-cleaned object failed, error %lu.\n", GetLastError());
    }

    SetLastError(0xdeadbeef);
    ret = create(hwnd, NULL, &first);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
       "null cookie returned %d, error %lu.\n", ret, GetLastError());

    SetLastError(0xdeadbeef);
    ret = create(hwnd, &cookie, NULL);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
       "null output returned %d, error %lu.\n", ret, GetLastError());

    ret = destroy(&second);
    ok(ret, "destroying second object failed, error %lu.\n", GetLastError());
    ret = destroy(&second);
    ok(ret, "repeated destroy failed, error %lu.\n", GetLastError());
    ret = configure(&second, 0, 0, 1, 1);
    ok(!ret && GetLastError() == ERROR_NOT_FOUND,
       "configure after destroy returned %d, error %lu.\n", ret, GetLastError());
    ret = destroy(&first);
    ok(ret, "destroying first object failed, error %lu.\n", GetLastError());
    DestroyWindow(hwnd);
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
    test_activation_objects(module);
    test_window_helpers(module);
}
