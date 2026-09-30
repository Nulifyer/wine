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
#include <stdio.h>
#include <string.h>

#include "windef.h"
#include "winbase.h"
#include "winuser.h"

#include "wine/test.h"

typedef BOOL (WINAPI *is_current_process_gdi_scaled_fn)(void);
typedef BOOL (WINAPI *enable_mouse_in_pointer_for_thread_fn)(void);
typedef BOOL (WINAPI *get_process_ui_context_information_fn)(HANDLE, void *);
typedef BOOL (WINAPI *is_immersive_process_fn)(HANDLE);
typedef BOOL (WINAPI *get_current_dpi_info_for_window_fn)(HWND, void *);
typedef BOOL (WINAPI *get_current_dpi_info_fn)(HMONITOR, void *);
typedef BOOL (WINAPI *is_thread_desktop_composited_fn)(void);
typedef void (WINAPI *internal_enum_desktop_windows_fn)(HDESK, WNDENUMPROC, LPARAM);
typedef void (WINAPI *internal_enum_child_windows_fn)(HWND, WNDENUMPROC, LPARAM);
typedef BOOL (WINAPI *broadcast_theme_change_event_fn)(DWORD, LONG);
typedef DWORD (WINAPI *get_queue_status_readonly_fn)(UINT);
typedef BOOL (WINAPI *register_user_api_hook_fn)(const struct user_api_hook_descriptor *);
typedef BOOL (WINAPI *register_dmanip_hook_fn)(void);
typedef BOOL (WINAPI *init_dmanip_hook_ex_fn)(BOOL);
typedef BOOL (WINAPI *set_core_window_fn)(HWND, BOOL);
typedef BOOL (WINAPI *is_core_window_fn)(HWND);
struct composition_attribute_data
{
    int attribute;
    void *data;
    SIZE_T size;
};
typedef BOOL (WINAPI *get_window_composition_attribute_fn)(HWND, struct composition_attribute_data *);
typedef BOOL (WINAPI *set_window_composition_attribute_fn)(HWND, struct composition_attribute_data *);
typedef INT (WINAPI *schedule_dispatch_notification_fn)(HWND);
typedef UINT_PTR (WINAPI *delegate_input_fn)(DWORD, void *, void *, HWND, UINT, void *);
typedef BOOL (WINAPI *undelegate_input_fn)(HWND, UINT);
typedef void (CDECL *window_services_destroy_callback)(HWND);
typedef BOOL (WINAPI *set_window_services_destroy_callback_fn)(HWND, window_services_destroy_callback);
typedef BOOL (WINAPI *report_inertia_fn)(ULONG_PTR, UINT, HWND, const void *, const void *);
typedef BOOL (WINAPI *force_enable_numpad_translation_fn)(BOOL);
typedef UINT (WINAPI *get_window_dpi_fn)(HWND);

static get_process_ui_context_information_fn pGetProcessUIContextInformation;
static is_immersive_process_fn pIsImmersiveProcess;
static set_window_services_destroy_callback_fn pSetWindowServicesDestroyCallback;

#define WM_WINDOW_SERVICES_DESTROY 0x0272

static const WCHAR window_services_class[] = L"WineWindowServicesDestroy";
static unsigned int window_services_events[16], window_services_event_count;
static unsigned int callback_a_count, callback_b_count;
static HWND callback_target, thread_window;
static BOOL callback_window_matches = TRUE, callback_window_valid = TRUE;
static BOOL thread_registration_ret;
static DWORD thread_registration_error;
static HWND enum_target, enum_child, enum_grandchild;
static unsigned int enum_count;
static BOOL enum_saw_target, enum_saw_child, enum_saw_grandchild;
static unsigned int theme_change_count;
static WPARAM theme_change_wparam;
static LPARAM theme_change_lparam;
static unsigned int dispatch_notification_count;
static WPARAM dispatch_notification_wparam;
static LPARAM dispatch_notification_lparam;
static HANDLE input_delegate_ready, input_delegate_stop, input_delegate_called;
static DWORD input_delegate_tid, input_delegate_callback_tid;
static HWND input_delegate_target, input_delegate_callback_hwnd;
static void *input_delegate_callback_context;
static UINT input_delegate_callback_message, input_delegate_option;
static unsigned int input_delegate_callback_count, input_delegate_target_count;

struct test_inertia_info
{
    float velocity_x;
    float velocity_y;
    UINT source;
};

struct test_inertia_region
{
    RECT rect;
    float transform[6];
};

struct numpad_translation_thread_params
{
    force_enable_numpad_translation_fn function;
    BOOL first_previous;
    BOOL second_previous;
};

static DWORD WINAPI numpad_translation_thread(void *arg)
{
    struct numpad_translation_thread_params *params = arg;

    params->first_previous = params->function(TRUE);
    params->second_previous = params->function(FALSE);
    return 0;
}

static void test_force_enable_numpad_translation(HMODULE module)
{
    force_enable_numpad_translation_fn function =
        (void *)GetProcAddress(module, (const char *)2600);
    struct numpad_translation_thread_params params = {0};
    HANDLE thread;
    BOOL previous;

    ok(!!function, "ForceEnableNumpadTranslation ordinal is unavailable.\n");
    if (!function) return;

    previous = function(FALSE);
    ok(!previous, "initial disable returned previous state %d.\n", previous);
    previous = function(TRUE);
    ok(!previous, "first enable returned previous state %d.\n", previous);
    previous = function(TRUE);
    ok(previous, "repeated enable returned previous state %d.\n", previous);
    previous = function(2);
    ok(previous, "noncanonical disable returned previous state %d.\n", previous);
    previous = function(FALSE);
    ok(!previous, "noncanonical disable retained state %d.\n", previous);
    previous = function(TRUE);
    ok(!previous, "enable after noncanonical disable returned previous state %d.\n", previous);

    params.function = function;
    thread = CreateThread(NULL, 0, numpad_translation_thread, &params, 0, NULL);
    ok(!!thread, "failed to create numpad translation thread, error %lu.\n", GetLastError());
    if (thread)
    {
        ok(WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0,
           "numpad translation thread did not exit.\n");
        CloseHandle(thread);
        ok(!params.first_previous, "new thread inherited state %d.\n", params.first_previous);
        ok(params.second_previous, "new thread did not retain enabled state %d.\n",
           params.second_previous);
    }

    previous = function(FALSE);
    ok(previous, "main thread lost enabled state %d.\n", previous);
    previous = function(FALSE);
    ok(!previous, "repeated disable returned previous state %d.\n", previous);
}

static void test_get_window_dpi(HMODULE module)
{
    get_window_dpi_fn get_window_dpi = (void *)GetProcAddress(module, (const char *)2707);
    HWND desktop = GetDesktopWindow();
    UINT dpi;

    ok(!!get_window_dpi, "GetWindowDPI ordinal is unavailable.\n");
    if (!get_window_dpi) return;

    SetLastError(0xdeadbeef);
    dpi = get_window_dpi(NULL);
    ok(!dpi, "null window returned %u.\n", dpi);
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "null window error %lu.\n", GetLastError());

    SetLastError(0xdeadbeef);
    dpi = get_window_dpi((HWND)0xdeadbeef);
    ok(!dpi, "invalid window returned %u.\n", dpi);
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "invalid window error %lu.\n", GetLastError());

    SetLastError(0xdeadbeef);
    dpi = get_window_dpi(desktop);
    ok(dpi == GetDpiForWindow(desktop), "desktop returned %u.\n", dpi);
    ok(GetLastError() == 0xdeadbeef, "desktop changed last error to %lu.\n", GetLastError());
}

static void test_report_inertia(HMODULE module)
{
    report_inertia_fn report_inertia = (void *)GetProcAddress(module, (const char *)2551);
    struct test_inertia_info info = {3.0f, 4.0f, 1};
    struct test_inertia_region region = {{0, 0, 100, 100}, {1.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f}};
    BOOL ret;

    ok(!!report_inertia, "ReportInertia ordinal is unavailable.\n");
    if (!report_inertia || !winetest_platform_is_wine) return;

    SetLastError(0xdeadbeef);
    ret = report_inertia(0, 5, NULL, &info, &region);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
       "zero identity returned %d, error %lu.\n", ret, GetLastError());

    SetLastError(0xdeadbeef);
    ret = report_inertia(0x1234, 0, NULL, &info, &region);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
       "missing operation returned %d, error %lu.\n", ret, GetLastError());

    SetLastError(0xdeadbeef);
    ret = report_inertia(0x1234, 3, NULL, &info, &region);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
       "combined operation returned %d, error %lu.\n", ret, GetLastError());

    info.velocity_x = info.velocity_y = 0.0f;
    SetLastError(0xdeadbeef);
    ret = report_inertia(0x1234, 5, NULL, &info, &region);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
       "zero velocity returned %d, error %lu.\n", ret, GetLastError());

    info.velocity_x = 3.0f;
    info.velocity_y = 4.0f;
    ret = report_inertia(0x1234, 5, NULL, &info, &region);
    ok(ret, "start failed, error %lu.\n", GetLastError());

    SetLastError(0xdeadbeef);
    ret = report_inertia(0x1234, 5, NULL, &info, &region);
    ok(!ret && GetLastError() == ERROR_ACCESS_DENIED,
       "weaker duplicate returned %d, error %lu.\n", ret, GetLastError());

    info.velocity_x = 1.0f;
    info.velocity_y = 0.0f;
    ret = report_inertia(0x1234, 13, NULL, &info, &region);
    ok(ret, "explicit replacement failed, error %lu.\n", GetLastError());

    ret = report_inertia(0x1234, 6, NULL, NULL, NULL);
    ok(ret, "stop failed, error %lu.\n", GetLastError());

    SetLastError(0xdeadbeef);
    ret = report_inertia(0x1234, 6, NULL, NULL, NULL);
    ok(!ret && GetLastError() == ERROR_ACCESS_DENIED,
       "second stop returned %d, error %lu.\n", ret, GetLastError());
}

static UINT_PTR WINAPI input_delegate_callback(MSG *message, void *context)
{
    input_delegate_callback_count++;
    input_delegate_callback_tid = GetCurrentThreadId();
    input_delegate_callback_hwnd = message->hwnd;
    input_delegate_callback_message = message->message;
    input_delegate_callback_context = context;
    SetEvent(input_delegate_called);
    return input_delegate_option;
}

static LRESULT WINAPI input_delegate_target_proc(HWND hwnd, UINT message, WPARAM wparam,
                                                  LPARAM lparam)
{
    if (message == WM_LBUTTONDOWN) input_delegate_target_count++;
    return DefWindowProcW(hwnd, message, wparam, lparam);
}

static DWORD WINAPI input_delegate_thread(void *param)
{
    MSG message;
    DWORD wait;

    input_delegate_tid = GetCurrentThreadId();
    PeekMessageW(&message, NULL, 0, 0, PM_NOREMOVE);
    SetEvent(input_delegate_ready);
    for (;;)
    {
        wait = MsgWaitForMultipleObjects(1, &input_delegate_stop, FALSE, 10000, QS_ALLINPUT);
        if (wait == WAIT_OBJECT_0) break;
        if (wait != WAIT_OBJECT_0 + 1) continue;
        while (PeekMessageW(&message, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    return 0;
}

static void send_input_delegate_click(HWND window)
{
    INPUT inputs[2] = {0};
    RECT rect;

    GetWindowRect(window, &rect);
    SetCursorPos((rect.left + rect.right) / 2, (rect.top + rect.bottom) / 2);
    inputs[0].type = INPUT_MOUSE;
    inputs[0].mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
    inputs[1].type = INPUT_MOUSE;
    inputs[1].mi.dwFlags = MOUSEEVENTF_LEFTUP;
    ok(SendInput(ARRAY_SIZE(inputs), inputs, sizeof(inputs[0])) == ARRAY_SIZE(inputs),
       "SendInput failed, error %lu.\n", GetLastError());
}

static void test_input_delegation(HMODULE module)
{
    static const WCHAR class_name[] = L"WineInputDelegation";
    static const UINT delegation_flags = QS_MOUSEBUTTON;
    delegate_input_fn delegate_input;
    undelegate_input_fn undelegate_input;
    WNDCLASSW class = {0};
    HANDLE thread = NULL;
    MSG message;
    DWORD wait;
    UINT_PTR result;
    BOOL ret;

    delegate_input = (void *)GetProcAddress(module, (const char *)2503);
    undelegate_input = (void *)GetProcAddress(module, (const char *)2504);
    ok(!!delegate_input && !!undelegate_input, "input-delegation ordinals are unavailable.\n");
    if (!delegate_input || !undelegate_input) return;

    class.lpfnWndProc = input_delegate_target_proc;
    class.hInstance = GetModuleHandleW(NULL);
    class.lpszClassName = class_name;
    ok(RegisterClassW(&class), "RegisterClassW failed, error %lu.\n", GetLastError());
    input_delegate_target = CreateWindowExW(0, class_name, NULL, WS_POPUP | WS_VISIBLE,
                                             100, 100, 160, 120, NULL, NULL,
                                             class.hInstance, NULL);
    ok(!!input_delegate_target, "failed to create input target, error %lu.\n", GetLastError());
    if (!input_delegate_target) return;
    UpdateWindow(input_delegate_target);

    input_delegate_ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    input_delegate_stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    input_delegate_called = CreateEventW(NULL, FALSE, FALSE, NULL);
    ok(!!input_delegate_ready && !!input_delegate_stop && !!input_delegate_called,
       "failed to create input-delegation events, error %lu.\n", GetLastError());
    if (!input_delegate_ready || !input_delegate_stop || !input_delegate_called) goto done;

    thread = CreateThread(NULL, 0, input_delegate_thread, NULL, 0, NULL);
    ok(!!thread, "failed to create input-delegate thread, error %lu.\n", GetLastError());
    if (!thread) goto done;
    wait = WaitForSingleObject(input_delegate_ready, 10000);
    ok(wait == WAIT_OBJECT_0, "input-delegate thread was not ready, wait %#lx.\n", wait);
    if (wait != WAIT_OBJECT_0) goto done;

    SetLastError(0x13579bdf);
    result = delegate_input(input_delegate_tid, input_delegate_callback, (void *)0x12345678,
                            input_delegate_target, 0, NULL);
    ok(!result && GetLastError() == ERROR_INVALID_PARAMETER,
       "zero flags returned %Ix, error %lu.\n", result, GetLastError());

    SetLastError(0x13579bdf);
    result = delegate_input(GetCurrentThreadId(), input_delegate_callback, (void *)0x12345678,
                            input_delegate_target, delegation_flags, NULL);
    ok(!result && GetLastError() == ERROR_ACCESS_DENIED,
       "same-thread delegation returned %Ix, error %lu.\n", result, GetLastError());

    ok(AttachThreadInput(input_delegate_tid, GetCurrentThreadId(), TRUE),
       "AttachThreadInput failed, error %lu.\n", GetLastError());
    SetLastError(0x13579bdf);
    result = delegate_input(input_delegate_tid, input_delegate_callback, (void *)0x12345678,
                            input_delegate_target, delegation_flags, NULL);
    ok(!result && GetLastError() == ERROR_ACCESS_DENIED,
       "attached-thread delegation returned %Ix, error %lu.\n", result, GetLastError());
    ok(AttachThreadInput(input_delegate_tid, GetCurrentThreadId(), FALSE),
       "AttachThreadInput detach failed, error %lu.\n", GetLastError());

    SetLastError(0x13579bdf);
    result = delegate_input(input_delegate_tid, input_delegate_callback, (void *)0x12345678,
                            input_delegate_target, delegation_flags, NULL);
    ok(result && GetLastError() == 0x13579bdf,
       "delegation returned %Ix, error %lu.\n", result, GetLastError());

    SetLastError(0x13579bdf);
    result = delegate_input(input_delegate_tid, input_delegate_callback, (void *)0x12345678,
                            input_delegate_target, delegation_flags, NULL);
    ok(!result && GetLastError() == ERROR_ALREADY_EXISTS,
       "duplicate delegation returned %Ix, error %lu.\n", result, GetLastError());

    input_delegate_callback_count = input_delegate_target_count = 0;
    input_delegate_option = 2;
    send_input_delegate_click(input_delegate_target);
    wait = WaitForSingleObject(input_delegate_called, 10000);
    ok(wait == WAIT_OBJECT_0, "release callback was not called, wait %#lx.\n", wait);
    for (wait = 0; wait < 100 && input_delegate_callback_count < 2; wait++) Sleep(10);
    ok(input_delegate_callback_tid == input_delegate_tid,
       "callback ran on thread %lu instead of %lu.\n",
       input_delegate_callback_tid, input_delegate_tid);
    ok(input_delegate_callback_hwnd == input_delegate_target,
       "callback received hwnd %p instead of %p.\n",
       input_delegate_callback_hwnd, input_delegate_target);
    ok(input_delegate_callback_context == (void *)0x12345678,
       "callback received context %p.\n", input_delegate_callback_context);
    ok(input_delegate_callback_message == WM_LBUTTONDOWN ||
       input_delegate_callback_message == WM_LBUTTONUP,
       "callback received message %#x.\n", input_delegate_callback_message);
    while (PeekMessageW(&message, NULL, 0, 0, PM_REMOVE))
    {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    ok(!input_delegate_target_count, "released input reached the target %u times.\n",
       input_delegate_target_count);

    input_delegate_option = 1;
    ResetEvent(input_delegate_called);
    send_input_delegate_click(input_delegate_target);
    wait = WaitForSingleObject(input_delegate_called, 10000);
    ok(wait == WAIT_OBJECT_0, "reassign callback was not called, wait %#lx.\n", wait);
    for (wait = 0; wait < 200 && !input_delegate_target_count; wait++)
    {
        while (PeekMessageW(&message, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        Sleep(10);
    }
    ok(input_delegate_target_count != 0, "reassigned input did not reach the target.\n");

    SetLastError(0x13579bdf);
    ret = undelegate_input(input_delegate_target, 3);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
       "invalid undelegate returned %d, error %lu.\n", ret, GetLastError());
    SetLastError(0x13579bdf);
    ret = undelegate_input(input_delegate_target, 2);
    ok(ret && GetLastError() == 0x13579bdf,
       "undelegate returned %d, error %lu.\n", ret, GetLastError());
    SetLastError(0x13579bdf);
    ret = undelegate_input(input_delegate_target, 2);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
       "repeated undelegate returned %d, error %lu.\n", ret, GetLastError());

done:
    if (input_delegate_stop) SetEvent(input_delegate_stop);
    if (thread)
    {
        WaitForSingleObject(thread, 10000);
        CloseHandle(thread);
    }
    if (input_delegate_called) CloseHandle(input_delegate_called);
    if (input_delegate_stop) CloseHandle(input_delegate_stop);
    if (input_delegate_ready) CloseHandle(input_delegate_ready);
    input_delegate_called = input_delegate_stop = input_delegate_ready = NULL;
    if (input_delegate_target) DestroyWindow(input_delegate_target);
    input_delegate_target = NULL;
    UnregisterClassW(class_name, class.hInstance);
}

static LRESULT WINAPI dispatch_notification_proc(HWND hwnd, UINT message, WPARAM wparam,
                                                 LPARAM lparam)
{
    if (message == 0x60)
    {
        dispatch_notification_count++;
        dispatch_notification_wparam = wparam;
        dispatch_notification_lparam = lparam;
        return 0;
    }
    return DefWindowProcW(hwnd, message, wparam, lparam);
}

static void test_schedule_dispatch_notification(HMODULE module)
{
    static const WCHAR class_name[] = L"WineScheduleDispatchNotification";
    schedule_dispatch_notification_fn function;
    WNDCLASSW class = {0};
    MSG message;
    HWND window;
    INT ret;

    function = (void *)GetProcAddress(module, (const char *)2582);
    ok(!!function, "Ordinal 2582 is unavailable.\n");
    if (!function) return;

    class.lpfnWndProc = dispatch_notification_proc;
    class.hInstance = GetModuleHandleW(NULL);
    class.lpszClassName = class_name;
    ok(RegisterClassW(&class), "RegisterClassW failed, error %lu.\n", GetLastError());

    window = CreateWindowExW(0, class_name, NULL, WS_POPUP, 0, 0, 32, 32,
                             NULL, NULL, class.hInstance, NULL);
    ok(!!window, "failed to create dispatch window, error %lu.\n", GetLastError());
    if (!window) return;

    SetLastError(0x13579bdf);
    ret = function(NULL);
    ok(!ret && GetLastError() == ERROR_INVALID_WINDOW_HANDLE,
       "null HWND returned %d, error %lu.\n", ret, GetLastError());

    dispatch_notification_count = 0;
    dispatch_notification_wparam = 1;
    dispatch_notification_lparam = 1;
    SetLastError(0x13579bdf);
    ret = function(window);
    ok(ret == 2, "dispatch schedule returned %d, error %lu.\n", ret, GetLastError());
    ok(!dispatch_notification_count, "notification was delivered synchronously.\n");

    PeekMessageW(&message, NULL, 0, 0, PM_NOREMOVE);
    ok(dispatch_notification_count == 1, "received %u dispatch notifications.\n",
       dispatch_notification_count);
    ok(!dispatch_notification_wparam, "received wparam %#Ix.\n",
       dispatch_notification_wparam);
    ok(!dispatch_notification_lparam, "received lparam %#Ix.\n",
       dispatch_notification_lparam);

    DestroyWindow(window);
    UnregisterClassW(class_name, class.hInstance);
}

static void test_queue_status_readonly(HMODULE module)
{
    get_queue_status_readonly_fn function;
    DWORD first, second, cleared, after_clear;
    MSG message;
    BOOL ret;

    function = (void *)GetProcAddress(module, (const char *)2541);
    ok(!!function, "Ordinal 2541 is unavailable.\n");
    if (!function) return;

    PeekMessageW(&message, NULL, 0, 0, PM_NOREMOVE);
    while (PeekMessageW(&message, NULL, WM_APP, WM_APP, PM_REMOVE)) /* nothing */;
    GetQueueStatus(QS_ALLINPUT);

    ret = PostThreadMessageW(GetCurrentThreadId(), WM_APP, 0, 0);
    ok(ret, "PostThreadMessageW failed, error %lu.\n", GetLastError());
    if (!ret) return;

    SetLastError(0x13579bdf);
    first = function(QS_POSTMESSAGE);
    ok(first == MAKELONG(QS_POSTMESSAGE, QS_POSTMESSAGE),
       "first read returned %#lx.\n", first);
    ok(GetLastError() == 0x13579bdf, "first read changed last error to %#lx.\n",
       GetLastError());

    second = function(QS_POSTMESSAGE);
    ok(second == first, "repeated read returned %#lx after %#lx.\n", second, first);
    ok(!function(QS_TIMER), "unmatched filter returned nonzero.\n");

    cleared = GetQueueStatus(QS_POSTMESSAGE);
    ok(cleared == first, "GetQueueStatus returned %#lx after readonly result %#lx.\n",
       cleared, first);
    after_clear = function(QS_POSTMESSAGE);
    ok(after_clear == MAKELONG(0, QS_POSTMESSAGE),
       "post-clear read returned %#lx.\n", after_clear);

    ret = PeekMessageW(&message, NULL, WM_APP, WM_APP, PM_REMOVE);
    ok(ret && message.message == WM_APP, "failed to remove posted message, ret %d message %#x.\n",
       ret, message.message);
    ok(!function(QS_POSTMESSAGE), "empty queue returned nonzero.\n");
}

static LRESULT WINAPI theme_change_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
{
    if (message == WM_THEMECHANGED)
    {
        theme_change_count++;
        theme_change_wparam = wparam;
        theme_change_lparam = lparam;
    }
    return DefWindowProcW(hwnd, message, wparam, lparam);
}

static void test_broadcast_theme_change_event(HMODULE module)
{
    static const WCHAR class_name[] = L"WineBroadcastThemeChange";
    broadcast_theme_change_event_fn function;
    WNDCLASSW class = {0};
    MSG message;
    HWND window;
    BOOL ret;

    function = (void *)GetProcAddress(module, (const char *)2708);
    ok(!!function, "Ordinal 2708 is unavailable.\n");
    if (!function) return;

    class.lpfnWndProc = theme_change_proc;
    class.hInstance = GetModuleHandleW(NULL);
    class.lpszClassName = class_name;
    ok(RegisterClassW(&class), "RegisterClassW failed, error %lu.\n", GetLastError());

    window = CreateWindowExW(0, class_name, NULL, WS_POPUP, 0, 0, 32, 32,
                             NULL, NULL, class.hInstance, NULL);
    ok(!!window, "failed to create theme-change window, error %lu.\n", GetLastError());
    if (!window) return;

    theme_change_count = 0;
    theme_change_wparam = 0;
    theme_change_lparam = 0;
    SetLastError(0x13579bdf);
    ret = function(0xabcdef01, 0x76543210);
    ok(ret, "BroadcastThemeChangeEvent returned %d, error %lu.\n", ret, GetLastError());
    ok(GetLastError() == 0x13579bdf, "call changed last error to %#lx.\n", GetLastError());
    ok(!theme_change_count, "theme notification was delivered synchronously.\n");

    while (PeekMessageW(&message, NULL, 0, 0, PM_REMOVE))
    {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    ok(theme_change_count == 1, "received %u theme notifications.\n", theme_change_count);
    ok(theme_change_wparam == (WPARAM)0xabcdef01,
       "received wparam %#Ix.\n", theme_change_wparam);
    ok(theme_change_lparam == (LPARAM)0x76543210,
       "received lparam %#Ix.\n", theme_change_lparam);

    DestroyWindow(window);
    UnregisterClassW(class_name, class.hInstance);
}

static BOOL CALLBACK record_desktop_window(HWND hwnd, LPARAM stop_after_first)
{
    enum_count++;
    if (hwnd == enum_target) enum_saw_target = TRUE;
    if (hwnd == enum_child) enum_saw_child = TRUE;
    if (hwnd == enum_grandchild) enum_saw_grandchild = TRUE;
    return !stop_after_first;
}

static void test_internal_window_enumeration(HMODULE module)
{
    internal_enum_desktop_windows_fn function;
    internal_enum_child_windows_fn child_function;
    HDESK desktop;

    function = (void *)GetProcAddress(module, (const char *)2527);
    child_function = (void *)GetProcAddress(module, (const char *)2525);
    ok(!!function, "Ordinal 2527 is unavailable.\n");
    ok(!!child_function, "Ordinal 2525 is unavailable.\n");
    if (!function || !child_function) return;

    enum_target = CreateWindowExW(0, L"Static", NULL, WS_POPUP, 0, 0, 32, 32,
                                  NULL, NULL, GetModuleHandleW(NULL), NULL);
    enum_child = enum_target ? CreateWindowExW(0, L"Static", NULL, WS_CHILD, 0, 0, 16, 16,
                                               enum_target, NULL, GetModuleHandleW(NULL), NULL) : NULL;
    enum_grandchild = enum_child ? CreateWindowExW(0, L"Static", NULL, WS_CHILD, 0, 0, 8, 8,
                                                   enum_child, NULL, GetModuleHandleW(NULL), NULL) : NULL;
    ok(!!enum_target && !!enum_child && !!enum_grandchild,
       "failed to create enumeration windows, error %lu.\n", GetLastError());
    if (!enum_target || !enum_child || !enum_grandchild) goto done;

    desktop = GetThreadDesktop(GetCurrentThreadId());
    ok(!!desktop, "GetThreadDesktop failed, error %lu.\n", GetLastError());
    if (!desktop) goto done;

    enum_count = 0;
    enum_saw_target = enum_saw_child = enum_saw_grandchild = FALSE;
    function(desktop, record_desktop_window, FALSE);
    ok(enum_count != 0, "desktop enumeration returned no windows.\n");
    ok(enum_saw_target, "desktop enumeration did not return the top-level test window.\n");
    ok(!enum_saw_child, "desktop enumeration returned child window %p.\n", enum_child);
    ok(!enum_saw_grandchild, "desktop enumeration returned grandchild window %p.\n",
       enum_grandchild);

    enum_count = 0;
    function(desktop, record_desktop_window, TRUE);
    ok(enum_count == 1, "stopped enumeration invoked %u callbacks.\n", enum_count);

    enum_count = 0;
    function((HDESK)(UINT_PTR)0xdeadbeef, record_desktop_window, FALSE);
    ok(enum_count == 0, "invalid desktop invoked %u callbacks.\n", enum_count);

    enum_count = 0;
    enum_saw_target = enum_saw_child = enum_saw_grandchild = FALSE;
    child_function(enum_target, record_desktop_window, FALSE);
    ok(enum_count >= 2, "child enumeration invoked only %u callbacks.\n", enum_count);
    ok(!enum_saw_target, "child enumeration returned parent window %p.\n", enum_target);
    ok(enum_saw_child, "child enumeration did not return child window %p.\n", enum_child);
    ok(enum_saw_grandchild, "child enumeration did not return grandchild window %p.\n",
       enum_grandchild);

    enum_count = 0;
    child_function(enum_target, record_desktop_window, TRUE);
    ok(enum_count == 1, "stopped child enumeration invoked %u callbacks.\n", enum_count);

    enum_count = 0;
    child_function((HWND)(UINT_PTR)0xdeadbeef, record_desktop_window, FALSE);
    ok(enum_count == 0, "invalid parent invoked %u callbacks.\n", enum_count);

done:
    if (enum_grandchild) DestroyWindow(enum_grandchild);
    if (enum_child) DestroyWindow(enum_child);
    if (enum_target) DestroyWindow(enum_target);
    enum_grandchild = enum_child = enum_target = NULL;
}

static void record_window_services_event(unsigned int event)
{
    if (window_services_event_count < ARRAY_SIZE(window_services_events))
        window_services_events[window_services_event_count++] = event;
}

static void callback_common(HWND hwnd, unsigned int event)
{
    record_window_services_event(event);
    callback_window_matches = callback_window_matches && hwnd == callback_target;
    callback_window_valid = callback_window_valid && IsWindow(hwnd);
}

static void CDECL window_services_callback_a(HWND hwnd)
{
    callback_a_count++;
    callback_common(hwnd, 2);
}

static void CDECL window_services_callback_b(HWND hwnd)
{
    callback_b_count++;
    callback_common(hwnd, 6);
}

static LRESULT WINAPI window_services_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
{
    LRESULT ret;

    if (message == WM_WINDOW_SERVICES_DESTROY)
    {
        record_window_services_event(1);
        ret = DefWindowProcW(hwnd, message, wparam, lparam);
        record_window_services_event(3);
        return ret;
    }
    if (message == WM_DESTROY) record_window_services_event(4);
    if (message == WM_NCDESTROY) record_window_services_event(5);
    return DefWindowProcW(hwnd, message, wparam, lparam);
}

static HWND create_window_services_window(void)
{
    return CreateWindowExW(0, window_services_class, NULL, WS_POPUP, 0, 0, 32, 32,
                           NULL, NULL, GetModuleHandleW(NULL), NULL);
}

static void check_window_services_events(const unsigned int *expected, unsigned int count,
                                         const char *description)
{
    unsigned int i;

    ok(window_services_event_count == count, "%s produced %u events, expected %u\n",
       description, window_services_event_count, count);
    for (i = 0; i < min(window_services_event_count, count); i++)
        ok(window_services_events[i] == expected[i], "%s event %u is %u, expected %u\n",
           description, i, window_services_events[i], expected[i]);
    window_services_event_count = 0;
}

static DWORD WINAPI window_services_thread(void *param)
{
    thread_window = create_window_services_window();
    if (!thread_window) return 1;
    callback_target = thread_window;
    SetLastError(0x13579bdf);
    thread_registration_ret = pSetWindowServicesDestroyCallback(
        thread_window, window_services_callback_a);
    thread_registration_error = GetLastError();
    return 0;
}

static void test_window_services_destroy(HMODULE module)
{
    static const unsigned int cleared_events[] = {4, 5};
    static const unsigned int callback_a_events[] = {1, 2, 3, 4, 5};
    static const unsigned int callback_b_events[] = {1, 6, 3, 4, 5};
    WNDCLASSW class = {0};
    HWND first, second, third, fourth;
    HANDLE thread;
    DWORD wait;
    BOOL ret;

    pSetWindowServicesDestroyCallback = (void *)GetProcAddress(module, (const char *)2536);
    ok(!!pSetWindowServicesDestroyCallback, "Ordinal 2536 is unavailable.\n");
    if (!pSetWindowServicesDestroyCallback) return;

    class.lpfnWndProc = window_services_proc;
    class.hInstance = GetModuleHandleW(NULL);
    class.lpszClassName = window_services_class;
    ok(RegisterClassW(&class), "RegisterClassW failed, error %lu.\n", GetLastError());

    first = create_window_services_window();
    second = create_window_services_window();
    third = create_window_services_window();
    fourth = create_window_services_window();
    ok(!!first && !!second && !!third && !!fourth,
       "failed to create window-services test windows, error %lu.\n", GetLastError());
    if (!first || !second || !third || !fourth) return;
    window_services_event_count = 0;

    SetLastError(0x13579bdf);
    ret = pSetWindowServicesDestroyCallback(NULL, window_services_callback_a);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
       "null HWND returned %d, error %lu.\n", ret, GetLastError());

    SetLastError(0x13579bdf);
    ret = pSetWindowServicesDestroyCallback(first, window_services_callback_a);
    ok(ret && GetLastError() == ERROR_SUCCESS,
       "first registration returned %d, error %lu.\n", ret, GetLastError());
    ret = pSetWindowServicesDestroyCallback(first, window_services_callback_a);
    ok(ret && GetLastError() == ERROR_SUCCESS,
       "repeated registration returned %d, error %lu.\n", ret, GetLastError());
    ret = pSetWindowServicesDestroyCallback(second, window_services_callback_a);
    ok(ret && GetLastError() == ERROR_SUCCESS,
       "second registration returned %d, error %lu.\n", ret, GetLastError());

    SetLastError(0x13579bdf);
    ret = pSetWindowServicesDestroyCallback(third, window_services_callback_b);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
       "conflicting registration returned %d, error %lu.\n", ret, GetLastError());
    ret = pSetWindowServicesDestroyCallback(third, NULL);
    ok(ret && GetLastError() == ERROR_SUCCESS,
       "unregistered clear returned %d, error %lu.\n", ret, GetLastError());
    ret = pSetWindowServicesDestroyCallback(second, NULL);
    ok(ret && GetLastError() == ERROR_SUCCESS,
       "registered clear returned %d, error %lu.\n", ret, GetLastError());

    ok(DestroyWindow(second), "DestroyWindow(second) failed, error %lu.\n", GetLastError());
    check_window_services_events(cleared_events, ARRAY_SIZE(cleared_events), "cleared destroy");

    callback_target = first;
    ok(DestroyWindow(first), "DestroyWindow(first) failed, error %lu.\n", GetLastError());
    check_window_services_events(callback_a_events, ARRAY_SIZE(callback_a_events),
                                 "callback A destroy");
    ok(callback_a_count == 1, "callback A ran %u times.\n", callback_a_count);

    ret = pSetWindowServicesDestroyCallback(fourth, window_services_callback_b);
    ok(ret && GetLastError() == ERROR_SUCCESS,
       "post-cleanup registration returned %d, error %lu.\n", ret, GetLastError());
    callback_target = fourth;
    ok(DestroyWindow(fourth), "DestroyWindow(fourth) failed, error %lu.\n", GetLastError());
    check_window_services_events(callback_b_events, ARRAY_SIZE(callback_b_events),
                                 "callback B destroy");
    ok(callback_b_count == 1, "callback B ran %u times.\n", callback_b_count);
    ok(DestroyWindow(third), "DestroyWindow(third) failed, error %lu.\n", GetLastError());
    window_services_event_count = 0;

    thread = CreateThread(NULL, 0, window_services_thread, NULL, 0, NULL);
    ok(!!thread, "CreateThread failed, error %lu.\n", GetLastError());
    if (!thread) return;
    wait = WaitForSingleObject(thread, 10000);
    ok(wait == WAIT_OBJECT_0, "window-services thread wait returned %#lx.\n", wait);
    CloseHandle(thread);
    ok(thread_registration_ret && thread_registration_error == ERROR_SUCCESS,
       "thread registration returned %d, error %lu.\n",
       thread_registration_ret, thread_registration_error);
    ok(!IsWindow(thread_window), "thread window %p remains valid.\n", thread_window);
    check_window_services_events(NULL, 0, "thread exit");
    ok(callback_a_count == 1, "callback A ran during thread exit, count %u.\n", callback_a_count);
    ok(callback_window_matches, "a callback received the wrong HWND.\n");
    ok(callback_window_valid, "a callback received an invalid HWND.\n");
}

struct guarded_ui_context_information
{
    DWORD before;
    DWORD context;
    DWORD flags;
    DWORD after;
};

static void check_process_ui_context(HANDLE process, BOOL expected_success, DWORD expected_error,
                                     const char *description)
{
    struct guarded_ui_context_information information;
    DWORD error;
    BOOL ret;

    memset(&information, 0xcc, sizeof(information));
    SetLastError(0x13579bdf);
    ret = pGetProcessUIContextInformation(process, &information.context);
    error = GetLastError();
    ok(ret == expected_success, "%s returned %d, error %lu\n", description, ret, error);
    ok(error == expected_error, "%s changed last error to %#lx\n", description, error);
    ok(information.before == 0xcccccccc, "%s overwrote the leading guard: %#lx\n",
       description, information.before);
    ok(information.after == 0xcccccccc, "%s overwrote the trailing guard: %#lx\n",
       description, information.after);
    if (expected_success)
    {
        ok(information.context == 0, "%s returned context %#lx\n", description,
           information.context);
        ok(information.flags == 0, "%s returned flags %#lx\n", description,
           information.flags);
    }
    else
    {
        ok(information.context == 0xcccccccc, "%s changed context on failure: %#lx\n",
           description, information.context);
        ok(information.flags == 0xcccccccc, "%s changed flags on failure: %#lx\n",
           description, information.flags);
    }

    SetLastError(0x13579bdf);
    ret = pIsImmersiveProcess(process);
    error = GetLastError();
    ok(!ret, "%s unexpectedly reported an immersive process\n", description);
    ok(error == expected_error, "%s IsImmersiveProcess changed last error to %#lx\n",
       description, error);
}

static void test_process_ui_context(char **argv)
{
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), NULL, TRUE};
    STARTUPINFOA startup = { .cb = sizeof(startup) };
    PROCESS_INFORMATION child = {0};
    char command[MAX_PATH * 3];
    HANDLE process, zero_access, event, ready = NULL, stop = NULL;
    DWORD wait;
    BOOL ret;

    check_process_ui_context(GetCurrentProcess(), TRUE, 0x13579bdf, "current pseudo handle");

    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    ok(!!process, "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) failed, error %lu\n",
       GetLastError());
    if (process)
    {
        check_process_ui_context(process, TRUE, 0x13579bdf, "query-limited handle");
        CloseHandle(process);
    }

    process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    ok(!!process, "OpenProcess(PROCESS_QUERY_INFORMATION) failed, error %lu\n", GetLastError());
    if (process)
    {
        check_process_ui_context(process, TRUE, 0x13579bdf, "query handle");
        CloseHandle(process);
    }

    process = OpenProcess(SYNCHRONIZE, FALSE, GetCurrentProcessId());
    ok(!!process, "OpenProcess(SYNCHRONIZE) failed, error %lu\n", GetLastError());
    if (process)
    {
        check_process_ui_context(process, FALSE, ERROR_INVALID_PARAMETER, "synchronize handle");
        CloseHandle(process);
    }

    zero_access = NULL;
    ret = DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(),
                          &zero_access, 0, FALSE, 0);
    ok(ret, "DuplicateHandle(zero access) failed, error %lu\n", GetLastError());
    if (ret)
    {
        check_process_ui_context(zero_access, FALSE, ERROR_INVALID_PARAMETER, "zero-access handle");
        CloseHandle(zero_access);
    }

    check_process_ui_context(NULL, FALSE, ERROR_INVALID_PARAMETER, "null handle");
    check_process_ui_context(GetCurrentThread(), FALSE, ERROR_INVALID_PARAMETER,
                             "thread pseudo handle");
    event = CreateEventW(NULL, FALSE, FALSE, NULL);
    ok(!!event, "CreateEventW failed, error %lu\n", GetLastError());
    if (event)
    {
        check_process_ui_context(event, FALSE, ERROR_INVALID_PARAMETER, "event handle");
        CloseHandle(event);
    }

    ready = CreateEventW(&attributes, TRUE, FALSE, NULL);
    stop = CreateEventW(&attributes, TRUE, FALSE, NULL);
    ok(!!ready && !!stop, "failed to create child events, error %lu\n", GetLastError());
    if (!ready || !stop) goto done;

    sprintf(command, "\"%s\" %s ui-context-child %p %p", argv[0], argv[1], ready, stop);
    ret = CreateProcessA(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &startup, &child);
    ok(ret, "failed to create UI-context child, error %lu\n", GetLastError());
    if (!ret) goto done;

    wait = WaitForSingleObject(ready, 10000);
    ok(wait == WAIT_OBJECT_0, "UI-context child did not become ready, wait %#lx\n", wait);
    if (wait == WAIT_OBJECT_0)
        check_process_ui_context(child.hProcess, TRUE, 0x13579bdf, "live GUI child");

    SetEvent(stop);
    wait = WaitForSingleObject(child.hProcess, 10000);
    ok(wait == WAIT_OBJECT_0, "UI-context child did not exit, wait %#lx\n", wait);
    if (wait == WAIT_OBJECT_0)
        check_process_ui_context(child.hProcess, FALSE, ERROR_NOT_GUI_PROCESS,
                                 "terminated GUI child");
    else
        TerminateProcess(child.hProcess, 1);

done:
    if (child.hThread) CloseHandle(child.hThread);
    if (child.hProcess) CloseHandle(child.hProcess);
    if (stop) CloseHandle(stop);
    if (ready) CloseHandle(ready);
}

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

static void test_thread_desktop_composited(HMODULE module)
{
    is_thread_desktop_composited_fn function;
    BOOL ret;

    function = (void *)GetProcAddress(module, "IsThreadDesktopComposited");
    ok(!!function, "IsThreadDesktopComposited is unavailable.\n");
    if (!function) return;

    SetLastError(0x13579bdf);
    ret = function();
    ok(!ret, "desktop without a DWM owner is unexpectedly composited.\n");
    ok(GetLastError() == 0x13579bdf, "call changed last error to %#lx.\n", GetLastError());
}

struct current_dpi_info
{
    UINT values[24];
};

static void check_current_dpi_info_for_window(get_current_dpi_info_for_window_fn get_window_info,
                                              get_current_dpi_info_fn get_monitor_info, HWND hwnd,
                                              const char *description)
{
    struct current_dpi_info actual, expected;
    HMONITOR monitor;
    BOOL ret;

    monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
    ok(!!monitor, "%s has no monitor, error %lu.\n", description, GetLastError());
    if (!monitor) return;

    memset(&expected, 0xcc, sizeof(expected));
    ret = get_monitor_info(monitor, &expected);
    ok(ret, "GetCurrentDpiInfo failed for %s, error %lu.\n", description, GetLastError());
    if (!ret) return;

    memset(&actual, 0xcc, sizeof(actual));
    SetLastError(0x13579bdf);
    ret = get_window_info(hwnd, &actual);
    ok(ret, "%s returned %d, error %lu.\n", description, ret, GetLastError());
    ok(GetLastError() == 0x13579bdf, "%s changed last error to %#lx.\n",
       description, GetLastError());
    ok(!memcmp(&actual, &expected, sizeof(actual)), "%s returned a different DPI record.\n",
       description);
}

static void test_current_dpi_info_for_window(HMODULE module)
{
    get_current_dpi_info_for_window_fn get_window_info;
    get_current_dpi_info_fn get_monitor_info;
    struct current_dpi_info info, unchanged;
    HWND popup, child;
    HMODULE gdi32;
    BOOL ret;

    get_window_info = (void *)GetProcAddress(module, (const char *)2636);
    gdi32 = GetModuleHandleW(L"gdi32.dll");
    get_monitor_info = gdi32 ? (void *)GetProcAddress(gdi32, "GetCurrentDpiInfo") : NULL;
    ok(!!get_window_info, "Ordinal 2636 is unavailable.\n");
    ok(!!get_monitor_info, "GetCurrentDpiInfo is unavailable.\n");
    if (!get_window_info || !get_monitor_info) return;

    memset(&info, 0, sizeof(info));
    unchanged = info;
    SetLastError(0x13579bdf);
    ret = get_window_info(NULL, &info);
    ok(!ret, "null HWND returned %d.\n", ret);
    ok(GetLastError() == ERROR_INVALID_WINDOW_HANDLE, "null HWND set error %#lx.\n", GetLastError());
    ok(!memcmp(&info, &unchanged, sizeof(info)), "null HWND changed the output record.\n");

    memset(&info, 0xcc, sizeof(info));
    unchanged = info;
    SetLastError(0x13579bdf);
    ret = get_window_info((HWND)(UINT_PTR)0xdeadbeef, &info);
    ok(!ret, "invalid HWND returned %d.\n", ret);
    ok(GetLastError() == ERROR_INVALID_WINDOW_HANDLE, "invalid HWND set error %#lx.\n",
       GetLastError());
    ok(!memcmp(&info, &unchanged, sizeof(info)), "invalid HWND changed the output record.\n");

    popup = CreateWindowExW(0, L"Static", NULL, WS_POPUP, 0, 0, 32, 32,
                            NULL, NULL, GetModuleHandleW(NULL), NULL);
    child = popup ? CreateWindowExW(0, L"Static", NULL, WS_CHILD, 0, 0, 16, 16,
                                    popup, NULL, GetModuleHandleW(NULL), NULL) : NULL;
    ok(!!popup && !!child, "failed to create DPI test windows, error %lu.\n", GetLastError());

    check_current_dpi_info_for_window(get_window_info, get_monitor_info, GetDesktopWindow(),
                                      "desktop window");
    if (popup) check_current_dpi_info_for_window(get_window_info, get_monitor_info, popup,
                                                 "popup window");
    if (child) check_current_dpi_info_for_window(get_window_info, get_monitor_info, child,
                                                 "child window");

    if (child) DestroyWindow(child);
    if (popup) DestroyWindow(popup);
}

static void test_register_user_api_hook(HMODULE module)
{
    static const WCHAR uxtheme[] = L"C:\\Windows\\System32\\uxtheme.dll";
    static const WCHAR init[] = L"ThemeInitApiHook";
    struct user_api_hook_descriptor descriptor =
    {
        sizeof(descriptor), uxtheme, init, uxtheme, init
    };
    register_user_api_hook_fn function;
    BOOL ret;

    function = (void *)GetProcAddress(module, "RegisterUserApiHook");
    ok(!!function, "RegisterUserApiHook is unavailable.\n");
    if (!function) return;

    SetLastError(0x13579bdf);
    ret = function(NULL);
    ok(!ret, "null descriptor returned %d.\n", ret);
    ok(GetLastError() == ERROR_INVALID_PARAMETER,
       "null descriptor set error %#lx.\n", GetLastError());

    descriptor.size--;
    SetLastError(0x13579bdf);
    ret = function(&descriptor);
    ok(!ret, "wrong descriptor size returned %d.\n", ret);
    ok(GetLastError() == ERROR_INVALID_PARAMETER,
       "wrong descriptor size set error %#lx.\n", GetLastError());
    descriptor.size++;

    SetLastError(0x13579bdf);
    ret = function(&descriptor);
    ok(!ret, "unprivileged registration returned %d.\n", ret);
    ok(GetLastError() == ERROR_ACCESS_DENIED,
       "unprivileged registration set error %#lx.\n", GetLastError());
}

static void test_dmanip_hook_registration(HMODULE module)
{
    register_dmanip_hook_fn register_hook;
    init_dmanip_hook_ex_fn init_hook;
    BOOL ret;

    register_hook = (void *)GetProcAddress(module, "RegisterDManipHook");
    init_hook = (void *)GetProcAddress(module, (const char *)2587);
    ok(!!register_hook, "RegisterDManipHook is unavailable.\n");
    ok(!!init_hook, "ordinal 2587 is unavailable.\n");
    if (!register_hook || !init_hook) return;

    SetLastError(0x13579bdf);
    ret = register_hook();
    ok(!ret, "unprivileged Direct Manipulation registration returned %d.\n", ret);
    ok(GetLastError() == ERROR_ACCESS_DENIED,
       "unprivileged Direct Manipulation registration set error %#lx.\n", GetLastError());

    ret = init_hook(FALSE);
    ok(ret, "Direct Manipulation teardown returned %d.\n", ret);
}

static void test_core_window(HMODULE module)
{
    set_core_window_fn set_core_window;
    is_core_window_fn is_core_window;
    HWND parent, child, grandchild;
    BOOL ret;

    set_core_window = (void *)GetProcAddress(module, "SetCoreWindow");
    is_core_window = (void *)GetProcAddress(module, (const char *)2572);
    ok(!!set_core_window, "SetCoreWindow is unavailable.\n");
    ok(!!is_core_window, "Ordinal 2572 is unavailable.\n");
    if (!set_core_window || !is_core_window) return;

    parent = CreateWindowExW(0, L"Static", NULL, WS_POPUP, 0, 0, 100, 100,
                             NULL, NULL, GetModuleHandleW(NULL), NULL);
    child = parent ? CreateWindowExW(0, L"Static", NULL, WS_CHILD, 0, 0, 50, 50,
                                     parent, NULL, GetModuleHandleW(NULL), NULL) : NULL;
    grandchild = child ? CreateWindowExW(0, L"Static", NULL, WS_CHILD, 0, 0, 25, 25,
                                         child, NULL, GetModuleHandleW(NULL), NULL) : NULL;
    ok(!!parent && !!child && !!grandchild,
       "failed to create core-window hierarchy, error %lu.\n", GetLastError());
    if (!parent || !child || !grandchild) goto done;

    ok(!is_core_window(parent), "parent unexpectedly starts as a core window.\n");
    ok(!is_core_window(child), "child unexpectedly starts as a core window.\n");
    ok(!is_core_window(grandchild), "grandchild unexpectedly starts as a core window.\n");

    ret = set_core_window(parent, TRUE);
    ok(ret, "SetCoreWindow(TRUE) failed, error %lu.\n", GetLastError());
    ok(is_core_window(parent), "parent did not become a core window.\n");
    ok(is_core_window(child), "core-window state did not reach child.\n");
    ok(is_core_window(grandchild), "core-window state did not reach grandchild.\n");

    ret = set_core_window(parent, FALSE);
    ok(ret, "SetCoreWindow(FALSE) failed, error %lu.\n", GetLastError());
    ok(!is_core_window(parent), "parent retained core-window state.\n");
    ok(!is_core_window(child), "child retained core-window state.\n");
    ok(!is_core_window(grandchild), "grandchild retained core-window state.\n");

    SetLastError(0xdeadbeef);
    ret = set_core_window((HWND)(UINT_PTR)0xdeadbeef, TRUE);
    ok(!ret, "SetCoreWindow accepted an invalid HWND.\n");
    ok(GetLastError() == ERROR_INVALID_PARAMETER,
       "invalid HWND set error %#lx.\n", GetLastError());

done:
    if (grandchild) DestroyWindow(grandchild);
    if (child) DestroyWindow(child);
    if (parent) DestroyWindow(parent);
}

static void test_window_composition_attributes(HMODULE module)
{
    get_window_composition_attribute_fn get_attribute;
    set_window_composition_attribute_fn set_attribute;
    struct composition_attribute_data data;
    DWORD accent[4], value;
    HWND window, child;
    BOOL ret;

    get_attribute = (void *)GetProcAddress(module, "GetWindowCompositionAttribute");
    set_attribute = (void *)GetProcAddress(module, "SetWindowCompositionAttribute");
    ok(!!get_attribute, "GetWindowCompositionAttribute is unavailable.\n");
    ok(!!set_attribute, "SetWindowCompositionAttribute is unavailable.\n");
    if (!get_attribute || !set_attribute) return;

    window = CreateWindowExW(0, L"Static", NULL, WS_OVERLAPPEDWINDOW, 0, 0, 100, 100,
                             NULL, NULL, GetModuleHandleW(NULL), NULL);
    child = window ? CreateWindowExW(0, L"Static", NULL, WS_CHILD, 0, 0, 50, 50,
                                     window, NULL, GetModuleHandleW(NULL), NULL) : NULL;
    ok(!!window && !!child, "failed to create composition windows, error %lu.\n", GetLastError());
    if (!window || !child) goto done;

    value = 0xdeadbeef;
    data.attribute = 1;
    data.data = &value;
    data.size = sizeof(value);
    ret = get_attribute(window, &data);
    ok(ret, "non-client rendering query failed, error %lu.\n", GetLastError());
    ok(value == TRUE, "default non-client rendering state is %#lx.\n", value);

    value = 1; /* DWMNCRP_DISABLED */
    data.attribute = 2;
    ret = set_attribute(window, &data);
    ok(ret, "disabling non-client rendering failed, error %lu.\n", GetLastError());
    value = 0xdeadbeef;
    ret = get_attribute(window, &data);
    ok(ret && value == 1, "policy query returned %d, value %#lx, error %lu.\n",
       ret, value, GetLastError());
    data.attribute = 1;
    ret = get_attribute(window, &data);
    ok(ret && value == FALSE, "disabled non-client rendering returned %d, value %#lx.\n",
       ret, value);

    value = 2; /* DWMNCRP_ENABLED */
    data.attribute = 2;
    ret = set_attribute(window, &data);
    ok(ret, "enabling non-client rendering failed, error %lu.\n", GetLastError());
    value = 0;
    data.attribute = 1;
    ret = get_attribute(window, &data);
    ok(ret && value == TRUE, "enabled non-client rendering returned %d, value %#lx.\n",
       ret, value);

    accent[0] = 5;
    accent[1] = 2;
    accent[2] = 0xff123456;
    accent[3] = 7;
    data.attribute = 19;
    data.data = accent;
    data.size = sizeof(accent);
    ret = set_attribute(window, &data);
    ok(ret, "setting accent policy failed, error %lu.\n", GetLastError());
    memset(accent, 0, sizeof(accent));
    ret = get_attribute(window, &data);
    ok(ret, "getting accent policy failed, error %lu.\n", GetLastError());
    ok(accent[0] == 5 && accent[1] == 2 && accent[2] == 0xff123456 && accent[3] == 7,
       "accent policy returned {%#lx, %#lx, %#lx, %#lx}.\n",
       accent[0], accent[1], accent[2], accent[3]);

    value = 0;
    data.attribute = 34;
    data.data = &value;
    data.size = sizeof(value);
    ret = get_attribute(window, &data);
    ok(ret && value == TRUE, "accent-presence query returned %d, value %#lx.\n", ret, value);

    value = TRUE;
    data.attribute = 17; /* WCA_CLOAK */
    data.data = &value;
    data.size = sizeof(value);
    ret = set_attribute(window, &data);
    ok(ret, "setting window cloak failed, error %lu.\n", GetLastError());
    value = FALSE;
    data.attribute = 18; /* WCA_CLOAKED */
    ret = get_attribute(window, &data);
    ok(ret && value == TRUE, "cloaked-state query returned %d, value %#lx.\n", ret, value);

    value = FALSE;
    data.attribute = 17;
    ret = set_attribute(window, &data);
    ok(ret, "clearing window cloak failed, error %lu.\n", GetLastError());
    value = TRUE;
    data.attribute = 18;
    ret = get_attribute(window, &data);
    ok(ret && value == FALSE, "uncloaked-state query returned %d, value %#lx.\n", ret, value);

    memset(accent, 0, sizeof(accent));
    data.attribute = 19;
    data.data = accent;
    data.size = sizeof(accent);
    ret = set_attribute(window, &data);
    ok(ret, "clearing accent policy failed, error %lu.\n", GetLastError());
    value = 0xdeadbeef;
    data.attribute = 34;
    data.data = &value;
    data.size = sizeof(value);
    ret = get_attribute(window, &data);
    ok(ret && value == FALSE, "cleared accent-presence query returned %d, value %#lx.\n",
       ret, value);

    SetLastError(0xdeadbeef);
    data.attribute = 19;
    data.data = accent;
    data.size = sizeof(accent) - sizeof(accent[0]);
    ret = set_attribute(window, &data);
    ok(!ret && GetLastError() == ERROR_INSUFFICIENT_BUFFER,
       "short accent policy returned %d, error %lu.\n", ret, GetLastError());

    SetLastError(0xdeadbeef);
    data.attribute = 1;
    data.data = &value;
    data.size = sizeof(value);
    ret = set_attribute(window, &data);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
       "read-only attribute returned %d, error %lu.\n", ret, GetLastError());

    SetLastError(0xdeadbeef);
    ret = get_attribute(child, &data);
    ok(!ret && GetLastError() == ERROR_INVALID_WINDOW_HANDLE,
       "child attribute query returned %d, error %lu.\n", ret, GetLastError());

    SetLastError(0xdeadbeef);
    ret = get_attribute((HWND)(UINT_PTR)0xdeadbeef, &data);
    ok(!ret && GetLastError() == ERROR_INVALID_WINDOW_HANDLE,
       "invalid-window query returned %d, error %lu.\n", ret, GetLastError());

done:
    if (child) DestroyWindow(child);
    if (window) DestroyWindow(window);
}

START_TEST(native_ordinals)
{
    char **argv;
    int argc;
    HANDLE ready, stop;
    HMODULE module;

    argc = winetest_get_mainargs(&argv);
    if (argc == 5 && !strcmp(argv[2], "ui-context-child"))
    {
        sscanf(argv[3], "%p", &ready);
        sscanf(argv[4], "%p", &stop);
        SetEvent(ready);
        WaitForSingleObject(stop, 10000);
        return;
    }

    module = GetModuleHandleW(L"user32.dll");
    test_force_enable_numpad_translation(module);
    test_get_window_dpi(module);
    test_report_inertia(module);
    test_input_delegation(module);
    test_schedule_dispatch_notification(module);
    test_queue_status_readonly(module);
    test_broadcast_theme_change_event(module);
    test_internal_window_enumeration(module);
    test_window_services_destroy(module);
    test_gdi_scaled_process();
    test_thread_desktop_composited(module);
    test_current_dpi_info_for_window(module);
    test_register_user_api_hook(module);
    test_dmanip_hook_registration(module);
    test_core_window(module);
    test_window_composition_attributes(module);

    pGetProcessUIContextInformation = (void *)GetProcAddress(module,
                                                             "GetProcessUIContextInformation");
    pIsImmersiveProcess = (void *)GetProcAddress(module, "IsImmersiveProcess");
    if (!pGetProcessUIContextInformation || !pIsImmersiveProcess)
    {
        win_skip("process UI-context entry points are unavailable\n");
        return;
    }
    test_process_ui_context(argv);
}
