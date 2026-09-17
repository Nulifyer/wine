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
typedef void (CDECL *window_services_destroy_callback)(HWND);
typedef BOOL (WINAPI *set_window_services_destroy_callback_fn)(HWND, window_services_destroy_callback);

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
    test_broadcast_theme_change_event(module);
    test_internal_window_enumeration(module);
    test_window_services_destroy(module);
    test_gdi_scaled_process();
    test_thread_desktop_composited(module);
    test_current_dpi_info_for_window(module);

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
