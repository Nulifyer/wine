/*
 * Private USER32 window-state lifetime and style tests
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <windows.h>
#include "wine/test.h"

struct client_state
{
    DWORD flags, flags2, ex_style, style;
};

static const WCHAR class_name[] = L"WineWindowClientState";
static const struct client_state *retained;
static HWND tracked;
static BOOL recording;
static unsigned int create_callbacks, destroy_callbacks, style_callbacks;

static const struct client_state *check_state(HWND hwnd, const struct client_state *saved, const char *stage)
{
    const struct client_state *wide, *ansi;
    struct client_state current, original;
    SIZE_T count;
    DWORD error;
    BOOL ret;

    winetest_push_context("%s", stage);
    SetLastError(0x12345678);
    wide = (void *)GetWindowLongPtrW(hwnd, -1);
    error = GetLastError();
    ok(!!wide, "No Unicode client state, error %lu\n", error);
    ok(error == 0x12345678, "Unicode query changed error to %lu\n", error);
    SetLastError(0x12345678);
    ansi = (void *)GetWindowLongPtrA(hwnd, -1);
    error = GetLastError();
    ok(ansi == wide, "ANSI state %p differs from Unicode %p\n", ansi, wide);
    ok(error == 0x12345678, "ANSI query changed error to %lu\n", error);
    if (wide)
    {
        count = 0;
        ret = ReadProcessMemory(GetCurrentProcess(), wide, &current, sizeof(current), &count);
        ok(ret && count == sizeof(current), "Could not read client state, error %lu\n", GetLastError());
        if (ret && count == sizeof(current))
        {
            ok(current.style == GetWindowLongW(hwnd, GWL_STYLE), "Style %#lx differs from public %#lx\n",
               current.style, GetWindowLongW(hwnd, GWL_STYLE));
            /* Windows uses reserved bit 0x800 internally for a shown window. */
            ok((current.ex_style & ~0x800) == GetWindowLongW(hwnd, GWL_EXSTYLE),
               "Extended style %#lx differs from public %#lx\n", current.ex_style,
               GetWindowLongW(hwnd, GWL_EXSTYLE));
            if (saved)
            {
                ok(wide == saved, "State moved from %p to %p\n", saved, wide);
                count = 0;
                ret = ReadProcessMemory(GetCurrentProcess(), saved, &original, sizeof(original), &count);
                ok(ret && count == sizeof(original), "Could not read retained state, error %lu\n", GetLastError());
                if (ret && count == sizeof(original))
                    ok(!memcmp(&original, &current, sizeof(current)), "Retained state is stale\n");
            }
        }
    }
    winetest_pop_context();
    return wide;
}

static LRESULT CALLBACK window_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
{
    if (message == WM_NCCREATE && recording)
    {
        tracked = hwnd;
        retained = check_state(hwnd, NULL, "WM_NCCREATE");
        ++create_callbacks;
    }
    if (hwnd == tracked)
    {
        if (message == WM_CREATE)
        {
            check_state(hwnd, retained, "WM_CREATE");
            ++create_callbacks;
        }
        else if (message == WM_STYLECHANGING || message == WM_STYLECHANGED)
        {
            check_state(hwnd, retained, message == WM_STYLECHANGING ? "WM_STYLECHANGING" : "WM_STYLECHANGED");
            ++style_callbacks;
        }
        else if (message == WM_DESTROY || message == WM_NCDESTROY)
        {
            check_state(hwnd, retained, message == WM_DESTROY ? "WM_DESTROY" : "WM_NCDESTROY");
            ++destroy_callbacks;
        }
    }
    return DefWindowProcW(hwnd, message, wparam, lparam);
}

static void check_invalid(HWND hwnd)
{
    LONG_PTR ret;
    SetLastError(0x12345678);
    ret = GetWindowLongPtrW(hwnd, -1);
    ok(!ret && GetLastError() == ERROR_INVALID_WINDOW_HANDLE,
       "Unicode query for invalid %p returned %Ix, error %lu\n", hwnd, ret, GetLastError());
    SetLastError(0x12345678);
    ret = GetWindowLongPtrA(hwnd, -1);
    ok(!ret && GetLastError() == ERROR_INVALID_WINDOW_HANDLE,
       "ANSI query for invalid %p returned %Ix, error %lu\n", hwnd, ret, GetLastError());
}

static void test_window_state(BOOL ansi)
{
    const struct client_state *second_state;
    HWND hwnd, second;
    DWORD style;

    retained = NULL;
    tracked = NULL;
    create_callbacks = destroy_callbacks = style_callbacks = 0;
    recording = TRUE;
    hwnd = ansi ? CreateWindowExA(WS_EX_TOOLWINDOW, "WineWindowClientState", "State", WS_DISABLED,
                                 10, 20, 120, 80, NULL, NULL, GetModuleHandleA(NULL), NULL)
                : CreateWindowExW(WS_EX_TOOLWINDOW, class_name, L"State", WS_DISABLED,
                                  10, 20, 120, 80, NULL, NULL, GetModuleHandleW(NULL), NULL);
    ok(!!hwnd, "CreateWindow failed, error %lu\n", GetLastError());
    if (!hwnd) return;
    recording = FALSE;
    ok(create_callbacks == 2, "Expected two create callbacks, got %u\n", create_callbacks);
    check_state(hwnd, retained, "after create");
    second = CreateWindowExW(0, class_name, L"Second", WS_POPUP, 0, 0, 20, 20,
                             NULL, NULL, GetModuleHandleW(NULL), NULL);
    ok(!!second, "Second CreateWindow failed, error %lu\n", GetLastError());
    if (second)
    {
        second_state = check_state(second, NULL, "second window");
        ok(second_state != retained, "Windows share client-state storage\n");
        DestroyWindow(second);
        check_state(hwnd, retained, "after second destroy");
    }
    style = GetWindowLongW(hwnd, GWL_STYLE);
    SetWindowLongW(hwnd, GWL_STYLE, style | WS_CLIPCHILDREN);
    check_state(hwnd, retained, "after style");
    SetWindowLongW(hwnd, GWL_EXSTYLE, WS_EX_TOOLWINDOW | WS_EX_LAYOUTRTL);
    check_state(hwnd, retained, "after extended style");
    ok(style_callbacks == 4, "Expected four style callbacks, got %u\n", style_callbacks);
    EnableWindow(hwnd, TRUE);
    check_state(hwnd, retained, "enabled");
    EnableWindow(hwnd, FALSE);
    check_state(hwnd, retained, "disabled");
    SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    check_state(hwnd, retained, "topmost");
    ShowWindow(hwnd, SW_SHOWNOACTIVATE);
    check_state(hwnd, retained, "shown");
    ShowWindow(hwnd, SW_HIDE);
    check_state(hwnd, retained, "hidden");
    DestroyWindow(hwnd);
    ok(destroy_callbacks == 2, "Expected two destroy callbacks, got %u\n", destroy_callbacks);
    /* The saved pointer is not valid after destruction. */
    check_invalid(hwnd);
    tracked = NULL;
    retained = NULL;
}

START_TEST(window_state)
{
    WNDCLASSW cls = {0};
    cls.lpfnWndProc = window_proc;
    cls.hInstance = GetModuleHandleW(NULL);
    cls.lpszClassName = class_name;
    ok(!!RegisterClassW(&cls), "RegisterClass failed, error %lu\n", GetLastError());
    test_window_state(FALSE);
    test_window_state(TRUE);
    check_invalid(NULL);
    check_invalid((HWND)(ULONG_PTR)0xdeadbeef);
    UnregisterClassW(class_name, cls.hInstance);
}
