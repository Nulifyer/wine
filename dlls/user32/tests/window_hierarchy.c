/*
 * Private USER32 top-level hierarchy tests
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

static HWND (WINAPI *pGetTopLevelWindow)(HWND);
static HWND (WINAPI *pNtUserGetTopLevelWindow)(HWND);
static const WCHAR class_name[] = L"WineTopLevelHierarchy";
static HWND windows[12];

static void check(HWND hwnd, HWND expected, DWORD expected_error, const char *stage)
{
    HWND ret;
    DWORD error;

    winetest_push_context("%s", stage);
    SetLastError(0x12345678);
    ret = pGetTopLevelWindow(hwnd);
    error = GetLastError();
    ok(ret == expected, "Got %p, expected %p for %p\n", ret, expected, hwnd);
    ok(error == expected_error, "Error %lu, expected %lu\n", error, expected_error);
    if (pNtUserGetTopLevelWindow)
    {
        SetLastError(0x12345678);
        ret = pNtUserGetTopLevelWindow(hwnd);
        error = GetLastError();
        ok(ret == expected, "NtUser returned %p, expected %p\n", ret, expected);
        ok(error == expected_error, "NtUser error %lu, expected %lu\n", error, expected_error);
    }
    winetest_pop_context();
}

static HWND create(DWORD style, HWND parent)
{
    HWND hwnd = CreateWindowExW(0, class_name, L"Hierarchy", style, 10, 20, 100, 80,
                                parent, NULL, GetModuleHandleW(NULL), NULL);
    ok(!!hwnd, "Window creation failed, error %lu\n", GetLastError());
    return hwnd;
}

START_TEST(window_hierarchy)
{
    /* Frozen Windows 26200 / UBR 9168 hierarchy results. Owners are not parents. */
    static const int roots[] = {-1, -1, 2, 2, 2, 5, 5, 7, -1, -1, 10, 10};
    WNDCLASSW cls = {0};
    HMODULE module;
    DWORD style;
    unsigned int i;

    pGetTopLevelWindow = (void *)GetProcAddress(GetModuleHandleW(L"user32.dll"), "GetTopLevelWindow");
    module = GetModuleHandleW(L"win32u.dll");
    pNtUserGetTopLevelWindow = module ? (void *)GetProcAddress(module, "NtUserGetTopLevelWindow") : NULL;
    if (!pGetTopLevelWindow)
    {
        win_skip("GetTopLevelWindow unavailable\n");
        return;
    }
    cls.hInstance = GetModuleHandleW(NULL);
    cls.lpszClassName = class_name;
    cls.lpfnWndProc = DefWindowProcW;
    if (!RegisterClassW(&cls))
    {
        ok(0, "Class registration failed\n");
        return;
    }
    windows[0] = GetDesktopWindow();
    windows[2] = create(WS_OVERLAPPEDWINDOW, NULL);
    windows[3] = create(WS_CHILD, windows[2]);
    windows[4] = create(WS_CHILD, windows[3]);
    windows[5] = create(WS_POPUP, windows[2]);
    windows[6] = create(WS_CHILD, windows[5]);
    windows[7] = create(WS_POPUP, windows[5]);
    windows[8] = create(0, HWND_MESSAGE);
    windows[1] = GetAncestor(windows[8], GA_PARENT);
    windows[9] = create(WS_CHILD, windows[8]);
    windows[10] = create(WS_OVERLAPPEDWINDOW, NULL);
    windows[11] = create(WS_CHILD, windows[10]);
    for (i = 0; i < ARRAY_SIZE(windows); ++i)
        check(windows[i], roots[i] < 0 ? NULL : windows[roots[i]], 0x12345678, "initial");
    check(NULL, NULL, ERROR_INVALID_WINDOW_HANDLE, "null");
    check(HWND_MESSAGE, NULL, ERROR_INVALID_WINDOW_HANDLE, "message pseudo-handle");
    check((HWND)(ULONG_PTR)0xdeadbeef, NULL, ERROR_INVALID_WINDOW_HANDLE, "invalid");
    check((HWND)((ULONG_PTR)windows[4] & 0xffff), NULL, ERROR_INVALID_WINDOW_HANDLE, "truncated");
    SetParent(windows[3], windows[10]);
    check(windows[3], windows[10], 0x12345678, "reparented child");
    check(windows[4], windows[10], 0x12345678, "reparented grandchild");
    SetParent(windows[3], NULL);
    check(windows[3], windows[3], 0x12345678, "child under desktop");
    check(windows[4], windows[3], 0x12345678, "grandchild under desktop");
    SetParent(windows[3], windows[8]);
    check(windows[3], NULL, 0x12345678, "child under message");
    check(windows[4], NULL, 0x12345678, "grandchild under message");
    SetParent(windows[3], windows[2]);
    style = GetWindowLongW(windows[3], GWL_STYLE);
    SetWindowLongW(windows[3], GWL_STYLE, (style & ~WS_CHILD) | WS_POPUP);
    check(windows[3], windows[2], 0x12345678, "popup style with real parent");
    check(windows[4], windows[2], 0x12345678, "child under popup style");
    SetWindowLongW(windows[3], GWL_STYLE, style);
    SetWindowLongPtrW(windows[5], GWLP_HWNDPARENT, (LONG_PTR)windows[10]);
    check(windows[5], windows[5], 0x12345678, "owner changed");
    check(windows[6], windows[5], 0x12345678, "child of owner changed");
    DestroyWindow(windows[4]);
    check(windows[4], NULL, ERROR_INVALID_WINDOW_HANDLE, "destroyed");
    DestroyWindow(windows[7]);
    DestroyWindow(windows[5]);
    DestroyWindow(windows[2]);
    DestroyWindow(windows[8]);
    DestroyWindow(windows[10]);
    UnregisterClassW(class_name, cls.hInstance);
}
