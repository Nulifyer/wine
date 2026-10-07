/*
 * Window monitor inheritance validation tests
 * Copyright 2026 LinuxNT contributors
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1, or any later version.
 */
#include <stdarg.h>
#include "windef.h"
#include "winbase.h"
#include "winuser.h"
#include "wine/test.h"

static BOOL (WINAPI *functions[2])(HWND, HWND);

static void check(const char *name, HWND target, HWND source, BOOL expected, DWORD expected_error)
{
    unsigned int i;
    for (i = 0; i < ARRAY_SIZE(functions); ++i)
    {
        BOOL ret;
        DWORD error;
        if (!functions[i]) continue;
        SetLastError(0x12345678);
        ret = functions[i](target, source);
        error = GetLastError();
        ok(ret == expected, "%s entry%u returned %d, expected %d\n", name, i, ret, expected);
        ok(error == expected_error, "%s entry%u error %lu, expected %lu\n", name, i, error, expected_error);
    }
}

START_TEST(window_monitor)
{
    WNDCLASSW wc = {0};
    HWND root, source, child, popup, message, destroyed;
    HMODULE win32u;
    unsigned int i;

    functions[0] = (void *)GetProcAddress(GetModuleHandleW(L"user32.dll"), "InheritWindowMonitor");
    win32u = LoadLibraryW(L"win32u.dll");
    functions[1] = win32u ? (void *)GetProcAddress(win32u, "NtUserInheritWindowMonitor") : NULL;
    if (!functions[0])
    {
        win_skip("Monitor inheritance unavailable\n");
        if (win32u) FreeLibrary(win32u);
        return;
    }
    ok(!!functions[1], "Missing Win32u entrypoint\n");
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"LinuxNTMonitorInheritanceTest";
    ok(!!RegisterClassW(&wc), "Class registration failed\n");
    root = CreateWindowW(wc.lpszClassName, L"root", WS_OVERLAPPEDWINDOW, 80, 80, 200, 160, NULL, NULL, wc.hInstance, NULL);
    source = CreateWindowW(wc.lpszClassName, L"source", WS_OVERLAPPEDWINDOW, 120, 120, 200, 160, NULL, NULL, wc.hInstance, NULL);
    child = CreateWindowW(wc.lpszClassName, L"child", WS_CHILD, 0, 0, 40, 40, root, NULL, wc.hInstance, NULL);
    popup = CreateWindowW(wc.lpszClassName, L"popup", WS_POPUP, 32767, 32767, 80, 80, root, NULL, wc.hInstance, NULL);
    message = CreateWindowW(wc.lpszClassName, L"message", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, wc.hInstance, NULL);
    destroyed = CreateWindowW(wc.lpszClassName, L"destroyed", 0, 0, 0, 40, 40, NULL, NULL, wc.hInstance, NULL);
    ok(root && source && child && popup && message && destroyed, "Window creation failed\n");
    if (!(root && source && child && popup && message && destroyed)) goto done;
    DestroyWindow(destroyed);
    check("root-source", root, source, TRUE, 0x12345678);
    check("popup-source", popup, source, TRUE, 0x12345678);
    check("child-source", child, source, TRUE, 0x12345678);
    check("message-source", message, source, TRUE, 0x12345678);
    check("source-message", source, message, TRUE, 0x12345678);
    check("self", root, root, TRUE, 0x12345678);
    check("repeat", root, source, TRUE, 0x12345678);
    check("root-null", root, NULL, TRUE, 0x12345678);
    check("popup-null", popup, NULL, TRUE, 0x12345678);
    check("root-desktop", root, GetDesktopWindow(), TRUE, 0x12345678);
    check("desktop-source", GetDesktopWindow(), source, FALSE, 0x12345678);
    check("root-message-pseudo", root, HWND_MESSAGE, FALSE, ERROR_INVALID_WINDOW_HANDLE);
    check("message-pseudo-source", HWND_MESSAGE, source, FALSE, ERROR_INVALID_WINDOW_HANDLE);
    check("root-invalid", root, (HWND)0x12345678, FALSE, ERROR_INVALID_WINDOW_HANDLE);
    check("invalid-source", (HWND)0x12345678, source, FALSE, ERROR_INVALID_WINDOW_HANDLE);
    check("root-destroyed", root, destroyed, FALSE, ERROR_INVALID_WINDOW_HANDLE);
    check("destroyed-source", destroyed, source, FALSE, ERROR_INVALID_WINDOW_HANDLE);
    check("null-source", NULL, source, FALSE, ERROR_INVALID_WINDOW_HANDLE);
    check("null-null", NULL, NULL, FALSE, ERROR_INVALID_WINDOW_HANDLE);
    check("null-invalid", NULL, (HWND)0x12345678, FALSE, ERROR_INVALID_WINDOW_HANDLE);
    check("invalid-null", (HWND)0x12345678, NULL, FALSE, ERROR_INVALID_WINDOW_HANDLE);
    check("invalid-invalid", (HWND)0x12345678, (HWND)0x12345678, FALSE, ERROR_INVALID_WINDOW_HANDLE);
    check("truncated-target", (HWND)((ULONG_PTR)root & 0xffff), source, FALSE, ERROR_INVALID_WINDOW_HANDLE);
    check("truncated-source", root, (HWND)((ULONG_PTR)source & 0xffff), FALSE, ERROR_INVALID_WINDOW_HANDLE);
    check("popup-source-again", popup, source, TRUE, 0x12345678);
    MoveWindow(source, 32767, 32767, 200, 160, FALSE);
    MoveWindow(popup, 32767, 32767, 80, 80, FALSE);
    DestroyWindow(source); source = NULL;
    MoveWindow(popup, 32767, 32767, 80, 80, FALSE);
    check("reset-after-source-destroy", popup, NULL, TRUE, 0x12345678);
    for (i = 0; i < 3; ++i) check("repeat-reset", popup, NULL, TRUE, 0x12345678);
done:
    if (source) DestroyWindow(source);
    if (message) DestroyWindow(message);
    if (popup) DestroyWindow(popup);
    if (root) DestroyWindow(root);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    if (win32u) FreeLibrary(win32u);
}
