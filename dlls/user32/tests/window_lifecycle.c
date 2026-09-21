/*
 * USER32 window lifecycle tests
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

static BOOL (WINAPI *pIsWindowInDestroy)(HWND);
static HANDLE destroy_event, destroy_process;
static HWND destroy_window;

static LRESULT CALLBACK window_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
{
    if (message == WM_DESTROY)
    {
        DWORD exit_code, wait;
        BOOL ret;

        ok(pIsWindowInDestroy(hwnd), "window %p is not marked as destroying\n", hwnd);
        if (destroy_event && destroy_process)
        {
            ret = SetEvent(destroy_event);
            ok(ret, "SetEvent failed, error %lu\n", GetLastError());
            wait = WaitForSingleObject(destroy_process, 5000);
            ok(wait == WAIT_OBJECT_0, "child wait returned %#lx\n", wait);
            ret = GetExitCodeProcess(destroy_process, &exit_code);
            ok(ret, "GetExitCodeProcess failed, error %lu\n", GetLastError());
            if (ret) ok(!exit_code, "cross-process destroy query exited with %lu\n", exit_code);
        }
    }
    return DefWindowProcA(hwnd, message, wparam, lparam);
}

static LRESULT CALLBACK cbt_proc(int code, WPARAM wparam, LPARAM lparam)
{
    if (code == HCBT_DESTROYWND && (HWND)wparam == destroy_window) return 1;
    return CallNextHookEx(NULL, code, wparam, lparam);
}

static void child_process(char **argv)
{
    HANDLE event;
    HWND hwnd;

    sscanf(argv[3], "%p", &hwnd);
    sscanf(argv[4], "%p", &event);
    if (WaitForSingleObject(event, 5000) != WAIT_OBJECT_0) ExitProcess(2);
    ExitProcess(pIsWindowInDestroy && pIsWindowInDestroy(hwnd) ? 0 : 1);
}

static void test_window_destroy_state(char **argv)
{
    SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
    STARTUPINFOA startup = {sizeof(startup)};
    PROCESS_INFORMATION info;
    WNDCLASSA class = {0};
    char cmd[MAX_PATH];
    HHOOK hook;
    ATOM atom;
    BOOL ret;

    if (!pIsWindowInDestroy)
    {
        win_skip("IsWindowInDestroy is unavailable\n");
        return;
    }

    class.lpfnWndProc = window_proc;
    class.hInstance = GetModuleHandleA(NULL);
    class.lpszClassName = "window_lifecycle_test";
    atom = RegisterClassA(&class);
    ok(atom, "RegisterClassA failed, error %lu\n", GetLastError());
    if (!atom) return;

    destroy_window = CreateWindowExA(0, class.lpszClassName, NULL, WS_POPUP, 0, 0, 32, 32,
            NULL, NULL, class.hInstance, NULL);
    ok(!!destroy_window, "CreateWindowExA failed, error %lu\n", GetLastError());
    if (!destroy_window) goto done;

    ok(!pIsWindowInDestroy(destroy_window), "window %p is already marked as destroying\n", destroy_window);
    ok(!pIsWindowInDestroy((HWND)(ULONG_PTR)0xdeadbeef), "invalid window is marked as destroying\n");

    hook = SetWindowsHookExA(WH_CBT, cbt_proc, NULL, GetCurrentThreadId());
    ok(!!hook, "SetWindowsHookExA failed, error %lu\n", GetLastError());
    if (hook)
    {
        ret = DestroyWindow(destroy_window);
        ok(!ret, "DestroyWindow succeeded despite the CBT veto\n");
        ok(IsWindow(destroy_window), "CBT veto destroyed window %p\n", destroy_window);
        ok(!pIsWindowInDestroy(destroy_window), "CBT-vetoed window %p is marked as destroying\n", destroy_window);
        UnhookWindowsHookEx(hook);
    }

    destroy_event = CreateEventA(&security, FALSE, FALSE, NULL);
    ok(!!destroy_event, "CreateEventA failed, error %lu\n", GetLastError());
    if (destroy_event)
    {
        sprintf(cmd, "%s %s child %p %p", argv[0], argv[1], destroy_window, destroy_event);
        ret = CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &startup, &info);
        ok(ret, "CreateProcessA failed, error %lu\n", GetLastError());
        if (ret)
        {
            CloseHandle(info.hThread);
            destroy_process = info.hProcess;
        }
    }

    ret = DestroyWindow(destroy_window);
    ok(ret, "DestroyWindow failed, error %lu\n", GetLastError());
    ok(!pIsWindowInDestroy(destroy_window), "destroyed window %p is still marked as destroying\n", destroy_window);

done:
    if (destroy_process) CloseHandle(destroy_process);
    if (destroy_event) CloseHandle(destroy_event);
    destroy_process = NULL;
    destroy_event = NULL;
    destroy_window = NULL;
    UnregisterClassA(class.lpszClassName, class.hInstance);
}

START_TEST(window_lifecycle)
{
    char **argv;
    int argc = winetest_get_mainargs(&argv);
    HMODULE user32 = GetModuleHandleA("user32.dll");

    pIsWindowInDestroy = (void *)GetProcAddress(user32, "IsWindowInDestroy");
    if (argc == 5 && !strcmp(argv[2], "child"))
    {
        child_process(argv);
        return;
    }

    test_window_destroy_state(argv);
}
