/*
 * Blocked-shutdown resolver window tests
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>

#include "wine/test.h"

static HWND (WINAPI *pQueryBSDRWindow)(void);
static BOOL (WINAPI *pRegisterBSDRWindow)(HWND, DWORD);
static DWORD (WINAPI *pRegisterLogonProcess)(DWORD, BOOL);

static BOOL set_tcb_privilege(BOOL enable)
{
    TOKEN_PRIVILEGES privileges;
    HANDLE token;
    BOOL ret;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return FALSE;

    privileges.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(NULL, L"SeTcbPrivilege", &privileges.Privileges[0].Luid))
    {
        CloseHandle(token);
        return FALSE;
    }
    privileges.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
    SetLastError(ERROR_SUCCESS);
    ret = AdjustTokenPrivileges(token, FALSE, &privileges, 0, NULL, NULL);
    if (ret && GetLastError() == ERROR_NOT_ALL_ASSIGNED) ret = FALSE;
    CloseHandle(token);
    return ret;
}

static BOOL register_after_owner_exit(char **argv)
{
    STARTUPINFOA startup = { .cb = sizeof(startup) };
    PROCESS_INFORMATION process = {0};
    char command[MAX_PATH * 3];
    BOOL ret;

    sprintf(command, "\"%s\" %s owner-child %lu", argv[0], argv[1], GetCurrentProcessId());
    ret = CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process);
    ok(ret, "failed to create owner child, error %lu\n", GetLastError());
    if (!ret) return FALSE;
    wait_child_process(&process);

    if (!set_tcb_privilege(TRUE))
    {
        win_skip("SeTcbPrivilege is unavailable\n");
        return FALSE;
    }
    ret = pRegisterLogonProcess(GetCurrentProcessId(), TRUE);
    ok(ret, "failed to replace exited logon owner, error %lu\n", GetLastError());
    set_tcb_privilege(FALSE);
    return ret;
}

static void test_bsdr_window(char **argv)
{
    HINSTANCE instance = GetModuleHandleW(NULL);
    HWND first, second, dead;
    BOOL ret;

    ok(!pQueryBSDRWindow(), "expected no initial BSDR window\n");

    first = CreateWindowExW(0, L"static", L"first", WS_OVERLAPPED,
                            0, 0, 100, 100, NULL, NULL, instance, NULL);
    second = CreateWindowExW(0, L"static", L"second", WS_OVERLAPPED,
                             0, 0, 100, 100, NULL, NULL, instance, NULL);
    dead = CreateWindowExW(0, L"static", L"dead", WS_OVERLAPPED,
                           0, 0, 100, 100, NULL, NULL, instance, NULL);
    ok(!!first && !!second && !!dead, "failed to create test windows, error %lu\n", GetLastError());
    if (!first || !second || !dead) goto done;

    set_tcb_privilege(FALSE);
    SetLastError(0xdeadbeef);
    ret = pRegisterBSDRWindow(first, 0);
    ok(!ret, "unregistered process unexpectedly registered a BSDR window\n");
    ok(GetLastError() == ERROR_ACCESS_DENIED, "expected ERROR_ACCESS_DENIED, got %lu\n", GetLastError());

    if (!register_after_owner_exit(argv)) goto done;

    ret = pRegisterBSDRWindow(first, 0);
    ok(ret, "RegisterBSDRWindow failed, error %lu\n", GetLastError());
    ok(pQueryBSDRWindow() == first, "expected %p, got %p\n", first, pQueryBSDRWindow());

    ret = pRegisterBSDRWindow(second, 4);
    ok(ret, "replacing BSDR window failed, error %lu\n", GetLastError());
    ok(pQueryBSDRWindow() == second, "expected %p, got %p\n", second, pQueryBSDRWindow());

    DestroyWindow(dead);
    SetLastError(0xdeadbeef);
    ret = pRegisterBSDRWindow(dead, 0);
    ok(!ret, "destroyed window unexpectedly registered\n");
    ok(GetLastError() == ERROR_INVALID_WINDOW_HANDLE,
       "expected ERROR_INVALID_WINDOW_HANDLE, got %lu\n", GetLastError());
    ok(pQueryBSDRWindow() == second, "failed registration replaced the BSDR window\n");
    dead = NULL;

    ret = pRegisterBSDRWindow(first, 0);
    ok(ret, "RegisterBSDRWindow failed, error %lu\n", GetLastError());
    DestroyWindow(first);
    first = NULL;
    ok(!pQueryBSDRWindow(), "destroyed BSDR window was not cleared\n");

    ret = pRegisterBSDRWindow(second, 0);
    ok(ret, "RegisterBSDRWindow failed, error %lu\n", GetLastError());
    ret = pRegisterBSDRWindow(NULL, 0);
    ok(ret, "clearing BSDR window failed, error %lu\n", GetLastError());
    ok(!pQueryBSDRWindow(), "BSDR window was not cleared\n");

done:
    if (dead) DestroyWindow(dead);
    if (second) DestroyWindow(second);
    if (first) DestroyWindow(first);
}

START_TEST(bsdr)
{
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    char **argv;
    int argc;

    pQueryBSDRWindow = (void *)GetProcAddress(user32, "QueryBSDRWindow");
    pRegisterBSDRWindow = (void *)GetProcAddress(user32, "RegisterBSDRWindow");
    pRegisterLogonProcess = (void *)GetProcAddress(user32, "RegisterLogonProcess");
    if (!pQueryBSDRWindow || !pRegisterBSDRWindow || !pRegisterLogonProcess)
    {
        win_skip("BSDR registration APIs are unavailable\n");
        return;
    }

    argc = winetest_get_mainargs(&argv);
    if (argc > 3 && !strcmp(argv[2], "owner-child"))
    {
        BOOL ret;

        if (!set_tcb_privilege(TRUE))
        {
            win_skip("SeTcbPrivilege is unavailable\n");
            return;
        }
        ret = pRegisterLogonProcess(strtoul(argv[3], NULL, 10), TRUE);
        ok(ret, "child RegisterLogonProcess failed, error %lu\n", GetLastError());
        return;
    }

    test_bsdr_window(argv);
}
