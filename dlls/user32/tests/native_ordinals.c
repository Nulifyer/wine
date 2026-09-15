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

static get_process_ui_context_information_fn pGetProcessUIContextInformation;
static is_immersive_process_fn pIsImmersiveProcess;

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

    test_gdi_scaled_process();

    module = GetModuleHandleW(L"user32.dll");
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
