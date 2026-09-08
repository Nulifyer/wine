/* Tests for per-user Active Setup
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdio.h>
#include <wchar.h>
#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "winuser.h"
#include "objbase.h"
#include "wine/test.h"

static void (WINAPI *run_setup)(const WCHAR *);
static WCHAR component[80];

static DWORD WINAPI setup_thread(void *context)
{
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ok(SUCCEEDED(hr), "COM initialization failed: %#lx.\n", hr);
    run_setup(component);
    if (SUCCEEDED(hr)) CoUninitialize();
    return 0;
}

static BOOL CALLBACK answer_removal(HWND window, LPARAM answer)
{
    WCHAR class_name[64];
    GetClassNameW(window, class_name, ARRAY_SIZE(class_name));
    if (!wcscmp(class_name, L"#32770") && GetDlgItem(window, IDYES) && GetDlgItem(window, IDNO))
        PostMessageW(window, WM_COMMAND, answer, 0);
    return TRUE;
}

static BOOL call_setup(int answer)
{
    DWORD tid, wait, ticks = 0;
    HANDLE thread = CreateThread(NULL, 0, setup_thread, NULL, 0, &tid);
    ok(!!thread, "CreateThread failed: %lu.\n", GetLastError());
    if (!thread) return FALSE;
    while ((wait = WaitForSingleObject(thread, 100)) == WAIT_TIMEOUT && ticks++ < 200)
        EnumThreadWindows(tid, answer_removal, answer);
    ok(wait == WAIT_OBJECT_0, "Active Setup did not return, wait %#lx.\n", wait);
    CloseHandle(thread);
    /* Do not delete a fixture's registry data while its setup thread is live. */
    if (wait != WAIT_OBJECT_0) ExitProcess(1);
    return TRUE;
}

static void write_string(HKEY key, const WCHAR *name, const WCHAR *value)
{
    LONG ret = RegSetValueExW(key, name, 0, REG_SZ, (const BYTE *)value, (wcslen(value) + 1) * sizeof(WCHAR));
    ok(!ret, "RegSetValueExW failed: %ld.\n", ret);
}

START_TEST(active_setup)
{
    static const struct
    {
        const WCHAR *version, *locale, *user_version;
        DWORD installed, expected_bytes;
        int answer;
    } cases[] =
    {
        {L"1,0,0,0", L"en-US", L"1,0,0,0", 1, 5, IDYES},
        {L"1,0,0,0", L"en-US", L"1,0,0,0", 1, 5, IDYES},
        {L"2,0,0,0", L"en-US", L"2,0,0,0", 1, 10, IDYES},
        {L"1,0,0,0", L"en-US", L"2,0,0,0", 1, 10, IDYES},
        {L"2,0,0,0", L"fr-FR", L"2,0,0,0", 1, 15, IDYES},
        {L"3,0,0,0", L"fr-FR", L"2,0,0,0", 0, 15, IDNO},
        {L"3,0,0,0", L"fr-FR", NULL, 0, 20, IDYES},
        {L"3,0,0,0", L"fr-FR", L"3,0,0,0", 1, 25, IDYES},
    };
    WCHAR path[256], marker[MAX_PATH], temp[MAX_PATH], command[2 * MAX_PATH], value[64];
    HMODULE shell = LoadLibraryW(L"shell32.dll");
    HKEY machine, user;
    DWORD disposition, size, type;
    LONG ret;
    unsigned int i;

    run_setup = (void *)GetProcAddress(shell, (const char *)885);
    if (!run_setup) { win_skip("RunInstallUninstallStubs unavailable.\n"); FreeLibrary(shell); return; }
    swprintf(component, ARRAY_SIZE(component), L"WineActiveSetup-%lu-%lu", GetCurrentProcessId(), GetTickCount());
    swprintf(path, ARRAY_SIZE(path), L"Software\\Microsoft\\Active Setup\\Installed Components\\%s", component);
    ret = RegCreateKeyExW(HKEY_LOCAL_MACHINE, path, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &machine, &disposition);
    if (ret == ERROR_ACCESS_DENIED) { win_skip("Active Setup tests require registry write access.\n"); FreeLibrary(shell); return; }
    ok(!ret, "Could not create machine component: %ld.\n", ret);
    if (ret) { FreeLibrary(shell); return; }
    ok(disposition == REG_CREATED_NEW_KEY, "Fixture component already exists.\n");
    if (disposition != REG_CREATED_NEW_KEY) { RegCloseKey(machine); FreeLibrary(shell); return; }
    GetTempPathW(ARRAY_SIZE(temp), temp);
    GetTempFileNameW(temp, L"ast", 0, marker);
    swprintf(command, ARRAY_SIZE(command), L"cmd.exe /d /c echo ran>>\"%s\"", marker);
    write_string(machine, L"StubPath", command);
    for (i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        HANDLE file;
        LARGE_INTEGER length = {0};
        winetest_push_context("case %u", i);
        write_string(machine, L"Version", cases[i].version);
        write_string(machine, L"Locale", cases[i].locale);
        ret = RegSetValueExW(machine, L"IsInstalled", 0, REG_DWORD,
                            (const BYTE *)&cases[i].installed, sizeof(DWORD));
        ok(!ret, "Could not set installed state: %ld.\n", ret);
        if (!call_setup(cases[i].answer)) { winetest_pop_context(); break; }
        ret = RegOpenKeyExW(HKEY_CURRENT_USER, path, 0, KEY_READ, &user);
        ok(ret == (cases[i].user_version ? ERROR_SUCCESS : ERROR_FILE_NOT_FOUND),
           "Unexpected user component status: %ld.\n", ret);
        if (!ret)
        {
            size = sizeof(value);
            ret = RegQueryValueExW(user, L"Version", NULL, &type, (BYTE *)value, &size);
            ok(!ret && type == REG_SZ, "Unexpected version status %ld, type %lu.\n", ret, type);
            if (!ret && cases[i].user_version)
                ok(!wcscmp(value, cases[i].user_version), "Unexpected version %s.\n", wine_dbgstr_w(value));
            RegCloseKey(user);
        }
        file = CreateFileW(marker, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        ok(file != INVALID_HANDLE_VALUE, "Could not open command marker: %lu.\n", GetLastError());
        if (file != INVALID_HANDLE_VALUE)
        {
            GetFileSizeEx(file, &length);
            CloseHandle(file);
        }
        ok(length.QuadPart == cases[i].expected_bytes, "Command marker size %s, expected %lu.\n",
           wine_dbgstr_longlong(length.QuadPart), cases[i].expected_bytes);
        winetest_pop_context();
    }
    RegCloseKey(machine);
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, path);
    RegDeleteTreeW(HKEY_CURRENT_USER, path);
    DeleteFileW(marker);
    FreeLibrary(shell);
}
