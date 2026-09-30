/*
 * Profile API tests
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "wine/test.h"

typedef HRESULT (WINAPI *open_package_registry)(const WCHAR *, const WCHAR *, const WCHAR *,
                                                REGSAM, HKEY *);

static void test_open_package_registry(void)
{
    static const WCHAR storage[] =
        L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage";
    static const WCHAR value_name[] = L"Owner";
    static const DWORD root_value = 0x12345678, child_value = 0x87654321;
    WCHAR family[80], family_path[256], child_path[320];
    open_package_registry open_registry;
    DWORD disposition, type, value, size;
    HMODULE module;
    HRESULT hr;
    HKEY key;
    LSTATUS status;

    module = LoadLibraryA("profapi.dll");
    ok(!!module, "failed to load profapi.dll, error %lu.\n", GetLastError());
    if (!module) return;

    open_registry = (void *)GetProcAddress(module, (const char *)114);
    ok(!!open_registry, "ordinal 114 is missing.\n");
    if (!open_registry)
    {
        FreeLibrary(module);
        return;
    }

    swprintf(family, ARRAY_SIZE(family), L"LinuxNT.Profapi.Test.%08lx", GetCurrentProcessId());
    swprintf(family_path, ARRAY_SIZE(family_path), L"%s\\%s", storage, family);
    swprintf(child_path, ARRAY_SIZE(child_path), L"%s\\Children\\Child\\Settings", family_path);

    status = RegCreateKeyExW(HKEY_CURRENT_USER, family_path, 0, NULL, 0,
                             KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, NULL, &key, &disposition);
    ok(!status, "failed to create family key, status %ld.\n", status);
    if (status) goto done;
    status = RegSetValueExW(key, value_name, 0, REG_DWORD, (const BYTE *)&root_value,
                            sizeof(root_value));
    ok(!status, "failed to set family value, status %ld.\n", status);
    RegCloseKey(key);

    status = RegCreateKeyExW(HKEY_CURRENT_USER, child_path, 0, NULL, 0,
                             KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, NULL, &key, &disposition);
    ok(!status, "failed to create child key, status %ld.\n", status);
    if (!status)
    {
        status = RegSetValueExW(key, value_name, 0, REG_DWORD, (const BYTE *)&child_value,
                                sizeof(child_value));
        ok(!status, "failed to set child value, status %ld.\n", status);
        RegCloseKey(key);
    }

    key = (HKEY)0xdeadbeef;
    hr = open_registry(NULL, NULL, NULL, KEY_READ, &key);
    ok(hr == E_INVALIDARG, "null family returned %#lx.\n", hr);
    ok(key == (HKEY)0xdeadbeef, "null family changed key to %p.\n", key);

    hr = open_registry(family, NULL, NULL, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key);
    ok(hr == S_OK, "family open returned %#lx.\n", hr);
    if (SUCCEEDED(hr))
    {
        type = 0;
        value = 0;
        size = sizeof(value);
        status = RegQueryValueExW(key, value_name, NULL, &type, (BYTE *)&value, &size);
        ok(!status, "family value query failed, status %ld.\n", status);
        ok(type == REG_DWORD && value == root_value, "got type %lu, value %#lx.\n", type, value);
        RegCloseKey(key);
    }

    hr = open_registry(family, L"Child", L"Settings",
                       KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key);
    ok(hr == S_OK, "child open returned %#lx.\n", hr);
    if (SUCCEEDED(hr))
    {
        type = 0;
        value = 0;
        size = sizeof(value);
        status = RegQueryValueExW(key, value_name, NULL, &type, (BYTE *)&value, &size);
        ok(!status, "child value query failed, status %ld.\n", status);
        ok(type == REG_DWORD && value == child_value, "got type %lu, value %#lx.\n", type, value);
        RegCloseKey(key);
    }

    key = (HKEY)0xdeadbeef;
    hr = open_registry(family, NULL, L"Missing", KEY_READ | KEY_WOW64_64KEY, &key);
    ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), "missing subkey returned %#lx.\n", hr);
    ok(!key, "missing subkey returned key %p.\n", key);

done:
    RegDeleteTreeW(HKEY_CURRENT_USER, family_path);
    FreeLibrary(module);
}

START_TEST(profapi)
{
    test_open_package_registry();
}
