/* Registry fallback policy tests.
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

static LSTATUS (WINAPI *get_value)(HKEY, const WCHAR *, HKEY, const WCHAR *, const WCHAR *,
                                   DWORD, DWORD *, void *, DWORD, DWORD *);
static LSTATUS (WINAPI *get_persisted_value)(const WCHAR *, const WCHAR *, const WCHAR *,
                                             DWORD, DWORD *, void *, DWORD, DWORD *);
static LSTATUS (WINAPI *set_persisted_bool)(const WCHAR *, const WCHAR *, const WCHAR *, BOOL);
static LSTATUS (WINAPI *set_persisted_string)(const WCHAR *, const WCHAR *, const WCHAR *,
                                              const WCHAR *);
static LSTATUS (WINAPI *open_key_internal)(HKEY, const WCHAR *, DWORD, REGSAM, PHKEY, void *);

static void test_open_key_internal(void)
{
    HKEY key = NULL;
    LSTATUS status;

    open_key_internal = (void *)GetProcAddress(GetModuleHandleA("kernelbase.dll"),
                                               "RegOpenKeyExInternalW");
    if (!open_key_internal)
    {
        win_skip("RegOpenKeyExInternalW is not available.\n");
        return;
    }

    status = open_key_internal(HKEY_CURRENT_USER, L"Software", 0, KEY_READ, &key, NULL);
    ok(status == ERROR_SUCCESS, "RegOpenKeyExInternalW returned %ld.\n", status);
    ok(!!key, "RegOpenKeyExInternalW returned a null key.\n");
    if (key) RegCloseKey(key);
}

static void test_persisted_registry_value(void)
{
    static const WCHAR path[] = L"Software\\Wine\\Tests\\StateHelpers\\Persisted";
    static const WCHAR string_value[] = L"persisted";
    DWORD value = 42, result = 0, size = sizeof(result), type = 0;
    WCHAR string_result[16];
    HKEY key;
    LSTATUS status;

    get_persisted_value = (void *)GetProcAddress(GetModuleHandleA("kernelbase.dll"),
                                                 "GetPersistedRegistryValueW");
    set_persisted_bool = (void *)GetProcAddress(GetModuleHandleA("kernelbase.dll"),
                                                "SetPersistedRegistryBOOL");
    set_persisted_string = (void *)GetProcAddress(GetModuleHandleA("kernelbase.dll"),
                                                  "SetPersistedRegistryString");
    if (!get_persisted_value)
    {
        win_skip("GetPersistedRegistryValueW is not available.\n");
        return;
    }
    if (!set_persisted_bool || !set_persisted_string)
    {
        win_skip("Persisted-registry setters are not available.\n");
        return;
    }
    if (!winetest_platform_is_wine)
    {
        win_skip("Wine's unseparated persisted-registry path is Wine-specific.\n");
        return;
    }

    RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"Software\\Wine\\Tests\\StateHelpers");
    status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, path, 0, NULL, 0, KEY_WRITE,
                             NULL, &key, NULL);
    ok(status == ERROR_SUCCESS, "RegCreateKeyExW returned %ld.\n", status);
    if (status) return;

    status = RegSetValueExW(key, L"Value", 0, REG_DWORD, (const BYTE *)&value, sizeof(value));
    ok(status == ERROR_SUCCESS, "RegSetValueExW returned %ld.\n", status);
    RegCloseKey(key);

    status = get_persisted_value(L"WineTests", path, L"Value", RRF_RT_REG_DWORD,
                                 &type, &result, sizeof(result), &size);
    ok(status == ERROR_SUCCESS, "GetPersistedRegistryValueW returned %ld.\n", status);
    ok(type == REG_DWORD, "got type %lu.\n", type);
    ok(size == sizeof(result), "got size %lu.\n", size);
    ok(result == value, "got value %lu.\n", result);

    RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"Software\\Wine\\Tests\\StateHelpers");

    status = set_persisted_bool(L"WineTests", path, L"Bool", TRUE);
    ok(status == ERROR_SUCCESS, "SetPersistedRegistryBOOL returned %ld.\n", status);

    size = sizeof(result);
    result = 0;
    status = RegGetValueW(HKEY_LOCAL_MACHINE, path, L"Bool", RRF_RT_REG_DWORD,
                          &type, &result, &size);
    ok(status == ERROR_SUCCESS, "RegGetValueW returned %ld.\n", status);
    ok(result == TRUE, "got Boolean value %lu.\n", result);

    status = set_persisted_string(L"WineTests", path, L"String", string_value);
    ok(status == ERROR_SUCCESS, "SetPersistedRegistryString returned %ld.\n", status);

    size = sizeof(string_result);
    status = RegGetValueW(HKEY_LOCAL_MACHINE, path, L"String", RRF_RT_REG_SZ,
                          &type, string_result, &size);
    ok(status == ERROR_SUCCESS, "RegGetValueW returned %ld.\n", status);
    ok(!lstrcmpW(string_result, string_value), "got wrong persisted string.\n");

    RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"Software\\Wine\\Tests\\StateHelpers");
}

START_TEST(state_helpers)
{
    static const WCHAR primary_path[] = L"Software\\Wine\\Tests\\StateHelpers\\Primary";
    static const WCHAR fallback_path[] = L"Software\\Wine\\Tests\\StateHelpers\\Fallback";
    static const WCHAR primary_data[] = L"primary";
    static const WCHAR fallback_data[] = L"fallback";
    HKEY key;
    WCHAR buffer[32];
    DWORD size, type;
    LSTATUS status;

    test_open_key_internal();
    test_persisted_registry_value();

    get_value = (void *)GetProcAddress(GetModuleHandleA("kernelbase.dll"),
                                       "GetRegistryValueWithFallbackW");
    if (!get_value)
    {
        win_skip("GetRegistryValueWithFallbackW is not available.\n");
        return;
    }

    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Wine\\Tests\\StateHelpers");
    status = RegCreateKeyExW(HKEY_CURRENT_USER, primary_path, 0, NULL, 0, KEY_WRITE,
                             NULL, &key, NULL);
    ok(status == ERROR_SUCCESS, "RegCreateKeyExW returned %ld.\n", status);
    if (!status)
    {
        RegSetValueExW(key, L"Value", 0, REG_SZ, (const BYTE *)primary_data,
                       sizeof(primary_data));
        RegCloseKey(key);
    }
    status = RegCreateKeyExW(HKEY_CURRENT_USER, fallback_path, 0, NULL, 0, KEY_WRITE,
                             NULL, &key, NULL);
    ok(status == ERROR_SUCCESS, "RegCreateKeyExW returned %ld.\n", status);
    if (!status)
    {
        RegSetValueExW(key, L"Value", 0, REG_SZ, (const BYTE *)fallback_data,
                       sizeof(fallback_data));
        RegSetValueExW(key, L"FallbackOnly", 0, REG_SZ, (const BYTE *)fallback_data,
                       sizeof(fallback_data));
        RegCloseKey(key);
    }

    memset(buffer, 0xcc, sizeof(buffer));
    size = 0xdeadbeef;
    status = get_value(HKEY_CURRENT_USER, primary_path, HKEY_CURRENT_USER, fallback_path,
                       L"Value", RRF_RT_REG_SZ, &type, buffer, sizeof(buffer), &size);
    ok(status == ERROR_SUCCESS, "get_value returned %ld.\n", status);
    ok(type == REG_SZ, "got type %lu.\n", type);
    ok(size == sizeof(primary_data), "got size %lu.\n", size);
    ok(!memcmp(buffer, primary_data, sizeof(primary_data)), "got wrong primary value.\n");

    memset(buffer, 0xcc, sizeof(buffer));
    status = get_value(HKEY_CURRENT_USER, primary_path, HKEY_CURRENT_USER, fallback_path,
                       L"FallbackOnly", RRF_RT_REG_SZ, &type, buffer, sizeof(buffer), &size);
    ok(status == ERROR_SUCCESS, "get_value returned %ld.\n", status);
    ok(size == sizeof(fallback_data), "got size %lu.\n", size);
    ok(!memcmp(buffer, fallback_data, sizeof(fallback_data)), "got wrong fallback value.\n");

    status = get_value(NULL, primary_path, HKEY_CURRENT_USER, fallback_path,
                       L"Value", RRF_RT_REG_SZ, &type, buffer, sizeof(buffer), &size);
    ok(status == ERROR_SUCCESS, "get_value returned %ld.\n", status);
    ok(size == sizeof(fallback_data), "got size %lu.\n", size);
    ok(!memcmp(buffer, fallback_data, sizeof(fallback_data)), "got wrong fallback value.\n");

    size = 17;
    status = get_value(NULL, NULL, NULL, NULL, L"Value", 0, NULL, NULL, size, &size);
    ok(status == ERROR_INVALID_PARAMETER, "get_value returned %ld.\n", status);
    ok(size == 17, "got size %lu.\n", size);

    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Wine\\Tests\\StateHelpers");
}
