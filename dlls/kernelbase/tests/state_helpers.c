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
