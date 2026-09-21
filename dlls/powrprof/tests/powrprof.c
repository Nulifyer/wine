/*
 * Copyright 2026 LinuxNT project
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "windows.h"
#include "winternl.h"
#include "powrprof.h"
#include "wine/test.h"

#define POWER_SETTING_NOTIFY_CALLBACK 2

struct power_setting_callback
{
    ULONG (CALLBACK *callback)(void *, ULONG, void *);
    void *context;
};

static const GUID monitor_power_on =
    {0x02731015, 0x4510, 0x4526, {0x99, 0xe6, 0xe5, 0xa1, 0x7e, 0xbd, 0x1a, 0xea}};

static ULONG CALLBACK power_callback(void *context, ULONG type, void *setting)
{
    return ERROR_SUCCESS;
}

START_TEST(powrprof)
{
    struct power_setting_callback callback = {power_callback, (void *)0x1234};
    DWORD (WINAPI *register_ex)(const GUID *, DWORD, DWORD, HANDLE, PHPOWERNOTIFY);
    HPOWERNOTIFY first = (HPOWERNOTIFY)0xdeadbeef, second = (HPOWERNOTIFY)0xdeadbeef;
    HMODULE module = GetModuleHandleA("powrprof.dll");
    DWORD ret;

    register_ex = (void *)GetProcAddress(module, "PowerSettingRegisterNotificationEx");
    if (!register_ex)
    {
        win_skip("PowerSettingRegisterNotificationEx is unavailable\n");
        return;
    }

    ret = register_ex(&monitor_power_on, ~0u, POWER_SETTING_NOTIFY_CALLBACK,
                      (HANDLE)&callback, NULL);
    ok(ret == ERROR_INVALID_PARAMETER, "got %lu\n", ret);

    ret = register_ex(&monitor_power_on, ~0u, 0, (HANDLE)&callback, &first);
    ok(ret == ERROR_INVALID_PARAMETER, "got %lu\n", ret);
    ok(first == (HPOWERNOTIFY)0xdeadbeef, "handle changed to %p\n", first);

    ret = register_ex(&monitor_power_on, ~0u, POWER_SETTING_NOTIFY_CALLBACK, NULL, &first);
    ok(ret == ERROR_INVALID_PARAMETER, "got %lu\n", ret);
    ok(first == (HPOWERNOTIFY)0xdeadbeef, "handle changed to %p\n", first);

    ret = register_ex(&monitor_power_on, ~0u, POWER_SETTING_NOTIFY_CALLBACK,
                      (HANDLE)&callback, &first);
    ok(!ret, "got %lu\n", ret);
    ok(first && first != (HPOWERNOTIFY)0xdeadbeef, "got handle %p\n", first);

    ret = register_ex(&monitor_power_on, 1, POWER_SETTING_NOTIFY_CALLBACK,
                      (HANDLE)&callback, &second);
    ok(!ret, "got %lu\n", ret);
    ok(second && second != (HPOWERNOTIFY)0xdeadbeef, "got handle %p\n", second);
    ok(second != first, "registrations share handle %p\n", first);

    ret = PowerSettingUnregisterNotification(first);
    ok(!ret, "got %lu\n", ret);
    ret = PowerSettingUnregisterNotification(second);
    ok(!ret, "got %lu\n", ret);

    first = (HPOWERNOTIFY)0xdeadbeef;
    ret = PowerSettingRegisterNotification(&monitor_power_on, POWER_SETTING_NOTIFY_CALLBACK,
                                           (HANDLE)&callback, &first);
    ok(!ret, "got %lu\n", ret);
    ok(first && first != (HPOWERNOTIFY)0xdeadbeef, "got handle %p\n", first);
    ret = PowerSettingUnregisterNotification(first);
    ok(!ret, "got %lu\n", ret);

    ret = PowerSettingUnregisterNotification(NULL);
    ok(ret == ERROR_INVALID_PARAMETER, "got %lu\n", ret);
}
