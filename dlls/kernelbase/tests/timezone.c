/* Private client timezone notification tests.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "timezoneapi.h"
#include "wine/test.h"

static BOOL (WINAPI *set_client_dynamic_timezone)(const DYNAMIC_TIME_ZONE_INFORMATION *);
static BOOL (WINAPI *set_client_timezone)(const TIME_ZONE_INFORMATION *);

START_TEST(timezone)
{
    DYNAMIC_TIME_ZONE_INFORMATION dynamic = {0};
    TIME_ZONE_INFORMATION classic = {0};
    HMODULE module = GetModuleHandleA("kernelbase.dll");
    BOOL ret;

    set_client_dynamic_timezone = (void *)GetProcAddress(module, "SetClientDynamicTimeZoneInformation");
    set_client_timezone = (void *)GetProcAddress(module, "SetClientTimeZoneInformation");
    ok(!!set_client_dynamic_timezone, "SetClientDynamicTimeZoneInformation is not exported.\n");
    ok(!!set_client_timezone, "SetClientTimeZoneInformation is not exported.\n");
    if (!set_client_dynamic_timezone || !set_client_timezone) return;

    SetLastError(0xdeadbeef);
    ret = set_client_dynamic_timezone(&dynamic);
    ok(ret, "SetClientDynamicTimeZoneInformation failed, error %lu.\n", GetLastError());
    ok(GetLastError() == 0xdeadbeef, "Last error changed to %lu.\n", GetLastError());

    SetLastError(0xdeadbeef);
    ret = set_client_timezone(&classic);
    ok(ret, "SetClientTimeZoneInformation failed, error %lu.\n", GetLastError());
    ok(GetLastError() == 0xdeadbeef, "Last error changed to %lu.\n", GetLastError());
}
