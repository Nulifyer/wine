/*
 * Copyright 2026
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "windows.h"

#include "wine/test.h"

typedef LONG (WINAPI *get_application_user_model_id_fn)(HANDLE, UINT32 *, WCHAR *);

static void test_GetApplicationUserModelId(void)
{
    get_application_user_model_id_fn get_aumid;
    WCHAR buffer[260];
    HMODULE module;
    UINT32 length;
    LONG result;

    module = GetModuleHandleW(L"kernelbase.dll");
    get_aumid = (get_application_user_model_id_fn)GetProcAddress(module, "GetApplicationUserModelId");
    ok(!!get_aumid, "GetApplicationUserModelId is not exported.\n");
    if (!get_aumid) return;

    length = 0;
    result = get_aumid(GetCurrentProcess(), &length, NULL);
    ok(result == APPMODEL_ERROR_NO_APPLICATION, "Got result %#lx.\n", result);
    ok(!length, "Got length %u.\n", length);

    length = 0xcccccccc;
    result = get_aumid(GetCurrentProcess(), &length, NULL);
    ok(result == ERROR_INVALID_PARAMETER, "Got result %#lx.\n", result);
    ok(length == 0xcccccccc, "Got length %u.\n", length);

    length = ARRAY_SIZE(buffer);
    buffer[0] = 0xcccc;
    result = get_aumid(GetCurrentProcess(), &length, buffer);
    ok(result == APPMODEL_ERROR_NO_APPLICATION, "Got result %#lx.\n", result);
    ok(length == ARRAY_SIZE(buffer), "Got length %u.\n", length);
    ok(buffer[0] == 0xcccc, "Got buffer[0] %#x.\n", buffer[0]);

    result = get_aumid(NULL, &length, buffer);
    ok(result == ERROR_INVALID_PARAMETER, "Got result %#lx.\n", result);
    result = get_aumid(GetCurrentProcess(), NULL, buffer);
    ok(result == ERROR_INVALID_PARAMETER, "Got result %#lx.\n", result);
}

START_TEST(appmodel)
{
    test_GetApplicationUserModelId();
}
