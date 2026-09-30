/*
 * AppModel application state tests
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
#include "winerror.h"
#include "appmodel.h"
#include "wine/test.h"

typedef LONG (WINAPI *token_identity_query)(HANDLE, UINT32 *, WCHAR *);
typedef LONG (WINAPI *package_path_query)(const WCHAR *, UINT32, UINT32 *, WCHAR *);
typedef HRESULT (WINAPI *package_alias_query)(UINT32, UINT32 *, void *, UINT32 *);
typedef HRESULT (WINAPI *package_info3_query)(UINT32, UINT32, UINT32 *, void *, UINT32 *);

static void test_open_state_unpackaged_identity(void)
{
    void *(WINAPI *open_state)(void);
    LONG (WINAPI *get_current_package_family_name)(UINT32 *, WCHAR *);
    UINT32 length = 0;
    unsigned int i;
    LONG status;
    void *state;

    open_state = (void *)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "OpenState");
    get_current_package_family_name = (void *)GetProcAddress(GetModuleHandleA("kernelbase.dll"),
                                                             "GetCurrentPackageFamilyName");
    if (!open_state || !get_current_package_family_name)
    {
        win_skip("OpenState is not available.\n");
        return;
    }

    SetLastError(0x0badf00d);
    status = get_current_package_family_name(&length, NULL);
    ok(status == APPMODEL_ERROR_NO_PACKAGE, "got package status %#lx.\n", status);
    ok(!length, "got package family length %u.\n", length);
    ok(GetLastError() == 0x0badf00d, "package query changed last error to %lu.\n", GetLastError());

    for (i = 0; i < 2; ++i)
    {
        SetLastError(0x13579bdf + i);
        state = open_state();
        ok(!state, "call %u returned state %p.\n", i, state);
        ok(GetLastError() == APPMODEL_ERROR_NO_PACKAGE, "call %u set last error to %lu.\n",
           i, GetLastError());
    }
}

static void test_token_package_identity(void)
{
    static const struct
    {
        const char *name;
        LONG no_identity;
    }
    functions[] =
    {
        { "GetPackageFamilyNameFromToken", APPMODEL_ERROR_NO_PACKAGE },
        { "GetPackageFullNameFromToken", APPMODEL_ERROR_NO_PACKAGE },
        { "GetApplicationUserModelIdFromToken", APPMODEL_ERROR_NO_APPLICATION },
    };
    HANDLE process_token, impersonation_token;
    WCHAR buffer[4];
    UINT32 length;
    unsigned int i;
    LONG status;
    BOOL ret;

    ret = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &process_token);
    ok(ret, "OpenProcessToken failed, error %lu.\n", GetLastError());
    if (!ret) return;
    ret = DuplicateToken(process_token, SecurityImpersonation, &impersonation_token);
    ok(ret, "DuplicateToken failed, error %lu.\n", GetLastError());
    if (!ret)
    {
        CloseHandle(process_token);
        return;
    }

    for (i = 0; i < ARRAY_SIZE(functions); ++i)
    {
        token_identity_query query = (void *)GetProcAddress(GetModuleHandleA("kernelbase.dll"), functions[i].name);
        if (!query)
        {
            win_skip("%s is not available.\n", functions[i].name);
            continue;
        }

        length = 0;
        SetLastError(0x13579bdf);
        status = query(process_token, &length, NULL);
        ok(status == functions[i].no_identity, "%s returned %#lx.\n", functions[i].name, status);
        ok(!length, "%s changed length to %u.\n", functions[i].name, length);
        ok(GetLastError() == 0x13579bdf, "%s changed last error to %lu.\n",
           functions[i].name, GetLastError());

        memset(buffer, 0xcc, sizeof(buffer));
        length = ARRAY_SIZE(buffer);
        status = query(process_token, &length, buffer);
        ok(status == functions[i].no_identity, "%s returned %#lx.\n", functions[i].name, status);
        ok(length == ARRAY_SIZE(buffer), "%s changed length to %u.\n", functions[i].name, length);
        ok(buffer[0] == 0xcccc && buffer[3] == 0xcccc, "%s changed the output buffer.\n", functions[i].name);

        length = ARRAY_SIZE(buffer);
        status = query(process_token, &length, NULL);
        ok(status == ERROR_INVALID_PARAMETER, "%s returned %#lx.\n", functions[i].name, status);

        length = 0;
        status = query(impersonation_token, &length, NULL);
        ok(status == functions[i].no_identity, "%s returned %#lx.\n", functions[i].name, status);
        status = query((HANDLE)0xdead, &length, NULL);
        ok(status == ERROR_INVALID_HANDLE, "%s returned %#lx.\n", functions[i].name, status);
        status = query(NULL, &length, NULL);
        ok(status == ERROR_INVALID_PARAMETER, "%s returned %#lx.\n", functions[i].name, status);
        status = query(process_token, NULL, NULL);
        ok(status == ERROR_INVALID_PARAMETER, "%s returned %#lx.\n", functions[i].name, status);
    }

    CloseHandle(impersonation_token);
    CloseHandle(process_token);
}

static void test_package_path_validation(void)
{
    static const char *names[] =
    {
        "GetPackagePathByFullName2",
        "GetStagedPackagePathByFullName2",
    };
    static const WCHAR full_name[] = L"Test.Package_1.0.0.0_neutral__123456789abcd";
    WCHAR buffer[2];
    HMODULE module = GetModuleHandleA("kernelbase.dll");
    package_path_query query;
    UINT32 length;
    unsigned int i;
    LONG status;

    for (i = 0; i < ARRAY_SIZE(names); ++i)
    {
        query = (void *)GetProcAddress(module, names[i]);
        if (!query)
        {
            win_skip("%s is not available.\n", names[i]);
            continue;
        }

        length = 0;
        status = query(NULL, PackagePathType_Install, &length, NULL);
        ok(status == ERROR_INVALID_PARAMETER, "%s returned %#lx.\n", names[i], status);
        status = query(full_name, PackagePathType_Install, NULL, NULL);
        ok(status == ERROR_INVALID_PARAMETER, "%s returned %#lx.\n", names[i], status);
        length = ARRAY_SIZE(buffer);
        status = query(full_name, PackagePathType_Install, &length, NULL);
        ok(status == ERROR_INVALID_PARAMETER, "%s returned %#lx.\n", names[i], status);
        length = 0;
        status = query(full_name, PackagePathType_EffectiveExternal + 1, &length, NULL);
        ok(status == ERROR_INVALID_PARAMETER, "%s returned %#lx.\n", names[i], status);
    }
}

static void test_package_alias_validation(void)
{
    package_alias_query query;
    package_info3_query query3;
    BYTE buffer[16];
    UINT32 count, size;
    HRESULT hr;

    query = (void *)GetProcAddress(GetModuleHandleA("kernelbase.dll"),
                                   "GetCurrentPackageInfo_PackageNameAliases");
    if (!query)
    {
        win_skip("GetCurrentPackageInfo_PackageNameAliases is not available.\n");
        return;
    }

    hr = query(0, NULL, NULL, NULL);
    ok(hr == E_INVALIDARG, "got hr %#lx.\n", hr);

    size = 1;
    hr = query(0, &size, NULL, NULL);
    ok(hr == E_INVALIDARG, "got hr %#lx.\n", hr);

    size = sizeof(buffer);
    hr = query(0, &size, buffer, NULL);
    ok(hr == E_INVALIDARG, "got hr %#lx.\n", hr);

    size = 0;
    count = 0xcccccccc;
    hr = query(0, &size, NULL, &count);
    ok(hr == S_OK, "got hr %#lx.\n", hr);
    ok(!size, "got size %u.\n", size);
    ok(!count, "got count %u.\n", count);

    query3 = (void *)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "GetCurrentPackageInfo3");
    if (!query3)
    {
        win_skip("GetCurrentPackageInfo3 is not available.\n");
        return;
    }

    hr = query3(0, 0x11, NULL, NULL, NULL);
    ok(hr == E_INVALIDARG, "got hr %#lx.\n", hr);

    size = 1;
    hr = query3(0, 0x11, &size, NULL, NULL);
    ok(hr == E_INVALIDARG, "got hr %#lx.\n", hr);

    size = sizeof(buffer);
    hr = query3(0, 0x11, &size, buffer, NULL);
    ok(hr == E_INVALIDARG, "got hr %#lx.\n", hr);
}

START_TEST(appmodel_state)
{
    test_open_state_unpackaged_identity();
    test_token_package_identity();
    test_package_path_validation();
    test_package_alias_validation();
}
