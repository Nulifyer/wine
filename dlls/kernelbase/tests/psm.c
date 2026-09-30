/*
 * Process state management key tests
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "wine/test.h"
#include "winbase.h"
#include "winternl.h"

static NTSTATUS (WINAPI *create_key)(const WCHAR *, const WCHAR *, WCHAR *, UINT32 *);
static NTSTATUS (WINAPI *create_dynamic)(const WCHAR *, const WCHAR *, const GUID *, WCHAR *, UINT32 *);
static NTSTATUS (WINAPI *get_package)(const WCHAR *, WCHAR *, UINT32 *);
static NTSTATUS (WINAPI *get_application)(const WCHAR *, WCHAR *, UINT32 *);
static NTSTATUS (WINAPI *get_dynamic)(const WCHAR *, GUID *);
static NTSTATUS (WINAPI *get_aumid)(const WCHAR *, UINT32 *, WCHAR *);
static BOOLEAN (WINAPI *is_valid)(const WCHAR *);
static BOOLEAN (WINAPI *is_dynamic)(const WCHAR *);
static BOOLEAN (WINAPI *equal_package)(const WCHAR *, const WCHAR *);
static BOOLEAN (WINAPI *equal_application)(const WCHAR *, const WCHAR *);
static BOOLEAN (WINAPI *is_child)(const WCHAR *, const WCHAR *);

static const GUID dynamic_id = {0xabcdef12, 0x3456, 0x789a, {0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a}};
static const WCHAR package[] = L"Test.Package_1.2.3.4_x64__1234567890abc";

static void fill(WCHAR *buffer, unsigned int length)
{
    unsigned int i;
    for (i = 0; i < length; ++i) buffer[i] = 0xcccc;
}

static void test_constructors(void)
{
    static const WCHAR *families[] = { L"", L"x", L"not a package", package };
    static const WCHAR *apps[] = { L"", L"A", L"Not!An.Id", L"App" };
    WCHAR key[300], expected[300];
    UINT32 size, required;
    NTSTATUS status;
    unsigned int i, extra;

    for (i = 0; i < ARRAY_SIZE(families); ++i)
    {
        lstrcpyW(expected, families[i]); lstrcatW(expected, L"+"); lstrcatW(expected, apps[i]);
        required = (lstrlenW(expected) + 1) * sizeof(WCHAR);
        size = 0;
        SetLastError(0xdeadbeef);
        status = create_key(families[i], apps[i], NULL, &size);
        ok(status == STATUS_BUFFER_TOO_SMALL && size == required, "sizing returned %#lx/%u.\n", status, size);
        fill(key, ARRAY_SIZE(key)); size = required - 1;
        status = create_key(families[i], apps[i], key, &size);
        ok(status == STATUS_BUFFER_TOO_SMALL && size == required && key[0] == 0xcccc,
           "short constructor returned %#lx/%u.\n", status, size);
        size = required + 1;
        status = create_key(families[i], apps[i], key, &size);
        ok(!status && size == required && !lstrcmpW(key, expected), "constructor returned %#lx/%u %s.\n", status, size, wine_dbgstr_w(key));
        ok(key[required / 2] == 0xcccc, "constructor wrote past its terminator.\n");
        ok(GetLastError() == 0xdeadbeef, "constructor changed last error.\n");

        lstrcatW(expected, L"#{abcdef12-3456-789a-bcde-f0123456789a}");
        required = lstrlenW(expected) * sizeof(WCHAR);
        size = 0;
        status = create_dynamic(families[i], apps[i], &dynamic_id, NULL, &size);
        ok(status == STATUS_BUFFER_TOO_SMALL && size == required, "dynamic sizing %#lx/%u.\n", status, size);
        fill(key, ARRAY_SIZE(key)); size = required - 1;
        status = create_dynamic(families[i], apps[i], &dynamic_id, key, &size);
        ok(status == STATUS_BUFFER_TOO_SMALL && size == required && key[0] == 0xcccc,
           "short dynamic constructor %#lx/%u.\n", status, size);
        /* Native reports bytes excluding NUL, and ignores NULL_ON_FAILURE truncation. */
        for (extra = 0; extra < 4; ++extra)
        {
            unsigned int capacity = (required + extra) / sizeof(WCHAR);
            fill(key, ARRAY_SIZE(key)); size = required + extra;
            status = create_dynamic(families[i], apps[i], &dynamic_id, key, &size);
            ok(!status && size == required, "dynamic capacity +%u returned %#lx/%u.\n", extra, status, size);
            if (extra < sizeof(WCHAR))
            {
                ok(!key[0] && !key[capacity - 1], "truncation did not clear ends at +%u.\n", extra);
                ok(!memcmp(key + 1, expected + 1, (capacity - 2) * sizeof(WCHAR)),
                   "truncated prefix changed at +%u.\n", extra);
            }
            else ok(!lstrcmpW(key, expected), "dynamic key +%u is %s.\n", extra, wine_dbgstr_w(key));
            ok(key[capacity] == 0xcccc && GetLastError() == 0xdeadbeef,
               "dynamic changed trailing data/error at +%u.\n", extra);
        }
    }
}

static void check_reader(NTSTATUS (WINAPI *reader)(const WCHAR *, WCHAR *, UINT32 *),
                         const WCHAR *key, const WCHAR *expected, NTSTATUS wanted)
{
    WCHAR output[300];
    UINT32 size = 0, required = expected ? (lstrlenW(expected) + 1) * sizeof(WCHAR) : 0;
    NTSTATUS status;

    SetLastError(0xdeadbeef);
    status = reader(key, NULL, &size);
    if (wanted)
    {
        ok(status == wanted && !size, "bad reader %s returned %#lx/%u.\n", wine_dbgstr_w(key), status, size);
        return;
    }
    ok(status == STATUS_BUFFER_TOO_SMALL && size == required, "reader sizing %#lx/%u, expected %u.\n", status, size, required);
    fill(output, ARRAY_SIZE(output)); size = required - 1;
    status = reader(key, output, &size);
    ok(status == STATUS_BUFFER_TOO_SMALL && size == required && output[0] == 0xcccc,
       "short reader %#lx/%u.\n", status, size);
    size = required + 1;
    status = reader(key, output, &size);
    ok(!status && size == required && !lstrcmpW(output, expected), "reader returned %#lx/%u %s.\n", status, size, wine_dbgstr_w(output));
    ok(output[required / 2] == 0xcccc && GetLastError() == 0xdeadbeef, "reader changed trailing data/error.\n");
}

static void test_readers(void)
{
    static const WCHAR *invalid_keys[] = { L"", L"abc", L"+App", L"abc+", L"abc+app+again", L"abc!+App", L"abc+App#x", L"abc+App##" };
    WCHAR key[300], name[130], relative[70], suffix[39];
    GUID result, sentinel;
    UINT32 size;
    NTSTATUS status;
    unsigned int i;

    lstrcpyW(key, package); lstrcatW(key, L"+App");
    ok(is_valid(key) && !is_dynamic(key), "normal key predicates failed.\n");
    check_reader(get_package, key, package, 0);
    check_reader(get_application, key, L"App", 0);
    memset(&sentinel, 0xcc, sizeof(sentinel)); result = sentinel;
    status = get_dynamic(key, &result);
    ok(status == STATUS_NOT_FOUND && !memcmp(&result, &sentinel, sizeof(result)), "no dynamic ID returned %#lx.\n", status);
    lstrcatW(key, L"#{abcdef12-3456-789a-bcde-f0123456789a}");
    ok(is_valid(key) && is_dynamic(key), "dynamic key predicates failed.\n");
    check_reader(get_package, key, package, 0);
    check_reader(get_application, key, L"App", 0);
    status = get_dynamic(key, &result);
    ok(!status && !memcmp(&result, &dynamic_id, sizeof(result)), "dynamic ID returned %#lx.\n", status);
    for (i = 0; i < ARRAY_SIZE(invalid_keys); ++i)
    {
        ok(!is_valid(invalid_keys[i]), "invalid key %s accepted.\n", wine_dbgstr_w(invalid_keys[i]));
        result = sentinel;
        status = get_dynamic(invalid_keys[i], &result);
        ok(status == STATUS_BAD_KEY && !memcmp(&result, &sentinel, sizeof(result)), "invalid dynamic returned %#lx.\n", status);
    }
    ok(is_dynamic(L"#"), "dynamic predicate validates syntax.\n");
    /* Component readers do not require the entire key to be valid. */
    check_reader(get_package, L"abc+", L"abc", 0);
    check_reader(get_package, L"+App", NULL, STATUS_BAD_KEY);
    check_reader(get_application, L"+App", L"App", 0);
    check_reader(get_application, L"abc+", NULL, STATUS_BAD_KEY);
    check_reader(get_application, L"abc+App*wildcard", L"App", 0);
    check_reader(get_application, L"abc+App+Other", L"App+Other", 0);
    ok(is_valid(L"abc+App*wildcard"), "wildcard key rejected by shape check.\n");

    for (i = 0; i < 127; ++i) name[i] = L'a'; name[127] = 0;
    for (i = 0; i < 64; ++i) relative[i] = L'b'; relative[64] = 0;
    lstrcpyW(key, name); lstrcatW(key, L"+"); lstrcatW(key, relative);
    ok(is_valid(key), "maximum normal key rejected.\n");
    check_reader(get_package, key, name, 0); check_reader(get_application, key, relative, 0);
    for (i = 0; i < 38; ++i) suffix[i] = L'x'; suffix[38] = 0;
    lstrcatW(key, L"#"); lstrcatW(key, suffix);
    ok(is_valid(key), "shape-valid malformed GUID rejected.\n");
    result = sentinel;
    status = get_dynamic(key, &result);
    ok(!status && !memcmp(&result, &sentinel, sizeof(result)), "ignored GUID parse error returned %#lx.\n", status);
    name[127] = L'a'; name[128] = 0;
    lstrcpyW(key, name); lstrcatW(key, L"+App");
    ok(!is_valid(key), "oversized package accepted.\n");
    check_reader(get_package, key, NULL, STATUS_BAD_KEY);
    relative[64] = L'b'; relative[65] = 0;
    lstrcpyW(key, L"abc+"); lstrcatW(key, relative);
    ok(!is_valid(key), "oversized application accepted.\n");
    check_reader(get_application, key, NULL, STATUS_BAD_KEY);

    lstrcpyW(key, package); lstrcatW(key, L"+App"); size = 0;
    status = get_aumid(key, &size, NULL);
    ok(status == STATUS_BUFFER_TOO_SMALL && size == lstrlenW(L"Test.Package_1234567890abc!App") + 1,
       "AUMID sizing %#lx/%u.\n", status, size);
    fill(name, ARRAY_SIZE(name)); --size;
    status = get_aumid(key, &size, name);
    ok(status == STATUS_BUFFER_TOO_SMALL && name[0] == 0xcccc, "short AUMID returned %#lx.\n", status);
    size = ARRAY_SIZE(name);
    status = get_aumid(key, &size, name);
    ok(!status && !lstrcmpW(name, L"Test.Package_1234567890abc!App"), "AUMID returned %#lx %s.\n", status, wine_dbgstr_w(name));
    size = 123;
    ok(get_aumid(L"notpackage+App", &size, name) == STATUS_INVALID_PARAMETER && size == 123,
       "invalid package AUMID accepted.\n");
    lstrcpyW(key, package); lstrcatW(key, L"+App-Bad"); size = 123; fill(name, ARRAY_SIZE(name));
    status = get_aumid(key, &size, name);
    ok(status == STATUS_BUFFER_TOO_SMALL && size == 123 && name[0] == 0xcccc,
       "format failure mapping %#lx/%u.\n", status, size);
    ok(GetLastError() == 0xdeadbeef, "key readers changed last error.\n");
}

static void test_relationships(void)
{
    const WCHAR *parent = L"Package+App", *child = L"package+aPP#{abcdef12-3456-789a-bcde-f0123456789a}";
    ok(equal_package(parent, child), "package comparison includes suffix/case.\n");
    ok(equal_application(parent, child), "application comparison includes suffix/case.\n");
    ok(is_child(parent, child), "parent-child relationship missing.\n");
    ok(!is_child(child, parent) && !is_child(child, child) && !is_child(parent, parent), "child direction ignored.\n");
    ok(equal_package(parent, L"PACKAGE+Other") && !equal_application(parent, L"PACKAGE+Other"), "application distinction missing.\n");
    ok(!equal_package(parent, L"Other+App") && !equal_application(parent, L"Other+App"), "package distinction missing.\n");
}

START_TEST(psm)
{
    const char *names[] = { "PsmCreateKey", "PsmCreateKeyWithDynamicId", "PsmGetPackageFullNameFromKey",
                           "PsmGetApplicationNameFromKey", "PsmGetDynamicIdFromKey", "PsmGetAumidFromKey",
                           "PsmIsValidKey", "PsmIsDynamicKey", "PsmEqualPackage", "PsmEqualApplication", "PsmIsChildKey" };
    HMODULE module = GetModuleHandleA("kernelbase.dll"), api;
    unsigned int i;
    BOOL available = TRUE;

    for (i = 0; i < ARRAY_SIZE(names); ++i)
    {
        FARPROC proc = GetProcAddress(module, names[i]);
        ok(!!proc, "%s missing.\n", names[i]);
        available &= !!proc;
    }
    if (!available) return;
    create_key = (void *)GetProcAddress(module, names[0]);
    create_dynamic = (void *)GetProcAddress(module, names[1]);
    get_package = (void *)GetProcAddress(module, names[2]);
    get_application = (void *)GetProcAddress(module, names[3]);
    get_dynamic = (void *)GetProcAddress(module, names[4]);
    get_aumid = (void *)GetProcAddress(module, names[5]);
    is_valid = (void *)GetProcAddress(module, names[6]);
    is_dynamic = (void *)GetProcAddress(module, names[7]);
    equal_package = (void *)GetProcAddress(module, names[8]);
    equal_application = (void *)GetProcAddress(module, names[9]);
    is_child = (void *)GetProcAddress(module, names[10]);
    test_constructors(); test_readers(); test_relationships();

    api = LoadLibraryA("api-ms-win-core-psm-key-l1-1-0.dll");
    ok(!!api && GetProcAddress(api, names[0]) == (FARPROC)create_key, "base PSM API set did not resolve constructor.\n");
    if (api) FreeLibrary(api);
    api = LoadLibraryA("api-ms-win-core-psm-key-l1-1-3.dll");
    ok(!!api && GetProcAddress(api, names[5]) == (FARPROC)get_aumid, "current PSM API set did not resolve AUMID reader.\n");
    if (api) FreeLibrary(api);
}
