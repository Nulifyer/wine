/*
 * AppModel identifier conversion tests
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "wine/test.h"
#include "winbase.h"
#include "appmodel.h"

static LONG (WINAPI *parse_id)(const WCHAR *, UINT32 *, WCHAR *, UINT32 *, WCHAR *);
static LONG (WINAPI *format_id)(const WCHAR *, const WCHAR *, UINT32 *, WCHAR *);

static void fill(WCHAR *buffer, unsigned int count)
{
    unsigned int i;
    for (i = 0; i < count; ++i) buffer[i] = 0xcccc;
}

static void check_valid(const WCHAR *family, const WCHAR *relative)
{
    WCHAR id[140], family_out[70], relative_out[70], expected[140];
    UINT32 family_size = lstrlenW(family) + 1, relative_size = lstrlenW(relative) + 1;
    UINT32 id_size = family_size + relative_size, a, b, length;
    LONG ret;

    lstrcpyW(expected, family);
    lstrcatW(expected, L"!");
    lstrcatW(expected, relative);
    length = 0;
    SetLastError(0xdeadbeef);
    ret = format_id(family, relative, &length, NULL);
    ok(ret == ERROR_INSUFFICIENT_BUFFER, "format query returned %ld.\n", ret);
    ok(length == id_size, "format query length %u, expected %u.\n", length, id_size);
    ok(GetLastError() == 0xdeadbeef, "format query changed last error.\n");

    fill(id, ARRAY_SIZE(id));
    length = id_size - 1;
    ret = format_id(family, relative, &length, id);
    ok(ret == ERROR_INSUFFICIENT_BUFFER && length == id_size, "short format %ld/%u.\n", ret, length);
    ok(id[0] == 0xcccc && id[id_size - 1] == 0xcccc, "short format wrote output.\n");
    length = ARRAY_SIZE(id);
    ret = format_id(family, relative, &length, id);
    ok(!ret && length == id_size, "format returned %ld/%u.\n", ret, length);
    ok(!lstrcmpW(id, expected) && id[id_size] == 0xcccc, "format data %s.\n", wine_dbgstr_w(id));
    ok(GetLastError() == 0xdeadbeef, "format changed last error.\n");

    a = b = 0;
    ret = parse_id(id, &a, NULL, &b, NULL);
    ok(ret == ERROR_INSUFFICIENT_BUFFER && a == family_size && b == relative_size,
       "parse query returned %ld/%u/%u.\n", ret, a, b);
    fill(family_out, ARRAY_SIZE(family_out));
    fill(relative_out, ARRAY_SIZE(relative_out));
    a = family_size - 1; b = relative_size;
    ret = parse_id(id, &a, family_out, &b, relative_out);
    ok(ret == ERROR_INSUFFICIENT_BUFFER && a == family_size && b == relative_size,
       "short family returned %ld/%u/%u.\n", ret, a, b);
    ok(family_out[0] == 0xcccc && relative_out[0] == 0xcccc, "short family wrote outputs.\n");
    a = family_size; b = relative_size - 1;
    ret = parse_id(id, &a, family_out, &b, relative_out);
    ok(ret == ERROR_INSUFFICIENT_BUFFER && a == family_size && b == relative_size,
       "short relative returned %ld/%u/%u.\n", ret, a, b);
    ok(family_out[0] == 0xcccc && relative_out[0] == 0xcccc, "short relative wrote outputs.\n");
    a = family_size; b = relative_size;
    ret = parse_id(id, &a, family_out, &b, relative_out);
    ok(!ret && a == family_size && b == relative_size, "parse returned %ld/%u/%u.\n", ret, a, b);
    ok(!lstrcmpW(family_out, family) && family_out[a] == 0xcccc, "family output %s.\n", wine_dbgstr_w(family_out));
    ok(!lstrcmpW(relative_out, relative) && relative_out[b] == 0xcccc, "relative output %s.\n", wine_dbgstr_w(relative_out));
    ok(GetLastError() == 0xdeadbeef, "parse changed last error.\n");
}

static void check_invalid(const WCHAR *family, const WCHAR *relative)
{
    WCHAR id[200], output[200], second[200];
    UINT32 a = 150, b = 160;
    LONG ret;

    fill(output, ARRAY_SIZE(output));
    fill(second, ARRAY_SIZE(second));
    SetLastError(0xdeadbeef);
    ret = format_id(family, relative, &a, output);
    ok(ret == ERROR_INVALID_PARAMETER && a == 150, "invalid format %s/%s returned %ld/%u.\n",
       wine_dbgstr_w(family), wine_dbgstr_w(relative), ret, a);
    ok(output[0] == 0xcccc && GetLastError() == 0xdeadbeef, "invalid format changed output/error.\n");
    lstrcpyW(id, family); lstrcatW(id, L"!"); lstrcatW(id, relative);
    ret = parse_id(id, &a, output, &b, second);
    ok(ret == ERROR_INVALID_PARAMETER && a == 150 && b == 160,
       "invalid parse %s returned %ld/%u/%u.\n", wine_dbgstr_w(id), ret, a, b);
    ok(output[0] == 0xcccc && second[0] == 0xcccc && GetLastError() == 0xdeadbeef,
       "invalid parse changed outputs/error.\n");
}

static void test_syntax(void)
{
    static const WCHAR *invalid_families[] =
    {
        L"", L"ab_1234567890abc", L"abc", L"abc_1234567890ab", L"abc_1234567890abcd",
        L"abc_1234567890abi", L"abc_1234567890abl", L"abc_1234567890abo", L"abc_1234567890abu",
        L"abc def_1234567890abc", L"abc+def_1234567890abc", L"abc_def_1234567890abc",
        L"con_1234567890abc", L"PrN_1234567890abc", L"aux_1234567890abc", L"nul_1234567890abc",
        L"COM1_1234567890abc", L"lpt9_1234567890abc", L"con.app_1234567890abc",
        L"com4.app_1234567890abc", L"lpt5.app_1234567890abc", L"abc._1234567890abc",
        L"xn--abc_1234567890abc", L"abc.XN--def_1234567890abc",
    };
    static const WCHAR *invalid_relative[] = { L"", L"App-1", L"App_1", L"App!1", L"App 1", L"App/1", L"App\\1" };
    static const WCHAR *valid_relative[] = { L".", L"..", L"con", L"9.App", L"App.0" };
    WCHAR family[100], relative[100];
    unsigned int i;

    check_valid(L"Microsoft.WindowsCalculator_8wekyb3d8bbwe", L"App");
    check_valid(L"NotInstalled.Package_1234567890abc", L"App");
    check_valid(L"abc_0123456789ABC", L"A");
    check_valid(L"com0_1234567890abc", L"App");
    check_valid(L"conapp_1234567890abc", L"App");
    check_valid(L"-ab_1234567890abc", L"App");
    for (i = 0; i < ARRAY_SIZE(valid_relative); ++i) check_valid(L"abc_1234567890abc", valid_relative[i]);
    for (i = 0; i < ARRAY_SIZE(invalid_families); ++i) check_invalid(invalid_families[i], L"App");
    for (i = 0; i < ARRAY_SIZE(invalid_relative); ++i) check_invalid(L"abc_1234567890abc", invalid_relative[i]);

    for (i = 0; i < 50; ++i) family[i] = L'a';
    lstrcpyW(family + 50, L"_1234567890abc");
    for (i = 0; i < 64; ++i) relative[i] = L'Z';
    relative[64] = 0;
    check_valid(family, relative);
    relative[64] = L'Z'; relative[65] = 0;
    check_invalid(family, relative);
    lstrcpyW(family + 51, L"_1234567890abc"); family[50] = L'a';
    check_invalid(family, L"App");
}

static void test_characters(void)
{
    WCHAR family[] = L"abc_1234567890abc", relative[] = L"a";
    WCHAR id[100];
    UINT32 length, a, b;
    unsigned int i, field;
    BOOL valid;
    LONG ret;

    for (field = 0; field < 3; ++field)
        for (i = 0; i < 132; ++i)
        {
            WCHAR ch = i < 128 ? i : (WCHAR[]){ 0x80, 0x100, 0xd800, 0xffff }[i - 128];
            family[1] = L'b'; family[4] = L'1'; relative[0] = L'a';
            if (!field) family[1] = ch;
            else if (field == 1) family[4] = ch;
            else relative[0] = ch;
            valid = (ch >= L'0' && ch <= L'9') || (ch >= L'A' && ch <= L'Z') || (ch >= L'a' && ch <= L'z');
            if (!field) valid |= ch == L'.' || ch == L'-';
            else if (field == 1) valid = ch && !!wcschr(L"0123456789abcdefghjkmnpqrstvwxyzABCDEFGHJKMNPQRSTVWXYZ", ch);
            else valid |= ch == L'.';
            length = 0;
            ret = format_id(family, relative, &length, NULL);
            ok(ret == (valid ? ERROR_INSUFFICIENT_BUFFER : ERROR_INVALID_PARAMETER),
               "field %u character %#x format returned %ld.\n", field, ch, ret);
            lstrcpyW(id, family); lstrcatW(id, L"!"); lstrcatW(id, relative);
            a = b = 0;
            ret = parse_id(id, &a, NULL, &b, NULL);
            ok(ret == (valid ? ERROR_INSUFFICIENT_BUFFER : ERROR_INVALID_PARAMETER),
               "field %u character %#x parse returned %ld.\n", field, ch, ret);
        }
}

static void test_parameters(void)
{
    const WCHAR *family = L"abc_1234567890abc", *id = L"abc_1234567890abc!App";
    WCHAR output[140], second[70];
    UINT32 a, b;
    LONG ret;

    a = b = 100;
    ok(format_id(NULL, L"App", &a, output) == ERROR_INVALID_PARAMETER, "null family accepted.\n");
    ok(format_id(family, NULL, &a, output) == ERROR_INVALID_PARAMETER, "null relative accepted.\n");
    ok(format_id(family, L"App", NULL, output) == ERROR_INVALID_PARAMETER, "null format length accepted.\n");
    ok(format_id(family, L"App", &a, NULL) == ERROR_INVALID_PARAMETER && a == 100, "null format buffer accepted.\n");
    ok(parse_id(NULL, &a, output, &b, second) == ERROR_INVALID_PARAMETER, "null ID accepted.\n");
    ok(parse_id(id, NULL, output, &b, second) == ERROR_INVALID_PARAMETER, "null family length accepted.\n");
    ok(parse_id(id, &a, output, NULL, second) == ERROR_INVALID_PARAMETER, "null relative length accepted.\n");
    ok(parse_id(id, &a, NULL, &b, second) == ERROR_INVALID_PARAMETER && a == 100 && b == 100,
       "null family buffer accepted.\n");
    ok(parse_id(id, &a, output, &b, NULL) == ERROR_INVALID_PARAMETER && a == 100 && b == 100,
       "null relative buffer accepted.\n");
    a = 0;
    fill(second, ARRAY_SIZE(second));
    ret = parse_id(id, &a, NULL, &b, second);
    ok(ret == ERROR_INSUFFICIENT_BUFFER && a == 18 && b == 4 && second[0] == 0xcccc,
       "partial sizing returned %ld/%u/%u.\n", ret, a, b);
    a = b = ~0u;
    ret = parse_id(id, &a, output, &b, second);
    ok(!ret && a == 18 && b == 4, "large capacities returned %ld/%u/%u.\n", ret, a, b);

    lstrcpyW(output, family); a = ARRAY_SIZE(output);
    ret = format_id(output, L"App", &a, output);
    ok(!ret && !lstrcmpW(output, id), "aliased family formatting returned %ld.\n", ret);
    lstrcpyW(output, L"App"); a = ARRAY_SIZE(output);
    ret = format_id(family, output, &a, output);
    ok(!ret && !lstrcmpW(output, id), "aliased relative formatting returned %ld.\n", ret);
}

START_TEST(appmodel_identity)
{
    const char *modules[] = { "kernelbase.dll", "kernel32.dll" };
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(modules); ++i)
    {
        HMODULE module = GetModuleHandleA(modules[i]);
        parse_id = (void *)GetProcAddress(module, "ParseApplicationUserModelId");
        format_id = (void *)GetProcAddress(module, "FormatApplicationUserModelId");
        ok(!!parse_id, "%s parser missing.\n", modules[i]);
        ok(!!format_id, "%s formatter missing.\n", modules[i]);
        if (!parse_id || !format_id) continue;
        test_syntax();
        test_characters();
        test_parameters();
    }
}
