/* Unit tests for UI language information.
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
#include "winnls.h"

#include "wine/test.h"

static void test_ui_language_info(void)
{
    BOOL (WINAPI *get_ui_language_info)(DWORD, const WCHAR *, WCHAR *, DWORD *, DWORD *);
    HMODULE kernelbase = GetModuleHandleA( "kernelbase.dll" );
    static const WCHAR language[] = L"en-US\0";
    WCHAR fallback[2] = {'x', 'x'};
    DWORD attributes, size;
    BOOL ret;

    get_ui_language_info = (void *)GetProcAddress( kernelbase, "GetUILanguageInfo" );
    ok( !!get_ui_language_info, "GetUILanguageInfo is unavailable\n" );
    if (!get_ui_language_info) return;

    size = 0;
    attributes = 0;
    ret = get_ui_language_info( MUI_LANGUAGE_NAME, language, NULL, &size, &attributes );
    ok( ret, "got error %lu\n", GetLastError() );
    ok( size == 2, "got fallback size %lu\n", size );
    ok( attributes == (MUI_FULL_LANGUAGE | MUI_LANGUAGE_INSTALLED | MUI_LANGUAGE_LICENSED),
        "got attributes %#lx\n", attributes );

    size = 1;
    ret = get_ui_language_info( MUI_LANGUAGE_NAME, language, fallback, &size, &attributes );
    ok( !ret, "unexpected success\n" );
    ok( GetLastError() == ERROR_INSUFFICIENT_BUFFER, "got error %lu\n", GetLastError() );
    ok( size == 2, "got fallback size %lu\n", size );

    size = ARRAY_SIZE(fallback);
    ret = get_ui_language_info( 0, language, fallback, &size, &attributes );
    ok( ret, "got error %lu\n", GetLastError() );
    ok( !fallback[0] && !fallback[1], "fallback is not empty\n" );

    ret = get_ui_language_info( MUI_LANGUAGE_ID | MUI_LANGUAGE_NAME, language,
                                NULL, NULL, &attributes );
    ok( !ret, "unexpected success\n" );
    ok( GetLastError() == ERROR_INVALID_PARAMETER, "got error %lu\n", GetLastError() );
}

START_TEST(ui_language)
{
    test_ui_language_info();
}
