/*
 * AppCompat infrastructure query ABI tests
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
#include "wine/test.h"

static void check_queries(const char *stage)
{
    static const DWORD errors[] = {0, ERROR_ACCESS_DENIED, 0x12345678, 0x87654321};
    HMODULE base = GetModuleHandleW(L"kernelbase.dll");
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    HMODULE apiset = LoadLibraryW(L"api-ms-win-core-appcompat-l1-1-0.dll");
    BOOL (WINAPI *functions[4])(void);
    unsigned int i, j;
    BOOL ret;
    DWORD error;

    functions[0] = base ? (void *)GetProcAddress(base, "BaseIsAppcompatInfrastructureDisabled") : NULL;
    functions[1] = (void *)GetProcAddress(kernel, "BaseIsAppcompatInfrastructureDisabled");
    functions[2] = (void *)GetProcAddress(kernel, "BaseIsAppcompatInfrastructureDisabledWorker");
    functions[3] = apiset ? (void *)GetProcAddress(apiset, "BaseIsAppcompatInfrastructureDisabled") : NULL;
    if (!functions[0])
    {
        win_skip("Infrastructure query unavailable\n");
        if (apiset) FreeLibrary(apiset);
        return;
    }
    winetest_push_context("%s", stage);
    for (i = 0; i < ARRAY_SIZE(functions); ++i)
    {
        winetest_push_context("entry %u", i);
        ok(!!functions[i], "Missing query entrypoint\n");
        if (functions[i])
        {
            for (j = 0; j < ARRAY_SIZE(errors); ++j)
            {
                SetLastError(errors[j]);
                ret = functions[i]();
                error = GetLastError();
                ok(ret == FALSE, "Query returned %d\n", ret);
                ok(error == errors[j], "Error %#lx, expected %#lx\n", error, errors[j]);
            }
        }
        winetest_pop_context();
    }
    winetest_pop_context();
    if (apiset) FreeLibrary(apiset);
}

START_TEST(appcompat)
{
    BOOL (WINAPI *init_cache)(void);
    HMODULE base = GetModuleHandleW(L"kernelbase.dll");

    /* Frozen Windows 26200 reference: all four entrypoints agree before and
     * after cache initialization. Cache success is a separate contract. */
    check_queries("first");
    check_queries("repeat");
    init_cache = base ? (void *)GetProcAddress(base, "BaseInitAppcompatCacheSupport") : NULL;
    if (init_cache) init_cache();
    check_queries("after-cache-init");
}
