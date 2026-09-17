/*
 * KernelBase loader tests
 *
 * Copyright 2026
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "windows.h"

#include "wine/test.h"

static FARPROC (WINAPI *pDelayLoadFailureHook)(LPCSTR, LPCSTR);

static void test_wer_xbox_fallback(void)
{
    static const char *modules[] =
    {
        "ext-ms-win-wer-xbox-l1-2-0.dll",
        "EXT-MS-WIN-WER-XBOX-L1-2-0.DLL",
        "ext-ms-win-wer-xbox-l1-2-1.dll",
    };
    BOOL (WINAPI *handler)(void);
    unsigned int i;
    BOOL ret;

    for (i = 0; i < ARRAY_SIZE(modules); ++i)
    {
        handler = (void *)pDelayLoadFailureHook( modules[i], "XerShouldWerManageRootDirectory" );
        ok(!!handler, "%s returned a null fallback\n", modules[i]);
        if (!handler) continue;

        SetLastError( 0xdeadbeef );
        ret = handler();
        ok(ret == TRUE, "%s fallback returned %d\n", modules[i], ret);
        ok(GetLastError() == ERROR_PROC_NOT_FOUND, "%s fallback set error %lu\n",
           modules[i], GetLastError());
    }
}

START_TEST(loader)
{
    HMODULE module = GetModuleHandleA( "kernelbase.dll" );

    pDelayLoadFailureHook = (void *)GetProcAddress( module, "DelayLoadFailureHook" );
    if (!pDelayLoadFailureHook)
    {
        win_skip("DelayLoadFailureHook is unavailable\n");
        return;
    }

    test_wer_xbox_fallback();
}
