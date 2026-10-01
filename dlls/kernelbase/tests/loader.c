/*
 * Kernelbase loader tests
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>

#include <windef.h>
#include <winbase.h>
#include <winerror.h>

#include "wine/test.h"

static FARPROC (WINAPI *pDelayLoadFailureHook)(LPCSTR, LPCSTR);

static void test_minuser_SetClassScope(void)
{
    typedef HRESULT (WINAPI *set_class_scope_fn)(void *, void *, UINT);
    static const char *contracts[] =
    {
        "ext-ms-win-rtcore-minuser-private-ext-l1-1-0.dll",
        "ext-ms-win-rtcore-minuser-private-ext-l1-1-1.dll",
        "ext-ms-win-rtcore-minuser-private-ext-l1-1-2.dll",
        "ext-ms-win-rtcore-minuser-private-ext-l1-1-3.dll",
    };
    HMODULE kernelbase = GetModuleHandleA("kernelbase.dll"), provider;
    FARPROC first = NULL, proc;
    unsigned int i;
    BOOL ret;

    if (!pDelayLoadFailureHook)
    {
        win_skip("DelayLoadFailureHook is not available\n");
        return;
    }

    for (i = 0; i < ARRAY_SIZE(contracts); ++i)
    {
        proc = pDelayLoadFailureHook(contracts[i], "SetClassScope");
        ok(!!proc, "%s SetClassScope fallback is missing\n", contracts[i]);
        if (!proc) continue;
        if (!first) first = proc;
        else ok(proc == first, "%s returned %p, expected %p\n", contracts[i], proc, first);
        ok(((set_class_scope_fn)proc)((void *)0xdeadbeef, (void *)0xdeadf00d, 3) == S_OK,
           "%s SetClassScope returned failure\n", contracts[i]);
        provider = NULL;
        ret = GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                 GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                 (const char *)proc, &provider);
        ok(ret, "%s GetModuleHandleExA failed: %lu\n", contracts[i], GetLastError());
        ok(provider == kernelbase, "%s provider is %p, expected kernelbase %p\n",
           contracts[i], provider, kernelbase);
    }
}

START_TEST(loader)
{
    HMODULE kernelbase = GetModuleHandleA("kernelbase.dll");

    pDelayLoadFailureHook = (void *)GetProcAddress(kernelbase, "DelayLoadFailureHook");
    test_minuser_SetClassScope();
}
