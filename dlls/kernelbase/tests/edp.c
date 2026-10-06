/*
 * Copyright 2026
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

#include "wine/test.h"

START_TEST(edp)
{
    BOOL (WINAPI *pGetIsEdpEnabled)(void);
    HMODULE module;
    BOOL ret;

    module = LoadLibraryA("kernelbase.dll");
    ok(!!module, "Failed to load kernelbase.dll, error %lu.\n", GetLastError());
    if (!module) return;

    pGetIsEdpEnabled = (void *)GetProcAddress(module, "GetIsEdpEnabled");
    if (!pGetIsEdpEnabled)
    {
        win_skip("GetIsEdpEnabled is not available.\n");
        return;
    }

    SetLastError(0xdeadbeef);
    ret = pGetIsEdpEnabled();
    ok(ret == FALSE || ret == TRUE, "Got unexpected return value %d.\n", ret);
    ok(GetLastError() == 0xdeadbeef, "GetIsEdpEnabled changed error to %lu.\n", GetLastError());
}
