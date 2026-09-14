/*
 * Text-readiness tests
 *
 * Copyright 2026 Nulifyer
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

#include "windef.h"
#include "winbase.h"
#include "wine/test.h"

#include "ntgdi.h"

typedef BOOL (WINAPI *gdi_wait_for_text_ready_t)(void);

START_TEST( text_ready )
{
    gdi_wait_for_text_ready_t gdi_wait_for_text_ready;
    HMODULE gdi32;
    BOOL ret;

    ret = NtGdiWaitForTextReady();
    ok( ret, "NtGdiWaitForTextReady failed, error %lu\n", GetLastError() );

    gdi32 = LoadLibraryA( "gdi32.dll" );
    ok( gdi32 != NULL, "LoadLibraryA failed, error %lu\n", GetLastError() );
    if (!gdi32) return;

    gdi_wait_for_text_ready = (void *)GetProcAddress( gdi32, "GdiWaitForTextReady" );
    ok( gdi_wait_for_text_ready != NULL, "GdiWaitForTextReady is not exported\n" );
    if (!gdi_wait_for_text_ready) return;

    ret = gdi_wait_for_text_ready();
    ok( ret, "GdiWaitForTextReady failed, error %lu\n", GetLastError() );
}
