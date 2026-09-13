/*
 * Mouse-input cursor-suppression tests
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
#include "winuser.h"
#include "wine/test.h"

typedef BOOL (WINAPI *enable_mouse_input_for_cursor_suppression_t)(BOOL enable);

START_TEST( cursor_suppression )
{
    enable_mouse_input_for_cursor_suppression_t enable_mouse_input;
    HMODULE user32 = GetModuleHandleW( L"user32.dll" );

    enable_mouse_input = (void *)GetProcAddress( user32, (const char *)2519 );
    ok( !!enable_mouse_input, "EnableMouseInputForCursorSuppression is not exported\n" );
    if (!enable_mouse_input) return;

    SetLastError( 0xdeadbeef );
    ok( enable_mouse_input( TRUE ), "failed to enable cursor-suppression mouse input, error %lu\n",
        GetLastError() );

    SetLastError( 0xdeadbeef );
    ok( !enable_mouse_input( 2 ), "accepted a non-Boolean input\n" );
    ok( GetLastError() == ERROR_INVALID_PARAMETER, "got error %lu\n", GetLastError() );
}
