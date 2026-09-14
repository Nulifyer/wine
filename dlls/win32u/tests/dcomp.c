/*
 * DirectComposition syscall tests
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

#include "ntstatus.h"
#define WIN32_NO_STATUS

#include "wine/test.h"

#include "winbase.h"
#include "ntuser.h"

static void test_connection_lifetime(void)
{
    HANDLE event, connection = (HANDLE)0xdeadbeef;
    NTSTATUS status;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "CreateEventW failed, error %lu\n", GetLastError() );
    if (!event) return;

    status = NtDCompositionCreateConnection( FALSE, event, &connection );
    ok( status == STATUS_SUCCESS, "got status %#lx\n", status );
    ok( connection && connection != (HANDLE)0xdeadbeef, "got connection %p\n", connection );
    ok( connection != event, "connection unexpectedly aliases work event %p\n", event );

    CloseHandle( event );
    if (!status)
    {
        status = NtDCompositionDestroyConnection( connection );
        ok( status == STATUS_SUCCESS, "got destroy status %#lx\n", status );
        status = NtDCompositionDestroyConnection( connection );
        ok( status == STATUS_INVALID_HANDLE, "got second destroy status %#lx\n", status );
    }
}

START_TEST(dcomp)
{
    test_connection_lifetime();
}
