/*
 * Winstation tests
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

#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "../winsta.h"
#include "wine/test.h"

static BOOLEAN (WINAPI *pWinStationQueryInformationA)(HANDLE,ULONG,WINSTATIONINFOCLASS,void *,ULONG,ULONG *);
static BOOLEAN (WINAPI *pWinStationQueryInformationW)(HANDLE,ULONG,WINSTATIONINFOCLASS,void *,ULONG,ULONG *);

static void test_query_session_type(void)
{
    ULONG buffer[2], expected, length, session_id;
    BOOLEAN ret;

    ret = ProcessIdToSessionId(GetCurrentProcessId(), &session_id);
    ok(ret, "ProcessIdToSessionId failed, error %lu\n", GetLastError());
    expected = session_id ? SESSIONTYPE_REGULARDESKTOP : SESSIONTYPE_SERVICES;

    buffer[0] = 0xdeadbeef;
    buffer[1] = 0xdeadbeef;
    length = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    ret = pWinStationQueryInformationW(NULL, LOGONID_CURRENT, WinStationType,
                                       buffer, sizeof(buffer), &length);
    ok(ret, "WinStationQueryInformationW failed, error %lu\n", GetLastError());
    ok(!GetLastError(), "expected ERROR_SUCCESS, got %lu\n", GetLastError());
    ok(buffer[0] == expected, "expected session type %lu, got %lu\n", expected, buffer[0]);
    ok(buffer[1] == 0xdeadbeef, "function wrote past its four-byte payload\n");
    ok(length == sizeof(ULONG), "expected length %Iu, got %lu\n", sizeof(ULONG), length);

    buffer[0] = 0xdeadbeef;
    length = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    ret = pWinStationQueryInformationA(NULL, session_id, WinStationType,
                                       buffer, sizeof(ULONG), &length);
    ok(ret, "WinStationQueryInformationA failed, error %lu\n", GetLastError());
    ok(!GetLastError(), "expected ERROR_SUCCESS, got %lu\n", GetLastError());
    ok(buffer[0] == expected, "expected session type %lu, got %lu\n", expected, buffer[0]);
    ok(length == sizeof(ULONG), "expected length %Iu, got %lu\n", sizeof(ULONG), length);

    buffer[0] = 0xdeadbeef;
    length = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    ret = pWinStationQueryInformationW(NULL, LOGONID_CURRENT, WinStationType,
                                       buffer, sizeof(ULONG) - 1, &length);
    ok(!ret, "expected failure for a short buffer\n");
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "expected ERROR_INVALID_PARAMETER, got %lu\n",
       GetLastError());
    ok(buffer[0] == 0xdeadbeef, "buffer changed on failure\n");

    buffer[0] = 0xdeadbeef;
    length = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    ret = pWinStationQueryInformationW(NULL, 0xfffffffe, WinStationType,
                                       buffer, sizeof(ULONG), &length);
    ok(!ret, "expected failure for an unknown session\n");
    ok(GetLastError() == ERROR_FILE_NOT_FOUND, "expected ERROR_FILE_NOT_FOUND, got %lu\n",
       GetLastError());
    ok(buffer[0] == 0xdeadbeef, "buffer changed on failure\n");
}

START_TEST(winsta)
{
    HMODULE module = LoadLibraryA("winsta.dll");

    if (!module)
    {
        win_skip("winsta.dll is unavailable\n");
        return;
    }
    pWinStationQueryInformationA = (void *)GetProcAddress(module, "WinStationQueryInformationA");
    pWinStationQueryInformationW = (void *)GetProcAddress(module, "WinStationQueryInformationW");
    if (!pWinStationQueryInformationA || !pWinStationQueryInformationW)
    {
        win_skip("WinStationQueryInformation is unavailable\n");
        return;
    }
    test_query_session_type();
}
