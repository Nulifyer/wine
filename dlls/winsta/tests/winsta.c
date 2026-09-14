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
static BOOLEAN (WINAPI *pWinStationGetConnectionProperty)(ULONG,const GUID *,void **);
static BOOLEAN (WINAPI *pWinStationFreePropertyValue)(void *);
static DWORD (WINAPI *pWinStationIsSessionPermitted)(void);
static BOOLEAN (WINAPI *p_WinStationWaitForConnect)(void);
static BOOLEAN (WINAPI *p_WinStationWaitForConnectEx)(const GUID *);

static void test_connection_property(void)
{
    static const GUID property =
        {0x846b20bb, 0x6254, 0x430e, {0x95, 0x2f, 0xb0, 0xc7, 0xca, 0x08, 0x19, 0x15}};
    static const GUID unknown_property =
        {0xdeadbeef, 0x1234, 0x5678, {0x90, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67}};
    void *value = (void *)0xdeadbeef;
    BOOLEAN ret;

    SetLastError(0xdeadbeef);
    ret = pWinStationGetConnectionProperty(LOGONID_CURRENT, &property, &value);
    ok(ret, "WinStationGetConnectionProperty failed, error %lu\n", GetLastError());
    ok(!GetLastError(), "expected ERROR_SUCCESS, got %lu\n", GetLastError());
    ok(value != NULL, "expected an allocated property value\n");
    if (value)
    {
        ok(*(USHORT *)value == 1, "expected type 1, got %#x\n", *(USHORT *)value);
        ok(*(ULONG *)((BYTE *)value + 8) == FALSE, "expected a disabled property, got %#lx\n",
           *(ULONG *)((BYTE *)value + 8));
        SetLastError(0xdeadbeef);
        ret = pWinStationFreePropertyValue(value);
        ok(ret, "WinStationFreePropertyValue failed, error %lu\n", GetLastError());
        ok(GetLastError() == 0xdeadbeef, "expected last error to remain unchanged, got %lu\n",
           GetLastError());
    }

    value = (void *)0xdeadbeef;
    SetLastError(0xdeadbeef);
    ret = pWinStationGetConnectionProperty(LOGONID_CURRENT, &unknown_property, &value);
    ok(!ret, "expected an unknown property to fail\n");
    ok(GetLastError() == ERROR_NOT_SUPPORTED, "expected ERROR_NOT_SUPPORTED, got %lu\n",
       GetLastError());
    ok(value == NULL, "expected the output to be cleared, got %p\n", value);

    SetLastError(0xdeadbeef);
    ret = pWinStationGetConnectionProperty(LOGONID_CURRENT, &property, NULL);
    ok(!ret, "expected a null output pointer to fail\n");
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "expected ERROR_INVALID_PARAMETER, got %lu\n",
       GetLastError());

    SetLastError(0xdeadbeef);
    ret = pWinStationFreePropertyValue(NULL);
    ok(!ret, "expected a null property value to fail\n");
    ok(GetLastError() == ERROR_INVALID_DATA, "expected ERROR_INVALID_DATA, got %lu\n",
       GetLastError());
}

static void test_wait_for_connect(void)
{
    static const GUID activity_id =
        {0x9dcf77ab, 0xaed8, 0x4d85, {0x8a, 0x54, 0x74, 0x09, 0x4d, 0x68, 0x0c, 0x20}};
    BOOLEAN ret;

    SetLastError(0xdeadbeef);
    ret = p_WinStationWaitForConnect();
    ok(ret, "_WinStationWaitForConnect failed, error %lu\n", GetLastError());
    ok(GetLastError() == 0xdeadbeef, "expected last error to remain unchanged, got %lu\n",
       GetLastError());

    SetLastError(0xdeadbeef);
    ret = p_WinStationWaitForConnectEx(&activity_id);
    ok(ret, "_WinStationWaitForConnectEx failed, error %lu\n", GetLastError());
    ok(GetLastError() == 0xdeadbeef, "expected last error to remain unchanged, got %lu\n",
       GetLastError());
}

static void test_session_permitted(void)
{
    DWORD ret;

    SetLastError(0xdeadbeef);
    ret = pWinStationIsSessionPermitted();
    ok(ret == ERROR_SUCCESS, "WinStationIsSessionPermitted returned %lu.\n", ret);
    ok(GetLastError() == 0xdeadbeef, "expected last error to remain unchanged, got %lu\n",
       GetLastError());
}

static void test_query_session_information(void)
{
    struct
    {
        WINSTATIONINFORMATIONW info;
        ULONG guard;
    } buffer;
    ULONG length, session_id;
    BOOLEAN ret;

    ret = ProcessIdToSessionId(GetCurrentProcessId(), &session_id);
    ok(ret, "ProcessIdToSessionId failed, error %lu\n", GetLastError());

    memset(&buffer, 0xa5, sizeof(buffer));
    length = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    ret = pWinStationQueryInformationW(NULL, LOGONID_CURRENT, WinStationInformation,
                                       &buffer.info, sizeof(buffer.info), &length);
    ok(ret, "WinStationQueryInformationW failed, error %lu\n", GetLastError());
    ok(!GetLastError(), "expected ERROR_SUCCESS, got %lu\n", GetLastError());
    ok(length == sizeof(buffer.info), "expected length %Iu, got %lu\n", sizeof(buffer.info), length);
    ok(*(ULONG *)buffer.info.Reserved2 == State_Active, "expected active state, got %lu\n",
       *(ULONG *)buffer.info.Reserved2);
    ok(buffer.info.LogonId == session_id, "expected session %lu, got %lu\n",
       session_id, buffer.info.LogonId);
    ok(!buffer.info.Reserved3[0] && !buffer.info.Reserved3[sizeof(buffer.info.Reserved3) - 1],
       "expected reserved information to be cleared\n");
    ok(buffer.guard == 0xa5a5a5a5, "function wrote past the information buffer\n");
}

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
    pWinStationGetConnectionProperty = (void *)GetProcAddress(module, "WinStationGetConnectionProperty");
    pWinStationFreePropertyValue = (void *)GetProcAddress(module, "WinStationFreePropertyValue");
    pWinStationIsSessionPermitted = (void *)GetProcAddress(module, "WinStationIsSessionPermitted");
    p_WinStationWaitForConnect = (void *)GetProcAddress(module, "_WinStationWaitForConnect");
    p_WinStationWaitForConnectEx = (void *)GetProcAddress(module, "_WinStationWaitForConnectEx");
    if (!pWinStationQueryInformationA || !pWinStationQueryInformationW ||
        !pWinStationGetConnectionProperty || !pWinStationFreePropertyValue ||
        !pWinStationIsSessionPermitted || !p_WinStationWaitForConnect ||
        !p_WinStationWaitForConnectEx)
    {
        win_skip("required WinStation exports are unavailable\n");
        return;
    }
    test_session_permitted();
    test_connection_property();
    test_wait_for_connect();
    test_query_session_information();
    test_query_session_type();
}
