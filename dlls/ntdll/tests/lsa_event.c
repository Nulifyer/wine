/* Unit tests for the LinuxNT LSA initialization event.
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "evntprov.h"
#include "wine/test.h"

static void test_security_provider(void)
{
    ULONG (WINAPI *pEtwRegisterSecurityProvider)(void);
    ULONG (WINAPI *pEtwWriteUMSecurityEvent)(const EVENT_DESCRIPTOR *, USHORT, ULONG,
                                             EVENT_DATA_DESCRIPTOR *);
    EVENT_DESCRIPTOR descriptor = {0};
    ULONG ret;

    pEtwRegisterSecurityProvider = (void *)GetProcAddress( GetModuleHandleW( L"ntdll.dll" ),
                                                           "EtwRegisterSecurityProvider" );
    ok( pEtwRegisterSecurityProvider != NULL, "EtwRegisterSecurityProvider is not exported\n" );
    if (!pEtwRegisterSecurityProvider) return;

    ret = pEtwRegisterSecurityProvider();
    ok( ret == ERROR_SUCCESS, "EtwRegisterSecurityProvider returned %lu\n", ret );

    pEtwWriteUMSecurityEvent = (void *)GetProcAddress( GetModuleHandleW( L"ntdll.dll" ),
                                                       "EtwWriteUMSecurityEvent" );
    ok( pEtwWriteUMSecurityEvent != NULL, "EtwWriteUMSecurityEvent is not exported\n" );
    if (!pEtwWriteUMSecurityEvent) return;

    ret = pEtwWriteUMSecurityEvent( NULL, 0, 0, NULL );
    ok( ret == ERROR_INVALID_PARAMETER, "NULL descriptor returned %lu\n", ret );
    ret = pEtwWriteUMSecurityEvent( &descriptor, 0, 0, NULL );
    ok( ret == ERROR_SUCCESS, "EtwWriteUMSecurityEvent returned %lu\n", ret );
}

static void test_report_event(void)
{
    BOOL (WINAPI *pEvtIntReportEventAndSourceAsync)(HANDLE, const WCHAR *, USHORT, USHORT,
                                                    ULONG, PSID, USHORT, ULONG,
                                                    const WCHAR **, void *);
    static const WCHAR sourceW[] = L"Wine test";
    BOOL ret;

    pEvtIntReportEventAndSourceAsync = (void *)GetProcAddress( GetModuleHandleW( L"ntdll.dll" ),
                                                               "EvtIntReportEventAndSourceAsync" );
    ok( pEvtIntReportEventAndSourceAsync != NULL,
        "EvtIntReportEventAndSourceAsync is not exported\n" );
    if (!pEvtIntReportEventAndSourceAsync) return;

    SetLastError( 0xdeadbeef );
    ret = pEvtIntReportEventAndSourceAsync( NULL, sourceW, EVENTLOG_ERROR_TYPE, 0, 1,
                                            NULL, 0, 0, NULL, NULL );
    ok( ret == TRUE, "EvtIntReportEventAndSourceAsync returned %d\n", ret );
    ok( GetLastError() == ERROR_SUCCESS, "last error is %lu\n", GetLastError() );
}

static void test_cpu_speed(void)
{
    NTSTATUS (WINAPI *pEtwpGetCpuSpeed)(ULONG *);
    ULONG speed = 0;
    NTSTATUS status;

    pEtwpGetCpuSpeed = (void *)GetProcAddress( GetModuleHandleW( L"ntdll.dll" ),
                                               "EtwpGetCpuSpeed" );
    ok( pEtwpGetCpuSpeed != NULL, "EtwpGetCpuSpeed is not exported\n" );
    if (!pEtwpGetCpuSpeed) return;

    status = pEtwpGetCpuSpeed( &speed );
    ok( status == STATUS_SUCCESS, "EtwpGetCpuSpeed returned %#lx\n", status );
    ok( speed != 0, "EtwpGetCpuSpeed returned a zero speed\n" );
}

START_TEST(lsa_event)
{
    static const WCHAR event_nameW[] = L"\\Security\\LSA_AUTHENTICATION_INITIALIZED";
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING name;
    LARGE_INTEGER timeout;
    HANDLE event;
    NTSTATUS status;

    test_security_provider();
    test_report_event();
    test_cpu_speed();

    RtlInitUnicodeString( &name, event_nameW );
    InitializeObjectAttributes( &attributes, &name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    status = NtOpenEvent( &event, SYNCHRONIZE | EVENT_MODIFY_STATE, &attributes );
    ok( status == STATUS_SUCCESS, "NtOpenEvent returned %#lx\n", status );
    if (status) return;

    timeout.QuadPart = 0;
    status = NtWaitForSingleObject( event, FALSE, &timeout );
    ok( status == STATUS_TIMEOUT, "initial wait returned %#lx\n", status );

    status = NtSetEvent( event, NULL );
    ok( status == STATUS_SUCCESS, "NtSetEvent returned %#lx\n", status );
    status = NtWaitForSingleObject( event, FALSE, &timeout );
    ok( status == STATUS_SUCCESS, "signaled wait returned %#lx\n", status );
    status = NtResetEvent( event, NULL );
    ok( status == STATUS_SUCCESS, "NtResetEvent returned %#lx\n", status );
    status = NtClose( event );
    ok( status == STATUS_SUCCESS, "NtClose returned %#lx\n", status );
}
