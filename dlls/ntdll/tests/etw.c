/* Unit tests for NTDLL ETW support.
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>
#include <string.h>

#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "wmistr.h"
#include "evntprov.h"

#include "wine/test.h"

struct etw_private_logger_request
{
    ULONG type;
    ULONG size;
    ULONGLONG reserved[6];
    ULONGLONG context[2];
    WNODE_HEADER logger;
    BYTE data[0xb0 - sizeof(WNODE_HEADER)];
};

static void test_private_logger_request(void)
{
    static const GUID system_trace_control_guid =
        {0x9e814aad, 0x3204, 0x11d2, {0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39}};
    ULONG (WINAPI *process_private_logger_request)(struct etw_private_logger_request *);
    struct etw_private_logger_request request;
    HMODULE ntdll = GetModuleHandleA( "ntdll.dll" );
    ULONG ret;

    process_private_logger_request = (void *)GetProcAddress( ntdll, "EtwProcessPrivateLoggerRequest" );
    ok( !!process_private_logger_request, "EtwProcessPrivateLoggerRequest is unavailable\n" );
    if (!process_private_logger_request) return;

    memset( &request, 0xcc, sizeof(request) );
    request.size = sizeof(request) - 1;
    ret = process_private_logger_request( &request );
    ok( ret == ERROR_WMI_INSTANCE_NOT_FOUND, "got %lu\n", ret );
    ok( request.type == 0xcccccccc, "request was modified\n" );

    memset( &request, 0, sizeof(request) );
    request.size = sizeof(request);
    request.logger.BufferSize = 0xb0;
    request.logger.ProviderId = 3;
    request.logger.Guid = system_trace_control_guid;
    request.logger.Flags = WNODE_FLAG_TRACED_GUID;
    request.context[0] = 0x1122334455667788;
    request.context[1] = 0x8877665544332211;
    ret = process_private_logger_request( &request );
    ok( ret == ERROR_SUCCESS, "got %lu\n", ret );
    ok( request.type == 4, "got response type %lu\n", request.type );
    ok( request.size == 0x4c, "got response size %lu\n", request.size );
    ok( request.reserved[4] == 0x1122334455667788, "context 0 was not preserved\n" );
    ok( request.reserved[5] == 0x8877665544332211, "context 1 was not preserved\n" );
    ok( request.logger.BufferSize == ERROR_WMI_INSTANCE_NOT_FOUND, "got logger status %lu\n",
        request.logger.BufferSize );

    memset( &request, 0, sizeof(request) );
    request.size = sizeof(request);
    request.logger.BufferSize = 0xb0;
    request.logger.ProviderId = 3;
    request.logger.Guid = system_trace_control_guid;
    ret = process_private_logger_request( &request );
    ok( ret == ERROR_SUCCESS, "got %lu\n", ret );
    ok( request.logger.BufferSize == ERROR_INVALID_DATA, "got logger status %lu\n",
        request.logger.BufferSize );
}

static void test_event_write_no_registration(void)
{
    static const GUID provider =
        {0x57696e65, 0x4554, 0x5700, {0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x01}};
    ULONG (WINAPI *write_no_registration)(const GUID *, const EVENT_DESCRIPTOR *, ULONG,
                                          EVENT_DATA_DESCRIPTOR *);
    EVENT_DESCRIPTOR descriptor = {0};
    EVENT_DATA_DESCRIPTOR data;
    HMODULE ntdll = GetModuleHandleA( "ntdll.dll" );
    ULONG value = 0x12345678, ret;

    write_no_registration = (void *)GetProcAddress( ntdll, "EtwEventWriteNoRegistration" );
    ok( !!write_no_registration, "EtwEventWriteNoRegistration is unavailable\n" );
    if (!write_no_registration) return;

    descriptor.Id = 1;
    descriptor.Level = 4;
    data.Ptr = (ULONGLONG)(ULONG_PTR)&value;
    data.Size = sizeof(value);
    data.Reserved = 0;

    ret = write_no_registration( NULL, &descriptor, 1, &data );
    ok( ret == ERROR_INVALID_PARAMETER, "null provider returned %lu\n", ret );
    ret = write_no_registration( &provider, NULL, 1, &data );
    ok( ret == ERROR_INVALID_PARAMETER, "null descriptor returned %lu\n", ret );
    ret = write_no_registration( &provider, &descriptor, 1, NULL );
    ok( ret == ERROR_INVALID_PARAMETER, "null data returned %lu\n", ret );
    ret = write_no_registration( &provider, &descriptor, 1, &data );
    ok( ret == ERROR_SUCCESS, "valid event returned %lu\n", ret );
}

START_TEST(etw)
{
    test_private_logger_request();
    test_event_write_no_registration();
}
