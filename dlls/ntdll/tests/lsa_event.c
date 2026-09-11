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
#include "wine/test.h"

START_TEST(lsa_event)
{
    static const WCHAR event_nameW[] = L"\\Security\\LSA_AUTHENTICATION_INITIALIZED";
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING name;
    LARGE_INTEGER timeout;
    HANDLE event;
    NTSTATUS status;

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
