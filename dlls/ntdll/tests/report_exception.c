/*
 * Exception reporting tests
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

static NTSTATUS (WINAPI *pRtlReportException)(EXCEPTION_RECORD *, CONTEXT *, ULONG);
static NTSTATUS (WINAPI *pRtlReportExceptionEx)(EXCEPTION_RECORD *, CONTEXT *, ULONG, HANDLE, HANDLE);

static void test_report_exception(void)
{
    EXCEPTION_RECORD record = {0};
    CONTEXT context;
    NTSTATUS status;

    if (!pRtlReportException)
    {
        win_skip("RtlReportException is unavailable.\n");
        return;
    }

    memset(&context, 0, sizeof(context));
    RtlCaptureContext(&context);
    record.ExceptionCode = STATUS_UNSUCCESSFUL;

    status = pRtlReportException(&record, &context, 0x20);
    ok(status == STATUS_INVALID_PARAMETER, "got status %#lx.\n", status);

    if (pRtlReportExceptionEx)
    {
        status = pRtlReportExceptionEx(&record, &context, 0x20,
                                       GetCurrentProcess(), GetCurrentThread());
        ok(status == STATUS_INVALID_PARAMETER, "got status %#lx.\n", status);
    }

    /* A valid native report can invoke Windows Error Reporting. */
    if (!winetest_platform_is_wine) return;

    status = pRtlReportException(&record, &context, 4);
    ok(status == STATUS_SUCCESS, "got status %#lx.\n", status);

    if (pRtlReportExceptionEx)
    {
        status = pRtlReportExceptionEx(&record, &context, 4,
                                       GetCurrentProcess(), GetCurrentThread());
        ok(status == STATUS_SUCCESS, "got status %#lx.\n", status);
    }
}

START_TEST(report_exception)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    pRtlReportException = (void *)GetProcAddress(ntdll, "RtlReportException");
    pRtlReportExceptionEx = (void *)GetProcAddress(ntdll, "RtlReportExceptionEx");

    ok(!!pRtlReportException, "RtlReportException is not exported.\n");
    ok(!!pRtlReportExceptionEx, "RtlReportExceptionEx is not exported.\n");
    test_report_exception();
}
