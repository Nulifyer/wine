/* WinRT restricted error matching and thread-local ownership tests.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */
#define COBJMACROS
#include <stdarg.h>
#include "windef.h"
#include "winbase.h"
#include "objbase.h"
#include "oleauto.h"
#include "roapi.h"
#include "roerrorapi.h"
#include "wine/test.h"

static void check_empty(void)
{
    IRestrictedErrorInfo *info = (void *)0xdeadbeef;
    HRESULT hr = GetRestrictedErrorInfo(&info);
    ok(hr == S_FALSE, "GetRestrictedErrorInfo returned %#lx.\n", hr);
    ok(!info, "Unexpected error object %p.\n", info);
    if (info && info != (void *)0xdeadbeef) IRestrictedErrorInfo_Release(info);
}

static void check_details(IRestrictedErrorInfo *info, HRESULT expected, const WCHAR *message)
{
    BSTR description = NULL, restricted = NULL, sid = NULL;
    HRESULT hr, error = S_OK;

    ok(!!info, "Missing restricted error object.\n");
    if (!info) return;
    hr = IRestrictedErrorInfo_GetErrorDetails(info, &description, &error, &restricted, &sid);
    ok(hr == S_OK, "GetErrorDetails returned %#lx.\n", hr);
    ok(error == expected, "Expected %#lx, got %#lx.\n", expected, error);
    ok(SysStringLen(description) != 0, "Missing system description.\n");
    if (message)
        ok(restricted && !wcscmp(restricted, message), "Unexpected restricted description %s.\n", wine_dbgstr_w(restricted));
    else
        ok(description && restricted && !wcscmp(description, restricted), "Default descriptions differ.\n");
    SysFreeString(description);
    SysFreeString(restricted);
    SysFreeString(sid);
}

static void test_matching(void)
{
    static const HRESULT codes[] = {S_OK, S_FALSE, E_FAIL, E_ACCESSDENIED, 0xc0000005};
    static const UINT32 flags[] = {RO_ERROR_REPORTING_USESETERRORINFO, RO_ERROR_REPORTING_NONE,
        RO_ERROR_REPORTING_SUPPRESSSETERRORINFO,
        RO_ERROR_REPORTING_USESETERRORINFO | RO_ERROR_REPORTING_SUPPRESSSETERRORINFO};
    IRestrictedErrorInfo *info, *held;
    ICreateErrorInfo *create;
    IErrorInfo *plain;
    HRESULT hr, expected;
    unsigned int i, j;
    BOOL ret;

    for (i = 0; i < ARRAY_SIZE(flags); ++i)
    {
        hr = RoSetErrorReportingFlags(flags[i]);
        ok(hr == S_OK, "RoSetErrorReportingFlags returned %#lx.\n", hr);
        for (j = 0; j < ARRAY_SIZE(codes); ++j)
        {
            winetest_push_context("flags=%#x code=%#lx", flags[i], codes[j]);
            hr = SetRestrictedErrorInfo(NULL);
            ok(hr == S_OK, "Clear returned %#lx.\n", hr);
            info = (void *)0xdeadbeef;
            expected = FAILED(codes[j]) && flags[i] == RO_ERROR_REPORTING_USESETERRORINFO ? S_OK : E_UNEXPECTED;
            hr = RoGetMatchingRestrictedErrorInfo(codes[j], &info);
            ok(hr == expected, "Matching returned %#lx, expected %#lx.\n", hr, expected);
            if (hr == S_OK && info && info != (void *)0xdeadbeef)
            {
                check_details(info, codes[j], NULL);
                IRestrictedErrorInfo_Release(info);
            }
            else ok(!info, "Unexpected object %p.\n", info);
            check_empty();
            winetest_pop_context();
        }

        /* An existing match is consumed even when origination is suppressed. */
        RoSetErrorReportingFlags(RO_ERROR_REPORTING_USESETERRORINFO);
        ret = RoOriginateErrorW(E_INVALIDARG, 0, L"alpha");
        ok(ret, "Origination failed.\n");
        held = NULL;
        hr = GetRestrictedErrorInfo(&held);
        ok(hr == S_OK && held, "GetRestrictedErrorInfo returned %#lx, %p.\n", hr, held);
        if (!held) continue;
        hr = SetRestrictedErrorInfo(held);
        ok(hr == S_OK, "SetRestrictedErrorInfo returned %#lx.\n", hr);
        RoSetErrorReportingFlags(flags[i]);
        info = NULL;
        hr = RoGetMatchingRestrictedErrorInfo(E_INVALIDARG, &info);
        ok(hr == S_OK, "Existing matching returned %#lx.\n", hr);
        ok(info == held, "Object identity changed.\n");
        check_details(info, E_INVALIDARG, L"alpha");
        if (info) IRestrictedErrorInfo_Release(info);
        check_empty();

        hr = SetRestrictedErrorInfo(held);
        ok(hr == S_OK, "SetRestrictedErrorInfo returned %#lx.\n", hr);
        info = NULL;
        hr = RoGetMatchingRestrictedErrorInfo(E_ACCESSDENIED, &info);
        expected = flags[i] == RO_ERROR_REPORTING_USESETERRORINFO ? S_OK : E_UNEXPECTED;
        ok(hr == expected, "Mismatching returned %#lx, expected %#lx.\n", hr, expected);
        ok(info != held, "Mismatched error retained its identity.\n");
        if (info)
        {
            check_details(info, E_ACCESSDENIED, NULL);
            IRestrictedErrorInfo_Release(info);
        }
        check_details(held, E_INVALIDARG, L"alpha");
        check_empty();

        hr = SetRestrictedErrorInfo(held);
        ok(hr == S_OK, "SetRestrictedErrorInfo returned %#lx.\n", hr);
        info = NULL;
        hr = RoGetMatchingRestrictedErrorInfo(S_OK, &info);
        ok(hr == E_UNEXPECTED && !info, "Success-code matching returned %#lx, %p.\n", hr, info);
        if (info) IRestrictedErrorInfo_Release(info);
        check_empty();
        IRestrictedErrorInfo_Release(held);
    }
    RoSetErrorReportingFlags(RO_ERROR_REPORTING_USESETERRORINFO);

    /* Ordinary IErrorInfo is replaced, not exposed as restricted error info. */
    hr = CreateErrorInfo(&create);
    ok(hr == S_OK, "CreateErrorInfo returned %#lx.\n", hr);
    if (FAILED(hr)) return;
    ICreateErrorInfo_SetDescription(create, L"plain");
    hr = ICreateErrorInfo_QueryInterface(create, &IID_IErrorInfo, (void **)&plain);
    ok(hr == S_OK, "QueryInterface returned %#lx.\n", hr);
    ICreateErrorInfo_Release(create);
    if (FAILED(hr)) return;
    hr = SetErrorInfo(0, plain);
    ok(hr == S_OK, "SetErrorInfo returned %#lx.\n", hr);
    IErrorInfo_Release(plain);
    info = NULL;
    hr = RoGetMatchingRestrictedErrorInfo(E_FAIL, &info);
    ok(hr == S_OK, "Plain replacement returned %#lx.\n", hr);
    check_details(info, E_FAIL, NULL);
    if (info) IRestrictedErrorInfo_Release(info);
    check_empty();
}

static DWORD WINAPI isolated_thread(void *unused)
{
    IRestrictedErrorInfo *info = NULL;
    HRESULT hr;
    check_empty();
    hr = RoGetMatchingRestrictedErrorInfo(E_ACCESSDENIED, &info);
    ok(hr == S_OK, "Worker matching returned %#lx.\n", hr);
    check_details(info, E_ACCESSDENIED, NULL);
    if (info) IRestrictedErrorInfo_Release(info);
    check_empty();
    return 0;
}

START_TEST(restricted_error)
{
    IRestrictedErrorInfo *info = NULL;
    HRESULT hr;
    HANDLE thread;
    DWORD wait;

    test_matching();
    hr = RoInitialize(RO_INIT_MULTITHREADED);
    ok(hr == S_OK, "RoInitialize returned %#lx.\n", hr);
    test_matching();
    ok(RoOriginateErrorW(E_INVALIDARG, 0, L"parent"), "Parent origination failed.\n");
    thread = CreateThread(NULL, 0, isolated_thread, NULL, 0, NULL);
    ok(!!thread, "CreateThread failed.\n");
    if (thread)
    {
        wait = WaitForSingleObject(thread, 5000);
        ok(wait == WAIT_OBJECT_0, "Worker did not finish, %lu.\n", wait);
        if (wait != WAIT_OBJECT_0) ExitProcess(3);
        CloseHandle(thread);
    }
    hr = RoGetMatchingRestrictedErrorInfo(E_INVALIDARG, &info);
    ok(hr == S_OK, "Parent matching returned %#lx.\n", hr);
    check_details(info, E_INVALIDARG, L"parent");
    if (info) IRestrictedErrorInfo_Release(info);
    check_empty();
    RoUninitialize();
}
