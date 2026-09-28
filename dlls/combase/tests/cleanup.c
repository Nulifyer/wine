/*
 * Copyright 2026 Nulifyer
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
#include "winternl.h"

#include "wine/test.h"

static void test_cleanup_flags(void)
{
    void (WINAPI *clear_cleanup_flag)(DWORD);
    void (WINAPI *set_cleanup_flag)(DWORD);
    HMODULE module;

    module = GetModuleHandleW(L"combase.dll");
    ok(!!module, "combase.dll is not loaded.\n");
    if (!module) return;

    clear_cleanup_flag = (void *)GetProcAddress(module, "ClearCleanupFlag");
    set_cleanup_flag = (void *)GetProcAddress(module, "SetCleanupFlag");
    ok(!!clear_cleanup_flag, "ClearCleanupFlag is not exported.\n");
    ok(!!set_cleanup_flag, "SetCleanupFlag is not exported.\n");
    if (!clear_cleanup_flag || !set_cleanup_flag) return;

    set_cleanup_flag(0x1);
    set_cleanup_flag(0x2);
    clear_cleanup_flag(0x1);
    clear_cleanup_flag(0x2);
}

struct cleanup_context
{
    HANDLE ready;
    HANDLE cleaned;
};

static DWORD WINAPI cleanup_thread(void *arg)
{
    struct cleanup_context *context = arg;
    ICreateErrorInfo *create;
    IErrorInfo *errorinfo = NULL;
    HRESULT hr;

    hr = CreateErrorInfo(&create);
    ok(hr == S_OK, "CreateErrorInfo returned %#lx.\n", hr);
    if (FAILED(hr)) return 1;
    hr = ICreateErrorInfo_QueryInterface(create, &IID_IErrorInfo, (void **)&errorinfo);
    ok(hr == S_OK, "QueryInterface returned %#lx.\n", hr);
    ICreateErrorInfo_Release(create);
    if (FAILED(hr)) return 1;

    hr = SetErrorInfo(0, errorinfo);
    ok(hr == S_OK, "SetErrorInfo returned %#lx.\n", hr);
    IErrorInfo_Release(errorinfo);
    SetEvent(context->ready);

    ok(WaitForSingleObject(context->cleaned, 5000) == WAIT_OBJECT_0, "Cleanup wait timed out.\n");
    errorinfo = (void *)0xdeadbeef;
    hr = GetErrorInfo(0, &errorinfo);
    ok(hr == S_FALSE, "GetErrorInfo returned %#lx.\n", hr);
    ok(!errorinfo, "Expected cleared error info, got %p.\n", errorinfo);
    return 0;
}

static void test_coml2_cleanup(void)
{
    void (WINAPI *cleanup_all)(void);
    void (WINAPI *cleanup_tls)(void *);
    struct cleanup_context context;
    ICreateErrorInfo *create;
    IErrorInfo *errorinfo = NULL;
    HMODULE module;
    HANDLE thread;
    HRESULT hr;

    module = GetModuleHandleW(L"combase.dll");
    cleanup_all = (void *)GetProcAddress(module, "CleanupComl2StateInAllTls");
    cleanup_tls = (void *)GetProcAddress(module, "CleanupTlsComl2State");
    ok(!!cleanup_all, "CleanupComl2StateInAllTls is not exported.\n");
    ok(!!cleanup_tls, "CleanupTlsComl2State is not exported.\n");
    ok((FARPROC)cleanup_all == GetProcAddress(module, (const char *)248),
            "CleanupComl2StateInAllTls ordinal mismatch.\n");
    ok((FARPROC)cleanup_tls == GetProcAddress(module, (const char *)250),
            "CleanupTlsComl2State ordinal mismatch.\n");
    if (!cleanup_all || !cleanup_tls) return;

    hr = CreateErrorInfo(&create);
    ok(hr == S_OK, "CreateErrorInfo returned %#lx.\n", hr);
    if (FAILED(hr)) return;
    hr = ICreateErrorInfo_QueryInterface(create, &IID_IErrorInfo, (void **)&errorinfo);
    ok(hr == S_OK, "QueryInterface returned %#lx.\n", hr);
    ICreateErrorInfo_Release(create);
    if (FAILED(hr)) return;
    hr = SetErrorInfo(0, errorinfo);
    ok(hr == S_OK, "SetErrorInfo returned %#lx.\n", hr);
    IErrorInfo_Release(errorinfo);

    cleanup_tls(NtCurrentTeb()->ReservedForOle);
    errorinfo = (void *)0xdeadbeef;
    hr = GetErrorInfo(0, &errorinfo);
    ok(hr == S_FALSE, "GetErrorInfo returned %#lx.\n", hr);
    ok(!errorinfo, "Expected cleared error info, got %p.\n", errorinfo);

    context.ready = CreateEventW(NULL, FALSE, FALSE, NULL);
    context.cleaned = CreateEventW(NULL, FALSE, FALSE, NULL);
    ok(!!context.ready && !!context.cleaned, "Failed to create events, error %lu.\n", GetLastError());
    thread = CreateThread(NULL, 0, cleanup_thread, &context, 0, NULL);
    ok(!!thread, "Failed to create thread, error %lu.\n", GetLastError());
    if (thread)
    {
        ok(WaitForSingleObject(context.ready, 5000) == WAIT_OBJECT_0, "Worker wait timed out.\n");
        cleanup_all();
        SetEvent(context.cleaned);
        ok(WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0, "Thread wait timed out.\n");
        CloseHandle(thread);
    }
    CloseHandle(context.cleaned);
    CloseHandle(context.ready);
}

START_TEST(cleanup)
{
    test_cleanup_flags();
    test_coml2_cleanup();
}
