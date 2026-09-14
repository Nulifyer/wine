/*
 * Tests for CoSetOutgoingCallState
 *
 * Copyright 2026 Nulifyer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "objbase.h"

#include "wine/test.h"

typedef HRESULT (WINAPI *co_set_outgoing_call_state_fn)(const ULONG_PTR *, ULONG_PTR *);

struct thread_args
{
    co_set_outgoing_call_state_fn set_state;
    ULONG_PTR first_old;
    ULONG_PTR second_old;
    HRESULT first_hr;
    HRESULT second_hr;
};

static DWORD WINAPI test_thread_state(void *opaque)
{
    static const ULONG_PTR first = (ULONG_PTR)0x1122334455667788ULL;
    static const ULONG_PTR second = (ULONG_PTR)0x8877665544332211ULL;
    struct thread_args *args = opaque;

    args->first_hr = args->set_state(&first, &args->first_old);
    args->second_hr = args->set_state(&second, &args->second_old);
    return 0;
}

static void test_outgoing_call_state(void)
{
    static const ULONG_PTR first = (ULONG_PTR)0x0123456789abcdefULL;
    static const ULONG_PTR second = (ULONG_PTR)0xfedcba9876543210ULL;
    co_set_outgoing_call_state_fn set_state;
    struct thread_args args = {0};
    ULONG_PTR old_state;
    HRESULT hr;
    HANDLE thread;
    DWORD wait;

    set_state = (void *)GetProcAddress(GetModuleHandleW(L"combase.dll"), "CoSetOutgoingCallState");
    if (!set_state)
    {
        win_skip("CoSetOutgoingCallState is unavailable.\n");
        return;
    }

    old_state = (ULONG_PTR)0xaaaaaaaaaaaaaaaaULL;
    hr = set_state(&first, &old_state);
    ok(hr == S_OK, "Got hr %#lx.\n", hr);
    ok(old_state == ~(ULONG_PTR)0, "Got initial state %#Ix.\n", old_state);

    old_state = (ULONG_PTR)0xbbbbbbbbbbbbbbbbULL;
    hr = set_state(&second, &old_state);
    ok(hr == S_OK, "Got hr %#lx.\n", hr);
    ok(old_state == first, "Got prior state %#Ix.\n", old_state);

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ok(hr == S_OK, "CoInitializeEx returned %#lx.\n", hr);

    old_state = (ULONG_PTR)0xccccccccccccccccULL;
    hr = set_state(&first, &old_state);
    ok(hr == S_OK, "Got hr %#lx.\n", hr);
    ok(old_state == second, "Got state after initialization %#Ix.\n", old_state);

    hr = set_state(&second, NULL);
    ok(hr == S_OK, "Got hr %#lx with no prior-state output.\n", hr);

    old_state = (ULONG_PTR)0xddddddddddddddddULL;
    hr = set_state(&first, &old_state);
    ok(hr == S_OK, "Got hr %#lx.\n", hr);
    ok(old_state == second, "Got state after null output %#Ix.\n", old_state);

    args.set_state = set_state;
    args.first_old = (ULONG_PTR)0xccccccccccccccccULL;
    args.second_old = (ULONG_PTR)0xddddddddddddddddULL;
    thread = CreateThread(NULL, 0, test_thread_state, &args, 0, NULL);
    ok(!!thread, "CreateThread failed, error %lu.\n", GetLastError());
    if (thread)
    {
        wait = WaitForSingleObject(thread, 5000);
        ok(wait == WAIT_OBJECT_0, "Thread wait returned %#lx.\n", wait);
        CloseHandle(thread);
        ok(args.first_hr == S_OK, "First thread call returned %#lx.\n", args.first_hr);
        ok(args.first_old == ~(ULONG_PTR)0, "Got initial thread state %#Ix.\n", args.first_old);
        ok(args.second_hr == S_OK, "Second thread call returned %#lx.\n", args.second_hr);
        ok(args.second_old == (ULONG_PTR)0x1122334455667788ULL,
                "Got prior thread state %#Ix.\n", args.second_old);
    }

    old_state = (ULONG_PTR)0xeeeeeeeeeeeeeeeeULL;
    hr = set_state(&second, &old_state);
    ok(hr == S_OK, "Got hr %#lx.\n", hr);
    ok(old_state == first, "Other thread changed main state to %#Ix.\n", old_state);

    CoUninitialize();
    old_state = ~(ULONG_PTR)0;
    hr = set_state(&first, &old_state);
    ok(hr == S_OK, "Got hr %#lx after uninitialization.\n", hr);
    ok(old_state == second, "Got state after uninitialization %#Ix.\n", old_state);
}

START_TEST(outgoing_call_state)
{
    test_outgoing_call_state();
}
