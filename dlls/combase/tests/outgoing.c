/*
 * Copyright 2026 LinuxNT contributors
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

static DWORD WINAPI test_outgoing_call_state_thread(void *opaque)
{
    co_set_outgoing_call_state_fn set_state = opaque;
    const ULONG_PTR first = (ULONG_PTR)0x12345678;
    const ULONG_PTR second = (ULONG_PTR)0x76543210;
    ULONG_PTR old;
    HRESULT hr;

    old = 0;
    hr = set_state(&first, &old);
    ok(hr == S_OK, "got hr %#lx.\n", hr);
    ok(old == ~(ULONG_PTR)0, "got initial state %Ix.\n", old);

    old = 0;
    hr = set_state(&second, &old);
    ok(hr == S_OK, "got hr %#lx.\n", hr);
    ok(old == first, "got previous state %Ix.\n", old);

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ok(hr == S_OK, "CoInitializeEx returned %#lx.\n", hr);

    old = 0;
    hr = set_state(&first, &old);
    ok(hr == S_OK, "got hr %#lx.\n", hr);
    ok(old == second, "got initialized previous state %Ix.\n", old);

    hr = set_state(&second, NULL);
    ok(hr == S_OK, "got hr %#lx.\n", hr);

    old = 0;
    hr = set_state(&first, &old);
    ok(hr == S_OK, "got hr %#lx.\n", hr);
    ok(old == second, "got state after NULL output %Ix.\n", old);

    CoUninitialize();
    old = 0;
    hr = set_state(&second, &old);
    ok(hr == S_OK, "got hr %#lx.\n", hr);
    ok(old == first, "got state after CoUninitialize %Ix.\n", old);
    return 0;
}

START_TEST(outgoing)
{
    co_set_outgoing_call_state_fn set_state;
    HANDLE first_thread, second_thread;

    set_state = (void *)GetProcAddress(GetModuleHandleW(L"combase.dll"),
                                      "CoSetOutgoingCallState");
    if (!set_state)
    {
        win_skip("CoSetOutgoingCallState is unavailable.\n");
        return;
    }

    first_thread = CreateThread(NULL, 0, test_outgoing_call_state_thread, set_state, 0, NULL);
    ok(!!first_thread, "CreateThread failed, error %lu.\n", GetLastError());
    if (first_thread)
    {
        WaitForSingleObject(first_thread, INFINITE);
        CloseHandle(first_thread);
    }

    second_thread = CreateThread(NULL, 0, test_outgoing_call_state_thread, set_state, 0, NULL);
    ok(!!second_thread, "CreateThread failed, error %lu.\n", GetLastError());
    if (second_thread)
    {
        WaitForSingleObject(second_thread, INFINITE);
        CloseHandle(second_thread);
    }
}
