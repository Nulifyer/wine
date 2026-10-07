/* Private USER32 message-pump hook tests.
 *
 * Copyright 2026 Nulifyer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "windows.h"
#include "wine/test.h"

struct pump
{
    DWORD size;
    BOOL (CDECL *message)(MSG *, HWND, UINT, UINT, UINT, BOOL);
    BOOL (CDECL *wait)(UINT, DWORD);
    DWORD (CDECL *queue)(UINT);
    DWORD (CDECL *objects)(DWORD, const HANDLE *, DWORD, DWORD, DWORD);
};
typedef BOOL (CDECL *init_fn)(DWORD, struct pump *);
static BOOL (WINAPI *pRegisterMessagePumpHook)(init_fn);
static BOOL (WINAPI *pUnregisterMessagePumpHook)(void);
static struct pump original;
static unsigned int init_calls, done_calls, message_calls, wait_calls, queue_calls, object_calls;
static int init_mode, message_ret = 77;

static BOOL CDECL message_hook(MSG *msg, HWND hwnd, UINT first, UINT last, UINT flags, BOOL blocking)
{
    message_calls++;
    if (!blocking)
    {
        ok(!hwnd && first == WM_APP + 10 && last == WM_APP + 10 && flags == PM_REMOVE,
           "unexpected nonblocking retrieval filter %p %u %u %#x\n", hwnd, first, last, flags);
        return original.message(msg, hwnd, first, last, flags, blocking);
    }
    ok(!hwnd && !first && !last, "unexpected retrieval filter %p %u %u\n", hwnd, first, last);
    ok(flags == PM_REMOVE && blocking == TRUE, "unexpected retrieval flags %#x, blocking %d\n", flags, blocking);
    memset(msg, 0, sizeof(*msg));
    msg->message = message_ret ? WM_APP + 7 : WM_QUIT;
    msg->wParam = 0x99;
    msg->lParam = 0x55;
    return message_ret;
}

static BOOL CDECL wait_hook(UINT mask, DWORD timeout)
{
    wait_calls++;
    ok(mask == 0x3cff && !timeout, "unexpected wait mask %#x, timeout %lu\n", mask, timeout);
    return original.wait(mask, timeout);
}

static DWORD CDECL queue_hook(UINT mask)
{
    queue_calls++;
    ok(!mask, "unexpected queue mask %#x\n", mask);
    return original.queue(mask);
}

static DWORD CDECL objects_hook(DWORD count, const HANDLE *handles, DWORD timeout, DWORD mask, DWORD flags)
{
    object_calls++;
    ok(!count && !handles && !timeout && !mask && !flags, "unexpected object wait arguments\n");
    return original.objects(count, handles, timeout, mask, flags);
}

static BOOL CDECL initialize(DWORD code, struct pump *table)
{
    if (code == 1)
    {
        done_calls++;
        ok(!table, "cleanup table %p\n", table);
        return TRUE;
    }
    init_calls++;
    ok(!code && table, "unexpected initialization %lu %p\n", code, table);
    if (!table) return FALSE;
    ok(table->size == sizeof(*table), "table size %lu\n", table->size);
    ok(table->message && table->wait && table->queue && table->objects, "missing original function\n");
    if (init_mode == 1) return FALSE;
    if (init_mode == 2) { table->size = 0; return TRUE; }
    original = *table;
    table->message = message_hook;
    table->wait = wait_hook;
    table->queue = queue_hook;
    table->objects = objects_hook;
    return TRUE;
}

static BOOL CDECL other_initialize(DWORD code, struct pump *table)
{
    ok(0, "conflicting callback reached\n");
    return FALSE;
}

static void register_hook(init_fn callback, BOOL expected)
{
    BOOL ret;
    SetLastError(0x12345678);
    ret = pRegisterMessagePumpHook(callback);
    ok(ret == expected, "register returned %d, expected %d\n", ret, expected);
    ok(GetLastError() == (callback ? 0x12345678 : ERROR_INVALID_PARAMETER),
       "register last error %lu\n", GetLastError());
}

static void unregister_hook(BOOL expected)
{
    BOOL ret;
    SetLastError(0x12345678);
    ret = pUnregisterMessagePumpHook();
    ok(ret == expected, "unregister returned %d, expected %d\n", ret, expected);
    ok(GetLastError() == 0x12345678, "unregister last error %lu\n", GetLastError());
}

static void exercise(BOOL active)
{
    MSG msg;
    unsigned int old_queue = queue_calls, old_objects = object_calls, old_wait = wait_calls;

    GetQueueStatus(0);
    MsgWaitForMultipleObjectsEx(0, NULL, 0, 0, 0);
    MsgWaitForMultipleObjects(0, NULL, FALSE, 0, 0);
    PeekMessageW(&msg, NULL, 0, 0, PM_NOREMOVE);
    PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE);
    ok(queue_calls == old_queue + active, "queue hook count %u\n", queue_calls);
    ok(object_calls == old_objects + 2 * active, "object hook count %u\n", object_calls);
    if (active)
    {
        SetLastError(0x12345678);
        ok(!WaitMessage(), "original wait unexpectedly succeeded\n");
        ok(GetLastError() == ERROR_INVALID_FLAGS, "wait error %lu\n", GetLastError());
        ok(wait_calls == old_wait + 1, "wait hook count %u\n", wait_calls);
    }
}

static DWORD WINAPI worker(void *unused)
{
    exercise(FALSE);
    unregister_hook(FALSE);
    register_hook(initialize, TRUE);
    exercise(TRUE);
    unregister_hook(TRUE);
    exercise(FALSE);
    return 0;
}

static DWORD WINAPI exiting_worker(void *unused)
{
    register_hook(initialize, TRUE);
    register_hook(initialize, TRUE);
    return 0;
}

static void run_thread(LPTHREAD_START_ROUTINE routine)
{
    HANDLE thread = CreateThread(NULL, 0, routine, NULL, 0, NULL);
    ok(!!thread, "CreateThread failed %lu\n", GetLastError());
    if (!thread) return;
    ok(WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0, "worker did not complete\n");
    CloseHandle(thread);
}

START_TEST(message_pump)
{
    HMODULE user32 = GetModuleHandleA("user32.dll");
    MSG msg;
    BOOL ret;
    unsigned int i;
    static const int returns[] = {77, 0, -1};

    pRegisterMessagePumpHook = (void *)GetProcAddress(user32, "RegisterMessagePumpHook");
    pUnregisterMessagePumpHook = (void *)GetProcAddress(user32, "UnregisterMessagePumpHook");
    if (!pRegisterMessagePumpHook || !pUnregisterMessagePumpHook)
    {
        win_skip("message-pump hook exports unavailable\n");
        return;
    }
    PeekMessageW(&msg, NULL, 0, 0, PM_NOREMOVE);
    unregister_hook(FALSE);
    register_hook(NULL, FALSE);
    init_mode = 1; register_hook(initialize, FALSE);
    init_mode = 2; register_hook(initialize, FALSE);
    init_mode = 0; register_hook(initialize, TRUE);
    register_hook(initialize, TRUE);
    register_hook(other_initialize, FALSE);
    ok(init_calls == 3 && !done_calls, "initial callback counts %u %u\n", init_calls, done_calls);
    exercise(TRUE);
    for (i = 0; i < ARRAY_SIZE(returns); i++)
    {
        message_ret = returns[i];
        memset(&msg, 0, sizeof(msg)); SetLastError(0x12345678);
        ret = GetMessageW(&msg, NULL, 0, 0);
        ok(ret == message_ret, "Unicode retrieval returned %d\n", ret);
        ok(msg.message == (message_ret ? WM_APP + 7 : WM_QUIT) && msg.wParam == 0x99 && msg.lParam == 0x55,
           "Unicode message output %u %Ix %Ix\n", msg.message, msg.wParam, msg.lParam);
        ok(GetLastError() == 0x12345678, "Unicode retrieval error %lu\n", GetLastError());
        memset(&msg, 0, sizeof(msg)); SetLastError(0x12345678);
        ret = GetMessageA(&msg, NULL, 0, 0);
        ok(ret == message_ret, "ANSI retrieval returned %d\n", ret);
        ok(msg.message == (message_ret ? WM_APP + 7 : WM_QUIT) && msg.wParam == 0x99 && msg.lParam == 0x55,
           "ANSI message output %u %Ix %Ix\n", msg.message, msg.wParam, msg.lParam);
        ok(GetLastError() == 0x12345678, "ANSI retrieval error %lu\n", GetLastError());
    }
    ok(message_calls == 6, "retrieval hook count %u\n", message_calls);
    memset(&msg, 0, sizeof(msg));
    ret = original.message(&msg, NULL, WM_APP + 10, WM_APP + 10, PM_NOREMOVE, FALSE);
    ok(!ret && !msg.message, "empty original retrieval %d %u\n", ret, msg.message);
    PostThreadMessageW(GetCurrentThreadId(), WM_APP + 10, 0x66, 0x77);
    SetLastError(0x12345678);
    ret = original.message(&msg, NULL, WM_APP + 10, WM_APP + 10, PM_NOREMOVE, FALSE);
    ok(GetLastError() == 0x12345678, "thread-message peek error %lu\n", GetLastError());
    ok(ret == 1 && msg.message == WM_APP + 10 && msg.wParam == 0x66 && msg.lParam == 0x77,
       "original peek result %d %u\n", ret, msg.message);
    SetLastError(0x12345678);
    ret = original.message(&msg, NULL, WM_APP + 10, WM_APP + 10, PM_REMOVE, TRUE);
    ok(GetLastError() == 0x12345678, "thread-message retrieval error %lu\n", GetLastError());
    ok(ret == 1 && msg.wParam == 0x66, "original blocking retrieval %d\n", ret);
    msg.message = 0x1234; SetLastError(0x12345678);
    ret = original.message(&msg, NULL, 0, 0, 4, FALSE);
    ok(!ret && msg.message == 0x1234 && GetLastError() == ERROR_INVALID_FLAGS,
       "invalid original flags %d %u %lu\n", ret, msg.message, GetLastError());
    SetLastError(0x12345678);
    ret = original.wait(QS_ALLINPUT, 1);
    ok(!ret && GetLastError() == ERROR_TIMEOUT, "original timeout %d %lu\n", ret, GetLastError());
    PostThreadMessageW(GetCurrentThreadId(), WM_APP + 10, 0xaa, 0xbb);
    SetLastError(0x12345678);
    ret = PeekMessageW(&msg, NULL, WM_APP + 10, WM_APP + 10, PM_REMOVE);
    ok(ret == 1 && msg.message == WM_APP + 10 && msg.wParam == 0xaa && msg.lParam == 0xbb,
       "queued public peek returned %d %u\n", ret, msg.message);
    ok(GetLastError() == 0x12345678, "queued public peek error %lu\n", GetLastError());
    ok(message_calls == 7, "queued public peek hook count %u\n", message_calls);
    run_thread(worker);
    ok(init_calls == 3 && !done_calls, "worker changed callback lifetime %u %u\n", init_calls, done_calls);
    unregister_hook(TRUE); exercise(TRUE);
    unregister_hook(TRUE); exercise(FALSE);
    ok(done_calls == 1, "final cleanup count %u\n", done_calls);
    unregister_hook(FALSE);
    register_hook(initialize, TRUE); unregister_hook(TRUE);
    ok(init_calls == 4 && done_calls == 2, "fresh lifetime counts %u %u\n", init_calls, done_calls);
    run_thread(exiting_worker);
    ok(init_calls == 5 && done_calls == 2, "thread exit changed callback lifetime %u %u\n", init_calls, done_calls);
    register_hook(other_initialize, FALSE);
    register_hook(initialize, TRUE); unregister_hook(TRUE); unregister_hook(FALSE);
    ok(init_calls == 5 && done_calls == 2, "unbalanced lifetime counts %u %u\n", init_calls, done_calls);
}
