/*
 * Synchronous COM task-pool completion and apartment dispatch.
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */
#define COBJMACROS
#include "windows.h"
#include "objbase.h"
#include "initguid.h"
#include "ctxtcall.h"
#include "wine/test.h"

struct task_iface;
struct task_vtbl
{
    HRESULT (WINAPI *QueryInterface)(struct task_iface *, REFIID, void **);
    ULONG (WINAPI *AddRef)(struct task_iface *);
    ULONG (WINAPI *Release)(struct task_iface *);
    HRESULT (WINAPI *Run)(struct task_iface *);
};
struct task_iface { const struct task_vtbl *lpVtbl; };
struct task
{
    struct task_iface iface;
    LONG refs;
    HANDLE entered, allow_finish, returned, completed, released;
    DWORD caller, worker, callback_thread;
    APTTYPE apartment;
    APTTYPEQUALIFIER qualifier;
    HRESULT apartment_hr, callback_hr;
    IContextCallback *context;
    BOOL waited_before_return;
    LONG writes;
};

static HRESULT (WINAPI *queue_task)(DWORD, DWORD, DWORD, DWORD, struct task_iface *, IUnknown **);
static DWORD (WINAPI *unique_context)(void);

static struct task *impl(struct task_iface *iface)
{
    return CONTAINING_RECORD(iface, struct task, iface);
}

static HRESULT WINAPI task_QueryInterface(struct task_iface *iface, REFIID iid, void **out)
{
    *out = NULL;
    if (!IsEqualIID(iid, &IID_IUnknown)) return E_NOINTERFACE;
    *out = iface;
    iface->lpVtbl->AddRef(iface);
    return S_OK;
}
static ULONG WINAPI task_AddRef(struct task_iface *iface)
{
    return InterlockedIncrement(&impl(iface)->refs);
}
static ULONG WINAPI task_Release(struct task_iface *iface)
{
    struct task *task = impl(iface);
    ULONG refs = InterlockedDecrement(&task->refs);
    if (refs == 1) SetEvent(task->released);
    return refs;
}
static HRESULT WINAPI context_callback(ComCallData *data)
{
    struct task *task = data->pUserDefined;
    task->callback_thread = GetCurrentThreadId();
    return S_OK;
}
static HRESULT WINAPI task_Run(struct task_iface *iface)
{
    struct task *task = impl(iface);
    ComCallData data = {0};

    task->worker = GetCurrentThreadId();
    task->apartment_hr = CoGetApartmentType(&task->apartment, &task->qualifier);
    SetEvent(task->entered);
    if (task->context)
    {
        data.pUserDefined = task;
        task->callback_hr = IContextCallback_ContextCallback(task->context, context_callback,
                &data, &IID_IContextCallback, 0, NULL);
    }
    ok(WaitForSingleObject(task->allow_finish, 5000) == WAIT_OBJECT_0, "finish gate timed out\n");
    InterlockedIncrement(&task->writes);
    SetEvent(task->completed);
    return E_FAIL; /* Queue success is independent of the task's HRESULT. */
}
static const struct task_vtbl task_vtbl = {task_QueryInterface, task_AddRef, task_Release, task_Run};

static DWORD WINAPI release_gate(void *arg)
{
    struct task *task = arg;
    ok(WaitForSingleObject(task->entered, 5000) == WAIT_OBJECT_0, "task did not enter\n");
    task->waited_before_return = WaitForSingleObject(task->returned, 100) == WAIT_TIMEOUT;
    SetEvent(task->allow_finish);
    return 0;
}

static void test_sync(DWORD apartment, DWORD options, BOOL callback)
{
    struct task task = {{&task_vtbl}, 1};
    IUnknown *delayed = (IUnknown *)0xdeadbeef;
    HANDLE observer;
    HRESULT hr;
    DWORD expected = apartment == 1 ? APTTYPE_STA : APTTYPE_MTA;
    BOOL finished_before_return;

    winetest_push_context("apartment %lu options %#lx callback %u", apartment, options, callback);
    task.caller = GetCurrentThreadId();
    task.entered = CreateEventW(NULL, TRUE, FALSE, NULL);
    task.allow_finish = CreateEventW(NULL, TRUE, FALSE, NULL);
    task.returned = CreateEventW(NULL, TRUE, FALSE, NULL);
    task.completed = CreateEventW(NULL, TRUE, FALSE, NULL);
    task.released = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (callback)
    {
        hr = CoGetObjectContext(&IID_IContextCallback, (void **)&task.context);
        ok(hr == S_OK, "context hr %#lx\n", hr);
    }
    observer = CreateThread(NULL, 0, release_gate, &task, 0, NULL);
    ok(!!observer, "observer creation failed\n");
    if (!observer) goto done;
    hr = queue_task(apartment, options, unique_context(), 0, &task.iface, &delayed);
    finished_before_return = task.writes == 1;
    SetEvent(task.returned);
    ok(hr == S_OK, "queue hr %#lx\n", hr);
    ok(!delayed, "unexpected delayed task %p\n", delayed);
    ok(finished_before_return, "queue returned before task completion, writes %ld\n", task.writes);
    ok(WaitForSingleObject(observer, 6000) == WAIT_OBJECT_0, "observer did not finish\n");
    ok(task.waited_before_return, "queue returned while the task was blocked\n");
    ok(WaitForSingleObject(task.completed, 5000) == WAIT_OBJECT_0, "task did not complete\n");
    ok(WaitForSingleObject(task.released, 5000) == WAIT_OBJECT_0, "worker did not release task\n");
    ok(task.refs == 1, "refs %ld\n", task.refs);
    ok(task.worker != task.caller, "task ran on caller\n");
    ok(task.apartment_hr == S_OK, "apartment hr %#lx\n", task.apartment_hr);
    ok(task.apartment == expected || (expected == APTTYPE_STA && task.apartment == APTTYPE_MAINSTA),
            "apartment %u, expected %lu\n", task.apartment, expected);
    if (callback)
    {
        ok(task.callback_hr == S_OK, "callback hr %#lx\n", task.callback_hr);
        ok(task.callback_thread == task.caller, "callback did not enter caller STA\n");
    }
    trace("sync-record target=%lu options=%#lx completed=%u blocked=%u apartment=%u callback=%#lx\n",
            apartment, options, finished_before_return, task.waited_before_return, task.apartment, task.callback_hr);
    CloseHandle(observer);
done:
    if (task.context) IContextCallback_Release(task.context);
    CloseHandle(task.entered);
    CloseHandle(task.allow_finish);
    CloseHandle(task.returned);
    CloseHandle(task.completed);
    CloseHandle(task.released);
    winetest_pop_context();
}

START_TEST(taskpool_sync)
{
    HMODULE module = LoadLibraryW(L"shcore.dll");
    HRESULT hr;

    queue_task = (void *)GetProcAddress(module, "SHTaskPoolQueueTask");
    unique_context = (void *)GetProcAddress(module, "SHTaskPoolGetUniqueContext");
    if (!queue_task || !unique_context)
    {
        win_skip("COM task pool unavailable\n");
        return;
    }
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ok(hr == S_OK, "STA initialization %#lx\n", hr);
    test_sync(0, 0x20, FALSE);
    test_sync(1, 0x20, FALSE);
    test_sync(0, 0x40, TRUE);
    CoUninitialize();
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(hr == S_OK, "MTA initialization %#lx\n", hr);
    test_sync(0, 0x20, FALSE);
    test_sync(1, 0x20, FALSE);
    CoUninitialize();
    FreeLibrary(module);
}
