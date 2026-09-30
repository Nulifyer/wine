/*
 * Local process proxies for ordinary and free-threaded objects.
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */
#define COBJMACROS
#define CONST_VTABLE
#include <stdio.h>
#include <stdlib.h>
#include "objbase.h"
#include "wine/orpc.h"
#include "wine/test.h"

struct shared
{
    HRESULT marshal_hr;
    DWORD size;
    LONG calls;
    DWORD reserved;
    BYTE bytes[2048];
};
static IUnknown *ftm;
static LONG refs = 1;
static struct shared *shared;

static HRESULT WINAPI factory_QueryInterface(IPersist *iface, REFIID iid, void **out)
{
    *out = NULL;
    if (IsEqualIID(iid, &IID_IMarshal) && ftm)
        return IUnknown_QueryInterface(ftm, iid, out);
    if (!IsEqualIID(iid, &IID_IUnknown) && !IsEqualIID(iid, &IID_IPersist))
        return E_NOINTERFACE;
    *out = iface;
    IPersist_AddRef(iface);
    return S_OK;
}
static ULONG WINAPI factory_AddRef(IPersist *iface) { return InterlockedIncrement(&refs); }
static ULONG WINAPI factory_Release(IPersist *iface) { return InterlockedDecrement(&refs); }
static HRESULT WINAPI factory_GetClassID(IPersist *iface, CLSID *clsid)
{
    *clsid = IID_IPersist;
    InterlockedIncrement(&shared->calls);
    return S_OK;
}
static const IPersistVtbl factory_vtbl =
    {factory_QueryInterface, factory_AddRef, factory_Release, factory_GetClassID};
static IPersist factory = {&factory_vtbl};

static void server(const char *map_name, const char *ready_name, const char *stop_name, BOOL agile)
{
    HANDLE map = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, map_name);
    HANDLE ready = OpenEventA(EVENT_MODIFY_STATE, FALSE, ready_name);
    HANDLE stop = OpenEventA(SYNCHRONIZE, FALSE, stop_name);
    IStream *stream = NULL;
    STATSTG stat;
    ULONG count;
    MSG msg;
    HRESULT hr;
    DWORD wait;
    CO_MTA_USAGE_COOKIE cookie = NULL;

    if (!map || !ready || !stop) ExitProcess(2);
    shared = MapViewOfFile(map, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(*shared));
    if (!shared) ExitProcess(3);
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ok(hr == S_OK, "server initialization %#lx\n", hr);
    if (agile)
    {
        hr = CoIncrementMTAUsage(&cookie);
        ok(hr == S_OK, "keep server MTA %#lx\n", hr);
        hr = CoCreateFreeThreadedMarshaler((IUnknown *)&factory, &ftm);
        ok(hr == S_OK, "create FTM %#lx\n", hr);
    }
    hr = CreateStreamOnHGlobal(NULL, TRUE, &stream);
    ok(hr == S_OK, "create stream %#lx\n", hr);
    if (SUCCEEDED(hr)) hr = CoMarshalInterface(stream, &IID_IPersist, (IUnknown *)&factory,
            MSHCTX_LOCAL, NULL, MSHLFLAGS_TABLESTRONG);
    shared->marshal_hr = hr;
    ok(hr == S_OK, "marshal %#lx\n", hr);
    if (SUCCEEDED(hr))
    {
        hr = IStream_Stat(stream, &stat, STATFLAG_NONAME);
        ok(hr == S_OK && !stat.cbSize.HighPart && stat.cbSize.LowPart <= sizeof(shared->bytes),
                "marshal size %#lx/%lu\n", hr, stat.cbSize.LowPart);
        if (SUCCEEDED(hr) && !stat.cbSize.HighPart && stat.cbSize.LowPart <= sizeof(shared->bytes))
        {
            shared->size = stat.cbSize.LowPart;
            IStream_Seek(stream, (LARGE_INTEGER){{0}}, STREAM_SEEK_SET, NULL);
            hr = IStream_Read(stream, shared->bytes, shared->size, &count);
            ok(hr == S_OK && count == shared->size, "read marshal bytes %#lx/%lu\n", hr, count);
        }
    }
    PeekMessageA(&msg, NULL, 0, 0, PM_NOREMOVE);
    if (agile) CoUninitialize(); /* The FTM export must survive its originating STA. */
    SetEvent(ready);
    for (;;)
    {
        wait = MsgWaitForMultipleObjects(1, &stop, FALSE, 30000, QS_ALLINPUT);
        if (wait == WAIT_OBJECT_0 || wait != WAIT_OBJECT_0 + 1) break;
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) DispatchMessageA(&msg);
    }
    ok(wait == WAIT_OBJECT_0, "server stop wait %lu\n", wait);
    if (stream)
    {
        IStream_Seek(stream, (LARGE_INTEGER){{0}}, STREAM_SEEK_SET, NULL);
        if (SUCCEEDED(shared->marshal_hr))
        {
            hr = CoReleaseMarshalData(stream);
            ok(hr == S_OK, "release marshal data %#lx\n", hr);
        }
        IStream_Release(stream);
    }
    if (ftm) IUnknown_Release(ftm);
    if (cookie) CoDecrementMTAUsage(cookie);
    if (!agile) CoUninitialize();
    ok(refs == 1, "server object refs %ld\n", refs);
    UnmapViewOfFile(shared);
    CloseHandle(map);
    CloseHandle(ready);
    CloseHandle(stop);
}

struct worker_data { IPersist *proxy; HRESULT hr; };
static DWORD WINAPI worker(void *arg)
{
    struct worker_data *data = arg;
    CLSID clsid;
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(hr == S_OK, "worker initialization %#lx\n", hr);
    data->hr = IPersist_GetClassID(data->proxy, &clsid);
    if (SUCCEEDED(data->hr)) ok(IsEqualGUID(&clsid, &IID_IPersist), "worker class id\n");
    CoUninitialize();
    return 0;
}

static void test_local(BOOL agile)
{
    char map_name[100], ready_name[100], stop_name[100], executable[MAX_PATH], command[5 * MAX_PATH];
    HANDLE map, ready, stop, waits[2], thread;
    PROCESS_INFORMATION process = {0};
    STARTUPINFOA startup = {sizeof(startup)};
    struct worker_data data = {0};
    IStream *stream = NULL;
    IPersist *proxy = NULL;
    IUnknown *identity = NULL;
    OBJREF *objref;
    CLSID clsid;
    ULONG written;
    DWORD exit_code, wait;
    HRESULT hr;
    BOOL ret;

    winetest_push_context("FTM %u", agile);
    sprintf(map_name, "WineFtmMap-%08lx-%u", GetCurrentProcessId(), agile);
    sprintf(ready_name, "WineFtmReady-%08lx-%u", GetCurrentProcessId(), agile);
    sprintf(stop_name, "WineFtmStop-%08lx-%u", GetCurrentProcessId(), agile);
    map = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(*shared), map_name);
    ready = CreateEventA(NULL, TRUE, FALSE, ready_name);
    stop = CreateEventA(NULL, TRUE, FALSE, stop_name);
    ok(!!map && !!ready && !!stop, "create IPC objects %lu\n", GetLastError());
    if (!map || !ready || !stop) goto done;
    shared = MapViewOfFile(map, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(*shared));
    ok(!!shared, "map IPC %lu\n", GetLastError());
    if (!shared) goto done;
    GetModuleFileNameA(NULL, executable, sizeof(executable));
    sprintf(command, "\"%s\" ftm_local child %s %s %s %u", executable, map_name, ready_name, stop_name, agile);
    ret = CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process);
    ok(ret, "create server %lu\n", GetLastError());
    if (!ret) goto done;
    waits[0] = ready;
    waits[1] = process.hProcess;
    wait = WaitForMultipleObjects(2, waits, FALSE, 15000);
    ok(wait == WAIT_OBJECT_0, "server ready wait %lu\n", wait);
    if (wait != WAIT_OBJECT_0) goto done;
    ok(shared->marshal_hr == S_OK, "marshal result %#lx\n", shared->marshal_hr);
    ok(shared->size >= FIELD_OFFSET(OBJREF, u_objref.u_standard.saResAddr), "short OBJREF %lu\n", shared->size);
    if (FAILED(shared->marshal_hr) || shared->size < FIELD_OFFSET(OBJREF, u_objref.u_standard.saResAddr)) goto done;
    objref = (OBJREF *)shared->bytes;
    ok(objref->signature == OBJREF_SIGNATURE && objref->flags == OBJREF_STANDARD,
            "OBJREF signature/flags %#lx/%#lx\n", objref->signature, objref->flags);
    ok(!!(objref->u_objref.u_standard.std.flags & 0x200) == agile,
            "free-threaded STDOBJREF flags %#lx\n", objref->u_objref.u_standard.std.flags);
    hr = CreateStreamOnHGlobal(NULL, TRUE, &stream);
    ok(hr == S_OK, "client stream %#lx\n", hr);
    if (FAILED(hr)) goto done;
    hr = IStream_Write(stream, shared->bytes, shared->size, &written);
    ok(hr == S_OK && written == shared->size, "write stream %#lx/%lu\n", hr, written);
    IStream_Seek(stream, (LARGE_INTEGER){{0}}, STREAM_SEEK_SET, NULL);
    hr = CoUnmarshalInterface(stream, &IID_IPersist, (void **)&proxy);
    ok(hr == S_OK, "unmarshal %#lx\n", hr);
    if (FAILED(hr)) goto done;
    hr = IPersist_QueryInterface(proxy, &IID_IUnknown, (void **)&identity);
    ok(hr == S_OK && !!identity, "identity %#lx/%p\n", hr, identity);
    hr = IPersist_GetClassID(proxy, &clsid);
    ok(hr == S_OK, "STA method %#lx\n", hr);
    ok(IsEqualGUID(&clsid, &IID_IPersist), "STA class id\n");
    data.proxy = proxy;
    thread = CreateThread(NULL, 0, worker, &data, 0, NULL);
    ok(!!thread, "worker creation %lu\n", GetLastError());
    if (thread)
    {
        wait = WaitForSingleObject(thread, 15000);
        ok(wait == WAIT_OBJECT_0, "worker wait %lu\n", wait);
        if (wait != WAIT_OBJECT_0) ExitProcess(4); /* No stack/object cleanup while still in use. */
        CloseHandle(thread);
        ok(data.hr == (agile ? S_OK : RPC_E_WRONG_THREAD), "MTA method %#lx\n", data.hr);
        ok(shared->calls == (agile ? 2 : 1), "server calls %ld\n", shared->calls);
        trace("ftm-record agile=%u wire_agile=%u sta=%#lx mta=%#lx calls=%ld\n", agile,
                !!(objref->u_objref.u_standard.std.flags & 0x200), hr, data.hr, shared->calls);
        CoUninitialize();
        thread = CreateThread(NULL, 0, worker, &data, 0, NULL);
        ok(!!thread, "teardown worker creation %lu\n", GetLastError());
        if (thread)
        {
            wait = WaitForSingleObject(thread, 15000);
            ok(wait == WAIT_OBJECT_0, "teardown worker wait %lu\n", wait);
            if (wait != WAIT_OBJECT_0) ExitProcess(4);
            CloseHandle(thread);
            ok(data.hr == (agile ? S_OK : CO_E_OBJNOTCONNECTED), "method after client STA teardown %#lx\n", data.hr);
            ok(shared->calls == (agile ? 3 : 1), "calls after teardown %ld\n", shared->calls);
            trace("ftm-teardown agile=%u hr=%#lx calls=%ld\n", agile, data.hr, shared->calls);
        }
        hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        ok(hr == S_OK, "reinitialize caller %#lx\n", hr);
    }
done:
    if (identity) IUnknown_Release(identity);
    if (proxy) IPersist_Release(proxy);
    if (stream) IStream_Release(stream);
    if (process.hProcess)
    {
        SetEvent(stop);
        ok(WaitForSingleObject(process.hProcess, 15000) == WAIT_OBJECT_0, "server did not stop\n");
        GetExitCodeProcess(process.hProcess, &exit_code);
        ok(!exit_code, "server exit %lu\n", exit_code);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    if (shared) UnmapViewOfFile(shared);
    shared = NULL;
    if (map) CloseHandle(map);
    if (ready) CloseHandle(ready);
    if (stop) CloseHandle(stop);
    winetest_pop_context();
}

START_TEST(ftm_local)
{
    char **argv;
    int argc = winetest_get_mainargs(&argv);
    HRESULT hr;
    CO_MTA_USAGE_COOKIE cookie = NULL;
    if (argc == 7 && !strcmp(argv[2], "child"))
    {
        server(argv[3], argv[4], argv[5], atoi(argv[6]));
        return;
    }
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ok(hr == S_OK, "client initialization %#lx\n", hr);
    hr = CoIncrementMTAUsage(&cookie);
    ok(hr == S_OK, "keep client MTA %#lx\n", hr);
    test_local(FALSE);
    test_local(TRUE);
    CoUninitialize();
    if (cookie) CoDecrementMTAUsage(cookie);
}
