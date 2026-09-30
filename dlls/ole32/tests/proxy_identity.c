/*
 * Standard COM proxy server identity tests
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
#include "wine/test.h"

/* Private interface recovered from matching Windows 11 combase symbols. */
typedef struct IProxyServerIdentity IProxyServerIdentity;
typedef struct IProxyServerIdentityVtbl
{
    HRESULT (WINAPI *QueryInterface)(IProxyServerIdentity *, REFIID, void **);
    ULONG (WINAPI *AddRef)(IProxyServerIdentity *);
    ULONG (WINAPI *Release)(IProxyServerIdentity *);
    HRESULT (WINAPI *GetServerProcessId)(IProxyServerIdentity *, DWORD *);
    HRESULT (WINAPI *GetServerProcessHandle)(IProxyServerIdentity *, DWORD, BOOL, HANDLE *);
    HRESULT (WINAPI *IsAppSilo)(IProxyServerIdentity *, BOOL *);
} IProxyServerIdentityVtbl;
struct IProxyServerIdentity { const IProxyServerIdentityVtbl *lpVtbl; };
static const GUID IID_ProxyServerIdentity =
    {0x5524fe34, 0x8da7, 0x40a8, {0x81,0x65,0xe8,0xb3,0x7a,0x8b,0x4a,0x4b}};
static LONG object_refs = 1;

static HRESULT WINAPI factory_QueryInterface(IClassFactory *iface, REFIID iid, void **out)
{
    *out = NULL;
    if (!IsEqualIID(iid, &IID_IUnknown) && !IsEqualIID(iid, &IID_IClassFactory)) return E_NOINTERFACE;
    *out = iface;
    IClassFactory_AddRef(iface);
    return S_OK;
}
static ULONG WINAPI factory_AddRef(IClassFactory *iface) { return InterlockedIncrement(&object_refs); }
static ULONG WINAPI factory_Release(IClassFactory *iface) { return InterlockedDecrement(&object_refs); }
static HRESULT WINAPI factory_CreateInstance(IClassFactory *iface, IUnknown *outer, REFIID iid, void **out)
{
    *out = NULL;
    return CLASS_E_CLASSNOTAVAILABLE;
}
static HRESULT WINAPI factory_LockServer(IClassFactory *iface, BOOL lock) { return S_OK; }
static const IClassFactoryVtbl factory_vtbl =
    {factory_QueryInterface, factory_AddRef, factory_Release, factory_CreateInstance, factory_LockServer};
static IClassFactory factory = {&factory_vtbl};

struct server_data
{
    IStream *stream;
    const char *path;
    HANDLE ready, command, done;
    BOOL disconnected, stopped;
    HANDLE server;
};

static DWORD CALLBACK identity_server(void *arg)
{
    struct server_data *data = arg;
    HRESULT hr;
    MSG msg;
    DWORD wait, count, written;
    HANDLE file;
    STATSTG stat;
    char buffer[4096];
    unsigned int commands = 0;

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ok(hr == S_OK, "server initialization %#lx\n", hr);
    if (FAILED(hr)) { SetEvent(data->ready); return 1; }
    hr = CreateStreamOnHGlobal(NULL, TRUE, &data->stream);
    ok(hr == S_OK, "create stream %#lx\n", hr);
    if (FAILED(hr)) goto finished;
    hr = CoMarshalInterface(data->stream, &IID_IClassFactory, (IUnknown *)&factory,
                            data->path ? MSHCTX_LOCAL : MSHCTX_INPROC, NULL, MSHLFLAGS_NORMAL);
    ok(hr == S_OK, "marshal %#lx\n", hr);
    if (FAILED(hr)) goto finished;
    if (data->path)
    {
        hr = IStream_Stat(data->stream, &stat, STATFLAG_NONAME);
        ok(hr == S_OK && !stat.cbSize.HighPart && stat.cbSize.LowPart <= sizeof(buffer), "marshal size\n");
        if (FAILED(hr) || stat.cbSize.HighPart || stat.cbSize.LowPart > sizeof(buffer)) goto finished;
        IStream_Seek(data->stream, (LARGE_INTEGER){{0}}, STREAM_SEEK_SET, NULL);
        hr = IStream_Read(data->stream, buffer, stat.cbSize.LowPart, &count);
        ok(hr == S_OK && count == stat.cbSize.LowPart, "read marshal bytes %#lx/%lu\n", hr, count);
        file = CreateFileA(data->path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
        ok(file != INVALID_HANDLE_VALUE, "create marshal file %lu\n", GetLastError());
        if (file == INVALID_HANDLE_VALUE) goto finished;
        ok(WriteFile(file, buffer, count, &written, NULL) && written == count, "write marshal file\n");
        CloseHandle(file);
    }
    PeekMessageA(&msg, NULL, 0, 0, PM_NOREMOVE);
    SetEvent(data->ready);
    for (;;)
    {
        wait = MsgWaitForMultipleObjects(1, &data->command, FALSE, 30000, QS_ALLINPUT);
        if (wait == WAIT_OBJECT_0)
        {
            if (++commands == 2) break;
            hr = CoDisconnectObject((IUnknown *)&factory, 0);
            ok(hr == S_OK, "server disconnect %#lx\n", hr);
            SetEvent(data->done);
        }
        else if (wait == WAIT_OBJECT_0 + 1)
        {
            while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) DispatchMessageA(&msg);
        }
        else
        {
            ok(0, "server command wait %#lx\n", wait);
            break;
        }
    }
finished:
    SetEvent(data->ready);
    if (data->stream) IStream_Release(data->stream);
    if (data->path) data->stream = NULL;
    CoUninitialize();
    return 0;
}

static void observe_disconnected(IProxyServerIdentity *identity, unsigned int mode, const char *phase, DWORD expected_pid)
{
    HANDLE process = (HANDLE)(ULONG_PTR)0xdeadbeef;
    DWORD pid = 0xdeadbeef;
    BOOL silo = TRUE;
    HRESULT pid_hr, handle_hr, silo_hr;

    pid_hr = identity->lpVtbl->GetServerProcessId(identity, &pid);
    handle_hr = identity->lpVtbl->GetServerProcessHandle(identity, PROCESS_QUERY_LIMITED_INFORMATION, FALSE, &process);
    silo_hr = identity->lpVtbl->IsAppSilo(identity, &silo);
    trace("proxy-identity mode=%u phase=%s pid_hr=%#lx pid_zero=%u handle_hr=%#lx handle_null=%u silo_hr=%#lx silo=%u\n",
          mode, phase, pid_hr, !pid, handle_hr, !process, silo_hr, silo);
    if (!strcmp(phase, "apartment-ended"))
    {
        ok(pid_hr == CO_E_OBJNOTCONNECTED && !pid, "ended apartment PID %#lx/%lu\n", pid_hr, pid);
        ok(handle_hr == CO_E_OBJNOTCONNECTED && !process, "ended apartment handle %#lx/%p\n", handle_hr, process);
        ok(silo_hr == CO_E_OBJNOTCONNECTED && !silo, "ended apartment silo %#lx/%u\n", silo_hr, silo);
    }
    else
    {
        ok(pid_hr == S_OK && pid == expected_pid, "cached exporter PID %#lx/%lu\n", pid_hr, pid);
        if ((mode & 1) && !strcmp(phase, "server-ended"))
            ok(handle_hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE) && !process, "exited exporter handle %#lx/%p\n", handle_hr, process);
        else
            ok(handle_hr == S_OK && process && GetProcessId(process) == expected_pid, "exporter handle %#lx/%p\n", handle_hr, process);
        /* App-silo metadata is not represented by Wine tokens yet. */
        todo_wine ok(silo_hr == S_OK && !silo, "ordinary exporter silo %#lx/%u\n", silo_hr, silo);
    }
    if (SUCCEEDED(handle_hr) && process && process != (HANDLE)(ULONG_PTR)0xdeadbeef) CloseHandle(process);
}

static void check_identity(IClassFactory *proxy, DWORD expected_pid, unsigned int mode,
                           struct server_data *data)
{
    IProxyServerIdentity *identity = NULL, *again = NULL;
    IUnknown *unk = NULL, *other = NULL;
    IClassFactory *retained = NULL;
    HANDLE process;
    HRESULT hr;
    DWORD pid, flags;
    BOOL silo, inherit;

    hr = IClassFactory_QueryInterface(proxy, &IID_ProxyServerIdentity, (void **)&identity);
    trace("proxy-identity mode=%u qi=%#lx present=%u\n", mode, hr, !!identity);
    ok(hr == S_OK && identity, "proxy identity %#lx/%p\n", hr, identity);
    if (!identity) { IClassFactory_Release(proxy); return; }
    hr = identity->lpVtbl->QueryInterface(identity, &IID_ProxyServerIdentity, (void **)&again);
    ok(hr == S_OK && again == identity, "repeat identity %#lx/%p\n", hr, again);
    if (again) again->lpVtbl->Release(again);
    hr = IClassFactory_QueryInterface(proxy, &IID_IUnknown, (void **)&unk);
    ok(hr == S_OK, "proxy unknown %#lx\n", hr);
    hr = identity->lpVtbl->QueryInterface(identity, &IID_IUnknown, (void **)&other);
    ok(hr == S_OK && unk == other, "controlling unknown %#lx/%p/%p\n", hr, unk, other);
    trace("proxy-identity mode=%u shared_unknown=%u\n", mode, unk == other);
    if (unk) IUnknown_Release(unk);
    if (other) IUnknown_Release(other);
    for (inherit = FALSE; inherit <= TRUE; inherit++)
    {
        pid = 0xdeadbeef;
        SetLastError(0xdeadbeef);
        hr = identity->lpVtbl->GetServerProcessId(identity, &pid);
        trace("proxy-identity mode=%u pid_hr=%#lx pid_match=%u error=%#lx\n", mode, hr, pid == expected_pid, GetLastError());
        ok(hr == S_OK && pid == expected_pid, "PID %#lx/%lu expected %lu\n", hr, pid, expected_pid);
        ok(GetLastError() == 0xdeadbeef, "PID query last error %#lx\n", GetLastError());
        process = NULL;
        hr = identity->lpVtbl->GetServerProcessHandle(identity, PROCESS_QUERY_LIMITED_INFORMATION, inherit, &process);
        trace("proxy-identity mode=%u inherit=%u handle_hr=%#lx handle_pid_match=%u\n", mode, inherit, hr,
              process && GetProcessId(process) == expected_pid);
        ok(hr == S_OK && process, "process handle %#lx/%p\n", hr, process);
        if (process)
        {
            ok(GetProcessId(process) == expected_pid, "handle PID %lu\n", GetProcessId(process));
            ok(GetHandleInformation(process, &flags), "handle flags %lu\n", GetLastError());
            ok(!!(flags & HANDLE_FLAG_INHERIT) == inherit, "inheritance %#lx/%u\n", flags, inherit);
            CloseHandle(process);
        }
    }
    silo = TRUE;
    hr = identity->lpVtbl->IsAppSilo(identity, &silo);
    trace("proxy-identity mode=%u silo_hr=%#lx silo=%u\n", mode, hr, silo);
    todo_wine ok(hr == S_OK && !silo, "ordinary server silo %#lx/%u\n", hr, silo);
    IClassFactory_Release(proxy);
    pid = 0;
    hr = identity->lpVtbl->GetServerProcessId(identity, &pid);
    ok(hr == S_OK && pid == expected_pid, "retained identity %#lx/%lu\n", hr, pid);
    trace("proxy-identity mode=%u retained_hr=%#lx pid_match=%u\n", mode, hr, pid == expected_pid);
    SetEvent(data->command);
    data->disconnected = WaitForSingleObject(data->done, 10000) == WAIT_OBJECT_0;
    ok(data->disconnected, "disconnect completion\n");
    observe_disconnected(identity, mode, "server-disconnected", expected_pid);
    hr = identity->lpVtbl->QueryInterface(identity, &IID_IClassFactory, (void **)&retained);
    trace("proxy-identity mode=%u disconnected_factory_qi=%#lx\n", mode, hr);
    if (retained)
    {
        hr = IClassFactory_LockServer(retained, FALSE);
        trace("proxy-identity mode=%u disconnected_call=%#lx\n", mode, hr);
        IClassFactory_Release(retained);
    }
    observe_disconnected(identity, mode, "after-call", expected_pid);
    SetEvent(data->command);
    data->stopped = WaitForSingleObject(data->server, 10000) == WAIT_OBJECT_0;
    ok(data->stopped, "server stopped\n");
    observe_disconnected(identity, mode, "server-ended", expected_pid);
    CoUninitialize();
    observe_disconnected(identity, mode, "apartment-ended", expected_pid);
    identity->lpVtbl->Release(identity);
    CoInitializeEx(NULL, mode & 2 ? COINIT_APARTMENTTHREADED : COINIT_MULTITHREADED);
}

static void test_identity(unsigned int mode)
{
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    struct server_data data = {0};
    PROCESS_INFORMATION pi = {0};
    STARTUPINFOA si = {sizeof(si)};
    IClassFactory *proxy = NULL;
    IProxyServerIdentity *direct = (void *)(ULONG_PTR)0xdeadbeef;
    IStream *stream = NULL;
    HANDLE thread = NULL, file;
    DWORD expected_pid, count;
    HRESULT hr;
    char path[MAX_PATH], exe[MAX_PATH], command[2048], buffer[4096];

    hr = CoInitializeEx(NULL, mode & 2 ? COINIT_APARTMENTTHREADED : COINIT_MULTITHREADED);
    ok(hr == S_OK, "initialize %#lx\n", hr);
    hr = IClassFactory_QueryInterface(&factory, &IID_ProxyServerIdentity, (void **)&direct);
    ok(hr == E_NOINTERFACE && !direct, "ordinary object identity %#lx/%p\n", hr, direct);
    trace("proxy-identity mode=%u direct_qi=%#lx cleared=%u\n", mode, hr, !direct);
    data.ready = CreateEventA(&sa, TRUE, FALSE, NULL);
    data.command = CreateEventA(&sa, FALSE, FALSE, NULL);
    data.done = CreateEventA(&sa, FALSE, FALSE, NULL);
    ok(data.ready && data.command && data.done, "create server events\n");
    if (!(data.ready && data.command && data.done)) goto cleanup;
    if (mode & 1)
    {
        ok(GetTempFileNameA(".", "psi", 0, path), "temporary file %lu\n", GetLastError());
        GetModuleFileNameA(NULL, exe, sizeof(exe));
        snprintf(command, sizeof(command), "\"%s\" proxy_identity --identity-server \"%s\" %I64x %I64x %I64x", exe, path,
                 (ULONGLONG)(ULONG_PTR)data.ready, (ULONGLONG)(ULONG_PTR)data.command, (ULONGLONG)(ULONG_PTR)data.done);
        ok(CreateProcessA(exe, command, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi), "create server %lu\n", GetLastError());
        if (!pi.hProcess) goto cleanup;
        expected_pid = pi.dwProcessId;
    }
    else
    {
        thread = CreateThread(NULL, 0, identity_server, &data, 0, NULL);
        ok(!!thread, "create server thread %lu\n", GetLastError());
        if (!thread) goto cleanup;
        expected_pid = GetCurrentProcessId();
    }
    data.server = thread ? thread : pi.hProcess;
    if (WaitForSingleObject(data.ready, 10000) != WAIT_OBJECT_0) { ok(0, "server ready timeout\n"); goto stop; }
    if (mode & 1)
    {
        file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        ok(file != INVALID_HANDLE_VALUE, "open marshal file %lu\n", GetLastError());
        if (file == INVALID_HANDLE_VALUE) goto stop;
        count = 0;
        ok(ReadFile(file, buffer, sizeof(buffer), &count, NULL) && count, "read marshal file\n");
        CloseHandle(file);
        hr = CreateStreamOnHGlobal(NULL, TRUE, &stream);
        ok(hr == S_OK, "create client stream %#lx\n", hr);
        if (FAILED(hr)) goto stop;
        hr = IStream_Write(stream, buffer, count, NULL);
        ok(hr == S_OK, "write client stream %#lx\n", hr);
    }
    else
    {
        stream = data.stream;
        if (stream) IStream_AddRef(stream);
    }
    if (!stream) goto stop;
    IStream_Seek(stream, (LARGE_INTEGER){{0}}, STREAM_SEEK_SET, NULL);
    hr = CoUnmarshalInterface(stream, &IID_IClassFactory, (void **)&proxy);
    ok(hr == S_OK && proxy, "unmarshal %#lx/%p\n", hr, proxy);
    if (proxy) check_identity(proxy, expected_pid, mode, &data);
stop:
    if (!data.stopped && !data.disconnected && WaitForSingleObject(thread ? thread : pi.hProcess, 0) == WAIT_TIMEOUT)
    {
        SetEvent(data.command);
        data.disconnected = WaitForSingleObject(data.done, 10000) == WAIT_OBJECT_0;
        ok(data.disconnected, "server cleanup disconnect\n");
    }
    if (!data.stopped) SetEvent(data.command);
    if (thread)
    {
        ok(WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0, "join server thread\n");
        CloseHandle(thread);
    }
    if (pi.hProcess)
    {
        winetest_wait_child_process(&pi);
        DeleteFileA(path);
    }
    if (stream) IStream_Release(stream);
cleanup:
    if (data.ready) CloseHandle(data.ready);
    if (data.command) CloseHandle(data.command);
    if (data.done) CloseHandle(data.done);
    CoUninitialize();
}

START_TEST(proxy_identity)
{
    char **argv;
    int argc = winetest_get_mainargs(&argv);
    struct server_data data = {0};

    if (argc == 7 && !strcmp(argv[2], "--identity-server"))
    {
        data.path = argv[3];
        data.ready = (HANDLE)(ULONG_PTR)strtoull(argv[4], NULL, 16);
        data.command = (HANDLE)(ULONG_PTR)strtoull(argv[5], NULL, 16);
        data.done = (HANDLE)(ULONG_PTR)strtoull(argv[6], NULL, 16);
        identity_server(&data);
        CloseHandle(data.ready);
        CloseHandle(data.command);
        CloseHandle(data.done);
        return;
    }
    test_identity(0);
    test_identity(1);
    test_identity(2);
    test_identity(3);
}
