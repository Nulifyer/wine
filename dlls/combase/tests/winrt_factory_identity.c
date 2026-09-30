/*
 * Registered WinRT factory identity and local process marshaling.
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
#include "roapi.h"
#include "activation.h"
#include "winstring.h"
#include "sddl.h"
#include "wine/test.h"

struct shared
{
    HRESULT marshal_hr;
    LONG calls;
    LONG callbacks;
};
static IUnknown *ftm;
static HSTRING classids[3];
static IActivationFactory activation;
static LONG refs = 1;
static struct shared *shared;

static HRESULT WINAPI factory_QueryInterface(IPersist *iface, REFIID iid, void **out)
{
    *out = NULL;
    if (IsEqualIID(iid, &IID_IMarshal) && ftm)
        return IUnknown_QueryInterface(ftm, iid, out);
    if (IsEqualIID(iid, &IID_IActivationFactory) || IsEqualIID(iid, &IID_IInspectable))
    {
        *out = &activation;
        IPersist_AddRef(iface);
        return S_OK;
    }
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

static HRESULT WINAPI activation_QueryInterface(IActivationFactory *iface, REFIID iid, void **out)
{ return IPersist_QueryInterface(&factory, iid, out); }
static ULONG WINAPI activation_AddRef(IActivationFactory *iface) { return IPersist_AddRef(&factory); }
static ULONG WINAPI activation_Release(IActivationFactory *iface) { return IPersist_Release(&factory); }
static HRESULT WINAPI activation_GetIids(IActivationFactory *iface, ULONG *count, IID **iids)
{ *count = 0; *iids = NULL; return S_OK; }
static HRESULT WINAPI activation_GetRuntimeClassName(IActivationFactory *iface, HSTRING *name)
{ *name = NULL; return E_NOTIMPL; }
static HRESULT WINAPI activation_GetTrustLevel(IActivationFactory *iface, TrustLevel *level)
{ *level = BaseTrust; return S_OK; }
static HRESULT WINAPI activation_ActivateInstance(IActivationFactory *iface, IInspectable **object)
{ *object = NULL; return E_NOTIMPL; }
static const IActivationFactoryVtbl activation_vtbl = {activation_QueryInterface,
    activation_AddRef, activation_Release, activation_GetIids, activation_GetRuntimeClassName,
    activation_GetTrustLevel, activation_ActivateInstance};
static IActivationFactory activation = {&activation_vtbl};

static HRESULT WINAPI callback(HSTRING classid, IActivationFactory **out)
{
    INT32 order;
    InterlockedIncrement(&shared->callbacks);
    *out = NULL;
    WindowsCompareStringOrdinal(classid, classids[1], &order);
    if (!order) return E_ACCESSDENIED;
    WindowsCompareStringOrdinal(classid, classids[2], &order);
    if (!order) return S_OK; /* A broken selected callback must not select another provider. */
    *out = &activation;
    IActivationFactory_AddRef(*out);
    return S_OK;
}

static void make_classids(const char *suffix)
{
    WCHAR name[160];
    unsigned int i;
    for (i = 0; i < 3; ++i)
    {
        swprintf(name, ARRAY_SIZE(name), L"Wine.Test.FactoryIdentity.%hs.%u", suffix, i);
        ok(WindowsCreateString(name, wcslen(name), &classids[i]) == S_OK, "create class name\n");
    }
}

static void server(const char *map_name, const char *ready_name, const char *stop_name,
        const char *revoke_name, const char *revoked_name, const char *suffix, BOOL agile)
{
    HANDLE map = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, map_name);
    HANDLE ready = OpenEventA(EVENT_MODIFY_STATE, FALSE, ready_name);
    HANDLE stop = OpenEventA(SYNCHRONIZE, FALSE, stop_name);
    HANDLE revoke = OpenEventA(SYNCHRONIZE, FALSE, revoke_name);
    HANDLE revoked = OpenEventA(EVENT_MODIFY_STATE, FALSE, revoked_name);
    PFNGETACTIVATIONFACTORY callbacks[3] = {callback, callback, callback};
    RO_REGISTRATION_COOKIE cookie = NULL;
    HRESULT hr;
    unsigned int i;

    if (!map || !ready || !stop || !revoke || !revoked) ExitProcess(2);
    shared = MapViewOfFile(map, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(*shared));
    if (!shared) ExitProcess(3);
    hr = RoInitialize(RO_INIT_MULTITHREADED);
    ok(hr == S_OK, "server initialization %#lx\n", hr);
    make_classids(suffix);
    if (agile)
    {
        hr = CoCreateFreeThreadedMarshaler((IUnknown *)&factory, &ftm);
        ok(hr == S_OK, "create FTM %#lx\n", hr);
    }
    hr = RoRegisterActivationFactories(classids, callbacks, 3, &cookie);
    shared->marshal_hr = hr;
    ok(hr == S_OK && cookie, "register factories %#lx/%p\n", hr, cookie);
    SetEvent(ready);
    if (cookie)
    {
        ok(WaitForSingleObject(revoke, 20000) == WAIT_OBJECT_0, "revoke wait\n");
        RoRevokeActivationFactories(cookie);
        cookie = NULL;
        SetEvent(revoked);
    }
    ok(WaitForSingleObject(stop, 20000) == WAIT_OBJECT_0, "server stop\n");
    if (ftm) IUnknown_Release(ftm);
    RoUninitialize();
    ok(refs == 1, "server object refs %ld\n", refs);
    for (i = 0; i < 3; ++i) WindowsDeleteString(classids[i]);
    UnmapViewOfFile(shared);
    CloseHandle(map);
    CloseHandle(ready);
    CloseHandle(stop);
    CloseHandle(revoke);
    CloseHandle(revoked);
}

static void registry_classes(const WCHAR *executable, const WCHAR *server_name, BOOL remove)
{
    WCHAR path[320];
    HKEY key;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), NULL, FALSE};
    DWORD type = 1, zero = 0;
    LONG ret;
    unsigned int i;
    /* The reference actor has SeRestorePrivilege enabled. Setup creates only
     * unique synthetic keys, with explicit writable ACLs, beneath protected
     * native catalog parents; the parents and their ACLs remain unchanged. */
    if (!remove)
    {
        ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;;KA;;;BA)(A;;KA;;;SY)(A;;KR;;;BU)", SDDL_REVISION_1,
                &descriptor, NULL), "test key descriptor %lu\n", GetLastError());
        attributes.lpSecurityDescriptor = descriptor;
    }
    for (i = 0; i < 3; ++i)
    {
        swprintf(path, ARRAY_SIZE(path), L"Software\\Microsoft\\WindowsRuntime\\ActivatableClassId\\%s",
                WindowsGetStringRawBuffer(classids[i], NULL));
        if (remove) { RegDeleteTreeW(HKEY_LOCAL_MACHINE, path); continue; }
        ret = RegCreateKeyExW(HKEY_LOCAL_MACHINE, path, 0, NULL, REG_OPTION_BACKUP_RESTORE, KEY_WRITE, &attributes, &key, NULL);
        ok(ret == ERROR_SUCCESS, "create class key %ld\n", ret);
        if (ret) continue;
        ok(!RegSetValueExW(key, L"ActivationType", 0, REG_DWORD, (BYTE *)&type, sizeof(type)), "activation type\n");
        ok(!RegSetValueExW(key, L"Server", 0, REG_SZ, (BYTE *)server_name,
                (wcslen(server_name) + 1) * sizeof(WCHAR)), "server name\n");
        ok(!RegSetValueExW(key, L"TrustLevel", 0, REG_DWORD, (BYTE *)&zero, sizeof(zero)), "trust\n");
        RegCloseKey(key);
    }
    swprintf(path, ARRAY_SIZE(path), L"Software\\Microsoft\\WindowsRuntime\\Server\\%s", server_name);
    if (remove) { RegDeleteTreeW(HKEY_LOCAL_MACHINE, path); return; }
    ret = RegCreateKeyExW(HKEY_LOCAL_MACHINE, path, 0, NULL, REG_OPTION_BACKUP_RESTORE, KEY_WRITE, &attributes, &key, NULL);
    ok(ret == ERROR_SUCCESS, "create server key %ld\n", ret);
    if (ret) { LocalFree(descriptor); return; }
    ok(!RegSetValueExW(key, L"ExePath", 0, REG_SZ, (BYTE *)executable,
            (wcslen(executable) + 1) * sizeof(WCHAR)), "server path\n");
    ok(!RegSetValueExW(key, L"ServerType", 0, REG_DWORD, (BYTE *)&zero, sizeof(zero)), "server type\n");
    ok(!RegSetValueExW(key, L"IdentityType", 0, REG_DWORD, (BYTE *)&zero, sizeof(zero)), "server identity\n");
    RegCloseKey(key);
    LocalFree(descriptor);
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

static void test_registered(BOOL agile)
{
    char map_name[100], ready_name[100], stop_name[100], revoke_name[100], revoked_name[100];
    char executable[MAX_PATH], command[10 * MAX_PATH], suffix[80];
    WCHAR executable_w[MAX_PATH], server_name[160];
    HANDLE map, ready, stop, revoke, revoked, waits[2], thread;
    PROCESS_INFORMATION process = {0};
    STARTUPINFOA startup = {sizeof(startup)};
    struct worker_data data = {0};
    IPersist *proxy = NULL, *failed;
    IUnknown *identity = NULL, *activation_identity = NULL;
    IActivationFactory *activation_proxy = NULL;
    CLSID clsid;
    DWORD exit_code, wait;
    HRESULT hr;
    BOOL ret;
    LONG calls;
    unsigned int i;

    winetest_push_context("FTM %u", agile);
    sprintf(suffix, "%08lx-%u", GetCurrentProcessId(), agile);
    sprintf(map_name, "WineWinrtMap-%s", suffix);
    sprintf(ready_name, "WineWinrtReady-%s", suffix);
    sprintf(stop_name, "WineWinrtStop-%s", suffix);
    sprintf(revoke_name, "WineWinrtRevoke-%s", suffix);
    sprintf(revoked_name, "WineWinrtRevoked-%s", suffix);
    make_classids(suffix);
    GetModuleFileNameW(NULL, executable_w, ARRAY_SIZE(executable_w));
    swprintf(server_name, ARRAY_SIZE(server_name), L"Wine.Test.FactoryServer.%hs", suffix);
    registry_classes(executable_w, server_name, FALSE);
    map = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(*shared), map_name);
    ready = CreateEventA(NULL, TRUE, FALSE, ready_name);
    stop = CreateEventA(NULL, TRUE, FALSE, stop_name);
    revoke = CreateEventA(NULL, TRUE, FALSE, revoke_name);
    revoked = CreateEventA(NULL, TRUE, FALSE, revoked_name);
    ok(!!map && !!ready && !!stop && !!revoke && !!revoked, "create IPC %lu\n", GetLastError());
    if (!map || !ready || !stop || !revoke || !revoked) goto done;
    shared = MapViewOfFile(map, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(*shared));
    ok(!!shared, "map IPC %lu\n", GetLastError());
    if (!shared) goto done;
    GetModuleFileNameA(NULL, executable, sizeof(executable));
    sprintf(command, "\"%s\" winrt_factory_identity child %s %s %s %s %s %s %u",
            executable, map_name, ready_name, stop_name, revoke_name, revoked_name, suffix, agile);
    ret = CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process);
    ok(ret, "create server %lu\n", GetLastError());
    if (!ret) goto done;
    waits[0] = ready;
    waits[1] = process.hProcess;
    wait = WaitForMultipleObjects(2, waits, FALSE, 15000);
    ok(wait == WAIT_OBJECT_0, "server ready %lu\n", wait);
    if (wait != WAIT_OBJECT_0) goto done;
    ok(shared->marshal_hr == S_OK, "registration result %#lx\n", shared->marshal_hr);
    if (FAILED(shared->marshal_hr)) goto done;
    hr = RoGetActivationFactory(classids[0], &IID_IPersist, (void **)&proxy);
    ok(hr == S_OK && proxy, "factory IPersist %#lx/%p\n", hr, proxy);
    if (FAILED(hr) || !proxy) goto done;
    hr = IPersist_QueryInterface(proxy, &IID_IUnknown, (void **)&identity);
    ok(hr == S_OK && identity, "factory identity %#lx\n", hr);
    hr = RoGetActivationFactory(classids[0], &IID_IActivationFactory, (void **)&activation_proxy);
    ok(hr == S_OK && activation_proxy, "activation factory %#lx\n", hr);
    if (activation_proxy)
    {
        hr = IActivationFactory_QueryInterface(activation_proxy, &IID_IUnknown, (void **)&activation_identity);
        ok(hr == S_OK && identity == activation_identity, "shared controlling identity %#lx/%p/%p\n",
                hr, identity, activation_identity);
    }
    hr = IPersist_GetClassID(proxy, &clsid);
    ok(hr == S_OK && IsEqualGUID(&clsid, &IID_IPersist), "STA method %#lx\n", hr);
    data.proxy = proxy;
    thread = CreateThread(NULL, 0, worker, &data, 0, NULL);
    ok(!!thread, "create MTA worker\n");
    if (thread)
    {
        wait = WaitForSingleObject(thread, 15000);
        ok(wait == WAIT_OBJECT_0, "worker wait %lu\n", wait);
        if (wait != WAIT_OBJECT_0) ExitProcess(4);
        CloseHandle(thread);
        ok(data.hr == (agile ? S_OK : RPC_E_WRONG_THREAD), "MTA factory method %#lx\n", data.hr);
        ok(shared->calls == (agile ? 2 : 1), "factory execution count %ld\n", shared->calls);
        trace("winrt-record agile=%u sta=%#lx mta=%#lx calls=%ld identity=%u\n", agile,
                hr, data.hr, shared->calls, identity == activation_identity);
    }
    failed = (void *)0xdeadbeef;
    hr = RoGetActivationFactory(classids[0], &IID_IStream, (void **)&failed);
    ok(hr == E_NOINTERFACE && !failed, "unsupported factory IID %#lx/%p\n", hr, failed);
    trace("winrt-iid agile=%u hr=%#lx output_null=%u\n", agile, hr, !failed);
    calls = shared->calls;
    failed = (void *)0xdeadbeef;
    hr = RoGetActivationFactory(classids[1], &IID_IPersist, (void **)&failed);
    ok(hr == E_ACCESSDENIED && !failed, "selected callback failure %#lx/%p\n", hr, failed);
    trace("winrt-failure agile=%u denied=%#lx output_null=%u\n", agile, hr, !failed);
    failed = (void *)0xdeadbeef;
    hr = RoGetActivationFactory(classids[2], &IID_IPersist, (void **)&failed);
    ok(hr == RPC_E_SERVERFAULT && !failed, "empty callback result %#lx/%p\n", hr, failed);
    trace("winrt-empty agile=%u hr=%#lx output_null=%u\n", agile, hr, !failed);
    SetEvent(revoke);
    ok(WaitForSingleObject(revoked, 15000) == WAIT_OBJECT_0, "registration revoked\n");
    hr = IPersist_GetClassID(proxy, &clsid);
    ok(hr == S_OK && shared->calls == calls + 1, "existing factory after revoke %#lx/%ld\n", hr, shared->calls);
    trace("winrt-revoke agile=%u existing=%#lx calls=%ld\n", agile, hr, shared->calls);

done:
    if (activation_identity) IUnknown_Release(activation_identity);
    if (identity) IUnknown_Release(identity);
    if (activation_proxy) IActivationFactory_Release(activation_proxy);
    if (proxy) IPersist_Release(proxy);
    if (process.hProcess)
    {
        SetEvent(revoke);
        SetEvent(stop);
        wait = WaitForSingleObject(process.hProcess, 15000);
        ok(wait == WAIT_OBJECT_0, "server did not stop\n");
        if (wait != WAIT_OBJECT_0) ExitProcess(4);
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
    if (revoke) CloseHandle(revoke);
    if (revoked) CloseHandle(revoked);
    registry_classes(executable_w, server_name, TRUE);
    for (i = 0; i < 3; ++i) WindowsDeleteString(classids[i]);
    winetest_pop_context();
}

START_TEST(winrt_factory_identity)
{
    char **argv;
    int argc = winetest_get_mainargs(&argv);
    HRESULT hr;
    if (argc == 10 && !strcmp(argv[2], "child"))
    {
        server(argv[3], argv[4], argv[5], argv[6], argv[7], argv[8], atoi(argv[9]));
        return;
    }
    hr = RoInitialize(RO_INIT_SINGLETHREADED);
    ok(hr == S_OK, "client initialization %#lx\n", hr);
    test_registered(FALSE);
    test_registered(TRUE);
    RoUninitialize();
}
