/* Delayed local-server activation
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */
#define COBJMACROS
#include <stdio.h>
#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "objbase.h"
#include "wine/test.h"

static HRESULT WINAPI factory_query(IClassFactory *iface, REFIID iid, void **out)
{
    *out = NULL;
    if (!IsEqualGUID(iid, &IID_IUnknown) && !IsEqualGUID(iid, &IID_IClassFactory)) return E_NOINTERFACE;
    *out = iface;
    IClassFactory_AddRef(iface);
    return S_OK;
}
static ULONG WINAPI factory_addref(IClassFactory *iface) { return 2; }
static ULONG WINAPI factory_release(IClassFactory *iface) { return 1; }
static HRESULT WINAPI factory_create(IClassFactory *iface, IUnknown *outer, REFIID iid, void **out)
{
    *out = NULL;
    return E_NOTIMPL;
}
static HRESULT WINAPI factory_lock(IClassFactory *iface, BOOL lock) { return S_OK; }
static const IClassFactoryVtbl factory_vtbl =
{
    factory_query, factory_addref, factory_release, factory_create, factory_lock
};
static IClassFactory factory = {&factory_vtbl};

static void run_server(const char *guid_string, const char *quit_name)
{
    WCHAR guidW[40];
    GUID clsid;
    DWORD cookie;
    HANDLE quit = OpenEventA(SYNCHRONIZE, FALSE, quit_name);
    HRESULT hr;

    if (!quit) ExitProcess(2);
    MultiByteToWideChar(CP_ACP, 0, guid_string, -1, guidW, ARRAY_SIZE(guidW));
    CLSIDFromString(guidW, &clsid);
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) ExitProcess(3);
    Sleep(3000);
    hr = CoRegisterClassObject(&clsid, (IUnknown *)&factory, CLSCTX_LOCAL_SERVER, REGCLS_MULTIPLEUSE, &cookie);
    if (FAILED(hr)) ExitProcess(4);
    WaitForSingleObject(quit, 15000);
    CoRevokeClassObject(cookie);
    CoUninitialize();
    CloseHandle(quit);
}

static ULONGLONG thread_cpu_time(void)
{
    FILETIME created, exited, kernel, user;
    BOOL ret = GetThreadTimes(GetCurrentThread(), &created, &exited, &kernel, &user);
    ok(ret, "GetThreadTimes failed: %lu.\n", GetLastError());
    if (!ret) return 0;
    return ((ULONGLONG)kernel.dwHighDateTime << 32) + kernel.dwLowDateTime +
           ((ULONGLONG)user.dwHighDateTime << 32) + user.dwLowDateTime;
}

static void test_delayed_activation(DWORD apartment)
{
    WCHAR guidW[40];
    char guid_string[40], key_name[96], command[3 * MAX_PATH], executable[MAX_PATH], quit_name[80];
    IClassFactory *remote = NULL;
    HKEY key, server;
    GUID clsid;
    HANDLE quit;
    DWORD disposition, start, elapsed;
    ULONGLONG cpu;
    HRESULT hr;
    LONG ret;

    CoCreateGuid(&clsid);
    StringFromGUID2(&clsid, guidW, ARRAY_SIZE(guidW));
    WideCharToMultiByte(CP_ACP, 0, guidW, -1, guid_string, sizeof(guid_string), NULL, NULL);
    sprintf(key_name, "CLSID\\%s", guid_string);
    ret = RegCreateKeyExA(HKEY_CLASSES_ROOT, key_name, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, &disposition);
    if (ret == ERROR_ACCESS_DENIED) { win_skip("Need class registry write access.\n"); return; }
    ok(!ret, "Could not create class key: %ld.\n", ret);
    if (ret) return;
    if (disposition != REG_CREATED_NEW_KEY) { RegCloseKey(key); return; }
    sprintf(quit_name, "Wine activation wait %s", guid_string);
    quit = CreateEventA(NULL, TRUE, FALSE, quit_name);
    ok(!!quit, "CreateEvent failed: %lu.\n", GetLastError());
    GetModuleFileNameA(NULL, executable, ARRAY_SIZE(executable));
    sprintf(command, "\"%s\" activation_wait server %s \"%s\"", executable, guid_string, quit_name);
    ret = RegCreateKeyExA(key, "LocalServer32", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &server, NULL);
    ok(!ret, "Could not create local server key: %ld.\n", ret);
    if (!ret)
    {
        ret = RegSetValueExA(server, NULL, 0, REG_SZ, (const BYTE *)command, strlen(command) + 1);
        ok(!ret, "Could not set server command: %ld.\n", ret);
        RegCloseKey(server);
        hr = CoInitializeEx(NULL, apartment);
        ok(hr == S_OK, "CoInitializeEx returned %#lx.\n", hr);
        cpu = thread_cpu_time();
        start = GetTickCount();
        hr = CoGetClassObject(&clsid, CLSCTX_LOCAL_SERVER, NULL, &IID_IClassFactory, (void **)&remote);
        elapsed = GetTickCount() - start;
        cpu = thread_cpu_time() - cpu;
        ok(hr == S_OK, "CoGetClassObject returned %#lx.\n", hr);
        trace("apartment %lu: wall %lu ms, client CPU %s (100 ns units).\n",
              apartment, elapsed, wine_dbgstr_longlong(cpu));
        if (remote)
        {
            hr = IClassFactory_LockServer(remote, FALSE);
            todo_wine ok(hr == S_OK, "Factory call returned %#lx.\n", hr);
            IClassFactory_Release(remote);
            ok(cpu < 10000000, "Activation spun for %s (100 ns units).\n", wine_dbgstr_longlong(cpu));
        }
        CoUninitialize();
    }
    SetEvent(quit);
    CloseHandle(quit);
    RegDeleteTreeA(key, NULL);
    RegCloseKey(key);
    RegDeleteKeyA(HKEY_CLASSES_ROOT, key_name);
}

START_TEST(activation_wait)
{
    char **argv;
    int argc = winetest_get_mainargs(&argv);
    if (argc >= 5 && !strcmp(argv[2], "server")) { run_server(argv[3], argv[4]); return; }
    test_delayed_activation(COINIT_MULTITHREADED);
    test_delayed_activation(COINIT_APARTMENTTHREADED);
}
