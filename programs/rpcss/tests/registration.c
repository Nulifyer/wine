/* Shared local-class registration ownership and publisher exit.
 * Copyright 2026 Nulifyer
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 or
 * any later version.
 */
#define COBJMACROS
#include <stdio.h>
#include "windows.h"
#include "objbase.h"
#include "irpcss.h"
#include "wine/test.h"
#include "wine/exception.h"

static RPC_BINDING_HANDLE binding;
static LONG factory_refs = 1;

static HRESULT WINAPI factory_query(IClassFactory *iface, REFIID iid, void **object)
{
    *object = NULL;
    if (!IsEqualIID(iid, &IID_IUnknown) && !IsEqualIID(iid, &IID_IClassFactory)) return E_NOINTERFACE;
    *object = iface;
    IClassFactory_AddRef(iface);
    return S_OK;
}
static ULONG WINAPI factory_addref(IClassFactory *iface) { return InterlockedIncrement(&factory_refs); }
static ULONG WINAPI factory_release(IClassFactory *iface) { return InterlockedDecrement(&factory_refs); }
static HRESULT WINAPI factory_create(IClassFactory *iface, IUnknown *outer, REFIID iid, void **object)
{
    *object = NULL;
    return E_NOTIMPL;
}
static HRESULT WINAPI factory_lock(IClassFactory *iface, BOOL lock) { return S_OK; }
static const IClassFactoryVtbl factory_vtbl =
{
    factory_query, factory_addref, factory_release, factory_create, factory_lock
};
static IClassFactory factory = {&factory_vtbl};

void *__RPC_USER MIDL_user_allocate(SIZE_T size) { return malloc(size); }
void __RPC_USER MIDL_user_free(void *ptr) { free(ptr); }

static BOOL create_binding(void)
{
    RPC_STATUS status;
    RPC_WSTR string;

    status = RpcStringBindingComposeW(NULL, (RPC_WSTR)L"ncalrpc", NULL, (RPC_WSTR)L"irpcss", NULL, &string);
    ok(!status, "Compose binding returned %lu.\n", status);
    if (status) return FALSE;
    status = RpcBindingFromStringBindingW(string, &binding);
    RpcStringFreeW(&string);
    ok(!status, "Create binding returned %lu.\n", status);
    return !status;
}

static HRESULT register_class(const GUID *clsid, DWORD flags, DWORD value, unsigned int *cookie)
{
    struct { ULONG size; BYTE data[sizeof(DWORD)]; } object;

    object.size = sizeof(value);
    memcpy(object.data, &value, sizeof(value));
    return irpcss_server_register(binding, clsid, flags, (MInterfacePointer *)&object, cookie);
}

static void check_class(const GUID *clsid, HRESULT expected, DWORD expected_value)
{
    MInterfacePointer *object = NULL;
    DWORD value = 0;
    HRESULT hr = irpcss_get_class_object(binding, clsid, &object);

    ok(hr == expected, "Lookup returned %#lx, expected %#lx.\n", hr, expected);
    if (SUCCEEDED(expected))
    {
        ok(!!object, "Missing class object.\n");
        if (object)
        {
            ok(object->ulCntData == sizeof(value), "Unexpected data size %lu.\n", object->ulCntData);
            if (object->ulCntData == sizeof(value)) memcpy(&value, object->abData, sizeof(value));
            ok(value == expected_value, "Got publisher value %lu, expected %lu.\n", value, expected_value);
        }
    }
    else ok(!object, "Failure left output %p.\n", object);
    if (object) MIDL_user_free(object);
}

static BOOL start_rpcss(void)
{
    STARTUPINFOA startup = {sizeof(startup)};
    PROCESS_INFORMATION process;
    char command[] = "rpcss.exe --standalone";
    DWORD deadline = GetTickCount() + 10000, sequence;
    BOOL launched = FALSE;
    RPC_STATUS status;

    do
    {
        status = RPC_S_OK;
        RpcTryExcept { irpcss_get_thread_seq_id(binding, &sequence); }
        RpcExcept(1) { status = RpcExceptionCode(); }
        RpcEndExcept
        if (!status) return TRUE;
        if (!launched)
        {
            launched = CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process);
            ok(launched, "Start RPCSS failed: %lu.\n", GetLastError());
            if (!launched) return FALSE;
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
        }
        Sleep(50);
    } while ((LONG)(deadline - GetTickCount()) > 0);
    ok(0, "RPCSS endpoint did not become ready, last status %lu.\n", status);
    return FALSE;
}

static void run_publisher(const char *guid_string, const char *pipe_string, DWORD value)
{
    WCHAR guidW[40];
    GUID clsid;
    HANDLE pipe = (HANDLE)(ULONG_PTR)_strtoui64(pipe_string, NULL, 16);
    unsigned int cookie = 0;
    DWORD written;
    HRESULT hr;

    MultiByteToWideChar(CP_ACP, 0, guid_string, -1, guidW, ARRAY_SIZE(guidW));
    hr = CLSIDFromString(guidW, &clsid);
    ok(hr == S_OK, "Parse class returned %#lx.\n", hr);
    if (FAILED(hr) || !create_binding()) ExitProcess(2);
    hr = register_class(&clsid, REGCLS_MULTIPLEUSE, value, &cookie);
    ok(hr == S_OK, "Child registration returned %#lx.\n", hr);
    if (FAILED(hr)) ExitProcess(3);
    hr = irpcss_register_oxid(binding, ((OXID)GetCurrentProcessId() << 32) | 0xffff0002);
    ok(hr == S_OK, "Child exporter publication returned %#lx.\n", hr);
    if (FAILED(hr)) ExitProcess(4);
    ok(WriteFile(pipe, &cookie, sizeof(cookie), &written, NULL) && written == sizeof(cookie),
       "Report cookie failed: %lu.\n", GetLastError());
    CloseHandle(pipe);
    /* Exit without revoke. The parent terminates us to test owner death. */
    Sleep(INFINITE);
}

static BOOL start_publisher(const GUID *clsid, DWORD value, PROCESS_INFORMATION *process, unsigned int *cookie)
{
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), NULL, TRUE};
    STARTUPINFOA startup = {sizeof(startup)};
    WCHAR guidW[40];
    char executable[MAX_PATH], guid[40], command[3 * MAX_PATH];
    HANDLE read_pipe, write_pipe;
    DWORD read, available = 0, deadline;
    BOOL ret;

    ret = CreatePipe(&read_pipe, &write_pipe, &attributes, 0);
    ok(ret, "Create pipe failed: %lu.\n", GetLastError());
    if (!ret) return FALSE;
    SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);
    StringFromGUID2(clsid, guidW, ARRAY_SIZE(guidW));
    WideCharToMultiByte(CP_ACP, 0, guidW, -1, guid, sizeof(guid), NULL, NULL);
    GetModuleFileNameA(NULL, executable, ARRAY_SIZE(executable));
    sprintf(command, "\"%s\" registration publisher %s %I64x %lu", executable, guid, (UINT64)(ULONG_PTR)write_pipe, value);
    ret = CreateProcessA(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &startup, process);
    CloseHandle(write_pipe);
    ok(ret, "Start publisher failed: %lu.\n", GetLastError());
    if (ret)
    {
        deadline = GetTickCount() + 10000;
        do
        {
            if (!PeekNamedPipe(read_pipe, NULL, 0, NULL, &available, NULL)) break;
            if (available >= sizeof(*cookie)) break;
            if (WaitForSingleObject(process->hProcess, 0) == WAIT_OBJECT_0) break;
            Sleep(10);
        } while ((LONG)(deadline - GetTickCount()) > 0);
        ret = available >= sizeof(*cookie) && ReadFile(read_pipe, cookie, sizeof(*cookie), &read, NULL) && read == sizeof(*cookie);
        ok(ret, "Publisher did not report a cookie.\n");
        if (!ret)
        {
            TerminateProcess(process->hProcess, 4);
            WaitForSingleObject(process->hProcess, 10000);
            CloseHandle(process->hThread);
            CloseHandle(process->hProcess);
        }
    }
    CloseHandle(read_pipe);
    return ret;
}

static void stop_publisher(PROCESS_INFORMATION *process)
{
    BOOL ret = TerminateProcess(process->hProcess, 0);
    DWORD wait;

    ok(ret, "Terminate publisher failed: %lu.\n", GetLastError());
    wait = WaitForSingleObject(process->hProcess, 10000);
    ok(wait == WAIT_OBJECT_0, "Publisher exit wait returned %#lx.\n", wait);
    CloseHandle(process->hThread);
    CloseHandle(process->hProcess);
}

static void test_registration_ownership(void)
{
    PROCESS_INFORMATION first, second;
    GUID clsid;
    unsigned int own_cookie = 0, first_cookie = 0, second_cookie = 0;
    HRESULT hr;

    CoCreateGuid(&clsid);
    hr = register_class(&clsid, REGCLS_MULTIPLEUSE, 111, &own_cookie);
    ok(hr == S_OK && own_cookie, "Register returned %#lx, cookie %u.\n", hr, own_cookie);
    if (FAILED(hr)) return;
    if (start_publisher(&clsid, 222, &first, &first_cookie))
    {
        ok(first_cookie != own_cookie, "Publishers share cookie %u.\n", own_cookie);
        hr = irpcss_server_revoke(binding, first_cookie);
        ok(hr == E_ACCESSDENIED, "Foreign revoke returned %#lx.\n", hr);
        check_class(&clsid, S_OK, 111);
        hr = irpcss_server_revoke(binding, own_cookie);
        ok(hr == S_OK, "Own revoke returned %#lx.\n", hr);
        own_cookie = 0;
        check_class(&clsid, S_OK, 222);
        if (start_publisher(&clsid, 333, &second, &second_cookie))
        {
            ok(second_cookie != first_cookie, "Publishers share cookie %u.\n", first_cookie);
            stop_publisher(&first);
            check_class(&clsid, S_OK, 333);
            stop_publisher(&second);
        }
        else stop_publisher(&first);
        check_class(&clsid, E_NOINTERFACE, 0);
    }
    if (own_cookie) irpcss_server_revoke(binding, own_cookie);
    hr = register_class(&clsid, REGCLS_SINGLEUSE, 444, &own_cookie);
    ok(hr == S_OK, "Single-use register returned %#lx.\n", hr);
    if (SUCCEEDED(hr))
    {
        check_class(&clsid, S_OK, 444);
        check_class(&clsid, E_NOINTERFACE, 0);
        hr = irpcss_server_revoke(binding, own_cookie);
        ok(hr == S_OK, "Consumed cookie revoke returned %#lx.\n", hr);
    }
}

static void test_exporter_ownership(void)
{
    OXID own = ((OXID)GetCurrentProcessId() << 32) | 0xffff0001, foreign;
    ExporterContext context = NULL, missing = NULL;
    PROCESS_INFORMATION child;
    DWORD pid = 0xdeadbeef;
    BOOL silo = TRUE, alive = FALSE;
    HRESULT hr, silo_status = S_OK;
    unsigned int cookie;
    GUID clsid;

    hr = irpcss_resolve_oxid(binding, own, &missing, &pid, &silo, &silo_status);
    ok(hr == CO_E_OBJNOTCONNECTED && !missing && !pid && !silo && silo_status == CO_E_NOT_SUPPORTED,
       "Unknown exporter %#lx/%p/%lu/%u/%#lx.\n", hr, missing, pid, silo, silo_status);
    hr = irpcss_register_oxid(binding, own ^ ((OXID)4 << 32));
    ok(hr == E_ACCESSDENIED, "Spoofed publisher returned %#lx.\n", hr);
    hr = irpcss_register_oxid(binding, own);
    ok(hr == S_OK, "Publish own exporter %#lx.\n", hr);
    if (FAILED(hr)) return;
    hr = irpcss_register_oxid(binding, own);
    ok(hr == S_OK, "Repeat publication %#lx.\n", hr);
    hr = irpcss_resolve_oxid(binding, own, &context, &pid, &silo, &silo_status);
    ok(hr == S_OK && context && pid == GetCurrentProcessId(), "Own identity %#lx/%p/%lu.\n", hr, context, pid);
    hr = irpcss_revoke_oxid(binding, own);
    ok(hr == S_OK, "Revoke own exporter %#lx.\n", hr);
    if (context)
    {
        hr = irpcss_query_exporter(binding, context, &alive);
        ok(hr == S_OK && alive, "Retained revoked exporter %#lx/%u.\n", hr, alive);
        hr = irpcss_release_exporter(binding, &context);
        ok(hr == S_OK && !context, "Release own context %#lx/%p.\n", hr, context);
    }
    CoCreateGuid(&clsid);
    if (!start_publisher(&clsid, 555, &child, &cookie)) return;
    foreign = ((OXID)child.dwProcessId << 32) | 0xffff0002;
    hr = irpcss_register_oxid(binding, foreign);
    ok(hr == E_ACCESSDENIED, "Acquire foreign registration %#lx.\n", hr);
    hr = irpcss_revoke_oxid(binding, foreign);
    ok(hr == E_ACCESSDENIED, "Revoke foreign registration %#lx.\n", hr);
    hr = irpcss_resolve_oxid(binding, foreign, &context, &pid, &silo, &silo_status);
    ok(hr == S_OK && context && pid == child.dwProcessId, "Child identity %#lx/%p/%lu.\n", hr, context, pid);
    stop_publisher(&child);
    if (context)
    {
        alive = TRUE;
        hr = irpcss_query_exporter(binding, context, &alive);
        ok(hr == S_OK && !alive, "Exited exporter %#lx/%u.\n", hr, alive);
        hr = irpcss_release_exporter(binding, &context);
        ok(hr == S_OK && !context, "Release child context %#lx/%p.\n", hr, context);
    }
    hr = irpcss_resolve_oxid(binding, foreign, &missing, &pid, &silo, &silo_status);
    ok(hr == CO_E_OBJNOTCONNECTED && !missing && !pid && !silo,
       "Exited registration %#lx/%p/%lu/%u.\n", hr, missing, pid, silo);
}

static void test_failed_publication(void)
{
    SECURITY_DESCRIPTOR descriptor;
    SECURITY_DESCRIPTOR *original;
    IClassFactory *object = NULL;
    DWORD size, cookie = 0xdeadbeef;
    GUID clsid;
    ACL acl;
    HRESULT hr;
    BOOL ret;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(hr == S_OK, "Initialize COM returned %#lx.\n", hr);
    if (FAILED(hr)) return;
    size = 0;
    GetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, NULL, 0, &size);
    original = malloc(size);
    ret = !!original && GetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, original, size, &size);
    ok(ret, "Read process security failed: %lu.\n", GetLastError());
    if (ret)
    {
        InitializeAcl(&acl, sizeof(acl), ACL_REVISION);
        InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(&descriptor, TRUE, &acl, FALSE);
        ret = SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, &descriptor);
        ok(ret, "Set restrictive process security failed: %lu.\n", GetLastError());
        if (ret)
        {
            CoCreateGuid(&clsid);
            hr = CoRegisterClassObject(&clsid, (IUnknown *)&factory, CLSCTX_LOCAL_SERVER,
                                       REGCLS_MULTIPLEUSE, &cookie);
            ret = SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, original);
            ok(ret, "Restore process security failed: %lu.\n", GetLastError());
            ok(hr == E_ACCESSDENIED, "Rejected publication returned %#lx.\n", hr);
            ok(!cookie, "Failed publication returned cookie %lu.\n", cookie);
            if (SUCCEEDED(hr)) CoRevokeClassObject(cookie);
            ok(factory_refs == 1, "Failed publication retained %ld factory references.\n", factory_refs);
            hr = CoGetClassObject(&clsid, CLSCTX_INPROC_SERVER, NULL, &IID_IClassFactory, (void **)&object);
            ok(hr == REGDB_E_CLASSNOTREG && !object, "Failed class remained visible: %#lx, %p.\n", hr, object);
            if (object) IClassFactory_Release(object);
        }
    }
    free(original);
    CoUninitialize();
}

START_TEST(registration)
{
    char **argv;
    int argc = winetest_get_mainargs(&argv);

    if (strcmp(winetest_platform, "wine"))
    {
        win_skip("Wine-private class registry protocol.\n");
        return;
    }
    if (argc == 6 && !strcmp(argv[2], "publisher"))
    {
        run_publisher(argv[3], argv[4], strtoul(argv[5], NULL, 10));
        return;
    }
    if (create_binding() && start_rpcss())
    {
        test_registration_ownership();
        test_exporter_ownership();
        test_failed_publication();
        RpcBindingFree(&binding);
    }
}
