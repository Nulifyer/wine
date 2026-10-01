/*
 * Copyright (c) 2018 Alistair Leslie-Hughes
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#define COBJMACROS
#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "winstring.h"
#include "winternl.h"
#include "ctxtcall.h"

#include "initguid.h"
#include "roapi.h"
#include "roerrorapi.h"

#include "wine/test.h"

#define EXPECT_REF(obj,ref) _expect_ref((IUnknown*)obj, ref, __LINE__)

typedef HRESULT (WINAPI *ro_initialize_strict_fn)(INT type);
typedef HRESULT (WINAPI *get_shared_service_id_fn)(DWORD *id);
typedef LONG (WINAPI *shared_service_reference_fn)(DWORD id);
typedef HRESULT (WINAPI *dll_get_activation_factory_fn)(HSTRING classid, IActivationFactory **factory);

struct extension_catalog;
struct extension_iterator;

struct extension_catalog_vtbl
{
    HRESULT (WINAPI *QueryInterface)(struct extension_catalog *, REFIID, void **);
    ULONG (WINAPI *AddRef)(struct extension_catalog *);
    ULONG (WINAPI *Release)(struct extension_catalog *);
    HRESULT (WINAPI *GetIids)(struct extension_catalog *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(struct extension_catalog *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(struct extension_catalog *, TrustLevel *);
    HRESULT (WINAPI *QueryCatalog)(struct extension_catalog *, HSTRING, struct extension_iterator **);
    HRESULT (WINAPI *QueryCatalogByPackageFamilyName)(struct extension_catalog *, HSTRING, HSTRING,
                                                       struct extension_iterator **);
};

struct extension_catalog
{
    const struct extension_catalog_vtbl *lpVtbl;
};

struct extension_iterator_vtbl
{
    HRESULT (WINAPI *QueryInterface)(struct extension_iterator *, REFIID, void **);
    ULONG (WINAPI *AddRef)(struct extension_iterator *);
    ULONG (WINAPI *Release)(struct extension_iterator *);
    HRESULT (WINAPI *GetIids)(struct extension_iterator *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(struct extension_iterator *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(struct extension_iterator *, TrustLevel *);
    HRESULT (WINAPI *get_Current)(struct extension_iterator *, IInspectable **);
    HRESULT (WINAPI *get_HasCurrent)(struct extension_iterator *, boolean *);
    HRESULT (WINAPI *MoveNext)(struct extension_iterator *, boolean *);
    HRESULT (WINAPI *GetMany)(struct extension_iterator *, UINT32, IInspectable **, UINT32 *);
};

struct extension_iterator
{
    const struct extension_iterator_vtbl *lpVtbl;
};

static const IID IID_IExtensionCatalog =
    {0x07cee0d8, 0xd555, 0x4d61, {0x9c, 0x37, 0x01, 0xc1, 0x94, 0xb0, 0xf2, 0x08}};

static const CLSID context_switcher_clsid =
    {0x0000034e, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

struct context_switcher_callback_state
{
    ULONG_PTR token;
    HRESULT token_hr;
    unsigned int calls;
};

static HRESULT WINAPI context_switcher_callback(ComCallData *data)
{
    struct context_switcher_callback_state *state = data->pUserDefined;

    ++state->calls;
    state->token_hr = CoGetContextToken(&state->token);
    return S_FALSE;
}

static void test_context_switcher(void)
{
    struct context_switcher_callback_state first_state = {0}, second_state = {0};
    ComCallData first_data = {0, 0, &first_state}, second_data = {0, 0, &second_state};
    IContextCallback *first = NULL, *second = NULL;
    IComThreadingInfo *threading_info = (void *)0xdeadbeef;
    ULONG_PTR original_token, after_token;
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(hr == S_OK, "CoInitializeEx returned %#lx.\n", hr);

    hr = CoGetContextToken(&original_token);
    ok(hr == S_OK, "CoGetContextToken returned %#lx.\n", hr);

    hr = CoCreateInstance(&context_switcher_clsid, NULL, CLSCTX_INPROC_SERVER,
            &IID_IContextCallback, (void **)&first);
    ok(hr == S_OK, "first CoCreateInstance returned %#lx.\n", hr);
    ok(!!first, "first context switcher is NULL.\n");

    hr = CoCreateInstance(&context_switcher_clsid, NULL, CLSCTX_INPROC_SERVER,
            &IID_IContextCallback, (void **)&second);
    ok(hr == S_OK, "second CoCreateInstance returned %#lx.\n", hr);
    ok(!!second, "second context switcher is NULL.\n");
    ok(first != second, "separate activations returned the same object.\n");

    hr = IContextCallback_QueryInterface(first, &IID_IComThreadingInfo, (void **)&threading_info);
    ok(hr == E_NOINTERFACE, "IComThreadingInfo query returned %#lx.\n", hr);
    ok(!threading_info, "IComThreadingInfo query returned %p.\n", threading_info);

    hr = IContextCallback_ContextCallback(first, context_switcher_callback, &first_data,
            &IID_IContextCallback, 5, NULL);
    ok(hr == S_FALSE, "first ContextCallback returned %#lx.\n", hr);
    ok(first_state.calls == 1, "callback ran %u times.\n", first_state.calls);
    ok(first_state.token_hr == S_OK, "callback CoGetContextToken returned %#lx.\n", first_state.token_hr);
    ok(first_state.token != original_token, "callback did not enter a distinct context.\n");

    hr = CoGetContextToken(&after_token);
    ok(hr == S_OK, "post-callback CoGetContextToken returned %#lx.\n", hr);
    ok(after_token == original_token, "callback did not restore the original context.\n");

    first_state.calls = 0;
    after_token = first_state.token;
    hr = IContextCallback_ContextCallback(first, context_switcher_callback, &first_data,
            &IID_IContextCallback, 5, NULL);
    ok(hr == S_FALSE, "repeat ContextCallback returned %#lx.\n", hr);
    ok(first_state.token == after_token, "repeat callback entered a different context.\n");

    hr = IContextCallback_ContextCallback(second, context_switcher_callback, &second_data,
            &IID_IContextCallback, 5, NULL);
    ok(hr == S_FALSE, "second ContextCallback returned %#lx.\n", hr);
    ok(second_state.token != original_token, "second callback did not enter a distinct context.\n");
    ok(second_state.token != first_state.token, "separate context switchers shared a context.\n");

    hr = IContextCallback_ContextCallback(first, NULL, &first_data, &IID_IContextCallback, 5, NULL);
    ok(hr == E_INVALIDARG, "NULL callback returned %#lx.\n", hr);

    if (second) IContextCallback_Release(second);
    if (first) IContextCallback_Release(first);
    CoUninitialize();
}

static void test_shared_service_ordinals(void)
{
    shared_service_reference_fn add_ref, release;
    get_shared_service_id_fn get_id;
    HMODULE module;
    DWORD first = 0xcccccccc, second = 0xdddddddd;
    HRESULT hr;

    module = GetModuleHandleW(L"combase.dll");
    get_id = (void *)GetProcAddress(module, MAKEINTRESOURCEA(66));
    add_ref = (void *)GetProcAddress(module, MAKEINTRESOURCEA(67));
    release = (void *)GetProcAddress(module, MAKEINTRESOURCEA(68));
    if (!get_id || !add_ref || !release)
    {
        win_skip("shared-service ordinals are unavailable.\n");
        return;
    }

    hr = get_id(NULL);
    ok(hr == E_INVALIDARG, "null output returned %#lx.\n", hr);
    hr = get_id(&first);
    ok(hr == S_OK, "first call returned %#lx.\n", hr);
    ok(first == (DWORD)(ULONG_PTR)NtCurrentTeb()->SubProcessTag,
            "got id %#lx, expected current service tag %p.\n", first, NtCurrentTeb()->SubProcessTag);
    hr = get_id(&second);
    ok(hr == S_OK, "second call returned %#lx.\n", hr);
    ok(second == first, "second id %#lx differs from first %#lx.\n", second, first);

    ok(add_ref(first) == 1, "first add-ref returned an unexpected count.\n");
    ok(add_ref(first) == 2, "second add-ref returned an unexpected count.\n");
    ok(release(first) == 1, "first release returned an unexpected count.\n");
    ok(release(first) == 0, "second release returned an unexpected count.\n");
    ok(add_ref(0x12345678) == -1, "missing-id add-ref did not return -1.\n");
    ok(release(0x12345678) == -1, "missing-id release did not return -1.\n");
}

struct ro_initialize_strict_result
{
    ro_initialize_strict_fn initialize;
    INT input;
    HRESULT first_hr;
    HRESULT query_hr;
    HRESULT second_hr;
    APTTYPE type;
    APTTYPEQUALIFIER qualifier;
};

static DWORD WINAPI ro_initialize_strict_thread(void *arg)
{
    struct ro_initialize_strict_result *result = arg;

    result->first_hr = result->initialize(result->input);
    result->type = APTTYPE_CURRENT;
    result->qualifier = APTTYPEQUALIFIER_NONE;
    result->query_hr = CoGetApartmentType(&result->type, &result->qualifier);
    result->second_hr = result->initialize(result->input);
    if (SUCCEEDED(result->first_hr)) CoUninitialize();
    return 0;
}

static void test_RoInitializeStrict(void)
{
    static const struct
    {
        INT input;
        HRESULT first_hr;
        HRESULT query_hr;
        APTTYPE type;
        INT qualifier;
    }
    tests[] =
    {
        {-1, E_INVALIDARG, CO_E_NOTINITIALIZED, APTTYPE_CURRENT, APTTYPEQUALIFIER_NONE},
        { 0, S_OK, S_OK, APTTYPE_MAINSTA, APTTYPEQUALIFIER_NONE},
        { 1, S_OK, S_OK, APTTYPE_STA, APTTYPEQUALIFIER_APPLICATION_STA},
        { 2, S_OK, S_OK, APTTYPE_MTA, APTTYPEQUALIFIER_NONE},
        { 3, CO_E_NOT_SUPPORTED, CO_E_NOTINITIALIZED, APTTYPE_CURRENT, APTTYPEQUALIFIER_NONE},
        { 4, S_OK, S_OK, APTTYPE_STA, 7},
        { 5, E_INVALIDARG, CO_E_NOTINITIALIZED, APTTYPE_CURRENT, APTTYPEQUALIFIER_NONE},
    };
    ro_initialize_strict_fn initialize;
    unsigned int i;

    initialize = (void *)GetProcAddress(GetModuleHandleW(L"combase.dll"), MAKEINTRESOURCEA(179));
    if (!initialize)
    {
        win_skip("RoInitializeStrict is unavailable.\n");
        return;
    }

    for (i = 0; i < ARRAY_SIZE(tests); ++i)
    {
        struct ro_initialize_strict_result result = {initialize, tests[i].input};
        HANDLE thread;

        winetest_push_context("input %d", tests[i].input);
        thread = CreateThread(NULL, 0, ro_initialize_strict_thread, &result, 0, NULL);
        ok(!!thread, "CreateThread failed, error %lu.\n", GetLastError());
        if (thread)
        {
            WaitForSingleObject(thread, INFINITE);
            CloseHandle(thread);
            ok(result.first_hr == tests[i].first_hr, "first call returned %#lx.\n", result.first_hr);
            ok(result.query_hr == tests[i].query_hr, "CoGetApartmentType returned %#lx.\n", result.query_hr);
            if (SUCCEEDED(result.query_hr))
            {
                ok(result.type == tests[i].type, "got apartment type %d.\n", result.type);
                ok(result.qualifier == tests[i].qualifier, "got apartment qualifier %d.\n", result.qualifier);
            }
            ok(result.second_hr == (SUCCEEDED(tests[i].first_hr) ? CO_E_INIT_ONLY_SINGLE_THREADED : tests[i].first_hr),
                    "second call returned %#lx.\n", result.second_hr);
        }
        winetest_pop_context();
    }
}

static void _expect_ref(IUnknown* obj, ULONG ref, int line)
{
    ULONG rc;
    IUnknown_AddRef(obj);
    rc = IUnknown_Release(obj);
    ok_(__FILE__,line)(rc == ref, "expected refcount %ld, got %ld\n", ref, rc);
}

static void flush_events(void)
{
    int diff = 200;
    DWORD time;
    MSG msg;

    time = GetTickCount() + diff;
    while (diff > 0)
    {
        if (MsgWaitForMultipleObjects(0, NULL, FALSE, 100, QS_ALLINPUT) == WAIT_TIMEOUT)
            break;
        while (PeekMessageA(&msg, 0, 0, 0, PM_REMOVE))
            DispatchMessageA(&msg);
        diff = time - GetTickCount();
    }
}

static void load_resource(const WCHAR *filename)
{
    DWORD written;
    HANDLE file;
    HRSRC res;
    void *ptr;

    file = CreateFileW(filename, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, 0);
    ok(file != INVALID_HANDLE_VALUE, "failed to create %s, error %lu\n", debugstr_w(filename), GetLastError());

    res = FindResourceW(NULL, filename, L"TESTDLL");
    ok(res != 0, "couldn't find resource\n");
    ptr = LockResource(LoadResource(GetModuleHandleW(NULL), res));
    WriteFile(file, ptr, SizeofResource(GetModuleHandleW(NULL), res), &written, NULL);
    ok(written == SizeofResource(GetModuleHandleW(NULL), res), "couldn't write resource\n");
    CloseHandle(file);
}

static HRESULT WINAPI outproc_factory_QueryInterface(IActivationFactory *iface, REFIID iid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
            IsEqualGUID(iid, &IID_IAgileObject) || IsEqualGUID(iid, &IID_IActivationFactory))
    {
        *out = iface;
        IActivationFactory_AddRef(iface);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG WINAPI outproc_factory_AddRef(IActivationFactory *iface)
{
    return 2;
}

static ULONG WINAPI outproc_factory_Release(IActivationFactory *iface)
{
    return 1;
}

static HRESULT WINAPI outproc_factory_GetIids(IActivationFactory *iface, ULONG *count, IID **iids)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI outproc_factory_GetRuntimeClassName(IActivationFactory *iface, HSTRING *name)
{
    return WindowsCreateString(L"Wine.Test.OutOfProcess", ARRAY_SIZE(L"Wine.Test.OutOfProcess") - 1, name);
}

static HRESULT WINAPI outproc_factory_GetTrustLevel(IActivationFactory *iface, TrustLevel *level)
{
    if (!level) return E_POINTER;
    *level = BaseTrust;
    return S_OK;
}

static HRESULT WINAPI outproc_factory_ActivateInstance(IActivationFactory *iface, IInspectable **instance)
{
    return E_NOTIMPL;
}

static const IActivationFactoryVtbl outproc_factory_vtbl =
{
    outproc_factory_QueryInterface,
    outproc_factory_AddRef,
    outproc_factory_Release,
    outproc_factory_GetIids,
    outproc_factory_GetRuntimeClassName,
    outproc_factory_GetTrustLevel,
    outproc_factory_ActivateInstance,
};

static IActivationFactory outproc_factory = {&outproc_factory_vtbl};

static HRESULT WINAPI get_outproc_factory(HSTRING classid, IActivationFactory **factory)
{
    if (wcscmp(WindowsGetStringRawBuffer(classid, NULL), L"Wine.Test.OutOfProcess"))
        return REGDB_E_CLASSNOTREG;
    *factory = &outproc_factory;
    IActivationFactory_AddRef(*factory);
    return S_OK;
}

static void outproc_activation_server(const char *ready_name, const char *quit_name)
{
    RO_REGISTRATION_COOKIE cookie = NULL;
    PFNGETACTIVATIONFACTORY callback = get_outproc_factory;
    HANDLE ready, quit;
    HSTRING classid;
    HRESULT hr;

    ready = OpenEventA(EVENT_MODIFY_STATE, FALSE, ready_name);
    ok(!!ready, "OpenEventA(%s) failed, error %lu.\n", ready_name, GetLastError());
    quit = OpenEventA(SYNCHRONIZE, FALSE, quit_name);
    ok(!!quit, "OpenEventA(%s) failed, error %lu.\n", quit_name, GetLastError());

    hr = RoInitialize(RO_INIT_MULTITHREADED);
    ok(hr == S_OK, "RoInitialize returned %#lx.\n", hr);
    hr = WindowsCreateString(L"Wine.Test.OutOfProcess", ARRAY_SIZE(L"Wine.Test.OutOfProcess") - 1, &classid);
    ok(hr == S_OK, "WindowsCreateString returned %#lx.\n", hr);
    hr = RoRegisterActivationFactories(&classid, &callback, 1, &cookie);
    ok(hr == S_OK, "RoRegisterActivationFactories returned %#lx.\n", hr);
    SetEvent(ready);

    if (SUCCEEDED(hr))
    {
        ok(WaitForSingleObject(quit, 10000) == WAIT_OBJECT_0, "quit event wait timed out.\n");
        RoRevokeActivationFactories(cookie);
    }
    WindowsDeleteString(classid);
    RoUninitialize();
    CloseHandle(quit);
    CloseHandle(ready);
}

static void test_outproc_activation(void)
{
    static const WCHAR class_key_name[] =
            L"Software\\Microsoft\\WindowsRuntime\\ActivatableClassId\\Wine.Test.OutOfProcess";
    static const WCHAR server_key_name[] =
            L"Software\\Microsoft\\WindowsRuntime\\Server\\Wine.Test.Server";
    static const WCHAR server_name[] = L"Wine.Test.Server";
    PROCESS_INFORMATION process = {0};
    STARTUPINFOA startup = {sizeof(startup)};
    char **argv, command[3 * MAX_PATH], ready_name[64], quit_name[64];
    IActivationFactory *factory = NULL;
    HANDLE ready, quit;
    HSTRING classid;
    TrustLevel level;
    HRESULT hr;
    HKEY key;
    LONG ret;

    ret = RegCreateKeyExW(HKEY_LOCAL_MACHINE, class_key_name, 0, NULL, 0, KEY_ALL_ACCESS,
            NULL, &key, NULL);
    ok(!ret, "RegCreateKeyExW(class) returned %ld.\n", ret);
    if (ret) return;
    ret = RegSetValueExW(key, L"Server", 0, REG_SZ, (const BYTE *)server_name, sizeof(server_name));
    ok(!ret, "RegSetValueExW returned %ld.\n", ret);
    RegCloseKey(key);
    ret = RegCreateKeyExW(HKEY_LOCAL_MACHINE, server_key_name, 0, NULL, 0, KEY_ALL_ACCESS,
            NULL, &key, NULL);
    ok(!ret, "RegCreateKeyExW(server) returned %ld.\n", ret);
    if (!ret) RegCloseKey(key);

    sprintf(ready_name, "Wine Combase WinRT Ready %lu", GetCurrentProcessId());
    sprintf(quit_name, "Wine Combase WinRT Quit %lu", GetCurrentProcessId());
    ready = CreateEventA(NULL, TRUE, FALSE, ready_name);
    quit = CreateEventA(NULL, TRUE, FALSE, quit_name);
    ok(!!ready && !!quit, "failed to create server events, error %lu.\n", GetLastError());

    winetest_get_mainargs(&argv);
    sprintf(command, "\"%s\" %s outproc_activation_server \"%s\" \"%s\"",
            argv[0], argv[1], ready_name, quit_name);
    ret = CreateProcessA(argv[0], command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process);
    ok(ret, "CreateProcessA failed, error %lu.\n", GetLastError());
    if (ret)
    {
        ok(WaitForSingleObject(ready, 10000) == WAIT_OBJECT_0, "server ready event wait timed out.\n");
        hr = RoInitialize(RO_INIT_MULTITHREADED);
        ok(hr == S_OK, "RoInitialize returned %#lx.\n", hr);
        hr = WindowsCreateString(L"Wine.Test.OutOfProcess", ARRAY_SIZE(L"Wine.Test.OutOfProcess") - 1,
                &classid);
        ok(hr == S_OK, "WindowsCreateString returned %#lx.\n", hr);
        hr = RoGetActivationFactory(classid, &IID_IActivationFactory, (void **)&factory);
        ok(hr == S_OK, "RoGetActivationFactory returned %#lx.\n", hr);
        if (factory)
        {
            level = -1;
            hr = IActivationFactory_GetTrustLevel(factory, &level);
            ok(hr == S_OK, "GetTrustLevel returned %#lx.\n", hr);
            ok(level == BaseTrust, "GetTrustLevel returned %d.\n", level);
            IActivationFactory_Release(factory);
        }
        WindowsDeleteString(classid);
        RoUninitialize();
        SetEvent(quit);
        winetest_wait_child_process(&process);
    }

    CloseHandle(quit);
    CloseHandle(ready);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, server_key_name);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, class_key_name);
}

static void test_extension_catalog(void)
{
    static const WCHAR class_name[] = L"Windows.Foundation.ExtensionCatalog";
    static const WCHAR extension_name[] = L"linuxnt.nonexistent";
    static const IID expected_catalog_iids[] =
    {
        {0x07cee0d8, 0xd555, 0x4d61, {0x9c, 0x37, 0x01, 0xc1, 0x94, 0xb0, 0xf2, 0x08}},
        {0x00000038, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}},
    };
    static const IID expected_iterator_iids[] =
    {
        {0xb4d4a79e, 0xfe15, 0x5272, {0x99, 0x88, 0x61, 0x7a, 0x34, 0xd8, 0x30, 0x0b}},
        {0x00000038, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}},
    };
    dll_get_activation_factory_fn get_factory;
    struct extension_catalog *catalog = NULL, *catalog_iface = NULL;
    struct extension_iterator *iterator = NULL;
    IActivationFactory *factory = NULL;
    IInspectable *current = (void *)0xdeadbeef;
    HSTRING classid = NULL, name = NULL, query = NULL;
    IID *iids = NULL;
    TrustLevel level;
    const WCHAR *buffer;
    boolean value;
    UINT32 length;
    ULONG count;
    HRESULT hr;

    get_factory = (void *)GetProcAddress(GetModuleHandleW(L"combase.dll"), "DllGetActivationFactory");
    ok(!!get_factory, "DllGetActivationFactory is missing.\n");
    if (!get_factory) return;

    hr = WindowsCreateString(class_name, ARRAY_SIZE(class_name) - 1, &classid);
    ok(hr == S_OK, "WindowsCreateString returned %#lx.\n", hr);
    hr = get_factory(classid, &factory);
    ok(hr == S_OK, "DllGetActivationFactory returned %#lx.\n", hr);
    ok(!!factory, "factory is NULL.\n");
    if (!factory) goto done;

    count = 0xdeadbeef;
    hr = IActivationFactory_GetIids(factory, &count, &iids);
    ok(hr == S_OK, "factory GetIids returned %#lx.\n", hr);
    ok(count == 1, "factory GetIids returned %lu interfaces.\n", count);
    if (count == 1) ok(IsEqualGUID(&iids[0], &IID_IActivationFactory), "unexpected factory IID %s.\n",
                       wine_dbgstr_guid(&iids[0]));
    CoTaskMemFree(iids);
    iids = NULL;

    hr = IActivationFactory_GetRuntimeClassName(factory, &name);
    ok(hr == E_ILLEGAL_METHOD_CALL, "factory GetRuntimeClassName returned %#lx.\n", hr);
    ok(!name, "factory returned class name %p.\n", name);
    level = BaseTrust;
    hr = IActivationFactory_GetTrustLevel(factory, &level);
    ok(hr == S_OK, "factory GetTrustLevel returned %#lx.\n", hr);
    ok(level == FullTrust, "factory trust level is %u.\n", level);

    hr = IActivationFactory_ActivateInstance(factory, (IInspectable **)&catalog);
    ok(hr == S_OK, "ActivateInstance returned %#lx.\n", hr);
    ok(!!catalog, "catalog is NULL.\n");
    if (!catalog) goto done;

    hr = catalog->lpVtbl->QueryInterface(catalog, &IID_IExtensionCatalog, (void **)&catalog_iface);
    ok(hr == S_OK, "catalog QueryInterface returned %#lx.\n", hr);
    ok(catalog_iface == catalog, "catalog QueryInterface returned %p, expected %p.\n", catalog_iface, catalog);
    if (catalog_iface) catalog_iface->lpVtbl->Release(catalog_iface);

    count = 0xdeadbeef;
    hr = catalog->lpVtbl->GetIids(catalog, &count, &iids);
    ok(hr == S_OK, "catalog GetIids returned %#lx.\n", hr);
    ok(count == ARRAY_SIZE(expected_catalog_iids), "catalog GetIids returned %lu interfaces.\n", count);
    if (count == ARRAY_SIZE(expected_catalog_iids))
    {
        ok(IsEqualGUID(&iids[0], &expected_catalog_iids[0]), "unexpected catalog IID[0] %s.\n",
           wine_dbgstr_guid(&iids[0]));
        ok(IsEqualGUID(&iids[1], &expected_catalog_iids[1]), "unexpected catalog IID[1] %s.\n",
           wine_dbgstr_guid(&iids[1]));
    }
    CoTaskMemFree(iids);
    iids = NULL;

    hr = catalog->lpVtbl->GetRuntimeClassName(catalog, &name);
    ok(hr == S_OK, "catalog GetRuntimeClassName returned %#lx.\n", hr);
    buffer = WindowsGetStringRawBuffer(name, &length);
    ok(length == ARRAY_SIZE(class_name) - 1 && !wcscmp(buffer, class_name), "unexpected class name %s.\n",
       wine_dbgstr_w(buffer));
    WindowsDeleteString(name);
    name = NULL;
    level = BaseTrust;
    hr = catalog->lpVtbl->GetTrustLevel(catalog, &level);
    ok(hr == S_OK, "catalog GetTrustLevel returned %#lx.\n", hr);
    ok(level == FullTrust, "catalog trust level is %u.\n", level);

    hr = WindowsCreateString(extension_name, ARRAY_SIZE(extension_name) - 1, &query);
    ok(hr == S_OK, "WindowsCreateString returned %#lx.\n", hr);
    hr = catalog->lpVtbl->QueryCatalog(catalog, query, &iterator);
    ok(hr == S_OK, "QueryCatalog returned %#lx.\n", hr);
    ok(!!iterator, "iterator is NULL.\n");
    if (iterator)
    {
        count = 0xdeadbeef;
        hr = iterator->lpVtbl->GetIids(iterator, &count, &iids);
        ok(hr == S_OK, "iterator GetIids returned %#lx.\n", hr);
        ok(count == ARRAY_SIZE(expected_iterator_iids), "iterator GetIids returned %lu interfaces.\n", count);
        if (count == ARRAY_SIZE(expected_iterator_iids))
        {
            ok(IsEqualGUID(&iids[0], &expected_iterator_iids[0]), "unexpected iterator IID[0] %s.\n",
               wine_dbgstr_guid(&iids[0]));
            ok(IsEqualGUID(&iids[1], &expected_iterator_iids[1]), "unexpected iterator IID[1] %s.\n",
               wine_dbgstr_guid(&iids[1]));
        }
        CoTaskMemFree(iids);
        iids = NULL;

        hr = iterator->lpVtbl->GetRuntimeClassName(iterator, &name);
        ok(hr == E_NOTIMPL, "iterator GetRuntimeClassName returned %#lx.\n", hr);
        ok(!name, "iterator returned class name %p.\n", name);
        value = 0xff;
        hr = iterator->lpVtbl->get_HasCurrent(iterator, &value);
        ok(hr == S_OK, "iterator get_HasCurrent returned %#lx.\n", hr);
        ok(!value, "iterator has current value %u.\n", value);
        hr = iterator->lpVtbl->get_Current(iterator, &current);
        ok(hr == E_BOUNDS, "iterator get_Current returned %#lx.\n", hr);
        ok(!current, "iterator current is %p.\n", current);
        value = 0xff;
        hr = iterator->lpVtbl->MoveNext(iterator, &value);
        ok(hr == E_BOUNDS, "iterator MoveNext returned %#lx.\n", hr);
        ok(!value, "iterator MoveNext value is %u.\n", value);
        iterator->lpVtbl->Release(iterator);
    }

done:
    if (catalog) catalog->lpVtbl->Release(catalog);
    if (factory) IActivationFactory_Release(factory);
    WindowsDeleteString(query);
    WindowsDeleteString(classid);
}

static void test_ActivationFactories(void)
{
    HRESULT hr;
    HSTRING str, str2;
    IActivationFactory *factory = NULL;
    IInspectable *inspect = NULL;
    ULONG ref;

    hr = WindowsCreateString(L"Windows.Data.Xml.Dom.XmlDocument",
                              ARRAY_SIZE(L"Windows.Data.Xml.Dom.XmlDocument") - 1, &str);
    ok(hr == S_OK, "Unexpected hr %#lx.\n", hr);

    hr = WindowsCreateString(L"Does.Not.Exist", ARRAY_SIZE(L"Does.Not.Exist") - 1, &str2);
    ok(hr == S_OK, "Unexpected hr %#lx.\n", hr);

    hr = RoInitialize(RO_INIT_MULTITHREADED);
    ok(hr == S_OK, "Unexpected hr %#lx.\n", hr);

    hr = RoGetActivationFactory(str2, &IID_IActivationFactory, (void **)&factory);
    ok(hr == REGDB_E_CLASSNOTREG, "Unexpected hr %#lx.\n", hr);

    hr = RoGetActivationFactory(str, &IID_IActivationFactory, (void **)&factory);
    todo_wine ok(hr == S_OK, "Unexpected hr %#lx.\n", hr);
    if(factory)
        IActivationFactory_Release(factory);

    hr = RoActivateInstance(str2, &inspect);
    ok(hr == REGDB_E_CLASSNOTREG, "Unexpected hr %#lx.\n", hr);

    hr = RoActivateInstance(str, &inspect);
    todo_wine ok(hr == S_OK, "UNexpected hr %#lx.\n", hr);
    if(inspect)
        IInspectable_Release(inspect);

    WindowsDeleteString(str2);
    WindowsDeleteString(str);

    hr = WindowsCreateString(L"Wine.Test.Missing", ARRAY_SIZE(L"Wine.Test.Missing") - 1, &str);
    ok(hr == S_OK, "WindowsCreateString returned %#lx.\n", hr);
    hr = RoGetActivationFactory(str, &IID_IActivationFactory, (void **)&factory);
    ok(hr == REGDB_E_CLASSNOTREG, "RoGetActivationFactory returned %#lx.\n", hr);
    ok(factory == NULL, "got factory %p.\n", factory);
    WindowsDeleteString(str);
    hr = WindowsCreateString(L"Wine.Test.Class", ARRAY_SIZE(L"Wine.Test.Class") - 1, &str);
    ok(hr == S_OK, "WindowsCreateString returned %#lx.\n", hr);
    hr = RoGetActivationFactory(str, &IID_IActivationFactory, (void **)&factory);
    todo_wine
    ok(hr == E_NOTIMPL || broken(hr == REGDB_E_CLASSNOTREG) /* <= w1064v1809 */,
            "RoGetActivationFactory returned %#lx.\n", hr);
    todo_wine
    ok(factory == NULL, "got factory %p.\n", factory);
    if (factory) IActivationFactory_Release(factory);
    WindowsDeleteString(str);
    hr = WindowsCreateString(L"Wine.Test.Trusted", ARRAY_SIZE(L"Wine.Test.Trusted") - 1, &str);
    ok(hr == S_OK, "WindowsCreateString returned %#lx.\n", hr);
    hr = RoGetActivationFactory(str, &IID_IActivationFactory, (void **)&factory);
    ok(hr == S_OK || broken(hr == REGDB_E_CLASSNOTREG) /* <= w1064v1809 */,
            "RoGetActivationFactory returned %#lx.\n", hr);
    if (hr == REGDB_E_CLASSNOTREG)
        ok(!factory, "got factory %p.\n", factory);
    else
        ok(!!factory, "got factory %p.\n", factory);
    if (!factory) ref = 0;
    else ref = IActivationFactory_Release(factory);
    ok(ref == 0, "Release returned %lu\n", ref);
    WindowsDeleteString(str);

    RoUninitialize();
}

static APTTYPE check_thread_apttype;
static APTTYPEQUALIFIER check_thread_aptqualifier;
static HRESULT check_thread_hr;

static DWORD WINAPI check_apartment_thread(void *dummy)
{
    check_thread_apttype = 0xdeadbeef;
    check_thread_aptqualifier = 0xdeadbeef;
    check_thread_hr = CoGetApartmentType(&check_thread_apttype, &check_thread_aptqualifier);
    return 0;
}

#define check_thread_apartment(a) check_thread_apartment_(__LINE__, FALSE, a)
#define check_thread_apartment_broken(a) check_thread_apartment_(__LINE__, TRUE, a)
static void check_thread_apartment_(unsigned int line, BOOL broken_fail, HRESULT expected_hr_thread)
{
    HANDLE thread;

    check_thread_hr = 0xdeadbeef;
    thread = CreateThread(NULL, 0, check_apartment_thread, NULL, 0, NULL);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    ok_(__FILE__, line)(check_thread_hr == expected_hr_thread
            || broken(broken_fail && expected_hr_thread == S_OK && check_thread_hr == CO_E_NOTINITIALIZED),
            "got %#lx, expected %#lx.\n", check_thread_hr, expected_hr_thread);
    if (SUCCEEDED(check_thread_hr))
    {
        ok_(__FILE__, line)(check_thread_apttype == APTTYPE_MTA, "got %d.\n", check_thread_apttype);
        ok_(__FILE__, line)(check_thread_aptqualifier == APTTYPEQUALIFIER_IMPLICIT_MTA, "got %d.\n", check_thread_aptqualifier);
    }
}

static HANDLE mta_init_thread_init_done_event, mta_init_thread_done_event;

static DWORD WINAPI mta_init_thread(void *dummy)
{
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(hr == S_OK, "got %#lx.\n", hr);
    SetEvent(mta_init_thread_init_done_event);

    WaitForSingleObject(mta_init_thread_done_event, INFINITE);
    CoUninitialize();
    return 0;
}

static DWORD WINAPI mta_init_implicit_thread(void *dummy)
{
    IActivationFactory *factory;
    HSTRING str;
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ok(hr == S_OK, "got %#lx.\n", hr);

    hr = WindowsCreateString(L"Does.Not.Exist", ARRAY_SIZE(L"Does.Not.Exist") - 1, &str);
    ok(hr == S_OK, "got %#lx.\n", hr);
    hr = RoGetActivationFactory(str, &IID_IActivationFactory, (void **)&factory);
    ok(hr == REGDB_E_CLASSNOTREG, "got %#lx.\n", hr);
    WindowsDeleteString(str);

    SetEvent(mta_init_thread_init_done_event);
    WaitForSingleObject(mta_init_thread_done_event, INFINITE);

    /* No CoUninitialize(), testing cleanup on thread exit. */
    return 0;
}

enum oletlsflags
{
    OLETLS_UUIDINITIALIZED = 0x2,
    OLETLS_DISABLE_OLE1DDE = 0x40,
    OLETLS_APARTMENTTHREADED = 0x80,
    OLETLS_MULTITHREADED = 0x100,
};

struct oletlsdata
{
    void *threadbase;
    void *smallocator;
    DWORD id;
    DWORD flags;
};

static DWORD get_oletlsflags(void)
{
    struct oletlsdata *data = NtCurrentTeb()->ReservedForOle;
    return data ? data->flags : 0;
}

static void test_implicit_mta(void)
{
    static const struct
    {
        BOOL ro_init;
        BOOL mta;
    }
    tests[] =
    {
        { FALSE, FALSE },
        { FALSE, TRUE },
        { TRUE, FALSE },
        { TRUE, TRUE },
    };
    APTTYPEQUALIFIER aptqualifier;
    IActivationFactory *factory;
    APTTYPE apttype;
    unsigned int i;
    HANDLE thread;
    HSTRING str;
    HRESULT hr;

    hr = WindowsCreateString(L"Does.Not.Exist", ARRAY_SIZE(L"Does.Not.Exist") - 1, &str);
    ok(hr == S_OK, "got %#lx.\n", hr);
    /* RoGetActivationFactory doesn't implicitly initialize COM. */
    hr = RoGetActivationFactory(str, &IID_IActivationFactory, (void **)&factory);
    ok(hr == CO_E_NOTINITIALIZED, "got %#lx.\n", hr);

    check_thread_apartment(CO_E_NOTINITIALIZED);

    /* RoGetActivationFactory initializes implicit MTA. */
    for (i = 0; i < ARRAY_SIZE(tests); ++i)
    {
        winetest_push_context("test %u", i);
        if (tests[i].ro_init)
        {
            DWORD flags = tests[i].mta ? OLETLS_MULTITHREADED : OLETLS_APARTMENTTHREADED;

            hr = RoInitialize(tests[i].mta ? RO_INIT_MULTITHREADED : RO_INIT_SINGLETHREADED);

            flags |= OLETLS_DISABLE_OLE1DDE;
            ok((get_oletlsflags() & flags) == flags, "get_oletlsflags() = %lx\n", get_oletlsflags());
        }
        else
            hr = CoInitializeEx(NULL, tests[i].mta ? COINIT_MULTITHREADED : COINIT_APARTMENTTHREADED);
        ok(hr == S_OK, "got %#lx.\n", hr);
        check_thread_apartment(tests[i].mta ? S_OK : CO_E_NOTINITIALIZED);
        hr = RoGetActivationFactory(str, &IID_IActivationFactory, (void **)&factory);
        ok(hr == REGDB_E_CLASSNOTREG, "got %#lx.\n", hr);
        check_thread_apartment_broken(S_OK); /* Broken on Win8. */
        hr = RoGetActivationFactory(str, &IID_IActivationFactory, (void **)&factory);
        ok(hr == REGDB_E_CLASSNOTREG, "got %#lx.\n", hr);
        check_thread_apartment_broken(S_OK); /* Broken on Win8. */
        if (tests[i].ro_init)
            RoUninitialize();
        else
            CoUninitialize();
        check_thread_apartment(CO_E_NOTINITIALIZED);
        winetest_pop_context();
    }

    mta_init_thread_init_done_event = CreateEventW(NULL, FALSE, FALSE, NULL);
    mta_init_thread_done_event = CreateEventW(NULL, FALSE, FALSE, NULL);

    /* RoGetActivationFactory references implicit MTA in a current thread
     * even if implicit MTA was already initialized: check with STA init
     * after RoGetActivationFactory(). */
    thread = CreateThread(NULL, 0, mta_init_thread, NULL, 0, NULL);
    ok(!!thread, "failed.\n");
    WaitForSingleObject(mta_init_thread_init_done_event, INFINITE);
    check_thread_apartment(S_OK);

    hr = RoGetActivationFactory(str, &IID_IActivationFactory, (void **)&factory);
    ok(hr == REGDB_E_CLASSNOTREG, "got %#lx.\n", hr);
    check_thread_apartment(S_OK);

    hr = CoGetApartmentType(&apttype, &aptqualifier);
    ok(hr == S_OK, "got %#lx.\n", hr);
    ok(apttype == APTTYPE_MTA, "got %d.\n", apttype);
    ok(aptqualifier == APTTYPEQUALIFIER_IMPLICIT_MTA, "got %d.\n", aptqualifier);

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ok(hr == S_OK, "got %#lx.\n", hr);

    hr = CoGetApartmentType(&apttype, &aptqualifier);
    ok(hr == S_OK, "got %#lx.\n", hr);
    ok(apttype == APTTYPE_MAINSTA, "got %d.\n", apttype);
    ok(aptqualifier == APTTYPEQUALIFIER_NONE, "got %d.\n", aptqualifier);

    SetEvent(mta_init_thread_done_event);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    check_thread_apartment_broken(S_OK); /* Broken on Win8. */
    CoUninitialize();
    check_thread_apartment(CO_E_NOTINITIALIZED);

    /* RoGetActivationFactory references implicit MTA in a current thread
     * even if implicit MTA was already initialized: check with STA init
     * before RoGetActivationFactory(). */
    thread = CreateThread(NULL, 0, mta_init_thread, NULL, 0, NULL);
    ok(!!thread, "failed.\n");
    WaitForSingleObject(mta_init_thread_init_done_event, INFINITE);
    check_thread_apartment(S_OK);

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ok(hr == S_OK, "got %#lx.\n", hr);

    hr = RoGetActivationFactory(str, &IID_IActivationFactory, (void **)&factory);
    ok(hr == REGDB_E_CLASSNOTREG, "got %#lx.\n", hr);
    check_thread_apartment(S_OK);

    SetEvent(mta_init_thread_done_event);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    check_thread_apartment_broken(S_OK); /* Broken on Win8. */
    CoUninitialize();
    check_thread_apartment(CO_E_NOTINITIALIZED);

    /* Test implicit MTA apartment thread exit. */
    thread = CreateThread(NULL, 0, mta_init_implicit_thread, NULL, 0, NULL);
    ok(!!thread, "failed.\n");
    WaitForSingleObject(mta_init_thread_init_done_event, INFINITE);
    check_thread_apartment_broken(S_OK); /* Broken on Win8. */
    SetEvent(mta_init_thread_done_event);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    check_thread_apartment(CO_E_NOTINITIALIZED);

    CloseHandle(mta_init_thread_init_done_event);
    CloseHandle(mta_init_thread_done_event);
    WindowsDeleteString(str);
}

struct unk_impl
{
    IUnknown IUnknown_iface;
    LONG ref;
};

static inline struct unk_impl *impl_from_IUnknown(IUnknown *iface)
{
    return CONTAINING_RECORD(iface, struct unk_impl, IUnknown_iface);
}

static HRESULT WINAPI unk_QueryInterface(IUnknown *iface, REFIID riid, void **ppv)
{
    if (IsEqualGUID(riid, &IID_IUnknown))
    {
        *ppv = iface;
        IUnknown_AddRef(iface);
        return S_OK;
    }

    return E_NOINTERFACE;
}

static HRESULT WINAPI unk_no_marshal_QueryInterface(IUnknown *iface, REFIID riid, void **ppv)
{
    if (IsEqualGUID(riid, &IID_IUnknown)
        || IsEqualGUID(riid, &IID_INoMarshal))
    {
        *ppv = iface;
        IUnknown_AddRef(iface);
        return S_OK;
    }

    return E_NOINTERFACE;
}

static HRESULT WINAPI unk_agile_QueryInterface(IUnknown *iface, REFIID riid, void **ppv)
{
    if (IsEqualGUID(riid, &IID_IUnknown)
        || IsEqualGUID(riid, &IID_IAgileObject))
    {
        *ppv = iface;
        IUnknown_AddRef(iface);
        return S_OK;
    }

    return E_NOINTERFACE;
}

static ULONG WINAPI unk_AddRef(IUnknown *iface)
{
    struct unk_impl *impl = impl_from_IUnknown(iface);
    return InterlockedIncrement(&impl->ref);
}

static ULONG WINAPI unk_Release(IUnknown *iface)
{
    struct unk_impl *impl = impl_from_IUnknown(iface);
    return InterlockedDecrement(&impl->ref);
}

static const IUnknownVtbl unk_vtbl =
{
    unk_QueryInterface,
    unk_AddRef,
    unk_Release
};

static const IUnknownVtbl unk_no_marshal_vtbl =
{
    unk_no_marshal_QueryInterface,
    unk_AddRef,
    unk_Release
};

static const IUnknownVtbl unk_agile_vtbl =
{
    unk_agile_QueryInterface,
    unk_AddRef,
    unk_Release
};

/* IUnknown implementation that has affinity to the STA it was created in. */
struct unk_ctx_impl
{
    IUnknown IUnknown_iface;
    BOOL todo;
    UINT64 apt_id; /* Identifier of the apartment this object belongs to. */
    ULONG_PTR context; /* The COM context this object belongs to. */
    APTTYPE type; /* APTTYPE of the apartment this object belongs to. */
    DWORD thread_id;
    GUID com_thread_id;
    LONG ref;
};

static inline struct unk_ctx_impl *impl_unk_ctx_impl_from_IUnknown(IUnknown *iface)
{
    return CONTAINING_RECORD(iface, struct unk_ctx_impl, IUnknown_iface);
}

/* If true, the method call is being made from the test thread. */
static BOOL caller_test_thread;

#define test_apartment_context(impl) test_apartment_context_(__LINE__, impl)
static void test_apartment_context_(int line, const struct unk_ctx_impl *impl)
{
    APTTYPEQUALIFIER qualifier;
    ULONG_PTR cur_ctx;
    UINT64 cur_id;
    APTTYPE type;
    HRESULT hr;

    hr = CoGetContextToken(&cur_ctx);
    ok_(__FILE__, line)(hr == S_OK, "CoGetContextToken failed, got hr %#lx\n", hr);
    /* As this object has apartment-affinity, its methods can only be called from the apartment and context it was
     * created in. */
    ok_(__FILE__, line)(cur_ctx == impl->context, "got cur_ctx %#Ix != %#Ix\n", cur_ctx, impl->context);

    hr = CoGetApartmentType(&type, &qualifier);
    ok_(__FILE__, line)(hr == S_OK, "CoGetApartmentType failed, got hr %#lx\n", hr);
    ok_(__FILE__, line)(type == impl->type, "got type %d\n", type);

    hr = RoGetApartmentIdentifier(&cur_id);
    /* win10 and below fail with ERROR_API_UNAVAILABLE */
    ok_(__FILE__, line)(hr == S_OK || broken(hr == HRESULT_FROM_WIN32(ERROR_API_UNAVAILABLE)),
                        "RoGetApartmentIdentifier failed, got hr %#lx\n", hr);
    if (SUCCEEDED(hr))
        ok_(__FILE__, line)(cur_id == impl->apt_id, "got cur_id %#I64x != %#I64x\n", cur_id, impl->apt_id);

    if (caller_test_thread)
    {
        DWORD cur_tid = GetCurrentThreadId();
        IUnknown *unk = (IUnknown *)cur_ctx;
        GUID ctx_com_tid, cur_com_tid;
        IComThreadingInfo *info;

        hr = IUnknown_QueryInterface(unk, &IID_IComThreadingInfo, (void **)&info);
        ok_(__FILE__, line)(hr == S_OK, "QueryInterface failed, got hr %#lx\n", hr);

        hr = IComThreadingInfo_GetCurrentLogicalThreadId(info, &ctx_com_tid);
        ok_(__FILE__, line)(hr == S_OK, "GetCurrentLogicalThreadId failed, got hr %#lx\n", hr);

        hr = CoGetCurrentLogicalThreadId(&cur_com_tid);
        ok_(__FILE__, line)(hr == S_OK, "CoGetCurrentLogicalThreadId failed, got hr %#lx\n", hr);
        ok_(__FILE__, line)(IsEqualGUID(&cur_com_tid, &ctx_com_tid), "Got cur_com_tid %s != %s.\n",
                            debugstr_guid(&cur_com_tid), debugstr_guid(&ctx_com_tid));
        IComThreadingInfo_Release(info);

        /* If this object belongs to an STA, we should now be in the same thread that the object was created in. */
        if (impl->type == APTTYPE_STA || impl->type == APTTYPE_MAINSTA)
        {
            ok(cur_tid == impl->thread_id, "Got cur_tid %lu != %lu\n", cur_tid, impl->thread_id);
            ok(!IsEqualGUID(&ctx_com_tid, &impl->com_thread_id), "Got cur_com_tid %s != %s\n",
               debugstr_guid(&ctx_com_tid), debugstr_guid(&impl->com_thread_id));
        }
        else
            /* If this object belongs to a MTA, then the method call will be made from the same thread as that of the
             * caller. */
            ok(cur_tid != impl->thread_id, "Got cur_tid %lu\n", cur_tid);
    }
}

static HRESULT WINAPI unk_ctx_impl_QueryInterface(IUnknown *iface, const GUID *iid, void **out)
{
    struct unk_ctx_impl *impl = impl_unk_ctx_impl_from_IUnknown(iface);

    if (winetest_debug > 1)
        trace("(%p, %s, %p)\n", iface, debugstr_guid(iid), out);

    test_apartment_context(impl);
    if (IsEqualGUID(iid, &IID_IUnknown))
    {
        *out = &impl->IUnknown_iface;
        IUnknown_AddRef((IUnknown *)*out);
        return S_OK;
    }

    *out = NULL;
    if (winetest_debug > 1)
        trace("%s not implemeneted, returning E_NOINTERFACE\n", debugstr_guid(iid));
    return E_NOINTERFACE;
}

static ULONG WINAPI unk_ctx_impl_AddRef(IUnknown *iface)
{
    struct unk_ctx_impl *impl = impl_unk_ctx_impl_from_IUnknown(iface);

    test_apartment_context(impl);
    return InterlockedIncrement(&impl->ref);
}

static ULONG WINAPI unk_ctx_impl_Release(IUnknown *iface)
{
    struct unk_ctx_impl *impl = impl_unk_ctx_impl_from_IUnknown(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);

    test_apartment_context(impl);
    if (!ref) free(impl);
    return ref;
}

static const IUnknownVtbl unk_ctx_impl_IUnknown_vtbl =
{
    unk_ctx_impl_QueryInterface,
    unk_ctx_impl_AddRef,
    unk_ctx_impl_Release,
};

static IUnknown *unk_ctx_impl_create(void)
{
    APTTYPEQUALIFIER qualifier;
    struct unk_ctx_impl *impl;
    UINT64 apt_id = 0;
    ULONG_PTR context;
    APTTYPE type;
    HRESULT hr;
    GUID id;

    hr = CoGetApartmentType(&type, &qualifier);
    ok(hr == S_OK, "got hr %#lx\n", hr);

    hr = CoGetContextToken(&context);
    ok(hr == S_OK, "got hr %#lx\n", hr);

    hr = RoGetApartmentIdentifier(&apt_id);
    /* win10 and below fail with ERROR_API_UNAVAILABLE */
    ok(hr == S_OK || broken(hr == HRESULT_FROM_WIN32(ERROR_API_UNAVAILABLE)), "got hr %#lx\n", hr);

    hr = CoGetCurrentLogicalThreadId(&id);
    ok(hr == S_OK, "got hr %#lx\n", hr);

    if (!(impl = calloc(1, sizeof(*impl)))) return NULL;
    impl->IUnknown_iface.lpVtbl = &unk_ctx_impl_IUnknown_vtbl;
    impl->context = context;
    impl->type = type;
    impl->apt_id = apt_id;
    impl->com_thread_id = id;
    impl->thread_id = GetCurrentThreadId();
    impl->ref = 1;
    return &impl->IUnknown_iface;
}

struct test_RoGetAgileReference_thread_param
{
    enum AgileReferenceOptions option;
    RO_INIT_TYPE from_type;
    RO_INIT_TYPE to_type;
    IAgileReference *agile_reference;
    IUnknown *unk_obj;
    BOOLEAN obj_is_agile;
};

static DWORD CALLBACK test_RoGetAgileReference_thread_proc(void *arg)
{
    struct test_RoGetAgileReference_thread_param *param = (struct test_RoGetAgileReference_thread_param *)arg;
    IUnknown *unknown;
    HRESULT hr;

    winetest_push_context("%d %d %d", param->option, param->from_type, param->to_type);

    RoInitialize(param->to_type);

    unknown = NULL;
    hr = IAgileReference_Resolve(param->agile_reference, &IID_IUnknown, (void **)&unknown);
    ok(hr == S_OK, "Got unexpected hr %#lx.\n", hr);
    ok(!!unknown, "Expected pointer not NULL.\n");
    if (param->obj_is_agile)
    {
        ok(unknown == param->unk_obj, "Expected the same object.\n");
        EXPECT_REF(param->unk_obj, 4);
    }
    else if (param->from_type == RO_INIT_MULTITHREADED && param->to_type == RO_INIT_MULTITHREADED)
    {
        ok(unknown == param->unk_obj, "Expected the same object.\n");
        todo_wine_if(param->option == AGILEREFERENCE_DEFAULT)
        EXPECT_REF(param->unk_obj, param->option == AGILEREFERENCE_DEFAULT ? 5 : 6);
    }
    else
    {
        ok(unknown != param->unk_obj, "Expected a different object pointer.\n");
        todo_wine_if(param->option == AGILEREFERENCE_DEFAULT)
        EXPECT_REF(param->unk_obj, param->option == AGILEREFERENCE_DEFAULT ? 4 : 5);
        EXPECT_REF(unknown, 1);
    }
    IUnknown_Release(unknown);

    RoUninitialize();
    winetest_pop_context();
    return 0;
}

struct test_agile_resolve_context_params
{
    RO_INIT_TYPE from_type;
    RO_INIT_TYPE to_type;
    IAgileReference *ref;
};

static DWORD CALLBACK test_agile_resolve_context(void *arg)
{
    struct test_agile_resolve_context_params *params = arg;
    IUnknown *unknown;
    HRESULT hr;

    caller_test_thread = TRUE;
    hr = RoInitialize(params->to_type);
    ok(hr == S_OK, "got hr %#lx.\n", hr);

    winetest_push_context("from_type=%d, to_type=%d", params->from_type, params->to_type);
    hr = IAgileReference_Resolve(params->ref, &IID_IUnknown, (void **)&unknown);
    ok(hr == S_OK, "got hr %#lx\n", hr);
    if (SUCCEEDED(hr))
        IUnknown_Release(unknown);
    winetest_pop_context();

    RoUninitialize();
    caller_test_thread = FALSE;
    return 0;
}

static void test_RoGetAgileReference(void)
{
    struct test_RoGetAgileReference_thread_param param;
    struct unk_impl unk_no_marshal_obj = {{&unk_no_marshal_vtbl}, 1};
    struct unk_impl unk_obj = {{&unk_vtbl}, 1};
    struct unk_impl unk_agile_obj = {{&unk_agile_vtbl}, 1};
    struct unk_ctx_impl *unk_ctx_impl;
    enum AgileReferenceOptions option;
    IAgileReference *agile_reference;
    RO_INIT_TYPE from_type, to_type;
    IUnknown *unknown, *unknown2;
    IAgileObject *agile_object;
    HANDLE thread;
    HRESULT hr;
    DWORD ret;

    for (option = AGILEREFERENCE_DEFAULT; option <= AGILEREFERENCE_DELAYEDMARSHAL; option++)
    {
        for (from_type = RO_INIT_SINGLETHREADED; from_type <= RO_INIT_MULTITHREADED; from_type++)
        {
            winetest_push_context("%d %d", option, from_type);

            hr = RoGetAgileReference(option, &IID_IUnknown, &unk_obj.IUnknown_iface, &agile_reference);
            ok(hr == CO_E_NOTINITIALIZED, "Got unexpected hr %#lx.\n", hr);

            RoInitialize(from_type);

            agile_reference = NULL;
            EXPECT_REF(&unk_obj, 1);

            /* Invalid option */
            hr = RoGetAgileReference(AGILEREFERENCE_DELAYEDMARSHAL + 1, &IID_IUnknown, &unk_obj.IUnknown_iface, &agile_reference);
            ok(hr == E_INVALIDARG, "Got unexpected hr %#lx.\n", hr);

            /* Non-existent interface for the object */
            hr = RoGetAgileReference(option, &IID_IActivationFactory, &unk_obj.IUnknown_iface, &agile_reference);
            ok(hr == E_NOINTERFACE, "Got unexpected hr %#lx.\n", hr);

            /* Objects that implements INoMarshal */
            hr = RoGetAgileReference(option, &IID_IUnknown, &unk_no_marshal_obj.IUnknown_iface, &agile_reference);
            ok(hr == CO_E_NOT_SUPPORTED, "Got unexpected hr %#lx.\n", hr);

            /* Create agile reference object */
            hr = RoGetAgileReference(option, &IID_IUnknown, &unk_obj.IUnknown_iface, &agile_reference);
            ok(hr == S_OK, "Got unexpected hr %#lx.\n", hr);
            ok(!!agile_reference, "Got unexpected agile_reference.\n");
            todo_wine_if(option == AGILEREFERENCE_DEFAULT)
            EXPECT_REF(&unk_obj, 2);

            /* Check the created agile reference object has IAgileObject */
            hr = IAgileReference_QueryInterface(agile_reference, &IID_IAgileObject, (void **)&agile_object);
            ok(hr == S_OK, "Got unexpected hr %#lx.\n", hr);
            IAgileObject_Release(agile_object);

            /* Resolve once */
            unknown = NULL;
            hr = IAgileReference_Resolve(agile_reference, &IID_IUnknown, (void **)&unknown);
            ok(hr == S_OK, "Got unexpected hr %#lx.\n", hr);
            ok(!!unknown, "Expected pointer not NULL.\n");
            ok(unknown == &unk_obj.IUnknown_iface, "Expected the same object.\n");
            todo_wine
            EXPECT_REF(&unk_obj, 3);

            /* Resolve twice */
            unknown2 = NULL;
            hr = IAgileReference_Resolve(agile_reference, &IID_IUnknown, (void **)&unknown2);
            ok(hr == S_OK, "Got unexpected hr %#lx.\n", hr);
            ok(!!unknown2, "Expected pointer not NULL.\n");
            ok(unknown2 == &unk_obj.IUnknown_iface, "Expected the same object.\n");
            todo_wine
            EXPECT_REF(&unk_obj, 4);

            /* Resolve in another apartment */
            for (to_type = RO_INIT_SINGLETHREADED; to_type <= RO_INIT_MULTITHREADED; to_type++)
            {
                param.option = option;
                param.from_type = from_type;
                param.to_type = to_type;
                param.agile_reference = agile_reference;
                param.unk_obj = &unk_obj.IUnknown_iface;
                param.obj_is_agile = FALSE;
                thread = CreateThread(NULL, 0, test_RoGetAgileReference_thread_proc, &param, 0, NULL);
                flush_events();
                ret = WaitForSingleObject(thread, 100);
                ok(!ret, "WaitForSingleObject failed, error %ld.\n", GetLastError());
            }

            IUnknown_Release(unknown2);
            IUnknown_Release(unknown);
            IAgileReference_Release(agile_reference);
            EXPECT_REF(&unk_obj, 1);

            hr = RoGetAgileReference(option, &IID_IUnknown, &unk_agile_obj.IUnknown_iface, &agile_reference);
            ok(hr == S_OK, "Got unexpected hr %#lx.\n", hr);
            ok(!!agile_reference, "Got unexpected agile_reference.\n");
            EXPECT_REF(&unk_agile_obj, 2);

            unknown = NULL;
            hr = IAgileReference_Resolve(agile_reference, &IID_IUnknown, (void **)&unknown);
            ok(hr == S_OK, "Got unexpected hr %#lx.\n", hr);
            ok(!!unknown, "Expected pointer not NULL.\n");
            ok(unknown == &unk_agile_obj.IUnknown_iface, "Expected the same object.\n");
            EXPECT_REF(&unk_agile_obj, 3);

            for (to_type = RO_INIT_SINGLETHREADED; to_type <= RO_INIT_MULTITHREADED; to_type++)
            {
                param.option = option;
                param.from_type = from_type;
                param.to_type = to_type;
                param.agile_reference = agile_reference;
                param.unk_obj = &unk_agile_obj.IUnknown_iface;
                param.obj_is_agile = TRUE;
                thread = CreateThread(NULL, 0, test_RoGetAgileReference_thread_proc, &param, 0, NULL);
                flush_events();
                ret = WaitForSingleObject(thread, 100);
                ok(!ret, "WaitForSingleObject failed, error %ld.\n", GetLastError());
            }

            IUnknown_Release(unknown);
            IAgileReference_Release(agile_reference);
            EXPECT_REF(&unk_obj, 1);

            RoUninitialize();
            winetest_pop_context();
        }
    }

    /* Tests specific to delayed marshaling */
    for (from_type = RO_INIT_SINGLETHREADED; from_type <= RO_INIT_MULTITHREADED; from_type++)
    {
        winetest_push_context("from_type=%d", from_type);
        hr = RoInitialize(from_type);
        ok(hr == S_OK, "got hr %#lx.\n", hr);

        unknown = unk_ctx_impl_create();
        ok(unknown != NULL, "got unknown %p.\n", unknown);

        unk_ctx_impl = impl_unk_ctx_impl_from_IUnknown(unknown);
        hr = RoGetAgileReference(AGILEREFERENCE_DELAYEDMARSHAL, &IID_IUnknown, unknown, &agile_reference);
        ok(hr == S_OK, "got hr %#lx\n", hr);
        EXPECT_REF(unknown, 2);

        for (to_type = RO_INIT_SINGLETHREADED; to_type <= RO_INIT_MULTITHREADED; to_type++)
        {
            struct test_agile_resolve_context_params params = {from_type, to_type, agile_reference};

            winetest_push_context("to_type=%d", to_type);
            unk_ctx_impl->todo = TRUE;
            thread = CreateThread(NULL, 0, test_agile_resolve_context, &params, 0, NULL);
            flush_events();
            ret = WaitForSingleObject(thread, INFINITE);
            ok(!ret, "got ret %lu\n", ret);
            CloseHandle(thread);
            unk_ctx_impl->todo = FALSE;
            winetest_pop_context();
        }

        IAgileReference_Release(agile_reference);
        EXPECT_REF(unknown, 1);
        IUnknown_Release(unknown);
        RoUninitialize();
        winetest_pop_context();
    }
}

static void test_RoGetErrorReportingFlags(void)
{
    UINT32 flags;
    HRESULT hr;

    hr = RoGetErrorReportingFlags(NULL);
    ok(hr == E_POINTER, "Got unexpected hr %#lx.\n", hr);

    hr = RoGetErrorReportingFlags(&flags);
    ok(hr == S_OK, "Got unexpected hr %#lx.\n", hr);
    ok(flags == RO_ERROR_REPORTING_USESETERRORINFO, "Got unexpected flag %#x.\n", flags);
}

START_TEST(roapi)
{
    char **argv;
    int argc;
    BOOL ret;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 5 && !strcmp(argv[2], "outproc_activation_server"))
    {
        outproc_activation_server(argv[3], argv[4]);
        return;
    }
    if (argc >= 3 && !strcmp(argv[2], "outproc_activation"))
    {
        test_outproc_activation();
        return;
    }
    if (argc >= 3 && !strcmp(argv[2], "shared_service"))
    {
        test_shared_service_ordinals();
        return;
    }
    if (argc >= 3 && !strcmp(argv[2], "context_switcher"))
    {
        test_context_switcher();
        return;
    }

    test_shared_service_ordinals();
    test_context_switcher();
    test_outproc_activation();
    test_extension_catalog();
    test_RoInitializeStrict();
    load_resource(L"wine.combase.test.dll");

    test_implicit_mta();
    test_ActivationFactories();
    test_RoGetAgileReference();
    test_RoGetErrorReportingFlags();

    SetLastError(0xdeadbeef);
    ret = DeleteFileW(L"wine.combase.test.dll");
    todo_wine_if(!ret && GetLastError() == ERROR_ACCESS_DENIED)
    ok(ret, "Failed to delete file, error %lu\n", GetLastError());
}
