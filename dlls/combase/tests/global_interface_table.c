/*
 * Global Interface Table ownership tests
 *
 * Copyright 2026 Nulifyer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>

#define COBJMACROS
#include "windef.h"
#include "winbase.h"
#include "objbase.h"

#include "wine/test.h"

typedef HRESULT (WINAPI *dll_get_class_object_fn)(REFCLSID, REFIID, void **);

static IClassFactory *get_factory(const WCHAR *module_name)
{
    dll_get_class_object_fn get_class_object;
    IClassFactory *factory = NULL;
    HMODULE module;
    HRESULT hr;

    module = GetModuleHandleW(module_name);
    ok(!!module, "%s is not loaded.\n", wine_dbgstr_w(module_name));
    if (!module) return NULL;

    get_class_object = (void *)GetProcAddress(module, "DllGetClassObject");
    ok(!!get_class_object, "%s has no DllGetClassObject export.\n", wine_dbgstr_w(module_name));
    if (!get_class_object) return NULL;

    hr = get_class_object(&CLSID_StdGlobalInterfaceTable, &IID_IClassFactory, (void **)&factory);
    ok(hr == S_OK, "%s DllGetClassObject returned %#lx.\n", wine_dbgstr_w(module_name), hr);
    ok(!!factory, "%s returned a NULL class factory.\n", wine_dbgstr_w(module_name));
    return factory;
}

static IGlobalInterfaceTable *create_from_factory(IClassFactory *factory)
{
    IGlobalInterfaceTable *git = NULL;
    HRESULT hr;

    if (!factory) return NULL;
    hr = IClassFactory_CreateInstance(factory, NULL, &IID_IGlobalInterfaceTable, (void **)&git);
    ok(hr == S_OK, "IClassFactory::CreateInstance returned %#lx.\n", hr);
    ok(!!git, "IClassFactory::CreateInstance returned NULL.\n");
    return git;
}

static void test_process_singleton(void)
{
    IGlobalInterfaceTable *combase_git, *ole32_git, *cocreate_git = NULL;
    IClassFactory *combase_factory, *ole32_factory;
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(hr == S_OK, "CoInitializeEx returned %#lx.\n", hr);
    if (FAILED(hr)) return;

    combase_factory = get_factory(L"combase.dll");
    ole32_factory = get_factory(L"ole32.dll");
    combase_git = create_from_factory(combase_factory);
    ole32_git = create_from_factory(ole32_factory);

    hr = CoCreateInstance(&CLSID_StdGlobalInterfaceTable, NULL, CLSCTX_INPROC_SERVER,
            &IID_IGlobalInterfaceTable, (void **)&cocreate_git);
    ok(hr == S_OK, "CoCreateInstance returned %#lx.\n", hr);
    ok(!!cocreate_git, "CoCreateInstance returned NULL.\n");

    if (combase_git && ole32_git)
        ok(combase_git == ole32_git, "combase returned %p, but ole32 returned %p.\n", combase_git, ole32_git);
    if (combase_git && cocreate_git)
        ok(combase_git == cocreate_git, "combase returned %p, but CoCreateInstance returned %p.\n",
                combase_git, cocreate_git);

    if (cocreate_git) IGlobalInterfaceTable_Release(cocreate_git);
    if (ole32_git) IGlobalInterfaceTable_Release(ole32_git);
    if (combase_git) IGlobalInterfaceTable_Release(combase_git);
    if (ole32_factory) IClassFactory_Release(ole32_factory);
    if (combase_factory) IClassFactory_Release(combase_factory);
    CoUninitialize();
}

START_TEST(global_interface_table)
{
    test_process_singleton();
}
