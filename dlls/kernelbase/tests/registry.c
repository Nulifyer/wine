/*
 * KernelBase registry tests
 *
 * Copyright 2026
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>

#include <windef.h>
#include <winbase.h>
#include <winerror.h>
#include <winreg.h>

#include "wine/test.h"

static LSTATUS (WINAPI *pMapPredefinedHandleInternal)(HKEY, HKEY *, HKEY *, void **);
static void (WINAPI *pCLOSE_LOCAL_HANDLE_INTERNAL)(HKEY, void *);
static DWORD (WINAPI *pRegKrnGetTermsrvRegistryExtensionFlags)(void);
static void (WINAPI *pRegKrnSetTermsrvRegistryExtensionFlags)(DWORD);
static LSTATUS (WINAPI *pRegQueryMultipleValuesW)(HKEY, PVALENTW, DWORD, WCHAR *, DWORD *);

static void test_map_predefined_handle(void)
{
    HKEY key, mapped, close;
    void *cache_entry;
    LSTATUS status;

    mapped = (HKEY)0xdeadbeef;
    close = (HKEY)0xdeadbeef;
    cache_entry = (void *)0xdeadbeef;
    status = pMapPredefinedHandleInternal(NULL, &mapped, &close, &cache_entry);
    ok(status == ERROR_INVALID_HANDLE, "got status %ld\n", status);
    ok(mapped == (HKEY)0xdeadbeef, "mapped handle changed to %p\n", mapped);
    ok(!close, "got close handle %p\n", close);
    ok(!cache_entry, "got cache entry %p\n", cache_entry);

    status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software", 0, KEY_READ, &key);
    ok(!status, "failed to open HKLM\\Software, status %ld\n", status);
    if (status) return;

    mapped = NULL;
    close = (HKEY)0xdeadbeef;
    cache_entry = (void *)0xdeadbeef;
    status = pMapPredefinedHandleInternal(key, &mapped, &close, &cache_entry);
    ok(!status, "got status %ld\n", status);
    ok(mapped == key, "expected %p, got %p\n", key, mapped);
    ok(!close, "got close handle %p\n", close);
    ok(!cache_entry, "got cache entry %p\n", cache_entry);
    pCLOSE_LOCAL_HANDLE_INTERNAL(close, cache_entry);
    RegCloseKey(key);

    mapped = NULL;
    close = (HKEY)0xdeadbeef;
    cache_entry = (void *)0xdeadbeef;
    status = pMapPredefinedHandleInternal(HKEY_LOCAL_MACHINE, &mapped, &close, &cache_entry);
    ok(!status, "got status %ld\n", status);
    ok(mapped && mapped != HKEY_LOCAL_MACHINE, "got mapped handle %p\n", mapped);
    ok(!cache_entry, "got cache entry %p\n", cache_entry);
    pCLOSE_LOCAL_HANDLE_INTERNAL(close, cache_entry);
}

static void test_termsrv_registry_extension_flags(void)
{
    DWORD old = pRegKrnGetTermsrvRegistryExtensionFlags();

    pRegKrnSetTermsrvRegistryExtensionFlags(0xa5a55a5a);
    ok(pRegKrnGetTermsrvRegistryExtensionFlags() == 0xa5a55a5a,
       "registry extension flags were not preserved\n");
    pRegKrnSetTermsrvRegistryExtensionFlags(old);
}

static void test_query_multiple_values(void)
{
    static const WCHAR path[] = L"Software\\Wine\\Tests\\KernelBase";
    static const WCHAR dword_name[] = L"MultipleDword";
    static const WCHAR string_name[] = L"MultipleString";
    static const WCHAR string_value[] = L"value";
    VALENTW values[2] = {{0}};
    BYTE buffer[64];
    DWORD dword = 0x12345678, size;
    HKEY key;
    LSTATUS status;

    status = RegCreateKeyExW(HKEY_CURRENT_USER, path, 0, NULL, 0, KEY_ALL_ACCESS,
                             NULL, &key, NULL);
    ok(!status, "failed to create test key, status %ld\n", status);
    if (status) return;

    status = RegSetValueExW(key, dword_name, 0, REG_DWORD, (BYTE *)&dword, sizeof(dword));
    ok(!status, "failed to set DWORD value, status %ld\n", status);
    status = RegSetValueExW(key, string_name, 0, REG_SZ, (BYTE *)string_value, sizeof(string_value));
    ok(!status, "failed to set string value, status %ld\n", status);

    values[0].ve_valuename = (WCHAR *)dword_name;
    values[1].ve_valuename = (WCHAR *)string_name;
    size = 0;
    status = pRegQueryMultipleValuesW(key, values, ARRAY_SIZE(values), NULL, &size);
    ok(status == ERROR_MORE_DATA, "got status %ld\n", status);
    ok(size == sizeof(dword) + sizeof(string_value), "got required size %lu\n", size);

    memset(buffer, 0xcc, sizeof(buffer));
    size = sizeof(buffer);
    status = pRegQueryMultipleValuesW(key, values, ARRAY_SIZE(values), (WCHAR *)buffer, &size);
    ok(!status, "got status %ld\n", status);
    ok(size == sizeof(dword) + sizeof(string_value), "got size %lu\n", size);
    ok(values[0].ve_type == REG_DWORD, "got first type %lu\n", values[0].ve_type);
    ok(values[0].ve_valuelen == sizeof(dword), "got first length %lu\n", values[0].ve_valuelen);
    ok(values[0].ve_valueptr == (DWORD_PTR)buffer, "got first value pointer %Ix\n",
       values[0].ve_valueptr);
    ok(*(DWORD *)buffer == dword, "got DWORD %#lx\n", *(DWORD *)buffer);
    ok(values[1].ve_type == REG_SZ, "got second type %lu\n", values[1].ve_type);
    ok(values[1].ve_valuelen == sizeof(string_value), "got second length %lu\n",
       values[1].ve_valuelen);
    ok(values[1].ve_valueptr == (DWORD_PTR)(buffer + sizeof(dword)),
       "got second value pointer %Ix\n", values[1].ve_valueptr);
    ok(!lstrcmpW((WCHAR *)(buffer + sizeof(dword)), string_value), "got string %s\n",
       wine_dbgstr_w((WCHAR *)(buffer + sizeof(dword))));

    RegCloseKey(key);
    RegDeleteKeyW(HKEY_CURRENT_USER, path);
}

START_TEST(registry)
{
    HMODULE module = GetModuleHandleA("kernelbase.dll");

    pMapPredefinedHandleInternal = (void *)GetProcAddress(module, "MapPredefinedHandleInternal");
    pCLOSE_LOCAL_HANDLE_INTERNAL = (void *)GetProcAddress(module, "CLOSE_LOCAL_HANDLE_INTERNAL");
    pRegKrnGetTermsrvRegistryExtensionFlags = (void *)GetProcAddress(module,
            "RegKrnGetTermsrvRegistryExtensionFlags");
    pRegKrnSetTermsrvRegistryExtensionFlags = (void *)GetProcAddress(module,
            "RegKrnSetTermsrvRegistryExtensionFlags");
    pRegQueryMultipleValuesW = (void *)GetProcAddress(module, "RegQueryMultipleValuesW");
    if (!pMapPredefinedHandleInternal || !pCLOSE_LOCAL_HANDLE_INTERNAL ||
        !pRegKrnGetTermsrvRegistryExtensionFlags || !pRegKrnSetTermsrvRegistryExtensionFlags)
    {
        win_skip("Predefined-handle internal exports are unavailable.\n");
        return;
    }

    test_map_predefined_handle();
    test_termsrv_registry_extension_flags();
    if (pRegQueryMultipleValuesW) test_query_multiple_values();
    else win_skip("RegQueryMultipleValuesW is unavailable.\n");
}
