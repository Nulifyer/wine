/* Session launch configuration queries.
 *
 * Copyright 2026 Nulifyer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */
#include <stdarg.h>
#include <string.h>
#include "windef.h"
#include "winbase.h"
#include "winnls.h"
#include "wtsapi32.h"
#include "wine/test.h"

/* MS-TSTS WINSTATIONCONFIG, with the queried USERCONFIG string fields exposed.
 * The x64 source-image WTS adapter corroborates these offsets and capacity. */
struct station_config
{
    BYTE prefix[0xf0];
    WCHAR working_directory[257];
    WCHAR initial_program[257];
    BYTE remainder[0xa68 - 0x4f4];
};
C_ASSERT(sizeof(struct station_config) == 0xa68);
C_ASSERT(FIELD_OFFSET(struct station_config, working_directory) == 0xf0);
C_ASSERT(FIELD_OFFSET(struct station_config, initial_program) == 0x2f2);

static BOOLEAN (WINAPI *query_station)(HANDLE, ULONG, ULONG, void *, ULONG, ULONG *);

static void test_config(DWORD session, WTS_INFO_CLASS class)
{
    struct station_config config = {0};
    WCHAR *buffer, *expected;
    char *buffer_a, expected_a[1028];
    DWORD count, error, expected_count;
    ULONG station_count = 0;
    BOOL control, ret;

    winetest_push_context("session %lu class %u", session, class);
    SetLastError(0xdeadbeef);
    control = query_station(NULL, session, 1, &config, sizeof(config), &station_count);
    error = GetLastError();
    trace("WINSTA configuration control ret %d error %lu bytes %lu.\n", control, error, station_count);
    if (control && class == WTSInitialProgram && !session)
    {
        control = FALSE;
        error = ERROR_INVALID_PARAMETER;
    }
    expected = class == WTSInitialProgram ? config.initial_program : config.working_directory;
    count = 0xdeadbeef;
    buffer = (void *)0xdeadbeef;
    SetLastError(0xdeadbeef);
    ret = WTSQuerySessionInformationW(NULL, session, class, &buffer, &count);
    ok(ret == control, "W query returned %d, expected %d.\n", ret, control);
    if (!control)
    {
        ok(GetLastError() == error, "W query error %lu, expected %lu.\n", GetLastError(), error);
        ok(buffer == (void *)0xdeadbeef, "Failed W query changed output.\n");
        ok(count == 0xdeadbeef, "Failed W query changed count to %lu.\n", count);
    }
    else if (ret)
    {
        expected_count = (lstrlenW(expected) + 1) * sizeof(WCHAR);
        ok(count == expected_count, "W query bytes %lu, expected %lu.\n", count, expected_count);
        ok(buffer && !lstrcmpW(buffer, expected), "W query does not preserve session configuration.\n");
        trace("W session configuration %s, bytes %lu.\n", wine_dbgstr_w(buffer), count);
    }
    if (ret) WTSFreeMemory(buffer);

    count = 0xdeadbeef;
    buffer_a = (void *)0xdeadbeef;
    SetLastError(0xdeadbeef);
    ret = WTSQuerySessionInformationA(NULL, session, class, &buffer_a, &count);
    ok(ret == control, "A query returned %d, expected %d.\n", ret, control);
    if (!control)
    {
        ok(GetLastError() == error, "A query error %lu, expected %lu.\n", GetLastError(), error);
        ok(buffer_a == (void *)0xdeadbeef, "Failed A query changed output.\n");
        ok(count == 0xdeadbeef, "Failed A query changed count to %lu.\n", count);
    }
    else if (ret)
    {
        expected_count = WideCharToMultiByte(CP_ACP, 0, expected, -1, expected_a, sizeof(expected_a), NULL, NULL);
        ok(count == expected_count, "A query bytes %lu, expected %lu.\n", count, expected_count);
        ok(buffer_a && !lstrcmpA(buffer_a, expected_a), "A query does not preserve session configuration.\n");
    }
    if (ret) WTSFreeMemory(buffer_a);
    winetest_pop_context();
}

static void test_arguments(void)
{
    WCHAR *buffer = (void *)0xdeadbeef;
    DWORD count = 0xdeadbeef;
    BOOL ret;

    SetLastError(0xdeadbeef);
    ret = WTSQuerySessionInformationW(NULL, WTS_CURRENT_SESSION, WTSInitialProgram, NULL, &count);
    ok(!ret && GetLastError() == ERROR_INVALID_USER_BUFFER, "Missing output ret %d error %lu.\n", ret, GetLastError());
    ok(count == 0xdeadbeef, "Missing output changed count.\n");
    SetLastError(0xdeadbeef);
    ret = WTSQuerySessionInformationW(NULL, WTS_CURRENT_SESSION, WTSInitialProgram, &buffer, NULL);
    ok(!ret && GetLastError() == ERROR_INVALID_USER_BUFFER, "Missing count ret %d error %lu.\n", ret, GetLastError());
    ok(buffer == (void *)0xdeadbeef, "Missing count changed output.\n");
}

static struct station_config payload;
static DWORD payload_error, payload_size, payload_calls;

static BOOLEAN WINAPI query_payload(HANDLE server, ULONG session, ULONG class, void *buffer, ULONG size, ULONG *count)
{
    ++payload_calls;
    ok(!server && session == WTS_CURRENT_SESSION && class == 1 && size == sizeof(payload),
       "Configuration owner received %p %lu %lu %lu.\n", server, session, class, size);
    if (payload_error)
    {
        SetLastError(payload_error);
        return FALSE;
    }
    memcpy(buffer, &payload, sizeof(payload));
    *count = payload_size;
    return TRUE;
}

/* Substitute the imported configuration owner in this single-threaded fixture.
 * Production still calls WINSTA; no fixture callback enters the runtime. */
static void **configuration_import(void)
{
    BYTE *base = (BYTE *)GetModuleHandleW(L"wtsapi32.dll");
    IMAGE_DOS_HEADER *dos = (void *)base;
    IMAGE_NT_HEADERS *nt = (void *)(base + dos->e_lfanew);
    IMAGE_IMPORT_DESCRIPTOR *import;
    IMAGE_THUNK_DATA *name, *slot;

    if (!nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) return NULL;
    import = (void *)(base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    for (; import->Name; ++import)
    {
        if (lstrcmpiA((char *)base + import->Name, "winsta.dll") || !import->OriginalFirstThunk) continue;
        name = (void *)(base + import->OriginalFirstThunk);
        slot = (void *)(base + import->FirstThunk);
        for (; name->u1.AddressOfData; ++name, ++slot)
        {
            IMAGE_IMPORT_BY_NAME *entry;
            if (IMAGE_SNAP_BY_ORDINAL(name->u1.Ordinal)) continue;
            entry = (void *)(base + name->u1.AddressOfData);
            if (!lstrcmpA((char *)entry->Name, "WinStationQueryInformationW")) return (void **)&slot->u1.Function;
        }
    }
    return NULL;
}

static void test_payload(WTS_INFO_CLASS class, const WCHAR *expected)
{
    WCHAR *first, *second;
    char *ansi, expected_a[1028];
    DWORD count, count_a, size, calls = payload_calls;
    BOOL ret;

    ret = WTSQuerySessionInformationW(NULL, WTS_CURRENT_SESSION, class, &first, &count);
    ok(ret, "Payload W query failed, error %lu.\n", GetLastError());
    if (!ret) return;
    size = (lstrlenW(expected) + 1) * sizeof(WCHAR);
    ok(count == size && !lstrcmpW(first, expected), "Payload W string/count changed.\n");
    ret = WTSQuerySessionInformationW(NULL, WTS_CURRENT_SESSION, class, &second, &count);
    ok(ret, "Second payload W query failed.\n");
    if (ret)
    {
        ok(first != second, "Query allocations alias.\n");
        first[0] ^= 1;
        ok(!lstrcmpW(second, expected), "Caller mutation changed another query.\n");
        WTSFreeMemory(second);
    }
    WTSFreeMemory(first);
    ret = WTSQuerySessionInformationA(NULL, WTS_CURRENT_SESSION, class, &ansi, &count_a);
    ok(ret, "Payload A query failed, error %lu.\n", GetLastError());
    if (ret)
    {
        size = WideCharToMultiByte(CP_ACP, 0, expected, -1, expected_a, sizeof(expected_a), NULL, NULL);
        ok(count_a == size && !lstrcmpA(ansi, expected_a), "Payload A string/count changed.\n");
        WTSFreeMemory(ansi);
    }
    ok(payload_calls == calls + 3, "Query bypassed the configuration owner.\n");
}

static void test_controlled_owner(void)
{
    void **slot = configuration_import(), *original;
    WCHAR *buffer;
    DWORD old_protect, unused, count, calls;
    BOOL ret;
    unsigned int i;

    if (!slot && strcmp(winetest_platform, "wine"))
    {
        win_skip("No directly imported WINSTA configuration seam.\n");
        return;
    }
    ok(!!slot, "No imported WINSTA configuration owner.\n");
    if (!slot) return;
    ret = VirtualProtect(slot, sizeof(*slot), PAGE_READWRITE, &old_protect);
    ok(ret, "Cannot substitute configuration owner, error %lu.\n", GetLastError());
    if (!ret) return;
    original = *slot;
    *slot = query_payload;
    payload_size = sizeof(payload);
    lstrcpyW(payload.initial_program, L"C:\\Program Files\\配置\\app.exe");
    lstrcpyW(payload.working_directory, L"C:\\Users\\Alice");
    test_payload(WTSInitialProgram, payload.initial_program);
    test_payload(WTSWorkingDirectory, payload.working_directory);
    payload.initial_program[0] = payload.working_directory[0] = 0;
    payload_size = 0;
    test_payload(WTSInitialProgram, L"");
    test_payload(WTSWorkingDirectory, L"");
    for (i = 0; i < 256; ++i) payload.initial_program[i] = 'x';
    payload.initial_program[256] = 0;
    payload_size = sizeof(payload);
    test_payload(WTSInitialProgram, payload.initial_program);
    payload_error = ERROR_ACCESS_DENIED;
    buffer = (void *)0xdeadbeef;
    count = 0xdeadbeef;
    ret = WTSQuerySessionInformationW(NULL, WTS_CURRENT_SESSION, WTSInitialProgram, &buffer, &count);
    ok(!ret && GetLastError() == ERROR_ACCESS_DENIED, "Owner failure lost, ret %d error %lu.\n", ret, GetLastError());
    ok(buffer == (void *)0xdeadbeef && count == 0xdeadbeef, "Owner failure changed outputs.\n");
    payload_error = 0;
    payload_size = sizeof(payload) + 1;
    ret = WTSQuerySessionInformationW(NULL, WTS_CURRENT_SESSION, WTSInitialProgram, &buffer, &count);
    ok(!ret && GetLastError() == ERROR_INVALID_DATA, "Oversized owner record accepted.\n");
    ok(buffer == (void *)0xdeadbeef && count == 0xdeadbeef, "Oversized record changed outputs.\n");
    payload_size = sizeof(payload);
    payload.initial_program[256] = 'x';
    ret = WTSQuerySessionInformationW(NULL, WTS_CURRENT_SESSION, WTSInitialProgram, &buffer, &count);
    ok(!ret && GetLastError() == ERROR_INVALID_DATA, "Unterminated owner string accepted.\n");
    ok(buffer == (void *)0xdeadbeef && count == 0xdeadbeef, "Malformed string changed outputs.\n");
    calls = payload_calls;
    ret = WTSQuerySessionInformationW((HANDLE)1, WTS_CURRENT_SESSION, WTSInitialProgram, &buffer, &count);
    ok(!ret && GetLastError() == ERROR_NOT_SUPPORTED, "Unrepresented server accepted.\n");
    ok(payload_calls == calls, "Unrepresented server reached the owner.\n");
    ok(buffer == (void *)0xdeadbeef && count == 0xdeadbeef, "Unrepresented server changed outputs.\n");
    *slot = original;
    VirtualProtect(slot, sizeof(*slot), old_protect, &unused);
}

START_TEST(session_config)
{
    static const WTS_INFO_CLASS classes[] = {WTSInitialProgram, WTSWorkingDirectory};
    HMODULE module = LoadLibraryW(L"winsta.dll");
    DWORD sessions[] = {WTS_CURRENT_SESSION, 0, 0};
    unsigned int i, j;

    ok(!!module, "WINSTA owner failed to load, error %lu.\n", GetLastError());
    if (!module) return;
    query_station = (void *)GetProcAddress(module, "WinStationQueryInformationW");
    ok(!!query_station, "WINSTA query missing, error %lu.\n", GetLastError());
    if (!query_station) goto done;
    test_arguments();
    ok(ProcessIdToSessionId(GetCurrentProcessId(), &sessions[1]), "Process session unavailable.\n");
    for (i = 0; i < ARRAY_SIZE(sessions); ++i)
        for (j = 0; j < ARRAY_SIZE(classes); ++j) test_config(sessions[i], classes[j]);
    test_controlled_owner();
done:
    FreeLibrary(module);
}
