/* Globalization key selection, null-context partition.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */
#include <stdarg.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "wincon.h"
#include "winreg.h"
#include "winternl.h"
#include "wine/test.h"

static NTSTATUS (WINAPI *open_settings)(ACCESS_MASK, const void *, HANDLE *);
static NTSTATUS (WINAPI *open_current)(ACCESS_MASK, HANDLE *);
static NTSTATUS (WINAPI *query_key)(HANDLE, KEY_INFORMATION_CLASS, void *, ULONG, ULONG *);
static NTSTATUS (WINAPI *close_key)(HANDLE);

START_TEST(globalization_key)
{
    static const ACCESS_MASK masks[] = {KEY_READ, KEY_QUERY_VALUE, 0};
    BYTE expected_buffer[2048], actual_buffer[2048];
    KEY_NAME_INFORMATION *expected = (void *)expected_buffer, *actual = (void *)actual_buffer;
    HMODULE base = GetModuleHandleA("kernelbase.dll"), nt = GetModuleHandleA("ntdll.dll");
    HANDLE current, settings, second;
    NTSTATUS status;
    ULONG length;
    unsigned int i;

    open_settings = (void *)GetProcAddress(base, "OpenGlobalizationUserSettingsKey");
    open_current = (void *)GetProcAddress(nt, "RtlOpenCurrentUser");
    query_key = (void *)GetProcAddress(nt, "NtQueryKey");
    close_key = (void *)GetProcAddress(nt, "NtClose");
    ok(open_settings && open_current && query_key && close_key, "Required exports missing.\n");
    if (!open_settings || !open_current || !query_key || !close_key) return;
    status = open_current(KEY_READ, &current);
    ok(status == STATUS_SUCCESS, "Open current user returned %#lx.\n", status);
    if (status) return;
    status = query_key(current, KeyNameInformation, expected, sizeof(expected_buffer), &length);
    ok(status == STATUS_SUCCESS, "Query current user returned %#lx.\n", status);
    if (status) { close_key(current); return; }

    for (i = 0; i < ARRAY_SIZE(masks); ++i)
    {
        winetest_push_context("access=%#lx", masks[i]);
        settings = (HANDLE)(ULONG_PTR)0xdeadbeef;
        SetLastError(0x12345678);
        status = open_settings(masks[i], NULL, &settings);
        ok(status == (masks[i] ? STATUS_SUCCESS : STATUS_ACCESS_DENIED), "Unexpected status %#lx.\n", status);
        ok(GetLastError() == 0x12345678, "Last error changed to %#lx.\n", GetLastError());
        if (!masks[i]) ok(!settings, "Failure did not clear output, %p.\n", settings);
        else if (!status && settings && settings != (HANDLE)(ULONG_PTR)0xdeadbeef)
        {
            ok(settings != current, "Did not return an independent handle.\n");
            status = query_key(settings, KeyNameInformation, actual, sizeof(actual_buffer), &length);
            ok(status == STATUS_SUCCESS, "Query settings returned %#lx.\n", status);
            if (!status)
            {
                ok(actual->NameLength == expected->NameLength, "Key name lengths differ, %lu vs %lu.\n",
                   actual->NameLength, expected->NameLength);
                ok(actual->NameLength == expected->NameLength &&
                   !memcmp(actual->Name, expected->Name, expected->NameLength), "Settings key is not the current user root.\n");
            }
            second = NULL;
            status = open_settings(masks[i], NULL, &second);
            ok(status == STATUS_SUCCESS, "Second open returned %#lx.\n", status);
            ok(second != settings, "Repeated open reused live handle.\n");
            ok(close_key(settings) == STATUS_SUCCESS, "Close failed.\n");
            if (!status)
            {
                status = query_key(second, KeyNameInformation, actual, sizeof(actual_buffer), &length);
                ok(status == STATUS_SUCCESS, "Closing first handle invalidated second, %#lx.\n", status);
                ok(close_key(second) == STATUS_SUCCESS, "Second close failed.\n");
            }
        }
        else ok(FALSE, "Missing valid settings handle.\n");
        winetest_pop_context();
    }
    ok(close_key(current) == STATUS_SUCCESS, "Current-user close failed.\n");
}
