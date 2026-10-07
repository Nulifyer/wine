/*
 * Modern AppCompat Cdb lookup tests
 * Copyright 2026 LinuxNT contributors
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1, or any later version.
 */
#include <stdarg.h>
#include <stdio.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "wine/test.h"

/* Matched x64 AppHelp CompatCachepLookupCdb packet, not an SDK type. */
struct cdb_packet
{
    BYTE prefix[0xf8];
    UNICODE_STRING name;
    BYTE reserved[0x70];
    void *data;
    ULONG data_size;
    ULONG tail;
};
C_ASSERT(sizeof(void *) != 8 || sizeof(struct cdb_packet) == 0x188);
C_ASSERT(sizeof(void *) != 8 || offsetof(struct cdb_packet, name) == 0xf8);
C_ASSERT(sizeof(void *) != 8 || offsetof(struct cdb_packet, data) == 0x178);
C_ASSERT(sizeof(void *) != 8 || offsetof(struct cdb_packet, data_size) == 0x180);
static NTSTATUS (WINAPI *cache_control)(ULONG, void *);
static NTSTATUS expected_status;

static void run(const char *label, ULONG service, void *context, struct cdb_packet *packet, ULONG *output)
{
    struct cdb_packet before;
    NTSTATUS status;
    DWORD error;
    if (packet) before = *packet;
    *output = 0x12345678;
    SetLastError(0x87654321);
    status = cache_control(service, context);
    error = GetLastError();
    ok(status == expected_status, "%s: status %#lx, expected %#lx\n", label, status, expected_status);
    ok(error == 0x87654321, "%s: error %#lx\n", label, error);
    ok(*output == (status == STATUS_SUCCESS ? 0 : 0x12345678), "%s: output %#lx\n", label, *output);
    if (packet) ok(!memcmp(&before, packet, sizeof(before)), "%s: input packet changed\n", label);
}

START_TEST(appcompat)
{
    static const WCHAR *names[] = {L"", L"linuxnt-absent-cdb-1234.dll", L"shell32.dll", L"explorer.exe", L"SHELL32.DLL", L"C:\\Windows\\System32\\shell32.dll"};
    static const char *labels[] = {"empty", "absent", "shell32", "explorer", "uppercase", "full-path"};
    struct cdb_packet p;
    ULONG output, size;
    unsigned i;
    BYTE *page;
    cache_control = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtApphelpCacheControl");
    if (!cache_control || sizeof(void *) != 8)
    {
        win_skip("Modern x64 cache control unavailable\n");
        return;
    }
    memset(&p, 0, sizeof(p));
    expected_status = STATUS_ACCESS_VIOLATION;
    run("null-context", 6, NULL, NULL, &output);
    expected_status = STATUS_DATATYPE_MISALIGNMENT;
    run("invalid-context", 6, (void *)1, NULL, &output);
    expected_status = STATUS_INVALID_PARAMETER;
    run("zero-packet", 6, &p, &p, &output);
    for (i = 0; i < ARRAY_SIZE(names); ++i)
    {
        memset(&p, 0, sizeof(p));
        p.name.Buffer = (WCHAR *)names[i];
        p.name.Length = lstrlenW(names[i]) * 2;
        p.name.MaximumLength = p.name.Length + 2;
        p.data = &output;
        p.data_size = 4;
        expected_status = i ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
        run(labels[i], 6, &p, &p, &output);
        run(labels[i], 6, &p, &p, &output);
    }
    memset(&p, 0, sizeof(p));
    p.name.Buffer = (WCHAR *)names[2];
    p.name.Length = lstrlenW(names[2]) * 2;
    p.name.MaximumLength = p.name.Length + 2;
    p.data = &output;
    for (size = 0; size <= 8; ++size)
    {
        char label[32];
        expected_status = size == 4 ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
        p.data_size = size;
        sprintf(label, "size-%lu", size);
        run(label, 6, &p, &p, &output);
    }
    expected_status = STATUS_INVALID_PARAMETER;
    p.data_size = 4;
    p.data = NULL;
    run("null-output", 6, &p, &p, &output);
    expected_status = STATUS_DATATYPE_MISALIGNMENT;
    p.data = (void *)1;
    run("invalid-output", 6, &p, &p, &output);
    expected_status = STATUS_INVALID_PARAMETER;
    p.data = &output;
    p.name.Buffer = NULL;
    run("null-name", 6, &p, &p, &output);
    expected_status = STATUS_ACCESS_VIOLATION;
    p.name.Buffer = (void *)1;
    run("invalid-name", 6, &p, &p, &output);
    expected_status = STATUS_SUCCESS;
    p.name.Buffer = (WCHAR *)names[2];
    p.name.Length = 3;
    run("odd-name-length", 6, &p, &p, &output);
    p.name.Length = 20;
    p.name.MaximumLength = 0;
    run("short-max-length", 6, &p, &p, &output);
    page = VirtualAlloc(NULL, 0x2000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    ok(!!page, "Page allocation failed\n");
    if (!page) return;
    expected_status = STATUS_DATATYPE_MISALIGNMENT;
    memcpy(page + 1, &p, sizeof(p));
    run("unaligned-context", 6, page + 1, NULL, &output);
    expected_status = STATUS_ACCESS_VIOLATION;
    VirtualProtect(page, 0x1000, PAGE_NOACCESS, &size);
    run("inaccessible-context", 6, page, NULL, &output);
    VirtualFree(page, 0, MEM_RELEASE);
    expected_status = STATUS_INVALID_PARAMETER;
    run("unknown-class-null", 0xffffffff, NULL, NULL, &output);
    run("unknown-class-invalid", 0xffffffff, (void *)1, NULL, &output);
    run("class-14-null", 14, NULL, NULL, &output);
}
