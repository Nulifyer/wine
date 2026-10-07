/*
 * Empty font-association configuration queries
 * Copyright 2026 LinuxNT contributors
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1, or any later version.
 */
#include <stdarg.h>
#include "windef.h"
#include "winbase.h"
#include "wingdi.h"
#include "winnls.h"
#include "wine/test.h"

static DWORD (WINAPI *query)(void);
static DWORD (WINAPI *functions[2])(HDC);
static LONG thread_failures;

static DWORD WINAPI worker(void *arg)
{
    DWORD result, error;
    SetLastError(0x12345678);
    result = query(); error = GetLastError();
    if (result || error != 0x12345678) InterlockedIncrement(&thread_failures);
    SetLastError(0x12345678);
    result = functions[1](NULL); error = GetLastError();
    if (result || error != 0x12345678) InterlockedIncrement(&thread_failures);
    return 0;
}

static void check(const char *label, HDC dc, DWORD expected_error)
{
    unsigned int i;
    for (i = 0; i < ARRAY_SIZE(functions); ++i)
    {
        DWORD result, error;
        SetLastError(0x12345678);
        result = functions[i](dc); error = GetLastError();
        ok(!result, "%s entry%u result %#lx\n", label, i, result);
        ok(error == expected_error, "%s entry%u error %lu, expected %lu\n", label, i, error, expected_error);
    }
}

START_TEST(font_association)
{
    HMODULE win32u;
    HDC dc, dead;
    HBITMAP bitmap;
    HANDLE threads[8];
    HFONT font;
    HGDIOBJ old;
    DWORD result, error;
    unsigned int i;
    static const BYTE charsets[] = {ANSI_CHARSET, SYMBOL_CHARSET, OEM_CHARSET, SHIFTJIS_CHARSET,
                                    GB2312_CHARSET, HANGEUL_CHARSET, CHINESEBIG5_CHARSET};

    query = (void *)GetProcAddress(GetModuleHandleW(L"gdi32.dll"), "QueryFontAssocStatus");
    functions[0] = (void *)GetProcAddress(GetModuleHandleW(L"gdi32.dll"), "GetFontAssocStatus");
    win32u = LoadLibraryW(L"win32u.dll");
    functions[1] = win32u ? (void *)GetProcAddress(win32u, "NtGdiQueryFontAssocInfo") : NULL;
    if (!query || !functions[0] || !functions[1])
    {
        win_skip("Font association entrypoints unavailable\n");
        if (win32u) FreeLibrary(win32u);
        return;
    }
    if (GetACP() != 1252)
    {
        skip("Empty English font-association reference requires ACP1252\n");
        FreeLibrary(win32u);
        return;
    }
    for (i = 0; i < ARRAY_SIZE(threads); ++i)
    {
        threads[i] = CreateThread(NULL, 0, worker, NULL, 0, NULL);
        ok(!!threads[i], "Worker %u creation failed\n", i);
    }
    for (i = 0; i < ARRAY_SIZE(threads); ++i)
    {
        if (!threads[i]) continue;
        ok(WaitForSingleObject(threads[i], 10000) == WAIT_OBJECT_0, "Worker %u did not complete\n", i);
        CloseHandle(threads[i]);
    }
    ok(!thread_failures, "Concurrent global initialization failures %ld\n", thread_failures);
    SetLastError(0x12345678);
    result = query(); error = GetLastError();
    ok(!result, "Global result %#lx\n", result);
    ok(error == 0x12345678, "Global error %lu\n", error);
    check("null", NULL, 0x12345678);
    check("invalid", (HDC)0x12345678, ERROR_INVALID_HANDLE);
    dc = CreateCompatibleDC(NULL);
    ok(!!dc, "DC creation failed\n");
    if (!dc) goto done;
    check("default", dc, 0x12345678);
    for (i = 0; i < ARRAY_SIZE(charsets); ++i)
    {
        font = CreateFontW(18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, charsets[i],
                           OUT_DEFAULT_PRECIS, 0, DEFAULT_QUALITY, DEFAULT_PITCH, L"Arial");
        ok(!!font, "Font %u creation failed\n", i);
        if (!font) continue;
        old = SelectObject(dc, font);
        ok(old && old != HGDI_ERROR, "Font %u selection failed\n", i);
        check("selected", dc, 0x12345678);
        if (old && old != HGDI_ERROR) SelectObject(dc, old);
        DeleteObject(font);
    }
    dead = CreateCompatibleDC(NULL);
    ok(!!dead, "Second DC creation failed\n");
    if (dead) { DeleteDC(dead); check("destroyed", dead, ERROR_INVALID_HANDLE); }
    bitmap = CreateBitmap(1, 1, 1, 1, NULL);
    ok(!!bitmap, "Bitmap creation failed\n");
    if (bitmap) { check("wrong-type", (HDC)bitmap, ERROR_INVALID_HANDLE); DeleteObject(bitmap); }
    DeleteDC(dc);
done:
    FreeLibrary(win32u);
}
