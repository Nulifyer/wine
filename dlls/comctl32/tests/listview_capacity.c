/* Tests for the private list-view capacity queries.
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#define USE_COMPILER_EXCEPTIONS
#include <windows.h>
#include <commctrl.h>
#include <objbase.h>
#include "wine/test.h"
#include "wine/exception.h"
#include "v6util.h"

#define LVM_QUERYINTERFACE (LVM_FIRST + 189)
#define SENTINEL 0x12345678

static const IID listview_iid =
    {0xe5b16af2,0x3990,0x4681,{0xa6,0x09,0x1f,0x06,0x0c,0xd1,0x42,0x69}};
typedef HRESULT (WINAPI *capacity_fn)(IUnknown *, INT *);
static HWND child;
static BOOL destroy_on_measure;

static LRESULT CALLBACK parent_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
{
    if (message == WM_MEASUREITEM)
    {
        ((MEASUREITEMSTRUCT *)lparam)->itemHeight = 20;
        if (destroy_on_measure)
        {
            destroy_on_measure = FALSE;
            DestroyWindow(child);
        }
        return TRUE;
    }
    return DefWindowProcW(hwnd, message, wparam, lparam);
}

static void check_capacity(IUnknown *iface, UINT slot, HRESULT expected_hr, INT expected_count)
{
    const void *const *table = *(const void *const **)iface;
    INT count = -123456;
    HRESULT hr;

    SetLastError(SENTINEL);
    hr = ((capacity_fn)table[slot])(iface, &count);
    ok(hr == expected_hr, "Slot %u returned %#lx, expected %#lx.\n", slot, hr, expected_hr);
    ok(count == expected_count, "Slot %u count %d, expected %d.\n", slot, count, expected_count);
    ok(GetLastError() == SENTINEL, "Slot %u changed last error to %lu.\n", slot, GetLastError());
}

static void test_capacity(HWND parent, UINT view)
{
    static const struct {INT width, height, capacity;} sizes[] =
        {{0,0,9},{1,1,9},{60,70,9},{120,140,16},{240,280,36}};
    const void *const *table;
    IUnknown *iface = NULL;
    LVITEMW item = {0};
    UINT i, slot;
    HRESULT hr;

    child = CreateWindowExW(0, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | LVS_NOSCROLL |
                            LVS_OWNERDRAWFIXED | LVS_NOCOLUMNHEADER, 0, 0, 240, 280,
                            parent, NULL, GetModuleHandleW(NULL), NULL);
    ok(child != NULL, "Failed to create list view.\n");
    if (!child) return;
    SendMessageW(child, LVM_SETICONSPACING, 0, MAKELPARAM(60,70));
    item.mask = LVIF_TEXT;
    item.pszText = (WCHAR *)L"";
    for (i = 0; i < 7; ++i)
    {
        item.iItem = i;
        ok(SendMessageW(child, LVM_INSERTITEMW, 0, (LPARAM)&item) == i, "Insert %u failed.\n", i);
    }
    ok(SendMessageW(child, LVM_SETVIEW, view, 0) == 1, "Set view %u failed.\n", view);
    if (view == LV_VIEW_SMALLICON)
        ok(!SendMessageW(child, LVM_SETCOLUMNWIDTH, 0, 60), "Expected FALSE for small-icon width.\n");
    ok(SendMessageW(child, LVM_QUERYINTERFACE, (WPARAM)&listview_iid, (LPARAM)&iface),
       "Interface query failed.\n");
    if (!iface) goto done;
    table = *(const void *const **)iface;
    ok(table[76] && table[139], "Capacity methods are absent.\n");
    if (!table[76] || !table[139]) goto release;

    if (view == LV_VIEW_ICON)
    {
        for (i = 0; i < ARRAY_SIZE(sizes); ++i)
        {
            SetWindowPos(child, NULL, 0, 0, sizes[i].width, sizes[i].height, SWP_NOZORDER | SWP_NOACTIVATE);
            check_capacity(iface, 76, S_OK, 7);
            check_capacity(iface, 139, S_OK, sizes[i].capacity);
        }
    }
    else
    {
        SetWindowPos(child, NULL, 0, 0, 60, 70, SWP_NOZORDER | SWP_NOACTIVATE);
        check_capacity(iface, 76, S_OK, view == LV_VIEW_DETAILS ? 3 : 7);
        check_capacity(iface, 139, S_OK, view == LV_VIEW_DETAILS ? 3 : 15);
    }

    for (slot = 76; slot <= 139; slot += 63)
    {
        DWORD exception = 0;
        hr = 0xcccccccc;
        SetLastError(SENTINEL);
        __TRY { hr = ((capacity_fn)table[slot])(iface, NULL); }
        __EXCEPT_ALL { exception = GetExceptionCode(); }
        __ENDTRY
        ok(exception == 0xc0000005, "Slot %u exception %#lx.\n", slot, exception);
        ok(hr == 0xcccccccc, "Slot %u returned %#lx for NULL output.\n", slot, hr);
        ok(GetLastError() == SENTINEL, "Slot %u changed last error.\n", slot);
    }

    if (view == LV_VIEW_SMALLICON)
    {
        destroy_on_measure = TRUE;
        SetWindowPos(child, NULL, 0, 0, 61, 71, SWP_NOZORDER | SWP_NOACTIVATE);
        ok(!destroy_on_measure, "Measurement callback was not reached.\n");
        ok(!IsWindow(child), "Measurement callback did not destroy the control.\n");
        destroy_on_measure = FALSE;
    }
    else DestroyWindow(child);
    check_capacity(iface, 76, E_UNEXPECTED, 0);
    check_capacity(iface, 139, E_UNEXPECTED, 0);
release:
    iface->lpVtbl->Release(iface);
done:
    if (IsWindow(child)) DestroyWindow(child);
}

START_TEST(listview_capacity)
{
    INITCOMMONCONTROLSEX init = {sizeof(init), ICC_LISTVIEW_CLASSES};
    WNDCLASSW wc = {0};
    HWND parent;
    ULONG_PTR cookie;
    HANDLE context;
    HMODULE controls;
    BOOL (WINAPI *init_controls)(const INITCOMMONCONTROLSEX *);

    if (!load_v6_module(&cookie, &context)) return;
    controls = LoadLibraryW(L"comctl32.dll");
    init_controls = (void *)GetProcAddress(controls, "InitCommonControlsEx");
    ok(init_controls && init_controls(&init), "Failed to initialize version-six controls.\n");
    wc.lpfnWndProc = parent_proc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"CapacityParent";
    ok(RegisterClassW(&wc), "Failed to register parent class.\n");
    parent = CreateWindowExW(0, wc.lpszClassName, L"", WS_POPUP, 0, 0, 1000, 1000,
                             NULL, NULL, wc.hInstance, NULL);
    ok(parent != NULL, "Failed to create parent.\n");
    if (parent)
    {
        test_capacity(parent, LV_VIEW_ICON);
        test_capacity(parent, LV_VIEW_DETAILS);
        test_capacity(parent, LV_VIEW_SMALLICON);
        DestroyWindow(parent);
    }
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    FreeLibrary(controls);
    unload_v6_module(cookie, context);
}
