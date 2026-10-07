/*
 * Language-pack Edit callouts
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "windef.h"
#include "winbase.h"
#include "wingdi.h"
#include "winuser.h"
#include "winnls.h"
#include "usp10.h"
#include "wine/debug.h"

#ifdef _WIN64

WINE_DEFAULT_DEBUG_CHANNEL(edit);

/* The x64 user-mode Edit callout ABI.  The control owns this state and all
 * its objects.  Callouts borrow it only for the duration of the call; they
 * do not retain a native pointer or use native GDI shared-memory layouts. */
struct edit_state
{
    HLOCAL text;
    UINT allocated, limit, length, line_count;
    UINT selection_start, selection_end, caret, caret_line, first_line, reserved_2c;
    int scroll;
    UINT password;
    BYTE reserved_38[8];
    HWND hwnd, parent;
    RECT rect;
    BYTE reserved_60[0x14];
    UINT flags, flags2;
    WORD reserved_7c, character_size;
    UINT *lines;
    int alignment;
    BYTE reserved_8c[0x3c];
    int tab_width, line_height;
    BYTE reserved_d0[0x18];
    int *tabs;
    BYTE reserved_f0[8];
    BYTE charset;
    BYTE reserved_f9[0x37];
    UINT caret_flags;
};

C_ASSERT(offsetof(struct edit_state, hwnd) == 0x40);
C_ASSERT(offsetof(struct edit_state, rect) == 0x50);
C_ASSERT(offsetof(struct edit_state, flags) == 0x74);
C_ASSERT(offsetof(struct edit_state, character_size) == 0x7e);
C_ASSERT(offsetof(struct edit_state, alignment) == 0x88);
C_ASSERT(offsetof(struct edit_state, tab_width) == 0xc8);
C_ASSERT(offsetof(struct edit_state, tabs) == 0xe8);
C_ASSERT(offsetof(struct edit_state, charset) == 0xf8);
C_ASSERT(offsetof(struct edit_state, caret_flags) == 0x130);

#define EDIT_SINGLE_LINE 0x00000001
#define EDIT_FOCUSED     0x00000008
#define EDIT_NOHIDESEL   0x00000800
#define EDIT_NO_SCROLL   0x00004000
#define EDIT_ANSI        0x00400000
#define EDIT_DIGITS      0x40000000
#define EDIT_RTL         0x80000000

struct edit_analysis
{
    SCRIPT_STRING_ANALYSIS ssa;
    WCHAR *converted;
    const WCHAR *text;
    int length;
    UINT codepage;
};

static UINT edit_codepage(const struct edit_state *edit)
{
    CHARSETINFO info;
    UINT charset = edit->charset;

    if (charset == SYMBOL_CHARSET || charset == OEM_CHARSET) charset = ANSI_CHARSET;
    if (charset == ANSI_CHARSET) return CP_ACP;
    if (TranslateCharsetInfo((DWORD *)(ULONG_PTR)charset, &info, TCI_SRCCHARSET)) return info.ciACP;
    return CP_ACP;
}

static void free_analysis(struct edit_analysis *analysis)
{
    if (analysis->ssa) ScriptStringFree(&analysis->ssa);
    free(analysis->converted);
}

static HRESULT analyse(const struct edit_state *edit, HDC hdc, const void *text,
                       int length, DWORD flags, struct edit_analysis *analysis)
{
    SCRIPT_CONTROL control = {0};
    SCRIPT_STATE state = {0};
    SCRIPT_TABDEF tabs = {0};
    int default_tab = edit->tab_width * 8;
    HRESULT hr;

    memset(analysis, 0, sizeof(*analysis));
    if (length <= 0) return E_INVALIDARG;
    analysis->text = text;
    analysis->length = length;
    if (edit->flags & EDIT_ANSI)
    {
        analysis->codepage = edit_codepage(edit);
        analysis->length = MultiByteToWideChar(analysis->codepage, 0, text, length, NULL, 0);
        if (!analysis->length) return E_INVALIDARG;
        if (!(analysis->converted = malloc(analysis->length * sizeof(WCHAR)))) return E_OUTOFMEMORY;
        MultiByteToWideChar(analysis->codepage, 0, text, length, analysis->converted, analysis->length);
        analysis->text = analysis->converted;
    }
    if (edit->password)
    {
        analysis->text = (const WCHAR *)&edit->password;
        flags |= SSA_PASSWORD;
    }
    if (edit->flags & EDIT_RTL)
    {
        flags |= SSA_RTL;
        state.uBidiLevel = 1;
    }
    flags |= SSA_TAB | SSA_FALLBACK | SSA_LINK;
    tabs.iScale = 4;
    tabs.cTabStops = edit->tabs ? edit->tabs[0] : 1;
    tabs.pTabStops = edit->tabs ? edit->tabs + 1 : &default_tab;
    /* Keep shaping and font fallback in the existing Uniscribe owner. */
    hr = ScriptStringAnalyse(hdc, analysis->text, analysis->length, 0, -1, flags,
                             0, &control, &state, NULL, &tabs, NULL, &analysis->ssa);
    if (FAILED(hr)) free_analysis(analysis);
    return hr;
}

static int wide_index(const struct edit_state *edit, const void *text, int index)
{
    if (!(edit->flags & EDIT_ANSI) || index <= 0) return index;
    return MultiByteToWideChar(edit_codepage(edit), 0, text, index, NULL, 0);
}

static int native_index(const struct edit_state *edit, const struct edit_analysis *analysis, int index)
{
    if (!(edit->flags & EDIT_ANSI) || index <= 0) return index;
    return WideCharToMultiByte(analysis->codepage, 0, analysis->text, index, NULL, 0, NULL, NULL);
}

static int left_edge(const struct edit_state *edit, int width)
{
    int offset = 0, available = edit->rect.right - edit->rect.left;

    if (edit->alignment == 1) offset = (available - width) / 2;
    else if (edit->alignment == 2) offset = available - width;
    if (!edit->alignment || offset < 0)
        offset = (edit->flags & EDIT_NO_SCROLL) ? 0 : -edit->scroll;
    return (edit->flags & EDIT_RTL) ? edit->rect.right - offset - width : edit->rect.left + offset;
}

static BOOL WINAPI edit_create(struct edit_state *edit, HWND hwnd)
{
    LONG_PTR exstyle = GetWindowLongPtrW(hwnd, GWL_EXSTYLE), style;
    HKL *layouts;
    LOCALESIGNATURE signature;
    int i, count;

    TRACE("state %p, hwnd %p, error %lu\n", edit, hwnd, GetLastError());

    edit->flags &= ~0x20000000;
    count = GetKeyboardLayoutList(0, NULL);
    if (count > 1 && (layouts = malloc((SIZE_T)count * sizeof(*layouts))))
    {
        if (GetKeyboardLayoutList(count, layouts) == count)
            for (i = 0; i < count; ++i)
                if (GetLocaleInfoW(LOWORD(layouts[i]), LOCALE_FONTSIGNATURE, (WCHAR *)&signature,
                                  sizeof(signature) / sizeof(WCHAR)) &&
                    (signature.lsUsb[3] & 0xc8000000) == 0x88000000)
                {
                    edit->flags |= 0x20000000;
                    break;
                }
        free(layouts);
    }
    if (exstyle & WS_EX_LAYOUTRTL)
    {
        exstyle = (exstyle ^ (WS_EX_RIGHT | WS_EX_RTLREADING | WS_EX_LEFTSCROLLBAR)) & ~WS_EX_LAYOUTRTL;
        SetWindowLongPtrW(hwnd, GWL_EXSTYLE, exstyle);
        style = GetWindowLongPtrW(hwnd, GWL_STYLE);
        if (!(style & ES_CENTER)) SetWindowLongPtrW(hwnd, GWL_STYLE, style ^ ES_RIGHT);
    }
    if ((exstyle & WS_EX_RIGHT) && !edit->alignment) edit->alignment = 2;
    if (exstyle & WS_EX_RTLREADING)
    {
        edit->flags |= EDIT_RTL;
        if (!edit->alignment) edit->alignment = 2;
        else if (edit->alignment == 2) edit->alignment = 0;
    }
    TRACE("state %p, hwnd %p, error %lu after creation\n", edit, hwnd, GetLastError());
    return TRUE;
}

static int WINAPI edit_ich_to_xy(struct edit_state *edit, HDC hdc, const void *text, int length, int index)
{
    struct edit_analysis analysis;
    int x = 0, edge;

    if (FAILED(analyse(edit, hdc, text, length, SSA_GLYPHS, &analysis))) return left_edge(edit, 0);
    index = wide_index(edit, text, index);
    ScriptStringCPtoX(analysis.ssa, index ? index - 1 : 0, index != 0, &x);
    edge = left_edge(edit, ScriptString_pSize(analysis.ssa)->cx);
    free_analysis(&analysis);
    return edge + x;
}

static int WINAPI edit_mouse_to_ich(struct edit_state *edit, HDC hdc, const void *text, int length, int x)
{
    struct edit_analysis analysis;
    int index = 0, trailing = 0, width;

    if (FAILED(analyse(edit, hdc, text, length, SSA_GLYPHS, &analysis))) return 0;
    width = ScriptString_pSize(analysis.ssa)->cx;
    x -= left_edge(edit, width);
    if (x < 0) index = (edit->flags & EDIT_RTL) ? analysis.length : 0;
    else if (x > width) index = (edit->flags & EDIT_RTL) ? 0 : analysis.length;
    else if (SUCCEEDED(ScriptStringXtoCP(analysis.ssa, x, &index, &trailing))) index += trailing;
    index = native_index(edit, &analysis, min(max(index, 0), analysis.length));
    free_analysis(&analysis);
    return index;
}

static int WINAPI edit_cch_in_width(struct edit_state *edit, HDC hdc, const void *text, UINT length, int width)
{
    struct edit_analysis analysis;
    int i, x, fit = 0;

    if (FAILED(analyse(edit, hdc, text, min(length, 1024), SSA_GLYPHS, &analysis))) return 0;
    for (i = 0; i < analysis.length; ++i)
    {
        if (FAILED(ScriptStringCPtoX(analysis.ssa, i, TRUE, &x)) || x > width) break;
        fit = i + 1;
    }
    fit = native_index(edit, &analysis, fit);
    free_analysis(&analysis);
    return fit;
}

static int WINAPI edit_line_width(struct edit_state *edit, HDC hdc, const void *text, UINT length)
{
    struct edit_analysis analysis;
    int width;

    if (FAILED(analyse(edit, hdc, text, min(length, 1024), SSA_GLYPHS, &analysis))) return 0;
    width = ScriptString_pSize(analysis.ssa)->cx;
    free_analysis(&analysis);
    return width;
}

static void WINAPI edit_draw(struct edit_state *edit, HDC hdc, const void *text, int length,
                            int selection_start, int selection_end, int y)
{
    struct edit_analysis analysis;
    RECT rect = {edit->rect.left, y, edit->rect.right, y + edit->line_height};
    UINT flags = ETO_CLIPPED;

    if (GetBkMode(hdc) == OPAQUE) flags |= ETO_OPAQUE;
    if (!length)
    {
        if (flags & ETO_OPAQUE) ExtTextOutW(hdc, 0, y, ETO_OPAQUE, &rect, NULL, 0, NULL);
        return;
    }
    if (FAILED(analyse(edit, hdc, text, length, SSA_GLYPHS, &analysis))) return;
    selection_start = wide_index(edit, text, max(selection_start, 0));
    selection_end = wide_index(edit, text, min(selection_end, length));
    if (!(edit->flags & (EDIT_FOCUSED | EDIT_NOHIDESEL))) selection_end = selection_start;
    ScriptStringOut(analysis.ssa, left_edge(edit, ScriptString_pSize(analysis.ssa)->cx), y,
                    flags, &rect, selection_start, selection_end, !!(edit->flags & 0x20));
    free_analysis(&analysis);
}

static BOOL WINAPI edit_hscroll(struct edit_state *edit, HDC hdc, const void *text)
{
    struct edit_analysis analysis;
    int old = edit->scroll, x = 0, index, width, available, delta = 0;

    if (!edit->length || edit->caret > edit->length)
    {
        edit->scroll = 0;
        return FALSE;
    }
    if (FAILED(analyse(edit, hdc, text, edit->length, SSA_GLYPHS, &analysis))) return FALSE;
    index = wide_index(edit, text, edit->caret);
    ScriptStringCPtoX(analysis.ssa, index ? index - 1 : 0, index != 0, &x);
    width = ScriptString_pSize(analysis.ssa)->cx;
    available = edit->rect.right - edit->rect.left;
    x += left_edge(edit, width);
    if (x < edit->rect.left) delta = available / 4 - x;
    else if (x > edit->rect.right) delta = available * 3 / 4 - x;
    if (edit->flags & EDIT_RTL) delta = -delta;
    if (width > available && width + delta - old < available) edit->scroll = width - available;
    else edit->scroll = max(old - delta, 0);
    free_analysis(&analysis);
    return edit->scroll != old;
}

static UINT WINAPI edit_move_selection(struct edit_state *edit, HDC hdc, const void *text, UINT index, BOOL backward)
{
    struct edit_analysis analysis;
    const SCRIPT_LOGATTR *attr;
    int pos, result;

    if (!edit->length || (backward && index < 2)) return 0;
    if (!backward && index >= edit->length - 1) return edit->length;
    if (FAILED(analyse(edit, hdc, text, edit->length, SSA_BREAK, &analysis)))
        return backward ? index - 1 : index + 1;
    pos = wide_index(edit, text, index);
    attr = ScriptString_pLogAttr(analysis.ssa);
    if (backward)
    {
        for (pos = max(pos - 1, 0); pos > 0 && !attr[pos].fCharStop; --pos) ;
    }
    else
    {
        for (++pos; pos < analysis.length && !attr[pos].fCharStop; ++pos) ;
    }
    result = native_index(edit, &analysis, pos);
    free_analysis(&analysis);
    return result;
}

static BOOL WINAPI edit_verify_text(struct edit_state *edit, HDC hdc, const void *text, UINT index,
                                  const void *insert, UINT count)
{
    struct edit_analysis analysis;
    const SCRIPT_LOGATTR *attr;
    BYTE *combined;
    UINT size, length;
    int pos, i;
    BOOL valid = TRUE;

    if (!edit->lines || count > 1) return TRUE;
    if (index > edit->length || edit->length > INT_MAX - count) return FALSE;
    length = edit->length + count;
    size = (edit->flags & EDIT_ANSI) ? 1 : sizeof(WCHAR);
    if (!(combined = malloc((SIZE_T)length * size))) return TRUE;
    memcpy(combined, text, (SIZE_T)index * size);
    memcpy(combined + (SIZE_T)index * size, insert, count * size);
    memcpy(combined + (SIZE_T)(index + count) * size, (const BYTE *)text + (SIZE_T)index * size,
           (SIZE_T)(edit->length - index) * size);
    if (SUCCEEDED(analyse(edit, hdc, combined, length, SSA_BREAK, &analysis)))
    {
        pos = wide_index(edit, combined, index);
        attr = ScriptString_pLogAttr(analysis.ssa);
        for (i = pos; i < analysis.length; ++i)
            if (attr[i].fInvalid) { valid = FALSE; break; }
        free_analysis(&analysis);
    }
    free(combined);
    if (!valid) MessageBeep(-1);
    return valid;
}

static void WINAPI edit_next_word(struct edit_state *edit, HDC hdc, const void *text, UINT index,
                                 BOOL backward, UINT *start, UINT *end)
{
    struct edit_analysis analysis;
    const SCRIPT_LOGATTR *attr;
    int left = 0, right = edit->length, pos;

    if (SUCCEEDED(analyse(edit, hdc, text, edit->length, SSA_BREAK, &analysis)))
    {
        pos = min(wide_index(edit, text, index), analysis.length);
        if (backward && pos) --pos;
        attr = ScriptString_pLogAttr(analysis.ssa);
        left = pos;
        while (left > 0 && (left == analysis.length || !attr[left].fSoftBreak)) --left;
        right = left + 1;
        while (right < analysis.length && !attr[right].fSoftBreak) ++right;
        left = native_index(edit, &analysis, left);
        right = native_index(edit, &analysis, min(right, analysis.length));
        free_analysis(&analysis);
    }
    if (start) *start = left;
    if (end) *end = right;
}

static void WINAPI edit_set_menu(struct edit_state *edit, HMENU menu)
{
    UINT id;
    EnableMenuItem(menu, 0x8000, MF_ENABLED);
    CheckMenuItem(menu, 0x8000, (edit->flags & EDIT_RTL) ? MF_CHECKED : MF_UNCHECKED);
    for (id = 0x8001; id <= 0x8013; ++id)
    {
        BOOL enabled = !(edit->flags & EDIT_ANSI) || edit->charset == ARABIC_CHARSET || edit->charset == HEBREW_CHARSET;
        if (id >= 0x8006 && id <= 0x8012 && (edit->flags & EDIT_ANSI)) continue;
        if ((id == 0x8002 || id == 0x8003) && edit->charset == HEBREW_CHARSET && (edit->flags & EDIT_ANSI)) continue;
        EnableMenuItem(menu, id, enabled ? MF_ENABLED : MF_GRAYED);
    }
    CheckMenuItem(menu, 0x8001, (edit->flags & EDIT_DIGITS) ? MF_CHECKED : MF_UNCHECKED);
}

static BOOL WINAPI edit_process_menu(struct edit_state *edit, UINT command)
{
    static const WCHAR characters[] = {0x200d,0x200c,0x200e,0x200f,0x202a,0x202b,0x202d,0x202e,
                                      0x202c,0x206e,0x206f,0x206b,0x206a,0x206d,0x206c,0x1e,0x1f};
    static const BYTE ansi[] = {0x9e,0x9d,0xfd,0xfe};
    LONG_PTR style;

    if (command == 0x8000)
    {
        style = GetWindowLongPtrW(edit->hwnd, GWL_STYLE);
        SetWindowLongPtrW(edit->hwnd, GWL_STYLE, style & ~3);
        style = GetWindowLongPtrW(edit->hwnd, GWL_EXSTYLE);
        if (edit->flags & EDIT_RTL) style &= ~(WS_EX_RIGHT | WS_EX_RTLREADING | WS_EX_LEFTSCROLLBAR);
        else style |= WS_EX_RIGHT | WS_EX_RTLREADING | WS_EX_LEFTSCROLLBAR;
        SetWindowLongPtrW(edit->hwnd, GWL_EXSTYLE, style);
    }
    else if (command == 0x8001)
    {
        edit->flags ^= EDIT_DIGITS;
        InvalidateRect(edit->hwnd, NULL, TRUE);
    }
    else if (command >= 0x8002 && command <= 0x8012)
    {
        if ((edit->flags & EDIT_ANSI) && command <= 0x8005)
            SendMessageA(edit->hwnd, WM_CHAR, ansi[command - 0x8002], 0);
        else SendMessageW(edit->hwnd, WM_CHAR, characters[command - 0x8002], 0);
    }
    return TRUE;
}

static BOOL WINAPI edit_create_caret(struct edit_state *edit, HDC hdc, int width, int height, HKL layout)
{
    edit->caret_flags = 0;
    return CreateCaret(edit->hwnd, NULL, width, height);
}

static UINT WINAPI edit_adjust_caret(struct edit_state *edit, HDC hdc, const void *text, UINT index)
{
    return index;
}

void *LpkEditControl[14] =
{
    edit_create, edit_ich_to_xy, edit_mouse_to_ich, edit_cch_in_width, edit_line_width,
    edit_draw, edit_hscroll, edit_move_selection, edit_verify_text, edit_next_word,
    edit_set_menu, edit_process_menu, edit_create_caret, edit_adjust_caret
};

void **WINAPI LpkGetEditControl(void)
{
    TRACE("returning %p\n", LpkEditControl);
    return LpkEditControl;
}

BOOL WINAPI LpkpInitializeEditControl(void **callbacks, int count)
{
    int i;
    TRACE("callbacks %p, count %d\n", callbacks, count);
    if (count != ARRAY_SIZE(LpkEditControl)) return FALSE;
    for (i = 0; i < count; ++i) LpkEditControl[i] = callbacks[i];
    return TRUE;
}

#endif /* _WIN64 */
