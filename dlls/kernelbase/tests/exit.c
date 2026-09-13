/*
 * KernelBase process termination tests
 *
 * Copyright 2026
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "windows.h"
#include "winternl.h"

#include "wine/test.h"

struct dllonexit_table
{
    void *encoded_begin;
    void *encoded_end;
    void *entries[4];
    ULONG count;
    ULONG reserved;
};

static void * (CDECL *p__dllonexit3)(void *, struct dllonexit_table *);
static void (CDECL *p_initterm)(void (**)(void), void (**)(void));
static int (CDECL *p_initterm_e)(int (**)(void), int (**)(void));
static unsigned int callback_count;

static void CDECL count_callback(void)
{
    callback_count++;
}

static int CDECL count_success(void)
{
    callback_count++;
    return 0;
}

static int CDECL count_failure(void)
{
    callback_count++;
    return 42;
}

static void test_initterm(void)
{
    void (*callbacks[])(void) = {count_callback, NULL, count_callback};
    int (*callbacks_e[])(void) = {count_success, NULL, count_failure, count_success};
    int ret;

    callback_count = 0;
    p_initterm( callbacks, callbacks + ARRAY_SIZE(callbacks) );
    ok(callback_count == 2, "_initterm called %u callbacks\n", callback_count);

    callback_count = 0;
    ret = p_initterm_e( callbacks_e, callbacks_e + ARRAY_SIZE(callbacks_e) );
    ok(ret == 42, "_initterm_e returned %d\n", ret);
    ok(callback_count == 2, "_initterm_e called %u callbacks\n", callback_count);
}

static void test_dllonexit3(void)
{
    struct dllonexit_table table = {0};
    void **begin, **end;
    unsigned int i;

    for (i = 0; i < 12; ++i)
    {
        void *func = (void *)(ULONG_PTR)(0x1000 + i * 0x10);
        void *ret = p__dllonexit3( func, &table );

        ok(ret == func, "registration %u returned %p, expected %p\n", i, ret, func);
        ok(table.count == i + 1, "registration %u set count %lu\n", i, table.count);

        begin = RtlDecodePointer( table.encoded_begin );
        end = RtlDecodePointer( table.encoded_end );
        ok(end == begin + i + 1, "registration %u has begin %p, end %p\n", i, begin, end);
        ok(RtlDecodePointer( begin[i] ) == func,
           "registration %u stored %p, expected %p\n", i, RtlDecodePointer( begin[i] ), func);

        if (i < ARRAY_SIZE(table.entries))
            ok(begin == table.entries, "registration %u unexpectedly used heap storage %p\n", i, begin);
        else
            ok(begin != table.entries, "registration %u still uses inline storage\n", i);
    }

    begin = RtlDecodePointer( table.encoded_begin );
    RtlFreeHeap( NtCurrentTeb()->Peb->ProcessHeap, 0, begin );
}

START_TEST(exit)
{
    HMODULE module = GetModuleHandleA("kernelbase.dll");

    p__dllonexit3 = (void *)GetProcAddress(module, "__dllonexit3");
    p_initterm = (void *)GetProcAddress(module, "_initterm");
    p_initterm_e = (void *)GetProcAddress(module, "_initterm_e");
    if (!p__dllonexit3)
    {
        win_skip("__dllonexit3 is unavailable\n");
        return;
    }

    ok(!!p_initterm, "_initterm is unavailable\n");
    ok(!!p_initterm_e, "_initterm_e is unavailable\n");
    if (p_initterm && p_initterm_e) test_initterm();
    test_dllonexit3();
}
