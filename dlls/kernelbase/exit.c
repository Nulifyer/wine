/*
 * Process termination support
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

struct dllonexit_table
{
    void *encoded_begin;
    void *encoded_end;
    void *entries[4];
    ULONG count;
    ULONG reserved;
};

static CRITICAL_SECTION dllonexit_section = { NULL, -1, 0, 0, 0, 0 };

typedef void (CDECL *initterm_func)(void);
typedef int (CDECL *initterm_e_func)(void);

/***********************************************************************
 *           _initterm   (KERNELBASE.@)
 */
void CDECL _initterm( initterm_func *first, initterm_func *last )
{
    while (first < last)
    {
        if (*first) (**first)();
        first++;
    }
}

/***********************************************************************
 *           _initterm_e   (KERNELBASE.@)
 */
int CDECL _initterm_e( initterm_e_func *first, initterm_e_func *last )
{
    int ret = 0;

    while (!ret && first < last)
    {
        if (*first) ret = (**first)();
        first++;
    }
    return ret;
}

static void *register_dllonexit( void *func, struct dllonexit_table *table )
{
    HANDLE heap = NtCurrentTeb()->Peb->ProcessHeap;
    void **begin, **end, **new_begin;
    SIZE_T allocated, used, new_size;

    if (!table->count)
    {
        begin = table->entries;
        end = begin;
        table->encoded_begin = RtlEncodePointer( begin );
    }
    else if (table->count == ARRAY_SIZE(table->entries))
    {
        if (!(begin = RtlAllocateHeap( heap, HEAP_ZERO_MEMORY, sizeof(*table) ))) return NULL;
        memcpy( begin, table->entries, sizeof(table->entries) );
        end = begin + ARRAY_SIZE(table->entries);
        table->encoded_begin = RtlEncodePointer( begin );
    }
    else
    {
        begin = RtlDecodePointer( table->encoded_begin );
        end = RtlDecodePointer( table->encoded_end );
    }

    if (table->count > ARRAY_SIZE(table->entries))
    {
        used = (char *)end - (char *)begin;
        allocated = RtlSizeHeap( heap, 0, begin );
        if (allocated <= used)
        {
            new_size = allocated + min( allocated, 32 * sizeof(void *) );
            new_begin = RtlReAllocateHeap( heap, HEAP_ZERO_MEMORY, begin, new_size );
            if (!new_begin)
                new_begin = RtlReAllocateHeap( heap, HEAP_ZERO_MEMORY, begin,
                                               allocated + 4 * sizeof(void *) );
            if (!new_begin) return NULL;

            end = new_begin + used / sizeof(void *);
            begin = new_begin;
            table->encoded_begin = RtlEncodePointer( begin );
        }
    }

    *end++ = RtlEncodePointer( func );
    table->encoded_end = RtlEncodePointer( end );
    table->count++;
    return func;
}

/***********************************************************************
 *           __dllonexit3   (KERNELBASE.@)
 */
void *CDECL __dllonexit3( void *func, struct dllonexit_table *table )
{
    void *ret;

    RtlEnterCriticalSection( &dllonexit_section );
    ret = register_dllonexit( func, table );
    RtlLeaveCriticalSection( &dllonexit_section );
    return ret;
}
