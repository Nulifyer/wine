/*
 * Dynamic RTL hash table tests
 *
 * Copyright 2026 LinuxNT contributors
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
#include "winternl.h"
#include "wine/test.h"

static BOOLEAN (WINAPI *pRtlCreateHashTable)(RTL_DYNAMIC_HASH_TABLE **, ULONG, ULONG);
static BOOLEAN (WINAPI *pRtlCreateHashTableEx)(RTL_DYNAMIC_HASH_TABLE **, ULONG, ULONG, ULONG);
static BOOLEAN (WINAPI *pRtlDeleteHashTable)(RTL_DYNAMIC_HASH_TABLE *);
static void (WINAPI *pRtlEndEnumerationHashTable)(RTL_DYNAMIC_HASH_TABLE *, RTL_DYNAMIC_HASH_TABLE_ENUMERATOR *);
static RTL_DYNAMIC_HASH_TABLE_ENTRY * (WINAPI *pRtlEnumerateEntryHashTable)(RTL_DYNAMIC_HASH_TABLE *, RTL_DYNAMIC_HASH_TABLE_ENUMERATOR *);
static RTL_DYNAMIC_HASH_TABLE_ENTRY * (WINAPI *pRtlGetNextEntryHashTable)(RTL_DYNAMIC_HASH_TABLE *, RTL_DYNAMIC_HASH_TABLE_CONTEXT *);
static BOOLEAN (WINAPI *pRtlInitEnumerationHashTable)(RTL_DYNAMIC_HASH_TABLE *, RTL_DYNAMIC_HASH_TABLE_ENUMERATOR *);
static BOOLEAN (WINAPI *pRtlInsertEntryHashTable)(RTL_DYNAMIC_HASH_TABLE *, RTL_DYNAMIC_HASH_TABLE_ENTRY *, ULONG_PTR, RTL_DYNAMIC_HASH_TABLE_CONTEXT *);
static RTL_DYNAMIC_HASH_TABLE_ENTRY * (WINAPI *pRtlLookupEntryHashTable)(RTL_DYNAMIC_HASH_TABLE *, ULONG_PTR, RTL_DYNAMIC_HASH_TABLE_CONTEXT *);
static BOOLEAN (WINAPI *pRtlRemoveEntryHashTable)(RTL_DYNAMIC_HASH_TABLE *, RTL_DYNAMIC_HASH_TABLE_ENTRY *, RTL_DYNAMIC_HASH_TABLE_CONTEXT *);

START_TEST(hash_table)
{
    RTL_DYNAMIC_HASH_TABLE storage, *table = &storage, *allocated = NULL;
    RTL_DYNAMIC_HASH_TABLE_ENTRY entries[3], *entry;
    RTL_DYNAMIC_HASH_TABLE_CONTEXT context;
    RTL_DYNAMIC_HASH_TABLE_ENUMERATOR enumerator;
    HMODULE ntdll = GetModuleHandleA( "ntdll.dll" );
    unsigned int found = 0, i;
    BOOLEAN ret;

    pRtlCreateHashTable = (void *)GetProcAddress( ntdll, "RtlCreateHashTable" );
    pRtlCreateHashTableEx = (void *)GetProcAddress( ntdll, "RtlCreateHashTableEx" );
    pRtlDeleteHashTable = (void *)GetProcAddress( ntdll, "RtlDeleteHashTable" );
    pRtlEndEnumerationHashTable = (void *)GetProcAddress( ntdll, "RtlEndEnumerationHashTable" );
    pRtlEnumerateEntryHashTable = (void *)GetProcAddress( ntdll, "RtlEnumerateEntryHashTable" );
    pRtlGetNextEntryHashTable = (void *)GetProcAddress( ntdll, "RtlGetNextEntryHashTable" );
    pRtlInitEnumerationHashTable = (void *)GetProcAddress( ntdll, "RtlInitEnumerationHashTable" );
    pRtlInsertEntryHashTable = (void *)GetProcAddress( ntdll, "RtlInsertEntryHashTable" );
    pRtlLookupEntryHashTable = (void *)GetProcAddress( ntdll, "RtlLookupEntryHashTable" );
    pRtlRemoveEntryHashTable = (void *)GetProcAddress( ntdll, "RtlRemoveEntryHashTable" );
    if (!pRtlCreateHashTable || !pRtlCreateHashTableEx || !pRtlDeleteHashTable ||
        !pRtlEndEnumerationHashTable || !pRtlEnumerateEntryHashTable ||
        !pRtlGetNextEntryHashTable || !pRtlInitEnumerationHashTable ||
        !pRtlInsertEntryHashTable || !pRtlLookupEntryHashTable ||
        !pRtlRemoveEntryHashTable)
    {
        win_skip( "Dynamic hash table functions are not available.\n" );
        return;
    }

    memset( &storage, 0xcc, sizeof(storage) );
    ret = pRtlCreateHashTableEx( &table, 64, 0, 0 );
    ok( !ret, "created a table with 64 buckets.\n" );
    ok( table == &storage, "changed caller table pointer to %p.\n", table );

    memset( &storage, 0, sizeof(storage) );
    ret = pRtlCreateHashTableEx( &table, 128, 3, 0 );
    ok( ret, "failed to create caller-allocated table.\n" );
    ok( table == &storage, "returned table %p, expected %p.\n", table, &storage );
    ok( table->Flags == 0, "got flags %#lx.\n", table->Flags );
    ok( table->Shift == 3, "got shift %lu.\n", table->Shift );
    ok( table->TableSize == 128, "got table size %lu.\n", table->TableSize );
    ok( table->DivisorMask == 127, "got divisor mask %#lx.\n", table->DivisorMask );
    ok( table->NumEntries == 0, "got %lu entries.\n", table->NumEntries );
    ok( table->Directory != NULL, "missing bucket directory.\n" );

    memset( entries, 0, sizeof(entries) );
    ok( pRtlInsertEntryHashTable( table, entries, 0x100, NULL ), "failed to insert first entry.\n" );
    memset( &context, 0, sizeof(context) );
    pRtlLookupEntryHashTable( table, 0x100, &context );
    ok( pRtlInsertEntryHashTable( table, entries + 1, 0x100, &context ),
        "failed to insert duplicate-signature entry.\n" );
    ok( pRtlInsertEntryHashTable( table, entries + 2, 0x200, NULL ), "failed to insert third entry.\n" );
    ok( table->NumEntries == 3, "got %lu entries.\n", table->NumEntries );

    memset( &context, 0, sizeof(context) );
    entry = pRtlLookupEntryHashTable( table, 0x100, &context );
    ok( entry == entries + 1, "lookup returned %p, expected %p.\n", entry, entries + 1 );
    entry = pRtlGetNextEntryHashTable( table, &context );
    ok( entry == entries, "next returned %p, expected %p.\n", entry, entries );
    entry = pRtlGetNextEntryHashTable( table, &context );
    ok( !entry, "unexpected third matching entry %p.\n", entry );

    memset( &context, 0, sizeof(context) );
    ok( pRtlRemoveEntryHashTable( table, entries + 1, &context ),
        "failed to remove duplicate-signature entry.\n" );
    ok( context.ChainHead != NULL, "remove did not initialize context.\n" );
    entry = pRtlLookupEntryHashTable( table, 0x100, NULL );
    ok( entry == entries, "lookup returned %p, expected %p.\n", entry, entries );

    ok( pRtlInitEnumerationHashTable( table, &enumerator ), "failed to initialize enumeration.\n" );
    ok( table->NumEnumerators == 1, "got %lu enumerators.\n", table->NumEnumerators );
    while ((entry = pRtlEnumerateEntryHashTable( table, &enumerator )))
    {
        for (i = 0; i < ARRAY_SIZE(entries); ++i)
            if (entry == entries + i) found |= 1u << i;
    }
    ok( found == 0x5, "enumerated entry mask %#x.\n", found );
    pRtlEndEnumerationHashTable( table, &enumerator );
    ok( table->NumEnumerators == 0, "got %lu enumerators.\n", table->NumEnumerators );

    pRtlRemoveEntryHashTable( table, entries, NULL );
    pRtlRemoveEntryHashTable( table, entries + 2, NULL );
    ok( table->NumEntries == 0, "got %lu entries.\n", table->NumEntries );
    ok( table->NonEmptyBuckets == 0, "got %lu nonempty buckets.\n", table->NonEmptyBuckets );
    ok( pRtlDeleteHashTable( table ), "failed to delete caller-allocated table.\n" );

    ok( pRtlCreateHashTable( &allocated, 0, 0 ), "failed to create allocated table.\n" );
    ok( allocated != NULL, "missing allocated table.\n" );
    if (allocated)
    {
        ok( allocated->Flags & RTL_HASH_ALLOCATED_HEADER, "got flags %#lx.\n", allocated->Flags );
        ok( pRtlDeleteHashTable( allocated ), "failed to delete allocated table.\n" );
    }
}
