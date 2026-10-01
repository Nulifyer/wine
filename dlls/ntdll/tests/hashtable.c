/*
 * RTL dynamic hash table tests
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "wine/test.h"

static void test_dynamic_hash_table(void)
{
    RTL_DYNAMIC_HASH_TABLE *table = NULL;
    RTL_DYNAMIC_HASH_TABLE_ENTRY entries[5] = {{0}};
    RTL_DYNAMIC_HASH_TABLE_CONTEXT context = {0};
    RTL_DYNAMIC_HASH_TABLE_ENUMERATOR enumerator = {0};
    static const ULONG_PTR signatures[] = {1, 65, 2, 129, 1};
    static const unsigned int enumeration_order[] = {2, 4, 0, 1, 3};
    RTL_DYNAMIC_HASH_TABLE_ENTRY *entry;
    unsigned int i;

    ok(RtlCreateHashTable(&table, 0, 0), "RtlCreateHashTable failed\n");
    if (!table) return;
    ok(table->Flags == 1, "got flags %#lx\n", table->Flags);
    ok(table->Shift == 0, "got shift %lu\n", table->Shift);
    ok(table->TableSize == 128, "got table size %lu\n", table->TableSize);
    ok(table->Pivot == 0, "got pivot %lu\n", table->Pivot);
    ok(table->DivisorMask == 0x7f, "got divisor mask %#lx\n", table->DivisorMask);

    for (i = 0; i < ARRAY_SIZE(entries); ++i)
    {
        memset(&context, 0, sizeof(context));
        ok(RtlInsertEntryHashTable(table, entries + i, signatures[i], &context),
           "insert %u failed\n", i);
    }
    ok(table->NumEntries == 5, "got %lu entries\n", table->NumEntries);
    ok(table->NonEmptyBuckets == 4, "got %lu nonempty buckets\n", table->NonEmptyBuckets);

    memset(&context, 0, sizeof(context));
    entry = RtlLookupEntryHashTable(table, 1, &context);
    ok(entry == entries + 4, "got entry %p\n", entry);
    entry = RtlGetNextEntryHashTable(table, &context);
    ok(entry == entries, "got duplicate entry %p\n", entry);
    ok(!RtlGetNextEntryHashTable(table, &context), "unexpected third duplicate\n");

    ok(RtlInitEnumerationHashTable(table, &enumerator), "enumeration init failed\n");
    ok(table->NumEnumerators == 1, "got %lu enumerators\n", table->NumEnumerators);
    ok(table->NonEmptyBuckets == 5, "got %lu nonempty buckets\n", table->NonEmptyBuckets);
    for (i = 0; i < ARRAY_SIZE(enumeration_order); ++i)
    {
        entry = RtlEnumerateEntryHashTable(table, &enumerator);
        ok(entry == entries + enumeration_order[i], "enumeration %u returned %p\n", i, entry);
    }
    ok(!RtlEnumerateEntryHashTable(table, &enumerator), "enumeration returned an extra entry\n");
    RtlEndEnumerationHashTable(table, &enumerator);
    ok(table->NumEnumerators == 0, "got %lu enumerators\n", table->NumEnumerators);
    ok(table->NonEmptyBuckets == 4, "got %lu nonempty buckets\n", table->NonEmptyBuckets);

    for (i = 0; i < 4; ++i) ok(RtlExpandHashTable(table), "expand %u failed\n", i);
    ok(table->TableSize == 132, "got table size %lu\n", table->TableSize);
    ok(table->Pivot == 4, "got pivot %lu\n", table->Pivot);
    for (i = 0; i < 4; ++i) ok(RtlContractHashTable(table), "contract %u failed\n", i);
    ok(table->TableSize == 128, "got table size %lu\n", table->TableSize);
    ok(table->Pivot == 0, "got pivot %lu\n", table->Pivot);

    for (i = 0; i < ARRAY_SIZE(entries); ++i)
        ok(RtlRemoveEntryHashTable(table, entries + i, NULL), "remove %u failed\n", i);
    ok(table->NumEntries == 0, "got %lu entries\n", table->NumEntries);
    ok(table->NonEmptyBuckets == 0, "got %lu nonempty buckets\n", table->NonEmptyBuckets);
    RtlDeleteHashTable(table);
}

START_TEST(hashtable)
{
    test_dynamic_hash_table();
}
