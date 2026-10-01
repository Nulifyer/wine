/*
 * RTL dynamic hash tables
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
#include "winternl.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(ntdll);

#define HASH_TABLE_MIN_SIZE 0x80
#define HASH_TABLE_MAX_SIZE 0x7fff80
#define HASH_TABLE_DIRECTORY_SIZE 16
#define HASH_TABLE_ALLOCATED 0x1

static void init_list( LIST_ENTRY *head )
{
    head->Flink = head->Blink = head;
}

static void remove_list_entry( LIST_ENTRY *entry )
{
    entry->Blink->Flink = entry->Flink;
    entry->Flink->Blink = entry->Blink;
}

static void insert_list_after( LIST_ENTRY *prev, LIST_ENTRY *entry )
{
    entry->Flink = prev->Flink;
    entry->Blink = prev;
    prev->Flink->Blink = entry;
    prev->Flink = entry;
}

static void *hash_alloc( SIZE_T size )
{
    return RtlAllocateHeap( NtCurrentTeb()->Peb->ProcessHeap, 0, size );
}

static void hash_free( void *ptr )
{
    RtlFreeHeap( NtCurrentTeb()->Peb->ProcessHeap, 0, ptr );
}

static ULONG hash_signature( const RTL_DYNAMIC_HASH_TABLE *table, ULONG_PTR signature )
{
    ULONG value = (ULONG)signature >> (table->Shift & 31);
    ULONG hash = ((value * 0x41c64e6d + 0x3039) >> 16) |
                 ((value * 0x10dcd + 1) & 0xffff0000);
    ULONG bucket = hash & table->DivisorMask;

    if (bucket < table->Pivot) bucket = hash & ((table->DivisorMask << 1) | 1);
    return bucket;
}

static unsigned int bucket_segment( ULONG bucket, ULONG *offset )
{
    ULONG value = bucket + HASH_TABLE_MIN_SIZE;
    unsigned int bit = 0;

    while (value >>= 1) ++bit;
    *offset = (bucket + HASH_TABLE_MIN_SIZE) ^ (1u << bit);
    return bit - 7;
}

static LIST_ENTRY *get_bucket_head( const RTL_DYNAMIC_HASH_TABLE *table, ULONG bucket )
{
    LIST_ENTRY *segment;
    ULONG offset;
    unsigned int index;

    if (table->TableSize <= HASH_TABLE_MIN_SIZE)
        return (LIST_ENTRY *)table->Directory + bucket;

    index = bucket_segment( bucket, &offset );
    segment = ((LIST_ENTRY **)table->Directory)[index];
    return segment + offset;
}

static LIST_ENTRY *alloc_segment( unsigned int index )
{
    ULONG count = HASH_TABLE_MIN_SIZE << index;
    LIST_ENTRY *segment;
    ULONG i;

    if (!(segment = hash_alloc( count * sizeof(*segment) ))) return NULL;
    for (i = 0; i < count; ++i) init_list( segment + i );
    return segment;
}

static void init_context( RTL_DYNAMIC_HASH_TABLE *table, RTL_DYNAMIC_HASH_TABLE_CONTEXT *context,
                          ULONG_PTR signature )
{
    LIST_ENTRY *head = get_bucket_head( table, hash_signature( table, signature ));
    LIST_ENTRY *prev = head, *cursor = head->Flink;

    while (cursor != head)
    {
        RTL_DYNAMIC_HASH_TABLE_ENTRY *entry = CONTAINING_RECORD( cursor, RTL_DYNAMIC_HASH_TABLE_ENTRY, Linkage );
        if (entry->Signature && entry->Signature >= signature) break;
        prev = cursor;
        cursor = cursor->Flink;
    }
    context->ChainHead = head;
    context->PrevLinkage = prev;
    context->Signature = signature;
}

BOOLEAN WINAPI RtlCreateHashTableEx( RTL_DYNAMIC_HASH_TABLE **table_ptr, ULONG size, ULONG shift, ULONG flags )
{
    RTL_DYNAMIC_HASH_TABLE *table = *table_ptr;
    BOOL allocated = FALSE;
    unsigned int last_segment, i;
    ULONG offset;

    TRACE("(%p, %lu, %lu, %#lx)\n", table_ptr, size, shift, flags);

    if (size < HASH_TABLE_MIN_SIZE || size > HASH_TABLE_MAX_SIZE || (size & (size - 1))) return FALSE;
    if (!table)
    {
        if (!(table = hash_alloc( sizeof(*table) ))) return FALSE;
        allocated = TRUE;
    }

    memset( table, 0, sizeof(*table) );
    table->Flags = flags | (allocated ? HASH_TABLE_ALLOCATED : 0);
    table->Shift = shift;
    table->TableSize = size;
    table->DivisorMask = size - 1;

    if (size == HASH_TABLE_MIN_SIZE)
    {
        if (!(table->Directory = alloc_segment( 0 ))) goto failed;
    }
    else
    {
        if (!(table->Directory = hash_alloc( HASH_TABLE_DIRECTORY_SIZE * sizeof(void *) ))) goto failed;
        memset( table->Directory, 0, HASH_TABLE_DIRECTORY_SIZE * sizeof(void *) );
        last_segment = bucket_segment( size - 1, &offset );
        for (i = 0; i <= last_segment; ++i)
            if (!(((LIST_ENTRY **)table->Directory)[i] = alloc_segment( i ))) goto failed;
    }

    *table_ptr = table;
    return TRUE;

failed:
    RtlDeleteHashTable( table );
    if (!allocated) memset( table, 0, sizeof(*table) );
    return FALSE;
}

BOOLEAN WINAPI RtlCreateHashTable( RTL_DYNAMIC_HASH_TABLE **table, ULONG shift, ULONG flags )
{
    return RtlCreateHashTableEx( table, HASH_TABLE_MIN_SIZE, shift, flags );
}

void WINAPI RtlDeleteHashTable( RTL_DYNAMIC_HASH_TABLE *table )
{
    BOOL allocated = table->Flags & HASH_TABLE_ALLOCATED;
    unsigned int i;

    TRACE("(%p)\n", table);

    if (table->Directory)
    {
        if (table->TableSize <= HASH_TABLE_MIN_SIZE) hash_free( table->Directory );
        else
        {
            LIST_ENTRY **directory = table->Directory;
            for (i = 0; i < HASH_TABLE_DIRECTORY_SIZE; ++i)
                if (directory[i]) hash_free( directory[i] );
            hash_free( directory );
        }
    }
    if (allocated) hash_free( table );
}

BOOLEAN WINAPI RtlInsertEntryHashTable( RTL_DYNAMIC_HASH_TABLE *table, RTL_DYNAMIC_HASH_TABLE_ENTRY *entry,
                                        ULONG_PTR signature, RTL_DYNAMIC_HASH_TABLE_CONTEXT *context )
{
    RTL_DYNAMIC_HASH_TABLE_CONTEXT local;

    TRACE("(%p, %p, %p, %p)\n", table, entry, (void *)signature, context);

    entry->Signature = signature;
    ++table->NumEntries;
    if (!context) context = &local;
    if (!context->ChainHead) init_context( table, context, signature );
    if (context->ChainHead->Flink == context->ChainHead) ++table->NonEmptyBuckets;
    insert_list_after( context->PrevLinkage, &entry->Linkage );
    return TRUE;
}

BOOLEAN WINAPI RtlRemoveEntryHashTable( RTL_DYNAMIC_HASH_TABLE *table, RTL_DYNAMIC_HASH_TABLE_ENTRY *entry,
                                        RTL_DYNAMIC_HASH_TABLE_CONTEXT *context )
{
    ULONG_PTR signature = entry->Signature;

    TRACE("(%p, %p, %p)\n", table, entry, context);

    --table->NumEntries;
    if (entry->Linkage.Flink == entry->Linkage.Blink) --table->NonEmptyBuckets;
    remove_list_entry( &entry->Linkage );
    if (context && !context->ChainHead) init_context( table, context, signature );
    return TRUE;
}

RTL_DYNAMIC_HASH_TABLE_ENTRY * WINAPI RtlLookupEntryHashTable( RTL_DYNAMIC_HASH_TABLE *table,
                                                               ULONG_PTR signature,
                                                               RTL_DYNAMIC_HASH_TABLE_CONTEXT *context )
{
    RTL_DYNAMIC_HASH_TABLE_CONTEXT local;
    LIST_ENTRY *cursor;

    TRACE("(%p, %p, %p)\n", table, (void *)signature, context);

    if (!context) context = &local;
    init_context( table, context, signature );
    cursor = context->PrevLinkage->Flink;
    if (cursor == context->ChainHead) return NULL;
    if (CONTAINING_RECORD( cursor, RTL_DYNAMIC_HASH_TABLE_ENTRY, Linkage )->Signature != signature) return NULL;
    return CONTAINING_RECORD( cursor, RTL_DYNAMIC_HASH_TABLE_ENTRY, Linkage );
}

RTL_DYNAMIC_HASH_TABLE_ENTRY * WINAPI RtlGetNextEntryHashTable( RTL_DYNAMIC_HASH_TABLE *table,
                                                                RTL_DYNAMIC_HASH_TABLE_CONTEXT *context )
{
    LIST_ENTRY *previous = context->PrevLinkage->Flink;
    LIST_ENTRY *cursor = previous->Flink;

    TRACE("(%p, %p)\n", table, context);

    while (cursor != context->ChainHead)
    {
        RTL_DYNAMIC_HASH_TABLE_ENTRY *entry = CONTAINING_RECORD( cursor, RTL_DYNAMIC_HASH_TABLE_ENTRY, Linkage );
        if (!table->NumEnumerators || entry->Signature) break;
        previous = cursor;
        cursor = cursor->Flink;
    }
    if (cursor == context->ChainHead) return NULL;
    if (CONTAINING_RECORD( cursor, RTL_DYNAMIC_HASH_TABLE_ENTRY, Linkage )->Signature != context->Signature) return NULL;
    context->PrevLinkage = previous;
    return CONTAINING_RECORD( cursor, RTL_DYNAMIC_HASH_TABLE_ENTRY, Linkage );
}

BOOLEAN WINAPI RtlInitEnumerationHashTable( RTL_DYNAMIC_HASH_TABLE *table,
                                            RTL_DYNAMIC_HASH_TABLE_ENUMERATOR *enumerator )
{
    RTL_DYNAMIC_HASH_TABLE_CONTEXT context = {0};

    TRACE("(%p, %p)\n", table, enumerator);

    init_context( table, &context, 0 );
    if (context.ChainHead->Flink == context.ChainHead) ++table->NonEmptyBuckets;
    insert_list_after( context.PrevLinkage, &enumerator->HashEntry.Linkage );
    enumerator->HashEntry.Signature = 0;
    enumerator->ChainHead = context.ChainHead;
    enumerator->BucketIndex = 0;
    ++table->NumEnumerators;
    return TRUE;
}

RTL_DYNAMIC_HASH_TABLE_ENTRY * WINAPI RtlEnumerateEntryHashTable( RTL_DYNAMIC_HASH_TABLE *table,
                                                                  RTL_DYNAMIC_HASH_TABLE_ENUMERATOR *enumerator )
{
    ULONG bucket = enumerator->BucketIndex;
    LIST_ENTRY *head, *cursor;

    TRACE("(%p, %p)\n", table, enumerator);

    while (bucket < table->TableSize)
    {
        head = get_bucket_head( table, bucket );
        cursor = bucket == enumerator->BucketIndex ? enumerator->HashEntry.Linkage.Flink : head->Flink;
        while (cursor != head && !CONTAINING_RECORD( cursor, RTL_DYNAMIC_HASH_TABLE_ENTRY, Linkage )->Signature)
            cursor = cursor->Flink;
        if (cursor != head)
        {
            BOOL old_marker_only = enumerator->ChainHead->Flink == &enumerator->HashEntry.Linkage &&
                                   enumerator->ChainHead->Blink == &enumerator->HashEntry.Linkage;
            BOOL new_was_empty = head->Flink == head;

            remove_list_entry( &enumerator->HashEntry.Linkage );
            if (old_marker_only) --table->NonEmptyBuckets;
            if (new_was_empty) ++table->NonEmptyBuckets;
            insert_list_after( cursor, &enumerator->HashEntry.Linkage );
            enumerator->ChainHead = head;
            enumerator->BucketIndex = bucket;
            return CONTAINING_RECORD( cursor, RTL_DYNAMIC_HASH_TABLE_ENTRY, Linkage );
        }
        ++bucket;
    }
    return NULL;
}

void WINAPI RtlEndEnumerationHashTable( RTL_DYNAMIC_HASH_TABLE *table,
                                        RTL_DYNAMIC_HASH_TABLE_ENUMERATOR *enumerator )
{
    TRACE("(%p, %p)\n", table, enumerator);

    --table->NumEnumerators;
    if (enumerator->HashEntry.Linkage.Flink == enumerator->HashEntry.Linkage.Blink)
        --table->NonEmptyBuckets;
    remove_list_entry( &enumerator->HashEntry.Linkage );
    enumerator->ChainHead = NULL;
}

BOOLEAN WINAPI RtlExpandHashTable( RTL_DYNAMIC_HASH_TABLE *table )
{
    LIST_ENTRY **directory, *old_directory = NULL;
    LIST_ENTRY *old_head, *new_head, *cursor, *next;
    ULONG new_bucket = table->TableSize, offset;
    unsigned int segment;
    BOOL old_nonempty;

    TRACE("(%p)\n", table);

    if (table->NumEnumerators || table->TableSize >= HASH_TABLE_MAX_SIZE) return FALSE;
    old_head = get_bucket_head( table, table->Pivot );

    if (table->TableSize == HASH_TABLE_MIN_SIZE)
    {
        old_directory = table->Directory;
        if (!(directory = hash_alloc( HASH_TABLE_DIRECTORY_SIZE * sizeof(*directory) ))) return FALSE;
        memset( directory, 0, HASH_TABLE_DIRECTORY_SIZE * sizeof(*directory) );
        directory[0] = old_directory;
        table->Directory = directory;
    }
    else directory = table->Directory;

    segment = bucket_segment( new_bucket, &offset );
    if (!directory[segment] && !(directory[segment] = alloc_segment( segment )))
    {
        if (old_directory)
        {
            table->Directory = old_directory;
            hash_free( directory );
        }
        return FALSE;
    }

    new_head = directory[segment] + offset;
    init_list( new_head );
    old_nonempty = old_head->Flink != old_head;
    ++table->TableSize;
    ++table->Pivot;

    for (cursor = old_head->Flink; cursor != old_head; cursor = next)
    {
        RTL_DYNAMIC_HASH_TABLE_ENTRY *entry = CONTAINING_RECORD( cursor, RTL_DYNAMIC_HASH_TABLE_ENTRY, Linkage );
        ULONG hash = hash_signature( table, entry->Signature );
        next = cursor->Flink;
        if (hash == new_bucket)
        {
            remove_list_entry( cursor );
            insert_list_after( new_head->Blink, cursor );
        }
    }

    if (old_nonempty && old_head->Flink == old_head) --table->NonEmptyBuckets;
    if (new_head->Flink != new_head) ++table->NonEmptyBuckets;
    if (table->Pivot == table->DivisorMask + 1)
    {
        table->Pivot = 0;
        table->DivisorMask = (table->DivisorMask << 1) | 1;
    }
    return TRUE;
}

BOOLEAN WINAPI RtlContractHashTable( RTL_DYNAMIC_HASH_TABLE *table )
{
    LIST_ENTRY **directory = table->Directory;
    LIST_ENTRY *destination, *source, *cursor, *next;
    BOOL destination_nonempty, source_nonempty;
    ULONG value, offset;
    unsigned int segment;

    TRACE("(%p)\n", table);

    if (table->NumEnumerators || table->TableSize == HASH_TABLE_MIN_SIZE) return FALSE;

    if (!table->Pivot)
    {
        table->DivisorMask >>= 1;
        table->Pivot = table->DivisorMask + 1;
    }
    --table->Pivot;
    --table->TableSize;
    destination = get_bucket_head( table, table->Pivot );
    segment = bucket_segment( table->TableSize, &offset );
    source = directory[segment] + offset;
    destination_nonempty = destination->Flink != destination;
    source_nonempty = source->Flink != source;

    for (cursor = source->Flink; cursor != source; cursor = next)
    {
        LIST_ENTRY *position = destination;
        RTL_DYNAMIC_HASH_TABLE_ENTRY *entry = CONTAINING_RECORD( cursor, RTL_DYNAMIC_HASH_TABLE_ENTRY, Linkage );
        next = cursor->Flink;
        while (position->Flink != destination)
        {
            RTL_DYNAMIC_HASH_TABLE_ENTRY *candidate = CONTAINING_RECORD( position->Flink,
                                                                         RTL_DYNAMIC_HASH_TABLE_ENTRY, Linkage );
            if (candidate->Signature && candidate->Signature >= entry->Signature) break;
            position = position->Flink;
        }
        remove_list_entry( cursor );
        insert_list_after( position, cursor );
    }

    if (source_nonempty && destination_nonempty) --table->NonEmptyBuckets;

    value = table->TableSize + HASH_TABLE_MIN_SIZE;
    if (!(value & (value - 1)))
    {
        hash_free( directory[segment] );
        directory[segment] = NULL;
        if (table->TableSize == HASH_TABLE_MIN_SIZE)
        {
            table->Directory = directory[0];
            hash_free( directory );
        }
    }
    return TRUE;
}
