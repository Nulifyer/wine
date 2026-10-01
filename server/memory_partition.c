/*
 * Server-side system memory partition objects
 *
 * Copyright 2026 LinuxNT project
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "config.h"

#include <assert.h>
#include <stdio.h>

#include "ntstatus.h"
#include "windef.h"
#include "winnt.h"

#include "handle.h"
#include "request.h"
#include "security.h"

#define MEMORY_PARTITION_QUERY_ACCESS  0x0001
#define MEMORY_PARTITION_MODIFY_ACCESS 0x0002
#define MEMORY_PARTITION_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
                                     MEMORY_PARTITION_QUERY_ACCESS | MEMORY_PARTITION_MODIFY_ACCESS)

static const WCHAR memory_partition_type_name[] = {'P','a','r','t','i','t','i','o','n'};

struct type_descr memory_partition_type =
{
    { memory_partition_type_name, sizeof(memory_partition_type_name) },
    MEMORY_PARTITION_ALL_ACCESS,
    {
        STANDARD_RIGHTS_READ | MEMORY_PARTITION_QUERY_ACCESS,
        STANDARD_RIGHTS_WRITE | MEMORY_PARTITION_MODIFY_ACCESS,
        STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,
        MEMORY_PARTITION_ALL_ACCESS
    },
};

struct memory_partition
{
    struct object obj;
};

static void memory_partition_dump( struct object *obj, int verbose );

static const struct object_ops memory_partition_ops =
{
    .size = sizeof(struct memory_partition),
    .type = &memory_partition_type,
    .dump = memory_partition_dump,
};

static void memory_partition_dump( struct object *obj, int verbose )
{
    assert( obj->ops == &memory_partition_ops );
    fputs( "Memory partition\n", stderr );
}

static struct memory_partition *create_memory_partition( struct object *root, struct unicode_str name,
                                                         unsigned int attr )
{
    struct object_params params = { .ops = &memory_partition_ops, .root = root,
                                    .name = name, .attr = attr };

    return create_named_object( &params );
}

void create_system_memory_objects( struct object *kernel_dir )
{
    static const WCHAR partitionW[] = {'M','e','m','o','r','y','P','a','r','t','i','t','i','o','n','0'};
    static const WCHAR lowW[] = {'L','o','w','C','o','m','m','i','t','C','o','n','d','i','t','i','o','n'};
    static const WCHAR highW[] = {'H','i','g','h','C','o','m','m','i','t','C','o','n','d','i','t','i','o','n'};
    static const WCHAR maximumW[] = {'M','a','x','i','m','u','m','C','o','m','m','i','t','C','o','n','d','i','t','i','o','n'};
    static const struct unicode_str partition = { partitionW, sizeof(partitionW) };
    static const struct unicode_str low = { lowW, sizeof(lowW) };
    static const struct unicode_str high = { highW, sizeof(highW) };
    static const struct unicode_str maximum = { maximumW, sizeof(maximumW) };

    release_object( create_memory_partition( kernel_dir, partition, OBJ_PERMANENT ) );
    release_object( create_event( kernel_dir, low, OBJ_PERMANENT, TRUE, FALSE, NULL ) );
    release_object( create_event( kernel_dir, high, OBJ_PERMANENT, TRUE, FALSE, NULL ) );
    release_object( create_event( kernel_dir, maximum, OBJ_PERMANENT, TRUE, FALSE, NULL ) );
}

DECL_HANDLER(open_memory_partition)
{
    reply->handle = open_object( current->process, req->rootdir, req->access,
                                 &memory_partition_ops, get_req_unicode_str(), req->attributes );
}

DECL_HANDLER(query_memory_partition)
{
    struct object *partition;

    if ((partition = get_handle_obj( current->process, req->handle, MEMORY_PARTITION_QUERY_ACCESS,
                                     &memory_partition_ops )))
        release_object( partition );
}
