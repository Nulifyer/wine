/*
 * D3D11 shared fence timelines
 *
 * Copyright 2026 Nulifyer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "ntstatus.h"
#include "windef.h"
#include "winternl.h"

#include "handle.h"
#include "request.h"
#include "security.h"

struct d3d11_fence_waiter
{
    struct list entry;
    unsigned __int64 value;
    struct event *event;
};

struct d3d11_fence
{
    struct object obj;
    unsigned int flags;
    unsigned __int64 value;
    struct list waiters;
};

struct d3d11_shared_fence
{
    struct object obj;
    struct d3d11_fence *fence;
};

static const WCHAR d3d11_shared_fence_name[] =
    {'D','3','D','1','1','S','h','a','r','e','d','F','e','n','c','e'};

static struct type_descr d3d11_shared_fence_type =
{
    { d3d11_shared_fence_name, sizeof(d3d11_shared_fence_name) },
    STANDARD_RIGHTS_ALL | SYNCHRONIZE,
    {
        STANDARD_RIGHTS_READ,
        STANDARD_RIGHTS_WRITE,
        STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,
        STANDARD_RIGHTS_ALL | SYNCHRONIZE,
    },
};

static void d3d11_fence_dump(struct object *obj, int verbose)
{
    struct d3d11_fence *fence = (struct d3d11_fence *)obj;

    assert(obj->ops->size == sizeof(*fence));
    fprintf(stderr, "D3D11 fence value=%016llx flags=%#x\n",
            (unsigned long long)fence->value, fence->flags);
}

static void d3d11_fence_destroy(struct object *obj)
{
    struct d3d11_fence *fence = (struct d3d11_fence *)obj;
    struct d3d11_fence_waiter *waiter, *next;

    LIST_FOR_EACH_ENTRY_SAFE(waiter, next, &fence->waiters, struct d3d11_fence_waiter, entry)
    {
        release_object(waiter->event);
        list_remove(&waiter->entry);
        free(waiter);
    }
}

static const struct object_ops d3d11_fence_ops =
{
    .size = sizeof(struct d3d11_fence),
    .type = &no_type,
    .dump = d3d11_fence_dump,
    .destroy = d3d11_fence_destroy,
};

static void d3d11_shared_fence_dump(struct object *obj, int verbose)
{
    struct d3d11_shared_fence *shared = (struct d3d11_shared_fence *)obj;

    assert(obj->ops->size == sizeof(*shared));
    fprintf(stderr, "D3D11 shared fence fence=%p\n", shared->fence);
}

static bool d3d11_shared_fence_init(struct object *obj, const void *init_data)
{
    struct d3d11_shared_fence *shared = (struct d3d11_shared_fence *)obj;

    shared->fence = (struct d3d11_fence *)grab_object((void *)init_data);
    return true;
}

static void d3d11_shared_fence_destroy(struct object *obj)
{
    struct d3d11_shared_fence *shared = (struct d3d11_shared_fence *)obj;

    if (shared->fence) release_object(shared->fence);
}

static const struct object_ops d3d11_shared_fence_ops =
{
    .size = sizeof(struct d3d11_shared_fence),
    .type = &d3d11_shared_fence_type,
    .dump = d3d11_shared_fence_dump,
    .init = d3d11_shared_fence_init,
    .destroy = d3d11_shared_fence_destroy,
};

static struct d3d11_fence *get_d3d11_fence(obj_handle_t handle)
{
    return (struct d3d11_fence *)get_handle_obj(current->process, handle, 0, &d3d11_fence_ops);
}

DECL_HANDLER(create_d3d11_fence)
{
    struct d3d11_fence *fence;

    if (!(fence = alloc_object(&d3d11_fence_ops))) return;
    fence->flags = req->flags;
    fence->value = req->value;
    list_init(&fence->waiters);
    /* This handle is private to d3d11.dll and is only used as an object
     * identity in the fence protocol.  It must not inherit the caller's
     * object DACL or expose user-visible access rights. */
    reply->handle = alloc_handle_no_access_check(current->process, fence, 0, 0);
    release_object(fence);
}

DECL_HANDLER(share_d3d11_fence)
{
    struct d3d11_shared_fence *shared;
    struct d3d11_fence *fence;
    struct object_params params =
    {
        .ops = &d3d11_shared_fence_ops,
        .access = req->access,
    };

    if (!(fence = get_d3d11_fence(req->fence))) return;
    if (!get_req_object_attributes(&params)) goto done;
    params.init_data = fence;
    if (!(shared = create_named_object(&params))) goto done_params;
    if (get_error() == STATUS_OBJECT_NAME_EXISTS)
    {
        release_object(shared);
        goto done_params;
    }
    /* create_named_obj_handle() also skips the access check for a newly
     * created object.  Do the same here; the requested access is still
     * mapped onto the returned handle. */
    reply->handle = alloc_handle_no_access_check(current->process, shared,
            req->access, params.attr);
    release_object(shared);

done_params:
    if (params.root) release_object(params.root);
done:
    release_object(fence);
}

DECL_HANDLER(open_d3d11_fence)
{
    struct d3d11_shared_fence *shared;

    if (!(shared = (struct d3d11_shared_fence *)get_handle_obj(current->process, req->handle,
            0, &d3d11_shared_fence_ops))) return;
    reply->fence = alloc_handle(current->process, shared->fence, STANDARD_RIGHTS_ALL, 0);
    reply->flags = shared->fence->flags;
    release_object(shared);
}

DECL_HANDLER(query_d3d11_fence)
{
    struct d3d11_fence *fence;

    if (!(fence = get_d3d11_fence(req->fence))) return;
    reply->value = fence->value;
    release_object(fence);
}

DECL_HANDLER(signal_d3d11_fence)
{
    struct d3d11_fence_waiter *waiter, *next;
    struct d3d11_fence *fence;

    if (!(fence = get_d3d11_fence(req->fence))) return;
    fence->value = req->value;
    LIST_FOR_EACH_ENTRY_SAFE(waiter, next, &fence->waiters, struct d3d11_fence_waiter, entry)
    {
        if (waiter->value > fence->value) continue;
        set_event(waiter->event);
        release_object(waiter->event);
        list_remove(&waiter->entry);
        free(waiter);
    }
    release_object(fence);
}

DECL_HANDLER(set_d3d11_fence_event)
{
    struct d3d11_fence_waiter *waiter;
    struct d3d11_fence *fence;
    struct event *event;

    if (!(fence = get_d3d11_fence(req->fence))) return;
    if (!(event = get_event_obj(current->process, req->event, EVENT_MODIFY_STATE))) goto done;
    if (fence->value >= req->value)
    {
        set_event(event);
        release_object(event);
        goto done;
    }
    if (!(waiter = mem_alloc(sizeof(*waiter))))
    {
        release_object(event);
        goto done;
    }
    waiter->value = req->value;
    waiter->event = event;
    list_add_tail(&fence->waiters, &waiter->entry);

done:
    release_object(fence);
}
