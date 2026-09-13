/*
 * Server-side KsecDD device management
 *
 * Copyright 2026
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
#include "winternl.h"

#include "file.h"
#include "handle.h"
#include "process.h"
#include "request.h"
#include "thread.h"

struct ksec_device
{
    struct object obj;
    process_id_t  lsa_process_id;
    unsigned int  lsa_file_count;
    struct async_queue ipc_queue;
};

struct ksec_file
{
    struct object       obj;
    struct fd          *fd;
    struct ksec_device *device;
    unsigned int        lsa_file;
};

#define IOCTL_KSEC_CONNECT_LSA 0x398000
#define IOCTL_KSEC_DUPLICATE_HANDLE 0x390034
#define IOCTL_KSEC_IPC_GET_QUEUED_FUNCTION_CALLS 0x39006a
#define KSEC_SYSTEM_PROCESS_ID 4

struct ksec_duplicate_handle_request
{
    ULONGLONG source_handle;
    ULONGLONG target_process;
    ULONGLONG package_id;
};

static void ksec_device_dump( struct object *obj, int verbose );
static bool ksec_device_init( struct object *obj, const void *init_data );
static struct object *ksec_device_open_file( struct object *obj, unsigned int access,
                                             unsigned int sharing, unsigned int options );
static void ksec_device_destroy( struct object *obj );

static const struct object_ops ksec_device_ops =
{
    .size      = sizeof(struct ksec_device),
    .type      = &device_type,
    .dump      = ksec_device_dump,
    .init      = ksec_device_init,
    .open_file = ksec_device_open_file,
    .destroy   = ksec_device_destroy,
};

static void ksec_file_dump( struct object *obj, int verbose );
static struct fd *ksec_file_get_fd( struct object *obj );
static WCHAR *ksec_file_get_full_name( struct object *obj, data_size_t max, data_size_t *len );
static void ksec_file_destroy( struct object *obj );

static const struct object_ops ksec_file_ops =
{
    .size          = sizeof(struct ksec_file),
    .type          = &file_type,
    .dump          = ksec_file_dump,
    .get_fd        = ksec_file_get_fd,
    .get_sync      = default_fd_get_sync,
    .get_full_name = ksec_file_get_full_name,
    .destroy       = ksec_file_destroy,
};

static enum server_fd_type ksec_file_get_fd_type( struct fd *fd );
static void ksec_file_ioctl( struct fd *fd, ioctl_code_t code, struct async *async );

static const struct fd_ops ksec_file_fd_ops =
{
    .get_fd_type   = ksec_file_get_fd_type,
    .get_file_info = default_fd_get_file_info,
    .ioctl         = ksec_file_ioctl,
    .queue_async   = default_fd_queue_async,
};

static void ksec_device_dump( struct object *obj, int verbose )
{
    fputs( "KsecDD device\n", stderr );
}

static bool ksec_device_init( struct object *obj, const void *init_data )
{
    struct ksec_device *device = (struct ksec_device *)obj;

    device->lsa_process_id = 0;
    device->lsa_file_count = 0;
    init_async_queue( &device->ipc_queue );
    return true;
}

static void ksec_device_destroy( struct object *obj )
{
    struct ksec_device *device = (struct ksec_device *)obj;

    free_async_queue( &device->ipc_queue );
}

static struct object *ksec_device_open_file( struct object *obj, unsigned int access,
                                             unsigned int sharing, unsigned int options )
{
    struct ksec_file *file;

    if (!(file = alloc_object( &ksec_file_ops ))) return NULL;
    file->device = (struct ksec_device *)grab_object( obj );
    file->lsa_file = file->device->lsa_process_id == current->process->id;
    if (file->lsa_file) file->device->lsa_file_count++;
    if (!(file->fd = alloc_pseudo_fd( &ksec_file_fd_ops, &file->obj, options )))
    {
        release_object( file );
        return NULL;
    }
    allow_fd_caching( file->fd );
    return &file->obj;
}

static void ksec_file_dump( struct object *obj, int verbose )
{
    struct ksec_file *file = (struct ksec_file *)obj;

    fprintf( stderr, "File on KsecDD device %p\n", file->device );
}

static struct fd *ksec_file_get_fd( struct object *obj )
{
    struct ksec_file *file = (struct ksec_file *)obj;
    return (struct fd *)grab_object( file->fd );
}

static WCHAR *ksec_file_get_full_name( struct object *obj, data_size_t max, data_size_t *len )
{
    struct ksec_file *file = (struct ksec_file *)obj;
    WCHAR *ret = default_get_full_name( &file->device->obj, max, len );
    if (*len > max) set_error( STATUS_BUFFER_OVERFLOW );
    return ret;
}

static void ksec_file_destroy( struct object *obj )
{
    struct ksec_file *file = (struct ksec_file *)obj;

    assert( obj->ops == &ksec_file_ops );
    if (file->lsa_file && !--file->device->lsa_file_count) file->device->lsa_process_id = 0;
    if (file->fd) release_object( file->fd );
    release_object( file->device );
}

static enum server_fd_type ksec_file_get_fd_type( struct fd *fd )
{
    return FD_TYPE_DEVICE;
}

static void ksec_file_ioctl( struct fd *fd, ioctl_code_t code, struct async *async )
{
    struct ksec_file *file = get_fd_user( fd );

    if (debug_level)
        fprintf( stderr, "KsecDD ioctl %#x in_size=%u out_size=%u\n", code,
                 get_req_data_size(), get_reply_max_size() );

    switch (code)
    {
    case IOCTL_KSEC_DUPLICATE_HANDLE:
        {
            const struct ksec_duplicate_handle_request *params = get_req_data();
            struct process *target;
            ULONGLONG handle;

            if (file->device->lsa_process_id != current->process->id)
            {
                set_error( STATUS_ACCESS_DENIED );
                return;
            }
            if (get_req_data_size() != sizeof(*params))
            {
                set_error( STATUS_INVALID_PARAMETER );
                return;
            }
            if (get_reply_max_size() < sizeof(handle))
            {
                set_error( STATUS_BUFFER_TOO_SMALL );
                return;
            }
            if (!(target = get_process_from_handle( (obj_handle_t)params->target_process,
                                                     PROCESS_QUERY_LIMITED_INFORMATION )))
                return;

            handle = duplicate_handle( current->process, (obj_handle_t)params->source_handle,
                                       target, 0, 0, DUPLICATE_SAME_ACCESS );
            release_object( target );
            if (!handle) return;

            /* package_id identifies the calling LSA security package on Windows. The
             * Wine server already confines this operation to the registered LSA process. */
            set_reply_data( &handle, sizeof(handle) );
            return;
        }

    case IOCTL_KSEC_CONNECT_LSA:
        {
            const unsigned int system_process_id = KSEC_SYSTEM_PROCESS_ID;

            if (get_req_data_size())
            {
                set_error( STATUS_INVALID_PARAMETER );
                return;
            }
            if (get_reply_max_size() < sizeof(system_process_id))
            {
                set_error( STATUS_BUFFER_TOO_SMALL );
                return;
            }
            if (file->device->lsa_process_id)
            {
                set_error( STATUS_NOT_SUPPORTED );
                return;
            }

            file->device->lsa_process_id = current->process->id;
            file->device->lsa_file_count = 1;
            file->lsa_file = 1;
            set_reply_data( &system_process_id, sizeof(system_process_id) );
            return;
        }

    case IOCTL_KSEC_IPC_GET_QUEUED_FUNCTION_CALLS:
        if (file->device->lsa_process_id != current->process->id)
        {
            set_error( STATUS_ACCESS_DENIED );
            return;
        }
        if (get_req_data_size() != sizeof(ULONGLONG) || get_reply_max_size() != sizeof(ULONGLONG))
        {
            set_error( STATUS_INVALID_PARAMETER );
            return;
        }
        queue_async( &file->device->ipc_queue, async );
        set_error( STATUS_PENDING );
        return;

    default:
        default_fd_ioctl( fd, code, async );
    }
}

struct object *create_ksec_device( struct object *root, struct unicode_str name,
                                   unsigned int attr, const struct security_descriptor *sd )
{
    struct object_params params = { .ops = &ksec_device_ops, .root = root,
                                    .name = name, .attr = attr, .sd = sd };

    return create_named_object( &params );
}
