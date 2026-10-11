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
#include <string.h>

#include "ntstatus.h"
#include "windef.h"
#include "winternl.h"

#include "file.h"
#include "handle.h"
#include "ksec.h"
#include "image_trust.h"
#include "process.h"
#include "request.h"
#include "thread.h"

struct ksec_device
{
    struct object obj;
    process_id_t  lsa_process_id;
    struct async_queue ipc_queue;
    struct async_queue connect_queue;
    struct list ipc_files;
    struct list entry;
    enum { KSEC_IDLE, KSEC_CONNECTING, KSEC_CONNECTED, KSEC_DRAINING } state;
    object_id_t generation;
    struct process *actor;
    struct thread *caller;
    struct ksec_file *origin;
    struct async *connect_async;
    struct event *revoked;
    obj_handle_t revoke_handle;
    unsigned int cleanup_ack;
    unsigned int transport_closed;
    struct object *client_port, *server_port, *listener;
    unsigned int bind_id, call_id, rpc_id, presentation_context;
    const void *bind_request, *call_request;
    unsigned int bound, reply_seen, first, second;
    unsigned char wire_context[20];

};

struct ksec_file
{
    struct object       obj;
    struct fd          *fd;
    struct ksec_device *device;
    struct list ipc_entry; /* retained while the shared IPC queue borrows this fd */
};

static struct list ksec_devices = LIST_INIT(ksec_devices);
static object_id_t next_generation;

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
static int ksec_file_close_handle( struct object *obj, struct process *process, obj_handle_t handle );
static void ksec_revoke( struct ksec_device *device, unsigned int status );

static const struct object_ops ksec_file_ops =
{
    .size          = sizeof(struct ksec_file),
    .type          = &file_type,
    .dump          = ksec_file_dump,
    .get_fd        = ksec_file_get_fd,
    .get_sync      = default_fd_get_sync,
    .get_full_name = ksec_file_get_full_name,
    .close_handle  = ksec_file_close_handle,
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
    init_async_queue( &device->ipc_queue );
    init_async_queue( &device->connect_queue );
    list_init( &device->ipc_files );
    device->state = KSEC_IDLE;
    device->generation = 0;
    device->actor = NULL;
    device->caller = NULL;
    device->origin = NULL;
    device->connect_async = NULL;
    device->revoked = NULL;
    device->revoke_handle = 0;
    device->client_port = device->server_port = device->listener = NULL;
    device->bind_request = device->call_request = NULL;
    device->cleanup_ack = device->transport_closed = device->bound = device->reply_seen = 0;
    device->bind_id = device->call_id = device->rpc_id = device->presentation_context = 0;
    device->first = device->second = 0;
    memset( device->wire_context, 0, sizeof(device->wire_context) );
    list_add_tail( &ksec_devices, &device->entry );
    return true;
}

static void ksec_device_destroy( struct object *obj )
{
    struct ksec_device *device = (struct ksec_device *)obj;

    assert( device->state == KSEC_IDLE );
    list_remove( &device->entry );
    free_async_queue( &device->connect_queue );
    free_async_queue( &device->ipc_queue );
}

static struct object *ksec_device_open_file( struct object *obj, unsigned int access,
                                             unsigned int sharing, unsigned int options )
{
    struct ksec_file *file;

    if (!(file = alloc_object( &ksec_file_ops ))) return NULL;
    file->device = (struct ksec_device *)grab_object( obj );
    list_init( &file->ipc_entry );
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
    assert( list_empty( &file->ipc_entry ) );
    if (file->fd) release_object( file->fd );
    release_object( file->device );
}

static enum server_fd_type ksec_file_get_fd_type( struct fd *fd )
{
    return FD_TYPE_DEVICE;
}

/* The original async and callback each retain the device until terminal completion.
 * Detach the callback before completing here; cancellation calls it through the
 * existing queue, whose reference keeps the async alive through that callback. */
static void ksec_complete_io( struct ksec_device *device, unsigned int status )
{
    struct async *async = device->connect_async;
    const unsigned int system_process_id = KSEC_SYSTEM_PROCESS_ID;

    if (!async) return;
    device->connect_async = NULL;
    async_set_completion_callback( async, NULL, NULL );
    async_set_termination_callback( async, NULL, NULL );
    async_request_complete_alloc( async, status, status ? 0 : sizeof(system_process_id),
                                 status ? 0 : sizeof(system_process_id), &system_process_id );
    release_object( async );
    release_object( device ); /* completion callback reference */
}

static void ksec_revoke( struct ksec_device *device, unsigned int status )
{
    if (device->state == KSEC_IDLE || device->state == KSEC_DRAINING) return;
    device->state = KSEC_DRAINING;
    device->lsa_process_id = 0;
    set_event( device->revoked );
    alpc_cancel_ksec_request( device->bind_request );
    alpc_cancel_ksec_request( device->call_request );
    free_async_queue( &device->ipc_queue );
    init_async_queue( &device->ipc_queue );
    while (!list_empty( &device->ipc_files ))
    {
        struct ksec_file *file = LIST_ENTRY( list_head( &device->ipc_files ), struct ksec_file, ipc_entry );
        list_remove( &file->ipc_entry );
        list_init( &file->ipc_entry );
        release_object( file );
    }
    ksec_complete_io( device, status );
}

static void ksec_connect_completed( void *private )
{
    struct ksec_device *device = private;
    struct async *async = device->connect_async;

    /* The completion is a cancellation/timeout, not a callback receipt. */
    device->connect_async = NULL;
    async_set_termination_callback( async, NULL, NULL );
    ksec_revoke( device, STATUS_CANCELLED );
    release_object( async );
    release_object( device );
}

static void ksec_connect_terminated( void *private, unsigned int status )
{
    struct ksec_device *device = private;
    ksec_revoke( device, status ? status : (unsigned int)STATUS_UNSUCCESSFUL );
}

static void ksec_clear_connection( struct ksec_device *device )
{
    struct ksec_file *origin = device->origin;

    assert( device->state == KSEC_DRAINING && !device->connect_async );
    /* Detach the queue while origin still owns its borrowed fd. The client
     * wait/IOSB retains the terminal result independently of the queue. */
    free_async_queue( &device->connect_queue );
    init_async_queue( &device->connect_queue );
    device->origin = NULL;
    if (device->client_port) release_object( device->client_port );
    if (device->server_port) release_object( device->server_port );
    if (device->listener) release_object( device->listener );
    device->client_port = device->server_port = device->listener = NULL;
    device->state = KSEC_IDLE;
    device->generation = 0;
    device->bind_request = device->call_request = NULL;
    release_object( device->caller );
    release_object( device->actor );
    release_object( device->revoked );
    device->caller = NULL;
    device->actor = NULL;
    device->revoked = NULL;
    device->revoke_handle = 0;
    release_object( origin );
}

static int ksec_file_close_handle( struct object *obj, struct process *process, obj_handle_t handle )
{
    struct ksec_file *file = (struct ksec_file *)obj;
    struct ksec_device *device = file->device;

    /* A foreign duplicate cannot keep the actor's reservation alive. During
     * handle-table destruction the table may already be detached. */
    if (device->origin == file && device->actor == process &&
        get_obj_handle_count( process, obj ) <= 1)
        ksec_revoke( device, STATUS_CANCELLED );
    return async_close_obj_handle( obj, process, handle );
}

void ksec_thread_exit( struct thread *thread )
{
    struct ksec_device *device;

    LIST_FOR_EACH_ENTRY( device, &ksec_devices, struct ksec_device, entry )
        if (device->caller == thread && device->state == KSEC_CONNECTING)
            ksec_revoke( device, STATUS_THREAD_IS_TERMINATING );
}

void ksec_image_unmapped( struct process *process )
{
    struct ksec_device *device;
    LIST_FOR_EACH_ENTRY( device, &ksec_devices, struct ksec_device, entry )
        if (device->actor == process) ksec_revoke( device, STATUS_ACCESS_DENIED );
}

void ksec_process_exit( struct process *process )
{
    struct ksec_device *device, *next;

    LIST_FOR_EACH_ENTRY_SAFE( device, next, &ksec_devices, struct ksec_device, entry )
        if (device->actor == process)
        {
            grab_object( device );
            ksec_revoke( device, STATUS_PROCESS_IS_TERMINATING );
            /* Last-thread death is an independent terminal writer boundary. */
            ksec_clear_connection( device );
            release_object( device );
        }
}

void ksec_ioctl_info( struct fd *fd, object_id_t *generation, obj_handle_t *event )
{
    struct object *obj = get_fd_user( fd );
    struct ksec_file *file;

    if (obj->ops != &ksec_file_ops) return;
    file = (struct ksec_file *)obj;
    if (file->device->origin != file || file->device->caller != current ||
        file->device->state != KSEC_CONNECTING) return;
    *generation = file->device->generation;
    *event = file->device->revoke_handle;
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

            if ((file->device->state != KSEC_CONNECTED || file->device->actor != current->process ||
                !thread_has_ksec_lsa_role( current )))
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
            struct ksec_device *device = file->device;
            struct event *event;
            obj_handle_t handle;

            if (get_req_data_size())
            {
                set_error( STATUS_INVALID_PARAMETER );
                return;
            }
            if (get_reply_max_size() < sizeof(unsigned int))
            {
                set_error( STATUS_BUFFER_TOO_SMALL );
                return;
            }
            if (!thread_has_ksec_lsa_role( current ))
            {
                set_error( STATUS_ACCESS_DENIED );
                return;
            }
            if (device->state != KSEC_IDLE || next_generation == ~(object_id_t)0)
            {
                set_error( STATUS_NOT_SUPPORTED );
                return;
            }
            if (!(event = create_event( NULL, empty_str, 0, 1, 0, NULL ))) return;
            if (!(handle = alloc_handle( current->process, event, SYNCHRONIZE, 0 )))
            {
                release_object( event );
                return;
            }
            device->state = KSEC_CONNECTING;
            device->generation = ++next_generation;
            device->actor = (struct process *)grab_object( current->process );
            device->caller = (struct thread *)grab_object( current );
            device->origin = (struct ksec_file *)grab_object( file );
            device->revoked = event;
            device->revoke_handle = handle;
            device->cleanup_ack = 0;
            device->transport_closed = 1; /* no connection has been bound yet */
            device->bound = device->reply_seen = 0;
            device->bind_id = device->call_id = device->rpc_id = 0;
            device->bind_request = device->call_request = NULL;
            device->connect_async = (struct async *)grab_object( async );
            queue_async( &device->connect_queue, async );
            async_set_completion_callback( async, ksec_connect_completed, grab_object( device ) );
            async_set_termination_callback( async, ksec_connect_terminated, device );
            async_set_timeout( async, -30 * (timeout_t)10000000, STATUS_IO_TIMEOUT );
            set_error( STATUS_PENDING );
            return;
        }

    case IOCTL_KSEC_IPC_GET_QUEUED_FUNCTION_CALLS:
        if ((file->device->state != KSEC_CONNECTED || file->device->actor != current->process ||
                !thread_has_ksec_lsa_role( current )))
        {
            set_error( STATUS_ACCESS_DENIED );
            return;
        }
        if (get_req_data_size() != sizeof(ULONGLONG) || get_reply_max_size() != sizeof(ULONGLONG))
        {
            set_error( STATUS_INVALID_PARAMETER );
            return;
        }
        if (list_empty( &file->ipc_entry ))
        {
            grab_object( file );
            list_add_tail( &file->device->ipc_files, &file->ipc_entry );
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

/* These offsets describe the selected small x64 LRPC packets. They are private
 * transport bindings, not Windows device inputs. Unsupported packet shapes
 * receive no kernel-origin attribute. Never copy a caller-supplied Type bit. */
static unsigned int ksec_word( const unsigned char *data )
{
    unsigned int value;
    memcpy( &value, data, sizeof(value) );
    return value;
}

static int ksec_packet_type( const unsigned char *data, data_size_t size, unsigned int type )
{
    return size >= 8 && ksec_word( data ) == type && !ksec_word( data + 4 );
}

static int ksec_listener_name( struct object *listener )
{
    static const WCHAR expected[] = { '\\','R','P','C',' ','C','o','n','t','r','o','l','\\',
                                      'l','s','a','s','s','p','i','r','p','c' };
    data_size_t len = 0;
    WCHAR *name = default_get_full_name( listener, sizeof(expected), &len );
    int match = name && len == sizeof(expected) &&
                !memcmp( name, expected, len );
    free( name );
    return match;
}

static void ksec_try_drain( struct ksec_device *device )
{
    if (device->state == KSEC_DRAINING && device->cleanup_ack && device->transport_closed)
        ksec_clear_connection( device );
}

int ksec_alpc_message( struct object *source, struct object *target,
                       struct object *listener, struct process *receiver,
                       const void *request, unsigned int id, int reply, const void *buffer, data_size_t size )
{
    static const unsigned char interface_id[] =
        { 0xc8,0xad,0x32,0x4f,0x52,0x60,0x04,0x4a,0x87,0x01,0x29,0x3c,0xcf,0x20,0x96,0xf0 };
    static const unsigned char zero_uuid[16];
    const unsigned char *data = buffer;
    struct ksec_device *device;

    LIST_FOR_EACH_ENTRY( device, &ksec_devices, struct ksec_device, entry )
    {
        if (device->state != KSEC_CONNECTING) continue;
        if (!reply)
        {
            if (device->caller != current || receiver != device->actor ||
                !thread_has_ksec_lsa_role( current )) continue;
            if (!device->client_port)
            {
                if (!listener || !ksec_listener_name( listener ) || size != 0x48 ||
                    !ksec_packet_type( data, size, 1 ) ||
                    memcmp( data + 0x0c, interface_id, sizeof(interface_id) ) ||
                    ksec_word( data + 0x1c ) != 1 || ksec_word( data + 0x20 ) != 1)
                    continue;
                device->client_port = grab_object( source );
                device->server_port = grab_object( target );
                device->listener = grab_object( listener );
                device->bind_id = id;
                device->bind_request = request;
                device->presentation_context = data[0x24] | data[0x25] << 8;
                device->transport_closed = 0;
                return 0; /* Bind is never privileged. */
            }
            if (source != device->client_port || target != device->server_port ||
                listener != device->listener || !device->bound || device->call_id ||
                size != 0x5c || !ksec_packet_type( data, size, 0 ) ||
                ksec_word( data + 0x10 ) != device->presentation_context ||
                ksec_word( data + 0x14 ) != 0 || (ksec_word( data + 8 ) & 4) ||
                !ksec_word( data + 0x40 ) || ksec_word( data + 0x44 ) != 7 ||
                ksec_word( data + 0x48 ) != 0 || ksec_word( data + 0x4c ) != 7 ||
                memcmp( data + 0x50, "KSecDD", 7 ) || ksec_word( data + 0x58 ) != 1)
                continue;
            device->call_id = id;
            device->call_request = request;
            device->rpc_id = ksec_word( data + 0x0c );
            return 1;
        }
        if (source != device->server_port || target != device->client_port ||
            current->process != device->actor || !thread_has_ksec_lsa_role( current )) continue;
        if (id == device->bind_id && request == device->bind_request && !device->bound)
        {
            if (size == 0x48 && ksec_packet_type( data, size, 1 ) &&
                ksec_word( data + 0x20 ) == 1)
                device->bound = 1;
            return 0;
        }
        if (id != device->call_id || request != device->call_request || !id || device->reply_seen) continue;
        /* The selected native provider emits either the NDR32 result extent or
         * a 0x90-byte inline envelope. Its extra bytes are zero, not fields
         * in the context contract. Reject other extents or nonzero tails. */
        if ((size != 0x38 && size != 0x90) ||
            (size == 0x90 && memcmp( data + 0x38, (const unsigned char[0x58]){0}, 0x58 )) ||
            !ksec_packet_type( data, size, 3 ) ||
            (ksec_word( data + 8 ) & 4) || ksec_word( data + 0x0c ) != device->rpc_id ||
            ksec_word( data + 0x34 ) || !memcmp( data + 0x24, zero_uuid, 16 ))
        {
            ksec_revoke( device, STATUS_UNSUCCESSFUL );
            return -1; /* Cancellation may retire request; sender must stop. */
        }
        device->first = ksec_word( data + 0x18 );
        device->second = ksec_word( data + 0x1c );
        memcpy( device->wire_context, data + 0x20, 20 );
        device->reply_seen = 1;
        return 0;
    }
    return 0;
}

void ksec_alpc_request_end( const void *request )
{
    struct ksec_device *device;

    LIST_FOR_EACH_ENTRY( device, &ksec_devices, struct ksec_device, entry )
    {
        if (device->bind_request == request)
        {
            device->bind_request = NULL;
            if (!device->bound) ksec_revoke( device, STATUS_REQUEST_CANCELED );
        }
        if (device->call_request == request)
        {
            device->call_request = NULL;
            if (!device->reply_seen) ksec_revoke( device, STATUS_REQUEST_CANCELED );
        }
    }
}

void ksec_alpc_close( struct object *port )
{
    struct ksec_device *device, *next;

    LIST_FOR_EACH_ENTRY_SAFE( device, next, &ksec_devices, struct ksec_device, entry )
        if (port == device->client_port || port == device->server_port || port == device->listener)
        {
            grab_object( device );
            ksec_revoke( device, STATUS_PORT_DISCONNECTED );
            if (port == device->client_port || port == device->server_port) device->transport_closed = 1;
            ksec_try_drain( device );
            release_object( device );
        }
}

/* An adapter receipt cannot establish authority without the server's paired
 * bind/request/reply observation. Generation checks reject late completions. */
DECL_HANDLER(ksec_connection)
{
    struct ksec_device *device;

    LIST_FOR_EACH_ENTRY( device, &ksec_devices, struct ksec_device, entry )
        if (device->generation == req->generation && device->actor == current->process) break;
    if (&device->entry == &ksec_devices) { set_error( STATUS_INVALID_HANDLE ); return; }
    grab_object( device );
    if (req->cleanup)
    {
        if (device->state != KSEC_DRAINING || req->status)
            set_error( STATUS_INVALID_PARAMETER );
        else
        {
            device->cleanup_ack = 1;
            ksec_try_drain( device );
        }
    }
    else if (device->caller != current || device->state != KSEC_CONNECTING)
        set_error( STATUS_CANCELLED );
    else if (req->status || req->rpc_status || !req->has_context || !device->reply_seen ||
             req->first != device->first || req->second != device->second ||
             !thread_has_ksec_lsa_role( current ))
    {
        ksec_revoke( device, req->status ? req->status : (unsigned int)STATUS_ACCESS_DENIED );
        set_error( req->status ? req->status : (unsigned int)STATUS_ACCESS_DENIED );
    }
    else
    {
        struct iosb *iosb = async_get_iosb( device->connect_async );
        if (iosb->status != STATUS_PENDING)
        {
            ksec_revoke( device, STATUS_CANCELLED );
            set_error( STATUS_CANCELLED );
        }
        else
        {
            device->state = KSEC_CONNECTED;
            device->lsa_process_id = device->actor->id;
            ksec_complete_io( device, STATUS_SUCCESS );
        }
        release_object( iosb );
    }
    release_object( device );
}
