/*
 * Server-side advanced local procedure call management
 *
 * Copyright 2026 Zhiyi Zhang for CodeWeavers
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 */

#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>

#include "windef.h"
#include "winternl.h"
#include "ntstatus.h"

#include "handle.h"
#include "process.h"
#include "thread.h"
#include "security.h"
#include "request.h"

static const WCHAR alpc_port_name[] = {'A','L','P','C',' ','P','o','r','t'};

struct type_descr alpc_port_type =
{
    { alpc_port_name, sizeof(alpc_port_name) }, /* name */
    ALPC_PORT_ALL_ACCESS,                       /* valid_access */
    {                                           /* mapping */
         STANDARD_RIGHTS_READ | ALPC_PORT_QUERY_STATE,
         DELETE | ALPC_PORT_QUERY_STATE,
         0,
         ALPC_PORT_ALL_ACCESS
    },
};

enum alpc_port_enum_type
{
    CONNECTION_PORT,
    COMMUNICATION_PORT
};

enum alpc_port_status
{
    UNINITIALIZED,
    CONNECTED,
    REFUSED,
    DISCONNECTED
};

struct alpc_port
{
    struct object            obj;                   /* object header */
    struct object           *sync;                  /* waitable queue state */
    struct list              messages;              /* owned copies, in send order */
    struct alpc_port        *peer;                  /* strong, detached on final handle close */
    struct alpc_port        *connection_port;       /* strong parent of an accepted server port */
    struct alpc_port        *pending_listener;      /* weak; listener owns pending list reference */
    struct list             accepted_connections; /* weak children; each child retains this listener */
    struct list             accepted_entry;
    struct list             pending_connections;
    struct list             pending_entry;
    struct alpc_message    *connect_reply;          /* owned until connection result is fetched */
    unsigned int            connection_id;
    unsigned int            connect_status;
    unsigned int            request_delivered;
    unsigned int            want_reply;
    struct list             connecting_entry;      /* weak, while NTDLL owns the temporary handle */
    obj_handle_t            connecting_handle;
    unsigned int            wow64;
    client_ptr_t            context;
    enum alpc_port_enum_type type;                  /* communication port or connection port */
    enum alpc_port_status    status;                /* port status */
    struct thread           *thread;                /* thread owning the port */
    unsigned int             flags;                 /* flags in port attributes */
    mem_size_t               max_msg_len;           /* max message length in port attributes */
};

/* The registry owns each live request. Endpoint pointers are weak: final
 * handle close removes every request using that endpoint before destruction.
 * A queued message points back only while its copy remains in a port queue. */
struct alpc_request
{
    struct list entry;
    struct alpc_port *source, *target, *queue;
    struct alpc_message *message;
    struct alpc_wait *wait; /* weak; its private handle owns the blocking call */
    unsigned int id, wow64, canceled, released;
    process_id_t pid;
    thread_id_t tid;
};

struct alpc_wait
{
    struct object obj;
    struct object *sync;
    struct thread *thread;
    struct list entry; /* weak operation registry for thread-exit cleanup */
    obj_handle_t handle;
    struct alpc_request *request; /* weak; cleared when request ownership changes */
    struct alpc_message *reply; /* owned reply for a successful blocking call */
    data_size_t capacity, required_size;
    unsigned int status;
};
static struct list message_waits = LIST_INIT(message_waits);
static void cleanup_thread_message_waits( struct thread *thread );

static struct list message_requests = LIST_INIT(message_requests);

struct alpc_message
{
    struct list entry;
    struct alpc_request *request;
    unsigned int id, type;
    process_id_t pid;
    thread_id_t tid;
    data_size_t size;
    unsigned char data[];
};

struct alpc_port_init_data
{
    enum alpc_port_enum_type type;
    unsigned int             flags;
    mem_size_t               max_msg_len;
};

static void alpc_port_dump( struct object *obj, int verbose );
static bool alpc_port_init( struct object *obj, const void *init_data );
static void alpc_port_destroy( struct object *obj );
static struct object *alpc_port_get_sync( struct object *obj );
static int alpc_port_close_handle( struct object *obj, struct process *process, obj_handle_t handle );

static const struct object_ops alpc_port_ops =
{
    .size         = sizeof(struct alpc_port),
    .type         = &alpc_port_type,
    .dump         = alpc_port_dump,
    .init         = alpc_port_init,
    .add_queue    = add_queue,
    .remove_queue = remove_queue,
    .get_sync     = alpc_port_get_sync,
    .close_handle = alpc_port_close_handle,
    .destroy      = alpc_port_destroy
};

static void alpc_port_dump( struct object *obj, int verbose )
{
    struct alpc_port *port = (struct alpc_port *)obj;
    assert( obj->ops == &alpc_port_ops );
    fprintf( stderr, "ALPC Port type=%d status=%d\n", port->type, port->status );
}

static bool alpc_port_init( struct object *obj, const void *init_data )
{
    struct alpc_port *port = (struct alpc_port *)obj;
    const struct alpc_port_init_data *data = init_data;

    port->type        = data->type;
    port->flags       = data->flags;
    port->max_msg_len = data->max_msg_len;
    port->status      = UNINITIALIZED;
    port->thread      = (struct thread *)grab_object( current );
    list_init( &port->messages );
    list_init( &port->accepted_connections );
    list_init( &port->accepted_entry );
    list_init( &port->pending_connections );
    list_init( &port->pending_entry );
    port->peer = NULL;
    port->connection_port = NULL;
    port->pending_listener = NULL;
    port->connect_reply = NULL;
    port->connection_id = 0;
    port->connect_status = STATUS_PENDING;
    port->request_delivered = 0;
    port->want_reply = 0;
    list_init( &port->connecting_entry );
    port->connecting_handle = 0;
    port->wow64 = 0;
    port->context = 0;
    return !!(port->sync = create_internal_sync( 1, 0 ));
}

static struct object *alpc_port_get_sync( struct object *obj )
{
    struct alpc_port *port = (struct alpc_port *)obj;
    if (!(port->flags & 0x40000))
    {
        set_error( STATUS_OBJECT_TYPE_MISMATCH );
        return NULL;
    }
    return grab_object( port->sync );
}

static void alpc_port_destroy( struct object *obj )
{
    struct alpc_port *port = (struct alpc_port *)obj;
    struct alpc_message *message, *next;

    assert( obj->ops == &alpc_port_ops );

    LIST_FOR_EACH_ENTRY_SAFE( message, next, &port->messages, struct alpc_message, entry )
    {
        list_remove( &message->entry );
        free( message );
    }
    assert( !port->peer && !port->pending_listener && list_empty( &port->pending_connections ) );
    free( port->connect_reply );
    if (port->connection_port)
    {
        list_remove( &port->accepted_entry );
        release_object( port->connection_port );
    }
    if (port->sync) release_object( port->sync );
    release_object( port->thread );
}

static unsigned int next_message_id;
static struct list connecting_ports = LIST_INIT(connecting_ports);

static void finish_connect_operation( struct alpc_port *port )
{
    if (!port->connecting_handle) return;
    list_remove( &port->connecting_entry );
    port->connecting_handle = 0;
}

void cleanup_thread_alpc( struct thread *thread )
{
    struct alpc_port *port, *next;
    LIST_FOR_EACH_ENTRY_SAFE( port, next, &connecting_ports, struct alpc_port, connecting_entry )
        if (port->thread == thread) close_handle( thread->process, port->connecting_handle );
    cleanup_thread_message_waits( thread );
}

static struct alpc_message *new_message( const void *data, data_size_t size, unsigned int type,
                                        unsigned int id, struct thread *sender )
{
    struct alpc_message *message;
    if (!(message = mem_alloc( sizeof(*message) + size ))) return NULL;
    if (!id && !(id = ++next_message_id)) id = ++next_message_id;
    message->request = NULL;
    message->id = id;
    message->type = type;
    message->pid = sender->process->id;
    message->tid = sender->id;
    message->size = size;
    if (size) memcpy( message->data, data, size );
    return message;
}

static void unlink_pending( struct alpc_port *client )
{
    assert( client->pending_listener );
    list_remove( &client->pending_entry );
    client->pending_listener = NULL;
    release_object( client );
}

static void lose_message_wait( struct alpc_request *request )
{
    struct alpc_wait *wait = request->wait;
    if (!wait) return;
    request->wait = NULL;
    wait->request = NULL;
    wait->status = STATUS_MESSAGE_LOST;
    signal_sync( wait->sync );
}

static void free_message_request( struct alpc_request *request )
{
    if (request->message) request->message->request = NULL;
    lose_message_wait( request );
    list_remove( &request->entry );
    free( request );
}

static struct alpc_port *message_queue( struct alpc_port *endpoint );

/* Canceling an undelivered request retains its queue position. A listener
 * closing returns cancellations to the originating endpoints instead. */
static struct alpc_message *new_cancellation( struct alpc_request *request )
{
    struct alpc_message *message;
    if (!(message = new_message( NULL, 0, ALPC_MESSAGE_TYPE_CANCELED |
                                (request->wow64 ? 0x1000 : 0), request->id, request->target->thread ))) return NULL;
    message->pid = request->pid;
    message->tid = request->tid;
    return message;
}

static void cancel_message_request( struct alpc_request *request, struct alpc_port *queue )
{
    struct alpc_message *message = request->message;
    int delivered = !message;
    if (!message)
    {
        if ((message = new_cancellation( request ))) list_add_tail( &queue->messages, &message->entry );
    }
    else
    {
        if (queue != request->queue)
        {
            list_remove( &message->entry );
            list_add_tail( &queue->messages, &message->entry );
        }
        message->size = 0;
        message->type = ALPC_MESSAGE_TYPE_CANCELED | (message->type & 0x1000);
    }
    if (message) signal_sync( queue->sync );
    if (delivered && queue == request->queue)
    {
        request->source = NULL;
        request->canceled = 1;
        request->message = message;
        if (message) message->request = request;
    }
    else free_message_request( request );
}

static void alpc_wait_dump( struct object *obj, int verbose )
{
    struct alpc_wait *wait = (struct alpc_wait *)obj;
    fprintf( stderr, "ALPC message wait status=%08x\n", wait->status );
}

static struct object *alpc_wait_get_sync( struct object *obj )
{
    return grab_object( ((struct alpc_wait *)obj)->sync );
}

static int alpc_wait_close_handle( struct object *obj, struct process *process, obj_handle_t handle )
{
    struct alpc_wait *wait = (struct alpc_wait *)obj;
    struct alpc_request *request = wait->request;
    if (process != wait->thread->process || handle != wait->handle) return 1;
    list_remove( &wait->entry );
    wait->handle = 0;
    if (request)
    {
        wait->request = NULL;
        request->wait = NULL;
        if (request->target->status == DISCONNECTED && !request->message) free_message_request( request );
        else cancel_message_request( request, request->queue );
    }
    return 1;
}

static void alpc_wait_destroy( struct object *obj )
{
    struct alpc_wait *wait = (struct alpc_wait *)obj;
    assert( !wait->request && !wait->handle );
    free( wait->reply );
    if (wait->sync) release_object( wait->sync );
    release_object( wait->thread );
}

static const struct object_ops alpc_wait_ops =
{
    .size = sizeof(struct alpc_wait),
    .type = &no_type,
    .dump = alpc_wait_dump,
    .add_queue = add_queue,
    .remove_queue = remove_queue,
    .get_sync = alpc_wait_get_sync,
    .close_handle = alpc_wait_close_handle,
    .destroy = alpc_wait_destroy
};

static struct alpc_wait *create_message_wait( data_size_t capacity )
{
    struct alpc_wait *wait;
    if (!(wait = alloc_object( &alpc_wait_ops ))) return NULL;
    wait->thread = (struct thread *)grab_object( current );
    wait->sync = NULL;
    wait->handle = 0;
    wait->request = NULL;
    wait->reply = NULL;
    wait->capacity = capacity;
    wait->required_size = 0;
    wait->status = STATUS_PENDING;
    list_init( &wait->entry );
    if (!(wait->sync = create_internal_sync( 1, 0 )) ||
        !(wait->handle = alloc_handle( current->process, wait, SYNCHRONIZE, 0 )))
    {
        release_object( wait );
        return NULL;
    }
    list_add_tail( &message_waits, &wait->entry );
    return wait;
}

static void cleanup_thread_message_waits( struct thread *thread )
{
    struct alpc_wait *wait, *next;
    LIST_FOR_EACH_ENTRY_SAFE( wait, next, &message_waits, struct alpc_wait, entry )
        if (wait->thread == thread) close_handle( thread->process, wait->handle );
}

static void close_message_requests( struct alpc_port *port )
{
    struct alpc_request *request, *next;
    LIST_FOR_EACH_ENTRY_SAFE( request, next, &message_requests, struct alpc_request, entry )
    {
        if (request->source == port)
        {
            lose_message_wait( request );
            cancel_message_request( request, request->queue );
        }
        else if (request->queue == port && request->source && request->source != port && !request->wait)
            cancel_message_request( request, message_queue( request->source ) );
        else if (request->target == port || request->queue == port)
        {
            if (request->message)
            {
                list_remove( &request->message->entry );
                free( request->message );
                request->message = NULL;
            }
            free_message_request( request );
        }
    }
}

static void disconnect_message_requests( struct alpc_port *port )
{
    struct alpc_request *request, *next;
    LIST_FOR_EACH_ENTRY_SAFE( request, next, &message_requests, struct alpc_request, entry )
        if (request->source == port)
        {
            struct alpc_message *copy;
            int synchronous = !!request->wait;
            lose_message_wait( request );
            if (!synchronous && (copy = new_cancellation( request )))
            {
                list_add_tail( &message_queue( port )->messages, &copy->entry );
                signal_sync( message_queue( port )->sync );
            }
            cancel_message_request( request, request->queue );
        }
}

static void queue_port_closed( struct alpc_port *port )
{
    struct alpc_port *queue;
    struct alpc_message *message;
    timeout_t start_time = port->thread->process->start_time;
    if (!port->peer) return;
    queue = message_queue( port->peer );
    if (!(message = new_message( &start_time, sizeof(start_time), ALPC_MESSAGE_TYPE_PORT_CLOSED |
                                (port->wow64 ? 0x1000 : 0), 0, port->thread ))) return;
    message->pid = message->tid = 0;
    list_add_tail( &queue->messages, &message->entry );
    signal_sync( queue->sync );
}

/* Server communication handles send through their peer but receive through
 * their listener. Client endpoints have their own incoming queue. */
static struct alpc_port *message_queue( struct alpc_port *endpoint )
{
    return endpoint->connection_port ? endpoint->connection_port : endpoint;
}

static int send_message( struct alpc_port *port, unsigned int flags, unsigned int id,
                         int wow64, const void *data, data_size_t size, struct alpc_wait *wait )
{
    struct alpc_port *target = port, *queue;
    struct alpc_request *request = NULL, *candidate;
    struct alpc_message *message;
    unsigned int type = flags & 0x10000 ? 3 : 0x2001;

    if (port->type == COMMUNICATION_PORT)
    {
        if (port->status == DISCONNECTED || (!port->peer && !id))
        {
            set_error( STATUS_PORT_DISCONNECTED );
            return 0;
        }
        target = port->peer;
    }
    if (id)
    {
        LIST_FOR_EACH_ENTRY( candidate, &message_requests, struct alpc_request, entry )
            if (candidate->id == id) { request = candidate; break; }
        if (!request)
        {
            set_error( STATUS_INVALID_MESSAGE );
            return 0;
        }
        if (request->target != port)
        {
            set_error( STATUS_ACCESS_DENIED );
            return 0;
        }
        if (request->canceled)
        {
            if (request->message)
            {
                list_remove( &request->message->entry );
                free( request->message );
                request->message = NULL;
            }
            free_message_request( request );
            set_error( STATUS_REQUEST_CANCELED );
            return 0;
        }
        if (request->message)
        {
            set_error( STATUS_INVALID_MESSAGE );
            return 0;
        }
        target = request->source;
        type = flags & 0x10000 ? 2 : 0x2001;
    }
    queue = message_queue( target );
    if (size > 65535 - sizeof(ALPC_PORT_MESSAGE) || size + sizeof(ALPC_PORT_MESSAGE) > port->max_msg_len)
    {
        set_error( STATUS_PORT_MESSAGE_TOO_LONG );
        return 0;
    }
    if (!(message = new_message( data, size, type | (wow64 ? 0x1000 : 0), id, current ))) return 0;
    if (!request && !(flags & 0x10000) && port->type == COMMUNICATION_PORT)
    {
        if (!(request = mem_alloc( sizeof(*request) ))) { free( message ); return 0; }
        request->wait = NULL;
        request->released = 0;
        request->id = message->id;
        request->message = NULL;
        list_add_tail( &message_requests, &request->entry );
    }
    if (request && request->wait)
    {
        struct alpc_wait *receiver = request->wait;
        receiver->required_size = message->size;
        receiver->request = NULL;
        request->wait = NULL;
        if (message->size <= receiver->capacity)
        {
            receiver->reply = message;
            receiver->status = STATUS_SUCCESS;
            signal_sync( receiver->sync );
            if (flags & 0x10000) free_message_request( request );
            else
            {
                request->source = port;
                request->target = target;
                request->queue = queue;
                request->pid = current->process->id;
                request->tid = current->id;
                request->wow64 = wow64;
            }
            return 1;
        }
        receiver->status = STATUS_BUFFER_TOO_SMALL;
        signal_sync( receiver->sync );
        /* A short synchronous receive leaves its reply queued. The receiver
         * owns it until a later receive, even when the sender released it. */
        request->released = !!(flags & 0x10000);
        flags &= ~0x10000;
    }
    if (request)
    {
        if (flags & 0x10000) free_message_request( request );
        else
        {
            request->wait = wait;
            if (wait) wait->request = request;
            request->source = port;
            request->wow64 = wow64;
            request->canceled = 0;
            request->pid = current->process->id;
            request->tid = current->id;
            request->target = target;
            request->queue = queue;
            request->message = message;
            message->request = request;
        }
    }
    list_add_tail( &queue->messages, &message->entry );
    signal_sync( queue->sync );
    return 1;
}

static void detach_peer( struct alpc_port *port )
{
    struct alpc_port *peer = port->peer;
    if (!peer) return;
    port->peer = NULL;
    assert( peer->peer == port );
    peer->peer = NULL;
    signal_sync( peer->sync );
    release_object( port );
    release_object( peer );
}

/* The port handle keeps its object alive throughout this callback. */
static int alpc_port_close_handle( struct object *obj, struct process *process, obj_handle_t handle )
{
    struct alpc_port *port = (struct alpc_port *)obj, *client, *next;
    struct alpc_message *message;

    int cancel_operation = process == port->thread->process && handle == port->connecting_handle;

    if (cancel_operation) finish_connect_operation( port );
    if (obj->handle_count != 1 && !cancel_operation) return 1;
    if (port->pending_listener)
    {
        struct alpc_port *listener = port->pending_listener;
        /* Convert an undelivered request to a cancellation notification.
         * If it was already received, publish a new notification with its ID. */
        LIST_FOR_EACH_ENTRY( message, &listener->messages, struct alpc_message, entry )
            if (message->id == port->connection_id) break;
        if (&message->entry != &listener->messages)
        {
            message->size = 0;
            message->type = ALPC_MESSAGE_TYPE_CANCELED | (port->wow64 ? 0x1000 : 0);
        }
        else if ((message = new_message( NULL, 0, ALPC_MESSAGE_TYPE_CANCELED |
                                         (port->wow64 ? 0x1000 : 0), port->connection_id, port->thread )))
            list_add_tail( &listener->messages, &message->entry );
        signal_sync( listener->sync );
        unlink_pending( port );
    }
    LIST_FOR_EACH_ENTRY_SAFE( client, next, &port->pending_connections, struct alpc_port, pending_entry )
    {
        client->connect_status = STATUS_MESSAGE_LOST;
        signal_sync( client->sync );
        unlink_pending( client );
    }
    close_message_requests( port );
    queue_port_closed( port );
    LIST_FOR_EACH_ENTRY_SAFE( client, next, &port->accepted_connections, struct alpc_port, accepted_entry )
        detach_peer( client );
    port->status = DISCONNECTED;
    detach_peer( port );
    return 1;
}

/* Create an ALPC port */
DECL_HANDLER(alpc_create_port)
{
    struct alpc_port_init_data data = { .type = CONNECTION_PORT, .flags = req->flags,
                                        .max_msg_len = req->max_msg_len };
    struct object_params params = { .ops = &alpc_port_ops, .init_data = &data,
                                    .access = ALPC_PORT_ALL_ACCESS };

    if (!get_req_object_attributes( &params )) return;
    reply->handle = create_named_obj_handle( current->process, &params );
    if (params.root) release_object( params.root );
}

/* The listening-port queue is shared by every duplicate of its handle. */
DECL_HANDLER(alpc_send_receive)
{
    struct alpc_port *port;
    struct alpc_message *message;
    data_size_t size = get_req_data_size();
    struct alpc_wait *wait = NULL;

    if (!(port = (struct alpc_port *)get_handle_obj( current->process, req->handle,
                                                    ALPC_PORT_ALL_ACCESS, &alpc_port_ops ))) return;
    if (port->thread->process != current->process)
    {
        set_error( STATUS_ACCESS_DENIED );
        goto done;
    }
    if (req->flags & ~(1 | 0x10000 | 0x20000) || !(port->flags & 0x40000) ||
        (port->type == CONNECTION_PORT && (req->message_id || (req->flags & 0x20000))) ||
        ((req->flags & 0x20000) && (!req->send || !req->receive || req->message_id || (req->flags & 0x10000))))
    {
        set_error( STATUS_NOT_IMPLEMENTED );
        goto done;
    }
    if ((req->flags & 0x20000) && !(wait = create_message_wait( get_reply_max_size() ))) goto done;
    if (req->send && !send_message( port, req->flags, req->message_id, req->wow64,
                                    get_req_data(), size, wait )) goto done;
    if (wait)
    {
        reply->wait_handle = wait->handle;
        set_error( STATUS_PENDING );
        goto done;
    }
    if (!req->receive) goto done;
    if (list_empty( &port->messages ))
    {
        set_error( port->connection_port ? STATUS_TIMEOUT : STATUS_UNSUCCESSFUL );
        goto done;
    }
    message = LIST_ENTRY( list_head( &port->messages ), struct alpc_message, entry );
    reply->message_size = message->size;
    if (message->size > get_reply_max_size())
    {
        set_error( STATUS_BUFFER_TOO_SMALL );
        goto done;
    }
    reply->message_id = message->id;
    reply->message_type = message->type;
    reply->sender_pid = message->pid;
    reply->sender_tid = message->tid;
    if (message->size && !set_reply_data( message->data, message->size )) goto done;
    if ((message->type & 0xff) == ALPC_MESSAGE_TYPE_CONNECTION_REQUEST)
    {
        struct alpc_port *client;
        LIST_FOR_EACH_ENTRY( client, &port->pending_connections, struct alpc_port, pending_entry )
            if (client->connection_id == message->id) client->request_delivered = 1;
    }
    if (message->request)
    {
        message->request->message = NULL;
        if (message->request->canceled || message->request->released) free_message_request( message->request );
    }
    list_remove( &message->entry );
    /* Received replies retain their signal; requests and datagrams clear it. */
    if ((message->type & 0xff) != 2) reset_sync( port->sync );
    free( message );

done:
    if (wait)
    {
        if (!reply->wait_handle) close_handle( current->process, wait->handle );
        release_object( wait );
    }
    release_object( port );
}

/* A blocking call can retrieve only its own private wait result. */
DECL_HANDLER(alpc_get_message_result)
{
    struct alpc_wait *wait;
    struct alpc_message *message;
    if (!(wait = (struct alpc_wait *)get_handle_obj( current->process, req->handle, 0, &alpc_wait_ops ))) return;
    if (wait->thread != current || wait->handle != req->handle) set_error( STATUS_ACCESS_DENIED );
    else
    {
        reply->message_size = wait->required_size;
        set_error( wait->status );
        if (!wait->status && (message = wait->reply))
        {
            if (message->size > get_reply_max_size()) set_error( STATUS_BUFFER_TOO_SMALL );
            else if (!message->size || set_reply_data( message->data, message->size ))
            {
                reply->message_id = message->id;
                reply->message_type = message->type;
                reply->sender_pid = message->pid;
                reply->sender_tid = message->tid;
                free( wait->reply );
                wait->reply = NULL;
            }
        }
    }
    release_object( wait );
}

/* Admission uses the same listening queue, with a pending client reference
 * owned by its listener. The client's wait handle is private to NTDLL until
 * acceptance completes. */
DECL_HANDLER(alpc_connect_port)
{
    const unsigned char *data = get_req_data();
    data_size_t size = get_req_data_size(), payload_size;
    struct unicode_str name;
    const struct sid *sid;
    struct alpc_port *listener = NULL, *client = NULL;
    struct alpc_message *message;
    struct alpc_port_init_data init = { .type = COMMUNICATION_PORT, .flags = req->port_flags,
                                        .max_msg_len = req->max_msg_len };
    struct object_params params = { .ops = &alpc_port_ops, .init_data = &init };
    obj_handle_t lookup = 0, handle = 0;

    if (req->name_size > size || req->name_size % sizeof(WCHAR) || req->sid_size > size - req->name_size)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    if (req->flags & ~0x20000 || !(req->port_flags & 0x40000))
    {
        set_error( STATUS_NOT_IMPLEMENTED );
        return;
    }
    name.str = (const WCHAR *)data;
    name.len = req->name_size;
    sid = (const struct sid *)(data + req->name_size);
    if (req->sid_size && (!sid_valid_size( sid, req->sid_size ) || sid->revision != SID_REVISION ||
                         sid->sub_count > SID_MAX_SUB_AUTHORITIES || sid_len( sid ) != req->sid_size))
    {
        set_error( STATUS_INVALID_SID );
        return;
    }
    payload_size = size - req->name_size - req->sid_size;
    if (!(lookup = open_object( current->process, req->rootdir, ALPC_PORT_QUERY_STATE,
                                &alpc_port_ops, name, req->attributes ))) return;
    if (!(listener = (struct alpc_port *)get_handle_obj( current->process, lookup,
                                                        ALPC_PORT_QUERY_STATE, &alpc_port_ops ))) goto done;
    if (listener->type != CONNECTION_PORT || listener->status == DISCONNECTED)
    {
        set_error( STATUS_PORT_DISCONNECTED );
        goto done;
    }
    if (!(listener->flags & 0x40000))
    {
        set_error( STATUS_NOT_IMPLEMENTED );
        goto done;
    }
    if (req->sid_size && !equal_sid( sid, token_get_user( listener->thread->process->token ) ))
    {
        set_error( STATUS_SERVER_SID_MISMATCH );
        goto done;
    }
    if (payload_size > 65535 - sizeof(ALPC_PORT_MESSAGE) ||
        payload_size + sizeof(ALPC_PORT_MESSAGE) > listener->max_msg_len)
    {
        set_error( STATUS_PORT_MESSAGE_TOO_LONG );
        goto done;
    }
    if (!(client = create_named_object( &params ))) goto done;
    if (!(handle = alloc_handle( current->process, client, ALPC_PORT_ALL_ACCESS, 0 ))) goto done;
    if (!(message = new_message( data + req->name_size + req->sid_size, payload_size,
                                ALPC_MESSAGE_TYPE_CONNECTION_REQUEST | 0x2000 |
                                (req->wow64 ? 0x1000 : 0), 0, current )))
    {
        close_handle( current->process, handle );
        goto done;
    }
    client->connecting_handle = handle;
    list_add_tail( &connecting_ports, &client->connecting_entry );
    client->want_reply = req->flags & 0x20000;
    client->connection_id = message->id;
    client->wow64 = req->wow64;
    client->pending_listener = listener;
    list_add_tail( &listener->pending_connections, &client->pending_entry );
    grab_object( client );
    list_add_tail( &listener->messages, &message->entry );
    signal_sync( listener->sync );
    reply->handle = handle;

done:
    if (client) release_object( client );
    if (listener) release_object( listener );
    if (lookup) close_handle( current->process, lookup );
}

DECL_HANDLER(alpc_get_connect_result)
{
    struct alpc_port *client;
    struct alpc_message *message;
    if (!(client = (struct alpc_port *)get_handle_obj( current->process, req->handle,
                                                      ALPC_PORT_ALL_ACCESS, &alpc_port_ops ))) return;
    if (client->thread != current || client->connecting_handle != req->handle)
    {
        set_error( STATUS_ACCESS_DENIED );
        goto done;
    }
    reply->status = client->connect_status;
    if (client->connect_status) goto done;
    if (!client->want_reply)
    {
        finish_connect_operation( client );
        goto done;
    }
    if (!(message = client->connect_reply))
    {
        set_error( STATUS_INVALID_MESSAGE );
        goto done;
    }
    reply->message_size = message->size;
    if (message->size > get_reply_max_size())
    {
        set_error( STATUS_BUFFER_TOO_SMALL );
        goto done;
    }
    if (message->size && !set_reply_data( message->data, message->size )) goto done;
    reply->message_id = message->id;
    reply->message_type = message->type;
    reply->sender_pid = message->pid;
    reply->sender_tid = message->tid;
    free( message );
    client->connect_reply = NULL;
    finish_connect_operation( client );
    reset_sync( client->sync );
done:
    release_object( client );
}

DECL_HANDLER(alpc_accept_connect_port)
{
    struct alpc_port *listener, *client = NULL, *candidate, *server = NULL;
    struct alpc_port_init_data init = { .type = COMMUNICATION_PORT, .flags = req->port_flags,
                                        .max_msg_len = req->max_msg_len };
    struct object_params params = { .ops = &alpc_port_ops, .init_data = &init };
    struct alpc_message *message = NULL;
    data_size_t size = get_req_data_size();
    obj_handle_t handle;

    if (!(listener = (struct alpc_port *)get_handle_obj( current->process, req->connection,
                                                       ALPC_PORT_ALL_ACCESS, &alpc_port_ops ))) return;
    if (listener->thread->process != current->process)
    {
        set_error( STATUS_ACCESS_DENIED );
        goto done;
    }
    LIST_FOR_EACH_ENTRY( candidate, &listener->pending_connections, struct alpc_port, pending_entry )
        if (candidate->connection_id == req->message_id && candidate->request_delivered &&
            candidate->thread->process->id == req->sender_pid && candidate->thread->id == req->sender_tid)
        {
            client = candidate;
            break;
        }
    if (!client)
    {
        /* Consuming the canceled request reports REQUEST_CANCELED once. Later
         * attempts no longer identify a live or canceled admission. */
        LIST_FOR_EACH_ENTRY( message, &listener->messages, struct alpc_message, entry )
            if (message->id == req->message_id && message->pid == req->sender_pid &&
                message->tid == req->sender_tid && (message->type & 0xff) == ALPC_MESSAGE_TYPE_CANCELED)
            {
                list_remove( &message->entry );
                if (list_empty( &listener->messages )) reset_sync( listener->sync );
                set_error( STATUS_REQUEST_CANCELED );
                goto done;
            }
        message = NULL;
        set_error( STATUS_INVALID_MESSAGE );
        goto done;
    }
    if (!req->accept)
    {
        client->connect_status = STATUS_PORT_CONNECTION_REFUSED;
        signal_sync( client->sync );
        unlink_pending( client );
        goto done;
    }
    if (size > 65535 - sizeof(ALPC_PORT_MESSAGE) || size + sizeof(ALPC_PORT_MESSAGE) > client->max_msg_len)
    {
        set_error( STATUS_PORT_MESSAGE_TOO_LONG );
        goto done;
    }
    if (!(server = create_named_object( &params ))) goto done;
    if (!(message = new_message( get_req_data(), size, ALPC_MESSAGE_TYPE_CONNECTION_REPLY |
                                (client->wow64 ? 0x1000 : 0), client->connection_id, client->thread ))) goto done;
    if (!(handle = alloc_handle( current->process, server, ALPC_PORT_ALL_ACCESS, req->attributes ))) goto done;
    server->connection_port = (struct alpc_port *)grab_object( listener );
    list_add_tail( &listener->accepted_connections, &server->accepted_entry );
    server->wow64 = client->wow64;
    server->context = req->context;
    server->peer = (struct alpc_port *)grab_object( client );
    client->peer = (struct alpc_port *)grab_object( server );
    server->status = client->status = CONNECTED;
    client->connect_status = STATUS_SUCCESS;
    if (client->want_reply)
    {
        client->connect_reply = message;
        message = NULL;
    }
    signal_sync( client->sync );
    signal_sync( server->sync );
    unlink_pending( client );
    reply->handle = handle;
done:
    free( message );
    if (server) release_object( server );
    release_object( listener );
}

DECL_HANDLER(alpc_disconnect_port)
{
    struct alpc_port *port;
    if (!(port = (struct alpc_port *)get_handle_obj( current->process, req->handle,
                                                  ALPC_PORT_ALL_ACCESS, &alpc_port_ops ))) return;
    if (port->thread->process != current->process) set_error( STATUS_ACCESS_DENIED );
    else if (port->status == DISCONNECTED) set_error( STATUS_PORT_DISCONNECTED );
    else
    {
        disconnect_message_requests( port );
        port->status = DISCONNECTED;
        detach_peer( port );
    }
    release_object( port );
}
