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

struct alpc_message
{
    struct list entry;
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
    if (port->connection_port) release_object( port->connection_port );
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
}

static struct alpc_message *new_message( const void *data, data_size_t size, unsigned int type,
                                        unsigned int id, struct thread *sender )
{
    struct alpc_message *message;
    if (!(message = mem_alloc( sizeof(*message) + size ))) return NULL;
    if (!id && !(id = ++next_message_id)) id = ++next_message_id;
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

    if (!(port = (struct alpc_port *)get_handle_obj( current->process, req->handle,
                                                    ALPC_PORT_ALL_ACCESS, &alpc_port_ops ))) return;
    if (port->thread->process != current->process)
    {
        set_error( STATUS_ACCESS_DENIED );
        goto done;
    }
    /* Connections, replies, and message attributes need their own lifetime
     * contracts before they can enter this transport. */
    if (req->flags & ~(1 | 0x10000) || req->message_id || port->type != CONNECTION_PORT ||
        !(port->flags & 0x40000))
    {
        set_error( STATUS_NOT_IMPLEMENTED );
        goto done;
    }
    if (req->send)
    {
        if (size > 65535 - sizeof(ALPC_PORT_MESSAGE) ||
            size + sizeof(ALPC_PORT_MESSAGE) > port->max_msg_len)
        {
            set_error( STATUS_PORT_MESSAGE_TOO_LONG );
            goto done;
        }
        if (!(message = new_message( get_req_data(), size,
                                     (req->flags & 0x10000 ? 3 : 0x2001) |
                                     (req->wow64 ? 0x1000 : 0), 0, current ))) goto done;
        list_add_tail( &port->messages, &message->entry );
        signal_sync( port->sync );
    }
    if (!req->receive) goto done;
    if (list_empty( &port->messages ))
    {
        set_error( STATUS_UNSUCCESSFUL );
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
    list_remove( &message->entry );
    free( message );
    /* Successful receive clears the notification, even with queued data. */
    reset_sync( port->sync );

done:
    release_object( port );
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
        port->status = DISCONNECTED;
        detach_peer( port );
    }
    release_object( port );
}
