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
#include "object.h"
#include "process.h"
#include "thread.h"
#include "security.h"
#include "request.h"

static const WCHAR alpc_port_name[] = {'A','L','P','C',' ','P','o','r','t'};

#define ALPC_CONTINUATION_REQUIRED 0x2000

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

enum alpc_kernel_endpoint
{
    ALPC_KERNEL_ENDPOINT_NONE,
    ALPC_KERNEL_ENDPOINT_POWER,
    ALPC_KERNEL_ENDPOINT_PDC
};

struct alpc_port
{
    struct object            obj;                   /* object header */
    struct object           *sync;                  /* queue/connection state sync object */
    enum alpc_port_enum_type type;                  /* communication port or connection port */
    enum alpc_port_status    status;                /* port status */
    enum alpc_kernel_endpoint kernel_endpoint;      /* server-owned endpoint contract */
    struct thread           *thread;                /* thread owning the port */
    unsigned int             flags;                 /* flags in port attributes */
    mem_size_t               max_msg_len;           /* max message length in port attributes */
    client_ptr_t             context;               /* server-defined communication context */
    struct alpc_port        *peer;                  /* opposite communication endpoint */
    struct alpc_port        *connection_port;       /* parent connection port */
    struct alpc_port        *last_reply_port;       /* endpoint for the last received request */
    struct alpc_port        *kernel_client;          /* weak reference to exclusive kernel client */
    struct list              pending_entry;         /* entry in connection port pending list */
    struct list              pending_connections;   /* pending client communication ports */
    struct list              messages;              /* received messages */
    unsigned int             connection_message_id; /* pending connection request id */
    unsigned int             last_message_id;       /* last received message id */
    unsigned int             waiting_message_id;    /* synchronous request reply expected by this endpoint */
    thread_id_t              last_sender_tid;       /* last received message sender */
    unsigned int             pending_linked : 1;
};

struct alpc_message
{
    struct list entry;
    void *data;
    data_size_t size;
    unsigned int message_id;
    process_id_t sender_pid;
    thread_id_t sender_tid;
    unsigned int message_type;
    unsigned int valid_attributes;
    client_ptr_t message_context;
    client_ptr_t port_context;
    unsigned __int64 work_on_behalf;
    struct alpc_port *reply_port;
};

struct alpc_port_init_data
{
    enum alpc_port_enum_type type;
    enum alpc_kernel_endpoint kernel_endpoint;
    unsigned int             flags;
    mem_size_t               max_msg_len;
};

static void alpc_port_dump( struct object *obj, int verbose );
static bool alpc_port_init( struct object *obj, const void *init_data );
static struct object *alpc_port_get_sync( struct object *obj );
static int alpc_port_close_handle( struct object *obj, struct process *process, obj_handle_t handle );
static void alpc_port_destroy( struct object *obj );

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
    fprintf( stderr, "ALPC Port type=%d status=%d messages=%s\n", port->type, port->status,
             list_empty( &port->messages ) ? "empty" : "queued" );
}

static bool alpc_port_init( struct object *obj, const void *init_data )
{
    struct alpc_port *port = (struct alpc_port *)obj;
    const struct alpc_port_init_data *data = init_data;

    port->type        = data->type;
    port->flags       = data->flags;
    port->max_msg_len = data->max_msg_len;
    port->status      = UNINITIALIZED;
    port->kernel_endpoint = data->kernel_endpoint;
    port->thread      = current ? (struct thread *)grab_object( current ) : NULL;
    port->context     = 0;
    port->peer        = NULL;
    port->connection_port = NULL;
    port->last_reply_port = NULL;
    port->kernel_client = NULL;
    port->connection_message_id = 0;
    port->last_message_id = 0;
    port->waiting_message_id = 0;
    port->last_sender_tid = 0;
    port->pending_linked = 0;
    list_init( &port->pending_entry );
    list_init( &port->pending_connections );
    list_init( &port->messages );
    return !!(port->sync = create_internal_sync( 1, 0 ));
}

static struct object *alpc_port_get_sync( struct object *obj )
{
    struct alpc_port *port = (struct alpc_port *)obj;
    assert( obj->ops == &alpc_port_ops );
    return grab_object( port->sync );
}

static void alpc_free_message( struct alpc_message *message )
{
    if (message->reply_port) release_object( message->reply_port );
    free( message->data );
    free( message );
}

static void alpc_disconnect_peer( struct alpc_port *port )
{
    struct alpc_port *peer = port->peer;
    struct alpc_port *connection = NULL;

    if (!peer) return;
    if (port->connection_port && port->connection_port->kernel_client == peer)
        connection = port->connection_port;
    else if (peer->connection_port && peer->connection_port->kernel_client == port)
        connection = peer->connection_port;
    if (connection) connection->kernel_client = NULL;
    port->peer = NULL;
    if (peer->peer == port)
    {
        peer->peer = NULL;
        peer->status = DISCONNECTED;
        signal_sync( peer->sync );
        release_object( port );
    }
    release_object( peer );
}

static int alpc_port_close_handle( struct object *obj, struct process *process, obj_handle_t handle )
{
    struct alpc_port *port = (struct alpc_port *)obj;
    struct alpc_port *client, *next;

    assert( obj->ops == &alpc_port_ops );
    if (obj->handle_count != 1) return 1;

    if (port->pending_linked)
    {
        list_remove( &port->pending_entry );
        port->pending_linked = 0;
        port->connection_port = NULL;
        release_object( port );
    }

    if (port->type == CONNECTION_PORT)
    {
        LIST_FOR_EACH_ENTRY_SAFE( client, next, &port->pending_connections,
                                  struct alpc_port, pending_entry )
        {
            list_remove( &client->pending_entry );
            client->pending_linked = 0;
            client->connection_port = NULL;
            client->status = REFUSED;
            signal_sync( client->sync );
            release_object( client );
        }
    }
    alpc_disconnect_peer( port );
    return 1;
}

static void alpc_port_destroy( struct object *obj )
{
    struct alpc_port *port = (struct alpc_port *)obj;
    struct alpc_message *message, *next;

    assert( obj->ops == &alpc_port_ops );
    assert( !port->pending_linked );
    assert( !port->peer );
    LIST_FOR_EACH_ENTRY_SAFE( message, next, &port->messages, struct alpc_message, entry )
    {
        list_remove( &message->entry );
        alpc_free_message( message );
    }
    if (port->sync) release_object( port->sync );
    if (port->connection_port) release_object( port->connection_port );
    if (port->last_reply_port) release_object( port->last_reply_port );
    if (port->thread) release_object( port->thread );
}

static struct alpc_port *get_alpc_port( obj_handle_t handle, unsigned int access )
{
    return (struct alpc_port *)get_handle_obj( current->process, handle, access, &alpc_port_ops );
}

static struct alpc_port *create_communication_port( unsigned int flags, mem_size_t max_msg_len )
{
    struct alpc_port_init_data data = { .type = COMMUNICATION_PORT, .flags = flags,
                                        .max_msg_len = max_msg_len };
    struct object_params params = { .ops = &alpc_port_ops, .init_data = &data };

    return create_named_object( &params );
}

void create_system_alpc_objects( struct object *root )
{
    static const WCHAR power_portW[] = {'P','o','w','e','r','P','o','r','t'};
    static const WCHAR pdc_portW[] = {'P','d','c','P','o','r','t'};
    static const struct unicode_str power_port = {power_portW, sizeof(power_portW)};
    static const struct unicode_str pdc_port = {pdc_portW, sizeof(pdc_portW)};
    struct alpc_port_init_data power_data = { .type = CONNECTION_PORT,
                                              .kernel_endpoint = ALPC_KERNEL_ENDPOINT_POWER,
                                              .flags = 0x20000, .max_msg_len = 0x1000 };
    struct alpc_port_init_data pdc_data = { .type = CONNECTION_PORT,
                                            .kernel_endpoint = ALPC_KERNEL_ENDPOINT_PDC,
                                            .flags = 0, .max_msg_len = 0x320 };
    struct object_params power_params = { .ops = &alpc_port_ops, .init_data = &power_data,
                                          .root = root, .name = power_port, .attr = OBJ_PERMANENT };
    struct object_params pdc_params = { .ops = &alpc_port_ops, .init_data = &pdc_data,
                                        .root = root, .name = pdc_port, .attr = OBJ_PERMANENT };

    release_object( create_named_object( &power_params ) );
    release_object( create_named_object( &pdc_params ) );
}

static int connect_kernel_alpc_port( struct alpc_port *connection, struct alpc_port *client,
                                     const struct alpc_connect_port_request *req,
                                     struct alpc_connect_port_reply *reply )
{
    struct alpc_port *server;

    if (connection->kernel_endpoint == ALPC_KERNEL_ENDPOINT_POWER && connection->kernel_client)
    {
        set_error( STATUS_PORT_CONNECTION_REFUSED );
        return 0;
    }
    if (!(server = create_communication_port( connection->flags, connection->max_msg_len ))) return 0;

    server->connection_port = (struct alpc_port *)grab_object( connection );
    server->status = CONNECTED;
    client->status = CONNECTED;
    server->peer = (struct alpc_port *)grab_object( client );
    client->peer = (struct alpc_port *)grab_object( server );
    if (connection->kernel_endpoint == ALPC_KERNEL_ENDPOINT_POWER) connection->kernel_client = client;

    reply->handle = alloc_handle( current->process, client, ALPC_PORT_ALL_ACCESS, req->attributes );
    if (!reply->handle)
    {
        alpc_disconnect_peer( client );
        client->status = DISCONNECTED;
        release_object( server );
        return 0;
    }
    release_object( server );
    return 1;
}

static unsigned int next_alpc_message_id(void)
{
    static unsigned int next_id;

    if (!++next_id) ++next_id;
    return next_id;
}

static struct alpc_message *alloc_alpc_message( const void *data, data_size_t size,
                                                unsigned int message_id, unsigned int message_type,
                                                unsigned int valid_attributes, client_ptr_t message_context,
                                                client_ptr_t port_context, unsigned __int64 work_on_behalf,
                                                struct alpc_port *reply_port )
{
    struct alpc_message *message;

    if (!(message = mem_alloc( sizeof(*message) ))) return NULL;
    if (size && !(message->data = memdup( data, size )))
    {
        free( message );
        return NULL;
    }
    if (!size) message->data = NULL;
    message->size = size;
    message->message_id = message_id ? message_id : next_alpc_message_id();
    message->sender_pid = current->process->id;
    message->sender_tid = current->id;
    message->message_type = message_type;
    message->valid_attributes = valid_attributes;
    message->message_context = message_context;
    message->port_context = port_context;
    message->work_on_behalf = work_on_behalf;
    message->reply_port = reply_port ? (struct alpc_port *)grab_object( reply_port ) : NULL;
    return message;
}

static int queue_alpc_message( struct alpc_port *port, const void *data, data_size_t size,
                               unsigned int message_id, unsigned int message_type,
                               unsigned int valid_attributes, client_ptr_t message_context,
                               client_ptr_t port_context, unsigned __int64 work_on_behalf,
                               struct alpc_port *reply_port )
{
    struct alpc_message *message;

    if (size > port->max_msg_len)
    {
        set_error( STATUS_PORT_MESSAGE_TOO_LONG );
        return 0;
    }
    if (!(message = alloc_alpc_message( data, size, message_id, message_type, valid_attributes,
                                        message_context, port_context, work_on_behalf, reply_port ))) return 0;
    list_add_tail( &port->messages, &message->entry );
    signal_sync( port->sync );
    return message->message_id;
}

static void reply_alpc_message( struct alpc_port *port, struct alpc_message *message,
                                struct alpc_send_receive_reply *reply )
{
    struct alpc_port *communication_port = NULL;
    data_size_t size = min( message->size, get_reply_max_size() );

    reply->message_id = message->message_id;
    reply->sender_pid = message->sender_pid;
    reply->sender_tid = message->sender_tid;
    reply->message_type = message->message_type;
    reply->message_size = message->size;
    reply->port_context = message->port_context;
    reply->message_context = message->message_context;
    reply->valid_attributes = message->valid_attributes;
    reply->work_on_behalf = message->work_on_behalf;
    if (message->size > get_reply_max_size())
    {
        set_error( STATUS_BUFFER_TOO_SMALL );
        return;
    }
    if (size) set_reply_data( message->data, size );
    port->last_message_id = message->message_id;
    port->last_sender_tid = message->sender_tid;
    /* Client requests are dequeued from the shared connection port, but the
     * server impersonates them through the accepted communication port. */
    if (port->type == CONNECTION_PORT && message->reply_port && message->reply_port->peer &&
        message->reply_port->peer->connection_port == port)
        communication_port = message->reply_port->peer;
    if (communication_port)
    {
        communication_port->last_message_id = message->message_id;
        communication_port->last_sender_tid = message->sender_tid;
    }
    if (port->last_reply_port) release_object( port->last_reply_port );
    port->last_reply_port = message->reply_port ?
                            (struct alpc_port *)grab_object( message->reply_port ) : NULL;
    list_remove( &message->entry );
    alpc_free_message( message );
    if (list_empty( &port->messages )) reset_sync( port->sync );
}

/* Create an ALPC port */
DECL_HANDLER(alpc_create_port)
{
    struct alpc_port *alpc_port;
    struct alpc_port_init_data data = { .type = CONNECTION_PORT, .flags = req->flags,
                                        .max_msg_len = req->max_msg_len };
    struct object_params params = { .ops = &alpc_port_ops, .init_data = &data };

    if (!get_req_object_attributes( &params )) return;

    if ((alpc_port = create_named_object( &params )))
    {
        reply->handle = alloc_handle( current->process, alpc_port, ALPC_PORT_ALL_ACCESS, params.attr );
        release_object( alpc_port );
    }

    if (params.root) release_object( params.root );
}

/* Connect to a named ALPC connection port */
DECL_HANDLER(alpc_connect_port)
{
    const unsigned char *data = get_req_data();
    data_size_t data_size = get_req_data_size();
    struct unicode_str name;
    struct alpc_port *connection = NULL, *client = NULL;
    obj_handle_t connection_handle = 0;
    data_size_t message_size;
    unsigned int id;

    if (req->name_size > data_size || (req->name_size & (sizeof(WCHAR) - 1)))
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    name.str = (const WCHAR *)data;
    name.len = req->name_size;
    message_size = data_size - req->name_size;

    connection_handle = open_object( current->process, req->rootdir, ALPC_PORT_ALL_ACCESS,
                                     &alpc_port_ops, name, req->attributes );
    if (!connection_handle) return;
    if (!(connection = get_alpc_port( connection_handle, ALPC_PORT_ALL_ACCESS ))) goto done;
    if (connection->type != CONNECTION_PORT)
    {
        set_error( STATUS_OBJECT_TYPE_MISMATCH );
        goto done;
    }
    if (!(client = create_communication_port( req->flags, req->max_msg_len ))) goto done;
    if (connection->kernel_endpoint != ALPC_KERNEL_ENDPOINT_NONE)
    {
        connect_kernel_alpc_port( connection, client, req, reply );
        goto done;
    }
    fprintf( stderr, "linuxnt-alpc: connect target packets=%u message=%u\n",
             list_count( &connection->sync->completion_packet_queue ), (unsigned int)message_size );
    if (!(id = queue_alpc_message( connection, data + req->name_size, message_size, 0,
                                   ALPC_MESSAGE_TYPE_CONNECTION_REQUEST | ALPC_CONTINUATION_REQUIRED,
                                   0, 0, 0, 0, NULL ))) goto done;
    fprintf( stderr, "linuxnt-alpc: connect queued id=%u packets=%u\n", id,
             list_count( &connection->sync->completion_packet_queue ) );

    client->connection_message_id = id;
    client->connection_port = connection;
    client->pending_linked = 1;
    list_add_tail( &connection->pending_connections, &client->pending_entry );
    grab_object( client ); /* pending connection list reference */
    reply->handle = alloc_handle( current->process, client, ALPC_PORT_ALL_ACCESS, req->attributes );
    reply->message_id = id;

done:
    if (client) release_object( client );
    if (connection) release_object( connection );
    if (connection_handle) close_handle( current->process, connection_handle );
}

/* Retrieve the result of a connection request */
DECL_HANDLER(alpc_get_connect_result)
{
    struct alpc_port *client;
    struct alpc_message *message;

    if (!(client = get_alpc_port( req->handle, ALPC_PORT_QUERY_STATE ))) return;
    if (client->type != COMMUNICATION_PORT)
    {
        set_error( STATUS_INVALID_PORT_HANDLE );
        goto done;
    }

    switch (client->status)
    {
    case UNINITIALIZED:
        reply->status = STATUS_PENDING;
        break;
    case REFUSED:
        reply->status = STATUS_PORT_CONNECTION_REFUSED;
        reset_sync( client->sync );
        break;
    case DISCONNECTED:
        reply->status = STATUS_PORT_DISCONNECTED;
        reset_sync( client->sync );
        break;
    case CONNECTED:
        reply->status = STATUS_SUCCESS;
        if (!list_empty( &client->messages ))
        {
            message = LIST_ENTRY( list_head( &client->messages ), struct alpc_message, entry );
            reply->message_id = message->message_id;
            reply->message_size = message->size;
            if (message->size > get_reply_max_size())
            {
                set_error( STATUS_BUFFER_TOO_SMALL );
                break;
            }
            if (message->size) set_reply_data( message->data, message->size );
            list_remove( &message->entry );
            alpc_free_message( message );
        }
        if (list_empty( &client->messages )) reset_sync( client->sync );
        break;
    }

done:
    release_object( client );
}

/* Accept or reject a pending connection */
DECL_HANDLER(alpc_accept_connect_port)
{
    const void *data = get_req_data();
    data_size_t size = get_req_data_size();
    struct alpc_port *connection, *client = NULL, *candidate, *next, *server = NULL;

    if (!(connection = get_alpc_port( req->connection, ALPC_PORT_ALL_ACCESS ))) return;
    if (connection->type != CONNECTION_PORT)
    {
        set_error( STATUS_INVALID_PORT_HANDLE );
        goto done;
    }

    LIST_FOR_EACH_ENTRY_SAFE( candidate, next, &connection->pending_connections,
                              struct alpc_port, pending_entry )
    {
        if (candidate->connection_message_id == req->message_id)
        {
            client = candidate;
            break;
        }
    }
    if (!client)
    {
        set_error( STATUS_REPLY_MESSAGE_MISMATCH );
        goto done;
    }

    list_remove( &client->pending_entry );
    client->pending_linked = 0;
    client->connection_port = NULL;
    if (!req->accept)
    {
        client->status = REFUSED;
        signal_sync( client->sync );
        release_object( client ); /* pending connection list reference */
        goto done;
    }

    if (!(server = create_communication_port( req->flags, req->max_msg_len )))
    {
        client->status = REFUSED;
        signal_sync( client->sync );
        release_object( client );
        goto done;
    }
    server->context = req->port_context;
    server->connection_port = (struct alpc_port *)grab_object( connection );
    server->status = CONNECTED;
    client->status = CONNECTED;
    server->peer = (struct alpc_port *)grab_object( client );
    client->peer = (struct alpc_port *)grab_object( server );
    if (size && !queue_alpc_message( client, data, size, req->message_id,
                                     ALPC_MESSAGE_TYPE_CONNECTION_REPLY, 0, req->message_context,
                                     0, 0, NULL ))
    {
        alpc_disconnect_peer( server );
        client->status = REFUSED;
        signal_sync( client->sync );
        release_object( client );
        goto done;
    }
    signal_sync( client->sync );
    reply->handle = alloc_handle( current->process, server, ALPC_PORT_ALL_ACCESS, req->attributes );
    release_object( client ); /* pending connection list reference */

done:
    if (server) release_object( server );
    release_object( connection );
}

/* Send and/or receive an ALPC message */
DECL_HANDLER(alpc_send_receive)
{
    const unsigned char *data = get_req_data();
    data_size_t data_size = get_req_data_size();
    struct alpc_port *port;
    struct alpc_port *target = NULL, *reply_port = NULL;
    struct alpc_message *message;
    unsigned int type, message_id, queued_id;
    client_ptr_t port_context = 0;

    if (req->send_size > data_size)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    if (!(port = get_alpc_port( req->handle, ALPC_PORT_ALL_ACCESS ))) return;
    if (req->send_size)
    {
        if (port->type == CONNECTION_PORT)
        {
            /* A new message on the listening handle targets its own queue,
             * including when a connection request is awaiting acceptance. */
            if (!req->message_id)
                target = port;
            else if (port->last_message_id == req->message_id && port->last_reply_port)
                target = port->last_reply_port;
        }
        else if (port->type == COMMUNICATION_PORT && port->status == CONNECTED && port->peer)
        {
            if (port->peer->connection_port)
            {
                target = port->peer->connection_port;
                port_context = port->peer->context;
                reply_port = port;
            }
            else target = port->peer;
        }
        if (!target)
        {
            fprintf( stderr, "linuxnt-alpc: no route handle_type=%u flags=%#x id=%u last_id=%u last=%p peer=%p\n",
                     port->type, req->flags, req->message_id, port->last_message_id,
                     port->last_reply_port, port->peer );
            set_error( STATUS_PORT_DISCONNECTED );
            goto done;
        }
        if (target == port)
            type = req->flags & ALPC_MSGFLG_RELEASE_MESSAGE ? ALPC_MESSAGE_TYPE_DATAGRAM :
                   ALPC_MESSAGE_TYPE_REQUEST | ALPC_CONTINUATION_REQUIRED;
        else type = (req->flags & ALPC_MSGFLG_REPLY_MESSAGE) ||
               (port->type == CONNECTION_PORT && req->message_id &&
                port->last_message_id == req->message_id) ? ALPC_MESSAGE_TYPE_REPLY :
               get_reply_max_size() ? ALPC_MESSAGE_TYPE_REQUEST : ALPC_MESSAGE_TYPE_DATAGRAM;
        message_id = req->message_id;
        if (port->type == CONNECTION_PORT && type == ALPC_MESSAGE_TYPE_REPLY && !message_id)
            message_id = port->last_message_id;
        fprintf( stderr, "linuxnt-alpc: send handle_type=%u type=%u id=%u size=%u target=%p\n",
                 port->type, type, message_id, req->send_size, target );
        if (!(queued_id = queue_alpc_message( target, data, req->send_size, message_id,
                                               type, req->valid_attributes, req->message_context,
                                               port_context, req->work_on_behalf,
                                               reply_port ))) goto done;
        if (port->type == COMMUNICATION_PORT && (req->flags & ALPC_MSGFLG_SYNC_REQUEST))
            port->waiting_message_id = queued_id;
        /* A server may send more than one reply-flagged message for a request.
         * Keep the route until receiving another request replaces it. */
    }

    if (!get_reply_max_size()) goto done;
    if (port->waiting_message_id)
    {
        message = NULL;
        LIST_FOR_EACH_ENTRY( message, &port->messages, struct alpc_message, entry )
            if (message->message_type == ALPC_MESSAGE_TYPE_REPLY &&
                message->message_id == port->waiting_message_id) break;
        if (&message->entry == &port->messages) message = NULL;
        if (!message)
        {
            reply->pending = 1;
            goto done;
        }
        port->waiting_message_id = 0;
    }
    else if (list_empty( &port->messages ))
    {
        reply->pending = 1;
        goto done;
    }
    else message = LIST_ENTRY( list_head( &port->messages ), struct alpc_message, entry );
    reply_alpc_message( port, message, reply );

done:
    release_object( port );
}

/* Disconnect an ALPC communication port */
DECL_HANDLER(alpc_disconnect_port)
{
    struct alpc_port *port;

    if (!(port = get_alpc_port( req->handle, ALPC_PORT_ALL_ACCESS ))) return;
    if (port->type != COMMUNICATION_PORT)
        set_error( STATUS_INVALID_PORT_HANDLE );
    else
    {
        port->status = DISCONNECTED;
        alpc_disconnect_peer( port );
        signal_sync( port->sync );
    }
    release_object( port );
}

/* Query basic ALPC port state */
DECL_HANDLER(alpc_query_information)
{
    struct alpc_port *port;

    if (!(port = get_alpc_port( req->handle, ALPC_PORT_QUERY_STATE ))) return;
    reply->flags = port->flags;
    reply->sequence = port->last_message_id;
    reply->context = port->context;
    release_object( port );
}

/* Impersonate the sender of a received ALPC message */
DECL_HANDLER(alpc_impersonate_client)
{
    struct alpc_port *port;
    struct thread *sender;
    struct token *token;

    if (!(port = get_alpc_port( req->handle, ALPC_PORT_ALL_ACCESS ))) return;
    if (!req->message_id || port->last_message_id != req->message_id || !port->last_sender_tid)
    {
        set_error( STATUS_REPLY_MESSAGE_MISMATCH );
        goto done;
    }
    if (!(sender = get_thread_from_id( port->last_sender_tid ))) goto done;
    token = token_duplicate( thread_get_impersonation_token( sender ), 0, SecurityImpersonation,
                             NULL, NULL, 0, NULL, 0 );
    release_object( sender );
    if (!token) goto done;
    if (current->token) release_object( current->token );
    current->token = token;

done:
    release_object( port );
}
