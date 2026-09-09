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

static const struct object_ops alpc_port_ops =
{
    .size         = sizeof(struct alpc_port),
    .type         = &alpc_port_type,
    .dump         = alpc_port_dump,
    .init         = alpc_port_init,
    .add_queue    = add_queue,
    .remove_queue = remove_queue,
    .get_sync     = alpc_port_get_sync,
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
    if (port->sync) release_object( port->sync );
    release_object( port->thread );
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

/* The listening-port queue is shared by every duplicate of its handle. */
DECL_HANDLER(alpc_send_receive)
{
    static unsigned int next_id;
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
        if (!(message = mem_alloc( sizeof(*message) + size ))) goto done;
        if (!++next_id) ++next_id;
        message->id = next_id;
        message->type = req->flags & 0x10000 ? 3 : 0x2001;
        if (req->wow64) message->type |= 0x1000;
        message->pid = current->process->id;
        message->tid = current->id;
        message->size = size;
        if (size) memcpy( message->data, get_req_data(), size );
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
    list_remove( &message->entry );
    free( message );
    /* Successful receive clears the notification, even with queued data. */
    reset_sync( port->sync );

done:
    release_object( port );
}
