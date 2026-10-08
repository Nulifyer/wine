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
#include "file.h"
#include "process.h"
#include "thread.h"
#include "security.h"
#include "pdc.h"
#include "request.h"
#include "unicode.h"
#include "user.h"

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

enum alpc_kernel_port
{
    ALPC_KERNEL_PORT_NONE,
    ALPC_KERNEL_POWER_PORT,
    ALPC_KERNEL_DWM_SESSION_PORT,
    ALPC_KERNEL_COREMSG_PORT,
    ALPC_KERNEL_PDC_PORT
};

enum dwm_session_port_phase
{
    DWM_SESSION_PORT_REGISTERED,
    DWM_SESSION_PORT_INITIALIZING,
    DWM_SESSION_PORT_STARTED,
    DWM_SESSION_PORT_READY
};

struct coremsg_client_port;

struct alpc_port
{
    struct object            obj;                   /* object header */
    struct completion       *completion;            /* owned I/O completion association */
    struct alpc_completion_lease *completion_lease; /* weak; lease retains this port */
    apc_param_t              completion_key;
    unsigned int             completion_associated; /* one-shot, including released registrations */
    struct object           *sync;                  /* public port notification state */
    struct list              receive_waiters;       /* weak private receive operations */
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
    unsigned int            security_context;
    struct list             connecting_entry;      /* weak, while NTDLL owns the temporary handle */
    obj_handle_t            connecting_wait_handle; /* private admission wait handle */
    struct object          *connect_sync;
    unsigned int            counted_sync;
    obj_handle_t            connecting_handle;
    unsigned int            wow64;
    unsigned int            receive_sequence;
    client_ptr_t            initial_message_context;
    client_ptr_t            context;
    enum alpc_port_enum_type type;                  /* communication port or connection port */
    enum alpc_port_status    status;                /* port status */
    enum alpc_kernel_port    kernel_port;            /* server-owned kernel compatibility endpoint */
    struct list             kernel_session_entry;   /* weak entry in the live session-port registry */
    unsigned int            kernel_session_id;
    enum dwm_session_port_phase kernel_session_phase;
    struct winstation       *composited_winstation; /* strong while this DWM owns composition */
    struct event            *composed_event;        /* session DwmComposedEvent generation */
    unsigned int            composition_id;
    struct coremsg_client_port *coremsg_client;      /* owned virtual-kernel client record */
    struct pdc_client       *pdc_client;             /* owned by the server endpoint */
    struct token            *client_token;          /* captured connecting security */
    int                      impersonation_level, tracking_mode, effective_only;
    struct thread           *thread;                /* thread owning the port */
    unsigned int             flags;                 /* flags in port attributes */
    mem_size_t               max_msg_len;           /* max message length in port attributes */
};

/* The registry owns each live request. Endpoint pointers are weak and are
 * cleared or removed on final handle close. A released private reply retains
 * identity until its operation consumes or abandons it. */
struct alpc_request
{
    struct list entry;
    struct alpc_port *source, *target, *queue;
    struct alpc_message *message;
    struct alpc_message *reply; /* weak, while a released private reply is fetched */
    struct alpc_wait *wait; /* weak; its private handle owns the blocking call */
    unsigned int id, callback_id, wow64, canceled, released, no_impersonate;
    struct alpc_resource_reserve *reserve; /* retained until reply consumption */
    unsigned int security_context; /* captured context identity, independent of registration */
    client_ptr_t message_context;         /* context returned to the originating endpoint */
    client_ptr_t receive_message_context; /* context delivered to the current receiver */
    process_id_t pid;
    thread_id_t tid;
    struct process *sender_process; /* retained independently of the connector */
    struct token *token; /* retained after the sending endpoint closes */
    int impersonation_level;
};

struct alpc_wait
{
    struct object obj;
    struct object *sync;
    struct thread *thread;
    struct list entry; /* weak operation registry for thread-exit cleanup */
    obj_handle_t handle;
    struct alpc_port *receive_port; /* weak; cleared on handle close or delivery */
    struct list receive_entry;
    struct alpc_request *request; /* weak; cleared when request ownership changes */
    struct alpc_message *reply; /* owned reply for a successful blocking call */
    data_size_t capacity;
    struct alpc_message_info info;
    unsigned int status;
};
static struct list message_waits = LIST_INIT(message_waits);
static void cleanup_thread_message_waits( struct thread *thread );
static void dispatch_receives( struct alpc_port *port );
static void dispatch_all_receives( void );
static int send_message( struct alpc_port *port, unsigned int flags, unsigned int id,
                         unsigned int callback_id, unsigned int message_type, int wow64,
                         unsigned int send_attributes, client_ptr_t message_context, client_ptr_t security_context,
                         const void *data, data_size_t size, struct alpc_wait *wait );

static struct list message_requests = LIST_INIT(message_requests);
static struct alpc_port *default_hard_error_port;
static struct process *default_hard_error_process;
static void disconnect_coremsg_client_port( struct coremsg_client_port *client );

struct alpc_message
{
    struct list entry;
    struct alpc_request *request;
    struct alpc_resource_reserve *reserve; /* reference while this buffer is in use */
    struct alpc_port *destination; /* weak; queue or accepted receive view */
    struct alpc_message_info info;
    struct token *token; /* owned security capture for this receipt */
    unsigned int security_context;
    unsigned __int64 work_ticket; /* opaque per-message work-on-behalf receipt */
    unsigned char data[];
};

/* Registration, active request and queued/private buffer each own a reference.
 * Deletion removes registration; an in-flight message can still complete. */
struct alpc_resource_reserve
{
    struct list entry;
    struct alpc_port *owner; /* weak; final handle close unregisters resources */
    struct alpc_message *buffer;
    struct alpc_request *spare_request;
    unsigned int refs, id, message_id, size, buffer_in_use;
};
static struct list resource_reserves = LIST_INIT(resource_reserves);

/* Registration owns the capture; messages and requests retain their own token
 * references, so deleting a context cannot revoke a queued message's authority. */
struct alpc_security_context
{
    struct list entry;
    struct alpc_port *owner; /* weak; final handle close removes registration */
    struct token *token;
    unsigned int id;
    int impersonation_level;
};
static struct list security_contexts = LIST_INIT(security_contexts);
static unsigned int next_resource_id;

static unsigned int allocate_resource_id(void)
{
    struct alpc_resource_reserve *reserve;
    struct alpc_request *request;
    struct alpc_security_context *context;
    unsigned int id;
    int occupied;

    do
    {
        if (++next_resource_id >= 0x7fffffff) next_resource_id = 1;
        id = 0x80000000 | next_resource_id;
        occupied = 0;
        LIST_FOR_EACH_ENTRY( reserve, &resource_reserves, struct alpc_resource_reserve, entry )
            if (reserve->id == id) { occupied = 1; break; }
        if (!occupied)
            LIST_FOR_EACH_ENTRY( context, &security_contexts, struct alpc_security_context, entry )
                if (context->id == id) { occupied = 1; break; }
        if (!occupied)
            LIST_FOR_EACH_ENTRY( request, &message_requests, struct alpc_request, entry )
                if ((request->reserve && request->reserve->id == id) || request->security_context == id)
                { occupied = 1; break; }
    } while (occupied);
    return id;
}

static void release_resource_reserve( struct alpc_resource_reserve *reserve )
{
    if (--reserve->refs) return;
    assert( !reserve->owner && !reserve->buffer_in_use );
    free( reserve->spare_request );
    free( reserve->buffer );
    free( reserve );
}

static void unregister_resource_reserve( struct alpc_resource_reserve *reserve )
{
    list_remove( &reserve->entry );
    reserve->owner = NULL;
    release_resource_reserve( reserve );
}

static struct alpc_resource_reserve *find_resource_reserve( struct alpc_port *port, unsigned int id )
{
    struct alpc_resource_reserve *reserve;
    LIST_FOR_EACH_ENTRY( reserve, &resource_reserves, struct alpc_resource_reserve, entry )
        if (reserve->id == id && (reserve->owner == port || reserve->owner->peer == port)) return reserve;
    return NULL;
}

/* Connected endpoints share the lookup scope, but only the exact originating
 * endpoint may send with or delete a security context. */
static struct alpc_security_context *find_security_context( struct alpc_port *port, client_ptr_t id )
{
    struct alpc_security_context *context;
    LIST_FOR_EACH_ENTRY( context, &security_contexts, struct alpc_security_context, entry )
        if (context->id == id && (context->owner == port || context->owner->peer == port)) return context;
    return NULL;
}

static void unregister_security_context( struct alpc_security_context *context )
{
    list_remove( &context->entry );
    release_object( context->token );
    free( context );
}

static void free_message_request( struct alpc_request *request );

static data_size_t get_receipt_size( unsigned int attributes )
{
    data_size_t size = 0;
    if (attributes & ALPC_MESSAGE_TOKEN_ATTRIBUTE) size += sizeof(struct token_identity);
    if (attributes & ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE) size += sizeof(unsigned __int64);
    if (attributes & ALPC_MESSAGE_SECURITY_ATTRIBUTE) size += sizeof(unsigned int);
    return size;
}

/* Messages keep security alive independently of weak endpoint pointers. */
static void free_message( struct alpc_message *message )
{
    if (!message) return;
    if (message->request && message->request->reply == message) free_message_request( message->request );
    if (message->token) release_object( message->token );
    if (message->reserve)
    {
        struct alpc_resource_reserve *reserve = message->reserve;
        reserve->buffer_in_use = 0;
        release_resource_reserve( reserve );
    }
    else free( message );
}

/* Token metadata is a bounded prefix of successful variable reply data.
 * Error and short paths publish only the fixed message information. */
static int get_receive_capacity( unsigned int attributes, data_size_t *capacity )
{
    data_size_t prefix = get_receipt_size( attributes );
    if ((attributes & ~(ALPC_MESSAGE_TOKEN_ATTRIBUTE | ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE |
                        ALPC_MESSAGE_SECURITY_ATTRIBUTE)) ||
        get_reply_max_size() < prefix)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return 0;
    }
    *capacity = get_reply_max_size() - prefix;
    return 1;
}

static int set_message_reply( const struct alpc_message *message, unsigned int attributes )
{
    struct token_identity identity = {0};
    data_size_t prefix = get_receipt_size( attributes );
    unsigned char *data, *receipt;
    if (!prefix && !message->info.size) return 1;
    if (!(data = set_reply_data_size( prefix + message->info.size ))) return 0;
    receipt = data;
    if (attributes & ALPC_MESSAGE_TOKEN_ATTRIBUTE)
    {
        if (message->token) token_get_identity( message->token, &identity );
        memcpy( receipt, &identity, sizeof(identity) );
        receipt += sizeof(identity);
    }
    if (attributes & ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE)
    {
        memcpy( receipt, &message->work_ticket, sizeof(message->work_ticket) );
        receipt += sizeof(message->work_ticket);
    }
    if (attributes & ALPC_MESSAGE_SECURITY_ATTRIBUTE)
        memcpy( receipt, &message->security_context, sizeof(message->security_context) );
    if (message->info.size) memcpy( data + prefix, message->data, message->info.size );
    return 1;
}

struct alpc_port_init_data
{
    enum alpc_port_enum_type type;
    unsigned int             server;
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

struct object *get_alpc_port_obj( struct process *process, obj_handle_t handle, unsigned int access )
{
    struct alpc_port *port;

    if (!(port = (struct alpc_port *)get_handle_obj( process, handle, access, &alpc_port_ops ))) return NULL;
    if (port->thread->process == process) return &port->obj;

    release_object( port );
    set_error( STATUS_ACCESS_DENIED );
    return NULL;
}

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
    port->kernel_port = ALPC_KERNEL_PORT_NONE;
    list_init( &port->kernel_session_entry );
    port->kernel_session_id = 0;
    port->kernel_session_phase = DWM_SESSION_PORT_REGISTERED;
    port->composited_winstation = NULL;
    port->composed_event = NULL;
    port->composition_id = 0;
    port->coremsg_client = NULL;
    port->pdc_client = NULL;
    port->thread      = (struct thread *)grab_object( current );
    list_init( &port->messages );
    list_init( &port->receive_waiters );
    list_init( &port->accepted_connections );
    list_init( &port->accepted_entry );
    list_init( &port->pending_connections );
    list_init( &port->pending_entry );
    port->client_token = NULL;
    port->impersonation_level = port->tracking_mode = port->effective_only = 0;
    port->peer = NULL;
    port->connection_port = NULL;
    port->pending_listener = NULL;
    port->connect_reply = NULL;
    port->connection_id = 0;
    port->connect_status = STATUS_PENDING;
    port->request_delivered = 0;
    port->want_reply = 0;
    port->security_context = 0;
    list_init( &port->connecting_entry );
    port->connecting_handle = 0;
    port->connecting_wait_handle = 0;
    port->connect_sync = NULL;
    port->counted_sync = !data->server && (data->flags & 0x40000);
    port->wow64 = 0;
    port->context = 0;
    port->receive_sequence = 0;
    port->completion = NULL;
    port->completion_lease = NULL;
    port->completion_key = 0;
    port->completion_associated = 0;
    port->initial_message_context = 0;
    return !!(port->sync = port->counted_sync ? create_semaphore_sync( 0, 0x7fffffff ) :
                                              create_internal_sync( 1, 1 ));
}

static struct object *alpc_port_get_sync( struct object *obj )
{
    struct alpc_port *port = (struct alpc_port *)obj;
    return grab_object( port->sync );
}

/* Queue notification counts are consumed by public waits, independently of
 * message dequeue. Other observed port handles remain signaled. */
static void notify_port( struct alpc_port *port )
{
    if (port->counted_sync) release_semaphore_sync( port->sync, 1 );
    if (port->completion) add_completion( port->completion, port->completion_key, 0, 0, 0, NULL );
}

static void alpc_port_destroy( struct object *obj )
{
    struct alpc_port *port = (struct alpc_port *)obj;
    struct alpc_message *message, *next;

    assert( obj->ops == &alpc_port_ops );
    if (port->pdc_client) pdc_disconnect_client( port->pdc_client );
    if (port->coremsg_client)
    {
        disconnect_coremsg_client_port( port->coremsg_client );
        port->coremsg_client = NULL;
    }
    if (!list_empty( &port->kernel_session_entry ))
    {
        if (port->kernel_port == ALPC_KERNEL_DWM_SESSION_PORT)
        {
            port->thread->process->native_dwm_owner = 0;
            cleanup_dwm_logical_surfaces( port->composition_id );
        }
        list_remove( &port->kernel_session_entry );
    }
    if (port->composited_winstation)
    {
        set_winstation_composited( port->composited_winstation, 0 );
        release_object( port->composited_winstation );
    }
    if (port->composed_event) release_object( port->composed_event );
    assert( !port->completion_lease );
    if (port->completion) release_object( port->completion );

    LIST_FOR_EACH_ENTRY_SAFE( message, next, &port->messages, struct alpc_message, entry )
    {
        list_remove( &message->entry );
        free_message( message );
    }
    assert( !port->peer && !port->pending_listener && list_empty( &port->pending_connections ) );
    free_message( port->connect_reply );
    if (port->connection_port)
    {
        list_remove( &port->accepted_entry );
        release_object( port->connection_port );
    }
    if (port->sync) release_object( port->sync );
    if (port->connect_sync) release_object( port->connect_sync );
    if (port->client_token) release_object( port->client_token );
    release_object( port->thread );
}

static unsigned int next_message_id;
static struct list connecting_ports = LIST_INIT(connecting_ports);
static struct list dwm_session_ports = LIST_INIT(dwm_session_ports);
static struct list coremsg_kernel_ports = LIST_INIT(coremsg_kernel_ports);
static unsigned int next_coremsg_guid;

struct coremsg_client_port
{
    struct list entry;             /* weak entry in coremsg_kernel_port.clients */
    struct coremsg_kernel_port *port;
    process_id_t pid;
    thread_id_t tid;
    unsigned int refs;             /* ALPC endpoint plus open selector targets */
    unsigned int connected;
};

struct coremsg_connection_target
{
    struct process *owner;         /* weak; process cleanup clears the target */
    struct coremsg_client_port *client;
    unsigned char routing[40];
};

struct coremsg_kernel_port
{
    struct list entry;
    unsigned int session_id;
    unsigned char guid[16]; /* little-endian GUID wire representation */
    struct list clients;    /* weak; ALPC server endpoints own records */
    struct coremsg_connection_target targets[23];
};

static const WCHAR dwm_api_port_name[] = {'D','w','m','A','p','i','P','o','r','t'};
static const WCHAR coremsg_registrar_name[] =
    {'C','o','r','e','M','e','s','s','a','g','i','n','g','R','e','g','i','s','t','r','a','r'};
static const WCHAR coremsg_input_name[] =
    {'K','e','r','n','e','l','\\','M','I','T','\\','I','n','p','u','t','P','o','r','t',0};
static const WCHAR coremsg_listener_prefix[] =
    {'\\','B','a','s','e','N','a','m','e','d','O','b','j','e','c','t','s','\\',
     '[','C','o','r','e','M','s','g','K',']','-'};

/* CoreMessaging's AlpcClientConnection::CreateClientPort sends the private
 * ConnectionParams record as the ALPC connection message.  The kernel port
 * consumes the record while the client identity used for routing remains the
 * authenticated ALPC caller identity. */
#define COREMSG_CONNECTION_PARAMS_SIZE 24

static unsigned int get_u32( const unsigned char *data )
{
    return (unsigned int)data[0] | (unsigned int)data[1] << 8 |
           (unsigned int)data[2] << 16 | (unsigned int)data[3] << 24;
}

static unsigned int get_u16( const unsigned char *data )
{
    return (unsigned int)data[0] | (unsigned int)data[1] << 8;
}

static void put_u32( unsigned char *data, unsigned int value )
{
    data[0] = value;
    data[1] = value >> 8;
    data[2] = value >> 16;
    data[3] = value >> 24;
}

static struct coremsg_kernel_port *find_coremsg_kernel_port( unsigned int session_id )
{
    struct coremsg_kernel_port *port;

    LIST_FOR_EACH_ENTRY( port, &coremsg_kernel_ports, struct coremsg_kernel_port, entry )
        if (port->session_id == session_id) return port;
    return NULL;
}

static void make_coremsg_guid( struct coremsg_kernel_port *port )
{
    unsigned int serial = ++next_coremsg_guid;

    if (!serial) serial = ++next_coremsg_guid;
    put_u32( port->guid, 0x4e540000 | (serial & 0xffff) );
    port->guid[4] = port->session_id;
    port->guid[5] = port->session_id >> 8;
    port->guid[6] = serial >> 8;
    port->guid[7] = 0x40 | ((serial >> 16) & 0x0f);
    port->guid[8] = 0x80 | ((serial >> 16) & 0x3f);
    port->guid[9] = serial >> 24;
    memcpy( port->guid + 10, "LinuxT", 6 );
}

static struct coremsg_kernel_port *register_coremsg_kernel_port( struct process *process,
                                                                 const unsigned char *guid )
{
    struct coremsg_kernel_port *port = find_coremsg_kernel_port( process->session_id );

    if (port)
    {
        if (!guid || !memcmp( port->guid, guid, sizeof(port->guid) )) return port;
        set_error( STATUS_ALREADY_REGISTERED );
        return NULL;
    }
    if (is_native_machine() && !process->native_dwm_owner)
    {
        set_error( STATUS_ACCESS_DENIED );
        return NULL;
    }
    if (!(port = mem_alloc( sizeof(*port) ))) return NULL;
    port->session_id = process->session_id;
    list_init( &port->clients );
    memset( port->targets, 0, sizeof(port->targets) );
    if (guid) memcpy( port->guid, guid, sizeof(port->guid) );
    else make_coremsg_guid( port );
    list_add_tail( &coremsg_kernel_ports, &port->entry );
    return port;
}

static struct coremsg_client_port *grab_coremsg_client_port( struct coremsg_client_port *client )
{
    if (client) client->refs++;
    return client;
}

static void release_coremsg_client_port( struct coremsg_client_port *client )
{
    if (client && !--client->refs) free( client );
}

static void disconnect_coremsg_client_port( struct coremsg_client_port *client )
{
    if (!client->connected) return;
    list_remove( &client->entry );
    list_init( &client->entry );
    client->connected = 0;
    client->port = NULL;
    release_coremsg_client_port( client );
}

static struct coremsg_client_port *connect_coremsg_client_port( struct coremsg_kernel_port *port,
                                                                process_id_t pid, thread_id_t tid )
{
    struct coremsg_client_port *client;

    if (!(client = mem_alloc( sizeof(*client) ))) return NULL;
    client->port = port;
    client->pid = pid;
    client->tid = tid;
    client->refs = 1;
    client->connected = 1;
    list_add_tail( &port->clients, &client->entry );
    return client;
}

static struct coremsg_client_port *find_coremsg_client_port( struct coremsg_kernel_port *port,
                                                             process_id_t pid, thread_id_t tid )
{
    struct coremsg_client_port *client;

    LIST_FOR_EACH_ENTRY( client, &port->clients, struct coremsg_client_port, entry )
        if (client->connected && client->pid == pid && client->tid == tid) return client;
    return NULL;
}

static void clear_coremsg_target( struct coremsg_connection_target *target )
{
    release_coremsg_client_port( target->client );
    memset( target, 0, sizeof(*target) );
}

int set_coremsg_input_port_ready( struct process *process, int enabled )
{
    struct coremsg_kernel_port *port;

    if (!enabled) return 1;
    if (!(port = find_coremsg_kernel_port( process->session_id )) &&
        !(port = register_coremsg_kernel_port( process, NULL ))) return 0;
    if (getenv( "LINUXNT_DEBUG_PROCESS_EXITS" ))
        fprintf( stderr, "linuxnt: server coremsg-input-port winpid=%04x session=%u guid=%02x%02x%02x%02x\n",
                 process->id, process->session_id, port->guid[0], port->guid[1],
                 port->guid[2], port->guid[3] );
    return 1;
}

void cleanup_process_coremsg_connections( struct process *process )
{
    struct coremsg_kernel_port *port;
    unsigned int i;

    LIST_FOR_EACH_ENTRY( port, &coremsg_kernel_ports, struct coremsg_kernel_port, entry )
        for (i = 0; i < ARRAY_SIZE(port->targets); ++i)
            if (port->targets[i].owner == process) clear_coremsg_target( &port->targets[i] );
}

static void coremsg_guid_string( const unsigned char guid[16], WCHAR string[39] )
{
    static const unsigned char order[16] = {3,2,1,0,5,4,7,6,8,9,10,11,12,13,14,15};
    static const WCHAR hex[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
    unsigned int i, pos = 0;

    string[pos++] = '{';
    for (i = 0; i < 16; ++i)
    {
        unsigned char byte = guid[order[i]];
        string[pos++] = hex[byte >> 4];
        string[pos++] = hex[byte & 0x0f];
        if (i == 3 || i == 5 || i == 7 || i == 9) string[pos++] = '-';
    }
    string[pos++] = '}';
    string[pos] = 0;
}

static void coremsg_listener_name( const struct coremsg_kernel_port *port, WCHAR name[68] )
{
    memcpy( name, coremsg_listener_prefix, sizeof(coremsg_listener_prefix) );
    coremsg_guid_string( port->guid, name + ARRAY_SIZE(coremsg_listener_prefix) );
}

static struct coremsg_kernel_port *find_coremsg_listener( struct process *process,
                                                          const struct unicode_str *name )
{
    struct coremsg_kernel_port *port = find_coremsg_kernel_port( process->session_id );
    WCHAR expected[68];

    if (!port) return NULL;
    coremsg_listener_name( port, expected );
    if (name->len != (ARRAY_SIZE(expected) - 1) * sizeof(WCHAR) ||
        memcmp( name->str, expected, name->len )) return NULL;
    return port;
}

static struct alpc_port *find_dwm_session_port( unsigned int session_id )
{
    struct alpc_port *port;

    LIST_FOR_EACH_ENTRY( port, &dwm_session_ports, struct alpc_port, kernel_session_entry )
        if (port->kernel_session_id == session_id) return port;
    return NULL;
}

static int create_dwm_composed_event( struct alpc_port *port )
{
    static unsigned int next_composition_id = 1;
    struct object *root;
    struct unicode_str name;
    WCHAR *nameW;
    char nameA[40];

    if (!(root = get_session_base_named_objects( port->kernel_session_id ))) return 0;
    for (;;)
    {
        port->composition_id = next_composition_id++;
        if (!next_composition_id) next_composition_id = 1;
        snprintf( nameA, sizeof(nameA), "DwmComposedEvent_%x", port->composition_id );
        nameW = ascii_to_unicode_str( nameA, &name );
        port->composed_event = create_event( root, name, OBJ_CASE_INSENSITIVE, 1, 0, NULL );
        free( nameW );
        if (port->composed_event || get_error() != STATUS_OBJECT_NAME_COLLISION) break;
    }
    release_object( root );
    if (!port->composed_event) port->composition_id = 0;
    return !!port->composed_event;
}

static int is_coremsg_registrar_connection( struct alpc_port *port )
{
    struct alpc_port *server, *listener;
    const WCHAR *name;
    data_size_t name_len;

    if (port->type != COMMUNICATION_PORT || !(server = port->peer) ||
        !(listener = server->connection_port)) return 0;
    name = get_object_name( &listener->obj, &name_len );
    return name && name_len == sizeof(coremsg_registrar_name) &&
           !memcmp( name, coremsg_registrar_name, sizeof(coremsg_registrar_name) );
}

static int coremsg_request_envelope( const unsigned char *data, data_size_t size,
                                     unsigned int method )
{
    return size >= 48 && !(size & 3) && get_u32( data + 16 ) == 2 &&
           get_u32( data + 24 ) == 0x10000 && !get_u32( data + 28 ) &&
           get_u32( data + 32 ) == size - 40 && !get_u32( data + 36 ) &&
           get_u32( data + 40 ) == (size - 40) / 4 && get_u16( data + 44 ) == 1 &&
           get_u16( data + 46 ) == method;
}

static int coremsg_request_name( const unsigned char *data, data_size_t size,
                                 unsigned int method )
{
    if (!coremsg_request_envelope( data, size, method ) || size < 96 ||
        get_u32( data + 48 ) != sizeof(coremsg_input_name) ||
        memcmp( data + 52, coremsg_input_name, sizeof(coremsg_input_name) )) return 0;

    if (method == 11)
        return size == 164 && get_u32( data + 96 ) == 24 && get_u32( data + 124 ) == 8 &&
               get_u32( data + 136 ) == 16 && get_u32( data + 156 ) == 4 &&
               get_u32( data + 160 ) == 1;
    if (method == 12)
        return size == 132 && get_u32( data + 96 ) == 24 && get_u32( data + 124 ) == 4 &&
               get_u32( data + 128 ) == 1;
    return 0;
}

static int coremsg_request_record( const unsigned char *data, data_size_t size,
                                   unsigned int method, data_size_t record_size,
                                   const unsigned char guid[16] )
{
    return size == 52 + record_size && coremsg_request_envelope( data, size, method ) &&
           get_u32( data + 48 ) == record_size &&
           !memcmp( data + 52 + 24, guid, 16 );
}

static void set_coremsg_reply( struct alpc_send_receive_reply *reply, data_size_t capacity,
                               unsigned int attributes, const unsigned char *data, data_size_t size )
{
    data_size_t prefix = get_receipt_size( attributes );
    unsigned char *buffer;

    if (capacity < size)
    {
        reply->info.size = size;
        set_error( STATUS_BUFFER_TOO_SMALL );
        return;
    }
    memset( &reply->info, 0, sizeof(reply->info) );
    reply->info.type = ALPC_MESSAGE_TYPE_REPLY;
    reply->info.size = size;
    if (!(buffer = set_reply_data_size( prefix + size ))) return;
    memset( buffer, 0, prefix );
    memcpy( buffer + prefix, data, size );
}

static void build_coremsg_register_reply( unsigned int correlation, unsigned char reply[56] )
{
    memset( reply, 0, 56 );
    put_u32( reply + 20, correlation );
    put_u32( reply + 24, 0x10000 );
    put_u32( reply + 32, 16 );
    put_u32( reply + 40, 4 );
    reply[46] = 0x0e;
    put_u32( reply + 48, 4 );
}

static void build_coremsg_find_reply( const struct coremsg_kernel_port *port, unsigned int correlation,
                                      unsigned char reply[108] )
{
    memset( reply, 0, 108 );
    put_u32( reply + 20, correlation );
    put_u32( reply + 24, 0x10000 );
    put_u32( reply + 32, 68 );
    put_u32( reply + 40, 17 );
    reply[46] = 0x0f;
    put_u32( reply + 48, 4 );
    put_u32( reply + 56, 1 );
    put_u32( reply + 64, 40 );
    if (port)
    {
        put_u32( reply + 60, 1 );
        put_u32( reply + 84, 50 );
        memcpy( reply + 92, port->guid, sizeof(port->guid) );
    }
    else put_u32( reply + 52, 0x87b20809 );
}

static void build_coremsg_extended_info_reply( unsigned int correlation, unsigned char reply[76] )
{
    memset( reply, 0, 76 );
    put_u32( reply + 20, correlation );
    put_u32( reply + 24, 0x10000 );
    put_u32( reply + 32, 36 );
    put_u32( reply + 40, 9 );
    reply[46] = 0x0d;
    put_u32( reply + 48, 4 );
    put_u32( reply + 56, 16 );
    /* ExtendedRoutingInfo is the target client's VM id.  The ordinary ALPC
     * registrar initializes its local VM id to Guid::Empty; advertising a
     * nonzero value makes genuine CoreMessaging select its cross-partition
     * adapter for this otherwise local connection. */
}

static void build_coremsg_prepare_reply( const struct coremsg_kernel_port *port, unsigned int correlation,
                                         unsigned char reply[296] )
{
    WCHAR name[68];
    unsigned int i;

    coremsg_listener_name( port, name );
    memset( reply, 0, 296 );
    put_u32( reply + 20, correlation );
    put_u32( reply + 24, 0x10000 );
    put_u32( reply + 32, 256 );
    put_u32( reply + 40, 64 );
    reply[46] = 6;
    put_u32( reply + 48, 4 );
    put_u32( reply + 56, sizeof(name) );
    for (i = 0; i < ARRAY_SIZE(name); ++i)
    {
        reply[60 + 2 * i] = name[i];
        reply[61 + 2 * i] = name[i] >> 8;
    }
    put_u32( reply + 196, 16 );
    put_u32( reply + 216, 16 );
    put_u32( reply + 236, 56 );
}

/* CoreMessagingRegistrar owns public endpoint traffic.  Only the kernel-name
 * family that win32k normally publishes is consumed here. */
static int handle_coremsg_registrar_message( struct alpc_port *port,
                                             const struct alpc_send_receive_request *req,
                                             struct alpc_send_receive_reply *reply, data_size_t capacity )
{
    const unsigned char *data = get_req_data();
    data_size_t size = get_req_data_size();
    struct coremsg_kernel_port *kernel_port;
    unsigned int correlation, method;
    unsigned char response[296];

    if (!is_coremsg_registrar_connection( port ) || !(req->operation & ALPC_OPERATION_SEND) || size < 48) return 0;
    if (get_u16( data + 44 ) != 1) return 0;
    correlation = get_u32( data + 20 );
    method = get_u16( data + 46 );
    kernel_port = find_coremsg_kernel_port( current->process->session_id );
    if (getenv( "LINUXNT_DEBUG_PROCESS_EXITS" ) &&
        (method == 3 || method == 10 || method == 11 || method == 12))
        fprintf( stderr, "linuxnt: server coremsg-registrar winpid=%04x session=%u method=%u correlation=%u registered=%u\n",
                 current->process->id, current->process->session_id, method, correlation,
                 !!kernel_port );

    if (method == 11 && kernel_port && size == 164 && coremsg_request_name( data, size, 11 ) &&
        !memcmp( data + 140, kernel_port->guid, sizeof(kernel_port->guid) ))
    {
        if (!(req->operation & ALPC_OPERATION_RECEIVE) || req->flags != 0x20000)
        {
            set_error( STATUS_INVALID_PARAMETER );
            return 1;
        }
        build_coremsg_register_reply( correlation, response );
        set_coremsg_reply( reply, capacity, req->receive_attributes, response, 56 );
        return 1;
    }
    if (method == 12 && coremsg_request_name( data, size, 12 ))
    {
        if (!(req->operation & ALPC_OPERATION_RECEIVE) || req->flags != 0x20000)
        {
            set_error( STATUS_INVALID_PARAMETER );
            return 1;
        }
        build_coremsg_find_reply( kernel_port, correlation, response );
        set_coremsg_reply( reply, capacity, req->receive_attributes, response, 108 );
        return 1;
    }
    if (method == 10 && kernel_port &&
        coremsg_request_record( data, size, 10, 40, kernel_port->guid ))
    {
        if (!(req->operation & ALPC_OPERATION_RECEIVE) || req->flags != 0x20000)
        {
            set_error( STATUS_INVALID_PARAMETER );
            return 1;
        }
        build_coremsg_extended_info_reply( correlation, response );
        set_coremsg_reply( reply, capacity, req->receive_attributes, response, 76 );
        return 1;
    }
    if (method == 3 && kernel_port &&
        coremsg_request_record( data, size, 3, 56, kernel_port->guid ))
    {
        if (!(req->operation & ALPC_OPERATION_RECEIVE) || req->flags != 0x20000)
        {
            set_error( STATUS_INVALID_PARAMETER );
            return 1;
        }
        build_coremsg_prepare_reply( kernel_port, correlation, response );
        set_coremsg_reply( reply, capacity, req->receive_attributes, response, 296 );
        return 1;
    }
    return 0;
}

/* USER observes the startup messages while the DWM port server dispatches the
 * same messages to uDWM.  Keep the phase transition in the session owner, but
 * retain normal ALPC delivery for the upper user-mode protocol. */
static int handle_dwm_session_message( struct alpc_port *port, const struct alpc_send_receive_request *req,
                                       struct alpc_send_receive_reply *reply, data_size_t capacity )
{
    const unsigned int *message = get_req_data();
    unsigned int response[4];
    data_size_t size = get_req_data_size();

    if (!(req->operation & ALPC_OPERATION_SEND) || req->message_id) return 0;
    if (size < sizeof(*message))
    {
        set_error( STATUS_INVALID_PARAMETER );
        return 1;
    }

    if (req->flags == 0x10000)
    {
        enum dwm_session_port_phase next_phase;

        if (size != 2 * sizeof(*message) || message[1])
        {
            set_error( STATUS_INVALID_PARAMETER );
            return 1;
        }
        if (message[0] == 0x40000025 && port->kernel_session_phase == DWM_SESSION_PORT_REGISTERED)
            next_phase = DWM_SESSION_PORT_INITIALIZING;
        else if (message[0] == 0x40000026 && port->kernel_session_phase == DWM_SESSION_PORT_STARTED)
            next_phase = DWM_SESSION_PORT_READY;
        else
        {
            set_error( STATUS_INVALID_DEVICE_STATE );
            return 1;
        }
        /* StartupBegin enables monitor targets and expects the desktop root
         * visuals published by win32k startup to exist already.  Hold the
         * initializing record until start_dwm_kernel has queued the initial
         * kernel-only desktop-create set; the ready record can follow the
         * ordinary port path. */
        if (message[0] == 0x40000025)
            port->kernel_session_phase = next_phase;
        else if (send_message( port, req->flags, req->message_id, req->callback_id, req->message_type, (req->operation & ALPC_OPERATION_WOW64),
                               req->send_attributes, req->message_context, req->security_context,
                               message, size, NULL ))
        {
            port->kernel_session_phase = next_phase;
            replay_dcomp_window_targets( port->kernel_session_id );
        }
        return 1;
    }

    if (req->flags != 0x20000 || !(req->operation & ALPC_OPERATION_RECEIVE) || size != sizeof(response) ||
        message[0] != 0x8000000a)
    {
        set_error( STATUS_NOT_IMPLEMENTED );
        return 1;
    }
    if (port->kernel_session_phase != DWM_SESSION_PORT_READY)
    {
        set_error( STATUS_INVALID_DEVICE_STATE );
        return 1;
    }
    if (capacity < size)
    {
        reply->info.size = size;
        set_error( STATUS_BUFFER_TOO_SMALL );
        return 1;
    }

    memcpy( response, message, sizeof(response) );
    response[1] = 0;
    memset( &reply->info, 0, sizeof(reply->info) );
    reply->info.type = ALPC_MESSAGE_TYPE_REPLY;
    reply->info.size = sizeof(response);
    set_reply_data( response, sizeof(response) );
    return 1;
}

static void finish_connect_operation( struct alpc_port *port )
{
    if (!port->connecting_handle) return;
    list_remove( &port->connecting_entry );
    port->connecting_handle = 0;
    if (port->connecting_wait_handle)
    {
        close_handle( port->thread->process, port->connecting_wait_handle );
        port->connecting_wait_handle = 0;
    }
    release_object( port->connect_sync );
    port->connect_sync = NULL;
}

void cleanup_thread_alpc( struct thread *thread )
{
    struct alpc_port *port, *next;
    LIST_FOR_EACH_ENTRY_SAFE( port, next, &connecting_ports, struct alpc_port, connecting_entry )
        if (port->thread == thread) close_handle( thread->process, port->connecting_handle );
    cleanup_thread_message_waits( thread );
}

static void initialize_message( struct alpc_message *message, const void *data, data_size_t size,
                                 unsigned int type, unsigned int id, struct thread *sender )
{
    message->request = NULL;
    message->reserve = NULL;
    message->destination = NULL;
    message->token = NULL;
    message->work_ticket = 0;
    message->security_context = 0;
    memset( &message->info, 0, sizeof(message->info) );
    message->info.callback_id = id;
    message->info.id = id;
    message->info.type = type;
    message->info.pid = sender->process->id;
    message->info.tid = sender->id;
    message->info.size = size;
    if (size) memcpy( message->data, data, size );
}

static struct alpc_message *new_message( const void *data, data_size_t size, unsigned int type,
                                        unsigned int id, struct thread *sender )
{
    struct alpc_message *message;
    if (!(message = mem_alloc( sizeof(*message) + size ))) return NULL;
    if (!id && !(id = ++next_message_id)) id = ++next_message_id;
    initialize_message( message, data, size, type, id, sender );
    return message;
}

static struct alpc_message *reserved_message( struct alpc_resource_reserve *reserve, const void *data,
                                             data_size_t size, unsigned int type, unsigned int callback_id )
{
    struct alpc_message *message = reserve->buffer;
    if (reserve->buffer_in_use || size > reserve->size)
    {
        set_error( STATUS_NOT_IMPLEMENTED ); /* capacity exhaustion is not yet observed */
        return NULL;
    }
    initialize_message( message, data, size, type, reserve->message_id, current );
    message->info.callback_id = callback_id;
    message->reserve = reserve;
    reserve->refs++;
    reserve->buffer_in_use = 1;
    return message;
}

/* Metadata is assigned once when a message is destined for an endpoint.
 * Short results and retries retain the same sequence and context. */
static void set_message_destination( struct alpc_message *message, struct alpc_port *port,
                                     client_ptr_t message_context )
{
    message->destination = port;
    message->info.port_context = port->context;
    message->info.message_context = message_context;
    message->info.sequence = ++port->receive_sequence;
    message->info.attributes_valid |= ALPC_MESSAGE_CONTEXT_ATTRIBUTE;
    port->initial_message_context = 0;
}

/* Win32k publishes desktop composition lifecycle changes as kernel-only
 * datagrams on the registered DwmApiPort.  The genuine redirection layer
 * forwards these records to uDWM, which keys its root visuals by the same
 * stable desktop identity exposed through GetDesktopID(). */
static void queue_dwm_desktop_message( struct alpc_port *port, unsigned int command,
                                       struct desktop *desktop )
{
    struct alpc_message *message;
    unsigned __int64 id;
    unsigned int data[3];

    if (!desktop->shared) return;
    id = get_shared_object_locator( desktop->shared ).id;
    data[0] = command;
    memcpy( data + 1, &id, sizeof(id) );
    /* LpcRequestPort supplies the asynchronous datagram type while win32k's
     * packet sets the private kernel-only bit.  DwmRedir requires both: its
     * router dispatches low-byte type 3 before ProcessCommand examines bit
     * 0x8000 to select the kernel-only handler. */
    if (!(message = new_message( data, sizeof(data),
                                 ALPC_MESSAGE_TYPE_DATAGRAM | 0x8000, 0, port->thread ))) return;

    /* Native kernel messages have no client identity or request/reply ID. */
    message->info.pid = 0;
    message->info.tid = 0;
    message->info.id = 0;
    message->info.callback_id = 0;
    set_message_destination( message, port, port->initial_message_context );
    list_add_tail( &port->messages, &message->entry );
    notify_port( port );
    dispatch_receives( port );
    if (getenv( "LINUXNT_DEBUG_PROCESS_EXITS" ))
        fprintf( stderr, "linuxnt: server dwm-desktop-message command=%08x id=%016llx phase=%u\n",
                 command, (unsigned long long)id, port->kernel_session_phase );
}

static struct alpc_port *find_dwm_session_port_for_winstation( struct winstation *winstation )
{
    struct alpc_port *port;

    LIST_FOR_EACH_ENTRY( port, &dwm_session_ports, struct alpc_port, kernel_session_entry )
        if (port->composited_winstation == winstation &&
            port->kernel_session_phase >= DWM_SESSION_PORT_STARTED) return port;
    return NULL;
}

void notify_dwm_desktop_created( struct desktop *desktop )
{
    struct alpc_port *port;

    if ((port = find_dwm_session_port_for_winstation( desktop->winstation )))
        queue_dwm_desktop_message( port, 0x4000000e, desktop );
}

void notify_dwm_desktop_destroyed( struct desktop *desktop )
{
    struct alpc_port *port;

    if ((port = find_dwm_session_port_for_winstation( desktop->winstation )))
        queue_dwm_desktop_message( port, 0x40000010, desktop );
}

static int queue_dwm_window_message( struct alpc_port *port, const void *data,
                                     data_size_t size, const char *name,
                                     unsigned int window );

void notify_dwm_shell_window_changed( struct desktop *desktop, unsigned int window )
{
    struct alpc_port *port = find_dwm_session_port_for_winstation( desktop->winstation );
    unsigned __int64 desktop_id, value = window;
    unsigned char data[20] = {0};

    if (!port || !desktop->shared) return;
    desktop_id = get_shared_object_locator( desktop->shared ).id;
    put_u32( data, 0x4000000d );
    memcpy( data + 4, &value, sizeof(value) );
    memcpy( data + 12, &desktop_id, sizeof(desktop_id) );
    queue_dwm_window_message( port, data, sizeof(data), "shell-change", window );
}

static int queue_dwm_window_message( struct alpc_port *port, const void *data,
                                     data_size_t size, const char *name,
                                     unsigned int window )
{
    struct alpc_message *message;

    if (!(message = new_message( data, size, ALPC_MESSAGE_TYPE_DATAGRAM | 0x8000,
                                 0, port->thread ))) return 0;
    message->info.pid = 0;
    message->info.tid = 0;
    message->info.id = 0;
    message->info.callback_id = 0;
    set_message_destination( message, port, port->initial_message_context );
    list_add_tail( &port->messages, &message->entry );
    notify_port( port );
    dispatch_receives( port );
    if (getenv( "LINUXNT_DEBUG_PROCESS_EXITS" ))
        fprintf( stderr, "linuxnt: server dwm-window-%s window=%08x phase=%u\n",
                 name, window, port->kernel_session_phase );
    return 1;
}

unsigned int notify_dwm_window_created( struct desktop *desktop, unsigned int generation,
                                        unsigned int window, unsigned int parent,
                                        unsigned int style, unsigned int ex_style,
                                        const struct rectangle *rect, unsigned int process_id,
                                        unsigned __int64 process_sequence )
{
    struct alpc_port *port = find_dwm_session_port_for_winstation( desktop->winstation );
    unsigned __int64 value;
    unsigned char data[124] = {0};

    if (!port) return 0;
    if (generation == port->composition_id) return generation;
    put_u32( data, 0x40000011 );
    value = window;
    memcpy( data + 4, &value, sizeof(value) );
    value = parent;
    memcpy( data + 12, &value, sizeof(value) );
    put_u32( data + 20, style );
    put_u32( data + 24, ex_style );
    memcpy( data + 28, rect, sizeof(*rect) );
    /* data + 44 is the initial private composition state and data + 48 is
     * WINDOWCOMPOSITIONINFO. Wine has no corresponding server state yet;
     * their all-zero values are the native default-window representation. */
    value = get_shared_object_locator( desktop->shared ).id;
    memcpy( data + 104, &value, sizeof(value) );
    put_u32( data + 112, process_id );
    memcpy( data + 116, &process_sequence, sizeof(process_sequence) );
    if (!queue_dwm_window_message( port, data, sizeof(data), "create", window )) return 0;
    return port->composition_id;
}

void notify_dwm_window_sprite_order( struct desktop *desktop, unsigned int generation,
                                      unsigned int window, unsigned int below )
{
    struct alpc_port *port = find_dwm_session_port_for_winstation( desktop->winstation );
    unsigned __int64 value;
    unsigned char data[20] = {0};

    if (!port || generation != port->composition_id) return;
    put_u32( data, 0x40000005 );
    value = window;
    memcpy( data + 4, &value, sizeof(value) );
    value = below;
    memcpy( data + 12, &value, sizeof(value) );
    queue_dwm_window_message( port, data, sizeof(data), "sprite-order", window );
}

void notify_dwm_window_rects_changed( struct desktop *desktop, unsigned int generation,
                                      unsigned int window, const struct rectangle *window_rect,
                                      const struct rectangle *client_rect )
{
    struct alpc_port *port = find_dwm_session_port_for_winstation( desktop->winstation );
    unsigned __int64 value = window;
    unsigned char data[64] = {0};

    if (!port || generation != port->composition_id) return;
    put_u32( data, 0x40000015 );
    memcpy( data + 4, &value, sizeof(value) );
    memcpy( data + 12, window_rect, sizeof(*window_rect) );
    memcpy( data + 28, client_rect, sizeof(*client_rect) );
    /* Borderless contexts have no content insets or resize-border width. */
    memcpy( data + 44, window_rect, sizeof(*window_rect) );
    queue_dwm_window_message( port, data, sizeof(data), "rects", window );
}

int notify_dwm_window_linked( struct desktop *desktop, unsigned int generation,
                              unsigned int window, unsigned int parent,
                              unsigned int previous, unsigned int band )
{
    struct alpc_port *port = find_dwm_session_port_for_winstation( desktop->winstation );
    unsigned __int64 value;
    unsigned char data[32] = {0};

    if (!port || generation != port->composition_id) return 0;
    put_u32( data, 0x40000012 );
    value = window;
    memcpy( data + 4, &value, sizeof(value) );
    value = parent;
    memcpy( data + 12, &value, sizeof(value) );
    value = previous;
    memcpy( data + 20, &value, sizeof(value) );
    put_u32( data + 28, band );
    return queue_dwm_window_message( port, data, sizeof(data), "link", window );
}

void notify_dwm_window_style_changed( struct desktop *desktop, unsigned int generation,
                                      unsigned int window, int offset, unsigned int value )
{
    struct alpc_port *port = find_dwm_session_port_for_winstation( desktop->winstation );
    unsigned __int64 hwnd = window;
    unsigned char data[20] = {0};

    if (!port || generation != port->composition_id) return;
    put_u32( data, 0x40000016 );
    memcpy( data + 4, &hwnd, sizeof(hwnd) );
    put_u32( data + 12, offset );
    put_u32( data + 16, value );
    queue_dwm_window_message( port, data, sizeof(data), "style", window );
}

void notify_dwm_window_visibility_changed( struct desktop *desktop, unsigned int generation,
                                           unsigned int window, int visible )
{
    struct alpc_port *port = find_dwm_session_port_for_winstation( desktop->winstation );
    unsigned __int64 hwnd = window;
    unsigned char data[16] = {0};

    if (!port || generation != port->composition_id) return;
    put_u32( data, 0x40000007 );
    memcpy( data + 4, &hwnd, sizeof(hwnd) );
    put_u32( data + 12, visible );
    queue_dwm_window_message( port, data, sizeof(data), "visibility", window );
}

static void put_dwm_mini_window_info( unsigned char *data, struct desktop *desktop,
                                      unsigned int style, unsigned int ex_style, int active,
                                      const struct rectangle *window_rect,
                                      const struct rectangle *client_rect )
{
    unsigned __int64 desktop_id = get_shared_object_locator( desktop->shared ).id;

    memcpy( data, window_rect, sizeof(*window_rect) );
    memcpy( data + 16, client_rect, sizeof(*client_rect) );
    put_u32( data + 32, style );
    put_u32( data + 36, ex_style );
    put_u32( data + 44, !!active );
    memcpy( data + 48, &desktop_id, sizeof(desktop_id) );
}

static void build_dwm_sprite_update( unsigned char data[196], struct desktop *desktop,
                                     unsigned int window, unsigned int style,
                                     unsigned int ex_style, int active,
                                     const struct rectangle *window_rect,
                                     const struct rectangle *client_rect,
                                     unsigned int logical_surface,
                                     unsigned int surface_width,
                                     unsigned int surface_height )
{
    unsigned __int64 value = window, surface = logical_surface;

    memset( data, 0, 196 );
    put_u32( data, 0x40000006 );
    memcpy( data + 4, &value, sizeof(value) );
    /* Bit 3 publishes an independent logical-surface identity.  It must not
     * be the HWND: queued compositor updates may outlive their source window. */
    put_u32( data + 12, (logical_surface ? 0x8 : 0) | !!(style & WS_VISIBLE) );
    put_u32( data + 16, 1 );
    put_dwm_mini_window_info( data + 20, desktop, style, ex_style, active,
                              window_rect, client_rect );
    memcpy( data + 168, &surface, sizeof(surface) );
    put_u32( data + 180, surface_width );
    put_u32( data + 184, surface_height );
}

int notify_dwm_window_sprite_created( struct desktop *desktop, unsigned int generation,
                                      unsigned int window, unsigned int style,
                                      unsigned int ex_style, int active,
                                      const struct rectangle *window_rect,
                                      const struct rectangle *client_rect,
                                      unsigned int logical_surface,
                                      unsigned int surface_width,
                                      unsigned int surface_height )
{
    struct alpc_port *port = find_dwm_session_port_for_winstation( desktop->winstation );
    unsigned __int64 value = window;
    unsigned char create[180] = {0};
    unsigned char update[196];

    if (!port || generation != port->composition_id) return 0;
    put_u32( create, 0x40000002 );
    memcpy( create + 4, &value, sizeof(value) );
    memcpy( create + 12, &value, sizeof(value) );
    memcpy( create + 20, window_rect, sizeof(*window_rect) );
    put_u32( create + 36, !!(style & WS_VISIBLE) );
    put_dwm_mini_window_info( create + 40, desktop, style, ex_style, active,
                              window_rect, client_rect );
    /* Native DwmRedir uses this Win32 compatibility version only to retain
     * pre-Windows-8 source-modification behavior. */
    put_u32( create + 176, 0x0a00 );
    build_dwm_sprite_update( update, desktop, window, style, ex_style, active,
                             window_rect, client_rect, logical_surface,
                             surface_width, surface_height );
    if (!queue_dwm_window_message( port, create, sizeof(create), "sprite-create", window ))
        return 0;
    if (!queue_dwm_window_message( port, update, sizeof(update), "sprite-update", window ))
        return 0;
    if (getenv( "LINUXNT_DEBUG_PROCESS_EXITS" ))
        fprintf( stderr, "linuxnt: server dwm-window-sprite-data window=%08x "
                 "surface=%08x size=%ux%u rect=%d,%d-%d,%d visible=%u\n",
                 window, logical_surface, surface_width, surface_height,
                 window_rect->left, window_rect->top, window_rect->right,
                 window_rect->bottom, !!(style & WS_VISIBLE) );
    return 1;
}

void notify_dwm_window_sprite_updated( struct desktop *desktop, unsigned int generation,
                                       unsigned int window, unsigned int style,
                                       unsigned int ex_style, int active,
                                       const struct rectangle *window_rect,
                                       const struct rectangle *client_rect,
                                       unsigned int logical_surface,
                                       unsigned int surface_width,
                                       unsigned int surface_height )
{
    struct alpc_port *port = find_dwm_session_port_for_winstation( desktop->winstation );
    unsigned char data[196];

    if (!port || generation != port->composition_id) return;
    build_dwm_sprite_update( data, desktop, window, style, ex_style, active,
                             window_rect, client_rect, logical_surface,
                             surface_width, surface_height );
    queue_dwm_window_message( port, data, sizeof(data), "sprite-update", window );
    if (getenv( "LINUXNT_DEBUG_PROCESS_EXITS" ))
        fprintf( stderr, "linuxnt: server dwm-window-sprite-data window=%08x "
                 "surface=%08x size=%ux%u rect=%d,%d-%d,%d visible=%u\n",
                 window, logical_surface, surface_width, surface_height,
                 window_rect->left, window_rect->top, window_rect->right,
                 window_rect->bottom, !!(style & WS_VISIBLE) );
}

void notify_dwm_window_sprite_dirty( struct desktop *desktop, unsigned int generation,
                                     unsigned int window, unsigned int flags,
                                     unsigned __int64 update_id )
{
    struct alpc_port *port = find_dwm_session_port_for_winstation( desktop->winstation );
    unsigned __int64 sprite = window;
    unsigned char data[24] = {0};

    if (!port || generation != port->composition_id) return;
    put_u32( data, 0x40000004 );
    put_u32( data + 4, flags );
    memcpy( data + 8, &sprite, sizeof(sprite) );
    memcpy( data + 16, &update_id, sizeof(update_id) );
    queue_dwm_window_message( port, data, sizeof(data), "sprite-dirty", window );
}

void notify_dwm_window_sprite_destroyed( struct desktop *desktop, unsigned int generation,
                                         unsigned int window )
{
    struct alpc_port *port = find_dwm_session_port_for_winstation( desktop->winstation );
    unsigned __int64 value = window;
    unsigned char data[12] = {0};

    if (!port || generation != port->composition_id) return;
    put_u32( data, 0x40000003 );
    memcpy( data + 4, &value, sizeof(value) );
    queue_dwm_window_message( port, data, sizeof(data), "sprite-destroy", window );
}

void notify_dwm_window_unlinked( struct desktop *desktop, unsigned int generation,
                                 unsigned int window, unsigned int parent )
{
    struct alpc_port *port = find_dwm_session_port_for_winstation( desktop->winstation );
    unsigned __int64 value;
    unsigned char data[20] = {0};

    if (!port || generation != port->composition_id) return;
    put_u32( data, 0x40000013 );
    value = window;
    memcpy( data + 4, &value, sizeof(value) );
    value = parent;
    memcpy( data + 12, &value, sizeof(value) );
    queue_dwm_window_message( port, data, sizeof(data), "unlink", window );
}

void notify_dwm_window_destroyed( struct desktop *desktop, unsigned int generation,
                                  unsigned int window )
{
    struct alpc_port *port = find_dwm_session_port_for_winstation( desktop->winstation );
    unsigned __int64 value = window;
    unsigned char data[12] = {0};

    if (!port || generation != port->composition_id) return;
    put_u32( data, 0x40000014 );
    memcpy( data + 4, &value, sizeof(value) );
    queue_dwm_window_message( port, data, sizeof(data), "destroy", window );
}

/* Native win32k publishes window-relative visible regions in chunks of at
 * most 27 RECTs.  A null region removes the corresponding tracker region;
 * an empty region is represented by one empty RECT. */
int notify_dwm_window_visible_region( struct desktop *desktop, unsigned int generation,
                                      unsigned int window, unsigned int type,
                                      const struct region *region )
{
    struct alpc_port *port = find_dwm_session_port_for_winstation( desktop->winstation );
    struct rectangle *rects = NULL;
    data_size_t rect_size = 0;
    unsigned int offset = 0, count = 0;
    unsigned __int64 hwnd = window;
    int ret = 1;

    if (!port || generation != port->composition_id ||
        port->kernel_session_phase != DWM_SESSION_PORT_READY) return 0;
    if (region)
    {
        if (!(rects = get_region_data( region, ~(data_size_t)0, &rect_size ))) return 0;
        count = rect_size / sizeof(*rects);
    }

    do
    {
        unsigned int chunk = min( count - offset, 27u );
        unsigned char data[28 + 27 * sizeof(struct rectangle)] = {0};

        put_u32( data, 0x40000096 );
        memcpy( data + 4, &hwnd, sizeof(hwnd) );
        put_u32( data + 12, offset );
        put_u32( data + 16, count );
        put_u32( data + 20, type );
        put_u32( data + 24, chunk );
        if (chunk) memcpy( data + 28, rects + offset, chunk * sizeof(*rects) );
        if (!queue_dwm_window_message( port, data, 28 + chunk * sizeof(*rects),
                                       "visible-region", window ))
        {
            ret = 0;
            break;
        }
        offset += chunk;
    } while (offset < count);

    free( rects );
    return ret;
}

static int queue_dwm_window_target_message( struct alpc_port *port, unsigned int command,
                                            unsigned int window, unsigned int type,
                                            obj_handle_t handle )
{
    struct alpc_message *message;
    unsigned char data[24] = {0};
    unsigned __int64 value;
    data_size_t size;

    memcpy( data, &command, sizeof(command) );
    value = window;
    memcpy( data + 4, &value, sizeof(value) );
    memcpy( data + 12, &type, sizeof(type) );
    if (command == 0x40000045)
    {
        value = handle;
        memcpy( data + 16, &value, sizeof(value) );
        size = sizeof(data);
    }
    else size = 16;

    if (!(message = new_message( data, size, ALPC_MESSAGE_TYPE_DATAGRAM | 0x8000,
                                 0, port->thread ))) return 0;
    message->info.pid = 0;
    message->info.tid = 0;
    message->info.id = 0;
    message->info.callback_id = 0;
    set_message_destination( message, port, port->initial_message_context );
    list_add_tail( &port->messages, &message->entry );
    notify_port( port );
    dispatch_receives( port );
    if (getenv( "LINUXNT_DEBUG_PROCESS_EXITS" ))
        fprintf( stderr, "linuxnt: server dwm-window-target command=%08x window=%08x "
                 "type=%u handle=%04x\n", command, window, type, handle );
    return 1;
}

int notify_dwm_window_target_created( unsigned int session_id, unsigned int window,
                                      unsigned int type, struct object *target )
{
    struct alpc_port *port = find_dwm_session_port( session_id );
    obj_handle_t handle;

    if (!port || port->kernel_session_phase != DWM_SESSION_PORT_READY) return 1;
    if (!(handle = alloc_handle_no_access_check( port->thread->process, target, 0, 0 ))) return 0;
    if (!queue_dwm_window_target_message( port, 0x40000045, window, type, handle ))
    {
        close_handle( port->thread->process, handle );
        return 0;
    }
    return 1;
}

void notify_dwm_window_target_destroyed( unsigned int session_id, unsigned int window,
                                         unsigned int type )
{
    struct alpc_port *port = find_dwm_session_port( session_id );

    if (port && port->kernel_session_phase == DWM_SESSION_PORT_READY)
        queue_dwm_window_target_message( port, 0x40000046, window, type, 0 );
}

int notify_dwm_blurred_wallpaper_surface( unsigned int session_id, struct object *surface,
                                          const struct rectangle *rect )
{
    struct alpc_port *port = find_dwm_session_port( session_id );
    unsigned char data[28] = {0};
    obj_handle_t handle = 0;
    unsigned __int64 value = 0;

    /* The native syscall is asynchronous and succeeds when DWM is absent. */
    if (!port || port->kernel_session_phase != DWM_SESSION_PORT_READY) return 1;
    if (surface)
    {
        if (!(handle = alloc_handle_no_access_check( port->thread->process, surface, 0, 0 )))
            return 0;
        value = handle;
    }
    put_u32( data, 0x40000058 );
    memcpy( data + 4, &value, sizeof(value) );
    memcpy( data + 12, rect, sizeof(*rect) );
    if (!queue_dwm_window_message( port, data, sizeof(data), "blurred-wallpaper", 0 ))
    {
        if (handle) close_handle( port->thread->process, handle );
        return 0;
    }
    return 1;
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
    if (request->reply) request->reply->request = NULL;
    lose_message_wait( request );
    list_remove( &request->entry );
    if (request->token) release_object( request->token );
    if (request->sender_process) release_object( request->sender_process );
    if (request->reserve)
    {
        struct alpc_resource_reserve *reserve = request->reserve;
        assert( !reserve->spare_request );
        memset( request, 0, sizeof(*request) );
        reserve->spare_request = request;
        release_resource_reserve( reserve );
    }
    else free( request );
}

static struct alpc_port *message_queue( struct alpc_port *endpoint );

static struct alpc_message *find_message( struct alpc_port *port )
{
    struct alpc_port *queue = message_queue( port );
    struct alpc_message *message;

    LIST_FOR_EACH_ENTRY( message, &queue->messages, struct alpc_message, entry )
        if (queue == port || message->destination == port) return message;
    return NULL;
}

/* Canceling an undelivered request retains its queue position. A listener
 * closing returns cancellations to the originating endpoints instead. */
static struct alpc_message *new_cancellation( struct alpc_request *request )
{
    struct alpc_message *message;
    if (!(message = new_message( NULL, 0, ALPC_MESSAGE_TYPE_CANCELED |
                                (request->wow64 ? 0x1000 : 0), request->id, request->target->thread ))) return NULL;
    message->info.callback_id = request->callback_id;
    message->info.pid = request->pid;
    message->info.tid = request->tid;
    return message;
}

static void cancel_queued_message( struct alpc_message *message )
{
    message->info.size = 0;
    message->info.type = ALPC_MESSAGE_TYPE_CANCELED | (message->info.type & 0x1000);
}

static void cancel_message_request( struct alpc_request *request, struct alpc_port *queue )
{
    struct alpc_message *message = request->message;
    int delivered = !message;
    if (!message)
    {
        /* Delivered requests retain a canceled reply right, without publishing
         * another queue entry. Moving ownership to a closing listener's peer
         * does publish a cancellation there. */
        if (queue != request->queue && (message = new_cancellation( request )))
        {
            set_message_destination( message, queue, request->message_context );
            list_add_tail( &queue->messages, &message->entry );
        }
    }
    else
    {
        if (queue != request->queue)
        {
            list_remove( &message->entry );
            set_message_destination( message, queue, request->message_context );
            list_add_tail( &queue->messages, &message->entry );
        }
        cancel_queued_message( message );
    }
    if (message && (delivered || queue != request->queue)) notify_port( queue );
    if (delivered && queue == request->queue)
    {
        request->source = NULL;
        request->canceled = 1;
        request->message = message;
        if (message) message->request = request;
    }
    else free_message_request( request );
}

/* Explicit cancellation of a delivered request returns a cancellation to the
 * originating endpoint. Synchronous callers own the result through their
 * private wait; asynchronous callers receive it through the endpoint queue. */
static int return_request_cancellation( struct alpc_request *request )
{
    struct alpc_port *source = request->source;
    struct alpc_message *message;

    if (!source)
    {
        set_error( STATUS_PORT_DISCONNECTED );
        return 0;
    }
    if (!(message = new_cancellation( request ))) return 0;
    set_message_destination( message, source, request->message_context );
    request->canceled = 1;

    if (request->wait)
    {
        struct alpc_wait *wait = request->wait;

        request->wait = NULL;
        wait->request = NULL;
        wait->info = message->info;
        wait->reply = message;
        wait->status = STATUS_SUCCESS;
        request->released = 1;
        request->reply = message;
        message->request = request;
        signal_sync( wait->sync );
    }
    else
    {
        struct alpc_port *queue = message_queue( source );

        request->message = message;
        message->request = request;
        list_add_tail( &queue->messages, &message->entry );
        notify_port( queue );
    }
    return 1;
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

/* The owner decides completion versus cancellation before the client returns.
 * A client-side wait timeout alone cannot discard a concurrently delivered message. */
static void cancel_message_wait( struct alpc_wait *wait )
{
    struct alpc_request *request = wait->request;
    if (wait->receive_port)
    {
        list_remove( &wait->receive_entry );
        wait->receive_port = NULL;
    }
    if (request)
    {
        wait->request = NULL;
        request->wait = NULL;
        if (request->target->status == DISCONNECTED && !request->message) free_message_request( request );
        else cancel_message_request( request, request->queue );
    }
    dispatch_all_receives();
}

static int alpc_wait_close_handle( struct object *obj, struct process *process, obj_handle_t handle )
{
    struct alpc_wait *wait = (struct alpc_wait *)obj;
    if (process != wait->thread->process || handle != wait->handle) return 1;
    list_remove( &wait->entry );
    wait->handle = 0;
    cancel_message_wait( wait );
    return 1;
}

static void alpc_wait_destroy( struct object *obj )
{
    struct alpc_wait *wait = (struct alpc_wait *)obj;
    assert( !wait->request && !wait->handle && !wait->receive_port );
    free_message( wait->reply );
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
    wait->receive_port = NULL;
    list_init( &wait->receive_entry );
    wait->reply = NULL;
    wait->capacity = capacity;
    memset( &wait->info, 0, sizeof(wait->info) );
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

/* Taking a queued copy is the single transition that grants receive ownership. */
static struct alpc_message *take_message( struct alpc_port *queue, struct alpc_message *message )
{
    if ((message->info.type & 0xff) == ALPC_MESSAGE_TYPE_CONNECTION_REQUEST)
    {
        struct alpc_port *client;
        LIST_FOR_EACH_ENTRY( client, &queue->pending_connections, struct alpc_port, pending_entry )
            if (client->connection_id == message->info.id) client->request_delivered = 1;
    }
    if (message->request)
    {
        message->request->message = NULL;
        if (message->request->canceled || message->request->released) free_message_request( message->request );
        message->request = NULL;
    }
    list_remove( &message->entry );
    return message;
}

static void dispatch_receives( struct alpc_port *port )
{
    struct alpc_port *queue = message_queue( port );
    struct alpc_message *message;

    while (!list_empty( &port->receive_waiters ))
    {
        struct alpc_wait *wait = LIST_ENTRY( list_head( &port->receive_waiters ), struct alpc_wait, receive_entry );
        unsigned int status = port->connect_status == STATUS_PENDING ? 0 : port->connect_status;

        if (!(message = find_message( port )) && !status) break;
        list_remove( &wait->receive_entry );
        wait->receive_port = NULL;
        if (status) wait->status = status;
        else
        {
            wait->info = message->info;
            if (message->info.size > wait->capacity) wait->status = STATUS_BUFFER_TOO_SMALL;
            else
            {
                wait->reply = take_message( queue, message );
                wait->status = STATUS_SUCCESS;
            }
        }
        signal_sync( wait->sync );
    }
    if (queue == port)
    {
        struct alpc_port *accepted;
        LIST_FOR_EACH_ENTRY( accepted, &port->accepted_connections, struct alpc_port, accepted_entry )
            dispatch_receives( accepted );
    }
}

/* Cancellation and closure can publish to several queues in one operation.
 * Dispatch only after their request and endpoint mutations are complete. */
static void dispatch_all_receives( void )
{
    struct alpc_wait *wait;
    LIST_FOR_EACH_ENTRY( wait, &message_waits, struct alpc_wait, entry )
        if (wait->receive_port) dispatch_receives( wait->receive_port );
}

static void close_receive_waits( struct alpc_port *port )
{
    struct alpc_wait *wait, *next;
    LIST_FOR_EACH_ENTRY_SAFE( wait, next, &port->receive_waiters, struct alpc_wait, receive_entry )
    {
        list_remove( &wait->receive_entry );
        wait->receive_port = NULL;
        wait->status = STATUS_PORT_CLOSED;
        signal_sync( wait->sync );
    }
}

static void close_message_requests( struct alpc_port *port )
{
    struct alpc_request *request, *next;
    LIST_FOR_EACH_ENTRY_SAFE( request, next, &message_requests, struct alpc_request, entry )
    {
        if (request->released)
        {
            if (request->reply)
            {
                /* Delivery to a private operation survives endpoint close.
                 * Keep identity, but never retain a dangling endpoint. */
                if (request->source == port) request->source = NULL;
                if (request->target == port) request->target = NULL;
                if (request->queue == port) request->queue = NULL;
            }
            else if (request->target == port || request->queue == port)
            {
                if (request->message)
                {
                    list_remove( &request->message->entry );
                    free_message( request->message );
                    request->message = NULL;
                }
                free_message_request( request );
            }
            else if (request->source == port)
            {
                /* A queued reply has not reached its receiver. Retain its
                 * registry identity while turning that copy into cancellation. */
                if (request->message) cancel_queued_message( request->message );
                request->source = NULL;
                request->canceled = 1;
            }
            continue;
        }
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
                free_message( request->message );
                request->message = NULL;
            }
            free_message_request( request );
        }
    }
}

static void close_destination_messages( struct alpc_port *port )
{
    struct alpc_message *message, *next;
    struct alpc_port *queue;

    if (!(queue = port->connection_port)) return;
    LIST_FOR_EACH_ENTRY_SAFE( message, next, &queue->messages, struct alpc_message, entry )
    {
        struct alpc_request *request;

        if (message->destination != port) continue;
        list_remove( &message->entry );
        if ((request = message->request) && request->message == message)
        {
            request->message = NULL;
            message->request = NULL;
            free_message_request( request );
        }
        free_message( message );
    }
}

static void disconnect_message_requests( struct alpc_port *port )
{
    struct alpc_request *request, *next;
    LIST_FOR_EACH_ENTRY_SAFE( request, next, &message_requests, struct alpc_request, entry )
        if (request->source == port && !request->reply)
        {
            struct alpc_message *copy;
            int synchronous = !!request->wait;
            if (request->released)
            {
                if (request->message) cancel_queued_message( request->message );
                continue;
            }
            lose_message_wait( request );
            if (!synchronous && (copy = new_cancellation( request )))
            {
                set_message_destination( copy, port, request->message_context );
                list_add_tail( &message_queue( port )->messages, &copy->entry );
                notify_port( message_queue( port ) );
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
    set_message_destination( message, port->peer, port->peer->initial_message_context );
    message->info.pid = message->info.tid = 0;
    list_add_tail( &queue->messages, &message->entry );
    notify_port( queue );
}

/* Server communication handles send through their peer but receive through
 * their listener. Client endpoints have their own incoming queue. */
static struct alpc_port *message_queue( struct alpc_port *endpoint )
{
    return endpoint->connection_port ? endpoint->connection_port : endpoint;
}

static int send_message( struct alpc_port *port, unsigned int flags, unsigned int id,
                         unsigned int callback_id, unsigned int message_type, int wow64,
                         unsigned int send_attributes, client_ptr_t message_context, client_ptr_t security_context,
                         const void *data, data_size_t size, struct alpc_wait *wait )
{
    struct alpc_port *target = port, *queue, *origin = port;
    struct alpc_request *request = NULL, *candidate;
    struct alpc_message *message;
    struct alpc_resource_reserve *reserve = NULL;
    struct alpc_security_context *context = NULL;
    int reserved_send = (message_type & 0x4000) && (id & 0x80000000);
    unsigned int type = flags & 0x10000 ? 3 : 0x2001;
    client_ptr_t received_context;

    if (send_attributes & ALPC_MESSAGE_SECURITY_ATTRIBUTE)
    {
        if (!(context = find_security_context( port, security_context )))
        { set_error( STATUS_INVALID_HANDLE ); return 0; }
        if (context->owner != port) { set_error( STATUS_ACCESS_DENIED ); return 0; }
    }

    if (reserved_send)
    {
        if (!(reserve = find_resource_reserve( port, id )) || reserve->owner != port)
        { set_error( STATUS_OBJECTID_NOT_FOUND ); return 0; }
        if (!reserve->spare_request) { set_error( STATUS_RESOURCE_IN_USE ); return 0; }
        if (flags || port->type != COMMUNICATION_PORT)
        { set_error( STATUS_NOT_IMPLEMENTED ); return 0; }
        id = 0;
        if (!(callback_id = ++next_message_id)) callback_id = ++next_message_id;
    }
    if (port->type == COMMUNICATION_PORT)
    {
        if (port->status == DISCONNECTED || (!port->peer && !id))
        {
            set_error( STATUS_PORT_DISCONNECTED );
            return 0;
        }
        target = port->peer;
        if (target && target->kernel_port == ALPC_KERNEL_PDC_PORT)
        {
            set_error( pdc_receive_message( target->pdc_client, data, size ) );
            return 0;
        }
        if (!id && target->kernel_port == ALPC_KERNEL_POWER_PORT)
        {
            /* The kernel power manager consumes policy updates without a
             * user-mode reply. Kernel-originated notifications are not yet
             * synthesized. */
            if (flags & 0x20000)
            {
                set_error( STATUS_NOT_IMPLEMENTED );
                return 0;
            }
            return 1;
        }
        if (!id && target->kernel_port == ALPC_KERNEL_COREMSG_PORT)
        {
            /* The connection and lifetime are real ALPC state.  Private input
             * packet delivery is a separate contract and is not fabricated. */
            if (flags & 0x20000)
            {
                set_error( STATUS_NOT_IMPLEMENTED );
                return 0;
            }
            return 1;
        }
        if (!id && port->connection_port && !(target->flags & 0x20000))
        {
            set_error( STATUS_LPC_REQUESTS_NOT_ALLOWED );
            return 0;
        }
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
        if (request->reserve && request->callback_id != callback_id)
        { set_error( STATUS_INVALID_MESSAGE ); return 0; }
        if (request->reserve) reserve = request->reserve;
        /* A released private reply is already owned by the waiting operation.
         * Retain its request for result cleanup and impersonation, but reject
         * another reply independently of the retargeted endpoint pointers. */
        if (request->released && request->reply)
        {
            set_error( STATUS_INVALID_MESSAGE );
            return 0;
        }
        if (!request->target || (request->target != port && request->target->connection_port != port))
        {
            set_error( STATUS_ACCESS_DENIED );
            return 0;
        }
        if (request->released)
        {
            set_error( STATUS_INVALID_MESSAGE );
            return 0;
        }
        origin = request->target;
        if (request->canceled)
        {
            if (request->message)
            {
                list_remove( &request->message->entry );
                free_message( request->message );
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
    type |= (message_type & 0x4000) | (wow64 ? 0x1000 : 0);
    message = reserve ? reserved_message( reserve, data, size, type, callback_id ) :
                        new_message( data, size, type, id, current );
    if (!message) return 0;
    if (send_attributes & ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE)
    {
        if (!(message->work_ticket = thread_get_work_ticket( current )))
        {
            free_message( message );
            return 0;
        }
        message->info.attributes_valid |= ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE;
    }
    if (context)
    {
        message->token = (struct token *)grab_object( context->token );
        message->security_context = context->id;
        message->info.attributes_valid |= ALPC_MESSAGE_SECURITY_ATTRIBUTE | ALPC_MESSAGE_TOKEN_ATTRIBUTE;
    }
    else if (!origin->connection_port && !origin->tracking_mode && origin->client_token)
    {
        message->token = (struct token *)grab_object( origin->client_token );
        message->info.attributes_valid |= ALPC_MESSAGE_TOKEN_ATTRIBUTE;
    }
    else if (!origin->connection_port && origin->tracking_mode &&
             (flags & 0x20000) && (origin->flags & 0x10000))
    {
        /* A dynamically tracked datagram has no stable sender context and
         * cannot be impersonated.  A synchronous sender is blocked until its
         * reply, so retain its current effective token for authorization and
         * expose its metadata in the receiving listener's receipt. */
        message->token = (struct token *)grab_object( thread_get_impersonation_token( current ) );
        message->info.attributes_valid |= ALPC_MESSAGE_TOKEN_ATTRIBUTE;
    }
    received_context = request ? request->message_context : target->initial_message_context;
    if (!request && !(flags & 0x10000) && port->type == COMMUNICATION_PORT)
    {
        if (reserve)
        {
            request = reserve->spare_request;
            reserve->spare_request = NULL;
            reserve->refs++;
        }
        else if (!(request = mem_alloc( sizeof(*request) ))) { free_message( message ); return 0; }
        request->reserve = reserve;
        request->security_context = 0;
        request->callback_id = message->info.callback_id;
        request->no_impersonate = !!(message_type & 0x4000);
        request->token = NULL;
        request->sender_process = NULL;
        request->reply = NULL;
        request->wait = NULL;
        request->message_context = message_context;
        request->released = 0;
        request->id = message->info.id;
        request->message = NULL;
        list_add_tail( &message_requests, &request->entry );
    }
    if (request)
    {
        if (request->token) release_object( request->token );
        request->token = message->token ? (struct token *)grab_object( message->token ) : NULL;
        request->impersonation_level = context ? context->impersonation_level : origin->impersonation_level;
        request->security_context = context ? context->id : 0;
        request->message_context = message_context;
        request->receive_message_context = received_context;
        request->source = origin;
        request->target = target;
        request->queue = queue;
        if (request->sender_process) release_object( request->sender_process );
        request->sender_process = (struct process *)grab_object( current->process );
        request->pid = current->process->id;
        request->tid = current->id;
        request->wow64 = wow64;
        request->canceled = 0;
    }
    set_message_destination( message, target, received_context );
    if (request && request->wait)
    {
        struct alpc_wait *receiver = request->wait;
        receiver->info = message->info;
        /* A private synchronous result omits token metadata. If the buffer
         * is short, ordinary recovery still observes the queued receipt. */
        receiver->info.attributes_valid &= ~ALPC_MESSAGE_TOKEN_ATTRIBUTE;
        receiver->request = NULL;
        request->wait = NULL;
        if (message->info.size <= receiver->capacity)
        {
            receiver->reply = message;
            receiver->status = STATUS_SUCCESS;
            signal_sync( receiver->sync );
            if (flags & 0x10000)
            {
                request->released = 1;
                request->reply = message;
                message->request = request;
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
        if (flags & 0x10000) request->released = 1;
        request->wait = wait;
        if (wait) wait->request = request;
        request->message = message;
        message->request = request;
    }
    list_add_tail( &queue->messages, &message->entry );
    notify_port( queue );
    dispatch_receives( queue );
    return 1;
}

static void detach_peer( struct alpc_port *port )
{
    struct alpc_port *peer = port->peer;
    if (!peer) return;
    port->peer = NULL;
    assert( peer->peer == port );
    peer->peer = NULL;
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
    {
        struct alpc_resource_reserve *reserve, *next;
        LIST_FOR_EACH_ENTRY_SAFE( reserve, next, &resource_reserves, struct alpc_resource_reserve, entry )
            if (reserve->owner == port) unregister_resource_reserve( reserve );
    }
    {
        struct alpc_security_context *context, *next;
        LIST_FOR_EACH_ENTRY_SAFE( context, next, &security_contexts, struct alpc_security_context, entry )
            if (context->owner == port) unregister_security_context( context );
    }
    if (port->pending_listener)
    {
        struct alpc_port *listener = port->pending_listener;
        /* Convert an undelivered request to a cancellation notification.
         * If it was already received, publish a new notification with its ID. */
        LIST_FOR_EACH_ENTRY( message, &listener->messages, struct alpc_message, entry )
            if (message->info.id == port->connection_id) break;
        if (&message->entry != &listener->messages)
        {
            message->info.size = 0;
            message->info.type = ALPC_MESSAGE_TYPE_CANCELED | (port->wow64 ? 0x1000 : 0);
        }
        else if ((message = new_message( NULL, 0, ALPC_MESSAGE_TYPE_CANCELED |
                                         (port->wow64 ? 0x1000 : 0), port->connection_id, port->thread )))
        {
            list_add_tail( &listener->messages, &message->entry );
            notify_port( listener );
        }
        unlink_pending( port );
    }
    LIST_FOR_EACH_ENTRY_SAFE( client, next, &port->pending_connections, struct alpc_port, pending_entry )
    {
        if (client->want_reply)
        {
            client->connect_status = STATUS_MESSAGE_LOST;
            signal_sync( client->connect_sync );
        }
        else
        {
            if ((message = new_message( NULL, 0, ALPC_MESSAGE_TYPE_CANCELED |
                                         (client->wow64 ? 0x1000 : 0), client->connection_id, client->thread )))
            {
                set_message_destination( message, client, client->initial_message_context );
                list_add_tail( &client->messages, &message->entry );
            }
            else client->connect_status = STATUS_NO_MEMORY;
            notify_port( client );
        }
        unlink_pending( client );
    }
    close_receive_waits( port );
    close_message_requests( port );
    close_destination_messages( port );
    queue_port_closed( port );
    LIST_FOR_EACH_ENTRY_SAFE( client, next, &port->accepted_connections, struct alpc_port, accepted_entry )
        detach_peer( client );
    port->status = DISCONNECTED;
    detach_peer( port );
    dispatch_all_receives();
    return 1;
}

/* A thread-pool registration keeps the object alive without adding a port
 * handle. Closing the last real port handle must still disconnect its peers. */
struct alpc_completion_lease
{
    struct object obj;
    struct alpc_port *port;
};

static void alpc_completion_lease_dump( struct object *obj, int verbose )
{
    fprintf( stderr, "ALPC completion registration port=%p\n", ((struct alpc_completion_lease *)obj)->port );
}

static void alpc_completion_lease_destroy( struct object *obj )
{
    struct alpc_completion_lease *lease = (struct alpc_completion_lease *)obj;
    struct alpc_port *port = lease->port;

    if (!port) return;
    assert( port->completion_lease == lease );
    port->completion_lease = NULL;
    if (port->completion) release_object( port->completion );
    port->completion = NULL;
    /* The Windows-visible association remains consumed after TP release. */
    release_object( port );
}

static const struct object_ops alpc_completion_lease_ops =
{
    .size = sizeof(struct alpc_completion_lease),
    .type = &no_type,
    .dump = alpc_completion_lease_dump,
    .destroy = alpc_completion_lease_destroy
};

/* Associate an I/O completion queue, optionally retaining a private TP lease. */
DECL_HANDLER(alpc_set_completion)
{
    struct alpc_completion_lease *lease = NULL;
    struct completion *completion;
    struct alpc_port *port;
    struct alpc_message *message;
    unsigned int count = 0;

    if (!req->handle || !req->completion || req->lease > 1)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    if (!(port = (struct alpc_port *)get_handle_obj( current->process, req->handle,
                                                    ALPC_PORT_QUERY_STATE, &alpc_port_ops ))) return;
    if (port->completion_associated)
    {
        set_error( STATUS_PORT_ALREADY_SET );
        goto done;
    }
    if (!(completion = get_completion_obj( current->process, req->completion, IO_COMPLETION_MODIFY_STATE )))
        goto done;
    if (req->lease)
    {
        if (!(lease = alloc_object( &alpc_completion_lease_ops )))
        {
            release_object( completion );
            goto done;
        }
        lease->port = NULL;
        if (!(reply->lease = alloc_handle_no_access_check( current->process, lease, 0, 0 )))
        {
            release_object( lease );
            release_object( completion );
            goto done;
        }
        lease->port = (struct alpc_port *)grab_object( port );
        port->completion_lease = lease;
        release_object( lease );
    }
    port->completion = completion;
    port->completion_key = req->key;
    port->completion_associated = 1;
    LIST_FOR_EACH_ENTRY( message, &port->messages, struct alpc_message, entry ) ++count;
    if (!add_completion_notifications( completion, req->key, count ))
    {
        unsigned int status = get_error();
        if (reply->lease)
        {
            close_handle( current->process, reply->lease );
            reply->lease = 0;
        }
        else
        {
            release_object( port->completion );
            port->completion = NULL;
        }
        port->completion_associated = 0;
        port->completion_key = 0;
        set_error( status );
    }
done:
    release_object( port );
}

/* Return the state exposed by AlpcBasicInformation. */
DECL_HANDLER(alpc_query_information)
{
    struct alpc_port *port;

    if (!(port = (struct alpc_port *)get_handle_obj( current->process, req->handle,
                                                    ALPC_PORT_QUERY_STATE, &alpc_port_ops ))) return;
    reply->flags = port->flags;
    reply->sequence = port->receive_sequence;
    reply->context = port->context;
    release_object( port );
}

/* Create an ALPC port */
DECL_HANDLER(alpc_create_port)
{
    struct alpc_port_init_data data = { .type = CONNECTION_PORT, .flags = req->flags,
                                        .max_msg_len = req->max_msg_len };
    struct object_params params = { .ops = &alpc_port_ops, .init_data = &data,
                                    .access = ALPC_PORT_ALL_ACCESS };

    if (!get_req_object_attributes( &params )) return;
    if (current->process->native_dwm_owner && getenv( "LINUXNT_DEBUG_PROCESS_EXITS" ))
    {
        fprintf( stderr, "linuxnt: server dwm-alpc-create winpid=%04x root=%p attributes=%#x name=\"",
                 current->process->id, params.root, params.attr );
        dump_strW( params.name.str, params.name.len, stderr, "\"\"" );
        fputs( "\"\n", stderr );
    }
    reply->handle = create_named_obj_handle( current->process, &params );
    if (params.root) release_object( params.root );
}

DECL_HANDLER(alpc_create_resource_reserve)
{
    struct alpc_port *port;
    struct alpc_resource_reserve *reserve;

    if (!(port = (struct alpc_port *)get_handle_obj( current->process, req->handle,
                                                    ALPC_PORT_QUERY_STATE, &alpc_port_ops ))) return;
    if (req->size < 40) { set_error( STATUS_INVALID_PARAMETER ); goto done; }
    if (req->size > 65495) { set_error( STATUS_BUFFER_OVERFLOW ); goto done; }
    if (!(reserve = mem_alloc( sizeof(*reserve) ))) goto done;
    memset( reserve, 0, sizeof(*reserve) );
    reserve->buffer = mem_alloc( sizeof(*reserve->buffer) + req->size );
    reserve->spare_request = mem_alloc( sizeof(*reserve->spare_request) );
    if (!reserve->buffer || !reserve->spare_request)
    {
        free( reserve->buffer );
        free( reserve->spare_request );
        free( reserve );
        goto done;
    }
    memset( reserve->spare_request, 0, sizeof(*reserve->spare_request) );
    reserve->owner = port;
    reserve->refs = 1;
    reserve->size = req->size;
    if (!(reserve->message_id = ++next_message_id)) reserve->message_id = ++next_message_id;
    reserve->id = allocate_resource_id();
    list_add_tail( &resource_reserves, &reserve->entry );
    reply->id = reserve->id;
done:
    release_object( port );
}

DECL_HANDLER(alpc_delete_resource_reserve)
{
    struct alpc_port *port;
    struct alpc_resource_reserve *reserve;

    if (!(port = (struct alpc_port *)get_handle_obj( current->process, req->handle,
                                                    ALPC_PORT_QUERY_STATE, &alpc_port_ops ))) return;
    if ((reserve = find_resource_reserve( port, req->id ))) unregister_resource_reserve( reserve );
    else set_error( STATUS_INVALID_HANDLE );
    release_object( port );
}

DECL_HANDLER(alpc_create_security_context)
{
    struct alpc_port *port;
    struct alpc_security_context *context;
    struct token *token;
    int level, tracking, effective;

    if (!(port = (struct alpc_port *)get_handle_obj( current->process, req->handle,
                                                    ALPC_PORT_QUERY_STATE, &alpc_port_ops ))) return;
    level = req->qos_present ? req->impersonation_level : port->impersonation_level;
    tracking = req->qos_present ? req->tracking_mode : port->tracking_mode;
    effective = req->qos_present ? req->effective_only : port->effective_only;
    if (level < SecurityAnonymous || level > SecurityDelegation)
    { set_error( STATUS_BAD_IMPERSONATION_LEVEL ); goto done; }
    if (!(context = mem_alloc( sizeof(*context) ))) goto done;
    token = thread_get_impersonation_token( current );
    context->token = tracking ? (struct token *)grab_object( token ) :
                               token_duplicate_impersonation( token, level, effective & 1 );
    if (!context->token) { free( context ); goto done; }
    context->owner = port;
    context->id = allocate_resource_id();
    context->impersonation_level = level;
    list_add_tail( &security_contexts, &context->entry );
    reply->id = context->id;
done:
    release_object( port );
}

DECL_HANDLER(alpc_delete_security_context)
{
    struct alpc_port *port;
    struct alpc_security_context *context;

    if (!(port = (struct alpc_port *)get_handle_obj( current->process, req->handle,
                                                    ALPC_PORT_QUERY_STATE, &alpc_port_ops ))) return;
    if (!(context = find_security_context( port, req->id ))) set_error( STATUS_INVALID_HANDLE );
    else if (context->owner != port) set_error( STATUS_ACCESS_DENIED );
    else unregister_security_context( context );
    release_object( port );
}

/* The listening-port queue is shared by every duplicate of its handle. */
DECL_HANDLER(alpc_send_receive)
{
    struct alpc_port *port, *queue;
    struct alpc_message *message;
    data_size_t capacity;
    data_size_t size = get_req_data_size();
    struct alpc_wait *wait = NULL;
    int reply_receive;

    if (!get_receive_capacity( req->receive_attributes, &capacity )) return;
    if (!(port = (struct alpc_port *)get_handle_obj( current->process, req->handle,
                                                    ALPC_PORT_ALL_ACCESS, &alpc_port_ops ))) return;
    queue = message_queue( port );
    if (port->thread->process != current->process)
    {
        set_error( STATUS_ACCESS_DENIED );
        goto done;
    }
    reply_receive = (req->flags & 0x20000) && (req->operation & ALPC_OPERATION_SEND) && (req->operation & ALPC_OPERATION_RECEIVE) && req->message_id;
    if ((req->flags & 0x20000) &&
        (!(req->operation & ALPC_OPERATION_SEND) || (req->message_id && !(req->operation & ALPC_OPERATION_RECEIVE)) || (req->flags & 0x10000)))
    {
        set_error( STATUS_INVALID_PARAMETER_2 );
        goto done;
    }
    if (port->kernel_port == ALPC_KERNEL_DWM_SESSION_PORT)
    {
        if (handle_dwm_session_message( port, req, reply, capacity )) goto done;
    }
    if (handle_coremsg_registrar_message( port, req, reply, capacity )) goto done;
    /* The native RPC 0x400000 modifier preserves plain-message ownership.
     * It does not bypass endpoint authorization or resource validation. */
    if (req->flags & ~(ALPC_MSGFLG_REPLY_MESSAGE | ALPC_MSGFLG_RELEASE_MESSAGE |
                       ALPC_MSGFLG_SYNC_REQUEST | ALPC_MSGFLG_TRACK_PORT_REFERENCES |
                       ALPC_MSGFLG_WOW64_CALL | 0x400000) ||
        ((req->flags & 0x20000) && (!(req->operation & ALPC_OPERATION_RECEIVE) || port->type == CONNECTION_PORT)))
    {
        set_error( STATUS_NOT_IMPLEMENTED );
        goto done;
    }
    if ((req->flags & 0x20000) && !reply_receive && !(wait = create_message_wait( capacity ))) goto done;
    if ((req->operation & ALPC_OPERATION_SEND) && !send_message( port, reply_receive ? 1 : req->flags, req->message_id,
                                    req->callback_id, req->message_type, (req->operation & ALPC_OPERATION_WOW64), req->send_attributes, req->message_context,
                                    req->security_context,
                                    get_req_data(), size, wait )) goto done;
    if (wait)
    {
        reply->wait_handle = wait->handle;
        set_error( STATUS_PENDING );
        goto done;
    }
    if (!(req->operation & ALPC_OPERATION_RECEIVE)) goto done;
    if (port->connect_status && port->connect_status != STATUS_PENDING)
    {
        set_error( port->connect_status );
        goto done;
    }
    if (!(message = find_message( port )))
    {
        if (port->connection_port || !(port->flags & 0x40000))
        {
            if ((req->operation & ALPC_OPERATION_NO_WAIT))
            {
                set_error( STATUS_TIMEOUT );
                goto done;
            }
            if (!(wait = create_message_wait( capacity ))) goto done;
            wait->receive_port = port;
            list_add_tail( &port->receive_waiters, &wait->receive_entry );
            reply->wait_handle = wait->handle;
            set_error( STATUS_PENDING );
        }
        else set_error( STATUS_UNSUCCESSFUL );
        goto done;
    }
    reply->info = message->info;
    if (message->info.size > capacity)
    {
        set_error( STATUS_BUFFER_TOO_SMALL );
        goto done;
    }

    if (!set_message_reply( message, req->receive_attributes )) goto done;
    free_message( take_message( queue, message ) );

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
    data_size_t capacity;
    if (!get_receive_capacity( req->receive_attributes, &capacity )) return;
    if (!(wait = (struct alpc_wait *)get_handle_obj( current->process, req->handle, 0, &alpc_wait_ops ))) return;
    if (wait->thread != current || wait->handle != req->handle) set_error( STATUS_ACCESS_DENIED );
    else
    {
        if (wait->status == STATUS_PENDING && req->wait_status)
        {
            wait->status = req->wait_status;
            cancel_message_wait( wait );
        }
        reply->info = wait->info;
        set_error( wait->status );
        if (!wait->status && (message = wait->reply))
        {
            if (message->info.size > capacity) set_error( STATUS_BUFFER_TOO_SMALL );
            else if (set_message_reply( message, req->receive_attributes ))
            {
                free_message( wait->reply );
                wait->reply = NULL;
            }
        }
    }
    release_object( wait );
}

/* Native resolves the global message identity first, then authorizes it
 * against the supplied communication endpoint or its listener. */
DECL_HANDLER(alpc_cancel_message)
{
    struct alpc_request *request = NULL, *candidate;
    struct alpc_port *port;
    unsigned int status;

    if (!(port = (struct alpc_port *)get_handle_obj( current->process, req->handle,
                                                    ALPC_PORT_QUERY_STATE, &alpc_port_ops ))) return;
    if (port->thread->process != current->process)
    {
        set_error( STATUS_ACCESS_DENIED );
        goto done;
    }

    LIST_FOR_EACH_ENTRY( candidate, &message_requests, struct alpc_request, entry )
        if (candidate->id == req->message_id &&
            (!req->callback_id || candidate->callback_id == req->callback_id))
        {
            request = candidate;
            break;
        }
    if (!request)
    {
        set_error( STATUS_INVALID_MESSAGE );
        goto done;
    }
    if (!request->target || (request->target != port && request->target->connection_port != port &&
                             request->queue != port))
    {
        set_error( STATUS_ACCESS_DENIED );
        goto done;
    }
    if (request->canceled)
    {
        set_error( STATUS_REQUEST_CANCELED );
        goto done;
    }
    if ((req->flags & 8) && request->receive_message_context != req->message_context)
    {
        set_error( STATUS_CONTEXT_MISMATCH );
        goto done;
    }

    status = request->message ? STATUS_PENDING : STATUS_MESSAGE_RETRIEVED;
    if (req->flags & 1)
    {
        set_error( status );
        goto done;
    }
    if (request->message) cancel_message_request( request, request->queue );
    else if (!return_request_cancellation( request )) goto done;
    set_error( status );

done:
    release_object( port );
}

/* The listener owns pending clients. Synchronous admission uses a private
 * wait handle; asynchronous admission returns the client immediately and
 * delivers acceptance or cancellation through its receive queue. */
DECL_HANDLER(alpc_connect_port)
{
    static const WCHAR pdc_port_name[] = {'\\','P','d','c','P','o','r','t'};
    static const WCHAR power_port_name[] = {'\\','P','o','w','e','r','P','o','r','t'};
    const struct alpc_security_qos *qos = get_req_data();
    const unsigned char *data = (const unsigned char *)(qos + 1);
    data_size_t size = get_req_data_size(), payload_size;
    struct unicode_str name;
    const struct sid *sid;
    const struct security_descriptor *server_sd;
    struct alpc_port *listener = NULL, *client = NULL, *server = NULL;
    struct coremsg_kernel_port *coremsg_port = NULL;
    struct pdc_client *pdc_client = NULL;
    struct alpc_message *message;
    enum alpc_kernel_port kernel_port = ALPC_KERNEL_PORT_NONE;
    struct alpc_port_init_data init = { .type = COMMUNICATION_PORT,
                                        .flags = req->port_flags |
                                                 (req->flags & ALPC_PORTFLG_ALLOW_DUP_OBJECT),
                                        .max_msg_len = req->max_msg_len };
    struct alpc_port_init_data server_init = { .type = COMMUNICATION_PORT, .server = 1,
                                               .flags = req->port_flags,
                                               .max_msg_len = req->max_msg_len };
    struct object_params params = { .ops = &alpc_port_ops, .init_data = &init };
    struct object_params server_params = { .ops = &alpc_port_ops, .init_data = &server_init };
    obj_handle_t lookup = 0, handle = 0;

    if (size < sizeof(*qos)) { set_error( STATUS_INVALID_PARAMETER ); return; }
    size -= sizeof(*qos);
    if (qos->tracking_mode != SECURITY_STATIC_TRACKING && qos->tracking_mode != SECURITY_DYNAMIC_TRACKING)
    { set_error( STATUS_INVALID_PARAMETER ); return; }
    if (qos->impersonation_level < SecurityAnonymous || qos->impersonation_level > SecurityDelegation)
    { set_error( STATUS_BAD_IMPERSONATION_LEVEL ); return; }
    if (req->name_size > size || req->name_size % sizeof(WCHAR) || req->sid_size > size - req->name_size ||
        req->server_sd_size > size - req->name_size - req->sid_size)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    if (req->flags & ~(ALPC_SYNC_CONNECTION | ALPC_PORTFLG_ALLOW_DUP_OBJECT))
    {
        set_error( STATUS_NOT_IMPLEMENTED );
        return;
    }
    name.str = (const WCHAR *)data;
    name.len = req->name_size;
    if (current->process->native_dwm_owner && getenv( "LINUXNT_DEBUG_PROCESS_EXITS" ))
    {
        fprintf( stderr, "linuxnt: server dwm-alpc-connect winpid=%04x root=%04x attributes=%#x name=\"",
                 current->process->id, req->rootdir, req->attributes );
        dump_strW( name.str, name.len, stderr, "\"\"" );
        fputs( "\"\n", stderr );
    }
    sid = (const struct sid *)(data + req->name_size);
    if (req->sid_size && (!sid_valid_size( sid, req->sid_size ) || sid->revision != SID_REVISION ||
                         sid->sub_count > SID_MAX_SUB_AUTHORITIES || sid_len( sid ) != req->sid_size))
    {
        set_error( STATUS_INVALID_SID );
        return;
    }
    server_sd = (const struct security_descriptor *)(data + req->name_size + req->sid_size);
    if (req->server_sd_size && !sd_is_valid( server_sd, req->server_sd_size ))
    {
        set_error( STATUS_INVALID_SECURITY_DESCR );
        return;
    }
    payload_size = size - req->name_size - req->sid_size - req->server_sd_size;
    if (!req->rootdir && !req->attributes && name.len == sizeof(power_port_name) &&
        !memcmp( name.str, power_port_name, sizeof(power_port_name) ))
        kernel_port = ALPC_KERNEL_POWER_PORT;
    else if (!req->rootdir && !(req->attributes & ~OBJ_CASE_INSENSITIVE) && name.len == sizeof(pdc_port_name) &&
             !(req->attributes & OBJ_CASE_INSENSITIVE ? memicmp_strW( name.str, pdc_port_name, name.len ) :
                                                       memcmp( name.str, pdc_port_name, name.len )))
        kernel_port = ALPC_KERNEL_PDC_PORT;
    else if (!req->rootdir && !(req->attributes & ~OBJ_CASE_INSENSITIVE) &&
             (coremsg_port = find_coremsg_listener( current->process, &name )))
    {
        kernel_port = ALPC_KERNEL_COREMSG_PORT;
        if (getenv( "LINUXNT_DEBUG_PROCESS_EXITS" ))
            fprintf( stderr, "linuxnt: server coremsg-connect winpid=%04x session=%u attributes=%#x\n",
                     current->process->id, current->process->session_id, req->attributes );
    }
    if (kernel_port != ALPC_KERNEL_PORT_NONE)
    {
        if (req->sid_size || req->server_sd_size ||
            (kernel_port != ALPC_KERNEL_PDC_PORT &&
             (coremsg_port ? payload_size != COREMSG_CONNECTION_PARAMS_SIZE : payload_size)))
        {
            set_error( STATUS_INVALID_PARAMETER );
            goto done;
        }
        if (kernel_port == ALPC_KERNEL_PDC_PORT)
        {
            if (!(pdc_client = pdc_connect_client( current->process, thread_get_impersonation_token( current ),
                                                   &alpc_port_type.mapping, data + req->name_size,
                                                   payload_size, req->client_flags & 1 ))) goto done;
            if (req->max_msg_len < sizeof(ALPC_PORT_MESSAGE) + payload_size)
            { set_error( STATUS_PORT_MESSAGE_TOO_LONG ); goto done; }
        }
        if (!(client = create_named_object( &params ))) goto done;
        client->impersonation_level = qos->impersonation_level;
        client->tracking_mode = qos->tracking_mode;
        client->effective_only = qos->effective_only;
        if (qos->tracking_mode == SECURITY_DYNAMIC_TRACKING)
            client->client_token = (struct token *)grab_object( thread_get_impersonation_token( current ) );
        else if (!(client->client_token = token_duplicate_impersonation( thread_get_impersonation_token( current ),
                                           qos->impersonation_level, qos->effective_only & 1 ))) goto done;
        if (!(handle = alloc_handle( current->process, client, ALPC_PORT_ALL_ACCESS, 0 ))) goto done;
        if (!(client->connect_sync = create_internal_sync( 1, 1 )) ||
            !(client->connecting_wait_handle = alloc_handle( current->process, client->connect_sync,
                                                             SYNCHRONIZE, 0 )))
        {
            close_handle( current->process, handle );
            handle = 0;
            goto done;
        }
        if (!(server = create_named_object( &server_params )))
        {
            close_handle( current->process, handle );
            handle = 0;
            goto done;
        }
        server->kernel_port = kernel_port;
        server->pdc_client = pdc_client;
        pdc_client = NULL;
        if (coremsg_port) server->kernel_session_id = coremsg_port->session_id;
        if (coremsg_port && !(server->coremsg_client = connect_coremsg_client_port(
                                 coremsg_port, current->process->id, current->id )))
        {
            close_handle( current->process, handle );
            handle = 0;
            goto done;
        }
        server->impersonation_level = client->impersonation_level;
        server->tracking_mode = client->tracking_mode;
        server->effective_only = client->effective_only;
        if (!client->tracking_mode)
            server->client_token = (struct token *)grab_object( client->client_token );
        client->context = handle;
        if (kernel_port == ALPC_KERNEL_PDC_PORT)
        {
            if (!(message = new_message( data + req->name_size, payload_size,
                                          ALPC_MESSAGE_TYPE_CONNECTION_REPLY, 0, current )))
            {
                close_handle( current->process, client->connecting_wait_handle );
                client->connecting_wait_handle = 0;
                close_handle( current->process, handle );
                handle = 0;
                goto done;
            }
            set_message_destination( message, client, req->message_context );
            client->want_reply = req->flags & ALPC_SYNC_CONNECTION;
            client->connect_reply = message;
        }
        server->peer = (struct alpc_port *)grab_object( client );
        client->peer = (struct alpc_port *)grab_object( server );
        server->status = client->status = CONNECTED;
        client->connect_status = STATUS_SUCCESS;
        client->context = handle;
        client->connecting_handle = handle;
        list_add_tail( &connecting_ports, &client->connecting_entry );
        reply->handle = handle;
        reply->wait_handle = client->connecting_wait_handle;
        goto done;
    }
    if (!(lookup = open_object( current->process, req->rootdir, ALPC_PORT_QUERY_STATE,
                                &alpc_port_ops, name, req->attributes ))) return;
    if (!(listener = (struct alpc_port *)get_handle_obj( current->process, lookup,
                                                        ALPC_PORT_QUERY_STATE, &alpc_port_ops ))) goto done;
    if (listener->type != CONNECTION_PORT || listener->status == DISCONNECTED)
    {
        set_error( STATUS_PORT_DISCONNECTED );
        goto done;
    }
    if (req->sid_size && !equal_sid( sid, token_get_user( listener->thread->process->token ) ))
    {
        set_error( STATUS_SERVER_SID_MISMATCH );
        goto done;
    }
    if (req->server_sd_size &&
        !token_check_security_descriptor_access( listener->thread->process->token, server_sd,
                                                 ALPC_PORT_QUERY_STATE, &alpc_port_type.mapping ))
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
    client->impersonation_level = qos->impersonation_level;
    client->tracking_mode = qos->tracking_mode;
    client->effective_only = qos->effective_only;
    client->security_context = !!(req->client_flags & 2);
    if (qos->tracking_mode == SECURITY_DYNAMIC_TRACKING)
        client->client_token = (struct token *)grab_object( thread_get_impersonation_token( current ) );
    else if (!(client->client_token = token_duplicate_impersonation( thread_get_impersonation_token( current ),
                                       qos->impersonation_level, qos->effective_only & 1 ))) goto done;
    if (!(handle = alloc_handle( current->process, client, ALPC_PORT_ALL_ACCESS, 0 ))) goto done;
    if (!(message = new_message( data + req->name_size + req->sid_size + req->server_sd_size, payload_size,
                                ALPC_MESSAGE_TYPE_CONNECTION_REQUEST | 0x2000 |
                                (req->client_flags & 1 ? 0x1000 : 0), 0, current )))
    {
        close_handle( current->process, handle );
        goto done;
    }
    if (req->flags & ALPC_SYNC_CONNECTION)
    {
        if (!(client->connect_sync = create_internal_sync( 1, 0 )) ||
            !(client->connecting_wait_handle = alloc_handle( current->process, client->connect_sync, SYNCHRONIZE, 0 )))
        {
            free_message( message );
            close_handle( current->process, handle );
            goto done;
        }
        client->connecting_handle = handle;
        list_add_tail( &connecting_ports, &client->connecting_entry );
    }
    message->token = (struct token *)grab_object( client->client_token );
    message->info.attributes_valid |= ALPC_MESSAGE_TOKEN_ATTRIBUTE;
    client->context = handle;
    client->initial_message_context = req->message_context;
    message->info.sequence = ++listener->receive_sequence;
    client->want_reply = !!(req->flags & ALPC_SYNC_CONNECTION);
    client->connection_id = message->info.id;
    client->wow64 = req->client_flags & 1;
    client->pending_listener = listener;
    list_add_tail( &listener->pending_connections, &client->pending_entry );
    grab_object( client );
    list_add_tail( &listener->messages, &message->entry );
    notify_port( listener );
    reply->handle = handle;
    reply->wait_handle = client->connecting_wait_handle;
    dispatch_receives( listener );

done:
    if (client && !reply->handle && client->connecting_wait_handle)
    {
        unsigned int status = get_error();
        close_handle( current->process, client->connecting_wait_handle );
        client->connecting_wait_handle = 0;
        set_error( status );
    }
    if (pdc_client) pdc_disconnect_client( pdc_client );
    if (server) release_object( server );
    if (client) release_object( client );
    if (listener) release_object( listener );
    if (lookup) close_handle( current->process, lookup );
}

DECL_HANDLER(alpc_get_connect_result)
{
    struct alpc_port *client;
    struct alpc_message *message;
    data_size_t capacity;
    if (!get_receive_capacity( req->receive_attributes, &capacity )) return;
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
    reply->info = message->info;
    if (message->info.size > capacity)
    {
        set_error( STATUS_BUFFER_TOO_SMALL );
        goto done;
    }
    if (!set_message_reply( message, req->receive_attributes )) goto done;

    free_message( message );
    client->connect_reply = NULL;
    finish_connect_operation( client );
done:
    release_object( client );
}

DECL_HANDLER(alpc_accept_connect_port)
{
    struct alpc_port *listener, *client = NULL, *candidate, *server = NULL;
    struct alpc_port_init_data init = { .type = COMMUNICATION_PORT, .server = 1, .flags = req->port_flags,
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
            if (message->info.id == req->message_id && message->info.pid == req->sender_pid &&
                message->info.tid == req->sender_tid && (message->info.type & 0xff) == ALPC_MESSAGE_TYPE_CANCELED)
            {
                list_remove( &message->entry );
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
        if (client->want_reply) signal_sync( client->connect_sync );
        else
        {
            notify_port( client );
            dispatch_receives( client );
        }
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
                                (client->wow64 ? 0x1000 : 0), client->connection_id, current ))) goto done;
    if (!(handle = alloc_handle( current->process, server, ALPC_PORT_ALL_ACCESS, req->attributes ))) goto done;
    server->connection_port = (struct alpc_port *)grab_object( listener );
    list_add_tail( &listener->accepted_connections, &server->accepted_entry );
    server->impersonation_level = client->impersonation_level;
    server->tracking_mode = client->tracking_mode;
    server->effective_only = client->effective_only;
    if (!client->tracking_mode) server->client_token = (struct token *)grab_object( client->client_token );
    server->wow64 = client->wow64;
    server->context = req->context ? req->context : handle;
    server->peer = (struct alpc_port *)grab_object( client );
    client->peer = (struct alpc_port *)grab_object( server );
    server->status = client->status = CONNECTED;
    client->connect_status = STATUS_SUCCESS;
    set_message_destination( message, client, client->initial_message_context );
    if (client->want_reply)
    {
        client->connect_reply = message;
        signal_sync( client->connect_sync );
    }
    else
    {
        list_add_tail( &client->messages, &message->entry );
        notify_port( client );
        dispatch_receives( client );
    }
    message = NULL;
    unlink_pending( client );
    reply->handle = handle;
done:
    free_message( message );
    if (server) release_object( server );
    release_object( listener );
}

/* Querying requires the receiving queue, unlike endpoint impersonation. The
 * request owns the token; caller-supplied sender IDs and type do not select it. */
DECL_HANDLER(alpc_query_message_security)
{
    struct alpc_port *port;
    struct alpc_request *request = NULL, *candidate;
    struct token_identity identity;
    const struct sid *sid;

    if (!(port = (struct alpc_port *)get_handle_obj( current->process, req->handle,
                                                    ALPC_PORT_QUERY_STATE, &alpc_port_ops ))) return;
    LIST_FOR_EACH_ENTRY( candidate, &message_requests, struct alpc_request, entry )
        if (candidate->id == req->message_id && candidate->callback_id == req->callback_id)
        {
            request = candidate;
            break;
        }
    if (!request) { set_error( STATUS_INVALID_MESSAGE ); goto done; }
    if (request->canceled) { set_error( STATUS_REQUEST_CANCELED ); goto done; }
    if (req->info_class >= MaxAlpcMessageInfoClass) { set_error( STATUS_INVALID_PARAMETER ); goto done; }
    if (req->info_class != AlpcMessageSidInformation &&
        req->info_class != AlpcMessageTokenModifiedIdInformation)
    { set_error( STATUS_NOT_IMPLEMENTED ); goto done; }
    if (request->queue != port) { set_error( STATUS_ACCESS_DENIED ); goto done; }
    /* The fixed-size class validates its buffer before token availability. */
    if (req->info_class == AlpcMessageTokenModifiedIdInformation && req->length < sizeof(identity.modified_id))
    {
        reply->required = sizeof(identity.modified_id);
        set_error( STATUS_BUFFER_TOO_SMALL );
        goto done;
    }
    if (!request->token) { set_error( STATUS_ACCESS_DENIED ); goto done; }
    /* Queued, undelivered metadata is outside the established query contract. */
    if (request->message) { set_error( STATUS_NOT_IMPLEMENTED ); goto done; }
    sid = token_get_user( request->token );
    reply->required = req->info_class == AlpcMessageSidInformation ? sid_len( sid ) : sizeof(identity.modified_id);
    if (req->length < reply->required) { set_error( STATUS_BUFFER_TOO_SMALL ); goto done; }
    if (req->info_class == AlpcMessageSidInformation) set_reply_data( sid, reply->required );
    else
    {
        token_get_identity( request->token, &identity );
        set_reply_data( &identity.modified_id, reply->required );
    }
done:
    release_object( port );
}

/* Message identity selects retained objects, never an arbitrary client ID.
 * A synchronous wait pins the actual sending thread. An ordinary request
 * retains its process but cannot authorize a thread open. */
DECL_HANDLER(alpc_open_sender)
{
    struct alpc_port *port, *client;
    struct alpc_request *request;
    struct process *process = NULL;
    struct thread *thread = NULL;
    int found = 0;

    reply->handle = 0;
    if (!(port = (struct alpc_port *)get_handle_obj( current->process, req->handle,
                                                    ALPC_PORT_QUERY_STATE, &alpc_port_ops ))) return;
    /* Native port errors precede the client buffer probes. No handle is
     * allocated when those probes failed. */
    if (req->capture_status) { set_error( req->capture_status ); goto done; }
    LIST_FOR_EACH_ENTRY( request, &message_requests, struct alpc_request, entry )
        if (request->id == req->message_id && request->callback_id == req->callback_id)
        {
            found = 1;
            if (port != request->queue && port != request->target && port != request->source)
            { set_error( STATUS_ACCESS_DENIED ); goto done; }
            if (request->message || request->released || request->canceled)
            { set_error( STATUS_NOT_IMPLEMENTED ); goto done; }
            process = request->sender_process;
            if (request->wait) thread = request->wait->thread;
            break;
        }
    if (!found)
        LIST_FOR_EACH_ENTRY( client, &connecting_ports, struct alpc_port, connecting_entry )
            if (client->connection_id == req->message_id && client->connection_id == req->callback_id &&
                client->request_delivered)
            {
                found = 1;
                if (client->pending_listener != port)
                { set_error( STATUS_ACCESS_DENIED ); goto done; }
                thread = client->thread;
                process = thread->process;
                break;
            }
    if (!found) { set_error( STATUS_INVALID_MESSAGE ); goto done; }
    if (thread && (thread->process->id != req->sender_pid || thread->id != req->sender_tid))
    { set_error( req->open_thread ? STATUS_ACCESS_DENIED : STATUS_INVALID_CID ); goto done; }
    if (req->open_thread && !thread)
    { set_error( STATUS_ACCESS_DENIED ); goto done; }
    if (!thread && process->id != req->sender_pid)
    { set_error( STATUS_ACCESS_DENIED ); goto done; }
    if (req->named) { set_error( STATUS_INVALID_PARAMETER_MIX ); goto done; }
    /* Delivered authority selects the object before the ordinary open owner's
     * effective-token privilege and protected-access policy is applied. */
    reply->handle = req->open_thread ? alloc_thread_handle( thread, req->access, req->attributes ) :
                                      alloc_process_handle( process, req->access, req->attributes );
done:
    release_object( port );
}

DECL_HANDLER(alpc_disconnect_port)
{
    struct alpc_port *port;
    if (!(port = (struct alpc_port *)get_handle_obj( current->process, req->handle,
                                                  ALPC_PORT_ALL_ACCESS, &alpc_port_ops ))) return;
    if (port->thread->process != current->process) set_error( STATUS_ACCESS_DENIED );
    else if (port->status == DISCONNECTED) set_error( STATUS_PORT_DISCONNECTED );
    /* Skip-pending-flush is currently supported only for PDC endpoints:
     * they accept no operation that can leave a pending request/reply queue.
     * Do not discard the flag on ordinary ports. */
    else if (req->flags && (req->flags != 1 || !port->peer ||
                            port->peer->kernel_port != ALPC_KERNEL_PDC_PORT))
        set_error( STATUS_NOT_SUPPORTED );
    else
    {
        disconnect_message_requests( port );
        port->status = DISCONNECTED;
        detach_peer( port );
        dispatch_all_receives();
    }
    release_object( port );
}

DECL_HANDLER(register_dwm_session_port)
{
    struct alpc_port *port, *registered;
    const WCHAR *name;
    data_size_t name_len;
    unsigned int session_id = current->process->session_id;

    /* Native rejects session-zero registration before it reveals handle
     * validity.  Admit only a server-authenticated child of the session owner,
     * a process-trust bearer, or a caller holding enabled TCB privilege. */
    if (!session_id ||
        (!current->process->native_session_delegate &&
         !token_has_process_trust( current->process->token ) &&
         !thread_single_check_privilege( current, SeTcbPrivilege )))
    {
        set_error( STATUS_PRIVILEGE_NOT_HELD );
        return;
    }
    if (!(port = (struct alpc_port *)get_handle_obj( current->process, req->handle,
                                                     ALPC_PORT_ALL_ACCESS, &alpc_port_ops ))) return;
    name = get_object_name( &port->obj, &name_len );
    if (port->thread->process != current->process)
        set_error( STATUS_ACCESS_DENIED );
    else if (port->type != CONNECTION_PORT || port->status != UNINITIALIZED ||
             port->flags != 0x60000 || port->max_msg_len != 0x200 ||
             !name || name_len != sizeof(dwm_api_port_name) ||
             memcmp( name, dwm_api_port_name, sizeof(dwm_api_port_name) ))
        set_error( STATUS_INVALID_PARAMETER );
    else if ((registered = find_dwm_session_port( session_id )) && registered != port)
        set_error( STATUS_ALREADY_REGISTERED );
    else
    {
        if (!registered)
        {
            port->kernel_port = ALPC_KERNEL_DWM_SESSION_PORT;
            port->kernel_session_id = session_id;
            port->kernel_session_phase = DWM_SESSION_PORT_REGISTERED;
            if (!create_dwm_composed_event( port ))
            {
                port->kernel_port = ALPC_KERNEL_PORT_NONE;
                port->kernel_session_id = 0;
                release_object( port );
                return;
            }
            list_add_tail( &dwm_session_ports, &port->kernel_session_entry );
        }
        current->process->native_dwm_owner = 1;
        if (getenv( "LINUXNT_DEBUG_PROCESS_EXITS" ))
            fprintf( stderr, "linuxnt: server dwm-session-owner winpid=%04x session=%u\n",
                     current->process->id, session_id );
    }
    release_object( port );
}

DECL_HANDLER(query_dwm_composition_id)
{
    struct alpc_port *port = find_dwm_session_port( current->process->session_id );

    reply->id = port ? port->composition_id : 0;
}

DECL_HANDLER(start_dwm_kernel)
{
    struct alpc_port *port = find_dwm_session_port( current->process->session_id );
    struct desktop *desktop;
    struct winstation *winstation;
    unsigned int startup_begin[2] = {0x40000025, 0};
    int initializing;

    if (getenv( "LINUXNT_DEBUG_PROCESS_EXITS" ))
        fprintf( stderr, "linuxnt: server dwm-kernel-start winpid=%04x session=%u phase=%u\n",
                 current->process->id, current->process->session_id,
                 port ? port->kernel_session_phase : ~0u );

    if (!port || port->thread->process != current->process)
    {
        set_error( STATUS_ACCESS_DENIED );
        return;
    }
    if (port->kernel_session_phase == DWM_SESSION_PORT_REGISTERED)
    {
        set_error( STATUS_INVALID_DEVICE_STATE );
        return;
    }
    initializing = port->kernel_session_phase == DWM_SESSION_PORT_INITIALIZING;
    if (!(winstation = get_process_winstation( current->process, 0 ))) return;
    if (port->composited_winstation && port->composited_winstation != winstation)
    {
        release_object( winstation );
        set_error( STATUS_ACCESS_DENIED );
        return;
    }
    if (!port->composited_winstation) port->composited_winstation = winstation;
    else release_object( winstation );
    if (initializing)
        port->kernel_session_phase = DWM_SESSION_PORT_STARTED;
    if (!port->composited_winstation->composited)
    {
        LIST_FOR_EACH_ENTRY( desktop, &port->composited_winstation->desktops, struct desktop, entry )
            queue_dwm_desktop_message( port, 0x4000000e, desktop );
        replay_dwm_window_contexts( port->composited_winstation );
        LIST_FOR_EACH_ENTRY( desktop, &port->composited_winstation->desktops, struct desktop, entry )
        {
            user_handle_t shell_window = get_desktop_shell_window( desktop );
            if (shell_window) notify_dwm_shell_window_changed( desktop, shell_window );
        }
        set_winstation_composited( port->composited_winstation, 1 );
    }
    if (initializing)
        send_message( port, 0x10000, 0, 0, 0, 0, 0, 0, 0,
                      startup_begin, sizeof(startup_begin), NULL );
}

DECL_HANDLER(stop_dwm_kernel)
{
    struct alpc_port *port = find_dwm_session_port( current->process->session_id );
    struct desktop *desktop;

    if (!port || port->thread->process != current->process)
    {
        set_error( STATUS_ACCESS_DENIED );
        return;
    }
    if (port->composited_winstation)
    {
        LIST_FOR_EACH_ENTRY( desktop, &port->composited_winstation->desktops, struct desktop, entry )
            queue_dwm_desktop_message( port, 0x40000010, desktop );
        set_winstation_composited( port->composited_winstation, 0 );
    }
}

DECL_HANDLER(open_coremsg_kernel_connection)
{
    const unsigned char *routing = get_req_data();
    struct coremsg_kernel_port *port;
    struct coremsg_client_port *client;
    struct coremsg_connection_target *target;
    process_id_t pid;
    thread_id_t tid;

    if (req->selector > 22 || get_req_data_size() != 40)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    if (!(port = find_coremsg_kernel_port( current->process->session_id )))
    {
        set_error( STATUS_NOT_FOUND );
        return;
    }
    if (is_native_machine() && !current->process->native_dwm_owner)
    {
        set_error( STATUS_ACCESS_DENIED );
        return;
    }
    target = &port->targets[req->selector];
    if (target->client)
    {
        set_error( STATUS_ALREADY_REGISTERED );
        return;
    }
    pid = get_u32( routing );
    tid = get_u32( routing + 4 );
    if (!(client = find_coremsg_client_port( port, pid, tid )))
    {
        set_error( STATUS_UNSUCCESSFUL );
        return;
    }
    target->owner = current->process;
    target->client = grab_coremsg_client_port( client );
    memcpy( target->routing, routing, sizeof(target->routing) );
    if (getenv( "LINUXNT_DEBUG_PROCESS_EXITS" ))
        fprintf( stderr, "linuxnt: server coremsg-open winpid=%04x session=%u selector=%u client=%04x:%04x\n",
                 current->process->id, current->process->session_id, req->selector, pid, tid );
}

/* Handle access precedes message lookup. The caller supplies identity only;
 * sender IDs and message type are not authorization credentials. */
DECL_HANDLER(alpc_impersonate_client)
{
    struct alpc_port *port, *client;
    struct alpc_request *request;
    struct token *source = NULL, *token = NULL;
    int level = SecurityAnonymous, found = 0, explicit_context = 0;

    if (req->flags & ~0xf) { set_error( STATUS_INVALID_PARAMETER ); return; }
    if (!(port = (struct alpc_port *)get_handle_obj( current->process, req->handle,
                                                    ALPC_PORT_QUERY_STATE, &alpc_port_ops ))) return;
    if (!req->message_present)
    {
        if (port->connection_port)
        {
            if (port->tracking_mode) { set_error( STATUS_ACCESS_DENIED ); goto done; }
            source = port->client_token;
            level = port->impersonation_level;
        }
    }
    else
    {
        LIST_FOR_EACH_ENTRY( request, &message_requests, struct alpc_request, entry )
            if (request->id == req->message_id && request->callback_id == req->callback_id)
            {
                found = 1;
                if (request->no_impersonate) { set_error( STATUS_ACCESS_DENIED ); goto done; }
                if (!request->target || (request->target != port && request->target->connection_port != port))
                { set_error( STATUS_ACCESS_DENIED ); goto done; }
                /* A listener validates message ownership but has no connected
                 * security context to install. Only its accepted endpoint does. */
                if (request->target == port)
                {
                    if (!(source = request->token)) { set_error( STATUS_ACCESS_DENIED ); goto done; }
                    level = request->impersonation_level;
                    explicit_context = !!request->security_context;
                }
                break;
            }
        if (!found)
        {
            LIST_FOR_EACH_ENTRY( client, &connecting_ports, struct alpc_port, connecting_entry )
                if (client->connection_id == req->message_id && client->connection_id == req->callback_id &&
                    client->request_delivered)
                {
                    if (client->pending_listener != port) { set_error( STATUS_ACCESS_DENIED ); goto done; }
                    if (client->security_context)
                    {
                        source = client->client_token;
                        level = client->impersonation_level;
                    }
                    found = 1;
                    break;
                }
        }
        if (!found) { set_error( STATUS_INVALID_MESSAGE ); goto done; }
    }
    if (level < (req->flags >> 2)) { set_error( STATUS_ACCESS_DENIED ); goto done; }
    if (req->flags & 2) level = SecurityAnonymous;
    else if (source && !explicit_context && port->tracking_mode && level > SecurityAnonymous)
    {
        /* Dynamic synchronous requests retain the actual sending token. The
         * negotiated level bounds the requirement check, not that token's level. */
        int source_level = token_get_impersonation_level( source );
        if (source_level >= SecurityAnonymous) level = source_level;
    }
    if (source)
    {
        /* Cross-user credential exceptions are not in the observed contract.
         * Do not grant high-level impersonation without a known authority. */
        if (level > SecurityIdentification &&
            !equal_sid( token_get_user( source ), token_get_user( thread_get_impersonation_token( current ) ) ) &&
            !thread_single_check_privilege( current, SeImpersonatePrivilege ))
        { set_error( STATUS_NOT_IMPLEMENTED ); goto done; }
        if (!(token = token_duplicate_impersonation( source, level, FALSE ))) goto done;
    }
    if (current->token) release_object( current->token );
    current->token = token;
    current->token_copy_on_open = !!token;
done:
    release_object( port );
}

DECL_HANDLER(set_default_hard_error_port)
{
    struct alpc_port *port;

    if (!thread_single_check_privilege( current, SeTcbPrivilege ))
    {
        set_error( STATUS_PRIVILEGE_NOT_HELD );
        return;
    }
    if (default_hard_error_port)
    {
        set_error( STATUS_UNSUCCESSFUL );
        return;
    }
    if (!(port = (struct alpc_port *)get_handle_obj( current->process, req->handle, 0,
                                                     &alpc_port_ops ))) return;
    default_hard_error_port = (struct alpc_port *)grab_object( port );
    default_hard_error_process = (struct process *)grab_object( current->process );
    release_object( port );
}

DECL_HANDLER(set_process_exception_port)
{
    struct alpc_port *port;
    struct process *process;

    if (!(process = get_process_from_handle( req->process, PROCESS_SET_INFORMATION ))) return;
    if (process->exception_port)
    {
        set_error( STATUS_PORT_ALREADY_SET );
        release_object( process );
        return;
    }
    if ((port = (struct alpc_port *)get_handle_obj( current->process, req->port,
                                                    ALPC_PORT_ALL_ACCESS, &alpc_port_ops )))
        process->exception_port = &port->obj;
    release_object( process );
}
