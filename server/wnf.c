/*
 * Server-side Windows Notification Facility states
 *
 * Copyright 2026 LinuxNT contributors
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
 */

#include "config.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "ntstatus.h"
#include "request.h"
#include "process.h"
#include "thread.h"
#include "security.h"

#define WNF_NAME_KEY 0x41c64e6da3bc0074ULL
#define WNF_FT_LAST_PROCESS_PROMOTION_TRIGGER 0x41c61a2ba3bc2875ULL

static const WCHAR wnf_name[] = {'W','n','f','S','t','a','t','e'};
static struct type_descr wnf_type =
{
    { wnf_name, sizeof(wnf_name) }, 0x1f0007,
    { STANDARD_RIGHTS_READ | 1, STANDARD_RIGHTS_WRITE | 2,
      STANDARD_RIGHTS_EXECUTE | DELETE, 0x1f0007 }
};

struct wnf_state
{
    struct object obj;
    struct list entry, process_entry, subscriptions;
    struct process *creator; /* weak; process_killed removes its names before signaling */
    unsigned __int64 name, type_low, type_high;
    unsigned int maximum, size, stamp, session;
    int has_type, well_known;
    void *data;
};
struct wnf_subscription
{
    struct list process_entry, state_entry;
    struct process *process; /* weak; owns this subscription until teardown */
    struct wnf_state *state; /* strong, including after name deletion */
    unsigned __int64 id;
    unsigned int events, stamp, pending, outstanding;
};
static unsigned __int64 next_subscription = 1;
static struct list states = LIST_INIT(states);
static unsigned __int64 next_unique = 1;

static void wnf_dump( struct object *obj, int verbose )
{
    struct wnf_state *state = (struct wnf_state *)obj;
    fprintf( stderr, "WNF state %llx size=%u stamp=%u\n", (unsigned long long)state->name, state->size, state->stamp );
}
static void wnf_destroy( struct object *obj )
{
    struct wnf_state *state = (struct wnf_state *)obj;
    assert( list_empty( &state->subscriptions ));
    free( state->data );
}
static const struct object_ops wnf_ops =
{
    .size = sizeof(struct wnf_state), .type = &wnf_type,
    .dump = wnf_dump, .destroy = wnf_destroy,
};

static struct wnf_state *create_well_known_state( unsigned __int64 name )
{
    struct wnf_state *state;

    if (!(state = alloc_object( &wnf_ops ))) return NULL;
    list_init( &state->process_entry );
    list_init( &state->subscriptions );
    state->creator = NULL;
    state->name = name;
    state->type_low = state->type_high = 0;
    state->maximum = state->size = state->stamp = state->session = 0;
    state->has_type = 0;
    state->well_known = 1;
    state->data = NULL;
    list_add_tail( &states, &state->entry );
    return state;
}

static void refresh_process_event( struct process *process )
{
    struct wnf_subscription *sub;
    if (!process->wnf_event) return;
    LIST_FOR_EACH_ENTRY( sub, &process->wnf_subscriptions, struct wnf_subscription, process_entry )
        if (sub->pending && !sub->outstanding) { set_event( process->wnf_event ); return; }
    reset_event( process->wnf_event );
}
static void notify_state( struct wnf_state *state, unsigned int events )
{
    struct wnf_subscription *sub;
    LIST_FOR_EACH_ENTRY( sub, &state->subscriptions, struct wnf_subscription, state_entry )
    {
        unsigned int pending = events & sub->events;
        if (sub->stamp == state->stamp) pending &= ~1;
        sub->pending |= pending;
        refresh_process_event( sub->process );
    }
}
static void remove_subscription( struct wnf_subscription *sub )
{
    struct wnf_state *state = sub->state;
    struct process *process = sub->process;
    list_remove( &sub->state_entry );
    list_remove( &sub->process_entry );
    free( sub );
    refresh_process_event( process );
    release_object( state );
}
static void remove_state( struct wnf_state *state )
{
    struct wnf_subscription *sub;
    list_remove( &state->entry );
    list_remove( &state->process_entry );
    state->creator = NULL;
    LIST_FOR_EACH_ENTRY( sub, &state->subscriptions, struct wnf_subscription, state_entry )
    {
        sub->pending = sub->events & 16;
        refresh_process_event( sub->process );
    }
    release_object( state );
}
void cleanup_process_wnf_states( struct process *process )
{
    struct wnf_state *state, *next;
    struct wnf_subscription *sub, *sub_next;
    LIST_FOR_EACH_ENTRY_SAFE( sub, sub_next, &process->wnf_subscriptions, struct wnf_subscription, process_entry )
        remove_subscription( sub );
    LIST_FOR_EACH_ENTRY_SAFE( state, next, &process->wnf_states, struct wnf_state, process_entry )
        remove_state( state );
    if (process->wnf_event) release_object( process->wnf_event );
    process->wnf_event = NULL;
}

struct session_search { unsigned int id; int found; };
static int find_session_process( struct process *process, void *context )
{
    struct session_search *search = context;
    if (process->session_id != search->id) return 0;
    search->found = 1;
    return 1;
}
static struct wnf_state *find_state( unsigned __int64 name, int explicit_scope,
                                     unsigned int session )
{
    struct session_search search = { session, 0 };
    unsigned int scope = ((name ^ WNF_NAME_KEY) >> 6) & 0xf;
    struct wnf_state *state;
    if (explicit_scope)
    {
        if (scope != 1) { set_error( STATUS_INVALID_PARAMETER ); return NULL; }
        /* Reserved session zero and sessions represented by this server. */
        if (session) enum_processes( find_session_process, &search );
        if (session && !search.found) { set_error( STATUS_INVALID_PARAMETER ); return NULL; }
        if (!thread_single_check_privilege( current, SeTcbPrivilege ))
        { set_error( STATUS_PRIVILEGE_NOT_HELD ); return NULL; }
    }
    else session = current->process->session_id;
    LIST_FOR_EACH_ENTRY( state, &states, struct wnf_state, entry )
        if (state->name == name && (scope != 1 || state->session == session)) return state;
    if (name == WNF_FT_LAST_PROCESS_PROMOTION_TRIGGER)
        return create_well_known_state( name );
    set_error( STATUS_OBJECT_NAME_NOT_FOUND );
    return NULL;
}
static int check_state( struct wnf_state *state, unsigned int access, int has_type,
                        unsigned __int64 type_low, unsigned __int64 type_high )
{
    if (!check_object_access( NULL, &state->obj, &access )) return 0;
    if (state->has_type && (!has_type || state->type_low != type_low || state->type_high != type_high))
    { set_error( STATUS_INVALID_PARAMETER ); return 0; }
    return 1;
}

DECL_HANDLER(create_wnf_state_name)
{
    struct object_params params = {0};
    struct wnf_state *state;
    if (req->maximum_size > 4096 || req->data_scope > 4 || req->data_scope == 3)
    { set_error( STATUS_INVALID_PARAMETER ); return; }
    if (req->name_lifetime != 3 || req->persist_data)
    { set_error( STATUS_NOT_IMPLEMENTED ); return; }
    if (!get_req_object_attributes( &params )) return;
    if (params.root) release_object( params.root );
    if (!params.sd) { set_error( STATUS_ACCESS_VIOLATION ); return; }
    if (next_unique >= ((unsigned __int64)1 << 53))
    { set_error( STATUS_INSUFFICIENT_RESOURCES ); return; }
    if (!(state = alloc_object( &wnf_ops ))) return;
    list_init( &state->subscriptions );
    state->name = 0;
    state->data = NULL;
    state->size = state->stamp = 0;
    if (!set_sd_defaults_from_token( &state->obj, params.sd,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
            SACL_SECURITY_INFORMATION, current->token ? current->token : current->process->token ))
    { release_object( state ); return; }
    state->maximum = req->maximum_size;
    state->session = current->process->session_id;
    state->creator = current->process;
    state->has_type = req->has_type;
    state->well_known = 0;
    state->type_low = req->type_low;
    state->type_high = req->type_high;
    state->name = WNF_NAME_KEY ^ (1 | 3 << 4 | req->data_scope << 6 | next_unique++ << 11);
    list_add_tail( &states, &state->entry );
    list_add_tail( &state->creator->wnf_states, &state->process_entry );
    reply->state_name = state->name;
}
DECL_HANDLER(delete_wnf_state_name)
{
    struct wnf_state *state = find_state( req->state_name, 0, 0 );
    unsigned int access = DELETE;
    if (!state) return;
    if (state->creator != current->process) { set_error( STATUS_ACCESS_DENIED ); return; }
    if (check_object_access( NULL, &state->obj, &access )) remove_state( state );
}
DECL_HANDLER(query_wnf_state_data)
{
    struct wnf_state *state = find_state( req->state_name, req->explicit_scope, req->session_id );
    if (!state || !check_state( state, 1, req->has_type, req->type_low, req->type_high )) return;
    reply->change_stamp = state->stamp;
    reply->total = state->size;
    if (get_reply_max_size() >= state->size) set_reply_data( state->data, state->size );
}
DECL_HANDLER(update_wnf_state_data)
{
    struct wnf_state *state = find_state( req->state_name, req->explicit_scope, req->session_id );
    data_size_t size = get_req_data_size();
    void *data = NULL;
    if (!state || !check_state( state, 2, req->has_type, req->type_low, req->type_high )) return;
    if (state->well_known) { set_error( STATUS_ACCESS_DENIED ); return; }
    if (size > state->maximum) { set_error( STATUS_INVALID_PARAMETER ); return; }
    if (req->check_stamp && req->matching_stamp != state->stamp)
    { set_error( STATUS_UNSUCCESSFUL ); return; }
    if (size && !(data = memdup( get_req_data(), size ))) return;
    free( state->data );
    state->data = data;
    state->size = size;
    state->stamp++;
    notify_state( state, 1 );
}

static struct wnf_subscription *find_subscription( struct process *process, unsigned __int64 name )
{
    struct wnf_subscription *sub;
    LIST_FOR_EACH_ENTRY( sub, &process->wnf_subscriptions, struct wnf_subscription, process_entry )
        if (sub->state->name == name) return sub;
    return NULL;
}
DECL_HANDLER(subscribe_wnf_state)
{
    struct wnf_state *state;
    struct wnf_subscription *sub;
    unsigned int access = ((req->events & 0x11) ? 1 : 0) | ((req->events & 0x0e) ? 2 : 0);
    if (req->events & ~0x1f) { set_error( STATUS_INVALID_PARAMETER ); return; }
    if (!(state = find_state( req->state_name, 0, 0 ))) return;
    if (access && !check_object_access( NULL, &state->obj, &access )) return;
    sub = find_subscription( current->process, req->state_name );
    if (!sub)
    {
        if (!next_subscription) { set_error( STATUS_INSUFFICIENT_RESOURCES ); return; }
        if (!(sub = mem_alloc( sizeof(*sub) ))) return;
        sub->state = (struct wnf_state *)grab_object( state );
        sub->process = current->process;
        sub->id = next_subscription++;
        sub->pending = sub->outstanding = 0;
        list_add_tail( &state->subscriptions, &sub->state_entry );
        list_add_tail( &current->process->wnf_subscriptions, &sub->process_entry );
    }
    sub->events = req->events;
    sub->stamp = req->change_stamp;
    sub->pending &= req->events;
    if (state->stamp && state->stamp != sub->stamp) sub->pending |= req->events & 1;
    reply->subscription_id = sub->id;
    refresh_process_event( current->process );
}
DECL_HANDLER(unsubscribe_wnf_state)
{
    struct wnf_subscription *sub = find_subscription( current->process, req->state_name );
    if (!sub) { set_error( STATUS_OBJECT_NAME_NOT_FOUND ); return; }
    remove_subscription( sub );
}
DECL_HANDLER(set_wnf_process_event)
{
    struct event *event;
    if (current->process->wnf_event) { set_error( STATUS_ALREADY_REGISTERED ); return; }
    if (!(event = get_event_obj( current->process, req->handle, EVENT_MODIFY_STATE ))) return;
    current->process->wnf_event = event;
    refresh_process_event( current->process );
}
DECL_HANDLER(query_wnf_state_info)
{
    struct wnf_state *state;
    unsigned int access = req->info_class ? 2 : 0;
    if (req->info_class > 2) { set_error( STATUS_INVALID_INFO_CLASS ); return; }
    if (!(state = find_state( req->state_name, req->explicit_scope, req->session_id ))) return;
    if (access && !check_object_access( NULL, &state->obj, &access )) return;
    switch (req->info_class)
    {
    case 0: reply->value = 1; break;
    case 1: reply->value = !list_empty( &state->subscriptions ); break;
    case 2: reply->value = list_empty( &state->subscriptions ); break;
    }
}
DECL_HANDLER(complete_wnf_subscription)
{
    struct wnf_subscription *sub, *ready = NULL;
    struct wnf_state *state;
    if (req->retrieve && get_reply_max_size() < 4096)
    { set_error( STATUS_BUFFER_TOO_SMALL ); return; }
    if (req->acknowledge)
    {
        sub = find_subscription( current->process, req->state_name );
        if (sub && sub->id == req->subscription_id) sub->outstanding &= ~req->events;
        refresh_process_event( current->process );
    }
    if (!req->retrieve) { refresh_process_event( current->process ); return; }
    LIST_FOR_EACH_ENTRY( sub, &current->process->wnf_subscriptions, struct wnf_subscription, process_entry )
        if (sub->pending && !sub->outstanding) { ready = sub; break; }
    if (!ready)
    {
        refresh_process_event( current->process );
        set_error( STATUS_NO_MORE_ENTRIES );
        return;
    }
    sub = ready;
    state = sub->state;
    if ((sub->pending & 1) && (state->well_known || state->creator) && state->size &&
        !set_reply_data( state->data, state->size )) return;
    reply->subscription_id = sub->id;
    reply->state_name = state->name;
    reply->events = sub->pending;
    reply->change_stamp = (state->well_known || state->creator) ? state->stamp : 0;
    reply->type_low = state->has_type ? state->type_low : 0;
    reply->type_high = state->has_type ? state->type_high : 0;
    sub->outstanding = sub->pending;
    sub->pending = 0;
    sub->stamp = state->stamp;
    list_remove( &sub->process_entry );
    list_add_tail( &current->process->wnf_subscriptions, &sub->process_entry );
    refresh_process_event( current->process );
}
