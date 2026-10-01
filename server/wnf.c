/*
 * Server-side Windows Notification Facility state
 *
 * Copyright 2026 LinuxNT project
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

#include <stdlib.h>
#include <string.h>

#include "ntstatus.h"
#include "request.h"
#include "process.h"
#include "thread.h"
#include "security.h"

#define WNF_MAXIMUM_STATE_SIZE 4096
#define WNF_MAXIMUM_DYNAMIC_STATES 64
#define WNF_STATE_NAME_KEY 0x41c64e6da3bc0074ULL

struct wnf_state
{
    unsigned __int64 name;
    unsigned int change_stamp;
    unsigned int maximum_size;
    data_size_t size;
    void *data;
    int active;
    unsigned int session_id;
    struct wnf_state *next;
};

/* These well-known states are queried and published by the pinned Windows 11
 * UMPO and PSM services while they initialize their shared policy state. */
static struct wnf_state well_known_states[] =
{
    /* WNF_UMGR_SIHOST_READY starts empty and is published by the shell host. */
    { 0x13810338a3bc0835ULL, 0, WNF_MAXIMUM_STATE_SIZE, 0, NULL, 1 },
    { 0x41c6013da3bce875ULL, 0, WNF_MAXIMUM_STATE_SIZE, 0, NULL, 1 },
    { 0x41c6033fa3bc1875ULL, 0, WNF_MAXIMUM_STATE_SIZE, 0, NULL, 1 },
};

static struct wnf_state dynamic_states[WNF_MAXIMUM_DYNAMIC_STATES];
static unsigned __int64 next_unique = 1;
static struct wnf_state *session_states;

static unsigned int state_scope( unsigned __int64 name )
{
    return ((name ^ WNF_STATE_NAME_KEY) >> 6) & 0xf;
}

struct session_search { unsigned int id; int found; };

static int find_session_process( struct process *process, void *context )
{
    struct session_search *search = context;
    if (process->session_id != search->id) return 0;
    search->found = 1;
    return 1;
}

static int resolve_session( unsigned __int64 name, int explicit_scope,
                            unsigned int requested, unsigned int *session )
{
    struct session_search search = { requested, 0 };

    *session = state_scope(name) == 1 ? current->process->session_id : 0;
    if (!explicit_scope) return 1;
    if (state_scope(name) != 1)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return 0;
    }
    /* Session zero is the system session. Other sessions must have a live
     * process in this server; disconnected-session retention is not modeled. */
    if (requested) enum_processes( find_session_process, &search );
    if (requested && !search.found)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return 0;
    }
    if (!thread_single_check_privilege( current, SeTcbPrivilege ))
    {
        set_error( STATUS_PRIVILEGE_NOT_HELD );
        return 0;
    }
    *session = requested;
    return 1;
}

static struct wnf_state *find_wnf_state( unsigned __int64 name )
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(well_known_states); ++i)
        if (well_known_states[i].name == name) return &well_known_states[i];
    for (i = 0; i < ARRAY_SIZE(dynamic_states); ++i)
        if (dynamic_states[i].active && dynamic_states[i].name == name) return &dynamic_states[i];
    return NULL;
}

static struct wnf_state *find_scoped_state( unsigned __int64 name, unsigned int session )
{
    struct wnf_state *state, *prototype = find_wnf_state( name );
    unsigned int i;

    if (!prototype) goto not_found;
    if (state_scope(name) != 1) return prototype;
    for (i = 0; i < ARRAY_SIZE(dynamic_states); ++i)
        if (prototype == &dynamic_states[i])
        {
            if (prototype->session_id == session) return prototype;
            goto not_found;
        }
    for (state = session_states; state; state = state->next)
        if (state->name == name && state->session_id == session) return state;
    if (!(state = mem_alloc( sizeof(*state) ))) return NULL;
    *state = *prototype;
    state->session_id = session;
    state->next = session_states;
    session_states = state;
    return state;

not_found:
    set_error( STATUS_OBJECT_NAME_NOT_FOUND );
    return NULL;
}

static unsigned __int64 allocate_wnf_state_name( unsigned int lifetime, unsigned int scope )
{
    unsigned __int64 clear_name, candidate;

    for (;;)
    {
        clear_name = 1 | ((unsigned __int64)lifetime << 4) |
                     ((unsigned __int64)scope << 6) | (next_unique++ << 11);
        candidate = clear_name ^ WNF_STATE_NAME_KEY;
        if (candidate && !find_wnf_state( candidate )) return candidate;
    }
}

DECL_HANDLER(create_wnf_state_name)
{
    struct wnf_state *state = NULL;
    unsigned int i;

    if ((req->name_lifetime != 2 && req->name_lifetime != 3) || req->data_scope > 1 ||
        (req->data_scope == 1 && req->name_lifetime != 3) ||
        req->persist_data || req->type_id || !req->security_descriptor ||
        !req->maximum_size || req->maximum_size > WNF_MAXIMUM_STATE_SIZE)
    {
        set_error( STATUS_NOT_IMPLEMENTED );
        return;
    }

    for (i = 0; i < ARRAY_SIZE(dynamic_states); ++i)
        if (!dynamic_states[i].active)
        {
            state = &dynamic_states[i];
            break;
        }
    if (!state)
    {
        set_error( STATUS_INSUFFICIENT_RESOURCES );
        return;
    }

    state->name = allocate_wnf_state_name( req->name_lifetime, req->data_scope );
    state->change_stamp = 0;
    state->maximum_size = req->maximum_size;
    state->size = 0;
    state->data = NULL;
    state->active = 1;
    state->session_id = req->data_scope == 1 ? current->process->session_id : 0;
    reply->state_name = state->name;
}

DECL_HANDLER(delete_wnf_state_name)
{
    struct wnf_state *state;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(well_known_states); ++i)
        if (well_known_states[i].name == req->state_name)
        {
            set_error( STATUS_INVALID_PARAMETER );
            return;
        }

    for (i = 0; i < ARRAY_SIZE(dynamic_states); ++i)
        if (dynamic_states[i].active && dynamic_states[i].name == req->state_name)
        {
            state = &dynamic_states[i];
            if (state_scope(state->name) == 1 && state->session_id != current->process->session_id)
                break;
            free( state->data );
            memset( state, 0, sizeof(*state) );
            return;
        }

    set_error( STATUS_OBJECT_NAME_NOT_FOUND );
}

DECL_HANDLER(query_wnf_state_data)
{
    struct wnf_state *state;
    unsigned int session;

    if (!resolve_session( req->state_name, req->explicit_scope, req->session_id, &session )) return;
    if (!(state = find_scoped_state( req->state_name, session ))) return;

    reply->change_stamp = state->change_stamp;
    reply->total = state->size;
    if (state->size) set_reply_data( state->data, min( state->size, get_reply_max_size() ));
}

DECL_HANDLER(update_wnf_state_data)
{
    struct wnf_state *state;
    data_size_t size = get_req_data_size();
    void *data = NULL;
    unsigned int session;

    if (req->check_stamp != 0 && req->check_stamp != 1)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    if (!resolve_session( req->state_name, req->explicit_scope, req->session_id, &session )) return;
    if (!(state = find_scoped_state( req->state_name, session ))) return;
    if (size > state->maximum_size)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    if (req->check_stamp && req->matching_stamp != state->change_stamp)
    {
        set_error( STATUS_UNSUCCESSFUL );
        return;
    }
    if (size && !(data = memdup( get_req_data(), size ))) return;

    free( state->data );
    state->data = data;
    state->size = size;
    ++state->change_stamp;
    reply->change_stamp = state->change_stamp;
}
