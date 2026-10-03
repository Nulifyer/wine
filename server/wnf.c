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
#define WNF_GPOL_SYSTEM_CHANGES 0x0d891e2aa3bc0875ULL
#define WNF_SPI_LOGICALDPIOVERRIDE 0x418f1e3ea3bc0835ULL
#define WNF_IME_EXPLICIT_PRIVATE_MODE 0x41830324a3bc1035ULL
#define WNF_IME_AUTOMATIC_PRIVATE_MODE 0x41830324a3bc1835ULL
#define WNF_DX_MODE_CHANGE_NOTIFICATION 0x41c61629a3bc1035ULL
#define WNF_DX_MONITOR_CHANGE_NOTIFICATION 0x41c61629a3bc2835ULL
#define WNF_DX_MODERN_OUTPUTDUPLICATION_CONTEXTS 0x41c61629a3bc6835ULL
#define WNF_DX_CONSOLE_ADAPTER_START 0x41c61629a3bc8075ULL
#define WNF_DX_CONSOLE_ADAPTER_STOP 0x41c61629a3bc8875ULL
#define WNF_DX_REMOTE_ADAPTER_START 0x41c61629a3bcb835ULL
#define WNF_DX_REMOTE_ADAPTER_STOP 0x41c61629a3bcc035ULL
#define WNF_DX_RENDER_ADAPTER_PAIRING_CHANGED 0x41c61629a3bcf035ULL
#define WNF_DXGK_PATH_FAILED_OR_INVALIDATED 0x0a811629a3bc1075ULL
#define WNF_DXGK_PATH_FAILED_OR_INVALIDATED_V2 0x0a811629a3bc2835ULL
#define WNF_PNPA_DEVNODES_CHANGED 0x0096003da3bc0875ULL
#define WNF_PNPA_DEVNODES_CHANGED_SESSION 0x0096003da3bc1035ULL
#define WNF_PNPA_VOLUMES_CHANGED 0x0096003da3bc1875ULL
#define WNF_PNPA_VOLUMES_CHANGED_SESSION 0x0096003da3bc2035ULL
#define WNF_PNPA_HARDWAREPROFILES_CHANGED 0x0096003da3bc2875ULL
#define WNF_PNPA_HARDWAREPROFILES_CHANGED_SESSION 0x0096003da3bc3035ULL
#define WNF_PNPA_PORTS_CHANGED 0x0096003da3bc3875ULL
#define WNF_PNPA_PORTS_CHANGED_SESSION 0x0096003da3bc4035ULL
#define WNF_PO_SCENARIO_CHANGE 0x41c6013da3bce875ULL
#define WNF_RM_MEMORY_MONITOR_USAGE_METRICS 0x41c6033fa3bc0875ULL
#define WNF_RM_GAME_MODE_ACTIVE 0x41c6033fa3bc1075ULL
#define WNF_RM_QUIET_MODE 0x41c6033fa3bc1875ULL
#define WNF_RM_DEVELOPER_QUIET_MODE_ACTIVE 0x41c6033fa3bc2075ULL
#define WNF_HAM_SYSTEM_STATE_CHANGED 0x418b0f25a3bc0875ULL
#define WNF_RPCF_FWMAN_RUNNING 0x07851e3fa3bc0875ULL
#define WNF_SHEL_OOBE_USER_LOGON_COMPLETE 0x0d83063ea3bc2475ULL
#define WNF_DEP_OOBE_STATE 0x41960b29a3bc0c75ULL
#define WNF_SHEL_LOCKSCREEN_ACTIVE 0x0d83063ea3bc5835ULL
#define WNF_SHEL_WINDOW_ACTIVATED 0x0d83063ea3bfb035ULL
#define WNF_THME_THEME_CHANGED 0x048b0639a3bc0875ULL
#define WNF_TMCN_ISTABLETMODE 0x0f850339a3bc0835ULL
#define WNF_UMGR_SIHOST_READY 0x13810338a3bc0835ULL
#define WNF_UMGR_USER_LOGIN 0x13810338a3bc1075ULL
#define WNF_UMGR_USER_LOGOUT 0x13810338a3bc1875ULL
#define WNF_UMGR_SESSIONUSER_TOKEN_CHANGE 0x13810338a3bc2875ULL
#define WNF_UMGR_SESSION_ACTIVE_SHELL_USER_CHANGE 0x13810338a3bc3035ULL
#define WNF_UMGR_USER_PICTURE_CHANGED 0x13810338a3bc4075ULL
#define WNF_UMGR_USER_PICTURE_ID 0x13810338a3bc48f5ULL
#define WNF_UMGR_USER_PICTURE_CHANGED_CONTAINED 0x19890c35a3bc5075ULL

static const struct sid network_service_sid =
    { SID_REVISION, 1, SECURITY_NT_AUTHORITY, { SECURITY_NETWORK_SERVICE_RID } };
static const struct sid authenticated_users_sid =
    { SID_REVISION, 1, SECURITY_NT_AUTHORITY, { SECURITY_AUTHENTICATED_USER_RID } };

enum well_known_writer
{
    WNF_WRITER_NONE,
    WNF_WRITER_USER,
    WNF_WRITER_SYSTEM,
    WNF_WRITER_RPC_SERVICE,
    WNF_WRITER_DACL,
};

struct well_known_state
{
    unsigned __int64 name;
    unsigned int maximum, initial_size, initial_stamp;
    enum well_known_writer writer;
};

static const struct well_known_state well_known_states[] =
{
    { WNF_FT_LAST_PROCESS_PROMOTION_TRIGGER },
    { WNF_GPOL_SYSTEM_CHANGES },
    { WNF_SPI_LOGICALDPIOVERRIDE, sizeof(unsigned int) },
    { WNF_IME_EXPLICIT_PRIVATE_MODE, sizeof(unsigned int) },
    { WNF_IME_AUTOMATIC_PRIVATE_MODE, sizeof(unsigned int) },
    { WNF_DX_MODE_CHANGE_NOTIFICATION },
    { WNF_DX_MONITOR_CHANGE_NOTIFICATION, 16, 16, 1 },
    { WNF_DX_MODERN_OUTPUTDUPLICATION_CONTEXTS, 0x188 },
    { WNF_DX_CONSOLE_ADAPTER_START },
    { WNF_DX_CONSOLE_ADAPTER_STOP },
    { WNF_DX_REMOTE_ADAPTER_START },
    { WNF_DX_REMOTE_ADAPTER_STOP },
    { WNF_DX_RENDER_ADAPTER_PAIRING_CHANGED },
    { WNF_DXGK_PATH_FAILED_OR_INVALIDATED, 16 },
    { WNF_DXGK_PATH_FAILED_OR_INVALIDATED_V2, 16 },
    { WNF_PNPA_DEVNODES_CHANGED },
    { WNF_PNPA_DEVNODES_CHANGED_SESSION },
    { WNF_PNPA_VOLUMES_CHANGED },
    { WNF_PNPA_VOLUMES_CHANGED_SESSION },
    { WNF_PNPA_HARDWAREPROFILES_CHANGED },
    { WNF_PNPA_HARDWAREPROFILES_CHANGED_SESSION },
    { WNF_PNPA_PORTS_CHANGED },
    { WNF_PNPA_PORTS_CHANGED_SESSION },
    { WNF_PO_SCENARIO_CHANGE, 20, 0, 0, WNF_WRITER_SYSTEM },
    { WNF_RM_MEMORY_MONITOR_USAGE_METRICS, 24, 0, 0, WNF_WRITER_SYSTEM },
    { WNF_RM_GAME_MODE_ACTIVE, sizeof(unsigned int), 0, 0, WNF_WRITER_SYSTEM },
    { WNF_RM_QUIET_MODE, sizeof(unsigned int), 0, 0, WNF_WRITER_SYSTEM },
    { WNF_RM_DEVELOPER_QUIET_MODE_ACTIVE, sizeof(unsigned int), 0, 0, WNF_WRITER_SYSTEM },
    { WNF_HAM_SYSTEM_STATE_CHANGED, sizeof(unsigned int), 0, 0, WNF_WRITER_SYSTEM },
    { WNF_RPCF_FWMAN_RUNNING, sizeof(unsigned int), 0, 0, WNF_WRITER_RPC_SERVICE },
    { WNF_SHEL_OOBE_USER_LOGON_COMPLETE, sizeof(unsigned int), 0, 0, WNF_WRITER_DACL },
    { WNF_DEP_OOBE_STATE, sizeof(unsigned int), 0, 0, WNF_WRITER_DACL },
    { WNF_SHEL_LOCKSCREEN_ACTIVE, sizeof(unsigned int), 0, 0, WNF_WRITER_SYSTEM },
    { WNF_SHEL_WINDOW_ACTIVATED, sizeof(unsigned int), 0, 0, WNF_WRITER_DACL },
    { WNF_THME_THEME_CHANGED },
    { WNF_TMCN_ISTABLETMODE, sizeof(unsigned int) },
    { WNF_UMGR_SIHOST_READY, sizeof(unsigned int), 0, 0, WNF_WRITER_SYSTEM },
    { WNF_UMGR_USER_LOGIN, 16, 0, 0, WNF_WRITER_SYSTEM },
    { WNF_UMGR_USER_LOGOUT, 16, 0, 0, WNF_WRITER_SYSTEM },
    { WNF_UMGR_SESSIONUSER_TOKEN_CHANGE, sizeof(unsigned int), 0, 0, WNF_WRITER_SYSTEM },
    { WNF_UMGR_SESSION_ACTIVE_SHELL_USER_CHANGE, 12, 0, 0, WNF_WRITER_SYSTEM },
    { WNF_UMGR_USER_PICTURE_CHANGED, 0, 0, 0, WNF_WRITER_SYSTEM },
    { WNF_UMGR_USER_PICTURE_ID, 78, 0, 0, WNF_WRITER_USER },
    { WNF_UMGR_USER_PICTURE_CHANGED_CONTAINED, sizeof(unsigned int), 0, 0, WNF_WRITER_SYSTEM },
};

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
    int has_type, well_known, deleted;
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

/* Both OOBE states use the source-image notification DACL. Keep access in
 * the existing token owner so impersonation and restricting SIDs participate.
 * They start empty; the genuine setup/logon producer publishes completion. */
static struct security_descriptor *create_oobe_sd( unsigned __int64 name )
{
    static const struct sid shell_capability =
        { SID_REVISION, 10, {0,0,0,0,0,15},
          {3,1024,2152139330u,3124897132u,671935159u,3762809077u,
           3273429135u,2233686478u,1435376800u,2420532691u} };
    static const struct sid shell_package =
        { SID_REVISION, 8, {0,0,0,0,0,15},
          {2,2916343524u,3430662180u,516348105u,118121672u,
           2355345734u,3902897351u,118975284u} };
    struct
    {
        struct security_descriptor sd;
        unsigned char owner[12], group[12];
        struct acl acl;
        unsigned char aces[5 * sizeof(struct ace) + 12 + 12 + 16 + 48 + 40];
    } descriptor = {0};
    struct ace *ace = ace_first( &descriptor.acl );
    int shell = name == WNF_SHEL_OOBE_USER_LOGON_COMPLETE;

    ace = ace_next( set_ace( ace, &authenticated_users_sid, ACCESS_ALLOWED_ACE_TYPE, 0, shell ? 3 : 1 ) );
    ace = ace_next( set_ace( ace, &local_system_sid, ACCESS_ALLOWED_ACE_TYPE, 0, 3 ) );
    ace = ace_next( set_ace( ace, &builtin_admins_sid, ACCESS_ALLOWED_ACE_TYPE, 0, 3 ) );
    if (shell)
    {
        ace = ace_next( set_ace( ace, &shell_capability, ACCESS_ALLOWED_ACE_TYPE, 0, GENERIC_READ | GENERIC_WRITE ) );
        ace = ace_next( set_ace( ace, &shell_package, ACCESS_ALLOWED_ACE_TYPE, 0, GENERIC_READ ) );
    }
    /* The source registry supplies a DACL without object owner/group fields.
     * Wine requires a complete object descriptor. These machine states are
     * server-owned, independent of the first process that queries them. */
    descriptor.sd.owner_len = descriptor.sd.group_len = sid_len( &local_system_sid );
    memcpy( descriptor.owner, &local_system_sid, descriptor.sd.owner_len );
    memcpy( descriptor.group, &local_system_sid, descriptor.sd.group_len );
    descriptor.sd.control = SE_DACL_PRESENT;
    descriptor.sd.dacl_len = (char *)ace - (char *)&descriptor.acl;
    descriptor.acl.revision = ACL_REVISION;
    descriptor.acl.size = descriptor.sd.dacl_len;
    descriptor.acl.count = shell ? 5 : 3;
    return memdup( &descriptor, sizeof(descriptor.sd) + descriptor.sd.owner_len +
                    descriptor.sd.group_len + descriptor.sd.dacl_len );
}

/* The source notification registry grants read/write access for this
 * session-scoped state to Authenticated Users. */
static struct security_descriptor *create_shell_window_activated_sd(void)
{
    struct
    {
        struct security_descriptor sd;
        unsigned char owner[12], group[12];
        struct acl acl;
        unsigned char ace[sizeof(struct ace) + 12];
    } descriptor = {0};
    struct ace *end;

    end = ace_next( set_ace( ace_first( &descriptor.acl ), &authenticated_users_sid,
                             ACCESS_ALLOWED_ACE_TYPE, 0, 3 ) );
    descriptor.sd.owner_len = descriptor.sd.group_len = sid_len( &local_system_sid );
    memcpy( descriptor.owner, &local_system_sid, descriptor.sd.owner_len );
    memcpy( descriptor.group, &local_system_sid, descriptor.sd.group_len );
    descriptor.sd.control = SE_DACL_PRESENT;
    descriptor.sd.dacl_len = (char *)end - (char *)&descriptor.acl;
    descriptor.acl.revision = ACL_REVISION;
    descriptor.acl.size = descriptor.sd.dacl_len;
    descriptor.acl.count = 1;
    return memdup( &descriptor, sizeof(descriptor.sd) + descriptor.sd.owner_len +
                    descriptor.sd.group_len + descriptor.sd.dacl_len );
}

static struct wnf_state *create_well_known_state( const struct well_known_state *definition,
                                                  unsigned int session )
{
    struct wnf_state *state;

    if (!(state = alloc_object( &wnf_ops ))) return NULL;
    list_init( &state->process_entry );
    list_init( &state->subscriptions );
    state->data = NULL;
    state->creator = NULL;
    state->name = definition->name;
    state->type_low = state->type_high = 0;
    state->maximum = definition->maximum;
    state->size = definition->initial_size;
    state->stamp = definition->initial_stamp;
    state->session = session;
    state->has_type = 0;
    state->well_known = 1;
    state->deleted = 0;
    if (state->size)
    {
        if (!(state->data = mem_alloc( state->size ))) { release_object( state ); return NULL; }
        memset( state->data, 0, state->size );
    }
    if (state->name == WNF_SHEL_OOBE_USER_LOGON_COMPLETE || state->name == WNF_DEP_OOBE_STATE)
    {
        if (!(state->obj.sd = create_oobe_sd( state->name ))) { release_object( state ); return NULL; }
    }
    else if (state->name == WNF_SHEL_WINDOW_ACTIVATED)
    {
        if (!(state->obj.sd = create_shell_window_activated_sd())) { release_object( state ); return NULL; }
    }
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
    if (state->creator) list_remove( &state->process_entry );
    state->creator = NULL;
    state->deleted = 1;
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
    const unsigned __int64 decoded = name ^ WNF_NAME_KEY;
    struct session_search search = { session, 0 };
    unsigned int scope = (decoded >> 6) & 0xf;
    struct wnf_state *state;
    struct well_known_state fallback;
    unsigned int i;
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
    for (i = 0; i < sizeof(well_known_states) / sizeof(well_known_states[0]); i++)
        if (name == well_known_states[i].name)
            return create_well_known_state( &well_known_states[i], scope == 1 ? session : 0 );

    /* The well-known namespace is provisioned by Windows and changes between builds.  Materialize
     * structurally valid names as read-only empty states so consumers can subscribe even when Wine
     * has no payload or publisher contract for a newer state.  Named entries above remain the only
     * well-known states that may be published. */
    if ((decoded & 0xf) == 1 && ((decoded >> 4) & 3) == 0 &&
        (scope == 0 || scope == 1 || scope == 2 || scope == 4) && decoded >> 32)
    {
        memset( &fallback, 0, sizeof(fallback) );
        fallback.name = name;
        return create_well_known_state( &fallback, scope == 1 ? session : 0 );
    }
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

static int can_write_well_known_state( const struct wnf_state *state )
{
    const struct well_known_state *definition = NULL;
    const struct sid *user;
    struct token *token;
    unsigned int i;

    if (!state->well_known) return 1;
    for (i = 0; i < sizeof(well_known_states) / sizeof(well_known_states[0]); i++)
        if (well_known_states[i].name == state->name) { definition = &well_known_states[i]; break; }
    if (!definition) { set_error( STATUS_ACCESS_DENIED ); return 0; }
    /* check_state/check_object_access already enforced the published DACL. */
    if (definition->writer == WNF_WRITER_DACL) return 1;
    token = current->token ? current->token : current->process->token;
    user = token ? token_get_user( token ) : NULL;
    if (user) switch (definition->writer)
    {
    case WNF_WRITER_USER:
        return 1;
    case WNF_WRITER_SYSTEM:
        if (equal_sid( user, &local_system_sid )) return 1;
        break;
    case WNF_WRITER_RPC_SERVICE:
        if (equal_sid( user, &local_system_sid ) || equal_sid( user, &network_service_sid )) return 1;
        break;
    default:
        break;
    }
    set_error( STATUS_ACCESS_DENIED );
    return 0;
}

DECL_HANDLER(create_wnf_state_name)
{
    struct object_params params = {0};
    struct wnf_state *state;
    if (req->maximum_size > 4096 || req->data_scope > 4 || req->data_scope == 3)
    { set_error( STATUS_INVALID_PARAMETER ); return; }
    if ((req->name_lifetime != 2 && req->name_lifetime != 3) || req->persist_data)
    { set_error( STATUS_NOT_IMPLEMENTED ); return; }
    if (!get_req_object_attributes( &params )) return;
    if (params.root) release_object( params.root );
    if (!params.sd) { set_error( STATUS_ACCESS_VIOLATION ); return; }
    if (next_unique >= ((unsigned __int64)1 << 53))
    { set_error( STATUS_INSUFFICIENT_RESOURCES ); return; }
    if (!(state = alloc_object( &wnf_ops ))) return;
    list_init( &state->process_entry );
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
    state->creator = req->name_lifetime == 3 ? current->process : NULL;
    state->has_type = req->has_type;
    state->well_known = 0;
    state->deleted = 0;
    state->type_low = req->type_low;
    state->type_high = req->type_high;
    state->name = WNF_NAME_KEY ^
                  (1 | (unsigned __int64)req->name_lifetime << 4 |
                   (unsigned __int64)req->data_scope << 6 | next_unique++ << 11);
    list_add_tail( &states, &state->entry );
    if (state->creator) list_add_tail( &state->creator->wnf_states, &state->process_entry );
    reply->state_name = state->name;
}
DECL_HANDLER(delete_wnf_state_name)
{
    struct wnf_state *state = find_state( req->state_name, 0, 0 );
    unsigned int access = DELETE;
    if (!state) return;
    if (state->creator && state->creator != current->process) { set_error( STATUS_ACCESS_DENIED ); return; }
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
    if (!can_write_well_known_state( state )) return;
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

DECL_HANDLER(delete_wnf_state_data)
{
    struct wnf_state *state = find_state( req->state_name, req->explicit_scope, req->session_id );
    unsigned int access = 2;

    if (!state || !check_object_access( NULL, &state->obj, &access )) return;
    if (!can_write_well_known_state( state )) return;
    free( state->data );
    state->data = NULL;
    state->size = 0;
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
    if ((sub->pending & 1) && !state->deleted && state->size &&
        !set_reply_data( state->data, state->size )) return;
    reply->subscription_id = sub->id;
    reply->state_name = state->name;
    reply->events = sub->pending;
    reply->change_stamp = !state->deleted ? state->stamp : 0;
    reply->type_low = state->has_type ? state->type_low : 0;
    reply->type_high = state->has_type ? state->type_high : 0;
    sub->outstanding = sub->pending;
    sub->pending = 0;
    sub->stamp = state->stamp;
    list_remove( &sub->process_entry );
    list_add_tail( &current->process->wnf_subscriptions, &sub->process_entry );
    refresh_process_event( current->process );
}
