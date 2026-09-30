/*
 * Power Dependency Coordinator registration and notification lifetime
 *
 * Copyright 2026 LinuxNT project
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "windef.h"
#include "winternl.h"
#include "ntstatus.h"
#include "process.h"
#include "thread.h"
#include "request.h"
#include "security.h"
#include "pdc.h"

/* Revision 6 x64 payload, without its 40-byte ALPC header. Foreign addresses
 * are diagnostic cookies. They never identify server objects or callbacks. */
struct pdc_registration
{
    unsigned int message_type, revision;
    unsigned __int64 reserved;
    unsigned int client_id, client_type;
    unsigned __int64 triage_context;
    WCHAR module[64];
    unsigned char client_data[600];
};
C_ASSERT( sizeof(struct pdc_registration) == 760 );
C_ASSERT( offsetof(struct pdc_registration, client_id) == 16 );
C_ASSERT( offsetof(struct pdc_registration, client_data) == 160 );

struct pdc_client
{
    struct list entry;
    process_id_t pid;
    unsigned int id, type, notification_category;
    unsigned __int64 triage_context;
};
static struct list clients = LIST_INIT(clients);

/* Native channel DACL is independent of registration policy. The token owner
 * performs both ordinary and restricting-SID access checks. */
static int check_channel_access( struct token *token, const struct generic_map *mapping )
{
    static const struct sid all_app_packages =
        { SID_REVISION, 2, {0,0,0,0,0,15}, {2,1} };
    static const struct sid capability =
        { SID_REVISION, 10, {0,0,0,0,0,15},
          {3,1024,1502825166u,1963708345u,2616377461u,2562897074u,
           4192028372u,3968301570u,1997628692u,1435953622u} };
    struct
    {
        struct security_descriptor sd;
        struct acl acl;
        unsigned char aces[3 * sizeof(struct ace) + 12 + 16 + 48];
    } descriptor = {0};
    struct ace *ace = ace_first( &descriptor.acl );

    descriptor.sd.control = SE_DACL_PRESENT;
    descriptor.sd.dacl_len = sizeof(descriptor.acl) + sizeof(descriptor.aces);
    descriptor.acl.revision = ACL_REVISION;
    descriptor.acl.size = descriptor.sd.dacl_len;
    descriptor.acl.count = 3;
    ace = ace_next( set_ace( ace, &world_sid, ACCESS_ALLOWED_ACE_TYPE, 0, GENERIC_ALL ) );
    ace = ace_next( set_ace( ace, &all_app_packages, ACCESS_ALLOWED_ACE_TYPE, 0, GENERIC_ALL ) );
    set_ace( ace, &capability, ACCESS_ALLOWED_ACE_TYPE, 0, GENERIC_ALL );
    return token_check_security_descriptor_access( token, &descriptor.sd, ALPC_PORT_ALL_ACCESS, mapping );
}

struct pdc_client *pdc_connect_client( struct process *process, struct token *effective,
                                     const struct generic_map *mapping, const void *data,
                                     unsigned int size, int wow64 )
{
    static const unsigned char mandatory_authority[] = SECURITY_MANDATORY_LABEL_AUTHORITY;
    struct pdc_registration registration;
    struct pdc_client *client;
    const struct sid *integrity;

    if (!check_channel_access( effective, mapping )) goto denied;
    if (wow64) { set_error( STATUS_NOT_SUPPORTED ); return NULL; }
    if (size != sizeof(registration)) { set_error( STATUS_INVALID_PARAMETER ); return NULL; }
    memcpy( &registration, data, sizeof(registration) );
    if (registration.revision != 6)
    {
        set_error( registration.revision == 1 || registration.revision == 4 || registration.revision == 5 ?
                   STATUS_NOT_SUPPORTED : STATUS_INVALID_PARAMETER );
        return NULL;
    }
    if (registration.message_type || !registration.client_id || registration.client_id > 124 ||
        registration.client_type > 8) goto denied;
    /* This partition supplies PLM, HAM and BI, not the remaining native
     * clients whose policy and operations have different owners. */
    if (registration.client_id != 1 && registration.client_id != 100 && registration.client_id != 15)
    { set_error( STATUS_NOT_SUPPORTED ); return NULL; }
    if (registration.client_type != 0 && registration.client_type != 2 && registration.client_type != 7)
        goto denied;
    /* BI flags 0x24141 permit activators, not notification clients, and
     * require LocalSystem membership independently of the channel DACL. */
    if (registration.client_id == 15 &&
        (registration.client_type == 0 || !token_sid_present( process->token, &local_system_sid, 0 ))) goto denied;
    integrity = token_get_integrity_sid( process->token );
    if (integrity->sub_count != 1 || memcmp( integrity->id_auth, mandatory_authority, sizeof(mandatory_authority) ) ||
        integrity->sub_auth[0] < SECURITY_MANDATORY_MEDIUM_RID) goto denied;
    if (registration.client_type == 2) { set_error( STATUS_NOT_SUPPORTED ); return NULL; }
    if (!(client = mem_alloc( sizeof(*client) ))) return NULL;
    client->pid = process->id;
    client->id = registration.client_id;
    client->type = registration.client_type;
    client->notification_category = registration.client_id == 1 ? 1 : registration.client_id == 100 ? 2 : 6;
    client->triage_context = registration.triage_context;
    list_add_tail( &clients, &client->entry );
    /* No connected-standby state is supported or advertised. Registering a
     * notification client therefore has no catch-up event to queue. Future
     * transitions need owned state before publication through ALPC. */
    if (getenv( "LINUXNT_DEBUG_PROCESS_EXITS" ))
        fprintf( stderr, "linuxnt: pdc-register winpid=%04x id=%u type=%u notification=%u client=%p\n",
                 client->pid, client->id, client->type, client->notification_category, client );
    return client;
denied:
    set_error( STATUS_ACCESS_DENIED );
    return NULL;
}

void pdc_disconnect_client( struct pdc_client *client )
{
    if (getenv( "LINUXNT_DEBUG_PROCESS_EXITS" ))
        fprintf( stderr, "linuxnt: pdc-disconnect winpid=%04x id=%u type=%u client=%p\n",
                 client->pid, client->id, client->type, client );
    list_remove( &client->entry );
    free( client );
}

unsigned int pdc_receive_message( struct pdc_client *client, const void *data, unsigned int size )
{
    struct pdc_registration message;
    if (size != sizeof(message)) return STATUS_INVALID_PARAMETER;
    memcpy( &message, data, sizeof(message) );
    if (message.revision != 6) return STATUS_INVALID_PARAMETER;
    if (client->type != 7 && message.message_type >= 10 && message.message_type <= 13)
        return STATUS_INVALID_PARAMETER;
    /* Registration does not invent activation identifiers, renewal timers,
     * acknowledgements or power transitions. Both sync and async callers get
     * an explicit failure rather than a successful, unconsumed operation. */
    return STATUS_NOT_SUPPORTED;
}
