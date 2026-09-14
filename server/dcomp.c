/*
 * Server-side DirectComposition connection management
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
#include <stdio.h>

#include "ntstatus.h"
#include "windef.h"
#include "winternl.h"

#include "handle.h"
#include "object.h"
#include "request.h"

struct dcomp_connection
{
    struct object obj;
    struct event *work_event;
    int is_dwm;
};

static void dcomp_connection_dump( struct object *obj, int verbose );
static void dcomp_connection_destroy( struct object *obj );

static const struct object_ops dcomp_connection_ops =
{
    .size    = sizeof(struct dcomp_connection),
    .type    = &no_type,
    .dump    = dcomp_connection_dump,
    .destroy = dcomp_connection_destroy,
};

static void dcomp_connection_dump( struct object *obj, int verbose )
{
    struct dcomp_connection *connection = (struct dcomp_connection *)obj;

    assert( obj->ops == &dcomp_connection_ops );
    fprintf( stderr, "DirectComposition connection is_dwm=%u work_event=%p\n",
             connection->is_dwm, connection->work_event );
}

static void dcomp_connection_destroy( struct object *obj )
{
    struct dcomp_connection *connection = (struct dcomp_connection *)obj;

    assert( obj->ops == &dcomp_connection_ops );
    if (connection->work_event) release_object( connection->work_event );
}

DECL_HANDLER(create_dcomp_connection)
{
    struct dcomp_connection *connection;
    struct event *event;

    if (!(event = get_event_obj( current->process, req->event, SYNCHRONIZE ))) return;
    if (!(connection = alloc_object( &dcomp_connection_ops )))
    {
        release_object( event );
        return;
    }

    connection->work_event = event;
    connection->is_dwm = !!req->is_dwm;
    reply->handle = alloc_handle_no_access_check( current->process, connection, 0, 0 );
    release_object( connection );
}

DECL_HANDLER(destroy_dcomp_connection)
{
    struct dcomp_connection *connection;
    unsigned int status;

    if (!(connection = (struct dcomp_connection *)get_handle_obj( current->process, req->handle,
                                                                  0, &dcomp_connection_ops ))) return;
    status = close_handle( current->process, req->handle );
    release_object( connection );
    set_error( status );
}
