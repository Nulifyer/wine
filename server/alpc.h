/*
 * Server-side ALPC compatibility interfaces
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __WINE_SERVER_ALPC_H
#define __WINE_SERVER_ALPC_H

struct process;
struct desktop;
struct object;

extern int set_coremsg_input_port_ready( struct process *process, int enabled );
extern void cleanup_process_coremsg_connections( struct process *process );
extern void notify_dwm_desktop_created( struct desktop *desktop );
extern void notify_dwm_desktop_destroyed( struct desktop *desktop );
extern int notify_dwm_window_target_created( unsigned int session_id, unsigned int window,
                                             unsigned int type, struct object *target );
extern void notify_dwm_window_target_destroyed( unsigned int session_id, unsigned int window,
                                                unsigned int type );

#endif /* __WINE_SERVER_ALPC_H */
