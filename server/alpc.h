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

extern int set_coremsg_input_port_ready( struct process *process, int enabled );
extern void cleanup_process_coremsg_connections( struct process *process );

#endif /* __WINE_SERVER_ALPC_H */
