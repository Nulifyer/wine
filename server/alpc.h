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
struct rectangle;
struct region;
struct winstation;

extern int set_coremsg_input_port_ready( struct process *process, int enabled );
extern void cleanup_process_coremsg_connections( struct process *process );
extern void notify_dwm_desktop_created( struct desktop *desktop );
extern void notify_dwm_desktop_destroyed( struct desktop *desktop );
extern unsigned int notify_dwm_window_created( struct desktop *desktop, unsigned int generation,
                                                unsigned int window, unsigned int parent,
                                                unsigned int style, unsigned int ex_style,
                                                const struct rectangle *rect, unsigned int process_id,
                                                unsigned __int64 process_sequence );
extern int notify_dwm_window_sprite_created( struct desktop *desktop, unsigned int generation,
                                              unsigned int window, unsigned int style,
                                              unsigned int ex_style, int active,
                                              const struct rectangle *window_rect,
                                              const struct rectangle *client_rect,
                                              unsigned int logical_surface,
                                              unsigned int surface_width,
                                              unsigned int surface_height );
extern void notify_dwm_window_sprite_updated( struct desktop *desktop, unsigned int generation,
                                               unsigned int window, unsigned int style,
                                               unsigned int ex_style, int active,
                                               const struct rectangle *window_rect,
                                               const struct rectangle *client_rect,
                                               unsigned int logical_surface,
                                               unsigned int surface_width,
                                               unsigned int surface_height );
extern void notify_dwm_window_sprite_destroyed( struct desktop *desktop,
                                                 unsigned int generation,
                                                 unsigned int window );
extern int notify_dwm_window_linked( struct desktop *desktop, unsigned int generation,
                                     unsigned int window, unsigned int parent,
                                     unsigned int previous, unsigned int band );
extern void notify_dwm_window_style_changed( struct desktop *desktop, unsigned int generation,
                                             unsigned int window, int offset,
                                             unsigned int value );
extern void notify_dwm_window_visibility_changed( struct desktop *desktop, unsigned int generation,
                                                  unsigned int window, int visible );
extern void notify_dwm_window_unlinked( struct desktop *desktop, unsigned int generation,
                                        unsigned int window, unsigned int parent );
extern void notify_dwm_window_destroyed( struct desktop *desktop, unsigned int generation,
                                         unsigned int window );
extern int notify_dwm_window_visible_region( struct desktop *desktop, unsigned int generation,
                                             unsigned int window, unsigned int type,
                                             const struct region *region );
extern int notify_dwm_window_target_created( unsigned int session_id, unsigned int window,
                                             unsigned int type, struct object *target );
extern void notify_dwm_window_target_destroyed( unsigned int session_id, unsigned int window,
                                                unsigned int type );

#endif /* __WINE_SERVER_ALPC_H */
