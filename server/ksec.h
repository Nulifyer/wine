/* Shared Ksec connection ownership. */
#ifndef __WINE_SERVER_KSEC_H
#define __WINE_SERVER_KSEC_H

struct fd;
struct process;
struct thread;
extern void ksec_thread_exit( struct thread *thread );
extern void ksec_image_unmapped( struct process *process );
extern void alpc_cancel_ksec_request( const void *request );
extern void ksec_process_exit( struct process *process );
extern void ksec_ioctl_info( struct fd *fd, object_id_t *generation, obj_handle_t *event );

/* 1 assigns the scoped Type bit; 0 leaves ordinary delivery; -1 means
 * revocation may have retired the request and the send must stop. */
extern int ksec_alpc_message( struct object *source, struct object *target,
                             struct object *listener, struct process *receiver,
                             const void *request, unsigned int id, int reply, const void *data, data_size_t size );
extern void ksec_alpc_request_end( const void *request );
extern void ksec_alpc_close( struct object *port );

#endif
