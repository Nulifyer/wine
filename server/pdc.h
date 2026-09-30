/* Current PDC registration owner. ALPC owns endpoint and completion lifetime. */
#ifndef __WINE_SERVER_PDC_H
#define __WINE_SERVER_PDC_H

struct pdc_client;
struct process;
struct token;
struct generic_map;

extern struct pdc_client *pdc_connect_client( struct process *process, struct token *effective,
                                            const struct generic_map *mapping, const void *data,
                                            unsigned int size, int wow64 );
extern void pdc_disconnect_client( struct pdc_client *client );
extern unsigned int pdc_receive_message( struct pdc_client *client, const void *data, unsigned int size );

#endif
