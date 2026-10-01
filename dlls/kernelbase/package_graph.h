/* Process-owned package state. No pointers to mutable graph state escape. */
#ifndef __WINE_PACKAGE_GRAPH_H
#define __WINE_PACKAGE_GRAPH_H
LONG package_graph_info(UINT32 flags, UINT32 path_type, UINT32 *size, BYTE *buffer, UINT32 *count);
HRESULT package_graph_info3(UINT32 flags, UINT32 type, UINT32 *size, void *buffer, UINT32 *count);
#endif
