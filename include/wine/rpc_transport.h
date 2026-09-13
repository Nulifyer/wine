/*
 * Wine local RPC transport definitions
 *
 * Copyright 2026
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __WINE_RPC_TRANSPORT_H
#define __WINE_RPC_TRANSPORT_H

#include "winioctl.h"

#define FSCTL_PIPE_WINE_RPC_SYSTEM_HANDLE \
    CTL_CODE(FILE_DEVICE_NAMED_PIPE, 2044, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define WINE_RPC_SYSTEM_HANDLE_SEND    1
#define WINE_RPC_SYSTEM_HANDLE_RECEIVE 2

struct wine_rpc_system_handle_request
{
    ULONGLONG value;
    ULONG access;
    ULONG attributes;
    ULONG options;
    ULONG operation;
};

#endif /* __WINE_RPC_TRANSPORT_H */
