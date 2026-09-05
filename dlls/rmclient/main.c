/*
 * Resource manager client APIs
 *
 * Copyright 2026 LinuxNT project
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(rmclient);

/***********************************************************************
 *           RmEnableLimits   (RMCLIENT.@)
 */
DWORD WINAPI RmEnableLimits(void)
{
    TRACE("\n");
    return ERROR_SUCCESS;
}
