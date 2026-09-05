/*
 * Mobile Device Management registration compatibility.
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
#include "winerror.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(mdmreg);

HRESULT WINAPI IsDeviceRegisteredWithManagement(BOOL *registered, DWORD upn_size, WCHAR *upn)
{
    TRACE("registered %p, upn_size %lu, upn %p\n", registered, upn_size, upn);

    if (!registered) return E_INVALIDARG;
    *registered = FALSE;
    if (upn && upn_size) upn[0] = 0;
    return S_OK;
}
