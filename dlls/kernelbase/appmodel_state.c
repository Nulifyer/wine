/*
 * AppModel application state
 *
 * Copyright 2026 LinuxNT contributors
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

WINE_DEFAULT_DEBUG_CHANNEL(appmodel);

extern LONG WINAPI GetCurrentPackageFamilyName(UINT32 *length, WCHAR *name);

/***********************************************************************
 *         OpenState   (kernelbase.@)
 */
void * WINAPI OpenState(void)
{
    UINT32 length = 0;
    LONG status;

    status = GetCurrentPackageFamilyName(&length, NULL);
    if (status != APPMODEL_ERROR_NO_PACKAGE)
    {
        FIXME("packaged state spaces are not implemented, package query returned %#lx.\n", status);
        status = ERROR_CALL_NOT_IMPLEMENTED;
    }

    SetLastError(status);
    return NULL;
}
