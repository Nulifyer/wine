/* Out-of-box experience state
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
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(kernel);

/***********************************************************************
 *           OOBEComplete   (KERNEL32.@)
 *
 * Wine finishes prefix initialization before starting user processes,
 * so there is no user-visible Windows OOBE phase at this layer.
 */
BOOL WINAPI OOBEComplete(BOOL *complete)
{
    TRACE("complete %p.\n", complete);

    if (!complete)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *complete = TRUE;
    return TRUE;
}
