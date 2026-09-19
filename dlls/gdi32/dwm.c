/*
 * Private desktop-composition GDI entry points
 *
 * Copyright 2026
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "gdi_private.h"
#include "ntuser.h"

/***********************************************************************
 *           DwmQueryCompositionId (GDI32.@)
 *
 * Return the generation of the composed-event object owned by the active
 * DWM session port. Windows publishes this through win32k shared state;
 * Wine keeps the equivalent session state in the server.
 */
UINT WINAPI DwmQueryCompositionId(void)
{
    return NtUserCallNoParam( NtUserCallNoParam_GetDwmCompositionId );
}
