/*
 * Windows and DOS version functions
 *
 * Copyright 1997 Marcus Meissner
 * Copyright 1998 Patrik Stridvall
 * Copyright 1998, 2003 Andreas Mohr
 * Copyright 1997, 2003 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "wingdi.h"
#include "winuser.h"
#include "winternl.h"
#include "winerror.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(ver);


/******************************************************************************
 *        VerifyVersionInfoA   (KERNEL32.@)
 */
BOOL WINAPI VerifyVersionInfoA( LPOSVERSIONINFOEXA lpVersionInfo, DWORD dwTypeMask,
                                DWORDLONG dwlConditionMask)
{
    OSVERSIONINFOEXW verW;

    verW.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
    verW.dwMajorVersion = lpVersionInfo->dwMajorVersion;
    verW.dwMinorVersion = lpVersionInfo->dwMinorVersion;
    verW.dwBuildNumber = lpVersionInfo->dwBuildNumber;
    verW.dwPlatformId = lpVersionInfo->dwPlatformId;
    verW.wServicePackMajor = lpVersionInfo->wServicePackMajor;
    verW.wServicePackMinor = lpVersionInfo->wServicePackMinor;
    verW.wSuiteMask = lpVersionInfo->wSuiteMask;
    verW.wProductType = lpVersionInfo->wProductType;
    verW.wReserved = lpVersionInfo->wReserved;

    return VerifyVersionInfoW(&verW, dwTypeMask, dwlConditionMask);
}


/******************************************************************************
 *        VerifyVersionInfoW   (KERNEL32.@)
 */
BOOL WINAPI VerifyVersionInfoW( LPOSVERSIONINFOEXW info, DWORD type, DWORDLONG mask )
{
    NTSTATUS status;

    TRACE("(%p 0x%lx 0x%s)\n", info, type, wine_dbgstr_longlong(mask));
    status = RtlSwitchedVVI( info, type, mask );
    if (status == STATUS_INVALID_PARAMETER) SetLastError( ERROR_BAD_ARGUMENTS );
    else if (status == STATUS_REVISION_MISMATCH) SetLastError( ERROR_OLD_WIN_VERSION );
    else return TRUE;
    return FALSE;
}

/***********************************************************************
 *           TermsrvAppInstallMode       (KERNEL32.@)
 *
 * Find out whether the terminal server is in INSTALL or EXECUTE mode.
 */
BOOL WINAPI TermsrvAppInstallMode(void)
{
    FIXME("stub\n");
    return FALSE;
}

/***********************************************************************
 *           TermsrvDeleteKey       (KERNEL32.@)
 *
 * Windows dispatches this to an optional terminal-services registry
 * extension and otherwise returns without doing anything.  Wine has no
 * corresponding extension to notify.
 */
void WINAPI TermsrvDeleteKey( HANDLE key )
{
    TRACE("(%p)\n", key);
}

/***********************************************************************
 *           TermsrvOpenUserClasses       (KERNEL32.@)
 *
 * Return the result of Windows' no-extension path.  The caller owns and
 * initializes the output slot when no terminal-services hook is installed.
 */
LONG WINAPI TermsrvOpenUserClasses( DWORD access, HANDLE *key )
{
    TRACE("(%#lx, %p)\n", access, key);
    return ERROR_SUCCESS;
}

/***********************************************************************
 *           SetTermsrvAppInstallMode       (KERNEL32.@)
 *
 * This function is said to switch between the INSTALL (TRUE) or
 * EXECUTE (FALSE) terminal server modes.
 *
 * This function always returns zero on WinXP Home so it's probably
 * safe to return that value in most cases. However, if a terminal
 * server is running it will probably return something else.
 */
DWORD WINAPI SetTermsrvAppInstallMode(BOOL bInstallMode)
{
    FIXME("(%d): stub\n", bInstallMode);
    return 0;
}
