/*
 * Shell COM worker dispatch
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 */

#include <stdarg.h>
#include "windef.h"
#include "winbase.h"
#include "objbase.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(kernelbase);

typedef HRESULT (WINAPI *shell_create_fn)( const WCHAR *, const CLSID *, IUnknown *, REFIID, void ** );
static void *shell_create_worker;

HRESULT WINAPI SHCoCreateInstance( const WCHAR *string, const CLSID *clsid, IUnknown *outer,
                                  REFIID iid, void **out )
{
    DWORD error = GetLastError();
    shell_create_fn create = InterlockedCompareExchangePointer( &shell_create_worker, NULL, NULL );

    if (!create)
    {
        HMODULE module = LoadLibraryW( L"ext-ms-win-shell32-shellcom-l1-1-0.dll" );
        void *previous;

        if (!module) return HRESULT_FROM_WIN32( ERROR_PROC_NOT_FOUND );
        create = (shell_create_fn)GetProcAddress( module, "SHCoCreateInstanceWorker" );
        if (!create)
        {
            FreeLibrary( module );
            return HRESULT_FROM_WIN32( ERROR_PROC_NOT_FOUND );
        }
        previous = InterlockedCompareExchangePointer( &shell_create_worker, create, NULL );
        if (previous)
        {
            FreeLibrary( module );
            create = previous;
        }
        /* The winning module reference lives with the process. Objects returned
         * by the worker may keep vtables in it after this function returns.
         * Resolve outside an init-once callback so DLL initialization can reenter. */
    }
    TRACE( "%p %p %p %p %p\n", string, clsid, outer, iid, out );
    SetLastError( error );
    return create( string, clsid, outer, iid, out );
}
