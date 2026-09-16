/*
 * Window-services destruction callback
 *
 * Copyright 2026 Nulifyer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "user_private.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(win);

typedef void (CDECL *window_services_destroy_callback)(HWND);

static SRWLOCK callback_lock = SRWLOCK_INIT;
static window_services_destroy_callback destroy_callback;
static HMODULE callback_module;
static unsigned int registered_windows;

/***********************************************************************
 *           SetWindowServicesDestroyCallback  (USER32.@)
 */
BOOL WINAPI SetWindowServicesDestroyCallback( HWND hwnd, window_services_destroy_callback callback )
{
    window_services_destroy_callback current_callback;
    HMODULE release_module = NULL, module = NULL;
    HWND full_handle;
    LONG_PTR previous;
    DWORD error;
    BOOL ret = FALSE;

    TRACE( "hwnd %p, callback %p\n", hwnd, callback );

    if (!(full_handle = WIN_IsCurrentProcess( hwnd )))
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }
    hwnd = full_handle;

    AcquireSRWLockExclusive( &callback_lock );
    current_callback = destroy_callback;
    if (callback && current_callback && callback != current_callback)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        goto done;
    }

    SetLastError( ERROR_SUCCESS );
    previous = NtUserSetWindowLongPtr( hwnd, GWLP_WINDOW_SERVICES, !!callback, FALSE );
    error = GetLastError();
    if (!previous && error)
    {
        SetLastError( error );
        goto done;
    }

    if (callback && !previous)
    {
        if (!current_callback)
        {
            if (!GetModuleHandleExW( GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                                     (const WCHAR *)callback, &module ))
            {
                error = GetLastError();
                NtUserSetWindowLongPtr( hwnd, GWLP_WINDOW_SERVICES, FALSE, FALSE );
                SetLastError( error );
                goto done;
            }
            destroy_callback = callback;
            callback_module = module;
        }
        registered_windows++;
    }
    else if (!callback && previous && registered_windows)
    {
        if (--registered_windows == 0)
        {
            destroy_callback = NULL;
            release_module = callback_module;
            callback_module = NULL;
        }
    }

    SetLastError( ERROR_SUCCESS );
    ret = TRUE;

done:
    ReleaseSRWLockExclusive( &callback_lock );
    if (release_module) FreeLibrary( release_module );
    if (ret) SetLastError( ERROR_SUCCESS );
    return ret;
}

void call_window_services_destroy_callback( HWND hwnd )
{
    window_services_destroy_callback callback;
    HMODULE module = NULL;

    AcquireSRWLockShared( &callback_lock );
    callback = destroy_callback;
    if (callback)
        GetModuleHandleExW( GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                            (const WCHAR *)callback, &module );
    ReleaseSRWLockShared( &callback_lock );

    if (callback && module)
    {
        callback( hwnd );
        FreeLibrary( module );
    }
    SetWindowServicesDestroyCallback( hwnd, NULL );
}

void window_services_process_detach( BOOL process_terminating )
{
    HMODULE module = callback_module;

    destroy_callback = NULL;
    callback_module = NULL;
    registered_windows = 0;
    if (module && !process_terminating) FreeLibrary( module );
}
