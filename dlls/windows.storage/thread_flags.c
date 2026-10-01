/* Windows.Storage thread flags
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "private.h"

WINE_DEFAULT_DEBUG_CHANNEL(storage);

#define TLS_ALLOCATION_FAILED (TLS_OUT_OF_INDEXES - 1)

static LONG thread_flags_tls = TLS_OUT_OF_INDEXES;

LONG *WINAPI Global_WindowsStorage_tlsThreadFlags(void)
{
    return &thread_flags_tls;
}

static DWORD get_thread_flags_tls(void)
{
    DWORD allocated;
    LONG index, previous;

    index = InterlockedCompareExchange(&thread_flags_tls, 0, 0);
    if (index != TLS_OUT_OF_INDEXES) return index;

    allocated = TlsAlloc();
    index = allocated == TLS_OUT_OF_INDEXES ? TLS_ALLOCATION_FAILED : allocated;
    previous = InterlockedCompareExchange(&thread_flags_tls, index, TLS_OUT_OF_INDEXES);
    if (previous != TLS_OUT_OF_INDEXES)
    {
        if (allocated != TLS_OUT_OF_INDEXES) TlsFree(allocated);
        index = previous;
    }
    return index;
}

HRESULT WINAPI GetThreadFlags(DWORD mask, DWORD *flags)
{
    DWORD error, index;
    ULONG_PTR value;

    TRACE("mask %#lx, flags %p.\n", mask, flags);

    *flags = 0;
    index = InterlockedCompareExchange(&thread_flags_tls, 0, 0);
    if (index == TLS_OUT_OF_INDEXES) return S_OK;
    if (index == TLS_ALLOCATION_FAILED) return E_FAIL;

    SetLastError(ERROR_SUCCESS);
    value = (ULONG_PTR)TlsGetValue(index);
    if (!value && (error = GetLastError()) != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(error);

    *flags = value & mask;
    return S_OK;
}

HRESULT WINAPI SetThreadFlags(DWORD mask, DWORD flags)
{
    DWORD error, index;
    ULONG_PTR value;

    TRACE("mask %#lx, flags %#lx.\n", mask, flags);

    index = get_thread_flags_tls();
    if (index == TLS_ALLOCATION_FAILED) return E_FAIL;

    SetLastError(ERROR_SUCCESS);
    value = (ULONG_PTR)TlsGetValue(index);
    if (!value && (error = GetLastError()) != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(error);

    value = (value & ~mask) | flags;
    if (!TlsSetValue(index, (void *)value)) return HRESULT_FROM_WIN32(GetLastError());
    return S_OK;
}
