/* COM window-property interface marshaling.
 *
 * Copyright 2026 Nulifyer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#define COBJMACROS
#include "objbase.h"
#include "winuser.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(ole);

#define WINDOW_PROP_MAGIC 0x504d4f43 /* COMP */
#define WINDOW_PROP_VERSION 1

struct window_prop_marshaled
{
    DWORD magic;
    DWORD version;
    DWORD size;
    DWORD process_id;
    DWORD thread_id;
    UINT64 hwnd;
    GUID iid;
    BYTE data[1];
};

static HRESULT create_mapping_from_stream(IStream *stream, HWND hwnd, REFIID iid, HANDLE *mapping)
{
    struct window_prop_marshaled *header;
    STATSTG stat;
    HGLOBAL global;
    SIZE_T mapping_size;
    const void *source;
    HRESULT hr;

    *mapping = NULL;
    if (FAILED(hr = IStream_Stat(stream, &stat, STATFLAG_NONAME))) return hr;
    if (stat.cbSize.HighPart || stat.cbSize.LowPart > MAXDWORD - offsetof(struct window_prop_marshaled, data))
        return E_OUTOFMEMORY;
    if (FAILED(hr = GetHGlobalFromStream(stream, &global))) return hr;
    if (!(source = GlobalLock(global))) return E_OUTOFMEMORY;

    mapping_size = offsetof(struct window_prop_marshaled, data) + stat.cbSize.LowPart;
    *mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, mapping_size, NULL);
    if (!*mapping)
    {
        GlobalUnlock(global);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    if (!(header = MapViewOfFile(*mapping, FILE_MAP_WRITE, 0, 0, mapping_size)))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        CloseHandle(*mapping);
        *mapping = NULL;
        GlobalUnlock(global);
        return hr;
    }

    header->magic = WINDOW_PROP_MAGIC;
    header->version = WINDOW_PROP_VERSION;
    header->size = stat.cbSize.LowPart;
    header->process_id = GetCurrentProcessId();
    header->thread_id = GetCurrentThreadId();
    header->hwnd = (UINT64)(ULONG_PTR)hwnd;
    header->iid = *iid;
    memcpy(header->data, source, header->size);
    UnmapViewOfFile(header);
    GlobalUnlock(global);
    return S_OK;
}

static HRESULT duplicate_mapping(HWND hwnd, UINT64 cookie, HANDLE *mapping)
{
    HANDLE process, source = (HANDLE)(ULONG_PTR)cookie;
    DWORD process_id;

    *mapping = NULL;
    if (!cookie || !GetWindowThreadProcessId(hwnd, &process_id))
        return HRESULT_FROM_WIN32(ERROR_INVALID_WINDOW_HANDLE);

    if (process_id == GetCurrentProcessId()) process = GetCurrentProcess();
    else if (!(process = OpenProcess(PROCESS_DUP_HANDLE, FALSE, process_id)))
        return HRESULT_FROM_WIN32(GetLastError());

    if (!DuplicateHandle(process, source, GetCurrentProcess(), mapping, 0, FALSE, DUPLICATE_SAME_ACCESS))
    {
        HRESULT hr = HRESULT_FROM_WIN32(GetLastError());
        if (process != GetCurrentProcess()) CloseHandle(process);
        return hr;
    }
    if (process != GetCurrentProcess()) CloseHandle(process);
    return S_OK;
}

static HRESULT create_stream_from_mapping(HANDLE mapping, HWND hwnd, REFIID iid,
        IStream **stream, DWORD *process_id, DWORD *thread_id)
{
    const struct window_prop_marshaled *header;
    MEMORY_BASIC_INFORMATION info;
    HGLOBAL global;
    void *destination;
    HRESULT hr;

    *stream = NULL;
    if (!(header = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0)))
        return HRESULT_FROM_WIN32(GetLastError());

    if (!VirtualQuery(header, &info, sizeof(info)) ||
        info.RegionSize < offsetof(struct window_prop_marshaled, data) ||
        header->magic != WINDOW_PROP_MAGIC || header->version != WINDOW_PROP_VERSION ||
        header->size > info.RegionSize - offsetof(struct window_prop_marshaled, data) ||
        header->hwnd != (UINT64)(ULONG_PTR)hwnd || !IsEqualIID(&header->iid, iid))
    {
        UnmapViewOfFile(header);
        return E_INVALIDARG;
    }

    if (process_id) *process_id = header->process_id;
    if (thread_id) *thread_id = header->thread_id;
    if (!(global = GlobalAlloc(GMEM_MOVEABLE, header->size)))
    {
        UnmapViewOfFile(header);
        return E_OUTOFMEMORY;
    }
    if (!(destination = GlobalLock(global)))
    {
        GlobalFree(global);
        UnmapViewOfFile(header);
        return E_OUTOFMEMORY;
    }

    memcpy(destination, header->data, header->size);
    GlobalUnlock(global);
    UnmapViewOfFile(header);
    hr = CreateStreamOnHGlobal(global, TRUE, stream);
    if (FAILED(hr)) GlobalFree(global);
    return hr;
}

/***********************************************************************
 *           InternalRegisterWindowPropInterface2 (combase.@)
 */
HRESULT WINAPI InternalRegisterWindowPropInterface2(HWND hwnd, REFIID iid, IUnknown *object,
        DWORD flags, UINT64 *cookie)
{
    LARGE_INTEGER zero;
    IStream *stream;
    HANDLE mapping;
    DWORD process_id;
    HRESULT hr;

    TRACE("%p, %s, %p, %#lx, %p.\n", hwnd, debugstr_guid(iid), object, flags, cookie);

    if (!cookie) return E_POINTER;
    *cookie = 0;
    if (!iid || !object) return E_INVALIDARG;
    if (!GetWindowThreadProcessId(hwnd, &process_id))
        return HRESULT_FROM_WIN32(ERROR_INVALID_WINDOW_HANDLE);
    if (process_id != GetCurrentProcessId()) return E_ACCESSDENIED;

    if (FAILED(hr = CreateStreamOnHGlobal(NULL, TRUE, &stream))) return hr;
    hr = CoMarshalInterface(stream, iid, object, MSHCTX_LOCAL, NULL, MSHLFLAGS_TABLESTRONG);
    if (SUCCEEDED(hr)) hr = create_mapping_from_stream(stream, hwnd, iid, &mapping);
    if (SUCCEEDED(hr)) *cookie = (UINT64)(ULONG_PTR)mapping;
    else
    {
        zero.QuadPart = 0;
        IStream_Seek(stream, zero, STREAM_SEEK_SET, NULL);
        CoReleaseMarshalData(stream);
    }
    IStream_Release(stream);
    return hr;
}

/***********************************************************************
 *           InternalGetWindowPropInterface2 (combase.@)
 */
HRESULT WINAPI InternalGetWindowPropInterface2(HWND hwnd, UINT64 cookie, DWORD flags,
        REFIID iid, void **object, DWORD *context)
{
    LARGE_INTEGER zero;
    IStream *stream;
    HANDLE mapping;
    HRESULT hr;

    TRACE("%p, %s, %#I64x, %#lx, %p, %p.\n", hwnd, debugstr_guid(iid), cookie,
            flags, object, context);

    if (!object || !context) return E_POINTER;
    *object = NULL;
    *context = 0;
    if (!iid) return E_INVALIDARG;
    if (FAILED(hr = duplicate_mapping(hwnd, cookie, &mapping))) return hr;
    hr = create_stream_from_mapping(mapping, hwnd, iid, &stream, NULL, NULL);
    CloseHandle(mapping);
    if (FAILED(hr)) return hr;

    zero.QuadPart = 0;
    IStream_Seek(stream, zero, STREAM_SEEK_SET, NULL);
    hr = CoUnmarshalInterface(stream, iid, object);
    IStream_Release(stream);
    return hr;
}

/***********************************************************************
 *           InternalRevokeWindowPropInterface (combase.@)
 */
HRESULT WINAPI InternalRevokeWindowPropInterface(HWND hwnd, UINT64 cookie, REFIID iid,
        DWORD *thread_id, DWORD *process_id)
{
    LARGE_INTEGER zero;
    IStream *stream;
    HANDLE mapping = (HANDLE)(ULONG_PTR)cookie;
    HRESULT hr;

    TRACE("%p, %s, %#I64x, %p, %p.\n", hwnd, debugstr_guid(iid), cookie,
            thread_id, process_id);

    if (!thread_id || !process_id) return E_POINTER;
    *thread_id = 0;
    *process_id = 0;
    if (!iid || !cookie) return E_INVALIDARG;

    hr = create_stream_from_mapping(mapping, hwnd, iid, &stream, process_id, thread_id);
    if (FAILED(hr)) return hr;
    zero.QuadPart = 0;
    IStream_Seek(stream, zero, STREAM_SEEK_SET, NULL);
    hr = CoReleaseMarshalData(stream);
    IStream_Release(stream);
    CloseHandle(mapping);
    return hr;
}
