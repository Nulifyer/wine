/*
 * Process package graph and package-name aliases.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "winerror.h"
#include "appmodel.h"
#include "kernelbase.h"
#include "package_catalog.h"
#include "package_graph.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(appmodel);

struct graph_node
{
    struct graph_node *next;
    struct package_catalog_entry *package;
    PACKAGE_ID *id;
    WCHAR *aliases;
    UINT32 alias_count, alias_chars;
};

static SRWLOCK graph_lock = SRWLOCK_INIT;
static struct graph_node *graph_head;
static UINT32 graph_generation;

extern NTSTATUS WINAPI __wine_set_package_dll_path(const UNICODE_STRING *path);

/* Prepare the loader's derived path before publishing a new graph head.
 * No loader callback enters this module while its search-path lock is held. */
static HRESULT update_loader_path(struct graph_node *head)
{
    struct graph_node *node;
    SIZE_T chars = 0, length;
    WCHAR *storage, *cursor;
    UNICODE_STRING path;
    NTSTATUS status;

    for (node = head; node; node = node->next)
    {
        if (wcschr(node->package->path, L';')) return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
        length = wcslen(node->package->path) + 1;
        if (length > 32767 - chars) return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
        chars += length;
    }
    if (!(storage = HeapAlloc(GetProcessHeap(), 0, chars * sizeof(WCHAR)))) return E_OUTOFMEMORY;
    for (cursor = storage, node = head; node; node = node->next)
    {
        length = wcslen(node->package->path);
        memcpy(cursor, node->package->path, length * sizeof(WCHAR));
        cursor += length;
        *cursor++ = node->next ? L';' : 0;
    }
    path.Buffer = storage;
    path.Length = (chars - 1) * sizeof(WCHAR);
    path.MaximumLength = chars * sizeof(WCHAR);
    status = __wine_set_package_dll_path(&path);
    HeapFree(GetProcessHeap(), 0, storage);
    return status ? HRESULT_FROM_NT(status) : S_OK;
}

/* Entries live until process teardown. Every mutation prepares its allocations
 * before publication; readers copy while holding the shared lock. */
static void free_node(struct graph_node *node)
{
    if (!node) return;
    package_catalog_free(node->package);
    HeapFree(GetProcessHeap(), 0, node->id);
    HeapFree(GetProcessHeap(), 0, node->aliases);
    HeapFree(GetProcessHeap(), 0, node);
}

static HRESULT append_aliases(struct graph_node *node, UINT32 count, const WCHAR **aliases)
{
    SIZE_T chars = node->alias_chars, length;
    UINT32 total = node->alias_count, i;
    WCHAR *values, *cursor;

    for (i = 0; i < count; ++i)
    {
        if (!aliases[i] || !*aliases[i]) continue;
        length = wcslen(aliases[i]) + 1;
        if (length > (~0u / sizeof(WCHAR)) - chars || total == ~0u)
            return E_OUTOFMEMORY;
        chars += length;
        ++total;
    }
    if (total == node->alias_count) return S_OK;
    if (!(values = HeapAlloc(GetProcessHeap(), 0, chars * sizeof(WCHAR)))) return E_OUTOFMEMORY;
    if (node->alias_chars) memcpy(values, node->aliases, node->alias_chars * sizeof(WCHAR));
    cursor = values + node->alias_chars;
    for (i = 0; i < count; ++i)
    {
        if (!aliases[i] || !*aliases[i]) continue;
        length = wcslen(aliases[i]) + 1;
        memcpy(cursor, aliases[i], length * sizeof(WCHAR));
        cursor += length;
    }
    HeapFree(GetProcessHeap(), 0, node->aliases);
    node->aliases = values;
    node->alias_count = total;
    node->alias_chars = chars;
    return S_OK;
}

HRESULT WINAPI AddDependencyToProcessPackageGraph(const WCHAR *family, const WCHAR *alias,
                                                   INT32 ordering, UINT32 options)
{
    struct package_catalog_entry *package = NULL;
    struct graph_node *node = NULL;
    UINT32 id_size = 0;
    HRESULT hr;
    LONG ret;

    TRACE("%s, %s, %d, %#x\n", debugstr_w(family), debugstr_w(alias), ordering, options);
    if (!family || !*family) return E_INVALIDARG;
    /* Ordering/options beyond the reached private contract need their own
     * baseline, not the public AddPackageDependency parameter conventions. */
    if (ordering || options != 3) return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    hr = package_catalog_family(family, &package);
    if (FAILED(hr)) goto done;
    if (!package) { hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND); goto done; }
    if (package->next || package->type != 1)
    { hr = HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED); goto done; }
    if (!(node = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*node))))
    { hr = E_OUTOFMEMORY; goto done; }
    node->package = package;
    package = NULL;
    ret = PackageIdFromFullName(node->package->full_name, 0, &id_size, NULL);
    if (ret != ERROR_INSUFFICIENT_BUFFER) { hr = HRESULT_FROM_WIN32(ret); goto done; }
    if (!(node->id = HeapAlloc(GetProcessHeap(), 0, id_size))) { hr = E_OUTOFMEMORY; goto done; }
    if ((ret = PackageIdFromFullName(node->package->full_name, 0, &id_size, (BYTE *)node->id)))
    { hr = HRESULT_FROM_WIN32(ret); goto done; }
    if (alias && FAILED(hr = append_aliases(node, 1, &alias))) goto done;
    RtlAcquireSRWLockExclusive(&graph_lock);
    node->next = graph_head;
    if (FAILED(hr = update_loader_path(node)))
    {
        RtlReleaseSRWLockExclusive(&graph_lock);
        goto done;
    }
    graph_head = node;
    ++graph_generation;
    RtlReleaseSRWLockExclusive(&graph_lock);
    node = NULL;
    hr = S_OK;
done:
    free_node(node);
    package_catalog_free(package);
    SetLastError(0);
    return hr;
}

HRESULT WINAPI AddPackageNameAliasesByPackageFullName(const WCHAR *full_name, UINT32 count,
                                                       const WCHAR **aliases)
{
    struct graph_node *node;
    HRESULT hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    DWORD error = GetLastError();

    TRACE("%s, %u, %p\n", debugstr_w(full_name), count, aliases);
    if (!full_name || !*full_name || !count || !aliases) return E_INVALIDARG;
    RtlAcquireSRWLockExclusive(&graph_lock);
    for (node = graph_head; node; node = node->next)
    {
        if (wcsicmp(full_name, node->package->full_name)) continue;
        hr = append_aliases(node, count, aliases);
        break;
    }
    RtlReleaseSRWLockExclusive(&graph_lock);
    SetLastError(node ? error : 0);
    return hr;
}

HRESULT WINAPI GetPackageNameAliasesByPackageFullName(const WCHAR *full_name, WCHAR **aliases,
                                                       UINT32 *count)
{
    struct graph_node *node;
    HRESULT hr = S_OK;

    TRACE("%s, %p, %p\n", debugstr_w(full_name), aliases, count);
    if (!full_name || !aliases) return E_INVALIDARG;
    *aliases = NULL;
    if (count) *count = 0;
    RtlAcquireSRWLockShared(&graph_lock);
    for (node = graph_head; node; node = node->next)
    {
        if (wcsicmp(full_name, node->package->full_name)) continue;
        if (node->alias_chars)
        {
            if (!(*aliases = HeapAlloc(GetProcessHeap(), 0, node->alias_chars * sizeof(WCHAR))))
            { hr = E_OUTOFMEMORY; break; }
            memcpy(*aliases, node->aliases, node->alias_chars * sizeof(WCHAR));
            if (count) *count = node->alias_count;
        }
        break;
    }
    RtlReleaseSRWLockShared(&graph_lock);
    return hr;
}

static SIZE_T string_bytes(const WCHAR *value)
{
    return value && *value ? (wcslen(value) + 1) * sizeof(WCHAR) : 0;
}

static WCHAR *copy_string(BYTE **cursor, const WCHAR *value)
{
    SIZE_T bytes = string_bytes(value);
    WCHAR *out = (WCHAR *)*cursor;
    if (!bytes) return NULL;
    memcpy(out, value, bytes);
    *cursor += bytes;
    return out;
}

static LONG graph_info_locked(UINT32 flags, UINT32 path_type, UINT32 *size, BYTE *buffer, UINT32 *count)
{
    struct graph_node *node;
    SIZE_T required = 0, node_size;
    UINT32 total = 0, supplied;
    PACKAGE_INFO *info;
    BYTE *cursor;
    LONG ret = ERROR_SUCCESS;

    if (!size || (!buffer && *size)) return ERROR_INVALID_PARAMETER;
    if (!(flags & 0x100000) || !graph_head) { ret = APPMODEL_ERROR_NO_PACKAGE; goto done; }
    if (path_type > 2) /* Install, Mutable, Effective for the ordinary package. */
    { SetLastError(0); return ERROR_INVALID_PARAMETER; }
    if (flags & ~0x100030u) return ERROR_NOT_SUPPORTED;
    if (!(flags & 0x30) || (flags & 0x10))
        for (node = graph_head; node; node = node->next)
        {
            node_size = sizeof(*info) + string_bytes(node->package->path) +
                string_bytes(node->id->name) + string_bytes(node->id->resourceId) +
                string_bytes(node->id->publisherId) + string_bytes(node->package->publisher) +
                string_bytes(node->package->full_name) + string_bytes(node->package->family_name);
            if (node_size > ~0u - required || total == ~0u)
            { ret = ERROR_ARITHMETIC_OVERFLOW; goto done; }
            required += node_size;
            ++total;
        }
    supplied = *size;
    *size = required;
    if (count) *count = total;
    if (supplied < required) { ret = ERROR_INSUFFICIENT_BUFFER; goto done; }
    if (!total) goto done;
    memset(buffer, 0, required);
    info = (PACKAGE_INFO *)buffer;
    cursor = buffer + total * sizeof(*info);
    for (node = graph_head; node; node = node->next, ++info)
    {
        info->flags = 0x10;
        info->packageId = *node->id;
        info->path = copy_string(&cursor, node->package->path);
        info->packageId.name = copy_string(&cursor, node->id->name);
        info->packageId.resourceId = copy_string(&cursor, node->id->resourceId);
        info->packageId.publisherId = copy_string(&cursor, node->id->publisherId);
        info->packageId.publisher = copy_string(&cursor, node->package->publisher);
        info->packageFullName = copy_string(&cursor, node->package->full_name);
        info->packageFamilyName = copy_string(&cursor, node->package->family_name);
    }
done:
    return ret;
}

LONG package_graph_info(UINT32 flags, UINT32 path_type, UINT32 *size, BYTE *buffer, UINT32 *count)
{
    LONG ret;
    RtlAcquireSRWLockShared(&graph_lock);
    ret = graph_info_locked(flags, path_type, size, buffer, count);
    RtlReleaseSRWLockShared(&graph_lock);
    return ret;
}

HRESULT package_graph_info3(UINT32 flags, UINT32 type, UINT32 *size, void *buffer, UINT32 *count)
{
    LONG ret;
    if (!size) return E_INVALIDARG;
    RtlAcquireSRWLockShared(&graph_lock);
    if (type == 0x10)
    {
        if (count) *count = 0;
        if (!buffer || *size < sizeof(UINT32)) ret = ERROR_INSUFFICIENT_BUFFER;
        else
        {
            *(UINT32 *)buffer = graph_generation;
            *size = sizeof(UINT32);
            ret = ERROR_SUCCESS;
        }
    }
    else if (!graph_head) ret = APPMODEL_ERROR_NO_PACKAGE;
    else if (type == 0x11)
    {
        *size = 0;
        if (count) *count = 0;
        ret = ERROR_SUCCESS;
    }
    else ret = graph_info_locked(flags | 0x100000, type, size, buffer, count);
    RtlReleaseSRWLockShared(&graph_lock);
    return HRESULT_FROM_WIN32(ret);
}
