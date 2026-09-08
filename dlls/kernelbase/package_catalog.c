/*
 * Research package catalog access through the selected StateRepository owner.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "winerror.h"
#include "appmodel.h"
#include "kernelbase.h"
#include "package_catalog.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(appmodel);

struct cache_reader
{
    HMODULE module;
    void *manager;
    HRESULT (WINAPI *open_manager)(UINT32, void **);
    void (WINAPI *close_manager)(void *);
    HRESULT (WINAPI *open)(void *, const WCHAR *, UINT32, void **);
    void (WINAPI *close)(void *);
    HRESULT (WINAPI *enumerate)(void *, UINT32, UINT64 *);
    HRESULT (WINAPI *string)(void *, const WCHAR *, WCHAR **);
    HRESULT (WINAPI *integer)(void *, const WCHAR *, UINT64 *);
    void (WINAPI *release)(void *);
};

static void close_reader(struct cache_reader *reader)
{
    if (reader->manager) reader->close_manager(reader->manager);
    if (reader->module) FreeLibrary(reader->module);
}

static HRESULT open_reader(struct cache_reader *reader)
{
    memset(reader, 0, sizeof(*reader));
    reader->module = LoadLibraryExW(L"ext-ms-onecore-appmodel-staterepository-cache-l1-1-5.dll",
                                   NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!reader->module) return HRESULT_FROM_WIN32(GetLastError());
#define LOAD(field, name) do { \
    reader->field = (void *)GetProcAddress(reader->module, name); \
    if (!reader->field) return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND); \
} while (0)
    LOAD(open_manager, "SRCacheManager_Open");
    LOAD(close_manager, "SRCacheManager_Close");
    LOAD(open, "SRCacheContext_Open");
    LOAD(close, "SRCacheContext_Close");
    LOAD(enumerate, "SRCacheContext_EnumerateIndex");
    LOAD(string, "SRCacheContext_GetField_String");
    LOAD(integer, "SRCacheContext_GetField_UInt64");
    LOAD(release, "SRCache_Free");
#undef LOAD
    return reader->open_manager(0, &reader->manager);
}

static HRESULT lookup(struct cache_reader *reader, const WCHAR *path, UINT64 *id)
{
    void *context = NULL;
    HRESULT hr;

    *id = 0;
    if (FAILED(hr = reader->open(reader->manager, path, 0, &context))) return hr;
    if (!context) return S_FALSE;
    hr = reader->enumerate(context, 0, id);
    reader->close(context);
    if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) return S_FALSE;
    return hr;
}

static HRESULT current_user(struct cache_reader *reader, UINT64 *id)
{
    union { TOKEN_USER user; BYTE bytes[256]; } token;
    UNICODE_STRING sid;
    WCHAR path[256];
    ULONG length;
    NTSTATUS status;
    HRESULT hr;

    /* Effective token preserves impersonation instead of treating the process
     * user's registration as authority for every calling thread. */
    status = NtQueryInformationToken((HANDLE)-6, TokenUser, &token, sizeof(token), &length);
    if (status) return HRESULT_FROM_NT(status);
    if ((status = RtlConvertSidToUnicodeString(&sid, token.user.User.Sid, TRUE)))
        return HRESULT_FROM_NT(status);
    if (sid.Length / sizeof(WCHAR) + wcslen(L"User\\Index\\UserSid\\") >= ARRAY_SIZE(path))
        hr = E_INVALIDARG;
    else
    {
        swprintf(path, ARRAY_SIZE(path), L"User\\Index\\UserSid\\%s", sid.Buffer);
        hr = lookup(reader, path, id);
    }
    RtlFreeUnicodeString(&sid);
    return hr;
}

static HRESULT read_string(struct cache_reader *reader, void *context, const WCHAR *field, WCHAR **out)
{
    WCHAR *value = NULL;
    HRESULT hr;

    *out = NULL;
    if (FAILED(hr = reader->string(context, field, &value))) return hr;
    if (!value) return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    if ((*out = HeapAlloc(GetProcessHeap(), 0, (wcslen(value) + 1) * sizeof(WCHAR))))
        wcscpy(*out, value);
    reader->release(value);
    return *out ? S_OK : E_OUTOFMEMORY;
}

void package_catalog_free(struct package_catalog_entry *entry)
{
    while (entry)
    {
        struct package_catalog_entry *next = entry->next;
        HeapFree(GetProcessHeap(), 0, entry->full_name);
        HeapFree(GetProcessHeap(), 0, entry->family_name);
        HeapFree(GetProcessHeap(), 0, entry->path);
        HeapFree(GetProcessHeap(), 0, entry->publisher);
        HeapFree(GetProcessHeap(), 0, entry);
        entry = next;
    }
}

static HRESULT read_package(struct cache_reader *reader, UINT64 id, UINT64 user,
                            struct package_catalog_entry **result)
{
    struct package_catalog_entry *entry = NULL;
    void *registration = NULL, *package = NULL, *family = NULL;
    WCHAR path[256];
    UINT64 registration_id, family_id, state, linked_id;
    HRESULT hr;

    *result = NULL;
    swprintf(path, ARRAY_SIZE(path), L"PackageUser\\Index\\UserAndPackage\\%llx^%llx", user, id);
    if ((hr = lookup(reader, path, &registration_id)) != S_OK) return hr;
    swprintf(path, ARRAY_SIZE(path), L"PackageUser\\Data\\%llx", registration_id);
    if (FAILED(hr = reader->open(reader->manager, path, 0, &registration))) goto done;
    if (!registration) { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); goto done; }
    if (FAILED(hr = reader->integer(registration, L"User", &linked_id))) goto done;
    if (linked_id != user) { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); goto done; }
    if (FAILED(hr = reader->integer(registration, L"Package", &linked_id))) goto done;
    if (linked_id != id) { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); goto done; }
    if (FAILED(hr = reader->integer(registration, L"DeploymentState", &state))) goto done;
    /* Other deployment states need their own registration/activation contract. */
    if (state != 2) { hr = HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED); goto done; }
    swprintf(path, ARRAY_SIZE(path), L"Package\\Data\\%llx", id);
    if (FAILED(hr = reader->open(reader->manager, path, 0, &package))) goto done;
    if (!package) { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); goto done; }
    if (!(entry = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*entry))))
    { hr = E_OUTOFMEMORY; goto done; }
    if (FAILED(hr = read_string(reader, package, L"PackageFullName", &entry->full_name))) goto done;
    if (FAILED(hr = read_string(reader, package, L"InstalledLocation", &entry->path))) goto done;
    if (FAILED(hr = reader->integer(package, L"PackageType", &entry->type))) goto done;
    if (FAILED(hr = reader->integer(package, L"PackageFamily", &family_id))) goto done;
    swprintf(path, ARRAY_SIZE(path), L"PackageFamily\\Data\\%llx", family_id);
    if (FAILED(hr = reader->open(reader->manager, path, 0, &family))) goto done;
    if (!family) { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); goto done; }
    if (FAILED(hr = read_string(reader, family, L"PackageFamilyName", &entry->family_name))) goto done;
    if (FAILED(hr = read_string(reader, family, L"Publisher", &entry->publisher))) goto done;
    *result = entry;
    entry = NULL;
done:
    package_catalog_free(entry);
    if (family) reader->close(family);
    if (package) reader->close(package);
    if (registration) reader->close(registration);
    return hr;
}

HRESULT package_catalog_family(const WCHAR *family_name, struct package_catalog_entry **result)
{
    struct cache_reader reader;
    struct package_catalog_entry **tail = result, *entry;
    void *index = NULL;
    WCHAR path[256];
    UINT64 family_id, user, id;
    UINT32 ordinal;
    HRESULT hr;

    TRACE("family %s\n", debugstr_w(family_name));
    *result = NULL;
    if (!family_name || !*family_name || wcslen(family_name) > 64 || wcschr(family_name, L'\\'))
        return E_INVALIDARG;
    if (FAILED(hr = open_reader(&reader))) goto done;
    if (!reader.manager) { hr = S_FALSE; goto done; }
    swprintf(path, ARRAY_SIZE(path), L"PackageFamily\\Index\\PackageFamilyName\\%s", family_name);
    if ((hr = lookup(&reader, path, &family_id)) != S_OK) goto done;
    if ((hr = current_user(&reader, &user)) != S_OK) goto done;
    swprintf(path, ARRAY_SIZE(path), L"Package\\Index\\PackageFamily\\%llx", family_id);
    if (FAILED(hr = reader.open(reader.manager, path, 0, &index))) goto done;
    if (!index) { hr = S_FALSE; goto done; }
    for (ordinal = 0; ; ++ordinal)
    {
        hr = reader.enumerate(index, ordinal, &id);
        if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) { hr = S_OK; break; }
        if (FAILED(hr)) goto done;
        if (!id || ordinal == ~0u) { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); goto done; }
        hr = read_package(&reader, id, user, &entry);
        if (hr == S_FALSE) continue;
        if (FAILED(hr)) goto done;
        if (wcsicmp(entry->family_name, family_name))
        {
            package_catalog_free(entry);
            hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
            goto done;
        }
        *tail = entry;
        tail = &entry->next;
    }
done:
    if (index) reader.close(index);
    close_reader(&reader);
    if (FAILED(hr)) { package_catalog_free(*result); *result = NULL; }
    return hr;
}

/***********************************************************************
 *         FindPackagesByPackageFamily   (kernelbase.@)
 */
LONG WINAPI FindPackagesByPackageFamily( const WCHAR *family_name, UINT32 filters,
                                         UINT32 *count, WCHAR **full_names,
                                         UINT32 *buffer_length, WCHAR *buffer,
                                         UINT32 *properties )
{
    struct package_catalog_entry *entries = NULL, *entry;
    UINT32 supplied_count, supplied_length, required_length = 0, required_count = 0, i;
    DWORD error = GetLastError();
    const WCHAR *separator;
    HRESULT hr;
    LONG ret = ERROR_SUCCESS;

    TRACE( "(%s %#x %p %p %p %p %p)\n", debugstr_w(family_name), filters,
           count, full_names, buffer_length, buffer, properties );

    if (!family_name || !filters || !count || !buffer_length ||
        (*count && (!full_names || !buffer)) || (*buffer_length && !buffer))
    {
        SetLastError(0);
        return ERROR_INVALID_PARAMETER;
    }
    if (!*family_name) { SetLastError(0); return ERROR_MORE_DATA; }
    separator = wcschr(family_name, L'_');
    if (!separator || separator == family_name || wcslen(separator + 1) != 13 ||
        wcslen(family_name) > PACKAGE_FAMILY_NAME_MAX_LENGTH || wcschr(family_name, L'\\'))
    {
        SetLastError(0);
        return ERROR_INVALID_PARAMETER;
    }
    /* The catalog head is the reached contract. Dependency/resource filters
     * require package dependency metadata; do not fabricate an empty graph. */
    if (filters != 0x10) return ERROR_NOT_SUPPORTED;
    supplied_count = *count;
    supplied_length = *buffer_length;
    hr = package_catalog_family(family_name, &entries);
    if (FAILED(hr)) return HRESULT_CODE(hr);
    for (entry = entries; entry; entry = entry->next)
    {
        SIZE_T length = wcslen(entry->full_name) + 1;
        if (entry->type != 1) { ret = ERROR_NOT_SUPPORTED; goto done; }
        if (length > ~0u - required_length || required_count == ~0u)
        { ret = ERROR_ARITHMETIC_OVERFLOW; goto done; }
        required_length += length;
        ++required_count;
    }
    *count = required_count;
    *buffer_length = required_length;
    if (supplied_count < required_count || supplied_length < required_length)
    { ret = ERROR_INSUFFICIENT_BUFFER; goto done; }
    for (entry = entries, i = 0; entry; entry = entry->next, ++i)
    {
        UINT32 length = wcslen(entry->full_name) + 1;
        full_names[i] = buffer;
        memcpy(buffer, entry->full_name, length * sizeof(*buffer));
        buffer += length;
        if (properties) properties[i] = 0;
    }
done:
    package_catalog_free(entries);
    SetLastError(required_count ? 0 : error);
    return ret;
}
