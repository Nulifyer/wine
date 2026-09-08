/*
 * Package-scoped WinRT registration from immutable package manifests.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */
#define COBJMACROS
#include <stdlib.h>
#include <string.h>
#include "objbase.h"
#include "appmodel.h"
#include "shlwapi.h"
#include "initguid.h"
#include "xmllite.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(combase);

extern LONG WINAPI GetCurrentPackageInfo(UINT32, UINT32 *, BYTE *, UINT32 *);

struct package_class
{
    struct package_class *next;
    WCHAR *name, *path;
    UINT32 threading_model; /* 1: both, 2: STA, 3: MTA */
};

struct package_metadata
{
    struct package_metadata *next;
    WCHAR *full_name, *root;
    struct package_class *classes;
};

/* Only immutable metadata is cached, never a second process graph. Each
 * activation obtains an owned graph snapshot from KernelBase. */
static SRWLOCK metadata_lock = SRWLOCK_INIT;
static struct package_metadata *metadata_cache;

static void free_metadata(struct package_metadata *metadata)
{
    struct package_class *entry, *next;
    if (!metadata) return;
    for (entry = metadata->classes; entry; entry = next)
    {
        next = entry->next;
        free(entry->name);
        free(entry->path);
        free(entry);
    }
    free(metadata->full_name);
    free(metadata->root);
    free(metadata);
}

static BOOL foundation_element(IXmlReader *reader, const WCHAR *name)
{
    const WCHAR *local, *ns;
    if (FAILED(IXmlReader_GetLocalName(reader, &local, NULL)) || wcscmp(local, name) ||
        FAILED(IXmlReader_GetNamespaceUri(reader, &ns, NULL))) return FALSE;
    return !wcscmp(ns, L"http://schemas.microsoft.com/appx/manifest/foundation/windows10");
}

static HRESULT attribute(IXmlReader *reader, const WCHAR *name, WCHAR **out)
{
    const WCHAR *value;
    HRESULT hr;
    *out = NULL;
    if ((hr = IXmlReader_MoveToAttributeByName(reader, name, NULL)) != S_OK)
        return FAILED(hr) ? hr : APPX_E_INVALID_MANIFEST;
    hr = IXmlReader_GetValue(reader, &value, NULL);
    if (SUCCEEDED(hr) && !(*out = wcsdup(value))) hr = E_OUTOFMEMORY;
    IXmlReader_MoveToElement(reader);
    return hr;
}

static HRESULT element_text(IXmlReader *reader, WCHAR **out)
{
    XmlNodeType type;
    const WCHAR *value;
    WCHAR *result = NULL, *larger;
    SIZE_T length = 0;
    UINT32 chars;
    HRESULT hr;

    *out = NULL;
    while ((hr = IXmlReader_Read(reader, &type)) == S_OK)
    {
        if (type == XmlNodeType_EndElement) break;
        if (type == XmlNodeType_Element) { hr = APPX_E_INVALID_MANIFEST; break; }
        if (type != XmlNodeType_Text && type != XmlNodeType_CDATA && type != XmlNodeType_Whitespace)
            continue;
        if (FAILED(hr = IXmlReader_GetValue(reader, &value, &chars))) break;
        if (chars > 32767 - length) { hr = APPX_E_INVALID_MANIFEST; break; }
        if (!(larger = realloc(result, (length + chars + 1) * sizeof(WCHAR))))
        { hr = E_OUTOFMEMORY; break; }
        result = larger;
        memcpy(result + length, value, chars * sizeof(WCHAR));
        length += chars;
        result[length] = 0;
    }
    if (hr != S_OK || !length)
    { free(result); return FAILED(hr) ? hr : APPX_E_INVALID_MANIFEST; }
    *out = result;
    return S_OK;
}

static HRESULT package_path(const WCHAR *root, const WCHAR *relative, WCHAR **out)
{
    const WCHAR *component, *end;
    SIZE_T root_length = wcslen(root), length = wcslen(relative);
    *out = NULL;
    if (!length || relative[0] == '\\' || relative[0] == '/' || wcschr(relative, L':'))
        return APPX_E_INVALID_MANIFEST;
    for (component = relative; *component; component = *end ? end + 1 : end)
    {
        for (end = component; *end && *end != '\\' && *end != '/'; ++end) {}
        if (end == component || (end - component == 1 && *component == '.') ||
            (end - component == 2 && component[0] == '.' && component[1] == '.'))
            return APPX_E_INVALID_MANIFEST;
    }
    if (root_length + length + 2 > 32767) return APPX_E_INVALID_MANIFEST;
    if (!(*out = malloc((root_length + length + 2) * sizeof(WCHAR)))) return E_OUTOFMEMORY;
    memcpy(*out, root, root_length * sizeof(WCHAR));
    (*out)[root_length] = '\\';
    memcpy(*out + root_length + 1, relative, (length + 1) * sizeof(WCHAR));
    return S_OK;
}

static HRESULT parse_server(IXmlReader *reader, struct package_metadata *metadata)
{
    WCHAR *path = NULL, *relative = NULL;
    UINT32 depth, child_depth;
    XmlNodeType type;
    HRESULT hr;
    BOOL found_class = FALSE;

    if (FAILED(hr = IXmlReader_GetDepth(reader, &depth))) return hr;
    while ((hr = IXmlReader_Read(reader, &type)) == S_OK)
    {
        if (FAILED(hr = IXmlReader_GetDepth(reader, &child_depth))) break;
        if (type == XmlNodeType_EndElement && child_depth == depth) break;
        if (type != XmlNodeType_Element || child_depth != depth + 1) continue;
        if (foundation_element(reader, L"Path"))
        {
            if (path) { hr = APPX_E_INVALID_MANIFEST; break; }
            if (FAILED(hr = element_text(reader, &relative))) break;
            hr = package_path(metadata->root, relative, &path);
            free(relative);
            relative = NULL;
            if (FAILED(hr)) break;
        }
        else if (foundation_element(reader, L"ActivatableClass"))
        {
            struct package_class *entry;
            WCHAR *name = NULL, *threading = NULL;
            if (!path) { hr = APPX_E_INVALID_MANIFEST; break; }
            hr = attribute(reader, L"ActivatableClassId", &name);
            if (SUCCEEDED(hr)) hr = attribute(reader, L"ThreadingModel", &threading);
            if (SUCCEEDED(hr) && (!*name || (wcscmp(threading, L"both") &&
                wcscmp(threading, L"STA") && wcscmp(threading, L"MTA"))))
                hr = APPX_E_INVALID_MANIFEST;
            if (FAILED(hr)) { free(name); free(threading); break; }
            if (!(entry = calloc(1, sizeof(*entry))))
            { free(name); free(threading); hr = E_OUTOFMEMORY; break; }
            entry->name = name;
            entry->threading_model = !wcscmp(threading, L"both") ? 1 : !wcscmp(threading, L"STA") ? 2 : 3;
            free(threading);
            if (!(entry->path = wcsdup(path)))
            { free(entry->name); free(entry); hr = E_OUTOFMEMORY; break; }
            {
                struct package_class *existing;
                for (existing = metadata->classes; existing; existing = existing->next)
                    if (!wcscmp(existing->name, entry->name)) break;
                if (existing)
                {
                    hr = wcsicmp(existing->path, entry->path) || existing->threading_model != entry->threading_model
                         ? APPX_E_INVALID_MANIFEST : S_OK;
                    free(entry->name);
                    free(entry->path);
                    free(entry);
                    if (FAILED(hr)) break;
                    found_class = TRUE;
                    continue;
                }
            }
            entry->next = metadata->classes;
            metadata->classes = entry;
            found_class = TRUE;
        }
    }
    free(path);
    if (hr == S_FALSE || !found_class) return APPX_E_INVALID_MANIFEST;
    return hr;
}

static HRESULT parse_manifest(struct package_metadata *metadata)
{
    IXmlReader *reader = NULL;
    IStream *stream = NULL;
    WCHAR *filename = NULL, *category = NULL;
    UINT32 depth, extension_depth = ~0u;
    XmlNodeType type;
    HRESULT hr;
    BOOL root_seen = FALSE, package_extensions = FALSE;

    if (FAILED(hr = package_path(metadata->root, L"appxmanifest.xml", &filename))) return hr;
    hr = SHCreateStreamOnFileEx(filename, STGM_READ | STGM_SHARE_DENY_WRITE,
                                FILE_ATTRIBUTE_NORMAL, FALSE, NULL, &stream);
    free(filename);
    if (FAILED(hr)) goto done;
    if (FAILED(hr = CreateXmlReader(&IID_IXmlReader, (void **)&reader, NULL))) goto done;
    if (FAILED(hr = IXmlReader_SetProperty(reader, XmlReaderProperty_DtdProcessing, DtdProcessing_Prohibit))) goto done;
    if (FAILED(hr = IXmlReader_SetInput(reader, (IUnknown *)stream))) goto done;
    while ((hr = IXmlReader_Read(reader, &type)) == S_OK)
    {
        if (FAILED(hr = IXmlReader_GetDepth(reader, &depth))) break;
        if (type == XmlNodeType_EndElement && depth == extension_depth) extension_depth = ~0u;
        if (type == XmlNodeType_EndElement && depth == 1) package_extensions = FALSE;
        if (type != XmlNodeType_Element) continue;
        if (!depth)
        {
            if (!foundation_element(reader, L"Package")) { hr = APPX_E_INVALID_MANIFEST; break; }
            root_seen = TRUE;
        }
        if (depth == 1 && foundation_element(reader, L"Extensions")) package_extensions = TRUE;
        if (package_extensions && depth == 2 && foundation_element(reader, L"Extension"))
        {
            if (FAILED(hr = attribute(reader, L"Category", &category))) break;
            extension_depth = !wcscmp(category, L"windows.activatableClass.inProcessServer") ? depth : ~0u;
            free(category);
            category = NULL;
        }
        else if (extension_depth != ~0u && depth == extension_depth + 1 &&
                 foundation_element(reader, L"InProcessServer"))
        {
            if (FAILED(hr = parse_server(reader, metadata))) break;
        }
    }
    if (hr == S_FALSE) hr = root_seen ? S_OK : APPX_E_INVALID_MANIFEST;
done:
    if (reader) IXmlReader_Release(reader);
    if (stream) IStream_Release(stream);
    free(category);
    return hr;
}

static struct package_metadata *find_metadata(const PACKAGE_INFO *package)
{
    struct package_metadata *metadata;
    for (metadata = metadata_cache; metadata; metadata = metadata->next)
        if (!wcsicmp(metadata->full_name, package->packageFullName) && !wcsicmp(metadata->root, package->path))
            return metadata;
    return NULL;
}

static HRESULT get_metadata(const PACKAGE_INFO *package, struct package_metadata **out)
{
    struct package_metadata *metadata;
    HRESULT hr;

    AcquireSRWLockShared(&metadata_lock);
    *out = find_metadata(package);
    ReleaseSRWLockShared(&metadata_lock);
    if (*out) return S_OK;
    if (!(metadata = calloc(1, sizeof(*metadata)))) return E_OUTOFMEMORY;
    metadata->full_name = wcsdup(package->packageFullName);
    metadata->root = wcsdup(package->path);
    if (!metadata->full_name || !metadata->root) { free_metadata(metadata); return E_OUTOFMEMORY; }
    /* XML and stream calls run without a cache lock or graph lock. */
    if (FAILED(hr = parse_manifest(metadata))) { free_metadata(metadata); return hr; }
    AcquireSRWLockExclusive(&metadata_lock);
    if (!(*out = find_metadata(package)))
    {
        metadata->next = metadata_cache;
        metadata_cache = *out = metadata;
        metadata = NULL;
    }
    ReleaseSRWLockExclusive(&metadata_lock);
    free_metadata(metadata);
    return S_OK;
}

HRESULT package_get_class_path(const WCHAR *classid, WCHAR **path)
{
    struct package_metadata *metadata;
    struct package_class *entry;
    PACKAGE_INFO *packages = NULL;
    UINT32 size = 0, count = 0, i, attempt;
    LONG ret;
    HRESULT hr = S_FALSE;

    *path = NULL;
    ret = GetCurrentPackageInfo(0x100030, &size, NULL, &count);
    if (ret == APPMODEL_ERROR_NO_PACKAGE || (!ret && !count)) return S_FALSE;
    for (attempt = 0; ret == ERROR_INSUFFICIENT_BUFFER && attempt < 8; ++attempt)
    {
        free(packages);
        if (!(packages = malloc(size))) return E_OUTOFMEMORY;
        ret = GetCurrentPackageInfo(0x100030, &size, (BYTE *)packages, &count);
    }
    if (ret) { free(packages); return HRESULT_FROM_WIN32(ret); }
    if (count > size / sizeof(*packages)) { free(packages); return E_UNEXPECTED; }
    for (i = 0; i < count; ++i)
    {
        if (FAILED(hr = get_metadata(&packages[i], &metadata))) break;
        hr = S_FALSE;
        for (entry = metadata->classes; entry; entry = entry->next)
        {
            if (wcscmp(entry->name, classid)) continue;
            if (entry->threading_model != 1) hr = E_NOTIMPL; /* apartment routing is not implemented here */
            else if (!(*path = wcsdup(entry->path))) hr = E_OUTOFMEMORY;
            else hr = S_OK;
            TRACE("Package %s selects %s for %s, hr %#lx\n", debugstr_w(packages[i].packageFullName),
                  debugstr_w(entry->path), debugstr_w(classid), hr);
            break;
        }
        if (hr != S_FALSE) break;
    }
    free(packages);
    return hr;
}
