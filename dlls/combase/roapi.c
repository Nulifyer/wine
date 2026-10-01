/*
 * Copyright 2014 Martin Storsjo
 * Copyright 2016 Michael Müller
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
#define COBJMACROS
#include "objbase.h"
#include "bcrypt.h"
#include "ctxtcall.h"
#include "comsvcs.h"
#include "initguid.h"
#include "roapi.h"
#include "roparameterizediid.h"
#include "roerrorapi.h"
#include "winstring.h"
#include "winsvc.h"
#include "errhandlingapi.h"

#include "combase_private.h"

#include "wine/exception.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(combase);

HRESULT WINAPI RoGetExtensionRegistrationForLaunchContracts(HSTRING contract_id, HSTRING package_id,
        UINT32 class_count, HSTRING *class_ids, IInspectable **registration)
{
    UINT32 i;

    if (!registration) return E_POINTER;
    *registration = NULL;

    FIXME("contract %s package %s, %u classes\n",
            debugstr_w(WindowsGetStringRawBuffer(contract_id, NULL)),
            debugstr_w(WindowsGetStringRawBuffer(package_id, NULL)), class_count);
    for (i = 0; i < class_count; ++i)
        FIXME("class[%u] %s\n", i, debugstr_w(WindowsGetStringRawBuffer(class_ids[i], NULL)));

    return E_NOTIMPL;
}

IActivationFactory *linuxnt_wrap_xaml_metadata_factory(IActivationFactory *factory);
HRESULT extension_catalog_get_factory(HSTRING classid, IActivationFactory **factory);
HRESULT package_get_class_path(const WCHAR *classid, WCHAR **path);

struct vector_statics;

struct vector_statics_vtbl
{
    HRESULT (WINAPI *QueryInterface)(struct vector_statics *, REFIID, void **);
    ULONG (WINAPI *AddRef)(struct vector_statics *);
    ULONG (WINAPI *Release)(struct vector_statics *);
    HRESULT (WINAPI *GetIids)(struct vector_statics *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(struct vector_statics *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(struct vector_statics *, TrustLevel *);
    HRESULT (WINAPI *CreateBooleanVector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateAgileBooleanVector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateUInt8Vector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateAgileUInt8Vector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateInt16Vector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateAgileInt16Vector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateUInt16Vector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateAgileUInt16Vector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateInt32Vector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateAgileInt32Vector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateUInt32Vector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateAgileUInt32Vector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateInt64Vector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateAgileInt64Vector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateUInt64Vector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateAgileUInt64Vector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateSingleVector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateAgileSingleVector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateDoubleVector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateAgileDoubleVector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateStringVector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateAgileStringVector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateGuidVector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateAgileGuidVector)(struct vector_statics *, void **);
    HRESULT (WINAPI *CreateObjectVector)(struct vector_statics *, const void *, IInspectable **);
    HRESULT (WINAPI *CreateAgileObjectVector)(struct vector_statics *, const void *, IInspectable **);
};

struct vector_statics
{
    const struct vector_statics_vtbl *lpVtbl;
};

static const IID IID_IVectorStatics =
    {0x08c77958, 0x89bf, 0x5cf8, {0xa9, 0xcd, 0xc7, 0x21, 0x47, 0xb9, 0xb3, 0xa9}};

static HRESULT WINAPI vector_statics_QueryInterface(struct vector_statics *iface, REFIID iid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IAgileObject) || IsEqualGUID(iid, &IID_IVectorStatics))
    {
        *out = iface;
        return S_OK;
    }
    FIXME("unsupported interface %s\n", debugstr_guid(iid));
    return E_NOINTERFACE;
}

static ULONG WINAPI vector_statics_AddRef(struct vector_statics *iface)
{
    return 2;
}

static ULONG WINAPI vector_statics_Release(struct vector_statics *iface)
{
    return 1;
}

static HRESULT WINAPI vector_statics_GetIids(struct vector_statics *iface, ULONG *count, IID **iids)
{
    if (!count || !iids) return E_POINTER;
    if (!(*iids = CoTaskMemAlloc(sizeof(**iids)))) return E_OUTOFMEMORY;
    **iids = IID_IVectorStatics;
    *count = 1;
    return S_OK;
}

static HRESULT WINAPI vector_statics_GetRuntimeClassName(struct vector_statics *iface, HSTRING *name)
{
    static const WCHAR class_name[] = L"Windows.Foundation.Collections.Detail.Vector";
    if (!name) return E_POINTER;
    return WindowsCreateString(class_name, ARRAY_SIZE(class_name) - 1, name);
}

static HRESULT WINAPI vector_statics_GetTrustLevel(struct vector_statics *iface, TrustLevel *trust)
{
    if (!trust) return E_POINTER;
    *trust = BaseTrust;
    return S_OK;
}

#define DEFINE_VECTOR_CREATE(name) \
    static HRESULT WINAPI vector_statics_##name(struct vector_statics *iface, void **out) \
    { \
        FIXME(#name " not implemented\n"); \
        if (!out) return E_POINTER; \
        *out = NULL; \
        return E_NOTIMPL; \
    }

DEFINE_VECTOR_CREATE(CreateBooleanVector)
DEFINE_VECTOR_CREATE(CreateAgileBooleanVector)
DEFINE_VECTOR_CREATE(CreateUInt8Vector)
DEFINE_VECTOR_CREATE(CreateAgileUInt8Vector)
DEFINE_VECTOR_CREATE(CreateInt16Vector)
DEFINE_VECTOR_CREATE(CreateAgileInt16Vector)
DEFINE_VECTOR_CREATE(CreateUInt16Vector)
DEFINE_VECTOR_CREATE(CreateAgileUInt16Vector)
DEFINE_VECTOR_CREATE(CreateInt32Vector)
DEFINE_VECTOR_CREATE(CreateAgileInt32Vector)
DEFINE_VECTOR_CREATE(CreateUInt32Vector)
DEFINE_VECTOR_CREATE(CreateAgileUInt32Vector)
DEFINE_VECTOR_CREATE(CreateInt64Vector)
DEFINE_VECTOR_CREATE(CreateAgileInt64Vector)
DEFINE_VECTOR_CREATE(CreateUInt64Vector)
DEFINE_VECTOR_CREATE(CreateAgileUInt64Vector)
DEFINE_VECTOR_CREATE(CreateSingleVector)
DEFINE_VECTOR_CREATE(CreateAgileSingleVector)
DEFINE_VECTOR_CREATE(CreateDoubleVector)
DEFINE_VECTOR_CREATE(CreateAgileDoubleVector)
DEFINE_VECTOR_CREATE(CreateStringVector)
DEFINE_VECTOR_CREATE(CreateAgileStringVector)
DEFINE_VECTOR_CREATE(CreateGuidVector)
DEFINE_VECTOR_CREATE(CreateAgileGuidVector)

struct object_vector_info
{
    HSTRING vector_class_name;
    HSTRING vector_view_class_name;
    HSTRING iterator_class_name;
    IID object_iid;
    IID vector_iid;
    IID vector_view_iid;
    IID iterable_iid;
    IID iterator_iid;
};

struct object_vector_iface;
struct object_vector_view_iface;
struct object_iterable_iface;
struct object_iterator_iface;

struct object_vector_vtbl
{
    HRESULT (WINAPI *QueryInterface)(struct object_vector_iface *, REFIID, void **);
    ULONG (WINAPI *AddRef)(struct object_vector_iface *);
    ULONG (WINAPI *Release)(struct object_vector_iface *);
    HRESULT (WINAPI *GetIids)(struct object_vector_iface *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(struct object_vector_iface *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(struct object_vector_iface *, TrustLevel *);
    HRESULT (WINAPI *GetAt)(struct object_vector_iface *, UINT32, IInspectable **);
    HRESULT (WINAPI *get_Size)(struct object_vector_iface *, UINT32 *);
    HRESULT (WINAPI *GetView)(struct object_vector_iface *, struct object_vector_view_iface **);
    HRESULT (WINAPI *IndexOf)(struct object_vector_iface *, IInspectable *, UINT32 *, BYTE *);
    HRESULT (WINAPI *SetAt)(struct object_vector_iface *, UINT32, IInspectable *);
    HRESULT (WINAPI *InsertAt)(struct object_vector_iface *, UINT32, IInspectable *);
    HRESULT (WINAPI *RemoveAt)(struct object_vector_iface *, UINT32);
    HRESULT (WINAPI *Append)(struct object_vector_iface *, IInspectable *);
    HRESULT (WINAPI *RemoveAtEnd)(struct object_vector_iface *);
    HRESULT (WINAPI *Clear)(struct object_vector_iface *);
    HRESULT (WINAPI *GetMany)(struct object_vector_iface *, UINT32, UINT32, IInspectable **, UINT32 *);
    HRESULT (WINAPI *ReplaceAll)(struct object_vector_iface *, UINT32, IInspectable **);
};

struct object_vector_view_vtbl
{
    HRESULT (WINAPI *QueryInterface)(struct object_vector_view_iface *, REFIID, void **);
    ULONG (WINAPI *AddRef)(struct object_vector_view_iface *);
    ULONG (WINAPI *Release)(struct object_vector_view_iface *);
    HRESULT (WINAPI *GetIids)(struct object_vector_view_iface *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(struct object_vector_view_iface *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(struct object_vector_view_iface *, TrustLevel *);
    HRESULT (WINAPI *GetAt)(struct object_vector_view_iface *, UINT32, IInspectable **);
    HRESULT (WINAPI *get_Size)(struct object_vector_view_iface *, UINT32 *);
    HRESULT (WINAPI *IndexOf)(struct object_vector_view_iface *, IInspectable *, UINT32 *, BYTE *);
    HRESULT (WINAPI *GetMany)(struct object_vector_view_iface *, UINT32, UINT32, IInspectable **, UINT32 *);
};

struct object_iterable_vtbl
{
    HRESULT (WINAPI *QueryInterface)(struct object_iterable_iface *, REFIID, void **);
    ULONG (WINAPI *AddRef)(struct object_iterable_iface *);
    ULONG (WINAPI *Release)(struct object_iterable_iface *);
    HRESULT (WINAPI *GetIids)(struct object_iterable_iface *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(struct object_iterable_iface *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(struct object_iterable_iface *, TrustLevel *);
    HRESULT (WINAPI *First)(struct object_iterable_iface *, struct object_iterator_iface **);
};

struct object_iterator_vtbl
{
    HRESULT (WINAPI *QueryInterface)(struct object_iterator_iface *, REFIID, void **);
    ULONG (WINAPI *AddRef)(struct object_iterator_iface *);
    ULONG (WINAPI *Release)(struct object_iterator_iface *);
    HRESULT (WINAPI *GetIids)(struct object_iterator_iface *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(struct object_iterator_iface *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(struct object_iterator_iface *, TrustLevel *);
    HRESULT (WINAPI *get_Current)(struct object_iterator_iface *, IInspectable **);
    HRESULT (WINAPI *get_HasCurrent)(struct object_iterator_iface *, BYTE *);
    HRESULT (WINAPI *MoveNext)(struct object_iterator_iface *, BYTE *);
    HRESULT (WINAPI *GetMany)(struct object_iterator_iface *, UINT32, IInspectable **, UINT32 *);
};

struct object_vector_iface { const struct object_vector_vtbl *lpVtbl; };
struct object_vector_view_iface { const struct object_vector_view_vtbl *lpVtbl; };
struct object_iterable_iface { const struct object_iterable_vtbl *lpVtbl; };
struct object_iterator_iface { const struct object_iterator_vtbl *lpVtbl; };

struct object_vector
{
    struct object_vector_iface vector_iface;
    struct object_vector_view_iface view_iface;
    struct object_iterable_iface iterable_iface;
    LONG ref;
    BOOL agile;
    struct object_vector_info info;
    IInspectable **items;
    UINT32 size;
    UINT32 capacity;
};

struct object_iterator
{
    struct object_iterator_iface iface;
    LONG ref;
    struct object_vector *vector;
    UINT32 index;
};

static const struct object_vector_vtbl object_vector_vtbl;
static const struct object_vector_view_vtbl object_vector_view_vtbl;
static const struct object_iterable_vtbl object_iterable_vtbl;
static const struct object_iterator_vtbl object_iterator_vtbl;

static inline struct object_vector *impl_from_object_vector(struct object_vector_iface *iface)
{
    return CONTAINING_RECORD(iface, struct object_vector, vector_iface);
}

static inline struct object_vector *impl_from_object_vector_view(struct object_vector_view_iface *iface)
{
    return CONTAINING_RECORD(iface, struct object_vector, view_iface);
}

static inline struct object_vector *impl_from_object_iterable(struct object_iterable_iface *iface)
{
    return CONTAINING_RECORD(iface, struct object_vector, iterable_iface);
}

static inline struct object_iterator *impl_from_object_iterator(struct object_iterator_iface *iface)
{
    return CONTAINING_RECORD(iface, struct object_iterator, iface);
}

static ULONG object_vector_addref(struct object_vector *impl)
{
    return InterlockedIncrement(&impl->ref);
}

static ULONG object_vector_release(struct object_vector *impl)
{
    ULONG ref = InterlockedDecrement(&impl->ref);
    UINT32 i;

    if (!ref)
    {
        for (i = 0; i < impl->size; ++i)
            if (impl->items[i]) IInspectable_Release(impl->items[i]);
        free(impl->items);
        WindowsDeleteString(impl->info.vector_class_name);
        WindowsDeleteString(impl->info.vector_view_class_name);
        WindowsDeleteString(impl->info.iterator_class_name);
        free(impl);
    }
    return ref;
}

static HRESULT object_vector_query_interface(struct object_vector *impl, REFIID iid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &impl->info.vector_iid))
        *out = &impl->vector_iface;
    else if (IsEqualGUID(iid, &impl->info.vector_view_iid))
        *out = &impl->view_iface;
    else if (IsEqualGUID(iid, &impl->info.iterable_iid))
        *out = &impl->iterable_iface;
    else if (impl->agile && IsEqualGUID(iid, &IID_IAgileObject))
        *out = &impl->vector_iface;
    else
        return E_NOINTERFACE;
    object_vector_addref(impl);
    return S_OK;
}

static HRESULT object_vector_get_iids(struct object_vector *impl, ULONG *count, IID **iids)
{
    if (!count || !iids) return E_POINTER;
    if (!(*iids = CoTaskMemAlloc(3 * sizeof(**iids)))) return E_OUTOFMEMORY;
    (*iids)[0] = impl->info.vector_iid;
    (*iids)[1] = impl->info.vector_view_iid;
    (*iids)[2] = impl->info.iterable_iid;
    *count = 3;
    return S_OK;
}

static HRESULT object_vector_get_name(HSTRING source, HSTRING *name)
{
    if (!name) return E_POINTER;
    return WindowsDuplicateString(source, name);
}

static HRESULT object_vector_get_trust(TrustLevel *trust)
{
    if (!trust) return E_POINTER;
    *trust = BaseTrust;
    return S_OK;
}

static HRESULT object_vector_reserve(struct object_vector *impl, UINT32 capacity)
{
    IInspectable **items;
    UINT32 new_capacity;
    SIZE_T bytes;

    if (capacity <= impl->capacity) return S_OK;
    new_capacity = impl->capacity ? impl->capacity * 2 : 8;
    if (new_capacity < capacity) new_capacity = capacity;
    bytes = (SIZE_T)new_capacity * sizeof(*items);
    if (new_capacity < impl->capacity || (new_capacity && bytes / new_capacity != sizeof(*items)))
        return E_OUTOFMEMORY;
    if (!(items = realloc(impl->items, bytes))) return E_OUTOFMEMORY;
    impl->items = items;
    impl->capacity = new_capacity;
    return S_OK;
}

static HRESULT object_vector_get_at(struct object_vector *impl, UINT32 index, IInspectable **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (index >= impl->size) return E_BOUNDS;
    *out = impl->items[index];
    if (*out) IInspectable_AddRef(*out);
    return S_OK;
}

static HRESULT object_vector_index_of(struct object_vector *impl, IInspectable *value,
                                      UINT32 *index, BYTE *found)
{
    UINT32 i;
    if (!index || !found) return E_POINTER;
    *index = 0;
    *found = FALSE;
    for (i = 0; i < impl->size; ++i)
    {
        if (impl->items[i] != value) continue;
        *index = i;
        *found = TRUE;
        break;
    }
    return S_OK;
}

static HRESULT object_vector_get_many(struct object_vector *impl, UINT32 start, UINT32 capacity,
                                      IInspectable **items, UINT32 *actual)
{
    UINT32 i, count;
    if (!actual || (capacity && !items)) return E_POINTER;
    *actual = 0;
    if (start > impl->size) return E_BOUNDS;
    count = min(capacity, impl->size - start);
    for (i = 0; i < count; ++i)
    {
        items[i] = impl->items[start + i];
        if (items[i]) IInspectable_AddRef(items[i]);
    }
    for (; i < capacity; ++i) items[i] = NULL;
    *actual = count;
    return S_OK;
}

static HRESULT WINAPI object_vector_QueryInterface(struct object_vector_iface *iface, REFIID iid, void **out)
{
    return object_vector_query_interface(impl_from_object_vector(iface), iid, out);
}

static ULONG WINAPI object_vector_AddRef(struct object_vector_iface *iface)
{
    return object_vector_addref(impl_from_object_vector(iface));
}

static ULONG WINAPI object_vector_Release(struct object_vector_iface *iface)
{
    return object_vector_release(impl_from_object_vector(iface));
}

static HRESULT WINAPI object_vector_GetIids(struct object_vector_iface *iface, ULONG *count, IID **iids)
{
    return object_vector_get_iids(impl_from_object_vector(iface), count, iids);
}

static HRESULT WINAPI object_vector_GetRuntimeClassName(struct object_vector_iface *iface, HSTRING *name)
{
    return object_vector_get_name(impl_from_object_vector(iface)->info.vector_class_name, name);
}

static HRESULT WINAPI object_vector_GetTrustLevel(struct object_vector_iface *iface, TrustLevel *trust)
{
    return object_vector_get_trust(trust);
}

static HRESULT WINAPI object_vector_GetAt(struct object_vector_iface *iface, UINT32 index, IInspectable **out)
{
    return object_vector_get_at(impl_from_object_vector(iface), index, out);
}

static HRESULT WINAPI object_vector_get_Size(struct object_vector_iface *iface, UINT32 *size)
{
    if (!size) return E_POINTER;
    *size = impl_from_object_vector(iface)->size;
    return S_OK;
}

static HRESULT WINAPI object_vector_GetView(struct object_vector_iface *iface,
                                            struct object_vector_view_iface **out)
{
    struct object_vector *impl = impl_from_object_vector(iface);
    if (!out) return E_POINTER;
    *out = &impl->view_iface;
    object_vector_addref(impl);
    return S_OK;
}

static HRESULT WINAPI object_vector_IndexOf(struct object_vector_iface *iface, IInspectable *value,
                                            UINT32 *index, BYTE *found)
{
    return object_vector_index_of(impl_from_object_vector(iface), value, index, found);
}

static HRESULT WINAPI object_vector_SetAt(struct object_vector_iface *iface, UINT32 index,
                                          IInspectable *value)
{
    struct object_vector *impl = impl_from_object_vector(iface);
    IInspectable *old;
    if (index >= impl->size) return E_BOUNDS;
    if (value) IInspectable_AddRef(value);
    old = impl->items[index];
    impl->items[index] = value;
    if (old) IInspectable_Release(old);
    return S_OK;
}

static HRESULT WINAPI object_vector_InsertAt(struct object_vector_iface *iface, UINT32 index,
                                             IInspectable *value)
{
    struct object_vector *impl = impl_from_object_vector(iface);
    HRESULT hr;
    if (index > impl->size) return E_BOUNDS;
    if (FAILED(hr = object_vector_reserve(impl, impl->size + 1))) return hr;
    memmove(impl->items + index + 1, impl->items + index,
            (impl->size - index) * sizeof(*impl->items));
    if (value) IInspectable_AddRef(value);
    impl->items[index] = value;
    ++impl->size;
    return S_OK;
}

static HRESULT WINAPI object_vector_RemoveAt(struct object_vector_iface *iface, UINT32 index)
{
    struct object_vector *impl = impl_from_object_vector(iface);
    IInspectable *old;
    if (index >= impl->size) return E_BOUNDS;
    old = impl->items[index];
    memmove(impl->items + index, impl->items + index + 1,
            (impl->size - index - 1) * sizeof(*impl->items));
    --impl->size;
    if (old) IInspectable_Release(old);
    return S_OK;
}

static HRESULT WINAPI object_vector_Append(struct object_vector_iface *iface, IInspectable *value)
{
    struct object_vector *impl = impl_from_object_vector(iface);
    HRESULT hr;
    if (FAILED(hr = object_vector_reserve(impl, impl->size + 1))) return hr;
    if (value) IInspectable_AddRef(value);
    impl->items[impl->size++] = value;
    return S_OK;
}

static HRESULT WINAPI object_vector_RemoveAtEnd(struct object_vector_iface *iface)
{
    struct object_vector *impl = impl_from_object_vector(iface);
    IInspectable *old;
    if (!impl->size) return E_BOUNDS;
    old = impl->items[--impl->size];
    if (old) IInspectable_Release(old);
    return S_OK;
}

static HRESULT WINAPI object_vector_Clear(struct object_vector_iface *iface)
{
    struct object_vector *impl = impl_from_object_vector(iface);
    UINT32 i;
    for (i = 0; i < impl->size; ++i)
        if (impl->items[i]) IInspectable_Release(impl->items[i]);
    impl->size = 0;
    return S_OK;
}

static HRESULT WINAPI object_vector_GetMany(struct object_vector_iface *iface, UINT32 start,
                                            UINT32 capacity, IInspectable **items, UINT32 *actual)
{
    return object_vector_get_many(impl_from_object_vector(iface), start, capacity, items, actual);
}

static HRESULT WINAPI object_vector_ReplaceAll(struct object_vector_iface *iface, UINT32 count,
                                               IInspectable **items)
{
    struct object_vector *impl = impl_from_object_vector(iface);
    UINT32 i;
    HRESULT hr;
    if (count && !items) return E_POINTER;
    if (FAILED(hr = object_vector_reserve(impl, count))) return hr;
    object_vector_Clear(iface);
    for (i = 0; i < count; ++i)
    {
        impl->items[i] = items[i];
        if (items[i]) IInspectable_AddRef(items[i]);
    }
    impl->size = count;
    return S_OK;
}

static HRESULT WINAPI object_vector_view_QueryInterface(struct object_vector_view_iface *iface,
                                                         REFIID iid, void **out)
{
    return object_vector_query_interface(impl_from_object_vector_view(iface), iid, out);
}

static ULONG WINAPI object_vector_view_AddRef(struct object_vector_view_iface *iface)
{
    return object_vector_addref(impl_from_object_vector_view(iface));
}

static ULONG WINAPI object_vector_view_Release(struct object_vector_view_iface *iface)
{
    return object_vector_release(impl_from_object_vector_view(iface));
}

static HRESULT WINAPI object_vector_view_GetIids(struct object_vector_view_iface *iface,
                                                 ULONG *count, IID **iids)
{
    return object_vector_get_iids(impl_from_object_vector_view(iface), count, iids);
}

static HRESULT WINAPI object_vector_view_GetRuntimeClassName(struct object_vector_view_iface *iface,
                                                             HSTRING *name)
{
    return object_vector_get_name(impl_from_object_vector_view(iface)->info.vector_view_class_name, name);
}

static HRESULT WINAPI object_vector_view_GetTrustLevel(struct object_vector_view_iface *iface,
                                                       TrustLevel *trust)
{
    return object_vector_get_trust(trust);
}

static HRESULT WINAPI object_vector_view_GetAt(struct object_vector_view_iface *iface, UINT32 index,
                                               IInspectable **out)
{
    return object_vector_get_at(impl_from_object_vector_view(iface), index, out);
}

static HRESULT WINAPI object_vector_view_get_Size(struct object_vector_view_iface *iface, UINT32 *size)
{
    if (!size) return E_POINTER;
    *size = impl_from_object_vector_view(iface)->size;
    return S_OK;
}

static HRESULT WINAPI object_vector_view_IndexOf(struct object_vector_view_iface *iface,
                                                 IInspectable *value, UINT32 *index, BYTE *found)
{
    return object_vector_index_of(impl_from_object_vector_view(iface), value, index, found);
}

static HRESULT WINAPI object_vector_view_GetMany(struct object_vector_view_iface *iface, UINT32 start,
                                                 UINT32 capacity, IInspectable **items, UINT32 *actual)
{
    return object_vector_get_many(impl_from_object_vector_view(iface), start, capacity, items, actual);
}

static HRESULT WINAPI object_iterable_QueryInterface(struct object_iterable_iface *iface,
                                                      REFIID iid, void **out)
{
    return object_vector_query_interface(impl_from_object_iterable(iface), iid, out);
}

static ULONG WINAPI object_iterable_AddRef(struct object_iterable_iface *iface)
{
    return object_vector_addref(impl_from_object_iterable(iface));
}

static ULONG WINAPI object_iterable_Release(struct object_iterable_iface *iface)
{
    return object_vector_release(impl_from_object_iterable(iface));
}

static HRESULT WINAPI object_iterable_GetIids(struct object_iterable_iface *iface, ULONG *count, IID **iids)
{
    return object_vector_get_iids(impl_from_object_iterable(iface), count, iids);
}

static HRESULT WINAPI object_iterable_GetRuntimeClassName(struct object_iterable_iface *iface, HSTRING *name)
{
    return object_vector_get_name(impl_from_object_iterable(iface)->info.vector_class_name, name);
}

static HRESULT WINAPI object_iterable_GetTrustLevel(struct object_iterable_iface *iface, TrustLevel *trust)
{
    return object_vector_get_trust(trust);
}

static HRESULT WINAPI object_iterator_QueryInterface(struct object_iterator_iface *iface,
                                                      REFIID iid, void **out)
{
    struct object_iterator *impl = impl_from_object_iterator(iface);
    if (!out) return E_POINTER;
    *out = NULL;
    if (!IsEqualGUID(iid, &IID_IUnknown) && !IsEqualGUID(iid, &IID_IInspectable) &&
        !IsEqualGUID(iid, &impl->vector->info.iterator_iid) &&
        !(impl->vector->agile && IsEqualGUID(iid, &IID_IAgileObject)))
        return E_NOINTERFACE;
    *out = iface;
    InterlockedIncrement(&impl->ref);
    return S_OK;
}

static ULONG WINAPI object_iterator_AddRef(struct object_iterator_iface *iface)
{
    return InterlockedIncrement(&impl_from_object_iterator(iface)->ref);
}

static ULONG WINAPI object_iterator_Release(struct object_iterator_iface *iface)
{
    struct object_iterator *impl = impl_from_object_iterator(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);
    if (!ref)
    {
        object_vector_release(impl->vector);
        free(impl);
    }
    return ref;
}

static HRESULT WINAPI object_iterator_GetIids(struct object_iterator_iface *iface, ULONG *count, IID **iids)
{
    struct object_iterator *impl = impl_from_object_iterator(iface);
    if (!count || !iids) return E_POINTER;
    if (!(*iids = CoTaskMemAlloc(sizeof(**iids)))) return E_OUTOFMEMORY;
    **iids = impl->vector->info.iterator_iid;
    *count = 1;
    return S_OK;
}

static HRESULT WINAPI object_iterator_GetRuntimeClassName(struct object_iterator_iface *iface, HSTRING *name)
{
    return object_vector_get_name(impl_from_object_iterator(iface)->vector->info.iterator_class_name, name);
}

static HRESULT WINAPI object_iterator_GetTrustLevel(struct object_iterator_iface *iface, TrustLevel *trust)
{
    return object_vector_get_trust(trust);
}

static HRESULT WINAPI object_iterator_get_Current(struct object_iterator_iface *iface, IInspectable **out)
{
    struct object_iterator *impl = impl_from_object_iterator(iface);
    return object_vector_get_at(impl->vector, impl->index, out);
}

static HRESULT WINAPI object_iterator_get_HasCurrent(struct object_iterator_iface *iface, BYTE *current)
{
    struct object_iterator *impl = impl_from_object_iterator(iface);
    if (!current) return E_POINTER;
    *current = impl->index < impl->vector->size;
    return S_OK;
}

static HRESULT WINAPI object_iterator_MoveNext(struct object_iterator_iface *iface, BYTE *current)
{
    struct object_iterator *impl = impl_from_object_iterator(iface);
    if (!current) return E_POINTER;
    if (impl->index < impl->vector->size) ++impl->index;
    *current = impl->index < impl->vector->size;
    return S_OK;
}

static HRESULT WINAPI object_iterator_GetMany(struct object_iterator_iface *iface, UINT32 capacity,
                                              IInspectable **items, UINT32 *actual)
{
    struct object_iterator *impl = impl_from_object_iterator(iface);
    HRESULT hr = object_vector_get_many(impl->vector, impl->index, capacity, items, actual);
    if (SUCCEEDED(hr)) impl->index += *actual;
    return hr;
}

static HRESULT WINAPI object_iterable_First(struct object_iterable_iface *iface,
                                            struct object_iterator_iface **out)
{
    struct object_vector *vector = impl_from_object_iterable(iface);
    struct object_iterator *iterator;
    if (!out) return E_POINTER;
    *out = NULL;
    if (!(iterator = calloc(1, sizeof(*iterator)))) return E_OUTOFMEMORY;
    iterator->iface.lpVtbl = &object_iterator_vtbl;
    iterator->ref = 1;
    iterator->vector = vector;
    object_vector_addref(vector);
    *out = &iterator->iface;
    return S_OK;
}

static const struct object_vector_vtbl object_vector_vtbl =
{
    object_vector_QueryInterface, object_vector_AddRef, object_vector_Release,
    object_vector_GetIids, object_vector_GetRuntimeClassName, object_vector_GetTrustLevel,
    object_vector_GetAt, object_vector_get_Size, object_vector_GetView, object_vector_IndexOf,
    object_vector_SetAt, object_vector_InsertAt, object_vector_RemoveAt, object_vector_Append,
    object_vector_RemoveAtEnd, object_vector_Clear, object_vector_GetMany, object_vector_ReplaceAll,
};

static const struct object_vector_view_vtbl object_vector_view_vtbl =
{
    object_vector_view_QueryInterface, object_vector_view_AddRef, object_vector_view_Release,
    object_vector_view_GetIids, object_vector_view_GetRuntimeClassName, object_vector_view_GetTrustLevel,
    object_vector_view_GetAt, object_vector_view_get_Size, object_vector_view_IndexOf,
    object_vector_view_GetMany,
};

static const struct object_iterable_vtbl object_iterable_vtbl =
{
    object_iterable_QueryInterface, object_iterable_AddRef, object_iterable_Release,
    object_iterable_GetIids, object_iterable_GetRuntimeClassName, object_iterable_GetTrustLevel,
    object_iterable_First,
};

static const struct object_iterator_vtbl object_iterator_vtbl =
{
    object_iterator_QueryInterface, object_iterator_AddRef, object_iterator_Release,
    object_iterator_GetIids, object_iterator_GetRuntimeClassName, object_iterator_GetTrustLevel,
    object_iterator_get_Current, object_iterator_get_HasCurrent, object_iterator_MoveNext,
    object_iterator_GetMany,
};

static HRESULT create_object_vector(const struct object_vector_info *info, BOOL agile, IInspectable **out)
{
    struct object_vector *impl;
    HRESULT hr;

    if (!info || !out) return E_POINTER;
    *out = NULL;
    TRACE("vector %s, view %s, iterator %s; object %s, vector %s, view %s, iterable %s, iterator %s\n",
          debugstr_hstring(info->vector_class_name), debugstr_hstring(info->vector_view_class_name),
          debugstr_hstring(info->iterator_class_name), debugstr_guid(&info->object_iid),
          debugstr_guid(&info->vector_iid), debugstr_guid(&info->vector_view_iid),
          debugstr_guid(&info->iterable_iid), debugstr_guid(&info->iterator_iid));
    if (!(impl = calloc(1, sizeof(*impl)))) return E_OUTOFMEMORY;
    impl->vector_iface.lpVtbl = &object_vector_vtbl;
    impl->view_iface.lpVtbl = &object_vector_view_vtbl;
    impl->iterable_iface.lpVtbl = &object_iterable_vtbl;
    impl->ref = 1;
    impl->agile = agile;
    impl->info.object_iid = info->object_iid;
    impl->info.vector_iid = info->vector_iid;
    impl->info.vector_view_iid = info->vector_view_iid;
    impl->info.iterable_iid = info->iterable_iid;
    impl->info.iterator_iid = info->iterator_iid;
    if (FAILED(hr = WindowsDuplicateString(info->vector_class_name, &impl->info.vector_class_name)) ||
        FAILED(hr = WindowsDuplicateString(info->vector_view_class_name, &impl->info.vector_view_class_name)) ||
        FAILED(hr = WindowsDuplicateString(info->iterator_class_name, &impl->info.iterator_class_name)))
    {
        object_vector_release(impl);
        return hr;
    }
    *out = (IInspectable *)&impl->vector_iface;
    return S_OK;
}

static HRESULT WINAPI vector_statics_CreateObjectVector(struct vector_statics *iface,
                                                         const void *info, IInspectable **out)
{
    return create_object_vector(info, FALSE, out);
}

static HRESULT WINAPI vector_statics_CreateAgileObjectVector(struct vector_statics *iface,
                                                              const void *info, IInspectable **out)
{
    return create_object_vector(info, TRUE, out);
}

static const struct vector_statics_vtbl vector_statics_vtbl =
{
    vector_statics_QueryInterface,
    vector_statics_AddRef,
    vector_statics_Release,
    vector_statics_GetIids,
    vector_statics_GetRuntimeClassName,
    vector_statics_GetTrustLevel,
    vector_statics_CreateBooleanVector,
    vector_statics_CreateAgileBooleanVector,
    vector_statics_CreateUInt8Vector,
    vector_statics_CreateAgileUInt8Vector,
    vector_statics_CreateInt16Vector,
    vector_statics_CreateAgileInt16Vector,
    vector_statics_CreateUInt16Vector,
    vector_statics_CreateAgileUInt16Vector,
    vector_statics_CreateInt32Vector,
    vector_statics_CreateAgileInt32Vector,
    vector_statics_CreateUInt32Vector,
    vector_statics_CreateAgileUInt32Vector,
    vector_statics_CreateInt64Vector,
    vector_statics_CreateAgileInt64Vector,
    vector_statics_CreateUInt64Vector,
    vector_statics_CreateAgileUInt64Vector,
    vector_statics_CreateSingleVector,
    vector_statics_CreateAgileSingleVector,
    vector_statics_CreateDoubleVector,
    vector_statics_CreateAgileDoubleVector,
    vector_statics_CreateStringVector,
    vector_statics_CreateAgileStringVector,
    vector_statics_CreateGuidVector,
    vector_statics_CreateAgileGuidVector,
    vector_statics_CreateObjectVector,
    vector_statics_CreateAgileObjectVector,
};

static struct vector_statics vector_statics = {&vector_statics_vtbl};

struct activatable_class_data
{
    ULONG size;
    DWORD unk;
    DWORD module_len;
    DWORD module_offset;
    DWORD threading_model;
};

enum runtime_class_provider
{
    RUNTIME_CLASS_IN_PROCESS,
    RUNTIME_CLASS_OUT_OF_PROCESS,
};

struct runtime_class_registration
{
    enum runtime_class_provider provider;
    WCHAR *target;
};

static LONG query_registry_string(HKEY key, const WCHAR *name, WCHAR **out)
{
    DWORD type, size;
    WCHAR *value;
    LONG ret;

    *out = NULL;
    if ((ret = RegQueryValueExW(key, name, NULL, &type, NULL, &size))) return ret;
    if ((type != REG_SZ && type != REG_EXPAND_SZ) || size < sizeof(WCHAR)) return ERROR_DATATYPE_MISMATCH;
    if (!(value = malloc(size))) return ERROR_NOT_ENOUGH_MEMORY;
    if ((ret = RegQueryValueExW(key, name, NULL, &type, (BYTE *)value, &size)))
    {
        free(value);
        return ret;
    }
    value[size / sizeof(WCHAR) - 1] = 0;

    if (type == REG_EXPAND_SZ)
    {
        WCHAR *expanded;
        DWORD len = ExpandEnvironmentStringsW(value, NULL, 0);

        if (!len || !(expanded = malloc(len * sizeof(WCHAR))))
        {
            free(value);
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        ExpandEnvironmentStringsW(value, expanded, len);
        free(value);
        value = expanded;
    }

    *out = value;
    return ERROR_SUCCESS;
}

static HRESULT get_registration_for_classid(const WCHAR *classid, struct runtime_class_registration *registration)
{
    ACTCTX_SECTION_KEYED_DATA data;
    HKEY hkey_root, hkey_class;
    WCHAR *library = NULL, *server = NULL;
    LONG library_ret, server_ret;
    HRESULT hr;

    registration->target = NULL;

    /* search activation context first */
    data.cbSize = sizeof(data);
    if (FindActCtxSectionStringW(FIND_ACTCTX_SECTION_KEY_RETURN_HACTCTX, NULL,
            ACTIVATION_CONTEXT_SECTION_WINRT_ACTIVATABLE_CLASSES, classid, &data))
    {
        struct activatable_class_data *activatable_class = (struct activatable_class_data *)data.lpData;
        void *ptr = (BYTE *)data.lpSectionBase + activatable_class->module_offset;
        if (!(registration->target = wcsdup(ptr))) return E_OUTOFMEMORY;
        registration->provider = RUNTIME_CLASS_IN_PROCESS;
        return S_OK;
    }

    /* Resolve the package namespace before selecting a system registration.
     * Once a package owns the class, errors do not retry another provider. */
    if ((hr = package_get_class_path(classid, &registration->target)) != S_FALSE)
    {
        if (SUCCEEDED(hr)) registration->provider = RUNTIME_CLASS_IN_PROCESS;
        return hr;
    }

    /* load class registry key */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\WindowsRuntime\\ActivatableClassId",
                      0, KEY_READ, &hkey_root))
        return REGDB_E_READREGDB;
    if (RegOpenKeyExW(hkey_root, classid, 0, KEY_READ, &hkey_class))
    {
        WARN("Class %s not found in registry\n", debugstr_w(classid));
        RegCloseKey(hkey_root);
        return REGDB_E_CLASSNOTREG;
    }
    RegCloseKey(hkey_root);

    library_ret = query_registry_string(hkey_class, L"DllPath", &library);
    server_ret = query_registry_string(hkey_class, L"Server", &server);
    RegCloseKey(hkey_class);

    if (!library_ret && !server_ret)
    {
        ERR("Class %s declares both DllPath and Server providers\n", debugstr_w(classid));
        free(library);
        free(server);
        return REGDB_E_READREGDB;
    }
    if (!library_ret)
    {
        registration->provider = RUNTIME_CLASS_IN_PROCESS;
        registration->target = library;
        return S_OK;
    }
    if (!server_ret)
    {
        registration->provider = RUNTIME_CLASS_OUT_OF_PROCESS;
        registration->target = server;
        return S_OK;
    }
    return library_ret == ERROR_NOT_ENOUGH_MEMORY || server_ret == ERROR_NOT_ENOUGH_MEMORY
            ? E_OUTOFMEMORY : REGDB_E_READREGDB;
}

static HRESULT runtime_class_transport_clsid(const WCHAR *classid, CLSID *clsid)
{
    static const GUID namespace =
        {0x26d4f5a6, 0x9c71, 0x4fb8, {0x8c, 0xb1, 0x18, 0xaf, 0xb4, 0x99, 0x57, 0x0a}};
    BYTE digest[20], *input;
    SIZE_T class_size, input_size;
    NTSTATUS status;

    class_size = wcslen(classid) * sizeof(WCHAR);
    if (class_size > ~(ULONG)0 - sizeof(namespace)) return E_INVALIDARG;
    input_size = sizeof(namespace) + class_size;
    if (!(input = malloc(input_size))) return E_OUTOFMEMORY;

    memcpy(input, &namespace, sizeof(namespace));
    memcpy(input + sizeof(namespace), classid, class_size);
    status = BCryptHash(BCRYPT_SHA1_ALG_HANDLE, NULL, 0, input, input_size, digest, sizeof(digest));
    free(input);
    if (status) return HRESULT_FROM_NT(status);

    memcpy(clsid, digest, sizeof(*clsid));
    clsid->Data3 = (clsid->Data3 & 0x0fff) | 0x5000;
    clsid->Data4[0] = (clsid->Data4[0] & 0x3f) | 0x80;
    return S_OK;
}

static HRESULT start_runtime_service(const WCHAR *server_name)
{
    static const WCHAR server_root[] = L"Software\\Microsoft\\WindowsRuntime\\Server\\";
    SC_HANDLE manager = NULL, service = NULL;
    WCHAR *key_name = NULL, *service_name = NULL;
    HKEY key;
    HRESULT hr = S_OK;
    LONG ret;

    if (!(key_name = malloc((wcslen(server_root) + wcslen(server_name) + 1) * sizeof(WCHAR))))
        return E_OUTOFMEMORY;
    wcscpy(key_name, server_root);
    wcscat(key_name, server_name);

    if ((ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_name, 0, KEY_READ, &key)))
    {
        hr = HRESULT_FROM_WIN32(ret);
        goto done;
    }
    ret = query_registry_string(key, L"ServiceName", &service_name);
    RegCloseKey(key);
    if (ret == ERROR_FILE_NOT_FOUND)
        goto done; /* An executable server may already be running and registered. */
    if (ret)
    {
        hr = ret == ERROR_NOT_ENOUGH_MEMORY ? E_OUTOFMEMORY : HRESULT_FROM_WIN32(ret);
        goto done;
    }

    if (!(manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT)))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto done;
    }
    if (!(service = OpenServiceW(manager, service_name, SERVICE_START | SERVICE_QUERY_STATUS)))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto done;
    }
    if (!StartServiceW(service, 0, NULL))
    {
        DWORD error = GetLastError();

        /* The runtime factory registration is the readiness signal.  Some
         * Windows services do not complete Wine's SCM start handshake before
         * that handshake times out, but can still publish the requested
         * factory while we wait below. */
        if (error != ERROR_SERVICE_ALREADY_RUNNING && error != ERROR_SERVICE_REQUEST_TIMEOUT)
            hr = HRESULT_FROM_WIN32(error);
    }

done:
    if (service) CloseServiceHandle(service);
    if (manager) CloseServiceHandle(manager);
    free(service_name);
    free(key_name);
    return hr;
}

static HRESULT get_out_of_process_activation_factory(const WCHAR *classid, const WCHAR *server_name,
        REFIID iid, void **factory)
{
    CLSID clsid;
    HRESULT hr;

    if (FAILED(hr = runtime_class_transport_clsid(classid, &clsid))) return hr;
    if (FAILED(hr = start_runtime_service(server_name))) return hr;
    return rpc_get_registered_local_class_object(&clsid, iid, factory);
}


/***********************************************************************
 *      RoInitialize (combase.@)
 */
HRESULT WINAPI RoInitialize(RO_INIT_TYPE type)
{
    switch (type) {
    case RO_INIT_SINGLETHREADED:
        return CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    default:
        FIXME("type %d\n", type);
    case RO_INIT_MULTITHREADED:
        return CoInitializeEx(NULL, COINIT_MULTITHREADED);
    }
}

/***********************************************************************
 *      RoInitializeStrict (combase.179)
 *
 * Private Windows entry point used by the Immersive Shell. The selector
 * mapping and apartment qualifiers are covered by the LinuxNT Windows
 * oracle; selector 4's qualifier is not named by the public SDK.
 */
HRESULT WINAPI RoInitializeStrict(INT type)
{
    switch (type)
    {
    case 0:
        return CoInitializeEx(NULL, COINIT_INTERNAL_STRICT | COINIT_APARTMENTTHREADED |
                COINIT_DISABLE_OLE1DDE);
    case 1:
        return CoInitializeEx(NULL, COINIT_INTERNAL_STRICT | COINIT_INTERNAL_APPLICATION_STA |
                COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    case 2:
        return CoInitializeEx(NULL, COINIT_INTERNAL_STRICT | COINIT_MULTITHREADED);
    case 3:
        return CO_E_NOT_SUPPORTED;
    case 4:
        return CoInitializeEx(NULL, COINIT_INTERNAL_STRICT | COINIT_INTERNAL_QUALIFIER_7 |
                COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    default:
        return E_INVALIDARG;
    }
}

/***********************************************************************
 *      RoUninitialize (combase.@)
 */
void WINAPI RoUninitialize(void)
{
    CoUninitialize();
}

/***********************************************************************
 *      RoGetActivationFactory (combase.@)
 */
HRESULT WINAPI DECLSPEC_HOTPATCH RoGetActivationFactory(HSTRING classid, REFIID iid, void **class_factory)
{
    static const WCHAR vector_class[] = L"Windows.Foundation.Collections.Detail.Vector";
    static const WCHAR xaml_metadata_provider[] =
        L"Microsoft.UI.Xaml.XamlTypeInfo.XamlControlsXamlMetaDataProvider";
    PFNGETACTIVATIONFACTORY pDllGetActivationFactory;
    struct runtime_class_registration registration;
    IActivationFactory *factory;
    HMODULE module;
    HRESULT hr;

    FIXME("(%s, %s, %p): semi-stub\n", debugstr_hstring(classid), debugstr_guid(iid), class_factory);

    if (!iid || !class_factory)
        return E_INVALIDARG;

    if (FAILED(hr = ensure_mta()))
        return hr;

    if (!wcscmp(WindowsGetStringRawBuffer(classid, NULL), vector_class))
        return vector_statics_QueryInterface(&vector_statics, iid, class_factory);

    hr = get_registration_for_classid(WindowsGetStringRawBuffer(classid, NULL), &registration);
    if (FAILED(hr))
    {
        ERR("Failed to find provider for %s\n", debugstr_hstring(classid));
        return hr;
    }

    if (registration.provider == RUNTIME_CLASS_OUT_OF_PROCESS)
    {
        hr = get_out_of_process_activation_factory(WindowsGetStringRawBuffer(classid, NULL),
                registration.target, iid, class_factory);
        free(registration.target);
        return hr;
    }

    if (!(module = LoadLibraryW(registration.target)))
    {
        ERR("Failed to load module %s\n", debugstr_w(registration.target));
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto done;
    }

    if (!(pDllGetActivationFactory = (void *)GetProcAddress(module, "DllGetActivationFactory")))
    {
        ERR("Module %s does not implement DllGetActivationFactory\n", debugstr_w(registration.target));
        hr = E_FAIL;
        goto done;
    }

    TRACE("Found library %s for class %s\n", debugstr_w(registration.target), debugstr_hstring(classid));

    hr = pDllGetActivationFactory(classid, &factory);
    if (SUCCEEDED(hr))
    {
        hr = IActivationFactory_QueryInterface(factory, iid, class_factory);
        if (SUCCEEDED(hr))
        {
            if (IsEqualGUID(iid, &IID_IActivationFactory) &&
                !wcscmp(WindowsGetStringRawBuffer(classid, NULL), xaml_metadata_provider))
                *class_factory = linuxnt_wrap_xaml_metadata_factory(*class_factory);
            TRACE("Created interface %p\n", *class_factory);
            module = NULL;
        }
        IActivationFactory_Release(factory);
    }
    else
    {
        ERR("Class %s not found in %s, hr %#lx.\n", wine_dbgstr_hstring(classid),
                debugstr_w(registration.target), hr);
    }

done:
    free(registration.target);
    if (module) FreeLibrary(module);
    return hr;
}

/***********************************************************************
 *      RoGetParameterizedTypeInstanceIID (combase.@)
 */
HRESULT WINAPI RoGetParameterizedTypeInstanceIID(UINT32 name_element_count, const WCHAR **name_elements,
                                                 const IRoMetaDataLocator *meta_data_locator, GUID *iid,
                                                 ROPARAMIIDHANDLE *hiid)
{
    FIXME("stub: %d %p %p %p %p\n", name_element_count, name_elements, meta_data_locator, iid, hiid);
    if (iid) *iid = GUID_NULL;
    if (hiid) *hiid = INVALID_HANDLE_VALUE;
    return E_NOTIMPL;
}

/***********************************************************************
 *      RoActivateInstance (combase.@)
 */
HRESULT WINAPI RoActivateInstance(HSTRING classid, IInspectable **instance)
{
    IActivationFactory *factory;
    HRESULT hr;

    FIXME("(%p, %p): semi-stub\n", classid, instance);

    hr = RoGetActivationFactory(classid, &IID_IActivationFactory, (void **)&factory);
    if (SUCCEEDED(hr))
    {
        hr = IActivationFactory_ActivateInstance(factory, instance);
        IActivationFactory_Release(factory);
    }

    return hr;
}

struct agile_reference
{
    IAgileReference IAgileReference_iface;
    enum AgileReferenceOptions option;
    IStream *marshal_stream;
    CRITICAL_SECTION cs;
    IUnknown *obj;
    BOOLEAN is_agile;
    IUnknown *ctx;
    LONG ref;
};

static HRESULT marshal_object_in_agile_reference(struct agile_reference *ref, REFIID riid, IUnknown *obj)
{
    HRESULT hr;

    hr = CreateStreamOnHGlobal(0, TRUE, &ref->marshal_stream);
    if (FAILED(hr))
        return hr;

    hr = CoMarshalInterface(ref->marshal_stream, riid, obj, MSHCTX_INPROC, NULL, MSHLFLAGS_TABLESTRONG);
    if (FAILED(hr))
    {
        IStream_Release(ref->marshal_stream);
        ref->marshal_stream = NULL;
    }
    return hr;
}

static inline struct agile_reference *impl_from_IAgileReference(IAgileReference *iface)
{
    return CONTAINING_RECORD(iface, struct agile_reference, IAgileReference_iface);
}

static HRESULT WINAPI agile_ref_QueryInterface(IAgileReference *iface, REFIID riid, void **obj)
{
    TRACE("(%p, %s, %p)\n", iface, debugstr_guid(riid), obj);

    if (!riid || !obj) return E_INVALIDARG;

    if (IsEqualGUID(riid, &IID_IUnknown)
        || IsEqualGUID(riid, &IID_IAgileObject)
        || IsEqualGUID(riid, &IID_IAgileReference))
    {
        IUnknown_AddRef(iface);
        *obj = iface;
        return S_OK;
    }

    *obj = NULL;
    FIXME("interface %s is not implemented\n", debugstr_guid(riid));
    return E_NOINTERFACE;
}

static ULONG WINAPI agile_ref_AddRef(IAgileReference *iface)
{
    struct agile_reference *impl = impl_from_IAgileReference(iface);
    return InterlockedIncrement(&impl->ref);
}

static ULONG WINAPI agile_ref_Release(IAgileReference *iface)
{
    struct agile_reference *impl = impl_from_IAgileReference(iface);
    LONG ref = InterlockedDecrement(&impl->ref);

    if (!ref)
    {
        TRACE("destroying %p\n", iface);

        if (impl->obj)
            IUnknown_Release(impl->obj);

        if (impl->marshal_stream)
        {
            LARGE_INTEGER zero = {0};

            IStream_Seek(impl->marshal_stream, zero, STREAM_SEEK_SET, NULL);
            CoReleaseMarshalData(impl->marshal_stream);
            IStream_Release(impl->marshal_stream);
        }
        DeleteCriticalSection(&impl->cs);
        free(impl);
    }

    return ref;
}

struct marshal_context_params
{
    struct agile_reference *impl;
    REFIID iid;
};

static HRESULT WINAPI marshal_object_in_context(ComCallData *arg)
{
    struct marshal_context_params *params = (struct marshal_context_params *)arg;
    HRESULT hr;

    hr = marshal_object_in_agile_reference(params->impl, params->iid, params->impl->obj);
    IUnknown_Release(params->impl->obj);
    params->impl->obj = NULL;
    return hr;
}

static HRESULT WINAPI agile_ref_Resolve(IAgileReference *iface, REFIID riid, void **obj)
{
    struct agile_reference *impl = impl_from_IAgileReference(iface);
    LARGE_INTEGER zero = {0};
    void *cur_ctx;
    HRESULT hr;

    TRACE("(%p, %s, %p)\n", iface, debugstr_guid(riid), obj);

    if (impl->is_agile)
        return IUnknown_QueryInterface(impl->obj, riid, obj);

    if (FAILED(hr = CoGetContextToken((ULONG_PTR *)&cur_ctx)))
        return hr;

    EnterCriticalSection(&impl->cs);
    if (impl->option == AGILEREFERENCE_DELAYEDMARSHAL && impl->marshal_stream == NULL)
    {
        struct marshal_context_params params = { impl, riid };
        IContextCallback *ctx;

        if (FAILED(hr = IUnknown_QueryInterface(impl->ctx, &IID_IContextCallback, (void **)&ctx)))
        {
            LeaveCriticalSection(&impl->cs);
            return hr;
        }

        hr = IContextCallback_ContextCallback(ctx, marshal_object_in_context, (ComCallData *)&params,
                                              &IID_IContextCallback, 5, NULL);
        IContextCallback_Release(ctx);
        if (FAILED(hr))
        {
            LeaveCriticalSection(&impl->cs);
            return hr;
        }
    }

    if (SUCCEEDED(hr = IStream_Seek(impl->marshal_stream, zero, STREAM_SEEK_SET, NULL)))
        hr = CoUnmarshalInterface(impl->marshal_stream, riid, obj);

    LeaveCriticalSection(&impl->cs);
    return hr;
}

static const IAgileReferenceVtbl agile_ref_vtbl =
{
    agile_ref_QueryInterface,
    agile_ref_AddRef,
    agile_ref_Release,
    agile_ref_Resolve,
};

static BOOL object_has_interface(IUnknown *obj, REFIID iid)
{
    IUnknown *unk;
    HRESULT hr;

    hr = IUnknown_QueryInterface(obj, iid, (void **)&unk);
    if (SUCCEEDED(hr))
        IUnknown_Release(unk);
    return SUCCEEDED(hr);
}

/***********************************************************************
 *      RoGetAgileReference (combase.@)
 */
HRESULT WINAPI RoGetAgileReference(enum AgileReferenceOptions option, REFIID riid, IUnknown *obj,
                                   IAgileReference **agile_reference)
{
    struct apartment *apt;
    struct agile_reference *impl;
    HRESULT hr;

    TRACE("(%d, %s, %p, %p).\n", option, debugstr_guid(riid), obj, agile_reference);

    if (option != AGILEREFERENCE_DEFAULT && option != AGILEREFERENCE_DELAYEDMARSHAL)
        return E_INVALIDARG;

    if (!(apt = apartment_get_current_or_mta()))
    {
        ERR("Apartment not initialized\n");
        return CO_E_NOTINITIALIZED;
    }
    rpc_start_remoting(apt);
    apartment_release(apt);

    if (!object_has_interface(obj, riid))
        return E_NOINTERFACE;
    if (object_has_interface(obj, &IID_INoMarshal))
        return CO_E_NOT_SUPPORTED;

    impl = calloc(1, sizeof(*impl));
    if (!impl)
        return E_OUTOFMEMORY;

    impl->IAgileReference_iface.lpVtbl = &agile_ref_vtbl;
    impl->option = option;
    impl->is_agile = object_has_interface(obj, &IID_IAgileObject);
    impl->ref = 1;
    if (FAILED(hr = CoGetContextToken((ULONG_PTR *)&impl->ctx)))
    {
        free( impl );
        return hr;
    }

    if (option == AGILEREFERENCE_DELAYEDMARSHAL || impl->is_agile)
    {
        impl->obj = obj;
        IUnknown_AddRef(impl->obj);
    }
    else if (option == AGILEREFERENCE_DEFAULT)
    {
        if (FAILED(hr = marshal_object_in_agile_reference(impl, riid, obj)))
        {
            free(impl);
            return hr;
        }
    }

    InitializeCriticalSection(&impl->cs);

    *agile_reference = &impl->IAgileReference_iface;
    return S_OK;
}

/***********************************************************************
 *      RoFailFastWithErrorContextInternal2 (combase.@)
 */
void WINAPI RoFailFastWithErrorContextInternal2(HRESULT error, ULONG exception_count, /* PSTOWED_EXCEPTION_INFORMATION_V2 */void *information)
{
    void *frames[32], *module;
    WCHAR module_name[MAX_PATH];
    USHORT frame_count, i;

    FIXME("%#lx, %lu, %p stub.\n", error, exception_count, information);
    frame_count = RtlCaptureStackBackTrace(1, ARRAY_SIZE(frames), frames, NULL);
    for (i = 0; i < frame_count; ++i)
    {
        module = NULL;
        RtlPcToFileHeader(frames[i], &module);
        module_name[0] = 0;
        if (module) GetModuleFileNameW(module, module_name, ARRAY_SIZE(module_name));
        ERR("LinuxNT failfast %#lx frame %u pc %p module %p rva %Ix name %s\n", error, i,
            frames[i], module, module ? (SIZE_T)frames[i] - (SIZE_T)module : 0,
            debugstr_w(module_name));
    }
    RaiseFailFastException(NULL, NULL, 0);
}

/***********************************************************************
 *      RoGetApartmentIdentifier (combase.@)
 */
HRESULT WINAPI RoGetApartmentIdentifier(UINT64 *identifier)
{
    struct apartment *apt;

    if (!identifier)
        return E_INVALIDARG;

    if (!(apt = apartment_get_current_or_mta()))
        return CO_E_NOTINITIALIZED;

    *identifier = apartment_getoxid(apt);
    apartment_release(apt);

    TRACE("(%p): %s\n", identifier, wine_dbgstr_longlong(*identifier));
    return S_OK;
}

/***********************************************************************
 *      RoRegisterForApartmentShutdown (combase.@)
 */
HRESULT WINAPI RoRegisterForApartmentShutdown(IApartmentShutdown *callback,
        UINT64 *identifier, APARTMENT_SHUTDOWN_REGISTRATION_COOKIE *cookie)
{
    HRESULT hr;

    FIXME("(%p, %p, %p): stub\n", callback, identifier, cookie);

    hr = RoGetApartmentIdentifier(identifier);
    if (FAILED(hr))
        return hr;

    if (cookie)
        *cookie = (void *)0xcafecafe;
    return S_OK;
}

/***********************************************************************
 *      RoGetServerActivatableClasses (combase.@)
 */
HRESULT WINAPI RoGetServerActivatableClasses(HSTRING name, HSTRING **classes, DWORD *count)
{
    FIXME("(%p, %p, %p): stub\n", name, classes, count);

    if (count)
        *count = 0;
    return S_OK;
}

/***********************************************************************
 *      RoRegisterActivationFactories (combase.@)
 */
struct activation_factory_bridge
{
    IUnknown IUnknown_iface;
    LONG refcount;
    HSTRING classid;
    PFNGETACTIVATIONFACTORY callback;
    DWORD class_cookie;
};

struct activation_registration
{
    UINT32 count;
    struct activation_factory_bridge *bridges[1];
};

static inline struct activation_factory_bridge *impl_from_activation_bridge(IUnknown *iface)
{
    return CONTAINING_RECORD(iface, struct activation_factory_bridge, IUnknown_iface);
}

static HRESULT WINAPI activation_bridge_QueryInterface(IUnknown *iface, REFIID iid, void **out)
{
    struct activation_factory_bridge *bridge = impl_from_activation_bridge(iface);
    IActivationFactory *factory = NULL;
    HRESULT hr;

    if (!out) return E_POINTER;
    *out = NULL;
    if (!iid) return E_INVALIDARG;

    hr = bridge->callback(bridge->classid, &factory);
    if (FAILED(hr)) return hr;
    if (!factory) return E_UNEXPECTED;
    hr = IActivationFactory_QueryInterface(factory, iid, out);
    IActivationFactory_Release(factory);
    return hr;
}

static ULONG WINAPI activation_bridge_AddRef(IUnknown *iface)
{
    struct activation_factory_bridge *bridge = impl_from_activation_bridge(iface);
    return InterlockedIncrement(&bridge->refcount);
}

static ULONG WINAPI activation_bridge_Release(IUnknown *iface)
{
    struct activation_factory_bridge *bridge = impl_from_activation_bridge(iface);
    ULONG refcount = InterlockedDecrement(&bridge->refcount);

    if (!refcount)
    {
        WindowsDeleteString(bridge->classid);
        free(bridge);
    }
    return refcount;
}

static const IUnknownVtbl activation_bridge_vtbl =
{
    activation_bridge_QueryInterface,
    activation_bridge_AddRef,
    activation_bridge_Release,
};

static void revoke_activation_registration(struct activation_registration *registration)
{
    UINT32 i;

    for (i = 0; i < registration->count; ++i)
    {
        struct activation_factory_bridge *bridge = registration->bridges[i];
        if (bridge->class_cookie) CoRevokeClassObject(bridge->class_cookie);
        IUnknown_Release(&bridge->IUnknown_iface);
    }
    free(registration);
}

HRESULT WINAPI RoRegisterActivationFactories(HSTRING *classes, PFNGETACTIVATIONFACTORY *callbacks,
                                             UINT32 count, RO_REGISTRATION_COOKIE *cookie)
{
    struct runtime_class_registration class_registration;
    struct activation_registration *registration;
    struct activation_factory_bridge *bridge;
    SIZE_T registration_size;
    CLSID clsid;
    HRESULT hr;
    UINT32 i;

    TRACE("(%p, %p, %d, %p)\n", classes, callbacks, count, cookie);

    if (!cookie) return E_POINTER;
    *cookie = NULL;
    if (!classes || !callbacks || !count) return E_INVALIDARG;
    registration_size = offsetof(struct activation_registration, bridges) +
            (SIZE_T)count * sizeof(*registration->bridges);
    if (registration_size < offsetof(struct activation_registration, bridges) ||
            (registration_size - offsetof(struct activation_registration, bridges)) /
            sizeof(*registration->bridges) != count)
        return E_OUTOFMEMORY;
    if (!(registration = calloc(1, registration_size)))
        return E_OUTOFMEMORY;

    for (i = 0; i < count; ++i)
    {
        if (!classes[i] || !callbacks[i])
        {
            hr = E_INVALIDARG;
            goto failed;
        }
        if (FAILED(hr = get_registration_for_classid(WindowsGetStringRawBuffer(classes[i], NULL),
                &class_registration)))
            goto failed;
        if (class_registration.provider != RUNTIME_CLASS_OUT_OF_PROCESS)
        {
            free(class_registration.target);
            hr = REGDB_E_CLASSNOTREG;
            goto failed;
        }
        free(class_registration.target);

        if (!(bridge = calloc(1, sizeof(*bridge))))
        {
            hr = E_OUTOFMEMORY;
            goto failed;
        }
        bridge->IUnknown_iface.lpVtbl = &activation_bridge_vtbl;
        bridge->refcount = 1;
        bridge->callback = callbacks[i];
        if (FAILED(hr = WindowsDuplicateString(classes[i], &bridge->classid)) ||
                FAILED(hr = runtime_class_transport_clsid(WindowsGetStringRawBuffer(classes[i], NULL), &clsid)))
        {
            IUnknown_Release(&bridge->IUnknown_iface);
            goto failed;
        }
        hr = CoRegisterClassObject(&clsid, &bridge->IUnknown_iface, CLSCTX_LOCAL_SERVER,
                REGCLS_MULTIPLEUSE, &bridge->class_cookie);
        if (SUCCEEDED(hr) && !bridge->class_cookie) hr = CO_E_ALREADYINITIALIZED;
        if (FAILED(hr))
        {
            IUnknown_Release(&bridge->IUnknown_iface);
            goto failed;
        }
        registration->bridges[registration->count++] = bridge;
    }

    *cookie = (RO_REGISTRATION_COOKIE)registration;
    return S_OK;

failed:
    revoke_activation_registration(registration);
    return hr;
}

/***********************************************************************
 *      RoRevokeActivationFactories (combase.@)
 */
void WINAPI RoRevokeActivationFactories(RO_REGISTRATION_COOKIE cookie)
{
    TRACE("(%p)\n", cookie);
    if (cookie) revoke_activation_registration((struct activation_registration *)cookie);
}

struct restricted_error_info
{
    IRestrictedErrorInfo IRestrictedErrorInfo_iface;
    IErrorInfo IErrorInfo_iface;
    BSTR description;
    BSTR restricted_description;
    HRESULT code;
    LONG ref;
};

static inline struct restricted_error_info *impl_from_IRestrictedErrorInfo(IRestrictedErrorInfo *iface)
{
    return CONTAINING_RECORD(iface, struct restricted_error_info, IRestrictedErrorInfo_iface);
}

static HRESULT WINAPI restricted_error_info_QueryInterface(IRestrictedErrorInfo *iface, REFIID iid, void **out)
{
    struct restricted_error_info *impl = impl_from_IRestrictedErrorInfo(iface);

    TRACE("(%p, %s, %p)\n", iface, debugstr_guid(iid), out);

    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IRestrictedErrorInfo))
    {
        IRestrictedErrorInfo_AddRef((*out = &impl->IRestrictedErrorInfo_iface));
        return S_OK;
    }
    if (IsEqualGUID(iid, &IID_IErrorInfo))
    {
        IErrorInfo_AddRef((*out = &impl->IErrorInfo_iface));
        return S_OK;
    }

    *out = NULL;
    FIXME("%s not implemented, returning E_NOINTERFACE.", debugstr_guid(iid));
    return E_NOINTERFACE;
}

static ULONG WINAPI restricted_error_info_AddRef(IRestrictedErrorInfo *iface)
{
    struct restricted_error_info *impl = impl_from_IRestrictedErrorInfo(iface);
    TRACE("(%p)\n", iface);
    return InterlockedIncrement(&impl->ref);
}

static ULONG WINAPI restricted_error_info_Release(IRestrictedErrorInfo *iface)
{
    struct restricted_error_info *impl = impl_from_IRestrictedErrorInfo(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);

    TRACE("(%p)\n", iface);

    if (!ref)
    {
        SysFreeString(impl->description);
        SysFreeString(impl->restricted_description);
        free(impl);
    }
    return ref;
}

static HRESULT WINAPI restricted_error_info_GetErrorDetails(IRestrictedErrorInfo *iface, BSTR *ret_desc, HRESULT *code,
                                                            BSTR *ret_restricted_desc, BSTR *sid)
{
    struct restricted_error_info *impl = impl_from_IRestrictedErrorInfo(iface);
    BSTR desc, restricted_desc;

    TRACE("(%p, %p, %p, %p, %p)\n", iface, ret_desc, code, ret_restricted_desc, sid);

    /* There are no terminating NUL characters, so we can use SysStringLen. */
    if (!(desc = SysAllocStringLen(impl->description, SysStringLen(impl->description)))) return E_OUTOFMEMORY;
    if (!(restricted_desc = SysAllocStringLen(impl->restricted_description, SysStringLen(impl->restricted_description))))
    {
        SysFreeString(desc);
        return E_OUTOFMEMORY;
    }
    *code = impl->code;
    *ret_desc = desc;
    *ret_restricted_desc = restricted_desc;

    return S_OK;
}

static HRESULT WINAPI restricted_error_info_GetReference(IRestrictedErrorInfo *iface, BSTR *reference)
{
    FIXME("(%p, %p): semi-stub!\n", iface, reference);
    *reference = NULL;
    return S_OK;
}

static IRestrictedErrorInfoVtbl restricted_error_info_vtbl =
{
    /* IUnknown */
    restricted_error_info_QueryInterface,
    restricted_error_info_AddRef,
    restricted_error_info_Release,
    /* IRestrictedErrorInfo */
    restricted_error_info_GetErrorDetails,
    restricted_error_info_GetReference,
};

static inline struct restricted_error_info *impl_from_IErrorInfo(IErrorInfo *iface)
{
    return CONTAINING_RECORD(iface, struct restricted_error_info, IErrorInfo_iface);
}

static HRESULT WINAPI error_info_QueryInterface(IErrorInfo *iface, REFIID iid, void **out)
{
    struct restricted_error_info *impl = impl_from_IErrorInfo(iface);
    TRACE("(%p, %s, %p)\n", iface, debugstr_guid(iid), out);
    return IRestrictedErrorInfo_QueryInterface(&impl->IRestrictedErrorInfo_iface, iid, out);
}

static ULONG WINAPI error_info_AddRef(IErrorInfo *iface)
{
    struct restricted_error_info *impl = impl_from_IErrorInfo(iface);
    TRACE("(%p)\n", iface);
    return IRestrictedErrorInfo_AddRef(&impl->IRestrictedErrorInfo_iface);
}

static ULONG WINAPI error_info_Release(IErrorInfo *iface)
{
    struct restricted_error_info *impl = impl_from_IErrorInfo(iface);
    TRACE("(%p)\n", iface);
    return IRestrictedErrorInfo_Release(&impl->IRestrictedErrorInfo_iface);
}

static HRESULT WINAPI error_info_GetDescription(IErrorInfo *iface, BSTR *description)
{
    struct restricted_error_info *impl = impl_from_IErrorInfo(iface);

    TRACE("(%p, %p)\n", iface, description);

    *description = SysAllocStringLen(impl->description, SysStringLen(impl->description));
    return *description ? S_OK : E_OUTOFMEMORY;
}

static HRESULT WINAPI error_info_GetGUID(IErrorInfo *iface, GUID *guid)
{
    TRACE("(%p, %p)\n", iface, guid);
    memset(guid, 0, sizeof(*guid));
    return S_OK;
}

static HRESULT WINAPI error_info_GetHelpContext(IErrorInfo *iface, DWORD *context)
{
    TRACE("(%p, %p)\n", iface, context);
    *context = 0;
    return S_OK;
}

static HRESULT WINAPI error_info_GetHelpFile(IErrorInfo *iface, BSTR *file)
{
    TRACE("(%p, %p)\n", iface, file);
    *file = NULL;
    return S_OK;
}

static HRESULT WINAPI error_info_GetSource(IErrorInfo *iface, BSTR *source)
{
    TRACE("(%p, %p)\n", iface, source);
    *source = NULL;
    return S_OK;
}

static const IErrorInfoVtbl error_info_vtbl =
{
    /* IUnknown */
    error_info_QueryInterface,
    error_info_AddRef,
    error_info_Release,
    /* IErrorInfo */
    error_info_GetGUID,
    error_info_GetSource,
    error_info_GetDescription,
    error_info_GetHelpFile,
    error_info_GetHelpContext
};

static HRESULT restricted_error_info_create(HRESULT code, ULONG len_msg, const WCHAR *message, ULONG len_desc,
                                     const WCHAR *desc, IErrorInfo **info)
{
    struct restricted_error_info *impl;

    if (!(impl = calloc(1, sizeof(*impl)))) return E_OUTOFMEMORY;

    impl->IRestrictedErrorInfo_iface.lpVtbl = &restricted_error_info_vtbl;
    impl->IErrorInfo_iface.lpVtbl = &error_info_vtbl;
    impl->code = code;
    impl->ref = 1;
    if (!(impl->description = SysAllocStringLen(desc, len_desc)))
    {
        free(impl);
        return E_OUTOFMEMORY;
    }
    /* If the caller did not provide a message, use the description. */
    if (!len_msg)
    {
        message = impl->description;
        len_msg = len_desc;
    }
    if (!(impl->restricted_description = SysAllocStringLen(message, len_msg)))
    {
        SysFreeString(impl->description);
        free(impl);
        return E_OUTOFMEMORY;
    }
    *info = &impl->IErrorInfo_iface;
    return S_OK;
}

/***********************************************************************
 *      GetRestrictedErrorInfo (combase.@)
 */
HRESULT WINAPI GetRestrictedErrorInfo(IRestrictedErrorInfo **info)
{
    IErrorInfo *error_info;
    HRESULT hr;

    TRACE("(%p)\n", info);

    *info = NULL;
    hr = get_error_info(&error_info);
    if (hr != S_OK) return hr;

    hr = IErrorInfo_QueryInterface(error_info, &IID_IRestrictedErrorInfo, (void **)info);
    IErrorInfo_Release(error_info);
    return FAILED(hr) ? S_FALSE : S_OK;
}

/***********************************************************************
 *      SetRestrictedErrorInfo (combase.@)
 */
HRESULT WINAPI SetRestrictedErrorInfo(IRestrictedErrorInfo *info)
{
    IErrorInfo *error_info = NULL;
    HRESULT hr;

    TRACE("(%p)\n", info);

    if (!info)
        return set_error_info(NULL);

    hr = IRestrictedErrorInfo_QueryInterface(info, &IID_IErrorInfo, (void **)&error_info);
    if (FAILED(hr))
        return hr;

    hr = set_error_info(error_info);
    IErrorInfo_Release(error_info);
    return hr;
}

/***********************************************************************
 *      RoOriginateLanguageException (combase.@)
 */
BOOL WINAPI RoOriginateLanguageException(HRESULT error, HSTRING message, IUnknown *language_exception)
{
    FIXME("%#lx, %s, %p: semi-stub\n", error, debugstr_hstring(message), language_exception);
    return RoOriginateError(error, message);
}

/***********************************************************************
 *      RoOriginateError (combase.@)
 */
BOOL WINAPI RoOriginateError(HRESULT error, HSTRING message)
{
    const WCHAR *buf;
    UINT32 len;

    TRACE("%#lx, %s\n", error, debugstr_hstring(message));

    buf = WindowsGetStringRawBuffer(message, &len);
    return RoOriginateErrorW(error, len, buf);
}

static LONG WINAPI rooriginate_handler(EXCEPTION_POINTERS *ptrs)
{
    EXCEPTION_RECORD *rec = ptrs->ExceptionRecord;
    return (rec->ExceptionCode == EXCEPTION_RO_ORIGINATEERROR) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}

/***********************************************************************
 *      RoOriginateErrorW (combase.@)
 */
BOOL WINAPI RoOriginateErrorW(HRESULT error, UINT max_len, const WCHAR *message)
{
    BOOL set_error, raise_exception, ret = TRUE;
    UINT32 flags, len_msg = 0, len_desc;
    WCHAR desc[512];

    TRACE("%#lx, %u, %p\n", error, max_len, message);

    if (SUCCEEDED(error)) return FALSE;
    RoGetErrorReportingFlags(&flags); /* RoGetErrorReportingFlags is infalliable with a valid pointer. */
    /* We call SetErrorInfo if USESETERRORINFO is set and SUPPRESSSETERRORINFO is *not* set. */
    set_error = flags & RO_ERROR_REPORTING_USESETERRORINFO && !(flags & RO_ERROR_REPORTING_SUPPRESSSETERRORINFO);
    /* We raise a structured exception if a debugger is present and SUPPRESSEXCEPTIONS is not set.
     * However, FORCEEXCEPTIONS being set will always cause an exception to be raised. */
    raise_exception = (IsDebuggerPresent() && !(flags & RO_ERROR_REPORTING_SUPPRESSEXCEPTIONS)) ||
                      (flags & RO_ERROR_REPORTING_FORCEEXCEPTIONS);
    if (set_error || raise_exception)
    {
        /* Get the HRESULT description. */
        if (!(len_desc = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, 0, desc, ARRAY_SIZE(desc), NULL)))
            len_desc = swprintf(desc, ARRAY_SIZE(desc), L"Error code '%#lx'.\r\n", error);
        /* If the caller provided a message, find the terminating NUL and truncate it to 512 characters. */
        if (message)
        {
            max_len = max_len ? min(max_len, 512) : 512;
            while (len_msg < max_len && message[len_msg]) len_msg++;
        }
    }
    if (set_error)
    {
        IErrorInfo *info = NULL;
        HRESULT hr;

        if (FAILED(restricted_error_info_create(error, len_msg, message, len_desc, desc, &info)))
            ret = FALSE;
        /* If restricted_error_info_create failed, this clears the current error object. */
        if (FAILED(hr = set_error_info(info)))
        {
            FIXME("Failed to set current error: %#lx\n", hr);
            ret = FALSE;
        }
        if (info) IErrorInfo_Release(info);
    }
    if (raise_exception)
    {
        const WCHAR *src = len_msg ? message : desc;
        ULONG len = len_msg ? len_msg : len_desc;
        WCHAR *str;

        if (!(str = malloc(sizeof(WCHAR) * (len + 1)))) return ret;
        memcpy(str, src, len * sizeof(WCHAR));
        str[len] = L'\0';

        __TRY
        {
            ULONG_PTR args[3];

            args[0] = error;
            args[1] = len;
            args[2] = (ULONG_PTR)str;
            RaiseException(EXCEPTION_RO_ORIGINATEERROR, 0, 3, args);
        }
        __EXCEPT(rooriginate_handler)
        {
        }
        __ENDTRY;
        free(str);
    }

    return ret;
}

/***********************************************************************
 *      RoGetMatchingRestrictedErrorInfo (combase.@)
 */
HRESULT WINAPI RoGetMatchingRestrictedErrorInfo(HRESULT error, IRestrictedErrorInfo **info)
{
    BSTR description = NULL, restricted = NULL, sid = NULL;
    HRESULT hr, current_error;

    TRACE("%#lx, %p\n", error, info);

    hr = GetRestrictedErrorInfo(info);
    if (FAILED(hr)) return hr;
    if (*info)
    {
        hr = IRestrictedErrorInfo_GetErrorDetails(*info, &description, &current_error, &restricted, &sid);
        SysFreeString(description);
        SysFreeString(restricted);
        SysFreeString(sid);
        if (SUCCEEDED(hr) && current_error == error) return S_OK;
        IRestrictedErrorInfo_Release(*info);
        *info = NULL;
    }
    RoOriginateError(error, NULL);
    hr = GetRestrictedErrorInfo(info);
    if (FAILED(hr)) return hr;
    return *info ? S_OK : E_UNEXPECTED;
}

/***********************************************************************
 *      RoTransformError (combase.@)
 */
BOOL WINAPI RoTransformError(HRESULT old_error, HRESULT new_error, HSTRING message)
{
    UINT32 len = 0;

    TRACE("%#lx, %#lx, %s\n", old_error, new_error, debugstr_hstring(message));

    if (old_error == new_error || (SUCCEEDED(old_error) && SUCCEEDED(new_error))) return FALSE;
    if (!message || !WindowsGetStringRawBuffer(message, &len) || !len) return FALSE;

    /* Wine does not yet expose debugger WinRT error records or restricted
     * error-info propagation.  There is still a successful transformation
     * from the caller's perspective when a non-empty diagnostic is present. */
    return TRUE;
}

/***********************************************************************
 *      RoTransformErrorW (combase.@)
 */
BOOL WINAPI RoTransformErrorW(HRESULT old_error, HRESULT new_error, UINT max_len,
                              const WCHAR *message)
{
    TRACE("%#lx, %#lx, %u, %s\n", old_error, new_error, max_len, debugstr_w(message));

    if (old_error == new_error || (SUCCEEDED(old_error) && SUCCEEDED(new_error))) return FALSE;
    if (!message || !*message) return FALSE;
    return TRUE;
}

/***********************************************************************
 *      RoReportUnhandledError (combase.@)
 */
HRESULT WINAPI RoReportUnhandledError(IRestrictedErrorInfo *info)
{
    FIXME("(%p): stub\n", info);
    return S_OK;
}

static LONG error_reporting_flags = RO_ERROR_REPORTING_USESETERRORINFO;
/***********************************************************************
 *      RoSetErrorReportingFlags (combase.@)
 */
HRESULT WINAPI RoSetErrorReportingFlags(UINT32 flags)
{
    UINT32 valid_flags = RO_ERROR_REPORTING_SUPPRESSEXCEPTIONS | RO_ERROR_REPORTING_FORCEEXCEPTIONS |
                         RO_ERROR_REPORTING_USESETERRORINFO | RO_ERROR_REPORTING_SUPPRESSSETERRORINFO;

    TRACE("(%08x)\n", flags);

    if (flags & ~valid_flags) return E_INVALIDARG;
    WriteRelease(&error_reporting_flags, flags);
    return S_OK;
}

/***********************************************************************
 *      RoGetErrorReportingFlags (combase.@)
 */
HRESULT WINAPI RoGetErrorReportingFlags(UINT32 *flags)
{
    TRACE("(%p)\n", flags);

    if (!flags)
        return E_POINTER;

    *flags = ReadAcquire(&error_reporting_flags);
    return S_OK;
}


/***********************************************************************
 *      CleanupTlsOleState (combase.@)
 */
void WINAPI CleanupTlsOleState(void *unknown)
{
    FIXME("(%p): stub\n", unknown);
}

/***********************************************************************
 *      DllGetActivationFactory (combase.@)
 */
HRESULT WINAPI DllGetActivationFactory(HSTRING classid, IActivationFactory **factory)
{
    HRESULT hr;

    TRACE("(%s, %p)\n", debugstr_hstring(classid), factory);

    if (SUCCEEDED(hr = extension_catalog_get_factory(classid, factory))) return hr;
    return hr;
}

/***********************************************************************
 *      RoFailFastWithErrorContext (combase.@)
 */
void WINAPI RoFailFastWithErrorContext(HRESULT hr)
{
    FIXME("(0x%08lx)\n", hr);
    RaiseFailFastException(NULL, NULL, 0);
}
