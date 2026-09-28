/* Tests for the private COM drag/drop proxy. */

/* Copyright 2026 Nulifyer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>

#define COBJMACROS
#include "../dcom.h"

#include "wine/test.h"

static const CLSID psfactory_clsid =
    {0x00000320, 0, 0, {0xc0, 0, 0, 0, 0, 0, 0, 0x46}};
static const IID priv_dragdrop_iid =
    {0x00000160, 0, 0, {0xc0, 0, 0, 0, 0, 0, 0, 0x46}};

struct dragdrop_object
{
    IPrivDragDrop IPrivDragDrop_iface;
    LONG refcount;
    LONG dragdrop_calls;
    LONG brokered_calls;
    LONG enterprise_id_calls;
    LONG status_calls;
    CallerLocalityIndicator locality;
};

struct client_args
{
    IStream *stream;
    HRESULT unmarshal_hr;
    HRESULT dragdrop_hr;
    HRESULT null_effect_hr;
    HRESULT brokered_hr;
    HRESULT enterprise_id_hr;
    HRESULT status_hr;
    ULONG effect;
    BOOL brokered;
    BOOL is_enterprise_target;
    BOOL policy_allows_drop;
};

static inline struct dragdrop_object *impl_from_IPrivDragDrop(IPrivDragDrop *iface)
{
    return CONTAINING_RECORD(iface, struct dragdrop_object, IPrivDragDrop_iface);
}

static HRESULT WINAPI dragdrop_QueryInterface(IPrivDragDrop *iface, REFIID iid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (!IsEqualIID(iid, &IID_IUnknown) && !IsEqualIID(iid, &priv_dragdrop_iid))
        return E_NOINTERFACE;
    *out = iface;
    IPrivDragDrop_AddRef(iface);
    return S_OK;
}

static ULONG WINAPI dragdrop_AddRef(IPrivDragDrop *iface)
{
    return InterlockedIncrement(&impl_from_IPrivDragDrop(iface)->refcount);
}

static ULONG WINAPI dragdrop_Release(IPrivDragDrop *iface)
{
    return InterlockedDecrement(&impl_from_IPrivDragDrop(iface)->refcount);
}

static HRESULT WINAPI dragdrop_PrivDragDrop(IPrivDragDrop *iface,
        CallerLocalityIndicator locality, HWND hwnd, InterfaceData *interface_data,
        ULONG operation, ULONG key_state, POINTL point, ULONG *effect, ULONG process_id,
        IDataObject *data_object, HWND other_hwnd)
{
    struct dragdrop_object *object = impl_from_IPrivDragDrop(iface);

    object->locality = locality;
    InterlockedIncrement(&object->dragdrop_calls);
    ok(!hwnd, "got hwnd %p.\n", hwnd);
    ok(!interface_data, "got interface data %p.\n", interface_data);
    ok(operation == 2, "got operation %lu.\n", operation);
    ok(key_state == 3, "got key state %lu.\n", key_state);
    ok(point.x == 11 && point.y == -12, "got point %ld,%ld.\n", point.x, point.y);
    ok(process_id == 4, "got process id %lu.\n", process_id);
    ok(!data_object, "got data object %p.\n", data_object);
    ok(!other_hwnd, "got other hwnd %p.\n", other_hwnd);
    if (effect) *effect = 0x42;
    return S_OK;
}

static HRESULT WINAPI dragdrop_IsBrokeredTarget(IPrivDragDrop *iface, BOOL *brokered)
{
    InterlockedIncrement(&impl_from_IPrivDragDrop(iface)->brokered_calls);
    *brokered = TRUE;
    return S_OK;
}

static HRESULT WINAPI dragdrop_SetDropSourceEnterpriseId(IPrivDragDrop *iface,
        const WCHAR *enterprise_id)
{
    InterlockedIncrement(&impl_from_IPrivDragDrop(iface)->enterprise_id_calls);
    ok(!lstrcmpW(enterprise_id, L"enterprise"), "got enterprise id %s.\n",
            wine_dbgstr_w(enterprise_id));
    return S_OK;
}

static HRESULT WINAPI dragdrop_GetEnterpriseDropTargetStatus(IPrivDragDrop *iface,
        BOOL *is_enterprise_target, BOOL *policy_allows_drop)
{
    InterlockedIncrement(&impl_from_IPrivDragDrop(iface)->status_calls);
    *is_enterprise_target = TRUE;
    *policy_allows_drop = FALSE;
    return S_OK;
}

static const IPrivDragDropVtbl dragdrop_vtbl =
{
    dragdrop_QueryInterface,
    dragdrop_AddRef,
    dragdrop_Release,
    dragdrop_PrivDragDrop,
    dragdrop_IsBrokeredTarget,
    dragdrop_SetDropSourceEnterpriseId,
    dragdrop_GetEnterpriseDropTargetStatus,
};

static DWORD WINAPI client_thread(void *param)
{
    struct client_args *args = param;
    IPrivDragDrop *proxy = NULL;
    POINTL point = {11, -12};
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ok(hr == S_OK, "CoInitializeEx returned %#lx.\n", hr);
    if (FAILED(hr)) return 0;

    args->unmarshal_hr = CoGetInterfaceAndReleaseStream(args->stream, &priv_dragdrop_iid,
            (void **)&proxy);
    args->stream = NULL;
    if (SUCCEEDED(args->unmarshal_hr))
    {
        args->effect = 7;
        args->dragdrop_hr = IPrivDragDrop_PrivDragDrop(proxy, CallerIsDirect, NULL, NULL,
                2, 3, point, &args->effect, 4, NULL, NULL);
        args->null_effect_hr = IPrivDragDrop_PrivDragDrop(proxy, CallerIsDirect, NULL, NULL,
                2, 3, point, NULL, 4, NULL, NULL);
        args->brokered_hr = IPrivDragDrop_IsBrokeredTarget(proxy, &args->brokered);
        args->enterprise_id_hr = IPrivDragDrop_SetDropSourceEnterpriseId(proxy, L"enterprise");
        args->status_hr = IPrivDragDrop_GetEnterpriseDropTargetStatus(proxy,
                &args->is_enterprise_target, &args->policy_allows_drop);
        IPrivDragDrop_Release(proxy);
    }

    CoUninitialize();
    return 0;
}

START_TEST(priv_dragdrop)
{
    struct dragdrop_object object = {{&dragdrop_vtbl}, 1};
    struct client_args args = {0};
    IStream *stream = NULL;
    CLSID clsid;
    HANDLE thread;
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(hr == S_OK, "CoInitializeEx returned %#lx.\n", hr);
    if (FAILED(hr)) return;

    hr = CoGetPSClsid(&priv_dragdrop_iid, &clsid);
    ok(hr == S_OK, "CoGetPSClsid returned %#lx.\n", hr);
    ok(IsEqualCLSID(&clsid, &psfactory_clsid), "got proxy/stub CLSID %s.\n",
            wine_dbgstr_guid(&clsid));

    hr = CoMarshalInterThreadInterfaceInStream(&priv_dragdrop_iid,
            (IUnknown *)&object.IPrivDragDrop_iface, &stream);
    ok(hr == S_OK, "CoMarshalInterThreadInterfaceInStream returned %#lx.\n", hr);
    if (SUCCEEDED(hr))
    {
        args.stream = stream;
        thread = CreateThread(NULL, 0, client_thread, &args, 0, NULL);
        ok(!!thread, "CreateThread failed, error %lu.\n", GetLastError());
        if (thread)
        {
            ok(WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0, "client thread timed out.\n");
            CloseHandle(thread);
        }
        else IStream_Release(stream);

        ok(args.unmarshal_hr == S_OK, "CoGetInterfaceAndReleaseStream returned %#lx.\n",
                args.unmarshal_hr);
        ok(args.dragdrop_hr == S_OK, "PrivDragDrop returned %#lx.\n", args.dragdrop_hr);
        ok(args.null_effect_hr == S_OK, "PrivDragDrop with NULL effect returned %#lx.\n",
                args.null_effect_hr);
        ok(args.effect == 0x42, "got effect %#lx.\n", args.effect);
        ok(args.brokered_hr == S_OK && args.brokered,
                "IsBrokeredTarget returned %#lx, %d.\n", args.brokered_hr, args.brokered);
        ok(args.enterprise_id_hr == S_OK, "SetDropSourceEnterpriseId returned %#lx.\n",
                args.enterprise_id_hr);
        ok(args.status_hr == S_OK, "GetEnterpriseDropTargetStatus returned %#lx.\n",
                args.status_hr);
        ok(args.is_enterprise_target && !args.policy_allows_drop,
                "got enterprise status %d, %d.\n", args.is_enterprise_target,
                args.policy_allows_drop);
    }

    ok(object.dragdrop_calls == 2, "PrivDragDrop was called %ld times.\n", object.dragdrop_calls);
    ok(object.brokered_calls == 1, "IsBrokeredTarget was called %ld times.\n",
            object.brokered_calls);
    ok(object.enterprise_id_calls == 1, "SetDropSourceEnterpriseId was called %ld times.\n",
            object.enterprise_id_calls);
    ok(object.status_calls == 1, "GetEnterpriseDropTargetStatus was called %ld times.\n",
            object.status_calls);
    ok(object.locality == CallerIsInproc, "got caller locality %u.\n", object.locality);
    ok(object.refcount == 1, "object refcount is %ld.\n", object.refcount);

    CoUninitialize();
}
