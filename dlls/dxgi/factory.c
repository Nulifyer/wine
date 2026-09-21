/*
 * Copyright 2008 Henri Verbeet for CodeWeavers
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
 *
 */

#include "dxgi_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(dxgi);

static const GUID IID_IDXGIFactoryDWM =
        {0x713f394e, 0x92ca, 0x47e7, {0xab, 0x81, 0x11, 0x59, 0xc2, 0x79, 0x1e, 0x54}};
static const GUID IID_IDXGIFactoryDWM2 =
        {0x1ddd77aa, 0x9a4a, 0x4cc8, {0x9e, 0x55, 0x98, 0xc1, 0x96, 0xba, 0xfc, 0x8f}};
static const GUID IID_IDXGIFactoryPartner =
        {0xb14887d9, 0xf537, 0x4af5, {0xb3, 0x79, 0x7d, 0x33, 0x03, 0x1b, 0xe7, 0x73}};
static const GUID IID_IDXGIOutputDWM =
        {0x6f66a9a0, 0xbece, 0x4ee8, {0xb1, 0x1b, 0x99, 0x0e, 0xb3, 0x8e, 0xd9, 0x76}};
static const GUID IID_IDXGISwapChainDWM1 =
        {0xfc4f7700, 0x8c88, 0x43fb, {0xaa, 0x4f, 0x44, 0xc4, 0xa5, 0x84, 0xdc, 0x19}};

struct dxgi_adapter_change_notification
{
    struct list entry;
    HANDLE source_event;
    HANDLE event;
    DWORD cookie;
};

static inline struct dxgi_factory *impl_from_IWineDXGIFactory(IWineDXGIFactory *iface)
{
    return CONTAINING_RECORD(iface, struct dxgi_factory, IWineDXGIFactory_iface);
}

static inline struct dxgi_factory *impl_from_IDXGIFactoryDWM(IDXGIFactoryDWM *iface)
{
    return CONTAINING_RECORD(iface, struct dxgi_factory, IDXGIFactoryDWM_iface);
}

static inline struct dxgi_factory *impl_from_IDXGIFactoryDWM2(IDXGIFactoryDWM2 *iface)
{
    return CONTAINING_RECORD(iface, struct dxgi_factory, IDXGIFactoryDWM2_iface);
}

static inline struct dxgi_factory *impl_from_IDXGIFactoryPartner(IDXGIFactoryPartner *iface)
{
    return CONTAINING_RECORD(iface, struct dxgi_factory, IDXGIFactoryPartner_iface);
}

static inline struct dxgi_factory *impl_from_IDXGIDisplayControl(IDXGIDisplayControl *iface)
{
    return CONTAINING_RECORD(iface, struct dxgi_factory, IDXGIDisplayControl_iface);
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_QueryInterface(IWineDXGIFactory *iface, REFIID iid, void **out)
{
    struct dxgi_factory *factory = impl_from_IWineDXGIFactory(iface);

    TRACE("iface %p, iid %s, out %p.\n", iface, debugstr_guid(iid), out);

    if (IsEqualGUID(iid, &IID_IWineDXGIFactory)
            || IsEqualGUID(iid, &IID_IDXGIFactory7)
            || IsEqualGUID(iid, &IID_IDXGIFactory6)
            || IsEqualGUID(iid, &IID_IDXGIFactory5)
            || IsEqualGUID(iid, &IID_IDXGIFactory4)
            || IsEqualGUID(iid, &IID_IDXGIFactory3)
            || IsEqualGUID(iid, &IID_IDXGIFactory2)
            || (factory->extended && IsEqualGUID(iid, &IID_IDXGIFactory1))
            || IsEqualGUID(iid, &IID_IDXGIFactory)
            || IsEqualGUID(iid, &IID_IDXGIObject)
            || IsEqualGUID(iid, &IID_IUnknown))
    {
        IUnknown_AddRef(iface);
        *out = iface;
        return S_OK;
    }

    if (IsEqualGUID(iid, &IID_IDXGIFactoryDWM))
    {
        IWineDXGIFactory_AddRef(iface);
        *out = &factory->IDXGIFactoryDWM_iface;
        return S_OK;
    }
    if (IsEqualGUID(iid, &IID_IDXGIFactoryDWM2))
    {
        IWineDXGIFactory_AddRef(iface);
        *out = &factory->IDXGIFactoryDWM2_iface;
        return S_OK;
    }
    if (IsEqualGUID(iid, &IID_IDXGIFactoryPartner))
    {
        IWineDXGIFactory_AddRef(iface);
        *out = &factory->IDXGIFactoryPartner_iface;
        return S_OK;
    }
    if (IsEqualGUID(iid, &IID_IDXGIDisplayControl))
    {
        IWineDXGIFactory_AddRef(iface);
        *out = &factory->IDXGIDisplayControl_iface;
        return S_OK;
    }

    WARN("%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(iid));

    *out = NULL;
    return E_NOINTERFACE;
}

static HRESULT dxgi_factory_private_QueryInterface(struct dxgi_factory *factory,
        REFIID iid, void **object)
{
    return IWineDXGIFactory_QueryInterface(&factory->IWineDXGIFactory_iface, iid, object);
}

static ULONG dxgi_factory_private_AddRef(struct dxgi_factory *factory)
{
    return IWineDXGIFactory_AddRef(&factory->IWineDXGIFactory_iface);
}

static ULONG dxgi_factory_private_Release(struct dxgi_factory *factory)
{
    return IWineDXGIFactory_Release(&factory->IWineDXGIFactory_iface);
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_dwm_QueryInterface(IDXGIFactoryDWM *iface,
        REFIID iid, void **object)
{
    return dxgi_factory_private_QueryInterface(impl_from_IDXGIFactoryDWM(iface), iid, object);
}

static ULONG STDMETHODCALLTYPE dxgi_factory_dwm_AddRef(IDXGIFactoryDWM *iface)
{
    return dxgi_factory_private_AddRef(impl_from_IDXGIFactoryDWM(iface));
}

static ULONG STDMETHODCALLTYPE dxgi_factory_dwm_Release(IDXGIFactoryDWM *iface)
{
    return dxgi_factory_private_Release(impl_from_IDXGIFactoryDWM(iface));
}

static HWND dxgi_factory_create_dwm_host_window(const DXGI_SWAP_CHAIN_DESC *desc,
        IDXGIOutput *output)
{
    static const DWORD ex_style = WS_EX_NOACTIVATE | WS_EX_NOREDIRECTIONBITMAP
            | WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_TRANSPARENT;
    DXGI_OUTPUT_DESC output_desc;
    unsigned int width, height;
    int x = 0, y = 0;
    HWND window;

    width = desc->BufferDesc.Width;
    height = desc->BufferDesc.Height;
    if (output && SUCCEEDED(IDXGIOutput_GetDesc(output, &output_desc)))
    {
        x = output_desc.DesktopCoordinates.left;
        y = output_desc.DesktopCoordinates.top;
        if (!width)
            width = output_desc.DesktopCoordinates.right - output_desc.DesktopCoordinates.left;
        if (!height)
            height = output_desc.DesktopCoordinates.bottom - output_desc.DesktopCoordinates.top;
    }
    if (!width || !height)
        return NULL;

    window = CreateWindowExW(ex_style, L"static", L"DXGI DWM output",
            WS_POPUP, x, y, width, height, NULL, NULL, NULL, NULL);
    if (!window)
        return NULL;

    if (!SetWindowPos(window, HWND_TOPMOST, x, y, width, height,
            SWP_NOACTIVATE | SWP_SHOWWINDOW))
    {
        DestroyWindow(window);
        return NULL;
    }
    return window;
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_dwm_CreateSwapChain(IDXGIFactoryDWM *iface,
        IUnknown *device, DXGI_SWAP_CHAIN_DESC *desc, IDXGIOutput *output,
        IDXGISwapChainDWM1 **swapchain)
{
    struct dxgi_factory *factory = impl_from_IDXGIFactoryDWM(iface);
    DXGI_SWAP_CHAIN_FULLSCREEN_DESC fullscreen_desc = {0};
    DXGI_SWAP_CHAIN_DESC1 desc1;
    IWineDXGISwapChainFactory *swapchain_factory;
    IDXGISwapChain1 *public_swapchain;
    HWND host_window;
    HRESULT hr;

    TRACE("iface %p, device %p, desc %p, output %p, swapchain %p.\n",
            iface, device, desc, output, swapchain);

    if (!device || !desc || !swapchain)
        return DXGI_ERROR_INVALID_CALL;
    *swapchain = NULL;

    memset(&desc1, 0, sizeof(desc1));
    desc1.Width = desc->BufferDesc.Width;
    desc1.Height = desc->BufferDesc.Height;
    desc1.Format = desc->BufferDesc.Format;
    desc1.Stereo = FALSE;
    desc1.SampleDesc = desc->SampleDesc;
    desc1.BufferUsage = desc->BufferUsage;
    desc1.BufferCount = desc->BufferCount;
    desc1.Scaling = desc->BufferDesc.Scaling == DXGI_MODE_SCALING_CENTERED
            ? DXGI_SCALING_NONE : DXGI_SCALING_STRETCH;
    desc1.SwapEffect = desc->SwapEffect;
    desc1.AlphaMode = DXGI_ALPHA_MODE_IGNORE;
    desc1.Flags = desc->Flags;

    if (!dxgi_validate_swapchain_desc(&desc1))
        return DXGI_ERROR_INVALID_CALL;

    fullscreen_desc.RefreshRate = desc->BufferDesc.RefreshRate;
    fullscreen_desc.ScanlineOrdering = desc->BufferDesc.ScanlineOrdering;
    fullscreen_desc.Scaling = desc->BufferDesc.Scaling;
    /* Native DWM swap chains are windowless. WineD3D needs a real host window;
     * using the pseudo desktop HWND selects its offscreen backup drawable. */
    fullscreen_desc.Windowed = TRUE;

    if (!(host_window = dxgi_factory_create_dwm_host_window(desc, output)))
    {
        WARN("Failed to create DWM presentation window, error %lu.\n", GetLastError());
        return DXGI_ERROR_NOT_CURRENTLY_AVAILABLE;
    }

    if (FAILED(hr = IUnknown_QueryInterface(device, &IID_IWineDXGISwapChainFactory,
            (void **)&swapchain_factory)))
    {
        DestroyWindow(host_window);
        return DXGI_ERROR_UNSUPPORTED;
    }

    hr = IWineDXGISwapChainFactory_create_swapchain(swapchain_factory,
            (IDXGIFactory *)&factory->IWineDXGIFactory_iface, host_window, &desc1,
            &fullscreen_desc, output, &public_swapchain);
    IWineDXGISwapChainFactory_Release(swapchain_factory);
    if (FAILED(hr))
    {
        DestroyWindow(host_window);
        return hr;
    }

    d3d11_swapchain_set_dwm_mode(public_swapchain, desc, host_window);
    hr = IDXGISwapChain1_QueryInterface(public_swapchain, &IID_IDXGISwapChainDWM1,
            (void **)swapchain);
    IDXGISwapChain1_Release(public_swapchain);
    return hr;
}

static const struct IDXGIFactoryDWMVtbl dxgi_factory_dwm_vtbl =
{
    dxgi_factory_dwm_QueryInterface,
    dxgi_factory_dwm_AddRef,
    dxgi_factory_dwm_Release,
    dxgi_factory_dwm_CreateSwapChain,
};

static HRESULT STDMETHODCALLTYPE dxgi_factory_dwm2_QueryInterface(IDXGIFactoryDWM2 *iface,
        REFIID iid, void **object)
{
    return dxgi_factory_private_QueryInterface(impl_from_IDXGIFactoryDWM2(iface), iid, object);
}

static ULONG STDMETHODCALLTYPE dxgi_factory_dwm2_AddRef(IDXGIFactoryDWM2 *iface)
{
    return dxgi_factory_private_AddRef(impl_from_IDXGIFactoryDWM2(iface));
}

static ULONG STDMETHODCALLTYPE dxgi_factory_dwm2_Release(IDXGIFactoryDWM2 *iface)
{
    return dxgi_factory_private_Release(impl_from_IDXGIFactoryDWM2(iface));
}

static HRESULT dxgi_factory_dwm2_swapchain_unavailable(IDXGIFactoryDWM2 *iface,
        IUnknown **swapchain)
{
    FIXME("iface %p, swapchain %p: private DWM swap chains are not implemented.\n", iface, swapchain);

    if (!swapchain)
        return DXGI_ERROR_INVALID_CALL;
    *swapchain = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_dwm2_CreateSwapChainDWM(IDXGIFactoryDWM2 *iface,
        IUnknown *device, DXGI_SWAP_CHAIN_DESC1 *desc,
        DXGI_SWAP_CHAIN_FULLSCREEN_DESC *fullscreen_desc, IDXGIOutput *output, IUnknown **swapchain)
{
    return dxgi_factory_dwm2_swapchain_unavailable(iface, swapchain);
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_dwm2_CreateSwapChainDDA(IDXGIFactoryDWM2 *iface,
        IUnknown *device, DXGI_SWAP_CHAIN_DESC1 *desc, IDXGIOutput *output, IUnknown **swapchain)
{
    return dxgi_factory_dwm2_swapchain_unavailable(iface, swapchain);
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_dwm2_CreateSwapChainDWMFromHandle(
        IDXGIFactoryDWM2 *iface, IUnknown *device, DXGI_SWAP_CHAIN_DESC1 *desc,
        DXGI_SWAP_CHAIN_FULLSCREEN_DESC *fullscreen_desc, HANDLE handle, IUnknown **swapchain)
{
    return dxgi_factory_dwm2_swapchain_unavailable(iface, swapchain);
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_dwm2_CreateSwapChainDDAFromHandle(
        IDXGIFactoryDWM2 *iface, IUnknown *device, DXGI_SWAP_CHAIN_DESC1 *desc,
        HANDLE handle, IUnknown **swapchain)
{
    return dxgi_factory_dwm2_swapchain_unavailable(iface, swapchain);
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_dwm2_EnumOutputByLuid(IDXGIFactoryDWM2 *iface,
        LUID output_luid, REFIID iid, void **object)
{
    struct dxgi_factory *factory = impl_from_IDXGIFactoryDWM2(iface);
    struct dxgi_output_dwm_desc desc;
    IDXGIOutputDWM *output_dwm;
    IDXGIAdapter *adapter;
    IDXGIOutput *output;
    unsigned int adapter_idx, output_idx;
    HRESULT hr;

    TRACE("iface %p, output_luid %08lx:%08lx, iid %s, object %p.\n", iface,
            output_luid.HighPart, output_luid.LowPart, debugstr_guid(iid), object);

    if (!object)
        return DXGI_ERROR_INVALID_CALL;
    *object = NULL;

    for (adapter_idx = 0; ; ++adapter_idx)
    {
        if (FAILED(hr = IWineDXGIFactory_EnumAdapters(&factory->IWineDXGIFactory_iface,
                adapter_idx, &adapter)))
            return hr == DXGI_ERROR_NOT_FOUND ? DXGI_ERROR_NOT_FOUND : hr;

        for (output_idx = 0; ; ++output_idx)
        {
            if (FAILED(hr = IDXGIAdapter_EnumOutputs(adapter, output_idx, &output)))
                break;
            if (SUCCEEDED(hr = IDXGIOutput_QueryInterface(output, &IID_IDXGIOutputDWM,
                    (void **)&output_dwm)))
            {
                if (SUCCEEDED(hr = output_dwm->lpVtbl->GetDesc(output_dwm, &desc))
                        && desc.output_luid.LowPart == output_luid.LowPart
                        && desc.output_luid.HighPart == output_luid.HighPart)
                {
                    hr = IDXGIOutput_QueryInterface(output, iid, object);
                    output_dwm->lpVtbl->Release(output_dwm);
                    IDXGIOutput_Release(output);
                    IDXGIAdapter_Release(adapter);
                    return hr;
                }
                output_dwm->lpVtbl->Release(output_dwm);
            }
            IDXGIOutput_Release(output);
        }
        IDXGIAdapter_Release(adapter);
        if (hr != DXGI_ERROR_NOT_FOUND)
            return hr;
    }
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_dwm2_CreateExclusiveWindowlessSwapChain(
        IDXGIFactoryDWM2 *iface, IUnknown *device, DXGI_SWAP_CHAIN_DESC1 *desc,
        DXGI_SWAP_CHAIN_FULLSCREEN_DESC *fullscreen_desc, IDXGIOutput *output,
        IUnknown **swapchain)
{
    return dxgi_factory_dwm2_swapchain_unavailable(iface, swapchain);
}

static const struct IDXGIFactoryDWM2Vtbl dxgi_factory_dwm2_vtbl =
{
    dxgi_factory_dwm2_QueryInterface,
    dxgi_factory_dwm2_AddRef,
    dxgi_factory_dwm2_Release,
    dxgi_factory_dwm2_CreateSwapChainDWM,
    dxgi_factory_dwm2_CreateSwapChainDDA,
    dxgi_factory_dwm2_CreateSwapChainDWMFromHandle,
    dxgi_factory_dwm2_CreateSwapChainDDAFromHandle,
    dxgi_factory_dwm2_EnumOutputByLuid,
    dxgi_factory_dwm2_CreateExclusiveWindowlessSwapChain,
};

static HRESULT STDMETHODCALLTYPE dxgi_factory_partner_QueryInterface(IDXGIFactoryPartner *iface,
        REFIID iid, void **object)
{
    return dxgi_factory_private_QueryInterface(impl_from_IDXGIFactoryPartner(iface), iid, object);
}

static ULONG STDMETHODCALLTYPE dxgi_factory_partner_AddRef(IDXGIFactoryPartner *iface)
{
    return dxgi_factory_private_AddRef(impl_from_IDXGIFactoryPartner(iface));
}

static ULONG STDMETHODCALLTYPE dxgi_factory_partner_Release(IDXGIFactoryPartner *iface)
{
    return dxgi_factory_private_Release(impl_from_IDXGIFactoryPartner(iface));
}

static HRESULT dxgi_factory_partner_unavailable(IDXGIFactoryPartner *iface, IUnknown **swapchain)
{
    FIXME("iface %p, swapchain %p: indirect swap chains are not implemented.\n", iface, swapchain);

    if (!swapchain)
        return DXGI_ERROR_INVALID_CALL;
    *swapchain = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_partner_CreateIndirectSwapChain(
        IDXGIFactoryPartner *iface, IDXGIDevice *device, UINT resource_count,
        IDXGIResource **resources, HANDLE handle, UINT flags, const SECURITY_ATTRIBUTES *attributes,
        DWORD access, const WCHAR *name, HANDLE *shared_handle, IUnknown **swapchain)
{
    return dxgi_factory_partner_unavailable(iface, swapchain);
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_partner_OpenIndirectSwapChainFromHandle(
        IDXGIFactoryPartner *iface, IDXGIDevice *device, HANDLE handle, HANDLE metadata_handle,
        UINT flags, UINT resource_count, IUnknown **swapchain)
{
    return dxgi_factory_partner_unavailable(iface, swapchain);
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_partner_OpenIndirectSwapChainFromName(
        IDXGIFactoryPartner *iface, IDXGIDevice *device, DWORD access, BOOL inherit,
        const WCHAR *name, HANDLE metadata_handle, UINT flags, UINT resource_count,
        IUnknown **swapchain)
{
    return dxgi_factory_partner_unavailable(iface, swapchain);
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_partner_ApplicationPresentationMode(
        IDXGIFactoryPartner *iface, HWND window, HANDLE handle, UINT *mode, REFIID iid, void **object)
{
    FIXME("iface %p, window %p, handle %p, mode %p, iid %s, object %p stub.\n",
            iface, window, handle, mode, debugstr_guid(iid), object);
    if (object)
        *object = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_partner_CreateIndirectSwapChain12(
        IDXGIFactoryPartner *iface, ID3D12Device *device, UINT resource_count,
        ID3D12Resource **resources, HANDLE handle, UINT flags, const SECURITY_ATTRIBUTES *attributes,
        DWORD access, const WCHAR *name, HANDLE *shared_handle, IUnknown **swapchain)
{
    return dxgi_factory_partner_unavailable(iface, swapchain);
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_partner_OpenIndirectSwapChainFromHandle12(
        IDXGIFactoryPartner *iface, ID3D12Device *device, HANDLE handle, HANDLE metadata_handle,
        UINT flags, UINT resource_count, IUnknown **swapchain)
{
    return dxgi_factory_partner_unavailable(iface, swapchain);
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_partner_OpenIndirectSwapChainFromName12(
        IDXGIFactoryPartner *iface, ID3D12Device *device, DWORD access, BOOL inherit,
        const WCHAR *name, HANDLE metadata_handle, UINT flags, UINT resource_count,
        IUnknown **swapchain)
{
    return dxgi_factory_partner_unavailable(iface, swapchain);
}

static const struct IDXGIFactoryPartnerVtbl dxgi_factory_partner_vtbl =
{
    dxgi_factory_partner_QueryInterface,
    dxgi_factory_partner_AddRef,
    dxgi_factory_partner_Release,
    dxgi_factory_partner_CreateIndirectSwapChain,
    dxgi_factory_partner_OpenIndirectSwapChainFromHandle,
    dxgi_factory_partner_OpenIndirectSwapChainFromName,
    dxgi_factory_partner_ApplicationPresentationMode,
    dxgi_factory_partner_CreateIndirectSwapChain12,
    dxgi_factory_partner_OpenIndirectSwapChainFromHandle12,
    dxgi_factory_partner_OpenIndirectSwapChainFromName12,
};

static HRESULT STDMETHODCALLTYPE dxgi_display_control_QueryInterface(IDXGIDisplayControl *iface,
        REFIID iid, void **object)
{
    return dxgi_factory_private_QueryInterface(impl_from_IDXGIDisplayControl(iface), iid, object);
}

static ULONG STDMETHODCALLTYPE dxgi_display_control_AddRef(IDXGIDisplayControl *iface)
{
    return dxgi_factory_private_AddRef(impl_from_IDXGIDisplayControl(iface));
}

static ULONG STDMETHODCALLTYPE dxgi_display_control_Release(IDXGIDisplayControl *iface)
{
    return dxgi_factory_private_Release(impl_from_IDXGIDisplayControl(iface));
}

static BOOL STDMETHODCALLTYPE dxgi_display_control_IsStereoEnabled(IDXGIDisplayControl *iface)
{
    TRACE("iface %p.\n", iface);
    return FALSE;
}

static void STDMETHODCALLTYPE dxgi_display_control_SetStereoEnabled(IDXGIDisplayControl *iface,
        BOOL enabled)
{
    FIXME("iface %p, enabled %#x: stereo display mode is not implemented.\n", iface, enabled);
}

static const IDXGIDisplayControlVtbl dxgi_display_control_vtbl =
{
    dxgi_display_control_QueryInterface,
    dxgi_display_control_AddRef,
    dxgi_display_control_Release,
    dxgi_display_control_IsStereoEnabled,
    dxgi_display_control_SetStereoEnabled,
};

static ULONG STDMETHODCALLTYPE dxgi_factory_AddRef(IWineDXGIFactory *iface)
{
    struct dxgi_factory *factory = impl_from_IWineDXGIFactory(iface);
    ULONG refcount = InterlockedIncrement(&factory->refcount);

    TRACE("%p increasing refcount to %lu.\n", iface, refcount);

    return refcount;
}

static ULONG STDMETHODCALLTYPE dxgi_factory_Release(IWineDXGIFactory *iface)
{
    struct dxgi_factory *factory = impl_from_IWineDXGIFactory(iface);
    ULONG refcount = InterlockedDecrement(&factory->refcount);

    TRACE("%p decreasing refcount to %lu.\n", iface, refcount);

    if (!refcount)
    {
        struct dxgi_adapter_change_notification *notification, *next;

        if (factory->device_window)
            DestroyWindow(factory->device_window);

        EnterCriticalSection(&factory->adapter_change_cs);
        LIST_FOR_EACH_ENTRY_SAFE(notification, next, &factory->adapter_change_notifications,
                struct dxgi_adapter_change_notification, entry)
        {
            list_remove(&notification->entry);
            CloseHandle(notification->event);
            free(notification);
        }
        LeaveCriticalSection(&factory->adapter_change_cs);
        DeleteCriticalSection(&factory->adapter_change_cs);

        wined3d_decref(factory->wined3d);
        wined3d_private_store_cleanup(&factory->private_store);
        free(factory);
    }

    return refcount;
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_SetPrivateData(IWineDXGIFactory *iface,
        REFGUID guid, UINT data_size, const void *data)
{
    struct dxgi_factory *factory = impl_from_IWineDXGIFactory(iface);

    TRACE("iface %p, guid %s, data_size %u, data %p.\n", iface, debugstr_guid(guid), data_size, data);

    return dxgi_set_private_data(&factory->private_store, guid, data_size, data);
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_SetPrivateDataInterface(IWineDXGIFactory *iface,
        REFGUID guid, const IUnknown *object)
{
    struct dxgi_factory *factory = impl_from_IWineDXGIFactory(iface);

    TRACE("iface %p, guid %s, object %p.\n", iface, debugstr_guid(guid), object);

    return dxgi_set_private_data_interface(&factory->private_store, guid, object);
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_GetPrivateData(IWineDXGIFactory *iface,
        REFGUID guid, UINT *data_size, void *data)
{
    struct dxgi_factory *factory = impl_from_IWineDXGIFactory(iface);

    TRACE("iface %p, guid %s, data_size %p, data %p.\n", iface, debugstr_guid(guid), data_size, data);

    return dxgi_get_private_data(&factory->private_store, guid, data_size, data);
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_GetParent(IWineDXGIFactory *iface, REFIID iid, void **parent)
{
    WARN("iface %p, iid %s, parent %p.\n", iface, debugstr_guid(iid), parent);

    *parent = NULL;

    return E_NOINTERFACE;
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_EnumAdapters1(IWineDXGIFactory *iface,
        UINT adapter_idx, IDXGIAdapter1 **adapter)
{
    struct dxgi_factory *factory = impl_from_IWineDXGIFactory(iface);
    struct dxgi_adapter *adapter_object;
    UINT adapter_count;
    HRESULT hr;

    TRACE("iface %p, adapter_idx %u, adapter %p.\n", iface, adapter_idx, adapter);

    if (!adapter)
        return DXGI_ERROR_INVALID_CALL;

    wined3d_mutex_lock();
    adapter_count = wined3d_get_adapter_count(factory->wined3d);
    wined3d_mutex_unlock();

    if (adapter_idx >= adapter_count)
    {
        *adapter = NULL;
        return DXGI_ERROR_NOT_FOUND;
    }

    if (FAILED(hr = dxgi_adapter_create(factory, adapter_idx, &adapter_object)))
    {
        *adapter = NULL;
        return hr;
    }

    *adapter = (IDXGIAdapter1 *)&adapter_object->IWineDXGIAdapter_iface;

    TRACE("Returning adapter %p.\n", *adapter);

    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_EnumAdapters(IWineDXGIFactory *iface,
        UINT adapter_idx, IDXGIAdapter **adapter)
{
    TRACE("iface %p, adapter_idx %u, adapter %p.\n", iface, adapter_idx, adapter);

    return dxgi_factory_EnumAdapters1(iface, adapter_idx, (IDXGIAdapter1 **)adapter);
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_MakeWindowAssociation(IWineDXGIFactory *iface,
        HWND window, UINT flags)
{
    struct dxgi_factory *factory = impl_from_IWineDXGIFactory(iface);

    TRACE("iface %p, window %p, flags %#x.\n", iface, window, flags);

    if (flags > DXGI_MWA_VALID)
        return DXGI_ERROR_INVALID_CALL;

    if (!window)
    {
        wined3d_unregister_windows(factory->wined3d);
        return S_OK;
    }

    if (!wined3d_register_window(factory->wined3d, window, NULL, flags))
        return E_FAIL;

    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_GetWindowAssociation(IWineDXGIFactory *iface, HWND *window)
{
    TRACE("iface %p, window %p.\n", iface, window);

    if (!window)
        return DXGI_ERROR_INVALID_CALL;

    /* The tests show that this always returns NULL for some unknown reason. */
    *window = NULL;

    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_CreateSwapChain(IWineDXGIFactory *iface,
        IUnknown *device, DXGI_SWAP_CHAIN_DESC *desc, IDXGISwapChain **swapchain)
{
    struct dxgi_factory *factory = impl_from_IWineDXGIFactory(iface);
    DXGI_SWAP_CHAIN_FULLSCREEN_DESC fullscreen_desc;
    DXGI_SWAP_CHAIN_DESC1 swapchain_desc;

    TRACE("iface %p, device %p, desc %p, swapchain %p.\n", iface, device, desc, swapchain);

    if (!desc)
    {
        WARN("Invalid pointer.\n");
        return DXGI_ERROR_INVALID_CALL;
    }

    swapchain_desc.Width = desc->BufferDesc.Width;
    swapchain_desc.Height = desc->BufferDesc.Height;
    swapchain_desc.Format = desc->BufferDesc.Format;
    swapchain_desc.Stereo = FALSE;
    swapchain_desc.SampleDesc = desc->SampleDesc;
    swapchain_desc.BufferUsage = desc->BufferUsage;
    swapchain_desc.BufferCount = desc->BufferCount;
    swapchain_desc.Scaling = DXGI_SCALING_STRETCH;
    swapchain_desc.SwapEffect = desc->SwapEffect;
    swapchain_desc.AlphaMode = DXGI_ALPHA_MODE_IGNORE;
    swapchain_desc.Flags = desc->Flags;

    fullscreen_desc.RefreshRate = desc->BufferDesc.RefreshRate;
    fullscreen_desc.ScanlineOrdering = desc->BufferDesc.ScanlineOrdering;
    fullscreen_desc.Scaling = desc->BufferDesc.Scaling;
    fullscreen_desc.Windowed = desc->Windowed;

    return IWineDXGIFactory_CreateSwapChainForHwnd(&factory->IWineDXGIFactory_iface,
            device, desc->OutputWindow, &swapchain_desc, &fullscreen_desc, NULL,
            (IDXGISwapChain1 **)swapchain);
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_CreateSoftwareAdapter(IWineDXGIFactory *iface,
        HMODULE swrast, IDXGIAdapter **adapter)
{
    FIXME("iface %p, swrast %p, adapter %p stub!\n", iface, swrast, adapter);

    return E_NOTIMPL;
}

static BOOL STDMETHODCALLTYPE dxgi_factory_IsCurrent(IWineDXGIFactory *iface)
{
    static BOOL once = FALSE;

    if (!once++)
        FIXME("iface %p stub!\n", iface);
    else
        WARN("iface %p stub!\n", iface);

    return TRUE;
}

static BOOL STDMETHODCALLTYPE dxgi_factory_IsWindowedStereoEnabled(IWineDXGIFactory *iface)
{
    FIXME("iface %p stub!\n", iface);

    return FALSE;
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_CreateSwapChainForHwnd(IWineDXGIFactory *iface,
        IUnknown *device, HWND window, const DXGI_SWAP_CHAIN_DESC1 *desc,
        const DXGI_SWAP_CHAIN_FULLSCREEN_DESC *fullscreen_desc,
        IDXGIOutput *output, IDXGISwapChain1 **swapchain)
{
    DXGI_SWAP_CHAIN_FULLSCREEN_DESC windowed_fullscreen_desc = {0};
    IWineDXGISwapChainFactory *swapchain_factory;
    ID3D12CommandQueue *command_queue;
    HRESULT hr;

    TRACE("iface %p, device %p, window %p, desc %p, fullscreen_desc %p, output %p, swapchain %p.\n",
            iface, device, window, desc, fullscreen_desc, output, swapchain);

    if (!device || !window || !desc || !swapchain)
    {
        WARN("Invalid pointer.\n");
        return DXGI_ERROR_INVALID_CALL;
    }

    if (desc->Stereo)
    {
        FIXME("Stereo swapchains are not supported.\n");
        return DXGI_ERROR_UNSUPPORTED;
    }

    if (!dxgi_validate_swapchain_desc(desc))
        return DXGI_ERROR_INVALID_CALL;

    if (!fullscreen_desc || !dxgi_validate_swapchain_fullscreen_desc(fullscreen_desc))
    {
        if (fullscreen_desc)
            windowed_fullscreen_desc = *fullscreen_desc;
        windowed_fullscreen_desc.Windowed = TRUE;
        fullscreen_desc = &windowed_fullscreen_desc;
    }

    if (output)
        FIXME("Ignoring output %p.\n", output);

    if (SUCCEEDED(IUnknown_QueryInterface(device, &IID_IWineDXGISwapChainFactory, (void **)&swapchain_factory)))
    {
        hr = IWineDXGISwapChainFactory_create_swapchain(swapchain_factory,
                (IDXGIFactory *)iface, window, desc, fullscreen_desc, output, swapchain);
        IWineDXGISwapChainFactory_Release(swapchain_factory);
        return hr;
    }

    if (SUCCEEDED(IUnknown_QueryInterface(device, &IID_ID3D12CommandQueue, (void **)&command_queue)))
    {
        hr = d3d12_swapchain_create(iface, command_queue, window, desc, fullscreen_desc, swapchain);
        ID3D12CommandQueue_Release(command_queue);
        return hr;
    }

    ERR("This is not the device we're looking for.\n");
    return DXGI_ERROR_UNSUPPORTED;
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_CreateSwapChainForCoreWindow(IWineDXGIFactory *iface,
        IUnknown *device, IUnknown *window, const DXGI_SWAP_CHAIN_DESC1 *desc,
        IDXGIOutput *output, IDXGISwapChain1 **swapchain)
{
    FIXME("iface %p, device %p, window %p, desc %p, output %p, swapchain %p stub!\n",
            iface, device, window, desc, output, swapchain);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_GetSharedResourceAdapterLuid(IWineDXGIFactory *iface,
        HANDLE resource, LUID *luid)
{
    FIXME("iface %p, resource %p, luid %p stub!\n", iface, resource, luid);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_RegisterOcclusionStatusWindow(IWineDXGIFactory *iface,
        HWND window, UINT message, DWORD *cookie)
{
    FIXME("iface %p, window %p, message %#x, cookie %p stub!\n",
            iface, window, message, cookie);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_RegisterStereoStatusEvent(IWineDXGIFactory *iface,
        HANDLE event, DWORD *cookie)
{
    FIXME("iface %p, event %p, cookie %p stub!\n", iface, event, cookie);

    return E_NOTIMPL;
}

static void STDMETHODCALLTYPE dxgi_factory_UnregisterStereoStatus(IWineDXGIFactory *iface, DWORD cookie)
{
    FIXME("iface %p, cookie %#lx stub!\n", iface, cookie);
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_RegisterStereoStatusWindow(IWineDXGIFactory *iface,
        HWND window, UINT message, DWORD *cookie)
{
    FIXME("iface %p, window %p, message %#x, cookie %p stub!\n",
            iface, window, message, cookie);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_RegisterOcclusionStatusEvent(IWineDXGIFactory *iface,
        HANDLE event, DWORD *cookie)
{
    FIXME("iface %p, event %p, cookie %p stub!\n", iface, event, cookie);

    return E_NOTIMPL;
}

static void STDMETHODCALLTYPE dxgi_factory_UnregisterOcclusionStatus(IWineDXGIFactory *iface, DWORD cookie)
{
    FIXME("iface %p, cookie %#lx stub!\n", iface, cookie);
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_CreateSwapChainForComposition(IWineDXGIFactory *iface,
        IUnknown *device, const DXGI_SWAP_CHAIN_DESC1 *desc, IDXGIOutput *output, IDXGISwapChain1 **swapchain)
{
    FIXME("iface %p, device %p, desc %p, output %p, swapchain %p stub!\n",
            iface, device, desc, output, swapchain);

    return E_NOTIMPL;
}

static UINT STDMETHODCALLTYPE dxgi_factory_GetCreationFlags(IWineDXGIFactory *iface)
{
    FIXME("iface %p stub!\n", iface);

    return 0;
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_EnumAdapterByLuid(IWineDXGIFactory *iface,
        LUID luid, REFIID iid, void **adapter)
{
    unsigned int adapter_index;
    DXGI_ADAPTER_DESC1 desc;
    IDXGIAdapter1 *adapter1;
    HRESULT hr;

    TRACE("iface %p, luid %08lx:%08lx, iid %s, adapter %p.\n",
            iface, luid.HighPart, luid.LowPart, debugstr_guid(iid), adapter);

    if (!adapter)
        return DXGI_ERROR_INVALID_CALL;

    adapter_index = 0;
    while ((hr = dxgi_factory_EnumAdapters1(iface, adapter_index, &adapter1)) == S_OK)
    {
        if (FAILED(hr = IDXGIAdapter1_GetDesc1(adapter1, &desc)))
        {
            WARN("Failed to get adapter %u desc, hr %#lx.\n", adapter_index, hr);
            ++adapter_index;
            continue;
        }

        if (desc.AdapterLuid.LowPart == luid.LowPart
                && desc.AdapterLuid.HighPart == luid.HighPart)
        {
            hr = IDXGIAdapter1_QueryInterface(adapter1, iid, adapter);
            IDXGIAdapter1_Release(adapter1);
            return hr;
        }

        IDXGIAdapter1_Release(adapter1);
        ++adapter_index;
    }
    if (hr != DXGI_ERROR_NOT_FOUND)
        WARN("Failed to enumerate adapters, hr %#lx.\n", hr);

    WARN("Adapter could not be found.\n");
    return DXGI_ERROR_NOT_FOUND;
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_EnumWarpAdapter(IWineDXGIFactory *iface,
        REFIID iid, void **adapter)
{
    IDXGIAdapter1 *adapter_object;
    HRESULT hr;

    FIXME("iface %p, iid %s, adapter %p semi-stub, returning a hardware adapter.\n",
            iface, debugstr_guid(iid), adapter);

    if (!adapter)
        return DXGI_ERROR_INVALID_CALL;

    if (FAILED(hr = dxgi_factory_EnumAdapters1(iface, 0, &adapter_object)))
        return hr;

    hr = IDXGIAdapter1_QueryInterface(adapter_object, iid, adapter);
    IDXGIAdapter1_Release(adapter_object);
    return hr;
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_CheckFeatureSupport(IWineDXGIFactory *iface,
        DXGI_FEATURE feature, void *feature_data, UINT data_size)
{
    TRACE("iface %p, feature %#x, feature_data %p, data_size %u.\n",
            iface, feature, feature_data, data_size);

    switch (feature)
    {
        case DXGI_FEATURE_PRESENT_ALLOW_TEARING:
            if (data_size != sizeof(BOOL))
                return DXGI_ERROR_INVALID_CALL;
            *(BOOL *)feature_data = TRUE;
            return S_OK;

        default:
            WARN("Unsupported feature %#x.\n", feature);
            return DXGI_ERROR_INVALID_CALL;
    }
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_EnumAdapterByGpuPreference(IWineDXGIFactory *iface,
        UINT adapter_idx, DXGI_GPU_PREFERENCE gpu_preference, REFIID iid, void **adapter)
{
    IDXGIAdapter1 *adapter_object;
    HRESULT hr;

    TRACE("iface %p, adapter_idx %u, gpu_preference %#x, iid %s, adapter %p.\n",
            iface, adapter_idx, gpu_preference, debugstr_guid(iid), adapter);

    if (gpu_preference != DXGI_GPU_PREFERENCE_UNSPECIFIED)
        FIXME("Ignoring GPU preference %#x.\n", gpu_preference);

    if (FAILED(hr = dxgi_factory_EnumAdapters1(iface, adapter_idx, &adapter_object)))
        return hr;

    hr = IDXGIAdapter1_QueryInterface(adapter_object, iid, adapter);
    IDXGIAdapter1_Release(adapter_object);
    return hr;
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_RegisterAdaptersChangedEvent(IWineDXGIFactory *iface,
        HANDLE event, DWORD *cookie)
{
    struct dxgi_factory *factory = impl_from_IWineDXGIFactory(iface);
    struct dxgi_adapter_change_notification *notification, *cursor;
    struct list *insert_before = &factory->adapter_change_notifications;
    DWORD next_cookie = 1;

    TRACE("iface %p, event %p, cookie %p.\n", iface, event, cookie);

    if (!event || !cookie)
        return DXGI_ERROR_INVALID_CALL;
    if (!(notification = malloc(sizeof(*notification))))
        return E_OUTOFMEMORY;

    EnterCriticalSection(&factory->adapter_change_cs);

    if (list_count(&factory->adapter_change_notifications) >= 0xffff)
        goto failed;

    LIST_FOR_EACH_ENTRY(cursor, &factory->adapter_change_notifications,
            struct dxgi_adapter_change_notification, entry)
    {
        if (cursor->source_event == event)
        {
            LeaveCriticalSection(&factory->adapter_change_cs);
            free(notification);
            return DXGI_ERROR_INVALID_CALL;
        }
        if (cursor->cookie == next_cookie)
            ++next_cookie;
        else if (cursor->cookie > next_cookie && insert_before == &factory->adapter_change_notifications)
            insert_before = &cursor->entry;
    }

    /* The registration owns a duplicate so the caller may close its handle before unregistering. */
    if (!DuplicateHandle(GetCurrentProcess(), event, GetCurrentProcess(), &notification->event,
            0, FALSE, DUPLICATE_SAME_ACCESS))
        goto failed;

    notification->source_event = event;
    notification->cookie = next_cookie;
    list_add_before(insert_before, &notification->entry);
    *cookie = next_cookie;
    LeaveCriticalSection(&factory->adapter_change_cs);

    return S_OK;

failed:
    LeaveCriticalSection(&factory->adapter_change_cs);
    free(notification);
    return E_OUTOFMEMORY;
}

static HRESULT STDMETHODCALLTYPE dxgi_factory_UnregisterAdaptersChangedEvent(IWineDXGIFactory *iface,
        DWORD cookie)
{
    struct dxgi_factory *factory = impl_from_IWineDXGIFactory(iface);
    struct dxgi_adapter_change_notification *notification;

    TRACE("iface %p, cookie %#lx.\n", iface, cookie);

    EnterCriticalSection(&factory->adapter_change_cs);
    LIST_FOR_EACH_ENTRY(notification, &factory->adapter_change_notifications,
            struct dxgi_adapter_change_notification, entry)
    {
        if (notification->cookie != cookie)
            continue;

        list_remove(&notification->entry);
        LeaveCriticalSection(&factory->adapter_change_cs);
        CloseHandle(notification->event);
        free(notification);
        return S_OK;
    }
    LeaveCriticalSection(&factory->adapter_change_cs);

    return DXGI_ERROR_INVALID_CALL;
}

static const struct IWineDXGIFactoryVtbl dxgi_factory_vtbl =
{
    dxgi_factory_QueryInterface,
    dxgi_factory_AddRef,
    dxgi_factory_Release,
    dxgi_factory_SetPrivateData,
    dxgi_factory_SetPrivateDataInterface,
    dxgi_factory_GetPrivateData,
    dxgi_factory_GetParent,
    dxgi_factory_EnumAdapters,
    dxgi_factory_MakeWindowAssociation,
    dxgi_factory_GetWindowAssociation,
    dxgi_factory_CreateSwapChain,
    dxgi_factory_CreateSoftwareAdapter,
    /* IDXGIFactory1 methods */
    dxgi_factory_EnumAdapters1,
    dxgi_factory_IsCurrent,
    /* IDXGIFactory2 methods */
    dxgi_factory_IsWindowedStereoEnabled,
    dxgi_factory_CreateSwapChainForHwnd,
    dxgi_factory_CreateSwapChainForCoreWindow,
    dxgi_factory_GetSharedResourceAdapterLuid,
    dxgi_factory_RegisterStereoStatusWindow,
    dxgi_factory_RegisterStereoStatusEvent,
    dxgi_factory_UnregisterStereoStatus,
    dxgi_factory_RegisterOcclusionStatusWindow,
    dxgi_factory_RegisterOcclusionStatusEvent,
    dxgi_factory_UnregisterOcclusionStatus,
    dxgi_factory_CreateSwapChainForComposition,
    /* IDXGIFactory3 methods */
    dxgi_factory_GetCreationFlags,
    /* IDXGIFactory4 methods */
    dxgi_factory_EnumAdapterByLuid,
    dxgi_factory_EnumWarpAdapter,
    /* IDXIGFactory5 methods */
    dxgi_factory_CheckFeatureSupport,
    /* IDXGIFactory6 methods */
    dxgi_factory_EnumAdapterByGpuPreference,
    /* IDXGIFactory7 methods */
    dxgi_factory_RegisterAdaptersChangedEvent,
    dxgi_factory_UnregisterAdaptersChangedEvent,
};

struct dxgi_factory *unsafe_impl_from_IDXGIFactory(IDXGIFactory *iface)
{
    IWineDXGIFactory *wine_factory;
    struct dxgi_factory *factory;
    HRESULT hr;

    if (!iface)
        return NULL;
    if (FAILED(hr = IDXGIFactory_QueryInterface(iface, &IID_IWineDXGIFactory, (void **)&wine_factory)))
    {
        ERR("Failed to get IWineDXGIFactory interface, hr %#lx.\n", hr);
        return NULL;
    }
    assert(wine_factory->lpVtbl == &dxgi_factory_vtbl);
    factory = CONTAINING_RECORD(wine_factory, struct dxgi_factory, IWineDXGIFactory_iface);
    IWineDXGIFactory_Release(wine_factory);
    return factory;
}

static HRESULT dxgi_factory_init(struct dxgi_factory *factory, BOOL extended)
{
    factory->IWineDXGIFactory_iface.lpVtbl = &dxgi_factory_vtbl;
    factory->IDXGIFactoryDWM_iface.lpVtbl = &dxgi_factory_dwm_vtbl;
    factory->IDXGIFactoryDWM2_iface.lpVtbl = &dxgi_factory_dwm2_vtbl;
    factory->IDXGIFactoryPartner_iface.lpVtbl = &dxgi_factory_partner_vtbl;
    factory->IDXGIDisplayControl_iface.lpVtbl = &dxgi_display_control_vtbl;
    factory->refcount = 1;
    wined3d_private_store_init(&factory->private_store);
    InitializeCriticalSection(&factory->adapter_change_cs);
    list_init(&factory->adapter_change_notifications);

    wined3d_mutex_lock();
    factory->wined3d = wined3d_create(0);
    wined3d_mutex_unlock();
    if (!factory->wined3d)
    {
        DeleteCriticalSection(&factory->adapter_change_cs);
        wined3d_private_store_cleanup(&factory->private_store);
        return DXGI_ERROR_UNSUPPORTED;
    }

    factory->extended = extended;

    return S_OK;
}

HRESULT dxgi_factory_create(REFIID riid, void **factory, BOOL extended)
{
    struct dxgi_factory *object;
    HRESULT hr;

    if (!(object = calloc(1, sizeof(*object))))
        return E_OUTOFMEMORY;

    if (FAILED(hr = dxgi_factory_init(object, extended)))
    {
        WARN("Failed to initialize factory, hr %#lx.\n", hr);
        free(object);
        return hr;
    }

    TRACE("Created factory %p.\n", object);

    hr = IWineDXGIFactory_QueryInterface(&object->IWineDXGIFactory_iface, riid, factory);
    IWineDXGIFactory_Release(&object->IWineDXGIFactory_iface);
    return hr;
}

HWND dxgi_factory_get_device_window(struct dxgi_factory *factory)
{
    wined3d_mutex_lock();

    if (!factory->device_window)
    {
        if (!(factory->device_window = CreateWindowA("static", "DXGI device window",
                WS_DISABLED, 0, 0, 0, 0, NULL, NULL, NULL, NULL)))
        {
            wined3d_mutex_unlock();
            ERR("Failed to create a window.\n");
            return NULL;
        }
        SetWindowPos(factory->device_window, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        TRACE("Created device window %p for factory %p.\n", factory->device_window, factory);
    }

    wined3d_mutex_unlock();

    return factory->device_window;
}
