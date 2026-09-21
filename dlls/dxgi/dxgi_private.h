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
 */

#ifndef __WINE_DXGI_PRIVATE_H
#define __WINE_DXGI_PRIVATE_H

#include "wine/debug.h"

#include <assert.h>

#define COBJMACROS
#include "winbase.h"
#include "wingdi.h"
#include "winuser.h"
#include "objbase.h"
#include "winnls.h"

#include "dxgi1_6.h"
#include "d3d10_1.h"
#include "d3d12.h"
#include "ddk/d3dkmthk.h"
#ifdef DXGI_INIT_GUID
#include "initguid.h"
#endif
#include "wine/wined3d.h"
#include "wine/winedxgi.h"

enum dxgi_frame_latency
{
    DXGI_FRAME_LATENCY_MAX     = 16,
};

/* Undocumented interfaces used by the desktop compositor. */
typedef struct IDXGIAdapterDWM IDXGIAdapterDWM;
typedef struct IDXGIAdapterPartner IDXGIAdapterPartner;
typedef struct IDXGIFactoryDWM IDXGIFactoryDWM;
typedef struct IDXGIFactoryDWM2 IDXGIFactoryDWM2;
typedef struct IDXGIFactoryPartner IDXGIFactoryPartner;
typedef struct IDXGIOutputDWM IDXGIOutputDWM;
typedef struct IDXGISwapChainDWM1 IDXGISwapChainDWM1;

enum dxgi_output_dwm_display_flags
{
    DXGI_OUTPUT_DWM_DISPLAY_FLAG_PRIMARY = 0x4,
    DXGI_OUTPUT_DWM_DISPLAY_FLAG_ATTACHED_TO_DESKTOP = 0x8,
};

#pragma pack(push, 4)
struct dxgi_output_dwm_desc
{
    LUID adapter_luid;
    UINT vidpn_source_id;
    UINT vidpn_target_id;
    UINT display_id;
    LUID output_luid;
    UINT monitor_resolution_width;
    UINT monitor_resolution_height;
    DXGI_FORMAT pixel_format;
    DXGI_RATIONAL refresh_rate;
    DXGI_RATIONAL minimum_refresh_rate;
    DXGI_RATIONAL maximum_refresh_rate;
    UINT boost_refresh_rate_multiplier;
    DXGI_MODE_ROTATION rotation;
    DXGI_MODE_SCANLINE_ORDER scanline_ordering;
    RECT clip_box;
    RECT content_resolution;
    UINT flags;
    WCHAR display_name[CCHDEVICENAME];
    float sdr_white_level;
    UINT sync_lock_group_id;
    UINT sync_lock_style;
    DXGI_FORMAT hdr_pixel_format;
    UINT64 umd_driver_version;
};
#pragma pack(pop)

struct dxgi_frame_statistics_dwm
{
    UINT present_count;
    UINT present_refresh_count;
    LARGE_INTEGER present_qpc_time;
    UINT sync_refresh_count;
    LARGE_INTEGER sync_qpc_time;
    UINT custom_present_duration;
    UINT virtual_sync_refresh_count;
    LARGE_INTEGER virtual_sync_qpc_time;
    UINT virtual_present_refresh_count;
    LARGE_INTEGER virtual_present_qpc_time;
    LARGE_INTEGER vsync_duration_qpc_time;
    UINT vsync_multiplier;
};

struct dxgi_multiplane_overlay_group_caps
{
    UINT max_rgb_planes;
    UINT max_yuv_planes;
    UINT overlay_caps;
    float max_stretch_factor;
    float max_shrink_factor;
};

struct dxgi_multiplane_overlay_caps
{
    UINT max_planes;
    struct dxgi_multiplane_overlay_group_caps overlay;
    struct dxgi_multiplane_overlay_group_caps panel_fitter;
};

C_ASSERT(sizeof(struct dxgi_output_dwm_desc) == 0xc8);
C_ASSERT(sizeof(struct dxgi_frame_statistics_dwm) == 0x50);
C_ASSERT(sizeof(struct dxgi_multiplane_overlay_caps) == 0x2c);
C_ASSERT(offsetof(struct dxgi_output_dwm_desc, monitor_resolution_width) == 0x1c);
C_ASSERT(offsetof(struct dxgi_output_dwm_desc, content_resolution) == 0x5c);
C_ASSERT(offsetof(struct dxgi_output_dwm_desc, display_name) == 0x70);

struct IDXGIAdapterDWMVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IDXGIAdapterDWM *iface, REFIID iid, void **object);
    ULONG (STDMETHODCALLTYPE *AddRef)(IDXGIAdapterDWM *iface);
    ULONG (STDMETHODCALLTYPE *Release)(IDXGIAdapterDWM *iface);
    HRESULT (STDMETHODCALLTYPE *OpenKernelHandle)(IDXGIAdapterDWM *iface, HANDLE *handle);
    HRESULT (STDMETHODCALLTYPE *CloseKernelHandle)(IDXGIAdapterDWM *iface, HANDLE handle);
    HRESULT (STDMETHODCALLTYPE *EnumOutputs)(IDXGIAdapterDWM *iface, UINT output_idx,
            UINT output_class, IDXGIOutput **output);
};

struct IDXGIAdapterDWM
{
    const struct IDXGIAdapterDWMVtbl *lpVtbl;
};

enum dxgi_internal_adapter_role
{
    DXGI_INTERNAL_ADAPTER_ROLE_UNKNOWN = 0,
    DXGI_INTERNAL_ADAPTER_ROLE_STANDALONE = 1,
    DXGI_INTERNAL_ADAPTER_ROLE_HYBRID_INTEGRATED = 2,
    DXGI_INTERNAL_ADAPTER_ROLE_HYBRID_DISCRETE = 3,
};

struct IDXGIAdapterPartnerVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IDXGIAdapterPartner *iface, REFIID iid, void **object);
    ULONG (STDMETHODCALLTYPE *AddRef)(IDXGIAdapterPartner *iface);
    ULONG (STDMETHODCALLTYPE *Release)(IDXGIAdapterPartner *iface);
    enum dxgi_internal_adapter_role (STDMETHODCALLTYPE *GetAdapterRole)(IDXGIAdapterPartner *iface);
};

struct IDXGIAdapterPartner
{
    const struct IDXGIAdapterPartnerVtbl *lpVtbl;
};

struct IDXGIFactoryDWMVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IDXGIFactoryDWM *iface, REFIID iid, void **object);
    ULONG (STDMETHODCALLTYPE *AddRef)(IDXGIFactoryDWM *iface);
    ULONG (STDMETHODCALLTYPE *Release)(IDXGIFactoryDWM *iface);
    HRESULT (STDMETHODCALLTYPE *CreateSwapChain)(IDXGIFactoryDWM *iface, IUnknown *device,
            DXGI_SWAP_CHAIN_DESC *desc, IDXGIOutput *output, IDXGISwapChainDWM1 **swapchain);
};

struct IDXGIFactoryDWM
{
    const struct IDXGIFactoryDWMVtbl *lpVtbl;
};

struct IDXGIFactoryDWM2Vtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IDXGIFactoryDWM2 *iface, REFIID iid, void **object);
    ULONG (STDMETHODCALLTYPE *AddRef)(IDXGIFactoryDWM2 *iface);
    ULONG (STDMETHODCALLTYPE *Release)(IDXGIFactoryDWM2 *iface);
    HRESULT (STDMETHODCALLTYPE *CreateSwapChainDWM)(IDXGIFactoryDWM2 *iface, IUnknown *device,
            DXGI_SWAP_CHAIN_DESC1 *desc, DXGI_SWAP_CHAIN_FULLSCREEN_DESC *fullscreen_desc,
            IDXGIOutput *output, IUnknown **swapchain);
    HRESULT (STDMETHODCALLTYPE *CreateSwapChainDDA)(IDXGIFactoryDWM2 *iface, IUnknown *device,
            DXGI_SWAP_CHAIN_DESC1 *desc, IDXGIOutput *output, IUnknown **swapchain);
    HRESULT (STDMETHODCALLTYPE *CreateSwapChainDWMFromHandle)(IDXGIFactoryDWM2 *iface,
            IUnknown *device, DXGI_SWAP_CHAIN_DESC1 *desc,
            DXGI_SWAP_CHAIN_FULLSCREEN_DESC *fullscreen_desc, HANDLE handle, IUnknown **swapchain);
    HRESULT (STDMETHODCALLTYPE *CreateSwapChainDDAFromHandle)(IDXGIFactoryDWM2 *iface,
            IUnknown *device, DXGI_SWAP_CHAIN_DESC1 *desc, HANDLE handle, IUnknown **swapchain);
    HRESULT (STDMETHODCALLTYPE *EnumOutputByLuid)(IDXGIFactoryDWM2 *iface,
            LUID output_luid, REFIID iid, void **output);
    HRESULT (STDMETHODCALLTYPE *CreateExclusiveWindowlessSwapChain)(IDXGIFactoryDWM2 *iface,
            IUnknown *device, DXGI_SWAP_CHAIN_DESC1 *desc,
            DXGI_SWAP_CHAIN_FULLSCREEN_DESC *fullscreen_desc, IDXGIOutput *output,
            IUnknown **swapchain);
};

struct IDXGIFactoryDWM2
{
    const struct IDXGIFactoryDWM2Vtbl *lpVtbl;
};

struct IDXGIFactoryPartnerVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IDXGIFactoryPartner *iface, REFIID iid, void **object);
    ULONG (STDMETHODCALLTYPE *AddRef)(IDXGIFactoryPartner *iface);
    ULONG (STDMETHODCALLTYPE *Release)(IDXGIFactoryPartner *iface);
    HRESULT (STDMETHODCALLTYPE *CreateIndirectSwapChain)(IDXGIFactoryPartner *iface,
            IDXGIDevice *device, UINT resource_count, IDXGIResource **resources, HANDLE handle,
            UINT flags, const SECURITY_ATTRIBUTES *attributes, DWORD access, const WCHAR *name,
            HANDLE *shared_handle, IUnknown **swapchain);
    HRESULT (STDMETHODCALLTYPE *OpenIndirectSwapChainFromHandle)(IDXGIFactoryPartner *iface,
            IDXGIDevice *device, HANDLE handle, HANDLE metadata_handle, UINT flags,
            UINT resource_count, IUnknown **swapchain);
    HRESULT (STDMETHODCALLTYPE *OpenIndirectSwapChainFromName)(IDXGIFactoryPartner *iface,
            IDXGIDevice *device, DWORD access, BOOL inherit, const WCHAR *name,
            HANDLE metadata_handle, UINT flags, UINT resource_count, IUnknown **swapchain);
    HRESULT (STDMETHODCALLTYPE *ApplicationPresentationMode)(IDXGIFactoryPartner *iface,
            HWND window, HANDLE handle, UINT *mode, REFIID iid, void **object);
    HRESULT (STDMETHODCALLTYPE *CreateIndirectSwapChain12)(IDXGIFactoryPartner *iface,
            ID3D12Device *device, UINT resource_count, ID3D12Resource **resources, HANDLE handle,
            UINT flags, const SECURITY_ATTRIBUTES *attributes, DWORD access, const WCHAR *name,
            HANDLE *shared_handle, IUnknown **swapchain);
    HRESULT (STDMETHODCALLTYPE *OpenIndirectSwapChainFromHandle12)(IDXGIFactoryPartner *iface,
            ID3D12Device *device, HANDLE handle, HANDLE metadata_handle, UINT flags,
            UINT resource_count, IUnknown **swapchain);
    HRESULT (STDMETHODCALLTYPE *OpenIndirectSwapChainFromName12)(IDXGIFactoryPartner *iface,
            ID3D12Device *device, DWORD access, BOOL inherit, const WCHAR *name,
            HANDLE metadata_handle, UINT flags, UINT resource_count, IUnknown **swapchain);
};

struct IDXGIFactoryPartner
{
    const struct IDXGIFactoryPartnerVtbl *lpVtbl;
};

struct IDXGIOutputDWMVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IDXGIOutputDWM *iface, REFIID iid, void **object);
    ULONG (STDMETHODCALLTYPE *AddRef)(IDXGIOutputDWM *iface);
    ULONG (STDMETHODCALLTYPE *Release)(IDXGIOutputDWM *iface);
    BOOL (STDMETHODCALLTYPE *HasDDAClient)(IDXGIOutputDWM *iface);
    HRESULT (STDMETHODCALLTYPE *GetDesc)(IDXGIOutputDWM *iface, struct dxgi_output_dwm_desc *desc);
    HRESULT (STDMETHODCALLTYPE *FindClosestMatchingModeFromDesktop)(IDXGIOutputDWM *iface,
            const DXGI_MODE_DESC1 *mode, DXGI_MODE_DESC1 *closest_match, IUnknown *device);
    HRESULT (STDMETHODCALLTYPE *WaitForVBlankOrObjects)(IDXGIOutputDWM *iface,
            UINT object_count, const HANDLE *objects);
    HRESULT (STDMETHODCALLTYPE *SetSyncRefreshCountWaitTarget)(IDXGIOutputDWM *iface, UINT target);
    HRESULT (STDMETHODCALLTYPE *GetFrameStatisticsDWM)(IDXGIOutputDWM *iface,
            struct dxgi_frame_statistics_dwm *statistics);
    HRESULT (STDMETHODCALLTYPE *GetVBlankEvent)(IDXGIOutputDWM *iface, HANDLE *event);
    BOOL (STDMETHODCALLTYPE *IsIndependentFlipSupported)(IDXGIOutputDWM *iface);
    HRESULT (STDMETHODCALLTYPE *GetMultiplaneOverlayCaps)(IDXGIOutputDWM *iface,
            IUnknown *device, struct dxgi_multiplane_overlay_caps *caps);
    HRESULT (STDMETHODCALLTYPE *GetStereoCaps)(IDXGIOutputDWM *iface, DWORD *caps);
};

struct IDXGIOutputDWM
{
    const struct IDXGIOutputDWMVtbl *lpVtbl;
};

struct IDXGISwapChainDWM1Vtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IDXGISwapChainDWM1 *iface,
            REFIID iid, void **object);
    ULONG (STDMETHODCALLTYPE *AddRef)(IDXGISwapChainDWM1 *iface);
    ULONG (STDMETHODCALLTYPE *Release)(IDXGISwapChainDWM1 *iface);
    HRESULT (STDMETHODCALLTYPE *SetPrivateData)(IDXGISwapChainDWM1 *iface,
            REFGUID guid, UINT data_size, const void *data);
    HRESULT (STDMETHODCALLTYPE *SetPrivateDataInterface)(IDXGISwapChainDWM1 *iface,
            REFGUID guid, const IUnknown *object);
    HRESULT (STDMETHODCALLTYPE *GetPrivateData)(IDXGISwapChainDWM1 *iface,
            REFGUID guid, UINT *data_size, void *data);
    HRESULT (STDMETHODCALLTYPE *GetParent)(IDXGISwapChainDWM1 *iface,
            REFIID iid, void **parent);
    HRESULT (STDMETHODCALLTYPE *GetDevice)(IDXGISwapChainDWM1 *iface,
            REFIID iid, void **device);
    HRESULT (STDMETHODCALLTYPE *Present)(IDXGISwapChainDWM1 *iface,
            UINT sync_interval, UINT flags);
    HRESULT (STDMETHODCALLTYPE *GetBuffer)(IDXGISwapChainDWM1 *iface,
            UINT buffer_idx, REFIID iid, void **surface);
    HRESULT (STDMETHODCALLTYPE *GetDesc)(IDXGISwapChainDWM1 *iface,
            DXGI_SWAP_CHAIN_DESC *desc);
    HRESULT (STDMETHODCALLTYPE *ResizeBuffers)(IDXGISwapChainDWM1 *iface,
            UINT buffer_count, UINT width, UINT height, DXGI_FORMAT format, UINT flags);
    HRESULT (STDMETHODCALLTYPE *ResizeTarget)(IDXGISwapChainDWM1 *iface,
            const DXGI_MODE_DESC *target_mode_desc);
    HRESULT (STDMETHODCALLTYPE *GetContainingOutput)(IDXGISwapChainDWM1 *iface,
            IDXGIOutput **output);
    HRESULT (STDMETHODCALLTYPE *GetFrameStatistics)(IDXGISwapChainDWM1 *iface,
            DXGI_FRAME_STATISTICS *statistics);
    HRESULT (STDMETHODCALLTYPE *GetLastPresentCount)(IDXGISwapChainDWM1 *iface,
            UINT *last_present_count);
    HRESULT (STDMETHODCALLTYPE *PresentDWM)(IDXGISwapChainDWM1 *iface,
            UINT sync_interval, UINT flags, UINT dirty_rect_count, const RECT *dirty_rects,
            UINT scroll_rect_count, const void *scroll_rects, IDXGIResource *resource,
            UINT private_flags);
    HRESULT (STDMETHODCALLTYPE *GetLogicalSurfaceHandle)(IDXGISwapChainDWM1 *iface,
            UINT64 *handle);
    HRESULT (STDMETHODCALLTYPE *CheckDirectFlipSupport)(IDXGISwapChainDWM1 *iface,
            UINT flags, IDXGIResource *resource, BOOL *supported);
    HRESULT (STDMETHODCALLTYPE *GetCompositionSurface)(IDXGISwapChainDWM1 *iface,
            void **surface);
    HRESULT (STDMETHODCALLTYPE *GetFrameStatisticsDWM)(IDXGISwapChainDWM1 *iface,
            struct dxgi_frame_statistics_dwm *statistics);
    HRESULT (STDMETHODCALLTYPE *GetMultiplaneOverlayCaps)(IDXGISwapChainDWM1 *iface,
            struct dxgi_multiplane_overlay_caps *caps);
    HRESULT (STDMETHODCALLTYPE *CheckMultiplaneOverlaySupport)(IDXGISwapChainDWM1 *iface,
            UINT plane_count, const void *plane_info, BOOL *supported, UINT *flags);
    HRESULT (STDMETHODCALLTYPE *PresentMultiplaneOverlay)(IDXGISwapChainDWM1 *iface,
            UINT sync_interval, UINT present_flags, DXGI_HDR_METADATA_TYPE metadata_type,
            const void *metadata, UINT plane_count, const void *planes);
    HRESULT (STDMETHODCALLTYPE *CheckPresentDurationSupport)(IDXGISwapChainDWM1 *iface,
            UINT desired_duration, UINT *closest_smaller, UINT *closest_larger);
    HRESULT (STDMETHODCALLTYPE *SetPrivateFrameDuration)(IDXGISwapChainDWM1 *iface,
            UINT numerator, UINT denominator);
    HRESULT (STDMETHODCALLTYPE *SetHardwareProtection)(IDXGISwapChainDWM1 *iface,
            BOOL enabled);
    HRESULT (STDMETHODCALLTYPE *GetHardwareProtection)(IDXGISwapChainDWM1 *iface,
            BOOL *enabled);
    HRESULT (STDMETHODCALLTYPE *SetLatencyHint)(IDXGISwapChainDWM1 *iface, UINT hint);
    HRESULT (STDMETHODCALLTYPE *SwapBuffers)(IDXGISwapChainDWM1 *iface,
            UINT first_buffer, UINT second_buffer);
    HRESULT (STDMETHODCALLTYPE *CheckDwmVidPnOwnership)(IDXGISwapChainDWM1 *iface,
            BOOL *owned);
    UINT (STDMETHODCALLTYPE *GetCurrentBackBufferIndex)(IDXGISwapChainDWM1 *iface);
    UINT (STDMETHODCALLTYPE *GetBackBufferImplicitRotationCount)(IDXGISwapChainDWM1 *iface);
    UINT (STDMETHODCALLTYPE *GetFrontBufferRenderingCapability)(IDXGISwapChainDWM1 *iface);
    HRESULT (STDMETHODCALLTYPE *SetFrontBufferRenderingMode)(IDXGISwapChainDWM1 *iface,
            BOOL enabled);
};

struct IDXGISwapChainDWM1
{
    const struct IDXGISwapChainDWM1Vtbl *lpVtbl;
};

/* Layered device */
enum dxgi_device_layer_id
{
    DXGI_DEVICE_LAYER_DEBUG1        = 0x8,
    DXGI_DEVICE_LAYER_THREAD_SAFE   = 0x10,
    DXGI_DEVICE_LAYER_DEBUG2        = 0x20,
    DXGI_DEVICE_LAYER_SWITCH_TO_REF = 0x30,
    DXGI_DEVICE_LAYER_D3D10_DEVICE  = 0xffffffff,
};

struct layer_get_size_args
{
    DWORD unknown0;
    DWORD unknown1;
    DWORD *unknown2;
    DWORD *unknown3;
    IDXGIAdapter *adapter;
    WORD interface_major;
    WORD interface_minor;
    WORD version_build;
    WORD version_revision;
};

struct dxgi_device_layer
{
    enum dxgi_device_layer_id id;
    HRESULT (WINAPI *init)(enum dxgi_device_layer_id id, DWORD *count, DWORD *values);
    UINT (WINAPI *get_size)(enum dxgi_device_layer_id id, struct layer_get_size_args *args, DWORD unknown0);
    HRESULT (WINAPI *create)(enum dxgi_device_layer_id id, void **layer_base, DWORD unknown0,
            void *device_object, REFIID riid, void **device_layer);
};

/* TRACE helper functions */
const char *debug_dxgi_format(DXGI_FORMAT format);
const char *debug_dxgi_mode(const DXGI_MODE_DESC *desc);
const char *debug_dxgi_mode1(const DXGI_MODE_DESC1 *desc);
void dump_feature_levels(const D3D_FEATURE_LEVEL *feature_levels, unsigned int level_count);

DXGI_FORMAT dxgi_format_from_wined3dformat(enum wined3d_format_id format);
enum wined3d_format_id wined3dformat_from_dxgi_format(DXGI_FORMAT format);
void dxgi_sample_desc_from_wined3d(DXGI_SAMPLE_DESC *desc,
        enum wined3d_multisample_type wined3d_type, unsigned int wined3d_quality);
void wined3d_sample_desc_from_dxgi(enum wined3d_multisample_type *wined3d_type,
        unsigned int *wined3d_quality, const DXGI_SAMPLE_DESC *dxgi_desc);
void wined3d_display_mode_from_dxgi(struct wined3d_display_mode *wined3d_mode,
        const DXGI_MODE_DESC *mode);
void wined3d_display_mode_from_dxgi1(struct wined3d_display_mode *wined3d_mode,
        const DXGI_MODE_DESC1 *mode);
DXGI_USAGE dxgi_usage_from_wined3d_bind_flags(unsigned int wined3d_bind_flags);
unsigned int wined3d_bind_flags_from_dxgi_usage(DXGI_USAGE usage);
unsigned int dxgi_swapchain_flags_from_wined3d(unsigned int wined3d_flags);
unsigned int wined3d_swapchain_flags_from_dxgi(unsigned int flags);
HRESULT dxgi_get_output_from_window(IWineDXGIFactory *factory, HWND window, IDXGIOutput **dxgi_output)
       ;
HRESULT wined3d_swapchain_desc_from_dxgi(struct wined3d_swapchain_desc *wined3d_desc,
        IDXGIOutput *dxgi_containing_output, HWND window, const DXGI_SWAP_CHAIN_DESC1 *dxgi_desc,
        const DXGI_SWAP_CHAIN_FULLSCREEN_DESC *dxgi_fullscreen_desc);

HRESULT dxgi_get_private_data(struct wined3d_private_store *store,
        REFGUID guid, UINT *data_size, void *data);
HRESULT dxgi_set_private_data(struct wined3d_private_store *store,
        REFGUID guid, UINT data_size, const void *data);
HRESULT dxgi_set_private_data_interface(struct wined3d_private_store *store,
        REFGUID guid, const IUnknown *object);

/* IDXGIFactory */
struct dxgi_factory
{
    IWineDXGIFactory IWineDXGIFactory_iface;
    IDXGIFactoryDWM IDXGIFactoryDWM_iface;
    IDXGIFactoryDWM2 IDXGIFactoryDWM2_iface;
    IDXGIFactoryPartner IDXGIFactoryPartner_iface;
    IDXGIDisplayControl IDXGIDisplayControl_iface;
    LONG refcount;
    struct wined3d_private_store private_store;
    CRITICAL_SECTION adapter_change_cs;
    struct list adapter_change_notifications;
    struct wined3d *wined3d;
    BOOL extended;
    HWND device_window;
};

HRESULT dxgi_factory_create(REFIID riid, void **factory, BOOL extended);
HWND dxgi_factory_get_device_window(struct dxgi_factory *factory);
struct dxgi_factory *unsafe_impl_from_IDXGIFactory(IDXGIFactory *iface);

/* IDXGIDevice */
struct dxgi_device
{
    IWineDXGIDevice IWineDXGIDevice_iface;
    IWineDXGISwapChainFactory IWineDXGISwapChainFactory_iface;
    IUnknown IDXGIDeviceXAML_iface;
    IUnknown IDXGIDeviceDWM_iface;
    IUnknown *child_layer;
    LONG refcount;
    LONG in_process_gpu_priority;
    struct wined3d_private_store private_store;
    struct wined3d_device *wined3d_device;
    struct wined3d_swapchain *implicit_swapchain;
    IWineDXGIAdapter *adapter;
};

HRESULT dxgi_device_init(struct dxgi_device *device, struct dxgi_device_layer *layer,
        IDXGIFactory *factory, IDXGIAdapter *adapter,
        const D3D_FEATURE_LEVEL *feature_levels, unsigned int level_count);

/* IDXGIOutput */
struct dxgi_output
{
    IDXGIOutput6 IDXGIOutput6_iface;
    IDXGIOutputDWM IDXGIOutputDWM_iface;
    LONG refcount;
    struct wined3d_output *wined3d_output;
    struct wined3d_private_store private_store;
    struct dxgi_adapter *adapter;
    HANDLE vblank_timer;
};

HRESULT dxgi_output_create(struct dxgi_adapter *adapter, unsigned int output_idx,
        struct dxgi_output **output);
struct dxgi_output *unsafe_impl_from_IDXGIOutput(IDXGIOutput *iface);

/* IDXGIAdapter */
struct dxgi_adapter
{
    IWineDXGIAdapter IWineDXGIAdapter_iface;
    IDXGIAdapterDWM IDXGIAdapterDWM_iface;
    IDXGIAdapterPartner IDXGIAdapterPartner_iface;
    LONG refcount;
    struct wined3d_adapter *wined3d_adapter;
    struct wined3d_private_store private_store;
    UINT ordinal;
    struct dxgi_factory *factory;
};

HRESULT dxgi_adapter_create(struct dxgi_factory *factory, UINT ordinal,
        struct dxgi_adapter **adapter);
struct dxgi_adapter *unsafe_impl_from_IDXGIAdapter(IDXGIAdapter *iface);

/* IDXGISwapChain */
struct d3d11_swapchain
{
    IDXGISwapChain4 IDXGISwapChain4_iface;
    IDXGISwapChainDWM1 IDXGISwapChainDWM1_iface;
    LONG refcount;
    struct wined3d_private_store private_store;
    struct wined3d_swapchain *wined3d_swapchain;
    struct wined3d_swapchain_state_parent state_parent;
    IWineDXGIDevice *device;
    IWineDXGIFactory *factory;

    DXGI_SWAP_CHAIN_FULLSCREEN_DESC fullscreen_desc;
    IDXGIOutput *target;
    LONG present_count;
    LARGE_INTEGER last_present_qpc;
    DXGI_SWAP_CHAIN_DESC dwm_desc;
    UINT private_frame_duration_numerator;
    UINT private_frame_duration_denominator;
    UINT latency_hint;
    BOOL is_dwm;
    BOOL front_buffer_rendering;
    HWND dwm_host_window;
    LONG in_set_fullscreen_state;
};

HRESULT d3d11_swapchain_init(struct d3d11_swapchain *swapchain, struct dxgi_device *device,
        struct wined3d_swapchain_desc *desc, const DXGI_SWAP_CHAIN_FULLSCREEN_DESC *fullscreen_desc);
void d3d11_swapchain_set_dwm_mode(IDXGISwapChain1 *iface,
        const DXGI_SWAP_CHAIN_DESC *desc, HWND host_window);

HRESULT d3d12_swapchain_create(IWineDXGIFactory *factory, ID3D12CommandQueue *queue, HWND window,
        const DXGI_SWAP_CHAIN_DESC1 *swapchain_desc, const DXGI_SWAP_CHAIN_FULLSCREEN_DESC *fullscreen_desc,
        IDXGISwapChain1 **swapchain);

BOOL dxgi_validate_swapchain_desc(const DXGI_SWAP_CHAIN_DESC1 *desc);
BOOL dxgi_validate_swapchain_fullscreen_desc(const DXGI_SWAP_CHAIN_FULLSCREEN_DESC *desc);

/* IDXGISurface/IDXGIResource */
struct dxgi_resource
{
    IDXGISurface2 IDXGISurface2_iface;
    IDXGIResource1 IDXGIResource1_iface;
    IUnknown IUnknown_iface;
    IUnknown *outer_unknown;
    LONG refcount;
    struct wined3d_private_store private_store;
    IDXGIDevice *device;
    IDXGIResource1 *parent_resource;
    struct wined3d_resource *wined3d_resource;
    unsigned int subresource_idx;
    HDC dc;
};

HRESULT dxgi_resource_init(struct dxgi_resource *resource, IDXGIDevice *device,
        IUnknown *outer, BOOL needs_surface, struct wined3d_resource *wined3d_resource,
        IDXGIResource1 *parent_resource, unsigned int subresource_index);

#endif /* __WINE_DXGI_PRIVATE_H */
