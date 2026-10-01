/* WinRT Windows.Graphics Implementation
 *
 * Copyright 2026 Zhiyi Zhang for CodeWeavers
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

#include "initguid.h"
#include "private.h"
#include "weakreference.h"
#include "winuser.h"

WINE_DEFAULT_DEBUG_CHANNEL(display);

struct display_info
{
    IDisplayInformation IDisplayInformation_iface;
    IDisplayInformation2 IDisplayInformation2_iface;
    IDisplayInformation3 IDisplayInformation3_iface;
    IDisplayInformation4 IDisplayInformation4_iface;
    IDisplayInformation5 IDisplayInformation5_iface;
    IWeakReferenceSource IWeakReferenceSource_iface;
    IWeakReference IWeakReference_iface;
    LONG ref;
    LONG next_token;
};

static inline struct display_info *impl_from_IDisplayInformation( IDisplayInformation *iface )
{
    return CONTAINING_RECORD( iface, struct display_info, IDisplayInformation_iface );
}

static HRESULT WINAPI display_info_QueryInterface( IDisplayInformation *iface, REFIID iid, void **out )
{
    struct display_info *impl = impl_from_IDisplayInformation( iface );

    TRACE( "iface %p, iid %s, out %p.\n", iface, debugstr_guid( iid ), out );

    if (!out) return E_POINTER;
    *out = NULL;

    if (IsEqualGUID( iid, &IID_IUnknown ) || IsEqualGUID( iid, &IID_IInspectable )
            || IsEqualGUID( iid, &IID_IAgileObject ) || IsEqualGUID( iid, &IID_IDisplayInformation ))
        *out = &impl->IDisplayInformation_iface;
    else if (IsEqualGUID( iid, &IID_IDisplayInformation2 ))
        *out = &impl->IDisplayInformation2_iface;
    else if (IsEqualGUID( iid, &IID_IDisplayInformation3 ))
        *out = &impl->IDisplayInformation3_iface;
    else if (IsEqualGUID( iid, &IID_IDisplayInformation4 ))
        *out = &impl->IDisplayInformation4_iface;
    else if (IsEqualGUID( iid, &IID_IDisplayInformation5 ))
        *out = &impl->IDisplayInformation5_iface;
    else if (IsEqualGUID( iid, &IID_IWeakReferenceSource ))
        *out = &impl->IWeakReferenceSource_iface;

    if (!*out)
    {
        FIXME( "%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid( iid ) );
        return E_NOINTERFACE;
    }

    IUnknown_AddRef( (IUnknown *)*out );
    return S_OK;
}

static ULONG WINAPI display_info_AddRef( IDisplayInformation *iface )
{
    struct display_info *impl = impl_from_IDisplayInformation( iface );
    return InterlockedIncrement( &impl->ref );
}

static ULONG WINAPI display_info_Release( IDisplayInformation *iface )
{
    struct display_info *impl = impl_from_IDisplayInformation( iface );
    return InterlockedDecrement( &impl->ref );
}

static HRESULT WINAPI display_info_GetIids( IDisplayInformation *iface, ULONG *iid_count, IID **iids )
{
    FIXME( "iface %p, iid_count %p, iids %p stub!\n", iface, iid_count, iids );
    return E_NOTIMPL;
}

static HRESULT WINAPI display_info_GetRuntimeClassName( IDisplayInformation *iface, HSTRING *class_name )
{
    const WCHAR *name = RuntimeClass_Windows_Graphics_Display_DisplayInformation;

    TRACE( "iface %p, class_name %p.\n", iface, class_name );
    if (!class_name) return E_POINTER;
    return WindowsCreateString( name, wcslen( name ), class_name );
}

static HRESULT WINAPI display_info_GetTrustLevel( IDisplayInformation *iface, TrustLevel *trust_level )
{
    TRACE( "iface %p, trust_level %p.\n", iface, trust_level );
    if (!trust_level) return E_POINTER;
    *trust_level = BaseTrust;
    return S_OK;
}

static DisplayOrientations display_orientation(void)
{
    return GetSystemMetrics( SM_CXSCREEN ) >= GetSystemMetrics( SM_CYSCREEN )
            ? DisplayOrientations_Landscape : DisplayOrientations_Portrait;
}

static FLOAT display_dpi(void)
{
    UINT dpi = GetDpiForSystem();
    return dpi ? dpi : 96.0f;
}

static ResolutionScale display_resolution_scale(void)
{
    static const ResolutionScale scales[] =
    {
        ResolutionScale_Scale100Percent, ResolutionScale_Scale120Percent,
        ResolutionScale_Scale125Percent, ResolutionScale_Scale140Percent,
        ResolutionScale_Scale150Percent, ResolutionScale_Scale160Percent,
        ResolutionScale_Scale175Percent, ResolutionScale_Scale180Percent,
        ResolutionScale_Scale200Percent, ResolutionScale_Scale225Percent,
        ResolutionScale_Scale250Percent, ResolutionScale_Scale300Percent,
        ResolutionScale_Scale350Percent, ResolutionScale_Scale400Percent,
        ResolutionScale_Scale450Percent, ResolutionScale_Scale500Percent,
    };
    UINT percent = (UINT)(display_dpi() * 100.0f / 96.0f + 0.5f);
    UINT best_delta = ~0u;
    ResolutionScale best = ResolutionScale_Scale100Percent;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE( scales ); ++i)
    {
        UINT scale = scales[i], delta = scale > percent ? scale - percent : percent - scale;
        if (delta < best_delta) best = scales[i], best_delta = delta;
    }
    return best;
}

static HRESULT WINAPI display_info_get_CurrentOrientation( IDisplayInformation *iface, DisplayOrientations *value )
{
    if (!value) return E_POINTER;
    *value = display_orientation();
    return S_OK;
}

static HRESULT WINAPI display_info_get_NativeOrientation( IDisplayInformation *iface, DisplayOrientations *value )
{
    if (!value) return E_POINTER;
    *value = display_orientation();
    return S_OK;
}

static HRESULT display_info_add_event( struct display_info *impl, IUnknown *handler, EventRegistrationToken *token )
{
    if (!handler || !token) return E_INVALIDARG;
    token->value = InterlockedIncrement( &impl->next_token );
    return S_OK;
}

static HRESULT WINAPI display_info_add_OrientationChanged( IDisplayInformation *iface,
        ITypedEventHandler_DisplayInformation_IInspectable *handler, EventRegistrationToken *token )
{
    return display_info_add_event( impl_from_IDisplayInformation( iface ), (IUnknown *)handler, token );
}

static HRESULT WINAPI display_info_remove_OrientationChanged( IDisplayInformation *iface,
        EventRegistrationToken token )
{
    return S_OK;
}

static HRESULT WINAPI display_info_get_ResolutionScale( IDisplayInformation *iface, ResolutionScale *value )
{
    if (!value) return E_POINTER;
    *value = display_resolution_scale();
    return S_OK;
}

static HRESULT WINAPI display_info_get_LogicalDpi( IDisplayInformation *iface, FLOAT *value )
{
    if (!value) return E_POINTER;
    *value = display_dpi();
    return S_OK;
}

static HRESULT WINAPI display_info_get_RawDpiX( IDisplayInformation *iface, FLOAT *value )
{
    if (!value) return E_POINTER;
    *value = display_dpi();
    return S_OK;
}

static HRESULT WINAPI display_info_get_RawDpiY( IDisplayInformation *iface, FLOAT *value )
{
    if (!value) return E_POINTER;
    *value = display_dpi();
    return S_OK;
}

static HRESULT WINAPI display_info_add_DpiChanged( IDisplayInformation *iface,
        ITypedEventHandler_DisplayInformation_IInspectable *handler, EventRegistrationToken *token )
{
    return display_info_add_event( impl_from_IDisplayInformation( iface ), (IUnknown *)handler, token );
}

static HRESULT WINAPI display_info_remove_DpiChanged( IDisplayInformation *iface, EventRegistrationToken token )
{
    return S_OK;
}

static HRESULT WINAPI display_info_get_StereoEnabled( IDisplayInformation *iface, boolean *value )
{
    if (!value) return E_POINTER;
    *value = FALSE;
    return S_OK;
}

static HRESULT WINAPI display_info_add_StereoEnabledChanged( IDisplayInformation *iface,
        ITypedEventHandler_DisplayInformation_IInspectable *handler, EventRegistrationToken *token )
{
    return display_info_add_event( impl_from_IDisplayInformation( iface ), (IUnknown *)handler, token );
}

static HRESULT WINAPI display_info_remove_StereoEnabledChanged( IDisplayInformation *iface,
        EventRegistrationToken token )
{
    return S_OK;
}

static HRESULT WINAPI display_info_GetColorProfileAsync( IDisplayInformation *iface,
        __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream **async_info )
{
    if (async_info) *async_info = NULL;
    return E_NOTIMPL;
}

static HRESULT WINAPI display_info_add_ColorProfileChanged( IDisplayInformation *iface,
        ITypedEventHandler_DisplayInformation_IInspectable *handler, EventRegistrationToken *token )
{
    return display_info_add_event( impl_from_IDisplayInformation( iface ), (IUnknown *)handler, token );
}

static HRESULT WINAPI display_info_remove_ColorProfileChanged( IDisplayInformation *iface,
        EventRegistrationToken token )
{
    return S_OK;
}

static const struct IDisplayInformationVtbl display_info_vtbl =
{
    display_info_QueryInterface,
    display_info_AddRef,
    display_info_Release,
    display_info_GetIids,
    display_info_GetRuntimeClassName,
    display_info_GetTrustLevel,
    display_info_get_CurrentOrientation,
    display_info_get_NativeOrientation,
    display_info_add_OrientationChanged,
    display_info_remove_OrientationChanged,
    display_info_get_ResolutionScale,
    display_info_get_LogicalDpi,
    display_info_get_RawDpiX,
    display_info_get_RawDpiY,
    display_info_add_DpiChanged,
    display_info_remove_DpiChanged,
    display_info_get_StereoEnabled,
    display_info_add_StereoEnabledChanged,
    display_info_remove_StereoEnabledChanged,
    display_info_GetColorProfileAsync,
    display_info_add_ColorProfileChanged,
    display_info_remove_ColorProfileChanged,
};

DEFINE_IINSPECTABLE( display_info2, IDisplayInformation2, struct display_info, IDisplayInformation_iface )

static HRESULT WINAPI display_info2_get_RawPixelsPerViewPixel( IDisplayInformation2 *iface, DOUBLE *value )
{
    if (!value) return E_POINTER;
    *value = display_dpi() / 96.0;
    return S_OK;
}

static const struct IDisplayInformation2Vtbl display_info2_vtbl =
{
    display_info2_QueryInterface,
    display_info2_AddRef,
    display_info2_Release,
    display_info2_GetIids,
    display_info2_GetRuntimeClassName,
    display_info2_GetTrustLevel,
    display_info2_get_RawPixelsPerViewPixel,
};

DEFINE_IINSPECTABLE( display_info3, IDisplayInformation3, struct display_info, IDisplayInformation_iface )

static HRESULT WINAPI display_info3_get_DiagonalSizeInInches( IDisplayInformation3 *iface,
        IReference_DOUBLE **value )
{
    if (!value) return E_POINTER;
    *value = NULL;
    return S_OK;
}

static const struct IDisplayInformation3Vtbl display_info3_vtbl =
{
    display_info3_QueryInterface,
    display_info3_AddRef,
    display_info3_Release,
    display_info3_GetIids,
    display_info3_GetRuntimeClassName,
    display_info3_GetTrustLevel,
    display_info3_get_DiagonalSizeInInches,
};

DEFINE_IINSPECTABLE( display_info4, IDisplayInformation4, struct display_info, IDisplayInformation_iface )

static HRESULT WINAPI display_info4_get_ScreenWidthInRawPixels( IDisplayInformation4 *iface, UINT32 *value )
{
    if (!value) return E_POINTER;
    *value = GetSystemMetrics( SM_CXSCREEN );
    return S_OK;
}

static HRESULT WINAPI display_info4_get_ScreenHeightInRawPixels( IDisplayInformation4 *iface, UINT32 *value )
{
    if (!value) return E_POINTER;
    *value = GetSystemMetrics( SM_CYSCREEN );
    return S_OK;
}

static const struct IDisplayInformation4Vtbl display_info4_vtbl =
{
    display_info4_QueryInterface,
    display_info4_AddRef,
    display_info4_Release,
    display_info4_GetIids,
    display_info4_GetRuntimeClassName,
    display_info4_GetTrustLevel,
    display_info4_get_ScreenWidthInRawPixels,
    display_info4_get_ScreenHeightInRawPixels,
};

DEFINE_IINSPECTABLE( display_info5, IDisplayInformation5, struct display_info, IDisplayInformation_iface )

static HRESULT WINAPI display_info5_GetAdvancedColorInfo( IDisplayInformation5 *iface,
        IAdvancedColorInfo **value )
{
    if (value) *value = NULL;
    return E_NOTIMPL;
}

static HRESULT WINAPI display_info5_add_AdvancedColorInfoChanged( IDisplayInformation5 *iface,
        ITypedEventHandler_DisplayInformation_IInspectable *handler, EventRegistrationToken *token )
{
    struct display_info *impl = impl_from_IDisplayInformation5( iface );
    return display_info_add_event( impl, (IUnknown *)handler, token );
}

static HRESULT WINAPI display_info5_remove_AdvancedColorInfoChanged( IDisplayInformation5 *iface,
        EventRegistrationToken token )
{
    return S_OK;
}

static const struct IDisplayInformation5Vtbl display_info5_vtbl =
{
    display_info5_QueryInterface,
    display_info5_AddRef,
    display_info5_Release,
    display_info5_GetIids,
    display_info5_GetRuntimeClassName,
    display_info5_GetTrustLevel,
    display_info5_GetAdvancedColorInfo,
    display_info5_add_AdvancedColorInfoChanged,
    display_info5_remove_AdvancedColorInfoChanged,
};

static inline struct display_info *impl_from_IWeakReferenceSource( IWeakReferenceSource *iface )
{
    return CONTAINING_RECORD( iface, struct display_info, IWeakReferenceSource_iface );
}

static HRESULT WINAPI weak_source_QueryInterface( IWeakReferenceSource *iface, REFIID iid, void **out )
{
    struct display_info *impl = impl_from_IWeakReferenceSource( iface );
    return IDisplayInformation_QueryInterface( &impl->IDisplayInformation_iface, iid, out );
}

static ULONG WINAPI weak_source_AddRef( IWeakReferenceSource *iface )
{
    struct display_info *impl = impl_from_IWeakReferenceSource( iface );
    return IDisplayInformation_AddRef( &impl->IDisplayInformation_iface );
}

static ULONG WINAPI weak_source_Release( IWeakReferenceSource *iface )
{
    struct display_info *impl = impl_from_IWeakReferenceSource( iface );
    return IDisplayInformation_Release( &impl->IDisplayInformation_iface );
}

static HRESULT WINAPI weak_source_GetWeakReference( IWeakReferenceSource *iface, IWeakReference **out )
{
    struct display_info *impl = impl_from_IWeakReferenceSource( iface );

    if (!out) return E_POINTER;
    *out = &impl->IWeakReference_iface;
    IWeakReference_AddRef( *out );
    return S_OK;
}

static const struct IWeakReferenceSourceVtbl weak_source_vtbl =
{
    weak_source_QueryInterface,
    weak_source_AddRef,
    weak_source_Release,
    weak_source_GetWeakReference,
};

static inline struct display_info *impl_from_IWeakReference( IWeakReference *iface )
{
    return CONTAINING_RECORD( iface, struct display_info, IWeakReference_iface );
}

static HRESULT WINAPI weak_reference_QueryInterface( IWeakReference *iface, REFIID iid, void **out )
{
    struct display_info *impl = impl_from_IWeakReference( iface );

    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualGUID( iid, &IID_IUnknown ) || IsEqualGUID( iid, &IID_IWeakReference ))
        *out = &impl->IWeakReference_iface;
    if (!*out) return E_NOINTERFACE;
    IWeakReference_AddRef( *out );
    return S_OK;
}

static ULONG WINAPI weak_reference_AddRef( IWeakReference *iface )
{
    struct display_info *impl = impl_from_IWeakReference( iface );
    return InterlockedIncrement( &impl->ref );
}

static ULONG WINAPI weak_reference_Release( IWeakReference *iface )
{
    struct display_info *impl = impl_from_IWeakReference( iface );
    return InterlockedDecrement( &impl->ref );
}

static HRESULT WINAPI weak_reference_Resolve( IWeakReference *iface, REFIID iid, IInspectable **out )
{
    struct display_info *impl = impl_from_IWeakReference( iface );

    if (!out) return E_POINTER;
    return IDisplayInformation_QueryInterface( &impl->IDisplayInformation_iface, iid, (void **)out );
}

static const struct IWeakReferenceVtbl weak_reference_vtbl =
{
    weak_reference_QueryInterface,
    weak_reference_AddRef,
    weak_reference_Release,
    weak_reference_Resolve,
};

static struct display_info display_info =
{
    {&display_info_vtbl},
    {&display_info2_vtbl},
    {&display_info3_vtbl},
    {&display_info4_vtbl},
    {&display_info5_vtbl},
    {&weak_source_vtbl},
    {&weak_reference_vtbl},
    1,
    0,
};

struct display_info_statics
{
    IActivationFactory IActivationFactory_iface;
    IDisplayInformationStatics IDisplayInformationStatics_iface;
    LONG ref;
};

static inline struct display_info_statics *impl_from_IActivationFactory( IActivationFactory *iface )
{
    return CONTAINING_RECORD( iface, struct display_info_statics, IActivationFactory_iface );
}

static HRESULT WINAPI factory_QueryInterface( IActivationFactory *iface, REFIID iid, void **out )
{
    struct display_info_statics *impl = impl_from_IActivationFactory( iface );

    TRACE( "iface %p, iid %s, out %p.\n", iface, debugstr_guid( iid ), out );

    if (IsEqualGUID( iid, &IID_IUnknown )
        || IsEqualGUID( iid, &IID_IInspectable )
        || IsEqualGUID( iid, &IID_IActivationFactory ))
    {
        *out = &impl->IActivationFactory_iface;
        IActivationFactory_AddRef( *out );
        return S_OK;
    }
    else if (IsEqualGUID( iid, &IID_IDisplayInformationStatics ))
    {
        *out = &impl->IDisplayInformationStatics_iface;
        IDisplayInformationStatics_AddRef( *out );
        return S_OK;
    }

    FIXME( "%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid( iid ) );
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI factory_AddRef( IActivationFactory *iface )
{
    struct display_info_statics *impl = impl_from_IActivationFactory( iface );
    ULONG ref = InterlockedIncrement( &impl->ref );
    TRACE( "iface %p, ref %lu.\n", iface, ref );
    return ref;
}

static ULONG WINAPI factory_Release( IActivationFactory *iface )
{
    struct display_info_statics *impl = impl_from_IActivationFactory( iface );
    ULONG ref = InterlockedDecrement( &impl->ref );
    TRACE( "iface %p, ref %lu.\n", iface, ref );
    return ref;
}

static HRESULT WINAPI factory_GetIids( IActivationFactory *iface, ULONG *iid_count, IID **iids )
{
    FIXME( "iface %p, iid_count %p, iids %p stub!\n", iface, iid_count, iids );
    return E_NOTIMPL;
}

static HRESULT WINAPI factory_GetRuntimeClassName( IActivationFactory *iface, HSTRING *class_name )
{
    FIXME( "iface %p, class_name %p stub!\n", iface, class_name );
    return E_NOTIMPL;
}

static HRESULT WINAPI factory_GetTrustLevel( IActivationFactory *iface, TrustLevel *trust_level )
{
    FIXME( "iface %p, trust_level %p stub!\n", iface, trust_level );
    return E_NOTIMPL;
}

static HRESULT WINAPI factory_ActivateInstance( IActivationFactory *iface, IInspectable **instance )
{
    FIXME( "iface %p, instance %p stub!\n", iface, instance );
    return E_NOTIMPL;
}

static const struct IActivationFactoryVtbl factory_vtbl =
{
    factory_QueryInterface,
    factory_AddRef,
    factory_Release,
    /* IInspectable methods */
    factory_GetIids,
    factory_GetRuntimeClassName,
    factory_GetTrustLevel,
    /* IActivationFactory methods */
    factory_ActivateInstance,
};

DEFINE_IINSPECTABLE( display_info_statics, IDisplayInformationStatics, struct display_info_statics,
                     IActivationFactory_iface )

static HRESULT WINAPI display_info_statics_GetForCurrentView( IDisplayInformationStatics *iface,
        IDisplayInformation **current )
{
    TRACE( "iface %p, current %p.\n", iface, current );

    if (!current) return E_POINTER;
    *current = &display_info.IDisplayInformation_iface;
    IDisplayInformation_AddRef( *current );
    return S_OK;
}

static HRESULT WINAPI display_info_statics_get_AutoRotationPreferences( IDisplayInformationStatics *iface,
        DisplayOrientations *value )
{
    FIXME( "iface %p, value %p stub!\n", iface, value );
    return E_NOTIMPL;
}

static HRESULT WINAPI display_info_statics_put_AutoRotationPreferences( IDisplayInformationStatics *iface,
        DisplayOrientations value )
{
    FIXME( "iface %p, value %#x stub!\n", iface, value );
    return E_NOTIMPL;
}

static HRESULT WINAPI display_info_statics_add_DisplayContentsInvalidated( IDisplayInformationStatics *iface,
        ITypedEventHandler_DisplayInformation_IInspectable *handler, EventRegistrationToken *token )
{
    FIXME( "iface %p, handler %p, token %p stub!\n", iface, handler, token );
    return E_NOTIMPL;
}

static HRESULT WINAPI display_info_statics_remove_DisplayContentsInvalidated( IDisplayInformationStatics *iface,
        EventRegistrationToken token )
{
    FIXME( "iface %p, token %I64x stub!\n", iface, token.value );
    return E_NOTIMPL;
}

static const struct IDisplayInformationStaticsVtbl display_info_statics_vtbl =
{
    display_info_statics_QueryInterface,
    display_info_statics_AddRef,
    display_info_statics_Release,
    /* IInspectable methods */
    display_info_statics_GetIids,
    display_info_statics_GetRuntimeClassName,
    display_info_statics_GetTrustLevel,
    /* IDisplayInformationStatics methods */
    display_info_statics_GetForCurrentView,
    display_info_statics_get_AutoRotationPreferences,
    display_info_statics_put_AutoRotationPreferences,
    display_info_statics_add_DisplayContentsInvalidated,
    display_info_statics_remove_DisplayContentsInvalidated
};

static struct display_info_statics display_info_statics =
{
    {&factory_vtbl},
    {&display_info_statics_vtbl},
    1,
};

static IActivationFactory *display_info_factory = &display_info_statics.IActivationFactory_iface;

HRESULT WINAPI DllGetClassObject( REFCLSID clsid, REFIID riid, void **out )
{
    FIXME( "clsid %s, riid %s, out %p stub!\n", debugstr_guid( clsid ), debugstr_guid( riid ), out );
    return CLASS_E_CLASSNOTAVAILABLE;
}

HRESULT WINAPI DllGetActivationFactory( HSTRING classid, IActivationFactory **factory )
{
    const WCHAR *name = WindowsGetStringRawBuffer( classid, NULL );

    TRACE( "classid %s, factory %p.\n", debugstr_hstring( classid ), factory );

    *factory = NULL;

    if (!wcscmp( name, RuntimeClass_Windows_Graphics_Display_DisplayInformation ))
        IActivationFactory_QueryInterface( display_info_factory, &IID_IActivationFactory, (void **)factory );

    return *factory ? S_OK : CLASS_E_CLASSNOTAVAILABLE;
}
