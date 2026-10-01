/* Windows.Storage.AppDataPaths implementation
 *
 * Copyright (C) 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "private.h"
#include "shlobj.h"

WINE_DEFAULT_DEBUG_CHANNEL(storage);

struct app_data_paths
{
    IAppDataPaths IAppDataPaths_iface;
    LONG ref;
};

struct app_data_paths_statics
{
    IActivationFactory IActivationFactory_iface;
    IAppDataPathsStatics IAppDataPathsStatics_iface;
    LONG ref;
};

static inline struct app_data_paths *impl_from_IAppDataPaths( IAppDataPaths *iface )
{
    return CONTAINING_RECORD( iface, struct app_data_paths, IAppDataPaths_iface );
}

static inline struct app_data_paths_statics *factory_from_IActivationFactory( IActivationFactory *iface )
{
    return CONTAINING_RECORD( iface, struct app_data_paths_statics, IActivationFactory_iface );
}

static inline struct app_data_paths_statics *factory_from_IAppDataPathsStatics( IAppDataPathsStatics *iface )
{
    return CONTAINING_RECORD( iface, struct app_data_paths_statics, IAppDataPathsStatics_iface );
}

static HRESULT WINAPI app_data_paths_QueryInterface( IAppDataPaths *iface, REFIID iid, void **out )
{
    if (!out) return E_POINTER;
    *out = NULL;

    if (IsEqualIID( iid, &IID_IUnknown ) || IsEqualIID( iid, &IID_IInspectable ) ||
        IsEqualIID( iid, &IID_IAgileObject ) || IsEqualIID( iid, &IID_IAppDataPaths ))
    {
        *out = iface;
        IAppDataPaths_AddRef( iface );
        return S_OK;
    }

    return E_NOINTERFACE;
}

static ULONG WINAPI app_data_paths_AddRef( IAppDataPaths *iface )
{
    struct app_data_paths *impl = impl_from_IAppDataPaths( iface );
    return InterlockedIncrement( &impl->ref );
}

static ULONG WINAPI app_data_paths_Release( IAppDataPaths *iface )
{
    struct app_data_paths *impl = impl_from_IAppDataPaths( iface );
    ULONG ref = InterlockedDecrement( &impl->ref );

    if (!ref) free( impl );
    return ref;
}

static HRESULT WINAPI app_data_paths_GetIids( IAppDataPaths *iface, ULONG *iid_count, IID **iids )
{
    if (!iid_count || !iids) return E_POINTER;
    *iid_count = 0;
    *iids = CoTaskMemAlloc( sizeof(**iids) );
    if (!*iids) return E_OUTOFMEMORY;
    **iids = IID_IAppDataPaths;
    *iid_count = 1;
    return S_OK;
}

static HRESULT WINAPI app_data_paths_GetRuntimeClassName( IAppDataPaths *iface, HSTRING *class_name )
{
    if (!class_name) return E_POINTER;
    return WindowsCreateString( RuntimeClass_Windows_Storage_AppDataPaths,
            ARRAY_SIZE(RuntimeClass_Windows_Storage_AppDataPaths) - 1, class_name );
}

static HRESULT WINAPI app_data_paths_GetTrustLevel( IAppDataPaths *iface, TrustLevel *trust_level )
{
    if (!trust_level) return E_POINTER;
    *trust_level = BaseTrust;
    return S_OK;
}

static HRESULT app_data_paths_get_known_folder( int csidl, HSTRING *value )
{
    WCHAR path[MAX_PATH];
    HRESULT hr;

    if (!value) return E_POINTER;
    *value = NULL;
    if (FAILED(hr = SHGetFolderPathW( NULL, csidl | CSIDL_FLAG_CREATE, NULL,
            SHGFP_TYPE_CURRENT, path ))) return hr;
    hr = WindowsCreateString( path, wcslen(path), value );
    return hr;
}

#define APP_DATA_PATH_GETTER(name, csidl) \
    static HRESULT WINAPI app_data_paths_get_##name( IAppDataPaths *iface, HSTRING *value ) \
    { \
        TRACE( "iface %p, value %p.\n", iface, value ); \
        return app_data_paths_get_known_folder( csidl, value ); \
    }

APP_DATA_PATH_GETTER( Cookies, CSIDL_COOKIES )
APP_DATA_PATH_GETTER( Desktop, CSIDL_DESKTOPDIRECTORY )
APP_DATA_PATH_GETTER( Documents, CSIDL_PERSONAL )
APP_DATA_PATH_GETTER( Favorites, CSIDL_FAVORITES )
APP_DATA_PATH_GETTER( History, CSIDL_HISTORY )
APP_DATA_PATH_GETTER( InternetCache, CSIDL_INTERNET_CACHE )
APP_DATA_PATH_GETTER( LocalAppData, CSIDL_LOCAL_APPDATA )
APP_DATA_PATH_GETTER( ProgramData, CSIDL_COMMON_APPDATA )
APP_DATA_PATH_GETTER( RoamingAppData, CSIDL_APPDATA )

static const IAppDataPathsVtbl app_data_paths_vtbl =
{
    app_data_paths_QueryInterface,
    app_data_paths_AddRef,
    app_data_paths_Release,
    app_data_paths_GetIids,
    app_data_paths_GetRuntimeClassName,
    app_data_paths_GetTrustLevel,
    app_data_paths_get_Cookies,
    app_data_paths_get_Desktop,
    app_data_paths_get_Documents,
    app_data_paths_get_Favorites,
    app_data_paths_get_History,
    app_data_paths_get_InternetCache,
    app_data_paths_get_LocalAppData,
    app_data_paths_get_ProgramData,
    app_data_paths_get_RoamingAppData,
};

static HRESULT app_data_paths_create( IAppDataPaths **out )
{
    struct app_data_paths *impl;

    if (!out) return E_POINTER;
    *out = NULL;
    if (!(impl = calloc( 1, sizeof(*impl) ))) return E_OUTOFMEMORY;
    impl->IAppDataPaths_iface.lpVtbl = &app_data_paths_vtbl;
    impl->ref = 1;
    *out = &impl->IAppDataPaths_iface;
    return S_OK;
}

static HRESULT WINAPI app_data_paths_factory_QueryInterface( IActivationFactory *iface, REFIID iid, void **out )
{
    struct app_data_paths_statics *impl = factory_from_IActivationFactory( iface );

    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualIID( iid, &IID_IUnknown ) || IsEqualIID( iid, &IID_IInspectable ) ||
        IsEqualIID( iid, &IID_IAgileObject ) || IsEqualIID( iid, &IID_IActivationFactory ))
        *out = &impl->IActivationFactory_iface;
    else if (IsEqualIID( iid, &IID_IAppDataPathsStatics ))
        *out = &impl->IAppDataPathsStatics_iface;
    else
        return E_NOINTERFACE;

    IInspectable_AddRef( (IInspectable *)*out );
    return S_OK;
}

static ULONG WINAPI app_data_paths_factory_AddRef( IActivationFactory *iface )
{
    struct app_data_paths_statics *impl = factory_from_IActivationFactory( iface );
    return InterlockedIncrement( &impl->ref );
}

static ULONG WINAPI app_data_paths_factory_Release( IActivationFactory *iface )
{
    struct app_data_paths_statics *impl = factory_from_IActivationFactory( iface );
    return InterlockedDecrement( &impl->ref );
}

static HRESULT WINAPI app_data_paths_factory_GetIids( IActivationFactory *iface, ULONG *iid_count, IID **iids )
{
    if (!iid_count || !iids) return E_POINTER;
    *iid_count = 0;
    *iids = CoTaskMemAlloc( 2 * sizeof(**iids) );
    if (!*iids) return E_OUTOFMEMORY;
    (*iids)[0] = IID_IActivationFactory;
    (*iids)[1] = IID_IAppDataPathsStatics;
    *iid_count = 2;
    return S_OK;
}

static HRESULT WINAPI app_data_paths_factory_GetRuntimeClassName( IActivationFactory *iface, HSTRING *class_name )
{
    if (!class_name) return E_POINTER;
    return WindowsCreateString( RuntimeClass_Windows_Storage_AppDataPaths,
            ARRAY_SIZE(RuntimeClass_Windows_Storage_AppDataPaths) - 1, class_name );
}

static HRESULT WINAPI app_data_paths_factory_GetTrustLevel( IActivationFactory *iface, TrustLevel *trust_level )
{
    if (!trust_level) return E_POINTER;
    *trust_level = BaseTrust;
    return S_OK;
}

static HRESULT WINAPI app_data_paths_factory_ActivateInstance( IActivationFactory *iface, IInspectable **instance )
{
    if (!instance) return E_POINTER;
    *instance = NULL;
    return E_NOTIMPL;
}

static const IActivationFactoryVtbl app_data_paths_factory_vtbl =
{
    app_data_paths_factory_QueryInterface,
    app_data_paths_factory_AddRef,
    app_data_paths_factory_Release,
    app_data_paths_factory_GetIids,
    app_data_paths_factory_GetRuntimeClassName,
    app_data_paths_factory_GetTrustLevel,
    app_data_paths_factory_ActivateInstance,
};

static HRESULT WINAPI app_data_paths_statics_QueryInterface( IAppDataPathsStatics *iface, REFIID iid, void **out )
{
    struct app_data_paths_statics *impl = factory_from_IAppDataPathsStatics( iface );
    return IActivationFactory_QueryInterface( &impl->IActivationFactory_iface, iid, out );
}

static ULONG WINAPI app_data_paths_statics_AddRef( IAppDataPathsStatics *iface )
{
    struct app_data_paths_statics *impl = factory_from_IAppDataPathsStatics( iface );
    return IActivationFactory_AddRef( &impl->IActivationFactory_iface );
}

static ULONG WINAPI app_data_paths_statics_Release( IAppDataPathsStatics *iface )
{
    struct app_data_paths_statics *impl = factory_from_IAppDataPathsStatics( iface );
    return IActivationFactory_Release( &impl->IActivationFactory_iface );
}

static HRESULT WINAPI app_data_paths_statics_GetIids( IAppDataPathsStatics *iface, ULONG *iid_count, IID **iids )
{
    struct app_data_paths_statics *impl = factory_from_IAppDataPathsStatics( iface );
    return IActivationFactory_GetIids( &impl->IActivationFactory_iface, iid_count, iids );
}

static HRESULT WINAPI app_data_paths_statics_GetRuntimeClassName( IAppDataPathsStatics *iface, HSTRING *class_name )
{
    struct app_data_paths_statics *impl = factory_from_IAppDataPathsStatics( iface );
    return IActivationFactory_GetRuntimeClassName( &impl->IActivationFactory_iface, class_name );
}

static HRESULT WINAPI app_data_paths_statics_GetTrustLevel( IAppDataPathsStatics *iface, TrustLevel *trust_level )
{
    struct app_data_paths_statics *impl = factory_from_IAppDataPathsStatics( iface );
    return IActivationFactory_GetTrustLevel( &impl->IActivationFactory_iface, trust_level );
}

static HRESULT WINAPI app_data_paths_statics_GetForUser( IAppDataPathsStatics *iface,
        __x_ABI_CWindows_CSystem_CIUser *user,
        IAppDataPaths **value )
{
    TRACE( "iface %p, user %p, value %p.\n", iface, user, value );
    if (!user) return E_INVALIDARG;
    return app_data_paths_create( value );
}

static HRESULT WINAPI app_data_paths_statics_GetDefault( IAppDataPathsStatics *iface, IAppDataPaths **value )
{
    TRACE( "iface %p, value %p.\n", iface, value );
    return app_data_paths_create( value );
}

static const IAppDataPathsStaticsVtbl app_data_paths_statics_vtbl =
{
    app_data_paths_statics_QueryInterface,
    app_data_paths_statics_AddRef,
    app_data_paths_statics_Release,
    app_data_paths_statics_GetIids,
    app_data_paths_statics_GetRuntimeClassName,
    app_data_paths_statics_GetTrustLevel,
    app_data_paths_statics_GetForUser,
    app_data_paths_statics_GetDefault,
};

static struct app_data_paths_statics app_data_paths_statics =
{
    {&app_data_paths_factory_vtbl},
    {&app_data_paths_statics_vtbl},
    1,
};

IActivationFactory *app_data_paths_factory = &app_data_paths_statics.IActivationFactory_iface;
