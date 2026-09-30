/*
 * Copyright 2023 Rémi Bernon for CodeWeavers
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

#include <stdarg.h>
#include <stddef.h>

#include "windef.h"
#include "winbase.h"

#define COBJMACROS
#include "initguid.h"
#include "winstring.h"
#include "winternl.h"
#include "roapi.h"
#include "shobjidl_core.h"

#define WIDL_using_Windows_Foundation
#define WIDL_using_Windows_Foundation_Collections
#include "windows.foundation.h"
#define WIDL_using_Windows_Security_ExchangeActiveSyncProvisioning
#include "windows.security.exchangeactivesyncprovisioning.h"
#define WIDL_using_Windows_System_Profile
#include "windows.system.profile.h"
#define WIDL_using_Windows_System_UserProfile
#include "windows.system.userprofile.h"
#define WIDL_using_Windows_UI_ViewManagement
#include "windows.ui.viewmanagement.h"
#define WIDL_using_Windows_ApplicationModel_Core
#include "windows.applicationmodel.core.h"
#define WIDL_using_Windows_ApplicationModel_DataTransfer
#include "windows.applicationmodel.datatransfer.h"

#include "wine/test.h"

#define check_interface( a, b, c ) check_interface_( __LINE__, a, b, c, FALSE )

typedef struct ICoreApplicationPrivate ICoreApplicationPrivate;
typedef struct ICoreApplicationPrivateVtbl
{
    HRESULT (WINAPI *QueryInterface)(ICoreApplicationPrivate *, REFIID, void **);
    ULONG (WINAPI *AddRef)(ICoreApplicationPrivate *);
    ULONG (WINAPI *Release)(ICoreApplicationPrivate *);
    HRESULT (WINAPI *GetIids)(ICoreApplicationPrivate *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(ICoreApplicationPrivate *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(ICoreApplicationPrivate *, TrustLevel *);
    HRESULT (WINAPI *get_Properties)(ICoreApplicationPrivate *, IPropertySet **);
    HRESULT (WINAPI *get_PrivateProperties)(ICoreApplicationPrivate *, IPropertySet **);
} ICoreApplicationPrivateVtbl;

struct ICoreApplicationPrivate
{
    const ICoreApplicationPrivateVtbl *lpVtbl;
};

static const IID IID_ICoreApplicationPrivate =
    {0x17b0e613, 0x942a, 0x422d, {0x90, 0x4c, 0xf9, 0x0d, 0xc7, 0x1a, 0x7d, 0xae}};
static void check_interface_( unsigned int line, void *iface_ptr, REFIID iid, BOOL supported, BOOL is_broken )
{
    HRESULT hr, expected_hr, broken_hr;
    IUnknown *iface = iface_ptr;
    IUnknown *unk;

    expected_hr = supported ? S_OK : E_NOINTERFACE;
    broken_hr = supported ? E_NOINTERFACE : S_OK;
    hr = IUnknown_QueryInterface( iface, iid, (void **)&unk );
    ok_(__FILE__, line)( hr == expected_hr || broken( is_broken && hr == broken_hr ),
                         "got hr %#lx, expected %#lx.\n", hr, expected_hr );
    if (SUCCEEDED(hr)) IUnknown_Release( unk );
}

static void test_EasClientDeviceInformation(void)
{
    static const WCHAR *class_name = RuntimeClass_Windows_Security_ExchangeActiveSyncProvisioning_EasClientDeviceInformation;
    IEasClientDeviceInformation *client_device_information;
    IActivationFactory *factory;
    HSTRING str;
    HRESULT hr;
    LONG ref;

    hr = WindowsCreateString( class_name, wcslen( class_name ), &str );
    ok( hr == S_OK, "got hr %#lx.\n", hr );

    hr = RoGetActivationFactory( str, &IID_IActivationFactory, (void **)&factory );
    WindowsDeleteString( str );
    ok( hr == S_OK || broken( hr == REGDB_E_CLASSNOTREG ), "got hr %#lx.\n", hr );
    if (hr == REGDB_E_CLASSNOTREG)
    {
        win_skip( "%s runtimeclass not registered, skipping tests.\n", wine_dbgstr_w( class_name ) );
        return;
    }

    check_interface( factory, &IID_IUnknown, TRUE );
    check_interface( factory, &IID_IInspectable, TRUE );
    check_interface( factory, &IID_IAgileObject, FALSE );

    hr = IActivationFactory_ActivateInstance( factory, (IInspectable **)&client_device_information );
    ok( hr == S_OK, "got hr %#lx.\n", hr );

    check_interface( client_device_information, &IID_IUnknown, TRUE );
    check_interface( client_device_information, &IID_IInspectable, TRUE );
    check_interface( client_device_information, &IID_IAgileObject, FALSE );

    hr = IEasClientDeviceInformation_get_OperatingSystem( client_device_information, &str );
    ok( hr == S_OK, "got hr %#lx\n", hr );
    WindowsDeleteString( str );

    hr = IEasClientDeviceInformation_get_FriendlyName( client_device_information, &str );
    ok( hr == S_OK, "got hr %#lx\n", hr );
    WindowsDeleteString( str );

    hr = IEasClientDeviceInformation_get_SystemManufacturer( client_device_information, &str );
    ok( hr == S_OK, "got hr %#lx\n", hr );
    WindowsDeleteString( str );

    hr = IEasClientDeviceInformation_get_SystemProductName( client_device_information, &str );
    ok( hr == S_OK, "got hr %#lx\n", hr );
    WindowsDeleteString( str );

    hr = IEasClientDeviceInformation_get_SystemSku( client_device_information, &str );
    ok( hr == S_OK, "got hr %#lx\n", hr );
    WindowsDeleteString( str );

    ref = IEasClientDeviceInformation_Release( client_device_information );
    ok( ref == 0, "got ref %ld.\n", ref );

    ref = IActivationFactory_Release( factory );
    ok( ref == 1, "got ref %ld.\n", ref );
}

static void test_AnalyticsVersionInfo(void)
{
    static const WCHAR *class_name = RuntimeClass_Windows_System_Profile_AnalyticsInfo;
    IAnalyticsInfoStatics *analytics_info_statics;
    IAnalyticsVersionInfo *analytics_version_info;
    IActivationFactory *factory;
    HSTRING str, expect_str;
    DWORD revision, size;
    WCHAR buffer[32];
    UINT64 version;
    HRESULT hr;
    INT32 res;
    LONG ref;

    hr = WindowsCreateString( class_name, wcslen( class_name ), &str );
    ok( hr == S_OK, "got hr %#lx.\n", hr );

    hr = RoGetActivationFactory( str, &IID_IActivationFactory, (void **)&factory );
    WindowsDeleteString( str );
    ok( hr == S_OK || broken( hr == REGDB_E_CLASSNOTREG ), "got hr %#lx.\n", hr );
    if (hr == REGDB_E_CLASSNOTREG)
    {
        win_skip( "%s runtimeclass not registered, skipping tests.\n", wine_dbgstr_w( class_name ) );
        return;
    }

    check_interface( factory, &IID_IUnknown, TRUE );
    check_interface( factory, &IID_IInspectable, TRUE );
    check_interface( factory, &IID_IAgileObject, TRUE );

    hr = IActivationFactory_QueryInterface( factory, &IID_IAnalyticsInfoStatics, (void **)&analytics_info_statics );
    ok( hr == S_OK, "got hr %#lx.\n", hr );

    hr = IAnalyticsInfoStatics_get_VersionInfo( analytics_info_statics, &analytics_version_info );
    ok( hr == S_OK, "got hr %#lx.\n", hr );

    check_interface( analytics_version_info, &IID_IUnknown, TRUE );
    check_interface( analytics_version_info, &IID_IInspectable, TRUE );
    check_interface( analytics_version_info, &IID_IAgileObject, TRUE );

    hr = WindowsCreateString( L"Windows.Desktop", wcslen( L"Windows.Desktop" ), &expect_str );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    hr = IAnalyticsVersionInfo_get_DeviceFamily( analytics_version_info, &str );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    hr = WindowsCompareStringOrdinal( str, expect_str, &res );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    ok( !res, "got unexpected string %s.\n", debugstr_hstring(str) );
    WindowsDeleteString( str );
    WindowsDeleteString( expect_str );

    size = sizeof(revision);
    if (RegGetValueW( HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion", L"UBR",
                      RRF_RT_REG_DWORD, NULL, &revision, &size ))
        revision = 0;
    version = NtCurrentTeb()->Peb->OSMajorVersion & 0xffff;
    version = (version << 16) | (NtCurrentTeb()->Peb->OSMinorVersion & 0xffff);
    version = (version << 16) | (NtCurrentTeb()->Peb->OSBuildNumber & 0xffff);
    version = (version << 16) | revision;

    res = swprintf( buffer, ARRAY_SIZE(buffer), L"%I64u", version );
    hr = WindowsCreateString( buffer, res, &expect_str );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    hr = IAnalyticsVersionInfo_get_DeviceFamilyVersion( analytics_version_info, &str );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    hr = WindowsCompareStringOrdinal( str, expect_str, &res );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    ok( !res || broken(revision == 0) /* Win11 */, "got unexpected string %s.\n", debugstr_hstring(str) );
    WindowsDeleteString( str );
    WindowsDeleteString( expect_str );

    ref = IAnalyticsVersionInfo_Release( analytics_version_info );
    ok( ref == 0, "got ref %ld.\n", ref );

    ref = IAnalyticsInfoStatics_Release( analytics_info_statics );
    ok( ref == 2, "got ref %ld.\n", ref );
    ref = IActivationFactory_Release( factory );
    ok( ref == 1, "got ref %ld.\n", ref );
}

static void test_AdvertisingManager(void)
{
    static const WCHAR *class_name = RuntimeClass_Windows_System_UserProfile_AdvertisingManager;
    IAdvertisingManagerStatics *advertising_manager_statics;
    IActivationFactory *factory;
    HSTRING str;
    HRESULT hr;
    LONG ref;

    hr = WindowsCreateString( class_name, wcslen( class_name ), &str );
    ok( hr == S_OK, "got hr %#lx.\n", hr );

    hr = RoGetActivationFactory( str, &IID_IActivationFactory, (void **)&factory );
    WindowsDeleteString( str );
    ok( hr == S_OK || broken( hr == REGDB_E_CLASSNOTREG ), "got hr %#lx.\n", hr );
    if (hr == REGDB_E_CLASSNOTREG)
    {
        win_skip( "%s runtimeclass not registered, skipping tests.\n", wine_dbgstr_w( class_name ) );
        return;
    }

    check_interface( factory, &IID_IUnknown, TRUE );
    check_interface( factory, &IID_IInspectable, TRUE );
    check_interface_( __LINE__, factory, &IID_IAgileObject, TRUE, TRUE );

    hr = IActivationFactory_QueryInterface( factory, &IID_IAdvertisingManagerStatics, (void **)&advertising_manager_statics );
    ok( hr == S_OK, "got hr %#lx.\n", hr );

    hr = IAdvertisingManagerStatics_get_AdvertisingId( advertising_manager_statics, &str );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    WindowsDeleteString( str );

    ref = IAdvertisingManagerStatics_Release( advertising_manager_statics );
    ok( ref == 2, "got ref %ld.\n", ref );
    ref = IActivationFactory_Release( factory );
    ok( ref == 1, "got ref %ld.\n", ref );
}

static void test_ApplicationView(void)
{
    static const WCHAR *class_name = RuntimeClass_Windows_UI_ViewManagement_ApplicationView;
    IApplicationViewStatics2 *app_view_statics2;
    IActivationFactory *factory;
    IApplicationView *app_view;
    HSTRING str;
    HRESULT hr;
    LONG ref;

    hr = WindowsCreateString( class_name, wcslen( class_name ), &str );
    ok( hr == S_OK, "got hr %#lx.\n", hr );

    hr = RoGetActivationFactory( str, &IID_IActivationFactory, (void **)&factory );
    WindowsDeleteString( str );
    ok( hr == S_OK || broken( hr == REGDB_E_CLASSNOTREG ), "got hr %#lx.\n", hr );
    if (FAILED( hr ))
    {
        win_skip( "%s runtimeclass not registered, skipping tests.\n", wine_dbgstr_w( class_name ) );
        return;
    }

    check_interface( factory, &IID_IUnknown, TRUE );
    check_interface( factory, &IID_IInspectable, TRUE );
    check_interface( factory, &IID_IAgileObject, TRUE );
    check_interface( factory, &IID_IActivationFactory, TRUE );
    check_interface( factory, &IID_IApplicationViewStatics, TRUE );
    check_interface( factory, &IID_IApplicationViewStatics2, TRUE );

    /* Test IApplicationViewStatics2 */
    hr = IActivationFactory_QueryInterface( factory, &IID_IApplicationViewStatics2,
                                            (void **)&app_view_statics2 );
    ok( hr == S_OK, "got hr %#lx.\n", hr );

    hr = IApplicationViewStatics2_GetForCurrentView( app_view_statics2, &app_view );
    ok( hr == 0x80070490, "got hr %#lx.\n", hr );

    IApplicationViewStatics2_Release( app_view_statics2 );

    ref = IActivationFactory_Release( factory );
    ok( ref == 1, "got ref %ld.\n", ref );
}

static void test_CoreApplication(void)
{
    static const WCHAR *class_name = RuntimeClass_Windows_ApplicationModel_Core_CoreApplication;
    ICoreApplicationPrivate *private;
    ICoreImmersiveApplication *immersive;
    ICoreApplicationUseCount *use_count;
    ICoreApplication *core;
    IVectorView_CoreApplicationView *views;
    IMap_HSTRING_IInspectable *map;
    IPropertySet *props, *props2, *private_props;
    IInspectable *value;
    IUnknown *identity, *identity2;
    IActivationFactory *factory;
    HSTRING str, key;
    IID *iids;
    UINT32 size;
    ULONG count;
    boolean replaced;
    HRESULT hr;
    LONG ref;

    hr = WindowsCreateString( class_name, wcslen( class_name ), &str );
    ok( hr == S_OK, "got hr %#lx.\n", hr );

    hr = RoGetActivationFactory( str, &IID_IActivationFactory, (void **)&factory );
    WindowsDeleteString( str );
    ok( hr == S_OK || broken( hr == REGDB_E_CLASSNOTREG ), "got hr %#lx.\n", hr );
    if (FAILED( hr ))
    {
        win_skip( "%s runtimeclass not registered, skipping tests.\n", wine_dbgstr_w( class_name ) );
        return;
    }

    check_interface( factory, &IID_IUnknown, TRUE );
    check_interface( factory, &IID_IInspectable, TRUE );
    check_interface( factory, &IID_IAgileObject, TRUE );
    check_interface( factory, &IID_IActivationFactory, TRUE );
    check_interface( factory, &IID_ICoreApplication, TRUE );
    check_interface( factory, &IID_ICoreApplication2, TRUE );
    check_interface( factory, &IID_ICoreApplication3, TRUE );
    check_interface( factory, &IID_ICoreApplicationExit, TRUE );
    check_interface( factory, &IID_ICoreApplicationUnhandledError, TRUE );
    check_interface( factory, &IID_ICoreApplicationUseCount, TRUE );
    check_interface( factory, &IID_ICoreImmersiveApplication, TRUE );
    check_interface( factory, &IID_ICoreImmersiveApplication2, TRUE );
    check_interface( factory, &IID_ICoreImmersiveApplication3, TRUE );
    check_interface( factory, &IID_ICoreApplicationPrivate, TRUE );

    hr = IActivationFactory_GetIids( factory, &count, &iids );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    ok( count >= 9, "got %lu interfaces.\n", count );
    CoTaskMemFree( iids );

    hr = IActivationFactory_GetRuntimeClassName( factory, &str );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    ok( !wcscmp( WindowsGetStringRawBuffer( str, NULL ), class_name ), "got %s.\n", debugstr_hstring(str) );
    WindowsDeleteString( str );

    hr = IActivationFactory_QueryInterface( factory, &IID_ICoreApplication, (void **)&core );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    hr = IActivationFactory_QueryInterface( factory, &IID_IUnknown, (void **)&identity );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    hr = ICoreApplication_QueryInterface( core, &IID_IUnknown, (void **)&identity2 );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    ok( identity == identity2, "factory %p and statics %p have different identities.\n", identity, identity2 );
    IUnknown_Release( identity2 );
    IUnknown_Release( identity );

    hr = ICoreApplication_get_Properties( core, &props );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    hr = ICoreApplication_get_Properties( core, &props2 );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    ok( props == props2, "property set identity changed, %p != %p.\n", props, props2 );
    IPropertySet_Release( props2 );

    hr = IActivationFactory_QueryInterface( factory, &IID_ICoreApplicationPrivate, (void **)&private );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    hr = private->lpVtbl->get_PrivateProperties( private, &private_props );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    ok( private_props != props, "public and private property sets unexpectedly share identity.\n" );

    hr = IPropertySet_QueryInterface( private_props, &IID_IMap_HSTRING_IInspectable, (void **)&map );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    hr = WindowsCreateString( L"linuxnt.test", 12, &key );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    hr = IMap_HSTRING_IInspectable_Insert( map, key, (IInspectable *)props, &replaced );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    ok( !replaced, "new value was reported as replaced.\n" );
    hr = IMap_HSTRING_IInspectable_Lookup( map, key, &value );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    ok( value == (IInspectable *)props, "got value %p, expected %p.\n", value, props );
    IInspectable_Release( value );
    hr = IMap_HSTRING_IInspectable_Remove( map, key );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    WindowsDeleteString( key );
    IMap_HSTRING_IInspectable_Release( map );
    IPropertySet_Release( private_props );
    private->lpVtbl->Release( private );
    IPropertySet_Release( props );

    hr = IActivationFactory_QueryInterface( factory, &IID_ICoreImmersiveApplication, (void **)&immersive );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    hr = ICoreImmersiveApplication_get_Views( immersive, &views );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    hr = IVectorView_CoreApplicationView_get_Size( views, &size );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    ok( !size, "got %u views.\n", size );
    IVectorView_CoreApplicationView_Release( views );
    ICoreImmersiveApplication_Release( immersive );

    hr = IActivationFactory_QueryInterface( factory, &IID_ICoreApplicationUseCount, (void **)&use_count );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    hr = ICoreApplicationUseCount_IncrementApplicationUseCount( use_count );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    hr = ICoreApplicationUseCount_DecrementApplicationUseCount( use_count );
    ok( hr == S_OK, "got hr %#lx.\n", hr );
    ICoreApplicationUseCount_Release( use_count );
    ICoreApplication_Release( core );

    ref = IActivationFactory_Release( factory );
    ok( ref == 1, "got ref %ld.\n", ref );
}

static void test_DataTransferManager(void)
{
    static const WCHAR *class_name = RuntimeClass_Windows_ApplicationModel_DataTransfer_DataTransferManager;
    IActivationFactory *factory;
    HSTRING str;
    HRESULT hr;

    hr = WindowsCreateString( class_name, wcslen( class_name ), &str );
    ok( hr == S_OK, "got hr %#lx.\n", hr );

    hr = RoGetActivationFactory( str, &IID_IActivationFactory, (void **)&factory );
    WindowsDeleteString( str );
    ok( hr == S_OK || broken( hr == REGDB_E_CLASSNOTREG ), "got hr %#lx.\n", hr );
    if (FAILED( hr ))
    {
        win_skip( "%s runtimeclass not registered, skipping tests.\n", wine_dbgstr_w( class_name ) );
        return;
    }

    check_interface( factory, &IID_IUnknown, TRUE );
    check_interface( factory, &IID_IInspectable, TRUE );
    check_interface( factory, &IID_IAgileObject, FALSE );
    check_interface( factory, &IID_IActivationFactory, TRUE );
    check_interface( factory, &IID_IDataTransferManagerInterop, TRUE );
    check_interface( factory, &IID_IDataTransferManagerStatics, TRUE );

    IActivationFactory_Release( factory );
}

START_TEST(twinapi)
{
    HRESULT hr;

    hr = RoInitialize( RO_INIT_MULTITHREADED );
    ok( hr == S_OK, "RoInitialize failed, hr %#lx\n", hr );

    test_EasClientDeviceInformation();
    test_AnalyticsVersionInfo();
    test_AdvertisingManager();
    test_ApplicationView();
    test_CoreApplication();
    test_DataTransferManager();

    RoUninitialize();
}
