/* WinRT Windows.System.Power implementation
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "initguid.h"
#include "private.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(powerwinrt);

struct power_manager_statics
{
    IActivationFactory IActivationFactory_iface;
    IPowerManagerStatics IPowerManagerStatics_iface;
    LONG ref;
    LONG next_token;
};

static inline struct power_manager_statics *impl_from_IActivationFactory(IActivationFactory *iface)
{
    return CONTAINING_RECORD(iface, struct power_manager_statics, IActivationFactory_iface);
}

static HRESULT WINAPI factory_QueryInterface(IActivationFactory *iface, REFIID iid, void **out)
{
    struct power_manager_statics *impl = impl_from_IActivationFactory(iface);

    TRACE("iface %p, iid %s, out %p.\n", iface, debugstr_guid(iid), out);

    if (!out) return E_POINTER;
    *out = NULL;

    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable)
            || IsEqualGUID(iid, &IID_IAgileObject) || IsEqualGUID(iid, &IID_IActivationFactory))
        *out = &impl->IActivationFactory_iface;
    else if (IsEqualGUID(iid, &IID_IPowerManagerStatics))
        *out = &impl->IPowerManagerStatics_iface;

    if (!*out)
    {
        FIXME("%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(iid));
        return E_NOINTERFACE;
    }

    IUnknown_AddRef((IUnknown *)*out);
    return S_OK;
}

static ULONG WINAPI factory_AddRef(IActivationFactory *iface)
{
    struct power_manager_statics *impl = impl_from_IActivationFactory(iface);
    return InterlockedIncrement(&impl->ref);
}

static ULONG WINAPI factory_Release(IActivationFactory *iface)
{
    struct power_manager_statics *impl = impl_from_IActivationFactory(iface);
    return InterlockedDecrement(&impl->ref);
}

static HRESULT WINAPI factory_GetIids(IActivationFactory *iface, ULONG *iid_count, IID **iids)
{
    FIXME("iface %p, iid_count %p, iids %p stub.\n", iface, iid_count, iids);
    return E_NOTIMPL;
}

static HRESULT WINAPI factory_GetRuntimeClassName(IActivationFactory *iface, HSTRING *class_name)
{
    const WCHAR *name = RuntimeClass_Windows_System_Power_PowerManager;

    if (!class_name) return E_POINTER;
    return WindowsCreateString(name, wcslen(name), class_name);
}

static HRESULT WINAPI factory_GetTrustLevel(IActivationFactory *iface, TrustLevel *trust_level)
{
    if (!trust_level) return E_POINTER;
    *trust_level = BaseTrust;
    return S_OK;
}

static HRESULT WINAPI factory_ActivateInstance(IActivationFactory *iface, IInspectable **instance)
{
    if (instance) *instance = NULL;
    return E_NOTIMPL;
}

static const struct IActivationFactoryVtbl factory_vtbl =
{
    factory_QueryInterface,
    factory_AddRef,
    factory_Release,
    factory_GetIids,
    factory_GetRuntimeClassName,
    factory_GetTrustLevel,
    factory_ActivateInstance,
};

DEFINE_IINSPECTABLE(statics, IPowerManagerStatics, struct power_manager_statics,
                    IActivationFactory_iface)

static BOOL query_power_status(SYSTEM_POWER_STATUS *status)
{
    memset(status, 0xff, sizeof(*status));
    return GetSystemPowerStatus(status);
}

static BOOL battery_present(const SYSTEM_POWER_STATUS *status)
{
    return status->BatteryFlag != BATTERY_FLAG_NO_BATTERY && status->BatteryFlag != BATTERY_FLAG_UNKNOWN;
}

static HRESULT add_changed_handler(struct power_manager_statics *impl,
                                   IEventHandler_IInspectable *handler,
                                   EventRegistrationToken *token)
{
    if (!handler || !token) return E_INVALIDARG;
    token->value = InterlockedIncrement(&impl->next_token);
    return S_OK;
}

static HRESULT WINAPI statics_get_EnergySaverStatus(IPowerManagerStatics *iface,
                                                     EnergySaverStatus *value)
{
    SYSTEM_POWER_STATUS status;

    if (!value) return E_POINTER;
    if (!query_power_status(&status) || !battery_present(&status))
        *value = EnergySaverStatus_Disabled;
    else
        *value = status.SystemStatusFlag ? EnergySaverStatus_On : EnergySaverStatus_Off;
    return S_OK;
}

static HRESULT WINAPI statics_add_EnergySaverStatusChanged(IPowerManagerStatics *iface,
                                                            IEventHandler_IInspectable *handler,
                                                            EventRegistrationToken *token)
{
    return add_changed_handler(impl_from_IPowerManagerStatics(iface), handler, token);
}

static HRESULT WINAPI statics_remove_EnergySaverStatusChanged(IPowerManagerStatics *iface,
                                                               EventRegistrationToken token)
{
    return S_OK;
}

static HRESULT WINAPI statics_get_BatteryStatus(IPowerManagerStatics *iface, BatteryStatus *value)
{
    SYSTEM_POWER_STATUS status;

    if (!value) return E_POINTER;
    if (!query_power_status(&status) || !battery_present(&status))
        *value = BatteryStatus_NotPresent;
    else if (status.BatteryFlag & BATTERY_FLAG_CHARGING)
        *value = BatteryStatus_Charging;
    else if (status.ACLineStatus == 0)
        *value = BatteryStatus_Discharging;
    else
        *value = BatteryStatus_Idle;
    return S_OK;
}

static HRESULT WINAPI statics_add_BatteryStatusChanged(IPowerManagerStatics *iface,
                                                        IEventHandler_IInspectable *handler,
                                                        EventRegistrationToken *token)
{
    return add_changed_handler(impl_from_IPowerManagerStatics(iface), handler, token);
}

static HRESULT WINAPI statics_remove_BatteryStatusChanged(IPowerManagerStatics *iface,
                                                           EventRegistrationToken token)
{
    return S_OK;
}

static HRESULT WINAPI statics_get_PowerSupplyStatus(IPowerManagerStatics *iface,
                                                     PowerSupplyStatus *value)
{
    SYSTEM_POWER_STATUS status;

    if (!value) return E_POINTER;
    if (!query_power_status(&status) || status.ACLineStatus == 255)
        *value = PowerSupplyStatus_Inadequate;
    else
        *value = status.ACLineStatus ? PowerSupplyStatus_Adequate : PowerSupplyStatus_NotPresent;
    return S_OK;
}

static HRESULT WINAPI statics_add_PowerSupplyStatusChanged(IPowerManagerStatics *iface,
                                                            IEventHandler_IInspectable *handler,
                                                            EventRegistrationToken *token)
{
    return add_changed_handler(impl_from_IPowerManagerStatics(iface), handler, token);
}

static HRESULT WINAPI statics_remove_PowerSupplyStatusChanged(IPowerManagerStatics *iface,
                                                               EventRegistrationToken token)
{
    return S_OK;
}

static HRESULT WINAPI statics_get_RemainingChargePercent(IPowerManagerStatics *iface, INT32 *value)
{
    SYSTEM_POWER_STATUS status;

    if (!value) return E_POINTER;
    if (!query_power_status(&status) || !battery_present(&status) || status.BatteryLifePercent > 100)
        *value = 100;
    else
        *value = status.BatteryLifePercent;
    return S_OK;
}

static HRESULT WINAPI statics_add_RemainingChargePercentChanged(IPowerManagerStatics *iface,
                                                                 IEventHandler_IInspectable *handler,
                                                                 EventRegistrationToken *token)
{
    return add_changed_handler(impl_from_IPowerManagerStatics(iface), handler, token);
}

static HRESULT WINAPI statics_remove_RemainingChargePercentChanged(IPowerManagerStatics *iface,
                                                                    EventRegistrationToken token)
{
    return S_OK;
}

static HRESULT WINAPI statics_get_RemainingDischargeTime(IPowerManagerStatics *iface,
                                                          TimeSpan *value)
{
    SYSTEM_POWER_STATUS status;

    if (!value) return E_POINTER;
    if (!query_power_status(&status) || !battery_present(&status)
            || status.BatteryLifeTime == (DWORD)-1)
        value->Duration = MAXLONGLONG;
    else
        value->Duration = (LONGLONG)status.BatteryLifeTime * 10000000;
    return S_OK;
}

static HRESULT WINAPI statics_add_RemainingDischargeTimeChanged(IPowerManagerStatics *iface,
                                                                 IEventHandler_IInspectable *handler,
                                                                 EventRegistrationToken *token)
{
    return add_changed_handler(impl_from_IPowerManagerStatics(iface), handler, token);
}

static HRESULT WINAPI statics_remove_RemainingDischargeTimeChanged(IPowerManagerStatics *iface,
                                                                    EventRegistrationToken token)
{
    return S_OK;
}

static const struct IPowerManagerStaticsVtbl statics_vtbl =
{
    statics_QueryInterface,
    statics_AddRef,
    statics_Release,
    statics_GetIids,
    statics_GetRuntimeClassName,
    statics_GetTrustLevel,
    statics_get_EnergySaverStatus,
    statics_add_EnergySaverStatusChanged,
    statics_remove_EnergySaverStatusChanged,
    statics_get_BatteryStatus,
    statics_add_BatteryStatusChanged,
    statics_remove_BatteryStatusChanged,
    statics_get_PowerSupplyStatus,
    statics_add_PowerSupplyStatusChanged,
    statics_remove_PowerSupplyStatusChanged,
    statics_get_RemainingChargePercent,
    statics_add_RemainingChargePercentChanged,
    statics_remove_RemainingChargePercentChanged,
    statics_get_RemainingDischargeTime,
    statics_add_RemainingDischargeTimeChanged,
    statics_remove_RemainingDischargeTimeChanged,
};

static struct power_manager_statics power_manager_statics =
{
    {&factory_vtbl},
    {&statics_vtbl},
    1,
    0,
};

HRESULT WINAPI DllGetClassObject(REFCLSID clsid, REFIID iid, void **out)
{
    return CLASS_E_CLASSNOTAVAILABLE;
}

HRESULT WINAPI DllGetActivationFactory(HSTRING classid, IActivationFactory **factory)
{
    const WCHAR *name;

    if (!factory) return E_POINTER;
    *factory = NULL;
    name = WindowsGetStringRawBuffer(classid, NULL);

    TRACE("class %s, factory %p.\n", debugstr_hstring(classid), factory);
    if (!wcscmp(name, RuntimeClass_Windows_System_Power_PowerManager))
        return IActivationFactory_QueryInterface(&power_manager_statics.IActivationFactory_iface,
                                                 &IID_IActivationFactory, (void **)factory);
    return CLASS_E_CLASSNOTAVAILABLE;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved)
{
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(instance);
    return TRUE;
}
