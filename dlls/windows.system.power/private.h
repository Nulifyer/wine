/* WinRT Windows.System.Power implementation */

#include <stdarg.h>
#include <stddef.h>

#define COBJMACROS
#include "windef.h"
#include "winbase.h"
#include "winstring.h"

#define WIDL_using_Windows_Foundation
#define WIDL_using_Windows_System_Power
#include "activation.h"
#include "windows.system.power.h"

#define DEFINE_IINSPECTABLE_(pfx, iface_type, impl_type, impl_from, iface_mem, expr)               \
    static inline impl_type *impl_from(iface_type *iface)                                          \
    {                                                                                              \
        return CONTAINING_RECORD(iface, impl_type, iface_mem);                                     \
    }                                                                                              \
    static HRESULT WINAPI pfx##_QueryInterface(iface_type *iface, REFIID iid, void **out)          \
    {                                                                                              \
        impl_type *impl = impl_from(iface);                                                        \
        return IInspectable_QueryInterface((IInspectable *)(expr), iid, out);                      \
    }                                                                                              \
    static ULONG WINAPI pfx##_AddRef(iface_type *iface)                                            \
    {                                                                                              \
        impl_type *impl = impl_from(iface);                                                        \
        return IInspectable_AddRef((IInspectable *)(expr));                                        \
    }                                                                                              \
    static ULONG WINAPI pfx##_Release(iface_type *iface)                                           \
    {                                                                                              \
        impl_type *impl = impl_from(iface);                                                        \
        return IInspectable_Release((IInspectable *)(expr));                                       \
    }                                                                                              \
    static HRESULT WINAPI pfx##_GetIids(iface_type *iface, ULONG *iid_count, IID **iids)           \
    {                                                                                              \
        impl_type *impl = impl_from(iface);                                                        \
        return IInspectable_GetIids((IInspectable *)(expr), iid_count, iids);                      \
    }                                                                                              \
    static HRESULT WINAPI pfx##_GetRuntimeClassName(iface_type *iface, HSTRING *class_name)        \
    {                                                                                              \
        impl_type *impl = impl_from(iface);                                                        \
        return IInspectable_GetRuntimeClassName((IInspectable *)(expr), class_name);               \
    }                                                                                              \
    static HRESULT WINAPI pfx##_GetTrustLevel(iface_type *iface, TrustLevel *trust_level)          \
    {                                                                                              \
        impl_type *impl = impl_from(iface);                                                        \
        return IInspectable_GetTrustLevel((IInspectable *)(expr), trust_level);                    \
    }
#define DEFINE_IINSPECTABLE(pfx, iface_type, impl_type, base_iface)                                \
    DEFINE_IINSPECTABLE_(pfx, iface_type, impl_type, impl_from_##iface_type, iface_type##_iface, &impl->base_iface)
