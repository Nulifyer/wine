/* Service-session identity tests. */
#include <stdarg.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "ddk/wdm.h"
#include "wine/test.h"

START_TEST(service_session)
{
    ULONG (WINAPI *get_active_console_id)(void);
    ULONG (WINAPI *get_current_service_session_id)(void);
    const KUSER_SHARED_DATA *user_shared_data = ULongToPtr(0x7ffe0000);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    get_active_console_id = (void *)GetProcAddress(ntdll, "RtlGetActiveConsoleId");
    ok(!!get_active_console_id, "RtlGetActiveConsoleId is not exported\n");
    if (get_active_console_id)
        ok(get_active_console_id() == user_shared_data->ActiveConsoleId,
           "active console id %lu differs from shared data %lu\n",
           get_active_console_id(), user_shared_data->ActiveConsoleId);

    get_current_service_session_id = (void *)GetProcAddress(ntdll, "RtlGetCurrentServiceSessionId");
    ok(!!get_current_service_session_id, "RtlGetCurrentServiceSessionId is not exported\n");
    if (get_current_service_session_id)
        ok(!get_current_service_session_id(), "expected service session zero\n");
}
