/* Service-session identity tests. */
#include <stdarg.h>
#include "windef.h"
#include "winbase.h"
#include "wine/test.h"

START_TEST(service_session)
{
    ULONG (WINAPI *get_current_service_session_id)(void);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    get_current_service_session_id = (void *)GetProcAddress(ntdll, "RtlGetCurrentServiceSessionId");
    ok(!!get_current_service_session_id, "RtlGetCurrentServiceSessionId is not exported\n");
    if (get_current_service_session_id)
        ok(!get_current_service_session_id(), "expected service session zero\n");
}
