/* Native system-root tests. */
#include <stdarg.h>
#include "windef.h"
#include "winbase.h"
#include "wine/test.h"

START_TEST(system_root)
{
    WCHAR *(WINAPI *get_nt_system_root)(void);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    WCHAR *first, *second;

    get_nt_system_root = (void *)GetProcAddress(ntdll, "RtlGetNtSystemRoot");
    ok(!!get_nt_system_root, "RtlGetNtSystemRoot is not exported\n");
    if (!get_nt_system_root) return;

    SetLastError(0x13579bdf);
    first = get_nt_system_root();
    second = get_nt_system_root();
    ok(!!first, "Expected a system-root pointer\n");
    ok(first == second, "Expected a stable system-root pointer\n");
    ok(!lstrcmpW(first, L"C:\\WINDOWS"), "Unexpected system root %s\n", wine_dbgstr_w(first));
    ok(GetLastError() == 0x13579bdf, "Expected last error to be preserved, got %lu\n", GetLastError());
}
