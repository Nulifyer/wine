/* Copyright 2026 LinuxNT contributors; LGPL version 2.1 or later. */
#include "thread_callouts.h"
static struct callouts_state state;
#if TEST_STATIC_TLS
static __declspec(thread) DWORD tls_value = 7;
static void WINAPI tls_callback(void *instance, DWORD reason, void *reserved)
{
    if (reason == DLL_THREAD_ATTACH) InterlockedIncrement(&state.tls_attach);
    if (reason == DLL_THREAD_DETACH) InterlockedIncrement(&state.tls_detach);
}
static PIMAGE_TLS_CALLBACK const callback_entry __attribute__((section(".CRT$XLB"), used)) = tls_callback;
#endif
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        SetLastError(0xdeadbeef);
        state.disable_result = DisableThreadLibraryCalls(instance);
        state.disable_error = GetLastError();
    }
    if (reason == DLL_THREAD_ATTACH) InterlockedIncrement(&state.dll_attach);
    if (reason == DLL_THREAD_DETACH) InterlockedIncrement(&state.dll_detach);
    return TRUE; /* Retain observable failure instead of rejecting the module. */
}
void WINAPI get_state(struct callouts_state *out) { *out = state; }
DWORD WINAPI get_tls_value(void)
{
#if TEST_STATIC_TLS
    return ++tls_value;
#else
    return 0;
#endif
}
