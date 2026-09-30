/*
 * Loaded DLL thread notification policy with and without static TLS.
 * Copyright 2026 LinuxNT contributors
 * LGPL version 2.1 or later.
 */
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include <stdarg.h>
#include "winternl.h"
#include "thread_callouts.h"
#include "wine/test.h"
#include <stdio.h>

static NTSTATUS (WINAPI *pLdrDisableThreadCalloutsForDll)(HMODULE);
static DWORD (WINAPI *get_tls_value)(void);
static DWORD WINAPI worker(void *arg) { return get_tls_value(); }

static BOOL extract(const char *name, const char *path)
{
    HRSRC resource = FindResourceA(NULL, name, "TESTDLL");
    HGLOBAL loaded;
    HANDLE file;
    DWORD size, written;
    BOOL ret;
    ok(!!resource, "resource %s %lu\n", name, GetLastError());
    if (!resource) return FALSE;
    loaded = LoadResource(NULL, resource);
    size = SizeofResource(NULL, resource);
    ok(!!loaded && !!size, "load resource %s\n", name);
    if (!loaded || !size) return FALSE;
    file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
    ok(file != INVALID_HANDLE_VALUE, "create fixture %lu\n", GetLastError());
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    ret = WriteFile(file, LockResource(loaded), size, &written, NULL);
    ok(ret && written == size, "write fixture %lu/%lu\n", written, size);
    CloseHandle(file);
    return ret && written == size;
}

static void test_module(BOOL tls)
{
    const char *name = tls ? "thread_callouts_tls.dll" : "thread_callouts_plain.dll";
    char temp[MAX_PATH], dir[MAX_PATH], path[MAX_PATH];
    HMODULE module = NULL;
    HANDLE thread;
    void (WINAPI *get_state)(struct callouts_state *);
    struct callouts_state state;
    IMAGE_NT_HEADERS *nt;
    DWORD value, wait, length;
    NTSTATUS status;
    unsigned int i;

    winetest_push_context("TLS %u", tls);
    length = GetTempPathA(sizeof(temp), temp);
    ok(length && length < sizeof(temp), "temp path %lu\n", length);
    if (!length || length >= sizeof(temp)) goto done;
    sprintf(dir, "%sWineCallouts-%08lx-%u", temp, GetCurrentProcessId(), tls);
    ok(CreateDirectoryA(dir, NULL), "create directory %lu\n", GetLastError());
    sprintf(path, "%s\\%s", dir, name);
    if (!extract(name, path)) goto remove;
    module = LoadLibraryA(path);
    ok(!!module, "load fixture %lu\n", GetLastError());
    if (!module) goto remove;
    nt = (IMAGE_NT_HEADERS *)((BYTE *)module + ((IMAGE_DOS_HEADER *)module)->e_lfanew);
    ok(!!nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress == tls,
            "TLS directory %#lx\n", nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    get_state = (void *)GetProcAddress(module, "get_state");
    get_tls_value = (void *)GetProcAddress(module, "get_tls_value");
    ok(!!get_state && !!get_tls_value, "fixture exports\n");
    if (!get_state || !get_tls_value) goto remove;
    get_state(&state);
    ok(state.disable_result, "DllMain disable result %u, error %lu\n", state.disable_result, state.disable_error);
    ok(state.disable_error == 0xdeadbeef, "DllMain last error %#lx\n", state.disable_error);
    SetLastError(0xdeadbeef);
    status = pLdrDisableThreadCalloutsForDll(module);
    ok(status == STATUS_SUCCESS, "loaded LdrDisableThreadCalloutsForDll %#lx\n", status);
    ok(GetLastError() == 0xdeadbeef, "raw NT last error %#lx\n", GetLastError());
    value = get_tls_value();
    ok(value == (tls ? 8 : 0), "parent TLS value %lu\n", value);
    for (i = 0; i < 2; ++i)
    {
        thread = CreateThread(NULL, 0, worker, NULL, 0, NULL);
        ok(!!thread, "create worker %lu\n", GetLastError());
        if (!thread) continue;
        wait = WaitForSingleObject(thread, 15000);
        ok(wait == WAIT_OBJECT_0, "worker wait %lu\n", wait);
        if (wait != WAIT_OBJECT_0) ExitProcess(4);
        ok(GetExitCodeThread(thread, &value), "worker result\n");
        ok(value == (tls ? 8 : 0), "independent worker TLS value %lu\n", value);
        CloseHandle(thread);
    }
    get_state(&state);
    ok(state.dll_attach == (tls ? 2 : 0) && state.dll_detach == (tls ? 2 : 0),
            "DLL notifications %ld/%ld\n", state.dll_attach, state.dll_detach);
    ok(state.tls_attach == (tls ? 2 : 0) && state.tls_detach == (tls ? 2 : 0),
            "TLS notifications %ld/%ld\n", state.tls_attach, state.tls_detach);
    trace("callout-record tls=%u disable=%u error=%#lx nt=%#lx dll=%ld/%ld callback=%ld/%ld\n",
            tls, state.disable_result, state.disable_error, status, state.dll_attach,
            state.dll_detach, state.tls_attach, state.tls_detach);
remove:
    if (module) FreeLibrary(module);
    ok(DeleteFileA(path), "delete fixture %lu\n", GetLastError());
    ok(RemoveDirectoryA(dir), "remove directory %lu\n", GetLastError());
done:
    winetest_pop_context();
}

START_TEST(thread_callouts)
{
    pLdrDisableThreadCalloutsForDll = (void *)GetProcAddress(GetModuleHandleA("ntdll.dll"),
            "LdrDisableThreadCalloutsForDll");
    ok(!!pLdrDisableThreadCalloutsForDll, "NT loader export\n");
    if (!pLdrDisableThreadCalloutsForDll) return;
    test_module(FALSE);
    test_module(TRUE);
    {
        HMODULE invalid = (HMODULE)(ULONG_PTR)0xd00df00d;
        NTSTATUS status;
        BOOL ret;
        DWORD error;
        SetLastError(0xdeadbeef);
        status = pLdrDisableThreadCalloutsForDll(invalid);
        ok(status == STATUS_DLL_NOT_FOUND, "invalid module NT status %#lx\n", status);
        ok(GetLastError() == 0xdeadbeef, "invalid raw last error %#lx\n", GetLastError());
        SetLastError(0xdeadbeef);
        ret = DisableThreadLibraryCalls(invalid);
        error = GetLastError();
        ok(!ret && error == ERROR_MOD_NOT_FOUND, "invalid Win32 call %u/%lu\n", ret, error);
        trace("callout-invalid nt=%#lx win32=%u error=%lu\n", status, ret, error);
    }
}
