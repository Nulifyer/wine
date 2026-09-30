/* Tests for shared out-of-box experience notifications
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>
#include <stdio.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "winternl.h"
#include "wine/test.h"

#define SHELL_STATE 0x0d83063ea3bc2475ULL
#define DEPLOYMENT_STATE 0x41960b29a3bc0c75ULL

static BOOL (WINAPI *pOOBEComplete)(BOOL *);
static BOOL (WINAPI *pRegister)(void (WINAPI *)(void *), void *, void **);
static BOOL (WINAPI *pUnregister)(void *);
static typeof(NtUpdateWnfStateData) *pUpdate;
static typeof(NtQueryWnfStateData) *pQuery;
static typeof(NtDeleteWnfStateData) *pDelete;
static char **argv;

struct saved_value
{
    const char *path, *name;
    DWORD type, size;
    BYTE data[64];
    BOOL present;
};
static struct saved_value values[] =
{
    {"SYSTEM\\Setup", "SetupSupported"},
    {"Software\\Microsoft\\Shell\\Oobe", "OobeCompleteWnfSupported"},
    {"SYSTEM\\CurrentControlSet\\Control\\WinInit", "Headless"},
    {"Software\\Wine\\LicenseInformation", "Kernel-SkipOOBE"},
    {"Software\\Wine\\LicenseInformation", "OOBE-ServerIsClient"},
};

static void set_value(unsigned int index, DWORD value)
{
    HKEY key;
    LSTATUS status;
    status = RegCreateKeyExA(HKEY_LOCAL_MACHINE, values[index].path, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL);
    ok(!status, "create %s: %ld\n", values[index].path, status);
    if (status) return;
    status = RegSetValueExA(key, values[index].name, 0, REG_DWORD, (BYTE *)&value, sizeof(value));
    ok(!status, "set %s: %ld\n", values[index].name, status);
    RegCloseKey(key);
}

static void save_values(void)
{
    unsigned int i;
    HKEY key;
    LSTATUS status;
    for (i = 0; i < ARRAY_SIZE(values); i++)
    {
        values[i].size = sizeof(values[i].data);
        status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, values[i].path, 0, KEY_QUERY_VALUE, &key);
        if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) continue;
        ok(!status, "open saved key: %ld\n", status);
        if (status) continue;
        status = RegQueryValueExA(key, values[i].name, NULL, &values[i].type, values[i].data, &values[i].size);
        ok(!status || status == ERROR_FILE_NOT_FOUND, "save %s: %ld\n", values[i].name, status);
        values[i].present = !status;
        RegCloseKey(key);
    }
}

static void restore_values(void)
{
    unsigned int i;
    HKEY key;
    LSTATUS status;
    for (i = 0; i < ARRAY_SIZE(values); i++)
    {
        status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, values[i].path, 0, KEY_SET_VALUE, &key);
        ok(!status, "open restore key: %ld\n", status);
        if (status) continue;
        if (values[i].present)
            status = RegSetValueExA(key, values[i].name, 0, values[i].type, values[i].data, values[i].size);
        else status = RegDeleteValueA(key, values[i].name);
        ok(!status || status == ERROR_FILE_NOT_FOUND, "restore %s: %ld\n", values[i].name, status);
        RegCloseKey(key);
    }
}

static void run_child(const char *mode)
{
    STARTUPINFOA startup = {sizeof(startup)};
    PROCESS_INFORMATION process;
    char command[2 * MAX_PATH];
    BOOL ret;
    sprintf(command, "\"%s\" %s oobe-child %s", argv[0], argv[1], mode);
    ret = CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process);
    ok(ret, "create %s child: %lu\n", mode, GetLastError());
    if (ret) wait_child_process(&process);
}

static void publish(ULONGLONG state, ULONG value)
{
    NTSTATUS status = pUpdate(&state, &value, sizeof(value), NULL, NULL, 0, FALSE);
    ok(!status, "publish %#I64x value %lu: %#lx\n", state, value, status);
}

struct callback_context
{
    HANDLE event, release;
    LONG calls;
    void *wait;
    BOOL self_cancel, cancel_result;
};
static void WINAPI completed(void *opaque)
{
    struct callback_context *context = opaque;
    InterlockedIncrement(&context->calls);
    if (context->release) WaitForSingleObject(context->release, 5000);
    if (context->self_cancel) context->cancel_result = pUnregister(context->wait);
    SetEvent(context->event);
}

struct cancel_context
{
    void *wait;
    HANDLE started, finished;
    BOOL ret;
};
static DWORD WINAPI cancel_thread(void *opaque)
{
    struct cancel_context *context = opaque;
    SetEvent(context->started);
    context->ret = pUnregister(context->wait);
    SetEvent(context->finished);
    return 0;
}
static void WINAPI blocked_callback(void *opaque)
{
    struct callback_context *context = opaque;
    InterlockedIncrement(&context->calls);
    SetEvent(context->event);
    WaitForSingleObject(context->release, 5000);
}

static void test_family(ULONGLONG state)
{
    struct callback_context a = {0}, b = {0};
    struct cancel_context cancel;
    HANDLE thread;
    void *wait;
    BOOL complete, ret;
    NTSTATUS status;
    ULONG value, size, stamp;
    BYTE oversized[5] = {1}, short_value = 1;

    publish(state, 0);
    complete = TRUE;
    SetLastError(0xdeadbeef);
    ret = pOOBEComplete(&complete);
    ok(ret && !complete, "initial query: %d %d error %lu\n", ret, complete, GetLastError());
    ok(GetLastError() == 0xdeadbeef, "query altered last error %lu\n", GetLastError());
    status = pUpdate(&state, oversized, sizeof(oversized), NULL, NULL, 0, FALSE);
    ok(status == STATUS_INVALID_PARAMETER, "oversized payload: %#lx\n", status);
    status = pQuery(&state, NULL, NULL, &stamp, &value, &(ULONG){sizeof(value)});
    ok(!status && value == 0, "oversized update changed state: %#lx %lu\n", status, value);

    a.event = CreateEventW(NULL, FALSE, FALSE, NULL);
    b.event = CreateEventW(NULL, FALSE, FALSE, NULL);
    ret = pRegister(completed, &a, &a.wait);
    ok(ret && a.wait, "first registration: %d error %lu\n", ret, GetLastError());
    ret = pRegister(completed, &b, &b.wait);
    ok(ret && b.wait && b.wait != a.wait, "independent registration: %d error %lu\n", ret, GetLastError());
    if (a.wait && b.wait)
    {
        ret = pUnregister(a.wait);
        ok(ret, "cancel before publication: %lu\n", GetLastError());
        a.wait = NULL;
        run_child(state == SHELL_STATE ? "publish-shell" : "publish-deployment");
        ok(WaitForSingleObject(b.event, 5000) == WAIT_OBJECT_0, "cross-process callback timed out\n");
        ret = pUnregister(b.wait);
        ok(ret, "cancel surviving registration: %lu\n", GetLastError());
        b.wait = NULL;
        ok(a.calls == 0 && b.calls == 1, "independent callbacks %ld %ld\n", a.calls, b.calls);
        ok(WaitForSingleObject(a.event, 100) == WAIT_TIMEOUT, "canceled registration fired\n");
    }
    if (a.wait) pUnregister(a.wait);
    if (b.wait) pUnregister(b.wait);
    complete = FALSE;
    ret = pOOBEComplete(&complete);
    ok(ret && complete, "completed query: %d %d error %lu\n", ret, complete, GetLastError());
    wait = (void *)0xdeadbeef;
    ret = pRegister(completed, &a, &wait);
    ok(!ret && GetLastError() == ERROR_INVALID_STATE, "already complete registration: %d error %lu\n", ret, GetLastError());
    ok(wait == (void *)0xdeadbeef, "failed registration published %p\n", wait);

    publish(state, 2);
    complete = FALSE;
    ret = pOOBEComplete(&complete);
    ok(ret && complete, "nonzero query value: %d %d\n", ret, complete);
    wait = (void *)0xdeadbeef;
    ret = pRegister(completed, NULL, &wait);
    ok(!ret && GetLastError() == ERROR_INVALID_STATE && wait == (void *)0xdeadbeef,
       "nonzero state registration: %d error %lu wait %p\n", ret, GetLastError(), wait);

    publish(state, 0);
    a.calls = 0;
    a.wait = NULL;
    ret = pRegister(completed, &a, &a.wait);
    ok(ret, "filter registration: %lu\n", GetLastError());
    if (ret)
    {
        publish(state, 2);
        ok(WaitForSingleObject(a.event, 100) == WAIT_TIMEOUT, "value 2 invoked wait callback\n");
        status = pUpdate(&state, &short_value, sizeof(short_value), NULL, NULL, 0, FALSE);
        ok(!status, "short payload publication: %#lx\n", status);
        complete = TRUE;
        ret = pOOBEComplete(&complete);
        ok(ret && !complete, "short payload query: %d %d\n", ret, complete);
        ok(WaitForSingleObject(a.event, 100) == WAIT_TIMEOUT, "short payload invoked callback\n");
        publish(state, 1);
        ok(WaitForSingleObject(a.event, 5000) == WAIT_OBJECT_0, "value 1 callback timed out\n");
        ret = pUnregister(a.wait);
        ok(ret && a.calls == 1, "filter cancel %d callbacks %ld\n", ret, a.calls);
    }

    publish(state, 0);
    a.calls = 0;
    a.release = CreateEventW(NULL, TRUE, FALSE, NULL);
    a.self_cancel = TRUE;
    a.cancel_result = FALSE;
    ret = pRegister(completed, &a, &a.wait);
    ok(ret, "self-cancel registration: %lu\n", GetLastError());
    if (ret)
    {
        publish(state, 1);
        /* The callback may run before Register returns. Publish its output
         * before allowing this test callback to cancel its own registration. */
        SetEvent(a.release);
        ok(WaitForSingleObject(a.event, 5000) == WAIT_OBJECT_0, "self-cancel callback timed out\n");
        ok(a.cancel_result, "callback self-cancellation failed\n");
        if (!a.cancel_result) pUnregister(a.wait);
        publish(state, 1);
        ok(WaitForSingleObject(a.event, 100) == WAIT_TIMEOUT && a.calls == 1, "callback after self-cancel %ld\n", a.calls);
    }
    CloseHandle(a.release);
    a.self_cancel = FALSE;

    publish(state, 0);
    a.calls = 0;
    a.release = CreateEventW(NULL, TRUE, FALSE, NULL);
    ret = pRegister(blocked_callback, &a, &a.wait);
    ok(ret, "blocked callback registration: %lu\n", GetLastError());
    if (ret)
    {
        publish(state, 1);
        ok(WaitForSingleObject(a.event, 5000) == WAIT_OBJECT_0, "blocked callback did not enter\n");
        cancel.wait = a.wait;
        cancel.started = CreateEventW(NULL, FALSE, FALSE, NULL);
        cancel.finished = CreateEventW(NULL, FALSE, FALSE, NULL);
        cancel.ret = FALSE;
        thread = CreateThread(NULL, 0, cancel_thread, &cancel, 0, NULL);
        ok(!!thread, "create cancellation thread: %lu\n", GetLastError());
        if (thread)
        {
            ok(WaitForSingleObject(cancel.started, 5000) == WAIT_OBJECT_0, "cancellation thread did not start\n");
            ok(WaitForSingleObject(cancel.finished, 100) == WAIT_TIMEOUT, "cancellation returned during callback\n");
            SetEvent(a.release);
            ok(WaitForSingleObject(cancel.finished, 5000) == WAIT_OBJECT_0 && cancel.ret, "cancellation did not finish\n");
            WaitForSingleObject(thread, 5000);
            CloseHandle(thread);
        }
        else { SetEvent(a.release); pUnregister(a.wait); }
        CloseHandle(cancel.started);
        CloseHandle(cancel.finished);
        publish(state, 1);
        ok(WaitForSingleObject(a.event, 100) == WAIT_TIMEOUT && a.calls == 1, "callback after blocking cancellation\n");
    }
    CloseHandle(a.release);
    CloseHandle(a.event);
    CloseHandle(b.event);
    status = pDelete(&state, NULL);
    ok(!status, "delete state data: %#lx\n", status);
    size = sizeof(value);
    status = pQuery(&state, NULL, NULL, &stamp, &value, &size);
    ok(!status && size == 0, "deleted payload query: %#lx size %lu\n", status, size);
    complete = TRUE;
    ret = pOOBEComplete(&complete);
    ok(ret && !complete, "empty payload query: %d %d\n", ret, complete);
}

static void test_access(void)
{
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    SID_AND_ATTRIBUTES disabled[2] = {{0}};
    HANDLE original, primary, restricted;
    TOKEN_TYPE token_type;
    DWORD token_size;
    ULONGLONG shell = SHELL_STATE, deployment = DEPLOYMENT_STATE;
    ULONG value = 0, size, stamp;
    NTSTATUS status;
    BOOL ret, complete;
    void *wait;
    unsigned int i;

    AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0,0,0,0,0,0, &disabled[0].Sid);
    AllocateAndInitializeSid(&authority, 1, SECURITY_AUTHENTICATED_USER_RID, 0,0,0,0,0,0,0, &disabled[1].Sid);
    ret = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &original);
    ok(ret, "open token: %lu\n", GetLastError());
    if (!ret) goto done;
    for (i = 1; i <= 2; i++)
    {
        ret = CreateRestrictedToken(original, DISABLE_MAX_PRIVILEGE, i, disabled, 0, NULL, 0, NULL, &primary);
        ok(ret, "create filtered token %u: %lu\n", i, GetLastError());
        if (!ret) continue;
        ret = DuplicateToken(primary, SecurityImpersonation, &restricted);
        ok(ret, "duplicate filtered impersonation token: %lu\n", GetLastError());
        CloseHandle(primary);
        if (!ret) continue;
        ret = GetTokenInformation(restricted, TokenType, &token_type, sizeof(token_type), &token_size);
        ok(ret && token_type == TokenImpersonation, "filtered token type %u error %lu\n", token_type, GetLastError());
        ret = SetThreadToken(NULL, restricted);
        ok(ret, "impersonate filtered token: %lu\n", GetLastError());
        if (ret)
        {
            size = sizeof(value);
            status = pQuery(&shell, NULL, NULL, &stamp, &value, &size);
            ok(status == (i == 1 ? STATUS_SUCCESS : STATUS_ACCESS_DENIED), "filtered shell query %u: %#lx\n", i, status);
            status = pUpdate(&shell, &value, sizeof(value), NULL, NULL, 0, FALSE);
            ok(status == (i == 1 ? STATUS_SUCCESS : STATUS_ACCESS_DENIED), "filtered shell write %u: %#lx\n", i, status);
            size = sizeof(value);
            status = pQuery(&deployment, NULL, NULL, &stamp, &value, &size);
            ok(status == (i == 1 ? STATUS_SUCCESS : STATUS_ACCESS_DENIED), "filtered deployment query %u: %#lx\n", i, status);
            status = pUpdate(&deployment, &value, sizeof(value), NULL, NULL, 0, FALSE);
            ok(status == STATUS_ACCESS_DENIED, "filtered deployment write %u: %#lx\n", i, status);
            if (i == 2)
            {
                complete = TRUE;
                ret = pOOBEComplete(&complete);
                ok(!ret && complete && GetLastError() == ERROR_ACCESS_DENIED, "denied query %d %d error %lu\n", ret, complete, GetLastError());
                wait = (void *)0xdeadbeef;
                ret = pRegister(completed, NULL, &wait);
                ok(!ret && wait == (void *)0xdeadbeef && GetLastError() == ERROR_ACCESS_DENIED,
                   "denied register %d %p error %lu\n", ret, wait, GetLastError());
            }
            RevertToSelf();
        }
        CloseHandle(restricted);
    }
    CloseHandle(original);
done:
    FreeSid(disabled[0].Sid);
    FreeSid(disabled[1].Sid);
}

START_TEST(oobe)
{
    HMODULE kernel = GetModuleHandleA("kernel32.dll"), ntdll = GetModuleHandleA("ntdll.dll");
    BOOL complete, ret;
    void *wait;
    int argc;

    pOOBEComplete = (void *)GetProcAddress(kernel, "OOBEComplete");
    pRegister = (void *)GetProcAddress(kernel, "RegisterWaitUntilOOBECompleted");
    pUnregister = (void *)GetProcAddress(kernel, "UnregisterWaitUntilOOBECompleted");
    pUpdate = (void *)GetProcAddress(ntdll, "NtUpdateWnfStateData");
    pQuery = (void *)GetProcAddress(ntdll, "NtQueryWnfStateData");
    pDelete = (void *)GetProcAddress(ntdll, "NtDeleteWnfStateData");
    ok(!!pOOBEComplete, "query export absent\n");
    ok(!!pRegister, "register export absent\n");
    ok(!!pUnregister, "unregister export absent\n");
    if (!pOOBEComplete || !pRegister || !pUnregister) return;
    argc = winetest_get_mainargs(&argv);
    if (argc >= 4 && !strcmp(argv[2], "oobe-child"))
    {
        if (!strcmp(argv[3], "unsupported"))
        {
            complete = TRUE;
            ret = pOOBEComplete(&complete);
            ok(!ret && complete && GetLastError() == ERROR_NOT_SUPPORTED, "unsupported query %d %d error %lu\n", ret, complete, GetLastError());
            wait = (void *)0xdeadbeef;
            ret = pRegister(completed, NULL, &wait);
            ok(!ret && GetLastError() == ERROR_NOT_SUPPORTED && wait == (void *)0xdeadbeef,
               "unsupported registration %d %p error %lu\n", ret, wait, GetLastError());
        }
        else if (!strcmp(argv[3], "skip"))
        {
            complete = FALSE;
            ret = pOOBEComplete(&complete);
            ok(ret && complete, "skip capability query %d %d\n", ret, complete);
            wait = NULL;
            ret = pRegister(completed, NULL, &wait);
            ok(!ret && GetLastError() == ERROR_NOT_SUPPORTED, "skip capability invented registration support\n");
        }
        else if (!strcmp(argv[3], "shell")) { test_family(SHELL_STATE); test_access(); }
        else if (!strcmp(argv[3], "deployment")) test_family(DEPLOYMENT_STATE);
        else if (!strcmp(argv[3], "publish-shell")) publish(SHELL_STATE, 1);
        else if (!strcmp(argv[3], "publish-deployment")) publish(DEPLOYMENT_STATE, 1);
        else ok(0, "unknown child mode %s\n", argv[3]);
        return;
    }
    ret = pOOBEComplete(NULL);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER, "null query %d error %lu\n", ret, GetLastError());
    wait = (void *)0xdeadbeef;
    ret = pRegister(NULL, NULL, &wait);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER && wait == (void *)0xdeadbeef, "null callback\n");
    ret = pRegister(completed, NULL, NULL);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER, "null output\n");
    ret = pUnregister(NULL);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER, "null cancellation\n");
    ok(pUpdate && pQuery && pDelete, "WNF exports missing\n");
    if (!pUpdate || !pQuery || !pDelete) return;
    save_values();
    set_value(0, 0); set_value(1, 0); set_value(2, 0); set_value(3, 0); set_value(4, 0);
    run_child("unsupported");
    set_value(3, 1);
    run_child("skip");
    set_value(3, 0); set_value(0, 1);
    run_child("shell");
    set_value(0, 0); set_value(1, 1); set_value(2, 1);
    run_child("deployment");
    restore_values();
}
