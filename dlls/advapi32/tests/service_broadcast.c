/* Service session-change broadcasts.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>
#include <stdio.h>
#include "windef.h"
#include "winbase.h"
#include "winsvc.h"
#include "wine/test.h"

#define TEST_SESSION 0x7ffffffe
#define RESULT_MAGIC 0x4c4e5442

static DWORD (WINAPI *broadcast)(DWORD, DWORD, DWORD, BYTE *);
static SERVICE_STATUS_HANDLE status_handle;
static SERVICE_STATUS status;
static HANDLE stop_event, entered_event, release_event, done_event;
static char *service_name, *record_path;

static struct broadcast_result
{
    DWORD magic, privilege_error, empty_result, valid_result, last_error;
    DWORD entered_result, done_result, handler_wait, control, event, size, session;
    LONG calls;
} result;

static DWORD WINAPI control_handler(DWORD control, DWORD event, void *data, void *context)
{
    DWORD *payload = data;

    if (control == SERVICE_CONTROL_SESSIONCHANGE && event == 7 && payload && payload[1] == TEST_SESSION)
    {
        InterlockedIncrement(&result.calls);
        SetEvent(entered_event);
        result.handler_wait = WaitForSingleObject(release_event, 5000);
        result.control = control;
        result.event = event;
        result.size = payload[0];
        result.session = payload[1];
        SetEvent(done_event);
    }
    else if (control == SERVICE_CONTROL_STOP)
    {
        status.dwCurrentState = SERVICE_STOP_PENDING;
        status.dwControlsAccepted = 0;
        SetServiceStatus(status_handle, &status);
        SetEvent(stop_event);
    }
    return ERROR_SUCCESS;
}

static void WINAPI service_main(DWORD argc, char **argv)
{
    TOKEN_PRIVILEGES privileges;
    DWORD payload[2] = {sizeof(payload), TEST_SESSION}, written;
    HANDLE token, file;

    stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    entered_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    release_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    done_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    status_handle = RegisterServiceCtrlHandlerExA(service_name, control_handler, NULL);
    if (!status_handle || !stop_event || !entered_event || !release_event || !done_event) goto cleanup;
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = SERVICE_RUNNING;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE;
    if (!SetServiceStatus(status_handle, &status)) goto cleanup;

    result.privilege_error = ERROR_ACCESS_DENIED;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token))
    {
        privileges.PrivilegeCount = 1;
        if (LookupPrivilegeValueW(NULL, L"SeTcbPrivilege", &privileges.Privileges[0].Luid))
        {
            privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            SetLastError(0xdeadbeef);
            AdjustTokenPrivileges(token, FALSE, &privileges, 0, NULL, NULL);
            result.privilege_error = GetLastError();
        }
        CloseHandle(token);
    }
    result.empty_result = broadcast(SERVICE_CONTROL_SESSIONCHANGE, 7, 0, NULL);
    SetLastError(0xdeadbeef);
    result.valid_result = broadcast(SERVICE_CONTROL_SESSIONCHANGE, 7, sizeof(payload), (BYTE *)payload);
    result.last_error = GetLastError();
    /* A synchronous sender would keep its own handler blocked until timeout.
     * Also invalidate the caller buffer before allowing the handler to finish. */
    payload[0] = payload[1] = 0xdeadbeef;
    result.entered_result = WaitForSingleObject(entered_event, 5000);
    SetEvent(release_event);
    result.done_result = WaitForSingleObject(done_event, 5000);
    result.magic = RESULT_MAGIC;
    file = CreateFileA(record_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, TRUNCATE_EXISTING, 0, NULL);
    if (file != INVALID_HANDLE_VALUE)
    {
        WriteFile(file, &result, sizeof(result), &written, NULL);
        CloseHandle(file);
    }
    WaitForSingleObject(stop_event, 30000);

cleanup:
    if (status_handle)
    {
        status.dwCurrentState = SERVICE_STOPPED;
        status.dwControlsAccepted = 0;
        SetServiceStatus(status_handle, &status);
    }
    if (done_event) CloseHandle(done_event);
    if (release_event) CloseHandle(release_event);
    if (entered_event) CloseHandle(entered_event);
    if (stop_event) CloseHandle(stop_event);
}

static void test_broadcast(void)
{
    char executable[MAX_PATH], temporary[MAX_PATH], record[MAX_PATH], name[96];
    char command[3 * MAX_PATH + 128];
    SC_HANDLE manager, service, deleted;
    SERVICE_STATUS service_status;
    DWORD payload[2] = {sizeof(payload), TEST_SESSION};
    DWORD i, bytes, ret, error;
    HANDLE file;
    BOOL received = FALSE, stopped = FALSE;

    manager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!manager)
    {
        skip("service creation requires administrator access, error %lu\n", GetLastError());
        return;
    }
    ret = GetTempPathA(sizeof(temporary), temporary);
    ok(ret && ret < sizeof(temporary), "GetTempPathA returned %lu\n", ret);
    if (!ret || ret >= sizeof(temporary)) goto close_manager;
    ret = GetTempFileNameA(temporary, "lnt", 0, record);
    ok(ret, "GetTempFileNameA failed, error %lu\n", GetLastError());
    if (!ret) goto close_manager;
    ret = GetModuleFileNameA(NULL, executable, sizeof(executable));
    ok(ret && ret < sizeof(executable), "GetModuleFileNameA returned %lu\n", ret);
    if (!ret || ret >= sizeof(executable)) goto delete_record;
    sprintf(name, "LinuxNTBroadcast_%lu_%lu", GetCurrentProcessId(), GetTickCount());
    sprintf(command, "\"%s\" service_broadcast service %s \"%s\"", executable, name, record);
    service = CreateServiceA(manager, name, name, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, command, NULL, NULL, NULL, NULL, NULL);
    ok(!!service, "CreateServiceA failed, error %lu\n", GetLastError());
    if (!service) goto delete_record;
    trace("temporary service %s, record %s\n", name, record);
    ret = StartServiceA(service, 0, NULL);
    ok(ret, "StartServiceA failed, error %lu\n", GetLastError());
    if (!ret) goto delete_service;
    for (i = 0; i < 200 && !received; ++i)
    {
        file = CreateFileA(record, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (file != INVALID_HANDLE_VALUE)
        {
            received = ReadFile(file, &result, sizeof(result), &bytes, NULL) &&
                bytes == sizeof(result) && result.magic == RESULT_MAGIC;
            CloseHandle(file);
        }
        if (!received) Sleep(100);
    }
    ok(received, "service did not publish its result\n");
    if (received)
    {
        ok(!result.privilege_error, "enabling TCB privilege failed, error %lu\n", result.privilege_error);
        ok(result.empty_result == ERROR_INVALID_PARAMETER, "empty payload returned %lu\n", result.empty_result);
        ok(!result.valid_result, "valid payload returned %lu\n", result.valid_result);
        ok(!result.last_error, "broadcast left last error %lu\n", result.last_error);
        ok(result.entered_result == WAIT_OBJECT_0, "handler did not start, wait %lu\n", result.entered_result);
        ok(result.done_result == WAIT_OBJECT_0, "handler did not finish, wait %lu\n", result.done_result);
        ok(result.handler_wait == WAIT_OBJECT_0, "sender did not return before handler completed, wait %lu\n", result.handler_wait);
        ok(result.calls == 1, "received %ld matching notifications\n", result.calls);
        ok(result.control == SERVICE_CONTROL_SESSIONCHANGE, "control %lu\n", result.control);
        ok(result.event == 7, "event %lu\n", result.event);
        ok(result.size == sizeof(payload), "payload size %lu\n", result.size);
        ok(result.session == TEST_SESSION, "payload session %#lx\n", result.session);
    }
    SetLastError(0xdeadbeef);
    ret = broadcast(SERVICE_CONTROL_SESSIONCHANGE, 7, sizeof(payload), (BYTE *)payload);
    error = GetLastError();
    ok(ret == ERROR_ACCESS_DENIED, "unprivileged broadcast returned %lu\n", ret);
    ok(!error, "unprivileged broadcast left last error %lu\n", error);
    ret = ControlService(service, SERVICE_CONTROL_STOP, &service_status);
    ok(ret, "ControlService(STOP) failed, error %lu\n", GetLastError());
    for (i = 0; i < 150; ++i)
    {
        if (QueryServiceStatus(service, &service_status) && service_status.dwCurrentState == SERVICE_STOPPED)
        {
            stopped = TRUE;
            break;
        }
        Sleep(100);
    }
    ok(stopped, "service did not stop\n");

delete_service:
    ret = DeleteService(service);
    ok(ret, "DeleteService failed, error %lu\n", GetLastError());
    CloseServiceHandle(service);
    /* Native SCM can retain a stopped service briefly after DeleteService. */
    for (i = 0; i < 100; ++i)
    {
        deleted = OpenServiceA(manager, name, SERVICE_QUERY_STATUS);
        error = GetLastError();
        if (deleted) CloseServiceHandle(deleted);
        else if (error == ERROR_SERVICE_DOES_NOT_EXIST) break;
        Sleep(50);
    }
    ok(i < 100, "deleted service remained accessible, last error %lu\n", error);
delete_record:
    ret = DeleteFileA(record);
    ok(ret, "DeleteFileA failed, error %lu\n", GetLastError());
close_manager:
    CloseServiceHandle(manager);
}

START_TEST(service_broadcast)
{
    HMODULE module = LoadLibraryA("sechost.dll");
    char **argv;
    int argc = winetest_get_mainargs(&argv);

    broadcast = module ? (void *)GetProcAddress(module, "I_ScBroadcastServiceControlMessage") : NULL;
    if (!broadcast)
    {
        win_skip("service broadcast export is unavailable\n");
        if (module) FreeLibrary(module);
        return;
    }
    if (argc == 5 && !strcmp(argv[2], "service"))
    {
        SERVICE_TABLE_ENTRYA table[] = {{argv[3], service_main}, {NULL, NULL}};
        service_name = argv[3];
        record_path = argv[4];
        StartServiceCtrlDispatcherA(table);
    }
    else test_broadcast();
    FreeLibrary(module);
}
