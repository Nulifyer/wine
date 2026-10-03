/*
 * Wine private RPCSS service host adapter
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

#include "windef.h"
#include "winbase.h"
#include "winsvc.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(ole);

static const WCHAR service_name[] = L"WineRpcSs";
static SERVICE_STATUS_HANDLE service_handle;
static HANDLE child_process;
static HANDLE stop_event;

static void update_service_status(DWORD state, DWORD error)
{
    SERVICE_STATUS status;

    status.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    status.dwCurrentState = state;
    status.dwControlsAccepted = state == SERVICE_RUNNING ?
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    status.dwWin32ExitCode = error;
    status.dwServiceSpecificExitCode = 0;
    status.dwCheckPoint = 0;
    status.dwWaitHint = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING ? 30000 : 0;
    SetServiceStatus(service_handle, &status);
}

static DWORD WINAPI service_handler(DWORD control, DWORD event_type, void *event_data, void *context)
{
    switch (control)
    {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        TRACE("stopping private RPCSS child\n");
        update_service_status(SERVICE_STOP_PENDING, ERROR_SUCCESS);
        SetEvent(stop_event);
        return ERROR_SUCCESS;
    default:
        update_service_status(SERVICE_RUNNING, ERROR_SUCCESS);
        return ERROR_SUCCESS;
    }
}

static DWORD start_rpcss_child(HANDLE ready_event)
{
    STARTUPINFOEXW startup = {{0}};
    PROCESS_INFORMATION process;
    SIZE_T attribute_size = 0;
    HANDLE inherited_handles[2] = {stop_event, ready_event};
    WCHAR system_dir[MAX_PATH];
    WCHAR command[2 * MAX_PATH];
    DWORD error = ERROR_SUCCESS;
    DWORD wait;

    if (!GetSystemDirectoryW(system_dir, ARRAY_SIZE(system_dir))) return GetLastError();
    if (swprintf(command, ARRAY_SIZE(command), L"\"%ls\\rpcss.exe\" --adapter-child %p %p",
                 system_dir, stop_event, ready_event) < 0)
        return ERROR_INSUFFICIENT_BUFFER;

    InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return GetLastError();
    if (!(startup.lpAttributeList = HeapAlloc(GetProcessHeap(), 0, attribute_size)))
        return ERROR_NOT_ENOUGH_MEMORY;
    if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &attribute_size))
    {
        error = GetLastError();
        goto done;
    }
    if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                   inherited_handles, sizeof(inherited_handles), NULL, NULL))
    {
        error = GetLastError();
        goto done;
    }

    startup.StartupInfo.cb = sizeof(startup);
    if (!CreateProcessW(NULL, command, NULL, NULL, TRUE,
                        DETACHED_PROCESS | EXTENDED_STARTUPINFO_PRESENT,
                        NULL, NULL, &startup.StartupInfo, &process))
    {
        error = GetLastError();
        goto done;
    }
    CloseHandle(process.hThread);
    child_process = process.hProcess;

    inherited_handles[0] = ready_event;
    inherited_handles[1] = child_process;
    wait = WaitForMultipleObjects(ARRAY_SIZE(inherited_handles), inherited_handles, FALSE, 30000);
    if (wait == WAIT_OBJECT_0)
        TRACE("private RPCSS child is ready\n");
    else if (wait == WAIT_OBJECT_0 + 1)
    {
        if (!GetExitCodeProcess(child_process, &error)) error = GetLastError();
        if (error == ERROR_SUCCESS) error = ERROR_SERVICE_NOT_ACTIVE;
        WARN("private RPCSS child exited during startup, error %lu\n", error);
    }
    else
    {
        error = wait == WAIT_TIMEOUT ? ERROR_SERVICE_REQUEST_TIMEOUT : GetLastError();
        WARN("private RPCSS child did not become ready, error %lu\n", error);
    }

done:
    if (startup.lpAttributeList)
    {
        DeleteProcThreadAttributeList(startup.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, startup.lpAttributeList);
    }
    return error;
}

void WINAPI ServiceMain(DWORD argc, WCHAR **argv)
{
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), NULL, TRUE};
    HANDLE ready_event;
    DWORD error;

    TRACE("starting Wine private RPCSS adapter service\n");

    service_handle = RegisterServiceCtrlHandlerExW(service_name, service_handler, NULL);
    if (!service_handle)
    {
        WARN("failed to register service control handler, error %lu\n", GetLastError());
        return;
    }
    update_service_status(SERVICE_START_PENDING, ERROR_SUCCESS);

    if (!(stop_event = CreateEventW(&attributes, TRUE, FALSE, NULL)) ||
        !(ready_event = CreateEventW(&attributes, TRUE, FALSE, NULL)))
    {
        error = GetLastError();
        update_service_status(SERVICE_STOPPED, error);
        if (stop_event) CloseHandle(stop_event);
        return;
    }

    error = start_rpcss_child(ready_event);
    CloseHandle(ready_event);
    if (error)
    {
        SetEvent(stop_event);
        if (child_process)
        {
            WaitForSingleObject(child_process, 10000);
            CloseHandle(child_process);
        }
        CloseHandle(stop_event);
        update_service_status(SERVICE_STOPPED, error);
        return;
    }

    update_service_status(SERVICE_RUNNING, ERROR_SUCCESS);
    WaitForSingleObject(child_process, INFINITE);
    CloseHandle(child_process);
    CloseHandle(stop_event);
    child_process = NULL;
    stop_event = NULL;
    update_service_status(SERVICE_STOPPED, ERROR_SUCCESS);
    TRACE("Wine private RPCSS adapter service stopped\n");
}
