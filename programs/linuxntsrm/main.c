/*
 * LinuxNT native Security Reference Monitor launcher
 *
 * Copyright 2026 Nulifyer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>

#include "windef.h"
#include "winternl.h"
#include "ntstatus.h"

#define SRM_READY_TIMEOUT_SECONDS 120

static NTSTATUS build_child_command( const UNICODE_STRING *image, HANDLE ready_event,
                                     WCHAR *buffer, SIZE_T capacity, UNICODE_STRING *command )
{
    static const WCHAR suffix[] = L" --serve ";
    static const WCHAR hex[] = L"0123456789abcdef";
    SIZE_T image_len = image->Length / sizeof(WCHAR), suffix_len = ARRAY_SIZE(suffix) - 1;
    SIZE_T pos = 0, i;
    ULONG_PTR value = (ULONG_PTR)ready_event;

    if (image_len + suffix_len + 2 + sizeof(value) * 2 >= capacity) return STATUS_BUFFER_TOO_SMALL;
    buffer[pos++] = '"';
    for (i = 0; i < image_len; i++) buffer[pos++] = image->Buffer[i];
    buffer[pos++] = '"';
    for (i = 0; i < suffix_len; i++) buffer[pos++] = suffix[i];
    for (i = sizeof(value) * 2; i; i--) buffer[pos++] = hex[(value >> ((i - 1) * 4)) & 0xf];
    buffer[pos] = 0;

    command->Buffer = buffer;
    command->Length = pos * sizeof(WCHAR);
    command->MaximumLength = (pos + 1) * sizeof(WCHAR);
    return STATUS_SUCCESS;
}

static NTSTATUS boot_server( PEB *peb )
{
    static WCHAR server_path_buffer[] = L"C:\\windows\\system32\\linuxntsrm-server.exe";
    RTL_USER_PROCESS_PARAMETERS *current = peb->ProcessParameters, *child_params = NULL;
    RTL_USER_PROCESS_INFORMATION child = {sizeof(child)};
    UNICODE_STRING server_path = RTL_CONSTANT_STRING(server_path_buffer);
    UNICODE_STRING nt_image, command;
    OBJECT_ATTRIBUTES attributes;
    PROCESS_BASIC_INFORMATION process_info;
    WCHAR command_buffer[1024];
    HANDLE handles[2], ready_event = NULL;
    LARGE_INTEGER timeout;
    NTSTATUS status, wait_status;

    InitializeObjectAttributes( &attributes, NULL, OBJ_INHERIT, NULL, NULL );
    status = NtCreateEvent( &ready_event, EVENT_ALL_ACCESS, &attributes, NotificationEvent, FALSE );
    if (status) return status;

    status = build_child_command( &server_path, ready_event, command_buffer,
                                  ARRAY_SIZE(command_buffer), &command );
    if (status) goto done;

    status = RtlCreateProcessParametersEx( &child_params, &server_path, &current->DllPath,
                                           &current->CurrentDirectory.DosPath, &command,
                                           current->Environment, &current->WindowTitle,
                                           &current->Desktop, &current->ShellInfo,
                                           &current->RuntimeInfo, PROCESS_PARAMS_FLAG_NORMALIZED );
    if (status) goto done;

    status = RtlDosPathNameToNtPathName_U_WithStatus( server_path.Buffer, &nt_image, NULL, NULL );
    if (status) goto done;

    status = RtlCreateUserProcess( &nt_image, 0, child_params, NULL, NULL, NULL, TRUE,
                                   NULL, NULL, &child );
    RtlFreeUnicodeString( &nt_image );
    if (status) goto done;

    status = NtResumeThread( child.Thread, NULL );
    if (status) goto child_failed;

    handles[0] = ready_event;
    handles[1] = child.Process;
    timeout.QuadPart = -(LONGLONG)SRM_READY_TIMEOUT_SECONDS * 10000000;
    wait_status = NtWaitForMultipleObjects( ARRAY_SIZE(handles), handles, WaitAny, FALSE, &timeout );
    if (wait_status == STATUS_WAIT_0)
    {
        status = STATUS_SUCCESS;
        goto child_done;
    }
    if (wait_status == STATUS_WAIT_0 + 1 &&
        !NtQueryInformationProcess( child.Process, ProcessBasicInformation, &process_info,
                                    sizeof(process_info), NULL ))
        status = process_info.ExitStatus;
    else
        status = wait_status;

child_failed:
    NtTerminateProcess( child.Process, status );
child_done:
    NtClose( child.Thread );
    NtClose( child.Process );
done:
    if (child_params) RtlDestroyProcessParameters( child_params );
    NtClose( ready_event );
    return status;
}

void WINAPI NtProcessStartup( PEB *peb )
{
    RtlExitUserProcess( boot_server( peb ) );
}
