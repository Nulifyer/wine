/* LSASS handle transfer through Wine's KSecDD compatibility device. */

#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "ksec.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(secur32);

#define IOCTL_KSEC_CONNECT_LSA 0x398000
#define IOCTL_KSEC_DUPLICATE_HANDLE 0x390034

struct ksec_duplicate_handle_request
{
    ULONGLONG source_handle;
    ULONGLONG target_process;
    ULONGLONG package_id;
};

static HANDLE ksec_handle;

BOOL lsa_ksec_initialize( void )
{
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK io;
    UNICODE_STRING name;
    ULONG system_pid = 0;
    NTSTATUS status;

    RtlInitUnicodeString( &name, L"\\Device\\KsecDD" );
    InitializeObjectAttributes( &attr, &name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    status = NtOpenFile( &ksec_handle, FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
                         &attr, &io, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         FILE_NON_DIRECTORY_FILE );
    if (status)
    {
        WARN( "failed to open KSecDD, status %#lx\n", status );
        ksec_handle = NULL;
        return FALSE;
    }

    status = NtDeviceIoControlFile( ksec_handle, NULL, NULL, NULL, &io,
                                    IOCTL_KSEC_CONNECT_LSA, NULL, 0,
                                    &system_pid, sizeof(system_pid) );
    if (status || io.Status || io.Information != sizeof(system_pid))
    {
        WARN( "failed to register LSASS with KSecDD, status %#lx, io %#lx, size %Iu\n",
              status, io.Status, io.Information );
        NtClose( ksec_handle );
        ksec_handle = NULL;
        return FALSE;
    }
    TRACE( "registered LSASS with KSecDD, system pid %lu\n", system_pid );
    return TRUE;
}

void lsa_ksec_cleanup( void )
{
    if (ksec_handle) NtClose( ksec_handle );
    ksec_handle = NULL;
}

NTSTATUS lsa_ksec_transfer_handle( HANDLE source, HANDLE target_process, ULONG package_id,
                                   HANDLE *target_handle )
{
    struct ksec_duplicate_handle_request request;
    ULONGLONG transferred = 0;
    IO_STATUS_BLOCK io;
    NTSTATUS status;

    if (!ksec_handle) return STATUS_DEVICE_NOT_READY;
    if (!source || !target_process || !target_handle) return STATUS_INVALID_PARAMETER;
    *target_handle = NULL;

    request.source_handle = (ULONG_PTR)source;
    request.target_process = (ULONG_PTR)target_process;
    request.package_id = package_id;
    status = NtDeviceIoControlFile( ksec_handle, NULL, NULL, NULL, &io,
                                    IOCTL_KSEC_DUPLICATE_HANDLE, &request, sizeof(request),
                                    &transferred, sizeof(transferred) );
    if (status) return status;
    if (io.Status) return io.Status;
    if (io.Information != sizeof(transferred) || !transferred) return STATUS_UNSUCCESSFUL;
    *target_handle = (HANDLE)(ULONG_PTR)transferred;
    return STATUS_SUCCESS;
}
