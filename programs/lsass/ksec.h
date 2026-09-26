#pragma once

#include "windef.h"
#include "winnt.h"

BOOL lsa_ksec_initialize( void );
void lsa_ksec_cleanup( void );
NTSTATUS lsa_ksec_transfer_handle( HANDLE source, HANDLE target_process, ULONG package_id,
                                   HANDLE *target_handle );
