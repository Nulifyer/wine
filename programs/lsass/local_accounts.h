/* Shared local account identity for the LSASS-owned compatibility services. */

#pragma once

#include "windef.h"
#include "winnt.h"
#include "winternl.h"
#include "lmcons.h"

#define LSA_LOCAL_USER_RID 1000

struct lsa_local_account
{
    WCHAR name[UNLEN + 1];
    DWORD rid;
    DWORD primary_group_rid;
    DWORD account_control;
    BOOL password_is_blank;
};

SID *lsa_allocate_computer_sid( void );
SID *lsa_allocate_local_account_sid( DWORD rid );
BOOL lsa_is_computer_sid( const SID *sid );
BOOL lsa_is_builtin_domain_sid( const SID *sid );
BOOL lsa_get_local_account( struct lsa_local_account *account );
NTSTATUS lsa_validate_local_credentials( const WCHAR *domain, const WCHAR *user,
                                         const WCHAR *password, struct lsa_local_account *account,
                                         NTSTATUS *substatus );
