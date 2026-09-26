/* Shared local account identity for the LSASS-owned compatibility services. */

#pragma once

#include "windef.h"
#include "winnt.h"

SID *lsa_allocate_computer_sid( void );
BOOL lsa_is_computer_sid( const SID *sid );
BOOL lsa_is_builtin_domain_sid( const SID *sid );
