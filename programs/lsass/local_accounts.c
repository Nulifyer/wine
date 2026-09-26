/*
 * Shared local account identity
 *
 * Copyright 2026
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winnt.h"
#include "rpc.h"
#include "rpcndr.h"
#include "local_accounts.h"

SID *lsa_allocate_computer_sid(void)
{
    static const SID_IDENTIFIER_AUTHORITY authority = { SECURITY_NT_AUTHORITY };
    const DWORD size = offsetof( SID, SubAuthority[4] );
    SID *sid;

    if (!(sid = MIDL_user_allocate( size ))) return NULL;
    sid->Revision = SID_REVISION;
    sid->SubAuthorityCount = 4;
    sid->IdentifierAuthority = authority;
    sid->SubAuthority[0] = SECURITY_NT_NON_UNIQUE;
    sid->SubAuthority[1] = 0;
    sid->SubAuthority[2] = 0;
    sid->SubAuthority[3] = 0;
    return sid;
}

BOOL lsa_is_computer_sid( const SID *sid )
{
    SID *computer_sid;
    BOOL ret;

    if (!sid || !IsValidSid((SID *)sid)) return FALSE;
    if (!(computer_sid = lsa_allocate_computer_sid())) return FALSE;
    ret = EqualSid( (SID *)sid, computer_sid );
    MIDL_user_free( computer_sid );
    return ret;
}

BOOL lsa_is_builtin_domain_sid( const SID *sid )
{
    static const SID_IDENTIFIER_AUTHORITY authority = { SECURITY_NT_AUTHORITY };
    SID builtin = {SID_REVISION, 1, authority, {SECURITY_BUILTIN_DOMAIN_RID}};

    return sid && IsValidSid((SID *)sid) && EqualSid( (SID *)sid, &builtin );
}
