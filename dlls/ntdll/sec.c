/*
 *	Security functions
 *
 *	Copyright 1996-1998 Marcus Meissner
 * 	Copyright 2003 CodeWeavers Inc. (Ulrich Czekalla)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <math.h>

#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "ntdll_misc.h"
#include "ddk/ntddk.h"
#include "symcrypt.h"
#include "wine/exception.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(ntdll);
WINE_DECLARE_DEBUG_CHANNEL(secdesc);

static const USHORT protected_access_by_source_signer[] =
{
    0x000, 0x002, 0x004, 0x108, 0x110, 0x13e, 0x17e, 0x1fe, 0x000
};

/***********************************************************************
 *             RtlTestProtectedAccess  (NTDLL.@)
 */
BOOLEAN WINAPI RtlTestProtectedAccess( UCHAR source, UCHAR target )
{
    unsigned int source_signer = source >> 4;
    unsigned int target_signer = target >> 4;
    unsigned int target_type = target & 7;

    if (!target_type) return TRUE;
    if ((source & 7) < target_type) return FALSE;
    if (source_signer >= ARRAY_SIZE(protected_access_by_source_signer)) return FALSE;
    return !!(protected_access_by_source_signer[source_signer] & (1u << target_signer));
}

/***********************************************************************
 *             RtlValidProcessProtection  (NTDLL.@)
 */
BOOLEAN WINAPI RtlValidProcessProtection( UCHAR protection )
{
    static const UCHAR valid[] =
    {
        0x00, 0x08, 0x12, 0x21, 0x31, 0x41, 0x51, 0x52, 0x61, 0x62, 0x72, 0x81
    };
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(valid); ++i)
        if (protection == valid[i]) return TRUE;
    return FALSE;
}

/* wrappers for symcrypt */
SYMCRYPT_CPU_FEATURES SYMCRYPT_CALL SymCryptCpuFeaturesNeverPresent(void) { return 0; }
void SYMCRYPT_CALL SymCryptFatal( UINT32 fatalCode ) { }
void SYMCRYPT_CALL SymCryptInjectError( PBYTE pbBuf, SIZE_T cbBuf ) { }
#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
SYMCRYPT_ERROR SYMCRYPT_CALL SymCryptSaveXmm( PSYMCRYPT_EXTENDED_SAVE_DATA pSaveArea ) { return SYMCRYPT_NO_ERROR; }
void SYMCRYPT_CALL SymCryptRestoreXmm( PSYMCRYPT_EXTENDED_SAVE_DATA pSaveArea ) { }
#endif
__ASM_GLOBAL_IMPORT(memcmp)
__ASM_GLOBAL_IMPORT(memcpy)
__ASM_GLOBAL_IMPORT(memset)

#define SELF_RELATIVE_FIELD(sd,field) ((BYTE *)(sd) + ((SECURITY_DESCRIPTOR_RELATIVE *)(sd))->field)

static const SID world_sid = { SID_REVISION, 1, { SECURITY_WORLD_SID_AUTHORITY} , { SECURITY_WORLD_RID } };
static const DWORD world_access_acl_size = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + sizeof(world_sid) - sizeof(DWORD);

static void get_world_access_acl( PACL acl )
{
    PACCESS_ALLOWED_ACE ace = (PACCESS_ALLOWED_ACE)(acl + 1);

    acl->AclRevision = ACL_REVISION;
    acl->Sbz1 = 0;
    acl->AclSize = world_access_acl_size;
    acl->AceCount = 1;
    acl->Sbz2 = 0;
    ace->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    ace->Header.AceFlags = CONTAINER_INHERIT_ACE;
    ace->Header.AceSize = sizeof(ACCESS_ALLOWED_ACE) + sizeof(world_sid) - sizeof(DWORD);
    ace->Mask = 0xf3ffffff; /* Everything except reserved bits */
    memcpy( &ace->SidStart, &world_sid, sizeof(world_sid) );
}

/* helper function to retrieve active length of an ACL */
static size_t acl_bytesInUse(PACL pAcl)
{
    int i;
    size_t bytesInUse = sizeof(ACL);
    PACE_HEADER ace = (PACE_HEADER) (pAcl + 1);
    for (i = 0; i < pAcl->AceCount; i++)
    {
	bytesInUse += ace->AceSize;
	ace = (PACE_HEADER)(((BYTE*)ace)+ace->AceSize);
    }
    return bytesInUse;
}

/* generically adds an ACE to an ACL */
static NTSTATUS add_access_ace(PACL pAcl, DWORD dwAceRevision, DWORD dwAceFlags,
                               DWORD dwAccessMask, PSID pSid, DWORD dwAceType)
{
    ACE_HEADER *pAceHeader;
    DWORD dwLengthSid;
    DWORD dwAceSize;
    DWORD *pAccessMask;
    DWORD *pSidStart;

    if (!RtlValidSid(pSid))
        return STATUS_INVALID_SID;

    if (pAcl->AclRevision > MAX_ACL_REVISION || dwAceRevision > MAX_ACL_REVISION)
        return STATUS_REVISION_MISMATCH;

    if (!RtlValidAcl(pAcl))
        return STATUS_INVALID_ACL;

    if (!RtlFirstFreeAce(pAcl, &pAceHeader))
        return STATUS_INVALID_ACL;

    if (!pAceHeader)
        return STATUS_ALLOTTED_SPACE_EXCEEDED;

    /* calculate generic size of the ACE */
    dwLengthSid = RtlLengthSid(pSid);
    dwAceSize = sizeof(ACE_HEADER) + sizeof(DWORD) + dwLengthSid;
    if ((char *)pAceHeader + dwAceSize > (char *)pAcl + pAcl->AclSize)
        return STATUS_ALLOTTED_SPACE_EXCEEDED;

    /* fill the new ACE */
    pAceHeader->AceType = dwAceType;
    pAceHeader->AceFlags = dwAceFlags;
    pAceHeader->AceSize = dwAceSize;

    /* skip past the ACE_HEADER of the ACE */
    pAccessMask = (DWORD *)(pAceHeader + 1);
    *pAccessMask = dwAccessMask;

    /* skip past ACE->Mask */
    pSidStart = pAccessMask + 1;
    RtlCopySid(dwLengthSid, pSidStart, pSid);

    pAcl->AclRevision = max(pAcl->AclRevision, dwAceRevision);
    pAcl->AceCount++;

    return STATUS_SUCCESS;
}

/*
 *	SID FUNCTIONS
 */

/******************************************************************************
 *  RtlAllocateAndInitializeSid		[NTDLL.@]
 *
 */
NTSTATUS WINAPI RtlAllocateAndInitializeSid (
	PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
	BYTE nSubAuthorityCount,
	DWORD nSubAuthority0, DWORD nSubAuthority1,
	DWORD nSubAuthority2, DWORD nSubAuthority3,
	DWORD nSubAuthority4, DWORD nSubAuthority5,
	DWORD nSubAuthority6, DWORD nSubAuthority7,
	PSID *pSid )
{
    SID *tmp_sid;

    TRACE("(%p, 0x%04x,0x%08lx,0x%08lx,0x%08lx,0x%08lx,0x%08lx,0x%08lx,0x%08lx,0x%08lx,%p)\n",
		pIdentifierAuthority,nSubAuthorityCount,
		nSubAuthority0, nSubAuthority1,	nSubAuthority2, nSubAuthority3,
		nSubAuthority4, nSubAuthority5,	nSubAuthority6, nSubAuthority7, pSid);

    if (nSubAuthorityCount > 8) return STATUS_INVALID_SID;

    if (!(tmp_sid= RtlAllocateHeap( GetProcessHeap(), 0,
                                    RtlLengthRequiredSid(nSubAuthorityCount))))
        return STATUS_NO_MEMORY;

    tmp_sid->Revision = SID_REVISION;

    if (pIdentifierAuthority)
        tmp_sid->IdentifierAuthority = *pIdentifierAuthority;
    tmp_sid->SubAuthorityCount = nSubAuthorityCount;

    switch( nSubAuthorityCount )
    {
        case 8: tmp_sid->SubAuthority[7]= nSubAuthority7;
            /* fall through */
        case 7: tmp_sid->SubAuthority[6]= nSubAuthority6;
            /* fall through */
        case 6: tmp_sid->SubAuthority[5]= nSubAuthority5;
            /* fall through */
        case 5: tmp_sid->SubAuthority[4]= nSubAuthority4;
            /* fall through */
        case 4: tmp_sid->SubAuthority[3]= nSubAuthority3;
            /* fall through */
        case 3: tmp_sid->SubAuthority[2]= nSubAuthority2;
            /* fall through */
        case 2: tmp_sid->SubAuthority[1]= nSubAuthority1;
            /* fall through */
        case 1: tmp_sid->SubAuthority[0]= nSubAuthority0;
        break;
    }
    *pSid = tmp_sid;
    return STATUS_SUCCESS;
}

/******************************************************************************
 *  RtlAllocateAndInitializeSidEx             [NTDLL.@]
 */
NTSTATUS WINAPI RtlAllocateAndInitializeSidEx( PSID_IDENTIFIER_AUTHORITY authority,
                                               BYTE sub_authority_count,
                                               ULONG *sub_authorities, PSID *sid )
{
    SID *ret;

    TRACE( "(%p, %u, %p, %p)\n", authority, sub_authority_count, sub_authorities, sid );

    if (sub_authority_count > SID_MAX_SUB_AUTHORITIES) return STATUS_INVALID_PARAMETER;

    if (!(ret = RtlAllocateHeap( GetProcessHeap(), 0,
                                 RtlLengthRequiredSid( sub_authority_count ) )))
        return STATUS_NO_MEMORY;

    ret->Revision = SID_REVISION;
    ret->SubAuthorityCount = sub_authority_count;
    ret->IdentifierAuthority = *authority;
    if (sub_authority_count)
        memcpy( ret->SubAuthority, sub_authorities,
                sub_authority_count * sizeof(*sub_authorities) );
    *sid = ret;
    return STATUS_SUCCESS;
}

/******************************************************************************
 *  RtlEqualSid		[NTDLL.@]
 *
 * Determine if two SIDs are equal.
 *
 * PARAMS
 *  pSid1 [I] Source SID
 *  pSid2 [I] SID to compare with
 *
 * RETURNS
 *  TRUE, if pSid1 is equal to pSid2,
 *  FALSE otherwise.
 */
BOOL WINAPI RtlEqualSid( PSID pSid1, PSID pSid2 )
{
    if (!RtlValidSid(pSid1) || !RtlValidSid(pSid2))
        return FALSE;

    if (*RtlSubAuthorityCountSid(pSid1) != *RtlSubAuthorityCountSid(pSid2))
        return FALSE;

    if (memcmp(pSid1, pSid2, RtlLengthSid(pSid1)) != 0)
        return FALSE;

    return TRUE;
}

/******************************************************************************
 * RtlEqualPrefixSid	[NTDLL.@]
 */
BOOL WINAPI RtlEqualPrefixSid (PSID pSid1, PSID pSid2)
{
    if (!RtlValidSid(pSid1) || !RtlValidSid(pSid2))
        return FALSE;

    if (*RtlSubAuthorityCountSid(pSid1) != *RtlSubAuthorityCountSid(pSid2))
        return FALSE;

    if (memcmp(pSid1, pSid2, RtlLengthRequiredSid(((SID*)pSid1)->SubAuthorityCount - 1)) != 0)
        return FALSE;

    return TRUE;
}


/******************************************************************************
 *  RtlFreeSid		[NTDLL.@]
 *
 * Free the resources used by a SID.
 *
 * PARAMS
 *  pSid [I] SID to Free.
 *
 * RETURNS
 *  STATUS_SUCCESS.
 */
DWORD WINAPI RtlFreeSid(PSID pSid)
{
	TRACE("(%p)\n", pSid);
	RtlFreeHeap( GetProcessHeap(), 0, pSid );
	return STATUS_SUCCESS;
}

/**************************************************************************
 * RtlLengthRequiredSid	[NTDLL.@]
 *
 * Determine the amount of memory a SID will use
 *
 * PARAMS
 *   nrofsubauths [I] Number of Sub Authorities in the SID.
 *
 * RETURNS
 *   The size, in bytes, of a SID with nrofsubauths Sub Authorities.
 */
DWORD WINAPI RtlLengthRequiredSid(DWORD nrofsubauths)
{
	return (nrofsubauths-1)*sizeof(DWORD) + sizeof(SID);
}

/**************************************************************************
 *                 RtlLengthSid				[NTDLL.@]
 *
 * Determine the amount of memory a SID is using
 *
 * PARAMS
 *  pSid [I] SID to get the size of.
 *
 * RETURNS
 *  The size, in bytes, of pSid.
 */
DWORD WINAPI RtlLengthSid(PSID pSid)
{
	return RtlLengthRequiredSid(*RtlSubAuthorityCountSid(pSid));
}

/**************************************************************************
 *                 RtlInitializeSid			[NTDLL.@]
 */
NTSTATUS WINAPI RtlInitializeSid(
	PSID pSid,
	PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
	BYTE nSubAuthorityCount)
{
	int i;
	SID* pisid=pSid;

	if (nSubAuthorityCount > SID_MAX_SUB_AUTHORITIES)
	  return STATUS_INVALID_PARAMETER;

	pisid->Revision = SID_REVISION;
	pisid->SubAuthorityCount = nSubAuthorityCount;
	if (pIdentifierAuthority)
	  pisid->IdentifierAuthority = *pIdentifierAuthority;

	for (i = 0; i < nSubAuthorityCount; i++)
	  *RtlSubAuthoritySid(pSid, i) = 0;

	return STATUS_SUCCESS;
}

/**************************************************************************
 *                 RtlSubAuthoritySid			[NTDLL.@]
 *
 * Return the Sub Authority of a SID
 *
 * PARAMS
 *   pSid          [I] SID to get the Sub Authority from.
 *   nSubAuthority [I] Sub Authority number.
 *
 * RETURNS
 *   A pointer to The Sub Authority value of pSid.
 */
LPDWORD WINAPI RtlSubAuthoritySid( PSID pSid, DWORD nSubAuthority )
{
    return &(((SID*)pSid)->SubAuthority[nSubAuthority]);
}

/**************************************************************************
 * RtlIdentifierAuthoritySid	[NTDLL.@]
 *
 * Return the Identifier Authority of a SID.
 *
 * PARAMS
 *   pSid [I] SID to get the Identifier Authority from.
 *
 * RETURNS
 *   A pointer to the Identifier Authority value of pSid.
 */
PSID_IDENTIFIER_AUTHORITY WINAPI RtlIdentifierAuthoritySid( PSID pSid )
{
    return &(((SID*)pSid)->IdentifierAuthority);
}

/**************************************************************************
 *                 RtlSubAuthorityCountSid		[NTDLL.@]
 *
 * Get the number of Sub Authorities in a SID.
 *
 * PARAMS
 *   pSid [I] SID to get the count from.
 *
 * RETURNS
 *  A pointer to the Sub Authority count of pSid.
 */
LPBYTE WINAPI RtlSubAuthorityCountSid(PSID pSid)
{
    return &(((SID*)pSid)->SubAuthorityCount);
}

/**************************************************************************
 *                 RtlSidHashInitialize                [NTDLL.@]
 */
NTSTATUS WINAPI RtlSidHashInitialize( SID_AND_ATTRIBUTES *attrs, ULONG count,
                                      SID_AND_ATTRIBUTES_HASH *hash )
{
    ULONG i, hash_count;

    if (!hash) return STATUS_INVALID_PARAMETER;

    memset( hash, 0, sizeof(*hash) );
    if (!attrs || !count) return STATUS_SUCCESS;

    hash->SidCount = count;
    hash->SidAttr = attrs;
    hash_count = min( count, 8 * sizeof(hash->Hash[0]) );

    for (i = 0; i < hash_count; i++)
    {
        SID *sid = attrs[i].Sid;
        BYTE value = *((BYTE *)sid + 4 + 4 * sid->SubAuthorityCount);
        SID_HASH_ENTRY bit = (SID_HASH_ENTRY)1 << i;

        hash->Hash[value & 0x0f] |= bit;
        hash->Hash[16 + (value >> 4)] |= bit;
    }
    return STATUS_SUCCESS;
}

/**************************************************************************
 *                 RtlSidHashLookup                    [NTDLL.@]
 */
SID_AND_ATTRIBUTES * WINAPI RtlSidHashLookup( SID_AND_ATTRIBUTES_HASH *hash, PSID sid )
{
    SID_HASH_ENTRY candidates;
    ULONG i, hash_count, sid_len;
    BYTE value;

    if (!hash || !sid) return NULL;

    value = *((BYTE *)sid + 4 + 4 * ((SID *)sid)->SubAuthorityCount);
    candidates = hash->Hash[value & 0x0f] & hash->Hash[16 + (value >> 4)];
    hash_count = min( hash->SidCount, 8 * sizeof(hash->Hash[0]) );
    sid_len = RtlLengthSid( sid );

    for (i = 0; i < hash_count; i++)
    {
        PSID candidate;

        if (!(candidates & ((SID_HASH_ENTRY)1 << i))) continue;
        candidate = hash->SidAttr[i].Sid;
        if (RtlLengthSid( candidate ) == sid_len && !memcmp( candidate, sid, sid_len ))
            return &hash->SidAttr[i];
    }

    for (; i < hash->SidCount; i++)
    {
        PSID candidate = hash->SidAttr[i].Sid;

        if (RtlLengthSid( candidate ) == sid_len && !memcmp( candidate, sid, sid_len ))
            return &hash->SidAttr[i];
    }
    return NULL;
}

/**************************************************************************
 *                 NtCreateTokenEx                      [NTDLL.@]
 */
NTSTATUS WINAPI NtCreateTokenEx( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr,
                                 TOKEN_TYPE type, LUID *token_id, LARGE_INTEGER *expire,
                                 TOKEN_USER *user, TOKEN_GROUPS *groups, TOKEN_PRIVILEGES *privs,
                                 void *user_attrs, void *device_attrs, TOKEN_GROUPS *device_groups,
                                 TOKEN_MANDATORY_POLICY *mandatory_policy, TOKEN_OWNER *owner,
                                 TOKEN_PRIMARY_GROUP *group, TOKEN_DEFAULT_DACL *dacl,
                                 TOKEN_SOURCE *source )
{
    TRACE( "(%p,0x%08lx,%p,%d,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p)\n",
           handle, access, attr, type, token_id, expire, user, groups, privs, user_attrs,
           device_attrs, device_groups, mandatory_policy, owner, group, dacl, source );

    if (user_attrs || device_attrs || device_groups)
        FIXME( "token security attributes and device groups are not supported\n" );

    return NtCreateToken( handle, access, attr, type, token_id, expire, user, groups, privs,
                          owner, group, dacl, source );
}

/**************************************************************************
 *                 RtlCopySid				[NTDLL.@]
 */
NTSTATUS WINAPI RtlCopySid( DWORD destlen, PSID dest, PSID source )
{
	DWORD len = RtlLengthSid(source);

	if (destlen < len) return STATUS_BUFFER_TOO_SMALL;
	memmove(dest, source, len);
	return STATUS_SUCCESS;
}

/******************************************************************************
 * RtlValidSid [NTDLL.@]
 *
 * Determine if a SID is valid.
 *
 * PARAMS
 *   pSid [I] SID to check
 *
 * RETURNS
 *   TRUE if pSid is valid,
 *   FALSE otherwise.
 */
BOOLEAN WINAPI RtlValidSid( PSID pSid )
{
    BOOL ret;
    __TRY
    {
        ret = TRUE;
        if (!pSid || ((SID*)pSid)->Revision != SID_REVISION ||
            ((SID*)pSid)->SubAuthorityCount > SID_MAX_SUB_AUTHORITIES)
        {
            ret = FALSE;
        }
    }
    __EXCEPT_PAGE_FAULT
    {
        WARN("(%p): invalid pointer!\n", pSid);
        return FALSE;
    }
    __ENDTRY
    return ret;
}


/*
 *	security descriptor functions
 */

/**************************************************************************
 * RtlCreateSecurityDescriptor			[NTDLL.@]
 *
 * Initialise a SECURITY_DESCRIPTOR.
 *
 * PARAMS
 *  lpsd [O] Descriptor to initialise.
 *  rev  [I] Revision, must be set to SECURITY_DESCRIPTOR_REVISION.
 *
 * RETURNS
 *  Success: STATUS_SUCCESS.
 *  Failure: STATUS_UNKNOWN_REVISION if rev is incorrect.
 */
NTSTATUS WINAPI RtlCreateSecurityDescriptor(
	PSECURITY_DESCRIPTOR lpsd,
	DWORD rev)
{
	if (rev!=SECURITY_DESCRIPTOR_REVISION)
		return STATUS_UNKNOWN_REVISION;
	memset(lpsd,'\0',sizeof(SECURITY_DESCRIPTOR));
	((SECURITY_DESCRIPTOR*)lpsd)->Revision = SECURITY_DESCRIPTOR_REVISION;
	return STATUS_SUCCESS;
}

/**************************************************************************
 * RtlCreateAndSetSD                              [NTDLL.@]
 */
NTSTATUS WINAPI RtlCreateAndSetSD( RTL_ACE_DATA *ace_data, ULONG ace_count, PSID owner_sid,
                                   PSID group_sid, PSECURITY_DESCRIPTOR *new_sd )
{
    ULONG dacl_size = sizeof(ACL), sacl_size = sizeof(ACL), max_ace_size = 0;
    ACL *dacl = NULL, *sacl = NULL;
    SECURITY_DESCRIPTOR *sd;
    BYTE *ace_buffer = NULL;
    ULONG total_size, i;
    HANDLE heap = GetProcessHeap();
    NTSTATUS status;

    TRACE( "(%p,%lu,%p,%p,%p)\n", ace_data, ace_count, owner_sid, group_sid, new_sd );

    for (i = 0; i < ace_count; i++)
    {
        ULONG ace_size = RtlLengthSid( *ace_data[i].Sid ) + 12;
        ULONG *acl_size;

        switch (ace_data[i].AceType)
        {
        case ACCESS_ALLOWED_ACE_TYPE:
        case ACCESS_DENIED_ACE_TYPE:
            acl_size = &dacl_size;
            break;
        case SYSTEM_AUDIT_ACE_TYPE:
            acl_size = &sacl_size;
            break;
        default:
            return STATUS_INVALID_PARAMETER;
        }

        if (*acl_size > ~(ULONG)0 - ace_size) return STATUS_NO_MEMORY;
        *acl_size += ace_size;
        if (ace_size > max_ace_size) max_ace_size = ace_size;
    }

    total_size = sizeof(*sd);
    if (dacl_size != sizeof(ACL))
    {
        if (total_size > ~(ULONG)0 - dacl_size) return STATUS_NO_MEMORY;
        total_size += dacl_size;
    }
    if (sacl_size != sizeof(ACL))
    {
        if (total_size > ~(ULONG)0 - sacl_size) return STATUS_NO_MEMORY;
        total_size += sacl_size;
    }

    if (!(sd = RtlAllocateHeap( heap, 0, total_size ))) return STATUS_NO_MEMORY;

    if (dacl_size != sizeof(ACL))
    {
        dacl = (ACL *)(sd + 1);
        status = RtlCreateAcl( dacl, dacl_size, ACL_REVISION );
        if (status) goto failed;
    }
    if (sacl_size != sizeof(ACL))
    {
        sacl = (ACL *)((BYTE *)(sd + 1) + (dacl ? dacl_size : 0));
        status = RtlCreateAcl( sacl, sacl_size, ACL_REVISION );
        if (status) goto failed;
    }

    if (max_ace_size && !(ace_buffer = RtlAllocateHeap( heap, 0, max_ace_size )))
    {
        status = STATUS_NO_MEMORY;
        goto failed;
    }

    for (i = 0; i < ace_count; i++)
    {
        PSID sid = *ace_data[i].Sid;
        ULONG sid_size = RtlLengthSid( sid );
        ULONG ace_size = sid_size + 12;
        ACE_HEADER *header = (ACE_HEADER *)ace_buffer;
        ACL *acl;

        memset( ace_buffer, 0, ace_size );
        header->AceType = ace_data[i].AceType;
        header->AceFlags = ace_data[i].InheritFlags | ace_data[i].AceFlags;
        header->AceSize = ace_size;
        *(ACCESS_MASK *)(ace_buffer + sizeof(*header)) = ace_data[i].Mask;

        status = RtlCopySid( sid_size, ace_buffer + sizeof(*header) + sizeof(ACCESS_MASK), sid );
        if (status) goto failed;

        acl = ace_data[i].AceType == SYSTEM_AUDIT_ACE_TYPE ? sacl : dacl;
        status = RtlAddAce( acl, ACL_REVISION, ~(ULONG)0, header, ace_size );
        if (status) goto failed;
    }

    if ((status = RtlCreateSecurityDescriptor( sd, SECURITY_DESCRIPTOR_REVISION ))) goto failed;
    if ((status = RtlSetOwnerSecurityDescriptor( sd, owner_sid, FALSE ))) goto failed;
    if ((status = RtlSetGroupSecurityDescriptor( sd, group_sid, FALSE ))) goto failed;
    if ((status = RtlSetDaclSecurityDescriptor( sd, TRUE, dacl, FALSE ))) goto failed;
    if ((status = RtlSetSaclSecurityDescriptor( sd, sacl != NULL, sacl, FALSE ))) goto failed;

    *new_sd = sd;
    RtlFreeHeap( heap, 0, ace_buffer );
    return STATUS_SUCCESS;

failed:
    RtlFreeHeap( heap, 0, ace_buffer );
    RtlFreeHeap( heap, 0, sd );
    return status;
}

static ULONG align_security_descriptor_size( ULONG size )
{
    return (size + sizeof(ULONG) - 1) & ~(sizeof(ULONG) - 1);
}

/**************************************************************************
 * RtlCopySecurityDescriptor            [NTDLL.@]
 *
 * Allocates a copy of an absolute or self-relative SECURITY_DESCRIPTOR.
 */
NTSTATUS WINAPI RtlCopySecurityDescriptor( PSECURITY_DESCRIPTOR source,
                                           PSECURITY_DESCRIPTOR *destination )
{
    SECURITY_DESCRIPTOR_RELATIVE *relative = source;
    SECURITY_DESCRIPTOR *absolute = source;
    SECURITY_DESCRIPTOR_CONTROL control = absolute->Control;
    PSID owner, group;
    ACL *dacl, *sacl;
    ULONG size = sizeof(*relative);

    if (control & SE_SELF_RELATIVE)
    {
        owner = relative->Owner ? (PSID)SELF_RELATIVE_FIELD(relative, Owner) : NULL;
        group = relative->Group ? (PSID)SELF_RELATIVE_FIELD(relative, Group) : NULL;
        dacl = (control & SE_DACL_PRESENT) && relative->Dacl
            ? (ACL *)SELF_RELATIVE_FIELD(relative, Dacl) : NULL;
        sacl = (control & SE_SACL_PRESENT) && relative->Sacl
            ? (ACL *)SELF_RELATIVE_FIELD(relative, Sacl) : NULL;
    }
    else
    {
        owner = absolute->Owner;
        group = absolute->Group;
        dacl = (control & SE_DACL_PRESENT) ? absolute->Dacl : NULL;
        sacl = (control & SE_SACL_PRESENT) ? absolute->Sacl : NULL;
    }

    if (owner) size += align_security_descriptor_size( RtlLengthSid(owner) );
    if (group) size += align_security_descriptor_size( RtlLengthSid(group) );
    if (dacl) size += align_security_descriptor_size( dacl->AclSize );
    if (sacl) size += align_security_descriptor_size( sacl->AclSize );

    if (!(*destination = RtlAllocateHeap( GetProcessHeap(), 0, size )))
        return STATUS_NO_MEMORY;
    memcpy( *destination, source, size );
    return STATUS_SUCCESS;
}

/**************************************************************************
 * RtlValidSecurityDescriptor			[NTDLL.@]
 */
BOOLEAN WINAPI RtlValidSecurityDescriptor(PSECURITY_DESCRIPTOR descriptor)
{
    SECURITY_DESCRIPTOR *sd = descriptor;
    return sd && sd->Revision == SECURITY_DESCRIPTOR_REVISION;
}

static BOOLEAN valid_sid_buffer( const SID *sid, ULONG length )
{
    if (length < offsetof( SID, SubAuthority )) return FALSE;
    return sid->Revision == SID_REVISION && sid->SubAuthorityCount <= SID_MAX_SUB_AUTHORITIES &&
           length >= offsetof( SID, SubAuthority ) + sid->SubAuthorityCount * sizeof(DWORD);
}

static BOOLEAN valid_relative_sid( const SECURITY_DESCRIPTOR_RELATIVE *sd, ULONG length, ULONG offset )
{
    if (offset < sizeof(*sd) || offset >= length || (offset & 3)) return FALSE;
    if (length - offset < sizeof(SID)) return FALSE;
    return valid_sid_buffer( (const SID *)((const BYTE *)sd + offset), length - offset );
}

static BOOLEAN valid_relative_acl( const SECURITY_DESCRIPTOR_RELATIVE *sd, ULONG length, ULONG offset )
{
    ACL *acl;

    if (!offset) return TRUE;
    if (offset < sizeof(*sd) || offset >= length || (offset & 3)) return FALSE;
    if (length - offset < sizeof(*acl)) return FALSE;
    acl = (ACL *)((BYTE *)sd + offset);
    return acl->AclSize <= length - offset && RtlValidAcl( acl );
}

static BOOLEAN valid_relative_security_descriptor( const SECURITY_DESCRIPTOR_RELATIVE *sd,
                                                   ULONG length, SECURITY_INFORMATION info )
{
    if (length < sizeof(*sd)) return FALSE;
    if (sd->Revision != SECURITY_DESCRIPTOR_REVISION || !(sd->Control & SE_SELF_RELATIVE)) return FALSE;
    if (sd->Owner ? !valid_relative_sid( sd, length, sd->Owner ) : !!(info & OWNER_SECURITY_INFORMATION))
        return FALSE;
    if (sd->Group ? !valid_relative_sid( sd, length, sd->Group ) : !!(info & GROUP_SECURITY_INFORMATION))
        return FALSE;
    if ((sd->Control & SE_DACL_PRESENT) && !valid_relative_acl( sd, length, sd->Dacl )) return FALSE;
    if ((sd->Control & SE_SACL_PRESENT) && !valid_relative_acl( sd, length, sd->Sacl )) return FALSE;
    return TRUE;
}

/**************************************************************************
 * RtlValidRelativeSecurityDescriptor            [NTDLL.@]
 */
BOOLEAN WINAPI RtlValidRelativeSecurityDescriptor( PSECURITY_DESCRIPTOR descriptor,
                                                   ULONG length, SECURITY_INFORMATION info )
{
    BOOLEAN ret = valid_relative_security_descriptor( descriptor, length, info );

    TRACE_(secdesc)( "%p, %lu, %#lx: %u\n", descriptor, length, info, ret );
    return ret;
}

/**************************************************************************
 *  RtlLengthSecurityDescriptor			[NTDLL.@]
 */
ULONG WINAPI RtlLengthSecurityDescriptor(
	PSECURITY_DESCRIPTOR pSecurityDescriptor)
{
	ULONG size;

	if ( pSecurityDescriptor == NULL )
		return 0;

	if (((SECURITY_DESCRIPTOR *)pSecurityDescriptor)->Control & SE_SELF_RELATIVE)
        {
            SECURITY_DESCRIPTOR_RELATIVE *sd = pSecurityDescriptor;
            size = sizeof(*sd);
            if (sd->Owner) size += RtlLengthSid((PSID)SELF_RELATIVE_FIELD(sd,Owner));
            if (sd->Group) size += RtlLengthSid((PSID)SELF_RELATIVE_FIELD(sd,Group));
            if ((sd->Control & SE_SACL_PRESENT) && sd->Sacl)
		size += ((PACL)SELF_RELATIVE_FIELD(sd,Sacl))->AclSize;
            if ((sd->Control & SE_DACL_PRESENT) && sd->Dacl)
		size += ((PACL)SELF_RELATIVE_FIELD(sd,Dacl))->AclSize;
        }
        else
        {
            SECURITY_DESCRIPTOR *sd = pSecurityDescriptor;
            size = sizeof(*sd);
            if (sd->Owner) size += RtlLengthSid( sd->Owner );
            if (sd->Group) size += RtlLengthSid( sd->Group );
            if ((sd->Control & SE_SACL_PRESENT) && sd->Sacl) size += sd->Sacl->AclSize;
            if ((sd->Control & SE_DACL_PRESENT) && sd->Dacl) size += sd->Dacl->AclSize;
        }
	return size;
}

/******************************************************************************
 *  RtlGetDaclSecurityDescriptor		[NTDLL.@]
 *
 */
NTSTATUS WINAPI RtlGetDaclSecurityDescriptor(
	IN PSECURITY_DESCRIPTOR pSecurityDescriptor,
	OUT PBOOLEAN lpbDaclPresent,
	OUT PACL *pDacl,
	OUT PBOOLEAN lpbDaclDefaulted)
{
	SECURITY_DESCRIPTOR* lpsd=pSecurityDescriptor;

	TRACE("(%p,%p,%p,%p)\n",
	pSecurityDescriptor, lpbDaclPresent, pDacl, lpbDaclDefaulted);

	if (lpsd->Revision != SECURITY_DESCRIPTOR_REVISION)
	  return STATUS_UNKNOWN_REVISION ;

	if ( (*lpbDaclPresent = (SE_DACL_PRESENT & lpsd->Control) ? 1 : 0) )
	{
            if (lpsd->Control & SE_SELF_RELATIVE)
            {
                SECURITY_DESCRIPTOR_RELATIVE *sdr = pSecurityDescriptor;
                if (sdr->Dacl) *pDacl = (PACL)SELF_RELATIVE_FIELD( sdr, Dacl );
                else *pDacl = NULL;
            }
            else *pDacl = lpsd->Dacl;

            *lpbDaclDefaulted = (lpsd->Control & SE_DACL_DEFAULTED) != 0;
        }
        else
        {
            *pDacl = NULL;
            *lpbDaclDefaulted = 0;
        }

	return STATUS_SUCCESS;
}

/**************************************************************************
 *  RtlSetDaclSecurityDescriptor		[NTDLL.@]
 */
NTSTATUS WINAPI RtlSetDaclSecurityDescriptor (
	PSECURITY_DESCRIPTOR pSecurityDescriptor,
	BOOLEAN daclpresent,
	PACL dacl,
	BOOLEAN dacldefaulted )
{
	SECURITY_DESCRIPTOR* lpsd=pSecurityDescriptor;

	if (lpsd->Revision!=SECURITY_DESCRIPTOR_REVISION)
		return STATUS_UNKNOWN_REVISION;
	if (lpsd->Control & SE_SELF_RELATIVE)
		return STATUS_INVALID_SECURITY_DESCR;

	if (!daclpresent)
	{
		lpsd->Control &= ~SE_DACL_PRESENT;
		return STATUS_SUCCESS;
	}

	lpsd->Control |= SE_DACL_PRESENT;
	lpsd->Dacl = dacl;

	if (dacldefaulted)
		lpsd->Control |= SE_DACL_DEFAULTED;
	else
		lpsd->Control &= ~SE_DACL_DEFAULTED;

	return STATUS_SUCCESS;
}

/******************************************************************************
 *  RtlGetSaclSecurityDescriptor		[NTDLL.@]
 *
 */
NTSTATUS WINAPI RtlGetSaclSecurityDescriptor(
	IN PSECURITY_DESCRIPTOR pSecurityDescriptor,
	OUT PBOOLEAN lpbSaclPresent,
	OUT PACL *pSacl,
	OUT PBOOLEAN lpbSaclDefaulted)
{
	SECURITY_DESCRIPTOR* lpsd=pSecurityDescriptor;

	TRACE("(%p,%p,%p,%p)\n",
	pSecurityDescriptor, lpbSaclPresent, pSacl, lpbSaclDefaulted);

	if (lpsd->Revision != SECURITY_DESCRIPTOR_REVISION)
	  return STATUS_UNKNOWN_REVISION;

	if ( (*lpbSaclPresent = (SE_SACL_PRESENT & lpsd->Control) ? 1 : 0) )
	{
            if (lpsd->Control & SE_SELF_RELATIVE)
            {
                SECURITY_DESCRIPTOR_RELATIVE *sdr = pSecurityDescriptor;
                if (sdr->Sacl) *pSacl = (PACL)SELF_RELATIVE_FIELD( sdr, Sacl );
                else *pSacl = NULL;
            }
            else *pSacl = lpsd->Sacl;

            *lpbSaclDefaulted = (lpsd->Control & SE_SACL_DEFAULTED) != 0;
	}
	return STATUS_SUCCESS;
}

/**************************************************************************
 * RtlSetSaclSecurityDescriptor			[NTDLL.@]
 */
NTSTATUS WINAPI RtlSetSaclSecurityDescriptor (
	PSECURITY_DESCRIPTOR pSecurityDescriptor,
	BOOLEAN saclpresent,
	PACL sacl,
	BOOLEAN sacldefaulted)
{
	SECURITY_DESCRIPTOR* lpsd=pSecurityDescriptor;

	if (lpsd->Revision!=SECURITY_DESCRIPTOR_REVISION)
		return STATUS_UNKNOWN_REVISION;
	if (lpsd->Control & SE_SELF_RELATIVE)
		return STATUS_INVALID_SECURITY_DESCR;
	if (!saclpresent) {
		lpsd->Control &= ~SE_SACL_PRESENT;
		return 0;
	}
	lpsd->Control |= SE_SACL_PRESENT;
	lpsd->Sacl = sacl;
	if (sacldefaulted)
		lpsd->Control |= SE_SACL_DEFAULTED;
	else
		lpsd->Control &= ~SE_SACL_DEFAULTED;
	return STATUS_SUCCESS;
}

/**************************************************************************
 * RtlGetOwnerSecurityDescriptor		[NTDLL.@]
 */
NTSTATUS WINAPI RtlGetOwnerSecurityDescriptor(
	PSECURITY_DESCRIPTOR pSecurityDescriptor,
	PSID *Owner,
	PBOOLEAN OwnerDefaulted)
{
	SECURITY_DESCRIPTOR* lpsd=pSecurityDescriptor;

	if ( !lpsd  || !Owner || !OwnerDefaulted )
		return STATUS_INVALID_PARAMETER;

        if ( lpsd->Control & SE_OWNER_DEFAULTED )
            *OwnerDefaulted = TRUE;
        else
            *OwnerDefaulted = FALSE;

        if (lpsd->Control & SE_SELF_RELATIVE)
        {
            SECURITY_DESCRIPTOR_RELATIVE *sd = pSecurityDescriptor;
            if (sd->Owner) *Owner = (PSID)SELF_RELATIVE_FIELD( sd, Owner );
            else *Owner = NULL;
        }
        else
            *Owner = lpsd->Owner;

	return STATUS_SUCCESS;
}

/**************************************************************************
 *                 RtlSetOwnerSecurityDescriptor		[NTDLL.@]
 */
NTSTATUS WINAPI RtlSetOwnerSecurityDescriptor(
	PSECURITY_DESCRIPTOR pSecurityDescriptor,
	PSID owner,
	BOOLEAN ownerdefaulted)
{
	SECURITY_DESCRIPTOR* lpsd=pSecurityDescriptor;

	if (lpsd->Revision!=SECURITY_DESCRIPTOR_REVISION)
		return STATUS_UNKNOWN_REVISION;
	if (lpsd->Control & SE_SELF_RELATIVE)
		return STATUS_INVALID_SECURITY_DESCR;

	lpsd->Owner = owner;
	if (ownerdefaulted)
		lpsd->Control |= SE_OWNER_DEFAULTED;
	else
		lpsd->Control &= ~SE_OWNER_DEFAULTED;
	return STATUS_SUCCESS;
}

/**************************************************************************
 *                 RtlSetGroupSecurityDescriptor		[NTDLL.@]
 */
NTSTATUS WINAPI RtlSetGroupSecurityDescriptor (
	PSECURITY_DESCRIPTOR pSecurityDescriptor,
	PSID group,
	BOOLEAN groupdefaulted)
{
	SECURITY_DESCRIPTOR* lpsd=pSecurityDescriptor;

	if (lpsd->Revision!=SECURITY_DESCRIPTOR_REVISION)
		return STATUS_UNKNOWN_REVISION;
	if (lpsd->Control & SE_SELF_RELATIVE)
		return STATUS_INVALID_SECURITY_DESCR;

	lpsd->Group = group;
	if (groupdefaulted)
		lpsd->Control |= SE_GROUP_DEFAULTED;
	else
		lpsd->Control &= ~SE_GROUP_DEFAULTED;
	return STATUS_SUCCESS;
}

/**************************************************************************
 *                 RtlGetGroupSecurityDescriptor		[NTDLL.@]
 */
NTSTATUS WINAPI RtlGetGroupSecurityDescriptor(
	PSECURITY_DESCRIPTOR pSecurityDescriptor,
	PSID *Group,
	PBOOLEAN GroupDefaulted)
{
	SECURITY_DESCRIPTOR* lpsd=pSecurityDescriptor;

	if ( !lpsd || !Group || !GroupDefaulted )
		return STATUS_INVALID_PARAMETER;

        if ( lpsd->Control & SE_GROUP_DEFAULTED )
            *GroupDefaulted = TRUE;
        else
            *GroupDefaulted = FALSE;

        if (lpsd->Control & SE_SELF_RELATIVE)
        {
            SECURITY_DESCRIPTOR_RELATIVE *sd = pSecurityDescriptor;
            if (sd->Group) *Group = (PSID)SELF_RELATIVE_FIELD( sd, Group );
            else *Group = NULL;
        }
        else
            *Group = lpsd->Group;

	return STATUS_SUCCESS;
}

/**************************************************************************
 *                 RtlMakeSelfRelativeSD		[NTDLL.@]
 */
NTSTATUS WINAPI RtlMakeSelfRelativeSD(
	IN PSECURITY_DESCRIPTOR pAbsoluteSecurityDescriptor,
	IN PSECURITY_DESCRIPTOR pSelfRelativeSecurityDescriptor,
	IN OUT LPDWORD lpdwBufferLength)
{
    DWORD offsetRel;
    ULONG length;
    SECURITY_DESCRIPTOR* pAbs = pAbsoluteSecurityDescriptor;
    SECURITY_DESCRIPTOR_RELATIVE *pRel = pSelfRelativeSecurityDescriptor;

    TRACE(" %p %p %p(%ld)\n", pAbs, pRel, lpdwBufferLength,
        lpdwBufferLength ? *lpdwBufferLength: -1);

    if (!lpdwBufferLength || !pAbs)
        return STATUS_INVALID_PARAMETER;

    length = RtlLengthSecurityDescriptor(pAbs);
    if (!(pAbs->Control & SE_SELF_RELATIVE)) length -= (sizeof(*pAbs) - sizeof(*pRel));
    if (*lpdwBufferLength < length)
    {
        *lpdwBufferLength = length;
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (!pRel)
        return STATUS_INVALID_PARAMETER;

    if (pAbs->Control & SE_SELF_RELATIVE)
    {
        memcpy(pRel, pAbs, length);
        return STATUS_SUCCESS;
    }

    pRel->Revision = pAbs->Revision;
    pRel->Sbz1 = pAbs->Sbz1;
    pRel->Control = pAbs->Control | SE_SELF_RELATIVE;

    offsetRel = sizeof(SECURITY_DESCRIPTOR_RELATIVE);
    if (pAbs->Owner)
    {
        pRel->Owner = offsetRel;
        length = RtlLengthSid(pAbs->Owner);
        memcpy((LPBYTE)pRel + offsetRel, pAbs->Owner, length);
        offsetRel += length;
    }
    else
    {
        pRel->Owner = 0;
    }

    if (pAbs->Group)
    {
        pRel->Group = offsetRel;
        length = RtlLengthSid(pAbs->Group);
        memcpy((LPBYTE)pRel + offsetRel, pAbs->Group, length);
        offsetRel += length;
    }
    else
    {
        pRel->Group = 0;
    }

    if (pAbs->Sacl)
    {
        pRel->Sacl = offsetRel;
        length = pAbs->Sacl->AclSize;
        memcpy((LPBYTE)pRel + offsetRel, pAbs->Sacl, length);
        offsetRel += length;
    }
    else
    {
        pRel->Sacl = 0;
    }

    if (pAbs->Dacl)
    {
        pRel->Dacl = offsetRel;
        length = pAbs->Dacl->AclSize;
        memcpy((LPBYTE)pRel + offsetRel, pAbs->Dacl, length);
    }
    else
    {
        pRel->Dacl = 0;
    }

    return STATUS_SUCCESS;
}


/**************************************************************************
 *                 RtlSelfRelativeToAbsoluteSD [NTDLL.@]
 */
NTSTATUS WINAPI RtlSelfRelativeToAbsoluteSD(
        IN PSECURITY_DESCRIPTOR pSelfRelativeSecurityDescriptor,
	OUT PSECURITY_DESCRIPTOR pAbsoluteSecurityDescriptor,
	OUT LPDWORD lpdwAbsoluteSecurityDescriptorSize,
	OUT PACL pDacl,
	OUT LPDWORD lpdwDaclSize,
	OUT PACL pSacl,
	OUT LPDWORD lpdwSaclSize,
	OUT PSID pOwner,
	OUT LPDWORD lpdwOwnerSize,
	OUT PSID pPrimaryGroup,
	OUT LPDWORD lpdwPrimaryGroupSize)
{
    NTSTATUS status = STATUS_SUCCESS;
    SECURITY_DESCRIPTOR* pAbs = pAbsoluteSecurityDescriptor;
    SECURITY_DESCRIPTOR_RELATIVE* pRel = pSelfRelativeSecurityDescriptor;

    if (!pRel ||
        !lpdwAbsoluteSecurityDescriptorSize ||
        !lpdwDaclSize ||
        !lpdwSaclSize ||
        !lpdwOwnerSize ||
        !lpdwPrimaryGroupSize ||
        ~pRel->Control & SE_SELF_RELATIVE)
        return STATUS_INVALID_PARAMETER;

    /* Confirm buffers are sufficiently large */
    if (*lpdwAbsoluteSecurityDescriptorSize < sizeof(SECURITY_DESCRIPTOR))
    {
        *lpdwAbsoluteSecurityDescriptorSize = sizeof(SECURITY_DESCRIPTOR);
        status = STATUS_BUFFER_TOO_SMALL;
    }

    if ((pRel->Control & SE_DACL_PRESENT) && pRel->Dacl &&
        *lpdwDaclSize  < ((PACL)SELF_RELATIVE_FIELD(pRel,Dacl))->AclSize)
    {
        *lpdwDaclSize = ((PACL)SELF_RELATIVE_FIELD(pRel,Dacl))->AclSize;
        status = STATUS_BUFFER_TOO_SMALL;
    }

    if ((pRel->Control & SE_SACL_PRESENT) && pRel->Sacl &&
        *lpdwSaclSize  < ((PACL)SELF_RELATIVE_FIELD(pRel,Sacl))->AclSize)
    {
        *lpdwSaclSize = ((PACL)SELF_RELATIVE_FIELD(pRel,Sacl))->AclSize;
        status = STATUS_BUFFER_TOO_SMALL;
    }

    if (pRel->Owner &&
        *lpdwOwnerSize < RtlLengthSid((PSID)SELF_RELATIVE_FIELD(pRel,Owner)))
    {
        *lpdwOwnerSize = RtlLengthSid((PSID)SELF_RELATIVE_FIELD(pRel,Owner));
        status = STATUS_BUFFER_TOO_SMALL;
    }

    if (pRel->Group &&
        *lpdwPrimaryGroupSize < RtlLengthSid((PSID)SELF_RELATIVE_FIELD(pRel,Group)))
    {
        *lpdwPrimaryGroupSize = RtlLengthSid((PSID)SELF_RELATIVE_FIELD(pRel,Group));
        status = STATUS_BUFFER_TOO_SMALL;
    }

    if (status != STATUS_SUCCESS)
        return status;

    /* Copy structures, and clear the ones we don't set */
    pAbs->Revision = pRel->Revision;
    pAbs->Control = pRel->Control & ~SE_SELF_RELATIVE;
    pAbs->Sacl = NULL;
    pAbs->Dacl = NULL;
    pAbs->Owner = NULL;
    pAbs->Group = NULL;

    if ((pRel->Control & SE_SACL_PRESENT) && pRel->Sacl)
    {
        PACL pAcl = (PACL)SELF_RELATIVE_FIELD( pRel, Sacl );

        memcpy(pSacl, pAcl, pAcl->AclSize);
        pAbs->Sacl = pSacl;
    }

    if ((pRel->Control & SE_DACL_PRESENT) && pRel->Dacl)
    {
        PACL pAcl = (PACL)SELF_RELATIVE_FIELD( pRel, Dacl );
        memcpy(pDacl, pAcl, pAcl->AclSize);
        pAbs->Dacl = pDacl;
    }

    if (pRel->Owner)
    {
        PSID psid = (PSID)SELF_RELATIVE_FIELD( pRel, Owner );
        memcpy(pOwner, psid, RtlLengthSid(psid));
        pAbs->Owner = pOwner;
    }

    if (pRel->Group)
    {
        PSID psid = (PSID)SELF_RELATIVE_FIELD( pRel, Group );
        memcpy(pPrimaryGroup, psid, RtlLengthSid(psid));
        pAbs->Group = pPrimaryGroup;
    }

    return status;
}

/******************************************************************************
 * RtlGetControlSecurityDescriptor (NTDLL.@)
 */
NTSTATUS WINAPI RtlGetControlSecurityDescriptor(
    PSECURITY_DESCRIPTOR pSecurityDescriptor,
    PSECURITY_DESCRIPTOR_CONTROL pControl,
    LPDWORD lpdwRevision)
{
    SECURITY_DESCRIPTOR *lpsd = pSecurityDescriptor;

    TRACE("(%p,%p,%p)\n",pSecurityDescriptor,pControl,lpdwRevision);

    *lpdwRevision = lpsd->Revision;

    if (*lpdwRevision != SECURITY_DESCRIPTOR_REVISION)
        return STATUS_UNKNOWN_REVISION;

    *pControl = lpsd->Control;

    return STATUS_SUCCESS;
}

/******************************************************************************
 * RtlSetControlSecurityDescriptor (NTDLL.@)
 */
NTSTATUS WINAPI RtlSetControlSecurityDescriptor(
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    SECURITY_DESCRIPTOR_CONTROL ControlBitsOfInterest,
    SECURITY_DESCRIPTOR_CONTROL ControlBitsToSet)
{
    SECURITY_DESCRIPTOR_CONTROL const immutable
       = SE_OWNER_DEFAULTED  | SE_GROUP_DEFAULTED
       | SE_DACL_PRESENT     | SE_DACL_DEFAULTED
       | SE_SACL_PRESENT     | SE_SACL_DEFAULTED
       | SE_RM_CONTROL_VALID | SE_SELF_RELATIVE
       ;

    SECURITY_DESCRIPTOR *lpsd = SecurityDescriptor;

    TRACE("(%p 0x%04x 0x%04x)\n", SecurityDescriptor,
          ControlBitsOfInterest, ControlBitsToSet);

    if ((ControlBitsOfInterest | ControlBitsToSet) & immutable)
        return STATUS_INVALID_PARAMETER;

    lpsd->Control |=  (ControlBitsOfInterest &  ControlBitsToSet);
    lpsd->Control &= ~(ControlBitsOfInterest & ~ControlBitsToSet);

    return STATUS_SUCCESS;
}


/**************************************************************************
 *                 RtlAbsoluteToSelfRelativeSD [NTDLL.@]
 */
NTSTATUS WINAPI RtlAbsoluteToSelfRelativeSD(
    PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
    PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
    PULONG BufferLength)
{
    SECURITY_DESCRIPTOR *abs = AbsoluteSecurityDescriptor;

    TRACE("%p %p %p\n", AbsoluteSecurityDescriptor,
          SelfRelativeSecurityDescriptor, BufferLength);

    if (abs->Control & SE_SELF_RELATIVE)
        return STATUS_BAD_DESCRIPTOR_FORMAT;

    return RtlMakeSelfRelativeSD(AbsoluteSecurityDescriptor, 
        SelfRelativeSecurityDescriptor, BufferLength);
}

/******************************************************************************
 *  RtlNewSecurityObject		[NTDLL.@]
 */
NTSTATUS WINAPI RtlNewSecurityObject(PSECURITY_DESCRIPTOR parent, PSECURITY_DESCRIPTOR creator,
    PSECURITY_DESCRIPTOR *descr, BOOLEAN is_container, HANDLE token, PGENERIC_MAPPING mapping)
{
    return RtlNewSecurityObjectEx(parent, creator, descr, NULL, is_container, 0, token, mapping);
}

/******************************************************************************
 *  RtlNewSecurityObjectEx              [NTDLL.@]
 */
NTSTATUS WINAPI RtlNewSecurityObjectEx(PSECURITY_DESCRIPTOR parent, PSECURITY_DESCRIPTOR creator,
    PSECURITY_DESCRIPTOR *descr, GUID *type, BOOLEAN is_container, ULONG flags, HANDLE token, PGENERIC_MAPPING mapping )
{
    SECURITY_DESCRIPTOR_RELATIVE *relative;
    DWORD needed, offset;
    NTSTATUS status;
    BYTE *buffer;

    FIXME("%p, %p, %p, %p, %d, %#lx, %p %p - semi-stub\n", parent, creator, descr, type, is_container, flags, token, mapping);

    needed = sizeof(SECURITY_DESCRIPTOR_RELATIVE);
    needed += sizeof(world_sid);
    needed += sizeof(world_sid);
    needed += world_access_acl_size;
    needed += world_access_acl_size;

    if (!(buffer = RtlAllocateHeap( GetProcessHeap(), 0, needed ))) return STATUS_NO_MEMORY;
    relative = (SECURITY_DESCRIPTOR_RELATIVE *)buffer;
    if ((status = RtlCreateSecurityDescriptor( relative, SECURITY_DESCRIPTOR_REVISION )))
    {
        RtlFreeHeap( GetProcessHeap(), 0, buffer );
        return status;
    }
    relative->Control |= SE_SELF_RELATIVE;
    offset = sizeof(SECURITY_DESCRIPTOR_RELATIVE);

    memcpy( buffer + offset, &world_sid, sizeof(world_sid) );
    relative->Owner = offset;
    offset += sizeof(world_sid);

    memcpy( buffer + offset, &world_sid, sizeof(world_sid) );
    relative->Group = offset;
    offset += sizeof(world_sid);

    get_world_access_acl( (ACL *)(buffer + offset) );
    relative->Dacl = offset;
    offset += world_access_acl_size;

    get_world_access_acl( (ACL *)(buffer + offset) );
    relative->Sacl = offset;

    *descr = relative;
    return STATUS_SUCCESS;
}

/******************************************************************************
 *  RtlNewSecurityObjectWithMultipleInheritance        [NTDLL.@]
 */
NTSTATUS WINAPI RtlNewSecurityObjectWithMultipleInheritance(PSECURITY_DESCRIPTOR parent, PSECURITY_DESCRIPTOR creator,
    PSECURITY_DESCRIPTOR *descr, GUID **types, ULONG count, BOOLEAN is_container, ULONG flags,
    HANDLE token, PGENERIC_MAPPING mapping )
{
    FIXME("semi-stub\n");
    return RtlNewSecurityObjectEx(parent, creator, descr, NULL, is_container, flags, token, mapping);
}

static NTSTATUS validate_security_object_dacl( ACL *acl )
{
    ACE_HEADER *ace;
    ULONG i;

    if (!acl) return STATUS_SUCCESS;
    if (!RtlValidAcl( acl )) return STATUS_INVALID_ACL;

    ace = (ACE_HEADER *)(acl + 1);
    for (i = 0; i < acl->AceCount; ++i)
    {
        if (ace->AceType != ACCESS_ALLOWED_ACE_TYPE && ace->AceType != ACCESS_DENIED_ACE_TYPE)
            return STATUS_NOT_SUPPORTED;
        ace = (ACE_HEADER *)((BYTE *)ace + ace->AceSize);
    }
    return STATUS_SUCCESS;
}

static void map_security_object_dacl( SECURITY_DESCRIPTOR_RELATIVE *descriptor,
                                      const GENERIC_MAPPING *mapping )
{
    ACL *acl;
    ACE_HEADER *ace;
    ULONG i;

    if (!descriptor->Dacl) return;
    acl = (ACL *)((BYTE *)descriptor + descriptor->Dacl);
    ace = (ACE_HEADER *)(acl + 1);
    for (i = 0; i < acl->AceCount; ++i)
    {
        if (!(ace->AceFlags & INHERIT_ONLY_ACE))
        {
            ACCESS_MASK *mask = (ACCESS_MASK *)((BYTE *)ace + sizeof(*ace));
            RtlMapGenericMask( mask, mapping );
            *mask &= mapping->GenericAll;
        }
        ace = (ACE_HEADER *)((BYTE *)ace + ace->AceSize);
    }
}

/******************************************************************************
 *  RtlCreateUserSecurityObject                         [NTDLL.@]
 */
NTSTATUS WINAPI RtlCreateUserSecurityObject( RTL_ACE_DATA *ace_data, ULONG ace_count,
                                              PSID owner_sid, PSID group_sid,
                                              BOOLEAN is_directory, GENERIC_MAPPING *mapping,
                                              PSECURITY_DESCRIPTOR *new_sd )
{
    SECURITY_DESCRIPTOR_RELATIVE *relative;
    SECURITY_DESCRIPTOR *absolute;
    ULONG size = 0;
    NTSTATUS status;

    TRACE( "%p,%lu,%p,%p,%u,%p,%p\n", ace_data, ace_count, owner_sid, group_sid,
           is_directory, mapping, new_sd );

    if (!mapping || !new_sd) return STATUS_INVALID_PARAMETER;

    status = RtlCreateAndSetSD( ace_data, ace_count, owner_sid, group_sid,
                                (PSECURITY_DESCRIPTOR *)&absolute );
    if (status) return status;

    status = RtlMakeSelfRelativeSD( absolute, NULL, &size );
    if (status != STATUS_BUFFER_TOO_SMALL) goto done;
    if (!(relative = RtlAllocateHeap( GetProcessHeap(), 0, size )))
    {
        status = STATUS_NO_MEMORY;
        goto done;
    }

    status = RtlMakeSelfRelativeSD( absolute, (PSECURITY_DESCRIPTOR)relative, &size );
    if (status)
    {
        RtlFreeHeap( GetProcessHeap(), 0, relative );
        goto done;
    }

    map_security_object_dacl( relative, mapping );
    *new_sd = (PSECURITY_DESCRIPTOR)relative;

done:
    RtlFreeHeap( GetProcessHeap(), 0, absolute );
    return status;
}

/******************************************************************************
 *  RtlSetSecurityObject                         [NTDLL.@]
 */
NTSTATUS WINAPI RtlSetSecurityObject( SECURITY_INFORMATION info, PSECURITY_DESCRIPTOR modification,
                                      PSECURITY_DESCRIPTOR *object, PGENERIC_MAPPING mapping,
                                      HANDLE token )
{
    static const SECURITY_DESCRIPTOR_CONTROL preserved_sacl_control =
        SE_SACL_PRESENT | SE_SACL_DEFAULTED | SE_SACL_AUTO_INHERITED | SE_SACL_PROTECTED;
    SECURITY_DESCRIPTOR_RELATIVE *relative;
    SECURITY_DESCRIPTOR combined;
    SECURITY_DESCRIPTOR *current;
    SECURITY_DESCRIPTOR *mod = modification;
    PSID owner, group;
    ACL *dacl = NULL, *sacl = NULL;
    BOOLEAN present = FALSE, defaulted = FALSE;
    ULONG size, offset, component_size;
    NTSTATUS status;
    BYTE *buffer;

    TRACE("%#lx,%p,%p,%p,%p\n", info, modification, object, mapping, token);

    if (info != DACL_SECURITY_INFORMATION) return STATUS_NOT_SUPPORTED;
    if (!object || !(current = *object)) return STATUS_INVALID_SECURITY_DESCR;
    if (!modification || !mapping) return STATUS_INVALID_PARAMETER;
    if (!RtlValidSecurityDescriptor( current )) return STATUS_INVALID_SECURITY_DESCR;

    memset( &combined, 0, sizeof(combined) );
    combined.Revision = SECURITY_DESCRIPTOR_REVISION;

    if ((status = RtlGetOwnerSecurityDescriptor( current, &owner, &defaulted ))) return status;
    if (!owner || !RtlValidSid( owner )) return STATUS_INVALID_OWNER;
    combined.Owner = owner;
    if (defaulted) combined.Control |= SE_OWNER_DEFAULTED;

    if ((status = RtlGetGroupSecurityDescriptor( current, &group, &defaulted ))) return status;
    if (!group || !RtlValidSid( group )) return STATUS_INVALID_PRIMARY_GROUP;
    combined.Group = group;
    if (defaulted) combined.Control |= SE_GROUP_DEFAULTED;

    if ((status = RtlGetDaclSecurityDescriptor( modification, &present, &dacl, &defaulted ))) return status;
    if (!present) return STATUS_NOT_SUPPORTED;
    if ((status = validate_security_object_dacl( dacl ))) return status;
    combined.Dacl = dacl;
    combined.Control |= SE_DACL_PRESENT | (mod->Control & SE_DACL_PROTECTED);

    present = defaulted = FALSE;
    if ((status = RtlGetSaclSecurityDescriptor( current, &present, &sacl, &defaulted ))) return status;
    if (present)
    {
        combined.Sacl = sacl;
        combined.Control |= current->Control & preserved_sacl_control;
    }

    size = sizeof(*relative);
    if (sacl) size += align_security_descriptor_size( sacl->AclSize );
    if (dacl) size += align_security_descriptor_size( dacl->AclSize );
    size += align_security_descriptor_size( RtlLengthSid( owner ) );
    size += align_security_descriptor_size( RtlLengthSid( group ) );

    if (!(buffer = RtlAllocateHeap( GetProcessHeap(), 0, size ))) return STATUS_NO_MEMORY;
    memset( buffer, 0, size );
    relative = (SECURITY_DESCRIPTOR_RELATIVE *)buffer;
    relative->Revision = SECURITY_DESCRIPTOR_REVISION;
    relative->Control = combined.Control | SE_SELF_RELATIVE;
    offset = sizeof(*relative);

    if (sacl)
    {
        relative->Sacl = offset;
        memcpy( buffer + offset, sacl, sacl->AclSize );
        offset += align_security_descriptor_size( sacl->AclSize );
    }
    if (dacl)
    {
        relative->Dacl = offset;
        memcpy( buffer + offset, dacl, dacl->AclSize );
        offset += align_security_descriptor_size( dacl->AclSize );
    }

    relative->Owner = offset;
    component_size = RtlLengthSid( owner );
    memcpy( buffer + offset, owner, component_size );
    offset += align_security_descriptor_size( component_size );

    relative->Group = offset;
    component_size = RtlLengthSid( group );
    memcpy( buffer + offset, group, component_size );

    map_security_object_dacl( relative, mapping );
    RtlFreeHeap( GetProcessHeap(), 0, current );
    *object = (PSECURITY_DESCRIPTOR)relative;
    return STATUS_SUCCESS;
}

/******************************************************************************
 *  RtlDeleteSecurityObject		[NTDLL.@]
 */
NTSTATUS WINAPI RtlDeleteSecurityObject( PSECURITY_DESCRIPTOR *descr )
{
    FIXME("%p stub.\n", descr);
    RtlFreeHeap( GetProcessHeap(), 0, *descr );
    return STATUS_SUCCESS;
}

/*
 *	access control list's
 */

/**************************************************************************
 *                 RtlCreateAcl				[NTDLL.@]
 *
 * NOTES
 *    This should return NTSTATUS
 */
NTSTATUS WINAPI RtlCreateAcl(PACL acl,DWORD size,DWORD rev)
{
	TRACE("%p 0x%08lx 0x%08lx\n", acl, size, rev);

	if (rev < MIN_ACL_REVISION || rev > MAX_ACL_REVISION)
		return STATUS_INVALID_PARAMETER;
	if (size<sizeof(ACL))
		return STATUS_BUFFER_TOO_SMALL;
	if (size>0xFFFF)
		return STATUS_INVALID_PARAMETER;

	memset(acl,'\0',sizeof(ACL));
	acl->AclRevision	= rev;
	acl->AclSize		= size;
	acl->AceCount		= 0;
	return STATUS_SUCCESS;
}

/**************************************************************************
 *                 RtlFirstFreeAce			[NTDLL.@]
 * looks for the AceCount+1 ACE, and if it is still within the alloced
 * ACL, return a pointer to it
 */
BOOLEAN WINAPI RtlFirstFreeAce(
	PACL acl,
	PACE_HEADER *x)
{
	PACE_HEADER	ace;
	int		i;

	*x = 0;
	ace = (PACE_HEADER)(acl+1);
	for (i=0;i<acl->AceCount;i++) {
		if ((BYTE *)ace >= (BYTE *)acl + acl->AclSize)
			return FALSE;
		ace = (PACE_HEADER)(((BYTE*)ace)+ace->AceSize);
	}
	if ((BYTE *)ace <= (BYTE *)acl + acl->AclSize)
		*x = ace;
	return TRUE;
}

/**************************************************************************
 *                 RtlAddAce				[NTDLL.@]
 */
NTSTATUS WINAPI RtlAddAce(
	PACL acl,
	DWORD rev,
	DWORD xnrofaces,
	PACE_HEADER acestart,
	DWORD acelen)
{
	PACE_HEADER	ace,targetace;
	int		nrofaces;

	if (!RtlValidAcl(acl))
		return STATUS_INVALID_PARAMETER;
	if (!RtlFirstFreeAce(acl,&targetace))
		return STATUS_INVALID_PARAMETER;
	if (!targetace)
		return STATUS_ALLOTTED_SPACE_EXCEEDED;
	nrofaces=0;ace=acestart;
	while (((BYTE *)ace - (BYTE *)acestart) < acelen) {
		nrofaces++;
		ace = (PACE_HEADER)(((BYTE*)ace)+ace->AceSize);
	}
	if ((BYTE *)targetace + acelen > (BYTE *)acl + acl->AclSize) /* too much aces */
		return STATUS_INVALID_PARAMETER;
	memcpy(targetace,acestart,acelen);
	acl->AceCount+=nrofaces;
	if (rev > acl->AclRevision)
		acl->AclRevision = rev;
	return STATUS_SUCCESS;
}

/**************************************************************************
 *                 RtlDeleteAce				[NTDLL.@]
 */
NTSTATUS  WINAPI RtlDeleteAce(PACL pAcl, DWORD dwAceIndex)
{
	NTSTATUS status;
	PACE_HEADER pAce;

	status = RtlGetAce(pAcl,dwAceIndex,(LPVOID*)&pAce);

	if (STATUS_SUCCESS == status)
	{
		PACE_HEADER pcAce;
		DWORD len = 0;

		/* skip over the ACE we are deleting */
		pcAce = (PACE_HEADER)(((BYTE*)pAce)+pAce->AceSize);
		dwAceIndex++;

		/* calculate the length of the rest */
		for (; dwAceIndex < pAcl->AceCount; dwAceIndex++)
		{
			len += pcAce->AceSize;
			pcAce = (PACE_HEADER)(((BYTE*)pcAce) + pcAce->AceSize);
		}

		/* slide them all backwards */
		memmove(pAce, ((BYTE*)pAce)+pAce->AceSize, len);
		pAcl->AceCount--;
	}

	TRACE("pAcl=%p dwAceIndex=%ld status=0x%08lx\n", pAcl, dwAceIndex, status);

	return status;
}

/******************************************************************************
 *  RtlAddAccessAllowedAce		[NTDLL.@]
 */
NTSTATUS WINAPI RtlAddAccessAllowedAce(
	IN OUT PACL pAcl,
	IN DWORD dwAceRevision,
	IN DWORD AccessMask,
	IN PSID pSid)
{
	return RtlAddAccessAllowedAceEx( pAcl, dwAceRevision, 0, AccessMask, pSid);
}
 
/******************************************************************************
 *  RtlAddAccessAllowedAceEx		[NTDLL.@]
 */
NTSTATUS WINAPI RtlAddAccessAllowedAceEx(
	IN OUT PACL pAcl,
	IN DWORD dwAceRevision,
	IN DWORD AceFlags,
	IN DWORD AccessMask,
	IN PSID pSid)
{
   TRACE("(%p,0x%08lx,0x%08lx,%p)\n", pAcl, dwAceRevision, AccessMask, pSid);

    return add_access_ace(pAcl, dwAceRevision, AceFlags,
                          AccessMask, pSid, ACCESS_ALLOWED_ACE_TYPE);
}

/******************************************************************************
 *  RtlAddAccessAllowedObjectAce		[NTDLL.@]
 */
NTSTATUS WINAPI RtlAddAccessAllowedObjectAce(
    IN OUT PACL pAcl,
    IN DWORD dwAceRevision,
    IN DWORD dwAceFlags,
    IN DWORD dwAccessMask,
    IN GUID* pObjectTypeGuid,
    IN GUID* pInheritedObjectTypeGuid,
    IN PSID pSid)
{
    FIXME("%p %lx %lx %lx %p %p %p - stub\n", pAcl, dwAceRevision, dwAceFlags, dwAccessMask,
          pObjectTypeGuid, pInheritedObjectTypeGuid, pSid);
    return STATUS_NOT_IMPLEMENTED;
}

/******************************************************************************
 *  RtlAddAccessDeniedAce		[NTDLL.@]
 */
NTSTATUS WINAPI RtlAddAccessDeniedAce(
	IN OUT PACL pAcl,
	IN DWORD dwAceRevision,
	IN DWORD AccessMask,
	IN PSID pSid)
{
	return RtlAddAccessDeniedAceEx( pAcl, dwAceRevision, 0, AccessMask, pSid);
}

/******************************************************************************
 *  RtlAddAccessDeniedAceEx		[NTDLL.@]
 */
NTSTATUS WINAPI RtlAddAccessDeniedAceEx(
	IN OUT PACL pAcl,
	IN DWORD dwAceRevision,
	IN DWORD AceFlags,
	IN DWORD AccessMask,
	IN PSID pSid)
{
   TRACE("(%p,0x%08lx,0x%08lx,%p)\n", pAcl, dwAceRevision, AccessMask, pSid);

    return add_access_ace(pAcl, dwAceRevision, AceFlags,
                          AccessMask, pSid, ACCESS_DENIED_ACE_TYPE);
}

/******************************************************************************
 *  RtlAddAccessDeniedObjectAce [NTDLL.@]
 */
NTSTATUS WINAPI RtlAddAccessDeniedObjectAce(
    IN OUT PACL pAcl,
    IN DWORD dwAceRevision,
    IN DWORD dwAceFlags,
    IN DWORD dwAccessMask,
    IN GUID* pObjectTypeGuid,
    IN GUID* pInheritedObjectTypeGuid,
    IN PSID pSid)
{
    FIXME("%p %lx %lx %lx %p %p %p - stub\n", pAcl, dwAceRevision, dwAceFlags, dwAccessMask,
          pObjectTypeGuid, pInheritedObjectTypeGuid, pSid);
    return STATUS_NOT_IMPLEMENTED;
}

/************************************************************************** 
 *  RtlAddAuditAccessAce     [NTDLL.@] 
 */ 
NTSTATUS WINAPI RtlAddAuditAccessAceEx(
    IN OUT PACL pAcl, 
    IN DWORD dwAceRevision, 
    IN DWORD dwAceFlags,
    IN DWORD dwAccessMask, 
    IN PSID pSid, 
    IN BOOL bAuditSuccess, 
    IN BOOL bAuditFailure) 
{ 
    TRACE("(%p,%ld,0x%08lx,0x%08lx,%p,%u,%u)\n",pAcl,dwAceRevision,dwAceFlags,dwAccessMask,
          pSid,bAuditSuccess,bAuditFailure);

    if (bAuditSuccess)
        dwAceFlags |= SUCCESSFUL_ACCESS_ACE_FLAG;

    if (bAuditFailure)
        dwAceFlags |= FAILED_ACCESS_ACE_FLAG;

    return add_access_ace(pAcl, dwAceRevision, dwAceFlags,
                          dwAccessMask, pSid, SYSTEM_AUDIT_ACE_TYPE);
} 

/**************************************************************************
 *  RtlAddAuditAccessAce     [NTDLL.@]
 */
NTSTATUS WINAPI RtlAddAuditAccessAce(
    IN OUT PACL pAcl,
    IN DWORD dwAceRevision,
    IN DWORD dwAccessMask,
    IN PSID pSid,
    IN BOOL bAuditSuccess,
    IN BOOL bAuditFailure)
{
    return RtlAddAuditAccessAceEx(pAcl, dwAceRevision, 0, dwAccessMask, pSid, bAuditSuccess, bAuditFailure);
}

/******************************************************************************
 *  RtlAddAuditAccessObjectAce [NTDLL.@]
 */
NTSTATUS WINAPI RtlAddAuditAccessObjectAce(
    IN OUT PACL pAcl,
    IN DWORD dwAceRevision,
    IN DWORD dwAceFlags,
    IN DWORD dwAccessMask,
    IN GUID* pObjectTypeGuid,
    IN GUID* pInheritedObjectTypeGuid,
    IN PSID pSid,
    IN BOOL bAuditSuccess,
    IN BOOL bAuditFailure)
{
    FIXME("%p %lx %lx %lx %p %p %p %d %d - stub\n", pAcl, dwAceRevision, dwAceFlags, dwAccessMask,
          pObjectTypeGuid, pInheritedObjectTypeGuid, pSid, bAuditSuccess, bAuditFailure);
    return STATUS_NOT_IMPLEMENTED;
}

/* Validate label-specific policy before appending an ordinary SID-bearing ACE. */
static NTSTATUS add_label_ace( ACL *acl, DWORD revision, DWORD flags, PSID sid,
                               BYTE type, DWORD mask )
{
    static const SID_IDENTIFIER_AUTHORITY mandatory_authority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    static const SID_IDENTIFIER_AUTHORITY trust_authority = {{0, 0, 0, 0, 0, 19}};

    if (!RtlValidSid( sid )) return STATUS_INVALID_SID;
    if (acl->AclRevision > MAX_ACL_REVISION || revision > MAX_ACL_REVISION)
        return STATUS_REVISION_MISMATCH;
    if (flags & ~VALID_INHERIT_FLAGS) return STATUS_INVALID_PARAMETER;

    if (type == SYSTEM_MANDATORY_LABEL_ACE_TYPE)
    {
        if (mask & ~SYSTEM_MANDATORY_LABEL_VALID_MASK) return STATUS_INVALID_PARAMETER;
        if (memcmp( RtlIdentifierAuthoritySid( sid ), &mandatory_authority, sizeof(mandatory_authority) ))
            return STATUS_INVALID_PARAMETER;
    }
    else
    {
        if (mask & ~SYSTEM_PROCESS_TRUST_LABEL_VALID_MASK) return STATUS_INVALID_PARAMETER;
        if (*RtlSubAuthorityCountSid( sid ) != 2 ||
            memcmp( RtlIdentifierAuthoritySid( sid ), &trust_authority, sizeof(trust_authority) ))
            return STATUS_INVALID_PARAMETER;
    }
    return add_access_ace( acl, revision, flags, mask, sid, type );
}

/**************************************************************************
 *  RtlAddMandatoryAce     [NTDLL.@]
 */
NTSTATUS WINAPI RtlAddMandatoryAce( ACL *acl, DWORD revision, DWORD flags,
                                    PSID sid, BYTE type, DWORD mask )
{
    TRACE( "%p %lx %lx %p %x %lx\n", acl, revision, flags, sid, type, mask );

    if (type != SYSTEM_MANDATORY_LABEL_ACE_TYPE) return STATUS_INVALID_PARAMETER;
    return add_label_ace( acl, revision, flags, sid, type, mask );
}

/**************************************************************************
 *  RtlAddProcessTrustLabelAce     [NTDLL.@]
 */
NTSTATUS WINAPI RtlAddProcessTrustLabelAce( ACL *acl, DWORD revision, DWORD flags,
                                            PSID sid, BYTE type, DWORD mask )
{
    TRACE( "%p %lx %lx %p %x %lx\n", acl, revision, flags, sid, type, mask );

    if (type != SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE) return STATUS_INVALID_PARAMETER;
    return add_label_ace( acl, revision, flags, sid, type, mask );
}

static BOOLEAN valid_acl( const ACL *acl )
{
    const ACE_HEADER *ace;
    const BYTE *ptr;
    const SID *sid;
    ULONG offset, sid_offset, sid_length, flags;
    unsigned int i;

    if ((ULONG_PTR)acl & 1) return FALSE;
    if (acl->AclRevision < MIN_ACL_REVISION || acl->AclRevision > MAX_ACL_REVISION) return FALSE;
    if (acl->AclSize < sizeof(*acl)) return FALSE;

    offset = sizeof(*acl);
    for (i = 0; i < acl->AceCount; ++i)
    {
        if (acl->AclSize - offset < sizeof(*ace)) return FALSE;
        ptr = (const BYTE *)acl + offset;
        if ((ULONG_PTR)ptr & 1) return FALSE;
        ace = (const ACE_HEADER *)ptr;
        if (ace->AceSize < sizeof(*ace) || ace->AceSize > acl->AclSize - offset) return FALSE;

        switch (ace->AceType)
        {
        case ACCESS_ALLOWED_ACE_TYPE:
        case ACCESS_DENIED_ACE_TYPE:
        case SYSTEM_AUDIT_ACE_TYPE:
        case SYSTEM_ALARM_ACE_TYPE:
        case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
        case ACCESS_DENIED_CALLBACK_ACE_TYPE:
        case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
        case SYSTEM_ALARM_CALLBACK_ACE_TYPE:
        case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
        case SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:
        case SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE:
            sid_offset = offsetof( ACCESS_ALLOWED_ACE, SidStart );
            if ((ace->AceSize & 3) || ace->AceSize < sid_offset + offsetof( SID, SubAuthority ) ||
                !valid_sid_buffer( (const SID *)(ptr + sid_offset), ace->AceSize - sid_offset ))
                return FALSE;
            break;

        case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
        case ACCESS_DENIED_OBJECT_ACE_TYPE:
        case ACCESS_AUDIT_OBJECT_ACE_TYPE:
        case ACCESS_ALARM_OBJECT_ACE_TYPE:
        case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
        case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
        case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
        case SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:
            if (acl->AclRevision < ACL_REVISION4 || (ace->AceSize & 3) || ace->AceSize < 12) return FALSE;
            memcpy( &flags, ptr + 8, sizeof(flags) );
            sid_offset = 12;
            if (flags & ACE_OBJECT_TYPE_PRESENT) sid_offset += sizeof(GUID);
            if (flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) sid_offset += sizeof(GUID);
            if (ace->AceSize < sid_offset + sizeof(SID) ||
                !valid_sid_buffer( (const SID *)(ptr + sid_offset), ace->AceSize - sid_offset )) return FALSE;
            break;

        case ACCESS_ALLOWED_COMPOUND_ACE_TYPE:
            if (acl->AclRevision < 3 || (ace->AceSize & 3) || ace->AceSize < 24) return FALSE;
            if (*(const USHORT *)(ptr + 8) != 1) return FALSE;
            sid = (const SID *)(ptr + 12);
            if (!valid_sid_buffer( sid, ace->AceSize - 12 )) return FALSE;
            sid_length = offsetof( SID, SubAuthority ) + sid->SubAuthorityCount * sizeof(DWORD);
            sid_offset = 12 + sid_length;
            if (ace->AceSize < sid_offset + sizeof(SID) ||
                !valid_sid_buffer( (const SID *)(ptr + sid_offset), ace->AceSize - sid_offset )) return FALSE;
            break;

        default:
            break;
        }
        offset += ace->AceSize;
    }
    return TRUE;
}

/******************************************************************************
 *  RtlValidAcl                  [NTDLL.@]
 */
BOOLEAN WINAPI RtlValidAcl( ACL *acl )
{
    BOOLEAN ret;

    __TRY
    {
        ret = valid_acl( acl );
    }
    __EXCEPT_PAGE_FAULT
    {
        WARN( "%p: invalid pointer!\n", acl );
        return FALSE;
    }
    __ENDTRY
    TRACE_(secdesc)( "%p: %u\n", acl, ret );
    return ret;
}

/******************************************************************************
 *  RtlGetAce		[NTDLL.@]
 */
NTSTATUS WINAPI RtlGetAce(PACL pAcl,DWORD dwAceIndex,LPVOID *pAce )
{
	PACE_HEADER ace;

	TRACE("(%p,%ld,%p)\n",pAcl,dwAceIndex,pAce);

	if (dwAceIndex >= pAcl->AceCount)
		return STATUS_INVALID_PARAMETER;

	ace = (PACE_HEADER)(pAcl + 1);
	for (;dwAceIndex;dwAceIndex--)
		ace = (PACE_HEADER)(((BYTE*)ace)+ace->AceSize);

	*pAce = ace;

	return STATUS_SUCCESS;
}

/******************************************************************************
 *  RtlGetAcesBufferSize                              [NTDLL.@]
 */
NTSTATUS WINAPI RtlGetAcesBufferSize( PACL acl, ULONG *size )
{
    ACE_HEADER *ace;
    ULONG i, total = 0;

    TRACE( "(%p,%p)\n", acl, size );

    if (!acl || !size) return STATUS_INVALID_PARAMETER;

    ace = (ACE_HEADER *)(acl + 1);
    for (i = 0; i < acl->AceCount; i++)
    {
        total += ace->AceSize;
        ace = (ACE_HEADER *)((BYTE *)ace + ace->AceSize);
    }
    *size = total;
    return STATUS_SUCCESS;
}

/*************************************************************************
 * RtlAreAllAccessesGranted   [NTDLL.@]
 */
BOOLEAN WINAPI RtlAreAllAccessesGranted( ACCESS_MASK granted, ACCESS_MASK desired )
{
    return (granted & desired) == desired;
}

/*************************************************************************
 * RtlAreAnyAccessesGranted   [NTDLL.@]
 */
BOOLEAN WINAPI RtlAreAnyAccessesGranted( ACCESS_MASK granted, ACCESS_MASK desired )
{
    return (granted & desired) != 0;
}

/*************************************************************************
 * RtlMapGenericMask   [NTDLL.@]
 */
void WINAPI RtlMapGenericMask( ACCESS_MASK *mask, const GENERIC_MAPPING *mapping )
{
    if (*mask & GENERIC_READ) *mask |= mapping->GenericRead;
    if (*mask & GENERIC_WRITE) *mask |= mapping->GenericWrite;
    if (*mask & GENERIC_EXECUTE) *mask |= mapping->GenericExecute;
    if (*mask & GENERIC_ALL) *mask |= mapping->GenericAll;
    *mask &= ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
}

/*************************************************************************
 * RtlCopyLuid   [NTDLL.@]
 */
void WINAPI RtlCopyLuid( LUID *dest, const LUID *src )
{
    *dest = *src;
}

/*************************************************************************
 * RtlEqualLuid   [NTDLL.@]
 */
BOOLEAN WINAPI RtlEqualLuid( const LUID *luid1, const LUID *luid2 )
{
  return (luid1->LowPart == luid2->LowPart && luid1->HighPart == luid2->HighPart);
}

/*************************************************************************
 * RtlCopyLuidAndAttributesArray   [NTDLL.@]
 */
void WINAPI RtlCopyLuidAndAttributesArray( ULONG count, const LUID_AND_ATTRIBUTES *src, PLUID_AND_ATTRIBUTES dest )
{
    ULONG i;

    for (i = 0; i < count; i++) dest[i] = src[i];
}

/*
 *	misc
 */

struct acquired_privilege_state
{
    ULONGLONG magic;
    ULONG privilege;
    ULONG flags;
    BOOLEAN was_enabled;
    BOOLEAN active;
    BYTE padding[6];
};

/******************************************************************************
 *  RtlAcquirePrivilege                 [NTDLL.@]
 */
NTSTATUS WINAPI RtlAcquirePrivilege( const ULONG *privileges, ULONG count, ULONG flags, void **returned_state )
{
    struct acquired_privilege_state *state;
    DWORD last_error = NtCurrentTeb()->LastErrorValue;
    NTSTATUS status;

    TRACE( "(%p, %lu, %#lx, %p)\n", privileges, count, flags, returned_state );

    if (!returned_state || !privileges)
    {
        status = STATUS_INVALID_PARAMETER;
        goto done;
    }
    *returned_state = NULL;
    if (count != 1 || flags != 2 || privileges[0] != 10)
    {
        FIXME( "unsupported privilege request count %lu flags %#lx privilege %lu\n",
               count, flags, count ? privileges[0] : 0 );
        status = STATUS_NOT_IMPLEMENTED;
        goto done;
    }
    if (!(state = RtlAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*state) )))
    {
        status = STATUS_NO_MEMORY;
        goto done;
    }
    state->magic = 0x4c4e545052495602ULL;
    state->privilege = privileges[0];
    state->flags = flags;
    status = RtlAdjustPrivilege( state->privilege, TRUE, FALSE, &state->was_enabled );
    if (status)
    {
        state->magic = 0;
        RtlFreeHeap( GetProcessHeap(), 0, state );
        goto done;
    }
    state->active = TRUE;
    *returned_state = state;

done:
    NtCurrentTeb()->LastErrorValue = last_error;
    return status;
}

/******************************************************************************
 *  RtlReleasePrivilege                 [NTDLL.@]
 */
void WINAPI RtlReleasePrivilege( void *state_ptr )
{
    struct acquired_privilege_state *state = state_ptr;
    DWORD last_error = NtCurrentTeb()->LastErrorValue;
    BOOLEAN ignored;

    TRACE( "(%p)\n", state_ptr );

    if (!state || RtlSizeHeap( GetProcessHeap(), 0, state ) != sizeof(*state) ||
        state->magic != 0x4c4e545052495602ULL || !state->active ||
        state->flags != 2 || state->privilege != 10)
        goto done;

    RtlAdjustPrivilege( state->privilege, state->was_enabled, FALSE, &ignored );
    state->active = FALSE;
    state->magic = 0;
    RtlFreeHeap( GetProcessHeap(), 0, state );

done:
    NtCurrentTeb()->LastErrorValue = last_error;
}

/******************************************************************************
 *  NtSerializeBoot                     [NTDLL.@]
 */
NTSTATUS WINAPI NtSerializeBoot(void)
{
    return STATUS_SUCCESS;
}

/******************************************************************************
 *  RtlAdjustPrivilege                  [NTDLL.@]
 *
 * Enables or disables a privilege from the calling thread or process.
 *
 * PARAMS
 *  Privilege     [I] Privilege index to change.
 *  Enable        [I] If TRUE, then enable the privilege otherwise disable.
 *  CurrentThread [I] If TRUE, then enable in calling thread, otherwise process.
 *  Enabled       [O] Whether privilege was previously enabled or disabled.
 *
 * RETURNS
 *  Success: STATUS_SUCCESS.
 *  Failure: NTSTATUS code.
 *
 * SEE ALSO
 *  NtAdjustPrivilegesToken, NtOpenThreadToken, NtOpenProcessToken.
 *
 */
NTSTATUS WINAPI
RtlAdjustPrivilege(ULONG Privilege,
                   BOOLEAN Enable,
                   BOOLEAN CurrentThread,
                   PBOOLEAN Enabled)
{
    TOKEN_PRIVILEGES NewState;
    TOKEN_PRIVILEGES OldState;
    ULONG ReturnLength;
    HANDLE TokenHandle;
    NTSTATUS Status;

    TRACE("(%ld, %s, %s, %p)\n", Privilege, Enable ? "TRUE" : "FALSE",
        CurrentThread ? "TRUE" : "FALSE", Enabled);

    if (CurrentThread)
    {
        Status = NtOpenThreadToken(GetCurrentThread(),
                                   TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                   FALSE,
                                   &TokenHandle);
    }
    else
    {
        Status = NtOpenProcessToken(GetCurrentProcess(),
                                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                    &TokenHandle);
    }

    if (Status)
    {
        WARN("Retrieving token handle failed (Status %lx)\n", Status);
        return Status;
    }

    OldState.PrivilegeCount = 1;

    NewState.PrivilegeCount = 1;
    NewState.Privileges[0].Luid.LowPart = Privilege;
    NewState.Privileges[0].Luid.HighPart = 0;
    NewState.Privileges[0].Attributes = (Enable) ? SE_PRIVILEGE_ENABLED : 0;

    Status = NtAdjustPrivilegesToken(TokenHandle,
                                     FALSE,
                                     &NewState,
                                     sizeof(TOKEN_PRIVILEGES),
                                     &OldState,
                                     &ReturnLength);
    NtClose (TokenHandle);
    if (Status == STATUS_NOT_ALL_ASSIGNED)
    {
        TRACE("Failed to assign all privileges\n");
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    if (Status)
    {
        WARN("NtAdjustPrivilegesToken() failed (Status %lx)\n", Status);
        return Status;
    }

    if (OldState.PrivilegeCount == 0)
        *Enabled = Enable;
    else
        *Enabled = (OldState.Privileges[0].Attributes & SE_PRIVILEGE_ENABLED);

    return STATUS_SUCCESS;
}

/******************************************************************************
 *  RtlRemovePrivileges                 [NTDLL.@]
 *
 * Removes every token privilege whose LUID is absent from the supplied keep
 * list. Privilege LUIDs accepted by Windows occupy the range 2 through 36.
 */
NTSTATUS WINAPI RtlRemovePrivileges(HANDLE token, const ULONG *keep, ULONG keep_count)
{
    TOKEN_PRIVILEGES *privileges;
    ULONG i, j, needed = 0, remove_count = 0;
    NTSTATUS status;

    if (keep_count && !keep) return STATUS_INVALID_PARAMETER;
    for (i = 0; i < keep_count; ++i)
        if (keep[i] < 2 || keep[i] > 36) return STATUS_INVALID_PARAMETER;

    status = NtQueryInformationToken(token, TokenPrivileges, NULL, 0, &needed);
    if (status != STATUS_BUFFER_TOO_SMALL) return status;
    if (!(privileges = RtlAllocateHeap(GetProcessHeap(), 0, needed))) return STATUS_NO_MEMORY;
    status = NtQueryInformationToken(token, TokenPrivileges, privileges, needed, &needed);
    if (status) goto done;

    for (i = 0; i < keep_count; ++i)
    {
        for (j = 0; j < privileges->PrivilegeCount; ++j)
            if (!privileges->Privileges[j].Luid.HighPart &&
                privileges->Privileges[j].Luid.LowPart == keep[i]) break;
        if (j == privileges->PrivilegeCount)
        {
            status = STATUS_NOT_ALL_ASSIGNED;
            goto done;
        }
    }

    for (i = 0; i < privileges->PrivilegeCount; ++i)
    {
        for (j = 0; j < keep_count; ++j)
            if (!privileges->Privileges[i].Luid.HighPart &&
                privileges->Privileges[i].Luid.LowPart == keep[j]) break;
        if (j != keep_count) continue;
        privileges->Privileges[remove_count] = privileges->Privileges[i];
        privileges->Privileges[remove_count++].Attributes = SE_PRIVILEGE_REMOVED;
    }
    privileges->PrivilegeCount = remove_count;
    status = NtAdjustPrivilegesToken(token, FALSE, privileges, 0, NULL, NULL);

done:
    RtlFreeHeap(GetProcessHeap(), 0, privileges);
    return status;
}

/******************************************************************************
 *  RtlImpersonateSelfEx		[NTDLL.@]
 *
 * Makes an impersonation token that represents the process user and assigns
 * to the current thread.
 *
 * PARAMS
 *  ImpersonationLevel [I] Level at which to impersonate.
 *  AdditionalAccess   [I] Additional access rights for the returned token.
 *  ThreadToken        [O] Optional returned token handle.
 *
 * RETURNS
 *  Success: STATUS_SUCCESS.
 *  Failure: NTSTATUS code.
 */
NTSTATUS WINAPI
RtlImpersonateSelfEx( SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
                      ACCESS_MASK AdditionalAccess, HANDLE *ThreadToken )
{
    SECURITY_QUALITY_OF_SERVICE qos;
    NTSTATUS Status;
    OBJECT_ATTRIBUTES attr;
    HANDLE ProcessToken;
    HANDLE ImpersonationToken;

    TRACE("(%08x, %08x, %p)\n", ImpersonationLevel, AdditionalAccess, ThreadToken);

    if (!ThreadToken && AdditionalAccess) return STATUS_INVALID_PARAMETER_2;

    Status = NtOpenProcessToken( NtCurrentProcess(), TOKEN_DUPLICATE,
                                 &ProcessToken);
    if (Status != STATUS_SUCCESS)
        return Status;

    qos.Length = sizeof(qos);
    qos.ImpersonationLevel = ImpersonationLevel;
    qos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
    qos.EffectiveOnly = FALSE;
    InitializeObjectAttributes( &attr, NULL, 0, NULL, NULL );
    attr.SecurityQualityOfService = &qos;

    Status = NtDuplicateToken( ProcessToken, TOKEN_IMPERSONATE | AdditionalAccess, &attr, FALSE,
                               TokenImpersonation, &ImpersonationToken );
    if (Status != STATUS_SUCCESS)
    {
        NtClose( ProcessToken );
        return Status;
    }

    Status = NtSetInformationThread( GetCurrentThread(),
                                     ThreadImpersonationToken,
                                     &ImpersonationToken,
                                     sizeof(ImpersonationToken) );

    if (Status || !ThreadToken)
        NtClose( ImpersonationToken );
    else
        *ThreadToken = ImpersonationToken;
    NtClose( ProcessToken );

    return Status;
}

/******************************************************************************
 *  RtlImpersonateSelf		[NTDLL.@]
 */
NTSTATUS WINAPI RtlImpersonateSelf( SECURITY_IMPERSONATION_LEVEL ImpersonationLevel )
{
    return RtlImpersonateSelfEx( ImpersonationLevel, 0, NULL );
}


/******************************************************************************
 * RtlConvertSidToUnicodeString (NTDLL.@)
 *
 * The returned SID is used to access the USER registry hive usually
 *
 * the native function returns something like
 * "S-1-5-21-0000000000-000000000-0000000000-500";
 */
NTSTATUS WINAPI RtlConvertSidToUnicodeString(
       PUNICODE_STRING String,
       PSID pSid,
       BOOLEAN AllocateString)
{
    WCHAR buffer[2 + 10 + 10 + 10 * SID_MAX_SUB_AUTHORITIES];
    WCHAR *p = buffer;
    const SID *sid = pSid;
    DWORD i, len;

    *p++ = 'S';
    p += swprintf( p, ARRAY_SIZE(buffer) - (p - buffer), L"-%u", sid->Revision );
    p += swprintf( p, ARRAY_SIZE(buffer) - (p - buffer), L"-%u",
                   MAKELONG( MAKEWORD( sid->IdentifierAuthority.Value[5],
                                       sid->IdentifierAuthority.Value[4] ),
                             MAKEWORD( sid->IdentifierAuthority.Value[3],
                                       sid->IdentifierAuthority.Value[2] )));
    for (i = 0; i < sid->SubAuthorityCount; i++)
        p += swprintf( p, ARRAY_SIZE(buffer) - (p - buffer), L"-%u", sid->SubAuthority[i] );

    len = (p + 1 - buffer) * sizeof(WCHAR);

    String->Length = len - sizeof(WCHAR);
    if (AllocateString)
    {
        String->MaximumLength = len;
        if (!(String->Buffer = RtlAllocateHeap( GetProcessHeap(), 0, len )))
            return STATUS_NO_MEMORY;
    }
    else if (len > String->MaximumLength) return STATUS_BUFFER_OVERFLOW;

    memcpy( String->Buffer, buffer, len );
    return STATUS_SUCCESS;
}

/******************************************************************************
 * RtlQueryInformationAcl (NTDLL.@)
 */
NTSTATUS WINAPI RtlQueryInformationAcl(
    PACL pAcl,
    LPVOID pAclInformation,
    DWORD nAclInformationLength,
    ACL_INFORMATION_CLASS dwAclInformationClass)
{
    NTSTATUS status = STATUS_SUCCESS;

    TRACE("pAcl=%p pAclInfo=%p len=%ld, class=%d\n",
        pAcl, pAclInformation, nAclInformationLength, dwAclInformationClass);

    switch (dwAclInformationClass)
    {
        case AclRevisionInformation:
        {
            PACL_REVISION_INFORMATION paclrev = pAclInformation;

            if (nAclInformationLength < sizeof(ACL_REVISION_INFORMATION))
                status = STATUS_INVALID_PARAMETER;
            else
                paclrev->AclRevision = pAcl->AclRevision;

            break;
        }

        case AclSizeInformation:
        {
            PACL_SIZE_INFORMATION paclsize = pAclInformation;

            if (nAclInformationLength < sizeof(ACL_SIZE_INFORMATION))
                status = STATUS_INVALID_PARAMETER;
            else
            {
                paclsize->AceCount = pAcl->AceCount;
                paclsize->AclBytesInUse = acl_bytesInUse(pAcl);
		if (pAcl->AclSize < paclsize->AclBytesInUse)
                {
                    WARN("Acl uses %d bytes, but only has %ld allocated!  Returning smaller of the two values.\n", pAcl->AclSize, paclsize->AclBytesInUse);
                    paclsize->AclBytesFree = 0;
                    paclsize->AclBytesInUse = pAcl->AclSize;
                }
                else
                    paclsize->AclBytesFree = pAcl->AclSize - paclsize->AclBytesInUse;
            }

            break;
        }

        default:
            WARN("Unknown AclInformationClass value: %d\n", dwAclInformationClass);
            status = STATUS_INVALID_PARAMETER;
    }

    return status;
}

NTSTATUS WINAPI RtlConvertToAutoInheritSecurityObject(
        PSECURITY_DESCRIPTOR pdesc,
        PSECURITY_DESCRIPTOR cdesc,
        PSECURITY_DESCRIPTOR* ndesc,
        GUID* objtype,
        BOOL isdir,
        PGENERIC_MAPPING genmap )
{
    FIXME("%p %p %p %p %d %p - stub\n", pdesc, cdesc, ndesc, objtype, isdir, genmap);

    return STATUS_NOT_IMPLEMENTED;
}

/******************************************************************************
 * RtlDefaultNpAcl (NTDLL.@)
 */
NTSTATUS WINAPI RtlDefaultNpAcl(PACL *pAcl)
{
    FIXME("%p - stub\n", pAcl);

    *pAcl = NULL;
    return STATUS_SUCCESS;
}

/******************************************************************************
 * RtlCreateServiceSid [NTDLL.@]
 */
NTSTATUS WINAPI RtlCreateServiceSid( PUNICODE_STRING name, PSID pSid, LPDWORD len )
{
    static const SID_IDENTIFIER_AUTHORITY nt_authority = { SECURITY_NT_AUTHORITY };
    DWORD sid_length;
    NTSTATUS status;
    UNICODE_STRING name_upper;
    SID *sid = (SID *)pSid;
    ULONG count = 1 + SYMCRYPT_SHA1_RESULT_SIZE / sizeof(sid->SubAuthority[0]);

    if (name == NULL || len == NULL) return STATUS_INVALID_PARAMETER;

    sid_length = RtlLengthRequiredSid( count );
    if (*len < sid_length)
    {
        *len = sid_length;
        return STATUS_BUFFER_TOO_SMALL;
    }

    sid->Revision = SID_REVISION;
    sid->IdentifierAuthority = nt_authority;
    sid->SubAuthorityCount = count;
    sid->SubAuthority[0] = SECURITY_SERVICE_ID_BASE_RID;
    *len = sid_length;

    if ((status = RtlUpcaseUnicodeString( &name_upper, name, TRUE ))) return status;

    SymCryptSha1( (BYTE *)name_upper.Buffer, name_upper.Length, (BYTE *)(sid->SubAuthority + 1) );
    RtlFreeUnicodeString( &name_upper );
    return STATUS_SUCCESS;
}

/******************************************************************************
 * RtlDeriveCapabilitySidsFromName (NTDLL.@)
 */
NTSTATUS WINAPI RtlDeriveCapabilitySidsFromName( UNICODE_STRING *cap_name, PSID cap_group_sid, PSID cap_sid )
{
    static const SID_IDENTIFIER_AUTHORITY app_authority = { SECURITY_APP_PACKAGE_AUTHORITY };
    static const SID_IDENTIFIER_AUTHORITY nt_authority = { SECURITY_NT_AUTHORITY };
    UNICODE_STRING cap_upcase;
    NTSTATUS status;
    ULONG hash[8];
    SID *sid;

    TRACE( "cap_name %s, cap_group_sid %p, cap_sid %p.\n", debugstr_us(cap_name), cap_group_sid, cap_sid );

    if ((status = RtlUpcaseUnicodeString( &cap_upcase, cap_name, TRUE ))) return status;
    SymCryptSha256( (BYTE *)cap_upcase.Buffer, cap_upcase.Length, (BYTE *)hash );
    RtlFreeUnicodeString( &cap_upcase );

    sid = cap_sid;
    sid->Revision = SID_REVISION;
    sid->IdentifierAuthority = app_authority;
    sid->SubAuthorityCount = 2 + ARRAY_SIZE(hash);
    sid->SubAuthority[0] = SECURITY_BATCH_RID;
    sid->SubAuthority[1] = SECURITY_CAPABILITY_APP_RID;
    memcpy( sid->SubAuthority + 2, hash, sizeof(hash) );

    sid = cap_group_sid;
    sid->Revision = SID_REVISION;
    sid->IdentifierAuthority = nt_authority;
    sid->SubAuthorityCount = 1 + ARRAY_SIZE(hash);
    sid->SubAuthority[0] = SECURITY_BUILTIN_DOMAIN_RID;
    memcpy( sid->SubAuthority + 1, hash, sizeof(hash) );

    return STATUS_SUCCESS;
}

/******************************************************************************
 * RtlCapabilityCheck (NTDLL.@)
 */
NTSTATUS WINAPI RtlCapabilityCheck( HANDLE token, UNICODE_STRING *cap_name, BOOLEAN *has_capability )
{
    BYTE cap_group_buffer[SECURITY_MAX_SID_SIZE], cap_buffer[SECURITY_MAX_SID_SIZE];
    HANDLE effective_token = token;
    DWORD is_appcontainer;
    TOKEN_TYPE type;
    NTSTATUS status;
    ULONG size;

    TRACE( "token %p, cap_name %s, has_capability %p.\n",
           token, debugstr_us(cap_name), has_capability );
    if (!cap_name) return STATUS_INVALID_PARAMETER;
    if (!has_capability) return STATUS_ACCESS_VIOLATION;
    *has_capability = FALSE;

    status = RtlDeriveCapabilitySidsFromName( cap_name, cap_group_buffer, cap_buffer );
    if (status) return status;

    if (!effective_token) effective_token = GetCurrentThreadEffectiveToken();
    else
    {
        status = NtQueryInformationToken( effective_token, TokenType, &type, sizeof(type), &size );
        if (status) return status;
        if (type == TokenPrimary) return STATUS_NO_IMPERSONATION_TOKEN;
    }

    status = NtQueryInformationToken( effective_token, TokenIsAppContainer,
                                      &is_appcontainer, sizeof(is_appcontainer), &size );
    if (status) return status;
    if (!is_appcontainer)
    {
        *has_capability = TRUE;
        return STATUS_SUCCESS;
    }

    return RtlCheckTokenCapability( effective_token, cap_buffer, has_capability );
}

/******************************************************************************
 * RtlCheckSandboxedToken (NTDLL.@)
 */
NTSTATUS WINAPI RtlCheckSandboxedToken( HANDLE token, BOOLEAN *is_sandboxed )
{
    DWORD value = FALSE;
    ULONG size;
    NTSTATUS status;

    TRACE( "token %p, is_sandboxed %p.\n", token, is_sandboxed );

    if (!is_sandboxed) return STATUS_ACCESS_VIOLATION;
    *is_sandboxed = FALSE;
    if (!token) token = GetCurrentThreadEffectiveToken();
    status = NtQueryInformationToken( token, TokenIsSandboxed, &value, sizeof(value), &size );
    if (!status && value) *is_sandboxed = TRUE;
    return status;
}

/******************************************************************************
 * RtlCheckTokenCapability (NTDLL.@)
 */
NTSTATUS WINAPI RtlCheckTokenCapability( HANDLE token, PSID capability_sid, BOOLEAN *has_capability )
{
    static const SID_IDENTIFIER_AUTHORITY app_authority = { SECURITY_APP_PACKAGE_AUTHORITY };
    GENERIC_MAPPING mapping = { 0x10001, 0x10001, 0x10001, 0x10001 };
    struct { TOKEN_USER user; BYTE sid[SECURITY_MAX_SID_SIZE]; } user;
    union { ACL acl; BYTE buffer[sizeof(ACL) + 2 * (offsetof(ACCESS_ALLOWED_ACE, SidStart) + SECURITY_MAX_SID_SIZE)]; } acl;
    SECURITY_QUALITY_OF_SERVICE qos = { sizeof(qos), SecurityImpersonation, SECURITY_STATIC_TRACKING, FALSE };
    SECURITY_DESCRIPTOR sd;
    OBJECT_ATTRIBUTES attr;
    PRIVILEGE_SET privileges;
    HANDLE opened_token = NULL, process_token;
    ULONG size, granted = 0;
    NTSTATUS status, access_status;

    TRACE( "token %p, capability_sid %p, has_capability %p.\n",
           token, capability_sid, has_capability );

    if (!has_capability) return STATUS_ACCESS_VIOLATION;
    *has_capability = FALSE;
    if (!RtlValidSid( capability_sid ) || ((SID *)capability_sid)->SubAuthorityCount < 2 ||
        memcmp( ((SID *)capability_sid)->IdentifierAuthority.Value, app_authority.Value, sizeof(app_authority.Value) ) ||
        ((SID *)capability_sid)->SubAuthority[0] != SECURITY_CAPABILITY_BASE_RID)
        return STATUS_INVALID_PARAMETER;

    if (!token)
    {
        status = NtOpenThreadToken( NtCurrentThread(), TOKEN_QUERY, TRUE, &opened_token );
        if (status == STATUS_NO_TOKEN)
        {
            status = NtOpenProcessToken( NtCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &process_token );
            if (status) return status;
            InitializeObjectAttributes( &attr, NULL, 0, NULL, NULL );
            attr.SecurityQualityOfService = &qos;
            status = NtDuplicateToken( process_token, TOKEN_QUERY, &attr, FALSE,
                                       TokenImpersonation, &opened_token );
            NtClose( process_token );
        }
        if (status) return status;
        token = opened_token;
    }

    status = NtQueryInformationToken( token, TokenUser, &user, sizeof(user), &size );
    if (status) goto done;
    RtlCreateSecurityDescriptor( &sd, SECURITY_DESCRIPTOR_REVISION );
    RtlSetOwnerSecurityDescriptor( &sd, user.user.User.Sid, FALSE );
    RtlSetGroupSecurityDescriptor( &sd, user.user.User.Sid, FALSE );
    RtlCreateAcl( &acl.acl, sizeof(acl), ACL_REVISION );
    RtlAddAccessAllowedAce( &acl.acl, ACL_REVISION, 0x10001, user.user.User.Sid );
    RtlAddAccessAllowedAce( &acl.acl, ACL_REVISION, 0x10001, capability_sid );
    RtlSetDaclSecurityDescriptor( &sd, TRUE, &acl.acl, FALSE );

    /* Full-trust tokens use the user ACE. Restricted tokens must also pass
     * their second access-check pass; capability membership alone is not the
     * entire contract. Keep that authorization in the shared token owner. */
    size = sizeof(privileges);
    status = NtAccessCheck( &sd, token, 0x10001, &mapping,
                            &privileges, &size, &granted, &access_status );
    if (!status && !access_status && granted == 0x10001) *has_capability = TRUE;

done:
    if (opened_token) NtClose( opened_token );
    TRACE( "status %#lx, has_capability %u.\n", status, *has_capability );
    return status;
}

/******************************************************************************
 * RtlCheckTokenMembership (NTDLL.@)
 */
NTSTATUS WINAPI RtlCheckTokenMembership( HANDLE token, PSID sid, BOOLEAN *is_member )
{
    return RtlCheckTokenMembershipEx( token, sid, 0, is_member );
}

/******************************************************************************
 * RtlCheckTokenMembershipEx (NTDLL.@)
 */
NTSTATUS WINAPI RtlCheckTokenMembershipEx( HANDLE token, PSID sid, ULONG flags, BOOLEAN *is_member )
{
    TOKEN_GROUPS *groups = NULL;
    TOKEN_USER *user = NULL;
    TOKEN_TYPE type;
    NTSTATUS status;
    ULONG size, i;
    BOOL explicit_token = !!token;

    TRACE( "token %p, sid %p, flags %#lx, is_member %p.\n", token, sid, flags, is_member );

    if (!is_member) return STATUS_ACCESS_VIOLATION;
    *is_member = FALSE;
    if (flags & ~3) return STATUS_INVALID_PARAMETER;
    if (!RtlValidSid( sid )) return STATUS_INVALID_SID;

    if (!token) token = GetCurrentThreadEffectiveToken();
    if (explicit_token)
    {
        status = NtQueryInformationToken( token, TokenType, &type, sizeof(type), &size );
        if (status) return status;
        if (type == TokenPrimary) return STATUS_NO_IMPERSONATION_TOKEN;
    }

    status = NtQueryInformationToken( token, TokenUser, NULL, 0, &size );
    if (status != STATUS_BUFFER_TOO_SMALL) return status;
    if (!(user = RtlAllocateHeap( GetProcessHeap(), 0, size ))) return STATUS_NO_MEMORY;
    status = NtQueryInformationToken( token, TokenUser, user, size, &size );
    if (status) goto done;
    if (RtlEqualSid( user->User.Sid, sid ))
    {
        *is_member = TRUE;
        goto done;
    }

    status = NtQueryInformationToken( token, TokenGroups, NULL, 0, &size );
    if (status != STATUS_BUFFER_TOO_SMALL) goto done;
    if (!(groups = RtlAllocateHeap( GetProcessHeap(), 0, size )))
    {
        status = STATUS_NO_MEMORY;
        goto done;
    }
    status = NtQueryInformationToken( token, TokenGroups, groups, size, &size );
    if (status) goto done;

    for (i = 0; i < groups->GroupCount; ++i)
    {
        if ((groups->Groups[i].Attributes & SE_GROUP_ENABLED) &&
            RtlEqualSid( groups->Groups[i].Sid, sid ))
        {
            *is_member = TRUE;
            break;
        }
    }

done:
    RtlFreeHeap( GetProcessHeap(), 0, groups );
    RtlFreeHeap( GetProcessHeap(), 0, user );
    return status;
}

/***********************************************************************
 *             RtlGetAppContainerSidType  (NTDLL.@)
 */
NTSTATUS WINAPI RtlGetAppContainerSidType( PSID sid_ptr, ULONG *type )
{
    static const SID_IDENTIFIER_AUTHORITY authority = { SECURITY_APP_PACKAGE_AUTHORITY };
    SID *sid = sid_ptr;

    if (sid->Revision != SID_REVISION || sid->SubAuthorityCount < 2 ||
        memcmp( &sid->IdentifierAuthority, &authority, sizeof(authority) ) ||
        sid->SubAuthority[0] != SECURITY_APP_PACKAGE_BASE_RID)
    {
        *type = 0;
        return STATUS_NOT_APPCONTAINER;
    }

    if (sid->SubAuthorityCount == 12)
    {
        *type = 1;
        return STATUS_SUCCESS;
    }
    if (sid->SubAuthorityCount == 8)
    {
        *type = 2;
        return STATUS_SUCCESS;
    }

    *type = 3;
    return STATUS_NOT_APPCONTAINER;
}

/***********************************************************************
 *             RtlGetAppContainerNamedObjectPath  (NTDLL.@)
 */
NTSTATUS WINAPI RtlGetAppContainerNamedObjectPath( HANDLE token, PSID appcontainer_sid,
                                                    BOOLEAN relative_path, UNICODE_STRING *path )
{
    DWORD is_appcontainer;
    NTSTATUS status;

    TRACE( "(%p,%p,%u,%p)\n", token, appcontainer_sid, relative_path, path );

    if (!path) return STATUS_INVALID_PARAMETER;
    if (token && appcontainer_sid) return STATUS_INVALID_PARAMETER_MIX;

    if (appcontainer_sid)
    {
        FIXME( "AppContainer named-object paths are not supported.\n" );
        return STATUS_NOT_SUPPORTED;
    }

    if (!token) token = GetCurrentThreadEffectiveToken();
    status = NtQueryInformationToken( token, TokenIsAppContainer, &is_appcontainer,
                                      sizeof(is_appcontainer), NULL );
    if (status) return status;

    if (is_appcontainer)
    {
        FIXME( "AppContainer named-object paths are not supported.\n" );
        return STATUS_NOT_SUPPORTED;
    }

    memset( path, 0, sizeof(*path) );
    return STATUS_SUCCESS;
}
