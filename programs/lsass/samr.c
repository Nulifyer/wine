/*
 * Security Account Manager RPC entry point
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
#include "lmcons.h"
#include "lmaccess.h"
#include "winternl.h"
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "samr.h"
#include "local_accounts.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(secur32);

#define SAMR_CONTEXT_MAGIC 0x53414d52
#define SAMR_SERVER_ALL_ACCESS 0x000f003f
#define SAMR_SERVER_LOOKUP_DOMAIN 0x00000020
#define SAMR_DOMAIN_ALL_ACCESS 0x000f07ff
#define SAMR_DOMAIN_LIST_ACCOUNTS 0x00000100
#define SAMR_DOMAIN_OPEN_ACCOUNT 0x00000200
#define SAMR_LOCAL_USER_RID 1000
#define SAMR_SID_TYPE_USER 1
#define SAMR_SID_TYPE_UNKNOWN 8

enum samr_context_type
{
    SAMR_CONTEXT_SERVER,
    SAMR_CONTEXT_ACCOUNT_DOMAIN,
    SAMR_CONTEXT_BUILTIN_DOMAIN
};

struct samr_context
{
    DWORD magic;
    enum samr_context_type type;
    ACCESS_MASK access;
};

static NTSTATUS create_context( enum samr_context_type type, ACCESS_MASK requested,
                                ACCESS_MASK all_access, SAMR_HANDLE *handle )
{
    struct samr_context *context;
    ACCESS_MASK access = requested;

    if (!handle || !requested) return STATUS_INVALID_PARAMETER;
    *handle = NULL;
    if (requested & MAXIMUM_ALLOWED) access = all_access;
    else if (requested & ~all_access) return STATUS_ACCESS_DENIED;
    if (!(context = malloc( sizeof(*context) ))) return STATUS_NO_MEMORY;
    context->magic = SAMR_CONTEXT_MAGIC;
    context->type = type;
    context->access = access;
    *handle = context;
    return STATUS_SUCCESS;
}

static struct samr_context *get_context( SAMR_HANDLE handle, enum samr_context_type type )
{
    struct samr_context *context = handle;

    if (!context || context->magic != SAMR_CONTEXT_MAGIC || context->type != type) return NULL;
    return context;
}

void __RPC_USER SAMR_HANDLE_rundown( SAMR_HANDLE handle )
{
    struct samr_context *context = handle;

    if (!context || context->magic != SAMR_CONTEXT_MAGIC) return;
    context->magic = 0;
    free( context );
}

NTSTATUS samr_close_handle( SAMR_HANDLE *handle )
{
    struct samr_context *context;

    if (!handle || !(context = *handle) || context->magic != SAMR_CONTEXT_MAGIC)
        return STATUS_INVALID_HANDLE;
    context->magic = 0;
    free( context );
    *handle = NULL;
    return STATUS_SUCCESS;
}

static NTSTATUS connect_server( ACCESS_MASK desired_access, SAMR_HANDLE *server_handle )
{
    return create_context( SAMR_CONTEXT_SERVER, desired_access, SAMR_SERVER_ALL_ACCESS,
                           server_handle );
}

NTSTATUS samr_connect4( WCHAR *server_name, SAMR_HANDLE *server_handle,
                        ULONG client_revision, ULONG desired_access )
{
    TRACE( "server %s, revision %lu, access %#lx, handle %p\n",
           debugstr_w(server_name), client_revision, desired_access, server_handle );
    return connect_server( desired_access, server_handle );
}

NTSTATUS samr_connect5( WCHAR *server_name, ULONG desired_access, ULONG in_version,
                        SAMR_IN_REVISION_INFO *in_revision_info, ULONG *out_version,
                        SAMR_OUT_REVISION_INFO *out_revision_info, SAMR_HANDLE *server_handle )
{
    NTSTATUS status;

    TRACE( "server %s, access %#lx, version %lu, input %p, output %p, handle %p\n",
           debugstr_w(server_name), desired_access, in_version, in_revision_info,
           out_revision_info, server_handle );

    if (!out_version || !out_revision_info || !server_handle || !in_revision_info)
        return STATUS_INVALID_PARAMETER;
    *server_handle = NULL;
    if (in_version != 1) return STATUS_NOT_SUPPORTED;
    *out_version = 1;
    memset( out_revision_info, 0, sizeof(*out_revision_info) );
    out_revision_info->V1.Revision = 3;
    out_revision_info->V1.SupportedFeatures = 0;
    if ((status = connect_server( desired_access, server_handle ))) return status;
    return STATUS_SUCCESS;
}

NTSTATUS samr_open_domain( SAMR_HANDLE server_handle, ULONG desired_access,
                           SID *domain_sid, SAMR_HANDLE *domain_handle )
{
    struct samr_context *server = get_context( server_handle, SAMR_CONTEXT_SERVER );
    enum samr_context_type type;

    TRACE( "server %p, access %#lx, sid %p, domain %p\n", server_handle,
           desired_access, domain_sid, domain_handle );

    if (!server) return STATUS_INVALID_HANDLE;
    if (!(server->access & SAMR_SERVER_LOOKUP_DOMAIN)) return STATUS_ACCESS_DENIED;
    if (!domain_sid || !IsValidSid( domain_sid )) return STATUS_INVALID_SID;
    if (lsa_is_computer_sid( domain_sid )) type = SAMR_CONTEXT_ACCOUNT_DOMAIN;
    else if (lsa_is_builtin_domain_sid( domain_sid )) type = SAMR_CONTEXT_BUILTIN_DOMAIN;
    else return STATUS_NO_SUCH_DOMAIN;
    return create_context( type, desired_access, SAMR_DOMAIN_ALL_ACCESS, domain_handle );
}

static void free_enumeration_buffer( SAMR_ENUMERATION_BUFFER *buffer )
{
    if (!buffer) return;
    if (buffer->Buffer)
    {
        MIDL_user_free( buffer->Buffer[0].Name.Buffer );
        MIDL_user_free( buffer->Buffer );
    }
    MIDL_user_free( buffer );
}

NTSTATUS samr_enumerate_users_in_domain( SAMR_HANDLE domain_handle, ULONG *enumeration_context,
                                         ULONG user_account_control,
                                         SAMR_ENUMERATION_BUFFER **buffer,
                                         ULONG preferred_maximum_length,
                                         ULONG *count_returned )
{
    struct samr_context *domain = domain_handle;
    SAMR_ENUMERATION_BUFFER *result = NULL;
    WCHAR user_name[UNLEN + 1];
    DWORD user_name_chars = ARRAY_SIZE(user_name);
    SIZE_T name_bytes, required;

    TRACE( "domain %p, context %p, control %#lx, buffer %p, maximum %lu, count %p\n",
           domain_handle, enumeration_context, user_account_control, buffer,
           preferred_maximum_length, count_returned );

    if (!domain || domain->magic != SAMR_CONTEXT_MAGIC ||
        (domain->type != SAMR_CONTEXT_ACCOUNT_DOMAIN &&
         domain->type != SAMR_CONTEXT_BUILTIN_DOMAIN))
        return STATUS_INVALID_HANDLE;
    if (!(domain->access & SAMR_DOMAIN_LIST_ACCOUNTS)) return STATUS_ACCESS_DENIED;
    if (!enumeration_context || !buffer || !count_returned) return STATUS_INVALID_PARAMETER;
    *buffer = NULL;
    *count_returned = 0;

    if (*enumeration_context || domain->type == SAMR_CONTEXT_BUILTIN_DOMAIN ||
        (user_account_control & ~UF_NORMAL_ACCOUNT))
        return STATUS_SUCCESS;
    if (!GetUserNameW( user_name, &user_name_chars )) return STATUS_UNSUCCESSFUL;
    name_bytes = (user_name_chars - 1) * sizeof(WCHAR);
    required = sizeof(*result) + sizeof(*result->Buffer) + name_bytes + sizeof(WCHAR);
    if (preferred_maximum_length && preferred_maximum_length < required)
        return STATUS_MORE_ENTRIES;

    if (!(result = MIDL_user_allocate( sizeof(*result) ))) return STATUS_NO_MEMORY;
    memset( result, 0, sizeof(*result) );
    if (!(result->Buffer = MIDL_user_allocate( sizeof(*result->Buffer) ))) goto no_memory;
    memset( result->Buffer, 0, sizeof(*result->Buffer) );
    if (!(result->Buffer[0].Name.Buffer = MIDL_user_allocate( name_bytes + sizeof(WCHAR) )))
        goto no_memory;
    memcpy( result->Buffer[0].Name.Buffer, user_name, name_bytes + sizeof(WCHAR) );
    result->EntriesRead = 1;
    result->Buffer[0].RelativeId = SAMR_LOCAL_USER_RID;
    result->Buffer[0].Name.Length = name_bytes;
    result->Buffer[0].Name.MaximumLength = name_bytes + sizeof(WCHAR);
    *enumeration_context = 1;
    *count_returned = 1;
    *buffer = result;
    return STATUS_SUCCESS;

no_memory:
    free_enumeration_buffer( result );
    return STATUS_NO_MEMORY;
}

static NTSTATUS lookup_names_in_domain( SAMR_HANDLE domain_handle, ULONG count,
                                        SAMR_UNICODE_STRING *names,
                                        SAMR_ULONG_ARRAY *relative_ids,
                                        SAMR_ULONG_ARRAY *use )
{
    struct samr_context *domain = domain_handle;
    UNICODE_STRING local_name;
    WCHAR user_name[UNLEN + 1];
    DWORD user_name_chars = ARRAY_SIZE(user_name);
    ULONG mapped = 0, i;

    if (!domain || domain->magic != SAMR_CONTEXT_MAGIC ||
        (domain->type != SAMR_CONTEXT_ACCOUNT_DOMAIN &&
         domain->type != SAMR_CONTEXT_BUILTIN_DOMAIN))
        return STATUS_INVALID_HANDLE;
    if (!(domain->access & SAMR_DOMAIN_OPEN_ACCOUNT)) return STATUS_ACCESS_DENIED;
    if (!relative_ids || !use || (count && !names)) return STATUS_INVALID_PARAMETER;
    relative_ids->Count = use->Count = 0;
    relative_ids->Element = use->Element = NULL;
    if (!count) return STATUS_SUCCESS;
    if (count > 1000) return STATUS_INVALID_PARAMETER;
    if (!GetUserNameW( user_name, &user_name_chars )) return STATUS_UNSUCCESSFUL;
    RtlInitUnicodeString( &local_name, user_name );

    if (!(relative_ids->Element = MIDL_user_allocate( count * sizeof(*relative_ids->Element) )))
        return STATUS_NO_MEMORY;
    if (!(use->Element = MIDL_user_allocate( count * sizeof(*use->Element) )))
    {
        MIDL_user_free( relative_ids->Element );
        relative_ids->Element = NULL;
        return STATUS_NO_MEMORY;
    }
    relative_ids->Count = use->Count = count;
    for (i = 0; i < count; ++i)
    {
        UNICODE_STRING name = {names[i].Length, names[i].MaximumLength, names[i].Buffer};
        BOOL match = domain->type == SAMR_CONTEXT_ACCOUNT_DOMAIN &&
                     name.Buffer && RtlEqualUnicodeString( &name, &local_name, TRUE );

        relative_ids->Element[i] = match ? SAMR_LOCAL_USER_RID : 0;
        use->Element[i] = match ? SAMR_SID_TYPE_USER : SAMR_SID_TYPE_UNKNOWN;
        if (match) ++mapped;
    }
    if (!mapped) return STATUS_NONE_MAPPED;
    return mapped == count ? STATUS_SUCCESS : STATUS_SOME_NOT_MAPPED;
}

NTSTATUS samr_lookup_names_in_domain( SAMR_HANDLE domain_handle, ULONG count,
                                      SAMR_UNICODE_STRING *names,
                                      SAMR_ULONG_ARRAY *relative_ids,
                                      SAMR_ULONG_ARRAY *use )
{
    TRACE( "domain %p, count %lu, names %p, ids %p, use %p\n",
           domain_handle, count, names, relative_ids, use );
    return lookup_names_in_domain( domain_handle, count, names, relative_ids, use );
}

NTSTATUS samr_lookup_names_in_domain2( SAMR_HANDLE domain_handle, ULONG count,
                                       SAMR_UNICODE_STRING *names,
                                       SAMR_ULONG_ARRAY *relative_ids,
                                       SAMR_ULONG_ARRAY *use )
{
    TRACE( "domain %p, count %lu, names %p, ids %p, use %p\n",
           domain_handle, count, names, relative_ids, use );
    return lookup_names_in_domain( domain_handle, count, names, relative_ids, use );
}

static void free_returned_names( SAMR_RETURNED_USTRING_ARRAY *names )
{
    ULONG i;

    if (!names || !names->Element) return;
    for (i = 0; i < names->Count; ++i) MIDL_user_free( names->Element[i].Buffer );
    MIDL_user_free( names->Element );
    names->Element = NULL;
    names->Count = 0;
}

NTSTATUS samr_lookup_ids_in_domain( SAMR_HANDLE domain_handle, ULONG count,
                                    ULONG *relative_ids,
                                    SAMR_RETURNED_USTRING_ARRAY *names,
                                    SAMR_ULONG_ARRAY *use )
{
    struct samr_context *domain = domain_handle;
    WCHAR user_name[UNLEN + 1];
    DWORD user_name_chars = ARRAY_SIZE(user_name);
    SIZE_T name_bytes;
    ULONG mapped = 0, i;

    TRACE( "domain %p, count %lu, ids %p, names %p, use %p\n",
           domain_handle, count, relative_ids, names, use );
    if (!domain || domain->magic != SAMR_CONTEXT_MAGIC ||
        (domain->type != SAMR_CONTEXT_ACCOUNT_DOMAIN &&
         domain->type != SAMR_CONTEXT_BUILTIN_DOMAIN))
        return STATUS_INVALID_HANDLE;
    if (!(domain->access & SAMR_DOMAIN_OPEN_ACCOUNT)) return STATUS_ACCESS_DENIED;
    if (!names || !use || (count && !relative_ids)) return STATUS_INVALID_PARAMETER;
    names->Count = use->Count = 0;
    names->Element = NULL;
    use->Element = NULL;
    if (!count) return STATUS_SUCCESS;
    if (count > 1000) return STATUS_INVALID_PARAMETER;
    if (!GetUserNameW( user_name, &user_name_chars )) return STATUS_UNSUCCESSFUL;
    name_bytes = (user_name_chars - 1) * sizeof(WCHAR);

    if (!(names->Element = MIDL_user_allocate( count * sizeof(*names->Element) )))
        return STATUS_NO_MEMORY;
    memset( names->Element, 0, count * sizeof(*names->Element) );
    names->Count = count;
    if (!(use->Element = MIDL_user_allocate( count * sizeof(*use->Element) )))
        goto no_memory;
    use->Count = count;
    for (i = 0; i < count; ++i)
    {
        BOOL match = domain->type == SAMR_CONTEXT_ACCOUNT_DOMAIN &&
                     relative_ids[i] == SAMR_LOCAL_USER_RID;

        use->Element[i] = match ? SAMR_SID_TYPE_USER : SAMR_SID_TYPE_UNKNOWN;
        if (!match) continue;
        if (!(names->Element[i].Buffer = MIDL_user_allocate( name_bytes + sizeof(WCHAR) )))
            goto no_memory;
        memcpy( names->Element[i].Buffer, user_name, name_bytes + sizeof(WCHAR) );
        names->Element[i].Length = name_bytes;
        names->Element[i].MaximumLength = name_bytes + sizeof(WCHAR);
        ++mapped;
    }
    if (!mapped) return STATUS_NONE_MAPPED;
    return mapped == count ? STATUS_SUCCESS : STATUS_SOME_NOT_MAPPED;

no_memory:
    MIDL_user_free( use->Element );
    use->Element = NULL;
    use->Count = 0;
    free_returned_names( names );
    return STATUS_NO_MEMORY;
}

NTSTATUS samr_rid_to_sid( SAMR_HANDLE object_handle, ULONG relative_id, SID **sid )
{
    struct samr_context *domain = object_handle;
    SID *domain_sid, *result;
    DWORD domain_size, result_size;

    TRACE( "object %p, rid %lu, sid %p\n", object_handle, relative_id, sid );
    if (!domain || domain->magic != SAMR_CONTEXT_MAGIC ||
        domain->type != SAMR_CONTEXT_ACCOUNT_DOMAIN)
        return STATUS_INVALID_HANDLE;
    if (!(domain->access & SAMR_DOMAIN_OPEN_ACCOUNT)) return STATUS_ACCESS_DENIED;
    if (!sid) return STATUS_INVALID_PARAMETER;
    *sid = NULL;
    if (!(domain_sid = lsa_allocate_computer_sid())) return STATUS_NO_MEMORY;
    domain_size = GetLengthSid( domain_sid );
    result_size = domain_size + sizeof(DWORD);
    if (!(result = MIDL_user_allocate( result_size )))
    {
        MIDL_user_free( domain_sid );
        return STATUS_NO_MEMORY;
    }
    memcpy( result, domain_sid, domain_size );
    ++result->SubAuthorityCount;
    result->SubAuthority[result->SubAuthorityCount - 1] = relative_id;
    MIDL_user_free( domain_sid );
    *sid = result;
    return STATUS_SUCCESS;
}

#define DEFINE_UNUSED_OPNUM(n) \
    NTSTATUS samr_unused_##n(void) { return STATUS_NOT_IMPLEMENTED; }

DEFINE_UNUSED_OPNUM(0)
DEFINE_UNUSED_OPNUM(2)
DEFINE_UNUSED_OPNUM(3)
DEFINE_UNUSED_OPNUM(4)
DEFINE_UNUSED_OPNUM(5)
DEFINE_UNUSED_OPNUM(6)
DEFINE_UNUSED_OPNUM(8)
DEFINE_UNUSED_OPNUM(9)
DEFINE_UNUSED_OPNUM(10)
DEFINE_UNUSED_OPNUM(11)
DEFINE_UNUSED_OPNUM(12)
DEFINE_UNUSED_OPNUM(14)
DEFINE_UNUSED_OPNUM(15)
DEFINE_UNUSED_OPNUM(16)
DEFINE_UNUSED_OPNUM(19)
DEFINE_UNUSED_OPNUM(20)
DEFINE_UNUSED_OPNUM(21)
DEFINE_UNUSED_OPNUM(22)
DEFINE_UNUSED_OPNUM(23)
DEFINE_UNUSED_OPNUM(24)
DEFINE_UNUSED_OPNUM(25)
DEFINE_UNUSED_OPNUM(26)
DEFINE_UNUSED_OPNUM(27)
DEFINE_UNUSED_OPNUM(28)
DEFINE_UNUSED_OPNUM(29)
DEFINE_UNUSED_OPNUM(30)
DEFINE_UNUSED_OPNUM(31)
DEFINE_UNUSED_OPNUM(32)
DEFINE_UNUSED_OPNUM(33)
DEFINE_UNUSED_OPNUM(34)
DEFINE_UNUSED_OPNUM(35)
DEFINE_UNUSED_OPNUM(36)
DEFINE_UNUSED_OPNUM(37)
DEFINE_UNUSED_OPNUM(38)
DEFINE_UNUSED_OPNUM(39)
DEFINE_UNUSED_OPNUM(40)
DEFINE_UNUSED_OPNUM(41)
DEFINE_UNUSED_OPNUM(42)
DEFINE_UNUSED_OPNUM(43)
DEFINE_UNUSED_OPNUM(44)
DEFINE_UNUSED_OPNUM(45)
DEFINE_UNUSED_OPNUM(46)
DEFINE_UNUSED_OPNUM(47)
DEFINE_UNUSED_OPNUM(48)
DEFINE_UNUSED_OPNUM(49)
DEFINE_UNUSED_OPNUM(50)
DEFINE_UNUSED_OPNUM(51)
DEFINE_UNUSED_OPNUM(52)
DEFINE_UNUSED_OPNUM(53)
DEFINE_UNUSED_OPNUM(54)
DEFINE_UNUSED_OPNUM(55)
DEFINE_UNUSED_OPNUM(56)
DEFINE_UNUSED_OPNUM(57)
DEFINE_UNUSED_OPNUM(58)
DEFINE_UNUSED_OPNUM(59)
DEFINE_UNUSED_OPNUM(60)
DEFINE_UNUSED_OPNUM(61)
DEFINE_UNUSED_OPNUM(63)
DEFINE_UNUSED_OPNUM(66)
DEFINE_UNUSED_OPNUM(67)
DEFINE_UNUSED_OPNUM(68)
DEFINE_UNUSED_OPNUM(69)
DEFINE_UNUSED_OPNUM(70)
