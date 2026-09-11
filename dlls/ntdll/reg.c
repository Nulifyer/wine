/*
 * Registry functions
 *
 * Copyright (C) 1999 Juergen Schmied
 * Copyright (C) 2000 Alexandre Julliard
 * Copyright 2005 Ivan Leo Puoti, Laurent Pinchart
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
 *
 * NOTES:
 * 	HKEY_LOCAL_MACHINE	\\REGISTRY\\MACHINE
 *	HKEY_USERS		\\REGISTRY\\USER
 *	HKEY_CURRENT_CONFIG	\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\HARDWARE PROFILES\\CURRENT
  *	HKEY_CLASSES		\\REGISTRY\\MACHINE\\SOFTWARE\\CLASSES
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "ntstatus.h"
#include "ntdll_misc.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(reg);


/******************************************************************************
 *  RtlpNtCreateKey [NTDLL.@]
 *
 *  See NtCreateKey.
 */
NTSTATUS WINAPI RtlpNtCreateKey( PHANDLE retkey, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                 ULONG TitleIndex, const UNICODE_STRING *class, ULONG options,
                                 PULONG dispos )
{
    OBJECT_ATTRIBUTES oa;

    if (attr)
    {
        oa = *attr;
        oa.Attributes &= ~(OBJ_PERMANENT|OBJ_EXCLUSIVE);
        attr = &oa;
    }

    return NtCreateKey(retkey, access, attr, 0, NULL, 0, dispos);
}

/******************************************************************************
 * RtlpNtOpenKey [NTDLL.@]
 *
 * See NtOpenKey.
 */
NTSTATUS WINAPI RtlpNtOpenKey( PHANDLE retkey, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr )
{
    if (attr)
        attr->Attributes &= ~(OBJ_PERMANENT|OBJ_EXCLUSIVE);
    return NtOpenKey(retkey, access, attr);
}

/******************************************************************************
 * RtlpNtMakeTemporaryKey [NTDLL.@]
 *
 *  See NtDeleteKey.
 */
NTSTATUS WINAPI RtlpNtMakeTemporaryKey( HANDLE hkey )
{
    return NtDeleteKey(hkey);
}

/******************************************************************************
 * RtlpNtEnumerateSubKey [NTDLL.@]
 *
 */
NTSTATUS WINAPI RtlpNtEnumerateSubKey( HANDLE handle, UNICODE_STRING *out, ULONG index )
{
  KEY_BASIC_INFORMATION *info;
  DWORD dwLen, dwResultLen;
  NTSTATUS ret;

  if (out->MaximumLength)
  {
    dwLen = out->MaximumLength + offsetof(KEY_BASIC_INFORMATION, Name);
    info = RtlAllocateHeap( GetProcessHeap(), 0, dwLen );
    if (!info)
      return STATUS_NO_MEMORY;
  }
  else
  {
    dwLen = 0;
    info = NULL;
  }

  ret = NtEnumerateKey( handle, index, KeyBasicInformation, info, dwLen, &dwResultLen );
  dwResultLen -= offsetof(KEY_BASIC_INFORMATION, Name);

  if (ret == STATUS_BUFFER_OVERFLOW)
    out->Length = dwResultLen;
  else if (!ret)
  {
    if (out->MaximumLength < info->NameLength)
    {
      out->Length = dwResultLen;
      ret = STATUS_BUFFER_OVERFLOW;
    }
    else
    {
      out->Length = info->NameLength;
      memcpy(out->Buffer, info->Name, info->NameLength);
    }
  }

  RtlFreeHeap( GetProcessHeap(), 0, info );
  return ret;
}

/******************************************************************************
 * RtlpNtQueryValueKey [NTDLL.@]
 *
 */
NTSTATUS WINAPI RtlpNtQueryValueKey( HANDLE handle, ULONG *result_type, PBYTE dest,
                                     DWORD *result_len, void *unknown )
{
    KEY_VALUE_PARTIAL_INFORMATION *info;
    UNICODE_STRING name;
    NTSTATUS ret;
    DWORD dwResultLen;
    DWORD dwLen = offsetof(KEY_VALUE_PARTIAL_INFORMATION, Data[result_len ? *result_len : 0]);

    info = RtlAllocateHeap( GetProcessHeap(), 0, dwLen );
    if (!info)
      return STATUS_NO_MEMORY;

    name.Length = 0;
    ret = NtQueryValueKey( handle, &name, KeyValuePartialInformation, info, dwLen, &dwResultLen );

    if (!ret || ret == STATUS_BUFFER_OVERFLOW)
    {
        if (result_len)
            *result_len = info->DataLength;

        if (result_type)
            *result_type = info->Type;

        if (ret != STATUS_BUFFER_OVERFLOW)
            memcpy( dest, info->Data, info->DataLength );
    }

    RtlFreeHeap( GetProcessHeap(), 0, info );
    return ret;
}

/******************************************************************************
 * RtlpNtSetValueKey [NTDLL.@]
 *
 */
NTSTATUS WINAPI RtlpNtSetValueKey( HANDLE hkey, ULONG type, const void *data,
                                   ULONG count )
{
    UNICODE_STRING name;

    name.Length = 0;
    return NtSetValueKey( hkey, &name, 0, type, data, count );
}

/*
 * The RXACT implementation is based on the ReactOS sdk/lib/rtl/rxact.c
 * implementation and was also compared with Windows 11 ntdll.
 *
 * Copyright 2014 Timo Kreuzer <timo.kreuzer@reactos.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#define RXACT_DEFAULT_BUFFER_SIZE (4 * 4096)

struct rxact_info
{
    ULONG revision;
    ULONG unknown1;
    ULONG unknown2;
};

struct rxact_data
{
    ULONG action_count;
    ULONG buffer_size;
    ULONG current_size;
};

struct rxact_context
{
    HANDLE root;
    HANDLE key;
    BOOLEAN can_use_handles;
    struct rxact_data *data;
};

struct rxact_action
{
    ULONG size;
    ULONG type;
    UNICODE_STRING key_name;
    UNICODE_STRING value_name;
    HANDLE key;
    ULONG value_type;
    ULONG value_data_size;
    void *value_data;
};

enum rxact_action_type
{
    RXACT_DELETE_KEY = 1,
    RXACT_SET_VALUE = 2,
};

static ULONG rxact_align( ULONG size, ULONG alignment )
{
    return (size + alignment - 1) & ~(alignment - 1);
}

static void rxact_init_context( struct rxact_context *context, HANDLE root, HANDLE key )
{
    context->root = root;
    context->key = key;
    context->can_use_handles = TRUE;
    context->data = NULL;
}

static NTSTATUS rxact_open_target_key( HANDLE root, ULONG action_type,
                                       const UNICODE_STRING *name, HANDLE *key )
{
    OBJECT_ATTRIBUTES attr;

    if (action_type == RXACT_DELETE_KEY)
    {
        InitializeObjectAttributes( &attr, (UNICODE_STRING *)name, OBJ_CASE_INSENSITIVE, root, NULL );
        return NtOpenKey( key, DELETE, &attr );
    }
    if (action_type == RXACT_SET_VALUE)
    {
        InitializeObjectAttributes( &attr, (UNICODE_STRING *)name,
                                    OBJ_CASE_INSENSITIVE | OBJ_OPENIF, root, NULL );
        return NtCreateKey( key, KEY_WRITE, &attr, 0, NULL, 0, NULL );
    }
    return STATUS_INVALID_PARAMETER;
}

static NTSTATUS rxact_commit( struct rxact_context *context )
{
    struct rxact_data *data = context->data;
    struct rxact_action *action;
    NTSTATUS status;
    HANDLE key;
    ULONG i;

    action = (struct rxact_action *)((BYTE *)data + rxact_align( sizeof(*data), sizeof(void *) ));
    for (i = 0; i < data->action_count; ++i)
    {
        action->key_name.Buffer = (WCHAR *)((BYTE *)data + (ULONG_PTR)action->key_name.Buffer);
        action->value_name.Buffer = (WCHAR *)((BYTE *)data + (ULONG_PTR)action->value_name.Buffer);
        action->value_data = (BYTE *)data + (ULONG_PTR)action->value_data;

        if (action->type == RXACT_DELETE_KEY)
        {
            if (action->key != INVALID_HANDLE_VALUE && context->can_use_handles)
                status = NtDeleteKey( action->key );
            else
            {
                status = rxact_open_target_key( context->root, RXACT_DELETE_KEY,
                                                &action->key_name, &key );
                if (!status)
                {
                    status = NtDeleteKey( key );
                    NtClose( key );
                }
                else if (status == STATUS_OBJECT_NAME_NOT_FOUND)
                    status = STATUS_SUCCESS;
            }
        }
        else if (action->type == RXACT_SET_VALUE)
        {
            if (action->key != INVALID_HANDLE_VALUE && context->can_use_handles)
                status = NtSetValueKey( action->key, &action->value_name, 0, action->value_type,
                                        action->value_data, action->value_data_size );
            else
            {
                status = rxact_open_target_key( context->root, RXACT_SET_VALUE,
                                                &action->key_name, &key );
                if (!status)
                {
                    status = NtSetValueKey( key, &action->value_name, 0, action->value_type,
                                            action->value_data, action->value_data_size );
                    NtClose( key );
                }
            }
        }
        else
            return STATUS_INVALID_PARAMETER;

        if (status) return status;
        action = (struct rxact_action *)((BYTE *)action + action->size);
    }
    return STATUS_SUCCESS;
}

/******************************************************************************
 * RtlStartRXact [NTDLL.@]
 */
NTSTATUS WINAPI RtlStartRXact( struct rxact_context *context )
{
    struct rxact_data *data;

    if (context->data) return STATUS_RXACT_INVALID_STATE;
    if (!(data = RtlAllocateHeap( GetProcessHeap(), 0, RXACT_DEFAULT_BUFFER_SIZE )))
        return STATUS_NO_MEMORY;

    data->action_count = 0;
    data->buffer_size = RXACT_DEFAULT_BUFFER_SIZE;
    data->current_size = rxact_align( sizeof(*data), sizeof(void *) );
    context->data = data;
    return STATUS_SUCCESS;
}

/******************************************************************************
 * RtlAbortRXact [NTDLL.@]
 */
NTSTATUS WINAPI RtlAbortRXact( struct rxact_context *context )
{
    if (!context->data) return STATUS_RXACT_INVALID_STATE;
    RtlFreeHeap( GetProcessHeap(), 0, context->data );
    context->data = NULL;
    context->can_use_handles = TRUE;
    return STATUS_SUCCESS;
}

/******************************************************************************
 * RtlInitializeRXact [NTDLL.@]
 */
NTSTATUS WINAPI RtlInitializeRXact( HANDLE root, BOOLEAN commit,
                                    struct rxact_context **out_context )
{
    KEY_VALUE_FULL_INFORMATION *value_info;
    BYTE basic_info[128];
    struct rxact_context *context;
    struct rxact_info info;
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING name;
    ULONG disposition, type, data_size, size;
    HANDLE key;
    NTSTATUS status;

    RtlInitUnicodeString( &name, L"RXACT" );
    InitializeObjectAttributes( &attr, &name, OBJ_CASE_INSENSITIVE | OBJ_OPENIF, root, NULL );
    status = NtCreateKey( &key, KEY_READ | KEY_WRITE | DELETE, &attr, 0, NULL, 0, &disposition );
    if (status) return status;

    if (!(context = RtlAllocateHeap( GetProcessHeap(), 0, sizeof(*context) )))
    {
        NtDeleteKey( key );
        NtClose( key );
        return STATUS_NO_MEMORY;
    }
    *out_context = context;
    rxact_init_context( context, root, key );

    if (disposition == REG_CREATED_NEW_KEY)
    {
        memset( &info, 0, sizeof(info) );
        info.revision = 1;
        RtlInitUnicodeString( &name, NULL );
        status = NtSetValueKey( key, &name, 0, REG_NONE, &info, sizeof(info) );
        if (!status) return STATUS_RXACT_STATE_CREATED;

        NtDeleteKey( key );
        NtClose( key );
        RtlFreeHeap( GetProcessHeap(), 0, context );
        return status;
    }

    data_size = sizeof(info);
    status = RtlpNtQueryValueKey( key, &type, (BYTE *)&info, &data_size, NULL );
    if (status)
    {
        NtClose( key );
        RtlFreeHeap( GetProcessHeap(), 0, context );
        return status;
    }
    if (data_size != sizeof(info) || info.revision != 1)
    {
        NtClose( key );
        RtlFreeHeap( GetProcessHeap(), 0, context );
        return STATUS_UNKNOWN_REVISION;
    }

    RtlInitUnicodeString( &name, L"Log" );
    status = NtQueryValueKey( key, &name, KeyValueBasicInformation,
                              &basic_info, sizeof(basic_info), &size );
    if (status) return STATUS_SUCCESS;
    if (!commit) return STATUS_RXACT_COMMIT_NECESSARY;

    status = NtQueryValueKey( key, &name, KeyValueFullInformation, NULL, 0, &size );
    if (status != STATUS_BUFFER_TOO_SMALL) return status;
    if (!(value_info = RtlAllocateHeap( GetProcessHeap(), 0, size ))) return STATUS_NO_MEMORY;

    status = NtQueryValueKey( key, &name, KeyValueFullInformation, value_info, size, &size );
    if (status)
    {
        RtlFreeHeap( GetProcessHeap(), 0, value_info );
        NtClose( key );
        RtlFreeHeap( GetProcessHeap(), 0, context );
        return status;
    }

    context->data = (struct rxact_data *)((BYTE *)value_info + value_info->DataOffset);
    context->can_use_handles = FALSE;
    status = rxact_commit( context );
    if (status)
    {
        RtlFreeHeap( GetProcessHeap(), 0, value_info );
        NtClose( key );
        RtlFreeHeap( GetProcessHeap(), 0, context );
        return status;
    }

    NtDeleteValueKey( key, &name );
    context->data = (struct rxact_data *)value_info;
    RtlAbortRXact( context );
    return STATUS_SUCCESS;
}

/******************************************************************************
 * RtlAddAttributeActionToRXact [NTDLL.@]
 */
NTSTATUS WINAPI RtlAddAttributeActionToRXact( struct rxact_context *context, ULONG type,
                                              const UNICODE_STRING *key_name, HANDLE key,
                                              const UNICODE_STRING *value_name, ULONG value_type,
                                              const void *value_data, ULONG value_data_size )
{
    struct rxact_action *action;
    struct rxact_data *new_data;
    ULONG action_size, required_size, buffer_size, offset;

    if (type != RXACT_DELETE_KEY && type != RXACT_SET_VALUE) return STATUS_INVALID_PARAMETER;

    action_size = rxact_align( sizeof(*action) + rxact_align( key_name->Length, sizeof(ULONG) ) +
                               rxact_align( value_name->Length, sizeof(ULONG) ) +
                               rxact_align( value_data_size, sizeof(ULONG) ), sizeof(void *) );
    required_size = context->data->current_size + action_size;
    if (required_size < action_size) return STATUS_NO_MEMORY;

    buffer_size = context->data->buffer_size;
    if (required_size > buffer_size)
    {
        while (buffer_size < required_size) buffer_size *= 2;
        if (!(new_data = RtlAllocateHeap( GetProcessHeap(), 0, buffer_size )))
            return STATUS_NO_MEMORY;
        memcpy( new_data, context->data, context->data->current_size );
        RtlFreeHeap( GetProcessHeap(), 0, context->data );
        context->data = new_data;
        new_data->buffer_size = buffer_size;
    }

    action = (struct rxact_action *)((BYTE *)context->data + context->data->current_size);
    action->size = action_size;
    action->type = type;
    action->key_name = *key_name;
    action->value_name = *value_name;
    action->key = key;
    action->value_type = value_type;
    action->value_data_size = value_data_size;
    action->value_data = NULL;

    offset = context->data->current_size + sizeof(*action);
    action->key_name.Buffer = (WCHAR *)(ULONG_PTR)offset;
    if (key_name->Length)
        memcpy( (BYTE *)context->data + offset, key_name->Buffer, key_name->Length );
    offset += rxact_align( key_name->Length, sizeof(ULONG) );

    action->value_name.Buffer = (WCHAR *)(ULONG_PTR)offset;
    if (value_name->Length)
        memcpy( (BYTE *)context->data + offset, value_name->Buffer, value_name->Length );
    offset += rxact_align( value_name->Length, sizeof(ULONG) );

    if (type == RXACT_SET_VALUE)
    {
        action->value_data = (void *)(ULONG_PTR)offset;
        if (value_data_size)
            memcpy( (BYTE *)context->data + offset, value_data, value_data_size );
        offset += rxact_align( value_data_size, sizeof(ULONG) );
    }

    context->data->current_size = rxact_align( offset, sizeof(void *) );
    context->data->action_count++;
    return STATUS_SUCCESS;
}

/******************************************************************************
 * RtlAddActionToRXact [NTDLL.@]
 */
NTSTATUS WINAPI RtlAddActionToRXact( struct rxact_context *context, ULONG type,
                                     const UNICODE_STRING *key_name, ULONG value_type,
                                     const void *value_data, ULONG value_data_size )
{
    UNICODE_STRING value_name;

    RtlInitUnicodeString( &value_name, NULL );
    return RtlAddAttributeActionToRXact( context, type, key_name, INVALID_HANDLE_VALUE,
                                        &value_name, value_type, value_data, value_data_size );
}

/******************************************************************************
 * RtlApplyRXactNoFlush [NTDLL.@]
 */
NTSTATUS WINAPI RtlApplyRXactNoFlush( struct rxact_context *context )
{
    NTSTATUS status;

    if (!(status = rxact_commit( context ))) status = RtlAbortRXact( context );
    return status;
}

/******************************************************************************
 * RtlApplyRXact [NTDLL.@]
 */
NTSTATUS WINAPI RtlApplyRXact( struct rxact_context *context )
{
    UNICODE_STRING name;
    NTSTATUS status;

    RtlInitUnicodeString( &name, L"Log" );
    status = NtSetValueKey( context->key, &name, 0, REG_BINARY,
                            context->data, context->data->current_size );
    if (status) return status;

    status = NtFlushKey( context->key );
    if (status)
    {
        NtDeleteValueKey( context->key, &name );
        return status;
    }

    status = rxact_commit( context );
    if (status)
    {
        NtDeleteValueKey( context->key, &name );
        return status;
    }

    NtDeleteValueKey( context->key, &name );
    RtlAbortRXact( context );
    return STATUS_SUCCESS;
}

/******************************************************************************
 *  RtlFormatCurrentUserKeyPath		[NTDLL.@]
 *
 */
NTSTATUS WINAPI RtlFormatCurrentUserKeyPath( IN OUT PUNICODE_STRING KeyPath)
{
    static const WCHAR pathW[] = {'\\','R','e','g','i','s','t','r','y','\\','U','s','e','r','\\'};
    char buffer[sizeof(TOKEN_USER) + sizeof(SID) + sizeof(DWORD)*SID_MAX_SUB_AUTHORITIES];
    DWORD len = sizeof(buffer);
    NTSTATUS status;

    status = NtQueryInformationToken(GetCurrentThreadEffectiveToken(), TokenUser, buffer, len, &len);
    if (status == STATUS_SUCCESS)
    {
        KeyPath->MaximumLength = 0;
        status = RtlConvertSidToUnicodeString(KeyPath, ((TOKEN_USER *)buffer)->User.Sid, FALSE);
        if (status == STATUS_BUFFER_OVERFLOW)
        {
            PWCHAR buf = RtlAllocateHeap(GetProcessHeap(), 0,
                                         sizeof(pathW) + KeyPath->Length + sizeof(WCHAR));
            if (buf)
            {
                memcpy(buf, pathW, sizeof(pathW));
                KeyPath->MaximumLength = KeyPath->Length + sizeof(WCHAR);
                KeyPath->Buffer = (PWCHAR)((LPBYTE)buf + sizeof(pathW));
                status = RtlConvertSidToUnicodeString(KeyPath,
                                                      ((TOKEN_USER *)buffer)->User.Sid, FALSE);
                KeyPath->Buffer = buf;
                KeyPath->Length += sizeof(pathW);
                KeyPath->MaximumLength += sizeof(pathW);
            }
            else
                status = STATUS_NO_MEMORY;
        }
    }
    return status;
}

/******************************************************************************
 *  RtlOpenCurrentUser		[NTDLL.@]
 *
 * NOTES
 *  If we return just HKEY_CURRENT_USER the advapi tries to find a remote
 *  registry (odd handle) and fails.
 */
NTSTATUS WINAPI RtlOpenCurrentUser(
	IN ACCESS_MASK DesiredAccess, /* [in] */
	OUT PHANDLE KeyHandle)	      /* [out] handle of HKEY_CURRENT_USER */
{
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING ObjectName;
	NTSTATUS ret;

	TRACE("(0x%08lx, %p)\n",DesiredAccess, KeyHandle);

        if ((ret = RtlFormatCurrentUserKeyPath(&ObjectName))) return ret;
	InitializeObjectAttributes(&ObjectAttributes,&ObjectName,OBJ_CASE_INSENSITIVE,0, NULL);
	ret = NtCreateKey(KeyHandle, DesiredAccess, &ObjectAttributes, 0, NULL, 0, NULL);
	RtlFreeUnicodeString(&ObjectName);
	return ret;
}


static NTSTATUS RTL_DeliverRegistryValue(PKEY_VALUE_FULL_INFORMATION pInfo,
                                        PRTL_QUERY_REGISTRY_TABLE pQuery, PVOID pContext, PVOID pEnvironment)
{
    PUNICODE_STRING str = pQuery->EntryContext;
    ULONG type, len, offset, count, res;
    UNICODE_STRING src, dst;
    WCHAR *data, *wstr;
    LONG *bin;
    NTSTATUS status = STATUS_SUCCESS;

    if (pInfo)
    {
        type = pInfo->Type;
        data = (WCHAR*)((char*)pInfo + pInfo->DataOffset);
        len = pInfo->DataLength;

        /* Ensure that multi-strings from the registry are double-null-terminated */
        if (type == REG_MULTI_SZ)
        {
            while (len < 2 * sizeof(WCHAR) || data[len / sizeof(WCHAR) - 2] || data[len / sizeof(WCHAR) - 1])
            {
                data[len / sizeof(WCHAR)] = 0;
                len += sizeof(WCHAR);
            }
        }
    }
    else
    {
        type = pQuery->DefaultType;
        data = pQuery->DefaultData;
        len = pQuery->DefaultLength;

        if (type == REG_NONE)
            return STATUS_SUCCESS;

        /* Zero-length DWORD defaults carry the value in DefaultData itself. */
        if (!data && !(type == REG_DWORD && !len))
            return STATUS_DATA_OVERRUN;

        if (!len)
        {
            switch (type)
            {
            case REG_SZ:
            case REG_EXPAND_SZ:
            case REG_LINK:
                len = (wcslen(data) + 1) * sizeof(WCHAR);
                break;

            case REG_MULTI_SZ:
                wstr = data;
                for (;;)
                {
                    count = wcslen(wstr) + 1;
                    len += count * sizeof(WCHAR);
                    if (!*wstr) break;
                    wstr += count;
                }
                break;
            }
        }
    }

    if (pQuery->Flags & RTL_QUERY_REGISTRY_DIRECT)
    {
        if (pQuery->QueryRoutine)
            return STATUS_INVALID_PARAMETER;

        switch (type)
        {
        case REG_EXPAND_SZ:
            if (!(pQuery->Flags & RTL_QUERY_REGISTRY_NOEXPAND))
            {
                RtlInitUnicodeString(&src, data);
                res = 0;
                dst.MaximumLength = 0;
                RtlExpandEnvironmentStrings_U(pEnvironment, &src, &dst, &res);
                if (str->Buffer == NULL)
                {
                    str->Buffer = RtlAllocateHeap(GetProcessHeap(), 0, res);
                    str->MaximumLength = res;
                }
                else if (str->MaximumLength < res)
                    return STATUS_BUFFER_TOO_SMALL;
                RtlExpandEnvironmentStrings_U(pEnvironment, &src, str, &res);
                str->Length = (res >= sizeof(WCHAR) ? res - sizeof(WCHAR) : res);
                break;
            }
            /* fallthrough */

        case REG_SZ:
        case REG_LINK:
            if (str->Buffer == NULL)
                RtlCreateUnicodeString(str, data);
            else
            {
                if (str->MaximumLength < len)
                    return STATUS_BUFFER_TOO_SMALL;
                memcpy(str->Buffer, data, len);
                str->Length = len - sizeof(WCHAR);
            }
            break;

        case REG_MULTI_SZ:
            if (!(pQuery->Flags & RTL_QUERY_REGISTRY_NOEXPAND))
                return STATUS_INVALID_PARAMETER;

            if (str->Buffer == NULL)
            {
                str->Buffer = RtlAllocateHeap(GetProcessHeap(), 0, len);
                str->MaximumLength = len;
            }
            else if (str->MaximumLength < len)
                return STATUS_BUFFER_TOO_SMALL;
            memcpy(str->Buffer, data, len);
            str->Length = (len >= sizeof(WCHAR) ? len - sizeof(WCHAR) : len);
            break;

        default:
            bin = pQuery->EntryContext;
            if (len <= sizeof(ULONG))
                memcpy(bin, data, len);
            else
            {
                if (bin[0] < 0)
                {
                    if (len <= -bin[0])
                        memcpy(bin, data, len);
                }
                else if (len <= bin[0])
                {
                    bin[0] = len;
                    bin[1] = type;
                    memcpy(bin + 2, data, len);
                }
            }
            break;
        }
    }
    else if (pQuery->QueryRoutine)
    {
        if((pQuery->Flags & RTL_QUERY_REGISTRY_NOEXPAND) ||
           (type != REG_EXPAND_SZ && type != REG_MULTI_SZ))
        {
            status = pQuery->QueryRoutine(pQuery->Name, type, data, len, pContext, pQuery->EntryContext);
        }
        else if (type == REG_EXPAND_SZ)
        {
            RtlInitUnicodeString(&src, data);
            res = 0;
            dst.MaximumLength = 0;
            RtlExpandEnvironmentStrings_U(pEnvironment, &src, &dst, &res);
            dst.Length = 0;
            dst.MaximumLength = res;
            dst.Buffer = RtlAllocateHeap(GetProcessHeap(), 0, res * sizeof(WCHAR));
            RtlExpandEnvironmentStrings_U(pEnvironment, &src, &dst, &res);
            status = pQuery->QueryRoutine(pQuery->Name, REG_SZ, dst.Buffer, res, pContext, pQuery->EntryContext);
            RtlFreeHeap(GetProcessHeap(), 0, dst.Buffer);
        }
        else /* REG_MULTI_SZ */
        {
            for (offset = 0; offset + 2 * sizeof(WCHAR) < len; offset += count)
            {
                wstr = (WCHAR*)((char*)data + offset);
                count = (wcslen(wstr) + 1) * sizeof(WCHAR);
                status = pQuery->QueryRoutine(pQuery->Name, REG_SZ, wstr, count, pContext, pQuery->EntryContext);
                if (status != STATUS_SUCCESS && status != STATUS_BUFFER_TOO_SMALL)
                    return status;
            }
        }
    }
    return status;
}


static NTSTATUS RTL_ReportRegistryValue(PKEY_VALUE_FULL_INFORMATION info,
                                        PRTL_QUERY_REGISTRY_TABLE query, PVOID context, PVOID environment)
{
    RTL_QUERY_REGISTRY_TABLE named_query;
    NTSTATUS status;
    WCHAR *name;

    if (!info) return RTL_DeliverRegistryValue(info, query, context, environment);
    if (!(name = RtlAllocateHeap(GetProcessHeap(), 0, (SIZE_T)info->NameLength + sizeof(WCHAR))))
        return STATUS_NO_MEMORY;
    memcpy(name, info->Name, info->NameLength);
    name[info->NameLength / sizeof(WCHAR)] = 0;
    named_query = *query;
    named_query.Name = name;
    status = RTL_DeliverRegistryValue(info, &named_query, context, environment);
    RtlFreeHeap(GetProcessHeap(), 0, name);
    return status;
}

static NTSTATUS RTL_KeyHandleCreateObject(ULONG RelativeTo, PCWSTR Path, POBJECT_ATTRIBUTES regkey, PUNICODE_STRING str)
{
    PCWSTR base;
    INT len;

    switch (RelativeTo & 0xff)
    {
    case RTL_REGISTRY_ABSOLUTE:
        base = L"";
        break;

    case RTL_REGISTRY_CONTROL:
        base = L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\";
        break;

    case RTL_REGISTRY_DEVICEMAP:
        base = L"\\Registry\\Machine\\Hardware\\DeviceMap\\";
        break;

    case RTL_REGISTRY_SERVICES:
        base = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
        break;

    case RTL_REGISTRY_USER:
        base = L"\\Registry\\User\\CurrentUser\\";
        break;

    case RTL_REGISTRY_WINDOWS_NT:
        base = L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\";
        break;

    default:
        return STATUS_INVALID_PARAMETER;
    }

    len = (wcslen(base) + wcslen(Path) + 1) * sizeof(WCHAR);
    str->Buffer = RtlAllocateHeap(GetProcessHeap(), 0, len);
    if (str->Buffer == NULL)
        return STATUS_NO_MEMORY;

    wcscpy(str->Buffer, base);
    wcscat(str->Buffer, Path);
    str->Length = len - sizeof(WCHAR);
    str->MaximumLength = len;
    InitializeObjectAttributes(regkey, str, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return STATUS_SUCCESS;
}

static NTSTATUS RTL_GetKeyHandle(ULONG RelativeTo, PCWSTR Path, PHANDLE handle)
{
    OBJECT_ATTRIBUTES regkey;
    UNICODE_STRING string;
    NTSTATUS status;

    status = RTL_KeyHandleCreateObject(RelativeTo, Path, &regkey, &string);
    if(status != STATUS_SUCCESS)
	return status;

    status = NtOpenKey(handle, KEY_ALL_ACCESS, &regkey);
    RtlFreeUnicodeString( &string );
    return status;
}

/******************************************************************************
 *              RtlQueryRegistryValues  (NTDLL.@)
 *              RtlQueryRegistryValuesEx  (NTDLL.@)
 */
NTSTATUS WINAPI RtlQueryRegistryValues(IN ULONG RelativeTo, IN PCWSTR Path,
                                       IN PRTL_QUERY_REGISTRY_TABLE QueryTable, IN PVOID Context,
                                       IN PVOID Environment OPTIONAL)
{
    UNICODE_STRING Value;
    HANDLE handle, topkey;
    PKEY_VALUE_FULL_INFORMATION pInfo = NULL;
    ULONG len, buflen = 0;
    NTSTATUS status=STATUS_SUCCESS, ret = STATUS_SUCCESS;
    INT i;

    TRACE("(%ld, %s, %p, %p, %p)\n", RelativeTo, debugstr_w(Path), QueryTable, Context, Environment);

    if(Path == NULL)
        return STATUS_INVALID_PARAMETER;

    /* get a valid handle */
    if (RelativeTo & RTL_REGISTRY_HANDLE)
        topkey = handle = (HANDLE)Path;
    else
    {
        status = RTL_GetKeyHandle(RelativeTo, Path, &topkey);
        if (status != STATUS_SUCCESS) return status;
        handle = topkey;
    }

    /* Process query table entries */
    for (; QueryTable->QueryRoutine != NULL || QueryTable->Name != NULL; ++QueryTable)
    {
        if (QueryTable->Flags &
            (RTL_QUERY_REGISTRY_SUBKEY | RTL_QUERY_REGISTRY_TOPKEY))
        {
            /* topkey must be kept open just in case we will reuse it later */
            if (handle != topkey)
                NtClose(handle);

            if (QueryTable->Flags & RTL_QUERY_REGISTRY_SUBKEY)
            {
                OBJECT_ATTRIBUTES attr;

                handle = 0;
                RtlInitUnicodeString(&Value, QueryTable->Name);
                InitializeObjectAttributes(&attr, &Value, OBJ_CASE_INSENSITIVE, topkey, NULL);
                status = NtOpenKey(&handle, KEY_ALL_ACCESS, &attr);
                if(status != STATUS_SUCCESS)
                {
                    ret = status;
                    goto out;
                }
            }
            else
                handle = topkey;

            if (!QueryTable->QueryRoutine) continue;
        }

        if (!QueryTable->Name && (QueryTable->Flags & RTL_QUERY_REGISTRY_NOVALUE))
        {
            QueryTable->QueryRoutine(QueryTable->Name, REG_NONE, NULL, 0,
                Context, QueryTable->EntryContext);
            continue;
        }

        if (!handle)
        {
            if (QueryTable->Flags & RTL_QUERY_REGISTRY_REQUIRED)
            {
                ret = STATUS_OBJECT_NAME_NOT_FOUND;
                goto out;
            }
            continue;
        }

        if (QueryTable->Name == NULL || (QueryTable->Flags & RTL_QUERY_REGISTRY_SUBKEY))
        {
            if (QueryTable->Flags & RTL_QUERY_REGISTRY_DIRECT)
            {
                ret = STATUS_INVALID_PARAMETER;
                goto out;
            }

            /* Report all subkeys */
            for (i = 0;; ++i)
            {
                status = NtEnumerateValueKey(handle, i,
                    KeyValueFullInformation, pInfo, buflen, &len);
                if (status == STATUS_NO_MORE_ENTRIES)
                    break;
                if (status == STATUS_BUFFER_OVERFLOW ||
                    status == STATUS_BUFFER_TOO_SMALL ||
                    (status == STATUS_SUCCESS && pInfo->Type == REG_MULTI_SZ && buflen < len + 2 * sizeof(L'\0')))
                {
                    buflen = len + 2 * sizeof(L'\0');
                    RtlFreeHeap(GetProcessHeap(), 0, pInfo);
                    pInfo = RtlAllocateHeap(GetProcessHeap(), 0, buflen);
                    NtEnumerateValueKey(handle, i, KeyValueFullInformation,
                        pInfo, buflen, &len);
                }

                status = RTL_ReportRegistryValue(pInfo, QueryTable, Context, Environment);
                if(status != STATUS_SUCCESS && status != STATUS_BUFFER_TOO_SMALL)
                {
                    ret = status;
                    goto out;
                }
                if (QueryTable->Flags & RTL_QUERY_REGISTRY_DELETE)
                {
                    RtlInitUnicodeString(&Value, pInfo->Name);
                    NtDeleteValueKey(handle, &Value);
                }
            }

            if (i == 0  && (QueryTable->Flags & RTL_QUERY_REGISTRY_REQUIRED))
            {
                ret = STATUS_OBJECT_NAME_NOT_FOUND;
                goto out;
            }
        }
        else
        {
            RtlInitUnicodeString(&Value, QueryTable->Name);
            status = NtQueryValueKey(handle, &Value, KeyValueFullInformation,
                pInfo, buflen, &len);
            if (status == STATUS_BUFFER_OVERFLOW ||
                status == STATUS_BUFFER_TOO_SMALL ||
                (status == STATUS_SUCCESS && pInfo->Type == REG_MULTI_SZ && buflen < len + 2 * sizeof(L'\0')))
            {
                buflen = len + 2 * sizeof(L'\0');
                RtlFreeHeap(GetProcessHeap(), 0, pInfo);
                pInfo = RtlAllocateHeap(GetProcessHeap(), 0, buflen);
                status = NtQueryValueKey(handle, &Value,
                    KeyValueFullInformation, pInfo, buflen, &len);
            }
            if (status != STATUS_SUCCESS)
            {
                if ((QueryTable->Flags & RTL_QUERY_REGISTRY_REQUIRED) &&
                    QueryTable->DefaultType == REG_NONE)
                {
                    ret = STATUS_OBJECT_NAME_NOT_FOUND;
                    goto out;
                }
                status = RTL_ReportRegistryValue(NULL, QueryTable, Context, Environment);
                if(status != STATUS_SUCCESS && status != STATUS_BUFFER_TOO_SMALL)
                {
                    ret = status;
                    goto out;
                }
            }
            else
            {
                status = RTL_ReportRegistryValue(pInfo, QueryTable, Context, Environment);
                if(status != STATUS_SUCCESS && status != STATUS_BUFFER_TOO_SMALL)
                {
                    ret = status;
                    goto out;
                }
                if (QueryTable->Flags & RTL_QUERY_REGISTRY_DELETE)
                    NtDeleteValueKey(handle, &Value);
            }
        }
    }

out:
    RtlFreeHeap(GetProcessHeap(), 0, pInfo);
    if (handle != topkey)
        NtClose(handle);
    if (!(RelativeTo & RTL_REGISTRY_HANDLE)) NtClose(topkey);
    return ret;
}

/*************************************************************************
 * RtlCheckRegistryKey   [NTDLL.@]
 *
 * Query multiple registry values with a single call.
 *
 * PARAMS
 *  RelativeTo [I] Registry path that Path refers to
 *  Path       [I] Path to key
 *
 * RETURNS
 *  STATUS_SUCCESS if the specified key exists, or an NTSTATUS error code.
 */
NTSTATUS WINAPI RtlCheckRegistryKey(IN ULONG RelativeTo, IN PWSTR Path)
{
    HANDLE handle;
    NTSTATUS status;

    TRACE("(%ld, %s)\n", RelativeTo, debugstr_w(Path));

    if(!RelativeTo && (Path == NULL || Path[0] == 0))
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    if(RelativeTo & RTL_REGISTRY_HANDLE)
        return STATUS_SUCCESS;
    if((RelativeTo <= RTL_REGISTRY_USER) && (Path == NULL || Path[0] == 0))
        return STATUS_SUCCESS;

    status = RTL_GetKeyHandle(RelativeTo, Path, &handle);
    if (!status) NtClose(handle);
    if (status == STATUS_INVALID_HANDLE) status = STATUS_OBJECT_NAME_NOT_FOUND;
    return status;
}

/*************************************************************************
 * RtlCreateRegistryKey   [NTDLL.@]
 *
 * Add a key to the registry given by absolute or relative path
 *
 * PARAMS
 *  RelativeTo  [I] Registry path that Path refers to
 *  path        [I] Path to key
 *
 * RETURNS
 *  STATUS_SUCCESS or an appropriate NTSTATUS error code.
 */
NTSTATUS WINAPI RtlCreateRegistryKey(ULONG RelativeTo, PWSTR path)
{
    OBJECT_ATTRIBUTES regkey;
    UNICODE_STRING string;
    HANDLE handle;
    NTSTATUS status;

    RelativeTo &= ~RTL_REGISTRY_OPTIONAL;

    if (!RelativeTo && (path == NULL || path[0] == 0))
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    if (RelativeTo <= RTL_REGISTRY_USER && (path == NULL || path[0] == 0))
        return STATUS_SUCCESS;
    status = RTL_KeyHandleCreateObject(RelativeTo, path, &regkey, &string);
    if(status != STATUS_SUCCESS)
	return status;

    status = NtCreateKey(&handle, KEY_ALL_ACCESS, &regkey, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (handle) NtClose(handle);
    RtlFreeUnicodeString( &string );
    return status;
}

/*************************************************************************
 * RtlDeleteRegistryValue   [NTDLL.@]
 *
 * Query multiple registry values with a single call.
 *
 * PARAMS
 *  RelativeTo [I] Registry path that Path refers to
 *  Path       [I] Path to key
 *  ValueName  [I] Name of the value to delete
 *
 * RETURNS
 *  STATUS_SUCCESS if the specified key is successfully deleted, or an NTSTATUS error code.
 */
NTSTATUS WINAPI RtlDeleteRegistryValue(IN ULONG RelativeTo, IN PCWSTR Path, IN PCWSTR ValueName)
{
    NTSTATUS status;
    HANDLE handle;
    UNICODE_STRING Value;

    TRACE("(%ld, %s, %s)\n", RelativeTo, debugstr_w(Path), debugstr_w(ValueName));

    RtlInitUnicodeString(&Value, ValueName);
    if(RelativeTo == RTL_REGISTRY_HANDLE)
    {
        return NtDeleteValueKey((HANDLE)Path, &Value);
    }
    status = RTL_GetKeyHandle(RelativeTo, Path, &handle);
    if (status) return status;
    status = NtDeleteValueKey(handle, &Value);
    NtClose(handle);
    return status;
}

/*************************************************************************
 * RtlWriteRegistryValue   [NTDLL.@]
 *
 * Sets the registry value with provided data.
 *
 * PARAMS
 *  RelativeTo [I] Registry path that path parameter refers to
 *  path       [I] Path to the key (or handle - see RTL_GetKeyHandle)
 *  name       [I] Name of the registry value to set
 *  type       [I] Type of the registry key to set
 *  data       [I] Pointer to the user data to be set
 *  length     [I] Length of the user data pointed by data
 *
 * RETURNS
 *  STATUS_SUCCESS if the specified key is successfully set,
 *  or an NTSTATUS error code.
 */
NTSTATUS WINAPI RtlWriteRegistryValue( ULONG RelativeTo, PCWSTR path, PCWSTR name,
                                       ULONG type, PVOID data, ULONG length )
{
    HANDLE hkey;
    NTSTATUS status;
    UNICODE_STRING str;

    TRACE( "(%ld, %s, %s) -> %ld: %p [%ld]\n", RelativeTo, debugstr_w(path), debugstr_w(name),
           type, data, length );

    RtlInitUnicodeString( &str, name );

    if (RelativeTo == RTL_REGISTRY_HANDLE)
        return NtSetValueKey( (HANDLE)path, &str, 0, type, data, length );

    status = RTL_GetKeyHandle( RelativeTo, path, &hkey );
    if (status != STATUS_SUCCESS) return status;

    status = NtSetValueKey( hkey, &str, 0, type, data, length );
    NtClose( hkey );

    return status;
}

/***********************************************************************
 *      RtlIsFeatureEnabledForEnterprise   (NTDLL.@)
 *
 * Enterprise temporary controls select a feature list and then consult
 * update policy. Missing or unreadable configuration leaves a feature enabled.
 * These are the ordinary machine roots; persisted-state redirection is not
 * implemented here.
 */
static NTSTATUS query_enterprise_dword( const WCHAR *path, const WCHAR *name, ULONG *value )
{
    struct
    {
        KEY_VALUE_PARTIAL_INFORMATION info;
        ULONG extra;
    } buffer;
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING key_name, value_name;
    HANDLE key;
    ULONG size;
    NTSTATUS status;

    RtlInitUnicodeString( &key_name, path );
    InitializeObjectAttributes( &attr, &key_name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    if ((status = NtOpenKey( &key, KEY_QUERY_VALUE, &attr ))) return status;
    RtlInitUnicodeString( &value_name, name );
    status = NtQueryValueKey( key, &value_name, KeyValuePartialInformation,
                             &buffer, sizeof(buffer), &size );
    NtClose( key );
    if (status) return status;
    if (buffer.info.Type != REG_DWORD || buffer.info.DataLength != sizeof(*value))
        return STATUS_OBJECT_TYPE_MISMATCH;
    memcpy( value, buffer.info.Data, sizeof(*value) );
    return STATUS_SUCCESS;
}

BOOLEAN WINAPI RtlIsFeatureEnabledForEnterprise( ULONG feature_id )
{
    static const WCHAR controls[] =
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\FeatureManagement\\EnterpriseTempControls";
    static const WCHAR active[] =
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\FeatureManagement\\EnterpriseTempControls\\Active";
    static const WCHAR primary_policy[] =
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\WindowsUpdate\\UpdatePolicy\\PolicyState";
    static const WCHAR mirrored_policy[] =
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\FeatureManagement\\Policies";
    UNICODE_STRING license_name = RTL_CONSTANT_STRING( L"UpdatePolicy-UpdateManagementGroup" );
    WCHAR path[160], name[16];
    ULONG config, value, hash, type, size;

    TRACE( "(%#lx)\n", feature_id );
    if (query_enterprise_dword( active, L"ActiveConfig", &config )) return TRUE;
    hash = RtlUlongByteSwap( feature_id ^ 0x74161a4e ) ^ 0x8fb23d4f;
    hash = ((hash << 1) | (hash >> 31)) ^ 0x833ea8ff;
    swprintf( path, ARRAY_SIZE(path), L"%s\\%lu", controls, config );
    swprintf( name, ARRAY_SIZE(name), L"%lu", hash );
    if (query_enterprise_dword( path, name, &value ) || !value) return TRUE;

    /* Native policy precedence, not alternative implementation selection. */
    if (!query_enterprise_dword( primary_policy, L"TemporaryEnterpriseFeatureControlState", &value ) ||
        !query_enterprise_dword( mirrored_policy, L"TemporaryEnterpriseFeatureControlState_Mirrored", &value ))
        return value == 1 || value == 2;

    if (!NtQueryLicenseValue( &license_name, &type, &value, sizeof(value), &size ) &&
        type == REG_DWORD && size == sizeof(value))
        return !value;
    return TRUE;
}
