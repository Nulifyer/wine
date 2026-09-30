/*
 * Copyright 2001, Ove Kåven, TransGaming Technologies Inc.
 * Copyright 2002 Greg Turner
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
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "windef.h"
#include "winbase.h"
#include "winnt.h"
#include "winternl.h"
#include "winreg.h"
#include "objbase.h"
#include "wtsapi32.h"
#include "irpcss.h"
#include "rpcss_private.h"

#include "wine/debug.h"
#include "wine/list.h"

WINE_DEFAULT_DEBUG_CHANNEL(rpcss);

struct class_client
{
    HANDLE process;
    HANDLE token;
    DWORD process_id;
    DWORD session_id;
    LUID authentication_id;
};

struct registered_class
{
    struct list entry;
    GUID clsid;
    unsigned int cookie;
    PMInterfacePointer object;
    struct class_client publisher;
    unsigned int single_use : 1;
};

static CRITICAL_SECTION registered_classes_cs = { NULL, -1, 0, 0, 0, 0 };
static struct list registered_classes = LIST_INIT(registered_classes);

/* Identity comes from the local RPC transport, not registration arguments or
 * the server thread's impersonation token. Keep the process object alive so
 * a recycled client PID cannot acquire ownership of an old registration. */
static HRESULT scm_get_client(handle_t binding, DWORD token_access, struct class_client *client)
{
    TOKEN_STATISTICS statistics;
    DWORD size;
    NTSTATUS status;
    HRESULT hr;

    status = I_RpcOpenClientProcess(binding, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, &client->process);
    if (status) return HRESULT_FROM_WIN32(RtlNtStatusToDosError(status));
    client->process_id = GetProcessId(client->process);
    if (!OpenProcessToken(client->process, token_access, &client->token) ||
        !GetTokenInformation(client->token, TokenSessionId, &client->session_id, sizeof(client->session_id), &size) ||
        !GetTokenInformation(client->token, TokenStatistics, &statistics, sizeof(statistics), &size))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        if (client->token) CloseHandle(client->token);
        CloseHandle(client->process);
        client->process = client->token = NULL;
        return hr;
    }
    client->authentication_id = statistics.AuthenticationId;
    return S_OK;
}

static void scm_revoke_class(struct registered_class *entry)
{
    list_remove(&entry->entry);
    CloseHandle(entry->publisher.token);
    CloseHandle(entry->publisher.process);
    free(entry->object);
    free(entry);
}

/* Reap on registry operations, without background polling or callbacks which
 * could race explicit revoke. The retained process handle identifies exit. */
static void scm_reap_classes(void)
{
    struct registered_class *cur, *next;

    LIST_FOR_EACH_ENTRY_SAFE(cur, next, &registered_classes, struct registered_class, entry)
    {
        if (WaitForSingleObject(cur->publisher.process, 0) != WAIT_OBJECT_0) continue;
        TRACE("retiring class %s cookie %u publisher %04lx session %lu\n",
              debugstr_guid(&cur->clsid), cur->cookie, cur->publisher.process_id, cur->publisher.session_id);
        scm_revoke_class(cur);
    }
}

HRESULT __cdecl irpcss_server_register(handle_t h, const GUID *clsid, unsigned int flags,
        PMInterfacePointer object, unsigned int *cookie)
{
    struct registered_class *entry;
    static LONG next_cookie;
    size_t size;
    HRESULT hr;

    *cookie = 0;
    if (!(entry = calloc(1, sizeof(*entry))))
        return E_OUTOFMEMORY;

    if (FAILED(hr = scm_get_client(h, TOKEN_QUERY, &entry->publisher)))
    {
        TRACE("rejecting class %s publisher %04lx identity query %#lx\n",
                     debugstr_guid(clsid), entry->publisher.process_id, hr);
        free(entry);
        return hr;
    }

    entry->clsid = *clsid;
    entry->single_use = !(flags & (REGCLS_MULTIPLEUSE | REGCLS_MULTI_SEPARATE));
    size = offsetof(MInterfacePointer, abData) + (size_t)object->ulCntData;
    if (size < object->ulCntData || !(entry->object = malloc(size)))
    {
        CloseHandle(entry->publisher.token);
        CloseHandle(entry->publisher.process);
        free(entry);
        return E_OUTOFMEMORY;
    }
    entry->object->ulCntData = object->ulCntData;
    memcpy(&entry->object->abData, object->abData, object->ulCntData);
    if (!(entry->cookie = InterlockedIncrement(&next_cookie)))
        entry->cookie = InterlockedIncrement(&next_cookie);

    EnterCriticalSection(&registered_classes_cs);
    scm_reap_classes();
    list_add_tail(&registered_classes, &entry->entry);
    *cookie = entry->cookie;
    TRACE("registered class %s cookie %u publisher %04lx session %lu authentication %08lx:%08lx\n",
          debugstr_guid(clsid), entry->cookie, entry->publisher.process_id, entry->publisher.session_id,
          entry->publisher.authentication_id.HighPart, entry->publisher.authentication_id.LowPart);
    LeaveCriticalSection(&registered_classes_cs);

    return S_OK;
}

HRESULT __cdecl irpcss_server_revoke(handle_t h, unsigned int cookie)
{
    struct registered_class *cur;
    HANDLE process;
    NTSTATUS status;
    DWORD process_id;
    HRESULT hr = S_OK;

    status = I_RpcOpenClientProcess(h, PROCESS_QUERY_LIMITED_INFORMATION, &process);
    if (status) return HRESULT_FROM_WIN32(RtlNtStatusToDosError(status));
    process_id = GetProcessId(process);

    EnterCriticalSection(&registered_classes_cs);
    scm_reap_classes();

    LIST_FOR_EACH_ENTRY(cur, &registered_classes, struct registered_class, entry)
    {
        if (cur->cookie == cookie)
        {
            if (cur->publisher.process_id != process_id)
            {
                TRACE("denying revoke cookie %u caller %04lx publisher %04lx session %lu\n",
                             cookie, process_id, cur->publisher.process_id, cur->publisher.session_id);
                hr = E_ACCESSDENIED;
            }
            else scm_revoke_class(cur);
            break;
        }
    }

    LeaveCriticalSection(&registered_classes_cs);
    CloseHandle(process);

    return hr;
}

/* The table lock protects both response copying and single-use consumption. */
static HRESULT scm_copy_class( struct registered_class *entry, PMInterfacePointer *object )
{
    *object = MIDL_user_allocate( offsetof(MInterfacePointer, abData) + (size_t)entry->object->ulCntData );
    if (!*object) return E_OUTOFMEMORY;
    (*object)->ulCntData = entry->object->ulCntData;
    memcpy( (*object)->abData, entry->object->abData, entry->object->ulCntData );
    if (entry->single_use) scm_revoke_class( entry );
    return S_OK;
}

HRESULT __cdecl irpcss_get_class_object(handle_t h, const GUID *clsid,
        PMInterfacePointer *object)
{
    struct registered_class *cur;
    HRESULT hr = E_NOINTERFACE;

    *object = NULL;

    EnterCriticalSection(&registered_classes_cs);
    scm_reap_classes();

    LIST_FOR_EACH_ENTRY(cur, &registered_classes, struct registered_class, entry)
    {
        if (!memcmp(clsid, &cur->clsid, sizeof(*clsid)))
        {
            hr = scm_copy_class( cur, object );

            break;
        }
    }

    LeaveCriticalSection(&registered_classes_cs);

    return hr;
}

/* Selection is separate from admission: a matching CLSID/session alone must
 * never expose another user's factory or bypass machine/application policy. */
static HRESULT scm_token_user( HANDLE token, TOKEN_USER **user )
{
    DWORD size = 0, error;

    *user = NULL;
    GetTokenInformation( token, TokenUser, NULL, 0, &size );
    if (!size) return HRESULT_FROM_WIN32( GetLastError() );
    if (!(*user = malloc( size ))) return E_OUTOFMEMORY;
    if (GetTokenInformation( token, TokenUser, *user, size, &size )) return S_OK;
    error = GetLastError();
    free( *user );
    *user = NULL;
    return HRESULT_FROM_WIN32( error );
}

static HRESULT scm_session_user( struct class_client *caller, HANDLE access_token, DWORD session,
                                 TOKEN_USER **user )
{
    SID interactive = { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_INTERACTIVE_RID } };
    HANDLE broker = NULL, target = NULL;
    TOKEN_USER *broker_user = NULL;
    BOOL is_interactive;
    HRESULT hr;

    *user = NULL;
    if (!CheckTokenMembership( access_token, &interactive, &is_interactive ))
        return HRESULT_FROM_WIN32( GetLastError() );
    if (session == caller->session_id && is_interactive)
        return scm_token_user( caller->token, user );

    /* WTS also requires LocalSystem. Its current lower adapter only enforces
     * TCB, so retain the documented identity requirement at this broker call. */
    if (!OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &broker ))
        return HRESULT_FROM_WIN32( GetLastError() );
    hr = scm_token_user( broker, &broker_user );
    CloseHandle( broker );
    if (FAILED(hr)) return hr;
    if (!IsWellKnownSid( broker_user->User.Sid, WinLocalSystemSid )) hr = E_ACCESSDENIED;
    free( broker_user );
    if (FAILED(hr)) return hr;
    if (!WTSQueryUserToken( session, &target )) return HRESULT_FROM_WIN32( GetLastError() );
    hr = scm_token_user( target, user );
    CloseHandle( target );
    return hr;
}

HRESULT __cdecl irpcss_get_class_object_session( handle_t binding, const GUID *clsid,
                                                DWORD session, DWORD context, PMInterfacePointer *object )
{
    struct class_client caller = {0};
    struct registered_class *cur;
    TOKEN_USER *target_user = NULL, *publisher_user;
    HANDLE access_token = NULL;
    DWORD is_appcontainer, size, publisher_session;
    HRESULT hr;

    *object = NULL;
    if (session == ~0u || !(context & CLSCTX_LOCAL_SERVER) ||
        (context & ~(CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER | CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER)))
        return E_NOTIMPL;
    hr = scm_get_client( binding, TOKEN_QUERY | TOKEN_DUPLICATE, &caller );
    if (FAILED(hr)) return hr;
    if (!GetTokenInformation( caller.token, TokenIsAppContainer, &is_appcontainer, sizeof(is_appcontainer), &size ))
    {
        hr = HRESULT_FROM_WIN32( GetLastError() );
        goto done;
    }
    if (is_appcontainer)
    {
        hr = E_NOTIMPL;
        goto done;
    }
    if (!DuplicateTokenEx( caller.token, TOKEN_QUERY, NULL, SecurityImpersonation, TokenImpersonation, &access_token ))
    {
        hr = HRESULT_FROM_WIN32( GetLastError() );
        goto done;
    }
    hr = scm_session_user( &caller, access_token, session, &target_user );
    if (FAILED(hr))
    {
        TRACE( "session user lookup %lu caller %04lx failed %#lx\n", session, caller.process_id, hr );
        goto done;
    }
    hr = scm_class_admission( clsid, access_token );
    if (FAILED(hr))
    {
        TRACE( "class %s caller %04lx admission failed %#lx\n", debugstr_guid(clsid), caller.process_id, hr );
        goto done;
    }

    hr = E_NOINTERFACE;
    EnterCriticalSection( &registered_classes_cs );
    scm_reap_classes();
    LIST_FOR_EACH_ENTRY( cur, &registered_classes, struct registered_class, entry )
    {
        if (memcmp( clsid, &cur->clsid, sizeof(*clsid) ) || cur->publisher.session_id != session) continue;
        if (!GetTokenInformation( cur->publisher.token, TokenSessionId, &publisher_session, sizeof(publisher_session), &size ) ||
            publisher_session != session) continue;
        hr = scm_token_user( cur->publisher.token, &publisher_user );
        if (FAILED(hr)) break;
        if (EqualSid( publisher_user->User.Sid, target_user->User.Sid ))
        {
            TRACE( "selected class %s publisher %04lx session %lu caller %04lx session %lu\n",
                   debugstr_guid(clsid), cur->publisher.process_id, session, caller.process_id, caller.session_id );
            free( publisher_user );
            hr = scm_copy_class( cur, object );
            break;
        }
        free( publisher_user );
        hr = E_NOINTERFACE;
    }
    LeaveCriticalSection( &registered_classes_cs );
done:
    TRACE( "scoped class %s session %lu caller %04lx context %#lx result %#lx\n",
           debugstr_guid(clsid), session, caller.process_id, context, hr );
    free( target_user );
    if (access_token) CloseHandle( access_token );
    CloseHandle( caller.token );
    CloseHandle( caller.process );
    return hr;
}
