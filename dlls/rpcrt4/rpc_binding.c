/*
 * RPC binding API
 *
 * Copyright 2001 Ove Kåven, TransGaming Technologies
 * Copyright 2003 Mike Hearn
 * Copyright 2004 Filip Navara
 * Copyright 2006 CodeWeavers
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "winnls.h"
#include "winerror.h"
#include "winternl.h"

#include "rpc.h"
#include "rpcndr.h"
#include "rpcasync.h"
#include "rpcdcep.h"

#include "wine/debug.h"

#include "rpc_binding.h"
#include "rpc_assoc.h"

WINE_DEFAULT_DEBUG_CHANNEL(rpc);
WINE_DECLARE_DEBUG_CHANNEL(rpc_auth);

LPSTR RPCRT4_strdupWtoA(LPCWSTR src)
{
  DWORD len;
  LPSTR s;
  if (!src) return NULL;
  len = WideCharToMultiByte(CP_ACP, 0, src, -1, NULL, 0, NULL, NULL);
  s = malloc(len);
  WideCharToMultiByte(CP_ACP, 0, src, -1, s, len, NULL, NULL);
  return s;
}

LPWSTR RPCRT4_strdupAtoW(LPCSTR src)
{
  DWORD len;
  LPWSTR s;
  if (!src) return NULL;
  len = MultiByteToWideChar(CP_ACP, 0, src, -1, NULL, 0);
  s = malloc(len * sizeof(WCHAR));
  MultiByteToWideChar(CP_ACP, 0, src, -1, s, len);
  return s;
}

static LPWSTR RPCRT4_strndupAtoW(LPCSTR src, INT slen)
{
  DWORD len;
  LPWSTR s;
  if (!src) return NULL;
  len = MultiByteToWideChar(CP_ACP, 0, src, slen, NULL, 0);
  s = malloc(len * sizeof(WCHAR));
  MultiByteToWideChar(CP_ACP, 0, src, slen, s, len);
  return s;
}

LPWSTR RPCRT4_strndupW(LPCWSTR src, INT slen)
{
  DWORD len;
  LPWSTR s;
  if (!src) return NULL;
  if (slen == -1) slen = lstrlenW(src);
  len = slen;
  s = malloc((len + 1) * sizeof(WCHAR));
  memcpy(s, src, len*sizeof(WCHAR));
  s[len] = 0;
  return s;
}

static RPC_STATUS RPCRT4_AllocBinding(RpcBinding** Binding, BOOL server)
{
  RpcBinding* NewBinding;

  NewBinding = calloc(1, sizeof(RpcBinding));
  NewBinding->refs = 1;
  NewBinding->server = server;

  *Binding = NewBinding;

  return RPC_S_OK;
}

static RPC_STATUS RPCRT4_CreateBindingA(RpcBinding** Binding, BOOL server, LPCSTR Protseq)
{
  RpcBinding* NewBinding;

  RPCRT4_AllocBinding(&NewBinding, server);
  NewBinding->Protseq = strdup(Protseq);

  TRACE("binding: %p\n", NewBinding);
  *Binding = NewBinding;

  return RPC_S_OK;
}

static RPC_STATUS RPCRT4_CreateBindingW(RpcBinding** Binding, BOOL server, LPCWSTR Protseq)
{
  RpcBinding* NewBinding;

  RPCRT4_AllocBinding(&NewBinding, server);
  NewBinding->Protseq = RPCRT4_strdupWtoA(Protseq);

  TRACE("binding: %p\n", NewBinding);
  *Binding = NewBinding;

  return RPC_S_OK;
}

static RPC_STATUS RPCRT4_CompleteBindingA(RpcBinding* Binding, LPCSTR NetworkAddr,
                                          LPCSTR Endpoint, LPCSTR NetworkOptions)
{
  RPC_STATUS status;

  TRACE("(RpcBinding == ^%p, NetworkAddr == %s, EndPoint == %s, NetworkOptions == %s)\n", Binding,
   debugstr_a(NetworkAddr), debugstr_a(Endpoint), debugstr_a(NetworkOptions));

  free(Binding->NetworkAddr);
  Binding->NetworkAddr = strdup(NetworkAddr);
  free(Binding->Endpoint);
  Binding->Endpoint = strdup(Endpoint);
  free(Binding->NetworkOptions);
  Binding->NetworkOptions = RPCRT4_strdupAtoW(NetworkOptions);

  /* only attempt to get an association if the binding is complete */
  if (Endpoint && Endpoint[0] != '\0')
  {
    status = RPCRT4_GetAssociation(Binding->Protseq, Binding->NetworkAddr,
                                   Binding->Endpoint, Binding->NetworkOptions,
                                   &Binding->Assoc);
    if (status != RPC_S_OK)
        return status;
  }

  return RPC_S_OK;
}

static RPC_STATUS RPCRT4_CompleteBindingW(RpcBinding* Binding, LPCWSTR NetworkAddr,
                                          LPCWSTR Endpoint, LPCWSTR NetworkOptions)
{
  RPC_STATUS status;

  TRACE("(RpcBinding == ^%p, NetworkAddr == %s, EndPoint == %s, NetworkOptions == %s)\n", Binding, 
   debugstr_w(NetworkAddr), debugstr_w(Endpoint), debugstr_w(NetworkOptions));

  free(Binding->NetworkAddr);
  Binding->NetworkAddr = RPCRT4_strdupWtoA(NetworkAddr);
  free(Binding->Endpoint);
  Binding->Endpoint = RPCRT4_strdupWtoA(Endpoint);
  free(Binding->NetworkOptions);
  Binding->NetworkOptions = wcsdup(NetworkOptions);

  /* only attempt to get an association if the binding is complete */
  if (Endpoint && Endpoint[0] != '\0')
  {
    status = RPCRT4_GetAssociation(Binding->Protseq, Binding->NetworkAddr,
                                   Binding->Endpoint, Binding->NetworkOptions,
                                   &Binding->Assoc);
    if (status != RPC_S_OK)
        return status;
  }

  return RPC_S_OK;
}

RPC_STATUS RPCRT4_ResolveBinding(RpcBinding* Binding, LPCSTR Endpoint)
{
  RPC_STATUS status;

  TRACE("(RpcBinding == ^%p, EndPoint == \"%s\"\n", Binding, Endpoint);

  free(Binding->Endpoint);
  Binding->Endpoint = strdup(Endpoint);

  if (Binding->Assoc) RpcAssoc_Release(Binding->Assoc);
  Binding->Assoc = NULL;
  status = RPCRT4_GetAssociation(Binding->Protseq, Binding->NetworkAddr,
                                 Binding->Endpoint, Binding->NetworkOptions,
                                 &Binding->Assoc);
  if (status != RPC_S_OK)
      return status;

  return RPC_S_OK;
}

RPC_STATUS RPCRT4_SetBindingObject(RpcBinding* Binding, const UUID* ObjectUuid)
{
  TRACE("(*RpcBinding == ^%p, UUID == %s)\n", Binding, debugstr_guid(ObjectUuid)); 
  if (ObjectUuid) Binding->ObjectUuid = *ObjectUuid;
  else UuidCreateNil(&Binding->ObjectUuid);
  return RPC_S_OK;
}

RPC_STATUS RPCRT4_MakeBinding(RpcBinding** Binding, RpcConnection* Connection)
{
  RpcBinding* NewBinding;
  TRACE("(RpcBinding == ^%p, Connection == ^%p)\n", Binding, Connection);

  RPCRT4_AllocBinding(&NewBinding, Connection->server);
  NewBinding->Protseq = strdup(rpcrt4_conn_get_name(Connection));
  NewBinding->NetworkAddr = strdup(Connection->NetworkAddr);
  NewBinding->Endpoint = strdup(Connection->Endpoint);
  NewBinding->FromConn = Connection;

  TRACE("binding: %p\n", NewBinding);
  *Binding = NewBinding;

  return RPC_S_OK;
}

void RPCRT4_AddRefBinding(RpcBinding* Binding)
{
  InterlockedIncrement(&Binding->refs);
}

RPC_STATUS RPCRT4_ReleaseBinding(RpcBinding* Binding)
{
  if (InterlockedDecrement(&Binding->refs))
    return RPC_S_OK;

  TRACE("binding: %p\n", Binding);
  if (Binding->Assoc) RpcAssoc_Release(Binding->Assoc);
  free(Binding->Endpoint);
  free(Binding->NetworkAddr);
  free(Binding->Protseq);
  free(Binding->NetworkOptions);
  free(Binding->CookieAuth);
  if (Binding->AuthInfo) RpcAuthInfo_Release(Binding->AuthInfo);
  if (Binding->QOS) RpcQualityOfService_Release(Binding->QOS);
  free(Binding);
  return RPC_S_OK;
}

RPC_STATUS RPCRT4_OpenBinding(RpcBinding* Binding, RpcConnection** Connection,
                              const RPC_SYNTAX_IDENTIFIER *TransferSyntax,
                              const RPC_SYNTAX_IDENTIFIER *InterfaceId, BOOL *from_cache)
{
  TRACE("(Binding == ^%p)\n", Binding);

  if (!Binding->server) {
     return RpcAssoc_GetClientConnection(Binding->Assoc, InterfaceId,
         TransferSyntax, Binding->AuthInfo, Binding->QOS, Binding->CookieAuth, Connection, from_cache);
  } else {
    /* we already have a connection with acceptable binding, so use it */
    if (Binding->FromConn) {
      *Connection = Binding->FromConn;
      return RPC_S_OK;
    } else {
       ERR("no connection in binding\n");
       return RPC_S_INTERNAL_ERROR;
    }
  }
}

RPC_STATUS RPCRT4_CloseBinding(RpcBinding* Binding, RpcConnection* Connection)
{
  TRACE("(Binding == ^%p)\n", Binding);
  if (!Connection) return RPC_S_OK;
  if (Binding->server) {
    /* don't destroy a connection that is cached in the binding */
    if (Binding->FromConn != Connection)
      RPCRT4_ReleaseConnection(Connection);
  }
  else {
    RpcAssoc_ReleaseIdleConnection(Binding->Assoc, Connection);
  }
  return RPC_S_OK;
}

static LPSTR RPCRT4_strconcatA(LPSTR dst, LPCSTR src)
{
  DWORD len = strlen(dst), slen = strlen(src);
  char *ndst = realloc(dst, len + slen + 2);
  if (!ndst)
  {
    free(dst);
    return NULL;
  }
  ndst[len] = ',';
  memcpy(ndst+len+1, src, slen+1);
  return ndst;
}

static LPWSTR RPCRT4_strconcatW(LPWSTR dst, LPCWSTR src)
{
  DWORD len = lstrlenW(dst), slen = lstrlenW(src);
  WCHAR *ndst = realloc(dst, (len + slen + 2) * sizeof(WCHAR));
  if (!ndst)
  {
    free(dst);
    return NULL;
  }
  ndst[len] = ',';
  memcpy(ndst+len+1, src, (slen+1)*sizeof(WCHAR));
  return ndst;
}

/* Copies the escaped version of a component into a string binding.
 * Note: doesn't nul-terminate the string */
static RPC_CSTR escape_string_binding_component(RPC_CSTR string_binding,
                                                const unsigned char *component)
{
  for (; *component; component++) {
    switch (*component) {
      case '@':
      case ':':
      case '[':
      case ']':
      case '\\':
        *string_binding++ = '\\';
        *string_binding++ = *component;
        break;
      default:
        *string_binding++ = *component;
        break;
    }
  }
  return string_binding;
}

static RPC_WSTR escape_string_binding_componentW(RPC_WSTR string_binding,
                                                 const WCHAR *component)
{
  for (; *component; component++) {
    switch (*component) {
      case '@':
      case ':':
      case '[':
      case ']':
      case '\\':
        *string_binding++ = '\\';
        *string_binding++ = *component;
        break;
      default:
        *string_binding++ = *component;
        break;
    }
  }
  return string_binding;
}

static const unsigned char *string_binding_find_delimiter(
    const unsigned char *string_binding, unsigned char delim)
{
  const unsigned char *next;
  for (next = string_binding; *next; next++) {
    if (*next == '\\') {
      next++;
      continue;
    }
    if (*next == delim)
      return next;
  }
  return NULL;
}

static const WCHAR *string_binding_find_delimiterW(
    const WCHAR *string_binding, WCHAR delim)
{
  const WCHAR *next;
  for (next = string_binding; *next; next++) {
    if (*next == '\\') {
      next++;
      continue;
    }
    if (*next == delim)
      return next;
  }
  return NULL;
}

static RPC_CSTR unescape_string_binding_component(
    const unsigned char *string_binding, int len)
{
  RPC_CSTR component, p;

  if (len == -1) len = strlen((const char *)string_binding);

  component = malloc((len + 1) * sizeof(*component));
  if (!component) return NULL;
  for (p = component; len > 0; string_binding++, len--) {
    if (*string_binding == '\\') {
      string_binding++;
      len--;
      *p++ = *string_binding;
    } else {
      *p++ = *string_binding;
    }
  }
  *p = '\0';
  return component;
}

static RPC_WSTR unescape_string_binding_componentW(
    const WCHAR *string_binding, int len)
{
  RPC_WSTR component, p;

  if (len == -1) len = lstrlenW(string_binding);

  component = malloc((len + 1) * sizeof(*component));
  if (!component) return NULL;
  for (p = component; len > 0; string_binding++, len--) {
    if (*string_binding == '\\') {
      string_binding++;
      len--;
      *p++ = *string_binding;
    } else {
      *p++ = *string_binding;
    }
  }
  *p = '\0';
  return component;
}

/***********************************************************************
 *             RpcStringBindingComposeA (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcStringBindingComposeA(RPC_CSTR ObjUuid, RPC_CSTR Protseq,
                                           RPC_CSTR NetworkAddr, RPC_CSTR Endpoint,
                                           RPC_CSTR Options, RPC_CSTR *StringBinding )
{
  DWORD len = 1;
  RPC_CSTR data;

  TRACE( "(%s,%s,%s,%s,%s,%p)\n",
        debugstr_a( (char*)ObjUuid ), debugstr_a( (char*)Protseq ),
        debugstr_a( (char*)NetworkAddr ), debugstr_a( (char*)Endpoint ),
        debugstr_a( (char*)Options ), StringBinding );

  /* overestimate for each component for escaping of delimiters */
  if (ObjUuid && *ObjUuid) len += strlen((char*)ObjUuid) * 2 + 1;
  if (Protseq && *Protseq) len += strlen((char*)Protseq) * 2 + 1;
  if (NetworkAddr && *NetworkAddr) len += strlen((char*)NetworkAddr) * 2;
  if (Endpoint && *Endpoint) len += strlen((char*)Endpoint) * 2 + 2;
  if (Options && *Options) len += strlen((char*)Options) * 2 + 2;

  data = malloc(len);
  *StringBinding = data;

  if (ObjUuid && *ObjUuid) {
    data = escape_string_binding_component(data, ObjUuid);
    *data++ = '@';
  }
  if (Protseq && *Protseq) {
    data = escape_string_binding_component(data, Protseq);
    *data++ = ':';
  }
  if (NetworkAddr && *NetworkAddr)
    data = escape_string_binding_component(data, NetworkAddr);

  if ((Endpoint && *Endpoint) ||
      (Options && *Options)) {
    *data++ = '[';
    if (Endpoint && *Endpoint) {
      data = escape_string_binding_component(data, Endpoint);
      if (Options && *Options) *data++ = ',';
    }
    if (Options && *Options) {
      data = escape_string_binding_component(data, Options);
    }
    *data++ = ']';
  }
  *data = 0;

  return RPC_S_OK;
}

/***********************************************************************
 *             RpcStringBindingComposeW (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcStringBindingComposeW( RPC_WSTR ObjUuid, RPC_WSTR Protseq,
                                            RPC_WSTR NetworkAddr, RPC_WSTR Endpoint,
                                            RPC_WSTR Options, RPC_WSTR* StringBinding )
{
  DWORD len = 1;
  RPC_WSTR data;

  TRACE("(%s,%s,%s,%s,%s,%p)\n",
       debugstr_w( ObjUuid ), debugstr_w( Protseq ),
       debugstr_w( NetworkAddr ), debugstr_w( Endpoint ),
       debugstr_w( Options ), StringBinding);

  /* overestimate for each component for escaping of delimiters */
  if (ObjUuid && *ObjUuid) len += lstrlenW(ObjUuid) * 2 + 1;
  if (Protseq && *Protseq) len += lstrlenW(Protseq) * 2 + 1;
  if (NetworkAddr && *NetworkAddr) len += lstrlenW(NetworkAddr) * 2;
  if (Endpoint && *Endpoint) len += lstrlenW(Endpoint) * 2 + 2;
  if (Options && *Options) len += lstrlenW(Options) * 2 + 2;

  data = malloc(len * sizeof(WCHAR));
  *StringBinding = data;

  if (ObjUuid && *ObjUuid) {
    data = escape_string_binding_componentW(data, ObjUuid);
    *data++ = '@';
  }
  if (Protseq && *Protseq) {
    data = escape_string_binding_componentW(data, Protseq);
    *data++ = ':';
  }
  if (NetworkAddr && *NetworkAddr) {
    data = escape_string_binding_componentW(data, NetworkAddr);
  }
  if ((Endpoint && *Endpoint) ||
      (Options && *Options)) {
    *data++ = '[';
    if (Endpoint && *Endpoint) {
      data = escape_string_binding_componentW(data, Endpoint);
      if (Options && *Options) *data++ = ',';
    }
    if (Options && *Options) {
      data = escape_string_binding_componentW(data, Options);
    }
    *data++ = ']';
  }
  *data = 0;

  return RPC_S_OK;
}


/***********************************************************************
 *             RpcStringBindingParseA (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcStringBindingParseA( RPC_CSTR StringBinding, RPC_CSTR *ObjUuid,
                                          RPC_CSTR *Protseq, RPC_CSTR *NetworkAddr,
                                          RPC_CSTR *Endpoint, RPC_CSTR *Options)
{
  const unsigned char *data, *next;
  static const char ep_opt[] = "endpoint=";
  BOOL endpoint_already_found = FALSE;

  TRACE("(%s,%p,%p,%p,%p,%p)\n", debugstr_a((char*)StringBinding),
       ObjUuid, Protseq, NetworkAddr, Endpoint, Options);

  if (ObjUuid) *ObjUuid = NULL;
  if (Protseq) *Protseq = NULL;
  if (NetworkAddr) *NetworkAddr = NULL;
  if (Endpoint) *Endpoint = NULL;
  if (Options) *Options = NULL;

  data = StringBinding;

  next = string_binding_find_delimiter(data, '@');
  if (next) {
    UUID uuid;
    RPC_STATUS status;
    RPC_CSTR str_uuid = unescape_string_binding_component(data, next - data);
    status = UuidFromStringA(str_uuid, &uuid);
    if (status != RPC_S_OK) {
      free(str_uuid);
      return status;
    }
    if (ObjUuid)
      *ObjUuid = str_uuid;
    else
      free(str_uuid);
    data = next+1;
  }

  next = string_binding_find_delimiter(data, ':');
  if (next) {
    if (Protseq) *Protseq = unescape_string_binding_component(data, next - data);
    data = next+1;
  }

  next = string_binding_find_delimiter(data, '[');
  if (next) {
    const unsigned char *close;
    RPC_CSTR opt;

    if (NetworkAddr) *NetworkAddr = unescape_string_binding_component(data, next - data);
    data = next+1;
    close = string_binding_find_delimiter(data, ']');
    if (!close) goto fail;

    /* tokenize options */
    while (data < close) {
      next = string_binding_find_delimiter(data, ',');
      if (!next || next > close) next = close;
      /* FIXME: this is kind of inefficient */
      opt = unescape_string_binding_component(data, next - data);
      data = next+1;

      /* parse option */
      next = string_binding_find_delimiter(opt, '=');
      if (!next) {
        /* not an option, must be an endpoint */
        if (endpoint_already_found) goto fail;
        if (Endpoint) *Endpoint = opt;
        else free(opt);
        endpoint_already_found = TRUE;
      } else {
        if (strncmp((const char *)opt, ep_opt, strlen(ep_opt)) == 0) {
          /* endpoint option */
          if (endpoint_already_found) goto fail;
          if (Endpoint) *Endpoint = unescape_string_binding_component(next+1, -1);
          free(opt);
          endpoint_already_found = TRUE;
        } else {
          /* network option */
          if (Options) {
            if (*Options) {
              /* FIXME: this is kind of inefficient */
              *Options = (unsigned char*) RPCRT4_strconcatA( (char*)*Options, (char *)opt);
              free(opt);
            } else
              *Options = opt;
          } else
            free(opt);
        }
      }
    }

    data = close+1;
    if (*data) goto fail;
  }
  else if (NetworkAddr) 
    *NetworkAddr = unescape_string_binding_component(data, -1);

  return RPC_S_OK;

fail:
  if (ObjUuid) RpcStringFreeA(ObjUuid);
  if (Protseq) RpcStringFreeA(Protseq);
  if (NetworkAddr) RpcStringFreeA(NetworkAddr);
  if (Endpoint) RpcStringFreeA(Endpoint);
  if (Options) RpcStringFreeA(Options);
  return RPC_S_INVALID_STRING_BINDING;
}

/***********************************************************************
 *             RpcStringBindingParseW (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcStringBindingParseW( RPC_WSTR StringBinding, RPC_WSTR *ObjUuid,
                                          RPC_WSTR *Protseq, RPC_WSTR *NetworkAddr,
                                          RPC_WSTR *Endpoint, RPC_WSTR *Options)
{
  const WCHAR *data, *next;
  BOOL endpoint_already_found = FALSE;

  TRACE("(%s,%p,%p,%p,%p,%p)\n", debugstr_w(StringBinding),
       ObjUuid, Protseq, NetworkAddr, Endpoint, Options);

  if (ObjUuid) *ObjUuid = NULL;
  if (Protseq) *Protseq = NULL;
  if (NetworkAddr) *NetworkAddr = NULL;
  if (Endpoint) *Endpoint = NULL;
  if (Options) *Options = NULL;

  data = StringBinding;

  next = string_binding_find_delimiterW(data, '@');
  if (next) {
    UUID uuid;
    RPC_STATUS status;
    RPC_WSTR str_uuid = unescape_string_binding_componentW(data, next - data);
    status = UuidFromStringW(str_uuid, &uuid);
    if (status != RPC_S_OK) {
      free(str_uuid);
      return status;
    }
    if (ObjUuid)
      *ObjUuid = str_uuid;
    else
      free(str_uuid);
    data = next+1;
  }

  next = string_binding_find_delimiterW(data, ':');
  if (next) {
    if (Protseq) *Protseq = unescape_string_binding_componentW(data, next - data);
    data = next+1;
  }

  next = string_binding_find_delimiterW(data, '[');
  if (next) {
    const WCHAR *close;
    RPC_WSTR opt;

    if (NetworkAddr) *NetworkAddr = unescape_string_binding_componentW(data, next - data);
    data = next+1;
    close = string_binding_find_delimiterW(data, ']');
    if (!close) goto fail;

    /* tokenize options */
    while (data < close) {
      next = string_binding_find_delimiterW(data, ',');
      if (!next || next > close) next = close;
      /* FIXME: this is kind of inefficient */
      opt = unescape_string_binding_componentW(data, next - data);
      data = next+1;

      /* parse option */
      next = string_binding_find_delimiterW(opt, '=');
      if (!next) {
        /* not an option, must be an endpoint */
        if (endpoint_already_found) goto fail;
        if (Endpoint) *Endpoint = opt;
        else free(opt);
        endpoint_already_found = TRUE;
      } else {
        if (wcsncmp(opt, L"endpoint=", lstrlenW(L"endpoint=")) == 0) {
          /* endpoint option */
          if (endpoint_already_found) goto fail;
          if (Endpoint) *Endpoint = unescape_string_binding_componentW(next+1, -1);
          free(opt);
          endpoint_already_found = TRUE;
        } else {
          /* network option */
          if (Options) {
            if (*Options) {
              /* FIXME: this is kind of inefficient */
              *Options = RPCRT4_strconcatW(*Options, opt);
              free(opt);
            } else
              *Options = opt;
          } else
            free(opt);
        }
      }
    }

    data = close+1;
    if (*data) goto fail;
  } else if (NetworkAddr) 
    *NetworkAddr = unescape_string_binding_componentW(data, -1);

  return RPC_S_OK;

fail:
  if (ObjUuid) RpcStringFreeW(ObjUuid);
  if (Protseq) RpcStringFreeW(Protseq);
  if (NetworkAddr) RpcStringFreeW(NetworkAddr);
  if (Endpoint) RpcStringFreeW(Endpoint);
  if (Options) RpcStringFreeW(Options);
  return RPC_S_INVALID_STRING_BINDING;
}

/***********************************************************************
 *             RpcBindingFree (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcBindingFree( RPC_BINDING_HANDLE* Binding )
{
  RPC_STATUS status;
  TRACE("(%p) = %p\n", Binding, *Binding);
  if (*Binding)
    status = RPCRT4_ReleaseBinding(*Binding);
  else
    status = RPC_S_INVALID_BINDING;
  if (status == RPC_S_OK) *Binding = NULL;
  return status;
}

static RPC_STATUS complete_fast_binding(RpcBinding *binding, const UUID *object,
                                        ULONG template_flags, ULONG option_flags,
                                        ULONG com_timeout, ULONG call_timeout)
{
  RPC_STATUS status;

  if (template_flags & RPC_BHT_OBJECT_UUID_VALID)
    status = RPCRT4_SetBindingObject(binding, object);
  else
    status = RPCRT4_SetBindingObject(binding, NULL);

  if (status == RPC_S_OK)
  {
    binding->FastBinding = TRUE;
    binding->FastDynamicEndpoint = !binding->Endpoint || !binding->Endpoint[0];
    binding->FastFlags = option_flags;
    binding->ComTimeout = com_timeout;
    binding->CallTimeout = call_timeout;
  }
  return status;
}

/***********************************************************************
 *             RpcBindingCreateA (RPCRT4.@)
 */
RPC_STATUS RPC_ENTRY RpcBindingCreateA(RPC_BINDING_HANDLE_TEMPLATE_V1_A *Template,
                                       RPC_BINDING_HANDLE_SECURITY_V1_A *Security,
                                       RPC_BINDING_HANDLE_OPTIONS_V1 *Options,
                                       RPC_BINDING_HANDLE *Binding)
{
  RpcBinding *binding = NULL;
  RPC_STATUS status;

  TRACE("(%p,%p,%p,%p)\n", Template, Security, Options, Binding);

  if (!Template || !Binding) return RPC_S_INVALID_ARG;
  if (Template->Version != 1 || (Security && Security->Version != 1) ||
      (Options && Options->Version != 1))
    return RPC_S_CANNOT_SUPPORT;
  if (Template->ProtocolSequence != RPC_PROTSEQ_LRPC)
    return RPC_S_CANNOT_SUPPORT;
  if ((Template->Flags & ~RPC_BHT_OBJECT_UUID_VALID) || Template->u1.Reserved ||
      (Options && (Options->Flags & ~(RPC_BHO_NONCAUSAL | RPC_BHO_DONTLINGER))))
    return RPC_S_INVALID_ARG;

  status = RPCRT4_CreateBindingA(&binding, FALSE, "ncalrpc");
  if (status == RPC_S_OK)
    status = RPCRT4_CompleteBindingA(binding,
                                     Template->NetworkAddress ? (const char *)Template->NetworkAddress : "",
                                     Template->StringEndpoint ? (const char *)Template->StringEndpoint : "", "");
  if (status == RPC_S_OK)
    status = complete_fast_binding(binding, &Template->ObjectUuid, Template->Flags,
                                   Options ? Options->Flags : 0,
                                   Options ? Options->ComTimeout : RPC_C_BINDING_DEFAULT_TIMEOUT,
                                   Options ? Options->CallTimeout : 0);
  if (status == RPC_S_OK && Security)
    status = RpcBindingSetAuthInfoExA(binding, Security->ServerPrincName,
                                     Security->AuthnLevel, Security->AuthnSvc,
                                     Security->AuthIdentity, RPC_C_AUTHZ_NONE,
                                     Security->SecurityQos);

  if (status == RPC_S_OK)
    *Binding = binding;
  else if (binding)
    RPCRT4_ReleaseBinding(binding);
  return status;
}

/***********************************************************************
 *             RpcBindingCreateW (RPCRT4.@)
 */
RPC_STATUS RPC_ENTRY RpcBindingCreateW(RPC_BINDING_HANDLE_TEMPLATE_V1_W *Template,
                                       RPC_BINDING_HANDLE_SECURITY_V1_W *Security,
                                       RPC_BINDING_HANDLE_OPTIONS_V1 *Options,
                                       RPC_BINDING_HANDLE *Binding)
{
  static const WCHAR ncalrpcW[] = L"ncalrpc";
  static const WCHAR emptyW[] = L"";
  RpcBinding *binding = NULL;
  RPC_STATUS status;

  TRACE("(%p,%p,%p,%p)\n", Template, Security, Options, Binding);

  if (!Template || !Binding) return RPC_S_INVALID_ARG;
  if (Template->Version != 1 || (Security && Security->Version != 1) ||
      (Options && Options->Version != 1))
    return RPC_S_CANNOT_SUPPORT;
  if (Template->ProtocolSequence != RPC_PROTSEQ_LRPC)
    return RPC_S_CANNOT_SUPPORT;
  if ((Template->Flags & ~RPC_BHT_OBJECT_UUID_VALID) || Template->u1.Reserved ||
      (Options && (Options->Flags & ~(RPC_BHO_NONCAUSAL | RPC_BHO_DONTLINGER))))
    return RPC_S_INVALID_ARG;

  status = RPCRT4_CreateBindingW(&binding, FALSE, ncalrpcW);
  if (status == RPC_S_OK)
    status = RPCRT4_CompleteBindingW(binding,
                                     Template->NetworkAddress ? (LPCWSTR)Template->NetworkAddress : emptyW,
                                     Template->StringEndpoint ? (LPCWSTR)Template->StringEndpoint : emptyW,
                                     emptyW);
  if (status == RPC_S_OK)
    status = complete_fast_binding(binding, &Template->ObjectUuid, Template->Flags,
                                   Options ? Options->Flags : 0,
                                   Options ? Options->ComTimeout : RPC_C_BINDING_DEFAULT_TIMEOUT,
                                   Options ? Options->CallTimeout : 0);
  if (status == RPC_S_OK && Security)
    status = RpcBindingSetAuthInfoExW(binding, Security->ServerPrincName,
                                     Security->AuthnLevel, Security->AuthnSvc,
                                     Security->AuthIdentity, RPC_C_AUTHZ_NONE,
                                     Security->SecurityQos);

  if (status == RPC_S_OK)
    *Binding = binding;
  else if (binding)
    RPCRT4_ReleaseBinding(binding);
  return status;
}

/***********************************************************************
 *             RpcBindingBind (RPCRT4.@)
 */
RPC_STATUS RPC_ENTRY RpcBindingBind(PRPC_ASYNC_STATE Async, RPC_BINDING_HANDLE Binding,
                                    RPC_IF_HANDLE IfSpec)
{
  const RPC_CLIENT_INTERFACE *client_if = IfSpec;
  RpcBinding *binding = Binding;
  RpcConnection *connection;
  RPC_STATUS status;

  TRACE("(%p,%p,%p) interface %s version %u.%u\n", Async, Binding, IfSpec,
        IfSpec ? debugstr_guid(&client_if->InterfaceId.SyntaxGUID) : "(null)",
        IfSpec ? client_if->InterfaceId.SyntaxVersion.MajorVersion : 0,
        IfSpec ? client_if->InterfaceId.SyntaxVersion.MinorVersion : 0);

  if (!binding || !client_if) return RPC_S_INVALID_ARG;
  if (!binding->FastBinding || binding->server || strcmp(binding->Protseq, "ncalrpc"))
    return RPC_S_INVALID_BINDING;
  if (Async) return RPC_S_CANNOT_SUPPORT;
  if (binding->FastBound) return RPC_S_OK;

  if (!binding->Endpoint || !binding->Endpoint[0])
  {
    status = RpcEpResolveBinding(binding, IfSpec);
    if (status != RPC_S_OK) return status;
  }
  else if (!binding->Assoc)
  {
    status = RPCRT4_GetAssociation(binding->Protseq, binding->NetworkAddr,
                                   binding->Endpoint, binding->NetworkOptions,
                                   &binding->Assoc);
    if (status != RPC_S_OK) return status;
  }

  status = RPCRT4_OpenBinding(binding, &connection, &client_if->TransferSyntax,
                              &client_if->InterfaceId, NULL);
  if (status != RPC_S_OK) return status;

  RPCRT4_CloseBinding(binding, connection);
  binding->FastInterface = client_if->InterfaceId;
  binding->FastTransferSyntax = client_if->TransferSyntax;
  binding->FastBound = TRUE;
  return RPC_S_OK;
}

/***********************************************************************
 *             RpcBindingUnbind (RPCRT4.@)
 */
RPC_STATUS RPC_ENTRY RpcBindingUnbind(RPC_BINDING_HANDLE Binding)
{
  RpcBinding *binding = Binding;

  TRACE("(%p)\n", Binding);

  if (!binding || !binding->FastBinding || !binding->FastBound)
    return RPC_S_INVALID_BINDING;

  if (binding->Assoc) RpcAssoc_Release(binding->Assoc);
  binding->Assoc = NULL;
  if (binding->FastDynamicEndpoint)
  {
    free(binding->Endpoint);
    binding->Endpoint = NULL;
  }
  memset(&binding->FastInterface, 0, sizeof(binding->FastInterface));
  memset(&binding->FastTransferSyntax, 0, sizeof(binding->FastTransferSyntax));
  binding->FastBound = FALSE;
  return RPC_S_OK;
}
  
/***********************************************************************
 *             RpcBindingVectorFree (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcBindingVectorFree( RPC_BINDING_VECTOR** BindingVector )
{
  ULONG c;

  TRACE("(%p)\n", BindingVector);
  for (c=0; c<(*BindingVector)->Count; c++) RpcBindingFree(&(*BindingVector)->BindingH[c]);
  free(*BindingVector);
  *BindingVector = NULL;
  return RPC_S_OK;
}
  
/***********************************************************************
 *             RpcBindingInqObject (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcBindingInqObject( RPC_BINDING_HANDLE Binding, UUID* ObjectUuid )
{
  RpcBinding* bind = Binding;

  TRACE("(%p,%p) = %s\n", Binding, ObjectUuid, debugstr_guid(&bind->ObjectUuid));
  *ObjectUuid = bind->ObjectUuid;
  return RPC_S_OK;
}

/***********************************************************************
 *             RpcBindingSetObject (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcBindingSetObject( RPC_BINDING_HANDLE Binding, UUID* ObjectUuid )
{
  RpcBinding* bind = Binding;

  TRACE("(%p,%s)\n", Binding, debugstr_guid(ObjectUuid));
  if (bind->server) return RPC_S_WRONG_KIND_OF_BINDING;
  return RPCRT4_SetBindingObject(Binding, ObjectUuid);
}

/***********************************************************************
 *             RpcBindingFromStringBindingA (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcBindingFromStringBindingA( RPC_CSTR StringBinding, RPC_BINDING_HANDLE* Binding )
{
  RPC_STATUS ret;
  RpcBinding* bind = NULL;
  RPC_CSTR ObjectUuid, Protseq, NetworkAddr, Endpoint, Options;
  UUID Uuid;

  TRACE("(%s,%p)\n", debugstr_a((char*)StringBinding), Binding);

  ret = RpcStringBindingParseA(StringBinding, &ObjectUuid, &Protseq,
                              &NetworkAddr, &Endpoint, &Options);
  if (ret != RPC_S_OK) return ret;

  ret = UuidFromStringA(ObjectUuid, &Uuid);

  if (ret == RPC_S_OK)
    ret = RPCRT4_CreateBindingA(&bind, FALSE, (char*)Protseq);
  if (ret == RPC_S_OK) {
      ret = RPCRT4_SetBindingObject(bind, &Uuid);
      if (ret == RPC_S_OK)
        ret = RPCRT4_CompleteBindingA(bind, (char*)NetworkAddr, (char*)Endpoint, (char*)Options);

      if (ret == RPC_S_OK)
        *Binding = (RPC_BINDING_HANDLE)bind;
      else
        RPCRT4_ReleaseBinding(bind);
  }

  RpcStringFreeA(&Options);
  RpcStringFreeA(&Endpoint);
  RpcStringFreeA(&NetworkAddr);
  RpcStringFreeA(&Protseq);
  RpcStringFreeA(&ObjectUuid);

  return ret;
}

/***********************************************************************
 *             RpcBindingFromStringBindingW (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcBindingFromStringBindingW( RPC_WSTR StringBinding, RPC_BINDING_HANDLE* Binding )
{
  RPC_STATUS ret;
  RpcBinding* bind = NULL;
  RPC_WSTR ObjectUuid, Protseq, NetworkAddr, Endpoint, Options;
  UUID Uuid;

  TRACE("(%s,%p)\n", debugstr_w(StringBinding), Binding);

  ret = RpcStringBindingParseW(StringBinding, &ObjectUuid, &Protseq,
                              &NetworkAddr, &Endpoint, &Options);
  if (ret != RPC_S_OK) return ret;

  ret = UuidFromStringW(ObjectUuid, &Uuid);

  if (ret == RPC_S_OK)
    ret = RPCRT4_CreateBindingW(&bind, FALSE, Protseq);
  if (ret == RPC_S_OK) {
      ret = RPCRT4_SetBindingObject(bind, &Uuid);
      if (ret == RPC_S_OK)
        ret = RPCRT4_CompleteBindingW(bind, NetworkAddr, Endpoint, Options);

      if (ret == RPC_S_OK)
        *Binding = (RPC_BINDING_HANDLE)bind;
      else
        RPCRT4_ReleaseBinding(bind);
  }

  RpcStringFreeW(&Options);
  RpcStringFreeW(&Endpoint);
  RpcStringFreeW(&NetworkAddr);
  RpcStringFreeW(&Protseq);
  RpcStringFreeW(&ObjectUuid);

  return ret;
}
  
/***********************************************************************
 *             RpcBindingToStringBindingA (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcBindingToStringBindingA( RPC_BINDING_HANDLE Binding, RPC_CSTR *StringBinding )
{
  RPC_STATUS ret;
  RpcBinding* bind = Binding;
  RPC_CSTR ObjectUuid;

  TRACE("(%p,%p)\n", Binding, StringBinding);

  if (UuidIsNil(&bind->ObjectUuid, &ret))
    ObjectUuid = NULL;
  else
  {
    ret = UuidToStringA(&bind->ObjectUuid, &ObjectUuid);
    if (ret != RPC_S_OK) return ret;
  }

  ret = RpcStringBindingComposeA(ObjectUuid, (unsigned char*)bind->Protseq, (unsigned char*) bind->NetworkAddr,
                                 (unsigned char*) bind->Endpoint, NULL, StringBinding);

  RpcStringFreeA(&ObjectUuid);

  return ret;
}
  
/***********************************************************************
 *             RpcBindingToStringBindingW (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcBindingToStringBindingW( RPC_BINDING_HANDLE Binding, RPC_WSTR *StringBinding )
{
  RPC_STATUS ret;
  unsigned char *str = NULL;
  TRACE("(%p,%p)\n", Binding, StringBinding);
  ret = RpcBindingToStringBindingA(Binding, &str);
  *StringBinding = RPCRT4_strdupAtoW((char*)str);
  RpcStringFreeA(&str);
  return ret;
}

/***********************************************************************
 *             I_RpcBindingInqTransportType (RPCRT4.@)
 */
RPC_STATUS WINAPI I_RpcBindingInqTransportType( RPC_BINDING_HANDLE Binding, unsigned int * Type )
{

  FIXME( "(%p,%p): stub\n", Binding, Type);
  *Type = TRANSPORT_TYPE_LPC;
  return RPC_S_OK;
}

/***********************************************************************
 *             I_RpcBindingSetAsync (RPCRT4.@)
 * NOTES
 *  Exists in win9x and winNT, but with different number of arguments
 *  (9x version has 3 arguments, NT has 2).
 */
RPC_STATUS WINAPI I_RpcBindingSetAsync( RPC_BINDING_HANDLE Binding, RPC_BLOCKING_FN BlockingFn)
{
  RpcBinding* bind = Binding;

  TRACE( "(%p,%p): stub\n", Binding, BlockingFn );

  bind->BlockingFn = BlockingFn;

  return RPC_S_OK;
}

/***********************************************************************
 *             RpcBindingCopy (RPCRT4.@)
 */
RPC_STATUS RPC_ENTRY RpcBindingCopy(
  RPC_BINDING_HANDLE SourceBinding,
  RPC_BINDING_HANDLE* DestinationBinding)
{
  RpcBinding *DestBinding;
  RpcBinding *SrcBinding = SourceBinding;
  RPC_STATUS status;

  TRACE("(%p, %p)\n", SourceBinding, DestinationBinding);

  status = RPCRT4_AllocBinding(&DestBinding, SrcBinding->server);
  if (status != RPC_S_OK) return status;

  DestBinding->ObjectUuid = SrcBinding->ObjectUuid;
  DestBinding->BlockingFn = SrcBinding->BlockingFn;
  DestBinding->Protseq = strdup(SrcBinding->Protseq);
  DestBinding->NetworkAddr = strdup(SrcBinding->NetworkAddr);
  DestBinding->Endpoint = strdup(SrcBinding->Endpoint);
  DestBinding->NetworkOptions = wcsdup(SrcBinding->NetworkOptions);
  DestBinding->CookieAuth = wcsdup(SrcBinding->CookieAuth);
  if (SrcBinding->Assoc) SrcBinding->Assoc->refs++;
  DestBinding->Assoc = SrcBinding->Assoc;

  if (SrcBinding->AuthInfo) RpcAuthInfo_AddRef(SrcBinding->AuthInfo);
  DestBinding->AuthInfo = SrcBinding->AuthInfo;
  if (SrcBinding->QOS) RpcQualityOfService_AddRef(SrcBinding->QOS);
  DestBinding->QOS = SrcBinding->QOS;

  *DestinationBinding = DestBinding;
  return RPC_S_OK;
}

/***********************************************************************
 *             RpcBindingReset (RPCRT4.@)
 */
RPC_STATUS RPC_ENTRY RpcBindingReset(RPC_BINDING_HANDLE Binding)
{
    RpcBinding *bind = Binding;

    TRACE("(%p)\n", Binding);

    free(bind->Endpoint);
    bind->Endpoint = NULL;
    if (bind->Assoc) RpcAssoc_Release(bind->Assoc);
    bind->Assoc = NULL;

    return RPC_S_OK;
}

/***********************************************************************
 *             RpcImpersonateClient (RPCRT4.@)
 *
 * Impersonates the client connected via a binding handle so that security
 * checks are done in the context of the client.
 *
 * PARAMS
 *  BindingHandle [I] Handle to the binding to the client.
 *
 * RETURNS
 *  Success: RPS_S_OK.
 *  Failure: RPC_STATUS value.
 *
 * NOTES
 *
 * If BindingHandle is NULL then the function impersonates the client
 * connected to the binding handle of the current thread.
 */
RPC_STATUS WINAPI RpcImpersonateClient(RPC_BINDING_HANDLE BindingHandle)
{
    RpcBinding *bind;

    TRACE("(%p)\n", BindingHandle);

    if (!BindingHandle) BindingHandle = I_RpcGetCurrentCallHandle();
    if (!BindingHandle) return RPC_S_INVALID_BINDING;

    bind = BindingHandle;
    if (bind->FromConn)
        return rpcrt4_conn_impersonate_client(bind->FromConn);
    return RPC_S_WRONG_KIND_OF_BINDING;
}

/***********************************************************************
 *             RpcRevertToSelfEx (RPCRT4.@)
 *
 * Stops impersonating the client connected to the binding handle so that security
 * checks are no longer done in the context of the client.
 *
 * PARAMS
 *  BindingHandle [I] Handle to the binding to the client.
 *
 * RETURNS
 *  Success: RPS_S_OK.
 *  Failure: RPC_STATUS value.
 *
 * NOTES
 *
 * If BindingHandle is NULL then the function stops impersonating the client
 * connected to the binding handle of the current thread.
 */
RPC_STATUS WINAPI RpcRevertToSelfEx(RPC_BINDING_HANDLE BindingHandle)
{
    RpcBinding *bind;

    TRACE("(%p)\n", BindingHandle);

    if (!BindingHandle) BindingHandle = I_RpcGetCurrentCallHandle();
    if (!BindingHandle) return RPC_S_INVALID_BINDING;

    bind = BindingHandle;
    if (bind->FromConn)
        return rpcrt4_conn_revert_to_self(bind->FromConn);
    return RPC_S_WRONG_KIND_OF_BINDING;
}

static inline BOOL has_nt_auth_identity(ULONG AuthnLevel)
{
    switch (AuthnLevel)
    {
    case RPC_C_AUTHN_GSS_NEGOTIATE:
    case RPC_C_AUTHN_WINNT:
    case RPC_C_AUTHN_GSS_KERBEROS:
        return TRUE;
    default:
        return FALSE;
    }
}

RPC_STATUS RpcAuthInfo_Create(ULONG AuthnLevel, ULONG AuthnSvc,
                              CredHandle cred, TimeStamp exp,
                              ULONG cbMaxToken,
                              RPC_AUTH_IDENTITY_HANDLE identity,
                              RpcAuthInfo **ret)
{
    RpcAuthInfo *AuthInfo = malloc(sizeof(*AuthInfo));
    if (!AuthInfo)
        return RPC_S_OUT_OF_MEMORY;

    AuthInfo->refs = 1;
    AuthInfo->transport_only = FALSE;
    AuthInfo->AuthnLevel = AuthnLevel;
    AuthInfo->AuthnSvc = AuthnSvc;
    AuthInfo->cred = cred;
    AuthInfo->exp = exp;
    AuthInfo->cbMaxToken = cbMaxToken;
    AuthInfo->identity = identity;
    AuthInfo->server_principal_name = NULL;

    /* duplicate the SEC_WINNT_AUTH_IDENTITY structure, if applicable, to
     * enable better matching in RpcAuthInfo_IsEqual */
    if (identity && has_nt_auth_identity(AuthnSvc))
    {
        const SEC_WINNT_AUTH_IDENTITY_W *nt_identity = identity;
        AuthInfo->nt_identity = malloc(sizeof(*AuthInfo->nt_identity));
        if (!AuthInfo->nt_identity)
        {
            free(AuthInfo);
            return RPC_S_OUT_OF_MEMORY;
        }

        AuthInfo->nt_identity->Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
        if (nt_identity->Flags & SEC_WINNT_AUTH_IDENTITY_UNICODE)
            AuthInfo->nt_identity->User = RPCRT4_strndupW(nt_identity->User, nt_identity->UserLength);
        else
            AuthInfo->nt_identity->User = RPCRT4_strndupAtoW((const char *)nt_identity->User, nt_identity->UserLength);
        AuthInfo->nt_identity->UserLength = nt_identity->UserLength;
        if (nt_identity->Flags & SEC_WINNT_AUTH_IDENTITY_UNICODE)
            AuthInfo->nt_identity->Domain = RPCRT4_strndupW(nt_identity->Domain, nt_identity->DomainLength);
        else
            AuthInfo->nt_identity->Domain = RPCRT4_strndupAtoW((const char *)nt_identity->Domain, nt_identity->DomainLength);
        AuthInfo->nt_identity->DomainLength = nt_identity->DomainLength;
        if (nt_identity->Flags & SEC_WINNT_AUTH_IDENTITY_UNICODE)
            AuthInfo->nt_identity->Password = RPCRT4_strndupW(nt_identity->Password, nt_identity->PasswordLength);
        else
            AuthInfo->nt_identity->Password = RPCRT4_strndupAtoW((const char *)nt_identity->Password, nt_identity->PasswordLength);
        AuthInfo->nt_identity->PasswordLength = nt_identity->PasswordLength;

        if ((nt_identity->User && !AuthInfo->nt_identity->User) ||
            (nt_identity->Domain && !AuthInfo->nt_identity->Domain) ||
            (nt_identity->Password && !AuthInfo->nt_identity->Password))
        {
            free(AuthInfo->nt_identity->User);
            free(AuthInfo->nt_identity->Domain);
            free(AuthInfo->nt_identity->Password);
            free(AuthInfo->nt_identity);
            free(AuthInfo);
            return RPC_S_OUT_OF_MEMORY;
        }
    }
    else
        AuthInfo->nt_identity = NULL;
    *ret = AuthInfo;
    return RPC_S_OK;
}

ULONG RpcAuthInfo_AddRef(RpcAuthInfo *AuthInfo)
{
    return InterlockedIncrement(&AuthInfo->refs);
}

ULONG RpcAuthInfo_Release(RpcAuthInfo *AuthInfo)
{
    ULONG refs = InterlockedDecrement(&AuthInfo->refs);

    if (!refs)
    {
        if (!AuthInfo->transport_only)
            FreeCredentialsHandle(&AuthInfo->cred);
        if (AuthInfo->nt_identity)
        {
            free(AuthInfo->nt_identity->User);
            free(AuthInfo->nt_identity->Domain);
            free(AuthInfo->nt_identity->Password);
            free(AuthInfo->nt_identity);
        }
        free(AuthInfo->server_principal_name);
        free(AuthInfo);
    }

    return refs;
}

BOOL RpcAuthInfo_IsEqual(const RpcAuthInfo *AuthInfo1, const RpcAuthInfo *AuthInfo2)
{
    if (AuthInfo1 == AuthInfo2)
        return TRUE;

    if (!AuthInfo1 || !AuthInfo2)
        return FALSE;

    if ((AuthInfo1->AuthnLevel != AuthInfo2->AuthnLevel) ||
        (AuthInfo1->AuthnSvc != AuthInfo2->AuthnSvc))
        return FALSE;

    if (AuthInfo1->identity == AuthInfo2->identity)
        return TRUE;

    if (!AuthInfo1->identity || !AuthInfo2->identity)
        return FALSE;

    if (has_nt_auth_identity(AuthInfo1->AuthnSvc))
    {
        const SEC_WINNT_AUTH_IDENTITY_W *identity1 = AuthInfo1->nt_identity;
        const SEC_WINNT_AUTH_IDENTITY_W *identity2 = AuthInfo2->nt_identity;
        /* compare user names */
        if (identity1->UserLength != identity2->UserLength ||
            memcmp(identity1->User, identity2->User, identity1->UserLength))
            return FALSE;
        /* compare domain names */
        if (identity1->DomainLength != identity2->DomainLength ||
            memcmp(identity1->Domain, identity2->Domain, identity1->DomainLength))
            return FALSE;
        /* compare passwords */
        if (identity1->PasswordLength != identity2->PasswordLength ||
            memcmp(identity1->Password, identity2->Password, identity1->PasswordLength))
            return FALSE;
    }
    else
        return FALSE;

    return TRUE;
}

static RPC_STATUS RpcQualityOfService_Create(const RPC_SECURITY_QOS *qos_src, BOOL unicode, RpcQualityOfService **qos_dst)
{
    RpcQualityOfService *qos = malloc(sizeof(*qos));

    if (!qos)
        return RPC_S_OUT_OF_RESOURCES;

    qos->refs = 1;
    qos->qos = malloc(sizeof(*qos->qos));
    if (!qos->qos) goto error;
    qos->qos->Version = qos_src->Version;
    qos->qos->Capabilities = qos_src->Capabilities;
    qos->qos->IdentityTracking = qos_src->IdentityTracking;
    qos->qos->ImpersonationType = qos_src->ImpersonationType;
    qos->qos->AdditionalSecurityInfoType = 0;

    if (qos_src->Version >= 2)
    {
        const RPC_SECURITY_QOS_V2_W *qos_src2 = (const RPC_SECURITY_QOS_V2_W *)qos_src;
        qos->qos->AdditionalSecurityInfoType = qos_src2->AdditionalSecurityInfoType;
        if (qos_src2->AdditionalSecurityInfoType == RPC_C_AUTHN_INFO_TYPE_HTTP)
        {
            const RPC_HTTP_TRANSPORT_CREDENTIALS_W *http_credentials_src = qos_src2->u.HttpCredentials;
            RPC_HTTP_TRANSPORT_CREDENTIALS_W *http_credentials_dst;

            http_credentials_dst = malloc(sizeof(*http_credentials_dst));
            qos->qos->u.HttpCredentials = http_credentials_dst;
            if (!http_credentials_dst) goto error;
            http_credentials_dst->TransportCredentials = NULL;
            http_credentials_dst->Flags = http_credentials_src->Flags;
            http_credentials_dst->AuthenticationTarget = http_credentials_src->AuthenticationTarget;
            http_credentials_dst->NumberOfAuthnSchemes = http_credentials_src->NumberOfAuthnSchemes;
            http_credentials_dst->AuthnSchemes = NULL;
            http_credentials_dst->ServerCertificateSubject = NULL;
            if (http_credentials_src->TransportCredentials)
            {
                SEC_WINNT_AUTH_IDENTITY_W *cred_dst;
                cred_dst = http_credentials_dst->TransportCredentials = calloc(1, sizeof(*cred_dst));
                if (!cred_dst) goto error;
                cred_dst->Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
                if (unicode)
                {
                    const SEC_WINNT_AUTH_IDENTITY_W *cred_src = http_credentials_src->TransportCredentials;
                    cred_dst->UserLength = cred_src->UserLength;
                    cred_dst->PasswordLength = cred_src->PasswordLength;
                    cred_dst->DomainLength = cred_src->DomainLength;
                    cred_dst->User = RPCRT4_strndupW(cred_src->User, cred_src->UserLength);
                    cred_dst->Password = RPCRT4_strndupW(cred_src->Password, cred_src->PasswordLength);
                    cred_dst->Domain = RPCRT4_strndupW(cred_src->Domain, cred_src->DomainLength);
                }
                else
                {
                    const SEC_WINNT_AUTH_IDENTITY_A *cred_src = (const SEC_WINNT_AUTH_IDENTITY_A *)http_credentials_src->TransportCredentials;
                    cred_dst->UserLength = MultiByteToWideChar(CP_ACP, 0, (char *)cred_src->User, cred_src->UserLength, NULL, 0);
                    cred_dst->DomainLength = MultiByteToWideChar(CP_ACP, 0, (char *)cred_src->Domain, cred_src->DomainLength, NULL, 0);
                    cred_dst->PasswordLength = MultiByteToWideChar(CP_ACP, 0, (char *)cred_src->Password, cred_src->PasswordLength, NULL, 0);
                    cred_dst->User = malloc(cred_dst->UserLength * sizeof(WCHAR));
                    cred_dst->Password = malloc(cred_dst->PasswordLength * sizeof(WCHAR));
                    cred_dst->Domain = malloc(cred_dst->DomainLength * sizeof(WCHAR));
                    if (!cred_dst->Password || !cred_dst->Domain) goto error;
                    MultiByteToWideChar(CP_ACP, 0, (char *)cred_src->User, cred_src->UserLength, cred_dst->User, cred_dst->UserLength);
                    MultiByteToWideChar(CP_ACP, 0, (char *)cred_src->Domain, cred_src->DomainLength, cred_dst->Domain, cred_dst->DomainLength);
                    MultiByteToWideChar(CP_ACP, 0, (char *)cred_src->Password, cred_src->PasswordLength, cred_dst->Password, cred_dst->PasswordLength);
                }
            }
            if (http_credentials_src->NumberOfAuthnSchemes)
            {
                http_credentials_dst->AuthnSchemes = malloc(http_credentials_src->NumberOfAuthnSchemes * sizeof(*http_credentials_dst->AuthnSchemes));
                if (!http_credentials_dst->AuthnSchemes) goto error;
                memcpy(http_credentials_dst->AuthnSchemes, http_credentials_src->AuthnSchemes, http_credentials_src->NumberOfAuthnSchemes * sizeof(*http_credentials_dst->AuthnSchemes));
            }
            if (http_credentials_src->ServerCertificateSubject)
            {
                if (unicode)
                    http_credentials_dst->ServerCertificateSubject =
                        RPCRT4_strndupW(http_credentials_src->ServerCertificateSubject,
                                        lstrlenW(http_credentials_src->ServerCertificateSubject));
                else
                    http_credentials_dst->ServerCertificateSubject =
                        RPCRT4_strdupAtoW((char *)http_credentials_src->ServerCertificateSubject);
                if (!http_credentials_dst->ServerCertificateSubject) goto error;
            }
        }
    }
    *qos_dst = qos;
    return RPC_S_OK;

error:
    if (qos->qos)
    {
        if (qos->qos->AdditionalSecurityInfoType == RPC_C_AUTHN_INFO_TYPE_HTTP &&
            qos->qos->u.HttpCredentials)
        {
            if (qos->qos->u.HttpCredentials->TransportCredentials)
            {
                free(qos->qos->u.HttpCredentials->TransportCredentials->User);
                free(qos->qos->u.HttpCredentials->TransportCredentials->Domain);
                free(qos->qos->u.HttpCredentials->TransportCredentials->Password);
                free(qos->qos->u.HttpCredentials->TransportCredentials);
            }
            free(qos->qos->u.HttpCredentials->AuthnSchemes);
            free(qos->qos->u.HttpCredentials->ServerCertificateSubject);
            free(qos->qos->u.HttpCredentials);
        }
        free(qos->qos);
    }
    free(qos);
    return RPC_S_OUT_OF_RESOURCES;
}

ULONG RpcQualityOfService_AddRef(RpcQualityOfService *qos)
{
    return InterlockedIncrement(&qos->refs);
}

ULONG RpcQualityOfService_Release(RpcQualityOfService *qos)
{
    ULONG refs = InterlockedDecrement(&qos->refs);

    if (!refs)
    {
        if (qos->qos->AdditionalSecurityInfoType == RPC_C_AUTHN_INFO_TYPE_HTTP)
        {
            if (qos->qos->u.HttpCredentials->TransportCredentials)
            {
                free(qos->qos->u.HttpCredentials->TransportCredentials->User);
                free(qos->qos->u.HttpCredentials->TransportCredentials->Domain);
                free(qos->qos->u.HttpCredentials->TransportCredentials->Password);
                free(qos->qos->u.HttpCredentials->TransportCredentials);
            }
            free(qos->qos->u.HttpCredentials->AuthnSchemes);
            free(qos->qos->u.HttpCredentials->ServerCertificateSubject);
            free(qos->qos->u.HttpCredentials);
        }
        free(qos->qos);
        free(qos);
    }
    return refs;
}

BOOL RpcQualityOfService_IsEqual(const RpcQualityOfService *qos1, const RpcQualityOfService *qos2)
{
    if (qos1 == qos2)
        return TRUE;

    if (!qos1 || !qos2)
        return FALSE;

    TRACE("qos1 = { %ld %ld %ld %ld }, qos2 = { %ld %ld %ld %ld }\n",
        qos1->qos->Capabilities, qos1->qos->IdentityTracking,
        qos1->qos->ImpersonationType, qos1->qos->AdditionalSecurityInfoType,
        qos2->qos->Capabilities, qos2->qos->IdentityTracking,
        qos2->qos->ImpersonationType, qos2->qos->AdditionalSecurityInfoType);

    if ((qos1->qos->Capabilities != qos2->qos->Capabilities) ||
        (qos1->qos->IdentityTracking != qos2->qos->IdentityTracking) ||
        (qos1->qos->ImpersonationType != qos2->qos->ImpersonationType) ||
        (qos1->qos->AdditionalSecurityInfoType != qos2->qos->AdditionalSecurityInfoType))
        return FALSE;

    if (qos1->qos->AdditionalSecurityInfoType == RPC_C_AUTHN_INFO_TYPE_HTTP)
    {
        const RPC_HTTP_TRANSPORT_CREDENTIALS_W *http_credentials1 = qos1->qos->u.HttpCredentials;
        const RPC_HTTP_TRANSPORT_CREDENTIALS_W *http_credentials2 = qos2->qos->u.HttpCredentials;

        if (http_credentials1->Flags != http_credentials2->Flags)
            return FALSE;

        if (http_credentials1->AuthenticationTarget != http_credentials2->AuthenticationTarget)
            return FALSE;

        if (http_credentials1->NumberOfAuthnSchemes != http_credentials2->NumberOfAuthnSchemes)
            return FALSE;

        if ((!http_credentials1->AuthnSchemes && http_credentials2->AuthnSchemes) ||
            (http_credentials1->AuthnSchemes && !http_credentials2->AuthnSchemes))
            return FALSE;

        if (memcmp(http_credentials1->AuthnSchemes, http_credentials2->AuthnSchemes,
                   http_credentials1->NumberOfAuthnSchemes * sizeof(http_credentials1->AuthnSchemes[0])))
            return FALSE;

        /* server certificate subject not currently used */

        if (http_credentials1->TransportCredentials != http_credentials2->TransportCredentials)
        {
            const SEC_WINNT_AUTH_IDENTITY_W *identity1 = http_credentials1->TransportCredentials;
            const SEC_WINNT_AUTH_IDENTITY_W *identity2 = http_credentials2->TransportCredentials;

            if (!identity1 || !identity2)
                return FALSE;

            /* compare user names */
            if (identity1->UserLength != identity2->UserLength ||
                memcmp(identity1->User, identity2->User, identity1->UserLength))
                return FALSE;
            /* compare domain names */
            if (identity1->DomainLength != identity2->DomainLength ||
                memcmp(identity1->Domain, identity2->Domain, identity1->DomainLength))
                return FALSE;
            /* compare passwords */
            if (identity1->PasswordLength != identity2->PasswordLength ||
                memcmp(identity1->Password, identity2->Password, identity1->PasswordLength))
                return FALSE;
        }
    }

    return TRUE;
}

/***********************************************************************
 *             RpcRevertToSelf (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcRevertToSelf(void)
{
    TRACE("\n");
    return RpcRevertToSelfEx(NULL);
}

/***********************************************************************
 *             RpcMgmtSetComTimeout (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcMgmtSetComTimeout(RPC_BINDING_HANDLE BindingHandle, unsigned int Timeout)
{
    FIXME("(%p, %d): stub\n", BindingHandle, Timeout);
    return RPC_S_OK;
}

/***********************************************************************
 *             RpcBindingInqAuthInfoExA (RPCRT4.@)
 */
RPCRTAPI RPC_STATUS RPC_ENTRY
RpcBindingInqAuthInfoExA( RPC_BINDING_HANDLE Binding, RPC_CSTR *ServerPrincName, ULONG *AuthnLevel,
                          ULONG *AuthnSvc, RPC_AUTH_IDENTITY_HANDLE *AuthIdentity, ULONG *AuthzSvc,
                          ULONG RpcQosVersion, RPC_SECURITY_QOS *SecurityQOS )
{
    RPC_STATUS status;
    RPC_WSTR principal;

    TRACE("%p %p %p %p %p %p %lu %p\n", Binding, ServerPrincName, AuthnLevel,
          AuthnSvc, AuthIdentity, AuthzSvc, RpcQosVersion, SecurityQOS);

    status = RpcBindingInqAuthInfoExW(Binding, ServerPrincName ? &principal : NULL, AuthnLevel,
                                      AuthnSvc, AuthIdentity, AuthzSvc, RpcQosVersion, SecurityQOS);
    if (status == RPC_S_OK && ServerPrincName)
    {
        *ServerPrincName = (RPC_CSTR)RPCRT4_strdupWtoA(principal);
        RpcStringFreeW(&principal);
        if (!*ServerPrincName) return RPC_S_OUT_OF_MEMORY;
    }

    return status;
}

/***********************************************************************
 *             RpcBindingInqAuthInfoExW (RPCRT4.@)
 */
RPCRTAPI RPC_STATUS RPC_ENTRY
RpcBindingInqAuthInfoExW( RPC_BINDING_HANDLE Binding, RPC_WSTR *ServerPrincName, ULONG *AuthnLevel,
                          ULONG *AuthnSvc, RPC_AUTH_IDENTITY_HANDLE *AuthIdentity, ULONG *AuthzSvc,
                          ULONG RpcQosVersion, RPC_SECURITY_QOS *SecurityQOS )
{
    RpcBinding *bind = Binding;

    TRACE("%p %p %p %p %p %p %lu %p\n", Binding, ServerPrincName, AuthnLevel,
          AuthnSvc, AuthIdentity, AuthzSvc, RpcQosVersion, SecurityQOS);

    if (!bind->AuthInfo) return RPC_S_BINDING_HAS_NO_AUTH;

    if (SecurityQOS)
    {
        FIXME("QOS not implemented\n");
        return RPC_S_INVALID_BINDING;
    }

    if (ServerPrincName)
    {
        if (bind->AuthInfo->server_principal_name)
        {
            *ServerPrincName = wcsdup(bind->AuthInfo->server_principal_name);
            if (!*ServerPrincName) return RPC_S_OUT_OF_MEMORY;
        }
        else *ServerPrincName = NULL;
    }
    if (AuthnLevel) *AuthnLevel = bind->AuthInfo->AuthnLevel;
    if (AuthnSvc) *AuthnSvc = bind->AuthInfo->AuthnSvc;
    if (AuthIdentity) *AuthIdentity = bind->AuthInfo->identity;
    if (AuthzSvc)
    {
        FIXME("authorization service not implemented\n");
        *AuthzSvc = RPC_C_AUTHZ_NONE;
    }

    return RPC_S_OK;
}

/***********************************************************************
 *             RpcBindingInqAuthInfoA (RPCRT4.@)
 */
RPCRTAPI RPC_STATUS RPC_ENTRY
RpcBindingInqAuthInfoA( RPC_BINDING_HANDLE Binding, RPC_CSTR *ServerPrincName, ULONG *AuthnLevel,
                        ULONG *AuthnSvc, RPC_AUTH_IDENTITY_HANDLE *AuthIdentity, ULONG *AuthzSvc )
{
    return RpcBindingInqAuthInfoExA(Binding, ServerPrincName, AuthnLevel, AuthnSvc, AuthIdentity,
                                    AuthzSvc, 0, NULL);
}

/***********************************************************************
 *             RpcBindingInqAuthInfoW (RPCRT4.@)
 */
RPCRTAPI RPC_STATUS RPC_ENTRY
RpcBindingInqAuthInfoW( RPC_BINDING_HANDLE Binding, RPC_WSTR *ServerPrincName, ULONG *AuthnLevel,
                        ULONG *AuthnSvc, RPC_AUTH_IDENTITY_HANDLE *AuthIdentity, ULONG *AuthzSvc )
{
    return RpcBindingInqAuthInfoExW(Binding, ServerPrincName, AuthnLevel, AuthnSvc, AuthIdentity,
                                    AuthzSvc, 0, NULL);
}

/***********************************************************************
 *             RpcBindingInqAuthClientA (RPCRT4.@)
 */
RPCRTAPI RPC_STATUS RPC_ENTRY
RpcBindingInqAuthClientA( RPC_BINDING_HANDLE ClientBinding, RPC_AUTHZ_HANDLE *Privs,
                          RPC_CSTR *ServerPrincName, ULONG *AuthnLevel, ULONG *AuthnSvc,
                          ULONG *AuthzSvc )
{
    return RpcBindingInqAuthClientExA(ClientBinding, Privs, ServerPrincName, AuthnLevel,
                                      AuthnSvc, AuthzSvc, 0);
}

/***********************************************************************
 *             RpcBindingInqAuthClientW (RPCRT4.@)
 */
RPCRTAPI RPC_STATUS RPC_ENTRY
RpcBindingInqAuthClientW( RPC_BINDING_HANDLE ClientBinding, RPC_AUTHZ_HANDLE *Privs,
                          RPC_WSTR *ServerPrincName, ULONG *AuthnLevel, ULONG *AuthnSvc,
                          ULONG *AuthzSvc )
{
    return RpcBindingInqAuthClientExW(ClientBinding, Privs, ServerPrincName, AuthnLevel,
                                      AuthnSvc, AuthzSvc, 0);
}

/***********************************************************************
 *             RpcBindingInqAuthClientExA (RPCRT4.@)
 */
RPCRTAPI RPC_STATUS RPC_ENTRY
RpcBindingInqAuthClientExA( RPC_BINDING_HANDLE ClientBinding, RPC_AUTHZ_HANDLE *Privs,
                            RPC_CSTR *ServerPrincName, ULONG *AuthnLevel, ULONG *AuthnSvc,
                            ULONG *AuthzSvc, ULONG Flags )
{
    RPC_STATUS status;
    RPC_WSTR principal;

    TRACE("%p %p %p %p %p %p 0x%lx\n", ClientBinding, Privs, ServerPrincName, AuthnLevel,
          AuthnSvc, AuthzSvc, Flags);

    status = RpcBindingInqAuthClientExW(ClientBinding, Privs, ServerPrincName ? &principal : NULL,
                                        AuthnLevel, AuthnSvc, AuthzSvc, Flags);
    if (status == RPC_S_OK && ServerPrincName)
    {
        *ServerPrincName = (RPC_CSTR)RPCRT4_strdupWtoA(principal);
        if (!*ServerPrincName && principal) status = RPC_S_OUT_OF_MEMORY;
        RpcStringFreeW(&principal);
    }

    return status;
}

/***********************************************************************
 *             RpcBindingInqAuthClientExW (RPCRT4.@)
 */
RPCRTAPI RPC_STATUS RPC_ENTRY
RpcBindingInqAuthClientExW( RPC_BINDING_HANDLE ClientBinding, RPC_AUTHZ_HANDLE *Privs,
                            RPC_WSTR *ServerPrincName, ULONG *AuthnLevel, ULONG *AuthnSvc,
                            ULONG *AuthzSvc, ULONG Flags )
{
    RpcBinding *bind;

    TRACE("%p %p %p %p %p %p 0x%lx\n", ClientBinding, Privs, ServerPrincName, AuthnLevel,
          AuthnSvc, AuthzSvc, Flags);

    if (!ClientBinding) ClientBinding = I_RpcGetCurrentCallHandle();
    if (!ClientBinding) return RPC_S_INVALID_BINDING;

    bind = ClientBinding;
    if (!bind->FromConn) return RPC_S_INVALID_BINDING;

    return rpcrt4_conn_inquire_auth_client(bind->FromConn, Privs,
                                           ServerPrincName, AuthnLevel,
                                           AuthnSvc, AuthzSvc, Flags);
}

/***********************************************************************
 *             RpcBindingServerFromClient (RPCRT4.@)
 */
RPCRTAPI RPC_STATUS RPC_ENTRY
RpcBindingServerFromClient(RPC_BINDING_HANDLE ClientBinding, RPC_BINDING_HANDLE* ServerBinding)
{
    RpcBinding* bind = ClientBinding;
    RpcBinding* NewBinding;

    if (!bind)
        bind = I_RpcGetCurrentCallHandle();
    if (!bind)
        return RPC_S_INVALID_BINDING;

    if (!bind->server)
        return RPC_S_INVALID_BINDING;

    RPCRT4_AllocBinding(&NewBinding, TRUE);
    NewBinding->Protseq = strdup(bind->Protseq);
    NewBinding->NetworkAddr = strdup(bind->NetworkAddr);

    *ServerBinding = NewBinding;

    return RPC_S_OK;
}

static RPC_STATUS normalize_kernel_auth_info(const RpcBinding *binding, ULONG *level, ULONG *service)
{
    if (*service != RPC_C_AUTHN_KERNEL) return RPC_S_OK;
    if (strcmp(binding->Protseq, "ncalrpc")) return RPC_S_UNKNOWN_AUTHN_SERVICE;
    if (*level > RPC_C_AUTHN_LEVEL_PKT_PRIVACY) return RPC_S_UNKNOWN_AUTHN_LEVEL;

    TRACE_(rpc_auth)("kernel authentication binding %p protseq %s level %lu -> %u service %lu -> %u\n",
          binding, debugstr_a(binding->Protseq), *level,
          *level == RPC_C_AUTHN_LEVEL_NONE ? RPC_C_AUTHN_LEVEL_NONE : RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
          *service, RPC_C_AUTHN_WINNT);
    if (*level != RPC_C_AUTHN_LEVEL_NONE) *level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
    *service = RPC_C_AUTHN_WINNT;
    return RPC_S_OK;
}

static RPC_STATUS set_ncalrpc_auth_info(RpcBinding *binding, const WCHAR *server_principal_name,
                                        ULONG authn_level, ULONG authn_svc,
                                        RPC_AUTH_IDENTITY_HANDLE identity)
{
    RpcAuthInfo *auth_info;
    CredHandle cred;
    TimeStamp exp = {0};
    RPC_STATUS status;

    SecInvalidateHandle(&cred);
    status = RpcAuthInfo_Create(authn_level, authn_svc, cred, exp, 0, identity, &auth_info);
    if (status != RPC_S_OK)
        return status;

    auth_info->transport_only = TRUE;
    auth_info->server_principal_name = server_principal_name ? wcsdup(server_principal_name) : NULL;
    if (server_principal_name && !auth_info->server_principal_name)
    {
        RpcAuthInfo_Release(auth_info);
        return RPC_S_OUT_OF_MEMORY;
    }

    if (binding->AuthInfo)
        RpcAuthInfo_Release(binding->AuthInfo);
    binding->AuthInfo = auth_info;
    return RPC_S_OK;
}

/***********************************************************************
 *             RpcBindingSetAuthInfoExA (RPCRT4.@)
 */
RPCRTAPI RPC_STATUS RPC_ENTRY
RpcBindingSetAuthInfoExA( RPC_BINDING_HANDLE Binding, RPC_CSTR ServerPrincName,
                          ULONG AuthnLevel, ULONG AuthnSvc,
                          RPC_AUTH_IDENTITY_HANDLE AuthIdentity, ULONG AuthzSvr,
                          RPC_SECURITY_QOS *SecurityQos )
{
  RpcBinding* bind = Binding;
  SECURITY_STATUS r;
  CredHandle cred;
  TimeStamp exp;
  ULONG package_count;
  ULONG i;
  PSecPkgInfoA packages;
  ULONG cbMaxToken;
  RPC_STATUS status;

  TRACE("%p %s %lu %lu %p %lu %p\n", Binding, debugstr_a((const char*)ServerPrincName),
        AuthnLevel, AuthnSvc, AuthIdentity, AuthzSvr, SecurityQos);

  if ((status = normalize_kernel_auth_info(bind, &AuthnLevel, &AuthnSvc))) return status;

  if (SecurityQos)
  {
      RPC_STATUS status;

      TRACE("SecurityQos { Version=%ld, Capabilities=0x%lx, IdentityTracking=%ld, ImpersonationLevel=%ld",
            SecurityQos->Version, SecurityQos->Capabilities, SecurityQos->IdentityTracking, SecurityQos->ImpersonationType);
      if (SecurityQos->Version >= 2)
      {
          const RPC_SECURITY_QOS_V2_A *SecurityQos2 = (const RPC_SECURITY_QOS_V2_A *)SecurityQos;
          TRACE(", AdditionalSecurityInfoType=%ld", SecurityQos2->AdditionalSecurityInfoType);
          if (SecurityQos2->AdditionalSecurityInfoType == RPC_C_AUTHN_INFO_TYPE_HTTP)
              TRACE(", { %p, 0x%lx, %ld, %ld, %p(%lu), %s }",
                    SecurityQos2->u.HttpCredentials->TransportCredentials,
                    SecurityQos2->u.HttpCredentials->Flags,
                    SecurityQos2->u.HttpCredentials->AuthenticationTarget,
                    SecurityQos2->u.HttpCredentials->NumberOfAuthnSchemes,
                    SecurityQos2->u.HttpCredentials->AuthnSchemes,
                    SecurityQos2->u.HttpCredentials->AuthnSchemes ? *SecurityQos2->u.HttpCredentials->AuthnSchemes : 0,
                    SecurityQos2->u.HttpCredentials->ServerCertificateSubject);
      }
      TRACE("}\n");
      status = RpcQualityOfService_Create(SecurityQos, FALSE, &bind->QOS);
      if (status != RPC_S_OK)
          return status;
  }
  else
  {
      if (bind->QOS) RpcQualityOfService_Release(bind->QOS);
      bind->QOS = NULL;
  }

  if (AuthnSvc == RPC_C_AUTHN_DEFAULT)
    AuthnSvc = RPC_C_AUTHN_WINNT;

  /* FIXME: the mapping should probably be retrieved using SSPI somehow */
  if (AuthnLevel == RPC_C_AUTHN_LEVEL_DEFAULT)
    AuthnLevel = RPC_C_AUTHN_LEVEL_NONE;

  if ((AuthnLevel == RPC_C_AUTHN_LEVEL_NONE) || (AuthnSvc == RPC_C_AUTHN_NONE))
  {
    if (bind->AuthInfo) RpcAuthInfo_Release(bind->AuthInfo);
    bind->AuthInfo = NULL;
    return RPC_S_OK;
  }

  if (AuthnLevel > RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
  {
    FIXME("unknown AuthnLevel %lu\n", AuthnLevel);
    return RPC_S_UNKNOWN_AUTHN_LEVEL;
  }

  /* RPC_C_AUTHN_WINNT ignores the AuthzSvr parameter */
  if (AuthzSvr && AuthnSvc != RPC_C_AUTHN_WINNT)
  {
    FIXME("unsupported AuthzSvr %lu\n", AuthzSvr);
    return RPC_S_UNKNOWN_AUTHZ_SERVICE;
  }

  if (!strcmp(bind->Protseq, "ncalrpc") && AuthnSvc == RPC_C_AUTHN_WINNT)
  {
    WCHAR *server_principal_name = RPCRT4_strdupAtoW((const char *)ServerPrincName);

    if (ServerPrincName && !server_principal_name)
      return RPC_S_OUT_OF_MEMORY;
    r = set_ncalrpc_auth_info(bind, server_principal_name, AuthnLevel,
                             AuthnSvc, AuthIdentity);
    free(server_principal_name);
    return r;
  }

  r = EnumerateSecurityPackagesA(&package_count, &packages);
  if (r != SEC_E_OK)
  {
    ERR("EnumerateSecurityPackagesA failed with error 0x%08lx\n", r);
    return RPC_S_SEC_PKG_ERROR;
  }

  for (i = 0; i < package_count; i++)
    if (packages[i].wRPCID == AuthnSvc)
        break;

  if (i == package_count)
  {
    FIXME("unsupported AuthnSvc %lu\n", AuthnSvc);
    FreeContextBuffer(packages);
    return RPC_S_UNKNOWN_AUTHN_SERVICE;
  }

  TRACE("found package %s for service %lu\n", packages[i].Name, AuthnSvc);
  r = AcquireCredentialsHandleA(NULL, packages[i].Name, SECPKG_CRED_OUTBOUND, NULL,
                                AuthIdentity, NULL, NULL, &cred, &exp);
  cbMaxToken = packages[i].cbMaxToken;
  FreeContextBuffer(packages);
  if (r == ERROR_SUCCESS)
  {
    RpcAuthInfo *new_auth_info;
    r = RpcAuthInfo_Create(AuthnLevel, AuthnSvc, cred, exp, cbMaxToken,
                           AuthIdentity, &new_auth_info);
    if (r == RPC_S_OK)
    {
      new_auth_info->server_principal_name = RPCRT4_strdupAtoW((char *)ServerPrincName);
      if (!ServerPrincName || new_auth_info->server_principal_name)
      {
        if (bind->AuthInfo) RpcAuthInfo_Release(bind->AuthInfo);
        bind->AuthInfo = new_auth_info;
      }
      else
      {
        RpcAuthInfo_Release(new_auth_info);
        r = RPC_S_OUT_OF_MEMORY;
      }
    }
    else
      FreeCredentialsHandle(&cred);
    return r;
  }
  else
  {
    ERR("AcquireCredentialsHandleA failed with error 0x%08lx\n", r);
    return RPC_S_SEC_PKG_ERROR;
  }
}

/***********************************************************************
 *             RpcBindingSetAuthInfoExW (RPCRT4.@)
 */
RPCRTAPI RPC_STATUS RPC_ENTRY
RpcBindingSetAuthInfoExW( RPC_BINDING_HANDLE Binding, RPC_WSTR ServerPrincName, ULONG AuthnLevel,
                          ULONG AuthnSvc, RPC_AUTH_IDENTITY_HANDLE AuthIdentity, ULONG AuthzSvr,
                          RPC_SECURITY_QOS *SecurityQos )
{
  RpcBinding* bind = Binding;
  SECURITY_STATUS r;
  CredHandle cred;
  TimeStamp exp;
  ULONG package_count;
  ULONG i;
  PSecPkgInfoW packages;
  ULONG cbMaxToken;
  RPC_STATUS status;

  TRACE("%p %s %lu %lu %p %lu %p\n", Binding, debugstr_w(ServerPrincName),
        AuthnLevel, AuthnSvc, AuthIdentity, AuthzSvr, SecurityQos);

  if ((status = normalize_kernel_auth_info(bind, &AuthnLevel, &AuthnSvc))) return status;

  if (SecurityQos)
  {
      RPC_STATUS status;

      TRACE("SecurityQos { Version=%ld, Capabilities=0x%lx, IdentityTracking=%ld, ImpersonationLevel=%ld",
            SecurityQos->Version, SecurityQos->Capabilities, SecurityQos->IdentityTracking, SecurityQos->ImpersonationType);
      if (SecurityQos->Version >= 2)
      {
          const RPC_SECURITY_QOS_V2_W *SecurityQos2 = (const RPC_SECURITY_QOS_V2_W *)SecurityQos;
          TRACE(", AdditionalSecurityInfoType=%ld", SecurityQos2->AdditionalSecurityInfoType);
          if (SecurityQos2->AdditionalSecurityInfoType == RPC_C_AUTHN_INFO_TYPE_HTTP)
              TRACE(", { %p, 0x%lx, %ld, %ld, %p(%lu), %s }",
                    SecurityQos2->u.HttpCredentials->TransportCredentials,
                    SecurityQos2->u.HttpCredentials->Flags,
                    SecurityQos2->u.HttpCredentials->AuthenticationTarget,
                    SecurityQos2->u.HttpCredentials->NumberOfAuthnSchemes,
                    SecurityQos2->u.HttpCredentials->AuthnSchemes,
                    SecurityQos2->u.HttpCredentials->AuthnSchemes ? *SecurityQos2->u.HttpCredentials->AuthnSchemes : 0,
                    debugstr_w(SecurityQos2->u.HttpCredentials->ServerCertificateSubject));
      }
      TRACE("}\n");
      status = RpcQualityOfService_Create(SecurityQos, TRUE, &bind->QOS);
      if (status != RPC_S_OK)
          return status;
  }
  else
  {
      if (bind->QOS) RpcQualityOfService_Release(bind->QOS);
      bind->QOS = NULL;
  }

  if (AuthnSvc == RPC_C_AUTHN_DEFAULT)
    AuthnSvc = RPC_C_AUTHN_WINNT;

  /* FIXME: the mapping should probably be retrieved using SSPI somehow */
  if (AuthnLevel == RPC_C_AUTHN_LEVEL_DEFAULT)
    AuthnLevel = RPC_C_AUTHN_LEVEL_NONE;

  if ((AuthnLevel == RPC_C_AUTHN_LEVEL_NONE) || (AuthnSvc == RPC_C_AUTHN_NONE))
  {
    if (bind->AuthInfo) RpcAuthInfo_Release(bind->AuthInfo);
    bind->AuthInfo = NULL;
    return RPC_S_OK;
  }

  if (AuthnLevel > RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
  {
    FIXME("unknown AuthnLevel %lu\n", AuthnLevel);
    return RPC_S_UNKNOWN_AUTHN_LEVEL;
  }

  /* RPC_C_AUTHN_WINNT ignores the AuthzSvr parameter */
  if (AuthzSvr && AuthnSvc != RPC_C_AUTHN_WINNT)
  {
    FIXME("unsupported AuthzSvr %lu\n", AuthzSvr);
    return RPC_S_UNKNOWN_AUTHZ_SERVICE;
  }

  if (!strcmp(bind->Protseq, "ncalrpc") && AuthnSvc == RPC_C_AUTHN_WINNT)
    return set_ncalrpc_auth_info(bind, ServerPrincName, AuthnLevel,
                                AuthnSvc, AuthIdentity);

  r = EnumerateSecurityPackagesW(&package_count, &packages);
  if (r != SEC_E_OK)
  {
    ERR("EnumerateSecurityPackagesW failed with error 0x%08lx\n", r);
    return RPC_S_SEC_PKG_ERROR;
  }

  for (i = 0; i < package_count; i++)
    if (packages[i].wRPCID == AuthnSvc)
        break;

  if (i == package_count)
  {
    FIXME("unsupported AuthnSvc %lu\n", AuthnSvc);
    FreeContextBuffer(packages);
    return RPC_S_UNKNOWN_AUTHN_SERVICE;
  }

  TRACE("found package %s for service %lu\n", debugstr_w(packages[i].Name), AuthnSvc);
  r = AcquireCredentialsHandleW(NULL, packages[i].Name, SECPKG_CRED_OUTBOUND, NULL,
                                AuthIdentity, NULL, NULL, &cred, &exp);
  cbMaxToken = packages[i].cbMaxToken;
  FreeContextBuffer(packages);
  if (r == ERROR_SUCCESS)
  {
    RpcAuthInfo *new_auth_info;
    r = RpcAuthInfo_Create(AuthnLevel, AuthnSvc, cred, exp, cbMaxToken,
                           AuthIdentity, &new_auth_info);
    if (r == RPC_S_OK)
    {
      new_auth_info->server_principal_name = wcsdup(ServerPrincName);
      if (!ServerPrincName || new_auth_info->server_principal_name)
      {
        if (bind->AuthInfo) RpcAuthInfo_Release(bind->AuthInfo);
        bind->AuthInfo = new_auth_info;
      }
      else
      {
        RpcAuthInfo_Release(new_auth_info);
        r = RPC_S_OUT_OF_MEMORY;
      }
    }
    else
      FreeCredentialsHandle(&cred);
    return r;
  }
  else
  {
    ERR("AcquireCredentialsHandleW failed with error 0x%08lx\n", r);
    return RPC_S_SEC_PKG_ERROR;
  }
}

/***********************************************************************
 *             RpcBindingSetAuthInfoA (RPCRT4.@)
 */
RPCRTAPI RPC_STATUS RPC_ENTRY
RpcBindingSetAuthInfoA( RPC_BINDING_HANDLE Binding, RPC_CSTR ServerPrincName, ULONG AuthnLevel,
                        ULONG AuthnSvc, RPC_AUTH_IDENTITY_HANDLE AuthIdentity, ULONG AuthzSvr )
{
    TRACE("%p %s %lu %lu %p %lu\n", Binding, debugstr_a((const char*)ServerPrincName),
          AuthnLevel, AuthnSvc, AuthIdentity, AuthzSvr);
    return RpcBindingSetAuthInfoExA(Binding, ServerPrincName, AuthnLevel, AuthnSvc, AuthIdentity, AuthzSvr, NULL);
}

/***********************************************************************
 *             RpcBindingSetAuthInfoW (RPCRT4.@)
 */
RPCRTAPI RPC_STATUS RPC_ENTRY
RpcBindingSetAuthInfoW( RPC_BINDING_HANDLE Binding, RPC_WSTR ServerPrincName, ULONG AuthnLevel,
                        ULONG AuthnSvc, RPC_AUTH_IDENTITY_HANDLE AuthIdentity, ULONG AuthzSvr )
{
    TRACE("%p %s %lu %lu %p %lu\n", Binding, debugstr_w(ServerPrincName),
          AuthnLevel, AuthnSvc, AuthIdentity, AuthzSvr);
    return RpcBindingSetAuthInfoExW(Binding, ServerPrincName, AuthnLevel, AuthnSvc, AuthIdentity, AuthzSvr, NULL);
}

/***********************************************************************
 *             RpcBindingSetOption (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcBindingSetOption(RPC_BINDING_HANDLE BindingHandle, ULONG Option, ULONG_PTR OptionValue)
{
    TRACE("(%p, %ld, %Id)\n", BindingHandle, Option, OptionValue);

    switch (Option)
    {
    case RPC_C_OPT_COOKIE_AUTH:
    {
        RPC_C_OPT_COOKIE_AUTH_DESCRIPTOR *cookie = (RPC_C_OPT_COOKIE_AUTH_DESCRIPTOR *)OptionValue;
        RpcBinding *binding = BindingHandle;
        int len = MultiByteToWideChar(CP_ACP, 0, cookie->Buffer, cookie->BufferSize, NULL, 0);
        WCHAR *str;

        if (!(str = malloc((len + 1) * sizeof(WCHAR)))) return RPC_S_OUT_OF_MEMORY;
        MultiByteToWideChar(CP_ACP, 0, cookie->Buffer, cookie->BufferSize, str, len);
        str[len] = 0;
        free(binding->CookieAuth);
        binding->CookieAuth = str;
        break;
    }
    default:
        FIXME("option %lu not supported\n", Option);
        break;
    }
    return RPC_S_OK;
}

/***********************************************************************
 *             I_RpcBindingInqLocalClientPID (RPCRT4.@)
 */

RPC_STATUS WINAPI I_RpcBindingInqLocalClientPID(RPC_BINDING_HANDLE ClientBinding, ULONG *ClientPID)
{
    RpcConnection *connection = NULL;
    RpcBinding *binding;

    TRACE("%p %p\n", ClientBinding, ClientPID);

    binding = ClientBinding ? ClientBinding : RPCRT4_GetThreadCurrentCallHandle();
    if (!binding)
        return RPC_S_NO_CALL_ACTIVE;

    connection = binding->FromConn;
    if (!connection->ops->inquire_client_pid)
        return RPC_S_INVALID_BINDING;

    return connection->ops->inquire_client_pid(connection, ClientPID);
}

/***********************************************************************
 *             I_RpcOpenClientProcess (RPCRT4.@)
 */
LONG WINAPI I_RpcOpenClientProcess(RPC_BINDING_HANDLE ClientBinding, ACCESS_MASK access,
                                    HANDLE *process_handle)
{
    RpcConnection *connection;
    RpcBinding *binding;
    CLIENT_ID client_id;
    RPC_STATUS status;
    ULONG pid;

    TRACE("%p %#lx %p\n", ClientBinding, access, process_handle);

    if (!process_handle) return STATUS_INVALID_PARAMETER;
    *process_handle = NULL;

    binding = ClientBinding ? ClientBinding : RPCRT4_GetThreadCurrentCallHandle();
    if (!binding) return RPC_NT_NO_CALL_ACTIVE;
    if (!(connection = binding->FromConn) || !connection->ops->inquire_client_pid)
        return RPC_NT_INVALID_BINDING;

    status = connection->ops->inquire_client_pid(connection, &pid);
    if (status != RPC_S_OK) return I_RpcMapWin32Status(status);

    client_id.UniqueProcess = ULongToHandle(pid);
    client_id.UniqueThread = 0;
    return NtOpenProcess(process_handle, access, NULL, &client_id);
}

/***********************************************************************
 *             I_RpcOpenClientThread (RPCRT4.@)
 */
LONG WINAPI I_RpcOpenClientThread(RPC_BINDING_HANDLE ClientBinding, ACCESS_MASK access,
                                   HANDLE *thread_handle)
{
    RpcBinding *binding;
    CLIENT_ID client_id;
    RPC_STATUS status;
    ULONG tid;

    TRACE("%p %#lx %p\n", ClientBinding, access, thread_handle);

    if (!thread_handle) return STATUS_INVALID_PARAMETER;
    *thread_handle = NULL;

    binding = ClientBinding ? ClientBinding : RPCRT4_GetThreadCurrentCallHandle();
    if (!binding) return RPC_NT_NO_CALL_ACTIVE;
    if (!binding->FromConn) return RPC_NT_INVALID_BINDING;

    status = RPCRT4_InquireLocalClientThreadId(binding->FromConn, &tid);
    if (status != RPC_S_OK) return I_RpcMapWin32Status(status);

    client_id.UniqueProcess = 0;
    client_id.UniqueThread = ULongToHandle(tid);
    return NtOpenThread(thread_handle, access, NULL, &client_id);
}

static ULONG get_call_protocol_sequence(const RpcBinding *binding)
{
    if (!binding->Protseq) return 0;
    if (!strcmp(binding->Protseq, "ncalrpc")) return RPC_PROTSEQ_LRPC;
    if (!strcmp(binding->Protseq, "ncacn_np")) return RPC_PROTSEQ_NMP;
    if (!strcmp(binding->Protseq, "ncacn_ip_tcp")) return RPC_PROTSEQ_TCP;
    if (!strcmp(binding->Protseq, "ncacn_http")) return RPC_PROTSEQ_HTTP;
    return 0;
}

/***********************************************************************
 *             I_RpcBindingIsClientLocal (RPCRT4.@)
 */
RPC_STATUS WINAPI I_RpcBindingIsClientLocal(RPC_BINDING_HANDLE ClientBinding,
                                             unsigned int *IsClientLocal)
{
    RpcBinding *binding;

    TRACE("%p %p\n", ClientBinding, IsClientLocal);

    if (!IsClientLocal) return RPC_S_INVALID_ARG;
    binding = ClientBinding ? ClientBinding : RPCRT4_GetThreadCurrentCallHandle();
    if (!binding) return RPC_S_NO_CALL_ACTIVE;
    if (!binding->FromConn) return RPC_S_INVALID_BINDING;

    *IsClientLocal = get_call_protocol_sequence(binding) == RPC_PROTSEQ_LRPC;
    return RPC_S_OK;
}

/***********************************************************************
 *             RpcServerInqCallAttributesW (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcServerInqCallAttributesW(RPC_BINDING_HANDLE ClientBinding,
                                               void *call_attributes)
{
    const ULONG unsupported_flags = RPC_QUERY_SERVER_PRINCIPAL_NAME |
                                    RPC_QUERY_CLIENT_PRINCIPAL_NAME |
                                    RPC_QUERY_CALL_LOCAL_ADDRESS |
                                    RPC_QUERY_CLIENT_ID;
    RPC_CALL_ATTRIBUTES_V1_W *attributes = call_attributes;
    RPC_CALL_ATTRIBUTES_V2_W *attributes_v2 = call_attributes;
    RPC_MESSAGE *message = RPCRT4_GetThreadCurrentCallMessage();
    RpcBinding *binding;
    RpcConnection *connection;
    RPC_STATUS status;
    ULONG pid = 0;

    TRACE("%p %p\n", ClientBinding, call_attributes);

    if (!attributes || attributes->Version < 1 || attributes->Version > 3)
        return RPC_S_INVALID_ARG;
    if (attributes->Flags & unsupported_flags) return RPC_S_CANNOT_SUPPORT;

    binding = ClientBinding ? ClientBinding : RPCRT4_GetThreadCurrentCallHandle();
    if (!binding) return RPC_S_NO_CALL_ACTIVE;
    if (!(connection = binding->FromConn)) return RPC_S_INVALID_BINDING;

    status = rpcrt4_conn_inquire_auth_client(connection, NULL, NULL,
                                              &attributes->AuthenticationLevel,
                                              &attributes->AuthenticationService,
                                              NULL, 0);
    if (status != RPC_S_OK && !(attributes->Flags & RPC_QUERY_NO_AUTH_REQUIRED))
        return status;
    if (status != RPC_S_OK)
    {
        attributes->AuthenticationLevel = RPC_C_AUTHN_LEVEL_NONE;
        attributes->AuthenticationService = RPC_C_AUTHN_NONE;
    }
    attributes->NullSession = FALSE;

    if (attributes->Version == 1) return RPC_S_OK;

    attributes_v2->KernelModeCaller = FALSE;
    attributes_v2->ProtocolSequence = get_call_protocol_sequence(binding);
    attributes_v2->IsClientLocal = attributes_v2->ProtocolSequence == RPC_PROTSEQ_LRPC ?
                                   rcclLocal : rcclClientUnknownLocality;
    attributes_v2->CallStatus = 0;
    attributes_v2->CallType = rctNormal;

    if (attributes->Flags & RPC_QUERY_CLIENT_PID)
    {
        if (!connection->ops->inquire_client_pid) return RPC_S_INVALID_BINDING;
        status = connection->ops->inquire_client_pid(connection, &pid);
        if (status != RPC_S_OK) return status;
        attributes_v2->ClientPID = ULongToHandle(pid);
    }

    if (message)
    {
        const RPC_SERVER_INTERFACE *server_if = message->RpcInterfaceInformation;

        attributes_v2->OpNum = message->ProcNum;
        if (server_if) attributes_v2->InterfaceUuid = server_if->InterfaceId.SyntaxGUID;
    }
    return RPC_S_OK;
}

/***********************************************************************
 *             I_RpcBindingInqClientTokenAttributes (RPCRT4.@)
 */
RPC_STATUS WINAPI I_RpcBindingInqClientTokenAttributes(RPC_BINDING_HANDLE ClientBinding,
                                                        LUID *TokenId,
                                                        LUID *AuthenticationId,
                                                        LUID *ModifiedId)
{
    TOKEN_STATISTICS statistics;
    RpcBinding *binding;
    RPC_STATUS status;
    DWORD size, error;
    HANDLE token;

    TRACE("%p %p %p %p\n", ClientBinding, TokenId, AuthenticationId, ModifiedId);

    binding = ClientBinding ? ClientBinding : RPCRT4_GetThreadCurrentCallHandle();
    if (!binding)
        return RPC_S_NO_CALL_ACTIVE;
    if (!binding->FromConn)
        return RPC_S_INVALID_BINDING;

    status = rpcrt4_conn_impersonate_client(binding->FromConn);
    if (status != RPC_S_OK)
        return ERROR_ACCESS_DENIED;

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token))
    {
        error = GetLastError();
    }
    else
    {
        if (GetTokenInformation(token, TokenStatistics, &statistics, sizeof(statistics), &size))
        {
            if (TokenId) *TokenId = statistics.TokenId;
            if (AuthenticationId) *AuthenticationId = statistics.AuthenticationId;
            if (ModifiedId) *ModifiedId = statistics.ModifiedId;
            error = ERROR_SUCCESS;
        }
        else
        {
            error = GetLastError();
        }
        CloseHandle(token);
    }

    status = rpcrt4_conn_revert_to_self(binding->FromConn);
    if (error == ERROR_SUCCESS && status != RPC_S_OK)
        error = ERROR_ACCESS_DENIED;

    return error;
}
