/*
 * RPC server API
 *
 * Copyright 2001 Ove Kåven, TransGaming Technologies
 * Copyright 2004 Filip Navara
 * Copyright 2006-2008 Robert Shearman (for CodeWeavers)
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

#include "windef.h"
#include "winbase.h"
#include "winerror.h"

#include "rpc.h"
#include "rpcasync.h"
#include "rpcndr.h"
#include "excpt.h"

#include "wine/debug.h"
#include "wine/exception.h"

#include "rpc_server.h"
#include "rpc_assoc.h"
#include "rpc_message.h"
#include "rpc_defs.h"
#include "ncastatus.h"
#include "secext.h"

WINE_DEFAULT_DEBUG_CHANNEL(rpc);

typedef struct _RpcPacket
{
  struct _RpcConnection* conn;
  RpcPktHdr* hdr;
  RPC_MESSAGE* msg;
  unsigned char *auth_data;
  ULONG auth_length;
} RpcPacket;

typedef struct _RpcObjTypeMap
{
  /* FIXME: a hash table would be better. */
  struct _RpcObjTypeMap *next;
  UUID Object;
  UUID Type;
} RpcObjTypeMap;

static RpcObjTypeMap *RpcObjTypeMaps;

/* list of type RpcServerProtseq */
static struct list protseqs = LIST_INIT(protseqs);
static struct list server_interfaces = LIST_INIT(server_interfaces);
static struct list server_registered_auth_info = LIST_INIT(server_registered_auth_info);

static CRITICAL_SECTION server_cs;
static CRITICAL_SECTION_DEBUG server_cs_debug =
{
    0, 0, &server_cs,
    { &server_cs_debug.ProcessLocksList, &server_cs_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": server_cs") }
};
static CRITICAL_SECTION server_cs = { &server_cs_debug, -1, 0, 0, 0, 0 };

static CRITICAL_SECTION listen_cs;
static CRITICAL_SECTION_DEBUG listen_cs_debug =
{
    0, 0, &listen_cs,
    { &listen_cs_debug.ProcessLocksList, &listen_cs_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": listen_cs") }
};
static CRITICAL_SECTION listen_cs = { &listen_cs_debug, -1, 0, 0, 0, 0 };

static CRITICAL_SECTION server_auth_info_cs;
static CRITICAL_SECTION_DEBUG server_auth_info_cs_debug =
{
    0, 0, &server_auth_info_cs,
    { &server_auth_info_cs_debug.ProcessLocksList, &server_auth_info_cs_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": server_auth_info_cs") }
};
static CRITICAL_SECTION server_auth_info_cs = { &server_auth_info_cs_debug, -1, 0, 0, 0, 0 };

/* whether the server is currently listening */
static BOOL std_listen;
/* total listeners including auto listeners */
static LONG listen_count;
/* event set once all manual listening is finished */
static HANDLE listen_done_event;
/* Whether server dispatch exceptions should escape the RPC runtime. */
static LONG server_exception_filter_disabled;
/* Process-local mode exposed by I_RpcSystemFunction001 selectors 3 and 4. */
static ULONG rpc_process_mode;
static RPC_FORWARD_FUNCTION server_forward_function;
static void *server_address_change_fn;

struct rpc_server_notification
{
    BOOL subscribed;
    BOOL delivered;
    RPC_NOTIFICATION_TYPES type;
    RPC_ASYNC_NOTIFICATION_INFO info;
    ULONG queued;
};

struct rpc_server_call
{
    LONG refs;
    CRITICAL_SECTION cs;
    struct list entry;
    RpcConnection *connection;
    RpcBinding *binding;
    RPC_ASYNC_STATE *async;
    ULONG call_id;
    BOOL disconnected;
    BOOL cancelled;
    struct rpc_server_notification notifications[2];
};

struct rpc_server_notification_work
{
    struct rpc_server_call *call;
    RPC_ASYNC_NOTIFICATION_INFO info;
    RPC_ASYNC_STATE *handle;
    RPC_NOTIFICATION_TYPES type;
    RPC_ASYNC_EVENT event;
};

struct rpc_port_allocation_data
{
    ULONG unknown0;
    ULONG unknown4;
    ULONG unknown8;
    ULONG unknownc;
    void *unknown10;
    void *unknown18;
};

static void rpc_server_call_release(struct rpc_server_call *call)
{
    RpcConnection *connection;

    connection = call->connection;
    EnterCriticalSection(&connection->server_calls_cs);
    if (InterlockedDecrement(&call->refs))
    {
        LeaveCriticalSection(&connection->server_calls_cs);
        return;
    }
    list_remove(&call->entry);
    LeaveCriticalSection(&connection->server_calls_cs);
    call->binding->server_call = NULL;
    RPCRT4_ReleaseBinding(call->binding);
    call->cs.DebugInfo->Spare[0] = 0;
    DeleteCriticalSection(&call->cs);
    free(call);
    RPCRT4_ReleaseConnection(connection);
}

static RPC_STATUS rpc_server_call_create(RpcConnection *connection,
                                         ULONG call_id,
                                         struct rpc_server_call **call_out)
{
    struct rpc_server_call *call;
    RPC_STATUS status;

    if (!(call = calloc(1, sizeof(*call)))) return RPC_S_OUT_OF_RESOURCES;

    call->refs = 1;
    call->connection = RPCRT4_GrabConnection(connection);
    call->call_id = call_id;
    InitializeCriticalSectionEx(&call->cs, 0, RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO);
    call->cs.DebugInfo->Spare[0] = (DWORD_PTR)(__FILE__ ": rpc_server_call.cs");

    if (!connection->server_binding || !connection->server_binding->Assoc)
        status = RPC_S_INVALID_BINDING;
    else
        status = RPCRT4_MakeBinding(&call->binding, connection);
    if (status == RPC_S_OK)
        status = RpcServerAssoc_GetAssociation(rpcrt4_conn_get_name(connection),
                                               connection->NetworkAddr, connection->Endpoint,
                                               connection->NetworkOptions,
                                               connection->server_binding->Assoc->assoc_group_id,
                                               &call->binding->Assoc);
    if (status != RPC_S_OK)
    {
        if (call->binding) RPCRT4_ReleaseBinding(call->binding);
        call->cs.DebugInfo->Spare[0] = 0;
        DeleteCriticalSection(&call->cs);
        RPCRT4_ReleaseConnection(call->connection);
        free(call);
        return status;
    }

    call->binding->server_call = call;
    EnterCriticalSection(&connection->server_calls_cs);
    call->disconnected = connection->server_disconnected;
    list_add_tail(&connection->server_calls, &call->entry);
    LeaveCriticalSection(&connection->server_calls_cs);
    *call_out = call;
    return RPC_S_OK;
}

static void rpc_server_notification_work_release(struct rpc_server_notification_work *work)
{
    rpc_server_call_release(work->call);
    free(work);
}

static void CALLBACK rpc_server_notification_apc(ULONG_PTR param)
{
    struct rpc_server_notification_work *work = (void *)param;

    work->info.APC.NotificationRoutine(work->handle, NULL, work->event);
    rpc_server_notification_work_release(work);
}

static DWORD CALLBACK rpc_server_notification_worker(void *param)
{
    struct rpc_server_notification_work *work = param;

    switch (work->type)
    {
    case RpcNotificationTypeEvent:
        SetEvent(work->info.hEvent);
        break;
    case RpcNotificationTypeApc:
        if (QueueUserAPC(rpc_server_notification_apc, work->info.APC.hThread,
                         (ULONG_PTR)work))
            return 0;
        break;
    case RpcNotificationTypeIoc:
        PostQueuedCompletionStatus(work->info.IOC.hIOPort,
                                   work->info.IOC.dwNumberOfBytesTransferred,
                                   work->info.IOC.dwCompletionKey,
                                   work->info.IOC.lpOverlapped);
        break;
    case RpcNotificationTypeHwnd:
        PostMessageW(work->info.HWND.hWnd, work->info.HWND.Msg, 0, 0);
        break;
    case RpcNotificationTypeCallback:
        work->info.NotificationRoutine(work->handle, NULL, work->event);
        break;
    default:
        break;
    }

    rpc_server_notification_work_release(work);
    return 0;
}

static void rpc_server_call_queue_notification(struct rpc_server_call *call,
                                               RPC_NOTIFICATIONS notification)
{
    struct rpc_server_notification_work *work;
    struct rpc_server_notification *state;
    unsigned int index = notification - RpcNotificationClientDisconnect;

    if (index >= ARRAY_SIZE(call->notifications)) return;

    EnterCriticalSection(&call->cs);
    state = &call->notifications[index];
    if (!state->subscribed || state->delivered)
    {
        LeaveCriticalSection(&call->cs);
        return;
    }

    if (!(work = malloc(sizeof(*work))))
    {
        ERR("failed to allocate notification work for call %p\n", call);
        LeaveCriticalSection(&call->cs);
        return;
    }

    InterlockedIncrement(&call->refs);
    work->call = call;
    work->info = state->info;
    work->handle = call->async ? call->async : (RPC_ASYNC_STATE *)call->binding;
    work->type = state->type;
    work->event = notification == RpcNotificationClientDisconnect
                  ? RpcClientDisconnect : RpcClientCancel;
    state->delivered = TRUE;
    ++state->queued;
    if (!QueueUserWorkItem(rpc_server_notification_worker, work, WT_EXECUTEDEFAULT))
    {
        ERR("failed to queue notification work for call %p, error %lu\n",
            call, GetLastError());
        state->delivered = FALSE;
        --state->queued;
        InterlockedDecrement(&call->refs);
        free(work);
    }
    LeaveCriticalSection(&call->cs);
}

static RPC_STATUS rpc_server_call_from_binding(RPC_BINDING_HANDLE binding_handle,
                                               struct rpc_server_call **call_out)
{
    RpcBinding *binding = binding_handle ? binding_handle : RPCRT4_GetThreadCurrentCallHandle();

    if (!binding) return RPC_S_NO_CALL_ACTIVE;
    if (!binding->server || !binding->FromConn) return RPC_S_INVALID_BINDING;
    if (!binding->server_call) return RPC_S_NO_CALL_ACTIVE;
    *call_out = binding->server_call;
    return RPC_S_OK;
}

void RPCRT4_ServerConnectionClosed(RpcConnection *connection)
{
    struct rpc_server_call *call;

    EnterCriticalSection(&connection->server_calls_cs);
    if (!connection->server_disconnected)
    {
        connection->server_disconnected = TRUE;
        LIST_FOR_EACH_ENTRY(call, &connection->server_calls, struct rpc_server_call, entry)
        {
            EnterCriticalSection(&call->cs);
            call->disconnected = TRUE;
            LeaveCriticalSection(&call->cs);
            rpc_server_call_queue_notification(call, RpcNotificationClientDisconnect);
        }
    }
    LeaveCriticalSection(&connection->server_calls_cs);
}

void RPCRT4_ServerCallCancelled(RpcConnection *connection, ULONG call_id)
{
    struct rpc_server_call *call;

    EnterCriticalSection(&connection->server_calls_cs);
    LIST_FOR_EACH_ENTRY(call, &connection->server_calls, struct rpc_server_call, entry)
    {
        if (call->call_id != call_id) continue;
        EnterCriticalSection(&call->cs);
        call->cancelled = TRUE;
        LeaveCriticalSection(&call->cs);
        rpc_server_call_queue_notification(call, RpcNotificationCallCancel);
        break;
    }
    LeaveCriticalSection(&connection->server_calls_cs);
}

struct rpc_server_call *RPCRT4_AsyncServerCallStart(RPC_ASYNC_STATE *async)
{
    RpcBinding *binding = RPCRT4_GetThreadCurrentCallHandle();
    struct rpc_server_call *call;

    if (!binding || !(call = binding->server_call)) return NULL;

    EnterCriticalSection(&call->cs);
    if (call->async)
    {
        LeaveCriticalSection(&call->cs);
        return NULL;
    }
    InterlockedIncrement(&call->refs);
    call->async = async;
    async->RuntimeInfo = binding;
    LeaveCriticalSection(&call->cs);
    return call;
}

void RPCRT4_AsyncServerCallFinish(struct rpc_server_call *call, RPC_ASYNC_STATE *async)
{
    unsigned int i;

    if (!call) return;

    EnterCriticalSection(&call->cs);
    if (call->async == async)
    {
        for (i = 0; i < ARRAY_SIZE(call->notifications); ++i)
            if (call->notifications[i].subscribed)
                WARN("async call %p completed with notification %u still subscribed\n", async, i + 1);
        call->async = NULL;
        async->RuntimeInfo = NULL;
    }
    LeaveCriticalSection(&call->cs);
    rpc_server_call_release(call);
}

static UUID uuid_nil;

static inline RpcObjTypeMap *LookupObjTypeMap(UUID *ObjUuid)
{
  RpcObjTypeMap *rslt = RpcObjTypeMaps;
  RPC_STATUS dummy;

  while (rslt) {
    if (! UuidCompare(ObjUuid, &rslt->Object, &dummy)) break;
    rslt = rslt->next;
  }

  return rslt;
}

static inline UUID *LookupObjType(UUID *ObjUuid)
{
  RpcObjTypeMap *map = LookupObjTypeMap(ObjUuid);
  if (map)
    return &map->Type;
  else
    return &uuid_nil;
}

static RpcServerInterface* RPCRT4_find_interface(UUID* object,
                                                 const RPC_SYNTAX_IDENTIFIER *if_id,
                                                 const RPC_SYNTAX_IDENTIFIER *transfer_syntax,
                                                 BOOL check_object)
{
  UUID* MgrType = NULL;
  RpcServerInterface* cif;
  RPC_STATUS status;

  if (check_object)
    MgrType = LookupObjType(object);
  EnterCriticalSection(&server_cs);
  LIST_FOR_EACH_ENTRY(cif, &server_interfaces, RpcServerInterface, entry) {
    if (!memcmp(if_id, &cif->If->InterfaceId, sizeof(RPC_SYNTAX_IDENTIFIER)) &&
        (!transfer_syntax || !memcmp(transfer_syntax, &cif->If->TransferSyntax, sizeof(RPC_SYNTAX_IDENTIFIER))) &&
        (check_object == FALSE || UuidEqual(MgrType, &cif->MgrTypeUuid, &status)) &&
        std_listen) {
      InterlockedIncrement(&cif->CurrentCalls);
      break;
    }
  }
  LeaveCriticalSection(&server_cs);
  if (&cif->entry == &server_interfaces) cif = NULL;
  TRACE("returning %p for object %s, if_id { %d.%d %s }\n", cif,
    debugstr_guid(object), if_id->SyntaxVersion.MajorVersion,
    if_id->SyntaxVersion.MinorVersion, debugstr_guid(&if_id->SyntaxGUID));
  return cif;
}

static void RPCRT4_release_server_interface(RpcServerInterface *sif)
{
  if (!InterlockedDecrement(&sif->CurrentCalls) &&
      sif->Delete) {
    /* sif must have been removed from server_interfaces before
     * CallsCompletedEvent is set */
    if (sif->CallsCompletedEvent)
      SetEvent(sif->CallsCompletedEvent);
    free(sif);
  }
}

static RpcPktHdr *handle_bind_error(RpcConnection *conn, RPC_STATUS error)
{
    unsigned int reject_reason;
    switch (error)
    {
    case RPC_S_SERVER_TOO_BUSY:
        reject_reason = REJECT_TEMPORARY_CONGESTION;
        break;
    case ERROR_OUTOFMEMORY:
    case RPC_S_OUT_OF_RESOURCES:
        reject_reason = REJECT_LOCAL_LIMIT_EXCEEDED;
        break;
    case RPC_S_PROTOCOL_ERROR:
        reject_reason = REJECT_PROTOCOL_VERSION_NOT_SUPPORTED;
        break;
    case RPC_S_UNKNOWN_AUTHN_SERVICE:
        reject_reason = REJECT_UNKNOWN_AUTHN_SERVICE;
        break;
    case ERROR_ACCESS_DENIED:
        reject_reason = REJECT_INVALID_CHECKSUM;
        break;
    default:
        FIXME("unexpected status value %ld\n", error);
        /* fall through */
    case RPC_S_INVALID_BOUND:
        reject_reason = REJECT_REASON_NOT_SPECIFIED;
        break;
    }
    return RPCRT4_BuildBindNackHeader(NDR_LOCAL_DATA_REPRESENTATION,
                                      RPC_VER_MAJOR, RPC_VER_MINOR,
                                      reject_reason);
}

static RPC_STATUS process_bind_packet_no_send(
    RpcConnection *conn, RpcPktBindHdr *hdr, RPC_MESSAGE *msg,
    unsigned char *auth_data, ULONG auth_length, RpcPktHdr **ack_response,
    unsigned char **auth_data_out, ULONG *auth_length_out)
{
  RPC_STATUS status;
  RpcContextElement *ctxt_elem;
  unsigned int i;
  RpcResult *results;

  /* validate data */
  for (i = 0, ctxt_elem = msg->Buffer;
       i < hdr->num_elements;
       i++, ctxt_elem = (RpcContextElement *)&ctxt_elem->transfer_syntaxes[ctxt_elem->num_syntaxes])
  {
      if (((char *)ctxt_elem - (char *)msg->Buffer) > msg->BufferLength ||
          ((char *)&ctxt_elem->transfer_syntaxes[ctxt_elem->num_syntaxes] - (char *)msg->Buffer) > msg->BufferLength)
      {
          ERR("inconsistent data in packet - packet length %d, num elements %d\n",
              msg->BufferLength, hdr->num_elements);
          return RPC_S_INVALID_BOUND;
      }
  }

  if (hdr->max_tsize < RPC_MIN_PACKET_SIZE ||
      !UuidIsNil(&conn->ActiveInterface.SyntaxGUID, &status) ||
      conn->server_binding)
  {
    TRACE("packet size less than min size, or active interface syntax guid non-null\n");

    return RPC_S_INVALID_BOUND;
  }

  results = malloc(hdr->num_elements * sizeof(*results));
  if (!results)
    return RPC_S_OUT_OF_RESOURCES;

  for (i = 0, ctxt_elem = (RpcContextElement *)msg->Buffer;
       i < hdr->num_elements;
       i++, ctxt_elem = (RpcContextElement *)&ctxt_elem->transfer_syntaxes[ctxt_elem->num_syntaxes])
  {
      RpcServerInterface* sif = NULL;
      unsigned int j;

      for (j = 0; !sif && j < ctxt_elem->num_syntaxes; j++)
      {
          sif = RPCRT4_find_interface(NULL, &ctxt_elem->abstract_syntax,
                                      &ctxt_elem->transfer_syntaxes[j], FALSE);
          if (sif)
              break;
      }
      if (sif)
      {
          RPCRT4_release_server_interface(sif);
          TRACE("accepting bind request on connection %p for %s\n", conn,
                debugstr_guid(&ctxt_elem->abstract_syntax.SyntaxGUID));
          results[i].result = RESULT_ACCEPT;
          results[i].reason = REASON_NONE;
          results[i].transfer_syntax = ctxt_elem->transfer_syntaxes[j];

          /* save the interface for later use */
          /* FIXME: save linked list */
          conn->ActiveInterface = ctxt_elem->abstract_syntax;
      }
      else if ((sif = RPCRT4_find_interface(NULL, &ctxt_elem->abstract_syntax,
                                            NULL, FALSE)) != NULL)
      {
          RPCRT4_release_server_interface(sif);
          TRACE("not accepting bind request on connection %p for %s - no transfer syntaxes supported\n",
                conn, debugstr_guid(&ctxt_elem->abstract_syntax.SyntaxGUID));
          results[i].result = RESULT_PROVIDER_REJECTION;
          results[i].reason = REASON_TRANSFER_SYNTAXES_NOT_SUPPORTED;
          memset(&results[i].transfer_syntax, 0, sizeof(results[i].transfer_syntax));
      }
      else
      {
          TRACE("not accepting bind request on connection %p for %s - abstract syntax not supported\n",
                conn, debugstr_guid(&ctxt_elem->abstract_syntax.SyntaxGUID));
          results[i].result = RESULT_PROVIDER_REJECTION;
          results[i].reason = REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED;
          memset(&results[i].transfer_syntax, 0, sizeof(results[i].transfer_syntax));
      }
  }

  /* create temporary binding */
  status = RPCRT4_MakeBinding(&conn->server_binding, conn);
  if (status != RPC_S_OK)
  {
      free(results);
      return status;
  }

  status = RpcServerAssoc_GetAssociation(rpcrt4_conn_get_name(conn),
                                         conn->NetworkAddr, conn->Endpoint,
                                         conn->NetworkOptions,
                                         hdr->assoc_gid,
                                         &conn->server_binding->Assoc);
  if (status != RPC_S_OK)
  {
      free(results);
      return status;
  }

  if (auth_length)
  {
      status = RPCRT4_ServerConnectionAuth(conn, TRUE,
                                           (RpcAuthVerifier *)auth_data,
                                           auth_length, auth_data_out,
                                           auth_length_out);
      if (status != RPC_S_OK)
      {
          free(results);
          return status;
      }
  }

  *ack_response = RPCRT4_BuildBindAckHeader(NDR_LOCAL_DATA_REPRESENTATION,
                                            RPC_MAX_PACKET_SIZE,
                                            RPC_MAX_PACKET_SIZE,
                                            conn->server_binding->Assoc->assoc_group_id,
                                            conn->Endpoint, hdr->num_elements,
                                            results);
  free(results);

  if (*ack_response)
      conn->MaxTransmissionSize = hdr->max_tsize;
  else
      status = RPC_S_OUT_OF_RESOURCES;

  return status;
}

static RPC_STATUS process_bind_packet(RpcConnection *conn, RpcPktBindHdr *hdr,
                                      RPC_MESSAGE *msg,
                                      unsigned char *auth_data,
                                      ULONG auth_length)
{
    RPC_STATUS status;
    RpcPktHdr *response = NULL;
    unsigned char *auth_data_out = NULL;
    ULONG auth_length_out = 0;

    status = process_bind_packet_no_send(conn, hdr, msg, auth_data, auth_length,
                                         &response, &auth_data_out,
                                         &auth_length_out);
    if (status != RPC_S_OK)
        response = handle_bind_error(conn, status);
    if (response)
        status = RPCRT4_SendWithAuth(conn, response, NULL, 0, auth_data_out, auth_length_out);
    else
        status = ERROR_OUTOFMEMORY;
    free(response);

    return status;
}


static RPC_STATUS process_request_packet(RpcConnection *conn, RpcPktRequestHdr *hdr, RPC_MESSAGE *msg)
{
  RPC_STATUS status;
  RpcPktHdr *response = NULL;
  RpcServerInterface* sif;
  struct rpc_server_call *call;
  RPC_DISPATCH_FUNCTION func;
  BOOL exception;
  UUID *object_uuid;
  NDR_SCONTEXT context_handle;
  void *buf = msg->Buffer;

  /* fail if the connection isn't bound with an interface */
  if (UuidIsNil(&conn->ActiveInterface.SyntaxGUID, &status)) {
    /* FIXME: should send BindNack instead */
    response = RPCRT4_BuildFaultHeader(NDR_LOCAL_DATA_REPRESENTATION,
                                       status);

    RPCRT4_Send(conn, response, NULL, 0);
    free(response);
    return RPC_S_OK;
  }

  if (hdr->common.flags & RPC_FLG_OBJECT_UUID) {
    object_uuid = (UUID*)(hdr + 1);
  } else {
    object_uuid = NULL;
  }

  sif = RPCRT4_find_interface(object_uuid, &conn->ActiveInterface, NULL, TRUE);
  if (!sif) {
    WARN("interface %s no longer registered, returning fault packet\n", debugstr_guid(&conn->ActiveInterface.SyntaxGUID));
    response = RPCRT4_BuildFaultHeader(NDR_LOCAL_DATA_REPRESENTATION,
                                       NCA_S_UNK_IF);

    RPCRT4_Send(conn, response, NULL, 0);
    free(response);
    return RPC_S_OK;
  }
  status = rpc_server_call_create(conn, hdr->common.call_id, &call);
  if (status != RPC_S_OK)
  {
    response = RPCRT4_BuildFaultHeader(NDR_LOCAL_DATA_REPRESENTATION,
                                       RPC2NCA_STATUS(status));
    if (response)
    {
      RPCRT4_Send(conn, response, NULL, 0);
      free(response);
    }
    RPCRT4_release_server_interface(sif);
    return RPC_S_OK;
  }
  msg->Handle = (RPC_BINDING_HANDLE)call->binding;
  msg->RpcInterfaceInformation = sif->If;
  /* copy the endpoint vector from sif to msg so that midl-generated code will use it */
  msg->ManagerEpv = sif->MgrEpv;
  if (object_uuid != NULL) {
    RPCRT4_SetBindingObject(msg->Handle, object_uuid);
  }

  /* find dispatch function */
  msg->ProcNum = hdr->opnum;
  if (sif->Flags & RPC_IF_OLE) {
    /* native ole32 always gives us a dispatch table with a single entry
    * (I assume that's a wrapper for IRpcStubBuffer::Invoke) */
    func = *sif->If->DispatchTable->DispatchTable;
  } else {
    if (msg->ProcNum >= sif->If->DispatchTable->DispatchTableCount) {
      WARN("invalid procnum (%d/%d)\n", msg->ProcNum, sif->If->DispatchTable->DispatchTableCount);
      response = RPCRT4_BuildFaultHeader(NDR_LOCAL_DATA_REPRESENTATION,
                                         NCA_S_OP_RNG_ERROR);

      RPCRT4_Send(conn, response, NULL, 0);
      free(response);
    }
    func = sif->If->DispatchTable->DispatchTable[msg->ProcNum];
  }

  /* put in the drep. FIXME: is this more universally applicable?
    perhaps we should move this outward... */
  msg->DataRepresentation =
    MAKELONG( MAKEWORD(hdr->common.drep[0], hdr->common.drep[1]),
              MAKEWORD(hdr->common.drep[2], hdr->common.drep[3]));
  msg->ReservedForRuntime = conn;

  exception = FALSE;

  /* dispatch */
  RPCRT4_SetThreadCurrentCallHandle(msg->Handle);
  RPCRT4_SetThreadCurrentCallMessage(msg);
  if (InterlockedCompareExchange(&server_exception_filter_disabled, 0, 0))
  {
    if (func) func(msg);
  }
  else
  {
    __TRY {
      if (func) func(msg);
    } __EXCEPT_ALL {
      WARN("exception caught with code 0x%08lx = %ld\n", GetExceptionCode(), GetExceptionCode());
      exception = TRUE;
      if (GetExceptionCode() == STATUS_ACCESS_VIOLATION)
        status = ERROR_NOACCESS;
      else
        status = GetExceptionCode();
      response = RPCRT4_BuildFaultHeader(msg->DataRepresentation,
                                         RPC2NCA_STATUS(status));
    } __ENDTRY
  }
    RPCRT4_SetThreadCurrentCallMessage(NULL);
    RPCRT4_SetThreadCurrentCallHandle(NULL);

  /* release any unmarshalled context handles */
  while ((context_handle = RPCRT4_PopThreadContextHandle()) != NULL)
    RpcServerAssoc_ReleaseContextHandle(conn->server_binding->Assoc, context_handle, TRUE);

  if (!exception && !(msg->RpcFlags & RPC_BUFFER_ASYNC))
    response = RPCRT4_BuildResponseHeader(msg->DataRepresentation,
                                          msg->BufferLength);

  /* send response packet */
  if (response) {
    status = RPCRT4_Send(conn, response, exception ? NULL : msg->Buffer,
                         exception ? 0 : msg->BufferLength);
    free(response);
  } else if (!(msg->RpcFlags & RPC_BUFFER_ASYNC))
    ERR("out of memory\n");

  msg->RpcInterfaceInformation = NULL;
  RPCRT4_release_server_interface(sif);

  if ((msg->RpcFlags & RPC_BUFFER_ASYNC) || msg->Buffer == buf) buf = NULL;
  TRACE("freeing Buffer=%p\n", buf);
  I_RpcFree(buf);
  rpc_server_call_release(call);

  return status;
}

static RPC_STATUS process_auth3_packet(RpcConnection *conn,
                                       RpcPktCommonHdr *hdr,
                                       RPC_MESSAGE *msg,
                                       unsigned char *auth_data,
                                       ULONG auth_length)
{
    RPC_STATUS status;

    if (UuidIsNil(&conn->ActiveInterface.SyntaxGUID, &status) ||
        !auth_length || msg->BufferLength != 0)
        status = RPC_S_PROTOCOL_ERROR;
    else
    {
        status = RPCRT4_ServerConnectionAuth(conn, FALSE,
                                             (RpcAuthVerifier *)auth_data,
                                             auth_length, NULL, NULL);
    }

    /* FIXME: client doesn't expect a response to this message so must store
     * status in connection so that fault packet can be returned when next
     * packet is received */

    return RPC_S_OK;
}

static void RPCRT4_process_packet(RpcConnection* conn, RpcPktHdr* hdr,
                                  RPC_MESSAGE* msg, unsigned char *auth_data,
                                  ULONG auth_length)
{
  msg->Handle = (RPC_BINDING_HANDLE)conn->server_binding;

  switch (hdr->common.ptype) {
    case PKT_BIND:
      TRACE("got bind packet\n");
      process_bind_packet(conn, &hdr->bind, msg, auth_data, auth_length);
      break;

    case PKT_REQUEST:
      TRACE("got request packet\n");
      process_request_packet(conn, &hdr->request, msg);
      break;

    case PKT_AUTH3:
      TRACE("got auth3 packet\n");
      process_auth3_packet(conn, &hdr->common, msg, auth_data, auth_length);
      break;
    default:
      FIXME("unhandled packet type %u\n", hdr->common.ptype);
      break;
  }

  /* clean up */
  I_RpcFree(msg->Buffer);
  free(hdr);
  free(msg);
  free(auth_data);
}

static DWORD CALLBACK RPCRT4_worker_thread(LPVOID the_arg)
{
  RpcPacket *pkt = the_arg;
  RPCRT4_process_packet(pkt->conn, pkt->hdr, pkt->msg, pkt->auth_data,
                        pkt->auth_length);
  RPCRT4_ReleaseConnection(pkt->conn);
  free(pkt);
  return 0;
}

static DWORD CALLBACK RPCRT4_io_thread(LPVOID the_arg)
{
  RpcConnection* conn = the_arg;
  RpcPktHdr *hdr;
  RPC_MESSAGE *msg;
  RPC_STATUS status;
  RpcPacket *packet;
  unsigned char *auth_data;
  ULONG auth_length;

  TRACE("(%p)\n", conn);
  SetThreadDescription(GetCurrentThread(), L"wine_rpcrt4_io");

  for (;;) {
    msg = calloc(1, sizeof(RPC_MESSAGE));
    if (!msg) break;

    status = RPCRT4_ReceiveWithAuth(conn, &hdr, msg, &auth_data, &auth_length);
    if (status != RPC_S_OK) {
      WARN("receive failed with error %lx\n", status);
      free(msg);
      break;
    }

    switch (hdr->common.ptype) {
    case PKT_BIND:
      TRACE("got bind packet\n");

      status = process_bind_packet(conn, &hdr->bind, msg, auth_data,
                                   auth_length);
      break;

    case PKT_REQUEST:
      TRACE("got request packet\n");

      packet = malloc(sizeof(RpcPacket));
      if (!packet) {
        I_RpcFree(msg->Buffer);
        free(hdr);
        free(msg);
        free(auth_data);
        goto exit;
      }
      packet->conn = RPCRT4_GrabConnection( conn );
      packet->hdr = hdr;
      packet->msg = msg;
      packet->auth_data = auth_data;
      packet->auth_length = auth_length;
      if (!QueueUserWorkItem(RPCRT4_worker_thread, packet, WT_EXECUTELONGFUNCTION)) {
        ERR("couldn't queue work item for worker thread, error was %ld\n", GetLastError());
        free(packet);
        status = RPC_S_OUT_OF_RESOURCES;
      } else {
        continue;
      }
      break;

    case PKT_AUTH3:
      TRACE("got auth3 packet\n");

      status = process_auth3_packet(conn, &hdr->common, msg, auth_data,
                                    auth_length);
      break;
    case PKT_CO_CANCEL:
      TRACE("got cancel packet for call %u\n", hdr->common.call_id);
      RPCRT4_ServerCallCancelled(conn, hdr->common.call_id);
      status = RPC_S_OK;
      break;
    default:
      FIXME("unhandled packet type %u\n", hdr->common.ptype);
      break;
    }

    I_RpcFree(msg->Buffer);
    free(hdr);
    free(msg);
    free(auth_data);

    if (status != RPC_S_OK) {
      WARN("processing packet failed with error %lu\n", status);
      break;
    }
  }
exit:
  RPCRT4_ServerConnectionClosed(conn);
  RPCRT4_ReleaseConnection(conn);
  return 0;
}

void RPCRT4_new_client(RpcConnection* conn)
{
  HANDLE thread = CreateThread(NULL, 0, RPCRT4_io_thread, conn, 0, NULL);
  if (!thread) {
    DWORD err = GetLastError();
    ERR("failed to create thread, error=%08lx\n", err);
    RPCRT4_ReleaseConnection(conn);
  }
  /* we could set conn->thread, but then we'd have to make the io_thread wait
   * for that, otherwise the thread might finish, destroy the connection, and
   * free the memory we'd write to before we did, causing crashes and stuff -
   * so let's implement that later, when we really need conn->thread */

  CloseHandle( thread );
}

static DWORD CALLBACK RPCRT4_server_thread(LPVOID the_arg)
{
  int res;
  unsigned int count;
  void *objs = NULL;
  RpcServerProtseq* cps = the_arg;
  RpcConnection* conn;
  BOOL set_ready_event = FALSE;

  TRACE("(the_arg == ^%p)\n", the_arg);
  SetThreadDescription(GetCurrentThread(), L"wine_rpcrt4_server");

  for (;;) {
    objs = cps->ops->get_wait_array(cps, objs, &count);

    if (set_ready_event)
    {
        /* signal to function that changed state that we are now sync'ed */
        SetEvent(cps->server_ready_event);
        set_ready_event = FALSE;
    }

    /* start waiting */
    res = cps->ops->wait_for_new_connection(cps, count, objs);

    if (res == -1 || (res == 0 && !std_listen))
    {
      /* cleanup */
      cps->ops->free_wait_array(cps, objs);
      break;
    }
    else if (res == 0)
      set_ready_event = TRUE;
  }

  TRACE("closing connections\n");

  EnterCriticalSection(&cps->cs);
  LIST_FOR_EACH_ENTRY(conn, &cps->listeners, RpcConnection, protseq_entry)
    RPCRT4_CloseConnection(conn);
  LIST_FOR_EACH_ENTRY(conn, &cps->connections, RpcConnection, protseq_entry)
  {
    RPCRT4_GrabConnection(conn);
    rpcrt4_conn_close_read(conn);
  }
  LeaveCriticalSection(&cps->cs);

  if (res == 0 && !std_listen)
      SetEvent(cps->server_ready_event);

  TRACE("waiting for active connections to close\n");

  EnterCriticalSection(&cps->cs);
  while (!list_empty(&cps->connections))
  {
    conn = LIST_ENTRY(list_head(&cps->connections), RpcConnection, protseq_entry);
    LeaveCriticalSection(&cps->cs);
    rpcrt4_conn_release_and_wait(conn);
    EnterCriticalSection(&cps->cs);
  }
  LeaveCriticalSection(&cps->cs);

  EnterCriticalSection(&listen_cs);
  CloseHandle(cps->server_thread);
  cps->server_thread = NULL;
  LeaveCriticalSection(&listen_cs);
  TRACE("done\n");
  return 0;
}

/* tells the server thread that the state has changed and waits for it to
 * make the changes */
static void RPCRT4_sync_with_server_thread(RpcServerProtseq *ps)
{
  /* make sure we are the only thread sync'ing the server state, otherwise
   * there is a race with the server thread setting an older state and setting
   * the server_ready_event when the new state hasn't yet been applied */
  WaitForSingleObject(ps->mgr_mutex, INFINITE);

  ps->ops->signal_state_changed(ps);

  /* wait for server thread to make the requested changes before returning */
  WaitForSingleObject(ps->server_ready_event, INFINITE);

  ReleaseMutex(ps->mgr_mutex);
}

static RPC_STATUS RPCRT4_start_listen_protseq(RpcServerProtseq *ps, BOOL auto_listen)
{
  RPC_STATUS status = RPC_S_OK;

  EnterCriticalSection(&listen_cs);
  if (ps->server_thread) goto done;

  if (!ps->mgr_mutex) ps->mgr_mutex = CreateMutexW(NULL, FALSE, NULL);
  if (!ps->server_ready_event) ps->server_ready_event = CreateEventW(NULL, FALSE, FALSE, NULL);
  ps->server_thread = CreateThread(NULL, 0, RPCRT4_server_thread, ps, 0, NULL);
  if (!ps->server_thread)
    status = RPC_S_OUT_OF_RESOURCES;

done:
  LeaveCriticalSection(&listen_cs);
  return status;
}

static RPC_STATUS RPCRT4_start_listen(BOOL auto_listen)
{
  RPC_STATUS status = RPC_S_ALREADY_LISTENING;
  RpcServerProtseq *cps;

  TRACE("\n");

  EnterCriticalSection(&listen_cs);
  if (auto_listen || !listen_done_event)
  {
    status = RPC_S_OK;
    if(!auto_listen)
      listen_done_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (++listen_count == 1)
      std_listen = TRUE;
  }
  LeaveCriticalSection(&listen_cs);
  if (status) return status;

  if (std_listen)
  {
    EnterCriticalSection(&server_cs);
    LIST_FOR_EACH_ENTRY(cps, &protseqs, RpcServerProtseq, entry)
    {
      status = RPCRT4_start_listen_protseq(cps, TRUE);
      if (status != RPC_S_OK)
        break;
      
      /* make sure server is actually listening on the interface before
       * returning */
      RPCRT4_sync_with_server_thread(cps);
    }
    LeaveCriticalSection(&server_cs);
  }

  return status;
}

static RPC_STATUS RPCRT4_stop_listen(BOOL auto_listen)
{
  BOOL stop_listen = FALSE;
  RPC_STATUS status = RPC_S_OK;

  EnterCriticalSection(&listen_cs);
  if (!std_listen && (auto_listen || !listen_done_event))
  {
    status = RPC_S_NOT_LISTENING;
  }
  else
  {
    stop_listen = listen_count != 0 && --listen_count == 0;
    assert(listen_count >= 0);
    if (stop_listen)
      std_listen = FALSE;
  }
  LeaveCriticalSection(&listen_cs);

  if (status) return status;

  if (stop_listen) {
    RpcServerProtseq *cps;
    EnterCriticalSection(&server_cs);
    LIST_FOR_EACH_ENTRY(cps, &protseqs, RpcServerProtseq, entry)
      RPCRT4_sync_with_server_thread(cps);
    LeaveCriticalSection(&server_cs);
  }

  if (!auto_listen)
  {
      EnterCriticalSection(&listen_cs);
      SetEvent( listen_done_event );
      LeaveCriticalSection(&listen_cs);
  }
  return RPC_S_OK;
}

static BOOL RPCRT4_protseq_is_endpoint_registered(RpcServerProtseq *protseq, const char *endpoint)
{
  RpcConnection *conn;
  BOOL registered = FALSE;
  EnterCriticalSection(&protseq->cs);
  LIST_FOR_EACH_ENTRY(conn, &protseq->listeners, RpcConnection, protseq_entry) {
    if (!endpoint || !strcmp(endpoint, conn->Endpoint)) {
      registered = TRUE;
      break;
    }
  }
  LeaveCriticalSection(&protseq->cs);
  return registered;
}

static RPC_STATUS RPCRT4_use_protseq(RpcServerProtseq* ps, const char *endpoint)
{
  RPC_STATUS status;

  EnterCriticalSection(&ps->cs);

  if (RPCRT4_protseq_is_endpoint_registered(ps, endpoint))
    status = RPC_S_OK;
  else
    status = ps->ops->open_endpoint(ps, endpoint);

  LeaveCriticalSection(&ps->cs);

  if (status != RPC_S_OK)
    return status;

  if (std_listen)
  {
    status = RPCRT4_start_listen_protseq(ps, FALSE);
    if (status == RPC_S_OK)
      RPCRT4_sync_with_server_thread(ps);
  }

  return status;
}

/***********************************************************************
 *             RpcServerInqBindings (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcServerInqBindings( RPC_BINDING_VECTOR** BindingVector )
{
  RPC_STATUS status;
  DWORD count;
  RpcServerProtseq* ps;
  RpcConnection* conn;

  if (BindingVector)
    TRACE("(*BindingVector == ^%p)\n", *BindingVector);
  else
    ERR("(BindingVector == NULL!!?)\n");

  EnterCriticalSection(&server_cs);
  /* count connections */
  count = 0;
  LIST_FOR_EACH_ENTRY(ps, &protseqs, RpcServerProtseq, entry) {
    EnterCriticalSection(&ps->cs);
    LIST_FOR_EACH_ENTRY(conn, &ps->listeners, RpcConnection, protseq_entry)
      count++;
    LeaveCriticalSection(&ps->cs);
  }
  if (count) {
    /* export bindings */
    *BindingVector = malloc(sizeof(RPC_BINDING_VECTOR) + sizeof(RPC_BINDING_HANDLE) * (count - 1));
    (*BindingVector)->Count = count;
    count = 0;
    LIST_FOR_EACH_ENTRY(ps, &protseqs, RpcServerProtseq, entry) {
      EnterCriticalSection(&ps->cs);
      LIST_FOR_EACH_ENTRY(conn, &ps->listeners, RpcConnection, protseq_entry) {
       RPCRT4_MakeBinding((RpcBinding**)&(*BindingVector)->BindingH[count],
                          conn);
       count++;
      }
      LeaveCriticalSection(&ps->cs);
    }
    status = RPC_S_OK;
  } else {
    *BindingVector = NULL;
    status = RPC_S_NO_BINDINGS;
  }
  LeaveCriticalSection(&server_cs);
  return status;
}

/***********************************************************************
 *             RpcServerUseProtseqEpA (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcServerUseProtseqEpA( RPC_CSTR Protseq, UINT MaxCalls, RPC_CSTR Endpoint, LPVOID SecurityDescriptor )
{
  RPC_POLICY policy;
  
  TRACE( "(%s,%u,%s,%p)\n", Protseq, MaxCalls, Endpoint, SecurityDescriptor );
  
  /* This should provide the default behaviour */
  policy.Length        = sizeof( policy );
  policy.EndpointFlags = 0;
  policy.NICFlags      = 0;
  
  return RpcServerUseProtseqEpExA( Protseq, MaxCalls, Endpoint, SecurityDescriptor, &policy );
}

/***********************************************************************
 *             RpcServerUseProtseqEpW (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcServerUseProtseqEpW( RPC_WSTR Protseq, UINT MaxCalls, RPC_WSTR Endpoint, LPVOID SecurityDescriptor )
{
  RPC_POLICY policy;
  
  TRACE( "(%s,%u,%s,%p)\n", debugstr_w( Protseq ), MaxCalls, debugstr_w( Endpoint ), SecurityDescriptor );
  
  /* This should provide the default behaviour */
  policy.Length        = sizeof( policy );
  policy.EndpointFlags = 0;
  policy.NICFlags      = 0;
  
  return RpcServerUseProtseqEpExW( Protseq, MaxCalls, Endpoint, SecurityDescriptor, &policy );
}

/***********************************************************************
 *             alloc_serverprotoseq (internal)
 *
 * Must be called with server_cs held.
 */
static RPC_STATUS alloc_serverprotoseq(UINT MaxCalls, const char *Protseq, RpcServerProtseq **ps)
{
  const struct protseq_ops *ops = rpcrt4_get_protseq_ops(Protseq);

  if (!ops)
  {
    FIXME("protseq %s not supported\n", debugstr_a(Protseq));
    return RPC_S_PROTSEQ_NOT_SUPPORTED;
  }

  *ps = ops->alloc();
  if (!*ps)
    return RPC_S_OUT_OF_RESOURCES;
  (*ps)->MaxCalls = MaxCalls;
  (*ps)->Protseq = strdup(Protseq);
  (*ps)->ops = ops;
  list_init(&(*ps)->listeners);
  list_init(&(*ps)->connections);
  InitializeCriticalSectionEx(&(*ps)->cs, 0, RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO);
  (*ps)->cs.DebugInfo->Spare[0] = (DWORD_PTR)(__FILE__ ": RpcServerProtseq.cs");

  list_add_head(&protseqs, &(*ps)->entry);

  TRACE("new protseq %p created for %s\n", *ps, Protseq);

  return RPC_S_OK;
}

/* must be called with server_cs held */
static void destroy_serverprotoseq(RpcServerProtseq *ps)
{
    free(ps->Protseq);
    ps->cs.DebugInfo->Spare[0] = 0;
    DeleteCriticalSection(&ps->cs);
    CloseHandle(ps->mgr_mutex);
    CloseHandle(ps->server_ready_event);
    list_remove(&ps->entry);
    free(ps);
}

/* Finds a given protseq or creates a new one if one doesn't already exist */
static RPC_STATUS RPCRT4_get_or_create_serverprotseq(UINT MaxCalls, const char *Protseq, RpcServerProtseq **ps)
{
    RPC_STATUS status;
    RpcServerProtseq *cps;

    EnterCriticalSection(&server_cs);

    LIST_FOR_EACH_ENTRY(cps, &protseqs, RpcServerProtseq, entry)
        if (!strcmp(cps->Protseq, Protseq))
        {
            TRACE("found existing protseq object for %s\n", Protseq);
            *ps = cps;
            LeaveCriticalSection(&server_cs);
            return S_OK;
        }

    status = alloc_serverprotoseq(MaxCalls, Protseq, ps);

    LeaveCriticalSection(&server_cs);

    return status;
}

/***********************************************************************
 *             RpcServerUseProtseqEpExA (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcServerUseProtseqEpExA( RPC_CSTR Protseq, UINT MaxCalls, RPC_CSTR Endpoint, LPVOID SecurityDescriptor,
                                            PRPC_POLICY lpPolicy )
{
  RpcServerProtseq* ps;
  RPC_STATUS status;

  TRACE("(%s,%u,%s,%p,{%u,%lu,%lu})\n", debugstr_a((const char *)Protseq),
       MaxCalls, debugstr_a((const char *)Endpoint), SecurityDescriptor,
       lpPolicy->Length, lpPolicy->EndpointFlags, lpPolicy->NICFlags );

  status = RPCRT4_get_or_create_serverprotseq(MaxCalls, (const char *)Protseq, &ps);
  if (status != RPC_S_OK)
    return status;

  return RPCRT4_use_protseq(ps, (const char *)Endpoint);
}

/***********************************************************************
 *             RpcServerUseProtseqEpExW (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcServerUseProtseqEpExW( RPC_WSTR Protseq, UINT MaxCalls, RPC_WSTR Endpoint, LPVOID SecurityDescriptor,
                                            PRPC_POLICY lpPolicy )
{
  RpcServerProtseq* ps;
  RPC_STATUS status;
  LPSTR ProtseqA;
  LPSTR EndpointA;

  TRACE("(%s,%u,%s,%p,{%u,%lu,%lu})\n", debugstr_w( Protseq ), MaxCalls,
       debugstr_w( Endpoint ), SecurityDescriptor,
       lpPolicy->Length, lpPolicy->EndpointFlags, lpPolicy->NICFlags );

  ProtseqA = RPCRT4_strdupWtoA(Protseq);
  status = RPCRT4_get_or_create_serverprotseq(MaxCalls, ProtseqA, &ps);
  free(ProtseqA);
  if (status != RPC_S_OK)
    return status;

  EndpointA = RPCRT4_strdupWtoA(Endpoint);
  status = RPCRT4_use_protseq(ps, EndpointA);
  free(EndpointA);
  return status;
}

/***********************************************************************
 *             RpcServerUseProtseqA (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcServerUseProtseqA(RPC_CSTR Protseq, unsigned int MaxCalls, void *SecurityDescriptor)
{
  RPC_STATUS status;
  RpcServerProtseq* ps;

  TRACE("(Protseq == %s, MaxCalls == %d, SecurityDescriptor == ^%p)\n", debugstr_a((char*)Protseq), MaxCalls, SecurityDescriptor);

  status = RPCRT4_get_or_create_serverprotseq(MaxCalls, (const char *)Protseq, &ps);
  if (status != RPC_S_OK)
    return status;

  return RPCRT4_use_protseq(ps, NULL);
}

/***********************************************************************
 *             RpcServerUseProtseqExA (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcServerUseProtseqExA(RPC_CSTR Protseq, unsigned int MaxCalls,
                                         void *SecurityDescriptor, PRPC_POLICY Policy)
{
  TRACE("(Protseq == %s, MaxCalls == %d, SecurityDescriptor == ^%p, Policy == ^%p)\n",
        debugstr_a((char *)Protseq), MaxCalls, SecurityDescriptor, Policy);

  return RpcServerUseProtseqA(Protseq, MaxCalls, SecurityDescriptor);
}

/***********************************************************************
 *             RpcServerUseProtseqW (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcServerUseProtseqW(RPC_WSTR Protseq, unsigned int MaxCalls, void *SecurityDescriptor)
{
  RPC_STATUS status;
  RpcServerProtseq* ps;
  LPSTR ProtseqA;

  TRACE("Protseq == %s, MaxCalls == %d, SecurityDescriptor == ^%p)\n", debugstr_w(Protseq), MaxCalls, SecurityDescriptor);

  ProtseqA = RPCRT4_strdupWtoA(Protseq);
  status = RPCRT4_get_or_create_serverprotseq(MaxCalls, ProtseqA, &ps);
  free(ProtseqA);
  if (status != RPC_S_OK)
    return status;

  return RPCRT4_use_protseq(ps, NULL);
}

/***********************************************************************
 *             RpcServerUseProtseqExW (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcServerUseProtseqExW(RPC_WSTR Protseq, unsigned int MaxCalls,
                                         void *SecurityDescriptor, PRPC_POLICY Policy)
{
  TRACE("(Protseq == %s, MaxCalls == %d, SecurityDescriptor == ^%p, Policy == ^%p)\n",
        debugstr_w(Protseq), MaxCalls, SecurityDescriptor, Policy);

  return RpcServerUseProtseqW(Protseq, MaxCalls, SecurityDescriptor);
}

void RPCRT4_destroy_all_protseqs(void)
{
    RpcServerProtseq *cps, *cursor2;

    if (listen_count != 0)
        std_listen = FALSE;

    EnterCriticalSection(&server_cs);
    LIST_FOR_EACH_ENTRY_SAFE(cps, cursor2, &protseqs, RpcServerProtseq, entry)
    {
        if (listen_count != 0)
            RPCRT4_sync_with_server_thread(cps);
        destroy_serverprotoseq(cps);
    }
    LeaveCriticalSection(&server_cs);
    DeleteCriticalSection(&server_cs);
    DeleteCriticalSection(&listen_cs);
}

/***********************************************************************
 *             RpcServerRegisterIf (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcServerRegisterIf( RPC_IF_HANDLE IfSpec, UUID* MgrTypeUuid, RPC_MGR_EPV* MgrEpv )
{
  TRACE("(%p,%s,%p)\n", IfSpec, debugstr_guid(MgrTypeUuid), MgrEpv);
  return RpcServerRegisterIf3( IfSpec, MgrTypeUuid, MgrEpv, 0, RPC_C_LISTEN_MAX_CALLS_DEFAULT, (UINT)-1, NULL, NULL );
}

/***********************************************************************
 *             RpcServerRegisterIfEx (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcServerRegisterIfEx( RPC_IF_HANDLE IfSpec, UUID* MgrTypeUuid, RPC_MGR_EPV* MgrEpv,
                       UINT Flags, UINT MaxCalls, RPC_IF_CALLBACK_FN* IfCallbackFn )
{
  TRACE("(%p,%s,%p,%u,%u,%p)\n", IfSpec, debugstr_guid(MgrTypeUuid), MgrEpv, Flags, MaxCalls, IfCallbackFn);
  return RpcServerRegisterIf3( IfSpec, MgrTypeUuid, MgrEpv, Flags, MaxCalls, (UINT)-1, IfCallbackFn, NULL );
}

/***********************************************************************
 *             RpcServerRegisterIf2 (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcServerRegisterIf2( RPC_IF_HANDLE IfSpec, UUID* MgrTypeUuid, RPC_MGR_EPV* MgrEpv,
                      UINT Flags, UINT MaxCalls, UINT MaxRpcSize, RPC_IF_CALLBACK_FN* IfCallbackFn )
{
  return RpcServerRegisterIf3( IfSpec, MgrTypeUuid, MgrEpv, Flags, MaxCalls, MaxRpcSize, IfCallbackFn, NULL );
}

/***********************************************************************
 *             RpcServerRegisterIf3 (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcServerRegisterIf3( RPC_IF_HANDLE IfSpec, UUID* MgrTypeUuid, RPC_MGR_EPV* MgrEpv,
    UINT Flags, UINT MaxCalls, UINT MaxRpcSize, RPC_IF_CALLBACK_FN* IfCallbackFn, void* SecurityDescriptor)
{
  PRPC_SERVER_INTERFACE If = IfSpec;
  RpcServerInterface* sif;
  unsigned int i;

  TRACE("(%p,%s,%p,%u,%u,%u,%p,%p)\n", IfSpec, debugstr_guid(MgrTypeUuid), MgrEpv, Flags, MaxCalls,
        MaxRpcSize, IfCallbackFn, SecurityDescriptor);

  if (SecurityDescriptor)
      FIXME("Unsupported SecurityDescriptor argument.\n");

  TRACE(" interface id: %s %d.%d\n", debugstr_guid(&If->InterfaceId.SyntaxGUID),
                                     If->InterfaceId.SyntaxVersion.MajorVersion,
                                     If->InterfaceId.SyntaxVersion.MinorVersion);
  TRACE(" transfer syntax: %s %d.%d\n", debugstr_guid(&If->TransferSyntax.SyntaxGUID),
                                        If->TransferSyntax.SyntaxVersion.MajorVersion,
                                        If->TransferSyntax.SyntaxVersion.MinorVersion);
  TRACE(" dispatch table: %p\n", If->DispatchTable);
  if (If->DispatchTable) {
    TRACE("  dispatch table count: %d\n", If->DispatchTable->DispatchTableCount);
    for (i=0; i<If->DispatchTable->DispatchTableCount; i++) {
      TRACE("   entry %d: %p\n", i, If->DispatchTable->DispatchTable[i]);
    }
    TRACE("  reserved: %Id\n", If->DispatchTable->Reserved);
  }
  TRACE(" protseq endpoint count: %d\n", If->RpcProtseqEndpointCount);
  TRACE(" default manager epv: %p\n", If->DefaultManagerEpv);
  TRACE(" interpreter info: %p\n", If->InterpreterInfo);

  sif = calloc(1, sizeof(RpcServerInterface));
  sif->If           = If;
  if (MgrTypeUuid) {
    sif->MgrTypeUuid = *MgrTypeUuid;
    sif->MgrEpv       = MgrEpv;
  } else {
    memset(&sif->MgrTypeUuid, 0, sizeof(UUID));
    sif->MgrEpv       = If->DefaultManagerEpv;
  }
  sif->Flags        = Flags;
  sif->MaxCalls     = MaxCalls;
  sif->MaxRpcSize   = MaxRpcSize;
  sif->IfCallbackFn = IfCallbackFn;

  EnterCriticalSection(&server_cs);
  list_add_head(&server_interfaces, &sif->entry);
  LeaveCriticalSection(&server_cs);

  if (sif->Flags & RPC_IF_AUTOLISTEN)
      RPCRT4_start_listen(TRUE);

  return RPC_S_OK;
}

static BOOL rpc_server_interface_matches(const RpcServerInterface *sif,
                                         const RPC_SERVER_INTERFACE *iface,
                                         const UUID *mgr_type)
{
  if (!iface && (sif->Flags & RPC_IF_AUTOLISTEN)) return FALSE;
  if (iface && memcmp(&iface->InterfaceId, &sif->If->InterfaceId,
                      sizeof(RPC_SYNTAX_IDENTIFIER))) return FALSE;
  if (mgr_type && memcmp(mgr_type, &sif->MgrTypeUuid, sizeof(*mgr_type))) return FALSE;
  return TRUE;
}

static RPC_STATUS rpc_server_unregister_interfaces(RPC_IF_HANDLE IfSpec, UUID *MgrTypeUuid,
                                                   BOOL wait, BOOL destroy_contexts,
                                                   BOOL rundown_contexts)
{
  RPC_SERVER_INTERFACE *iface = IfSpec;
  RpcServerInterface *sif;
  unsigned int found = 0;

  for (;;) {
    RPC_SYNTAX_IDENTIFIER *context_guard;
    HANDLE event = NULL;
    BOOL completed = TRUE;

    EnterCriticalSection(&server_cs);
    LIST_FOR_EACH_ENTRY(sif, &server_interfaces, RpcServerInterface, entry) {
      if (!rpc_server_interface_matches(sif, iface, MgrTypeUuid)) continue;

      if (sif->CurrentCalls && wait && !(event = CreateEventW(NULL, FALSE, FALSE, NULL))) {
        LeaveCriticalSection(&server_cs);
        return RPC_S_OUT_OF_RESOURCES;
      }

      list_remove(&sif->entry);
      TRACE("unregistering sif %p\n", sif);
      context_guard = &sif->If->InterfaceId;
      if (sif->CurrentCalls) {
        completed = FALSE;
        sif->Delete = TRUE;
        sif->CallsCompletedEvent = event;
      }
      break;
    }
    if (&sif->entry == &server_interfaces) {
      LeaveCriticalSection(&server_cs);
      break;
    }
    LeaveCriticalSection(&server_cs);

    ++found;
    if (completed)
      free(sif);
    else if (event) {
      /* sif is freed by the last completing call; do not access it here. */
      WaitForSingleObject(event, INFINITE);
      CloseHandle(event);
    }
    if (destroy_contexts)
      RpcServerAssoc_DestroyContextHandles(context_guard, rundown_contexts);
  }

  if (found) return RPC_S_OK;
  ERR("interface %s manager %s not found\n",
      iface ? debugstr_guid(&iface->InterfaceId.SyntaxGUID) : "(any)",
      debugstr_guid(MgrTypeUuid));
  return iface ? RPC_S_UNKNOWN_IF : RPC_S_UNKNOWN_MGR_TYPE;
}

/***********************************************************************
 *             RpcServerUnregisterIf (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcServerUnregisterIf( RPC_IF_HANDLE IfSpec, UUID* MgrTypeUuid, UINT WaitForCallsToComplete )
{
  RPC_SERVER_INTERFACE *iface = IfSpec;

  TRACE("(IfSpec == (RPC_IF_HANDLE)^%p (%s), MgrTypeUuid == %s, WaitForCallsToComplete == %u)\n",
    IfSpec, iface ? debugstr_guid(&iface->InterfaceId.SyntaxGUID) : "(any)",
    debugstr_guid(MgrTypeUuid), WaitForCallsToComplete);

  return rpc_server_unregister_interfaces(IfSpec, MgrTypeUuid, WaitForCallsToComplete,
                                          FALSE, FALSE);
}

/***********************************************************************
 *             RpcServerUnregisterIfEx (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcServerUnregisterIfEx( RPC_IF_HANDLE IfSpec, UUID* MgrTypeUuid, int RundownContextHandles )
{
  TRACE("(IfSpec == (RPC_IF_HANDLE)^%p, MgrTypeUuid == %s, RundownContextHandles == %d)\n",
    IfSpec, debugstr_guid(MgrTypeUuid), RundownContextHandles);

  return rpc_server_unregister_interfaces(IfSpec, MgrTypeUuid, TRUE, TRUE,
                                          RundownContextHandles != 0);
}

/***********************************************************************
 *             RpcObjectSetType (RPCRT4.@)
 *
 * PARAMS
 *   ObjUuid  [I] "Object" UUID
 *   TypeUuid [I] "Type" UUID
 *
 * RETURNS
 *   RPC_S_OK                 The call succeeded
 *   RPC_S_INVALID_OBJECT     The provided object (nil) is not valid
 *   RPC_S_ALREADY_REGISTERED The provided object is already registered
 *
 * Maps "Object" UUIDs to "Type" UUIDs.  Passing the nil UUID as the type
 * resets the mapping for the specified object UUID to nil (the default).
 * The nil object is always associated with the nil type and cannot be
 * reassigned.  Servers can support multiple implementations on the same
 * interface by registering different end-point vectors for the different
 * types.  There's no need to call this if a server only supports the nil
 * type, as is typical.
 */
RPC_STATUS WINAPI RpcObjectSetType( UUID* ObjUuid, UUID* TypeUuid )
{
  RpcObjTypeMap *map = RpcObjTypeMaps, *prev = NULL;
  RPC_STATUS dummy;

  TRACE("(ObjUUID == %s, TypeUuid == %s).\n", debugstr_guid(ObjUuid), debugstr_guid(TypeUuid));
  if ((! ObjUuid) || UuidIsNil(ObjUuid, &dummy)) {
    /* nil uuid cannot be remapped */
    return RPC_S_INVALID_OBJECT;
  }

  /* find the mapping for this object if there is one ... */
  while (map) {
    if (! UuidCompare(ObjUuid, &map->Object, &dummy)) break;
    prev = map;
    map = map->next;
  }
  if ((! TypeUuid) || UuidIsNil(TypeUuid, &dummy)) {
    /* ... and drop it from the list */
    if (map) {
      if (prev) 
        prev->next = map->next;
      else
        RpcObjTypeMaps = map->next;
      free(map);
    }
  } else {
    /* ... , fail if we found it ... */
    if (map)
      return RPC_S_ALREADY_REGISTERED;
    /* ... otherwise create a new one and add it in. */
    map = malloc(sizeof(RpcObjTypeMap));
    map->Object = *ObjUuid;
    map->Type = *TypeUuid;
    map->next = NULL;
    if (prev)
      prev->next = map; /* prev is the last map in the linklist */
    else
      RpcObjTypeMaps = map;
  }

  return RPC_S_OK;
}

struct rpc_server_registered_auth_info
{
    struct list entry;
    USHORT auth_type;
    WCHAR *package_name;
    WCHAR *principal;
    ULONG max_token;
};

static RPC_STATUS find_security_package(ULONG auth_type, SecPkgInfoW **packages_buf, SecPkgInfoW **ret)
{
    static WCHAR ntlm_name[] = L"NTLM";
    static WCHAR ntlm_comment[] = L"NTLM Security Package";
    static SecPkgInfoW ntlm_package =
    {
        0,
        1,
        RPC_C_AUTHN_WINNT,
        1904,
        ntlm_name,
        ntlm_comment,
    };
    SECURITY_STATUS sec_status;
    SecPkgInfoW *packages;
    ULONG package_count;
    ULONG i;

    *packages_buf = NULL;
    sec_status = EnumerateSecurityPackagesW(&package_count, &packages);
    if (sec_status != SEC_E_OK)
    {
        if (sec_status == SEC_E_SECPKG_NOT_FOUND && auth_type == RPC_C_AUTHN_WINNT)
        {
            WARN("EnumerateSecurityPackagesW could not query LSASS; using built-in NTLM metadata\n");
            *ret = &ntlm_package;
            return RPC_S_OK;
        }
        ERR("EnumerateSecurityPackagesW failed with error 0x%08lx\n", sec_status);
        return RPC_S_SEC_PKG_ERROR;
    }

    for (i = 0; i < package_count; i++)
        if (packages[i].wRPCID == auth_type)
            break;

    if (i == package_count)
    {
        WARN("unsupported AuthnSvc %lu\n", auth_type);
        FreeContextBuffer(packages);
        return RPC_S_UNKNOWN_AUTHN_SERVICE;
    }

    TRACE("found package %s for service %lu\n", debugstr_w(packages[i].Name), auth_type);
    *packages_buf = packages;
    *ret = packages + i;
    return RPC_S_OK;
}

RPC_STATUS RPCRT4_ServerGetRegisteredAuthInfo(
    USHORT auth_type, CredHandle *cred, TimeStamp *exp, ULONG *max_token)
{
    RPC_STATUS status = RPC_S_UNKNOWN_AUTHN_SERVICE;
    struct rpc_server_registered_auth_info *auth_info;
    SECURITY_STATUS sec_status;

    EnterCriticalSection(&server_auth_info_cs);
    LIST_FOR_EACH_ENTRY(auth_info, &server_registered_auth_info, struct rpc_server_registered_auth_info, entry)
    {
        if (auth_info->auth_type == auth_type)
        {
            sec_status = AcquireCredentialsHandleW((SEC_WCHAR *)auth_info->principal, auth_info->package_name,
                                                   SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL,
                                                   cred, exp);
            if (sec_status != SEC_E_OK)
            {
                status = RPC_S_SEC_PKG_ERROR;
                break;
            }

            *max_token = auth_info->max_token;
            status = RPC_S_OK;
            break;
        }
    }
    LeaveCriticalSection(&server_auth_info_cs);

    return status;
}

void RPCRT4_ServerFreeAllRegisteredAuthInfo(void)
{
    struct rpc_server_registered_auth_info *auth_info, *cursor2;

    EnterCriticalSection(&server_auth_info_cs);
    LIST_FOR_EACH_ENTRY_SAFE(auth_info, cursor2, &server_registered_auth_info, struct rpc_server_registered_auth_info, entry)
    {
        free(auth_info->package_name);
        free(auth_info->principal);
        free(auth_info);
    }
    LeaveCriticalSection(&server_auth_info_cs);
    DeleteCriticalSection(&server_auth_info_cs);
}

/***********************************************************************
 *             RpcServerRegisterAuthInfoA (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcServerRegisterAuthInfoA( RPC_CSTR ServerPrincName, ULONG AuthnSvc, RPC_AUTH_KEY_RETRIEVAL_FN GetKeyFn,
                            LPVOID Arg )
{
    WCHAR *principal_name = NULL;
    RPC_STATUS status;

    TRACE("(%s,%lu,%p,%p)\n", ServerPrincName, AuthnSvc, GetKeyFn, Arg);

    if(ServerPrincName && !(principal_name = RPCRT4_strdupAtoW((const char*)ServerPrincName)))
        return RPC_S_OUT_OF_RESOURCES;

    status = RpcServerRegisterAuthInfoW(principal_name, AuthnSvc, GetKeyFn, Arg);

    free(principal_name);
    return status;
}

/***********************************************************************
 *             RpcServerRegisterAuthInfoW (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcServerRegisterAuthInfoW( RPC_WSTR ServerPrincName, ULONG AuthnSvc, RPC_AUTH_KEY_RETRIEVAL_FN GetKeyFn,
                            LPVOID Arg )
{
    struct rpc_server_registered_auth_info *auth_info;
    SecPkgInfoW *packages, *package;
    WCHAR *package_name;
    ULONG max_token;
    RPC_STATUS status;

    TRACE("(%s,%lu,%p,%p)\n", debugstr_w(ServerPrincName), AuthnSvc, GetKeyFn, Arg);

    status = find_security_package(AuthnSvc, &packages, &package);
    if (status != RPC_S_OK)
        return status;

    package_name = wcsdup(package->Name);
    max_token = package->cbMaxToken;
    if (packages) FreeContextBuffer(packages);
    if (!package_name)
        return RPC_S_OUT_OF_RESOURCES;

    auth_info = calloc(1, sizeof(*auth_info));
    if (!auth_info) {
        free(package_name);
        return RPC_S_OUT_OF_RESOURCES;
    }

    if (ServerPrincName && !(auth_info->principal = wcsdup(ServerPrincName))) {
        free(package_name);
        free(auth_info);
        return RPC_S_OUT_OF_RESOURCES;
    }

    auth_info->auth_type = AuthnSvc;
    auth_info->package_name = package_name;
    auth_info->max_token = max_token;

    EnterCriticalSection(&server_auth_info_cs);
    list_add_tail(&server_registered_auth_info, &auth_info->entry);
    LeaveCriticalSection(&server_auth_info_cs);

    return RPC_S_OK;
}

/******************************************************************************
 * RpcServerInqDefaultPrincNameA   (rpcrt4.@)
 */
RPC_STATUS RPC_ENTRY RpcServerInqDefaultPrincNameA(ULONG AuthnSvc, RPC_CSTR *PrincName)
{
    RPC_STATUS ret;
    RPC_WSTR principalW;

    TRACE("%lu, %p\n", AuthnSvc, PrincName);

    if ((ret = RpcServerInqDefaultPrincNameW( AuthnSvc, &principalW )) == RPC_S_OK)
    {
        if (!(*PrincName = (RPC_CSTR)RPCRT4_strdupWtoA( principalW ))) return RPC_S_OUT_OF_MEMORY;
        RpcStringFreeW( &principalW );
    }
    return ret;
}

/******************************************************************************
 * RpcServerInqDefaultPrincNameW   (rpcrt4.@)
 */
RPC_STATUS RPC_ENTRY RpcServerInqDefaultPrincNameW(ULONG AuthnSvc, RPC_WSTR *PrincName)
{
    SecPkgCredentials_NamesW names = {0};
    SecPkgInfoW *packages, *package;
    SECURITY_STATUS sec_status;
    CredHandle credentials;
    TimeStamp expiry;
    RPC_STATUS status;
    WCHAR *principal;
    ULONG len = 0;

    TRACE("%lu, %p\n", AuthnSvc, PrincName);

    if (AuthnSvc == RPC_C_AUTHN_WINNT)
    {
        GetUserNameExW( NameSamCompatible, NULL, &len );
        if (GetLastError() != ERROR_MORE_DATA) return RPC_S_INTERNAL_ERROR;

        if (!(*PrincName = malloc(len * sizeof(WCHAR))))
            return RPC_S_OUT_OF_MEMORY;

        GetUserNameExW( NameSamCompatible, *PrincName, &len );
        return RPC_S_OK;
    }

    status = find_security_package( AuthnSvc, &packages, &package );
    if (status != RPC_S_OK) return status;

    sec_status = AcquireCredentialsHandleW( NULL, package->Name, SECPKG_CRED_INBOUND,
                                            NULL, NULL, NULL, NULL, &credentials, &expiry );
    if (packages) FreeContextBuffer( packages );
    if (sec_status != SEC_E_OK)
    {
        WARN("AcquireCredentialsHandleW failed with error %#lx\n", sec_status);
        return sec_status == SEC_E_INSUFFICIENT_MEMORY ? RPC_S_OUT_OF_MEMORY : RPC_S_SEC_PKG_ERROR;
    }

    sec_status = QueryCredentialsAttributesW( &credentials, SECPKG_CRED_ATTR_NAMES, &names );
    FreeCredentialsHandle( &credentials );
    if (sec_status != SEC_E_OK)
    {
        WARN("QueryCredentialsAttributesW failed with error %#lx\n", sec_status);
        return sec_status == SEC_E_INSUFFICIENT_MEMORY ? RPC_S_OUT_OF_MEMORY : RPC_S_SEC_PKG_ERROR;
    }

    principal = names.sUserName ? wcsdup( names.sUserName ) : NULL;
    if (names.sUserName) FreeContextBuffer( names.sUserName );
    if (!principal) return RPC_S_OUT_OF_MEMORY;

    *PrincName = principal;
    return RPC_S_OK;
}

/***********************************************************************
 *             RpcServerListen (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcServerListen( UINT MinimumCallThreads, UINT MaxCalls, UINT DontWait )
{
  RPC_STATUS status = RPC_S_OK;

  TRACE("(%u,%u,%u)\n", MinimumCallThreads, MaxCalls, DontWait);

  if (list_empty(&protseqs))
    return RPC_S_NO_PROTSEQS_REGISTERED;

  status = RPCRT4_start_listen(FALSE);

  if (DontWait || (status != RPC_S_OK)) return status;

  return RpcMgmtWaitServerListen();
}

/***********************************************************************
 *             RpcMgmtServerWaitListen (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcMgmtWaitServerListen( void )
{
  RpcServerProtseq *protseq;
  HANDLE event, wait_thread;

  TRACE("()\n");

  EnterCriticalSection(&listen_cs);
  event = listen_done_event;
  LeaveCriticalSection(&listen_cs);

  if (!event)
      return RPC_S_NOT_LISTENING;

  TRACE( "waiting for server calls to finish\n" );
  WaitForSingleObject( event, INFINITE );
  TRACE( "done waiting\n" );

  EnterCriticalSection(&listen_cs);
  /* wait for server threads to finish */
  while(1)
  {
      if (listen_count)
          break;

      wait_thread = NULL;
      EnterCriticalSection(&server_cs);
      LIST_FOR_EACH_ENTRY(protseq, &protseqs, RpcServerProtseq, entry)
      {
          if ((wait_thread = protseq->server_thread))
              break;
      }
      LeaveCriticalSection(&server_cs);
      if (!wait_thread)
          break;

      TRACE("waiting for thread %lu\n", GetThreadId(wait_thread));
      LeaveCriticalSection(&listen_cs);
      WaitForSingleObject(wait_thread, INFINITE);
      EnterCriticalSection(&listen_cs);
  }
  if (listen_done_event == event)
  {
      listen_done_event = NULL;
      CloseHandle( event );
  }
  LeaveCriticalSection(&listen_cs);
  return RPC_S_OK;
}

/***********************************************************************
 *             RpcMgmtStopServerListening (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcMgmtStopServerListening ( RPC_BINDING_HANDLE Binding )
{
  TRACE("(Binding == (RPC_BINDING_HANDLE)^%p)\n", Binding);

  if (Binding) {
    FIXME("client-side invocation not implemented.\n");
    return RPC_S_WRONG_KIND_OF_BINDING;
  }
  
  return RPCRT4_stop_listen(FALSE);
}

/***********************************************************************
 *             RpcMgmtEnableIdleCleanup (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcMgmtEnableIdleCleanup(void)
{
    FIXME("(): stub\n");
    return RPC_S_OK;
}

/***********************************************************************
 *             I_RpcServerStartListening (RPCRT4.@)
 */
RPC_STATUS WINAPI I_RpcServerStartListening( HWND hWnd )
{
  FIXME( "(%p): stub\n", hWnd );

  return RPC_S_OK;
}

/***********************************************************************
 *             I_RpcServerStopListening (RPCRT4.@)
 */
RPC_STATUS WINAPI I_RpcServerStopListening( void )
{
  FIXME( "(): stub\n" );

  return RPC_S_OK;
}

/***********************************************************************
 *             I_RpcServerDisableExceptionFilter (RPCRT4.@)
 */
void WINAPI I_RpcServerDisableExceptionFilter(void)
{
    InterlockedExchange(&server_exception_filter_disabled, TRUE);
}

/***********************************************************************
 *             I_RpcWindowProc (RPCRT4.@)
 */
UINT WINAPI I_RpcWindowProc( void *hWnd, UINT Message, UINT wParam, ULONG lParam )
{
  FIXME( "(%p,%08x,%08x,%08lx): stub\n", hWnd, Message, wParam, lParam );

  return 0;
}

/***********************************************************************
 *             RpcMgmtInqIfIds (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcMgmtInqIfIds(RPC_BINDING_HANDLE Binding, RPC_IF_ID_VECTOR **IfIdVector)
{
  FIXME("(%p,%p): stub\n", Binding, IfIdVector);
  return RPC_S_INVALID_BINDING;
}

/***********************************************************************
 *             RpcMgmtInqStats (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcMgmtInqStats(RPC_BINDING_HANDLE Binding, RPC_STATS_VECTOR **Statistics)
{
  RPC_STATS_VECTOR *stats;

  FIXME("(%p,%p)\n", Binding, Statistics);

  if ((stats = malloc(sizeof(RPC_STATS_VECTOR))))
  {
    stats->Count = 1;
    stats->Stats[0] = 0;
    *Statistics = stats;
    return RPC_S_OK;
  }
  return RPC_S_OUT_OF_RESOURCES;
}

/***********************************************************************
 *             RpcMgmtStatsVectorFree (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcMgmtStatsVectorFree(RPC_STATS_VECTOR **StatsVector)
{
  FIXME("(%p)\n", StatsVector);

  if (StatsVector)
  {
    free(*StatsVector);
    *StatsVector = NULL;
  }
  return RPC_S_OK;
}

/***********************************************************************
 *             RpcMgmtEpEltInqBegin (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcMgmtEpEltInqBegin(RPC_BINDING_HANDLE Binding, ULONG InquiryType,
    RPC_IF_ID *IfId, ULONG VersOption, UUID *ObjectUuid, RPC_EP_INQ_HANDLE* InquiryContext)
{
  FIXME("(%p,%lu,%p,%lu,%p,%p): stub\n",
        Binding, InquiryType, IfId, VersOption, ObjectUuid, InquiryContext);
  return RPC_S_INVALID_BINDING;
}

/***********************************************************************
 *             RpcMgmtIsServerListening (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcMgmtIsServerListening(RPC_BINDING_HANDLE Binding)
{
  RPC_STATUS status = RPC_S_NOT_LISTENING;

  TRACE("(%p)\n", Binding);

  if (Binding) {
    RpcBinding *rpc_binding = (RpcBinding*)Binding;
    /* Windows performs a remote management call for client bindings, which
     * also supports bindings that need endpoint resolution.  The direct
     * transport probe below cannot represent that operation. */
    if (!rpc_binding->Endpoint || !rpc_binding->Endpoint[0])
      return RPC_S_INVALID_BINDING;
    status = RPCRT4_IsServerListening(rpc_binding->Protseq, rpc_binding->Endpoint);
  }else {
    EnterCriticalSection(&listen_cs);
    if (listen_done_event && std_listen) status = RPC_S_OK;
    LeaveCriticalSection(&listen_cs);
  }

  return status;
}

/***********************************************************************
 *             RpcMgmtSetAuthorizationFn (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcMgmtSetAuthorizationFn(RPC_MGMT_AUTHORIZATION_FN fn)
{
  FIXME("(%p): stub\n", fn);
  return RPC_S_OK;
}

/***********************************************************************
 *             RpcMgmtSetServerStackSize (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcMgmtSetServerStackSize(ULONG ThreadStackSize)
{
  FIXME("(0x%lx): stub\n", ThreadStackSize);
  if (getenv("LINUXNT_DEBUG_DELAY_RPCSS_SERVICE")) Sleep(10000);
  return RPC_S_OK;
}

/***********************************************************************
 *             I_RpcGetCurrentCallHandle (RPCRT4.@)
 */
RPC_BINDING_HANDLE WINAPI I_RpcGetCurrentCallHandle(void)
{
    TRACE("\n");
    return RPCRT4_GetThreadCurrentCallHandle();
}

static RPC_STATUS rpc_server_inq_conn_address(RPC_BINDING_HANDLE client_binding,
                                               void *buffer, ULONG *buffer_size,
                                               ULONG *address_format)
{
    RpcBinding *binding;

    TRACE("%p %p %p %p\n", client_binding, buffer, buffer_size, address_format);

    binding = client_binding ? client_binding : RPCRT4_GetThreadCurrentCallHandle();
    if (!binding) return RPC_S_NO_CALL_ACTIVE;
    if (!binding->FromConn) return RPC_S_INVALID_BINDING;

    /* None of the current connection transports exposes a socket-address
     * inquiry operation.  Windows reports this as an unsupported transport
     * query, notably for ncalrpc, rather than raising an unimplemented-export
     * exception. */
    return RPC_S_CANNOT_SUPPORT;
}

/***********************************************************************
 *             I_RpcServerInqLocalConnAddress (RPCRT4.@)
 */
RPC_STATUS WINAPI I_RpcServerInqLocalConnAddress(RPC_BINDING_HANDLE client_binding,
                                                  void *buffer, ULONG *buffer_size,
                                                  ULONG *address_format)
{
    return rpc_server_inq_conn_address(client_binding, buffer, buffer_size, address_format);
}

/***********************************************************************
 *             I_RpcServerInqRemoteConnAddress (RPCRT4.@)
 */
RPC_STATUS WINAPI I_RpcServerInqRemoteConnAddress(RPC_BINDING_HANDLE client_binding,
                                                   void *buffer, ULONG *buffer_size,
                                                   ULONG *address_format)
{
    return rpc_server_inq_conn_address(client_binding, buffer, buffer_size, address_format);
}

/***********************************************************************
 *             I_RpcGetPortAllocationData (RPCRT4.@)
 */
void WINAPI I_RpcGetPortAllocationData(struct rpc_port_allocation_data *data)
{
    TRACE("%p\n", data);

    /* Windows returns this record when no port-allocation policy is configured. */
    memset(data, 0, sizeof(*data));
    data->unknown0 = 1;
    data->unknown8 = 3;
}

/***********************************************************************
 *             RpcServerInqBindingHandle (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcServerInqBindingHandle(RPC_BINDING_HANDLE *binding)
{
    RPC_BINDING_HANDLE current;

    TRACE("%p\n", binding);

    current = I_RpcGetCurrentCallHandle();
    if (!current) return RPC_S_NO_CALL_ACTIVE;

    *binding = current;
    return RPC_S_OK;
}

/***********************************************************************
 *             RpcServerTestCancel (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcServerTestCancel(RPC_BINDING_HANDLE client_binding)
{
    struct rpc_server_call *call;
    RpcBinding *binding;
    RPC_STATUS status;
    BOOL cancelled;

    TRACE("%p\n", client_binding);

    binding = client_binding ? client_binding : RPCRT4_GetThreadCurrentCallHandle();
    if (!binding) return RPC_S_NO_CALL_ACTIVE;
    if (!binding->FromConn) return RPC_S_INVALID_BINDING;

    status = rpc_server_call_from_binding(client_binding, &call);
    if (status != RPC_S_OK) return status;

    EnterCriticalSection(&call->cs);
    cancelled = call->cancelled;
    LeaveCriticalSection(&call->cs);

    return cancelled ? RPC_S_CALL_CANCELLED : RPC_S_CALL_IN_PROGRESS;
}

/***********************************************************************
 *             RpcServerSubscribeForNotification (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcServerSubscribeForNotification(RPC_BINDING_HANDLE binding,
                                                     RPC_NOTIFICATIONS notification,
                                                     RPC_NOTIFICATION_TYPES type,
                                                     RPC_ASYNC_NOTIFICATION_INFO *info)
{
    struct rpc_server_call *call;
    RPC_STATUS status;
    unsigned int i;
    BOOL disconnected, cancelled;

    TRACE("%p %#x %u %p\n", binding, notification, type, info);

    if (!notification || notification & ~(RpcNotificationClientDisconnect | RpcNotificationCallCancel))
        return RPC_S_CANNOT_SUPPORT;
    if (!info || type <= RpcNotificationTypeNone || type > RpcNotificationTypeCallback)
        return RPC_S_INVALID_ARG;
    if (type == RpcNotificationTypeEvent &&
        notification == (RpcNotificationClientDisconnect | RpcNotificationCallCancel))
        return RPC_S_INVALID_ARG;

    status = rpc_server_call_from_binding(binding, &call);
    if (status != RPC_S_OK) return status;

    EnterCriticalSection(&call->cs);
    for (i = 0; i < ARRAY_SIZE(call->notifications); ++i)
    {
        if (!(notification & (RpcNotificationClientDisconnect << i))) continue;
        if (call->notifications[i].subscribed)
        {
            LeaveCriticalSection(&call->cs);
            return RPC_S_ALREADY_REGISTERED;
        }
    }
    for (i = 0; i < ARRAY_SIZE(call->notifications); ++i)
    {
        if (!(notification & (RpcNotificationClientDisconnect << i))) continue;
        call->notifications[i].subscribed = TRUE;
        call->notifications[i].type = type;
        call->notifications[i].info = *info;
    }
    disconnected = call->disconnected;
    cancelled = call->cancelled;
    LeaveCriticalSection(&call->cs);

    if (disconnected && notification & RpcNotificationClientDisconnect)
        rpc_server_call_queue_notification(call, RpcNotificationClientDisconnect);
    if (cancelled && notification & RpcNotificationCallCancel)
        rpc_server_call_queue_notification(call, RpcNotificationCallCancel);

    return RPC_S_OK;
}

/***********************************************************************
 *             RpcServerUnsubscribeForNotification (RPCRT4.@)
 */
RPC_STATUS WINAPI RpcServerUnsubscribeForNotification(RPC_BINDING_HANDLE binding,
                                                       RPC_NOTIFICATIONS notification,
                                                       ULONG *notifications_queued)
{
    struct rpc_server_call *call;
    struct rpc_server_notification *state;
    RPC_STATUS status;
    unsigned int index;

    TRACE("%p %u %p\n", binding, notification, notifications_queued);

    if (notification != RpcNotificationClientDisconnect &&
        notification != RpcNotificationCallCancel)
        return RPC_S_CANNOT_SUPPORT;
    if (!notifications_queued) return RPC_S_INVALID_ARG;

    status = rpc_server_call_from_binding(binding, &call);
    if (status != RPC_S_OK) return status;

    index = notification - RpcNotificationClientDisconnect;
    EnterCriticalSection(&call->cs);
    state = &call->notifications[index];
    if (!state->subscribed)
    {
        LeaveCriticalSection(&call->cs);
        return RPC_S_INVALID_ARG;
    }
    state->subscribed = FALSE;
    *notifications_queued = state->queued;
    LeaveCriticalSection(&call->cs);
    return RPC_S_OK;
}

/***********************************************************************
 *             I_RpcSystemFunction001 (RPCRT4.@)
 */
RPC_STATUS WINAPI I_RpcSystemFunction001(ULONG selector, ULONG_PTR value, void *output)
{
    TRACE("%lu, %#Ix, %p\n", selector, value, output);

    switch (selector)
    {
    case 3:
    case 5:
        rpc_process_mode = value;
        return RPC_S_OK;
    case 4:
        *(ULONG *)output = rpc_process_mode;
        return RPC_S_OK;
    default:
        return RPC_S_INVALID_ARG;
    }
}

/***********************************************************************
 *             I_RpcServerRegisterForwardFunction (RPCRT4.@)
 */
RPC_STATUS WINAPI I_RpcServerRegisterForwardFunction(RPC_FORWARD_FUNCTION forward_fn)
{
    TRACE("%p\n", forward_fn);

    server_forward_function = forward_fn;
    return RPC_S_OK;
}

/***********************************************************************
 *             I_RpcServerInqAddressChangeFn (RPCRT4.@)
 */
void *WINAPI I_RpcServerInqAddressChangeFn(void)
{
    TRACE("\n");
    return server_address_change_fn;
}

/***********************************************************************
 *             I_RpcServerSetAddressChangeFn (RPCRT4.@)
 */
RPC_STATUS WINAPI I_RpcServerSetAddressChangeFn(void *address_change_fn)
{
    TRACE("%p\n", address_change_fn);
    server_address_change_fn = address_change_fn;
    return RPC_S_OK;
}
