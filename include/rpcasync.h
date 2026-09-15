/*
 * Copyright (C) 2007 Francois Gouget
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
#ifndef __WINE_RPCASYNC_H
#define __WINE_RPCASYNC_H

#ifdef RPC_NO_WINDOWS_H
# include <windef.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __RPC_WIN64__
# pragma pack(push,8)
#endif

typedef struct tagRPC_ERROR_ENUM_HANDLE
{
    ULONG Signature;
    void* CurrentPos;
    void* Head;
} RPC_ERROR_ENUM_HANDLE;

typedef enum tagExtendedErrorParamTypes
{
    eeptAnsiString = 1,
    eeptUnicodeString,
    eeptLongVal,
    eeptShortVal,
    eeptPointerVal,
    eeptNone,
    eeptBinary
} ExtendedErrorParamTypes;

#define MaxNumberOfEEInfoParams 4
#define RPC_EEINFO_VERSION      1

typedef struct tagBinaryParam
{
    void *Buffer;
    short Size;
} BinaryParam;

typedef struct tagRPC_EE_INFO_PARAM
{
    ExtendedErrorParamTypes ParameterType;
    union
    {
        LPSTR AnsiString;
        LPWSTR UnicodeString;
        LONG LVal;
        short SVal;
        ULONGLONG PVal;
        BinaryParam BVal;
    } u;
} RPC_EE_INFO_PARAM;

#define EEInfoPreviousRecordsMissing    0x1
#define EEInfoNextRecordsMissing        0x2
#define EEInfoUseFileTime               0x4

#define EEInfoGCCOM                     11
#define EEInfoGCFRS                     12

typedef struct tagRPC_EXTENDED_ERROR_INFO
{
    ULONG Version;
    LPWSTR ComputerName;
    ULONG ProcessID;
    union
    {
        SYSTEMTIME SystemTime;
        FILETIME FileTime;
    } u;
    ULONG GeneratingComponent;
    ULONG Status;
    USHORT DetectionLocation;
    USHORT Flags;
    int NumberOfParameters;
    RPC_EE_INFO_PARAM Parameters[MaxNumberOfEEInfoParams];
} RPC_EXTENDED_ERROR_INFO;

#define RPC_ASYNC_VERSION_1_0   sizeof(RPC_ASYNC_STATE)

typedef enum _RPC_NOTIFICATION_TYPES
{
    RpcNotificationTypeNone,
    RpcNotificationTypeEvent,
    RpcNotificationTypeApc,
    RpcNotificationTypeIoc,
    RpcNotificationTypeHwnd,
    RpcNotificationTypeCallback,
} RPC_NOTIFICATION_TYPES;

typedef enum _RPC_NOTIFICATIONS
{
    RpcNotificationCallNone,
    RpcNotificationClientDisconnect,
    RpcNotificationCallCancel,
} RPC_NOTIFICATIONS;

typedef enum _RPC_ASYNC_EVENT
{
    RpcCallComplete,
    RpcSendComplete,
    RpcReceiveComplete,
    RpcClientDisconnect,
    RpcClientCancel,
} RPC_ASYNC_EVENT;

struct _RPC_ASYNC_STATE;

typedef void RPC_ENTRY RPCNOTIFICATION_ROUTINE(struct _RPC_ASYNC_STATE *,void *,RPC_ASYNC_EVENT);
typedef RPCNOTIFICATION_ROUTINE *PFN_RPCNOTIFICATION_ROUTINE;

typedef union _RPC_ASYNC_NOTIFICATION_INFO
{
    struct
    {
        PFN_RPCNOTIFICATION_ROUTINE NotificationRoutine;
        HANDLE hThread;
    } APC;
    struct
    {
        HANDLE hIOPort;
        DWORD dwNumberOfBytesTransferred;
        DWORD_PTR dwCompletionKey;
        LPOVERLAPPED lpOverlapped;
    } IOC;
    struct
    {
        HWND hWnd;
        UINT Msg;
    } HWND;
    HANDLE hEvent;
    PFN_RPCNOTIFICATION_ROUTINE NotificationRoutine;
} RPC_ASYNC_NOTIFICATION_INFO, *PRPC_ASYNC_NOTIFICATION_INFO;

#define RPC_C_NOTIFY_ON_SEND_COMPLETE   0x1
#define RPC_C_INFINITE_TIMEOUT          INFINITE

typedef struct _RPC_ASYNC_STATE
{
    unsigned int Size;
    ULONG Signature;
    LONG Lock;
    ULONG Flags;
    void *StubInfo;
    void *UserInfo;
    void *RuntimeInfo;
    RPC_ASYNC_EVENT Event;
    RPC_NOTIFICATION_TYPES NotificationType;
    RPC_ASYNC_NOTIFICATION_INFO u;
    LONG_PTR Reserved[4];
} RPC_ASYNC_STATE, *PRPC_ASYNC_STATE;

#define RpcAsyncGetCallHandle(async) (((PRPC_ASYNC_STATE)async)->RuntimeInfo)

#define RPC_QUERY_SERVER_PRINCIPAL_NAME  0x02
#define RPC_QUERY_CLIENT_PRINCIPAL_NAME  0x04
#define RPC_QUERY_CALL_LOCAL_ADDRESS     0x08
#define RPC_QUERY_CLIENT_PID             0x10
#define RPC_QUERY_IS_CLIENT_LOCAL        0x20
#define RPC_QUERY_NO_AUTH_REQUIRED       0x40
#define RPC_QUERY_CLIENT_ID              0x80

#define RPC_CALL_STATUS_CANCELLED        0x01
#define RPC_CALL_STATUS_DISCONNECTED     0x02

typedef enum _RpcCallType
{
    rctInvalid,
    rctNormal,
    rctTraining,
    rctGuaranteed
} RpcCallType;

typedef enum _RpcLocalAddressFormat
{
    rlafInvalid,
    rlafIPv4,
    rlafIPv6
} RpcLocalAddressFormat;

typedef enum _RpcCallClientLocality
{
    rcclInvalid,
    rcclLocal,
    rcclRemote,
    rcclClientUnknownLocality
} RpcCallClientLocality;

typedef struct _RPC_CALL_LOCAL_ADDRESS_V1
{
    unsigned int Version;
    void *Buffer;
    ULONG BufferSize;
    RpcLocalAddressFormat AddressFormat;
} RPC_CALL_LOCAL_ADDRESS_V1, *PRPC_CALL_LOCAL_ADDRESS_V1;

typedef struct tagRPC_CALL_ATTRIBUTES_V1_W
{
    unsigned int Version;
    ULONG Flags;
    ULONG ServerPrincipalNameBufferLength;
    unsigned short *ServerPrincipalName;
    ULONG ClientPrincipalNameBufferLength;
    unsigned short *ClientPrincipalName;
    ULONG AuthenticationLevel;
    ULONG AuthenticationService;
    BOOL NullSession;
} RPC_CALL_ATTRIBUTES_V1_W;

typedef struct tagRPC_CALL_ATTRIBUTES_V2_W
{
    unsigned int Version;
    ULONG Flags;
    ULONG ServerPrincipalNameBufferLength;
    unsigned short *ServerPrincipalName;
    ULONG ClientPrincipalNameBufferLength;
    unsigned short *ClientPrincipalName;
    ULONG AuthenticationLevel;
    ULONG AuthenticationService;
    BOOL NullSession;
    BOOL KernelModeCaller;
    ULONG ProtocolSequence;
    RpcCallClientLocality IsClientLocal;
    HANDLE ClientPID;
    ULONG CallStatus;
    RpcCallType CallType;
    RPC_CALL_LOCAL_ADDRESS_V1 *CallLocalAddress;
    unsigned short OpNum;
    UUID InterfaceUuid;
} RPC_CALL_ATTRIBUTES_V2_W;

typedef struct tagRPC_CALL_ATTRIBUTES_V3_W
{
    unsigned int Version;
    ULONG Flags;
    ULONG ServerPrincipalNameBufferLength;
    unsigned short *ServerPrincipalName;
    ULONG ClientPrincipalNameBufferLength;
    unsigned short *ClientPrincipalName;
    ULONG AuthenticationLevel;
    ULONG AuthenticationService;
    BOOL NullSession;
    BOOL KernelModeCaller;
    ULONG ProtocolSequence;
    RpcCallClientLocality IsClientLocal;
    HANDLE ClientPID;
    ULONG CallStatus;
    RpcCallType CallType;
    RPC_CALL_LOCAL_ADDRESS_V1 *CallLocalAddress;
    unsigned short OpNum;
    UUID InterfaceUuid;
    ULONG ClientIdentifierBufferLength;
    unsigned char *ClientIdentifier;
} RPC_CALL_ATTRIBUTES_V3_W;

#ifdef __RPC_WIN64__
# pragma pack(pop)
#endif

RPCRTAPI RPC_STATUS RPC_ENTRY RpcAsyncInitializeHandle(PRPC_ASYNC_STATE,unsigned int);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcAsyncRegisterInfo(PRPC_ASYNC_STATE);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcAsyncGetCallStatus(PRPC_ASYNC_STATE);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcAsyncCompleteCall(PRPC_ASYNC_STATE,void *);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcAsyncAbortCall(PRPC_ASYNC_STATE,ULONG);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcAsyncCancelCall(PRPC_ASYNC_STATE,BOOL);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcAsyncCleanupThread(DWORD);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcBindingBind(PRPC_ASYNC_STATE,RPC_BINDING_HANDLE,RPC_IF_HANDLE);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcBindingUnbind(RPC_BINDING_HANDLE);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcServerInqCallAttributesW(RPC_BINDING_HANDLE,void *);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcServerSubscribeForNotification(RPC_BINDING_HANDLE,RPC_NOTIFICATIONS,RPC_NOTIFICATION_TYPES,RPC_ASYNC_NOTIFICATION_INFO *);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcServerUnsubscribeForNotification(RPC_BINDING_HANDLE,RPC_NOTIFICATIONS,ULONG *);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcErrorStartEnumeration(RPC_ERROR_ENUM_HANDLE*);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcErrorGetNextRecord(RPC_ERROR_ENUM_HANDLE*,BOOL,RPC_EXTENDED_ERROR_INFO*);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcErrorEndEnumeration(RPC_ERROR_ENUM_HANDLE*);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcErrorResetEnumeration(RPC_ERROR_ENUM_HANDLE*);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcErrorGetNumberOfRecords(RPC_ERROR_ENUM_HANDLE*,int*);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcErrorSaveErrorInfo(RPC_ERROR_ENUM_HANDLE*,PVOID*,SIZE_T*);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcErrorLoadErrorInfo(PVOID,SIZE_T,RPC_ERROR_ENUM_HANDLE*);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcErrorAddRecord(RPC_EXTENDED_ERROR_INFO*);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcErrorClearInformation(void);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcGetAuthorizationContextForClient(RPC_BINDING_HANDLE,BOOL,LPVOID,PLARGE_INTEGER,LUID,DWORD,PVOID,PVOID*);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcFreeAuthorizationContext(PVOID*);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcSsContextLockExclusive(RPC_BINDING_HANDLE,PVOID);
RPCRTAPI RPC_STATUS RPC_ENTRY RpcSsContextLockShared(RPC_BINDING_HANDLE,PVOID);

RPCRTAPI RPC_STATUS RPC_ENTRY I_RpcAsyncSetHandle(PRPC_MESSAGE,PRPC_ASYNC_STATE);
RPCRTAPI RPC_STATUS RPC_ENTRY I_RpcAsyncAbortCall(PRPC_ASYNC_STATE,ULONG);
RPCRTAPI int        RPC_ENTRY I_RpcExceptionFilter(ULONG);

#ifdef __cplusplus
}
#endif

#endif
