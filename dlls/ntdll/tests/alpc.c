/*
 * Advanced Local Procedure Call tests
 *
 * Copyright 2026 Zhiyi Zhang for CodeWeavers
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
#include <windef.h>
#include <winternl.h>
#include <ntstatus.h>
#include "wine/test.h"

#define DECL_FUNCPTR(f) static typeof(f) *p##f;

DECL_FUNCPTR(AlpcGetHeaderSize)
DECL_FUNCPTR(AlpcGetMessageAttribute)
DECL_FUNCPTR(AlpcInitializeMessageAttribute)
DECL_FUNCPTR(NtAlpcAcceptConnectPort)
DECL_FUNCPTR(NtAlpcCancelMessage)
DECL_FUNCPTR(NtAlpcCreatePort)
DECL_FUNCPTR(NtAlpcConnectPort)
DECL_FUNCPTR(NtAlpcConnectPortEx)
DECL_FUNCPTR(NtAlpcQueryInformation)
DECL_FUNCPTR(NtAlpcSendWaitReceivePort)

#undef DECL_FUNCPTR

static void init_functions(void)
{
    HMODULE ntdll;

    ntdll = GetModuleHandleA("ntdll.dll");
    ok(ntdll != NULL, "GetModuleHandleA failed.\n");

#define LOAD_FUNCPTR(f) p##f = (void *)GetProcAddress(ntdll, #f);

    LOAD_FUNCPTR(AlpcGetHeaderSize)
    LOAD_FUNCPTR(AlpcGetMessageAttribute)
    LOAD_FUNCPTR(AlpcInitializeMessageAttribute)
    LOAD_FUNCPTR(NtAlpcAcceptConnectPort)
    LOAD_FUNCPTR(NtAlpcCancelMessage)
    LOAD_FUNCPTR(NtAlpcCreatePort)
    LOAD_FUNCPTR(NtAlpcConnectPort)
    LOAD_FUNCPTR(NtAlpcConnectPortEx)
    LOAD_FUNCPTR(NtAlpcQueryInformation)
    LOAD_FUNCPTR(NtAlpcSendWaitReceivePort)

#undef LOAD_FUNCPTR
}

static void init_port_attr(ALPC_PORT_ATTRIBUTES *attr, ULONG flags, SIZE_T max_msg_length)
{
    attr->Flags = flags;
    attr->SecurityQos.Length = sizeof(attr->SecurityQos);
    attr->SecurityQos.ImpersonationLevel = SecurityIdentification;
    attr->SecurityQos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
    attr->SecurityQos.EffectiveOnly = FALSE;
    attr->MaxMessageLength = max_msg_length;
    attr->MemoryBandwidth = 512;
    attr->MaxPoolUsage = 0xffffffff;
    attr->MaxSectionSize = 0xffffffff;
    attr->MaxViewSize = 0xffffffff;
    attr->MaxTotalSectionSize = 0xffffffff;
    attr->DupObjectTypes = (flags & ALPC_PORTFLG_ALLOW_DUP_OBJECT) ? 0xffffffff : 0;
}

static void test_AlpcGetHeaderSize(void)
{
    unsigned int i, j;
    SIZE_T size;

    static const struct
    {
        ULONG attribute;
        SIZE_T size;
    }
    tests[] =
    {
        {0, 0},
        {1u << 1, 0},
        {1u << 2, 0},
        {1u << 3, 0},
        {1u << 4, 0},
        {1u << 5, 0},
        {1u << 6, 0},
        {1u << 7, 0},
        {1u << 8, 0},
        {1u << 9, 0},
        {1u << 10, 0},
        {1u << 11, 0},
        {1u << 12, 0},
        {1u << 13, 0},
        {1u << 14, 0},
        {1u << 15, 0},
        {1u << 16, 0},
        {1u << 17, 0},
        {1u << 18, 0},
        {1u << 19, 0},
        {1u << 20, 0},
        {1u << 21, 0},
        {1u << 22, 0},
        {1u << 23, 0},
        {1u << 24, 0},
        {1u << 25, sizeof(ALPC_WORK_ON_BEHALF_ATTR)},   /* ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE */
        {1u << 26, sizeof(ALPC_DIRECT_ATTR)},           /* ALPC_MESSAGE_DIRECT_ATTRIBUTE */
        {1u << 27, sizeof(ALPC_TOKEN_ATTR)},            /* ALPC_MESSAGE_TOKEN_ATTRIBUTE */
        {1u << 28, sizeof(ALPC_HANDLE_ATTR)},           /* ALPC_MESSAGE_HANDLE_ATTRIBUTE */
        {1u << 29, sizeof(ALPC_CONTEXT_ATTR)},          /* ALPC_MESSAGE_CONTEXT_ATTRIBUTE */
        {1u << 30, sizeof(ALPC_VIEW_ATTR)},             /* ALPC_MESSAGE_VIEW_ATTRIBUTE */
        {1u << 31, sizeof(ALPC_SECURITY_ATTR)},         /* ALPC_MESSAGE_SECURITY_ATTRIBUTE */
        {0xffffffff, sizeof(ALPC_WORK_ON_BEHALF_ATTR) +
                     sizeof(ALPC_DIRECT_ATTR) +
                     sizeof(ALPC_TOKEN_ATTR) +
                     sizeof(ALPC_HANDLE_ATTR) +
                     sizeof(ALPC_CONTEXT_ATTR) +
                     sizeof(ALPC_VIEW_ATTR) +
                     sizeof(ALPC_SECURITY_ATTR)},       /* All attributes */
    };

    if (!pAlpcGetHeaderSize)
    {
        win_skip("AlpcGetHeaderSize is unavailable.\n");
        return;
    }

    for (i = 0; i < ARRAY_SIZE(tests); i++)
    {
        winetest_push_context("i %d", i);

        /* Single attribute */
        size = pAlpcGetHeaderSize(tests[i].attribute);
        ok(size == sizeof(ALPC_MESSAGE_ATTRIBUTES) + tests[i].size, "Got unexpected size %Ix.\n", size);

        /* Two attributes */
        for (j = 0; j < ARRAY_SIZE(tests); j++)
        {
            if (tests[i].attribute & tests[j].attribute)
                continue;

            winetest_push_context("j %d", j);

            size = pAlpcGetHeaderSize(tests[i].attribute | tests[j].attribute);
            ok(size == sizeof(ALPC_MESSAGE_ATTRIBUTES) + tests[i].size + tests[j].size,
               "Got unexpected size %Ix.\n", size);

            winetest_pop_context();
        }
        winetest_pop_context();
    }
}

static void test_AlpcGetMessageAttribute(void)
{
    unsigned char buffer[1024];
    ALPC_MESSAGE_ATTRIBUTES *attr = (ALPC_MESSAGE_ATTRIBUTES *)buffer;
    unsigned int i, j;
    void *ptr;

    static const ULONG attributes[] =
    {
        0,
        ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE,
        ALPC_MESSAGE_DIRECT_ATTRIBUTE,
        ALPC_MESSAGE_TOKEN_ATTRIBUTE,
        ALPC_MESSAGE_HANDLE_ATTRIBUTE,
        ALPC_MESSAGE_CONTEXT_ATTRIBUTE,
        ALPC_MESSAGE_VIEW_ATTRIBUTE,
        ALPC_MESSAGE_SECURITY_ATTRIBUTE,
    };

    if (!pAlpcGetMessageAttribute)
    {
        win_skip("AlpcGetMessageAttribute is unavailable.\n");
        return;
    }

    /* Invalid flag */
    attr->AllocatedAttributes = ALPC_MESSAGE_ATTRIBUTE_ALL;
    attr->ValidAttributes = ALPC_MESSAGE_ATTRIBUTE_ALL;
    ptr = pAlpcGetMessageAttribute(attr, 0x1);
    ok(ptr == NULL, "Got unexpected ptr.\n");

    for (i = 0; i < ARRAY_SIZE(attributes); i++)
    {
        winetest_push_context("%#lx", attributes[i]);

        /* The message has no allocated attributes */
        attr->AllocatedAttributes = 0;
        attr->ValidAttributes = attributes[i];
        ptr = pAlpcGetMessageAttribute(attr, attributes[i]);
        ok(ptr == NULL, "Got unexpected ptr.\n");

        /* The message has no valid attributes */
        attr->AllocatedAttributes = attributes[i];
        attr->ValidAttributes = 0;
        ptr = pAlpcGetMessageAttribute(attr, attributes[i]);
        if (attributes[i])
            ok(ptr == ((unsigned char *)attr + sizeof(*attr)), "Got unexpected ptr.\n");
        else
            ok(ptr == NULL, "Got unexpected ptr.\n");

        /* Normal calls */
        attr->AllocatedAttributes = attributes[i];
        attr->ValidAttributes = attributes[i];
        ptr = pAlpcGetMessageAttribute(attr, attributes[i]);
        if (attributes[i])
            ok(ptr == ((unsigned char *)attr + sizeof(*attr)), "Got unexpected ptr.\n");
        else
            ok(ptr == NULL, "Got unexpected ptr.\n");

        /* The message has full attributes */
        attr->AllocatedAttributes = ALPC_MESSAGE_ATTRIBUTE_ALL;
        attr->ValidAttributes = ALPC_MESSAGE_ATTRIBUTE_ALL;
        ptr = pAlpcGetMessageAttribute(attr, attributes[i]);
        if (attributes[i])
            ok(ptr == ((unsigned char *)attr + pAlpcGetHeaderSize(attr->AllocatedAttributes & ~(attributes[i] | (attributes[i] - 1)))),
               "Got unexpected ptr.\n");
        else
            ok(ptr == NULL, "Got unexpected ptr.\n");

        /* The message has some valid attributes */
        for (j = 0; j < ARRAY_SIZE(attributes); j++)
        {
            attr->AllocatedAttributes = ALPC_MESSAGE_ATTRIBUTE_ALL;
            attr->ValidAttributes = ALPC_MESSAGE_ATTRIBUTE_ALL & ~attributes[j];
            ptr = pAlpcGetMessageAttribute(attr, attributes[i]);
            if (attributes[i])
                ok(ptr == ((unsigned char *)attr + pAlpcGetHeaderSize(attr->AllocatedAttributes & ~(attributes[i] | (attributes[i] - 1)))),
                   "Got unexpected ptr.\n");
            else
                ok(ptr == NULL, "Got unexpected ptr.\n");
        }

        /* Two attributes are passed to AlpcGetMessageAttribute() */
        for (j = 0; j < ARRAY_SIZE(attributes); j++)
        {
            if (!attributes[i] || !attributes[j] || attributes[i] == attributes[j])
                continue;

            attr->AllocatedAttributes = ALPC_MESSAGE_ATTRIBUTE_ALL;
            attr->ValidAttributes = ALPC_MESSAGE_ATTRIBUTE_ALL;
            ptr = pAlpcGetMessageAttribute(attr, attributes[i] | attributes[j]);
            ok(ptr == NULL, "Got unexpected ptr.\n");
        }

        winetest_pop_context();
    }
}

static void test_AlpcInitializeMessageAttribute(void)
{
    unsigned char buffer[1024];
    ALPC_MESSAGE_ATTRIBUTES *attr = (ALPC_MESSAGE_ATTRIBUTES *)buffer;
    SIZE_T required_size, size;
    unsigned int i, j, k;
    NTSTATUS status;

    static const ULONG attributes[] =
    {
        0,
        ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE,
        ALPC_MESSAGE_DIRECT_ATTRIBUTE,
        ALPC_MESSAGE_TOKEN_ATTRIBUTE,
        ALPC_MESSAGE_HANDLE_ATTRIBUTE,
        ALPC_MESSAGE_CONTEXT_ATTRIBUTE,
        ALPC_MESSAGE_VIEW_ATTRIBUTE,
        ALPC_MESSAGE_SECURITY_ATTRIBUTE,
        0xffffffff,
    };

    if (!pAlpcInitializeMessageAttribute)
    {
        win_skip("AlpcInitializeMessageAttribute is unavailable.\n");
        return;
    }

    /* Check parameters */
    for (i = 0; i < ARRAY_SIZE(attributes); i++)
    {
        winetest_push_context("i %d", i);

        size = pAlpcGetHeaderSize(attributes[i]);

        /* Null message pointer */
        required_size = 0;
        status = pAlpcInitializeMessageAttribute(attributes[i], NULL, size, &required_size);
        ok(status == STATUS_SUCCESS, "Got unexpected status %#lx.\n", status);
        ok(required_size == size, "Expected %Ix, got %Ix.\n", size, required_size);

        /* Buffer too small */
        attr->AllocatedAttributes = 0xdeadbeef;
        attr->ValidAttributes = 0xdeadbeef;
        required_size = 0;
        status = pAlpcInitializeMessageAttribute(attributes[i], attr, size - 1, &required_size);
        ok(status == STATUS_BUFFER_TOO_SMALL, "Got unexpected status %#lx.\n", status);
        ok(attr->AllocatedAttributes == 0xdeadbeef, "Got unexpected %#lx.\n", attr->AllocatedAttributes);
        ok(attr->ValidAttributes == 0xdeadbeef, "Got unexpected %#lx.\n", attr->ValidAttributes);
        ok(required_size == size, "Expected %Ix, got %Ix.\n", size, required_size);

        /* Buffer too large */
        attr->AllocatedAttributes = 0xdeadbeef;
        attr->ValidAttributes = 0xdeadbeef;
        required_size = 0;
        status = pAlpcInitializeMessageAttribute(attributes[i], attr, size + 1, &required_size);
        ok(status == STATUS_SUCCESS, "Got unexpected status %#lx.\n", status);
        ok(attr->AllocatedAttributes == attributes[i], "Got unexpected %#lx.\n", attr->AllocatedAttributes);
        ok(attr->ValidAttributes == 0, "Got unexpected %#lx.\n", attr->ValidAttributes);
        ok(required_size == size, "Expected %Ix, got %Ix.\n", size, required_size);

        /* Correct buffer size */
        memset(buffer, 0xa1, sizeof(buffer));
        required_size = 0;
        status = pAlpcInitializeMessageAttribute(attributes[i], attr, size, &required_size);
        ok(status == STATUS_SUCCESS, "Got unexpected status %#lx.\n", status);
        ok(attr->AllocatedAttributes == attributes[i], "Got unexpected %#lx.\n", attr->AllocatedAttributes);
        ok(attr->ValidAttributes == 0, "Got unexpected %#lx.\n", attr->ValidAttributes);
        ok(required_size == size, "Expected %Ix, got %Ix.\n", size, required_size);
        /* Test that AlpcInitializeMessageAttribute() only sets AllocatedAttributes and ValidAttributes */
        for (k = sizeof(*attr); k < sizeof(buffer); k++)
        {
            if (buffer[k] != 0xa1)
            {
                ok(0, "Marker got overwritten at %d.\n", k);
                break;
            }
        }

        /* Two attributes */
        for (j = 0; j < ARRAY_SIZE(attributes); j++)
        {
            if (attributes[i] & attributes[j])
                continue;

            winetest_push_context("j %d", j);

            memset(buffer, 0xb2, sizeof(buffer));
            size = pAlpcGetHeaderSize(attributes[i] | attributes[j]);
            required_size = 0;
            status = pAlpcInitializeMessageAttribute(attributes[i] | attributes[j], attr, size, &required_size);
            ok(status == STATUS_SUCCESS, "Got unexpected status %#lx.\n", status);
            ok(attr->AllocatedAttributes == (attributes[i] | attributes[j]),
               "Got unexpected %#lx.\n", attr->AllocatedAttributes);
            ok(attr->ValidAttributes == 0, "Got unexpected %#lx.\n", attr->ValidAttributes);
            ok(required_size == size, "Expected %Ix, got %Ix.\n", size, required_size);
            /* Test that AlpcInitializeMessageAttribute() only sets AllocatedAttributes and ValidAttributes */
            for (k = sizeof(*attr); k < sizeof(buffer); k++)
            {
                if (buffer[k] != 0xb2)
                {
                    ok(0, "Marker got overwritten at %d.\n", k);
                    break;
                }
            }

            winetest_pop_context();
        }
        winetest_pop_context();
    }
}

static void test_NtAlpcCreatePort(void)
{
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\test_NtAlpcCreatePort_port");
    OBJECT_NAME_INFORMATION *name_info;
    OBJECT_TYPE_INFORMATION *type_info;
    ALPC_PORT_ATTRIBUTES port_attr;
    OBJECT_BASIC_INFORMATION info;
    unsigned char buffer[1024];
    HANDLE handle, handle2;
    OBJECT_ATTRIBUTES attr;
    DWORD size, flags;
    NTSTATUS status;
    ULONG flag;
    BOOL ret;

    if (!pNtAlpcCreatePort)
    {
        win_skip("NtAlpcCreatePort is unavailable.\n");
        return;
    }

    InitializeObjectAttributes(&attr, &name, 0, NULL, NULL);
    init_port_attr(&port_attr, 0, 1024);

    /* Check parameters */
    status = pNtAlpcCreatePort(NULL, &attr, &port_attr);
    ok(status == STATUS_ACCESS_VIOLATION, "Got unexpected status %#lx.\n", status);

    status = pNtAlpcCreatePort(&handle, NULL, &port_attr);
    ok(status == STATUS_SUCCESS, "Got unexpected status %#lx.\n", status);
    ret = GetHandleInformation(handle, &flags);
    ok(ret, "GetHandleInformation failed, error %ld.\n", GetLastError());
    CloseHandle(handle);

    status = pNtAlpcCreatePort(&handle, &attr, NULL);
    ok(status == STATUS_SUCCESS, "Got unexpected status %#lx.\n", status);
    ret = GetHandleInformation(handle, &flags);
    ok(ret, "GetHandleInformation failed, error %ld.\n", GetLastError());
    CloseHandle(handle);

    status = pNtAlpcCreatePort(&handle, NULL, NULL);
    ok(status == STATUS_SUCCESS, "Got unexpected status %#lx.\n", status);
    ret = GetHandleInformation(handle, &flags);
    ok(ret, "GetHandleInformation failed, error %ld.\n", GetLastError());
    CloseHandle(handle);

    /* Normal calls */
    status = pNtAlpcCreatePort(&handle, &attr, &port_attr);
    ok(status == STATUS_SUCCESS, "Got unexpected status %#lx.\n", status);

    /* Check handle */
    ret = GetHandleInformation(handle, &flags);
    ok(ret, "GetHandleInformation failed, error %ld.\n", GetLastError());

    /* Check object attributes and granted access */
    status = NtQueryObject(handle, ObjectBasicInformation, &info, sizeof(info), NULL);
    ok(status == STATUS_SUCCESS, "Got unexpected status %#lx.\n", status);
    ok(info.Attributes == 0, "Got attributes %#lx\n", info.Attributes);
    ok(info.GrantedAccess == (STANDARD_RIGHTS_ALL | 0x1), "Got access %#lx\n", info.GrantedAccess);

    /* Check object name */
    status = NtQueryObject(handle, ObjectNameInformation, buffer, sizeof(buffer), &size);
    ok(status == STATUS_SUCCESS, "Got unexpected status %#lx.\n", status);
    name_info = (OBJECT_NAME_INFORMATION *)buffer;
    ok(!wcsicmp(name_info->Name.Buffer, name.Buffer), "Got unexpected name %s.\n",
       debugstr_w(name_info->Name.Buffer));

    /* Check object type */
    status = NtQueryObject(handle, ObjectTypeInformation, buffer, sizeof(buffer), &size);
    ok(status == STATUS_SUCCESS, "Got unexpected status %#lx.\n", status);
    type_info = (OBJECT_TYPE_INFORMATION *)buffer;
    ok(!wcscmp(type_info->TypeName.Buffer, L"ALPC Port"), "Got unexpected type %s.\n",
       debugstr_w(type_info->TypeName.Buffer));

    /* Duplicate name */
    status = pNtAlpcCreatePort(&handle2, &attr, &port_attr);
    ok(status == STATUS_OBJECT_NAME_COLLISION, "Got unexpected status %#lx.\n", status);

    CloseHandle(handle);

    /* Test handle validity after deletion */
    ret = GetHandleInformation(handle, &flags);
    ok(!ret, "GetHandleInformation succeeded.\n");

    /* Test Flags */
    for (flag = 0x1; flag != 0; flag = flag << 1)
    {
        winetest_push_context("%#lx", flag);

        port_attr.Flags = flag;
        status = pNtAlpcCreatePort(&handle, &attr, &port_attr);
        if (flag == 0x100000)
        {
            ok(status == STATUS_INVALID_PARAMETER, "Got unexpected status %#lx.\n", status);
            winetest_pop_context();
            continue;
        }
        else
        {
            ok(status == STATUS_SUCCESS, "Got unexpected status %#lx.\n", status);
        }
        ret = GetHandleInformation(handle, &flags);
        ok(ret, "GetHandleInformation failed, error %ld.\n", GetLastError());
        status = NtQueryObject(handle, ObjectBasicInformation, &info, sizeof(info), NULL);
        ok(status == STATUS_SUCCESS, "Got unexpected status %#lx.\n", status);
        ok(info.Attributes == 0, "Got attributes %#lx\n", info.Attributes);
        ok(info.GrantedAccess == (STANDARD_RIGHTS_ALL | 0x1), "Got access %#lx\n", info.GrantedAccess);

        CloseHandle(handle);
        winetest_pop_context();
    }
}

static void test_power_port(void)
{
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\PowerPort");
    ALPC_PORT_ATTRIBUTES port_attr;
    HANDLE handle = NULL;
    NTSTATUS status;

    if (!pNtAlpcConnectPort)
    {
        win_skip("NtAlpcConnectPort is unavailable.\n");
        return;
    }

    init_port_attr(&port_attr, 0x20000, 0x20000);
    status = pNtAlpcConnectPort(&handle, &name, NULL, &port_attr, 0x20000,
                                NULL, NULL, NULL, NULL, NULL, NULL);
    ok(status == STATUS_SUCCESS, "Got unexpected status %#lx.\n", status);
    if (!status) CloseHandle(handle);

    handle = NULL;
    status = pNtAlpcConnectPort(&handle, &name, NULL, &port_attr,
                                ALPC_SYNC_CONNECTION | ALPC_PORTFLG_ALLOW_DUP_OBJECT,
                                NULL, NULL, NULL, NULL, NULL, NULL);
    ok(status == STATUS_SUCCESS, "Allow-duplicate-object connect returned %#lx.\n", status);
    if (!status) CloseHandle(handle);
}

static void test_NtAlpcQueryInformation(void)
{
    ALPC_BASIC_INFORMATION info = {0xdeadbeef, 0xdeadbeef, (void *)0xdeadbeef};
    ALPC_PORT_MESSAGE message;
    ALPC_PORT_ATTRIBUTES attr = {0};
    LARGE_INTEGER timeout = {0};
    ULONG return_length = 0;
    HANDLE handle = NULL;
    NTSTATUS status;

    if (!pNtAlpcQueryInformation || !pNtAlpcSendWaitReceivePort)
    {
        win_skip("NtAlpcQueryInformation is unavailable.\n");
        return;
    }

    attr.Flags = 0x20000;
    attr.MaxMessageLength = 0x400;
    status = pNtAlpcCreatePort(&handle, NULL, &attr);
    ok(status == STATUS_SUCCESS, "Got unexpected status %#lx.\n", status);
    if (status) return;

    status = pNtAlpcQueryInformation(handle, 0, &info, sizeof(info), &return_length);
    ok(status == STATUS_SUCCESS, "Got unexpected status %#lx.\n", status);
    ok(return_length == sizeof(info), "Got return length %lu.\n", return_length);
    ok(info.Flags == attr.Flags, "Got flags %#lx.\n", info.Flags);
    ok(info.SequenceNo == 0, "Got sequence number %lu.\n", info.SequenceNo);
    ok(info.PortContext == NULL, "Got port context %p.\n", info.PortContext);

    status = pNtAlpcSendWaitReceivePort(handle, 0, NULL, NULL, &message, NULL, NULL, &timeout);
    ok(status == STATUS_TIMEOUT, "Got unexpected status %#lx.\n", status);

    CloseHandle(handle);
}

static void test_reply_receive_validation(void)
{
    ALPC_PORT_MESSAGE send = {0}, receive;
    NTSTATUS status;

    if (!pNtAlpcSendWaitReceivePort)
    {
        win_skip("NtAlpcSendWaitReceivePort is unavailable.\n");
        return;
    }

    send.TotalLength = sizeof(send);
    send.MessageId = 1;
    status = pNtAlpcSendWaitReceivePort((HANDLE)0xdead, 0x20000, &send, NULL,
                                        &receive, NULL, NULL, NULL);
    ok(status == STATUS_INVALID_HANDLE, "Got unexpected status %#lx.\n", status);
}

struct alpc_test_frame
{
    ALPC_PORT_MESSAGE header;
    BYTE data[32];
};

struct alpc_connect_context
{
    UNICODE_STRING name;
    ALPC_PORT_ATTRIBUTES attr;
    HANDLE port;
    NTSTATUS status;
};

struct alpc_sender_context
{
    HANDLE port;
    struct alpc_test_frame sent;
    struct alpc_test_frame received;
    SIZE_T capacity;
    LARGE_INTEGER timeout;
    NTSTATUS status;
};

static DWORD WINAPI alpc_connect_thread(void *arg)
{
    struct alpc_connect_context *context = arg;
    struct alpc_test_frame message = {0};
    SIZE_T size = sizeof(message);
    LARGE_INTEGER timeout;

    timeout.QuadPart = -100000000;
    message.header.TotalLength = sizeof(message.header);
    context->status = pNtAlpcConnectPort(&context->port, &context->name, NULL, &context->attr,
                                         0x20000, NULL, &message.header, &size, NULL, NULL, &timeout);
    return 0;
}

static void test_received_token_acceptance(void)
{
    unsigned int mode;

    if (!pNtAlpcAcceptConnectPort || !pAlpcInitializeMessageAttribute || !pAlpcGetMessageAttribute)
    {
        win_skip("ALPC acceptance attributes are unavailable.\n");
        return;
    }
    for (mode = 0; mode < 4; ++mode)
    {
        struct alpc_connect_context context = {0};
        struct alpc_test_frame message = {0};
        union { ULONGLONG align; BYTE bytes[256]; } buffer;
        ALPC_MESSAGE_ATTRIBUTES *attributes = (void *)&buffer;
        ALPC_TOKEN_ATTR *token;
        OBJECT_ATTRIBUTES object;
        LARGE_INTEGER zero = {0};
        HANDLE listener = NULL, server = NULL, thread = NULL;
        WCHAR name[100];
        SIZE_T size = sizeof(message), required;
        ULONG valid;
        NTSTATUS status;

        winetest_push_context("mode %u", mode);
        swprintf(name, ARRAY_SIZE(name), L"\\BaseNamedObjects\\WineAcceptToken_%lu_%u",
                 GetCurrentProcessId(), mode);
        RtlInitUnicodeString(&context.name, name);
        init_port_attr(&context.attr, 0x70000, sizeof(message));
        context.attr.SecurityQos.ImpersonationLevel = SecurityIdentification;
        context.attr.SecurityQos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
        InitializeObjectAttributes(&object, &context.name, 0, NULL, NULL);
        status = pNtAlpcCreatePort(&listener, &object, &context.attr);
        ok(!status, "Create port returned %#lx.\n", status);
        if (status) goto cleanup;
        thread = CreateThread(NULL, 0, alpc_connect_thread, &context, 0, NULL);
        ok(!!thread, "CreateThread failed, error %lu.\n", GetLastError());
        if (!thread) goto cleanup;
        ok(WaitForSingleObject(listener, 3000) == WAIT_OBJECT_0, "Listener not signaled.\n");
        memset(&buffer, 0xcc, sizeof(buffer));
        status = pAlpcInitializeMessageAttribute(mode ? 0xfa000000 : ALPC_MESSAGE_TOKEN_ATTRIBUTE,
                                                 attributes, sizeof(buffer), &required);
        ok(!status, "Initialize attributes returned %#lx.\n", status);
        if (status) goto cleanup;
        status = pNtAlpcSendWaitReceivePort(listener, 0, NULL, NULL, &message.header,
                                            &size, attributes, &zero);
        ok(!status, "Receive returned %#lx.\n", status);
        if (status) goto cleanup;
        valid = attributes->ValidAttributes;
        ok(valid == ALPC_MESSAGE_TOKEN_ATTRIBUTE, "Valid attributes %#lx.\n", valid);
        token = pAlpcGetMessageAttribute(attributes, ALPC_MESSAGE_TOKEN_ATTRIBUTE);
        if (mode == 2) memset(token, 0x5a, sizeof(*token));
        SetLastError(0x12345678);
        status = pNtAlpcAcceptConnectPort(&server, listener, 0, NULL, &context.attr,
                                          NULL, &message.header, attributes, mode != 3);
        ok(!status, "Accept returned %#lx.\n", status);
        ok(GetLastError() == 0x12345678, "Last error changed to %lu.\n", GetLastError());
        ok(attributes->ValidAttributes == valid, "Valid attributes changed.\n");
        if (status) goto cleanup;
        ok(WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0, "Connector did not finish.\n");
        ok(context.status == (mode == 3 ? STATUS_PORT_CONNECTION_REFUSED : STATUS_SUCCESS),
           "Connect returned %#lx.\n", context.status);

cleanup:
        if (listener) CloseHandle(listener);
        if (thread)
        {
            ok(WaitForSingleObject(thread, 11000) == WAIT_OBJECT_0, "Connector did not exit.\n");
            CloseHandle(thread);
        }
        if (!context.status && context.port) CloseHandle(context.port);
        if (server) CloseHandle(server);
        winetest_pop_context();
    }
}

static BOOL connect_alpc_pair(HANDLE listener, UNICODE_STRING *name, ALPC_PORT_ATTRIBUTES *attr,
                              HANDLE *server, HANDLE *client, void *port_context)
{
    struct alpc_connect_context context = {0};
    struct alpc_test_frame request = {0};
    LARGE_INTEGER zero = {0};
    HANDLE thread = NULL;
    SIZE_T size = sizeof(request);
    NTSTATUS status;
    BOOL ret = FALSE;

    context.name = *name;
    context.attr = *attr;
    thread = CreateThread(NULL, 0, alpc_connect_thread, &context, 0, NULL);
    ok(thread != NULL, "CreateThread failed, error %lu.\n", GetLastError());
    if (!thread) goto done;
    ok(WaitForSingleObject(listener, 3000) == WAIT_OBJECT_0, "Listener was not signaled.\n");
    status = pNtAlpcSendWaitReceivePort(listener, 0, NULL, NULL, &request.header, &size, NULL, &zero);
    ok(status == STATUS_SUCCESS, "Connection receive returned %#lx.\n", status);
    if (status) goto done;
    status = pNtAlpcAcceptConnectPort(server, listener, 0, NULL, &context.attr, port_context,
                                      &request.header, NULL, TRUE);
    ok(status == STATUS_SUCCESS, "NtAlpcAcceptConnectPort returned %#lx.\n", status);
    if (status) goto done;
    ok(WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0, "Connect thread did not finish.\n");
    ok(context.status == STATUS_SUCCESS, "NtAlpcConnectPort returned %#lx.\n", context.status);
    if (context.status) goto done;
    *client = context.port;
    context.port = NULL;
    ret = TRUE;

done:
    if (thread) CloseHandle(thread);
    if (context.port) CloseHandle(context.port);
    if (!ret && *server) CloseHandle(*server);
    if (!ret) *server = NULL;
    return ret;
}

static BOOL create_alpc_pair(HANDLE *listener, HANDLE *server, HANDLE *client, void *port_context)
{
    static LONG sequence;
    ALPC_PORT_ATTRIBUTES attr;
    OBJECT_ATTRIBUTES object_attr;
    UNICODE_STRING name_string;
    WCHAR name[96];
    NTSTATUS status;

    swprintf(name, ARRAY_SIZE(name), L"\\BaseNamedObjects\\winetest_alpc_cancel_%lu_%ld",
             GetCurrentProcessId(), InterlockedIncrement(&sequence));
    RtlInitUnicodeString(&name_string, name);
    init_port_attr(&attr, 0x70000, sizeof(struct alpc_test_frame));
    InitializeObjectAttributes(&object_attr, &name_string, 0, NULL, NULL);

    status = pNtAlpcCreatePort(listener, &object_attr, &attr);
    ok(status == STATUS_SUCCESS, "NtAlpcCreatePort returned %#lx.\n", status);
    if (status) return FALSE;
    if (connect_alpc_pair(*listener, &name_string, &attr, server, client, port_context)) return TRUE;
    CloseHandle(*listener);
    *listener = NULL;
    return FALSE;
}

static DWORD WINAPI alpc_sender_thread(void *arg)
{
    struct alpc_sender_context *context = arg;

    context->sent.header.DataLength = 1;
    context->sent.header.TotalLength = sizeof(context->sent.header) + 1;
    context->sent.data[0] = 0x42;
    context->capacity = sizeof(context->received);
    context->status = pNtAlpcSendWaitReceivePort(context->port, 0x20000, &context->sent.header, NULL,
                                                 &context->received.header, &context->capacity, NULL,
                                                 &context->timeout);
    return 0;
}

static void test_accepted_port_routing(void)
{
    static LONG sequence;
    ALPC_PORT_ATTRIBUTES attr;
    struct alpc_test_frame first = {0}, second = {0}, received = {0};
    OBJECT_ATTRIBUTES object_attr;
    HANDLE listener = NULL, server1 = NULL, server2 = NULL, client1 = NULL, client2 = NULL;
    LARGE_INTEGER zero = {0};
    UNICODE_STRING name_string;
    WCHAR name[96];
    SIZE_T size;
    NTSTATUS status;

    if (!pNtAlpcAcceptConnectPort || !pNtAlpcConnectPort || !pNtAlpcCreatePort ||
        !pNtAlpcSendWaitReceivePort)
    {
        win_skip("Accepted-port routing dependencies are unavailable.\n");
        return;
    }

    swprintf(name, ARRAY_SIZE(name), L"\\BaseNamedObjects\\winetest_alpc_route_%lu_%ld",
             GetCurrentProcessId(), InterlockedIncrement(&sequence));
    RtlInitUnicodeString(&name_string, name);
    init_port_attr(&attr, 0x70000, sizeof(first));
    InitializeObjectAttributes(&object_attr, &name_string, 0, NULL, NULL);
    status = pNtAlpcCreatePort(&listener, &object_attr, &attr);
    ok(status == STATUS_SUCCESS, "NtAlpcCreatePort returned %#lx.\n", status);
    if (status) goto done;
    if (!connect_alpc_pair(listener, &name_string, &attr, &server1, &client1, (void *)0x1111) ||
        !connect_alpc_pair(listener, &name_string, &attr, &server2, &client2, (void *)0x2222))
        goto done;

    first.header.DataLength = second.header.DataLength = 1;
    first.header.TotalLength = second.header.TotalLength = sizeof(first.header) + 1;
    first.data[0] = 0x11;
    second.data[0] = 0x22;
    status = pNtAlpcSendWaitReceivePort(client1, 0, &first.header, NULL, NULL, NULL, NULL, NULL);
    ok(status == STATUS_SUCCESS, "First send returned %#lx.\n", status);
    status = pNtAlpcSendWaitReceivePort(client2, 0, &second.header, NULL, NULL, NULL, NULL, NULL);
    ok(status == STATUS_SUCCESS, "Second send returned %#lx.\n", status);

    size = sizeof(received);
    status = pNtAlpcSendWaitReceivePort(server2, 0, NULL, NULL, &received.header, &size, NULL, &zero);
    ok(status == STATUS_SUCCESS, "Second endpoint receive returned %#lx.\n", status);
    ok(received.header.DataLength == 1 && received.data[0] == 0x22,
       "Second endpoint received length %u, payload %#x.\n",
       received.header.DataLength, received.data[0]);
    memset(&received, 0, sizeof(received));
    size = sizeof(received);
    status = pNtAlpcSendWaitReceivePort(server1, 0, NULL, NULL, &received.header, &size, NULL, &zero);
    ok(status == STATUS_SUCCESS, "First endpoint receive returned %#lx.\n", status);
    ok(received.header.DataLength == 1 && received.data[0] == 0x11,
       "First endpoint received length %u, payload %#x.\n",
       received.header.DataLength, received.data[0]);

done:
    if (client2) CloseHandle(client2);
    if (client1) CloseHandle(client1);
    if (server2) CloseHandle(server2);
    if (server1) CloseHandle(server1);
    if (listener) CloseHandle(listener);
}

static void test_empty_view_reply(void)
{
    union
    {
        ULONGLONG align;
        BYTE bytes[128];
    } attr_buffer = {0};
    ALPC_MESSAGE_ATTRIBUTES *attributes = (ALPC_MESSAGE_ATTRIBUTES *)attr_buffer.bytes;
    struct alpc_sender_context sender = {0};
    struct alpc_test_frame message = {0};
    ALPC_VIEW_ATTR *view;
    HANDLE listener = NULL, server = NULL, client = NULL, thread = NULL;
    LARGE_INTEGER zero = {0};
    SIZE_T attr_size, size = sizeof(message);
    NTSTATUS status;

    if (!pNtAlpcAcceptConnectPort || !pNtAlpcConnectPort || !pNtAlpcCreatePort ||
        !pNtAlpcSendWaitReceivePort || !pAlpcInitializeMessageAttribute ||
        !pAlpcGetMessageAttribute)
    {
        win_skip("Empty-view reply dependencies are unavailable.\n");
        return;
    }

    if (!create_alpc_pair(&listener, &server, &client, (void *)0x12345678)) goto done;
    sender.port = client;
    sender.timeout.QuadPart = -100000000;
    thread = CreateThread(NULL, 0, alpc_sender_thread, &sender, 0, NULL);
    ok(thread != NULL, "CreateThread failed, error %lu.\n", GetLastError());
    if (!thread) goto done;
    ok(WaitForSingleObject(listener, 3000) == WAIT_OBJECT_0, "Listener was not signaled.\n");
    status = pNtAlpcSendWaitReceivePort(listener, 0, NULL, NULL, &message.header, &size, NULL, &zero);
    ok(status == STATUS_SUCCESS, "Request receive returned %#lx.\n", status);
    if (status) goto done;

    status = pAlpcInitializeMessageAttribute(ALPC_MESSAGE_VIEW_ATTRIBUTE, attributes,
                                              sizeof(attr_buffer), &attr_size);
    ok(status == STATUS_SUCCESS, "AlpcInitializeMessageAttribute returned %#lx.\n", status);
    if (status) goto done;
    attributes->ValidAttributes = ALPC_MESSAGE_VIEW_ATTRIBUTE;
    view = pAlpcGetMessageAttribute(attributes, ALPC_MESSAGE_VIEW_ATTRIBUTE);
    ok(view != NULL, "AlpcGetMessageAttribute returned NULL.\n");
    if (!view) goto done;
    memset(view, 0, sizeof(*view));
    view->Flags = 0x10000;
    message.data[0] = 0x24;
    status = pNtAlpcSendWaitReceivePort(listener, ALPC_MSGFLG_REPLY_MESSAGE,
                                        &message.header, attributes, NULL, NULL, NULL, NULL);
    ok(status == STATUS_SUCCESS, "Empty-view reply returned %#lx.\n", status);
    ok(WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0, "Sender did not receive reply.\n");
    ok(sender.status == STATUS_SUCCESS, "Synchronous sender returned %#lx.\n", sender.status);
    ok(sender.received.header.MessageId == message.header.MessageId,
       "Reply message id %lu, request id %lu.\n",
       sender.received.header.MessageId, message.header.MessageId);
    ok(sender.received.header.DataLength == 1, "Reply data length %u.\n",
       sender.received.header.DataLength);
    ok(sender.received.data[0] == 0x24, "Reply data %#x.\n", sender.received.data[0]);

done:
    if (thread) CloseHandle(thread);
    if (client) CloseHandle(client);
    if (server) CloseHandle(server);
    if (listener) CloseHandle(listener);
}

static BOOL receive_cancel_request(HANDLE listener, struct alpc_test_frame *message,
                                   ALPC_CONTEXT_ATTR *context)
{
    union
    {
        ULONGLONG align;
        BYTE bytes[256];
    } attr_buffer;
    ALPC_MESSAGE_ATTRIBUTES *attributes = (ALPC_MESSAGE_ATTRIBUTES *)attr_buffer.bytes;
    LARGE_INTEGER zero = {0};
    SIZE_T attr_size, size = sizeof(*message);
    ALPC_CONTEXT_ATTR *received_context;
    NTSTATUS status;

    status = pAlpcInitializeMessageAttribute(ALPC_MESSAGE_CONTEXT_ATTRIBUTE, attributes,
                                              sizeof(attr_buffer), &attr_size);
    ok(status == STATUS_SUCCESS, "AlpcInitializeMessageAttribute returned %#lx.\n", status);
    if (status) return FALSE;
    status = pNtAlpcSendWaitReceivePort(listener, 0, NULL, NULL, &message->header, &size,
                                        attributes, &zero);
    ok(status == STATUS_SUCCESS, "Request receive returned %#lx.\n", status);
    if (status) return FALSE;
    ok(attributes->ValidAttributes & ALPC_MESSAGE_CONTEXT_ATTRIBUTE,
       "Context attribute was not returned, attributes %#lx.\n", attributes->ValidAttributes);
    received_context = pAlpcGetMessageAttribute(attributes, ALPC_MESSAGE_CONTEXT_ATTRIBUTE);
    ok(received_context != NULL, "AlpcGetMessageAttribute returned NULL.\n");
    if (!received_context) return FALSE;
    *context = *received_context;
    ok(context->MessageId == message->header.MessageId,
       "Context message id %lu, header id %lu.\n", context->MessageId, message->header.MessageId);
    return TRUE;
}

static void test_NtAlpcCancelMessage(void)
{
    ALPC_CONTEXT_ATTR context = {0}, mismatch;
    struct alpc_sender_context sender = {0};
    struct alpc_test_frame message = {0};
    HANDLE listener = NULL, server = NULL, client = NULL, thread = NULL;
    NTSTATUS status;

    if (!pNtAlpcCancelMessage || !pNtAlpcAcceptConnectPort || !pNtAlpcConnectPort ||
        !pNtAlpcCreatePort || !pNtAlpcSendWaitReceivePort || !pAlpcInitializeMessageAttribute ||
        !pAlpcGetMessageAttribute)
    {
        win_skip("NtAlpcCancelMessage dependencies are unavailable.\n");
        return;
    }

    status = pNtAlpcCancelMessage((HANDLE)0xdead, 0x10, &context);
    ok(status == STATUS_INVALID_PARAMETER, "Invalid flags returned %#lx.\n", status);
    status = pNtAlpcCancelMessage((HANDLE)0xdead, 0, &context);
    ok(status == STATUS_MESSAGE_NOT_FOUND, "Zero message id returned %#lx.\n", status);
    context.MessageId = 1;
    status = pNtAlpcCancelMessage((HANDLE)0xdead, 0, &context);
    ok(status == STATUS_INVALID_HANDLE, "Invalid handle returned %#lx.\n", status);

    if (!create_alpc_pair(&listener, &server, &client, (void *)0x12345678)) goto done;
    sender.port = client;
    sender.timeout.QuadPart = -100000000;
    thread = CreateThread(NULL, 0, alpc_sender_thread, &sender, 0, NULL);
    ok(thread != NULL, "CreateThread failed, error %lu.\n", GetLastError());
    if (!thread) goto done;
    ok(WaitForSingleObject(listener, 3000) == WAIT_OBJECT_0, "Listener was not signaled.\n");
    if (!receive_cancel_request(listener, &message, &context)) goto done;
    ok(context.PortContext == (void *)0x12345678, "Got port context %p.\n", context.PortContext);
    status = pNtAlpcCancelMessage(listener, 1, &context);
    ok(status == STATUS_MESSAGE_RETRIEVED, "Delivered try-cancel returned %#lx.\n", status);
    ok(WaitForSingleObject(thread, 0) == WAIT_TIMEOUT, "Try-cancel canceled the request.\n");
    status = pNtAlpcCancelMessage(listener, 0, &context);
    ok(status == STATUS_MESSAGE_RETRIEVED, "Delivered cancellation returned %#lx.\n", status);
    ok(WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0, "Sender did not receive cancellation.\n");
    ok(sender.status == STATUS_SUCCESS, "Synchronous sender returned %#lx.\n", sender.status);
    ok((sender.received.header.Type & 0xff) == ALPC_MESSAGE_TYPE_CANCELED,
       "Received message type %#x.\n", sender.received.header.Type);
    ok(sender.received.header.DataLength == 0, "Cancellation data length %u.\n",
       sender.received.header.DataLength);
    ok(sender.received.header.MessageId == message.header.MessageId,
       "Cancellation message id %lu, request id %lu.\n",
       sender.received.header.MessageId, message.header.MessageId);
    CloseHandle(thread);
    thread = NULL;

    memset(&sender, 0, sizeof(sender));
    memset(&message, 0, sizeof(message));
    sender.port = client;
    sender.timeout.QuadPart = -100000000;
    thread = CreateThread(NULL, 0, alpc_sender_thread, &sender, 0, NULL);
    ok(thread != NULL, "CreateThread failed, error %lu.\n", GetLastError());
    if (!thread) goto done;
    ok(WaitForSingleObject(listener, 3000) == WAIT_OBJECT_0, "Listener was not signaled.\n");
    if (!receive_cancel_request(listener, &message, &context)) goto done;
    mismatch = context;
    mismatch.MessageContext = (void *)((ULONG_PTR)mismatch.MessageContext ^ 1);
    status = pNtAlpcCancelMessage(server, 8, &mismatch);
    ok(status == STATUS_CONTEXT_MISMATCH, "Context mismatch returned %#lx.\n", status);
    ok(WaitForSingleObject(thread, 0) == WAIT_TIMEOUT, "Context mismatch canceled the request.\n");
    status = pNtAlpcCancelMessage(server, 0, &context);
    ok(status == STATUS_MESSAGE_RETRIEVED, "Cancellation after mismatch returned %#lx.\n", status);
    ok(WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0, "Sender did not receive cancellation.\n");
    ok(sender.status == STATUS_SUCCESS, "Synchronous sender returned %#lx.\n", sender.status);
    ok((sender.received.header.Type & 0xff) == ALPC_MESSAGE_TYPE_CANCELED,
       "Received message type %#x.\n", sender.received.header.Type);

done:
    if (thread) CloseHandle(thread);
    if (client) CloseHandle(client);
    if (server) CloseHandle(server);
    if (listener) CloseHandle(listener);
}


struct async_connect_context
{
    UNICODE_STRING name;
    ALPC_PORT_ATTRIBUTES attr;
    struct alpc_test_frame message;
    SIZE_T capacity;
    HANDLE port, completed, release;
    NTSTATUS status;
    ULONG flags;
    BOOL extended, no_message, detached;
};

static DWORD WINAPI async_connect_thread(void *arg)
{
    struct async_connect_context *context = arg;
    OBJECT_ATTRIBUTES object_attr;
    LARGE_INTEGER timeout;
    ALPC_PORT_MESSAGE *message = context->no_message ? NULL : &context->message.header;
    SIZE_T *capacity = context->no_message ? NULL : &context->capacity;

    timeout.QuadPart = -50000000;
    if (context->extended)
    {
        InitializeObjectAttributes(&object_attr, &context->name, 0, NULL, NULL);
        context->status = pNtAlpcConnectPortEx(&context->port, &object_attr, NULL, &context->attr,
                                                context->flags, NULL, message, capacity, NULL, NULL, &timeout);
    }
    else
        context->status = pNtAlpcConnectPort(&context->port, &context->name, NULL, &context->attr,
                                              context->flags, NULL, message, capacity, NULL, NULL, &timeout);
    SetEvent(context->completed);
    if (!context->detached) WaitForSingleObject(context->release, 10000);
    return 0;
}

static void test_async_connection_completion(void)
{
    struct async_connect_context context;
    struct alpc_test_frame incoming, received, original;
    OBJECT_ATTRIBUTES object_attr;
    UNICODE_STRING name;
    HANDLE listener, server, thread;
    LARGE_INTEGER zero = {0};
    WCHAR buffer[96];
    NTSTATUS status;
    SIZE_T size;
    DWORD tid, wait, before;
    unsigned int mode;

    if (!pNtAlpcConnectPort || !pNtAlpcConnectPortEx || !pNtAlpcAcceptConnectPort ||
        !pNtAlpcCreatePort || !pNtAlpcSendWaitReceivePort)
    {
        win_skip("Connection completion dependencies are unavailable.\n");
        return;
    }

    for (mode = 0; mode < 16; ++mode)
    {
        winetest_push_context("connection completion %u", mode);
        memset(&context, 0, sizeof(context));
        memset(&incoming, 0, sizeof(incoming));
        listener = server = thread = NULL;
        context.flags = mode < 8 && (mode & 1) ? ALPC_SYNC_CONNECTION : 0;
        context.extended = mode < 8 ? !!(mode & 2) : !!(mode & 1);
        context.no_message = mode == 8 || mode == 9;
        context.detached = mode >= 10;
        context.message.header.DataLength = 16;
        context.message.header.TotalLength = sizeof(context.message.header) + 16;
        memset(context.message.data, 0x42, 16);
        original = context.message;
        context.capacity = sizeof(context.message);
        context.completed = CreateEventW(NULL, TRUE, FALSE, NULL);
        context.release = CreateEventW(NULL, TRUE, FALSE, NULL);
        ok(context.completed && context.release, "CreateEvent failed, error %lu.\n", GetLastError());
        if (!context.completed || !context.release) goto cleanup;
        swprintf(buffer, ARRAY_SIZE(buffer), L"\\BaseNamedObjects\\winetest_async_connect_%lu_%u",
                 GetCurrentProcessId(), mode);
        RtlInitUnicodeString(&name, buffer);
        context.name = name;
        init_port_attr(&context.attr, 0x70000, sizeof(incoming));
        InitializeObjectAttributes(&object_attr, &name, 0, NULL, NULL);
        status = pNtAlpcCreatePort(&listener, &object_attr, &context.attr);
        ok(!status, "Create returned %#lx.\n", status);
        if (status) goto cleanup;
        thread = CreateThread(NULL, 0, async_connect_thread, &context, 0, &tid);
        ok(!!thread, "CreateThread failed, error %lu.\n", GetLastError());
        if (!thread) goto cleanup;
        wait = WaitForSingleObject(listener, 3000);
        ok(wait == WAIT_OBJECT_0, "Listener wait returned %#lx.\n", wait);
        if (wait != WAIT_OBJECT_0) goto cleanup;
        size = sizeof(incoming);
        status = pNtAlpcSendWaitReceivePort(listener, 0, NULL, NULL, &incoming.header, &size, NULL, &zero);
        ok(!status, "Request receive returned %#lx.\n", status);
        if (status) goto cleanup;
        before = WaitForSingleObject(context.completed, context.flags ? 0 : 1000);
        ok(before == (context.flags ? WAIT_TIMEOUT : WAIT_OBJECT_0),
           "Before accept connector wait returned %#lx.\n", before);
        if (context.detached)
            ok(WaitForSingleObject(thread, 1000) == WAIT_OBJECT_0, "Returned asynchronous connector did not exit.\n");
        incoming.header.DataLength = 16;
        incoming.header.TotalLength = sizeof(incoming.header) + 16;
        memset(incoming.data, 0x63, 16);
        if (mode == 12 || mode == 13)
        {
            CloseHandle(context.port);
            context.port = NULL;
            status = pNtAlpcAcceptConnectPort(&server, listener, 0, NULL, &context.attr, NULL,
                                             &incoming.header, NULL, TRUE);
            trace("async-connect mode=%u closed-client-accept=%08lx\n", mode, status);
            ok(status == STATUS_REQUEST_CANCELED, "Closed-client accept returned %#lx.\n", status);
            status = pNtAlpcAcceptConnectPort(&server, listener, 0, NULL, &context.attr, NULL,
                                             &incoming.header, NULL, TRUE);
            trace("async-connect mode=%u closed-client-again=%08lx\n", mode, status);
            ok(status == STATUS_INVALID_MESSAGE, "Repeated closed-client accept returned %#lx.\n", status);
            goto cleanup;
        }
        if (mode == 14 || mode == 15)
        {
            CloseHandle(listener);
            listener = NULL;
            wait = WaitForSingleObject(context.port, 500);
            trace("async-connect mode=%u closed-listener-wait=%lx\n", mode, wait);
            ok(wait == WAIT_OBJECT_0, "Closed-listener wait returned %#lx.\n", wait);
            memset(&received, 0xcc, sizeof(received));
            original = received;
            size = sizeof(received);
            status = pNtAlpcSendWaitReceivePort(context.port, 0, NULL, NULL, &received.header, &size, NULL, &zero);
            trace("async-connect mode=%u closed-listener-receive=%08lx size=%Iu type=%x data=%u id-match=%u id-zero=%u pid-zero=%u pid-self=%u tid-server=%u tid-client=%u tid-zero=%u byte=%x\n",
                  mode, status, size, received.header.Type, received.header.DataLength,
                  received.header.MessageId == incoming.header.MessageId, !received.header.MessageId,
                  !received.header.ClientId.UniqueProcess,
                  received.header.ClientId.UniqueProcess == ULongToHandle(GetCurrentProcessId()),
                  received.header.ClientId.UniqueThread == ULongToHandle(GetCurrentThreadId()),
                  received.header.ClientId.UniqueThread == ULongToHandle(tid),
                  !received.header.ClientId.UniqueThread, received.data[0]);
            ok(status == STATUS_SUCCESS, "Closed-listener receive returned %#lx.\n", status);
            ok(size == sizeof(received), "Closed-listener capacity changed to %Iu.\n", size);
            ok((received.header.Type & 0xff) == ALPC_MESSAGE_TYPE_CANCELED,
               "Closed-listener completion type %#x.\n", received.header.Type);
            ok(!received.header.DataLength, "Cancellation length %u.\n", received.header.DataLength);
            ok(received.header.MessageId == incoming.header.MessageId, "Cancellation id differs.\n");
            ok(received.header.ClientId.UniqueProcess == ULongToHandle(GetCurrentProcessId()),
               "Cancellation process %p.\n", received.header.ClientId.UniqueProcess);
            ok(received.header.ClientId.UniqueThread == ULongToHandle(tid),
               "Cancellation thread %p.\n", received.header.ClientId.UniqueThread);
            ok(!memcmp(original.data, received.data, sizeof(received.data)), "Empty cancellation changed data.\n");
            size = sizeof(received);
            status = pNtAlpcSendWaitReceivePort(context.port, 0, NULL, NULL, &received.header, &size, NULL, &zero);
            trace("async-connect mode=%u closed-listener-again=%08lx size=%Iu\n", mode, status, size);
            ok(status == STATUS_UNSUCCESSFUL, "Drained cancellation receive returned %#lx.\n", status);
            goto cleanup;
        }
        status = pNtAlpcAcceptConnectPort(&server, listener, 0, NULL, &context.attr, (void *)0x51,
                                         &incoming.header, NULL, mode >= 8 || !(mode & 4));
        ok(!status, "Accept returned %#lx.\n", status);
        if (status) goto cleanup;
        wait = WaitForSingleObject(context.completed, 3000);
        ok(wait == WAIT_OBJECT_0, "Connector wait returned %#lx.\n", wait);
        if (wait != WAIT_OBJECT_0) goto cleanup;
        trace("async-connect mode=%u before=%lx connect=%08lx handle=%u capacity=%Iu unchanged=%u type=%x\n",
              mode, before, context.status, !!context.port, context.capacity,
              !memcmp(&original, &context.message, sizeof(original)), context.message.header.Type);
        ok(context.status == (context.flags && (mode & 4) ? STATUS_PORT_CONNECTION_REFUSED : STATUS_SUCCESS),
           "Connect returned %#lx.\n", context.status);
        if (!context.flags || (mode & 4))
        {
            ok(context.capacity == sizeof(context.message), "Capacity changed to %Iu.\n", context.capacity);
            ok(!memcmp(&original, &context.message, sizeof(original)), "Connection buffer changed.\n");
        }
        else
        {
            ok(context.capacity == sizeof(context.message.header) + 16, "Reply capacity %Iu.\n", context.capacity);
            ok((context.message.header.Type & 0xff) == 11, "Reply type %#x.\n", context.message.header.Type);
            ok(context.message.header.ClientId.UniqueThread == ULongToHandle(GetCurrentThreadId()),
               "Reply sender thread %p.\n", context.message.header.ClientId.UniqueThread);
        }
        if (context.status) goto cleanup;
        wait = WaitForSingleObject(context.port, 500);
        trace("async-connect mode=%u queue-wait=%lx\n", mode, wait);
        ok(wait == (context.flags ? WAIT_TIMEOUT : WAIT_OBJECT_0), "Completion wait returned %#lx.\n", wait);
        if (wait != WAIT_OBJECT_0) goto cleanup;
        memset(&received, 0xcc, sizeof(received));
        size = sizeof(received.header) + 4;
        status = pNtAlpcSendWaitReceivePort(context.port, 0, NULL, NULL, &received.header, &size, NULL, &zero);
        trace("async-connect mode=%u short=%08lx size=%Iu\n", mode, status, size);
        ok(status == (mode < 8 && (mode & 4) ? STATUS_PORT_CONNECTION_REFUSED : STATUS_BUFFER_TOO_SMALL),
           "Short receive returned %#lx.\n", status);
        ok(size == (mode < 8 && (mode & 4) ? sizeof(received.header) + 4 : sizeof(received.header) + 16),
           "Short receive size %Iu.\n", size);
        size = sizeof(received);
        status = pNtAlpcSendWaitReceivePort(context.port, 0, NULL, NULL, &received.header, &size, NULL, &zero);
        trace("async-connect mode=%u receive=%08lx type=%x data=%u size=%Iu id-match=%u pid-self=%u tid-server=%u tid-client=%u tid-zero=%u byte=%x\n",
              mode, status, received.header.Type, received.header.DataLength, size,
              received.header.MessageId == incoming.header.MessageId,
              received.header.ClientId.UniqueProcess == ULongToHandle(GetCurrentProcessId()),
              received.header.ClientId.UniqueThread == ULongToHandle(GetCurrentThreadId()),
              received.header.ClientId.UniqueThread == ULongToHandle(tid),
              !received.header.ClientId.UniqueThread, received.data[0]);
        ok(status == (mode < 8 && (mode & 4) ? STATUS_PORT_CONNECTION_REFUSED : STATUS_SUCCESS),
           "Completion receive returned %#lx.\n", status);
        ok(size == sizeof(received), "Ordinary receive changed capacity to %Iu.\n", size);
        if (!status)
        {
            ok((received.header.Type & 0xff) == 11, "Completion type %#x.\n", received.header.Type);
            ok(received.header.DataLength == 16, "Completion length %u.\n", received.header.DataLength);
            ok(received.header.MessageId == incoming.header.MessageId, "Completion request id differs.\n");
            ok(received.header.ClientId.UniqueProcess == ULongToHandle(GetCurrentProcessId()),
               "Completion process %p.\n", received.header.ClientId.UniqueProcess);
            ok(received.header.ClientId.UniqueThread == ULongToHandle(GetCurrentThreadId()),
               "Completion thread %p.\n", received.header.ClientId.UniqueThread);
            ok(received.data[0] == 0x63 && received.data[15] == 0x63, "Completion data differs.\n");
        }
        wait = WaitForSingleObject(context.port, 0);
        ok(wait == WAIT_TIMEOUT, "Drained completion wait returned %#lx.\n", wait);
        trace("async-connect mode=%u drained-wait=%lx\n", mode, wait);

cleanup:
        if (listener) CloseHandle(listener);
        if (server) CloseHandle(server);
        SetEvent(context.release);
        if (thread)
        {
            ok(WaitForSingleObject(thread, 7000) == WAIT_OBJECT_0, "Connector did not exit.\n");
            CloseHandle(thread);
        }
        if (context.port) CloseHandle(context.port);
        if (context.completed) CloseHandle(context.completed);
        if (context.release) CloseHandle(context.release);
        winetest_pop_context();
    }
}

START_TEST(alpc)
{
    char **argv;
    int argc = winetest_get_mainargs(&argv);

    init_functions();
    if (argc > 2 && !strcmp(argv[2], "async-connect"))
    {
        test_async_connection_completion();
        return;
    }

    if (argc > 2 && !strcmp(argv[2], "received-token"))
    {
        test_received_token_acceptance();
        return;
    }

    test_AlpcGetHeaderSize();
    test_AlpcGetMessageAttribute();
    test_AlpcInitializeMessageAttribute();
    test_NtAlpcCreatePort();
    test_NtAlpcQueryInformation();
    test_reply_receive_validation();
    test_received_token_acceptance();
    test_accepted_port_routing();
    test_empty_view_reply();
    test_NtAlpcCancelMessage();
    test_async_connection_completion();
    test_power_port();
}
