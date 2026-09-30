/*
 * PDC current activation and notification registration
 *
 * Copyright 2026 LinuxNT project
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "ntstatus.h"
#include "wine/test.h"

static typeof(NtAlpcConnectPort) *pNtAlpcConnectPort;
static typeof(NtAlpcQueryInformation) *pNtAlpcQueryInformation;
static typeof(NtAlpcDisconnectPort) *pNtAlpcDisconnectPort;
static typeof(NtAlpcSendWaitReceivePort) *pNtAlpcSendWaitReceivePort;

struct pdc_message
{
    ALPC_PORT_MESSAGE header;
    ULONG message_type, revision;
    ULONGLONG reserved;
    ULONG client_id, client_type;
    ULONGLONG triage_context;
    WCHAR module[64];
    BYTE client_data[600];
};

struct pdc_descriptor
{
    ULONG version, reserved;
    void *callback, *control_callback, *reserved2;
};

static void init_message(struct pdc_message *message, ULONG id, ULONG type)
{
    memset(message, 0, sizeof(*message));
    message->header.DataLength = sizeof(*message) - sizeof(message->header);
    message->header.TotalLength = sizeof(*message);
    message->revision = 6;
    message->client_id = id;
    message->client_type = type;
    /* This is an opaque diagnostic cookie, not an address for the receiver. */
    message->triage_context = ~(ULONGLONG)0;
}

static NTSTATUS connect_message(struct pdc_message *message, SIZE_T size, HANDLE *port)
{
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\PdcPort");
    ALPC_PORT_ATTRIBUTES attr = {0};
    LARGE_INTEGER timeout;
    attr.Flags = 0x20000;
    attr.MaxMessageLength = sizeof(*message);
    attr.SecurityQos.Length = sizeof(attr.SecurityQos);
    attr.SecurityQos.ImpersonationLevel = SecurityIdentification;
    attr.SecurityQos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    timeout.QuadPart = -50000000;
    *port = NULL;
    return pNtAlpcConnectPort(port, &name, NULL, &attr, 0xa0000, NULL,
                             &message->header, &size, NULL, NULL, &timeout);
}

struct priority_result
{
    HANDLE event;
    NTSTATUS status;
    LONG priority;
};

static void WINAPI priority_callback(TP_CALLBACK_INSTANCE *instance, void *context, TP_WORK *work)
{
    struct priority_result *result = context;
    THREAD_BASIC_INFORMATION info;
    result->status = NtQueryInformationThread(GetCurrentThread(), ThreadBasicInformation, &info, sizeof(info), NULL);
    result->priority = info.Priority;
    SetEvent(result->event);
}

static void test_pool_priority(void)
{
    NTSTATUS (WINAPI *set_priority)(TP_POOL *, LONG);
    static const LONG inputs[] = {15, 0, -15, 100, -100, 2, -2, -14};
    struct priority_result result;
    PROCESS_BASIC_INFORMATION original;
    TP_CALLBACK_ENVIRON environment;
    TP_POOL *pool;
    TP_WORK *work;
    HMODULE module = GetModuleHandleA("ntdll.dll");
    NTSTATUS status;
    LONG expected;
    unsigned int i, pass;

    set_priority = (void *)GetProcAddress(module, "TpSetPoolThreadBasePriority");
    ok(set_priority != NULL, "pool base priority export absent\n");
    if (!set_priority) return;
    status = set_priority(NULL, 15);
    ok(status == STATUS_INVALID_PARAMETER, "null pool: %#lx\n", status);
    status = NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &original, sizeof(original), NULL);
    ok(!status, "query process base priority: %#lx\n", status);
    if (status) return;
    result.event = CreateEventW(NULL, FALSE, FALSE, NULL);
    for (pass = 0; pass < 2; ++pass)
    {
        status = TpAllocPool(&pool, NULL);
        ok(!status, "allocate priority pool: %#lx\n", status);
        if (status) break;
        TpSetPoolMaxThreads(pool, 1);
        if (!pass)
        {
            status = set_priority(pool, 15);
            ok(!status, "future worker priority: %#lx\n", status);
        }
        memset(&environment, 0, sizeof(environment));
        environment.Version = 1;
        environment.Pool = pool;
        status = TpAllocWork(&work, priority_callback, &result, &environment);
        ok(!status, "allocate priority work: %#lx\n", status);
        if (status) { TpReleasePool(pool); break; }
        TpPostWork(work);
        ok(WaitForSingleObject(result.event, 5000) == WAIT_OBJECT_0, "initial priority callback timed out\n");
        TpWaitForWork(work, FALSE);
        ok(!result.status && result.priority == (pass ? original.BasePriority : 15),
           "initial worker priority %ld status %#lx\n", result.priority, result.status);
        for (i = 0; i < ARRAY_SIZE(inputs); ++i)
        {
            status = set_priority(pool, inputs[i]);
            if (inputs[i] == -14)
            {
                ok(status == STATUS_NOT_SUPPORTED, "unsupported intermediate priority: %#lx\n", status);
                expected = original.BasePriority - 2;
            }
            else
            {
                ok(!status, "set priority %ld: %#lx\n", inputs[i], status);
                expected = inputs[i] >= 15 ? 15 : inputs[i] <= -15 ? 1 : original.BasePriority + inputs[i];
            }
            TpPostWork(work);
            ok(WaitForSingleObject(result.event, 5000) == WAIT_OBJECT_0, "updated priority callback timed out\n");
            TpWaitForWork(work, FALSE);
            ok(!result.status && result.priority == expected,
               "input %ld: actual priority %ld expected %ld status %#lx\n",
               inputs[i], result.priority, expected, result.status);
        }
        TpReleaseWork(work);
        TpReleasePool(pool);
    }
    CloseHandle(result.event);
}

static void test_raw_registration(void)
{
    static const struct { ULONG id, type; NTSTATUS status; } cases[] =
    {
        {1, 0, STATUS_SUCCESS}, {100, 0, STATUS_SUCCESS},
        {1, 7, STATUS_SUCCESS}, {100, 7, STATUS_SUCCESS},
        {0, 7, STATUS_ACCESS_DENIED}, {125, 7, STATUS_ACCESS_DENIED},
        {100, 9, STATUS_ACCESS_DENIED}, {100, 3, STATUS_ACCESS_DENIED},
        {100, 2, STATUS_NOT_SUPPORTED}, {18, 7, STATUS_NOT_SUPPORTED}
    };
    struct pdc_message message;
    ALPC_BASIC_INFORMATION info;
    HANDLE port, duplicate, second;
    NTSTATUS status;
    unsigned int i;
    ULONG size;
    SIZE_T receive_size;

    C_ASSERT(sizeof(struct pdc_message) == 800);
    C_ASSERT(offsetof(struct pdc_message, client_id) == 0x38);
    C_ASSERT(offsetof(struct pdc_message, client_data) == 0xc8);
    for (i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        init_message(&message, cases[i].id, cases[i].type);
        status = connect_message(&message, sizeof(message), &port);
        ok(status == cases[i].status, "id %lu type %lu: status %#lx expected %#lx\n",
           cases[i].id, cases[i].type, status, cases[i].status);
        if (!status)
        {
            ok(port != NULL, "accepted registration has no port\n");
            memset(&info, 0, sizeof(info));
            status = pNtAlpcQueryInformation(port, 0, &info, sizeof(info), &size);
            ok(!status, "query accepted port: %#lx\n", status);
            ok(info.SequenceNo == 1, "connection reply sequence %lu\n", info.SequenceNo);
            status = pNtAlpcDisconnectPort(port, 1);
            ok(!status, "disconnect: %#lx\n", status);
            status = pNtAlpcDisconnectPort(port, 1);
            ok(status == STATUS_PORT_DISCONNECTED, "repeat disconnect: %#lx\n", status);
            CloseHandle(port);
        }
        else ok(!port, "failed registration published port %p\n", port);
    }
    init_message(&message, 100, 7);
    message.revision = 3;
    status = connect_message(&message, sizeof(message), &port);
    ok(status == STATUS_INVALID_PARAMETER, "invalid revision: %#lx\n", status);
    ok(!port, "invalid revision published a port\n");
    message.revision = 5;
    status = connect_message(&message, sizeof(message), &port);
    ok(status == STATUS_NOT_SUPPORTED, "legacy revision: %#lx\n", status);
    ok(!port, "legacy revision published a port\n");
    init_message(&message, 100, 7);
    --message.header.DataLength;
    --message.header.TotalLength;
    status = connect_message(&message, sizeof(message) - 1, &port);
    ok(status == STATUS_INVALID_PARAMETER, "short message: %#lx\n", status);
    ok(!port, "short message published a port\n");
    init_message(&message, 100, 7);
    status = connect_message(&message, sizeof(message) - 1, &port);
    ok(status == STATUS_BUFFER_TOO_SMALL, "short reply capacity: %#lx\n", status);
    ok(!port, "partial connection failure published a port\n");
    init_message(&message, 100, 7);
    message.message_type = 10;
    status = connect_message(&message, sizeof(message), &port);
    ok(status == STATUS_ACCESS_DENIED, "non-registration: %#lx\n", status);
    ok(!port, "non-registration published a port\n");

    init_message(&message, 100, 7);
    status = connect_message(&message, sizeof(message), &port);
    ok(!status, "first independent client: %#lx\n", status);
    if (status) return;
    init_message(&message, 100, 7);
    status = connect_message(&message, sizeof(message), &second);
    ok(!status, "second independent client: %#lx\n", status);
    if (!status) CloseHandle(second);
    if (!DuplicateHandle(GetCurrentProcess(), port, GetCurrentProcess(), &duplicate,
                         0, FALSE, DUPLICATE_SAME_ACCESS))
    {
        ok(0, "duplicate failed %lu\n", GetLastError());
        CloseHandle(port);
        return;
    }
    CloseHandle(port);
    memset(&info, 0, sizeof(info));
    status = pNtAlpcQueryInformation(duplicate, 0, &info, sizeof(info), &size);
    ok(!status && info.SequenceNo == 1, "duplicate query: %#lx sequence %lu\n", status, info.SequenceNo);
    init_message(&message, 100, 7);
    message.message_type = 10;
    receive_size = sizeof(message);
    status = pNtAlpcSendWaitReceivePort(duplicate, 0x20000, &message.header, NULL,
                                      &message.header, &receive_size, NULL, NULL);
    ok(status == STATUS_NOT_SUPPORTED, "unowned activation: %#lx\n", status);
    message.message_type = 13;
    status = pNtAlpcSendWaitReceivePort(duplicate, 0, &message.header, NULL, NULL, NULL, NULL, NULL);
    ok(status == STATUS_NOT_SUPPORTED, "unowned asynchronous deactivation: %#lx\n", status);
    status = pNtAlpcDisconnectPort(duplicate, 1);
    ok(!status, "duplicate disconnect: %#lx\n", status);
    CloseHandle(duplicate);
    status = pNtAlpcQueryInformation(duplicate, 0, &info, sizeof(info), &size);
    ok(status == STATUS_INVALID_HANDLE, "closed duplicate: %#lx\n", status);
}


static HANDLE create_labeled_token(DWORD integrity, BOOL system_user)
{
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY world_authority = SECURITY_WORLD_SID_AUTHORITY;
    TOKEN_USER *user;
    TOKEN_GROUPS groups;
    TOKEN_PRIVILEGES privileges = {0};
    TOKEN_OWNER owner;
    TOKEN_PRIMARY_GROUP primary_group;
    TOKEN_DEFAULT_DACL dacl = {NULL};
    TOKEN_SOURCE source = {{'P','D','C','T','e','s','t',0}, {0}};
    TOKEN_STATISTICS statistics;
    BYTE user_buffer[128], label_buffer[128], acl_buffer[128];
    TOKEN_MANDATORY_LABEL *actual = (TOKEN_MANDATORY_LABEL *)label_buffer;
    SECURITY_DESCRIPTOR sd;
    OBJECT_ATTRIBUTES attr;
    LARGE_INTEGER expiration;
    PSID label, world, system_sid = NULL;
    HANDLE original, token = NULL;
    DWORD size;
    NTSTATUS status;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &original)) return NULL;
    if (!GetTokenInformation(original, TokenUser, user_buffer, sizeof(user_buffer), &size) ||
        !GetTokenInformation(original, TokenStatistics, &statistics, sizeof(statistics), &size))
    {
        ok(0, "query token construction inputs: %lu\n", GetLastError());
        CloseHandle(original);
        return NULL;
    }
    CloseHandle(original);
    user = (TOKEN_USER *)user_buffer;
    if (system_user)
    {
        SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
        AllocateAndInitializeSid(&nt_authority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &system_sid);
        user->User.Sid = system_sid;
    }
    AllocateAndInitializeSid(&authority, 1, integrity, 0, 0, 0, 0, 0, 0, 0, &label);
    AllocateAndInitializeSid(&world_authority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &world);
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    InitializeAcl((ACL *)acl_buffer, sizeof(acl_buffer), ACL_REVISION);
    AddMandatoryAce((ACL *)acl_buffer, ACL_REVISION, 0, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, label);
    SetSecurityDescriptorSacl(&sd, TRUE, (ACL *)acl_buffer, FALSE);
    InitializeObjectAttributes(&attr, NULL, 0, NULL, &sd);
    groups.GroupCount = 1;
    groups.Groups[0].Sid = world;
    groups.Groups[0].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
    owner.Owner = user->User.Sid;
    primary_group.PrimaryGroup = world;
    expiration.QuadPart = 0x7fffffffffffffff;
    /* Construct test tokens with an actual SACL at creation. Both setters
     * ignore integrity labels in this runtime. NtCreateToken privilege
     * enforcement is a separate known limit, not a PDC authorization rule. */
    status = NtCreateToken(&token, TOKEN_ALL_ACCESS, &attr, TokenPrimary,
                          &statistics.AuthenticationId, &expiration, user, &groups,
                          &privileges, &owner, &primary_group, &dacl, &source);
    ok(!status && token, "create labeled token %#lx: %#lx\n", integrity, status);
    if (!status)
    {
        status = NtQueryInformationToken(token, TokenIntegrityLevel, label_buffer, sizeof(label_buffer), &size);
        ok(!status && EqualSid(actual->Label.Sid, label), "actual token integrity %#lx: %#lx\n", integrity, status);
        if (status || !EqualSid(actual->Label.Sid, label))
        {
            CloseHandle(token);
            token = NULL;
        }
    }
    if (token && system_user)
    {
        status = NtQueryInformationToken(token, TokenUser, label_buffer, sizeof(label_buffer), &size);
        ok(!status && EqualSid(((TOKEN_USER *)label_buffer)->User.Sid, system_sid),
           "actual System identity: %#lx\n", status);
        if (status || !EqualSid(((TOKEN_USER *)label_buffer)->User.Sid, system_sid))
        {
            CloseHandle(token);
            token = NULL;
        }
    }
    if (system_sid) FreeSid(system_sid);
    FreeSid(label);
    FreeSid(world);
    return token;
}

static void test_effective_token_admission(void)
{
    SID_IDENTIFIER_AUTHORITY world_authority = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    SID_AND_ATTRIBUTES restricting;
    HANDLE primary, low, impersonation, restricted, port;
    struct pdc_message message;
    NTSTATUS status;

    ok(OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &primary), "open primary: %lu\n", GetLastError());
    low = create_labeled_token(SECURITY_MANDATORY_LOW_RID, FALSE);
    if (!low) { CloseHandle(primary); return; }
    if (!DuplicateTokenEx(low, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
                          TokenImpersonation, &impersonation))
    {
        ok(0, "duplicate impersonation: %lu\n", GetLastError());
        CloseHandle(primary);
        CloseHandle(low);
        return;
    }
    CloseHandle(low);
    ok(SetThreadToken(NULL, impersonation), "set low impersonation: %lu\n", GetLastError());
    init_message(&message, 100, 7);
    status = connect_message(&message, sizeof(message), &port);
    ok(!status, "primary admission must survive low impersonation: %#lx\n", status);
    if (!status) CloseHandle(port);
    ok(RevertToSelf(), "revert: %lu\n", GetLastError());

    /* Port DACL must check the restricting SID set as well as the normal groups. */
    AllocateAndInitializeSid(&nt_authority, 1, 987654, 0, 0, 0, 0, 0, 0, 0, &restricting.Sid);
    restricting.Attributes = 0;
    ok(CreateRestrictedToken(impersonation, 0, 0, NULL, 0, NULL, 1, &restricting, &restricted),
       "create restricted token: %lu\n", GetLastError());
    ok(SetThreadToken(NULL, restricted), "restricted impersonation: %lu\n", GetLastError());
    init_message(&message, 100, 7);
    status = connect_message(&message, sizeof(message), &port);
    ok(status == STATUS_ACCESS_DENIED, "restricted unknown SID: %#lx\n", status);
    ok(!port, "denied restricting SID published port\n");
    RevertToSelf();
    CloseHandle(restricted);
    FreeSid(restricting.Sid);
    AllocateAndInitializeSid(&world_authority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &restricting.Sid);
    ok(CreateRestrictedToken(impersonation, 0, 0, NULL, 0, NULL, 1, &restricting, &restricted),
       "create World restricted token: %lu\n", GetLastError());
    ok(SetThreadToken(NULL, restricted), "World restricted impersonation: %lu\n", GetLastError());
    init_message(&message, 100, 0);
    status = connect_message(&message, sizeof(message), &port);
    ok(!status, "restricted World SID: %#lx\n", status);
    if (!status) CloseHandle(port);
    RevertToSelf();
    CloseHandle(restricted);
    FreeSid(restricting.Sid);
    CloseHandle(impersonation);
    CloseHandle(primary);
}


static HANDLE disconnect_barrier;
static DWORD WINAPI disconnect_thread(void *arg)
{
    WaitForSingleObject(disconnect_barrier, INFINITE);
    return pNtAlpcDisconnectPort(arg, 1);
}

static void test_concurrent_disconnect(void)
{
    struct pdc_message message;
    HANDLE port, duplicate, threads[2];
    DWORD results[2];
    NTSTATUS status;
    init_message(&message, 100, 7);
    status = connect_message(&message, sizeof(message), &port);
    ok(!status, "concurrent registration: %#lx\n", status);
    if (status) return;
    if (!DuplicateHandle(GetCurrentProcess(), port, GetCurrentProcess(), &duplicate,
                         0, FALSE, DUPLICATE_SAME_ACCESS))
    {
        ok(0, "concurrent duplicate: %lu\n", GetLastError());
        CloseHandle(port);
        return;
    }
    disconnect_barrier = CreateEventW(NULL, TRUE, FALSE, NULL);
    threads[0] = CreateThread(NULL, 0, disconnect_thread, port, 0, NULL);
    threads[1] = CreateThread(NULL, 0, disconnect_thread, duplicate, 0, NULL);
    SetEvent(disconnect_barrier);
    ok(WaitForMultipleObjects(2, threads, TRUE, 5000) == WAIT_OBJECT_0, "concurrent disconnect did not finish\n");
    GetExitCodeThread(threads[0], &results[0]);
    GetExitCodeThread(threads[1], &results[1]);
    ok((results[0] == STATUS_SUCCESS && results[1] == STATUS_PORT_DISCONNECTED) ||
       (results[1] == STATUS_SUCCESS && results[0] == STATUS_PORT_DISCONNECTED),
       "concurrent disconnect results %#lx / %#lx\n", results[0], results[1]);
    CloseHandle(threads[0]);
    CloseHandle(threads[1]);
    CloseHandle(disconnect_barrier);
    CloseHandle(port);
    CloseHandle(duplicate);
}

static void run_child(BOOL low_integrity, BOOL medium_integrity)
{
    struct pdc_message message;
    TOKEN_MANDATORY_LABEL label;
    HANDLE token, ports[3];
    BYTE buffer[128];
    DWORD size;
    NTSTATUS status;
    unsigned int i;
    if (low_integrity || medium_integrity)
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) ExitProcess(2);
        if (!GetTokenInformation(token, TokenIntegrityLevel, buffer, sizeof(buffer), &size)) ExitProcess(3);
        label = *(TOKEN_MANDATORY_LABEL *)buffer;
        if (*GetSidSubAuthority(label.Label.Sid, 0) !=
            (low_integrity ? SECURITY_MANDATORY_LOW_RID : SECURITY_MANDATORY_MEDIUM_RID)) ExitProcess(4);
        CloseHandle(token);
        init_message(&message, 100, 7);
        status = connect_message(&message, sizeof(message), &ports[0]);
        if (medium_integrity)
        {
            if (status || !ports[0]) ExitProcess(7);
            CloseHandle(ports[0]);
            ExitProcess(0);
        }
        ExitProcess(status == STATUS_ACCESS_DENIED && !ports[0] ? 0 : 5);
    }
    for (i = 0; i < ARRAY_SIZE(ports); ++i)
    {
        init_message(&message, i ? 100 : 1, i == 2 ? 7 : 0);
        status = connect_message(&message, sizeof(message), &ports[i]);
        if (status) ExitProcess(6);
    }
    /* Exit without disconnect/close: the process and ALPC owners must reclaim all three. */
    ExitProcess(0);
}

static void test_process_admission_and_death(void)
{
    HANDLE low_token, medium_token;
    PROCESS_INFORMATION process;
    STARTUPINFOW startup = {sizeof(startup)};
    WCHAR path[MAX_PATH], command[2 * MAX_PATH];
    DWORD exit_code;
    BOOL ret;
    unsigned int i;

    GetModuleFileNameW(NULL, path, ARRAY_SIZE(path));
    low_token = create_labeled_token(SECURITY_MANDATORY_LOW_RID, FALSE);
    if (!low_token) return;
    medium_token = create_labeled_token(SECURITY_MANDATORY_MEDIUM_RID, FALSE);
    if (!medium_token) { CloseHandle(low_token); return; }
    for (i = 0; i < 3; ++i)
    {
        swprintf(command, ARRAY_SIZE(command), L"\"%ls\" pdc_activation %ls", path, i == 2 ? L"death-child" : i ? L"medium-child" : L"low-child");
        trace("child command %s\n", wine_dbgstr_w(command));
        ret = i == 2 ? CreateProcessW(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process) :
                  CreateProcessAsUserW(i ? medium_token : low_token, NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process);
        ok(ret, "create %s: %lu\n", i == 2 ? "death child" : i ? "medium child" : "low child", GetLastError());
        if (!ret) continue;
        ok(WaitForSingleObject(process.hProcess, 5000) == WAIT_OBJECT_0, "child %u timed out\n", i);
        GetExitCodeProcess(process.hProcess, &exit_code);
        ok(!exit_code, "child %u exit %lu\n", i, exit_code);
        if (exit_code == STILL_ACTIVE) TerminateProcess(process.hProcess, 1);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    CloseHandle(medium_token);
    CloseHandle(low_token);
}

static void run_bi_child(BOOL system_user, BOOL low_integrity)
{
    struct pdc_message message;
    ALPC_BASIC_INFORMATION info;
    HANDLE port;
    ULONG size;
    NTSTATUS status;
    init_message(&message, 15, 7);
    status = connect_message(&message, sizeof(message), &port);
    if (!system_user || low_integrity)
        ExitProcess(status == STATUS_ACCESS_DENIED && !port ? 0 : 8);
    if (status || !port) ExitProcess(9);
    status = pNtAlpcQueryInformation(port, 0, &info, sizeof(info), &size);
    if (status || info.SequenceNo != 1) ExitProcess(10);
    status = pNtAlpcDisconnectPort(port, 1);
    CloseHandle(port);
    if (status) ExitProcess(11);
    init_message(&message, 15, 0);
    status = connect_message(&message, sizeof(message), &port);
    ExitProcess(status == STATUS_ACCESS_DENIED && !port ? 0 : 12);
}

static void test_bi_admission(void)
{
    static const WCHAR *modes[] = {L"bi-user-child", L"bi-system-child", L"bi-low-child"};
    PROCESS_INFORMATION process;
    STARTUPINFOW startup = {sizeof(startup)};
    WCHAR path[MAX_PATH], command[2 * MAX_PATH];
    HANDLE token, impersonation;
    struct pdc_message message;
    HANDLE port;
    DWORD exit_code;
    BOOL ret;
    NTSTATUS status;
    unsigned int i;

    GetModuleFileNameW(NULL, path, ARRAY_SIZE(path));
    for (i = 0; i < ARRAY_SIZE(modes); ++i)
    {
        token = create_labeled_token(i == 2 ? SECURITY_MANDATORY_LOW_RID : SECURITY_MANDATORY_MEDIUM_RID, i != 0);
        if (!token) continue;
        if (i == 1)
        {
            ret = DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &impersonation);
            ok(ret, "duplicate System impersonation: %lu\n", GetLastError());
            if (ret)
            {
                ok(SetThreadToken(NULL, impersonation), "System impersonation: %lu\n", GetLastError());
                init_message(&message, 15, 7);
                status = connect_message(&message, sizeof(message), &port);
                ok(status == STATUS_ACCESS_DENIED && !port, "BI must use ordinary primary, not System impersonation: %#lx\n", status);
                if (!status) CloseHandle(port);
                ok(RevertToSelf(), "BI revert: %lu\n", GetLastError());
                CloseHandle(impersonation);
            }
        }
        swprintf(command, ARRAY_SIZE(command), L"\"%ls\" pdc_activation %ls", path, modes[i]);
        ret = CreateProcessAsUserW(token, NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process);
        ok(ret, "create BI child %u: %lu\n", i, GetLastError());
        if (ret)
        {
            ok(WaitForSingleObject(process.hProcess, 5000) == WAIT_OBJECT_0, "BI child %u timed out\n", i);
            GetExitCodeProcess(process.hProcess, &exit_code);
            ok(!exit_code, "BI child %u exit %lu\n", i, exit_code);
            if (exit_code == STILL_ACTIVE) TerminateProcess(process.hProcess, 1);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
        }
        CloseHandle(token);
    }
}

static LONG callback_count;
static void WINAPI notification_callback(void *context, ULONG kind, void *data)
{
    InterlockedIncrement(&callback_count);
}

static void test_native_umpdc(void)
{
    NTSTATUS (WINAPI *activation_register)(ULONG, const struct pdc_descriptor *, void **);
    NTSTATUS (WINAPI *activation_unregister)(void *, void *);
    NTSTATUS (WINAPI *notification_register)(ULONG, const struct pdc_descriptor *, void *, void **);
    NTSTATUS (WINAPI *notification_unregister)(void *);
    struct pdc_descriptor descriptor = {1, 0, notification_callback};
    void *activation = NULL, *notifications[2] = {NULL, NULL};
    static const ULONG ids[] = {1, 100};
    HMODULE module;
    WCHAR path[MAX_PATH];
    NTSTATUS status;
    unsigned int i;

    module = LoadLibraryW(L"umpdc.dll");
    ok(module != NULL, "load UMPDC: %lu\n", GetLastError());
    if (!module) return;
    GetModuleFileNameW(module, path, ARRAY_SIZE(path));
    trace("UMPDC provider %s\n", wine_dbgstr_w(path));
    activation_register = (void *)GetProcAddress(module, "Pdcv2ActivationClientRegister");
    activation_unregister = (void *)GetProcAddress(module, "Pdcv2ActivationClientUnregister");
    notification_register = (void *)GetProcAddress(module, "PdcNotificationClientRegister");
    notification_unregister = (void *)GetProcAddress(module, "PdcNotificationClientUnregister");
    ok(activation_register && activation_unregister && notification_register && notification_unregister,
       "required exports absent\n");
    if (!activation_register || !activation_unregister || !notification_register || !notification_unregister) goto done;
    descriptor.version = 9;
    activation = (void *)0xdeadbeef;
    status = activation_register(100, &descriptor, &activation);
    ok(status == STATUS_INVALID_PARAMETER_2 && !activation,
       "invalid descriptor: %#lx output %p\n", status, activation);
    descriptor.version = 1;
    /* Valid v2 registration also calls genuine RmClient CRM and requires the
     * boot services. The isolated fixture does not start that environment;
     * validate it in the full native startup replay. Both native categories
     * use the same PdcPortClose completion-drain implementation. */
    for (i = 0; i < ARRAY_SIZE(ids); ++i)
    {
        descriptor.version = i ? 2 : 1;
        descriptor.control_callback = notification_callback;
        status = notification_register(ids[i], &descriptor, NULL, &notifications[i]);
        ok(!status && notifications[i], "native notification %lu: %#lx output %p\n", ids[i], status, notifications[i]);
    }
    Sleep(100);
    ok(!callback_count, "no-AoAc registration fabricated %ld callbacks\n", callback_count);
    for (i = 0; i < ARRAY_SIZE(ids); ++i)
        if (notifications[i])
        {
            status = notification_unregister(notifications[i]);
            ok(!status, "native notification close %lu: %#lx\n", ids[i], status);
        }
    status = notification_unregister(NULL);
    ok(status == STATUS_INVALID_PARAMETER_1, "null notification unregister: %#lx\n", status);
    status = activation_unregister(NULL, NULL);
    ok(status == STATUS_INVALID_PARAMETER_1, "null activation unregister: %#lx\n", status);
done:
    FreeLibrary(module);
}

START_TEST(pdc_activation)
{
    int argc;
    char **argv;
    HMODULE module = GetModuleHandleA("ntdll.dll");
    pNtAlpcConnectPort = (void *)GetProcAddress(module, "NtAlpcConnectPort");
    pNtAlpcQueryInformation = (void *)GetProcAddress(module, "NtAlpcQueryInformation");
    pNtAlpcDisconnectPort = (void *)GetProcAddress(module, "NtAlpcDisconnectPort");
    pNtAlpcSendWaitReceivePort = (void *)GetProcAddress(module, "NtAlpcSendWaitReceivePort");
    if (!pNtAlpcConnectPort || !pNtAlpcQueryInformation || !pNtAlpcDisconnectPort || !pNtAlpcSendWaitReceivePort)
    {
        win_skip("ALPC exports unavailable\n");
        return;
    }
    /* This first support partition is current x64 and no-AoAc only. */
    if (sizeof(void *) != 8)
    {
        win_skip("current PDC fixture requires x64\n");
        return;
    }
    argc = winetest_get_mainargs(&argv);
    if (argc > 2 && (!strcmp(argv[2], "low-child") || !strcmp(argv[2], "medium-child") || !strcmp(argv[2], "death-child")))
        run_child(!strcmp(argv[2], "low-child"), !strcmp(argv[2], "medium-child"));
    if (argc > 2 && (!strcmp(argv[2], "bi-user-child") || !strcmp(argv[2], "bi-system-child") || !strcmp(argv[2], "bi-low-child")))
        run_bi_child(strcmp(argv[2], "bi-user-child") != 0, !strcmp(argv[2], "bi-low-child"));
    test_bi_admission();
    test_pool_priority();
    test_raw_registration();
    test_effective_token_admission();
    test_concurrent_disconnect();
    test_process_admission_and_death();
    test_native_umpdc();
}
