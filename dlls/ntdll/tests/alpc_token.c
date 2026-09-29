/*
 * Private IPC impersonation token ownership tests
 * Copyright 2026 LinuxNT contributors
 * LGPL-2.1-or-later
 */
#include <stdarg.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "wine/test.h"

static NTSTATUS (WINAPI *impersonate_port)(HANDLE, ALPC_PORT_MESSAGE *, void *);
static HANDLE client_token, pipe_finish;
static SECURITY_DESCRIPTOR port_sd;
static ALPC_PORT_ATTRIBUTES port_attributes;
static UNICODE_STRING port_name;
static HANDLE client_port;
static NTSTATUS client_status;
static const SID client_sid = {SID_REVISION, 1, {SECURITY_NT_AUTHORITY}, {SECURITY_LOCAL_SERVICE_RID}};

static HANDLE create_client_token(void)
{
    BYTE acl_buffer[128];
    ACL *acl = (ACL *)acl_buffer;
    SECURITY_DESCRIPTOR sd;
    SECURITY_QUALITY_OF_SERVICE qos = {sizeof(qos), SecurityIdentification, SECURITY_STATIC_TRACKING, FALSE};
    TOKEN_USER user = {{(PSID)&client_sid, 0}};
    TOKEN_OWNER owner = {(PSID)&client_sid};
    TOKEN_PRIMARY_GROUP group = {(PSID)&client_sid};
    TOKEN_GROUPS groups = {0};
    TOKEN_PRIVILEGES privileges = {0};
    TOKEN_DEFAULT_DACL default_dacl = {acl};
    TOKEN_SOURCE source = {{'I','P','C'}};
    LARGE_INTEGER expiration;
    OBJECT_ATTRIBUTES attributes;
    LUID authentication;
    HANDLE token = NULL;
    SID integrity_sid = {SID_REVISION, 1, {SECURITY_MANDATORY_LABEL_AUTHORITY}, {SECURITY_MANDATORY_MEDIUM_RID}};
    BYTE label_buffer[128];
    ACL *label_acl = (ACL *)label_buffer;
    ACCESS_ALLOWED_ACE *label_ace;
    NTSTATUS status;

    RtlCreateAcl(acl, sizeof(acl_buffer), ACL_REVISION);
    RtlAddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, (PSID)&client_sid);
    RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    RtlSetDaclSecurityDescriptor(&sd, TRUE, acl, FALSE);
    RtlCreateAcl(label_acl, sizeof(label_buffer), ACL_REVISION);
    RtlAddAccessAllowedAce(label_acl, ACL_REVISION, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, &integrity_sid);
    RtlGetAce(label_acl, 0, (void **)&label_ace);
    label_ace->Header.AceType = SYSTEM_MANDATORY_LABEL_ACE_TYPE;
    RtlSetSaclSecurityDescriptor(&sd, TRUE, label_acl, FALSE);
    RtlSetDaclSecurityDescriptor(&sd, TRUE, NULL, FALSE);
    InitializeObjectAttributes(&attributes, NULL, 0, NULL, &sd);
    attributes.SecurityQualityOfService = &qos;
    NtAllocateLocallyUniqueId(&authentication);
    NtAllocateLocallyUniqueId(&source.SourceIdentifier);
    expiration.QuadPart = MAXLONGLONG;
    status = NtCreateToken(&token, TOKEN_ALL_ACCESS, &attributes, TokenImpersonation,
                          &authentication, &expiration, &user, &groups, &privileges,
                          &owner, &group, &default_dacl, &source);
    ok(!status, "NtCreateToken returned %#lx.\n", status);
    if (status) return NULL;
    RtlSetDaclSecurityDescriptor(&sd, TRUE, acl, FALSE);
    status = NtSetSecurityObject(token, DACL_SECURITY_INFORMATION, &sd);
    ok(!status, "Client descriptor assignment returned %#lx.\n", status);
    if (status) { NtClose(token); return NULL; }
    return token;
}

static void check_private_token(const char *transport)
{
    BYTE buffer[512];
    TOKEN_USER *user = (TOKEN_USER *)buffer;
    TOKEN_STATISTICS first, second, source;
    SECURITY_DESCRIPTOR *sd = (SECURITY_DESCRIPTOR *)buffer;
    ACL *acl;
    ACCESS_ALLOWED_ACE *ace;
    BOOLEAN present, defaulted;
    SID world_sid = {SID_REVISION, 1, {SECURITY_WORLD_SID_AUTHORITY}, {SECURITY_WORLD_RID}};
    HANDLE token = NULL, reopened = NULL, limited = NULL;
    ULONG i;
    ULONG size;
    NTSTATUS status;

    ok(DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(),
                       &limited, 0, FALSE, 0), "%s: limited thread handle failed.\n", transport);
    if (limited)
    {
        status = NtOpenThreadToken(limited, TOKEN_QUERY, TRUE, &token);
        ok(status == STATUS_ACCESS_DENIED, "%s: private copy bypassed thread rights: %#lx.\n", transport, status);
        if (!status) NtClose(token);
        CloseHandle(limited);
    }
    status = NtOpenThreadToken(NtCurrentThread(), ACCESS_SYSTEM_SECURITY, TRUE, &token);
    ok(status == STATUS_PRIVILEGE_NOT_HELD, "%s: private copy bypassed security privilege: %#lx.\n", transport, status);
    if (!status) NtClose(token);
    status = NtOpenThreadToken(NtCurrentThread(), TOKEN_QUERY | READ_CONTROL, TRUE, &token);
    ok(!status, "%s: OpenAsSelf returned %#lx.\n", transport, status);
    if (status) return;
    status = NtQueryInformationToken(token, TokenUser, buffer, sizeof(buffer), &size);
    ok(!status, "%s: TokenUser returned %#lx.\n", transport, status);
    if (!status) ok(RtlEqualSid(user->User.Sid, (PSID)&client_sid), "%s: wrong client identity.\n", transport);
    status = NtQueryInformationToken(token, TokenStatistics, &first, sizeof(first), &size);
    ok(!status, "%s: TokenStatistics returned %#lx.\n", transport, status);
    status = NtQueryInformationToken(client_token, TokenStatistics, &source, sizeof(source), &size);
    ok(!status, "%s: source statistics returned %#lx.\n", transport, status);
    if (!status)
    {
        ok(memcmp(&first.TokenId, &source.TokenId, sizeof(LUID)), "%s: opened captured source directly.\n", transport);
        ok(!memcmp(&first.AuthenticationId, &source.AuthenticationId, sizeof(LUID)),
           "%s: private copy changed authentication identity.\n", transport);
    }
    status = NtQuerySecurityObject(token, DACL_SECURITY_INFORMATION, buffer, sizeof(buffer), &size);
    ok(!status, "%s: private descriptor returned %#lx.\n", transport, status);
    if (!status)
    {
        RtlGetDaclSecurityDescriptor(sd, &present, &acl, &defaulted);
        ok(present && acl && acl->AceCount == 4, "%s: expected four-principal private DACL.\n", transport);
        if (present && acl)
            for (i = 0; i < acl->AceCount; i++)
            {
                status = RtlGetAce(acl, i, (void **)&ace);
                ok(!status, "%s: private ACE %lu invalid: %#lx.\n", transport, i, status);
                if (status) continue;
                ok(ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && ace->Mask == GENERIC_ALL,
                   "%s: private ACE %lu has wrong grant.\n", transport, i);
                ok(!RtlEqualSid(&ace->SidStart, &world_sid), "%s: private descriptor grants Everyone.\n", transport);
            }
    }
    status = NtQuerySecurityObject(client_token, DACL_SECURITY_INFORMATION, buffer, sizeof(buffer), &size);
    ok(!status, "%s: source descriptor returned %#lx.\n", transport, status);
    if (!status)
    {
        RtlGetDaclSecurityDescriptor(sd, &present, &acl, &defaulted);
        ok(present && acl && acl->AceCount == 1, "%s: changed the source DACL.\n", transport);
        if (present && acl && acl->AceCount == 1)
        {
            RtlGetAce(acl, 0, (void **)&ace);
            ok(RtlEqualSid(&ace->SidStart, (PSID)&client_sid), "%s: changed the source principal.\n", transport);
        }
    }
    status = NtOpenThreadToken(NtCurrentThread(), TOKEN_QUERY, TRUE, &reopened);
    ok(!status, "%s: second OpenAsSelf returned %#lx.\n", transport, status);
    if (!status)
    {
        status = NtQueryInformationToken(reopened, TokenStatistics, &second, sizeof(second), &size);
        ok(!status, "%s: reopened statistics returned %#lx.\n", transport, status);
        ok(!memcmp(&first.TokenId, &second.TokenId, sizeof(LUID)), "%s: repeated opening changed token identity.\n", transport);
        NtClose(reopened);
    }
    ok(RevertToSelf(), "%s: RevertToSelf failed %lu.\n", transport, GetLastError());
    status = NtQueryInformationToken(token, TokenUser, buffer, sizeof(buffer), &size);
    ok(!status, "%s: private handle did not survive revert: %#lx.\n", transport, status);
    NtClose(token);
    token = (HANDLE)0xdeadbeef;
    status = NtOpenThreadToken(NtCurrentThread(), TOKEN_QUERY, TRUE, &token);
    ok(status == STATUS_NO_TOKEN, "%s: revert left token, status %#lx.\n", transport, status);
}

static DWORD WINAPI alpc_client(void *unused)
{
    OBJECT_ATTRIBUTES attributes;
    LARGE_INTEGER timeout;
    if (!SetThreadToken(NULL, client_token)) return GetLastError();
    InitializeObjectAttributes(&attributes, &port_name, 0, NULL, NULL);
    timeout.QuadPart = -100000000;
    client_status = NtAlpcConnectPortEx(&client_port, &attributes, NULL, &port_attributes,
                                      0x20000, NULL, NULL, NULL, NULL, NULL, &timeout);
    RevertToSelf();
    return 0;
}

static void test_alpc(void)
{
    ALPC_PORT_MESSAGE message = {0};
    OBJECT_ATTRIBUTES attributes;
    HANDLE listener = NULL, server = NULL, thread = NULL;
    WCHAR name[96];
    LARGE_INTEGER zero = {0};
    SIZE_T size = sizeof(message);
    NTSTATUS status;

    swprintf(name, ARRAY_SIZE(name), L"\\BaseNamedObjects\\winetest_private_token_%lu", GetCurrentProcessId());
    RtlInitUnicodeString(&port_name, name);
    InitializeObjectAttributes(&attributes, &port_name, 0, NULL, &port_sd);
    port_attributes.Flags = 0x70000;
    port_attributes.MaxMessageLength = sizeof(message);
    port_attributes.SecurityQos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
    port_attributes.SecurityQos.ImpersonationLevel = SecurityIdentification;
    status = NtAlpcCreatePort(&listener, &attributes, &port_attributes);
    ok(!status, "Port creation returned %#lx.\n", status);
    if (status) return;
    thread = CreateThread(NULL, 0, alpc_client, NULL, 0, NULL);
    ok(!!thread, "Client thread creation failed.\n");
    if (!thread) goto done;
    ok(WaitForSingleObject(listener, 5000) == WAIT_OBJECT_0, "Admission not signaled.\n");
    status = NtAlpcSendWaitReceivePort(listener, 0, NULL, NULL, &message, &size, NULL, &zero);
    ok(!status, "Admission receipt returned %#lx.\n", status);
    if (status) goto done;
    status = NtAlpcAcceptConnectPort(&server, listener, 0, NULL, &port_attributes, NULL, &message, NULL, TRUE);
    ok(!status, "Acceptance returned %#lx.\n", status);
    if (status) goto done;
    ok(WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0, "Client did not connect.\n");
    ok(!client_status, "Client connection returned %#lx.\n", client_status);
    status = impersonate_port(server, NULL, NULL);
    ok(!status, "ALPC impersonation returned %#lx.\n", status);
    if (!status) check_private_token("ALPC");
done:
    RevertToSelf();
    if (server) NtClose(server);
    if (client_port) NtClose(client_port);
    NtClose(listener);
    if (thread) { WaitForSingleObject(thread, 12000); CloseHandle(thread); }
}

static DWORD WINAPI pipe_client(void *name)
{
    HANDLE pipe;
    DWORD written;
    if (!SetThreadToken(NULL, client_token)) return GetLastError();
    pipe = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                       SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
    if (pipe == INVALID_HANDLE_VALUE) return GetLastError();
    WriteFile(pipe, "x", 1, &written, NULL);
    WaitForSingleObject(pipe_finish, 5000);
    CloseHandle(pipe);
    RevertToSelf();
    return 0;
}

static void test_pipe(void)
{
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), &port_sd, FALSE};
    WCHAR name[96];
    HANDLE pipe, thread;
    DWORD size;
    char byte;
    BOOL ret;

    swprintf(name, ARRAY_SIZE(name), L"\\\\.\\pipe\\winetest_private_token_%lu", GetCurrentProcessId());
    pipe = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_WAIT, 1, 128, 128, 1000, &attributes);
    ok(pipe != INVALID_HANDLE_VALUE, "Named pipe creation failed.\n");
    if (pipe == INVALID_HANDLE_VALUE) return;
    pipe_finish = CreateEventW(NULL, TRUE, FALSE, NULL);
    thread = CreateThread(NULL, 0, pipe_client, name, 0, NULL);
    ok(!!thread, "Pipe client thread creation failed.\n");
    if (thread)
    {
        ret = ConnectNamedPipe(pipe, NULL);
        ok(ret || GetLastError() == ERROR_PIPE_CONNECTED, "Pipe connection failed %lu.\n", GetLastError());
        ret = ReadFile(pipe, &byte, 1, &size, NULL);
        ok(ret && size == 1, "Pipe receipt failed %lu.\n", GetLastError());
        ret = ImpersonateNamedPipeClient(pipe);
        ok(ret, "Pipe impersonation failed %lu.\n", GetLastError());
        if (ret) check_private_token("pipe");
        RevertToSelf();
        SetEvent(pipe_finish);
        ok(WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0, "Pipe client did not exit.\n");
        CloseHandle(thread);
    }
    CloseHandle(pipe);
    CloseHandle(pipe_finish);
}

START_TEST(alpc_token)
{
    HANDLE opened;
    NTSTATUS status;
    if (!winetest_platform_is_wine)
    {
        win_skip("Synthetic cross-user tokens require Wine's controlled token authority.\n");
        return;
    }
    impersonate_port = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtAlpcImpersonateClientOfPort");
    ok(!!impersonate_port, "ALPC impersonation owner unavailable.\n");
    if (!impersonate_port || !(client_token = create_client_token())) return;
    RtlCreateSecurityDescriptor(&port_sd, SECURITY_DESCRIPTOR_REVISION);
    RtlSetDaclSecurityDescriptor(&port_sd, TRUE, NULL, FALSE);
    ok(SetThreadToken(NULL, client_token), "Explicit token assignment failed.\n");
    status = NtOpenThreadToken(NtCurrentThread(), TOKEN_QUERY, TRUE, &opened);
    ok(status == STATUS_ACCESS_DENIED, "Explicit assignment bypassed its descriptor: %#lx.\n", status);
    if (!status) NtClose(opened);
    RevertToSelf();
    test_alpc();
    test_pipe();
    NtClose(client_token);
}
