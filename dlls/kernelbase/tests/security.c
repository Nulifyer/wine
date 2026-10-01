/*
 * Copyright (C) 2023 Paul Gofman for CodeWeavers
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

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winerror.h>
#include <winternl.h>

#include "wine/test.h"

static BOOL (WINAPI *pDeriveCapabilitySidsFromName)(const WCHAR *, PSID **, DWORD *, PSID **, DWORD *);
static BOOL (WINAPI *pAccessCheckByType)(PSECURITY_DESCRIPTOR, PSID, HANDLE, DWORD,
                                        POBJECT_TYPE_LIST, DWORD, PGENERIC_MAPPING,
                                        PPRIVILEGE_SET, LPDWORD, LPDWORD, LPBOOL);
static BOOL (WINAPI *pCheckTokenCapability)(HANDLE, PSID, PBOOL);

static NTSTATUS (WINAPI *pRtlDeriveCapabilitySidsFromName)(UNICODE_STRING *, PSID, PSID);

static void test_DeriveCapabilitySidsFromName(void)
{
    BYTE auth_count_sid, auth_count_group_sid;
    PSID *check_group_sid, *check_sid;
    DWORD sid_count, group_sid_count;
    PSID *group_sids, *sids;
    UNICODE_STRING name_us;
    NTSTATUS status;
    DWORD size;
    BOOL bret;

    if (!pDeriveCapabilitySidsFromName)
    {
        win_skip ("DeriveCapabilitySidsFromName is not available.\n");
        return;
    }

    if (0)
    {
        /* Crashes on Windows. */
        pDeriveCapabilitySidsFromName(L"test", NULL, &group_sid_count, NULL, &sid_count);
    }

    sid_count = group_sid_count = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    bret = pDeriveCapabilitySidsFromName(L"test", &group_sids, &group_sid_count, &sids, &sid_count);
    ok(bret && GetLastError() == 0xdeadbeef, "got bret %d, err %lu.\n", bret, GetLastError());
    ok(group_sid_count == 1, "got %lu.\n", group_sid_count);
    ok(sid_count == 1, "got %lu.\n", sid_count);

    auth_count_sid = *RtlSubAuthorityCountSid(sids[0]);
    auth_count_group_sid = *RtlSubAuthorityCountSid(group_sids[0]);

    size = RtlLengthRequiredSid(auth_count_sid);
    check_sid = malloc( size );
    size = RtlLengthRequiredSid(auth_count_group_sid);
    check_group_sid = malloc( size );

    RtlInitUnicodeString(&name_us, L"test");
    status = pRtlDeriveCapabilitySidsFromName(&name_us, check_group_sid, check_sid);
    ok(!status, "failed, status %#lx.\n", status);
    ok(!memcmp(sids[0], check_sid, RtlLengthRequiredSid(auth_count_sid)), "mismatch.\n");
    ok(!memcmp(group_sids[0], check_group_sid, RtlLengthRequiredSid(auth_count_group_sid)), "mismatch.\n");

    free(check_sid);
    free(check_group_sid);

    LocalFree(group_sids[0]);
    LocalFree(group_sids);
    LocalFree(sids[0]);
    LocalFree(sids);
}

static void test_CheckTokenCapability(void)
{
    SID_IDENTIFIER_AUTHORITY app_authority = { SECURITY_APP_PACKAGE_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY world_authority = { SECURITY_WORLD_SID_AUTHORITY };
    PSID capability_sid, world_sid;
    HANDLE process_token;
    BOOL has_capability, ret;

    if (!pCheckTokenCapability)
    {
        win_skip("CheckTokenCapability is not available.\n");
        return;
    }

    ret = AllocateAndInitializeSid(&app_authority, 2, SECURITY_CAPABILITY_BASE_RID, 1,
                                   0, 0, 0, 0, 0, 0, &capability_sid);
    ok(ret, "AllocateAndInitializeSid failed, error %lu.\n", GetLastError());
    ret = AllocateAndInitializeSid(&world_authority, 1, SECURITY_WORLD_RID, 0,
                                   0, 0, 0, 0, 0, 0, &world_sid);
    ok(ret, "AllocateAndInitializeSid failed, error %lu.\n", GetLastError());
    ret = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &process_token);
    ok(ret, "OpenProcessToken failed, error %lu.\n", GetLastError());

    has_capability = TRUE;
    ret = pCheckTokenCapability(NULL, capability_sid, &has_capability);
    ok(ret, "implicit token check failed, error %lu.\n", GetLastError());

    has_capability = TRUE;
    SetLastError(0xdeadbeef);
    ret = pCheckTokenCapability(process_token, capability_sid, &has_capability);
    ok(!ret && GetLastError() == ERROR_NO_IMPERSONATION_TOKEN,
       "primary token check returned %d, error %lu.\n", ret, GetLastError());
    ok(!has_capability, "primary token check did not clear the result.\n");

    has_capability = TRUE;
    SetLastError(0xdeadbeef);
    ret = pCheckTokenCapability(NULL, world_sid, &has_capability);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
       "ordinary SID check returned %d, error %lu.\n", ret, GetLastError());
    ok(!has_capability, "ordinary SID check did not clear the result.\n");

    has_capability = TRUE;
    SetLastError(0xdeadbeef);
    ret = pCheckTokenCapability(NULL, NULL, &has_capability);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
       "NULL SID check returned %d, error %lu.\n", ret, GetLastError());
    ok(!has_capability, "NULL SID check did not clear the result.\n");

    SetLastError(0xdeadbeef);
    ret = pCheckTokenCapability(NULL, capability_sid, NULL);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
       "NULL result check returned %d, error %lu.\n", ret, GetLastError());

    CloseHandle(process_token);
    FreeSid(world_sid);
    FreeSid(capability_sid);
}

static void test_AccessCheckByType(void)
{
    BYTE token_buffer[512], self_buffer[SECURITY_MAX_SID_SIZE], system_buffer[SECURITY_MAX_SID_SIZE];
    BYTE acl_buffer[sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + SECURITY_MAX_SID_SIZE];
    DWORD token_size, self_size = sizeof(self_buffer), system_size = sizeof(system_buffer);
    GENERIC_MAPPING mapping = {1, 2, 4, 7};
    SECURITY_DESCRIPTOR descriptor;
    TOKEN_USER *token_user;
    PRIVILEGE_SET privileges;
    DWORD privileges_size, granted;
    HANDLE process_token, token;
    BOOL access_status, ret;
    PACL acl = (PACL)acl_buffer;

    if (!pAccessCheckByType)
    {
        win_skip("AccessCheckByType is not available.\n");
        return;
    }

    ret = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &process_token);
    ok(ret, "OpenProcessToken failed, error %lu.\n", GetLastError());
    ret = DuplicateToken(process_token, SecurityImpersonation, &token);
    ok(ret, "DuplicateToken failed, error %lu.\n", GetLastError());
    ret = GetTokenInformation(process_token, TokenUser, token_buffer, sizeof(token_buffer), &token_size);
    ok(ret, "GetTokenInformation failed, error %lu.\n", GetLastError());
    token_user = (TOKEN_USER *)token_buffer;

    ret = CreateWellKnownSid(WinSelfSid, NULL, self_buffer, &self_size);
    ok(ret, "CreateWellKnownSid(WinSelfSid) failed, error %lu.\n", GetLastError());
    ret = CreateWellKnownSid(WinLocalSystemSid, NULL, system_buffer, &system_size);
    ok(ret, "CreateWellKnownSid(WinLocalSystemSid) failed, error %lu.\n", GetLastError());
    ret = InitializeAcl(acl, sizeof(acl_buffer), ACL_REVISION);
    ok(ret, "InitializeAcl failed, error %lu.\n", GetLastError());
    ret = AddAccessAllowedAce(acl, ACL_REVISION, 1, self_buffer);
    ok(ret, "AddAccessAllowedAce failed, error %lu.\n", GetLastError());
    ret = InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION);
    ok(ret, "InitializeSecurityDescriptor failed, error %lu.\n", GetLastError());
    ret = SetSecurityDescriptorOwner(&descriptor, system_buffer, FALSE);
    ok(ret, "SetSecurityDescriptorOwner failed, error %lu.\n", GetLastError());
    ret = SetSecurityDescriptorGroup(&descriptor, system_buffer, FALSE);
    ok(ret, "SetSecurityDescriptorGroup failed, error %lu.\n", GetLastError());
    ret = SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE);
    ok(ret, "SetSecurityDescriptorDacl failed, error %lu.\n", GetLastError());

    privileges_size = sizeof(privileges);
    access_status = FALSE;
    granted = 0;
    ret = pAccessCheckByType(&descriptor, token_user->User.Sid, token, 1, NULL, 0,
                             &mapping, &privileges, &privileges_size, &granted, &access_status);
    ok(ret, "principal-self access check failed, error %lu.\n", GetLastError());
    ok(access_status, "principal-self access was denied.\n");
    ok(granted == 1, "principal-self granted access %#lx.\n", granted);

    privileges_size = sizeof(privileges);
    access_status = TRUE;
    granted = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    ret = pAccessCheckByType(&descriptor, NULL, token, 1, NULL, 0,
                             &mapping, &privileges, &privileges_size, &granted, &access_status);
    ok(ret, "NULL principal-self access check failed, error %lu.\n", GetLastError());
    ok(!access_status, "NULL principal-self access was granted.\n");
    ok(!granted, "NULL principal-self granted access %#lx.\n", granted);
    ok(GetLastError() == ERROR_ACCESS_DENIED, "got error %lu.\n", GetLastError());

    CloseHandle(token);
    CloseHandle(process_token);
}

START_TEST(security)
{
    HMODULE hmod;

    hmod = LoadLibraryA("kernelbase.dll");
    pAccessCheckByType = (void *)GetProcAddress(hmod, "AccessCheckByType");
    pDeriveCapabilitySidsFromName = (void *)GetProcAddress(hmod, "DeriveCapabilitySidsFromName");
    pCheckTokenCapability = (void *)GetProcAddress(hmod, "CheckTokenCapability");

    hmod = LoadLibraryA("ntdll.dll");
    pRtlDeriveCapabilitySidsFromName = (void *)GetProcAddress(hmod, "RtlDeriveCapabilitySidsFromName");

    test_DeriveCapabilitySidsFromName();
    test_AccessCheckByType();
    test_CheckTokenCapability();
}
