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
#include <winreg.h>

#include "wine/test.h"

static BOOL (WINAPI *pDeriveCapabilitySidsFromName)(const WCHAR *, PSID **, DWORD *, PSID **, DWORD *);
static HRESULT (WINAPI *pAppContainerDeriveSidFromMoniker)(const WCHAR *, PSID *);
static HRESULT (WINAPI *pAppContainerLookupMoniker)(PSID, WCHAR **);
static HRESULT (WINAPI *pAppContainerLookupDisplayNameMrtReference)(PSID, WCHAR **);
static HRESULT (WINAPI *pAppContainerRegisterSid)(PSID, const WCHAR *, const WCHAR *);
static HRESULT (WINAPI *pAppContainerUnregisterSid)(PSID);
static void (WINAPI *pAppContainerFreeMemory)(void *);
static BOOL (WINAPI *pAccessCheckByType)(PSECURITY_DESCRIPTOR, PSID, HANDLE, DWORD,
                                        POBJECT_TYPE_LIST, DWORD, PGENERIC_MAPPING,
                                        PPRIVILEGE_SET, LPDWORD, LPDWORD, LPBOOL);
static BOOL (WINAPI *pCheckTokenMembershipEx)(HANDLE, PSID, DWORD, PBOOL);

static NTSTATUS (WINAPI *pRtlDeriveCapabilitySidsFromName)(UNICODE_STRING *, PSID, PSID);

static void check_access_by_type(PSECURITY_DESCRIPTOR descriptor, PSID principal_self,
                                 HANDLE token, BOOL expected, const char *context)
{
    GENERIC_MAPPING mapping = { 1, 1, 1, 1 };
    PRIVILEGE_SET privileges;
    DWORD privileges_size = sizeof(privileges), granted = 0xdeadbeef;
    BOOL access = !expected, ret;

    SetLastError(0xdeadbeef);
    ret = pAccessCheckByType(descriptor, principal_self, token, 1, NULL, 0, &mapping,
                             &privileges, &privileges_size, &granted, &access);
    ok(ret, "%s: AccessCheckByType failed, error %lu.\n", context, GetLastError());
    ok(access == expected, "%s: got access %d.\n", context, access);
    ok(granted == (expected ? 1 : 0), "%s: got granted access %#lx.\n", context, granted);
}

static void test_AccessCheckByType(void)
{
    static SID world_sid = { SID_REVISION, 1, { SECURITY_WORLD_SID_AUTHORITY }, { SECURITY_WORLD_RID } };
    static SID principal_self_sid = { SID_REVISION, 1, { SECURITY_NT_AUTHORITY },
                                      { SECURITY_PRINCIPAL_SELF_RID } };
    static SID other_sid = { SID_REVISION, 1, { SECURITY_NT_AUTHORITY },
                             { SECURITY_LOCAL_SERVICE_RID } };
    BYTE acl_buffer[sizeof(ACL) + 2 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) +
                                      SECURITY_MAX_SID_SIZE)];
    SECURITY_DESCRIPTOR descriptor;
    SID_AND_ATTRIBUTES restriction;
    TOKEN_USER *user;
    DWORD user_size;
    HANDLE process_token, token, restricted_primary, restricted_token;
    BOOL ret;

    if (!pAccessCheckByType)
    {
        win_skip("AccessCheckByType is not available.\n");
        return;
    }

    ret = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &process_token);
    ok(ret, "OpenProcessToken failed, error %lu.\n", GetLastError());
    if (!ret) return;
    user_size = 0;
    ret = GetTokenInformation(process_token, TokenUser, NULL, 0, &user_size);
    ok(!ret && GetLastError() == ERROR_INSUFFICIENT_BUFFER,
       "GetTokenInformation returned %d, error %lu.\n", ret, GetLastError());
    user = malloc(user_size);
    ok(!!user, "Failed to allocate user buffer.\n");
    if (!user)
    {
        CloseHandle(process_token);
        return;
    }
    ret = GetTokenInformation(process_token, TokenUser, user, user_size, &user_size);
    ok(ret, "GetTokenInformation failed, error %lu.\n", GetLastError());

    ret = DuplicateToken(process_token, SecurityImpersonation, &token);
    ok(ret, "DuplicateToken failed, error %lu.\n", GetLastError());
    if (!ret)
    {
        CloseHandle(process_token);
        free(user);
        return;
    }

    ret = InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION);
    ok(ret, "InitializeSecurityDescriptor failed, error %lu.\n", GetLastError());
    ret = SetSecurityDescriptorOwner(&descriptor, &world_sid, FALSE);
    ok(ret, "SetSecurityDescriptorOwner failed, error %lu.\n", GetLastError());
    ret = SetSecurityDescriptorGroup(&descriptor, &world_sid, FALSE);
    ok(ret, "SetSecurityDescriptorGroup failed, error %lu.\n", GetLastError());
    ret = InitializeAcl((ACL *)acl_buffer, sizeof(acl_buffer), ACL_REVISION);
    ok(ret, "InitializeAcl failed, error %lu.\n", GetLastError());
    ret = AddAccessAllowedAce((ACL *)acl_buffer, ACL_REVISION, 1, &principal_self_sid);
    ok(ret, "AddAccessAllowedAce failed, error %lu.\n", GetLastError());
    ret = SetSecurityDescriptorDacl(&descriptor, TRUE, (ACL *)acl_buffer, FALSE);
    ok(ret, "SetSecurityDescriptorDacl failed, error %lu.\n", GetLastError());

    check_access_by_type(&descriptor, user->User.Sid, token, TRUE, "matching principal");
    check_access_by_type(&descriptor, &other_sid, token, FALSE, "nonmatching principal");
    check_access_by_type(&descriptor, NULL, token, FALSE, "null principal");

    restriction.Attributes = 0;
    restriction.Sid = user->User.Sid;
    ret = CreateRestrictedToken(process_token, 0, 0, NULL, 0, NULL, 1, &restriction,
                                &restricted_primary);
    ok(ret, "CreateRestrictedToken failed, error %lu.\n", GetLastError());
    if (ret)
    {
        ret = DuplicateToken(restricted_primary, SecurityImpersonation, &restricted_token);
        ok(ret, "DuplicateToken failed, error %lu.\n", GetLastError());
        if (ret)
        {
            check_access_by_type(&descriptor, user->User.Sid, restricted_token, TRUE,
                                 "matching restricted principal");
            CloseHandle(restricted_token);
        }
        CloseHandle(restricted_primary);
    }

    restriction.Sid = &world_sid;
    ret = CreateRestrictedToken(process_token, 0, 0, NULL, 0, NULL, 1, &restriction,
                                &restricted_primary);
    ok(ret, "CreateRestrictedToken failed, error %lu.\n", GetLastError());
    if (ret)
    {
        ret = DuplicateToken(restricted_primary, SecurityImpersonation, &restricted_token);
        ok(ret, "DuplicateToken failed, error %lu.\n", GetLastError());
        if (ret)
        {
            check_access_by_type(&descriptor, user->User.Sid, restricted_token, FALSE,
                                 "principal absent from restricting SIDs");
            CloseHandle(restricted_token);
        }
        CloseHandle(restricted_primary);
    }

    ret = InitializeAcl((ACL *)acl_buffer, sizeof(acl_buffer), ACL_REVISION);
    ok(ret, "InitializeAcl failed, error %lu.\n", GetLastError());
    ret = AddAccessDeniedAce((ACL *)acl_buffer, ACL_REVISION, 1, &principal_self_sid);
    ok(ret, "AddAccessDeniedAce failed, error %lu.\n", GetLastError());
    ret = AddAccessAllowedAce((ACL *)acl_buffer, ACL_REVISION, 1, &world_sid);
    ok(ret, "AddAccessAllowedAce failed, error %lu.\n", GetLastError());
    ret = SetSecurityDescriptorDacl(&descriptor, TRUE, (ACL *)acl_buffer, FALSE);
    ok(ret, "SetSecurityDescriptorDacl failed, error %lu.\n", GetLastError());

    check_access_by_type(&descriptor, user->User.Sid, token, FALSE, "matching deny principal");
    check_access_by_type(&descriptor, &other_sid, token, TRUE, "nonmatching deny principal");

    CloseHandle(process_token);
    CloseHandle(token);
    free(user);
}

static void test_CheckTokenMembershipEx(void)
{
    static SID world_sid = { SID_REVISION, 1, { SECURITY_WORLD_SID_AUTHORITY }, { SECURITY_WORLD_RID } };
    static SID invalid_sid = { 0, 1, { SECURITY_WORLD_SID_AUTHORITY }, { SECURITY_WORLD_RID } };
    HANDLE process_token, impersonation_token;
    BOOL member, ret;
    DWORD flags;

    if (!pCheckTokenMembershipEx)
    {
        win_skip("CheckTokenMembershipEx is not available.\n");
        return;
    }

    for (flags = 0; flags <= 3; ++flags)
    {
        member = FALSE;
        SetLastError(0xdeadbeef);
        ret = pCheckTokenMembershipEx(NULL, &world_sid, flags, &member);
        ok(ret, "flags %#lx failed, error %lu.\n", flags, GetLastError());
        ok(member, "flags %#lx did not find the World SID.\n", flags);
        ok(GetLastError() == 0xdeadbeef, "flags %#lx changed error to %lu.\n", flags, GetLastError());
    }

    member = 0x7f7f7f7f;
    SetLastError(0xdeadbeef);
    ret = pCheckTokenMembershipEx(NULL, NULL, 1, &member);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER, "null SID returned %d, error %lu.\n",
       ret, GetLastError());
    ok(member == 0x7f7f7f7f, "null SID changed member to %#x.\n", member);

    member = TRUE;
    SetLastError(0xdeadbeef);
    ret = pCheckTokenMembershipEx(NULL, &world_sid, 4, &member);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER, "invalid flags returned %d, error %lu.\n",
       ret, GetLastError());
    ok(!member, "invalid flags did not clear member.\n");

    member = TRUE;
    SetLastError(0xdeadbeef);
    ret = pCheckTokenMembershipEx(NULL, &invalid_sid, 1, &member);
    ok(!ret && GetLastError() == ERROR_INVALID_SID, "invalid SID returned %d, error %lu.\n",
       ret, GetLastError());
    ok(!member, "invalid SID did not clear member.\n");

    ret = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &process_token);
    ok(ret, "OpenProcessToken failed, error %lu.\n", GetLastError());
    if (!ret) return;

    member = TRUE;
    SetLastError(0xdeadbeef);
    ret = pCheckTokenMembershipEx(process_token, &world_sid, 1, &member);
    ok(!ret && GetLastError() == ERROR_NO_IMPERSONATION_TOKEN,
       "primary token returned %d, error %lu.\n", ret, GetLastError());
    ok(!member, "primary token did not clear member.\n");

    ret = DuplicateToken(process_token, SecurityImpersonation, &impersonation_token);
    ok(ret, "DuplicateToken failed, error %lu.\n", GetLastError());
    if (ret)
    {
        member = FALSE;
        SetLastError(0xdeadbeef);
        ret = pCheckTokenMembershipEx(impersonation_token, &world_sid, 1, &member);
        ok(ret, "impersonation token failed, error %lu.\n", GetLastError());
        ok(member, "impersonation token did not find the World SID.\n");
        ok(GetLastError() == 0xdeadbeef, "impersonation token changed error to %lu.\n", GetLastError());
        CloseHandle(impersonation_token);
    }
    CloseHandle(process_token);
}

static void test_AppContainerDeriveSidFromMoniker(void)
{
    static const DWORD expected[] =
    {
        SECURITY_APP_PACKAGE_BASE_RID, 1980125950, 1037672881, 421768107,
        1949737198, 2922275827u, 507320043, 1582245000
    };
    static const SID_IDENTIFIER_AUTHORITY authority = { SECURITY_APP_PACKAGE_AUTHORITY };
    PSID sid, mixed_case_sid;
    SID *sid_header;
    HRESULT hr;
    unsigned int i;

    if (!pAppContainerDeriveSidFromMoniker)
    {
        win_skip("AppContainerDeriveSidFromMoniker is not available.\n");
        return;
    }

    hr = pAppContainerDeriveSidFromMoniker(NULL, &sid);
    ok(hr == E_INVALIDARG, "got hr %#lx.\n", hr);
    hr = pAppContainerDeriveSidFromMoniker(L"test", NULL);
    ok(hr == E_INVALIDARG, "got hr %#lx.\n", hr);
    hr = pAppContainerDeriveSidFromMoniker(L"", &sid);
    ok(hr == E_INVALIDARG, "got hr %#lx.\n", hr);

    sid = NULL;
    hr = pAppContainerDeriveSidFromMoniker(L"test", &sid);
    ok(hr == S_OK, "got hr %#lx.\n", hr);
    ok(!!sid, "expected a SID.\n");
    if (sid)
    {
        sid_header = sid;
        ok(sid_header->Revision == SID_REVISION, "got revision %u.\n", sid_header->Revision);
        ok(sid_header->SubAuthorityCount == ARRAY_SIZE(expected), "got count %u.\n",
           sid_header->SubAuthorityCount);
        ok(!memcmp(&sid_header->IdentifierAuthority, &authority, sizeof(authority)),
           "got unexpected authority.\n");
        for (i = 0; i < ARRAY_SIZE(expected); ++i)
            ok(sid_header->SubAuthority[i] == expected[i], "subauthority %u: got %lu.\n",
               i, sid_header->SubAuthority[i]);
    }

    mixed_case_sid = NULL;
    hr = pAppContainerDeriveSidFromMoniker(L"TeSt", &mixed_case_sid);
    ok(hr == S_OK, "got hr %#lx.\n", hr);
    ok(!!mixed_case_sid, "expected a SID.\n");
    if (sid && mixed_case_sid)
        ok(EqualSid(sid, mixed_case_sid), "moniker hashing was not case-insensitive.\n");

    if (sid) FreeSid(sid);
    if (mixed_case_sid) FreeSid(mixed_case_sid);
}

static void test_AppContainerLookupMoniker(void)
{
    static const WCHAR key_path[] =
        L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Mappings\\"
        L"S-1-15-2-1980125950-1037672881-421768107-1949737198-2922275827-507320043-1582245000";
    static const WCHAR value[] = L"Wine.KernelBase.AppContainer.Test";
    static const WCHAR display_value[] = L"@{Wine.KernelBase.AppContainer?ms-resource://DisplayName}";
    WCHAR *moniker = (WCHAR *)0xdeadbeef;
    PSID sid = NULL;
    HRESULT hr;

    if (!pAppContainerLookupMoniker || !pAppContainerFreeMemory ||
        !pAppContainerLookupDisplayNameMrtReference || !pAppContainerDeriveSidFromMoniker ||
        !pAppContainerRegisterSid || !pAppContainerUnregisterSid)
    {
        win_skip("AppContainer lookup functions are not available.\n");
        return;
    }

    hr = pAppContainerLookupMoniker(NULL, &moniker);
    ok(hr == E_INVALIDARG, "got hr %#lx.\n", hr);
    hr = pAppContainerLookupMoniker((PSID)0xdeadbeef, NULL);
    ok(hr == E_INVALIDARG, "got hr %#lx.\n", hr);
    hr = pAppContainerLookupDisplayNameMrtReference(NULL, &moniker);
    ok(hr == E_INVALIDARG, "got hr %#lx.\n", hr);

    hr = pAppContainerRegisterSid(NULL, value, display_value);
    ok(hr == E_INVALIDARG, "got hr %#lx.\n", hr);
    hr = pAppContainerUnregisterSid(NULL);
    ok(hr == E_INVALIDARG, "got hr %#lx.\n", hr);

    hr = pAppContainerDeriveSidFromMoniker(L"test", &sid);
    ok(hr == S_OK, "got hr %#lx.\n", hr);
    if (FAILED(hr)) return;

    hr = pAppContainerRegisterSid(sid, NULL, display_value);
    ok(hr == E_INVALIDARG, "got hr %#lx.\n", hr);
    hr = pAppContainerRegisterSid(sid, L"", display_value);
    ok(hr == E_INVALIDARG, "got hr %#lx.\n", hr);
    hr = pAppContainerRegisterSid(sid, value, NULL);
    ok(hr == E_INVALIDARG, "got hr %#lx.\n", hr);
    hr = pAppContainerRegisterSid(sid, value, L"");
    ok(hr == E_INVALIDARG, "got hr %#lx.\n", hr);

    RegDeleteKeyW(HKEY_CURRENT_USER, key_path);
    moniker = (WCHAR *)0xdeadbeef;
    hr = pAppContainerLookupMoniker(sid, &moniker);
    ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), "got hr %#lx.\n", hr);
    ok(moniker == (WCHAR *)0xdeadbeef, "output changed to %p.\n", moniker);

    hr = pAppContainerRegisterSid(sid, value, display_value);
    ok(hr == S_OK, "got hr %#lx.\n", hr);
    hr = pAppContainerRegisterSid(sid, value, display_value);
    ok(hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS), "got hr %#lx.\n", hr);

    moniker = NULL;
    hr = pAppContainerLookupMoniker(sid, &moniker);
    ok(hr == S_OK, "got hr %#lx.\n", hr);
    ok(!!moniker, "expected a moniker.\n");
    if (moniker)
    {
        ok(!wcscmp(moniker, value), "got %s.\n", wine_dbgstr_w(moniker));
        pAppContainerFreeMemory(moniker);
    }

    moniker = NULL;
    hr = pAppContainerLookupDisplayNameMrtReference(sid, &moniker);
    ok(hr == S_OK, "got hr %#lx.\n", hr);
    ok(!!moniker, "expected a display name.\n");
    if (moniker)
    {
        ok(!wcscmp(moniker, display_value), "got %s.\n", wine_dbgstr_w(moniker));
        pAppContainerFreeMemory(moniker);
    }

    hr = pAppContainerUnregisterSid(sid);
    ok(hr == S_OK, "got hr %#lx.\n", hr);

    moniker = (WCHAR *)0xdeadbeef;
    hr = pAppContainerLookupMoniker(sid, &moniker);
    ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), "got hr %#lx.\n", hr);
    ok(moniker == (WCHAR *)0xdeadbeef, "output changed to %p.\n", moniker);

    FreeSid(sid);
}

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

START_TEST(security)
{
    HMODULE hmod;

    hmod = LoadLibraryA("kernelbase.dll");
    pDeriveCapabilitySidsFromName = (void *)GetProcAddress(hmod, "DeriveCapabilitySidsFromName");
    pAppContainerDeriveSidFromMoniker = (void *)GetProcAddress(hmod,
                                                               "AppContainerDeriveSidFromMoniker");
    pAppContainerLookupMoniker = (void *)GetProcAddress(hmod, "AppContainerLookupMoniker");
    pAppContainerLookupDisplayNameMrtReference = (void *)GetProcAddress(hmod,
                                                      "AppContainerLookupDisplayNameMrtReference");
    pAppContainerRegisterSid = (void *)GetProcAddress(hmod, "AppContainerRegisterSid");
    pAppContainerUnregisterSid = (void *)GetProcAddress(hmod, "AppContainerUnregisterSid");
    pAppContainerFreeMemory = (void *)GetProcAddress(hmod, "AppContainerFreeMemory");
    pAccessCheckByType = (void *)GetProcAddress(hmod, "AccessCheckByType");
    pCheckTokenMembershipEx = (void *)GetProcAddress(hmod, "CheckTokenMembershipEx");

    hmod = LoadLibraryA("ntdll.dll");
    pRtlDeriveCapabilitySidsFromName = (void *)GetProcAddress(hmod, "RtlDeriveCapabilitySidsFromName");

    test_DeriveCapabilitySidsFromName();
    test_AccessCheckByType();
    test_CheckTokenMembershipEx();
    test_AppContainerDeriveSidFromMoniker();
    test_AppContainerLookupMoniker();
}
