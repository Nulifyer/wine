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

static NTSTATUS (WINAPI *pRtlDeriveCapabilitySidsFromName)(UNICODE_STRING *, PSID, PSID);

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

    hmod = LoadLibraryA("ntdll.dll");
    pRtlDeriveCapabilitySidsFromName = (void *)GetProcAddress(hmod, "RtlDeriveCapabilitySidsFromName");

    test_DeriveCapabilitySidsFromName();
    test_AppContainerDeriveSidFromMoniker();
    test_AppContainerLookupMoniker();
}
