/*
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdlib.h>
#include <windows.h>
#include "wine/test.h"

static BOOL (WINAPI *pCheckTokenMembership)(HANDLE, PSID, PBOOL);

static void check_membership(HANDLE token, PSID sid, BOOL expected, const char *context)
{
    BOOL member = !expected, ret;

    ret = pCheckTokenMembership(token, sid, &member);
    ok(ret, "%s: query failed with error %lu.\n", context, GetLastError());
    ok(member == expected, "%s: got membership %d, expected %d.\n", context, member, expected);
}

START_TEST(security_membership)
{
    SID absent = { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { 0x7fffffff } };
    TOKEN_USER *user = NULL;
    TOKEN_GROUPS *groups = NULL;
    HANDLE primary = NULL, token = NULL, query_token = NULL;
    DWORD size, i;
    BOOL member, ret;

    pCheckTokenMembership = (void *)GetProcAddress(GetModuleHandleA("kernelbase.dll"),
                                                  "CheckTokenMembership");
    ok(!!pCheckTokenMembership, "CheckTokenMembership is missing.\n");
    if (!pCheckTokenMembership) return;

    ret = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &primary);
    ok(ret, "OpenProcessToken failed with error %lu.\n", GetLastError());
    if (!ret) return;
    ret = DuplicateTokenEx(primary, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                           NULL, SecurityImpersonation, TokenImpersonation, &token);
    ok(ret, "DuplicateTokenEx failed with error %lu.\n", GetLastError());
    if (!ret) goto done;

    ret = GetTokenInformation(token, TokenUser, NULL, 0, &size);
    ok(!ret && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "User size query failed.\n");
    user = malloc(size);
    if (!user) goto done;
    ret = GetTokenInformation(token, TokenUser, user, size, &size);
    ok(ret, "User query failed with error %lu.\n", GetLastError());
    if (!ret) goto done;
    ret = GetTokenInformation(token, TokenGroups, NULL, 0, &size);
    ok(!ret && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "Groups size query failed.\n");
    groups = malloc(size);
    if (!groups) goto done;
    ret = GetTokenInformation(token, TokenGroups, groups, size, &size);
    ok(ret, "Groups query failed with error %lu.\n", GetLastError());
    if (!ret) goto done;
    for (i = 0; i < groups->GroupCount; ++i)
        ok(!EqualSid(user->User.Sid, groups->Groups[i].Sid), "User SID is also group %lu.\n", i);

    check_membership(token, user->User.Sid, TRUE, "explicit user SID");
    check_membership(NULL, user->User.Sid, TRUE, "process effective user SID");
    check_membership(token, &absent, FALSE, "absent SID");
    for (i = 0; i < groups->GroupCount; ++i)
        check_membership(token, groups->Groups[i].Sid,
                         !!(groups->Groups[i].Attributes & SE_GROUP_ENABLED), "group SID");

    ret = DuplicateTokenEx(token, TOKEN_QUERY, NULL, SecurityImpersonation,
                           TokenImpersonation, &query_token);
    ok(ret, "Query-only duplicate failed with error %lu.\n", GetLastError());
    if (ret) check_membership(query_token, user->User.Sid, TRUE, "query-only user SID");
    ret = SetThreadToken(NULL, token);
    ok(ret, "SetThreadToken failed with error %lu.\n", GetLastError());
    if (ret)
    {
        check_membership(NULL, user->User.Sid, TRUE, "thread effective user SID");
        ret = RevertToSelf();
        ok(ret, "RevertToSelf failed with error %lu.\n", GetLastError());
    }

    member = TRUE;
    ret = pCheckTokenMembership(primary, user->User.Sid, &member);
    ok(!ret && GetLastError() == ERROR_NO_IMPERSONATION_TOKEN,
       "Primary token returned %d, error %lu.\n", ret, GetLastError());
    ok(!member, "Primary token did not clear membership.\n");
done:
    free(groups);
    free(user);
    if (query_token) CloseHandle(query_token);
    if (token) CloseHandle(token);
    CloseHandle(primary);
}
