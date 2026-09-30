/*
 * Explicit AppModel state-space identity, outputs and lifetime.
 * Copyright 2026 LinuxNT contributors
 * LGPL version 2.1 or later.
 */
#include <stdarg.h>
#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "winerror.h"
#include "sddl.h"
#include "wine/test.h"
#include <stdio.h>

static void *(WINAPI *open_state)(HANDLE, const WCHAR *);
static BOOL (WINAPI *close_state)(void *);
static BOOL (WINAPI *get_key)(void *, HKEY *, WCHAR *, UINT32 *);
static const WCHAR family[] = L"LinuxNT.StateSpace_cw5n1h2txyewy";
static const WCHAR suffix[] = L"\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\SystemAppData\\";

static void test_invalid(HANDLE token)
{
    static const struct { const char *label; const WCHAR *family; } families[] =
    {
        {"null", NULL}, {"empty", L""}, {"separator", L"missing"},
        {"short", L"ab_cw5n1h2txyewy"}, {"publisher", L"Valid_invalid"},
        {"path", L"Valid\\path_cw5n1h2txyewy"},
    };
    static const struct { const char *label; HANDLE token; DWORD error; } tokens[] =
    {
        {"null", NULL, ERROR_INVALID_PARAMETER},
        {"process", (HANDLE)(LONG_PTR)-1, ERROR_INVALID_HANDLE},
        {"unknown", (HANDLE)(ULONG_PTR)0xdeadbeef, ERROR_INVALID_HANDLE},
    };
    unsigned int i;
    void *state;
    HANDLE restricted;
    HKEY key = (HKEY)(ULONG_PTR)0xdeadbeef;
    WCHAR buffer[4] = {0xcccc,0xcccc,0xcccc,0xcccc};
    UINT32 length = ARRAY_SIZE(buffer);
    BOOL ret;
    DWORD error, close_error;
    BOOL precedence_matches, close_ret;

    for (i = 0; i < ARRAY_SIZE(families); ++i)
    {
        SetLastError(0xdeadbeef);
        state = open_state(token, families[i].family);
        error = GetLastError();
        ok(!state && error == ERROR_INVALID_PARAMETER, "%s open %p/%lu\n", families[i].label, state, error);
        trace("state-invalid family=%s result=%u error=%lu\n", families[i].label, !!state, error);
        if (state) close_state(state);
    }
    for (i = 0; i < ARRAY_SIZE(tokens); ++i)
    {
        SetLastError(0xdeadbeef);
        state = open_state(tokens[i].token, family);
        error = GetLastError();
        ok(!state && error == tokens[i].error, "%s token %p/%lu\n", tokens[i].label, state, error);
        trace("state-invalid token=%s result=%u error=%lu\n", tokens[i].label, !!state, error);
        if (state) close_state(state);
    }
    ret = DuplicateTokenEx(token, TOKEN_IMPERSONATE, NULL, SecurityImpersonation, TokenImpersonation, &restricted);
    ok(ret, "restricted token %lu\n", GetLastError());
    if (ret)
    {
        SetLastError(0xdeadbeef);
        state = open_state(restricted, family); error = GetLastError();
        ok(!state && error == ERROR_ACCESS_DENIED, "token without query %p/%lu\n", state, error);
        trace("state-invalid token=no-query result=%u error=%lu\n", !!state, error);
        if (state) close_state(state);
        CloseHandle(restricted);
        SetLastError(0xdeadbeef);
        state = open_state(restricted, family); error = GetLastError();
        ok(!state && error == ERROR_INVALID_HANDLE, "closed token %p/%lu\n", state, error);
        trace("state-invalid token=closed result=%u error=%lu\n", !!state, error);
        if (state) close_state(state);
    }
    SetLastError(0xdeadbeef);
    state = open_state((HANDLE)(LONG_PTR)-1, NULL);
    error = GetLastError();
    precedence_matches = !state && error == ERROR_INVALID_HANDLE;
    ok(precedence_matches, "token/family precedence %p/%lu\n", state, error);
    SetLastError(0xdeadbeef);
    close_ret = close_state(NULL);
    close_error = GetLastError();
    ok(!close_ret && close_error == ERROR_INVALID_HANDLE, "null close %u/%lu\n", close_ret, close_error);
    SetLastError(0xdeadbeef);
    ret = get_key(NULL, &key, buffer, &length);
    error = GetLastError();
    ok(!ret && error == ERROR_INVALID_HANDLE, "null key %u/%lu\n", ret, error);
    ok(key == (HKEY)(ULONG_PTR)0xdeadbeef && length == ARRAY_SIZE(buffer) && buffer[0] == 0xcccc,
            "invalid key changed outputs %p/%u/%x\n", key, length, buffer[0]);
    trace("state-invalid precedence=%u close=%u close_error=%lu key_error=%lu outputs_unchanged=%u\n",
            precedence_matches, close_ret, close_error, error,
            key == (HKEY)(ULONG_PTR)0xdeadbeef && length == ARRAY_SIZE(buffer) && buffer[0] == 0xcccc);
}

static void test_outputs(void *state, const WCHAR *sid)
{
    WCHAR expected[512], buffer[512], short_buffer[4];
    UINT32 length, required;
    HKEY key, check;
    BOOL ret;
    DWORD error, probe_error;
    BOOL short_unchanged = TRUE;
    unsigned int i;

    lstrcpyW(expected, sid); lstrcatW(expected, suffix); lstrcatW(expected, family);
    required = lstrlenW(expected) + 1;
    key = (HKEY)(ULONG_PTR)0xdeadbeef;
    length = 0;
    SetLastError(0xdeadbeef);
    ret = get_key(state, &key, NULL, &length);
    error = GetLastError();
    probe_error = error;
    ok(!ret && error == ERROR_INSUFFICIENT_BUFFER, "size probe %u/%lu\n", ret, error);
    ok(length == required && key == (HKEY)(ULONG_PTR)0xdeadbeef, "size outputs %u/%p\n", length, key);
    for (i = 0; i < ARRAY_SIZE(short_buffer); ++i) short_buffer[i] = 0xcccc;
    length = ARRAY_SIZE(short_buffer);
    ret = get_key(state, &key, short_buffer, &length);
    error = GetLastError();
    ok(!ret && error == ERROR_INSUFFICIENT_BUFFER, "short buffer %u/%lu\n", ret, error);
    ok(length == required && key == (HKEY)(ULONG_PTR)0xdeadbeef, "short outputs %u/%p\n", length, key);
    for (i = 0; i < ARRAY_SIZE(short_buffer); ++i)
    {
        ok(short_buffer[i] == 0xcccc, "short buffer[%u] changed\n", i);
        short_unchanged &= short_buffer[i] == 0xcccc;
    }
    length = 1;
    ret = get_key(state, &key, NULL, &length);
    error = GetLastError();
    ok(!ret && error == ERROR_INVALID_PARAMETER, "null nonzero buffer %u/%lu\n", ret, error);
    ok(length == 1 && key == (HKEY)(ULONG_PTR)0xdeadbeef, "invalid buffer outputs %u/%p\n", length, key);
    ret = get_key(state, &key, buffer, NULL);
    error = GetLastError();
    ok(!ret && error == ERROR_INVALID_PARAMETER, "null length %u/%lu\n", ret, error);
    ok(key == (HKEY)(ULONG_PTR)0xdeadbeef, "null length changed key %p\n", key);
    length = required - 1;
    buffer[0] = 0xcccc;
    ret = get_key(state, &key, buffer, &length);
    error = GetLastError();
    ok(!ret && error == ERROR_INSUFFICIENT_BUFFER && length == required && buffer[0] == 0xcccc,
            "one-short output %u/%lu/%u/%x\n", ret, error, length, buffer[0]);
    length = required;
    SetLastError(0xdeadbeef);
    ret = get_key(state, &key, buffer, &length);
    error = GetLastError();
    ok(ret && error == ERROR_SUCCESS, "exact output %u/%lu\n", ret, error);
    ok(length == required && !lstrcmpW(buffer, expected), "path %s expected %s, length %u\n",
            wine_dbgstr_w(buffer), wine_dbgstr_w(expected), length);
    ok(key == HKEY_USERS, "root key %p\n", key);
    length = ARRAY_SIZE(buffer);
    SetLastError(0xdeadbeef);
    ret = get_key(state, NULL, buffer, &length);
    error = GetLastError();
    ok(ret && error == ERROR_SUCCESS && length == required && !lstrcmpW(buffer, expected),
            "optional key output %u/%lu/%u\n", ret, error, length);
    ret = RegOpenKeyExW(key, sid, 0, KEY_READ, &check) == ERROR_SUCCESS;
    ok(ret, "returned predefined root does not resolve supplied token user\n");
    if (ret) RegCloseKey(check);
    trace("state-key probe_error=%lu short_untouched=%u path_matches=%u root_matches=%u suffix_chars=%u\n",
            probe_error, short_unchanged, !lstrcmpW(buffer, expected), key == HKEY_USERS, required - lstrlenW(sid));
}

START_TEST(state_space)
{
    HMODULE module = GetModuleHandleA("kernelbase.dll");
    HANDLE token, duplicate;
    DWORD size, error, appcontainer;
    TOKEN_USER *user;
    WCHAR *sid, mutable_family[ARRAY_SIZE(family)];
    void *first, *second;
    BOOL ret;

    open_state = (void *)GetProcAddress(module, "OpenStateExplicit");
    close_state = (void *)GetProcAddress(module, "CloseState");
    get_key = (void *)GetProcAddress(module, "GetSystemAppDataKey");
    ok(!!open_state && !!close_state && !!get_key, "state-space exports missing\n");
    if (!open_state || !close_state || !get_key) return;
    ret = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &token);
    ok(ret, "process token %lu\n", GetLastError());
    if (!ret) return;
    ret = GetTokenInformation(token, TokenIsAppContainer, &appcontainer, sizeof(appcontainer), &size);
    ok(ret && !appcontainer, "fixture requires non-AppContainer caller, result %u flag %lu error %lu\n",
            ret, appcontainer, GetLastError());
    if (!ret || appcontainer) { CloseHandle(token); return; }
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    user = HeapAlloc(GetProcessHeap(), 0, size);
    ok(!!user, "token buffer allocation\n");
    if (!user) { CloseHandle(token); return; }
    ret = GetTokenInformation(token, TokenUser, user, size, &size);
    ok(ret, "token user %lu\n", GetLastError());
    if (!ret) goto done;
    ret = ConvertSidToStringSidW(user->User.Sid, &sid);
    ok(ret, "SID string %lu\n", GetLastError());
    if (!ret) goto done;
    trace("state-actor sid=%s\n", wine_dbgstr_w(sid));
    test_invalid(token);
    ret = DuplicateTokenEx(token, TOKEN_QUERY, NULL, SecurityImpersonation, TokenImpersonation, &duplicate);
    ok(ret, "duplicate token %lu\n", GetLastError());
    if (!ret) goto free_sid;
    lstrcpyW(mutable_family, family);
    SetLastError(0xdeadbeef);
    first = open_state(duplicate, mutable_family);
    error = GetLastError();
    ok(!!first && error == ERROR_SUCCESS, "open duplicate %p/%lu\n", first, error);
    CloseHandle(duplicate);
    mutable_family[0] = L'X';
    SetLastError(0xdeadbeef);
    second = open_state((HANDLE)(LONG_PTR)-6, family);
    error = GetLastError();
    ok(!!second && error == ERROR_SUCCESS, "open effective token %p/%lu\n", second, error);
    ok(!first || !second || first != second, "state objects share lifetime\n");
    if (first) test_outputs(first, sid);
    if (first)
    {
        SetLastError(0xdeadbeef);
        ret = close_state(first); error = GetLastError();
        ok(ret && !error, "first close %u/%lu\n", ret, error);
    }
    if (second)
    {
        test_outputs(second, sid);
        SetLastError(0xdeadbeef);
        ret = close_state(second); error = GetLastError();
        ok(ret && !error, "second close %u/%lu\n", ret, error);
    }
    ret = GetTokenInformation(token, TokenUser, user, size, &size);
    ok(ret, "state close consumed caller token %lu\n", GetLastError());
    trace("state-lifetime independent=%u token_survives=%u input_snapshot=1\n", first != second, ret);
free_sid:
    LocalFree(sid);
done:
    HeapFree(GetProcessHeap(), 0, user);
    CloseHandle(token);
}
