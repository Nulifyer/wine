/*
 * Counted environment mutation tests
 *
 * Copyright 2026 LinuxNT contributors
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
 */
#include <stdarg.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "wincon.h"
#include "winternl.h"
#include "wine/test.h"

static NTSTATUS (WINAPI *set_var)(WCHAR **, const WCHAR *, SIZE_T, const WCHAR *, SIZE_T);

static void check_set( WCHAR **env, const WCHAR *name, SIZE_T nl, const WCHAR *value, SIZE_T vl,
                       NTSTATUS expected )
{
    NTSTATUS status;
    SetLastError(0x12345678);
    status = set_var(env, name, nl, value, vl);
    ok(status == expected, "Status %#lx, expected %#lx.\n", status, expected);
    ok(GetLastError() == 0x12345678, "Last error %#lx.\n", GetLastError());
}

static void check_value( WCHAR *env, const WCHAR *name, const WCHAR *value )
{
    WCHAR buffer[128];
    SIZE_T length = 0;
    NTSTATUS status = RtlQueryEnvironmentVariable(env, name, wcslen(name), buffer, ARRAY_SIZE(buffer), &length);
    ok(status == (value ? STATUS_SUCCESS : STATUS_VARIABLE_NOT_FOUND), "Query status %#lx.\n", status);
    if (value && !status)
    {
        ok(length == wcslen(value), "Length %Iu, expected %Iu.\n", length, wcslen(value));
        ok(!wcscmp(buffer, value), "Unexpected value %s.\n", wine_dbgstr_w(buffer));
    }
}

START_TEST(environment_var)
{
    static const struct { const WCHAR *name; SIZE_T nl; const WCHAR *value; SIZE_T vl; } invalid[] = {
        {L"",0,L"x",1}, {NULL,0,L"x",1}, {L"a=b",3,L"x",1},
        {L"a\0b",3,L"x",1}, {L"foo",3,L"a\0b",3}, {L"",1,L"x",1}
    };
    static const WCHAR process_name[] = L"LinuxNT_CountEnvironment_Probe_20260908";
    WCHAR *env, *large;
    unsigned int i;
    NTSTATUS status;

    set_var = (void *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlSetEnvironmentVar");
    ok(!!set_var, "Required export missing.\n");
    if (!set_var) return;
    status = RtlCreateEnvironment(FALSE, &env);
    ok(!status, "Create %#lx.\n", status);
    if (status) return;
    check_set(&env,L"sentinel",8,L"keep",4,0);
    check_set(&env,L"fooX",3,L"barX",3,0);
    check_value(env,L"foo",L"bar");
    check_set(&env,L"FOO",3,L"longer",6,0);
    check_value(env,L"foo",L"longer");
    check_set(&env,L"foo",3,L"x",1,0);
    check_value(env,L"FOO",L"x");
    check_set(&env,L"foo",3,L"",0,0);
    check_value(env,L"foo",L"");
    for (i=0;i<ARRAY_SIZE(invalid);++i)
    {
        winetest_push_context("invalid=%u",i);
        check_set(&env,invalid[i].name,invalid[i].nl,invalid[i].value,invalid[i].vl,STATUS_INVALID_PARAMETER);
        check_value(env,L"sentinel",L"keep");
        check_value(env,L"foo",L"");
        winetest_pop_context();
    }
    check_set(&env,L"foo",3,NULL,99,0);
    check_value(env,L"foo",NULL);
    check_set(&env,L"foo",3,NULL,0,0);
    check_value(env,L"foo",NULL);
    check_set(&env,L"=C:",3,L"C:\\",3,0);
    check_value(env,L"=C:",L"C:\\");
    check_value(env,L"sentinel",L"keep");
    ok(!RtlDestroyEnvironment(env), "Destroy failed.\n");

    env = NULL;
    check_set(&env,L"foo",3,L"bar",3,0);
    ok(!!env, "No allocated block.\n");
    if (env) { check_value(env,L"foo",L"bar"); RtlDestroyEnvironment(env); }
    large = HeapAlloc(GetProcessHeap(),0,40001 * sizeof(WCHAR));
    ok(!!large, "Allocation failed.\n");
    if (!large) return;
    for(i=0;i<40000;++i) large[i]='x';
    large[40000]=0;
    env=NULL;
    check_set(&env,L"long",4,large,40000,0);
    if(env)
    {
        ok(wcslen(env)==40005, "Long value truncated to %Iu.\n",wcslen(env));
        ok(!wcscmp(env+5,large), "Long value changed.\n");
        check_set(&env,L"long",4,NULL,0,0);
        ok(!*env, "Delete did not empty block.\n");
        RtlDestroyEnvironment(env);
    }
    env=NULL;
    check_set(&env,large,40000,L"v",1,0);
    if(env)
    {
        ok(wcslen(env)==40002 && env[40000]=='=' && env[40001]=='v', "Long name truncated.\n");
        check_set(&env,large,40000,L"updated",7,0);
        ok(wcslen(env)==40008 && !wcscmp(env+40001,L"updated"), "Long-name replacement failed.\n");
        check_set(&env,large,40000,NULL,0,0);
        ok(!*env, "Long-name deletion failed.\n");
        RtlDestroyEnvironment(env);
    }
    HeapFree(GetProcessHeap(),0,large);
    check_value(NULL,process_name,NULL);
    check_set(NULL,process_name,wcslen(process_name),L"process",7,0);
    check_value(NULL,process_name,L"process");
    check_set(NULL,process_name,wcslen(process_name),NULL,0,0);
    check_value(NULL,process_name,NULL);
}
