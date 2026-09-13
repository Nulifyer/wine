/*
 * SwitchBack compatibility procedure tests
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "wine/test.h"

#ifdef _WIN64
#define SB_BRANCH_COUNT_OFFSET 0x44
#define SB_BRANCH_OFFSET       0x48
#define SB_BRANCH_SIZE         0x80
#else
#define SB_BRANCH_COUNT_OFFSET 0x30
#define SB_BRANCH_OFFSET       0x34
#define SB_BRANCH_SIZE         0x70
#endif

static void * (WINAPI *pSbSelectProcedure)(ULONG, ULONG, const void *, ULONG);

static void WINAPI legacy_branch(void)
{
}

static void WINAPI current_branch(void)
{
}

static void test_select_procedure(void)
{
    BYTE scenario[SB_BRANCH_OFFSET + 2 * SB_BRANCH_SIZE] = {0};
    struct
    {
        ULONG count;
#ifdef _WIN64
        ULONG padding;
#endif
        void *scenario[1];
    } scenario_list = {1};
    struct
    {
        ULONGLONG module_id;
        ULONG version;
        ULONG scenario_count;
        void *selected[1];
    } module_table = {0, 7, 1};
    struct
    {
        ULONG tag;
        ULONG version;
        void *module_table;
        void *reserved;
        void *scenario_list;
        void *filter;
    } table = {0x45734c6b, 0x01000000};
    void *procedure;

    if (!pSbSelectProcedure)
    {
        win_skip( "SbSelectProcedure is unavailable.\n" );
        return;
    }

    table.module_table = &module_table;
    table.scenario_list = &scenario_list;
    scenario_list.scenario[0] = scenario;
    *(ULONG *)(scenario + SB_BRANCH_COUNT_OFFSET) = 2;
    *(void **)(scenario + SB_BRANCH_OFFSET + sizeof(void *)) = legacy_branch;
    *(void **)(scenario + SB_BRANCH_OFFSET + SB_BRANCH_SIZE + sizeof(void *)) = current_branch;

    procedure = pSbSelectProcedure( 0xabababab, 7, &table, 0 );
    ok( procedure == current_branch, "got procedure %p.\n", procedure );
    ok( module_table.selected[0] == scenario + SB_BRANCH_OFFSET + SB_BRANCH_SIZE,
        "got cached branch %p.\n", module_table.selected[0] );

    procedure = pSbSelectProcedure( 0xabababab, 7, &table, 0 );
    ok( procedure == current_branch, "got cached procedure %p.\n", procedure );
    ok( !pSbSelectProcedure( 0xabababab, 8, &table, 0 ), "version mismatch succeeded.\n" );
    ok( !pSbSelectProcedure( 0xabababab, 7, &table, 1 ), "invalid scenario succeeded.\n" );
    ok( !pSbSelectProcedure( 0xabababab, 7, NULL, 0 ), "null table succeeded.\n" );
}

START_TEST(switchback)
{
    pSbSelectProcedure = (void *)GetProcAddress( GetModuleHandleA( "ntdll.dll" ),
                                                 "SbSelectProcedure" );
    test_select_procedure();
}
