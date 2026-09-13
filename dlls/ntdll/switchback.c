/*
 * SwitchBack compatibility procedure selection
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
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(ntdll);

#ifdef _WIN64
#define SB_SCENARIO_LIST_OFFSET 0x18
#define SB_BRANCH_COUNT_OFFSET  0x44
#define SB_BRANCH_OFFSET        0x48
#define SB_BRANCH_SIZE          0x80
#else
#define SB_SCENARIO_LIST_OFFSET 0x10
#define SB_BRANCH_COUNT_OFFSET  0x30
#define SB_BRANCH_OFFSET        0x34
#define SB_BRANCH_SIZE          0x70
#endif

static void *sb_read_pointer( const BYTE *address )
{
    return *(void * const *)address;
}

/***********************************************************************
 *             SbSelectProcedure  (NTDLL.@)
 *
 * SwitchBack tables put compatibility procedures first and the current
 * implementation last. Wine does not expose a Windows shim-data context, so
 * select and cache the current implementation from the caller-owned table.
 */
void * WINAPI SbSelectProcedure( ULONG signature, ULONG version, const void *opaque_table,
                                 ULONG scenario_index )
{
    const BYTE *table = opaque_table, *module_table, *scenario_list, *scenario, *branch;
    void **cache;
    ULONG branch_count;

    TRACE( "(%#lx,%lu,%p,%lu)\n", signature, version, opaque_table, scenario_index );

    if (!table) return NULL;
    module_table = sb_read_pointer( table + 8 );
    scenario_list = sb_read_pointer( table + SB_SCENARIO_LIST_OFFSET );
    if (!module_table || !scenario_list) return NULL;
    if (*(const ULONG *)(module_table + 8) != version) return NULL;
    if (scenario_index >= *(const ULONG *)(module_table + 12) ||
        scenario_index >= *(const ULONG *)scenario_list) return NULL;

    cache = (void **)(module_table + 16) + scenario_index;
    if (*cache) return sb_read_pointer( (const BYTE *)*cache + sizeof(void *) );

    scenario = sb_read_pointer( scenario_list + sizeof(void *) * (scenario_index + 1) );
    if (!scenario) return NULL;
    branch_count = *(const ULONG *)(scenario + SB_BRANCH_COUNT_OFFSET);
    if (!branch_count) return NULL;

    branch = scenario + SB_BRANCH_OFFSET + (branch_count - 1) * SB_BRANCH_SIZE;
    *cache = (void *)branch;
    return sb_read_pointer( branch + sizeof(void *) );
}
