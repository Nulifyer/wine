/*
 * System power capability output initialization
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

static NTSTATUS (WINAPI *pNtPowerInformation)(POWER_INFORMATION_LEVEL, void *, ULONG, void *, ULONG);

static void test_capability_output(void)
{
    struct
    {
        SYSTEM_POWER_CAPABILITIES caps;
        BYTE guard[16];
    } outputs[2];
    BYTE short_buffer[sizeof(SYSTEM_POWER_CAPABILITIES)];
    const BYTE patterns[] = {0, 0xa5};
    NTSTATUS status;
    unsigned int i, j;

    C_ASSERT(sizeof(SYSTEM_POWER_CAPABILITIES) == 76);
    C_ASSERT(offsetof(SYSTEM_POWER_CAPABILITIES, spare2) + 3 == 20); /* modern AoAc field */
    for (i = 0; i < ARRAY_SIZE(outputs); ++i)
    {
        memset(&outputs[i], patterns[i], sizeof(outputs[i]));
        status = pNtPowerInformation(SystemPowerCapabilities, NULL, 0, &outputs[i].caps,
                                    i ? sizeof(outputs[i]) : sizeof(outputs[i].caps));
        ok(status == STATUS_SUCCESS, "pattern %#x: status %#lx\n", patterns[i], status);
        for (j = 0; j < sizeof(outputs[i].guard); ++j)
            ok(outputs[i].guard[j] == patterns[i], "pattern %#x: guard %u changed to %#x\n",
               patterns[i], j, outputs[i].guard[j]);
    }
    for (i = 0; i < sizeof(outputs[0].caps); ++i)
        ok(((BYTE *)&outputs[0].caps)[i] == ((BYTE *)&outputs[1].caps)[i],
           "capability byte %u depends on caller contents: %#x / %#x\n", i,
           ((BYTE *)&outputs[0].caps)[i], ((BYTE *)&outputs[1].caps)[i]);

    /* Wine currently exposes no connected-standby platform. The capability
     * query must agree with that model without depending on preinitialization. */
    if (!strcmp(winetest_platform, "wine"))
        for (i = 0; i < ARRAY_SIZE(outputs); ++i)
            ok(!outputs[i].caps.spare2[3], "pattern %#x: AoAc is %#x\n",
               patterns[i], outputs[i].caps.spare2[3]);

    memset(short_buffer, 0x5a, sizeof(short_buffer));
    status = pNtPowerInformation(SystemPowerCapabilities, NULL, 0, short_buffer, sizeof(short_buffer) - 1);
    ok(status == STATUS_BUFFER_TOO_SMALL, "short buffer: status %#lx\n", status);
    for (i = 0; i < sizeof(short_buffer); ++i)
        ok(short_buffer[i] == 0x5a, "short buffer byte %u changed to %#x\n", i, short_buffer[i]);
}

START_TEST(power_capabilities)
{
    pNtPowerInformation = (void *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtPowerInformation");
    if (!pNtPowerInformation)
    {
        win_skip("NtPowerInformation unavailable\n");
        return;
    }
    test_capability_output();
}
