/* Tests for out-of-box experience state
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

typedef BOOL (WINAPI *oobe_complete_fn)(BOOL *complete);

START_TEST(oobe)
{
    oobe_complete_fn OOBEComplete;
    BOOL complete, ret;

    OOBEComplete = (void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "OOBEComplete");
    if (!OOBEComplete)
    {
        win_skip("OOBEComplete is unavailable.\n");
        return;
    }

    complete = FALSE;
    SetLastError(0xdeadbeef);
    ret = OOBEComplete(&complete);
    ok(ret, "OOBEComplete failed, error %lu.\n", GetLastError());
    ok(complete, "OOBEComplete returned incomplete state.\n");
    ok(GetLastError() == 0xdeadbeef, "got error %lu.\n", GetLastError());

    complete = TRUE;
    SetLastError(0xdeadbeef);
    ret = OOBEComplete(&complete);
    ok(ret, "OOBEComplete failed, error %lu.\n", GetLastError());
    ok(complete, "OOBEComplete returned incomplete state.\n");
    ok(GetLastError() == 0xdeadbeef, "got error %lu.\n", GetLastError());

    SetLastError(0xdeadbeef);
    ret = OOBEComplete(NULL);
    ok(!ret, "OOBEComplete unexpectedly succeeded.\n");
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "got error %lu.\n", GetLastError());
}
