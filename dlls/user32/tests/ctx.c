/* Tests for private USER32 process initialization entry points. */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"

#include "wine/test.h"

START_TEST(ctx)
{
    BOOL (WINAPI *ctx_init_user32)(void);
    HMODULE user32;

    user32 = GetModuleHandleA( "user32.dll" );
    ok( user32 != NULL, "user32.dll is not loaded\n" );
    if (!user32) return;

    ctx_init_user32 = (void *)GetProcAddress( user32, "CtxInitUser32" );
    ok( ctx_init_user32 != NULL, "CtxInitUser32 is not exported\n" );
    if (!ctx_init_user32) return;

    ok( ctx_init_user32(), "CtxInitUser32 failed\n" );
    ok( ctx_init_user32(), "repeated CtxInitUser32 call failed\n" );
}
