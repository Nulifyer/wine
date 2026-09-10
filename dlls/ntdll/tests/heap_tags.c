/* Heap-tag creation with instrumentation disabled. */
#include <stdarg.h>
#include "windef.h"
#include "winbase.h"
#include "wincon.h"
#include "winternl.h"
#include "wine/test.h"

START_TEST(heap_tags)
{
    static const WCHAR prefix[] = L"LINUXNT!", names[] = L"ONE\0TWO\0";
    HANDLE heap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
    ULONG original_flags = NtCurrentTeb()->Peb->NtGlobalFlag;
    unsigned int i;
    struct
    {
        HANDLE heap;
        ULONG flags;
        const WCHAR *prefix, *names;
    } cases[] = {
        {NtCurrentTeb()->Peb->ProcessHeap, 0, prefix, names},
        {NtCurrentTeb()->Peb->ProcessHeap, 0, NULL, NULL},
        {heap, 0, prefix, names},
        {NtCurrentTeb()->Peb->ProcessHeap, 1, prefix, names},
        {NULL, 0, prefix, names},
        {heap, 0x80000000, prefix, names}
    };

    ok(!!heap, "private heap creation failed\n");
    if (!heap) return;
    NtCurrentTeb()->Peb->NtGlobalFlag &= ~(FLG_HEAP_ENABLE_TAGGING | FLG_HEAP_ENABLE_TAG_BY_DLL);
    for (i = 0; i < ARRAY_SIZE(cases); i++)
    {
        ULONG tag, error;
        void *allocation;
        SetLastError(0x13579bdf);
        tag = RtlCreateTagHeap(cases[i].heap, cases[i].flags, cases[i].prefix, cases[i].names);
        error = GetLastError();
        ok(!tag, "case %u tag %#lx\n", i, tag);
        ok(error == 0x13579bdf, "case %u last error %#lx\n", i, error);
        if (!cases[i].heap) continue;
        allocation = RtlAllocateHeap(cases[i].heap, tag + 0x40000, 16);
        ok(!!allocation, "case %u tagged allocation failed\n", i);
        if (allocation) ok(RtlFreeHeap(cases[i].heap, 0, allocation), "case %u free failed\n", i);
    }
    NtCurrentTeb()->Peb->NtGlobalFlag = original_flags;
    ok(!RtlDestroyHeap(heap), "private heap destruction failed\n");
}
