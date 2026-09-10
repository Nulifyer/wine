/* Process and thread critical-state ownership tests. */
#include <stdarg.h>
#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "wincon.h"
#include "winternl.h"
#include "wine/test.h"

static DWORD WINAPI observer(void *arg)
{
    ULONG value = 0xcccccccc, size = 0;
    NTSTATUS status;

    status = NtQueryInformationProcess(NtCurrentProcess(), ProcessBreakOnTermination,
                                      &value, sizeof(value), &size);
    ok(!status && value == 1 && size == sizeof(value),
       "process state %lx, %lu, %lu\n", status, value, size);
    value = 0xcccccccc;
    status = NtQueryInformationThread(NtCurrentThread(), ThreadBreakOnTermination,
                                     &value, sizeof(value), &size);
    ok(!status && !value, "observer thread state %lx, %lu\n", status, value);
    value = 0;
    status = NtQueryInformationThread(arg, ThreadBreakOnTermination, &value, sizeof(value), NULL);
    ok(!status && value == 1, "creator thread state %lx, %lu\n", status, value);
    return 0;
}

START_TEST(critical)
{
    BOOLEAN previous, ignored, old;
    ULONG value, original_flags = NtCurrentTeb()->Peb->NtGlobalFlag;
    HANDLE thread, self = NULL;
    NTSTATUS status;

    status = RtlAdjustPrivilege(20, TRUE, FALSE, &previous);
    if (status) { skip("SeDebugPrivilege unavailable: %lx\n", status); return; }
    NtCurrentTeb()->Peb->NtGlobalFlag &= ~FLG_ENABLE_SYSTEM_CRIT_BREAKS;
    status = RtlSetProcessIsCritical(2, &old, FALSE);
    ok(!status && !old, "enable process %lx, %u\n", status, old);
    status = RtlSetThreadIsCritical(2, &old, FALSE);
    ok(!status && !old, "enable thread %lx, %u\n", status, old);
    status = NtDuplicateObject(NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(),
                               &self, THREAD_QUERY_INFORMATION, 0, 0);
    ok(!status, "duplicate %lx\n", status);
    thread = CreateThread(NULL, 0, observer, self, 0, NULL);
    ok(!!thread, "CreateThread failed %lu\n", GetLastError());
    if (thread)
    {
        ok(WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0, "observer did not exit\n");
        CloseHandle(thread);
    }
    if (self) NtClose(self);

    old = 0xcc;
    status = RtlSetThreadIsCritical(FALSE, &old, TRUE);
    ok(status == STATUS_UNSUCCESSFUL && !old, "flag rejection %lx, %u\n", status, old);
    status = RtlAdjustPrivilege(20, FALSE, FALSE, &ignored);
    ok(!status, "disable privilege %lx\n", status);
    status = RtlSetProcessIsCritical(FALSE, &old, FALSE);
    ok(status == STATUS_PRIVILEGE_NOT_HELD && old == 1, "process rejection %lx, %u\n", status, old);
    status = RtlSetThreadIsCritical(FALSE, &old, FALSE);
    ok(status == STATUS_PRIVILEGE_NOT_HELD && old == 1, "thread rejection %lx, %u\n", status, old);
    status = NtQueryInformationProcess(NtCurrentProcess(), ProcessBreakOnTermination,
                                      &value, sizeof(value), NULL);
    ok(!status && value == 1, "process changed after rejection %lx, %lu\n", status, value);
    status = NtQueryInformationThread(NtCurrentThread(), ThreadBreakOnTermination,
                                     &value, sizeof(value), NULL);
    ok(!status && value == 1, "thread changed after rejection %lx, %lu\n", status, value);
    status = RtlAdjustPrivilege(20, TRUE, FALSE, &ignored);
    ok(!status, "enable privilege %lx\n", status);
    status = RtlSetThreadIsCritical(FALSE, &old, FALSE);
    ok(!status && old == 1, "clear thread %lx, %u\n", status, old);
    status = RtlSetProcessIsCritical(FALSE, &old, FALSE);
    ok(!status && old == 1, "clear process %lx, %u\n", status, old);
    status = RtlSetProcessIsCritical(FALSE, &old, FALSE);
    ok(!status && !old, "process cleared %lx, %u\n", status, old);
    status = RtlSetThreadIsCritical(FALSE, &old, FALSE);
    ok(!status && !old, "thread cleared %lx, %u\n", status, old);
    NtCurrentTeb()->Peb->NtGlobalFlag = original_flags;
    status = RtlAdjustPrivilege(20, previous, FALSE, &ignored);
    ok(!status, "restore privilege %lx\n", status);
}
