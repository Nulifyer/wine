/*
 * WoW64 DirectComposition win32u calls
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "wow64win_private.h"

extern NTSTATUS WINAPI NtCloseCompositionInputSink(HANDLE sink);
extern NTSTATUS WINAPI NtCreateCompositionInputSink(const void *descriptor, HANDLE *sink);
extern NTSTATUS WINAPI NtDCompositionCreateChannel(UINT *channel_id, UINT *section_size, void **mapping);
extern NTSTATUS WINAPI NtDCompositionGetBatchId(UINT channel_id, UINT type, UINT *batch_id);
extern NTSTATUS WINAPI NtDCompositionGetFrameStatistics(void *statistics, void *private_statistics);
extern NTSTATUS WINAPI NtDCompositionProcessChannelBatchBuffer(UINT channel_id, UINT size,
                                                                UINT *processed, BYTE *pending);
extern NTSTATUS WINAPI NtDCompositionSetChannelConnectionId(UINT channel_id);
extern NTSTATUS WINAPI NtQueryCompositionInputSinkLuid(HANDLE sink, LUID *luid);

NTSTATUS WINAPI wow64_NtCloseCompositionInputSink(UINT *args)
{
    HANDLE sink = get_handle(&args);

    return NtCloseCompositionInputSink(sink);
}

NTSTATUS WINAPI wow64_NtCreateCompositionInputSink(UINT *args)
{
    const void *descriptor = get_ptr(&args);
    ULONG *sink32 = get_ptr(&args);
    HANDLE sink;
    NTSTATUS status;

    status = NtCreateCompositionInputSink(descriptor, sink32 ? &sink : NULL);
    if (!status && sink32) *sink32 = HandleToUlong(sink);
    return status;
}

NTSTATUS WINAPI wow64_NtDCompositionCreateChannel(UINT *args)
{
    UINT *channel_id = get_ptr(&args);
    UINT *section_size = get_ptr(&args);
    ULONG *mapping32 = get_ptr(&args);
    void *mapping;
    NTSTATUS status;

    status = NtDCompositionCreateChannel(channel_id, section_size, mapping32 ? &mapping : NULL);
    if (!status && mapping32) put_addr(mapping32, mapping);
    return status;
}

NTSTATUS WINAPI wow64_NtDCompositionGetBatchId(UINT *args)
{
    UINT channel_id = get_ulong(&args);
    UINT type = get_ulong(&args);
    UINT *batch_id = get_ptr(&args);

    return NtDCompositionGetBatchId(channel_id, type, batch_id);
}

NTSTATUS WINAPI wow64_NtDCompositionGetFrameStatistics(UINT *args)
{
    void *statistics = get_ptr(&args);
    void *private_statistics = get_ptr(&args);

    return NtDCompositionGetFrameStatistics(statistics, private_statistics);
}

NTSTATUS WINAPI wow64_NtDCompositionProcessChannelBatchBuffer(UINT *args)
{
    UINT channel_id = get_ulong(&args);
    UINT size = get_ulong(&args);
    UINT *processed = get_ptr(&args);
    BYTE *pending = get_ptr(&args);

    return NtDCompositionProcessChannelBatchBuffer(channel_id, size, processed, pending);
}

NTSTATUS WINAPI wow64_NtDCompositionSetChannelConnectionId(UINT *args)
{
    UINT channel_id = get_ulong(&args);

    return NtDCompositionSetChannelConnectionId(channel_id);
}

NTSTATUS WINAPI wow64_NtQueryCompositionInputSinkLuid(UINT *args)
{
    HANDLE sink = get_handle(&args);
    LUID *luid = get_ptr(&args);

    return NtQueryCompositionInputSinkLuid(sink, luid);
}
