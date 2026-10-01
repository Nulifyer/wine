/* DirectComposition win32u calls
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#if 0
#pragma makedep unix
#endif

#include <limits.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "win32u_private.h"
#include "dcomptypes.h"
#include "winternl.h"

WINE_DEFAULT_DEBUG_CHANNEL(dcomp);

/* The second structure is private to win32k. dcomp.dll currently consumes its
 * first three 64-bit fields only as optional compositor details. Keeping those
 * fields zero is the native headless/fallback shape and is preferable to
 * aborting the process at the syscall boundary. */
struct dcomposition_private_frame_statistics
{
    ULONGLONG values[3];
};

static LONG next_channel_id;
static BYTE *last_channel_mapping;
static UINT last_channel_id;

/***********************************************************************
 *           NtCreateCompositionInputSink (win32u.@)
 *
 * The native object belongs to win32k's composition-input router. Wine's
 * input path does not use that router, but InputHost needs a closeable opaque
 * handle and a stable LUID while it creates a CoreWindow input site.
 */
NTSTATUS WINAPI NtCreateCompositionInputSink(const void *descriptor, HANDLE *sink)
{
    const DWORD *size = descriptor;
    NTSTATUS status;

    TRACE("descriptor %p, sink %p.\n", descriptor, sink);
    if (!descriptor || !sink || *size < sizeof(*size)) return STATUS_INVALID_PARAMETER;

    *sink = NULL;
    status = NtCreateEvent(sink, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
    TRACE("created sink %p, descriptor size %#x, status %#x.\n",
          *sink, *size, (UINT)status);
    return status;
}

/***********************************************************************
 *           NtQueryCompositionInputSinkLuid (win32u.@)
 */
NTSTATUS WINAPI NtQueryCompositionInputSinkLuid(HANDLE sink, LUID *luid)
{
    OBJECT_BASIC_INFORMATION info;
    NTSTATUS status;

    TRACE("sink %p, luid %p.\n", sink, luid);
    if (!luid) return STATUS_INVALID_PARAMETER;
    if ((status = NtQueryObject(sink, ObjectBasicInformation, &info, sizeof(info), NULL)))
        return status;

    luid->LowPart = HandleToULong(sink);
    luid->HighPart = HandleToLong(NtCurrentTeb()->ClientId.UniqueProcess);
    return STATUS_SUCCESS;
}

/***********************************************************************
 *           NtCloseCompositionInputSink (win32u.@)
 */
NTSTATUS WINAPI NtCloseCompositionInputSink(HANDLE sink)
{
    TRACE("sink %p.\n", sink);
    return NtClose(sink);
}

static UINT dcomposition_command_size(const BYTE *command, UINT remaining)
{
    const UINT *words = (const UINT *)command;
    UINT count, size;

    if (remaining < sizeof(*words)) return 0;

    switch (words[0])
    {
    case 1:
    case 4:
        return 8;
    case 2:
    case 5:
    case 9:
    case 12:
    case 16:
    case 18:
    case 19:
    case 22:
        return 16;
    case 3:
    case 6:
    case 7:
    case 11:
    case 13:
        return 24;
    case 8:
    case 10:
    case 23:
        return 12;
    case 14:
        if (remaining < 16) return 0;
        count = words[3];
        if (count > (UINT_MAX - 16) / 8) return 0;
        return 16 + count * 8;
    case 15:
        if (remaining < 16) return 0;
        count = words[3];
        if (count > UINT_MAX - 3) return 0;
        size = (count + 3) & ~3u;
        if (size > UINT_MAX - 16) return 0;
        return 16 + size;
    case 17:
        if (remaining < 16) return 0;
        count = words[3];
        if (count > (UINT_MAX - 16) / 4) return 0;
        return 16 + count * 4;
    case 20:
        return 20;
    case 21:
        return 72;
    default:
        return 0;
    }
}

static UINT dcomposition_count_commands(const BYTE *commands, UINT size)
{
    UINT count = 0, offset = 0, command_size;

    while (offset < size)
    {
        command_size = dcomposition_command_size(commands + offset, size - offset);
        TRACE("command %u id %u size %u remaining %u words %08x %08x %08x %08x %08x %08x.\n",
              count, *(const UINT *)(commands + offset), command_size, size - offset,
              ((const UINT *)(commands + offset))[0],
              size - offset >= 8 ? ((const UINT *)(commands + offset))[1] : 0,
              size - offset >= 12 ? ((const UINT *)(commands + offset))[2] : 0,
              size - offset >= 16 ? ((const UINT *)(commands + offset))[3] : 0,
              size - offset >= 20 ? ((const UINT *)(commands + offset))[4] : 0,
              size - offset >= 24 ? ((const UINT *)(commands + offset))[5] : 0);
        if (!command_size || command_size > size - offset) return 0;
        offset += command_size;
        ++count;
    }
    return count;
}
/***********************************************************************
 *           NtDCompositionCreateChannel (win32u.@)
 */
NTSTATUS WINAPI NtDCompositionCreateChannel(UINT *channel_id, UINT *section_size, void **mapping)
{
    HANDLE section = 0;
    LARGE_INTEGER size;
    SIZE_T view_size;
    NTSTATUS status;

    TRACE("channel_id %p, section_size %p, mapping %p.\n", channel_id, section_size, mapping);

    if (!channel_id || !section_size || !mapping || !*section_size)
        return STATUS_INVALID_PARAMETER;

    size.QuadPart = *section_size;
    view_size = *section_size;
    *channel_id = 0;
    *mapping = NULL;
    status = NtCreateSection(&section, SECTION_QUERY | SECTION_MAP_READ | SECTION_MAP_WRITE,
                             NULL, &size, PAGE_READWRITE, SEC_COMMIT, 0);
    if (status) return status;

    status = NtMapViewOfSection(section, NtCurrentProcess(), mapping, 0, 0, NULL,
                                &view_size, ViewUnmap, 0, PAGE_READWRITE);
    NtClose(section);
    if (status) return status;

    *section_size = view_size;
    *channel_id = InterlockedIncrement(&next_channel_id);
    last_channel_mapping = *mapping;
    last_channel_id = *channel_id;
    TRACE("created channel %u, size %u, mapping %p.\n", *channel_id, *section_size, *mapping);
    return STATUS_SUCCESS;
}

/***********************************************************************
 *           NtDCompositionSetChannelConnectionId (win32u.@)
 */
NTSTATUS WINAPI NtDCompositionSetChannelConnectionId(UINT channel_id)
{
    TRACE("channel_id %u.\n", channel_id);
    return channel_id ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}

/***********************************************************************
 *           NtDCompositionGetBatchId (win32u.@)
 */
NTSTATUS WINAPI NtDCompositionGetBatchId(UINT channel_id, UINT type, UINT *batch_id)
{
    TRACE("channel_id %u, type %u, batch_id %p.\n", channel_id, type, batch_id);

    if (!channel_id || !batch_id) return STATUS_INVALID_PARAMETER;
    *batch_id = 0;
    return STATUS_SUCCESS;
}

/***********************************************************************
 *           NtDCompositionProcessChannelBatchBuffer (win32u.@)
 *
 * Windows 11's user-mode dcomp submits commands through the mapping made by
 * NtDCompositionCreateChannel. Wine does not have a DWM kernel command
 * processor; accepting the batch lets native dcomp retain its user-mode
 * resource graph while Wine presents the HWND.
 */
NTSTATUS WINAPI NtDCompositionProcessChannelBatchBuffer(UINT channel_id, UINT size,
                                                         UINT *processed, BYTE *pending)
{
    const BYTE *commands;
    UINT count = 0;

    TRACE("channel_id %u, size %u, processed %p, pending %p.\n",
          channel_id, size, processed, pending);
    if (!channel_id || !processed || !pending) return STATUS_INVALID_PARAMETER;

    if (channel_id == last_channel_id && last_channel_mapping)
    {
        commands = last_channel_mapping;
        count = dcomposition_count_commands(commands, size);
        TRACE("batch words %08x %08x %08x %08x %08x %08x.\n",
              size >= 4 ? ((const UINT *)commands)[0] : 0,
              size >= 8 ? ((const UINT *)commands)[1] : 0,
              size >= 12 ? ((const UINT *)commands)[2] : 0,
              size >= 16 ? ((const UINT *)commands)[3] : 0,
              size >= 20 ? ((const UINT *)commands)[4] : 0,
              size >= 24 ? ((const UINT *)commands)[5] : 0);
    }

    if (size && !count) return STATUS_INVALID_PARAMETER;
    TRACE("processed %u commands.\n", count);
    *processed = count;
    *pending = FALSE;
    return STATUS_SUCCESS;
}

/***********************************************************************
 *           NtDCompositionGetFrameStatistics (win32u.@)
 */
NTSTATUS WINAPI NtDCompositionGetFrameStatistics(void *statistics_ptr, void *private_statistics)
{
    DCOMPOSITION_FRAME_STATISTICS *statistics = statistics_ptr;
    struct dcomposition_private_frame_statistics *private = private_statistics;
    LARGE_INTEGER counter, frequency;

    TRACE("statistics %p, private_statistics %p.\n", statistics, private_statistics);

    if (!statistics) return STATUS_INVALID_PARAMETER;

    NtQueryPerformanceCounter(&counter, &frequency);
    statistics->lastFrameTime = counter;
    statistics->currentCompositionRate.Numerator = 60;
    statistics->currentCompositionRate.Denominator = 1;
    statistics->currentTime = counter;
    statistics->timeFrequency = frequency;
    statistics->nextEstimatedFrameTime.QuadPart = counter.QuadPart + frequency.QuadPart / 60;
    if (private) memset(private, 0, sizeof(*private));

    return STATUS_SUCCESS;
}
