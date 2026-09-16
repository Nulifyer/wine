/*
 * DirectComposition syscall tests
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
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "ntstatus.h"
#define WIN32_NO_STATUS

#include "wine/test.h"

#include "winbase.h"
#include "ntuser.h"

static void test_frame_statistics(void)
{
    struct dcomposition_frame_statistics statistics, second;
    struct dcomposition_capability_info capabilities;
    LARGE_INTEGER before, after, frequency;
    NTSTATUS status;
    UINT i;

    memset( &statistics, 0xcc, sizeof(statistics) );
    memset( &capabilities, 0xcc, sizeof(capabilities) );
    QueryPerformanceFrequency( &frequency );
    QueryPerformanceCounter( &before );
    SetLastError( 0xdeadbeef );
    status = NtDCompositionGetFrameStatistics( &statistics, &capabilities );
    QueryPerformanceCounter( &after );

    ok( status == STATUS_SUCCESS, "got status %#lx\n", status );
    ok( GetLastError() == 0xdeadbeef, "got last error %lu\n", GetLastError() );
    ok( statistics.current_time.QuadPart >= before.QuadPart,
        "current time %s predates call %s\n", wine_dbgstr_longlong(statistics.current_time.QuadPart),
        wine_dbgstr_longlong(before.QuadPart) );
    ok( statistics.current_time.QuadPart <= after.QuadPart,
        "current time %s follows call %s\n", wine_dbgstr_longlong(statistics.current_time.QuadPart),
        wine_dbgstr_longlong(after.QuadPart) );
    ok( statistics.time_frequency.QuadPart == frequency.QuadPart,
        "got frequency %s, expected %s\n", wine_dbgstr_longlong(statistics.time_frequency.QuadPart),
        wine_dbgstr_longlong(frequency.QuadPart) );
    ok( statistics.current_composition_rate.numerator > 1,
        "got rate numerator %u\n", statistics.current_composition_rate.numerator );
    ok( statistics.current_composition_rate.denominator == 1,
        "got rate denominator %u\n", statistics.current_composition_rate.denominator );
    ok( statistics.last_frame_time.QuadPart <= statistics.current_time.QuadPart,
        "last frame %s follows current time %s\n", wine_dbgstr_longlong(statistics.last_frame_time.QuadPart),
        wine_dbgstr_longlong(statistics.current_time.QuadPart) );
    ok( statistics.next_estimated_frame_time.QuadPart > statistics.current_time.QuadPart,
        "next frame %s does not follow current time %s\n",
        wine_dbgstr_longlong(statistics.next_estimated_frame_time.QuadPart),
        wine_dbgstr_longlong(statistics.current_time.QuadPart) );
    for (i = 0; i < ARRAY_SIZE(capabilities.values); ++i)
        ok( !capabilities.values[i], "capability %u is %#x\n", i, capabilities.values[i] );

    Sleep( 30 );
    memset( &second, 0xcc, sizeof(second) );
    status = NtDCompositionGetFrameStatistics( &second, NULL );
    ok( status == STATUS_SUCCESS, "got status %#lx\n", status );
    ok( second.current_time.QuadPart > statistics.current_time.QuadPart,
        "second current time %s did not advance from %s\n", wine_dbgstr_longlong(second.current_time.QuadPart),
        wine_dbgstr_longlong(statistics.current_time.QuadPart) );

    status = NtDCompositionGetFrameStatistics( NULL, &capabilities );
    ok( status == STATUS_INVALID_PARAMETER, "got null-output status %#lx\n", status );
}

static void test_connection_lifetime(void)
{
    HANDLE event, connection = (HANDLE)0xdeadbeef;
    NTSTATUS status;

    event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!event, "CreateEventW failed, error %lu\n", GetLastError() );
    if (!event) return;

    status = NtDCompositionCreateConnection( FALSE, event, &connection );
    ok( status == STATUS_SUCCESS, "got status %#lx\n", status );
    ok( connection && connection != (HANDLE)0xdeadbeef, "got connection %p\n", connection );
    ok( connection != event, "connection unexpectedly aliases work event %p\n", event );

    CloseHandle( event );
    if (!status)
    {
        status = NtDCompositionDestroyConnection( connection );
        ok( status == STATUS_SUCCESS, "got destroy status %#lx\n", status );
        status = NtDCompositionDestroyConnection( connection );
        ok( status == STATUS_INVALID_HANDLE, "got second destroy status %#lx\n", status );
    }
}

static void test_token_manager_lifetime(void)
{
    HANDLE work_event, ordinary_connection = NULL, dwm_connection = NULL;
    HANDLE section = NULL, event_a = NULL, event_b = NULL;
    HANDLE section2 = NULL, event_a2 = NULL, event_b2 = NULL;
    SIZE_T section_size = ~(SIZE_T)0, section_size2 = ~(SIZE_T)0;
    NTSTATUS status;
    void *view;

    work_event = CreateEventW( NULL, FALSE, FALSE, NULL );
    ok( !!work_event, "CreateEventW failed, error %lu\n", GetLastError() );
    if (!work_event) return;

    status = NtDCompositionCreateConnection( FALSE, work_event, &ordinary_connection );
    ok( status == STATUS_SUCCESS, "got status %#lx\n", status );
    status = NtTokenManagerOpenSectionAndEvents( &section, &section_size, &event_a, &event_b );
    ok( status == STATUS_ACCESS_DENIED, "got status %#lx\n", status );
    ok( section == INVALID_HANDLE_VALUE, "got section %p\n", section );
    ok( !section_size, "got section size %Iu\n", section_size );
    ok( event_a == INVALID_HANDLE_VALUE, "got event_a %p\n", event_a );
    ok( event_b == INVALID_HANDLE_VALUE, "got event_b %p\n", event_b );
    if (ordinary_connection) NtDCompositionDestroyConnection( ordinary_connection );

    status = NtDCompositionCreateConnection( TRUE, work_event, &dwm_connection );
    ok( status == STATUS_SUCCESS, "got status %#lx\n", status );
    status = NtTokenManagerOpenSectionAndEvents( &section, &section_size, &event_a, &event_b );
    ok( status == STATUS_SUCCESS, "got status %#lx\n", status );
    ok( section && section != INVALID_HANDLE_VALUE, "got section %p\n", section );
    ok( section_size == 0x10000, "got section size %Iu\n", section_size );
    ok( event_a && event_a != INVALID_HANDLE_VALUE, "got event_a %p\n", event_a );
    ok( event_b && event_b != INVALID_HANDLE_VALUE, "got event_b %p\n", event_b );
    view = MapViewOfFile( section, FILE_MAP_READ, 0, 0, section_size );
    ok( !!view, "MapViewOfFile failed, error %lu\n", GetLastError() );
    if (view) UnmapViewOfFile( view );

    status = NtTokenManagerOpenSectionAndEvents( &section2, &section_size2, &event_a2, &event_b2 );
    ok( status == STATUS_SUCCESS, "got status %#lx\n", status );
    ok( section_size2 == section_size, "got section size %Iu\n", section_size2 );
    ok( SetEvent( event_a ), "SetEvent failed, error %lu\n", GetLastError() );
    ok( WaitForSingleObject( event_a2, 0 ) == WAIT_OBJECT_0, "event_a handles do not share state\n" );
    ok( SetEvent( event_b ), "SetEvent failed, error %lu\n", GetLastError() );
    ok( WaitForSingleObject( event_b2, 0 ) == WAIT_OBJECT_0, "event_b handles do not share state\n" );

    CloseHandle( section );
    CloseHandle( event_a );
    CloseHandle( event_b );
    CloseHandle( section2 );
    CloseHandle( event_a2 );
    CloseHandle( event_b2 );
    if (dwm_connection) NtDCompositionDestroyConnection( dwm_connection );

    section = NULL;
    event_a = NULL;
    event_b = NULL;
    section_size = ~(SIZE_T)0;
    status = NtTokenManagerOpenSectionAndEvents( &section, &section_size, &event_a, &event_b );
    ok( status == STATUS_ACCESS_DENIED, "got status %#lx\n", status );
    CloseHandle( work_event );
}

START_TEST(dcomp)
{
    test_frame_statistics();
    test_connection_lifetime();
    test_token_manager_lifetime();
}
