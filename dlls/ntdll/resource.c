/*
 * PE file resources
 *
 * Copyright 1995 Thomas Sandford
 * Copyright 1996 Martin von Loewis
 * Copyright 2003 Alexandre Julliard
 *
 * Based on the Win16 resource handling code in loader/resource.c
 * Copyright 1993 Robert J. Amstadt
 * Copyright 1995 Alexandre Julliard
 * Copyright 1997 Marcus Meissner
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

#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>

#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "winnls.h"
#include "winnt.h"
#include "winternl.h"
#include "ntdll_misc.h"
#include "wine/list.h"
#include "wine/asm.h"
#include "wine/exception.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(resource);

#define IS_INTRESOURCE(x)       (((ULONG_PTR)(x) >> 16) == 0)
#define MUI_SIGNATURE           0xfecdfecd

struct mui_resource
{
    DWORD signature;
    DWORD size;
    DWORD version;
    DWORD path_type;
    DWORD file_type;
    DWORD system_attributes;
    DWORD fallback_location;
    BYTE service_checksum[16];
    BYTE checksum[16];
    DWORD unknown1[2];
    DWORD mui_path_offset;
    DWORD mui_path_size;
    DWORD unknown2[2];
    DWORD main_type_name_offset;
    DWORD main_type_name_size;
    DWORD main_type_id_offset;
    DWORD main_type_id_size;
    DWORD mui_type_name_offset;
    DWORD mui_type_name_size;
    DWORD mui_type_id_offset;
    DWORD mui_type_id_size;
    DWORD language_offset;
    DWORD language_size;
    DWORD fallback_language_offset;
    DWORD fallback_language_size;
};

struct alternate_resource_module
{
    struct list entry;
    HMODULE base_module;
    HMODULE resource_module;
    void *view;
    SIZE_T view_size;
    WCHAR locale[LOCALE_NAME_MAX_LENGTH];
};

static struct list alternate_resource_modules = LIST_INIT( alternate_resource_modules );
static RTL_SRWLOCK alternate_resource_lock = RTL_SRWLOCK_INIT;

/**********************************************************************
 *  is_data_file_module
 *
 * Check if a module handle is for a LOAD_LIBRARY_AS_DATAFILE module.
 */
static inline BOOL is_data_file_module( HMODULE hmod )
{
    return (ULONG_PTR)hmod & 1;
}


/**********************************************************************
 *  find_first_entry
 *
 * Find the first suitable entry in a resource directory
 */
static const IMAGE_RESOURCE_DIRECTORY *find_first_entry( const IMAGE_RESOURCE_DIRECTORY *dir,
                                                         const void *root, int want_dir, LANGID *language )
{
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(dir + 1);
    int pos;

    for (pos = 0; pos < dir->NumberOfNamedEntries + dir->NumberOfIdEntries; pos++)
    {
        if (!entry[pos].DataIsDirectory == !want_dir)
        {
            if (language) *language = entry[pos].Id;
            return (const IMAGE_RESOURCE_DIRECTORY *)((const char *)root + entry[pos].OffsetToDirectory);
        }
    }
    return NULL;
}


/**********************************************************************
 *  find_entry_by_id
 *
 * Find an entry by id in a resource directory
 */
static const IMAGE_RESOURCE_DIRECTORY *find_entry_by_id( const IMAGE_RESOURCE_DIRECTORY *dir,
                                                         WORD id, const void *root, int want_dir )
{
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry;
    int min, max, pos;

    entry = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(dir + 1);
    min = dir->NumberOfNamedEntries;
    max = min + dir->NumberOfIdEntries - 1;
    while (min <= max)
    {
        pos = (min + max) / 2;
        if (entry[pos].Id == id)
        {
            if (!entry[pos].DataIsDirectory == !want_dir)
            {
                TRACE("root %p dir %p id %04x ret %p\n",
                      root, dir, id, (const char*)root + entry[pos].OffsetToDirectory);
                return (const IMAGE_RESOURCE_DIRECTORY *)((const char *)root + entry[pos].OffsetToDirectory);
            }
            break;
        }
        if (entry[pos].Id > id) max = pos - 1;
        else min = pos + 1;
    }
    TRACE("root %p dir %p id %04x not found\n", root, dir, id );
    return NULL;
}


/**********************************************************************
 *  find_entry_by_name
 *
 * Find an entry by name in a resource directory
 */
static const IMAGE_RESOURCE_DIRECTORY *find_entry_by_name( const IMAGE_RESOURCE_DIRECTORY *dir,
                                                           LPCWSTR name, const void *root,
                                                           int want_dir )
{
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry;
    const IMAGE_RESOURCE_DIR_STRING_U *str;
    int min, max, res, pos, namelen;

    if (IS_INTRESOURCE(name)) return find_entry_by_id( dir, LOWORD(name), root, want_dir );
    entry = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(dir + 1);
    namelen = wcslen(name);
    min = 0;
    max = dir->NumberOfNamedEntries - 1;
    while (min <= max)
    {
        pos = (min + max) / 2;
        str = (const IMAGE_RESOURCE_DIR_STRING_U *)((const char *)root + entry[pos].NameOffset);
        res = wcsncmp( name, str->NameString, str->Length );
        if (!res && namelen == str->Length)
        {
            if (!entry[pos].DataIsDirectory == !want_dir)
            {
                TRACE("root %p dir %p name %s ret %p\n",
                      root, dir, debugstr_w(name), (const char*)root + entry[pos].OffsetToDirectory);
                return (const IMAGE_RESOURCE_DIRECTORY *)((const char *)root + entry[pos].OffsetToDirectory);
            }
            break;
        }
        if (res < 0) max = pos - 1;
        else min = pos + 1;
    }
    TRACE("root %p dir %p name %s not found\n", root, dir, debugstr_w(name) );
    return NULL;
}


/**********************************************************************
 *  find_entry
 *
 * Find a resource entry
 */
static NTSTATUS find_entry( HMODULE hmod, const LDR_RESOURCE_INFO *info,
                            ULONG level, const void **ret, int want_dir, LANGID *language )
{
    ULONG size;
    const void *root;
    const IMAGE_RESOURCE_DIRECTORY *resdirptr;
    LANGID list[128];  /* list of languages to try */
    ULONG i, count;

    root = RtlImageDirectoryEntryToData( hmod, TRUE, IMAGE_DIRECTORY_ENTRY_RESOURCE, &size );
    if (!root) return STATUS_RESOURCE_DATA_NOT_FOUND;
    if (size < sizeof(*resdirptr)) return STATUS_RESOURCE_DATA_NOT_FOUND;
    resdirptr = root;

    if (!level--) goto done;
    if (!(*ret = find_entry_by_name( resdirptr, (LPCWSTR)info->Type, root, want_dir || level )))
        return STATUS_RESOURCE_TYPE_NOT_FOUND;
    if (!level--) return STATUS_SUCCESS;

    resdirptr = *ret;
    if (!(*ret = find_entry_by_name( resdirptr, (LPCWSTR)info->Name, root, want_dir || level )))
        return STATUS_RESOURCE_NAME_NOT_FOUND;
    if (!level--) return STATUS_SUCCESS;
    if (level) return STATUS_INVALID_PARAMETER;  /* level > 3 */

    resdirptr = *ret;
    count = get_resource_lcids( list, ARRAY_SIZE(list), info->Language );
    for (i = 0; i < count; i++)
        if ((*ret = find_entry_by_id( resdirptr, list[i], root, want_dir )))
        {
            if (language) *language = list[i];
            return STATUS_SUCCESS;
        }

    /* if no explicitly specified language, return the first entry */
    if (PRIMARYLANGID(info->Language) == LANG_NEUTRAL)
    {
        if ((*ret = find_first_entry( resdirptr, root, want_dir, language ))) return STATUS_SUCCESS;
    }
    return STATUS_RESOURCE_LANG_NOT_FOUND;

done:
    *ret = resdirptr;
    return STATUS_SUCCESS;
}


static NTSTATUS access_resource_from_module( HMODULE hmod, const IMAGE_RESOURCE_DATA_ENTRY *entry,
                                             void **ptr, ULONG *size )
{
    NTSTATUS status;

    __TRY
    {
        ULONG dirsize;

        if (!RtlImageDirectoryEntryToData( hmod, TRUE, IMAGE_DIRECTORY_ENTRY_RESOURCE, &dirsize ))
            status = STATUS_RESOURCE_DATA_NOT_FOUND;
        else
        {
            if (ptr)
            {
                BOOL is_data_file = is_data_file_module(hmod);
                hmod = (HMODULE)((ULONG_PTR)hmod & ~3);
                if (is_data_file)
                    *ptr = RtlImageRvaToVa( RtlImageNtHeader(hmod), hmod, entry->OffsetToData, NULL );
                else
                    *ptr = (char *)hmod + entry->OffsetToData;
            }
            if (size) *size = entry->Size;
            status = STATUS_SUCCESS;
        }
    }
    __EXCEPT_PAGE_FAULT
    {
        return GetExceptionCode();
    }
    __ENDTRY;
    return status;
}


static BOOL mui_range_valid( DWORD offset, DWORD length, DWORD size )
{
    if (!offset && !length) return TRUE;
    return offset && offset < size && length <= size - offset;
}


static BOOL validate_mui_resource( const struct mui_resource *mui, ULONG size )
{
    if (size < sizeof(*mui) || mui->signature != MUI_SIGNATURE) return FALSE;
    size = min( size, mui->size );
    if (size < sizeof(*mui)) return FALSE;

    return mui_range_valid( mui->main_type_name_offset, mui->main_type_name_size, size ) &&
           mui_range_valid( mui->main_type_id_offset, mui->main_type_id_size, size ) &&
           mui_range_valid( mui->mui_type_name_offset, mui->mui_type_name_size, size ) &&
           mui_range_valid( mui->mui_type_id_offset, mui->mui_type_id_size, size ) &&
           mui_range_valid( mui->language_offset, mui->language_size, size ) &&
           mui_range_valid( mui->fallback_language_offset, mui->fallback_language_size, size );
}


static const struct mui_resource *get_mui_resource( HMODULE module, ULONG *size )
{
    static const WCHAR muiW[] = L"MUI";
    LDR_RESOURCE_INFO info = { (ULONG_PTR)muiW, 1, 0 };
    const IMAGE_RESOURCE_DATA_ENTRY *entry;
    const struct mui_resource *mui;

    if (find_entry( module, &info, 3, (const void **)&entry, FALSE, NULL )) return NULL;
    if (access_resource_from_module( module, entry, (void **)&mui, size )) return NULL;
    return validate_mui_resource( mui, *size ) ? mui : NULL;
}


static BOOL mui_type_is_satellite( const struct mui_resource *mui, ULONG_PTR type )
{
    const BYTE *base = (const BYTE *)mui;

    if (IS_INTRESOURCE(type))
    {
        const DWORD *ids;
        DWORD i, count;

        if (mui->mui_type_id_size % sizeof(*ids)) return FALSE;
        ids = (const DWORD *)(base + mui->mui_type_id_offset);
        count = mui->mui_type_id_size / sizeof(*ids);
        for (i = 0; i < count; i++) if (ids[i] == LOWORD(type)) return TRUE;
    }
    else
    {
        const WCHAR *name = (const WCHAR *)type;
        const WCHAR *current = (const WCHAR *)(base + mui->mui_type_name_offset);
        const WCHAR *end = (const WCHAR *)(base + mui->mui_type_name_offset + mui->mui_type_name_size);

        if (mui->mui_type_name_size % sizeof(WCHAR)) return FALSE;
        while (current < end && *current)
        {
            SIZE_T len = wcsnlen( current, end - current );

            if (current + len == end) return FALSE;
            if (!wcsicmp( current, name )) return TRUE;
            current += len + 1;
        }
    }
    return FALSE;
}


static BOOL mui_configs_match( const struct mui_resource *main, const struct mui_resource *alternate,
                               BOOL neutral )
{
    if (!(alternate->file_type & ((neutral ? MUI_FILETYPE_LANGUAGE_NEUTRAL_MAIN :
                                  MUI_FILETYPE_LANGUAGE_NEUTRAL_MUI) >> 1))) return FALSE;
    return !memcmp( main->checksum, alternate->checksum, sizeof(main->checksum) ) &&
           !memcmp( main->service_checksum, alternate->service_checksum,
                    sizeof(main->service_checksum) );
}


static struct alternate_resource_module *find_cached_alternate( HMODULE module, const WCHAR *locale )
{
    struct alternate_resource_module *alternate;
    HMODULE base = (HMODULE)((ULONG_PTR)module & ~3);

    LIST_FOR_EACH_ENTRY( alternate, &alternate_resource_modules, struct alternate_resource_module, entry )
        if (alternate->base_module == base && !wcsicmp( alternate->locale, locale )) return alternate;
    return NULL;
}


static NTSTATUS get_module_filename( HMODULE module, MEMORY_SECTION_NAME **name )
{
    MEMORY_SECTION_NAME header;
    SIZE_T size = 0;
    NTSTATUS status;

    module = (HMODULE)((ULONG_PTR)module & ~3);
    status = NtQueryVirtualMemory( NtCurrentProcess(), module, MemoryMappedFilenameInformation,
                                   &header, sizeof(header), &size );
    if (status != STATUS_BUFFER_OVERFLOW && status != STATUS_BUFFER_TOO_SMALL) return status;
    if (!(*name = RtlAllocateHeap( GetProcessHeap(), 0, size ))) return STATUS_NO_MEMORY;
    status = NtQueryVirtualMemory( NtCurrentProcess(), module, MemoryMappedFilenameInformation,
                                   *name, size, &size );
    if (status)
    {
        RtlFreeHeap( GetProcessHeap(), 0, *name );
        *name = NULL;
    }
    return status;
}


static NTSTATUS map_alternate_resource( HMODULE module, const WCHAR *locale,
                                        HMODULE *mapped_module, void **view, SIZE_T *view_size )
{
    MEMORY_SECTION_NAME *section_name = NULL;
    const WCHAR *filename;
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK io;
    HANDLE file = NULL, section = NULL;
    WCHAR *buffer, *p;
    SIZE_T prefix_len, filename_len, directory_len, path_len;
    const WCHAR *directory = *locale ? locale : L"SystemResources";
    NTSTATUS status;

    if ((status = get_module_filename( module, &section_name ))) return status;

    filename = section_name->SectionFileName.Buffer +
               section_name->SectionFileName.Length / sizeof(WCHAR);
    while (filename > section_name->SectionFileName.Buffer && filename[-1] != '\\' && filename[-1] != '/')
        filename--;
    prefix_len = filename - section_name->SectionFileName.Buffer;
    filename_len = section_name->SectionFileName.Length / sizeof(WCHAR) - prefix_len;
    if (!*locale)
    {
        /* Neutral resources are siblings of the module's containing directory. */
        if (prefix_len) prefix_len--;
        while (prefix_len && section_name->SectionFileName.Buffer[prefix_len - 1] != '\\' &&
               section_name->SectionFileName.Buffer[prefix_len - 1] != '/') prefix_len--;
    }
    directory_len = wcslen( directory );
    path_len = prefix_len + directory_len + 1 + filename_len + 4;
    if (path_len >= 0x7fff / sizeof(WCHAR))
    {
        status = STATUS_NAME_TOO_LONG;
        goto done;
    }
    if (!(buffer = RtlAllocateHeap( GetProcessHeap(), 0, (path_len + 1) * sizeof(WCHAR) )))
    {
        status = STATUS_NO_MEMORY;
        goto done;
    }

    p = buffer;
    memcpy( p, section_name->SectionFileName.Buffer, prefix_len * sizeof(WCHAR) );
    p += prefix_len;
    memcpy( p, directory, directory_len * sizeof(WCHAR) );
    p += directory_len;
    *p++ = '\\';
    memcpy( p, filename, filename_len * sizeof(WCHAR) );
    p += filename_len;
    memcpy( p, *locale ? L".mui" : L".mun", 5 * sizeof(WCHAR) );

    path.Buffer = buffer;
    path.Length = path_len * sizeof(WCHAR);
    path.MaximumLength = (path_len + 1) * sizeof(WCHAR);
    InitializeObjectAttributes( &attr, &path, OBJ_CASE_INSENSITIVE, 0, NULL );
    TRACE( "loading alternate resource module %s\n", debugstr_us(&path) );
    status = NtOpenFile( &file, GENERIC_READ | SYNCHRONIZE, &attr, &io,
                         FILE_SHARE_READ | FILE_SHARE_DELETE,
                         FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE );
    if (NT_SUCCESS(status))
        status = NtCreateSection( &section, STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_READ,
                                  NULL, NULL, PAGE_READONLY, SEC_COMMIT, file );
    if (NT_SUCCESS(status))
    {
        *view = NULL;
        *view_size = 0;
        status = NtMapViewOfSection( section, NtCurrentProcess(), view, 0, 0, NULL, view_size,
                                     ViewShare, 0, PAGE_READONLY );
        if (NT_SUCCESS(status))
        {
            *mapped_module = (HMODULE)((ULONG_PTR)*view | 1);
            status = STATUS_SUCCESS;
        }
    }
    if (section) NtClose( section );
    if (file) NtClose( file );
    if (status) TRACE( "failed to load alternate resource %s, status %#lx\n", debugstr_us(&path), status );
    RtlFreeHeap( GetProcessHeap(), 0, buffer );

done:
    RtlFreeHeap( GetProcessHeap(), 0, section_name );
    return status;
}


/* The resource lock protects mapping, lookup and cache teardown together.  An empty
 * locale denotes the language-neutral file, including its cached failed load. */
static NTSTATUS find_file_resource( HMODULE module, const struct mui_resource *main_mui,
                                   const WCHAR *locale, const LDR_RESOURCE_INFO *info,
                                   ULONG level, const void **ret )
{
    struct alternate_resource_module *alternate;
    const struct mui_resource *alternate_mui;
    HMODULE resource_module = NULL;
    ULONG mui_size;
    void *view = NULL;
    SIZE_T view_size = 0;
    NTSTATUS status;
    BOOL published = FALSE;

    RtlAcquireSRWLockExclusive( &alternate_resource_lock );
    __TRY
    {
        if ((alternate = find_cached_alternate( module, locale ))) goto lookup;

        status = map_alternate_resource( module, locale, &resource_module, &view, &view_size );
        if (status)
        {
            if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND ||
                status == STATUS_NO_SUCH_FILE)
                status = *locale ? STATUS_MUI_FILE_NOT_FOUND : STATUS_RESOURCE_TYPE_NOT_FOUND;
            goto done;
        }
        alternate_mui = get_mui_resource( resource_module, &mui_size );
        status = STATUS_SUCCESS;
        if (!alternate_mui || !mui_configs_match( main_mui, alternate_mui, !*locale ))
        {
            TRACE( "alternate resource %p has no matching MUI configuration\n", resource_module );
            NtUnmapViewOfSection( NtCurrentProcess(), view );
            view = NULL;
            view_size = 0;
            resource_module = NULL;
            status = STATUS_MUI_INVALID_FILE;
            if (*locale) goto done;
        }
        if (!(alternate = RtlAllocateHeap( GetProcessHeap(), 0, sizeof(*alternate) )))
        {
            if (view) NtUnmapViewOfSection( NtCurrentProcess(), view );
            status = STATUS_NO_MEMORY;
            goto done;
        }
        alternate->base_module = (HMODULE)((ULONG_PTR)module & ~3);
        alternate->resource_module = resource_module;
        alternate->view = view;
        alternate->view_size = view_size;
        wcscpy( alternate->locale, locale );
        list_add_tail( &alternate_resource_modules, &alternate->entry );
        published = TRUE;
        if (status) goto done;

    lookup:
        if (alternate->resource_module)
        {
            LDR_RESOURCE_INFO lookup = *info;
            if (!*locale) lookup.Language = 0;
            status = find_entry( alternate->resource_module, &lookup, level, ret, FALSE, NULL );
        }
        else status = STATUS_RESOURCE_TYPE_NOT_FOUND;
    done:
        ;
    }
    __EXCEPT_PAGE_FAULT
    {
        status = GetExceptionCode();
        if (view && !published) NtUnmapViewOfSection( NtCurrentProcess(), view );
    }
    __ENDTRY
    RtlReleaseSRWLockExclusive( &alternate_resource_lock );
    return status;
}


static NTSTATUS find_alternate_resource( HMODULE module, const LDR_RESOURCE_INFO *info,
                                         ULONG level, const void **ret, NTSTATUS original_status )
{
    WCHAR locale_buffer[LOCALE_NAME_MAX_LENGTH];
    UNICODE_STRING locale = { 0, sizeof(locale_buffer), locale_buffer };
    const struct mui_resource *mui;
    LANGID languages[128];
    ULONG mui_size, i, count;
    NTSTATUS status = STATUS_RESOURCE_TYPE_NOT_FOUND;

    if (!info || !level || info->Type == 16 || info->Type == 24) return status;
    if (!(mui = get_mui_resource( module, &mui_size ))) return status;
    if (!(mui->file_type & (MUI_FILETYPE_LANGUAGE_NEUTRAL_MAIN >> 1))) return status;
    if (!mui_type_is_satellite( mui, info->Type ))
    {
        if (original_status != STATUS_RESOURCE_TYPE_NOT_FOUND)
            return status;
        return find_file_resource( module, mui, L"", info, level, ret );
    }

    count = get_resource_lcids( languages, ARRAY_SIZE(languages), info->Language );
    for (i = 0; i < count; i++)
    {
        if (!languages[i]) continue;
        locale.Length = 0;
        if (RtlLcidToLocaleName( MAKELCID( languages[i], SORT_DEFAULT ), &locale, 0, FALSE )) continue;
        locale.Buffer[locale.Length / sizeof(WCHAR)] = 0;
        status = find_file_resource( module, mui, locale.Buffer, info, level, ret );
        if (!status) return status;
    }

    if (mui->fallback_language_size >= sizeof(WCHAR) &&
        !(mui->fallback_language_size % sizeof(WCHAR)))
    {
        const WCHAR *fallback = (const WCHAR *)((const BYTE *)mui + mui->fallback_language_offset);
        SIZE_T length = mui->fallback_language_size / sizeof(WCHAR);

        if (length < ARRAY_SIZE(locale_buffer))
        {
            memcpy( locale_buffer, fallback, length * sizeof(WCHAR) );
            locale_buffer[length - 1] = 0;
            status = find_file_resource( module, mui, locale_buffer, info, level, ret );
        }
    }
    return status;
}


/**********************************************************************
 *  LdrResSearchResource (NTDLL.@)
 */
NTSTATUS WINAPI LdrResSearchResource( HMODULE module, const ULONG_PTR *path, ULONG count, ULONG flags,
                                    void **buffer, SIZE_T *size, WCHAR *culture, ULONG *culture_length )
{
    LDR_RESOURCE_INFO info = {0};
    const void *entry;
    LANGID language = 0;
    NTSTATUS status;
    ULONG mode;

    if (!module || !path || (culture && !culture_length)) return STATUS_INVALID_PARAMETER;
    if (!(flags & 0xf00)) flags |= 0x100;
    if (!(flags & 0x2000)) flags |= 0x1000;
    if (flags & 0xfff00000) return STATUS_INVALID_PARAMETER_4;
    if (count >= 5 || (count < 3 && !(flags & 2))) return STATUS_INVALID_PARAMETER_3;
    if ((flags & 0x41) && count != 4) return STATUS_INVALID_PARAMETER_3;
    if (!(flags & 0x41) && count == 4) return STATUS_INVALID_PARAMETER_4;
    mode = flags & 0xf00;
    if (mode != 0x100 && mode != 0x200 && mode != 0x400 && mode != 0x800)
        return STATUS_INVALID_PARAMETER_4;
    if ((flags & 0x3000) == 0x3000 || (flags & 0x18) == 0x18)
        return STATUS_INVALID_PARAMETER_4;
    if ((flags & 0x8000) && (flags & 0x810) != 0x810) return STATUS_INVALID_PARAMETER_4;

    /* File/handle mappings, four-key alternate types and MUI cache inputs need
     * their own contract. Mapped PE lookup keeps the existing resource owner. */
    if (count == 4 || mode == 0x400 || mode == 0x800 || (flags & 0xfc000))
        return STATUS_NOT_IMPLEMENTED;
    if (mode == 0x200) module = (HMODULE)((ULONG_PTR)module | 1);

    __TRY
    {
        if (count) info.Type = path[0];
        if (count > 1) info.Name = path[1];
        if (count > 2)
        {
            if (IS_INTRESOURCE(path[2])) info.Language = path[2];
            else
            {
                LCID lcid;
                if (!(status = RtlLocaleNameToLcid( (const WCHAR *)path[2], &lcid, 0 )))
                    info.Language = LANGIDFROMLCID( lcid );
                else status = STATUS_INVALID_PARAMETER;
                if (status) goto done;
            }
        }
        status = find_entry( module, &info, count, &entry, !!(flags & 2), &language );
        if (status) goto done;
        if (!count)
        {
            status = STATUS_INVALID_PARAMETER;
            goto done;
        }
        if (flags & 2)
        {
            if (buffer) *buffer = (void *)entry;
        }
        else
        {
            ULONG resource_size;
            status = access_resource_from_module( module, entry, buffer, size ? &resource_size : NULL );
            if (status) goto done;
            if (size) *size = resource_size;
        }
        if (culture_length)
        {
            WCHAR name[LOCALE_NAME_MAX_LENGTH];
            UNICODE_STRING locale = {0, sizeof(name), name};
            ULONG capacity = *culture_length, required;
            name[0] = 0;
            if (language && (status = RtlLcidToLocaleName( MAKELCID(language, SORT_DEFAULT), &locale, 2, FALSE )))
                goto done;
            required = locale.Length / sizeof(WCHAR) + 1;
            *culture_length = required;
            if (!culture || capacity < required) status = STATUS_BUFFER_TOO_SMALL;
            else memcpy( culture, name, required * sizeof(WCHAR) );
        }
    done:;
    }
    __EXCEPT_PAGE_FAULT
    {
        return GetExceptionCode();
    }
    __ENDTRY;
    return status;
}

/**********************************************************************
 *  LdrResFindResourceDirectory (NTDLL.@)
 */
NTSTATUS WINAPI LdrResFindResourceDirectory( HMODULE module, const WCHAR *type, const WCHAR *name,
                                           const IMAGE_RESOURCE_DIRECTORY **directory,
                                           WCHAR *culture, ULONG *culture_length, ULONG flags )
{
    ULONG_PTR path[2] = {(ULONG_PTR)type, (ULONG_PTR)name};
    ULONG count = name ? 2 : type ? 1 : 0;

    if (flags & 0xc00) return STATUS_INVALID_PARAMETER;
    return LdrResSearchResource( module, path, count, flags | 2, (void **)directory,
                                NULL, culture, culture_length );
}

/**********************************************************************
 *  LdrResFindResource (NTDLL.@)
 */
NTSTATUS WINAPI LdrResFindResource( HMODULE module, const WCHAR *type, const WCHAR *name,
                                  const WCHAR *language, void **buffer, SIZE_T *size,
                                  WCHAR *culture, ULONG *culture_length, ULONG flags )
{
    ULONG_PTR path[3] = {(ULONG_PTR)type, (ULONG_PTR)name, (ULONG_PTR)language};

    if (flags & 0xc02) return STATUS_INVALID_PARAMETER;
    return LdrResSearchResource( module, path, 3, flags, buffer, size, culture, culture_length );
}

/**********************************************************************
 *	LdrFindResourceDirectory_U  (NTDLL.@)
 */
NTSTATUS WINAPI DECLSPEC_HOTPATCH LdrFindResourceDirectory_U( HMODULE hmod, const LDR_RESOURCE_INFO *info,
                                            ULONG level, const IMAGE_RESOURCE_DIRECTORY **dir )
{
    const void *res;
    NTSTATUS status;

    __TRY
    {
	if (info) TRACE( "module %p type %s name %s lang %04lx level %ld\n",
                     hmod, debugstr_w((LPCWSTR)info->Type),
                     level > 1 ? debugstr_w((LPCWSTR)info->Name) : "",
                     level > 2 ? info->Language : 0, level );

        status = find_entry( hmod, info, level, &res, TRUE, NULL );
        if (status == STATUS_SUCCESS) *dir = res;
    }
    __EXCEPT_PAGE_FAULT
    {
        return GetExceptionCode();
    }
    __ENDTRY;
    return status;
}


/**********************************************************************
 *	LdrFindResource_U  (NTDLL.@)
 */
NTSTATUS WINAPI DECLSPEC_HOTPATCH LdrFindResource_U( HMODULE hmod, const LDR_RESOURCE_INFO *info,
                                   ULONG level, const IMAGE_RESOURCE_DATA_ENTRY **entry )
{
    const void *res;
    NTSTATUS status;

    __TRY
    {
	if (info) TRACE( "module %p type %s name %s lang %04lx level %ld\n",
                     hmod, debugstr_w((LPCWSTR)info->Type),
                     level > 1 ? debugstr_w((LPCWSTR)info->Name) : "",
                     level > 2 ? info->Language : 0, level );

        status = find_entry( hmod, info, level, &res, FALSE, NULL );
        if (status != STATUS_SUCCESS)
        {
            NTSTATUS alternate_status = find_alternate_resource( hmod, info, level, &res, status );
            if (alternate_status != STATUS_RESOURCE_TYPE_NOT_FOUND) status = alternate_status;
        }
        if (status == STATUS_SUCCESS) *entry = res;
    }
    __EXCEPT_PAGE_FAULT
    {
        return GetExceptionCode();
    }
    __ENDTRY;
    return status;
}


/* don't penalize other platforms with stuff needed on i386 for compatibility */
#ifdef __i386__
NTSTATUS WINAPI access_resource( HMODULE hmod, const IMAGE_RESOURCE_DATA_ENTRY *entry,
                                 void **ptr, ULONG *size )
#else
static inline NTSTATUS access_resource( HMODULE hmod, const IMAGE_RESOURCE_DATA_ENTRY *entry,
                                        void **ptr, ULONG *size )
#endif
{
    struct alternate_resource_module *alternate;
    HMODULE base = (HMODULE)((ULONG_PTR)hmod & ~3);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR address = (ULONG_PTR)entry;

    RtlAcquireSRWLockShared( &alternate_resource_lock );
    LIST_FOR_EACH_ENTRY( alternate, &alternate_resource_modules, struct alternate_resource_module, entry )
    {
        if (alternate->base_module == base && address >= (ULONG_PTR)alternate->view &&
            address < (ULONG_PTR)alternate->view + alternate->view_size)
        {
            status = access_resource_from_module( alternate->resource_module, entry, ptr, size );
            goto done;
        }
    }
    status = access_resource_from_module( hmod, entry, ptr, size );
done:
    RtlReleaseSRWLockShared( &alternate_resource_lock );
    return status;
}


/**********************************************************************
 *      LdrUnloadAlternateResourceModule  (NTDLL.@)
 */
BOOLEAN WINAPI LdrUnloadAlternateResourceModule( HMODULE module )
{
    struct alternate_resource_module *alternate, *next;
    HMODULE base = (HMODULE)((ULONG_PTR)module & ~3);
    BOOLEAN found = FALSE;

    RtlAcquireSRWLockExclusive( &alternate_resource_lock );
    LIST_FOR_EACH_ENTRY_SAFE( alternate, next, &alternate_resource_modules,
                              struct alternate_resource_module, entry )
    {
        if (alternate->base_module != base) continue;
        list_remove( &alternate->entry );
        if (alternate->view) NtUnmapViewOfSection( NtCurrentProcess(), alternate->view );
        RtlFreeHeap( GetProcessHeap(), 0, alternate );
        found = TRUE;
    }
    RtlReleaseSRWLockExclusive( &alternate_resource_lock );
    return found;
}


/**********************************************************************
 *      LdrFlushAlternateResourceModules  (NTDLL.@)
 */
BOOLEAN WINAPI LdrFlushAlternateResourceModules(void)
{
    struct alternate_resource_module *alternate, *next;
    BOOLEAN found = FALSE;

    RtlAcquireSRWLockExclusive( &alternate_resource_lock );
    LIST_FOR_EACH_ENTRY_SAFE( alternate, next, &alternate_resource_modules,
                              struct alternate_resource_module, entry )
    {
        list_remove( &alternate->entry );
        if (alternate->view) NtUnmapViewOfSection( NtCurrentProcess(), alternate->view );
        RtlFreeHeap( GetProcessHeap(), 0, alternate );
        found = TRUE;
    }
    RtlReleaseSRWLockExclusive( &alternate_resource_lock );
    return found;
}

/**********************************************************************
 *	LdrAccessResource  (NTDLL.@)
 *
 * NOTE
 * On x86, Shrinker, an executable compressor, depends on the
 * "call access_resource" instruction being there.
 */
#ifdef __i386__
__ASM_STDCALL_FUNC( LdrAccessResource, 16,
    "pushl %ebp\n\t"
    "movl %esp, %ebp\n\t"
    "subl $4,%esp\n\t"
    "pushl 24(%ebp)\n\t"
    "pushl 20(%ebp)\n\t"
    "pushl 16(%ebp)\n\t"
    "pushl 12(%ebp)\n\t"
    "pushl 8(%ebp)\n\t"
    "call " __ASM_STDCALL("access_resource",16) "\n\t"
    "leave\n\t"
    "ret $16"
)
#else
NTSTATUS WINAPI LdrAccessResource( HMODULE hmod, const IMAGE_RESOURCE_DATA_ENTRY *entry,
                                   void **ptr, ULONG *size )
{
    return access_resource( hmod, entry, ptr, size );
}
#endif

/**********************************************************************
 *	RtlFindMessage  (NTDLL.@)
 */
static HMODULE load_alternate_message_module( HMODULE module, LANGID lang )
{
    WCHAR locale_buffer[LOCALE_NAME_MAX_LENGTH];
    UNICODE_STRING locale = { 0, sizeof(locale_buffer), locale_buffer };
    LDR_DATA_TABLE_ENTRY *module_entry;
    UNICODE_STRING path;
    const WCHAR *filename;
    WCHAR *buffer, *p;
    HMODULE alternate;
    SIZE_T prefix_len, filename_len, path_len;
    NTSTATUS status;

    if ((ULONG_PTR)module & 3) return NULL;
    if (LdrFindEntryForAddress( module, &module_entry )) return NULL;

    if (!lang && RtlpQueryDefaultUILanguage( &lang, FALSE )) return NULL;
    if (RtlLcidToLocaleName( MAKELCID( lang, SORT_DEFAULT ), &locale, 0, FALSE )) return NULL;

    filename = module_entry->FullDllName.Buffer + module_entry->FullDllName.Length / sizeof(WCHAR);
    while (filename > module_entry->FullDllName.Buffer && filename[-1] != '\\' && filename[-1] != '/')
        filename--;

    prefix_len = filename - module_entry->FullDllName.Buffer;
    filename_len = module_entry->FullDllName.Length / sizeof(WCHAR) - prefix_len;
    path_len = prefix_len + locale.Length / sizeof(WCHAR) + 1 + filename_len + 4;
    if (path_len >= 0x7fff || !(buffer = RtlAllocateHeap( GetProcessHeap(), 0,
                                                         (path_len + 1) * sizeof(WCHAR) )))
        return NULL;

    p = buffer;
    memcpy( p, module_entry->FullDllName.Buffer, prefix_len * sizeof(WCHAR) );
    p += prefix_len;
    memcpy( p, locale.Buffer, locale.Length );
    p += locale.Length / sizeof(WCHAR);
    *p++ = '\\';
    memcpy( p, filename, filename_len * sizeof(WCHAR) );
    p += filename_len;
    memcpy( p, L".mui", 5 * sizeof(WCHAR) );

    path.Buffer = buffer;
    path.Length = path_len * sizeof(WCHAR);
    path.MaximumLength = (path_len + 1) * sizeof(WCHAR);
    TRACE( "loading alternate message module %s\n", debugstr_us(&path) );

    status = LdrGetDllHandle( NULL, 0, &path, &alternate );
    if (status) status = LdrLoadDll( NULL, NULL, &path, &alternate );
    RtlFreeHeap( GetProcessHeap(), 0, buffer );
    return status ? NULL : alternate;
}

NTSTATUS WINAPI RtlFindMessage( HMODULE hmod, ULONG type, ULONG lang,
                                ULONG msg_id, const MESSAGE_RESOURCE_ENTRY **ret )
{
    const MESSAGE_RESOURCE_DATA *data;
    const MESSAGE_RESOURCE_BLOCK *block;
    const IMAGE_RESOURCE_DATA_ENTRY *rsrc;
    LDR_RESOURCE_INFO info;
    NTSTATUS status;
    void *ptr;
    unsigned int i;

    info.Type     = type;
    info.Name     = 1;
    info.Language = lang;

    if ((status = LdrFindResource_U( hmod, &info, 3, &rsrc )) != STATUS_SUCCESS)
    {
        HMODULE alternate;

        if (!(alternate = load_alternate_message_module( hmod, lang )) ||
            (status = LdrFindResource_U( alternate, &info, 3, &rsrc )) != STATUS_SUCCESS)
            return status;
        hmod = alternate;
    }
    if ((status = LdrAccessResource( hmod, rsrc, &ptr, NULL )) != STATUS_SUCCESS)
        return status;

    data = ptr;
    block = data->Blocks;
    for (i = 0; i < data->NumberOfBlocks; i++, block++)
    {
        if (msg_id >= block->LowId && msg_id <= block->HighId)
        {
            const MESSAGE_RESOURCE_ENTRY *entry;

            entry = (const MESSAGE_RESOURCE_ENTRY *)((const char *)data + block->OffsetToEntries);
            for (i = msg_id - block->LowId; i > 0; i--)
                entry = (const MESSAGE_RESOURCE_ENTRY *)((const char *)entry + entry->Length);
            *ret = entry;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_MESSAGE_NOT_FOUND;
}

/**********************************************************************
 *      RtlLoadString  (NTDLL.@)
 */
NTSTATUS WINAPI RtlLoadString( HMODULE module, USHORT id, const WCHAR *language, ULONG flags,
                               const WCHAR **ret, USHORT *length, void *unknown1, void *unknown2 )
{
    const IMAGE_RESOURCE_DATA_ENTRY *entry;
    const WCHAR *string, *end;
    LDR_RESOURCE_INFO info;
    ULONG resource_size;
    LCID locale;
    NTSTATUS status;
    unsigned int i;
    void *data;

    TRACE( "module %p, id %#x, language %p, flags %#lx, ret %p, length %p\n",
           module, id, language, flags, ret, length );

    if (!module || !ret || (flags & ~1)) return STATUS_INVALID_PARAMETER;
    if ((flags & 1) && (unknown1 || unknown2)) return STATUS_NOT_SUPPORTED;

    if ((ULONG_PTR)language > 0xffff)
    {
        if (!*language)
            locale = 0;
        else if (RtlLocaleNameToLcid( language, &locale, 3 ))
            return STATUS_INVALID_PARAMETER;
    }
    else
        locale = (ULONG_PTR)language;

    info.Type = 6; /* RT_STRING */
    info.Name = (id >> 4) + 1;
    info.Language = LOWORD(locale);
    if ((status = LdrFindResource_U( module, &info, 3, &entry ))) return status;
    if ((status = LdrAccessResource( module, entry, &data, &resource_size ))) return status;
    if (resource_size > 0xffff) return STATUS_INVALID_IMAGE_FORMAT;

    string = data;
    end = (const WCHAR *)((const char *)data + resource_size);
    for (i = 0; i <= (id & 0xf); ++i)
    {
        USHORT string_length;

        if (string >= end) return STATUS_INVALID_IMAGE_FORMAT;
        string_length = *string++;
        if ((SIZE_T)(end - string) < string_length) return STATUS_INVALID_IMAGE_FORMAT;
        if (i == (id & 0xf))
        {
            *ret = string;
            if (length) *length = string_length;
            return STATUS_SUCCESS;
        }
        string += string_length;
    }
    return STATUS_INVALID_IMAGE_FORMAT;
}
