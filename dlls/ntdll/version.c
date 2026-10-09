/*
 * Windows and DOS version functions
 *
 * Copyright 1997 Marcus Meissner
 * Copyright 1998 Patrik Stridvall
 * Copyright 1998, 2003 Andreas Mohr
 * Copyright 1997, 2003 Alexandre Julliard
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

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include "ntstatus.h"
#include "windef.h"
#include "wine/debug.h"
#include "ntdll_misc.h"
#include "ddk/wdm.h"

WINE_DEFAULT_DEBUG_CHANNEL(ver);

typedef enum
{
    WIN20,   /* Windows 2.0 */
    WIN30,   /* Windows 3.0 */
    WIN31,   /* Windows 3.1 */
    WIN95,   /* Windows 95 */
    WIN98,   /* Windows 98 */
    WINME,   /* Windows Me */
    NT351,   /* Windows NT 3.51 */
    NT40,    /* Windows NT 4.0 */
    NT2K,    /* Windows 2000 */
    WINXP,   /* Windows XP */
    WINXP64, /* Windows XP 64-bit */
    WIN2K3,  /* Windows 2003 */
    WINVISTA,/* Windows Vista */
    WIN2K8,  /* Windows 2008 */
    WIN2K8R2,/* Windows 2008 R2 */
    WIN7,    /* Windows 7 */
    WIN8,    /* Windows 8 */
    WIN81,   /* Windows 8.1 */
    WIN10,   /* Windows 10 */
    WIN11,   /* Windows 11 */
    NB_WINDOWS_VERSIONS
} WINDOWS_VERSION;

/* FIXME: compare values below with original and fix.
 * An *excellent* win9x version page (ALL versions !)
 * can be found at www.mdgx.com/ver.htm */
static const RTL_OSVERSIONINFOEXW VersionData[NB_WINDOWS_VERSIONS] =
{
    /* WIN20 FIXME: verify values */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 2, 0, 0, VER_PLATFORM_WIN32s,
        L"Win32s 1.3", 0, 0, 0, 0, 0
    },
    /* WIN30 FIXME: verify values */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 3, 0, 0, VER_PLATFORM_WIN32s,
        L"Win32s 1.3", 0, 0, 0, 0, 0
    },
    /* WIN31 */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 3, 10, 0, VER_PLATFORM_WIN32s,
        L"Win32s 1.3", 0, 0, 0, 0, 0
    },
    /* WIN95 */
    {
        /* Win95:       4, 0, 0x40003B6, ""
         * Win95sp1:    4, 0, 0x40003B6, " A " (according to doc)
         * Win95osr2:   4, 0, 0x4000457, " B " (according to doc)
         * Win95osr2.1: 4, 3, 0x40304BC, " B " (according to doc)
         * Win95osr2.5: 4, 3, 0x40304BE, " C " (according to doc)
         * Win95a/b can be discerned via regkey SubVersionNumber
         */
        sizeof(RTL_OSVERSIONINFOEXW), 4, 0, 0x40003B6, VER_PLATFORM_WIN32_WINDOWS,
        L"", 0, 0, 0, 0, 0
    },
    /* WIN98 (second edition) */
    {
        /* Win98:   4, 10, 0x40A07CE, " "   4.10.1998
         * Win98SE: 4, 10, 0x40A08AE, " A " 4.10.2222
         */
        sizeof(RTL_OSVERSIONINFOEXW), 4, 10, 0x40A08AE, VER_PLATFORM_WIN32_WINDOWS,
        L" A ", 0, 0, 0, 0, 0
    },
    /* WINME */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 4, 90, 0x45A0BB8, VER_PLATFORM_WIN32_WINDOWS,
        L" ", 0, 0, 0, 0, 0
    },
    /* NT351 */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 3, 51, 1057, VER_PLATFORM_WIN32_NT,
        L"Service Pack 5", 5, 0, 0, VER_NT_WORKSTATION, 0
    },
    /* NT40 */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 4, 0, 1381, VER_PLATFORM_WIN32_NT,
        L"Service Pack 6a", 6, 0, 0, VER_NT_WORKSTATION, 0
    },
    /* NT2K */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 5, 0, 2195, VER_PLATFORM_WIN32_NT,
        L"Service Pack 4", 4, 0, 0, VER_NT_WORKSTATION,
        30 /* FIXME: Great, a reserved field with a value! */
    },
    /* WINXP */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 5, 1, 2600, VER_PLATFORM_WIN32_NT,
        L"Service Pack 3", 3, 0, VER_SUITE_SINGLEUSERTS | VER_SUITE_TERMINAL, VER_NT_WORKSTATION,
        30 /* FIXME: Great, a reserved field with a value! */
    },
    /* WINXP64 */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 5, 2, 3790, VER_PLATFORM_WIN32_NT,
        L"Service Pack 2", 2, 0, VER_SUITE_SINGLEUSERTS | VER_SUITE_TERMINAL, VER_NT_WORKSTATION, 0
    },
    /* WIN2K3 */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 5, 2, 3790, VER_PLATFORM_WIN32_NT,
        L"Service Pack 2", 2, 0, VER_SUITE_SINGLEUSERTS | VER_SUITE_TERMINAL, VER_NT_SERVER, 0
    },
    /* WINVISTA */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 6, 0, 6002, VER_PLATFORM_WIN32_NT,
        L"Service Pack 2", 2, 0, VER_SUITE_SINGLEUSERTS | VER_SUITE_TERMINAL, VER_NT_WORKSTATION, 0
    },
    /* WIN2K8 */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 6, 0, 6002, VER_PLATFORM_WIN32_NT,
        L"Service Pack 2", 2, 0, VER_SUITE_SINGLEUSERTS | VER_SUITE_TERMINAL, VER_NT_SERVER, 0
    },
    /* WIN7 */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 6, 1, 7601, VER_PLATFORM_WIN32_NT,
        L"Service Pack 1", 1, 0, VER_SUITE_SINGLEUSERTS | VER_SUITE_TERMINAL, VER_NT_WORKSTATION, 0
    },
    /* WIN2K8R2 */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 6, 1, 7601, VER_PLATFORM_WIN32_NT,
        L"Service Pack 1", 1, 0, VER_SUITE_SINGLEUSERTS | VER_SUITE_TERMINAL, VER_NT_SERVER, 0
    },
    /* WIN8 */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 6, 2, 9200, VER_PLATFORM_WIN32_NT,
        L"", 0, 0, VER_SUITE_SINGLEUSERTS | VER_SUITE_TERMINAL, VER_NT_WORKSTATION, 0
    },
    /* WIN81 */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 6, 3, 9600, VER_PLATFORM_WIN32_NT,
        L"", 0, 0, VER_SUITE_SINGLEUSERTS | VER_SUITE_TERMINAL, VER_NT_WORKSTATION, 0
    },
    /* WIN10 */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 10, 0, 19045, VER_PLATFORM_WIN32_NT,
        L"", 0, 0, VER_SUITE_SINGLEUSERTS | VER_SUITE_TERMINAL, VER_NT_WORKSTATION, 0
    },
    /* WIN11 */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 10, 0, 22000, VER_PLATFORM_WIN32_NT,
        L"", 0, 0, VER_SUITE_SINGLEUSERTS | VER_SUITE_TERMINAL, VER_NT_WORKSTATION, 0
    },
};

static const struct { WCHAR name[12]; WINDOWS_VERSION ver; } version_names[] =
{
    { L"win20", WIN20 },
    { L"win30", WIN30 },
    { L"win31", WIN31 },
    { L"win95", WIN95 },
    { L"win98", WIN98 },
    { L"winme", WINME },
    { L"nt351", NT351 },
    { L"nt40", NT40 },
    { L"win2000", NT2K },
    { L"win2k", NT2K },
    { L"nt2k", NT2K },
    { L"nt2000", NT2K },
    { L"winxp", WINXP },
    { L"winxp64", WINXP64 },
    { L"win2003", WIN2K3 },
    { L"win2k3", WIN2K3 },
    { L"vista", WINVISTA },
    { L"winvista", WINVISTA },
    { L"win2008", WIN2K8 },
    { L"win2k8", WIN2K8 },
    { L"win2008r2", WIN2K8R2 },
    { L"win2k8r2", WIN2K8R2 },
    { L"win7", WIN7 },
    { L"win8", WIN8 },
    { L"win81", WIN81 },
    { L"win10", WIN10 },
    { L"win11", WIN11 },
};


/* initialized to null so that we crash if we try to retrieve the version too early at startup */
static const RTL_OSVERSIONINFOEXW *current_version;

static char wine_version[256];

/*********************************************************************
 *                  wine_get_version
 */
const char * CDECL wine_get_version(void)
{
    return wine_version;
}


/*********************************************************************
 *                  wine_get_build_id
 */
const char * CDECL wine_get_build_id(void)
{
    const char *p = wine_version;
    p += strlen(p) + 1;  /* skip version */
    return p;
}


/*********************************************************************
 *                  wine_get_host_version
 */
void CDECL wine_get_host_version( const char **sysname, const char **release )
{
    const char *p = wine_version;
    p += strlen(p) + 1;  /* skip version */
    p += strlen(p) + 1;  /* skip build id */
    if (sysname) *sysname = p;
    p += strlen(p) + 1;
    if (release) *release = p;
}


/**********************************************************************
 *         get_nt_registry_version
 *
 * Fetch the version information from the NT-style registry keys.
 */
static BOOL get_nt_registry_version( RTL_OSVERSIONINFOEXW *version )
{
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING nameW, valueW;
    HANDLE hkey, hkey2;
    char tmp[64];
    DWORD count;
    BOOL ret = FALSE;
    KEY_VALUE_PARTIAL_INFORMATION *info = (KEY_VALUE_PARTIAL_INFORMATION *)tmp;

    InitializeObjectAttributes( &attr, &nameW, OBJ_CASE_INSENSITIVE, 0, NULL );
    RtlInitUnicodeString( &nameW, L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion" );

    if (NtOpenKey( &hkey, KEY_ALL_ACCESS, &attr )) return FALSE;

    memset( version, 0, sizeof(*version) );
    version->wSuiteMask = VER_SUITE_SINGLEUSERTS | VER_SUITE_TERMINAL;

    RtlInitUnicodeString( &valueW, L"CurrentMajorVersionNumber" );
    if (!NtQueryValueKey( hkey, &valueW, KeyValuePartialInformation, tmp, sizeof(tmp)-1, &count ) &&
        info->Type == REG_DWORD)
    {
        version->dwMajorVersion = *(DWORD *)info->Data;

        RtlInitUnicodeString( &valueW, L"CurrentMinorVersionNumber" );
        if (!NtQueryValueKey( hkey, &valueW, KeyValuePartialInformation, tmp, sizeof(tmp)-1, &count ) &&
            info->Type == REG_DWORD)
        {
            version->dwMinorVersion = *(DWORD *)info->Data;
        }
        else version->dwMajorVersion = 0;
    }

    if (!version->dwMajorVersion)
    {
        RtlInitUnicodeString( &valueW, L"CurrentVersion" );
        if (!NtQueryValueKey( hkey, &valueW, KeyValuePartialInformation, tmp, sizeof(tmp)-1, &count ))
        {
            WCHAR *p, *str = (WCHAR *)info->Data;
            str[info->DataLength / sizeof(WCHAR)] = 0;
            p = wcschr( str, '.' );
            if (p)
            {
                *p++ = 0;
                version->dwMinorVersion = wcstoul( p, NULL, 10 );
            }
            version->dwMajorVersion = wcstoul( str, NULL, 10 );
        }
    }

    if (version->dwMajorVersion)   /* we got the main version, now fetch the other fields */
    {
        ret = TRUE;
        version->dwPlatformId = VER_PLATFORM_WIN32_NT;

        /* get build number */

        RtlInitUnicodeString( &valueW, L"CurrentBuildNumber" );
        if (!NtQueryValueKey( hkey, &valueW, KeyValuePartialInformation, tmp, sizeof(tmp)-1, &count ))
        {
            WCHAR *str = (WCHAR *)info->Data;
            str[info->DataLength / sizeof(WCHAR)] = 0;
            version->dwBuildNumber = wcstoul( str, NULL, 10 );
        }

        /* get version description */

        RtlInitUnicodeString( &valueW, L"CSDVersion" );
        if (!NtQueryValueKey( hkey, &valueW, KeyValuePartialInformation, tmp, sizeof(tmp)-1, &count ))
        {
            DWORD len = min( info->DataLength, sizeof(version->szCSDVersion) - sizeof(WCHAR) );
            memcpy( version->szCSDVersion, info->Data, len );
            version->szCSDVersion[len / sizeof(WCHAR)] = 0;
        }

        /* get service pack version */

        RtlInitUnicodeString( &nameW, L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Windows" );
        if (!NtOpenKey( &hkey2, KEY_ALL_ACCESS, &attr ))
        {
            RtlInitUnicodeString( &valueW, L"CSDVersion" );
            if (!NtQueryValueKey( hkey2, &valueW, KeyValuePartialInformation, tmp, sizeof(tmp), &count ))
            {
                if (info->DataLength >= sizeof(DWORD))
                {
                    DWORD dw = *(DWORD *)info->Data;
                    version->wServicePackMajor = LOWORD(dw) >> 8;
                    version->wServicePackMinor = LOWORD(dw) & 0xff;
                }
            }
            NtClose( hkey2 );
        }

        /* get product type */

        RtlInitUnicodeString( &nameW, L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\ProductOptions" );
        if (!NtOpenKey( &hkey2, KEY_ALL_ACCESS, &attr ))
        {
            RtlInitUnicodeString( &valueW, L"ProductType" );
            if (!NtQueryValueKey( hkey2, &valueW, KeyValuePartialInformation, tmp, sizeof(tmp)-1, &count ))
            {
                WCHAR *str = (WCHAR *)info->Data;
                str[info->DataLength / sizeof(WCHAR)] = 0;
                if (!wcsicmp( str, L"WinNT" )) version->wProductType = VER_NT_WORKSTATION;
                else if (!wcsicmp( str, L"LanmanNT" )) version->wProductType = VER_NT_DOMAIN_CONTROLLER;
                else if (!wcsicmp( str, L"ServerNT" )) version->wProductType = VER_NT_SERVER;
            }
            NtClose( hkey2 );
        }

    }

    NtClose( hkey );
    return ret;
}


/**********************************************************************
 *         get_win9x_registry_version
 *
 * Fetch the version information from the Win9x-style registry keys.
 */
static BOOL get_win9x_registry_version( RTL_OSVERSIONINFOEXW *version )
{
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING nameW, valueW;
    HANDLE hkey;
    char tmp[64];
    DWORD count;
    BOOL ret = FALSE;
    KEY_VALUE_PARTIAL_INFORMATION *info = (KEY_VALUE_PARTIAL_INFORMATION *)tmp;

    InitializeObjectAttributes( &attr, &nameW, OBJ_CASE_INSENSITIVE, 0, NULL );
    RtlInitUnicodeString( &nameW, L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion" );

    if (NtOpenKey( &hkey, KEY_ALL_ACCESS, &attr )) return FALSE;

    memset( version, 0, sizeof(*version) );

    RtlInitUnicodeString( &valueW, L"VersionNumber" );
    if (!NtQueryValueKey( hkey, &valueW, KeyValuePartialInformation, tmp, sizeof(tmp)-1, &count ))
    {
        WCHAR *p, *str = (WCHAR *)info->Data;
        str[info->DataLength / sizeof(WCHAR)] = 0;
        p = wcschr( str, '.' );
        if (p) *p++ = 0;
        version->dwMajorVersion = wcstoul( str, NULL, 10 );
        if (p)
        {
            str = p;
            p = wcschr( str, '.' );
            if (p)
            {
                *p++ = 0;
                version->dwBuildNumber = wcstoul( p, NULL, 10 );
            }
            version->dwMinorVersion = wcstoul( str, NULL, 10 );
        }
        /* build number contains version too on Win9x */
        version->dwBuildNumber |= MAKEWORD( version->dwMinorVersion, version->dwMajorVersion ) << 16;
    }

    if (version->dwMajorVersion)   /* we got the main version, now fetch the other fields */
    {
        ret = TRUE;
        version->dwPlatformId = VER_PLATFORM_WIN32_WINDOWS;

        RtlInitUnicodeString( &valueW, L"SubVersionNumber" );
        if (!NtQueryValueKey( hkey, &valueW, KeyValuePartialInformation, tmp, sizeof(tmp)-1, &count ))
        {
            DWORD len = min( info->DataLength, sizeof(version->szCSDVersion) - sizeof(WCHAR) );
            memcpy( version->szCSDVersion, info->Data, len );
            version->szCSDVersion[len / sizeof(WCHAR)] = 0;
        }
    }

    NtClose( hkey );
    return ret;
}


/**********************************************************************
 *         parse_win_version
 *
 * Parse the contents of the Version key.
 */
static BOOL parse_win_version( HANDLE hkey )
{
    UNICODE_STRING valueW;
    WCHAR *name, tmp[64];
    KEY_VALUE_PARTIAL_INFORMATION *info = (KEY_VALUE_PARTIAL_INFORMATION *)tmp;
    DWORD i, count;

    RtlInitUnicodeString( &valueW, L"Version" );
    if (NtQueryValueKey( hkey, &valueW, KeyValuePartialInformation, tmp, sizeof(tmp) - sizeof(WCHAR), &count ))
        return FALSE;

    name = (WCHAR *)info->Data;
    name[info->DataLength / sizeof(WCHAR)] = 0;

    for (i = 0; i < ARRAY_SIZE(version_names); i++)
    {
        if (wcscmp( version_names[i].name, name )) continue;
        current_version = &VersionData[version_names[i].ver];
        TRACE( "got win version %s\n", debugstr_w(version_names[i].name) );
        return TRUE;
    }

    ERR( "Invalid Windows version value %s specified in config file.\n", debugstr_w(name) );
    return FALSE;
}


/**********************************************************************
 *         version_init
 */
void version_init(void)
{
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING nameW;
    HANDLE root, hkey, config_key;
    BOOL got_win_ver = FALSE;
    const WCHAR *p, *appname = NtCurrentTeb()->Peb->ProcessParameters->ImagePathName.Buffer;
    WCHAR appversion[MAX_PATH+20];

    NtQuerySystemInformation( SystemWineVersionInformation, wine_version, sizeof(wine_version), NULL );

    current_version = &VersionData[WIN10];

    RtlOpenCurrentUser( KEY_ALL_ACCESS, &root );
    InitializeObjectAttributes( &attr, &nameW, OBJ_CASE_INSENSITIVE, root, NULL );
    RtlInitUnicodeString( &nameW, L"Software\\Wine" );

    /* @@ Wine registry key: HKCU\Software\Wine */
    if (NtOpenKey( &config_key, KEY_ALL_ACCESS, &attr )) config_key = 0;
    NtClose( root );
    if (!config_key) goto done;

    /* open AppDefaults\\appname key */

    if ((p = wcsrchr( appname, '/' ))) appname = p + 1;
    if ((p = wcsrchr( appname, '\\' ))) appname = p + 1;

    wcscpy( appversion, L"AppDefaults\\" );
    wcscat( appversion, appname );
    RtlInitUnicodeString( &nameW, appversion );
    attr.RootDirectory = config_key;

    /* @@ Wine registry key: HKCU\Software\Wine\AppDefaults\app.exe */
    if (!NtOpenKey( &hkey, KEY_ALL_ACCESS, &attr ))
    {
        TRACE( "getting version from %s\n", debugstr_w(appversion) );
        got_win_ver = parse_win_version( hkey );
        NtClose( hkey );
    }

    if (!got_win_ver)
    {
        TRACE( "getting default version\n" );
        got_win_ver = parse_win_version( config_key );
    }
    NtClose( config_key );

done:
    if (!got_win_ver)
    {
        static RTL_OSVERSIONINFOEXW registry_version;

        TRACE( "getting registry version\n" );
        if (get_nt_registry_version( &registry_version ) ||
            get_win9x_registry_version( &registry_version ))
            current_version = &registry_version;
    }


    NtCurrentTeb()->Peb->OSMajorVersion = current_version->dwMajorVersion;
    NtCurrentTeb()->Peb->OSMinorVersion = current_version->dwMinorVersion;
    NtCurrentTeb()->Peb->OSBuildNumber  = current_version->dwBuildNumber;
    NtCurrentTeb()->Peb->OSPlatformId   = current_version->dwPlatformId;

    TRACE( "got %ld.%ld platform %ld build %lx name %s service pack %d.%d product %d\n",
           current_version->dwMajorVersion, current_version->dwMinorVersion,
           current_version->dwPlatformId, current_version->dwBuildNumber,
           debugstr_w(current_version->szCSDVersion),
           current_version->wServicePackMajor, current_version->wServicePackMinor,
           current_version->wProductType );
}

/* Prefix of the silo user shared data referenced by PEB.SharedData.  These
 * readers do not create a silo or provision its system capability flags. */
struct silo_shared_data
{
    ULONG service_session_id;
    ULONG active_console_id;
    LONGLONG foreground_process_id;
    ULONG product_type;
    ULONG suite_mask;
    ULONG shared_user_session_id;
    BOOLEAN multi_session_sku;
    BOOLEAN state_separation_enabled;
};

static const struct silo_shared_data *active_silo_shared_data(void)
{
    const struct silo_shared_data *data = NtCurrentTeb()->Peb->SharedData;
    return data && data->service_session_id ? data : NULL;
}

/***********************************************************************
 *           RtlGetCurrentServiceSessionId    (NTDLL.@)
 */
ULONG WINAPI RtlGetCurrentServiceSessionId(void)
{
    const struct silo_shared_data *data = active_silo_shared_data();
    return data ? data->service_session_id : 0;
}

/***********************************************************************
 *           RtlGetActiveConsoleId    (NTDLL.@)
 */
ULONG WINAPI RtlGetActiveConsoleId(void)
{
    const struct silo_shared_data *data = active_silo_shared_data();
    return data ? data->active_console_id : user_shared_data->ActiveConsoleId;
}

/***********************************************************************
 *           RtlGetSuiteMask    (NTDLL.@)
 */
ULONG WINAPI RtlGetSuiteMask(void)
{
    const struct silo_shared_data *data = active_silo_shared_data();
    return data ? data->suite_mask : user_shared_data->SuiteMask;
}

/***********************************************************************
 *           RtlIsMultiSessionSku    (NTDLL.@)
 */
BOOLEAN WINAPI RtlIsMultiSessionSku(void)
{
    const struct silo_shared_data *data = active_silo_shared_data();
    return data ? data->multi_session_sku : (user_shared_data->SharedDataFlags >> 8) & 1;
}

/***********************************************************************
 *           RtlIsMultiUsersInSessionSku    (NTDLL.@)
 */
BOOLEAN WINAPI RtlIsMultiUsersInSessionSku(void)
{
    return (user_shared_data->SharedDataFlags >> 9) & 1;
}

/***********************************************************************
 *           RtlIsStateSeparationEnabled    (NTDLL.@)
 */
BOOLEAN WINAPI RtlIsStateSeparationEnabled(void)
{
    const struct silo_shared_data *data = active_silo_shared_data();
    return data ? data->state_separation_enabled : (user_shared_data->SharedDataFlags >> 10) & 1;
}

/***********************************************************************
 *           RtlQueryElevationFlags    (NTDLL.@)
 */
NTSTATUS WINAPI RtlQueryElevationFlags( ULONG *flags )
{
    ULONG shared = user_shared_data->SharedDataFlags;

    *flags = ((shared & 0x02) >> 1) | ((shared & 0x04) >> 1) | ((shared & 0x08) >> 1) |
             ((shared & 0x1000) ? 0x10 : 0x08);
    return STATUS_SUCCESS;
}

/***********************************************************************
 *           RtlGetProductInfo    (NTDLL.@)
 *
 * Gives info about the current Windows product type, in a format compatible
 * with the given Windows version
 *
 * Returns TRUE if the input is valid, FALSE otherwise
 */
BOOLEAN WINAPI RtlGetProductInfo(DWORD dwOSMajorVersion, DWORD dwOSMinorVersion, DWORD dwSpMajorVersion,
                                 DWORD dwSpMinorVersion, PDWORD pdwReturnedProductType)
{
    TRACE("(%ld, %ld, %ld, %ld, %p)\n", dwOSMajorVersion, dwOSMinorVersion,
          dwSpMajorVersion, dwSpMinorVersion, pdwReturnedProductType);

    if (!pdwReturnedProductType)
        return FALSE;

    if (dwOSMajorVersion < 6)
    {
        *pdwReturnedProductType = PRODUCT_UNDEFINED;
        return FALSE;
    }

    if (current_version->wProductType == VER_NT_WORKSTATION)
        *pdwReturnedProductType = PRODUCT_ULTIMATE_N;
    else
        *pdwReturnedProductType = PRODUCT_STANDARD_SERVER;

    return TRUE;
}

/***********************************************************************
 *         RtlGetVersion   (NTDLL.@)
 */
NTSTATUS WINAPI RtlGetVersion( RTL_OSVERSIONINFOEXW *info )
{
    info->dwMajorVersion = current_version->dwMajorVersion;
    info->dwMinorVersion = current_version->dwMinorVersion;
    info->dwBuildNumber  = current_version->dwBuildNumber;
    info->dwPlatformId   = current_version->dwPlatformId;
    wcscpy( info->szCSDVersion, current_version->szCSDVersion );
    if(info->dwOSVersionInfoSize == sizeof(RTL_OSVERSIONINFOEXW))
    {
        info->wServicePackMajor = current_version->wServicePackMajor;
        info->wServicePackMinor = current_version->wServicePackMinor;
        info->wSuiteMask        = current_version->wSuiteMask;
        info->wProductType      = current_version->wProductType;
    }
    return STATUS_SUCCESS;
}


/******************************************************************************
 *  RtlGetNtVersionNumbers   (NTDLL.@)
 *
 * Get the version numbers of the run time library.
 *
 * PARAMS
 *  major [O] Destination for the Major version
 *  minor [O] Destination for the Minor version
 *  build [O] Destination for the Build version
 *
 * RETURNS
 *  Nothing.
 *
 * NOTES
 * Introduced in Windows XP (NT5.1)
 */
void WINAPI RtlGetNtVersionNumbers( LPDWORD major, LPDWORD minor, LPDWORD build )
{
    if (major) *major = current_version->dwMajorVersion;
    if (minor) *minor = current_version->dwMinorVersion;
    /* FIXME: Does anybody know the real formula? */
    if (build) *build = (0xF0000000 | current_version->dwBuildNumber);
}


/******************************************************************************
 *  RtlGetNtProductType   (NTDLL.@)
 */
BOOLEAN WINAPI RtlGetNtProductType( LPDWORD type )
{
    if (type) *type = current_version->wProductType;
    return TRUE;
}

/******************************************************************************
 *  RtlGetNtSystemRoot   (NTDLL.@)
 */
WCHAR * WINAPI RtlGetNtSystemRoot(void)
{
    return user_shared_data->NtSystemRoot;
}

struct version_info
{
    DWORD major;
    DWORD minor;
    DWORD build;
};

/***********************************************************************
 * Win8 info, reported if the app doesn't provide compat GUID in the manifest and
 * doesn't have higher OS version in PE header.
 */
static const struct version_info windows8_version_info = { 6, 2, 9200 };

/***********************************************************************
 * Win8.1 info, reported if the app doesn't provide compat GUID in the manifest and
 * OS version in PE header is 8.1 or higher but below 10.
 */
static const struct version_info windows8_1_version_info = { 6, 3, 9600 };


/***********************************************************************
 * Windows versions that need compatibility GUID specified in manifest
 * in order to be reported by the APIs.
 */
static const struct
{
    struct version_info info;
    GUID guid;
} version_data[] =
{
    /* Windows 8.1 */
    {
        { 6, 3, 9600 },
        {0x1f676c76,0x80e1,0x4239,{0x95,0xbb,0x83,0xd0,0xf6,0xd0,0xda,0x78}}
    },
    /* Windows 10 */
    {
        { 10, 0, 19045 },
        {0x8e0f7a12,0xbfb3,0x4fe8,{0xb9,0xa5,0x48,0xfd,0x50,0xa1,0x5a,0x9a}}
    }
};


/******************************************************************************
 *  init_apparent_version
 *
 * Initialize the apparent_version variable.
 *
 * For compatibility, Windows 8.1 and later report Win8 version unless the app
 * has a manifest or higher OS version in the PE optional header
 * that confirms its compatibility with newer versions of Windows.
 *
 */
static RTL_OSVERSIONINFOEXW apparent_version;

static DWORD WINAPI init_apparent_version(PRTL_RUN_ONCE init_once, PVOID parameter, PVOID *context)
{
    struct acci
    {
        DWORD ElementCount;
        COMPATIBILITY_CONTEXT_ELEMENT Elements[1];
    } *acci;
    BOOL have_os_compat_elements = FALSE;
    const struct version_info *ver;
    IMAGE_NT_HEADERS *nt;
    SIZE_T req;
    int idx;

    apparent_version.dwOSVersionInfoSize = sizeof(apparent_version);
    if ((*(NTSTATUS *)parameter = RtlGetVersion(&apparent_version))) return FALSE;

    for (idx = ARRAY_SIZE(version_data); idx--;)
        if ( apparent_version.dwMajorVersion >  version_data[idx].info.major ||
            (apparent_version.dwMajorVersion == version_data[idx].info.major &&
             apparent_version.dwMinorVersion >= version_data[idx].info.minor))
            break;

    if (idx < 0) return TRUE;
    ver = &windows8_version_info;

    if (RtlQueryInformationActivationContext(0, NtCurrentTeb()->Peb->ActivationContextData, NULL,
            CompatibilityInformationInActivationContext, NULL, 0, &req) != STATUS_BUFFER_TOO_SMALL
        || !req)
        goto done;

    if (!(acci = RtlAllocateHeap(NtCurrentTeb()->Peb->ProcessHeap, 0, req)))
    {
        *(NTSTATUS *)parameter = STATUS_NO_MEMORY;
        return FALSE;
    }

    if (RtlQueryInformationActivationContext(0, NtCurrentTeb()->Peb->ActivationContextData, NULL,
            CompatibilityInformationInActivationContext, acci, req, &req) == STATUS_SUCCESS)
    {
        do
        {
            DWORD i;

            for (i = 0; i < acci->ElementCount; i++)
            {
                if (acci->Elements[i].Type != ACTCTX_COMPATIBILITY_ELEMENT_TYPE_OS)
                    continue;

                have_os_compat_elements = TRUE;

                if (IsEqualGUID(&acci->Elements[i].Id, &version_data[idx].guid))
                {
                    ver = &version_data[idx].info;

                    if (ver->major == apparent_version.dwMajorVersion &&
                        ver->minor == apparent_version.dwMinorVersion)
                        ver = NULL;

                    idx = 0;  /* break from outer loop */
                    break;
                }
            }
        } while (idx--);
    }
    RtlFreeHeap(NtCurrentTeb()->Peb->ProcessHeap, 0, acci);

done:
    if (!have_os_compat_elements && apparent_version.dwMajorVersion >= 10
            && (nt = RtlImageNtHeader(NtCurrentTeb()->Peb->ImageBaseAddress))
            && (nt->OptionalHeader.MajorOperatingSystemVersion > 6
            || (nt->OptionalHeader.MajorOperatingSystemVersion == 6
            && nt->OptionalHeader.MinorOperatingSystemVersion >= 3)))
    {
        if (apparent_version.dwMajorVersion > 10)
            FIXME("Unsupported apparent_version.dwMajorVersion %lu.\n", apparent_version.dwMajorVersion);

        ver = nt->OptionalHeader.MajorOperatingSystemVersion >= 10 ? NULL : &windows8_1_version_info;
    }

    if (ver)
    {
        apparent_version.dwMajorVersion = ver->major;
        apparent_version.dwMinorVersion = ver->minor;
        apparent_version.dwBuildNumber  = ver->build;
    }
    return TRUE;
}


/* Share the process compatibility policy with Win32 version queries. */
NTSTATUS CDECL wine_get_version_info( RTL_OSVERSIONINFOEXW *info )
{
    static RTL_RUN_ONCE init_once = RTL_RUN_ONCE_INIT;
    NTSTATUS status = STATUS_UNSUCCESSFUL, ret;

    if ((ret = RtlRunOnceExecuteOnce( &init_once, init_apparent_version, &status, NULL )))
        return status ? status : ret;
    *info = apparent_version;
    return STATUS_SUCCESS;
}


/* Modern masks have three bits per field. Older masks only encode major,
 * minor and build conditions, at their historical offsets. */
static UCHAR version_condition( ULONGLONG mask, ULONG type )
{
    unsigned shift = 0;

    if (mask & ((ULONGLONG)1 << 63))
    {
        while (type >>= 1) shift += 3;
        return (mask >> shift) & 7;
    }
    switch (type)
    {
    case VER_MAJORVERSION: return (mask >> 4) & 0xff;
    case VER_MINORVERSION: return (mask >> 2) & 0xff;
    case VER_BUILDNUMBER: return (mask >> 16) & 0xff;
    default: return 0;
    }
}

static BOOL version_compare_values( ULONG current, ULONG requested, UCHAR condition, BOOL lexical )
{
    int comparison;

    if (lexical)
    {
        char left[12], right[12];
        sprintf( left, "%ld", (LONG)current );
        sprintf( right, "%ld", (LONG)requested );
        comparison = strcmp( left, right );
    }
    else comparison = (LONG)current < (LONG)requested ? -1 : (LONG)current != (LONG)requested;

    switch (condition)
    {
    case VER_EQUAL: return !comparison;
    case VER_GREATER: return comparison > 0;
    case VER_GREATER_EQUAL: return comparison >= 0;
    case VER_LESS: return comparison < 0;
    case VER_LESS_EQUAL: return comparison <= 0;
    default: return FALSE;
    }
}

static NTSTATUS verify_version_info( const RTL_OSVERSIONINFOEXW *info, ULONG type,
                                    ULONGLONG mask, const RTL_OSVERSIONINFOEXW *version )
{
    static const ULONG hierarchy[] = { VER_MAJORVERSION, VER_MINORVERSION,
                                      VER_SERVICEPACKMAJOR, VER_SERVICEPACKMINOR };
    UCHAR condition = VER_EQUAL;
    ULONG current, requested;
    unsigned i;

    if ((type & VER_SUITENAME) && info->wSuiteMask)
    {
        condition = version_condition( mask, VER_SUITENAME );
        if (!(mask & ((ULONGLONG)1 << 63))) return STATUS_INVALID_PARAMETER;
        if (condition == VER_AND)
        {
            if ((info->wSuiteMask & version->wSuiteMask) != info->wSuiteMask)
                return STATUS_REVISION_MISMATCH;
        }
        else if (condition == VER_OR)
        {
            if (!(info->wSuiteMask & version->wSuiteMask)) return STATUS_REVISION_MISMATCH;
        }
        else return STATUS_INVALID_PARAMETER;
    }

    condition = VER_EQUAL;
    for (i = 0; i < ARRAY_SIZE(hierarchy); i++)
    {
        if (!(type & hierarchy[i])) continue;
        if (condition == VER_EQUAL) condition = version_condition( mask, hierarchy[i] );
        switch (hierarchy[i])
        {
        case VER_MAJORVERSION:
            current = version->dwMajorVersion; requested = info->dwMajorVersion; break;
        case VER_MINORVERSION:
            current = version->dwMinorVersion; requested = info->dwMinorVersion; break;
        case VER_SERVICEPACKMAJOR:
            current = version->wServicePackMajor; requested = info->wServicePackMajor; break;
        default:
            current = version->wServicePackMinor; requested = info->wServicePackMinor; break;
        }
        if (!version_compare_values( current, requested, condition, i == 1 || i == 3 ) &&
            (current != requested || i == 3)) return STATUS_REVISION_MISMATCH;
        if (current != requested) break;
    }

    if ((type & VER_BUILDNUMBER) &&
        !version_compare_values( version->dwBuildNumber, info->dwBuildNumber,
                                 version_condition( mask, VER_BUILDNUMBER ), FALSE ))
        return STATUS_REVISION_MISMATCH;
    if ((type & VER_PLATFORMID) &&
        !version_compare_values( version->dwPlatformId, info->dwPlatformId,
                                 version_condition( mask, VER_PLATFORMID ), FALSE ))
        return STATUS_REVISION_MISMATCH;
    if ((type & VER_PRODUCT_TYPE) &&
        !version_compare_values( version->wProductType, info->wProductType,
                                 version_condition( mask, VER_PRODUCT_TYPE ), FALSE ))
        return STATUS_REVISION_MISMATCH;
    return STATUS_SUCCESS;
}

/******************************************************************************
 *        RtlVerifyVersionInfo   (NTDLL.@)
 */
NTSTATUS WINAPI RtlVerifyVersionInfo( const RTL_OSVERSIONINFOEXW *info, DWORD type, DWORDLONG mask )
{
    RTL_OSVERSIONINFOEXW version;
    NTSTATUS status;

    TRACE("(%p,0x%lx,0x%s)\n", info, type, wine_dbgstr_longlong(mask));
    if (!type) return STATUS_INVALID_PARAMETER;
    version.dwOSVersionInfoSize = sizeof(version);
    if ((status = RtlGetVersion( &version ))) return status;
    return verify_version_info( info, type, mask, &version );
}

/******************************************************************************
 *        RtlSwitchedVVI   (NTDLL.@)
 */
NTSTATUS WINAPI RtlSwitchedVVI( const RTL_OSVERSIONINFOEXW *info, DWORD type, DWORDLONG mask )
{
    RTL_OSVERSIONINFOEXW version;
    NTSTATUS status;

    TRACE("(%p,0x%lx,0x%s)\n", info, type, wine_dbgstr_longlong(mask));
    if (!type) return STATUS_INVALID_PARAMETER;
    if ((status = wine_get_version_info( &version ))) return status;
    return verify_version_info( info, type, mask, &version );
}

/******************************************************************************
 *        VerSetConditionMask   (NTDLL.@)
 */
ULONGLONG WINAPI VerSetConditionMask( ULONGLONG mask, DWORD type, BYTE condition )
{
    unsigned shift = 0;

    if (!type) return 0;
    while (type >>= 1) shift += 3;
#ifdef __i386__
    /* The x86 64-bit shift helper returns zero for shifts beyond the width. */
    if (shift >= 64) return mask | ((ULONGLONG)1 << 63);
#endif
    return mask | ((ULONGLONG)(condition & 7) << (shift & 63)) | ((ULONGLONG)1 << 63);
}
