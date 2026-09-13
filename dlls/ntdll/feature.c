/*
 * Windows feature configuration queries
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
#include "winternl.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(ntdll);

struct rtl_feature_configuration
{
    ULONG feature_id;
    ULONG flags;
    ULONG variant_payload;
};

/***********************************************************************
 *             RtlQueryFeatureConfiguration  (NTDLL.@)
 */
NTSTATUS WINAPI RtlQueryFeatureConfiguration( ULONG feature_id, ULONG configuration_type,
                                              ULONGLONG *change_stamp,
                                              struct rtl_feature_configuration *configuration )
{
    ULONG flags;

    TRACE( "(%#lx,%lu,%p,%p)\n", feature_id, configuration_type, change_stamp, configuration );

    if (configuration_type > 1) return STATUS_INVALID_PARAMETER;
    if (!change_stamp || !configuration) return STATUS_INVALID_PARAMETER;
    *change_stamp = 1;

    switch (feature_id)
    {
    case 0x038419ca: /* Ten2Loc */
        flags = 0x2f;
        break;
    case 0x037e2887: /* Standalone_26_04_NonSec */
        if (configuration_type) return STATUS_NOT_FOUND;
        flags = 0x2f;
        break;
    case 0x032cf8c5: /* Feature_1855570234 */
        if (configuration_type) return STATUS_NOT_FOUND;
        flags = 0x19;
        break;
    case 0x036933e4: /* ProperMbrContainment */
        if (configuration_type) return STATUS_NOT_FOUND;
        flags = 0x20;
        break;
    case 0x032204ec: /* Feature_3379165498 */
    case 0x03334051: /* Feature_1014611256 */
    case 0x036099b1: /* Feature_3206345019 */
        if (configuration_type) return STATUS_NOT_FOUND;
        flags = 0x29;
        break;
    default:
        return STATUS_NOT_FOUND;
    }

    configuration->feature_id = feature_id;
    configuration->flags = flags;
    configuration->variant_payload = 0;
    return STATUS_SUCCESS;
}
