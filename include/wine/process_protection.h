/*
 * Scalar process protection policy shared by NTDLL and server admission.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __WINE_PROCESS_PROTECTION_H
#define __WINE_PROCESS_PROTECTION_H

static inline int wine_protection_can_access( unsigned char source, unsigned char target )
{
    static const unsigned short signer_masks[] =
    {
        0x000, 0x002, 0x004, 0x108, 0x110, 0x13e, 0x17e, 0x1fe, 0x000
    };
    unsigned int source_signer = source >> 4;
    unsigned int target_signer = target >> 4;
    unsigned int target_type = target & 7;

    if (!target_type) return 1;
    if ((source & 7) < target_type) return 0;
    if (source_signer >= sizeof(signer_masks) / sizeof(signer_masks[0])) return 0;
    return !!(signer_masks[source_signer] & (1u << target_signer));
}

static inline int wine_protection_is_valid( unsigned char protection )
{
    static const unsigned char valid[] =
    {
        0x00, 0x08, 0x12, 0x21, 0x31, 0x41, 0x51, 0x52, 0x61, 0x62, 0x72, 0x81
    };
    unsigned int i;

    for (i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i)
        if (protection == valid[i]) return 1;
    return 0;
}

#endif
