/*
 * Advanced Local Procedure Call
 *
 * Copyright 2026 Zhiyi Zhang for CodeWeavers
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

#ifndef __WINE_ALPC_H
#define __WINE_ALPC_H

/* The caller supplies native-width winternl ALPC definitions. */
static inline SIZE_T wine_alpc_get_header_size( ULONG attribute_flags )
{
    static const struct
    {
        ULONG attribute;
        SIZE_T size;
    } attribute_sizes[] =
    {
        /* Attribute with a higher bit is stored before that with a lower bit */
        {ALPC_MESSAGE_SECURITY_ATTRIBUTE, sizeof(ALPC_SECURITY_ATTR)},
        {ALPC_MESSAGE_VIEW_ATTRIBUTE, sizeof(ALPC_VIEW_ATTR)},
        {ALPC_MESSAGE_CONTEXT_ATTRIBUTE, sizeof(ALPC_CONTEXT_ATTR)},
        {ALPC_MESSAGE_HANDLE_ATTRIBUTE, sizeof(ALPC_HANDLE_ATTR)},
        {ALPC_MESSAGE_TOKEN_ATTRIBUTE, sizeof(ALPC_TOKEN_ATTR)},
        {ALPC_MESSAGE_DIRECT_ATTRIBUTE, sizeof(ALPC_DIRECT_ATTR)},
        {ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE, sizeof(ALPC_WORK_ON_BEHALF_ATTR)},
    };
    unsigned int i;
    SIZE_T size;

    size = sizeof(ALPC_MESSAGE_ATTRIBUTES);
    for (i = 0; i < ARRAY_SIZE(attribute_sizes); i++)
    {
        if (attribute_flags & attribute_sizes[i].attribute)
            size += attribute_sizes[i].size;
    }

    return size;
}

static inline void *wine_alpc_get_attribute( const ALPC_MESSAGE_ATTRIBUTES *attributes, ULONG flag )
{
    if (!flag || (flag & (flag - 1)) ||
        (flag & attributes->AllocatedAttributes & ALPC_MESSAGE_ATTRIBUTE_ALL) != flag) return NULL;
    return (unsigned char *)attributes + wine_alpc_get_header_size(
            attributes->AllocatedAttributes & ~(flag | (flag - 1)) );
}

/* Observed receipt writes omit the direct slot when locating the eight-byte
 * work value. Public AlpcGetMessageAttribute geometry remains unchanged. */
static inline void *wine_alpc_get_receipt_work_slot( const ALPC_MESSAGE_ATTRIBUTES *attributes )
{
    unsigned char *slot = wine_alpc_get_attribute( attributes, ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE );
    if (slot && (attributes->AllocatedAttributes & ALPC_MESSAGE_DIRECT_ATTRIBUTE))
        slot -= sizeof(ALPC_DIRECT_ATTR);
    return slot;
}

#endif
