/* RPCSS class activation admission.
 * Copyright 2026 Nulifyer
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 or
 * any later version.
 */
#ifndef __WINE_RPCSS_PRIVATE_H
#define __WINE_RPCSS_PRIVATE_H

HRESULT scm_class_admission( const GUID *clsid, HANDLE token );

#endif
