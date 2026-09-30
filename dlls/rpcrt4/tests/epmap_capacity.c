/* Endpoint-map result capacity through the public binding API.
 *
 * Copyright 2026 LinuxNT project
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */
#include <stdio.h>
#include <string.h>
#include "windows.h"
#include "rpc.h"
#include "rpcdcep.h"
#include "wine/test.h"

static RPC_BINDING_HANDLE make_binding(const char *endpoint)
{
    RPC_BINDING_HANDLE binding = NULL;
    RPC_CSTR text = NULL;
    RPC_STATUS status;
    status = RpcStringBindingComposeA(NULL, (RPC_CSTR)"ncalrpc", NULL, (RPC_CSTR)endpoint, NULL, &text);
    ok(status == RPC_S_OK, "compose endpoint %s: %lu\n", endpoint ? endpoint : "<none>", status);
    if (status) return NULL;
    status = RpcBindingFromStringBindingA(text, &binding);
    ok(status == RPC_S_OK, "create binding: %lu\n", status);
    RpcStringFreeA(&text);
    return binding;
}

START_TEST(epmap_capacity)
{
    static const RPC_SYNTAX_IDENTIFIER ndr =
        {{0x8a885d04, 0x1ceb, 0x11c9, {0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}}, {2, 0}};
    static const unsigned int counts[] = {1, 4, 6, 8};
    struct { ULONG Count; RPC_BINDING_HANDLE BindingH[8]; } vector = {0};
    RPC_SERVER_INTERFACE iface = {0};
    RPC_BINDING_HANDLE query;
    RPC_CSTR text, endpoint;
    RPC_STATUS status;
    char endpoints[8][80];
    unsigned int i, j, pass;
    BOOL found;

    iface.Length = sizeof(iface);
    iface.InterfaceId.SyntaxVersion.MajorVersion = 1;
    iface.TransferSyntax = ndr;
    status = UuidCreate(&iface.InterfaceId.SyntaxGUID);
    ok(status == RPC_S_OK || status == RPC_S_UUID_LOCAL_ONLY, "interface UUID: %lu\n", status);
    if (status != RPC_S_OK && status != RPC_S_UUID_LOCAL_ONLY) return;
    for (i = 0; i < ARRAY_SIZE(vector.BindingH); ++i)
    {
        sprintf(endpoints[i], "linuxnt-epmap-capacity-%lu-%u", GetCurrentProcessId(), i);
        vector.BindingH[i] = make_binding(endpoints[i]);
        if (!vector.BindingH[i]) goto done;
    }
    query = make_binding(NULL);
    if (!query) goto done;
    status = RpcEpResolveBinding(query, &iface);
    ok(status == EPT_S_NOT_REGISTERED, "empty interface: %lu\n", status);
    for (pass = 0; pass < ARRAY_SIZE(counts); ++pass)
    {
        vector.Count = counts[pass];
        status = RpcEpRegisterA(&iface, (RPC_BINDING_VECTOR *)&vector, NULL, (RPC_CSTR)"capacity fixture");
        ok(status == RPC_S_OK, "register %lu alternatives: %lu\n", vector.Count, status);
        if (status) break;
        status = RpcBindingReset(query);
        ok(status == RPC_S_OK, "reset query: %lu\n", status);
        status = RpcEpResolveBinding(query, &iface);
        ok(status == RPC_S_OK, "resolve %lu alternatives with client capacity 4: %lu\n", vector.Count, status);
        if (!status)
        {
            text = endpoint = NULL;
            status = RpcBindingToStringBindingA(query, &text);
            ok(status == RPC_S_OK, "resolved string: %lu\n", status);
            if (!status)
            {
                status = RpcStringBindingParseA(text, NULL, NULL, NULL, &endpoint, NULL);
                ok(status == RPC_S_OK, "resolved endpoint: %lu\n", status);
                if (!status)
                {
                    found = FALSE;
                    for (j = 0; j < vector.Count; ++j)
                        if (!strcmp((char *)endpoint, endpoints[j])) found = TRUE;
                    ok(found, "unregistered endpoint %s\n", endpoint);
                }
            }
            if (endpoint) RpcStringFreeA(&endpoint);
            if (text) RpcStringFreeA(&text);
        }
        status = RpcEpUnregister(&iface, (RPC_BINDING_VECTOR *)&vector, NULL);
        ok(status == RPC_S_OK, "unregister %lu alternatives: %lu\n", vector.Count, status);
        RpcBindingReset(query);
        status = RpcEpResolveBinding(query, &iface);
        ok(status == EPT_S_NOT_REGISTERED, "query after unregister: %lu\n", status);
    }
    RpcBindingFree(&query);
done:
    for (i = 0; i < ARRAY_SIZE(vector.BindingH); ++i)
        if (vector.BindingH[i]) RpcBindingFree(&vector.BindingH[i]);
}
