/*
 * COM proxy forwarding thunks
 *
 * Copyright 2009, 2023 Alexandre Julliard
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

#if 0
#pragma makedep arm64ec_x64
#endif

#include "windef.h"
#include "wine/asm.h"

#define COMBASE_PROXY_THUNK_ENTRIES \
    T(3) T(4) T(5) T(6) T(7) T(8) T(9) T(10) T(11) T(12) T(13) T(14) T(15) T(16) T(17) \
    T(18) T(19) T(20) T(21) T(22) T(23) T(24) T(25) T(26) T(27) T(28) T(29) T(30) T(31) T(32)

/* Replace the delegating stub buffer passed as This with its server object,
 * then tail-call the same method index on that object's vtable. */
#ifdef __i386__

#define T(num) \
    ".balign 4\n\t" \
    ".globl " __ASM_NAME("NdrProxyForwardingFunction" #num) "\n" \
    __ASM_NAME("NdrProxyForwardingFunction" #num) ":\n\t" \
    "mov 4(%esp),%eax\n\t" \
    "mov 0x10(%eax),%eax\n\t" \
    "mov %eax,4(%esp)\n\t" \
    "mov (%eax),%eax\n\t" \
    ".byte 0xff,0xa0\n\t" \
    ".long 4*" #num "\n\t"

#elif defined __x86_64__

#define T(num) \
    ".balign 4\n\t" \
    ".globl " __ASM_NAME("NdrProxyForwardingFunction" #num) "\n" \
    __ASM_NAME("NdrProxyForwardingFunction" #num) ":\n\t" \
    "movq 0x20(%rcx),%rcx\n\t" \
    "movq (%rcx),%rax\n\t" \
    ".byte 0xff,0xa0\n\t" \
    ".long 8*" #num "\n\t"

#elif defined __aarch64__

#define T(num) \
    ".globl NdrProxyForwardingFunction" #num "\n" \
    "NdrProxyForwardingFunction" #num ":\n\t" \
    "ldr x0, [x0, #0x20]\n\t" \
    "ldr x16, [x0]\n\t" \
    "mov x17, #" #num "\n\t" \
    "ldr x16, [x16, x17, lsl #3]\n\t" \
    "br x16\n\t"

#elif defined __arm__

#define T(num) \
    ".balign 4\n\t" \
    ".globl NdrProxyForwardingFunction" #num "\n" \
    "NdrProxyForwardingFunction" #num ":\n\t" \
    "ldr r0, [r0, #0x10]\n\t" \
    "ldr ip, [r0]\n\t" \
    "ldr pc, [ip, #(4*" #num ")]\n\t"

#endif

__ASM_GLOBAL_FUNC( combase_proxy_thunks, COMBASE_PROXY_THUNK_ENTRIES )

#undef T
