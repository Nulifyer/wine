/* Copyright 2026 LinuxNT contributors; LGPL version 2.1 or later. */
#ifndef THREAD_CALLOUTS_H
#define THREAD_CALLOUTS_H
#include "windows.h"
struct callouts_state
{
    BOOL disable_result;
    DWORD disable_error;
    LONG dll_attach, dll_detach, tls_attach, tls_detach;
};
#endif
