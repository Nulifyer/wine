/*
 * Windows hook functions
 *
 * Copyright 2002 Alexandre Julliard
 * Copyright 2005 Dmitry Timoshkov
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
 *
 * NOTES:
 *   Status of the various hooks:
 *     WH_MSGFILTER                 OK
 *     WH_JOURNALRECORD             Partially implemented
 *     WH_JOURNALPLAYBACK           Partially implemented
 *     WH_KEYBOARD                  OK
 *     WH_GETMESSAGE	            OK (FIXME: A/W mapping?)
 *     WH_CALLWNDPROC	            OK (FIXME: A/W mapping?)
 *     WH_CBT
 *       HCBT_MOVESIZE              OK
 *       HCBT_MINMAX                OK
 *       HCBT_QS                    OK
 *       HCBT_CREATEWND             OK
 *       HCBT_DESTROYWND            OK
 *       HCBT_ACTIVATE              OK
 *       HCBT_CLICKSKIPPED          OK
 *       HCBT_KEYSKIPPED            OK
 *       HCBT_SYSCOMMAND            OK
 *       HCBT_SETFOCUS              OK
 *     WH_SYSMSGFILTER	            OK
 *     WH_MOUSE	                    OK
 *     WH_HARDWARE	            Not supported in Win32
 *     WH_DEBUG	                    Not implemented
 *     WH_SHELL
 *       HSHELL_WINDOWCREATED       OK
 *       HSHELL_WINDOWDESTROYED     OK
 *       HSHELL_ACTIVATESHELLWINDOW Not implemented
 *       HSHELL_WINDOWACTIVATED     Not implemented
 *       HSHELL_GETMINRECT          Not implemented
 *       HSHELL_REDRAW              Not implemented
 *       HSHELL_TASKMAN             Not implemented
 *       HSHELL_LANGUAGE            Not implemented
 *       HSHELL_SYSMENU             Not implemented
 *       HSHELL_ENDTASK             Not implemented
 *       HSHELL_ACCESSIBILITYSTATE  Not implemented
 *       HSHELL_APPCOMMAND          Not implemented
 *       HSHELL_WINDOWREPLACED      Not implemented
 *       HSHELL_WINDOWREPLACING     Not implemented
 *     WH_FOREGROUNDIDLE            Not implemented
 *     WH_CALLWNDPROCRET            OK (FIXME: A/W mapping?)
 *     WH_KEYBOARD_LL               Implemented but should use SendMessage instead
 *     WH_MOUSE_LL                  Implemented but should use SendMessage instead
 */

#include "ntstatus.h"
#include "user_private.h"
#include "wine/asm.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(hook);
WINE_DECLARE_DEBUG_CHANNEL(relay);

static struct user_api_hook original_user_api =
{
    USER_DefDlgProc,
    USER_NonClientButtonDraw,
    USER_ScrollBarDraw,
    USER_ScrollBarProc,
};
static struct user_api_hook hooked_user_api;
struct user_api_hook *user_api = &original_user_api;

struct hook_info
{
    INT id;
    void *proc;
    void *handle;
    DWORD pid, tid;
    BOOL prev_unicode, next_unicode;
    WCHAR module[MAX_PATH];
};

static CRITICAL_SECTION api_hook_cs;
static CRITICAL_SECTION_DEBUG critsect_debug =
{
    0, 0, &api_hook_cs,
    { &critsect_debug.ProcessLocksList, &critsect_debug.ProcessLocksList },
    0, 0, { (DWORD_PTR)(__FILE__ ": api_hook_cs") }
};
static CRITICAL_SECTION api_hook_cs = { &critsect_debug, -1, 0, 0, 0, 0 };

struct modern_user_api_hook
{
    DWORD size;
    DWORD reserved;
    void *def_window_proc_a;
    void *def_window_proc_w;
    const BYTE *def_window_msg_mask;
    DWORD def_window_msg_mask_size;
    DWORD def_window_flags;
    void *get_scroll_info;
    void *set_scroll_info;
    void *enable_scroll_bar;
    void *adjust_window_rect_ex;
    void *set_window_rgn;
    void *pre_window_proc;
    void *post_window_proc;
    const BYTE *window_msg_mask;
    DWORD window_msg_mask_size;
    DWORD window_flags;
    void *pre_dialog_proc;
    void *post_dialog_proc;
    const BYTE *dialog_msg_mask;
    DWORD dialog_msg_mask_size;
    DWORD dialog_flags;
    void *get_system_metrics;
    void *system_parameters_info_a;
    void *system_parameters_info_w;
    void *force_reset;
    void *draw_frame_control;
    void *draw_caption;
    void *mdi_redraw_frame;
    void *broadcast_theme_change;
    void *get_system_metrics_for_dpi;
    void *system_parameters_info_for_dpi;
    void *get_real_window_owner;
};

typedef BOOL (CDECL *user_api_hook_init_proc)( DWORD mode, struct modern_user_api_hook *hook );

static HMODULE modern_hook_module;
static user_api_hook_init_proc modern_hook_init;
static UINT modern_hook_generation;
static BOOL modern_hook_checked;
static BOOL modern_hook_loading;
static struct modern_user_api_hook modern_hook_table;

#ifdef _WIN64
C_ASSERT( sizeof(struct modern_user_api_hook) == 0xe8 );
C_ASSERT( offsetof(struct modern_user_api_hook, force_reset) == 0xa8 );
C_ASSERT( offsetof(struct modern_user_api_hook, broadcast_theme_change) == 0xc8 );
#else
C_ASSERT( sizeof(struct modern_user_api_hook) == 0x84 );
C_ASSERT( offsetof(struct modern_user_api_hook, force_reset) == 0x64 );
C_ASSERT( offsetof(struct modern_user_api_hook, broadcast_theme_change) == 0x74 );
#endif

static LRESULT WINAPI default_pre_dispatch_proc(void)
{
    return 0;
}

static void WINAPI real_mdi_redraw_frame(void)
{
}

static HWND WINAPI get_real_window_owner( HWND hwnd )
{
    return GetWindow( hwnd, GW_OWNER );
}

static BOOL CDECL force_reset_user_api_hook( HMODULE module )
{
    BOOL ret = FALSE;

    EnterCriticalSection( &api_hook_cs );
    if (module == modern_hook_module)
    {
        modern_hook_generation = 0;
        ret = TRUE;
    }
    LeaveCriticalSection( &api_hook_cs );
    return ret;
}

static void reset_modern_user_api_hook( struct modern_user_api_hook *hook )
{
    memset( hook, 0, sizeof(*hook) );
    hook->size = sizeof(*hook);
    hook->def_window_proc_a = DefWindowProcA;
    hook->def_window_proc_w = DefWindowProcW;
    hook->get_scroll_info = GetScrollInfo;
    hook->set_scroll_info = NtUserSetScrollInfo;
    hook->enable_scroll_bar = NtUserEnableScrollBar;
    hook->adjust_window_rect_ex = AdjustWindowRectEx;
    hook->set_window_rgn = NtUserSetWindowRgn;
    hook->pre_window_proc = default_pre_dispatch_proc;
    hook->post_window_proc = default_pre_dispatch_proc;
    hook->pre_dialog_proc = default_pre_dispatch_proc;
    hook->post_dialog_proc = default_pre_dispatch_proc;
    hook->get_system_metrics = GetSystemMetrics;
    hook->system_parameters_info_a = SystemParametersInfoA;
    hook->system_parameters_info_w = SystemParametersInfoW;
    hook->force_reset = (void *)force_reset_user_api_hook;
    hook->draw_frame_control = DrawFrameControl;
    hook->draw_caption = DrawCaption;
    hook->mdi_redraw_frame = real_mdi_redraw_frame;
    hook->get_system_metrics_for_dpi = GetSystemMetricsForDpi;
    hook->system_parameters_info_for_dpi = SystemParametersInfoForDpi;
    hook->get_real_window_owner = get_real_window_owner;
}

static void unload_modern_user_api_hook( DWORD mode )
{
    user_api_hook_init_proc init;
    HMODULE module;

    EnterCriticalSection( &api_hook_cs );
    init = modern_hook_init;
    module = modern_hook_module;
    modern_hook_init = NULL;
    modern_hook_module = NULL;
    modern_hook_generation = 0;
    memset( &modern_hook_table, 0, sizeof(modern_hook_table) );
    LeaveCriticalSection( &api_hook_cs );

    if (init) init( mode, NULL );
    if (module) FreeLibrary( module );
}

BOOL user_api_hook_load( const struct load_user_api_hook_params *params, ULONG size )
{
    struct modern_user_api_hook table;
    user_api_hook_init_proc init;
    const WCHAR *module_name, *proc_name;
    HMODULE module;
    char proc[MAX_PATH];
    BOOL ret = FALSE;

    if (!params || size < FIELD_OFFSET( struct load_user_api_hook_params, data ) ||
        params->module_offset > size || params->module_len > size - params->module_offset ||
        params->proc_offset > size || params->proc_len > size - params->proc_offset ||
        params->module_len > (MAX_PATH - 1) * sizeof(WCHAR) ||
        params->proc_len > (MAX_PATH - 1) * sizeof(WCHAR) ||
        params->module_offset + params->module_len + sizeof(WCHAR) > size ||
        params->proc_offset + params->proc_len + sizeof(WCHAR) > size) return FALSE;

    module_name = (const WCHAR *)((const BYTE *)params + params->module_offset);
    proc_name = (const WCHAR *)((const BYTE *)params + params->proc_offset);
    if (module_name[params->module_len / sizeof(WCHAR)] ||
        proc_name[params->proc_len / sizeof(WCHAR)]) return FALSE;

    EnterCriticalSection( &api_hook_cs );
    if (modern_hook_module && modern_hook_generation == params->generation)
    {
        LeaveCriticalSection( &api_hook_cs );
        return TRUE;
    }
    if (modern_hook_loading)
    {
        LeaveCriticalSection( &api_hook_cs );
        return FALSE;
    }
    modern_hook_checked = TRUE;
    modern_hook_loading = TRUE;
    LeaveCriticalSection( &api_hook_cs );

    unload_modern_user_api_hook( 1 );
    if (!(module = LoadLibraryExW( module_name, NULL, LOAD_WITH_ALTERED_SEARCH_PATH ))) goto done;
    if (!WideCharToMultiByte( CP_ACP, 0, proc_name, -1, proc, sizeof(proc), NULL, NULL ) ||
        !(init = (user_api_hook_init_proc)GetProcAddress( module, proc )))
    {
        FreeLibrary( module );
        goto done;
    }

    reset_modern_user_api_hook( &table );
    if (!init( 0, &table ) || table.size != sizeof(table) ||
        table.force_reset != (void *)force_reset_user_api_hook)
    {
        init( 1, NULL );
        FreeLibrary( module );
        goto done;
    }

    EnterCriticalSection( &api_hook_cs );
    modern_hook_module = module;
    modern_hook_init = init;
    modern_hook_generation = params->generation;
    modern_hook_table = table;
    LeaveCriticalSection( &api_hook_cs );
    ret = TRUE;

done:
    EnterCriticalSection( &api_hook_cs );
    modern_hook_loading = FALSE;
    LeaveCriticalSection( &api_hook_cs );
    return ret;
}

void user_api_hook_ensure_loaded(void)
{
    BOOL check = FALSE;

    if (RtlIsThreadWithinLoaderCallout()) return;
    EnterCriticalSection( &api_hook_cs );
    if (!modern_hook_checked && !modern_hook_module && !modern_hook_loading)
    {
        modern_hook_checked = TRUE;
        check = TRUE;
    }
    LeaveCriticalSection( &api_hook_cs );
    if (check) NtUserLoadUserApiHook();
}

void user_api_hook_process_detach( BOOL process_terminating )
{
    if (process_terminating) return;
    unload_modern_user_api_hook( 2 );
}


#define WH_WINEVENT (WH_MAXHOOK+1)

static const char * const hook_names[WH_WINEVENT - WH_MINHOOK + 1] =
{
    "WH_MSGFILTER",
    "WH_JOURNALRECORD",
    "WH_JOURNALPLAYBACK",
    "WH_KEYBOARD",
    "WH_GETMESSAGE",
    "WH_CALLWNDPROC",
    "WH_CBT",
    "WH_SYSMSGFILTER",
    "WH_MOUSE",
    "WH_HARDWARE",
    "WH_DEBUG",
    "WH_SHELL",
    "WH_FOREGROUNDIDLE",
    "WH_CALLWNDPROCRET",
    "WH_KEYBOARD_LL",
    "WH_MOUSE_LL",
    "WH_WINEVENT"
};


/***********************************************************************
 *		set_windows_hook
 *
 * Implementation of SetWindowsHookExA and SetWindowsHookExW.
 */
static HHOOK set_windows_hook( INT id, HOOKPROC proc, HINSTANCE inst, DWORD tid, BOOL ansi )
{
    WCHAR module[MAX_PATH];
    UNICODE_STRING str;

    if (!inst)
    {
        RtlInitUnicodeString( &str, NULL );
    }
    else
    {
        size_t len = GetModuleFileNameW( inst, module, ARRAYSIZE(module) );
        if (!len || len >= ARRAYSIZE(module))
        {
            SetLastError( ERROR_INVALID_PARAMETER );
            return 0;
        }
        str.Buffer = module;
        str.MaximumLength = str.Length = len * sizeof(WCHAR);
    }

    return NtUserSetWindowsHookEx( inst, &str, tid, id, proc, ansi );
}

#ifdef __i386__
/* Some apps pass a non-stdcall proc to SetWindowsHookExA,
 * so we need a small assembly wrapper to call the proc.
 */
extern LRESULT HOOKPROC_wrapper( HOOKPROC proc,
                                 INT code, WPARAM wParam, LPARAM lParam );
__ASM_GLOBAL_FUNC( HOOKPROC_wrapper,
                   "pushl %ebp\n\t"
                   __ASM_CFI(".cfi_adjust_cfa_offset 4\n\t")
                   __ASM_CFI(".cfi_rel_offset %ebp,0\n\t")
                   "movl %esp,%ebp\n\t"
                   __ASM_CFI(".cfi_def_cfa_register %ebp\n\t")
                   "pushl %edi\n\t"
                   __ASM_CFI(".cfi_rel_offset %edi,-4\n\t")
                   "pushl %esi\n\t"
                   __ASM_CFI(".cfi_rel_offset %esi,-8\n\t")
                   "pushl %ebx\n\t"
                   __ASM_CFI(".cfi_rel_offset %ebx,-12\n\t")
                   "pushl 20(%ebp)\n\t"
                   "pushl 16(%ebp)\n\t"
                   "pushl 12(%ebp)\n\t"
                   "movl 8(%ebp),%eax\n\t"
                   "call *%eax\n\t"
                   "leal -12(%ebp),%esp\n\t"
                   "popl %ebx\n\t"
                   __ASM_CFI(".cfi_same_value %ebx\n\t")
                   "popl %esi\n\t"
                   __ASM_CFI(".cfi_same_value %esi\n\t")
                   "popl %edi\n\t"
                   __ASM_CFI(".cfi_same_value %edi\n\t")
                   "leave\n\t"
                   __ASM_CFI(".cfi_def_cfa %esp,4\n\t")
                   __ASM_CFI(".cfi_same_value %ebp\n\t")
                   "ret" )
#else
static inline LRESULT HOOKPROC_wrapper( HOOKPROC proc,
                                 INT code, WPARAM wParam, LPARAM lParam )
{
    return proc( code, wParam, lParam );
}
#endif  /* __i386__ */


/***********************************************************************
 *		call_hook_AtoW
 */
static LRESULT call_hook_AtoW( HOOKPROC proc, INT id, INT code, WPARAM wparam, LPARAM lparam )
{
    LRESULT ret;
    UNICODE_STRING usBuffer;
    if (id != WH_CBT || code != HCBT_CREATEWND)
        ret = HOOKPROC_wrapper( proc, code, wparam, lparam );
    else
    {
        CBT_CREATEWNDA *cbtcwA = (CBT_CREATEWNDA *)lparam;
        CBT_CREATEWNDW cbtcwW;
        CREATESTRUCTW csW;
        LPWSTR nameW = NULL;
        LPWSTR classW = NULL;
        WCHAR name_buf[3];

        cbtcwW.lpcs = &csW;
        cbtcwW.hwndInsertAfter = cbtcwA->hwndInsertAfter;
        csW = *(CREATESTRUCTW *)cbtcwA->lpcs;

        if (!IS_INTRESOURCE(cbtcwA->lpcs->lpszName))
        {
            if (cbtcwA->lpcs->lpszName[0] != '\xff')
            {
                RtlCreateUnicodeStringFromAsciiz( &usBuffer, cbtcwA->lpcs->lpszName );
                csW.lpszName = nameW = usBuffer.Buffer;
            }
            else
            {
                name_buf[0] = 0xffff;
                name_buf[1] = MAKEWORD( cbtcwA->lpcs->lpszName[1], cbtcwA->lpcs->lpszName[2] );
                name_buf[2] = 0;
                csW.lpszName = name_buf;
            }
        }
        if (!IS_INTRESOURCE(cbtcwA->lpcs->lpszClass))
        {
            RtlCreateUnicodeStringFromAsciiz(&usBuffer,cbtcwA->lpcs->lpszClass);
            csW.lpszClass = classW = usBuffer.Buffer;
        }
        ret = HOOKPROC_wrapper( proc, code, wparam, (LPARAM)&cbtcwW );
        cbtcwA->hwndInsertAfter = cbtcwW.hwndInsertAfter;
        HeapFree( GetProcessHeap(), 0, nameW );
        HeapFree( GetProcessHeap(), 0, classW );
    }
    return ret;
}


/***********************************************************************
 *		call_hook_WtoA
 */
static LRESULT call_hook_WtoA( HOOKPROC proc, INT id, INT code, WPARAM wparam, LPARAM lparam )
{
    LRESULT ret;

    if (id != WH_CBT || code != HCBT_CREATEWND)
        ret = HOOKPROC_wrapper( proc, code, wparam, lparam );
    else
    {
        CBT_CREATEWNDW *cbtcwW = (CBT_CREATEWNDW *)lparam;
        CBT_CREATEWNDA cbtcwA;
        CREATESTRUCTA csA;
        int len;
        LPSTR nameA = NULL;
        LPSTR classA = NULL;
        char name_buf[4];

        cbtcwA.lpcs = &csA;
        cbtcwA.hwndInsertAfter = cbtcwW->hwndInsertAfter;
        csA = *(CREATESTRUCTA *)cbtcwW->lpcs;

        if (!IS_INTRESOURCE(cbtcwW->lpcs->lpszName))
        {
            if (cbtcwW->lpcs->lpszName[0] != 0xffff)
            {
                len = WideCharToMultiByte( CP_ACP, 0, cbtcwW->lpcs->lpszName, -1, NULL, 0, NULL, NULL );
                nameA = HeapAlloc( GetProcessHeap(), 0, len*sizeof(CHAR) );
                WideCharToMultiByte( CP_ACP, 0, cbtcwW->lpcs->lpszName, -1, nameA, len, NULL, NULL );
                csA.lpszName = nameA;
            }
            else
            {
                name_buf[0] = '\xff';
                name_buf[1] = cbtcwW->lpcs->lpszName[1];
                name_buf[2] = cbtcwW->lpcs->lpszName[1] >> 8;
                name_buf[3] = 0;
                csA.lpszName = name_buf;
            }
        }

        if (!IS_INTRESOURCE(cbtcwW->lpcs->lpszClass)) {
            len = WideCharToMultiByte( CP_ACP, 0, cbtcwW->lpcs->lpszClass, -1, NULL, 0, NULL, NULL );
            classA = HeapAlloc( GetProcessHeap(), 0, len*sizeof(CHAR) );
            WideCharToMultiByte( CP_ACP, 0, cbtcwW->lpcs->lpszClass, -1, classA, len, NULL, NULL );
            csA.lpszClass = classA;
        }

        ret = HOOKPROC_wrapper( proc, code, wparam, (LPARAM)&cbtcwA );
        cbtcwW->hwndInsertAfter = cbtcwA.hwndInsertAfter;
        HeapFree( GetProcessHeap(), 0, nameA );
        HeapFree( GetProcessHeap(), 0, classA );
    }
    return ret;
}


/***********************************************************************
 *		call_hook_proc
 */
static LRESULT call_hook_proc( HOOKPROC proc, INT id, INT code, WPARAM wparam, LPARAM lparam,
                               BOOL prev_unicode, BOOL next_unicode )
{
    LRESULT ret;

    TRACE_(relay)( "\1Call hook proc %p (id=%s,code=%x,wp=%08Ix,lp=%08Ix)\n",
                   proc, hook_names[id-WH_MINHOOK], code, wparam, lparam );

    if (!prev_unicode == !next_unicode) ret = proc( code, wparam, lparam );
    else if (prev_unicode) ret = call_hook_WtoA( proc, id, code, wparam, lparam );
    else ret = call_hook_AtoW( proc, id, code, wparam, lparam );

    TRACE_(relay)( "\1Ret  hook proc %p (id=%s,code=%x,wp=%08Ix,lp=%08Ix) retval=%08Ix\n",
                   proc, hook_names[id-WH_MINHOOK], code, wparam, lparam, ret );

    return ret;
}


/***********************************************************************
 *		get_hook_proc
 *
 * Retrieve the hook procedure real value for a module-relative proc
 */
void *get_hook_proc( void *proc, const WCHAR *module, HMODULE *free_module )
{
    HMODULE mod;

    GetModuleHandleExW( 0, module, &mod );
    *free_module = mod;
    if (!mod)
    {
        TRACE( "loading %s\n", debugstr_w(module) );
        /* FIXME: the library will never be freed */
        if (!(mod = LoadLibraryExW(module, NULL, LOAD_WITH_ALTERED_SEARCH_PATH))) return NULL;
    }
    return (char *)mod + (ULONG_PTR)proc;
}


/***********************************************************************
 *		SetWindowsHookA (USER32.@)
 */
HHOOK WINAPI SetWindowsHookA( INT id, HOOKPROC proc )
{
    return SetWindowsHookExA( id, proc, 0, GetCurrentThreadId() );
}


/***********************************************************************
 *		SetWindowsHookW (USER32.@)
 */
HHOOK WINAPI SetWindowsHookW( INT id, HOOKPROC proc )
{
    return SetWindowsHookExW( id, proc, 0, GetCurrentThreadId() );
}


/***********************************************************************
 *		SetWindowsHookExA (USER32.@)
 */
HHOOK WINAPI SetWindowsHookExA( INT id, HOOKPROC proc, HINSTANCE inst, DWORD tid )
{
    return set_windows_hook( id, proc, inst, tid, TRUE );
}

/***********************************************************************
 *		SetWindowsHookExW (USER32.@)
 */
HHOOK WINAPI SetWindowsHookExW( INT id, HOOKPROC proc, HINSTANCE inst, DWORD tid )
{
    return set_windows_hook( id, proc, inst, tid, FALSE );
}


/***********************************************************************
 *           SetWinEventHook                            [USER32.@]
 *
 * Set up an event hook for a set of events.
 *
 * PARAMS
 *  event_min [I] Lowest event handled by pfnProc
 *  event_max [I] Highest event handled by pfnProc
 *  inst      [I] DLL containing pfnProc
 *  proc      [I] Callback event hook function
 *  pid       [I] Process to get events from, or 0 for all processes
 *  tid       [I] Thread to get events from, or 0 for all threads
 *  flags     [I] Flags indicating the status of pfnProc
 *
 * RETURNS
 *  Success: A handle representing the hook.
 *  Failure: A NULL handle.
 */
HWINEVENTHOOK WINAPI SetWinEventHook(DWORD event_min, DWORD event_max,
                                     HMODULE inst, WINEVENTPROC proc,
                                     DWORD pid, DWORD tid, DWORD flags)
{
    WCHAR module[MAX_PATH];
    UNICODE_STRING str;
    DWORD len = 0;

    TRACE("%ld,%ld,%p,%p,%08lx,%04lx,%08lx\n", event_min, event_max, inst,
          proc, pid, tid, flags);

    if (inst && (!(len = GetModuleFileNameW( inst, module, MAX_PATH )) || len >= MAX_PATH))
    {
        inst = 0;
        len = 0;
    }
    str.Buffer = module;
    str.Length = str.MaximumLength = len * sizeof(WCHAR);
    return NtUserSetWinEventHook( event_min, event_max, inst, &str, proc, pid, tid, flags );
}

NTSTATUS WINAPI User32CallWinEventHook( void *args, ULONG size )
{
    const struct win_event_hook_params *params = args;
    WINEVENTPROC proc = params->proc;
    HMODULE free_module = 0;

    if (params->module[0] && !(proc = get_hook_proc( proc, params->module, &free_module )))
        return STATUS_INVALID_PARAMETER;

    TRACE_(relay)( "\1Call winevent hook proc %p (hhook=%p,event=%lx,hwnd=%p,object_id=%lx,child_id=%lx,tid=%04lx,time=%lx)\n",
                   proc, params->handle, params->event, params->hwnd, params->object_id,
                   params->child_id, params->tid, params->time );

    proc( params->handle, params->event, params->hwnd, params->object_id, params->child_id,
          params->tid, params->time );

    TRACE_(relay)( "\1Ret  winevent hook proc %p (hhook=%p,event=%lx,hwnd=%p,object_id=%lx,child_id=%lx,tid=%04lx,time=%lx)\n",
                   proc, params->handle, params->event, params->hwnd, params->object_id,
                   params->child_id, params->tid, params->time );

    if (free_module) FreeLibrary( free_module );
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI User32CallWindowsHook( void *args, ULONG size )
{
    struct win_hook_params *params = args;
    HOOKPROC proc = params->proc;
    HMODULE free_module = 0;
    void *ret_ptr = NULL;
    CBT_CREATEWNDW cbtc;
    UINT ret_size = 0;
    size_t lparam_offset;
    LRESULT ret;

    lparam_offset = FIELD_OFFSET( struct win_hook_params, module[wcslen( params->module ) + 1]);

    if (lparam_offset < size)
    {
        lparam_offset = (lparam_offset + 15) & ~15; /* align */
        ret_size = size - lparam_offset;
        ret_ptr = (char *)params + lparam_offset;
        params->lparam = (LPARAM)ret_ptr;

        switch (params->id)
        {
        case WH_CBT:
            if (params->code == HCBT_CREATEWND)
            {
                cbtc.hwndInsertAfter = HWND_TOP;
                unpack_message( (HWND)params->wparam, WM_CREATE, NULL, (LPARAM *)&cbtc.lpcs,
                                ret_ptr, FALSE );
                params->lparam = (LPARAM)&cbtc;
                ret_size = sizeof(*cbtc.lpcs);
            }
            break;
        case WH_CALLWNDPROC:
            if (ret_size > sizeof(CWPSTRUCT))
            {
                CWPSTRUCT *cwp = (CWPSTRUCT *)params->lparam;
                size_t offset = (lparam_offset + sizeof(*cwp) + 15) & ~15;

                unpack_message( cwp->hwnd, cwp->message, &cwp->wParam, &cwp->lParam,
                                (char *)params + offset, !params->prev_unicode );
                ret_size = 0;
                break;
            }
        case WH_CALLWNDPROCRET:
            if (ret_size > sizeof(CWPRETSTRUCT))
            {
                CWPRETSTRUCT *cwpret = (CWPRETSTRUCT *)params->lparam;
                size_t offset = (lparam_offset + sizeof(*cwpret) + 15) & ~15;

                unpack_message( cwpret->hwnd, cwpret->message, &cwpret->wParam, &cwpret->lParam,
                                (char *)params + offset, !params->prev_unicode );
                ret_size = 0;
                break;
            }
        }
    }
    if (params->module[0] && !(proc = get_hook_proc( proc, params->module, &free_module )))
        return FALSE;

    ret = call_hook_proc( proc, params->id, params->code, params->wparam, params->lparam,
                          params->prev_unicode, params->next_unicode );

    if (free_module) FreeLibrary( free_module );

    if (ret_size)
    {
        LRESULT *result_ptr = (LRESULT *)ret_ptr - 1;
        *result_ptr = ret;
        return NtCallbackReturn( result_ptr, sizeof(*result_ptr) + ret_size, STATUS_SUCCESS );
    }
    return NtCallbackReturn( &ret, sizeof(ret), STATUS_SUCCESS );
}

/***********************************************************************
 *           IsWinEventHookInstalled                       [USER32.@]
 *
 * Determine if an event hook is installed for an event.
 *
 * PARAMS
 *  dwEvent  [I] Id of the event
 *
 * RETURNS
 *  TRUE,  If there are any hooks installed for the event.
 *  FALSE, Otherwise.
 *
 * BUGS
 *  Not implemented.
 */
BOOL WINAPI IsWinEventHookInstalled(DWORD dwEvent)
{
    /* FIXME: Needed by Office 2007 installer */
    WARN("(%ld)-stub!\n", dwEvent);
    return TRUE;
}

/* Wine's original in-process hook table, retained for the builtin UxTheme implementation. */
BOOL CDECL __wine_register_user_api_hook(const struct user_api_hook *new_hook,
                                         struct user_api_hook *old_hook)
{
    if (!new_hook)
        return FALSE;

    EnterCriticalSection( &api_hook_cs );
    hooked_user_api = *new_hook;
    user_api = &hooked_user_api;
    if (old_hook)
        *old_hook = original_user_api;
    LeaveCriticalSection( &api_hook_cs );
    return TRUE;
}

void CDECL __wine_unregister_user_api_hook(void)
{
    InterlockedExchangePointer((void **)&user_api, &original_user_api);
}

/* Undocumented current Windows RegisterUserApiHook() descriptor ABI. */
BOOL WINAPI RegisterUserApiHook(const struct user_api_hook_descriptor *descriptor)
{
    UNICODE_STRING module64, proc64, module32, proc32;

    if (!descriptor || descriptor->size != sizeof(*descriptor) ||
        !descriptor->module64 || !descriptor->proc64 ||
        !descriptor->module32 || !descriptor->proc32)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }

    RtlInitUnicodeString( &module64, descriptor->module64 );
    RtlInitUnicodeString( &proc64, descriptor->proc64 );
    RtlInitUnicodeString( &module32, descriptor->module32 );
    RtlInitUnicodeString( &proc32, descriptor->proc32 );
    return NtUserRegisterUserApiHook( &module64, &proc64, &module32, &proc32 );
}

/* Undocumented UnregisterUserApiHook() */
void WINAPI UnregisterUserApiHook(void)
{
    if (NtUserUnregisterUserApiHook()) unload_modern_user_api_hook( 1 );
}
