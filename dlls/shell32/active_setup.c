/* Per-user Active Setup
 *
 * Copyright 2026 LinuxNT contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "winuser.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(shell);

static WCHAR *setup_string(HKEY key, const WCHAR *name, BOOL expand)
{
    DWORD size = 0, flags = RRF_RT_REG_SZ | (expand ? 0 : RRF_NOEXPAND);
    WCHAR *value;

    if (RegGetValueW(key, NULL, name, flags, NULL, NULL, &size)) return NULL;
    if (!(value = malloc(size + sizeof(WCHAR)))) return NULL;
    if (RegGetValueW(key, NULL, name, flags, NULL, value, &size))
    {
        free(value);
        return NULL;
    }
    value[size / sizeof(WCHAR)] = 0;
    return value;
}

static DWORD setup_dword(HKEY key, const WCHAR *name, DWORD fallback)
{
    DWORD value, size = sizeof(value);
    if (RegGetValueW(key, NULL, name, RRF_RT_REG_DWORD, NULL, &value, &size)) return fallback;
    return value;
}

static ULONGLONG setup_version(const WCHAR *text)
{
    unsigned int parts[4] = {0};
    if (!text || swscanf(text, L"%u,%u,%u,%u", parts, parts + 1, parts + 2, parts + 3) != 4)
        return 0;
    return ((ULONGLONG)(WORD)parts[0] << 48) | ((ULONGLONG)(WORD)parts[1] << 32) |
           ((DWORD)(WORD)parts[2] << 16) | (WORD)parts[3];
}

static void setup_write_string(HKEY key, const WCHAR *name, const WCHAR *value)
{
    if (value && *value)
        RegSetValueExW(key, name, 0, REG_SZ, (const BYTE *)value, (wcslen(value) + 1) * sizeof(WCHAR));
}

static BOOL setup_execute(WCHAR *command)
{
    STARTUPINFOW startup = {sizeof(startup)};
    PROCESS_INFORMATION process;
    DWORD wait;
    MSG message;

    TRACE("executing %s.\n", debugstr_w(command));
    if (!CreateProcessW(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process))
    {
        WARN("could not launch Active Setup command, error %lu.\n", GetLastError());
        return FALSE;
    }
    CloseHandle(process.hThread);
    while ((wait = MsgWaitForMultipleObjects(1, &process.hProcess, FALSE, INFINITE, QS_ALLINPUT)) == WAIT_OBJECT_0 + 1)
    {
        while (PeekMessageW(&message, NULL, 0, 0, PM_REMOVE))
        {
            if (message.message == WM_QUIT)
            {
                PostQuitMessage(message.wParam);
                CloseHandle(process.hProcess);
                return FALSE;
            }
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    CloseHandle(process.hProcess);
    return wait == WAIT_OBJECT_0;
}

static void setup_component(HKEY machine_root, HKEY user_root, const WCHAR *name, int pass)
{
    HKEY machine, user = NULL;
    WCHAR *command = NULL, *version = NULL, *locale = NULL, *user_version = NULL, *user_locale = NULL;
    BOOL installed, needed;

    if (RegOpenKeyExW(machine_root, name, 0, KEY_QUERY_VALUE, &machine)) return;
    if (!(command = setup_string(machine, L"StubPath", TRUE)) || !*command) goto done;
    installed = !!setup_dword(machine, L"IsInstalled", 1);
    /* '<' components install first and uninstall last; '>' reverses that order. */
    if (pass >= 0 && pass != (name[0] == '<' ? (installed ? 0 : 2) :
                             name[0] == '>' ? (installed ? 2 : 0) : 1)) goto done;
    RegOpenKeyExW(user_root, name, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &user);
    if (!installed)
    {
        DWORD dont_ask = setup_dword(machine, L"DontAsk", 0);
        WCHAR *label, *prompt;
        static const WCHAR question[] = L"%s has been removed from this computer. Do you want to clean up your personalized settings for this program?";
        int answer = IDYES;

        if (!user || dont_ask == 1) goto done;
        if (dont_ask != 2)
        {
            if (!(label = setup_string(machine, NULL, FALSE))) label = wcsdup(command);
            if (!label) goto done;
            prompt = malloc((wcslen(label) + ARRAY_SIZE(question)) * sizeof(WCHAR));
            if (!prompt) { free(label); goto done; }
            swprintf(prompt, wcslen(label) + ARRAY_SIZE(question), question, label);
            answer = MessageBoxW(NULL, prompt, L"Desktop", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2);
            free(prompt);
            free(label);
        }
        if (answer == IDYES && setup_execute(command))
        {
            RegCloseKey(user);
            user = NULL;
            RegDeleteKeyW(user_root, name);
        }
        goto done;
    }

    version = setup_string(machine, L"Version", FALSE);
    locale = setup_string(machine, L"Locale", FALSE);
    if (user)
    {
        user_version = setup_string(user, L"Version", FALSE);
        user_locale = setup_string(user, L"Locale", FALSE);
    }
    needed = !user || setup_version(version) > setup_version(user_version) ||
             (locale && *locale && (!user_locale || wcscmp(locale, user_locale)));
    if (!needed) goto done;
    if (!setup_execute(command)) goto done;
    if (!user && RegCreateKeyExW(user_root, name, 0, NULL, 0, KEY_SET_VALUE, NULL, &user, NULL)) goto done;
    setup_write_string(user, L"Version", version);
    setup_write_string(user, L"Locale", locale);

done:
    if (user) RegCloseKey(user);
    RegCloseKey(machine);
    free(command);
    free(version);
    free(locale);
    free(user_version);
    free(user_locale);
}

static void setup_root(const WCHAR *path, const WCHAR *component)
{
    HKEY machine, user;
    WCHAR name[256], *disabled;
    DWORD index, size;
    int pass;
    LONG status;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &machine)) return;
    disabled = setup_string(machine, L"NoIE4StubProcessing", FALSE);
    if (disabled && disabled[0] == 'Y') goto done;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, path, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &user, NULL)) goto done;
    if (component) setup_component(machine, user, component, -1);
    else for (pass = 0; pass < 3; ++pass)
    {
        for (index = 0;; ++index)
        {
            size = ARRAY_SIZE(name);
            status = RegEnumKeyExW(machine, index, name, &size, NULL, NULL, NULL, NULL);
            if (status == ERROR_NO_MORE_ITEMS) break;
            if (status) { WARN("Active Setup enumeration failed: %ld.\n", status); break; }
            setup_component(machine, user, name, pass);
        }
    }
    RegCloseKey(user);
done:
    free(disabled);
    RegCloseKey(machine);
}

/***********************************************************************
 *           RunInstallUninstallStubs (SHELL32.885)
 */
void WINAPI RunInstallUninstallStubs(const WCHAR *component)
{
    TRACE("%s.\n", debugstr_w(component));
    setup_root(L"Software\\Wow6432Node\\Microsoft\\Active Setup\\Installed Components", component);
    setup_root(L"Software\\Microsoft\\Active Setup\\Installed Components", component);
}
