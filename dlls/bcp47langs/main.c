/*
 * Copyright 2025 Zhiyi Zhang for CodeWeavers
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

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winnls.h"
#include "winstring.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(bcp47langs);

HRESULT WINAPI Bcp47GetDistance(HSTRING first, HSTRING second, INT *distance)
{
    const WCHAR *first_name, *second_name;
    WCHAR first_locale[LOCALE_NAME_MAX_LENGTH], second_locale[LOCALE_NAME_MAX_LENGTH];
    const WCHAR *first_separator, *second_separator;
    size_t first_language_length, second_language_length;

    TRACE("first %p, second %p, distance %p\n", first, second, distance);

    if (!distance) return E_INVALIDARG;
    *distance = 100;
    if (!first || !second) return S_OK;

    first_name = WindowsGetStringRawBuffer(first, NULL);
    second_name = WindowsGetStringRawBuffer(second, NULL);
    if (!first_name || !second_name ||
        !ResolveLocaleName(first_name, first_locale, ARRAY_SIZE(first_locale)) ||
        !ResolveLocaleName(second_name, second_locale, ARRAY_SIZE(second_locale)))
        return S_OK;

    if (!wcsicmp(first_locale, second_locale))
    {
        *distance = 0;
        return S_OK;
    }

    first_separator = wcschr(first_locale, '-');
    second_separator = wcschr(second_locale, '-');
    first_language_length = first_separator ? first_separator - first_locale : wcslen(first_locale);
    second_language_length = second_separator ? second_separator - second_locale : wcslen(second_locale);
    if (first_language_length == second_language_length &&
        !wcsnicmp(first_locale, second_locale, first_language_length))
    {
        /* Native assigns a slightly larger distance to two distinct
         * regional forms than to a neutral/specific pair. */
        *distance = (!first_separator || !second_separator) ? 20 : 24;
    }
    else *distance = 60;

    return S_OK;
}

HRESULT WINAPI GetFontFallbackLanguageList(const WCHAR *lang, size_t buffer_length, WCHAR *buffer,
                                           size_t *required_buffer_length)
{
    WCHAR requested[LOCALE_NAME_MAX_LENGTH], user_locale[LOCALE_NAME_MAX_LENGTH];
    const WCHAR *fallback;
    size_t fallback_length, requested_length, total_length;

    TRACE("lang %s, buffer_length %Iu, buffer %p, required_buffer_length %p\n",
          wine_dbgstr_w(lang), buffer_length, buffer, required_buffer_length);

    if (!buffer_length && buffer) return E_INVALIDARG;

    if (!GetUserDefaultLocaleName(user_locale, ARRAY_SIZE(user_locale))) return E_FAIL;

    if (!lang || !*lang)
    {
        wcscpy(requested, user_locale);
    }
    else
    {
        if (!ResolveLocaleName(lang, requested, ARRAY_SIZE(requested))) return E_INVALIDARG;
    }

    requested_length = wcslen(requested);
    fallback = !wcsicmp(requested, user_locale) ? NULL : user_locale;
    fallback_length = fallback ? wcslen(fallback) : 0;
    total_length = requested_length + (fallback ? fallback_length + 1 : 0) + 1;
    *required_buffer_length = total_length;

    if (!buffer)
        return buffer_length ? E_INVALIDARG : E_NOT_SUFFICIENT_BUFFER;
    if (buffer_length < total_length) return E_NOT_SUFFICIENT_BUFFER;

    memcpy(buffer, requested, requested_length * sizeof(*buffer));
    if (fallback)
    {
        buffer[requested_length++] = ';';
        memcpy(buffer + requested_length, fallback, fallback_length * sizeof(*buffer));
        requested_length += fallback_length;
    }
    buffer[requested_length] = 0;
    return S_OK;
}

HRESULT WINAPI GetUserLanguages(WCHAR delim, HSTRING *langs)
{
    WCHAR locale[LOCALE_NAME_MAX_LENGTH];

    TRACE("delim %lc, langs %p\n", delim, langs);

    if (!langs) return E_INVALIDARG;
    *langs = NULL;

    if (!GetUserDefaultLocaleName(locale, ARRAY_SIZE(locale))) return HRESULT_FROM_WIN32(GetLastError());
    return WindowsCreateString(locale, wcslen(locale), langs);
}

HRESULT WINAPI GetApplicationLanguages(void *context, WCHAR delim, HSTRING *langs)
{
    WCHAR locale[LOCALE_NAME_MAX_LENGTH];

    TRACE("context %p, delim %lc, langs %p\n", context, delim, langs);

    if (!langs) return E_INVALIDARG;
    *langs = NULL;

    /*
     * The native function filters the user language list through the package
     * resource graph represented by context.  Wine does not expose that graph
     * yet, but a valid user locale is the required fallback when the package
     * has no matching resource languages.  Returning that single BCP-47 tag
     * also preserves the native HSTRING ownership contract.
     */
    if (!GetUserDefaultLocaleName(locale, ARRAY_SIZE(locale))) return HRESULT_FROM_WIN32(GetLastError());
    return WindowsCreateString(locale, wcslen(locale), langs);
}

HRESULT WINAPI LanguageListAsMuiForm(WCHAR input_delim, HSTRING languages, WCHAR output_delim, HSTRING *result)
{
    const WCHAR *input;
    WCHAR *buffer;
    UINT32 i, length;
    HRESULT hr;

    TRACE("input_delim %lc, languages %p, output_delim %lc, result %p\n",
          input_delim, languages, output_delim, result);

    if (!result) return E_INVALIDARG;
    *result = NULL;
    if (!languages) return E_POINTER;

    input = WindowsGetStringRawBuffer(languages, &length);
    if (!input) return E_INVALIDARG;

    if (!input_delim || input_delim == output_delim)
        return WindowsCreateString(input, length, result);

    if (!(buffer = malloc((length + 1) * sizeof(*buffer)))) return E_OUTOFMEMORY;
    memcpy(buffer, input, length * sizeof(*buffer));
    buffer[length] = 0;
    for (i = 0; i < length; ++i)
        if (buffer[i] == input_delim) buffer[i] = output_delim;

    hr = WindowsCreateString(buffer, length, result);
    free(buffer);
    return hr;
}
