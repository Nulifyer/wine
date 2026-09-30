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
#include <stdint.h>

#include "windef.h"
#include "winbase.h"
#include "winnls.h"
#include "winstring.h"

#include "icu.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(bcp47langs);

HRESULT WINAPI Bcp47GetDirectionality(HSTRING language, INT *direction)
{
    UScriptCode scripts[8];
    char language_tag[LOCALE_NAME_MAX_LENGTH * 3];
    char locale_name[LOCALE_NAME_MAX_LENGTH * 3];
    const WCHAR *locale;
    BOOL embedded_null;
    UErrorCode status = U_ZERO_ERROR;
    UINT32 length;
    HRESULT hr;
    INT bytes, count, i, parsed;

    TRACE("language %s, direction %p\n", debugstr_hstring(language), direction);

    *direction = -1;
    if (FAILED(hr = WindowsStringHasEmbeddedNull(language, &embedded_null))) return hr;
    locale = WindowsGetStringRawBuffer(language, &length);
    if (!length || length >= LOCALE_NAME_MAX_LENGTH || embedded_null) return E_INVALIDARG;
    if (!(bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, locale, length, language_tag,
                                      ARRAY_SIZE(language_tag) - 1, NULL, NULL)))
        return HRESULT_FROM_WIN32(GetLastError());
    language_tag[bytes] = 0;

    parsed = 0;
    uloc_forLanguageTag(language_tag, locale_name, ARRAY_SIZE(locale_name), &parsed, &status);
    if (status > U_ZERO_ERROR || parsed != bytes) return E_INVALIDARG;

    count = uscript_getCode(locale_name, scripts, ARRAY_SIZE(scripts), &status);
    if (status > U_ZERO_ERROR) return E_INVALIDARG;

    for (i = 0; i < count; ++i)
        if (scripts[i] == USCRIPT_MONGOLIAN || scripts[i] == USCRIPT_PHAGS_PA)
        {
            *direction = 2;
            return S_OK;
        }
    for (i = 0; i < count; ++i)
        if (scripts[i] == USCRIPT_KHITAN_SMALL_SCRIPT ||
            scripts[i] == USCRIPT_MEROITIC_HIEROGLYPHS)
        {
            *direction = 3;
            return S_OK;
        }
    for (i = 0; i < count; ++i)
        if (uscript_isRightToLeft(scripts[i]))
        {
            *direction = 1;
            return S_OK;
        }

    *direction = 0;
    return S_OK;
}

HRESULT WINAPI GetFontFallbackLanguageList(const WCHAR *lang, size_t buffer_length, WCHAR *buffer,
                                           size_t *required_buffer_length)
{
    WCHAR locale[LOCALE_NAME_MAX_LENGTH];
    size_t lang_length;

    FIXME("lang %s, buffer_length %Iu, buffer %p, required_buffer_length %p stub!\n",
          wine_dbgstr_w(lang), buffer_length, buffer, required_buffer_length);

    if (!buffer_length || !buffer)
        return E_INVALIDARG;

    if (!lang)
    {
        if (!GetUserDefaultLocaleName(locale, LOCALE_NAME_MAX_LENGTH))
            return E_FAIL;

        lang = locale;
    }

    /* Return the original language as the fallback language list */
    lang_length = wcslen(lang) + 1;
    *required_buffer_length = lang_length;
    if (buffer_length < lang_length)
        return E_NOT_SUFFICIENT_BUFFER;

    memcpy(buffer, lang, lang_length * sizeof(WCHAR));
    return S_OK;
}

HRESULT WINAPI GetUserLanguages(WCHAR delim, HSTRING *langs)
{
    FIXME("%lc, %p\n", delim, langs);
    return S_OK;
}
