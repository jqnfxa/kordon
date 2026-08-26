/* Bodies for the wide-string functions, so ESBMC can reason about them.
 *
 * ESBMC ships models for the narrow string functions in its own
 * `c2goto/library/string.c` -- `strlen`, `strcpy`, `memcpy` and friends are
 * understood, and bounds derived from them are provable. It ships nothing for
 * `wchar.h`. Declaring the wide functions (see wchar.h next to this file) is
 * enough to make a file parse, but a declared-and-undefined function is
 * *havoc*: ESBMC prints "no body for function wcslen" and then assumes the
 * call could have done anything to the memory reachable through its pointer
 * arguments. Measured consequence: two of three false positives on the
 * corrected halves of CWE-121 were `dereference failure: invalid pointer
 * freed` raised at the closing brace of a function whose only wide-string
 * calls were unmodelled ones. The engine was not wrong about its own state --
 * the state was fabricated by the missing model.
 *
 * These are the obvious loop implementations. They are symbolically executed
 * like any other code, so `--unwind` has to exceed the longest string in play
 * or the loops become unwinding assertions -- undecided, which is at least
 * honest, unlike a havoc.
 */

#include <stddef.h>

size_t wcslen(const wchar_t *s)
{
    size_t n = 0;
    while (s[n] != L'\0') n++;
    return n;
}

wchar_t *wcscpy(wchar_t *d, const wchar_t *s)
{
    size_t i = 0;
    for (; s[i] != L'\0'; i++) d[i] = s[i];
    d[i] = L'\0';
    return d;
}

wchar_t *wcsncpy(wchar_t *d, const wchar_t *s, size_t n)
{
    size_t i = 0;
    for (; i < n && s[i] != L'\0'; i++) d[i] = s[i];
    for (; i < n; i++) d[i] = L'\0';
    return d;
}

wchar_t *wcscat(wchar_t *d, const wchar_t *s)
{
    size_t i = wcslen(d), j = 0;
    for (; s[j] != L'\0'; j++) d[i + j] = s[j];
    d[i + j] = L'\0';
    return d;
}

wchar_t *wcsncat(wchar_t *d, const wchar_t *s, size_t n)
{
    size_t i = wcslen(d), j = 0;
    for (; j < n && s[j] != L'\0'; j++) d[i + j] = s[j];
    d[i + j] = L'\0';
    return d;
}

int wcscmp(const wchar_t *a, const wchar_t *b)
{
    size_t i = 0;
    while (a[i] != L'\0' && a[i] == b[i]) i++;
    return (int)(a[i] - b[i]);
}

wchar_t *wmemset(wchar_t *d, wchar_t c, size_t n)
{
    for (size_t i = 0; i < n; i++) d[i] = c;
    return d;
}

wchar_t *wmemcpy(wchar_t *d, const wchar_t *s, size_t n)
{
    for (size_t i = 0; i < n; i++) d[i] = s[i];
    return d;
}

wchar_t *wmemmove(wchar_t *d, const wchar_t *s, size_t n)
{
    if (d < s) { for (size_t i = 0; i < n; i++) d[i] = s[i]; }
    else { for (size_t i = n; i > 0; i--) d[i - 1] = s[i - 1]; }
    return d;
}
