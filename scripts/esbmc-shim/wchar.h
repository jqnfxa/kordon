/* Minimal wchar.h for ESBMC.
 *
 * ESBMC ships models for stdio.h and string.h but not wchar.h, so including
 * the system one alongside them redefines FILE (struct _IO_FILE vs
 * __esbmc_file_t) and nothing parses. This declares only what Juliet uses and
 * pulls in no FILE definition, so ESBMC's own library models stay available. */
#ifndef ESBMC_SHIM_WCHAR_H
#define ESBMC_SHIM_WCHAR_H
#include <stddef.h>
size_t wcslen(const wchar_t *s);
wchar_t *wcscpy(wchar_t *d, const wchar_t *s);
wchar_t *wcsncpy(wchar_t *d, const wchar_t *s, size_t n);
wchar_t *wcscat(wchar_t *d, const wchar_t *s);
wchar_t *wcsncat(wchar_t *d, const wchar_t *s, size_t n);
int wcscmp(const wchar_t *a, const wchar_t *b);
wchar_t *wmemset(wchar_t *s, wchar_t c, size_t n);
wchar_t *wmemcpy(wchar_t *d, const wchar_t *s, size_t n);
wchar_t *wmemmove(wchar_t *d, const wchar_t *s, size_t n);
int wprintf(const wchar_t *fmt, ...);
#endif
