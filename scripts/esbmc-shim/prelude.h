/* Declarations ESBMC's own header models are missing, force-included ahead of
 * every translation unit.
 *
 * `alloca` is the one that matters and it cost a measurement. glibc declares
 * it from <stdlib.h>; ESBMC's model of <stdlib.h> does not, and Juliet never
 * includes <alloca.h>. In C that makes every `ALLOCA(n)` an *implicit*
 * declaration returning `int`, so the returned pointer is a truncated integer
 * and ESBMC reports `dereference failure: invalid pointer freed` at the
 * closing brace where the frame is released -- in the *corrected* function,
 * which is a false positive with no defect anywhere near it. Two of the three
 * false positives measured on CWE-121's good halves were exactly this, and
 * both are cases with `alloca` in the file name.
 *
 * A real compiler does not have this problem, so it is a property of running
 * the suite under ESBMC's headers rather than anything about the code.
 *
 * Declaring it is not enough: glibc's <alloca.h> also defines the macro that
 * routes the call to `__builtin_alloca`, and the *builtin* is what ESBMC
 * models. With only the prototype the run still fails the same way -- measured
 * both ways before writing this. */
#ifndef ESBMC_SHIM_PRELUDE_H
#define ESBMC_SHIM_PRELUDE_H
#include <stddef.h>
void *alloca(size_t size);
#undef alloca
#define alloca(size) __builtin_alloca(size)
#endif
