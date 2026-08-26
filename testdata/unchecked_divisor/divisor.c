/* An integer divisor that came from a call and is never compared to zero.
 *
 * core.DivideZero already reports the case where the divisor is provably
 * zero. It cannot bound a value that arrived from rand(), fscanf() or a
 * socket, and those are most of the ways this defect actually happens.
 */
#include <stdlib.h>
#include <stdio.h>

/* FLAW: divisor from a call, never checked. */
void divide_bad(void)
{
    int d = (int)rand();
    printf("%d\n", 100 / d);
}

/* FLAW: modulo is the same operation for this purpose. */
void modulo_bad(void)
{
    int d = (int)rand();
    printf("%d\n", 100 % d);
}

/* FLAW: compound assignment. */
void compound_bad(int x)
{
    int d = (int)rand();
    x /= d;
    printf("%d\n", x);
}

/* Not a finding: guarded. */
void divide_good(void)
{
    int d = (int)rand();
    if (d != 0) { printf("%d\n", 100 / d); }
}

/* Not a finding: guarded by an early return. */
void early_return_good(void)
{
    int d = (int)rand();
    if (d == 0) return;
    printf("%d\n", 100 / d);
}

/* Not a finding: the divisor is computed locally, not read from outside. */
void local_divisor_good(int n)
{
    int d = n + 1;
    printf("%d\n", 100 / d);
}

/* Not a finding: dividing a double by zero yields an infinity, not undefined
 * behaviour. Without this restriction the check reported 62 positions across
 * two real projects, nearly all of them `r = sqrt(x); p/r` in vendored code. */
void floating_divisor_good(void)
{
    double d = (double)rand();
    printf("%f\n", 100.0 / d);
}
