/* An integer divisor that came from a call and is never compared to zero.
 *
 * core.DivideZero already reports the case where the divisor is provably
 * zero. It cannot bound a value that arrived from rand(), fscanf() or a
 * socket, and those are most of the ways this defect actually happens.
 *
 * @kordon cwe: 369
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

/* Advice, not an error. IEEE 754 defines this: the division yields an
 * infinity rather than trapping. Still usually a mistake -- the infinity
 * propagates silently into every later result and surfaces as a nonsensical
 * number rather than a crash, which is harder to diagnose. Same confidence as
 * the integer case, lower severity, which is what the two axes are for. */
void floating_divisor_advice(void)
{
    double d = (double)rand();
    printf("%f\n", 100.0 / d);   /* @expect 369 -- reported, as advice */
}
