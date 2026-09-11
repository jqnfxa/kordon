/* An index from outside the program, checked for sign but never for range.
 *
 * The dynamic layer cannot be relied on for this class: the flawed branch is
 * taken only when rand() happens to return a positive value, so a sanitizer
 * reports nothing on the other runs. The code is wrong either way.
 *
 * @kordon cwe: 129, 124
 */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

/* FLAW: guarded against negative, never against the extent. */
void guard_form_bad(void)
{
    int data = (int)rand();
    int buffer[10] = {0};
    if (data >= 0)
    {
        buffer[data] = 1;
        printf("%d\n", buffer[data]);
    }
}

/* FLAW: same defect written as an early exit, which is how real code says it. */
void early_exit_bad(void)
{
    int data = (int)rand();
    int buffer[10] = {0};
    if (data < 0) return;
    buffer[data] = 1;
}

/* Not a finding: both sides tested. */
void guard_form_good(void)
{
    int data = (int)rand();
    int buffer[10] = {0};
    if (data >= 0 && data < 10)
    {
        buffer[data] = 1;
    }
}

/* Not a finding: the early-exit spelling of the same bound. */
void early_exit_good(void)
{
    int data = (int)rand();
    int buffer[10] = {0};
    if (data < 0 || data >= 10) return;
    buffer[data] = 1;
}

/* Not a finding: a loop counter is not an external value, and it is bounded.
 * Without the from-a-call clause this shape alone produced 160 positions
 * across two real projects. */
int loop_counter_good(const int *src)
{
    int total = 0;
    int buffer[10] = {0};
    for (int i = 0; i < 10; i++)
    {
        if (src[i] > 0) { total += buffer[i]; }
    }
    return total;
}

/* Not a finding: the bound is the argument handed to the call that produced
 * the index, not a comparison. `n = read(fd, buf, sizeof buf - 1); buf[n] = 0;`
 * is one of the most common idioms in C, and an equality test against zero is
 * an error check rather than a sign check. */
long read_terminate_good(int fd)
{
    char buf[256];
    long n = (long)read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) return n;
    buf[n] = '\0';
    return n;
}

/* --- the mirror: bounded above, never checked for negative --- */

/* FLAW: rejects too-large, never asks if it is negative. An index below zero
 * writes before the buffer. */
void upper_only_bad(void)
{
    int data = (int)rand();
    int buffer[10] = {0};
    if (data < 10)
    {
        buffer[data] = 1;
    }
}

/* FLAW: read() returns -1 on error, and nothing checks. This is why the
 * "bounded by its own call" exemption is sound for the upper bound and wrong
 * for the lower one. */
void read_negative_bad(int fd)
{
    char buf[256];
    int n = (int)read(fd, buf, sizeof(buf) - 1);
    if (n < 256)
    {
        buf[n] = '\0';
    }
}

/* Not a finding: an unsigned index cannot be negative, so the question does
 * not arise. Without the signedness clause this fires on every bounded loop
 * over a size_t. */
unsigned long unsigned_index_good(void)
{
    unsigned long n = (unsigned long)rand();
    int buffer[10] = {0};
    if (n < 10) { return (unsigned long)buffer[n]; }
    return 0;
}
