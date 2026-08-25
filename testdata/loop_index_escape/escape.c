#define MAXSAT 64
int ssat[MAXSAT];
int table[16];

/* POSITIVE 1: loop with break, index used after the loop (the ddidx shape). */
int bad_with_break(int k)
{
    int i;
    for (i = k; i < k + MAXSAT; i++) {
        if (ssat[i - k] == 1) break;
    }
    return ssat[i - k];              /* i-k == MAXSAT when loop completes */
}

/* POSITIVE 2: loop with no break at all -- exit value is always the bound. */
int bad_no_break(void)
{
    int i;
    for (i = 0; i < 16; i++) {
        table[i] = 0;
    }
    return table[i];                 /* always table[16] */
}

/* NEGATIVE 1: index used INSIDE the loop only. */
int good_inside(void)
{
    int i, s = 0;
    for (i = 0; i < 16; i++) {
        s += table[i];
    }
    return s;
}

/* NEGATIVE 2: reassigned after the loop before use. */
int good_reassigned(void)
{
    int i;
    for (i = 0; i < 16; i++) { }
    i = 3;
    return table[i];
}

/* NEGATIVE 3: a different variable indexes after the loop. */
int good_other_var(int j)
{
    int i;
    for (i = 0; i < 16; i++) { }
    return table[j];
}

/* NEGATIVE 4: clamped after the loop -- the remediation shape. */
int good_clamped(void)
{
    int i;
    for (i = 0; i < 16; i++) { }
    if (i > 15) { i = 15; }
    return table[i];
}

/* NEGATIVE 5: early exit on the bound -- the other remediation shape. */
int good_early_exit(void)
{
    int i;
    for (i = 0; i < 16; i++) { if (table[i]) break; }
    if (i >= 16) { return -1; }
    return table[i];
}

/* NEGATIVE 6: the bound is short-circuited in the same && chain. */
int good_short_circuit(int n, int j)
{
    int i;
    for (i = 0; i < n && table[i] == 0; i++);
    return (i + j < n && table[i + j] == 1) ? 1 : 0;
}
