/* Ignoring a return value that tells you whether the data is real.
 *
 * The rule for Kordon's CHECKED_FUNCTIONS list: ignoring the result must
 * leave the program using a value it did not compute. Parsers and readers
 * qualify. `snprintf` does not -- its result says the output was truncated --
 * and it was the noisiest name on the list before it was removed.
 */
#include <stdio.h>
#include <stdlib.h>

/* FLAW: if the parse fails, v keeps whatever it held. */
double parse_bad(const char *text)
{
    double v = 0.0;
    sscanf(text, "%lf", &v);
    return v;
}

/* FLAW: if the read fails, buf holds stale bytes. */
void read_bad(FILE *fp, char *buf, int n)
{
    fgets(buf, n, fp);
    printf("%s", buf);
}

/* Not a finding: the result decides what happens next. */
double parse_good(const char *text)
{
    double v = 0.0;
    if (sscanf(text, "%lf", &v) != 1) { return 0.0; }
    return v;
}

/* Not a finding: snprintf is not on the list. Its result reports truncation,
 * not an uncomputed value, and treating it as a defect produced 19 of 20
 * surfaced positions on a real project from a single error-reporting macro. */
void format_good(char *out, int n, int code)
{
    snprintf(out, n, "error %d", code);
}
