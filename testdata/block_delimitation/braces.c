/* Indentation that says one thing and the language another -- the goto-fail
 * shape. Only -Wmisleading-indentation reports it, and that warning is not on
 * by default, so Kordon turns it on itself. */
#include <stdlib.h>
#include "../../testdata/block_delimitation/print.h"

/* FLAW: the indentation says both statements belong to the if. Only the
 * first does. */
int forgot_the_braces_bad(int x)
{
    int y = 0;
    if (x == 0)
        print_line("x == 0");
        y = 1;
    return y;
}

/* Not a finding: the braces say what the indentation says. */
int with_braces_good(int x)
{
    int y = 0;
    if (x == 0)
    {
        print_line("x == 0");
        y = 1;
    }
    return y;
}

/* Not a finding: one statement, no ambiguity. */
int single_statement_good(int x)
{
    int y = 0;
    if (x == 0)
        y = 1;
    return y;
}
