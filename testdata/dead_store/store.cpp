// Fixture: values computed, stored, and never read.
//
// Synthetic. The distinction this fixture exists to hold is the one that makes
// CWE-563 useful rather than noisy:
//
//   double w = 0.0;  w = compute();     defensive initialisation -- harmless,
//                                       idiomatic, and reported by nobody here
//   var += i;  /* var never read */     work done and thrown away
//
// The first costs nothing. The second is either a wasted computation or, more
// often, a symptom that a result was meant to go somewhere and does not.

namespace kordon_probe {

double compute();
void sink(int *p);
void by_reference(int &r);

// ------------------------------------------------------------- must be flagged

// The accumulator: read only to feed itself, so its value never leaves the
// cycle. clang-analyzer's DeadStores does not report this -- the compound
// assignment reads `var`, and its liveness analysis stops there.
double accumulator_never_used(int n)
{
    int var = 0;
    double sum = 0.0;
    for (int i = 0; i < n; ++i) {
        sum += static_cast<double>(i) * 10.0;
        var += i;
    }
    return sum;
}

// The plain case: stored, then the function returns something else.
double stored_then_discarded(double x)
{
    double v = x;
    v = compute();
    return x;
}

// Outputs taken by value. The function computes both results and throws them
// away; every caller gets nothing. Somebody meant `double &`. This shape was
// found in real code and no other engine reports it.
void outputs_by_value(double angle, double tilt, double out_a, double out_b)
{
    out_a = angle * 2.0;
    out_b = tilt * 3.0;
}

// ------------------------------------------------------------ must stay silent

// Defensive initialisation, overwritten before it is read. Harmless.
double defensive_init()
{
    double w = 0.0;
    w = compute();
    return w;
}

// Accumulated and then actually used.
double accumulator_used(int n)
{
    int var = 0;
    for (int i = 0; i < n; ++i) {
        var += i;
    }
    return static_cast<double>(var);
}

// The address escapes, so a read can happen anywhere.
void address_taken()
{
    int a = 0;
    a = 5;
    sink(&a);
}

// Bound to a reference, same reasoning.
void passed_by_reference()
{
    int a = 0;
    a = 5;
    by_reference(a);
}

// A volatile write is observable even when nothing reads it back.
void volatile_write()
{
    volatile int a = 0;
    a = 5;
}

// Written through a reference parameter, which is how an out-parameter is
// meant to look. The contrast with outputs_by_value above is the whole point.
void outputs_by_reference(double angle, double &out_a)
{
    out_a = angle * 2.0;
}

}  // namespace kordon_probe
