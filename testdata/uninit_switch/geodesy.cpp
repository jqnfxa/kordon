// Fixture: a switch that does not cover its enum, over a struct nobody zeroed.
//
// Synthetic. The shape is a plain C-style parameter struct passed by value,
// populated by a switch on a coordinate-system enum, then post-processed
// unconditionally.
//
// The defect is not in any single line. It is a three-way conspiracy:
//
//   1. HelmertParams has no initializer and no constructor, so a local
//      instance holds whatever was on the stack.
//   2. The switch assigns its fields for only some of the enumerators. The
//      `default:` branch is present -- which makes the code *look* exhaustive
//      to a reviewer and silences -Wswitch -- but it assigns nothing.
//   3. The scaling step after the switch runs unconditionally and reads the
//      fields regardless of which branch ran.
//
// Pass an enumerator the switch does not handle (GSK_2011 below, a perfectly
// legitimate member of the enum) and `params.w *= DEG_PER_RAD` becomes
// `garbage * DEG_PER_RAD`. Clang SA phrases this as "The left operand of '*='
// is a garbage value" -- check core.UndefinedBinaryOperatorResult, which
// Kordon maps to CWE-457.
//
// Note the empty `default:` is what makes this dangerous rather than merely
// wrong. Without it, -Wswitch warns at compile time that enumerators are
// unhandled and the defect never ships. With it, the compiler is satisfied and
// the only remaining signal is a path-sensitive analyzer following a caller
// that passes an unhandled value.
//
// CWE-457 (Use of Uninitialized Variable), reached via CWE-665-style improper
// initialization of the struct. Same family as a switch-with-no-default whose
// locals are returned uninitialized, but with the opposite trigger: here the
// default branch exists and is empty.

namespace kordon_probe {

const double DEG_PER_RAD = 57.29577951308232;

enum CoordSystem {
    WGS_84 = 0,
    ITRF_2008,
    GSK_2011,   // in the enum, absent from the switch
    PZ_90       // likewise
};

// Plain aggregate. No default member initializers, deliberately.
struct HelmertParams {
    double dx;
    double dy;
    double dz;
    double w;      // rotation, radians -> degrees after the switch
    double scale;
};

// Fills `params` for the systems it knows about. Silently leaves it untouched
// for the others.
//
// `params` is an out-parameter by reference, not a local, and that detail
// decides whether this is findable at all. Analyzing this function on its own,
// the analyzer has no reason to believe the caller's object is uninitialized --
// it is an ordinary reference from outside, so the read below is unremarkable.
// The defect only becomes visible once a caller that passes an *uninitialized
// local* is in view. Verified both ways: with the caller present Clang SA
// reports the garbage read; with the caller removed it reports nothing at all.
//
// So a public API of this shape is only diagnosable when its callers are in the
// same translation unit, or when CTU is enabled. Callers elsewhere in the
// project are invisible without it.
static void load_params(CoordSystem system, HelmertParams &params)
{
    switch (system) {
    case WGS_84: {
        params.dx = 0.0;
        params.dy = 0.0;
        params.dz = 0.0;
        params.w = 0.0;
        params.scale = 1.0;
        break;
    }
    case ITRF_2008: {
        params.dx = 0.013;
        params.dy = -0.007;
        params.dz = 0.003;
        params.w = 0.000001;
        params.scale = 1.0000000021;
        break;
    }
    default: {
        // Nothing. Looks deliberate, assigns nothing, and stops -Wswitch
        // from ever mentioning GSK_2011 or PZ_90.
        break;
    }
    }
}

// The unconditional post-processing step, in the same function that ran the
// switch and on the same out-parameter -- which is how this shape appears in
// practice. Reads `params` regardless of whether any case populated it.
void scale_params(CoordSystem system, HelmertParams &params)
{
    load_params(system, params);

    // Garbage on any system the switch does not handle.
    params.w *= DEG_PER_RAD;
}

double transform(CoordSystem system, double x)
{
    HelmertParams params;   // uninitialized stack memory

    scale_params(system, params);

    return x * params.scale + params.dx + params.w;
}

// Concrete caller reaching the bad path. Without a call site passing an
// unhandled enumerator, the analyzer has no reason to explore it.
double transform_gsk()
{
    return transform(GSK_2011, 100.0);
}

}  // namespace kordon_probe
