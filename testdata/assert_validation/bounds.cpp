// Fixture: validation that only exists in debug builds (CWE-754 -> CWE-119).
//
// Synthetic. `assert(cond)` expands to nothing when NDEBUG is defined, so a
// function whose only precondition check is an assert has no check at all in
// the build that ships.
//
// This is invisible to every other engine, and not because they are weak: the
// assert is gone before any analyser sees the translation unit, so they
// correctly report a function with no check and no problem. Only a tool that
// deliberately restores the assert -- and knows the real build defines NDEBUG
// -- can say anything.
//
// Modelled on a real matrix library where `matMult` validated its dimensions
// with nothing but an assert and then indexed the second operand using the
// first operand's extent. Two of the defects its maintainers still list as
// open are exactly this, and they were the only positions in that class no
// engine reached.
//
// Needs the compile database in this directory, which defines NDEBUG the way
// the real build does. Without one the check stays silent by design: with no
// build flags to consult, "this is compiled out" would be a guess.

#include <cassert>
#include <cstddef>

namespace kordon_probe {

struct Matrix {
    double *data;
    std::size_t rows;
    std::size_t cols;
    double &at(std::size_t r, std::size_t c) { return data[r * cols + c]; }
};

// ------------------------------------------------------------- must be flagged

// The only thing standing between a mismatched pair and an out-of-bounds write
// is an assert, and this build has no asserts.
void multiply(Matrix &a, Matrix &b, Matrix &out)
{
    assert(a.cols == b.rows);

    for (std::size_t i = 0; i < a.rows; ++i) {
        for (std::size_t j = 0; j < b.cols; ++j) {
            for (std::size_t k = 0; k < a.cols; ++k) {
                // Bounded by a.cols; indexes b by k. If the assert were false
                // and absent, this runs off the end of b.
                out.at(i, j) += a.at(i, k) * b.at(k, j);
            }
        }
    }
}

// --------------------------------------------------------- must NOT be flagged

// The same precondition, enforced by something that survives the optimizer.
// A real check, so nothing to report.
bool multiply_checked(Matrix &a, Matrix &b, Matrix &out)
{
    if (a.cols != b.rows) {
        return false;
    }

    for (std::size_t i = 0; i < a.rows; ++i) {
        for (std::size_t j = 0; j < b.cols; ++j) {
            for (std::size_t k = 0; k < a.cols; ++k) {
                out.at(i, j) += a.at(i, k) * b.at(k, j);
            }
        }
    }
    return true;
}


// ------------------------- assert AND a real check: must NOT be flagged
//
// The idiom that decides whether this check is usable. `assert` documents the
// precondition and the `if` enforces it; the enforcement survives NDEBUG, so
// there is nothing to report. Before this case existed the check flagged it,
// which would have made every properly-defended function a finding.
//
// The two are told apart structurally rather than by guesswork: `assert(c)`
// expands to the ternary `c ? (void)0 : __assert_fail(...)` and never to an
// `if`, so any ifStmt in the function is code that survives the macro.

void multiply_asserted_and_checked(Matrix &a, Matrix &b, Matrix &out)
{
    assert(a.cols == b.rows);
    if (a.cols != b.rows) {
        return;
    }

    for (std::size_t i = 0; i < a.rows; ++i) {
        for (std::size_t j = 0; j < b.cols; ++j) {
            for (std::size_t k = 0; k < a.cols; ++k) {
                out.at(i, j) += a.at(i, k) * b.at(k, j);
            }
        }
    }
}

// The same pair for plain parameters rather than members, since the exemption
// has to recognise both ways of naming a value.

void fill_asserted_only(std::size_t n, std::size_t capacity, double *p)
{
    assert(n <= capacity);                      // must be flagged
    for (std::size_t i = 0; i < n; ++i) {
        p[i] = 0.0;
    }
}

void fill_asserted_and_checked(std::size_t n, std::size_t capacity, double *p)
{
    assert(n <= capacity);
    if (n > capacity) {                         // must NOT be flagged
        return;
    }
    for (std::size_t i = 0; i < n; ++i) {
        p[i] = 0.0;
    }
}
}  // namespace kordon_probe
