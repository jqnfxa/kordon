// Fixture: unsigned wraparound (CWE-191), guarded and unguarded.
//
// Synthetic. Paired cases: each unsafe function has a safe twin that differs
// only by a guard. The check must separate them -- flagging the guarded form
// would make it noise, and missing the unguarded form would make it useless.
//
// Why this class needs a Kordon-specific check at all: nothing else detects
// it. Verified against cppcheck (exhaustive), clang-tidy, Clang SA including
// alpha.core, and both gcc's and clang's warning sets -- none flags even a
// constant `size_t n = 0; return n - 1;`. That is not a tool deficiency.
// Unsigned wraparound is *well-defined* C++ (modular arithmetic), so there is
// nothing for a compiler to call erroneous. It is only a defect relative to
// what the programmer meant, which no tool can know.
//
// The consequence is what makes it worth reporting anyway: the wrapped value
// is not a small negative number, it is SIZE_MAX. Used as a length, an index
// or an allocation size it becomes a bounds violation (CWE-191 -> CWE-119).

#include <cstddef>
#include <vector>

namespace kordon_probe {

void consume(std::size_t);

// ------------------------------------------------------------ must be flagged

// The bare case: nothing establishes that k is non-zero.
void unguarded(std::size_t k)
{
    consume(k - 1);
}

// The dominant real-world shape: a size/dimension accessor minus one, used to
// build an inclusive upper bound. When the container is empty this is
// SIZE_MAX, not -1.
std::size_t last_index(const std::vector<int> &items)
{
    return items.size() - 1;
}

// Not a guard, and must not be treated as one: `k < n` says nothing about
// whether k is zero.
void unrelated_condition(std::size_t k, std::size_t n)
{
    if (k < n) {
        consume(k - 1);
    }
}

// --------------------------------------------------------- must NOT be flagged

// The canonical guard.
void guarded_greater(std::size_t k)
{
    if (k > 0) {
        consume(k - 1);
    }
}

// Same guarantee, written as an inequality.
void guarded_not_equal(std::size_t k)
{
    if (k != 0) {
        consume(k - 1);
    }
}

// Same guarantee again, as a lower bound.
void guarded_at_least_one(std::size_t k)
{
    if (k >= 1) {
        consume(k - 1);
    }
}

// ------------------------------------------------- known limit, still flagged

// An early return is a real guard, but the subtraction is not inside the `if`,
// so a purely syntactic matcher cannot see the relationship. Reported today;
// resolving it needs dataflow, i.e. the abstract-interpretation layer.
void guarded_by_early_return(std::size_t k)
{
    if (k == 0) {
        return;
    }
    consume(k - 1);
}

// Guard on a call rather than a variable. Correctly suppressed: the exemption
// binds the callee and the object separately, since the two call expressions
// are distinct AST nodes and comparing them directly would never match.
std::size_t guarded_call(const std::vector<int> &items)
{
    if (items.size() > 0) {
        return items.size() - 1;
    }
    return 0;
}

}  // namespace kordon_probe

// ---------------------------------------------------------------- CWE-190
//
// The mirror class: addition that wraps past the type maximum instead of
// growing. Same detection story as the subtraction above -- unsigned overflow
// is well-defined, so no compiler calls it erroneous.
//
// The characteristic real-world shape is an inclusive extent computed as
// `end - begin + 1`. When the subtraction already underflowed, the `+ 1`
// turns SIZE_MAX into 0, and a loop bounded by it runs zero times instead of
// once -- silently producing an empty result rather than crashing.

namespace kordon_probe {

struct Roi {
    std::size_t left() const;
    std::size_t right() const;
};

// `right() - left()` underflows when right < left, then + 1 wraps to zero.
std::size_t inclusive_width(const Roi &roi)
{
    return roi.right() - roi.left() + 1;
}

// A loop bound built the same way: if the bound wraps to 0 the body never
// runs, which is a silent wrong answer rather than a crash.
std::size_t count_columns(const Roi &roi)
{
    std::size_t n = 0;
    for (std::size_t x = roi.left(); x < roi.right() + 1; ++x) {
        ++n;
    }
    return n;
}

}  // namespace kordon_probe

// -------------------------------------------------- guard on a class member
//
// This is how the reference codebase actually wrote its fixes, and it is the
// case that decides whether the check is useful at all: before the member
// guard was understood, the check reported corrected code identically to the
// broken code, which makes a high recall number meaningless.

namespace kordon_probe {

class Frame {
public:
    void build();
private:
    Roi m_roi;
    std::size_t m_width = 0;
};

void Frame::build()
{
    // Guarded via a member's accessor -- must NOT be flagged.
    if (m_roi.right() > 0) {
        consume(m_roi.right() - 1);
    }
}

// Precondition validated by an early throw. Safe, but still reported: the
// subtraction is not inside the guard, the guard compares a different pair,
// and it relies on the throw not returning. Needs dataflow, not matching.
std::size_t validated_extent(const Roi &roi)
{
    if (roi.left() > roi.right()) {
        throw "bad roi";
    }
    return roi.right() - roi.left() + 1;
}

}  // namespace kordon_probe

// ------------------------------------------- guarded by the loop initialiser
//
// `for (i = 1; ...) v[i - 1]` is idiomatic and safe, and the guard is the
// loop's initialiser rather than any condition, so none of the `if`-based
// exemptions can see it. Found by running against a real project where two of
// the three reported defects were exactly this shape.

namespace kordon_probe {

std::size_t running_total(const std::vector<std::size_t> &v)
{
    std::size_t total = 0;
    // Starts at 1, so `i - 1` can never underflow. Must NOT be flagged.
    for (std::size_t i = 1; i < v.size(); ++i) {
        total += v[i] - v[i - 1];
    }
    return total;
}

std::size_t from_zero(const std::vector<std::size_t> &v)
{
    std::size_t total = 0;
    // Starts at 0, so the first iteration underflows. Must be flagged.
    for (std::size_t i = 0; i < v.size(); ++i) {
        total += v[i - 1];
    }
    return total;
}

}  // namespace kordon_probe
