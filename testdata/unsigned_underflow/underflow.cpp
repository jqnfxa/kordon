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

// ------------------------------------------------- known limits, still flagged

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

// Also a real guard, also still reported: the operand is a call rather than a
// variable, so there is no declaration to tie the condition and the
// subtraction together.
std::size_t guarded_call(const std::vector<int> &items)
{
    if (items.size() > 0) {
        return items.size() - 1;
    }
    return 0;
}

}  // namespace kordon_probe
