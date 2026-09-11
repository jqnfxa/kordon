// Fixture: identical call sites, opposite verdicts -- the allocator decides.
//
// Synthetic. Modelled on a real codebase carrying two container classes three
// directories apart in the same module tree, indistinguishable where they are
// used:
//
//     container.init(N);
//     use(container[0]);          // no length check, in both cases
//
// One allocates with plain `new`, which throws on failure and so can never
// hand back an empty container: reaching the subscript at all proves the
// allocation succeeded. The other allocates with `new (std::nothrow)`, which
// returns null, so the same two lines are a genuine null dereference. A vendor
// report flagged both and was right exactly once.
//
// The lesson recorded with this fixture: this family cannot be adjudicated at
// the call site. Deciding it means resolving which allocation the container
// ultimately performs, and a detector without that will either miss the real
// one or flood on the safe one. The cheap approximation is to classify
// container types once by their allocation call and say which assumption the
// finding rests on, so a reader can overrule it in one step.
//
// `testdata/fallible_init/container.cpp` covers the nothrow constructor on its
// own. What is new here is the *pair*: a check that flags both has learned
// nothing, and a check that flags neither is silent on a real defect.
//
// What Kordon actually reports on this file is recorded once, in
// docs/acl-report-findings.md under "Fixtures". It is kept there rather
// than here so six copies cannot drift apart.

#include <cstddef>
#include <cstdlib>
#include <new>

namespace kordon_probe {

// Each subscript below is written before it is read. Reading `v[0]` alone
// makes all three functions fire on the array's uninitialised contents --
// `new double[n]` does not zero -- which is a real defect but not the one this
// pair asks about, and it fires identically on the safe container. Measured:
// with bare reads, all three were flagged and the fixture discriminated
// exactly zero. Writing and then reading removes that confound, and the
// trailing read keeps the write from being a dead store.
void use(double);

// ---------------------------------------------------------------------------
// Infallible: plain `new`. Failure leaves by exception, never by return.
// ---------------------------------------------------------------------------

class ThrowingVec {
public:
    void init(int n)
    {
        delete[] m_data;
        m_data = new double[static_cast<std::size_t>(n)];  // throws on failure
        m_size = n;
    }

    ~ThrowingVec() { delete[] m_data; }

    ThrowingVec(const ThrowingVec &) = delete;
    ThrowingVec &operator=(const ThrowingVec &) = delete;
    ThrowingVec() = default;

    double &operator[](int i) { return m_data[i]; }

private:
    double *m_data = nullptr;
    int m_size = 0;
};

// ---------------------------------------------------------------------------
// Fallible: `new (std::nothrow)`. Failure is reported by returning null, and
// the only way to learn about it is to ask.
// ---------------------------------------------------------------------------

class NothrowVec {
public:
    void init(int n)
    {
        delete[] m_data;
        m_data = new (std::nothrow) double[static_cast<std::size_t>(n)];
        m_size = n;
    }

    ~NothrowVec() { delete[] m_data; }

    NothrowVec(const NothrowVec &) = delete;
    NothrowVec &operator=(const NothrowVec &) = delete;
    NothrowVec() = default;

    bool isNullPointer() const { return m_data == nullptr; }

    double &operator[](int i) { return m_data[i]; }

private:
    double *m_data = nullptr;
    int m_size = 0;
};

// ------------------------------------------------------------- must be flagged

// The allocation can return null and nobody asked. Character for character the
// same two statements as `polynomial_coefficients` below.
void image_corners()
{
    NothrowVec v;
    v.init(4);
    v[0] = 1.0;                 // null on the failure path
    use(v[0]);
}

// ------------------------------------------------------------ must stay silent

// `init(3)` either yields three elements or propagates an exception, so the
// subscript is unreachable with an empty container. Flagging this is the
// false positive the pair exists to catch.
void polynomial_coefficients()
{
    ThrowingVec v;
    v.init(3);
    v[0] = 1.0;
    use(v[0]);
}

// The fallible container used correctly.
void image_corners_checked()
{
    NothrowVec v;
    v.init(4);
    if (v.isNullPointer()) {
        return;
    }
    v[0] = 1.0;
    use(v[0]);
}

// ---------------------------------------------------------------------------
// The zero-size sibling: an allocator that returns a non-null pointer to
// nothing, so the null check passes and proves nothing.
// ---------------------------------------------------------------------------
//
// `calloc(n, 0)` -- and `calloc(0, n)`, and `malloc(0)` -- may return a unique
// non-null pointer to a zero-byte block. `if (!p) return;` accepts it, and the
// first subscript is out of bounds. This is what makes a runtime-zero extent
// unsafe even in code that does check its allocation, and it is a distinct
// hazard from "the allocation failed".

// Must be flagged: the null check passes for a zero-element block.
double *zero_element_block(std::size_t n, std::size_t elem_size)
{
    double *p = static_cast<double *>(std::calloc(n, elem_size));
    if (!p) {
        return nullptr;
    }
    p[0] = 0.0;                 // elem_size == 0 or n == 0 -> out of bounds
    return p;
}

// Must stay silent: the extent is established before the block is touched.
double *zero_element_block_checked(std::size_t n, std::size_t elem_size)
{
    if (n == 0 || elem_size == 0) {
        return nullptr;
    }
    double *p = static_cast<double *>(std::calloc(n, elem_size));
    if (!p) {
        return nullptr;
    }
    p[0] = 0.0;
    return p;
}

}  // namespace kordon_probe
