// Fixture: failure reported only by returning an empty container.
//
// Synthetic. Modelled on real image code in a project built without
// exceptions, where the idiom is pervasive: a function allocates its result,
// takes an early exit if the allocation failed, and signals that failure by
// returning the empty container it just built. Nothing in the signature says
// so. Two callers in the same file indexed the result unchecked; a vendor
// report caught one of them.
//
// The producing side is reachable rather than theoretical -- the container
// allocates with `new (std::nothrow)`, so the null path is a real allocation
// failure and not a branch that can only be taken if a throwing `new` returned
// null. See `testdata/allocator_fallibility/alloc.cpp` for why that
// distinction decides the whole family.
//
// Two properties are being pinned here, and they pull in opposite directions:
//
//   1. the defect -- a container returned across a function boundary whose
//      emptiness is the only failure signal, indexed by a caller that never
//      asks;
//   2. the exemption -- `init(n)` followed by `isNullPointer()` establishes an
//      extent, and a whole group of correctly-defended functions in the same
//      codebase was reported because nothing recognised that pair.
//
// It is a two-function property, so it needs cross-TU or at least same-TU
// interprocedural reach. Everything here is in one translation unit
// deliberately: this fixture asks whether the shape can be recognised at all,
// not whether it survives a TU boundary. `testdata/zero_length_ctu/` is the
// fixture for that second question.
//
// What Kordon actually reports on this file is recorded once, in
// docs/acl-report-findings.md under "Fixtures". It is kept there rather
// than here so six copies cannot drift apart.

#include <cstddef>
#include <new>

namespace kordon_probe {

void use(double);

class Vector {
public:
    // Returns false when the allocation failed. Every caller in the real code
    // discarded this, which is the CWE-252 half of the defect: honouring the
    // return closes the bounds issue at its source, and no length check is
    // needed at all.
    bool init(int n)
    {
        delete[] m_data;
        m_data = new (std::nothrow) double[static_cast<std::size_t>(n)];
        m_length = (m_data != nullptr) ? n : 0;
        return m_data != nullptr;
    }

    ~Vector() { delete[] m_data; }

    Vector() = default;
    Vector(const Vector &) = delete;
    Vector &operator=(const Vector &) = delete;

    bool isNullPointer() const { return m_data == nullptr; }
    int getLength() const { return m_length; }

    double &operator[](int i) { return m_data[i]; }

private:
    double *m_data = nullptr;
    int m_length = 0;
};

struct CornerCoord {
    Vector xCords;
    Vector yCords;
};

// ---------------------------------------------------------------------------
// The producer. Its only way of saying "this failed" is to hand back the
// containers still empty.
// ---------------------------------------------------------------------------

void find_corners(CornerCoord &out, int width, int height)
{
    if (!out.xCords.init(4) || !out.yCords.init(4)) {
        return;                 // the ONLY failure signal: both stay null
    }

    out.xCords[0] = 0.0;
    out.xCords[1] = static_cast<double>(width);
    out.xCords[2] = static_cast<double>(width);
    out.xCords[3] = 0.0;

    out.yCords[0] = 0.0;
    out.yCords[1] = 0.0;
    out.yCords[2] = static_cast<double>(height);
    out.yCords[3] = static_cast<double>(height);
}

// ------------------------------------------------------------- must be flagged

// The caller takes the result and indexes it. On the failure path `operator[]`
// is `return m_data[j];` with `m_data == nullptr`.
void calc_bounds(int width, int height)
{
    CornerCoord corner;
    find_corners(corner, width, height);
    use(corner.xCords[0]);
    use(corner.yCords[0]);
}

// The sibling that shares the defect. In the real code only one of the two was
// reported; both needed the identical fix, so a detector that finds one and
// not the other has found half the defect.
void default_find_scale(int width, int height)
{
    CornerCoord corner;
    find_corners(corner, width, height);
    use(corner.xCords[1] - corner.xCords[0]);
}

// The same defect one step further out: a void function returns early when its
// own check trips, leaving a container unsized that the caller then indexes.
// The guard is what creates the bug -- without it the code would at least have
// been consistently wrong.
void resize_pyramid(Vector &levels, int count)
{
    if (count > 64) {
        return;                 // caller is never told
    }
    levels.init(count);
}

void build_pyramid(int count)
{
    Vector levels;
    resize_pyramid(levels, count);
    levels[0] = 1.0;            // a write: `levels` is null when the guard tripped
    use(levels[0]);             // read it back, so the write is not a dead store
}

// ------------------------------------------------------------ must stay silent

// The producer's failure signal, honoured. This is the fix that was actually
// applied, and it is a return-value check rather than a length check.
void calc_bounds_checked(int width, int height)
{
    CornerCoord corner;
    find_corners(corner, width, height);
    if (corner.xCords.isNullPointer() || corner.yCords.isNullPointer()) {
        return;
    }
    use(corner.xCords[0]);
    use(corner.yCords[0]);
}

// `init(n)` then `isNullPointer()` establishes the extent. A whole group of
// correctly-defended functions was reported for want of this pair, so a
// detector that flags this one has reproduced the vendor's own false positive.
void rotation_matrix(Vector &out)
{
    out.init(3);
    if (out.isNullPointer()) {
        return;
    }
    out[0] = 1.0;
    out[1] = 0.0;
    out[2] = 0.0;
}

// The same pair with the extra dimension checks the real corrected code
// carried. Three guards stand between entry and the subscript.
void precondition_then_init(Vector &out, int n, const Vector &r)
{
    if (n <= 0 || r.getLength() < n) {
        return;
    }
    if (!out.init(n)) {
        return;
    }
    if (out.isNullPointer()) {
        return;
    }
    out[0] = 0.0;
}

}  // namespace kordon_probe
