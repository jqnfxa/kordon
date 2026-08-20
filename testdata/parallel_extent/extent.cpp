// Fixture: a loop bounded by one object's extent subscripts another.
//
// Synthetic. Modelled on a real vector class whose arithmetic operators loop
// over `this` object's length while indexing the operand, with nothing but an
// assert to say the two agree. Under NDEBUG the assert is gone and a shorter
// operand is read out of bounds.
//
// The safe twins matter as much as the defect: a check that flags all four of
// these is counting syntax, not finding a defect. The corrected form of the
// real code added exactly the `if` in `add_checked` below, so that shape must
// silence the check, while the assert alone must not.

#include <cassert>
#include <cstddef>

namespace kordon_probe {

class Vec {
public:
    double &operator[](int i) { return m_data[i]; }
    double operator[](int i) const { return m_data[i]; }

    void add_asserted(Vec &v);
    void add_unchecked(Vec &v);
    void add_checked(Vec &v);
    void add_over_own_extent(Vec &v);

    int m_length;

private:
    double *m_data;
};

// ------------------------------------------------------------- must be flagged

// The assert is the only validation, and it expands to nothing under NDEBUG.
void Vec::add_asserted(Vec &v)
{
    assert(m_length == v.m_length);
    for (int i = 0; i < m_length; i++) {
        m_data[i] += v[i];
    }
}

// The same defect stated plainly, with not even an assert.
void Vec::add_unchecked(Vec &v)
{
    for (int i = 0; i < m_length; i++) {
        m_data[i] += v[i];
    }
}

// ------------------------------------------------------------ must stay silent

// A real check that survives NDEBUG. This is the shape the corrected reference
// code used, and the reason the exemption looks for an `ifStmt` specifically.
void Vec::add_checked(Vec &v)
{
    assert(m_length == v.m_length);
    if (v.m_length < m_length) {
        return;
    }
    for (int i = 0; i < m_length; i++) {
        m_data[i] += v[i];
    }
}

// Bounded by the extent of the very object being subscripted. Safe by
// construction, and common enough that missing this exemption buried the
// check in a single file of `push_back(list[i])` loops.
void Vec::add_over_own_extent(Vec &v)
{
    for (int i = 0; i < v.m_length; i++) {
        m_data[i] += v[i];
    }
}

// ---------------------------------------------------------------------------
// Constant index: a parameter indexed at a fixed position.
// ---------------------------------------------------------------------------

class Mat {
public:
    double operator()(int r, int c) const { return m_data[r * m_cols + c]; }
    int getRows() const { return m_rows; }
    int getCols() const { return m_cols; }

private:
    double *m_data;
    int m_rows;
    int m_cols;
};

// Must be flagged: assumes R is at least 3x3, and says so nowhere.
double trace3_unchecked(const Mat &R)
{
    return R(0, 0) + R(1, 1) + R(2, 2);
}

// Must stay silent: the extent is tested before use. This is the shape the
// corrected reference code used.
double trace3_checked(const Mat &R)
{
    if (R.getRows() < 3 || R.getCols() < 3) {
        return 0.0;
    }
    return R(0, 0) + R(1, 1) + R(2, 2);
}

// Must stay silent: a test of the stored *value* is not a test of the extent,
// but it must not be mistaken for one in either direction -- this function
// checks the extent as well, so it is genuinely safe.
double trace3_value_test(const Mat &R)
{
    if (R.getRows() < 3 || R.getCols() < 3) {
        return 0.0;
    }
    double x = R(0, 0);
    if (R(1, 1) < 0) {
        x = -x;
    }
    return x;
}

}  // namespace kordon_probe
