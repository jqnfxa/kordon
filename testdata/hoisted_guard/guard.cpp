// Fixture: a precondition hoisted into a local bool, asserted, then enforced.
//
// Synthetic. Modelled on a real matrix library whose maintainers replaced bare
// asserts with real checks across an entire file, writing the precondition
// once into a `const bool` and branching on that:
//
//     const bool condition = a.rows() == b.rows() && !b.isNull() && !a.isNull();
//     assert(condition);
//     if (!condition) { return; }
//
// `kordon-unchecked-parallel-extent` fires on this shape. Its exemption looks
// for an `ifStmt` whose condition *mentions the subscripted parameter*, and
// here the `if` names only the local. The enforcement is real, survives
// NDEBUG, and the check cannot see it.
//
// This false positive is distributed in the worst possible way: it fires
// exactly on the functions where someone already applied the remediation, and
// stays quiet on the ones still relying on the assert alone. A check that
// penalises the fix is worse than no check, which is why this fixture exists
// before the fix does.
//
// `testdata/parallel_extent/extent.cpp` covers the form where the `if` tests
// the extent expression directly; that one is already exempt. The difference
// between the two files is the whole bug.
//
// What Kordon actually reports on this file is recorded once, in
// docs/acl-report-findings.md under "Fixtures". It is kept there rather
// than here so six copies cannot drift apart.

#include <cassert>
#include <cstddef>

namespace kordon_probe {

class Vec {
public:
    double &operator[](int i) { return m_data[i]; }
    double operator[](int i) const { return m_data[i]; }

    int length() const { return m_length; }
    bool isNullPointer() const { return m_data == nullptr; }

    int m_length;

private:
    double *m_data;
};

// ------------------------------------------------------------ must stay silent

// The remediated shape, and the false positive. `condition` carries the whole
// precondition; the `if` enforces it and returns. Nothing here can run with a
// short operand, and the check has nothing to report.
void add_hoisted_guard(Vec &self, Vec &v)
{
    const bool condition = self.m_length == v.m_length
                        && !v.isNullPointer()
                        && !self.isNullPointer();
    assert(condition);
    if (!condition) {
        return;
    }

    for (int i = 0; i < self.m_length; i++) {
        self[i] += v[i];
    }
}

// The same remediation without the assert. The assert is documentation here,
// not enforcement, so removing it must not change the verdict either way.
void add_hoisted_guard_no_assert(Vec &self, Vec &v)
{
    const bool ok = self.m_length == v.m_length && !v.isNullPointer();
    if (!ok) {
        return;
    }

    for (int i = 0; i < self.m_length; i++) {
        self[i] += v[i];
    }
}

// The hoisted condition negated the other way round: enforced by continuing
// only when it holds, rather than by returning when it does not.
void add_hoisted_guard_positive(Vec &self, Vec &v)
{
    const bool ok = v.m_length >= self.m_length;
    if (ok) {
        for (int i = 0; i < self.m_length; i++) {
            self[i] += v[i];
        }
    }
}

// ------------------------------------------------------------- must be flagged

// The unremediated sibling that shares the file in the real code. The assert
// is the only validation and expands to nothing under NDEBUG. If a fix for the
// hoisted case also silences this one, the exemption has become "any local
// bool anywhere in the function" and the check is dead.
void add_asserted_only(Vec &self, Vec &v)
{
    assert(self.m_length == v.m_length);
    for (int i = 0; i < self.m_length; i++) {
        self[i] += v[i];
    }
}

// A local bool that is computed and branched on, but says nothing about the
// operand's extent. The exemption must key on what the condition establishes,
// not on the presence of a bool.
void add_unrelated_bool(Vec &self, Vec &v, bool verbose)
{
    const bool noisy = verbose && self.m_length > 0;
    if (!noisy) {
        return;
    }
    for (int i = 0; i < self.m_length; i++) {
        self[i] += v[i];
    }
}

}  // namespace kordon_probe
