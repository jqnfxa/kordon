// Fixture: a guard disabled by a stray semicolon.
//
// Synthetic. Modelled on a real matrix routine whose author wrote the correct
// precondition -- non-null buffers and matching extents -- and then ended the
// `if` with a semicolon. The condition is evaluated, its result is discarded,
// and the block below always runs. The guard is not weakened; it is gone.
//
// This is CWE-483, a control-flow class rather than a memory one, and it is in
// scope because of what the guard was protecting: without it the loop below
// subscripts a possibly-null buffer past a possibly-wrong extent.
//
// The pair matters. An empty `if` body is legal and occasionally deliberate,
// so the safe twin below must stay silent or the check is unusable.

#include <cstddef>

namespace kordon_probe {

struct Matrix {
    double *m_data;
    int m_rows;
    int m_cols;

    void vec_mult_broken(const double *v, int n, double *out) const;
    void vec_mult_ok(const double *v, int n, double *out) const;
};

// ------------------------------------------------------------- must be flagged

// The precondition is written correctly and then deleted by the `;`.
void Matrix::vec_mult_broken(const double *v, int n, double *out) const
{
    if (m_data != nullptr && v != nullptr && n == m_cols);
    {
        for (int i = 0; i < m_rows; ++i) {
            for (int j = 0; j < m_cols; ++j) {
                out[i] += m_data[i * m_cols + j] * v[j];
            }
        }
    }
}

// ------------------------------------------------------------ must stay silent

// The same precondition, actually guarding the block.
void Matrix::vec_mult_ok(const double *v, int n, double *out) const
{
    if (m_data != nullptr && v != nullptr && n == m_cols) {
        for (int i = 0; i < m_rows; ++i) {
            for (int j = 0; j < m_cols; ++j) {
                out[i] += m_data[i * m_cols + j] * v[j];
            }
        }
    }
}

}  // namespace kordon_probe
