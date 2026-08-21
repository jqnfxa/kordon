// Fixture: a container's extent, minus a literal, on an unsigned type.
//
// Synthetic. Modelled on image code that builds a region of interest from
// `dataIn.width() - 1`. An empty image reports a width of 0, and 0 - 1 on an
// unsigned type is the type maximum, so the ROI bounds a loop that runs
// essentially forever over memory it does not own.
//
// The point of this fixture is the *pair*: the same subtraction written on a
// plain variable carries no such invariant and belongs in the general,
// low-confidence check instead. A change that collapses the two back together
// should fail here.

#include <cstddef>

namespace kordon_probe {

class Image {
public:
    std::size_t width() const { return m_width; }
    std::size_t height() const { return m_height; }

private:
    std::size_t m_width;
    std::size_t m_height;
};

struct Roi {
    std::size_t x0, x1, y0, y1;
};

// ------------------------------------------------------------- must be flagged

// Nothing establishes the image is non-empty.
Roi roi_unchecked(const Image &in)
{
    return Roi{0, in.width() - 1, 0, in.height() - 1};
}

// ------------------------------------------------------------ must stay silent

// The extent is established as non-zero by a condition that encloses the use.
// This is the guard shape the check understands.
Roi roi_checked(const Image &in)
{
    if (in.width() > 0 && in.height() > 0) {
        return Roi{0, in.width() - 1, 0, in.height() - 1};
    }
    return Roi{0, 0, 0, 0};
}

// ------------------------------------------------ must stay silent (early exit)

// Guarded by leaving the function rather than by an enclosing condition. This
// is at least as common as the shape above, because it is how preconditions
// are usually written, and it was a known false positive until the check
// learned to recognise an `if` whose branch exits.
//
// Ordering is deliberately not checked: AST matchers cannot express "this
// statement precedes that one", so any early exit naming the operand exempts
// every use of it in the function. A use placed *before* the guard would be
// wrongly exempted. That errs toward silence, which is the direction chosen
// throughout this file.
Roi roi_early_return(const Image &in)
{
    if (in.width() == 0 || in.height() == 0) {
        return Roi{0, 0, 0, 0};
    }
    return Roi{0, in.width() - 1, 0, in.height() - 1};
}

// ------------------------------------------- must be flagged (guard underflows)

// The subtraction is evaluated *by* the guard, not protected by it. If `width`
// is zero this underflows while computing the very condition meant to prevent
// it, and the comparison then succeeds against a huge value.
//
// This case is why the early-exit exemption excludes subtractions inside the
// exempting condition. Without that clause the check exempted this defect
// using this defect's own `if` -- measured on the reference corpus, the naive
// form suppressed two real defects the maintainers had fixed.
bool out_of_range(const Image &in, std::size_t x_begin, std::size_t x_end)
{
    if (x_begin > in.width() - 1 || x_end > in.height() - 1) {
        return true;
    }
    return false;
}

}  // namespace kordon_probe
