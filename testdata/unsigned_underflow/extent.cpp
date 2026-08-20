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

// ------------------------------------------------- known limitation: reported
//
// This is guarded just as correctly, by an early return rather than by an
// enclosing condition, and the check reports it anyway. Recognising it needs
// dataflow: the subtraction is not inside the guard, and the guard's effect is
// that control never reaches the subtraction -- a fact about reachability, not
// about the expression. IKOS was tested on exactly this shape and also warns.
//
// The fixture keeps the false positive rather than hiding it, so the cost of
// the limitation stays visible and nobody "fixes" the check by exempting every
// function that merely mentions the extent somewhere.
Roi roi_early_return(const Image &in)
{
    if (in.width() == 0 || in.height() == 0) {
        return Roi{0, 0, 0, 0};
    }
    return Roi{0, in.width() - 1, 0, in.height() - 1};
}

}  // namespace kordon_probe
