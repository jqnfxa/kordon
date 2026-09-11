// Fixture: unsigned wraparound that disables a check instead of crashing.
//
// Synthetic. Modelled on real image code. `testdata/unsigned_underflow/`
// already covers the plain `extent() - 1` wrap and its guard; what is new here
// is the three shapes a vendor report found in that codebase where the wrap
// does something worse than produce a large number.
//
//   1. MASKED. The wrapped value is widened to a signed or floating type
//      before it is compared, so the comparison stops rejecting anything. The
//      defect is not the wrap, it is that a bounds check now passes for every
//      input. This fails *open*, which is why it rates above a crash: nothing
//      goes wrong at the point of the wrap, and the consequence surfaces
//      somewhere else entirely.
//
//   2. THE WRONG CONNECTIVE. A guard that tests two extents with `&&` where it
//      needed `||` admits every mixed case. In the real code this appeared in
//      three identical overloads of one function and the report caught one --
//      hence the twins below. When a guard is wrong once, its siblings are the
//      highest-yield place to look next.
//
//   3. THE CLAMP ON THE WRONG SIDE. `max(1, n - 1)` evaluates the subtraction
//      first, so on an unsigned `n` the clamp receives the type maximum and
//      dutifully returns it. Written the other way round it is correct.
//
// The signed twins at the end are the discrimination test. `len - 2` where
// every operand is `int` is not an underflow -- it is -1, and -1 is just -1. A
// check that does not consult the type flags them and is measuring syntax.
//
// What Kordon actually reports on this file is recorded once, in
// docs/acl-report-findings.md under "Fixtures". It is kept there rather
// than here so six copies cannot drift apart.

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace kordon_probe {

class Image {
public:
    std::size_t width() const { return m_width; }
    std::size_t height() const { return m_height; }

private:
    std::size_t m_width;
    std::size_t m_height;
};

void consume(std::size_t);
void consume_d(double);

// ------------------------------------------------------------- must be flagged

// 1. MASKED. At width 0 the subtraction is SIZE_MAX, and widening it to double
// gives ~1.8e19. Every `x` passes. The bounds check is gone, and nothing about
// this line looks wrong at the point it executes.
bool within_bounds(const Image &in, double x)
{
    return x >= 0.0 && x <= static_cast<double>(in.width() - 1);
}

// The same masking through a signed widening rather than a floating one.
bool within_bounds_signed(const Image &in, std::int64_t x)
{
    return x <= static_cast<std::int64_t>(in.width() - 1);
}

// 2. THE WRONG CONNECTIVE, and its two twins. A 0x5 image passes the guard,
// because only one extent is zero. All three overloads carried this; only one
// was reported.
void build_roi(const Image &in)
{
    if (in.width() == 0 && in.height() == 0) {
        return;
    }
    consume(in.width() - 1);
    consume(in.height() - 1);
}

void build_roi(const Image &in, std::size_t margin)
{
    if (in.width() == 0 && in.height() == 0) {
        return;
    }
    consume(in.width() - 1 - margin);
    consume(in.height() - 1 - margin);
}

void build_roi(const Image &in, std::size_t mx, std::size_t my)
{
    if (in.width() == 0 && in.height() == 0) {
        return;
    }
    consume(in.width() - mx - 1);
    consume(in.height() - my - 1);
}

// 3. THE CLAMP ON THE WRONG SIDE. The subtraction happens first, so `max`
// receives SIZE_MAX and returns it. The clamp reads as defensive and defends
// nothing.
std::size_t stride_for(const Image &in)
{
    return std::max<std::size_t>(1, in.width() - 1);
}

// The row-address form: an unsigned extent minus one, scaled, with no
// validation of the extent anywhere in the function.
const unsigned char *last_row(const unsigned char *bits, std::uint32_t height,
                              std::uint32_t bytes_per_line)
{
    return bits + (height - 1) * bytes_per_line;
}

// ------------------------------------------------------------ must stay silent

// The connective the guard needed. A 0x5 image now returns early.
void build_roi_correct(const Image &in)
{
    if (in.width() == 0 || in.height() == 0) {
        return;
    }
    consume(in.width() - 1);
    consume(in.height() - 1);
}

// The clamp applied to the operand rather than the result.
std::size_t stride_for_correct(const Image &in)
{
    return std::max<std::size_t>(in.width(), 1) - 1;
}

// The masked comparison with the extent established first.
bool within_bounds_correct(const Image &in, double x)
{
    if (in.width() == 0) {
        return false;
    }
    return x >= 0.0 && x <= static_cast<double>(in.width() - 1);
}

// SIGNED, and therefore not this defect. Every operand is `int`; `len - 2` at
// len == 0 is -2, which is representable and means what it says. A check that
// flags these has skipped the type test.
int trailing_span(int len)
{
    return len - 2;
}

void scan_pairs(int len)
{
    for (int i = 0; i < len - 1; i++) {
        for (int j = i + 1; j < len; j++) {
            consume(static_cast<std::size_t>(j - i));
        }
    }
}

// Unsigned, but guarded on the line above -- the shape that was reported and
// should not have been.
void guarded_on_the_previous_line(std::size_t count)
{
    if (count == 0) {
        return;
    }
    consume(count - 1);
}

}  // namespace kordon_probe
