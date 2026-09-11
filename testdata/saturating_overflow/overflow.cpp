// Fixture: two overflow shapes where the author was already thinking about
// overflow one line away.
//
// Synthetic. Modelled on a real image-codec loader and a real stereo-matching
// module. Both shapes are mechanical enough to check, and both were found in a
// vendor report on that codebase.
//
//   1. A NEGATIVE ERROR RETURN STORED IN AN UNSIGNED TYPE. `ftell` reports
//      failure as -1. Assigned to a `size_t` that is SIZE_MAX, and the
//      *sanity check on the next line* then passes vacuously, because
//      `SIZE_MAX + 1` is 0 and the comparison it feeds compares 0 against 0.
//      The failure reaches `fread` as a length of SIZE_MAX. This is narrow and
//      mechanical -- an `ftell`/`ftello` result assigned to an unsigned type
//      with no `< 0` test -- and should cost nothing in false positives.
//
//   2. SATURATE, THEN UNSATURATE. A function deliberately clamps its result to
//      the type maximum to avoid an overflow, and its caller immediately adds
//      to that result. The clamp is proof the author understood the hazard, so
//      the arithmetic one call away is a strong signal rather than a weak one:
//      the wrap turns the saturated maximum into a very small number, which is
//      the opposite of what the clamp was defending.
//
// The lockstep case at the end is the discrimination test. Two expressions
// that wrap together preserve the relation between them, so the index stays in
// range and there is no defect -- flagging it is exactly the false positive
// the vendor report produced.
//
// What Kordon actually reports on this file is recorded once, in
// docs/acl-report-findings.md under "Fixtures". It is kept there rather
// than here so six copies cannot drift apart.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace kordon_probe {

// ------------------------------------------------------------- must be flagged

// 1. `ftell` failure stored unsigned. On a pipe or a closed stream this is
// SIZE_MAX; `file_size + 1` is then 0, the size comparison below is `0 != 0`
// and passes, and the read length handed to `fread` is SIZE_MAX.
bool load_whole_file(std::FILE *in, std::vector<unsigned char> &buf)
{
    std::fseek(in, 0, SEEK_END);
    std::size_t file_size = static_cast<std::size_t>(std::ftell(in));
    std::fseek(in, 0, SEEK_SET);

    buf.resize(file_size + 1);
    if (buf.size() != file_size + 1) {      // vacuously true when it wrapped
        return false;
    }
    return std::fread(buf.data(), file_size, 1, in) == 1;
}

// The same shape with the wider accessor and no sanity check at all.
std::size_t stream_length(std::FILE *in)
{
    std::fseek(in, 0, SEEK_END);
    return static_cast<std::size_t>(::ftello(in));
}

// 2. The saturating producer. Clamping here is correct and deliberate.
std::size_t disparity_range(std::size_t near, std::size_t far)
{
    if (far < near) {
        return SIZE_MAX;                    // saturate rather than wrap
    }
    return far - near;
}

// The consumer that undoes it. `SIZE_MAX + 2 * expansion` wraps to a small
// number, and a range that was deliberately made maximal becomes minimal.
std::size_t padded_range(std::size_t near, std::size_t far, std::size_t expansion)
{
    return disparity_range(near, far) + 2 * expansion;
}

// ------------------------------------------------------------ must stay silent

// The `ftell` result tested before it is widened. One `< 0` closes it.
bool load_whole_file_checked(std::FILE *in, std::vector<unsigned char> &buf)
{
    std::fseek(in, 0, SEEK_END);
    long n = std::ftell(in);
    std::fseek(in, 0, SEEK_SET);
    if (n < 0) {
        return false;
    }

    std::size_t file_size = static_cast<std::size_t>(n);
    buf.resize(file_size + 1);
    return std::fread(buf.data(), file_size, 1, in) == 1;
}

// The saturated value recognised for what it is before it is used.
std::size_t padded_range_checked(std::size_t near, std::size_t far,
                                 std::size_t expansion)
{
    std::size_t range = disparity_range(near, far);
    if (range > SIZE_MAX - 2 * expansion) {
        return SIZE_MAX;
    }
    return range + 2 * expansion;
}

// LOCKSTEP, and therefore not a defect. Both expressions wrap at the same
// input, so `octaves * layers_per_octave - 1` stays within `size() - 1` and
// every index is in range. The relation between the two is preserved by the
// wrap, which is what a check has to notice before flagging either of them.
// (`layers == 0` in this function is a division by zero, not an overflow --
// a different defect, and not this fixture's.)
std::size_t pyramid_index(std::size_t octaves, std::size_t layers)
{
    const std::size_t per_octave = layers + 3;
    std::vector<double> pyr(octaves * per_octave);
    const std::size_t last = octaves * (layers + 3) - 1;
    return pyr.size() > last ? last : 0;
}

}  // namespace kordon_probe
