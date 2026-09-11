// @kordon cwe: 787
// @kordon flags: --ctu
#include "buffer.hpp"

namespace kordon_probe {

Buffer::~Buffer()
{
    delete[] m_data;
}

// MUST BE FLAGGED -- CWE-787 (out-of-bounds write) / CWE-119.   @bad 787
//
// `new double[0]` is well defined: it succeeds, returns a distinct non-null
// pointer, and the array has zero elements. That is precisely what makes this
// worse than a failed allocation -- there is no null to check, and the write
// below is undefined behaviour with no diagnostic anywhere on the path.
//
// The `delete[]` is not incidental. Without it this method is also a genuine
// reinit-without-free (CWE-401), which Kordon reports at high confidence on
// both variants and which has nothing to do with what this fixture measures.
void Buffer::init(int count)
{
    delete[] m_data;
    m_count = count;
    m_data = new double[m_count];
    m_data[0] = 0.0;   // count == 0 -> index 0 of a zero-length array   @expect 787
}

// MUST STAY QUIET.   @good 787
//
// Identical allocation reached by an identical four-hop call chain. The only
// difference is that the zero-element case leaves before the write, so the
// out-of-bounds access is unreachable. A check that fires here is matching the
// shape rather than the defect.
void Buffer::init_guarded(int count)
{
    delete[] m_data;
    m_count = count;
    m_data = new double[m_count];
    if (m_count == 0)
    {
        return;
    }
    m_data[0] = 0.0;
}

}  // namespace kordon_probe
