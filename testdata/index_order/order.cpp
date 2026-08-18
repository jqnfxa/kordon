// Fixture: an index used to subscript before the condition that bounds it.
//
// Synthetic. `&&` and `||` evaluate left to right and short-circuit, so writing
// the bounds check on the wrong side of the operator means it never runs in
// time. The read happens first.
//
// Modelled on a real defect where a scan loop read one past the end of an
// array on its last iteration. It is easy to miss when reading, because the
// check *is* there -- just too late to help.

#include <cstddef>

namespace kordon_probe {

struct Tracker {
    void **m_slots;
    int m_count;
    int m_start;
    int m_end;
    void scan_forward();
    void scan_backward();
    void scan_forward_fixed();
};

// ------------------------------------------------------------- must be flagged

// Reads m_slots[m_start] first; when m_start reaches m_count the read is out
// of bounds and the following check is too late to stop it.
void Tracker::scan_forward()
{
    m_start = 0;
    while (m_slots[m_start] == nullptr && m_start < m_count) {
        m_start++;
    }
}

// The same defect walking backwards: the read happens at m_end == -1 before
// the check rejects it.
void Tracker::scan_backward()
{
    m_end = m_count - 1;
    while (m_slots[m_end] == nullptr && m_end >= 0) {
        m_end--;
    }
}

// --------------------------------------------------------- must NOT be flagged

// The same loop with the operands in the right order. Short-circuiting now
// works for us: the subscript is never evaluated unless the index is in range.
void Tracker::scan_forward_fixed()
{
    m_start = 0;
    while (m_start < m_count && m_slots[m_start] == nullptr) {
        m_start++;
    }
}

// Repeated subscripting with one index is not this defect -- nothing here is a
// bounds check, and an earlier, looser matcher reported all of it.
int peak(const int *hist, int i, int l, int r)
{
    if (hist[i] > hist[l] && hist[i] > hist[r]) {
        return i;
    }
    return -1;
}

}  // namespace kordon_probe
