// Fixture: an owning member overwritten without releasing what it held.
//
// Synthetic. Modelled on several real `init()` methods that allocate straight
// into an owning pointer member. Called once they are fine; called twice the
// first buffer becomes unreachable. This is why it is invisible to the
// path-sensitive engines -- the defect needs two calls to the same method, and
// they reason about one path at a time.
//
// The safe twins matter: releasing first is the fix, and a codebase will spell
// that release many ways, so the check matches release-method names as a
// substring. An exact-name list reported correct code as a defect.

#include <cstddef>
#include <cstdlib>

namespace kordon_probe {

class Buffer {
public:
    Buffer() : m_data(nullptr), m_size(0) {}
    ~Buffer() { delete[] m_data; }

    void init_leaking(std::size_t n);
    void init_released(std::size_t n);
    void init_via_helper(std::size_t n);
    void clearBuffer();

private:
    double *m_data;
    std::size_t m_size;
};

// ------------------------------------------------------------- must be flagged

// Whatever m_data held is unreachable after this line.
void Buffer::init_leaking(std::size_t n)
{
    m_data = new double[n];
    m_size = n;
}

// ------------------------------------------------------------ must stay silent

// Releases before allocating.
void Buffer::init_released(std::size_t n)
{
    delete[] m_data;
    m_data = new double[n];
    m_size = n;
}

void Buffer::clearBuffer()
{
    delete[] m_data;
    m_data = nullptr;
    m_size = 0;
}

// Releases through a helper whose name is not literally "clear". The check
// matches release names as a substring for exactly this case.
void Buffer::init_via_helper(std::size_t n)
{
    clearBuffer();
    m_data = new double[n];
    m_size = n;
}

}  // namespace kordon_probe
