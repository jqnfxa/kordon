// Fixture: a container whose constructor can fail, used without asking whether
// it did.
//
// Synthetic. This is the CWE-252 -> CWE-476 chain, classified as CWE-690: the
// constructor allocates with `new (std::nothrow)`, which returns null instead
// of throwing, so a failed allocation produces a fully-constructed object whose
// buffer is null. Nothing in the type system marks it as invalid. The caller
// has to ask, and the whole defect is not asking.
//
// Why this needs its own check: Clang SA never splits state on allocation
// failure. Measured on clang 18.1.3 -- it reports `int *p = nullptr; *p = 1;`
// but says nothing about `p = new (std::nothrow) int; *p = 1;`, and follows the
// null branch only when the code itself forces it there. So the guarded and
// unguarded functions below are indistinguishable to every configured engine,
// and silence on the guarded one is not evidence the guard was understood.

#include <cstddef>
#include <new>

namespace kordon_probe {

class Vector {
public:
    explicit Vector(int n)
        : m_data(new (std::nothrow) double[static_cast<std::size_t>(n)])
        , m_size(n)
    {
    }

    ~Vector() { delete[] m_data; }

    Vector(const Vector &) = delete;
    Vector &operator=(const Vector &) = delete;

    bool isNullPointer() const { return m_data == nullptr; }

    double &operator[](int i) { return m_data[i]; }

private:
    double *m_data;
    int m_size;
};

// ------------------------------------------------------------- must be flagged

// The allocation may have failed and nobody asked.
void unguarded()
{
    Vector v(5);
    v[2] = 0.0;
}

// ------------------------------------------------------------ must stay silent

// The caller asks before using. This is the correct idiom for a type that
// cannot report failure any other way.
void guarded()
{
    Vector v(5);
    if (v.isNullPointer()) {
        return;
    }
    v[2] = 0.0;
}

}  // namespace kordon_probe
