// Fixture: constructors that leave the object partially constructed.
//
// Root cause is CWE-665 (Improper Initialization), NOT CWE-252 (Unchecked
// Return Value). The distinction is easy to get wrong and worth stating: a
// constructor has no return value for a caller to ignore. Its only way to
// report failure is to throw. Neither constructor here does, so on the failure
// path each hands back an object indistinguishable from a valid one -- a
// "zombie" every caller is entitled to treat as constructed.
//
// Two independent defects, with different consequences:
//
//   Vector(int)            m_ownsData unassigned when the allocation fails.
//                          CWE-665 -> CWE-824 (init() reads it) -> CWE-476
//                          (init() returns early on garbage-true, leaving
//                          m_data null on an object reporting size() == n).
//
//   Vector(double*, int)   m_ownsData never assigned at all on the borrow
//                          path. CWE-665 -> CWE-824 (clear() reads it) ->
//                          CWE-590 (Free of Memory not on the Heap: the
//                          destructor may delete[] a caller's static array).
//
// Note where the danger is NOT. In the owning constructor's failure path,
// clear() looks like it would free garbage, but `m_data != nullptr &&`
// short-circuits and m_data is genuinely null after a failed nothrow new. The
// uninitialized flag is harmless there and lethal in init(). Reading this
// quickly gets it backwards.
//
// Both defects are structurally impossible if the constructor throws instead
// of returning quietly: no partially-constructed object can then exist to be
// misused. That is a design recommendation worth emitting whenever this shape
// is detected, not just the null deref at the end of the chain.

#include "vector.hpp"

#include <cstring>
#include <new>

namespace kordon_probe {

Vector::Vector(int length)
    : m_length(length)
{
    if (m_length > 0) {
        m_data = new (std::nothrow) double[m_length];
        if (m_data != nullptr) {
            m_ownsData = true;
            std::memset(m_data, 0, sizeof(double) * m_length);
        }
        // Allocation failed. m_data is null, which is survivable --
        // but m_ownsData is never assigned on this path, and the object is
        // handed back to the caller regardless.
    } else {
        m_data = nullptr;
        m_ownsData = false;
        m_length = 0;
    }
}

Vector::Vector(double *data, int length)
    : m_length(length)
{
    if (data != nullptr) {
        m_data = data;
        // Missing: m_ownsData = false;
        // The buffer belongs to the caller. If the garbage in m_ownsData
        // happens to be truthy, the destructor deletes memory this object
        // never allocated -- and the caller's array may not be on the heap
        // at all.
    } else {
        m_data = nullptr;
        m_ownsData = false;
        m_length = 0;
    }
}

Vector::~Vector()
{
    clear();
}

void Vector::clear()
{
    if (m_data != nullptr && m_ownsData) {
        delete[] m_data;
    }
    m_data = nullptr;
    m_ownsData = false;
    m_length = 0;
}

void Vector::init(int length)
{
    // The uninitialized read. After the owning constructor's failure path
    // m_ownsData is garbage; if truthy, this returns claiming the buffer is
    // already the right size while m_data is still null.
    if (length == m_length && m_ownsData) {
        return;
    }

    clear();

    if (length > 0) {
        m_data = new (std::nothrow) double[length];
        if (m_data != nullptr) {
            m_ownsData = true;
            m_length = length;
            std::memset(m_data, 0, sizeof(double) * length);
        }
    }
}

double Vector::at(int index) const
{
    // No null check: the object is supposed to be valid by construction.
    return m_data[index];
}

}  // namespace kordon_probe
