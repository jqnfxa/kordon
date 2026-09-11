// Fixture: new T[n] where n can be runtime-zero, followed by an unconditional
// index-0 write (CWE-787/CWE-119). new T[0] is well-defined and returns a
// valid, non-null pointer with zero elements -- indexing it at all is
// undefined behaviour.
//
// Modelled on acl::SparseBlockMatrix::initStructure, where the report caught
// one of two sibling overloads with this exact defect and missed the other.
//
// This fixture is also a *negative* result on purpose. clang-sa's
// ArrayBoundV2 catches BadInit here because `use()` calls `init(0)` in the
// same translation unit. The real acl defect was missed by a from-scratch
// scan not because the checker is absent, but because both real overloads
// are public API whose only callers live in a *different* TU (test files /
// external plugin code), and neither of those callers passes 0 regardless.
// Without --ctu, a single-TU run never explores the path this fixture makes
// trivially reachable. See docs/acl-report-findings.md section E for the
// three-way isolation (this file, a version with clear()+sibling array added,
// and a version with the in-TU call removed) that pins the cause down to TU
// reachability rather than clear()/ownership complexity.

namespace kordon_probe {

// -------------------------------------------------------------- must be flagged
class BadInit {
public:
    void init(int size)
    {
        m_size = size;
        m_ptr = new int[m_size];   // size == 0 -> new int[0], valid, zero elements
        m_ptr[0] = 1;              // index 0 of a zero-length array: out of bounds
    }
    ~BadInit() { delete[] m_ptr; }
private:
    int m_size = 0;
    int* m_ptr = nullptr;
};

// ------------------------------------------------------------- must stay quiet
class GuardedInit {
public:
    void init(int size)
    {
        m_size = size;
        m_ptr = new int[m_size];
        if (m_size > 0)
        {
            m_ptr[0] = 1;
        }
    }
    ~GuardedInit() { delete[] m_ptr; }
private:
    int m_size = 0;
    int* m_ptr = nullptr;
};

// The call site that makes size == 0 reachable IN THIS TU. Delete this
// function and re-run: BadInit stops being flagged, even though nothing about
// BadInit itself changed. That is the whole point of this fixture.
void use()
{
    BadInit a;
    a.init(0);
    GuardedInit b;
    b.init(0);
}

} // namespace kordon_probe
