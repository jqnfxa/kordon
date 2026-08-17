// Fixture: ownership expressed as a bool instead of in the type (CWE-401).
//
// Synthetic. Paired: the broken class and the corrected one, so the check must
// flag the first and stay silent on the second. Modelled on a real container
// whose correction consisted of deleting the flag and moving ownership into a
// member smart pointer.
//
// Why this check targets the class rather than the leak sites. On the reference
// corpus, 66 CWE-401 positions were recorded across 18 files, nearly all at a
// closing brace -- the scope exit of some unrelated function that merely held
// one of these objects as a local:
//
//     void Rotation::fromAxisAngleToRotation(...)
//     {
//         Vector w(3);
//         Matrix omegaX(3, 3), omega2X(3, 3);
//         ...
//     }                                    <-- "leak" reported here
//
// Those 66 are consequences of a handful of class-level defects. Reporting them
// individually is unactionable: nothing in that function is wrong. Reporting the
// class once is both actionable and sufficient, because fixing it removes every
// one of them.

#include <cstddef>
#include <memory>

namespace kordon_probe {

// -------------------------------------------------------------- must be flagged

// Ownership lives in `m_owns`. The class is only correct if every path through
// every constructor, assignment operator and re-initialiser leaves that flag
// consistent with reality -- a property nothing enforces.
//
// Two ways it goes wrong, both seen in real code:
//   flag false while memory was allocated  -> destructor skips the delete, leak
//   flag true on a copied object           -> two owners, double free
class FlagOwned {
public:
    explicit FlagOwned(std::size_t n)
    {
        if (n > 0) {
            m_data = new double[n];
            m_owns = true;
        }
        // n == 0: m_owns never assigned on this path.
    }

    ~FlagOwned() { clear(); }

    void clear()
    {
        // The defect: the release is conditional on a bool member.
        if (m_data != nullptr && m_owns) {
            delete[] m_data;
        }
        m_data = nullptr;
        m_owns = false;
    }

private:
    double *m_data = nullptr;
    bool m_owns;
};

// ---------------------------------------------------------- must NOT be flagged

// The correction: the flag is gone and ownership is a property of the type.
// There is no path that can get it wrong, because there is no flag to get
// wrong. The destructor is implicit and always correct.
class TypeOwned {
public:
    explicit TypeOwned(std::size_t n)
        : m_data(n > 0 ? new double[n] : nullptr)
    {
    }

    void clear() { m_data.reset(); }

private:
    std::unique_ptr<double[]> m_data;
};

// Also must not be flagged: an unconditional delete owns unconditionally, so
// there is no flag whose value could disagree with reality.
class AlwaysOwned {
public:
    explicit AlwaysOwned(std::size_t n) : m_data(new double[n]) {}
    ~AlwaysOwned() { delete[] m_data; }

private:
    double *m_data;
};

// Null-checking before delete is not the defect either -- `delete nullptr` is
// already well-defined, so the check is redundant rather than dangerous, and it
// says nothing about who owns the memory.
class NullCheckedOwner {
public:
    explicit NullCheckedOwner(std::size_t n) : m_data(new double[n]) {}
    ~NullCheckedOwner()
    {
        if (m_data != nullptr) {
            delete[] m_data;
        }
    }

private:
    double *m_data;
};

}  // namespace kordon_probe
