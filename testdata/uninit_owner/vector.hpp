// Fixture: a vector wrapper that can either own or borrow its buffer.
//
// Synthetic. This reproduces a *shape* common to hand-rolled C++ containers --
// a raw pointer plus a manual ownership flag, allocated with nothrow `new` --
// not any particular codebase's code.
//
// The manual flag is the reason the whole class of defect exists. It carries
// information the pointer itself cannot: "am I allowed to delete[] this?" Get
// the flag wrong and the destructor either leaks or frees memory it never
// owned. A std::vector or a unique_ptr cannot be wrong about this, because
// ownership is encoded in the type rather than in a bool a constructor might
// forget to assign.
//
// Defects are in vector.cpp; consumers are in algorithm.cpp. See README.md for
// what each engine is expected to catch and, more importantly, to miss.

#ifndef KORDON_TESTDATA_VECTOR_HPP
#define KORDON_TESTDATA_VECTOR_HPP

namespace kordon_probe {

class Vector {
public:
    // Owning: allocates `length` doubles with nothrow new.
    // Cannot report failure -- no return value, does not throw.
    explicit Vector(int length);

    // Borrowing: wraps a caller-owned buffer. Must never delete[] it.
    Vector(double *data, int length);

    ~Vector();

    // Reallocates to `length`, skipping the work if already that size.
    void init(int length);

    void clear();

    double at(int index) const;
    int size() const { return m_length; }

private:
    // No default member initializers, deliberately, and the constructors in
    // vector.cpp do not cover every path. That is the defect.
    double *m_data;
    bool m_ownsData;
    int m_length;
};

}  // namespace kordon_probe

#endif
