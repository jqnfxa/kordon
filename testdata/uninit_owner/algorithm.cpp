// Fixture: the consumer side. This is where the defects in vector.cpp
// actually bite.
//
// Every function here is correct in isolation. Read this file alone and there
// is nothing to find: it constructs objects, calls documented methods, and
// never touches a raw pointer. The defect lives entirely behind the
// constructor in the other translation unit.
//
// That is the point of splitting the fixture. Without cross-translation-unit
// analysis the constructors below are opaque -- Clang SA assumes a called
// function it cannot see leaves the object in a valid state, so it has nothing
// to report here, and analyzing vector.cpp alone does not know how any object
// reached init(). The defect falls in the gap between the two files.

#include "vector.hpp"

namespace kordon_probe {

// Not on the heap. Deleting this is undefined behavior, not a bookkeeping
// mistake that merely loses memory.
static double g_lookup_table[8] = {0, 1, 2, 3, 4, 5, 6, 7};

// CWE-590 (Free of Memory not on the Heap), reached through CWE-665.
//
// The borrowing constructor never assigns m_ownsData. When `wrapper` goes out
// of scope, ~Vector -> clear() tests `m_data != nullptr && m_ownsData`. m_data
// is the static array, so the only thing standing between this and
// `delete[] g_lookup_table` is whatever the stack happened to contain.
double sum_borrowed()
{
    Vector wrapper(g_lookup_table, 8);

    double total = 0.0;
    for (int i = 0; i < wrapper.size(); ++i) {
        total += wrapper.at(i);
    }
    return total;
    // ~Vector() here may delete[] a static array.
}

// CWE-476 (NULL Pointer Dereference), reached through CWE-665 and CWE-824.
//
// The owning constructor leaves m_ownsData unassigned when the allocation
// fails. init() then reads it: on garbage-true it returns early, believing the
// buffer is already the right size, and at() dereferences null.
double resize_then_read(int length)
{
    Vector values(length);

    // Looks defensive. Is not: init() short-circuits on the garbage flag.
    values.init(length);

    return values.at(0);
}

// The same object used the way a caller reasonably would. Nothing here is
// wrong; it inherits the constructor's failure.
double average(int length)
{
    Vector values(length);
    values.init(length);

    double total = 0.0;
    for (int i = 0; i < values.size(); ++i) {
        total += values.at(i);
    }
    return total / static_cast<double>(values.size());
}

}  // namespace kordon_probe
