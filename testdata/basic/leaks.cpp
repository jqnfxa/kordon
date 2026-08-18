// Guaranteed leaks and lifetime defects.
//
// Synthetic by construction: every function here is a self-contained, minimal
// reproduction of exactly one CWE. Nothing in this directory is derived from
// any real codebase.
//
// This file is a *fixture*, not a demo of good practice. It exists so that a
// change to Kordon's engine configuration that stops detecting a defect class
// fails loudly, instead of producing a quiet report that reads as clean code.
//
// ---------------------------------------------------------------------------
// Why some functions are duplicated in `_static` and `_runtime` form
//
// The two analysis layers need mutually incompatible code shapes for leaks,
// and this is measured, not assumed:
//
//   * A sanitizer needs the allocated pointer to ESCAPE the function (stored
//     somewhere the optimizer cannot see through). Otherwise clang and gcc are
//     free to delete the allocation entirely at -O1 and the defect never
//     reaches the runtime at all.
//
//   * A static analyzer needs the pointer to NOT escape. Once it is written to
//     an opaque global, both Clang SA and cppcheck conclude that ownership was
//     transferred elsewhere and stop reporting a leak. Verified with clang 18
//     and cppcheck 2.13: adding a single `sink = p;` line silently removes the
//     `unix.Malloc` and `memleak` findings.
//
// So one function cannot serve both layers. Leak cases appear twice, and the
// suffix says which layer is expected to catch it. Defects whose evidence is
// inside the function -- double free, use after free, mismatched deallocator
// -- do not need this split; escaping the pointer does not hide them.
// ---------------------------------------------------------------------------

#include <cstdlib>
#include <cstring>
#include <new>

namespace kordon_probe {

// Opaque to the optimizer: prevents allocation/free pairs being elided.
volatile void *escape_sink = nullptr;

inline void escape(void *pointer)
{
    escape_sink = pointer;
}

// Reaching malloc through a volatile function pointer keeps the optimizer from
// reasoning about the allocation at all.
void *(*volatile opaque_malloc)(std::size_t) = std::malloc;

// ------------------------------------------------------------- CWE-401 leaks

// Unconditional leak, visible to STATIC analysis. The pointer never escapes,
// so the analyzer can prove the allocation is unreachable on return.
void leak_unconditional_static()
{
    char *buffer = static_cast<char *>(std::malloc(32));
    if (buffer == nullptr) {
        return;
    }
    std::memset(buffer, 0, 32);
    // no free
}

// The same leak, shaped for a RUNTIME leak checker (LSan). The escape keeps
// the allocation alive through optimization; it also, by design, hides the
// leak from the static engines.
void leak_unconditional_runtime()
{
    void *buffer = opaque_malloc(32);
    escape(buffer);
    // no free
}

// Leak on an error path only. The success path frees correctly, so no test
// that avoids the error branch will ever observe this. This is the shape that
// motivates directed fuzzing: reaching the branch is the entire difficulty.
int leak_on_error_path(int size)
{
    int *values = new (std::nothrow) int[size];
    if (values == nullptr) {
        return -1;
    }

    if (size > 16) {
        return -2;  // leaks `values`
    }

    for (int i = 0; i < size; ++i) {
        values[i] = i;
    }

    delete[] values;
    return 0;
}

// ------------------------------------------------------ CWE-415/416 lifetime

// CWE-415: double free.
void double_free()
{
    void *block = opaque_malloc(16);
    escape(block);
    std::free(block);
    std::free(block);
}

// CWE-416: use after free.
int use_after_free()
{
    int *value = static_cast<int *>(opaque_malloc(sizeof(int)));
    if (value == nullptr) {
        return 0;
    }
    *value = 7;
    std::free(value);
    return *value;
}

// CWE-763: allocated with new[], released with free(). Both "free" the memory,
// but the routines are mismatched, so the release is of a pointer the C
// allocator never handed out.
//
// MITRE offers two classes for this and they overlap: 762 is the narrow one
// ("a release function not compatible with the function originally used to
// allocate"), 763 the broader one that also covers calling the wrong release
// function. Requirements lists in this domain name 763, so that is the default;
// --cwe-map flips it in one rule.
void mismatched_deallocator()
{
    int *values = new int[4];
    escape(values);
    std::free(values);
}

// --------------------------------------------------------------- CWE-476/369

// CWE-476: null dereference. Given a bare pointer parameter the analyzer
// cannot prove null is reachable, so a caller that actually passes null is
// required for this to be reported rather than assumed.
static int deref(int *pointer)
{
    return *pointer;
}

int null_dereference()
{
    int *pointer = nullptr;
    return deref(pointer);
}

// CWE-369: division by zero on a value the analyzer can track.
int divide_by_zero(int numerator)
{
    int divisor = 0;
    return numerator / divisor;
}

// ------------------------------------------------------------------- CWE-563

// Dead store: the first assignment is never read.
int dead_store(int input)
{
    int result = input * 2;
    result = input + 1;
    return result;
}

}  // namespace kordon_probe
