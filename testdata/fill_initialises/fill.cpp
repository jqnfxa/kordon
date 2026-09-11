// Fixture: a buffer that was filled, reported as uninitialised.
//
// Synthetic. Modelled on real terrain-tile loading code. Both cases below were
// reported as CWE-457 by a vendor tool and both are false positives, and the
// two causes are different:
//
//   1. THE FILL WAS NEVER VISITED. The trace jumped from `malloc` straight to
//      the read without passing through the `fread` in between. Any "read from
//      a malloc'd buffer" is noise until the standard fill functions --
//      `fread`, `memcpy`, `memset`, `strcpy` -- are modelled as initialising
//      their destination, and this family is large.
//
//   2. AN OBJECT'S FIELDS WERE INVALIDATED BY A CALL WHOSE BODY IS VISIBLE.
//      The trace lost precision through a `clear()` that assigns every member
//      a definite value. Treating the call as opaque marks the whole object
//      unknown, and the very next read of a member is then a finding.
//
// Both are silence tests, so this fixture is mostly negative controls -- which
// makes the two positives at the top load-bearing. A change that silences the
// false positives by silencing the check has to fail here.
//
// The real function behind case 1 also carried a genuine leak on the same
// lines: `malloc` with no `free` on any path, including the success path. The
// false positive sat directly on top of a real defect, which is the argument
// for fixing the noise rather than suppressing the file.
//
// What Kordon actually reports on this file is recorded once, in
// docs/acl-report-findings.md under "Fixtures". It is kept there rather
// than here so six copies cannot drift apart.

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace kordon_probe {

void consume(int);
void consume_p(const short *);

// ------------------------------------------------------------- must be flagged

// A genuine uninitialised read: nothing writes the block between the
// allocation and the read.
int genuinely_uninitialised(std::size_t n)
{
    int *p = static_cast<int *>(std::malloc(n * sizeof(int)));
    if (!p) {
        return 0;
    }
    int first = p[0];               // never written
    std::free(p);
    return first;
}

// The leak the false positive was sitting on. No `free` on any path, the
// success path included.
short *load_tile_leaking(std::FILE *in, std::size_t count)
{
    short *tile = static_cast<short *>(std::malloc(count * sizeof(short)));
    if (!tile) {
        return nullptr;
    }
    if (std::fread(tile, sizeof(short), count, in) != count) {
        return nullptr;             // leaks
    }
    return tile;                    // and the caller below never frees it
}

// ------------------------------------------------------------ must stay silent

// 1. `fread` initialises the block it is handed, and the return value is
// checked, so reaching the read means `count` elements were written.
short first_sample(std::FILE *in, std::size_t count)
{
    short *tile = static_cast<short *>(std::malloc(count * sizeof(short)));
    if (!tile) {
        return 0;
    }
    if (std::fread(tile, sizeof(short), count, in) != count) {
        std::free(tile);
        return 0;
    }
    short v = tile[0];
    std::free(tile);
    return v;
}

// The same property through the other fill functions, since a model that knows
// only `fread` closes a third of the family.
int first_of_memset(std::size_t n)
{
    int *p = static_cast<int *>(std::malloc(n * sizeof(int)));
    if (!p) {
        return 0;
    }
    std::memset(p, 0, n * sizeof(int));
    int v = p[0];
    std::free(p);
    return v;
}

int first_of_memcpy(const int *src, std::size_t n)
{
    int *p = static_cast<int *>(std::malloc(n * sizeof(int)));
    if (!p) {
        return 0;
    }
    std::memcpy(p, src, n * sizeof(int));
    int v = p[0];
    std::free(p);
    return v;
}

std::size_t length_of_strcpy(const char *src)
{
    char buf[64];
    std::strcpy(buf, src);
    return std::strlen(buf);
}

// 2. A call whose body is right here, assigning every member a definite value.
// After `clear()` nothing about this object is unknown, and the read below is
// not a read of anything uninitialised.
class Buffer {
public:
    Buffer() : m_data(nullptr), m_length(0) {}
    ~Buffer() { std::free(m_data); }

    Buffer(const Buffer &) = delete;
    Buffer &operator=(const Buffer &) = delete;

    void clear()
    {
        std::free(m_data);
        m_data = nullptr;
        m_length = 0;
    }

    std::size_t length() const { return m_length; }

private:
    int *m_data;
    std::size_t m_length;
};

std::size_t length_after_clear(Buffer &b)
{
    b.clear();
    return b.length();          // m_length is 0, and clear() said so
}

// A local aggregate cleared by the same route, since the object case and the
// member case are told apart by different machinery.
struct Header {
    int magic;
    int version;
};

int version_after_zeroing()
{
    Header h;
    std::memset(&h, 0, sizeof(h));
    return h.magic + h.version;      // both members, so neither reads as unused
}

}  // namespace kordon_probe
