// Layer 5 of 5 -- the sink. This is where the defect physically is.
//
// Nothing in this file knows that anyone ever asks for zero elements. Read it
// alone and `init` is a perfectly ordinary allocate-then-fill routine whose
// only sin is trusting its argument.

#ifndef KORDON_TESTDATA_ZLCTU_BUFFER_HPP
#define KORDON_TESTDATA_ZLCTU_BUFFER_HPP

namespace kordon_probe {

class Buffer {
public:
    Buffer() = default;
    ~Buffer();

    Buffer(const Buffer &) = delete;
    Buffer &operator=(const Buffer &) = delete;

    // Allocates `count` doubles and seeds element 0. Defective: `count == 0`
    // yields a valid, non-null, zero-element array, and seeding it is an
    // out-of-bounds write.
    void init(int count);

    // Same allocation, same seed, with the one line that makes it correct.
    void init_guarded(int count);

    // Deliberately does not read the buffer. An accessor returning m_data[0]
    // would be a second, independent out-of-bounds access on *both* chains --
    // measured, and it made the negative control fail for a reason that had
    // nothing to do with the guard under test.
    int size() const { return m_count; }

private:
    double *m_data = nullptr;
    int m_count = 0;
};

}  // namespace kordon_probe

#endif
