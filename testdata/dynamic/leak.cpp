// CWE-401. The pointer is lost when the scope ends, so LeakSanitizer and
// valgrind both see an allocation with nothing left pointing at it.
//
// Two constraints fight here, and both are load-bearing.
//
// The allocation must survive the optimizer. At -O1 -- which is what the asan
// profile builds with, because -O0 traces are worse and -O2 elides too much --
// clang deletes a malloc whose result is never used, and the fixture then
// reports nothing while looking like a clean run. Reaching malloc through a
// volatile function pointer stops that reasoning.
//
// The pointer must also not stay reachable. Memory alive at exit with a
// pointer still held is the normal state of any program with a cache or a
// singleton; neither LeakSanitizer nor valgrind calls that a leak. So it is
// deliberately *not* stored in a global -- which is the opposite of what the
// static leak fixtures in testdata/basic need.
#include <cstdlib>

namespace {

void *(*volatile opaque_malloc)(std::size_t) = std::malloc;

void lose_it()
{
    void *p = opaque_malloc(64);
    (void)p;
}

}  // namespace

int main()
{
    lose_it();
    return 0;
}
