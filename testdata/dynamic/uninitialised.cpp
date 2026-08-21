// CWE-457. A read of memory that was never written. Only MSan sees this: ASan
// tracks addressability, not definedness, so this program is silent under the
// asan profile and that is not a failure of the fixture.
#include <cstdlib>

int main()
{
    int *p = static_cast<int *>(std::malloc(4 * sizeof(int)));
    volatile int i = 2;
    int r = (p[i] == 42) ? 1 : 0;
    std::free(p);
    return r;
}
