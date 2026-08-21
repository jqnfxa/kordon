// CWE-787. A read past the end of a heap block. The index is volatile so the
// optimizer cannot fold the access away at -O1.
#include <cstdlib>

int main()
{
    int *p = static_cast<int *>(std::malloc(4 * sizeof(int)));
    volatile int i = 9;
    int r = p[i];
    std::free(p);
    return r;
}
