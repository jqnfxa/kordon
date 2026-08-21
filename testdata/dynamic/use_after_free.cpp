// CWE-416. Read through a pointer whose block has been returned to the
// allocator. ASan reports heap-use-after-free; valgrind reports InvalidRead.
#include <cstdlib>

int main()
{
    int *p = static_cast<int *>(std::malloc(4 * sizeof(int)));
    p[0] = 7;
    std::free(p);
    return p[0];
}
