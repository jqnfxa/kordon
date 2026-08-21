// CWE-190. Signed overflow is undefined behaviour, so UBSan traps it. It rides
// in the same build as ASan -- the two compose, which is why the asan profile
// covers this class without a second compile.
int main()
{
    int n = 2147483647;
    volatile int one = 1;
    return n + one;
}
