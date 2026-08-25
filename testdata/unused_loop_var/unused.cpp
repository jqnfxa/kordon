// An unused range-for variable, in the two forms that differ to the engines.
//
// The by-value form is a dead store -- the copy is a store nothing reads -- so
// Clang SA reports it. The reference form stores nothing at all, so only the
// compiler's -Wunused-variable sees it. Kordon needs both.

#include <string>
#include <vector>

// Reported by clang-analyzer-deadcode.DeadStores *and* by the compiler.
std::vector<bool> flags_by_value(const std::vector<double> &xs)
{
    std::vector<bool> flags = {};
    for (double x : xs)
    {
        flags.push_back(false);
    }
    return flags;
}

// Reported only by the compiler: binding a reference stores nothing, so there
// is no dead store for the analyzer to find.
int count_by_reference(const std::vector<std::string> &xs)
{
    int n = 0;
    for (const std::string &s : xs)
    {
        n++;
    }
    return n;
}

// Not a finding: the loop variable is read.
double sum(const std::vector<double> &xs)
{
    double total = 0.0;
    for (double x : xs)
    {
        total += x;
    }
    return total;
}
