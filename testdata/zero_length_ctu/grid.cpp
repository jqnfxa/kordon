#include "grid.hpp"

namespace kordon_probe {

// Pass-through. The negative-extent rejection is deliberately an early return
// rather than a `cells = 0` clamp: a clamp introduces a *concrete* zero one
// hop from the sink, and the analyzer then finds the defect from here without
// ever following the chain. Measured -- with the clamp, deleting app.cpp
// changes nothing, which is the opposite of what this fixture is for.
void Grid::allocate(int cells)
{
    if (cells < 0)
    {
        return;
    }
    m_cells.init(cells);
}

void Grid::allocate_guarded(int cells)
{
    if (cells < 0)
    {
        return;
    }
    m_cells.init_guarded(cells);
}

}  // namespace kordon_probe
