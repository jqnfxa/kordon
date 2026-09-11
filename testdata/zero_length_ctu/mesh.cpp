#include "mesh.hpp"

namespace kordon_probe {

// The arithmetic is where a reader stops tracking the value. `vertices == 0`
// gives `cells == 0`, which every layer below treats as an ordinary extent.
void Mesh::build(int vertices)
{
    const int cells = vertices * 2;
    m_grid.allocate(cells);
}

void Mesh::build_guarded(int vertices)
{
    const int cells = vertices * 2;
    m_grid.allocate_guarded(cells);
}

}  // namespace kordon_probe
