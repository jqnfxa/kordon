// Layer 3 of 5. Turns a vertex count into a cell count and hands it down.
#ifndef KORDON_TESTDATA_ZLCTU_MESH_HPP
#define KORDON_TESTDATA_ZLCTU_MESH_HPP

#include "grid.hpp"

namespace kordon_probe {

class Mesh {
public:
    void build(int vertices);
    void build_guarded(int vertices);
    int extent() const { return m_grid.extent(); }

private:
    Grid m_grid;
};

}  // namespace kordon_probe

#endif
